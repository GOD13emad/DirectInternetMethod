#!/usr/bin/env python3
"""R519 protected Linux in-place candidate Root transaction.

NOT PUBLIC, NOT INSTALLED. Fixed one slot; exact v1.5.4 protected root hashes,
bounded four-file mutation + protected version metadata, full SHA integrity,
preflight, replay guards, rollback after partial failures, serial lock.
The CLI is root-only and never takes a target/root-prefix from the caller.
A fake root is injectable ONLY by imported offline tests.
"""
from __future__ import annotations
import argparse,fcntl,hashlib,json,os,pathlib,re,shutil,stat,sys,tempfile
from contextlib import contextmanager

TARGET_VERSION="1.5.5-rc1"
CURRENT_BACKEND_VERSION="1.5.2"
SLOT="var/lib/directinternetmethod/upgrade-pending"
GUARD="var/lib/directinternetmethod/upgrade.lock"
ACTION_LOCK="run/directinternetmethod-action.lock"
METADATA="var/lib/directinternetmethod/install.json"

# name, payload-relative source, absolute-root-relative target, old SHA or absent,
# pinned newly accepted R517 source SHA, POSIX mode.
FILES=(
 ("helper","app/direct_method_helper.sh","usr/lib/directinternetmethod/direct_method_helper.sh",
  "E52FCAEB9C60D9E43D4A5B75462455AD8C5EE4D82FEE679A0CC4A3520D8ABEA5",
  "82051DCE83480A9C1C291AB9F13ACFF44B359655387DC253CB6DB00EAA27795A",0o755),
 ("uninstall","system/uninstall_system.sh","usr/lib/directinternetmethod/uninstall_system.sh",
  "29F9C04C07C01955DC67F491B417B89F57673FE782854025AC70E5D1B0EF7F31",
  "AB8E24FD468B7DEEBAC2F5CC4D7D5C309EDCB7E66B4F414BC9FB3FF97906F530",0o755),
 ("encrypted_controller","system/encrypted_selective_dns.py","usr/lib/directinternetmethod/encrypted_selective_dns.py",
  None,"A8A8DD6155DDC4E2C5295A6CAA7B8809144C43985B47FD4664501ED683DB0AAE",0o755),
 ("encrypted_policy","system/encrypted_selective_policy.py","usr/lib/directinternetmethod/encrypted_selective_policy.py",
  None,"BCADC01C4A0DEDA0AB7C678155BE6F6960D3B68D9CFE1307DF85A94F18785663",0o644),
)
# Other installed root files are NOT mutated, but their original identities
# are verified to prevent applying to an unknown or partially patched backend.
STATIC_ROOT={
 "usr/lib/directinternetmethod/selective_dns.py":"9701D1C0D03499F24678CF31E9FE0B68015EFA1EF3CA9E3653035B0B27727D65",
 "usr/lib/directinternetmethod/control.sh":"10BACBC871E5CEA1B109A82130AE2E1C490BC26E4E1CE91CACC6D893BE2C0A49",
 "usr/lib/directinternetmethod/direct_hosts.txt":"F9B2E12B4B77CAAD86FA15A14AC546A4611527280E4A0ECE5566EB1FF1B07184",
 "usr/lib/directinternetmethod/adult_hosts_fallback.txt":"25BA72F6D56EF1C405115C7AA5D6ED1985E8F6D56F306A95D5AD800602A75288",
 "usr/lib/directinternetmethod/strong_override_hosts.txt":"A706F1035230EDDFB1EA5037A4234AEA351018265F2B359DA4C9E1347A3A900A",
 "usr/lib/directinternetmethod/runtime/usr/bin/ctrld":"CA64579A2BC866CF72F3E46663E551162AFEFF0D448E899A01817A095E45B071",
 "usr/lib/directinternetmethod/runtime/usr/bin/nfqws":"F34615964D7321650197CD69D3F7CBFDAABE8118B5A0D57C6E41DCCDFF658999",
 "usr/lib/directinternetmethod/licenses/LICENSE-ctrld.txt":"55D82D13FE55D4B2AEC42166FCCD3C16C267B7131ECF2FBD7C3C6C3463494501",
 "usr/lib/directinternetmethod/licenses/LICENSE-zapret.txt":"DCF5ABD3E5D876C1065982871C0CEC7368C0E61FC795C541798729516BB6B54F",
}
SCHEMA=1

def need(ok,why):
    if not ok:raise RuntimeError("FAIL_CLOSED_"+why)
def sha(data):return hashlib.sha256(data).hexdigest().upper()
@contextmanager
def verified_regular_fd(path):
    """Pin a regular file by descriptor, never traversing a symlink parent.

    Unlike inspecting path.is_file() then opening later, both the metadata and
    streamed bytes refer to the same opened inode. This does not modify files.
    """
    path=pathlib.Path(path)
    need(path.is_absolute() and ".." not in path.parts and
         len(path.parts)>=2,"UNSAFE_ABSOLUTE_FILE_PATH")
    # O_NONBLOCK prevents a user-owned FIFO from blocking Root before fstat.
    flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK
    parent=os.open("/",flags|os.O_DIRECTORY)
    opened=None
    try:
        for part in path.parts[1:-1]:
            try:
                child=os.open(part,flags|os.O_DIRECTORY,dir_fd=parent)
            except OSError as exc:
                raise RuntimeError("FAIL_CLOSED_UNSAFE_PARENT_COMPONENT") from exc
            os.close(parent)
            parent=child
        try:
            opened=os.open(path.name,flags,dir_fd=parent)
        except OSError as exc:
            raise RuntimeError("FAIL_CLOSED_UNSAFE_FILE_COMPONENT") from exc
        st=os.fstat(opened)
        need(stat.S_ISREG(st.st_mode),"UNSAFE_FILE_TYPE_OR_SIZE")
        yield opened,st
    finally:
        if opened is not None:os.close(opened)
        os.close(parent)

def hash_file(path):
    h=hashlib.sha256()
    with verified_regular_fd(path) as (fd,_):
        with os.fdopen(os.dup(fd),"rb") as stream:
            for block in iter(lambda:stream.read(1048576),b""):
                h.update(block)
    return h.hexdigest().upper()
def checked_regular_bytes(path, *, owner=False, mode=None, max_bytes=2**20):
    """Check identity, ownership, type and read from ONE pinned regular inode."""
    with verified_regular_fd(path) as (fd, st):
        if owner:
            need(st.st_uid==0 and st.st_gid==0,
                 "CHECKED_FILE_FOREIGN_OWNER")
        if mode is not None:
            need(stat.S_IMODE(st.st_mode)==mode, "METADATA_MODE")
        need(0<=st.st_size<=max_bytes, "CHECKED_FILE_TOO_LARGE")
        with os.fdopen(os.dup(fd),"rb") as stream:
            data=stream.read(max_bytes+1)
        need(len(data)<=max_bytes, "CHECKED_FILE_SIZE_DRIFT")
        return data

def canonical(doc):
    return (json.dumps(doc,sort_keys=True,indent=2,ensure_ascii=False)+"\n").encode("utf8")
def no_symlink_regular(path,owner=True):
    path=pathlib.Path(path)
    need(not path.is_symlink(),"MISSING_OR_SYMLINK_"+path.name)
    with verified_regular_fd(path) as (_,st):
        if owner:need(st.st_uid==0 and st.st_gid==0,"OWNER_"+path.name)
        return st
def guarded_file_bytes(path, *, native_receipt=False, limit=2**21):
    """Read a bounded file through dirfds, refusing symlinks in EVERY parent.

    Package bytes may be user-owned; their exact SHA is separately pinned.
    Final native acceptance is more privileged and must have an OS-owned,
    non-group/world-writable file under safe OS-owned directories. A root-owned
    sticky directory (for example /tmp) may contain a private root test slot.
    """
    path=pathlib.Path(path)
    need(path.is_absolute() and ".." not in path.parts and
         len(path.parts)>=2, "UNSAFE_ABSOLUTE_FILE_PATH")
    # The source package is user-owned: never block on a FIFO before type check.
    flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK
    directory=os.open("/",flags|os.O_DIRECTORY)
    opened=None
    try:
        for part in path.parts[1:-1]:
            try:
                child=os.open(part,flags|os.O_DIRECTORY,dir_fd=directory)
            except OSError as exc:
                raise RuntimeError("FAIL_CLOSED_UNSAFE_PARENT_COMPONENT") from exc
            os.close(directory);directory=child
            if native_receipt:
                entry=os.fstat(directory)
                need(entry.st_uid==0 and
                     (not entry.st_mode & 0o022 or
                      (bool(entry.st_mode & stat.S_ISVTX) and
                       stat.S_ISDIR(entry.st_mode))),
                     "RECEIPT_PARENT_OWNER")
        try:
            opened=os.open(path.name,flags,dir_fd=directory)
        except OSError as exc:
            raise RuntimeError("FAIL_CLOSED_UNSAFE_FILE_COMPONENT") from exc
        info=os.fstat(opened)
        need(stat.S_ISREG(info.st_mode) and 0<=info.st_size<=limit,
             "UNSAFE_FILE_TYPE_OR_SIZE")
        if native_receipt:
            need(info.st_uid==0 and info.st_gid==0 and
                 not info.st_mode & 0o022, "UNTRUSTED_RECEIPT_OWNER")
        with os.fdopen(os.dup(opened),"rb") as reader:
            content=reader.read(limit+1)
        need(len(content)<=limit, "FILE_SIZE_CHANGED_DURING_READ")
        return content
    finally:
        if opened is not None:os.close(opened)
        os.close(directory)


def flush_dir(directory):
    f=os.open(directory,os.O_DIRECTORY)
    try:os.fsync(f)
    finally:os.close(f)
def atomic_bytes(path,data,mode,owner=True):
    directory=path.parent
    need(directory.is_dir() and not directory.is_symlink(),"TARGET_DIR_UNSAFE")
    fd,name=tempfile.mkstemp(prefix=".dim-r519-",dir=str(directory))
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(data);f.flush();os.fsync(f.fileno())
        os.chmod(name,mode)
        if owner:os.chown(name,0,0)
        os.replace(name,path)
        flush_dir(directory)
    finally:
        if os.path.lexists(name):os.unlink(name)

class RootTransaction:
    def __init__(self,root=pathlib.Path("/")):
        self.root=pathlib.Path(root)
        self.native=self.root==pathlib.Path("/")
        self.pending=self.root/SLOT
        self.base=self.root/"var/lib/directinternetmethod"
        self.lock=self.root/GUARD
        self.meta=self.root/METADATA
    def p(self,relative):
        need(type(relative) is str and not relative.startswith("/") and
             ".." not in pathlib.PurePosixPath(relative).parts,"PATH_TRAVERSAL")
        return self.root/relative
    def original_metadata(self):
        d=json.loads(checked_regular_bytes(
            self.meta,owner=self.native,mode=0o644,max_bytes=65536).decode("utf8"))
        need(type(d)==dict and d.get("schema")==1 and
             d.get("version")==CURRENT_BACKEND_VERSION,"OLD_ROOT_VERSION")
        uid=d.get("uid")
        need(type(uid) is int and uid>0 and uid<2**31,"OWNER_UID")
        need(re.fullmatch(r"[a-z_][a-z0-9_-]*[$]?",str(d.get("user",""))),"OWNER_USER")
        home=d.get("home")
        need(isinstance(home,str) and home.startswith("/home/") and
             ".." not in pathlib.PurePosixPath(home).parts,"OWNER_HOME")
        idfile=self.p("etc/directinternetmethod.uid")
        uid_marker=checked_regular_bytes(idfile,owner=self.native,max_bytes=128)
        need(uid_marker.decode("utf8").strip()==str(uid),"UID_MARKER_CHANGED")
        return d
    def _baseline(self):
        before=self.original_metadata()
        need(self.base.is_dir() and not self.base.is_symlink(),"BASE_DIR_UNSAFE")
        if self.native:
            need(self.base.stat().st_uid==0,"BASE_DIR_NOT_ROOT")
            # Fail before protected mutation if any live owned DNS or DPI state.
            need(not pathlib.Path("/run/directinternetmethod-encrypted").exists() and
                 not pathlib.Path("/run/directinternetmethod-encrypted-ctrld.toml").exists() and
                 not pathlib.Path("/run/directinternetmethod-selective/session.json").exists() and
                 not pathlib.Path("/sys/class/net/dimesd0").exists(),"ACTIVE_DNS_RESOURCE")
            home=pathlib.Path(before["home"])/".local/share/DirectInternetMethod/directmethod/state.json"
            need(not home.exists(),"ACTIVE_DIRECT_METHOD")
        for rel,want in STATIC_ROOT.items():
            p=self.p(rel)
            no_symlink_regular(p,self.native)
            need(hash_file(p)==want,"BASELINE_STATIC_SHA_"+pathlib.Path(rel).name)
        for name,src,target,old,new,mode in FILES:
            p=self.p(target)
            if old:
                s=no_symlink_regular(p,self.native)
                need(stat.S_IMODE(s.st_mode)==mode,"OLD_FILE_MODE_"+name)
                need(hash_file(p)==old,"OLD_FILE_SHA_"+name)
            else:
                need(not p.exists() and not p.is_symlink(),"NEW_TARGET_NOT_EMPTY_"+name)
        return before
    @contextmanager
    def exclusive(self):
        """Serialize with protected upgrade AND the real native Start/Stop lock."""
        need(self.base.is_dir() and not self.base.is_symlink(),"BASE_MISSING")
        action=self.root/ACTION_LOCK
        need(action.parent.is_dir() and not action.parent.is_symlink(),
             "NATIVE_ACTION_LOCK_PARENT_UNSAFE")
        if self.native:
            need(self.base.stat().st_uid==0 and action.parent.stat().st_uid==0,
                 "ROOT_LOCK_PARENT_UNOWNED")
        f=os.open(self.lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            a=os.open(action,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
            try:
                if self.native:
                    st=os.fstat(a)
                    need(st.st_uid==0 and stat.S_ISREG(st.st_mode),
                         "NATIVE_ACTION_LOCK_FOREIGN")
                fcntl.flock(a,fcntl.LOCK_EX|fcntl.LOCK_NB)
                yield
            finally:
                os.close(a)
        finally:
            os.close(f)
    def manifest(self):
        need(self.pending.is_dir() and not self.pending.is_symlink(),"SLOT_MISSING_OR_SYMLINK")
        if self.native:
            s=self.pending.stat()
            need(s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700,"SLOT_UNOWNED")
        p=self.pending/"manifest.json"
        data=json.loads(checked_regular_bytes(
            p,owner=self.native,max_bytes=131072).decode("utf8"))
        need(data.get("schema")==SCHEMA and data.get("revision")=="R519" and
             data.get("fromVersion")==CURRENT_BACKEND_VERSION and
             data.get("toVersion")==TARGET_VERSION,"MANIFEST_VERSION")
        need(data.get("phase") in ("STAGED","APPLIED","ROLLED_BACK","DEGRADED","COMMITTED"),
             "MANIFEST_PHASE")
        need(set(data.get("files",{}))=={row[0] for row in FILES},"MANIFEST_FILE_LIST")
        return data
    def write_manifest(self,data):
        atomic_bytes(self.pending/"manifest.json",canonical(data),0o600,self.native)
    def stage(self,source):
        with self.exclusive():
            need(not self.pending.exists() and not self.pending.is_symlink(),"SLOT_ALREADY_EXISTS")
            before=self._baseline()
            src=pathlib.Path(source)
            # R783: source member bytes are opened and SHA-pinned later through
            # guarded_file_bytes() on the SAME verified inode. A separate
            # is_dir()/is_symlink() pathname precheck cannot authenticate the
            # later descriptor and adds an avoidable time-of-check race.
            need(src.is_absolute() and ".." not in src.parts and
                 len(src.parts)>=2,"PACKAGE_SOURCE")
            # Source may be user-owned (pkexec), but its bytes are pinned to
            # the independently tested GitHub candidate; only mapped files read.
            data={}
            for name,rel,target,old,want,mode in FILES:
                file=src/rel
                no_symlink_regular(file,False)
                blob=guarded_file_bytes(file)
                need(sha(blob)==want,"PACKAGE_SOURCE_SHA_"+name)
                data[name]=blob
            # R778: both protected baseline snapshots must be captured through
            # the same pinned descriptor used to check identity and permissions.
            # Fail before creating a Root pending slot if files changed after
            # _baseline(), rather than retaining an untrusted backup.
            originals={}
            for name,rel,target,old,new,mode in FILES:
                if old:
                    old_blob=checked_regular_bytes(
                        self.p(target),owner=self.native,mode=mode,
                        max_bytes=1048576)
                    need(sha(old_blob)==old,"BASELINE_BACKUP_CHANGED_"+name)
                    originals[name]=old_blob
            orig=checked_regular_bytes(
                self.meta,owner=self.native,mode=0o644,max_bytes=65536)
            need(json.loads(orig.decode("utf8"))==before,
                 "BASELINE_METADATA_CHANGED_AFTER_PREFLIGHT")
            self.pending.mkdir(mode=0o700)
            (self.pending/"old").mkdir(mode=0o700)
            (self.pending/"new").mkdir(mode=0o700)
            try:
                entries={}
                for name,rel,target,old,new,mode in FILES:
                    atomic_bytes(self.pending/"new"/name,data[name],0o600,self.native)
                    if old:
                        atomic_bytes(self.pending/"old"/name,originals[name],0o600,self.native)
                    entries[name]={"target":target,"old":old,"new":new,"mode":mode}
                atomic_bytes(self.pending/"old"/"metadata",orig,0o600,self.native)
                new_meta=dict(before,version=TARGET_VERSION)
                new_blob=canonical(new_meta)
                atomic_bytes(self.pending/"new"/"metadata",new_blob,0o600,self.native)
                payload={"schema":SCHEMA,"revision":"R519","phase":"STAGED",
                         "fromVersion":CURRENT_BACKEND_VERSION,"toVersion":TARGET_VERSION,
                         "files":entries,"oldMetadataSHA":sha(orig),"newMetadataSHA":sha(new_blob),
                         "uid":before["uid"],"home":before["home"],"user":before["user"]}
                self.write_manifest(payload)
                return {"status":"STAGED","files":len(FILES),"version":TARGET_VERSION}
            except BaseException:
                # Preserve evidence rather than silently delete a partial slot.
                raise
    def _validate_slot(self,m):
        need(self.pending.is_dir() and not self.pending.is_symlink(),"SLOT_UNSAFE")
        for name,rel,target,old,new,mode in FILES:
            x=m["files"][name]
            need(x=={"target":target,"old":old,"new":new,"mode":mode},"MANIFEST_FILE_TAMPER_"+name)
            nf=self.pending/"new"/name
            need(no_symlink_regular(nf,self.native) and hash_file(nf)==new,
                 "PENDING_NEW_SHA_"+name)
            if old:
                backup=self.pending/"old"/name
                need(no_symlink_regular(backup,self.native) and hash_file(backup)==old,
                     "PENDING_OLD_SHA_"+name)
        for key,dir,want in (("metadata","old",m["oldMetadataSHA"]),
                              ("metadata","new",m["newMetadataSHA"])):
            file=self.pending/dir/key
            need(no_symlink_regular(file,self.native) and hash_file(file)==want,
                 "PENDING_METADATA_"+dir)
        need(m["uid"]>0 and m["home"].startswith("/home/"),"IDENTITY_CHANGED")
    def _target_states(self,m):
        result={}
        for name,rel,target,old,new,mode in FILES:
            file=self.p(target)
            if not file.exists() and not file.is_symlink():
                digest=None
            else:
                no_symlink_regular(file,self.native)
                digest=hash_file(file)
            need(digest in (old,new),"FOREIGN_TARGET_MODIFICATION_"+name)
            result[name]=digest
        no_symlink_regular(self.meta,self.native)
        meta_sha=hash_file(self.meta)
        need(meta_sha in (m["oldMetadataSHA"],m["newMetadataSHA"]),
             "FOREIGN_METADATA_CHANGE")
        return result,meta_sha
    def apply(self,fail_after=None):
        with self.exclusive():
            m=self.manifest()
            need(m["phase"]=="STAGED","UNSAFE_APPLY_RERUN")
            self._validate_slot(m)
            before,meta=self._target_states(m)
            for name,rel,target,old,new,mode in FILES:
                need(before[name]==old,"BASELINE_CHANGED_"+name)
            need(meta==m["oldMetadataSHA"],"OLD_META_CHANGED")
            changed=0
            try:
                for name,rel,target,old,new,mode in FILES:
                    atomic_bytes(self.p(target),(self.pending/"new"/name).read_bytes(),
                                 mode,self.native)
                    changed+=1
                    if fail_after is not None and changed>=fail_after:
                        raise RuntimeError("INJECTED_TEST_FAILURE_AFTER_"+str(changed))
                atomic_bytes(self.meta,(self.pending/"new"/"metadata").read_bytes(),
                             0o644,self.native)
                states,now=self._target_states(m)
                need(all(states[name]==new for name,src,target,old,new,mode in FILES) and
                     now==m["newMetadataSHA"],"POST_UPGRADE_HASHES")
                m["phase"]="APPLIED"
                self.write_manifest(m)
                return {"status":"APPLIED","changed":changed,"version":TARGET_VERSION}
            except BaseException:
                # Rollback is owned by this transaction. Preserve slot if
                # corrupted/ambiguous; never proceed blind.
                try:self._rollback_locked(m)
                except BaseException:
                    m["phase"]="DEGRADED";self.write_manifest(m)
                raise
    def _rollback_locked(self,m):
        self._validate_slot(m)
        states,metadata=self._target_states(m)
        # Verify ALL targets before a single mutation.
        for name,rel,target,old,new,mode in FILES:
            need(states[name] in (old,new),"FOREIGN_TARGET_"+name)
        for name,rel,target,old,new,mode in FILES:
            if states[name]==new:
                p=self.p(target)
                if old is None:
                    need(not p.is_symlink() and hash_file(p)==new,"FOREIGN_NEW_"+name)
                    p.unlink()
                    flush_dir(p.parent)
                else:
                    atomic_bytes(p,(self.pending/"old"/name).read_bytes(),mode,self.native)
        if metadata==m["newMetadataSHA"]:
            atomic_bytes(self.meta,(self.pending/"old"/"metadata").read_bytes(),
                         0o644,self.native)
        for name,rel,target,old,new,mode in FILES:
            p=self.p(target)
            if old:need(hash_file(p)==old,"ROLLBACK_SHA_"+name)
            else:need(not p.exists(),"ROLLBACK_NEW_REMAINS_"+name)
        need(hash_file(self.meta)==m["oldMetadataSHA"],"ROLLBACK_METADATA_SHA")
        m["phase"]="ROLLED_BACK"
        self.write_manifest(m)
        return {"status":"ROLLED_BACK","baselineRestored":True}
    def rollback(self):
        with self.exclusive():
            m=self.manifest()
            need(m["phase"] in ("STAGED","APPLIED","DEGRADED"),"ROLLBACK_ALREADY_COMMITTED_OR_DONE")
            return self._rollback_locked(m)
    def commit(self,acceptance):
        with self.exclusive():
            m=self.manifest()
            need(m["phase"]=="APPLIED","COMMIT_UNACCEPTED_PHASE")
            self._validate_slot(m)
            states,meta=self._target_states(m)
            need(all(states[name]==new for name,rel,target,old,new,mode in FILES),
                 "COMMIT_BACKEND_CHANGED")
            need(meta==m["newMetadataSHA"],"COMMIT_META_CHANGED")
            acceptance=pathlib.Path(acceptance)
            # R783: avoid pathname file/symlink preflight. guarded_file_bytes
            # alone opens NOFOLLOW through pinned dirfds, fstats that exact
            # inode, enforces root-owned receipt metadata in native mode and
            # reads the bounded bytes. Preserve the prior rejection contract
            # for missing or symlinked acceptance files.
            try:
                receipt_blob=guarded_file_bytes(
                    acceptance,native_receipt=self.native,limit=65536)
            except RuntimeError as exc:
                if str(exc)=="FAIL_CLOSED_UNSAFE_FILE_COMPONENT":
                    raise RuntimeError(
                        "FAIL_CLOSED_NATIVE_ACCEPTANCE_MISSING") from exc
                raise
            receipt=json.loads(receipt_blob.decode("utf8"))
            need(receipt.get("revision")=="R519" and
                 receipt.get("status")=="PASS_NATIVE_ROOT_UPGRADE" and
                 receipt.get("sourceRootSHA")==sha(canonical(m["files"])) and
                 receipt.get("protectedMetadataSHA")==meta and
                 receipt.get("nativeStartStopRecovery") is True and
                 receipt.get("tailscalePreserved") is True and
                 receipt.get("physicalDNSPreserved") is True,
                 "NATIVE_ACCEPTANCE_NOT_PROVEN")
            m["phase"]="COMMITTED"
            self.write_manifest(m)
            # The acceptance and parent lineage must be exported into Project
            # Brain before a separate maintenance cleanup is authorized.
            return {"status":"COMMITTED","backupRetainedUntilBrainPromotion":True}
    def status(self):
        if not self.pending.exists():return {"status":"NO_PENDING_UPGRADE"}
        m=self.manifest()
        return {"status":m["phase"],"version":m["toVersion"],"uid":m["uid"]}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("action",choices=("stage","apply","rollback","commit","status"))
    p.add_argument("--source")
    p.add_argument("--acceptance")
    args=p.parse_args()
    need(os.geteuid()==0,"ROOT_REQUIRED")
    t=RootTransaction() # No CLI root-prefix/dry-run/test-mode option.
    if args.action=="stage":need(bool(args.source),"SOURCE_REQUIRED");result=t.stage(args.source)
    elif args.action=="apply":result=t.apply()
    elif args.action=="rollback":result=t.rollback()
    elif args.action=="commit":need(bool(args.acceptance),"ACCEPTANCE_REQUIRED");result=t.commit(args.acceptance)
    else:result=t.status()
    print(json.dumps(result,sort_keys=True))
if __name__=="__main__":
    try:main()
    except Exception as e:
        print(json.dumps({"ok":False,"error":str(e)[:200]}),file=sys.stderr)
        sys.exit(82)
