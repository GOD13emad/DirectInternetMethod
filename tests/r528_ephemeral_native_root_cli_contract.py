#!/usr/bin/env python3
"""R528 GitHub disposable Ubuntu VM: real absolute-root CLI stage/apply/rollback.

NO production installation. This runs only in an ephemeral GitHub-hosted
ubuntu-latest VM with root privileges and a verified empty DIM state. It
creates the exact pinned v1.5.2 protected baseline at /usr/lib, /var/lib and
/etc in THAT VM using bytes from the official v1.5.4 Linux release ZIP.
Then runs the UNMODIFIED product RootTransaction() bound to real "/" with
actual native owner checks, filesystem locking, fsync, mode, stage, apply
and rollback. It NEVER invokes network service, GUI, DNS, Tailscale, NFT,
VPN, user installer, or a release operation.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import stat
import sys
import zipfile

BASE=Path(__file__).resolve().parents[1]
STABLE_SHA="4784fcd44ed3d1b40103bca140b2c0066784f794d07c3ae1f525334766a553c7"
CANDIDATE_SHA="f5506e1ae0092a20071b8d63e770adbf6cde3aa0701cc6a1b4f1e925c74cafb6"
STABLE_ARCHIVE="DirectInternetMethod_1.5.4_Linux_x86_64.zip"
CANDIDATE_ARCHIVE="DirectInternetMethod_1.5.7_Linux_x86_64.zip"
STABLE_PREFIX="DirectInternetMethod_1.5.4_Linux_x86_64/"
CANDIDATE_PREFIX="DirectInternetMethod_1.5.7_Linux_x86_64/"
SOURCE=BASE/"linux/system/protected_upgrade_transaction.py"
HOSTED_WORKSPACE=Path("/home/runner/work/DirectInternetMethod/DirectInternetMethod")
HOSTED_TEMP=Path("/home/runner/work/_temp")
MAPPING={
 "selective_dns.py":"system/selective_dns.py",
 "control.sh":"system/control.sh",
 "direct_hosts.txt":"app/hosts.txt",
 "adult_hosts_fallback.txt":"app/adult_hosts_fallback.txt",
 "strong_override_hosts.txt":"app/strong_override_hosts.txt",
 "ctrld":"runtime/ctrld",
 "nfqws":"runtime/nfqws",
 "LICENSE-ctrld.txt":"licenses/LICENSE-ctrld.txt",
 "LICENSE-zapret.txt":"licenses/LICENSE-zapret.txt",
 "direct_method_helper.sh":"app/direct_method_helper.sh",
 "uninstall_system.sh":"system/uninstall_system.sh",
}

def sha(raw:bytes)->str:
    return hashlib.sha256(raw).hexdigest().lower()

def fsha(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for piece in iter(lambda:f.read(1024*1024),b""):
            h.update(piece)
    return h.hexdigest()

def need(condition,why):
    if not condition:raise RuntimeError("R528_FAIL_CLOSED_"+why)

def module():
    spec=importlib.util.spec_from_file_location("r528_real_product_root",SOURCE)
    need(spec is not None and spec.loader is not None,"SOURCE_IMPORT_UNAVAILABLE")
    m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def prerequisites():
    need(sys.platform.startswith("linux") and os.geteuid()==0,"ROOT_LINUX_REQUIRED")
    need(os.environ.get("CI")=="true" and os.environ.get("GITHUB_ACTIONS")=="true",
         "DISPOSABLE_GITHUB_VM_REQUIRED")
    need(os.environ.get("GITHUB_REPOSITORY")=="GOD13emad/DirectInternetMethod",
         "REPOSITORY_AUTHORITY")
    need(os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted",
         "NOT_HOSTED_RUNNER")
    workspace=os.environ.get("GITHUB_WORKSPACE")
    runner_temp=os.environ.get("RUNNER_TEMP")
    need(workspace==str(HOSTED_WORKSPACE) and BASE==HOSTED_WORKSPACE,
         "WORKSPACE_AUTHORITY")
    need(runner_temp==str(HOSTED_TEMP) and HOSTED_TEMP.is_dir() and
         not HOSTED_TEMP.is_symlink(),"RUNNER_TEMP_AUTHORITY")
    need(json.loads((BASE/"RELEASE.json").read_text())["version"]=="1.5.4",
         "STABLE_RELEASE_AUTHORITY")
    stable=HOSTED_TEMP/"DIM_R528_STABLE.zip"
    candidate=BASE/"delivery"/CANDIDATE_ARCHIVE
    need(stable.is_file() and fsha(stable)==STABLE_SHA,"PINNED_PUBLIC_STABLE_ZIP")
    need(candidate.is_file() and fsha(candidate)==CANDIDATE_SHA,
         "PINNED_RC1_SOURCE_ZIP")
    # This job must run in a fresh standalone GH VM. Never touch any existing
    # DIM state, even if files appear to be owned by this test revision.
    must_absent=[
        "/usr/lib/directinternetmethod",
        "/var/lib/directinternetmethod",
        "/etc/directinternetmethod.uid",
        "/run/directinternetmethod-action.lock",
        "/run/directinternetmethod-encrypted",
        "/run/directinternetmethod-encrypted-ctrld.toml",
        "/run/directinternetmethod-selective",
        "/sys/class/net/dimesd0",
    ]
    for path in must_absent:
        p=Path(path)
        need(not p.exists() and not p.is_symlink(),"PREEXISTING_PATH_"+p.name)
    user=pwd.getpwnam("runner")
    need(user.pw_uid>0 and user.pw_dir=="/home/runner","STANDARD_HOSTED_RUNNER_USER")
    need(not Path("/home/runner/.local/share/DirectInternetMethod/directmethod/state.json").exists(),
         "EXISTING_ACTIVE_USER_ENGINE")
    return stable,candidate,HOSTED_TEMP,user

def archive_verify(z:zipfile.ZipFile,prefix:str,expected_count:int):
    names=z.namelist()
    need(len(names)==expected_count and len(names)==len(set(names)),
         "ZIP_MEMBER_CARDINALITY")
    need(z.testzip() is None,"ZIP_CRC")
    for n in names:
        posix=PurePosixPath(n)
        need(n.startswith(prefix) and not posix.is_absolute() and
             ".." not in posix.parts and "\\" not in n,"ZIP_PATH_TRAVERSAL")
        member=z.getinfo(n)
        mode=(member.external_attr>>16)&0xffff
        need(not stat.S_ISLNK(mode),"ZIP_SYMLINK_DENIED")

def stage_exact_candidate(candidate_zip:Path,temp:Path)->Path:
    extract=temp/"DIM_R528_CANDIDATE"
    need(not extract.exists() and not extract.is_symlink(),"TEMP_SOURCE_COLLISION")
    extract.mkdir(mode=0o700)
    with zipfile.ZipFile(candidate_zip) as z:
        archive_verify(z,CANDIDATE_PREFIX,30)
        manifest=json.loads(z.read(CANDIDATE_PREFIX+"PACKAGE_MANIFEST.json"))
        need(manifest.get("version")=="1.5.7" and len(manifest.get("files",[]))==28,
             "RC1_PACKAGE_VERSION_MANIFEST")
        for f in manifest["files"]:
            relative=f["file"]
            need(PurePosixPath(relative).as_posix()==relative and
                 ".." not in PurePosixPath(relative).parts,"RC1_PACKAGE_PATH")
            raw=z.read(CANDIDATE_PREFIX+relative)
            need(len(raw)==f["bytes"] and sha(raw)==f["sha256"].lower(),
                 "RC1_PACKAGE_FILE_HASH")
        z.extractall(extract)
    src=extract/CANDIDATE_PREFIX.rstrip("/")
    need(src.is_dir(),"CANDIDATE_EXTRACTION")
    return src

def seed_real_protected_root(stable_zip:Path,user,module):
    # Pre-checked empty paths. The runner is disposable and this setup never
    # alters a human workstation or another project. No service is started.
    root=Path("/usr/lib/directinternetmethod")
    root.mkdir(mode=0o755)
    baseline={}
    with zipfile.ZipFile(stable_zip) as z:
        archive_verify(z,STABLE_PREFIX,24)
        items=list(module.STATIC_ROOT.items())
        items.extend((row[2],row[3]) for row in module.FILES if row[3] is not None)
        need(len(items)==11,"R528_BASELINE_FILES_CHANGED")
        for path,want in items:
            member=STABLE_PREFIX+MAPPING[Path(path).name]
            raw=z.read(member)
            need(sha(raw)==want.lower(),"PUBLISHED_BASELINE_MISMATCH_"+Path(path).name)
            dest=Path("/")/path
            need(not dest.exists() and not dest.is_symlink(),
                 "BASELINE_TARGET_ALREADY_EXISTS_"+dest.name)
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(raw)
            mode=0o755 if dest.suffix==".sh" or dest.name in ("ctrld","nfqws","selective_dns.py") else 0o644
            dest.chmod(mode)
            need(dest.stat().st_uid==0 and dest.stat().st_gid==0,
                 "REAL_NATIVE_ROOT_OWNERSHIP")
            baseline[str(dest)]=sha(raw)
    base=Path("/var/lib/directinternetmethod")
    base.mkdir(mode=0o755)
    meta=base/"install.json"
    before={"schema":1,"version":"1.5.2","user":"runner","uid":user.pw_uid,"home":user.pw_dir}
    meta_bytes=(json.dumps(before,sort_keys=True)+"\n").encode()
    meta.write_bytes(meta_bytes)
    meta.chmod(0o644)
    uidfile=Path("/etc/directinternetmethod.uid")
    need(not uidfile.exists() and not uidfile.is_symlink(),"UID_MARKER_PREEXISTS")
    uidfile.write_text(str(user.pw_uid)+"\n")
    uidfile.chmod(0o644)
    baseline[str(meta)]=sha(meta_bytes)
    baseline[str(uidfile)]=sha(uidfile.read_bytes())
    return baseline

def run_native():
    stable,candidate,temp,user=prerequisites()
    network_pre={
        "resolv":fsha(Path("/etc/resolv.conf")),
        "resolvTarget":os.readlink("/etc/resolv.conf") if Path("/etc/resolv.conf").is_symlink() else None,
        "hosts":fsha(Path("/etc/hosts")),
    }
    m=module()
    need(m.TARGET_VERSION=="1.5.7" and
         m.CURRENT_BACKEND_VERSION=="1.5.2","NATIVE_PRODUCT_VERSION")
    source=stage_exact_candidate(candidate,temp)
    baseline=seed_real_protected_root(stable,user,m)
    t=m.RootTransaction()  # EXACT PRODUCT ABSOLUTE "/" ROOT, NOT PREFIX MOCK
    need(t.native and t.root==Path("/"),"REAL_NATIVE_ROOT_MODE")
    need(t.status()["status"]=="NO_PENDING_UPGRADE","ROOT_INITIAL_STATE")
    need(t.stage(source)["status"]=="STAGED","ROOT_STAGE")
    need(t.status()["status"]=="STAGED","ROOT_STAGE_STATUS")
    for path,hash_expected in baseline.items():
        need(fsha(Path(path))==hash_expected,"ROOT_STAGE_MODIFIED_BASELINE")
    pending=Path("/var/lib/directinternetmethod/upgrade-pending")
    need(pending.is_dir() and pending.stat().st_uid==0 and
         stat.S_IMODE(pending.stat().st_mode)==0o700,"ROOT_PENDING_OWNER_MODE")
    need(t.apply()["status"]=="APPLIED","ROOT_APPLY")
    need(t.status()["status"]=="APPLIED","ROOT_APPLY_STATUS")
    for name,relative,target,old,new,mode in m.FILES:
        file=Path("/")/target
        need(file.is_file() and not file.is_symlink() and
             fsha(file)==new.lower() and file.stat().st_uid==0 and
             stat.S_IMODE(file.stat().st_mode)==mode,
             "REAL_ROOT_UPGRADED_FILE_"+name)
    current=json.loads(Path("/var/lib/directinternetmethod/install.json").read_text())
    need(current["version"]=="1.5.7","REAL_ROOT_METADATA_NOT_ACTIVATED")
    try:
        t.commit(temp/"NO_NATIVE_ACCEPTANCE_RECEIPT.json")
        raise RuntimeError("R528_BAD_ACCEPTANCE_WAS_ALLOWED")
    except RuntimeError as exc:
        # R783: the disposable native runner puts its absent receipt under a
        # runner-owned temporary ancestor. The single-descriptor receipt read
        # must fail closed before opening that leaf; an untrusted parent and
        # a missing trusted leaf are both narrowly acceptable reject causes.
        need(("FAIL_CLOSED_NATIVE_ACCEPTANCE_MISSING" in str(exc) or
              "FAIL_CLOSED_RECEIPT_PARENT_OWNER" in str(exc)),
             "UNEXPECTED_ACCEPTANCE_REJECTION")
    need(t.rollback()["status"]=="ROLLED_BACK","ROOT_ROLLBACK")
    need(t.status()["status"]=="ROLLED_BACK","ROOT_ROLLBACK_STATE")
    for path,want in baseline.items():
        need(fsha(Path(path))==want,"ROOT_ROLLBACK_BYTE_DRIFT_"+Path(path).name)
    for name,relative,target,old,new,mode in m.FILES:
        if old is None:
            p=Path("/")/target
            need(not p.exists() and not p.is_symlink(),"NEW_ROOT_FILE_LEFT_"+name)
    for path in m.STATIC_ROOT:
        need(fsha(Path("/")/path)==m.STATIC_ROOT[path].lower(),
             "STATIC_BACKEND_CHANGED_"+Path(path).name)
    need(fsha(Path("/etc/resolv.conf"))==network_pre["resolv"] and
         fsha(Path("/etc/hosts"))==network_pre["hosts"] and
         (os.readlink("/etc/resolv.conf") if Path("/etc/resolv.conf").is_symlink() else None)==network_pre["resolvTarget"],
         "NETWORK_BASELINE_CHANGED")
    need(json.loads((BASE/"RELEASE.json").read_text())["version"]=="1.5.4",
         "PUBLIC_RELEASE_METADATA_CHANGED")
    report={
        "revision":"R528","status":"PASS_REAL_ROOT_STAGE_APPLY_ROLLBACK_ON_EPHEMERAL_GITHUB_VM",
        "productionMachineTouched":False,
        "nativeRoot":True,"effectiveUid":os.geteuid(),"protectedPreVersion":"1.5.2",
        "protectedPostRollbackVersion":"1.5.2",
        "protectedCandidateAppliedBeforeRollback":"1.5.7",
        "publicStablePreserved":"v1.5.4","pinnedSource":CANDIDATE_SHA,
        "pinnedPublishedStable":STABLE_SHA,
        "rootOwnedFilesRestored":len(baseline),
        "newRootTargetsRemoved":2,
        "upgradeSlotRetainedForAudit":pending.exists(),
        "metadataRollbackRestored":True,
        "networkResolvAndHostsUnchanged":True,
        "nativeEncryptedDnsAndGuiAcceptance":"NOT_TESTED",
    }
    print(json.dumps(report,sort_keys=True))
    return 0

if __name__=="__main__":
    try:sys.exit(run_native())
    except Exception as e:
        print(json.dumps({"revision":"R528","status":"FAIL_CLOSED","error":str(e)[:400]}),file=sys.stderr)
        sys.exit(84)
