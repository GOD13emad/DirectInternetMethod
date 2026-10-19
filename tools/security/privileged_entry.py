#!/usr/bin/env python3
"""Review-only R781 trusted Linux Root entry (NOT installed or authorized).

An OS administrator must first provision this exact, audited source at
/usr/local/libexec/directinternetmethod/privileged_entry.py as a root-owned 0500 file.
Never call pkexec on package-provided bash/python. No implicit sudo policy.

One frozen manifest SHA is an *authority from this root-owned file*, not
from untrusted argv or the downloaded package. A later release requires a
separately reviewed trust-anchor update; this is not a generic updater.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile

VERSION = "1.5.5-rc1"
PACKAGE = "DirectInternetMethod_1.5.5-rc1_Linux_x86_64"
MANIFEST_SHA256 = "E3D6186F8BC775FA7861DD506AA1EB978F6296BDC98D686CD3731C79680FEB42"
TRUSTED_ENTRY = Path("/usr/local/libexec/directinternetmethod/privileged_entry.py")
MAX_ITEM = 16 * 1024 * 1024
MAX_ALL = 48 * 1024 * 1024
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK

class AdmissionError(RuntimeError):
    pass

def require(value:bool, code:str)->None:
    if not value:
        raise AdmissionError("R781_REJECT_"+code)

def sha(data:bytes)->str:
    return hashlib.sha256(data).hexdigest().upper()

def _object_no_duplicates(pairs):
    result = {}
    for key,value in pairs:
        require(key not in result,"DUPLICATE_JSON_FIELD")
        result[key] = value
    return result

def strict_json(data:bytes):
    return json.loads(data.decode("utf-8"), object_pairs_hook=_object_no_duplicates)

def checked_parts(path:Path)->tuple[str,...]:
    require(path.is_absolute(),"SOURCE_MUST_BE_ABSOLUTE")
    parts = path.parts[1:]
    require(all(x not in ("", ".", "..") for x in parts) and len(parts)>0,
            "SOURCE_PATH_COMPONENTS")
    return parts

def open_pinned_directory(path:Path)->int:
    parts=checked_parts(path)
    parent=os.open("/",DIR_FLAGS)
    try:
        for comp in parts:
            try:
                child=os.open(comp,DIR_FLAGS,dir_fd=parent)
            except OSError as exc:
                raise AdmissionError("R781_REJECT_SOURCE_DIR_NOFOLLOW") from exc
            os.close(parent)
            parent=child
        return parent
    except BaseException:
        os.close(parent)
        raise

def read_pinned(root_fd:int,relative:str,max_bytes:int)->bytes:
    entry=PurePosixPath(relative)
    pieces=entry.parts
    require(0<len(pieces)<=6 and not entry.is_absolute() and
            all(c not in (".","..","") for c in pieces) and "\\" not in relative,
            "MEMBER_PATH")
    fd=os.dup(root_fd)
    leaf=None
    try:
        for part in pieces[:-1]:
            try:
                nxt=os.open(part,DIR_FLAGS,dir_fd=fd)
            except OSError as exc:
                raise AdmissionError("R781_REJECT_MEMBER_DIR_NOFOLLOW") from exc
            os.close(fd)
            fd=nxt
        try:
            leaf=os.open(pieces[-1],FILE_FLAGS,dir_fd=fd)
        except OSError as exc:
            raise AdmissionError("R781_REJECT_MEMBER_FILE_NOFOLLOW") from exc
        st=os.fstat(leaf)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
                0<=st.st_size<=max_bytes,"MEMBER_REGULAR_SIZE_LINK")
        with os.fdopen(os.dup(leaf),"rb") as stream:
            data=stream.read(max_bytes+1)
        require(len(data)==st.st_size and len(data)<=max_bytes,
                "MEMBER_BYTES_CHANGED")
        return data
    finally:
        if leaf is not None: os.close(leaf)
        os.close(fd)

def package_inventory(source_fd:int):
    manifest=read_pinned(source_fd,"PACKAGE_MANIFEST.json",128*1024)
    require(sha(manifest)==MANIFEST_SHA256,"TRUSTED_MANIFEST_DIGEST")
    m=strict_json(manifest)
    require(type(m) is dict and m.get("schema")==1 and
            m.get("version")==VERSION and m.get("platform")=="linux-x86_64",
            "MANIFEST_IDENTITY")
    entries=m.get("files")
    require(type(entries) is list and len(entries)==28,"INVENTORY_COUNT")
    names=set()
    total=0
    for row in entries:
        require(type(row) is dict and set(row)=={"file","bytes","sha256"},
                "MANIFEST_MEMBER_FIELDS")
        name,size,hashval=row["file"],row["bytes"],row["sha256"]
        require(type(name) is str and name not in names,"MANIFEST_DUPLICATE_PATH")
        name_parts=PurePosixPath(name).parts
        require(0<len(name_parts)<=6 and not PurePosixPath(name).is_absolute() and
                all(x not in ("", ".", "..") for x in name_parts) and
                "\\" not in name,"MANIFEST_UNSAFE_PATH")
        require(type(size) is int and 0<=size<=MAX_ITEM,"MANIFEST_BAD_BYTES")
        require(type(hashval) is str and len(hashval)==64 and
                all(c in "0123456789ABCDEF" for c in hashval),
                "MANIFEST_BAD_SHA")
        names.add(name)
        total+=size
    require(total<=MAX_ALL and
            {"install.sh","system/install_system.sh","system/upgrade_system.sh",
             "system/upgrade_guard.py","system/protected_upgrade_transaction.py",
             "app/user_update_transaction.py"}.issubset(names),
            "MANIFEST_CRITICAL_MEMBERS")
    sums="".join(f'{row["sha256"]}  {row["file"]}\n' for row in entries).encode()
    require(read_pinned(source_fd,"SHA256SUMS.txt",8192)==sums,
            "SHA256SUMS_NOT_CANONICAL")
    return manifest,entries

def _copy_new(p:Path,data:bytes):
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        with os.fdopen(fd,"wb") as out:
            fd=-1
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
    finally:
        if fd>=0:os.close(fd)

def freeze_package(source:Path,staging_root:Path,uid:int)->Path:
    """Pure source->private copy, isolated user-local in tests, root-only in CLI."""
    source=Path(source)
    require(source.name==PACKAGE and type(uid) is int and 0<uid<2**31,
            "EXPECTED_PACKAGE_AND_UID")
    require(staging_root.is_dir() and not staging_root.is_symlink(),
            "PRIVATE_STAGE_REQUIRED")
    protected=staging_root.stat()
    require(stat.S_IMODE(protected.st_mode)==0o700 and
            protected.st_uid==os.geteuid(),"PRIVATE_STAGE_OWNER_MODE")
    sourcefd=open_pinned_directory(source)
    try:
        src_st=os.fstat(sourcefd)
        require(src_st.st_uid==uid and stat.S_ISDIR(src_st.st_mode),
                "PACKAGE_SOURCE_OWNER")
        manifest,rows=package_inventory(sourcefd)
        # No user-provided digest controls acceptance; a root-owned helper
        # attests the entire candidate before executing any contained script.
        staged=staging_root/PACKAGE
        require(not staged.exists() and not staged.is_symlink(),
                "STAGED_SOURCE_EXISTS")
        staged.mkdir(mode=0o700)
        _copy_new(staged/"PACKAGE_MANIFEST.json",manifest)
        sums="".join(f'{r["sha256"]}  {r["file"]}\n' for r in rows).encode()
        _copy_new(staged/"SHA256SUMS.txt",sums)
        for row in rows:
            name=row["file"]
            blob=read_pinned(sourcefd,name,row["bytes"])
            require(len(blob)==row["bytes"] and sha(blob)==row["sha256"],
                    "PINNED_PAYLOAD_SHA")
            dest=staged.joinpath(*PurePosixPath(name).parts)
            dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            _copy_new(dest,blob)
        # Preserve the root-owned /run parent 0700. The package *leaf* is
        # marked with the invoking UID for the existing wrapper's owner check;
        # the invoker cannot traverse the root-owned parent.
        if os.geteuid()==0:
            os.chown(staged,uid,-1)
        else:
            require(uid==os.geteuid(),"NONROOT_TEST_UID_MISMATCH")
        staged.chmod(0o500)
        return staged
    finally:
        os.close(sourcefd)

def check_trusted_entry():
    require(os.geteuid()==0,"ROOT_REQUIRED")
    require(Path(__file__).absolute()==TRUSTED_ENTRY,
            "ROOT_OWNED_ENTRY_PATH")
    # Keep the administrator-provisioned executable outside product backend
    # so first-install can legitimately start from an otherwise empty host.
    for p in (Path("/usr"),Path("/usr/local"),Path("/usr/local/libexec"),
              Path("/usr/local/libexec/directinternetmethod"),TRUSTED_ENTRY):
        s=p.lstat()
        require(not stat.S_ISLNK(s.st_mode) and s.st_uid==0 and
                s.st_gid==0 and not (s.st_mode & 0o022),
                "ROOT_TRUST_ANCESTOR_OWNER_MODE")
    st=TRUSTED_ENTRY.lstat()
    require(stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o500 and
            st.st_nlink==1,"ROOT_ENTRY_EXACT_FILE_MODE")
    require("PKEXEC_UID" in os.environ and os.environ["PKEXEC_UID"].isdigit(),
            "NATIVE_PKEXEC_AUTH_REQUIRED")

def main():
    args=argparse.ArgumentParser()
    args.add_argument("--action",required=True,choices=("upgrade","install"))
    args.add_argument("--source",required=True)
    opts=args.parse_args()
    check_trusted_entry()
    uid=int(os.environ["PKEXEC_UID"])
    require(0<uid<2**31 and pwd.getpwuid(uid).pw_uid==uid,
            "CALLING_ACCOUNT_IDENTITY")
    require(Path("/run").is_dir() and Path("/run").stat().st_uid==0,
            "TRUSTED_RUN_DIR")
    temp=Path(tempfile.mkdtemp(prefix="dim-trusted-root-",dir="/run"))
    try:
        require(temp.stat().st_uid==0 and
                stat.S_IMODE(temp.stat().st_mode)==0o700,
                "TEMP_ROOT_OWNERSHIP")
        source=freeze_package(Path(opts.source),temp,uid)
        script=source/"system"/("upgrade_system.sh" if opts.action=="upgrade"
                              else "install_system.sh")
        require(script.is_file() and script.stat().st_uid==0,
                "ROOT_FROZEN_SCRIPT")
        safe_env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","HOME":"/root",
                  "LANG":"C","PYTHONDONTWRITEBYTECODE":"1"}
        done=subprocess.run(["/bin/bash",str(script),str(source),str(uid)],
                            cwd="/",env=safe_env,check=False,timeout=900)
        raise SystemExit(done.returncode)
    finally:
        # The independent Root watchdog owns its persistent rollback copy.
        # Only this ephemeral frozen source tree belongs to the bootstrap.
        shutil.rmtree(temp)

if __name__=="__main__":
    try:main()
    except AdmissionError as exc:
        print(str(exc),file=sys.stderr)
        raise SystemExit(86)
