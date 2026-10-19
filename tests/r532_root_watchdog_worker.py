#!/usr/bin/env python3
"""R532 independent root-owned timer worker on disposable GitHub Ubuntu VM.

Copied to /run/dim-r532 with root ownership BEFORE candidate mutation.
Executes only when systemd transient one-shot monotonic timer fires.
Never changes network, resolver, service, Tailscale or user preferences.
Refuses foreign files; product user/root transactions do their own checks.
NOT A PRODUCTION WATCHDOG; only tests the release gate in an ephemeral VM.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import time

GUARD = Path("/run/dim-r532")
MANIFEST = GUARD / "baseline.json"
RESULT = GUARD / "timer-return.json"
ROOT_HELPER = GUARD / "root_tx.py"
USER_HELPER = GUARD / "user_tx.py"
PIN_ROOT = "6abd10a709f68f4330b97cf903cb13e231ceb1b763ad9a378f422ea4f6a1e9a0"
PIN_USER = "c1bbf62d99e46cb8e349a38e60891027ff7276f85caceb597548c269203f28bf"

def digest(path:Path):
    h=hashlib.sha256()
    with path.open("rb") as inp:
        for p in iter(lambda:inp.read(1048576),b""):
            h.update(p)
    return h.hexdigest()

def require(ok,where):
    if not ok:
        raise RuntimeError("R532_GUARD_FAIL_CLOSED_"+where)

def valid_root_file(p:Path,mode=None):
    require(p.is_file() and not p.is_symlink(),"FILE_TYPE_"+p.name)
    s=p.stat()
    require(s.st_uid==0 and s.st_gid==0 and stat.S_ISREG(s.st_mode),
            "ROOT_OWNER_"+p.name)
    if mode is not None:
        require(stat.S_IMODE(s.st_mode)==mode,"MODE_"+p.name)

def write_once(outcome:dict):
    raw=(json.dumps(outcome,sort_keys=True,indent=2)+"\n").encode()
    fd=os.open(RESULT,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as handle:
        os.fchmod(handle.fileno(),0o600)
        handle.write(raw);handle.flush();os.fsync(handle.fileno())
    directory=os.open(GUARD,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(directory)
    finally:os.close(directory)

def module(path:Path):
    spec=importlib.util.spec_from_file_location("dim_r532_copied_protected_root",path)
    require(spec is not None and spec.loader is not None,"PINNED_ROOT_IMPORT")
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

def verify_receipt(doc):
    require(doc.get("revision")=="R532" and doc.get("schema")==1,"BASELINE_SCHEMA")
    require(doc.get("host")==os.uname().nodename,"HOST_CHANGED")
    require(doc.get("ownerUser")=="runner","UNEXPECTED_USER")
    u=pwd.getpwnam("runner")
    require(doc.get("ownerUid")==u.pw_uid and u.pw_dir=="/home/runner","USER_IDENTITY")
    require(doc.get("productionMachineTouched") is False,"SANDBOX_AUTHORITY")
    require(doc.get("rootHelperSHA256")==PIN_ROOT and
            doc.get("userHelperSHA256")==PIN_USER,"SOURCE_PIN_DECLARATION")
    require(doc.get("expectedRootVersion")=="1.5.2" and
            doc.get("expectedUserVersion")=="1.5.4","EXPECTED_VERSIONS")
    for key in ("protected","userCode","userMutable","network"):
        require(isinstance(doc.get(key),dict) and doc[key],"MISSING_BASELINE_"+key)
        for name,hashed in doc[key].items():
            path=Path(name)
            require(path.is_absolute() and
                    (name.startswith("/home/runner/.local/share/DirectInternetMethod/") or
                     name.startswith("/usr/lib/directinternetmethod/") or
                     name in ("/var/lib/directinternetmethod/install.json",
                              "/etc/directinternetmethod.uid",
                              "/etc/resolv.conf","/etc/hosts")),
                    "BASELINE_PATH_OUTSIDE_ALLOWLIST")
            require(isinstance(hashed,str) and len(hashed)==64,"BAD_BASELINE_SHA")
    require(doc.get("resolvLink")==(
        os.readlink("/etc/resolv.conf") if Path("/etc/resolv.conf").is_symlink() else None),
        "SYSTEM_RESOLVER_LINK_CHANGED")
    return u

def main():
    started=time.monotonic()
    outcome={"revision":"R532","status":"FAIL_UNRESOLVED",
             "mode":"SYSTEMD_TRANSIENT_INDEPENDENT_MONOTONIC_TIMER",
             "utc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
             "actualEffectiveUid":os.geteuid(),
             "productionMachineTouched":False,
             "mutatedNetworkOrTailscale":False,
             "recoveryAttempted":False}
    try:
        require(os.geteuid()==0 and sys.platform.startswith("linux"),"ROOT_LINUX")
        require(GUARD.is_dir() and not GUARD.is_symlink() and
                GUARD.stat().st_uid==0 and stat.S_IMODE(GUARD.stat().st_mode)==0o711,
                "INDEPENDENT_ROOT_DIR")
        require(not RESULT.exists() and not RESULT.is_symlink(),"ONCE_ONLY")
        for p,m in ((Path(__file__),0o500),(MANIFEST,0o600),(ROOT_HELPER,0o500),
                    (USER_HELPER,0o644)):
            valid_root_file(p,m)
        require(digest(ROOT_HELPER)==PIN_ROOT and digest(USER_HELPER)==PIN_USER,
                "ROOT_OWNED_PINNED_TX_CHANGED")
        baseline=json.loads(MANIFEST.read_text(encoding="utf8"))
        owner=verify_receipt(baseline)
        src=module(ROOT_HELPER)
        txn=src.RootTransaction()
        require(txn.native and txn.root==Path("/"),"NATIVE_ROOT_LOCK_AUTHORITY")
        pending=Path("/home/runner/.local/state/DirectInternetMethod/update-pending")
        root_phase=txn.status().get("status")
        outcome["preRollbackRootPhase"]=root_phase
        require(root_phase in ("STAGED","APPLIED","DEGRADED","ROLLED_BACK"),
                "ROOT_PENDING_MISSING_OR_ALREADY_COMMITTED")
        require(pending.is_dir() and not pending.is_symlink(),"USER_PENDING_NOT_FOUND")
        outcome["recoveryAttempted"]=True
        # Rollback user-owned files first while original protected baseline
        # still has an independently protected rollback slot.
        user=subprocess.run(
            ["/usr/sbin/runuser","-u",owner.pw_name,"--","/usr/bin/env",
             "HOME=/home/runner","PYTHONDONTWRITEBYTECODE=1","/usr/bin/python3","-B",
             str(USER_HELPER),"--rollback"],
            capture_output=True,text=True,timeout=35,check=False)
        require(user.returncode==0,
                "USER_ROLLBACK_"+user.stderr[-180:].replace(" ","_"))
        outcome["userRollback"]="PASS"
        if root_phase in ("STAGED","APPLIED","DEGRADED"):
            new=txn.rollback()
            require(new.get("status")=="ROLLED_BACK","ROOT_ROLLBACK_NOT_ACCEPTED")
        require(txn.status().get("status")=="ROLLED_BACK",
                "ROOT_PENDING_PHASE_NOT_ROLLED_BACK")
        outcome["protectedRootRollback"]="PASS"
        require(not pending.exists(),"USER_SLOT_NOT_CLEANED")
        require(json.loads(Path("/var/lib/directinternetmethod/install.json").read_text())["version"]=="1.5.2",
                "ROOT_VERSION_NOT_RESTORED")
        require(json.loads(Path("/home/runner/.local/share/DirectInternetMethod/INSTALL.json").read_text())["version"]=="1.5.4",
                "USER_VERSION_NOT_RESTORED")
        for kind in ("protected","userCode","userMutable","network"):
            for name,baseline_sha in baseline[kind].items():
                target=Path(name)
                require(target.is_file() and not target.is_symlink() or name=="/etc/resolv.conf" and target.is_symlink(),
                        "RESTORED_TYPE_"+target.name)
                require(digest(target)==baseline_sha,
                        "RESTORED_SHA_"+kind+"_"+target.name)
        for name in baseline.get("originalAbsentProtected",[]):
            file=Path(name)
            require(not file.exists() and not file.is_symlink(),"NEW_ROOT_BINARY_REMAINS")
        require(not Path("/home/runner/.local/share/DirectInternetMethod/directmethod/state.json").exists(),
                "OWNED_ENGINE_STATE_NOT_ABSENT")
        outcome["restoredFiles"]={
            name:len(baseline[name]) for name in ("protected","userCode","userMutable","network")}
        outcome["status"]="PASS_ROOT_USER_BYTE_EXACT_AUTONOMOUS_ROLLBACK"
    except BaseException as ex:
        outcome["failure"]=type(ex).__name__+":"+str(ex)[:350]
        outcome["status"]="DEGRADED_UNRESOLVED"
    finally:
        outcome["durationSec"]=round(time.monotonic()-started,3)
        try:
            write_once(outcome)
        except BaseException as ex:
            print("R532_RECEIPT_FAILED",type(ex).__name__,str(ex)[:220],file=sys.stderr)
            outcome["receiptWriteFailed"]=True
        print(json.dumps(outcome,sort_keys=True))
    if outcome.get("receiptWriteFailed"):
        return 91
    return 0 if outcome["status"]=="PASS_ROOT_USER_BYTE_EXACT_AUTONOMOUS_ROLLBACK" else 90

if __name__=="__main__":
    sys.exit(main())
