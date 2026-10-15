#!/usr/bin/env python3
"""R552 native Linux Root/User upgrade watchdog candidate, NOT authorized to arm.

Prepare a pinned root-owned detached systemd rollback guard BEFORE protected
upgrade. Never disable OS authentication, change networking, or act on foreign
owners. The preflight action is unprivileged/read-only. arm/rollback are root
only and are NOT to be used on human hosts before independent hosted validation
and explicit host authorization. No update/install is performed by this file.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time

VERSION="1.5.5-rc1"
BASELINE="1.5.2"
OLD_USER="1.5.4"
PIN_ROOT="EB107164CCEDE891C8BF41C06FF422F1B53B59D2D2DDF0B3DD23EBFE5DE9601B"
PIN_USER="A909BBB12B78875A9438C756AE2DCAFF05E0DF2EBB5551E97544D2B20C46346F"
PIN_PKG="27D5289236A9CDB125669E67269EF16A7C6FCD74AE9300E65B0C8AA2E10B5F70"
GUARD=Path("/var/lib/directinternetmethod/upgrade-guard")
BASELINE_FILE=GUARD/"baseline.json"
RESULT=GUARD/"rollback-result.json"
WORKER=GUARD/"worker.py"
ROOT_TX=GUARD/"root_tx.py"
USER_TX=GUARD/"user_tx.py"
UNIT="directinternetmethod-upgrade-rollback"
SERVICE=Path("/etc/systemd/system")/(UNIT+".service")
TIMER=Path("/etc/systemd/system")/(UNIT+".timer")
USER_REL=".local/share/DirectInternetMethod"
PENDING_REL=".local/state/DirectInternetMethod/update-pending"
RUNNER_OWNER="runner"

def need(ok:bool,label:str):
    if not ok:raise RuntimeError("R552_GUARD_FAIL_CLOSED_"+label)

def sha_file(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):h.update(chunk)
    return h.hexdigest().upper()

def regular(path:Path,uid=None,mode=None):
    need(path.is_file() and not path.is_symlink(),"REGULAR_"+path.name)
    s=path.stat()
    if uid is not None:need(s.st_uid==uid,"OWNER_"+path.name)
    if mode is not None:need(stat.S_IMODE(s.st_mode)==mode,"MODE_"+path.name)
    return s

def canonical(obj):return (json.dumps(obj,indent=2,sort_keys=True)+"\n").encode()

def command(args,timeout=15):
    return subprocess.run(args,text=True,capture_output=True,timeout=timeout,check=False)

def fsync_dir(path:Path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def write_new(path:Path,data:bytes,mode:int):
    need(path.parent.is_dir() and not path.parent.is_symlink(),"WRITER_PARENT")
    need(not path.exists() and not path.is_symlink(),"WRITER_EXISTS_"+path.name)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        with os.fdopen(fd,"wb") as f:
            os.fchmod(f.fileno(),mode)
            f.write(data);f.flush();os.fsync(f.fileno())
        fsync_dir(path.parent)
    finally:
        pass
    regular(path,0,mode)

def checked_owner():
    p=Path("/var/lib/directinternetmethod/install.json")
    regular(p,0,0o644)
    obj=json.loads(p.read_text(encoding="utf8"))
    need(obj.get("schema")==1 and obj.get("version")==BASELINE,"PROTECTED_BASELINE")
    uid=obj.get("uid");user=obj.get("user");home=obj.get("home")
    need(type(uid) is int and 0<uid<2**31,"UID")
    need(isinstance(user,str) and re.fullmatch(r"[a-z_][a-z0-9_-]*[$]?",user),"USER")
    need(isinstance(home,str) and home.startswith("/home/") and
         ".." not in Path(home).parts,"HOME_PATH")
    pw=pwd.getpwuid(uid)
    need(pw.pw_name==user and pw.pw_dir==home,"PASSWD_OWNER")
    need(Path("/etc/directinternetmethod.uid").read_text().strip()==str(uid),"OWNER_MARKER")
    root=Path(home)
    need(root.is_dir() and not root.is_symlink(),"HOME_UNSAFE")
    usermeta=root/USER_REL/"INSTALL.json"
    regular(usermeta,uid)
    meta=json.loads(usermeta.read_text("utf8"))
    need(meta.get("version")==OLD_USER and meta.get("schema")==2,"USER_VERSION")
    return uid,user,root,usermeta,p,meta

def state_is_off(home:Path):
    state=home/USER_REL/"directmethod/state.json"
    need(not state.exists() and not state.is_symlink(),"ACTIVE_DIRECT_ENGINE")
    for p in (Path("/run/directinternetmethod-encrypted"),
              Path("/run/directinternetmethod-encrypted-ctrld.toml"),
              Path("/run/directinternetmethod-selective/session.json"),
              Path("/var/lib/directinternetmethod/upgrade-pending")):
        need(not p.exists() and not p.is_symlink(),"ACTIVE_OR_PENDING_"+p.name)
    return True

def validate_source(source:Path):
    need(source.is_absolute() and source.is_dir() and not source.is_symlink() and
         source.name=="DirectInternetMethod_1.5.5-rc1_Linux_x86_64","SOURCE_LAYOUT")
    manifest=source/"PACKAGE_MANIFEST.json"
    regular(manifest)
    data=json.loads(manifest.read_text("utf8"))
    files=data.get("files")
    need(data.get("version")==VERSION and data.get("schema")==1 and
         isinstance(files,list) and len(files)==26,"PACKAGE_MANIFEST")
    pin={x.get("file"):x.get("sha256") for x in files if isinstance(x,dict)}
    for label,relative,want in (
        ("ROOT_TX","system/protected_upgrade_transaction.py",PIN_ROOT),
        ("USER_TX","app/user_update_transaction.py",PIN_USER)):
        candidate=source/relative
        regular(candidate)
        need(sha_file(candidate)==want and str(pin.get(relative,"")).upper()==want,
             "PACKAGE_"+label)
    return True

def preflight(source:Path):
    validate_source(source)
    uid,user,home,um,rm,_=checked_owner()
    state_is_off(home)
    need(not GUARD.exists() and not GUARD.is_symlink(),"GUARD_EXISTS")
    for p in (SERVICE,TIMER):
        need(not p.exists() and not p.is_symlink(),"UNIT_EXISTS_"+p.name)
    pending=home/PENDING_REL
    need(not pending.is_symlink(),"USER_PENDING_SYMLINK")
    return {"status":"SAFE_SOURCE_AND_INSTALLED_BASELINE_ONLY",
            "needsRootAuthorization":True,"rootVersion":BASELINE,
            "userVersion":OLD_USER,"uid":uid,"packageVersion":VERSION,
            "guardArmed":False,"networkUntouched":True}

def guard_files(source:Path,uid:int,user:str,home:Path,um:Path,rm:Path):
    GUARD.mkdir(mode=0o711)
    os.chown(GUARD,0,0);os.chmod(GUARD,0o711)
    write_new(ROOT_TX,(source/"system/protected_upgrade_transaction.py").read_bytes(),0o500)
    write_new(USER_TX,(source/"app/user_update_transaction.py").read_bytes(),0o644)
    write_new(WORKER,Path(__file__).read_bytes(),0o500)
    dns=Path("/etc/resolv.conf")
    baseline={"schema":1,"revision":"R552","uid":uid,"user":user,
              "home":str(home),"versionFromRoot":BASELINE,
              "versionFromUser":OLD_USER,"versionTo":VERSION,
              "rootTransactionSha":PIN_ROOT,"userTransactionSha":PIN_USER,
              "workerSha":sha_file(WORKER),"oldRootMetaSha":sha_file(rm),
              "oldUserMetaSha":sha_file(um),"oldResolverSha":sha_file(dns),
              "oldResolverLink":os.readlink(dns) if dns.is_symlink() else None,
              "createdUtc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
              "timerSeconds":480,"networkMutationByWatchdog":False}
    write_new(BASELINE_FILE,canonical(baseline),0o600)
    return baseline

def unit_templates():
    service=("[Unit]\nDescription=Direct Internet Method guarded root+user upgrade rollback\n"
             "After=local-fs.target\n"
             "[Service]\nType=oneshot\nUser=root\nGroup=root\n"
             "ExecStart=/usr/bin/python3 -B "+str(WORKER)+" rollback\n"
             "TimeoutStartSec=120\nNoNewPrivileges=false\nUMask=0077\n")
    timer=("[Unit]\nDescription=Direct Internet Method guarded upgrade timeout\n"
           "[Timer]\nOnActiveSec=480s\nAccuracySec=1s\n"
           "Unit="+UNIT+".service\n"
           "[Install]\nWantedBy=timers.target\n")
    return service.encode(),timer.encode()

def staged_user_manifest(home:Path,uid:int,installed:Path):
    """Attest the ACTUAL v1.5.5 User stage schema; no invented phase field."""
    pending=home/PENDING_REL
    need(pending.is_dir() and not pending.is_symlink(),"STAGED_USER_PENDING_REQUIRED")
    need(pending.stat().st_uid==uid and stat.S_IMODE(pending.stat().st_mode)==0o700,
         "PENDING_OWNER_OR_MODE")
    manifest=pending/"manifest.json"
    regular(manifest,uid,0o600)
    j=json.loads(manifest.read_text("utf8"))
    need(isinstance(j,dict) and j.get("schema")==1 and
         j.get("version")==VERSION and j.get("previousVersion")==OLD_USER,
         "USER_STAGE_IDENTITY")
    managed=j.get("managed");prior=j.get("old");mutable=j.get("mutable")
    need(isinstance(managed,dict) and len(managed) in (7,8) and
         isinstance(prior,dict) and set(prior)==set(managed)|{"INSTALL.json"} and
         isinstance(mutable,dict) and len(mutable)==9,
         "USER_STAGE_FILESET")
    meta=prior["INSTALL.json"]
    need(isinstance(meta,dict) and meta.get("exists") is True and
         str(meta.get("sha","")).lower()==sha_file(installed).lower(),
         "USER_BASELINE_METADATA_CHANGED")
    return j

def arm(source:Path,expected_uid:int):
    need(os.geteuid()==0,"ROOT_REQUIRED")
    status=preflight(source)
    uid,user,home,um,rm,meta=checked_owner()
    need(uid==expected_uid,"USER_IDENTITY_CHANGED")
    staged_user_manifest(home,uid,um)
    baseline=guard_files(source,uid,user,home,um,rm)
    s,t=unit_templates()
    write_new(SERVICE,s,0o644)
    write_new(TIMER,t,0o644)
    for cmd in ([ "/usr/bin/systemctl","daemon-reload"],
                ["/usr/bin/systemctl","enable","--now",UNIT+".timer"]):
        r=command(cmd)
        need(r.returncode==0,"SYSTEMD_ARM_"+r.stderr[-120:].replace(" ","_"))
    verify_timer()
    return {"status":"ARMED_INDEPENDENT_ROOT_USER_WATCHDOG",
            "armed":True,"ownedGuard":str(GUARD),
            "sourceSha":baseline["workerSha"],"timer":UNIT+".timer"}

def verify_guard_files():
    regular(WORKER,0,0o500)
    regular(ROOT_TX,0,0o500);regular(USER_TX,0,0o644)
    regular(BASELINE_FILE,0,0o600)
    need(GUARD.is_dir() and not GUARD.is_symlink() and GUARD.stat().st_uid==0 and
         stat.S_IMODE(GUARD.stat().st_mode)==0o711,"GUARD_OWNER")
    j=json.loads(BASELINE_FILE.read_text("utf8"))
    need(j.get("revision")=="R552" and j.get("workerSha")==sha_file(WORKER)
         and sha_file(ROOT_TX)==PIN_ROOT and sha_file(USER_TX)==PIN_USER,
         "GUARD_SOURCE_SHA")
    for p in (SERVICE,TIMER):regular(p,0,0o644)
    return j

def verify_timer():
    j=verify_guard_files()
    p=command(["/usr/bin/systemctl","show",UNIT+".timer",
              "--property=ActiveState,LoadState,UnitFileState,Triggers","--no-pager"])
    need(p.returncode==0,"TIMER_QUERY")
    need("ActiveState=active" in p.stdout and "LoadState=loaded" in p.stdout
         and "UnitFileState=enabled" in p.stdout and
         UNIT+".service" in p.stdout,"TIMER_NOT_INDEPENDENT_ACTIVE")
    return j

def imported_root():
    spec=importlib.util.spec_from_file_location("dim_r552_root_tx",ROOT_TX)
    need(spec is not None and spec.loader is not None,"ROOT_IMPORT")
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.RootTransaction()

def verify_installed_after_restore(j):
    uid,user,home,um,rm,_=checked_owner()
    need(uid==j["uid"] and user==j["user"] and str(home)==j["home"],"RESTORED_OWNER")
    need(sha_file(rm)==j["oldRootMetaSha"],"RESTORED_ROOT_META_SHA")
    need(sha_file(um)==j["oldUserMetaSha"],"RESTORED_USER_META_SHA")
    dns=Path("/etc/resolv.conf")
    need(sha_file(dns)==j["oldResolverSha"] and
         (os.readlink(dns) if dns.is_symlink() else None)==j["oldResolverLink"],
         "DNS_CHANGED_EXTERNALLY")
    need(not (home/PENDING_REL).exists(),"USER_SLOT_REMAINS")

def rollback_worker():
    need(os.geteuid()==0 and Path(__file__).resolve()==WORKER,"OWNED_WORKER_ROOT_REQUIRED")
    start=time.monotonic()
    report={"revision":"R552","status":"DEGRADED_UNRESOLVED",
            "whenUtc":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
            "uid":os.geteuid(),"networkMutationAttempted":False,
            "recoveryAttempted":False}
    try:
        # A one-shot monotonic timer may no longer be ActiveState=active
        # while it is executing its service. Validate root-owned guard bytes
        # instead of misclassifying a correctly fired timer as unsafe.
        j=verify_guard_files()
        home=Path(j["home"])
        pending=home/PENDING_REL
        tx=imported_root()
        need(tx.native,"REAL_ROOT_TRANSACTION")
        phase=tx.status()["status"]
        # Never replace installed code underneath a live owned network engine.
        # Such an ambiguous state requires local authorized Recovery first.
        need(not (home/USER_REL/"directmethod/state.json").exists(),
             "LIVE_ENGINE_REQUIRES_LOCAL_RECOVERY")
        report["rootPhaseBefore"]=phase
        if phase=="COMMITTED":
            need(not pending.exists(),"COMMITTED_USER_PENDING")
            report["status"]="NO_ROLLBACK_ALREADY_COMMITTED"
        elif phase=="NO_PENDING_UPGRADE" and not pending.exists():
            report["status"]="NO_CHANGE_NO_PENDING"
        else:
            need(phase in ("STAGED","APPLIED","DEGRADED","NO_PENDING_UPGRADE"),"UNKNOWN_ROOT_PHASE")
            report["recoveryAttempted"]=True
            if pending.exists():
                need(pending.is_dir() and not pending.is_symlink(),"UNSAFE_USER_SLOT")
                p=command(["/usr/sbin/runuser","-u",j["user"],"--",
                           "/usr/bin/env","HOME="+j["home"],
                           "PYTHONDONTWRITEBYTECODE=1","/usr/bin/python3","-B",
                           str(USER_TX),"--rollback"],timeout=45)
                need(p.returncode==0,"USER_ROLLBACK_"+p.stderr[-180:].replace(" ","_"))
                report["userRollback"]="PASS"
            if phase in ("STAGED","APPLIED","DEGRADED"):
                returned=tx.rollback()
                need(returned.get("status")=="ROLLED_BACK","ROOT_ROLLBACK")
                report["rootRollback"]="PASS"
            verify_installed_after_restore(j)
            report["status"]="PASS_AUTONOMOUS_TWO_SIDED_RESTORATION"
    except Exception as ex:
        report["failure"]=type(ex).__name__+":"+str(ex)[:320]
    report["durationSeconds"]=round(time.monotonic()-start,3)
    if not RESULT.exists() and not RESULT.is_symlink():
        write_new(RESULT,canonical(report),0o600)
    print(json.dumps(report,sort_keys=True))
    return 0 if report["status"] in (
        "NO_ROLLBACK_ALREADY_COMMITTED","NO_CHANGE_NO_PENDING",
        "PASS_AUTONOMOUS_TWO_SIDED_RESTORATION") else 90

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("action",choices=("preflight","arm","status","rollback"))
    parser.add_argument("--source",type=Path)
    parser.add_argument("--uid",type=int)
    opts=parser.parse_args()
    if opts.action in ("preflight","arm"):
        need(opts.source is not None,"SOURCE_REQUIRED")
        if opts.action=="preflight":
            print(json.dumps(preflight(opts.source),sort_keys=True))
        else:
            need(opts.uid is not None,"UID_REQUIRED")
            print(json.dumps(arm(opts.source,opts.uid),sort_keys=True))
    elif opts.action=="status":
        need(os.geteuid()==0,"ROOT_REQUIRED")
        print(json.dumps({"status":"ARMED",**verify_timer()},sort_keys=True))
    else:
        raise SystemExit(rollback_worker())

if __name__=="__main__":
    try:main()
    except Exception as e:
        print(json.dumps({"ok":False,"error":str(e)[:350]}),file=sys.stderr)
        sys.exit(82)
