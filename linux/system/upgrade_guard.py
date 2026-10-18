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
import datetime
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
PIN_ROOT="5A50FDBF3D8CC207FEBA35B85274606E226508AB3D5059DF231789E0D947A616"
PIN_USER="C1BBF62D99E46CB8E349A38E60891027FF7276F85CACEB597548C269203F28BF"
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
         isinstance(files,list) and len(files)==28,"PACKAGE_MANIFEST")
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
              "timerSeconds":480,"deadlineUnix":int(time.time())+480,
              "networkMutationByWatchdog":False}
    write_new(BASELINE_FILE,canonical(baseline),0o600)
    return baseline

def unit_templates(deadline_unix:int):
    need(type(deadline_unix) is int and deadline_unix>0,"INVALID_CALENDAR_DEADLINE")
    deadline=datetime.datetime.fromtimestamp(deadline_unix,datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    service=("[Unit]\nDescription=Direct Internet Method guarded root+user upgrade rollback\n"
             "After=local-fs.target\n"
             "[Service]\nType=oneshot\nUser=root\nGroup=root\n"
             "ExecStart=/usr/bin/python3 -B "+str(WORKER)+" rollback\n"
             "TimeoutStartSec=120\nNoNewPrivileges=false\nUMask=0077\n")
    timer=("[Unit]\nDescription=Direct Internet Method guarded upgrade timeout\n"
           "[Timer]\nOnActiveSec=480s\nOnCalendar="+deadline+"\nPersistent=true\nAccuracySec=1s\n"
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
    s,t=unit_templates(baseline["deadlineUnix"])
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
    need(j.get("timerSeconds")==480 and
         type(j.get("deadlineUnix")) is int and
         j["deadlineUnix"]>0,"BASELINE_DEADLINE")
    service,timer=unit_templates(j["deadlineUnix"])
    need(SERVICE.read_bytes()==service and TIMER.read_bytes()==timer,
         "ROOT_OWNED_TIMER_BYTES_CHANGED")
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

def finish_accepted_pair(j,tx,home:Path,pending:Path):
    """Resume only a ROOT-ACCEPTED pair; never invent acceptance or rollback it.

    Root's COMMITTED manifest is a privileged durable decision. The original
    user slot stays intact until the exact copied user transaction validates
    all managed bytes, mutable settings and new INSTALL.json and commits.
    An ambiguous/foreign state fails closed and retains its recovery evidence.
    """
    m=tx.manifest()
    need(m.get("phase")=="COMMITTED" and m.get("toVersion")==VERSION and
         m.get("fromVersion")==BASELINE and m.get("uid")==j["uid"] and
         m.get("home")==str(home),"ROOT_ACCEPTANCE_MANIFEST")
    tx._validate_slot(m)
    states,meta=tx._target_states(m)
    need(set(states)==set(m["files"]) and
         all(states[k]==m["files"][k]["new"] for k in states) and
         meta==m["newMetadataSHA"],"ACCEPTED_ROOT_BINARY_OR_METADATA_DRIFT")
    rootmeta=json.loads(tx.meta.read_text("utf8"))
    need(rootmeta.get("version")==VERSION and rootmeta.get("uid")==j["uid"],
         "ACCEPTED_ROOT_INSTALL_IDENTITY")
    usermeta=home/USER_REL/"INSTALL.json"
    regular(usermeta,j["uid"],0o600)
    installed=json.loads(usermeta.read_text("utf8"))
    need(installed.get("schema")==2 and installed.get("version")==VERSION and
         installed.get("protectedBackendVersion")==VERSION,
         "ACCEPTED_USER_INSTALL_IDENTITY")
    was_pending=pending.exists() or pending.is_symlink()
    if was_pending:
        need(pending.is_dir() and not pending.is_symlink() and
             pending.stat().st_uid==j["uid"],"ACCEPTED_USER_SLOT_FOREIGN")
        job=command(["/usr/sbin/runuser","-u",j["user"],"--",
                     "/usr/bin/env","HOME="+j["home"],
                     "PYTHONDONTWRITEBYTECODE=1","/usr/bin/python3","-B",
                     str(USER_TX),"--commit"],timeout=45)
        need(job.returncode==0,"USER_FORWARD_COMMIT_"+job.stderr[-180:].replace(" ","_"))
    need(not pending.exists() and not pending.is_symlink(),
         "ACCEPTED_USER_PENDING_REMAINS")
    # No network actions; no root backups are destroyed by this worker.
    return was_pending

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
        report["rootPhaseBefore"]=phase
        if phase=="COMMITTED":
            # Root acceptance is already durable and cannot be rolled back.
            # If its user partner was interrupted during finalization, resume
            # exact user-only commit after validating both installed sides.
            # An active engine may continue because this deletes ONLY the
            # owned user code backup, not the active network or program files.
            report["finalizationAttempted"]=pending.exists()
            finished=finish_accepted_pair(j,tx,home,pending)
            if finished:
                report["userForwardCommit"]="PASS"
                report["status"]="PASS_RESUMED_ACCEPTED_ROOT_USER_COMMIT"
            else:
                report["status"]="NO_ROLLBACK_ALREADY_COMMITTED"
        else:
            # Before Root acceptance, replacing installed code under a live
            # engine is unsafe; require authorized local Recovery.
            need(not (home/USER_REL/"directmethod/state.json").exists(),
                 "LIVE_ENGINE_REQUIRES_LOCAL_RECOVERY")
            if phase=="ROLLED_BACK":
                # R751: independent OnActiveSec/OnCalendar timer expressions may
                # re-activate the service after the first successful rollback.
                # Verify terminal Root/User bytes and the immutable original
                # root-owned success receipt; NEVER roll back a second time,
                # overwrite its evidence, or auto-retire the guard/slot here.
                need(not pending.exists() and not pending.is_symlink(),
                     "ROLLEDBACK_USER_PENDING_REMAINS")
                regular(RESULT,0,0o600)
                need(RESULT.stat().st_nlink==1,"ROLLEDBACK_RECEIPT_HARDLINK")
                receipt_bytes=RESULT.read_bytes()
                prior=json.loads(receipt_bytes)
                need(receipt_bytes==canonical(prior),"ROLLEDBACK_RECEIPT_NONCANONICAL")
                need(prior.get("revision")=="R552" and
                     prior.get("status")=="PASS_AUTONOMOUS_TWO_SIDED_RESTORATION" and
                     prior.get("rootRollback")=="PASS" and
                     prior.get("userRollback")=="PASS" and
                     prior.get("recoveryAttempted") is True and
                     prior.get("networkMutationAttempted") is False and
                     prior.get("uid")==0,
                     "ROLLEDBACK_PRIOR_RECEIPT_NOT_SUCCESSFUL")
                m=tx.manifest()
                need(m.get("phase")=="ROLLED_BACK" and
                     m.get("fromVersion")==BASELINE and
                     m.get("toVersion")==VERSION and
                     m.get("uid")==j["uid"] and
                     m.get("home")==j["home"] and
                     m.get("oldMetadataSHA")==j["oldRootMetaSha"],
                     "ROLLEDBACK_FOREIGN_ROOT_TRANSACTION")
                tx._validate_slot(m)
                states,metadata=tx._target_states(m)
                need(set(states)==set(m["files"]) and
                     all(states[name]==m["files"][name]["old"] for name in states) and
                     metadata==m["oldMetadataSHA"],
                     "ROLLEDBACK_ORIGINAL_ROOT_BYTES_CHANGED")
                verify_installed_after_restore(j)
                report["status"]="NO_CHANGE_ALREADY_ROLLED_BACK"
                report["restoredReceiptSha256"]=sha_file(RESULT)
            elif phase=="NO_PENDING_UPGRADE" and not pending.exists():
                report["status"]="NO_CHANGE_NO_PENDING"
            else:
                need(phase in ("STAGED","APPLIED","DEGRADED","NO_PENDING_UPGRADE"),
                     "UNKNOWN_ROOT_PHASE")
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
        "PASS_RESUMED_ACCEPTED_ROOT_USER_COMMIT",
        "NO_ROLLBACK_ALREADY_COMMITTED","NO_CHANGE_NO_PENDING",
        "PASS_AUTONOMOUS_TWO_SIDED_RESTORATION",
        "NO_CHANGE_ALREADY_ROLLED_BACK") else 90

def _exact_owned_inventory(root:Path,files:set[str],dirs:set[str],mode:int):
    """Allowlist every file/dir; no symlinks, foreign nodes or hardlinks."""
    need(root.is_dir() and not root.is_symlink(),"RETIRE_ROOT_UNSAFE")
    st=root.stat()
    need(st.st_uid==0 and stat.S_IMODE(st.st_mode)==mode,
         "RETIRE_ROOT_OWNER_MODE")
    actual_files=set();actual_dirs=set()
    for item in root.rglob("*"):
        rel=item.relative_to(root).as_posix()
        s=item.lstat()
        need(s.st_uid==0,"RETIRE_FOREIGN_OWNER_"+rel)
        if stat.S_ISDIR(s.st_mode):
            actual_dirs.add(rel)
        elif stat.S_ISREG(s.st_mode):
            need(s.st_nlink==1,"RETIRE_HARDLINK_"+rel)
            actual_files.add(rel)
        else:
            raise RuntimeError("RETIRE_FOREIGN_NODE_"+rel)
    need(actual_files==files and actual_dirs==dirs,"RETIRE_FOREIGN_ENTRY_SET")
    return True

def retire_rolledback(receipt_sha256:str):
    """Narrow operator-authenticated *post-rollback* recovery-slot retirement.

    Never auto-delete audit or live installation. An administrator must first
    export the unique rollback evidence to project Brain and supply the exact
    receipt SHA256. Root/User baseline must be byte-perfect; the guard and
    root-owned slots are only retired when already terminal ROLLED_BACK.
    Terminal COMMITTED, ambiguous, partial, live or foreign states are refused.
    """
    need(os.geteuid()==0 and Path(__file__).resolve()==WORKER,
         "RETIRE_OWNED_ROOT_WORKER_REQUIRED")
    need(type(receipt_sha256) is str and len(receipt_sha256)==64 and
         all(ch in "0123456789abcdefABCDEF" for ch in receipt_sha256),
         "RETIRE_EXACT_OPERATOR_RECEIPT_SHA_REQUIRED")
    j=verify_guard_files()
    regular(RESULT,0,0o600)
    digest=sha_file(RESULT)
    need(digest==receipt_sha256.upper(),"RETIRE_RECEIPT_SHA_CHANGED")
    evidence=json.loads(RESULT.read_text("utf8"))
    need(evidence.get("revision")=="R552"
         and evidence.get("status")=="PASS_AUTONOMOUS_TWO_SIDED_RESTORATION"
         and evidence.get("rootRollback")=="PASS"
         and evidence.get("userRollback")=="PASS"
         and evidence.get("recoveryAttempted") is True
         and evidence.get("networkMutationAttempted") is False,
         "RETIRE_ROLLBACK_EVIDENCE_NOT_ACCEPTED")
    tx=imported_root()
    need(tx.native and tx.status()["status"]=="ROLLED_BACK",
         "RETIRE_NONTERMINAL_ROOT")
    m=tx.manifest()
    need(m.get("phase")=="ROLLED_BACK" and m.get("uid")==j["uid"] and
         m.get("home")==j["home"] and m.get("fromVersion")==BASELINE and
         m.get("toVersion")==VERSION,"RETIRE_FOREIGN_ROOT_TRANSACTION")
    tx._validate_slot(m)
    states,metadata=tx._target_states(m)
    need(set(states)==set(m["files"]) and
         all(states[name]==row["old"] for name,row in m["files"].items()) and
         metadata==m["oldMetadataSHA"],"RETIRE_OLD_PROTECTED_BITS_NOT_RESTORED")
    home=Path(j["home"])
    need(not (home/USER_REL/"directmethod/state.json").exists(),
         "RETIRE_LIVE_DIRECT_ENGINE")
    verify_installed_after_restore(j)
    # Full inventory before deleting anything, including directories.
    names=set(m["files"])
    slotfiles={"manifest.json","old/metadata","new/metadata"}
    slotfiles.update("new/"+name for name in names)
    slotfiles.update("old/"+name for name,row in m["files"].items() if row["old"])
    _exact_owned_inventory(tx.pending,slotfiles,{"old","new"},0o700)
    guardfiles={"baseline.json","rollback-result.json",
                "worker.py","root_tx.py","user_tx.py"}
    _exact_owned_inventory(GUARD,guardfiles,set(),0o711)
    unit_sha={}
    for item in (SERVICE,TIMER):
        regular(item,0,0o644)
        need(item.stat().st_nlink==1,"RETIRE_HARDLINK_UNIT")
        unit_sha[item.name]=sha_file(item)
    for item in [*([tx.pending/p for p in slotfiles]),
                 BASELINE_FILE,RESULT,WORKER,ROOT_TX,USER_TX,SERVICE,TIMER]:
        need(item.is_file() and not item.is_symlink() and item.stat().st_uid==0
             and item.stat().st_nlink==1,"RETIRE_NAMED_ENTRY_CHANGED_"+item.name)
    state=command(["/usr/bin/systemctl","show",UNIT+".service",
                    "--property=ActiveState","--no-pager"])
    need(state.returncode==0 and
         ("ActiveState=inactive" in state.stdout or
          "ActiveState=failed" in state.stdout),
         "RETIRE_SERVICE_IS_BUSY")
    # No destructive operation before all checks above. After successful
    # restoration, first DISARM the timer and only then remove exact owned
    # transaction files. A partial maintenance interruption remains visibly
    # fail-closed, never auto-overwrites foreign content on a retry.
    disarmed=command(["/usr/bin/systemctl","disable","--now",UNIT+".timer"])
    need(disarmed.returncode==0,"RETIRE_TIMER_DISARM_FAILED")
    # systemd Persistent= leaves a separate on-disk last-trigger stamp.
    # Use the vendor-supported state-clean command before unit unlinking.
    stamp=command(["/usr/bin/systemctl","clean","--what=state",UNIT+".timer"])
    need(stamp.returncode==0,"RETIRE_PERSISTENT_TIMER_STATE_CLEAN_FAILED")
    for rel in sorted(slotfiles):
        p=tx.pending/rel
        need(p.is_file() and not p.is_symlink() and p.stat().st_uid==0,
             "RETIRE_SLOT_RACE_"+rel)
        p.unlink()
    for name in ("new","old"):
        (tx.pending/name).rmdir()
    tx.pending.rmdir()
    fsync_dir(tx.pending.parent)
    for p in (ROOT_TX,USER_TX,BASELINE_FILE,WORKER,RESULT):
        need(p.is_file() and not p.is_symlink() and p.stat().st_uid==0,
             "RETIRE_GUARD_RACE_"+p.name)
        p.unlink()
    GUARD.rmdir()
    fsync_dir(GUARD.parent)
    for p in (SERVICE,TIMER):
        need(p.is_file() and not p.is_symlink() and
             sha_file(p)==unit_sha[p.name],"RETIRE_UNIT_CHANGED_"+p.name)
        p.unlink()
    fsync_dir(SERVICE.parent)
    reload=command(["/usr/bin/systemctl","daemon-reload"])
    need(reload.returncode==0,"RETIRE_SYSTEMD_RELOAD_FAILED")
    need(tx.status()["status"]=="NO_PENDING_UPGRADE"
         and not GUARD.exists() and not TIMER.exists() and not SERVICE.exists(),
         "RETIRE_POSTCLEANUP_SLOT_LEFT")
    need(sha_file(Path("/etc/resolv.conf"))==j["oldResolverSha"],
         "RETIRE_DNS_CHANGED")
    return {"status":"PASS_AUTHORIZED_BOUNDED_ROLLBACK_RETIRE",
            "receiptSha256":digest,
            "oldRootVersion":BASELINE,"oldUserVersion":OLD_USER,
            "fileScopesExact":True,"networkMutationAttempted":False,
            "timerDisarmed":True,"repeatUpgradeUnblocked":True}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("action",choices=("preflight","arm","status","rollback","retire-rolledback"))
    parser.add_argument("--source",type=Path)
    parser.add_argument("--uid",type=int)
    parser.add_argument("--receipt-sha256")
    opts=parser.parse_args()
    if opts.action in ("preflight","arm"):
        need(opts.source is not None,"SOURCE_REQUIRED")
        if opts.action=="preflight":
            print(json.dumps(preflight(opts.source),sort_keys=True))
        else:
            need(opts.uid is not None,"UID_REQUIRED")
            print(json.dumps(arm(opts.source,opts.uid),sort_keys=True))
    elif opts.action=="retire-rolledback":
        need(opts.receipt_sha256 is not None,"RETIRE_RECEIPT_REQUIRED")
        print(json.dumps(retire_rolledback(opts.receipt_sha256),sort_keys=True))
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
