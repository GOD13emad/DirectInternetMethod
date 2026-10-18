#!/usr/bin/env python3
"""R532 one-shot hosted systemd root watchdog V&V. Execute 'arm', then 'verify'.

Both invocations are separate CI steps on an ephemeral GitHub-hosted Ubuntu VM.
The first starts a detached systemd monotonic timer BEFORE any candidate file
mutation, leaves actual protected Root+unprivileged User 1.5.5-rc1 staged and
applied, and EXITs. The second waits for the independent timer and verifies
byte-exact restoration to 1.5.2 Root / 1.5.4 User, without running rollback.
All installed products on physical hosts and network services are untouched.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import time

BASE = Path(__file__).resolve().parents[1]
R528 = BASE / "tests/r528_ephemeral_native_root_cli_contract.py"
R529 = BASE / "tests/r529_ephemeral_root_user_transaction.py"
R526 = BASE / "tests/r526_installer_metadata_contract.py"
WORKER_SOURCE = BASE / "tests/r532_root_watchdog_worker.py"
GUARD = Path("/run/dim-r532")
BASELINE = GUARD / "baseline.json"
ROOT_COPIED = GUARD / "root_tx.py"
USER_COPIED = GUARD / "user_tx.py"
WORKER_COPIED = GUARD / "worker.py"
WORKER_RETURN = GUARD / "timer-return.json"
UNIT = "dim-r532-watchdog"
TIMER = UNIT + ".timer"
SERVICE = UNIT + ".service"
ROOT_SHA = "7e539f39ce89e4352655ec820730ba18ea6397b91a970943d8a3a37d739acb3b"
USER_SHA = "c1bbf62d99e46cb8e349a38e60891027ff7276f85caceb597548c269203f28bf"

def sha(p:Path)->str:
    h=hashlib.sha256()
    with p.open("rb") as f:
        for part in iter(lambda:f.read(1048576),b""):h.update(part)
    return h.hexdigest()

def need(ok,why):
    if not ok:
        raise RuntimeError("R532_HOSTED_FAIL_CLOSED_"+why)

def mod(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    need(spec is not None and spec.loader is not None,"IMPORT_"+name)
    x=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(x)
    return x

def run(cmd,secs=15):
    v=subprocess.run(cmd,capture_output=True,text=True,timeout=secs,check=False)
    need(v.returncode==0,"SYSTEMD_CMD_"+v.stderr.strip()[-200:].replace(" ","_"))
    return v.stdout.strip()

def ensure_guard_absent():
    need(not GUARD.exists() and not GUARD.is_symlink(),"UNOWNED_OR_PREEXISTING_GUARD")
    for u in (TIMER,SERVICE):
        test=subprocess.run(["/usr/bin/systemctl","show",u,"-p","LoadState","--value"],
                            capture_output=True,text=True,timeout=5)
        need(test.stdout.strip() in ("not-found",""),"FOREIGN_SYSTEMD_UNIT_"+u)

def verify_host():
    need(sys.platform.startswith("linux") and os.geteuid()==0,"REAL_ROOT_GITHUB_VM_REQUIRED")
    need(os.environ.get("CI")=="true" and os.environ.get("GITHUB_ACTIONS")=="true",
         "GITHUB_CI_REQUIRED")
    need(os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted" and
         os.environ.get("GITHUB_REPOSITORY")=="GOD13emad/DirectInternetMethod",
         "EPHEMERAL_REPO_RUNNER_REQUIRED")
    need(Path(os.environ.get("GITHUB_WORKSPACE","")).resolve()==BASE.resolve(),"EXACT_WORKSPACE")
    need(Path(os.environ.get("RUNNER_TEMP","/does-not-exist")).is_dir(),"RUNNER_TEMP_REQUIRED")
    need(pwd.getpwnam("runner").pw_dir=="/home/runner","TEST_RUNNER_USER")
    need(Path("/proc/1/comm").read_text().strip()=="systemd","INDEPENDENT_SYSTEMD_PID1")
    need(WORKER_SOURCE.is_file() and not WORKER_SOURCE.is_symlink(),"GUARD_SOURCE_MISSING")

def own_root_copy(src:Path,dest:Path,mode:int):
    need(src.is_file() and not src.is_symlink(),"COPIED_SOURCE_UNSAFE")
    need(not dest.exists() and not dest.is_symlink(),"COPIED_TARGET_EXISTS")
    shutil.copyfile(src,dest)
    os.chown(dest,0,0)
    os.chmod(dest,mode)
    need(dest.stat().st_uid==0 and stat.S_IMODE(dest.stat().st_mode)==mode,
         "COPIED_ROOT_FILE_AUTHORITY")
    need(sha(src)==sha(dest),"COPY_SHA_CHANGED")

def save_manifest(doc):
    raw=(json.dumps(doc,indent=2,sort_keys=True)+"\n").encode()
    fd=os.open(BASELINE,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as out:
        os.fchmod(out.fileno(),0o600)
        out.write(raw);out.flush();os.fsync(out.fileno())
    need(BASELINE.stat().st_uid==0 and stat.S_IMODE(BASELINE.stat().st_mode)==0o600,
         "BASELINE_ROOT_OWNERSHIP")

def prepare_guard(source,user,root_hashes,user_hashes,mutables):
    need(sha(source/"system/protected_upgrade_transaction.py")==ROOT_SHA,
         "CANDIDATE_ROOT_PIN")
    need(sha(source/"app/user_update_transaction.py")==USER_SHA,
         "CANDIDATE_USER_PIN")
    GUARD.mkdir(mode=0o711)
    os.chown(GUARD,0,0)
    os.chmod(GUARD,0o711)
    own_root_copy(source/"system/protected_upgrade_transaction.py",ROOT_COPIED,0o500)
    own_root_copy(source/"app/user_update_transaction.py",USER_COPIED,0o644)
    own_root_copy(WORKER_SOURCE,WORKER_COPIED,0o500)
    network={"/etc/resolv.conf":sha(Path("/etc/resolv.conf")),
             "/etc/hosts":sha(Path("/etc/hosts"))}
    absent=[
      "/usr/lib/directinternetmethod/encrypted_selective_dns.py",
      "/usr/lib/directinternetmethod/encrypted_selective_policy.py"]
    need(all(not Path(a).exists() for a in absent),"NEW_PROTECTED_ROOT_NOT_ABSENT")
    doc={
      "schema":1,"revision":"R532","host":os.uname().nodename,
      "productionMachineTouched":False,
      "ownerUser":"runner","ownerUid":user.pw_uid,
      "rootHelperSHA256":ROOT_SHA,"userHelperSHA256":USER_SHA,
      "workerSHA256":sha(WORKER_SOURCE),
      "expectedRootVersion":"1.5.2","expectedUserVersion":"1.5.4",
      "originalAbsentProtected":absent,
      "protected":root_hashes,"userCode":user_hashes,"userMutable":mutables,
      "network":network,
      "resolvLink":os.readlink("/etc/resolv.conf") if Path("/etc/resolv.conf").is_symlink() else None
    }
    save_manifest(doc)
    return doc

def exact_inline(r526,src):
    raw=(src/"install.sh").read_text(encoding="utf8")
    marker=r526.BEGIN
    need(raw.count(marker)==1,"INSTALLED_INLINE_ENTRY_COUNT")
    tail=raw.split(marker,1)[1]
    need(tail.count(r526.END)==1,"INSTALLED_INLINE_TERMINATOR")
    code=tail.split(r526.END,1)[0]
    need('transaction_helper.atomic_bytes(' in code and len(code.splitlines())==64,
         "INSTALLED_METADATA_FRAGMENT_DRIFT")
    return code

def arm():
    ensure_guard_absent()
    r528=mod(R528,"r532_seed_root")
    r529=mod(R529,"r532_seed_user")
    r526=mod(R526,"r532_inline")
    stable,candidate,temp,user=r528.prerequisites()
    r529.require_clean_home(user)
    need(Path("/usr/sbin/runuser").is_file(),"RUNUSER_REQUIRED")
    extracted=r528.stage_exact_candidate(candidate,temp)
    r529.make_source_runner_owned(extracted,user)
    app,old_user,private=r529.prepare_user_from_official(stable,user)
    module=r528.module()
    root_before=r528.seed_real_protected_root(stable,user,module)
    doc=prepare_guard(extracted,user,root_before,old_user,private)
    run(["/usr/bin/systemd-run","--quiet","--unit="+UNIT,
         "--on-active=35s","--timer-property=AccuracySec=1s",
         "/usr/bin/python3","-B",str(WORKER_COPIED)])
    timer_state=run(["/usr/bin/systemctl","show",TIMER,"-p","ActiveState","--value"])
    need(timer_state=="active","INDEPENDENT_MONOTONIC_TIMER_NOT_ARMED")
    trigger=run(["/usr/bin/systemctl","show",TIMER,"-p","Triggers","--value"])
    need(SERVICE in trigger,"TIMER_NOT_CONNECTED_TO_OWNED_WORKER")
    # Everything below occurs AFTER detached root watchdog is independently armed.
    user_script=extracted/"app/user_update_transaction.py"
    root_tx=module.RootTransaction()
    need(root_tx.native and root_tx.status()["status"]=="NO_PENDING_UPGRADE",
         "PRE_MUTATION_ROOT_DIRTY")
    need(not Path("/home/runner/.local/state/DirectInternetMethod/update-pending").exists(),
         "PRE_MUTATION_USER_DIRTY")
    r529.as_runner(user,user_script,"--stage","--source",extracted)
    need(root_tx.stage(extracted)["status"]=="STAGED","ROOT_STAGE")
    need(root_tx.apply()["status"]=="APPLIED","ROOT_APPLY")
    r529.as_runner(user,user_script,"--apply","--source",extracted)
    r529.as_runner_inline(user,exact_inline(r526,extracted),
                          app/"INSTALL.json",user_script)
    need(json.loads((app/"INSTALL.json").read_text())["version"]=="1.5.5-rc1",
         "NEW_USER_METADATA")
    need(json.loads(Path("/var/lib/directinternetmethod/install.json").read_text())["version"]=="1.5.5-rc1",
         "NEW_ROOT_METADATA")
    need(root_tx.status()["status"]=="APPLIED","ROOT_APPLIED_PENDING")
    need((Path("/home/runner/.local/state/DirectInternetMethod/update-pending/manifest.json")).is_file(),
         "USER_SLOT_MISSING")
    # Leave both sides unapplied to no other action; arm process exits now.
    # The next CI step is a DIFFERENT process; only systemd timer may rollback.
    print("PASS_R532_WATCHDOG_ARMED_BEFORE_MUTATION_THEN_MAIN_EXIT")
    print("WORKER_ROOT_OWNED_SHA",doc["workerSHA256"])
    print("TIMER_UNIT",TIMER,"SERVICE_UNIT",SERVICE)
    print("PRE_TIMER_VERSIONS", "root=1.5.5-rc1","user=1.5.5-rc1")

def verify():
    need(GUARD.is_dir() and GUARD.stat().st_uid==0,"EXPECTED_GUARD_NOT_FOUND")
    need(BASELINE.is_file() and BASELINE.stat().st_uid==0,"ROOT_BASELINE_MISSING")
    check=json.loads(BASELINE.read_text())
    need(check["revision"]=="R532" and check["host"]==os.uname().nodename,
         "BASELINE_DIFFERENT_RUN")
    need(check["workerSHA256"]==sha(WORKER_COPIED),"WORKER_SOURCE_DRIFT")
    need(sha(ROOT_COPIED)==ROOT_SHA and sha(USER_COPIED)==USER_SHA,
         "OWNER_GUARD_COPY_SHA_DRIFT")
    start=time.monotonic()
    while not WORKER_RETURN.exists() and time.monotonic()-start<85:
        time.sleep(1)
    need(WORKER_RETURN.is_file() and not WORKER_RETURN.is_symlink(),
         "SYSTEMD_TIMER_DID_NOT_ACTIVATE")
    receipt=json.loads(WORKER_RETURN.read_text())
    need(receipt["status"]=="PASS_ROOT_USER_BYTE_EXACT_AUTONOMOUS_ROLLBACK",
         "TIMER_WORKER_NOT_SUCCESS:"+str(receipt.get("failure","NONE")))
    need(receipt.get("actualEffectiveUid")==0 and receipt.get("recoveryAttempted"),
         "ROOT_TIMER_EXECUTION_UNPROVEN")
    need(receipt["userRollback"]=="PASS" and receipt["protectedRootRollback"]=="PASS",
         "TWO_SIDED_ROLLBACK_MISSING")
    need(receipt["restoredFiles"]["userMutable"]>=8,
         "USER_MUTABLE_VERIFICATION_INSUFFICIENT")
    need(receipt["restoredFiles"]["protected"]>=11,
         "ROOT_BASELINE_VERIFICATION_INSUFFICIENT")
    require_versions={
      "protected":json.loads(Path("/var/lib/directinternetmethod/install.json").read_text())["version"],
      "user":json.loads(Path("/home/runner/.local/share/DirectInternetMethod/INSTALL.json").read_text())["version"],
    }
    need(require_versions=={"protected":"1.5.2","user":"1.5.4"},
         "LIVE_FINAL_VERSION_DRIFT")
    for cls in ("protected","userCode","userMutable","network"):
        for name,want in check[cls].items():
            need(sha(Path(name))==want,"POST_TIMER_SHA_DRIFT_"+cls)
    need(not Path("/home/runner/.local/state/DirectInternetMethod/update-pending").exists(),
         "USER_SLOT_NOT_CLEAN")
    need(not Path("/etc/systemd/system/directinternetmethod-start.service").exists(),
         "UNKNOWN_GLOBAL_PRODUCTION_SERVICE")
    need(not Path("/run/directinternetmethod-encrypted").exists(),
         "UNEXPECTED_ENCRYPTED_DNS_SESSION")
    print("PASS_R532_INDEPENDENT_SYSTEMD_ROOT_TIMER_RESTORED_BOTH_SIDES")
    print("WORKER_RECEIPT_SHA256",sha(WORKER_RETURN))
    print("RESTORED_SHA_GROUPS",json.dumps(receipt["restoredFiles"],sort_keys=True))
    print("PREVIOUS_PUBLIC_STABLE_UNCHANGED_v1.5.4")

def main():
    need(len(sys.argv)==2 and sys.argv[1] in ("arm","verify"),"CLI_ACTION")
    verify_host()
    if sys.argv[1]=="arm":arm()
    else:verify()

if __name__=="__main__":
    try:
        main()
    except BaseException as e:
        print("R532_HOSTED_TIMER_FAIL_CLOSED",type(e).__name__,str(e)[:450],file=sys.stderr)
        sys.exit(89)
