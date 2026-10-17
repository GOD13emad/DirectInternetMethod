#!/usr/bin/env python3
"""R554 exact product upgrade-guard native disposable systemd lifecycle proof.

Never execute outside an *empty* GitHub-hosted ephemeral Ubuntu VM. Uses
official SHA-pinned v1.5.4 baseline and exact 27-file 1.5.5 RC archive.
Stages real unprivileged user data, arms actual root-owned systemd timer BEFORE
any protected modification; invokes the protected root stage/apply, applies User
code, verifies exact installer inline metadata, triggers the separately owned
systemd SERVICE (not a fake Python callback) and checks two-sided byte-exact
restoration. Native monotonic timer expiration is independently proven by R532.
No network/DNS/Tailscale/GUI Start/Stop action; not production acceptance.
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

R=Path(__file__).resolve().parents[1]
R528=R/"tests/r528_ephemeral_native_root_cli_contract.py"
R529=R/"tests/r529_ephemeral_root_user_transaction.py"
R526=R/"tests/r526_installer_metadata_contract.py"
ROOT=R/"linux/system/protected_upgrade_transaction.py"
GUARD=R/"linux/system/upgrade_guard.py"
PIN_PACKAGE="C8E5A06387FF21EC0E048F8BB02DC1B4C31B364625E18EC641900356F60CE503"
PIN_ROOT="DE3ED6765DC8DB307297E49736483D02D7471B4F3FE7A77408A4368D7A2515A3"
PIN_GUARD="70D676AE7EBC71062C2F06B4506557DD3D5CC4FB43B9D771336DF5D32F3D35ED"
PIN_USER="EAC84CB951F520F0E6A05D1452EF355A1CC89D7C68DEB73F91BA14C8E1C4BD66"
NAME="directinternetmethod-upgrade-rollback"
SEEN=Path("/var/lib/directinternetmethod/upgrade-guard/rollback-result.json")

def need(ok,why):
    if not ok:raise RuntimeError("R554_NATIVE_GUARD_FAIL_CLOSED_"+why)

def sha(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for piece in iter(lambda:f.read(1048576),b""):h.update(piece)
    return h.hexdigest().upper()

def module(path,modname):
    spec=importlib.util.spec_from_file_location(modname,path)
    need(spec is not None and spec.loader is not None,"IMPORT_"+modname)
    obj=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj

def command(args,seconds=25):
    proc=subprocess.run(args,capture_output=True,text=True,check=False,timeout=seconds)
    need(proc.returncode==0,"COMMAND_"+str(proc.returncode)+"_"+proc.stderr[-200:].replace(" ","_"))
    return proc.stdout.strip()

def preflight_vm():
    need(os.geteuid()==0 and sys.platform.startswith("linux"),"NATIVE_ROOT")
    need(os.environ.get("GITHUB_ACTIONS")=="true" and os.environ.get("CI")=="true"
         and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted"
         and os.environ.get("GITHUB_REPOSITORY")=="GOD13emad/DirectInternetMethod"
         and Path(os.environ.get("GITHUB_WORKSPACE","")).resolve()==R.resolve(),
         "GITHUB_EPHEMERAL_ONLY")
    need(Path("/proc/1/comm").read_text().strip()=="systemd","SYSTEMD_PID1")
    runner=pwd.getpwnam("runner")
    need(runner.pw_dir=="/home/runner" and runner.pw_uid>0,"RUNNER_IDENTITY")
    for path in ("/usr/lib/directinternetmethod",
                 "/var/lib/directinternetmethod",
                 "/etc/directinternetmethod.uid",
                 "/etc/systemd/system/"+NAME+".service",
                 "/etc/systemd/system/"+NAME+".timer",
                 "/home/runner/.local/share/DirectInternetMethod",
                 "/home/runner/.local/state/DirectInternetMethod",
                 "/run/directinternetmethod-encrypted"):
        p=Path(path)
        need(not p.exists() and not p.is_symlink(),"FOREIGN_PREEXISTING_"+p.name)
    need(sha(ROOT)==PIN_ROOT and sha(GUARD)==PIN_GUARD,"SOURCE_SHA_DRIFT")
    need(sha(R/"linux/app/user_update_transaction.py")==PIN_USER,"USER_SOURCE_SHA_DRIFT")
    return runner

def run():
    runner=preflight_vm()
    r528=module(R528,"r554_r528")
    r529=module(R529,"r554_r529")
    r526=module(R526,"r554_r526")
    rootmod=r528.module()
    guard=module(GUARD,"r554_real_guard")
    stable,package,temp,user=r528.prerequisites()
    need(user.pw_uid==runner.pw_uid,"USER_CHANGED")
    need(sha(package)==PIN_PACKAGE,"PINNED_CANDIDATE")
    r529.require_clean_home(user)
    extracted=r528.stage_exact_candidate(package,temp)
    r529.make_source_runner_owned(extracted,user)
    # Installed user and root bytes come only from the public v1.5.4 ZIP.
    app,original_user,private=r529.prepare_user_from_official(stable,user)
    protected=r528.seed_real_protected_root(stable,user,rootmod)
    baseline_network={
        p:sha(p) for p in ("/etc/resolv.conf","/etc/hosts")
    }
    before_link=(os.readlink("/etc/resolv.conf")
                 if Path("/etc/resolv.conf").is_symlink() else None)
    before_user=sha(app/"INSTALL.json")
    before_root=sha("/var/lib/directinternetmethod/install.json")
    tx_user=extracted/"app/user_update_transaction.py"
    need(sha(tx_user)==PIN_USER,"EXTRACTED_USER_SHA")
    need(sha(extracted/"system/upgrade_guard.py")==PIN_GUARD,"EXTRACTED_GUARD_SHA")
    need(sha(extracted/"system/protected_upgrade_transaction.py")==PIN_ROOT,"EXTRACTED_ROOT_SHA")
    root_tx=rootmod.RootTransaction()
    need(root_tx.native and root_tx.status()["status"]=="NO_PENDING_UPGRADE","ROOT_PRESTATE")
    # Unprivileged stage creates only the bounded user rollback snapshot.
    r529.as_runner(user,tx_user,"--stage","--source",extracted)
    pending=Path("/home/runner/.local/state/DirectInternetMethod/update-pending")
    need((pending/"manifest.json").is_file(),"USER_STAGE")
    r529.unchanged_records(original_user)
    r529.unchanged_records(private)
    # Two separate disposable-VM paths: original direct product transaction
    # and the ACTUAL production upgrade_system.sh wrapper and auto-arm.
    # Both must install the same root-owned timer and restore exact baselines.
    native_wrapper=os.environ.get("DIM_R555_EXACT_WRAPPER")=="true"
    need(root_tx.status()["status"]=="NO_PENDING_UPGRADE","ROOT_MUTATED_BEFORE_ARM")
    if native_wrapper:
        wrapper=extracted/"system/upgrade_system.sh"
        need(wrapper.is_file() and not wrapper.is_symlink(),"EXACT_WRAPPER")
        out=command(["/bin/bash",str(wrapper),str(extracted),str(user.pw_uid)],80)
        need("R553_ROOT_GUARD_ACTIVE_PRESTAGE_VERIFIED" in out
             and "ROOT_R519_APPLIED_UNCOMMITTED" in out,
             "PRODUCTION_WRAPPER_GUARD_ACCEPTANCE")
    else:
        armed=guard.arm(extracted,user.pw_uid)
        need(armed["status"]=="ARMED_INDEPENDENT_ROOT_USER_WATCHDOG","WATCHDOG_ARM")
        need(root_tx.status()["status"]=="NO_PENDING_UPGRADE","ROOT_MUTATED_BEFORE_ARM")
        need(root_tx.stage(extracted)["status"]=="STAGED","ROOT_STAGE")
        need(root_tx.apply()["status"]=="APPLIED","ROOT_APPLY")
    present=guard.verify_timer()
    need(present["uid"]==user.pw_uid and present["workerSha"]==sha(guard.WORKER),
         "SYSTEMD_TIMER_GUARD")
    # R559: the calendar deadline is immutable across timer restart. On
    # reboot the original calendar event and Persistent=true restore the
    # missed rollback, rather than restarting OnActiveSec from zero.
    deadline=present.get("deadlineUnix")
    need(type(deadline) is int and deadline>0,"PERSISTENT_DEADLINE_IN_BASELINE")
    timestamp=guard.datetime.datetime.fromtimestamp(
        deadline,guard.datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    timer_body=guard.TIMER.read_text("utf8")
    need("OnCalendar="+timestamp+"\n" in timer_body and
         "Persistent=true\n" in timer_body and
         "OnActiveSec=480s\n" in timer_body,"PERSISTENT_WATCHDOG_TIMER_CONTENT")
    command(["/usr/bin/systemd-analyze","calendar",timestamp],10)
    next_cal_before=command(["/usr/bin/systemctl","show",NAME+".timer",
                             "-p","NextElapseUSecRealtime","--value"])
    need(next_cal_before and next_cal_before not in ("n/a","0"),
         "CALENDAR_DEADLINE_NOT_SCHEDULED")
    command(["/usr/bin/systemctl","restart",NAME+".timer"],12)
    next_cal_after=command(["/usr/bin/systemctl","show",NAME+".timer",
                            "-p","NextElapseUSecRealtime","--value"])
    need(next_cal_after==next_cal_before,"RESTART_MOVED_ORIGINAL_DEADLINE")
    guard.verify_timer()
    need(root_tx.status()["status"]=="APPLIED","ROOT_PENDING")
    r529.as_runner(user,tx_user,"--apply","--source",extracted)
    manifest=json.loads((pending/"manifest.json").read_text())
    for rel,row in manifest["managed"].items():
        need(r529.hash_file(app/rel)==row["sha"],"USER_APPLY_SHA_"+rel)
    r529.unchanged_records(private)
    # Run the exact, unchanged production installer INSTALL.json fragment.
    install=(extracted/"install.sh").read_text(encoding="utf8")
    need(install.count(r526.BEGIN)==1,"INSTALL_METADATA_ANCHOR")
    part=install.split(r526.BEGIN,1)[1]
    need(part.count(r526.END)==1,"INSTALL_END")
    inline=part.split(r526.END,1)[0]
    need("transaction_helper.atomic_bytes(" in inline
         and len(inline.splitlines())==64,"INSTALL_INLINE_IDENTITY")
    r529.as_runner_inline(user,inline,app/"INSTALL.json",tx_user)
    need(json.loads((app/"INSTALL.json").read_text())["version"]=="1.5.5-rc1",
         "UPGRADED_USER_VERSION")
    need(json.loads(Path("/var/lib/directinternetmethod/install.json").read_text())["version"]=="1.5.5-rc1",
         "UPGRADED_ROOT_VERSION")
    need(root_tx.status()["status"]=="APPLIED","ROOT_STILL_PENDING")
    # R562 tests interruption AFTER a deliberately simulated protected Root
    # acceptance and BEFORE User commit. NOT real owner/live acceptance:
    # a marked synthetic fixture exercises the fail-closed crash window only.
    synthetic_promotion=os.environ.get("DIM_R562_SYNTHETIC_PROMOTION")=="true"
    synthetic_reject=os.environ.get("DIM_R565_SYNTHETIC_MUTABLE_DRIFT")=="true"
    need(not synthetic_reject or synthetic_promotion,
         "MUTABLE_NEGATIVE_REQUIRES_DISPOSABLE_ROOT_ACCEPTANCE_FIXTURE")
    if synthetic_promotion:
        m=root_tx.manifest()
        fixture={
            "revision":"R519","status":"PASS_NATIVE_ROOT_UPGRADE",
            "syntheticAcceptanceFixture":True,
            "sourceRootSHA":rootmod.sha(rootmod.canonical(m["files"])),
            "protectedMetadataSHA":m["newMetadataSHA"],
            "nativeStartStopRecovery":True,
            "tailscalePreserved":True,
            "physicalDNSPreserved":True
        }
        acceptance=Path(temp)/"DIM_R562_TEST_ONLY_ACCEPTANCE.json"
        need(not acceptance.exists() and not acceptance.is_symlink(),
             "FOREIGN_TEST_ACCEPTANCE_EXISTS")
        acceptance.write_text(json.dumps(fixture,sort_keys=True,indent=2)+"\n")
        need(root_tx.commit(acceptance)["status"]=="COMMITTED",
             "SYNTHETIC_ROOT_FINALIZATION")
        need(root_tx.status()["status"]=="COMMITTED" and pending.is_dir(),
             "ROOT_COMMITTED_USER_STILL_PENDING_WINDOW")
    if synthetic_reject:
        # The *only* deliberate user-data mutation happens on this disposable
        # GitHub runner AFTER synthetically accepting Root and BEFORE user commit.
        mutable=app/"settings.json"
        old_mutable=mutable.read_bytes()
        need(sha(mutable).lower()==private[str(mutable)],
             "MUTABLE_TEST_PRESTATE_NOT_BASELINED")
        mutable.write_bytes(old_mutable+b"R565_TEST_ONLY_MUTABLE_DRIFT\n")
        need(sha(mutable).lower()!=private[str(mutable)],
             "MUTABLE_DRIFT_FIXTURE_INEFFECTIVE")
    # Actual independent root-owned systemd Service, rather than calling
    # guard.rollback_worker in-process. R532 separately proves timed firing.
    start=time.monotonic()
    if synthetic_reject:
        # A failure is expected here. Real systemd must propagate the owned
        # worker's nonzero exit rather than silently report successful commit.
        attempt=subprocess.run(
            ["/usr/bin/systemctl","start",NAME+".service"],
            capture_output=True,text=True,check=False,timeout=100)
        need(attempt.returncode!=0,"UNSAFE_USER_COMMIT_FALSE_SUCCESS")
    else:
        command(["/usr/bin/systemctl","start",NAME+".service"],100)
    need(SEEN.is_file() and not SEEN.is_symlink(),"SYSTEMD_RECEIPT_MISSING")
    receipt=json.loads(SEEN.read_text())
    receipt_sha_before_retirement=sha(SEEN)
    if synthetic_reject:
        need(receipt.get("status")=="DEGRADED_UNRESOLVED"
             and receipt.get("uid")==0
             and receipt.get("finalizationAttempted") is True
             and receipt.get("recoveryAttempted") is False,
             "FAILED_USER_FORWARD_COMMIT_WAS_NOT_RECORDED")
        need("USER_FORWARD_COMMIT" in str(receipt.get("failure", ""))
             and "MUTABLE_USER_DATA_CHANGED_CONCURRENTLY" in str(receipt.get("failure", "")),
             "MUTABLE_DATA_DRIFT_WAS_NOT_REJECTED")
        need(root_tx.status()["status"]=="COMMITTED"
             and root_tx.pending.is_dir() and pending.is_dir(),
             "ACCEPTED_ROOT_OR_USER_BACKUP_WAS_REVERTED")
        need(json.loads((app/"INSTALL.json").read_text())["version"]=="1.5.5-rc1"
             and json.loads(Path("/var/lib/directinternetmethod/install.json").read_text())["version"]=="1.5.5-rc1",
             "COMMITTED_VERSION_CHANGED_ON_FAILED_FINALIZATION")
        for rel,row in manifest["managed"].items():
            dest=app/rel
            need(dest.is_file() and sha(dest).lower()==row["sha"],
                 "USER_CODE_MUTATED_ON_REJECTED_COMMIT_"+rel)
        for _,relative,target,oldsha,newsha,mode in rootmod.FILES:
            dest=Path("/")/target
            need(dest.is_file() and sha(dest)==newsha
                 and stat.S_IMODE(dest.stat().st_mode)==mode,
                 "PROTECTED_ROOT_MUTATED_ON_REJECTED_COMMIT_"+dest.name)
        for rel,want in rootmod.STATIC_ROOT.items():
            need(sha(Path("/")/rel)==want,
                 "STATIC_ROOT_MUTATED_ON_REJECTED_USER_COMMIT_"+Path(rel).name)
        for file,want in private.items():
            now=sha(file).lower()
            if file==str(app/"settings.json"):
                need(now!=want,"FIXTURE_MUTABLE_DRIFT_WAS_LOST")
            else:
                need(now==want,"UNRELATED_USER_MUTABLE_DRIFT_"+Path(file).name)
    elif synthetic_promotion:
        need(receipt.get("status")=="PASS_RESUMED_ACCEPTED_ROOT_USER_COMMIT"
             and receipt.get("uid")==0
             and receipt.get("userForwardCommit")=="PASS"
             and receipt.get("finalizationAttempted") is True,
             "ACCEPTED_ROOT_USER_COMMIT_NOT_RECONCILED")
        need(root_tx.status()["status"]=="COMMITTED","ACCEPTED_ROOT_PHASE_LOST")
        need(not pending.exists(),"USER_BACKUP_NOT_RELEASED")
        need(json.loads((app/"INSTALL.json").read_text())["version"]=="1.5.5-rc1",
             "COMMITTED_USER_VERSION")
        need(json.loads(Path("/var/lib/directinternetmethod/install.json").read_text())["version"]=="1.5.5-rc1",
             "COMMITTED_ROOT_VERSION")
        installed_manifest=json.loads((app/"INSTALL.json").read_text())
        for rel,row in manifest["managed"].items():
            dest=app/rel
            need(dest.is_file() and sha(dest).lower()==row["sha"],
                 "COMMITTED_USER_CODE_DRIFT_"+rel)
        for _,relative,target,oldsha,newsha,mode in rootmod.FILES:
            dest=Path("/")/target
            need(dest.is_file() and sha(dest)==newsha
                 and stat.S_IMODE(dest.stat().st_mode)==mode,
                 "COMMITTED_ROOT_CODE_DRIFT_"+dest.name)
        for rel,want in rootmod.STATIC_ROOT.items():
            need(sha(Path("/")/rel)==want,"STATIC_ROOT_CHANGED_"+Path(rel).name)
        need(root_tx.pending.is_dir(),"ROOT_AUDIT_SLOT_STILL_RETAINED")
    else:
        need(receipt.get("status")=="PASS_AUTONOMOUS_TWO_SIDED_RESTORATION"
             and receipt.get("uid")==0 and receipt.get("userRollback")=="PASS"
             and receipt.get("rootRollback")=="PASS"
             and receipt.get("recoveryAttempted") is True,
             "ROOT_OWNED_SERVICE_NOT_ACCEPTED")
        need(root_tx.status()["status"]=="ROLLED_BACK","ROOT_PHASE_NOT_ROLLED_BACK")
        need(not pending.exists(),"USER_PENDING_REMAINS")
        need(json.loads((app/"INSTALL.json").read_text())["version"]=="1.5.4",
             "USER_VERSION_NOT_RESTORED")
        need(json.loads(Path("/var/lib/directinternetmethod/install.json").read_text())["version"]=="1.5.2",
             "ROOT_VERSION_NOT_RESTORED")
        need(sha(app/"INSTALL.json")==before_user
             and sha("/var/lib/directinternetmethod/install.json")==before_root,
             "ORIGINAL_METADATA_SHA_DRIFT")
        for target,want in original_user.items():
            need(sha(target).lower()==want,"USER_FILE_RESTORATION_"+Path(target).name)
        for target,want in protected.items():
            need(sha(target).lower()==want,"PROTECTED_FILE_RESTORATION_"+Path(target).name)
    if not synthetic_reject:
        r529.unchanged_records(private)
    for p,want in baseline_network.items():
        need(sha(p)==want,"NETWORK_FILE_MUTATED")
    need(before_link==(os.readlink("/etc/resolv.conf")
         if Path("/etc/resolv.conf").is_symlink() else None),"RESOLVER_SYMLINK_MUTATED")
    # R568 is an explicit root-authorized maintenance command AFTER verified
    # terminal two-sided rollback; never invoked by a live timer or installer.
    retire=os.environ.get("DIM_R568_TEST_RETIRE_ROLLED_BACK")=="true"
    retired=False
    if retire:
        need(not synthetic_promotion and not synthetic_reject,
             "RETIRE_TEST_NEEDS_REAL_ROLLBACK")
        need(root_tx.status()["status"]=="ROLLED_BACK"
             and root_tx.pending.is_dir() and guard.GUARD.is_dir(),
             "RETIRE_TEST_MISSING_REAL_TERMINAL_SLOT")
        sha_receipt=sha(SEEN)
        cli=["/usr/bin/python3","-B",str(guard.WORKER),
             "retire-rolledback","--receipt-sha256"]
        denied=subprocess.run(cli+["0"*64],text=True,capture_output=True,
                              timeout=12,check=False)
        need(denied.returncode!=0 and
             "RETIRE_RECEIPT_SHA_CHANGED" in denied.stderr,
             "RETIRE_BAD_EVIDENCE_NOT_REJECTED")
        need(root_tx.pending.is_dir() and guard.GUARD.is_dir()
             and guard.TIMER.exists(),"RETIRE_BAD_EVIDENCE_MUTATED_SLOT")
        foreign=guard.GUARD/"r568-synthetic-foreign.txt"
        need(not foreign.exists(),"RETIRE_SYNTHETIC_FOREIGN_PREEXISTS")
        foreign.write_text("foreign-test")
        foreign.chmod(0o600)
        refused=subprocess.run(cli+[sha_receipt],text=True,capture_output=True,
                               timeout=12,check=False)
        need(refused.returncode!=0 and
             "RETIRE_FOREIGN_ENTRY_SET" in refused.stderr,
             "RETIRE_FOREIGN_ENTRY_NOT_REJECTED")
        need(root_tx.pending.is_dir() and guard.GUARD.is_dir()
             and guard.TIMER.exists(),"RETIRE_FOREIGN_ENTRY_MUTATED_SLOT")
        foreign.unlink() # remove ONLY our synthetic test-owned file
        result=command(cli+[sha_receipt],40)
        doc=json.loads(result.splitlines()[-1])
        need(doc["status"]=="PASS_AUTHORIZED_BOUNDED_ROLLBACK_RETIRE"
             and doc["receiptSha256"]==sha_receipt,
             "RETIRE_BOUNDED_RESULT_NOT_ACCEPTED")
        need(root_tx.status()["status"]=="NO_PENDING_UPGRADE"
             and not guard.GUARD.exists() and not guard.SERVICE.exists()
             and not guard.TIMER.exists(),"RETIRE_LEFT_OWNED_ROOT_SLOT")
        stamp=Path("/var/lib/systemd/timers/stamp-"+NAME+".timer")
        need(not stamp.exists() and not stamp.is_symlink(),
             "RETIRE_SYSTEMD_PERSISTENT_TIMER_STAMP_REMAINS")
        pf=guard.preflight(extracted)
        need(pf["status"]=="SAFE_SOURCE_AND_INSTALLED_BASELINE_ONLY",
             "RETIRE_NEXT_SAFE_UPDATE_STILL_BLOCKED")
        retired=True
    # No reboot, no network/Tailscale manipulation, and no second install.
    need(not (app/"directmethod/state.json").exists(),"ACTIVE_ENGINE_UNEXPECTED")
    if not retired:
        command(["/usr/bin/systemctl","disable","--now",NAME+".timer"])
    print(json.dumps({
      "syntheticRootAcceptanceOnly":synthetic_promotion,
      "acceptedRootUserInterruptedResume":synthetic_promotion and not synthetic_reject,
      "operatorAttestedRollbackSlotRetired":retired,
      "repeatUpgradeSafelyUnblocked":retired,
      "expectedFailClosedSyntheticMutableDrift":synthetic_reject,
      "revision":"R554","status":(
          "PASS_EPHEMERAL_SYNTHETIC_MUTABLE_DRIFT_FAIL_CLOSED_AFTER_ACCEPTED_ROOT"
          if synthetic_reject else
          "PASS_EPHEMERAL_SYNTHETIC_ROOT_ACCEPTANCE_USER_FINALIZATION"
          if synthetic_promotion else
          "PASS_EPHEMERAL_ACTUAL_SYSTEMD_OWNED_GUARD_ROOT_USER_ROLLBACK"),
      "host":"ephemeral-github-ubuntu",
      "nativeProtectedRoot":True,"rootAuthorizedInDisposableVM":True,
      "guardArmedBeforeRootMutation":True,
      "systemdServiceStartedInSeparateProcess":True,
      "timerNativeLoadedAndEnabledBeforeMutation":True,
      "calendarDeadlinePreservedAcrossTimerRestart":True,
      "productionShellUpgradeWrapperExecuted":native_wrapper,
      "rootAndUserByteExactRestoration":not synthetic_promotion,
      "mutatedProductionHost":False,"modifiedRouteDnsOrTailscale":False,
      "publishedStablePreserved":"v1.5.4",
      "rootFileCount":len(protected),
      "userFileCount":len(original_user),
      "privateUserFileCount":len(private),
      "serviceDurationSeconds":round(time.monotonic()-start,3),
      "watchdogReceiptSHA256":receipt_sha_before_retirement},sort_keys=True))
if __name__=="__main__":
    try:run()
    except BaseException as e:
        print(json.dumps({"revision":"R554","status":"FAIL_CLOSED",
                          "reason":str(e)[:500]}),file=sys.stderr)
        sys.exit(94)
