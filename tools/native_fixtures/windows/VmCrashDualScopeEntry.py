"""R900 offline Windows Sandbox VM-termination recovery, synthetic two scopes.

Each invocation is a fresh frozen Python executable inside an independent
network-disabled Windows Sandbox guest. Only the separately mapped, disposable
host-owned R900 scratch folder persists between sandbox sessions.

This is not installed product, a native Windows service, UAC authority,
durable physical power-loss guarantee, nor publisher authentication.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time

from installer_engine.engine import (
    Engine, EngineError, hash_bytes, atomic_json, require,
)
from installer_engine.two_scope import TwoScopeFixtureCoordinator


PLATFORM = "windows-x86_64"
ROOT = Path(r"C:\DIMR900\persist")
ROOTS = {"code": ROOT/"synthetic-machine", "user": ROOT/"synthetic-user"}
LEDGER = ROOT/"transaction"
OWNER = ROOTS["user"]/"data"/"keep-owner-config.dat"
PACKAGES = ROOT/"source-packages"
STATUS = ROOT/"vm-status.json"
RESULT = ROOT/"vm-recovery-receipt.json"
MARKER = b"R900_OWNER_SETTINGS_MUST_SURVIVE_VM_SHUTDOWN"


def _pack(scope: str, release: str) -> tuple[Path, str]:
    identifier = scope + "_" + release.replace(".", "_")
    folder = PACKAGES/identifier
    payload = folder/"payload"/"app"/"synthetic.bin"
    content = ("R900_NONPRODUCT_CODE_"+scope+"_"+release).encode("utf-8")
    if not payload.exists():
        payload.parent.mkdir(parents=True, exist_ok=False)
        payload.write_bytes(content)
    require(payload.read_bytes() == content, "R900_PACKAGE_CHANGED")
    doc = {"schema":1,"product":"Direct Internet Method",
           "version":release,"platform":PLATFORM,
           "files":[{"path":"app/synthetic.bin","bytes":len(content),
                     "sha256":hash_bytes(content),"mode":0o644}]}
    manifest=(json.dumps(doc,sort_keys=True,separators=(",",":"))+"\n").encode()
    entry=folder/"manifest.json"
    if not entry.exists():
        entry.write_bytes(manifest)
    require(entry.read_bytes()==manifest,"R900_MANIFEST_CHANGED")
    return folder,hash_bytes(manifest)


def _source(release: str) -> dict:
    return {name:_pack(name,release) for name in ROOTS}


def _coord() -> TwoScopeFixtureCoordinator:
    return TwoScopeFixtureCoordinator(LEDGER,PLATFORM,ROOTS)


def _versions(release: str) -> None:
    for name,root in ROOTS.items():
        report=Engine(root,PLATFORM).verify()
        require(report["status"]=="PASS_INSTALLED" and
                report["version"]==release,
                "R900_SCOPE_VERSION_DRIFT_"+name)


def _owner() -> None:
    require(OWNER.is_file() and OWNER.read_bytes()==MARKER,
            "R900_OWNER_SETTINGS_CHANGED")


def _status(phase: str) -> None:
    require(STATUS.parent == ROOT and ROOT.is_dir(), "R900_STATUS_OUTSIDE_OWNED_ROOT")
    atomic_json(STATUS,{
        "schema":1,"phase":phase,
        "owner_sha256":hash_bytes(MARKER),
        "native_product_installation_accepted":False,
        "power_cut_or_real_reboot_accepted":False,
    })


def _check(phase: str) -> None:
    require(STATUS.exists(), "R900_STATUS_MISSING")
    report=json.loads(STATUS.read_text("utf-8"))
    require(type(report)==dict and report.get("phase")==phase and
            report.get("owner_sha256")==hash_bytes(MARKER) and
            report.get("native_product_installation_accepted") is False,
            "R900_STATUS_TAMPER_OR_WRONG_PHASE")


def _pause() -> None:
    # Host must verify ready marker, then forcibly STOP ONLY its guest
    # WindowsSandboxRemoteSession process. Never request host reboot.
    while True:
        time.sleep(1)


def stage_and_pause() -> None:
    require(ROOT.is_dir() and not LEDGER.exists() and
            not STATUS.exists() and not RESULT.exists(),
            "R900_FIRST_GUEST_NOT_EMPTY")
    coord=_coord()
    old=_source("1.5.6")
    newer=_source("1.5.7")
    coord.prepare(old)
    coord.activate(lambda:True)
    coord.finalize(lambda:True)
    _versions("1.5.6")
    OWNER.parent.mkdir(parents=True,exist_ok=True)
    OWNER.write_bytes(MARKER)
    _owner()
    coord.prepare(newer)
    coord.activate(lambda:True)
    require(coord._journal()["phase"]=="activated",
            "R900_PENDING_ACTIVATED_NOT_DURABLE")
    _status("READY_TO_FORCE_VM_EXIT_BEFORE_ROLLBACK")
    print("R900_GUEST_ONE_ACTIVATED_VM_CUT_READY",flush=True)
    _pause()


def rollback_and_prepare_forward_pause() -> None:
    _check("READY_TO_FORCE_VM_EXIT_BEFORE_ROLLBACK")
    coord=_coord()
    require(coord._journal()["phase"]=="activated",
            "R900_RESTART_PENDING_MISSING")
    _owner()
    coord.abort(lambda:True)
    _versions("1.5.6")
    _owner()
    coord.prepare(_source("1.5.7"))
    coord.activate(lambda:True)
    try:
        coord.finalize(lambda:True,fault_after="code")
    except EngineError as exc:
        require("FIXTURE_INJECTED_AFTER_FINALIZE_code" in str(exc),
                "R900_UNEXPECTED_FORWARD_FAILURE")
    else:
        raise EngineError("R900_COMMIT_INTERRUPTION_NOT_INJECTED")
    require(coord._journal()["phase"]=="finalizing",
            "R900_FORWARD_JOURNAL_NOT_DURABLE")
    _owner()
    _status("READY_TO_FORCE_VM_EXIT_AFTER_FIRST_CODE_COMMIT")
    print("R900_GUEST_TWO_FIRST_SCOPE_COMMITTED_VM_CUT_READY",flush=True)
    _pause()


def replay_forward_after_second_vm_exit() -> None:
    _check("READY_TO_FORCE_VM_EXIT_AFTER_FIRST_CODE_COMMIT")
    coord=_coord()
    require(coord._journal()["phase"]=="finalizing",
            "R900_RESTART_FORWARD_JOURNAL_MISSING")
    _owner()
    coord.finalize(lambda:True)
    _versions("1.5.7")
    _owner()
    require(not coord.path.exists(),
            "R900_COORDINATOR_JOURNAL_NOT_CLEARED")
    require(not RESULT.exists() and not RESULT.is_symlink(),
            "R900_RESULT_EXISTS")
    atomic_json(RESULT,{
        "schema":1,
        "status":"PASS_R900_SYNTHETIC_TWO_VM_FORCED_TERMINATIONS_REPLAY",
        "old_version":"1.5.6",
        "final_version":"1.5.7",
        "rollback_after_first_guest_exit":True,
        "forward_replay_after_second_guest_exit":True,
        "user_data_sha256":hash_bytes(MARKER),
        "native_product_installation_accepted":False,
        "physical_power_loss_accepted":False,
        "real_service_or_uac_accepted":False,
    })
    print("R900_GUEST_THREE_FORWARD_REPLAY_PASS",flush=True)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("phase",choices=(
        "stage","rollback-then-forward","complete"))
    args=parser.parse_args()
    require(os.name=="nt" and sys.platform=="win32",
            "R900_WINDOWS_GUEST_ONLY")
    require(ROOT == Path(r"C:\DIMR900\persist"),
            "R900_FIXED_SYNTHETIC_ROOT_ONLY")
    if args.phase=="stage":
        stage_and_pause()
    elif args.phase=="rollback-then-forward":
        rollback_and_prepare_forward_pause()
    else:
        replay_forward_after_second_vm_exit()


if __name__=="__main__":
    try:
        main()
    except (EngineError, OSError, ValueError, KeyError, TypeError) as err:
        print(json.dumps({"status":"FAIL_CLOSED_R900_SYNTHETIC_VM_REPLAY",
                          "phase":sys.argv[1:],
                          "reason":str(err),
                          "native_product_installation_accepted":False}),
              file=sys.stderr,flush=True)
        raise SystemExit(3)
