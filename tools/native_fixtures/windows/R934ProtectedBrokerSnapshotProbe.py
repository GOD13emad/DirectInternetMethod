"""R934 read-only broker policy/replay probe for disposable Windows Sandbox.

Uses the existing EXACT NativePlan, R899 policy/request and R901 replay parser
through the new Win32 held-file primitive. No SCM, publisher verification,
privileged operation, native receipt issuance or code installation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

from installer_engine.broker_trust_observe import (
    WINDOWS_STATUS, observe_windows_policy_replay_snapshot,
)
from installer_engine.engine import EngineError, hash_bytes
from tests.test_engine_broker_intent import (
    canonical, fixture_contract, fixture_plan,
)

ROOT = Path(r"C:\ProgramData\DIM_R934_IsolatedBrokerReadOnly")
INPUT = Path(r"C:\DIMR934\input")
EXPECTED = ("policy.json", "replay.json")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _contract():
    plan, policy, request, pb, rb = fixture_contract(
        fixture_plan("windows-x86_64"))
    journal = {
        "schema": 1, "platform": "windows-x86_64",
        "used_request_ids": [request["request_id"]],
        "active": {
            "request_id": request["request_id"],
            "request_sha256": hash_bytes(rb),
            "policy_sha256": hash_bytes(pb),
            "version": plan.version,
            "operation": request["operation"],
            "phase": "applying",
        },
    }
    return plan, pb, rb, canonical(journal)


def expected_input_bytes() -> dict:
    _, pb, rb, ledger = _contract()
    return {"policy.json": pb, "replay.json": ledger,
            "request": rb}


def run() -> dict:
    if os.name != "nt" or os.environ.get("DIM_R934_TEST_ONLY") != "true":
        raise EngineError("R934_NATIVE_WIN_SANDBOX_ONLY")
    if not Path(r"C:\Users\WDAGUtilityAccount").is_dir():
        raise EngineError("R934_NATIVE_WIN_GUEST_NOT_SANDBOX")
    plan, pb, rb, ledger = _contract()
    pins = json.loads((INPUT/"pins.json").read_text(encoding="utf8"))
    if (type(pins) is not dict or set(pins) != {
        "schema", "scope", "policy_sha256", "ledger_sha256",
        "policy_bytes", "ledger_bytes", "source_sha256", "probe_sha256"}
            or pins["schema"] != 1
            or pins["scope"] != "R934_WIN_NATIVE_HELD_READONLY"):
        raise EngineError("R934_PIN_SCHEMA_INVALID")
    if (pins["policy_sha256"] != sha(pb)
            or pins["ledger_sha256"] != sha(ledger)
            or pins["policy_bytes"] != len(pb)
            or pins["ledger_bytes"] != len(ledger)):
        raise EngineError("R934_PREBUILT_CONTRACT_DRIFT")
    if sha(Path(sys.executable).read_bytes()) != pins["probe_sha256"]:
        raise EngineError("R934_NATIVE_PROBE_SELF_DIGEST_DRIFT")
    # This is a test-only out-of-band pin from a read-only input mount.
    # Never interpret it as a trusted publisher credential.
    if ((INPUT/"policy.json").read_bytes() != pb or
            (INPUT/"replay.json").read_bytes() != ledger):
        raise EngineError("R934_INPUT_SOURCE_DRIFT")
    response = observe_windows_policy_replay_snapshot(
        plan, str(ROOT/"policy.json"), sha(pb), len(pb),
        str(ROOT/"replay.json"), sha(ledger), len(ledger), rb)
    if (response["status"] != WINDOWS_STATUS or
            response["native_installation_accepted"] or
            response["privileged_broker_implemented"] or
            response["publisher_authenticated"] or
            response["os_protected_parent_verified"] or
            response["protected_write_performed"]):
        raise EngineError("R934_OBSERVER_MUST_NEVER_AUTHORIZE")
    return {
        "schema": 1, "status": "PASS_R934_NATIVE_WINDOWS_HELD_OS_SNAPSHOT_READONLY_ONLY",
        "request_id": response["request_id"],
        "phase": response["phase"],
        "native_windows_held_file_policy_sha256": response["policy_sha256"],
        "native_windows_held_file_ledger_sha256": response["ledger_sha256"],
        "probe_process_os_rights": "NOT_ATTESTED_BY_THIS_MODULE",
        "publisher_authenticated": False,
        "native_receipt_issued": False,
        "native_installation_accepted": False,
        "privileged_broker_implemented": False,
        "os_protected_parent_verified_by_python_module": False,
    }


if __name__ == "__main__":
    try:
        # Avoid generating untrusted source files, running SCM or taking any
        # action other than the two OS-read-only pinned file observations.
        print(json.dumps(run(), sort_keys=True))
    except (EngineError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "FAIL_CLOSED_R934_NATIVE_READONLY",
                          "reason": str(exc),
                          "native_installation_accepted": False},
                         sort_keys=True), file=sys.stderr)
        raise SystemExit(3)
