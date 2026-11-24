"""Build R937 synthetic Windows SCM broker receipt inputs from existing contracts.

Input roots are disposable Windows temp, exact SHA-pinned .NET binary and
project-owned sources. Reuses R899 broker request and R926 native receipt
identity + R901 replay parser. No production publisher credential is minted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from installer_engine.broker_intent import compare_native_transaction_policy_intent
from installer_engine.broker_replay import parse_replay_snapshot
from installer_engine.engine import hash_bytes
from installer_engine.native_receipt import intent_sha256, validate_intent
from tests.test_engine_broker_intent import fixture_contract, fixture_plan, canonical

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "tools/native_fixtures/windows/R937NativeScmReceiptFixture.cs"
NAME = "R937NativeScmReceiptFixture.exe"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pinned_native_id64_contract():
    """Reuse ONE R899 plan/policy with real Inno-sized native identity.

    This remains deterministic SYNTHETIC VM input, not a caller-defined
    publisher pin. Native OS SCM and R901 replay must keep all 256 bits.
    Earlier archived R937 32-digit receipts remain immutable evidence.
    """
    plan, policy, request, _, _ = fixture_contract(
        fixture_plan("windows-x86_64"))
    request["request_id"] = "0123456789abcdef" * 4
    request_bytes = canonical(request)
    policy["request_sha256"] = sha(request_bytes)
    policy_bytes = canonical(policy)
    return plan, policy, request, policy_bytes, request_bytes


def build(test_root: Path, binary_sha256: str) -> dict:
    test_root = test_root.absolute()
    temp = Path(tempfile.gettempdir()).resolve()
    if (os.name != "nt" or test_root.parent.resolve() != temp
            or not re.fullmatch(r"dim-r937-scm-native-fixture-[a-z0-9]{8,20}",
                                test_root.name)
            or not test_root.is_dir() or test_root.is_symlink()):
        raise ValueError("R937_EXACT_NEW_OS_TEMP_ROOT_REQUIRED")
    input_root = test_root / "input"
    exe = input_root / NAME
    if (not exe.is_file() or exe.is_symlink()
            or not re.fullmatch(r"[a-f0-9]{64}", binary_sha256)
            or sha(exe.read_bytes()) != binary_sha256):
        raise ValueError("R937_PRECOMPILED_BINARY_PIN_DRIFT")
    allowed = {NAME}
    if any(p.name not in allowed for p in input_root.iterdir()):
        raise ValueError("R937_GUEST_SOURCE_INPUT_NOT_EMPTY")
    plan, policy, request, pb, rb = pinned_native_id64_contract()
    native = {
        "schema": 1,
        "request_id": request["request_id"],
        "platform": request["platform"],
        "operation": request["operation"],
        "old": "1.5.6",
        "new": "1.5.7",
        "preimage_sha256": sha(b"R937_SYNTHETIC_PREIMAGE_156"),
        "scope_pins": request["scopes"],
    }
    validate_intent(native)
    binding = compare_native_transaction_policy_intent(
        plan, pb, hash_bytes(pb), rb, native)
    if (binding["request_sha256"] != sha(rb)
            or binding["native_installation_accepted"]):
        raise ValueError("R937_R899_SOURCE_INTENT_OR_PRIVILEGE_MISMATCH")
    ni = canonical(native)
    ledger = {
        "schema": 1, "platform": "windows-x86_64",
        "used_request_ids": [], "active": None,
    }
    li = canonical(ledger)
    parse_replay_snapshot(li, "windows-x86_64")
    contract = {
        "schema": 1,
        "scope": "R937_SYNTHETIC_SCM_RECEIPT_ONLY",
        "service_name": "DIMR937BrokerFixtureSvc",
        "exe_sha256": binary_sha256,
        "source_sha256": sha(SOURCE.read_bytes()),
        "request_sha256": sha(rb),
        "policy_sha256": sha(pb),
        "native_intent_sha256": sha(ni),
        "native_receipt_intent_sha256": intent_sha256(native),
        "ledger_initial_sha256": sha(li),
        "request_id": request["request_id"],
        "native_product_installed": False,
        "production_broker_implemented": False,
        "publisher_authenticated": False,
    }
    values = {
        "broker-request.json": rb,
        "broker-policy.json": pb,
        "native-intent.json": ni,
        "broker-replay-initial.json": li,
        "pins.json": json.dumps(contract, sort_keys=True,
                                separators=(",", ":")).encode(),
    }
    for filename, content in values.items():
        path = input_root / filename
        if path.exists() or path.is_symlink():
            raise ValueError("R937_NO_INPUT_OVERWRITE_ALLOWED")
        path.write_bytes(content)
    assert intent_sha256(native) == contract["native_receipt_intent_sha256"]
    return contract


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.root,args.expected_binary_sha256),
                     sort_keys=True))
