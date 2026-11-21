"""R899 ephemeral GitHub-hosted Linux root-owned broker-policy fixture.

This script is UNPRIVILEGED. CI's sudo only creates, chmods and removes one
fixture directory and files, never executes this Python process as root.
The synthetic policy bytes are not a publisher signature. No code install,
service mutation, OS authorization or release acceptance is performed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from installer_engine.broker_intent import compare_linux_fd_pinned_intent
from installer_engine.engine import EngineError, hash_bytes
from installer_engine.linux_trusted_fd import TrustedLinuxRootFD
from installer_engine.broker_trust_observe import observe_linux_policy_replay_snapshot
from tests.test_engine_broker_intent import canonical
from tests.test_engine_broker_intent import fixture_contract

_ALLOWED_FIXTURE_NAME = "dim-r898-ci-protected-fd-fixture"
_POLICY_MEMBER = "synthetic-broker-policy.json"
_LEDGER_MEMBER = "synthetic-broker-journal.json"


def _inputs():
    plan, policy, request, pb, rb = fixture_contract()
    return plan, pb, rb


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Synthetic Linux-only root-owned broker POLICY test")
    parser.add_argument("action", choices=(
        "emit-synthetic-policy", "emit-synthetic-ledger",
        "verify-root-policy", "reject-unsafe-policy",
        "verify-root-snapshot", "reject-unsafe-ledger"))
    parser.add_argument("--fixture-root", type=Path)
    a = parser.parse_args(argv)
    plan, pb, rb = _inputs()
    request = json.loads(rb)
    active = {
        "request_id": request["request_id"],
        "request_sha256": hash_bytes(rb),
        "policy_sha256": hash_bytes(pb),
        "version": plan.version,
        "operation": request["operation"],
        "phase": "applying",
    }
    ledger_bytes = canonical({
        "schema": 1, "platform": plan.platform,
        "used_request_ids": [request["request_id"]],
        "active": active,
    })
    if a.action in ("emit-synthetic-policy", "emit-synthetic-ledger"):
        if a.fixture_root is not None:
            parser.error("emit action has no destination argument")
        sys.stdout.buffer.write(pb if a.action == "emit-synthetic-policy"
                                else ledger_bytes)
        return 0
    if a.fixture_root is None or a.fixture_root.name != _ALLOWED_FIXTURE_NAME:
        parser.error("synthetic fixture root name required")
    if not a.fixture_root.is_absolute():
        parser.error("synthetic fixture root must be absolute")
    with TrustedLinuxRootFD(a.fixture_root) as directory:
        if a.action == "verify-root-policy":
            report = compare_linux_fd_pinned_intent(
                plan, directory, _POLICY_MEMBER,
                hash_bytes(pb), len(pb), rb)
            if (report["native_installation_accepted"] is not False or
                    report["publisher_authenticated"] is not False or
                    report["privileged_broker_implemented"] is not False):
                raise EngineError("FIXTURE_BROKER_MUST_NOT_AUTHORIZE")
            try:
                compare_linux_fd_pinned_intent(
                    plan, directory, _POLICY_MEMBER,
                    hash_bytes(pb), len(pb), rb + b" ")
            except EngineError as exc:
                if "BROKER_REQUEST_BYTES_NOT_POLICY_PINNED" not in str(exc):
                    raise
            else:
                raise EngineError("FIXTURE_UNPINNED_REQUEST_ACCEPTED")
            print(json.dumps({
                "status": "PASS_R899_ROOT_OWNED_FD_POLICY_AND_INTENT_BOUND",
                "native_installation_accepted": False,
                "publisher_authenticated": False,
            }, sort_keys=True))
        elif a.action == "verify-root-snapshot":
            observed = observe_linux_policy_replay_snapshot(
                plan, directory, _POLICY_MEMBER, hash_bytes(pb), len(pb),
                _LEDGER_MEMBER, hash_bytes(ledger_bytes),
                len(ledger_bytes), rb)
            if (observed["native_installation_accepted"] is not False or
                    observed["publisher_authenticated"] is not False or
                    observed["privileged_broker_implemented"] is not False or
                    observed["protected_write_performed"] is not False or
                    observed["phase"] != "applying"):
                raise EngineError("FIXTURE_OS_TRUST_NOT_READ_ONLY")
            try:
                observe_linux_policy_replay_snapshot(
                    plan, directory, _POLICY_MEMBER, hash_bytes(pb), len(pb),
                    _LEDGER_MEMBER, hash_bytes(ledger_bytes),
                    len(ledger_bytes), rb + b" ")
            except EngineError as exc:
                if "BROKER_REQUEST_BYTES_NOT_POLICY_PINNED" not in str(exc):
                    raise
            else:
                raise EngineError("FIXTURE_UNPINNED_LEDGER_REQUEST_ACCEPTED")
            print("PASS_R902_FD_BOUND_ROOT_OWNED_POLICY_AND_LEDGER_MATCH")
        elif a.action == "reject-unsafe-ledger":
            try:
                observe_linux_policy_replay_snapshot(
                    plan, directory, _POLICY_MEMBER, hash_bytes(pb), len(pb),
                    _LEDGER_MEMBER, hash_bytes(ledger_bytes),
                    len(ledger_bytes), rb)
            except EngineError as exc:
                if "TRUSTED_FD_MEMBER_NOT_ROOT_OWNED_REGULAR" not in str(exc):
                    raise
            else:
                raise EngineError("FIXTURE_WORLD_WRITABLE_LEDGER_ACCEPTED")
            print("PASS_R902_WORLD_WRITABLE_LEDGER_REFUSED")
        else:
            try:
                compare_linux_fd_pinned_intent(
                    plan, directory, _POLICY_MEMBER,
                    hash_bytes(pb), len(pb), rb)
            except EngineError as exc:
                if "TRUSTED_FD_MEMBER_NOT_ROOT_OWNED_REGULAR" not in str(exc):
                    raise
            else:
                raise EngineError("FIXTURE_WORLD_WRITABLE_POLICY_ACCEPTED")
            print("PASS_R899_WORLD_WRITABLE_POLICY_REFUSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
