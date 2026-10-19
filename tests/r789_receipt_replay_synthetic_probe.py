#!/usr/bin/env python3
"""Defensive read-only-source regression: acceptance receipt replay across synthetic upgrade attempts.

Only R519 FakeFixture disposable user-owned roots; NEVER invokes pkexec,
real RootTransaction CLI, installed services or network. Evidence only.
"""
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("r789_fixture",ROOT/"tests/protected_upgrade_transaction_contract.py")
fixture=importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

def staged_fixture():
    obj=fixture.FakeFixture("test_success_stage_apply_rollback")
    obj.setUp()
    assert obj.tx.stage(obj.pkg)["status"]=="STAGED"
    assert obj.tx.apply()["status"]=="APPLIED"
    return obj

one=staged_fixture()
try:
    one_m=one.tx.manifest()
    prior={
        "revision":"R519",
        "status":"PASS_NATIVE_ROOT_UPGRADE",
        "sourceRootSHA":fixture.m.sha(fixture.m.canonical(one_m["files"])),
        "protectedMetadataSHA":one_m["newMetadataSHA"],
        "transactionNonce":one_m["transactionNonce"],
        "nativeStartStopRecovery":True,
        "tailscalePreserved":True,
        "physicalDNSPreserved":True
    }
    first_file=one.root/"first_attempt_receipt.json"
    first_file.write_text(json.dumps(prior)+"\n")
    assert one.tx.commit(first_file)["status"]=="COMMITTED"
finally:
    one.tearDown()

two=staged_fixture()
try:
    two_m=two.tx.manifest()
    assert prior["sourceRootSHA"]==fixture.m.sha(fixture.m.canonical(two_m["files"]))
    assert prior["protectedMetadataSHA"]==two_m["newMetadataSHA"]
    replay=two.root/"STALE_previous_attempt.json"
    replay.write_text(json.dumps(prior)+"\n")
    # No fresh acceptance exists yet. Reusing an older success receipt
    # from an identical baseline MUST be rejected.
    assert prior["transactionNonce"] != two_m["transactionNonce"]
    try:
        two.tx.commit(replay)
    except RuntimeError as exc:
        assert "FAIL_CLOSED_NATIVE_ACCEPTANCE_NOT_PROVEN" in str(exc),str(exc)
    else:
        raise AssertionError("R789_STALE_ACCEPTANCE_REPLAYED")
    assert two.tx.status()["status"] == "APPLIED"
    # A genuine fresh transaction-specific receipt still permits commit.
    fresh=dict(prior,transactionNonce=two_m["transactionNonce"])
    fresh_file=two.root/"current_attempt_receipt.json"
    fresh_file.write_text(json.dumps(fresh)+"\n")
    outcome=two.tx.commit(fresh_file)
    assert outcome["status"] == "COMMITTED"
    print(json.dumps({
        "schema":1,"scenario":"two_identical_synthetic_upgrade_attempts",
        "stale_receipt_rejected":True,
        "fresh_receipt_committed":True,
        "scope":"FAKE_ROOT_ONLY; native owner/mode and Polkit not tested"
    },sort_keys=True))
finally:
    two.tearDown()
