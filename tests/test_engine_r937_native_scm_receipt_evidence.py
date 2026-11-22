"""R937 immutable Windows SYSTEM guest evidence + shared R901/R926 verification.

These are checks of native source proof already captured on a real Windows
Sandbox. They do NOT execute an SCM service on CI or create publisher trust.
Actual tests were executed in a network-disabled guest; all native receipt
and replay claims are explicitly restricted to synthetic fixture operations.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from installer_engine.broker_replay import parse_replay_snapshot
from installer_engine.engine import EngineError
from installer_engine.native_receipt import (
    intent_sha256, validate_intent, verify_completion_receipt,
    verify_restoration_receipt,
)


ROOT = Path(__file__).resolve().parents[1] / "evidence"
PREFIX = "DIM_R937_WINDOWS_SCM_"
SHA256 = {
    "SETUP.json": "c397052cf8fbcf45f94935b50750e9bbc7f9bc31ca48dbf50ea30e408315c4f6",
    "CLIENT_GOOD.json": "ea098a12c4eeb340a5526fc767ebb0c9117b3a8c6fb2c86a1845ec5b08ffdd05",
    "CLIENT_TAMPERED.json": "9aa7d7d471aad7739e55c3941e9f0d9ae837ca74b06533fc0eda76d93bd78cec",
    "CLIENT_REPLAY.json": "b693e72906d49dbca42f4600699ceae44cd5ddb14680d170e74133b51dbf381d",
    "RESTART.json": "93fdf00e23bbc01609e5f2cfd15f7f9f3881c0bf4929cf33a0d29aa53f47702a",
    "CLIENT_REPLAY_POSTRESTART.json": "f9a96f227698b6b1569c572299624c12bc99ba994eb4a2842543e3ca0532c509",
    "FINAL_PROOF.json": "d466805f945e17bfb94e90cf9a3a888583011772ac04ec804e4989b5dacaf8d3",
    "NATIVE_RECEIPT.json": "49559dfbab63de74da7745c751a128dbbca8a011ca928a435e41d942ce731323",
    "REPLAY_LEDGER.json": "c653bf0e3ab213b146f1cddcfa6f2e67c3ed570e9547e753f1fb25a5e2a87701",
    "NATIVE_INTENT.json": "018ad8d31a9fdcac5cd6730c4d433fb2b44cf1a2a1189638a324e16330bc45bf",
    "INPUT_PINS.json": "c2b2ffdd5ee26c6796314aa6803a53ff3080fcc0e1881b7060cb35c28c6c4d25",
    "RAW_GOOD_CLIENT.log": "026dbe7237a14c237889c42a5e1ca445f231c4d0c928de63037b45ef6e2e92cb",
    "RAW_TAMPERED_CLIENT.log": "b76e48abc6eee9dfc5f9e9c46a11478f6b02f497eda57731d5a1d8873cbd9b17",
    "RAW_REPLAY_POSTRESTART_CLIENT.log": "67126e262bfc967a277d0697cc4b39950bf0271bbcc37ce30b32b298ae80d9bf",
    "HISTORICAL_SETUP_HARNESS_FAILURE.json": "423266963fb0f847183866da138c84018ef206b9482d93f8da07810aa714f401",
    "HISTORICAL_CLIENT_RIGHTS_FAILURE.json": "b0870b4ae6eea2a92e4fc75d5c519d48da16bf7c776b1efd409c17160b0b0fdc",
}


def raw(name: str) -> bytes:
    return (ROOT / (PREFIX + name)).read_bytes()


def data(name: str) -> dict:
    return json.loads(raw(name))


class R937NativeSystemScmReceiptEvidence(unittest.TestCase):
    def test_all_os_guest_bytes_preserved_exactly(self):
        for name, expected in SHA256.items():
            with self.subTest(original=name):
                self.assertEqual(hashlib.sha256(raw(name)).hexdigest(), expected)

    def test_exact_r926_receipt_matches_only_this_synthetic_intent(self):
        native = data("NATIVE_INTENT.json")
        pins = data("INPUT_PINS.json")
        validate_intent(native)
        receipt = raw("NATIVE_RECEIPT.json")
        self.assertTrue(verify_completion_receipt(native, receipt))
        self.assertEqual(intent_sha256(native), pins["native_receipt_intent_sha256"])
        self.assertEqual(native["request_id"], pins["request_id"])
        self.assertEqual(native["platform"], "windows-x86_64")
        self.assertEqual(len(native["scope_pins"]), 2)
        self.assertEqual([s["name"] for s in native["scope_pins"]],
                         ["code", "user"])
        with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_SCHEMA_INVALID"):
            verify_restoration_receipt(native, receipt)

    def test_r901_native_system_replay_closed_but_id_never_reused(self):
        ledger = parse_replay_snapshot(raw("REPLAY_LEDGER.json"), "windows-x86_64")
        native = data("NATIVE_INTENT.json")
        self.assertIsNone(ledger["active"])
        self.assertEqual(ledger["used_request_ids"], [native["request_id"]])
        self.assertEqual(data("FINAL_PROOF.json")["R901_replay_ledger_finalized_no_second_request"], True)

    def test_actual_independent_native_processes_have_only_restricted_token(self):
        setup = data("SETUP.json")
        good = data("CLIENT_GOOD.json")
        self.assertNotEqual(setup["service_pid"], good["client_pid"])
        self.assertEqual(setup["status"], "PASS_R937_REAL_SCM_SYSTEM_BROKER_READY_ONLY")
        for name in (
            "CLIENT_GOOD.json", "CLIENT_TAMPERED.json",
            "CLIENT_REPLAY.json", "CLIENT_REPLAY_POSTRESTART.json",
        ):
            with self.subTest(client=name):
                j = data(name)
                self.assertEqual(
                    j["status"], "PASS_R937_DIFFERENT_PROCESS_OS_RESTRICTED_CLIENT"
                )
                self.assertEqual(j["client_launcher_system_sid"], "S-1-5-18")
                self.assertTrue(j["native_restricted_client_token_verified"])
                self.assertTrue(j["restricted_write_denied"])
                self.assertFalse(j["real_non_system_login_verified"])
                self.assertFalse(j["native_product_installation_accepted"])

    def test_native_scm_restart_preserved_receipt_and_prevented_replay(self):
        restart = data("RESTART.json")
        self.assertNotEqual(
            restart["original_service_pid"], restart["restarted_service_pid"])
        self.assertEqual(
            restart["before_receipt_sha256"], restart["after_receipt_sha256"])
        self.assertEqual(restart["after_receipt_sha256"],
                         SHA256["NATIVE_RECEIPT.json"])
        self.assertEqual(
            data("CLIENT_TAMPERED.json")["rejection_reason"],
            "R937_REQUEST_SHA_MISMATCH")
        self.assertEqual(
            data("CLIENT_REPLAY.json")["rejection_reason"],
            "R937_REQUEST_REPLAY_DENIED")
        self.assertEqual(
            data("CLIENT_REPLAY_POSTRESTART.json")["rejection_reason"],
            "R937_REQUEST_REPLAY_DENIED")
        final = data("FINAL_PROOF.json")
        self.assertTrue(final["owner_data_preserved"])
        self.assertTrue(final["service_unregistered"])
        self.assertTrue(final["service_restarted_and_replay_denied"])

    def test_stale_tampered_or_restored_receipt_fails_closed(self):
        native = data("NATIVE_INTENT.json")
        receipt = raw("NATIVE_RECEIPT.json")
        altered = dict(native, request_id="33"*16)
        with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_INTENT_MISMATCH"):
            verify_completion_receipt(altered, receipt)
        changed = json.loads(json.dumps(native))
        changed["scope_pins"][0]["manifest_sha256"] = "f"*64
        with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_INTENT_MISMATCH"):
            verify_completion_receipt(changed, receipt)
        tampered = receipt.replace(b'"completed"', b'"restored"')
        with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_SCHEMA_INVALID"):
            verify_completion_receipt(native, tampered)

    def test_no_broad_product_or_publisher_acceptance_claim(self):
        final = data("FINAL_PROOF.json")
        for name in (
            "native_product_installation_accepted",
            "production_privileged_broker_implemented",
            "publisher_authenticated",
            "hard_powercut_reboot_accepted",
            "real_two_scope_app_upgrade_accepted",
            "real_non_system_login_verified",
        ):
            with self.subTest(claim=name):
                self.assertIs(final[name], False)
        self.assertIs(final["R926_native_completion_receipt_synthetic"], True)
        self.assertIs(final["OS_system_protected_replay_writer_fixture"], True)

    def test_original_failed_guest_evidence_not_rewritten_as_success(self):
        for name in (
            "HISTORICAL_SETUP_HARNESS_FAILURE.json",
            "HISTORICAL_CLIENT_RIGHTS_FAILURE.json",
        ):
            self.assertEqual(data(name)["status"],
                             "FAIL_CLOSED_R937_NATIVE_SCM_FIXTURE")


if __name__ == "__main__":
    unittest.main()
