"""R902 shared policy+replay OS trust preflight: pure contract tests.

Real kernel root-owned descriptor tests run in the feature-push-only isolated
Ubuntu CI fixture. A Mock here cannot grant an OS authorization.
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from installer_engine.broker_intent import BROKER_STATUS
from installer_engine.broker_replay import parse_replay_snapshot
from installer_engine.broker_trust_observe import (
    STATUS, observe_linux_policy_replay_snapshot,
)
from installer_engine.engine import EngineError, hash_bytes
from installer_engine.linux_trusted_fd import TrustedLinuxRootFD
from tests.test_engine_broker_intent import canonical, fixture_contract


def fixture():
    plan, policy, request, pb, rb = fixture_contract()
    active = {
        "request_id": request["request_id"],
        "request_sha256": hash_bytes(rb),
        "policy_sha256": hash_bytes(pb),
        "version": plan.version,
        "operation": request["operation"],
        "phase": "applying",
    }
    ledger = {
        "schema": 1,
        "platform": plan.platform,
        "used_request_ids": [request["request_id"]],
        "active": active,
    }
    return plan, pb, rb, ledger


def mock_observe(plan, policy_bytes, request_bytes, ledger):
    lb = canonical(ledger)
    root = object.__new__(TrustedLinuxRootFD)
    # No real open or file writes: the pure contract below gets preverified
    # byte fixtures from a Mock. Native OS protection is tested separately.
    def pinned(name, digest, count):
        content = {"policy.json": policy_bytes, "journal.json": lb}[name]
        if hash_bytes(content) != digest or len(content) != count:
            raise EngineError("MOCK_PIN_MISMATCH")
        return content
    with mock.patch.object(TrustedLinuxRootFD, "read_pinned_small_file",
                           autospec=True, side_effect=lambda _, *args: pinned(*args)):
        return observe_linux_policy_replay_snapshot(
            plan, root, "policy.json", hash_bytes(policy_bytes),
            len(policy_bytes), "journal.json", hash_bytes(lb),
            len(lb), request_bytes)


class BrokerProtectedSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.pb, self.rb, self.doc = fixture()

    def check(self):
        return mock_observe(self.plan, self.pb, self.rb, self.doc)

    def test_exact_active_request_with_two_trusted_members_is_readonly(self):
        result = self.check()
        self.assertEqual(result["status"], STATUS)
        self.assertEqual(result["phase"], "applying")
        self.assertEqual(result["request_id"], "10"*16)
        self.assertFalse(result["native_installation_accepted"])
        self.assertFalse(result["publisher_authenticated"])
        self.assertFalse(result["privileged_broker_implemented"])
        self.assertFalse(result["protected_write_performed"])

    def test_r973_broker_owned_staging_observed_without_authority(self):
        # R970 may persist staging before native quiesce; the SAME reader
        # should observe that ID without mistaking it for APPLYING.
        self.doc["active"]["phase"] = "staging"
        result = self.check()
        self.assertEqual(result["phase"], "staging")
        self.assertFalse(result["native_installation_accepted"])
        self.assertFalse(result["publisher_authenticated"])
        self.assertFalse(result["privileged_broker_implemented"])
        self.assertFalse(result["protected_write_performed"])
        self.assertNotIn("native_receipt", result)

    def test_r973_staging_uninstall_or_terminal_is_not_live_approval(self):
        self.doc["active"]["phase"] = "staging"
        self.doc["active"]["operation"] = "uninstall"
        with self.assertRaisesRegex(EngineError,
                                    "BROKER_REPLAY_STAGE_OPERATION_INVALID"):
            self.check()
        self.doc["active"]["operation"] = "upgrade"
        for phase in ("completed_synthetic", "aborted_synthetic"):
            self.doc["active"]["phase"] = phase
            with self.subTest(phase=phase), self.assertRaisesRegex(
                    EngineError, "BROKER_SNAPSHOT_PHASE_INVALID"):
                self.check()

    def test_reserved_snapshot_is_recovery_not_authorization(self):
        self.doc["active"]["phase"] = "reserved"
        result = self.check()
        self.assertEqual(result["phase"], "reserved")
        self.assertFalse(result["native_installation_accepted"])

    def test_no_active_request_cannot_be_read_as_approved(self):
        self.doc["active"] = None
        with self.assertRaisesRegex(EngineError, "BROKER_SNAPSHOT_NO_ACTIVE_REQUEST"):
            self.check()

    def test_changed_policy_hash_in_ledger_is_rejected(self):
        self.doc["active"]["policy_sha256"] = "0"*64
        with self.assertRaisesRegex(EngineError, "BROKER_SNAPSHOT_POLICY_REPLAY_IDENTITY_DRIFT"):
            self.check()

    def test_changed_client_request_hash_in_ledger_is_rejected(self):
        self.doc["active"]["request_sha256"] = "0"*64
        with self.assertRaisesRegex(EngineError, "BROKER_SNAPSHOT_POLICY_REPLAY_IDENTITY_DRIFT"):
            self.check()

    def test_changed_action_or_version_is_rejected(self):
        for key, bad in (("operation","uninstall"),("version","1.5.6")):
            original=self.doc["active"][key]
            with self.subTest(key=key):
                self.doc["active"][key]=bad
                with self.assertRaisesRegex(EngineError,"BROKER_SNAPSHOT_POLICY_REPLAY_IDENTITY_DRIFT"):
                    self.check()
            self.doc["active"][key]=original

    def test_wrong_active_id_is_rejected(self):
        self.doc["used_request_ids"].append("33"*16)
        self.doc["active"]["request_id"]="33"*16
        with self.assertRaisesRegex(EngineError,"BROKER_SNAPSHOT_POLICY_REPLAY_IDENTITY_DRIFT"):
            self.check()

    def test_wrong_replay_platform_rejected(self):
        self.doc["platform"]="windows-x86_64"
        with self.assertRaisesRegex(EngineError, "BROKER_REPLAY_SCHEMA_OR_PLATFORM"):
            self.check()

    def test_replay_document_invalid_structure_rejected(self):
        self.doc["active"]["native_installation_accepted"]=True
        with self.assertRaisesRegex(EngineError,"BROKER_REPLAY_ACTIVE_SCHEMA"):
            self.check()

    def test_replay_document_missing_used_request_id_rejected(self):
        self.doc["used_request_ids"]=[]
        with self.assertRaisesRegex(EngineError,"BROKER_REPLAY_ACTIVE_ID_NOT_RESERVED"):
            self.check()

    def test_untrusted_handle_is_rejected(self):
        with self.assertRaisesRegex(EngineError,"BROKER_SNAPSHOT_TRUSTED_ROOT_HANDLE_REQUIRED"):
            observe_linux_policy_replay_snapshot(
                self.plan, object(), "policy.json", hash_bytes(self.pb),
                len(self.pb), "journal.json", "0"*64, 20, self.rb)

    def test_cannot_use_same_member_for_policy_and_ledger(self):
        with self.assertRaisesRegex(EngineError,"BROKER_SNAPSHOT_DISTINCT_MEMBERS_REQUIRED"):
            observe_linux_policy_replay_snapshot(
                self.plan, object.__new__(TrustedLinuxRootFD),
                "policy.json", hash_bytes(self.pb), len(self.pb),
                "policy.json", hash_bytes(self.pb), len(self.pb), self.rb)

    def test_actual_policy_request_mismatch_rejected(self):
        with self.assertRaisesRegex(EngineError,"BROKER_REQUEST_BYTES_NOT_POLICY_PINNED"):
            mock_observe(self.plan,self.pb,self.rb+b" ",self.doc)

    def test_replay_snapshot_parser_rejects_empty_and_oversized(self):
        for candidate in (b"", b" "*65537):
            with self.subTest(len=len(candidate)):
                with self.assertRaisesRegex(EngineError,"BROKER_REPLAY_SNAPSHOT_BYTES_INVALID"):
                    parse_replay_snapshot(candidate, "linux-x86_64")

    def test_replay_snapshot_parser_rejects_duplicate_json_keys(self):
        raw=canonical(self.doc).replace(b'"schema":1',
                                        b'"schema":1,"schema":1',1)
        with self.assertRaisesRegex(EngineError,"BROKER_DUPLICATE_JSON_KEY"):
            parse_replay_snapshot(raw,"linux-x86_64")

    def test_replay_snapshot_parser_rejects_non_object(self):
        with self.assertRaisesRegex(EngineError,"BROKER_REPLAY_SCHEMA_OR_PLATFORM"):
            parse_replay_snapshot(b'[]',"linux-x86_64")

    def test_replay_snapshot_parser_rejects_nonstring_version(self):
        self.doc["active"]["version"]=123
        with self.assertRaisesRegex(EngineError,"BROKER_REPLAY_VERSION_INVALID"):
            parse_replay_snapshot(canonical(self.doc),"linux-x86_64")


if __name__=="__main__":
    unittest.main()
