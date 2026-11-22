"""R934: Windows actual-held-file policy + replay snapshot parity with Linux.

The exact same R899 policy/request and R901 replay parser are reused. This is
a read-only *preflight* of USER-OWNED TEST files: an OK result is NOT proof of
a protected parent, SCM authorization, a publisher or native installation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from installer_engine.broker_trust_observe import (
    WINDOWS_STATUS, observe_windows_policy_replay_snapshot,
)
from installer_engine.engine import EngineError, hash_bytes
from installer_engine.windows_handle_bound import read_windows_pinned_small_file
from tests.test_engine_broker_intent import (
    canonical, fixture_contract, fixture_plan,
)


@unittest.skipUnless(os.name == "nt", "OS native Win32 handles required")
class BrokerWindowsHeldSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="dim-r934-wbroker-")
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.plan, self.policy, self.request, self.pb, self.rb = (
            fixture_contract(fixture_plan("windows-x86_64")))
        self.policyfile = self.root/"policy.json"
        self.ledgerfile = self.root/"replay.json"
        self.policyfile.write_bytes(self.pb)
        self.ledger = {
            "schema": 1, "platform": "windows-x86_64",
            "used_request_ids": [self.request["request_id"]],
            "active": {
                "request_id": self.request["request_id"],
                "request_sha256": hash_bytes(self.rb),
                "policy_sha256": hash_bytes(self.pb),
                "version": self.plan.version,
                "operation": self.request["operation"],
                "phase": "applying",
            },
        }
        self.ledgerfile.write_bytes(canonical(self.ledger))

    def inspect(self, *, policy_pin=None, ledger_pin=None, policy_bytes=None,
                ledger_bytes=None, policyfile=None, ledgerfile=None,
                request=None, plan=None):
        return observe_windows_policy_replay_snapshot(
            plan or self.plan,
            str(policyfile or self.policyfile),
            policy_pin or hash_bytes(self.pb),
            len(self.pb) if policy_bytes is None else policy_bytes,
            str(ledgerfile or self.ledgerfile),
            ledger_pin or hash_bytes(self.ledgerfile.read_bytes()),
            self.ledgerfile.stat().st_size if ledger_bytes is None
            else ledger_bytes,
            self.rb if request is None else request,
        )

    def test_real_held_windows_snapshot_exact_readonly_and_no_authority(self):
        out = self.inspect()
        self.assertEqual(out["status"], WINDOWS_STATUS)
        self.assertEqual(out["request_id"], self.request["request_id"])
        self.assertEqual(out["phase"], "applying")
        self.assertFalse(out["native_installation_accepted"])
        self.assertFalse(out["privileged_broker_implemented"])
        self.assertFalse(out["publisher_authenticated"])
        self.assertFalse(out["protected_write_performed"])
        self.assertFalse(out["os_protected_parent_verified"])
        self.assertEqual(self.policyfile.read_bytes(), self.pb)

    def test_verified_read_is_exact_original_bytes_not_a_second_open(self):
        found = read_windows_pinned_small_file(
            self.policyfile, len(self.pb), hash_bytes(self.pb))
        self.assertEqual(found, self.pb)
        with self.assertRaisesRegex(EngineError, "WIN32_HANDLE_PIN_MISMATCH"):
            read_windows_pinned_small_file(
                self.policyfile, len(self.pb), "0"*64)
        with self.assertRaisesRegex(EngineError, "WIN32_HANDLE_SIZE_MISMATCH"):
            read_windows_pinned_small_file(
                self.policyfile, len(self.pb)+1, hash_bytes(self.pb))

    def test_zero_and_oversize_snapshot_are_not_authorized(self):
        for sz in (-1, 65537, 1 << 31):
            with self.subTest(size=sz):
                with self.assertRaisesRegex(EngineError, "WIN32_HANDLE_"):
                    read_windows_pinned_small_file(self.policyfile, sz,
                                                  hash_bytes(self.pb))
        self.policyfile.write_bytes(b"")
        with self.assertRaisesRegex(EngineError, "BROKER_POLICY_BYTES_INVALID"):
            self.inspect(policy_pin=hash_bytes(b""), policy_bytes=0)

    def test_changed_policy_pin_is_denied(self):
        with self.assertRaisesRegex(EngineError, "WIN32_HANDLE_PIN_MISMATCH"):
            self.inspect(policy_pin="0"*64)

    def test_changed_ledger_pin_is_denied(self):
        with self.assertRaisesRegex(EngineError, "WIN32_HANDLE_PIN_MISMATCH"):
            self.inspect(ledger_pin="0"*64)

    def test_ledger_wrong_native_request_identity_rejected(self):
        for name,wrong in (("request_sha256","0"*64),
                           ("policy_sha256","0"*64),
                           ("version","1.5.6"),
                           ("operation","uninstall"),
                           ("request_id","33"*16)):
            with self.subTest(field=name):
                before=self.ledger["active"][name]
                self.ledger["active"][name]=wrong
                if name=="request_id":
                    self.ledger["used_request_ids"].append(wrong)
                self.ledgerfile.write_bytes(canonical(self.ledger))
                with self.assertRaisesRegex(
                        EngineError, "BROKER_SNAPSHOT_POLICY_REPLAY_IDENTITY_DRIFT"):
                    self.inspect()
                self.ledger["active"][name]=before
                if name=="request_id":
                    self.ledger["used_request_ids"].remove(wrong)

    def test_closed_snapshot_without_active_request_not_accepted(self):
        self.ledger["active"]=None
        self.ledgerfile.write_bytes(canonical(self.ledger))
        with self.assertRaisesRegex(EngineError, "BROKER_SNAPSHOT_NO_ACTIVE_REQUEST"):
            self.inspect()

    def test_replay_snapshot_duplicate_field_denied(self):
        raw=canonical(self.ledger)
        dup=raw.replace(b'"schema":1',b'"schema":1,"schema":1',1)
        self.assertNotEqual(raw,dup)
        self.ledgerfile.write_bytes(dup)
        with self.assertRaisesRegex(EngineError, "BROKER_DUPLICATE_JSON_KEY"):
            self.inspect()

    def test_wrong_platform_denied_before_native_io(self):
        with self.assertRaisesRegex(EngineError, "BROKER_WINDOWS_TARGET_REQUIRED"):
            self.inspect(plan=fixture_plan("linux-x86_64"))

    def test_local_canonical_paths_distinct_and_no_reparse(self):
        with self.assertRaisesRegex(EngineError,
                                    "BROKER_SNAPSHOT_DISTINCT_MEMBERS_REQUIRED"):
            self.inspect(ledgerfile=self.policyfile)
        with self.assertRaisesRegex(EngineError,
                                    "WIN32_HANDLE_LOCAL_CANONICAL_PATH_REQUIRED"):
            self.inspect(policyfile=Path("relative-user-file.json"))
        alias=self.root/"alias.json"
        try:
            alias.symlink_to(self.policyfile)
        except (OSError, NotImplementedError):
            self.skipTest("Native Windows symlink privileges unavailable")
        with self.assertRaisesRegex(EngineError,
                                    "WIN32_HANDLE_REPARSE_DIRECTORY_OR_LINK"):
            self.inspect(policyfile=alias)

    def test_request_changed_without_policy_repin_denied(self):
        raw=self.rb+b" "
        with self.assertRaisesRegex(EngineError,
                                    "BROKER_REQUEST_BYTES_NOT_POLICY_PINNED"):
            self.inspect(request=raw)

    def test_readonly_user_owned_snapshot_cannot_mint_native_receipt(self):
        out=self.inspect()
        self.assertFalse(out["os_protected_parent_verified"])
        self.assertFalse(out["native_installation_accepted"])
        self.assertNotIn("native_receipt",out)
        self.assertNotIn("completed",out)
        self.assertNotIn("authorization_token",out)


if __name__ == "__main__":
    unittest.main()
