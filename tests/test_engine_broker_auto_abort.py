"""R981: exact broker auto-abort must be safe, scoped, and fail closed.

Tests ONLY the disposable common transaction fixture. A synthetic receipt,
restoration, or ledger is not evidence of a production Windows/Linux broker.
"""
from __future__ import annotations

import hashlib
import json
import unittest
from unittest.mock import patch

from installer_engine.broker_replay import BrokerReplayFixtureLedger
from installer_engine.engine import EngineError
from tests import test_engine_universal_install as _fixtures


class BrokerNativeFailureAutoAbort(unittest.TestCase):
    def setUp(self):
        self.fixture = _fixtures.UniversalInstallCrossPlatform(
            "test_policy_bound_request_survives_real_coordinator_journal")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.ledger = BrokerReplayFixtureLedger(
            self.fixture.base / "r981-broker", self.fixture.platform)

    def _upgrade(self):
        fixture = self.fixture
        fixture.cycle("1.5.6")
        plan, policy_bytes, _, request_bytes, intent, sources = (
            fixture.broker_bound_install_inputs())
        intent = dict(intent, old="1.5.6", operation="upgrade",
                      preimage_sha256=hashlib.sha256(
                          fixture.adapter.snapshot()).hexdigest())
        request = json.loads(request_bytes)
        request["operation"] = "upgrade"
        request_bytes = json.dumps(request, sort_keys=True).encode()
        policy = json.loads(policy_bytes)
        policy["operation"] = "upgrade"
        policy["request_sha256"] = hashlib.sha256(request_bytes).hexdigest()
        policy_bytes = json.dumps(policy, sort_keys=True).encode()
        return (plan, policy_bytes, hashlib.sha256(policy_bytes).hexdigest(),
                request_bytes, intent, sources)

    def test_realistic_failed_postinstall_without_receipt_auto_restores_old_version(self):
        f = self.fixture
        inputs = self._upgrade()
        owner = f.roots["user"] / "data" / "settings.bin"
        owner.parent.mkdir(parents=True, exist_ok=True)
        owner.write_bytes(b"OWNED-DATA-MUST-SURVIVE")
        f.adapter.complete_on_apply = False
        f.adapter.fail_after_apply = True
        with self.assertRaisesRegex(EngineError,
                                    "UNIVERSAL_BROKER_NATIVE_FAILURE_AUTO_ABORTED_FIXTURE_ONLY"):
            f.core.execute_broker_bound(self.ledger, *inputs)
        self.assertEqual(f.adapter.observed_version(), "1.5.6")
        self.assertEqual(set(f.state().values()), {"1.5.6"})
        self.assertFalse(f.core.journal.exists())
        self.assertIsNone(self.ledger.inspect_fixture()["active_phase"])
        self.assertEqual(self.ledger.inspect_fixture()["used_ids"], 1)
        self.assertEqual(owner.read_bytes(), b"OWNED-DATA-MUST-SURVIVE")
        with self.assertRaisesRegex(EngineError, "REQUEST_ID_ALREADY_USED"):
            f.core.execute_broker_bound(self.ledger, *inputs)

    def test_valid_completion_receipt_blocks_automatic_restore_on_ambiguous_exception(self):
        f = self.fixture
        inputs = f.broker_bound_install_inputs()
        f.adapter.complete_on_apply = True
        f.adapter.fail_after_apply = True
        with self.assertRaisesRegex(EngineError, "SYNTHETIC_NATIVE_POSTINSTALL_ERROR"):
            f.core.execute_broker_bound(self.ledger, *inputs)
        self.assertEqual(f.adapter.observed_version(), "1.5.7")
        self.assertEqual(f.core._load()["phase"], "activated")
        self.assertTrue(f.core.journal.exists())
        self.assertEqual(self.ledger.inspect_fixture()["active_phase"], "applying")

    def test_stale_completion_receipt_refuses_auto_restore_and_preserves_evidence(self):
        f = self.fixture
        inputs = f.broker_bound_install_inputs()
        f.adapter.fail_after_apply = True
        wrong = json.dumps({"schema": 1, "status": "completed",
                            "intent_sha256": "0" * 64}).encode()
        with patch.object(f.adapter, "completed", return_value=wrong):
            with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_INTENT_MISMATCH"):
                f.core.execute_broker_bound(self.ledger, *inputs)
        self.assertTrue(f.core.journal.exists())
        self.assertEqual(f.core._load()["phase"], "activated")
        self.assertEqual(self.ledger.inspect_fixture()["active_phase"], "applying")
        self.assertEqual(f.adapter.observed_version(), "1.5.7")

    def test_failed_restoration_keeps_broker_and_journal_for_recovery(self):
        f = self.fixture
        inputs = f.broker_bound_install_inputs()
        f.adapter.complete_on_apply = False
        f.adapter.fail_after_apply = True
        with patch.object(f.adapter, "restore",
                          side_effect=EngineError("DISPOSABLE_RESTORE_FAILURE")):
            with self.assertRaisesRegex(EngineError, "UNIVERSAL_BROKER_AUTO_ROLLBACK_UNRESOLVED"):
                f.core.execute_broker_bound(self.ledger, *inputs)
        self.assertEqual(self.ledger.inspect_fixture()["active_phase"], "applying")
        self.assertTrue(f.core.journal.exists())
        self.assertEqual(f.core._load()["phase"], "restoring-code")
        f.adapter.fail_after_apply = False
        f.new_engine().recover_broker_bound(self.ledger, *inputs[:4])
        self.assertFalse(f.core.journal.exists())
        self.assertIsNone(self.ledger.inspect_fixture()["active_phase"])
        self.assertEqual(set(f.state().values()), {None})

    def test_initial_install_without_completion_receipt_auto_restores_empty(self):
        f = self.fixture
        inputs = f.broker_bound_install_inputs()
        f.adapter.complete_on_apply = False
        f.adapter.fail_after_apply = True
        with self.assertRaisesRegex(EngineError, "AUTO_ABORTED_FIXTURE_ONLY"):
            f.core.execute_broker_bound(self.ledger, *inputs)
        self.assertIsNone(f.adapter.observed_version())
        self.assertEqual(set(f.state().values()), {None})
        self.assertFalse(f.core.journal.exists())


if __name__ == "__main__":
    unittest.main()
