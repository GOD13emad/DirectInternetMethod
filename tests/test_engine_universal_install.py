"""One OS-neutral install/upgrade/rollback protocol tested on Windows and Linux.

Native registration here is a deliberately disposable JSON fixture, NEVER
actual SCM/Inno, root/systemd or user-owned installed product registration.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from installer_engine.engine import Engine, EngineError
from installer_engine.universal_install import UniversalFixtureInstaller
from installer_engine.native_receipt import intent_sha256


class FileNativeFixture:
    """Disposable fake native state, intentionally independent of code slots."""

    def __init__(self, root: Path):
        self.path = root / "mock-native-registration.json"
        self.receipt = root / "mock-native-completion.json"
        self.write(None)
        self.complete_on_apply = True
        self.fail_after_apply = False
        self.restored_receipt = None
        self.fail_after_resume = False
        self.complete_on_resume = True
        self.resume_count = 0
        self.check_code_restored = None

    def write(self, version: str | None):
        self.path.write_text(
            json.dumps({"schema": 1, "version": version}, sort_keys=True),
            encoding="utf-8",
        )

    def snapshot(self) -> bytes:
        return self.path.read_bytes()

    def observed_version(self) -> str | None:
        return json.loads(self.path.read_text(encoding="utf-8"))["version"]

    def quiesced(self) -> bool:
        return True

    def quiesce(self) -> None:
        return None

    @staticmethod
    def _fixture_receipt(intent: dict, status: str = "completed") -> bytes:
        return json.dumps({"schema": 1, "status": status,
                           "intent_sha256": intent_sha256(intent)},
                          sort_keys=True).encode("utf8")

    def apply(self, target_version: str, intent: dict) -> None:
        self.write(target_version)
        self.receipt.unlink(missing_ok=True)
        if self.complete_on_apply:
            self.receipt.write_bytes(self._fixture_receipt(intent))
        if self.fail_after_apply:
            raise EngineError("SYNTHETIC_NATIVE_POSTINSTALL_ERROR")

    def completed(self, intent: dict) -> bytes | None:
        return self.receipt.read_bytes() if self.receipt.exists() else None

    def restore(self, snapshot: bytes, intent: dict) -> None:
        doc = json.loads(snapshot.decode("utf8"))
        if type(doc) is not dict or set(doc) != {"schema", "version"}:
            raise EngineError("SYNTHETIC_NATIVE_PREIMAGE_INVALID")
        self.path.write_bytes(snapshot)
        self.receipt.unlink(missing_ok=True)
        self.restored_receipt = None

    def unregister(self, intent: dict) -> None:
        self.write(None)
        self.receipt.unlink(missing_ok=True)
        if self.complete_on_apply:
            self.receipt.write_bytes(self._fixture_receipt(intent))
        if self.fail_after_apply:
            raise EngineError("SYNTHETIC_NATIVE_UNINSTALL_ERROR")

    def uninstall_completed(self, intent: dict) -> bytes | None:
        return self.receipt.read_bytes() if self.receipt.exists() else None

    def resume_restored(self, old_version: str | None, intent: dict) -> None:
        if self.observed_version() != old_version:
            raise EngineError("FIXTURE_RESTORE_VERSION_MISMATCH")
        if self.check_code_restored is not None and not self.check_code_restored(old_version):
            raise EngineError("FIXTURE_OLD_CODE_NOT_READY_FOR_NATIVE_START")
        self.resume_count += 1
        if self.complete_on_resume:
            self.restored_receipt = self._fixture_receipt(intent, "restored")
        if self.fail_after_resume:
            raise EngineError("SYNTHETIC_CRASH_AFTER_NATIVE_RESUME")

    def restored(self, intent: dict) -> bytes | None:
        return self.restored_receipt

class UniversalInstallCrossPlatform(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dim-universal-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.platform = ("windows-x86_64" if os.name == "nt"
                         else "linux-x86_64")
        self.roots = {
            "protected": self.base / "managed-protected",
            "user": self.base / "managed-user",
        }
        self.control = self.base / "managed-journal"
        self.adapter = FileNativeFixture(self.base)
        self.core = self.new_engine()
        self.adapter.check_code_restored = lambda old: set(self.state().values()) == {old}

    def new_engine(self):
        return UniversalFixtureInstaller(self.control, self.platform,
                                         self.roots, self.adapter)

    def package(self, scope, v):
        root = self.base / f"bundle-{scope}-{v}"
        file = root / "payload/app/code.fixture"
        file.parent.mkdir(parents=True, exist_ok=True)
        data = f"{scope}-v{v}-SYNTHETIC-DIM".encode("ascii")
        file.write_bytes(data)
        manifest = {
            "schema": 1, "platform": self.platform,
            "product": "Direct Internet Method", "version": v,
            "files": [{"path": "app/code.fixture", "bytes": len(data),
                       "sha256": hashlib.sha256(data).hexdigest(),
                       "mode": 0o644}]
        }
        m = root / "manifest.json"
        m.write_text(json.dumps(manifest, sort_keys=True) + "\n", "utf-8")
        return root, hashlib.sha256(m.read_bytes()).hexdigest()

    def sources(self, v):
        return {scope: self.package(scope, v) for scope in self.roots}

    def cycle(self, v):
        self.core.begin(self.sources(v))
        self.core.activate()
        return self.core.commit()

    def state(self):
        return {
            name: Engine(p, self.platform).verify().get("version")
            for name, p in self.roots.items()
        }

    def test_single_contract_fresh_install_and_upgrade_preserves_owner_data(self):
        self.assertEqual(self.cycle("1.5.6")["status"],
                         "UNIVERSAL_TWO_SCOPE_COMMIT_FIXTURE_ONLY")
        owner = self.roots["user"] / "data" / "settings.json"
        owner.parent.mkdir(parents=True)
        owner.write_bytes(b"USER_DATA_UNTOUCHED")
        self.assertEqual(self.cycle("1.5.7")["version"], "1.5.7")
        self.assertEqual(set(self.state().values()), {"1.5.7"})
        self.assertEqual(self.adapter.observed_version(), "1.5.7")
        self.assertEqual(owner.read_bytes(), b"USER_DATA_UNTOUCHED")
        self.assertFalse(self.core.journal.exists())
        self.assertFalse(self.core.code.path.exists())

    def test_native_failure_with_new_registration_must_rollback_not_commit(self):
        self.cycle("1.5.6")
        old_bytes = self.adapter.snapshot()
        self.adapter.complete_on_apply = False
        self.core.begin(self.sources("1.5.7"))
        self.core.activate()
        self.assertEqual(self.adapter.observed_version(), "1.5.7")
        with self.assertRaisesRegex(EngineError, "COMPLETION_RECEIPT_MISSING"):
            self.core.commit()
        result = self.new_engine().recover()
        self.assertEqual(result["version"], "1.5.6")
        self.assertEqual(self.adapter.snapshot(), old_bytes)
        self.assertEqual(set(self.state().values()), {"1.5.6"})

    def test_crash_after_partial_native_apply_restores_previous_version(self):
        self.cycle("1.5.6")
        self.adapter.fail_after_apply = True
        self.core.begin(self.sources("1.5.7"))
        with self.assertRaisesRegex(EngineError, "POSTINSTALL_ERROR"):
            self.core.activate()
        # New process: durable ledger plus existing code two-scope journal.
        self.adapter.fail_after_apply = False
        again = self.new_engine()
        self.assertEqual(again.recover()["version"], "1.5.6")
        self.assertEqual(self.adapter.observed_version(), "1.5.6")
        self.assertEqual(set(self.state().values()), {"1.5.6"})

    def test_prepared_without_native_apply_crash_recovers_empty_install(self):
        self.core.begin(self.sources("1.5.6"))
        other = self.new_engine()
        self.assertEqual(other.recover()["version"], None)
        self.assertEqual(set(self.state().values()), {None})
        self.assertFalse(other.journal.exists())

    def test_native_not_quiesced_rejects_activation(self):
        self.core.begin(self.sources("1.5.6"))
        self.adapter.quiesced = lambda: False
        with self.assertRaisesRegex(EngineError, "NOT_QUIESCED"):
            self.core.activate()
        self.adapter.quiesced = lambda: True
        self.core.abort()
        self.assertEqual(set(self.state().values()), {None})

    def test_nonmonotonic_upgrade_fails_before_any_transaction(self):
        self.cycle("1.5.7")
        with self.assertRaisesRegex(EngineError, "NOT_NEWER"):
            self.core.begin(self.sources("1.5.6"))
        self.assertFalse(self.core.journal.exists())
        self.assertEqual(set(self.state().values()), {"1.5.7"})

    def test_preimage_hash_tamper_fails_closed_without_deleting_slots(self):
        self.core.begin(self.sources("1.5.6"))
        doc = json.loads(self.core.journal.read_text("utf8"))
        doc["preimage_sha256"] = "0" * 64
        self.core.journal.write_text(json.dumps(doc), encoding="utf8")
        with self.assertRaisesRegex(EngineError, "PREIMAGE_SHA_INVALID"):
            self.new_engine().recover()
        self.assertTrue(self.core.code.path.exists())

    def test_version_split_prevents_mutation(self):
        s = {"protected": self.package("protected", "1.5.6"),
             "user": self.package("user", "1.5.7")}
        with self.assertRaisesRegex(EngineError, "PACKAGE_VERSION_SPLIT"):
            self.core.begin(s)
        self.assertFalse(self.core.journal.exists())
        self.assertEqual(set(self.state().values()), {None})

    def test_production_service_not_created_or_authorized(self):
        from installer_engine import universal_install as mod
        source = Path(mod.__file__).read_text("utf8")
        self.assertNotIn("subprocess", source)
        self.assertNotIn("Start-Process", source)
        self.assertNotIn("systemctl ", source)
        self.assertNotIn("sc.exe", source)
        self.assertIn('"native_product_installation_accepted": False', source)

    def test_cross_platform_uninstall_preserves_external_owner_settings(self):
        self.cycle("1.5.6")
        owner = self.roots["user"] / "data" / "settings.json"
        owner.parent.mkdir(parents=True)
        owner.write_bytes(b"OWNER_CONFIGURATION_DO_NOT_REMOVE")
        self.core.begin_uninstall()
        self.core.apply_uninstall()
        out = self.core.finish_uninstall()
        self.assertEqual(out["status"], "UNIVERSAL_UNINSTALL_COMPLETE_FIXTURE_ONLY")
        self.assertEqual(set(self.state().values()), {None})
        self.assertEqual(self.adapter.observed_version(), None)
        self.assertEqual(owner.read_bytes(), b"OWNER_CONFIGURATION_DO_NOT_REMOVE")
        self.assertFalse(self.core.journal.exists())
        self.assertFalse(self.core.uninstall.uninstall_path.exists())

    def test_uninstall_failure_without_native_completion_restores_old_install(self):
        self.cycle("1.5.6")
        self.adapter.complete_on_apply = False
        self.core.begin_uninstall()
        self.core.apply_uninstall()
        self.assertEqual(self.adapter.observed_version(), None)
        with self.assertRaisesRegex(EngineError, "UNINSTALL_RECEIPT_MISSING"):
            self.core.finish_uninstall()
        old = self.new_engine().recover()
        self.assertEqual(old["version"], "1.5.6")
        self.assertEqual(self.adapter.observed_version(), "1.5.6")
        self.assertEqual(set(self.state().values()), {"1.5.6"})

    def test_uninstall_partial_finalization_only_replays_forward(self):
        self.cycle("1.5.6")
        self.core.begin_uninstall()
        self.core.apply_uninstall()
        with self.assertRaisesRegex(EngineError, "INJECTED_AFTER_UNINSTALL_FINISH"):
            self.core.finish_uninstall(fault_after="protected")
        with self.assertRaisesRegex(EngineError, "FORWARD_REPLAY_REQUIRED"):
            self.new_engine().abort_uninstall()
        out = self.new_engine().recover()
        self.assertEqual(out["status"], "UNIVERSAL_UNINSTALL_COMPLETE_FIXTURE_ONLY")
        self.assertEqual(set(self.state().values()), {None})

    def test_upgrader_partial_finalization_only_replays_forward(self):
        self.cycle("1.5.6")
        self.core.begin(self.sources("1.5.7"))
        self.core.activate()
        with self.assertRaisesRegex(EngineError, "INJECTED_AFTER_FINALIZE"):
            self.core.commit(fault_after="protected")
        with self.assertRaisesRegex(EngineError, "FORWARD_REPLAY_REQUIRED"):
            self.new_engine().abort()
        out = self.new_engine().recover()
        self.assertEqual(out["version"], "1.5.7")
        self.assertEqual(set(self.state().values()), {"1.5.7"})

    def test_uninstall_native_error_after_unregistration_stays_recoverable(self):
        self.cycle("1.5.6")
        self.adapter.fail_after_apply = True
        self.core.begin_uninstall()
        with self.assertRaisesRegex(EngineError, "SYNTHETIC_NATIVE_UNINSTALL_ERROR"):
            self.core.apply_uninstall()
        self.adapter.fail_after_apply = False
        restored = self.new_engine().recover()
        self.assertEqual(restored["version"], "1.5.6")
        self.assertEqual(set(self.state().values()), {"1.5.6"})
    def test_second_writer_is_denied_by_one_shared_transaction_lock(self):
        sources = self.sources("1.5.6")
        with self.core.guard.locked():
            with self.assertRaisesRegex(EngineError, "TRANSACTION_LOCKED"):
                self.new_engine().begin(sources)
        self.assertFalse(self.core.journal.exists())
        self.core.begin(sources)
        self.core.abort()
        self.assertEqual(set(self.state().values()), {None})


    def test_stale_receipt_same_version_same_pins_new_request_id_denied(self):
        self.cycle("1.5.6")
        same_sources = self.sources("1.5.7")
        self.core.begin(same_sources)
        self.core.activate()
        prior = self.adapter.receipt.read_bytes()
        first_id = self.core._load()["request_id"]
        self.core.abort()
        self.adapter.complete_on_apply = False
        self.core.begin(same_sources)
        self.assertNotEqual(self.core._load()["request_id"], first_id)
        self.core.activate()
        self.adapter.receipt.write_bytes(prior)
        with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_INTENT_MISMATCH"):
            self.core.commit()
        self.assertTrue(self.core.journal.exists())
        self.core.abort()
        self.assertEqual(set(self.state().values()), {"1.5.6"})

    def test_changed_scope_manifest_pin_refuses_old_receipt(self):
        self.cycle("1.5.6")
        self.core.begin(self.sources("1.5.7"))
        self.core.activate()
        source = self.core.journal.read_bytes()
        altered = json.loads(source)
        altered["scope_pins"][0]["manifest_sha256"] = "0" * 64
        self.core.journal.write_text(json.dumps(altered), encoding="utf8")
        with self.assertRaisesRegex(EngineError, "UNIVERSAL_SCOPE_MANIFEST_PIN_DRIFT"):
            self.core.commit()
        self.assertTrue(self.core.code.path.exists())
        # Restore test-owned synthetic checkpoint before test-only rollback.
        self.core.journal.write_bytes(source)
        self.core.abort()

    def test_replayed_update_receipt_cannot_authorize_uninstall(self):
        self.cycle("1.5.6")
        upgrade_receipt = self.adapter.receipt.read_bytes()
        self.adapter.complete_on_apply = False
        self.core.begin_uninstall()
        self.core.apply_uninstall()
        self.adapter.receipt.write_bytes(upgrade_receipt)
        with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_INTENT_MISMATCH"):
            self.core.finish_uninstall()
        self.core.abort_uninstall()
        self.assertEqual(set(self.state().values()), {"1.5.6"})

    def test_duplicate_receipt_field_is_rejected_without_code_cleanup(self):
        self.core.begin(self.sources("1.5.6"))
        self.core.activate()
        self.adapter.receipt.write_bytes(
            b'{"schema":1,"schema":1,"status":"completed",'
            b'"intent_sha256":"' + b"0" * 64 + b'"}')
        with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_DUPLICATE_FIELD"):
            self.core.commit()
        self.assertTrue(self.core.code.path.exists())
        self.core.abort()

    def test_invalid_request_id_in_journal_blocks_resume(self):
        self.core.begin(self.sources("1.5.6"))
        orig = self.core.journal.read_bytes()
        doc = json.loads(orig)
        doc["request_id"] = "1" * 31 + "z"
        self.core.journal.write_text(json.dumps(doc), encoding="utf8")
        with self.assertRaisesRegex(EngineError, "NATIVE_INTENT_REQUEST_ID_INVALID"):
            self.new_engine().recover()
        self.assertTrue(self.core.code.path.exists())
        self.core.journal.write_bytes(orig)
        self.core.abort()

    def test_unrecognized_v1_fixture_journal_refused_without_mutation(self):
        self.core.begin(self.sources("1.5.6"))
        orig = self.core.journal.read_bytes()
        doc = json.loads(orig)
        doc["schema"] = 1
        self.core.journal.write_text(json.dumps(doc), encoding="utf8")
        with self.assertRaisesRegex(EngineError, "UNIVERSAL_TRANSACTION_SCHEMA_INVALID"):
            self.new_engine().recover()
        self.assertTrue(self.core.code.path.exists())
        self.core.journal.write_bytes(orig)
        self.core.abort()



    def test_upgrade_crash_after_native_restart_receipt_replays_without_restart(self):
        self.cycle("1.5.6")
        self.core.begin(self.sources("1.5.7"))
        self.core.activate()
        self.adapter.fail_after_resume = True
        with self.assertRaisesRegex(EngineError, "SYNTHETIC_CRASH_AFTER_NATIVE_RESUME"):
            self.core.abort()
        self.assertEqual(self.core._load()["phase"], "restoring-native")
        self.assertEqual(self.adapter.resume_count, 1)
        self.assertEqual(set(self.state().values()), {"1.5.6"})
        self.adapter.fail_after_resume = False
        self.assertEqual(self.new_engine().recover()["version"], "1.5.6")
        self.assertEqual(self.adapter.resume_count, 1)
        self.assertFalse(self.core.journal.exists())

    def test_uninstall_crash_after_native_restart_receipt_replays(self):
        self.cycle("1.5.6")
        self.core.begin_uninstall()
        self.core.apply_uninstall()
        self.adapter.fail_after_resume = True
        with self.assertRaisesRegex(EngineError, "SYNTHETIC_CRASH_AFTER_NATIVE_RESUME"):
            self.core.abort_uninstall()
        self.assertEqual(self.core._load()["phase"], "uninstall-restoring-native")
        self.assertEqual(set(self.state().values()), {"1.5.6"})
        self.adapter.fail_after_resume = False
        self.assertEqual(self.new_engine().recover()["version"], "1.5.6")
        self.assertEqual(self.adapter.resume_count, 1)
        self.assertFalse(self.core.journal.exists())

    def test_absent_native_restore_health_preserves_replay_journal(self):
        self.cycle("1.5.6")
        self.core.begin(self.sources("1.5.7"))
        self.core.activate()
        self.adapter.complete_on_resume = False
        with self.assertRaisesRegex(EngineError, "NATIVE_RESTORE_HEALTH_NOT_VERIFIED"):
            self.core.abort()
        self.assertEqual(self.core._load()["phase"], "restoring-native")
        self.assertEqual(set(self.state().values()), {"1.5.6"})
        self.adapter.complete_on_resume = True
        self.assertEqual(self.new_engine().recover()["version"], "1.5.6")
        self.assertEqual(self.adapter.resume_count, 2)

    def test_completed_native_receipt_cannot_replace_restoration_receipt(self):
        self.cycle("1.5.6")
        self.core.begin(self.sources("1.5.7"))
        self.core.activate()
        self.adapter.complete_on_resume = False
        with self.assertRaisesRegex(EngineError, "NATIVE_RESTORE_HEALTH_NOT_VERIFIED"):
            self.core.abort()
        doc = self.core._load()
        self.adapter.restored_receipt = self.adapter._fixture_receipt(
            self.core._intent(doc), "completed")
        with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_SCHEMA_INVALID"):
            self.new_engine().recover()
        self.assertTrue(self.core.journal.exists())
        self.adapter.restored_receipt = None
        self.adapter.complete_on_resume = True
        self.new_engine().recover()
        self.assertFalse(self.core.journal.exists())

    def test_uninstall_captures_native_running_state_before_quiesce(self):
        self.cycle("1.5.6")
        observed = []
        running = [True]
        original_snapshot = self.adapter.snapshot

        def snapshot():
            observed.append(("snapshot", running[0]))
            return original_snapshot()

        def quiesce():
            observed.append(("quiesce", running[0]))
            running[0] = False

        self.adapter.snapshot = snapshot
        self.adapter.quiesce = quiesce
        self.adapter.quiesced = lambda: not running[0]
        self.core.begin_uninstall()
        self.assertEqual(observed[:2],
                         [("snapshot", True), ("quiesce", True)])
        self.assertFalse(running[0])
        self.assertEqual(self.core._load()["phase"], "uninstall-prepared")
        self.core.abort_uninstall()
        self.assertFalse(self.core.journal.exists())

    def test_activation_stops_native_after_checkpoint_but_before_code_swap(self):
        self.cycle("1.5.6")
        events = []
        running = [True]
        original_snapshot = self.adapter.snapshot

        def snapshot():
            events.append(("snapshot", running[0]))
            return original_snapshot()

        def quiesce():
            events.append(("quiesce", running[0]))
            running[0] = False

        self.adapter.snapshot = snapshot
        self.adapter.quiesce = quiesce
        self.adapter.quiesced = lambda: not running[0]
        self.core.begin(self.sources("1.5.7"))
        self.assertEqual(events, [("snapshot", True)])
        self.core.activate()
        self.assertEqual(events, [("snapshot", True), ("quiesce", True)])
        self.core.commit()
        self.assertEqual(set(self.state().values()), {"1.5.7"})

if __name__ == "__main__":
    unittest.main()
