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


class FileNativeFixture:
    """Disposable fake native state, intentionally independent of code slots."""

    def __init__(self, root: Path):
        self.path = root / "mock-native-registration.json"
        self.receipt = root / "mock-native-completion.json"
        self.write(None)
        self.complete_on_apply = True
        self.fail_after_apply = False

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

    def apply(self, target_version: str) -> None:
        self.write(target_version)
        if self.complete_on_apply:
            self.receipt.write_text(
                json.dumps({"target": target_version}), encoding="utf8")
        if self.fail_after_apply:
            raise EngineError("SYNTHETIC_NATIVE_POSTINSTALL_ERROR")

    def completed(self, target_version: str) -> bool:
        if not self.receipt.exists():
            return False
        try:
            return json.loads(self.receipt.read_text("utf8")) == {
                "target": target_version}
        except ValueError:
            return False

    def restore(self, snapshot: bytes) -> None:
        doc = json.loads(snapshot.decode("utf8"))
        if type(doc) is not dict or set(doc) != {"schema", "version"}:
            raise EngineError("SYNTHETIC_NATIVE_PREIMAGE_INVALID")
        self.path.write_bytes(snapshot)
        self.receipt.unlink(missing_ok=True)

    def unregister(self) -> None:
        self.write(None)
        if self.complete_on_apply:
            self.receipt.write_text('{"uninstall": true}', encoding="utf8")
        if self.fail_after_apply:
            raise EngineError("SYNTHETIC_NATIVE_UNINSTALL_ERROR")

    def uninstall_completed(self) -> bool:
        return (self.receipt.exists() and
                self.receipt.read_text("utf8") == '{"uninstall": true}')

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

if __name__ == "__main__":
    unittest.main()
