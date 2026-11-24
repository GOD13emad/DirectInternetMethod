"""One OS-neutral install/upgrade/rollback protocol tested on Windows and Linux.

Native registration here is a deliberately disposable JSON fixture, NEVER
actual SCM/Inno, root/systemd or user-owned installed product registration.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
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


    def expected_intent(self, operation, old, new, pins):
        return {"schema": 1, "request_id": "a" * 32,
                "platform": self.platform, "operation": operation,
                "old": old, "new": new,
                "preimage_sha256": hashlib.sha256(self.adapter.snapshot()).hexdigest(),
                "scope_pins": [{"name": name, "manifest_sha256": pins[name]}
                               for name in sorted(pins)]}

    def test_broker_reserved_intent_exact_install_upgrade_and_uninstall(self):
        for old, new in ((None, "1.5.6"), ("1.5.6", "1.5.7")):
            sources = self.sources(new)
            intent = self.expected_intent("install" if old is None else "upgrade",
                                          old, new, {n: p[1] for n, p in sources.items()})
            self.core.begin(sources, expected_intent=intent)
            self.assertEqual(self.core._intent(self.core._load()), intent)
            self.core.activate()
            self.assertTrue(self.core._native_complete(self.core._load()))
            self.core.commit()
        pins = {n: self.core.code._snapshot(n)["pin"] for n in self.roots}
        intent = self.expected_intent("uninstall", "1.5.7", None, pins)
        self.core.begin_uninstall(expected_intent=intent)
        self.assertEqual(self.core._intent(self.core._load()), intent)
        self.core.apply_uninstall()
        self.core.finish_uninstall()
        self.assertEqual(set(self.state().values()), {None})


    def broker_bound_install_inputs(self):
        from installer_engine.native_plan import NativePlan
        sources = self.sources("1.5.7")
        manifests = []
        for name, (root, _) in sources.items():
            path = root / "manifest.json"
            manifest = json.loads(path.read_bytes())
            raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
            path.write_bytes(raw)
            sources[name] = root, hashlib.sha256(raw).hexdigest()
            manifests.append((name, manifest))
        plan = NativePlan("Direct Internet Method", "1.5.7", self.platform,
                          "PINNED_CODE_LAYOUT_REQUIRES_TRUSTED_NATIVE_ADAPTER",
                          tuple(sorted(manifests)))
        intent = self.expected_intent("install", None, "1.5.7",
                                      {n: p[1] for n, p in sources.items()})
        request = {"schema": 1, "product": plan.product, "platform": plan.platform,
                   "version": plan.version, "operation": "install",
                   "request_id": intent["request_id"], "scopes": intent["scope_pins"]}
        rb = json.dumps(request, sort_keys=True).encode()
        policy = {k: request[k] for k in ("schema", "product", "platform", "version", "operation")}
        policy["request_sha256"] = hashlib.sha256(rb).hexdigest()
        policy["scopes"] = [dict(row, role=row["name"]) for row in request["scopes"]]
        pb = json.dumps(policy, sort_keys=True).encode()
        policy_pin = hashlib.sha256(pb).hexdigest()
        return plan, pb, policy_pin, rb, intent, sources

    def test_policy_bound_request_survives_real_coordinator_journal(self):
        from installer_engine.broker_intent import compare_native_transaction_policy_intent
        plan, pb, policy_pin, rb, intent, sources = self.broker_bound_install_inputs()
        preflight = compare_native_transaction_policy_intent(plan, pb, policy_pin, rb, intent)
        self.core.begin(sources, expected_intent=intent)
        reopened = self.new_engine()
        recorded = reopened._intent(reopened._load())
        postflight = compare_native_transaction_policy_intent(plan, pb, policy_pin, rb, recorded)
        self.assertEqual(preflight["native_intent_sha256"], postflight["native_intent_sha256"])
        self.assertFalse(postflight["native_installation_accepted"])
        self.assertFalse(postflight["publisher_authenticated"])
        reopened.activate()
        reopened.commit()

    def test_windows_native_id64_enters_single_broker_journal_and_tombstones(self):
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        from installer_engine.native_receipt import correlate_windows_inno_ssdone
        # The ONE replay/journal identity must accept full native ID64 on
        # BOTH platforms; only Inno receipt syntax is Windows-specific.
        plan, pb, pin, rb, intent, sources = self.broker_bound_install_inputs()
        intent = dict(intent, request_id="fe12" * 16)
        request = json.loads(rb)
        request["request_id"] = intent["request_id"]
        rb = json.dumps(request, sort_keys=True).encode()
        policy = json.loads(pb)
        policy["request_sha256"] = hashlib.sha256(rb).hexdigest()
        pb = json.dumps(policy, sort_keys=True).encode()
        pin = hashlib.sha256(pb).hexdigest()
        if self.platform == "windows-x86_64":
            native_receipt = ("DIM-INNO-V1|" + intent["request_id"].upper() +
                              "|" + ("a" * 64).upper()).encode()
            observed = correlate_windows_inno_ssdone(
                intent, "a" * 64, native_receipt)
            self.assertFalse(observed["native_installation_accepted"])
        ledger = BrokerReplayFixtureLedger(self.base / "native-id64", self.platform)
        result = self.core.execute_broker_bound(
            ledger, plan, pb, pin, rb, intent, sources)
        self.assertEqual(result["version"], "1.5.7")
        self.assertIsNone(ledger.inspect_fixture()["active_phase"])
        self.assertEqual(ledger.inspect_fixture()["used_ids"], 1)
        self.assertEqual(set(self.state().values()), {"1.5.7"})
        with self.assertRaisesRegex(EngineError, "REQUEST_ID_ALREADY_USED"):
            self.core.execute_broker_bound(ledger, plan, pb, pin, rb, intent, sources)

    def test_broker_bound_dispatch_tombstones_and_denies_replay(self):
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        ledger = BrokerReplayFixtureLedger(self.base / "broker", self.platform)
        args = self.broker_bound_install_inputs()
        result = self.core.execute_broker_bound(ledger, *args)
        self.assertEqual(result["version"], "1.5.7")
        self.assertEqual(ledger.inspect_fixture()["used_ids"], 1)
        self.assertIsNone(ledger.inspect_fixture()["active_phase"])
        self.assertFalse(self.core.journal.exists())
        with self.assertRaisesRegex(EngineError, "REQUEST_ID_ALREADY_USED"):
            self.core.execute_broker_bound(ledger, *args)
        self.assertEqual(set(self.state().values()), {"1.5.7"})

    def test_broker_bound_failed_apply_recovers_exact_request_without_replay(self):
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        ledger = BrokerReplayFixtureLedger(self.base / "broker", self.platform)
        plan, pb, pin, rb, intent, sources = self.broker_bound_install_inputs()
        self.adapter.fail_after_apply = True
        with self.assertRaisesRegex(EngineError, "SYNTHETIC_NATIVE_POSTINSTALL_ERROR"):
            self.core.execute_broker_bound(ledger, plan, pb, pin, rb, intent, sources)
        self.assertEqual(ledger.inspect_fixture()["active_phase"], "applying")
        self.assertEqual(self.core._intent(self.core._load()), intent)
        again = self.new_engine()
        self.adapter.fail_after_apply = False
        with self.assertRaises(EngineError):
            again.recover_broker_bound(ledger, plan, pb, pin, rb + b" ")
        self.assertTrue(again.journal.exists())
        self.assertEqual(ledger.inspect_fixture()["active_phase"], "applying")
        result = again.recover_broker_bound(ledger, plan, pb, pin, rb)
        self.assertIsNone(result["version"])
        self.assertIsNone(ledger.inspect_fixture()["active_phase"])
        self.assertEqual(set(self.state().values()), {None})
        with self.assertRaisesRegex(EngineError, "REQUEST_ID_ALREADY_USED"):
            again.execute_broker_bound(ledger, plan, pb, pin, rb, intent, sources)

    def test_broker_bound_interrupted_commit_replays_forward(self):
        from unittest.mock import patch
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        ledger = BrokerReplayFixtureLedger(self.base / "broker", self.platform)
        plan, pb, pin, rb, intent, sources = self.broker_bound_install_inputs()
        commit = self.core._commit_locked
        with patch.object(self.core, "_commit_locked",
                          side_effect=lambda **kw: commit(fault_after="protected", **kw)):
            with self.assertRaisesRegex(EngineError, "INJECTED_AFTER_FINALIZE"):
                self.core.execute_broker_bound(ledger, plan, pb, pin, rb, intent, sources)
        self.assertEqual(self.core._load()["phase"], "finalizing")
        self.assertEqual(ledger.inspect_fixture()["active_phase"], "applying")
        result = self.new_engine().recover_broker_bound(ledger, plan, pb, pin, rb)
        self.assertEqual(result["version"], "1.5.7")
        self.assertIsNone(ledger.inspect_fixture()["active_phase"])
        self.assertEqual(set(self.state().values()), {"1.5.7"})

    def test_broker_terminal_recovery_across_both_retirement_boundaries(self):
        from unittest.mock import patch
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        for boundary in ("before-terminal", "before-remove", "before-close"):
            with self.subTest(boundary=boundary):
                # Independent disposable coordinator for each interruption.
                if boundary != "before-terminal":
                    self.core.begin_uninstall()
                    self.core.apply_uninstall()
                    self.core.finish_uninstall()
                ledger = BrokerReplayFixtureLedger(self.base / ("broker-" + boundary), self.platform)
                if boundary == "before-terminal":
                    inputs = self.broker_bound_install_inputs()
                plan, pb, pin, rb, intent, sources = inputs
                target, method = {
                    "before-terminal": (ledger, "mark_terminal_fixture"),
                    "before-remove": (self.core, "_remove"),
                    "before-close": (ledger, "close_fixture"),
                }[boundary]
                with patch.object(target, method, side_effect=EngineError("CUT")):
                    with self.assertRaisesRegex(EngineError, "CUT"):
                        self.core.execute_broker_bound(ledger, plan, pb, pin, rb, intent, sources)
                self.assertFalse(self.core.code.path.exists())
                self.assertEqual(ledger.inspect_fixture()["active_phase"],
                                 "applying" if boundary == "before-terminal" else "completed_synthetic")
                self.assertEqual(self.core.journal.exists(), boundary != "before-close")
                result = self.new_engine().recover_broker_bound(ledger, plan, pb, pin, rb)
                self.assertIsNone(ledger.inspect_fixture()["active_phase"])
                self.assertFalse(self.core.journal.exists())
                self.assertEqual(set(self.state().values()), {"1.5.7"})
                self.assertEqual(self.adapter.observed_version(), "1.5.7")

    def test_broker_real_child_exit_after_stage_before_apply(self):
        from unittest.mock import patch
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        plan, pb, pin, rb, intent, sources = self.broker_bound_install_inputs()
        before = self.adapter.snapshot()
        inputs = {
            "platform": self.platform, "product": plan.product,
            "version": plan.version, "scopes": list(plan.scopes),
            "pb": pb.hex(), "pin": pin, "rb": rb.hex(),
            "intent": intent,
            "sources": {name: [str(folder), digest]
                        for name, (folder, digest) in sources.items()},
        }
        path = self.base / "r970-subprocess-inputs.json"
        path.write_text(json.dumps(inputs), encoding="utf-8")
        child = r"""
import json, os, sys
from pathlib import Path
from installer_engine.broker_replay import BrokerReplayFixtureLedger
from installer_engine.native_plan import NativePlan
from installer_engine.universal_install import UniversalFixtureInstaller
from tests.test_engine_universal_install import FileNativeFixture
base = Path(sys.argv[1])
c = json.loads((base / "r970-subprocess-inputs.json").read_text())
plan = NativePlan(c["product"], c["version"], c["platform"],
                  "PINNED_CODE_LAYOUT_REQUIRES_TRUSTED_NATIVE_ADAPTER",
                  tuple((name, manifest) for name, manifest in c["scopes"]))
adapter = FileNativeFixture(base)
core = UniversalFixtureInstaller(base / "managed-journal", c["platform"],
    {"protected": base / "managed-protected", "user": base / "managed-user"},
    adapter)
ledger = BrokerReplayFixtureLedger(base / "broker-hard", c["platform"])
ledger.mark_applying_fixture = lambda *a, **kw: os._exit(78)
core.execute_broker_bound(
    ledger, plan, bytes.fromhex(c["pb"]), c["pin"],
    bytes.fromhex(c["rb"]), c["intent"],
    {key: (Path(folder), digest) for key, (folder, digest) in c["sources"].items()})
raise RuntimeError("CHILD_DID_NOT_HARD_EXIT")
"""
        root = Path(__file__).resolve().parents[1]
        run = subprocess.run(
            [sys.executable, "-c", child, str(self.base)],
            cwd=str(root), timeout=15, capture_output=True, text=True,
            env=dict(os.environ, PYTHONPATH=str(root),
                     PYTHONDONTWRITEBYTECODE="1"))
        self.assertEqual(run.returncode, 78, run.stderr)
        ledger = BrokerReplayFixtureLedger(self.base / "broker-hard", self.platform)
        self.assertEqual(ledger.inspect_fixture()["active_phase"], "staging")
        self.assertEqual(self.core._load()["phase"], "staged")
        self.assertEqual(self.adapter.snapshot(), before)
        with patch.object(self.adapter, "quiesce",
                          side_effect=AssertionError("NATIVE_QUIESCE_FORBIDDEN")), \
             patch.object(self.adapter, "restore",
                          side_effect=AssertionError("NATIVE_RESTORE_FORBIDDEN")):
            report = self.new_engine().recover_broker_bound(ledger, plan, pb, pin, rb)
        self.assertEqual(report["status"],
                         "UNIVERSAL_BROKER_RESERVED_STAGE_ABORTED_FIXTURE_ONLY")
        self.assertFalse(self.core.journal.exists())
        self.assertEqual(ledger.inspect_fixture()["used_ids"], 1)
        self.assertIsNone(ledger.inspect_fixture()["active_phase"])
        self.assertEqual(set(self.state().values()), {None})
        self.assertEqual(self.adapter.snapshot(), before)

    def test_broker_reserved_rejects_nonstaging_inner_journal(self):
        from unittest.mock import patch
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        ledger = BrokerReplayFixtureLedger(self.base / "broker-invalid-inner", self.platform)
        plan, pb, pin, rb, intent, sources = self.broker_bound_install_inputs()
        with patch.object(ledger, "mark_applying_fixture",
                          side_effect=EngineError("CUT")):
            with self.assertRaisesRegex(EngineError, "CUT"):
                self.core.execute_broker_bound(
                    ledger, plan, pb, pin, rb, intent, sources)
        prior = self.core.code.path.read_bytes()
        mutated = json.loads(prior)
        mutated["phase"] = "activated"
        self.core.code.path.write_text(json.dumps(mutated), encoding="utf-8")
        with self.assertRaisesRegex(EngineError, "RESERVED_CODE_NOT_STAGING"):
            self.new_engine().recover_broker_bound(ledger, plan, pb, pin, rb)
        self.assertEqual(ledger.inspect_fixture()["active_phase"], "staging")
        self.assertTrue(self.core.journal.exists())
        self.core.code.path.write_bytes(prior)
        self.new_engine().recover_broker_bound(ledger, plan, pb, pin, rb)
        self.assertIsNone(ledger.inspect_fixture()["active_phase"])
    def test_broker_staging_upgrade_reverts_without_native_callback(self):
        from unittest.mock import patch
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        self.cycle("1.5.6")
        before = self.adapter.snapshot()
        plan, pb, pin, rb, intent, sources = self.broker_bound_install_inputs()
        intent = dict(intent, old="1.5.6", operation="upgrade",
                      preimage_sha256=hashlib.sha256(before).hexdigest())
        request = json.loads(rb)
        request["operation"] = "upgrade"
        rb = json.dumps(request, sort_keys=True).encode()
        policy = json.loads(pb)
        policy["operation"] = "upgrade"
        policy["request_sha256"] = hashlib.sha256(rb).hexdigest()
        pb = json.dumps(policy, sort_keys=True).encode()
        pin = hashlib.sha256(pb).hexdigest()
        ledger = BrokerReplayFixtureLedger(self.base / "broker-upgrade-stage",
                                           self.platform)
        owner_data = self.roots["user"] / "data" / "my-configuration.ini"
        owner_data.parent.mkdir(parents=True, exist_ok=True)
        owner_data.write_bytes(b"USER-OWNED-FOREVER")
        with patch.object(ledger, "mark_applying_fixture",
                          side_effect=EngineError("CUT_PRE_NATIVE_UPGRADE")):
            with self.assertRaisesRegex(EngineError, "CUT_PRE_NATIVE_UPGRADE"):
                self.core.execute_broker_bound(
                    ledger, plan, pb, pin, rb, intent, sources)
        self.assertEqual(ledger.inspect_fixture()["active_phase"], "staging")
        self.assertEqual(self.core._load()["phase"], "staged")
        with patch.object(self.adapter, "quiesce",
                          side_effect=AssertionError("NO_NATIVE_QUIESCE")), \
             patch.object(self.adapter, "restore",
                          side_effect=AssertionError("NO_NATIVE_RESTORE")), \
             patch.object(self.adapter, "resume_restored",
                          side_effect=AssertionError("NO_NATIVE_RESTART")):
            result = self.new_engine().recover_broker_bound(ledger, plan, pb, pin, rb)
        self.assertEqual(result["version"], "1.5.6")
        self.assertEqual(set(self.state().values()), {"1.5.6"})
        self.assertEqual(self.adapter.snapshot(), before)
        self.assertEqual(owner_data.read_bytes(), b"USER-OWNED-FOREVER")
        self.assertIsNone(ledger.inspect_fixture()["active_phase"])
        self.assertEqual(ledger.inspect_fixture()["used_ids"], 1)
        self.assertFalse(self.core.journal.exists())

    def test_broker_staging_without_journal_is_safe_tombstone(self):
        from unittest.mock import patch
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        ledger = BrokerReplayFixtureLedger(self.base / "broker-empty-stage", self.platform)
        plan, pb, pin, rb, intent, sources = self.broker_bound_install_inputs()
        baseline = self.adapter.snapshot()
        with patch.object(self.core, "_begin_locked",
                          side_effect=EngineError("CUT_AFTER_STAGE_MARKER")):
            with self.assertRaisesRegex(EngineError, "CUT_AFTER_STAGE_MARKER"):
                self.core.execute_broker_bound(ledger, plan, pb, pin, rb, intent, sources)
        self.assertFalse(self.core.journal.exists())
        self.assertEqual(ledger.inspect_fixture()["active_phase"], "staging")
        result = self.new_engine().recover_broker_bound(ledger, plan, pb, pin, rb)
        self.assertEqual(result["outcome"], "aborted_synthetic")
        self.assertIsNone(ledger.inspect_fixture()["active_phase"])
        self.assertEqual(ledger.inspect_fixture()["used_ids"], 1)
        self.assertEqual(set(self.state().values()), {None})
        self.assertEqual(self.adapter.snapshot(), baseline)

    def test_broker_reserved_staged_journal_crash_is_code_only_recoverable(self):
        from unittest.mock import patch
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        ledger = BrokerReplayFixtureLedger(self.base / "broker-stage", self.platform)
        plan, pb, pin, rb, intent, sources = self.broker_bound_install_inputs()
        baseline = self.adapter.snapshot()
        owner_data = self.roots["user"] / "data" / "my-settings.json"
        owner_data.parent.mkdir(parents=True)
        owner_data.write_bytes(b"OWNER-SETTINGS-UNCHANGED")
        with patch.object(ledger, "mark_applying_fixture",
                          side_effect=EngineError("CUT_AFTER_DURABLE_STAGE")):
            with self.assertRaisesRegex(EngineError, "CUT_AFTER_DURABLE_STAGE"):
                self.core.execute_broker_bound(
                    ledger, plan, pb, pin, rb, intent, sources)
        self.assertEqual(ledger.inspect_fixture()["active_phase"], "staging")
        self.assertEqual(self.core._load()["phase"], "staged")
        self.assertTrue(self.core.code.path.exists())
        self.assertEqual(self.adapter.snapshot(), baseline)
        with patch.object(self.adapter, "quiesce",
                          side_effect=AssertionError("NATIVE_QUIESCE_FORBIDDEN")), \
             patch.object(self.adapter, "restore",
                          side_effect=AssertionError("NATIVE_RESTORE_FORBIDDEN")), \
             patch.object(self.adapter, "resume_restored",
                          side_effect=AssertionError("NATIVE_RESTART_FORBIDDEN")):
            result = self.new_engine().recover_broker_bound(
                ledger, plan, pb, pin, rb)
        self.assertEqual(result["status"],
                         "UNIVERSAL_BROKER_RESERVED_STAGE_ABORTED_FIXTURE_ONLY")
        self.assertFalse(result["native_product_rollback_accepted"])
        self.assertIsNone(ledger.inspect_fixture()["active_phase"])
        self.assertEqual(ledger.inspect_fixture()["used_ids"], 1)
        self.assertFalse(self.core.journal.exists())
        self.assertFalse(self.core.code.path.exists())
        self.assertEqual(self.adapter.snapshot(), baseline)
        self.assertEqual(set(self.state().values()), {None})
        self.assertEqual(owner_data.read_bytes(), b"OWNER-SETTINGS-UNCHANGED")
        with self.assertRaisesRegex(EngineError, "REQUEST_ID_ALREADY_USED"):
            self.core.execute_broker_bound(ledger, plan, pb, pin, rb, intent, sources)

    def test_broker_reserved_partial_prepare_journal_recovers_code_only(self):
        from unittest.mock import patch
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        ledger = BrokerReplayFixtureLedger(self.base / "broker-partial", self.platform)
        plan, pb, pin, rb, intent, sources = self.broker_bound_install_inputs()
        prepare = self.core.code.prepare
        baseline = self.adapter.snapshot()
        with patch.object(self.core.code, "prepare",
                          side_effect=lambda items: prepare(
                              items, fault_after="protected")):
            with self.assertRaisesRegex(EngineError, "INJECTED_AFTER_STAGE"):
                self.core.execute_broker_bound(
                    ledger, plan, pb, pin, rb, intent, sources)
        self.assertEqual(ledger.inspect_fixture()["active_phase"], "staging")
        self.assertEqual(self.core._load()["phase"], "preparing")
        with patch.object(self.adapter, "quiesce",
                          side_effect=AssertionError("NATIVE_QUIESCE_FORBIDDEN")), \
             patch.object(self.adapter, "restore",
                          side_effect=AssertionError("NATIVE_RESTORE_FORBIDDEN")):
            result = self.new_engine().recover_broker_bound(
                ledger, plan, pb, pin, rb)
        self.assertIsNone(result["version"])
        self.assertIsNone(ledger.inspect_fixture()["active_phase"])
        self.assertFalse(self.core.journal.exists())
        self.assertFalse(self.core.code.path.exists())
        self.assertEqual(set(self.state().values()), {None})
        self.assertEqual(self.adapter.snapshot(), baseline)

    def test_broker_reserved_stage_refuses_external_native_drift(self):
        from unittest.mock import patch
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        ledger = BrokerReplayFixtureLedger(self.base / "broker-drift", self.platform)
        plan, pb, pin, rb, intent, sources = self.broker_bound_install_inputs()
        baseline = self.adapter.snapshot()
        with patch.object(ledger, "mark_applying_fixture",
                          side_effect=EngineError("CUT")):
            with self.assertRaisesRegex(EngineError, "CUT"):
                self.core.execute_broker_bound(
                    ledger, plan, pb, pin, rb, intent, sources)
        journal = self.core.journal.read_bytes()
        self.adapter.write("1.5.6")
        with self.assertRaisesRegex(EngineError, "RESERVED_NATIVE_PREIMAGE_DRIFT"):
            self.new_engine().recover_broker_bound(ledger, plan, pb, pin, rb)
        self.assertEqual(ledger.inspect_fixture()["active_phase"], "staging")
        self.assertEqual(self.core.journal.read_bytes(), journal)
        self.assertTrue(self.core.code.path.exists())
        self.adapter.path.write_bytes(baseline)
        self.new_engine().recover_broker_bound(ledger, plan, pb, pin, rb)
        self.assertIsNone(ledger.inspect_fixture()["active_phase"])

    def test_broker_reserved_before_apply_can_retire_without_native_mutation(self):
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        ledger = BrokerReplayFixtureLedger(self.base / "broker", self.platform)
        plan, pb, pin, rb, intent, sources = self.broker_bound_install_inputs()
        baseline = self.adapter.snapshot()
        with self.assertRaisesRegex(EngineError, "INJECTED_AFTER_DURABLE_RESERVE"):
            ledger.reserve(plan, pb, pin, rb, fault_after_save=True)
        self.assertEqual(ledger.inspect_fixture()["active_phase"], "reserved")
        self.assertFalse(self.core.journal.exists())
        reopened = self.new_engine()
        with self.assertRaises(EngineError):
            reopened.recover_broker_bound(ledger, plan, pb, pin, rb + b" ")
        self.assertEqual(ledger.inspect_fixture()["active_phase"], "reserved")
        result = reopened.recover_broker_bound(ledger, plan, pb, pin, rb)
        self.assertEqual(result["outcome"], "aborted_synthetic")
        self.assertFalse(result["native_product_installation_accepted"])
        self.assertIsNone(ledger.inspect_fixture()["active_phase"])
        self.assertEqual(ledger.inspect_fixture()["used_ids"], 1)
        self.assertEqual(self.adapter.snapshot(), baseline)
        self.assertEqual(set(self.state().values()), {None})
        self.assertFalse(reopened.journal.exists())
        with self.assertRaisesRegex(EngineError, "REQUEST_ID_ALREADY_USED"):
            reopened.execute_broker_bound(ledger, plan, pb, pin, rb, intent, sources)

    def test_reserved_with_existing_transaction_never_aborts_implicitly(self):
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        ledger = BrokerReplayFixtureLedger(self.base / "broker", self.platform)
        plan, pb, pin, rb, intent, sources = self.broker_bound_install_inputs()
        ledger.reserve(plan, pb, pin, rb)
        self.core.begin(sources, expected_intent=intent)
        journal = self.core.journal.read_bytes()
        baseline = self.adapter.snapshot()
        with self.assertRaisesRegex(EngineError, "BROKER_RECOVERY_PHASE_DRIFT"):
            self.new_engine().recover_broker_bound(ledger, plan, pb, pin, rb)
        self.assertEqual(ledger.inspect_fixture()["active_phase"], "reserved")
        self.assertEqual(self.core.journal.read_bytes(), journal)
        self.assertEqual(self.adapter.snapshot(), baseline)
        self.core.abort()

    def test_broker_drift_preflight_tombstones_without_ambiguity(self):
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        ledger = BrokerReplayFixtureLedger(self.base / "broker", self.platform)
        plan, pb, pin, rb, intent, sources = self.broker_bound_install_inputs()
        baseline = self.adapter.snapshot()
        intent["preimage_sha256"] = "0" * 64
        with self.assertRaisesRegex(EngineError, "UNIVERSAL_BROKER_PREIMAGE_DRIFT"):
            self.core.execute_broker_bound(ledger, plan, pb, pin, rb, intent, sources)
        self.assertFalse(self.core.journal.exists())
        self.assertIsNone(ledger.inspect_fixture()["active_phase"])
        self.assertEqual(self.adapter.snapshot(), baseline)
        self.assertEqual(ledger.inspect_fixture()["used_ids"], 1)
        self.assertEqual(set(self.state().values()), {None})
        with self.assertRaisesRegex(EngineError, "REQUEST_ID_ALREADY_USED"):
            self.core.execute_broker_bound(ledger, plan, pb, pin, rb, intent, sources)

    def test_broker_source_digest_preflight_keeps_native_untouched(self):
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        ledger = BrokerReplayFixtureLedger(self.base / "broker", self.platform)
        plan, pb, pin, rb, intent, sources = self.broker_bound_install_inputs()
        bad_sources = dict(sources)
        scope = next(iter(bad_sources))
        bad_sources[scope] = bad_sources[scope][0], "0" * 64
        baseline = self.adapter.snapshot()
        with self.assertRaises(EngineError):
            self.core.execute_broker_bound(
                ledger, plan, pb, pin, rb, intent, bad_sources)
        self.assertIsNone(ledger.inspect_fixture()["active_phase"])
        self.assertFalse(self.core.journal.exists())
        self.assertEqual(self.adapter.snapshot(), baseline)
        self.assertEqual(ledger.inspect_fixture()["used_ids"], 1)
        self.assertEqual(set(self.state().values()), {None})

    def test_broker_uninstall_preflight_and_native_lifecycle(self):
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        from installer_engine.native_plan import NativePlan
        source = self.sources("1.5.6")
        for name, (folder, _) in source.items():
            path = folder / "manifest.json"
            manifest = json.loads(path.read_bytes())
            canonical = (json.dumps(manifest, sort_keys=True,
                                    separators=(",", ":")) + "\n").encode()
            path.write_bytes(canonical)
            source[name] = (folder, hashlib.sha256(canonical).hexdigest())
        self.core.begin(source)
        self.core.activate()
        self.core.commit()
        original = self.adapter.snapshot()
        manifests = tuple(sorted(
            (name, json.loads((folder / "manifest.json").read_bytes()))
            for name, (folder, _) in source.items()))
        plan = NativePlan("Direct Internet Method", "1.5.6", self.platform,
                          "PINNED_CODE_LAYOUT_REQUIRES_TRUSTED_NATIVE_ADAPTER",
                          manifests)
        pins = {name: self.core.code._snapshot(name)["pin"]
                for name in self.core.code.names}
        intent = self.expected_intent("uninstall", "1.5.6", None, pins)
        request = {"schema": 1, "product": plan.product, "platform": plan.platform,
                   "version": plan.version, "operation": "uninstall",
                   "request_id": intent["request_id"],
                   "scopes": intent["scope_pins"]}
        rb = json.dumps(request, sort_keys=True).encode()
        policy = {key: request[key] for key in (
            "schema", "product", "platform", "version", "operation")}
        policy["request_sha256"] = hashlib.sha256(rb).hexdigest()
        policy["scopes"] = [dict(row, role=row["name"])
                            for row in request["scopes"]]
        pb = json.dumps(policy, sort_keys=True).encode()
        pin = hashlib.sha256(pb).hexdigest()
        ledger = BrokerReplayFixtureLedger(self.base / "bad-uninstall", self.platform)
        bad_intent = dict(intent, preimage_sha256="0" * 64)
        with self.assertRaisesRegex(EngineError, "UNIVERSAL_BROKER_PREIMAGE_DRIFT"):
            self.core.execute_broker_bound(
                ledger, plan, pb, pin, rb, bad_intent)
        self.assertIsNone(ledger.inspect_fixture()["active_phase"])
        self.assertEqual(self.adapter.snapshot(), original)
        self.assertFalse(self.core.journal.exists())
        self.assertEqual(ledger.inspect_fixture()["used_ids"], 1)
        self.assertEqual(set(self.state().values()), {"1.5.6"})
        valid_ledger = BrokerReplayFixtureLedger(
            self.base / "valid-uninstall", self.platform)
        self.core.execute_broker_bound(valid_ledger, plan, pb, pin, rb, intent)
        self.assertIsNone(valid_ledger.inspect_fixture()["active_phase"])
        self.assertIsNone(self.adapter.observed_version())
        self.assertEqual(set(self.state().values()), {None})

    def test_broker_bound_missing_journal_keeps_ambiguous_reservation(self):
        from installer_engine.broker_replay import BrokerReplayFixtureLedger
        from installer_engine.engine import hash_bytes
        ledger = BrokerReplayFixtureLedger(self.base / "broker", self.platform)
        plan, pb, pin, rb, intent, sources = self.broker_bound_install_inputs()
        ledger.reserve(plan, pb, pin, rb)
        # Simulate real process death after durable applying, before begin.
        # Without a journal this is UNKNOWN, not an abort or a second apply.
        ledger.mark_applying_fixture(intent["request_id"], hash_bytes(rb), pin)
        self.assertFalse(self.core.journal.exists())
        self.assertEqual(ledger.inspect_fixture()["active_phase"], "applying")
        with self.assertRaisesRegex(EngineError, "NO_JOURNAL_RECONCILE"):
            self.core.recover_broker_bound(ledger, plan, pb, pin, rb)
        self.assertEqual(ledger.inspect_fixture()["active_phase"], "applying")
        self.assertEqual(set(self.state().values()), {None})

    def test_intent_drift_rejected_before_journal_and_native_mutation(self):
        import copy
        self.cycle("1.5.6")
        sources = self.sources("1.5.7")
        before = self.adapter.snapshot()
        valid = self.expected_intent("upgrade", "1.5.6", "1.5.7",
                                     {n: p[1] for n, p in sources.items()})
        variants = [
            {"preimage_sha256": "0" * 64},
            {"old": "1.5.5"},
            {"new": "1.5.8"},
            {"platform": "linux-x86_64" if self.platform == "windows-x86_64" else "windows-x86_64"},
            {"operation": "install", "old": None},
            {"scope_pins": [dict(valid["scope_pins"][0], manifest_sha256="0" * 64),
                            valid["scope_pins"][1]]},
        ]
        for changes in variants:
            with self.subTest(changes=changes):
                invalid = copy.deepcopy(valid)
                invalid.update(changes)
                with self.assertRaisesRegex(EngineError, "UNIVERSAL_EXPECTED_INTENT_DRIFT"):
                    self.core.begin(sources, expected_intent=invalid)
                self.assertFalse(self.core.journal.exists())
                self.assertFalse(self.core.code.path.exists())
                self.assertEqual(self.adapter.snapshot(), before)
                self.assertEqual(set(self.state().values()), {"1.5.6"})
        pins = {n: self.core.code._snapshot(n)["pin"] for n in self.roots}
        invalid = self.expected_intent("uninstall", "1.5.6", None, pins)
        invalid["preimage_sha256"] = "0" * 64
        with self.assertRaisesRegex(EngineError, "UNIVERSAL_EXPECTED_INTENT_DRIFT"):
            self.core.begin_uninstall(expected_intent=invalid)
        self.assertFalse(self.core.journal.exists())
        self.assertFalse(self.core.uninstall.uninstall_path.exists())
        self.assertEqual(self.adapter.snapshot(), before)
        self.assertEqual(set(self.state().values()), {"1.5.6"})

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
