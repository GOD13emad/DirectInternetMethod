"""Tracked 21-file Linux product code through ONE OS-neutral transaction kernel.

This is a source-provenance integration test, NOT an authorized native install.
The synthetic baseline 1.5.6 uses copied 1.5.7 source bytes with test-only
version metadata to exercise fail-closed rollback. Only the target 1.5.7
bytes are actually sourced from this exact checkout. Native registration
and receipt are still the existing FileNativeFixture, not systemd/polkit.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from installer_engine.engine import Engine, EngineError, hash_file
from installer_engine.scoped_bundle import materialize_scope_bundle
from installer_engine.universal_install import UniversalFixtureInstaller
from tests.test_engine_universal_install import FileNativeFixture


class RealLinuxTwoScopeIntegration(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory(prefix="dim-real-linux-scopes-")
        self.addCleanup(self.t.cleanup)
        self.base = Path(self.t.name)
        self.repo = Path(__file__).resolve().parents[1]
        self.layout = json.loads(
            (self.repo / "linux" / "native_layout.json").read_text("utf-8"))
        self.assertEqual(self.layout["version"], "1.5.7")
        self.assertEqual(self.layout["platform"], "linux-x86_64")
        self.assertEqual(len(self.layout["files"]), 21)
        self.assertEqual(
            {name: sum(x["scope"] == name for x in self.layout["files"])
             for name in ("privileged", "user")},
            {"privileged": 13, "user": 8})
        self.roots = {name: self.base / ("installed-" + name)
                      for name in ("privileged", "user")}
        self.adapter = FileNativeFixture(self.base)
        self.engine = self._engine()

    def _engine(self):
        return UniversalFixtureInstaller(
            self.base / "journal", "linux-x86_64", self.roots, self.adapter)

    def _build(self, version: str) -> dict:
        """Compile pinned manifests from tracked source, without elevation."""
        src = self.base / ("real-source-" + version)
        payload = src / "payload"
        payload.mkdir(parents=True)
        records = []
        for entry in self.layout["files"]:
            original = self.repo / "linux" / entry["source"]
            self.assertTrue(original.is_file(), "MISSING_REAL_LINUX_SOURCE: " +
                            entry["source"])
            target = payload / entry["source"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, target)
            checksum = hash_file(target)
            self.assertEqual(checksum, hash_file(original))
            records.append({
                "path": entry["source"], "bytes": target.stat().st_size,
                "sha256": checksum, "mode": entry["mode"]})
        manifest = {
            "schema": 1, "product": "Direct Internet Method",
            "platform": "linux-x86_64", "version": version, "files": records}
        manifest_file = src / "manifest.json"
        manifest_file.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) +
            "\n", encoding="utf-8")
        layout = dict(self.layout)
        layout["version"] = version
        layout_path = self.base / ("layout-" + version + ".json")
        layout_path.write_text(
            json.dumps(layout, sort_keys=True, separators=(",", ":")) +
            "\n", encoding="utf-8")
        out = {}
        for scope in ("privileged", "user"):
            destination = self.base / ("bundle-" + scope + "-" + version)
            result = materialize_scope_bundle(
                src, hash_file(manifest_file), layout_path,
                hash_file(layout_path), scope, destination, "linux-x86_64")
            self.assertFalse(result["native_installation_or_rollback_accepted"])
            self.assertEqual(result["files"],
                             13 if scope == "privileged" else 8)
            out[scope] = (destination, result["manifest_sha256"])
        return out

    def _states(self):
        return {scope: Engine(path, "linux-x86_64").verify()
                for scope, path in self.roots.items()}

    def test_r947_exact_real_code_activated_postflight_blocks_tamper_and_false_owner(self):
        """21 tracked files, one live transaction, before native completion."""
        import os
        import stat
        from installer_engine.engine import PRODUCT
        from installer_engine.native_plan import NativePlan
        from installer_engine.native_readiness import two_scope_code_postflight

        actual = self._build("1.5.7")
        manifests = {
            name: json.loads((directory / "manifest.json").read_text("utf-8"))
            for name, (directory, _) in actual.items()
        }
        plan = NativePlan(
            PRODUCT, "1.5.7", "linux-x86_64",
            "PINNED_CODE_LAYOUT_REQUIRES_TRUSTED_NATIVE_ADAPTER",
            tuple((name, manifests[name]) for name in ("privileged", "user")))
        data = self.roots["user"] / "data" / "settings.json"
        data.parent.mkdir(parents=True)
        data.write_bytes(b"R947_UNOWNED_OWNER_SETTINGS_KEEP")
        self.engine.begin(actual)
        self.engine.activate()
        native = self.engine._intent(self.engine._load())
        expected_uid = ({"privileged": os.getuid(), "user": os.getuid()}
                        if os.name == "posix" else None)
        result = two_scope_code_postflight(
            plan, self.roots, native, expected_uids=expected_uid)
        self.assertEqual({row["scope"]: row["files"] for row in result["scopes"]},
                         {"privileged": 13, "user": 8})
        self.assertFalse(result["native_installation_accepted"])
        self.assertFalse(result["os_native_registration_verified"])
        self.assertEqual(data.read_bytes(), b"R947_UNOWNED_OWNER_SETTINGS_KEEP")

        code = (self.roots["privileged"] / "current" / "runtime/usr/bin/ctrld")
        saved = code.read_bytes()
        with code.open("ab") as output:
            output.write(b"R947_FORBIDDEN_AFTER_ACTIVATION")
        with self.assertRaisesRegex(EngineError, "INSTALLED_MANAGED_FILE_CHANGED"):
            two_scope_code_postflight(plan, self.roots, native,
                                      expected_uids=expected_uid)
        code.write_bytes(saved)
        if os.name == "posix":
            code.chmod(0o755)
            code.chmod(0o666)
            with self.assertRaisesRegex(EngineError, "R947_MANAGED_FILE_MODE_DRIFT"):
                two_scope_code_postflight(plan, self.roots, native,
                                          expected_uids=expected_uid)
            code.chmod(0o755)
            with self.assertRaisesRegex(EngineError, "R947_MANAGED_FILE_OWNER_DRIFT"):
                two_scope_code_postflight(plan, self.roots, native,
                    expected_uids={"privileged": os.getuid() + 1,
                                   "user": os.getuid()})

        different = json.loads(json.dumps(native))
        different["scope_pins"][0]["manifest_sha256"] = "f" * 64
        with self.assertRaisesRegex(EngineError, "R947_TRANSACTION_MANIFEST_PIN_DRIFT"):
            two_scope_code_postflight(plan, self.roots, different)
        with self.assertRaisesRegex(EngineError, "R947_ACTIVE_REGISTRATION_OR_MANIFEST_DRIFT"):
            two_scope_code_postflight(plan, {"privileged": self.roots["user"],
                                              "user": self.roots["privileged"]}, native)
        self.engine.commit()
        self.assertEqual(data.read_bytes(), b"R947_UNOWNED_OWNER_SETTINGS_KEEP")

    def test_real_privileged_binary_tamper_denied_before_any_scope_mutation(self):
        # A corrupted REAL tracked executable in the privileged bundle is
        # rejected before even the user scope is staged; no OS authorization.
        sources = self._build("1.5.7")
        protected = sources["privileged"][0]
        executable = protected / "payload" / "runtime/usr/bin/ctrld"
        self.assertTrue(executable.is_file())
        with executable.open("ab") as stream:
            stream.write(b"R941_UNTRUSTED_APPEND")
        external = self.roots["user"] / "data" / "settings.json"
        external.parent.mkdir(parents=True)
        external.write_bytes(b"LEAVE_OWNER_DATA_UNTOUCHED")
        with self.assertRaisesRegex(EngineError, "PACKAGE_FILE_SHA_MISMATCH"):
            self.engine.begin(sources)
        self.assertFalse(self.engine.journal.exists())
        self.assertEqual({s["status"] for s in self._states().values()},
                         {"EMPTY"})
        self.assertEqual(external.read_bytes(), b"LEAVE_OWNER_DATA_UNTOUCHED")

    def test_exact_21_code_files_shared_transaction_recovery_and_uninstall(self):
        # Synthetic old version: its program bytes are NOT historical 1.5.6.
        baseline = self._build("1.5.6")
        self.engine.begin(baseline)
        self.engine.activate()
        self.engine.commit()
        self.assertEqual({s["version"] for s in self._states().values()},
                         {"1.5.6"})
        external = self.roots["user"] / "data" / "settings.json"
        external.parent.mkdir(parents=True)
        external.write_bytes(b"PERSONAL_CONFIGURATION_MUST_SURVIVE")

        # Exact current 1.5.7 checkout: 13 protected + 8 owner code files.
        actual = self._build("1.5.7")
        self.adapter.complete_on_apply = False
        self.engine.begin(actual)
        self.engine.activate()
        with self.assertRaisesRegex(EngineError, "COMPLETION_RECEIPT_MISSING"):
            self.engine.commit()
        self.assertTrue(self.engine.journal.exists())
        self.engine = self._engine()  # Fresh engine object replays real journal.
        self.assertEqual(self.engine.recover()["version"], "1.5.6")
        self.assertEqual({s["version"] for s in self._states().values()},
                         {"1.5.6"})
        self.assertEqual(external.read_bytes(),
                         b"PERSONAL_CONFIGURATION_MUST_SURVIVE")

        self.adapter.complete_on_apply = True
        self.engine.begin(actual)
        self.engine.activate()
        done = self.engine.commit()
        self.assertEqual(done["version"], "1.5.7")
        self.assertFalse(done["native_product_installation_accepted"])
        states = self._states()
        self.assertEqual({name: states[name]["files"] for name in states},
                         {"privileged": 13, "user": 8})
        for row in self.layout["files"]:
            managed = (Engine(self.roots[row["scope"]], "linux-x86_64")
                       .current / row["target"])
            original = self.repo / "linux" / row["source"]
            self.assertEqual(hash_file(managed), hash_file(original),
                             "REAL_SOURCE_CODE_SHA_DRIFT: " + row["target"])
        self.assertEqual(external.read_bytes(),
                         b"PERSONAL_CONFIGURATION_MUST_SURVIVE")

        self.engine.begin_uninstall()
        self.engine.apply_uninstall()
        result = self.engine.finish_uninstall()
        self.assertFalse(result["native_product_uninstall_accepted"])
        self.assertEqual({s["status"] for s in self._states().values()},
                         {"EMPTY"})
        self.assertEqual(external.read_bytes(),
                         b"PERSONAL_CONFIGURATION_MUST_SURVIVE")
        self.assertFalse(self.engine.journal.exists())


if __name__ == "__main__":
    unittest.main()
