"""R947 Windows-shaped two-scope activated code postflight, portable fixture.

This exercises the SAME cross-platform read-only postflight with Windows
manifest/pin identity on Windows/Linux CI, not genuine SCM/UAC/Inno custody.
"""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from installer_engine.engine import EngineError, PRODUCT, hash_bytes
from installer_engine.native_plan import NativePlan
from installer_engine.native_readiness import (two_scope_code_postflight,
                                              two_scope_native_postflight)
from installer_engine.universal_install import UniversalFixtureInstaller
from tests.test_engine_universal_install import FileNativeFixture


class WindowsTwoScopePostflightFixture(unittest.TestCase):
    def test_windows_manifest_and_native_intent_bind_exact_activated_files(self):
        with tempfile.TemporaryDirectory(prefix="dim-r947-win-synthetic-") as t:
            base = Path(t)
            roots = {name: base / ("installed-" + name)
                     for name in ("protected", "user")}
            adapter = FileNativeFixture(base)
            core = UniversalFixtureInstaller(
                base / "journal", "windows-x86_64", roots, adapter)
            sources = {}
            manifests = {}
            for name in sorted(roots):
                bundle = base / ("source-" + name)
                member = bundle / "payload" / "app" / "code.bin"
                member.parent.mkdir(parents=True)
                data = ("R947_SYNTHETIC_" + name).encode("ascii")
                member.write_bytes(data)
                manifest = {
                    "schema": 1, "product": PRODUCT,
                    "platform": "windows-x86_64", "version": "1.5.7",
                    "files": [{"path": "app/code.bin", "bytes": len(data),
                               "sha256": hash_bytes(data), "mode": 0o644}],
                }
                manifests[name] = manifest
                blob = (json.dumps(manifest, separators=(",", ":"), sort_keys=True)
                        + "\n").encode("utf-8")
                (bundle / "manifest.json").write_bytes(blob)
                sources[name] = (bundle, hash_bytes(blob))
            plan = NativePlan(
                PRODUCT, "1.5.7", "windows-x86_64",
                "PINNED_CODE_LAYOUT_REQUIRES_TRUSTED_NATIVE_ADAPTER",
                tuple((name, manifests[name]) for name in sorted(manifests)))
            core.begin(sources)
            core.activate()
            native = core._intent(core._load())
            ok = two_scope_code_postflight(plan, roots, native,
                                           journal_path=core.journal)
            self.assertEqual([r["files"] for r in ok["scopes"]], [1, 1])
            self.assertFalse(ok["os_native_registration_verified"])
            self.assertFalse(ok["native_installation_accepted"])
            if os.name == "nt":
                # Windows parity: the same shared code+journal gate requires
                # a separately observed SCM/Inno registration. The observation
                # is mocked here; this is NOT native Windows acceptance.
                params = dict(journal_path=core.journal,
                              windows_app_id="{00000000-0000-0000-0000-000000000001}",
                              windows_service_name="DIMR950Sandbox",
                              windows_expected_binary_command="C:\\Test\\dim-r950.exe")
                with patch("installer_engine.native_readiness.windows_readiness",
                           side_effect=EngineError("SCM_SERVICE_MISSING")):
                    with self.assertRaisesRegex(EngineError, "SCM_SERVICE_MISSING"):
                        two_scope_native_postflight(plan, roots, native, **params)
                with patch("installer_engine.native_readiness.windows_readiness",
                           return_value={"native_installation_or_rollback_accepted": False,
                                         "service": {"state": "RUNNING"},
                                         "registrations": [{"display_version": "1.5.7"}]}):
                    composed = two_scope_native_postflight(
                        plan, roots, native, **params)
                    self.assertFalse(composed["native_installation_accepted"])
                    self.assertEqual(composed["native"]["service"]["state"], "RUNNING")
                with patch("installer_engine.native_readiness.windows_readiness",
                           return_value={"native_installation_or_rollback_accepted": True}):
                    with self.assertRaisesRegex(
                            EngineError, "R950_NATIVE_OBSERVATION_MUST_NOT_AUTHORIZE"):
                        two_scope_native_postflight(plan, roots, native, **params)
            path = roots["user"] / "current" / "app" / "code.bin"
            before = path.read_bytes()
            path.write_bytes(b"R947_CORRUPT")
            with self.assertRaisesRegex(EngineError, "INSTALLED_MANAGED_FILE_CHANGED"):
                two_scope_code_postflight(plan, roots, native,
                                           journal_path=core.journal)
            path.write_bytes(before)
            forged = json.loads(json.dumps(native))
            forged["request_id"] = "0" * 32
            # A different valid request ID with identical source hashes
            # must not pass the read-only journal-to-native binding.
            with self.assertRaisesRegex(
                    EngineError, "R947_LIVE_JOURNAL_INTENT_DRIFT"):
                two_scope_code_postflight(plan, roots, forged,
                                          journal_path=core.journal)
            core.commit()


if __name__ == "__main__":
    unittest.main()
