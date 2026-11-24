"""R930 source-only contracts; real SCM/Inno runs only offline in Windows Sandbox."""
from __future__ import annotations
import ast
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "tools/native_fixtures/windows/BuildUniversalScmInnoSandboxInputs.py"
GUEST = ROOT / "tools/native_fixtures/windows/RunUniversalInnoScmSandboxFixture.py"


class UniversalScmInnoSandboxContract(unittest.TestCase):
    def test_native_sources_syntax(self):
        for file in (BUILD, GUEST):
            ast.parse(file.read_text("utf8"), filename=str(file))

    def test_scm_scope_is_disposable_and_cannot_touch_product(self):
        src = GUEST.read_text("utf8")
        for literal in (
            'SERVICE = "DIMR887IsolatedFixtureSvc"',
            'guest_guard(first=True)', 'UniversalFixtureInstaller',
            'Inno', 'scm_state()', '"service_exists"',
            'self._code_versions() == {old_version}',
            'self._native(old_version)', 'self._bump_native_resume()',
            'proc', '"native_scm_service_observed": True',
            '"real_product_install_accepted": False',
            '"protected_recovery_authority_accepted": False',
            '"hard_reboot_accepted": False',
        ):
            if literal == 'UniversalFixtureInstaller':
                # R930 wrapper imports R929 exact shared-engine factory.
                self.assertIn('from tools.native_fixtures.windows.RunUniversalInnoSandboxFixture import', src)
                continue
            self.assertIn(literal, src)
        for forbidden in ("DirectInternetMethodSvc", "Tailscale",
                          "netsh", "route.exe", "pkexec", "sudo "):
            self.assertNotIn(forbidden, src)
        self.assertIn('return engine(adapter)', src)
        self.assertIn('sc("create", SERVICE,', src)
        self.assertIn('sc("delete", SERVICE)', src)
        self.assertIn('not self._running(old_version)', src)

    def test_build_only_pins_two_separate_native_service_versions(self):
        src = BUILD.read_text("utf8")
        self.assertIn('ScmFixtureService.cs', src)
        self.assertIn('"VERSION_157"', src)
        self.assertIn('"R930_SYNTHETIC_SCM_ONLY"', src)
        self.assertNotIn('sc("create"', src)
        self.assertNotIn("sc create", src)

    @unittest.skipUnless(os.name == "nt",
                         "Native Inno and .NET Framework csc compile only on Windows")
    def test_native_csc_synthetic_versions_and_inno_compile(self):
        from tools.native_fixtures.windows.BuildUniversalScmInnoSandboxInputs import build
        exe = (Path(os.environ["SystemRoot"]) /
               "Microsoft.NET/Framework64/v4.0.30319/csc.exe")
        compiler = (Path(os.environ["LOCALAPPDATA"]) /
                    "Programs/Inno Setup 6/ISCC.exe")
        if not exe.is_file() or not compiler.is_file():
            self.skipTest("Native Windows compiler prerequisites missing")
        out = Path(tempfile.gettempdir()) / (
            "dim-r924-r929-r930-" + uuid.uuid4().hex[:8])
        self.assertFalse(out.exists())
        try:
            pins = build(out)
            self.assertEqual(pins["scope"], "R930_SYNTHETIC_SCM_ONLY")
            self.assertEqual(pins["name"], "DIMR887IsolatedFixtureSvc")
            self.assertNotEqual(pins["old_sha256"], pins["new_sha256"])
            for ver in ("1.5.6", "1.5.7"):
                self.assertTrue((out / ("ScmFixture-" + ver + ".exe")).is_file())
        finally:
            shutil.rmtree(out, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
