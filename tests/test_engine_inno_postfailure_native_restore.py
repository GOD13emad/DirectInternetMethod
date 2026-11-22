"""R924 contracts for isolated Inno postinstall failure and explicit old installer restore.

Build-time/source verification; live native verification requires network-off
Windows Sandbox, not the developer's host. Does not assert production rollback.
"""
from __future__ import annotations
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RENDER = ROOT / "tools/native_fixtures/windows/RenderInnoPostFailureFixture.py"
GUEST = ROOT / "tools/native_fixtures/windows/RunInnoPostFailureRecoverySandboxFixture.ps1"


class NativeInnoPostFailureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("dim_r924_inno_postfail", RENDER)
        cls.renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.renderer)

    def test_generated_scripts_are_synthetic_and_fail_only_new_postinstall(self):
        with tempfile.TemporaryDirectory(prefix="dim-r924-parent-") as root:
            # Renderer admits only a new direct child of the host OS-temp dir.
            dest = Path(tempfile.gettempdir()) / (Path(root).name + "-fixture")
            self.assertFalse(dest.exists())
            try:
                info = self.renderer.build(dest)
                self.assertEqual(info["scope"], "R924_SYNTHETIC_INNO_FAILURE_ONLY")
                old = (dest / "R924_1_5_6.iss").read_text("utf-8")
                new = (dest / "R924_1_5_7.iss").read_text("utf-8")
                for script in (old, new):
                    self.assertIn("PrivilegesRequired=admin", script)
                    self.assertIn("UninstallLogMode=overwrite", script)
                    self.assertIn("AppId={{BE452737-93D8-4693-930C-C0ABFF932924}", script)
                    self.assertNotIn("DirectInternetMethodSvc", script)
                    self.assertNotIn("{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}", script)
                    self.assertIn('DestName: "code.fixture"', script)
                self.assertNotIn("GetCustomSetupExitCode", old)
                self.assertIn("CurStep = ssPostInstall", new)
                self.assertIn("Result := 67", new)
                self.assertIn("if R924PostInstallError", new)
                with self.assertRaisesRegex(ValueError, "REFUSE_OVERWRITE_OR_REPLAY"):
                    self.renderer.build(dest)
            finally:
                shutil.rmtree(dest, ignore_errors=True)

    def test_refuses_foreign_or_nested_target(self):
        with tempfile.TemporaryDirectory(prefix="dim-r924-test-parent-") as root:
            with self.assertRaisesRegex(ValueError, "FIXTURE_ONLY_DIRECT_CHILD_OF_OS_TEMP"):
                self.renderer.build(Path(root) / "dim-r924-nested456")
            with self.assertRaisesRegex(ValueError, "FIXTURE_ROOT_NAME_REQUIRED"):
                self.renderer.build(Path(tempfile.gettempdir()) / "bad-root-name")

    def test_guest_native_assertions_are_required(self):
        s = GUEST.read_text(encoding="utf-8-sig")
        for required in ("S-1-5-18", "GetRegistry", "Sha $NewExe",
                         "InvokeSetup $NewExe 67",
                         "CheckNative '1.5.7' $newHash",
                         "InvokeSetup $OldExe 0",
                         "CheckNative '1.5.6' $oldHash",
                         "UNINSTALL_LEFT_REGISTRATION",
                         "OWNER_DATA_CHANGED_AFTER_UNINSTALL",
                         "real_product_rollback_accepted=$false"):
            self.assertIn(required, s)
        self.assertNotIn("DirectInternetMethodSvc", s)
        self.assertNotIn("sc.exe", s)

    @unittest.skipUnless(os.name == "nt", "Inno 6 fixture build only on Windows")
    def test_real_inno6_compiles_synthetic_failure_pair(self):
        compiler = Path(os.environ["LOCALAPPDATA"]) / "Programs/Inno Setup 6/ISCC.exe"
        if not compiler.is_file():
            self.skipTest("Inno 6 compiler missing")
        with tempfile.TemporaryDirectory(prefix="dim-r924-pair-") as root:
            dest = Path(tempfile.gettempdir()) / (Path(root).name + "-fixture")
            try:
                self.renderer.build(dest)
                for version in ("1_5_6", "1_5_7"):
                    script = dest / f"R924_{version}.iss"
                    result = subprocess.run([str(compiler), str(script)], timeout=50,
                                            text=True, capture_output=True)
                    self.assertEqual(0, result.returncode,
                                     (result.stdout + result.stderr)[-1800:])
                    self.assertTrue((dest / f"R924_Inno_{version}.exe").is_file())
            finally:
                shutil.rmtree(dest, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
