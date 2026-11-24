"""R929 safety and three pinned real synthetic Inno packages for Windows guest.

Native execution against HKLM/Program Files is ONLY inside Windows Sandbox,
not in this source test or on the Windows build machine.
"""
from __future__ import annotations
import ast
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "tools/native_fixtures/windows/BuildUniversalInnoSandboxInputs.py"
GUEST = ROOT / "tools/native_fixtures/windows/RunUniversalInnoSandboxFixture.py"


class UniversalWindowsInnoContracts(unittest.TestCase):
    def test_synthetic_scripts_parse_on_any_host(self):
        for path in (GEN, GUEST):
            with self.subTest(path=path):
                ast.parse(path.read_text("utf8"), filename=str(path))

    def test_native_adapter_uses_one_shared_orchestrator_and_is_guest_only(self):
        source = GUEST.read_text("utf8")
        for required in (
            'S-1-5-18', 'WDAGUtilityAccount', "guest_guard(first=True)",
            "UniversalFixtureInstaller(", 'APP_ID = "{BE452737',
            '"native_scm_service_accepted": False',
            '"real_product_rollback_accepted": False',
            '"native_os_broker_accepted": False',
            'self._native(target_version)',
            'self._code_versions() == {old_version}',
            'status": "restored"',
            'proc = subprocess.run([sys.executable, "--replay"]',
            "sha(owner) == owner_sha",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        for forbidden in ("DirectInternetMethodSvc", "sc.exe",
                          "netsh", "route.exe",
                          "root/polkit", "pkexec", "sudo "):
            self.assertNotIn(forbidden, source)

    def test_input_builder_is_confined_to_exact_nonproduct_identity(self):
        source = GEN.read_text("utf8")
        self.assertIn("RenderInnoPostFailureFixture import", source)
        self.assertIn("R929_SYNTHETIC_INNO_THREE_PACKAGES", source)
        self.assertIn("R929_TEMP_ONLY_SYNTHETIC_ROOT", source)
        self.assertIn("R929_Inno_1_5_7_good", source)
        self.assertNotIn("DirectInternetMethodSvc", source)

    @unittest.skipUnless(os.name == "nt",
                         "Actual Inno6 three-EXE compilation Windows only")
    def test_three_native_inno_synthetic_packages_compile_and_are_pinned(self):
        compiler = (Path(os.environ["LOCALAPPDATA"]) /
                    "Programs/Inno Setup 6/ISCC.exe")
        if not compiler.is_file():
            self.skipTest("Inno6 compiler not installed")
        spec = importlib.util.spec_from_file_location("r929_builder", GEN)
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        dest = Path(tempfile.gettempdir()) / (
            "dim-r924-r929-" + uuid.uuid4().hex[:8])
        self.assertFalse(dest.exists())
        try:
            pins = builder.render(dest)
            self.assertEqual(pins["scope"],
                             "R929_SYNTHETIC_INNO_THREE_PACKAGES")
            self.assertEqual(pins["app_id"],
                             "{BE452737-93D8-4693-930C-C0ABFF932924}")
            for k, filename in (
                ("old", "R924_Inno_1_5_6.exe"),
                ("failed", "R924_Inno_1_5_7.exe"),
                ("good", "R929_Inno_1_5_7_good.exe"),
            ):
                self.assertRegex(pins[k], r"^[0-9a-f]{64}$")
                with self.subTest(k=k):
                    self.assertEqual(hashlib.sha256(
                        (dest/filename).read_bytes()).hexdigest(), pins[k])
            good = (dest/"R929_1_5_7_good.iss").read_text("utf8")
            bad = (dest/"R924_1_5_7.iss").read_text("utf8")
            self.assertNotIn("[Code]", good)
            self.assertIn("GetCustomSetupExitCode", bad)
            with self.assertRaisesRegex(ValueError, "REFUSE_OVERWRITE"):
                builder.render(dest)
        finally:
            shutil.rmtree(dest, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
