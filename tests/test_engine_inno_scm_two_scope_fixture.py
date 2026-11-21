"""R892 synthetic native Inno + SCM + portable dual-scope fixture contracts.

CI only renders/compiles fake installers; NEVER installs them or changes SCM.
The actual synthetic native lifecycle must execute in isolated Windows Sandbox.
"""
from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1] / "tools/native_fixtures/windows"
RENDER = ROOT / "RenderInnoRegistryFixture.py"
WRAP = ROOT / "ScmInnoTwoScopeFixtureEntry.py"
GUEST = ROOT / "RunScmInnoTwoScopeSandboxFixture.ps1"
PRODUCT_APP_ID = "{E8039748-26D7-4E64-ACEF-3E24B708B9A2}"


class InnoScmDualFixtureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="dim-r892-inno-")
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.marker = self.d / "marker.txt"
        self.marker.write_text("SYNTHETIC_ONLY\n", "utf-8")
        spec = importlib.util.spec_from_file_location("dim_r892_fixture_render", RENDER)
        self.renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.renderer)

    def test_fixed_synthetic_appid_and_64_bit_hklm_setup(self):
        self.assertEqual(self.renderer.APP_ID, PRODUCT_APP_ID)
        script = self.d/"r892.iss"
        self.renderer.render("1.5.6", self.marker, self.d, script)
        text = script.read_text("utf-8")
        self.assertIn("AppId={{E8039748-26D7-4E64-ACEF-3E24B708B9A2}", text)
        self.assertIn("ArchitecturesInstallIn64BitMode=x64compatible", text)
        self.assertIn("PrivilegesRequired=admin", text)
        self.assertIn("UninstallLogMode=overwrite", text)
        self.assertNotIn("DirectInternetMethodSvc", text)
        self.assertNotIn("GOD13emad", text)

    def test_reject_wrong_version_and_overwriting_foreign_script(self):
        with self.assertRaisesRegex(ValueError, "SYNTHETIC_VERSIONS_ONLY"):
            self.renderer.render("9.9.9", self.marker, self.d, self.d/"new.iss")
        p = self.d/"existing.iss"
        p.write_bytes(b"FOREIGN_DO_NOT_REPLACE")
        with self.assertRaisesRegex(ValueError, "SCRIPT_DESTINATION_EXISTS"):
            self.renderer.render("1.5.7", self.marker, self.d, p)
        self.assertEqual(p.read_bytes(), b"FOREIGN_DO_NOT_REPLACE")

    def test_wrapper_requires_inno_registry_plus_service_observation(self):
        source = WRAP.read_text("utf-8")
        ast.parse(source, filename=str(WRAP))
        for phrase in ("observe_windows(APP_ID, base.SERVICE)",
                       'rows[0]["hive"] == "HKLM"',
                       'rows[0]["display_version"] == expected',
                       "base.observed = registered"):
            self.assertIn(phrase, source)
        self.assertIn("native_product_install_accepted", source)
        self.assertNotIn("DirectInternetMethodSvc", source)

    def test_native_guest_has_separate_report_and_path_and_inno_lifecycle(self):
        code = GUEST.read_text("utf-8")
        self.assertIn("$ReceiptPath = ", code)
        self.assertIn("$Report=[ordered]@{", code)
        self.assertNotIn("$receipt=[ordered]@{", code)
        self.assertIn("InstallInno '1.5.6'", code)
        self.assertIn("InstallInno '1.5.7'", code)
        self.assertIn("RemoveInno", code)
        self.assertIn("CheckInno '1.5.6'", code)
        self.assertIn("COORDINATOR_FORWARD_RECOVERY_REQUIRED", code)
        self.assertIn("PASS_R892_SYNTHETIC_NATIVE_INNO_SCM_TWO_SCOPE", code)
        self.assertIn("native_product_installation_accepted=$false", code)
        self.assertNotIn("DirectInternetMethodSvc", code)

    @unittest.skipUnless(os.name == "nt", "ISCC 6 fixture compilation only on Windows")
    def test_inno_6_compiles_two_versioned_isolated_installers(self):
        compiler = Path(os.environ["LOCALAPPDATA"]) / "Programs/Inno Setup 6/ISCC.exe"
        if not compiler.is_file():
            self.skipTest("Inno Setup 6 unavailable")
        outputs = []
        for version in ("1.5.6", "1.5.7"):
            path = self.d/("r892_"+version.replace(".", "_")+".iss")
            self.renderer.render(version, self.marker, self.d, path)
            result = subprocess.run([str(compiler), str(path)], capture_output=True,
                                    text=True, timeout=25)
            self.assertEqual(result.returncode, 0, result.stderr)
            output = self.d/("R892_Inno_"+version.replace(".", "_")+".exe")
            self.assertTrue(output.is_file())
            outputs.append(output.read_bytes())
        self.assertNotEqual(outputs[0], outputs[1])


if __name__ == "__main__":
    unittest.main()
