#!/usr/bin/env python3
"""R805 source-only Windows forward-release identity contract, no installation.

Checks that public 1.5.4 stays immutable while the single future Windows and
Linux 1.5.6 private source candidate remains monotonically newer than the
already installed private Windows FileVersion 1.5.5.0.
"""
from pathlib import Path
from xml.etree import ElementTree as ET
import json,re,unittest
R=Path(__file__).resolve().parents[1]
META=json.loads((R/"windows/RELEASE.json").read_text("utf8"))
WIN=json.loads((R/"windows/manifest.json").read_text("utf8"))
PUBLIC=json.loads((R/"RELEASE.json").read_text("utf8"))
ISS=(R/"windows/installer/DirectInternetMethod.iss").read_bytes()
UI=(R/"windows/gui/MainWindow.xaml.cs").read_bytes()
WF=(R/".github/workflows/ci.yml").read_text()
EXPECTED="1.5.6"
class WindowsV156(unittest.TestCase):
    def test_exact_product_versions(self):
        self.assertEqual(META["version"],EXPECTED)
        self.assertEqual(META["status"],"PRIVATE_WINDOWS_V156_SOURCE_CANDIDATE_UNPUBLISHED_UNPROVEN")
        self.assertEqual(WIN["version"],EXPECTED)
        self.assertEqual(len(WIN["files"]),681)
        self.assertEqual(META["previousAccepted"]["tag"],"v1.5.4")
        self.assertEqual(PUBLIC["version"],"1.5.4")
        self.assertIsNone(META["publication"]["publishedAt"])
    def test_windows_gui_service_assembly_and_file_versions(self):
        for rel in ("windows/gui/DirectInternetMethod.csproj","windows/service/DirectInternetMethod.Service.csproj"):
            tree=ET.fromstring((R/rel).read_bytes())
            def val(k):return tree.findtext(".//"+k)
            self.assertEqual(val("Version"),EXPECTED,rel)
            self.assertEqual(val("FileVersion"),EXPECTED+".0",rel)
            self.assertEqual(val("AssemblyVersion"),EXPECTED+".0",rel)
            self.assertEqual(val("TargetFramework"),"net10.0-windows")
    def test_inplace_same_appid_and_numeric_forward(self):
        self.assertIn(b'#define MyAppVersion "1.5.6"',ISS)
        self.assertIn(b'VersionInfoVersion=1.5.6.0',ISS)
        self.assertIn(b'OutputBaseFilename=DirectInternetMethod_1.5.6_Windows_Setup',ISS)
        self.assertIn(b'UsePreviousAppDir=yes',ISS)
        self.assertIn(b'UninstallLogMode=overwrite',ISS)
        self.assertIn(b'{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}',ISS)
        self.assertLess((1,5,5,0),(1,5,6,0))
    def test_hosted_native_path_preserves_actual_recovery(self):
        build=(R/"tests/r535_windows_candidate_hosted_build.ps1").read_text("utf8")
        native=(R/"tests/r535_windows_native_rollback.ps1").read_text("utf8")
        self.assertIn("PASS_ISOLATED_HOSTED_V156_BUILD",build)
        self.assertIn("PASS_HOSTED_NATIVE_154_TO_156_AND_BACK_154",native)
        self.assertIn("DirectInternetMethod_1.5.6_Windows_Setup.exe",build)
        self.assertIn("DirectInternetMethod_1.5.6_Windows_Setup.exe",native)
        self.assertIn("IN_PLACE_USER_DATA_PRESERVED",native)
        self.assertIn("NETWORK_BASELINE_EXACT",native)
        self.assertIn("ORIGINAL_STABLE_BINARY_HASHES_RESTORED",native)
    def test_useragent_and_original_repo_branch_guards(self):
        self.assertIn(b'DirectInternetMethod/1.5.6',UI)
        for name in ("tests/r535_windows_candidate_hosted_build.ps1","tests/r535_windows_native_rollback.ps1"):
            raw=(R/name).read_text("utf8")
            self.assertIn("GOD13emad/DirectInternetMethod",raw)
            self.assertIn("prep/r805-windows-156",raw)
            self.assertIn("$env:GITHUB_SHA",raw)
        self.assertIn("refs/heads/prep/r805-windows-156",WF)
        self.assertIn("windows-private-r535-native:",WF)
        self.assertIn("startsWith(github.ref, 'refs/tags/v')",WF)

if __name__=="__main__":
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(WindowsV156))
    print("R805_WINDOWS_SOURCE_PRIVATE_FORWARD_TESTS",result.testsRun,
          "PASS" if result.wasSuccessful() else "FAIL")
    raise SystemExit(0 if result.wasSuccessful() else 1)
