#!/usr/bin/env python3
"""R846: proposed private 1.5.7 Windows forward-source proof, not a release."""
import json
from pathlib import Path
from xml.etree import ElementTree
import unittest

R=Path(__file__).resolve().parents[1]
PUB=json.loads((R/"RELEASE.json").read_text("utf-8"))
META=json.loads((R/"windows/RELEASE.json").read_text("utf-8"))
ISS=(R/"windows/installer/DirectInternetMethod.iss").read_text("utf-8")
WF=(R/".github/workflows/ci.yml").read_text("utf-8")
UI=(R/"windows/gui/MainWindow.xaml.cs").read_text("utf-8")
UP=(R/"windows/gui/UpdateClient.cs").read_text("utf-8")
SVC=(R/"windows/service/Program.cs").read_text("utf-8")

class ForwardWindows157(unittest.TestCase):
    def test_private_version_not_published(self):
        self.assertEqual(PUB["version"],"1.5.4")
        self.assertEqual(META["version"],"1.5.7")
        self.assertEqual(META["status"],"PRIVATE_WINDOWS_V157_SOURCE_CANDIDATE_UNPUBLISHED_UNPROVEN")
        self.assertEqual(META["previousAccepted"]["tag"],"v1.5.4")
        self.assertIsNone(META["publication"]["publishedAt"])
    def test_assembly_forward_from_real_private156(self):
        for rel in ("windows/gui/DirectInternetMethod.csproj","windows/service/DirectInternetMethod.Service.csproj"):
            tree=ElementTree.parse(R/rel)
            for tag,expected in (("Version","1.5.7"),("FileVersion","1.5.7.0"),("AssemblyVersion","1.5.7.0"),("TargetFramework","net10.0-windows")):
                self.assertEqual(tree.findtext(".//"+tag),expected,rel)
        self.assertGreater((1,5,7,0),(1,5,6,0))
    def test_same_id_inplace_and_single_uninstall_log(self):
        for token in ('#define MyAppVersion "1.5.7"','VersionInfoVersion=1.5.7.0',
                      'OutputBaseFilename=DirectInternetMethod_1.5.7_Windows_Setup',
                      'UsePreviousAppDir=yes','UninstallLogMode=overwrite',
                      'AppId={{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}',
                      'PrivilegesRequired=admin'):
            self.assertIn(token,ISS)
    def test_monotonic_updater_unweakened(self):
        self.assertIn('latest <= current',UP)
        self.assertIn('latest <= CurrentVersion',SVC)
        self.assertIn('Version.TryParse(clean, out var latest)',UP)
        self.assertIn('Version.TryParse(clean, out var latest)',SVC)
        self.assertIn('DirectInternetMethod/1.5.7',UI)
    def test_historic_r535_receipts_retained(self):
        self.assertIn('PASS_HOSTED_NATIVE_154_TO_156_AND_BACK_154',
                      (R/"tests/r535_windows_native_rollback.ps1").read_text("utf-8"))
        self.assertIn('PRIVATE_WINDOWS_V156_SOURCE_CANDIDATE_UNPUBLISHED_UNPROVEN',
                      (R/"tests/r805_windows_156_forward_contract.py").read_text("utf-8"))
        self.assertIn('prep/r846-forward-157-native-gates',WF)
        self.assertIn('windows-private-r846-native:',WF)
        self.assertIn('tests/r846_windows_candidate_hosted_build.ps1',WF)
        self.assertIn('tests/r846_windows_native_rollback.ps1',WF)
        for rel in ("tests/r846_windows_candidate_hosted_build.ps1","tests/r846_windows_native_rollback.ps1"):
            source=(R/rel).read_text("utf-8")
            self.assertIn("R846",source)
            self.assertIn("refs/heads/prep/r846-forward-157-native-gates",source)
            self.assertIn("GOD13emad/DirectInternetMethod",source)
            self.assertIn("github-hosted",source)
            self.assertNotIn("refs/heads/prep/r803-forward-156-native-gates",source)

if __name__=="__main__":
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ForwardWindows157))
    raise SystemExit(0 if result.wasSuccessful() else 1)
