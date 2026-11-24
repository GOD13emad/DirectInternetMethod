"""R912 native Inno ssPostInstall false-success prevention contract.

Inno /VERYSILENT /SUPPRESSMSGBOXES may swallow a Pascal Script
RaiseException and still emit ssDone + exit 0. Source contract and
synthetic native test evidence are separate from privileged rollback.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "windows" / "installer" / "DirectInternetMethod.iss"


class InnoPostinstallExitContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = INSTALLER.read_text(encoding="utf-8-sig")

    def test_nonzero_exit_does_not_depend_on_exception_handling(self):
        s = self.source
        self.assertIn("DIMPostInstallCompleted: Boolean;", s)
        self.assertIn("function GetCustomSetupExitCode: Integer;", s)
        function = s.split("function GetCustomSetupExitCode: Integer;", 1)[1].split(
            "function InitializeUninstall()", 1
        )[0]
        self.assertRegex(
            function,
            r"if DIMPostInstallCompleted and\s+\(\(not DIMUpdateReceiptExpected\) or DIMUpdateReceiptCompleted\) then\s+Result := 0\s+else\s+Result := 67;",
        )
        self.assertNotIn("RaiseException(", function)

    def test_success_flag_set_once_only_after_native_scm_and_pending(self):
        s = self.source
        self.assertEqual(s.count("DIMPostInstallCompleted := True;"), 1)
        section = s.split("procedure CurStepChanged(CurStep: TSetupStep);", 1)[1].split(
            "function GetCustomSetupExitCode:", 1
        )[0]
        required = (
            "if CurStep = ssPostInstall then",
            "InstallOrUpdateCtrldService();",
            "InstallOrUpdateService();",
            "CompletePendingDirectUpdate();",
            "DIMPostInstallCompleted := True;",
        )
        positions = [section.index(snip) for snip in required]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(section.count("DIMPostInstallCompleted := True;"), 1)

    def test_registered_product_inno_identity_and_service_names_unchanged(self):
        s = self.source
        self.assertIn("UninstallDisplayName={#MyAppName}", s)
        self.assertIn("UninstallLogMode=overwrite", s)
        self.assertIn("ServiceName = 'DirectInternetMethodSvc';", s)
        self.assertIn("CtrldServiceName = 'ctrld';", s)
        self.assertIn("CompletePendingDirectUpdate();", s)

    def test_no_claim_that_custom_exit_implements_rollback(self):
        s = self.source
        code = s.split("function GetCustomSetupExitCode:", 1)[1].split(
            "function InitializeUninstall()", 1
        )[0]
        self.assertNotIn("File.Delete", code)
        self.assertNotIn("RunSc(", code)
        self.assertNotIn("RemoveDir(", code)


if __name__ == "__main__":
    unittest.main()
