"""R911 conservative Windows updater native-registration finalization contract.

Source-only regression tests, not a production service or UAC proof. Native
C# console-selftest is independently run on real Windows during R911 QA.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "windows" / "service" / "Program.cs"
RECEIPT = ROOT / "windows" / "service" / "NativePendingUpdateReceipt.cs"


class PendingNativeReceiptContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = SERVICE.read_text(encoding="utf-8-sig")
        cls.helper = RECEIPT.read_text(encoding="utf-8-sig")

    def test_native_registry_identity_required_before_pending_cleanup(self):
        source = self.program.split(
            "static void FinalizePendingUpdate()", 1)[1].split(
            "static async Task RunActionAsync(", 1)[0]
        prerequisite = source.index("PendingNativeRegistrationMatches(")
        installer_delete = source.index("File.Delete(stage);")
        pending_delete = source.index("File.Delete(PendingUpdatePath);")
        done = source.index('WriteActionStatus("update", "done",')
        self.assertLess(prerequisite, installer_delete)
        self.assertLess(prerequisite, pending_delete)
        self.assertLess(prerequisite, done)
        self.assertIn('pending-update-native-registration-unverified-preserving-evidence', source)
        self.assertIn('WriteActionStatus("update", "running", null,', source)

    def test_only_real_hklm_appid_and_pending_install_dir_used(self):
        native = self.program.split(
            "static bool PendingNativeRegistrationMatches(", 1)[1].split(
            "static async Task FinalizePendingAfterServiceRestartAsync()", 1)[0]
        for required in (
            'Registry.LocalMachine.OpenSubKey(keyPath, writable: false)',
            'InstallLocation', 'DisplayName', 'DisplayVersion',
            'TryGetProperty("installDir", out var installRoot)',
            'NativePendingUpdateReceipt.IsConsistent(',
            'GetRegisteredInstallDirectory();',
            'return false;',
        ):
            with self.subTest(required=required):
                self.assertIn(required, native)
        for forbidden in ("Registry.LocalMachine.CreateSubKey", "DeleteSubKey",
                          "File.Delete(", "File.Move(", "Process.Start("):
            self.assertNotIn(forbidden, native)

    def test_version_name_path_guard_is_explicit_and_fails_closed(self):
        body = self.helper
        for term in (
            '"Direct Internet Method"',
            'string.Equals(registeredDisplayName, ExactDisplayName,',
            'Path.IsPathFullyQualified(trimmed)',
            'char.IsAsciiLetter(trimmed[0])',
            'Path.GetFullPath(trimmed)',
            'StringComparison.OrdinalIgnoreCase',
            'runningServiceVersion.CompareTo(pendingTargetVersion) < 0',
            'registered.Major != runningServiceVersion.Major',
            'registered.Minor != runningServiceVersion.Minor',
            'registered.Build != runningServiceVersion.Build',
            'return false;',
        ):
            with self.subTest(term=term):
                self.assertIn(term, body)
        self.assertNotIn('Registry.LocalMachine', body)
        self.assertNotIn('File.Delete', body)

    def test_negative_probes_are_in_native_selftest(self):
        segment = self.program.split(
            "static string SelfTest()", 1)[1]
        for text in (
            'PENDING_NATIVE_VALID_RECEIPT_REJECTED',
            'PENDING_NATIVE_NEGATIVE_RECEIPT_ACCEPTED',
            'Direct Internet Method version 1.5.7',
            'new Version(1, 5, 8)',
            'new Version(1, 5, 6)',
            'foreign',
            'relative',
            'server',
        ):
            with self.subTest(text=text):
                self.assertIn(text, segment)

    def test_exhausted_retry_and_exception_preserve_pending_error(self):
        text = self.program
        self.assertIn('Post-install native verification incomplete; pending evidence preserved.', text)
        self.assertIn('Post-install verification failed; pending installer and identity preserved.', text)
        self.assertIn('if (File.Exists(PendingUpdatePath))', text)


if __name__ == "__main__":
    unittest.main()
