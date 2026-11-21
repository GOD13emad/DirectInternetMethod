"""R915 Windows native service updater protected transaction staging contract.

Source/regression contract only. The exact pending update and native Inno
finished receipt must still be independently tested as a real upgrade in a
privileged Sandbox. Legacy user-writable pending records are not erased.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROGRAM = ROOT / "windows" / "service" / "Program.cs"
POLICY = ROOT / "windows" / "service" / "NativeProtectedUpdateAcl.cs"
INNO = ROOT / "windows" / "installer" / "DirectInternetMethod.iss"


class ProtectedUpdateStagingContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = PROGRAM.read_text(encoding="utf-8-sig")
        cls.policy = POLICY.read_text(encoding="utf-8-sig")
        cls.inno = INNO.read_text(encoding="utf-8-sig")

    def test_active_pending_and_staged_installer_live_below_privileged_service(self):
        p = self.program
        self.assertIn('Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, ".."))', p)
        self.assertIn('"UpdateTransactions"', p)
        self.assertIn('static string PendingUpdatePath => Path.Combine(UpdatesDir, "pending-update.json");', p)
        self.assertIn('static string LegacyPendingUpdatePath => Path.Combine(RuntimeDir, "pending-update.json");', p)
        self.assertIn('static string OwnedUpdateInstallerPath => Path.Combine(UpdatesDir, "DirectInternetMethod-update-stage.exe");', p)
        self.assertNotIn('static string UpdatesDir => Path.Combine(RuntimeDir, "updates");', p)

    def test_legacy_untrusted_record_is_never_silently_accepted_or_deleted(self):
        p = self.program
        update = p.split('static async Task RunUpdateAsync()', 1)[1].split('static bool PendingNativeRegistrationMatches', 1)[0]
        self.assertLess(update.index('File.Exists(LegacyPendingUpdatePath)'),
                        update.index('GetLatestUpdateAsync('))
        self.assertIn('Legacy user-writable pending update requires protected native reconciliation', update)
        finalizer = p.split('static void FinalizePendingUpdate()', 1)[1].split('static async Task RunActionAsync(', 1)[0]
        self.assertLess(finalizer.index('File.Exists(LegacyPendingUpdatePath)'),
                        finalizer.index('File.Delete(PendingUpdatePath);'))
        self.assertNotIn('File.Delete(LegacyPendingUpdatePath)', p)
        self.assertIn('Legacy user-writable updater evidence cannot be auto-finalized.', finalizer)

    def test_approved_acl_precedes_download_or_native_process_handoff(self):
        update = self.program.split('static async Task RunUpdateAsync()', 1)[1].split(
            'static bool PendingNativeRegistrationMatches', 1
        )[0]
        acl = update.index('NativeProtectedUpdateAcl.PrepareProtectedTransactionDirectory(')
        download = update.index('DownloadWithSystemCurlAsync(')
        launch = update.index('Process.Start(psi)')
        self.assertLess(acl, download)
        self.assertLess(acl, launch)
        self.assertIn('!NativeProtectedUpdateAcl.IsProtectedExistingDirectory(UpdatesDir)', update)

    def test_finalize_rechecks_actual_acl_before_pending_provenance_deletion(self):
        final = self.program.split('static void FinalizePendingUpdate()', 1)[1].split(
            'static async Task RunActionAsync(', 1
        )[0]
        check = final.index('!NativeProtectedUpdateAcl.IsProtectedExistingDirectory(UpdatesDir)')
        load = final.index('JsonDocument.Parse(File.ReadAllText(PendingUpdatePath))')
        stage_delete = final.index('File.Delete(stage)')
        pending_delete = final.index('File.Delete(PendingUpdatePath)')
        self.assertLess(check, load)
        self.assertLess(check, stage_delete)
        self.assertLess(check, pending_delete)
        self.assertIn('OwnedUpdateInstallerPath', final)

    def test_inno_only_observes_protected_pending_without_deleting_evidence(self):
        i = self.inno
        self.assertIn("PendingPath := ExpandConstant('{commonpf}\\DirectInternetMethod\\Privileged\\UpdateTransactions\\pending-update.json')", i)
        self.assertIn("new service completes SHA-checked cleanup", i)
        self.assertNotIn('DeleteFile(PendingPath)', i)

    def test_uninstall_removes_only_empty_protected_transaction_directory(self):
        section = self.inno.split("[UninstallDelete]", 1)[1].split("[Icons]", 1)[0]
        expected = 'Type: dirifempty; Name: "{commonpf}\\DirectInternetMethod\\Privileged\\UpdateTransactions"'
        self.assertIn(expected, section)
        self.assertLess(section.index(expected),
                        section.index('Type: dirifempty; Name: "{commonpf}\\DirectInternetMethod\\Privileged"'))
        self.assertNotIn('Type: dir; Name: "{commonpf}\\DirectInternetMethod\\Privileged\\UpdateTransactions"', section)
        self.assertNotIn('Type: filesandordirs;', section)

    def test_private_parent_policy_does_not_grant_privileges_or_write_acl(self):
        src = self.policy
        self.assertIn('TryGetTrustedProtectedParent(', src)
        self.assertIn('Directory.CreateDirectory(transactions)', src)
        self.assertIn('!IsProtectedExistingDirectory(transactions)', src)
        self.assertNotIn('SetAccessControl(', src)


if __name__ == "__main__":
    unittest.main()
