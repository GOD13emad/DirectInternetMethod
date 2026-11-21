"""R918 native Inno ssDone protected, per-attempt completion contract.

Source-order checks only; paired actual Windows guest install/error injection is
a separate gate. No production updater/rollback acceptance from these tests.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROGRAM = (ROOT / "windows/service/Program.cs").read_text(encoding="utf-8-sig")
INNO = (ROOT / "windows/installer/DirectInternetMethod.iss").read_text(encoding="utf-8-sig")
HELPER = (ROOT / "windows/service/NativeInnoCompletionReceipt.cs").read_text(encoding="utf-8-sig")


class NativeInnoReceiptContract(unittest.TestCase):
    def test_service_creates_new_random_txn_and_preserves_legacy(self):
        update = PROGRAM.split("static async Task RunUpdateAsync()", 1)[1].split("static bool PendingNativeRegistrationMatches(", 1)[0]
        self.assertIn("RandomNumberGenerator.GetBytes(32)", update)
        self.assertIn("schema = 2,", update)
        self.assertIn("transactionId,", update)
        self.assertIn('psi.ArgumentList.Add("/DIMTXN=" + transactionId)', update)
        self.assertIn('psi.ArgumentList.Add("/DIMSHA256=" + actual)', update)
        self.assertLess(update.index("WriteJsonAtomic(PendingUpdatePath"), update.index("Process.Start(psi)"))
        self.assertLess(update.index("File.Exists(LegacyPendingUpdatePath)"), update.index("GetLatestUpdateAsync("))

    def test_inno_never_publishes_completion_before_ssdone(self):
        body = INNO.split("procedure CurStepChanged(CurStep: TSetupStep);", 1)[1].split("function GetCustomSetupExitCode", 1)[0]
        self.assertIn("InstallOrUpdateService();", body)
        self.assertIn("CompletePendingDirectUpdate();", body)
        self.assertIn("DIMPostInstallCompleted := True;", body)
        self.assertIn("(CurStep = ssDone) and DIMUpdateReceiptExpected", body)
        self.assertLess(body.index("DIMPostInstallCompleted := True"), body.index("DIMWriteSuccessfulNativeCompletion();"))

    def test_inno_pins_exact_owned_stage_and_hash(self):
        body = INNO.split("function InitializeSetup(): Boolean;", 1)[1].split("procedure DIMWriteSuccessfulNativeCompletion", 1)[0]
        for term in ('/DIMTXN=', '/DIMSHA256=', "HaveTxn <> HaveSHA", "DIMIsHex64(DIMTransactionId)",
                     "DIMIsHex64(DIMExpectedInstallerSHA)", "PathSame(ExpandConstant('{srcexe}'), ExpectedStage)",
                     "DirectInternetMethod-update-stage.exe"):
            self.assertIn(term, body)
        completion = INNO.split("procedure DIMWriteSuccessfulNativeCompletion();", 1)[1].split("function RunSc", 1)[0]
        for term in ("GetSHA256OfFile(ExpandConstant('{srcexe}'))", "ObservedSHA <> DIMExpectedInstallerSHA",
                     "FileExists(ReceiptPath) or FileExists(TempPath)",
                     "SaveStringToFile(TempPath", "RenameFile(TempPath, ReceiptPath)",
                     "DIMUpdateReceiptCompleted := True"):
            self.assertIn(term, completion)
        self.assertLess(completion.index("RenameFile(TempPath, ReceiptPath)"),
                        completion.index("DIMUpdateReceiptCompleted := True"))

    def test_service_receipt_binds_protected_nonce_and_hash_before_cleanup(self):
        final = PROGRAM.split("static void FinalizePendingUpdate()", 1)[1].split("static async Task RunActionAsync(", 1)[0]
        self.assertIn('GetProperty("schema").GetInt32() != 2', final)
        self.assertIn('GetProperty("transactionId")', final)
        self.assertIn('NativeInnoCompletionReceipt.Matches(', final)
        self.assertIn("FileAttributes.ReparsePoint", final)
        self.assertIn("pending-update-awaiting-inno-ssdone-completion-receipt", final)
        receipt = final.index("NativeInnoCompletionReceipt.Matches(")
        for marker in ("File.Delete(stage)", "File.Delete(PendingUpdatePath)", 'WriteActionStatus("update", "done"'):
            self.assertLess(receipt, final.index(marker))
        self.assertLess(final.index("File.Delete(stage)"), final.index("File.Delete(PendingUpdatePath)"))
        self.assertLess(final.index("File.Delete(PendingUpdatePath)"), final.index("File.Delete(receiptPath)"))

    def test_orphan_receipts_block_future_updater(self):
        update = PROGRAM.split("static async Task RunUpdateAsync()", 1)[1].split("static bool PendingNativeRegistrationMatches(", 1)[0]
        self.assertIn('Directory.EnumerateFiles(UpdatesDir, "completion-*.receipt")', update)
        self.assertIn("Orphan native completion evidence requires reconciliation", update)
        self.assertLess(update.index("completion-*.receipt"), update.index("GetLatestUpdateAsync("))

    def test_exit_nonzero_if_update_receipt_not_written(self):
        body = INNO.split("function GetCustomSetupExitCode: Integer;", 1)[1].split("function InitializeUninstall", 1)[0]
        self.assertIn("DIMPostInstallCompleted", body)
        self.assertIn("DIMUpdateReceiptExpected) or DIMUpdateReceiptCompleted", body)
        self.assertIn("Result := 67;", body)

    def test_native_validator_requires_exact_payload_and_negative_cases(self):
        for term in ("DIM-INNO-V1|", "value.All(Uri.IsHexDigit)", "string.Equals(content, expected, StringComparison.Ordinal)",
                     "!Matches(good, other, sha)", "!Matches(good, txn, other)",
                     '!Matches(good + "\\n", txn, sha)',
                     'FileName(txn.ToLowerInvariant())'):
            self.assertIn(term, HELPER)
        self.assertIn("NativeInnoCompletionReceipt.SelfTest()", PROGRAM)


if __name__ == "__main__":
    unittest.main()
