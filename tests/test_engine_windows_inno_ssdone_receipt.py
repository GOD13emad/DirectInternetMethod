"""R918 native Inno ssDone protected, per-attempt completion contract.

Source-order checks only; paired actual Windows guest install/error injection is
a separate gate. No production updater/rollback acceptance from these tests.
"""
from pathlib import Path
import hashlib
import os
import tempfile
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

    def test_native_handoff_hash_rejected_before_install(self):
        init = INNO.split('function InitializeSetup(): Boolean;', 1)[1].split(
            'procedure DIMWriteSuccessfulNativeCompletion', 1)[0]
        marker = "if UpperCase(GetSHA256OfFile(ExpandConstant('{srcexe}'))) <> DIMExpectedInstallerSHA then"
        self.assertIn(marker, init)
        self.assertLess(init.index('ExpectedStage) then'), init.index(marker))
        self.assertLess(init.index(marker), init.index('DIMUpdateReceiptExpected := True;'))
        rejection = init.split(marker, 1)[1].split('DIMUpdateReceiptExpected := True;', 1)[0]
        self.assertIn("Log('DIM_UPDATE_SOURCE_SHA_MISMATCH_BEFORE_INSTALL');", rejection)
        self.assertIn('exit;', rejection)

    def test_inno_main_service_keeps_literal_quotes_in_scm_binary_path(self):
        body = INNO.split("procedure InstallOrUpdateService();", 1)[1].split(
            "function PrepareToInstall", 1)[0]
        argument = r'''binPath= "\"' + ServiceExe + '\""'''
        self.assertEqual(body.count(argument), 2)
        for action in ('create', 'config'):
            command = next(line for line in body.splitlines()
                           if "Params := '" + action + " " in line)
            self.assertIn(argument, command)
        self.assertNotIn('''binPath= "' + ServiceExe + '"''', body)

    def test_r977_production_service_reads_ssdone_through_one_os_held_handle(self):
        # Test the real production finalize path, not another fixture.
        final = PROGRAM.split("static void FinalizePendingUpdate()", 1)[1].split(
            "static async Task RunActionAsync(", 1)[0]
        self.assertIn("NativeInnoCompletionReceipt.ReadHeldExact(", final)
        self.assertNotIn("File.ReadAllText(receiptPath)", final)
        self.assertIn("NativeInnoCompletionReceipt.Matches(", final)
        self.assertLess(final.index("NativeInnoCompletionReceipt.ReadHeldExact("),
                        final.index("NativeUpdateCleanupJournal.MarkReceiptConsumed("))
        for marker in ("CreateFileW", "GetFileInformationByHandle",
                       "GetFinalPathNameByHandleW",
                       "FILE_FLAG_OPEN_REPARSE_POINT",
                       "FILE_SHARE_READ", "SafeFileHandle",
                       "ReadExactly", "FILE_ATTRIBUTE_REPARSE_POINT"):
            self.assertIn(marker, HELPER)
        self.assertNotIn("File.ReadAllText(", HELPER)

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
        self.assertLess(final.index("File.Delete(receiptPath)"), final.index("File.Delete(PendingUpdatePath)"))
        self.assertLess(final.index("NativeUpdateCleanupJournal.MarkReceiptConsumed("),
                        final.index("File.Delete(receiptPath)"))

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

    @unittest.skipUnless(os.name == "nt", "real Windows file handles required")
    def test_r972_common_id64_actual_win32_handle_read_cannot_grant_native_authority(self):
        from installer_engine.native_receipt import correlate_windows_inno_ssdone
        from tools.native_fixtures.windows.RunCommonInnoReceiptCorrelation import (
            correlate_existing_vm_receipt,
        )
        manifest = ROOT / "windows/manifest.json"
        pin = hashlib.sha256(manifest.read_bytes()).hexdigest()
        native_id = "ABCD1234" * 8
        installer_sha = "EEDD1234" * 8
        baseline_service_sha = "FFEE4567" * 8
        contents = ("DIM-INNO-V1|" + native_id + "|" + installer_sha).encode()
        with tempfile.TemporaryDirectory(prefix="dim-r972-real-handle-", dir=ROOT) as temp:
            observed = Path(temp) / ("completion-" + native_id + ".receipt")
            observed.write_bytes(contents)
            out = correlate_existing_vm_receipt(
                manifest, pin, observed, native_id,
                installer_sha, baseline_service_sha)
            self.assertEqual(out["status"],
                             "R972_REAL_INNO_RECEIPT_CORRELATION_READONLY_PASS")
            self.assertEqual(out["request_id"], native_id.lower())
            self.assertTrue(out["native_receipt_exact_handle_read"])
            self.assertEqual(out["source_scopes"], 2)
            self.assertFalse(out["native_preimage_complete"])
            self.assertFalse(out["os_authorized_common_broker"])
            self.assertFalse(out["native_installation_accepted"])
            self.assertFalse(out["publisher_authenticated"])
            observed.write_bytes(contents + b"\n")
            with self.assertRaisesRegex(Exception, "WIN32_HANDLE_SIZE_MISMATCH"):
                correlate_existing_vm_receipt(
                    manifest, pin, observed, native_id,
                    installer_sha, baseline_service_sha)
            observed.write_bytes(contents)
            with self.assertRaisesRegex(Exception, "R972_SOURCE_MANIFEST_SHA_DRIFT"):
                correlate_existing_vm_receipt(
                    manifest, "0" * 64, observed, native_id,
                    installer_sha, baseline_service_sha)

    def test_native_validator_requires_exact_payload_and_negative_cases(self):
        for term in ("DIM-INNO-V1|", "value.All(Uri.IsHexDigit)", "string.Equals(content, expected, StringComparison.Ordinal)",
                     "!Matches(good, other, sha)", "!Matches(good, txn, other)",
                     '!Matches(good + "\\n", txn, sha)',
                     'FileName(txn.ToLowerInvariant())'):
            self.assertIn(term, HELPER)
        self.assertIn("NativeInnoCompletionReceipt.SelfTest()", PROGRAM)


if __name__ == "__main__":
    unittest.main()
