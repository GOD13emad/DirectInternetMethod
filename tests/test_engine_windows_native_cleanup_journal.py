"""R922 protected post-ssDone cleanup journal / process interruption contract.

Source-level ordering checks only; native selftest of the journal is run
separately in the built Windows Service. Power-failure rollback is NOT asserted.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROGRAM = (ROOT / "windows/service/Program.cs").read_text(encoding="utf-8-sig")
JOURNAL = (ROOT / "windows/service/NativeUpdateCleanupJournal.cs").read_text(encoding="utf-8-sig")


class NativeUpdateRestartJournalContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.final = PROGRAM.split("static void FinalizePendingUpdate()", 1)[1].split(
            "static async Task RunActionAsync(", 1
        )[0]
        cls.update = PROGRAM.split("static async Task RunUpdateAsync()", 1)[1].split(
            "static bool PendingNativeRegistrationMatches(", 1
        )[0]

    def test_native_pending_still_schema2_with_real_nonce_and_native_receipt(self):
        self.assertIn("schema = 2,", self.update)
        self.assertIn("RandomNumberGenerator.GetBytes(32)", self.update)
        self.assertIn('psi.ArgumentList.Add("/DIMTXN=" + transactionId)', self.update)
        self.assertIn('psi.ArgumentList.Add("/DIMSHA256=" + actual)', self.update)
        self.assertIn("NativeInnoCompletionReceipt.Matches(", self.final)

    def test_phase_is_trusted_only_from_protected_pending(self):
        f = self.final
        self.assertLess(f.index("!NativeProtectedUpdateAcl.IsProtectedExistingDirectory(UpdatesDir)"),
                        f.index("NativeUpdateCleanupJournal.IsReceiptConsumed(doc.RootElement)"))
        self.assertIn("if (!File.Exists(receiptPath) && !cleanupCommitted)", f)
        self.assertIn("if (File.Exists(receiptPath) &&", f)
        self.assertIn("NativeInnoCompletionReceipt.Matches(", f)
        self.assertIn("NativeUpdateCleanupJournal.RequireSafeStageAfterCommit(cleanupCommitted, File.Exists(stage))", f)
        self.assertIn("Unknown protected update cleanup phase", JOURNAL)
        self.assertNotIn("File.Delete(LegacyPendingUpdatePath)", PROGRAM)

    def test_cleanup_commit_after_receipt_and_stage_validation(self):
        f = self.final
        verify = f.index("NativeInnoCompletionReceipt.Matches(")
        stage_pin = f.index("observed.Equals(expectedSha, StringComparison.OrdinalIgnoreCase)")
        stage_delete = f.index("File.Delete(stage)")
        commit = f.index("NativeUpdateCleanupJournal.MarkReceiptConsumed(")
        receipt_delete = f.index("File.Delete(receiptPath)")
        pending_delete = f.index("File.Delete(PendingUpdatePath)")
        done = f.index('WriteActionStatus("update", "done", 0,')
        self.assertLess(verify, stage_pin)
        self.assertLess(stage_pin, stage_delete)
        self.assertLess(stage_delete, commit)
        self.assertLess(commit, receipt_delete)
        self.assertLess(receipt_delete, pending_delete)
        self.assertLess(pending_delete, done)

    def test_committed_phase_recovers_missing_receipt_but_refuses_present_stage(self):
        f = self.final
        self.assertIn("if (!File.Exists(receiptPath) && !cleanupCommitted)", f)
        self.assertIn("NativeUpdateCleanupJournal.RequireSafeStageAfterCommit(cleanupCommitted, File.Exists(stage))", f)
        self.assertIn("if (!cleanupCommitted)", f)
        self.assertIn("WriteJsonAtomic(PendingUpdatePath,", f)
        self.assertIn("File.Delete(PendingUpdatePath)", f)
        self.assertIn("Orphan native completion evidence requires reconciliation", self.update)

    def test_unknown_pending_cleanup_phase_fails_closed(self):
        for term in ('internal const string Consumed = "receipt-consumed";',
                     "phase.ValueKind != JsonValueKind.String",
                     "throw new InvalidDataException",
                     'record["cleanupPhase"] = Consumed;',
                     "pending.GetRawText()",
                     "JsonNode.Parse"):
            self.assertIn(term, JOURNAL)
        for invalid in ('unverified', 'receipt-consumed ', 'null', 'true'):
            self.assertIn(invalid, JOURNAL)

    def test_native_selftest_is_required(self):
        self.assertIn("NativeUpdateCleanupJournal.SelfTest()", PROGRAM)
        self.assertIn("NATIVE_UPDATE_CLEANUP_JOURNAL_SELFTEST_FAILED", PROGRAM)
        self.assertIn("using var committed = JsonDocument.Parse(consumed.ToJsonString());", JOURNAL)

    def test_no_claim_of_durable_powerloss_or_auto_rollback(self):
        self.assertIn("NOT a power-cut durability or automatic rollback guarantee", JOURNAL)


if __name__ == "__main__":
    unittest.main()
