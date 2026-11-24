"""R978: real production protected Windows pending-update journal, native disk API.

No installed software or service is touched. Windows .NET 10 test fixture
links the ACTUAL product class and uses a uniquely named owned temp folder.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "windows/service/Program.cs"
HELPER = ROOT / "windows/service/NativeProtectedUpdateJournal.cs"

PROBE = r"""
using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Runtime.InteropServices;

namespace DirectInternetMethod.Service;

internal static class NativeJournalProbe
{
    private static void Need(bool ok, string label)
    {
        if (!ok) throw new Exception(label);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(string newName, string oldName, IntPtr unused);

    private static void CheckRejected(Action call, string label)
    {
        try { call(); }
        catch (InvalidDataException) { return; }
        catch (IOException) { return; }
        throw new Exception(label);
    }

    public static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows() || args.Length < 1 || args.Length > 2)
            return 91;
        var dir = Path.Combine(Path.GetFullPath(args[0]), "UpdateTransactions");
        Directory.CreateDirectory(dir);
        var pending = Path.Combine(dir, "pending-update.json");
        var temp = pending + ".tmp";
        if (args.Length == 2)
        {
            Need(args[1] == "--resume-cleanup", "R979_UNKNOWN_PROBE_MODE");
            // This is an independent OS process. Reconstruct the expected
            // transition from the still-committed on-disk pending record.
            using var original = JsonDocument.Parse(File.ReadAllBytes(pending));
            var next = NativeUpdateCleanupJournal.MarkReceiptConsumed(original.RootElement);
            var exact = JsonSerializer.SerializeToUtf8Bytes(next);
            Need(File.Exists(temp), "R979_DURABLE_TEMP_MISSING_ON_RESTART");
            NativeProtectedUpdateJournal.CommitReceiptConsumed(pending, next);
            Need(!File.Exists(temp), "R979_RECOVERED_TEMP_NOT_RETIRED");
            Need(Convert.ToHexString(File.ReadAllBytes(pending)) == Convert.ToHexString(exact),
                 "R979_RECOVERED_COMMITTED_RECORD_MISMATCH");
            CheckRejected(() => NativeProtectedUpdateJournal.CommitReceiptConsumed(pending, next),
                          "R979_DOUBLE_COMMIT_ACCEPTED");
            Console.WriteLine("R979_REAL_WIN32_NEW_PROCESS_RECOVERED_EXACT_CLEANUP_ONLY");
            return 0;
        }
        NativeProtectedUpdateJournal.WriteJsonAtomic(pending,
            new { schema = 2, transactionId = "FIRST" });
        Need(!File.Exists(temp), "R978_TEMP_LEFT_AFTER_FIRST_WRITE");
        Need(JsonDocument.Parse(File.ReadAllBytes(pending)).RootElement
            .GetProperty("transactionId").GetString() == "FIRST",
            "R978_FIRST_WRITE_INVALID");
        NativeProtectedUpdateJournal.WriteJsonAtomic(pending,
            new { schema = 2, transactionId = "SECOND", cleanupPhase = "receipt-consumed" });
        Need(!File.Exists(temp), "R978_TEMP_LEFT_AFTER_REPLACE");
        var old = File.ReadAllBytes(pending);
        Need(JsonDocument.Parse(old).RootElement
            .GetProperty("cleanupPhase").GetString() == "receipt-consumed",
            "R978_COMMITTED_WRITE_MISSING");

        File.WriteAllText(temp, "R978_OWNED_STALE_TEMP_PRESERVE",
                          new UTF8Encoding(false));
        try
        {
            NativeProtectedUpdateJournal.WriteJsonAtomic(pending,
                new { schema = 2, transactionId = "UNSAFE_REPLAY" });
            throw new Exception("R978_STALE_TEMP_OVERWRITTEN");
        }
        catch (IOException) { }
        Need(File.ReadAllText(temp) == "R978_OWNED_STALE_TEMP_PRESERVE" &&
             Convert.ToHexString(File.ReadAllBytes(pending)) ==
             Convert.ToHexString(old), "R978_STALE_TEMP_OR_OLD_RECORD_CHANGED");
        File.Delete(temp);

        var unrelated = Path.Combine(dir, "other.json");
        try
        {
            NativeProtectedUpdateJournal.WriteJsonAtomic(unrelated,
                new { schema = 2 });
            throw new Exception("R978_UNRELATED_PATH_ACCEPTED");
        }
        catch (InvalidDataException) { }
        Need(!File.Exists(unrelated), "R978_FOREIGN_RECORD_WRITTEN");
        Console.WriteLine("R978_REAL_WIN32_WRITE_THROUGH_PENDING_JOURNAL_PASS_NO_PRODUCT");

        // Actual production writer fails its real Win32 rename while the old
        // pending file is open without delete sharing. No production fault
        // injection switch, no installed service or installer is involved.
        NativeProtectedUpdateJournal.WriteJsonAtomic(pending,
            new { schema = 2, transactionId = new string('A', 64),
                  sha256 = new string('B', 64), targetVersion = "1.5.7" });
        var baseline = File.ReadAllBytes(pending);
        using var prepared = JsonDocument.Parse(baseline);
        var consumed = NativeUpdateCleanupJournal.MarkReceiptConsumed(prepared.RootElement);
        var intended = JsonSerializer.SerializeToUtf8Bytes(consumed);
        using (var locked = new FileStream(pending, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            CheckRejected(() => NativeProtectedUpdateJournal.CommitReceiptConsumed(pending, consumed),
                          "R979_LOCKED_RENAME_UNEXPECTEDLY_SUCCEEDED");
        }
        Need(File.Exists(temp), "R979_INTERRUPTED_TEMP_MISSING");
        Need(Convert.ToHexString(File.ReadAllBytes(temp)) == Convert.ToHexString(intended),
             "R979_FLUSHED_TEMP_NOT_EXACT");
        Need(Convert.ToHexString(File.ReadAllBytes(pending)) == Convert.ToHexString(baseline),
             "R979_PREIMAGE_CHANGED_ON_RENAME_FAILURE");
        var altered = JsonNode.Parse(consumed.ToJsonString())!.AsObject();
        altered["transactionId"] = new string('C', 64);
        CheckRejected(() => NativeProtectedUpdateJournal.CommitReceiptConsumed(pending, altered),
                      "R979_WRONG_TRANSACTION_ACCEPTED");
        var wrong = (byte[])intended.Clone();
        wrong[0] = (byte)'!';
        File.WriteAllBytes(temp, wrong);
        CheckRejected(() => NativeProtectedUpdateJournal.CommitReceiptConsumed(pending, consumed),
                      "R979_TAMPERED_TEMP_ACCEPTED");
        Need(Convert.ToHexString(File.ReadAllBytes(temp)) == Convert.ToHexString(wrong),
             "R979_BAD_TEMP_OVERWRITTEN");
        File.WriteAllBytes(temp, intended);
        var alias = Path.Combine(dir, "hardlink.tmp");
        Need(CreateHardLinkW(alias, temp, IntPtr.Zero), "R979_HARDLINK_SETUP_FAILED");
        CheckRejected(() => NativeProtectedUpdateJournal.CommitReceiptConsumed(pending, consumed),
                      "R979_HARDLINK_TEMP_ACCEPTED");
        File.Delete(alias);
        Need(Convert.ToHexString(File.ReadAllBytes(pending)) == Convert.ToHexString(baseline),
             "R979_NEGATIVES_CHANGED_PREIMAGE");
        Need(Convert.ToHexString(File.ReadAllBytes(temp)) == Convert.ToHexString(intended),
             "R979_NEGATIVES_CHANGED_EXACT_TEMP");
        Console.WriteLine("R979_REAL_WIN32_RENAME_FAILURE_DURABLE_TEMP_PRESERVED");
        // Deliberately exit without cleanup, emulating process termination
        // after a failed native rename; the next invocation has no memory.
        return 78;
    }
}
"""


class NativeJournalDurabilityContract(unittest.TestCase):
    def test_real_service_uses_one_shared_protected_writer(self):
        program = SERVICE.read_text(encoding="utf-8-sig")
        segment = program.split("static void WriteJsonAtomic(string path, object payload)", 1)[1].split(
            "static string GetRegisteredInstallDirectory()", 1)[0]
        self.assertIn("NativeProtectedUpdateJournal.WriteJsonAtomic(path, payload);",
                      segment)
        self.assertNotIn("File.WriteAllText(temp", segment)
        self.assertNotIn("File.Move(temp, path, true)", segment)
        source = HELPER.read_text(encoding="utf-8-sig")
        for keyword in ("MOVEFILE_WRITE_THROUGH", "MOVEFILE_REPLACE_EXISTING",
                        "MoveFileExW", "FileOptions.WriteThrough",
                        "FileMode.CreateNew", "Flush(flushToDisk: true)"):
            self.assertIn(keyword, source)
        self.assertIn('pending-update.json', source)

    def test_r979_only_verified_cleanup_can_resume_exact_flushed_temp(self):
        program = SERVICE.read_text(encoding="utf-8-sig")
        final = program.split("static void FinalizePendingUpdate()", 1)[1].split(
            "static async Task RunActionAsync(", 1)[0]
        self.assertIn("NativeProtectedUpdateJournal.CommitReceiptConsumed(", final)
        self.assertLess(final.index("NativeInnoCompletionReceipt.Matches("),
                        final.index("NativeProtectedUpdateJournal.CommitReceiptConsumed("))
        self.assertLess(final.index("File.Delete(stage)"),
                        final.index("NativeProtectedUpdateJournal.CommitReceiptConsumed("))
        self.assertLess(final.index("NativeProtectedUpdateJournal.CommitReceiptConsumed("),
                        final.index("File.Delete(receiptPath)"))
        self.assertIn("VerifyAndFlushJournalTemp", HELPER.read_text(encoding="utf-8-sig"))
        update = program.split("static async Task RunUpdateAsync()", 1)[1]
        self.assertLess(update.index('File.Exists(PendingUpdatePath + ".tmp")'),
                        update.index("GetLatestUpdateAsync("))

    @unittest.skipUnless(os.name == "nt", "real Win32 file APIs require Windows")
    def test_actual_product_writer_win32_atomic_replace_and_stale_temp(self):
        dotnet = shutil.which("dotnet")
        if not dotnet:
            if os.environ.get("R978_REQUIRE_NATIVE") == "1":
                self.fail("R978_EXPECTED_DOTNET10_NATIVE_SDK_MISSING")
            self.skipTest("No .NET SDK")
        sdk = subprocess.run([dotnet, "--list-sdks"], capture_output=True,
                             text=True, timeout=12, check=True).stdout
        if not re.search(r"(?m)^10\.", sdk):
            if os.environ.get("R978_REQUIRE_NATIVE") == "1":
                self.fail("R978_EXPECTED_DOTNET10_NATIVE_SDK_MISSING")
            self.skipTest("No .NET 10 SDK")
        with tempfile.TemporaryDirectory(prefix="dim-r978-native-", dir=ROOT) as scratch:
            t = Path(scratch)
            project = t / "NativeJournalProbe.csproj"
            helper_path = escape(str(HELPER), {chr(34): "&quot;"})
            project.write_text(
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                '<TargetFramework>net10.0-windows</TargetFramework>'
                '<OutputType>Exe</OutputType><Nullable>enable</Nullable>'
                '<EnableDefaultCompileItems>false</EnableDefaultCompileItems>'
                '</PropertyGroup><ItemGroup>'
                f'<Compile Include="{helper_path}" '
                'Link="NativeProtectedUpdateJournal.cs"/>'
                f'<Compile Include="{escape(str(HELPER.with_name("NativeInnoCompletionReceipt.cs")))}"/>'
                f'<Compile Include="{escape(str(HELPER.with_name("NativeUpdateCleanupJournal.cs")))}"/>'
                '<Compile Include="NativeJournalProbe.cs"/>'
                '</ItemGroup></Project>', encoding="utf-8")
            (t / "NativeJournalProbe.cs").write_text(PROBE, encoding="utf-8")
            build = subprocess.run(
                [dotnet, "build", str(project), "-c", "Release", "--nologo",
                 "--verbosity", "quiet", "-p:NuGetAudit=false"],
                capture_output=True, text=True, timeout=100)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            dll = t / "bin/Release/net10.0-windows/NativeJournalProbe.dll"
            run = subprocess.run([dotnet, str(dll), str(t)],
                                 capture_output=True, text=True, timeout=30)
            self.assertEqual(run.returncode, 78, run.stdout + run.stderr)
            self.assertIn("R978_REAL_WIN32_WRITE_THROUGH_PENDING_JOURNAL_PASS_NO_PRODUCT",
                          run.stdout)
            self.assertIn("R979_REAL_WIN32_RENAME_FAILURE_DURABLE_TEMP_PRESERVED",
                          run.stdout)
            pending = t / "UpdateTransactions" / "pending-update.json"
            temp = pending.with_name(pending.name + ".tmp")
            self.assertTrue(temp.is_file())
            self.assertNotIn(b'"cleanupPhase"', pending.read_bytes())
            self.assertIn(b'"cleanupPhase":"receipt-consumed"', temp.read_bytes())
            resumed = subprocess.run(
                [dotnet, str(dll), str(t), "--resume-cleanup"],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
            self.assertIn("R979_REAL_WIN32_NEW_PROCESS_RECOVERED_EXACT_CLEANUP_ONLY",
                          resumed.stdout)
            self.assertFalse(temp.exists())
            self.assertIn(b'"cleanupPhase":"receipt-consumed"', pending.read_bytes())


if __name__ == "__main__":
    unittest.main()