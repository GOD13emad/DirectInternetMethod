"""R977 actual production C# Inno receipt helper, one pinned Win32 file handle.

Does not start SCM/Inno, install software, elevate privileges, or grant
native acceptance. Uses a fresh user-owned test directory, then cleans it.
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
HELPER = ROOT / "windows/service/NativeInnoCompletionReceipt.cs"

PROBE = r"""
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace DirectInternetMethod.Service;

internal static class HeldProbe
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLinkW(
        string newFileName, string existingFileName, IntPtr security);

    private static void Need(bool condition, string label)
    {
        if (!condition) throw new InvalidOperationException(label);
    }

    private static void Denied(Action candidate, string label)
    {
        try { candidate(); }
        catch (InvalidDataException) { return; }
        catch (IOException) { return; }
        throw new InvalidOperationException("R977_FALSE_ACCEPT_" + label);
    }

    public static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows() || args.Length != 1)
            return 90;
        var root = Path.GetFullPath(args[0]);
        var id = "ABCD1234" + new string('0', 56);
        var sha = "0123456789ABCDEF" + new string('A', 48);
        var value = "DIM-INNO-V1|" + id + "|" + sha;
        var receipt = Path.Combine(root,
            NativeInnoCompletionReceipt.FileName(id));
        Need(value.Length == 141, "R977_WRONG_RECEIPT_TEST_LENGTH");
        File.WriteAllText(receipt, value, new UTF8Encoding(false));
        Need(NativeInnoCompletionReceipt.Matches(
            NativeInnoCompletionReceipt.ReadHeldExact(receipt, id), id, sha),
            "R977_GOOD_HELD_RECEIPT_REJECTED");
        Denied(() => NativeInnoCompletionReceipt.ReadHeldExact(
            receipt, "F" + id[1..]), "wrong-transaction-id");
        Denied(() => NativeInnoCompletionReceipt.ReadHeldExact(
            Path.Combine(root, "..", Path.GetFileName(receipt)), id),
            "noncanonical-path");
        File.AppendAllText(receipt, "\n");
        Denied(() => NativeInnoCompletionReceipt.ReadHeldExact(receipt, id),
            "wrong-size");
        File.WriteAllText(receipt, new string('X', 141),
            new UTF8Encoding(false));
        Need(!NativeInnoCompletionReceipt.Matches(
            NativeInnoCompletionReceipt.ReadHeldExact(receipt, id), id, sha),
            "R977_WRONG_BYTES_ACCEPTED");
        File.WriteAllText(receipt, value, new UTF8Encoding(false));
        var hardlink = Path.Combine(root, "hardlink.txt");
        Need(CreateHardLinkW(hardlink, receipt, IntPtr.Zero),
            "R977_HARDLINK_TEST_SETUP_FAILED");
        Denied(() => NativeInnoCompletionReceipt.ReadHeldExact(receipt, id),
            "hardlink-count");
        File.Delete(hardlink);
        Need(NativeInnoCompletionReceipt.Matches(
            NativeInnoCompletionReceipt.ReadHeldExact(receipt, id), id, sha),
            "R977_HELD_REOPEN_AFTER_LINK_REMOVAL_FAILED");

        // Reparse attacks are tested if this Windows user has symlink creation
        // rights; restricted users still have mandatory hardlink/size tests.
        var target = Path.Combine(root, "target.txt");
        File.Move(receipt, target);
        bool symlink = false;
        try
        {
            File.CreateSymbolicLink(receipt, target);
            symlink = true;
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }
        if (symlink)
        {
            Denied(() => NativeInnoCompletionReceipt.ReadHeldExact(receipt, id),
                "symlink-reparse");
            File.Delete(receipt);
        }
        File.Move(target, receipt);
        Need(NativeInnoCompletionReceipt.Matches(
            NativeInnoCompletionReceipt.ReadHeldExact(receipt, id), id, sha),
            "R977_POST_SYMLINK_RECOVERY_FAILED");
        // R985: the actual production pending record must use the same
        // single-link no-follow native handle, with a bounded JSON size.
        var transactions = Path.Combine(root, "UpdateTransactions");
        Directory.CreateDirectory(transactions);
        var pending = Path.Combine(transactions, "pending-update.json");
        File.WriteAllText(pending, "{\"schema\":2,\"transactionId\":\"TEST\"}", new UTF8Encoding(false));
        using (var doc = NativeInnoCompletionReceipt.ReadHeldPendingJson(pending))
            Need(doc.RootElement.GetProperty("transactionId").GetString() == "TEST",
                 "R985_VALID_PENDING_DENIED");
        var pendingLink = Path.Combine(transactions, "pending-link.json");
        Need(CreateHardLinkW(pendingLink, pending, IntPtr.Zero), "R985_LINK_SETUP_FAILED");
        Denied(() => NativeInnoCompletionReceipt.ReadHeldPendingJson(pending).Dispose(),
               "pending-hardlink-count");
        File.Delete(pendingLink);
        using (var writer = new FileStream(pending, FileMode.Open, FileAccess.Write, FileShare.ReadWrite))
            Denied(() => NativeInnoCompletionReceipt.ReadHeldPendingJson(pending).Dispose(),
                   "pending-concurrent-writer");
        File.WriteAllText(pending, new string(' ', 65537));
        Denied(() => NativeInnoCompletionReceipt.ReadHeldPendingJson(pending).Dispose(),
               "pending-size-limit");
        File.WriteAllText(pending, "");
        Denied(() => NativeInnoCompletionReceipt.ReadHeldPendingJson(pending).Dispose(),
               "pending-empty");
        File.WriteAllText(pending, "{\"schema\":2}", new UTF8Encoding(false));
        Denied(() => NativeInnoCompletionReceipt.ReadHeldPendingJson(
            Path.Combine(transactions, "other.json")).Dispose(), "pending-wrong-leaf");
        using (var doc = NativeInnoCompletionReceipt.ReadHeldPendingJson(pending))
            Need(doc.RootElement.GetProperty("schema").GetInt32() == 2, "R985_PENDING_REOPEN_FAILED");
        Console.WriteLine("R985_REAL_NATIVE_WINDOWS_HELD_PENDING_PASS");
        Console.WriteLine("R977_REAL_NATIVE_WINDOWS_HELD_RECEIPT_PASS");
        return 0;
    }
}
"""


class NativeProductionHeldWin32Receipt(unittest.TestCase):
    def test_service_source_uses_held_receipt_instead_of_two_path_reads(self):
        code = (ROOT / "windows/service/Program.cs").read_text(encoding="utf-8-sig")
        part = code.split("static void FinalizePendingUpdate()", 1)[1].split(
            "static async Task RunActionAsync(", 1)[0]
        self.assertIn("NativeInnoCompletionReceipt.ReadHeldExact(", part)
        self.assertNotIn("File.ReadAllText(receiptPath)", part)

    def test_pending_and_transition_use_bounded_same_handle_reader(self):
        service = (ROOT / "windows/service/Program.cs").read_text("utf-8-sig")
        journal = (ROOT / "windows/service/NativeProtectedUpdateJournal.cs").read_text("utf-8-sig")
        self.assertIn("NativeInnoCompletionReceipt.ReadHeldPendingJson(PendingUpdatePath)", service)
        self.assertIn("NativeInnoCompletionReceipt.ReadHeldPendingJson(target)", journal)
        self.assertNotIn("File.ReadAllText(PendingUpdatePath)", service)
        self.assertNotIn("File.OpenRead(target)", journal)

    @unittest.skipUnless(os.name == "nt", "real Win32 handles require Windows")
    def test_actual_compiled_production_receipt_helper_native_win32(self):
        dotnet = shutil.which("dotnet")
        if not dotnet:
            if os.getenv("R977_REQUIRE_NATIVE") == "1":
                self.fail("R977_CI_MUST_HAVE_DOTNET")
            self.skipTest("no .NET SDK in this Windows test environment")
        sdk = subprocess.run([dotnet, "--list-sdks"],
                             text=True, capture_output=True, timeout=12,
                             check=True).stdout
        if not re.search(r"(?m)^10\.", sdk):
            if os.getenv("R977_REQUIRE_NATIVE") == "1":
                self.fail("R977_CI_MUST_HAVE_DOTNET10_SDK")
            self.skipTest("native .NET 10 SDK not installed")
        with tempfile.TemporaryDirectory(prefix="dim-r977-held-",
                                         dir=ROOT) as scratch:
            td = Path(scratch)
            csproj = td / "HeldInnoReceiptProbe.csproj"
            rel = escape(str(HELPER), {'"': "&quot;"})
            csproj.write_text(
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                '<OutputType>Exe</OutputType>'
                '<TargetFramework>net10.0-windows</TargetFramework>'
                '<Nullable>enable</Nullable>'
                '<EnableDefaultCompileItems>false</EnableDefaultCompileItems>'
                '</PropertyGroup><ItemGroup>'
                f'<Compile Include="{rel}" Link="NativeInnoCompletionReceipt.cs" />'
                '<Compile Include="HeldProbe.cs" />'
                '</ItemGroup></Project>',
                encoding="utf-8")
            (td / "HeldProbe.cs").write_text(PROBE, encoding="utf-8")
            built = subprocess.run(
                [dotnet, "build", str(csproj), "--configuration", "Release",
                 "--nologo", "--verbosity", "quiet", "-p:NuGetAudit=false"],
                text=True, capture_output=True, timeout=110)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            binary = td / "bin/Release/net10.0-windows/HeldInnoReceiptProbe.dll"
            self.assertTrue(binary.is_file())
            run = subprocess.run([dotnet, str(binary), scratch],
                                 text=True, capture_output=True, timeout=30)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("R977_REAL_NATIVE_WINDOWS_HELD_RECEIPT_PASS",
                          run.stdout)
            self.assertIn("R985_REAL_NATIVE_WINDOWS_HELD_PENDING_PASS", run.stdout)


if __name__ == "__main__":
    unittest.main()