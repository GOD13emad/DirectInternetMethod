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

namespace DirectInternetMethod.Service;

internal static class NativeJournalProbe
{
    private static void Need(bool ok, string label)
    {
        if (!ok) throw new Exception(label);
    }

    public static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows() || args.Length != 1)
            return 91;
        var dir = Path.Combine(Path.GetFullPath(args[0]), "UpdateTransactions");
        Directory.CreateDirectory(dir);
        var pending = Path.Combine(dir, "pending-update.json");
        var temp = pending + ".tmp";
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
        return 0;
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
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("R978_REAL_WIN32_WRITE_THROUGH_PENDING_JOURNAL_PASS_NO_PRODUCT",
                          run.stdout)


if __name__ == "__main__":
    unittest.main()