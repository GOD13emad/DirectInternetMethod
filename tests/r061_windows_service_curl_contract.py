#!/usr/bin/env python3
"""R061 no-execution Windows service curl provenance contract, with negative fixtures."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "windows" / "service" / "Program.cs"


def service_method(text):
    match = re.search(
        r"static async Task DownloadWithSystemCurlAsync\b[\s\S]*?(?=\n    static async Task RunUpdateAsync\b)",
        text,
    )
    if not match:
        raise AssertionError("R061_DOWNLOAD_METHOD_NOT_FOUND")
    return match.group(0)


def require_contract(text):
    method = service_method(text)
    required = (
        "Environment.SystemDirectory",
        "string.IsNullOrWhiteSpace(systemFolder)",
        "Path.IsPathFullyQualified(systemFolder)",
        'Path.GetFullPath(Path.Combine(systemFolder, "curl.exe"))',
        "if (!File.Exists(curl))",
        "new ProcessStartInfo(curl)",
        "UseShellExecute = false",
        "psi.ArgumentList.Add(arg)",
        "using var p = Process.Start(psi)",
        "await p.WaitForExitAsync(ct)",
    )
    for fragment in required:
        if fragment not in method:
            raise AssertionError("R061_MISSING_" + fragment)
    forbidden = (
        "Environment.GetFolderPath(",
        "Environment.GetEnvironmentVariable(",
        'new ProcessStartInfo("curl.exe")',
        "UseShellExecute = true",
        "psi.Arguments =",
        'Process.Start("curl.exe"',
    )
    for fragment in forbidden:
        if fragment in method:
            raise AssertionError("R061_UNSAFE_" + fragment)
    if method.index("Path.IsPathFullyQualified(systemFolder)") > method.index("new ProcessStartInfo(curl)"):
        raise AssertionError("R061_GUARD_AFTER_PROCESS_PLAN")
    if method.index("if (!File.Exists(curl))") > method.index("new ProcessStartInfo(curl)"):
        raise AssertionError("R061_EXISTENCE_AFTER_PROCESS_PLAN")
    return True


class TestSystemCurlProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = SOURCE.read_text(encoding="utf-8")

    def test_valid_service_source(self):
        self.assertTrue(require_contract(self.src))

    def test_fail_closed_to_old_special_folder_lookup(self):
        text = self.src.replace(
            "Environment.SystemDirectory",
            "Environment.GetFolderPath(Environment.SpecialFolder.System)",
        )
        with self.assertRaises(AssertionError):
            require_contract(text)

    def test_fail_closed_to_path_lookup(self):
        text = self.src.replace("Environment.SystemDirectory", 'Environment.GetEnvironmentVariable("PATH")')
        with self.assertRaises(AssertionError):
            require_contract(text)

    def test_fail_closed_if_absolute_path_guard_removed(self):
        text = self.src.replace("!Path.IsPathFullyQualified(systemFolder)", "false")
        with self.assertRaises(AssertionError):
            require_contract(text)

    def test_fail_closed_if_process_shell_enabled(self):
        method = service_method(self.src).replace("UseShellExecute = false", "UseShellExecute = true")
        with self.assertRaises(AssertionError):
            require_contract(self.src.replace(service_method(self.src), method))

    def test_fail_closed_to_non_tokenized_arguments(self):
        method = service_method(self.src).replace("psi.ArgumentList.Add(arg)", "psi.Arguments = arg")
        with self.assertRaises(AssertionError):
            require_contract(self.src.replace(service_method(self.src), method))

    def test_fail_closed_to_bare_executable(self):
        method = service_method(self.src).replace("new ProcessStartInfo(curl)", 'new ProcessStartInfo("curl.exe")')
        with self.assertRaises(AssertionError):
            require_contract(self.src.replace(service_method(self.src), method))

    def test_checksum_still_verified_before_installer_execution(self):
        source = self.src
        self.assertIn("await Sha256FileAsync(partPath, timeout.Token)", source)
        self.assertIn("actual.Equals(expected, StringComparison.OrdinalIgnoreCase)", source)
        self.assertIn("var psi = new ProcessStartInfo(finalPath)", source)
        self.assertLess(
            source.index("await Sha256FileAsync(partPath, timeout.Token)"),
            source.index("var psi = new ProcessStartInfo(finalPath)"),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
