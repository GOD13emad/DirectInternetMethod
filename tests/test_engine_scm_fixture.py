"""Reproducible, disposable Windows SCM service fixture source contracts.

No native service is registered from unit tests. A real SCM lifecycle must
be exercised separately in a network-isolated Windows Sandbox, never host.
"""
from __future__ import annotations

from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1] / "tools/native_fixtures/windows"
SOURCE = ROOT / "ScmFixtureService.cs"
GUEST = ROOT / "RunScmSandboxFixture.ps1"
FIXTURE_NAME = "DIMR887IsolatedFixtureSvc"


class NativeScmFixtureTests(unittest.TestCase):
    def test_identity_is_not_real_dim_service(self):
        src = SOURCE.read_text("utf-8")
        guest = GUEST.read_text("utf-8")
        self.assertIn('internal const string ServiceName = "' + FIXTURE_NAME + '"', src)
        self.assertIn("$Name = '" + FIXTURE_NAME + "'", guest)
        executable_guest = "\n".join(line for line in guest.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn("DirectInternetMethodSvc", src + executable_guest)
        self.assertNotIn("sc.exe config DirectInternetMethod", src + guest)
        self.assertNotIn("Get-Service -Name 'DirectInternetMethodSvc'", guest)

    def test_guest_script_is_pin_checked_and_fails_closed(self):
        guest = GUEST.read_text("utf-8")
        for term in ("PIN_156_WRONG", "PIN_157_WRONG",
                     "INVALID_BINARY_UNEXPECTEDLY_STARTED",
                     "ROLLBACK_TO_156_AND_RESTART",
                     "NATIVE_SCM_UNREGISTERED",
                     "OWNER_DATA_CHANGED",
                     "product_native_installation_accepted=$false"):
            self.assertIn(term, guest)
        self.assertIn("function Invoke-ScFixture", guest)
        self.assertNotRegex(guest, r"(?m)^\s*Sc @\(")
        self.assertNotIn("Restart-Computer", guest)

    @unittest.skipUnless(os.name == "nt", "native Framework csc only on Windows")
    def test_native_framework_fixture_has_two_distinct_versions(self):
        csc = Path(os.environ.get("WINDIR", r"C:\Windows")) / (
            "Microsoft.NET/Framework64/v4.0.30319/csc.exe")
        if not csc.exists():
            self.skipTest("native .NET Framework compiler not available")
        with tempfile.TemporaryDirectory(prefix="dim-scm-compiler-") as temp:
            results = []
            for label, define in (("1.5.6", None),
                                  ("1.5.7", "VERSION_157")):
                output = Path(temp) / (label + ".exe")
                cmd = [str(csc), "/nologo", "/target:exe", "/platform:x64",
                       "/r:System.ServiceProcess.dll", "/out:" + str(output)]
                if define:
                    cmd.append("/define:" + define)
                cmd.append(str(SOURCE))
                built = subprocess.run(cmd, capture_output=True, text=True,
                                       timeout=30)
                self.assertEqual(built.returncode, 0, built.stderr)
                ran = subprocess.run([str(output), "--version"],
                                     capture_output=True, text=True, timeout=15)
                self.assertEqual(ran.returncode, 0, ran.stderr)
                self.assertEqual(ran.stdout.strip(), label)
                results.append(output.read_bytes())
            self.assertNotEqual(results[0], results[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
