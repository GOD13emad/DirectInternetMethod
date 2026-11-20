#!/usr/bin/env python3
"""R850 native installed manifest hardening in both historic baseline paths."""
from pathlib import Path
import unittest
R=Path(__file__).resolve().parents[1]
PROBE=(R/"tests/r850_windows_privileged_manifest_attestation.ps1").read_text()
WF=(R/".github/workflows/ci.yml").read_text()
class Contract(unittest.TestCase):
 def test_strict_exact_manifest_and_protected_file_sha(self):
  for s in ("Get-FileHash","SHA256","ExpectedManifestSha256","FILE_REPARSE","PATH_ESCAPE",
            "PRIVILEGED_SHA_MISMATCH","PRIVILEGED_COUNT","DUPLICATE_SCOPE_FILE",
            "ExpectedManagedFiles=681","ExpectedPrivilegedFiles=674"):
   self.assertIn(s,PROBE)
 def test_exact_native_hosted_v154_and_v156_forward_suites(self):
  for file in ("tests/r846_windows_native_rollback.ps1","tests/r848_windows_private156_forward_native.ps1"):
   x=(R/file).read_text()
   self.assertIn("R850_INSTALLED_PRIVILEGED_674_SHA_MATCH",x)
   self.assertIn("r850_windows_privileged_manifest_attestation.ps1",x)
   self.assertIn("-ExpectedVersion '1.5.7'",x)
   self.assertIn("-ExpectedManifestSha256 $build.manifestSha",x)
 def test_one_time_private_source_prevent_repeated_artifact_use(self):
  self.assertIn("r850-hosted-integrity-once",WF)
  self.assertIn("github.repository == 'GOD13emad/DirectInternetMethod'",WF)
  self.assertIn("windows-private-r846-native:",WF)
  self.assertIn("windows-private-r848-v156-forward:",WF)
 def test_attestation_read_only(self):
  for s in ("Set-Content","WriteAllText","Copy-Item","Remove-Item","Start-Process","Invoke-WebRequest","pkexec"):
   self.assertNotIn(s,PROBE)
if __name__=="__main__":
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Contract))
 raise SystemExit(0 if result.wasSuccessful() else 1)
