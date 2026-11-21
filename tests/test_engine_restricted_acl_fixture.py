"""R896 native Windows restricted-token ACL fixture source and compile contract.

No test executes this probe on an installed host. Live integration runs in
an offline ephemeral Windows Sandbox with a unique non-product path identity.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
CS=ROOT/"tools/native_fixtures/windows/RestrictedBoundaryProbe.cs"
PS=ROOT/"tools/native_fixtures/windows/RunRestrictedBoundarySandboxFixture.ps1"


class RestrictedBoundaryFixtureTests(unittest.TestCase):
    def test_native_token_path_is_actually_restricted_and_impersonated(self):
        src=CS.read_text("utf-8")
        for word in ("CreateRestrictedToken(", "IsTokenRestricted(",
                     "ImpersonateLoggedOnUser(", "RevertToSelf()",
                     "BuiltinAdministratorsSid", "BuiltinUsersSid",
                     'Need(isRestricted, "TOKEN_NOT_RESTRICTED")'):
            self.assertIn(word,src)
        self.assertIn("protected_write_denied",src)
        self.assertIn("user_write_allowed",src)
        self.assertNotIn("DirectInternetMethodSvc",src)
        self.assertNotIn("Tailscale",src)

    def test_guest_paths_and_fail_closed_output_distinct(self):
        src=PS.read_text("utf-8")
        for phrase in ("C:\\DIMR896\\input", "C:\\DIMR896\\output",
                       "DIM_R896_ProtectedACL","DIM_R896_UserACL",
                       "PASS_R896_ISOLATED_RESTRICTED_TOKEN_ACL",
                       "FAIL_CLOSED_R896_RESTRICTED_TOKEN_ACL",
                       "production_privilege_boundary_accepted=$false",
                       "native_product_installation_accepted=$false",
                       "publisher_authenticated=$false"):
            self.assertIn(phrase,src)
        self.assertNotIn("DirectInternetMethodSvc",src)
        self.assertNotIn("sc.exe",src)
        self.assertNotIn("systemctl",src)
        self.assertNotIn("cmd.exe /c",src)

    def test_protected_root_has_no_builtin_users_write(self):
        src=PS.read_text("utf-8")
        line=next(x for x in src.splitlines()
                  if x.strip().startswith("Acl @($Protected,'/grant:r'"))
        self.assertIn("*S-1-5-32-544:(OI)(CI)F",line)
        self.assertNotIn("*S-1-5-32-545",line)
        self.assertIn("*S-1-5-32-545:(OI)(CI)M",src)
        self.assertIn("'/inheritance:r'",src)

    def test_automatic_powershell_args_collision_absent(self):
        src=PS.read_text("utf-8")
        self.assertNotIn("function Acl([string[]]$Args)",src)
        self.assertIn("function Acl([string[]]$AclArguments)",src)
        self.assertIn("@AclArguments",src)

    @unittest.skipUnless(os.name=="nt", "Windows-native test compiler only")
    def test_compiles_to_an_offline_fixture_not_owner_host_execution(self):
        compiler=Path("C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe")
        if not compiler.is_file():
            self.skipTest("C# Framework compiler not available")
        with tempfile.TemporaryDirectory(prefix="dim-r896-compile-") as d:
            dest=Path(d)/"SyntheticRestrictedBoundaryProbe.exe"
            process=subprocess.run(
                [str(compiler),"/nologo","/target:exe","/platform:x64",
                 "/out:"+str(dest),str(CS)],
                capture_output=True,text=True,timeout=15)
            self.assertEqual(process.returncode,0,process.stderr)
            self.assertTrue(dest.is_file())
            self.assertGreater(dest.stat().st_size,1000)


if __name__=="__main__":
    unittest.main()
