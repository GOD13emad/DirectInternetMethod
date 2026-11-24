"""R914 Windows privileged-only update transaction storage preflight.

Cross-platform tests verify source invariants. Actual Windows ACL behavior is
tested separately with native .NET SDK 10.0.403 and owner-host read-only ACLs.
No live ACLs, services or installer state may be changed by these tests.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "windows" / "service" / "NativeProtectedUpdateAcl.cs"
PROGRAM = ROOT / "windows" / "service" / "Program.cs"


class ProtectedUpdateAclContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = POLICY.read_text(encoding="utf-8-sig")
        cls.program = PROGRAM.read_text(encoding="utf-8-sig")

    def test_non_privileged_write_aces_fail_closed(self):
        source = self.policy
        for required in (
            "GetAccessRules(true, true, typeof(SecurityIdentifier))",
            "rule.AccessControlType != AccessControlType.Allow",
            "(rule.FileSystemRights & DangerousWriteRights) == 0",
            "!TrustedWriterSid(sid.Value)",
            "FileSystemRights.WriteData",
            "FileSystemRights.AppendData",
            "FileSystemRights.DeleteSubdirectoriesAndFiles",
            "FileSystemRights.ChangePermissions",
            "FileSystemRights.TakeOwnership",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)

    def test_path_is_restricted_to_actual_protected_program_files_install(self):
        p = self.policy
        for check in (
            "Environment.SpecialFolder.ProgramFiles",
            '"DirectInternetMethod"',
            '"Privileged"',
            '"app"',
            "StringComparison.OrdinalIgnoreCase",
            "FileAttributes.ReparsePoint",
            "IsProtectedExistingDirectory(candidate)",
            "Path.Combine(root, \"UpdateTransactions\")",
        ):
            with self.subTest(check=check):
                self.assertIn(check, p)

    def test_no_acl_privilege_bypass_or_user_root_acceptance(self):
        p = self.policy
        for forbidden in (
            "SetAccessControl(",
            "SeTakeOwnershipPrivilege",
            "SetNamedSecurityInfo",
            "TokenElevation",
            "BypassSecurity",
            "AppData\\DirectInternetMethod\\updates",
        ):
            self.assertNotIn(forbidden, p)

    def test_native_selftest_requires_safe_and_two_negative_descriptors(self):
        p = self.policy
        self.assertIn("!IsProtectedDescriptor(userWritable)", p)
        self.assertIn("!IsProtectedDescriptor(userOwned)", p)
        self.assertIn("IsProtectedDescriptor(safe)", p)
        self.assertIn("NativeProtectedUpdateAcl.SyntheticPolicySelfTest()", self.program)
        self.assertIn('"PROTECTED_UPDATE_ACL_SELFTEST_FAILED"', self.program)


if __name__ == "__main__":
    unittest.main()
