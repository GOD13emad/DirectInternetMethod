"""R931 exact restoration receipt OS-ACL fixture static/scope regression.

Host tests inspect and parse only. Native impersonation/ACL is accepted
ONLY by a separate command executed in a freshly isolated Windows Sandbox.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import unittest

from installer_engine.engine import EngineError
from installer_engine.native_receipt import (
    intent_sha256, verify_completion_receipt,
    verify_restoration_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT/"tools/native_fixtures/windows/RestrictedNativeReceiptProbe.cs"
RUNNER = ROOT/"tools/native_fixtures/windows/RunRestrictedNativeReceiptSandboxFixture.ps1"
BUILDER = ROOT/"tools/native_fixtures/windows/BuildRestrictedNativeReceiptInputs.py"


class ProtectedNativeReceiptContract(unittest.TestCase):
    def test_builder_python_syntax(self):
        ast.parse(BUILDER.read_text("utf8"), filename=str(BUILDER))

    def test_windows_native_restricted_token_is_not_a_mock_role(self):
        source = NATIVE.read_text("utf8")
        for required in (
            "CreateRestrictedToken(", "IsTokenRestricted(",
            "ImpersonateLoggedOnUser(", "RevertToSelf()",
            "BuiltinAdministratorsSid", "BuiltinUsersSid",
            "File.WriteAllText(receipt,", "File.AppendAllText(receipt,",
            "File.Delete(receipt)", "File.Move(receipt, moved)",
            "File.WriteAllText(other,", "userFile, \"UNPRIVILEGED_FORGED_RECEIPT_ONLY\"",
            "protected_receipt_intact", "trusted_broker_implemented",
            "DIM_R931_SyntheticReceiptCustody", "C:\\DIMR931\\user",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        self.assertNotIn("DirectInternetMethodSvc", source)
        self.assertNotIn("SeTakeOwnershipPrivilege", source)
        self.assertNotIn("AdjustTokenPrivileges", source)

    def test_guest_acl_setup_is_system_only_nonproduct_and_reported(self):
        source = RUNNER.read_text("utf8")
        for required in (
            "S-1-5-18", "WDAGUtilityAccount",
            "DIM_R931_SyntheticReceiptCustody", "C:\\DIMR931\\input",
            "C:\\DIMR931\\output", "'/inheritance:r'",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "*S-1-5-32-545:(OI)(CI)M",
            "restricted_token_observed=$true",
            "trusted_native_receipt_mint_accepted=$false",
            "native_product_installation_accepted=$false",
            "host_reboot_accepted=$false",
            "R931_OS_RESTRICTED_NATIVE_RECEIPT_CUSTODY_ONLY",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        self.assertNotIn("DirectInternetMethodSvc", source)
        self.assertNotIn("sc.exe", source)
        self.assertNotIn("Tailscale", source)
        self.assertNotIn("netsh ", source)
        self.assertNotIn("route.exe", source)
        self.assertNotIn("sudo ", source)

    def test_build_pins_actual_shared_restoration_receipt_contract(self):
        source = BUILDER.read_text("utf8")
        self.assertIn("verify_restoration_receipt(intent, data)", source)
        self.assertIn("intent_sha256(intent)", source)
        self.assertIn("receipt_sha256", source)
        self.assertIn("probe_sha256", source)
        self.assertIn("R931_REFUSE_OVERWRITE_OR_REUSE", source)
        self.assertIn("R931_NEW_DIRECT_OS_TEMP_FIXTURE_REQUIRED", source)

    def test_stale_or_completed_synthetic_receipt_fails_shared_core(self):
        intent = {"schema": 1, "request_id": "d"*32,
                  "platform": "windows-x86_64", "operation": "upgrade",
                  "old": "1.5.6", "new": "1.5.7",
                  "preimage_sha256": hashlib.sha256(b"previous").hexdigest(),
                  "scope_pins": [
                      {"name": "code", "manifest_sha256": hashlib.sha256(b"a").hexdigest()},
                      {"name": "user", "manifest_sha256": hashlib.sha256(b"b").hexdigest()},
                  ]}
        receipt = json.dumps({
            "schema": 1, "status": "restored",
            "intent_sha256": intent_sha256(intent),
        }, sort_keys=True).encode()
        self.assertTrue(verify_restoration_receipt(intent, receipt))
        with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_SCHEMA_INVALID"):
            verify_completion_receipt(intent, receipt)
        invalid = dict(intent, request_id="e"*32)
        with self.assertRaisesRegex(EngineError, "NATIVE_RECEIPT_INTENT_MISMATCH"):
            verify_restoration_receipt(invalid, receipt)


if __name__ == "__main__":
    unittest.main()
