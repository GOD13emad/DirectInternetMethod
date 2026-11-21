"""R891 synthetic Windows Sandbox two-scope SCM fixture source contracts.

No test in this module creates a Windows service. The complete native fixture
runs only in disposable offline Windows Sandbox with a separately pinned build.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from installer_engine.engine import read_package

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT/"tools/native_fixtures/windows/ScmTwoScopeFixtureEntry.py"
BUILDER = ROOT/"tools/native_fixtures/windows/BuildScmTwoScopePackages.py"
GUEST = ROOT/"tools/native_fixtures/windows/RunScmTwoScopeSandboxFixture.ps1"


class TwoScopeSCMFixtureTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="dim-r891-two-scope-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.old = self.base/"svc156.exe"
        self.new = self.base/"svc157.exe"
        self.old.write_bytes(b"SYNTHETIC_156_FOR_SCHEMA_ONLY")
        self.new.write_bytes(b"SYNTHETIC_157_FOR_SCHEMA_ONLY")
        self.target = self.base/"packages"

    def build(self, *, old_pin=None, destination=None):
        return subprocess.run([
            sys.executable, str(BUILDER),
            "--old", str(self.old), "--new", str(self.new),
            "--old-sha256", old_pin or hashlib.sha256(self.old.read_bytes()).hexdigest(),
            "--new-sha256", hashlib.sha256(self.new.read_bytes()).hexdigest(),
            "--output", str(destination or self.target),
        ], capture_output=True, text=True, timeout=20)

    def test_six_scope_packages_and_distinct_service_versions(self):
        out = self.build()
        self.assertEqual(out.returncode, 0, out.stderr)
        pins = json.loads((self.target/"pins.json").read_text())
        self.assertEqual(pins["scope"], "SYNTHETIC_R891")
        self.assertEqual(len(pins["manifest_sha256"]), 6)
        self.assertNotEqual(pins["manifest_sha256"]["code_157_bad"],
                            pins["manifest_sha256"]["code_1_5_7"])
        for key, digest in pins["manifest_sha256"].items():
            bundle = read_package(self.target/key, digest, "windows-x86_64")
            self.assertEqual(len(bundle["files"]), 1)
            self.assertEqual(bundle["version"],
                             "1.5.6" if key.endswith("1_5_6") else "1.5.7")

    def test_wrong_pin_cannot_write_distribution(self):
        out = self.build(old_pin="0"*64)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("FIXTURE_SOURCE_PIN_MISMATCH", out.stderr)
        self.assertFalse(self.target.exists())

    def test_existing_owner_destination_never_replaced(self):
        self.target.mkdir()
        foreign = self.target/"user.config"
        foreign.write_bytes(b"KEEP_FOREIGN")
        out = self.build()
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("FIXTURE_DESTINATION_ALREADY_EXISTS", out.stderr)
        self.assertEqual(foreign.read_bytes(), b"KEEP_FOREIGN")

    def test_guest_and_cli_do_not_target_product_service(self):
        entry = ENTRY.read_text("utf-8")
        guest = GUEST.read_text("utf-8")
        ast.parse(entry, filename=str(ENTRY))
        self.assertIn('SERVICE = "DIMR887IsolatedFixtureSvc"', entry)
        self.assertIn("DIM_R891_Isolated_Code", entry)
        self.assertIn("DIM_R891_Isolated_UserCode", entry)
        self.assertIn("windows_service_configuration(SERVICE)", entry)
        self.assertIn('pending = engine._pending()', entry)
        self.assertIn('validate_slot(engine.current, installed["manifest"])', entry)
        self.assertIn("TwoScopeFixtureCoordinator", entry)
        self.assertIn("native_product_install_accepted", entry)
        self.assertIn("native_product_installation_accepted=$false", guest)
        self.assertIn("$ReceiptPath = Join-Path $OutputRoot", guest)
        self.assertIn("$Report=[ordered]@{", guest)
        self.assertIn("Set-Content -LiteralPath $ReceiptPath", guest)
        self.assertNotRegex(guest, r"(?im)^\s*\$receipt\s*=")
        self.assertIn("COORDINATOR_FORWARD_RECOVERY_REQUIRED", guest)
        self.assertIn("BAD_NATIVE_START_ABORT_BOTH_ROOTS_RESTORE_156", guest)
        self.assertNotIn("DirectInternetMethodSvc", entry + guest)
        self.assertNotIn("Restart-Computer", guest)


if __name__ == "__main__":
    unittest.main()
