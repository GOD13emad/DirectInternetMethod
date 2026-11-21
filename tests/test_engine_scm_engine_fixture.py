"""Source qualification of offline real SCM + frozen Engine sandbox fixture.

These tests only build disposable packages. They never create a service.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from installer_engine.engine import read_package

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT/"tools/native_fixtures/windows/BuildScmEngineFixture.py"
GUEST = ROOT/"tools/native_fixtures/windows/RunScmEngineSandboxFixture.ps1"


class ScmEngineBuilderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="dim-scm-engine-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.old = self.root/"old.exe"
        self.new = self.root/"new.exe"
        self.old.write_bytes(b"SYNTHETIC_156_NOT_EXECUTABLE")
        self.new.write_bytes(b"SYNTHETIC_157_NOT_EXECUTABLE")
        self.pins = (hashlib.sha256(self.old.read_bytes()).hexdigest(),
                     hashlib.sha256(self.new.read_bytes()).hexdigest())
        self.output = self.root/"bundles"

    def build(self, old_pin=None, output=None):
        return subprocess.run([
            sys.executable, str(BUILDER),
            "--old", str(self.old), "--new", str(self.new),
            "--old-sha256", old_pin or self.pins[0],
            "--new-sha256", self.pins[1],
            "--output", str(output or self.output),
        ], capture_output=True, text=True, timeout=20)

    def test_three_hash_pinned_fixture_bundles(self):
        done = self.build()
        self.assertEqual(done.returncode, 0, done.stderr)
        import json
        pins = json.loads((self.output/"pins.json").read_text("utf-8"))
        for path, key, release in (
                ("old156", "old_manifest_sha256", "1.5.6"),
                ("bad157", "bad_manifest_sha256", "1.5.7"),
                ("new157", "new_manifest_sha256", "1.5.7")):
            doc = read_package(self.output/path, pins[key], "windows-x86_64")
            self.assertEqual(doc["version"], release)
            self.assertEqual(len(doc["files"]), 1)
        self.assertNotEqual(pins["new_manifest_sha256"],
                            pins["bad_manifest_sha256"])

    def test_wrong_independent_executable_pin_refused_without_output(self):
        result = self.build(old_pin="0"*64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL_SOURCE_SHA_OR_VERSION", result.stderr)
        self.assertFalse(self.output.exists())

    def test_existing_destination_preserves_foreign_owner_content(self):
        self.output.mkdir()
        foreign = self.output/"foreign.txt"
        foreign.write_bytes(b"DO_NOT_TOUCH")
        failed = self.build()
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("FAIL_DESTINATION_EXISTS", failed.stderr)
        self.assertEqual(foreign.read_bytes(), b"DO_NOT_TOUCH")

    def test_guest_script_does_not_target_real_product_service(self):
        text = GUEST.read_text("utf-8")
        self.assertIn("$Name = 'DIMR887IsolatedFixtureSvc'", text)
        self.assertNotIn("DirectInternetMethodSvc", text)
        self.assertIn("SCM_START_FAILURE_FROZEN_ENGINE_ROLLBACK_RESTART_156",
                      text)
        self.assertIn("NATIVE_SCM_DELETE_ENGINE_CODE_ONLY_UNINSTALL_PRESERVE_DATA",
                      text)
        self.assertIn("native_product_installation_accepted=$false", text)
        self.assertNotIn("Restart-Computer", text)
        self.assertNotRegex(text, r"(?m)^function [^\\n]*\\(\\[string\\[\\]\\]\\$args\\)")
        self.assertIn("function Invoke-DimEngineFixture([string[]]$engineArguments)", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
