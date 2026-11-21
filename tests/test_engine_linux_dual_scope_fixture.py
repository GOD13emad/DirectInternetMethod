"""R890 synthetic dual-code-root plus native systemd --user fixture contracts.

CI MUST NEVER register services, request root, or run the guest fixture.
The Linux native execution is separately evidenced on the Emad test host.
"""
from __future__ import annotations

import ast
import importlib.util
import hashlib
from pathlib import Path
import tempfile
import unittest
from installer_engine.engine import read_package

SOURCE = Path(__file__).resolve().parents[1] / "tools/native_fixtures/linux/RunSystemdDualScopeFixture.py"


class DualScopeNativeFixtureTests(unittest.TestCase):
    def test_syntax_and_only_test_identity(self):
        source = SOURCE.read_text("utf-8")
        ast.parse(source, filename=str(SOURCE))
        self.assertIn("dim-r890-dualscope-", source)
        self.assertIn("os.geteuid() != 0", source)
        self.assertIn('"systemctl", "--user"', source)
        self.assertNotIn("DirectInternetMethodSvc", source)
        self.assertNotIn("/etc/systemd/system", source)
        self.assertNotIn("pkexec", source)
        self.assertNotIn("sudo ", source)

    def test_two_scope_injection_and_replay_contract(self):
        s = SOURCE.read_text("utf-8")
        self.assertIn('fault_after="code"', s)
        self.assertIn('"FORWARD_RECOVERY_REQUIRED"', s)
        self.assertIn('coord = TwoScopeFixtureCoordinator(native, "linux-x86_64",', s)
        self.assertIn("coord.abort(stopped)", s)
        self.assertIn("coord.finalize(lambda: running", s)
        self.assertIn('"native_privileged_install_accepted": False', s)
        self.assertIn("USER_UNIT_UNLINKED_TWO_CODE_ROOTS_CLEANED", s)

    def test_synthetic_package_is_pinned_and_platform_valid(self):
        spec = importlib.util.spec_from_file_location("r890_dual_fixture", SOURCE)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory(prefix="dim-r890-unit-") as base:
            folder, pin = mod.bundle(Path(base), "unit", "code", "1.5.7",
                                     b"#!/bin/sh\nexit 0\n", 0o755)
            doc = read_package(folder, pin, "linux-x86_64")
            self.assertEqual(doc["version"], "1.5.7")
            self.assertEqual(doc["files"][0]["mode"], 0o755)
            self.assertEqual(hashlib.sha256((folder/"payload/app/service.sh").read_bytes()).hexdigest(),
                             doc["files"][0]["sha256"])


if __name__ == "__main__":
    unittest.main()
