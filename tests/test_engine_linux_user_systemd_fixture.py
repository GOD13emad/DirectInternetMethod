"""R889 isolated user-systemd fixture build and safety source contracts.

Actual systemd lifecycle is run ONLY on the separately authorized Emad Linux
test host. Hosted CI never starts units or requests root.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

from installer_engine.engine import read_package

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/native_fixtures/linux/RunSystemdUserEngineFixture.py"


class UserSystemdFixtureTests(unittest.TestCase):
    def test_python_source_is_valid(self):
        ast.parse(SOURCE.read_text("utf-8"), filename=str(SOURCE))

    def test_fixture_stays_user_only_and_never_requests_root(self):
        content = SOURCE.read_text("utf-8")
        code = "\n".join(line for line in content.splitlines()
                         if not line.lstrip().startswith("#"))
        self.assertIn('os.geteuid() != 0', code)
        self.assertIn('["systemctl", "--user", *args]', code)
        self.assertIn('native_root_systemd_polkit_install_accepted', code)
        self.assertIn('False', code)
        self.assertIn('dim-r889-engine-fixture-', code)
        self.assertNotIn('DirectInternetMethodSvc', code)
        self.assertNotIn('/etc/systemd/system', code)
        self.assertNotIn('/usr/lib/directinternetmethod', code)
        self.assertNotIn('pkexec ', code)
        self.assertNotIn('sudo ', code)

    def test_package_compiler_generates_exact_sha_verified_executable(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("dim_r889_fixture", SOURCE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        code = b"#!/bin/sh\nexit 0\n"
        with tempfile.TemporaryDirectory(prefix="dim-r889-pkg-") as td:
            folder, pin = module.package(Path(td), "old", "1.5.6", code)
            verified = read_package(folder, pin, "linux-x86_64")
            self.assertEqual(verified["files"][0]["mode"], 0o755)
            self.assertEqual(verified["version"], "1.5.6")
            self.assertEqual(hashlib.sha256(
                (folder/"payload/app/fixture.sh").read_bytes()).hexdigest(),
                verified["files"][0]["sha256"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
