"""The same portable CLI exposes a bounded cross-platform lifecycle self-test.

No production OS adapter, native installation or privilege authority implied.
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
import unittest


class UniversalCliSelfTest(unittest.TestCase):
    def command(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "installer_engine",
             "universal-selftest", *args],
            capture_output=True, text=True, timeout=25,
        )

    def test_universal_cli_cycle_on_native_host(self):
        platform = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
        result = self.command("--platform", platform)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["status"], "PASS_UNIVERSAL_TRANSACTION_FIXTURE")
        for op in ("fresh_install", "in_place_upgrade",
                   "incomplete_native_update_rollback",
                   "uninstall_preserves_owner_data"):
            self.assertEqual(data[op], "PASS")
        self.assertFalse(data["native_product_install_accepted"])
        self.assertFalse(data["native_os_rollback_accepted"])
        self.assertFalse(data["power_cut_accepted"])

    def test_universal_cli_rejects_user_supplied_physical_root(self):
        platform = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
        result = self.command("--platform", platform,
                              "--root", "forbidden-real-install-target")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stderr)["reason"],
                         "UNIVERSAL_SELFTEST_TAKES_NO_INSTALL_PATHS_OR_FLAGS")

    def test_cross_os_execution_is_not_silently_simulated(self):
        platform = "linux-x86_64" if os.name == "nt" else "windows-x86_64"
        result = self.command("--platform", platform)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stderr)["reason"],
                         "TARGET_PLATFORM_NOT_THIS_HOST")


if __name__ == "__main__":
    unittest.main()
