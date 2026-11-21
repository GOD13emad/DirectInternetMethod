"""R893 native adapter contract/bridge tests. Never invoke real services."""
from __future__ import annotations

import ast
from pathlib import Path
import unittest

BASE=Path(__file__).resolve().parents[1]
WIN=BASE/"tools/native_fixtures/windows"
LINUX=BASE/"tools/native_fixtures/linux"


class TwoScopeUninstallNativeContracts(unittest.TestCase):
    def test_wrapper_does_not_infer_privilege_from_cli_boolean(self):
        src=(WIN/"ScmInnoCoordinatedUninstallEntry.py").read_text("utf-8")
        ast.parse(src)
        self.assertIn("TwoScopeUninstallFixtureCoordinator",src)
        self.assertIn('observe_windows(inno.APP_ID, base.SERVICE)',src)
        self.assertIn('svc["state"] == "STOPPED"',src)
        self.assertIn('registrations[0]["display_version"] == expected_version',src)
        self.assertIn('lambda: base.observed("unregistered")',src)
        self.assertIn('"native_product_install_accepted": False',src)
        self.assertNotIn("DirectInternetMethodSvc",src)
        self.assertNotIn("--accepted",src)
        self.assertNotIn("pkexec",src)

    def test_guest_has_two_uninstall_crash_boundaries(self):
        src=(WIN/"RunScmInnoTwoScopeUninstallSandboxFixture.ps1").read_text("utf-8")
        self.assertIn("coordinated-uninstall-prepare','--fault-after','code",src)
        self.assertIn("coordinated-uninstall-abort",src)
        self.assertIn("coordinated-uninstall-finish','--fault-after','code",src)
        self.assertIn("COORDINATOR_UNINSTALL_FORWARD_ONLY",src)
        self.assertIn("INNO_SCM_UNREGISTERED_FIRST_SCOPE_REMOVED_REPLAY_BOTH_CODE_ONLY",src)
        self.assertIn("native_product_installation_accepted=$false",src)
        self.assertIn("$ReceiptPath",src)
        self.assertIn("$Report",src)
        self.assertNotIn("DirectInternetMethodSvc",src)

    def test_linux_user_systemd_is_unprivileged_and_cleanup_scoped(self):
        src=(LINUX/"RunSystemdUninstallTwoScopeFixture.py").read_text("utf-8")
        ast.parse(src)
        self.assertIn('os.geteuid() != 0',src)
        self.assertIn('systemctl("link", "--runtime", str(unit_file))',src)
        self.assertIn('TwoScopeUninstallFixtureCoordinator',src)
        self.assertIn('fault_after="code"',src)
        self.assertIn("COORDINATOR_UNINSTALL_FORWARD_ONLY",src)
        self.assertIn('"native_privileged_install_accepted": False',src)
        self.assertIn('symlink.resolve() == unit_file.resolve()',src)
        self.assertNotIn("sudo ",src)
        self.assertNotIn("pkexec",src)

    def test_coordinator_never_mutates_native_registration(self):
        source=(BASE/"installer_engine/two_scope_uninstall.py").read_text("utf-8")
        ast.parse(source)
        self.assertNotIn("subprocess",source)
        self.assertNotIn("Start-Process",source)
        self.assertNotIn("systemctl",source)
        self.assertNotIn("ctypes",source)
        self.assertIn('"finishing"',source)
        self.assertIn("native_still_registered",source)
        self.assertIn("native_unregistered",source)
        self.assertIn("self._preflight(journal, accepting=True)",source)


if __name__ == "__main__":
    unittest.main()
