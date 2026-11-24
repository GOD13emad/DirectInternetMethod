"""R928 source safety contract for the real, user-only native systemd fixture.

Full native user-unit integration runs separately on the authorized Linux host,
not in hosted CI; this suite is fast and OS independent.
"""
from __future__ import annotations
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tools/native_fixtures/linux/RunUniversalSystemdUserFixture.py"


class NativeUserSystemdOrchestratorContracts(unittest.TestCase):
    def test_runner_source_compiles(self):
        ast.parse(RUNNER.read_text("utf8"), filename=str(RUNNER))

    def test_real_systemd_fixture_is_explicitly_unprivileged_and_isolated(self):
        source = RUNNER.read_text("utf8")
        for required in (
            'os.geteuid() != 0', 'systemctl("link", "--runtime"',
            'systemctl("daemon-reload")', 'self.link.unlink()',
            'self._code_versions() == {old_version}',
            'status": STATUS', '"native_root_systemd_polkit_install_accepted": False',
            '"publisher_authenticated": False',
            '"native_product_rollback_accepted": False',
            '"host_reboot_accepted": False',
            'dim-r928-universal-', 'TemporaryDirectory(',
            'NativeAdapter',
        ):
            if required == 'NativeAdapter':
                continue
            with self.subTest(required=required):
                self.assertIn(required, source)
        self.assertNotIn("systemctl --system", source)
        self.assertNotIn("DirectInternetMethodSvc", source)
        self.assertNotIn("/etc/systemd/system", source)
        self.assertNotIn("pkexec", source)
        self.assertNotIn("sudo ", source)
        self.assertNotIn("Tailscale", source)
        self.assertIn("from installer_engine.universal_install import UniversalFixtureInstaller", source)

    def test_restore_phase_links_native_unit_before_resume_while_code_is_old(self):
        source = RUNNER.read_text("utf8")
        self.assertIn("pending = engine._pending()", source)
        self.assertIn('validate_slot(engine.current, installed["manifest"])', source)
        self.assertIn("tx.abort_uninstall()", source)
        self.assertIn("uninstall-restoring-native", source)
        self.assertIn("ctx.Process(", source)
        self.assertIn("_child_replay_after_restoration", source)
        self.assertIn('child_result["pid"] != os.getpid()', source)
        self.assertIn('"PROCESS_BOUNDARY_DUPLICATE_RESTART_OR_LOST_RUNTIME"', source)
        self.assertIn('self._code_versions() == {old_version}', source)
        self.assertIn('adapter._state()["resume_starts"] == start_count', source)
        self.assertIn('"OWNER_CONFIG_CHANGED"', source)


if __name__ == "__main__":
    unittest.main()
