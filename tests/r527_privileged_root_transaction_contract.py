#!/usr/bin/env python3
"""R527: real-root-owned file transaction on a DISPOSABLE GitHub Ubuntu VM.

This is not a live product installation or physical network acceptance.
The unchanged candidate RootTransaction class executes its native owner/permission
checks and real chown/fsync/flock/atomic rename/rollback syscalls as UID 0, but
EVERY write is confined to a new fixture beneath GITHUB_WORKSPACE. Existing
network, /usr/lib, /etc, real user homes, systemd and Tailscale are NEVER changed.
Do not run on personal machines, even as root.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import unittest

BASE = Path(__file__).resolve().parents[1]
ORIGINAL_TEST = BASE / "tests/protected_upgrade_transaction_contract.py"
ROOT_CODE = BASE / "linux/system/protected_upgrade_transaction.py"
REQUIRED_REPO = "GOD13emad/DirectInternetMethod"

def read_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("SOURCE_IMPORT_ERROR")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

fixture_source = read_module(ORIGINAL_TEST, "r527_fixtures")
m = fixture_source.m

def assert_ephemeral_runner():
    if os.name != "posix" or not sys.platform.startswith("linux"):
        raise RuntimeError("R527_LINUX_REQUIRED")
    if os.geteuid() != 0:
        raise RuntimeError("R527_ROOT_REQUIRED")
    if os.environ.get("CI") != "true" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("R527_GITHUB_EPHEMERAL_RUNNER_REQUIRED")
    if os.environ.get("GITHUB_REPOSITORY") != REQUIRED_REPO:
        raise RuntimeError("R527_EXACT_GITHUB_REPOSITORY_REQUIRED")
    workspace = os.environ.get("GITHUB_WORKSPACE")
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not workspace or not runner_temp:
        raise RuntimeError("R527_RUNNER_PATHS_REQUIRED")
    if Path(workspace).resolve() != BASE.resolve():
        raise RuntimeError("R527_WORKSPACE_MISMATCH")
    if not Path(runner_temp).is_dir():
        raise RuntimeError("R527_RUNNER_TEMP_MISSING")
    if BASE == Path("/") or BASE == Path("/usr") or BASE == Path("/home"):
        raise RuntimeError("R527_REAL_ROOT_BLOCKED")
    if (Path("/run/directinternetmethod-encrypted").exists()
        or Path("/run/directinternetmethod-selective/session.json").exists()
        or Path("/home/mmz/.local/share/DirectInternetMethod/directmethod/state.json").exists()):
        raise RuntimeError("R527_RUNNER_NOT_CLEAN")
    if not ROOT_CODE.is_file() or not ORIGINAL_TEST.is_file():
        raise RuntimeError("R527_PINNED_SOURCES_MISSING")
    # The product's CLI has no writable root-prefix option. This test only
    # exercises RootTransaction(temp_root) imported as a class, never main().
    source = ROOT_CODE.read_text(encoding="utf8")
    if 't=RootTransaction() # No CLI root-prefix/dry-run/test-mode option.' not in source:
        raise RuntimeError("R527_PRODUCT_NATIVE_ENTRYPOINT_CHANGED")

class PrivilegedRootFileTransaction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert_ephemeral_runner()

    def setUp(self):
        self.fx = fixture_source.FakeFixture("test_success_stage_apply_rollback")
        self.fx.setUp()
        self.addCleanup(self.fx.tearDown)
        self.root = self.fx.root
        self.tx = self.fx.tx
        self.assertNotEqual(self.root, Path("/"))
        self.assertTrue(self.root.resolve().is_relative_to(BASE.resolve()))
        self.assertEqual(self.root.stat().st_uid, 0)
        self.assertEqual(self.root.stat().st_gid, 0)
        # Activates original native file owner/lock/mode checks, but all
        # writes continue to target self.root, not /.
        self.tx.native = True
        self.assertNotEqual(self.tx.root, Path("/"))
        self.assertTrue(self.tx.meta.resolve().is_relative_to(self.root.resolve()))
        self.assertTrue(self.tx.pending.resolve().is_relative_to(self.root.resolve()))
        self.assertEqual(self.fx.meta.stat().st_uid, 0)
        self.assertEqual(stat.S_IMODE(self.fx.meta.stat().st_mode), 0o644)

    def assert_old(self):
        self.fx.all_old()

    def assert_new(self):
        self.fx.all_new()

    def test_01_stage_real_root_owned_pending_backup(self):
        self.assert_old()
        outcome = self.tx.stage(self.fx.pkg)
        self.assertEqual(outcome["status"], "STAGED")
        self.assertEqual(self.tx.status()["status"], "STAGED")
        self.assertEqual(self.tx.pending.stat().st_uid, 0)
        self.assertEqual(stat.S_IMODE(self.tx.pending.stat().st_mode), 0o700)
        record = self.tx.pending / "manifest.json"
        self.assertEqual(record.stat().st_uid, 0)
        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)
        self.assert_old()
        self.assertEqual(self.tx.rollback()["status"], "ROLLED_BACK")
        self.assert_old()

    def test_02_apply_native_root_modes_and_reversible_ownership(self):
        self.tx.stage(self.fx.pkg)
        self.assertEqual(self.tx.apply()["status"], "APPLIED")
        self.assert_new()
        for _, _, target, _, _, mode in self.fx.files:
            p = self.root / target
            self.assertEqual(p.stat().st_uid, 0)
            self.assertEqual(p.stat().st_gid, 0)
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), mode)
        self.assertEqual(self.fx.meta.stat().st_uid, 0)
        self.assertEqual(stat.S_IMODE(self.fx.meta.stat().st_mode), 0o644)
        self.assertEqual(self.tx.rollback()["status"], "ROLLED_BACK")
        self.assert_old()

    def test_03_mid_apply_1_auto_rollback(self):
        self.fault_recover(1)

    def test_04_mid_apply_2_auto_rollback(self):
        self.fault_recover(2)

    def test_05_mid_apply_3_auto_rollback(self):
        self.fault_recover(3)

    def test_06_mid_apply_4_auto_rollback(self):
        self.fault_recover(4)

    def fault_recover(self, fail_after):
        self.tx.stage(self.fx.pkg)
        with self.assertRaisesRegex(RuntimeError, "INJECTED_TEST_FAILURE"):
            self.tx.apply(fail_after=fail_after)
        self.assert_old()
        self.assertEqual(self.tx.status()["status"], "ROLLED_BACK")

    def test_07_reject_unknown_protected_file_before_stage(self):
        victim = self.root / self.fx.files[0][2]
        victim.write_bytes(b"FOREIGN_ROOT_FILE_NOT_OWNED")
        with self.assertRaisesRegex(RuntimeError, "OLD_FILE_SHA"):
            self.tx.stage(self.fx.pkg)
        self.assertEqual(victim.read_bytes(), b"FOREIGN_ROOT_FILE_NOT_OWNED")
        self.assertFalse(self.tx.pending.exists())

    def test_08_reject_symlink_protected_target(self):
        victim = self.root / self.fx.files[0][2]
        victim.unlink()
        victim.symlink_to(self.fx.meta)
        with self.assertRaisesRegex(RuntimeError, "MISSING_OR_SYMLINK"):
            self.tx.stage(self.fx.pkg)
        self.assertTrue(victim.is_symlink())
        self.assertFalse(self.tx.pending.exists())

    def test_09_reject_symlink_source_before_stage(self):
        candidate = self.fx.pkg / "system/encrypted_selective_dns.py"
        candidate.unlink()
        candidate.symlink_to(self.fx.pkg / "app/direct_method_helper.sh")
        with self.assertRaisesRegex(RuntimeError, "MISSING_OR_SYMLINK"):
            self.tx.stage(self.fx.pkg)
        self.assertFalse(self.tx.pending.exists())
        self.assert_old()

    def test_10_reject_foreign_pending_mutation(self):
        self.tx.stage(self.fx.pkg)
        victim = self.tx.pending / "new/encrypted_controller"
        victim.write_bytes(b"FOREIGN_PENDING_MUTATION")
        with self.assertRaisesRegex(RuntimeError, "PENDING_NEW_SHA"):
            self.tx.apply()
        self.assert_old()

    def test_11_reject_stale_second_stage(self):
        self.tx.stage(self.fx.pkg)
        with self.assertRaisesRegex(RuntimeError, "SLOT_ALREADY_EXISTS"):
            self.tx.stage(self.fx.pkg)
        self.assert_old()

    def test_12_commit_without_live_acceptance_forbidden(self):
        self.tx.stage(self.fx.pkg)
        self.tx.apply()
        # The fake Root fixture lives under runner-owned GITHUB_WORKSPACE.
        # R783's single-descriptor reader rejects its untrusted ancestor
        # before it would check the missing receipt leaf. Both are narrowly
        # valid fail-closed causes; neither may commit or mutate the baseline.
        with self.assertRaisesRegex(RuntimeError,
                                    "NATIVE_ACCEPTANCE_MISSING|RECEIPT_PARENT_OWNER"):
            self.tx.commit(self.root / "not-a-real-acceptance.json")
        self.assertEqual(self.tx.status()["status"], "APPLIED")
        self.assertEqual(self.tx.rollback()["status"], "ROLLED_BACK")
        self.assert_old()

    def test_13_reject_foreign_metadata_edit_before_apply(self):
        self.tx.stage(self.fx.pkg)
        self.fx.meta.write_text('{"schema":1,"version":"FOREIGN"}')
        with self.assertRaisesRegex(RuntimeError, "FOREIGN_METADATA_CHANGE"):
            self.tx.apply()
        self.assertEqual(json.loads(self.fx.meta.read_text())["version"], "FOREIGN")

    def test_14_reject_foreign_edit_during_rollback(self):
        self.tx.stage(self.fx.pkg)
        self.tx.apply()
        victim = self.root / self.fx.files[1][2]
        victim.write_bytes(b"FOREIGN_AFTER_ROOT_APPLY")
        with self.assertRaisesRegex(RuntimeError, "FOREIGN_TARGET_MODIFICATION"):
            self.tx.rollback()
        self.assertEqual(victim.read_bytes(), b"FOREIGN_AFTER_ROOT_APPLY")
        self.assertEqual(self.tx.status()["status"], "APPLIED")

    def test_15_native_uid_mode_guard_is_in_effect(self):
        marker = self.root / "etc/directinternetmethod.uid"
        marker.write_text("1000\n")
        self.assertEqual(marker.stat().st_uid, 0)
        self.fx.meta.chmod(0o600)  # old backend identity requires 0644
        with self.assertRaisesRegex(RuntimeError, "METADATA_MODE"):
            self.tx.stage(self.fx.pkg)
        self.assertFalse(self.tx.pending.exists())

    def test_16_root_lock_parent_and_file_owner_enforced(self):
        self.tx.stage(self.fx.pkg)
        self.assertEqual(self.tx.lock.stat().st_uid, 0)
        self.assertEqual(stat.S_IMODE(self.tx.lock.stat().st_mode), 0o600)
        self.assertEqual(self.tx.status()["status"], "STAGED")
        self.assert_old()


if __name__ == "__main__":
    # Runs ONLY on disposable GitHub Ubuntu runners. No preflight-mode bypass.
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PrivilegedRootFileTransaction)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print("R527_REAL_UID0_ISOLATED_ROOT_TRANSACTION",
          result.testsRun,
          "PASS" if result.wasSuccessful() else "FAIL",
          "NO_REAL_INSTALL_DNS_SYSTEMD_OR_TAILSCALE")
    raise SystemExit(0 if result.wasSuccessful() else 1)
