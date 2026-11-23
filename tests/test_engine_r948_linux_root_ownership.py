"""R948: real Linux DIM bytes in two OS-owned scopes on a disposable CI runner.

This test MUST run only as root on a trusted feature-PUSH GitHub Actions
runner. It writes only a fresh private /run fixture tree and never touches
DIM's actual systemd units, real installation roots, DNS, networking, or OS
policies. Its FileNativeFixture receipt is SYNTHETIC, NOT a product receipt.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import sys
import unittest

from installer_engine.engine import EngineError, PRODUCT
from installer_engine.linux_trusted_fd import TrustedLinuxRootFD
from installer_engine.native_plan import NativePlan
from installer_engine.native_readiness import two_scope_code_postflight
from tests import test_engine_real_linux_two_scope as real_linux


class LinuxRootOwnedTwoScopeProductFixture(unittest.TestCase):
    def setUp(self):
        scope = (
            sys.platform == "linux" and os.geteuid() == 0 and
            os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("GITHUB_EVENT_NAME") == "push" and
            os.environ.get("GITHUB_REF") ==
                "refs/heads/feature/universal-install-engine" and
            os.environ.get("CI") == "true" and
            os.environ.get("R948_ROOT_ISOLATED") == "1"
        )
        if not scope:
            self.skipTest("R948 requires an ephemeral trusted feature-push root runner")
        uid, gid = os.environ.get("SUDO_UID", ""), os.environ.get("SUDO_GID", "")
        if not uid.isdecimal() or not gid.isdecimal():
            self.fail("R948_EXPECTED_SUDO_OWNER_IDS")
        self.owner = (int(uid), int(gid))
        self.assertGreater(self.owner[0], 0)
        self.assertNotEqual(self.owner[0], os.geteuid())
        protected_parent = Path("/run")
        info = protected_parent.stat()
        self.assertEqual(info.st_uid, 0)
        self.assertFalse(stat.S_IMODE(info.st_mode) & 0o022)

        self.fx = real_linux.RealLinuxTwoScopeIntegration(
            "test_exact_21_code_files_shared_transaction_recovery_and_uninstall")
        self.fx._temp_parent = "/run"
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        base_stat = self.fx.base.lstat()
        self.assertEqual(base_stat.st_uid, 0)
        self.assertTrue(stat.S_ISDIR(base_stat.st_mode))
        # Allow pathname traversal into a user-owned scope while all fixture
        # parents remain root-owned and not group/world writable.
        self.fx.base.chmod(0o711)

    def assign_user_ownership(self):
        """Test native os.chown on ONLY the freshly created fixture user tree."""
        uid, gid = self.owner
        target = self.fx.roots["user"]
        self.assertEqual(target.parent, self.fx.base)
        for parent, dirs, files in os.walk(target, followlinks=False):
            for name in files + dirs:
                path = Path(parent) / name
                self.assertFalse(path.is_symlink())
                os.chown(path, uid, gid, follow_symlinks=False)
        os.chown(target, uid, gid, follow_symlinks=False)
        target.chmod(0o750)

    def plan_and_intent(self, sources):
        documents = {
            name: json.loads((source / "manifest.json").read_text("utf-8"))
            for name, (source, _) in sources.items()
        }
        plan = NativePlan(
            PRODUCT, "1.5.7", "linux-x86_64",
            "PINNED_CODE_LAYOUT_REQUIRES_TRUSTED_NATIVE_ADAPTER",
            tuple((name, documents[name]) for name in sorted(documents)))
        native = self.fx.engine._intent(self.fx.engine._load())
        return plan, native, documents

    def checked_postflight(self, plan, native):
        return two_scope_code_postflight(
            plan, self.fx.roots, native,
            journal_path=self.fx.engine.journal,
            expected_uids={"privileged": 0, "user": self.owner[0]})

    def test_exact_real_product_root_and_user_ownership_postflight_and_recovery(self):
        sources = self.fx._build("1.5.7")
        user_data = self.fx.roots["user"] / "data" / "settings.json"
        user_data.parent.mkdir(parents=True, exist_ok=True)
        user_data.write_bytes(b"R948_PRIVATE_USER_SETTINGS_UNCHANGED")
        self.fx.engine.begin(sources)
        self.fx.engine.activate()
        self.assign_user_ownership()
        plan, native, docs = self.plan_and_intent(sources)
        report = self.checked_postflight(plan, native)
        self.assertEqual({x["scope"]: x["files"] for x in report["scopes"]},
                         {"privileged": 13, "user": 8})
        self.assertFalse(report["native_installation_accepted"])
        self.assertFalse(report["os_native_registration_verified"])
        protected_code = self.fx.roots["privileged"] / "current"
        privileged_exe = protected_code / "runtime/usr/bin/ctrld"
        row = next(x for x in docs["privileged"]["files"]
                   if x["path"] == "runtime/usr/bin/ctrld")
        with TrustedLinuxRootFD(protected_code) as root:
            attestation = root.read_pinned_member(
                row["path"], row["sha256"], row["bytes"])
            self.assertEqual(attestation["sha256"], row["sha256"])

        # Real kernel DAC negative check, not just UID metadata comparison:
        # an unprivileged fork must be unable to modify root code or journal,
        # but must be able to read its own installed user code.
        user_exe = self.fx.roots["user"] / "current" / "direct_internet_method.py"
        pid = os.fork()
        if pid == 0:
            try:
                os.setgroups([])
                os.setgid(self.owner[1])
                os.setuid(self.owner[0])
                forbidden_checks = (
                    (privileged_exe, os.O_WRONLY | os.O_APPEND),
                    (self.fx.engine.journal, os.O_RDONLY),
                    (self.fx.engine.journal, os.O_WRONLY | os.O_APPEND),
                )
                for forbidden, flags in forbidden_checks:
                    try:
                        handle = os.open(forbidden, flags)
                    except PermissionError:
                        pass
                    else:
                        os.close(handle)
                        os._exit(91)
                with user_exe.open("rb") as owner_file:
                    if not owner_file.read(1):
                        os._exit(92)
                os._exit(0)
            except BaseException:
                os._exit(93)
        child, outcome = os.waitpid(pid, 0)
        self.assertEqual(child, pid)
        self.assertTrue(os.WIFEXITED(outcome))
        self.assertEqual(os.WEXITSTATUS(outcome), 0,
                         "R948_KERNEL_DAC_PROTECTED_CODE_OR_OWNER_ACCESS_FAILED")

        # A real OS uid mutation is detected even when file bytes and
        # manifest digest remain valid.
        os.chown(privileged_exe, *self.owner)
        with self.assertRaisesRegex(EngineError, "R947_MANAGED_FILE_OWNER_DRIFT"):
            self.checked_postflight(plan, native)
        with TrustedLinuxRootFD(protected_code) as root:
            with self.assertRaisesRegex(
                    EngineError, "TRUSTED_FD_MEMBER_NOT_ROOT_OWNED_REGULAR"):
                root.read_pinned_member(row["path"], row["sha256"], row["bytes"])
        os.chown(privileged_exe, 0, 0)
        self.checked_postflight(plan, native)

        user_exe = self.fx.roots["user"] / "current" / "direct_internet_method.py"
        os.chown(user_exe, 0, 0)
        with self.assertRaisesRegex(EngineError, "R947_MANAGED_FILE_OWNER_DRIFT"):
            self.checked_postflight(plan, native)
        os.chown(user_exe, *self.owner)
        self.checked_postflight(plan, native)

        # No native receipt -> the existing shared kernel must restore EMPTY;
        # user data remains outside the two managed code slots.
        self.fx.adapter.receipt.unlink(missing_ok=True)
        with self.assertRaisesRegex(
                EngineError, "UNIVERSAL_NATIVE_COMPLETION_RECEIPT_MISSING"):
            self.fx.engine.commit()
        recovered = self.fx._engine().recover()
        self.assertIsNone(recovered.get("version"))
        self.assertEqual({x["status"] for x in self.fx._states().values()},
                         {"EMPTY"})
        self.assertEqual(user_data.read_bytes(),
                         b"R948_PRIVATE_USER_SETTINGS_UNCHANGED")

        # Reuse SAME engine and source pins for a successful isolated code
        # transaction; native postflight remains a non-production fixture.
        self.fx.engine = self.fx._engine()
        self.fx.engine.begin(sources)
        self.fx.engine.activate()
        self.assign_user_ownership()
        plan, native, _ = self.plan_and_intent(sources)
        self.checked_postflight(plan, native)
        committed = self.fx.engine.commit()
        self.assertFalse(committed["native_product_installation_accepted"])
        self.assertEqual({x["version"] for x in self.fx._states().values()},
                         {"1.5.7"})
        self.assertEqual(user_data.read_bytes(),
                         b"R948_PRIVATE_USER_SETTINGS_UNCHANGED")
        self.fx.engine.begin_uninstall()
        self.fx.engine.apply_uninstall()
        uninstalled = self.fx.engine.finish_uninstall()
        self.assertFalse(uninstalled["native_product_uninstall_accepted"])
        self.assertEqual({x["status"] for x in self.fx._states().values()},
                         {"EMPTY"})
        self.assertEqual(user_data.read_bytes(),
                         b"R948_PRIVATE_USER_SETTINGS_UNCHANGED")
        print("R948_EPHEMERAL_ROOT_USER_ACTUAL_21_FILES_PASS_FIXTURE_ONLY")


if __name__ == "__main__":
    unittest.main()
