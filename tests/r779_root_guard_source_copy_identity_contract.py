#!/usr/bin/env python3
"""R779 Rootless negative-first source-to-root-guard byte identity regression.

Only disposable user-owned fixture paths. Never calls pkexec, systemctl, Root
CLI, or host networking. The guard functions are imported, not invoked as CLI.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import pathlib
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT=pathlib.Path(__file__).resolve().parents[1]
SRC=ROOT/"linux/system/upgrade_guard.py"
spec=importlib.util.spec_from_file_location("r779_guard",SRC)
g=importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)

class GuardSourceIdentity(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="r779-owned-",dir=str(ROOT))
        self.base=pathlib.Path(self.tmp.name)
        self.src=self.base/"DirectInternetMethod_1.5.5-rc1_Linux_x86_64"
        (self.src/"system").mkdir(parents=True)
        (self.src/"app").mkdir()
        self.root_tx=self.src/"system/protected_upgrade_transaction.py"
        self.user_tx=self.src/"app/user_update_transaction.py"
        shutil.copyfile(ROOT/"linux/system/protected_upgrade_transaction.py",self.root_tx)
        shutil.copyfile(ROOT/"linux/app/user_update_transaction.py",self.user_tx)
        self.assertEqual(hashlib.sha256(self.root_tx.read_bytes()).hexdigest().upper(),g.PIN_ROOT)
        self.assertEqual(hashlib.sha256(self.user_tx.read_bytes()).hexdigest().upper(),g.PIN_USER)
        rows=[{"file":"system/protected_upgrade_transaction.py","sha256":g.PIN_ROOT},
              {"file":"app/user_update_transaction.py","sha256":g.PIN_USER}]
        rows.extend({"file":f"unrelated-{i:02d}","sha256":"0"*64} for i in range(26))
        (self.src/"PACKAGE_MANIFEST.json").write_text(
            json.dumps({"schema":1,"version":g.VERSION,"files":rows})+"\n")
        self.guard_dir=self.base/"guard"
        self.home=self.base/"home"
        self.home.mkdir()
        self.um=self.home/"INSTALL.json"
        self.um.write_text('{"version":"1.5.4"}\n')
        self.rm=self.base/"root-install.json"
        self.rm.write_text('{"version":"1.5.2"}\n')
        self.write_calls=[]

    def tearDown(self):
        self.tmp.cleanup()

    def fake_write_new(self,path,data,mode):
        path=pathlib.Path(path)
        path.parent.mkdir(exist_ok=True,parents=True)
        self.assertFalse(path.exists(),"No writes to existing fixture files")
        path.write_bytes(data)
        path.chmod(mode)
        self.write_calls.append(str(path))

    def arm_fixture_without_privileges(self):
        with patch.object(g,"GUARD",self.guard_dir), \
             patch.object(g,"ROOT_TX",self.guard_dir/"root_tx.py"), \
             patch.object(g,"USER_TX",self.guard_dir/"user_tx.py"), \
             patch.object(g,"WORKER",self.guard_dir/"worker.py"), \
             patch.object(g,"BASELINE_FILE",self.guard_dir/"baseline.json"), \
             patch.object(g,"write_new",side_effect=self.fake_write_new), \
             patch.object(g.os,"chown",return_value=None):
            return g.guard_files(self.src,1000,"fixture",self.home,self.um,self.rm)

    def test_01_correct_pinned_source_can_be_staged(self):
        self.assertTrue(g.validate_source(self.src))
        doc=self.arm_fixture_without_privileges()
        self.assertEqual(doc["rootTransactionSha"],g.PIN_ROOT)
        self.assertEqual((self.guard_dir/"root_tx.py").read_bytes(),self.root_tx.read_bytes())
        self.assertEqual((self.guard_dir/"user_tx.py").read_bytes(),self.user_tx.read_bytes())
        self.assertEqual(len(self.write_calls),4)

    def test_02_changed_root_script_after_validation_never_installed_in_guard(self):
        self.assertTrue(g.validate_source(self.src))
        self.root_tx.write_bytes(b"print('UNTRUSTED_ROOT_CODE')\n")
        with self.assertRaises(RuntimeError):
            self.arm_fixture_without_privileges()
        self.assertFalse(self.guard_dir.exists(),"Changed root source must fail before guard creation")

    def test_03_changed_user_script_after_validation_never_installed_in_guard(self):
        self.assertTrue(g.validate_source(self.src))
        self.user_tx.write_bytes(b"print('UNTRUSTED_USER_CODE')\n")
        with self.assertRaises(RuntimeError):
            self.arm_fixture_without_privileges()
        self.assertFalse(self.guard_dir.exists(),"Changed user source must fail before guard creation")

    def test_04_fifo_source_never_blocks_root_before_sha_check(self):
        self.root_tx.unlink()
        os.mkfifo(self.root_tx,0o600)
        code="""
import importlib.util,sys
spec=importlib.util.spec_from_file_location("r779_child",sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
try:
    m.pinned_package_bytes(__import__("pathlib").Path(sys.argv[2]),
                           "system/protected_upgrade_transaction.py",m.PIN_ROOT)
except RuntimeError:
    sys.exit(0)
sys.exit(44)
"""
        child=subprocess.run(
            [sys.executable,"-B","-c",code,str(SRC),str(self.src)],
            capture_output=True,text=True,timeout=3)
        self.assertEqual(child.returncode,0,(child.stdout,child.stderr))

    def test_05_parent_directory_symlink_cannot_redirect_pinned_source(self):
        alias=self.base/"source-alias"
        alias.symlink_to(self.src,target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError,"PINNED_SOURCE_OPEN"):
            g.pinned_package_bytes(alias,"system/protected_upgrade_transaction.py",g.PIN_ROOT)

    def test_06_privileged_wrapper_executes_verified_root_owned_code_only(self):
        script=(ROOT/"linux/system/upgrade_system.sh").read_text()
        self.assertNotIn('python3 "$SRC/system/upgrade_guard.py" arm',script)
        self.assertNotIn('python3 "$SRC/system/protected_upgrade_transaction.py" stage',script)
        self.assertIn('mktemp -d /run/directinternetmethod-guard-XXXXXXXX',script)
        self.assertIn('install -m 0500 -- "$SRC/system/upgrade_guard.py"',script)
        self.assertIn('sha256sum "$GUARD_BOOTSTRAP_DIR/upgrade_guard.py"',script)
        launch='python3 -B "$GUARD_BOOTSTRAP_DIR/upgrade_guard.py" arm'
        self.assertIn(launch,script)
        self.assertLess(script.index('sha256sum "$GUARD_BOOTSTRAP_DIR/upgrade_guard.py"'),
                        script.index(launch))
        self.assertIn('GUARD_ROOT_TX="/var/lib/directinternetmethod/upgrade-guard/root_tx.py"',script)
        for verb in ("stage","apply","status"):
            self.assertIn('python3 -B "$GUARD_ROOT_TX" '+verb,script)

    def test_07_installer_rollback_uses_immutable_owned_root_transaction(self):
        src=(ROOT/"linux/install.sh").read_text()
        self.assertNotIn('ROOT_TRANSACTION="$HERE/system/protected_upgrade_transaction.py"',src)
        self.assertIn('ROOT_TRANSACTION="/var/lib/directinternetmethod/upgrade-guard/root_tx.py"',src)
        self.assertIn('pkexec /usr/bin/python3 "$ROOT_TRANSACTION" rollback',src)

if __name__=="__main__":
    unittest.main(verbosity=2)
