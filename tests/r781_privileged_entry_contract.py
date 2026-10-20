#!/usr/bin/env python3
"""R781 rootless negative-first trust bootstrap contracts; no Root or GUI use."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
SRC=ROOT/"tools/security/privileged_entry.py"
SPEC=importlib.util.spec_from_file_location("dim_r781",SRC)
m=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
PKG="DirectInternetMethod_1.5.6_Linux_x86_64"

class RootlessTrustedEntry(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="r781-only-user-",dir=str(ROOT))
        self.base=Path(self.tmp.name)
        self.src=self.base/"source"/PKG
        self.src.parent.mkdir()
        with zipfile.ZipFile(ROOT/"delivery"/(PKG+".zip")) as z:
            names=z.namelist()
            self.assertEqual(len(names),30)
            for name in names:
                self.assertTrue(name.startswith(PKG+"/"))
                self.assertNotIn("..",Path(name).parts)
            z.extractall(self.src.parent)
        self.private=self.base/"private"
        self.private.mkdir(mode=0o700)
        self.user=os.geteuid()
        self.assertNotEqual(self.user,0,"Do not run this rootless suite as Root.")

    def tearDown(self):
        self.tmp.cleanup()

    def candidate(self):
        return m.freeze_package(self.src,self.private,self.user)

    def test_01_valid_unchanged_exact_manifest(self):
        fd=m.open_pinned_directory(self.src)
        try:
            data, rows=m.package_inventory(fd)
            self.assertEqual(m.sha(data),m.MANIFEST_SHA256)
            self.assertEqual(len(rows),28)
        finally:
            os.close(fd)

    def test_02_integrity_frozen_canonical_archive(self):
        actual=self.candidate()
        self.assertEqual(actual.name,PKG)
        self.assertTrue(actual.is_dir())
        self.assertEqual(actual.stat().st_mode&0o777,0o500)
        for path in ("system/upgrade_system.sh","system/install_system.sh",
                     "system/upgrade_guard.py","system/protected_upgrade_transaction.py",
                     "app/user_update_transaction.py","runtime/ctrld"):
            before=self.src/path
            after=actual/path
            self.assertEqual(hashlib.sha256(before.read_bytes()).hexdigest(),
                             hashlib.sha256(after.read_bytes()).hexdigest())
        self.assertEqual(len([x for x in actual.rglob("*") if x.is_file()]),30)

    def test_03_modified_manifest_rejected(self):
        p=self.src/"PACKAGE_MANIFEST.json"
        p.write_bytes(p.read_bytes()+b" ")
        with self.assertRaisesRegex(m.AdmissionError,"TRUSTED_MANIFEST_DIGEST"):
            self.candidate()
        self.assertFalse((self.private/PKG).exists())

    def test_04_modified_payload_does_not_stage_valid_version(self):
        p=self.src/"system/upgrade_system.sh"
        p.write_bytes(b"print('untrusted')\n")
        with self.assertRaisesRegex(m.AdmissionError,"PINNED_PAYLOAD_SHA"):
            self.candidate()

    def test_05_manifest_duplicate_key_rejected(self):
        with self.assertRaisesRegex(m.AdmissionError,"DUPLICATE_JSON_FIELD"):
            m.strict_json(b'{"schema":1,"schema":1}')

    def test_06_linked_parent_is_not_followed(self):
        alias=self.base/"bad_symlink"
        alias.symlink_to(self.src.parent,target_is_directory=True)
        with self.assertRaisesRegex(m.AdmissionError,"SOURCE_DIR_NOFOLLOW"):
            m.freeze_package(alias/PKG,self.private,self.user)

    def test_07_payload_symlink_never_followed(self):
        p=self.src/"system/upgrade_system.sh"
        p.unlink();p.symlink_to(self.src/"system/install_system.sh")
        with self.assertRaisesRegex(m.AdmissionError,"MEMBER_FILE_NOFOLLOW"):
            self.candidate()

    def test_08_payload_fifo_never_blocks(self):
        p=self.src/"system/upgrade_system.sh"
        p.unlink();os.mkfifo(p,0o600)
        program="""
import importlib.util,sys,os
sp=importlib.util.spec_from_file_location("tested",sys.argv[1])
m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
fd=m.open_pinned_directory(__import__('pathlib').Path(sys.argv[2]))
try:
    m.read_pinned(fd,"system/upgrade_system.sh",100000)
except m.AdmissionError:
    sys.exit(0)
finally:
    os.close(fd)
sys.exit(99)
"""
        r=subprocess.run([sys.executable,"-B","-c",program,str(SRC),str(self.src)],
                         capture_output=True,text=True,timeout=4)
        self.assertEqual(r.returncode,0,r.stderr)

    def test_09_midstage_replacement_detected(self):
        original=m.package_inventory
        p=self.src/"system/upgrade_system.sh"
        def swap(fd):
            info=original(fd)
            p.rename(p.with_name(p.name+".pinned"))
            p.symlink_to(self.src/"system/install_system.sh")
            return info
        with patch.object(m,"package_inventory",side_effect=swap):
            with self.assertRaisesRegex(m.AdmissionError,"MEMBER_FILE_NOFOLLOW"):
                self.candidate()

    def test_10_untrusted_cli_without_root_refuses(self):
        r=subprocess.run([sys.executable,"-B",str(SRC),"--action","upgrade",
                          "--source",str(self.src)],
                         capture_output=True,text=True,timeout=4)
        self.assertEqual(r.returncode,86,(r.stdout,r.stderr))
        self.assertIn("ROOT_REQUIRED",r.stderr)
        self.assertFalse((self.private/PKG).exists())

    def test_12_no_pkexec_user_owned_code_and_missing_anchor_fails_closed(self):
        installer=(ROOT/"linux/install.sh").read_text()
        self.assertNotIn('pkexec /bin/bash "$HERE/system/',installer)
        self.assertEqual(installer.count(
            'pkexec /usr/bin/python3 -I "$TRUSTED_BOOTSTRAP"'),2)
        self.assertIn('R781_TRUSTED_BOOTSTRAP_NOT_PROVISIONED',installer)
        self.assertIn('trusted_bootstrap_ready()',installer)
        self.assertIn('rollback_failed_install 87',installer)
        self.assertIn('TRUSTED_BOOTSTRAP="/usr/local/libexec/directinternetmethod/privileged_entry.py"',installer)

    def test_14_fresh_install_anchor_does_not_create_primary_backend(self):
        installer=(ROOT/"linux/install.sh").read_text()
        anchor="/usr/local/libexec/directinternetmethod/privileged_entry.py"
        self.assertIn('TRUSTED_BOOTSTRAP="'+anchor+'"',installer)
        self.assertNotIn('TRUSTED_BOOTSTRAP="/usr/lib/directinternetmethod/',installer)
        self.assertNotIn("pkexec /bin/bash",installer)
        self.assertIn('[ ! -e /usr/lib/directinternetmethod ]',installer)
        self.assertIn("--action install --source",installer)
        self.assertIn("--action upgrade --source",installer)
        helper=(ROOT/"tools/security/privileged_entry.py").read_text()
        self.assertIn('TRUSTED_ENTRY = Path("'+anchor+'")',helper)
        self.assertIn('Path("/usr/local/libexec/directinternetmethod")',helper)

    def test_13_missing_root_provisioning_is_not_emulated(self):
        # A root-owned helper may legitimately be present on a CI host.
        # This user-only test verifies non-root invocation fails regardless.
        with self.assertRaisesRegex(m.AdmissionError,"ROOT_REQUIRED"):
            m.check_trusted_entry()

    def test_11_source_from_other_uid_rejected(self):
        with self.assertRaisesRegex(m.AdmissionError,"PACKAGE_SOURCE_OWNER"):
            m.freeze_package(self.src,self.private,self.user+1)

if __name__=="__main__":
    unittest.main(verbosity=2)
