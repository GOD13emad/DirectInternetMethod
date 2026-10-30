#!/usr/bin/env python3
"""R803: negative-first future Stable 1.5.6 migration from BOTH accepted Linux roots.

Only disposable user-owned fake-root trees. Never runs pkexec, native service,
installed backend, DNS, Tailscale, package installer or public publication.
"""
import importlib.util
import json
import os
import pathlib
import unittest
from unittest.mock import patch

HERE=pathlib.Path(__file__).resolve().parents[1]
old=HERE/"tests/protected_upgrade_transaction_contract.py"
spec=importlib.util.spec_from_file_location("r803_existing_fake_fixture",old)
assert spec and spec.loader
oldtests=importlib.util.module_from_spec(spec)
spec.loader.exec_module(oldtests)
m=oldtests.m

class DualBaselineForwardMigration(oldtests.FakeFixture):
    def setUp(self):
        super().setUp()
        self.patch_target=patch.object(m,"TARGET_VERSION","1.5.6")
        self.patch_target.start()
        self.addCleanup(self.patch_target.stop)
    def rc1_as_current_backend(self):
        for name,rel,target,old_sha,new_sha,mode in m.FILES:
            dest=self.root/target
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes((self.pkg/rel).read_bytes())
            dest.chmod(mode)
            self.assertEqual(m.hash_file(dest),new_sha)
        meta=dict(self.orig,version="1.5.5-rc1")
        self.meta.write_text(json.dumps(meta,sort_keys=True)+"\n")
        self.meta.chmod(0o644)
    def test_public_old_root_to_stable_then_rollback(self):
        initial=self.root_sha()
        result=self.tx.stage(self.pkg)
        self.assertEqual(result["status"],"STAGED")
        self.assertEqual(self.tx.manifest()["fromVersion"],"1.5.2")
        self.assertEqual(self.tx.manifest()["toVersion"],"1.5.6")
        self.assertEqual(self.tx.apply()["status"],"APPLIED")
        self.assertEqual(self.tx.rollback()["status"],"ROLLED_BACK")
        self.assertEqual(self.root_sha(),initial)
        self.assertEqual(json.loads(self.meta.read_text())["version"],"1.5.2")
    def test_private_rc1_root_to_stable_then_rollback(self):
        self.rc1_as_current_backend()
        initial=self.root_sha()
        self.assertEqual(len(initial),4)
        self.assertEqual(self.tx.stage(self.pkg)["status"],"STAGED")
        doc=self.tx.manifest()
        self.assertEqual(doc["fromVersion"],"1.5.5-rc1")
        self.assertEqual(doc["toVersion"],"1.5.6")
        for name,rel,target,old_sha,new_sha,mode in m.FILES:
            self.assertEqual(doc["files"][name]["old"],new_sha)
        self.assertEqual(self.tx.apply()["status"],"APPLIED")
        self.assertEqual(json.loads(self.meta.read_text())["version"],"1.5.6")
        self.assertEqual(self.tx.rollback()["status"],"ROLLED_BACK")
        self.assertEqual(json.loads(self.meta.read_text())["version"],"1.5.5-rc1")
        self.assertEqual(self.root_sha(),initial)
    def test_private_rc1_root_tampered_source_fails_before_slot(self):
        self.rc1_as_current_backend()
        p=self.root/m.FILES[0][2]
        p.write_bytes(b"tampered previously installed backend")
        with self.assertRaisesRegex(RuntimeError,"OLD_FILE_SHA|BASELINE"):
            self.tx.stage(self.pkg)
        self.assertFalse(self.tx.pending.exists())
    def test_unknown_old_root_version_rejected(self):
        data=dict(self.orig,version="1.5.3")
        self.meta.write_text(json.dumps(data)+"\n")
        with self.assertRaisesRegex(RuntimeError,"OLD_ROOT_VERSION"):
            self.tx.stage(self.pkg)
        self.assertFalse(self.tx.pending.exists())

if __name__=="__main__":
    suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName("DualBaselineForwardMigration.test_"+x,__name__) for x in ())
    suite=unittest.TestSuite([
       DualBaselineForwardMigration("test_public_old_root_to_stable_then_rollback"),
       DualBaselineForwardMigration("test_private_rc1_root_to_stable_then_rollback"),
       DualBaselineForwardMigration("test_private_rc1_root_tampered_source_fails_before_slot"),
       DualBaselineForwardMigration("test_unknown_old_root_version_rejected")
    ])
    r=unittest.TextTestRunner(verbosity=2).run(suite)
    print("R803_DUAL_BASELINE_FORWARD_CONTRACT",r.testsRun,"PASS" if r.wasSuccessful() else "FAIL")
    raise SystemExit(0 if r.wasSuccessful() else 1)
