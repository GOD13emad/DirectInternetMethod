#!/usr/bin/env python3
"""R764 nonprivileged negative-first parent-symlink path tests.
All stage/commit work uses R519's disposable fake filesystem under tests/.
"""
import importlib.util
import json
import pathlib
import unittest

HERE=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("r764_r519_fake_fixture",
                                            HERE/"protected_upgrade_transaction_contract.py")
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class R764PathParents(unittest.TestCase):
    def setUp(self):
        self.fake=module.FakeFixture("test_success_stage_apply_rollback")
        self.fake.setUp()
    def tearDown(self):
        self.fake.tearDown()

    def test_symlink_parent_of_source_package_is_rejected_before_stage(self):
        actual=self.fake.root/"real-source-parent"
        actual.mkdir()
        real_package=actual/"package"
        self.fake.pkg.rename(real_package)
        alias=self.fake.root/"source-parent-alias"
        alias.symlink_to(actual,target_is_directory=True)
        sourced=alias/"package"
        self.assertTrue(sourced.is_dir())
        self.assertFalse(sourced.is_symlink())
        with self.assertRaisesRegex(RuntimeError,"FAIL_CLOSED_UNSAFE_PARENT_COMPONENT"):
            self.fake.tx.stage(sourced)
        self.assertFalse(self.fake.tx.pending.exists())

    def test_symlink_parent_of_root_acceptance_receipt_is_rejected(self):
        self.fake.tx.stage(self.fake.pkg)
        self.fake.tx.apply()
        doc=self.fake.tx.manifest()
        root=self.fake.root/"actual-acceptance-parent"
        root.mkdir()
        receipt=root/"acceptance.json"
        data={"revision":"R519","status":"PASS_NATIVE_ROOT_UPGRADE",
              "sourceRootSHA":module.m.sha(module.m.canonical(doc["files"])),
              "protectedMetadataSHA":doc["newMetadataSHA"],
              "transactionNonce":doc["transactionNonce"],
              "nativeStartStopRecovery":True,
              "tailscalePreserved":True,"physicalDNSPreserved":True}
        receipt.write_text(json.dumps(data)+"\n")
        alias=self.fake.root/"receipt-parent-alias"
        alias.symlink_to(root,target_is_directory=True)
        bypass=alias/"acceptance.json"
        self.assertTrue(bypass.is_file())
        self.assertFalse(bypass.is_symlink())
        with self.assertRaisesRegex(RuntimeError,"FAIL_CLOSED_UNSAFE_PARENT_COMPONENT"):
            self.fake.tx.commit(bypass)
        self.assertEqual(self.fake.tx.status()["status"],"APPLIED")

    def test_untrusted_native_acceptance_owner_is_rejected(self):
        # No privilege requested: fake-owned receipt under a user-owned test
        # directory must not become a native Root acceptance proof.
        f=self.fake.root/"user-owned-test-receipt.json"
        f.write_text("{}")
        with self.assertRaisesRegex(RuntimeError,"FAIL_CLOSED_RECEIPT_PARENT_OWNER"):
            module.m.guarded_file_bytes(f,native_receipt=True,limit=65536)

if __name__=="__main__":
    unittest.main(verbosity=2)
