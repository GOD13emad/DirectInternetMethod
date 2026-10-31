#!/usr/bin/env python3
"""R845: fake-root private 1.5.6 -> 1.5.7 positive and negative regression.

No native Root, DNS, VPN, network route, polkit or actual installation.
"""
import importlib.util, json, pathlib, unittest
R=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("r845_fixture",R/"tests/protected_upgrade_transaction_contract.py")
assert spec and spec.loader
base=importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
m=base.m
class Private156To157(base.FakeFixture):
    def private_156(self):
        for name,source,target,old,new,mode in m.FILES:
            p=self.root/target
            p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes((self.pkg/source).read_bytes())
            p.chmod(mode)
            self.assertEqual(m.hash_file(p),new)
        meta=dict(self.orig,version="1.5.6")
        self.meta.write_text(json.dumps(meta,sort_keys=True)+"\n")
        self.meta.chmod(0o644)
    def test_forward_and_rollback(self):
        self.private_156()
        before=self.root_sha()
        self.assertEqual(m.TARGET_VERSION,"1.5.7")
        self.assertEqual(self.tx.stage(self.pkg)["status"],"STAGED")
        doc=self.tx.manifest()
        self.assertEqual(doc["fromVersion"],"1.5.6")
        self.assertEqual(doc["toVersion"],"1.5.7")
        self.assertEqual(self.tx.apply()["status"],"APPLIED")
        self.assertEqual(json.loads(self.meta.read_text())["version"],"1.5.7")
        self.assertEqual(self.tx.rollback()["status"],"ROLLED_BACK")
        self.assertEqual(json.loads(self.meta.read_text())["version"],"1.5.6")
        self.assertEqual(self.root_sha(),before)
    def test_tampered_root_denied(self):
        self.private_156()
        p=self.root/m.FILES[0][2]
        p.write_bytes(b"foreign modified root code")
        with self.assertRaisesRegex(RuntimeError,"BASELINE|OLD_FILE_SHA"):
            self.tx.stage(self.pkg)
        self.assertFalse(self.tx.pending.exists())
    def test_unknown_version_denied(self):
        self.private_156()
        meta=json.loads(self.meta.read_text())
        meta["version"]="1.5.8"
        self.meta.write_text(json.dumps(meta)+"\n")
        with self.assertRaisesRegex(RuntimeError,"OLD_ROOT_VERSION"):
            self.tx.stage(self.pkg)
        self.assertFalse(self.tx.pending.exists())
    def test_version_pair_whitelist(self):
        s=(R/"linux/system/upgrade_guard.py").read_text()
        self.assertIn('("1.5.6","1.5.6")',s)
        self.assertNotIn('("1.5.6","1.5.5-rc1")',s)
if __name__=="__main__":
    tests=("test_forward_and_rollback","test_tampered_root_denied","test_unknown_version_denied","test_version_pair_whitelist")
    run=unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(Private156To157(t) for t in tests))
    raise SystemExit(0 if run.wasSuccessful() else 1)
