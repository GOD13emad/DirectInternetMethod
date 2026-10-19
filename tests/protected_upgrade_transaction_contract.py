#!/usr/bin/env python3
"""R519 rootless fake-filesystem negative-first upgrade transaction validation.
DOES NOT execute protected CLI, use real /usr/lib, sudo, pkexec, systemctl,
Tailscale, user configuration or network. Fixtures are isolated per test.
"""
from __future__ import annotations
import fcntl,importlib.util,hashlib,json,os,pathlib,stat,tempfile,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE=ROOT/"linux/system/protected_upgrade_transaction.py"
spec=importlib.util.spec_from_file_location("dim_r518_txn",SOURCE)
assert spec and spec.loader
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
def sha(raw):return hashlib.sha256(raw).hexdigest().upper()

class FakeFixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="R519_FAKE_",dir=str(ROOT))
        self.root=pathlib.Path(self.temp.name)
        (self.root/"run").mkdir(mode=0o755)
        self.pkg=self.root/"package"
        self.pkg.mkdir()
        self.files=[]
        for name,rel,target,old,new,mode in m.FILES:
            source=(ROOT/"linux"/rel)
            self.assertTrue(source.is_file(),rel)
            content=source.read_bytes()
            self.assertEqual(sha(content),new)
            local=self.pkg/rel;local.parent.mkdir(exist_ok=True,parents=True)
            local.write_bytes(content)
            dest=self.root/target;dest.parent.mkdir(exist_ok=True,parents=True)
            if old:
                old_content=("BASELINE_FAKE_"+name).encode()
                dest.write_bytes(old_content)
                os.chmod(dest,mode)
                old=sha(old_content)
            self.files.append((name,rel,target,old,new,mode))
        self.static={}
        for name in m.STATIC_ROOT:
            p=self.root/name;p.parent.mkdir(exist_ok=True,parents=True)
            data=("IMMUTABLE_FAKE_"+name).encode()
            p.write_bytes(data)
            self.static[name]=sha(data)
        self.meta=self.root/m.METADATA
        self.meta.parent.mkdir(parents=True,exist_ok=True)
        self.orig={"schema":1,"version":"1.5.2","user":"mmz","uid":1000,"home":"/home/mmz"}
        self.meta.write_text(json.dumps(self.orig,sort_keys=True)+"\n")
        self.meta.chmod(0o644)
        uidfile=self.root/"etc/directinternetmethod.uid"
        uidfile.parent.mkdir(parents=True,exist_ok=True)
        uidfile.write_text("1000\n")
        self.tx=m.RootTransaction(self.root)
        self.patch_files=patch.object(m,"FILES",tuple(self.files))
        self.patch_static=patch.object(m,"STATIC_ROOT",dict(self.static))
        self.patch_files.start();self.patch_static.start()
    def tearDown(self):
        self.patch_files.stop();self.patch_static.stop()
        self.temp.cleanup()
    def root_sha(self):
        return {name:m.hash_file(self.root/target) if (self.root/target).exists() else None
                for name,rel,target,old,new,mode in self.files}
    def original_sha(self):
        return {name:old for name,rel,target,old,new,mode in self.files}
    def all_old(self):
        self.assertEqual(self.root_sha(),self.original_sha())
        self.assertEqual(json.loads(self.meta.read_text())["version"],"1.5.2")
    def all_new(self):
        self.assertEqual(self.root_sha(),{name:new for name,rel,target,old,new,mode in self.files})
        self.assertEqual(json.loads(self.meta.read_text())["version"],m.TARGET_VERSION)
    def test_success_stage_apply_rollback(self):
        self.all_old()
        self.assertEqual(self.tx.status()["status"],"NO_PENDING_UPGRADE")
        self.assertEqual(self.tx.stage(self.pkg)["status"],"STAGED")
        self.assertEqual(self.tx.status()["status"],"STAGED")
        self.all_old()
        self.assertEqual(self.tx.apply()["status"],"APPLIED")
        self.all_new()
        self.assertEqual(self.tx.rollback()["status"],"ROLLED_BACK")
        self.all_old()
        self.assertEqual(self.tx.status()["status"],"ROLLED_BACK")
    def test_failure_after_1(self):self.inject_partial_fail(1)
    def test_failure_after_2(self):self.inject_partial_fail(2)
    def test_failure_after_3(self):self.inject_partial_fail(3)
    def test_failure_after_4(self):self.inject_partial_fail(4)
    def inject_partial_fail(self,num):
        self.tx.stage(self.pkg)
        with self.assertRaisesRegex(RuntimeError,"INJECTED_TEST_FAILURE"):
            self.tx.apply(fail_after=num)
        self.all_old()
        self.assertEqual(self.tx.status()["status"],"ROLLED_BACK")
    def test_initial_symlink_failclosed(self):
        h=self.root/"usr/lib/directinternetmethod/direct_method_helper.sh"
        h.unlink();h.symlink_to(self.meta)
        with self.assertRaisesRegex(RuntimeError,"MISSING_OR_SYMLINK"):
            self.tx.stage(self.pkg)
        self.assertFalse(self.tx.pending.exists())
    def test_tampered_source_refused(self):
        bad=self.pkg/"system/encrypted_selective_dns.py"
        bad.write_bytes(b'fake malicious source')
        with self.assertRaisesRegex(RuntimeError,"PACKAGE_SOURCE_SHA"):
            self.tx.stage(self.pkg)
        self.assertFalse(self.tx.pending.exists())
        self.all_old()
    def test_existing_pending_refuses_rerun(self):
        self.tx.stage(self.pkg)
        with self.assertRaisesRegex(RuntimeError,"SLOT_ALREADY_EXISTS"):self.tx.stage(self.pkg)
        self.all_old()
    def test_tampered_pending_refuses_apply(self):
        self.tx.stage(self.pkg)
        dest=self.tx.pending/"new/encrypted_controller"
        dest.write_bytes(b'CHANGED_PAYLOAD')
        with self.assertRaisesRegex(RuntimeError,"PENDING_NEW_SHA"):
            self.tx.apply()
        self.all_old()
    def test_tampered_original_refuses_apply(self):
        self.tx.stage(self.pkg)
        target=self.root/self.files[0][2]
        target.write_bytes(b'FOREIGN_EDIT')
        with self.assertRaisesRegex(RuntimeError,"FOREIGN_TARGET_MODIFICATION"):
            self.tx.apply()
        self.assertEqual(target.read_bytes(),b'FOREIGN_EDIT')
    def test_rollback_refuses_unrecognized_changes(self):
        self.tx.stage(self.pkg)
        self.tx.apply()
        edited=self.root/self.files[1][2]
        edited.write_bytes(b'FOREIGN_AFTER_APPLY')
        with self.assertRaisesRegex(RuntimeError,"FOREIGN_TARGET_MODIFICATION"):
            self.tx.rollback()
        self.assertEqual(edited.read_bytes(),b'FOREIGN_AFTER_APPLY')
        self.assertEqual(self.tx.status()["status"],"APPLIED")
    def test_metadata_change_before_apply_refused(self):
        self.tx.stage(self.pkg)
        self.meta.write_text('{"schema":1,"version":"BOGUS"}')
        with self.assertRaisesRegex(RuntimeError,"FOREIGN_METADATA_CHANGE"):
            self.tx.apply()
    def test_source_symlink_refuses_stage(self):
        f=self.pkg/"system/encrypted_selective_dns.py"
        f.unlink();f.symlink_to(self.pkg/"app/direct_method_helper.sh")
        with self.assertRaisesRegex(RuntimeError,"MISSING_OR_SYMLINK"):self.tx.stage(self.pkg)
    def test_metadata_invalid_user_refuses_stage(self):
        self.orig["uid"]=-1
        self.meta.write_text(json.dumps(self.orig))
        with self.assertRaisesRegex(RuntimeError,"OWNER_UID"):self.tx.stage(self.pkg)
    def test_static_backend_changed_refuses_stage(self):
        x=self.root/next(iter(self.static))
        x.write_text("tampered")
        with self.assertRaisesRegex(RuntimeError,"BASELINE_STATIC_SHA"):self.tx.stage(self.pkg)
    def test_missing_acceptance_refuses_commit(self):
        self.tx.stage(self.pkg);self.tx.apply()
        with self.assertRaisesRegex(RuntimeError,"NATIVE_ACCEPTANCE_MISSING"):
            self.tx.commit(self.root/"NO_SATISFACTORY_NATIVE_RUN.json")
        self.all_new()
        self.assertTrue(self.tx.pending.exists())
    def test_r783_relative_source_refuses_before_pending_creation(self):
        # The actual read remains descriptor-relative to a validated absolute
        # package source; a relative caller path must not be accepted.
        relative=pathlib.Path(os.path.relpath(self.pkg,ROOT))
        with self.assertRaisesRegex(RuntimeError,"PACKAGE_SOURCE"):
            self.tx.stage(relative)
        self.assertFalse(self.tx.pending.exists())
        self.all_old()

    def test_r783_acceptance_symlink_fails_without_commit(self):
        self.tx.stage(self.pkg)
        self.tx.apply()
        link=self.root/"r783_receipt_symlink.json"
        link.symlink_to(self.meta)
        with self.assertRaisesRegex(RuntimeError,"NATIVE_ACCEPTANCE_MISSING"):
            self.tx.commit(link)
        self.assertEqual(self.tx.status()["status"],"APPLIED")
        self.all_new()

    def test_r783_acceptance_parent_symlink_fails_without_commit(self):
        self.tx.stage(self.pkg)
        self.tx.apply()
        alias=self.root/"r783_parent_symlink"
        alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError,"UNSAFE_PARENT_COMPONENT"):
            self.tx.commit(alias/"receipt.json")
        self.assertEqual(self.tx.status()["status"],"APPLIED")
        self.all_new()

    def test_acceptance_requires_real_gates(self):
        self.tx.stage(self.pkg);self.tx.apply()
        meta=self.tx.manifest()
        f=self.root/"acceptance.json"
        a={"revision":"R519","status":"PASS_NATIVE_ROOT_UPGRADE",
           "sourceRootSHA":m.sha(m.canonical(meta["files"])),
           "protectedMetadataSHA":meta["newMetadataSHA"],
           "nativeStartStopRecovery":False,"tailscalePreserved":True,
           "physicalDNSPreserved":True}
        f.write_text(json.dumps(a))
        with self.assertRaisesRegex(RuntimeError,"NATIVE_ACCEPTANCE_NOT_PROVEN"):
            self.tx.commit(f)
        a["nativeStartStopRecovery"]=True
        f.write_text(json.dumps(a))
        self.assertEqual(self.tx.commit(f)["status"],"COMMITTED")
        self.all_new()
        self.assertTrue(self.tx.pending.exists(),"Baseline backup held until Brain promotion")
        with self.assertRaisesRegex(RuntimeError,"UNSAFE_APPLY_RERUN"):
            self.tx.apply()
    def test_atomic_metadata_and_modes(self):
        self.tx.stage(self.pkg);self.tx.apply()
        for name,rel,target,old,new,mode in self.files:
            self.assertEqual(stat.S_IMODE((self.root/target).stat().st_mode),mode)
        self.assertEqual(stat.S_IMODE(self.meta.stat().st_mode),0o644)
        self.assertEqual(stat.S_IMODE(self.tx.pending.stat().st_mode),0o700)
        self.assertEqual(stat.S_IMODE((self.tx.pending/"manifest.json").stat().st_mode),0o600)
    def test_no_foreign_unknown_tree_removed(self):
        self.tx.stage(self.pkg)
        unknown=self.tx.pending/"foreign.txt"
        unknown.write_text("UNOWNED")
        self.tx.apply()
        self.tx.rollback()
        self.assertEqual(unknown.read_text(),"UNOWNED")
        self.assertTrue(self.tx.pending.exists())
    def test_native_action_lock_busy_refuses_stage(self):
        lock=self.root/m.ACTION_LOCK
        fd=os.open(lock,os.O_RDWR|os.O_CREAT,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.tx.stage(self.pkg)
            self.assertFalse(self.tx.pending.exists())
            self.all_old()
        finally:
            os.close(fd)
    def test_upgrade_lock_busy_refuses_stage(self):
        fd=os.open(self.tx.lock,os.O_RDWR|os.O_CREAT,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.tx.stage(self.pkg)
            self.assertFalse(self.tx.pending.exists())
            self.all_old()
        finally:
            os.close(fd)
    def test_native_action_lock_symlink_refuses_mutation(self):
        lock=self.root/m.ACTION_LOCK
        lock.symlink_to(self.meta)
        with self.assertRaises(OSError):
            self.tx.stage(self.pkg)
        self.all_old()
        self.assertFalse(self.tx.pending.exists())
    def test_file_list_exact(self):
        self.tx.stage(self.pkg)
        mdata=self.tx.manifest()
        mdata["files"]["extra"]={"target":"etc/shadow"}
        self.tx.write_manifest(mdata)
        with self.assertRaisesRegex(RuntimeError,"MANIFEST_FILE_LIST"):
            self.tx.apply()
        self.all_old()
    def test_no_product_service_commands(self):
        # Search for prohibited side-effect operations in the pure upgrade module.
        txt=SOURCE.read_text("utf8")
        for term in ('systemctl start','tailscale set','tailscale down','nft add',
                     'ip route add','shutil.rmtree("/usr','rm -rf /usr'):
            self.assertNotIn(term,txt)
    def test_cli_never_accepts_root_prefix(self):
        txt=SOURCE.read_text("utf8")
        self.assertNotIn('p.add_argument("--root"',txt)
        self.assertIn("need(os.geteuid()==0",txt)
        self.assertIn("RootTransaction() # No CLI root-prefix",txt)

if __name__=="__main__":
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(FakeFixture)
    r=unittest.TextTestRunner(verbosity=2).run(suite)
    print(f"R519_NEGATIVE_FIRST_ROOT_TRANSACTION cases={r.testsRun} fails={len(r.failures)} errors={len(r.errors)}")
    raise SystemExit(0 if r.wasSuccessful() else 1)
