#!/usr/bin/env python3
"""R552 source-extracted regression: worker/timer logic, ZERO installed actions."""
import hashlib,importlib.util,json,os,pathlib,tempfile,types,unittest
SRC=pathlib.Path(__file__).with_name("r552_native_upgrade_guard_candidate.py")
SOURCE_SHA="C977DE6C8E31D6F1E6134DF4E46F080A2D2BFB5BD7854119C2B46A0FB175BAFB"
assert hashlib.sha256(SRC.read_bytes()).hexdigest().upper()==SOURCE_SHA
spec=importlib.util.spec_from_file_location("r552_candidate",SRC)
g=importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
class FakeTx:
    def __init__(self,phase):
        self.native=True;self.phase=phase;self.calls=[]
    def status(self):self.calls.append("status");return {"status":self.phase}
    def rollback(self):self.calls.append("rollback");return {"status":"ROLLED_BACK"}
class Cases(unittest.TestCase):
    def setUp(self):
        self.dir=tempfile.TemporaryDirectory(prefix="DIM_R552_FAKE_")
        self.addCleanup(self.dir.cleanup)
        p=pathlib.Path(self.dir.name)
        self.home=p/"home";self.home.mkdir(mode=0o700)
        self.result=p/"result.json"
        self.original={k:getattr(g,k) for k in
                       ("GUARD","RESULT","WORKER","SERVICE","TIMER","verify_guard_files",
                        "imported_root","verify_installed_after_restore","command","write_new")}
        self.addCleanup(lambda:[setattr(g,k,v) for k,v in self.original.items()])
        g.GUARD=p;g.RESULT=self.result;g.WORKER=SRC.resolve()
        # Preserve the production root-owner constraint; in a nonroot
        # synthetic HOME intercept ONLY the test-owned receipt destination.
        def synthetic_receipt(target,blob,mode):
            self.assertEqual(target,self.result)
            self.assertEqual(mode,0o600)
            with target.open("xb") as stream:stream.write(blob)
            target.chmod(0o600)
        g.write_new=synthetic_receipt
        g.SERVICE=p/"unit.service";g.TIMER=p/"unit.timer"
        self.fake={"user":"runner","home":str(self.home),"uid":1000}
        g.verify_guard_files=lambda:self.fake
        self.events=[]
        g.verify_installed_after_restore=lambda j:self.events.append("validate_restored")
        g.command=lambda args,timeout=15:self.events.append("user_command") or types.SimpleNamespace(returncode=0,stdout="",stderr="")
        self.old_geteuid=g.os.geteuid
        g.os.geteuid=lambda:0
        self.addCleanup(lambda:setattr(g.os,"geteuid",self.old_geteuid))
    def test_01_independent_timer_survives_reboot(self):
        s,t=g.unit_templates()
        self.assertIn(b"OnActiveSec=480s",t)
        self.assertIn(b"WantedBy=timers.target",t)
        self.assertNotIn(b"OnBootSec=",t)
        self.assertIn(b"User=root",s)
        self.assertIn(b"rollback",s)
    def test_02_no_pending_does_not_change_system(self):
        tx=FakeTx("NO_PENDING_UPGRADE");g.imported_root=lambda:tx
        self.assertEqual(g.rollback_worker(),0)
        self.assertEqual(json.loads(self.result.read_text())["status"],"NO_CHANGE_NO_PENDING")
        self.assertNotIn("user_command",self.events)
        self.assertEqual(tx.calls,["status"])
    def test_03_active_owned_engine_never_mutates_on_timeout(self):
        tx=FakeTx("APPLIED");g.imported_root=lambda:tx
        s=self.home/g.USER_REL/"directmethod/state.json"
        s.parent.mkdir(parents=True);s.write_text("{}")
        self.assertEqual(g.rollback_worker(),90)
        self.assertIn("LIVE_ENGINE_REQUIRES_LOCAL_RECOVERY",
                      json.loads(self.result.read_text())["failure"])
        self.assertNotIn("user_command",self.events)
        self.assertEqual(tx.calls,["status"])
    def test_04_staged_unprivileged_user_then_root_rollback(self):
        tx=FakeTx("APPLIED");g.imported_root=lambda:tx
        slot=self.home/g.PENDING_REL;slot.mkdir(parents=True)
        self.assertEqual(g.rollback_worker(),0)
        out=json.loads(self.result.read_text())
        self.assertEqual(out["status"],"PASS_AUTONOMOUS_TWO_SIDED_RESTORATION")
        self.assertEqual(out["userRollback"],"PASS")
        self.assertEqual(out["rootRollback"],"PASS")
        self.assertEqual(self.events,["user_command","validate_restored"])
        self.assertEqual(tx.calls,["status","rollback"])
    def test_05_staged_user_only_restore(self):
        tx=FakeTx("NO_PENDING_UPGRADE");g.imported_root=lambda:tx
        slot=self.home/g.PENDING_REL;slot.mkdir(parents=True)
        self.assertEqual(g.rollback_worker(),0)
        self.assertEqual(tx.calls,["status"])
        self.assertEqual(json.loads(self.result.read_text())["status"],
                         "PASS_AUTONOMOUS_TWO_SIDED_RESTORATION")
    def test_06_rejected_user_rollback_never_attempts_root(self):
        tx=FakeTx("APPLIED");g.imported_root=lambda:tx
        slot=self.home/g.PENDING_REL;slot.mkdir(parents=True)
        g.command=lambda args,timeout=15:types.SimpleNamespace(returncode=22,stdout="",stderr="fake rejection")
        self.assertEqual(g.rollback_worker(),90)
        self.assertEqual(tx.calls,["status"])
        self.assertIn("USER_ROLLBACK",json.loads(self.result.read_text())["failure"])
    def test_07_committed_does_not_rollback(self):
        tx=FakeTx("COMMITTED");g.imported_root=lambda:tx
        self.assertEqual(g.rollback_worker(),0)
        self.assertEqual(json.loads(self.result.read_text())["status"],
                         "NO_ROLLBACK_ALREADY_COMMITTED")
        self.assertEqual(tx.calls,["status"])
    def test_08_idempotent_second_run_denied_by_owned_receipt(self):
        tx=FakeTx("NO_PENDING_UPGRADE");g.imported_root=lambda:tx
        self.assertEqual(g.rollback_worker(),0)
        self.assertEqual(g.rollback_worker(),0)
        self.assertEqual(json.loads(self.result.read_text())["status"],
                         "NO_CHANGE_NO_PENDING")
        # Note second call currently computes but does not overwrite receipt.
    def test_09_sources_are_not_host_install_commands(self):
        src=SRC.read_text()
        self.assertNotIn("sudo -S",src)
        self.assertNotIn("tailscale down",src)
        self.assertNotIn("nmcli con down",src)
        self.assertIn("Path(__file__).resolve()==WORKER",src)
    def test_10_readiness_worker_does_not_query_elapsed_active_timer(self):
        txt=SRC.read_text()
        self.assertIn("j=verify_guard_files()",txt)
        self.assertNotIn("j=verify_timer()\n        home=Path(j",txt)
if __name__=="__main__":
    t=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Cases))
    print("R552_SOURCE_EXTRACTED tests=",t.testsRun,"failures=",len(t.failures),"errors=",len(t.errors))
    raise SystemExit(0 if t.wasSuccessful() else 1)
