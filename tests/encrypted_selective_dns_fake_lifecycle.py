#!/usr/bin/env python3
"""R517 fake-root integration tests. All commands are captured and simulated.
No real systemd, D-Bus, NetworkManager, kernel link, NFT, DNS, or device access.
This tests lifecycle API state and owned cleanup, not real deployment.
"""
from __future__ import annotations
from contextlib import ExitStack,contextmanager
import importlib.util,json,os,pathlib,subprocess,tempfile,unittest
from unittest.mock import patch

BASE=pathlib.Path(__file__).resolve().parents[1]
FILE=BASE/"linux/system/encrypted_selective_dns.py"
spec=importlib.util.spec_from_file_location("r517_root_mock",FILE)
assert spec and spec.loader
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class FakeWorld:
    def __init__(self,directory:pathlib.Path):
        self.dir=directory
        self.state_dir=directory/"state"
        self.state=self.state_dir/"session.json"
        self.config=directory/"ctrld.toml"
        self.user_home=directory/"home"
        self.native=self.user_home/".local/share/DirectInternetMethod/directmethod/state.json"
        self.native.parent.mkdir(parents=True,exist_ok=True)
        self.virtual_nfqws=directory/"owned-nfqws"
        self.virtual_nfqws.write_bytes(b"FAKE_NOT_EXECUTED_BINARY")
        self.record=[]
        self.active={}
        self.link_index=11
        self.tailscale_id="A"*64
        self.physical={"dns":["192.168.8.1"],"domains":[],"default":True}
        self.local={"dns":[f"{m.IP}:{m.PORT}"],"domains":["~"+x for x in m.TARGETS],"default":False}
    def pseudo_call(self,*args,**kwargs):
        self.record.append(tuple(args))
        if args[0]=="systemd-run":
            name=next((z[7:] for z in args if z.startswith("--unit=")),None)
            assert name
            self.active[name+".service" if not "--on-active="+str(m.BACKSTOP_SEC)+"s" in args else name+".timer"]=True
            # Native controller creates timer with --on-active and --on-unit-active.
            if any(x.startswith("--on-active=") for x in args):
                self.active.pop(name+".service",None)
                self.active[name+".timer"]=True
        if args[:2]==("systemctl","stop"):
            self.active[args[2]]=False
        if args[:3]==("systemctl","show","directinternetmethod-nfqws-1000.service"):
            if "ActiveState" in args:return subprocess.CompletedProcess(args,0,"active\n","")
            if "MainPID" in args:return subprocess.CompletedProcess(args,0,"5454\n","")
        if args[:2]==("systemctl","show") and "MainPID" in args:
            return subprocess.CompletedProcess(args,0,"4567\n","")
        if args[:3]==("tailscale","status","--json"):
            return subprocess.CompletedProcess(args,0,json.dumps({"BackendState":"Running"}),"")
        return subprocess.CompletedProcess(args,0,"","")
    def unit_state(self,unit,timer=False):
        assert (m.TIMER_RE if timer else m.UNIT_RE).fullmatch(unit)
        return "active" if self.active.get(unit,False) else "inactive"
    def link_state(self,iface):
        if iface==m.IFACE:return dict(self.local)
        if iface=="enp7s0":return dict(self.physical)
        raise AssertionError("foreign interface "+iface)
    def read_state(self):
        return m.validate_state(json.loads(self.state.read_text())) if self.state.exists() else None
    def patch_all(self):
        st=ExitStack()
        self.stack=st
        def proxy_text(path,*args,**kwargs):
            if str(path)=="/sys/class/net/dimesd0/ifindex":return str(self.link_index)
            return self.orig_read_text(path,*args,**kwargs)
        self.orig_read_text=pathlib.Path.read_text
        real_stat=pathlib.Path.stat
        def simulated_owner_stat(path,*args,**kwargs):
            result=real_stat(path,*args,**kwargs)
            if str(path) in (str(self.state_dir),str(self.config),str(self.state)):
                # Root-owned test-private files only: virtual uid=0, no chown.
                values=list(result)
                values[4]=0
                return os.stat_result(values)
            if str(path)==str(self.native):
                # The native user State must belong to the simulated uid=1000,
                # independently of the real GitHub Actions runner's uid.
                # No host ownership or permissions are changed.
                values=list(result)
                values[4]=1000
                return os.stat_result(values)
            return result
        st.enter_context(patch.object(pathlib.Path,"stat",simulated_owner_stat))
        st.enter_context(patch.object(pathlib.Path,"read_text",proxy_text))
        real_realpath=os.path.realpath
        def simulated_realpath(path,*args,**kwargs):
            if str(path)=="/proc/4567/exe":return str(m.CTRLD)
            if str(path)=="/proc/5454/exe":return str(self.virtual_nfqws)
            return real_realpath(path,*args,**kwargs)
        st.enter_context(patch.object(os.path,"realpath",simulated_realpath))
        for key,val in {
            "STATE_DIR":self.state_dir,
            "STATE":self.state,
            "CONFIG":self.config,
            "NFQWS":self.virtual_nfqws,
            "file_sha":lambda p:m.VERSIONED_NFQWS_SHA if p==self.virtual_nfqws else "UNEXPECTED_FILE_HASH",
            "root":lambda:None,
            "require_consent":lambda uid,home:None,
            "network_preflight":lambda phy:dict(self.physical),
            "tailscale_fingerprint":lambda:self.tailscale_id,
            "policy_bytes":lambda router:b"trusted-test-config",
            "dummy_identity":lambda state:self.link_index if state["dummyIndex"] else None,
            "dns_is_owned":lambda:True,
            "public_dns":lambda name:True,
            "link_dns":lambda idx:self.record.append(("LINK_DNS_VIRTUAL",idx)),
            "unit_state":self.unit_state,
            "call":self.pseudo_call,
            "link_state":self.link_state,
            "runtime_tunnel_guard":lambda phy:self.record.append(("VPN_GUARD_READONLY",phy)),
            "read_state":self.read_state,
        }.items():st.enter_context(patch.object(m,key,val))
        return st
    def make_native(self):
        self.native.write_text(json.dumps({
            "schema":3,"status":"ACTIVE","physicalInterface":"enp7s0",
            "tailscaleCoexistence":True,"dnsMode":"system-preserved",
            "selectiveDnsEncrypted":True,"selectiveDns":False,
            "nfqwsUnit":"directinternetmethod-nfqws-1000.service",
            "scope":"targeted","strategy":"balanced","nfqwsPid":5454
        }))
        self.native.chmod(0o600)

class FakeLifecycle(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=str(BASE),prefix="R517_FAKE_NO_HOST_")
        self.world=FakeWorld(pathlib.Path(self.temp.name))
        self.stack=self.world.patch_all()
    def tearDown(self):
        self.stack.close()
        self.temp.cleanup()
    def test_owned_full_activate_commit_restore(self):
        w=self.world
        response=m.activate(1000,"enp7s0",str(w.user_home))
        self.assertEqual(response["state"],"ARMED")
        active=w.read_state()
        self.assertEqual(active["phase"],"ARMING")
        self.assertTrue(w.state.is_file() and w.config.is_file())
        self.assertTrue(w.active[active["monitorUnit"]])
        self.assertTrue(w.active[active["backstopTimer"]])
        self.assertTrue(w.active[active["ctrldUnit"]])
        self.assertIn(("LINK_DNS_VIRTUAL",w.link_index),w.record)
        # Before native helper creates state: commit must reject, remain ARMED.
        with self.assertRaisesRegex(RuntimeError,"NATIVE_STATE_MISSING_OR_SYMLINK"):m.commit()
        self.assertEqual(w.read_state()["phase"],"ARMING")
        w.make_native()
        committed=m.commit()
        self.assertEqual(committed["state"],"ACTIVE")
        self.assertEqual(m.status()["state"],"ACTIVE")
        rollback=m.rollback()
        self.assertEqual(rollback["state"],"RESTORED")
        self.assertFalse(w.state.exists())
        self.assertFalse(w.config.exists())
        self.assertFalse(w.state_dir.exists())
        self.assertFalse(any(w.active.values()))
        self.assertEqual(m.rollback()["state"],"NO_SESSION")
        # No systemd or D-Bus call ran: everything was fake.
        self.assertTrue(any(x[0]=="busctl" for x in w.record))
        self.assertTrue(any(x[0]=="systemctl" for x in w.record))
    def test_arm_failure_cleanup_before_link(self):
        w=self.world
        old=w.pseudo_call
        def fail_on_add(*args,**kwargs):
            if args[:3]==("ip","link","add"):
                raise RuntimeError("SIMULATED_IP_LINK_ADD_DENIED")
            return old(*args,**kwargs)
        with patch.object(m,"call",side_effect=fail_on_add):
            with self.assertRaisesRegex(RuntimeError,"SIMULATED_IP_LINK_ADD_DENIED"):
                m.activate(1000,"enp7s0",str(w.user_home))
        self.assertFalse(w.state.exists(),"STATE_NOT_RESTORED")
        self.assertFalse(w.config.exists(),"CONFIG_NOT_RESTORED")
        self.assertFalse(any(w.active.values()),"OWNED_UNITS_STILL_RUNNING")
    def test_state_phase_and_units_exclusive(self):
        w=self.world
        m.activate(1000,"enp7s0",str(w.user_home))
        raw=w.read_state()
        for key in ("ctrldUnit","monitorUnit","backstopTimer"):
            self.assertTrue(w.active[raw[key]])
        self.assertEqual(raw["physicalBaseline"],w.physical)
        self.assertEqual(raw["tailscaleDNS"],"A"*64)
        self.assertEqual(raw["configSha"],m.sha(b"trusted-test-config"))
        self.assertEqual(raw["dummyIndex"],11)
    def test_native_commit_rejects_forged_user_pid(self):
        w=self.world
        m.activate(1000,"enp7s0",str(w.user_home))
        w.make_native()
        doc=json.loads(w.native.read_text())
        doc["nfqwsPid"]=77
        w.native.write_text(json.dumps(doc))
        w.native.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError,"NATIVE_NFQWS_PID_MISMATCH"):
            m.commit()
        self.assertEqual(w.read_state()["phase"],"ARMING")
    def test_native_commit_rejects_user_state_symlink(self):
        w=self.world
        m.activate(1000,"enp7s0",str(w.user_home))
        w.make_native()
        target=w.native.with_name("foreign-native.json")
        w.native.rename(target)
        w.native.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError,"NATIVE_STATE_MISSING_OR_SYMLINK"):
            m.commit()
        self.assertEqual(w.read_state()["phase"],"ARMING")
    def test_owned_monitor_backstop_healthy(self):
        w=self.world
        m.activate(1000,"enp7s0",str(w.user_home))
        w.make_native();m.commit()
        @contextmanager
        def free_lock():
            yield True
        with patch.object(m,"observe_action_lock",free_lock):
            self.assertEqual(m.backstop()["state"],"HEALTHY")
        self.assertTrue(w.state.exists())
        self.assertTrue(w.active[w.read_state()["ctrldUnit"]])
    def test_failed_foreign_dns_restoration_guard(self):
        w=self.world
        m.activate(1000,"enp7s0",str(w.user_home))
        # The system DNS on the owned per-link interface was changed after
        # activation. Never overwrite foreign settings or remove identity.
        w.local={"dns":["8.8.8.8"],"domains":["~other.com"],"default":True}
        with patch.object(m,"dns_is_owned",return_value=False):
            with self.assertRaisesRegex(RuntimeError,"FOREIGN_LINK_DNS_PRESENT"):
                m.rollback()
        self.assertTrue(w.state.is_file())
        self.assertTrue(w.active[w.read_state()["backstopTimer"]])
    def test_stop_only_own_native_binary(self):
        w=self.world
        m.activate(1000,"enp7s0",str(w.user_home))
        # The mock controller must not kill other systemd services.
        previous_realpath=m.os.path.realpath
        def hostile_realpath(p,*a,**kw):
            if str(p)=="/proc/4567/exe":return "/usr/bin/foreign-binary"
            return previous_realpath(p,*a,**kw)
        with patch.object(m.os.path,"realpath",side_effect=hostile_realpath):
            with self.assertRaisesRegex(RuntimeError,"OWNED_CTRLD_PROCESS_MISMATCH"):
                m.rollback()
        self.assertTrue(w.state.exists())

if __name__=="__main__":
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(FakeLifecycle))
    print(f"R517_FAKE_NATIVE_LIFECYCLE cases={result.testsRun} failures={len(result.failures)} errors={len(result.errors)}")
    raise SystemExit(0 if result.wasSuccessful() else 1)
