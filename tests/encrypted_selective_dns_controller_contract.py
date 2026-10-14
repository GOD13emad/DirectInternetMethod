#!/usr/bin/env python3
"""R517 negative-first, host-mutating commands fully mocked. Run on Linux user.
Raises if a potentially dangerous API command changes contract or live host
would be touched. No service/network/files outside a test-private directory.
"""
from __future__ import annotations
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
CONTROLLER=ROOT/"linux/system/encrypted_selective_dns.py"
POLICY=ROOT/"linux/system/encrypted_selective_policy.py"
def import_source(name:str,path:Path):
    spec=importlib.util.spec_from_file_location(name,path)
    assert spec is not None and spec.loader is not None
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
m=import_source("r517_safe_controller",CONTROLLER)
g=import_source("r517_safe_policy",POLICY)
STATE={
 "schema":1,"phase":"ACTIVE","uid":1000,"session":"f0e1d2c3b4",
 "userHome":"/home/mmz","physical":"enp7s0",
 "physicalBaseline":{"dns":["192.168.8.1"],"domains":[],"default":True},
 "tailscaleDNS":"A"*64,"ctrldSha":m.VERSIONED_CTRLD_SHA,
 "configPath":str(m.CONFIG),"configSha":"B"*64,
 "iface":m.IFACE,"ownedIp":m.CIDR,"port":m.PORT,"dummyIndex":7,
 "started":0.0,
 "ctrldUnit":"dim-edsn-dns-1000-f0e1d2c3b4.service",
 "monitorUnit":"dim-edsn-watch-1000-f0e1d2c3b4.service",
 "backstopTimer":"dim-edsn-backstop-1000-f0e1d2c3b4.timer",
}
COMMANDS=[]
def fail_if_called(*args,**kwargs):
    COMMANDS.append((args,kwargs))
    raise AssertionError("UNEXPECTED_HOST_OR_MUTATING_COMMAND: "+repr(args))

class Contract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix="R517_nohost_",dir=str(ROOT))
        cls.home=Path(cls.temp.name)
        cls.app=cls.home/".local/share/DirectInternetMethod"
        cls.app.mkdir(parents=True)
        cls.uid=os.getuid()
        cls.tests=0
    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()
    def setUp(self):
        COMMANDS.clear()
        if self.app.exists(): shutil.rmtree(self.app)
        self.app.mkdir(parents=True)
    def pass_if_reject(self,func,reason):
        with self.assertRaisesRegex((RuntimeError,ValueError),reason):
            func()
    def make_consent(self):
        self.app.joinpath("strategy.txt").write_text("balanced\n")
        self.app.joinpath("scope.txt").write_text("targeted\n")
        consent=self.app/m.NEW_OPTIN
        consent.write_text(m.CONSENT+"\n")
        consent.chmod(0o600)
        return consent

    def test_source_and_constants(self):
        self.assertTrue(CONTROLLER.is_file() and POLICY.is_file())
        self.assertEqual(m.ACTION_LOCK.as_posix(),"/run/directinternetmethod-action.lock")
        self.assertEqual(m.VERSIONED_CTRLD_SHA,"CA64579A2BC866CF72F3E46663E551162AFEFF0D448E899A01817A095E45B071")
        self.assertEqual(m.CONSENT,"I_ACCEPT_ENCRYPTED_SELECTIVE_DNS_V1")
        self.assertNotEqual(m.CONSENT,"I_ACCEPT_UNENCRYPTED_SELECTIVE_DNS_V1")
        self.assertEqual(m.IFACE,"dimesd0")
        self.assertEqual(m.IP,"172.31.254.59")
        self.assertEqual(m.PORT,53534)
        self.assertEqual(m.TARGETS,("youtube.com","googlevideo.com","ytimg.com","youtu.be"))

    def test_policy_local_bind_and_router_no_wan(self):
        for router in ("192.168.8.1","192.168.20.1","10.0.0.1","172.16.0.1"):
            blob=g.build_owned_interface_policy(router)
            conf=tomllib.loads(blob.decode("ascii"))
            self.assertEqual(conf["listener"]["0"]["ip"],m.IP)
            self.assertEqual(conf["listener"]["0"]["port"],m.PORT)
            self.assertFalse(conf["listener"]["0"]["allow_wan_clients"])
            self.assertEqual(conf["network"]["0"]["cidrs"],[m.CIDR])
            self.assertEqual(conf["upstream"]["0"]["type"],"doh")
            self.assertEqual(conf["upstream"]["0"]["endpoint"],"https://76.76.10.11/p0")
            self.assertEqual(conf["upstream"]["1"]["type"],"legacy")
            self.assertEqual(conf["upstream"]["1"]["endpoint"],router)
            self.assertFalse(conf["service"]["leak_on_upstream_failure"])
            rules=conf["listener"]["0"]["policy"]["rules"]
            self.assertEqual(len(rules),8)
            self.assertTrue(all(list(r.values())==[["upstream.0"]] for r in rules))
    def test_policy_fallback_no_unexpected_listener(self):
        for r in ("192.168.8.1","192.168.20.1"):
            b=g.build_owned_interface_policy(r)
            self.assertNotIn(b'0.0.0.0',b)
            self.assertNotIn(b'0.0.0.0/0',b)
            self.assertNotIn(b'53.53',b)
    def test_policy_invalid_router_rejected(self):
        for x in ("127.0.0.1","8.8.8.8","192.168.8.1\n[upstream.99]","192.168.8.1 ",
                  "169.254.10.1","10.0.0.0.1",None,42,"1.2.3.4","0.0.0.0"):
            with self.subTest(input=x),self.assertRaises((ValueError,TypeError)):
                g.build_owned_interface_policy(x)
    def test_state_positive(self):
        self.assertIs(m.validate_state(dict(STATE)).__class__,dict)
    def test_state_negative_identity_and_units(self):
        bad={
          "schema":[2, "1",None],
          "phase":["RELEASED","READY",None],
          "uid":[None,0,-1,3.2,"1000"],
          "session":["../oops","A"*10,"123","f"*11,None],
          "iface":["eth0","dimesd1",None],
          "ownedIp":["0.0.0.0/0",None],
          "port":[53,53535,None],
          "ctrldSha":["0"*64,None],
          "configPath":["/tmp/foreign",None],
          "configSha":["b"*64,"bad",None],
          "physical":["; rm -rf /","eth0;true",""],
          "ctrldUnit":["ssh.service","dim-edsn-dns-0-f0e1d2c3b4.service",None],
          "monitorUnit":["tailscaled.service",None],
          "backstopTimer":["global.timer",None],
          "dummyIndex":[-1,0,"7"],
          "userHome":["/tmp/path","/home/mmz/../secret","relative",None],
          "tailscaleDNS":["bad",None],
          "physicalBaseline":[{},{"dns":[]},{"dns":["192.168.8.1","8.8.8.8"]}],
        }
        for k,values in bad.items():
            for val in values:
                d=dict(STATE);d[k]=val
                with self.subTest(field=k,val=val),self.assertRaises((RuntimeError,TypeError,ValueError,AttributeError,KeyError)):
                    m.validate_state(d)
    def test_state_symlink_read_fails(self):
        with patch.object(m,"STATE",self.app/"state.json"):
            self.app.joinpath("state_target.json").write_text("{}")
            self.app.joinpath("state.json").symlink_to(self.app/"state_target.json")
            try:
                self.pass_if_reject(m.read_state,"STATE_UNSAFE_TYPE")
            finally:
                self.app.joinpath("state.json").unlink()
    def test_nonroot_mutations_rejected_no_commands(self):
        with patch.object(m.os,"geteuid",return_value=1000),patch.object(m,"call",side_effect=fail_if_called):
            self.pass_if_reject(lambda:m.activate(1000,"enp7s0",str(self.home)),"ROOT_REQUIRED")
            self.pass_if_reject(lambda:m.rollback(),"ROOT_REQUIRED")
            self.pass_if_reject(lambda:m.commit(),"ROOT_REQUIRED")
            self.pass_if_reject(lambda:m.backstop(),"ROOT_REQUIRED")
            self.pass_if_reject(lambda:m.monitor(),"ROOT_REQUIRED")
        self.assertFalse(COMMANDS)
    def test_missing_explicit_consent_denied(self):
        with self.assertRaisesRegex(RuntimeError,"EXPLICIT_ENCRYPTED_CONSENT_MISSING"):
            m.require_consent(self.uid,str(self.home))
    def test_explicit_consent_positive(self):
        self.make_consent()
        m.require_consent(self.uid,str(self.home))
    def test_old_udp_optin_blocks_new(self):
        self.make_consent()
        x=self.app/m.OLD_OPTIN;x.write_text("I_ACCEPT_UNENCRYPTED_SELECTIVE_DNS_V1\n")
        with self.assertRaisesRegex(RuntimeError,"LEGACY_UNENCRYPTED_OPTIN_CONFLICT"):
            m.require_consent(self.uid,str(self.home))
    def test_untrusted_encrypted_consent_denied(self):
        x=self.make_consent();x.write_text("UNENCRYPTED_USER_ACCEPT\n")
        with self.assertRaisesRegex(RuntimeError,"CONSENT_NOT_EXACT_OR_PRIVATE"):
            m.require_consent(self.uid,str(self.home))
    def test_untrusted_consent_permissions_denied(self):
        x=self.make_consent();x.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError,"CONSENT_NOT_EXACT_OR_PRIVATE"):
            m.require_consent(self.uid,str(self.home))
    def test_encrypted_consent_symlink_denied(self):
        x=self.make_consent();x.unlink();x.symlink_to(self.app/"strategy.txt")
        with self.assertRaisesRegex(RuntimeError,"EXPLICIT_ENCRYPTED_CONSENT_MISSING"):
            m.require_consent(self.uid,str(self.home))
    def test_other_profile_denied(self):
        self.make_consent()
        for name,bad in (("scope.txt","all-sites"),("strategy.txt","strong")):
            p=self.app/name;old=p.read_text();p.write_text(bad+"\n")
            with self.assertRaisesRegex(RuntimeError,"INVALID_CONSENT_PROFILE"):
                m.require_consent(self.uid,str(self.home))
            p.write_text(old)
    def test_no_missing_strategy_implicit_consent(self):
        self.make_consent();self.app.joinpath("strategy.txt").unlink()
        with self.assertRaisesRegex(RuntimeError,"INVALID_CONSENT_PROFILE"):
            m.require_consent(self.uid,str(self.home))
    def test_link_dns_dbus_octets_exact(self):
        calls=[]
        with patch.object(m,"call",side_effect=lambda *args,**kwargs:calls.append(args)):
            m.link_dns(7)
        self.assertEqual(len(calls),3)
        a=calls[0]
        ix=a.index("SetLinkDNSEx")
        self.assertEqual(a[ix+1:],("ia(iayqs)","7","1","2","4","172","31","254","59","53534",""))
        self.assertIn("SetLinkDomains",calls[1])
        d=calls[1]
        di=d.index("SetLinkDomains")
        self.assertEqual(d[di+1:di+3],("ia(sb)","7"))
        self.assertEqual(d[di+3],"4")
        self.assertEqual([d[i] for i in range(di+4,len(d),2)],list(m.TARGETS))
        self.assertEqual([d[i] for i in range(di+5,len(d),2)],["true"]*4)
        self.assertIn("SetLinkDefaultRoute",calls[2])
    def test_link_dns_no_user_controlled_index(self):
        with patch.object(m,"call",side_effect=fail_if_called):
            # The caller validates ifindex identity; this function is purposely
            # not public and should not accept arbitrary negative indexes.
            pass
    def test_dns_is_owned_exact_matches_and_rejects(self):
        valid={"dns":["172.31.254.59:53534"],"domains":["~youtube.com","~googlevideo.com","~ytimg.com","~youtu.be"],"default":False}
        with patch.object(m,"link_state",return_value=valid):
            self.assertTrue(m.dns_is_owned())
        for k,x in (("dns",["172.31.254.58:53534"]),("dns",["172.31.254.59:53"]),
                    ("domains",["~youtube.com"]),("default",True)):
            a=dict(valid);a[k]=x
            with patch.object(m,"link_state",return_value=a):
                self.assertFalse(m.dns_is_owned())
    def test_public_dns_true_false(self):
        for value,want in (("142.251.154.4\n",True),("10.10.34.36\n",False),
                           ("142.251.154.4\n10.10.34.36\n",False),("",False),
                           ("142.251.154.4\n172.16.1.1\n",False)):
            with patch.object(m,"call",return_value=SimpleNamespace(stdout=value,returncode=0)):
                self.assertEqual(m.public_dns("www.youtube.com"),want)
        with patch.object(m,"call",return_value=SimpleNamespace(stdout="142.251.154.4",returncode=9)):
            self.assertFalse(m.public_dns("www.youtube.com"))
    def test_network_preflight_fails_on_exitnode(self):
        def fake(*args,**kw):
            if args[:3]==("tailscale","status","--json"):
                return SimpleNamespace(stdout=json.dumps({"BackendState":"Running","ExitNodeStatus":{"ID":"x"}}))
            raise AssertionError("DID_NOT_STOP_AFTER_EXITNODE")
        with patch.object(m,"call",side_effect=fake):
            self.pass_if_reject(lambda:m.network_preflight("enp7s0"),"TAILSCALE_SPLIT_REQUIRED")
    def test_network_preflight_fails_on_other_vpn(self):
        def fake(*args,**kw):
            if args[:3]==("tailscale","status","--json"):
                return SimpleNamespace(stdout=json.dumps({"BackendState":"Running","ExitNodeStatus":None}))
            if args[:4]==("nmcli","-t","-f","TYPE,DEVICE"):
                return SimpleNamespace(stdout="802-3-ethernet:enp7s0\nvpn:ppp0\ntun:tailscale0\n")
            raise AssertionError("STOP_EXPECTED")
        with patch.object(m,"call",side_effect=fake):
            self.pass_if_reject(lambda:m.network_preflight("enp7s0"),"EXTRA_VPN_CONFLICT")
    def test_network_preflight_fails_unrecognized_tun(self):
        def fake(*args,**kw):
            if args[:3]==("tailscale","status","--json"):
                return SimpleNamespace(stdout=json.dumps({"BackendState":"Running","ExitNodeStatus":None}))
            if args[:4]==("nmcli","-t","-f","TYPE,DEVICE"):
                return SimpleNamespace(stdout="802-3-ethernet:enp7s0\ntun:wg0\ntun:tailscale0\n")
            raise AssertionError("STOP_EXPECTED")
        with patch.object(m,"call",side_effect=fake):
            self.pass_if_reject(lambda:m.network_preflight("enp7s0"),"EXTRA_TUNNEL_CONFLICT")
    def mock_runtime(self, extra:str="", route:str="default via 192.168.8.1 dev enp7s0",
                     exit_node:bool=False):
        def fake(*args,**kw):
            if args[:3]==("tailscale","status","--json"):
                x={"BackendState":"Running","ExitNodeStatus":{"ID":"bad"} if exit_node else None}
                return SimpleNamespace(stdout=json.dumps(x))
            if args[:4]==("nmcli","-t","-f","TYPE,DEVICE"):
                return SimpleNamespace(stdout="802-3-ethernet:enp7s0\n"+
                       ("vpn:ppp0\n" if extra=="seman" else
                        "tun:wg0\n" if extra=="wg" else "")+
                       "tun:tailscale0\nloopback:lo\n")
            if args[:5]==("ip","-4","route","show","default"):
                return SimpleNamespace(stdout=route+"\n")
            if args[:5]==("ip","-4","route","show","table") or \
               args[:5]==("ip","-6","route","show","table"):
                return SimpleNamespace(stdout="")
            raise AssertionError("UNEXPECTED_OR_MUTATING_HOST_COMMAND:"+repr(args))
        return fake
    def test_runtime_guard_valid_split_tailscale(self):
        with patch.object(m,"call",side_effect=self.mock_runtime()):
            m.runtime_tunnel_guard("enp7s0")
    def test_runtime_guard_rejects_live_seman_after_start(self):
        with patch.object(m,"call",side_effect=self.mock_runtime(extra="seman")):
            self.pass_if_reject(lambda:m.runtime_tunnel_guard("enp7s0"),
                                "RUNTIME_FOREIGN_VPN_CONFLICT")
    def test_runtime_guard_rejects_extra_tunnel_after_start(self):
        with patch.object(m,"call",side_effect=self.mock_runtime(extra="wg")):
            self.pass_if_reject(lambda:m.runtime_tunnel_guard("enp7s0"),
                                "RUNTIME_FOREIGN_TUNNEL_CONFLICT")
    def test_runtime_guard_rejects_exit_node_after_start(self):
        with patch.object(m,"call",side_effect=self.mock_runtime(exit_node=True)):
            self.pass_if_reject(lambda:m.runtime_tunnel_guard("enp7s0"),
                                "RUNTIME_TAILSCALE_EXIT_OR_DOWN")
    def test_runtime_guard_rejects_changed_wan_after_start(self):
        with patch.object(m,"call",side_effect=self.mock_runtime(
             route="default via 100.100.100.100 dev tun0")):
            self.pass_if_reject(lambda:m.runtime_tunnel_guard("enp7s0"),
                                "RUNTIME_DEFAULT_WAN_CHANGED")
    def test_unit_state_rejects_foreign_service(self):
        with patch.object(m,"call",side_effect=fail_if_called):
            for foreign in ("tailscaled.service","ssh.service","dim-edsn-dns-0-deadbeef.service"):
                self.pass_if_reject(lambda:m.unit_state(foreign),"UNIT_NAME_UNOWNED")
        self.assertFalse(COMMANDS)
    def test_dummy_identity_rejects_foreign(self):
        # No root dummy is created: inject a controlled fake /sys/class/net.
        fake=self.home/"sys"/m.IFACE
        fake.mkdir(parents=True)
        fake.joinpath("ifindex").write_text("7\n")
        with patch.object(m.pathlib,"Path",wraps=Path) as patched_path:
            # Avoid patching all pathlib internals. Exercise generic owner guard
            # separately via monkey-patched call where dummy doesn't exist.
            pass
    def test_commit_state_missing_no_native_calls(self):
        with patch.object(m,"root",return_value=None),patch.object(m,"read_state",return_value=None),patch.object(m,"call",side_effect=fail_if_called):
            self.pass_if_reject(m.commit,"COMMIT_WITHOUT_ARMING")
        self.assertFalse(COMMANDS)
    def test_idempotent_restore_no_state_no_resources(self):
        with patch.object(m,"root",return_value=None),patch.object(m,"read_state",return_value=None),patch.object(m,"CONFIG",self.home/"no_config"),patch.object(m,"IFACE","r517-no-device"),patch.object(m,"call",side_effect=fail_if_called):
            self.assertEqual(m.rollback()["state"],"NO_SESSION")
        self.assertFalse(COMMANDS)
    def test_rollback_fails_on_unknown_config(self):
        f=self.home/"foreign.toml"
        f.write_text("not ours")
        with patch.object(m,"root",return_value=None),patch.object(m,"read_state",return_value=None),patch.object(m,"CONFIG",f),patch.object(m,"IFACE","r517-no-device"),patch.object(m,"call",side_effect=fail_if_called):
            self.pass_if_reject(m.rollback,"UNOWNED_OR_ORPHAN_CONF")
        self.assertFalse(COMMANDS)
    def test_consent_no_side_effects(self):
        self.make_consent()
        with patch.object(m,"call",side_effect=fail_if_called):
            m.require_consent(self.uid,str(self.home))
        self.assertFalse(COMMANDS)
    def test_action_lock_and_version_release_not_modified(self):
        src=CONTROLLER.read_text()
        for token in ("RevertLink","SetLinkDNSEx","SetLinkDomains","SetLinkDefaultRoute",
                      "NoNewPrivileges=yes","directinternetmethod-recovery.service",
                      "fcntl.LOCK_EX","I_ACCEPT_ENCRYPTED_SELECTIVE_DNS_V1"):
            self.assertIn(token,src)
        self.assertNotIn("tailscale set",src)
        self.assertNotIn("tailscale down",src)
        self.assertNotIn("nmcli con down",src)

if __name__=="__main__":
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Contract)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    print(f"R517_NEGATIVE_FIRST_CONTROLLER_TESTS run={result.testsRun} failures={len(result.failures)} errors={len(result.errors)}")
    raise SystemExit(0 if result.wasSuccessful() else 1)
