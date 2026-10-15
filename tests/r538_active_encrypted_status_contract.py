#!/usr/bin/env python3
"""R538 negative-first: real RC1 active-state DoH and HTTPS verifier semantics.

Execute just the actual production GUI load_state and verify_live functions
from pinned source AST with synthetic state and deliberately mocked command
outputs. No physical network, installed settings, privileges or GTK mutation.
"""
import ast
import json
import os
import pathlib
import subprocess
import tempfile
import types
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
APP=ROOT/"linux/app/direct_internet_method.py"
SOURCE=APP.read_text(encoding="utf-8")
TREE=ast.parse(SOURCE)
METHODS=[n for n in TREE.body if isinstance(n,ast.FunctionDef)
         and n.name in ("load_state","verify_live")]
assert len(METHODS)==2, "R538_EXPECTED_TWO_PRODUCTION_FUNCTIONS"

class ActiveEncryptedDoH(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="r538_active_doh_",dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name)
        self.statefile=self.root/"active.json"
        self.calls=[]
        self.remote_youtube_ok=True
        self.backend_unit_active=True
        self.external_tunnel=False
        self.tailscale_safe=True
        self.data={
           "schema":3,"status":"ACTIVE","uid":os.getuid(),
           "dnsMode":"system-preserved","tailscaleCoexistence":True,
           "selectiveDnsEncrypted":True,"selectiveDns":False,
           "physicalInterface":"enp7s0","dnsInterface":"","dnsIp":"",
           "ctrldPid":0,"ctrldUnit":None,
           "nfqwsUnit":f"directinternetmethod-nfqws-{os.getuid()}.service",
           "nfqwsPid":37531,"strategy":"balanced","scope":"targeted"}
        self.store()
        self.env={
            "json":json,"os":os,"pathlib":pathlib,
            "STATE":self.statefile,
            "subprocess":types.SimpleNamespace(run=self.fake_run),
            "_external_tunnel_active":lambda:self.external_tunnel,
            "_tailscale_split_safe":lambda:self.tailscale_safe,
            "_top_default_iface":lambda:self.data["physicalInterface"],
            "_systemd_unit_matches":lambda *a:self.backend_unit_active,
        }
        exec(compile(ast.Module(body=METHODS,type_ignores=[]),str(APP),"exec"),self.env)
        self.show=self.env["load_state"]
        self.verify=self.env["verify_live"]

    def store(self):
        self.statefile.write_text(json.dumps(self.data)+"\n",encoding="utf8")

    def fake_run(self,argv,**kwargs):
        program=argv[0]
        self.assertIn(program,("getent","curl"),"R538_ATTEMPTED_REAL_COMMAND")
        if program=="getent":
            return types.SimpleNamespace(returncode=0,stdout="142.251.151.4 STREAM www.youtube.com\n",stderr="")
        url=argv[-1]
        self.calls.append(url)
        mapping={
          "http://www.youtube.com/":"301|142.251.151.4|0.10",
          "https://www.youtube.com/":"200|142.251.151.4|0.31",
          # Deliberately incorrect endpoint for YouTube: using it would fail
          # a healthy connection and false-negative the acceptance.
          "https://www.youtube.com/generate_204":"404|142.251.151.4|0.25",
          "https://api.openai.com/v1/models":"401|104.18.0.1|0.25",
          "https://github.com/":"200|140.82.112.3|0.23",
          "https://gemini.google.com/":"200|142.250.191.14|0.20"
        }
        self.assertIn(url,mapping,"R538_UNRECOGNIZED_PROBE")
        if not self.remote_youtube_ok and url=="https://www.youtube.com/":
            return types.SimpleNamespace(returncode=35,stdout="000||1.30",stderr="TLS reset")
        return types.SimpleNamespace(returncode=0,stdout=mapping[url],stderr="")

    def test_01_active_encrypted_selected_shows_actual_doh(self):
        v=self.show()
        self.assertEqual(v["mode"],"ACTIVE")
        self.assertIn("Encrypted targeted DoH ACTIVE",v["detail"])
        self.assertIn("MagicDNS",v["detail"])

    def test_02_active_legacy_udp_remains_explicitly_unencrypted(self):
        self.data["selectiveDnsEncrypted"]=False
        self.data["selectiveDns"]=True
        self.store()
        v=self.show()
        self.assertEqual(v["mode"],"ACTIVE")
        self.assertIn("UNENCRYPTED",v["detail"])
        self.assertNotIn("Encrypted targeted DoH ACTIVE",v["detail"])

    def test_03_active_without_selected_dns_shows_preserved_dns(self):
        self.data["selectiveDnsEncrypted"]=False
        self.store()
        v=self.show()
        self.assertEqual(v["mode"],"ACTIVE")
        self.assertIn("DNS/MagicDNS preserved",v["detail"])
        self.assertNotIn("DoH ACTIVE",v["detail"])

    def test_04_conflicting_active_state_fails_closed(self):
        self.data["selectiveDns"]=True
        self.store()
        self.assertEqual(self.show()["mode"],"CONFLICT")

    def test_05_inactive_nfqws_stays_stale(self):
        self.backend_unit_active=False
        self.assertEqual(self.show()["mode"],"STALE")

    def test_06_unsupported_vpn_conflicts_even_with_valid_doh(self):
        self.external_tunnel=True
        self.assertEqual(self.show()["mode"],"CONFLICT")

    def test_07_selected_doh_live_probe_targets_real_homepage(self):
        result=self.verify()
        self.assertTrue(result["ok"])
        self.assertIn("https://www.youtube.com/",self.calls)
        self.assertNotIn("https://www.youtube.com/generate_204",self.calls)

    def test_08_selected_doh_live_methods_include_targeted_doh(self):
        result=self.verify()
        self.assertIn("encrypted-selective-doh",result["directMethods"])
        self.assertNotIn("unencrypted-selective-udp",result["directMethods"])

    def test_09_real_tls_failure_never_counted_as_success(self):
        self.remote_youtube_ok=False
        v=self.verify()
        self.assertFalse(v["ok"])
        self.assertEqual(v["youtube"]["exit"],35)

    def test_10_legacy_udp_never_claims_encrypted_methods(self):
        self.data["selectiveDnsEncrypted"]=False
        self.data["selectiveDns"]=True
        self.store()
        v=self.verify()
        self.assertIn("https://www.youtube.com/",self.calls)
        self.assertNotIn("encrypted-selective-doh",v["directMethods"])

    def test_11_mutually_selected_dns_modes_rejected_by_verifier(self):
        self.data["selectiveDns"]=True
        self.store()
        v=self.verify()
        self.assertFalse(v["ok"])
        self.assertEqual(v["error"],"CONFLICTING_SELECTIVE_DNS_STATE")

    def test_12_active_production_status_contains_no_network_mutations(self):
        for n in METHODS:
            source=ast.get_source_segment(SOURCE,n)
            for k in ("resolvectl dns enp7s0","tailscale down",
                      "systemctl start","ip route add","iptables",
                      "nft add","pkexec","os.system("):
                self.assertNotIn(k,source)
        self.assertIn('s.get("selectiveDnsEncrypted")',SOURCE)

if __name__=="__main__":
    res=unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ActiveEncryptedDoH))
    print("R538_ACTIVE_ENCRYPTED_DOH_AND_VERIFIER tests=",res.testsRun,
          "failures=",len(res.failures),"errors=",len(res.errors))
    raise SystemExit(0 if res.wasSuccessful() else 1)
