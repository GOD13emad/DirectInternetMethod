#!/usr/bin/env python3
"""R541 regression for route/interface drift after real network changes.

Derived from the physical Emad Linux read-only finding: old owned nft output
rules match recorded Wi-Fi wlp2s0, while live Internet egress uses enp1s0.
No installed state, network, DNS, Tailscale, nfqueue, privileged actions or
user settings may be changed by these tests.
"""
import ast
import json
import os
import shlex
import subprocess
from pathlib import Path
import tempfile
import types
import unittest

ROOT=Path(__file__).resolve().parents[1]
GUI=ROOT/"linux/app/direct_internet_method.py"
HELPER=ROOT/"linux/app/direct_method_helper.sh"
SOURCE=GUI.read_text(encoding="utf-8")
TREE=ast.parse(SOURCE)
FUNCS=[x for x in TREE.body if isinstance(x,ast.FunctionDef)
       and x.name in ("load_state","verify_live")]
assert len(FUNCS)==2

class RouteDrift(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix="r541_route_test_",dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.state=Path(self.temporary.name)/"state.json"
        self.egress="enp1s0"
        self.interface="wlp2s0"
        self.backend_running=True
        self.calls=[]
        self.row={
           "status":"ACTIVE","schema":3,"uid":os.getuid(),
           "physicalInterface":self.interface,
           "dnsMode":"system-preserved","tailscaleCoexistence":True,
           "selectiveDns":False,"selectiveDnsEncrypted":False,
           "ctrldPid":0,"ctrldUnit":None,
           "nfqwsPid":5005,"nfqwsUnit":f"directinternetmethod-nfqws-{os.getuid()}.service"
        }
        self.write()
        self.env={
            "json":json,"os":os,"pathlib":PathNamespace,
            "STATE":self.state,
            "_external_tunnel_active":lambda:False,
            "_tailscale_split_safe":lambda:True,
            "_top_default_iface":lambda:self.egress,
            "_systemd_unit_matches":lambda *args:self.backend_running,
            "subprocess":types.SimpleNamespace(run=self.fake_process),
        }
        exec(compile(ast.Module(body=FUNCS,type_ignores=[]),str(GUI),"exec"),self.env)
        self.show=self.env["load_state"]
        self.verify=self.env["verify_live"]

    def write(self):
        self.row["physicalInterface"]=self.interface
        self.state.write_text(json.dumps(self.row)+"\n",encoding="utf-8")

    def fake_process(self,*args,**kwargs):
        self.calls.append(args[0])
        raise AssertionError("R541_ROUTE_DRIFT_MUST_ABORT_BEFORE_NETWORK_PROBES")

    def test_01_stale_wifi_rule_vs_ethernet_default(self):
        s=self.show()
        self.assertEqual(s["mode"],"STALE")
        self.assertIn("wlp2s0",s["detail"])
        self.assertIn("enp1s0",s["detail"])
        self.assertIn("Stop",s["detail"])

    def test_02_default_route_missing_does_not_trust_running_pid(self):
        self.egress=""
        self.assertEqual(self.show()["mode"],"STALE")

    def test_03_route_returns_to_installed_interface(self):
        self.egress="wlp2s0"
        self.assertEqual(self.show()["mode"],"ACTIVE")

    def test_04_https_probe_preflights_route_without_curl(self):
        v=self.verify()
        self.assertEqual(v["ok"],False)
        self.assertEqual(v["error"],"PHYSICAL_INTERFACE_ROUTE_DRIFT")
        self.assertEqual(v["recordedInterface"],"wlp2s0")
        self.assertEqual(v["currentInterface"],"enp1s0")
        self.assertEqual(self.calls,[])

    def test_05_https_probe_no_default_route_fails_closed(self):
        self.egress=""
        v=self.verify()
        self.assertEqual(v["error"],"PHYSICAL_INTERFACE_ROUTE_DRIFT")
        self.assertEqual(self.calls,[])

    def test_06_original_missing_nfqws_pid_still_stale(self):
        self.backend_running=False
        self.assertEqual(self.show()["mode"],"STALE")

    def test_07_tailscale_state_does_not_mask_route_drift(self):
        self.row["selectiveDnsEncrypted"]=True
        self.write()
        s=self.show()
        self.assertEqual(s["mode"],"STALE")
        self.assertNotIn("DoH ACTIVE",s["detail"])

    def test_08_shell_backend_refuses_false_already_active_without_mutating(self):
        shell=HELPER.read_text(encoding="utf-8")
        start=shell.split("\n  start)\n",1)[1].split("\n    if nft_table_presence;",1)[0]
        self.assertIn('CURRENT_PHY="$(physical_iface)"',start)
        self.assertIn('PREVIOUS_PHY="$(state_value physicalInterface)"',start)
        self.assertIn('PHYSICAL_INTERFACE_ROUTE_DRIFT',start)
        self.assertIn('trap - EXIT',start)
        self.assertLess(start.index('PHYSICAL_INTERFACE_ROUTE_DRIFT'),
                        start.index('nft_table_owned "$(state_value physicalInterface)"'))
        self.assertIn('exit 79',start)
        self.assertIn('nft add rule inet "$TABLE" output oifname "$PHY"',shell)

    def test_09_shell_guard_is_before_any_cleanup(self):
        shell=HELPER.read_text(encoding="utf-8")
        start=shell.split("\n  start)\n",1)[1]
        self.assertLess(start.index('PHYSICAL_INTERFACE_ROUTE_DRIFT'),start.index('cleanup_state_owned'))


    def _real_shell_route_preflight(self, previous, current, top):
        """Run the exact installed Start preflight under unprivileged Bash stubs.

        This stops before CPID/readiness/cleanup, so no root, service, route,
        DNS, Tailscale, nft or network action is possible. Only the protected
        drift guard from the real helper is executed, not a rewritten model.
        """
        shell=HELPER.read_text(encoding="utf-8")
        start=shell.split("\n  start)\n",1)[1].split("\n      CPID=",1)[0]
        self.assertIn("PHYSICAL_INTERFACE_ROUTE_DRIFT",start)
        script=(
            "set -euo pipefail\n"
            f"STATE={shlex.quote(str(self.state))}\n"
            f"REQ_PREVIOUS={shlex.quote(previous)}\n"
            f"REQ_CURRENT={shlex.quote(current)}\n"
            f"REQ_TOP={shlex.quote(top)}\n"
            "require_root() { :; }\n"
            "acquire_action_lock() { :; }\n"
            "rollback_on_exit() { printf 'ROLLBACK_CALLED\\n'; }\n"
            "state_value() { [[ \"$1\" == physicalInterface ]] && "
            "printf '%s\\n' \"$REQ_PREVIOUS\"; }\n"
            "physical_iface() { printf '%s\\n' \"$REQ_CURRENT\"; }\n"
            "top_iface() { printf '%s\\n' \"$REQ_TOP\"; }\n"
            "cleanup_state_owned() { printf 'CLEANUP_CALLED\\n'; }\n"
            "ACTION=start\nSTART_COMMITTED=0\n"
            +start+
            "\n    fi\n"
            "trap - EXIT\nprintf 'PRECHECK_MATCHED\\n'\n"
        )
        return subprocess.run(["bash","-c",script],text=True,capture_output=True,
                              timeout=5,check=False)

    def test_10_executable_start_drift_refuses_without_cleanup(self):
        for name,old,new,top in (
            ("wifi_to_ethernet","wlp2s0","enp1s0","enp1s0"),
            ("default_route_lost","wlp2s0","",""),
            ("top_route_conflict","wlp2s0","wlp2s0","tailscale0"),
            ("recorded_interface_missing","","enp1s0","enp1s0"),
        ):
            with self.subTest(name=name):
                p=self._real_shell_route_preflight(old,new,top)
                self.assertEqual(p.returncode,79,p.stdout+p.stderr)
                self.assertIn('"error":"PHYSICAL_INTERFACE_ROUTE_DRIFT"',p.stdout)
                self.assertNotIn("CLEANUP_CALLED",p.stdout)
                self.assertNotIn("ROLLBACK_CALLED",p.stdout)
                self.assertNotIn("PRECHECK_MATCHED",p.stdout)

    def test_11_executable_start_matching_route_uses_safe_path(self):
        p=self._real_shell_route_preflight("wlp2s0","wlp2s0","wlp2s0")
        self.assertEqual(p.returncode,0,p.stdout+p.stderr)
        self.assertIn("PRECHECK_MATCHED",p.stdout)
        self.assertNotIn("CLEANUP_CALLED",p.stdout)

class PathNamespace:
    Path=Path

if __name__=="__main__":
    res=unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(RouteDrift))
    print("R541_ROUTE_DRIFT tests=",res.testsRun,
          "failures=",len(res.failures),"errors=",len(res.errors))
    raise SystemExit(0 if res.wasSuccessful() else 1)
