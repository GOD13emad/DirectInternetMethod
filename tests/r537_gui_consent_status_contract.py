#!/usr/bin/env python3
"""R537 negative-first GUI status/consent contract. No Gtk UI or live network.

Execute exact AST of the pre-release GUI load_state() against disposable
settings and mocked *read-only* backend status. No actual user consent token is
written, and no subprocess, systemd, DNS, routes, VPN or privileged mutation.
"""
import ast
import json
import os
import pathlib
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
APP=ROOT/"linux/app/direct_internet_method.py"
SOURCE=APP.read_text(encoding="utf8")
TREE=ast.parse(SOURCE)
FN=next(x for x in TREE.body if isinstance(x,ast.FunctionDef) and x.name=="load_state")

class ExplicitDoHStatus(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="r537_gui_state_",dir=str(ROOT))
        self.addCleanup(self.tmp.cleanup)
        base=pathlib.Path(self.tmp.name)
        self.scope=base/"scope.txt"
        self.strategy=base/"strategy.txt"
        self.scope.write_text("targeted\n")
        self.strategy.write_text("balanced\n")
        self.backend=True
        self.old="OFF"
        self.encrypted="OFF"
        self.split=True
        self.foreign=False
        self.globals={
            "json":json,"os":os,"pathlib":pathlib,
            "STATE":base/"missing-state.json",
            "SCOPE_FILE":self.scope,"STRATEGY_FILE":self.strategy,
            "_external_tunnel_active":lambda:self.foreign,
            "_tailscale_split_safe":lambda:self.split,
            "_coexistence_backend_ready":lambda:self.backend,
            "selective_dns_optin_state":lambda:self.old,
            "encrypted_dns_optin_state":lambda:self.encrypted,
        }
        exec(compile(ast.Module(body=[FN],type_ignores=[]),
                     str(APP), "exec"),self.globals)
        self.load=self.globals["load_state"]

    def test_01_default_both_disabled(self):
        state=self.load()
        self.assertEqual(state["mode"],"OFF")
        self.assertIn("both OFF",state["detail"])

    def test_02_authenticated_encrypted_optin_shown_distinctly(self):
        self.encrypted="ON"
        state=self.load()
        self.assertEqual(state["mode"],"OFF")
        self.assertIn("Control D DoH",state["detail"])
        self.assertIn("OPTED IN",state["detail"])
        self.assertIn("HTTPS reachability is not guaranteed",state["detail"])

    def test_03_invalid_encrypted_consent_disables_start(self):
        self.encrypted="INVALID"
        state=self.load()
        self.assertEqual(state["mode"],"CONFIG_REQUIRED")
        self.assertIn("invalid",state["detail"])

    def test_04_conflicting_legacy_consent_invalid_disables_start(self):
        self.old="ON"
        self.encrypted="INVALID"
        state=self.load()
        self.assertEqual(state["mode"],"CONFIG_REQUIRED")
        self.assertIn("conflicts",state["detail"])

    def test_05_encrypted_requires_balanced(self):
        self.encrypted="ON"
        self.strategy.write_text("strong\n")
        state=self.load()
        self.assertEqual(state["mode"],"CONFIG_REQUIRED")
        self.assertIn("Balanced",state["detail"])

    def test_06_encrypted_requires_explicit_strategy_file(self):
        self.encrypted="ON"
        self.strategy.unlink()
        state=self.load()
        self.assertEqual(state["mode"],"CONFIG_REQUIRED")

    def test_07_invalid_all_sites_precedes_encrypted(self):
        self.encrypted="ON"
        self.scope.write_text("all-sites\n")
        state=self.load()
        self.assertEqual(state["mode"],"CONFIG_REQUIRED")
        self.assertIn("All Sites",state["detail"])

    def test_08_legacy_unencrypted_consent_distinguished(self):
        self.old="ON"
        state=self.load()
        self.assertEqual(state["mode"],"OFF")
        self.assertIn("UNENCRYPTED",state["detail"])
        self.assertNotIn("Control D DoH",state["detail"])

    def test_09_legacy_invalid_consent_disables_start(self):
        self.old="INVALID"
        state=self.load()
        self.assertEqual(state["mode"],"CONFIG_REQUIRED")

    def test_10_backend_not_updated_refuses_start_even_with_consent(self):
        self.encrypted="ON"
        self.backend=False
        self.assertEqual(self.load()["mode"],"BACKEND_UPDATE_REQUIRED")

    def test_11_foreign_vpn_takes_precedence(self):
        self.encrypted="ON"
        self.foreign=True
        self.assertEqual(self.load()["mode"],"BLOCKED")

    def test_12_no_mutation_syscalls_in_ui_status_function(self):
        body=ast.get_source_segment(SOURCE,FN)
        for token in ("subprocess.run(", "subprocess.Popen(", "os.system(",
                      "systemctl start", "resolvectl dns enp7s0",
                      "pkexec", "tailscale down", ".write_text(", ".unlink("):
            self.assertNotIn(token,body)
        self.assertIn('encrypted_dns_optin_state()',body)

if __name__=="__main__":
    result=unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ExplicitDoHStatus))
    print(f"R537_GUI_DOHSCOPE_STATUS cases={result.testsRun} failures={len(result.failures)} errors={len(result.errors)}")
    raise SystemExit(0 if result.wasSuccessful() else 1)
