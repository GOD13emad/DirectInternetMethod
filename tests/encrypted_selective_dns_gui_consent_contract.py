#!/usr/bin/env python3
"""R517 isolated GUI consent tests. AST-only; no GI, network, or user settings."""
from __future__ import annotations
import ast
import os
import pathlib
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
APP=ROOT/"linux/app/direct_internet_method.py"
tree=ast.parse(APP.read_text("utf8"))
names=("selective_dns_optin_state","selective_dns_optin_save",
       "encrypted_dns_optin_state","encrypted_dns_optin_save")
funcs=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
assert sorted(x.name for x in funcs)==sorted(names)

class Consent(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="R517_optin_",dir=str(ROOT))
        self.folder=pathlib.Path(self.tmp.name)
        self.old=self.folder/"selective-dns-optin.txt"
        self.new=self.folder/"encrypted-dns-optin.txt"
        self.ns={
         "os":os,"pathlib":pathlib,"tempfile":tempfile,
         "SELECTIVE_DNS_OPT_IN":self.old,
         "SELECTIVE_DNS_TOKEN":"I_ACCEPT_UNENCRYPTED_SELECTIVE_DNS_V1",
         "ENCRYPTED_DNS_OPT_IN":self.new,
         "ENCRYPTED_DNS_TOKEN":"I_ACCEPT_ENCRYPTED_SELECTIVE_DNS_V1",
        }
        exec(compile(ast.Module(body=funcs,type_ignores=[]),"<isolated-gui>", "exec"),self.ns)
        self.old_status=self.ns["selective_dns_optin_state"]
        self.old_save=self.ns["selective_dns_optin_save"]
        self.new_status=self.ns["encrypted_dns_optin_state"]
        self.new_save=self.ns["encrypted_dns_optin_save"]
    def tearDown(self):self.tmp.cleanup()
    def test_default_off(self):
        self.assertEqual(self.new_status(),"OFF")
        self.assertEqual(self.old_status(),"OFF")
    def test_new_consent_exact_and_0600(self):
        self.new_save(True)
        self.assertEqual(self.new.read_text(),"I_ACCEPT_ENCRYPTED_SELECTIVE_DNS_V1\n")
        self.assertEqual(self.new.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.new_status(),"ON")
        self.assertEqual(self.old_status(),"OFF")
    def test_disable_preserves_foreign_other_file(self):
        unrelated=self.folder/"personal.txt"
        unrelated.write_text("preserve unrelated contents")
        self.new_save(True)
        self.new_save(False)
        self.assertFalse(self.new.exists())
        self.assertEqual(unrelated.read_text(),"preserve unrelated contents")
        self.assertEqual(self.new_status(),"OFF")
    def test_old_unencrypted_consent_cannot_enable_new(self):
        self.old_save(True)
        self.assertEqual(self.old_status(),"ON")
        self.assertEqual(self.new_status(),"OFF")
        with self.assertRaisesRegex(ValueError,"Unencrypted DNS consent"):
            self.new_save(True)
        self.assertFalse(self.new.exists())
    def test_disable_old_then_new_requires_explicit(self):
        self.old_save(True)
        self.old_save(False)
        self.assertEqual(self.new_status(),"OFF")
        self.new_save(True)
        self.assertEqual(self.new_status(),"ON")
        self.assertFalse(self.old.exists())
    def test_unknown_token_invalid(self):
        self.new.write_text("I_ACCEPT_ANYTHING\n")
        self.new.chmod(0o600)
        self.assertEqual(self.new_status(),"INVALID")
    def test_new_consent_must_not_be_world_readable(self):
        self.new_save(True)
        self.new.chmod(0o644)
        self.assertEqual(self.new_status(),"INVALID")
    def test_symlink_denied_and_target_unchanged(self):
        target=self.folder/"unrelated.json"
        target.write_text('{"secret":"do-not-change"}')
        self.new.symlink_to(target)
        self.assertEqual(self.new_status(),"INVALID")
        with self.assertRaisesRegex(ValueError,"symlink"):
            self.new_save(True)
        with self.assertRaisesRegex(ValueError,"symlink"):
            self.new_save(False)
        self.assertEqual(target.read_text(),'{"secret":"do-not-change"}')
    def test_conflicting_consent_invalidates_new_status(self):
        self.new_save(True)
        self.old_save(True)
        self.assertEqual(self.new_status(),"INVALID")
        self.assertEqual(self.old_status(),"ON")
    def test_legacy_optin_token_not_reused(self):
        self.new.write_text("I_ACCEPT_UNENCRYPTED_SELECTIVE_DNS_V1\n")
        self.new.chmod(0o600)
        self.assertEqual(self.new_status(),"INVALID")
    def test_gui_static_has_independent_toggle(self):
        text=APP.read_text("utf8")
        for term in ("encrypted_toggle=Gtk.CheckButton",
                     "enable_encrypted=bool(encrypted_toggle.get_active())",
                     "selective_dns_optin_save(enable_dns)",
                     "encrypted_dns_optin_save(enable_encrypted)",
                     "Choose exactly one DNS option"):
            self.assertIn(term,text)
    def test_consent_is_not_controller_action(self):
        src=ast.get_source_segment(APP.read_text("utf8"),
              next(x for x in funcs if x.name=="encrypted_dns_optin_save"))
        self.assertTrue(src)
        for forbidden in ("subprocess","systemctl","busctl","resolvectl","tailscale down","ip link"):
            self.assertNotIn(forbidden,src)

if __name__=="__main__":
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Consent))
    print(f"R517_GUI_DISTINCT_ENCRYPTED_CONSENT cases={result.testsRun} failed={len(result.failures)} errors={len(result.errors)}")
    raise SystemExit(0 if result.wasSuccessful() else 1)
