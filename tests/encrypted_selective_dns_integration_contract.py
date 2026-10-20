#!/usr/bin/env python3
"""R517 source-only integration contract. No native service/network mutations."""
from pathlib import Path
import ast,re,unittest,json
R=Path(__file__).resolve().parents[1]
H=(R/"linux/app/direct_method_helper.sh").read_text()
G=(R/"linux/app/direct_internet_method.py").read_text()
I=(R/"linux/system/install_system.sh").read_text()
U=(R/"linux/system/uninstall_system.sh").read_text()
B=(R/"build_linux_package.py").read_text()
CONTROLLER=(R/"linux/system/encrypted_selective_dns.py").read_text()
POLICY=(R/"linux/system/encrypted_selective_policy.py").read_text()
class Contract(unittest.TestCase):
 def test_helper_uses_exact_existing_action_lock(self):
  self.assertIn('lock_path="/run/directinternetmethod-action.lock"',H)
  self.assertIn('acquire_action_lock',H)
  self.assertIn('flock -n',H)
 def test_distinct_dns_optin(self):
  self.assertIn('ENCRYPTED_DNS_OPT_IN="$STATE_BASE/encrypted-dns-optin.txt"',H)
  self.assertIn('SELECTIVE_DNS_OPT_IN="$STATE_BASE/selective-dns-optin.txt"',H)
  self.assertIn('ENCRYPTED_DNS_ENABLED=0',H)
  self.assertIn('ENCRYPTED_AND_UNENCRYPTED_OPTIN_CONFLICT',H)
 def test_encrypted_activation_only_safe_split_and_profile(self):
  a=H.index('if [ -e "$ENCRYPTED_DNS_OPT_IN" ]')
  b=H.index('ENCRYPTED_DNS_ENABLED=1',a)
  scope=H[a:b]
  for part in ('"$TAILSCALE_COEXIST" -eq 1','"$STRATEGY" = "balanced"',
               '"$SCOPE" = "targeted"','-x "$ENCRYPTED_DNS"'):
   self.assertIn(part,scope)
 def test_unknown_consent_must_be_validated_by_native_controller(self):
  self.assertIn('require_consent(uid,home)',CONTROLLER)
  self.assertIn('I_ACCEPT_ENCRYPTED_SELECTIVE_DNS_V1',CONTROLLER)
  self.assertIn('LEGACY_UNENCRYPTED_OPTIN_CONFLICT',CONTROLLER)
 def test_active_native_dpi_attested_before_encrypted_commit(self):
  self.assertIn('native_engine_attested(s)',CONTROLLER)
  self.assertIn('"selectiveDnsEncrypted":bool(int(sys.argv[16]))',H)
  self.assertIn('ENCRYPTED_DNS_COMMIT_FAILED',H)
  a=H.index('python3 "$ENCRYPTED_DNS" activate')
  b=H.index('python3 "$ENCRYPTED_DNS" commit')
  self.assertLess(a,b)
  state=H.index('CREATED_STATE=1',a)
  self.assertLess(state,b)
 def test_failure_restores_encrypted_before_nft_owned_deletion(self):
  first=H.index('cleanup_transient(){')
  nextfn=H.index('cleanup_state_owned(){',first)
  sub=H[first:nextfn]
  self.assertLess(sub.index('restore_selective_dns || return 88'),sub.index('nft delete table inet'))
 def test_native_stop_reverts_before_killing_engines(self):
  a=H.index('cleanup_state_owned(){')
  b=H.index('restore_selective_dns(){',a) if 'restore_selective_dns(){' in H[a:] else H.index('verify_clean(){',a)
  sub=H[a:b]
  self.assertIn('restore_selective_dns || return 88',sub)
  self.assertLess(sub.index('restore_selective_dns || return 88'),sub.index('kill "$np"'))
 def test_encrypted_cleanup_detects_unknown_or_stale_resources(self):
  for text in ('/run/directinternetmethod-encrypted/session.json',
               '/run/directinternetmethod-encrypted-ctrld.toml',
               'ip link show dimesd0','ENCRYPTED_DNS_UNOWNED_RESIDUE'):
   self.assertIn(text,H)
  self.assertIn('ENCRYPTED_DNS_RESTORE_FAILED',H)
 def test_native_verify_clean_enforces_no_owned_or_orphan_resources(self):
  a=H.index('verify_clean(){')
  b=H.index('status(){',a)
  cleanup=H[a:b]
  for text in ('/run/directinternetmethod-encrypted', '/run/directinternetmethod-encrypted-ctrld.toml',
               'ip link show dimesd0'):
   self.assertIn(text,cleanup)
 def test_existing_already_active_checks_encrypted_health(self):
  self.assertIn('encrypted_dns_ready || DNS_HEALTHY=0',H)
  self.assertIn('encrypted_dns_ready || dns_ok=false',H)
 def test_r517_protected_install_requires_inactive_resources(self):
  for text in ('Stop Direct Internet Method before protected backend update',
               '/run/directinternetmethod-encrypted','/sys/class/net/dimesd0',
               'Incomplete candidate encrypted backend'):
   self.assertIn(text,I)
 def test_r517_installer_copies_both_owned_scripts(self):
  for text in ('"$SRC/system/encrypted_selective_dns.py"',
               '"$SRC/system/encrypted_selective_policy.py"',
               '"$ROOT/encrypted_selective_dns.py"',
               '"$ROOT/encrypted_selective_policy.py"'):
   self.assertIn(text,I)
 def test_uninstall_reverts_with_guard_before_removing_binaries(self):
  a=U.index('encrypted_selective_dns.py restore')
  b=U.index('rm -rf /usr/lib/directinternetmethod')
  self.assertLess(a,b)
  self.assertIn('Encrypted DNS resource remains',U)
 def test_gui_separate_privacy_choice_no_consent_inheritance(self):
  for text in ('ENCRYPTED_DNS_TOKEN="I_ACCEPT_ENCRYPTED_SELECTIVE_DNS_V1"',
               'encrypted_toggle=Gtk.CheckButton',
               'enable_encrypted=bool(encrypted_toggle.get_active())',
               'Choose exactly one DNS option',
               'encrypted_dns_optin_save(enable_encrypted)'):
   self.assertIn(text,G)
 def test_controller_fail_closed_sem_an_after_activation(self):
  for text in ('RUNTIME_FOREIGN_VPN_CONFLICT','RUNTIME_FOREIGN_TUNNEL_CONFLICT',
               'RUNTIME_TAILSCALE_EXIT_OR_DOWN','RUNTIME_DEFAULT_WAN_CHANGED'):
   self.assertIn(text,CONTROLLER)
  self.assertGreaterEqual(CONTROLLER.count('runtime_tunnel_guard('),4)
 def test_controller_perlink_dns_route_only_no_system_wide(self):
  for text in ('SetLinkDNSEx','SetLinkDomains','SetLinkDefaultRoute','RevertLink'):
   self.assertIn(text,CONTROLLER)
  self.assertIn('OWNED_DNS_IPV4 = "172.31.254.59"',POLICY)
  self.assertNotIn('resolvectl dns enp7s0 127.0.0.1',CONTROLLER)
  self.assertNotIn('tailscale down',CONTROLLER)
 def test_controller_checks_root_owned_process_sha_before_commit(self):
  for text in ('VERSIONED_NFQWS_SHA','NATIVE_NFQWS_BINARY_SHA',
               'NATIVE_NFQWS_PID_MISMATCH','NATIVE_NFQWS_PROCESS_FOREIGN'):
   self.assertIn(text,CONTROLLER)
 def test_r519_candidate_is_explicit_unreleased_versioned_bundle(self):
  self.assertIn('DirectInternetMethod_1.5.6_Linux_x86_64.zip',B)
  self.assertIn('linux/system/encrypted_selective_dns.py',B)
  self.assertIn('linux/system/encrypted_selective_policy.py',B)
  self.assertIn('linux/system/protected_upgrade_transaction.py',B)
  self.assertNotIn('DirectInternetMethod_1.5.4_Linux_x86_64.zip',B)
 def test_no_mutating_commands_in_source_contract(self):
  tree=ast.parse(Path(__file__).read_text())
  for node in ast.walk(tree):
   if isinstance(node,(ast.Import,ast.ImportFrom)):
    names=([a.name for a in node.names] if isinstance(node,ast.Import)
           else [node.module or ""])
    self.assertFalse(any(x.startswith(("subprocess","socket")) for x in names))
   if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute):
    if isinstance(node.func.value,ast.Name):
     self.assertNotIn((node.func.value.id,node.func.attr),
                      (("os","system"),("subprocess","run"),("subprocess","Popen")))
if __name__=="__main__":
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Contract))
 print(f"R517_NATIVE_SOURCE_INTEGRATION_CONTRACT cases={result.testsRun} failures={len(result.failures)} errors={len(result.errors)}")
 raise SystemExit(0 if result.wasSuccessful() else 1)
