#!/usr/bin/env python3
"""R247 negative-first source guard; prevents selective-DNS recovery races."""
from pathlib import Path
import ast, re
R=Path(__file__).resolve().parents[1]
helper=(R/"linux/app/direct_method_helper.sh").read_text(encoding="utf-8")
selective=(R/"linux/system/selective_dns.py").read_text(encoding="utf-8")
ast.parse(selective)
assert 'SELECTIVE_DNS="$APP_HOME/selective_dns.py"' not in helper, "UNSAFE_CONTROLLER_LOCATION"
assert 'SELECTIVE_DNS="$APP_HOME/selective_dns.py"' not in helper
assert 'SELECTIVE_DNS="/usr/lib/directinternetmethod/selective_dns.py"' in helper, "ROOT_OWNED_SELECTOR_REQUIRED"
assert 'install -m 0755 "$SRC/system/selective_dns.py" "$ROOT/selective_dns.py"' in (R/"linux/system/install_system.sh").read_text()
assert 'SELECTIVE_DNS_OPT_IN' in helper
assert 'if [ -e /run/directinternetmethod-selective/session.json ]' in helper
assert 'verify_clean(){' in helper
assert '[ ! -e /run/directinternetmethod-selective/session.json ] || return 1' in helper
assert '[ ! -e /run/directinternetmethod-selective.conf ] || return 1' in helper, "ORPHANED_FORWARDER_CONFIG_NOT_CLEAN"
m=ast.parse(selective)
func=next(x for x in m.body if isinstance(x,ast.FunctionDef) and x.name=="monitor")
blocks=[x for x in ast.walk(func) if isinstance(x,ast.With)]
lock_blocks=[x for x in blocks if 'action_lock_observe' in ast.unparse(x.items[0].context_expr)]
assert lock_blocks
for block in lock_blocks:
  code=ast.unparse(block)
  assert 'directinternetmethod-recovery.service' not in code, "RECOVERY_CALLED_WITH_ACTION_LOCK_HELD"
assert 'directinternetmethod-recovery.service' in ast.unparse(func), "RECOVERY_CALL_MISSING"
assert 'rollback(' in ast.unparse(func)
assert 'STATE_FILE' in selective
print("PASS R247 selective-DNS lifecycle recovery lock, source path, orphan markers")
