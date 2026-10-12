#!/usr/bin/env python3
"""R248 independent backstop acceptance: negative first, rootless only."""
from pathlib import Path
import ast, re
root=Path(__file__).resolve().parents[1]
source=(root/"linux/system/selective_dns.py").read_text()
tree=ast.parse(source)
funcs={x.name:x for x in tree.body if isinstance(x,ast.FunctionDef)}
assert "backstop" in funcs, "MISSING_SECOND_INDEPENDENT_BACKSTOP"
assert "status_timer" in funcs, "MISSING_BACKSTOP_TIMER_STATUS"
assert "backstop" in source.split('choices=(',1)[1], "BACKSTOP_NOT_CALLABLE_FROM_CLI"
assert 'backstopTimer' in source, "BACKSTOP_NOT_STORED_IN_ROOT_OWNED_STATE"
assert '--on-active=' in source and '--on-unit-active=' in source, "NONRECURRING_OR_MISSING_BACKSTOP_TIMER"
assert "--timer-property=AccuracySec=1s" in source, "MISSING_EXPLICIT_TIMER_ACCURACY"
assert 'status_timer(s["backstopTimer"])' in source or 'status_timer(state["backstopTimer"])' in source, "BACKSTOP_NOT_OBSERVED"
assert 'call("systemctl","stop",state["backstopTimer"]' in source, "ROLLBACK_LEAVES_BACKSTOP_RUNNING"
body=ast.unparse(funcs["backstop"])
assert "action_lock_observe" in body, "BACKSTOP_LACKS_ACTION_LOCK"
assert "rollback" in body, "BACKSTOP_CANNOT_RESTORE_DNS"
assert 'directinternetmethod-recovery.service' in body, "BACKSTOP_CANNOT_RECOVER_ENGINE"
for node in ast.walk(funcs["backstop"]):
    if isinstance(node,ast.With) and any("action_lock_observe" in ast.unparse(x.context_expr) for x in node.items):
        assert 'directinternetmethod-recovery.service' not in ast.unparse(node), "BACKSTOP_RECOVERY_RACES_ACTION_LOCK"
print("PASS R248 independent repeating Backstop, session ownership, lock order and recovery contract")
