#!/usr/bin/env python3
"""Reject undefined globals in the privileged selective-DNS controller."""
import builtins,pathlib,symtable
P=pathlib.Path(__file__).resolve().parents[1]/"linux/system/selective_dns.py"
s=P.read_text(encoding="utf-8")
def undefined(text):
 tree=symtable.symtable(text,str(P),"exec")
 declared={v.get_name() for v in tree.get_symbols()
           if v.is_assigned() or v.is_imported() or v.is_namespace()}
 allowed=set(dir(builtins))|{"__name__","__file__","__package__","__annotations__"}
 bad=set()
 def go(node):
  for value in node.get_symbols():
   if value.is_global() and value.is_referenced() and value.get_name() not in declared|allowed:
    bad.add((node.get_name(),value.get_name()))
  for child in node.get_children():go(child)
 go(tree)
 return sorted(bad)
assert undefined(s)==[],undefined(s)
print("PASS R247 privileged controller no unresolved global names")
negative=s+"\ndef intentionally_bad_r247_function():\n    return R247_UNKNOWN_UNBOUND_TEST_VALUE\n"
assert ("intentionally_bad_r247_function","R247_UNKNOWN_UNBOUND_TEST_VALUE") in undefined(negative)
print("PASS R247 negative fixture catches undefined global before Root runtime")
