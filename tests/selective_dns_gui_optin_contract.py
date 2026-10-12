#!/usr/bin/env python3
"""R247 GUI selected-DNS consent and compatibility tests, isolated user filesystem."""
import ast, os, pathlib, tempfile
from hashlib import sha256
from types import SimpleNamespace
from pathlib import Path
R=Path(__file__).resolve().parents[1]
src=(R/"linux/app/direct_internet_method.py").read_text()
tree=ast.parse(src)
funcs=[n for n in tree.body if isinstance(n,ast.FunctionDef) and
       n.name in ("selective_dns_optin_state","selective_dns_optin_save")]
assert len(funcs)==2
with tempfile.TemporaryDirectory(prefix="dim-r247-ui-optin-") as d:
    opt=pathlib.Path(d)/"selective-dns-optin.txt"
    ns={"os":os,"tempfile":tempfile,"SELECTIVE_DNS_OPT_IN":opt,
        "SELECTIVE_DNS_TOKEN":"I_ACCEPT_UNENCRYPTED_SELECTIVE_DNS_V1"}
    exec(compile(ast.Module(body=funcs,type_ignores=[]),"<UI_OPTIN_ONLY>","exec"),ns)
    state=ns["selective_dns_optin_state"]
    save=ns["selective_dns_optin_save"]
    assert state()=="OFF";print("PASS OFF default, no silent plaintext DNS")
    save(True)
    assert state()=="ON";print("PASS explicit local opt-in")
    assert opt.stat().st_mode & 0o777==0o600
    print("PASS opt-in file has private 0600 mode")
    assert opt.read_text()=="I_ACCEPT_UNENCRYPTED_SELECTIVE_DNS_V1\n"
    print("PASS exact consent token")
    opt.write_text("I_ACCEPT_MAYBE\n")
    assert state()=="INVALID";print("PASS refuses malformed consent")
    save(False)
    assert not opt.exists() and state()=="OFF"
    print("PASS disabling restores opt-out default")
    original=pathlib.Path(d)/"user-owned.txt"
    original.write_text("unrelated user content")
    opt.symlink_to(original)
    assert state()=="INVALID";print("PASS foreign symlink invalid")
    try:save(True)
    except ValueError:print("PASS cannot overwrite symlink")
    else:raise AssertionError("DANGEROUS_SYMLINK_OVERWRITE")
    assert original.read_text()=="unrelated user content"
    print("PASS foreign user content unchanged")
assert "UNENCRYPTED" in src and "Disabled by default" in src
assert "SELECTIVE_DNS_TOKEN" in src
assert "scope_toggle" in src and 'value!="balanced"' in src
print("PASS R247 9/9 GUI opt-in/privacy controls")
