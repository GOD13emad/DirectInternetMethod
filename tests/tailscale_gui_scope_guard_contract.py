#!/usr/bin/env python3
"""Negative-first Tailscale split GUI / backend scope consistency contract.

AST-only extraction, NO GTK, NO network/route/service operations, NO user files.
"""
import ast
import json
from pathlib import Path
from types import SimpleNamespace

src=(Path(__file__).resolve().parents[1]/"linux/app/direct_internet_method.py").read_text()
tree=ast.parse(src)
func=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=="load_state")
code=compile(ast.Module(body=[func],type_ignores=[]),"<gui_split_scope>","exec")

class FakePath:
    entries={}
    symlinks=set()
    unreadable=set()
    def __init__(self,path): self.path=str(path)
    def read_text(self,encoding="utf-8"):
        if self.path in self.unreadable: raise PermissionError(self.path)
        if self.path not in self.entries: raise FileNotFoundError(self.path)
        return self.entries[self.path]
    def is_symlink(self): return self.path in self.symlinks
    def exists(self): return self.path in self.entries or self.path in self.symlinks

scope=FakePath("scope.txt")
state=FakePath("state.json")
env={"json":json,"STATE":state,"SCOPE_FILE":scope,"pathlib":SimpleNamespace(Path=FakePath),
     "os":SimpleNamespace(getuid=lambda:1000),
     "_external_tunnel_active":lambda:False,
     "_tailscale_split_safe":lambda:True,
     "_systemd_unit_matches":lambda *args:False}
exec(code,env)
def mode():return env["load_state"]()

assert mode()["mode"]=="OFF",("missing scope should default targeted",mode())
print("PASS absent scope defaults to targeted, split Tailscale is not VPN-blocked")

FakePath.entries["scope.txt"]="targeted\n"
assert mode()["mode"]=="OFF",("targeted must allow Start",mode())
print("PASS targeted config allows Start while physical default route remains")

FakePath.entries["scope.txt"]="all-sites\n"
result=mode()
assert result["mode"]=="CONFIG_REQUIRED" and "Strategy" in result["detail"] and "Targeted" in result["detail"],(
    "unsafe all-sites treated as actionable Start",result)
print("PASS incompatible all-sites explicitly requests Strategy -> Targeted")

FakePath.entries["scope.txt"]="garbage\n"
assert mode()["mode"]=="CONFIG_REQUIRED",("invalid scope should be flagged",mode())
print("PASS invalid scope fails closed")

FakePath.entries["scope.txt"]="targeted\n"
FakePath.symlinks.add("scope.txt")
assert mode()["mode"]=="CONFIG_REQUIRED",("symlink scope should be rejected",mode())
FakePath.symlinks.clear()
print("PASS symlink scope not accepted silently")

FakePath.unreadable.add("scope.txt")
assert mode()["mode"]=="CONFIG_REQUIRED",("unreadable scope should be rejected",mode())
FakePath.unreadable.clear()
print("PASS unreadable scope not accepted silently")

env["_external_tunnel_active"]=lambda:True
assert mode()["mode"]=="BLOCKED",("exit node / foreign VPN must still block",mode())
print("PASS unknown VPN/exit node still fail-closed")

assert 'mode in ("BLOCKED","CONFIG_REQUIRED","CONFLICT")' in src
assert 'start_ok=(mode=="OFF")' in src
assert 'w.close();self.refresh()' in src
print("PASS CONFIG_REQUIRED warning; no Start until Strategy save; immediate refresh")
print("PASS 8/8 GUI/Scope contract cases; no live network mutation")
