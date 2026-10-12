#!/usr/bin/env python3
"""Negative-first Tailscale split GUI / backend scope consistency contract.

AST-only extraction, NO GTK, NO network/route/service operations, NO user files.
"""
import ast
import json
import hashlib
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
    def is_file(self): return self.path in self.entries
    def read_bytes(self): return self.read_text().encode("utf-8")
    def __truediv__(self,child): return FakePath(self.path.rstrip("/")+"/"+child)

scope=FakePath("scope.txt")
state=FakePath("state.json")
env={"json":json,"STATE":state,"SCOPE_FILE":scope,"pathlib":SimpleNamespace(Path=FakePath),
     "os":SimpleNamespace(getuid=lambda:1000),
     "_external_tunnel_active":lambda:False,
     "_tailscale_split_safe":lambda:True,
     "_coexistence_backend_ready":lambda:True,
     "selective_dns_optin_state":lambda:"OFF",
     "_systemd_unit_matches":lambda *args:False}
exec(code,env)
def mode():return env["load_state"]()

assert mode()["mode"]=="OFF",("missing scope should default targeted",mode())
print("PASS absent scope defaults to targeted, split Tailscale is not VPN-blocked")

FakePath.entries["scope.txt"]="targeted\n"
assert mode()["mode"]=="OFF",("targeted must allow Start",mode())
print("PASS targeted config allows Start while physical default route remains")

env["_coexistence_backend_ready"]=lambda:False
result=mode()
assert result["mode"]=="BACKEND_UPDATE_REQUIRED" and "backend" in result["detail"].lower(),(
    "OLD BACKEND MUST NOT ALLOW START UNDER SPLIT TAILSCALE",result)
env["_coexistence_backend_ready"]=lambda:True
print("PASS legacy/mismatched privileged backend blocks GUI Start while Tailscale split is active")

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

assert 'mode in ("BLOCKED","CONFIG_REQUIRED","BACKEND_UPDATE_REQUIRED","CONFLICT")' in src
assert 'start_ok=(mode=="OFF")' in src
assert 'w.close();self.refresh()' in src
print("PASS CONFIG_REQUIRED warning; no Start until Strategy save; immediate refresh")
print("PASS 9/9 GUI/Scope contract cases; no live network mutation")


# Validate helper-file identity, metadata UID/version, and symlink resistance
# without touching any real system path or using a real privilege boundary.
helperfunc=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=="_coexistence_backend_ready")
helpercode=compile(ast.Module(body=[helperfunc],type_ignores=[]),"<gui_privileged_backend_guard>","exec")
good="/mock/priv/direct_method_helper.sh"
meta="/var/lib/directinternetmethod/install.json"
h_env={"PRIV_HOME":FakePath("/mock/priv"),
       "pathlib":SimpleNamespace(Path=FakePath),
       "json":json,"hashlib":hashlib,
       "os":SimpleNamespace(getuid=lambda:1000),
       "COEXIST_HELPER_SHA256":hashlib.sha256(b"safe-backend").hexdigest()}
exec(helpercode,h_env)
check=h_env["_coexistence_backend_ready"]
assert check() is False
FakePath.entries[good]="safe-backend"
FakePath.entries[meta]='{"version":"1.5.2","uid":1000}'
assert check() is True, "pinned helper and metadata must be recognized"
FakePath.entries[good]="different-backend"
assert check() is False, "foreign helper must be refused"
FakePath.entries[good]="safe-backend"
FakePath.entries[meta]='{"version":"1.5.1","uid":1000}'
assert check() is False, "old metadata must be refused"
FakePath.entries[meta]='{"version":"1.5.2","uid":1001}'
assert check() is False, "different user metadata must be refused"
FakePath.entries[meta]='{"version":"1.5.2","uid":1000}'
FakePath.symlinks.add(good)
assert check() is False, "helper symlink must be refused"
FakePath.symlinks.clear()
FakePath.symlinks.add(meta)
assert check() is False, "metadata symlink must be refused"
FakePath.symlinks.clear()
print("PASS 7/7 pinned privileged backend identity gates; no system mutations")
