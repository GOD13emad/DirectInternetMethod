#!/usr/bin/env python3
"""Pure GUI state-mode test, no GTK import or network mutation."""
import ast
import json
from pathlib import Path
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/"linux/app/direct_internet_method.py").read_text(encoding="utf-8")
tree=ast.parse(source)
load=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=="load_state")
code=compile(ast.Module(body=[load],type_ignores=[]),"<isolated_gui_mode>","exec")

class FakePath:
    files={}
    exists_on=set()
    def __init__(self,path):
        self.path=str(path)
    def exists(self):
        return self.path in self.exists_on
    def read_text(self,encoding="utf-8"):
        if self.path not in self.files:
            raise FileNotFoundError(self.path)
        return self.files[self.path]

env={"STATE":FakePath("mock-state.json"),"pathlib":SimpleNamespace(Path=FakePath),
     "json":json,"os":SimpleNamespace(getuid=lambda:1000),
     "_systemd_unit_matches":lambda u,p,w:bool(p) and int(p)==400 and u==w,
     "_external_tunnel_active":lambda:False,
     "_tailscale_split_safe":lambda:True}
exec(code,env)
state=env["load_state"]()
assert state["mode"]=="OFF" and "Tailscale split" in state["detail"],state
print("PASS isolated GUI OFF with Tailscale split => actionable Start")

ts={"dnsMode":"system-preserved","tailscaleCoexistence":True,
    "ctrldPid":0,"ctrldUnit":"",
    "nfqwsPid":400,"nfqwsUnit":"directinternetmethod-nfqws-1000.service",
    "physicalInterface":"enp1s0"}
FakePath.files["mock-state.json"]=json.dumps(ts)
state=env["load_state"]()
assert state["mode"]=="ACTIVE" and "DNS/MagicDNS preserved" in state["detail"],state
assert "DoH" not in state["detail"],state
print("PASS isolated GUI ACTIVE coexists without invented ctrld/DoH")

env["_external_tunnel_active"]=lambda:True
state=env["load_state"]()
assert state["mode"]=="CONFLICT" and "Unsupported" in state["detail"],state
print("PASS unexpected exit node or second tunnel => GUI CONFLICT")

env["_external_tunnel_active"]=lambda:False
ts["nfqwsPid"]=0
FakePath.files["mock-state.json"]=json.dumps(ts)
state=env["load_state"]()
assert state["mode"]=="STALE",state
print("PASS missing nfqws => GUI STALE")

normal={"ctrldPid":400,"ctrldUnit":"directinternetmethod-ctrld-1000.service",
        "nfqwsPid":400,"nfqwsUnit":"directinternetmethod-nfqws-1000.service",
        "physicalInterface":"enp1s0"}
FakePath.files["mock-state.json"]=json.dumps(normal)
state=env["load_state"]()
assert state["mode"]=="CONFLICT" and "Stop then Start" in state["detail"],state
print("PASS Tailscale appearing after standalone Direct DoH triggers conflict")
env["_tailscale_split_safe"]=lambda:False
state=env["load_state"]()
assert state["mode"]=="ACTIVE" and "DoH" in state["detail"],state
print("PASS standalone mode retains DoH status")
print("PASS 6/6 GUI coexistence state fixtures, no network mutations")


# Regression: ip -o link prints "4: tailscale0: <...>" with TWO ": " separators.
# Parsing with split(": ", 1) mistakenly includes interface description.
f=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=="_tailscale_split_safe")
class FakeCompleted:
    def __init__(self,out):
        self.stdout=out
        self.returncode=0
exit_enabled=[False]
def fake_subprocess(args,*other,**kwargs):
    if args==["ip","-o","link","show","up"]:
        return FakeCompleted("\n".join(["1: lo: <LOOPBACK,UP>",
                                        "2: enp1s0: <BROADCAST,UP>",
                                        "4: tailscale0: <POINTOPOINT,UP>"])+"\n")
    if args[0]=="nmcli":
        return FakeCompleted("802-3-ethernet:enp1s0\ntun:tailscale0\n")
    if args==["tailscale","status","--json"]:
        return FakeCompleted(json.dumps({"BackendState":"Running",
                                         "ExitNodeStatus":{"ID":"exit"} if exit_enabled[0] else None}))
    if args[0]=="ip" and args[1]=="-4":
        return FakeCompleted("100.100.100.100 dev tailscale0\n")
    if args[0]=="ip" and args[1]=="-6":
        return FakeCompleted("fd7a:115c:a1e0::/48 dev tailscale0\n")
    raise AssertionError("UNEXPECTED_UI_COMMAND:"+repr(args))
FakePath.exists_on.add("/sys/class/net/tailscale0")
g={"subprocess":SimpleNamespace(run=fake_subprocess),
   "json":json,"pathlib":SimpleNamespace(Path=FakePath),
   "_top_default_iface":lambda:"enp1s0"}
exec(compile(ast.Module(body=[f],type_ignores=[]),"<ui_ip_link_format>","exec"),g)
assert g["_tailscale_split_safe"](), "GUI_REJECTED_VALID_TWO_SEPARATOR_IP_LINK"
exit_enabled[0]=True
assert not g["_tailscale_split_safe"](), "GUI_ACCEPTED_EXIT_NODE"
print("PASS real ip-link two-separator and exit-node UI regressions")
