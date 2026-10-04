#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, json, pathlib, queue, socket, sys, threading
R=pathlib.Path(__file__).resolve().parents[1]
mod_path=R/"linux/app/router_gateway_core.py"
spec=importlib.util.spec_from_file_location("router_gateway_smoke",mod_path)
rg=importlib.util.module_from_spec(spec);spec.loader.exec_module(rg)
rg.DATA_PATH=R/"router_gateway/providers.json"
data=rg._load()
profiles=data.get("profiles",[])
assert len(profiles)>=8
l2=next(p for p in profiles if p.get("protocol")=="L2TP/IPsec")
pptp=next(p for p in profiles if p.get("protocol")=="PPTP")
cfg=rg._config(data,l2,"generic")
for token in ("Protocol: L2TP/IPsec","Server:","Username: vpn","Password: vpn","IPsec PSK / Secret: vpn"):
    assert token in cfg, token
orig=socket.gethostbyname
try:
    socket.gethostbyname=lambda _host:"10.10.34.35"
    ok,detail=rg._test(pptp)
finally:
    socket.gethostbyname=orig
assert not ok and "DNS intercepted/private address 10.10.34.35" in detail
q=queue.Queue(maxsize=1)
def _live_worker():
    try:
        q.put(rg._test(l2),block=False)
    except Exception as e:
        q.put((False,f"exception:{e}"),block=False)
t=threading.Thread(target=_live_worker,daemon=True)
t.start()
try:
    live_ok,live_detail=q.get(timeout=5.0)
except queue.Empty:
    live_ok=False;live_detail="informational live endpoint probe timed out after 5s"
print(json.dumps({
 "status":"PASS",
 "profiles":len(profiles),
 "configFields":"PASS",
 "privateDnsGuard":"PASS",
 "liveEndpointInformational":{"ok":bool(live_ok),"detail":live_detail,"server":rg._server(l2)}
},ensure_ascii=False,indent=2))
