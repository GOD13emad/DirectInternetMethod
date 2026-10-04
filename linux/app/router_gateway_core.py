#!/usr/bin/env python3
from __future__ import annotations
import ipaddress, json, pathlib, re, socket, urllib.request

APP_HOME=pathlib.Path.home()/".local/share/DirectInternetMethod"
DATA_PATH=APP_HOME/"router_gateway/providers.json"
RAW_URL="https://raw.githubusercontent.com/GOD13emad/DirectInternetMethod/main/router_gateway/providers.json"
VPNBOOK_URL="https://www.vpnbook.com/freevpn/pptp-vpn"

def _load():
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))

def _server(p):
    return p.get("ip") or p.get("host") or ""

def _guide(data,guide_id,protocol):
    g=next((x for x in data.get("routerGuides",[]) if x.get("id")==guide_id),None) or {}
    return g.get("l2tp" if str(protocol).startswith("L2TP") else "pptp","")

def _config(data,p,guide_id):
    protocol=str(p.get("protocol",""))
    lines=[
      "Direct Internet Method — Router Gateway",
      f"Provider: {p.get('provider','')}",
      f"Protocol: {protocol}",
      f"Country: {p.get('country','')}",
      f"Server: {_server(p)}",
      f"Hostname (reference): {p.get('host','')}" if p.get("ip") else "",
      f"Username: {p.get('username','')}",
      f"Password: {p.get('password','')}",
      f"IPsec PSK / Secret: {p.get('preSharedKey','')}" if protocol.startswith("L2TP") else "",
      f"Security: {p.get('security','')}",
      f"Credential status: {p.get('credentialStatus','')}",
      f"Source observed UTC: {p.get('sourceObservedUtc','')}",
      "",
      _guide(data,guide_id,protocol),
      "",
      "WARNING: PPTP is a legacy fallback; prefer L2TP/IPsec or OpenVPN." if protocol.startswith("PPTP") else
      "Tip: use the numeric server IP if .opengw.net is filtered."
    ]
    return "\n".join(x for x in lines if x is not None)

def _test(p):
    host=_server(p)
    pptp=str(p.get("protocol","")).startswith("PPTP")
    port=1723 if pptp else 443
    try:
        ip=socket.gethostbyname(host)
        if not ipaddress.ip_address(ip).is_global:
            return False,f"DNS intercepted/private address {ip}"
        s=socket.create_connection((ip,port),timeout=2.0)
        s.close()
        if pptp:
            return True,f"PPTP control TCP/1723 reachable {ip}; GRE/authentication not verified"
        return True,f"Generic endpoint TCP/443 reachable {ip}; L2TP/IPsec UDP 500/4500/authentication not verified"
    except Exception as e:
        return False,str(e)

def _refresh():
    req=urllib.request.Request(RAW_URL,headers={"User-Agent":"DirectInternetMethod/1.5"})
    with urllib.request.urlopen(req,timeout=9) as r:
        data=json.load(r)
    try:
        req=urllib.request.Request(VPNBOOK_URL,headers={"User-Agent":"DirectInternetMethod/1.5"})
        with urllib.request.urlopen(req,timeout=9) as r:
            html=r.read().decode("utf-8","replace")
        m=re.search(r"(?is)Password.{0,1400}?(?:<code[^>]*>|>)([A-Za-z0-9]{6,16})(?:</code>|<)",html)
        if m:
            for p in data.get("profiles",[]):
                if p.get("provider")=="VPNBook":
                    p["password"]=m.group(1);p["credentialStatus"]="LIVE_REFRESHED_ROTATING"
    except Exception:
        pass
    DATA_PATH.parent.mkdir(parents=True,exist_ok=True)
    tmp=DATA_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    tmp.replace(DATA_PATH)
    return data
