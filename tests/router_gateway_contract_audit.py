#!/usr/bin/env python3
from pathlib import Path
import json,sys,re
R=Path(__file__).resolve().parents[1]
D={"schema":1,"status":"PASS","checks":{}}
def check(n,c):
    D["checks"][n]=bool(c)
    if not c:D["status"]="FAIL"
m=json.loads((R/"router_gateway/providers.json").read_text(encoding="utf-8"))
profiles=m.get("profiles",[])
l2=[p for p in profiles if p.get("protocol")=="L2TP/IPsec"]
pptp=[p for p in profiles if p.get("protocol")=="PPTP"]
check("schema",m.get("schema")==1 and m.get("version")=="1.3.2")
check("l2tp_present",len(l2)>=3)
check("l2tp_credentials_complete",all(p.get("username") and p.get("password") and p.get("preSharedKey") for p in l2))
vpngate=[p for p in l2 if p.get("provider")=="VPN Gate"]
pilovali=[p for p in l2 if p.get("provider")=="Pilovali"]
check("vpngate_official_credentials",len(vpngate)>=5 and all(p.get("username")=="vpn" and p.get("password")=="vpn" and p.get("preSharedKey")=="vpn" for p in vpngate))
check("pilovali_official_profile",len(pilovali)>=1 and all(p.get("host")=="freevpn.pilovali.nl" and p.get("username")=="VPN" and p.get("password")=="PASSWORD" and p.get("preSharedKey")=="vpn" for p in pilovali))
check("l2tp_numeric_ip",all(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}",p.get("ip","")) for p in l2 if p.get("ip")))
check("pptp_present",len(pptp)>=3)
check("pptp_rotating_status",all(p.get("username")=="vpnbook" and p.get("password") and "ROTATING" in p.get("credentialStatus","") for p in pptp))
check("pptp_legacy_label",all("legacy" in p.get("security","").lower() for p in pptp))
guides={g.get("id") for g in m.get("routerGuides",[])}
check("router_guides",{"generic","tplink","asus","mikrotik"}<=guides)
wclient=(R/"windows/gui/RouterGatewayClient.cs").read_text(encoding="utf-8")
wxaml=(R/"windows/gui/RouterGatewayWindow.xaml").read_text(encoding="utf-8")
mainx=(R/"windows/gui/MainWindow.xaml").read_text(encoding="utf-8")
iss=(R/"windows/installer/DirectInternetMethod.iss").read_text(encoding="utf-8")
check("windows_ui_entry","Router Gateway" in mainx and "RouterGatewayWindow" in wclient+wxaml)
check("windows_grid_readable_dark_rows", all(x in wxaml for x in ('RowBackground="#0E1D2D"','AlternatingRowBackground="#10263A"','TargetType="{x:Type DataGridRow}"','TargetType="{x:Type DataGridCell}"','TargetType="{x:Type DataGridColumnHeader}"','Foreground="#F7FAFC"')))
check("windows_offline_first","BundledPath" in wclient and "CachePath" in wclient and "RefreshAsync" in wclient)
check("windows_non_mutating_test","TestAsync" in wclient and "Ping" in wclient and "TcpClient" in wclient)
check("windows_private_dns_guard","IsPublicEndpointAddress" in wclient and "DNS intercepted/private address" in wclient)
check("windows_installer_data","router_gateway" in iss and "providers.json" in iss)
lmod=(R/"linux/app/router_gateway.py").read_text(encoding="utf-8")
lui=(R/"linux/app/direct_internet_method.py").read_text(encoding="utf-8")
linstall=(R/"linux/install.sh").read_text(encoding="utf-8")
check("linux_ui_entry","RouterGatewayWindow" in lui and '"Router Gateway","router"' in lui)
check("linux_offline_first","DATA_PATH" in lmod and "RAW_URL" in lmod and "_refresh" in lmod)
check("linux_non_mutating_test","socket.create_connection" in lmod and "systemctl" not in lmod and "nmcli" not in lmod)
check("linux_private_dns_guard","ipaddress.ip_address(ip).is_global" in lmod and "DNS intercepted/private address" in lmod)
check("linux_installer_data",'router_gateway/providers.json' in linstall and 'router_gateway.py' in linstall)
check("no_router_auto_mutation",all(x not in wclient+lmod for x in ["192.168.0.1/admin","192.168.1.1/admin","selenium","Playwright"]))
print(json.dumps(D,indent=2,ensure_ascii=False))
sys.exit(0 if D["status"]=="PASS" else 20)
