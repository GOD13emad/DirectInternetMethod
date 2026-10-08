#!/usr/bin/env python3
"""Offline, unprivileged Tailscale split-coexistence preflight matrix."""
from __future__ import annotations
import os
import pathlib
import re
import subprocess
import tempfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
HELPER=(ROOT/"linux/app/direct_method_helper.sh").read_text(encoding="utf-8")
UI=(ROOT/"linux/app/direct_internet_method.py").read_text(encoding="utf-8")
def function(name):
    match=re.search(r"^"+re.escape(name)+r"\(\)\{\n.*?^\}\n",HELPER,re.M|re.S)
    assert match is not None, name
    return match.group(0)

preamble="\n".join(function(s) for s in ("physical_iface","top_iface","external_tunnel_active","tailscale_split_safe"))
assert "dnsMode" in HELPER and "tailscaleCoexistence" in HELPER
assert "DNS_MODE=\"system-preserved\"" in HELPER
assert "TAILSCALE_ALL_SITES_UNSUPPORTED" in HELPER
assert "meta mark & 0xff0000 == 0x80000 return" in HELPER
assert HELPER.index("meta mark & 0xff0000 == 0x80000 return") < HELPER.index("tcp dport 80 ct original packets")
assert "if [ \"$DNS_MODE\" = \"direct-doh\" ]; then" in HELPER
assert HELPER.index("if tailscale_split_safe; then") < HELPER.index("ip link add \"$DNS_IF\" type dummy")
assert "system-preserved" in UI and "_tailscale_split_safe" in UI

ip_script=r"""#!/usr/bin/env bash
case "$*" in
  "-4 route show default")
    if [ "$MOCK_TOP_TS" = "1" ]; then
      echo "default dev tailscale0"
    else
      echo "default via 192.168.20.1 dev enp1s0 metric 100"
    fi ;;
  "link show tailscale0")
    if [ "$MOCK_HAS_TS" = "1" ]; then echo "4: tailscale0: <POINTOPOINT,UP>"; else exit 1; fi ;;
  "-o link show up")
    echo "2: enp1s0: <BROADCAST,UP>"
    [ "$MOCK_HAS_TS" = "1" ] && echo "4: tailscale0: <POINTOPOINT,UP>"
    [ "$MOCK_OTHER_TUN" = "1" ] && echo "5: wg0: <POINTOPOINT,UP>"
    exit 0 ;;
  "-4 route show table 52")
    if [ "$MOCK_EXIT_ROUTES" = "1" ]; then
      echo "0.0.0.0/1 dev tailscale0"
      echo "128.0.0.0/1 dev tailscale0"
    else
      [ "$MOCK_HAS_TS" = "1" ] && echo "100.100.100.100 dev tailscale0"
    fi
    exit 0 ;;
  "-6 route show table 52")
    [ "$MOCK_EXIT6" = "1" ] && echo "::/1 dev tailscale0"
    exit 0 ;;
  *) echo "UNEXPECTED_IP_COMMAND:$*" >&2; exit 89 ;;
esac
"""
nmcli_script=r"""#!/usr/bin/env bash
[ "$*" = "-t -f TYPE,DEVICE connection show --active" ] || exit 89
if [ "$MOCK_NMCLI_EMPTY" = "1" ]; then
  echo "802-3-ethernet:enp1s0"
  exit 0
fi
echo "802-3-ethernet:enp1s0"
[ "$MOCK_HAS_TS" = "1" ] && echo "tun:tailscale0"
[ "$MOCK_OTHER_TUN" = "1" ] && echo "wireguard:wg0"
[ "$MOCK_RENAMED_VPN" = "1" ] && echo "wireguard:private-office"
exit 0
"""
tailscale_script=r"""#!/usr/bin/env bash
[ "$*" = "status --json" ] || exit 89
if [ "$MOCK_TS_RUNNING" = "0" ]; then
  echo '{"BackendState":"Stopped","ExitNodeStatus":null}'
elif [ "$MOCK_EXIT_JSON" = "1" ]; then
  echo '{"BackendState":"Running","ExitNodeStatus":{"ID":"node"}}'
else
  echo '{"BackendState":"Running","ExitNodeStatus":null}'
fi
"""
cases=[
    ("tailscale_peer_routes",{}, "coexist"),
    ("tailscale_exit_node_status",{"MOCK_EXIT_JSON":"1"},"blocked"),
    ("tailscale_exit_routes",{"MOCK_EXIT_ROUTES":"1"},"blocked"),
    ("tailscale_ipv6_exit_routes",{"MOCK_EXIT6":"1"},"blocked"),
    ("tailscale_default_interface",{"MOCK_TOP_TS":"1"},"blocked"),
    ("tailscale_daemon_stopped",{"MOCK_TS_RUNNING":"0"},"blocked"),
    ("other_active_wireguard",{"MOCK_OTHER_TUN":"1"},"blocked"),
    ("networkmanager_renamed_wireguard",{"MOCK_RENAMED_VPN":"1"},"blocked"),
    ("non_networkmanager_wireguard",{"MOCK_OTHER_TUN":"1","MOCK_NMCLI_EMPTY":"1"},"blocked"),
    ("tailscale_without_nmcli_visibility",{"MOCK_NMCLI_EMPTY":"1"},"coexist"),
    ("standalone_without_tailscale",{"MOCK_HAS_TS":"0"},"direct"),
]
with tempfile.TemporaryDirectory(prefix="dim_tailscale_preflight_") as d:
    binpath=pathlib.Path(d)
    for name,content in (("ip",ip_script),("nmcli",nmcli_script),("tailscale",tailscale_script)):
        path=binpath/name
        path.write_text(content,encoding="utf-8")
        path.chmod(0o755)
    src=preamble+"""
if external_tunnel_active; then
  if tailscale_split_safe; then echo MODE=coexist; else echo MODE=blocked; fi
else
  echo MODE=direct
fi
"""
    for name,overrides,expected in cases:
        env=os.environ.copy()
        env.update({"MOCK_HAS_TS":"1","MOCK_TOP_TS":"0","MOCK_TS_RUNNING":"1","MOCK_EXIT_JSON":"0","MOCK_OTHER_TUN":"0","MOCK_EXIT_ROUTES":"0","MOCK_EXIT6":"0","MOCK_NMCLI_EMPTY":"0","MOCK_RENAMED_VPN":"0"})
        env.update(overrides)
        env["PATH"]=str(binpath)+os.pathsep+env.get("PATH","")
        p=subprocess.run(["bash","-c",src],env=env,capture_output=True,text=True,timeout=15)
        got=p.stdout.strip()
        assert p.returncode==0 and got=="MODE="+expected,(name,p.returncode,got,p.stderr)
        print(f"PASS {name}: {got}")
print(f"PASS tailscale_coexistence_preflight {len(cases)}/{len(cases)} cases; no network mutations")
