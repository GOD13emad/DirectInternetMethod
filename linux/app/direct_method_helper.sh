#!/usr/bin/env bash
set -euo pipefail
ACTION="${1:-status}"
APP_HOME="${2:-}"
USER_UID="${3:-1000}"
USER_GID="${4:-1000}"
[ "$(id -u)" -eq 0 ] || { echo '{"ok":false,"error":"ROOT_REQUIRED"}'; exit 77; }
[ -n "$APP_HOME" ] || { echo '{"ok":false,"error":"APP_HOME_REQUIRED"}'; exit 64; }
BIN="$APP_HOME/runtime/usr/bin"
DM="$APP_HOME/directmethod"
STATE="$DM/state.json"
CTRLD_CFG="$DM/ctrld.toml"
HOSTS="$APP_HOME/direct_hosts.txt"
CTRLD="$BIN/ctrld"
NFQWS="$BIN/nfqws"
TABLE="directinternetmethod"
DNS_IF="dimdns0"
DNS_IP="192.0.2.53"
QNUM=200
RUN_HOSTS="/run/directinternetmethod-hosts.txt"
CPID=""
NPID=""
mkdir -p "$DM"; chmod 0700 "$DM"; chown "$USER_UID:$USER_GID" "$DM" || true

json_escape(){ python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; }
physical_iface(){
  ip -4 route show default | awk '$0 !~ / dev (tun|tap|wg|warp|tailscale|zt|docker|br-|veth)/ {for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}'
}
top_iface(){ ip -4 route show default | head -1 | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}'; }
pid_alive(){ [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null; }
cleanup(){
  pid_alive "${NPID:-}" && kill "$NPID" 2>/dev/null || true
  pid_alive "${CPID:-}" && kill "$CPID" 2>/dev/null || true
  if [ -f "$STATE" ]; then
    CPID="$(python3 - "$STATE" <<'PY'
import json,sys
try: print(json.load(open(sys.argv[1])).get("ctrldPid",""))
except Exception: print("")
PY
)"
    NPID="$(python3 - "$STATE" <<'PY'
import json,sys
try: print(json.load(open(sys.argv[1])).get("nfqwsPid",""))
except Exception: print("")
PY
)"
    pid_alive "$NPID" && kill "$NPID" 2>/dev/null || true
    pid_alive "$CPID" && kill "$CPID" 2>/dev/null || true
  fi
  nft delete table inet "$TABLE" 2>/dev/null || true
  if ip link show "$DNS_IF" >/dev/null 2>&1; then
    IDX="$(cat /sys/class/net/$DNS_IF/ifindex 2>/dev/null || true)"
    [ -n "$IDX" ] && busctl call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager RevertLink i "$IDX" >/dev/null 2>&1 || true
    ip link del "$DNS_IF" 2>/dev/null || true
  fi
  rm -f "$RUN_HOSTS" "$STATE"
}
status(){
  local cp="" np=""
  if [ -f "$STATE" ]; then
    cp="$(python3 - "$STATE" <<'PY'
import json,sys
try: print(json.load(open(sys.argv[1])).get("ctrldPid",""))
except Exception: print("")
PY
)"
    np="$(python3 - "$STATE" <<'PY'
import json,sys
try: print(json.load(open(sys.argv[1])).get("nfqwsPid",""))
except Exception: print("")
PY
)"
  fi
  python3 - "$STATE" "$cp" "$np" <<'PY'
import json,os,sys
state={}
try: state=json.load(open(sys.argv[1]))
except Exception: pass
def alive(x):
 try: os.kill(int(x),0); return True
 except Exception: return False
print(json.dumps({"ok":bool(state and alive(sys.argv[2]) and alive(sys.argv[3])),"state":state,"ctrldAlive":alive(sys.argv[2]),"nfqwsAlive":alive(sys.argv[3])}))
PY
}
case "$ACTION" in
 stop)
   cleanup
   echo '{"ok":true,"state":"STOPPED"}'
   ;;
 status)
   status
   ;;
 start)
   if [ -f "$STATE" ]; then
      CPID="$(python3 - "$STATE" <<'PY'
import json,sys
try: print(json.load(open(sys.argv[1])).get("ctrldPid",""))
except Exception: print("")
PY
)"
      NPID="$(python3 - "$STATE" <<'PY'
import json,sys
try: print(json.load(open(sys.argv[1])).get("nfqwsPid",""))
except Exception: print("")
PY
)"
      if pid_alive "$CPID" && pid_alive "$NPID"; then
         echo '{"ok":true,"state":"ALREADY_ACTIVE"}'; exit 0
      fi
      cleanup
   elif nft list table inet "$TABLE" >/dev/null 2>&1; then
      echo '{"ok":false,"error":"FOREIGN_OR_STALE_OWNERSHIP_TABLE"}'; exit 69
   fi
   [ -x "$CTRLD" ] && [ -x "$NFQWS" ] && [ -s "$HOSTS" ] || { echo '{"ok":false,"error":"RUNTIME_NOT_PROVISIONED"}'; exit 70; }
   install -m 0644 "$HOSTS" "$RUN_HOSTS"
   TOP="$(top_iface)"; PHY="$(physical_iface)"
   [ -n "$PHY" ] || { echo '{"ok":false,"error":"PHYSICAL_DEFAULT_ROUTE_MISSING"}'; exit 71; }
   case "$TOP" in tun*|tap*|wg*|warp*|tailscale*|zt*) echo '{"ok":false,"error":"EXTERNAL_TUN_DEFAULT_ACTIVE"}'; exit 72;; esac
   command -v nft >/dev/null && command -v resolvectl >/dev/null || { echo '{"ok":false,"error":"NFT_OR_RESOLVECTL_MISSING"}'; exit 73; }
   if ip link show "$DNS_IF" >/dev/null 2>&1; then
      echo '{"ok":false,"error":"DNS_INTERFACE_ALREADY_EXISTS"}'; exit 74
   fi
   ip link add "$DNS_IF" type dummy
   ip addr add "$DNS_IP/32" dev "$DNS_IF"
   ip link set "$DNS_IF" up
   DIX="$(cat /sys/class/net/$DNS_IF/ifindex)"
   cat > "$CTRLD_CFG" <<'EOF'
[service]
log_level = "warn"
cache_enable = true
cache_size = 4096
cache_serve_stale = true

[network.0]
cidrs = ["0.0.0.0/0"]
name = "Loopback"

[upstream.0]
bootstrap_ip = "76.76.10.11"
endpoint = "https://76.76.10.11/p0"
name = "ControlD-p0"
timeout = 5000
type = "doh"
ip_stack = "v4"

[listener.0]
ip = "192.0.2.53"
port = 53
allow_wan_clients = true

[listener.0.policy]
name = "Direct Internet Method"
networks = [{"network.0" = ["upstream.0"]}]
EOF
   "$CTRLD" run --config "$CTRLD_CFG" >"$DM/ctrld.log" 2>&1 &
   CPID=$!
   for _ in $(seq 1 40); do ss -lntu 2>/dev/null | grep -q "$DNS_IP:53" && break; kill -0 "$CPID" 2>/dev/null || break; sleep .1; done
   ss -lntu 2>/dev/null | grep -q "$DNS_IP:53" || { kill "$CPID" 2>/dev/null || true; ip link del "$DNS_IF" 2>/dev/null || true; echo '{"ok":false,"error":"CTRLD_LISTENER_FAILED"}'; exit 75; }
   busctl call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDNS 'ia(iay)' "$DIX" 1 2 4 192 0 2 53 >/dev/null
   busctl call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDomains 'ia(sb)' "$DIX" 1 '.' true >/dev/null
   busctl call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDefaultRoute 'ib' "$DIX" true >/dev/null
   nft add table inet "$TABLE"
   nft "add chain inet $TABLE output { type filter hook output priority mangle; policy accept; }"
   nft add rule inet "$TABLE" output oifname "$PHY" udp dport 443 reject
   nft add rule inet "$TABLE" output oifname "$PHY" tcp dport 443 ct original packets 1-6 queue num "$QNUM" bypass
   "$NFQWS" --qnum="$QNUM" --filter-tcp=443 --hostlist="$RUN_HOSTS" --dpi-desync=multisplit --dpi-desync-split-pos=sniext+1 >"$DM/nfqws.log" 2>&1 &
   NPID=$!
   sleep .4
   kill -0 "$NPID" 2>/dev/null || { cleanup; echo '{"ok":false,"error":"NFQWS_START_FAILED"}'; exit 76; }
   python3 - "$STATE" "$CPID" "$NPID" "$PHY" "$USER_UID" "$USER_GID" <<'PY'
import json,os,sys,time
p=sys.argv[1]
d={"schema":1,"status":"ACTIVE","architecture":"LINUX_DUMMYLINK_SYSTEMD_RESOLVED_CTRLD_DOH_NFT_NFQWS","ctrldPid":int(sys.argv[2]),"nfqwsPid":int(sys.argv[3]),"physicalInterface":sys.argv[4],"dnsInterface":"dimdns0","dnsIp":"192.0.2.53","started":time.time()}
open(p,"w").write(json.dumps(d,indent=2)+"\n")
os.chmod(p,0o600); os.chown(p,int(sys.argv[5]),int(sys.argv[6]))
PY
   echo '{"ok":true,"state":"ACTIVE"}'
   ;;
 *) echo '{"ok":false,"error":"ACTION_INVALID"}'; exit 64;;
esac
