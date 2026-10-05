#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-status}"
APP_HOME="${2:-}"
USER_UID="${3:-1000}"
USER_GID="${4:-1000}"
STATE_BASE="${5:-$APP_HOME}"

[ -n "$APP_HOME" ] || { echo '{"ok":false,"error":"APP_HOME_REQUIRED"}'; exit 64; }

BIN="$APP_HOME/runtime/usr/bin"
DM="$STATE_BASE/directmethod"
STATE="$DM/state.json"
CTRLD_CFG="$DM/ctrld.toml"
HOSTS="$APP_HOME/direct_hosts.txt"
ADULT_FALLBACK="$APP_HOME/adult_hosts_fallback.txt"
CUSTOM_HOSTS="$STATE_BASE/custom-hosts.txt"
ADULT_ENABLED="$STATE_BASE/adult-enabled.txt"
ADULT_HOSTS="$STATE_BASE/adult-hosts.txt"
STRATEGY_FILE="$STATE_BASE/strategy.txt"
SCOPE_FILE="$STATE_BASE/scope.txt"
CTRLD="$BIN/ctrld"
NFQWS="$BIN/nfqws"
TABLE="directinternetmethod"
DNS_IF="dimdns0"
DNS_IP="192.0.2.53"
QNUM=200
RUN_HOSTS="/run/directinternetmethod-hosts.txt"
CPID=""
NPID=""
CTRLD_UNIT=""
NFQWS_UNIT=""
CREATED_LINK=0
CREATED_TABLE=0
START_COMMITTED=0

mkdir -p "$DM"
chmod 0700 "$DM"
chown "$USER_UID:$USER_GID" "$DM" 2>/dev/null || true

require_root(){
  [ "$(id -u)" -eq 0 ] || { echo '{"ok":false,"error":"ROOT_REQUIRED"}'; exit 77; }
}

pid_owned(){
  local pid="${1:-}" expected="${2:-}"
  [ -n "$pid" ] && [ -n "$expected" ] || return 1
  [ -e "/proc/$pid/exe" ] || return 1
  local actual wanted
  actual="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
  wanted="$(readlink -f "$expected" 2>/dev/null || true)"
  [ -n "$actual" ] && [ -n "$wanted" ] && [ "$actual" = "$wanted" ]
}

kill_all_owned_by_exe(){
  local expected="$1" p pid actual wanted
  wanted="$(readlink -f "$expected" 2>/dev/null || true)"
  [ -n "$wanted" ] || return 0
  for p in /proc/[0-9]*/exe; do
    [ -e "$p" ] || continue
    actual="$(readlink -f "$p" 2>/dev/null || true)"
    if [ "$actual" = "$wanted" ]; then
      pid="${p#/proc/}"
      pid="${pid%/exe}"
      case "$pid" in ''|*[!0-9]*) continue;; esac
      kill "$pid" 2>/dev/null || true
    fi
  done
}

dns_link_owned(){
  ip link show "$DNS_IF" >/dev/null 2>&1 || return 1
  ip -o -d link show dev "$DNS_IF" 2>/dev/null | grep -q 'dummy' || return 1
  ip -4 -o addr show dev "$DNS_IF" 2>/dev/null | grep -q " $DNS_IP/32 " || return 1
}

nft_table_owned(){
  local physical="${1:-}" out
  out="$(nft list table inet "$TABLE" 2>/dev/null)" || return 1
  grep -Fq 'chain output' <<<"$out" || return 1
  grep -Eq 'hook output priority (mangle|[-]?[0-9]+)' <<<"$out" || return 1
  grep -Eq 'tcp dport 80.*queue (num 200.*bypass|flags bypass to 200)' <<<"$out" || return 1
  grep -Eq 'tcp dport 443.*queue (num 200.*bypass|flags bypass to 200)' <<<"$out" || return 1
  grep -Eq 'udp dport 443.*queue (num 200.*bypass|flags bypass to 200)' <<<"$out" || return 1
  if [ -n "$physical" ]; then
    grep -Fq "oifname \"$physical\"" <<<"$out" || grep -Fq "oifname $physical" <<<"$out" || return 1
  fi
}

state_value(){
  local key="$1"
  python3 - "$STATE" "$key" <<'PY'
import json,sys
try:
    d=json.load(open(sys.argv[1],encoding="utf-8"))
    v=d.get(sys.argv[2],"")
    print(v if v is not None else "")
except Exception:
    print("")
PY
}

physical_iface(){
  ip -4 route show default |
    awk '$0 !~ / dev (tun|tap|wg|warp|tailscale|zt|docker|br-|veth)/ {for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}'
}

top_iface(){
  ip -4 route show default | head -1 |
    awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}'
}

external_tunnel_active(){
  local top
  top="$(top_iface)"
  case "$top" in
    tun*|tap*|wg*|warp*|tailscale*|zt*) return 0 ;;
  esac
  if command -v nmcli >/dev/null 2>&1; then
    while IFS=: read -r typ dev; do
      case "$dev" in
        tun*|tap*|wg*|warp*|tailscale*|zt*) return 0 ;;
      esac
    done < <(nmcli -t -f TYPE,DEVICE connection show --active 2>/dev/null || true)
  fi
  return 1
}

remove_dns_link(){
  if ip link show "$DNS_IF" >/dev/null 2>&1; then
    local idx
    idx="$(cat "/sys/class/net/$DNS_IF/ifindex" 2>/dev/null || true)"
    [ -n "$idx" ] && busctl call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager RevertLink i "$idx" >/dev/null 2>&1 || true
    ip link del "$DNS_IF" 2>/dev/null || true
  fi
}

cleanup_transient(){
  set +e
  pid_owned "$NPID" "$NFQWS" && kill "$NPID" 2>/dev/null
  pid_owned "$CPID" "$CTRLD" && kill "$CPID" 2>/dev/null
  [ "$CREATED_TABLE" -eq 1 ] && nft delete table inet "$TABLE" >/dev/null 2>&1
  [ "$CREATED_LINK" -eq 1 ] && remove_dns_link
  rm -f "$RUN_HOSTS"
  set -e
}

cleanup_state_owned(){
  [ -f "$STATE" ] || return 0
  local cp np phy
  cp="$(state_value ctrldPid)"
  np="$(state_value nfqwsPid)"
  phy="$(state_value physicalInterface)"
  pid_owned "$np" "$NFQWS" && kill "$np" 2>/dev/null || true
  pid_owned "$cp" "$CTRLD" && kill "$cp" 2>/dev/null || true
  if nft list table inet "$TABLE" >/dev/null 2>&1; then
    nft_table_owned "$phy" || { echo '{"ok":false,"error":"NFT_TABLE_OWNERSHIP_MISMATCH"}' >&2; return 81; }
    nft delete table inet "$TABLE"
  fi
  if ip link show "$DNS_IF" >/dev/null 2>&1; then
    dns_link_owned || { echo '{"ok":false,"error":"DNS_LINK_OWNERSHIP_MISMATCH"}' >&2; return 82; }
    remove_dns_link
  fi
  rm -f "$RUN_HOSTS" "$STATE"
}

verify_clean(){
  [ ! -f "$STATE" ] || return 1
  ! ip link show "$DNS_IF" >/dev/null 2>&1 || return 1
  ! nft list table inet "$TABLE" >/dev/null 2>&1 || return 1
  return 0
}

status(){
  local cp="" np="" ca=false na=false link=false table=false
  if [ -f "$STATE" ]; then
    cp="$(state_value ctrldPid)"
    np="$(state_value nfqwsPid)"
    pid_owned "$cp" "$CTRLD" && ca=true || true
    pid_owned "$np" "$NFQWS" && na=true || true
  fi
  dns_link_owned && link=true || true
  local phy=""
  [ -f "$STATE" ] && phy="$(state_value physicalInterface)"
  nft_table_owned "$phy" && table=true || true
  python3 - "$STATE" "$ca" "$na" "$link" "$table" <<'PY'
import json,sys
state={}
try:
    state=json.load(open(sys.argv[1],encoding="utf-8"))
except Exception:
    pass
flags=[x.lower()=="true" for x in sys.argv[2:]]
print(json.dumps({
    "ok":bool(state and all(flags)),
    "state":state,
    "ctrldAlive":flags[0],
    "nfqwsAlive":flags[1],
    "dnsLink":flags[2],
    "nftTable":flags[3]
}))
PY
}

rollback_on_exit(){
  local rc=$?
  if [ "$ACTION" = "start" ] && [ "$START_COMMITTED" -eq 0 ]; then
    cleanup_transient
  fi
  exit "$rc"
}

case "$ACTION" in
  status)
    status
    ;;

  stop)
    require_root
    if [ ! -f "$STATE" ]; then
      echo '{"ok":true,"state":"PASS_NO_STATE","note":"No owned state; no network resources were removed."}'
      exit 0
    fi
    cleanup_state_owned
    verify_clean || { echo '{"ok":false,"error":"STOP_RESIDUE"}'; exit 78; }
    echo '{"ok":true,"state":"STOPPED"}'
    ;;

  recovery)
    require_root
    if [ -f "$STATE" ]; then
      cleanup_state_owned
    else
      kill_all_owned_by_exe "$NFQWS"
      kill_all_owned_by_exe "$CTRLD"
      sleep .3
      if nft list table inet "$TABLE" >/dev/null 2>&1; then
        nft_table_owned "" || { echo '{"ok":false,"error":"NFT_TABLE_OWNERSHIP_MISMATCH"}'; exit 81; }
        nft delete table inet "$TABLE"
      fi
      if ip link show "$DNS_IF" >/dev/null 2>&1; then
        dns_link_owned || { echo '{"ok":false,"error":"DNS_LINK_OWNERSHIP_MISMATCH"}'; exit 79; }
        remove_dns_link
      fi
      rm -f "$RUN_HOSTS"
    fi
    verify_clean || { echo '{"ok":false,"error":"RECOVERY_RESIDUE"}'; exit 80; }
    echo '{"ok":true,"state":"RECOVERED"}'
    ;;

  start)
    require_root
    trap rollback_on_exit EXIT

    if [ -f "$STATE" ]; then
      CPID="$(state_value ctrldPid)"
      NPID="$(state_value nfqwsPid)"
      if pid_owned "$CPID" "$CTRLD" && pid_owned "$NPID" "$NFQWS" &&
         dns_link_owned &&
         nft_table_owned "$(state_value physicalInterface)"; then
        START_COMMITTED=1
        trap - EXIT
        echo '{"ok":true,"state":"ALREADY_ACTIVE"}'
        exit 0
      fi
      cleanup_state_owned
    fi

    if nft list table inet "$TABLE" >/dev/null 2>&1 || ip link show "$DNS_IF" >/dev/null 2>&1; then
      echo '{"ok":false,"error":"FOREIGN_OR_STALE_RESOURCE_WITHOUT_STATE"}'
      exit 69
    fi

    [ -x "$CTRLD" ] && [ -x "$NFQWS" ] && [ -s "$HOSTS" ] ||
      { echo '{"ok":false,"error":"RUNTIME_NOT_PROVISIONED"}'; exit 70; }

    command -v nft >/dev/null && command -v resolvectl >/dev/null &&
    command -v busctl >/dev/null && command -v ip >/dev/null &&
    command -v systemd-run >/dev/null && command -v systemctl >/dev/null ||
      { echo '{"ok":false,"error":"REQUIRED_NETWORK_TOOL_MISSING"}'; exit 73; }

    TOP="$(top_iface)"
    PHY="$(physical_iface)"
    [ -n "$PHY" ] || { echo '{"ok":false,"error":"PHYSICAL_DEFAULT_ROUTE_MISSING"}'; exit 71; }
    if external_tunnel_active; then
      echo '{"ok":false,"error":"EXTERNAL_TUNNEL_ACTIVE"}'
      exit 72
    fi

    for candidate in "$CUSTOM_HOSTS" "$ADULT_ENABLED" "$ADULT_HOSTS"; do
      if [ -L "$candidate" ]; then
        echo '{"ok":false,"error":"USER_HOSTLIST_SYMLINK_REJECTED"}'
        exit 74
      fi
    done
    ADULT_ON=0
    if [ -f "$ADULT_ENABLED" ] && [ "$(tr -d '\r\n[:space:]' <"$ADULT_ENABLED")" = "1" ]; then
      ADULT_ON=1
    fi
    ADULT_COUNT="$(
    python3 - "$HOSTS" "$CUSTOM_HOSTS" "$ADULT_FALLBACK" "$ADULT_HOSTS" "$ADULT_ON" "$RUN_HOSTS" <<'PY'
import pathlib,re,sys
built=pathlib.Path(sys.argv[1])
custom=pathlib.Path(sys.argv[2])
adult_fallback=pathlib.Path(sys.argv[3])
adult_hosts=pathlib.Path(sys.argv[4])
adult_on=sys.argv[5]=="1"
out=pathlib.Path(sys.argv[6])
label=re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
def valid(v):
    h=v[1:] if v.startswith("^") else v
    if len(h)>253 or "." not in h:
        return False
    return all(label.fullmatch(x) for x in h.split("."))
vals=[];seen=set();adult_count=0
sources=[(built,4096,False),(custom,256,False)]
if adult_on:
    sources += [(adult_fallback,256,True),(adult_hosts,100000,True)]
for p,limit,is_adult in sources:
    if not p.is_file():
        continue
    accepted=0
    for raw in p.read_text(encoding="utf-8",errors="ignore").splitlines():
        v=raw.strip().lower()
        if not v or v.startswith("#"):
            continue
        if valid(v) and v not in seen:
            seen.add(v);vals.append(v);accepted+=1
            if is_adult: adult_count+=1
        if accepted>=limit:
            break
if adult_on and adult_count<5:
    raise SystemExit("ADULT_CATALOG_INVALID")
out.write_text("\n".join(vals)+"\n",encoding="utf-8")
print(adult_count)
PY
    )"
    chmod 0644 "$RUN_HOSTS"
    STRATEGY="balanced"
    if [ -L "$STRATEGY_FILE" ]; then
      echo '{"ok":false,"error":"STRATEGY_SYMLINK_REJECTED"}'
      exit 74
    fi
    if [ -f "$STRATEGY_FILE" ]; then
      STRATEGY="$(tr -d '\r\n[:space:]' <"$STRATEGY_FILE" | tr '[:upper:]' '[:lower:]')"
      case "$STRATEGY" in balanced|compatibility|strong) ;; *) echo '{"ok":false,"error":"STRATEGY_INVALID"}'; exit 74;; esac
    fi

    SCOPE="targeted"
    if [ -L "$SCOPE_FILE" ]; then
      echo '{"ok":false,"error":"SCOPE_SYMLINK_REJECTED"}'
      exit 74
    fi
    if [ -f "$SCOPE_FILE" ]; then
      SCOPE="$(tr -d '\r\n[:space:]' <"$SCOPE_FILE" | tr '[:upper:]' '[:lower:]')"
      case "$SCOPE" in targeted|all-sites) ;; *) echo '{"ok":false,"error":"SCOPE_INVALID"}'; exit 74;; esac
    fi
    HOST_ARGS=()
    [ "$SCOPE" = "targeted" ] && HOST_ARGS=(--hostlist="$RUN_HOSTS")

    ip link add "$DNS_IF" type dummy
    CREATED_LINK=1
    ip addr add "$DNS_IP/32" dev "$DNS_IF"
    ip link set "$DNS_IF" up
    DIX="$(cat "/sys/class/net/$DNS_IF/ifindex")"

    cat > "$CTRLD_CFG" <<'EOF'
[service]
log_level = "warn"
cache_enable = true
cache_size = 4096
cache_serve_stale = true
leak_on_upstream_failure = false

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

    CTRLD_UNIT="directinternetmethod-ctrld-${USER_UID}.service"
    systemd-run --quiet --collect --unit="$CTRLD_UNIT" --service-type=exec --property=Restart=no -- "$CTRLD" run --config "$CTRLD_CFG"
    CPID="$(systemctl show "$CTRLD_UNIT" -p MainPID --value)"
    case "$CPID" in ''|0|*[!0-9]*) echo '{"ok":false,"error":"CTRLD_TRANSIENT_PID_MISSING"}'; exit 75;; esac
    for _ in $(seq 1 40); do
      ss -lntu 2>/dev/null | grep -q "$DNS_IP:53" && break
      pid_owned "$CPID" "$CTRLD" || break
      sleep .1
    done
    ss -lntu 2>/dev/null | grep -q "$DNS_IP:53" ||
      { echo '{"ok":false,"error":"CTRLD_LISTENER_FAILED"}'; exit 75; }

    busctl call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDNS 'ia(iay)' "$DIX" 1 2 4 192 0 2 53 >/dev/null
    busctl call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDomains 'ia(sb)' "$DIX" 1 '.' true >/dev/null
    busctl call org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager SetLinkDefaultRoute 'ib' "$DIX" true >/dev/null

    nft add table inet "$TABLE"
    CREATED_TABLE=1
    nft "add chain inet $TABLE output { type filter hook output priority mangle; policy accept; }"
    nft add rule inet "$TABLE" output oifname "$PHY" tcp dport 80 ct original packets 1-6 queue num "$QNUM" bypass
    nft add rule inet "$TABLE" output oifname "$PHY" tcp dport 443 ct original packets 1-6 queue num "$QNUM" bypass
    nft add rule inet "$TABLE" output oifname "$PHY" udp dport 443 ct original packets 1-6 queue num "$QNUM" bypass

    NFQWS_UNIT="directinternetmethod-nfqws-${USER_UID}.service"
    NFQWS_ARGS=(--qnum="$QNUM")
    case "$STRATEGY" in
      compatibility)
        NFQWS_ARGS+=(
          --filter-tcp=80 "${HOST_ARGS[@]}" --dpi-desync=multisplit --dpi-desync-split-pos=method+2
          --new --filter-tcp=443 "${HOST_ARGS[@]}" --dpi-desync=multisplit --dpi-desync-split-pos=1,sniext+1,host+1,midsld,endhost-1
          --new --filter-udp=443 --filter-l7=quic "${HOST_ARGS[@]}" --dpi-desync=fake --dpi-desync-repeats=4
        )
        ;;
      strong)
        NFQWS_ARGS+=(
          --filter-tcp=80 "${HOST_ARGS[@]}" --dpi-desync=fake,fakedsplit --dpi-desync-split-pos=method+2 --dpi-desync-fooling=md5sig --dpi-desync-repeats=2
          --new --filter-tcp=443 "${HOST_ARGS[@]}" --dpi-desync=fake,hostfakesplit --dpi-desync-hostfakesplit-midhost=midsld --dpi-desync-fooling=badseq,md5sig --dpi-desync-repeats=4
          --new --filter-udp=443 --filter-l7=quic "${HOST_ARGS[@]}" --dpi-desync=fake --dpi-desync-repeats=11
        )
        ;;
      *)
        NFQWS_ARGS+=(
          --filter-tcp=80 "${HOST_ARGS[@]}" --dpi-desync=fake,multisplit --dpi-desync-split-pos=method+2 --dpi-desync-fooling=md5sig
          --new --filter-tcp=443 "${HOST_ARGS[@]}" --dpi-desync=fake,multidisorder --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq,md5sig
          --new --filter-udp=443 --filter-l7=quic "${HOST_ARGS[@]}" --dpi-desync=fake --dpi-desync-repeats=6
        )
        ;;
    esac
    "$NFQWS" --dry-run "${NFQWS_ARGS[@]}" >/dev/null 2>&1 || { echo '{"ok":false,"error":"NFQWS_STRATEGY_INVALID"}'; exit 76; }
    systemd-run --quiet --collect --unit="$NFQWS_UNIT" --service-type=exec --property=Restart=no -- "$NFQWS" "${NFQWS_ARGS[@]}"
    NPID="$(systemctl show "$NFQWS_UNIT" -p MainPID --value)"
    case "$NPID" in ''|0|*[!0-9]*) echo '{"ok":false,"error":"NFQWS_TRANSIENT_PID_MISSING"}'; exit 76;; esac
    sleep .5
    pid_owned "$NPID" "$NFQWS" || { echo '{"ok":false,"error":"NFQWS_START_FAILED"}'; exit 76; }

    python3 - "$STATE" "$CPID" "$NPID" "$PHY" "$USER_UID" "$USER_GID" "$CTRLD_UNIT" "$NFQWS_UNIT" "$STRATEGY" "$SCOPE" "$ADULT_ON" "$ADULT_COUNT" <<'PY'
import json,os,sys,time
p=sys.argv[1]
d={
  "schema":3,
  "status":"ACTIVE",
  "architecture":"LINUX_DUMMYLINK_SYSTEMD_RESOLVED_CTRLD_DOH_NFT_NFQWS_MULTIPROTOCOL",
  "directMethods":["encrypted-dns-doh","http-host-split-tcp80","tls-sni-desync-tcp443","quic-desync-udp443","custom-hostlist","adult-catalog","strategy-profile"],
  "strategy":sys.argv[9],
  "scope":sys.argv[10],
  "adultCoverage":bool(int(sys.argv[11])),
  "adultHostCount":int(sys.argv[12]),
  "ctrldPid":int(sys.argv[2]),
  "nfqwsPid":int(sys.argv[3]),
  "physicalInterface":sys.argv[4],
  "dnsInterface":"dimdns0",
  "dnsIp":"192.0.2.53",
  "ctrldUnit":sys.argv[7],
  "nfqwsUnit":sys.argv[8],
  "started":time.time()
}
with open(p,"w",encoding="utf-8") as f:
    json.dump(d,f,indent=2)
    f.write("\n")
os.chmod(p,0o600)
os.chown(p,int(sys.argv[5]),int(sys.argv[6]))
PY

    START_COMMITTED=1
    trap - EXIT
    echo '{"ok":true,"state":"ACTIVE"}'
    ;;

  *)
    echo '{"ok":false,"error":"ACTION_INVALID"}'
    exit 64
    ;;
esac
