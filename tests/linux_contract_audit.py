#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,re,sys
R=Path(__file__).resolve().parents[1]
L=R/"linux"
def txt(rel): return (L/rel).read_text(encoding="utf-8")
ui=txt("app/direct_internet_method.py")
helper=txt("app/direct_method_helper.sh")
build=txt("../build_linux_package.py")
install=txt("install.sh")
uninstall=txt("uninstall.sh")
sysinstall=txt("system/install_system.sh")
control=txt("system/control.sh")
svg=txt("app/direct-internet-method.svg")
hostlist=txt("app/hosts.txt")
adult_fallback=txt("app/adult_hosts_fallback.txt")
D={"schema":2,"status":"PASS","checks":{},"hashes":{}}
def check(name,cond):
    D["checks"][name]=bool(cond)
    if not cond:D["status"]="FAIL"

check("version_150_backend_150", 'VERSION="1.5.0"' in ui and '"version":"1.5.0"' in install and '"version":"1.5.0"' in sysinstall and 'd.get("version")=="1.5.0"' in install)
check("no_default_route_mutation", not re.search(r'ip\s+route\s+(add|del|replace).*default|nmcli\s+.*ipv4\.gateway',helper,re.I))
check("no_physical_dns_mutation", "nmcli connection modify" not in helper and "resolvectl dns enp" not in helper and "resolvectl dns eth" not in helper)
check("dedicated_dns_link", all(x in helper for x in ('DNS_IF="dimdns0"','ip link add "$DNS_IF" type dummy','ip addr add "$DNS_IP/32" dev "$DNS_IF"','SetLinkDNS','SetLinkDomains','RevertLink','ip link del "$DNS_IF"')))
listener=re.search(r"\[listener\.0\](.*?)\[listener\.0\.policy\]",helper,re.S)
check("ctrld_listener_owned_link", listener is not None and 'ip = "192.0.2.53"' in listener.group(1) and "allow_wan_clients = true" in listener.group(1) and 'ip = "0.0.0.0"' not in listener.group(1))
check("external_tun_fail_closed_before_mutation", "EXTERNAL_TUNNEL_ACTIVE" in helper and helper.index("EXTERNAL_TUNNEL_ACTIVE") < helper.index('ip link add "$DNS_IF" type dummy'))
check("nft_owned_table", 'TABLE="directinternetmethod"' in helper and 'nft add table inet "$TABLE"' in helper and 'nft delete table inet "$TABLE"' in helper)
check("multiprotocol_nft_queue_scope", all(x in helper for x in (
    'tcp dport 80 ct original packets 1-6 queue num "$QNUM" bypass',
    'tcp dport 443 ct original packets 1-6 queue num "$QNUM" bypass',
    'udp dport 443 ct original packets 1-6 queue num "$QNUM" bypass'
)) and 'udp dport 443 reject' not in helper)
check("multiprotocol_nfqws_profiles", all(x in helper for x in (
    '--filter-tcp=80','--dpi-desync-split-pos=method+2','--dpi-desync-fooling=md5sig',
    '--new --filter-tcp=443','--dpi-desync=fake,multidisorder','--dpi-desync-split-pos=1,midsld',
    '--new --filter-udp=443 --filter-l7=quic','--dpi-desync-repeats=6'
)))
check("multiprotocol_state_methods", all(x in helper for x in (
    '"encrypted-dns-doh"','"http-host-split-tcp80"','"tls-sni-desync-tcp443"','"quic-desync-udp443"'
)))
check("secure_dns_no_os_leak", 'leak_on_upstream_failure = false' in helper)
check("nft_ownership_guard", "nft_table_owned()" in helper and "NFT_TABLE_OWNERSHIP_MISMATCH" in helper and 'queue num "$QNUM" bypass' in helper)
check("nft_queue_canonical_guard", "queue (num 200.*bypass|flags bypass to 200)" in helper)
check("dns_link_ownership_guard", "dns_link_owned()" in helper and "DNS_LINK_OWNERSHIP_MISMATCH" in helper)
check("nfqws_bounded_hostlist", 'RUN_HOSTS="/run/directinternetmethod-hosts.txt"' in helper and 'python3 - "$HOSTS" "$CUSTOM_HOSTS" "$ADULT_FALLBACK" "$ADULT_HOSTS" "$ADULT_ON" "$RUN_HOSTS"' in helper and 'accepted>=limit' in helper and 'rm -f "$RUN_HOSTS"' in helper)
check("pid_exact_executable_ownership", "pid_owned()" in helper and 'readlink -f "/proc/$pid/exe"' in helper and 'pid_owned "$NPID" "$NFQWS"' in helper and 'pid_owned "$CPID" "$CTRLD"' in helper)
check("daemon_lifecycle_transient_services", "systemd-run --quiet --collect" in helper and '--service-type=exec' in helper and 'systemctl show "$CTRLD_UNIT" -p MainPID --value' in helper and 'systemctl show "$NFQWS_UNIT" -p MainPID --value' in helper and 'directinternetmethod-ctrld-${USER_UID}.service' in helper and 'directinternetmethod-nfqws-${USER_UID}.service' in helper and '"$CTRLD" run --config "$CTRLD_CFG" >"$DM/ctrld.log" 2>&1 &' not in helper)
check("recovery_pid_extraction_fixed", 'pid="${p#/proc/}"' in helper and 'pid="${pid%/exe}"' in helper and 'kill "$pid"' in helper)
check("start_rollback_trap", "trap rollback_on_exit EXIT" in helper and "cleanup_transient" in helper and "START_COMMITTED=1" in helper)
check("ui_systemd_unit_ownership", '_systemd_unit_matches' in ui and '"systemctl","show",unit' in ui and 'MainPID' in ui and 'ActiveState' in ui and 'directinternetmethod-ctrld-{uid}.service' in ui and 'directinternetmethod-nfqws-{uid}.service' in ui)
check("ui_identity", 'APP_ID="io.github.god13emad.DirectInternetMethod"' in ui and 'GLib.set_prgname("DirectInternetMethod")' in ui and 'GLib.set_application_name("Direct Internet Method")' in ui)
check("ui_explicit_window_controls", all(x in ui for x in ("self.minimize()","self.maximize()","self.unmaximize()","self.close()","Gtk.WindowHandle")))
check("ui_live_verify_rollback", 'LIVE_VERIFY_FAILED_ROLLED_BACK' in ui and 'run_system_action("stop")' in ui)
check("ui_fixed_systemd_actions", 'unit=f"directinternetmethod-{action}.service"' in ui and 'subprocess.run(["systemctl","start",unit]' in ui)
check("ui_multiprotocol_label", "Encrypted DNS (DoH) + HTTP/TLS/QUIC DPI bypass" in ui)
check("ui_online_update_hash_gate", "SHA256SUMS.txt" in ui and "hashlib.sha256" in ui and "Unsafe update archive path." in ui)
check("ui_online_update_three_way_digest_gate", all(x in ui for x in ("GitHub release asset digest is missing/invalid","SHA256SUMS.txt must contain exactly one valid checksum","Linux update checksum disagrees with GitHub asset digest","three-way SHA-256 verification","expected_linux=f\"DirectInternetMethod_{release_version}_Linux_x86_64.zip\"")))
check("target_hostlist_scope", "^gemini.google.com" in hostlist.splitlines() and all(x not in hostlist.splitlines() for x in ("pornhub.com","phncdn.com","xvideos.com","xnxx.com","xhamster.com")) and all(x in adult_fallback.splitlines() for x in ("pornhub.com","phncdn.com","xvideos.com","xvideos-cdn.com","xvcdn.com","xnxx.com","xnxx-cdn.com","xhamster.com","xhcdn.com","redtube.com","rdtcdn.com")))
check("critical_global_services_hostlist", all(x in hostlist.splitlines() for x in ("openai.com","chatgpt.com","oaistatic.com","oaiusercontent.com","github.com","githubusercontent.com","githubassets.com")))
check("custom_site_hostlist", all(x in helper for x in ('CUSTOM_HOSTS="$STATE_BASE/custom-hosts.txt"','USER_HOSTLIST_SYMLINK_REJECTED','python3 - "$HOSTS" "$CUSTOM_HOSTS" "$ADULT_FALLBACK" "$ADULT_HOSTS" "$ADULT_ON" "$RUN_HOSTS"','"custom-hostlist"')) and all(x in ui for x in ('CUSTOM_HOSTS=APP_HOME/"custom-hosts.txt"','normalize_custom_site','save_custom_hosts_text','("Custom Sites","custom",None)','Maximum 256 entries')))
check("strategy_profiles", all(x in helper for x in ('STRATEGY_FILE="$STATE_BASE/strategy.txt"','balanced','compatibility','strong','fakedsplit','hostfakesplit','sniext+1','--dry-run','"strategy":sys.argv[9]')) and all(x in ui for x in ('STRATEGY_FILE=APP_HOME/"strategy.txt"','("Strategy","strategy",None)','open_strategy','Compatibility','Strong')))
check("all_sites_scope_optional_default_targeted", all(x in helper for x in ('SCOPE_FILE="$STATE_BASE/scope.txt"','SCOPE="targeted"','all-sites','SCOPE_INVALID','HOST_ARGS=()')) and all(x in ui for x in ('SCOPE_FILE=APP_HOME/"scope.txt"','Apply DPI strategy to all web sites (experimental)','all-sites','targeted')))
check("ui_gemini_adult_live_checks", all(x in ui for x in ('Gemini','Adult coverage','adultSiteLiveCheck','adultCoverageEnabled','Gtk.Switch','https://gemini.google.com/','https://www.pornhub.com/','https://www.xvideos.com/','https://www.xnxx.com/','https://xhamster.com/','format_adult_probes')))
check("ui_adult_check_default_off_persisted", 'adultCoverageEnabled' in ui and 'get("adultSiteLiveCheck",False)' in ui and 'self.adult_check_enabled=load_adult_site_check()' in ui)
check("adult_catalog_opt_in", all(x in ui for x in ("ADULT_ENABLED","ADULT_HOSTS","raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt","cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt","sync_adult_catalog","Adult catalog is unexpectedly small","xvideos.com","xnxx.com","xhamster.com")) and all(x in helper for x in ("ADULT_FALLBACK","ADULT_ENABLED","ADULT_HOSTS","ADULT_CATALOG_INVALID","adultHostCount")) and 'adult_hosts_fallback.txt' in build and 'adult_hosts_fallback.txt' in install and 'adult_hosts_fallback.txt' in sysinstall)
check("ui_live_probe_non_gating", 'g=curl("https://github.com/")' in ui and 'm=curl("https://gemini.google.com/")' in ui and 'and g["exit"]==0' in ui and 'and m["exit"]==0' not in ui)
check("install_no_network_start", 'systemctl start directinternetmethod-start.service' not in install and 'direct_method_helper.sh" start' not in install)
check("install_active_state_guard", "Stop/Recovery it before installing or upgrading." in install)
check("install_backup_excludes_runtime_state", 'for f in direct_internet_method.py router_gateway.py router_gateway_core.py direct-internet-method.svg uninstall.sh INSTALL.json' in install and 'cp -a "$APP" "$BACKUP"' not in install)
check("linux_package_includes_router_core", '("linux/app/router_gateway_core.py","app/router_gateway_core.py")' in build)
check("install_one_time_admin", 'pkexec /bin/bash "$HERE/system/install_system.sh"' in install)
check("install_idempotent_backend_hash_gate", "backend_matches_current()" in install and 'sha256sum "$src"' in install and "skipping admin authorization" in install)
check("install_no_unprivileged_polkit_probe", "test -f /etc/polkit-1/rules.d/49-directinternetmethod.rules" not in install and "test -f /etc/polkit-1/rules.d/49-directinternetmethod.rules" in sysinstall)
check("normal_actions_no_pkexec", "pkexec" not in ui and "pkexec" not in control)
check("protected_backend_root", "ROOT=/usr/lib/directinternetmethod" in sysinstall and "ROOT=/usr/lib/directinternetmethod" in control)
check("uid_only_root_config", "/etc/directinternetmethod.uid" in sysinstall and "/etc/directinternetmethod.uid" in control and "/etc/directinternetmethod.conf" not in control)
check("account_metadata_validation", "unsafe username" in sysinstall and "unsafe home path" in sysinstall and "getent passwd" in control)
check("install_avoids_readonly_uid_variable", "read -r USER_NAME _ UID " not in sysinstall and "USER_UID" in sysinstall)
check("systemd_fixed_units", all(f"directinternetmethod-{x}.service" in sysinstall for x in ("start","stop","recovery")) and "TimeoutStartSec=120" in sysinstall)
check("systemd_sandbox", all(x in sysinstall for x in ("PrivateTmp=true","ProtectSystem=full","ProtectHome=read-only","UMask=0077","ReadWritePaths=")))
check("polkit_narrow_action_scope", 'action.id == "org.freedesktop.systemd1.manage-units"' in sysinstall and 'verb == "start"' in sysinstall and 'subject.local && subject.active' in sysinstall and '"directinternetmethod-start.service"' in sysinstall and '"directinternetmethod-stop.service"' in sysinstall and '"directinternetmethod-recovery.service"' in sysinstall)
check("control_fixed_actions", 'case "$ACTION" in start|stop|recovery)' in control and 'exec /bin/bash "$ROOT/direct_method_helper.sh" "$ACTION"' in control)
check("desktop_identity", "io.github.god13emad.DirectInternetMethod.desktop" in install and "StartupWMClass=DirectInternetMethod" in install and "Terminal=false" in install)
check("desktop_shortcut", 'Direct Internet Method.desktop' in install and "metadata::trusted" in install)
check("uninstall_state_cleanup_gate", "directmethod/state.json" in uninstall and "Recovery could not be verified" in uninstall and "directinternetmethod-recovery.service" in uninstall)
check("uninstall_protected_backend_admin", "pkexec /bin/bash /usr/lib/directinternetmethod/uninstall_system.sh" in uninstall)
check("branding_slogan", "زن زندگی آزادی" in ui and "زن زندگی آزادی" in svg)

expected={
"ctrld":"ca64579a2bc866cf72f3e46663e551162afeff0d448e899a01817a095e45b071",
"nfqws":"f34615964d7321650197cd69d3f7cbfdaabe8118b5a0d57c6e41dccdff658999"}
for name,rel in (("ctrld","runtime/ctrld"),("nfqws","runtime/nfqws")):
    h=hashlib.sha256((L/rel).read_bytes()).hexdigest();D["hashes"][name]=h;check("runtime_"+name+"_pin",h==expected[name])
print(json.dumps(D,indent=2,ensure_ascii=False))
sys.exit(0 if D["status"]=="PASS" else 20)
