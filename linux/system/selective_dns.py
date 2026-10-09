#!/usr/bin/env python3
"""DirectInternetMethod opt-in, fail-closed selective DNS controller.

Experimental: target DNS UDP to a named third-party upstream is UNENCRYPTED.
User must opt in explicitly. Physical default routes and Tailscale settings
are NEVER modified. Root can restore DNS without ChatGPT or GUI connectivity.
"""
from __future__ import annotations
import argparse, fcntl, ipaddress, json, os, pathlib, re, shutil, socket
import subprocess, sys, tempfile, time, uuid
from contextlib import contextmanager

STATE_DIR=pathlib.Path("/run/directinternetmethod-selective")
STATE_FILE=STATE_DIR/"session.json"
CONF=pathlib.Path("/run/directinternetmethod-selective.conf")
HELPER_ROOT=pathlib.Path("/usr/lib/directinternetmethod")
SELECTOR=HELPER_ROOT/"selective_dns.py"
UPSTREAM="194.225.152.10"
PORT=10535
LOOPBACK="127.0.0.1"
TOKEN="I_ACCEPT_UNENCRYPTED_SELECTIVE_DNS_V1"
TARGETS=("youtube.com","googlevideo.com","ytimg.com","youtu.be")
MONITOR_GRACE=90
POLL_SECONDS=4
ACTION_LOCK=pathlib.Path("/run/directinternetmethod-action.lock")
IFACE_RE=re.compile(r"^[a-zA-Z0-9_.:-]{1,15}$")
UNIT_RE=re.compile(r"^dim-sdns-(?:dns|watch)-[0-9]{1,10}-[0-9a-f]{10}\.service$")
TIMER_RE=re.compile(r"^dim-sdns-backstop-[0-9]{1,10}-[0-9a-f]{10}\.timer$")
BACKSTOP_INTERVAL=40
LINE_RE=re.compile(r"^Link \d+ \(([A-Za-z0-9_.:-]+)\):(?: (.*))?$")

def call(*args, timeout=9, ok=True):
    p=subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if ok and p.returncode:
        raise RuntimeError("CMD_FAILED:"+str(args[:3])+":"+str(p.returncode)+":"+p.stderr[-140:])
    return p

def need(cond, reason):
    if not cond:raise RuntimeError(reason)

def require_root():
    need(os.geteuid()==0,"ROOT_REQUIRED")

def write_atomic(path: pathlib.Path,data:bytes,mode=0o600):
    fd,tmp=tempfile.mkstemp(prefix=".dim-select-",dir=str(path.parent))
    try:
        with os.fdopen(fd,"wb") as out:
            out.write(data);out.flush();os.fsync(out.fileno())
        os.chmod(tmp,mode)
        os.replace(tmp,path)
    finally:
        if os.path.lexists(tmp):os.unlink(tmp)

def json_atomic(state):
    need(STATE_DIR.is_dir() and not STATE_DIR.is_symlink(),"STATE_DIR_UNVERIFIED")
    write_atomic(STATE_FILE,(json.dumps(state,sort_keys=True,indent=2)+"\n").encode(),0o600)

def read_state():
    if not STATE_FILE.exists():return None
    need(not STATE_FILE.is_symlink() and STATE_FILE.is_file(),"STATE_SYMLINK_OR_TYPE")
    info=os.stat(STATE_FILE,follow_symlinks=False)
    need(info.st_uid==0 and info.st_mode&0o777==0o600,"STATE_OWNER_OR_MODE")
    state=json.loads(STATE_FILE.read_text())
    validate_state(state)
    return state

def validate_state(state):
    need(isinstance(state,dict) and state.get("schema")==1,"STATE_SCHEMA")
    iface=state.get("interface")
    need(isinstance(iface,str) and IFACE_RE.fullmatch(iface),"STATE_IFACE")
    need(state.get("phase") in ("ARMING","ACTIVE","STOPPING","DEGRADED"),"STATE_PHASE")
    uid=state.get("uid")
    need(type(uid)==int and uid>=0,"STATE_UID")
    need(state.get("dnsUnit") and UNIT_RE.fullmatch(state["dnsUnit"]),"STATE_DNS_UNIT")
    need(state.get("monitorUnit") and UNIT_RE.fullmatch(state["monitorUnit"]),"STATE_MONITOR_UNIT")
    need(state.get("session") and re.fullmatch("[0-9a-f]{10}",state["session"]),"STATE_SESSION")
    need(state["dnsUnit"]==f"dim-sdns-dns-{uid}-{state['session']}.service","DNS_UNIT_SESSION")
    need(state["monitorUnit"]==f"dim-sdns-watch-{uid}-{state['session']}.service","WATCH_UNIT_SESSION")
    need(bool(TIMER_RE.fullmatch(str(state.get("backstopTimer","")))),"BACKSTOP_TIMER_UNIT")
    need(state["backstopTimer"]==f"dim-sdns-backstop-{uid}-{state['session']}.timer",
         "BACKSTOP_TIMER_SESSION")
    need(state.get("upstream")==UPSTREAM,"STATE_UPSTREAM")
    need(isinstance(state.get("baseline"),dict),"STATE_BASELINE")
    base=state["baseline"]
    need(base.get("dns") and isinstance(base["dns"],list) and
         len(base["dns"])==1 and isinstance(base["dns"][0],str) and
         ipaddress.ip_address(base["dns"][0]).version==4,"BASE_DNS_INVALID")
    need(isinstance(base.get("domains"),list) and all(isinstance(x,str) and len(x)<120 for x in base["domains"]),"BASE_DOMAINS_INVALID")
    need(base.get("defaultRoute") is True,"BASE_DEFAULT_ROUTE_INVALID")
    need(state.get("configPath")==str(CONF),"STATE_CONFIG_PATH")
    need(bool(re.fullmatch("[0-9a-f]{64}",state.get("tailscaleDnsSha",""))),
         "STATE_TAILSCALE_DNS_SHA")
    home=state.get("home")
    need(isinstance(home,str) and home.startswith("/home/") and
         pathlib.Path(home).is_absolute() and ".." not in pathlib.Path(home).parts,
         "STATE_HOME_PATH_INVALID")

def parse_link_line(text,iface):
    line=text.strip()
    match=LINE_RE.fullmatch(line)
    need(bool(match) and match.group(1)==iface,"LINK_OUTPUT_MISMATCH")
    return (match.group(2) or "").split()

def link_fields(iface):
    need(IFACE_RE.fullmatch(iface),"BAD_LINK")
    dns=parse_link_line(call("resolvectl","dns",iface).stdout,iface)
    domains=parse_link_line(call("resolvectl","domain",iface).stdout,iface)
    droute=parse_link_line(call("resolvectl","default-route",iface).stdout,iface)
    need(len(droute)==1 and droute[0] in ("yes","no"),"BAD_LINK_DEFAULT_ROUTE")
    return {"dns":dns,"domains":domains,"defaultRoute":droute[0]=="yes"}

def original_baseline(iface):
    data=link_fields(iface)
    need(data["defaultRoute"] is True,"BASE_LINK_NOT_DEFAULT_DNS")
    need(len(data["dns"])==1,"BASE_NEEDS_SINGLE_IPV4_DNS")
    addr=ipaddress.ip_address(data["dns"][0])
    need(addr.version==4 and not addr.is_loopback and not addr.is_multicast,
         "BASE_DNS_NOT_SAFE_IPV4")
    need(all(len(x)<255 for x in data["domains"]),
         "BASE_DOMAIN_SET_INVALID")
    return data

def expected_active(base):
    return {"dns":[f"{LOOPBACK}:{PORT}"],
            "domains":list(base["domains"]),"defaultRoute":base["defaultRoute"]}

def valid_optin(home: pathlib.Path,uid:int):
    opt=home/".local/share/DirectInternetMethod/selective-dns-optin.txt"
    need(opt.is_file() and not opt.is_symlink(),"SELECTIVE_DNS_OPT_IN_MISSING")
    st=os.stat(opt,follow_symlinks=False)
    need(st.st_uid==uid and st.st_mode&0o022==0,"SELECTIVE_OPTIN_OWNER_OR_MODE")
    need(st.st_size<130 and opt.read_text().strip()==TOKEN,"SELECTIVE_DNS_EXPLICIT_CONSENT_REQUIRED")
    strategy=home/".local/share/DirectInternetMethod/strategy.txt"
    scope=home/".local/share/DirectInternetMethod/scope.txt"
    need(all(p.is_file() and not p.is_symlink() for p in (strategy,scope)),"STRATEGY_OR_SCOPE_UNSAFE")
    need(strategy.read_text().strip()=="balanced" and scope.read_text().strip()=="targeted",
         "SELECTIVE_DNS_REQUIRES_BALANCED_TARGETED")
    return True

def tailscale_dns_fingerprint():
    # This feature never modifies the separate tailscale0 link.
    raw=(call("resolvectl","dns","tailscale0").stdout+
         call("resolvectl","domain","tailscale0").stdout).encode()
    return __import__("hashlib").sha256(raw).hexdigest()

def split_tailscale_ready():
    d=json.loads(call("tailscale","status","--json").stdout)
    need(d.get("BackendState")=="Running" and not d.get("ExitNodeStatus"),
         "TAILSCALE_SPLIT_REQUIRED")
    return True

def make_conf(baseline):
    original=baseline["dns"][0]
    need(UPSTREAM!=original,"UPSTREAM_EQUALS_BASELINE")
    return ("\n".join([
        "# DirectInternetMethod: experimental opt-in plain UDP DNS, NOT DoH.",
        f"port={PORT}","listen-address=127.0.0.1","bind-interfaces",
        "no-resolv","no-hosts","cache-size=0",
        f"server={original}",*[f"server=/{host}/{UPSTREAM}" for host in TARGETS],
        "log-facility=-","",
    ])).encode()

def status_unit(unit):
    need(bool(UNIT_RE.fullmatch(unit)),"INVALID_OWNED_UNIT")
    p=call("systemctl","show",unit,"-p","ActiveState","--value",ok=False)
    return p.stdout.strip()

def status_timer(unit):
    need(bool(TIMER_RE.fullmatch(unit)),"INVALID_OWNED_TIMER")
    p=call("systemctl","show",unit,"-p","ActiveState","--value",ok=False)
    return p.stdout.strip()

def protect_marker():
    if STATE_DIR.exists():raise RuntimeError("PREEXISTING_OWNED_DNS_SESSION")
    if CONF.exists() or CONF.is_symlink():raise RuntimeError("DNS_FORWARDER_CONFIG_CONFLICT")
    STATE_DIR.mkdir(mode=0o700)
    os.chmod(STATE_DIR,0o700)
    need(STATE_DIR.stat().st_uid==0 and STATE_DIR.stat().st_mode&0o777==0o700,
         "STATE_DIR_NOT_PRIVATE_ROOT")

def public_answer(target,server=None,port=53):
    args=["dig",f"@{server}" if server else "@"+LOOPBACK]
    if port!=53:args+=["-p",str(port)]
    args += [target,"A","+short","+tries=1","+time=2"]
    p=call(*args,timeout=6,ok=False)
    addrs=[]
    for val in p.stdout.splitlines():
        try:
            addr=ipaddress.ip_address(val.strip())
            if addr.version==4:addrs.append(addr)
        except ValueError:pass
    return p.returncode==0 and len(addrs)>=1 and all(ip.is_global for ip in addrs)

def google_http204():
    p=call("curl","-4","--noproxy","*","--connect-timeout","3","--max-time","6",
           "-sS","-o","/dev/null","-w","%{http_code}",
           "https://www.google.com/generate_204",timeout=9,ok=False)
    return p.returncode==0 and p.stdout.strip()=="204"

def change_link(iface, dns, domains, defaultroute):
    need(dns and all(isinstance(x,str) and len(x)<120 for x in dns),"UNSAFE_DNS_ARGS")
    need(isinstance(domains,list) and
         all(isinstance(x,str) and len(x)<120 for x in domains),
         "UNSAFE_DOMAIN_ARGS")
    call("resolvectl","dns",iface,*dns)
    # Empty baseline domain lists are already empty in the active
    # session; never invent route-only or search domains.
    if domains:
        call("resolvectl","domain",iface,*domains)
    call("resolvectl","default-route",iface,"yes" if defaultroute else "no")
    call("resolvectl","flush-caches")

def rollback(reason="MANUAL",stop_monitor=True):
    require_root()
    state=read_state()
    if state is None:return {"ok":True,"state":"NO_SESSION"}
    iface=state["interface"]
    original=state["baseline"]
    observed=link_fields(iface)
    need(observed==original or observed==expected_active(original),
         "FOREIGN_DNS_POLICY_PRESERVED")
    # Restore physical DNS first, before touching our forwarder.
    if observed!=original:
        change_link(iface,original["dns"],original["domains"],original["defaultRoute"])
    need(link_fields(iface)==original,"DNS_RESTORE_UNVERIFIED")
    if status_unit(state["dnsUnit"])=="active":
        call("systemctl","stop",state["dnsUnit"],timeout=15)
    need(status_unit(state["dnsUnit"])!="active","OWNED_FORWARDER_STILL_RUNNING")
    if stop_monitor and status_unit(state["monitorUnit"])=="active":
        call("systemctl","stop",state["monitorUnit"],timeout=15)
    if status_timer(state["backstopTimer"])=="active":
        call("systemctl","stop",state["backstopTimer"],timeout=15)
    need(status_timer(state["backstopTimer"])!="active","BACKSTOP_TIMER_REMAINS_ACTIVE")
    if CONF.exists():
        need(not CONF.is_symlink() and CONF.is_file() and
             CONF.read_bytes()==make_conf(original),"DNS_CONFIG_FOREIGN_PRESERVED")
        CONF.unlink()
    if STATE_FILE.exists():STATE_FILE.unlink()
    # Keep the parent /run directory until shutdown; a new run rejects
    # stale root markers unless the directory is provably empty.
    if STATE_DIR.is_dir() and not any(STATE_DIR.iterdir()):
        STATE_DIR.rmdir()
    return {"ok":True,"state":"RESTORED","reason":reason}

def activate(uid:int,iface:str,home:str):
    require_root()
    need(type(uid)==int and 0<uid<2147483647,"INVALID_UID")
    need(IFACE_RE.fullmatch(iface),"INVALID_PHYSICAL_IFACE")
    h=pathlib.Path(home)
    need(h.is_dir() and not h.is_symlink() and str(h).startswith("/home/"),
         "INVALID_USER_HOME")
    need(h.stat().st_uid==uid,"HOME_UID_MISMATCH")
    valid_optin(h,uid)
    split_tailscale_ready()
    tsdns=tailscale_dns_fingerprint()
    base=original_baseline(iface)
    need(public_answer("www.youtube.com",UPSTREAM),"TARGET_UPSTREAM_NOT_USABLE")
    need(google_http204(),"BASELINE_GOOGLE_UNAVAILABLE")
    need(call("ip","-4","route","show","default").stdout.splitlines()[0].find("dev "+iface)>=0,
         "PHYSICAL_NOT_DEFAULT_ROUTE")
    need(not call("ss","-lun",ok=False).stdout.find(":"+str(PORT)+" ")>=0,
         "LOCAL_DNS_PORT_ALREADY_USED")
    protect_marker()
    session=uuid.uuid4().hex[:10]
    state={"schema":1,"phase":"ARMING","interface":iface,"uid":uid,"session":session,
           "upstream":UPSTREAM,"baseline":base,"started":time.time(),
           "home":str(h),"tailscaleDnsSha":tsdns,
           "dnsUnit":f"dim-sdns-dns-{uid}-{session}.service",
           "monitorUnit":f"dim-sdns-watch-{uid}-{session}.service",
           "backstopTimer":f"dim-sdns-backstop-{uid}-{session}.timer",
           "configPath":str(CONF)}
    try:
        write_atomic(CONF,make_conf(base),0o644)
        json_atomic(state)
        # Arm independent monitor BEFORE any DNS changes.
        call("systemd-run","--quiet",f"--unit={state['monitorUnit'][:-8]}",
             "--service-type=simple","--property=Restart=on-failure",
             "--property=RestartSec=2s","/usr/bin/python3",str(SELECTOR),"monitor",
             timeout=15)
        need(status_unit(state["monitorUnit"])=="active","MONITOR_NOT_ARMED")
        # Independent repeating systemd TIMER. If the monitor is killed
        # without a failure code, this timer still restores physical DNS.
        call("systemd-run","--quiet",
             f"--unit={state['backstopTimer'][:-6]}",
             f"--on-active={BACKSTOP_INTERVAL}s",
             f"--on-unit-active={BACKSTOP_INTERVAL}s",
             "--timer-property=AccuracySec=1s",
             "/usr/bin/python3",str(SELECTOR),"backstop",timeout=15)
        need(status_timer(state["backstopTimer"])=="active",
             "BACKSTOP_TIMER_NOT_ARMED")
        import pwd
        name=pwd.getpwuid(uid).pw_name
        call("systemd-run","--quiet",f"--unit={state['dnsUnit'][:-8]}",
             "--service-type=exec",f"--property=User={name}",
             "--property=NoNewPrivileges=yes",
             "/usr/sbin/dnsmasq","--no-daemon","--conf-file="+str(CONF),timeout=15)
        need(status_unit(state["dnsUnit"])=="active","OWNED_DNSMASQ_NOT_RUNNING")
        for q in ("www.youtube.com","i.ytimg.com","redirector.googlevideo.com",
                  "github.com","www.google.com"):
            need(public_answer(q,LOOPBACK,PORT),"LOCAL_SPLIT_DNS_UNVERIFIED_"+q)
        change_link(iface,[f"{LOOPBACK}:{PORT}"],base["domains"],base["defaultRoute"])
        need(link_fields(iface)==expected_active(base),"DNS_CHANGE_NOT_APPLIED")
        split_tailscale_ready()
        need(tailscale_dns_fingerprint()==tsdns,"TAILSCALE_MAGICDNS_CHANGED")
        need(google_http204(),"GOOGLE_FAILED_AFTER_DNS")
        need(public_answer("www.youtube.com",LOOPBACK,PORT),"YOUTUBE_DNS_FAILED")
        return {"ok":True,"state":"ARMED","session":session,"unencryptedDns":True}
    except BaseException:
        try:rollback("ACTIVATION_FAILED")
        except BaseException:pass  # monitor remains armed to retry rollback
        raise

def commit():
    require_root()
    s=read_state()
    need(s and s["phase"]=="ARMING","DNS_NOT_ARMED_BEFORE_COMMIT")
    uid=s["uid"]
    path=pathlib.Path(s["home"])/".local/share/DirectInternetMethod/directmethod/state.json"
    data=json.loads(path.read_text())
    need(data.get("tailscaleCoexistence") is True and
         data.get("dnsMode")=="system-preserved" and
         data.get("selectiveDns") is True and
         int(data.get("nfqwsPid") or 0)>1,"NATIVE_ENGINE_NOT_COMMITTED")
    need(status_unit(s["dnsUnit"])=="active" and
         status_unit(s["monitorUnit"])=="active" and
         status_timer(s["backstopTimer"])=="active",
         "DNS_MONITOR_BACKSTOP_OR_SERVER_FAILED")
    need(link_fields(s["interface"])==expected_active(s["baseline"]),"DNS_LINK_CHANGED")
    s["phase"]="ACTIVE";s["committed"]=time.time()
    json_atomic(s)
    return {"ok":True,"state":"ACTIVE"}

@contextmanager
def action_lock_observe():
    fd=os.open(ACTION_LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
        else:
            yield True
    finally:os.close(fd)

def monitor():
    require_root()
    while True:
        try:
            s=read_state()
            if s is None:return
            if s["phase"] in ("STOPPING","DEGRADED"):
                time.sleep(POLL_SECONDS)
                continue
            if s["phase"]=="ARMING":
                recover=False
                if time.time()-s["started"]>MONITOR_GRACE:
                    # An in-flight Start owns the global action lock.
                    with action_lock_observe() as available:
                        if available:
                            rollback("START_TIMEOUT",stop_monitor=False)
                            recover=True
                # Never call the root Recovery unit with our flock still held.
                if recover:
                    call("systemctl","start","directinternetmethod-recovery.service",
                         timeout=35,ok=False)
                    return
                time.sleep(POLL_SECONDS)
                continue
            recover=False
            with action_lock_observe() as available:
                if available:
                    reason=None
                    statepath=(pathlib.Path(s["home"])/
                               ".local/share/DirectInternetMethod/directmethod/state.json")
                    try:
                        loaded=json.loads(statepath.read_text())
                        need(loaded.get("selectiveDns") is True and
                             int(loaded.get("nfqwsPid") or 0)>1,"ENGINE_GONE")
                        need(os.path.exists(f"/proc/{loaded['nfqwsPid']}/exe"),
                             "NFQWS_PROCESS_MISSING")
                        need(os.readlink(f"/proc/{loaded['nfqwsPid']}/exe")==
                             os.path.realpath(str(HELPER_ROOT/"runtime/usr/bin/nfqws")),
                             "NFQWS_EXECUTABLE_NOT_OWNED")
                        need(status_unit(s["dnsUnit"])=="active","DNS_SERVICE_GONE")
                        need(link_fields(s["interface"])==expected_active(s["baseline"]),
                             "LINK_DNS_DRIFT")
                        split_tailscale_ready()
                        need(tailscale_dns_fingerprint()==s["tailscaleDnsSha"],
                             "TAILSCALE_DNS_DRIFT")
                    except Exception as error:
                        reason=str(error)
                    if reason:
                        rollback("MONITOR:"+reason,stop_monitor=False)
                        recover=True
            # The flock has been released before invoking the recovery unit.
            if recover:
                call("systemctl","start","directinternetmethod-recovery.service",
                     timeout=35,ok=False)
                return
        except Exception:
            # systemd Restart=on-failure retries rather than falsely
            # treating ambiguous restoration as completed.
            raise
        time.sleep(POLL_SECONDS)

def backstop():
    require_root()
    recover=False
    reason=""
    # This periodic check runs as a separate systemd timer/service.
    # Never modify DNS while an ordinary Start/Stop owns the global lock.
    with action_lock_observe() as available:
        if not available:
            return {"ok":True,"state":"ACTION_LOCK_BUSY_RETRY_NEXT_TICK"}
        s=read_state()
        if s is None:return {"ok":True,"state":"NO_SESSION"}
        phase=s["phase"]
        if phase=="ARMING" and time.time()-s["started"]<=MONITOR_GRACE:
            return {"ok":True,"state":"START_GRACE_PENDING"}
        if phase=="ACTIVE":
            try:
                need(status_unit(s["monitorUnit"])=="active","MONITOR_STOPPED")
                need(status_unit(s["dnsUnit"])=="active","FORWARDER_STOPPED")
                need(link_fields(s["interface"])==expected_active(s["baseline"]),
                     "DNS_LINK_DRIFT")
                split_tailscale_ready()
                need(tailscale_dns_fingerprint()==s["tailscaleDnsSha"],
                     "TAILSCALE_DNS_DRIFT")
                return {"ok":True,"state":"HEALTHY"}
            except Exception as error:
                reason=str(error)
        else:
            reason="NONACTIVE_PHASE_"+phase
        rollback("INDEPENDENT_BACKSTOP:"+reason,stop_monitor=True)
        recover=True
    # Critical: call Recovery only AFTER releasing the action lock.
    if recover:
        call("systemctl","start","directinternetmethod-recovery.service",
             timeout=35,ok=False)
    return {"ok":True,"state":"RESTORED_BY_BACKSTOP","reason":reason}

def status():
    s=read_state()
    if not s:return {"ok":True,"state":"INACTIVE"}
    return {"ok":True,"state":s["phase"],"interface":s["interface"],
            "unencryptedDns":True,
            "dnsRunning":status_unit(s["dnsUnit"])=="active",
            "monitorRunning":status_unit(s["monitorUnit"])=="active",
            "backstopRunning":status_timer(s["backstopTimer"])=="active"}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("action",choices=("activate","commit","restore","monitor","backstop","status"))
    ap.add_argument("--uid",type=int)
    ap.add_argument("--interface")
    ap.add_argument("--home")
    args=ap.parse_args()
    try:
        if args.action=="activate":
            result=activate(args.uid,args.interface,args.home)
        elif args.action=="commit":result=commit()
        elif args.action=="restore":result=rollback()
        elif args.action=="monitor":monitor();result={"ok":True,"state":"MONITOR_DONE"}
        elif args.action=="backstop":result=backstop()
        else:result=status()
        print(json.dumps(result,sort_keys=True))
    except Exception as err:
        print(json.dumps({"ok":False,"error":str(err)[:240]}),file=sys.stderr)
        return 83
    return 0

if __name__=="__main__":sys.exit(main())
