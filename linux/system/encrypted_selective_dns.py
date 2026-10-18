#!/usr/bin/env python3
"""R517 staged root-owned managed encrypted selective DNS controller.

NOT INSTALLED OR RELEASED. This source shares only the native DirectMethod
action lock and uses an independent explicit opt-in (never old UDP consent).
Owned dummy per-link DNS and monitored ctrld v1.5.7 are fail-closed; an
independent repeating systemd backstop is armed before any resolver mutation.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import importlib.util
import json
import os
import pathlib
import pwd
import re
import subprocess
import sys
import stat
import tempfile
import time
import uuid
from contextlib import contextmanager

ROOT = pathlib.Path("/usr/lib/directinternetmethod")
STATE_DIR = pathlib.Path("/run/directinternetmethod-encrypted")
STATE = STATE_DIR / "session.json"
CONFIG = pathlib.Path("/run/directinternetmethod-encrypted-ctrld.toml")
ACTION_LOCK = pathlib.Path("/run/directinternetmethod-action.lock")
CTRLD = ROOT / "runtime/usr/bin/ctrld"
SOURCE = ROOT / "encrypted_selective_dns.py"
POLICY = ROOT / "encrypted_selective_policy.py"
VERSIONED_CTRLD_SHA = "CA64579A2BC866CF72F3E46663E551162AFEFF0D448E899A01817A095E45B071"
VERSIONED_NFQWS_SHA = "F34615964D7321650197CD69D3F7CBFDAABE8118B5A0D57C6E41DCCDFF658999"
NFQWS = ROOT / "runtime/usr/bin/nfqws"
IFACE = "dimesd0"
IP = "172.31.254.59"
CIDR = IP + "/32"
PORT = 53534
TARGETS = ("youtube.com", "googlevideo.com", "ytimg.com", "youtu.be")
CONSENT = "I_ACCEPT_ENCRYPTED_SELECTIVE_DNS_V1"
OLD_OPTIN = "selective-dns-optin.txt"
NEW_OPTIN = "encrypted-dns-optin.txt"
GRACE_SEC = 120
BACKSTOP_SEC = 45
MONITOR_SEC = 4
UNIT_RE = re.compile(r"^dim-edsn-(?:dns|watch)-[0-9]{1,10}-[0-9a-f]{10}\.service$")
TIMER_RE = re.compile(r"^dim-edsn-backstop-[0-9]{1,10}-[0-9a-f]{10}\.timer$")
PHY_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
STATE_PHASES = frozenset(("ARMING", "ACTIVE", "STOPPING", "DEGRADED"))


def need(condition: bool, why: str) -> None:
    if not condition:
        raise RuntimeError("FAIL_CLOSED_" + why)


# Root action helpers must never resolve their executable from the caller's PATH.
# All call sites select one of these fixed, OS-owned executables.
TRUSTED_SYSTEM_BINARIES = {
    "resolvectl": "/usr/bin/resolvectl",
    "tailscale": "/usr/bin/tailscale",
    "nmcli": "/usr/bin/nmcli",
    "ip": "/usr/bin/ip",
    "ss": "/usr/bin/ss",
    "systemctl": "/usr/bin/systemctl",
    "busctl": "/usr/bin/busctl",
    "dig": "/usr/bin/dig",
    "systemd-run": "/usr/bin/systemd-run",
}


def call(*args: str, seconds: int = 10, ok: bool = True) -> subprocess.CompletedProcess:
    need(bool(args) and type(args[0]) is str and args[0] in TRUSTED_SYSTEM_BINARIES,
         "UNTRUSTED_COMMAND")
    executable = pathlib.Path(TRUSTED_SYSTEM_BINARIES[args[0]])
    need(executable.is_file() and not executable.is_symlink(), "TRUSTED_TOOL_MISSING")
    mode = executable.stat()
    need(mode.st_uid == 0 and mode.st_mode & 0o022 == 0, "TRUSTED_TOOL_OWNER")
    p = subprocess.run((str(executable), *args[1:]), capture_output=True, text=True,
                       timeout=seconds)
    if ok and p.returncode:
        raise RuntimeError("CALL_FAILED_" + repr(args[:3]) + "_" + str(p.returncode) +
                           "_" + p.stderr[-100:])
    return p


def root() -> None:
    need(os.geteuid() == 0, "ROOT_REQUIRED")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest().upper()


def file_sha(p: pathlib.Path) -> str:
    return sha(p.read_bytes())


def save(path: pathlib.Path, data: bytes, mode: int = 0o600) -> None:
    need(path.parent.is_dir() and not path.parent.is_symlink(), "OUTPUT_PARENT")
    f,temp = tempfile.mkstemp(prefix=".dim-encrypted-", dir=str(path.parent))
    try:
        with os.fdopen(f, "wb") as h:
            h.write(data); h.flush(); os.fsync(h.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
    finally:
        if os.path.lexists(temp):
            os.unlink(temp)


def write_state(state: dict) -> None:
    need(STATE_DIR.is_dir() and not STATE_DIR.is_symlink(), "ROOT_STATE_DIR")
    need(STATE_DIR.stat().st_uid == 0 and STATE_DIR.stat().st_mode & 0o777 == 0o700,
         "ROOT_DIR_MODE")
    save(STATE, (json.dumps(state, sort_keys=True, indent=2) + "\n").encode())


def validate_state(s: dict) -> dict:
    need(type(s) is dict and s.get("schema") == 1, "STATE_SCHEMA")
    need(s.get("phase") in STATE_PHASES, "STATE_PHASE")
    uid = s.get("uid")
    session = s.get("session")
    need(type(uid) is int and 0 < uid < 2**31, "STATE_UID")
    need(isinstance(session, str) and re.fullmatch("[0-9a-f]{10}", session),
         "STATE_SESSION")
    need(s.get("iface") == IFACE and s.get("ownedIp") == CIDR and s.get("port") == PORT,
         "STATE_LINK_BINDING")
    need(type(s.get("dummyIndex")) in (int, type(None)) and
         (s["dummyIndex"] is None or s["dummyIndex"] > 1), "STATE_DUMMY_INDEX")
    need(PHY_RE.fullmatch(str(s.get("physical", ""))), "STATE_PHY")
    need(s.get("ctrldUnit") == f"dim-edsn-dns-{uid}-{session}.service", "STATE_CTRLD")
    need(s.get("monitorUnit") == f"dim-edsn-watch-{uid}-{session}.service", "STATE_MONITOR")
    need(s.get("backstopTimer") == f"dim-edsn-backstop-{uid}-{session}.timer",
         "STATE_BACKSTOP")
    need(UNIT_RE.fullmatch(s["ctrldUnit"]) and UNIT_RE.fullmatch(s["monitorUnit"]) and
         TIMER_RE.fullmatch(s["backstopTimer"]), "STATE_UNIT_GRAMMAR")
    need(s.get("ctrldSha") == VERSIONED_CTRLD_SHA, "STATE_BINARY_SHA")
    need(s.get("configPath") == str(CONFIG), "STATE_CONF_PATH")
    need(s.get("configSha") and re.fullmatch("[0-9A-F]{64}",s["configSha"]),
         "STATE_CONFIG_SHA")
    need(s.get("userHome", "").startswith("/home/") and
         pathlib.Path(s["userHome"]).is_absolute() and
         ".." not in pathlib.Path(s["userHome"]).parts,"STATE_USER_HOME")
    need(s.get("physicalBaseline") and
         isinstance(s["physicalBaseline"], dict) and
         s["physicalBaseline"].get("dns") and
         len(s["physicalBaseline"]["dns"])==1, "STATE_PHYSICAL_BASELINE")
    need(re.fullmatch("[0-9A-F]{64}",str(s.get("tailscaleDNS",""))),
         "STATE_TAILSCALE_SHA")
    return s


def read_state() -> dict | None:
    if not STATE.exists():
        return None
    need(STATE.is_file() and not STATE.is_symlink(), "STATE_UNSAFE_TYPE")
    st = STATE.stat()
    need(st.st_uid == 0 and st.st_mode & 0o777 == 0o600, "STATE_UNSAFE_OWNER")
    return validate_state(json.loads(STATE.read_text()))


def require_consent(uid: int, home: str) -> None:
    # This is a privileged opt-in check. Reading a legitimate leaf through
    # a user-controlled symlink parent can otherwise select an unrelated
    # token/profile. Traverse *all* directories by descriptor, no-follow.
    need(type(uid) is int and 0 < uid < 2**31, "UID")
    need(type(home) is str and home.startswith("/home/"), "HOME_OWNER")
    p = pathlib.Path(home)
    need(p.is_absolute() and ".." not in p.parts and
         len(p.parts) >= 3, "HOME_OWNER")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY |
                       os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        home_parts = p.parts[1:]
        names = home_parts + (".local", "share", "DirectInternetMethod")
        for index, name in enumerate(names):
            need(name not in (".", "..", "") and "/" not in name,
                 "CONSENT_PARENT_COMPONENT")
            try:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=directory)
            except OSError as exc:
                raise RuntimeError("FAIL_CLOSED_CONSENT_PARENT_COMPONENT") from exc
            os.close(directory)
            directory = child
            info = os.fstat(directory)
            if index == len(home_parts) - 1:
                need(info.st_uid == uid, "HOME_OWNER")
            if index >= len(home_parts):
                need(info.st_uid == uid, "CONSENT_PARENT_OWNER")

        try:
            os.stat(OLD_OPTIN, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise RuntimeError("FAIL_CLOSED_LEGACY_UNENCRYPTED_OPTIN_CONFLICT") from exc
        else:
            need(False, "LEGACY_UNENCRYPTED_OPTIN_CONFLICT")

        def token(name: str, missing: str, invalid: str, length: int, private: bool=False) -> str:
            need("/" not in name and name not in (".", "..", ""),
                 "BAD_CONSENT_TOKEN_NAME")
            try:
                f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW |
                           os.O_CLOEXEC, dir_fd=directory)
            except OSError as exc:
                raise RuntimeError("FAIL_CLOSED_" + missing) from exc
            try:
                meta = os.fstat(f)
                need(stat.S_ISREG(meta.st_mode) and meta.st_uid == uid and
                     0 <= meta.st_size <= length and
                     (not private or meta.st_mode & 0o077 == 0), invalid)
                contents = os.read(f, length + 1)
                need(len(contents) <= length, invalid)
                return contents.decode("utf8").strip()
            finally:
                os.close(f)

        need(token(NEW_OPTIN, "EXPLICIT_ENCRYPTED_CONSENT_MISSING",
                   "CONSENT_NOT_EXACT_OR_PRIVATE",129, private=True) == CONSENT,
             "CONSENT_NOT_EXACT_OR_PRIVATE")
        for name, value in (("strategy.txt", "balanced"),
                            ("scope.txt", "targeted")):
            need(token(name, "INVALID_CONSENT_PROFILE_" + name,
                       "INVALID_CONSENT_PROFILE_" + name,32) == value,
                 "INVALID_CONSENT_PROFILE_" + name)
    finally:
        os.close(directory)


def link_state(iface: str) -> dict:
    need(PHY_RE.fullmatch(iface), "BAD_IFACE")
    def field(cmd: str) -> list[str]:
        text=call("resolvectl",cmd,iface).stdout.strip()
        m=re.fullmatch(r"Link \d+ \(" + re.escape(iface) + r"\):(?: (.*))?",text)
        need(bool(m),"LINK_FIELDS_UNPARSEABLE_"+cmd)
        return (m.group(1) or "").split()
    route=field("default-route")
    need(len(route)==1 and route[0] in ("yes","no"),"DNS_DEFAULT_ROUTE_INVALID")
    return {"dns":field("dns"),"domains":field("domain"),"default":route[0]=="yes"}


def tailscale_fingerprint() -> str:
    data=(call("resolvectl","dns","tailscale0").stdout+
          call("resolvectl","domain","tailscale0").stdout).encode()
    return sha(data)


def network_preflight(phy: str) -> dict:
    need(PHY_RE.fullmatch(phy) and phy not in ("lo", "tailscale0", IFACE),
         "PHYSICAL_LINK_UNSAFE")
    result=json.loads(call("tailscale","status","--json").stdout)
    need(result.get("BackendState")=="Running" and not result.get("ExitNodeStatus"),
         "TAILSCALE_SPLIT_REQUIRED")
    modes=call("nmcli","-t","-f","TYPE,DEVICE","connection","show","--active").stdout.splitlines()
    for mode in modes:
        need(mode and ":" in mode,"NETWORK_MANAGER_AMBIGUOUS")
        typ,dev=mode.split(":",1)
        need(typ not in ("vpn","wireguard"),"EXTRA_VPN_CONFLICT")
        if typ=="tun":
            need(dev=="tailscale0","EXTRA_TUNNEL_CONFLICT")
    route=call("ip","-4","route","show","default").stdout.strip()
    need("dev "+phy in route and not ("dev tun" in route or "dev wg" in route),
         "WAN_ROUTE_NOT_PHYSICAL")
    for family in ("-4","-6"):
        table=call("ip",family,"route","show","table","52").stdout.splitlines()
        need(not any(line.strip().startswith(("default","0.0.0.0/1","128.0.0.0/1",
                                              "::/1","8000::/1")) for line in table),
             "TAILSCALE_EXIT_ROUTE")
    physical=link_state(phy)
    need(physical["default"] and len(physical["dns"])==1, "NEED_SINGLE_PHYSICAL_DNS")
    # The pure protected policy validates literal RFC1918 router addresses.
    need(not STATE_DIR.exists() and not CONFIG.exists() and not CONFIG.is_symlink(),
         "PREEXISTING_ENCRYPTED_DNS")
    need(not pathlib.Path("/sys/class/net", IFACE).exists(),"DUMMY_LINK_COLLISION")
    need(not call("ip","-4","route","show","exact",CIDR).stdout.strip(),
         "RESERVED_IPV4_COLLISION")
    need(":"+str(PORT) not in call("ss","-lunpt",ok=False).stdout,
         "DNS_LISTENER_PORT_OCCUPIED")
    need(CTRLD.is_file() and file_sha(CTRLD)==VERSIONED_CTRLD_SHA,"CTRLD_VERSION_SHA")
    need(POLICY.is_file() and SOURCE.is_file(),"PROTECTED_CONTROLLER_INCOMPLETE")
    return physical


def runtime_tunnel_guard(physical: str) -> None:
    """Read-only fail-closed guard for VPN/Tailscale changes after activation."""
    need(bool(PHY_RE.fullmatch(physical)) and physical not in ("lo","tailscale0",IFACE),
         "RUNTIME_PHYSICAL_IFACE")
    ts=json.loads(call("tailscale","status","--json").stdout)
    need(ts.get("BackendState")=="Running" and not ts.get("ExitNodeStatus"),
         "RUNTIME_TAILSCALE_EXIT_OR_DOWN")
    modes=call("nmcli","-t","-f","TYPE,DEVICE","connection","show","--active").stdout.splitlines()
    seen_tailscale=False
    seen_physical=False
    for item in modes:
        need(":" in item,"RUNTIME_NMCLI_AMBIGUOUS")
        kind,dev=item.split(":",1)
        need(kind not in ("vpn","wireguard"),"RUNTIME_FOREIGN_VPN_CONFLICT")
        if kind=="tun":
            need(dev=="tailscale0","RUNTIME_FOREIGN_TUNNEL_CONFLICT")
            seen_tailscale=True
        if dev==physical:
            need(kind not in ("tun","vpn","wireguard"),"RUNTIME_PHY_RECLASSIFIED")
            seen_physical=True
    need(seen_physical and seen_tailscale,"RUNTIME_EXPECTED_INTERFACES_MISSING")
    route=call("ip","-4","route","show","default").stdout.strip()
    need("dev "+physical in route and "dev tun" not in route and "dev wg" not in route,
         "RUNTIME_DEFAULT_WAN_CHANGED")
    for family in ("-4","-6"):
        entries=call("ip",family,"route","show","table","52").stdout.splitlines()
        need(not any(x.strip().startswith(("default","0.0.0.0/1","128.0.0.0/1",
                                           "::/1","8000::/1")) for x in entries),
             "RUNTIME_TAILSCALE_EXIT_ROUTE")


def policy_bytes(router: str) -> bytes:
    spec=importlib.util.spec_from_file_location("dim_protected_policy",POLICY)
    need(spec is not None and spec.loader is not None,"POLICY_IMPORT_SPEC")
    mod=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    data=mod.build_owned_interface_policy(router)
    need(b'endpoint = "https://76.76.10.11/p0"' in data and
         b'ip = "172.31.254.59"' in data and
         b'allow_wan_clients = false' in data, "POLICY_BINDING_SHAPE")
    return data


def unit_state(name: str, timer: bool = False) -> str:
    need(bool((TIMER_RE if timer else UNIT_RE).fullmatch(name)),"UNIT_NAME_UNOWNED")
    return call("systemctl","show",name,"-p","ActiveState","--value",ok=False).stdout.strip()


def dummy_identity(s: dict) -> int | None:
    p=pathlib.Path("/sys/class/net")/IFACE
    if not p.exists():return None
    info=json.loads(call("ip","-j","-d","link","show","dev",IFACE).stdout)
    need(len(info)==1 and info[0].get("linkinfo",{}).get("info_kind")=="dummy",
         "FOREIGN_INTERFACE_KIND")
    index=int(p.joinpath("ifindex").read_text().strip())
    need(index>1 and index==s.get("dummyIndex"),"DUMMY_INDEX_REUSED")
    addresses=call("ip","-o","-4","addr","show","dev",IFACE).stdout
    need("inet "+CIDR+" " in addresses,"OWNED_LINK_ADDRESS_CHANGED")
    return index


def link_dns(idx: int) -> None:
    address=[str(x) for x in ipaddress.IPv4Address(IP).packed]
    call("busctl","--timeout=6s","call","org.freedesktop.resolve1",
         "/org/freedesktop/resolve1","org.freedesktop.resolve1.Manager",
         "SetLinkDNSEx","ia(iayqs)",str(idx),"1","2","4",*address,str(PORT),"")
    args=("busctl","--timeout=6s","call","org.freedesktop.resolve1",
          "/org/freedesktop/resolve1","org.freedesktop.resolve1.Manager",
          "SetLinkDomains","ia(sb)",str(idx),str(len(TARGETS)))
    domainargs=[x for name in TARGETS for x in (name,"true")]
    call(*args,*domainargs)
    call("busctl","--timeout=6s","call","org.freedesktop.resolve1",
         "/org/freedesktop/resolve1","org.freedesktop.resolve1.Manager",
         "SetLinkDefaultRoute","ib",str(idx),"false")


def dns_is_owned() -> bool:
    d=link_state(IFACE)
    return (d["dns"]==[f"{IP}:{PORT}"] and
            d["default"] is False and
            set(d["domains"])=={"~"+name for name in TARGETS})


def public_dns(domain: str) -> bool:
    p=call("dig","@"+IP,"-p",str(PORT),domain,"A","+tries=1","+time=3","+short",
           seconds=6,ok=False)
    ips=[]
    for line in p.stdout.splitlines():
        try:ips.append(ipaddress.IPv4Address(line.strip()))
        except (ipaddress.AddressValueError,ValueError):pass
    return bool(ips) and p.returncode==0 and all(x.is_global for x in ips)


def rollback(reason: str = "MANUAL", stop_monitor: bool = True) -> dict:
    root()
    s=read_state()
    if s is None:
        need(not CONFIG.exists(),"UNOWNED_OR_ORPHAN_CONF")
        need(not pathlib.Path("/sys/class/net",IFACE).exists(),"UNOWNED_ORPHAN_LINK")
        return {"ok":True,"state":"NO_SESSION"}
    idx=dummy_identity(s)
    if idx is not None:
        existing=link_state(IFACE)
        # Never revert foreign resolver settings or overwrite user rules.
        need((not existing["dns"] and not existing["domains"]) or
             dns_is_owned(), "FOREIGN_LINK_DNS_PRESENT")
        call("busctl","--timeout=6s","call","org.freedesktop.resolve1",
             "/org/freedesktop/resolve1","org.freedesktop.resolve1.Manager",
             "RevertLink","i",str(idx))
    if unit_state(s["ctrldUnit"])=="active":
        raw=call("systemctl","show",s["ctrldUnit"],"-p","MainPID","--value").stdout.strip()
        pid=int(raw)
        need(pid>1 and os.path.realpath(f"/proc/{pid}/exe")==os.path.realpath(CTRLD),
             "OWNED_CTRLD_PROCESS_MISMATCH")
        call("systemctl","stop",s["ctrldUnit"],seconds=16)
    need(unit_state(s["ctrldUnit"])!="active","OWNED_CTRLD_NOT_STOPPED")
    if idx is not None:
        need(dummy_identity(s)==idx,"LINK_REPLACED_DURING_ROLLBACK")
        call("ip","link","del","dev",IFACE)
    need(not pathlib.Path("/sys/class/net",IFACE).exists(),"DUMMY_STILL_EXISTS")
    if stop_monitor and unit_state(s["monitorUnit"])=="active":
        call("systemctl","stop",s["monitorUnit"],seconds=15)
    if unit_state(s["backstopTimer"],True)=="active":
        call("systemctl","stop",s["backstopTimer"],seconds=15)
    need(unit_state(s["backstopTimer"],True)!="active","TIMER_STILL_ACTIVE")
    need(CONFIG.is_file() and not CONFIG.is_symlink() and
         CONFIG.stat().st_uid==0 and sha(CONFIG.read_bytes())==s["configSha"],
         "CONFIG_FOREIGN_PRESERVED")
    CONFIG.unlink()
    STATE.unlink()
    if STATE_DIR.is_dir() and not any(STATE_DIR.iterdir()): STATE_DIR.rmdir()
    return {"ok":True,"state":"RESTORED","reason":reason}


def activate(uid: int, iface: str, home: str) -> dict:
    root()
    require_consent(uid,home)
    baseline=network_preflight(iface)
    fingerprint=tailscale_fingerprint()
    policy=policy_bytes(baseline["dns"][0])
    STATE_DIR.mkdir(mode=0o700)
    os.chmod(STATE_DIR,0o700)
    token=uuid.uuid4().hex[:10]
    s={
       "schema":1,"phase":"ARMING","uid":uid,"session":token,
       "userHome":home,"physical":iface,"physicalBaseline":baseline,
       "tailscaleDNS":fingerprint,"ctrldSha":VERSIONED_CTRLD_SHA,
       "configPath":str(CONFIG),"configSha":sha(policy),
       "iface":IFACE,"ownedIp":CIDR,"port":PORT,"dummyIndex":None,
       "started":time.time(),
       "ctrldUnit":f"dim-edsn-dns-{uid}-{token}.service",
       "monitorUnit":f"dim-edsn-watch-{uid}-{token}.service",
       "backstopTimer":f"dim-edsn-backstop-{uid}-{token}.timer"
    }
    try:
        write_state(s)
        save(CONFIG,policy,0o644)
        call("systemd-run","--quiet","--unit="+s["monitorUnit"][:-8],
             "--service-type=exec","--property=Restart=on-failure",
             "--property=RestartSec=3s","/usr/bin/python3",str(SOURCE),"monitor")
        need(unit_state(s["monitorUnit"])=="active","MONITOR_NOT_RUNNING")
        call("systemd-run","--quiet","--unit="+s["backstopTimer"][:-6],
             "--on-active="+str(BACKSTOP_SEC)+"s",
             "--on-unit-active="+str(BACKSTOP_SEC)+"s",
             "--timer-property=AccuracySec=1s",
             "/usr/bin/python3",str(SOURCE),"backstop")
        need(unit_state(s["backstopTimer"],True)=="active","INDEPENDENT_BACKSTOP_NOT_ARMED")
        call("ip","link","add",IFACE,"type","dummy")
        call("ip","addr","add",CIDR,"dev",IFACE)
        call("ip","link","set","dev",IFACE,"up")
        s["dummyIndex"]=int(pathlib.Path("/sys/class/net",IFACE,"ifindex").read_text())
        write_state(s)
        need(dummy_identity(s)==s["dummyIndex"],"NEW_DUMMY_IDENTITY")
        user=pwd.getpwuid(uid).pw_name
        call("systemd-run","--quiet","--unit="+s["ctrldUnit"][:-8],
             "--service-type=exec","--property=Restart=on-failure",
             "--property=RestartSec=3s","--property=User="+user,
             "--property=NoNewPrivileges=yes",str(CTRLD),"run","--config",str(CONFIG))
        need(unit_state(s["ctrldUnit"])=="active","CTRLD_NOT_ACTIVE")
        for target in ("www.youtube.com","redirector.googlevideo.com"):
            need(public_dns(target),"TARGET_DOH_PUBLIC_"+target)
        runtime_tunnel_guard(iface)
        link_dns(s["dummyIndex"])
        need(dns_is_owned(),"DBUS_DNS_OR_DOMAINS_NOT_OWNED")
        need(link_state(iface)==baseline,"PHYSICAL_LINK_DNS_CHANGED")
        need(tailscale_fingerprint()==fingerprint,"MAGICDNS_CHANGED")
        need(json.loads(call("tailscale","status","--json").stdout).get("BackendState")=="Running",
             "TAILSCALE_DOWN")
        need(public_dns("www.youtube.com"),"DOH_AFTER_NATIVE_DNS_MISSING")
        return {"ok":True,"state":"ARMED","session":token,"encryptedTargetDns":True}
    except BaseException:
        try:rollback("ACTIVATION_FAILED")
        except BaseException:pass
        raise


def native_engine_attested(state: dict) -> bool:
    """Cross-check the user-readable native state against *actual* root service.

    A writable state.json is never sufficient authority for protected Commit.
    """
    uid=state["uid"]
    app=(pathlib.Path(state["userHome"])/
         ".local/share/DirectInternetMethod/directmethod/state.json")
    need(app.is_file() and not app.is_symlink(),"NATIVE_STATE_MISSING_OR_SYMLINK")
    st=app.stat()
    need(st.st_uid==uid and st.st_size>40 and st.st_size<16384 and
         st.st_mode & 0o077==0,"NATIVE_STATE_OWNERSHIP")
    doc=json.loads(app.read_text(encoding="utf8"))
    unit=f"directinternetmethod-nfqws-{uid}.service"
    need(doc.get("schema")==3 and doc.get("status")=="ACTIVE" and
         doc.get("tailscaleCoexistence") is True and
         doc.get("dnsMode")=="system-preserved" and
         doc.get("selectiveDnsEncrypted") is True and
         doc.get("selectiveDns") is False and
         doc.get("physicalInterface")==state["physical"] and
         doc.get("scope")=="targeted" and doc.get("strategy")=="balanced" and
         doc.get("nfqwsUnit")==unit,"NATIVE_STATE_FIELDS")
    pid=doc.get("nfqwsPid")
    need(type(pid) is int and pid>1 and
         NFQWS.is_file() and file_sha(NFQWS)==VERSIONED_NFQWS_SHA,
         "NATIVE_NFQWS_BINARY_SHA")
    need(call("systemctl","show",unit,"-p","ActiveState","--value").stdout.strip()=="active",
         "NATIVE_NFQWS_UNIT_INACTIVE")
    number=call("systemctl","show",unit,"-p","MainPID","--value").stdout.strip()
    need(number.isdigit() and int(number)==pid,"NATIVE_NFQWS_PID_MISMATCH")
    need(os.path.realpath(f"/proc/{pid}/exe")==os.path.realpath(NFQWS),
         "NATIVE_NFQWS_PROCESS_FOREIGN")
    return True


def commit() -> dict:
    root()
    s=read_state()
    need(s is not None and s["phase"]=="ARMING","COMMIT_WITHOUT_ARMING")
    need(native_engine_attested(s),"NATIVE_ENGINE_UNCOMMITTED")
    need(unit_state(s["monitorUnit"])=="active" and
         unit_state(s["ctrldUnit"])=="active" and
         unit_state(s["backstopTimer"],True)=="active","OWNED_UNITS_LOST")
    need(dummy_identity(s)==s["dummyIndex"] and dns_is_owned(),
         "PER_LINK_SECURE_DNS_DRIFT")
    s["phase"]="ACTIVE"
    s["committed"]=time.time()
    write_state(s)
    return {"ok":True,"state":"ACTIVE","encryptedTargetDns":True}


@contextmanager
def observe_action_lock():
    fd=os.open(ACTION_LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:yield False
        else:yield True
    finally:os.close(fd)


def monitor() -> None:
    root()
    while True:
        s=read_state()
        if s is None:return
        if s["phase"] in ("STOPPING","DEGRADED"):
            time.sleep(MONITOR_SEC);continue
        failed=None
        with observe_action_lock() as available:
            if available:
                if s["phase"]=="ARMING":
                    if time.time()-s["started"]>GRACE_SEC:
                        failed="START_GRACE_EXPIRED"
                elif s["phase"]=="ACTIVE":
                    try:
                        runtime_tunnel_guard(s["physical"])
                        need(dummy_identity(s)==s["dummyIndex"] and dns_is_owned(),
                             "DNS_DRIFT")
                        need(unit_state(s["ctrldUnit"])=="active","CTRLD_DIED")
                        need(tailscale_fingerprint()==s["tailscaleDNS"],"MAGICDNS_DRIFT")
                        need(link_state(s["physical"])==s["physicalBaseline"],
                             "PHYSICAL_DNS_DRIFT")
                        need(json.loads(call("tailscale","status","--json").stdout)
                             .get("BackendState")=="Running","TAILSCALE_DIED")
                    except Exception as err:failed=str(err)
                if failed:rollback("MONITOR:"+failed,stop_monitor=False)
        if failed:
            call("systemctl","start","directinternetmethod-recovery.service",
                 seconds=35,ok=False)
            return
        time.sleep(MONITOR_SEC)


def backstop() -> dict:
    root()
    recover=None
    with observe_action_lock() as available:
        if not available:return {"ok":True,"state":"ACTION_BUSY_NEXT_TICK"}
        s=read_state()
        if s is None:return {"ok":True,"state":"INACTIVE"}
        if s["phase"]=="ARMING" and time.time()-s["started"]<=GRACE_SEC:
            return {"ok":True,"state":"START_PENDING"}
        if s["phase"]=="ACTIVE":
            try:
                runtime_tunnel_guard(s["physical"])
                need(unit_state(s["monitorUnit"])=="active","MONITOR_DIED")
                need(unit_state(s["ctrldUnit"])=="active","CTRLD_DIED")
                need(dummy_identity(s)==s["dummyIndex"] and dns_is_owned(),
                     "LINK_DNS_DRIFT")
                need(link_state(s["physical"])==s["physicalBaseline"],
                     "WAN_DNS_DRIFT")
                need(tailscale_fingerprint()==s["tailscaleDNS"],"TAILSCALE_DNS_DRIFT")
                return {"ok":True,"state":"HEALTHY"}
            except Exception as e:recover=str(e)
        else:recover="INCOMPLETE_PHASE_"+s["phase"]
        rollback("INDEPENDENT_BACKSTOP:"+recover)
    call("systemctl","start","directinternetmethod-recovery.service",
         seconds=35,ok=False)
    return {"ok":True,"state":"BACKSTOP_RECOVERED","reason":recover}


def status() -> dict:
    s=read_state()
    if s is None:return {"ok":True,"state":"INACTIVE"}
    return {"ok":True,"state":s["phase"],"iface":s["iface"],
            "encrypted":True,"monitor":unit_state(s["monitorUnit"]),
            "ctrld":unit_state(s["ctrldUnit"]),
            "backstop":unit_state(s["backstopTimer"],True)}


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("action",choices=("activate","commit","restore","monitor","backstop","status"))
    ap.add_argument("--uid",type=int)
    ap.add_argument("--interface")
    ap.add_argument("--home")
    args=ap.parse_args()
    try:
        if args.action=="activate":result=activate(args.uid,args.interface,args.home)
        elif args.action=="commit":result=commit()
        elif args.action=="restore":result=rollback()
        elif args.action=="monitor":monitor();result={"ok":True,"state":"MONITOR_DONE"}
        elif args.action=="backstop":result=backstop()
        else:result=status()
        print(json.dumps(result,sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"ok":False,"error":str(exc)[:280]}),file=sys.stderr)
        return 83


if __name__=="__main__":
    sys.exit(main())
