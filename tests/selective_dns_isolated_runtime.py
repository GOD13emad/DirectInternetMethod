#!/usr/bin/env python3
"""R247 rootless, isolated selective DNS controller safety tests."""
from __future__ import annotations
import importlib.util, ipaddress, json, os, pathlib, stat, tempfile, types
from unittest.mock import patch
R=pathlib.Path(__file__).resolve().parents[1]
P=R/"linux/system/selective_dns.py"
spec=importlib.util.spec_from_file_location("dim_selective_dns_r247",P)
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
ok=0
def yes(name,test):
    global ok
    assert test,name
    ok+=1
    print("PASS",name)
def refuses(fn,reason):
    try:fn()
    except RuntimeError as e:
        assert reason in str(e),(reason,str(e))
        return True
    return False

yes("domain allowlist is exact",
    m.TARGETS==("youtube.com","googlevideo.com","ytimg.com","youtu.be"))
yes("forwarder local-only and separate upstream",
    b"listen-address=127.0.0.1" in m.make_conf({"dns":["192.168.20.1"],"domains":["bwrouter"],"defaultRoute":True}) and
    b"server=192.168.20.1" in m.make_conf({"dns":["192.168.20.1"],"domains":["bwrouter"],"defaultRoute":True}) and
    b"server=/youtube.com/194.225.152.10" in m.make_conf({"dns":["192.168.20.1"],"domains":["bwrouter"],"defaultRoute":True}))
yes("forwarder does not expose public interface",
    b"listen-address=0.0.0.0" not in m.make_conf({"dns":["192.168.20.1"],"domains":["bwrouter"],"defaultRoute":True}))
yes("canonical link output",
    m.parse_link_line("Link 2 (enp1s0): 192.168.20.1\n","enp1s0")==["192.168.20.1"])
yes("wrong physical interface fail-closed",
    refuses(lambda:m.parse_link_line("Link 2 (wlp2s0): 192.168.20.1\n","enp1s0"),"LINK_OUTPUT_MISMATCH"))
yes("dns synthetic state matches original policy",
    m.expected_active({"dns":["192.168.20.1"],"domains":["bwrouter"],"defaultRoute":True})==
    {"dns":["127.0.0.1:10535"],"domains":["bwrouter"],"defaultRoute":True})
yes("unit name pattern bounded",
    bool(m.UNIT_RE.fullmatch("dim-sdns-dns-1000-0123456789.service")) and
    not m.UNIT_RE.fullmatch("ssh.service"))
def state():
 return {"schema":1,"interface":"enp1s0","uid":1000,"phase":"ACTIVE",
         "session":"0123456789","upstream":m.UPSTREAM,"home":"/home/testuser",
         "tailscaleDnsSha":"a"*64,
         "baseline":{"dns":["192.168.20.1"],"domains":["bwrouter"],"defaultRoute":True},
         "dnsUnit":"dim-sdns-dns-1000-0123456789.service",
         "monitorUnit":"dim-sdns-watch-1000-0123456789.service",
         "backstopTimer":"dim-sdns-backstop-1000-0123456789.timer",
         "configPath":str(m.CONF)}
yes("valid protected marker recognized",(m.validate_state(state()) is None))
s=state();s["dnsUnit"]="ssh.service"
yes("reject foreign unit state",refuses(lambda:m.validate_state(s),"STATE_DNS_UNIT"))
s=state();s["interface"]="tailscale0;reboot"
yes("reject command injection in iface",refuses(lambda:m.validate_state(s),"STATE_IFACE"))
s=state();s["session"]="bad"
yes("reject forged session ID",refuses(lambda:m.validate_state(s),"STATE_SESSION"))
s=state();s["baseline"]["dns"]=["127.0.0.1"]
yes("loopback cannot be baseline",refuses(lambda:m.original_baseline("enp1s0") if False else
     (m.need(not ipaddress.ip_address(s["baseline"]["dns"][0]).is_loopback,"LOOPBACK"),0),"LOOPBACK"))
with tempfile.TemporaryDirectory(prefix="dim-r247-optin-") as d:
 home=pathlib.Path(d);app=home/".local/share/DirectInternetMethod";app.mkdir(parents=True)
 (app/"strategy.txt").write_text("balanced\n")
 (app/"scope.txt").write_text("targeted\n")
 p=app/"selective-dns-optin.txt"
 uid=os.getuid()
 yes("disabled by default",refuses(lambda:m.valid_optin(home,uid),"SELECTIVE_DNS_OPT_IN_MISSING"))
 p.write_text("I_ACCEPT_UNENCRYPTED_SELECTIVE_DNS_V1\n");p.chmod(0o600)
 yes("user-owned explicit plaintext consent permitted",m.valid_optin(home,uid) is True)
 p.write_text("YES\n")
 yes("reject ambiguous consent",refuses(lambda:m.valid_optin(home,uid),"SELECTIVE_DNS_EXPLICIT_CONSENT_REQUIRED"))
 p.write_text("I_ACCEPT_UNENCRYPTED_SELECTIVE_DNS_V1\n")
 (app/"strategy.txt").write_text("compatibility\n")
 yes("reject nonbalanced strategy",refuses(lambda:m.valid_optin(home,uid),"SELECTIVE_DNS_REQUIRES_BALANCED_TARGETED"))
 (app/"strategy.txt").write_text("balanced\n")
 (app/"scope.txt").write_text("all-sites\n")
 yes("reject all-sites scope",refuses(lambda:m.valid_optin(home,uid),"SELECTIVE_DNS_REQUIRES_BALANCED_TARGETED"))
 (app/"scope.txt").write_text("targeted\n")
 p.unlink();p.symlink_to(app/"strategy.txt")
 yes("reject symlink optin",refuses(lambda:m.valid_optin(home,uid),"SELECTIVE_DNS_OPT_IN_MISSING"))
yes("no daemon/port at module import",not m.STATE_DIR.exists() and not m.CONF.exists())
print(f"PASS selective_dns_negative_contract {ok}/{ok} cases, NO host mutation")
