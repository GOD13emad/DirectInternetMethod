#!/usr/bin/env python3
"""R247 rootless failure-injection tests for selective DNS restoring order."""
from __future__ import annotations
import importlib.util,json,pathlib,tempfile,os
spec=importlib.util.spec_from_file_location(
    "r247_sel_restore",
    pathlib.Path(__file__).resolve().parents[1]/"linux/system/selective_dns.py")
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
root=pathlib.Path("/run/directinternetmethod-selective")
passed=0
def yes(name,ok):
    global passed
    assert ok,name
    passed+=1
    print("PASS",name)
def fixture(d):
    folder=pathlib.Path(d)/"session";folder.mkdir(mode=0o700)
    conf=pathlib.Path(d)/"service.conf"
    base={"dns":["192.168.20.1"],"domains":["bwrouter"],"defaultRoute":True}
    active=m.expected_active(base)
    state={"schema":1,"phase":"ACTIVE","uid":1000,"home":"/home/aliemad",
           "interface":"enp1s0","session":"0123456789","upstream":m.UPSTREAM,
           "baseline":base,"tailscaleDnsSha":"a"*64,
           "dnsUnit":"dim-sdns-dns-1000-0123456789.service",
           "monitorUnit":"dim-sdns-watch-1000-0123456789.service",
           "configPath":str(conf)}
    return folder,conf,base,active,state
old={k:getattr(m,k) for k in ("STATE_DIR","STATE_FILE","CONF","require_root",
                              "read_state","link_fields","change_link","status_unit","call")}
try:
    with tempfile.TemporaryDirectory(prefix="dim-r247-restore-tests-") as td:
        f,c,base,active,s=fixture(td)
        m.STATE_DIR=f;m.STATE_FILE=f/"session.json";m.CONF=c
        m.require_root=lambda:None
        m.validate_state(s)
        c.write_bytes(m.make_conf(base));m.STATE_FILE.write_text(json.dumps(s))
        modes={s["dnsUnit"]:"active",s["monitorUnit"]:"active"}
        observed=[dict(active)]
        actions=[]
        m.read_state=lambda:s
        m.link_fields=lambda iface:dict(observed[0])
        def change(iface,dns,domains,droute):
            actions.append("RESTORE_PHYSICAL_DNS_FIRST")
            observed[0]={"dns":list(dns),"domains":list(domains),"defaultRoute":droute}
        m.change_link=change
        m.status_unit=lambda unit:modes[unit]
        def call(*args,**kwargs):
            assert args[:2]==("systemctl","stop"),args
            actions.append("STOP_"+str(args[2]))
            modes[args[2]]="inactive"
            class Result:stdout="";stderr="";returncode=0
            return Result()
        m.call=call
        result=m.rollback("SIMULATED_TEST")
        yes("owned session rollback acknowledges restore",
            result["ok"] and result["state"]=="RESTORED")
        yes("original link policy completely restored",observed[0]==base)
        yes("dns restored before stopping dnsmasq",
            actions[0]=="RESTORE_PHYSICAL_DNS_FIRST" and
            actions[1]=="STOP_"+s["dnsUnit"])
        yes("monitor stopped after dnsmasq",actions[2]=="STOP_"+s["monitorUnit"])
        yes("owned config and state cleaned",not c.exists() and not f.exists())

    with tempfile.TemporaryDirectory(prefix="dim-r247-foreign-drift-") as td:
        f,c,base,active,s=fixture(td)
        m.STATE_DIR=f;m.STATE_FILE=f/"session.json";m.CONF=c
        m.require_root=lambda:None
        m.validate_state(s)
        c.write_bytes(m.make_conf(base));m.STATE_FILE.write_text(json.dumps(s))
        m.read_state=lambda:s
        m.link_fields=lambda iface:{"dns":["8.8.8.8"],"domains":["foreign"],
                                    "defaultRoute":False}
        actions=[]
        m.change_link=lambda *args:actions.append("UNEXPECTED_HOST_MUTATION")
        try:m.rollback("SIMULATED_FOREIGN")
        except RuntimeError as e:
            yes("foreign dns policy rejected fail closed",
                "FOREIGN_DNS_POLICY_PRESERVED" in str(e))
        else:raise AssertionError("FOREIGN_MUTATION_NOT_REJECTED")
        yes("no host changes during foreign conflict",not actions)
        yes("foreign marker remains for diagnosis",m.STATE_FILE.exists() and c.exists())
    print(f"PASS selective_dns_owned_rollback_negative {passed}/{passed}")
finally:
    for k,v in old.items():setattr(m,k,v)
