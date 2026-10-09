#!/usr/bin/env python3
"""R248 independent repeating backstop: rootless monitor-death fault injections."""
import importlib.util, pathlib, time
from contextlib import contextmanager
R=pathlib.Path(__file__).resolve().parents[1]
P=R/"linux/system/selective_dns.py"
spec=importlib.util.spec_from_file_location("dim_r248_backstop_runtime",P)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
count=0
def pass_case(name,ok):
    global count
    assert ok,name
    count+=1;print("PASS",name)
base={"dns":["192.168.20.1"],"domains":["bwrouter"],"defaultRoute":True}
active=m.expected_active(base)
root_state={
 "schema":1,"phase":"ACTIVE","interface":"enp1s0","uid":1000,
 "home":"/home/aliemad","session":"0123456789",
 "tailscaleDnsSha":"a"*64,
 "dnsUnit":"dim-sdns-dns-1000-0123456789.service",
 "monitorUnit":"dim-sdns-watch-1000-0123456789.service",
 "backstopTimer":"dim-sdns-backstop-1000-0123456789.timer",
 "upstream":m.UPSTREAM,"configPath":str(m.CONF),"baseline":base,
 "started":time.time()-180}
m.validate_state(root_state)
original={x:getattr(m,x) for x in ("require_root","read_state","status_unit",
        "link_fields","split_tailscale_ready","tailscale_dns_fingerprint",
        "action_lock_observe","rollback","call")}
m.require_root=lambda:None
m.split_tailscale_ready=lambda:True
m.tailscale_dns_fingerprint=lambda:"a"*64
try:
 for case in ("HEALTHY","MONITOR_STOPPED","ARMING_GRACE","ARMING_EXPIRED",
              "LOCK_BUSY","FOREIGN_DNS"):
    s=dict(root_state);events=[];held={"value":False}
    observed=[dict(active)]
    if case=="ARMING_GRACE":
        s["phase"]="ARMING";s["started"]=time.time()
    elif case=="ARMING_EXPIRED":
        s["phase"]="ARMING";s["started"]=time.time()-m.MONITOR_GRACE-15
    m.read_state=lambda:s
    m.link_fields=lambda iface:observed[0]
    monitor_status="inactive" if case=="MONITOR_STOPPED" else "active"
    m.status_unit=lambda unit: monitor_status if unit==s["monitorUnit"] else "active"
    if case=="FOREIGN_DNS":
        observed[0]={"dns":["8.8.8.8"],"domains":["foreign"],"defaultRoute":False}
    @contextmanager
    def take_lock():
        if case=="LOCK_BUSY":
            yield False;return
        assert not held["value"]
        held["value"]=True
        events.append("LOCK_ACQUIRED")
        try:yield True
        finally:held["value"]=False;events.append("LOCK_RELEASED")
    m.action_lock_observe=take_lock
    def restore(reason,stop_monitor=True):
        assert held["value"],"BACKSTOP_RESTORE_WITHOUT_LOCK"
        events.append("ROLLBACK")
        if case=="FOREIGN_DNS":
            raise RuntimeError("FOREIGN_DNS_POLICY_PRESERVED")
        observed[0]=dict(base)
        return {"ok":True}
    m.rollback=restore
    def launch(*args,**kwargs):
        assert args[:3]==("systemctl","start","directinternetmethod-recovery.service")
        assert not held["value"],"BACKSTOP_RECOVERY_WITH_ACTION_LOCK"
        events.append("RECOVERY_AFTER_UNLOCK")
        class Done:returncode=0;stdout="";stderr=""
        return Done()
    m.call=launch
    if case=="FOREIGN_DNS":
        try:m.backstop()
        except RuntimeError as err:
            pass_case("foreign DNS policy retained and reported",
                      "FOREIGN_DNS_POLICY_PRESERVED" in str(err))
        else:raise AssertionError("BACKSTOP_SILENT_FOREIGN_DNS")
        pass_case("no recovery for foreign mutation",
                  "RECOVERY_AFTER_UNLOCK" not in events)
    else:
        result=m.backstop()
        expected={
          "HEALTHY":"HEALTHY",
          "MONITOR_STOPPED":"RESTORED_BY_BACKSTOP",
          "ARMING_GRACE":"START_GRACE_PENDING",
          "ARMING_EXPIRED":"RESTORED_BY_BACKSTOP",
          "LOCK_BUSY":"ACTION_LOCK_BUSY_RETRY_NEXT_TICK"
        }[case]
        pass_case(case+" exact status",result["state"]==expected)
        if case in ("MONITOR_STOPPED","ARMING_EXPIRED"):
            pass_case(case+" DNS restore BEFORE recovery with unlocked flock",
                      events==["LOCK_ACQUIRED","ROLLBACK","LOCK_RELEASED","RECOVERY_AFTER_UNLOCK"])
            pass_case(case+" restores original DNS snapshot",observed[0]==base)
        else:
            pass_case(case+" does not mutate DNS or invoke Recovery",
                      "ROLLBACK" not in events and "RECOVERY_AFTER_UNLOCK" not in events)
    pass_case(case+" does not leak action flock",held["value"] is False)
finally:
 for key,value in original.items():setattr(m,key,value)
print(f"PASS R248 backstop fault injection {count}/{count}; zero host mutations")
