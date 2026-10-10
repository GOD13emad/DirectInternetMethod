#!/usr/bin/env python3
"""R247 monitor crash/timeout fail-closed ownership and lock ordering, no root."""
from __future__ import annotations
import importlib.util,json,pathlib,tempfile
from contextlib import contextmanager
R=pathlib.Path(__file__).resolve().parents[1]
p=R/"linux/system/selective_dns.py"
spec=importlib.util.spec_from_file_location("dim_r247_monitor_contract",p)
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
tests=0
def yes(name,ok):
    global tests
    assert ok,name
    tests+=1
    print("PASS",name)
old={name:getattr(mod,name) for name in
     ("require_root","read_state","action_lock_observe","rollback","call")}
try:
    for case in ("ACTIVE_ENGINE_MISSING","ARMING_EXPIRED","ACTIVE_FOREIGN_DNS"):
        with tempfile.TemporaryDirectory(prefix="dim-r247-monitor-") as tmp:
            home=pathlib.Path(tmp)
            app=home/".local/share/DirectInternetMethod/directmethod"
            app.mkdir(parents=True)
            (app/"state.json").write_text('{"selectiveDns":true,"nfqwsPid":9876543}')
            active=case!="ARMING_EXPIRED"
            state={"schema":1,"home":str(home),"phase":"ACTIVE" if active else "ARMING",
                   "started":0,"uid":1000,"interface":"enp1s0"}
            events=[]
            busy={"value":False}
            mod.require_root=lambda:None
            mod.read_state=lambda:state
            @contextmanager
            def flock():
                assert not busy["value"]
                events.append("LOCK_ACQUIRED")
                busy["value"]=True
                try:
                    yield True
                finally:
                    busy["value"]=False
                    events.append("LOCK_RELEASED")
            mod.action_lock_observe=flock
            def rollback(reason,stop_monitor):
                assert busy["value"]
                events.append("ROLLBACK_DNS")
                if case=="ACTIVE_FOREIGN_DNS":
                    raise RuntimeError("FOREIGN_DNS_POLICY_PRESERVED")
                return {"ok":True}
            mod.rollback=rollback
            def invoke(*args,**kwargs):
                assert args[:3]==("systemctl","start","directinternetmethod-recovery.service")
                assert not busy["value"],"RECOVERY_WAS_CALLED_WHILE_ACTION_LOCK_HELD"
                events.append("RECOVERY_UNIT")
                class Process:returncode=0;stdout="";stderr=""
                return Process()
            mod.call=invoke
            if case=="ACTIVE_FOREIGN_DNS":
                try:mod.monitor()
                except RuntimeError as err:
                    yes("foreign DNS aborts monitor and retains evidence",
                        "FOREIGN_DNS_POLICY_PRESERVED" in str(err))
                else:raise AssertionError("FOREIGN_DNS_ERROR_SWALLOWED")
                yes("foreign policy never triggers invasive Recovery",
                    "RECOVERY_UNIT" not in events)
                yes("foreign DNS still releases action lock",busy["value"] is False)
            else:
                mod.monitor()
                yes(case+" monitor restores before Recovery",
                    events==["LOCK_ACQUIRED","ROLLBACK_DNS","LOCK_RELEASED","RECOVERY_UNIT"])
                yes(case+" no action lock left",busy["value"] is False)
finally:
    for name,value in old.items():setattr(mod,name,value)
print(f"PASS selective_dns_monitor_lock_regression {tests}/{tests}; NO system mutations")
