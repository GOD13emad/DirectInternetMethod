#!/usr/bin/env python3
"""R247 fully mocked activate->commit->restore plus rollback-on-failure."""
from __future__ import annotations
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util,json,os

R=Path(__file__).resolve().parents[1]
P=R/"linux/system/selective_dns.py"
spec=importlib.util.spec_from_file_location("dim_r247_full_mock",P)
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
score=0
def passed(label,condition):
 global score
 assert condition,label
 score+=1;print("PASS",label)

with TemporaryDirectory(prefix=".dim-r247-mock-",dir=R) as td:
 root=Path(td);user_home=root/"user-home";user_home.mkdir()
 app=user_home/".local/share/DirectInternetMethod/directmethod"
 app.mkdir(parents=True)
 installed=app/"state.json"
 installed.write_text(json.dumps({
  "selectiveDns":True,"dnsMode":"system-preserved",
  "tailscaleCoexistence":True,"nfqwsPid":1234567}))
 conf=root/"transient-dns.conf"
 state_dir=root/"state-marker"
 bas={"dns":["192.168.20.1"],"domains":["bwrouter"],"defaultRoute":True}
 live=[dict(bas)]
 services={}
 actions=[]
 mod.CONF=conf;mod.STATE_DIR=state_dir;mod.STATE_FILE=state_dir/"session.json"
 mod.SELECTOR=P
 mod.require_root=lambda:None
 mod.valid_optin=lambda h,uid:True
 mod.split_tailscale_ready=lambda:True
 mod.tailscale_dns_fingerprint=lambda:"a"*64
 mod.original_baseline=lambda iface:dict(bas)
 mod.public_answer=lambda *args,**kwargs:True
 mod.google_http204=lambda:True
 mod.protect_marker=lambda:state_dir.mkdir(mode=0o700)
 mod.read_state=lambda:json.loads(mod.STATE_FILE.read_text()) if mod.STATE_FILE.exists() else None
 mod.status_unit=lambda unit:services.get(unit,"inactive")
 mod.status_timer=lambda unit:services.get(unit,"inactive")
 mod.link_fields=lambda iface:dict(live[0])
 def change(iface,dns,domains,default):
  actions.append("WRITE_PHYSICAL_DNS")
  live[0]={"dns":list(dns),"domains":list(domains),"defaultRoute":default}
 mod.change_link=change
 fail_google=[False]
 def google():
  if fail_google[0] and live[0]!=bas:return False
  return True
 mod.google_http204=google
 def command(*args,**kwargs):
  args=tuple(args)
  actions.append(" ".join(args[:3]))
  if args and args[0]=="systemd-run":
   unit=next((x for x in args if x.startswith("--unit=")))
   suffix=".timer" if any(x.startswith("--on-active=") for x in args) else ".service"
   services[unit.split("=",1)[1]+suffix]="active"
  elif args[:2]==("systemctl","stop"):
   services[args[2]]="inactive"
  class P:returncode=0;stderr=""
  if args[:4]==("ip","-4","route","show"):P.stdout="default via 192.168.20.1 dev enp1s0\n"
  elif args[:2]==("ss","-lun"):P.stdout=""
  else:P.stdout=""
  return P()
 mod.call=command
 with __import__("unittest.mock").mock.patch.object(mod.os,"geteuid",lambda:0):
  uid=os.getuid()
  result=mod.activate(uid,"enp1s0",str(user_home))
  passed("activate arms monitored selective DNS",result["state"]=="ARMED")
  st=mod.read_state()
  passed("session state root marker created and ARMING",st["phase"]=="ARMING")
  passed("forwarder started",services[st["dnsUnit"]]=="active")
  passed("independent monitor started",services[st["monitorUnit"]]=="active")
  passed("independent repeating backstop timer started",
         services[st["backstopTimer"]]=="active")
  passed("dns points only to local loopback after monitor",live[0]["dns"]==["127.0.0.1:10535"])
  commit=mod.commit()
  passed("native engine state commits guarded DNS",commit["state"]=="ACTIVE" and mod.read_state()["phase"]=="ACTIVE")
  done=mod.rollback("MOCK_STOP")
  passed("stop restores baseline",done["state"]=="RESTORED" and live[0]==bas)
  passed("all owned systemd services and timer stopped",
         services[st["dnsUnit"]]=="inactive" and
         services[st["monitorUnit"]]=="inactive" and
         services[st["backstopTimer"]]=="inactive")
  passed("root state/config removed",not conf.exists() and not state_dir.exists())
  # Simulate failure only after the local DNS has been redirected. The
  # activation exception handler must restore baseline automatically.
  fail_google[0]=True
  try:mod.activate(uid,"enp1s0",str(user_home))
  except RuntimeError as e:
   passed("after-DNS failure is reported", "GOOGLE_FAILED_AFTER_DNS" in str(e))
  else:raise AssertionError("GOOGLE_OUTAGE_DID_NOT_FAIL")
  passed("activation rollback restored original DNS",live[0]==bas)
  passed("failed activation retained no root marker or config",not conf.exists() and not state_dir.exists())
  passed("failure stopped owned DNS and monitor units",
         all(v=="inactive" for v in services.values()))
print(f"PASS R247 full isolated lifecycle+failure {score}/{score}; NO host network or systemd mutations")
