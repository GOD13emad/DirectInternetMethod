#!/usr/bin/env python3
"""R346 negative-first fail-closed Inno SCM lifecycle source regression contract.
Source-only verification; native Inno/R345 runtime acceptance is separate.
"""
from __future__ import annotations
import argparse,json,pathlib,re,sys,hashlib
def segment(s,begin,end):
 if s.count(begin)!=1 or s.count(end)!=1:return None
 i=s.find(begin);j=s.find(end,i+len(begin))
 return None if j<0 else s[i:j]
def audit(source:str):
 problems=[]
 def check(label,ok):
  if not ok:problems.append(label)
 definitions=(
 "DIM_SC_MANAGER_CONNECT = $0001;",
 "DIM_SERVICE_QUERY_STATUS = $0004;",
 "DIM_SERVICE_STOPPED = 1;",
 "DIM_SERVICE_STOP_PENDING = 3;",
 "OpenSCManagerW@advapi32.dll stdcall",
 "OpenServiceW@advapi32.dll stdcall",
 "QueryServiceStatus@advapi32.dll stdcall",
 "CloseServiceHandle@advapi32.dll stdcall",
 )
 check("native_SCM_API_declarations",all(x in source for x in definitions))
 a=segment(source,"function DIMReadServiceState(const Target: String): DWORD;","procedure DIMStopServiceAndWait(const Target: String);")
 b=segment(source,"procedure DIMStopServiceAndWait(const Target: String);","function ServiceExists(): Boolean;")
 c=segment(source,"procedure StopCtrldServiceIfOwned();","procedure InstallOrUpdateCtrldService();")
 d=segment(source,"procedure StopServiceIfPresent();","procedure InstallOrUpdateService();")
 check("native_query_function_unique",a is not None)
 check("stop_wait_function_unique",b is not None)
 check("ctrld_stop_wrapper_unique",c is not None)
 check("main_stop_wrapper_unique",d is not None)
 if a:
  check("native_query_preserves_handles",all(x in a for x in ("DIMOpenSCManager('', '', DIM_SC_MANAGER_CONNECT)","DIMOpenService(Manager, Target, DIM_SERVICE_QUERY_STATUS)","DIMQueryServiceStatus(Service, Status)","Result := Status.dwCurrentState","DIMCloseServiceHandle(Service)","DIMCloseServiceHandle(Manager)","finally","RaiseException(")))
 if b:
  check("stop_checks_native_state_before_control",b.find("State := DIMReadServiceState(Target)")>=0 and b.find("State := DIMReadServiceState(Target)")<b.find("RunSc('stop"))
  check("stop_idempotent_return",bool(re.search(r"if State = DIM_SERVICE_STOPPED then\s+exit;",b)))
  check("stop_pending_fallback", "if State <> DIM_SERVICE_STOP_PENDING then" in b)
  check("stop_requests_checked", "RunSc('stop \"' + Target + '\"', ResultCode)" in b and "ResultCode <> 0" in b and "ResultCode <> 1062" in b)
  check("stop_wait_bounded_poll", all(x in b for x in ("for Attempt := 1 to 120 do","DIMReadServiceState(Target) = DIM_SERVICE_STOPPED","Sleep(250);")))
  check("stop_timeout_failure_propagation","did not reach STOPPED in 30 seconds" in b and "RaiseException(" in b)
 if c:
  check("ctrld_ownership_guard","if CtrldServiceExists() and CtrldServiceOwned() then" in c)
  check("ctrld_uses_native_wait","DIMStopServiceAndWait(CtrldServiceName);" in c and "RunSc('stop" not in c)
 if d:
  check("main_service_exists_guard","if ServiceExists() then" in d)
  check("main_uses_native_wait","DIMStopServiceAndWait(ServiceName);" in d and "RunSc('stop" not in d)
 check("preinstall_guard_preserved","function PrepareToInstall(var NeedsRestart: Boolean): String;" in source and "StopCtrldServiceIfOwned();" in source and "StopServiceIfPresent();" in source)
 check("uninstall_guard_preserved","function InitializeUninstall(): Boolean;" in source and "Direct Method is active" in source and "StopCtrldServiceIfOwned();" in source)
 return problems
def run():
 p=argparse.ArgumentParser()
 p.add_argument("--iss",default=None)
 p.add_argument("--negative-only",action="store_true")
 args=p.parse_args()
 f=pathlib.Path(args.iss) if args.iss else pathlib.Path(__file__).resolve().parents[1]/"windows"/"installer"/"DirectInternetMethod.iss"
 if not f.is_file(): raise RuntimeError("SOURCE_FILE_MISSING:"+str(f))
 data=f.read_bytes()
 if data.startswith(b"\xef\xbb\xbf"):data=data[3:]
 source=data.decode("utf8")
 problems=audit(source)
 # Every negative fixture must be rejected even if a native query token remains elsewhere.
 fixtures={
  "no_native_declaration":source.replace("QueryServiceStatus@advapi32.dll stdcall","QueryServiceStatuz@advapi32.dll stdcall",1),
  "no_service_read":source.replace("State := DIMReadServiceState(Target);","State := DIM_SERVICE_STOPPED;",1),
  "no_idempotence":source.replace("if State = DIM_SERVICE_STOPPED then","if State = DIM_SERVICE_STOP_PENDING then",1),
  "skip_stop_result_check":source.replace("ResultCode <> 1062","ResultCode <> 1",1),
  "skip_timeout":source.replace("did not reach STOPPED in 30 seconds","did not reach STOPPED",1),
  "remove_bounded_loop":source.replace("for Attempt := 1 to 120 do","for Attempt := 1 to 999999 do",1),
  "detach_ctrld_stop":source.replace("DIMStopServiceAndWait(CtrldServiceName);","RunSc('stop \"' + CtrldServiceName + '\"', ResultCode);",1),
  "detach_main_stop":source.replace("DIMStopServiceAndWait(ServiceName);","RunSc('stop \"' + ServiceName + '\"', ResultCode);",1),
 }
 negative={}
 for label,bad in fixtures.items():
  if bad==source:
   negative[label]={"rejected":False,"why":"EXPECTED_SOURCE_ANCHOR_MISSING"}
  else:
   negative[label]={"rejected":bool(audit(bad))}
 negativePassed=all(item["rejected"] for item in negative.values())
 verdict="PASS" if not problems and negativePassed else "FAIL"
 obj={"schema":1,"test":"WINDOWS_NATIVE_SCM_STOP_CONTRACT_R346","status":verdict,
 "sourceSha256":hashlib.sha256(f.read_bytes()).hexdigest().upper(),
 "sourcePath":str(f),"checksFailed":problems,"negativeFixtures":negative,
 "nativeRuntimeAcceptance":"R345 separate and restricted to SCM query/stopped/no-op; real live service stop UNPROVEN",
 "unprivilegedUAC":"UNPROVEN","SAC":"UNPROVEN"}
 print(json.dumps(obj,indent=2))
 return 0 if verdict=="PASS" else 30
if __name__=="__main__":
 try:sys.exit(run())
 except Exception as ex:
  print("NATIVE_SCM_CONTRACT_FAIL_CLOSED:"+repr(ex),file=sys.stderr)
  sys.exit(91)
