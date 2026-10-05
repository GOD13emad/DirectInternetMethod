#!/usr/bin/env python3
import concurrent.futures, hashlib, json, os, pathlib, shutil, subprocess, time

HOME=pathlib.Path.home()
APP=HOME/".local/share/DirectInternetMethod"
STATE=APP/"directmethod/state.json"
OUT=HOME/".cache/LINUX_150_INSTALLED_LIFECYCLE_20261005.json"
STRATEGY=APP/"strategy.txt"
SCOPE=APP/"scope.txt"
CUSTOM=APP/"custom-hosts.txt"

def run(args, timeout=130, check=False):
    p=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"CMD_FAIL {args}: rc={p.returncode} out={p.stdout[-1000:]} err={p.stderr[-1000:]}")
    return p

def unit(action):
    name=f"directinternetmethod-{action}.service"
    p=run(["systemctl","start",name],timeout=130)
    show=run(["systemctl","show",name,"-p","Result","-p","ExecMainStatus","--value"],timeout=10)
    vals=[x.strip() for x in show.stdout.splitlines() if x.strip()]
    if p.returncode or (vals and ("success" not in vals and "0" not in vals)):
        raise RuntimeError(f"UNIT_{action.upper()}_FAIL rc={p.returncode} show={vals} err={p.stderr[-800:]}")
    return {"unit":name,"startRc":p.returncode,"show":vals}

def snapshot():
    return {
      "defaultRoute":run(["ip","-4","route","show","default"],10).stdout.strip(),
      "dns":run(["resolvectl","dns"],10).stdout.strip(),
      "domains":run(["resolvectl","domain"],10).stdout.strip(),
      "defaultRouteDns":run(["resolvectl","default-route"],10).stdout.strip(),
      "stateExists":STATE.exists(),
      "ownedProcesses":run(["bash","-lc","pgrep -af '/usr/lib/directinternetmethod/runtime/usr/bin/(ctrld|nfqws)' || true"],10).stdout.strip(),
    }

def probe(name,url,allowed):
    t=time.monotonic()
    p=run(["curl","-4","-L","--noproxy","*","-A","Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/140 Safari/537.36",
           "-sS","-o","/dev/null","-w","%{http_code}|%{remote_ip}|%{time_total}","--connect-timeout","6","--max-time","12",url],15)
    raw=p.stdout.strip()
    parts=raw.split("|")
    code=parts[0] if parts else ""
    remote=parts[1] if len(parts)>1 else ""
    reached=p.returncode==0 and len(code)==3 and code!="000"
    status="PASS" if reached and code in allowed else ("REACHABLE" if reached else "FAIL")
    return {"name":name,"url":url,"status":status,"http":code,"remote":remote,"exit":p.returncode,"elapsedMs":round((time.monotonic()-t)*1000),"raw":raw,"stderr":p.stderr.strip()}

TARGETS=[
 ("YouTube","https://www.youtube.com/generate_204",{"200","204"}),
 ("OpenAI","https://api.openai.com/v1/models",{"200","401","403"}),
 ("GitHub","https://github.com/",{"200","301","302","303","307","308"}),
 ("Gemini","https://gemini.google.com/",{"200","301","302","303","307","308"}),
 ("Adult site","https://www.pornhub.com/",{"200","301","302","303","307","308"}),
 ("Reddit","https://www.reddit.com/",{"200","301","302","303","307","308"}),
 ("Wikipedia","https://www.wikipedia.org/",{"200","301","302","303","307","308"}),
 ("Cloudflare","https://www.cloudflare.com/",{"200","301","302","303","307","308"}),
]

def matrix(label):
    st=json.loads(STATE.read_text())
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(TARGETS)) as ex:
        fut=[ex.submit(probe,*x) for x in TARGETS]
        rows=[f.result() for f in fut]
    return {"cycle":label,"state":{"phase":st.get("phase"),"strategy":st.get("strategy"),"scope":st.get("scope"),"directMethods":st.get("directMethods")},"rows":rows}

backups={}
for p in (STRATEGY,SCOPE,CUSTOM):
    backups[str(p)]={"exists":p.exists(),"bytes":p.read_bytes().hex() if p.exists() else ""}

result={"schema":1,"date":"2026-10-05","project":"Direct Internet Method","version":"1.5.0","status":"RUNNING",
        "installed":{},"pre":None,"cycles":[],"recovery":None,"post":None,"rollbackEqual":False,"error":None}
try:
    install=json.loads((HOME/".local/share/DirectInternetMethod/INSTALL.json").read_text())
    backend=json.loads(pathlib.Path("/var/lib/directinternetmethod/install.json").read_text())
    result["installed"]={"appVersion":install.get("version"),"backendVersion":backend.get("version")}
    if install.get("version")!="1.5.0" or backend.get("version")!="1.5.0":
        raise RuntimeError("INSTALLED_VERSION_MISMATCH")
    unit("recovery")
    time.sleep(.5)
    result["pre"]=snapshot()

    cycles=[
      ("balanced-targeted-builtins","balanced","targeted",None),
      ("strong-targeted-custom-reddit","strong","targeted","reddit.com\n"),
      ("strong-all-sites","strong","all-sites",None),
    ]
    for label,strat,scope,custom in cycles:
        STRATEGY.write_text(strat+"\n")
        SCOPE.write_text(scope+"\n")
        if custom is None:
            CUSTOM.unlink(missing_ok=True)
        else:
            CUSTOM.write_text(custom)
        unit("start")
        if not STATE.exists(): raise RuntimeError("STATE_MISSING_AFTER_START")
        m=matrix(label)
        result["cycles"].append(m)
        by={x["name"]:x for x in m["rows"]}
        for core in ("YouTube","OpenAI","GitHub","Adult site"):
            if by[core]["status"]!="PASS":
                raise RuntimeError(f"{label}_{core}_NOT_PASS_{by[core]['status']}_{by[core]['http']}")
        unit("stop")
        if STATE.exists(): raise RuntimeError("STATE_REMAINS_AFTER_STOP")

    result["status"]="PASS_LIFECYCLE_SITE_MATRIX"
except Exception as e:
    result["status"]="FAIL"
    result["error"]=str(e)
finally:
    try:
        result["recovery"]=unit("recovery")
    except Exception as e:
        result["recovery"]={"error":str(e)}
        result["status"]="FAIL_RECOVERY"
    for p in (STRATEGY,SCOPE,CUSTOM):
        b=backups[str(p)]
        if b["exists"]:
            p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(bytes.fromhex(b["bytes"]))
        else:
            p.unlink(missing_ok=True)
    time.sleep(.5)
    result["post"]=snapshot()
    pre=result.get("pre") or {}
    post=result["post"]
    keys=("defaultRoute","dns","domains","defaultRouteDns")
    result["rollbackEqual"]=all(pre.get(k)==post.get(k) for k in keys) and not post["stateExists"] and not post["ownedProcesses"]
    if result["status"].startswith("PASS") and not result["rollbackEqual"]:
        result["status"]="FAIL_ROLLBACK"
    OUT.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
if not result["status"].startswith("PASS"):
    raise SystemExit(31)
