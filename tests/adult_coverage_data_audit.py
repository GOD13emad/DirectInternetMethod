#!/usr/bin/env python3
from pathlib import Path
import json,re,subprocess,sys,tempfile

R=Path(__file__).resolve().parents[1]
W=R/"windows"
L=R/"linux"

required={"xvideos.com","xvideos-cdn.com","xvcdn.com","xnxx.com","xnxx-cdn.com","xhamster.com","xhcdn.com","pornhub.com","phncdn.com","redtube.com","rdtcdn.com"}
wf=(W/"bin/zapret/adult-fallback-hosts.txt").read_text(encoding="utf-8-sig")
lf=(L/"app/adult_hosts_fallback.txt").read_text(encoding="utf-8")
wcore=(W/"bin/zapret/hosts.txt").read_text(encoding="utf-8-sig")
lcore=(L/"app/hosts.txt").read_text(encoding="utf-8")
wgui=(W/"gui/MainWindow.xaml.cs").read_text(encoding="utf-8-sig")
lui=(L/"app/direct_internet_method.py").read_text(encoding="utf-8")
helper=(L/"app/direct_method_helper.sh").read_text(encoding="utf-8")

def domains(text):
    return {x.strip().lower().lstrip("^") for x in text.splitlines()
            if x.strip() and not x.lstrip().startswith("#")}

checks={}
def check(name,ok):
    checks[name]=bool(ok)

check("fallback_required_families", required <= domains(wf) and required <= domains(lf))
check("fallback_cross_platform_same", domains(wf)==domains(lf))
check("core_adult_free", not (required & domains(wcore)) and not (required & domains(lcore)))
check("catalog_source_same", all(x in wgui.lower() and x in lui.lower() for x in (
    "raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt",
    "cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt"
)))
check("catalog_validation_bounds", all(x in wgui for x in ("100000","10000","4 * 1024 * 1024"))
      and all(x in lui for x in ("100000","10000","4*1024*1024")))
for u in ("https://www.pornhub.com/","https://www.xvideos.com/","https://www.xnxx.com/","https://xhamster.com/"):
    check("windows_probe_"+u.split("//",1)[1].split("/",1)[0],u in wgui)
    check("linux_probe_"+u.split("//",1)[1].split("/",1)[0],u in lui)

# Execute the exact embedded Linux hostlist merger from direct_method_helper.sh.
m=re.search(
    r'python3 - "\$HOSTS" "\$CUSTOM_HOSTS" "\$ADULT_FALLBACK" "\$ADULT_HOSTS" "\$ADULT_ON" "\$RUN_HOSTS" <<\'PY\'\n(.*?)\nPY',
    helper,re.S
)
check("embedded_merger_found",m is not None)
merge_result={}
if m:
    with tempfile.TemporaryDirectory() as td:
        d=Path(td)
        built=d/"built.txt"; custom=d/"custom.txt"; fallback=d/"fallback.txt"; adult=d/"adult.txt"; out=d/"out.txt"; code=d/"merge.py"
        built.write_text("^gemini.google.com\nopenai.com\n",encoding="utf-8")
        custom.write_text("reddit.com\nxvideos.com\n",encoding="utf-8")
        fallback.write_text(wf,encoding="utf-8")
        vals=["xvideos.com","xnxx.com","xhamster.com","pornhub.com","redtube.com"]
        vals += [f"d{i}.example-adult.invalid" for i in range(20000)]
        adult.write_text("\n".join(vals)+"\n",encoding="utf-8")
        code.write_text(m.group(1)+"\n",encoding="utf-8")
        p=subprocess.run([sys.executable,str(code),str(built),str(custom),str(fallback),str(adult),"1",str(out)],
                         text=True,capture_output=True,timeout=10)
        merged=out.read_text(encoding="utf-8").splitlines() if out.exists() else []
        merge_result={"exit":p.returncode,"stdout":p.stdout.strip(),"stderr":p.stderr.strip(),
                      "mergedCount":len(merged),"uniqueCount":len(set(merged))}
        check("embedded_merger_exit",p.returncode==0)
        check("embedded_merger_large_catalog",len(merged)>=20000 and len(merged)==len(set(merged)))
        check("embedded_merger_required_families",required <= {x.lstrip("^") for x in merged})
        check("embedded_merger_custom_dedupe",merged.count("xvideos.com")==1)
        check("embedded_merger_adult_count",p.stdout.strip().isdigit() and int(p.stdout.strip())>=20000)

status="PASS" if all(checks.values()) else "FAIL"
print(json.dumps({"schema":1,"status":status,"checks":checks,"merge":merge_result},indent=2))
raise SystemExit(0 if status=="PASS" else 20)
