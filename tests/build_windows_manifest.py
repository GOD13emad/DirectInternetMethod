#!/usr/bin/env python3
import hashlib,json,pathlib
R=pathlib.Path(__file__).resolve().parent.parent
W=R/"windows"
FILES=[
("user","app/DirectInternetMethod.exe","app/DirectInternetMethod.exe"),
("user","app/DirectInternetMethod.ico","app/DirectInternetMethod.ico"),
("user","app/Status.ps1","app/Status.ps1"),
("user","../router_gateway/providers.json","app/router_gateway/providers.json"),
("user","docs/README-FA.md","docs/README-FA.md"),
("user","docs/ARCHITECTURE.md","docs/ARCHITECTURE.md"),
("user","RELEASE.json","RELEASE.json"),
("privileged","app/DirectInternetMethod.Service.exe","app/DirectInternetMethod.Service.exe"),
("privileged","app/Start-Direct.ps1","app/Start-Direct.ps1"),
("privileged","app/Stop-Direct.ps1","app/Stop-Direct.ps1"),
("privileged","app/Recovery.ps1","app/Recovery.ps1"),
("privileged","bin/ctrld/ctrld.exe","bin/ctrld/ctrld.exe"),
("privileged","bin/ctrld/ctrld.toml","bin/ctrld/ctrld.toml"),
("privileged","bin/ctrld/LICENSE.txt","bin/ctrld/LICENSE.txt"),
("privileged","bin/zapret/winws.exe","bin/zapret/winws.exe"),
("privileged","bin/zapret/WinDivert.dll","bin/zapret/WinDivert.dll"),
("privileged","bin/zapret/WinDivert64.sys","bin/zapret/WinDivert64.sys"),
("privileged","bin/zapret/cygwin1.dll","bin/zapret/cygwin1.dll"),
("privileged","bin/zapret/hosts.txt","bin/zapret/hosts.txt"),
("privileged","bin/zapret/adult-fallback-hosts.txt","bin/zapret/adult-fallback-hosts.txt"),
("privileged","bin/zapret/strong-override-hosts.txt","bin/zapret/strong-override-hosts.txt"),
("privileged","bin/zapret/LICENSE.txt","bin/zapret/LICENSE.txt"),
]
vendor=W/"vendor"/"pwsh"
if not vendor.is_dir(): raise SystemExit("MISSING:vendor/pwsh")
for p in sorted(x for x in vendor.rglob("*") if x.is_file()):
    rel=p.relative_to(W).as_posix()
    dst="runtime/pwsh/"+p.relative_to(vendor).as_posix()
    FILES.append(("privileged",rel,dst))
def h(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest().upper()
rows=[]
for scope,src,dst in FILES:
 p=W/src
 if not p.is_file(): raise SystemExit("MISSING:"+src)
 rows.append({"scope":scope,"file":dst,"source":src,"bytes":p.stat().st_size,"sha256":h(p)})
release=json.loads((W/"RELEASE.json").read_text(encoding="utf-8-sig"))
m={
 "schema":2,
 "product":"Direct Internet Method",
 "version":release["version"],
 "architecture":release["architecture"],
 "offlineRuntime":True,
 "normalRunRequiresAdmin":False,
 "installOrPrivilegedUpgradeRequiresAdmin":True,
 "directUpdate":{
   "transport":"GitHub latest release HTTPS",
   "privilegeModel":"DirectInternetMethodSvc performs download/verification/installer handoff",
   "userUacRequired":False,
   "integrity":"GitHub asset SHA-256 digest must equal SHA256SUMS.txt and downloaded installer SHA-256"
 },
 "bundledPowerShellVersion":"7.6.6",
 "bundledPowerShellArchiveSha256":"02FE458BE20493FBDF43F61EA20610B811EE6C738AB1676C61B9CFCD1A33C860",
 "files":rows
}
(W/"manifest.json").write_text(json.dumps(m,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
print(json.dumps({"status":"PASS","count":len(rows),"manifestSha256":h(W/"manifest.json")},indent=2))
