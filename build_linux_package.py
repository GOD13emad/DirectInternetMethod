#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,pathlib,zipfile,tempfile,os
R=pathlib.Path(__file__).resolve().parent
OUT=R/"delivery"/"DirectInternetMethod_1.2.1_Linux_x86_64.zip"
ROOT="DirectInternetMethod_1.2.1_Linux_x86_64"
FILES=[
 ("README.md","README.md"),
 ("linux/install.sh","install.sh"),
 ("linux/uninstall.sh","uninstall.sh"),
 ("linux/system/install_system.sh","system/install_system.sh"),
 ("linux/system/control.sh","system/control.sh"),
 ("linux/system/uninstall_system.sh","system/uninstall_system.sh"),
 ("linux/app/direct_internet_method.py","app/direct_internet_method.py"),
 ("linux/app/direct_method_helper.sh","app/direct_method_helper.sh"),
 ("linux/app/hosts.txt","app/hosts.txt"),
 ("linux/app/direct-internet-method.svg","app/direct-internet-method.svg"),
 ("linux/runtime/ctrld","runtime/ctrld"),
 ("linux/runtime/nfqws","runtime/nfqws"),
 ("linux/licenses/LICENSE-ctrld.txt","licenses/LICENSE-ctrld.txt"),
 ("linux/licenses/LICENSE-zapret.txt","licenses/LICENSE-zapret.txt")
]
def sha_bytes(data:bytes)->str:return hashlib.sha256(data).hexdigest().upper()
def sha(p):return sha_bytes(pathlib.Path(p).read_bytes())
def payload_bytes(src:str,dst:str)->bytes:
 data=(R/src).read_bytes()
 if pathlib.PurePosixPath(dst).suffix.lower() in {".sh",".py",".md",".txt",".svg"}:
  data=data.replace(b"\r\n",b"\n").replace(b"\r",b"\n")
 return data
rows=[]
for src,dst in FILES:
 p=R/src
 if not p.is_file(): raise SystemExit("MISSING:"+src)
 data=payload_bytes(src,dst)
 rows.append({"file":dst,"bytes":len(data),"sha256":sha_bytes(data)})
manifest={"schema":1,"product":"Direct Internet Method","version":"1.2.1","platform":"linux-x86_64","files":rows}
OUT.parent.mkdir(parents=True,exist_ok=True)
fd,tmp_name=tempfile.mkstemp(prefix="dim-build-",suffix=".zip",dir=OUT.parent)
os.close(fd)
tmp=pathlib.Path(tmp_name)
try:
 with zipfile.ZipFile(tmp,"w",compression=zipfile.ZIP_STORED) as z:
  for src,dst in sorted(FILES,key=lambda x:x[1]):
   data=payload_bytes(src,dst)
   zi=zipfile.ZipInfo(f"{ROOT}/{dst}",date_time=(2026,9,29,0,0,0))
   zi.create_system=3
   zi.external_attr=((0o755 if dst.endswith((".sh",".py")) or dst in ("runtime/ctrld","runtime/nfqws") else 0o644)&0xFFFF)<<16
   zi.compress_type=zipfile.ZIP_STORED
   z.writestr(zi,data)
  for name,obj in [
   ("PACKAGE_MANIFEST.json",manifest),
   ("SHA256SUMS.txt","".join(f'{x["sha256"]}  {x["file"]}\n' for x in rows))
  ]:
   data=(json.dumps(obj,ensure_ascii=False,indent=2)+"\n").encode() if isinstance(obj,dict) else obj.encode()
   zi=zipfile.ZipInfo(f"{ROOT}/{name}",date_time=(2026,9,29,0,0,0))
   zi.create_system=3
   zi.external_attr=(0o644&0xFFFF)<<16;zi.compress_type=zipfile.ZIP_STORED
   z.writestr(zi,data)
 os.replace(tmp,OUT)
finally:
 if tmp.exists(): tmp.unlink()
print(json.dumps({"status":"PASS","path":str(OUT),"bytes":OUT.stat().st_size,"sha256":sha(OUT),"files":len(FILES)},indent=2))
