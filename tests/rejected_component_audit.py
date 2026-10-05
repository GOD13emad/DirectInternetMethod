from __future__ import annotations
import hashlib, json, pathlib, subprocess, sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
policy=json.loads((ROOT/"security"/"rejected_components.json").read_text(encoding="utf-8"))
blocked={x["sha256"].upper():x for x in policy.get("rejected",[]) if x.get("status") in {"REJECTED_SEVERE_DEFENDER","UNAPPROVED_DO_NOT_SHIP"}}
tracked=subprocess.check_output(["git","ls-files","-z"],cwd=ROOT).decode("utf-8","surrogateescape").split("\0")
hits=[]
checked=0
for rel in tracked:
    if not rel:
        continue
    p=ROOT/rel
    if not p.is_file() or p.suffix.lower() not in {".exe",".dll",".sys",".zip"}:
        continue
    checked+=1
    h=hashlib.sha256(p.read_bytes()).hexdigest().upper()
    if h in blocked:
        hits.append({"path":rel,"sha256":h,"policy":blocked[h]})
if hits:
    print(json.dumps({"status":"FAIL","checked":checked,"hits":hits},indent=2))
    raise SystemExit(31)
print(json.dumps({"status":"PASS","checked":checked,"blockedHashes":len(blocked)},indent=2))
