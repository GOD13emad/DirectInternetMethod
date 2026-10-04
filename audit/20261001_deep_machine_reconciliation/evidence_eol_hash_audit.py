from __future__ import annotations
import hashlib, json, pathlib, subprocess

ROOT=pathlib.Path(__file__).resolve().parents[2]
FINAL=pathlib.Path(r"C:\Users\Aa.Emad\source\repos\DirectInternetMethod_v140final")
expected={
"WINDOWS_140_HOST_FINAL_ACCEPTANCE_20261001.json":"4453FAE1733A84BA8900F3FB89467AEAC60E14C1DBEADF3065158522559047CB",
"LINUX_140_PUBLIC_INSTALLED_FINAL_ACCEPTANCE_20261001.json":"7D987E1838CA1BAE0F609F631972655C354F5AB8D09510C91DDAAB9D5F00A0E2",
"DIM_140_PUBLICATION_INSTALLED_FINAL_20261001.json":"09137E037CDD10C30140EDE1909F56D3029B68D8BBC811E620FE8B08BF9DBACA",
}
rows=[]
for n,want in expected.items():
    rel=pathlib.Path("evidence")/n
    cur=(ROOT/rel).read_bytes()
    fin=(FINAL/rel).read_bytes()
    tree=subprocess.check_output(["git","ls-tree","HEAD",rel.as_posix()],cwd=ROOT,text=True).strip().split()
    blob=tree[2] if len(tree)>=3 else ""
    same=subprocess.run(["git","diff","--quiet","main","audit/v1.4.0-finalize","--",rel.as_posix()],cwd=ROOT).returncode==0
    rows.append({
      "file":n,
      "currentWorktreeRawSha256":hashlib.sha256(cur).hexdigest().upper(),
      "finalizationWorktreeRawSha256":hashlib.sha256(fin).hexdigest().upper(),
      "brainHistoricalRawSha256":want,
      "finalizationRawMatchesBrain":hashlib.sha256(fin).hexdigest().upper()==want,
      "gitContentEqualMainVsFinalization":same,
      "gitBlobOid":blob,
      "classification":"WORKTREE_SERIALIZATION_VARIANCE" if same else "CONTENT_DRIFT"
    })
ok=all(x["finalizationRawMatchesBrain"] and x["gitContentEqualMainVsFinalization"] and x["gitBlobOid"] for x in rows)
payload={
 "schema":2,
 "date":"2026-10-01",
 "status":"CLASSIFIED_WORKTREE_SERIALIZATION_NOT_CONTENT_DRIFT" if ok else "FAIL_CONTENT_OR_PROVENANCE_MISMATCH",
 "decision":"Use Git blob/commit identity for tracked text; treat raw worktree SHA as serialization-specific unless EOL/bytes are explicitly pinned.",
 "rows":rows
}
out=ROOT/"audit"/"20261001_deep_machine_reconciliation"/"EVIDENCE_EOL_HASH_AUDIT.json"
out.write_text(json.dumps(payload,indent=2)+"\n",encoding="utf-8")
print(json.dumps(payload,indent=2))
