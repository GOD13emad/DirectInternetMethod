from pathlib import Path
R=Path(__file__).resolve().parents[1]
W="FFB9A2AE19C2E89338EE12EE8DA133F5A16DBF4DCF961678C33D77D0C3843133"
L="4784FCD44ED3D1B40103BCA140B2C0066784F794D07C3AE1F525334766A553C7"
TAG="51009372e3c2d069d7016b97773f35ee5e1e0631"
def test(s,kind):
 if kind=="README":
  assert "Current public release: v1.5.4 Stable" in s[:280]
  assert W in s and L in s and "NOT YET PUBLIC" not in s[:850]
 elif kind=="NOTES":
  assert s.startswith("# v1.5.4 — published Stable") and "v1.5.3 — previous published Stable" in s
 elif kind=="DELIVERY":
  assert "Current application release: "+chr(96)+"v1.5.4"+chr(96) in s[:100]
 elif kind=="HISTORY":
  assert "Current public release: **v1.5.4 Stable**" in s[:300] and TAG in s[:380]
 elif kind=="AUTHORITY":
  assert s.startswith("# Current official Stable v1.5.4")
  assert all(x in s for x in (W,L,TAG,"ACCEPTANCE_V154.json","38466646243"))
 else:raise AssertionError("SCOPE")
def main():
 paths={"README":"README.md","NOTES":"RELEASE_NOTES.md","DELIVERY":"delivery/README.md","HISTORY":"PROJECT_BRAIN.md","AUTHORITY":"docs/PUBLISHED_V154_ASSET_AUTHORITY.md"}
 for scope,p in paths.items():
  s=(R/p).read_text(encoding="utf-8-sig")
  test(s,scope)
  try:test(s.replace("v1.5.4","v1.5.3",1),scope)
  except AssertionError:pass
  else:raise AssertionError(("FALSE_PASS_OLD_VERSION",scope))
 s=(R/paths["AUTHORITY"]).read_text(encoding="utf-8-sig")
 try:test(s.replace(W,"0"*64,1),"AUTHORITY")
 except AssertionError:pass
 else:raise AssertionError("FALSE_PASS_SHA")
 print("PASS_R497_CURRENT_PUBLIC_DOCS_154_POSITIVE_AND_NEGATIVE")
if __name__=="__main__":main()
