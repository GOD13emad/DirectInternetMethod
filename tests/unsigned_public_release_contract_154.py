#!/usr/bin/env python3
"""Direct Internet Method v1.5.4 exact-public native release gate.

--fixtures: hermetic positive/negative fixtures with no network or OS mutation.
--public-tag: disposable GitHub-hosted exact-tag CI only. Download official assets
and immutable hosted evidence; do not run installers or modify OS policy.
"""
from __future__ import annotations
import argparse,copy,datetime,hashlib,json,os,pathlib,re,subprocess,sys,tempfile,zipfile

REPO="GOD13emad/DirectInternetMethod"
TAG="v1.5.4"
VERSION="1.5.4"
PRODUCT="daf1a939c97f38d4ecec1f8144dd754a2d392c99"
SOURCE_CI=38460897907
RELEASE_ID=412071526
WIN="DirectInternetMethod_1.5.4_Windows_Setup.exe"
LINUX="DirectInternetMethod_1.5.4_Linux_x86_64.zip"
SUMS="SHA256SUMS.txt"
PROOF="ACCEPTANCE_V154.json"
EXPECTED={
WIN:("FFB9A2AE19C2E89338EE12EE8DA133F5A16DBF4DCF961678C33D77D0C3843133",154270907),
LINUX:("4784FCD44ED3D1B40103BCA140B2C0066784F794D07C3AE1F525334766A553C7",8270220),
SUMS:("68E70329E8B9DAC6B738CE9B90D99A0010030980CD9C17CDE45A5199A60692D8",221),
"cygwin-3.4.10-1-src.tar.xz":("AC70AF0D4E644732F74946F55F7BAFE010BAB9B9DA39A9327C3F0367F1FA43A2",8964220),
"WinDivert-v2.2.2-corresponding-source.zip":("65EC79C9E6AFA99F648A3F4D1F6DB794640B40D0B65BD438770EA503EE14ECB7",199555)
}
RUNS={
"windows151":{
 "runId":38461987721,"workflowCommit":"fcd9eed2e780ae8e3288645fef21329c4e88dc07",
 "artifactName":"dim-r488-hosted-legacy-38461987721",
 "reportPath":"_temp/DIM_R488_HOSTED/REPORT_R488.json",
 "reportSha256":"1F4D892157C8F79D8B156F52FBF17EC92E3CFE212C219F03C2A71B4682659D0E"},
"windows153":{
 "runId":38463483175,"workflowCommit":"eca472a7478b76585d23f386d7a257fee959cf26",
 "artifactName":"dim-r490-hosted-legacy-38463483175",
 "reportPath":"DIM_R490_HOSTED/REPORT_R490.json",
 "reportSha256":"C71BCFF174A45B49FD12A85DA9FF2D387B2870F08E1FA63D20EEAD4284DEF5AC"},
"linuxUpgrade":{
 "runId":38462619198,"workflowCommit":"ff9488c3fbdbb09c1ed97e616497f669bd1c0f70",
 "artifactName":"dim-r489-protected-guest-38462619198",
 "reportPath":"REPORT_R489.log",
 "reportSha256":"D15CFC438920B7AFDD22FADCD996B111BC3CE98313DC581D2D7DBDE833C1EF7F"},
"linuxFresh":{
 "runId":38463710954,"workflowCommit":"76287289aabeae459105ab46f40d113fba3b9b0a",
 "artifactName":"dim-r491-protected-guest-38463710954",
 "reportPath":"REPORT_R491.log",
 "reportSha256":"51783E1BA625ED6E371D80A0572C051F3F9F20222D3651025B684D071D84EC7D"}
}
SHA40=re.compile(r"^[a-f0-9]{40}$")
SHA64=re.compile(r"^[A-F0-9]{64}$")
LINUX_MARKERS={
"linuxUpgrade":[
 "R489_PUBLIC_V153_ROOT_USER_ACTUAL_INSTALL_PASS",
 "R489_REAL_INSTALLED_V154_STAGED_ROLLBACK_PASS",
 "Protected backend already matches current package; keeping root-owned code unchanged.",
 "Updated Direct Internet Method 1.5.4 in place; user data preserved.",
 "R489_GENUINE_V153_TO_V154_INPLACE_ROOT_UNCHANGED_DATA_PRESERVED",
 "R489_ROOT_USER_NATIVE_UNINSTALL_PRESERVES_DATA",
 "RESULT_CODE=0"],
"linuxFresh":[
 "PASS_R491_REAL_EXTRACTED_ZIP_6_OF_6",
 "PASS_R491_PROTECTED_BACKEND_EXACT_SOURCE_BYTES",
 "PASS_R491_TRUE_ROOT_AND_USER_INSTALL_CUSTOM_DATA_PRESERVED",
 "PASS_R491_REAL_HOSTED_ROOT_USER_NATIVE_INSTALL_UNINSTALL_NO_DUPLICATES",
 "R491_GUEST_SYSTEM_BACKEND_REMOVED",
 "RESULT_CODE=0"]
}
WIN_BOOL=[
 "installerNotSigned","testInstalledUnderGithubHostedOnly","noReboot",
 "watchdogDisarmed","baselineGuiHashPass","baselineServiceHashPass",
 "upgradedGuiHashPass","upgradedServiceHashPass","serviceCreated","serviceRunning",
 "installedGuiHashPass","installedServiceHashPass","installedManifestHashPass",
 "uninstallServiceAbsent","uninstallCtrldAbsent","removedInstalledFiles",
 "networkRestoredExact","userDataSeeded","userDataAfterUpgrade",
 "userDataAfterUninstall","userDataAfterRestore","updaterPendingCleared",
 "oneUninstallerRecorded","customProviderAfterUpgrade","customProviderAfterUninstall",
 "customProviderAfterRestore","legacyProviderRestoreConfirmed"
]
def must(ok,name):
 if not ok:raise RuntimeError("V154_FAIL_CLOSED_"+name)
def digest(data):return hashlib.sha256(data).hexdigest().upper()
def sha_file(p):
 h=hashlib.sha256()
 with pathlib.Path(p).open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest().upper()
def command(*args,timeout=180):
 p=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
 must(p.returncode==0,"COMMAND_"+str(args[0])+":"+p.stderr[-130:])
 return p.stdout.strip()
def api(endpoint):
 return json.loads(command("gh","api",endpoint,timeout=35))
def acceptance_gate(meta):
 must(isinstance(meta,dict),"ACCEPTANCE_NOT_OBJECT")
 for key,v in {"schema":1,"version":VERSION,"tag":TAG,"productCommit":PRODUCT,
               "sourceCiRunId":SOURCE_CI,"status":"PASS_EXACT_NATIVE_FOUR_HOSTED_V154"}.items():
  must(meta.get(key)==v,"ACCEPTANCE_FIELD_"+key)
 must(isinstance(meta.get("tagCommit"),str) and SHA40.fullmatch(meta["tagCommit"]) is not None,
      "ACCEPTANCE_TAG_SHA")
 must(meta.get("windowsSha256")==EXPECTED[WIN][0] and
      meta.get("linuxSha256")==EXPECTED[LINUX][0] and
      meta.get("sumsSha256")==EXPECTED[SUMS][0],"ACCEPTANCE_ASSET_ID")
 for k,expected in RUNS.items():
  r=meta.get(k)
  must(isinstance(r,dict),"ACCEPTANCE_MISSING_RUN_"+k)
  must(all(r.get(field)==value for field,value in expected.items()),
       "ACCEPTANCE_RUN_IDENTITY_"+k)
def report_gate(key,blob):
 must(key in RUNS and isinstance(blob,bytes),"REPORT_INPUT")
 if key.startswith("windows"):
  try:r=json.loads(blob.decode("utf-8-sig"))
  except Exception as exc:raise RuntimeError("V154_FAIL_CLOSED_WINDOWS_JSON") from exc
  expected="PASS_NET10_151_TO_154_NATIVE_AND_ORIGINAL151_ROLLBACK" if key=="windows151" else "PASS_EXACT_SHA_153_TO_154_FIVE_USER_FILES_AND_PROVIDER_PRESERVED"
  must(r.get("status")==expected,"WINDOWS_STATUS_"+key)
  identity=RUNS[key]
  must(str(r.get("runID"))==str(identity["runId"]) and
       r.get("CIcommit")==identity["workflowCommit"] and
       r.get("candidateCommit")==PRODUCT and
       str(r.get("installerSha256","")).upper()==EXPECTED[WIN][0],
       "WINDOWS_SOURCE_RUN_ASSET_"+key)
  must(r.get("errors")==[] and r.get("securityPolicyChanged") is False and
       r.get("userMachinesModified") is False and r.get("directEngineStateDuringInstall") is False,
       "WINDOWS_ERRORS_OR_SECURITY_CHANGE_"+key)
  for field in WIN_BOOL:
   must(r.get(field) is True,"WINDOWS_FALSE_GATE_"+key+"_"+field)
  rollback="restored151OriginalHashes" if key=="windows151" else "restored153OriginalHashes"
  must(r.get(rollback) is True,"WINDOWS_ROLLBACK_"+key)
  if key=="windows151":must(r.get("guiWindowObserved") is True,"WINDOWS_WPF_WINDOW_NOT_SHOWN")
  for field in ("upgradeExit","uninstallExit","rollbackRestoreExit"):
   must(r.get(field)==0,"WINDOWS_NATIVE_EXIT_"+key+"_"+field)
 else:
  try:text=blob.decode("utf-8")
  except UnicodeError as exc:raise RuntimeError("V154_FAIL_CLOSED_LINUX_UTF8") from exc
  for marker in LINUX_MARKERS[key]:
   must(marker in text,"LINUX_MISSING_MARKER_"+key+"_"+marker[:36])
def sums_gate(raw):
 must(digest(raw)==EXPECTED[SUMS][0],"SUMS_DIGEST")
 try:text=raw.decode("ascii")
 except UnicodeError as exc:raise RuntimeError("V154_FAIL_CLOSED_SUMS_ASCII") from exc
 lines=[x for x in text.splitlines() if x]
 must(len(lines)==2,"SUMS_EXACT_TWO_ROWS")
 for file in (WIN,LINUX):
  must(EXPECTED[file][0]+"  "+file in lines,"SUMS_ASSET_MISSING_"+file)
def fixtures():
 meta={"schema":1,"status":"PASS_EXACT_NATIVE_FOUR_HOSTED_V154",
       "version":VERSION,"tag":TAG,"productCommit":PRODUCT,"tagCommit":"a"*40,
       "windowsSha256":EXPECTED[WIN][0],"linuxSha256":EXPECTED[LINUX][0],
       "sumsSha256":EXPECTED[SUMS][0],"sourceCiRunId":SOURCE_CI}
 meta.update({k:dict(v) for k,v in RUNS.items()})
 acceptance_gate(meta)
 negatives=[
  ("wrong_version",lambda x:x.__setitem__("version","1.5.3")),
  ("wrong_source",lambda x:x.__setitem__("productCommit","0"*40)),
  ("bad_tag_sha",lambda x:x.__setitem__("tagCommit","bad")),
  ("wrong_windows",lambda x:x.__setitem__("windowsSha256","0"*64)),
  ("wrong_linux",lambda x:x.__setitem__("linuxSha256","0"*64)),
  ("wrong_ci",lambda x:x.__setitem__("sourceCiRunId",1)),
  ("missing_hosted",lambda x:x.pop("linuxFresh")),
  ("wrong_run",lambda x:x["windows153"].__setitem__("runId",1)),
  ("wrong_report",lambda x:x["linuxUpgrade"].__setitem__("reportSha256","0"*64)),
 ]
 for name,fn in negatives:
  corrupt=copy.deepcopy(meta);fn(corrupt)
  try:acceptance_gate(corrupt)
  except RuntimeError:pass
  else:raise RuntimeError("V154_FALSE_POSITIVE_ACCEPTANCE_"+name)
 for key in ("windows151","windows153"):
  fixture={"status":"PASS_NET10_151_TO_154_NATIVE_AND_ORIGINAL151_ROLLBACK" if key=="windows151" else "PASS_EXACT_SHA_153_TO_154_FIVE_USER_FILES_AND_PROVIDER_PRESERVED",
           "runID":str(RUNS[key]["runId"]),"CIcommit":RUNS[key]["workflowCommit"],
           "candidateCommit":PRODUCT,"installerSha256":EXPECTED[WIN][0],
           "errors":[],"securityPolicyChanged":False,"userMachinesModified":False,
           "directEngineStateDuringInstall":False,
           "upgradeExit":0,"uninstallExit":0,"rollbackRestoreExit":0}
  fixture.update({name:True for name in WIN_BOOL})
  fixture["restored151OriginalHashes" if key=="windows151" else "restored153OriginalHashes"]=True
  if key=="windows151":fixture["guiWindowObserved"]=True
  report_gate(key,json.dumps(fixture).encode())
  for field in ("oneUninstallerRecorded","networkRestoredExact","updaterPendingCleared"):
   alt=dict(fixture);alt[field]=False
   try:report_gate(key,json.dumps(alt).encode())
   except RuntimeError:pass
   else:raise RuntimeError("V154_FALSE_POSITIVE_WINDOWS_"+key+field)
 for key,markers in LINUX_MARKERS.items():
  content=("\n".join(markers)+"\n").encode()
  report_gate(key,content)
  for required in (markers[-1],markers[-2],markers[0]):
   broken=content.decode().replace(required,"").encode()
   try:report_gate(key,broken)
   except RuntimeError:pass
   else:raise RuntimeError("V154_FALSE_POSITIVE_LINUX_"+key+required[:22])
 print("PASS_V154_RELEASE_VERIFIER_POSITIVE_AND_NEGATIVE_FIXTURES")
def all_blob_shas(commit):
 t=api("repos/"+REPO+"/git/commits/"+commit).get("tree",{}).get("sha","")
 must(SHA40.fullmatch(t) is not None,"GIT_COMMIT_TREE_INVALID")
 j=api("repos/"+REPO+"/git/trees/"+t+"?recursive=1")
 must(j.get("truncated") is False,"GIT_TREE_TRUNCATED")
 return {x["path"]:(x["sha"],x["mode"]) for x in j["tree"] if x.get("type")=="blob"}
def zip_gate(archive):
 with zipfile.ZipFile(archive,"r") as z:
  must(z.testzip() is None,"LINUX_ZIP_CRC")
  names=z.namelist()
  must(len(names)==24 and len(set(names))==24,"LINUX_ARCHIVE_FILE_COUNT")
  prefix="DirectInternetMethod_1.5.4_Linux_x86_64/"
  must(all(n.startswith(prefix) and ".." not in pathlib.PurePosixPath(n).parts for n in names),"LINUX_ZIP_PATH")
  doc=json.loads(z.read(prefix+"PACKAGE_MANIFEST.json"))
  must(doc.get("schema")==1 and doc.get("product")=="Direct Internet Method" and
       doc.get("version")==VERSION and len(doc.get("files",[]))==22,"LINUX_ZIP_MANIFEST")
  seen=set()
  for e in doc["files"]:
   file=e["file"]
   must(isinstance(file,str) and file not in seen and ".." not in pathlib.PurePosixPath(file).parts,
        "LINUX_MANIFEST_DUPLICATE_UNSAFE")
   seen.add(file)
   payload=z.read(prefix+file)
   must(len(payload)==e["bytes"] and digest(payload)==e["sha256"].upper(),"LINUX_MANIFEST_SHA_"+file)
def public_tag():
 must(os.environ.get("GITHUB_ACTIONS")=="true" and
      os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted" and
      os.environ.get("RUNNER_OS")=="Windows" and
      os.environ.get("GITHUB_REPOSITORY")==REPO and
      os.environ.get("GITHUB_REF")=="refs/tags/"+TAG,"NOT_HOSTED_EXACT_PUBLIC_TAG")
 tagsha=os.environ.get("GITHUB_SHA","")
 must(SHA40.fullmatch(tagsha) is not None and command("git","rev-parse","HEAD")==tagsha,"PUBLIC_TAG_CHECKOUT_SHA")
 release=api("repos/"+REPO+"/releases/tags/"+TAG)
 latest=api("repos/"+REPO+"/releases/latest")
 must(release.get("id")==RELEASE_ID and latest.get("id")==RELEASE_ID and
      release.get("draft") is False and release.get("prerelease") is False and
      release.get("target_commitish")==tagsha,"PUBLISHED_LATEST_SOURCE_AUTHORITY")
 expected_names=set(EXPECTED)|{PROOF}
 assets={a["name"]:a for a in release.get("assets",[])}
 must(set(assets)==expected_names and len(release["assets"])==6,"PUBLIC_EXACT_SIX_ASSET_SET")
 for name,(hashvalue,size) in EXPECTED.items():
  a=assets[name]
  must(a.get("state")=="uploaded" and a.get("size")==size and
       a.get("digest","").lower()=="sha256:"+hashvalue.lower(),"PUBLIC_DIGEST_"+name)
 a=assets[PROOF]
 must(a.get("state")=="uploaded" and
      re.fullmatch(r"sha256:[a-f0-9]{64}",a.get("digest","")) is not None and
      1000<=a.get("size",0)<=20000,"ACCEPTANCE_DIGEST_METADATA")
 aTree=all_blob_shas(PRODUCT);bTree=all_blob_shas(tagsha)
 changes=sorted(k for k in set(aTree)|set(bTree) if aTree.get(k)!=bTree.get(k))
 must(changes==[".github/workflows/ci.yml","tests/unsigned_public_release_contract_154.py"],
      "UNTESTED_PRODUCT_SOURCE_MUTATION:"+",".join(changes))
 source_run=api("repos/"+REPO+"/actions/runs/"+str(SOURCE_CI))
 must(source_run.get("head_sha")==PRODUCT and source_run.get("status")=="completed" and
      source_run.get("conclusion")=="success","PRODUCT_SOURCE_CI_NOT_PASS")
 output=pathlib.Path(os.environ["RUNNER_TEMP"])/"DIM_R492_PUBLIC_TAG"
 must(not output.exists(),"PUBLIC_RECEIPT_REENTRY")
 output.mkdir(mode=0o700)
 try:
  for name in expected_names:
   command("gh","release","download",TAG,"--repo",REPO,"--pattern",name,
           "--dir",str(output),timeout=260)
   p=output/name
   must(p.is_file() and not p.is_symlink(),"MISSING_DOWNLOADED_"+name)
   expected=EXPECTED.get(name)
   if expected:
    must(p.stat().st_size==expected[1] and sha_file(p)==expected[0],"PUBLIC_ASSET_BYTES_"+name)
   else:
    must(p.stat().st_size==a["size"] and
         sha_file(p).lower()=="".join(a["digest"].split(":")[1:]),"ACCEPTANCE_RAW_SHA")
  sums_gate((output/SUMS).read_bytes())
  zip_gate(output/LINUX)
  proof=json.loads((output/PROOF).read_text("utf-8"))
  acceptance_gate(proof)
  must(proof["tagCommit"]==tagsha,"PUBLISHED_PROOF_TAG_SHA")
  for key,rec in RUNS.items():
   run=api("repos/"+REPO+"/actions/runs/"+str(rec["runId"]))
   must(run.get("status")=="completed" and run.get("conclusion")=="success" and
        run.get("head_sha")==rec["workflowCommit"],"HOSTED_RUN_NOT_ACCEPTED_"+key)
   dest=output/("REPORT_"+key)
   must(not dest.exists(),"HOSTED_RECEIPT_COLLISION")
   dest.mkdir()
   command("gh","run","download",str(rec["runId"]),"--repo",REPO,
           "--name",rec["artifactName"],"--dir",str(dest),timeout=240)
   path=dest/rec["reportPath"]
   must(path.is_file() and sha_file(path)==rec["reportSha256"],"HOSTED_RAW_SHA_"+key)
   report_gate(key,path.read_bytes())
  result={"schema":1,"status":"PASS_V154_PUBLIC_EXACT_SIX_ASSETS_FOUR_HOSTED_NATIVE",
          "tag":TAG,"tagCommit":tagsha,"productCommit":PRODUCT,
          "assetSHA":{key:sha_file(output/key) for key in expected_names},
          "sourceCI":SOURCE_CI,"nativeRuns":[x["runId"] for x in RUNS.values()],
          "gitTreeDiffExceptions":changes,
          "utc":datetime.datetime.now(datetime.timezone.utc).isoformat()}
  resultpath=output/"PUBLIC_TAG_R492_RESULT.json"
  resultpath.write_text(json.dumps(result,indent=2)+"\n","utf-8")
  print("PASS_R492_EXACT_PUBLIC_V154_NATIVE_PROVENANCE:"+json.dumps(result,sort_keys=True))
 finally:
  pass
def main():
 p=argparse.ArgumentParser()
 g=p.add_mutually_exclusive_group(required=True)
 g.add_argument("--fixtures",action="store_true")
 g.add_argument("--public-tag",action="store_true")
 a=p.parse_args()
 if a.fixtures:fixtures()
 else:public_tag()
if __name__=="__main__":
 try:main()
 except Exception as e:
  print("FAIL_CLOSED_R492_V154_PUBLIC:"+repr(e),file=sys.stderr)
  raise SystemExit(1)
