#!/usr/bin/env python3
"""Direct Internet Method v1.5.3 independent public-release tag verifier.
--fixtures runs locally without network; --public-tag runs only in hosted GitHub tag CI.
No installer execution, installed-host mutation, Windows signing mandate, or security bypass.
"""
from __future__ import annotations
import argparse,datetime,hashlib,json,os,pathlib,re,subprocess,sys,tempfile,zipfile

REPO="GOD13emad/DirectInternetMethod"
VERSION="1.5.3"
TAG="v"+VERSION
PRODUCT_SHA="eb6a7bf9a7c6a04cef5a85100e805d0575ef9c9a"
WIN="DirectInternetMethod_1.5.3_Windows_Setup.exe"
LINUX="DirectInternetMethod_1.5.3_Linux_x86_64.zip"
SUMS="SHA256SUMS.txt"
PROOF="ACCEPTANCE_V153.json"
CYGWIN="cygwin-3.4.10-1-src.tar.xz"
WINDIVERT="WinDivert-v2.2.2-corresponding-source.zip"
EXPECTED={
 WIN:("B517EA79C8949E960897CE814591F7C1518FDEA45E4419A891B64469E879B6FF",157138440),
 LINUX:("680343F86ABEC2D7B69CE807F4EC5B344789B2D6335C51C068BC49F4650DFC05",8274083),
 SUMS:("98B9AB15EA2894396CC8336BC0871C40388799E8EB211C6BA92437E28DB29331",221),
 CYGWIN:("AC70AF0D4E644732F74946F55F7BAFE010BAB9B9DA39A9327C3F0367F1FA43A2",8964220),
 WINDIVERT:("65EC79C9E6AFA99F648A3F4D1F6DB794640B40D0B65BD438770EA503EE14ECB7",199555)
}
RECEIPTS={
 "windowsUpgradeRollback":{"runId":38389324841,"workflowCommit":"578cc0340939450b66971de69432114f871ac6e9",
  "artifactName":"dim-r470-hosted-legacy-38389324841","reportPath":"DIM_R470_HOSTED/REPORT_R470.json",
  "reportSha256":"182295EC19BA872F5A9B35D72641A862F9EDF254361214049C8937CDDFB293F8"},
 "linuxFreshRootUser":{"runId":38388513538,"workflowCommit":"bdd7e89b83e94c2d044c53da61becfcfbfe12111",
  "artifactName":"dim-r469-protected-guest-38388513538","reportPath":"REPORT_R469.log",
  "reportSha256":"59ACF3DA53D549D1F898257C6E5B7AC094C5BBB9A0AAAD6185A427ED7793752F"},
 "linuxInPlaceUpgrade":{"runId":38390031680,"workflowCommit":"99d6137fadd60483b5c8b4c8ccfb384a40fe0ece",
  "artifactName":"dim-r471-protected-guest-38390031680","reportPath":"REPORT_R471.log",
  "reportSha256":"39282E4F2ECBBB563B5309AB668846FB464954B0419284EE8C6D403065857DCE"}
}
HEX=re.compile(r"^[A-Fa-f0-9]{64}$")
SHA=re.compile(r"^[a-f0-9]{40}$")
ALLOWED_SOURCE_ONLY={".github/workflows/ci.yml","tests/unsigned_public_release_contract_153.py"}

def must(ok,message):
 if not ok:raise RuntimeError(message)
def digest(b):return hashlib.sha256(b).hexdigest().upper()
def file_sha(path):
 h=hashlib.sha256()
 with open(path,"rb") as f:
  for chunk in iter(lambda:f.read(1048576),b""):h.update(chunk)
 return h.hexdigest().upper()
def cmd(*args,timeout=150):
 r=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
 must(r.returncode==0,"COMMAND_FAILED:"+str(args[:3])+":"+r.stderr[-350:])
 return r.stdout.strip()
def gh_api(endpoint):return json.loads(cmd("gh","api",endpoint,timeout=30))
def receipt_gate(meta):
 must(isinstance(meta,dict) and meta.get("schema")==1,"ACCEPTANCE_SCHEMA")
 must(meta.get("version")==VERSION and meta.get("tag")==TAG,"ACCEPTANCE_VERSION_TAG")
 must(meta.get("productCommit")==PRODUCT_SHA,"PRODUCT_SOURCE_NOT_TESTED")
 must(isinstance(meta.get("tagCommit"),str) and SHA.fullmatch(meta["tagCommit"]), "TAG_SHA_INVALID")
 must(meta.get("onePublicDistributionLine") is True and
      meta.get("signingCertificateRequired") is False and
      meta.get("disableWindowsSecurity") is False and
      meta.get("unsignedWindowsInstaller") is True,"UNSIGNED_PUBLISHER_POLICY")
 must(meta.get("windowsSha256")==EXPECTED[WIN][0] and
      meta.get("linuxSha256")==EXPECTED[LINUX][0],"ACCEPTANCE_PRODUCT_HASH")
 must(meta.get("sourceCiRunId")==38385602156,"PRODUCT_SOURCE_CI_ID")
 for key,known in RECEIPTS.items():
  r=meta.get(key)
  must(isinstance(r,dict),"ACCEPTANCE_MISSING_HOSTED:"+key)
  must(all(r.get(k)==v for k,v in known.items()),"ACCEPTANCE_HOSTED_IDENTITY_MISMATCH:"+key)
 return True
def sums_gate(data):
 try:s=data.decode("ascii")
 except UnicodeDecodeError as e:raise RuntimeError("SUMS_NOT_ASCII") from e
 rows={}
 for line in s.splitlines():
  if not line.strip():continue
  m=re.fullmatch(r"([A-Fa-f0-9]{64})\s+(.+)",line.strip())
  must(m is not None,"SUMS_BAD_ENTRY")
  sha,name=m.group(1).upper(),m.group(2).strip()
  must(name not in rows,"SUMS_DUPLICATE_NAME")
  rows[name]=sha
 must(rows=={WIN:EXPECTED[WIN][0],LINUX:EXPECTED[LINUX][0]},"SUMS_FILESET_OR_SHA_WRONG")
 return rows
def fixture():
 meta={"schema":1,"version":VERSION,"tag":TAG,"productCommit":PRODUCT_SHA,"tagCommit":"a"*40,
       "onePublicDistributionLine":True,"signingCertificateRequired":False,
       "disableWindowsSecurity":False,"unsignedWindowsInstaller":True,
       "windowsSha256":EXPECTED[WIN][0],"linuxSha256":EXPECTED[LINUX][0],
       "sourceCiRunId":38385602156,**{k:dict(v) for k,v in RECEIPTS.items()}}
 receipt_gate(meta)
 cases=[
  ("no_tag",lambda d:d.pop("tag"),"ACCEPTANCE_VERSION_TAG"),
  ("false_source",lambda d:d.__setitem__("productCommit","0"*40),"PRODUCT_SOURCE_NOT_TESTED"),
  ("signing_mandate",lambda d:d.__setitem__("signingCertificateRequired",True),"UNSIGNED_PUBLISHER_POLICY"),
  ("os_bypass",lambda d:d.__setitem__("disableWindowsSecurity",True),"UNSIGNED_PUBLISHER_POLICY"),
  ("bad_windows_sha",lambda d:d.__setitem__("windowsSha256","0"*64),"ACCEPTANCE_PRODUCT_HASH"),
  ("unproven_linux",lambda d:d.pop("linuxInPlaceUpgrade"),"ACCEPTANCE_MISSING_HOSTED"),
  ("wrong_hosted_run",lambda d:d["windowsUpgradeRollback"].__setitem__("runId",1),"ACCEPTANCE_HOSTED_IDENTITY_MISMATCH"),
  ("wrong_linux_report",lambda d:d["linuxFreshRootUser"].__setitem__("reportSha256","0"*64),"ACCEPTANCE_HOSTED_IDENTITY_MISMATCH"),
  ("invalid_tag_commit",lambda d:d.__setitem__("tagCommit","bad"),"TAG_SHA_INVALID")
 ]
 for label,change,code in cases:
  copy=json.loads(json.dumps(meta))
  change(copy)
  try:receipt_gate(copy)
  except RuntimeError as exc:
   must(code in str(exc),"WRONG_NEGATIVE_ERROR:"+label+":"+str(exc))
  else:raise RuntimeError("FALSE_ACCEPTANCE_NEGATIVE:"+label)
 original=(EXPECTED[WIN][0]+"  "+WIN+"\n"+EXPECTED[LINUX][0]+"  "+LINUX+"\n").encode("ascii")
 sums_gate(original)
 try:sums_gate(original+("0"*64+"  "+WIN+"\n").encode())
 except RuntimeError as ex:must("SUMS_DUPLICATE" in str(ex),"NEGATIVE_SUMS_GATE_WRONG")
 else:raise RuntimeError("DUPLICATE_SUMS_FALSE_ACCEPTANCE")
 print("PASS_R472_V153_10_NEGATIVE_AND_POSITIVE_FIXTURES")
def verify_hosted_report(key,blob):
 if key=="windowsUpgradeRollback":
  r=json.loads(blob.decode("utf-8-sig"))
  must(r.get("status")=="PASS_EXACT_SHA_152_TO_153_FIVE_USER_FILES_AND_PROVIDER_PRESERVED","HOSTED_WINDOWS_STATUS")
  must(r.get("CIcommit")==RECEIPTS[key]["workflowCommit"] and
       r.get("runID")==str(RECEIPTS[key]["runId"]) and
       r.get("candidateCommit")==PRODUCT_SHA and
       r.get("installerSha256","").upper()==EXPECTED[WIN][0],"HOSTED_WINDOWS_PRODUCT_RUN_IDENTITY")
  must(r.get("errors")==[] and r.get("installerNotSigned") is True and
       r.get("securityPolicyChanged") is False and r.get("userMachinesModified") is False,
       "HOSTED_WINDOWS_ERROR_OR_SECURITY_MUTATION")
  for name in ("updaterPendingCleared","oneUninstallerRecorded","userDataAfterUpgrade",
               "userDataAfterUninstall","userDataAfterRestore","legacyProviderRestoreConfirmed",
               "networkRestoredExact","watchdogDisarmed","restored152OriginalHashes",
               "serviceCreated","serviceRunning","installedGuiHashPass","installedServiceHashPass",
               "uninstallServiceAbsent","uninstallCtrldAbsent","removedInstalledFiles"):
   must(r.get(name) is True,"HOSTED_WINDOWS_REQUIRED_GATE:"+name)
  for name in ("upgradeExit","uninstallExit","rollbackRestoreExit","rollbackUninstallExit"):
   must(r.get(name)==0,"HOSTED_WINDOWS_EXIT:"+name)
 else:
  text=blob.decode("utf-8",errors="strict")
  if key=="linuxFreshRootUser":
   markers=("PASS_R469_REAL_EXTRACTED_ZIP_6_OF_6",
           '{"ok":true,"systemBackend":"installed","version":"1.5.3"}',
           "PASS_R469_PROTECTED_BACKEND_EXACT_SOURCE_BYTES",
           "PASS_R469_TRUE_ROOT_AND_USER_INSTALL_CUSTOM_DATA_PRESERVED",
           "PASS_R469_REAL_HOSTED_ROOT_USER_NATIVE_INSTALL_UNINSTALL_NO_DUPLICATES",
           "PASS_R469_GUEST_SYSTEM_BACKEND_REMOVED","RESULT_CODE=0")
  else:
   markers=("R471_PUBLIC_V152_ROOT_USER_ACTUAL_INSTALL_PASS",
           "R471_REAL_INSTALLED_V153_STAGED_ROLLBACK_PASS",
           "PASS_R471_USER_PROGRAM_153_ROOT_BACKEND_152",
           "R471_GENUINE_V152_TO_V153_INPLACE_ROOT_UNCHANGED_DATA_PRESERVED",
           "R471_ROOT_USER_NATIVE_UNINSTALL_PRESERVES_DATA","RESULT_CODE=0")
  for marker in markers:must(marker in text,"HOSTED_LINUX_MISSING_GATE:"+key+":"+marker)
 return True
def public_tag():
 must(os.environ.get("GITHUB_ACTIONS")=="true" and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted",
      "PUBLIC_TAG_HOSTED_ONLY")
 must(os.environ.get("GITHUB_REPOSITORY")==REPO and os.environ.get("GITHUB_REF")=="refs/tags/"+TAG,
      "PUBLIC_TAG_CONTEXT_WRONG")
 must(os.environ.get("RUNNER_OS") in ("Windows","Linux"),"UNEXPECTED_RUNNER_OS")
 must(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"),"GITHUB_TOKEN_REQUIRED")
 tag_sha=os.environ.get("GITHUB_SHA","")
 must(SHA.fullmatch(tag_sha) is not None and cmd("git","rev-parse","HEAD")==tag_sha,"TAG_CHECKOUT_IDENTITY")
 public=gh_api("repos/"+REPO+"/releases/tags/"+TAG)
 must(public.get("tag_name")==TAG and public.get("draft") is False and
      public.get("prerelease") is False and public.get("target_commitish")==tag_sha,
      "PUBLIC_TAG_OR_TARGET_MISMATCH")
 assets=public.get("assets")
 must(isinstance(assets,list),"PUBLIC_ASSETS_MISSING")
 must(len(assets)==6 and len({a.get("name") for a in assets})==6,"PUBLIC_MUST_HAVE_EXACT_SIX_ASSETS")
 by_name={a["name"]:a for a in assets}
 must(set(by_name)==set(EXPECTED)|{PROOF},"PUBLIC_SIX_ASSET_FILESET")
 for name,(sha,size) in EXPECTED.items():
  obj=by_name[name]
  must(obj.get("digest","").lower()=="sha256:"+sha.lower() and obj.get("size")==size
       and obj.get("state")=="uploaded","PUBLIC_GITHUB_DIGEST_OR_SIZE:"+name)
 proof_asset=by_name[PROOF]
 must(proof_asset.get("state")=="uploaded" and
      re.fullmatch(r"sha256:[a-f0-9]{64}",proof_asset.get("digest","")) is not None,
      "PUBLIC_PROOF_NO_SHA")
 # Compare actual source blob trees, not a merge-base diff: the verified product
 # commit and squash-merged public source have different ancestry, but identical
 # product files. Reject any real changed SHA or mode outside this exact allowlist.
 def source_tree(commit_sha):
  git_commit=gh_api("repos/"+REPO+"/git/commits/"+commit_sha)
  tree_sha=git_commit.get("tree",{}).get("sha","")
  must(SHA.fullmatch(tree_sha) is not None,"SOURCE_TREE_SHA_MISSING")
  tree=gh_api("repos/"+REPO+"/git/trees/"+tree_sha+"?recursive=1")
  must(tree.get("truncated") is False and isinstance(tree.get("tree"),list),
       "SOURCE_TREE_INCOMPLETE")
  return {entry["path"]:(entry["sha"],entry["mode"])
          for entry in tree["tree"] if entry.get("type")=="blob"}
 previous=source_tree(PRODUCT_SHA)
 current=source_tree(tag_sha)
 changed={p for p in set(previous)|set(current) if previous.get(p)!=current.get(p)}
 must(changed==ALLOWED_SOURCE_ONLY,
      "TAG_HAS_UNTESTED_PRODUCT_SOURCE_MUTATIONS:"+",".join(sorted(changed)))
 ci=gh_api("repos/"+REPO+"/actions/runs/38385602156")
 must(ci.get("head_sha")==PRODUCT_SHA and ci.get("conclusion")=="success","SOURCE_CI_NOT_APPROVED")
 with tempfile.TemporaryDirectory(prefix="dim-v153-public-verification-") as folder:
  root=pathlib.Path(folder)
  for name in sorted(by_name):
   cmd("gh","release","download",TAG,"--repo",REPO,"--pattern",name,
       "--dir",str(root),timeout=240)
   file=root/name
   must(file.is_file() and file.stat().st_size==by_name[name]["size"] and
        file_sha(file)==by_name[name]["digest"][7:].upper(),"REDOWNLOADED_PUBLIC_SHA:"+name)
  sums_gate((root/SUMS).read_bytes())
  meta=json.loads((root/PROOF).read_text(encoding="utf-8-sig"))
  receipt_gate(meta)
  must(meta["tagCommit"]==tag_sha,"PUBLIC_ACCEPTANCE_TAG_SHA")
  with zipfile.ZipFile(root/LINUX) as archive:
   must(archive.testzip() is None,"PUBLIC_LINUX_ARCHIVE_CRC")
   member=next((m for m in archive.namelist() if m.endswith("/PACKAGE_MANIFEST.json")),None)
   must(member is not None,"PUBLIC_LINUX_MANIFEST_ABSENT")
   manifest=json.loads(archive.read(member))
   must(manifest.get("version")==VERSION and len(manifest.get("files",[]))==22,
        "PUBLIC_LINUX_MANIFEST_WRONG")
  for key,receipt in RECEIPTS.items():
   remote=gh_api("repos/"+REPO+"/actions/runs/"+str(receipt["runId"]))
   must(remote.get("head_sha")==receipt["workflowCommit"] and
        remote.get("status")=="completed" and remote.get("conclusion")=="success",
        "HOSTED_GITHUB_RUN_NOT_SUCCESS:"+key)
   target=root/key;target.mkdir()
   cmd("gh","run","download",str(receipt["runId"]),"--repo",REPO,
       "--name",receipt["artifactName"],"--dir",str(target),timeout=120)
   file=target/receipt["reportPath"]
   must(file.is_file() and file_sha(file)==receipt["reportSha256"],
        "HOSTED_RAW_SHA_WRONG:"+key)
   verify_hosted_report(key,file.read_bytes())
  result={"schema":1,"status":"PASS_V153_PUBLIC_SIX_ASSETS_THREE_HOSTED_NATIVE_LIFECYCLES",
    "tag":TAG,"tagCommit":tag_sha,"productCommit":PRODUCT_SHA,
    "windowsSha256":EXPECTED[WIN][0],"linuxSha256":EXPECTED[LINUX][0],
    "sourceCi":38385602156,"hostedRuns":[RECEIPTS[k]["runId"] for k in RECEIPTS],
    "verifiedUTC":datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "signingRequired":False,"securityPolicyChanged":False,
    "emadLiveInstalledUpgrade":"OPEN_OWNER_HOST_UAC_NETWORK_SAFETY",
    "worldwideAuthWebsites":"UNPROVEN","ownerRightsReview":"EXTERNAL"}
  out=os.environ.get("RUNNER_TEMP")
  if out:
   path=pathlib.Path(out)/"DIRECT_R472_V153_PUBLIC_TAG_VERIFICATION.json"
   path.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
  print("PASS_R472_EXACT_PUBLIC_RELEASE_V153_NATIVE_PROVENANCE: "+json.dumps(result,sort_keys=True))
def main():
 parser=argparse.ArgumentParser()
 flags=parser.add_mutually_exclusive_group(required=True)
 flags.add_argument("--fixtures",action="store_true")
 flags.add_argument("--public-tag",action="store_true")
 args=parser.parse_args()
 if args.fixtures:fixture()
 else:public_tag()
if __name__=="__main__":
 try:main()
 except Exception as exc:
  print("FAIL_CLOSED_R472_PUBLIC_V153:"+repr(exc),file=sys.stderr)
  raise SystemExit(75)
