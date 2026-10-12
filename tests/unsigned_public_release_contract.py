#!/usr/bin/env python3
"""Direct Internet Method: strict one-public-unsigned-release contract.

--fixtures: no network/mutation, negative-first schema+digest+hosted acceptance tests.
--public-tag: GitHub-hosted tag CI only; independently download exact public assets,
  source acceptance artifact and two actual hosted install/rollback reports.
No code signing, security policy bypass, installer execution, or release mutation.
"""
from __future__ import annotations
import argparse,datetime,hashlib,json,os,pathlib,re,subprocess,sys,tempfile

REPO="GOD13emad/DirectInternetMethod"
VERSION="1.5.2"
TAG="v"+VERSION
W="DirectInternetMethod_1.5.2_Windows_Setup.exe"
L="DirectInternetMethod_1.5.2_Linux_x86_64.zip"
SUM="SHA256SUMS.txt"
PROOF="ACCEPTANCE_V152.json"
HEXDIGEST=re.compile(r"^[A-Fa-f0-9]{64}$")
COMMITSHA=re.compile(r"^[a-f0-9]{40}$")
REPORT_NAME=re.compile(r"^REPORT_R[0-9]{3,4}\.json$")
ARTIFACT_NAME=re.compile(r"^dim-r[0-9]{3,4}-disposable-windows-[0-9]{8,15}$")

def must(v,reason):
 if not v:raise RuntimeError(reason)
def checksum(buf:bytes)->str:return hashlib.sha256(buf).hexdigest().upper()
def file_digest(p:pathlib.Path)->str:
 h=hashlib.sha256()
 with p.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""):h.update(b)
 return h.hexdigest().upper()
def strict_hex(v):
 return isinstance(v,str) and HEXDIGEST.fullmatch(v) is not None
def run(*args,timeout=60):
 z=subprocess.run(args,text=True,capture_output=True,timeout=timeout,check=False)
 must(z.returncode==0,"HOST_TOOL_FAILURE:"+args[0]+" "+z.stderr[-300:])
 return z.stdout.strip()
def github_api(endpoint):
 return json.loads(run("gh","api",endpoint,timeout=30))
def valid_asset_list(assetlist):
 must(isinstance(assetlist,list),"GITHUB_ASSETS_NOT_LIST")
 names=[a.get("name") for a in assetlist]
 must(len(names)==len(set(names)),"DUPLICATE_PUBLIC_ASSET_NAME")
 assets={a["name"]:a for a in assetlist}
 for required in (W,L,SUM,PROOF):
  must(required in assets,"PUBLIC_RELEASE_ASSET_MISSING:"+required)
  a=assets[required]
  digest=a.get("digest","")
  must(isinstance(digest,str) and digest.lower().startswith("sha256:") and strict_hex(digest[7:]),
       "PUBLIC_RELEASE_ASSET_NO_VALID_GITHUB_DIGEST:"+required)
  must(isinstance(a.get("size"),int) and a["size"]>50,"PUBLIC_RELEASE_ASSET_SIZE_INVALID:"+required)
 return assets
def parse_sums(data:bytes):
 must(data.decode("ascii").encode("ascii")==data,"PUBLIC_SHA256SUMS_NOT_ASCII")
 lines=[x.strip() for x in data.decode("ascii").splitlines() if x.strip()]
 must(len(lines)==2,"PUBLIC_SHA256SUMS_NOT_EXACTLY_TWO_FILES")
 rows={}
 for line in lines:
  m=re.fullmatch(r"([A-Fa-f0-9]{64})\s+(.+)",line)
  must(m is not None,"PUBLIC_SHA256SUMS_LINE_INVALID")
  h,name=m.group(1).upper(),m.group(2).strip()
  must(name not in rows,"PUBLIC_SHA256SUMS_DUPLICATE_NAME")
  rows[name]=h
 must(set(rows)=={W,L},"PUBLIC_SHA256SUMS_FILESET_WRONG")
 return rows
def qa_receipt(meta,which):
 r=meta.get(which)
 must(isinstance(r,dict),"HOSTED_RECEIPT_MISSING:"+which)
 must(isinstance(r.get("runId"),int) and r["runId"]>=10000000000,"HOSTED_RUN_ID_INVALID:"+which)
 must(COMMITSHA.fullmatch(r.get("workflowCommit","")) is not None,"HOSTED_WORKFLOW_COMMIT_INVALID:"+which)
 must(ARTIFACT_NAME.fullmatch(r.get("artifactName","")) is not None,"HOSTED_ARTIFACT_NAME_INVALID:"+which)
 must(r["artifactName"].endswith("-"+str(r["runId"])),"HOSTED_ARTIFACT_RUN_MISMATCH:"+which)
 must(REPORT_NAME.fullmatch(r.get("reportName","")) is not None,"HOSTED_REPORT_NAME_INVALID:"+which)
 must(strict_hex(r.get("reportSha256")),"HOSTED_REPORT_SHA_INVALID:"+which)
 return r
def validate_policy(meta,source,sha_w,sha_l):
 must(isinstance(meta,dict) and meta.get("schema")==1,"RELEASE_ACCEPTANCE_SCHEMA_INVALID")
 must(meta.get("version")==VERSION and meta.get("tag")==TAG,"RELEASE_ACCEPTANCE_TAG_WRONG")
 must(meta.get("onePublicDistributionLine") is True,"SINGLE_PUBLIC_LINE_NOT_ACCEPTED")
 must(meta.get("signingCertificateRequired") is False,"SIGNING_POLICY_MUST_NOT_BE_REQUIRED")
 must(meta.get("disableWindowsSecurity") is False,"SECURITY_BYPASS_REJECTED")
 must(meta.get("unsignedWindowsInstaller") is True,"UNSIGNED_STATUS_NOT_DISCLOSED")
 must(meta.get("productCommit")==source,"RELEASE_ACCEPTANCE_SOURCE_SHA_WRONG")
 must(COMMITSHA.fullmatch(source) is not None,"SOURCE_SHA_INVALID")
 must(strict_hex(meta.get("windowsSha256")) and meta["windowsSha256"].upper()==sha_w.upper(),"RELEASE_ACCEPTANCE_WINDOWS_SHA_WRONG")
 must(strict_hex(meta.get("linuxSha256")) and meta["linuxSha256"].upper()==sha_l.upper(),"RELEASE_ACCEPTANCE_LINUX_SHA_WRONG")
 must(isinstance(meta.get("sourceCiRunId"),int) and meta["sourceCiRunId"]>=10000000000,"SOURCE_CI_RECEIPT_MISSING")
 qa_receipt(meta,"freshInstall")
 qa_receipt(meta,"upgradeRollback")
 return True
def validate_report(report,meta,receipt,kind):
 must(report.get("candidateCommit")==meta["productCommit"],"HOSTED_REPORT_PRODUCT_SHA_MISMATCH:"+kind)
 must(report.get("installerSha256","").upper()==meta["windowsSha256"].upper(),"HOSTED_REPORT_INSTALLER_SHA_MISMATCH:"+kind)
 must(report.get("CIcommit")==receipt["workflowCommit"],"HOSTED_REPORT_QA_WORKFLOW_MISMATCH:"+kind)
 must(report.get("runID")==str(receipt["runId"]),"HOSTED_REPORT_RUN_ID_MISMATCH:"+kind)
 must(report.get("runnerEnvironment")=="github-hosted" and report.get("runnerOS")=="Windows","HOSTED_REPORT_NOT_DISPOSABLE_WINDOWS:"+kind)
 must(report.get("installerNotSigned") is True and report.get("securityPolicyChanged") is False,"HOSTED_REPORT_POLICY_BYPASS:"+kind)
 must(report.get("watchdogArmed") is True and report.get("watchdogDisarmed") is True
     and report.get("networkRestoredExact") is True,"HOSTED_REPORT_WATCHDOG_OR_NETWORK_ROLLBACK_FAIL:"+kind)
 must(report.get("errors")==[],"HOSTED_REPORT_UNRESOLVED_ERRORS:"+kind)
 for gate in ("serviceCreated","serviceRunning","ctrldCreated","installedGuiHashPass",
   "installedServiceHashPass","installedManifestHashPass","uninstallServiceAbsent",
   "uninstallCtrldAbsent","removedInstalledFiles"):
  must(report.get(gate) is True,"HOSTED_REPORT_REQUIRED_GATE_MISSING:"+kind+":"+gate)
 if kind=="freshInstall":
  must(report.get("status")=="PASS_EPHEMERAL_WINDOWS_REAL_INSTALL_AND_UNINSTALL","FRESH_INSTALL_NOT_ACCEPTED")
  must(report.get("installExit")==0 and report.get("uninstallExit")==0,"FRESH_INSTALL_EXIT_NONZERO")
 elif kind=="upgradeRollback":
  must(report.get("status")=="PASS_EPHEMERAL_WINDOWS_REAL_151_TO_152_UPGRADE_AND_151_RESTORE","UPGRADE_ROLLBACK_NOT_ACCEPTED")
  for field in ("baselineInstallExit","upgradeExit","rollbackRestoreExit","rollbackUninstallExit"):
   must(report.get(field)==0,"UPGRADE_ROLLBACK_EXIT_NONZERO:"+field)
  for field in ("baselineGuiHashPass","baselineServiceHashPass","upgradedGuiHashPass",
    "upgradedServiceHashPass","restored151OriginalHashes"):
   must(report.get(field) is True,"RESTORED_BASELINE_SHA_NOT_EXACT:"+field)
 else:raise RuntimeError("UNKNOWN_REPORT_KIND")
 return True
def fixture():
 sha_w="A"*64;sha_l="B"*64;src="a"*40
 payload=lambda x:json.loads(json.dumps(x))
 rec={"runId":38168392209,"workflowCommit":"b"*40,"artifactName":"dim-r389-disposable-windows-38168392209",
  "reportName":"REPORT_R389.json","reportSha256":"C"*64}
 other=dict(rec,runId=38167341910,artifactName="dim-r384-disposable-windows-38167341910",reportName="REPORT_R384.json")
 meta={"schema":1,"tag":TAG,"version":VERSION,"onePublicDistributionLine":True,
  "signingCertificateRequired":False,"disableWindowsSecurity":False,
  "unsignedWindowsInstaller":True,"productCommit":src,"windowsSha256":sha_w,
  "linuxSha256":sha_l,"sourceCiRunId":38152706915,"freshInstall":other,"upgradeRollback":rec}
 report={"candidateCommit":src,"installerSha256":sha_w,"CIcommit":rec["workflowCommit"],
  "runID":str(rec["runId"]),"runnerEnvironment":"github-hosted","runnerOS":"Windows",
  "installerNotSigned":True,"securityPolicyChanged":False,"watchdogArmed":True,
  "watchdogDisarmed":True,"networkRestoredExact":True,"errors":[],
  "serviceCreated":True,"serviceRunning":True,"ctrldCreated":True,"installedGuiHashPass":True,
  "installedServiceHashPass":True,"installedManifestHashPass":True,
  "uninstallServiceAbsent":True,"uninstallCtrldAbsent":True,"removedInstalledFiles":True,
  "status":"PASS_EPHEMERAL_WINDOWS_REAL_151_TO_152_UPGRADE_AND_151_RESTORE",
  "baselineInstallExit":0,"upgradeExit":0,"rollbackRestoreExit":0,"rollbackUninstallExit":0,
  "baselineGuiHashPass":True,"baselineServiceHashPass":True,"upgradedGuiHashPass":True,
  "upgradedServiceHashPass":True,"restored151OriginalHashes":True}
 must(validate_policy(meta,src,sha_w,sha_l),"FIXTURE_POSITIVE_POLICY_FAIL")
 must(validate_report(report,meta,rec,"upgradeRollback"),"FIXTURE_POSITIVE_ROLLBACK_FAIL")
 def reject(fn):
  try:fn()
  except RuntimeError:return
  raise AssertionError("MALFORMED_UNSIGNED_RELEASE_FALSE_ACCEPTED")
 variants=[
  lambda:validate_policy(dict(meta,signingCertificateRequired=True),src,sha_w,sha_l),
  lambda:validate_policy(dict(meta,disableWindowsSecurity=True),src,sha_w,sha_l),
  lambda:validate_policy(dict(meta,productCommit="f"*40),src,sha_w,sha_l),
  lambda:validate_policy(dict(meta,windowsSha256="0"*64),src,sha_w,sha_l),
  lambda:validate_policy(dict(meta,upgradeRollback={}),src,sha_w,sha_l),
  lambda:validate_report(dict(report,networkRestoredExact=False),meta,rec,"upgradeRollback"),
  lambda:validate_report(dict(report,errors=["RECOVERY_UNINSTALL_EXIT_1"]),meta,rec,"upgradeRollback"),
  lambda:validate_report(dict(report,restored151OriginalHashes=False),meta,rec,"upgradeRollback"),
  lambda:parse_sums(("0"*64+"  "+W+"\n"+sha_l+"  "+W+"\n").encode()),
  lambda:valid_asset_list([{"name":W,"size":100,"digest":"sha256:"+sha_w}]),
  lambda:validate_report(dict(report,CIcommit="c"*40),meta,rec,"upgradeRollback"),
 ]
 for fn in variants:reject(fn)
 print("PASS_UNSIGNED_RELEASE_CONTRACT_NEGATIVE_FIXTURES: "+str(len(variants))+"/"+str(len(variants)))
def public_tag():
 must(os.environ.get("GITHUB_ACTIONS")=="true" and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted","HOSTED_TAG_CI_ONLY")
 must(os.environ.get("GITHUB_REPOSITORY")==REPO,"TAG_REPOSITORY_WRONG")
 must(os.environ.get("GITHUB_REF")=="refs/tags/"+TAG,"TAG_REF_WRONG")
 must(os.environ.get("RUNNER_OS") in ("Windows","Linux"),"UNSUPPORTED_QA_RUNNER_OS")
 must(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"),"GITHUB_READ_TOKEN_MISSING")
 checkout=run("git","rev-parse","HEAD")
 src=os.environ.get("GITHUB_SHA","")
 must(checkout==src and COMMITSHA.fullmatch(src) is not None,"TAG_CHECKOUT_SHA_CHANGED")
 raw=github_api("repos/"+REPO+"/releases/tags/"+TAG)
 must(raw.get("draft") is False and raw.get("prerelease") is False and raw.get("tag_name")==TAG,"RELEASE_NOT_PUBLIC_STABLE")
 must(raw.get("target_commitish")==src,"RELEASE_TARGET_COMMIT_MISMATCH")
 assets=valid_asset_list(raw.get("assets"))
 now=datetime.datetime.now(datetime.timezone.utc).isoformat()
 with tempfile.TemporaryDirectory(prefix="dim-public-release-") as folder:
  root=pathlib.Path(folder)
  for name in (W,L,SUM,PROOF):
   run("gh","release","download",TAG,"--repo",REPO,"--pattern",name,"--dir",str(root),timeout=240)
   p=root/name
   must(p.is_file() and p.stat().st_size==assets[name]["size"],"RELEASE_DOWNLOADED_ASSET_SIZE_CHANGED:"+name)
   must(file_digest(p)==assets[name]["digest"][7:].upper(),"RELEASE_DOWNLOADED_ASSET_SHA_CHANGED:"+name)
  sums=parse_sums((root/SUM).read_bytes())
  for name in (W,L):must(sums[name]==file_digest(root/name),"PUBLIC_THREE_WAY_SHA_DISAGREEMENT:"+name)
  metadata=json.loads((root/PROOF).read_text(encoding="utf-8"))
  validate_policy(metadata,src,sums[W],sums[L])
  sourceci=github_api("repos/"+REPO+"/actions/runs/"+str(metadata["sourceCiRunId"]))
  must(sourceci.get("head_sha")==src and sourceci.get("conclusion")=="success" and sourceci.get("status")=="completed","SOURCE_CI_NOT_ACCEPTED_FOR_TAG")
  for key,kind in (("freshInstall","freshInstall"),("upgradeRollback","upgradeRollback")):
   receipt=qa_receipt(metadata,key)
   runmeta=github_api("repos/"+REPO+"/actions/runs/"+str(receipt["runId"]))
   must(runmeta.get("head_sha")==receipt["workflowCommit"] and runmeta.get("conclusion")=="success" and runmeta.get("status")=="completed","GITHUB_RUN_NOT_SUCCESS:"+key)
   dir_=root/key;dir_.mkdir()
   run("gh","run","download",str(receipt["runId"]),"--repo",REPO,"--name",receipt["artifactName"],"--dir",str(dir_),timeout=100)
   reportfile=dir_/receipt["reportName"]
   must(reportfile.is_file() and file_digest(reportfile)==receipt["reportSha256"].upper(),"HOSTED_RAW_REPORT_SHA_MISMATCH:"+key)
   report=json.loads(reportfile.read_text(encoding="utf-8-sig"))
   validate_report(report,metadata,receipt,kind)
  final={"status":"PASS_PUBLIC_UNSIGNED_TAG_ASSETS_AND_BOTH_HOSTED_LIFECYCLES",
   "tag":TAG,"source":src,"windowsSha256":sums[W],"linuxSha256":sums[L],
   "validatedUtc":now,"signingRequired":False,"securityConfigurationChanged":False,
   "hostedInstallAndRollback":"PASS","authenticatedWebSiteUAT":"UNPROVEN",
   "redistributionRights":"OWNER_REVIEW_REQUIRED","productFinal":"UNPROVEN"}
  out=os.environ.get("RUNNER_TEMP")
  if out:
   path=pathlib.Path(out)/"DIRECT_R394_PUBLIC_TAG_VERIFICATION.json"
   path.write_text(json.dumps(final,indent=2)+"\n",encoding="utf8")
  print("PASS_PUBLIC_UNSIGNED_RELEASE_FINAL_PROVENANCE: "+json.dumps(final,sort_keys=True))
def main():
 p=argparse.ArgumentParser()
 z=p.add_mutually_exclusive_group(required=True)
 z.add_argument("--fixtures",action="store_true")
 z.add_argument("--public-tag",action="store_true")
 opts=p.parse_args()
 if opts.fixtures:fixture()
 if opts.public_tag:public_tag()
if __name__=="__main__":
 try:main()
 except Exception as e:
  print("FAIL_CLOSED_PUBLIC_UNSIGNED_RELEASE_CONTRACT: "+repr(e),file=sys.stderr)
  sys.exit(75)
