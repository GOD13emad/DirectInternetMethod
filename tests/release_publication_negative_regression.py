#!/usr/bin/env python3
"""Negative-first safeguards for owner-approved one public unsigned release line.
No signature purchase/trust-policy bypass required. No published claims without
exact hosted installation/rollback receipt fields; actual remote byte proof
is in unsigned_public_release_contract.py --public-tag.
"""
from copy import deepcopy
from pathlib import Path
import json,runpy

ROOT=Path(__file__).resolve().parents[1]
audit=runpy.run_path(str(ROOT/"tests/release_metadata_audit.py"))
check=audit["assert_unsigned_publication_acceptance"]
meta=json.loads((ROOT/"RELEASE.json").read_text(encoding="utf-8-sig"))
assert meta["version"]=="1.5.2"
assert meta["publicUnsignedDistribution"]["codeSigningCertificateRequired"] is False
assert meta["publicUnsignedDistribution"]["onePublicLine"] is True
assert "SIGNING" not in meta["status"]
check(meta)
def failure(stage,change,expected):
 v=deepcopy(meta)
 change(v)
 try:check(v)
 except SystemExit as err:
  assert expected in str(err),(stage,err)
 else:raise AssertionError("FALSE_RELEASE_ACCEPTED:"+stage)

def public(v):
 v["status"]="PASS_FINAL_PUBLISHED_VERIFIED"
 v["acceptance"]["publication"]="PASS_PUBLIC_REDOWNLOAD_VERIFIED"
failure("required_certificate",lambda m:m["publicUnsignedDistribution"].update(codeSigningCertificateRequired=True),"OWNER_UNSIGNED_DISTRIBUTION_POLICY_MISSING_OR_UNSAFE")
failure("security_bypass",lambda m:m["publicUnsignedDistribution"].update(disableWindowsSecurity=True),"OWNER_UNSIGNED_DISTRIBUTION_POLICY_MISSING_OR_UNSAFE")
failure("internal_external_split",lambda m:m["publicUnsignedDistribution"].update(onePublicLine=False),"OWNER_UNSIGNED_DISTRIBUTION_POLICY_MISSING_OR_UNSAFE")
failure("historical_signer_blocker",lambda m:m.update(status="CANDIDATE_V152_HOLD_APP_CONTROL_SIGNING"),"SUPERSEDED_SIGNING_RELEASE_BLOCKER_STILL_ACTIVE")
failure("false_published",lambda m:(public(m),m["publication"].update(tagCommit="")),"PUBLIC_STABLE_RELEASE_AUTHORITY_INCOMPLETE")
failure("wrong_hosted_fresh",lambda m:(public(m),m["acceptance"].update(windowsFreshInstall="COMPILER_ONLY")),"REAL_UNSIGNED_WINDOWS_INSTALL_AND_ROLLBACK_REQUIRED")
failure("wrong_hosted_upgrade",lambda m:(public(m),m["acceptance"].update(windowsUpgradeRollback="PASS_BUILD_ONLY")),"REAL_UNSIGNED_WINDOWS_INSTALL_AND_ROLLBACK_REQUIRED")
failure("faked_security_mutation",lambda m:(public(m),m["acceptance"].update(windowsSecurityPolicyUnchanged=False)),"REAL_UNSIGNED_WINDOWS_INSTALL_AND_ROLLBACK_REQUIRED")
failure("no_host_run",lambda m:(public(m),m["windowsHostAcceptanceEvidence"].pop("upgradeRunId")),"HOSTED_RELEASE_RECEIPT_RUN_ID_MISSING")
failure("missing_report_sha",lambda m:(public(m),m["windowsHostAcceptanceEvidence"].pop("freshReportSha256")),"HOSTED_RELEASE_RECEIPT_HASH_MISSING")
failure("wrong_binary_receipt",lambda m:(public(m),m["windowsHostAcceptanceEvidence"].update(installerSha256="0"*64)),"HOSTED_RELEASE_INSTALLER_SHA_MISMATCH")
failure("missing_published_timestamp",lambda m:m["publication"].update(publishedAt=""),"PUBLIC_STABLE_RELEASE_AUTHORITY_INCOMPLETE")
valid=deepcopy(meta)
public(valid)
valid["publication"]={"tag":"v1.5.2","tagCommit":"14a3eec378eb75856f6691b7b3edc970507ee61f",
 "releaseUrl":"https://github.com/GOD13emad/DirectInternetMethod/releases/tag/v1.5.2",
 "publishedAt":"2026-10-11T00:00:00Z"}
check(valid)
assert valid["acceptance"]["windowsUpgradeRollback"]=="PASS_HOSTED_151_TO_152_AND_151_RESTORE_ZERO_ERRORS"
print("PASS_12_OF_12_NEGATIVE_UNSIGNED_PUBLICATION_FIXTURES_AND_POSITIVE_SCHEMA")
