#!/usr/bin/env python3
"""R461: exact legacy v1.5.1 updater stage-path security regression.

This is a source contract plus an independently modeled path/ownership matrix.
It does NOT substitute for native Windows postinstall acceptance.
No host, service, files or OS networking are changed by this test.
"""
from __future__ import annotations
import ntpath
import pathlib
import re

ROOT=pathlib.Path(__file__).resolve().parents[1]
svc=(ROOT/"windows/service/Program.cs").read_text(encoding="utf-8-sig")
start=svc.index("    static void FinalizePendingUpdate()")
end=svc.index("    static async Task RunActionAsync(",start)
body=svc[start:end]
def guard(ok,why):
    if not ok:raise AssertionError("R461_LEGACY_STAGE_SOURCE_GUARD:"+why)
def check_order(parts):
    cursor=0
    for fragment in parts:
        pos=body.find(fragment,cursor)
        guard(pos>=0,"MISSING_OR_WRONG_ORDER:"+fragment)
        cursor=pos+len(fragment)

required=[
    'var targetText = doc.RootElement.GetProperty("targetVersion").GetString()',
    'doc.RootElement.GetProperty("schema").GetInt32() != 1',
    '!Version.TryParse(targetText, out var target)',
    'var installed = CurrentVersion;',
    'if (installed >= target)',
    'var stage = doc.RootElement.GetProperty("installer").GetString()',
    'var expectedSha = doc.RootElement.GetProperty("sha256").GetString()',
    'var oldOfficialName = "DirectInternetMethod_" + versionText + "_Windows_Setup.exe";',
    'var oldOfficialPath = Path.Combine(UpdatesDir, oldOfficialName);',
    'var tag = doc.RootElement.GetProperty("tag").GetString()',
    'var canonicalStage = Path.GetFullPath(stage);',
    'var fixedOwnedStage = canonicalStage.Equals(Path.GetFullPath(OwnedUpdateInstallerPath),',
    'var pinnedLegacyStage = target >= new Version(1, 5, 2)',
    'tag.Equals("v" + versionText, StringComparison.OrdinalIgnoreCase)',
    'canonicalStage.Equals(Path.GetFullPath(oldOfficialPath),',
    'if (!Path.IsPathFullyQualified(stage) ||',
    '(!fixedOwnedStage && !pinnedLegacyStage) ||',
    'expectedSha.Length != 64 || !expectedSha.All(Uri.IsHexDigit)',
    'File.GetAttributes(stage) & FileAttributes.ReparsePoint',
    'File.GetAttributes(UpdatesDir) & FileAttributes.ReparsePoint',
    'observed = Convert.ToHexString(SHA256.HashData(input))',
    '!observed.Equals(expectedSha, StringComparison.OrdinalIgnoreCase)',
    'File.Delete(stage);',
    'File.Delete(PendingUpdatePath);',
    'WriteActionStatus("update", "done", 0,',
]
check_order(required)
guard(body.count("File.Delete(stage);")==1,"STAGING_DELETE_COUNT")
guard(body.count("File.Delete(PendingUpdatePath);")==1,"PENDING_DELETE_COUNT")
guard(body.count("throw new CryptographicException(")>=3,"NO_FOREIGN_OR_SHA_REJECTION")
guard("File.Delete(PendingUpdatePath)" not in body[:body.index("observed = Convert.ToHexString")],"EARLY_CLEAR")
guard('GetProperty("targetVersion")' in body and 'GetProperty("tag")' in body,
      "HISTORICAL_TAG_VERSION_NOT_REQUIRED")

DIR=r"C:\ProgramData\DirectInternetMethod\updates"
def normalized(path):
    return ntpath.normcase(ntpath.normpath(path))
def is_absolute_windows(path):
    return bool(re.match(r"^[A-Za-z]:\\",path))
def decision(stage,version,tag,sha,installed="1.5.2",is_reparse=False,
             digest_matches=True,installer_present=True):
    """Safety-model of the C# decision, NOT invocation of privileged service."""
    if tuple(map(int,installed.split("."))) < tuple(map(int,version.split("."))):
        return "RETAIN_PENDING_UNINSTALLED_TARGET"
    canonical=normalized(stage)
    fixed=canonical==normalized(ntpath.join(DIR,"DirectInternetMethod-update-stage.exe"))
    legacy=(tuple(map(int,version.split("."))) >= (1,5,2)
         and tag.lower()=="v"+version.lower()
         and canonical==normalized(ntpath.join(DIR,
                   "DirectInternetMethod_"+version+"_Windows_Setup.exe")))
    if not is_absolute_windows(stage) or not (fixed or legacy) or len(sha)!=64 or not re.fullmatch("[A-Fa-f0-9]{64}",sha):
        return "REJECT_FOREIGN_OR_INVALID_RECORD"
    if installer_present:
        if is_reparse:return "REJECT_REPARSE_POINT"
        if not digest_matches:return "REJECT_STAGE_SHA_CHANGED"
    return "ACCEPT_FINALIZE_AND_REMOVE_ONLY_OWNED_STAGE"

correct="F94A81CC819E465D6B1000FFDB0B20A7212E39B6F6282ED8A720774148DFC78D"
tests=[
 ("v151_name_matches_published_v152",ntpath.join(DIR,"DirectInternetMethod_1.5.2_Windows_Setup.exe"),"1.5.2","v1.5.2",correct,"ACCEPT_FINALIZE_AND_REMOVE_ONLY_OWNED_STAGE",{}),
 ("v152_fixed_new_name",ntpath.join(DIR,"DirectInternetMethod-update-stage.exe"),"1.5.2","v1.5.2",correct,"ACCEPT_FINALIZE_AND_REMOVE_ONLY_OWNED_STAGE",{}),
 ("wrong_previous_minor",ntpath.join(DIR,"DirectInternetMethod_1.5.1_Windows_Setup.exe"),"1.5.2","v1.5.2",correct,"REJECT_FOREIGN_OR_INVALID_RECORD",{}),
 ("changed_version",ntpath.join(DIR,"DirectInternetMethod_1.5.2_Windows_Setup.exe"),"1.5.3","v1.5.2",correct,"RETAIN_PENDING_UNINSTALLED_TARGET",{}),
 ("wrong_tag",ntpath.join(DIR,"DirectInternetMethod_1.5.2_Windows_Setup.exe"),"1.5.2","v1.5.2-preview4",correct,"REJECT_FOREIGN_OR_INVALID_RECORD",{}),
 ("missing_tag",ntpath.join(DIR,"DirectInternetMethod_1.5.2_Windows_Setup.exe"),"1.5.2","",correct,"REJECT_FOREIGN_OR_INVALID_RECORD",{}),
 ("arbitrary_abs_path",r"C:\Temp\DirectInternetMethod_1.5.2_Windows_Setup.exe","1.5.2","v1.5.2",correct,"REJECT_FOREIGN_OR_INVALID_RECORD",{}),
 ("sibling_dir",r"C:\ProgramData\DirectInternetMethod\bad-updates\DirectInternetMethod_1.5.2_Windows_Setup.exe","1.5.2","v1.5.2",correct,"REJECT_FOREIGN_OR_INVALID_RECORD",{}),
 ("relative_path","DirectInternetMethod_1.5.2_Windows_Setup.exe","1.5.2","v1.5.2",correct,"REJECT_FOREIGN_OR_INVALID_RECORD",{}),
 ("bad_sha_hex",ntpath.join(DIR,"DirectInternetMethod_1.5.2_Windows_Setup.exe"),"1.5.2","v1.5.2","Z"*64,"REJECT_FOREIGN_OR_INVALID_RECORD",{}),
 ("bad_sha_length",ntpath.join(DIR,"DirectInternetMethod_1.5.2_Windows_Setup.exe"),"1.5.2","v1.5.2","AB","REJECT_FOREIGN_OR_INVALID_RECORD",{}),
 ("symlink_owned_path",ntpath.join(DIR,"DirectInternetMethod_1.5.2_Windows_Setup.exe"),"1.5.2","v1.5.2",correct,"REJECT_REPARSE_POINT",{"is_reparse":True}),
 ("stage_sha_mutation",ntpath.join(DIR,"DirectInternetMethod_1.5.2_Windows_Setup.exe"),"1.5.2","v1.5.2",correct,"REJECT_STAGE_SHA_CHANGED",{"digest_matches":False}),
 ("absent_stage_valid_pending",ntpath.join(DIR,"DirectInternetMethod_1.5.2_Windows_Setup.exe"),"1.5.2","v1.5.2",correct,"ACCEPT_FINALIZE_AND_REMOVE_ONLY_OWNED_STAGE",{"installer_present":False}),
 ("installed_older_than_target",ntpath.join(DIR,"DirectInternetMethod_1.5.2_Windows_Setup.exe"),"1.5.2","v1.5.2",correct,"RETAIN_PENDING_UNINSTALLED_TARGET",{"installed":"1.5.1"}),
 ("case_insensitive_official_name",ntpath.join(DIR.lower(),"directinternetmethod_1.5.2_windows_setup.EXE"),"1.5.2","v1.5.2",correct,"ACCEPT_FINALIZE_AND_REMOVE_ONLY_OWNED_STAGE",{}),
]
for name,path,version,tag,sha,expected,kwargs in tests:
    actual=decision(path,version,tag,sha,**kwargs)
    guard(actual==expected,name+":"+actual)
print("PASS_R461_LEGACY_V151_STAGE_SOURCE_GUARDS_AND_NEGATIVE_MODEL",len(tests),"/",len(tests))
print("PASS_R461_SOURCE_HAS_NO_CLEANUP_BEFORE_EXACT_SHA_AND_OWNER_PATH_CHECK")
