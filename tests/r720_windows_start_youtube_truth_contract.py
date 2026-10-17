#!/usr/bin/env python3
"""R720: exact production Windows Start health must require YouTube's real page.

Only extract and run the production Get-CoreSiteHealth AST function in pwsh.
Do not source the lifecycle script, send SCM actions, or change networking.
"""
from __future__ import annotations
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"windows/app/Start-Direct.ps1"
text=SCRIPT.read_text(encoding="utf-8-sig")
required=(
    "function Get-CoreSiteHealth($ytPage,$yt204,$oa,$gh)",
    "if(-not ([bool]$ytPage.ok -and [bool]$yt204.ok)){[void]$failed.Add('youtube')}",
    "$ytPage=Curl-Probe-Retry 'https://www.youtube.com/' $route.LocalIp '^200\\|' 8 2",
    "$yt=Curl-Probe-Retry 'https://www.youtube.com/generate_204' $route.LocalIp '^204\\|' 8 2",
    "$httpsHealth=Get-CoreSiteHealth $ytPage $yt $oa $gh",
    "youtubePage=$ytPage;youtube204=$yt",
    "required=2",
    "passed=3-$failed.Count",
    "reachability=if($failed.Count -eq 0){'HEALTHY'}else{'PARTIAL'}",
)
for key in required:
    assert text.count(key)==1,("R720_MISSING_OR_DUPLICATE_PRODUCTION_GUARD",key)
assert "function Get-CoreSiteHealth($yt,$oa,$gh)" not in text
assert "$httpsHealth=Get-CoreSiteHealth $yt $oa $gh" not in text
assert "$httpsProbePassCount -lt 2" in text,"OLD_2_OF_3_ENGINE_PARTIAL_SEMANTICS_LOST"
assert "if(-not $dy.ok){throw 'YOUTUBE_DNS_NOT_CLEAN'}" in text
assert "Curl-Probe-Retry" in text and "--noproxy '*'" in text

native=shutil.which("pwsh")
if sys.platform=="win32":
    assert native is not None,"R720_NATIVE_WINDOWS_POWERSHELL_REQUIRED"
if native is not None:
    code=r'''
$ErrorActionPreference='Stop'
$astTokens=$null
$astErrors=$null
$source=[System.Management.Automation.Language.Parser]::ParseFile(
    $args[0],[ref]$astTokens,[ref]$astErrors)
if($astErrors.Count){throw 'R720_SOURCE_START_SCRIPT_PARSE_ERROR'}
$defs=@($source.FindAll({
  param($node)
  $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
  $node.Name -eq 'Get-CoreSiteHealth'
},$true))
if($defs.Count -ne 1){throw 'R720_SOURCE_HEALTH_AST_NOT_UNIQUE'}
. ([scriptblock]::Create($defs[0].Extent.Text))
for($mask=0;$mask -lt 16;$mask++){
   $page=[pscustomobject]@{ok=($mask -band 1) -ne 0}
   $ping=[pscustomobject]@{ok=($mask -band 2) -ne 0}
   $openai=[pscustomobject]@{ok=($mask -band 4) -ne 0}
   $github=[pscustomobject]@{ok=($mask -band 8) -ne 0}
   $truth=Get-CoreSiteHealth $page $ping $openai $github
   $ytOk=[bool]($page.ok -and $ping.ok)
   $expectedPassed=[int]$ytOk+[int]$openai.ok+[int]$github.ok
   $expectedHealthy=$expectedPassed -eq 3
   $list=@($truth.unreachableCoreSites)
   if([int]$truth.required -ne 2 -or
      [int]$truth.passed -ne $expectedPassed -or
      [bool]$truth.allCoreSitesOk -ne $expectedHealthy -or
      ($truth.reachability -eq 'HEALTHY') -ne $expectedHealthy -or
      ($list -contains 'youtube') -ne (-not $ytOk) -or
      ($list -contains 'openai') -ne (-not $openai.ok) -or
      ($list -contains 'github') -ne (-not $github.ok)){
     throw "R720_CORE_SITE_TRUTH_TABLE_MISMATCH_$mask"
   }
}
Write-Output 'R720_PRODUCTION_NATIVE_POWERSHELL_16_OF_16_TRUTH_PASS'
'''
    with tempfile.TemporaryDirectory(prefix="dim-r720-native-") as d:
        p=pathlib.Path(d)/"verify.ps1"
        p.write_text(code,encoding="utf-8")
        result=subprocess.run([native,"-NoProfile","-NonInteractive","-File",
              str(p),str(SCRIPT)],capture_output=True,text=True,timeout=45)
        assert result.returncode==0,("R720_NATIVE_POWERSHELL_FAILED",result.stdout,result.stderr)
        assert "16_OF_16_TRUTH_PASS" in result.stdout,"R720_NATIVE_SCRIPT_NOT_PROVEN"
        print(result.stdout.strip())
else:
    print("R720_STATIC_GUARDS_PASS_NONWINDOWS_NATIVE_MATRIX_DEFERRED")
print("R720_WINDOWS_ENGINE_YOUTUBE_PAGE_AND_204_FULL_HEALTH_CONTRACT_PASS")
