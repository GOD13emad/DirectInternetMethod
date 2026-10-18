#!/usr/bin/env python3
"""R726: privileged Windows Start must never resolve curl.exe from PATH.

Read-only native exercise of the production Curl-Probe function (via PowerShell AST).
The chosen target is closed IPv4 loopback port 1, with no SCM, engine, DNS or
network configuration changes. A genuine Microsoft executable copied under the
name curl.exe is placed first on PATH to prove that the system-owned curl wins.
"""
from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "windows/app/Start-Direct.ps1"
source = SOURCE.read_text(encoding="utf-8-sig")
functions = re.findall(
    r"^function Curl-Probe\([^\r\n]*\)\{\s*\n.*?^\}",
    source,
    flags=re.MULTILINE | re.DOTALL,
)
assert len(functions) == 1, "R726_PRIVILEGED_CURL_FUNCTION_NOT_UNIQUE"
fn = functions[0]
assert fn.count("Join-Path ([Environment]::SystemDirectory) 'curl.exe'") == 1, \
    "R726_SYSTEM32_CURL_NOT_PINNED"
assert "if(-not [IO.File]::Exists($SystemCurl)){throw 'WINDOWS_SYSTEM_CURL_MISSING'}" in fn, \
    "R726_MISSING_FAIL_CLOSED_GUARD"
assert "$m=& $SystemCurl -4 --interface $LocalIp --noproxy '*'" in fn, \
    "R726_CURL_CALL_NOT_ABSOLUTE"
assert "& curl.exe" not in fn and "Invoke-Expression" not in fn, \
    "R726_PATH_OR_SHELL_RESOLUTION_FORBIDDEN"
assert "%{http_code}|%{remote_ip}|%{time_connect}|%{time_appconnect}|%{time_total}" in fn, \
    "R726_PROBE_OUTPUT_CONTRACT_CHANGED"
assert "$LASTEXITCODE" in fn and "--max-time $Timeout" in fn, \
    "R726_NATIVE_EXIT_AND_TIMEOUT_PRESERVATION"

pwsh = shutil.which("pwsh")
if sys.platform == "win32":
    assert pwsh, "R726_NATIVE_WINDOWS_PWSH_REQUIRED"

if pwsh:
    verify = r"""
$ErrorActionPreference='Stop'
$PSNativeCommandUseErrorActionPreference=$false
$native=$args[0]
$fixture=$args[1]
$windowsCurl=Join-Path ([Environment]::SystemDirectory) 'curl.exe'
$decoySource=Join-Path ([Environment]::SystemDirectory) 'whoami.exe'
if(-not (Test-Path -LiteralPath $windowsCurl -PathType Leaf)){throw 'R726_WINDOWS_CURL_NOT_PRESENT'}
if(-not (Test-Path -LiteralPath $decoySource -PathType Leaf)){throw 'R726_WINDOWS_DECOY_FIXTURE_MISSING'}
Copy-Item -LiteralPath $decoySource -Destination (Join-Path $fixture 'curl.exe') -ErrorAction Stop
$tokens=$null
$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($native,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'R726_PRODUCTION_SOURCE_PARSE_FAILED'}
$defs=@($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Curl-Probe'
},$true))
if($defs.Count -ne 1){throw 'R726_CURL_AST_NOT_UNIQUE'}
. ([scriptblock]::Create($defs[0].Extent.Text))
$oldPath=$env:PATH
try {
    $env:PATH=$fixture+';'+$oldPath
    $resolution=(Get-Command -Name curl.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    if(-not [string]::Equals($resolution,(Join-Path $fixture 'curl.exe'),[StringComparison]::OrdinalIgnoreCase)){
        throw ('R726_PATH_DECOY_NOT_FIRST_'+$resolution)
    }
    # The production function must choose the OS-owned executable, not the decoy.
    # Port 1 is local, closed, and never uses a real external network.
    $probe=Curl-Probe 'https://127.0.0.1:1/' '127.0.0.1' 1
    if([int]$probe.exit -notin @(7,28)){
        throw ('R726_NATIVE_EXIT_NOT_SYSTEM_CURL_'+$probe.exit+'_'+$probe.meta)
    }
    if([string]$probe.meta -notmatch 'curl:.*\((7|28)\)'){
        throw ('R726_NATIVE_CURL_OUTPUT_MISSING_'+$probe.meta)
    }
    Write-Output 'R726_NATIVE_SYSTEM_CURL_PATH_DECOY_PASS'
}
finally {
    $env:PATH=$oldPath
}
"""
    with tempfile.TemporaryDirectory(prefix="dim-r726-curl-") as td:
        script = pathlib.Path(td) / "verify.ps1"
        script.write_text(verify, encoding="utf-8")
        result = subprocess.run(
            [pwsh, "-NoProfile", "-NonInteractive", "-File", str(script), str(SOURCE), td],
            capture_output=True,
            text=True,
            timeout=35,
        )
        assert result.returncode == 0, (
            "R726_NATIVE_PATH_DECOY_FAILED",
            result.stdout,
            result.stderr,
        )
        assert "R726_NATIVE_SYSTEM_CURL_PATH_DECOY_PASS" in result.stdout, \
            "R726_NATIVE_ACCEPTANCE_RECEIPT_MISSING"
        print(result.stdout.strip())
else:
    print("R726_STATIC_ONLY_NONWINDOWS_NATIVE_HOST_TEST_DEFERRED")

print("R726_PRIVILEGED_START_SYSTEM_CURL_PIN_CONTRACT_PASS")
