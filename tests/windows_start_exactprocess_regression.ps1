$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot '..\windows\app\Start-Direct.ps1'
$raw=Get-Content $path -Raw
if($raw -match '\[string\[\]\]\$Args\b'){throw 'RESERVED_ARGS_PARAMETER_REGRESSION'}
if($raw -notmatch 'function\s+Start-ExactProcess\(\[string\]\$File,\[string\[\]\]\$ArgumentList,\[string\]\$WorkingDirectory\)'){
  throw 'START_EXACT_PROCESS_SIGNATURE_MISMATCH'
}
function Test-Binding([string]$File,[string[]]$ArgumentList,[string]$WorkingDirectory){
  [pscustomobject]@{File=$File;Count=$ArgumentList.Count;Values=@($ArgumentList);Work=$WorkingDirectory}
}
$r=Test-Binding 'ctrld.exe' @('-s','run','-c','C:\ProgramData\DirectDnsDpiHarness\ctrld\ctrld.toml') 'C:\ProgramData\DirectDnsDpiHarness\ctrld'
if($r.Count -ne 4){throw ('ARGUMENT_BINDING_BAD_COUNT_'+$r.Count)}
if(($r.Values -join '|') -ne '-s|run|-c|C:\ProgramData\DirectDnsDpiHarness\ctrld\ctrld.toml'){throw 'ARGUMENT_BINDING_BAD_VALUES'}
[pscustomobject]@{Status='PASS';Count=$r.Count;Values=$r.Values}|ConvertTo-Json -Depth 4
