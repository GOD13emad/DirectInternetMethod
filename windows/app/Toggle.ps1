[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Start=Join-Path $PSScriptRoot 'Start-Direct.ps1'
$Stop=Join-Path $PSScriptRoot 'Stop-Direct.ps1'
$Status=Join-Path $PSScriptRoot 'Status.ps1'
$raw=@(& pwsh.exe -NoProfile -ExecutionPolicy Bypass -File $Status -Json 2>&1)
if($LASTEXITCODE -ne 0){throw 'STATUS_READ_FAIL'}
$s=($raw -join [Environment]::NewLine)|ConvertFrom-Json
if([string]$s.mode -eq 'ACTIVE'){
 & pwsh.exe -NoProfile -ExecutionPolicy Bypass -File $Stop
}else{
 & pwsh.exe -NoProfile -ExecutionPolicy Bypass -File $Start
}
$code=$LASTEXITCODE
& pwsh.exe -NoProfile -ExecutionPolicy Bypass -File $Status
exit $code
