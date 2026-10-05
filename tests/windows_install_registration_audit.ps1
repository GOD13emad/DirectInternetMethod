$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$Root=Split-Path $PSScriptRoot -Parent
$Release=Get-Content (Join-Path $Root 'RELEASE.json') -Raw | ConvertFrom-Json
$ExpectedVersion=[string]$Release.version
$AppId='{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}_is1'
$Hklm="HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$AppId"
$Hkcu="HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$AppId"

function UninstallExe([string]$Raw) {
  if([string]::IsNullOrWhiteSpace($Raw)){return ''}
  $m=[regex]::Match($Raw,'^\s*"([^"]+)"')
  if($m.Success){return $m.Groups[1].Value}
  $m=[regex]::Match($Raw,'^\s*([^\s]+)')
  if($m.Success){return $m.Groups[1].Value}
  return ''
}

$current=$null
if(Test-Path -LiteralPath $Hklm){$current=Get-ItemProperty -LiteralPath $Hklm}
$install=if($null -ne $current){[string]$current.InstallLocation}else{''}
$uninstall=if($null -ne $current){UninstallExe ([string]$current.UninstallString)}else{''}

$checks=[ordered]@{
  allUsersRegistrationExists=(Test-Path -LiteralPath $Hklm)
  displayVersionMatches=($null -ne $current -and [string]$current.DisplayVersion -eq $ExpectedVersion)
  publisherMatches=($null -ne $current -and [string]$current.Publisher -eq 'Direct Internet Method')
  installLocationPresent=(-not [string]::IsNullOrWhiteSpace($install))
  releaseJsonPresent=(-not [string]::IsNullOrWhiteSpace($install) -and (Test-Path -LiteralPath (Join-Path $install 'RELEASE.json')))
  manifestPresent=(-not [string]::IsNullOrWhiteSpace($install) -and (Test-Path -LiteralPath (Join-Path $install 'manifest.json')))
  guiPresent=(-not [string]::IsNullOrWhiteSpace($install) -and (Test-Path -LiteralPath (Join-Path $install 'app\DirectInternetMethod.exe')))
  registeredUninstallerPresent=(-not [string]::IsNullOrWhiteSpace($uninstall) -and (Test-Path -LiteralPath $uninstall))
  noSameAppIdPerUserDuplicate=(-not (Test-Path -LiteralPath $Hkcu))
}

$installedVersion=''
if($checks.releaseJsonPresent){
  try {$installedVersion=[string](Get-Content (Join-Path $install 'RELEASE.json') -Raw | ConvertFrom-Json).version} catch {}
}
$checks['installedReleaseMatches']=($installedVersion -eq $ExpectedVersion)

$status=if(@($checks.Values | Where-Object {-not $_}).Count -eq 0){'PASS'}else{'FAIL'}
[ordered]@{
  schema=1
  status=$status
  expectedVersion=$ExpectedVersion
  current=[ordered]@{
    key=$Hklm
    displayName=if($null -ne $current){[string]$current.DisplayName}else{''}
    displayVersion=if($null -ne $current){[string]$current.DisplayVersion}else{''}
    installLocation=$install
    uninstallExe=$uninstall
  }
  stalePerUserKey=$Hkcu
  checks=$checks
}|ConvertTo-Json -Depth 6
if($status -ne 'PASS'){exit 31}
