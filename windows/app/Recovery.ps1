[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

$Root=Split-Path $PSScriptRoot -Parent
$Runtime=Join-Path $env:ProgramData 'DirectDnsDpiHarness'
$StatePath=Join-Path $Runtime 'state.json'
$RuntimeCtrld=Join-Path $Runtime 'ctrld'
$RuntimeConfig=Join-Path $RuntimeCtrld 'ctrld.toml'
$Stop=Join-Path $PSScriptRoot 'Stop-Direct.ps1'
$CtrldDir=Join-Path $Root 'bin\ctrld'
$Ctrld=Join-Path $CtrldDir 'ctrld.exe'
$CtrldServiceName='ctrld'
$CtrldSock=Join-Path $CtrldDir 'ctrld_control.sock'
$ZapretDir=Join-Path $Root 'bin\zapret'
$Ula='fd53:4444:48::53'
$LoopbackRoute=Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::1/128' -ErrorAction Stop | Sort-Object RouteMetric | Select-Object -First 1
if(-not $LoopbackRoute){throw 'LOOPBACK_INTERFACE_MISSING'}
$LoopbackIndex=[int]$LoopbackRoute.InterfaceIndex
$NrptDisplay='DirectDnsDpiHarness'
$NrptComment='Owned by DirectDnsDpiHarness; safe to remove only by this harness.'

function IsAdmin{
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 $p=[Security.Principal.WindowsPrincipal]::new($id)
 $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Same-Path([string]$A,[string]$B){
 try{
  $aa=[IO.Path]::GetFullPath($A).TrimEnd('\')
  $bb=[IO.Path]::GetFullPath($B).TrimEnd('\')
  [string]::Equals($aa,$bb,[StringComparison]::OrdinalIgnoreCase)
 }catch{$false}
}
function Get-OwnedDrivers{
 @(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue|Where-Object{$_.Name -match '^WinDivert' -and $_.PathName -and $_.PathName.Contains($Root,[StringComparison]::OrdinalIgnoreCase)})
}

if(-not(IsAdmin)){
 $p=Start-Process pwsh.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath) -Wait -PassThru
 exit $p.ExitCode
}

function Safe-Contains($Value,[string]$Needle){
 try{$s=[string]$Value;return ($s.Length -gt 0 -and $s.Contains($Needle,[StringComparison]::OrdinalIgnoreCase))}catch{return $false}
}
function Get-OwnedCtrldService{
 $svc=Get-CimInstance Win32_Service -Filter "Name='$CtrldServiceName'" -ErrorAction SilentlyContinue
 if(-not $svc){return $null}
 $path=[string]$svc.PathName
 if(-not(Safe-Contains $path $Ctrld) -or -not(Safe-Contains $path $RuntimeConfig) -or -not(Safe-Contains $path 'run -s -c')){throw 'REFUSE_EXTERNAL_CTRLD_SERVICE'}
 return $svc
}
function Stop-OwnedCtrldService{
 $svc=Get-OwnedCtrldService
 if(-not $svc){return}
 if([string]$svc.State -ne 'Stopped'){
  & sc.exe stop $CtrldServiceName|Out-Null
  for($i=0;$i -lt 50;$i++){
   Start-Sleep -Milliseconds 100
   $svc=Get-CimInstance Win32_Service -Filter "Name='$CtrldServiceName'" -ErrorAction SilentlyContinue
   if(-not $svc -or [string]$svc.State -eq 'Stopped'){return}
  }
  throw 'CTRLD_SERVICE_STOP_TIMEOUT'
 }
}

$stateOwned=$false
if(Test-Path $StatePath){
 $s=$null
 try{$s=Get-Content $StatePath -Raw -Encoding UTF8|ConvertFrom-Json}catch{throw 'STATE_UNREADABLE'}
 if(-not $s.root -or -not(Same-Path ([string]$s.root) $Root)){throw 'STATE_ROOT_OWNERSHIP_MISMATCH'}
 $stateOwned=$true
 & pwsh.exe -NoProfile -ExecutionPolicy Bypass -File $Stop
 if($LASTEXITCODE -eq 0){exit 0}
}

$ownedRules=@(Get-DnsClientNrptRule -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName -eq $NrptDisplay -and $_.Comment -eq $NrptComment})
$ctrldSvc=Get-OwnedCtrldService
$ownedCtrld=@(Get-Process ctrld -ErrorAction SilentlyContinue|Where-Object{$_.Path -and $_.Path.StartsWith($CtrldDir,[StringComparison]::OrdinalIgnoreCase)})
$ownedWinws=@(Get-Process winws -ErrorAction SilentlyContinue|Where-Object{$_.Path -and $_.Path.StartsWith($ZapretDir,[StringComparison]::OrdinalIgnoreCase)})
$ownedDrivers=@(Get-OwnedDrivers)
$runtimeExists=Test-Path $RuntimeCtrld
$ulaCandidates=@(Get-NetIPAddress -InterfaceIndex $LoopbackIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue|Where-Object IPAddress -eq $Ula)
$ownedUla=$false
if($ulaCandidates.Count -gt 1){throw 'ULA_OWNERSHIP_AMBIGUOUS'}
if($ulaCandidates.Count -eq 1){
 $u=$ulaCandidates[0]
 if([int]$u.PrefixLength -ne 128 -or -not [bool]$u.SkipAsSource){throw 'ULA_OWNERSHIP_MISMATCH'}
 $ownedUla=$true
}
$corroborated=($stateOwned -or $ownedRules.Count -gt 0 -or $ownedCtrld.Count -gt 0 -or $ownedWinws.Count -gt 0 -or $ownedDrivers.Count -gt 0 -or $runtimeExists -or $ownedUla)

foreach($r in $ownedRules){Remove-DnsClientNrptRule -Name $r.Name -Force -ErrorAction SilentlyContinue}
Clear-DnsClientCache -ErrorAction SilentlyContinue
$ownedWinws|Stop-Process -Force -ErrorAction SilentlyContinue
Stop-OwnedCtrldService
Start-Sleep -Milliseconds 300
Remove-Item -LiteralPath $CtrldSock -Force -ErrorAction SilentlyContinue
foreach($d in $ownedDrivers){& sc.exe stop $d.Name|Out-Null;Start-Sleep -Milliseconds 100;& sc.exe delete $d.Name|Out-Null}
Start-Sleep -Milliseconds 300

if($ownedUla){
 Remove-NetIPAddress -InterfaceIndex $LoopbackIndex -IPAddress $Ula -AddressFamily IPv6 -Confirm:$false -ErrorAction Stop
}
Remove-Item -LiteralPath $RuntimeCtrld -Recurse -Force -ErrorAction SilentlyContinue
if($stateOwned){Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue}
Clear-DnsClientCache -ErrorAction SilentlyContinue

$leftRules=@(Get-DnsClientNrptRule -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName -eq $NrptDisplay -and $_.Comment -eq $NrptComment})
$leftCtrld=@(Get-Process ctrld -ErrorAction SilentlyContinue|Where-Object{$_.Path -and $_.Path.StartsWith($CtrldDir,[StringComparison]::OrdinalIgnoreCase)})
$leftWinws=@(Get-Process winws -ErrorAction SilentlyContinue|Where-Object{$_.Path -and $_.Path.StartsWith($ZapretDir,[StringComparison]::OrdinalIgnoreCase)})
$leftDrivers=@(Get-OwnedDrivers)
$leftUla=@(Get-NetIPAddress -InterfaceIndex $LoopbackIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue|Where-Object IPAddress -eq $Ula)
if($leftRules.Count -or $leftCtrld.Count -or $leftWinws.Count -or $leftDrivers.Count -or $leftUla.Count -or (Test-Path -LiteralPath $CtrldSock)){throw 'RECOVERY_INCOMPLETE'}

Write-Host 'Recovery PASS. Owned Direct Internet resources are clean.'
