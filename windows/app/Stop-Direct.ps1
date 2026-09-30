[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

$Root=Split-Path $PSScriptRoot -Parent
$CtrldDir=Join-Path $Root 'bin\ctrld'
$CtrldSock=Join-Path $CtrldDir 'ctrld_control.sock'
$ZapretDir=Join-Path $Root 'bin\zapret'
$Runtime=Join-Path $env:ProgramData 'DirectDnsDpiHarness'
$RuntimeCtrld=Join-Path $Runtime 'ctrld'
$StatePath=Join-Path $Runtime 'state.json'
$Evidence=Join-Path $Root 'evidence\stop-latest.json'
$Ula='fd53:4444:48::53'
$LoopbackIndex=1
$NrptDisplay='DirectDnsDpiHarness'
$NrptComment='Owned by DirectDnsDpiHarness; safe to remove only by this harness.'

function Test-Admin{
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 $p=[Security.Principal.WindowsPrincipal]::new($id)
 return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Write-JsonAtomic([string]$Path,$Value){
 $d=Split-Path -Parent $Path
 New-Item -ItemType Directory -Force -Path $d|Out-Null
 $tmp=$Path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
 [IO.File]::WriteAllText($tmp,($Value|ConvertTo-Json -Depth 24),[Text.UTF8Encoding]::new($false))
 [IO.File]::Move($tmp,$Path,$true)
}
function Same-Path([string]$A,[string]$B){
 try{
  $aa=[IO.Path]::GetFullPath($A).TrimEnd('\')
  $bb=[IO.Path]::GetFullPath($B).TrimEnd('\')
  return [string]::Equals($aa,$bb,[StringComparison]::OrdinalIgnoreCase)
 }catch{return $false}
}
function Same-Json($a,$b){($a|ConvertTo-Json -Depth 20 -Compress) -eq ($b|ConvertTo-Json -Depth 20 -Compress)}
function Get-Ics{
 $s=Get-CimInstance Win32_Service -Filter "Name='SharedAccess'" -ErrorAction SilentlyContinue
 if(-not $s){return [ordered]@{exists=$false;state='';pid=0}}
 [ordered]@{exists=$true;state=[string]$s.State;pid=[int64]$s.ProcessId}
}
function Get-ExternalNrpt([string]$OwnedName){
 @(
  Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
   Where-Object {$_.Name -ne $OwnedName} |
   Sort-Object Name |
   ForEach-Object {
    [ordered]@{
     Name=[string]$_.Name;DisplayName=[string]$_.DisplayName
     Namespace=@($_.Namespace|ForEach-Object{[string]$_})
     NameServers=@($_.NameServers|ForEach-Object{[string]$_})
     Comment=[string]$_.Comment
    }
   }
 )
}
function Get-BroadRoutes{
 @(
  foreach($prefix in @('0.0.0.0/1','128.0.0.0/1')){
   Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
    Sort-Object InterfaceIndex,NextHop,RouteMetric |
    ForEach-Object {
     [ordered]@{
      DestinationPrefix=[string]$_.DestinationPrefix
      InterfaceIndex=[int]$_.InterfaceIndex
      InterfaceAlias=[string]$_.InterfaceAlias
      NextHop=[string]$_.NextHop
      RouteMetric=[int]$_.RouteMetric
     }
    }
  }
 )
}
function Get-OwnedDrivers{
 @(
  Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
   Where-Object {$_.Name -match '^WinDivert' -and $_.PathName -and $_.PathName.Contains($Root,[StringComparison]::OrdinalIgnoreCase)}
 )
}
function Stop-OwnedWinws{
 Get-Process winws -ErrorAction SilentlyContinue |
  Where-Object {$_.Path -and $_.Path.StartsWith($ZapretDir,[StringComparison]::OrdinalIgnoreCase)} |
  Stop-Process -Force -ErrorAction SilentlyContinue
 Start-Sleep -Milliseconds 250
 foreach($d in @(Get-OwnedDrivers)){
  & sc.exe stop $d.Name|Out-Null
  Start-Sleep -Milliseconds 100
  & sc.exe delete $d.Name|Out-Null
 }
 Start-Sleep -Milliseconds 300
}
function Get-OwnedCtrld{
 @(Get-Process ctrld -ErrorAction SilentlyContinue|Where-Object{$_.Path -and $_.Path.StartsWith($CtrldDir,[StringComparison]::OrdinalIgnoreCase)})
}
function Get-Ula{
 @(Get-NetIPAddress -InterfaceIndex $LoopbackIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue|Where-Object IPAddress -eq $Ula)
}

if(-not(Test-Admin)){
 $p=Start-Process pwsh.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath) -PassThru -Wait
 exit $p.ExitCode
}

if(-not(Test-Path -LiteralPath $StatePath)){
 $ownedRules=@(Get-DnsClientNrptRule -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName -eq $NrptDisplay -and $_.Comment -eq $NrptComment})
 foreach($r in $ownedRules){Remove-DnsClientNrptRule -Name $r.Name -Force -ErrorAction SilentlyContinue}
 Clear-DnsClientCache -ErrorAction SilentlyContinue
 Get-OwnedCtrld|Stop-Process -Force -ErrorAction SilentlyContinue
 Stop-OwnedWinws
 Remove-Item -LiteralPath $RuntimeCtrld -Recurse -Force -ErrorAction SilentlyContinue
 $r=[ordered]@{status='PASS_NO_STATE';ownedNrptRemoved=$ownedRules.Count;note='ULA is not removed without state ownership evidence.'}
 Write-JsonAtomic $Evidence $r
 $r|ConvertTo-Json -Depth 6
 return
}

$s=Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8|ConvertFrom-Json
if(-not $s.root -or -not(Same-Path ([string]$s.root) $Root)){throw 'STATE_ROOT_OWNERSHIP_MISMATCH'}
$ownedName=[string]$s.nrptRuleName
$before=[ordered]@{
 dnsV4=@((Get-DnsClientServerAddress -InterfaceAlias ([string]$s.interface) -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
 dnsV6=@((Get-DnsClientServerAddress -InterfaceAlias ([string]$s.interface) -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses)
 externalNrpt=@(Get-ExternalNrpt $ownedName)
 broadRoutes=@(Get-BroadRoutes)
 winHttp=(netsh winhttp show proxy|Out-String).Trim()
 ics=Get-Ics
}
$actions=@()
try{
 if($ownedName){
  $r=Get-DnsClientNrptRule -Name $ownedName -ErrorAction SilentlyContinue
  if($r){
   if([string]$r.DisplayName -ne $NrptDisplay -or [string]$r.Comment -ne $NrptComment){throw 'NRPT_OWNERSHIP_MISMATCH'}
   Remove-DnsClientNrptRule -Name $ownedName -Force
  }
  $actions+='Removed owned NRPT catch-all'
 }
 Clear-DnsClientCache -ErrorAction SilentlyContinue

 if($s.winwsPid){
  $wp=Get-Process -Id ([int]$s.winwsPid) -ErrorAction SilentlyContinue
  if($wp -and $wp.Path -and $wp.Path.StartsWith($ZapretDir,[StringComparison]::OrdinalIgnoreCase)){Stop-Process -Id $wp.Id -Force -ErrorAction SilentlyContinue}
 }
 Stop-OwnedWinws
 $actions+='Stopped owned winws and WinDivert'

 if($s.ctrldPid){
  $cp=Get-Process -Id ([int]$s.ctrldPid) -ErrorAction SilentlyContinue
  if($cp -and $cp.Path -and $cp.Path.StartsWith($CtrldDir,[StringComparison]::OrdinalIgnoreCase)){Stop-Process -Id $cp.Id -Force -ErrorAction SilentlyContinue}
 }
 Get-OwnedCtrld|Stop-Process -Force -ErrorAction SilentlyContinue
 Start-Sleep -Milliseconds 350
 Remove-Item -LiteralPath $CtrldSock -Force -ErrorAction SilentlyContinue
 $actions+='Stopped owned ctrld'

 if([bool]$s.ulaCreated){
  $a=@(Get-Ula)
  if($a.Count){
   if([int]$a[0].PrefixLength -ne 128 -or -not [bool]$a[0].SkipAsSource){throw 'ULA_OWNERSHIP_MISMATCH'}
   Remove-NetIPAddress -InterfaceIndex $LoopbackIndex -IPAddress $Ula -AddressFamily IPv6 -Confirm:$false -ErrorAction Stop
  }
  $actions+='Removed owned loopback ULA'
 }
 Remove-Item -LiteralPath $RuntimeCtrld -Recurse -Force -ErrorAction SilentlyContinue
 Clear-DnsClientCache -ErrorAction SilentlyContinue
 Start-Sleep -Milliseconds 350

 $post=[ordered]@{
  dnsV4=@((Get-DnsClientServerAddress -InterfaceAlias ([string]$s.interface) -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
  dnsV6=@((Get-DnsClientServerAddress -InterfaceAlias ([string]$s.interface) -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses)
  externalNrpt=@(Get-ExternalNrpt $ownedName)
  broadRoutes=@(Get-BroadRoutes)
  winHttp=(netsh winhttp show proxy|Out-String).Trim()
  ics=Get-Ics
  ownedNrptCount=@(Get-DnsClientNrptRule -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName -eq $NrptDisplay -and $_.Comment -eq $NrptComment}).Count
  ulaCount=@(Get-Ula).Count
  ctrldOwnedCount=@(Get-OwnedCtrld).Count
  winwsOwnedCount=@(Get-Process winws -ErrorAction SilentlyContinue|Where-Object{$_.Path -and $_.Path.StartsWith($ZapretDir,[StringComparison]::OrdinalIgnoreCase)}).Count
  driverOwnedCount=@(Get-OwnedDrivers).Count
  runtimeCtrldExists=(Test-Path -LiteralPath $RuntimeCtrld)
  ctrldSocketExists=(Test-Path -LiteralPath $CtrldSock)
 }
 if(($post.dnsV4 -join '|') -ne ($before.dnsV4 -join '|')){throw 'STOP_MUTATED_ADAPTER_DNSV4'}
 if(($post.dnsV6 -join '|') -ne ($before.dnsV6 -join '|')){throw 'STOP_MUTATED_ADAPTER_DNSV6'}
 if(-not(Same-Json @($post.externalNrpt) @($before.externalNrpt))){throw 'STOP_MUTATED_EXTERNAL_NRPT'}
 if(-not(Same-Json @($post.broadRoutes) @($before.broadRoutes))){throw 'STOP_MUTATED_EXTERNAL_ROUTES'}
 if($post.winHttp -ne $before.winHttp){throw 'STOP_MUTATED_WINHTTP'}
 if(-not(Same-Json $post.ics $before.ics)){throw 'STOP_MUTATED_ICS'}
 if($post.ownedNrptCount -or $post.ctrldOwnedCount -or $post.winwsOwnedCount -or $post.driverOwnedCount -or $post.runtimeCtrldExists -or $post.ctrldSocketExists){throw 'STOP_OWNED_RESIDUE'}
 if([bool]$s.ulaCreated -and $post.ulaCount){throw 'STOP_ULA_RESIDUE'}

 Remove-Item -LiteralPath $StatePath -Force
 $result=[ordered]@{status='PASS';actions=$actions;externalPreserved=$true;before=$before;post=$post}
 Write-JsonAtomic $Evidence $result
 $result|ConvertTo-Json -Depth 16
 return
}catch{
 $result=[ordered]@{status='FAIL';actions=$actions;error=$_.Exception.Message;stack=$_.ScriptStackTrace}
 Write-JsonAtomic $Evidence $result
 $result|ConvertTo-Json -Depth 10
 throw ('STOP_FAIL_'+$result.error)
}
