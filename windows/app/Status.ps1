[CmdletBinding()]
param([switch]$Json)

Set-StrictMode -Version Latest
$ErrorActionPreference='SilentlyContinue'

$Root=Split-Path $PSScriptRoot -Parent
$PrivilegedRoot=Join-Path $env:ProgramFiles 'DirectInternetMethod\Privileged'
$StatePath=Join-Path $env:ProgramData 'DirectDnsDpiHarness\state.json'
$Ula='fd53:4444:48::53'
$NrptDisplay='DirectDnsDpiHarness'
$NrptComment='Owned by DirectDnsDpiHarness; safe to remove only by this harness.'

function Same-Path([string]$A,[string]$B){
 try{
  return [string]::Equals([IO.Path]::GetFullPath($A),[IO.Path]::GetFullPath($B),[StringComparison]::OrdinalIgnoreCase)
 }catch{return $false}
}

function Get-PidHealth($State,[string]$Property,[string]$ExpectedName){
 $id=0
 if($State -and ($State.PSObject.Properties.Name -contains $Property)){$id=[int]$State.$Property}
 if($id -le 0){return [ordered]@{ok=$false;pid=0;name=''}}
 $p=Get-Process -Id $id -ErrorAction SilentlyContinue
 if(-not $p){return [ordered]@{ok=$false;pid=$id;name=''}}
 $name=[string]$p.ProcessName
 return [ordered]@{ok=[string]::Equals($name,$ExpectedName,[StringComparison]::OrdinalIgnoreCase);pid=$id;name=$name}
}

function Get-PhysicalDefault{
 $rows=@()
 foreach($line in @(& route.exe print -4 0.0.0.0 2>$null)){
  if($line -match '^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)\s+(\S+)\s+(\d+)\s*$'){
   $rows += [pscustomobject]@{NextHop=$matches[1];LocalIp=$matches[2];Metric=[int]$matches[3]}
  }
 }
 $best=$rows|Sort-Object Metric|Select-Object -First 1
 if(-not $best){return $null}
 $ip=Get-NetIPAddress -AddressFamily IPv4 -IPAddress ([string]$best.LocalIp) -ErrorAction SilentlyContinue|Select-Object -First 1
 if(-not $ip){return $null}
 return [pscustomobject]@{Alias=[string]$ip.InterfaceAlias;Index=[int]$ip.InterfaceIndex;LocalIp=[string]$best.LocalIp}
}

function Get-BroadRoutes{
 $out=@()
 foreach($line in @(& route.exe print -4 2>$null)){
  if($line -match '^\s*(0\.0\.0\.0|128\.0\.0\.0)\s+128\.0\.0\.0\s+(\S+)\s+(\S+)\s+(\d+)\s*$'){
   $prefix=if($matches[1] -eq '0.0.0.0'){'0.0.0.0/1'}else{'128.0.0.0/1'}
   $local=[string]$matches[3]
   $ip=Get-NetIPAddress -AddressFamily IPv4 -IPAddress $local -ErrorAction SilentlyContinue|Select-Object -First 1
   $out += [ordered]@{
    prefix=$prefix
    interface=if($ip){[string]$ip.InterfaceAlias}else{$local}
    interfaceIndex=if($ip){[int]$ip.InterfaceIndex}else{0}
    description=if($ip){[string]$ip.InterfaceAlias}else{$local}
    nextHop=[string]$matches[2]
   }
  }
 }
 return $out
}

function Get-IcsStatus{
 $raw=(& sc.exe queryex SharedAccess 2>$null|Out-String)
 if(-not $raw){return $null}
 $state=if($raw -match 'STATE\s+:\s+4\s+RUNNING'){'Running'}elseif($raw -match 'STATE\s+:\s+1\s+STOPPED'){'Stopped'}else{'Unknown'}
 $pid=0
 if($raw -match 'PID\s+:\s+(\d+)'){$pid=[int64]$matches[1]}
 return [ordered]@{state=$state;pid=$pid}
}

$state=$null
if(Test-Path -LiteralPath $StatePath){
 try{$state=Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8|ConvertFrom-Json}catch{}
}
$rootOk=[bool]($state -and $state.root -and ((Same-Path ([string]$state.root) $Root) -or (Same-Path ([string]$state.root) $PrivilegedRoot)))

if($rootOk -and $state.interface -and $state.localIp){
 $route=[pscustomobject]@{Alias=[string]$state.interface;Index=0;LocalIp=[string]$state.localIp}
}else{
 $route=Get-PhysicalDefault
}

$ctrld=Get-PidHealth $state 'ctrldPid' 'ctrld'
$winws=Get-PidHealth $state 'winwsPid' 'winws'

$nrpt=@()
$ownedNrpt=@()
if($state -and $state.nrptRuleName){
 $candidate=Get-DnsClientNrptRule -Name ([string]$state.nrptRuleName) -ErrorAction SilentlyContinue
 if($candidate -and [string]$candidate.DisplayName -eq $NrptDisplay){
  $ownedNrpt=@($candidate)
  if([string]$candidate.Comment -eq $NrptComment){
   $nrpt=@($candidate|Select-Object Name,Namespace,NameServers,Comment)
  }
 }
}else{
 $ownedNrpt=@(Get-DnsClientNrptRule -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName -eq $NrptDisplay})
}

$ula=@(
 Get-NetIPAddress -InterfaceIndex 1 -AddressFamily IPv6 -ErrorAction SilentlyContinue |
 Where-Object IPAddress -eq $Ula |
 Select-Object IPAddress,PrefixLength,AddressState,SkipAsSource
)
$broad=@(Get-BroadRoutes)

$ownedHealthy=[bool](
 $state -and
 [string]$state.phase -eq 'ACTIVE' -and
 $rootOk -and
 $ctrld.ok -and
 $winws.ok -and
 $nrpt.Count -eq 1 -and
 $ula.Count -eq 1
)
$anyOwned=[bool]($state -or $ownedNrpt.Count -or $ula.Count -or $ctrld.pid -or $winws.pid)
$conflict=[bool]($ownedHealthy -and $broad.Count -gt 0)
$blocked=[bool]((-not $anyOwned) -and $broad.Count -gt 0)

$mode=if($conflict){'CONFLICT'}elseif($ownedHealthy){'ACTIVE'}elseif($anyOwned){'DEGRADED'}elseif($blocked){'BLOCKED'}else{'OFF'}

$adapterDns=[string[]]@()
if($route){
 $adapterDns=[string[]]@((Get-DnsClientServerAddress -InterfaceAlias $route.Alias -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)
}

$reason=switch($mode){
 'ACTIVE' {'Direct Method resources are healthy.'}
 'CONFLICT' {'Direct Method resources are healthy, but another VPN/tunnel owns broad /1 routes.'}
 'BLOCKED' {'Another VPN/tunnel owns broad /1 routes; disconnect it before Start.'}
 'DEGRADED' {'Owned state/resources are incomplete or mismatched. Use Recovery.'}
 default {'Direct Method is off.'}
}

$proxy=(netsh winhttp show proxy|Out-String).Trim()
$ics=Get-IcsStatus

$result=[ordered]@{
 mode=$mode
 reason=$reason
 statePhase=if($state){[string]$state.phase}else{$null}
 stateRootOk=$rootOk
 ownedResourcesHealthy=$ownedHealthy
 externalRouteConflict=($conflict -or $blocked)
 interface=if($route){$route.Alias}else{$null}
 localIp=if($route){$route.LocalIp}else{$null}
 adapterDns=$adapterDns
 ula=$ula
 nrpt=$nrpt
 ctrldPid=if($ctrld.ok){$ctrld.pid}else{0}
 winwsPid=if($winws.ok){$winws.pid}else{0}
 ctrldState=$ctrld
 winwsState=$winws
 winDivertCount=if($winws.ok){1}else{0}
 broadRouteCount=$broad.Count
 broadRoutes=$broad
 winHttpDirect=($proxy -match 'Direct access')
 ics=$ics
}

if($Json){
 $result|ConvertTo-Json -Depth 10
 exit 0
}
$result|Format-List
