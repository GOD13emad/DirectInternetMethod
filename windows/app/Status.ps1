[CmdletBinding()]
param([switch]$Json)
Set-StrictMode -Version Latest
$ErrorActionPreference='SilentlyContinue'

$Root=Split-Path $PSScriptRoot -Parent
$Runtime=Join-Path $env:ProgramData 'DirectDnsDpiHarness'
$StatePath=Join-Path $Runtime 'state.json'
$CtrldDir=Join-Path $Root 'bin\ctrld'
$CtrldSock=Join-Path $CtrldDir 'ctrld_control.sock'
$ZapretDir=Join-Path $Root 'bin\zapret'
$Ula='fd53:4444:48::53'
$NrptDisplay='DirectDnsDpiHarness'

function Resolve-PhysicalDefault{
 $r=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
   Where-Object {$_.State -eq 'Alive'} |
   Sort-Object @{Expression={[int]$_.RouteMetric+[int]$_.InterfaceMetric}},RouteMetric,InterfaceMetric |
   Select-Object -First 1
 if(-not $r){return $null}
 $a=Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction SilentlyContinue
 $ip=Get-NetIPAddress -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
   Where-Object {$_.IPAddress -and $_.IPAddress -notlike '169.254.*'} | Select-Object -First 1
 if(-not $a -or -not $ip){return $null}
 [pscustomobject]@{Alias=[string]$a.Name;LocalIp=[string]$ip.IPAddress;Description=[string]$a.InterfaceDescription}
}
function ProbeDns([string]$Name){
 try{
  $sw=[Diagnostics.Stopwatch]::StartNew()
  $a=@([Net.Dns]::GetHostAddresses($Name)|Where-Object AddressFamily -eq InterNetwork|ForEach-Object IPAddressToString|Select-Object -Unique)
  $sw.Stop()
  [ordered]@{ok=($a.Count -gt 0);ms=$sw.ElapsedMilliseconds;answers=$a}
 }catch{[ordered]@{ok=$false;ms=-1;answers=@();error=$_.Exception.Message}}
}
$route=Resolve-PhysicalDefault
$state=$null
if(Test-Path $StatePath){try{$state=Get-Content -Raw -Encoding UTF8 $StatePath|ConvertFrom-Json}catch{}}
$ctrld=@(Get-Process ctrld -ErrorAction SilentlyContinue|Where-Object{$_.Path -and $_.Path.StartsWith($CtrldDir,[StringComparison]::OrdinalIgnoreCase)})
$winws=@(Get-Process winws -ErrorAction SilentlyContinue|Where-Object{$_.Path -and $_.Path.StartsWith($ZapretDir,[StringComparison]::OrdinalIgnoreCase)})
$nrpt=@(Get-DnsClientNrptRule -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName -eq $NrptDisplay}|Select-Object Name,Namespace,NameServers,Comment)
$ula=@(Get-NetIPAddress -InterfaceIndex 1 -AddressFamily IPv6 -ErrorAction SilentlyContinue|Where-Object IPAddress -eq $Ula|Select-Object IPAddress,PrefixLength,AddressState,SkipAsSource)
$drivers=@(Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue|Where-Object{$_.Name -match '^WinDivert' -and $_.PathName -and $_.PathName.Contains($Root,[StringComparison]::OrdinalIgnoreCase)}|Select-Object Name,State,PathName)
$broad=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
$proxy=(netsh winhttp show proxy|Out-String).Trim()
$ics=Get-CimInstance Win32_Service -Filter "Name='SharedAccess'" -ErrorAction SilentlyContinue
$active=($state -and [string]$state.phase -eq 'ACTIVE' -and $ctrld.Count -eq 1 -and $winws.Count -eq 1 -and $nrpt.Count -eq 1 -and $ula.Count -eq 1 -and $drivers.Count -ge 1)
$sock=[bool](Test-Path -LiteralPath $CtrldSock)
$degraded=(-not $active -and ($state -or $ctrld.Count -or $winws.Count -or $nrpt.Count -or $ula.Count -or $drivers.Count -or $sock))
$mode=if($active){'ACTIVE'}elseif($degraded){'DEGRADED'}else{'OFF'}
$result=[ordered]@{
 mode=$mode
 statePhase=if($state){[string]$state.phase}else{$null}
 interface=if($route){$route.Alias}else{$null}
 localIp=if($route){$route.LocalIp}else{$null}
 adapterDns=if($route){@((Get-DnsClientServerAddress -InterfaceAlias $route.Alias -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)}else{@()}
 ula=$ula
 nrpt=$nrpt
 ctrldPid=if($ctrld.Count){$ctrld[0].Id}else{0}
 winwsPid=if($winws.Count){$winws[0].Id}else{0}
 winDivertCount=$drivers.Count
 ctrldSocketExists=$sock
 broadRouteCount=$broad.Count
 winHttpDirect=($proxy -match 'Direct access')
 ics=if($ics){[ordered]@{state=[string]$ics.State;pid=[int64]$ics.ProcessId}}else{$null}
 dnsTest=if($active){[ordered]@{youtube=(ProbeDns 'www.youtube.com');github=(ProbeDns 'github.com');openai=(ProbeDns 'api.openai.com')}}else{$null}
}
if($Json){$result|ConvertTo-Json -Depth 12;exit 0}
Write-Host ''
Write-Host ('Direct Internet status: '+$mode)
Write-Host ('Interface: '+$result.interface+'  IP: '+$result.localIp)
Write-Host ('Adapter DNS: '+(@($result.adapterDns)-join ', '))
Write-Host ('Owned ULA: '+$ula.Count+' | NRPT: '+$nrpt.Count+' | ctrld: '+$ctrld.Count+' | winws: '+$winws.Count+' | WinDivert: '+$drivers.Count)
Write-Host ('Broad tunnel routes: '+$broad.Count+' | WinHTTP direct: '+$result.winHttpDirect)
if($ics){Write-Host ('ICS: '+$ics.State+' PID '+$ics.ProcessId)}
if($active){
 foreach($k in @('youtube','github','openai')){
  $d=$result.dnsTest[$k]
  Write-Host ('DNS '+$k+': '+($(if($d.ok){'PASS'}else{'FAIL'}))+' '+$d.ms+'ms')
 }
}
Write-Host ''
