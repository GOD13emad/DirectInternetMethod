[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

$Root=Split-Path $PSScriptRoot -Parent
$CtrldDir=Join-Path $Root 'bin\ctrld'
$Ctrld=Join-Path $CtrldDir 'ctrld.exe'
$CtrldSock=Join-Path $CtrldDir 'ctrld_control.sock'
$CtrldTemplate=Join-Path $CtrldDir 'ctrld.toml'
$CtrldServiceName='ctrld'
$ZapretDir=Join-Path $Root 'bin\zapret'
$Winws=Join-Path $ZapretDir 'winws.exe'
$HostList=Join-Path $ZapretDir 'hosts.txt'
$Runtime=Join-Path $env:ProgramData 'DirectDnsDpiHarness'
$RuntimeCtrld=Join-Path $Runtime 'ctrld'
$RuntimeConfig=Join-Path $RuntimeCtrld 'ctrld.toml'
$StatePath=Join-Path $Runtime 'state.json'
$Evidence=Join-Path $Root 'evidence\runtime-latest.json'
$Ula='fd53:4444:48::53'
$LoopbackRoute=Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::1/128' -ErrorAction Stop | Sort-Object RouteMetric | Select-Object -First 1
if(-not $LoopbackRoute){throw 'LOOPBACK_INTERFACE_MISSING'}
$LoopbackIndex=[int]$LoopbackRoute.InterfaceIndex
$NrptDisplay='DirectDnsDpiHarness'
$NrptComment='Owned by DirectDnsDpiHarness; safe to remove only by this harness.'

$Expected=@{
 'ctrld.exe'='FC966FD7DD5EE850A9709F632789CFB5BBC06C45D903D24B8ECFCE3306B658CD'
 'ctrld.toml'='2E1AF2EF934367465B15284DE93016B839849D717F9A8DC4AC18858FC123EAE2'
 'winws.exe'='A14BFF1DF6234EA555D2E0C61B589F0707C0B12D6C9B7EECCDA76012154996E8'
 'WinDivert.dll'='C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2'
 'WinDivert64.sys'='8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2'
 'cygwin1.dll'='103104A52E5293CE418944725DF19E2BF81AD9269B9A120D71D39028E821499B'
 'hosts.txt'='9C8DBCC6FCFA607BEE4AE16F2DFDEB8D025D66FFD94208A53ED480C2B6892D4B'
}

function Start-ExactProcess([string]$File,[string[]]$ArgumentList,[string]$WorkingDirectory){
 $psi=[Diagnostics.ProcessStartInfo]::new()
 $psi.FileName=$File
 $psi.WorkingDirectory=$WorkingDirectory
 $psi.UseShellExecute=$false
 $psi.CreateNoWindow=$true
 foreach($a in $ArgumentList){[void]$psi.ArgumentList.Add([string]$a)}
 $p=[Diagnostics.Process]::Start($psi)
 if(-not $p){throw ('PROCESS_START_FAILED_'+[IO.Path]::GetFileName($File))}
 return $p
}

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
function Resolve-PhysicalDefault{
 $rs=@(
  Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
   Where-Object {$_.State -eq 'Alive'} |
   Sort-Object @{Expression={[int]$_.RouteMetric+[int]$_.InterfaceMetric}},RouteMetric,InterfaceMetric
 )
 if(-not $rs.Count){throw 'NO_DEFAULT_ROUTE'}
 $r=$rs[0]
 $a=Get-NetAdapter -InterfaceIndex $r.InterfaceIndex -ErrorAction Stop
 $ip=Get-NetIPAddress -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop |
  Where-Object {$_.IPAddress -and $_.IPAddress -notlike '169.254.*'} | Select-Object -First 1
 if($a.Status -ne 'Up' -or -not $ip){throw 'DEFAULT_INTERFACE_UNUSABLE'}
 if($a.InterfaceDescription -match '(?i)Wintun|WireGuard|TAP|TUN|VPN|Loopback'){throw 'DEFAULT_ROUTE_NOT_PHYSICAL'}
 [pscustomobject]@{Alias=[string]$a.Name;Index=[int]$r.InterfaceIndex;LocalIp=[string]$ip.IPAddress;NextHop=[string]$r.NextHop;Description=[string]$a.InterfaceDescription}
}
function Get-Ics{
 $s=Get-CimInstance Win32_Service -Filter "Name='SharedAccess'" -ErrorAction SilentlyContinue
 if(-not $s){return [ordered]@{exists=$false;state='';pid=0}}
 [ordered]@{exists=$true;state=[string]$s.State;pid=[int64]$s.ProcessId}
}
function Get-NrptSignature{
 @(
  Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
   Sort-Object Name |
   ForEach-Object {
    [ordered]@{
     Name=[string]$_.Name
     DisplayName=[string]$_.DisplayName
     Namespace=@($_.Namespace|ForEach-Object{[string]$_})
     NameServers=@($_.NameServers|ForEach-Object{[string]$_})
     Comment=[string]$_.Comment
    }
   }
 )
}
function Safe-StartsWith($Value,[string]$Prefix){
 try{$s=[string]$Value;return ($s.Length -gt 0 -and $s.StartsWith($Prefix,[StringComparison]::OrdinalIgnoreCase))}catch{return $false}
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
function Start-OwnedCtrldService{
 $svc=Get-OwnedCtrldService
 if(-not $svc){throw 'CTRLD_SERVICE_MISSING'}
 if([string]$svc.State -ne 'Running'){
  $o=& sc.exe start $CtrldServiceName 2>&1
  if($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1056){throw ('CTRLD_SERVICE_START_FAILED_'+$LASTEXITCODE+'_'+($o -join ' '))}
 }
 for($i=0;$i -lt 80;$i++){
  Start-Sleep -Milliseconds 100
  $svc=Get-CimInstance Win32_Service -Filter "Name='$CtrldServiceName'" -ErrorAction SilentlyContinue
  if($svc -and [string]$svc.State -eq 'Running' -and [int64]$svc.ProcessId -gt 0){return $svc}
 }
 throw 'CTRLD_SERVICE_NOT_RUNNING'
}

function Get-OwnedDrivers{
 @(
  Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
   Where-Object {$_.Name -match '^WinDivert' -and (Safe-Contains $_.PathName $Root)}
 )
}
function Stop-OwnedWinws{
 Get-Process winws -ErrorAction SilentlyContinue |
  Where-Object {Safe-StartsWith $_.Path $ZapretDir} |
  Stop-Process -Force -ErrorAction SilentlyContinue
 Start-Sleep -Milliseconds 350
 foreach($d in @(Get-OwnedDrivers)){
  & sc.exe stop $d.Name|Out-Null
  Start-Sleep -Milliseconds 200
  & sc.exe delete $d.Name|Out-Null
 }
 Start-Sleep -Milliseconds 500
}
function Get-OwnedCtrld{
 @(
  Get-Process ctrld -ErrorAction SilentlyContinue |
   Where-Object {Safe-StartsWith $_.Path $CtrldDir}
 )
}
function Get-Ula{
 @(Get-NetIPAddress -InterfaceIndex $LoopbackIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue|Where-Object IPAddress -eq $Ula)
}
function Remove-OwnedNrpt([string]$RuleName){
 if(-not $RuleName){return}
 $r=Get-DnsClientNrptRule -Name $RuleName -ErrorAction SilentlyContinue
 if($r){
  if([string]$r.DisplayName -ne $NrptDisplay -or [string]$r.Comment -ne $NrptComment){throw 'NRPT_OWNERSHIP_MISMATCH'}
  Remove-DnsClientNrptRule -Name $RuleName -Force -ErrorAction Stop
 }
}
function Remove-OwnedUla($s){
 $created=$false
 if($s.PSObject.Properties.Name -contains 'ulaCreated'){$created=[bool]$s.ulaCreated}
 if(-not $created){return}
 $a=@(Get-Ula)
 if($a.Count){
  $x=$a[0]
  if([int]$x.PrefixLength -ne 128 -or -not [bool]$x.SkipAsSource){throw 'ULA_OWNERSHIP_MISMATCH'}
  Remove-NetIPAddress -InterfaceIndex $LoopbackIndex -IPAddress $Ula -AddressFamily IPv6 -Confirm:$false -ErrorAction Stop
 }
}
function Dns-Probe([string]$Name){
 try{
  $sw=[Diagnostics.Stopwatch]::StartNew()
  $a=@([Net.Dns]::GetHostAddresses($Name)|Where-Object AddressFamily -eq InterNetwork|ForEach-Object IPAddressToString|Select-Object -Unique)
  $sw.Stop()
  $private=@($a|Where-Object{$_ -match '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.)'})
  [ordered]@{name=$Name;ok=($a.Count -gt 0 -and $private.Count -eq 0);ms=$sw.ElapsedMilliseconds;answers=$a;private=$private}
 }catch{[ordered]@{name=$Name;ok=$false;ms=-1;answers=@();private=@();error=$_.Exception.Message}}
}
function Curl-Probe([string]$Url,[string]$LocalIp,[int]$Timeout=7){
 $m=& curl.exe -4 --interface $LocalIp --noproxy '*' -sS -o NUL -w '%{http_code}|%{remote_ip}|%{time_connect}|%{time_appconnect}|%{time_total}' --max-time $Timeout $Url 2>&1
 [ordered]@{url=$Url;exit=$LASTEXITCODE;meta=($m -join ' ')}
}
function Rollback($s){
 try{Remove-OwnedNrpt ([string]$s.nrptRuleName)}catch{}
 Clear-DnsClientCache -ErrorAction SilentlyContinue
 if($s.PSObject.Properties.Name -contains 'winwsPid' -and $s.winwsPid){
  $wp=Get-Process -Id ([int]$s.winwsPid) -ErrorAction SilentlyContinue
  if($wp -and $wp.Path -and $wp.Path.StartsWith($ZapretDir,[StringComparison]::OrdinalIgnoreCase)){Stop-Process -Id $wp.Id -Force -ErrorAction SilentlyContinue}
 }
 Stop-OwnedWinws
 Stop-OwnedCtrldService
 Start-Sleep -Milliseconds 400
 Remove-Item -LiteralPath $CtrldSock -Force -ErrorAction SilentlyContinue
 try{Remove-OwnedUla $s}catch{}
 Remove-Item -LiteralPath $RuntimeCtrld -Recurse -Force -ErrorAction SilentlyContinue
 Clear-DnsClientCache -ErrorAction SilentlyContinue
 Remove-Item -LiteralPath $StatePath -Force -ErrorAction SilentlyContinue
}

if(-not(Test-Admin)){
 $p=Start-Process pwsh.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath) -PassThru -Wait
 exit $p.ExitCode
}

New-Item -ItemType Directory -Force -Path $Runtime,(Join-Path $Root 'evidence')|Out-Null
$files=@{
 'ctrld.exe'=$Ctrld
 'ctrld.toml'=$CtrldTemplate
 'winws.exe'=$Winws
 'WinDivert.dll'=Join-Path $ZapretDir 'WinDivert.dll'
 'WinDivert64.sys'=Join-Path $ZapretDir 'WinDivert64.sys'
 'cygwin1.dll'=Join-Path $ZapretDir 'cygwin1.dll'
 'hosts.txt'=$HostList
}
foreach($n in $Expected.Keys){
 $p=$files[$n]
 if(-not(Test-Path -LiteralPath $p)){throw ('MISSING_'+$n)}
 if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -ne $Expected[$n]){throw ('HASH_MISMATCH_'+$n)}
}
$ctrldSvc=Get-OwnedCtrldService
if(-not $ctrldSvc){throw 'CTRLD_SERVICE_MISSING'}
if(@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')}).Count){throw 'REFUSE_BROAD_TUNNEL_ROUTE'}

if(Test-Path -LiteralPath $StatePath){
 $old=Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8|ConvertFrom-Json
 $ca=(@(Get-OwnedCtrld).Count -gt 0)
 $wa=(@(Get-Process winws -ErrorAction SilentlyContinue|Where-Object{$_.Path -and $_.Path.StartsWith($ZapretDir,[StringComparison]::OrdinalIgnoreCase)}).Count -gt 0)
 $ua=(@(Get-Ula).Count -eq 1)
 $nr=$false
 if($old.nrptRuleName){$nr=[bool](Get-DnsClientNrptRule -Name ([string]$old.nrptRuleName) -ErrorAction SilentlyContinue)}
 if([string]$old.phase -eq 'ACTIVE' -and $ca -and $wa -and $ua -and $nr){
  [ordered]@{status='ALREADY_ACTIVE';state=$StatePath;ctrldPid=$old.ctrldPid;winwsPid=$old.winwsPid;nrptRule=$old.nrptRuleName}|ConvertTo-Json -Depth 5
  return
 }
 Rollback $old
}
if(Get-DnsClientNrptRule -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName -eq $NrptDisplay}){throw 'REFUSE_OWNED_NRPT_WITHOUT_STATE'}
if(@(Get-Ula).Count){throw 'REFUSE_ULA_WITHOUT_STATE'}
if(@(Get-OwnedCtrld).Count){throw 'STALE_OWNED_CTRLD_WITHOUT_STATE'}
if(Test-Path -LiteralPath $CtrldSock){Remove-Item -LiteralPath $CtrldSock -Force -ErrorAction SilentlyContinue}
if(Get-Process winws -ErrorAction SilentlyContinue|Where-Object{Safe-StartsWith $_.Path $ZapretDir}){throw 'STALE_OWNED_WINWS_WITHOUT_STATE'}
if(Test-Path -LiteralPath $RuntimeCtrld){Remove-Item -LiteralPath $RuntimeCtrld -Recurse -Force -ErrorAction SilentlyContinue}

$route=Resolve-PhysicalDefault
$pre=[ordered]@{
 dnsV4=@((Get-DnsClientServerAddress -InterfaceAlias $route.Alias -AddressFamily IPv4).ServerAddresses)
 dnsV6=@((Get-DnsClientServerAddress -InterfaceAlias $route.Alias -AddressFamily IPv6).ServerAddresses)
 nrpt=@(Get-NrptSignature)
 ulaExists=(@(Get-Ula).Count -gt 0)
 ics=Get-Ics
 broadRouteCount=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')}).Count
 winHttp=(netsh winhttp show proxy|Out-String).Trim()
}
if($pre.ulaExists){throw 'ULA_PREEXISTS'}
$state=[ordered]@{
 schema=3;phase='PREPARED';architecture='LOOPBACK_ULA_CTRLD_DOH_NRPT_PLUS_ZAPRET'
 root=$Root;interface=$route.Alias;localIp=$route.LocalIp;prepared=(Get-Date).ToString('o')
 pre=$pre;ulaAddress=$Ula;ulaCreated=$false;nrptRuleName='';ctrldPid=0;ctrldServiceName=$CtrldServiceName;winwsPid=0;runtimeConfig=$RuntimeConfig
}
Write-JsonAtomic $StatePath $state

$ev=[ordered]@{schema=3;status='FAIL';architecture=$state.architecture;pre=$pre;dnsStage=$null;live=$null;error=''}
try{
 New-Item -ItemType Directory -Force -Path $RuntimeCtrld|Out-Null
 $cfg=Get-Content -LiteralPath $CtrldTemplate -Raw -Encoding UTF8
 $cfg=$cfg.Replace('ip = "::1"',('ip = "'+$Ula+'"'))
 [IO.File]::WriteAllText($RuntimeConfig,$cfg,[Text.UTF8Encoding]::new($false))

 New-NetIPAddress -InterfaceIndex $LoopbackIndex -IPAddress $Ula -PrefixLength 128 -AddressFamily IPv6 -SkipAsSource $true -PolicyStore ActiveStore|Out-Null
 $state.ulaCreated=$true
 Write-JsonAtomic $StatePath $state
 $ready=$false
 for($i=0;$i -lt 40;$i++){
  Start-Sleep -Milliseconds 100
  $a=Get-NetIPAddress -InterfaceIndex $LoopbackIndex -AddressFamily IPv6 -IPAddress $Ula -ErrorAction SilentlyContinue
  if($a -and $a.AddressState -in @('Preferred','Deprecated')){$ready=$true;break}
 }
 if(-not $ready){throw 'ULA_NOT_READY'}

 $ctrldSvc=Start-OwnedCtrldService
 $cpid=[int64]$ctrldSvc.ProcessId
 $cp=Get-Process -Id $cpid -ErrorAction Stop
 if(-not $cp.Path -or -not(Safe-StartsWith $cp.Path $CtrldDir)){throw 'CTRLD_SERVICE_PROCESS_OWNERSHIP_MISMATCH'}
 $state.ctrldPid=$cpid
 Write-JsonAtomic $StatePath $state
 $udp=@();$tcp=@()
 for($i=0;$i -lt 80;$i++){
  $udp=@(Get-NetUDPEndpoint -LocalAddress $Ula -LocalPort 53 -ErrorAction SilentlyContinue|Where-Object OwningProcess -eq $cpid)
  $tcp=@(Get-NetTCPConnection -LocalAddress $Ula -LocalPort 53 -State Listen -ErrorAction SilentlyContinue|Where-Object OwningProcess -eq $cpid)
  if($udp.Count -and $tcp.Count){break}
  $svcNow=Get-CimInstance Win32_Service -Filter "Name='$CtrldServiceName'" -ErrorAction SilentlyContinue
  if(-not $svcNow -or [string]$svcNow.State -ne 'Running'){throw 'CTRLD_SERVICE_EXITED_BEFORE_LISTENER'}
  Start-Sleep -Milliseconds 100
 }
 if(-not $udp.Count -or -not $tcp.Count){throw 'ULA_LISTENER_NOT_OWNED'}

 $rule=Add-DnsClientNrptRule -Namespace '.' -NameServers $Ula -DisplayName $NrptDisplay -Comment $NrptComment -PassThru
 $state.nrptRuleName=[string]$rule.Name
 Write-JsonAtomic $StatePath $state
 Clear-DnsClientCache
 $dns=@();$allOk=$false
 for($attempt=1;$attempt -le 5 -and -not $allOk;$attempt++){
  Start-Sleep -Seconds 1
  $dns=@()
  foreach($n in @('www.youtube.com','github.com','api.openai.com')){$dns+=Dns-Probe $n}
  $allOk=(@($dns|Where-Object{-not $_.ok}).Count -eq 0)
 }
 if(-not $allOk){throw 'SYSTEM_DNS_VIA_ULA_FAIL'}
 $icsNow=Get-Ics
 if($pre.ics.exists -and ($icsNow.state -ne $pre.ics.state -or $icsNow.pid -ne $pre.ics.pid)){throw 'ICS_CHANGED_DURING_DNS_STAGE'}
 $dnsNow=@((Get-DnsClientServerAddress -InterfaceAlias $route.Alias -AddressFamily IPv4).ServerAddresses)
 if(($dnsNow -join '|') -ne ($pre.dnsV4 -join '|')){throw 'ADAPTER_DNS_CHANGED'}
 $cd=Curl-Probe 'https://76.76.10.11/p0' $route.LocalIp 5
 if($cd.exit -ne 0 -or $cd.meta -notmatch '^(200|400)\|'){throw 'CONTROL_D_DOH_DIRECT_FAIL'}
 $ev.dnsStage=[ordered]@{
  ula=(Get-NetIPAddress -InterfaceIndex $LoopbackIndex -IPAddress $Ula -AddressFamily IPv6|Select-Object IPAddress,PrefixLength,AddressState,SkipAsSource)
  ctrldPid=$cpid;udp=$udp.Count;tcp=$tcp.Count
  nrptRule=$rule|Select-Object Name,DisplayName,Namespace,NameServers,Comment
  dns=$dns;adapterDns=$dnsNow;controlD=$cd;ics=$icsNow
 }

 $args=@(
  '--wf-l3=ipv4','--wf-tcp=443',
  '--filter-l3=ipv4','--filter-tcp=443',
  ('--hostlist='+$HostList),
  '--ipset-exclude-ip=76.76.10.11',
  '--dpi-desync=fake,multidisorder',
  '--dpi-desync-split-pos=1,midsld',
  '--dpi-desync-fooling=badseq,md5sig'
 )
 $wp=Start-ExactProcess $Winws $args $ZapretDir
 $state.winwsPid=$wp.Id
 Write-JsonAtomic $StatePath $state
 Start-Sleep -Seconds 3
 if($wp.HasExited){throw ('WINWS_EXIT_'+$wp.ExitCode)}

 $dy=Dns-Probe 'www.youtube.com'
 $yt=Curl-Probe 'https://www.youtube.com/generate_204' $route.LocalIp 8
 $oa=Curl-Probe 'https://api.openai.com/v1/models' $route.LocalIp 7
 $gh=Curl-Probe 'https://github.com/' $route.LocalIp 7
 $routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
 $proxy=(netsh winhttp show proxy|Out-String).Trim()
 $icsLive=Get-Ics
 if(-not $dy.ok){throw 'YOUTUBE_DNS_NOT_CLEAN'}
 if($yt.exit -ne 0 -or $yt.meta -notmatch '^(200|204)\|'){throw 'YOUTUBE_HTTPS_FAIL'}
 if($oa.exit -ne 0 -or $oa.meta -notmatch '^(200|401|403)\|'){throw 'OPENAI_HTTPS_FAIL'}
 if($gh.exit -ne 0 -or $gh.meta -notmatch '^(200|301|302)\|'){throw 'GITHUB_HTTPS_FAIL'}
 if($routes.Count){throw 'BROAD_ROUTE_APPEARED'}
 if($proxy -notmatch 'Direct access'){throw 'WINHTTP_PROXY_CHANGED'}
 if($pre.ics.exists -and ($icsLive.state -ne $pre.ics.state -or $icsLive.pid -ne $pre.ics.pid)){throw 'ICS_CHANGED_LIVE'}
 if(@(Get-OwnedDrivers).Count -lt 1){throw 'WINDIVERT_DRIVER_MISSING'}

 $state.phase='ACTIVE';$state.started=(Get-Date).ToString('o')
 Write-JsonAtomic $StatePath $state
 $ev.status='PASS_ACTIVE'
 $ev.live=[ordered]@{
  ctrldPid=$cpid;winwsPid=$wp.Id;dns=$dy;youtube=$yt;openai=$oa;github=$gh
  ics=$icsLive;proxy=$proxy;broadRouteCount=$routes.Count
  drivers=@(Get-OwnedDrivers|Select-Object Name,State,PathName)
 }
 Write-JsonAtomic $Evidence $ev
 [ordered]@{status='PASS_ACTIVE';state=$StatePath;ctrldPid=$cpid;winwsPid=$wp.Id;nrptRule=$state.nrptRuleName;ula=$Ula;evidence=$Evidence}|ConvertTo-Json -Depth 6
 return
}catch{
 $ev.error=$_.Exception.Message
 try{Rollback $state}catch{}
 Write-JsonAtomic $Evidence $ev
 [ordered]@{status='FAIL_ROLLED_BACK';error=$ev.error;evidence=$Evidence}|ConvertTo-Json -Depth 6
 throw ('START_FAIL_'+$ev.error)
}
