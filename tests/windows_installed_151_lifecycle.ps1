$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$Service='DirectInternetMethodSvc'
$StatusPath='C:\ProgramData\DirectInternetMethod\action-status.json'
$StatePath='C:\ProgramData\DirectDnsDpiHarness\state.json'
$ConfigDir='C:\ProgramData\DirectInternetMethod\UserConfig'
$StrategyPath=Join-Path $ConfigDir 'strategy.txt'
$ScopePath=Join-Path $ConfigDir 'scope.txt'
$CustomPath=Join-Path $ConfigDir 'custom-hosts.txt'
$AdultEnabled=Join-Path $ConfigDir 'adult-enabled.txt'
$AdultHosts=Join-Path $ConfigDir 'adult-hosts.txt'
$RepoRoot=Split-Path $PSScriptRoot -Parent
$EvidencePath=Join-Path $RepoRoot 'evidence\WINDOWS_151_INSTALLED_LIFECYCLE_20261005.json'
$Authority=Get-Content (Join-Path $RepoRoot 'RELEASE.json') -Raw | ConvertFrom-Json
$ExpectedGui=[string]$Authority.platforms.windows.guiSha256
$ExpectedService=[string]$Authority.platforms.windows.serviceSha256
$ExpectedManifest=[string]$Authority.platforms.windows.manifestSha256
$Install='C:\Users\Aa.Emad\AppData\Local\Programs\DirectInternetMethod'
$Priv='C:\Program Files\DirectInternetMethod\Privileged'

function Cmd([string]$exe,[string[]]$args){
  $psi=[Diagnostics.ProcessStartInfo]::new()
  $psi.FileName=$exe
  $psi.UseShellExecute=$false
  $psi.CreateNoWindow=$true
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  foreach($a in $args){[void]$psi.ArgumentList.Add($a)}
  $p=[Diagnostics.Process]::Start($psi)
  if(-not $p.WaitForExit(8000)){try{$p.Kill($true)}catch{};try{$p.WaitForExit(1000)}catch{};throw "CMD_TIMEOUT_$exe"}
  $o=$p.StandardOutput.ReadToEnd()
  $e=$p.StandardError.ReadToEnd()
  [ordered]@{exit=$p.ExitCode;stdout=$o.Trim();stderr=$e.Trim()}
}

function Snapshot-Network {
  $route=Cmd 'route.exe' @('print','0.0.0.0')
  $dns=Cmd 'netsh.exe' @('interface','ipv4','show','dnsservers')
  $wh=Cmd 'netsh.exe' @('winhttp','show','proxy')
  [ordered]@{
    route=$route.stdout
    dns=$dns.stdout
    winhttp=$wh.stdout
    stateExists=(Test-Path $StatePath)
    ctrld=@(Get-Process ctrld -ErrorAction SilentlyContinue).Count
    winws=@(Get-Process winws -ErrorAction SilentlyContinue).Count
  }
}

function Wait-Action([string]$Name,[datetime]$Since,[int]$TimeoutSec=130) {
  $deadline=(Get-Date).AddSeconds($TimeoutSec)
  do {
    if(Test-Path $StatusPath){
      try {
        $item=Get-Item $StatusPath
        $j=Get-Content $StatusPath -Raw|ConvertFrom-Json
        if($item.LastWriteTime -ge $Since -and [string]$j.action -eq $Name){
          if([string]$j.phase -eq 'done'){
            if([int]$j.exitCode -ne 0){throw "$Name exit=$($j.exitCode): $($j.message)"}
            return $j
          }
          if([string]$j.phase -in @('failed','error')){throw "$Name phase=$($j.phase): $($j.message)"}
        }
      } catch {
        if($_.Exception.Message -match '^'+[regex]::Escape($Name)+' '){throw}
      }
    }
    Start-Sleep -Milliseconds 500
  } while((Get-Date)-lt $deadline)
  throw "ACTION_TIMEOUT_$Name"
}

function Invoke-Action([int]$Code,[string]$Name,[int]$TimeoutSec=130) {
  $since=(Get-Date).AddSeconds(-1)
  & sc.exe control $Service $Code | Out-Null
  if($LASTEXITCODE -ne 0){throw "SC_CONTROL_$($Name)_EXIT_$LASTEXITCODE"}
  Wait-Action $Name $since $TimeoutSec
}

function Probe([string]$Name,[string]$Url,[string[]]$PassCodes) {
  $psi=[Diagnostics.ProcessStartInfo]::new()
  $psi.FileName='curl.exe';$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
  $psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
  foreach($a in @('-4','-L','--noproxy','*','-A','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36','-sS','-o','NUL','-w','%{http_code}|%{remote_ip}|%{time_total}','--connect-timeout','6','--max-time','15',$Url)){[void]$psi.ArgumentList.Add($a)}
  $sw=[Diagnostics.Stopwatch]::StartNew()
  $p=[Diagnostics.Process]::Start($psi);$o=$p.StandardOutput.ReadToEnd();$e=$p.StandardError.ReadToEnd()
  if(-not $p.WaitForExit(18000)){try{$p.Kill($true)}catch{};$exit=124}else{$exit=$p.ExitCode}
  $sw.Stop()
  $joined=$o.Trim();$parts=$joined.Split('|');$code=if($parts.Count){$parts[0]}else{''};$remote=if($parts.Count -gt 1){$parts[1]}else{''}
  $usable=($exit -eq 0 -and $PassCodes -contains $code)
  $status=if($usable){'PASS'}elseif($exit -eq 0 -and $code -match '^\d{3}$' -and $code -ne '000'){'FAIL_HTTP'}else{'FAIL_TRANSPORT'}
  [ordered]@{name=$Name;url=$Url;status=$status;http=$code;remote=$remote;exit=$exit;elapsedMs=$sw.ElapsedMilliseconds;stderr=$e.Trim()}
}

function Matrix([string]$cycle){
  $state=if(Test-Path $StatePath){Get-Content $StatePath -Raw|ConvertFrom-Json}else{$null}
  $strategy=$null;$scope=$null;$adultCoverage=$null;$adultHostCount=$null
  if($state){$strategy=[string]$state.strategy;$scope=[string]$state.scope;$adultCoverage=[bool]$state.adultCoverage;$adultHostCount=[int]$state.adultHostCount}
  $runtimeCount=if(Test-Path 'C:\ProgramData\DirectInternetMethod\runtime-hosts.txt'){@(Get-Content 'C:\ProgramData\DirectInternetMethod\runtime-hosts.txt'|Where-Object{$_}).Count}else{0}
  [ordered]@{
    cycle=$cycle
    state=[ordered]@{strategy=$strategy;scope=$scope;adultCoverage=$adultCoverage;adultHostCount=$adultHostCount;runtimeHostCount=$runtimeCount}
    rows=@(
      (Probe 'YouTube' 'https://www.youtube.com/generate_204' @('200','204')),
      (Probe 'OpenAI' 'https://api.openai.com/v1/models' @('200','401')),
      (Probe 'GitHub' 'https://github.com/' @('200','301','302','303','307','308')),
      (Probe 'Gemini' 'https://gemini.google.com/' @('200','301','302','303','307','308')),
      (Probe 'Pornhub' 'https://www.pornhub.com/' @('200','301','302','303','307','308')),
      (Probe 'XVideos' 'https://www.xvideos.com/' @('200','301','302','303','307','308')),
      (Probe 'XNXX' 'https://www.xnxx.com/' @('200','301','302','303','307','308')),
      (Probe 'XHamster' 'https://xhamster.com/' @('200','301','302','303','307','308')),
      (Probe 'Reddit' 'https://www.reddit.com/' @('200','301','302','303','307','308')),
      (Probe 'Wikipedia' 'https://www.wikipedia.org/' @('200','301','302','303','307','308'))
    )
  }
}

function Baseline($s){
  [ordered]@{
    interface=[string]$s.interface
    localIp=[string]$s.localIp
    dnsV4=@($s.pre.dnsV4|ForEach-Object{[string]$_})
    dnsV6=@($s.pre.dnsV6|ForEach-Object{[string]$_})
    nrpt=@($s.pre.nrpt)
    ulaExists=[bool]$s.pre.ulaExists
    ics=[ordered]@{exists=[bool]$s.pre.ics.exists;state=[string]$s.pre.ics.state;pid=[int64]$s.pre.ics.pid}
    broadRouteCount=[int]$s.pre.broadRouteCount
    winHttp=[string]$s.pre.winHttp
  }
}

$initialState=if(Test-Path $StatePath){Get-Content $StatePath -Raw|ConvertFrom-Json}else{$null}
$result=[ordered]@{schema=1;date='2026-10-05';project='Direct Internet Method';version='1.5.1';status='RUNNING';installed=$null;adult=$null;pre=$null;cycles=@();recovery=$null;post=$null;rollbackEqual=$false;finalActive=$null;error=$null}
try {
  $rel=Get-Content (Join-Path $Install 'RELEASE.json') -Raw|ConvertFrom-Json
  $gui=(Get-FileHash (Join-Path $Install 'app\DirectInternetMethod.exe') -Algorithm SHA256).Hash
  $svc=(Get-FileHash (Join-Path $Priv 'app\DirectInternetMethod.Service.exe') -Algorithm SHA256).Hash
  $man=(Get-FileHash (Join-Path $Install 'manifest.json') -Algorithm SHA256).Hash
  $result.installed=[ordered]@{version=$rel.version;guiSha256=$gui;serviceSha256=$svc;manifestSha256=$man}
  if([string]$rel.version -ne '1.5.1'){throw "INSTALLED_VERSION_$($rel.version)"}
  if($gui -ne $ExpectedGui){throw 'GUI_HASH'}
  if($svc -ne $ExpectedService){throw 'SERVICE_HASH'}
  if($man -ne $ExpectedManifest){throw 'MANIFEST_HASH'}
  if(-not (Test-Path $AdultEnabled) -or (Get-Content $AdultEnabled -Raw).Trim() -ne '1'){throw 'ADULT_FLAG_NOT_ENABLED'}
  if(-not (Test-Path $AdultHosts)){throw 'ADULT_CATALOG_MISSING'}
  $adultCount=@(Get-Content $AdultHosts|Where-Object {$_ -and -not $_.StartsWith('#')}).Count
  if($adultCount -lt 10000){throw "ADULT_CATALOG_TOO_SMALL_$adultCount"}
  $result.adult=[ordered]@{entries=$adultCount;sha256=(Get-FileHash $AdultHosts -Algorithm SHA256).Hash}

  New-Item -ItemType Directory -Force -Path $ConfigDir|Out-Null
  if(-not $initialState){
    Set-Content $StrategyPath 'balanced' -Encoding ascii -NoNewline
    Set-Content $ScopePath 'targeted' -Encoding ascii -NoNewline
    Remove-Item $CustomPath -Force -ErrorAction SilentlyContinue
    Invoke-Action 128 'start'|Out-Null
    $initialState=Get-Content $StatePath -Raw|ConvertFrom-Json
  }
  $initialBaseline=Baseline $initialState
  $result.pre=$initialBaseline
  Invoke-Action 130 'recovery'|Out-Null

  Set-Content $StrategyPath 'balanced' -Encoding ascii -NoNewline
  Set-Content $ScopePath 'targeted' -Encoding ascii -NoNewline
  Remove-Item $CustomPath -Force -ErrorAction SilentlyContinue
  Invoke-Action 128 'start'|Out-Null
  $result.cycles += Matrix 'balanced-targeted-adult-catalog'
  Invoke-Action 129 'stop'|Out-Null

  Set-Content $StrategyPath 'strong' -Encoding ascii -NoNewline
  Set-Content $ScopePath 'all-sites' -Encoding ascii -NoNewline
  Invoke-Action 128 'start'|Out-Null
  $result.cycles += Matrix 'strong-all-sites'
  Invoke-Action 129 'stop'|Out-Null

  $result.recovery=Invoke-Action 130 'recovery'
  $result.post=[ordered]@{stateExists=(Test-Path $StatePath)}

  Set-Content $StrategyPath 'balanced' -Encoding ascii -NoNewline
  Set-Content $ScopePath 'targeted' -Encoding ascii -NoNewline
  Remove-Item $CustomPath -Force -ErrorAction SilentlyContinue
  Invoke-Action 128 'start'|Out-Null
  $fs=Get-Content $StatePath -Raw|ConvertFrom-Json
  $finalBaseline=Baseline $fs
  $preNorm=$initialBaseline|ConvertTo-Json -Depth 10 -Compress
  $finalNorm=$finalBaseline|ConvertTo-Json -Depth 10 -Compress
  $result.rollbackEqual=(-not $result.post.stateExists -and $preNorm -eq $finalNorm)
  $finalRuntimeCount=if(Test-Path 'C:\ProgramData\DirectInternetMethod\runtime-hosts.txt'){@(Get-Content 'C:\ProgramData\DirectInternetMethod\runtime-hosts.txt'|Where-Object{$_}).Count}else{0}
  $result.finalActive=[ordered]@{strategy=$fs.strategy;scope=$fs.scope;adultCoverage=$fs.adultCoverage;adultHostCount=$fs.adultHostCount;runtimeHostCount=$finalRuntimeCount;ctrldPid=$fs.ctrldPid;winwsPid=$fs.winwsPid;pre=$finalBaseline}
  if(-not $result.rollbackEqual){throw 'ROLLBACK_PRESTATE_MISMATCH'}
  if([string]$fs.strategy -ne 'balanced' -or [string]$fs.scope -ne 'targeted'){throw 'FINAL_PROFILE_NOT_BALANCED_TARGETED'}
  if(-not $fs.adultCoverage -or [int]$fs.adultHostCount -lt 10000){throw 'FINAL_ADULT_STATE_NOT_ACTIVE'}
  $result.status='PASS_INSTALLED_LIFECYCLE_SITE_MATRIX_ROLLBACK_EQUAL_RESTORED_ACTIVE'
} catch {
  $result.status='FAIL';$result.error=$_.Exception.Message
  try {Invoke-Action 130 'recovery'|Out-Null}catch{}
  try {
    Set-Content $StrategyPath 'balanced' -Encoding ascii -NoNewline
    Set-Content $ScopePath 'targeted' -Encoding ascii -NoNewline
    Remove-Item $CustomPath -Force -ErrorAction SilentlyContinue
    Invoke-Action 128 'start'|Out-Null
  }catch{}
}
$result|ConvertTo-Json -Depth 12|Set-Content $EvidencePath -Encoding utf8
$result|ConvertTo-Json -Depth 12
if($result.status -notlike 'PASS*'){exit 31}
