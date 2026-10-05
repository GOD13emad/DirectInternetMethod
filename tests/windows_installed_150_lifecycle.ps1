$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$Service='DirectInternetMethodSvc'
$StatusPath='C:\ProgramData\DirectInternetMethod\action-status.json'
$StatePath='C:\ProgramData\DirectDnsDpiHarness\state.json'
$ConfigDir='C:\ProgramData\DirectInternetMethod\UserConfig'
$StrategyPath=Join-Path $ConfigDir 'strategy.txt'
$ScopePath=Join-Path $ConfigDir 'scope.txt'
$CustomPath=Join-Path $ConfigDir 'custom-hosts.txt'
$EvidencePath=Join-Path (Split-Path $PSScriptRoot -Parent) 'evidence\WINDOWS_150_INSTALLED_LIFECYCLE_20261005.json'
$ExpectedGui='055C2F10BFBEEE13496FBC75B3151D08FCC5AAB3E6D2B0ED27A1D3D0E4450A86'
$ExpectedService='E0BAB3C9E97287E31EE920DB137B7B0C6314194F74D79B2918B25804E2445A8C'
$Install='C:\Users\Aa.Emad\AppData\Local\Programs\DirectInternetMethod'
$Priv='C:\Program Files\DirectInternetMethod\Privileged'

function Snapshot-Network {
  $routes=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Sort-Object InterfaceAlias,NextHop,RouteMetric |
    Select-Object InterfaceAlias,NextHop,RouteMetric)
  $dns=@(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {$_.ServerAddresses.Count -gt 0} |
    Sort-Object InterfaceAlias |
    ForEach-Object {[pscustomobject]@{InterfaceAlias=$_.InterfaceAlias;ServerAddresses=@($_.ServerAddresses)}})
  [ordered]@{
    routes=$routes
    dns=$dns
    winhttp=(netsh winhttp show proxy | Out-String).Trim()
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
        $j=Get-Content $StatusPath -Raw | ConvertFrom-Json
        if($item.LastWriteTime -ge $Since -and [string]$j.action -eq $Name){
          if([string]$j.phase -eq 'done'){
            if([int]$j.exitCode -ne 0){throw "$Name exit=$($j.exitCode): $($j.message)"}
            return $j
          }
          if([string]$j.phase -in @('failed','error')){
            throw "$Name phase=$($j.phase): $($j.message)"
          }
        }
      } catch {
        if($_.Exception.Message -match '^'+[regex]::Escape($Name)+' '){throw}
      }
    }
    Start-Sleep -Milliseconds 500
  } while((Get-Date) -lt $deadline)
  throw "ACTION_TIMEOUT_$Name"
}

function Invoke-Action([int]$Code,[string]$Name,[int]$TimeoutSec=130) {
  $since=(Get-Date).AddSeconds(-1)
  & sc.exe control $Service $Code | Out-Null
  if($LASTEXITCODE -ne 0){throw "SC_CONTROL_$($Name)_EXIT_$LASTEXITCODE"}
  Wait-Action $Name $since $TimeoutSec
}

function Probe([string]$Name,[string]$Url,[string[]]$PassCodes) {
  $sw=[Diagnostics.Stopwatch]::StartNew()
  $raw=& curl.exe -4 -L --noproxy '*' -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36' -sS -o NUL -w '%{http_code}|%{remote_ip}|%{time_total}' --connect-timeout 6 --max-time 12 $Url 2>&1
  $exit=$LASTEXITCODE
  $sw.Stop()
  $joined=($raw -join ' ').Trim()
  $parts=$joined.Split('|')
  $code=if($parts.Count -gt 0){$parts[0]}else{''}
  $remote=if($parts.Count -gt 1){$parts[1]}else{''}
  $reached=($exit -eq 0 -and $code -match '^\d{3}$' -and $code -ne '000')
  $status=if($reached -and $PassCodes -contains $code){'PASS'}elseif($reached){'REACHABLE'}else{'FAIL'}
  [ordered]@{name=$Name;url=$Url;status=$status;http=$code;remote=$remote;exit=$exit;elapsedMs=$sw.ElapsedMilliseconds;raw=$joined}
}

function Run-Matrix([string]$Cycle) {
  $rows=@(
    (Probe 'YouTube' 'https://www.youtube.com/generate_204' @('200','204')),
    (Probe 'OpenAI' 'https://api.openai.com/v1/models' @('200','401','403')),
    (Probe 'GitHub' 'https://github.com/' @('200','301','302','303','307','308')),
    (Probe 'Gemini' 'https://gemini.google.com/' @('200','301','302','303','307','308')),
    (Probe 'Adult site' 'https://www.pornhub.com/' @('200','301','302','303','307','308')),
    (Probe 'Reddit' 'https://www.reddit.com/' @('200','301','302','303','307','308')),
    (Probe 'Wikipedia' 'https://www.wikipedia.org/' @('200','301','302','303','307','308')),
    (Probe 'Cloudflare' 'https://www.cloudflare.com/' @('200','301','302','303','307','308'))
  )
  [ordered]@{cycle=$Cycle;strategy=(Get-Content $StrategyPath -Raw).Trim();scope=(Get-Content $ScopePath -Raw).Trim();rows=$rows}
}

$backup=[ordered]@{}
foreach($p in @($StrategyPath,$ScopePath,$CustomPath)){
  $backup[$p]=[ordered]@{exists=(Test-Path $p);content=if(Test-Path $p){Get-Content $p -Raw}else{''}}
}
$pre=Snapshot-Network
$result=[ordered]@{
  schema=1
  date='2026-10-05'
  project='Direct Internet Method'
  version='1.5.0'
  status='RUNNING'
  installed=[ordered]@{}
  pre=$pre
  cycles=@()
  recovery=$null
  post=$null
  rollbackEqual=$false
  error=$null
}
try {
  $release=Get-Content (Join-Path $Install 'RELEASE.json') -Raw|ConvertFrom-Json
  $guiHash=(Get-FileHash (Join-Path $Install 'app\DirectInternetMethod.exe') -Algorithm SHA256).Hash
  $svcHash=(Get-FileHash (Join-Path $Priv 'app\DirectInternetMethod.Service.exe') -Algorithm SHA256).Hash
  $result.installed=[ordered]@{version=$release.version;guiSha256=$guiHash;serviceSha256=$svcHash}
  if([string]$release.version -ne '1.5.0'){throw "INSTALLED_VERSION_$($release.version)"}
  if($guiHash -ne $ExpectedGui){throw 'INSTALLED_GUI_HASH_MISMATCH'}
  if($svcHash -ne $ExpectedService){throw 'INSTALLED_SERVICE_HASH_MISMATCH'}
  if(Test-Path $StatePath){Invoke-Action 130 'recovery' | Out-Null}

  New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null

  Set-Content -LiteralPath $StrategyPath -Value 'balanced' -Encoding ascii -NoNewline
  Set-Content -LiteralPath $ScopePath -Value 'targeted' -Encoding ascii -NoNewline
  Remove-Item -LiteralPath $CustomPath -Force -ErrorAction SilentlyContinue
  Invoke-Action 128 'start' | Out-Null
  $result.cycles += Run-Matrix 'balanced-targeted-builtins'
  Invoke-Action 129 'stop' | Out-Null

  Set-Content -LiteralPath $StrategyPath -Value 'strong' -Encoding ascii -NoNewline
  Set-Content -LiteralPath $ScopePath -Value 'targeted' -Encoding ascii -NoNewline
  Set-Content -LiteralPath $CustomPath -Value 'reddit.com' -Encoding ascii -NoNewline
  Invoke-Action 128 'start' | Out-Null
  $result.cycles += Run-Matrix 'strong-targeted-custom-reddit'
  Invoke-Action 129 'stop' | Out-Null

  Set-Content -LiteralPath $StrategyPath -Value 'strong' -Encoding ascii -NoNewline
  Set-Content -LiteralPath $ScopePath -Value 'all-sites' -Encoding ascii -NoNewline
  Remove-Item -LiteralPath $CustomPath -Force -ErrorAction SilentlyContinue
  Invoke-Action 128 'start' | Out-Null
  $result.cycles += Run-Matrix 'strong-all-sites'
  Invoke-Action 129 'stop' | Out-Null

  $result.status='PASS_LIFECYCLE_SITE_MATRIX'
}
catch {
  $result.status='FAIL'
  $result.error=$_.Exception.Message
}
finally {
  try {$result.recovery=Invoke-Action 130 'recovery'} catch {$result.recovery=[ordered]@{error=$_.Exception.Message};$result.status='FAIL_RECOVERY'}
  foreach($p in $backup.Keys){
    $b=$backup[$p]
    if($b.exists){
      [IO.File]::WriteAllText($p,[string]$b.content,[Text.UTF8Encoding]::new($false))
    } else {
      Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    }
  }
  Start-Sleep -Milliseconds 500
  $result.post=Snapshot-Network
  $preNorm=ConvertTo-Json ([ordered]@{routes=$pre.routes;dns=$pre.dns;winhttp=$pre.winhttp}) -Depth 8 -Compress
  $postNorm=ConvertTo-Json ([ordered]@{routes=$result.post.routes;dns=$result.post.dns;winhttp=$result.post.winhttp}) -Depth 8 -Compress
  $result.rollbackEqual=($preNorm -eq $postNorm -and -not $result.post.stateExists -and $result.post.ctrld -eq 0 -and $result.post.winws -eq 0)
  if(-not $result.rollbackEqual -and $result.status -like 'PASS*'){$result.status='FAIL_ROLLBACK'}
  $result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $EvidencePath -Encoding utf8
  $result | ConvertTo-Json -Depth 12
}
if($result.status -notlike 'PASS*'){exit 31}
