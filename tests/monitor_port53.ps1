param([string]$Out,[int]$DurationMs=8000)
$ErrorActionPreference='SilentlyContinue'
Remove-Item $Out -Force -ErrorAction SilentlyContinue
$sw=[Diagnostics.Stopwatch]::StartNew()
while($sw.ElapsedMilliseconds -lt $DurationMs){
  $now=(Get-Date).ToString('o')
  $udp=@(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue|Select-Object LocalAddress,LocalPort,OwningProcess)
  $tcp=@(Get-NetTCPConnection -LocalPort 53 -State Listen -ErrorAction SilentlyContinue|Select-Object LocalAddress,LocalPort,OwningProcess)
  if($udp.Count -or $tcp.Count){
    [ordered]@{t=$now;ms=$sw.ElapsedMilliseconds;udp=$udp;tcp=$tcp}|ConvertTo-Json -Compress -Depth 5|Add-Content -LiteralPath $Out -Encoding UTF8
  }
  Start-Sleep -Milliseconds 100
}
