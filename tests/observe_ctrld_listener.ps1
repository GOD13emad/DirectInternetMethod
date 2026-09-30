$ErrorActionPreference='SilentlyContinue'
$Root=Split-Path $PSScriptRoot -Parent
$Out=Join-Path $Root 'evidence\CTRLD_LISTENER_OBSERVER.jsonl'
Remove-Item $Out -Force -ErrorAction SilentlyContinue
$until=(Get-Date).AddSeconds(12)
while((Get-Date)-lt $until){
 $ps=@(Get-CimInstance Win32_Process -Filter "Name='ctrld.exe'" -ErrorAction SilentlyContinue|Select-Object ProcessId,ParentProcessId,Name,ExecutablePath)
 $udp=@(Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue|Select-Object LocalAddress,LocalPort,OwningProcess)
 $tcp=@(Get-NetTCPConnection -LocalPort 53 -State Listen -ErrorAction SilentlyContinue|Select-Object LocalAddress,LocalPort,OwningProcess)
 if($ps.Count -or $udp.Count -or $tcp.Count){
  [ordered]@{t=(Get-Date).ToString('o');p=$ps;udp=$udp;tcp=$tcp}|ConvertTo-Json -Depth 5 -Compress|Add-Content $Out -Encoding UTF8
 }
 Start-Sleep -Milliseconds 100
}
