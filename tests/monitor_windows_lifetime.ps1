$ErrorActionPreference='Stop'
$exe=Join-Path $env:LOCALAPPDATA 'Programs\DirectInternetMethod\app\DirectInternetMethod.exe'
$p=Start-Process $exe -PassThru
$rows=@()
for($i=0;$i -le 20;$i++){
  Start-Sleep -Seconds 1
  $p.Refresh()
  $rows += [pscustomobject]@{Second=$i+1;HasExited=$p.HasExited;ExitCode=$(if($p.HasExited){$p.ExitCode}else{$null});Title=$(if(!$p.HasExited){$p.MainWindowTitle}else{''});Responding=$(if(!$p.HasExited){$p.Responding}else{$false})}
  if($p.HasExited){break}
}
$rows|ConvertTo-Json -Depth 3|Set-Content -Encoding UTF8 (Join-Path $env:TEMP 'dim-lifetime.json')
if(!$p.HasExited){Write-Output 'APP_STILL_ALIVE_20S'}else{Write-Output ('APP_EXIT_'+$p.ExitCode)}
