$ErrorActionPreference='Continue'
$rg=(Get-Command rg.exe -ErrorAction Stop).Source
$roots=@(
 'C:\Users\Aa.Emad\Downloads',
 'C:\Users\Aa.Emad\Desktop',
 'C:\Users\Aa.Emad\Documents',
 'C:\Users\Aa.Emad\source',
 'C:\Users\Aa.Emad\AppData\Local',
 'C:\Users\Aa.Emad\AppData\Roaming',
 'C:\Users\Public',
 'C:\ProgramData',
 'C:\Program Files',
 'C:\Program Files (x86)',
 'C:\Windows\Temp'
) | Where-Object {Test-Path -LiteralPath $_}
$nameRx='(?i)DirectInternetMethod|Direct Internet Method|direct-internet-method|direct_method|DIM_[0-9]{3}|DirectDnsDpiHarness'
$rows=@()
foreach($root in $roots){
  $files=@(& $rg --files -uuu -- $root 2>$null)
  foreach($f in $files){
    if($f -match $nameRx){
      $rows += [pscustomobject]@{ScanRoot=$root;Path=$f;Match='NAME'}
    }
  }
}
$rows=$rows|Sort-Object Path -Unique
$rows|ConvertTo-Json -Depth 4|Set-Content -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\audit\20261001_deep_machine_reconciliation\TARGETED_MACHINE_NAME_HITS.json' -Encoding utf8
$myProject='C:\Users\Aa.Emad\Downloads\My Project'
$mp=@()
if(Test-Path -LiteralPath $myProject){
  $mpFiles=@(& $rg --files -uuu -- $myProject 2>$null)
  foreach($f in $mpFiles){if($f -match $nameRx){$mp += $f}}
  $mp=@($mp|Sort-Object -Unique)
}
$mp|Set-Content -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\audit\20261001_deep_machine_reconciliation\DOWNLOADS_MY_PROJECT_HITS.txt' -Encoding utf8
[pscustomobject]@{generatedUtc=[DateTime]::UtcNow.ToString('o');roots=$roots;hits=$rows.Count;myProjectHits=$mp.Count}|ConvertTo-Json -Depth 4|Set-Content -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\audit\20261001_deep_machine_reconciliation\TARGETED_MACHINE_SCAN_SUMMARY.json' -Encoding utf8
Get-Content -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\audit\20261001_deep_machine_reconciliation\TARGETED_MACHINE_SCAN_SUMMARY.json' -Raw
