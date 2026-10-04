$ErrorActionPreference='Stop'
$items=@(
'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\archive\machine-snapshots\crashdumps\DirectInternetMethod.exe.67464.dmp',
'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\archive\worktree-history\DirectInternetMethod_all_refs_precleanup_20261001.bundle',
'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\delivery\DirectInternetMethod_1.4.0_Windows_Setup.exe',
'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\delivery\DirectInternetMethod_1.4.0_Linux_x86_64.zip',
'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\delivery\SHA256SUMS.txt'
)
$rows=foreach($x in $items){$i=Get-Item -LiteralPath $x;[pscustomobject]@{Path=$i.FullName;Bytes=$i.Length;Sha256=(Get-FileHash -LiteralPath $x -Algorithm SHA256).Hash}}
$rows|ConvertTo-Json -Depth 4|Set-Content -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\audit\20261001_deep_machine_reconciliation\KEY_ARCHIVE_HASHES.json' -Encoding utf8
$rows|ConvertTo-Json -Depth 4
