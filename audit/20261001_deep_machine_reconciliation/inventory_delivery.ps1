$ErrorActionPreference='Stop'
$dirs=@(
 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\delivery',
 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod_hotfix121\delivery',
 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod_provider131\delivery',
 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod_ui131\delivery',
 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod_v131final\delivery',
 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod_v140\delivery',
 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod_v140final\delivery'
)
$rows=@()
foreach($d in $dirs){
 if(-not(Test-Path -LiteralPath $d)){continue}
 Get-ChildItem -LiteralPath $d -File -ErrorAction Stop | ForEach-Object {
  $rows += [pscustomobject]@{
   Path=$_.FullName
   Name=$_.Name
   Bytes=$_.Length
   Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
   LastWriteTimeUtc=$_.LastWriteTimeUtc.ToString('o')
  }
 }
}
$rows | Sort-Object Name,Path | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\audit\20261001_deep_machine_reconciliation\DELIVERY_ARTIFACT_INVENTORY.json' -Encoding utf8
$rows | Group-Object Sha256 | ForEach-Object {
 [pscustomobject]@{Sha256=$_.Name;Count=$_.Count;Paths=@($_.Group.Path)}
} | Sort-Object Count -Descending | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\audit\20261001_deep_machine_reconciliation\DELIVERY_DUPLICATE_HASH_GROUPS.json' -Encoding utf8
"FILES=$($rows.Count)"
