$ErrorActionPreference='Stop'
$backupRoot='C:\Users\Aa.Emad\.chatgpt-remote-commander\backups'
$out='C:\Users\Aa.Emad\source\repos\DirectInternetMethod\audit\20261001_deep_machine_reconciliation\REMOTE_COMMANDER_PROJECT_BACKUPS.json'
$rows=@()
if(Test-Path -LiteralPath $backupRoot){
  Get-ChildItem -LiteralPath $backupRoot -Recurse -File -Force -ErrorAction SilentlyContinue |
    Where-Object {
      $_.FullName -match '\\source\\repos\\DirectInternetMethod(?:_|\\)' -or
      $_.FullName -match '\\AppData\\Local\\DirectInternetMethod(?:_|\\)' -or
      $_.FullName -match '\\ProgramData\\DirectInternetMethod(?:_|\\)'
    } |
    ForEach-Object {
      $rows += [pscustomobject]@{
        Path=$_.FullName
        Bytes=$_.Length
        Sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        LastWriteTimeUtc=$_.LastWriteTimeUtc.ToString('o')
      }
    }
}
$rows=$rows|Sort-Object Path -Unique
$rows|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $out -Encoding utf8
$unique=@($rows|Group-Object Sha256)
[pscustomobject]@{
 schema=1
 generatedUtc=[DateTime]::UtcNow.ToString('o')
 fileCount=$rows.Count
 uniqueContentCount=$unique.Count
 totalBytes=($rows|Measure-Object Bytes -Sum).Sum
 uniqueBytes=($unique|ForEach-Object{$_.Group[0].Bytes}|Measure-Object -Sum).Sum
}|ConvertTo-Json -Depth 4|Set-Content -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\audit\20261001_deep_machine_reconciliation\REMOTE_COMMANDER_PROJECT_BACKUPS_SUMMARY.json' -Encoding utf8
Get-Content -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\audit\20261001_deep_machine_reconciliation\REMOTE_COMMANDER_PROJECT_BACKUPS_SUMMARY.json' -Raw
