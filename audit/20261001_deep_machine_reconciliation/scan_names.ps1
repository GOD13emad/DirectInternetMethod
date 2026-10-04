$ErrorActionPreference='Continue'
$rg=(Get-Command rg.exe -ErrorAction Stop).Source
$allFiles=& $rg --files -uuu 'C:\' 2>$null
$nameHits=@($allFiles | Where-Object { $_ -match '(?i)DirectInternetMethod|Direct Internet Method|direct-internet-method|direct_method|\\DIM_1[0-9]' } | Sort-Object -Unique)
$nameHits | Set-Content -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\audit\20261001_deep_machine_reconciliation\C_DRIVE_NAME_SWEEP.txt' -Encoding utf8

$contentHits=& $rg -l -uuu -i -e 'Direct Internet Method' -e 'GOD13emad/DirectInternetMethod' 'C:\' -g 'PROJECT_BRAIN.md' -g 'RELEASE.json' -g 'README.md' -g '*.ps1' -g '*.py' -g '*.sh' -g '*.json' 2>$null
$contentHits=@($contentHits | Sort-Object -Unique)
$contentHits | Set-Content -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\audit\20261001_deep_machine_reconciliation\C_DRIVE_CONTENT_FINGERPRINT_HITS.txt' -Encoding utf8

$repoHits=& $rg -l -uuu -i 'GOD13emad/DirectInternetMethod' 'C:\Users\Aa.Emad\source\repos' 'C:\Users\Aa.Emad\Downloads\My Project' -g 'config' 2>$null
$repoHits=@($repoHits | Sort-Object -Unique)
$repoHits | Set-Content -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\audit\20261001_deep_machine_reconciliation\DIRECTINTERNETMETHOD_GIT_CONFIG_HITS.txt' -Encoding utf8

[pscustomobject]@{
 generatedUtc=[DateTime]::UtcNow.ToString('o')
 nameHits=$nameHits.Count
 contentHits=$contentHits.Count
 gitConfigHits=$repoHits.Count
} | ConvertTo-Json | Set-Content -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\audit\20261001_deep_machine_reconciliation\C_DRIVE_SWEEP_SUMMARY.json' -Encoding utf8

Get-Content -LiteralPath 'C:\Users\Aa.Emad\source\repos\DirectInternetMethod\audit\20261001_deep_machine_reconciliation\C_DRIVE_SWEEP_SUMMARY.json' -Raw
