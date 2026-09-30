$ErrorActionPreference='SilentlyContinue'
$Root=Split-Path $PSScriptRoot -Parent
$Out=Join-Path $Root 'evidence\CTRLD_FAST_OBSERVER.log'
"observer-start $(Get-Date -Format o)"|Set-Content $Out -Encoding UTF8
$until=(Get-Date).AddSeconds(10)
while((Get-Date)-lt $until){
 $p=@(Get-Process ctrld -ErrorAction SilentlyContinue)
 if($p.Count){
   "seen $(Get-Date -Format o) pid=$($p[0].Id) path=$($p[0].Path)"|Add-Content $Out -Encoding UTF8
   (netstat -ano | Select-String ':53')|ForEach-Object{$_.Line}|Add-Content $Out -Encoding UTF8
 }
 Start-Sleep -Milliseconds 50
}
"observer-end $(Get-Date -Format o)"|Add-Content $Out -Encoding UTF8
