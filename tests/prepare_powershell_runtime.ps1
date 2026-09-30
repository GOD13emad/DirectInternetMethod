$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Root=Split-Path $PSScriptRoot -Parent
$Cache=Join-Path $Root '.cache\powershell'
$Zip=Join-Path $Cache 'PowerShell-7.6.6-win-x64.zip'
$Vendor=Join-Path $Root 'windows\vendor\pwsh'
$Url='https://github.com/PowerShell/PowerShell/releases/download/v7.6.6/PowerShell-7.6.6-win-x64.zip'
$Expected='02FE458BE20493FBDF43F61EA20610B811EE6C738AB1676C61B9CFCD1A33C860'
New-Item -ItemType Directory -Force -Path $Cache|Out-Null
$need=$true
if(Test-Path $Zip){
  $need=((Get-FileHash $Zip -Algorithm SHA256).Hash -ne $Expected)
}
if($need){
  Remove-Item $Zip -Force -ErrorAction SilentlyContinue
  Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Zip
}
$actual=(Get-FileHash $Zip -Algorithm SHA256).Hash
if($actual -ne $Expected){throw "POWERSHELL_ARCHIVE_HASH_MISMATCH:$actual"}
Remove-Item $Vendor -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $Vendor|Out-Null
Expand-Archive -LiteralPath $Zip -DestinationPath $Vendor -Force
$Pwsh=Join-Path $Vendor 'pwsh.exe'
if(!(Test-Path $Pwsh)){throw 'PWSH_EXTRACT_MISSING'}
$ver=& $Pwsh -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
if(($ver|Out-String).Trim() -ne '7.6.6'){throw "PWSH_VERSION_MISMATCH:$ver"}
$r=[ordered]@{
 status='PASS';version='7.6.6';source=$Url;archiveSha256=$actual;archiveBytes=(Get-Item $Zip).Length;
 extractedFiles=@(Get-ChildItem $Vendor -Recurse -File).Count;
 pwshSha256=(Get-FileHash $Pwsh -Algorithm SHA256).Hash;
 pwshBytes=(Get-Item $Pwsh).Length
}
$r|ConvertTo-Json -Depth 4|Set-Content -LiteralPath (Join-Path $Root 'evidence\POWERSHELL_RUNTIME_7.6.6_20260930.json') -Encoding UTF8
$r|ConvertTo-Json -Depth 4
