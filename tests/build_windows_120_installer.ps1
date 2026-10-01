$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Root=Split-Path $PSScriptRoot -Parent
Set-Location $Root
$Iscc=Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'
if(!(Test-Path $Iscc)){throw 'ISCC_NOT_FOUND'}
$Out=Join-Path $Root 'delivery\DirectInternetMethod_1.2.0_Windows_Setup.exe'
Remove-Item $Out -Force -ErrorAction SilentlyContinue
& $Iscc /Qp '.\windows\installer\DirectInternetMethod.iss'
if($LASTEXITCODE -ne 0){throw "ISCC_EXIT_$LASTEXITCODE"}
if(!(Test-Path $Out)){throw 'OUTPUT_MISSING'}
$r=[ordered]@{
 status='PASS';version='1.2.0';path='delivery/DirectInternetMethod_1.2.0_Windows_Setup.exe';
 bytes=(Get-Item $Out).Length;sha256=(Get-FileHash $Out -Algorithm SHA256).Hash;
 authenticode=[string](Get-AuthenticodeSignature $Out).Status;
 guiSha256=(Get-FileHash '.\windows\app\DirectInternetMethod.exe' -Algorithm SHA256).Hash;
 serviceSha256=(Get-FileHash '.\windows\app\DirectInternetMethod.Service.exe' -Algorithm SHA256).Hash;
 manifestSha256=(Get-FileHash '.\windows\manifest.json' -Algorithm SHA256).Hash;
 built=(Get-Date).ToString('o')
}
$r|ConvertTo-Json -Depth 4|Set-Content '.\evidence\WINDOWS_120_INSTALLER_BUILD_20261001.json' -Encoding utf8
$r|ConvertTo-Json -Depth 4
