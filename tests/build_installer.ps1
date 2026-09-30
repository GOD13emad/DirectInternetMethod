$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
Set-Location $root
$iscc=Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'
$out=Join-Path $root 'delivery\DirectInternetMethod_1.0.1_Windows_Setup.exe'
Remove-Item $out -Force -ErrorAction SilentlyContinue
& $iscc /Qp (Join-Path $root 'windows\installer\DirectInternetMethod.iss')
if($LASTEXITCODE -ne 0){throw 'ISCC_FAIL'}
$h=(Get-FileHash $out -Algorithm SHA256).Hash
[pscustomobject]@{Status='PASS';Path=$out;Bytes=(Get-Item $out).Length;Sha256=$h;Auth=[string](Get-AuthenticodeSignature $out).Status}|ConvertTo-Json
