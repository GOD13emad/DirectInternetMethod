$ErrorActionPreference='Stop'
$Root=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Iscc=Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'
if(!(Test-Path $Iscc)){throw 'ISCC_MISSING'}
$Out=Join-Path $Root 'delivery\DirectInternetMethod_1.0.1_Windows_Setup.exe'
Remove-Item $Out -Force -ErrorAction SilentlyContinue
& $Iscc /Qp (Join-Path $Root 'windows\installer\DirectInternetMethod.iss')
if($LASTEXITCODE -ne 0){throw "ISCC_EXIT_$LASTEXITCODE"}
if(!(Test-Path $Out)){throw 'SETUP_OUTPUT_MISSING'}
[pscustomobject]@{
  Bytes=(Get-Item $Out).Length
  Sha256=(Get-FileHash $Out -Algorithm SHA256).Hash
  Auth=[string](Get-AuthenticodeSignature $Out).Status
}|ConvertTo-Json
Write-Output '__DIM_ISCC_DONE__'
