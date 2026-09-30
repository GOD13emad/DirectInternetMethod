$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Root=Split-Path $PSScriptRoot -Parent
Set-Location $Root
$Stage=Join-Path $Root 'tmp\service-publish-110'
$Project=Join-Path $Root 'windows\service\DirectInternetMethod.Service.csproj'
$Target=Join-Path $Root 'windows\app\DirectInternetMethod.Service.exe'
Remove-Item $Stage -Recurse -Force -ErrorAction SilentlyContinue
& dotnet publish $Project -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -o $Stage
if($LASTEXITCODE -ne 0){throw "DOTNET_PUBLISH_EXIT_$LASTEXITCODE"}
$Built=Join-Path $Stage 'DirectInternetMethod.Service.exe'
if(!(Test-Path -LiteralPath $Built)){throw 'SERVICE_OUTPUT_MISSING'}
foreach($n in @('Start-Direct.ps1','Stop-Direct.ps1','Recovery.ps1')){
 Copy-Item (Join-Path $Root ('windows\app\'+$n)) (Join-Path $Stage $n) -Force
}
$p=Start-Process -FilePath $Built -ArgumentList '--console-selftest' -Wait -PassThru
if($p.ExitCode -ne 0){throw "SERVICE_SELFTEST_EXIT_$($p.ExitCode)"}
$BuiltHash=(Get-FileHash $Built -Algorithm SHA256).Hash
Copy-Item $Built $Target -Force
$TargetHash=(Get-FileHash $Target -Algorithm SHA256).Hash
if($TargetHash -ne $BuiltHash){throw 'SERVICE_PROMOTION_HASH_MISMATCH'}
& python (Join-Path $Root 'tests\build_windows_manifest.py')
if($LASTEXITCODE -ne 0){throw "MANIFEST_BUILD_EXIT_$LASTEXITCODE"}
$Manifest=Join-Path $Root 'windows\manifest.json'
[ordered]@{
 status='PASS';version='1.1.0';service='windows/app/DirectInternetMethod.Service.exe';
 serviceBytes=(Get-Item $Target).Length;serviceSha256=$TargetHash;
 manifestSha256=(Get-FileHash $Manifest -Algorithm SHA256).Hash
}|ConvertTo-Json -Depth 4
