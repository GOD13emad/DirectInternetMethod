$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Root=Split-Path $PSScriptRoot -Parent
Set-Location $Root
$GuiStage=Join-Path $Root 'tmp\gui-publish-120'
$SvcStage=Join-Path $Root 'tmp\service-publish-120'
Remove-Item $GuiStage,$SvcStage -Recurse -Force -ErrorAction SilentlyContinue

& dotnet publish '.\windows\gui\DirectInternetMethod.csproj' -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -o $GuiStage
if($LASTEXITCODE -ne 0){throw "GUI_PUBLISH_EXIT_$LASTEXITCODE"}
& dotnet publish '.\windows\service\DirectInternetMethod.Service.csproj' -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -o $SvcStage
if($LASTEXITCODE -ne 0){throw "SERVICE_PUBLISH_EXIT_$LASTEXITCODE"}

$GuiBuilt=Join-Path $GuiStage 'DirectInternetMethod.exe'
$SvcBuilt=Join-Path $SvcStage 'DirectInternetMethod.Service.exe'
if(!(Test-Path $GuiBuilt)){throw 'GUI_OUTPUT_MISSING'}
if(!(Test-Path $SvcBuilt)){throw 'SERVICE_OUTPUT_MISSING'}
foreach($n in @('Start-Direct.ps1','Stop-Direct.ps1','Recovery.ps1')){Copy-Item (Join-Path $Root ('windows\app\'+$n)) (Join-Path $SvcStage $n) -Force}
$p=Start-Process -FilePath $SvcBuilt -ArgumentList '--console-selftest' -Wait -PassThru
if($p.ExitCode -ne 0){throw "SERVICE_SELFTEST_EXIT_$($p.ExitCode)"}

$GuiTarget=Join-Path $Root 'windows\app\DirectInternetMethod.exe'
$SvcTarget=Join-Path $Root 'windows\app\DirectInternetMethod.Service.exe'
Copy-Item $GuiBuilt $GuiTarget -Force
Copy-Item $SvcBuilt $SvcTarget -Force
& python '.\tests\build_windows_manifest.py'
if($LASTEXITCODE -ne 0){throw "MANIFEST_BUILD_EXIT_$LASTEXITCODE"}
& python '.\tests\windows_contract_audit.py'
if($LASTEXITCODE -ne 0){throw "CONTRACT_AUDIT_EXIT_$LASTEXITCODE"}
[ordered]@{
 status='PASS';version='1.2.0';
 guiBytes=(Get-Item $GuiTarget).Length;guiSha256=(Get-FileHash $GuiTarget -Algorithm SHA256).Hash;
 serviceBytes=(Get-Item $SvcTarget).Length;serviceSha256=(Get-FileHash $SvcTarget -Algorithm SHA256).Hash;
 manifestSha256=(Get-FileHash '.\windows\manifest.json' -Algorithm SHA256).Hash
}|ConvertTo-Json -Depth 4|Set-Content '.\evidence\WINDOWS_120_PAYLOAD_BUILD_20261001.json' -Encoding utf8
Get-Content '.\evidence\WINDOWS_120_PAYLOAD_BUILD_20261001.json' -Raw
