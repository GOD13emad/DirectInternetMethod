[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Root=$env:GITHUB_WORKSPACE
if($env:CI -ne 'true' -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:GITHUB_REPOSITORY -cne 'GOD13emad/DirectInternetMethod'){throw 'R535_GITHUB_HOST_ONLY'}
if($env:GITHUB_REF -cnotin @('refs/heads/feature/r535-windows-155rc1','refs/heads/feature/r520-linux-155rc1-ci') -or (git -C $Root rev-parse HEAD).Trim() -cne $env:GITHUB_SHA){throw 'R535_BRANCH_HEAD_AUTHORITY'}
$r=Get-Content (Join-Path $Root 'windows\RELEASE.json') -Raw|ConvertFrom-Json
if($r.version -cne '1.5.5-rc1' -or $r.status -cne 'PRIVATE_WINDOWS_RC1_SOURCE_CANDIDATE_UNPUBLISHED_UNPROVEN'){throw 'R535_RC1_DECLARATION'}
$qa=Join-Path $env:RUNNER_TEMP 'DIM_R535_NATIVE'
$gstage=Join-Path $qa 'gui'
$sstage=Join-Path $qa 'service'
$gt=Join-Path $Root 'windows\app\DirectInternetMethod.exe'
$st=Join-Path $Root 'windows\app\DirectInternetMethod.Service.exe'
$installer=Join-Path $Root 'delivery\DirectInternetMethod_1.5.5-rc1_Windows_Setup.exe'
foreach($p in @($qa,$gt,$st,$installer)){if(Test-Path $p){throw ('R535_UNSAFE_RERUN_'+$p)}}
New-Item -ItemType Directory -Path $qa|Out-Null
$iscc=Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Inno Setup 6\ISCC.exe'
if(!(Test-Path $iscc)){$iscc=Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe'}
if(!(Test-Path $iscc)){throw 'R535_GITHUB_IMAGE_INNO_COMPILER_ABSENT'}
Set-Location $Root
& pwsh -NoProfile -NonInteractive -File tests/prepare_powershell_runtime.ps1
if($LASTEXITCODE -ne 0){throw 'PWSH_BUNDLE_PREP_FAILED'}
if((Get-FileHash (Join-Path $Root 'windows\vendor\pwsh\pwsh.exe') -Algorithm SHA256).Hash -cne 'BFB46AF89433268872DDB43D1CA7A3F433452EE91ED356A9786940F90118E285'){throw 'PWSH_BUNDLE_SHA'}
& dotnet publish windows/gui/DirectInternetMethod.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -o $gstage
if($LASTEXITCODE -ne 0){throw 'GUI_PUBLISH_FAILED'}
& dotnet publish windows/service/DirectInternetMethod.Service.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -o $sstage
if($LASTEXITCODE -ne 0){throw 'SERVICE_PUBLISH_FAILED'}
$gb=Join-Path $gstage 'DirectInternetMethod.exe';$sb=Join-Path $sstage 'DirectInternetMethod.Service.exe'
if(!(Test-Path $gb) -or !(Test-Path $sb)){throw 'RC1_BINARIES_MISSING'}
foreach($name in @('Start-Direct.ps1','Stop-Direct.ps1','Recovery.ps1')){Copy-Item -LiteralPath (Join-Path $Root ('windows\app\'+$name)) -Destination (Join-Path $sstage $name)}
$test=Start-Process $sb -ArgumentList '--console-selftest' -Wait -PassThru -NoNewWindow
if($test.ExitCode -ne 0){throw ('SERVICE_SELFTEST_'+$test.ExitCode)}
Copy-Item $gb $gt
Copy-Item $sb $st
& python -B tests/build_windows_manifest.py
if($LASTEXITCODE -ne 0){throw 'MANIFEST_FAILED'}
& python -B tests/dotnet10_target_contract.py
if($LASTEXITCODE -ne 0){throw 'NET10_CONTRACT_FAILED'}
& python -B tests/windows_contract_audit.py | Out-Null
if($LASTEXITCODE -ne 0){throw 'WINDOWS_AUDIT_FAILED'}
$m=Get-Content (Join-Path $Root 'windows\manifest.json') -Raw|ConvertFrom-Json
if($m.version -cne '1.5.5-rc1' -or @($m.files).Count -ne 681){throw 'RC1_MANIFEST_IDENTITY'}
& $iscc /Qp (Join-Path $Root 'windows\installer\DirectInternetMethod.iss')
if($LASTEXITCODE -ne 0){throw 'INNO_COMPILATION_FAILED'}
if(!(Test-Path $installer) -or (Get-Item $installer).Length -lt 50000000){throw 'R535_INSTALLER_MISSING'}
if([string](Get-AuthenticodeSignature $installer).Status -ne 'NotSigned'){throw 'R535_SIGNATURE_POLICY_CHANGED'}
$report=[ordered]@{
 revision='R535';stage='BUILD';status='PASS_ISOLATED_HOSTED_RC1_BUILD'
 head=$env:GITHUB_SHA;version='1.5.5-rc1';stable='v1.5.4'
 manifestCount=@($m.files).Count;manifestSha=(Get-FileHash (Join-Path $Root 'windows\manifest.json') -Algorithm SHA256).Hash
 guiSha=(Get-FileHash $gt -Algorithm SHA256).Hash
 serviceSha=(Get-FileHash $st -Algorithm SHA256).Hash
 installerSha=(Get-FileHash $installer -Algorithm SHA256).Hash
 installerBytes=(Get-Item $installer).Length;unsigned=$true
 installation='NOT_TESTED_YET';publicReleaseUnchanged=$true
}
[IO.File]::WriteAllText((Join-Path $qa 'BUILD_R535.json'),(($report|ConvertTo-Json -Depth 5)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
Write-Output ('PASS_R535_HOSTED_BUILD_SHA256='+$report.installerSha)
