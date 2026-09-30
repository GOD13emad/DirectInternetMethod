$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Root=Split-Path $PSScriptRoot -Parent
Set-Location $Root
$Files=@(
 'windows\app\DirectInternetMethod.exe','windows\app\DirectInternetMethod.ico','windows\app\Status.ps1','windows\app\DirectInternetMethod.Service.exe',
 'windows\app\Start-Direct.ps1','windows\app\Stop-Direct.ps1','windows\app\Recovery.ps1',
 'windows\bin\ctrld\ctrld.exe','windows\bin\ctrld\ctrld.toml','windows\bin\ctrld\LICENSE.txt',
 'windows\bin\zapret\winws.exe','windows\bin\zapret\WinDivert.dll','windows\bin\zapret\WinDivert64.sys','windows\bin\zapret\cygwin1.dll','windows\bin\zapret\hosts.txt','windows\bin\zapret\LICENSE.txt',
 'windows\manifest.json','windows\RELEASE.json','windows\installer\DirectInternetMethod.iss'
)
$VendorFiles=@(Get-ChildItem -LiteralPath (Join-Path $Root 'windows\vendor\pwsh') -Recurse -File | ForEach-Object {$_.FullName.Substring($Root.Length+1)})
$Files=@($Files+$VendorFiles)
$Before=@{}
foreach($f in $Files){$Before[$f]=(Get-FileHash -LiteralPath (Join-Path $Root $f) -Algorithm SHA256).Hash}
$Iscc=Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'
if(!(Test-Path $Iscc)){throw 'ISCC_NOT_FOUND'}
$Out=Join-Path $Root 'delivery\DirectInternetMethod_1.1.0_Windows_Setup.exe'
Remove-Item $Out -Force -ErrorAction SilentlyContinue
& $Iscc /Qp (Join-Path $Root 'windows\installer\DirectInternetMethod.iss')
if($LASTEXITCODE -ne 0){throw "ISCC_EXIT_$LASTEXITCODE"}
if(!(Test-Path $Out)){throw 'OUTPUT_MISSING'}
$Changed=@()
foreach($f in $Files){if((Get-FileHash -LiteralPath (Join-Path $Root $f) -Algorithm SHA256).Hash -ne $Before[$f]){$Changed+=$f}}
if($Changed.Count){throw ('SOURCE_CHANGED_DURING_BUILD:'+($Changed -join ','))}
$r=[ordered]@{
 status='PASS';version='1.1.0';path='delivery/DirectInternetMethod_1.1.0_Windows_Setup.exe';
 bytes=(Get-Item $Out).Length;sha256=(Get-FileHash $Out -Algorithm SHA256).Hash;
 authenticode=[string](Get-AuthenticodeSignature $Out).Status;frozenInputs=$Files.Count;
 guiSha256=$Before['windows\app\DirectInternetMethod.exe'];serviceSha256=$Before['windows\app\DirectInternetMethod.Service.exe'];
 manifestSha256=$Before['windows\manifest.json'];built=(Get-Date).ToString('o')
}
$r|ConvertTo-Json -Depth 4|Set-Content -LiteralPath (Join-Path $Root 'evidence\WINDOWS_110_INSTALLER_BUILD_20260930.json') -Encoding UTF8
$r|ConvertTo-Json -Depth 4
