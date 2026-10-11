[CmdletBinding()]
param([switch]$PreflightOnly)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Root=Split-Path $PSScriptRoot -Parent
Set-Location $Root
$PythonExe=$null
$Portable=Join-Path $Root 'qa\tools\python\python.exe'
if(Test-Path -LiteralPath $Portable -PathType Leaf){
  $PinnedPortableSha='4942B86A6597E5AEE0128DAA00050ED79BC21F6E709A78EB19CBFEB0C2F39AC9'
  if((Get-FileHash -LiteralPath $Portable -Algorithm SHA256).Hash -ne $PinnedPortableSha){
    throw 'WINDOWS_BUILD_PORTABLE_PYTHON_SHA_INVALID'
  }
  $PythonExe=$Portable
}else{
  foreach($name in @('py','python')){
    $cmd=Get-Command $name -ErrorAction SilentlyContinue
    if($null -eq $cmd){continue}
    try{
      $probe=(& $cmd.Source -c 'import sys; print("DIM_PY_OK" if sys.version_info >= (3,10) else "DIM_PY_OLD")' 2>$null | Out-String).Trim()
      if($LASTEXITCODE -eq 0 -and $probe -eq 'DIM_PY_OK'){
        $PythonExe=$cmd.Source
        break
      }
    }catch{}
  }
}
if([string]::IsNullOrWhiteSpace($PythonExe)){
  throw 'WINDOWS_BUILD_PYTHON_MISSING: Python 3.10+ or pinned Python 3.14.7 embeddable required for manifest and audits BEFORE dotnet build.'
}
$Vendor=Join-Path $Root 'windows\vendor\pwsh\pwsh.exe'
if(!(Test-Path -LiteralPath $Vendor -PathType Leaf)){
  throw 'WINDOWS_BUILD_VENDOR_PWSH_MISSING: stage SHA-verified PowerShell runtime BEFORE dotnet build.'
}
$VendorSha='BFB46AF89433268872DDB43D1CA7A3F433452EE91ED356A9786940F90118E285'
if((Get-FileHash -LiteralPath $Vendor -Algorithm SHA256).Hash -ne $VendorSha){
  throw 'WINDOWS_BUILD_VENDOR_PWSH_SHA_INVALID'
}
if($PreflightOnly){
  [ordered]@{status='PASS';mode='PREFLIGHT_ONLY';python=$PythonExe;
    source=(git -C $Root rev-parse HEAD);bundledPwshSha256=$VendorSha;
    noBuildOrSourceMutation=$true}|ConvertTo-Json -Compress
  return
}
$Tmp=Join-Path $Root 'tmp'
New-Item -ItemType Directory -Force -Path $Tmp | Out-Null
$LockPath=Join-Path $Tmp 'windows-152-build.lock'
$Lock=$null
try {
  try {
    $Lock=[IO.File]::Open($LockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  } catch {
    throw 'WINDOWS_152_BUILD_LOCKED'
  }
  $GuiStage=Join-Path $Root 'tmp\gui-publish-152'
  $SvcStage=Join-Path $Root 'tmp\service-publish-152'
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
  & $PythonExe '.\tests\build_windows_manifest.py'
  if($LASTEXITCODE -ne 0){throw "MANIFEST_BUILD_EXIT_$LASTEXITCODE"}
  & $PythonExe '.\tests\windows_contract_audit.py'
  if($LASTEXITCODE -ne 0){throw "CONTRACT_AUDIT_EXIT_$LASTEXITCODE"}
  [ordered]@{
   status='PASS';version='1.5.2';
   guiBytes=(Get-Item $GuiTarget).Length;guiSha256=(Get-FileHash $GuiTarget -Algorithm SHA256).Hash;
   serviceBytes=(Get-Item $SvcTarget).Length;serviceSha256=(Get-FileHash $SvcTarget -Algorithm SHA256).Hash;
   manifestSha256=(Get-FileHash '.\windows\manifest.json' -Algorithm SHA256).Hash
  }|ConvertTo-Json -Depth 4|Set-Content '.\evidence\WINDOWS_152_PAYLOAD_BUILD_20261008.json' -Encoding utf8
  Get-Content '.\evidence\WINDOWS_152_PAYLOAD_BUILD_20261008.json' -Raw

}
finally {
  if($null -ne $Lock){$Lock.Dispose()}
}
