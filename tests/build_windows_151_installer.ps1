$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Root=Split-Path $PSScriptRoot -Parent
Set-Location $Root
$Tmp=Join-Path $Root 'tmp'
New-Item -ItemType Directory -Force -Path $Tmp | Out-Null
$LockPath=Join-Path $Tmp 'windows-151-build.lock'
$Lock=$null
try {
  try {
    $Lock=[IO.File]::Open($LockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  } catch {
    throw 'WINDOWS_151_BUILD_LOCKED'
  }

  $Iscc=Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'
  if(!(Test-Path $Iscc)){throw 'ISCC_NOT_FOUND'}
  $Out=Join-Path $Root 'delivery\DirectInternetMethod_1.5.1_Windows_Setup.exe'

  if(Test-Path $Out){
    $free=$false
    for($i=0;$i -lt 480 -and -not $free;$i++){
      try {
        $Probe=[IO.File]::Open($Out,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $Probe.Dispose()
        $free=$true
      } catch {
        Start-Sleep -Milliseconds 250
      }
    }
    if(-not $free){throw 'PREVIOUS_OUTPUT_STILL_LOCKED'}
    Remove-Item $Out -Force
    if(Test-Path $Out){throw 'PREVIOUS_OUTPUT_DELETE_FAILED'}
  }

  & $Iscc /Qp '.\windows\installer\DirectInternetMethod.iss'
  if($LASTEXITCODE -ne 0){throw "ISCC_EXIT_$LASTEXITCODE"}
  if(!(Test-Path $Out)){throw 'OUTPUT_MISSING'}

  $Exclusive=$false
  $OutputWaitLoops=0
  for($i=0;$i -lt 480 -and -not $Exclusive;$i++){
    $OutputWaitLoops=$i+1
    try {
      $Probe=[IO.File]::Open($Out,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
      $Probe.Dispose()
      $Exclusive=$true
    } catch {
      Start-Sleep -Milliseconds 250
    }
  }
  if(-not $Exclusive){throw 'OUTPUT_STILL_LOCKED_AFTER_ISCC_EXIT'}

  $Sizes=@()
  for($i=0;$i -lt 3;$i++){
    $Sizes += (Get-Item $Out).Length
    Start-Sleep -Milliseconds 350
  }
  if(@($Sizes | Select-Object -Unique).Count -ne 1){throw ('OUTPUT_SIZE_UNSTABLE_'+($Sizes -join '_'))}

  $r=[ordered]@{
    status='PASS';version='1.5.1';path='delivery/DirectInternetMethod_1.5.1_Windows_Setup.exe';
    bytes=(Get-Item $Out).Length;sha256=(Get-FileHash $Out -Algorithm SHA256).Hash;
    authenticode=[string](Get-AuthenticodeSignature $Out).Status;
    guiSha256=(Get-FileHash '.\windows\app\DirectInternetMethod.exe' -Algorithm SHA256).Hash;
    serviceSha256=(Get-FileHash '.\windows\app\DirectInternetMethod.Service.exe' -Algorithm SHA256).Hash;
    manifestSha256=(Get-FileHash '.\windows\manifest.json' -Algorithm SHA256).Hash;
    buildLock='exclusive-shared-windows-151';
    outputExclusiveOpen='PASS';
    outputExclusiveWaitMs=($OutputWaitLoops*250);
    outputStableSamples=$Sizes;
    built=(Get-Date).ToString('o')
  }
  $r|ConvertTo-Json -Depth 4|Set-Content '.\evidence\WINDOWS_151_INSTALLER_BUILD_20261005.json' -Encoding utf8
  $r|ConvertTo-Json -Depth 4
}
finally {
  if($null -ne $Lock){$Lock.Dispose()}
}
