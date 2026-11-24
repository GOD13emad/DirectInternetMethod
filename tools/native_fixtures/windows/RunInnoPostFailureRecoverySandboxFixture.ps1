# R924: network-disabled disposable Windows Sandbox ONLY.
# Actual native Inno synthetic 1.5.6 -> postinstall failure 1.5.7 ->
# explicitly reinstall SHA-pinned synthetic older Setup. NOT real DIM rollback.
$ErrorActionPreference='Stop'
$InputRoot='C:\DIMR924\input'
$OutputRoot='C:\DIMR924\output'
$ReportPath=Join-Path $OutputRoot 'r924-native-recovery.json'
$AppId='{BE452737-93D8-4693-930C-C0ABFF932924}'
$Name='DIM R924 Synthetic Post-Failure Fixture'
$RegPath='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'+$AppId+'_is1'
$InstallDir=Join-Path $env:ProgramFiles 'DIM_R924_Synthetic_Inno'
$OwnerRoot=Join-Path $env:PROGRAMDATA 'DIM_R924_Synthetic_Owner'
$OwnerFile=Join-Path $OwnerRoot 'owner.settings'
$OldExe=Join-Path $InputRoot 'R924_Inno_1_5_6.exe'
$NewExe=Join-Path $InputRoot 'R924_Inno_1_5_7.exe'
$Stages=New-Object 'System.Collections.Generic.List[string]'
function Need([bool]$condition,[string]$reason) {
  if(-not $condition){throw $reason}
}
function Sha([string]$f) { return (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash }
function GetRegistry(){
  $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey(
       [Microsoft.Win32.RegistryHive]::LocalMachine,
       [Microsoft.Win32.RegistryView]::Registry64)
  try{
    $key=$base.OpenSubKey($RegPath)
    if($null -eq $key){return $null}
    try{
      return @{name=$key.GetValue('DisplayName');
               version=$key.GetValue('DisplayVersion');
               install=$key.GetValue('InstallLocation');
               uninstall=$key.GetValue('UninstallString')}
    } finally{$key.Close()}
  }finally{$base.Close()}
}
function CheckNative([string]$version,[string]$expectedHash){
  $found=GetRegistry
  Need ($null -ne $found) 'NATIVE_REGISTRATION_MISSING'
  Need ($found.name -eq $Name -and $found.version -eq $version) 'NATIVE_REGISTRATION_VERSION_WRONG'
  Need (-not [string]::IsNullOrWhiteSpace($found.uninstall)) 'INNO_UNINSTALLER_MISSING'
  Need ((Test-Path -LiteralPath (Join-Path $InstallDir 'code.fixture')) -and
      (Sha (Join-Path $InstallDir 'code.fixture')) -eq $expectedHash) 'NATIVE_CODE_BYTES_NOT_EXPECTED'
}
function InvokeSetup([string]$exe,[int]$expectedExit) {
  $process=Start-Process -FilePath $exe -ArgumentList @(
      '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-',
      '/NOCLOSEAPPLICATIONS') -Wait -PassThru -ErrorAction Stop
  Need ($process.ExitCode -eq $expectedExit) ('SETUP_EXIT_'+$process.ExitCode+'_EXPECTED_'+$expectedExit)
}
$report=$null
try {
  Need ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18') 'SYSTEM_GUEST_REQUIRED'
  Need ([Environment]::Is64BitProcess) 'GUEST_X64_REQUIRED'
  Need (Test-Path -LiteralPath $InputRoot) 'GUEST_INPUT_NOT_MAPPED'
  Need (Test-Path -LiteralPath $OutputRoot) 'GUEST_OUTPUT_NOT_MAPPED'
  Need (-not (Test-Path -LiteralPath $ReportPath)) 'REPORT_ALREADY_EXISTS'
  # No real product identity may be touched or even exist in this disposable test.
  Need (-not (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'DirectInternetMethod'))) 'REAL_PRODUCT_PRESENT_REFUSE'
  Need (-not (Test-Path -LiteralPath $InstallDir)) 'SYNTHETIC_APP_PREEXISTS'
  Need (-not (Test-Path -LiteralPath $OwnerRoot)) 'SYNTHETIC_OWNER_PREEXISTS'
  Need ($null -eq (GetRegistry)) 'SYNTHETIC_REGISTRY_PREEXISTS'
  $fixture=Get-Content -LiteralPath (Join-Path $InputRoot 'fixture.json') -Raw | ConvertFrom-Json
  $pins=Get-Content -LiteralPath (Join-Path $InputRoot 'inno-pins.json') -Raw | ConvertFrom-Json
  Need ($fixture.schema -eq 1 -and $pins.schema -eq 1 -and
        $fixture.scope -eq 'R924_SYNTHETIC_INNO_FAILURE_ONLY' -and
        $fixture.app_id -eq $AppId -and $pins.app_id -eq $AppId) 'INVALID_SYNTHETIC_SCOPE'
  Need ($pins.old -match '^[a-fA-F0-9]{64}$' -and $pins.new -match '^[a-fA-F0-9]{64}$') 'PIN_FORMAT_INVALID'
  Need ((Sha $OldExe) -eq $pins.old -and (Sha $NewExe) -eq $pins.new) 'SETUP_PIN_MISMATCH'
  $oldHash=$fixture.old_marker_sha256
  $newHash=$fixture.new_marker_sha256
  Need ($oldHash -match '^[a-fA-F0-9]{64}$' -and $newHash -match '^[a-fA-F0-9]{64}$' -and
       $oldHash -ne $newHash) 'MARKER_PINS_INVALID'
  [void]$Stages.Add('BOTH_SYNTHETIC_INNO_EXE_SHA_PINNED')

  [IO.Directory]::CreateDirectory($OwnerRoot)|Out-Null
  [IO.File]::WriteAllText($OwnerFile,'R924_OWNER_CONFIG_PRESERVED')
  $ownerHash=Sha $OwnerFile

  InvokeSetup $OldExe 0
  CheckNative '1.5.6' $oldHash
  Need ((Sha $OwnerFile) -eq $ownerHash) 'OWNER_CHANGED_AFTER_OLD'
  [void]$Stages.Add('REAL_INNO_OLD_SETUP_156_REGISTERED_AND_HASHED')

  # R924 injects failure at ssPostInstall, after Inno files/uninstall log.
  InvokeSetup $NewExe 67
  # Deliberate negative acceptance: Inno exit 67 DID NOT roll back.
  CheckNative '1.5.7' $newHash
  Need ((Sha $OwnerFile) -eq $ownerHash) 'OWNER_CHANGED_AFTER_FAIL'
  [void]$Stages.Add('POSTINSTALL_EXIT67_LEFT_NEW_NATIVE_CODE_AND_REGISTRY')

  # A separately SHA-pinned prior Setup explicitly restores the synthetic
  # old version. This is NOT complete independent OS/service rollback.
  InvokeSetup $OldExe 0
  CheckNative '1.5.6' $oldHash
  Need ((Sha $OwnerFile) -eq $ownerHash) 'OWNER_CHANGED_AFTER_REINSTALL'
  $installer=@(Get-ChildItem -LiteralPath $InstallDir -Filter 'unins*.exe' -File)
  Need ($installer.Count -eq 1) 'INNO_UNINSTALLER_COUNT_NOT_ONE'
  [void]$Stages.Add('EXPLICIT_PINNED_OLD_INNO_REINSTALL_RESTORED_NATIVE_CODE_AND_REGISTRY')

  $u=Start-Process -FilePath $installer[0].FullName -ArgumentList @(
       '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -PassThru -Wait
  Need ($u.ExitCode -eq 0) 'INNO_UNINSTALL_FAILED'
  Need ($null -eq (GetRegistry)) 'UNINSTALL_LEFT_REGISTRATION'
  Need (-not (Test-Path -LiteralPath (Join-Path $InstallDir 'code.fixture'))) 'UNINSTALL_LEFT_MANAGED_CODE'
  Need ((Sha $OwnerFile) -eq $ownerHash) 'OWNER_DATA_CHANGED_AFTER_UNINSTALL'
  [void]$Stages.Add('NATIVE_UNINSTALL_REMOVED_REGISTRATION_CODE_KEPT_USER_DATA')
  $report=[ordered]@{
     schema=1;status='PASS_R924_SYNTHETIC_INNO_FAILURE_REINSTALL';
     stages=$Stages.ToArray(); old_sha256=$pins.old;new_sha256=$pins.new;
     old_code_sha256=$oldHash;new_code_sha256=$newHash;
     owner_data_sha256=$ownerHash; appid=$AppId;
     real_product_rollback_accepted=$false;
     power_loss_accepted=$false;native_service_rollback_accepted=$false;
     human_release_accepted=$false
  }
} catch{
  $report=[ordered]@{
    schema=1;status='FAIL_CLOSED_R924_SYNTHETIC_INNO_FAILURE_REINSTALL';
    error=$_.Exception.Message;stages=$Stages.ToArray();
    real_product_rollback_accepted=$false;
    power_loss_accepted=$false
  }
} finally {
  if(Test-Path -LiteralPath $OutputRoot){
    $report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $ReportPath -Encoding UTF8
  }
}
if($report.status -like 'PASS_*') {exit 0}else{exit 31}
