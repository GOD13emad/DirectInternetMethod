# Real product, QA-only postinstall failure on a disposable hosted Windows VM.
# Production Inno and installer are NEVER modified; the failure is injected
# ONLY into a private Inno script copy inside this ephemeral VM checkout.
[CmdletBinding()]
param([switch]$CommonBrokerRecovery)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

# NO environment-derived path is evaluated until the original-repository,
# exact-SHA, hosted-VM authorization has passed. This also safely denies
# ordinary Windows/PowerShell shells where RUNNER_TEMP is unset.
if($env:CI -cne 'true' -or $env:GITHUB_ACTIONS -cne 'true' -or
 $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
 $env:GITHUB_REPOSITORY -cne 'GOD13emad/DirectInternetMethod' -or
 $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or
 $env:GITHUB_REF -cne 'refs/heads/feature/universal-install-engine' -or
 [string]::IsNullOrWhiteSpace($env:GITHUB_WORKSPACE) -or
 [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -or
 $env:GITHUB_SHA -cnotmatch '^[0-9a-f]{40}$' -or
 $env:R980_EXPECTED_SHA -cne $env:GITHUB_SHA){
 throw 'R980_DISPOSABLE_REVIEWED_VM_ONLY'
}
if((git -C $env:GITHUB_WORKSPACE rev-parse HEAD).Trim() -cne $env:GITHUB_SHA){
 throw 'R980_EXACT_SOURCE_SHA_REQUIRED'
}

if($CommonBrokerRecovery -and $env:R982_EXPECTED_SHA -cne $env:GITHUB_SHA){
 throw 'R982_DISPOSABLE_REVIEWED_VM_ONLY'
}
$r984Mode=($env:R984_NATIVE_PREIMAGE -ceq 'true')
if($r984Mode -and (!$CommonBrokerRecovery -or $env:R983_CRASH_RECOVERY -cne 'true')){
 throw 'R984_REQUIRES_REVIEWED_R983_NATIVE_CRASH_MODE'
}
$Root=$env:GITHUB_WORKSPACE
$Sha=$env:GITHUB_SHA
$BuildDir=Join-Path $env:RUNNER_TEMP 'DIM_R846_NATIVE'
$Build=Join-Path $BuildDir 'BUILD_R846.json'
$QaDir=Join-Path $env:RUNNER_TEMP 'DIM_R980_REAL_POSTFAIL'
$Report=Join-Path $QaDir 'R980_REAL_POSTFAIL.json'
$Old=Join-Path $QaDir 'DirectInternetMethod_1.5.4_Windows_Setup.exe'
$ProductInstaller=Join-Path $Root 'delivery\DirectInternetMethod_1.5.7_Windows_Setup.exe'
$ScriptSource=Join-Path $Root 'windows\installer\DirectInternetMethod.iss'
$QaScript=Join-Path $Root 'windows\installer\R980_REAL_POSTFAIL_VM_ONLY.iss'
$QaInstaller=Join-Path $QaDir 'R980_FAILED_PRODUCT_SETUP.exe'
$App=Join-Path $env:LOCALAPPDATA 'Programs\DirectInternetMethod'
$Priv=Join-Path $env:ProgramFiles 'DirectInternetMethod\Privileged'
$Reg='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}_is1'
$OldSetupSha='FFB9A2AE19C2E89338EE12EE8DA133F5A16DBF4DCF961678C33D77D0C3843133'
$OldGuiSha='BE9C78C0B5C007B4A46480D423079C219006B730D9589279AA466B0F14BCF00F'
$OldSvcSha='2AE7EA11A94BFA3187BC7CDF63A37CB5CD5B55C313C3966330FD280ECC9ECE41'
$Gui=Join-Path $App 'app\DirectInternetMethod.exe'
$ServiceExe=Join-Path $Priv 'app\DirectInternetMethod.Service.exe'
$OwnerFile=Join-Path $env:ProgramData 'DirectInternetMethod\UserConfig\r980-private-settings.txt'
$UserEvidence=Join-Path $App 'evidence\R980_KEEP.txt'
$steps=New-Object 'System.Collections.Generic.List[string]'
$observed=[ordered]@{
 schema=1;source=$Sha;revision='R980';status='NOT_TESTED'
 realProductPostinstallFailureObserved=$false;nativeAutomaticRollbackAccepted=$false
 powercutAccepted=$false;publisherAuthenticated=$false
 separatelyProvisionedNativeBrokerAccepted=$false
 noPhysicalMachines=$true;noReboot=$true;checks=@();errors=@()
}
function Need([bool]$pass,[string]$label) {
 if(!$pass){throw ('R980_FAIL_CLOSED_'+$label)}
 [void]$steps.Add($label)
}
function ShaFile([string]$p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }
function NativeVersion {
 if(!(Test-Path -LiteralPath $Reg)){return $null}
 return [string](Get-ItemProperty -LiteralPath $Reg).DisplayVersion
}
function Setup([string]$p) {
 $process=Start-Process -FilePath $p -ArgumentList @(
  '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',
  '/NORESTARTAPPLICATIONS','/CLOSEAPPLICATIONS','/SP-') -Wait -PassThru -NoNewWindow
 return [int]$process.ExitCode
}
# Observe stable, selected native metadata. No ACL/registry writes or repair
# are performed here. This is a VM acceptance comparison, not a full backup.
function Get-R984NativePreimage {
 $svc=Get-CimInstance -ClassName Win32_Service -Filter "Name='DirectInternetMethodSvc'"
 if($null -eq $svc){throw 'R984_NATIVE_SCM_MISSING'}
 $sd=@(& sc.exe sdshow DirectInternetMethodSvc)
 if($LASTEXITCODE -ne 0){throw 'R984_NATIVE_SCM_SDDL_UNAVAILABLE'}
 $sddl=@($sd|ForEach-Object{$_.Trim()}|Where-Object{$_ -match '^[OGDS]:'})
 if($sddl.Count -ne 1){throw 'R984_NATIVE_SCM_SDDL_INVALID'}
 $key=Get-Item -LiteralPath $Reg -ErrorAction Stop
 $regValues=[ordered]@{}
 foreach($name in @('DisplayName','DisplayVersion','InstallLocation','UninstallString','QuietUninstallString','Publisher','DisplayIcon','NoModify','NoRepair')){
  if($key.GetValueNames() -ccontains $name){
   $regValues[$name]=[ordered]@{kind=[string]$key.GetValueKind($name);value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
  }else{$regValues[$name]=$null}
 }
 $acl=[ordered]@{}
 $paths=[ordered]@{app=$App;privileged=$Priv;gui=$Gui;service=$ServiceExe;uninstallKey=$Reg;serviceKey='HKLM:\SYSTEM\CurrentControlSet\Services\DirectInternetMethodSvc'}
 foreach($name in $paths.Keys){
  $entry=Get-Acl -LiteralPath $paths[$name] -ErrorAction Stop
  if([string]::IsNullOrWhiteSpace($entry.Sddl)){throw ('R984_NATIVE_ACL_UNAVAILABLE_'+$name)}
  $acl[$name]=[string]$entry.Sddl
 }
 $deps=@((Get-Service -Name DirectInternetMethodSvc -ErrorAction Stop).RequiredServices|ForEach-Object{$_.Name}|Sort-Object)
 return [ordered]@{
  scm=[ordered]@{name=[string]$svc.Name;displayName=[string]$svc.DisplayName;pathName=[string]$svc.PathName;startMode=[string]$svc.StartMode;startName=[string]$svc.StartName;serviceType=[string]$svc.ServiceType;errorControl=[string]$svc.ErrorControl;dependencies=$deps;sddl=$sddl[0]}
  registry=$regValues;acl=$acl
 }
}
function Compare-R984NativePreimage($before,$after) {
 $different=@()
 foreach($section in @('scm','registry','acl')){
  if(($before[$section]|ConvertTo-Json -Compress -Depth 8) -cne ($after[$section]|ConvertTo-Json -Compress -Depth 8)){
   $different += $section
  }
 }
 return $different
}
function Get-R984HeldMediaSha([IO.FileStream]$stream) {
 $stream.Position=0
 $hasher=[Security.Cryptography.SHA256]::Create()
 try { return [Convert]::ToHexString($hasher.ComputeHash($stream)) }
 finally { $hasher.Dispose();$stream.Position=0 }
}
function Network {
 return [ordered]@{
  dns=(@(Get-DnsClientServerAddress -AddressFamily IPv4 |
   Select-Object InterfaceIndex,ServerAddresses |
   Sort-Object InterfaceIndex |ConvertTo-Json -Compress -Depth 4) -join '')
  routes=(@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' |
   Select-Object InterfaceIndex,NextHop,RouteMetric |
   Sort-Object InterfaceIndex,NextHop |ConvertTo-Json -Compress -Depth 4) -join '')
 }
}

# Reject ALL unreviewed hosts and requests BEFORE any native file modification.
if($env:CI -cne 'true' -or $env:GITHUB_ACTIONS -cne 'true' -or
 $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
 $env:GITHUB_REPOSITORY -cne 'GOD13emad/DirectInternetMethod' -or
 $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or
 $env:GITHUB_REF -cne 'refs/heads/feature/universal-install-engine' -or
 $env:R980_EXPECTED_SHA -cne $Sha -or $Sha -cnotmatch '^[0-9a-f]{40}$' -or
 (git -C $Root rev-parse HEAD).Trim() -cne $Sha){
 throw 'R980_DISPOSABLE_REVIEWED_VM_ONLY'
}
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
 throw 'R980_GITHUB_VM_ADMIN_REQUIRED'
}
if(!(Test-Path -LiteralPath $Build) -or (Test-Path -LiteralPath $QaDir) -or
   (Test-Path -LiteralPath $QaScript) -or (Test-Path -LiteralPath $App) -or
   (Test-Path -LiteralPath $Priv) -or (Test-Path -LiteralPath $Reg)){
 throw 'R980_NOT_FRESH_VM_OR_BUILD_MISSING'
}
$build=Get-Content -LiteralPath $Build -Raw | ConvertFrom-Json
if($build.status -cne 'PASS_ISOLATED_HOSTED_V157_BUILD' -or $build.head -cne $Sha -or
   (ShaFile $ProductInstaller) -cne $build.installerSha){
 throw 'R980_BUILT_CANDIDATE_NOT_PINNED'
}
[void](New-Item -ItemType Directory -Path $QaDir)
$original=[IO.File]::ReadAllText($ScriptSource)
$originalHash=ShaFile $ScriptSource
$LF=[string][char]10
$normalized=$original.Replace(([string][char]13+$LF),$LF)
$script:modified=$normalized
$heldOldSetup=$null
function ReplaceOnce([string]$old,[string]$new) {
 $count=[regex]::Matches($script:modified,[regex]::Escape($old)).Count
 if($count -ne 1){throw ('R980_ISS_SOURCE_ANCHOR_'+$count)}
 $script:modified=$script:modified.Replace($old,$new)
}
try {
 $iscc=Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Inno Setup 6\ISCC.exe'
 if(!(Test-Path -LiteralPath $iscc)){$iscc=Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe'}
 Need (Test-Path -LiteralPath $iscc -PathType Leaf) 'INNO_COMPILER_PRESENT'
 ReplaceOnce 'OutputDir=..\..\delivery' ('OutputDir='+$QaDir)
 ReplaceOnce 'OutputBaseFilename=DirectInternetMethod_1.5.7_Windows_Setup' 'OutputBaseFilename=R980_FAILED_PRODUCT_SETUP'
 $oldCall='    InstallOrUpdateCtrldService();'+$LF+'    InstallOrUpdateService();'
 $newCall='    InstallOrUpdateCtrldService();'+$LF+
     "    RaiseException('R980_VM_ONLY_FORCED_NATIVE_POSTINSTALL_FAILURE');"+$LF+
     '    InstallOrUpdateService();'
 ReplaceOnce $oldCall $newCall
 Need ($script:modified -cne $normalized) 'QA_ISS_COPY_CHANGED'
 [IO.File]::WriteAllText($QaScript,$script:modified,[Text.UTF8Encoding]::new($false))
 & $iscc /Qp $QaScript
 Need ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $QaInstaller -PathType Leaf) -and
       (Get-Item $QaInstaller).Length -gt 50000000) 'ACTUAL_PRODUCT_QA_SETUP_COMPILED'
 Need ((ShaFile $ScriptSource) -ceq $originalHash -and
       (ShaFile $ProductInstaller) -ceq $build.installerSha) 'PRODUCTION_INSTALLER_UNCHANGED'
 $observed['qaInstallerSha']=ShaFile $QaInstaller
 # Pinned official public stable installer; never an arbitrary downloaded EXE.
 Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/GOD13emad/DirectInternetMethod/releases/download/v1.5.4/DirectInternetMethod_1.5.4_Windows_Setup.exe' -OutFile $Old -MaximumRedirection 5 -TimeoutSec 180
 Need ((Get-Item $Old).Length -eq 154270907 -and (ShaFile $Old) -ceq $OldSetupSha) 'EXACT_PUBLIC_STABLE_INSTALLER_PIN'
 $netBefore=Network
 $observed['networkBefore']=$netBefore
 Need ((Setup $Old) -eq 0) 'PUBLIC_STABLE_FRESH_INNO_INSTALL'
 Need ((NativeVersion) -ceq '1.5.4') 'PUBLIC_STABLE_HKLM_APPID'
 Need ((ShaFile $Gui) -ceq $OldGuiSha -and (ShaFile $ServiceExe) -ceq $OldSvcSha) 'PUBLIC_STABLE_INSTALLED_BINARY_HASHES'
 [void](New-Item -ItemType Directory -Path (Split-Path $OwnerFile) -Force)
 [IO.File]::WriteAllText($OwnerFile,'R980_OWNER_SETTINGS_PRESERVE')
 [void](New-Item -ItemType Directory -Path (Split-Path $UserEvidence) -Force)
 [IO.File]::WriteAllText($UserEvidence,'R980_UNKNOWN_USER_EVIDENCE_KEEP')
 $ownerHash=ShaFile $OwnerFile
 $evidenceHash=ShaFile $UserEvidence
 if($r984Mode){
  $observed['r984Scope']='R984_NATIVE_METADATA_OBSERVED_NOT_FULL_PREIMAGE'
  $observed['r984Before']=Get-R984NativePreimage
  Need (((Get-Item -LiteralPath $Old).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'R984_OLD_SETUP_NOT_REPARSE'
  # Hold the exact prior asset across the existing broker's native child exit
  # and rollback; no extra copy and no ordinary write/delete sharing.
  $heldOldSetup=[IO.File]::Open($Old,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  Need ($heldOldSetup.Length -eq 154270907 -and (Get-R984HeldMediaSha $heldOldSetup) -ceq $OldSetupSha) 'R984_HELD_OLD_SETUP_SHA_PIN'
  $writeDenied=$false
  try{
   $unexpected=[IO.File]::Open($Old,[IO.FileMode]::Open,[IO.FileAccess]::Write,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
   $unexpected.Dispose()
  }catch [IO.IOException]{
   $writeDenied=(($_.Exception.HResult -band 0xffff) -eq 32)
  }
  Need $writeDenied 'R984_HELD_OLD_SETUP_WRITE_DENIED'
 }

 if(-not $CommonBrokerRecovery){
 $exitCode=Setup $QaInstaller
 $observed['failingInstallerExitCode']=$exitCode
 Need ($exitCode -ne 0) 'REAL_PRODUCT_POSTINSTALL_EXPLICIT_FAILURE'
 Need ((ShaFile $OwnerFile) -ceq $ownerHash -and
       (ShaFile $UserEvidence) -ceq $evidenceHash) 'NATIVE_FAILURE_PRESERVED_UNKNOWN_OWNER_DATA'
 $afterVersion=NativeVersion
 $afterGuiSha=if(Test-Path -LiteralPath $Gui){ShaFile $Gui}else{''}
 $afterSvcSha=if(Test-Path -LiteralPath $ServiceExe){ShaFile $ServiceExe}else{''}
 $observed['afterFailure']=[ordered]@{
   registeredVersion=$afterVersion;guiSha256=$afterGuiSha;serviceSha256=$afterSvcSha
   matchesOldGui=($afterGuiSha -ceq $OldGuiSha);matchesNewGui=($afterGuiSha -ceq $build.guiSha)
   matchesOldService=($afterSvcSha -ceq $OldSvcSha);matchesNewService=($afterSvcSha -ceq $build.serviceSha)
 }
 # Prove we reached failure AFTER actual Inno payload replacement.
 Need ($afterGuiSha -ceq $build.guiSha -and $afterSvcSha -ceq $build.serviceSha) 'REAL_CANDIDATE_FILES_APPLIED_BEFORE_FAILURE'
 $observed.realProductPostinstallFailureObserved=$true
 $observed.nativeAutomaticRollbackAccepted=$false

 # Explicit old-Setup reinstall is a recovery REFERENCE, not automatic
 # native rollback or an accepted general product broker.
 $restoreExit=Setup $Old
 $observed['explicitOldSetupExitCode']=$restoreExit
 Need ($restoreExit -eq 0) 'EXPLICIT_PINNED_OLD_SETUP_REINSTALL'
 Need ((NativeVersion) -ceq '1.5.4' -and
       (ShaFile $Gui) -ceq $OldGuiSha -and
       (ShaFile $ServiceExe) -ceq $OldSvcSha) 'EXPLICIT_REINSTALL_RESTORED_STABLE_NATIVE_BINARIES'
 $nativeSvc=Get-Service -Name DirectInternetMethodSvc -ErrorAction Stop
 Need ($nativeSvc.Status -eq 'Running') 'EXPLICIT_REINSTALL_RESTORED_NATIVE_SERVICE_RUNNING'
 $innoLogs=@(Get-ChildItem -LiteralPath $App -Force -File |
             Where-Object {$_.Name -match '^unins[0-9]{3}[.]exe$'})
 Need ($innoLogs.Count -eq 1) 'EXPLICIT_REINSTALL_ONE_INNO_UNINSTALLER'
 Need (!(Test-Path -LiteralPath ('HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}_is1'))) 'NO_DUPLICATE_HKCU_APPID'
 Need ((ShaFile $OwnerFile) -ceq $ownerHash -and
       (ShaFile $UserEvidence) -ceq $evidenceHash) 'EXPLICIT_REINSTALL_PRESERVED_OWNER_DATA'
 } else {
  # Exact restored source must be present and pinned BEFORE the first native mutation.
  $r982input=Join-Path $QaDir 'R982_RECOVERY_INPUTS.json'
  $r982out=Join-Path $QaDir 'R982_REAL_NATIVE_BROKER_VM_RESULT.json'
  $r982plan=@{source=$Sha;new_gui=[string]$build.guiSha;new_service=[string]$build.serviceSha;failed_setup_sha=(ShaFile $QaInstaller)}
  [IO.File]::WriteAllText($r982input,($r982plan|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
  $script=Join-Path $Root 'tests/r982_windows_real_native_compensation_vm.py'
  & python $script
  if($LASTEXITCODE -ne 0){throw 'R982_COMMON_BROKER_NATIVE_COMPENSATION_UNRESOLVED'}
  $result=Get-Content -LiteralPath $r982out -Raw|ConvertFrom-Json
  Need ($result.status -ceq 'R982_REAL_INNO_FAILED_OLD_RESTORED_VIA_COMMON_BROKER' -and
        $result.real_inno_native_restore_invoked_by_common_fixture -eq $true -and
        $result.native_production_broker_accepted -eq $false -and
        $result.real_product_failed_setup_exit -eq 67) 'R982_REAL_COMMON_BROKER_VM_EVIDENCE'
  Need ((NativeVersion) -ceq '1.5.4' -and (ShaFile $Gui) -ceq $OldGuiSha -and
        (ShaFile $ServiceExe) -ceq $OldSvcSha -and
        (Get-Service DirectInternetMethodSvc).Status -eq 'Running') 'R982_REAL_NATIVE_RETURNED_TO_OLD'
  Need ((ShaFile $OwnerFile) -ceq $ownerHash -and
        (ShaFile $UserEvidence) -ceq $evidenceHash) 'R982_UNTOUCHED_OWNER_DATA'
  if($env:R983_CRASH_RECOVERY -ceq 'true'){
   Need ($result.r983_child_exit -eq 79 -and
         $result.r983_reopened_common_broker_recovered -eq $true -and
         $result.r983_crash_scope -ceq 'AFTER_REAL_INNO_EXIT_BEFORE_COMPENSATION' -and
         $result.r983_os_service_supervisor_accepted -eq $false -and
         $result.r983_reboot_accepted -eq $false) 'R983_REAL_NATIVE_CHILD_EXIT_RECOVERED'
   $observed['r983AbruptChildRecoveryObserved']=$true
  }
  $observed.realProductPostinstallFailureObserved=$true
  $observed['r982CommonBrokerVm']=$result
  $observed['vmFixtureAutomaticCompensationObserved']=$true
 }
 if($r984Mode){
  $observed['r984After']=Get-R984NativePreimage
  $observed['r984MetadataDifferences']=@(Compare-R984NativePreimage $observed.r984Before $observed.r984After)
  Need ($observed.r984MetadataDifferences.Count -eq 0) 'R984_SELECTED_NATIVE_PREIMAGE_EQUAL'
  Need ((Get-R984HeldMediaSha $heldOldSetup) -ceq $OldSetupSha -and (ShaFile $Old) -ceq $OldSetupSha) 'R984_HELD_OLD_SETUP_SHA_UNCHANGED'
  $observed['r984HeldMediaThroughRecovery']=$true
 }
 $afterNetwork=Network
 $observed['networkAfter']=$afterNetwork
 Need ($afterNetwork.dns -ceq $netBefore.dns -and
       $afterNetwork.routes -ceq $netBefore.routes) 'NO_NETWORK_DNS_ROUTE_DRIFT'
 if($CommonBrokerRecovery){
  $observed.revision='R982'
  $observed.status='PASS_R982_REAL_PRODUCT_NATIVE_COMPENSATION_VM_ONLY'
 } else {
  $observed.status='PASS_REAL_PRODUCT_INNO_POSTINSTALL_FAILURE_REQUIRES_EXTERNAL_RECOVERY'
 }
} catch {
 $observed.errors=@($observed.errors)+@($_.Exception.Message)
 $observed.status='FAIL_CLOSED_REAL_POSTINSTALL_EXPERIMENT'
} finally {
 if($null -ne $heldOldSetup){$heldOldSetup.Dispose()}
 $observed.checks=$steps.ToArray()
 $observed|ConvertTo-Json -Depth 9 |Set-Content -LiteralPath $Report -Encoding utf8
 if(Test-Path -LiteralPath $QaScript -PathType Leaf) {
  Remove-Item -LiteralPath $QaScript -Force
 }
}
Write-Output ('R980_REAL_NATIVE_FAILURE_STATUS='+$observed.status)
Write-Output ('R980_PROBE_REPORT='+$Report)
$expectedStatus=if($CommonBrokerRecovery){
 'PASS_R982_REAL_PRODUCT_NATIVE_COMPENSATION_VM_ONLY'
}else{
 'PASS_REAL_PRODUCT_INNO_POSTINSTALL_FAILURE_REQUIRES_EXTERNAL_RECOVERY'
}
if($observed.status -cne $expectedStatus){exit 31}