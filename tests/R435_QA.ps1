# R435 - disposable GitHub-hosted Windows ONLY: install, inspect, uninstall and rollback
# the exact PR44 unsigned 1.5.2 candidate; ONLY on disposable GitHub-hosted VMs.
[CmdletBinding()]
param(
  [string]$Installer,
  [string]$BaselineInstaller,
  [switch]$StaticOnly
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$ExpectedRepo='GOD13emad/DirectInternetMethod'
$ExpectedBranch='refs/heads/audit/r432-windows-final-install-acceptance-20261012'
$CandidateCommit='14a3eec378eb75856f6691b7b3edc970507ee61f'
$SetupSHA=''
$GuiSHA=''
$ServiceSHA=''
$ManifestSHA=''
$AppDir=Join-Path $env:LOCALAPPDATA 'Programs\DirectInternetMethod'
$Privileged=Join-Path $env:ProgramFiles 'DirectInternetMethod\Privileged'
$StateFile='C:\ProgramData\DirectDnsDpiHarness\state.json'
function Assert([bool]$ok,[string]$code){if(-not $ok){throw $code}}
function Hash([string]$path){return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash}
function ReadSvc([string]$name){
  return Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
}
function CurrentNet{
  $route=@(Get-NetRoute -AddressFamily IPv4,IPv6 -ErrorAction Stop |
     Sort-Object AddressFamily,InterfaceIndex,DestinationPrefix,NextHop,RouteMetric |
     Select-Object AddressFamily,InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)
  $dns=@(Get-DnsClientServerAddress -ErrorAction Stop |
     Sort-Object InterfaceIndex,AddressFamily |
     Select-Object InterfaceIndex,AddressFamily,ServerAddresses)
  $text=[pscustomobject]@{route=$route;dns=$dns}|ConvertTo-Json -Compress -Depth 7
  return [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($text)))
}
function WaitAbsent([string]$name){
  for($i=0;$i -lt 45;$i++){
    if($null -eq (Get-Service -Name $name -ErrorAction SilentlyContinue)){return $true}
    Start-Sleep -Seconds 1
  }
  return $false
}
function StartKnown([string]$file,[string[]]$arguments,[int]$timeoutSec){
  $p=Start-Process -FilePath $file -ArgumentList $arguments -PassThru -ErrorAction Stop
  $finished=$p.WaitForExit($timeoutSec*1000)
  if(-not $finished){
    $still=Get-Process -Id $p.Id -ErrorAction SilentlyContinue
    if($still -and $still.Path -eq $file){
      Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
    throw ('OWNED_EXE_TIMEOUT: '+[IO.Path]::GetFileName($file))
  }
  return [int]$p.ExitCode
}
if($StaticOnly){
  Write-Output 'R435_PARSER_CONTRACT_ONLY_NO_INSTALL_OR_MUTATION'
  return
}
Assert ($env:CI -eq 'true' -and $env:GITHUB_ACTIONS -eq 'true') 'NOT_GITHUB_CI'
Assert ($env:RUNNER_ENVIRONMENT -eq 'github-hosted') 'SELF_HOSTED_REFUSED'
Assert ($env:RUNNER_OS -eq 'Windows' -and $env:RUNNER_ARCH -eq 'X64') 'WRONG_RUNNER_PLATFORM'
Assert ($env:GITHUB_REPOSITORY -eq $ExpectedRepo) 'WRONG_REPO'
Assert ($env:GITHUB_REF -eq $ExpectedBranch) 'WRONG_BRANCH'
$ProductRoot=Join-Path $env:GITHUB_WORKSPACE 'candidate'
$RollbackHelper=Join-Path $ProductRoot 'windows\app\SafeLegacyProviderRollback.ps1'
Assert ((Test-Path -LiteralPath $RollbackHelper -PathType Leaf) -and (Hash $RollbackHelper) -eq '522D78CB2A40A917B4E86DD7F98F4D3B076FD8A551B97C4B0C211FDFC7D9B322') 'R425_HELPER_SHA_NOT_VERIFIED'
Assert ((git -C $ProductRoot rev-parse HEAD).Trim() -eq $CandidateCommit) 'EXACT_CANDIDATE_CODE_SHA_NOT_CHECKED_OUT'
Assert (-not [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) 'RUNNER_TEMP_MISSING'

$ReceiptPath=Join-Path $env:RUNNER_TEMP 'DIM_R435_BUILD.json'
Assert (Test-Path -LiteralPath $ReceiptPath -PathType Leaf) 'NEW_CANDIDATE_SHA_RECEIPT_MISSING'
$Build=Get-Content -LiteralPath $ReceiptPath -Raw|ConvertFrom-Json
Assert ($Build.source -eq $CandidateCommit -and $Build.status -eq 'PASS_NATIVE_SOURCE_COMPILE_INNO_QA') 'EXACT_SHA_BUILD_RECEIPT_NOT_ACCEPTED'
$SetupSHA=[string]$Build.setupSHA
$GuiSHA=[string]$Build.guiSHA
$ServiceSHA=[string]$Build.serviceSHA
$ManifestSHA=[string]$Build.manifestSHA
$ExpectedBytes=[int64]$Build.setupBytes
foreach($value in @($SetupSHA,$GuiSHA,$ServiceSHA,$ManifestSHA)){
  Assert ($value -match '^[0-9A-Fa-f]{64}$') 'INVALID_CANDIDATE_CHECKSUM'
}
Assert ($ExpectedBytes -gt 100000000 -and $ExpectedBytes -lt 250000000) 'CANDIDATE_BYTES_UNSAFE'

$Principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
Assert ($Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'GITHUB_VM_ADMIN_NOT_GRANTED'
Assert (-not [string]::IsNullOrWhiteSpace($Installer)) 'INSTALLER_ARGUMENT_MISSING'
$ResolvedInstaller=(Resolve-Path -LiteralPath $Installer -ErrorAction Stop).Path
Assert (-not [string]::IsNullOrWhiteSpace($BaselineInstaller)) 'BASELINE_INSTALLER_ARGUMENT_MISSING'
$ResolvedBaseline=(Resolve-Path -LiteralPath $BaselineInstaller -ErrorAction Stop).Path
$BaselineSha='4E1974B5A40F96B49B7B4196FFE963DCDF65B05E4F2B89DE4EC06E794B77EE9B'
$BaselineGuiSHA='B85460B8225060E7C8C9C54F5C39D444457071E77C0BBD7CD39BF34343F8B619'
$BaselineServiceSHA='A327B01DFB7C05896DDB9F81E123E8A0362B200E52A5EB061AFDB4A7BCA367A5'
$TempRoot=[IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\')+'\'
Assert ($ResolvedInstaller.StartsWith($TempRoot,[StringComparison]::OrdinalIgnoreCase)) 'INSTALLER_OUTSIDE_HOSTED_RUNNER_TEMP'
Assert ($ResolvedBaseline.StartsWith($TempRoot,[StringComparison]::OrdinalIgnoreCase)) 'BASELINE_OUTSIDE_HOSTED_RUNNER_TEMP'
Assert ((Get-Item $ResolvedBaseline).Length -eq 157111497 -and (Hash $ResolvedBaseline) -eq $BaselineSha) 'STABLE_V151_INSTALLER_SHA_DRIFT'
Assert ((Get-AuthenticodeSignature -FilePath $ResolvedBaseline).Status.ToString() -eq 'NotSigned') 'HISTORICAL_STABLE_NOT_UNSIGNED_UNEXPECTED'
Assert ((Get-Item -LiteralPath $ResolvedInstaller).Length -eq $ExpectedBytes) 'INSTALLER_SIZE_CHANGED'
Assert ((Hash $ResolvedInstaller) -eq $SetupSHA) 'INSTALLER_SHA_CHANGED'
Assert ((Get-AuthenticodeSignature -FilePath $ResolvedInstaller).Status.ToString() -eq 'NotSigned') 'UNSIGNED_QA_NOT_UNSIGNED'
Assert ($null -eq (ReadSvc 'DirectInternetMethodSvc') -and $null -eq (ReadSvc 'ctrld')) 'GUEST_NOT_CLEAN_SERVICES_EXIST'
Assert (-not (Test-Path $AppDir) -and -not (Test-Path $Privileged) -and -not (Test-Path $StateFile)) 'GUEST_HAS_EXISTING_DIM_INSTALL_OR_NETWORK_STATE'
$Out=Join-Path $TempRoot 'DIM_R435_HOSTED'
Assert (-not (Test-Path $Out)) 'SINGLE_USE_GUEST_REPORT_EXISTS'
New-Item -Path $Out -ItemType Directory -ErrorAction Stop | Out-Null
$ReportPath=Join-Path $Out 'REPORT_R435.json'
$InstallLog=Join-Path $Out 'InnoSetup_R435.log'
$UninstallLog=Join-Path $Out 'Uninstall_R435.log'
$WatchdogPath=Join-Path $Out 'Rollback_R435.ps1'
$Task='DIM-R435-GitHub-Hosted-Recovery'
$Baseline=CurrentNet
$ExpectedSvcExe=Join-Path $Privileged 'app\DirectInternetMethod.Service.exe'
$ExpectedCtrldExe=Join-Path $Privileged 'bin\ctrld\ctrld.exe'
$Uninstaller=Join-Path $AppDir 'unins000.exe'
$State=[ordered]@{
  schema=1;revision='R435';status='UNVERIFIED';
  createdUTC=(Get-Date).ToUniversalTime().ToString('o')
  CIcommit=$env:GITHUB_SHA;candidateCommit=$CandidateCommit
  runnerEnvironment=$env:RUNNER_ENVIRONMENT;runnerOS=$env:RUNNER_OS
  WindowsOS=[Environment]::OSVersion.VersionString;runID=$env:GITHUB_RUN_ID
  installerSha256=$SetupSHA;installerNotSigned=$true
  testInstalledUnderGithubHostedOnly=$true;userMachinesModified=$false
  securityPolicyChanged=$false;noReboot=$true
  watchdogArmed=$false;watchdogDisarmed=$false
  baselineInstallExit=$null;upgradeExit=$null;rollbackRestoreExit=$null
  rollbackUninstallExit=$null;baselineGuiHashPass=$false;baselineServiceHashPass=$false
  upgradedGuiHashPass=$false;upgradedServiceHashPass=$false
  restored151OriginalHashes=$false
  installExit=$null;uninstallExit=$null
  serviceCreated=$false;serviceRunning=$false;ctrldCreated=$false
  installedGuiHashPass=$false;installedServiceHashPass=$false
  installedManifestHashPass=$false
  directEngineStateDuringInstall=$false
  uninstallServiceAbsent=$false;uninstallCtrldAbsent=$false
  removedInstalledFiles=$false;networkRestoredExact=$false
  sourceRootLicenseAccepted=$false;fullEndUserUAT='UNPROVEN'
  userDataSeeded=$false;userDataAfterUpgrade=$false;userDataAfterUninstall=$false
  userDataAfterRestore=$false;updaterPendingCleared=$false;oneUninstallerRecorded=$false
  baselineNetworkSHA=$Baseline;postNetworkSHA=$null
  errors=@();productFinal='UNPROVEN';checkpointHistory=@()
  customProviderFixtureSHA=$null;customProviderAfterUpgrade=$false;customProviderAfterUninstall=$false;customProviderAfterRestore=$false
  legacyProviderBackupSHA=$null;legacyProviderRestoreSHA=$null;legacyProviderRestoreConfirmed=$false
  watchdogBudgetMinutes=25
}
$Armed=$false
function SaveCheckpoint([string]$phase) {
  $State['lastCheckpoint']=$phase
  $State['checkpointUTC']=(Get-Date).ToUniversalTime().ToString('o')
  $State['checkpointHistory']=@($State['checkpointHistory'])+@($phase)
  $tmp=$ReportPath+'.tmp'
  Assert (-not (Test-Path -LiteralPath $tmp)) 'CHECKPOINT_TEMP_ALREADY_EXISTS_NO_BLIND_REPLAY'
  [IO.File]::WriteAllText($tmp,($State|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
  [IO.File]::Move($tmp,$ReportPath,$true)
}
SaveCheckpoint 'PREFLIGHT_APPROVED_GUEST_NO_HOST_INSTALL'
try{
  # This autonomous SYSTEM backstop runs on its own clock if the test process dies.
  # Only touches service names that were required to be absent on the fresh VM.
  $WatchdogCode=@'
$ErrorActionPreference='Continue'
$App='__APP__'
$Svc='__SVC__'
$Ctrld='__CTRLD__'
$Uninst=Join-Path $App 'unins000.exe'
$Owner=Get-CimInstance Win32_Service -Filter "Name='DirectInternetMethodSvc'" -ErrorAction SilentlyContinue
if($Owner -and $Owner.PathName -like '*DirectInternetMethod\Privileged\app\DirectInternetMethod.Service.exe*'){
  if(Test-Path -LiteralPath $Uninst){
    $P=Start-Process -FilePath $Uninst -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -Wait -PassThru -ErrorAction SilentlyContinue
  }
  sc.exe stop DirectInternetMethodSvc | Out-Null
  sc.exe delete DirectInternetMethodSvc | Out-Null
}
$OwnCtrld=Get-CimInstance Win32_Service -Filter "Name='ctrld'" -ErrorAction SilentlyContinue
if($OwnCtrld -and $OwnCtrld.PathName -like '*DirectInternetMethod\Privileged\bin\ctrld\ctrld.exe*'){
  sc.exe stop ctrld | Out-Null
  sc.exe delete ctrld | Out-Null
}
'@
  $WatchdogCode=$WatchdogCode.Replace('__APP__',$AppDir.Replace("'","''"))
  $WatchdogCode=$WatchdogCode.Replace('__SVC__',$ExpectedSvcExe.Replace("'","''"))
  $WatchdogCode=$WatchdogCode.Replace('__CTRLD__',$ExpectedCtrldExe.Replace("'","''"))
  [IO.File]::WriteAllText($WatchdogPath,$WatchdogCode,[Text.UTF8Encoding]::new($false))
  $action=New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -NonInteractive -File "'+$WatchdogPath+'"')
  $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(25)
  Assert ($null -eq (Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue)) 'GUEST_WATCHDOG_ALREADY_PRESENT'
  Register-ScheduledTask -TaskName $Task -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -ErrorAction Stop | Out-Null
  $Armed=$true;$State.watchdogArmed=$true
  Assert ($null -ne (Get-ScheduledTask -TaskName $Task -ErrorAction Stop)) 'GUEST_WATCHDOG_NOT_ARMED'
  SaveCheckpoint 'WATCHDOG_ARMED_25_MINUTES'
  # Stage A: establish the real unsigned public 1.5.1 installed baseline on clean VM.
  $S151Log=Join-Path $Out 'Install151_R435.log'
  $S151Args=@('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+$S151Log+'"'))
  $State.baselineInstallExit=StartKnown $ResolvedBaseline $S151Args 165
  Assert ($State.baselineInstallExit -eq 0) ('HISTORICAL_STABLE_INSTALL_EXIT_'+$State.baselineInstallExit)
  $s151=ReadSvc 'DirectInternetMethodSvc'
  Assert ($null -ne $s151 -and $s151.State -eq 'Running') 'V151_SERVICE_NOT_RUNNING'
  Assert ($null -ne (ReadSvc 'ctrld')) 'V151_CTRLD_SERVICE_MISSING'
  $State.baselineGuiHashPass=((Hash (Join-Path $AppDir 'app\DirectInternetMethod.exe')) -eq $BaselineGuiSHA)
  $State.baselineServiceHashPass=((Hash $ExpectedSvcExe) -eq $BaselineServiceSHA)
  Assert ($State.baselineGuiHashPass -and $State.baselineServiceHashPass) 'V151_INSTALLED_HASH_NOT_ACCEPTED'
  Assert (-not (Test-Path $StateFile)) 'V151_ACTIVE_ENGINE_UNEXPECTED'
  Assert ((CurrentNet) -eq $Baseline) 'NETWORK_DRIFT_FROM_V151_INSTALL'
  SaveCheckpoint 'BASELINE_STABLE_151_SHA_SERVICE_AND_NETWORK_PASS'

  # Only disposable synthetic test files: never user data or owner machine.
  $Seeds=@(
    (Join-Path $AppDir 'evidence\R435_QA_USER_EVIDENCE.txt'),
    (Join-Path $AppDir 'bin\R435_QA_OWN_USER_SCRIPT.txt'),
    (Join-Path $env:ProgramData 'DirectInternetMethod\UserConfig\R435_QA_PROFILE.json'),
    (Join-Path $env:LOCALAPPDATA 'DirectInternetMethod\R435_QA_SETTINGS.json')
  )
  $PinValues=@{}
  foreach($owned in $Seeds){
    Assert (-not (Test-Path -LiteralPath $owned)) ('USER_SEED_PATH_ALREADY_PRESENT_'+$owned)
    New-Item -Path (Split-Path $owned -Parent) -ItemType Directory -Force|Out-Null
    [IO.File]::WriteAllBytes($owned,[Text.Encoding]::UTF8.GetBytes('R435-synthetic-private-data:'+ [IO.Path]::GetFileName($owned)))
    $PinValues[$owned]=Hash $owned
  }

  # Preserve a truly modified Router Gateway provider file inside {app}\app.
  # Only synthetic bytes on a dedicated GitHub-hosted ephemeral runner.
  $ProviderFixture=Join-Path $AppDir 'app\router_gateway\providers.json'
  $providerNode=Get-Item -LiteralPath $ProviderFixture -Force -ErrorAction SilentlyContinue
  Assert ($null -eq $providerNode -or ($providerNode -is [IO.FileInfo] -and -not $providerNode.LinkType)) 'UNSAFE_PROVIDER_SYMLINK_OR_FOREIGN_TYPE'
  if(Test-Path -LiteralPath $ProviderFixture -PathType Leaf){
    $providerOriginal=[IO.File]::ReadAllBytes($ProviderFixture)
    [IO.File]::WriteAllBytes((Join-Path $Out 'R435_PUBLIC_BASELINE_PROVIDER_ORIGINAL.json'),$providerOriginal)
    $providerDoc=Get-Content -LiteralPath $ProviderFixture -Raw -Encoding utf8|ConvertFrom-Json -AsHashtable
    Assert ($providerDoc -is [System.Collections.IDictionary]) 'PUBLIC_PROVIDER_JSON_NOT_OBJECT'
  }else{
    Assert (-not (Test-Path -LiteralPath $ProviderFixture)) 'PUBLIC_PROVIDER_UNSAFE_FILE_TYPE'
    New-Item -ItemType Directory -Path (Split-Path $ProviderFixture -Parent) -Force|Out-Null
    $providerDoc=@{schema=1;providers=@()}
  }
  $providerDoc['r435SyntheticOwnerMarker']='PRIVATE_CUSTOM_CONFIG_PRESERVE_R435'
  [IO.File]::WriteAllText($ProviderFixture,($providerDoc|ConvertTo-Json -Depth 40),[Text.UTF8Encoding]::new($false))
  $Seeds=@($Seeds)+@($ProviderFixture)
  $PinValues[$ProviderFixture]=Hash $ProviderFixture
  $State.customProviderFixtureSHA=$PinValues[$ProviderFixture]
  $State.userDataSeeded=$true
  SaveCheckpoint 'FIVE_USER_FILES_SEEDED_INCLUDING_CUSTOM_PROVIDERS'
  function VerifySeeds([hashtable]$pins){
    foreach($key in $pins.Keys){
      if(!(Test-Path -LiteralPath $key -PathType Leaf) -or (Hash $key) -ne $pins[$key]){return $false}
    }
    return $true
  }
  $UpdaterSlot=Join-Path $env:ProgramData 'DirectInternetMethod\updates\DirectInternetMethod-update-stage.exe'
  $Pending=Join-Path $env:ProgramData 'DirectInternetMethod\pending-update.json'
  Assert (-not (Test-Path $UpdaterSlot) -and -not (Test-Path $Pending)) 'PREEXISTING_PENDING_UPDATE'
  New-Item -Path (Split-Path $UpdaterSlot -Parent) -ItemType Directory -Force|Out-Null
  Copy-Item -LiteralPath $ResolvedInstaller -Destination $UpdaterSlot -ErrorAction Stop
  Assert ((Hash $UpdaterSlot) -eq $SetupSHA) 'STAGED_INSTALLER_SHA_CHANGED'
  $PendingData=@{schema=1;targetVersion='1.5.2';tag='R435-qa-exact-source';
    installer=$UpdaterSlot;sha256=$SetupSHA;installDir=$AppDir;preparedUtc=(Get-Date).ToUniversalTime().ToString('o')}
  [IO.File]::WriteAllText($Pending,($PendingData|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
  SaveCheckpoint 'EXACT_SHA_SERVICE_UPDATER_STAGE_PREPARED'
  # Stage B: genuine in-place 1.5.1 -> 1.5.2 upgrade by newer Inno Setup.
  $SetupArgs=@('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+$InstallLog+'"'))
  $State.installExit=StartKnown $ResolvedInstaller $SetupArgs 165
  $State.upgradeExit=$State.installExit
  Assert ($State.installExit -eq 0) ('V152_UPGRADE_SETUP_EXIT_'+$State.installExit)
  $dimSvc=ReadSvc 'DirectInternetMethodSvc'
  $dnsSvc=ReadSvc 'ctrld'
  Assert ($null -ne $dimSvc -and $dimSvc.PathName.Contains($ExpectedSvcExe,[StringComparison]::OrdinalIgnoreCase)) 'OWNED_DIM_SERVICE_NOT_CREATED'
  Assert ($null -ne $dnsSvc -and $dnsSvc.PathName.Contains($ExpectedCtrldExe,[StringComparison]::OrdinalIgnoreCase)) 'OWNED_CTRLD_SERVICE_NOT_CREATED'
  $State.serviceCreated=$true;$State.ctrldCreated=$true
  $State.serviceRunning=($dimSvc.State -eq 'Running')
  Assert $State.serviceRunning 'INSTALLED_SERVICE_NOT_RUNNING'
  $State.installedGuiHashPass=((Hash (Join-Path $AppDir 'app\DirectInternetMethod.exe')) -eq $GuiSHA)
  $State.installedServiceHashPass=((Hash $ExpectedSvcExe) -eq $ServiceSHA)
  $State.upgradedGuiHashPass=$State.installedGuiHashPass
  $State.upgradedServiceHashPass=$State.installedServiceHashPass
  $State.installedManifestHashPass=((Hash (Join-Path $AppDir 'manifest.json')) -eq $ManifestSHA)
  Assert ($State.installedGuiHashPass -and $State.installedServiceHashPass -and $State.installedManifestHashPass) 'INSTALLED_FILES_SHA_MISMATCH'
  $State.directEngineStateDuringInstall=(Test-Path -LiteralPath $StateFile)
  Assert (-not $State.directEngineStateDuringInstall) 'INSTALLER_STARTED_DPI_NETWORK_UNEXPECTED'
  Assert ((CurrentNet) -eq $Baseline) 'NETWORK_CHANGED_DURING_FRESH_INSTALL'
  SaveCheckpoint 'UPGRADED_152_EXACT_GUI_SERVICE_AND_NETWORK_PASS'

  $State.userDataAfterUpgrade=VerifySeeds $PinValues
  Assert $State.userDataAfterUpgrade 'USER_DATA_CHANGED_DURING_UPGRADE'
  $State.customProviderAfterUpgrade=((Hash $ProviderFixture) -eq $State.customProviderFixtureSHA)
  Assert $State.customProviderAfterUpgrade 'CUSTOM_ROUTER_PROVIDER_LOST_IN_INPLACE_UPDATE'
  SaveCheckpoint 'UPGRADE_CUSTOM_ROUTER_PROVIDER_PRESERVED'
  for($i=0; $i -lt 35 -and ((Test-Path $Pending) -or (Test-Path $UpdaterSlot)); $i++){Start-Sleep -Seconds 3}
  $State.updaterPendingCleared=(-not (Test-Path $Pending) -and -not (Test-Path $UpdaterSlot))
  Assert $State.updaterPendingCleared 'NEW_SERVICE_PENDING_OR_VERIFIED_UPDATER_NOT_CLEANED'
  $State.oneUninstallerRecorded=(@(Get-ChildItem -LiteralPath $AppDir -File -Filter 'unins*.exe').Count -eq 1)
  Assert $State.oneUninstallerRecorded 'TWO_INNO_UNINSTALLERS_OR_DUPLICATE_APP'
  SaveCheckpoint 'ONE_UNINSTALLER_AND_SINGLE_UPDATER_SLOT_VERIFIED'
  Assert (Test-Path -LiteralPath $Uninstaller -PathType Leaf) 'EXPECTED_INNO_UNINSTALLER_MISSING'
  $State.uninstallExit=StartKnown $Uninstaller @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+$UninstallLog+'"')) 125
  Assert ($State.uninstallExit -eq 0) ('INNO_UNINSTALL_EXIT_'+$State.uninstallExit)
  $State.uninstallServiceAbsent=WaitAbsent 'DirectInternetMethodSvc'
  $State.uninstallCtrldAbsent=WaitAbsent 'ctrld'
  Assert ($State.uninstallServiceAbsent -and $State.uninstallCtrldAbsent) 'INSTALLED_SERVICES_REMAIN_AFTER_UNINSTALL'
  $State.removedInstalledFiles=(-not (Test-Path -LiteralPath $ExpectedSvcExe) -and -not (Test-Path -LiteralPath (Join-Path $AppDir 'app\DirectInternetMethod.exe')))
  Assert $State.removedInstalledFiles 'UNINSTALL_LEFT_EXECUTABLES'
  Assert (-not (Test-Path -LiteralPath $StateFile)) 'UNINSTALL_LEFT_DIRECT_NETWORK_STATE'
  $State.userDataAfterUninstall=VerifySeeds $PinValues
  Assert $State.userDataAfterUninstall 'USER_DATA_LOST_ON_152_UNINSTALL'
  $State.customProviderAfterUninstall=((Hash $ProviderFixture) -eq $State.customProviderFixtureSHA)
  Assert $State.customProviderAfterUninstall 'CUSTOM_ROUTER_PROVIDER_LOST_AFTER_UNINSTALL'
  SaveCheckpoint 'UNINSTALLED_152_CUSTOM_DATA_PRESERVED'
  # R435: staged data protection before legacy installer can overwrite custom provider.
  $stageProof=@(& $RollbackHelper -Action Stage -BaselineInstaller $ResolvedBaseline)
  Assert ($? -and ($stageProof -join ' ') -match 'PASS_EXACT_PROVIDER_STAGED_PENDING_LEGACY_ROLLBACK_SHA=') 'LEGACY_PROVIDER_BACKUP_STAGE_FAILED'
  $State.legacyProviderBackupSHA=$State.customProviderFixtureSHA
  SaveCheckpoint 'LEGACY_V151_ROLLBACK_PROVIDER_SHA_STAGED'
  # Stage C: restore exact previous public unsigned stable by its pinned installer,
  # then uninstall again to prove a clean disposable guest rollback.
  $RollbackLog=Join-Path $Out 'Reinstall151_R435.log'
  $State.rollbackRestoreExit=StartKnown $ResolvedBaseline @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+$RollbackLog+'"')) 165
  Assert ($State.rollbackRestoreExit -eq 0) ('V151_RESTORE_INSTALL_EXIT_'+$State.rollbackRestoreExit)
  $State.restored151OriginalHashes=((Hash (Join-Path $AppDir 'app\DirectInternetMethod.exe')) -eq $BaselineGuiSHA) -and
      ((Hash $ExpectedSvcExe) -eq $BaselineServiceSHA)
  Assert $State.restored151OriginalHashes 'PREVIOUS_STABLE_RESTORE_EXACT_BINARIES_FAILED'
  Assert ((ReadSvc 'DirectInternetMethodSvc').State -eq 'Running') 'PREVIOUS_STABLE_RESTORE_SERVICE_NOT_RUNNING'
  Assert ((CurrentNet) -eq $Baseline) 'NETWORK_DRIFT_AFTER_ROLLBACK_TO_151'
  $preRestore=Hash $ProviderFixture
  Assert ($preRestore -ne $State.customProviderFixtureSHA) 'EXPECTED_LEGACY_DEFAULT_REPLACEMENT_NOT_REPRODUCED'
  $restoreProof=@(& $RollbackHelper -Action Restore -BaselineInstaller $ResolvedBaseline)
  Assert ($? -and ($restoreProof -join ' ') -match 'PASS_LEGACY_151_PROVIDER_RESTORED_SHA=') 'LEGACY_PROVIDER_RESTORE_STEP_FAILED'
  $State.legacyProviderRestoreSHA=Hash $ProviderFixture
  $State.legacyProviderRestoreConfirmed=($State.legacyProviderRestoreSHA -eq $State.customProviderFixtureSHA)
  Assert $State.legacyProviderRestoreConfirmed 'LEGACY_CUSTOM_PROVIDER_NOT_RESTORED'
  $binRestored=@($restoreProof | Where-Object { $_ -match '^PASS_LEGACY_151_USER_BIN_RESTORED_COUNT=1$' })
  Assert ($binRestored.Count -eq 1) 'LEGACY_BIN_RESTORE_RECEIPT_MISSING'
  $seededBin=(Join-Path $AppDir 'bin\R435_QA_OWN_USER_SCRIPT.txt')
  Assert ((Test-Path -LiteralPath $seededBin -PathType Leaf) -and ((Hash $seededBin) -eq $PinValues[$seededBin])) 'LEGACY_BIN_CUSTOM_FILE_NOT_RESTORED'

  SaveCheckpoint 'R435_SHA_VERIFIED_CUSTOM_PROVIDER_RESTORED_AFTER_LEGACY_151'

  foreach($key in @($PinValues.Keys)){
    Assert ((Test-Path -LiteralPath $key -PathType Leaf) -and (Hash $key) -eq $PinValues[$key]) ('R435_RESTORED_SEED_SHA_MISMATCH_'+[IO.Path]::GetFileName($key))
  }
  $State.userDataAfterRestore=VerifySeeds $PinValues
  Assert $State.userDataAfterRestore 'USER_DATA_LOST_WHEN_RESTORING_151'
  $State.customProviderAfterRestore=((Hash $ProviderFixture) -eq $State.customProviderFixtureSHA)
  Assert $State.customProviderAfterRestore 'CUSTOM_ROUTER_PROVIDER_LOST_AFTER_ROLLBACK_RESTORE'
  SaveCheckpoint 'RESTORED_ORIGINAL_151_WITH_CUSTOM_PROVIDERS'
  # Previous v1.5.1 uninstaller has historic recursive cleanup; only remove
  # the EXACT four seeded QA files before final old-version teardown.
  foreach($owned in $Seeds){
    Assert ((Hash $owned) -eq $PinValues[$owned]) 'SYNTHETIC_QA_SEED_CHANGED_BEFORE_REMOVAL'
    Remove-Item -LiteralPath $owned -ErrorAction Stop
  }
  $RestoreUninstall=Join-Path $AppDir 'unins000.exe'
  Assert (Test-Path $RestoreUninstall) 'RESTORED_151_UNINSTALLER_MISSING'
  $State.rollbackUninstallExit=StartKnown $RestoreUninstall @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') 125
  Assert ($State.rollbackUninstallExit -eq 0) ('RESTORED_151_CLEANUP_EXIT_'+$State.rollbackUninstallExit)
  $State.uninstallServiceAbsent=WaitAbsent 'DirectInternetMethodSvc'
  $State.uninstallCtrldAbsent=WaitAbsent 'ctrld'
  Assert ($State.uninstallServiceAbsent -and $State.uninstallCtrldAbsent) 'RESTORED_BASELINE_SERVICE_CLEANUP_FAILED'
  $State.removedInstalledFiles=(-not (Test-Path -LiteralPath $ExpectedSvcExe) -and -not (Test-Path (Join-Path $AppDir 'app\DirectInternetMethod.exe')))
  Assert $State.removedInstalledFiles 'RESTORED_BASELINE_UNINSTALL_LEFT_EXECUTABLES'
  Assert ((CurrentNet) -eq $Baseline) 'NETWORK_DRIFT_AFTER_CLEANUP'
  $State.status='PASS_EXACT_SHA_151_TO_152_FIVE_USER_FILES_AND_PROVIDER_RESTORED'
  SaveCheckpoint 'INSTALLED_LIFECYCLE_ACCEPTANCE_PENDING_CLEANUP'
}
catch{
  $State.status='FAIL_CLOSED_INSTALLED_LIFECYCLE'
  $State.errors+=($_.Exception.Message)
}
finally{
  # Always run best-effort exact-owned cleanup on the disposable runner.
  try{
    # The successful Inno uninstaller may still have its own executable on disk
    # for milliseconds while scheduling self-deletion. Never launch it again when
    # owned service/GUI/service-binary are already absent.
    $checkSvc=ReadSvc 'DirectInternetMethodSvc'
    $checkCtrld=ReadSvc 'ctrld'
    $ownedSvc=($null -ne $checkSvc -and $checkSvc.PathName.Contains($ExpectedSvcExe,[StringComparison]::OrdinalIgnoreCase))
    $ownedCtrld=($null -ne $checkCtrld -and $checkCtrld.PathName.Contains($ExpectedCtrldExe,[StringComparison]::OrdinalIgnoreCase))
    $filesLive=(Test-Path -LiteralPath $ExpectedSvcExe) -or
      (Test-Path -LiteralPath (Join-Path $AppDir 'app\DirectInternetMethod.exe'))
    if($ownedSvc -or $ownedCtrld -or $filesLive){
      if(Test-Path -LiteralPath $Uninstaller -PathType Leaf){
        $cleanup=StartKnown $Uninstaller @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') 100
        if($cleanup -ne 0){$State.errors+=('RECOVERY_UNINSTALL_EXIT_'+$cleanup)}
      }
    }
    else{
      # No installed product remains: give Inno time to remove its own uninstaller.
      for($attempt=0; $attempt -lt 30 -and (Test-Path -LiteralPath $Uninstaller); $attempt++){
        Start-Sleep -Milliseconds 500
      }
      if(Test-Path -LiteralPath $Uninstaller){
        $State.errors+=('INNO_UNINSTALLER_SELF_DELETE_RESIDUE')
        $State.status='FAIL_UNINSTALLER_SELF_DELETE_RESIDUE'
      }
    }
    $svc=ReadSvc 'DirectInternetMethodSvc'
    if($svc -and $svc.PathName.Contains($ExpectedSvcExe,[StringComparison]::OrdinalIgnoreCase)){
      sc.exe stop DirectInternetMethodSvc | Out-Null
      sc.exe delete DirectInternetMethodSvc | Out-Null
    }
    $dns=ReadSvc 'ctrld'
    if($dns -and $dns.PathName.Contains($ExpectedCtrldExe,[StringComparison]::OrdinalIgnoreCase)){
      sc.exe stop ctrld | Out-Null
      sc.exe delete ctrld | Out-Null
    }
    $State.uninstallServiceAbsent=WaitAbsent 'DirectInternetMethodSvc'
    $State.uninstallCtrldAbsent=WaitAbsent 'ctrld'
  }catch{
    $State.errors+=('CLEANUP_EXCEPTION_'+$_.Exception.Message)
    $State.status='DEGRADED_CLEANUP'
  }
  $State.postNetworkSHA=CurrentNet
  $State.networkRestoredExact=($State.postNetworkSHA -eq $Baseline)
  if($State.networkRestoredExact -and $State.uninstallServiceAbsent -and $State.uninstallCtrldAbsent -and -not (Test-Path $StateFile)){
    if($Armed){
      try{
        Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction Stop
        $State.watchdogDisarmed=$true
      }catch{$State.errors+=('WATCHDOG_DISARM_FAILED_'+$_.Exception.Message)}
    }
  }else{
    $State.errors+=('HOSTED_NETWORK_OR_SERVICES_NOT_RESTORED_WATCHDOG_LEFT_ARMED')
  }
  if($State.status -like 'PASS_*' -and -not ($State.networkRestoredExact -and $State.watchdogDisarmed -and $State.removedInstalledFiles -and $State.errors.Count -eq 0 -and $State.userDataAfterUpgrade -and $State.userDataAfterUninstall -and $State.userDataAfterRestore -and $State.customProviderAfterUpgrade -and $State.customProviderAfterUninstall -and $State.customProviderAfterRestore -and $State.legacyProviderRestoreConfirmed -and $State.updaterPendingCleared -and $State.oneUninstallerRecorded)){
    $State.status='FAIL_POSTSTATE_OR_ROLLBACK_GATE'
  }
  $State.finishedUTC=(Get-Date).ToUniversalTime().ToString('o')
  SaveCheckpoint 'FINAL_RESULT_AND_POSTCLEANUP'
  Write-Output ('R435_RESULT: '+$State.status)
  Write-Output ('R435_REPORT: '+$ReportPath)
}
if($State.status -notlike 'PASS_*'){exit 78}
