# R387 - disposable GitHub-hosted Windows ONLY: install, inspect, uninstall and rollback
# the exact PR30 unsigned 1.5.2 installer. Never run this on user workstations.
[CmdletBinding()]
param(
  [string]$Installer,
  [string]$BaselineInstaller,
  [switch]$StaticOnly
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$ExpectedRepo='GOD13emad/DirectInternetMethod'
$ExpectedBranch='refs/heads/feature/unsigned-windows-hosted-upgrade-20261011'
$CandidateCommit='3ead24911ca583932ed8fbcb5820b8a25b20303f'
$SetupSHA='2F054752E3B1B4715D68958CA49639AEA6FE43E0E4CBC6611DDEEBABAE2C7EB5'
$GuiSHA='B8B2BBDBA477E6E7CAACC5C2E0E11F408309000FA0657EF95E36E212376D6C4F'
$ServiceSHA='314B1E3D8D83F386CB54CD0819C7571014F3A5EAC6970F9026DA5146154C85B5'
$ManifestSHA='44434B0B03391A7BCF9513443DED1B608703225B5900F5DBDAB7F558D011AC38'
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
  Write-Output 'R387_PARSER_CONTRACT_ONLY_NO_INSTALL_OR_MUTATION'
  return
}
Assert ($env:CI -eq 'true' -and $env:GITHUB_ACTIONS -eq 'true') 'NOT_GITHUB_CI'
Assert ($env:RUNNER_ENVIRONMENT -eq 'github-hosted') 'SELF_HOSTED_REFUSED'
Assert ($env:RUNNER_OS -eq 'Windows' -and $env:RUNNER_ARCH -eq 'X64') 'WRONG_RUNNER_PLATFORM'
Assert ($env:GITHUB_REPOSITORY -eq $ExpectedRepo) 'WRONG_REPO'
Assert ($env:GITHUB_REF -eq $ExpectedBranch) 'WRONG_BRANCH'
Assert ((git rev-parse HEAD).Trim() -eq $env:GITHUB_SHA) 'CI_SOURCE_CHECKOUT_DRIFT'
Assert (-not [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) 'RUNNER_TEMP_MISSING'
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
Assert ((Get-Item -LiteralPath $ResolvedInstaller).Length -eq 157124929) 'INSTALLER_SIZE_CHANGED'
Assert ((Hash $ResolvedInstaller) -eq $SetupSHA) 'INSTALLER_SHA_CHANGED'
Assert ((Get-AuthenticodeSignature -FilePath $ResolvedInstaller).Status.ToString() -eq 'NotSigned') 'UNSIGNED_QA_NOT_UNSIGNED'
Assert ($null -eq (ReadSvc 'DirectInternetMethodSvc') -and $null -eq (ReadSvc 'ctrld')) 'GUEST_NOT_CLEAN_SERVICES_EXIST'
Assert (-not (Test-Path $AppDir) -and -not (Test-Path $Privileged) -and -not (Test-Path $StateFile)) 'GUEST_HAS_EXISTING_DIM_INSTALL_OR_NETWORK_STATE'
$Out=Join-Path $TempRoot 'DIM_R387_HOSTED'
Assert (-not (Test-Path $Out)) 'SINGLE_USE_GUEST_REPORT_EXISTS'
New-Item -Path $Out -ItemType Directory -ErrorAction Stop | Out-Null
$ReportPath=Join-Path $Out 'REPORT_R387.json'
$InstallLog=Join-Path $Out 'InnoSetup_R387.log'
$UninstallLog=Join-Path $Out 'Uninstall_R387.log'
$WatchdogPath=Join-Path $Out 'Rollback_R387.ps1'
$Task='DIM-R387-GitHub-Hosted-Recovery'
$Baseline=CurrentNet
$ExpectedSvcExe=Join-Path $Privileged 'app\DirectInternetMethod.Service.exe'
$ExpectedCtrldExe=Join-Path $Privileged 'bin\ctrld\ctrld.exe'
$Uninstaller=Join-Path $AppDir 'unins000.exe'
$State=[ordered]@{
  schema=1;revision='R387';status='UNVERIFIED';
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
  baselineNetworkSHA=$Baseline;postNetworkSHA=$null
  errors=@();productFinal='UNPROVEN'
}
$Armed=$false
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
  $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(7)
  Assert ($null -eq (Get-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue)) 'GUEST_WATCHDOG_ALREADY_PRESENT'
  Register-ScheduledTask -TaskName $Task -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -ErrorAction Stop | Out-Null
  $Armed=$true;$State.watchdogArmed=$true
  Assert ($null -ne (Get-ScheduledTask -TaskName $Task -ErrorAction Stop)) 'GUEST_WATCHDOG_NOT_ARMED'
  # Stage A: establish the real unsigned public 1.5.1 installed baseline on clean VM.
  $S151Log=Join-Path $Out 'Install151_R387.log'
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
  Assert (Test-Path -LiteralPath $Uninstaller -PathType Leaf) 'EXPECTED_INNO_UNINSTALLER_MISSING'
  $State.uninstallExit=StartKnown $Uninstaller @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+$UninstallLog+'"')) 125
  Assert ($State.uninstallExit -eq 0) ('INNO_UNINSTALL_EXIT_'+$State.uninstallExit)
  $State.uninstallServiceAbsent=WaitAbsent 'DirectInternetMethodSvc'
  $State.uninstallCtrldAbsent=WaitAbsent 'ctrld'
  Assert ($State.uninstallServiceAbsent -and $State.uninstallCtrldAbsent) 'INSTALLED_SERVICES_REMAIN_AFTER_UNINSTALL'
  $State.removedInstalledFiles=(-not (Test-Path -LiteralPath $ExpectedSvcExe) -and -not (Test-Path -LiteralPath (Join-Path $AppDir 'app\DirectInternetMethod.exe')))
  Assert $State.removedInstalledFiles 'UNINSTALL_LEFT_EXECUTABLES'
  Assert (-not (Test-Path -LiteralPath $StateFile)) 'UNINSTALL_LEFT_DIRECT_NETWORK_STATE'
  # Stage C: restore exact previous public unsigned stable by its pinned installer,
  # then uninstall again to prove a clean disposable guest rollback.
  $RollbackLog=Join-Path $Out 'Reinstall151_R387.log'
  $State.rollbackRestoreExit=StartKnown $ResolvedBaseline @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART',('/LOG="'+$RollbackLog+'"')) 165
  Assert ($State.rollbackRestoreExit -eq 0) ('V151_RESTORE_INSTALL_EXIT_'+$State.rollbackRestoreExit)
  $State.restored151OriginalHashes=((Hash (Join-Path $AppDir 'app\DirectInternetMethod.exe')) -eq $BaselineGuiSHA) -and
      ((Hash $ExpectedSvcExe) -eq $BaselineServiceSHA)
  Assert $State.restored151OriginalHashes 'PREVIOUS_STABLE_RESTORE_EXACT_BINARIES_FAILED'
  Assert ((ReadSvc 'DirectInternetMethodSvc').State -eq 'Running') 'PREVIOUS_STABLE_RESTORE_SERVICE_NOT_RUNNING'
  Assert ((CurrentNet) -eq $Baseline) 'NETWORK_DRIFT_AFTER_ROLLBACK_TO_151'
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
  $State.status='PASS_EPHEMERAL_WINDOWS_REAL_151_TO_152_UPGRADE_AND_151_RESTORE'
}
catch{
  $State.status='FAIL_CLOSED_INSTALLED_LIFECYCLE'
  $State.errors+=($_.Exception.Message)
}
finally{
  # Always run best-effort exact-owned cleanup on the disposable runner.
  try{
    if(Test-Path -LiteralPath $Uninstaller -PathType Leaf){
      $cleanup=StartKnown $Uninstaller @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') 100
      if($cleanup -ne 0){$State.errors+=('RECOVERY_UNINSTALL_EXIT_'+$cleanup)}
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
  if($State.status -like 'PASS_*' -and -not ($State.networkRestoredExact -and $State.watchdogDisarmed -and $State.removedInstalledFiles)){
    $State.status='FAIL_POSTSTATE_OR_ROLLBACK_GATE'
  }
  $State.finishedUTC=(Get-Date).ToUniversalTime().ToString('o')
  $State|ConvertTo-Json -Depth 7|Set-Content -LiteralPath $ReportPath -Encoding utf8
  Write-Output ('R387_RESULT: '+$State.status)
  Write-Output ('R387_REPORT: '+$ReportPath)
}
if($State.status -notlike 'PASS_*'){exit 78}
