[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Root=$env:GITHUB_WORKSPACE
$Dir=Join-Path $env:RUNNER_TEMP 'DIM_R848_NATIVE'
$Build=Join-Path $env:RUNNER_TEMP 'DIM_R846_NATIVE\BUILD_R846.json'
$Result=Join-Path $Dir 'NATIVE_R848.json'
$Old=Join-Path $Dir 'DirectInternetMethod_1.5.6_Windows_Setup.exe'
$New=Join-Path $Root 'delivery\DirectInternetMethod_1.5.7_Windows_Setup.exe'
$App=Join-Path $env:LOCALAPPDATA 'Programs\DirectInternetMethod'
$Priv=Join-Path $env:ProgramFiles 'DirectInternetMethod\Privileged'
$Config=Join-Path $env:ProgramData 'DirectInternetMethod\UserConfig\custom-hosts.txt'
$Provider=Join-Path $App 'app\router_gateway\providers.json'
$Evidence=Join-Path $App 'evidence\R848_KEEP.txt'
$Gui=Join-Path $App 'app\DirectInternetMethod.exe'
$Svc=Join-Path $Priv 'app\DirectInternetMethod.Service.exe'
$Key='HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}_is1'
$PublicSha='5BDE9DFFC3B866A7754DABEF9EDC853CFE519A08944163C39D812B2C8E9F3620'
$PublicGui='0CC4270B507BC9A141B4012378EE28D42C0EE8C5509E03A9ED3FB8C73B9865A3'
$PublicSvc='32AA6E88F57097D669D395999ED23A8AA85C2A330C41C542D1CB44A744C031FB'
if($env:CI -ne 'true' -or $env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:GITHUB_REPOSITORY -cne 'GOD13emad/DirectInternetMethod'){throw 'R848_HOSTED_VM_ONLY'}
if($env:GITHUB_REF -cnotin @('refs/heads/prep/r846-forward-157-native-gates') -or (git -C $Root rev-parse HEAD).Trim() -cne $env:GITHUB_SHA){throw 'R848_BRANCH_HEAD_DRIFT'}
$admin=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(!$admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'R848_ADMIN_TOKEN_REQUIRED'}
if(!(Test-Path $Build) -or (Test-Path $Result) -or (Test-Path $Old)){throw 'R848_UNSAFE_REPLAY_OR_MISSING_BUILD'}
if([string]::IsNullOrWhiteSpace($env:GH_TOKEN)){throw 'R848_GH_TOKEN_ACTIONS_READ_REQUIRED'}
$build=Get-Content $Build -Raw |ConvertFrom-Json
if($build.status -cne 'PASS_ISOLATED_HOSTED_V157_BUILD' -or $build.head -cne $env:GITHUB_SHA){throw 'R848_BUILD_AUTHORITY'}
if((Get-FileHash $New -Algorithm SHA256).Hash -cne $build.installerSha){throw 'R848_RC1_INSTALLER_SHA'}
$report=[ordered]@{schema=1;revision='R848';status='FAIL_UNPROVEN';source=$env:GITHUB_SHA;
 runner='github-hosted-windows-2025';privateInstallerSha=$build.installerSha;
 previousPrivateSha=$PublicSha;noReboot=$true;noPhysicalMachines=$true;
 checks=@();errors=@()}
function Require([bool]$ok,[string]$name) {
 if(!$ok){throw ('R848_FAIL_CLOSED_'+$name)}
 $report.checks+=($name+':PASS')
}
function FileSha([string]$p){ (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }
function Network {
 [ordered]@{
  defaultRoutes=(@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' |
    Select-Object InterfaceIndex,NextHop,RouteMetric|Sort-Object InterfaceIndex,NextHop)|ConvertTo-Json -Depth 5 -Compress)
  dns=(@(Get-DnsClientServerAddress -AddressFamily IPv4|
    Select-Object InterfaceIndex,ServerAddresses|Sort-Object InterfaceIndex)|ConvertTo-Json -Depth 5 -Compress)}
}
function Install([string]$exe,[string]$step) {
 $args=@('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/NORESTARTAPPLICATIONS','/CLOSEAPPLICATIONS','/SP-')
 $p=Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru -NoNewWindow
 Require ($p.ExitCode -eq 0) ($step+'_EXIT')
}
function ExactRegisteredUninstaller([object]$d) {
 # Inno Setup allocates uninsNNN per directory, not per version. Inspect
 # the real AppId registration and require just one corresponding file pair.
 $entries=@(Get-ChildItem -LiteralPath $App -Force -ErrorAction Stop | Where-Object { $_.Name -match '^unins[0-9]{3}[.](exe|dat|msg)$' })
 $exes=@($entries|Where-Object { $_.Extension -ieq '.exe' })
 $datas=@($entries|Where-Object { $_.Extension -ieq '.dat' })
 $msgs=@($entries|Where-Object { $_.Extension -ieq '.msg' })
 Require ($exes.Count -eq 1 -and $datas.Count -eq 1 -and $msgs.Count -le 1) 'ONE_UNINSTALLER'
 $stem=[IO.Path]::GetFileNameWithoutExtension($exes[0].Name)
 Require ($stem -ieq [IO.Path]::GetFileNameWithoutExtension($datas[0].Name)) 'MATCHED_UNINSTALL_LOG'
 Require ($msgs.Count -eq 0 -or $stem -ieq [IO.Path]::GetFileNameWithoutExtension($msgs[0].Name)) 'MATCHED_UNINSTALL_MSG'
 foreach($item in $entries) {
   Require (!$item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'UNINSTALLER_NODE_UNSAFE'
 }
 $path=[IO.Path]::GetFullPath($exes[0].FullName)
 Require ([string]$d.UninstallString -ieq ('"'+$path+'"')) 'EXACT_UNINSTALL_PATH_OWNED'
 return $path
}
function Registered([string]$version) {
 Require (Test-Path $Key) 'SINGLE_HKLM_APPID'
 $d=Get-ItemProperty -LiteralPath $Key
 Require ($d.DisplayVersion -ceq $version) 'EXACT_REGISTERED_VERSION'
 Require ($d.InstallLocation.TrimEnd('\') -ieq $App.TrimEnd('\')) 'SINGLE_INSTALL_PATH'
 Require (!(Test-Path ('HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}_is1'))) 'NO_HKCU_DUPLICATE'
 [void](ExactRegisteredUninstaller $d)
 return $d
}
try {
 Require (!(Test-Path $Key) -and !(Test-Path $App) -and !(Test-Path $Priv)) 'CLEAN_DISPOSABLE_VM'
 $before=Network
 $report.networkBefore=$before
 $artifactJson=& gh api repos/GOD13emad/DirectInternetMethod/actions/artifacts/12969796101 --jq '{id: .id, name: .name, expired: .expired, run: .workflow_run.id}'
 if($LASTEXITCODE -ne 0){throw 'R848_GITHUB_ARTIFACT_QUERY_FAILED'}
 $artifact=$artifactJson|ConvertFrom-Json
 Require ($artifact.id -eq 12969796101 -and $artifact.name -ceq 'r600-private-tested-v156-41038434425' -and $artifact.expired -eq $false -and $artifact.run -eq 41038434425) 'PRIVATE_156_ARTIFACT_PROVENANCE'
 & gh run download 41038434425 -R GOD13emad/DirectInternetMethod -n r600-private-tested-v156-41038434425 -D $Dir
 if($LASTEXITCODE -ne 0){throw 'R848_DOWNLOAD_PRIVATE_156_FAILED'}
 Require (Test-Path $Old) 'PRIVATE_156_SETUP_DOWNLOADED'
 Require ((Get-Item $Old).Length -eq 154257997 -and (FileSha $Old) -ceq $PublicSha) 'EXACT_PRIVATE_156_SETUP_PIN'
 Install $Old 'PRIVATE_156_FRESH'
 [void](Registered '1.5.6')
 Require ((FileSha $Gui) -ceq $PublicGui -and (FileSha $Svc) -ceq $PublicSvc) 'EXACT_PRIVATE_156_GUI_AND_SERVICE'
 New-Item -ItemType Directory -Path (Split-Path $Config -Parent) -Force|Out-Null
 Require (!(Test-Path $Config)) 'NO_PREEXISTING_PRIVATE_CONFIG'
 [IO.File]::WriteAllText($Config,'R848_PRIVATE_CUSTOM_SITE_SENTINEL')
 $configSha=FileSha $Config
 Require (Test-Path $Provider) 'PROVIDER_EXISTS'
 [IO.File]::AppendAllText($Provider,[Environment]::NewLine+' ')
 $providerSha=FileSha $Provider
 New-Item -ItemType Directory -Path (Split-Path $Evidence -Parent) -Force|Out-Null
 [IO.File]::WriteAllText($Evidence,'R848_USER_UNKNOWN_EVIDENCE_KEEP')
 $evidenceSha=FileSha $Evidence
 Install $New 'RC1_IN_PLACE'
 [void](Registered '1.5.7')
 Require ((FileSha $Gui) -ceq $build.guiSha -and (FileSha $Svc) -ceq $build.serviceSha) 'RC1_GUI_SERVICE_PIN'
 Require ((FileSha (Join-Path $App 'manifest.json')) -ceq $build.manifestSha) 'RC1_MANIFEST_PIN'
 & pwsh -NoProfile -NonInteractive -File (Join-Path $Root 'tests/r850_windows_privileged_manifest_attestation.ps1') -UserRoot $App -PrivilegedRoot $Priv -ExpectedVersion '1.5.7' -ExpectedManifestSha256 $build.manifestSha -ExpectedManagedFiles 681 -ExpectedPrivilegedFiles 674
 Require ($LASTEXITCODE -eq 0) 'R850_INSTALLED_PRIVILEGED_674_SHA_MATCH'
 Require ((Get-Content (Join-Path $App 'RELEASE.json') -Raw|ConvertFrom-Json).version -ceq '1.5.7') 'RC1_INSTALLED_VERSION'
 Require ((FileSha $Config) -ceq $configSha -and (FileSha $Provider) -ceq $providerSha -and (FileSha $Evidence) -ceq $evidenceSha) 'IN_PLACE_USER_DATA_PRESERVED'
 $d=Registered '1.5.7'
 $uninstaller=ExactRegisteredUninstaller $d
 $u=Start-Process $uninstaller -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -Wait -PassThru -NoNewWindow
 Require ($u.ExitCode -eq 0) 'RC1_UNINSTALL_ZERO'
 Require (!(Test-Path $Key)) 'ONE_UNINSTALLER_REMOVED_REGISTRY'
 Require ((FileSha $Config) -ceq $configSha -and (FileSha $Evidence) -ceq $evidenceSha) 'UNKNOWN_USER_DATA_SURVIVED_UNINSTALL'
 Install $Old 'PRIVATE_156_ROLLBACK_REINSTALL'
 [void](Registered '1.5.6')
 Require ((FileSha $Gui) -ceq $PublicGui -and (FileSha $Svc) -ceq $PublicSvc) 'EXACT_PRIVATE_156_BINARY_HASHES_RESTORED'
 Require ((FileSha $Config) -ceq $configSha -and (FileSha $Evidence) -ceq $evidenceSha) 'PRIVATE_CONFIG_PRESERVED_ROLLBACK'
 $after=Network;$report.networkAfter=$after
 Require ($before.defaultRoutes -ceq $after.defaultRoutes -and $before.dns -ceq $after.dns) 'NETWORK_BASELINE_EXACT'
 $report.status='PASS_HOSTED_NATIVE_156_TO_157_AND_BACK_156'
 $report.singleUninstaller=$true;$report.customProviderUpgradePreserved=$true;$report.dataPreserved=$true
} catch {
 $report.status='DEGRADED_UNRESOLVED'
 $report.errors+=([string]$_.Exception.Message)
} finally {
 [IO.File]::WriteAllText($Result,(ConvertTo-Json $report -Depth 9)+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
 Write-Output ('R848_NATIVE_STATUS='+$report.status)
 Write-Output ('R848_RECEIPT_SHA256='+((Get-FileHash $Result -Algorithm SHA256).Hash))
}
if($report.status -ne 'PASS_HOSTED_NATIVE_156_TO_157_AND_BACK_156'){throw ('R848_NATIVE_NOT_ACCEPTED_'+($report.errors -join ';'))}
