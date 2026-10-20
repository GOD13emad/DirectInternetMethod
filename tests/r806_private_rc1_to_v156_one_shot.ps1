[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$Repo='GOD13emad/DirectInternetMethod'
$ExpectedParent='2ff2d4db27a4f7c125ad9099157aa0d29af9b568'
if($env:CI -cne 'true' -or $env:GITHUB_ACTIONS -cne 'true' -or
   $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
   $env:GITHUB_REPOSITORY -cne $Repo -or
   $env:GITHUB_REF -cne 'refs/heads/prep/r805-windows-156' -or
   [string]::IsNullOrEmpty($env:GH_TOKEN)){throw 'R806_UNTRUSTED_RUNNER_CONTEXT'}
if((git rev-parse HEAD).Trim() -cne $env:GITHUB_SHA -or
   (git rev-parse HEAD^).Trim() -cne $ExpectedParent){throw 'R806_ONE_SHOT_PARENT_OR_HEAD_MISMATCH'}
$identity=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(!$identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'R806_ADMINISTRATOR_VM_REQUIRED'}
if(!(Get-Command gh -ErrorAction SilentlyContinue)){throw 'R806_GH_CLI_MISSING'}

$Scratch=Join-Path $env:RUNNER_TEMP 'DIM_R806_NATIVE'
if(Test-Path -LiteralPath $Scratch){throw 'R806_TEMP_ALREADY_EXISTS'}
New-Item -ItemType Directory -Path $Scratch |Out-Null
$PreviousDir=Join-Path $Scratch 'previous'
$NextDir=Join-Path $Scratch 'next'
New-Item -ItemType Directory -Path @($PreviousDir,$NextDir)|Out-Null
$Old=Join-Path $PreviousDir 'DirectInternetMethod_1.5.5-rc1_Windows_Setup.exe'
$New=Join-Path $NextDir 'DirectInternetMethod_1.5.6_Windows_Setup.exe'
$OldSHA='FD078EA29369877DC6DEF89125DDC2FD8BDB67CD994A2811681093D115B266C3'
$NewSHA='13E7B8ACB0392D0CB5C2CB64CFCBB4FC4B5F0E69B10E391803BF899CECBF16DA'
$App=Join-Path $env:LOCALAPPDATA 'Programs\DirectInternetMethod'
$Private=Join-Path $env:ProgramFiles 'DirectInternetMethod\Privileged'
$Config=Join-Path $env:ProgramData 'DirectInternetMethod\UserConfig\custom-hosts.txt'
$Provider=Join-Path $App 'app\router_gateway\providers.json'
$Unknown=Join-Path $App 'evidence\R806_UNMANAGED_KEEP.txt'
$Gui=Join-Path $App 'app\DirectInternetMethod.exe'
$Svc=Join-Path $Private 'app\DirectInternetMethod.Service.exe'
$Key='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}_is1'
$Receipt=Join-Path $Scratch 'NATIVE_R806.json'
$report=[ordered]@{
 schema=1;revision='R806';status='FAIL_UNPROVEN';head=$env:GITHUB_SHA
 oldArtifactId=12220929264;newArtifactId=12247793992;shaOld=$OldSHA;shaNew=$NewSHA
 hostedOnly=$true;checks=@();errors=@();networkPreserved=$false
}
function Need([bool]$v,[string]$name){
 if(!$v){throw ('R806_FAIL_CLOSED_'+$name)}
 $script:report.checks+=($name+':PASS')
}
function FileSha([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash}
function NetIdentity{
 [ordered]@{
 routes=(@(Get-NetRoute -DestinationPrefix '0.0.0.0/0'|Select-Object InterfaceIndex,NextHop,RouteMetric|Sort-Object InterfaceIndex,NextHop)|ConvertTo-Json -Depth 5 -Compress)
 dns=(@(Get-DnsClientServerAddress -AddressFamily IPv4|Select-Object InterfaceIndex,ServerAddresses|Sort-Object InterfaceIndex)|ConvertTo-Json -Depth 5 -Compress)
 }
}
function Install([string]$path,[string]$stage){
 $argv=@('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/NORESTARTAPPLICATIONS','/CLOSEAPPLICATIONS','/SP-')
 $p=Start-Process -FilePath $path -ArgumentList $argv -Wait -PassThru -NoNewWindow
 Need ($p.ExitCode -eq 0) ($stage+'_EXIT')
}
function Registration([string]$version){
 Need (Test-Path -LiteralPath $Key) 'ONE_HKLM_APPID'
 $x=Get-ItemProperty -LiteralPath $Key
 Need ($x.DisplayVersion -ceq $version) 'EXACT_REGISTERED_VERSION'
 Need ($x.InstallLocation.TrimEnd('\') -ieq $App.TrimEnd('\')) 'ONE_INSTALL_DIRECTORY'
 Need (!(Test-Path -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}_is1')) 'NO_HKCU_DUPLICATE'
 $items=@(Get-ChildItem -LiteralPath $App -Force | Where-Object {$_.Name -match '^unins[0-9]{3}[.](exe|dat|msg)$'})
 $exe=@($items|Where-Object {$_.Extension -ieq '.exe'})
 $dat=@($items|Where-Object {$_.Extension -ieq '.dat'})
 $msg=@($items|Where-Object {$_.Extension -ieq '.msg'})
 Need ($exe.Count -eq 1 -and $dat.Count -eq 1 -and $msg.Count -le 1) 'ONE_UNINSTALLER_AND_LOG'
 $stem=[IO.Path]::GetFileNameWithoutExtension($exe[0].Name)
 Need ($stem -ieq [IO.Path]::GetFileNameWithoutExtension($dat[0].Name)) 'MATCHING_LOG_STEM'
 foreach($f in $items){Need (!$f.PSIsContainer -and ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'NO_REPARSE_UNINSTALLER'}
 Need ([string]$x.UninstallString -ieq ('"'+$exe[0].FullName+'"')) 'APPID_OWNED_UNINSTALLER'
 return $exe[0].FullName
}
try{
 Need (!(Test-Path $Key) -and !(Test-Path $App) -and !(Test-Path $Private)) 'EMPTY_DISPOSABLE_WINDOWS_VM'
 $before=NetIdentity
 foreach($artifact in @(
   @{id=12220929264;name='r600-private-tested-rc1-39323686950';run=39323686950;dir=$PreviousDir},
   @{id=12247793992;name='r600-private-tested-v156-39386955434';run=39386955434;dir=$NextDir})){
   $m=(& gh api "repos/$Repo/actions/artifacts/$($artifact.id)" |ConvertFrom-Json)
   if($LASTEXITCODE -ne 0){throw 'R806_GH_ARTIFACT_API_FAILED'}
   Need ([long]$m.id -eq [long]$artifact.id -and $m.name -ceq $artifact.name -and
         !$m.expired -and [long]$m.workflow_run.id -eq [long]$artifact.run) 'EXACT_PREVIOUSLY_TESTED_ARTIFACT_ORIGIN'
   & gh run download $artifact.run -n $artifact.name -D $artifact.dir -R $Repo
   if($LASTEXITCODE -ne 0){throw 'R806_GH_ARTIFACT_DOWNLOAD_FAILED'}
 }
 Need (@(Get-ChildItem -LiteralPath $PreviousDir -File).Count -eq 1 -and
       @(Get-ChildItem -LiteralPath $NextDir -File).Count -eq 1) 'EXACT_SINGLE_INSTALLER_EACH'
 foreach($p in @($Old,$New)){
   Need (Test-Path -LiteralPath $p -PathType Leaf) 'INSTALLER_FILE'
   $f=Get-Item -LiteralPath $p
   Need (($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'INSTALLER_NO_REPARSE'
   Need ((Get-AuthenticodeSignature -FilePath $p).Status.ToString() -ceq 'NotSigned') 'UNSIGNED_POLICY_UNCHANGED'
 }
 Need ((Get-Item $Old).Length -eq 154314003 -and (FileSha $Old) -ceq $OldSHA) 'PRIOR_RC1_EXACT_SHA'
 Need ((Get-Item $New).Length -eq 154320361 -and (FileSha $New) -ceq $NewSHA) 'V156_EXACT_SHA'
 Install $Old 'PRIVATE_RC1_FRESH'
 [void](Registration '1.5.5-rc1')
 $originalGui=FileSha $Gui
 $originalSvc=FileSha $Svc
 Need ((Get-Item $Gui).VersionInfo.FileVersion -ceq '1.5.5.0' -and
       (Get-Item $Svc).VersionInfo.FileVersion -ceq '1.5.5.0') 'OLD_RC1_FILEVERSION'
 New-Item -ItemType Directory -Path (Split-Path $Config -Parent) -Force|Out-Null
 Need (!(Test-Path $Config)) 'NO_PREVIOUS_PRIVATE_CONFIG'
 [IO.File]::WriteAllText($Config,'R806_CUSTOM_SITES_HASH_SENTINEL')
 $configSha=FileSha $Config
 Need (Test-Path -LiteralPath $Provider -PathType Leaf) 'PROVIDER_JSON_PRESENT'
 [IO.File]::AppendAllText($Provider,[Environment]::NewLine+' ')
 $providerSha=FileSha $Provider
 New-Item -ItemType Directory -Path (Split-Path $Unknown -Parent) -Force|Out-Null
 [IO.File]::WriteAllText($Unknown,'R806_UNMANAGED_EVIDENCE_SURVIVE')
 $unknownSha=FileSha $Unknown
 Install $New 'PRIVATE_RC1_TO_V156'
 $uninstaller=Registration '1.5.6'
 Need ((Get-Item $Gui).VersionInfo.FileVersion -ceq '1.5.6.0' -and
       (Get-Item $Svc).VersionInfo.FileVersion -ceq '1.5.6.0') 'NEW_V156_FILEVERSION'
 Need ((FileSha $Gui) -ceq '1EAD4A7212E0ADE871CCE9864088891A7A96E0E5D890A5D5A7E361AFDA4436D2' -and
       (FileSha $Svc) -ceq '237FDF518783194295072B6C1C14C744BB83E260005BDA4117DBB30FD8909130') 'R805_TESTED_GUI_SERVICE_DIGESTS'
 Need ((FileSha (Join-Path $App 'manifest.json')) -ceq '0084F000B7E4741C181F92240378206E1249C643A6291611D15C1021AA8FD328') 'R805_TESTED_MANIFEST'
 Need ((FileSha $Config) -ceq $configSha -and (FileSha $Provider) -ceq $providerSha -and
       (FileSha $Unknown) -ceq $unknownSha) 'USER_DATA_PRESERVED_RC1_TO_156'
 $un=Start-Process -FilePath $uninstaller -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -Wait -PassThru -NoNewWindow
 Need ($un.ExitCode -eq 0 -and !(Test-Path $Key)) 'V156_UNINSTALL_EXIT_REGISTRY'
 Need ((FileSha $Config) -ceq $configSha -and (FileSha $Unknown) -ceq $unknownSha) 'UNMANAGED_DATA_SURVIVES_UNINSTALL'
 Install $Old 'RESTORE_PRIVATE_RC1'
 [void](Registration '1.5.5-rc1')
 Need ((FileSha $Gui) -ceq $originalGui -and (FileSha $Svc) -ceq $originalSvc) 'PREVIOUS_RC1_BINARIES_RESTORED'
 Need ((FileSha $Config) -ceq $configSha -and (FileSha $Unknown) -ceq $unknownSha) 'PREVIOUS_RC1_CONFIG_RESTORED'
 $after=NetIdentity
 Need ($before.routes -ceq $after.routes -and $before.dns -ceq $after.dns) 'DEFAULT_ROUTES_AND_DNS_UNCHANGED'
 $report.status='PASS_HOSTED_NATIVE_PRIVATE_RC1_TO_V156_AND_BACK_TO_RC1'
 $report.networkPreserved=$true
}catch{
 $report.errors+=([string]$_.Exception.Message)
}finally{
 [IO.File]::WriteAllText($Receipt,(ConvertTo-Json $report -Depth 10)+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
 Write-Output ('R806_NATIVE_STATUS='+$report.status)
 Write-Output ('R806_RECEIPT_SHA256='+((Get-FileHash $Receipt -Algorithm SHA256).Hash))
 Write-Output ('R806_CHECKS='+$report.checks.Count)
}
if($report.status -cne 'PASS_HOSTED_NATIVE_PRIVATE_RC1_TO_V156_AND_BACK_TO_RC1'){
 throw ('R806_ACCEPTANCE_NOT_PROVEN_'+($report.errors -join ';'))
}
