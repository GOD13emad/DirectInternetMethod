# R933 TEST ONLY: Windows Sandbox SYSTEM, genuine vendor Qt metadata-shell.
# No owner host installation, SCM, Tailscale, network or product changes.
$ErrorActionPreference='Stop'
$input='C:\DIMR933\input'
$output='C:\DIMR933\output'
$root='C:\DIMR933'
$target=Join-Path $root 'qt-shell'
$owner=Join-Path $root 'owner-data\settings.ini'
$pinFile=Join-Path $input 'native-pins.json'
$reportFile=Join-Path $output 'R933_WIN_QT_NATIVE_PROOF.json'
$stages=New-Object 'System.Collections.Generic.List[string]'
$record=$null

function Must([bool] $ok,[string] $reason){
 if(-not $ok){throw $reason}
}
function Sha([string]$path){
 return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Invoke-QtNative([string]$tag,[string]$program,[string[]]$arguments){
 $stdout=Join-Path $output ($tag+'.stdout.log')
 $stderr=Join-Path $output ($tag+'.stderr.log')
 $process=Start-Process -FilePath $program -ArgumentList $arguments -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden
 if(-not $process.WaitForExit(90000)){
   Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
   throw ('R933_GUEST_NATIVE_QT_TIMEOUT_'+$tag)
 }
 return [int]$process.ExitCode
}
function Inventory(){
 $component=Join-Path $target 'components.xml'
 Must (Test-Path -LiteralPath $component) 'R933_GUEST_QT_COMPONENTS_FILE_ABSENT'
 [xml]$doc=Get-Content -LiteralPath $component -Raw
 $rows=@()
 foreach($node in $doc.SelectNodes('/Packages/Package')){
   $name=$node.SelectSingleNode('Name')
   $ver=$node.SelectSingleNode('Version')
   Must ($null -ne $name -and $null -ne $ver) 'R933_QT_METADATA_SCHEMA_INVALID'
   $rows+=([string]$name.InnerText + ':' + [string]$ver.InnerText)
 }
 return @($rows)
}
function Assert-External-Isolation([string]$sha){
 Must ((Sha $owner) -eq $sha) 'R933_GUEST_OWNER_CONFIG_CHANGED'
 foreach($dir in @('code','user','app','managed-protected','managed-user')){
   Must (-not (Test-Path -LiteralPath (Join-Path $target $dir))) ('R933_QT_OWNED_PRODUCT_CODE_'+$dir)
 }
 Must (-not (Get-Service -Name 'DirectInternetMethodSvc' -ErrorAction SilentlyContinue)) 'R933_REAL_DIM_SERVICE_PRESENT'
}

try {
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 Must ($identity.User.Value -eq 'S-1-5-18') 'R933_GUEST_SYSTEM_TOKEN_REQUIRED'
 Must (Test-Path -LiteralPath 'C:\Users\WDAGUtilityAccount') 'R933_WINDOWS_SANDBOX_IDENTITY_REQUIRED'
 Must ((Test-Path -LiteralPath $input) -and (Test-Path -LiteralPath $output)) 'R933_GUEST_SHARES_MISSING'
 Must (-not (Test-Path -LiteralPath $target) -and -not (Test-Path -LiteralPath $reportFile)) 'R933_GUEST_ROOT_NOT_FRESH'
 Must (-not (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'DirectInternetMethod'))) 'R933_REAL_PRODUCT_PRESENT_REFUSE'
 $pins=Get-Content -LiteralPath $pinFile -Raw |ConvertFrom-Json
 Must ($pins.schema -eq 1 -and $pins.scope -eq 'R933_WINDOWS_SANDBOX_QT_VENDOR_METADATA_ONLY') 'R933_GUEST_PIN_SCHEMA_INVALID'
 Must ((Sha $PSCommandPath) -eq $pins.guest_runner_sha256) 'R933_GUEST_RUNNER_SOURCE_PIN_DRIFT'
 Must ($pins.project_source_head -eq '308faa0e08b7803a7f96a417128ddd36aef2237f') 'R933_SOURCE_HEAD_CHANGED'
 Must ($pins.qt_product_payload_file_count -eq 0 -and $pins.network_enabled -eq $false -and $pins.product_installed -eq $false) 'R933_PRECONDITION_TRUST_OVERCLAIM'
 $engine=Join-Path $input 'dim-universal-engine.exe'
 $setup=Join-Path $input 'qt-shell-setup.exe'
 Must ((Sha $engine) -eq $pins.frozen_engine_sha256 -and (Sha $setup) -eq $pins.vendor_qt_setup_sha256) 'R933_GUEST_PINNED_BINARY_CHANGED'
 Must (((Get-Item $engine).Length -eq $pins.frozen_engine_bytes) -and ((Get-Item $setup).Length -eq $pins.vendor_qt_setup_bytes)) 'R933_GUEST_NATIVE_BINARY_SIZE_CHANGED'
 [void]$stages.Add('REAL_SYSTEM_WINDOWS_SANDBOX_AND_PINNED_OFFICIAL_VENDOR_BINARIES')
 $ownerFolder=Split-Path $owner -Parent
 [void][IO.Directory]::CreateDirectory($ownerFolder)
 [IO.File]::WriteAllText($owner,'R933_SYNTHETIC_OWNER_INDEPENDENT_OF_QT_SHELL')
 $ownerSha=Sha $owner
 $a=@('--root',$target,'--confirm-command','--accept-licenses','--default-answer','install')
 $rc=Invoke-QtNative 'install-100' $setup $a
 Must ($rc -eq 0) ('R933_WIN_QT_NATIVE_INSTALL_RC_'+$rc)
 $maintenance=Join-Path $target 'maintenancetool.exe'
 Must (Test-Path -LiteralPath $maintenance) 'R933_WIN_QT_MAINTENANCE_BINARY_MISSING'
 Copy-Item -LiteralPath (Join-Path $target 'components.xml') -Destination (Join-Path $output 'components-after-install.xml')
 $list=@(Inventory)
 ($list | ConvertTo-Json -Compress) | Set-Content -LiteralPath (Join-Path $output 'initial-inventory.json') -Encoding utf8
 Must ($list.Count -eq 1 -and $list[0] -eq 'org.dim.bridge.fixture:1.0.0-1') 'R933_QT_INITIAL_COMPONENT_WRONG'
 Must ((Get-Content (Join-Path $output 'install-100.stdout.log') -Raw).Contains('PASS_UNIVERSAL_TRANSACTION_FIXTURE')) 'R933_QT_NO_SHARED_FROZEN_ENGINE_RUN'
 Assert-External-Isolation $ownerSha
 [void]$stages.Add('REAL_QT_VENDOR_SETUP_EXECUTES_EXISTING_FROZEN_COMMON_ENGINE_NO_CODE_PAYLOAD')

 $repo101='file:///C:/DIMR933/input/repository-101'
 $repo102='file:///C:/DIMR933/input/repository-102'
 $rc=Invoke-QtNative 'update-101' $maintenance @('--set-temp-repository',$repo101,'--confirm-command','--accept-licenses','--default-answer','update')
 Must ($rc -eq 0) ('R933_QT_HEALTHY_UPGRADE_RC_'+$rc)
 $list=@(Inventory)
 Must ($list.Count -eq 1 -and $list[0] -eq 'org.dim.bridge.fixture:1.0.1-1') 'R933_QT_HEALTHY_UPGRADE_BAD_COMPONENT'
 Must ((Get-Content (Join-Path $output 'update-101.stdout.log') -Raw).Contains('PASS_UNIVERSAL_TRANSACTION_FIXTURE')) 'R933_QT_HEALTHY_UPGRADE_NO_SHARED_CORE'
 Assert-External-Isolation $ownerSha
 [void]$stages.Add('REAL_QT_VENDOR_HEALTHY_SHELL_UPDATE_EXTERNAL_OWNER_UNCHANGED')

 $rc=Invoke-QtNative 'failed-update-102' $maintenance @('--set-temp-repository',$repo102,'--confirm-command','--accept-licenses','--default-answer','update')
 # Qt Windows CLI may report process exit 0 even after verified native abort.
 $brokenRc=$rc
 $failure=Get-Content (Join-Path $output 'failed-update-102.stdout.log') -Raw
 Must ($failure.Contains('PASS_UNIVERSAL_TRANSACTION_FIXTURE') -and $failure.Contains('Update aborted!') -and $failure.Contains('Unexpected exit code: 7')) 'R933_QT_NEGATIVE_NATIVE_EVENT_NOT_PROVEN'
 $list=@(Inventory)
 Copy-Item -LiteralPath (Join-Path $target 'components.xml') -Destination (Join-Path $output 'components-after-abort.xml')
 Must (-not ($list -contains 'org.dim.bridge.fixture:1.0.2-1')) 'R933_QT_FALSE_SUCCESS_FOR_BROKEN_UPGRADE'
 Assert-External-Isolation $ownerSha
 [void]$stages.Add('REAL_QT_VENDOR_FAILED_SHELL_UPDATE_CANNOT_MUTATE_OWNER_CONFIG_OR_PRODUCT_CODE')

 if($list.Count -eq 0){
   $rc=Invoke-QtNative 'repair-101' $maintenance @('--set-temp-repository',$repo101,'--confirm-command','--accept-licenses','--default-answer','install','org.dim.bridge.fixture')
   Must ($rc -eq 0) ('R933_QT_METADATA_REPAIR_RC_'+$rc)
 }
 $list=@(Inventory)
 Must ($list.Count -eq 1 -and $list[0] -eq 'org.dim.bridge.fixture:1.0.1-1') 'R933_QT_QT_METADATA_CANNOT_REPAIR'
 Assert-External-Isolation $ownerSha
 [void]$stages.Add('REAL_QT_VENDOR_METADATA_RECONCILIATION_FROM_PINNED_PACKAGE')

 $rc=Invoke-QtNative 'remove-final' $maintenance @('--set-temp-repository',$repo101,'--confirm-command','--accept-licenses','--default-answer','remove','org.dim.bridge.fixture')
 Must ($rc -eq 0) ('R933_QT_FINAL_REMOVE_RC_'+$rc)
 Must ((Inventory).Count -eq 0) 'R933_QT_FINAL_COMPONENT_NOT_REMOVED'
 Assert-External-Isolation $ownerSha
 [void]$stages.Add('REAL_QT_SHELL_UNINSTALLED_OWNER_DATA_STILL_INTACT')

 $record=[ordered]@{
   schema=1;status='PASS_R933_REAL_WINDOWS_QT_VENDOR_SHELL_ONLY'
   stages=@($stages)
   vendor='Qt Installer Framework';vendor_version='4.7.0'
   vendor_archive_sha256=$pins.vendor_archive_sha256
   vendor_compiled_setup_sha256=$pins.vendor_qt_setup_sha256
   frozen_existing_engine_sha256=$pins.frozen_engine_sha256
   source_commit=$pins.project_source_head
   owner_data_sha256=$ownerSha
   broken_update_exit_code=$brokenRc
   qt_windows_cli_zero_exit_despite_native_abort=($brokenRc -eq 0)
   internal_qt_native_abort_verified_by_log=$true
   qt_component_metadata_final_empty=$true
   os_native_windows_sandbox=$true
   qt_owns_product_code=$false
   product_service_modified=$false
   native_privileged_broker_authenticated=$false
   product_installation_accepted=$false
   publisher_authenticated=$false
   powercut_accepted=$false
 }
} catch {
 $record=[ordered]@{
   schema=1;status='FAIL_R933_REAL_WINDOWS_QT_VENDOR_SHELL'
   stages=@($stages);error=$_.Exception.Message
   product_installation_accepted=$false
   native_privileged_broker_authenticated=$false
 }
} finally {
 if(Test-Path -LiteralPath $output){
    $record|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $reportFile -Encoding utf8
 }
}
if($record.status -ne 'PASS_R933_REAL_WINDOWS_QT_VENDOR_SHELL_ONLY'){throw $record.error}
Write-Output ($record|ConvertTo-Json -Compress -Depth 10)
