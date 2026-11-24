# R935: Windows Sandbox SYSTEM-only native named pipe token preflight.
# Guest synthetic root only; NO production DIM code, service or root change.
$ErrorActionPreference='Stop'
$InputRoot='C:\DIMR935\input'
$OutputRoot='C:\DIMR935\output'
$GuestRoot='C:\ProgramData\DIM_R935_NativeBrokerPipeSandbox'
$Probe=Join-Path $InputRoot 'R935NativePipeBoundaryFixture.exe'
$Pins=Join-Path $InputRoot 'pins.json'
$Report=Join-Path $OutputRoot 'R935_NATIVE_PIPE_OS_PROOF.json'
$Stages=New-Object 'System.Collections.Generic.List[string]'
$result=$null
function Must([bool]$ok,[string]$why){if(-not $ok){throw $why}}
function Digest([string]$path){return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
try {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  Must ($id.User.Value -eq 'S-1-5-18') 'R935_WIN_GUEST_SYSTEM_REQUIRED'
  Must (Test-Path 'C:\Users\WDAGUtilityAccount') 'R935_OFFLINE_WINDOWS_SANDBOX_ONLY'
  Must ((Test-Path $InputRoot) -and (Test-Path $OutputRoot)) 'R935_SANDBOX_MOUNTS_REQUIRED'
  Must (-not (Test-Path $GuestRoot) -and -not (Test-Path $Report)) 'R935_ROOT_OR_REPORT_ALREADY_EXISTS'
  Must (-not (Get-Service DirectInternetMethodSvc -ErrorAction SilentlyContinue)) 'R935_REAL_DIM_SERVICE_IN_GUEST_ABORT'
  $pin=Get-Content $Pins -Raw|ConvertFrom-Json
  Must ($pin.schema -eq 1 -and $pin.scope -eq 'R935_SYNTHETIC_NATIVE_BROKER_PIPE_ONLY' -and $pin.probe_sha256 -match '^[a-f0-9]{64}$') 'R935_FROZEN_SOURCE_PIN_SCHEMA'
  Must ((Digest $Probe) -eq $pin.probe_sha256) 'R935_FROZEN_PROBE_PIN_MISMATCH'
  Must ((Digest (Join-Path $InputRoot 'broker-request.json')) -eq $pin.request_sha256) 'R935_SHARED_REQUEST_SHA_PIN_MISMATCH'
  Must ((Digest (Join-Path $InputRoot 'broker-policy.json')) -eq $pin.policy_sha256) 'R935_SHARED_POLICY_SHA_PIN_MISMATCH'
  [void]$Stages.Add('SYSTEM_WINDOWS_SANDBOX_VERIFIED_PINNED_DOTNET_NATIVE_API')

  [IO.Directory]::CreateDirectory($GuestRoot)|Out-Null
  & "$env:WINDIR\System32\icacls.exe" $GuestRoot '/inheritance:r' |Out-Null
  Must ($LASTEXITCODE -eq 0) 'R935_DISABLE_INHERITANCE_FAILED'
  & "$env:WINDIR\System32\icacls.exe" $GuestRoot '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)R'|Out-Null
  Must ($LASTEXITCODE -eq 0) 'R935_OS_PROTECTED_DIRECTORY_CREATE_FAILED'
  $acl=Get-Acl -LiteralPath $GuestRoot
  Must ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-18') 'R935_DIRECTORY_NOT_SYSTEM_OWNED'
  $trusted=@('S-1-5-18','S-1-5-32-544')
  $mask=[Security.AccessControl.FileSystemRights]::Write
  $mask=$mask -bor [Security.AccessControl.FileSystemRights]::Delete
  $mask=$mask -bor [Security.AccessControl.FileSystemRights]::ChangePermissions
  $mask=$mask -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
    Must ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or ($rule.FileSystemRights -band $mask) -eq 0 -or $rule.IdentityReference.Value -in $trusted) ('R935_UNTRUSTED_DIRECTORY_WRITE_ACE_'+$rule.IdentityReference.Value)
  }
  [void]$Stages.Add('REAL_SYSTEM_NTFS_PROTECTED_FIXTURE_ROOT_ONLY')

  $stdout=Join-Path $OutputRoot 'R935_NATIVE_PIPE.stdout.log'
  $stderr=Join-Path $OutputRoot 'R935_NATIVE_PIPE.stderr.log'
  $ran=Start-Process -FilePath $Probe -ArgumentList @('--offline-guest-preflight') -PassThru -Wait -RedirectStandardOutput $stdout -RedirectStandardError $stderr
  Must ($ran.ExitCode -eq 0) ('R935_NATIVE_PIPE_EXE_FAILED_'+$ran.ExitCode+'_'+(Get-Content $stderr -Raw))
  $j=Get-Content $stdout -Raw|ConvertFrom-Json
  Must ($j.status -eq 'PASS_R935_ISOLATED_NATIVE_WIN_PIPE_CLIENT_TOKEN_PREFLIGHT' -and $j.native_restricted_client_token_observed -eq $true -and $j.protected_system_store_unchanged -eq $true -and $j.OS_authenticated_production_broker -eq $false) 'R935_NATIVE_PIPE_RESULT_NOT_SCOPED'
  Must ($j.successful_token_and_pinned_request.actual_pinned_request_match -eq $true -and $j.rejected_tampered_request.actual_pinned_request_match -eq $false) 'R935_NATIVE_BROKER_PIN_CHECK_NOT_PROVEN'
  Must ($j.reused_shared_r899_broker_request_schema -eq $true -and $j.shared_policy_pins_request_sha256 -eq $true -and $j.request_bytes_transported_length_prefixed -eq $true -and $j.native_pinned_request_sha256 -eq $pin.request_sha256) 'R935_SHARED_R899_POLICY_PIPE_INTEGRATION_UNPROVEN'
  foreach($round in @($j.successful_token_and_pinned_request,$j.rejected_tampered_request)){
    Must ($round.protected_writer_denied_to_restricted_client -eq $true -and $round.server_real_client_token_restricted -eq $true -and $round.pipe_client_process_id_matches -eq $true -and $round.server_reverted_to_system -eq $true -and $round.native_product_installation_accepted -eq $false) 'R935_OS_PIPE_SECURITY_TOKEN_CHECK_FAILED'
  }
  Must (-not (Test-Path (Join-Path $GuestRoot 'untrusted-write.json'))) 'R935_UNTRUSTED_USER_FORGED_FILE'
  [void]$Stages.Add('REAL_NTFS_RESTRICTED_TOKEN_WRITE_DENIED')
  [void]$Stages.Add('REAL_SYSTEM_NAMED_PIPE_SESSION_WITH_RESTRICTED_CLIENT_TOKEN')
  [void]$Stages.Add('EXACT_EXISTING_R899_POLICY_REQUEST_ACCEPTED_TAMPERED_REQUEST_REJECTED')
  $result=[ordered]@{
    schema=1
    status='PASS_R935_GENUINE_WINDOWS_SANDBOX_PIPE_IDENTITY_ONLY'
    stages=@($Stages)
    probe_sha256=$pin.probe_sha256
    verified_guest_client_os_identity=$true
    restricted_os_client_denied_protected_writer=$true
    native_pipe_acl=$true
    trusted_production_broker_implemented=$false
    native_product_installation_accepted=$false
    publisher_authenticated=$false
    native_completed_receipt_issued=$false
    protected_replay_writer_implemented=$false
    native_scm_operations_tested=$false
  }
} catch {
  $result=[ordered]@{
    schema=1
    status='FAIL_CLOSED_R935_GUEST_NATIVE_PIPE_IDENTITY'
    stages=@($Stages)
    error=$_.Exception.Message
    trusted_production_broker_implemented=$false
    native_product_installation_accepted=$false
  }
} finally {
  if(Test-Path $OutputRoot){
    $result|ConvertTo-Json -Depth 9|Set-Content -LiteralPath $Report -Encoding utf8
  }
}
if($result.status -ne 'PASS_R935_GENUINE_WINDOWS_SANDBOX_PIPE_IDENTITY_ONLY'){throw $result.error}
Write-Output ($result|ConvertTo-Json -Compress -Depth 9)
