# R934. Windows Sandbox SYSTEM-only real NTFS DACL / existing broker held-file read.
# Synthetic fixture only; never grants service/publisher/native installation authority.
$ErrorActionPreference='Stop'
$InputRoot='C:\DIMR934\input'
$OutputRoot='C:\DIMR934\output'
$Protected='C:\ProgramData\DIM_R934_IsolatedBrokerReadOnly'
$Policy=Join-Path $Protected 'policy.json'
$Ledger=Join-Path $Protected 'replay.json'
$Probe=Join-Path $InputRoot 'R934NativeBrokerSnapshotProbe.exe'
$PinsFile=Join-Path $InputRoot 'pins.json'
$Report=Join-Path $OutputRoot 'R934_NATIVE_WINDOWS_BROKER_SNAPSHOT.json'
$Stages=New-Object 'System.Collections.Generic.List[string]'
$Result=$null
function Must([bool]$ok,[string]$why){if(-not $ok){throw $why}}
function Hash([string]$p){return (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
function RunProbe([string]$tag){
  $out=Join-Path $OutputRoot ($tag+'.stdout.log')
  $err=Join-Path $OutputRoot ($tag+'.stderr.log')
  $process=Start-Process -FilePath $Probe -PassThru -Wait -RedirectStandardOutput $out -RedirectStandardError $err -WindowStyle Hidden
  return [int]$process.ExitCode
}
function ProtectedAclChecked {
  $acl=Get-Acl -LiteralPath $Protected
  $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  Must ($owner -eq 'S-1-5-18') 'R934_POLICY_ROOT_NOT_SYSTEM_OWNED'
  $writers=@('S-1-5-18','S-1-5-32-544')
  $mask=[Security.AccessControl.FileSystemRights]::Write
  $mask=$mask -bor [Security.AccessControl.FileSystemRights]::Delete
  $mask=$mask -bor [Security.AccessControl.FileSystemRights]::ChangePermissions
  $mask=$mask -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
    if($ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and ($ace.FileSystemRights -band $mask) -ne 0 -and $ace.IdentityReference.Value -notin $writers){
      throw ('R934_UNTRUSTED_ALLOW_WRITE_ACE_'+$ace.IdentityReference.Value)
    }
  }
  return $true
}
try {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  Must ($identity.User.Value -eq 'S-1-5-18') 'R934_NATIVE_WINDOWS_SYSTEM_REQUIRED'
  Must (Test-Path 'C:\Users\WDAGUtilityAccount') 'R934_SANDBOX_IDENTITY_REQUIRED'
  Must ((Test-Path $InputRoot) -and (Test-Path $OutputRoot)) 'R934_SANDBOX_MOUNT_REQUIRED'
  Must (-not (Test-Path $Protected) -and -not (Test-Path $Report)) 'R934_PROTECTED_ROOT_PREEXISTS'
  Must (-not (Get-Service 'DirectInternetMethodSvc' -ErrorAction SilentlyContinue)) 'R934_PRODUCTION_SERVICE_IN_GUEST_REFUSED'
  $pins=Get-Content $PinsFile -Raw|ConvertFrom-Json
  Must ($pins.schema -eq 1 -and $pins.scope -eq 'R934_WIN_NATIVE_HELD_READONLY') 'R934_PIN_SCHEMA_INVALID'
  Must ($pins.policy_bytes -eq 446 -and $pins.ledger_bytes -eq 382) 'R934_TEST_SIZE_UNEXPECTED'
  Must ((Hash $Probe) -eq $pins.probe_sha256) 'R934_PROBE_BINARY_PIN_MISMATCH'
  Must ((Hash (Join-Path $InputRoot 'policy.json')) -eq $pins.policy_sha256) 'R934_POLICY_INPUT_PIN_MISMATCH'
  Must ((Hash (Join-Path $InputRoot 'replay.json')) -eq $pins.ledger_sha256) 'R934_LEDGER_INPUT_PIN_MISMATCH'
  [void]$Stages.Add('SYSTEM_SANDBOX_AND_FROZEN_ORIGINAL_SHARED_ENGINE_PINS')

  [IO.Directory]::CreateDirectory($Protected)|Out-Null
  & "$env:WINDIR\System32\icacls.exe" $Protected '/inheritance:r' |Out-Null
  Must ($LASTEXITCODE -eq 0) 'R934_NTFS_INHERITANCE_REMOVE_FAILED'
  & "$env:WINDIR\System32\icacls.exe" $Protected '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)R' |Out-Null
  Must ($LASTEXITCODE -eq 0) 'R934_NTFS_OS_ACL_GRANT_FAILED'
  Must (ProtectedAclChecked) 'R934_OS_ROOT_DACL_UNTRUSTED'
  Copy-Item -LiteralPath (Join-Path $InputRoot 'policy.json') -Destination $Policy
  Copy-Item -LiteralPath (Join-Path $InputRoot 'replay.json') -Destination $Ledger
  Must ((Hash $Policy) -eq $pins.policy_sha256 -and (Hash $Ledger) -eq $pins.ledger_sha256) 'R934_PROTECTED_BYTES_CHANGED'
  [void]$Stages.Add('SYSTEM_OWNED_PROTECTED_DIR_REAL_NTFS_DACL')

  $env:DIM_R934_TEST_ONLY='true'
  $rc=RunProbe 'positive-1'
  Must ($rc -eq 0) ('R934_NATIVE_WIN32_HANDLE_OBSERVE_FAILED_'+$rc)
  $pass=Get-Content (Join-Path $OutputRoot 'positive-1.stdout.log') -Raw|ConvertFrom-Json
  Must ($pass.status -eq 'PASS_R934_NATIVE_WINDOWS_HELD_OS_SNAPSHOT_READONLY_ONLY' -and $pass.native_installation_accepted -eq $false -and $pass.native_receipt_issued -eq $false -and $pass.os_protected_parent_verified_by_python_module -eq $false) 'R934_OBSERVER_NATIVE_AUTHORITY_OVERCLAIM'
  [void]$Stages.Add('REAL_WIN32_HELD_POLICY_AND_LEDGER_BYTES_PASS')

  [IO.File]::AppendAllText($Policy,' ')
  $rc=RunProbe 'tampered-policy-size'
  $errorMessage=Get-Content (Join-Path $OutputRoot 'tampered-policy-size.stderr.log') -Raw
  Must ($rc -eq 3 -and $errorMessage.Contains('WIN32_HANDLE_SIZE_MISMATCH')) 'R934_POLICY_SIZE_TAMPER_NOT_FAIL_CLOSED'
  Copy-Item -LiteralPath (Join-Path $InputRoot 'policy.json') -Destination $Policy -Force
  Must ((Hash $Policy) -eq $pins.policy_sha256) 'R934_POLICY_SOURCE_RESTORE_FAILED'
  [void]$Stages.Add('OS_PROTECTED_POLICY_TAMPER_SIZE_DENIED')

  $bytes=[IO.File]::ReadAllBytes($Ledger)
  $bytes[0]=[byte]($bytes[0] -bxor 1)
  [IO.File]::WriteAllBytes($Ledger,$bytes)
  Must ((Get-Item $Ledger).Length -eq $pins.ledger_bytes) 'R934_TAMPER_SIZE_NOT_CONSTANT'
  $rc=RunProbe 'tampered-ledger-digest'
  $errorMessage=Get-Content (Join-Path $OutputRoot 'tampered-ledger-digest.stderr.log') -Raw
  Must ($rc -eq 3 -and $errorMessage.Contains('WIN32_HANDLE_PIN_MISMATCH')) 'R934_LEDGER_SAME_SIZE_TAMPER_NOT_FAIL_CLOSED'
  Copy-Item -LiteralPath (Join-Path $InputRoot 'replay.json') -Destination $Ledger -Force
  Must ((Hash $Ledger) -eq $pins.ledger_sha256) 'R934_LEDGER_RESTORE_FAILED'
  [void]$Stages.Add('OS_PROTECTED_LEDGER_TAMPER_SAME_SIZE_SHA_DENIED')

  $rc=RunProbe 'positive-recovery'
  Must ($rc -eq 0) 'R934_EXACT_RESTORED_OS_SNAPSHOT_REFUSED'
  Must ((Hash $Policy) -eq $pins.policy_sha256 -and (Hash $Ledger) -eq $pins.ledger_sha256) 'R934_PROTECTED_BYTES_POST_INVALID'
  Must (ProtectedAclChecked) 'R934_OS_DACL_POST_INVALID'
  [void]$Stages.Add('OS_PROTECTED_NATIVE_BROKER_READONLY_RECOVERY_PASS')
  $Result=[ordered]@{
    schema=1
    status='PASS_R934_WINDOWS_SYSTEM_PROTECTED_BROKER_SNAPSHOT_READONLY_ONLY'
    stages=@($Stages)
    policy_sha256=$pins.policy_sha256
    ledger_sha256=$pins.ledger_sha256
    probe_sha256=$pins.probe_sha256
    protected_root_owner_system=$true
    directory_no_nontrusted_write_ace=$true
    policy_size_tamper_denied=$true
    same_size_ledger_hash_tamper_denied=$true
    native_installation_accepted=$false
    privileged_broker_implemented=$false
    publisher_authenticated=$false
    native_receipt_issued=$false
    actual_scm_service_tested=$false
    reboot_accepted=$false
  }
} catch {
  $Result=[ordered]@{
    schema=1
    status='FAIL_CLOSED_R934_WINDOWS_PROTECTED_READONLY'
    stages=@($Stages)
    error=$_.Exception.Message
    native_installation_accepted=$false
    privileged_broker_implemented=$false
  }
} finally {
  if(Test-Path $OutputRoot){
    $Result|ConvertTo-Json -Depth 9|Set-Content -LiteralPath $Report -Encoding utf8
  }
}
if($Result.status -ne 'PASS_R934_WINDOWS_SYSTEM_PROTECTED_BROKER_SNAPSHOT_READONLY_ONLY'){throw $Result.error}
Write-Output ($Result|ConvertTo-Json -Compress -Depth 9)
