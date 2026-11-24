# R931: Isolated Windows Sandbox ONLY, real OS ACL against a restricted token.
# No native broker created. Does NOT authorize production installer operations.
$ErrorActionPreference='Stop'
$InputRoot='C:\DIMR931\input'
$OutputRoot='C:\DIMR931\output'
$Probe=Join-Path $InputRoot 'RestrictedNativeReceiptProbe.exe'
$ReceiptInput=Join-Path $InputRoot 'restored.receipt.json'
$Pins=Join-Path $InputRoot 'receipt-pins.json'
$Report=Join-Path $OutputRoot 'r931-receipt-custody.json'
$Protected=Join-Path $env:ProgramData 'DIM_R931_SyntheticReceiptCustody'
$UserRoot='C:\DIMR931\user'
$Receipt=Join-Path $Protected 'restored.receipt.json'
$Stages=New-Object 'System.Collections.Generic.List[string]'
function Must([bool]$ok,[string]$reason) { if(-not $ok){throw $reason} }
function Digest([string]$path){ return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
function SecureAcl([string[]]$aclArguments) {
  & "$env:WINDIR\System32\icacls.exe" @aclArguments |Out-Null
  Must ($LASTEXITCODE -eq 0) ('R931_ACL_FAILED_'+($aclArguments -join ';'))
}
$record=$null
try {
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
  Must ($identity.User.Value -eq 'S-1-5-18') 'R931_SYSTEM_GUEST_REQUIRED'
  Must ([Environment]::Is64BitProcess) 'R931_64BIT_REQUIRED'
  Must (Test-Path -LiteralPath 'C:\Users\WDAGUtilityAccount') 'R931_SANDBOX_ACCOUNT_REQUIRED'
  Must ((Test-Path -LiteralPath $InputRoot) -and (Test-Path -LiteralPath $OutputRoot)) 'R931_GUEST_MOUNT_MISSING'
  Must (-not (Test-Path -LiteralPath $Report)) 'R931_REPORT_ALREADY_EXISTS'
  Must (-not (Test-Path -LiteralPath $Protected) -and
        -not (Test-Path -LiteralPath $UserRoot)) 'R931_PROTECTED_ROOT_PREEXISTS'
  $pin=Get-Content -LiteralPath $Pins -Raw|ConvertFrom-Json
  Must ($pin.schema -eq 1 -and $pin.scope -eq 'R931_OS_SYNTHETIC_RECEIPT_ONLY' -and
        $pin.receipt_sha256 -match '^[0-9a-fA-F]{64}$' -and
        $pin.probe_sha256 -match '^[0-9a-fA-F]{64}$' -and
        $pin.intent_sha256 -match '^[0-9a-fA-F]{64}$') 'R931_PIN_SCHEMA_INVALID'
  Must ((Test-Path -LiteralPath $Probe) -and
        (Digest $Probe) -eq $pin.probe_sha256.ToLowerInvariant()) 'R931_PROBE_SHA_MISMATCH'
  Must ((Test-Path -LiteralPath $ReceiptInput) -and
        (Digest $ReceiptInput) -eq $pin.receipt_sha256.ToLowerInvariant()) 'R931_RECEIPT_SHA_MISMATCH'
  $receiptObject=Get-Content -LiteralPath $ReceiptInput -Raw|ConvertFrom-Json
  Must ($receiptObject.schema -eq 1 -and $receiptObject.status -eq 'restored' -and
        $receiptObject.intent_sha256 -eq $pin.intent_sha256) 'R931_RECEIPT_INTENT_INVALID'
  [void]$Stages.Add('SHA_PINNED_EXACT_SHARED_NATIVE_RECEIPT')
  [IO.Directory]::CreateDirectory($Protected)|Out-Null
  [IO.Directory]::CreateDirectory($UserRoot)|Out-Null
  SecureAcl @($Protected,'/inheritance:r')
  SecureAcl @($Protected,'/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')
  SecureAcl @($UserRoot,'/inheritance:r')
  SecureAcl @($UserRoot,'/grant:r','*S-1-5-18:(OI)(CI)F',
               '*S-1-5-32-544:(OI)(CI)F','*S-1-5-32-545:(OI)(CI)M')
  Copy-Item -LiteralPath $ReceiptInput -Destination $Receipt -ErrorAction Stop
  Must ((Digest $Receipt) -eq $pin.receipt_sha256.ToLowerInvariant()) 'R931_NATIVE_RECEIPT_COPY_CHANGED'
  [void]$Stages.Add('SYSTEM_OWNED_PROTECTED_RECEIPT_ROOT_IN_REAL_NTFS_DACL')
  $stdout=Join-Path $OutputRoot 'r931-probe.stdout'
  $stderr=Join-Path $OutputRoot 'r931-probe.stderr'
  $run=Start-Process -FilePath $Probe -ArgumentList @($Protected,$UserRoot,$pin.receipt_sha256) -Wait -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
  Must ($run.ExitCode -eq 0) ('R931_RESTRICTED_PROBE_EXIT_'+$run.ExitCode)
  $native=(Get-Content -LiteralPath $stdout -Raw|ConvertFrom-Json)
  foreach($field in @('restricted_token','overwrite_denied','append_denied','delete_denied',
                      'rename_denied','injection_denied','user_scope_write_allowed',
                      'protected_receipt_intact')) {
    Must ($native.$field -eq $true) ('R931_RESTRICTED_ATTACK_WAS_NOT_BLOCKED_'+$field)
  }
  Must ($native.status -eq 'PASS_R931_RESTRICTED_RECEIPT_CUSTODY' -and
        $native.trusted_broker_implemented -eq $false) 'R931_NATIVE_PROBE_UNEXPECTED_STATUS'
  Must ((Digest $Receipt) -eq $pin.receipt_sha256.ToLowerInvariant()) 'R931_PROTECTED_RECEIPT_CHANGED_AFTER_ATTACK'
  Must ((Get-Content -LiteralPath (Join-Path $UserRoot 'untrusted-receipt.json') -Raw) -eq
        'UNPRIVILEGED_FORGED_RECEIPT_ONLY') 'R931_USER_SCOPE_WAS_NOT_WRITABLE'
  [void]$Stages.Add('RESTRICTED_WINDOWS_TOKEN_DENIED_OVERWRITE_APPEND_DELETE_RENAME_INJECT')
  [void]$Stages.Add('SEPARATE_USER_SCOPE_CAN_WRITE_BUT_PROTECTED_RECEIPT_SHA_UNCHANGED')
  $record=[ordered]@{
     schema=1
     status='PASS_R931_OS_RESTRICTED_NATIVE_RECEIPT_CUSTODY_ONLY'
     stages=@($Stages)
     receipt_sha256=$pin.receipt_sha256
     intent_sha256=$pin.intent_sha256
     probe_sha256=$pin.probe_sha256
     restricted_token_observed=$true
     native_probe=$native
     os_acl_protection_observed=$true
     native_privileged_broker_implemented=$false
     publisher_authenticated=$false
     trusted_native_receipt_mint_accepted=$false
     native_product_installation_accepted=$false
     host_reboot_accepted=$false
  }
} catch {
  $record=[ordered]@{
    schema=1
    status='FAIL_CLOSED_R931_RECEIPT_CUSTODY'
    stages=@($Stages)
    error=$_.Exception.Message
    native_privileged_broker_implemented=$false
    trusted_native_receipt_mint_accepted=$false
    native_product_installation_accepted=$false
  }
} finally {
  if(Test-Path -LiteralPath $OutputRoot) {
    $record|ConvertTo-Json -Depth 9 |Set-Content -LiteralPath $Report -Encoding UTF8
  }
}
if($record.status -ne 'PASS_R931_OS_RESTRICTED_NATIVE_RECEIPT_CUSTODY_ONLY'){ throw $record.error }
Write-Output ($record |ConvertTo-Json -Compress -Depth 9)
