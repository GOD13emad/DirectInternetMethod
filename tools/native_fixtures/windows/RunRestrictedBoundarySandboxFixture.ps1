# R896: Windows Sandbox only, synthetic DACL + genuinely restricted Windows token.
# No DIM installation, SCM, Tailscale, network, credentials or owner profile.
$ErrorActionPreference = 'Stop'
$InputRoot = 'C:\DIMR896\input'
$OutputRoot = 'C:\DIMR896\output'
$Exe = Join-Path $InputRoot 'RestrictedBoundaryProbe.exe'
$Pin = Join-Path $InputRoot 'probe.sha256'
$ReceiptPath = Join-Path $OutputRoot 'restricted_acl_receipt.json'
$Trace = Join-Path $OutputRoot 'trace.txt'
$Protected = Join-Path $env:ProgramData 'DIM_R896_ProtectedACL'
$UserRoot = Join-Path $env:LocalAppData 'DIM_R896_UserACL'
$Marker = 'R896_PROTECTED_IMMUTABLE'
$Report = $null
function Require([bool]$OK, [string]$Reason) {
    if(-not $OK) { throw $Reason }
}
function Mark([string]$Message) {
    if(Test-Path -LiteralPath $OutputRoot) {
        Add-Content -LiteralPath $Trace -Value ((Get-Date -Format o) + '|' + $Message)
    }
}
function Acl([string[]]$AclArguments) {
    & "$env:WINDIR\System32\icacls.exe" @AclArguments | Out-Null
    Require ($LASTEXITCODE -eq 0) ('ICACLS_FAILED_' + ($AclArguments -join '_'))
}
try {
    Mark 'GUEST_STARTED'
    $admin = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    Require ($admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'SANDBOX_ADMIN_REQUIRED'
    Require ([Environment]::Is64BitProcess) 'SANDBOX_64BIT_REQUIRED'
    Require (-not (Test-Path -LiteralPath $ReceiptPath)) 'RESULT_PREEXISTS'
    Require (-not (Test-Path -LiteralPath $Protected) -and
             -not (Test-Path -LiteralPath $UserRoot)) 'SYNTHETIC_ROOT_ALREADY_EXISTS'
    Require ((Test-Path $Pin) -and (Test-Path $Exe)) 'PIN_INPUT_MISSING'
    $expectedPin=(Get-Content -LiteralPath $Pin -Raw).Trim()
    Require ($expectedPin -match '^[0-9A-Fa-f]{64}$') 'PIN_FORMAT'
    Require ((Get-FileHash -LiteralPath $Exe).Hash -eq $expectedPin) 'PROBE_BINARY_SHA_MISMATCH'

    [IO.Directory]::CreateDirectory($Protected)|Out-Null
    [IO.Directory]::CreateDirectory($UserRoot)|Out-Null
    # Only synthetic roots: reject broad inherited access to protected
    # code, while allowing builtin Users on the separate user scope.
    Acl @($Protected,'/inheritance:r')
    Acl @($Protected,'/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')
    Acl @($UserRoot,'/inheritance:r')
    Acl @($UserRoot,'/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F',
          '*S-1-5-32-545:(OI)(CI)M')
    [IO.File]::WriteAllText((Join-Path $Protected 'fixture-owner-marker.txt'),
                            $Marker,[Text.UTF8Encoding]::new($false))
    $oldHash=(Get-FileHash (Join-Path $Protected 'fixture-owner-marker.txt')).Hash
    Mark 'SYNTHETIC_ACLS_CONFIGURED'

    $out=Join-Path $OutputRoot 'probe.stdout'
    $err=Join-Path $OutputRoot 'probe.stderr'
    $run=Start-Process -FilePath $Exe -ArgumentList @($Protected,$UserRoot,$Marker) -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    $raw=Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue
    $probe=$raw | ConvertFrom-Json
    Require ($run.ExitCode -eq 0 -and
             $probe.status -eq 'PASS_R896_RESTRICTED_TOKEN_ACL' -and
             $probe.restricted_token -eq $true -and
             $probe.protected_write_denied -eq $true -and
             $probe.user_write_allowed -eq $true -and
             $probe.protected_marker_preserved -eq $true -and
             $probe.native_product_installation_accepted -eq $false) 'RESTRICTED_TOKEN_PROBE_FAILED'
    Require ((Get-FileHash (Join-Path $Protected 'fixture-owner-marker.txt')).Hash -eq $oldHash) 'PROTECTED_MARKER_TAMPERED'
    Require (-not (Test-Path (Join-Path $Protected 'unprivileged-injection.txt'))) 'UNPRIVILEGED_PROTECTED_WRITE_SUCCEEDED'
    Require ((Get-Content (Join-Path $UserRoot 'restricted-user-marker.txt') -Raw).Trim() -eq 'R896_USER_ONLY_WRITE_OK') 'USER_WRITABLE_SCOPE_FAILED'
    Mark 'RESTRICTED_TOKEN_PROBE_PASS'
    $Report=[ordered]@{
        schema=1;status='PASS_R896_ISOLATED_RESTRICTED_TOKEN_ACL'
        native_product_installation_accepted=$false
        source_scope='synthetic Administrator-created fixture roots in offline Sandbox'
        protected_root=$Protected
        user_root=$UserRoot
        probe=$probe
        executable_sha256=$expectedPin
        protected_marker_sha256=$oldHash
        user_data_separate=$true
        actual_acl_authorization_test=$true
        publisher_authenticated=$false
        uac_elevation_boundary_accepted=$false
        production_privilege_boundary_accepted=$false
    }
} catch {
    Mark ('FAIL_' + $_.Exception.GetType().Name)
    $Report=[ordered]@{
        schema=1;status='FAIL_CLOSED_R896_RESTRICTED_TOKEN_ACL'
        native_product_installation_accepted=$false
        error=$_.Exception.Message
        probe_stdout=(Get-Content (Join-Path $OutputRoot 'probe.stdout') -Raw -ErrorAction SilentlyContinue)
        probe_stderr=(Get-Content (Join-Path $OutputRoot 'probe.stderr') -Raw -ErrorAction SilentlyContinue)
    }
} finally {
    if(Test-Path -LiteralPath $OutputRoot) {
        $Report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $ReceiptPath -Encoding UTF8
        Mark 'RECEIPT_SAVED'
    }
}
