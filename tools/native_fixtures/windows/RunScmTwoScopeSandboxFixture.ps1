# R891 Windows Sandbox isolated SCM + two code roots + frozen coordinator.
# Synthetic test only; never the installed DIM Service or Inno identity.
$ErrorActionPreference = 'Stop'
$ServiceName = 'DIMR887IsolatedFixtureSvc'
$InputRoot = 'C:\DIMR891\input'
$OutputRoot = 'C:\DIMR891\output'
$Packages = Join-Path $InputRoot 'packages'
$Exe = Join-Path $InputRoot 'dual-scope-fixture.exe'
$CodeRoot = Join-Path $env:PROGRAMDATA 'DIM_R891_Isolated_Code'
$UserRoot = Join-Path $env:LOCALAPPDATA 'DIM_R891_Isolated_UserCode'
$JournalRoot = Join-Path $env:PROGRAMDATA 'DIM_R891_Isolated_Journal'
$Binary = Join-Path $CodeRoot 'current\app\FixtureService.exe'
$Marker = 'C:\ProgramData\DIM_R887_SCMSandboxFixture\active-version.txt'
$OwnerData = Join-Path $UserRoot 'data\owner.settings'
$ReceiptPath = Join-Path $OutputRoot 'two_scope_scm_receipt.json'
$Trace = Join-Path $OutputRoot 'trace.txt'
$Stages = New-Object 'System.Collections.Generic.List[string]'

function Require([bool]$ok,[string]$why) {
    if (-not $ok) { throw $why }
}
function Mark([string]$message) {
    # Explicitly scoped guest-only progress for interrupted/slow native tests.
    if (Test-Path -LiteralPath $OutputRoot) {
        [IO.File]::AppendAllText($Trace, ((Get-Date).ToString('o') + '|' + $message + "`n"))
    }
}
function Invoke-Sc([string[]]$scArgs,[bool]$allowFailure=$false) {
    Mark ('SC_BEGIN_' + $scArgs[0])
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = (& "$env:WINDIR\System32\sc.exe" @scArgs 2>&1 | Out-String); $code = $LASTEXITCODE }
    finally { $ErrorActionPreference = $previous }
    Mark ('SC_END_' + $scArgs[0] + '_' + $code)
    if ($code -ne 0 -and -not $allowFailure) {
        throw ('SC_' + $scArgs[0] + '_FAILED_' + $code + '_' + $out.Trim())
    }
    return @{code=$code;out=$out.Trim()}
}
function Invoke-Dual([string[]]$cliArgs,[bool]$allowFailure=$false) {
    Mark ('DUAL_BEGIN_' + $cliArgs[0])
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = (& $Exe @cliArgs 2>&1 | Out-String); $code = $LASTEXITCODE }
    finally { $ErrorActionPreference = $previous }
    Mark ('DUAL_END_' + $cliArgs[0] + '_' + $code)
    if ($code -ne 0) {
        if ($allowFailure) { return @{code=$code;out=$out.Trim()} }
        throw ('DUAL_' + $cliArgs[0] + '_FAILED_' + $code + '_' + $out.Trim())
    }
    $json = $out | ConvertFrom-Json
    Require ($null -ne $json.status -and $json.native_product_install_accepted -eq $false) 'UNSAFE_CLI_REPORT'
    return $json
}
function WaitState([string]$state) {
    for ($i=0; $i -lt 50; $i++) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($null -ne $svc -and "$($svc.Status)" -eq $state) { return }
        Start-Sleep -Milliseconds 300
    }
    throw ('STATE_TIMEOUT_' + $state)
}
function WaitRemoved() {
    for ($i=0; $i -lt 50; $i++) {
        $svc = Get-CimInstance Win32_Service -Filter "Name = '$ServiceName'" -ErrorAction SilentlyContinue
        if ($null -eq $svc) { return }
        Start-Sleep -Milliseconds 300
    }
    throw 'SCM_DID_NOT_UNREGISTER'
}
function CheckRuntime([string]$release,[string]$hash) {
    WaitState 'Running'
    Require ((Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash -eq $hash) 'SERVICE_CODE_SHA_MISMATCH'
    for ($i=0; $i -lt 40; $i++) {
        if ((Test-Path $Marker) -and
            ((Get-Content -LiteralPath $Marker -Raw).Trim() -eq $release)) { return }
        Start-Sleep -Milliseconds 300
    }
    throw ('RUNTIME_RELEASE_MISMATCH_' + $release)
}
function CheckScopes([string]$release) {
    $v = Invoke-Dual @('verify')
    Require ($v.result.phase -eq $null) 'DUAL_JOURNAL_LEFT_ACTIVE'
    Require ($v.result.scopes.code.version -eq $release -and
             $v.result.scopes.user.version -eq $release) 'DUAL_SCOPE_VERSION_DRIFT'
}
function Prepare([string]$release,[bool]$broken=$false) {
    $options = @('prepare', '--source', $Packages, '--version', $release)
    if($broken){$options += '--bad-fixture'}
    Invoke-Dual $options | Out-Null
    Invoke-Dual @('activate') | Out-Null
}

try {
    Mark 'SCRIPT_STARTED'
    $admin = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    Require ($admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'SANDBOX_ADMIN_REQUIRED'
    Require ((Test-Path -LiteralPath $Packages) -and (Test-Path -LiteralPath $Exe)) 'PINNED_INPUT_MISSING'
    Require (-not (Test-Path -LiteralPath $ReceiptPath)) 'RECEIPT_ALREADY_EXISTS'
    foreach($p in @($CodeRoot,$UserRoot,$JournalRoot)){
        Require (-not (Test-Path -LiteralPath $p)) 'ROOT_ALREADY_EXISTS'
    }
    Require (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) 'FIXTURE_SERVICE_ALREADY_EXISTS'

    $enginePin = (Get-Content (Join-Path $InputRoot 'dual.sha256') -Raw).Trim()
    Require ((Get-FileHash -LiteralPath $Exe).Hash -eq $enginePin) 'FROZEN_PIN_MISMATCH'
    $pins=Get-Content (Join-Path $Packages 'pins.json') -Raw| ConvertFrom-Json
    Require ($pins.schema -eq 1 -and $pins.scope -eq 'SYNTHETIC_R891') 'PINS_SCHEMA'
    foreach ($k in $pins.manifest_sha256.PSObject.Properties.Name) {
        $man = Join-Path (Join-Path $Packages $k) 'manifest.json'
        Require ((Get-FileHash -LiteralPath $man).Hash -eq $pins.manifest_sha256.$k) ('PACKAGE_SHA_' + $k)
    }
    [void]$Stages.Add('FROZEN_CLI_AND_6_SOURCE_PACKAGES_SHA_PINNED')
    Mark 'PIN_CHECKS_COMPLETE'

    Prepare '1.5.6'
    Invoke-Sc @('create',$ServiceName,'binPath=',$Binary,'start=','demand',
                'obj=','LocalSystem','DisplayName=','DIM R891 Isolated TwoScope Fixture')|Out-Null
    Invoke-Sc @('start',$ServiceName)|Out-Null
    CheckRuntime '1.5.6' $pins.binary_sha256_old
    Invoke-Dual @('finalize','--version','1.5.6') | Out-Null
    CheckScopes '1.5.6'
    [void]$Stages.Add('SCM_NATIVE_156_AND_BOTH_SCOPE_COMMIT')

    [IO.Directory]::CreateDirectory((Split-Path $OwnerData -Parent))|Out-Null
    [IO.File]::WriteAllBytes($OwnerData,[Text.Encoding]::UTF8.GetBytes('R891_OWNER_CONFIGURATION_KEEP'))
    $ownerHash = (Get-FileHash $OwnerData).Hash

    Invoke-Sc @('stop',$ServiceName)|Out-Null
    WaitState 'Stopped'
    Prepare '1.5.7' $true
    $failed=Invoke-Sc @('start',$ServiceName) $true
    Require ($failed.code -ne 0) 'INVALID_BINARY_SC_START_SUCCEEDED'
    WaitState 'Stopped'
    Invoke-Dual @('abort')|Out-Null
    Invoke-Sc @('start',$ServiceName)|Out-Null
    CheckRuntime '1.5.6' $pins.binary_sha256_old
    CheckScopes '1.5.6'
    Require ((Get-FileHash $OwnerData).Hash -eq $ownerHash) 'OWNER_CHANGED_AFTER_ABORT'
    [void]$Stages.Add('BAD_NATIVE_START_ABORT_BOTH_ROOTS_RESTORE_156')

    Invoke-Sc @('stop',$ServiceName)|Out-Null
    WaitState 'Stopped'
    Prepare '1.5.7'
    Invoke-Sc @('start',$ServiceName)|Out-Null
    CheckRuntime '1.5.7' $pins.binary_sha256_new
    $injected=Invoke-Dual @('finalize','--version','1.5.7','--fault-after','code') $true
    Require ($injected.code -ne 0 -and $injected.out.Contains('FIXTURE_INJECTED_AFTER_FINALIZE')) 'EXPECTED_COMMIT_INJECTION_MISSING'
    $abort=Invoke-Dual @('abort') $true
    Require ($abort.code -ne 0 -and $abort.out.Contains('COORDINATOR_FORWARD_RECOVERY_REQUIRED')) 'ILLEGAL_ROLLBACK_AFTER_COMMIT_ACCEPTED'
    Invoke-Dual @('finalize','--version','1.5.7')|Out-Null
    CheckScopes '1.5.7'
    CheckRuntime '1.5.7' $pins.binary_sha256_new
    Require ((Get-FileHash $OwnerData).Hash -eq $ownerHash) 'OWNER_CHANGED_AFTER_FORWARD_RECOVERY'
    [void]$Stages.Add('FIRST_SCOPE_FINALIZE_INTERRUPTED_REPLAY_BOTH_ROOTS_157')

    Invoke-Sc @('stop',$ServiceName)|Out-Null
    WaitState 'Stopped'
    Invoke-Dual @('uninstall-prepare')|Out-Null
    Invoke-Sc @('delete',$ServiceName)|Out-Null
    WaitRemoved
    Invoke-Dual @('uninstall-commit')|Out-Null
    $after=Invoke-Dual @('verify')
    Require ($after.result.scopes.code.status -eq 'EMPTY' -and
             $after.result.scopes.user.status -eq 'EMPTY') 'ENGINE_CODE_NOT_UNINSTALLED'
    Require ((Get-FileHash $OwnerData).Hash -eq $ownerHash) 'OWNER_CONFIGURATION_DELETED'
    [void]$Stages.Add('NATIVE_SCM_DELETE_TWO_SCOPE_UNINSTALL_OWNER_DATA_PRESERVED')

    $Report=[ordered]@{
        schema=1
        status='PASS_R891_SYNTHETIC_NATIVE_SCM_TWO_SCOPE'
        native_product_installation_accepted=$false
        service=$ServiceName
        platform='windows-x86_64'
        code_root=$CodeRoot
        user_root=$UserRoot
        stages=$Stages.ToArray()
        frozen_sha256=$enginePin
        owner_data_sha256=$ownerHash
        original_service_sha256=$pins.binary_sha256_old
        upgraded_service_sha256=$pins.binary_sha256_new
    }
} catch {
    Mark ('FAIL_' + $_.Exception.GetType().Name)
    $Report=[ordered]@{
        schema=1
        status='FAIL_CLOSED_R891_SYNTHETIC_NATIVE_SCM_TWO_SCOPE'
        native_product_installation_accepted=$false
        error=$_.Exception.Message
        stages=$Stages.ToArray()
    }
} finally {
    Mark 'FINALLY_STARTED'
    # Persist the guest result BEFORE any best-effort cleanup call. A failed or
    # delayed SCM cleanup must never silently suppress the V&V receipt.
    if (Test-Path -LiteralPath $OutputRoot) {
        $Report | ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath $ReceiptPath -Encoding UTF8
        Mark 'RECEIPT_SAVED'
    }
    # Do not re-open an already-deleted SCM service after a proven completed
    # unregistration: Windows can hold service handles marked for deletion.
    if ($Report.status -eq 'PASS_R891_SYNTHETIC_NATIVE_SCM_TWO_SCOPE') {
        Mark 'POST_UNREGISTER_CLEANUP_NOT_REQUIRED'
    } else {
        Mark 'BEST_EFFORT_FAILED_GUEST_CLEANUP'
        # Only the unique synthetic fixture service may be targeted.
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            try { & "$env:WINDIR\System32\sc.exe" stop $ServiceName | Out-Null } catch {}
            try { & "$env:WINDIR\System32\sc.exe" delete $ServiceName | Out-Null } catch {}
        }
    }
}
