# R893 offline Windows Sandbox native Inno+SCM and coordinated uninstall replay.
# Synthetic-only AppId and service; never installed DIM product identity.
$ErrorActionPreference = 'Stop'
$ServiceName = 'DIMR887IsolatedFixtureSvc'
$InputRoot = 'C:\DIMR893\input'
$OutputRoot = 'C:\DIMR893\output'
$Packages = Join-Path $InputRoot 'packages'
$Exe = Join-Path $InputRoot 'dual-scope-uninstall-fixture.exe'
$CodeRoot = Join-Path $env:PROGRAMDATA 'DIM_R891_Isolated_Code'
$UserRoot = Join-Path $env:LOCALAPPDATA 'DIM_R891_Isolated_UserCode'
$JournalRoot = Join-Path $env:PROGRAMDATA 'DIM_R891_Isolated_Journal'
$Binary = Join-Path $CodeRoot 'current\app\FixtureService.exe'
$Marker = 'C:\ProgramData\DIM_R887_SCMSandboxFixture\active-version.txt'
$OwnerData = Join-Path $UserRoot 'data\owner.settings'
$ReceiptPath = Join-Path $OutputRoot 'inno_scm_two_scope_uninstall_receipt.json'
$Trace = Join-Path $OutputRoot 'trace.txt'
$InnoId = '{E8039748-26D7-4E64-ACEF-3E24B708B9A2}'
$InnoName = 'DIM R892 Isolated Inno Registry Fixture'
$InnoPath = Join-Path $env:ProgramFiles 'DIM_R892_Isolated_Inno'
$UninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' + $InnoId + '_is1'
$InnoSetupOld = Join-Path $InputRoot 'R892_Inno_1_5_6.exe'
$InnoSetupNew = Join-Path $InputRoot 'R892_Inno_1_5_7.exe'
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
function CheckInno([string]$expected) {
    $key = Get-ItemProperty -LiteralPath $UninstallKey -ErrorAction SilentlyContinue
    Require ($null -ne $key) ('INNO_REGISTRATION_MISSING_' + $expected)
    Require ($key.DisplayName -eq $InnoName -and $key.DisplayVersion -eq $expected -and
             -not [string]::IsNullOrWhiteSpace($key.UninstallString)) 'INNO_REGISTRATION_WRONG'
    Require (Test-Path -LiteralPath (Join-Path $InnoPath 'synthetic.marker')) 'INNO_MARKER_MISSING'
}
function InstallInno([string]$version, [string]$pin) {
    $file = if ($version -eq '1.5.6') { $InnoSetupOld } else { $InnoSetupNew }
    Require ((Get-FileHash -LiteralPath $file).Hash -eq $pin) 'INNO_BINARY_PIN_MISMATCH'
    Mark ('INNO_INSTALL_BEGIN_' + $version)
    $run = Start-Process -FilePath $file -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-') -PassThru -Wait -ErrorAction Stop
    Require ($run.ExitCode -eq 0) ('INNO_INSTALL_FAILED_' + $run.ExitCode)
    CheckInno $version
    Mark ('INNO_INSTALL_PASS_' + $version)
}
function RemoveInno() {
    CheckInno '1.5.7'
    $list = @(Get-ChildItem -LiteralPath $InnoPath -Filter 'unins*.exe' -File)
    Require ($list.Count -eq 1) 'INNO_UNINSTALL_COUNT_WRONG'
    Mark 'INNO_UNINSTALL_BEGIN'
    $run = Start-Process -FilePath $list[0].FullName -ArgumentList @('/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART') -PassThru -Wait -ErrorAction Stop
    Require ($run.ExitCode -eq 0) ('INNO_UNINSTALL_FAILED_' + $run.ExitCode)
    Require (-not (Test-Path -LiteralPath $UninstallKey)) 'INNO_REGISTRY_REMAINS'
    Mark 'INNO_UNINSTALL_PASS'
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
    Require (-not (Test-Path -LiteralPath $UninstallKey) -and
             -not (Test-Path -LiteralPath $InnoPath)) 'INNO_FIXTURE_PREEXISTS'
    Require ([Environment]::Is64BitProcess) 'SANDBOX_64_BIT_REQUIRED'
    $innoPins = Get-Content (Join-Path $InputRoot 'inno-pins.json') -Raw | ConvertFrom-Json
    Require ($innoPins.schema -eq 1 -and $innoPins.appid -eq $InnoId) 'INNO_PIN_SCHEMA'
    Require ((Get-FileHash $InnoSetupOld).Hash -eq $innoPins.old -and
             (Get-FileHash $InnoSetupNew).Hash -eq $innoPins.new) 'INNO_BINARY_PINS_WRONG'

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
    InstallInno '1.5.6' $innoPins.old
    Invoke-Sc @('create',$ServiceName,'binPath=',$Binary,'start=','demand',
                'obj=','LocalSystem','DisplayName=','DIM R892 Isolated TwoScope Fixture')|Out-Null
    Invoke-Sc @('start',$ServiceName)|Out-Null
    CheckRuntime '1.5.6' $pins.binary_sha256_old
    Invoke-Dual @('finalize','--version','1.5.6') | Out-Null
    CheckScopes '1.5.6'
    [void]$Stages.Add('INNO_HKLM_AND_SCM_156_TWO_SCOPE_COMMIT')

    [IO.Directory]::CreateDirectory((Split-Path $OwnerData -Parent))|Out-Null
    [IO.File]::WriteAllBytes($OwnerData,[Text.Encoding]::UTF8.GetBytes('R893_OWNER_CONFIGURATION_KEEP'))
    $ownerHash = (Get-FileHash $OwnerData).Hash

    Invoke-Sc @('stop',$ServiceName)|Out-Null
    WaitState 'Stopped'
    Prepare '1.5.7' $true
    $failed=Invoke-Sc @('start',$ServiceName) $true
    Require ($failed.code -ne 0) 'INVALID_BINARY_SC_START_SUCCEEDED'
    WaitState 'Stopped'
    Invoke-Dual @('abort')|Out-Null
    CheckInno '1.5.6'
    Invoke-Sc @('start',$ServiceName)|Out-Null
    CheckRuntime '1.5.6' $pins.binary_sha256_old
    CheckScopes '1.5.6'
    Require ((Get-FileHash $OwnerData).Hash -eq $ownerHash) 'OWNER_CHANGED_AFTER_ABORT'
    [void]$Stages.Add('BAD_NATIVE_START_ABORT_BOTH_ROOTS_RESTORE_156')

    Invoke-Sc @('stop',$ServiceName)|Out-Null
    WaitState 'Stopped'
    Prepare '1.5.7'
    InstallInno '1.5.7' $innoPins.new
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
    [void]$Stages.Add('INNO_HKLM_SCM_FIRST_COMMIT_REPLAY_BOTH_ROOTS_157')

    Invoke-Sc @('stop',$ServiceName)|Out-Null
    WaitState 'Stopped'
    # A staged removal interrupted after first park must roll back BOTH roots
    # while native registrations are still present.
    $interrupt=Invoke-Dual @('coordinated-uninstall-prepare','--fault-after','code') $true
    Require ($interrupt.code -ne 0 -and $interrupt.out.Contains('FIXTURE_INJECTED_AFTER_UNINSTALL_PREPARE')) 'FIRST_PARK_INJECTION_NOT_OBSERVED'
    Invoke-Dual @('coordinated-uninstall-abort')|Out-Null
    CheckScopes '1.5.7'
    CheckInno '1.5.7'
    Require ((Get-FileHash $OwnerData).Hash -eq $ownerHash) 'OWNER_CHANGED_ON_ABORT'
    [void]$Stages.Add('FIRST_PARK_INTERRUPTED_BOTH_SCOPES_ABORTED_NATIVE_REGISTERED')

    Invoke-Dual @('coordinated-uninstall-prepare')|Out-Null
    RemoveInno
    Invoke-Sc @('delete',$ServiceName)|Out-Null
    WaitRemoved
    $interrupt=Invoke-Dual @('coordinated-uninstall-finish','--fault-after','code') $true
    Require ($interrupt.code -ne 0 -and $interrupt.out.Contains('FIXTURE_INJECTED_AFTER_UNINSTALL_FINISH')) 'FIRST_IRREVERSIBLE_FINISH_INJECTION_NOT_OBSERVED'
    $rollback=Invoke-Dual @('coordinated-uninstall-abort') $true
    Require ($rollback.code -ne 0 -and $rollback.out.Contains('COORDINATOR_UNINSTALL_FORWARD_ONLY')) 'ILLEGAL_NATIVE_UNREGISTRATION_ROLLBACK'
    Invoke-Dual @('coordinated-uninstall-finish')|Out-Null
    $after=Invoke-Dual @('verify')
    Require ($after.result.scopes.code.status -eq 'EMPTY' -and
             $after.result.scopes.user.status -eq 'EMPTY') 'ENGINE_CODE_NOT_UNINSTALLED'
    Require ((Get-FileHash $OwnerData).Hash -eq $ownerHash) 'OWNER_CONFIGURATION_DELETED'
    [void]$Stages.Add('INNO_SCM_UNREGISTERED_FIRST_SCOPE_REMOVED_REPLAY_BOTH_CODE_ONLY')

    $Report=[ordered]@{
        schema=1
        status='PASS_R893_SYNTHETIC_INNO_SCM_COORDINATED_UNINSTALL'
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
        inno_appid=$InnoId
        inno_old_installer_sha256=$innoPins.old
        inno_new_installer_sha256=$innoPins.new
    }
} catch {
    Mark ('FAIL_' + $_.Exception.GetType().Name)
    $Report=[ordered]@{
        schema=1
        status='FAIL_CLOSED_R893_SYNTHETIC_INNO_SCM_COORDINATED_UNINSTALL'
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
    if ($Report.status -eq 'PASS_R893_SYNTHETIC_INNO_SCM_COORDINATED_UNINSTALL') {
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
