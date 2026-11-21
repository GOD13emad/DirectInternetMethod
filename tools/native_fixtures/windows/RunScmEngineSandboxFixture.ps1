# Isolated Windows Sandbox R888: frozen file transaction kernel + real synthetic SCM.
# NO actual DIM Service, Inno, root production files, owner network, or host install.
$ErrorActionPreference = 'Stop'
$Name = 'DIMR887IsolatedFixtureSvc'
$Root = 'C:\ProgramData\DIM_R888_EngineScmFixture'
$Binary = Join-Path $Root 'current\app\FixtureService.exe'
$Marker = 'C:\ProgramData\DIM_R887_SCMSandboxFixture\active-version.txt'
$OwnerData = Join-Path $Root 'data\owner.settings'
$InputRoot = 'C:\DIMR888\input'
$OutputRoot = 'C:\DIMR888\output'
$Receipt = Join-Path $OutputRoot 'engine_scm_receipt.json'
$exe = Join-Path $InputRoot 'dim-universal-engine.exe'
$Packages = Join-Path $InputRoot 'packages'
$done = New-Object 'System.Collections.Generic.List[string]'

function Require([bool]$condition, [string]$reason) {
    if (-not $condition) { throw $reason }
}
function Invoke-ScFixture([string[]]$scArguments) {
    $result = (& "$env:WINDIR\System32\sc.exe" @scArguments 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw ('SC_FAILED_' + $scArguments[0] + '_' + $LASTEXITCODE + '_' + $result.Trim())
    }
    return $result
}
function Invoke-DimEngineFixture([string[]]$engineArguments) {
    # PowerShell's automatic $args is not a safe named parameter.
    # Native CLI stderr must remain observable for a deliberate failure.
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $result = (& $exe @engineArguments 2>&1 | Out-String)
        $exit = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $saved
    }
    if ($exit -ne 0) {
        throw ('ENGINE_FAILED_' + $engineArguments[0] + '_' + $exit + '_' + $result.Trim())
    }
    $json = $result | ConvertFrom-Json
    Require ($null -ne $json.status) 'ENGINE_JSON_STATUS_MISSING'
    return $json
}
function WaitState([string]$expected) {
    for ($i = 0; $i -lt 50; $i++) {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $service -and "$($service.Status)" -eq $expected) { return }
        Start-Sleep -Milliseconds 400
    }
    throw ('SCM_STATE_TIMEOUT_' + $expected)
}
function WaitRemoved {
    for ($i = 0; $i -lt 50; $i++) {
        $svc = Get-CimInstance Win32_Service -Filter "Name = '$Name'" -ErrorAction SilentlyContinue
        if ($null -eq $svc) { return }
        Start-Sleep -Milliseconds 400
    }
    throw 'SCM_REGISTRATION_STILL_PRESENT'
}
function AssertActive([string]$version, [string]$hash) {
    WaitState 'Running'
    Require ((Get-FileHash -LiteralPath $Binary).Hash -eq $hash) ('ACTIVE_BINARY_HASH_' + $version)
    for ($i = 0; $i -lt 40; $i++) {
        if ((Test-Path -LiteralPath $Marker) -and
            ((Get-Content -LiteralPath $Marker -Raw).Trim() -eq $version)) { return }
        Start-Sleep -Milliseconds 350
    }
    throw ('RUNTIME_SERVICE_VERSION_WRONG_' + $version)
}
function EngineStep([string]$action, [string[]]$options) {
    $parameters = @($action, '--platform', 'windows-x86_64', '--root', $Root) + @($options)
    return Invoke-DimEngineFixture $parameters
}
function StageAndActivate([string]$folder, [string]$pin) {
    EngineStep 'stage' @('--bundle', (Join-Path $Packages $folder),
                         '--expected-manifest-sha256', $pin) | Out-Null
    EngineStep 'activate' @('--quiesced') | Out-Null
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    Require ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'SANDBOX_ADMIN_REQUIRED'
    Require (-not (Test-Path -LiteralPath $Receipt)) 'RECEIPT_ALREADY_EXISTS'
    Require (-not (Test-Path -LiteralPath $Root)) 'ROOT_ALREADY_EXISTS'
    Require (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) 'SCM_FIXTURE_ALREADY_EXISTS'
    Require (Test-Path -LiteralPath $Packages) 'PACKAGE_ROOT_MISSING'
    $pins = Get-Content (Join-Path $Packages 'pins.json') -Raw | ConvertFrom-Json
    Require ($pins.fixture_name -eq $Name -and $pins.schema -eq 1) 'PACKAGE_PIN_SCHEMA'
    $enginePin = (Get-Content (Join-Path $InputRoot 'engine.sha256') -Raw).Trim()
    Require ((Get-FileHash -LiteralPath $exe).Hash -eq $enginePin) 'FROZEN_ENGINE_PIN_INVALID'
    foreach ($row in @(@('old156', $pins.old_manifest_sha256),
                       @('bad157', $pins.bad_manifest_sha256),
                       @('new157', $pins.new_manifest_sha256))) {
        $manifest = Join-Path (Join-Path $Packages $row[0]) 'manifest.json'
        Require ((Get-FileHash -LiteralPath $manifest).Hash -eq $row[1]) ('SOURCE_MANIFEST_PIN_' + $row[0])
    }
    [void]$done.Add('PINNED_FROZEN_ENGINE_AND_3_BUNDLES')

    $empty = EngineStep 'verify' @()
    Require ($empty.status -eq 'EMPTY') 'INITIAL_ENGINE_NOT_EMPTY'
    StageAndActivate 'old156' $pins.old_manifest_sha256
    Require ((Get-FileHash -LiteralPath $Binary).Hash -eq $pins.old_binary_sha256) 'OLD_SOURCE_COPY_HASH'
    Invoke-ScFixture @('create', $Name, 'binPath=', $Binary,
                       'start=', 'demand', 'obj=', 'LocalSystem',
                       'DisplayName=', 'DIM R888 Isolated SCM+Engine Fixture') | Out-Null
    $scm = Get-CimInstance Win32_Service -Filter "Name = '$Name'"
    Require ($null -ne $scm -and $scm.PathName -eq $Binary -and
             $scm.StartName -eq 'LocalSystem') 'NATIVE_SCM_IDENTITY_FAILED'
    Invoke-ScFixture @('start', $Name) | Out-Null
    AssertActive '1.5.6' $pins.old_binary_sha256
    EngineStep 'commit' @('--accepted') | Out-Null
    $state = EngineStep 'verify' @()
    Require ($state.version -eq '1.5.6') 'INITIAL_COMMIT_WRONG_VERSION'
    [void]$done.Add('SCM_NATIVE_156_PLUS_FROZEN_ENGINE_COMMIT')

    [IO.Directory]::CreateDirectory((Split-Path $OwnerData -Parent)) | Out-Null
    [IO.File]::WriteAllBytes($OwnerData, [Text.Encoding]::UTF8.GetBytes('DIM_R888_OWNER_DATA_KEEP'))
    $ownerHash = (Get-FileHash -LiteralPath $OwnerData).Hash

    Invoke-ScFixture @('stop', $Name) | Out-Null
    WaitState 'Stopped'
    StageAndActivate 'bad157' $pins.bad_manifest_sha256
    $err = (& "$env:WINDIR\System32\sc.exe" start $Name 2>&1 | Out-String)
    Require ($LASTEXITCODE -ne 0) 'BAD_SERVICE_BINARY_UNEXPECTEDLY_STARTED'
    WaitState 'Stopped'
    EngineStep 'rollback' @('--quiesced') | Out-Null
    $state = EngineStep 'verify' @()
    Require ($state.version -eq '1.5.6') 'ENGINE_ROLLBACK_VERSION_WRONG'
    Invoke-ScFixture @('start', $Name) | Out-Null
    AssertActive '1.5.6' $pins.old_binary_sha256
    Require ((Get-FileHash -LiteralPath $OwnerData).Hash -eq $ownerHash) 'OWNER_CHANGED_DURING_ROLLBACK'
    [void]$done.Add('SCM_START_FAILURE_FROZEN_ENGINE_ROLLBACK_RESTART_156')

    Invoke-ScFixture @('stop', $Name) | Out-Null
    WaitState 'Stopped'
    StageAndActivate 'new157' $pins.new_manifest_sha256
    Invoke-ScFixture @('start', $Name) | Out-Null
    AssertActive '1.5.7' $pins.new_binary_sha256
    EngineStep 'commit' @('--accepted') | Out-Null
    $state = EngineStep 'verify' @()
    Require ($state.version -eq '1.5.7') 'ENGINE_COMMIT_157_WRONG'
    Require ((Get-FileHash -LiteralPath $OwnerData).Hash -eq $ownerHash) 'OWNER_CHANGED_DURING_UPGRADE'
    [void]$done.Add('SCM_NATIVE_157_PLUS_FROZEN_ENGINE_COMMIT')

    Invoke-ScFixture @('stop', $Name) | Out-Null
    WaitState 'Stopped'
    EngineStep 'uninstall-prepare' @('--quiesced') | Out-Null
    Invoke-ScFixture @('delete', $Name) | Out-Null
    WaitRemoved
    EngineStep 'uninstall-commit' @('--native-unregistered') | Out-Null
    $state = EngineStep 'verify' @()
    Require ($state.status -eq 'EMPTY') 'ENGINE_UNINSTALL_NOT_EMPTY'
    Require ((Get-FileHash -LiteralPath $OwnerData).Hash -eq $ownerHash) 'OWNER_CHANGED_DURING_UNINSTALL'
    [void]$done.Add('NATIVE_SCM_DELETE_ENGINE_CODE_ONLY_UNINSTALL_PRESERVE_DATA')

    $result = [ordered]@{
        schema=1
        status='PASS_ISOLATED_SCM_PLUS_FROZEN_ENGINE_FIXTURE'
        native_product_installation_accepted=$false
        platform='windows-x86_64'
        service=$Name
        stages=$done.ToArray()
        engine_sha256=$enginePin
        old_manifest_sha256=$pins.old_manifest_sha256
        bad_manifest_sha256=$pins.bad_manifest_sha256
        new_manifest_sha256=$pins.new_manifest_sha256
        owner_data_sha256=$ownerHash
    }
} catch {
    $result = [ordered]@{
        schema=1
        status='FAIL_CLOSED_ISOLATED_SCM_ENGINE_FIXTURE'
        native_product_installation_accepted=$false
        error=$_.Exception.Message
        stages=$done.ToArray()
    }
} finally {
    # Only the hard-coded fixture service can be stopped/deleted on this guest.
    $existing = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        try { & "$env:WINDIR\System32\sc.exe" stop $Name | Out-Null } catch {}
        try { & "$env:WINDIR\System32\sc.exe" delete $Name | Out-Null } catch {}
    }
    if (Test-Path -LiteralPath $OutputRoot) {
        $result | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $Receipt -Encoding UTF8
    }
}
