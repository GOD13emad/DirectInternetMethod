# Native SCM service fixture in an isolated, offline Windows Sandbox ONLY.
# The fixed service identity does not match DirectInternetMethodSvc.
# Input is a SHA-pinned mapped fixture folder; output is mapped scratch.
# No installer, release, real product service, or host network is changed.
$ErrorActionPreference = 'Stop'
$Name = 'DIMR887IsolatedFixtureSvc'
$InputRoot = 'C:\DIMR887\input'
$OutputRoot = 'C:\DIMR887\output'
$GuestRoot = 'C:\ProgramData\DIM_R887_SCMSandboxFixture'
$Binary = Join-Path $GuestRoot 'svc.exe'
$Marker = Join-Path $GuestRoot 'active-version.txt'
$OwnerData = Join-Path $GuestRoot 'data\owner.settings'
$Receipt = Join-Path $OutputRoot 'native_scm_receipt.json'
$stages = New-Object 'System.Collections.Generic.List[string]'
$before = $null

function Require([bool]$ok, [string]$reason) {
    if (-not $ok) { throw $reason }
}
function Invoke-ScFixture([string[]]$values) {
    $out = (& "$env:WINDIR\System32\sc.exe" @values 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw ('SC_FAILED_' + $values[0] + '_' + $LASTEXITCODE + '_' + $out.Trim()) }
    return $out
}
function WaitState([string]$expected) {
    for ($i = 0; $i -lt 50; $i++) {
        $s = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $s -and "$($s.Status)" -eq $expected) { return }
        Start-Sleep -Milliseconds 400
    }
    throw ('SCM_STATE_TIMEOUT_' + $expected)
}
function WaitRemoved {
    for ($i = 0; $i -lt 50; $i++) {
        $s = Get-CimInstance Win32_Service -Filter "Name = '$Name'" -ErrorAction SilentlyContinue
        if ($null -eq $s) { return }
        Start-Sleep -Milliseconds 400
    }
    throw 'SCM_SERVICE_NOT_REMOVED'
}
function AssertBinary([string]$version, [string]$sha) {
    Require ((Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash -eq $sha) ('BINARY_HASH_' + $version)
    Require ((& $Binary --version) -eq $version) ('BINARY_VERSION_' + $version)
}
function AssertActive([string]$version) {
    WaitState 'Running'
    for ($i = 0; $i -lt 30; $i++) {
        if ((Test-Path -LiteralPath $Marker) -and
            ((Get-Content -LiteralPath $Marker -Raw).Trim() -eq $version)) { return }
        Start-Sleep -Milliseconds 300
    }
    throw ('SERVICE_RUNTIME_MARKER_MISMATCH_' + $version)
}

try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    Require ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'GUEST_ADMIN_REQUIRED'
    Require (-not (Test-Path -LiteralPath $Receipt)) 'OUTPUT_RECEIPT_ALREADY_EXISTS'
    Require (-not (Get-Service -Name $Name -ErrorAction SilentlyContinue)) 'FIXTURE_SERVICE_ALREADY_EXISTS'
    Require (-not (Test-Path -LiteralPath $GuestRoot)) 'FIXTURE_ROOT_ALREADY_EXISTS'
    $pins = Get-Content -LiteralPath (Join-Path $InputRoot 'pins.json') -Raw | ConvertFrom-Json
    Require ($pins.schema -eq 1 -and $pins.name -eq $Name) 'PIN_SCHEMA'
    $old = Join-Path $InputRoot 'ScmFixture-1.5.6.exe'
    $new = Join-Path $InputRoot 'ScmFixture-1.5.7.exe'
    Require ((Get-FileHash -LiteralPath $old -Algorithm SHA256).Hash -eq $pins.old_sha256) 'PIN_156_WRONG'
    Require ((Get-FileHash -LiteralPath $new -Algorithm SHA256).Hash -eq $pins.new_sha256) 'PIN_157_WRONG'
    Require ((& $old --version) -eq '1.5.6' -and (& $new --version) -eq '1.5.7') 'VERSIONED_BINARIES_INVALID'
    [void]$stages.Add('PINNED_TWO_DIFFERENT_BINARIES')

    New-Item -Path (Join-Path $GuestRoot 'data') -ItemType Directory -Force | Out-Null
    [IO.File]::WriteAllBytes($OwnerData, [Text.Encoding]::UTF8.GetBytes('SYNTHETIC_OWNER_DATA_KEEP'))
    $before = (Get-FileHash -LiteralPath $OwnerData -Algorithm SHA256).Hash
    Copy-Item -LiteralPath $old -Destination $Binary
    AssertBinary '1.5.6' $pins.old_sha256
    Invoke-ScFixture @('create', $Name, 'binPath=', $Binary, 'start=', 'demand', 'obj=', 'LocalSystem', 'DisplayName=', 'DIM R887 Isolated SCM Fixture') | Out-Null
    $scm = Get-CimInstance Win32_Service -Filter "Name = '$Name'"
    Require ($null -ne $scm -and $scm.PathName -eq $Binary -and
             $scm.StartName -eq 'LocalSystem') 'SCM_REGISTRATION_IDENTITY_INVALID'
    [void]$stages.Add('REAL_SCM_REGISTRATION')

    Invoke-ScFixture @('start', $Name) | Out-Null
    AssertActive '1.5.6'
    [void]$stages.Add('REAL_SCM_START_156')

    Invoke-ScFixture @('stop', $Name) | Out-Null
    WaitState 'Stopped'
    [IO.File]::WriteAllBytes($Binary, [byte[]](0,1,2,3,4))
    $badText = (& "$env:WINDIR\System32\sc.exe" start $Name 2>&1 | Out-String)
    Require ($LASTEXITCODE -ne 0) 'INVALID_BINARY_UNEXPECTEDLY_STARTED'
    WaitState 'Stopped'
    [void]$stages.Add('INVALID_BINARY_START_REJECTED')

    Copy-Item -LiteralPath $old -Destination $Binary -Force
    AssertBinary '1.5.6' $pins.old_sha256
    Invoke-ScFixture @('start', $Name) | Out-Null
    AssertActive '1.5.6'
    [void]$stages.Add('ROLLBACK_TO_156_AND_RESTART')

    Invoke-ScFixture @('stop', $Name) | Out-Null
    WaitState 'Stopped'
    Copy-Item -LiteralPath $new -Destination $Binary -Force
    AssertBinary '1.5.7' $pins.new_sha256
    Invoke-ScFixture @('start', $Name) | Out-Null
    AssertActive '1.5.7'
    [void]$stages.Add('UPGRADE_TO_157_AND_RESTART')

    Invoke-ScFixture @('stop', $Name) | Out-Null
    WaitState 'Stopped'
    Invoke-ScFixture @('delete', $Name) | Out-Null
    WaitRemoved
    [void]$stages.Add('NATIVE_SCM_UNREGISTERED')

    Remove-Item -LiteralPath $Binary -Force
    Require (-not (Test-Path $Binary)) 'OWNED_CODE_REMAINS'
    Require ((Get-FileHash -LiteralPath $OwnerData -Algorithm SHA256).Hash -eq $before) 'OWNER_DATA_CHANGED'
    [void]$stages.Add('OWNED_CODE_REMOVED_OWNER_DATA_PRESERVED')
    $result = [ordered]@{
        schema=1
        status='PASS_ISOLATED_NATIVE_SCM_FIXTURE_NO_PRODUCT'
        product_native_installation_accepted=$false
        platform='windows-x86_64'
        service=$Name
        stages=$stages.ToArray()
        old_sha256=$pins.old_sha256
        new_sha256=$pins.new_sha256
        owner_data_sha256=$before
    }
} catch {
    $result = [ordered]@{
        schema=1
        status='FAIL_CLOSED_ISOLATED_SCM_FIXTURE'
        product_native_installation_accepted=$false
        error=$_.Exception.Message
        stages=$stages.ToArray()
    }
} finally {
    # Cleanup is limited to guest fixture identity, never the live DIM service.
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $svc) {
        try { & "$env:WINDIR\System32\sc.exe" stop $Name | Out-Null } catch {}
        try { & "$env:WINDIR\System32\sc.exe" delete $Name | Out-Null } catch {}
    }
    if (Test-Path -LiteralPath $OutputRoot) {
        $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Receipt -Encoding UTF8
    }
}
