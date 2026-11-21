# R900: disposable Windows Sandbox only, using one frozen synthetic CLI.
# This PowerShell wrapper never touches production DIM, SCM or Tailscale.
param(
    [ValidateSet('stage','rollback-then-forward','complete')]
    [string]$Phase='stage'
)
$ErrorActionPreference='Stop'
$InputRoot='C:\DIMR900\input'
$PersistRoot='C:\DIMR900\persist'
$OutputRoot='C:\DIMR900\output'
$Exe=Join-Path $InputRoot 'R900VmReplayFixture.exe'
$Pin=Join-Path $InputRoot 'fixture.sha256'
$Log=Join-Path $OutputRoot ($Phase+'.guest.log')
$Receipt=Join-Path $OutputRoot ($Phase+'.guest.receipt.json')
function Require([bool]$OK,[string]$Reason) { if(-not $OK) { throw $Reason } }
try {
    Require ([Environment]::Is64BitProcess) 'R900_64BIT_GUEST_REQUIRED'
    Require (Test-Path -LiteralPath $Exe) 'R900_GUEST_EXE_MISSING'
    Require (Test-Path -LiteralPath $Pin) 'R900_GUEST_PIN_MISSING'
    $wanted=(Get-Content -LiteralPath $Pin -Raw).Trim()
    Require ($wanted -match '^[a-fA-F0-9]{64}$') 'R900_GUEST_PIN_FORMAT'
    Require ((Get-FileHash -LiteralPath $Exe).Hash -eq $wanted) 'R900_EXE_PIN_MISMATCH'
    Require (Test-Path -LiteralPath $PersistRoot) 'R900_PERSIST_FOLDER_NOT_MOUNTED'
    Require (-not (Test-Path -LiteralPath $Receipt)) 'R900_GUEST_RECEIPT_ALREADY_EXISTS'
    # Deliberately blocks for stage/resume, awaiting forced closure of this
    # exact WindowsSandbox guest by the host after checking persisted status.
    & $Exe $Phase *> $Log
    Require ($LASTEXITCODE -eq 0) 'R900_FROZEN_GUEST_NONZERO'
    if($Phase -ne 'complete') {
        throw 'R900_EXPECTED_GUEST_FORCED_VM_CLOSE_NOT_OBSERVED'
    }
    $result=Join-Path $PersistRoot 'vm-recovery-receipt.json'
    Require (Test-Path -LiteralPath $result) 'R900_FINAL_RESULT_MISSING'
    $raw=Get-Content -LiteralPath $result -Raw|ConvertFrom-Json
    Require ($raw.status -eq 'PASS_R900_SYNTHETIC_TWO_VM_FORCED_TERMINATIONS_REPLAY' -and
             $raw.native_product_installation_accepted -eq $false -and
             $raw.physical_power_loss_accepted -eq $false) 'R900_FINAL_SCOPE_INVALID'
    $report=[ordered]@{status='PASS_R900_GUEST_THREE_REPLAY';
        schema=1;phase=$Phase;frozen_sha256=$wanted;
        persist_receipt_sha256=(Get-FileHash $result).Hash;
        native_product_installation_accepted=$false;
        physical_power_loss_accepted=$false}
    $report|ConvertTo-Json -Compress|Set-Content -LiteralPath $Receipt -Encoding UTF8
} catch {
    $report=[ordered]@{
        status='FAIL_CLOSED_R900_GUEST';
        schema=1;phase=$Phase;error=$_.Exception.Message;
        native_product_installation_accepted=$false}
    $report|ConvertTo-Json -Compress|Set-Content -LiteralPath $Receipt -Encoding UTF8
}
