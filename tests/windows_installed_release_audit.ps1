$ErrorActionPreference='Stop'
$Guard=Join-Path $PSScriptRoot 'windows_install_registration_audit.ps1'
if(!(Test-Path -LiteralPath $Guard)){throw 'WINDOWS_INSTALL_REGISTRATION_AUDIT_MISSING'}
& pwsh.exe -NoProfile -File $Guard
$code=$LASTEXITCODE
if($code -ne 0){exit $code}
