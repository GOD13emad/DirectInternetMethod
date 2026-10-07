[CmdletBinding()]
param([string]$InstallerPath='')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Root=Split-Path $PSScriptRoot -Parent
if([string]::IsNullOrWhiteSpace($InstallerPath)){
  $InstallerPath=Join-Path $Root 'delivery\DirectInternetMethod_1.5.2_Windows_Setup.exe'
}
$Result=[ordered]@{
 schema=1;project='Direct Internet Method';version='1.5.2'
 status='UNPROVEN';installer='DirectInternetMethod_1.5.2_Windows_Setup.exe'
 actualSha256=$null;expectedSha256=$null;signatureStatus=$null
 trustCertificateSubject=$null;reason=$null
}
try{
 $Rel=Get-Content -LiteralPath (Join-Path $Root 'RELEASE.json') -Raw | ConvertFrom-Json
 if([string]$Rel.version -ne '1.5.2'){throw 'RELEASE_VERSION_MISMATCH'}
 $Result.expectedSha256=[string]$Rel.platforms.windows.sha256
 if($Result.expectedSha256 -notmatch '^[A-Fa-f0-9]{64}$'){throw 'EXPECTED_HASH_MISSING'}
 if(!(Test-Path -LiteralPath $InstallerPath -PathType Leaf)){throw 'INSTALLER_FILE_MISSING'}
 $Result.actualSha256=(Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash
 if($Result.actualSha256 -ne $Result.expectedSha256){throw 'INSTALLER_SHA_MISMATCH'}
 $sig=Get-AuthenticodeSignature -LiteralPath $InstallerPath
 $Result.signatureStatus=[string]$sig.Status
 if($sig.SignerCertificate){$Result.trustCertificateSubject=[string]$sig.SignerCertificate.Subject}
 if($sig.Status -ne 'Valid'){throw 'TRUSTED_AUTHENTICODE_SIGNATURE_REQUIRED'}
 $Result.status='PASS_SIGNATURE_INTEGRITY_ONLY'
 $Result.reason='Still requires independent Windows App Control and installation acceptance on an enforced clean sandbox.'
}catch{
 $Result.status='FAIL_CLOSED'
 $Result.reason=$_.Exception.Message
}
$Result|ConvertTo-Json -Depth 4
if($Result.status -ne 'PASS_SIGNATURE_INTEGRITY_ONLY'){exit 42}
