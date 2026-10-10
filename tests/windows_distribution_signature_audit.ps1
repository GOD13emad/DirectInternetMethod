[CmdletBinding()]
param([string]$InstallerPath='')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Assert-EligibleSignerForSmartAppControl {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][object]$Signature)
  if([string]$Signature.Status -ne 'Valid'){throw 'TRUSTED_AUTHENTICODE_SIGNATURE_REQUIRED'}
  $cert=$Signature.SignerCertificate
  if($null -eq $cert -or $cert -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]){
    throw 'SIGNER_CERTIFICATE_MISSING'
  }
  if($cert.Subject -eq $cert.Issuer){throw 'SELF_SIGNED_SIGNER_NOT_PUBLIC_TRUSTED'}
  # Smart App Control only supports RSA-based code signing, not ECC.
  if([string]$cert.PublicKey.Oid.Value -ne '1.2.840.113549.1.1.1'){
    throw 'SMART_APP_CONTROL_RSA_SIGNER_REQUIRED'
  }
  $hasCodeSigningEku=$false
  foreach($ext in $cert.Extensions){
    if($ext -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]){
      foreach($oid in $ext.EnhancedKeyUsages){
        if([string]$oid.Value -eq '1.3.6.1.5.5.7.3.3'){$hasCodeSigningEku=$true}
      }
    }
  }
  if(-not $hasCodeSigningEku){throw 'CODE_SIGNING_EKU_REQUIRED'}
  $chain=[System.Security.Cryptography.X509Certificates.X509Chain]::new()
  try{
    # Authenticode=Valid must still be checked first; independent issuer
    # chain rejects locally generated, privately issued certificates.
    $chain.ChainPolicy.RevocationMode=[System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.VerificationFlags=[System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
    # Artifact Signing leaf certs can be short-lived; trusted timestamps
    # are adjudicated by Authenticode itself. Inspect chain at last valid time.
    $now=[DateTime]::UtcNow
    $validAt=if($now -gt $cert.NotAfter.ToUniversalTime()){$cert.NotAfter.ToUniversalTime().AddSeconds(-1)}else{$now}
    if($validAt -lt $cert.NotBefore.ToUniversalTime()){throw 'SIGNER_CERTIFICATE_NOT_YET_VALID'}
    $chain.ChainPolicy.VerificationTime=$validAt
    if(-not $chain.Build($cert) -or $chain.ChainElements.Count -lt 2){
      throw 'PUBLIC_TRUST_CHAIN_UNVERIFIED'
    }
  }finally{$chain.Dispose()}
  return $cert
}


function Assert-ExpectedInstallerArtifact {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][string]$DeclaredArtifact,
        [Parameter(Mandatory=$true)][string]$InstallerPath)
  $expectedLeaf='DirectInternetMethod_1.5.2_Windows_Setup.exe'
  if($DeclaredArtifact.Replace('\','/') -cne ('delivery/'+$expectedLeaf)){
    throw 'RELEASE_INSTALLER_ARTIFACT_IDENTITY_MISMATCH'
  }
  if([IO.Path]::GetFileName($InstallerPath) -cne $expectedLeaf){
    throw 'INSTALLER_FILENAME_MISMATCH'
  }
}
function Assert-ExpectedInstallerVersion {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][object]$VersionInfo)
  if((([string]$VersionInfo.ProductName).Trim() -cne 'Direct Internet Method') -or
     (([string]$VersionInfo.FileDescription).Trim() -cne 'Direct Internet Method Setup') -or
     (([string]$VersionInfo.CompanyName).Trim() -cne 'Direct Internet Method')){
    throw 'INSTALLER_PRODUCT_IDENTITY_MISMATCH'
  }
}

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
 # An Authenticode Valid executable with a matching declared SHA is not
 # automatically the Inno Setup distribution for this product (e.g. signed Notepad).
 Assert-ExpectedInstallerArtifact -DeclaredArtifact ([string]$Rel.platforms.windows.artifact) -InstallerPath $InstallerPath
 if(!(Test-Path -LiteralPath $InstallerPath -PathType Leaf)){throw 'INSTALLER_FILE_MISSING'}
 $ver=(Get-Item -LiteralPath $InstallerPath).VersionInfo
 Assert-ExpectedInstallerVersion -VersionInfo $ver
 $Result.actualSha256=(Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash
 if($Result.actualSha256 -ne $Result.expectedSha256){throw 'INSTALLER_SHA_MISMATCH'}
 $sig=Get-AuthenticodeSignature -LiteralPath $InstallerPath
 $Result.signatureStatus=[string]$sig.Status
 if($sig.SignerCertificate){$Result.trustCertificateSubject=[string]$sig.SignerCertificate.Subject}
 $signer=Assert-EligibleSignerForSmartAppControl -Signature $sig
 $Result['signerAlgorithm']='RSA'
 $Result['signerEku']='CodeSigning'
 $Result.status='PASS_SIGNATURE_INTEGRITY_ONLY'
 $Result.reason='Still requires independent Windows App Control and installation acceptance on an enforced clean sandbox.'
}catch{
 $Result.status='FAIL_CLOSED'
 $Result.reason=$_.Exception.Message
}
$Result|ConvertTo-Json -Depth 4
if($Result.status -ne 'PASS_SIGNATURE_INTEGRITY_ONLY'){exit 42}
