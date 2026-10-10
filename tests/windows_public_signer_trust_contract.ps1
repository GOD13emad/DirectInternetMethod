$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Run in QA or CI: NO certificate-store trust mutation and NO network/service changes.
$Audit=Join-Path $PSScriptRoot 'windows_distribution_signature_audit.ps1'
if(!(Test-Path -LiteralPath $Audit)){throw 'SIGNING_AUDIT_SOURCE_MISSING'}
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Audit,[ref]$tokens,[ref]$errors)
if(@($errors).Count){throw 'SIGNING_AUDIT_PARSE_FAILED'}
$defs=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-EligibleSignerForSmartAppControl'},$true))
if($defs.Count -ne 1){throw 'SIGNING_PUBLIC_TRUST_AND_RSA_GUARD_MISSING'}
. ([scriptblock]::Create($defs[0].Extent.Text))

function Expect-Denial([object]$Signature,[string]$ExpectedReason,[string]$Name){
  $found=$null
  try {
    $null=Assert-EligibleSignerForSmartAppControl -Signature $Signature
  } catch {$found=[string]$_.Exception.Message}
  if($found -ne $ExpectedReason){throw ('NEGATIVE_FIXTURE_NOT_REJECTED_'+$Name+'_EXPECTED_'+$ExpectedReason+'_ACTUAL_'+$found)}
  Write-Output ('PASS '+$Name+' '+$ExpectedReason)
}

# Non-mutating ephemeral certificates, never imported into CurrentUser/LocalMachine trust stores.
$rsa=[System.Security.Cryptography.RSA]::Create(2048)
$rootReq=[System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
  'CN=R223 Untrusted QA Root',$rsa,
  [System.Security.Cryptography.HashAlgorithmName]::SHA256,
  [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$rootReq.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$false,0,$true))
$root=$rootReq.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5),[DateTimeOffset]::UtcNow.AddHours(2))
$signingOids=[System.Security.Cryptography.OidCollection]::new()
[void]$signingOids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
$rootReq2=[System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
  'CN=R223 Self Signed Dev',$rsa,
  [System.Security.Cryptography.HashAlgorithmName]::SHA256,
  [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$rootReq2.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($signingOids,$false))
$self=$rootReq2.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5),[DateTimeOffset]::UtcNow.AddHours(1))
$invalid=[pscustomobject]@{Status='NotSigned';SignerCertificate=$null}
Expect-Denial $invalid 'TRUSTED_AUTHENTICODE_SIGNATURE_REQUIRED' 'unsigned'
$missing=[pscustomobject]@{Status='Valid';SignerCertificate=$null}
Expect-Denial $missing 'SIGNER_CERTIFICATE_MISSING' 'missing-certificate'
$mockSelf=[pscustomobject]@{Status='Valid';SignerCertificate=$self}
Expect-Denial $mockSelf 'SELF_SIGNED_SIGNER_NOT_PUBLIC_TRUSTED' 'local-self-signed-dev'
$ec=[System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256'))
$ecCaReq=[System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=R223 EC Fixture CA',$ec,[System.Security.Cryptography.HashAlgorithmName]::SHA256)
$ecCaReq.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$false,0,$true))
$ecCa=$ecCaReq.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5),[DateTimeOffset]::UtcNow.AddHours(2))
$ecReq=[System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=R223 ECC Test Leaf',$ec,[System.Security.Cryptography.HashAlgorithmName]::SHA256)
$ecReq.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($signingOids,$false))
$eccLeaf=$ecReq.Create($ecCa,[DateTimeOffset]::UtcNow.AddMinutes(-3),[DateTimeOffset]::UtcNow.AddHours(1),[byte[]](1..16))
$mockEcc=[pscustomobject]@{Status='Valid';SignerCertificate=$eccLeaf}
Expect-Denial $mockEcc 'SMART_APP_CONTROL_RSA_SIGNER_REQUIRED' 'ecc-ca-issued'
$leafRsa=[System.Security.Cryptography.RSA]::Create(2048)
$leafReq=[System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
  'CN=R223 Untrusted RSA Leaf',$leafRsa,[System.Security.Cryptography.HashAlgorithmName]::SHA256,
  [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$leafReq.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($signingOids,$false))
$rsaLeaf=$leafReq.Create($root,[DateTimeOffset]::UtcNow.AddMinutes(-3),[DateTimeOffset]::UtcNow.AddHours(1),[byte[]](20..35))
Expect-Denial ([pscustomobject]@{Status='Valid';SignerCertificate=$rsaLeaf}) 'PUBLIC_TRUST_CHAIN_UNVERIFIED' 'untrusted-private-root'
$noEkuReq=[System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
  'CN=R223 Wrong EKU Leaf',$leafRsa,[System.Security.Cryptography.HashAlgorithmName]::SHA256,
  [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$noEku=$noEkuReq.Create($root,[DateTimeOffset]::UtcNow.AddMinutes(-3),[DateTimeOffset]::UtcNow.AddHours(1),[byte[]](40..55))
Expect-Denial ([pscustomobject]@{Status='Valid';SignerCertificate=$noEku}) 'CODE_SIGNING_EKU_REQUIRED' 'missing-code-signing-eku'

# Runtime helper tests do NOT attest to a real product signature.
$platformSigned=Join-Path $env:SystemRoot 'System32\notepad.exe'
$platformSig=Get-AuthenticodeSignature -LiteralPath $platformSigned
if($platformSig.Status -ne 'Valid'){throw 'REFERENCE_PLATFORM_SIGNED_BINARY_NOT_TRUSTED'}
$platformSigner=Assert-EligibleSignerForSmartAppControl -Signature $platformSig
if(-not $platformSigner){throw 'PLATFORM_REFERENCE_POSITIVE_REJECTED'}
Write-Output 'PASS Microsoft-authenticode-signed OS reference, positive branch (not Direct Method)'
Write-Output 'PASS 6/6 negative signer eligibility fixtures; production Windows signed installer still UNPROVEN'
# R302: permanent, disk-free installer identity regressions; no signed binaries copied or renamed.
$identityNames=@('Assert-ExpectedInstallerArtifact','Assert-ExpectedInstallerVersion')
foreach($identityName in $identityNames){
  $identityDefs=@($ast.FindAll({
    param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $identityName
  },$true))
  if($identityDefs.Count -ne 1){throw ('INSTALLER_IDENTITY_GUARD_FUNCTION_MISSING_'+$identityName)}
  $identityCalls=@($ast.FindAll({
    param($node) $node -is [Management.Automation.Language.CommandAst] -and $node.GetCommandName() -eq $identityName
  },$true))
  if($identityCalls.Count -ne 1){throw ('INSTALLER_IDENTITY_GUARD_NOT_USED_'+$identityName)}
  . ([scriptblock]::Create($identityDefs[0].Extent.Text))
}
function Expect-IdentityDenial([scriptblock]$Action,[string]$Expected,[string]$Case){
  $actual=$null
  try { & $Action } catch { $actual=[string]$_.Exception.Message }
  if($actual -cne $Expected){throw ('INSTALLER_IDENTITY_FALSE_ACCEPT_'+$Case+'_EXPECTED_'+$Expected+'_ACTUAL_'+$actual)}
  Write-Output ('PASS identity-denied '+$Case+' '+$Expected)
}
$qaSetup=Join-Path $PSScriptRoot 'DirectInternetMethod_1.5.2_Windows_Setup.exe'
$qaArtifact='delivery/DirectInternetMethod_1.5.2_Windows_Setup.exe'
$qaVersion=[pscustomobject]@{
  ProductName='Direct Internet Method'
  FileDescription='Direct Internet Method Setup'
  CompanyName='Direct Internet Method'
}
Assert-ExpectedInstallerArtifact -DeclaredArtifact $qaArtifact -InstallerPath $qaSetup
Assert-ExpectedInstallerArtifact -DeclaredArtifact 'delivery\DirectInternetMethod_1.5.2_Windows_Setup.exe' -InstallerPath $qaSetup
Assert-ExpectedInstallerVersion -VersionInfo $qaVersion
Write-Output 'PASS identity-positive synthetic setup metadata'
Expect-IdentityDenial { Assert-ExpectedInstallerArtifact -DeclaredArtifact 'delivery/Other.exe' -InstallerPath $qaSetup } 'RELEASE_INSTALLER_ARTIFACT_IDENTITY_MISMATCH' 'foreign-declared-artifact'
Expect-IdentityDenial { Assert-ExpectedInstallerArtifact -DeclaredArtifact $qaArtifact -InstallerPath (Join-Path $PSScriptRoot 'notepad.exe') } 'INSTALLER_FILENAME_MISMATCH' 'foreign-executable-filename'
Expect-IdentityDenial { Assert-ExpectedInstallerVersion -VersionInfo ([pscustomobject]@{ProductName='Unrelated';FileDescription='Direct Internet Method Setup';CompanyName='Direct Internet Method'}) } 'INSTALLER_PRODUCT_IDENTITY_MISMATCH' 'foreign-product-name'
Expect-IdentityDenial { Assert-ExpectedInstallerVersion -VersionInfo ([pscustomobject]@{ProductName='Direct Internet Method';FileDescription='Unrelated';CompanyName='Direct Internet Method'}) } 'INSTALLER_PRODUCT_IDENTITY_MISMATCH' 'foreign-file-description'
Expect-IdentityDenial { Assert-ExpectedInstallerVersion -VersionInfo ([pscustomobject]@{ProductName='Direct Internet Method';FileDescription='Direct Internet Method Setup';CompanyName='Unrelated'}) } 'INSTALLER_PRODUCT_IDENTITY_MISMATCH' 'foreign-company'
Write-Output 'PASS 5/5 dynamic installer identity negative fixtures; actual public signed installer remains UNPROVEN'
