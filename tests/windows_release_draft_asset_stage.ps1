[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# R303: Download ONLY an owner-staged private draft asset; do not sign/publish/change trust.
function Assert-DraftReleaseInstallerAsset {
  [CmdletBinding()]
  param([object]$Release,[string]$Repository,[string]$ExpectedTag,
        [string]$ExpectedCommit,[string]$ExpectedArtifact,
        [string]$ExpectedSha256,[long]$ExpectedBytes)
  if($Release.draft -ne $true){throw 'RELEASE_NOT_PRIVATE_DRAFT'}
  if([string]$Release.tag_name -cne $ExpectedTag){throw 'RELEASE_TAG_MISMATCH'}
  if([string]$Release.target_commitish -cne $ExpectedCommit){throw 'RELEASE_TARGET_COMMIT_MISMATCH'}
  $matches=@($Release.assets | Where-Object { [string]$_.name -ceq $ExpectedArtifact })
  if($matches.Count -ne 1){throw 'SIGNED_DRAFT_INSTALLER_ASSET_MISSING_OR_DUPLICATE'}
  $asset=$matches[0]
  if([string]$asset.state -cne 'uploaded'){throw 'SIGNED_DRAFT_INSTALLER_NOT_UPLOADED'}
  if([long]$asset.size -ne $ExpectedBytes){throw 'SIGNED_DRAFT_INSTALLER_BYTES_MISMATCH'}
  if([string]$asset.digest -ine ('sha256:'+$ExpectedSha256)){throw 'SIGNED_DRAFT_INSTALLER_DIGEST_MISMATCH'}
  $assetId=[string]$asset.id
  if($assetId -notmatch '^[1-9][0-9]*$'){throw 'SIGNED_DRAFT_INSTALLER_ASSET_ID_INVALID'}
  if([string]$asset.url -cne ('https://api.github.com/repos/'+$Repository+'/releases/assets/'+$assetId)){
    throw 'SIGNED_DRAFT_INSTALLER_ASSET_ORIGIN_MISMATCH'
  }
  return $asset
}
$partial=$null
try {
  $repository='GOD13emad/DirectInternetMethod'
  $expectedTag='v1.5.2'
  $expectedLeaf='DirectInternetMethod_1.5.2_Windows_Setup.exe'
  if($env:GITHUB_REPOSITORY -cne $repository){throw 'REPOSITORY_AUTHORITY_MISMATCH'}
  if($env:GITHUB_REF -cne ('refs/tags/'+$expectedTag)){throw 'EXACT_VERSION_TAG_REQUIRED'}
  if([string]::IsNullOrWhiteSpace($env:GITHUB_TOKEN)){throw 'GITHUB_JOB_READ_TOKEN_MISSING'}
  if([string]$env:GITHUB_SHA -notmatch '^[a-fA-F0-9]{40}$'){throw 'GITHUB_EXACT_SHA_REQUIRED'}
  $root=Split-Path $PSScriptRoot -Parent
  $gitHead=((& git -C $root rev-parse HEAD)|Out-String).Trim()
  if($LASTEXITCODE -ne 0 -or $gitHead -cne $env:GITHUB_SHA){throw 'TAG_CHECKOUT_COMMIT_MISMATCH'}
  $rel=Get-Content -LiteralPath (Join-Path $root 'RELEASE.json') -Raw | ConvertFrom-Json
  if([string]$rel.version -cne '1.5.2'){throw 'RELEASE_METADATA_VERSION_MISMATCH'}
  $win=$rel.platforms.windows
  if([string]$win.artifact -cne ('delivery/'+$expectedLeaf)){throw 'RELEASE_METADATA_ARTIFACT_MISMATCH'}
  $sha=([string]$win.sha256).ToUpperInvariant()
  if($sha -notmatch '^[0-9A-F]{64}$'){throw 'RELEASE_METADATA_SHA_MISSING'}
  $bytes=[long]$win.bytes
  if($bytes -lt 1000000){throw 'RELEASE_METADATA_BYTES_IMPLAUSIBLE'}
  $dest=Join-Path $root ('delivery/'+$expectedLeaf)
  $partial=Join-Path $root ('delivery/.'+$expectedLeaf+'.pending')
  if((Test-Path -LiteralPath $dest) -or (Test-Path -LiteralPath $partial)){throw 'UNSAFE_RERUN_STAGING_PATH_OCCUPIED'}
  $headers=@{
    Authorization='Bearer '+$env:GITHUB_TOKEN
    Accept='application/vnd.github+json'
    'User-Agent'='DirectInternetMethod-R303-Tag-Staging'
    'X-GitHub-Api-Version'='2026-03-10'
  }
  # Enumerate authenticated drafts: /releases/tags/{tag} is for published releases.
  $releases=@(Invoke-RestMethod -Uri ('https://api.github.com/repos/'+$repository+'/releases?per_page=100') -Headers $headers -TimeoutSec 30)
  $match=@($releases | Where-Object { [string]$_.tag_name -ceq $expectedTag })
  if($match.Count -ne 1){throw 'EXACT_PRIVATE_DRAFT_RELEASE_MISSING_OR_AMBIGUOUS'}
  $asset=Assert-DraftReleaseInstallerAsset -Release $match[0] -Repository $repository -ExpectedTag $expectedTag -ExpectedCommit $gitHead -ExpectedArtifact $expectedLeaf -ExpectedSha256 $sha -ExpectedBytes $bytes
  $headers.Accept='application/octet-stream'
  Invoke-WebRequest -Uri ([string]$asset.url) -Headers $headers -OutFile $partial -MaximumRedirection 5 -TimeoutSec 180 -UseBasicParsing
  if(!(Test-Path -LiteralPath $partial -PathType Leaf)){throw 'SIGNED_DRAFT_INSTALLER_DOWNLOAD_MISSING'}
  if((Get-Item -LiteralPath $partial).Length -ne $bytes){throw 'SIGNED_DRAFT_INSTALLER_DOWNLOADED_SIZE_MISMATCH'}
  $actual=(Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash
  if($actual -cne $sha){throw 'SIGNED_DRAFT_INSTALLER_DOWNLOADED_SHA_MISMATCH'}
  if(Test-Path -LiteralPath $dest){throw 'SIGNED_DRAFT_INSTALLER_DESTINATION_RACE'}
  [IO.File]::Move($partial,$dest)
  $partial=$null
  Write-Output ('PASS_DRAFT_INSTALLER_STAGED_SHA_ONLY asset='+$expectedLeaf+' sha256='+$actual)
  Write-Output 'TRUSTED_AUTHENTICODE_AND_REAL_SAC_ACCEPTANCE_REMAIN_SEPARATE'
} catch {
  [Console]::Error.WriteLine('FAIL_CLOSED_RELEASE_STAGING: '+$_.Exception.Message)
  exit 42
} finally {
  if($null -ne $partial -and (Test-Path -LiteralPath $partial)){
    Remove-Item -LiteralPath $partial -Force -ErrorAction SilentlyContinue
  }
}
