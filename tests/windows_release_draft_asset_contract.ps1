[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
# R303: disk-free, token-free synthetic private draft asset scenarios.
$path=Join-Path $PSScriptRoot 'windows_release_draft_asset_stage.ps1'
$t=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$t,[ref]$errors)
if(@($errors).Count){throw 'STAGING_SCRIPT_PARSE_FAILED'}
$found=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Assert-DraftReleaseInstallerAsset'},$true))
if($found.Count -ne 1){throw 'DRAFT_METADATA_VALIDATOR_MISSING'}
. ([scriptblock]::Create($found[0].Extent.Text))
$repo='GOD13emad/DirectInternetMethod'
$tag='v1.5.2'
$head='63859378c0c0c88feb7a228cedc52485e2160f2e'
$leaf='DirectInternetMethod_1.5.2_Windows_Setup.exe'
$hash='A'*64
$bytes=[long]157128933
$baseline=[pscustomobject]@{
 draft=$true;tag_name=$tag;target_commitish=$head
 assets=@([pscustomobject]@{
   id=314159;name=$leaf;state='uploaded';size=$bytes;digest='sha256:'+$hash
   url='https://api.github.com/repos/'+$repo+'/releases/assets/314159'
 })
}
function Run-Test([object]$data){
 Assert-DraftReleaseInstallerAsset -Release $data -Repository $repo -ExpectedTag $tag -ExpectedCommit $head -ExpectedArtifact $leaf -ExpectedSha256 $hash -ExpectedBytes $bytes
}
$good=Run-Test $baseline
if($null -eq $good -or [string]$good.id -cne '314159'){throw 'VALID_DRAFT_REJECTED'}
Write-Output 'PASS valid-private-draft'
function Deny([string]$case,[scriptblock]$change,[string]$expected){
 $x=$baseline|ConvertTo-Json -Depth 10|ConvertFrom-Json
 & $change $x
 $reason=$null
 try{$null=Run-Test $x}catch{$reason=[string]$_.Exception.Message}
 if($reason -cne $expected){throw ('DRAFT_FALSE_ACCEPT_'+$case+'_expected_'+$expected+'_got_'+$reason)}
 Write-Output ('PASS negative-'+$case+' '+$expected)
}
Deny 'published' {param($x)$x.draft=$false} 'RELEASE_NOT_PRIVATE_DRAFT'
Deny 'tag' {param($x)$x.tag_name='v1.5.1'} 'RELEASE_TAG_MISMATCH'
Deny 'commit' {param($x)$x.target_commitish='0'*40} 'RELEASE_TARGET_COMMIT_MISMATCH'
Deny 'missing' {param($x)$x.assets=@()} 'SIGNED_DRAFT_INSTALLER_ASSET_MISSING_OR_DUPLICATE'
Deny 'duplicate' {param($x)$x.assets=@($x.assets[0],$x.assets[0])} 'SIGNED_DRAFT_INSTALLER_ASSET_MISSING_OR_DUPLICATE'
Deny 'state' {param($x)$x.assets[0].state='starter'} 'SIGNED_DRAFT_INSTALLER_NOT_UPLOADED'
Deny 'size' {param($x)$x.assets[0].size=1} 'SIGNED_DRAFT_INSTALLER_BYTES_MISMATCH'
Deny 'digest' {param($x)$x.assets[0].digest='sha256:'+('B'*64)} 'SIGNED_DRAFT_INSTALLER_DIGEST_MISMATCH'
Deny 'id' {param($x)$x.assets[0].id='invalid'} 'SIGNED_DRAFT_INSTALLER_ASSET_ID_INVALID'
Deny 'origin' {param($x)$x.assets[0].url='https://example.org/asset'} 'SIGNED_DRAFT_INSTALLER_ASSET_ORIGIN_MISMATCH'
Write-Output 'PASS 10/10 release draft negative fixtures; NO actual signed asset acceptance'
