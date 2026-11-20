[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$UserRoot,
 [Parameter(Mandatory=$true)][string]$PrivilegedRoot,
 [Parameter(Mandatory=$true)][string]$ExpectedVersion,
 [Parameter(Mandatory=$true)][string]$ExpectedManifestSha256,
 [int]$ExpectedManagedFiles=681,
 [int]$ExpectedPrivilegedFiles=674
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Guard([bool]$ok,[string]$errorCode) {
 if(!$ok){throw ('R850_INSTALLED_MANIFEST_FAIL_CLOSED_'+$errorCode)}
}
Guard ($ExpectedVersion -cin @('1.5.6','1.5.7')) 'VERSION_ARGUMENT'
Guard ($ExpectedManifestSha256 -match '^[A-Fa-f0-9]{64}$') 'EXPECTED_SHA_FORMAT'
Guard ($ExpectedManagedFiles -gt 0 -and $ExpectedPrivilegedFiles -gt 0 -and $ExpectedPrivilegedFiles -le $ExpectedManagedFiles) 'COUNTS'
$rootUser=[IO.Path]::GetFullPath($UserRoot).TrimEnd('\')
$rootPriv=[IO.Path]::GetFullPath($PrivilegedRoot).TrimEnd('\')
Guard ($rootUser -cne $rootPriv) 'ROOTS_IDENTICAL'
Guard (Test-Path -LiteralPath $rootUser -PathType Container) 'USER_ROOT_ABSENT'
Guard (Test-Path -LiteralPath $rootPriv -PathType Container) 'PRIV_ROOT_ABSENT'
$manifest=Join-Path $rootUser 'manifest.json'
Guard (Test-Path -LiteralPath $manifest -PathType Leaf) 'MANIFEST_ABSENT'
$item=Get-Item -LiteralPath $manifest -Force
Guard (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'MANIFEST_REPARSE'
Guard ((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash -ceq $ExpectedManifestSha256.ToUpperInvariant()) 'MANIFEST_SHA_MISMATCH'
$doc=Get-Content -LiteralPath $manifest -Raw -Encoding UTF8|ConvertFrom-Json
Guard ([string]$doc.version -ceq $ExpectedVersion) 'VERSION_MISMATCH'
Guard (@($doc.files).Count -eq $ExpectedManagedFiles) 'TOTAL_COUNT'
$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$good=0
foreach($f in @($doc.files)){
 $scope=[string]$f.scope
 Guard ($scope -cin @('privileged','user')) 'INVALID_SCOPE'
 $relative=[string]$f.file
 Guard (![string]::IsNullOrWhiteSpace($relative)) 'BLANK_RELATIVE_PATH'
 Guard (!([IO.Path]::IsPathRooted($relative)) -and !$relative.Contains('..') -and !$relative.Contains(':') -and !$relative.Contains([char]0)) 'UNSAFE_RELATIVE_PATH'
 Guard ($seen.Add($scope+':'+$relative)) 'DUPLICATE_SCOPE_FILE'
 $root=if($scope -ceq 'privileged'){$rootPriv}else{$rootUser}
 $file=[IO.Path]::GetFullPath((Join-Path $root ($relative.Replace('/',[IO.Path]::DirectorySeparatorChar))))
 Guard ($file.StartsWith(($root+[IO.Path]::DirectorySeparatorChar),[StringComparison]::OrdinalIgnoreCase)) 'PATH_ESCAPE'
 Guard (Test-Path -LiteralPath $file -PathType Leaf) 'FILE_MISSING'
 $fi=Get-Item -LiteralPath $file -Force
 Guard (($fi.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'FILE_REPARSE'
 if($scope -ceq 'privileged'){
  Guard ($fi.Length -eq [long]$f.bytes) 'PRIVILEGED_SIZE_MISMATCH'
  Guard ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ceq ([string]$f.sha256).ToUpperInvariant()) 'PRIVILEGED_SHA_MISMATCH'
  $good++
 }
}
Guard ($good -eq $ExpectedPrivilegedFiles) 'PRIVILEGED_COUNT'
Write-Output ('R850_NATIVE_INSTALLED_PRIVILEGED_MANIFEST_PASS_'+$good+'_OF_'+$ExpectedPrivilegedFiles)
