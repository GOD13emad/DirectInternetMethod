# Direct Internet Method R425 - guarded two-step legacy v1.5.1 provider preservation.
# Explicit admin rollback ONLY. Never changes DNS/routes/firewall/Tailscale or silently invokes Setup.
# Stage before running the SHA-pinned old installer; Restore only AFTER exact old
# GUI+service have been verified. No automatic deletion of unknown files/backups.
[CmdletBinding()]
param(
  [ValidateSet('Stage','Restore')][string]$Action = 'Stage',
  [string]$BaselineInstaller,
  [switch]$StaticOnly
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Need([bool]$ok,[string]$failure) { if(-not $ok){throw ('LEGACY_PROVIDER_FAIL_CLOSED:'+ $failure)} }
function Sha([string]$p) { return (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash }
$ExpectedSetupSha='4E1974B5A40F96B49B7B4196FFE963DCDF65B05E4F2B89DE4EC06E794B77EE9B'
$ExpectedSetupBytes=157111497
$LegacyDefaultProviderSha='D4E4B3A91252802DF33A46FE4F36067BA02A3E28974EDD23D458127E5224E0CD'
$LegacyGuiSha='B85460B8225060E7C8C9C54F5C39D444457071E77C0BBD7CD39BF34343F8B619'
$LegacyServiceSha='A327B01DFB7C05896DDB9F81E123E8A0362B200E52A5EB061AFDB4A7BCA367A5'
if($StaticOnly) {
 Write-Output 'PASS_R425_STATIC_ONLY_NO_FS_OR_INSTALLER_MUTATION'
 return
}
Need ($env:OS -eq 'Windows_NT') 'WINDOWS_ONLY'
$Principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
Need $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) 'EXPLICIT_ADMIN_REQUIRED_FOR_DOWNGRADE'
Need (-not [string]::IsNullOrWhiteSpace($BaselineInstaller)) 'EXACT_151_INSTALLER_ARGUMENT_REQUIRED'
$installer=(Resolve-Path -LiteralPath $BaselineInstaller -ErrorAction Stop).Path
Need ((Get-Item -LiteralPath $installer).Length -eq $ExpectedSetupBytes -and
      (Sha $installer) -eq $ExpectedSetupSha) 'PUBLISHED_STABLE_151_INSTALLER_SHA_CHANGED'
$app=Join-Path $env:LOCALAPPDATA 'Programs\DirectInternetMethod'
$provider=Join-Path $app 'app\router_gateway\providers.json'
$state=Join-Path $env:ProgramData 'DirectInternetMethod'
$slot=Join-Path $state 'RollbackProviderPending'
$backup=Join-Path $slot 'provider.bin'
$record=Join-Path $slot 'manifest.json'
$gui=Join-Path $app 'app\DirectInternetMethod.exe'
$service=Join-Path $env:ProgramFiles 'DirectInternetMethod\Privileged\app\DirectInternetMethod.Service.exe'
$binRoot=Join-Path $app 'bin'
function GuardPath([string]$path) {
  $cur=[IO.Path]::GetFullPath($path)
  for($i=0;$i -lt 40;$i++){
    $it=Get-Item -LiteralPath $cur -Force -ErrorAction SilentlyContinue
    if($null -ne $it) {
      Need (-not [bool]($it.Attributes -band [IO.FileAttributes]::ReparsePoint)) ('SYMLINK_OR_JUNCTION_REFUSED_'+$cur)
    }
    $parent=[IO.Path]::GetDirectoryName($cur)
    if([string]::IsNullOrEmpty($parent) -or $parent -eq $cur){break}
    $cur=$parent
  }
}
GuardPath $provider
GuardPath $slot
GuardPath $installer
function FileIsPlain([string]$path) {
  $i=Get-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
  return ($null -ne $i -and $i -is [IO.FileInfo] -and
          -not [bool]($i.Attributes -band [IO.FileAttributes]::ReparsePoint))
}
if($Action -eq 'Stage') {
  Need (-not (Test-Path -LiteralPath $slot)) 'PENDING_SLOT_EXISTS_NO_BLIND_REPLAY'
  Need (FileIsPlain $provider) 'CUSTOM_PROVIDER_NOT_REGULAR_FILE'
  $bytes=[IO.File]::ReadAllBytes($provider)
  Need ($bytes.Length -gt 0 -and $bytes.Length -le 1048576) 'PROVIDER_SIZE_NOT_BOUNDED'
  $oldSha=Sha $provider
  $oldJson=$null
  try {$oldJson=[Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json -AsHashtable}
  catch {throw 'LEGACY_PROVIDER_FAIL_CLOSED:PROVIDER_JSON_NOT_VALID'}
  Need ($oldJson -is [System.Collections.IDictionary]) 'PROVIDER_NOT_JSON_OBJECT'

  # v1.5.1 InstallDelete recursively clears {app}\bin. Save exact user bytes.
  $binInventory=@()
  if(Test-Path -LiteralPath $binRoot){
    GuardPath $binRoot
    Need ((Get-Item -LiteralPath $binRoot -Force) -is [IO.DirectoryInfo]) 'BIN_ROOT_NOT_DIRECTORY'
    $nodes=@(Get-ChildItem -LiteralPath $binRoot -Recurse -Force)
    Need ($nodes.Count -le 1536) 'BIN_NODE_COUNT_EXCEEDED'
    [long]$total=0
    foreach($node in $nodes){
      GuardPath $node.FullName
      Need (-not [bool]($node.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'BIN_SYMLINK_REFUSED'
      if($node -is [IO.DirectoryInfo]){continue}
      Need ($node -is [IO.FileInfo] -and
            $node.FullName.StartsWith($binRoot+'\', [StringComparison]::OrdinalIgnoreCase)) 'BIN_NODE_NOT_REGULAR_OR_OUTSIDE'
      $rel=$node.FullName.Substring($binRoot.Length+1)
      Need ($rel.Length -gt 0 -and $rel.Length -le 250 -and
            (-not [IO.Path]::IsPathRooted($rel)) -and
            ($rel -notmatch '(^|[\\/])\.\.([\\/]|$)|[:<>|*?"]')) 'BIN_RELATIVE_PATH_UNSAFE'
      $total += [long]$node.Length
      Need ($total -le 268435456 -and $node.Length -le 67108864 -and
            $binInventory.Count -lt 1024) 'BIN_FILE_SIZE_OR_COUNT_EXCEEDED'
      $binInventory+=@{relative=$rel;sha256=(Sha $node.FullName);bytes=[long]$node.Length}
    }
  }
  [void][IO.Directory]::CreateDirectory($state)
  [void][IO.Directory]::CreateDirectory($slot)
  # A partial stage is preserved as evidence; never removed on error.
  $fs=[IO.FileStream]::new($backup,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try {$fs.Write($bytes,0,$bytes.Length);$fs.Flush($true)} finally {$fs.Dispose()}
  Need ((Sha $backup) -eq $oldSha) 'STAGED_PROVIDER_SHA_CHANGED'
  foreach($item in $binInventory){
    $old=Join-Path $binRoot $item.relative
    $dest=Join-Path (Join-Path $slot 'bin') $item.relative
    GuardPath $old; GuardPath $dest
    Need ((FileIsPlain $old) -and (Sha $old) -eq $item.sha256) 'BIN_CHANGED_DURING_STAGE'
    [void][IO.Directory]::CreateDirectory((Split-Path $dest -Parent))
    Need (-not(Test-Path -LiteralPath $dest)) 'BIN_STAGE_COLLISION'
    [IO.File]::Copy($old,$dest,$false)
    Need ((Sha $dest) -eq $item.sha256) 'BIN_COPY_SHA_CHANGED'
  }
  $m=[ordered]@{
    schema=1;product='Direct Internet Method';operation='PRESERVE_CUSTOM_PROVIDER_BEFORE_LEGACY_151_REINSTALL'
    providerPath=$provider;providerSha256=$oldSha;providerBytes=$bytes.Length
    installerSha256=$ExpectedSetupSha;expectedLegacyProviderSha256=$LegacyDefaultProviderSha
    expectedLegacyGuiSha256=$LegacyGuiSha;expectedLegacyServiceSha256=$LegacyServiceSha
    stagedUtc=(Get-Date).ToUniversalTime().ToString('o');binFiles=@($binInventory)
  }
  [IO.File]::WriteAllText($record,($m|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
  Need ((@(Get-ChildItem -LiteralPath $slot -File -Recurse -Force).Count -eq (2+$binInventory.Count)) -and (Sha $backup) -eq $oldSha) 'STAGE_HAS_UNKNOWN_CONTENT_OR_SHA'
  Write-Output ('PASS_EXACT_PROVIDER_STAGED_PENDING_LEGACY_ROLLBACK_SHA='+$oldSha)
  return
}
# Restore requires the exact old version to be installed and trusted. Nothing
# touches user data until ALL file/metadata/concurrent-edit guards pass.
Need (Test-Path -LiteralPath $slot -PathType Container) 'RECOVERY_SLOT_MISSING'
GuardPath $backup;GuardPath $record;GuardPath $gui;GuardPath $service
Need (FileIsPlain $backup -and (FileIsPlain $record)) 'STAGE_FILES_NOT_PLAIN'

$m=Get-Content -LiteralPath $record -Raw -Encoding UTF8|ConvertFrom-Json -AsHashtable
Need ($m.schema -eq 1 -and $m.operation -eq 'PRESERVE_CUSTOM_PROVIDER_BEFORE_LEGACY_151_REINSTALL' -and
      $m.providerPath -ceq $provider -and $m.installerSha256 -eq $ExpectedSetupSha -and
      $m.expectedLegacyProviderSha256 -eq $LegacyDefaultProviderSha -and
      $m.expectedLegacyGuiSha256 -eq $LegacyGuiSha -and
      $m.expectedLegacyServiceSha256 -eq $LegacyServiceSha) 'STAGE_MANIFEST_PROVENANCE_CHANGED'
$staged=[IO.File]::ReadAllBytes($backup)
Need ($m.providerSha256 -match '^[A-F0-9]{64}$' -and
      $m.providerBytes -eq $staged.Length -and
      (Sha $backup) -eq $m.providerSha256) 'STAGE_BACKUP_SHA_CHANGED'
Need ((FileIsPlain $gui) -and (FileIsPlain $service) -and
      (Sha $gui) -eq $LegacyGuiSha -and (Sha $service) -eq $LegacyServiceSha) 'LEGACY_151_BINARY_POSTINSTALL_SHA_NOT_ACCEPTED'

Need ($m.ContainsKey('binFiles')) 'BIN_MANIFEST_MISSING'
$binRows=@($m.binFiles)
Need ($binRows.Count -le 1024) 'BIN_MANIFEST_COUNT_INVALID'
$known=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
[void]$known.Add('provider.bin')
[void]$known.Add('manifest.json')
$restoreBin=@()
[long]$total=0
foreach($entry in $binRows){
  Need ($entry -is [Collections.IDictionary]) 'BIN_ROW_TYPE_INVALID'
  $rel=[string]$entry.relative
  Need ($rel.Length -gt 0 -and $rel.Length -le 250 -and
        (-not [IO.Path]::IsPathRooted($rel)) -and
        ($rel -notmatch '(^|[\\/])\.\.([\\/]|$)|[:<>|*?"]') -and
        ([string]$entry.sha256 -match '^[0-9a-fA-F]{64}$')) 'BIN_MANIFEST_UNSAFE'
  [long]$n=$entry.bytes
  $total += $n
  Need ($n -ge 0 -and $n -le 67108864 -and $total -le 268435456) 'BIN_MANIFEST_BYTES_UNSAFE'
  $relative='bin\'+$rel
  Need ($known.Add($relative)) 'BIN_DUPLICATE_PATH'
  $src=Join-Path $slot $relative
  GuardPath $src
  Need ((FileIsPlain $src) -and
        (Get-Item -LiteralPath $src).Length -eq $n -and
        (Sha $src) -eq $entry.sha256) 'BIN_STAGED_FILE_CHANGED'
  $target=Join-Path $binRoot $rel
  GuardPath $target
  if(Test-Path -LiteralPath $target){
    Need ((FileIsPlain $target) -and
          (Sha $target) -eq $entry.sha256) 'FOREIGN_BIN_EDIT_PRESERVED'
  }
  $restoreBin+=@{src=$src;dest=$target;sha=$entry.sha256}
}
foreach($node in @(Get-ChildItem -LiteralPath $slot -Recurse -Force)){
  GuardPath $node.FullName
  Need (-not [bool]($node.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'FOREIGN_STAGE_SYMLINK'
  if($node -is [IO.DirectoryInfo]){continue}
  Need ($node -is [IO.FileInfo]) 'FOREIGN_STAGE_FILE_TYPE'
  $relative=$node.FullName.Substring($slot.Length+1)
  Need ($known.Contains($relative)) 'UNKNOWN_STAGE_FILE_PRESERVED'
}

GuardPath $provider
$present=Test-Path -LiteralPath $provider -PathType Leaf
Need ($present -or -not (Test-Path -LiteralPath $provider)) 'TARGET_FOREIGN_TYPE'
$current=if($present){Sha $provider}else{$null}
Need ($null -eq $current -or $current -eq $m.providerSha256 -or
      $current -eq $LegacyDefaultProviderSha) 'FOREIGN_POST_STAGE_PROVIDER_EDIT_PRESERVED'
if($current -ne $m.providerSha256) {
  $tmp=Join-Path (Split-Path $provider -Parent) '.providers.json.dim-restore-stage'
  Need (-not(Test-Path -LiteralPath $tmp)) 'STALE_RESTORE_STAGE_NOT_OWNED'
  GuardPath $tmp
  $f=[IO.FileStream]::new($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try {$f.Write($staged,0,$staged.Length);$f.Flush($true)} finally {$f.Dispose()}
  Need ((Sha $tmp) -eq $m.providerSha256) 'RESTORE_STAGE_SHA_FAILED'
  [IO.File]::Move($tmp,$provider,$true)
}
Need ((Sha $provider) -eq $m.providerSha256) 'RESTORED_PROVIDER_SHA_FAILED'

# Restore only the SHA-attested user files deleted by historical InstallDelete.
foreach($file in $restoreBin){
  if(Test-Path -LiteralPath $file.dest -PathType Leaf){
    Need ((Sha $file.dest) -eq $file.sha) 'BIN_CONCURRENT_EDIT_PRESERVED'
    continue
  }
  $parent=Split-Path $file.dest -Parent
  GuardPath $parent
  [void][IO.Directory]::CreateDirectory($parent)
  $tmp=Join-Path $parent ('.'+[IO.Path]::GetFileName($file.dest)+'.dim-restore-stage')
  Need (-not (Test-Path -LiteralPath $tmp)) 'BIN_STAGED_RESTORE_COLLISION'
  $data=[IO.File]::ReadAllBytes($file.src)
  $stream=[IO.FileStream]::new($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{$stream.Write($data,0,$data.Length);$stream.Flush($true)}finally{$stream.Dispose()}
  Need ((Sha $tmp) -eq $file.sha) 'BIN_RESTORE_TEMP_SHA_FAILED'
  [IO.File]::Move($tmp,$file.dest,$false)
  Need ((Sha $file.dest) -eq $file.sha) 'BIN_RESTORATION_SHA_FAILED'
}
foreach($file in $restoreBin){
  Need ((FileIsPlain $file.dest) -and (Sha $file.dest) -eq $file.sha) 'BIN_RESTORE_POST_SHA_FAILED'
}
# Cleanup only snapshot-attested items, never arbitrary bin/user files.
foreach($file in $restoreBin){Remove-Item -LiteralPath $file.src -Force -ErrorAction Stop}
$snapshotRoot=Join-Path $slot 'bin'
if(Test-Path -LiteralPath $snapshotRoot -PathType Container){
  foreach($folder in @(Get-ChildItem -LiteralPath $snapshotRoot -Directory -Recurse -Force |
                      Sort-Object { $_.FullName.Length } -Descending)){
    Need (@(Get-ChildItem -LiteralPath $folder.FullName -Force).Count -eq 0) 'BIN_SNAPSHOT_FOLDER_NOT_EMPTY'
    Remove-Item -LiteralPath $folder.FullName -ErrorAction Stop
  }
  Need (@(Get-ChildItem -LiteralPath $snapshotRoot -Force).Count -eq 0) 'BIN_SNAPSHOT_UNKNOWN_CONTENT'
  Remove-Item -LiteralPath $snapshotRoot -ErrorAction Stop
}

# Acknowledge the provider snapshot after exact user bin restoration.
Remove-Item -LiteralPath $backup -Force -ErrorAction Stop
Remove-Item -LiteralPath $record -Force -ErrorAction Stop
Need (@(Get-ChildItem -LiteralPath $slot -Force).Count -eq 0) 'UNKNOWN_STAGE_CONTENT_PRESERVED'
Remove-Item -LiteralPath $slot -ErrorAction Stop
Write-Output ('PASS_LEGACY_151_PROVIDER_RESTORED_SHA='+$m.providerSha256)
Write-Output ('PASS_LEGACY_151_USER_BIN_RESTORED_COUNT='+$restoreBin.Count)
