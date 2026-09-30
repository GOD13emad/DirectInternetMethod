$ErrorActionPreference='Stop'
$failed=$false
foreach($f in @(
  '.\windows\app\Start-Direct.ps1',
  '.\windows\app\Stop-Direct.ps1',
  '.\windows\app\Recovery.ps1'
)){
  $tokens=$null;$errors=$null
  [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $f),[ref]$tokens,[ref]$errors)|Out-Null
  if($errors.Count){
    $failed=$true
    foreach($e in $errors){Write-Error ($f+': '+$e.Message)}
  }
}
if($failed){exit 20}
'PS_PARSE_PASS'
