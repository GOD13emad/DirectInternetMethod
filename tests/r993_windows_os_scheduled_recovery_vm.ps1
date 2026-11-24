# R993: disposable hosted Windows VM only; never an installed product broker.
# The scheduler, not the observer, starts the exact R986 recovery process.
[CmdletBinding()]
param(
 [Parameter(Mandatory)][ValidateSet('Register','Inspect','Recover','Remove')][string]$Mode,
 [Parameter(Mandatory)][string]$Config
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Need([bool]$ok,[string]$label){if(!$ok){throw $label}}
function Hex([string]$value,[int]$size){return $value -cmatch ('^[a-f0-9]{'+$size+'}$')}
function Assert-R993Identity([object]$c) {
 Need ($c.schema -eq 1) 'R993_SCHEMA_DRIFT'
 Need (Hex ([string]$c.source) 40) 'R993_SOURCE_PIN_DRIFT'
 Need (Hex ([string]$c.dispatchPin) 64) 'R993_DISPATCH_PIN_DRIFT'
 Need (Hex ([string]$c.scriptSha) 64) 'R993_SCRIPT_PIN_DRIFT'
 Need (Hex ([string]$c.pythonScriptSha) 64) 'R993_PYTHON_PIN_DRIFT'
 # Python tempfile's safe random alphabet contains underscores.
 Need ([string]$c.name -cmatch '^dim-universal-[a-zA-Z0-9_-]+$') 'R993_TEMP_BASE_NAME_DRIFT'
 Need ($c.taskName -ceq ('DIMR993VM-'+$c.source.Substring(0,12))) 'R993_TASK_NAME_DRIFT'
 Need ([string]$c.ownerSid -cmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') 'R993_OWNER_SID_DRIFT'
 Need (![string]::IsNullOrWhiteSpace([string]$c.ownerName)) 'R993_OWNER_NAME_MISSING'
}
function Test-R993OwnerPrincipal([string]$principal,[object]$c) {
 if([string]::IsNullOrWhiteSpace($principal)){return $false}
 if($principal -ieq [string]$c.ownerSid){return $true}
 if($principal -ieq [string]$c.ownerName){return $true}
 try {
  $sid=[Security.Principal.NTAccount]::new($principal).Translate(
       [Security.Principal.SecurityIdentifier]).Value
  return ($sid -ceq [string]$c.ownerSid)
 }catch [Security.Principal.IdentityNotMappedException] {
  return $false
 }
}
function Test-R993OwnedAction([object]$task,[object]$c,[string]$script,[string]$config) {
 $exe=Join-Path $PSHOME 'pwsh.exe'
 $args='-NoLogo -NoProfile -NonInteractive -File "'+$script+'" -Mode Recover -Config "'+$config+'"'
 return (Test-R993OwnerPrincipal ([string]$task.Principal.UserId) $c) -and
        [string]$task.Principal.LogonType -ceq 'S4U' -and
        [string]$task.Principal.RunLevel -ceq 'Highest' -and
        @($task.Actions).Count -eq 1 -and
        [string]$task.Actions[0].Execute -ieq $exe -and
        [string]$task.Actions[0].Arguments -ceq $args -and
        @($task.Triggers).Count -eq 1
}
function Check-R993Config {
 Need ([IO.Path]::IsPathFullyQualified($Config) -and
        [IO.Path]::GetFullPath($Config) -ceq $Config -and
        [IO.Path]::GetFileName($Config) -ceq 'R993RecoveryConfig.json' -and
        [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($Config)) -ceq 'UpdateTransactions') 'R993_BAD_CONFIG_LEAF'
 $cFile=Get-Item -LiteralPath $Config -ErrorAction Stop
 Need (!$cFile.PSIsContainer -and $cFile.Length -gt 100 -and $cFile.Length -le 8192 -and
        ($cFile.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'R993_CONFIG_NOT_BOUND'
 $c=Get-Content -LiteralPath $Config -Raw|ConvertFrom-Json
 Assert-R993Identity $c
 Need ((Split-Path -Leaf $c.workspace) -ceq 'DirectInternetMethod' -or
        (Test-Path -LiteralPath (Join-Path $c.workspace '.git'))) 'R993_WORKSPACE_UNRESOLVED'
 Need ([IO.Path]::IsPathFullyQualified([string]$c.runnerTemp) -and
        [IO.Path]::IsPathFullyQualified([string]$c.workspace) -and
        [IO.Path]::IsPathFullyQualified([string]$c.python) -and
        [IO.Path]::IsPathFullyQualified([string]$c.localAppData)) 'R993_PATHS_MISSING'
 # R993_PROTECTED_HARNESS: the task action lives in the protected product store.
 $folder=Split-Path -Parent $Config
 $product=[IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'DirectInternetMethod\Privileged\UpdateTransactions'))
 Need ($folder -ieq $product) 'R993_CONFIG_NOT_PRODUCT_PROTECTED_ROOT'
 return $c
}
$c=Check-R993Config
$folder=Split-Path -Parent $Config
$script=Join-Path $folder 'R993ProtectedRecoveryHarness.ps1'
$source=Join-Path $c.workspace 'tests\r993_windows_os_scheduled_recovery_vm.ps1'
$pythonScript=Join-Path $c.workspace 'tests\r982_windows_real_native_compensation_vm.py'
function Verify-ScriptPins {
 Need ((Test-Path -LiteralPath $script -PathType Leaf) -and
       ((Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash -ieq $c.scriptSha) -and
       ((Get-FileHash -LiteralPath $pythonScript -Algorithm SHA256).Hash -ieq $c.pythonScriptSha)) 'R993_FIXED_ACTION_ONLY'
}
if($Mode -ceq 'Register'){
 Need ($env:CI -ceq 'true' -and $env:GITHUB_ACTIONS -ceq 'true' -and
       $env:RUNNER_ENVIRONMENT -ceq 'github-hosted' -and
       $env:GITHUB_REPOSITORY -ceq 'GOD13emad/DirectInternetMethod' -and
       $env:GITHUB_EVENT_NAME -ceq 'workflow_dispatch' -and
       $env:GITHUB_REF -ceq 'refs/heads/feature/universal-install-engine' -and
       $env:GITHUB_SHA -ceq $c.source -and
       (git -C $c.workspace rev-parse HEAD).Trim() -ceq $c.source -and
       $env:R993_OS_SCHEDULED_RECOVERY -ceq 'true' -and
       $env:R992_PROTECTED_RECOVERY_MEDIA -ceq 'true') 'R993_REVIEWED_HOST_ONLY'
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $principal=[Security.Principal.WindowsPrincipal]::new($identity)
 Need ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -and
       $identity.User.Value -ceq $c.ownerSid -and
       $identity.Name -ieq $c.ownerName) 'R993_APPROVED_OWNER_TOKEN_REQUIRED'
 Need (!(Get-ScheduledTask -TaskName $c.taskName -ErrorAction SilentlyContinue) -and
       !(Test-Path -LiteralPath $script)) 'R993_TASK_OR_SCRIPT_ALREADY_EXISTS'
 Need ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ieq $c.scriptSha -and
       (Get-FileHash -LiteralPath $pythonScript -Algorithm SHA256).Hash -ieq $c.pythonScriptSha) 'R993_SOURCE_PINS'
 $src=[IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 $dest=$null
 try {
  $dest=[IO.File]::Open($script,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  $src.CopyTo($dest)
  $dest.Flush($true)
 } finally {
  if($null -ne $dest){$dest.Dispose()}
  $src.Dispose()
 }
 Verify-ScriptPins
 $exe=Join-Path $PSHOME 'pwsh.exe'
 Need (Test-Path -LiteralPath $exe -PathType Leaf) 'R993_PWSH_BINARY_MISSING'
 $action=New-ScheduledTaskAction -Execute $exe -Argument ('-NoLogo -NoProfile -NonInteractive -File "'+$script+'" -Mode Recover -Config "'+$Config+'"')
 $trigger=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddSeconds(45))
 # Inno per-user shell folders must remain tied to the target SID;
 # S4U stores no password and has no network access. VM-only fixture.
 $account=New-ScheduledTaskPrincipal -UserId ([string]$c.ownerName) -LogonType S4U -RunLevel Highest
 $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew -StartWhenAvailable
 Register-ScheduledTask -TaskName $c.taskName -Action $action -Trigger $trigger -Principal $account -Settings $settings -Description 'VM-only R993 observed common broker recovery; never production' -ErrorAction Stop|Out-Null
 Need (Test-R993OwnerPrincipal ([string](Get-ScheduledTask -TaskName $c.taskName).Principal.UserId) $c) 'R993_TASK_NOT_OWNER'
 Write-Output ('R993_TASK_CREATED '+$c.taskName)
 exit 0
}
if($Mode -ceq 'Recover'){
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 Need ($identity.User.Value -ceq $c.ownerSid -and
       $identity.User.Value -cne 'S-1-5-18') 'R993_NOT_APPROVED_OWNER_CONTEXT'
 Verify-ScriptPins
 $env:CI='true'
 $env:GITHUB_ACTIONS='true'
 $env:RUNNER_ENVIRONMENT='github-hosted'
 $env:GITHUB_REPOSITORY='GOD13emad/DirectInternetMethod'
 $env:GITHUB_EVENT_NAME='workflow_dispatch'
 $env:GITHUB_REF='refs/heads/feature/universal-install-engine'
 $env:GITHUB_SHA=[string]$c.source
 $env:GITHUB_WORKSPACE=[string]$c.workspace
 $env:RUNNER_TEMP=[string]$c.runnerTemp
 $env:LOCALAPPDATA=[string]$c.localAppData
 $env:R980_EXPECTED_SHA=[string]$c.source
 $env:R982_EXPECTED_SHA=[string]$c.source
 $env:R983_CRASH_RECOVERY='true'
 $env:R984_NATIVE_PREIMAGE='true'
 $env:R992_PROTECTED_RECOVERY_MEDIA='true'
 $env:R993_OS_SCHEDULED_RECOVERY='true'
 & ([string]$c.python) $pythonScript '--r986-recover' ([string]$c.name) ([string]$c.dispatchPin)
 $code=[int]$LASTEXITCODE
 $base=Join-Path (Join-Path $c.runnerTemp 'DIM_R980_REAL_POSTFAIL') $c.name
 $receipt=Join-Path $base 'r993-system-task-receipt.json'
 if(Test-Path -LiteralPath $receipt){throw 'R993_SYSTEM_RECEIPT_REPLAY'}
 $record=[ordered]@{schema=1;source=$c.source;taskName=$c.taskName;sid=$identity.User.Value;launcherPid=$PID;workerExit=$code;dispatchPin=$c.dispatchPin;action='R986_COMMON_RECOVER_BY_OS_TASK_S4U'}
 [IO.File]::WriteAllText($receipt,($record|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
 if($code -ne 0){throw ('R993_WORKER_FAILURE_'+$code)}
 Write-Output 'R993_SCHEDULED_OS_RECEIPT_VERIFIED'
 exit 0
}
if($Mode -ceq 'Inspect'){
 $task=Get-ScheduledTask -TaskName $c.taskName -ErrorAction Stop
 Verify-ScriptPins
 Need (Test-R993OwnedAction $task $c $script $Config) 'R993_FIXED_ACTION_ONLY'
 $info=Get-ScheduledTaskInfo -TaskName $c.taskName
 [ordered]@{task=$c.taskName;identity=$c.ownerSid;logonType=[string]$task.Principal.LogonType;runLevel=[string]$task.Principal.RunLevel;state=[string]$task.State;lastTaskResult=[int]$info.LastTaskResult;lastRunTime=$info.LastRunTime.ToString('o');lastTrigger=$task.Triggers[0].StartBoundary}|ConvertTo-Json -Compress
 Write-Output 'R993_TASK_STATUS'
 exit 0
}
if($Mode -ceq 'Remove'){
 $task=Get-ScheduledTask -TaskName $c.taskName -ErrorAction SilentlyContinue
 if($null -ne $task){
  Need (Test-R993OwnedAction $task $c $script $Config) 'R993_REFUSE_FOREIGN_TASK'
  Unregister-ScheduledTask -TaskName $c.taskName -Confirm:$false -ErrorAction Stop
 }
 if(Test-Path -LiteralPath $script){
  Verify-ScriptPins
  [IO.File]::Delete($script)
 }
 if(Test-Path -LiteralPath $Config){[IO.File]::Delete($Config)}
 Write-Output 'R993_TASK_OWNED_CLEANUP_PASS'
 exit 0
}
throw 'R993_UNKNOWN_MODE'
