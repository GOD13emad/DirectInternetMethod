# R937 Windows Sandbox guest-only OS SCM fixture. No host product service.
# "setup/restart/finalize" require NT AUTHORITY\SYSTEM.
# "client-*" run in a separate SYSTEM-launched process that restricts
# its own thread token with Windows CreateRestrictedToken before pipe I/O.
# This is NOT evidence of a real distinct non-SYSTEM Windows login.
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('setup','client-good','client-tampered','client-replay',
                 'restart','client-replay-postrestart','finalize')]
    [string]$Phase
)
$ErrorActionPreference='Stop'
$Name='DIMR937BrokerFixtureSvc'
$Root='C:\ProgramData\DIM_R937_ScmBrokerReceiptFixture'
$In='C:\DIMR937\input'
$Out='C:\DIMR937\output'
$Binary=Join-Path $Root 'R937NativeScmReceiptFixture.exe'
$Receipt=Join-Path $Root 'native-completed-receipt.json'
$Ledger=Join-Path $Root 'broker-replay.json'
$Ready=Join-Path $Root 'ready.txt'
$PinsFile=Join-Path $In 'pins.json'
$Proof=Join-Path $Out ('R937_'+$Phase+'.json')
$Identity=[Security.Principal.WindowsIdentity]::GetCurrent()
function Must([bool]$ok,[string]$reason) {if(-not $ok){throw $reason}}
function Sha([string]$file) {return (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()}
function Invoke-R937SCM([string[]]$words) {
    $result=& "$env:WINDIR\System32\sc.exe" @words 2>&1 | Out-String
    Must ($LASTEXITCODE -eq 0) ('R937_SCM_'+$words[0]+'_FAILED_'+$LASTEXITCODE+'_'+$result.Trim())
}
function State([string]$wanted) {
    for($i=0;$i -lt 60;$i++) {
        $svc=Get-CimInstance Win32_Service -Filter "Name = '$Name'" -ErrorAction SilentlyContinue
        if($null -ne $svc -and [string]$svc.State -eq $wanted) {return $svc}
        Start-Sleep -Milliseconds 300
    }
    throw ('R937_SCM_WAIT_STATE_TIMEOUT_'+$wanted)
}
function Running {
    $svc=State 'Running'
    Must ($svc.ProcessId -gt 0 -and $svc.StartName -eq 'LocalSystem' -and
          $svc.PathName.Trim('"') -eq $Binary) 'R937_SCM_PID_OR_BINARY_IDENTITY_FAILED'
    for($i=0;$i -lt 40;$i++) {
        if((Test-Path $Ready) -and ((Get-Content $Ready -Raw).Trim() -eq [string]$svc.ProcessId)) {return $svc}
        Start-Sleep -Milliseconds 250
    }
    throw 'R937_NATIVE_SCM_WORKER_NOT_READY_WITH_PID'
}
function NativeAcl {
    $acl=Get-Acl -LiteralPath $Root
    Must ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-18') 'R937_STORE_OWNER_NOT_SYSTEM'
    $writers=@('S-1-5-18','S-1-5-32-544')
    $mask=[Security.AccessControl.FileSystemRights]::Write
    $mask=$mask -bor [Security.AccessControl.FileSystemRights]::Delete
    $mask=$mask -bor [Security.AccessControl.FileSystemRights]::ChangePermissions
    $mask=$mask -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if($ace.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
           ($ace.FileSystemRights -band $mask) -ne 0 -and
           $ace.IdentityReference.Value -notin $writers){
            throw ('R937_UNTRUSTED_FILE_WRITER_ACE_'+$ace.IdentityReference.Value)
        }
    }
    return $true
}
function TokenCheck([bool]$system) {
    Must (($Identity.User.Value -eq 'S-1-5-18') -eq $system) ('R937_OS_TOKEN_WRONG_ROLE_'+$Phase)
}
function NativePins {
    $p=Get-Content $PinsFile -Raw|ConvertFrom-Json
    Must ($p.schema -eq 1 -and $p.scope -eq 'R937_SYNTHETIC_SCM_RECEIPT_ONLY' -and
          $p.service_name -eq $Name) 'R937_TEST_ONLY_PIN_SCHEMA_INVALID'
    foreach($row in @(@('R937NativeScmReceiptFixture.exe',$p.exe_sha256),
                       @('broker-request.json',$p.request_sha256),
                       @('broker-policy.json',$p.policy_sha256),
                       @('native-intent.json',$p.native_intent_sha256),
                       @('broker-replay-initial.json',$p.ledger_initial_sha256))) {
        Must ((Sha (Join-Path $In $row[0])) -eq $row[1]) ('R937_PREBUILT_INPUT_SHA_CHANGED_'+$row[0])
    }
    return $p
}
Must (Test-Path 'C:\Users\WDAGUtilityAccount') 'R937_OFFLINE_SANDBOX_ONLY'
Must ((Test-Path $In) -and (Test-Path $Out)) 'R937_SANDBOX_MOUNT_MISSING'
Must (-not (Get-Service 'DirectInternetMethodSvc' -ErrorAction SilentlyContinue)) 'R937_REAL_PRODUCT_SERVICE_IN_GUEST_REFUSE'
Must (-not (Test-Path $Proof)) 'R937_PHASE_REPORT_ALREADY_EXISTS'
$report=$null
try {
    if($Phase -eq 'setup') {
        TokenCheck $true
        Must (-not (Test-Path $Root)) 'R937_GUEST_ROOT_PREEXISTS'
        Must (-not (Get-Service $Name -ErrorAction SilentlyContinue)) 'R937_TEST_SERVICE_PREEXISTS'
        $pins=NativePins
        [IO.Directory]::CreateDirectory($Root)|Out-Null
        & "$env:WINDIR\System32\icacls.exe" $Root '/inheritance:r'|Out-Null
        Must ($LASTEXITCODE -eq 0) 'R937_NTFS_INHERITANCE_DISABLE_FAILED'
        & "$env:WINDIR\System32\icacls.exe" $Root '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)R'|Out-Null
        Must ($LASTEXITCODE -eq 0) 'R937_NTFS_PROTECTED_DIRECTORY_ACL_FAILED'
        Must (NativeAcl) 'R937_NTFS_ROOT_ACL_INVALID'
        foreach($pair in @(@('R937NativeScmReceiptFixture.exe','R937NativeScmReceiptFixture.exe'),
                           @('pins.json','pins.json'),
                           @('broker-request.json','broker-request.json'),
                           @('broker-policy.json','broker-policy.json'),
                           @('native-intent.json','native-intent.json'),
                           @('broker-replay-initial.json','broker-replay.json'))) {
            $target=Join-Path $Root $pair[1]
            Must (-not (Test-Path $target)) ('R937_OS_SYSTEM_COPY_ALREADY_PRESENT_'+$pair[1])
            Copy-Item -LiteralPath (Join-Path $In $pair[0]) -Destination $target
        }
        Must ((Sha $Binary) -eq $pins.exe_sha256 -and
              (Sha $Ledger) -eq $pins.ledger_initial_sha256) 'R937_OS_PROTECTED_COPY_DRIFT'
        [IO.File]::WriteAllBytes((Join-Path $Root 'owner-data.txt'),
                               [Text.Encoding]::UTF8.GetBytes('R937_SYNTHETIC_USER_DATA_KEEP'))
        $ownerHash=Sha (Join-Path $Root 'owner-data.txt')
        Invoke-R937SCM @('create',$Name,'binPath=',$Binary,'start=','demand','obj=','LocalSystem',
             'DisplayName=','DIM R937 Isolated SCM Receipt Broker')
        Invoke-R937SCM @('start',$Name)
        $svc=Running
        $report=[ordered]@{
           schema=1;status='PASS_R937_REAL_SCM_SYSTEM_BROKER_READY_ONLY'
           service_pid=$svc.ProcessId
           protected_root_system_owned=$true
           service_executable_sha256=$pins.exe_sha256
           owner_data_sha256=$ownerHash
           native_product_installation_accepted=$false
           publisher_authenticated=$false
        }
    } elseif($Phase.StartsWith('client-')) {
        TokenCheck $true
        $pins=NativePins
        $mode=if($Phase -eq 'client-good'){'good'}elseif($Phase -eq 'client-tampered'){'tampered'}else{'replay'}
        $name=$Phase.Replace('client-','')
        $stdout=Join-Path $Out ('R937_client_'+$name+'.stdout.log')
        $stderr=Join-Path $Out ('R937_client_'+$name+'.stderr.log')
        $cmd=Join-Path $In 'R937NativeScmReceiptFixture.exe'
        $process=Start-Process -FilePath $cmd -ArgumentList @('--client',$mode) -PassThru -Wait -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden
        Must ($process.ExitCode -eq 0) ('R937_DIFFERENT_USER_CLIENT_EXIT_'+$process.ExitCode+'_'+(Get-Content $stderr -Raw))
        $raw=Get-Content $stdout -Raw|ConvertFrom-Json
        Must ($raw.status -eq 'PASS_R937_DIFFERENT_PROCESS_NATIVE_RESTRICTED_CLIENT' -and
              $raw.mode -eq $mode -and
              $raw.token_owner_sid -eq 'S-1-5-18' -and
              $raw.OS_restricted_client_token_verified -eq $true -and
              $raw.separate_real_non_system_login_verified -eq $false -and
              $raw.protected_receipt_forgery_denied -eq $true -and
              $raw.native_product_installation_accepted -eq $false) 'R937_CLIENT_OS_RESTRICTION_OR_DENIAL_NOT_VERIFIED'
        if($mode -eq 'good') {
            Must ($raw.native_scm_owned_broker_result -eq 'COMPLETED_SYNTHETIC_SCM_POSTFLIGHT') 'R937_CLIENT_POSTFLIGHT_RECEIPT_MISSING'
        } elseif($mode -eq 'tampered') {
            Must ($raw.rejection_reason -eq 'R937_REQUEST_SHA_MISMATCH') 'R937_CLIENT_TAMPER_NOT_DENIED'
        }else{
            Must ($raw.rejection_reason -eq 'R937_REQUEST_REPLAY_DENIED') 'R937_CLIENT_REPLAY_NOT_DENIED'
        }
        $report=[ordered]@{
           schema=1;status='PASS_R937_DIFFERENT_PROCESS_OS_RESTRICTED_CLIENT'
           mode=$mode
           client_pid=$raw.independent_client_process_id
           client_launcher_system_sid=$raw.token_owner_sid
           native_restricted_client_token_verified=$true
           real_non_system_login_verified=$false
           restricted_write_denied=$true
           rpc_result=$raw.native_scm_owned_broker_result
           rejection_reason=$raw.rejection_reason
           native_product_installation_accepted=$false
        }
    } elseif($Phase -eq 'restart') {
        TokenCheck $true
        $p=NativePins
        $before=Sha $Receipt
        $ledgerState=Get-Content $Ledger -Raw|ConvertFrom-Json
        Must ($null -eq $ledgerState.active -and
              @($ledgerState.used_request_ids).Count -eq 1 -and
              $ledgerState.used_request_ids[0] -eq $p.request_id) 'R937_INITIAL_COMPLETED_LEDGER_NOT_DURABLE'
        $old=Running
        Invoke-R937SCM @('stop',$Name)
        State 'Stopped'|Out-Null
        Invoke-R937SCM @('start',$Name)
        $new=Running
        Must ((Sha $Receipt) -eq $before) 'R937_SERVICE_RESTART_MUTATED_COMPLETION_RECEIPT'
        $report=[ordered]@{
          schema=1;status='PASS_R937_REAL_SCM_STOP_RESTART_LEDGER_PRESERVED'
          original_service_pid=$old.ProcessId
          restarted_service_pid=$new.ProcessId
          before_receipt_sha256=$before
          after_receipt_sha256=(Sha $Receipt)
          native_product_installation_accepted=$false
        }
    } else {
        TokenCheck $true
        $p=NativePins
        $svc=Running
        $ledgerState=Get-Content $Ledger -Raw|ConvertFrom-Json
        Must ($ledgerState.schema -eq 1 -and
              $ledgerState.platform -eq 'windows-x86_64' -and
              $null -eq $ledgerState.active -and
              @($ledgerState.used_request_ids).Count -eq 1 -and
              $ledgerState.used_request_ids[0] -eq $p.request_id) 'R937_REPLAY_LEDGER_NOT_FINAL'
        $receiptJson=Get-Content $Receipt -Raw|ConvertFrom-Json
        Must ($receiptJson.schema -eq 1 -and $receiptJson.status -eq 'completed' -and
              $receiptJson.intent_sha256 -eq $p.native_receipt_intent_sha256) 'R937_R926_MATCHED_RECEIPT_ABSENT'
        Must (NativeAcl) 'R937_PROTECTED_ACL_CHANGED'
        Must ((Sha (Join-Path $Root 'owner-data.txt')) -eq
              (Get-Content (Join-Path $Out 'R937_setup.json') -Raw|ConvertFrom-Json).owner_data_sha256) 'R937_OWNER_DATA_MODIFIED'
        Must (-not (Test-Path (Join-Path $Root 'untrusted-forged-receipt.json'))) 'R937_FORGED_RECEIPT_FILE_PRESENT'
        Must ((Sha (Join-Path $Root 'broker-request.json')) -eq $p.request_sha256 -and
              (Sha (Join-Path $Root 'native-intent.json')) -eq $p.native_intent_sha256) 'R937_OS_TRUSTED_INPUT_CHANGED'
        foreach($copy in @(@($Receipt,'R937_SCMSERVICE_NATIVE_RECEIPT.json'),
                            @($Ledger,'R937_SCMSERVICE_REPLAY_LEDGER.json'),
                            @((Join-Path $Root 'native-intent.json'),'R937_NATIVE_INTENT.json'))) {
            $dst=Join-Path $Out $copy[1]
            Must (-not (Test-Path $dst)) ('R937_RAW_EVIDENCE_ALREADY_COPIED_'+$copy[1])
            Copy-Item -LiteralPath $copy[0] -Destination $dst
            Must ((Sha $dst) -eq (Sha $copy[0])) 'R937_RAW_BROKER_EVIDENCE_CHANGED'
        }
        Invoke-R937SCM @('stop',$Name)
        State 'Stopped'|Out-Null
        Invoke-R937SCM @('delete',$Name)
        for($i=0;$i -lt 60;$i++){
            if($null -eq (Get-CimInstance Win32_Service -Filter "Name = '$Name'" -ErrorAction SilentlyContinue)){break}
            Start-Sleep -Milliseconds 300
        }
        Must ($null -eq (Get-CimInstance Win32_Service -Filter "Name = '$Name'" -ErrorAction SilentlyContinue)) 'R937_SYNTHETIC_SERVICE_NOT_UNREGISTERED'
        $report=[ordered]@{
           schema=1;status='PASS_R937_REAL_SYSTEM_SCM_BROKER_REPLAY_AND_RECEIPT_SYNTHETIC_ONLY'
           service_name=$Name
           running_scm_pid_at_completion=$svc.ProcessId
           actual_different_os_processes_restricted_client=$true
           real_non_system_login_verified=$false
           OS_system_protected_replay_writer_fixture=$true
           R899_exact_request_reused=$true
           R901_replay_ledger_finalized_no_second_request=$true
           R926_native_completion_receipt_synthetic=$true
           service_restarted_and_replay_denied=$true
           owner_data_preserved=$true
           service_unregistered=$true
           native_receipt_sha256=(Sha (Join-Path $Out 'R937_SCMSERVICE_NATIVE_RECEIPT.json'))
           replay_ledger_sha256=(Sha (Join-Path $Out 'R937_SCMSERVICE_REPLAY_LEDGER.json'))
           native_product_installation_accepted=$false
           production_privileged_broker_implemented=$false
           publisher_authenticated=$false
           hard_powercut_reboot_accepted=$false
           real_two_scope_app_upgrade_accepted=$false
        }
    }
} catch {
    $report=[ordered]@{
       schema=1;status='FAIL_CLOSED_R937_NATIVE_SCM_FIXTURE'
       phase=$Phase;reason=$_.Exception.Message
       native_product_installation_accepted=$false
    }
} finally {
    if(Test-Path $Out){
        $report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $Proof -Encoding utf8
    }
}
if($report.status -like 'FAIL_CLOSED*'){throw $report.reason}
Write-Output ($report|ConvertTo-Json -Compress -Depth 8)
