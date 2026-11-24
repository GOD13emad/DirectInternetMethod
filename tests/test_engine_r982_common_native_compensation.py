"""R982 source guards: genuine hosted Inno restore through the SAME shared broker fixture.

No installed system or native installer is exercised by these local tests.
"""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
VM=ROOT/"tests/r982_windows_real_native_compensation_vm.py"
R980=ROOT/"tests/r980_windows_real_product_postfailure_vm.ps1"
CI=ROOT/".github/workflows/ci.yml"
ENGINE=ROOT/"installer_engine/universal_install.py"

class R982CommonBrokerNativeScope(unittest.TestCase):
    def test_real_windows_fixture_is_hard_denied_on_unreviewed_host(self):
        result=subprocess.run([sys.executable,str(VM)],
                              cwd=ROOT,capture_output=True,text=True,timeout=8)
        self.assertNotEqual(result.returncode,0)
        self.assertIn("R982_DISPOSABLE_REVIEWED_VM_ONLY",
                      result.stdout+result.stderr)

    def test_r981_common_broker_consumes_real_native_adapter_not_new_installer(self):
        src=VM.read_text("utf-8")
        for s in ("UniversalFixtureInstaller","BrokerReplayFixtureLedger",
                  "execute_broker_bound", "R982_RECOVERY_ASSET_SHA_MISMATCH",
                  "RealInnoVmAdapter","observed_version","def restore(",
                  "restored","R982_REAL_INNO_FAILED_OLD_RESTORED_VIA_COMMON_BROKER",
                  "publisher_authenticated", "native_production_broker_accepted"):
            self.assertIn(s,src)
        self.assertNotIn("shell=True",src)
        self.assertIn("UNIVERSAL_BROKER_NATIVE_FAILURE_AUTO_ABORTED_FIXTURE_ONLY",
                      ENGINE.read_text("utf-8"))

    def test_existing_original_r980_experiment_preserved_and_optin_r982(self):
        src=R980.read_text("utf-8-sig")
        for s in ("param([switch]$CommonBrokerRecovery)",
                  "R982_EXPECTED_SHA", "R982_DISPOSABLE_REVIEWED_VM_ONLY",
                  "tests/r982_windows_real_native_compensation_vm.py",
                  "R982_REAL_NATIVE_BROKER_VM_RESULT.json",
                  "PASS_R982_REAL_PRODUCT_NATIVE_COMPENSATION_VM_ONLY",
                  "if(-not $CommonBrokerRecovery)"):
            self.assertIn(s,src)
        self.assertIn("EXPLICIT_PINNED_OLD_SETUP_REINSTALL",src)
        self.assertIn("PASS_REAL_PRODUCT_INNO_POSTINSTALL_FAILURE_REQUIRES_EXTERNAL_RECOVERY",src)
        self.assertIn("nativeAutomaticRollbackAccepted=$false",src)

    def test_vm_final_exit_condition_accepts_only_matching_mode_success(self):
        source=R980.read_text("utf-8-sig")
        self.assertIn("$expectedStatus=if($CommonBrokerRecovery){", source)
        self.assertIn("'PASS_R982_REAL_PRODUCT_NATIVE_COMPENSATION_VM_ONLY'", source)
        self.assertIn("if($observed.status -cne $expectedStatus){exit 31}", source)
        self.assertIn("if($CommonBrokerRecovery){", source)
        self.assertIn("nativeAutomaticRollbackAccepted=$false", source)

    def test_crash_recovery_is_separate_reviewed_vm_mode(self):
        source=VM.read_text("utf-8")
        workflow=CI.read_text("utf-8")
        for marker in ("R983_CRASH_RECOVERY", "--r983-child",
                       "os._exit(79)", "recover_broker_bound",
                       "R983_CHILD_DID_NOT_EXIT_AT_NATIVE_FAILURE",
                       "R983_PERSISTED_INTENT_DRIFT",
                       "R983_REAL_NATIVE_CHILD_EXIT_RESTORED"):
            self.assertIn(marker,source)
        self.assertIn("native_broker_crash_recovery:",workflow)
        self.assertIn("R983_CRASH_RECOVERY:",workflow)
        self.assertIn("default: false",workflow)

    def test_crash_observation_rejects_wrong_identity_and_bytes(self):
        from tests import r982_windows_real_native_compensation_vm as vm
        from installer_engine.engine import EngineError
        identity = "a" * 64
        cfg = {"new_gui": "B" * 64, "new_service": "C" * 64,
               "failed_setup_sha": "D" * 64}
        observation = {"schema": 1, "intent_sha256": identity,
                       "failed_setup_sha": cfg["failed_setup_sha"],
                       "registered_version": "1.5.7",
                       "gui_sha256": cfg["new_gui"],
                       "service_sha256": cfg["new_service"],
                       "installer_exit_code": 67}
        self.assertEqual(vm._validate_crash_observation(
            observation, identity, cfg), observation)
        for key, wrong in (("intent_sha256", "f"*64),
                           ("failed_setup_sha", "E"*64),
                           ("gui_sha256", "A"*64),
                           ("service_sha256", "A"*64),
                           ("registered_version", "1.5.4"),
                           ("installer_exit_code", 0),
                           ("schema", True)):
            with self.subTest(key=key):
                with self.assertRaisesRegex(EngineError,"R983_CRASH_OBSERVATION_INVALID"):
                    vm._validate_crash_observation(
                        dict(observation, **{key: wrong}), identity, cfg)

    def test_r986_recovery_worker_is_fresh_process_and_bound_to_disk(self):
        source=VM.read_text("utf-8")
        for marker in ("--r986-recover", "def _run_recovery_worker(",
                       "R986_DISPATCH_PIN_MISMATCH", "r986-recovery.json",
                       "R986_RECOVERY_WORKER_REPLAY_DENIED",
                       "R986_FRESH_RECOVERY_PROCESS_CONFIRMED"):
            self.assertIn(marker,source)
        self.assertIn("R986_FRESH_RECOVERY_PROCESS_CONFIRMED",
                      R980.read_text("utf-8-sig"))

    def test_r986_disk_dispatch_pin_and_worker_replay_fail_before_native(self):
        import hashlib
        import json
        import tempfile
        from unittest.mock import patch
        from tests import r982_windows_real_native_compensation_vm as vm
        from installer_engine.engine import EngineError
        with tempfile.TemporaryDirectory() as td:
            qa = Path(td)
            base = qa / "dim-universal-r986"
            base.mkdir()
            policy = b'{}'
            payload = {"platform": "windows-x86_64",
                       "product": "Direct Internet Method", "version": "1.5.7",
                       "scopes": [], "pb": policy.hex(), "rb": "7b7d",
                       "pin": hashlib.sha256(policy).hexdigest(), "intent": {},
                       "sources": {name: [f"bundle-{name}-1.5.7", "a"*64]
                                   for name in ("protected", "user")}}
            raw = json.dumps(payload).encode()
            path = base / "r983-dispatch.json"
            path.write_bytes(raw)
            pin = hashlib.sha256(raw).hexdigest()
            self.assertEqual(vm._read_crash_dispatch(qa, base.name, pin)[0], base)
            path.write_bytes(raw + b" ")
            with self.assertRaisesRegex(EngineError, "R986_DISPATCH_PIN_MISMATCH"):
                vm._read_crash_dispatch(qa, base.name, pin)
            path.write_bytes(raw)
            (base / "r986-recovery.json").write_text("existing", encoding="utf-8")
            with patch.object(vm, "RealInnoVmAdapter") as native:
                with self.assertRaisesRegex(EngineError, "R986_RECOVERY_WORKER_REPLAY_DENIED"):
                    vm._run_recovery_worker(qa, {}, base.name, pin)
                native.assert_not_called()

    def test_r984_opt_in_native_metadata_and_held_media_gate(self):
        source=R980.read_text("utf-8-sig")
        workflow=CI.read_text("utf-8")
        for marker in ("R984_NATIVE_PREIMAGE", "Get-R984NativePreimage",
                       "Compare-R984NativePreimage", "Win32_Service",
                       "Get-Acl -LiteralPath", "sdshow",
                       "[IO.FileShare]::Read",
                       "R984_HELD_OLD_SETUP_WRITE_DENIED",
                       "R984_HELD_OLD_SETUP_SHA_UNCHANGED",
                       "R984_SELECTED_NATIVE_PREIMAGE_EQUAL",
                       "R984_NATIVE_METADATA_OBSERVED_NOT_FULL_PREIMAGE"):
            self.assertIn(marker, source)
        self.assertIn("native_broker_native_preimage:", workflow)
        self.assertIn("R984_NATIVE_PREIMAGE:", workflow)

    def test_r994_os_task_survives_registrar_crash_mode_gated(self):
        vm = VM.read_text("utf-8")
        ps = R980.read_text("utf-8-sig")
        ci = CI.read_text("utf-8")
        for token in ("R994_REGISTRAR_EXIT", "--r994-register-exit",
                      "R994_REGISTRAR_DIED_BEFORE_OS_TRIGGER",
                      "R994_OS_TASK_RECOVERY_AFTER_REGISTRAR_EXIT",
                      "def _run_r994_registrar_exit("):
            self.assertIn(token, vm)
        for token in ("R994_REGISTRAR_EXIT",
                      "R994_REAL_NATIVE_REGISTRAR_EXIT_RECOVERY"):
            self.assertIn(token, ps)
        self.assertIn("native_broker_registrar_exit:", ci)
        self.assertIn("R994_REGISTRAR_EXIT:", ci)
        self.assertNotIn("Start-ScheduledTask", (
            ROOT / "tests/r993_windows_os_scheduled_recovery_vm.ps1"
        ).read_text("utf-8-sig"))

    def test_r993_os_scheduled_native_recovery_requires_exact_vm_mode(self):
        vm=VM.read_text("utf-8")
        ps=R980.read_text("utf-8-sig")
        ci=CI.read_text("utf-8")
        scheduler=(ROOT/"tests/r993_windows_os_scheduled_recovery_vm.ps1")
        self.assertTrue(scheduler.is_file())
        task=scheduler.read_text("utf-8-sig")
        for marker in ("R993_OS_SCHEDULED_RECOVERY", "def _run_os_scheduled_recovery(",
                       "R993_SCHEDULED_OS_RECEIPT_VERIFIED",
                       "R993_OS_TASK_NOT_SAME_AS_OBSERVER"):
            self.assertIn(marker,vm)
        for marker in ("R993_OS_SCHEDULED_RECOVERY",
                       "R993_REAL_NATIVE_OS_SCHEDULED_RECOVERY",
                       "R993_REQUIRES_R992_PROTECTED_MEDIA"):
            self.assertIn(marker,ps)
        for marker in ("Register-ScheduledTask", "New-ScheduledTaskTrigger",
                       "New-ScheduledTaskPrincipal", "S-1-5-18",
                       "R993_TASK_CREATED", "R993_TASK_STATUS",
                       "Unregister-ScheduledTask", "R993_PROTECTED_HARNESS",
                       "R993_FIXED_ACTION_ONLY"):
            self.assertIn(marker,task)
        self.assertNotIn("Start-ScheduledTask",task)
        self.assertIn("native_broker_os_scheduled_recovery:",ci)
        self.assertIn("R993_OS_SCHEDULED_RECOVERY:",ci)

    @unittest.skipUnless(sys.platform == "win32", "PowerShell native identity validator needs Windows")
    def test_r993_windows_actual_powershell_temp_identity_and_negatives(self):
        path = ROOT / "tests/r993_windows_os_scheduled_recovery_vm.ps1"
        command = "$p='" + str(path).replace("'", "''") + "';" + r"""
$ErrorActionPreference='Stop'
$t=$null;$err=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$t,[ref]$err)
if($err.Count){throw 'PS_PARSE'}
foreach($name in @('Need','Hex','Assert-R993Identity')){
  $nodes=@($ast.FindAll({param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name
  },$true))
  if($nodes.Count -ne 1){throw ('FUNCTION_'+$name)}
  . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$sha='a'*40
$obj=[pscustomobject]@{
  schema=1;source=$sha;dispatchPin='b'*64;scriptSha='c'*64;pythonScriptSha='d'*64;
  name='dim-universal-test_ab12';taskName=('DIMR993VM-'+$sha.Substring(0,12));
  ownerSid='S-1-5-21-3414932011-3134797172-3625386099-513';
  ownerName='RUNNER\runneradmin'
}
if(($obj.name -cmatch '^dim-universal-[0-9a-zA-Z-]+$') -or
   !($obj.name -cmatch '^dim-universal-[a-zA-Z0-9_-]+$')){throw 'ROOT_NOT_REPRODUCED'}
Assert-R993Identity $obj
foreach($case in @(
  @('name','dim-universal-test/../bad','R993_TEMP_BASE_NAME_DRIFT'),
  @('name','dim-universal','R993_TEMP_BASE_NAME_DRIFT'),
  @('ownerSid','S-1-5-18','R993_OWNER_SID_DRIFT'),
  @('scriptSha',('z'*64),'R993_SCRIPT_PIN_DRIFT'),
  @('taskName','DIMR993VM-another','R993_TASK_NAME_DRIFT')
)){
  $copy=($obj|ConvertTo-Json -Compress|ConvertFrom-Json)
  $copy.PSObject.Properties[$case[0]].Value=$case[1]
  $denied=$false
  try{Assert-R993Identity $copy}
  catch{$denied=$_.Exception.Message -ceq $case[2]}
  if(!$denied){throw ('NEGATIVE_MISSED_'+$case[0])}
}
'R993_WIN32_TEMPFILE_UNDERSCORE_AND_5_NEGATIVE_PASS'
"""
        result=subprocess.run(["pwsh","-NoProfile","-NonInteractive","-Command",command],
                              cwd=ROOT,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn("R993_WIN32_TEMPFILE_UNDERSCORE_AND_5_NEGATIVE_PASS",result.stdout)

    @unittest.skipUnless(sys.platform == "win32", "native task principal normalization needs Windows")
    def test_r993_native_task_sid_normalization_and_exact_action(self):
        path = ROOT / "tests/r993_windows_os_scheduled_recovery_vm.ps1"
        command = "$p='" + str(path).replace("'", "''") + "';" + r"""
$ErrorActionPreference='Stop'
$tok=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$tok,[ref]$errors)
if($errors.Count){throw 'R993_SOURCE_PARSE'}
foreach($name in @('Test-R993OwnerPrincipal','Test-R993OwnedAction')){
 $f=@($ast.FindAll({param($n)
   $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name
 },$true))
 if($f.Count -ne 1){throw ('FUNCTION_'+$name)}
 . ([scriptblock]::Create($f[0].Extent.Text))
}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$owner=$identity.User.Value
$c=[pscustomobject]@{ownerSid=$owner;ownerName=$identity.Name}
$script='C:\VM\DirectInternetMethod\Privileged\UpdateTransactions\R993ProtectedRecoveryHarness.ps1'
$config='C:\VM\DirectInternetMethod\Privileged\UpdateTransactions\R993RecoveryConfig.json'
$execute=Join-Path $PSHOME 'pwsh.exe'
$args='-NoLogo -NoProfile -NonInteractive -File "'+$script+'" -Mode Recover -Config "'+$config+'"'
$task=[pscustomobject]@{
 Principal=[pscustomobject]@{UserId=$owner;LogonType='S4U';RunLevel='Highest'}
 Actions=@([pscustomobject]@{Execute=$execute;Arguments=$args})
 Triggers=@([pscustomobject]@{StartBoundary='2026-11-24T19:20:00'})
}
if(!(Test-R993OwnerPrincipal $owner $c) -or
   !(Test-R993OwnerPrincipal $identity.Name $c) -or
   !(Test-R993OwnedAction $task $c $script $config)){throw 'R993_VALID_NORMALIZED_TASK_REJECTED'}
foreach($field in @('UserId','LogonType','RunLevel')){
 $copy=($task|ConvertTo-Json -Depth 8|ConvertFrom-Json)
 $copy.Principal.$field=if($field -eq 'UserId'){'S-1-5-18'}else{'Invalid'}
 if(Test-R993OwnedAction $copy $c $script $config){throw ('R993_INVALID_'+$field+'_ACCEPTED')}
}
foreach($field in @('Execute','Arguments')){
 $copy=($task|ConvertTo-Json -Depth 8|ConvertFrom-Json)
 $copy.Actions[0].$field='C:\Windows\not-reviewed.exe'
 if(Test-R993OwnedAction $copy $c $script $config){throw ('R993_INVALID_'+$field+'_ACCEPTED')}
}
$copy=($task|ConvertTo-Json -Depth 8|ConvertFrom-Json)
$copy.Triggers=@()
if(Test-R993OwnedAction $copy $c $script $config){throw 'R993_NO_TRIGGER_ACCEPTED'}
'R993_NATIVE_SID_ORIGINAL_OWNER_AND_EXACT_ACTION_PASS'
"""
        result=subprocess.run(["pwsh","-NoProfile","-NonInteractive","-Command",command],
                              cwd=ROOT,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn("R993_NATIVE_SID_ORIGINAL_OWNER_AND_EXACT_ACTION_PASS",result.stdout)

    def test_r992_recovery_media_uses_actual_protected_store(self):
        ps = R980.read_text("utf-8-sig")
        vm = VM.read_text("utf-8")
        workflow = CI.read_text("utf-8")
        for marker in ("R992_PROTECTED_RECOVERY_MEDIA", "PrepareProtectedTransactionDirectory",
                       "NativeProtectedUpdateAcl.cs", "Get-R992MediaAcl",
                       "R992_PROTECTED_PRIOR_MEDIA_PIN", "R992_PROTECTED_PRIOR_MEDIA_UNCHANGED",
                       "R992_PROTECTED_MEDIA_SOURCE_RETIRED"):
            self.assertIn(marker, ps)
        self.assertIn('DirectInternetMethod-recovery-1.5.4.exe', vm)
        self.assertIn("R992_PROTECTED_RECOVERY_MEDIA", vm)
        self.assertIn("native_broker_protected_recovery_media:", workflow)
        self.assertIn("R992_PROTECTED_RECOVERY_MEDIA:", workflow)

    def test_explicit_hosted_exact_source_dispatch_only(self):
        s=CI.read_text("utf-8")
        self.assertIn("native_broker_recovery_candidate_sha:",s)
        block=s.split("  windows-r982-common-broker-native-compensation:",1)[1].split(
            "  windows-private-r848-v156-forward:",1)[0]
        for required in ("runs-on: windows-2025",
                        "github.event_name == 'workflow_dispatch'",
                        "github.repository == 'GOD13emad/DirectInternetMethod'",
                        "inputs.native_broker_recovery_candidate_sha == github.sha",
                        "R982_EXPECTED_SHA:",
                        "R980_EXPECTED_SHA:",
                        "tests/r980_windows_real_product_postfailure_vm.ps1 -CommonBrokerRecovery",
                        "actions/upload-artifact@"):
            self.assertIn(required,block)
        self.assertNotIn("gh release",block)

if __name__=="__main__":
    unittest.main()
