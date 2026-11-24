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
