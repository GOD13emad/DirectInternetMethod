"""Non-destructive source guards for the R980 REAL product Inno failure VM.

This test never invokes the native installer or touches an installed host.
"""
from __future__ import annotations
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "tests/r980_windows_real_product_postfailure_vm.ps1"
ISS = ROOT / "windows/installer/DirectInternetMethod.iss"
WORKFLOW = ROOT / ".github/workflows/ci.yml"


class RealProductPostfailureSafety(unittest.TestCase):
    def test_real_product_qa_copy_and_pinned_vm_only_authority(self):
        s = PROBE.read_text(encoding="utf-8")
        for required in (
            "R980_DISPOSABLE_REVIEWED_VM_ONLY",
            "$env:RUNNER_ENVIRONMENT -cne 'github-hosted'",
            "$env:GITHUB_REPOSITORY -cne 'GOD13emad/DirectInternetMethod'",
            "$env:GITHUB_EVENT_NAME -cne 'workflow_dispatch'",
            "$env:R980_EXPECTED_SHA -cne $Sha",
            "$env:GITHUB_REF -cne 'refs/heads/feature/universal-install-engine'",
            "R980_NOT_FRESH_VM_OR_BUILD_MISSING",
            "R980_BUILT_CANDIDATE_NOT_PINNED",
            "R980_VM_ONLY_FORCED_NATIVE_POSTINSTALL_FAILURE",
            "R980_REAL_POSTFAIL.json",
            "R980_REAL_POSTFAIL_VM_ONLY.iss",
            "R980_FAILED_PRODUCT_SETUP",
            "EXACT_PUBLIC_STABLE_INSTALLER_PIN",
            "EXPLICIT_REINSTALL_RESTORED_STABLE_NATIVE_BINARIES",
            "EXPLICIT_REINSTALL_RESTORED_NATIVE_SERVICE_RUNNING",
            "EXPLICIT_REINSTALL_ONE_INNO_UNINSTALLER",
            "NATIVE_FAILURE_PRESERVED_UNKNOWN_OWNER_DATA",
            "NO_NETWORK_DNS_ROUTE_DRIFT",
            "REAL_CANDIDATE_FILES_APPLIED_BEFORE_FAILURE",
            "nativeAutomaticRollbackAccepted=$false",
            "powercutAccepted=$false",
        ):
            self.assertIn(required, s)
        self.assertLess(
            s.index("R980_DISPOSABLE_REVIEWED_VM_ONLY"),
            s.index("[void](New-Item -ItemType Directory -Path $QaDir)"))
        self.assertLess(
            s.index("R980_BUILT_CANDIDATE_NOT_PINNED"),
            s.index("[void](New-Item -ItemType Directory -Path $QaDir)"))
        original = ISS.read_text(encoding="utf-8-sig")
        self.assertNotIn("R980_VM_ONLY_FORCED_NATIVE_POSTINSTALL_FAILURE", original)
        self.assertIn("    InstallOrUpdateCtrldService();", original)
        self.assertIn("    InstallOrUpdateService();", original)
        self.assertNotIn("R980_FAILED_PRODUCT_SETUP", original)

    def test_stable_gui_and_service_pins_are_exactly_r846_accepted(self):
        from re import search
        accepted = (ROOT / "tests/r846_windows_native_rollback.ps1").read_text(
            encoding="utf-8-sig")
        probe = PROBE.read_text(encoding="utf-8-sig")
        for old_key, probe_key in (("PublicSha", "OldSetupSha"),
                                   ("PublicGui", "OldGuiSha"),
                                   ("PublicSvc", "OldSvcSha")):
            def pin(raw, key):
                match = search(r"(?m)^\$" + key + r"='([A-F0-9]{64})'$", raw)
                self.assertIsNotNone(match, f"{key} SHA-256 length and syntax")
                return match.group(1)
            self.assertEqual(pin(accepted, old_key), pin(probe, probe_key))
    def test_reviewed_workflow_isolated_and_no_unprompted_release(self):
        flow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("native_failure_candidate_sha:", flow)
        job = flow.split("  windows-r980-real-postinstall-failure:", 1)[1].split(
            "  windows-private-r848-v156-forward:", 1)[0]
        for required in (
            "runs-on: windows-2025",
            "github.repository == 'GOD13emad/DirectInternetMethod'",
            "github.event_name == 'workflow_dispatch'",
            "inputs.native_failure_candidate_sha == github.sha",
            "R980_EXPECTED_SHA:",
            "R951_EXPECTED_SHA:",
            "tests/r846_windows_candidate_hosted_build.ps1",
            "tests/r980_windows_real_product_postfailure_vm.ps1",
            "actions/upload-artifact@",
            "R980_REAL_POSTFAIL.json",
        ):
            self.assertIn(required, job)
        self.assertNotIn("release.yml", job)
        self.assertNotIn("gh release", job)
        self.assertNotIn("sudo", job)
        self.assertNotIn("shell: bash", job)


if __name__ == "__main__":
    unittest.main()