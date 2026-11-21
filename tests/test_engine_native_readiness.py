"""Native SCM and systemd read-only consistency gates; never acceptance."""
from __future__ import annotations

import os
import unittest
from unittest import mock

from installer_engine.engine import EngineError
from installer_engine.native_readiness import (
    READINESS, linux_readiness, windows_readiness,
    windows_service_configuration,
)


def fixture_windows():
    return {"service": {"exists": True, "state": "RUNNING"},
            "registrations": [{"hive": "HKLM",
                               "display_name": "Direct Internet Method",
                               "display_version": "1.5.6",
                               "uninstall_command_present": True}]}


def fixture_linux():
    return {"protected_root": "/usr/lib/directinternetmethod",
            "protected_root_safe_ownership_observed": True,
            "protected_root_ancestor_chain_trusted": True,
            "units": [{"unit": "dim-start.service", "LoadState": "loaded",
                       "ActiveState": "active"},
                      {"unit": "dim-stop.service", "LoadState": "loaded",
                       "ActiveState": "inactive"}]}


class NativeReadinessTests(unittest.TestCase):
    def test_product_inno_display_name_matches_strict_native_readiness(self):
        from pathlib import Path
        iss = (Path(__file__).resolve().parents[1] / "windows" / "installer" /
               "DirectInternetMethod.iss").read_text(encoding="utf-8-sig")
        self.assertIn('AppId={{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}', iss)
        self.assertIn('AppName={#MyAppName}', iss)
        self.assertIn('UninstallDisplayName={#MyAppName}', iss)
        self.assertIn('UninstallLogMode=overwrite', iss)

    def test_windows_readiness_is_not_native_acceptance(self):
        with mock.patch("installer_engine.native_readiness.observe_windows",
                        return_value=fixture_windows()), mock.patch(
                "installer_engine.native_readiness.windows_service_configuration",
                return_value={"binary_command": '"C:\\app\\svc.exe" --run',
                              "service_account": "LocalSystem"}):
            report = windows_readiness(
                "{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}",
                "DirectInternetMethodSvc", expected_version="1.5.6",
                expected_binary_command='"C:\\app\\svc.exe" --run')
        self.assertEqual(report["status"], READINESS)
        self.assertFalse(report["native_installation_or_rollback_accepted"])

    def test_wrong_scm_command_refused(self):
        with mock.patch("installer_engine.native_readiness.observe_windows",
                        return_value=fixture_windows()), mock.patch(
                "installer_engine.native_readiness.windows_service_configuration",
                return_value={"binary_command": "C:\\foreign\\svc.exe"}):
            with self.assertRaisesRegex(EngineError, "SCM_BINARY_COMMAND_MISMATCH"):
                windows_readiness("{00000000-0000-0000-0000-000000000000}",
                    "DirectInternetMethodSvc", expected_version="1.5.6",
                    expected_binary_command="C:\\trusted\\svc.exe")

    def test_duplicate_inno_registration_refused(self):
        report = fixture_windows()
        report["registrations"].append(dict(report["registrations"][0], hive="HKCU"))
        with mock.patch("installer_engine.native_readiness.observe_windows",
                        return_value=report), mock.patch(
                "installer_engine.native_readiness.windows_service_configuration",
                return_value={"binary_command": "C:\\trusted\\svc.exe"}):
            with self.assertRaisesRegex(EngineError, "INNO_REGISTRATION_COUNT_MISMATCH"):
                windows_readiness("{00000000-0000-0000-0000-000000000000}",
                    "DirectInternetMethodSvc", expected_version="1.5.6",
                    expected_binary_command="C:\\trusted\\svc.exe")

    def test_registry_identity_mismatch_refused(self):
        for key, bad in (("display_version", "1.5.5"),
                         ("display_name", "Other app"),
                         ("uninstall_command_present", False)):
            with self.subTest(key=key):
                report = fixture_windows()
                report["registrations"][0][key] = bad
                with mock.patch("installer_engine.native_readiness.observe_windows",
                                return_value=report), mock.patch(
                        "installer_engine.native_readiness.windows_service_configuration",
                        return_value={"binary_command": "C:\\trusted\\svc.exe"}):
                    with self.assertRaisesRegex(EngineError, "INNO_REGISTRATION_IDENTITY_MISMATCH"):
                        windows_readiness("{00000000-0000-0000-0000-000000000000}",
                            "DirectInternetMethodSvc", expected_version="1.5.6",
                            expected_binary_command="C:\\trusted\\svc.exe")

    def test_stopped_service_refused_for_running_gate(self):
        report = fixture_windows()
        report["service"]["state"] = "STOPPED"
        with mock.patch("installer_engine.native_readiness.observe_windows",
                        return_value=report), mock.patch(
                "installer_engine.native_readiness.windows_service_configuration",
                return_value={"binary_command": "C:\\trusted\\svc.exe"}):
            with self.assertRaisesRegex(EngineError, "SCM_SERVICE_STATE_MISMATCH"):
                windows_readiness("{00000000-0000-0000-0000-000000000000}",
                    "DirectInternetMethodSvc", expected_version="1.5.6",
                    expected_binary_command="C:\\trusted\\svc.exe")

    def test_linux_readiness_not_acceptance(self):
        with mock.patch("installer_engine.native_readiness.observe_linux",
                        return_value=fixture_linux()):
            report = linux_readiness("/usr/lib/directinternetmethod",
                ["dim-start.service", "dim-stop.service"],
                required_active_units=("dim-start.service",))
        self.assertEqual(report["status"], READINESS)
        self.assertFalse(report["native_installation_or_rollback_accepted"])

    def test_linux_missing_root_ownership_refused(self):
        report = fixture_linux()
        report["protected_root_safe_ownership_observed"] = False
        with mock.patch("installer_engine.native_readiness.observe_linux",
                        return_value=report):
            with self.assertRaisesRegex(EngineError, "LINUX_PROTECTED_ROOT_UNTRUSTED"):
                linux_readiness("/tmp/foreign", ["dim-start.service"])

    def test_linux_spoofed_safe_leaf_but_untrusted_ancestor_refused(self):
        report = fixture_linux()
        report["protected_root_ancestor_chain_trusted"] = False
        with mock.patch("installer_engine.native_readiness.observe_linux",
                        return_value=report):
            with self.assertRaisesRegex(EngineError, "LINUX_PROTECTED_ROOT_PARENT_UNTRUSTED"):
                linux_readiness("/tmp/fake-root-owned", ["dim-start.service"])

    def test_linux_missing_parent_chain_evidence_is_not_trust(self):
        report = fixture_linux()
        report.pop("protected_root_ancestor_chain_trusted")
        with mock.patch("installer_engine.native_readiness.observe_linux",
                        return_value=report):
            with self.assertRaisesRegex(EngineError, "LINUX_PROTECTED_ROOT_PARENT_UNTRUSTED"):
                linux_readiness("/usr/lib/directinternetmethod", ["dim-start.service"])

    def test_linux_unloaded_and_inactive_refused(self):
        for key, value, expected in (
            ("LoadState", "not-found", "SYSTEMD_UNIT_NOT_LOADED"),
            ("ActiveState", "inactive", "SYSTEMD_UNIT_NOT_ACTIVE")):
            with self.subTest(key=key):
                report = fixture_linux()
                report["units"][0][key] = value
                with mock.patch("installer_engine.native_readiness.observe_linux",
                                return_value=report):
                    with self.assertRaisesRegex(EngineError, expected):
                        linux_readiness("/usr/lib/directinternetmethod",
                            ["dim-start.service"], required_active_units=("dim-start.service",))

    def test_invalid_active_expectation_rejected(self):
        with self.assertRaisesRegex(EngineError, "EXPECTED_ACTIVE_UNITS_INVALID"):
            linux_readiness("/tmp", ["dim-start.service"],
                required_active_units=("dim-start.service", "dim-start.service"))

    @unittest.skipUnless(os.name == "nt", "Windows host required")
    def test_windows_native_scm_config_query_on_missing_service_fails_closed(self):
        with self.assertRaisesRegex(EngineError, "SCM_CONFIG_READ_DENIED_OR_MISSING"):
            windows_service_configuration("DIM_NeverRegistered_271828")
