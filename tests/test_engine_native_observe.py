"""Read-only native SCM/Inno/systemd evidence tests; never mutate services."""
from __future__ import annotations
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from installer_engine.engine import EngineError
from installer_engine.native_observe import (
    IDENTITY, _unit_observation, observe_linux, observe_windows,
)


class NativeObservationTests(unittest.TestCase):
    def test_systemd_readonly_fields_from_controlled_fixture(self):
        response=mock.Mock(returncode=0,stdout="LoadState=loaded\nActiveState=inactive\n")
        with mock.patch("installer_engine.native_observe.subprocess.run",
                        return_value=response) as process:
            result=_unit_observation("fixture-example.service")
        self.assertEqual(result,{"unit":"fixture-example.service",
                                 "LoadState":"loaded","ActiveState":"inactive"})
        args=process.call_args.args[0]
        self.assertEqual(args[:2],["/usr/bin/systemctl","show"])
        self.assertNotIn("start",args)
        self.assertNotIn("stop",args)
        self.assertNotIn("daemon-reload",args)

    def test_reject_command_injection_in_unit_name(self):
        for unit in ("../../etc/passwd","a.service;rm -rf /",
                     "foo.service --system","", "foo.timer"):
            with self.subTest(unit=unit):
                with self.assertRaisesRegex(EngineError,"SYSTEMD_UNIT_NAME_INVALID"):
                    _unit_observation(unit)

    def test_incomplete_systemd_observation_not_accepted(self):
        response=mock.Mock(returncode=0,stdout="ActiveState=active\n")
        with mock.patch("installer_engine.native_observe.subprocess.run",
                        return_value=response):
            with self.assertRaisesRegex(EngineError,"SYSTEMD_INCOMPLETE_OBSERVATION"):
                _unit_observation("fixture.service")

    def test_duplicate_systemd_status_line_rejected(self):
        response=mock.Mock(returncode=0,stdout="LoadState=loaded\nLoadState=masked\nActiveState=active\n")
        with mock.patch("installer_engine.native_observe.subprocess.run",
                        return_value=response):
            with self.assertRaisesRegex(EngineError,"SYSTEMD_DUPLICATE_FIELD"):
                _unit_observation("fixture.service")

    def test_unavailable_service_is_not_proof_of_native_acceptance(self):
        response=mock.Mock(returncode=1,stdout="",stderr="not found")
        with mock.patch("installer_engine.native_observe.subprocess.run",
                        return_value=response):
            with self.assertRaisesRegex(EngineError,"SYSTEMD_READ_FAILED"):
                _unit_observation("fixture.service")

    @unittest.skipUnless(os.name=="nt","Windows registry/SCM APIs")
    def test_windows_nonexistent_registration_is_observation_only(self):
        report=observe_windows("{00000000-0000-0000-0000-000000000000}",
                               "DIM_UnitTest_NeverRegistered_271828")
        self.assertEqual(report["status"],IDENTITY)
        self.assertFalse(report["service"]["exists"])
        self.assertEqual(report["registrations"],[])
        self.assertFalse(report["native_installation_or_rollback_accepted"])

    @unittest.skipUnless(os.name=="nt","Windows registry/SCM APIs")
    def test_invalid_windows_appid_fails_closed(self):
        with self.assertRaisesRegex(EngineError,"APP_ID_FORMAT_INVALID"):
            observe_windows("app id; injected", "service")

    @unittest.skipUnless(os.name=="posix","Linux owner/mode check")
    def test_linux_user_owned_directory_not_trusted_native_root(self):
        with tempfile.TemporaryDirectory(prefix="dim-linux-observe-") as t:
            p=Path(t)/"user-dir"
            p.mkdir()
            response=mock.Mock(returncode=0,stdout="LoadState=loaded\nActiveState=inactive\n")
            with mock.patch("installer_engine.native_observe.subprocess.run",
                            return_value=response):
                report=observe_linux(p,["dim-fixture.service"])
            self.assertEqual(report["status"],IDENTITY)
            self.assertFalse(report["native_installation_or_rollback_accepted"])
            if os.geteuid()!=0:
                self.assertFalse(report["protected_root_safe_ownership_observed"])


if __name__=="__main__":
    unittest.main(verbosity=2)
