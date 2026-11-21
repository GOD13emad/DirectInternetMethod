"""R900 synthetic two-scope VM termination native fixture source contract.

These tests never open/stop a Sandbox or modify SCM. Actual three separate
Windows Sandbox guest sessions and forced host session termination are recorded
in the independent R900 native receipt, not in this source-only CI test.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from installer_engine.engine import Engine, EngineError


ROOT=Path(__file__).resolve().parents[1]
ENTRY=ROOT/"tools/native_fixtures/windows/VmCrashDualScopeEntry.py"
GUEST=ROOT/"tools/native_fixtures/windows/RunVmCrashGuest.ps1"


class VmCrashFixtureContracts(unittest.TestCase):
    def fixture(self):
        with tempfile.TemporaryDirectory(prefix="dim-r900-sandbox-equivalent-") as tmp:
            folder=Path(tmp)
            spec=importlib.util.spec_from_file_location("dim_r900_guest_fixture",ENTRY)
            module=importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.ROOT=folder
            module.ROOTS={"code":folder/"synthetic-machine",
                          "user":folder/"synthetic-user"}
            module.LEDGER=folder/"transaction"
            module.OWNER=module.ROOTS["user"]/"data"/"keep-owner-config.dat"
            module.PACKAGES=folder/"source-packages"
            module.STATUS=folder/"vm-status.json"
            module.RESULT=folder/"vm-recovery-receipt.json"
            module._pause=lambda:None  # no guest session in a unit test
            yield module

    def test_three_native_fixture_phases_reconcile_two_scopes(self):
        for m in self.fixture():
            m.stage_and_pause()
            self.assertEqual(json.loads(m.STATUS.read_text())["phase"],
                             "READY_TO_FORCE_VM_EXIT_BEFORE_ROLLBACK")
            self.assertEqual(m._coord()._journal()["phase"],"activated")
            m.rollback_and_prepare_forward_pause()
            self.assertEqual(json.loads(m.STATUS.read_text())["phase"],
                             "READY_TO_FORCE_VM_EXIT_AFTER_FIRST_CODE_COMMIT")
            self.assertEqual(m._coord()._journal()["phase"],"finalizing")
            m.replay_forward_after_second_vm_exit()
            final=json.loads(m.RESULT.read_text())
            self.assertEqual(final["status"],
                             "PASS_R900_SYNTHETIC_TWO_VM_FORCED_TERMINATIONS_REPLAY")
            self.assertFalse(final["native_product_installation_accepted"])
            self.assertFalse(final["physical_power_loss_accepted"])
            self.assertEqual(Engine(m.ROOTS["code"],m.PLATFORM).verify()["version"],
                             "1.5.7")
            self.assertEqual(Engine(m.ROOTS["user"],m.PLATFORM).verify()["version"],
                             "1.5.7")
            self.assertEqual(m.OWNER.read_bytes(),m.MARKER)

    def test_second_phase_cannot_start_before_stage(self):
        for m in self.fixture():
            with self.assertRaisesRegex(EngineError,"R900_STATUS_MISSING"):
                m.rollback_and_prepare_forward_pause()

    def test_third_phase_cannot_be_called_while_activated_only(self):
        for m in self.fixture():
            m.stage_and_pause()
            with self.assertRaisesRegex(EngineError,"R900_STATUS_TAMPER_OR_WRONG_PHASE"):
                m.replay_forward_after_second_vm_exit()

    def test_no_production_windows_service_or_product_appid(self):
        code=ENTRY.read_text("utf-8")
        guest=GUEST.read_text("utf-8")
        for text in (code,guest):
            self.assertNotIn("DirectInternetMethodSvc",text)
            self.assertNotIn("Get-Service Tailscale",text)
            self.assertNotIn("Stop-Service Tailscale",text)
            self.assertNotIn("AppId={{",text)
        self.assertIn("native_product_installation_accepted",code)
        self.assertIn("physical_power_loss_accepted",code)
        self.assertIn("C:\\DIMR900\\persist",guest)

    def test_no_networked_or_privileged_fixture_actions(self):
        script=GUEST.read_text("utf-8")
        for forbidden in ("Start-Service","sc.exe","pkexec","sudo ",
                          "Restart-Computer","Stop-Computer","rm -rf"):
            self.assertNotIn(forbidden,script)
        self.assertIn("PASS_R900_GUEST_THREE_REPLAY",script)
        self.assertIn("FAIL_CLOSED_R900_GUEST",script)


if __name__=="__main__":
    unittest.main()
