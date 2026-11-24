"""R901: portable replay journal fixture, deliberate NO native privilege proof."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from installer_engine.broker_replay import (
    BrokerReplayFixtureLedger, MAX_USED_REQUEST_IDS, STATUS,
)
from installer_engine.engine import EngineError, hash_bytes
from tests.test_engine_broker_intent import fixture_contract, canonical


class ReplayJournalFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dim-r901-replay-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)/"unprivileged-request-journal"
        self.ledger = BrokerReplayFixtureLedger(
            self.root, "linux-x86_64")
        self.plan, self.policy, self.req, self.pb, self.rb = fixture_contract()
        self.pin=hash_bytes(self.pb)
        self.reqpin=hash_bytes(self.rb)
        self.rid=self.req["request_id"]

    def reserve(self, fault=False):
        return self.ledger.reserve(self.plan,self.pb,self.pin,self.rb,
                                   fault_after_save=fault)

    def again(self):
        return BrokerReplayFixtureLedger(self.root,"linux-x86_64")

    def recover(self, other=None):
        return (other or self.ledger).recover(
            self.rid,self.reqpin,self.pin)

    def apply(self, other=None, fault=False):
        return (other or self.ledger).mark_applying_fixture(
            self.rid,self.reqpin,self.pin,fault_after_save=fault)

    def close(self, outcome="completed_synthetic", other=None):
        return (other or self.ledger).close_fixture(
            self.rid,self.reqpin,self.pin,outcome=outcome)

    def test_empty_ledger_is_not_native_acceptance(self):
        report=self.ledger.inspect_fixture()
        self.assertEqual(report["used_ids"],0)
        self.assertFalse(report["native_installation_accepted"])
        self.assertIsNone(report["active_phase"])

    def test_reserve_exact_policy_request_and_recover(self):
        report=self.reserve()
        self.assertEqual(report["status"],STATUS)
        self.assertEqual(report["phase"],"reserved")
        self.assertFalse(report["privileged_broker_implemented"])
        fresh=self.again()
        self.assertEqual(self.recover(fresh)["phase"],"reserved")
        self.assertEqual(fresh.inspect_fixture()["used_ids"],1)

    def test_crash_after_reservation_recovers_without_rerunning(self):
        with self.assertRaisesRegex(
                EngineError,"FIXTURE_INJECTED_AFTER_DURABLE_RESERVE"):
            self.reserve(fault=True)
        fresh=self.again()
        self.assertEqual(self.recover(fresh)["phase"],"reserved")
        with self.assertRaisesRegex(EngineError,"ACTIVE_FIRST_RECOVER"):
            fresh.reserve(self.plan,self.pb,self.pin,self.rb)
        self.close("aborted_synthetic",fresh)

    def test_crash_after_applying_recovery_is_not_second_apply(self):
        self.reserve()
        with self.assertRaisesRegex(
                EngineError,"FIXTURE_INJECTED_AFTER_DURABLE_APPLYING"):
            self.apply(fault=True)
        fresh=self.again()
        self.assertEqual(self.recover(fresh)["phase"],"applying")
        with self.assertRaisesRegex(EngineError,
                                    "ALREADY_APPLYING_USE_RECOVER"):
            self.apply(fresh)
        result=self.close(other=fresh)
        self.assertFalse(result["native_installation_accepted"])

    def test_corrupt_staging_uninstall_phase_refused(self):
        self.reserve()
        doc = json.loads(self.ledger.path.read_text())
        doc["active"]["phase"] = "staging"
        doc["active"]["operation"] = "uninstall"
        self.ledger.path.write_text(json.dumps(doc), encoding="utf-8")
        with self.assertRaisesRegex(EngineError, "STAGE_OPERATION_INVALID"):
            self.ledger.inspect_fixture()

    def test_staging_transition_is_exact_one_time_and_abortable(self):
        self.reserve()
        state = self.ledger.mark_staging_fixture(
            self.rid, self.reqpin, self.pin)
        self.assertEqual(state["phase"], "staging")
        self.assertEqual(self.recover()["phase"], "staging")
        with self.assertRaisesRegex(EngineError, "CODE_STAGE_NOT_RESERVED"):
            self.ledger.mark_staging_fixture(
                self.rid, self.reqpin, self.pin)
        with self.assertRaisesRegex(EngineError, "BROKER_REPLAY_CLOSE_PHASE_DRIFT"):
            self.ledger.close_fixture(
                self.rid, self.reqpin, self.pin,
                outcome="aborted_synthetic", expected_phase="reserved")
        self.close("aborted_synthetic")
        self.assertEqual(self.ledger.inspect_fixture()["used_ids"], 1)
        self.assertIsNone(self.ledger.inspect_fixture()["active_phase"])

    def test_completed_id_tombstoned_forever_within_fixture_epoch(self):
        self.reserve()
        self.apply()
        self.close()
        self.assertEqual(self.ledger.inspect_fixture()["used_ids"],1)
        with self.assertRaisesRegex(EngineError,"REQUEST_ID_ALREADY_USED"):
            self.reserve()

    def test_aborted_id_also_tombstoned(self):
        self.reserve()
        self.close("aborted_synthetic")
        with self.assertRaisesRegex(EngineError,"REQUEST_ID_ALREADY_USED"):
            self.reserve()

    def test_new_id_allowed_only_after_previous_closed(self):
        self.reserve()
        changed=dict(self.req, request_id="22"*16)
        newrb=canonical(changed)
        newpolicy=dict(self.policy, request_sha256=hash_bytes(newrb))
        newpb=canonical(newpolicy)
        with self.assertRaisesRegex(EngineError,"ACTIVE_FIRST_RECOVER"):
            self.ledger.reserve(self.plan,newpb,hash_bytes(newpb),newrb)
        self.close("aborted_synthetic")
        report=self.ledger.reserve(
            self.plan,newpb,hash_bytes(newpb),newrb)
        self.assertEqual(report["request_id"],"22"*16)
        self.assertEqual(self.ledger.inspect_fixture()["used_ids"],2)

    def test_wrong_identity_denied_while_recovering(self):
        self.reserve()
        for ids in ((self.rid,"0"*64,self.pin),
                    (self.rid,self.reqpin,"0"*64),
                    ("55"*16,self.reqpin,self.pin)):
            with self.subTest(ids=ids):
                with self.assertRaisesRegex(
                        EngineError,"EXACT_ACTIVE_IDENTITY_REQUIRED"):
                    self.ledger.recover(*ids)
        self.assertEqual(self.recover()["phase"],"reserved")

    def test_invalid_ids_digest_and_outcome_rejected(self):
        self.reserve()
        with self.assertRaisesRegex(EngineError,"BROKER_REPLAY_ID_REQUIRED"):
            self.ledger.recover("invalid",self.reqpin,self.pin)
        with self.assertRaisesRegex(EngineError,
                                    "BROKER_REPLAY_EXACT_PINS_REQUIRED"):
            self.ledger.recover(self.rid,"invalid",self.pin)
        with self.assertRaisesRegex(EngineError,
                                    "BROKER_REPLAY_FIXTURE_OUTCOME_INVALID"):
            self.close("native_accepted")

    def test_compare_and_close_reserved_refuses_concurrent_phase_change(self):
        self.reserve()
        self.apply()
        with self.assertRaisesRegex(EngineError, "BROKER_REPLAY_CLOSE_PHASE_DRIFT"):
            self.ledger.close_fixture(self.rid, self.reqpin, self.pin,
                                      outcome="aborted_synthetic",
                                      expected_phase="reserved")
        self.assertEqual(self.recover()["phase"], "applying")
        self.assertEqual(self.ledger.inspect_fixture()["used_ids"], 1)

    def test_complete_requires_applying_but_abort_from_reserved_allowed(self):
        self.reserve()
        with self.assertRaisesRegex(EngineError,
                                   "SYNTHETIC_COMPLETION_NOT_APPLYING"):
            self.close()
        self.close("aborted_synthetic")

    def test_tampered_duplicate_used_id_refused(self):
        self.reserve()
        doc=json.loads(self.ledger.path.read_text())
        doc["used_request_ids"].append(self.rid)
        self.ledger.path.write_text(json.dumps(doc))
        with self.assertRaisesRegex(EngineError,
                                    "BROKER_REPLAY_USED_IDS_INVALID"):
            self.ledger.inspect_fixture()

    def test_tampered_missing_active_id_refused(self):
        self.reserve()
        doc=json.loads(self.ledger.path.read_text())
        doc["used_request_ids"]=[]
        self.ledger.path.write_text(json.dumps(doc))
        with self.assertRaisesRegex(EngineError,
                                   "BROKER_REPLAY_ACTIVE_ID_NOT_RESERVED"):
            self.ledger.inspect_fixture()

    def test_tampered_foreign_json_key_refused(self):
        self.reserve()
        doc=json.loads(self.ledger.path.read_text())
        doc["root"]="/tmp/untrusted"
        self.ledger.path.write_text(json.dumps(doc))
        with self.assertRaisesRegex(EngineError,
                                   "BROKER_REPLAY_SCHEMA_OR_PLATFORM"):
            self.ledger.inspect_fixture()

    def test_duplicate_json_key_refused_by_engine_reader(self):
        self.reserve()
        doc=self.ledger.path.read_text()
        doc=doc.replace('"schema":1',
                        '"schema":1,"schema":1',1)
        self.ledger.path.write_text(doc)
        with self.assertRaisesRegex(EngineError,"DUPLICATE_JSON_KEY"):
            self.ledger.inspect_fixture()

    def test_no_history_eviction_on_capacity_exhaustion(self):
        self.ledger.inspect_fixture()
        unused=[f"{i:032x}" for i in range(MAX_USED_REQUEST_IDS)]
        self.ledger.path.write_text(json.dumps({
            "schema":1,"platform":"linux-x86_64",
            "used_request_ids":unused,"active":None}))
        with self.assertRaisesRegex(EngineError,
                                   "BROKER_REPLAY_HISTORY_CAPACITY_EXHAUSTED"):
            self.reserve()
        self.assertEqual(self.ledger.inspect_fixture()["used_ids"],
                         MAX_USED_REQUEST_IDS)

    def test_metadata_temp_left_by_crash_fails_closed(self):
        self.ledger.inspect_fixture()
        path=self.ledger.path.with_name("broker-replay.json.writing")
        path.write_text("HALF_WRITTEN")
        with self.assertRaisesRegex(EngineError,"STALE_METADATA_TEMP"):
            self.reserve()
        self.assertFalse(self.ledger.path.exists())

    def test_replay_file_symlink_refused(self):
        self.ledger.inspect_fixture()
        foreign=self.root/"external.json"
        foreign.write_text("{}")
        try:
            self.ledger.path.symlink_to(foreign)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink privilege unavailable")
        with self.assertRaisesRegex(EngineError,
                                   "BROKER_REPLAY_SYMLINK_STATE"):
            self.ledger.inspect_fixture()
        self.assertEqual(foreign.read_text(),"{}")

    def test_invalid_client_policy_rejected_before_creating_ledger(self):
        with self.assertRaisesRegex(
                EngineError,"BROKER_PROTECTED_POLICY_PIN_MISMATCH"):
            self.ledger.reserve(self.plan,self.pb,"0"*64,self.rb)
        self.assertFalse(self.root.exists())

    def test_hard_child_process_exit_inside_locked_atomic_reserve(self):
        # The CHILD, never the owner host service/VM, exits via os._exit
        # while Engine's OS lock is held and AFTER atomic_json/fsync writes.
        # Parent starts a new Engine instance and checks actual persistence.
        project_root=Path(__file__).resolve().parents[1]
        child=r"""
import os,sys
from installer_engine import broker_replay as module
from installer_engine.engine import hash_bytes
from tests.test_engine_broker_intent import fixture_contract
root=sys.argv[1]
plan,policy,req,pb,rb=fixture_contract()
original=module.atomic_json
def persist_then_terminate(p,obj):
    original(p,obj)
    os._exit(42)
module.atomic_json=persist_then_terminate
module.BrokerReplayFixtureLedger(root,'linux-x86_64').reserve(
    plan,pb,hash_bytes(pb),rb)
raise RuntimeError('CHILD_DID_NOT_TERMINATE')
"""
        env=dict(os.environ,PYTHONPATH=str(project_root),
                 PYTHONDONTWRITEBYTECODE="1")
        run=subprocess.run(
            [sys.executable,"-c",child,str(self.root)],
            cwd=str(project_root),env=env,timeout=10,capture_output=True,text=True)
        self.assertEqual(run.returncode,42,run.stderr)
        fresh=self.again()
        self.assertEqual(self.recover(fresh)["phase"],"reserved")
        with self.assertRaisesRegex(EngineError,"ACTIVE_FIRST_RECOVER"):
            fresh.reserve(self.plan,self.pb,self.pin,self.rb)
        self.close("aborted_synthetic",fresh)

    def test_simultaneous_independent_processes_cannot_double_reserve(self):
        project_root=Path(__file__).resolve().parents[1]
        child=r"""
import sys
from installer_engine.broker_replay import BrokerReplayFixtureLedger
from installer_engine.engine import EngineError,hash_bytes
from tests.test_engine_broker_intent import fixture_contract
plan,policy,req,pb,rb=fixture_contract()
try:
    BrokerReplayFixtureLedger(sys.argv[1],'linux-x86_64').reserve(
        plan,pb,hash_bytes(pb),rb)
except EngineError:
    sys.exit(3)
sys.exit(0)
"""
        env=dict(os.environ,PYTHONPATH=str(project_root),
                 PYTHONDONTWRITEBYTECODE="1")
        args=[sys.executable,"-c",child,str(self.root)]
        first=subprocess.Popen(args,cwd=str(project_root),env=env,
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        second=subprocess.Popen(args,cwd=str(project_root),env=env,
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            _,err1=first.communicate(timeout=10)
            _,err2=second.communicate(timeout=10)
        finally:
            for proc in (first,second):
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)
        self.assertEqual(sorted([first.returncode,second.returncode]),
                         [0,3],f"CHILD1={err1!r} CHILD2={err2!r}")
        self.assertEqual(self.recover(self.again())["phase"],"reserved")

    def test_wrong_platform_ledger_rejected(self):
        self.reserve()
        foreign=BrokerReplayFixtureLedger(self.root,"windows-x86_64")
        with self.assertRaisesRegex(EngineError,
                                   "BROKER_REPLAY_SCHEMA_OR_PLATFORM"):
            foreign.inspect_fixture()


if __name__=="__main__":
    unittest.main()
