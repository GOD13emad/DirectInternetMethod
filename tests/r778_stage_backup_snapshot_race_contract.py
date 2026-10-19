#!/usr/bin/env python3
"""R778 synthetic-fake-root negative-first stage snapshot race; never privileged.

A controlled attacker-controlled symlink swap happens after accepted baseline
checks and before old backup bytes are captured. The intended security contract
is fail-closed before creating any pending transaction slot.
"""
import importlib.util
import json
import pathlib
import unittest

BASE=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("r778_original_fixture",
                                             BASE/"tests/protected_upgrade_transaction_contract.py")
fixture_module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_module)

class StageSnapshotRace(unittest.TestCase):
    def setUp(self):
        self.case=fixture_module.FakeFixture("test_success_stage_apply_rollback")
        self.case.setUp()

    def tearDown(self):
        self.case.tearDown()

    def _swap_after_baseline(self,target: pathlib.Path, content:bytes):
        replacement=self.case.root/("untrusted-r778-"+target.name)
        replacement.write_bytes(content)
        old=self.case.tx._baseline
        calls=[]
        def switch():
            verified=old()
            calls.append(True)
            target.rename(target.with_name(target.name+".original-unchanged"))
            target.symlink_to(replacement)
            return verified
        self.case.tx._baseline=switch
        return calls,replacement

    def _must_reject_before_pending(self,calls):
        with self.assertRaises((RuntimeError,OSError,ValueError)):
            self.case.tx.stage(self.case.pkg)
        self.assertEqual(calls,[True])
        self.assertFalse(self.case.tx.pending.exists(),
                         "R778_UNVERIFIED_PROTECTED_BACKUP_SLOT_CREATED")

    def test_01_valid_no_swap_stage_is_unmodified(self):
        self.assertEqual(self.case.tx.stage(self.case.pkg)["status"],"STAGED")
        self.case.all_old()
        self.assertTrue(self.case.tx.pending.is_dir())

    def test_02_old_protected_file_swapped_to_symlink_after_baseline(self):
        row=next(x for x in self.case.files if x[3])
        target=self.case.root/row[2]
        calls,_=self._swap_after_baseline(target,b"ATTACKER_CONTROLLED_UNPINNED_OLD_BYTES")
        self._must_reject_before_pending(calls)

    def test_03_root_metadata_swapped_after_baseline(self):
        meta=self.case.meta
        attacker=dict(self.case.orig,home="/home/attacker")
        data=(json.dumps(attacker,sort_keys=True)+"\n").encode()
        calls,_=self._swap_after_baseline(meta,data)
        self._must_reject_before_pending(calls)

if __name__=="__main__":
    unittest.main(verbosity=2)
