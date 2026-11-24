"""Dual managed-code-scope coordinator, fault and forward-recovery tests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from installer_engine.engine import Engine, EngineError
from installer_engine.two_scope import TwoScopeFixtureCoordinator


class TwoScopeTests(unittest.TestCase):
    platform = "windows-x86_64"

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="dim-twoscope-")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.roots = {"user": self.base/"userroot",
                      "protected": self.base/"protectedroot"}
        self.coord = TwoScopeFixtureCoordinator(
            self.base/"coord-state", self.platform, self.roots)

    def package(self, name, ver):
        bundle = self.base / (name + "_" + ver.replace(".","_"))
        path = bundle/"payload"/"app"/"code.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        data = (name+"-"+ver+"-SYNTHETIC_CODE_ONLY").encode()
        path.write_bytes(data)
        doc={"schema":1,"product":"Direct Internet Method",
             "version":ver,"platform":self.platform,
             "files":[{"path":"app/code.bin","bytes":len(data),
                       "sha256":hashlib.sha256(data).hexdigest(),"mode":0o644}]}
        source = bundle/"manifest.json"
        source.write_text(json.dumps(doc,sort_keys=True)+"\n",encoding="utf8")
        pin=hashlib.sha256(source.read_bytes()).hexdigest()
        return bundle,pin

    def sources(self,ver):
        return {n:self.package(n,ver) for n in self.roots}

    def install(self,ver):
        self.coord.prepare(self.sources(ver))
        self.coord.activate(lambda:True)
        self.coord.finalize(lambda:True)
        return ver

    def states(self):
        return {name:Engine(root,self.platform).verify()
                for name,root in self.roots.items()}

    def test_fresh_two_scopes_staged_activated_committed(self):
        self.install("1.5.7")
        for state in self.states().values():
            self.assertEqual((state["version"],state["files"]),("1.5.7",1))
        self.assertFalse(self.coord.path.exists())

    def test_update_then_abort_restores_both_previous_versions(self):
        self.install("1.5.6")
        data=self.roots["user"]/"data"/"owner.config"
        data.parent.mkdir();data.write_bytes(b"OWNER DATA KEEP")
        self.coord.prepare(self.sources("1.5.7"))
        self.coord.activate(lambda:True)
        self.assertEqual(self.coord.abort(lambda:True)["status"],
                         "PASS_BOTH_SCOPES_ROLLED_BACK")
        for state in self.states().values():
            self.assertEqual(state["version"],"1.5.6")
        self.assertEqual(data.read_bytes(),b"OWNER DATA KEEP")

    def test_interrupted_stage_first_scope_rolls_back(self):
        with self.assertRaisesRegex(EngineError,"INJECTED_AFTER_STAGE"):
            self.coord.prepare(self.sources("1.5.7"),fault_after="protected")
        self.coord.abort(lambda:True)
        for state in self.states().values():
            self.assertEqual(state["status"],"EMPTY")

    def test_interrupted_activation_rolls_both_back(self):
        self.coord.prepare(self.sources("1.5.7"))
        with self.assertRaisesRegex(EngineError,"INJECTED_AFTER_ACTIVATE"):
            self.coord.activate(lambda:True,fault_after="protected")
        self.coord.abort(lambda:True)
        for state in self.states().values():
            self.assertEqual(state["status"],"EMPTY")

    def test_finalize_crash_after_first_commit_replays_forward(self):
        self.install("1.5.6")
        self.coord.prepare(self.sources("1.5.7"))
        self.coord.activate(lambda:True)
        with self.assertRaisesRegex(EngineError,"INJECTED_AFTER_FINALIZE"):
            self.coord.finalize(lambda:True,fault_after="protected")
        with self.assertRaisesRegex(EngineError,"FORWARD_RECOVERY_REQUIRED"):
            self.coord.abort(lambda:True)
        self.assertTrue(self.coord.path.exists())
        result=self.coord.finalize(lambda:True)
        self.assertEqual(result["status"],"PASS_BOTH_SCOPES_COMMITTED_CODE_ONLY")
        self.assertFalse(self.coord.path.exists())
        self.assertEqual({s["version"] for s in self.states().values()},
                         {"1.5.7"})

    def test_no_native_acceptance_blocks_finalization(self):
        self.coord.prepare(self.sources("1.5.7"))
        self.coord.activate(lambda:True)
        with self.assertRaisesRegex(EngineError,"NATIVE_ACCEPTANCE_NOT_PROVEN"):
            self.coord.finalize(lambda:False)
        self.assertEqual(self.coord._journal()["phase"],"activated")
        self.coord.abort(lambda:True)
        self.assertFalse(self.coord.path.exists())

    def test_unsafe_one_scope_payload_blocks_all_commit_preflight(self):
        self.install("1.5.6")
        self.coord.prepare(self.sources("1.5.7"))
        self.coord.activate(lambda:True)
        tampered=self.roots["user"]/"current"/"app"/"code.bin"
        tampered.write_bytes(b"EXTERNAL TAMPER")
        with self.assertRaisesRegex(EngineError,"INSTALLED_MANAGED_FILE_CHANGED"):
            self.coord.finalize(lambda:True)
        self.assertEqual(self.coord._journal()["phase"],"activated")
        self.assertTrue((self.roots["protected"]/
                         ".dim-engine"/"previous").exists())
        self.assertTrue((self.roots["user"]/
                         ".dim-engine"/"previous").exists())
        # Do not auto-delete or overwrite a tampered code file to clean up.

    def test_quiescence_failure_leaves_both_staged_for_safe_abort(self):
        self.coord.prepare(self.sources("1.5.7"))
        with self.assertRaisesRegex(EngineError,"NATIVE_QUIESCENCE_NOT_PROVEN"):
            self.coord.activate(lambda:False)
        self.coord.abort(lambda:True)
        self.assertFalse(self.coord.path.exists())

    def test_reject_mismatched_versions_before_any_stage(self):
        src={"user":self.package("user","1.5.7"),
             "protected":self.package("protected","1.5.6")}
        with self.assertRaisesRegex(EngineError,"NEW_VERSION_CONFLICT"):
            self.coord.prepare(src)
        self.assertFalse(self.coord.path.exists())
        for state in self.states().values():
            self.assertEqual(state["status"],"EMPTY")

    def test_reject_downgrade_before_any_stage(self):
        self.install("1.5.7")
        with self.assertRaisesRegex(EngineError,"DOWNGRADE_OR_SAME_VERSION"):
            self.coord.prepare(self.sources("1.5.7"))
        self.assertFalse(self.coord.path.exists())

    def test_prevent_recovery_with_swapped_scope_paths(self):
        self.coord.prepare(self.sources("1.5.7"))
        swapped={k:self.roots[n] for k,n in
                 (("user","protected"),("protected","user"))}
        other=TwoScopeFixtureCoordinator(self.base/"coord-state",
                                         self.platform,swapped)
        with self.assertRaisesRegex(EngineError,"COORDINATOR_PATH_TAMPERED"):
            other.abort(lambda:True)
        self.coord.abort(lambda:True)

    def test_reject_overlapping_coordinator_and_scope_roots(self):
        with self.assertRaisesRegex(EngineError,"ROOT_OVERLAP"):
            TwoScopeFixtureCoordinator(self.base/"coord-state",
                    self.platform,{"a":self.base/"coord-state"/"sub",
                                   "b":self.base/"another"})

    def test_foreign_file_in_original_code_refuses_upgrading(self):
        self.install("1.5.6")
        foreign=self.roots["protected"]/"current"/"foreign-owner.log"
        foreign.write_bytes(b"KEEP FOREVER")
        with self.assertRaisesRegex(EngineError,"FOREIGN_OR_MISSING_ACTIVE_FILES"):
            self.coord.prepare(self.sources("1.5.7"))
        self.assertFalse(self.coord.path.exists())
        self.assertEqual(foreign.read_bytes(),b"KEEP FOREVER")


if __name__=="__main__":
    unittest.main(verbosity=2)
