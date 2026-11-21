"""R893 cross-platform crash/abort/replay tests for coordinated code uninstall."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from installer_engine.engine import Engine, EngineError, hash_bytes
from installer_engine.two_scope import TwoScopeFixtureCoordinator
from installer_engine.two_scope_uninstall import TwoScopeUninstallFixtureCoordinator


class CoordinatedUninstallTests(unittest.TestCase):
    platform = "windows-x86_64"

    def setUp(self):
        td = tempfile.TemporaryDirectory(prefix="dim-r893-uninstall-")
        self.addCleanup(td.cleanup)
        self.base = Path(td.name)
        self.roots = {"code": self.base/"managed-code",
                      "user": self.base/"managed-user-code"}
        self.ledger = self.base/"coord"
        self.installer = TwoScopeFixtureCoordinator(
            self.ledger, self.platform, self.roots)
        self.uninstaller = TwoScopeUninstallFixtureCoordinator(
            self.ledger, self.platform, self.roots)
        self.install("1.5.7")
        self.owned = {}
        for name, root in self.roots.items():
            p = root/"data"/"settings"
            p.parent.mkdir(parents=True)
            p.write_bytes(b"owner-data-r893-"+name.encode())
            self.owned[name] = hash_bytes(p.read_bytes())

    def package(self, name, ver):
        base = self.base/(name+"_"+ver.replace(".", "_"))
        target = base/"payload"/"app"/"program.bin"
        target.parent.mkdir(parents=True)
        data = ("fixture-"+name+"-"+ver).encode()
        target.write_bytes(data)
        doc = {"schema": 1, "product": "Direct Internet Method",
               "version": ver, "platform": self.platform,
               "files": [{"path": "app/program.bin", "sha256": hash_bytes(data),
                          "bytes": len(data), "mode": 0o644}]}
        raw = (json.dumps(doc, sort_keys=True, separators=(",", ":"))+"\n").encode()
        (base/"manifest.json").write_bytes(raw)
        return base, hash_bytes(raw)

    def install(self, ver):
        sources = {name:self.package(name, ver) for name in self.roots}
        self.installer.prepare(sources)
        self.installer.activate(lambda: True)
        self.installer.finalize(lambda: True)

    def check_owner(self):
        for name, root in self.roots.items():
            self.assertEqual(hash_bytes((root/"data"/"settings").read_bytes()),
                             self.owned[name])

    def check_old(self):
        for path in self.roots.values():
            self.assertEqual(Engine(path,self.platform).verify()["version"],"1.5.7")
        self.check_owner()

    def check_empty(self):
        for path in self.roots.values():
            self.assertEqual(Engine(path,self.platform).verify()["status"],"EMPTY")
        self.check_owner()

    def test_happy_path_prepare_then_native_unregister_then_finish(self):
        self.uninstaller.prepare(lambda: True)
        self.assertEqual(self.uninstaller._uninstall_journal()["phase"],"prepared")
        self.assertEqual(self.uninstaller.finish(lambda: True)["status"],
                         "PASS_BOTH_SCOPES_CODE_ONLY_UNINSTALLED")
        self.check_empty()
        self.assertFalse(self.uninstaller.uninstall_path.exists())

    def test_abort_partial_prepare_restores_both(self):
        with self.assertRaisesRegex(EngineError, "INJECTED_AFTER_UNINSTALL_PREPARE_code"):
            self.uninstaller.prepare(lambda: True, fault_after="code")
        self.assertEqual(self.uninstaller._uninstall_journal()["phase"],"preparing")
        self.uninstaller.abort(lambda: True, lambda: True)
        self.check_old()
        self.assertFalse(self.uninstaller.uninstall_path.exists())

    def test_abort_both_prepared_restores_both(self):
        self.uninstaller.prepare(lambda: True)
        self.uninstaller.abort(lambda: True, lambda: True)
        self.check_old()

    def test_no_external_registration_prevents_abort(self):
        self.uninstaller.prepare(lambda: True)
        with self.assertRaisesRegex(EngineError, "NATIVE_REGISTRATION_NOT_PRESENT"):
            self.uninstaller.abort(lambda: True, lambda: False)
        self.assertEqual(self.uninstaller._uninstall_journal()["phase"],"prepared")

    def test_no_external_unregistration_prevents_finish(self):
        self.uninstaller.prepare(lambda: True)
        with self.assertRaisesRegex(EngineError, "NATIVE_NOT_UNREGISTERED"):
            self.uninstaller.finish(lambda: False)
        self.assertEqual(self.uninstaller._uninstall_journal()["phase"],"prepared")

    def test_fresh_process_replays_after_first_irreversible_cleanup(self):
        self.uninstaller.prepare(lambda: True)
        with self.assertRaisesRegex(EngineError,"INJECTED_AFTER_UNINSTALL_FINISH_code"):
            self.uninstaller.finish(lambda: True, fault_after="code")
        self.assertEqual(self.uninstaller._uninstall_journal()["phase"],"finishing")
        with self.assertRaisesRegex(EngineError,"FORWARD_ONLY"):
            self.uninstaller.abort(lambda: True, lambda: True)
        again = TwoScopeUninstallFixtureCoordinator(
            self.ledger, self.platform, self.roots)
        self.assertEqual(again.finish(lambda: True)["status"],
                         "PASS_BOTH_SCOPES_CODE_ONLY_UNINSTALLED")
        self.check_empty()

    def test_wrong_native_state_on_replay_keeps_journal(self):
        self.uninstaller.prepare(lambda: True)
        with self.assertRaisesRegex(EngineError,"INJECTED_AFTER_UNINSTALL_FINISH_code"):
            self.uninstaller.finish(lambda: True,fault_after="code")
        with self.assertRaisesRegex(EngineError, "NATIVE_NOT_UNREGISTERED"):
            self.uninstaller.finish(lambda: False)
        self.assertTrue(self.uninstaller.uninstall_path.exists())

    def test_second_scope_tamper_prevents_first_scope_irreversible_delete(self):
        self.uninstaller.prepare(lambda: True)
        bad = self.roots["user"]/".dim-engine"/"previous"/"app"/"program.bin"
        # The previous managed code slot is internal to .dim-engine.
        self.assertTrue(bad.exists())
        bad.write_bytes(b"FOREIGN_TAMPER")
        with self.assertRaisesRegex(EngineError,"INSTALLED_MANAGED_FILE_CHANGED"):
            self.uninstaller.finish(lambda: True)
        self.assertEqual(self.uninstaller._uninstall_journal()["phase"],"prepared")
        self.assertTrue((self.roots["code"]/".dim-engine"/"previous"/"app"/"program.bin").exists())

    def test_cross_scope_version_drift_blocks_journal_creation(self):
        # Two individually valid but different installed versions are still
        # not one acceptable globally-coherent uninstall transaction.
        e = Engine(self.roots["user"], self.platform)
        bundle, pin = self.package("user", "1.5.8")
        e.stage(bundle, pin)
        e.activate(lambda: True)
        e.commit(lambda: True)
        with self.assertRaisesRegex(EngineError, "UNINSTALL_VERSION_DRIFT"):
            self.uninstaller.prepare(lambda: True)
        self.assertFalse(self.uninstaller.uninstall_path.exists())
        self.assertEqual(
            Engine(self.roots["code"], self.platform).verify()["version"],
            "1.5.7")
        self.assertEqual(e.verify()["version"], "1.5.8")

    def test_upgrade_coordinator_blocks_uninstall(self):
        src={name:self.package(name,"1.5.8") for name in self.roots}
        self.installer.prepare(src)
        with self.assertRaisesRegex(EngineError,"COORDINATOR_UPGRADE_ACTIVE"):
            self.uninstaller.prepare(lambda: True)
        self.installer.abort(lambda: True)
        self.check_old()

    def test_swapped_scopes_cannot_resume_foreign_uninstall(self):
        self.uninstaller.prepare(lambda: True)
        swapped={"code":self.roots["user"],"user":self.roots["code"]}
        wrong = TwoScopeUninstallFixtureCoordinator(self.ledger, self.platform, swapped)
        with self.assertRaisesRegex(EngineError,"PATH_CHANGED"):
            wrong.finish(lambda: True)
        self.uninstaller.abort(lambda: True, lambda: True)
        self.check_old()

    def test_quiescence_false_refuses_journal(self):
        with self.assertRaisesRegex(EngineError,"SERVICE_NOT_QUIESCENT"):
            self.uninstaller.prepare(lambda: False)
        self.assertFalse(self.uninstaller.uninstall_path.exists())
        self.check_old()

    def test_other_scope_isnt_silently_swept(self):
        self.uninstaller.prepare(lambda: True)
        foreign=self.roots["user"]/".dim-engine"/"previous"/"foreign-owner.txt"
        foreign.write_text("DO_NOT_TOUCH")
        with self.assertRaises(EngineError):
            self.uninstaller.finish(lambda: True)
        self.assertEqual(foreign.read_text(),"DO_NOT_TOUCH")
        self.assertTrue((self.roots["code"]/".dim-engine"/"previous"/"app"/"program.bin").exists())

    def test_malformed_journal_fails_closed_without_file_change(self):
        self.uninstaller.prepare(lambda: True)
        doc=json.loads(self.uninstaller.uninstall_path.read_text())
        doc["scopes"][0]["path"]=str(self.base/"foreign")
        from installer_engine.engine import atomic_json
        atomic_json(self.uninstaller.uninstall_path,doc)
        with self.assertRaisesRegex(EngineError,"PATH_CHANGED"):
            self.uninstaller.finish(lambda: True)
        self.assertTrue((self.roots["code"]/".dim-engine"/"previous"/"app"/"program.bin").exists())


    def _crash_worker(self, action):
        """Hard process exit AFTER a real Engine filesystem mutation.

        No exception handler, atexit, or Python resource cleanup in the
        worker; the parent is a fresh coordinator process and must recover.
        """
        root = Path(__file__).resolve().parents[1]
        code = r'''
import os
from pathlib import Path
import sys
from installer_engine.engine import Engine
from installer_engine.two_scope_uninstall import TwoScopeUninstallFixtureCoordinator
op, ledger, code_root, user_root = sys.argv[1:]
roots = {"code": Path(code_root), "user": Path(user_root)}
method = "prepare_uninstall" if op == "prepare" else "finish_uninstall"
prior = getattr(Engine, method)
def interrupted(self, *a, **kw):
    result = prior(self, *a, **kw)
    if self.root == roots["code"]:
        os._exit(71 if op == "prepare" else 72)
    return result
setattr(Engine, method, interrupted)
co = TwoScopeUninstallFixtureCoordinator(Path(ledger), "windows-x86_64", roots)
if op == "prepare":
    co.prepare(lambda: True)
else:
    co.finish(lambda: True)
sys.exit(99)
'''
        env = os.environ.copy()
        env["PYTHONPATH"] = (str(root) + os.pathsep + env.get("PYTHONPATH", ""))
        out = subprocess.run(
            [sys.executable, "-c", code, action, str(self.ledger),
             str(self.roots["code"]), str(self.roots["user"])],
            cwd=root, env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(out.returncode, 71 if action == "prepare" else 72,
                         (out.stdout, out.stderr))

    def test_hard_process_exit_after_first_prepare_recover_abort(self):
        self._crash_worker("prepare")
        self.assertEqual(self.uninstaller._uninstall_journal()["phase"], "preparing")
        fresh = TwoScopeUninstallFixtureCoordinator(
            self.ledger, self.platform, self.roots)
        fresh.abort(lambda: True, lambda: True)
        self.check_old()
        self.assertFalse(fresh.uninstall_path.exists())

    def test_hard_process_exit_after_first_finish_recover_forward(self):
        self.uninstaller.prepare(lambda: True)
        self._crash_worker("finish")
        self.assertEqual(self.uninstaller._uninstall_journal()["phase"], "finishing")
        self.assertEqual(
            Engine(self.roots["code"], self.platform).verify()["status"], "EMPTY")
        fresh = TwoScopeUninstallFixtureCoordinator(
            self.ledger, self.platform, self.roots)
        with self.assertRaisesRegex(EngineError, "UNINSTALL_FORWARD_ONLY"):
            fresh.abort(lambda: True, lambda: True)
        fresh.finish(lambda: True)
        self.check_empty()
        self.assertFalse(fresh.uninstall_path.exists())


if __name__ == "__main__":
    unittest.main()
