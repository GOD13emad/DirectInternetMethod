"""R895: hard process termination in the middle of one scope's file deletion.

No privileged service is modified; synthetic in-process acceptance callback
is a fixture and NOT authenticated native installer evidence.
"""
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


class PartialUninstallReplayTests(unittest.TestCase):
    platform = "windows-x86_64"

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="dim-r895-partial-delete-")
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.roots = {"code": self.home/"scm-code",
                      "user": self.home/"owner-code"}
        self.ledger = self.home/"coordinator"
        self.coord = TwoScopeFixtureCoordinator(
            self.ledger, self.platform, self.roots)
        self.uninstall = TwoScopeUninstallFixtureCoordinator(
            self.ledger, self.platform, self.roots)
        sources = {k:self.bundle(k) for k in self.roots}
        self.coord.prepare(sources)
        self.coord.activate(lambda: True)
        self.coord.finalize(lambda: True)
        self.data_hashes = {}
        for key, root in self.roots.items():
            target = root/"data"/"keep.settings"
            target.parent.mkdir(parents=True)
            target.write_bytes(("owner-"+key).encode())
            self.data_hashes[key] = hash_bytes(target.read_bytes())

    def bundle(self, key):
        target = self.home/("bundle-"+key)
        payload = target/"payload"/"app"
        payload.mkdir(parents=True)
        records=[]
        for filename in ("part_a.bin", "part_b.bin"):
            data=(key+filename+"1.5.7").encode()
            (payload/filename).write_bytes(data)
            records.append({"path":"app/"+filename,"bytes":len(data),
                            "sha256":hash_bytes(data),"mode":0o644})
        manifest={"schema":1,"product":"Direct Internet Method",
                  "version":"1.5.7","platform":self.platform,"files":records}
        raw=(json.dumps(manifest,sort_keys=True)+"\n").encode()
        (target/"manifest.json").write_bytes(raw)
        return (target,hash_bytes(raw))

    def hard_kill(self, stage):
        """Real immediate process death via os._exit after first unlink/rmdir."""
        repo=Path(__file__).resolve().parents[1]
        worker=r'''
import os
from pathlib import Path
import sys
from installer_engine.two_scope_uninstall import TwoScopeUninstallFixtureCoordinator
stage,ledger,code,user=sys.argv[1:]
roots={"code":Path(code),"user":Path(user)}
previous=roots["code"]/".dim-engine"/"previous"
if stage == "unlink":
    real=Path.unlink
    def fatal(self,*args,**kwargs):
        result=real(self,*args,**kwargs)
        if self==previous/"app"/"part_a.bin":
            os._exit(81)
        return result
    Path.unlink=fatal
elif stage == "rmdir":
    real=Path.rmdir
    def fatal(self,*args,**kwargs):
        result=real(self,*args,**kwargs)
        if self==previous/"app":
            os._exit(82)
        return result
    Path.rmdir=fatal
else:
    os._exit(98)
co=TwoScopeUninstallFixtureCoordinator(Path(ledger),"windows-x86_64",roots)
co.finish(lambda:True)
os._exit(99)
'''
        env=os.environ.copy()
        env["PYTHONPATH"]=str(repo)+os.pathsep+env.get("PYTHONPATH","")
        r=subprocess.run(
            [sys.executable,"-c",worker,stage,str(self.ledger),
             str(self.roots["code"]),str(self.roots["user"])],
            cwd=repo,env=env,capture_output=True,text=True,timeout=20)
        self.assertEqual(r.returncode,81 if stage=="unlink" else 82,
                         (r.stdout,r.stderr))

    def check_replay(self):
        fresh=TwoScopeUninstallFixtureCoordinator(
            self.ledger,self.platform,self.roots)
        self.assertEqual(fresh._uninstall_journal()["phase"],"finishing")
        with self.assertRaisesRegex(EngineError,"FORWARD_ONLY"):
            fresh.abort(lambda:True,lambda:True)
        self.assertEqual(fresh.finish(lambda:True)["status"],
                         "PASS_BOTH_SCOPES_CODE_ONLY_UNINSTALLED")
        self.assertFalse(fresh.uninstall_path.exists())
        for key,root in self.roots.items():
            self.assertEqual(Engine(root,self.platform).verify()["status"],"EMPTY")
            self.assertEqual(hash_bytes((root/"data"/"keep.settings").read_bytes()),
                             self.data_hashes[key])

    def test_hard_exit_mid_first_managed_file_unlink_replays_both(self):
        self.uninstall.prepare(lambda:True)
        self.hard_kill("unlink")
        first=self.roots["code"]/".dim-engine"/"previous"/"app"
        self.assertFalse((first/"part_a.bin").exists())
        self.assertTrue((first/"part_b.bin").exists())
        self.assertTrue((self.roots["user"]/".dim-engine"/"previous"/"app"/"part_a.bin").exists())
        self.check_replay()

    def test_hard_exit_after_managed_directory_rmdir_replays_both(self):
        self.uninstall.prepare(lambda:True)
        self.hard_kill("rmdir")
        self.assertFalse((self.roots["code"]/".dim-engine"/"previous"/"app").exists())
        self.check_replay()

    def test_foreign_file_after_partial_removal_refused_both_scopes(self):
        self.uninstall.prepare(lambda:True)
        self.hard_kill("unlink")
        parent=self.roots["code"]/".dim-engine"/"previous"/"app"
        foreign=parent/"UNOWNED.txt"
        foreign.write_text("KEEP ME")
        with self.assertRaisesRegex(EngineError,"FOREIGN_UNINSTALL_RESIDUAL_FILE"):
            self.uninstall.finish(lambda:True)
        self.assertEqual(foreign.read_text(),"KEEP ME")
        self.assertTrue((self.roots["user"]/".dim-engine"/"previous"/"app"/"part_a.bin").exists())
        self.assertTrue(self.uninstall.uninstall_path.exists())

    def test_surviving_file_tamper_refuses_replay(self):
        self.uninstall.prepare(lambda:True)
        self.hard_kill("unlink")
        surviving=self.roots["code"]/".dim-engine"/"previous"/"app"/"part_b.bin"
        surviving.write_bytes(b"FOREIGN MUTATION")
        with self.assertRaisesRegex(EngineError,"UNINSTALL_RESIDUAL_FILE_CHANGED"):
            self.uninstall.finish(lambda:True)
        self.assertEqual(surviving.read_bytes(),b"FOREIGN MUTATION")
        self.assertTrue((self.roots["user"]/".dim-engine"/"previous"/"app"/"part_a.bin").exists())

    def test_foreign_empty_directory_after_partial_removal_refused(self):
        self.uninstall.prepare(lambda:True)
        self.hard_kill("unlink")
        extra=self.roots["code"]/".dim-engine"/"previous"/"foreign_empty"
        extra.mkdir()
        with self.assertRaisesRegex(EngineError,"FOREIGN_UNINSTALL_RESIDUAL_DIRECTORY"):
            self.uninstall.finish(lambda:True)
        self.assertTrue(extra.is_dir())

    def test_missing_preacceptance_file_does_not_justify_deletion(self):
        self.uninstall.prepare(lambda:True)
        missing=self.roots["user"]/".dim-engine"/"previous"/"app"/"part_a.bin"
        missing.unlink()
        with self.assertRaisesRegex(EngineError,"FOREIGN_OR_MISSING_ACTIVE_FILES"):
            self.uninstall.finish(lambda:True)
        self.assertEqual(self.uninstall._uninstall_journal()["phase"],"prepared")
        self.assertTrue((self.roots["code"]/".dim-engine"/"previous"/"app"/"part_a.bin").exists())

    @unittest.skipUnless(os.name == "posix", "symlink creation requires POSIX fixture")
    def test_symlink_inserted_after_partial_removal_is_refused(self):
        self.uninstall.prepare(lambda:True)
        self.hard_kill("unlink")
        external=self.home/"foreign.txt"
        external.write_text("FOREIGN")
        link=self.roots["code"]/".dim-engine"/"previous"/"app"/"link"
        link.symlink_to(external)
        with self.assertRaises(EngineError):
            self.uninstall.finish(lambda:True)
        self.assertEqual(external.read_text(),"FOREIGN")


if __name__=="__main__":
    unittest.main()
