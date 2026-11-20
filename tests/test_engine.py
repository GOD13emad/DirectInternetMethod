"""Platform-independent behavioral and fault-injection acceptance suite.

Only TemporaryDirectory data is mutated. No real installation or service is
accessed. Run unchanged on Windows and Linux using Python 3.10+.
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

from installer_engine.engine import Engine, EngineError, hash_file, manifest_schema

PLATFORM = "windows-x86_64" if os.name == "nt" else "linux-x86_64"


def bundle(home: Path, name: str, version: str, files: dict[str, bytes], *, target=PLATFORM):
    root = home / name
    (root / "payload").mkdir(parents=True)
    listing = []
    for path, raw in files.items():
        p = root / "payload" / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(raw)
        listing.append({"path": path, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": 0o644})
    listing.sort(key=lambda x: x["path"])
    doc = {"schema": 1, "product": "Direct Internet Method", "version": version,
           "platform": target, "files": listing}
    mf = root / "manifest.json"
    mf.write_text(json.dumps(doc, sort_keys=True), encoding="utf8")
    return root, hash_file(mf)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="dim-generic-engine-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.root = self.home / "installation"
        self.engine = Engine(self.root, PLATFORM)
        self.old, self.old_pin = bundle(self.home, "old", "1.5.6", {
            "app/main.bin": b"old program", "app/runtime.bin": b"r1"})
        self.new, self.new_pin = bundle(self.home, "new", "1.5.7", {
            "app/main.bin": b"new program", "app/runtime.bin": b"r2",
            "lib/extra.bin": b"new component"})

    def clean_install(self):
        self.engine.stage(self.old, self.old_pin)
        self.engine.activate(lambda: True)
        self.engine.commit(lambda: True)
        self.assertEqual(self.engine.verify()["version"], "1.5.6")

    def test_one_active_install_upgrade_commit_and_user_data_preserved(self):
        self.assertEqual(self.engine.verify()["status"], "EMPTY")
        self.clean_install()
        user = self.root / "data" / "user-settings.json"
        user.parent.mkdir()
        user.write_bytes(b'{"secret":"never touched"}')
        before = hash_file(user)
        staged = self.engine.stage(self.new, self.new_pin)
        self.assertEqual(staged["version"], "1.5.7")
        with self.assertRaisesRegex(EngineError, "PENDING"):
            self.engine.verify()
        with self.assertRaisesRegex(EngineError, "PRODUCT_NOT_QUIESCED"):
            self.engine.activate(lambda: False)
        self.engine.activate(lambda: True)
        with self.assertRaisesRegex(EngineError, "PLATFORM_ACCEPTANCE_REQUIRED"):
            self.engine.commit(lambda: False)
        self.engine.commit(lambda: True)
        self.assertEqual(self.engine.verify(), {"status":"PASS_INSTALLED", "version":"1.5.7", "files":3})
        self.assertFalse(self.engine.previous.exists())
        self.assertFalse(self.engine.staging.exists())
        self.assertFalse(self.engine.pending.exists())
        self.assertEqual(hash_file(user), before)
        self.assertEqual((self.root / "current" / "app" / "main.bin").read_bytes(), b"new program")

    def test_no_network_or_user_data_action(self):
        self.clean_install()
        forbidden = ["import requests", "http.client", "urllib.request", "subprocess.run", "sc.exe", "systemctl", "pkexec", "Remove-Item"]
        text = (Path(__file__).parents[1]/"installer_engine"/"engine.py").read_text()
        for word in forbidden:
            self.assertNotIn(word, text)

    def test_failure_after_old_move_recovers(self):
        self.clean_install()
        self.engine.stage(self.new, self.new_pin)
        with self.assertRaisesRegex(EngineError, "INJECTED_AFTER_OLD_MOVE"):
            self.engine.activate(lambda: True, fault="after_old_move")
        self.assertFalse(self.engine.current.exists())
        self.assertTrue(self.engine.previous.exists())
        self.assertEqual(self.engine.rollback(lambda: True)["status"], "PASS_ROLLED_BACK")
        self.assertEqual(self.engine.verify()["version"], "1.5.6")

    def test_failure_after_new_move_recovers(self):
        self.clean_install()
        self.engine.stage(self.new, self.new_pin)
        with self.assertRaisesRegex(EngineError, "INJECTED_AFTER_NEW_MOVE"):
            self.engine.activate(lambda: True, fault="after_new_move")
        self.assertTrue(self.engine.current.exists())
        self.assertTrue(self.engine.previous.exists())
        self.engine.rollback(lambda: True)
        self.assertEqual(self.engine.verify()["version"], "1.5.6")

    def test_rollback_before_activation_and_fresh_install(self):
        self.engine.stage(self.old, self.old_pin)
        self.engine.rollback(lambda: True)
        self.assertEqual(self.engine.verify()["status"], "EMPTY")
        self.engine.stage(self.old, self.old_pin)
        self.engine.activate(lambda: True)
        self.engine.rollback(lambda: True)
        self.assertEqual(self.engine.verify()["status"], "EMPTY")

    def test_replay_safe_commit_after_old_slot_already_removed(self):
        self.clean_install()
        self.engine.stage(self.new, self.new_pin)
        self.engine.activate(lambda: True)
        # Simulate a kill between the old slot cleanup and pending deletion.
        # Test explicitly removes only the verified old files.
        from installer_engine.engine import safe_remove_slot
        with self.engine.locked():
            old = self.engine._pending()["old"]["manifest"]
            safe_remove_slot(self.engine.previous, old)
        self.assertEqual(self.engine.commit(lambda: True)["status"], "PASS_COMMITTED_ONE_INSTALL")
        self.assertEqual(self.engine.verify()["version"], "1.5.7")

    def test_untrusted_managed_file_refused_without_overwriting(self):
        self.clean_install()
        original = self.root / "current" / "app" / "main.bin"
        original.write_bytes(b"owner edited code")
        with self.assertRaisesRegex(EngineError, "INSTALLED_MANAGED_FILE_CHANGED"):
            self.engine.stage(self.new, self.new_pin)
        self.assertEqual(original.read_bytes(), b"owner edited code")
        self.assertFalse(self.engine.pending.exists())

    def test_unknown_file_in_active_tree_preserved_and_refused(self):
        self.clean_install()
        unknown = self.root / "current" / "UNOWNED.txt"
        unknown.write_text("retain me")
        with self.assertRaisesRegex(EngineError, "FOREIGN_OR_MISSING_ACTIVE_FILES"):
            self.engine.stage(self.new, self.new_pin)
        self.assertEqual(unknown.read_text(), "retain me")

    def test_manifest_wrong_pin_tamper_downgrade_and_same_version(self):
        with self.assertRaisesRegex(EngineError, "MANIFEST_PIN_MISMATCH"):
            self.engine.stage(self.old, "0"*64)
        self.clean_install()
        with self.assertRaisesRegex(EngineError, "NOT_STRICTLY_NEWER"):
            self.engine.stage(self.old, self.old_pin)
        (self.new / "payload" / "app" / "main.bin").write_bytes(b"evil")
        with self.assertRaisesRegex(EngineError, "PACKAGE_FILE_SHA_MISMATCH"):
            self.engine.stage(self.new, self.new_pin)
        self.assertEqual(self.engine.verify()["version"], "1.5.6")

    def test_duplicate_malformed_json_and_portable_path_rules(self):
        path = self.home / "bad.json"
        path.write_text('{"schema":1,"schema":2}')
        from installer_engine.engine import load_json
        with self.assertRaisesRegex(EngineError, "DUPLICATE_JSON_KEY"):
            load_json(path)
        for bad in ("../evil", "c:/abs", "dir\\file", "CON", "a/NUL.txt", "foo/./bar", "app/.hidden"):
            with self.assertRaises(EngineError, msg=bad):
                manifest_schema({"schema":1,"product":"Direct Internet Method","version":"1.5.7",
                                 "platform":PLATFORM,"files":[{"path":bad,"bytes":1,"sha256":"a"*64,"mode":0o644}]})
        files = [{"path":p,"bytes":1,"sha256":"a"*64,"mode":0o644} for p in ("APP/a", "app/A")]
        with self.assertRaisesRegex(EngineError, "DUPLICATE_OR_CASEFOLD_PATH"):
            manifest_schema({"schema":1,"product":"Direct Internet Method","version":"1.5.7", "platform":PLATFORM,"files":files})

    def test_bundle_link_refused(self):
        foreign = self.home / "elsewhere.txt"
        foreign.write_bytes(b"external")
        linked = self.new / "payload" / "lib" / "extra.bin"
        linked.unlink()
        try:
            linked.symlink_to(foreign)
        except (NotImplementedError, OSError):
            self.skipTest("unprivileged Windows symlinks unavailable")
        with self.assertRaises(EngineError):
            self.engine.stage(self.new, self.new_pin)

    def test_two_processes_real_mutex_and_crash_recovery(self):
        self.clean_install()
        self.engine.stage(self.new, self.new_pin)
        helper = """
import os, sys
from pathlib import Path
from installer_engine.engine import Engine
root=Path(sys.argv[1]); plat=sys.argv[2]
original=os.rename

def abruptly_exit(src, dst):
    original(src, dst)
    if Path(dst).name == 'previous':
        os._exit(73)
os.rename=abruptly_exit
Engine(root, plat).activate(lambda: True)
"""
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).parents[1])
        p = subprocess.run([sys.executable, "-c", helper, str(self.root), PLATFORM], env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(p.returncode, 73, p.stderr.decode(errors="ignore"))
        # OS released lock after hard-exit. Explicit rollback recovers old slot.
        self.assertTrue(self.engine.previous.exists())
        self.assertFalse(self.engine.current.exists())
        self.engine.rollback(lambda: True)
        self.assertEqual(self.engine.verify()["version"], "1.5.6")

    def test_reject_wrong_runtime_target(self):
        other = "windows-x86_64" if PLATFORM.startswith("linux") else "linux-x86_64"
        with self.assertRaisesRegex(EngineError, "PLATFORM_MISMATCH"):
            self.engine.stage(*bundle(self.home, "wrong", "1.5.8", {"app/a":b"x"},target=other))


# Interrupted finalization is distinct from the original activation failure:
# the old slot was already restored, but its pending journal survived a crash.
class ReplayFinalizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='dim-replay-')
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.engine = Engine(self.home / 'installed', PLATFORM)
        self.old, self.old_pin = bundle(self.home, 'one', '1.5.6', {'app/main.bin': b'old'})
        self.new, self.new_pin = bundle(self.home, 'two', '1.5.7', {'app/main.bin': b'new'})

    def test_upgrade_rollback_replay_after_previous_restored(self):
        e = self.engine
        e.stage(self.old, self.old_pin)
        e.activate(lambda: True)
        e.commit(lambda: True)
        e.stage(self.new, self.new_pin)
        e.activate(lambda: True)
        # Crash after removing the new slot, restoring the old slot and
        # restoring the old installed.json, before removing pending.json.
        from installer_engine.engine import safe_remove_slot, atomic_json
        with e.locked():
            p = e._pending()
            safe_remove_slot(e.current, p['new']['manifest'])
            os.rename(e.previous, e.current)
            atomic_json(e.installed, p['old'])
        self.assertEqual(e.rollback(lambda: True)['status'], 'PASS_ROLLED_BACK')
        self.assertEqual(e.verify()['version'], '1.5.6')

    def test_fresh_rollback_replay_after_current_removed(self):
        e = self.engine
        e.stage(self.old, self.old_pin)
        e.activate(lambda: True)
        from installer_engine.engine import safe_remove_slot
        with e.locked():
            p = e._pending()
            safe_remove_slot(e.current, p['new']['manifest'])
        self.assertEqual(e.rollback(lambda: True)['status'], 'PASS_ROLLED_BACK')
        self.assertEqual(e.verify()['status'], 'EMPTY')

    def test_replayed_rollback_refuses_foreign_managed_data(self):
        e = self.engine
        e.stage(self.old, self.old_pin)
        e.activate(lambda: True)
        e.commit(lambda: True)
        e.stage(self.new, self.new_pin)
        e.activate(lambda: True)
        from installer_engine.engine import safe_remove_slot, atomic_json
        with e.locked():
            p = e._pending()
            safe_remove_slot(e.current, p['new']['manifest'])
            os.rename(e.previous, e.current)
            atomic_json(e.installed, p['old'])
        (e.current / 'app' / 'main.bin').write_bytes(b'user altered code')
        with self.assertRaisesRegex(EngineError, 'INSTALLED_MANAGED_FILE_CHANGED'):
            e.rollback(lambda: True)
        self.assertTrue(e.pending.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
