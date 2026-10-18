#!/usr/bin/env python3
"""Negative-first PATH-poisoning regression, only user-local subprocess fixtures."""
import importlib.util
import pathlib
import os
import tempfile
import hashlib
import stat
import subprocess
import unittest
from unittest.mock import patch
from types import SimpleNamespace

ROOT=pathlib.Path(__file__).resolve().parents[1]
CODE=ROOT / "linux/system/encrypted_selective_dns.py"
SPEC=importlib.util.spec_from_file_location("dim_r762_dns", CODE)
MOD=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class R762TrustedSystemExec(unittest.TestCase):
    def test_01_path_first_decoy_never_executes(self):
        with tempfile.TemporaryDirectory(prefix="dim-r762-sec-") as td:
            root=pathlib.Path(td)
            marker=root / "executed"
            fake=root / "resolvectl"
            fake.write_text("#!/bin/sh\\nprintf 'POISON\\n' > '"+str(marker)+"'\\n")
            fake.chmod(0o700)
            with patch.dict(os.environ, {"PATH":td+":"+os.environ.get("PATH","")}):
                result=MOD.call("resolvectl","--version",seconds=4)
            self.assertEqual(result.returncode, 0)
            self.assertFalse(marker.exists())
            self.assertNotIn("POISON", result.stdout)

    def test_02_unknown_command_name_is_rejected_before_any_spawn(self):
        with patch.object(MOD.subprocess, "run", side_effect=AssertionError("spawned")):
            with self.assertRaisesRegex(RuntimeError,"FAIL_CLOSED_UNTRUSTED_COMMAND"):
                MOD.call("malicious", "--do-not-run")

    def test_03_exact_absolute_argv_and_bounded_timeout(self):
        with patch.object(MOD.subprocess, "run",
                          return_value=SimpleNamespace(stdout="ok",stderr="",returncode=0)) as run:
            result=MOD.call("ip","-4","route","show","default",seconds=5)
        argv=run.call_args.args[0]
        self.assertEqual(argv[0], "/usr/bin/ip")
        self.assertEqual(argv[1:], ("-4","route","show","default"))
        self.assertEqual(run.call_args.kwargs["timeout"],5)
        self.assertNotIn("shell",run.call_args.kwargs)
        self.assertEqual(result.stdout,"ok")

    def test_04_every_allowed_binary_is_absolute_root_owned_not_world_writable(self):
        for label,name in MOD.TRUSTED_SYSTEM_BINARIES.items():
            path=pathlib.Path(name)
            with self.subTest(label=label):
                self.assertTrue(path.is_absolute())
                self.assertTrue(path.is_file())
                self.assertFalse(path.is_symlink())
                st=path.stat()
                self.assertEqual(st.st_uid,0)
                self.assertFalse(st.st_mode & 0o022)


if __name__ == "__main__":
    unittest.main(verbosity=2)
