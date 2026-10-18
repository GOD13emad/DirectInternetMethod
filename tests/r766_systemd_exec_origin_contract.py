#!/usr/bin/env python3
"""Unprivileged R766 hostile command-origin tests; never spawn systemctl."""
import importlib.util
import pathlib
import unittest
from unittest.mock import patch
from types import SimpleNamespace

TARGET=pathlib.Path(__file__).with_name("r566_native_systemd_persistent_catchup.py")
s=importlib.util.spec_from_file_location("dim_r766_sysctl",TARGET)
m=importlib.util.module_from_spec(s)
s.loader.exec_module(m)

class TrustedSystemctlOnly(unittest.TestCase):
    def _no_spawn(self,*args):
        with patch.object(m.subprocess,"run",side_effect=AssertionError("UNEXPECTED_SUBPROCESS_EXECUTION")) as mocked:
            with self.assertRaisesRegex(RuntimeError,"R566_SYSTEMD_FAIL_CLOSED_"):
                m.run(*args)
            mocked.assert_not_called()

    def test_non_systemctl_executable_never_spawns(self):
        self._no_spawn("/bin/sh","-c","echo NOT_EXECUTED")

    def test_non_owned_target_unit_never_spawns(self):
        self._no_spawn("/usr/bin/systemctl","start","../../other.service")

    def test_show_of_privileged_property_never_spawns(self):
        self._no_spawn("/usr/bin/systemctl","show","dim-r566-catchup-123.timer",
                       "-p","ExecStart","--value")

    def test_valid_expected_commands_still_use_argv(self):
        valid=[
            ("/usr/bin/systemctl","daemon-reload"),
            ("/usr/bin/systemctl","start","dim-r566-catchup-123.timer"),
            ("/usr/bin/systemctl","stop","dim-r566-catchup-123.timer"),
            ("/usr/bin/systemctl","show","dim-r566-catchup-123.timer","-p","ActiveState","--value")
        ]
        with patch.object(m.subprocess,"run",return_value=SimpleNamespace(returncode=0,stdout="active\n",stderr="")) as mocked:
            for args in valid:
                self.assertEqual(m.run(*args),"active")
            self.assertEqual(mocked.call_count,len(valid))
            for call,args in zip(mocked.call_args_list,valid):
                self.assertEqual(call.args[0],args)
                self.assertNotIn("shell",call.kwargs)

if __name__=="__main__":
    unittest.main(verbosity=2)
