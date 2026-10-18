#!/usr/bin/env python3
"""R747 GUI opt-in contract: real production Window methods, no GTK or network.

The opt-in SOCKS process is never created by Application/Window constructor;
only a clicked Start action may create it. Close must dispose it and restore
control state. No system/root/Tailscale/browser proxy settings are touched.
"""
from __future__ import annotations

import ast
import pathlib
import types
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE=(ROOT/"linux/app/direct_internet_method.py").read_text("utf-8")
APP=ast.parse(SOURCE)
WINDOW=next(n for n in APP.body if isinstance(n,ast.ClassDef) and n.name=="Window")
METHODS={n.name:n for n in WINDOW.body if isinstance(n,ast.FunctionDef)}
NEED=("on_local_socket_start","on_local_socket_stop","close_local_socket","on_action")
assert all(n in METHODS for n in NEED),"R747_REQUIRED_GUI_CONTROLS_MISSING"
BODY=ast.unparse(next(x for x in WINDOW.body if x.name=="__init__"))
assert "self.local_socket_bridge = None" in BODY
assert 'self.local_socket_start_button.connect(' in BODY and 'self.on_local_socket_start' in BODY
assert 'self.local_socket_stop_button.connect(' in BODY and 'self.on_local_socket_stop' in BODY
assert 'self.connect(' in BODY and 'self.close_local_socket' in BODY
assert "candidate.start()" not in BODY and "LocalSocketFallback()" not in BODY
assert "self.local_socket_bridge" in SOURCE
assert "SOCKS5 127.0.0.1" in SOURCE
assert "action == 'start'" in ast.unparse(METHODS["on_action"])
assert "on_local_socket_start" in SOURCE

class Button:
    def __init__(self):self.enabled=None
    def set_sensitive(self,v):self.enabled=bool(v)

class Label:
    def __init__(self):self.value=""
    def set_text(self,s):self.value=str(s)

class State:
    symlink=False
    present=False
    def is_symlink(self):return self.symlink
    def exists(self):return self.present

class TestGUI(unittest.TestCase):
    def setUp(self):
        self.state=State()
        self.tunnel=False
        self.starts=0
        self.stops=0
        self.should_fail=False
        testcase=self
        class Local:
            def __init__(self):pass
            def start(self):
                testcase.starts+=1
                if testcase.should_fail:raise RuntimeError("TEST_BIND_ERROR")
                return 47321
            def stop(self):testcase.stops+=1
        env={"STATE":self.state,"_external_tunnel_active":lambda:self.tunnel,
             "LocalSocketFallback":Local,"ui_test_log":lambda *args:None}
        sub=ast.Module(body=[METHODS[n] for n in NEED],type_ignores=[])
        exec(compile(sub,"r747_actual_GUI_methods","exec"),env)
        self.env=env
        self.window=types.SimpleNamespace(
            local_socket_bridge=None,
            local_socket_start_button=Button(),local_socket_stop_button=Button(),
            local_socket_status=Label(),result=Label(),
        )
        for name in NEED:
            setattr(self.window,name,types.MethodType(env[name],self.window))

    def test_01_direct_user_click_is_only_activation(self):
        self.assertEqual(self.starts,0)
        self.window.on_local_socket_start()
        self.assertEqual(self.starts,1)
        self.assertIsNotNone(self.window.local_socket_bridge)
        self.assertFalse(self.window.local_socket_start_button.enabled)
        self.assertTrue(self.window.local_socket_stop_button.enabled)
        self.assertIn("127.0.0.1:47321",self.window.local_socket_status.value)
        self.assertIn("manual",SOURCE.lower())

    def test_02_explicit_stop_disposes_single_instance(self):
        self.window.on_local_socket_start()
        self.window.on_local_socket_stop()
        self.assertEqual(self.stops,1)
        self.assertIsNone(self.window.local_socket_bridge)
        self.assertTrue(self.window.local_socket_start_button.enabled)
        self.assertFalse(self.window.local_socket_stop_button.enabled)
        self.window.on_local_socket_stop()
        self.assertEqual(self.stops,1)

    def test_03_close_disposes_session_without_admin(self):
        self.window.on_local_socket_start()
        self.assertIs(self.window.close_local_socket(),False)
        self.assertEqual(self.stops,1)
        self.assertIsNone(self.window.local_socket_bridge)

    def test_04_reentrant_start_does_not_create_duplicate_listener(self):
        self.window.on_local_socket_start()
        self.window.on_local_socket_start()
        self.assertEqual(self.starts,1)

    def test_05_conflicting_main_engine_denies_fallback(self):
        self.state.present=True
        self.window.on_local_socket_start()
        self.assertEqual(self.starts,0)
        self.assertIn("OFF",self.window.local_socket_status.value)

    def test_06_symlink_engine_state_denies_fallback(self):
        self.state.symlink=True
        self.window.on_local_socket_start()
        self.assertEqual(self.starts,0)

    def test_07_external_tunnel_denies_fallback(self):
        self.tunnel=True
        self.window.on_local_socket_start()
        self.assertEqual(self.starts,0)

    def test_08_startup_error_does_not_leave_owned_listener(self):
        self.should_fail=True
        self.window.on_local_socket_start()
        self.assertEqual(self.starts,1)
        self.assertEqual(self.stops,1)
        self.assertIsNone(self.window.local_socket_bridge)
        self.assertIn("TEST_BIND_ERROR",self.window.local_socket_status.value)

    def test_09_normal_system_start_denied_while_local_proxy_active(self):
        self.window.on_local_socket_start()
        self.window.on_action(None,"start")
        self.assertIn("Stop the optional local SOCKS5",self.window.result.value)

    def test_10_no_global_proxy_writes_or_automatic_third_party_bundle(self):
        for bad in ("gsettings set org.gnome.system.proxy",
                    "network.proxy.socks_host =",
                    "xdg-settings set default-web-browser",
                    "pkexec /usr/bin","sudo /usr/bin",
                    "os.environ['ALL_PROXY']",
                    "os.environ['HTTPS_PROXY']"):
            self.assertNotIn(bad,SOURCE)
        self.assertIn("from socket_fallback import LocalSocketFallback",SOURCE)

if __name__=="__main__":
    unittest.main(verbosity=1)
    print("R747_GUI_OPTIN_START_STOP_CLOSE_NO_SYSTEM_PROXY_10_TESTS_PASS")
