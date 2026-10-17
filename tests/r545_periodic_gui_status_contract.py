#!/usr/bin/env python3
"""Isolated negative-first source-extracted GUI status timer regression.

Does not import GTK or run a service, subprocess, DNS, route, network request,
user setting or privileged command. Only original AST methods are executed.
"""
import ast
from pathlib import Path
import types
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/"linux/app/direct_internet_method.py").read_text(encoding="utf-8")
TREE=ast.parse(SOURCE)
WINDOW=next(x for x in TREE.body if isinstance(x,ast.ClassDef) and x.name=="Window")
names={"refresh","periodic_state_tick","stop_status_timer"}
funcs=[n for n in WINDOW.body if isinstance(n,ast.FunctionDef) and n.name in names]
assert {f.name for f in funcs}==names
INIT=next(n for n in WINDOW.body if isinstance(n,ast.FunctionDef) and n.name=="__init__")
init=ast.get_source_segment(SOURCE,INIT)
assert 'GLib.timeout_add_seconds(15,self.periodic_state_tick)' in init
assert 'self.connect("close-request",self.stop_status_timer)' in init

class Label:
    def __init__(self,text=""):self.text=text
    def get_text(self):return self.text
    def set_text(self,text):self.text=text
    def remove_css_class(self,*_):pass
    def add_css_class(self,*_):pass

class Button:
    def __init__(self):self.enabled=None
    def set_sensitive(self,v):self.enabled=v
    def remove_css_class(self,*_):pass
    def add_css_class(self,*_):pass

class FakeGLib:
    removed=[]
    @classmethod
    def source_remove(cls,i):cls.removed.append(i)

class ForbiddenThread:
    def __init__(self,*_,**__):raise AssertionError("PERIODIC_REFRESH_MUST_NOT_SPAWN_WEB_PROBES")

_state=[{"mode":"ACTIVE","detail":"ok"}]
def read_state():
    if isinstance(_state[0],Exception):raise _state[0]
    return _state[0]
env={"load_state":read_state,"GLib":FakeGLib,"threading":types.SimpleNamespace(Thread=ForbiddenThread)}
exec(compile(ast.Module(body=funcs,type_ignores=[]),"original_gui_methods","exec"),env)

class Dummy:
    def __init__(self,mode="ACTIVE",detail="ok"):
        self.status=Label("Status: "+mode)
        self.detail=Label(detail)
        self.gemini_live=Label("Gemini: previous")
        self.adult_live=Label("Adult coverage: previous")
        self.live_check_generation=0
        self.adult_check_enabled=True
        self.buttons={k:Button() for k in ("start","stop","recovery","refresh","update")}
        self.refresh=types.MethodType(env["refresh"],self)
        self.periodic_state_tick=types.MethodType(env["periodic_state_tick"],self)
        self.stop_status_timer=types.MethodType(env["stop_status_timer"],self)
        self._status_timer_id=0

class TimerContract(unittest.TestCase):
    def test_01_stable_active_no_repeated_live_probe(self):
        _state[0]={"mode":"ACTIVE","detail":"ok"}
        d=Dummy()
        self.assertTrue(d.periodic_state_tick())
        self.assertEqual(d.live_check_generation,0)
        self.assertEqual(d.gemini_live.get_text(),"Gemini: previous")
    def test_02_physical_route_drift_marks_stale_and_disables_start(self):
        _state[0]={"mode":"STALE","detail":"wlp2s0 differs from enp1s0"}
        d=Dummy()
        self.assertTrue(d.periodic_state_tick())
        self.assertEqual(d.status.get_text(),"Status: STALE")
        self.assertFalse(d.buttons["start"].enabled)
        self.assertTrue(d.buttons["recovery"].enabled)
        self.assertIn("enp1s0",d.detail.get_text())
        self.assertEqual(d.live_check_generation,1)
    def test_03_stale_detail_change_does_not_start_probes(self):
        _state[0]={"mode":"STALE","detail":"now no route"}
        d=Dummy("STALE","old route")
        self.assertTrue(d.periodic_state_tick())
        self.assertEqual(d.detail.get_text(),"now no route")
        self.assertEqual(d.live_check_generation,0)
    def test_04_auto_recovery_active_no_background_web_checks(self):
        _state[0]={"mode":"ACTIVE","detail":"route recovered"}
        d=Dummy("STALE","was stale")
        self.assertTrue(d.periodic_state_tick())
        self.assertEqual(d.status.get_text(),"Status: ACTIVE")
        self.assertIn("Press Refresh",d.gemini_live.get_text())
        self.assertFalse(d.buttons["start"].enabled)
    def test_05_state_read_error_is_fail_closed(self):
        _state[0]=RuntimeError("synthetic read failure")
        d=Dummy()
        self.assertTrue(d.periodic_state_tick())
        self.assertEqual(d.status.get_text(),"Status: STALE")
        self.assertFalse(d.buttons["start"].enabled)
        self.assertTrue(d.buttons["recovery"].enabled)
    def test_06_close_removes_only_owned_timer_once(self):
        FakeGLib.removed=[]
        d=Dummy()
        d._status_timer_id=4321
        self.assertFalse(d.stop_status_timer())
        self.assertFalse(d.stop_status_timer())
        self.assertEqual(FakeGLib.removed,[4321])
        self.assertEqual(d._status_timer_id,0)

if __name__=="__main__":
    res=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(TimerContract))
    print("R545_PERIODIC_GUI_STATUS cases=",res.testsRun,"failures=",len(res.failures),"errors=",len(res.errors))
    raise SystemExit(0 if res.wasSuccessful() else 1)
