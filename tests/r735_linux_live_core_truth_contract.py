#!/usr/bin/env python3
"""R735: the native Linux GUI must not turn green from engine ownership alone.

Production AST-extracted Window methods are executed with synthetic health and
route state, never with real GTK, network, DNS, services or user settings.
"""
import ast
import concurrent.futures
import json
import pathlib
import threading
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "linux/app/direct_internet_method.py").read_text("utf-8")
TREE = ast.parse(SOURCE)
WINDOW = next(n for n in TREE.body if isinstance(n, ast.ClassDef) and n.name == "Window")
METHODS = {n.name: n for n in WINDOW.body if isinstance(n, ast.FunctionDef)}
NAMES = {"refresh", "periodic_state_tick", "finish_core_checks", "live_checks_worker"}
assert NAMES <= METHODS.keys(), "R735_PRODUCTION_GUI_CORE_SITE_HEALTH_METHODS_MISSING"
assert "R735_GUI_NO_UNVERIFIED_GREEN" in SOURCE, "R735_PRODUCTION_GREEN_GUARD_MISSING"

class Label:
    def __init__(self, text=""):
        self.value = text
        self.classes = set()
    def set_text(self, text):
        self.value = str(text)
    def get_text(self):
        return self.value
    def remove_css_class(self, x):
        self.classes.discard(x)
    def add_css_class(self, x):
        self.classes.add(x)

class Button:
    def __init__(self):
        self.enabled = False
    def set_sensitive(self, v):
        self.enabled = bool(v)
    def remove_css_class(self, *_):
        pass
    def add_css_class(self, *_):
        pass

STATE_DOC = [{"mode": "ACTIVE", "detail": "Backend owns nft"}]
ACTUAL = [{"physicalInterface": "enp1s0", "selectiveDns": False, "selectiveDnsEncrypted": False}]
CALLS = []
QUEUED = []
def fake_probe(url, iface, allowed):
    CALLS.append((url, iface, tuple(sorted(allowed))))
    code = {"https://www.youtube.com/": "200",
            "https://www.youtube.com/generate_204": "204",
            "https://api.openai.com/v1/models": "401",
            "https://github.com/": "200",
            "https://gemini.google.com/": "200"}[url]
    return {"ok": code in allowed, "reached": True, "code": code}

class FakeStatePath:
    def read_text(self, encoding="utf-8"):
        return json.dumps(ACTUAL[0])

class GLib:
    @staticmethod
    def idle_add(fn, *args):
        QUEUED.append((fn, args))
        return 1

class NoThread:
    def __init__(self, *args, **kwargs):
        raise AssertionError("R735_PERIODIC_BACKGROUND_WEB_PROBE_FORBIDDEN")

def read_state():
    if isinstance(STATE_DOC[0], Exception):
        raise STATE_DOC[0]
    return STATE_DOC[0]

env = {
    "load_state": read_state, "STATE": FakeStatePath(),
    "json": json, "GLib": GLib, "probe_url": fake_probe,
    "format_probe": lambda name, result: name + ": " + ("PASS" if result["ok"] else "FAIL"),
    "format_adult_probes": lambda results: "Adult coverage: disabled",
    "threading": types.SimpleNamespace(Thread=NoThread),
    "ThreadPoolExecutor": concurrent.futures.ThreadPoolExecutor,
}
exec(compile(ast.Module(body=[METHODS[n] for n in sorted(NAMES)], type_ignores=[]),
             "r735_real_source_methods", "exec"), env)

class Dummy:
    def __init__(self, mode="ACTIVE"):
        self.status = Label("Status: " + mode)
        self.detail = Label("Backend owns nft")
        self.gemini_live = Label("Gemini: unverified")
        self.adult_live = Label("Adult coverage: Disabled")
        self.core_live = Label("Core HTTPS: unverified")
        self.live_check_generation = 17
        self.adult_check_enabled = False
        self.finish_live_checks = lambda *args: False
        self.buttons = {n: Button() for n in ("start", "stop", "recovery", "refresh", "update")}
        self.buttons["stop"].enabled = True
        for n in NAMES:
            setattr(self, n, types.MethodType(env[n], self))

def core(*, home=True, light=True, openai=True, github=True, selected=False):
    return {
        "youtube": {"ok": home, "code": "200" if home else "000"},
        "youtube204": None if selected else {"ok": light, "code": "204" if light else "000"},
        "openai": {"ok": openai, "code": "401" if openai else "000"},
        "github": {"ok": github, "code": "200" if github else "000"},
        "selected_dns": selected,
    }

class Contract(unittest.TestCase):
    def setUp(self):
        STATE_DOC[0] = {"mode": "ACTIVE", "detail": "Backend owns nft"}
        ACTUAL[0] = {"physicalInterface": "enp1s0", "selectiveDns": False, "selectiveDnsEncrypted": False}
        CALLS.clear()
        QUEUED.clear()
    def test_01_engine_active_starts_unverified_not_green(self):
        d=Dummy()
        d.refresh(state=STATE_DOC[0], start_checks=False)
        self.assertEqual(d.status.get_text(), "Status: ACTIVE")
        self.assertNotIn("success", d.status.classes)
        self.assertIn("warning", d.status.classes)
        self.assertTrue(d.buttons["stop"].enabled)
        self.assertFalse(d.buttons["start"].enabled)
    def test_02_complete_core_https_proofs_required_for_green(self):
        d=Dummy()
        d.finish_core_checks(17, core())
        self.assertEqual(d.status.get_text(), "Status: ACTIVE")
        self.assertIn("success", d.status.classes)
        self.assertIn("healthy", d.core_live.get_text().lower())
    def test_03_lightweight_success_cannot_hide_youtube_home_failure(self):
        d=Dummy()
        d.finish_core_checks(17, core(home=False, light=True))
        self.assertEqual(d.status.get_text(), "Status: PARTIAL")
        self.assertNotIn("success", d.status.classes)
        self.assertIn("warning", d.status.classes)
        self.assertTrue(d.buttons["stop"].enabled)
        self.assertFalse(d.buttons["start"].enabled)
    def test_04_page_success_cannot_hide_lightweight_failure(self):
        d=Dummy()
        d.finish_core_checks(17, core(home=True,light=False))
        self.assertEqual(d.status.get_text(), "Status: PARTIAL")
    def test_05_selected_dns_preserves_original_page_only_gate(self):
        d=Dummy()
        d.finish_core_checks(17, core(selected=True))
        self.assertIn("success",d.status.classes)
    def test_13_missing_or_malformed_lightweight_proof_is_partial(self):
        d=Dummy()
        payload=core()
        payload["youtube204"]=None
        d.finish_core_checks(17,payload)
        self.assertEqual(d.status.get_text(),"Status: PARTIAL")
        self.assertIn("warning",d.status.classes)
    def test_14_missing_worker_proof_fails_closed(self):
        d=Dummy()
        d.finish_core_checks(17,{"error":"CORE_PROBE_FAILED"})
        self.assertEqual(d.status.get_text(),"Status: PARTIAL")
        self.assertNotIn("success",d.status.classes)
    def test_06_stale_generation_rejected(self):
        d=Dummy()
        d.finish_core_checks(16,core())
        self.assertEqual(d.status.get_text(), "Status: ACTIVE")
        self.assertNotIn("success", d.status.classes)
    def test_07_stale_after_stop_rejected(self):
        d=Dummy()
        STATE_DOC[0]={"mode":"OFF","detail":"Clean"}
        d.finish_core_checks(17,core())
        self.assertNotIn("success",d.status.classes)
    def test_08_partial_persists_periodic_observation_without_network(self):
        d=Dummy()
        d.finish_core_checks(17,core(home=False))
        self.assertEqual(d.status.get_text(),"Status: PARTIAL")
        self.assertTrue(d.periodic_state_tick())
        self.assertEqual(d.status.get_text(),"Status: PARTIAL")
        self.assertEqual(CALLS,[])
    def test_09_backend_off_overrides_partial_and_stop_disabled(self):
        d=Dummy()
        d.finish_core_checks(17,core(home=False))
        STATE_DOC[0]={"mode":"OFF","detail":"Clean"}
        d.periodic_state_tick()
        self.assertEqual(d.status.get_text(),"Status: OFF")
        self.assertFalse(d.buttons["stop"].enabled)
        self.assertTrue(d.buttons["start"].enabled)
    def test_10_worker_checks_real_home_and_204_before_green(self):
        d=Dummy()
        d.live_checks_worker(17)
        urls=[c[0] for c in CALLS]
        self.assertIn("https://www.youtube.com/",urls)
        self.assertIn("https://www.youtube.com/generate_204",urls)
        self.assertIn("https://github.com/",urls)
        self.assertIn("https://api.openai.com/v1/models",urls)
        self.assertTrue(any(fn.__name__=="finish_core_checks" for fn,_ in QUEUED))
    def test_11_selected_dns_worker_page_only(self):
        ACTUAL[0]={"physicalInterface":"enp1s0","selectiveDns":False,"selectiveDnsEncrypted":True}
        d=Dummy()
        d.live_checks_worker(17)
        self.assertIn("https://www.youtube.com/",[c[0] for c in CALLS])
        self.assertNotIn("https://www.youtube.com/generate_204",[c[0] for c in CALLS])
    def test_12_empty_iface_fails_closed_without_network(self):
        ACTUAL[0]={"physicalInterface":""}
        d=Dummy()
        d.live_checks_worker(17)
        self.assertEqual(CALLS,[])
        self.assertTrue(any(fn.__name__=="finish_core_checks" for fn,_ in QUEUED))

if __name__ == "__main__":
    result = unittest.main(verbosity=1, exit=False)
    if not result.result.wasSuccessful():
        raise SystemExit(1)
    print("R735_LINUX_GUI_CORE_HTTP_TRUTH_NEGATIVE_FIRST_14_CASES_PASS")
