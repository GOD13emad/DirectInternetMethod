#!/usr/bin/env python3
"""Native original Linux GUI Start acceptance negative-first regression.

Only AST-extracted verify_live() and Window.worker() execute with mocked
filesystem and subprocess responses. No GTK, network, route, sudo, DNS, service
or installed-user app state is modified. Both Google-style YouTube 204 and a
real YouTube HTTPS homepage must succeed to accept Start.
"""
from __future__ import annotations
import ast
import json
import pathlib
from types import SimpleNamespace
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = (ROOT/"linux/app/direct_internet_method.py").read_text("utf8")
TREE = ast.parse(SRC)
FUNCS = [n for n in TREE.body
         if isinstance(n, ast.FunctionDef) and n.name=="verify_live"]
assert len(FUNCS)==1
GUI = next(n for n in TREE.body if isinstance(n,ast.ClassDef) and n.name=="Window")
WORKER = next(n for n in GUI.body if isinstance(n,ast.FunctionDef) and n.name=="worker")


class FakeState:
    def __init__(self,doc): self.doc=doc
    def read_text(self,encoding="utf-8"): return json.dumps(self.doc)


def fixture(*, page="200", lightweight="204", selective=False, route="enp1s0",
            google="200", external=False):
    requested=[]
    doc={"physicalInterface":"enp1s0","dnsMode":"system-preserved",
         "selectiveDnsEncrypted":bool(selective),"selectiveDns":False}
    answers={
        "http://www.youtube.com/":(0,"200"),
        "https://www.youtube.com/":(0,page),
        "https://www.youtube.com/generate_204":(0,lightweight),
        "https://api.openai.com/v1/models":(0,"401"),
        "https://github.com/":(0,google),
        "https://gemini.google.com/":(0,"403")
    }
    def runner(args,**kw):
        assert args[0] in ("curl","getent"),args
        if args[0]=="getent":
            return SimpleNamespace(returncode=0,stdout="1.2.3.4 STREAM\n",stderr="")
        assert "--noproxy" in args and "--interface" in args, args
        url=args[-1]
        requested.append(url)
        assert url in answers,url
        code,status=answers[url]
        if status=="000":code=35
        return SimpleNamespace(returncode=code,stdout=status+"|142.251.157.4|0.2",
                               stderr="reset" if code else "")
    e={
        "json":json, "STATE":FakeState(doc),
        "_top_default_iface":lambda:route,
        "_external_tunnel_active":lambda:external,
        "subprocess":SimpleNamespace(run=runner),
    }
    exec(compile(ast.Module(body=FUNCS,type_ignores=[]),
                 "<original-verify-live>", "exec"),e)
    return e["verify_live"],requested


class Contract(unittest.TestCase):
    def test_lightweight_success_does_not_hide_real_page_failure(self):
        f,urls=fixture(page="000",lightweight="204")
        result=f()
        self.assertIn("https://www.youtube.com/",urls)
        self.assertIn("https://www.youtube.com/generate_204",urls)
        self.assertFalse(result["ok"])
        self.assertEqual(result["youtube"]["meta"].split("|")[0],"000")

    def test_real_page_success_does_not_hide_lightweight_failure(self):
        f,urls=fixture(page="200",lightweight="000")
        result=f()
        self.assertFalse(result["ok"])
        self.assertIn("https://www.youtube.com/generate_204",urls)

    def test_both_youtube_targets_and_google_openai_github_pass(self):
        f,urls=fixture(page="200",lightweight="204")
        self.assertTrue(f()["ok"])
        self.assertEqual(urls.count("https://www.youtube.com/"),1)
        self.assertEqual(urls.count("https://www.youtube.com/generate_204"),1)

    def test_selected_dns_also_requires_both_youtube_targets(self):
        f,urls=fixture(page="200",lightweight="000",selective=True)
        self.assertFalse(f()["ok"])
        self.assertIn("https://www.youtube.com/generate_204",urls)

    def test_route_drift_sends_no_http_or_dns(self):
        f,urls=fixture(route="eth9")
        got=f()
        self.assertEqual(got["error"],"PHYSICAL_INTERFACE_ROUTE_DRIFT")
        self.assertEqual(urls,[])

    def test_other_core_site_failure_is_not_accepted(self):
        f,_=fixture(google="000")
        self.assertFalse(f()["ok"])

    def test_gui_worker_rolls_back_a_failed_live_acceptance(self):
        calls=[]
        queued=[]
        class GLib:
            @staticmethod
            def idle_add(fn,*args):queued.append((fn,args))
        def action(command):
            calls.append(command)
            return {"ok":True,"unit":"directinternetmethod-"+command}
        f,_=fixture(page="000",lightweight="204")
        e={"run_system_action":action,"verify_live":f,"GLib":GLib}
        exec(compile(ast.Module(body=[WORKER],type_ignores=[]),
                     "<original-gui-start-worker>", "exec"),e)
        instance=SimpleNamespace(finish=lambda r:None)
        e["worker"](instance,"start")
        self.assertEqual(calls,["start","stop"])
        self.assertFalse(queued[0][1][0]["ok"])
        self.assertEqual(queued[0][1][0]["error"],"LIVE_VERIFY_FAILED_ROLLED_BACK")


if __name__ == "__main__":
    result=unittest.main(verbosity=0,exit=False)
    if not result.result.wasSuccessful():raise SystemExit(20)
    print("R678_GUI_FULL_YOUTUBE_HTTPS_AND_204_NEGATIVE_FIRST_PASS")