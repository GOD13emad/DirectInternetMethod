"""Native payload source plans: dual-root Windows, distribution-only Linux.

These contract tests deliberately never perform installer registration,
privilege elevation, file mutation outside unittest temp dirs or real updates.
"""
import copy
import json
from pathlib import Path
import unittest

from installer_engine.engine import EngineError
from installer_engine.native_plan import linux_distribution_plan, windows_scoped_plan

ROOT = Path(__file__).resolve().parents[1]


class NativeInstallPlanTests(unittest.TestCase):
    def sample_windows(self):
        return {
            "schema": 2, "product": "Direct Internet Method", "version": "1.5.7",
            "files": [
                {"scope":"user", "file":"app/DirectInternetMethod.exe",
                 "source":"app/DirectInternetMethod.exe", "bytes":2,
                 "sha256":"a"*64},
                {"scope":"privileged", "file":"runtime/pwsh/Modules/PSReadLine/.signature.p7s",
                 "source":"../router_gateway/providers.json", "bytes":1,
                 "sha256":"b"*64}
            ]
        }

    def sample_linux(self):
        return {
            "schema":1, "product":"Direct Internet Method",
            "version":"1.5.7", "platform":"linux-x86_64",
            "files":[{"file":"install.sh","bytes":3,"sha256":"c"*64},
                     {"file":"system/install_system.sh","bytes":5,
                      "sha256":"d"*64}]
        }

    def test_windows_real_681_scopes_are_separate_native_roots(self):
        with (ROOT/"windows"/"manifest.json").open(encoding="utf8") as f:
            original=json.load(f)
        plan=windows_scoped_plan(original)
        self.assertEqual(plan.source_kind,"INSTALLED_SCOPES_NEED_INNO_SCM")
        scopes=dict(plan.scopes)
        self.assertEqual(len(scopes["user"]["files"]),7)
        self.assertEqual(len(scopes["privileged"]["files"]),674)
        self.assertTrue(any(x["path"].endswith("/.signature.p7s")
                            for x in scopes["privileged"]["files"]))
        self.assertEqual(scopes["user"]["version"],scopes["privileged"]["version"])
        self.assertFalse(plan.native_adapter_accepted)
        with self.assertRaisesRegex(EngineError,"NATIVE_ADAPTER_REGISTRATION"):
            plan.require_ready_for_native_install()

    def test_windows_source_path_outside_windows_subtree_is_build_metadata_only(self):
        plan=windows_scoped_plan(self.sample_windows())
        self.assertEqual(set(dict(plan.scopes)),{"user","privileged"})
        self.assertFalse(any("source" in f
                         for _,m in plan.scopes for f in m["files"]))

    def test_windows_duplicate_and_casefold_refused(self):
        m=self.sample_windows()
        m["files"].append(dict(m["files"][0],file="APP/directinternetmethod.EXE"))
        with self.assertRaisesRegex(EngineError,"DUPLICATE_OR_CASEFOLD"):
            windows_scoped_plan(m)

    def test_windows_rejects_bad_scope_invalid_path_or_source_location(self):
        original=self.sample_windows()
        for field,val,expected in (
            ("scope","system","WINDOWS_SCOPE"),
            ("scope",[],"WINDOWS_SCOPE"),
            ("file","../outside.exe","MEMBER_UNSAFE_COMPONENT"),
            ("source","C:/foreign.exe","WINDOWS_SOURCE_LOCATION"),
            ("sha256","not-a-hash","PLAN_INVALID_DIGEST")):
            x=copy.deepcopy(original)
            x["files"][0][field]=val
            with self.subTest(field=field,value=val):
                with self.assertRaisesRegex(EngineError,expected):
                    windows_scoped_plan(x)

    def test_windows_requires_both_scopes(self):
        x=self.sample_windows()
        x["files"]=x["files"][:1]
        with self.assertRaisesRegex(EngineError,"TWO_SCOPE"):
            windows_scoped_plan(x)

    def test_linux_bundle_is_explicitly_distribution_not_root_install(self):
        plan=linux_distribution_plan(self.sample_linux())
        self.assertEqual(plan.source_kind,
                         "DISTRIBUTION_SOURCE_NOT_NATIVE_INSTALLED_ROOTS")
        self.assertEqual(list(dict(plan.scopes)),["distribution"])
        self.assertEqual(len(dict(plan.scopes)["distribution"]["files"]),2)
        with self.assertRaisesRegex(EngineError,"NATIVE_ADAPTER_REGISTRATION"):
            plan.require_ready_for_native_install()

    def test_linux_rejects_wrong_version_and_link_traversal_path(self):
        original=self.sample_linux()
        for f,v,reason in (
            ("platform","windows-x86_64","LINUX_SOURCE_IDENTITY"),
            ("version","1.5.7.0","INVALID_VERSION"),
            ("file","../etc/shadow","MEMBER_UNSAFE_COMPONENT")):
            x=copy.deepcopy(original)
            if f=="file":x["files"][0][f]=v
            else:x[f]=v
            with self.subTest(field=f):
                with self.assertRaisesRegex(EngineError,reason):
                    linux_distribution_plan(x)

    def test_linux_duplicate_and_bad_manifest_fields_refused(self):
        m=self.sample_linux()
        m["files"].append(dict(m["files"][0],file="INSTALL.SH"))
        with self.assertRaisesRegex(EngineError,"DUPLICATE_OR_CASEFOLD"):
            linux_distribution_plan(m)
        m=self.sample_linux()
        m["files"][0]["fake_privilege_grant"]=True
        with self.assertRaisesRegex(EngineError,"LINUX_SOURCE_FILE_KEYS"):
            linux_distribution_plan(m)


if __name__=="__main__":
    unittest.main(verbosity=2)
