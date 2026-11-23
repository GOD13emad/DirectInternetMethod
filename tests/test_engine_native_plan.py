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



class WindowsFlatNativeReadbackTests(unittest.TestCase):
    @unittest.skipUnless(__import__("os").name == "nt", "requires Win32 file handles")
    def test_flat_installed_files_and_mutable_owner_member(self):
        import hashlib
        import tempfile
        from unittest.mock import patch
        from installer_engine.native_readiness import windows_flat_native_postflight
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            user, protected = base / "user", base / "protected"
            user.mkdir()
            protected.mkdir()
            entries = []
            for scope, root, rel, body in (
                ("privileged", protected, "app/DirectInternetMethod.Service.exe", b"service"),
                ("user", user, "app/DirectInternetMethod.exe", b"gui"),
                ("user", user, "app/router_gateway/providers.json", b"default"),
            ):
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body)
                entries.append(dict(scope=scope, file=rel, source=rel,
                                    bytes=len(body), sha256=hashlib.sha256(body).hexdigest()))
            raw = json.dumps(dict(schema=2, product="Direct Internet Method",
                                  version="1.5.7", files=entries)).encode()
            source = base / "build.json"
            source.write_bytes(raw)
            (user / "manifest.json").write_bytes(raw)
            pin = hashlib.sha256(raw).hexdigest()
            provider = user / "app/router_gateway/providers.json"
            provider.write_bytes(b"custom owner provider")
            command = str(protected / "app/DirectInternetMethod.Service.exe")
            config = dict(binary_command=command, service_account="LocalSystem", start_type=2)
            observed = dict(registrations=[dict(hive="HKLM")], scm_config=config)
            with patch("installer_engine.native_readiness.windows_service_configuration",
                       return_value=config), patch(
                       "installer_engine.native_readiness.windows_readiness",
                       return_value=observed):
                args = (source, pin, user, protected)
                result = windows_flat_native_postflight(*args)
                self.assertEqual(result["verified_immutable_files"],
                                 {"user": 1, "privileged": 1})
                self.assertEqual(result["mutable_owner_members_not_hashed_to_source"],
                                 ["app/router_gateway/providers.json"])
                self.assertFalse(result["native_installation_accepted"])
                self.assertEqual(provider.read_bytes(), b"custom owner provider")
                with self.assertRaisesRegex(EngineError, "BUILD_MANIFEST_PIN"):
                    windows_flat_native_postflight(source, "0"*64, user, protected)
                (user / "app/DirectInternetMethod.exe").write_bytes(b"bad")
                with self.assertRaisesRegex(EngineError, "WIN32_HANDLE_PIN"):
                    windows_flat_native_postflight(*args)
                (user / "app/DirectInternetMethod.exe").write_bytes(b"gui")
                config["binary_command"] = command + " --other"
                with self.assertRaisesRegex(EngineError, "SCM_BINARY_COMMAND_MISMATCH"):
                    windows_flat_native_postflight(*args)


if __name__=="__main__":
    unittest.main(verbosity=2)
