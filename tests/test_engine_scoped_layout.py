"""Generic pinned layout compiler and Linux installed-root drift contracts."""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from functools import lru_cache
from pathlib import Path
import re
import unittest

from installer_engine.engine import EngineError
from installer_engine.broker_intent import compare_pinned_policy_intent
from tests.test_engine_broker_intent import fixture_contract
from installer_engine.scoped_layout import compile_scoped_layout

ROOT = Path(__file__).resolve().parents[1]
MAPPING = ROOT / "linux" / "native_layout.json"
SAMPLE = ROOT / "tests" / "fixtures" / "r519_original" / "PACKAGE_MANIFEST.json"


def _static_assignment(path: Path, name: str):
    # Parse the exact real package script's declarative FILES value without
    # executing the packaging script or touching delivery/release artifacts.
    tree = ast.parse(path.read_text("utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and (
                isinstance(node.targets[0], ast.Name) and
                node.targets[0].id == name):
            return ast.literal_eval(node.value)
    raise AssertionError("MISSING_STATIC_PACKAGE_ASSIGNMENT:" + name)


@lru_cache(maxsize=1)
def _current_source_manifest():
    rows = []
    declared = _static_assignment(ROOT / "build_linux_package.py", "FILES")
    for source, target in declared:
        raw = (ROOT / source).read_bytes()
        if Path(target).suffix.lower() in {
                ".sh", ".py", ".md", ".txt", ".svg", ".json"}:
            raw = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        rows.append({
            "file": target, "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest().upper(),
        })
    assert len(rows) == 28 and len({r["file"] for r in rows}) == 28
    return {"schema": 1, "product": "Direct Internet Method",
            "version": "1.5.7", "platform": "linux-x86_64", "files": rows}


class PinnedLayoutTests(unittest.TestCase):
    def setUp(self):
        self.layout = json.loads(MAPPING.read_text("utf-8"))
        # Real v1.5.7 package source bytes and source paths, produced purely
        # from the existing build script declarations without building/releasing.
        self.source = copy.deepcopy(_current_source_manifest())

    def build(self, *, layout=None, source=None, pin=None, raw=None):
        blob = raw if raw is not None else json.dumps(
            layout if layout is not None else self.layout,
            separators=(",", ":"), sort_keys=True).encode("utf-8")
        good_pin = hashlib.sha256(blob).hexdigest()
        return compile_scoped_layout(
            source if source is not None else self.source,
            blob, pin if pin is not None else good_pin)

    def test_real_linux_mapping_has_all_13_protected_plus_8_user_code_files(self):
        plan = self.build()
        self.assertEqual([name for name, _ in plan.scopes], ["privileged", "user"])
        self.assertEqual(len(plan.scopes[0][1]["files"]), 13)
        self.assertEqual(len(plan.scopes[1][1]["files"]), 8)
        self.assertFalse(plan.native_adapter_accepted)
        with self.assertRaisesRegex(EngineError, "NATIVE_ADAPTER"):
            plan.require_ready_for_native_install()

    def test_corrupt_external_layout_pin_refused(self):
        with self.assertRaisesRegex(EngineError, "LAYOUT_PIN_MISMATCH"):
            self.build(pin="0"*64)

    def test_different_source_version_refused(self):
        source = dict(self.source, version="1.5.6")
        with self.assertRaisesRegex(EngineError, "LAYOUT_SOURCE_VERSION_PLATFORM_MISMATCH"):
            self.build(source=source)

    def test_undeclared_source_refused(self):
        layout = json.loads(json.dumps(self.layout))
        layout["files"][0]["source"] = "missing.sh"
        with self.assertRaisesRegex(EngineError, "LAYOUT_SOURCE_MISSING_OR_REUSED"):
            self.build(layout=layout)

    def test_duplicate_target_and_reused_source_refused(self):
        for key, label in (("target", "LAYOUT_DESTINATION_COLLISION"),
                           ("source", "LAYOUT_SOURCE_MISSING_OR_REUSED")):
            with self.subTest(key=key):
                layout = json.loads(json.dumps(self.layout))
                layout["files"][1][key] = layout["files"][0][key]
                with self.assertRaisesRegex(EngineError, label):
                    self.build(layout=layout)

    def test_windows_unsafe_target_refused_for_linux_too(self):
        for path in ("../../usr/lib", "/etc/passwd", "CON", "name:stream",
                     "dir\\evil.exe", "foo/.dim-engine/test"):
            with self.subTest(path=path):
                layout = json.loads(json.dumps(self.layout))
                layout["files"][0]["target"] = path
                with self.assertRaises(EngineError):
                    self.build(layout=layout)

    def test_no_mode_or_privileged_path_inference(self):
        layout = json.loads(json.dumps(self.layout))
        layout["files"][0]["mode"] = 0o4755
        with self.assertRaisesRegex(EngineError, "LAYOUT_FILE_MODE_INVALID"):
            self.build(layout=layout)

    def test_duplicate_json_key_rejected(self):
        raw = b'{"schema":1,"schema":2}'
        with self.assertRaisesRegex(EngineError, "LAYOUT_DUPLICATE_JSON_KEY"):
            self.build(raw=raw)

    def test_fails_if_linux_existing_native_installer_mappings_drift(self):
        script = (ROOT/"linux"/"system"/"install_system.sh").read_text("utf-8")
        actual = set((s, t, int(m, 8)) for m, s, t in re.findall(
            r'^install -m (0[0-7]{3}) "\$SRC/([^"]+)" "\$ROOT/([^"]+)"$',
            script, re.MULTILINE))
        expected = set((e["source"], e["target"], e["mode"])
                       for e in self.layout["files"] if e["scope"] == "privileged")
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 13)

    def test_real_user_managed_source_and_destination_match_transaction(self):
        actual = set(_static_assignment(
            ROOT / "linux" / "app" / "user_update_transaction.py", "FILES"))
        expected = set((e["source"], e["target"], e["mode"])
                       for e in self.layout["files"] if e["scope"] == "user")
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 8)
        # Provider data is intentionally mutable/customizable. It must never
        # silently become a code file overwritten by the native Engine.
        self.assertNotIn("app/router_gateway/providers.json",
                         {e["source"] for e in self.layout["files"]})
        self.assertNotIn("router_gateway/providers.json",
                         {e["target"] for e in self.layout["files"]})

    def test_real_complete_linux_plan_matches_two_scope_broker_intent(self):
        # End-to-end SOURCE CONTRACT ONLY, not independently authenticated
        # release policy, root service commit, or systemd acceptance.
        plan = self.build()
        _, policy, request, pb, rb = fixture_contract(plan)
        receipt = compare_pinned_policy_intent(
            plan, pb, hashlib.sha256(pb).hexdigest(), rb)
        self.assertEqual(receipt["platform"], "linux-x86_64")
        self.assertEqual(receipt["version"], "1.5.7")
        self.assertFalse(receipt["native_installation_accepted"])
        self.assertFalse(receipt["publisher_authenticated"])
        self.assertFalse(receipt["privileged_broker_implemented"])

    def test_historical_r519_archive_lacks_new_socket_code_and_fails_closed(self):
        historical = json.loads(SAMPLE.read_text("utf-8"))
        self.assertNotIn("app/socket_fallback.py",
                         {row["file"] for row in historical["files"]})
        historical["version"] = "1.5.7"  # historical bytes are NOT v1.5.7
        with self.assertRaisesRegex(EngineError, "LAYOUT_SOURCE_MISSING_OR_REUSED"):
            self.build(source=historical)

    def test_full_21_code_sources_are_unique_in_real_28_file_package(self):
        plan = self.build()
        used = [item["source"] for item in self.layout["files"]]
        self.assertEqual(len(used), 21)
        self.assertEqual(len(set(used)), 21)
        self.assertTrue(set(used) <= {row["file"] for row in self.source["files"]})
        self.assertFalse(plan.native_adapter_accepted)


if __name__ == "__main__":
    unittest.main(verbosity=2)
