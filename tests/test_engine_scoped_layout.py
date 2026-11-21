"""Generic pinned layout compiler and Linux installed-root drift contracts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import unittest

from installer_engine.engine import EngineError
from installer_engine.scoped_layout import compile_scoped_layout

ROOT = Path(__file__).resolve().parents[1]
MAPPING = ROOT / "linux" / "native_layout.json"
SAMPLE = ROOT / "tests" / "fixtures" / "r519_original" / "PACKAGE_MANIFEST.json"


class PinnedLayoutTests(unittest.TestCase):
    def setUp(self):
        self.layout = json.loads(MAPPING.read_text("utf-8"))
        # Historical 1.5.5-rc1 bytes are only a synthetic source inventory
        # in this fixture; resetting the version does NOT make them v1.5.7.
        self.source = json.loads(SAMPLE.read_text("utf-8"))
        self.source["version"] = "1.5.7"

    def build(self, *, layout=None, source=None, pin=None, raw=None):
        blob = raw if raw is not None else json.dumps(
            layout if layout is not None else self.layout,
            separators=(",", ":"), sort_keys=True).encode("utf-8")
        good_pin = hashlib.sha256(blob).hexdigest()
        return compile_scoped_layout(
            source if source is not None else self.source,
            blob, pin if pin is not None else good_pin)

    def test_protected_mapping_has_13_source_verified_entries_not_native_acceptance(self):
        plan = self.build()
        self.assertEqual([name for name, _ in plan.scopes], ["privileged"])
        self.assertEqual(len(plan.scopes[0][1]["files"]), 13)
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
                       for e in self.layout["files"])
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 13)


if __name__ == "__main__":
    unittest.main(verbosity=2)
