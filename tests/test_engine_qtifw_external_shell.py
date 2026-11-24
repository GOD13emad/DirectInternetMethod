"""Static and rendered Qt IFW one-owner boundary contracts (no vendor install).

The real Qt 4.7 vendor process pilot is recorded separately in R933 evidence.
These tests run on Windows/Linux without fetching Qt or touching SCM/systemd.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import uuid
from xml.etree import ElementTree as ET

from tools.native_fixtures.qtifw.RenderExternalShellFixture import (
    COMPONENT, PACKAGES, PLATFORM, render,
)

SOURCE = Path(__file__).resolve().parents[1]


class QtExternalOwnerShellContracts(unittest.TestCase):
    def setUp(self):
        self.target = (Path(tempfile.gettempdir()) /
                       ("dim-qtifw-bridge-" + uuid.uuid4().hex[:12]))
        self.assertFalse(self.target.exists())
        self.addCleanup(self.cleanup)

    def cleanup(self):
        # The fixture generator is the sole writer; never delete links or
        # paths outside the exact newly-created temp root.
        if self.target.is_symlink():
            return
        if (self.target.exists() and
                self.target.parent.resolve() ==
                Path(tempfile.gettempdir()).resolve() and
                self.target.name.startswith("dim-qtifw-bridge-")):
            shutil.rmtree(self.target)

    def test_exact_cross_platform_common_engine_no_managed_payload(self):
        receipt = render(self.target, SOURCE)
        self.assertEqual(receipt["component"], COMPONENT)
        self.assertEqual(receipt["platform"], PLATFORM)
        self.assertFalse(receipt["qt_owns_product_code"])
        self.assertFalse(receipt["native_os_service_accepted"])
        self.assertFalse(receipt["publisher_authenticated"])
        self.assertFalse(receipt["powercut_accepted"])
        self.assertFalse(receipt["product_installation_accepted"])
        self.assertEqual(len(receipt["packages"]), 3)
        root = ET.parse(self.target / "config/config.xml").getroot()
        self.assertEqual(root.findtext("RemoveTargetDir"), "false")
        self.assertEqual(root.findtext("TargetDir"),
                         str(self.target / "qt-shell-root"))
        for dirname, ver, failing in PACKAGES:
            with self.subTest(dirname=dirname):
                p = self.target / dirname / COMPONENT
                self.assertEqual(list((p / "data").iterdir()), [])
                doc = ET.parse(p / "meta/package.xml").getroot()
                self.assertEqual(doc.findtext("Version"), ver)
                self.assertEqual(doc.findtext("Script"), "bridge.qs")
                script = (p / "meta/bridge.qs").read_text("utf8")
                self.assertIn("Component.prototype.createOperations", script)
                self.assertIn("universal-selftest", script)
                self.assertIn(PLATFORM, script)
                self.assertIn("workingdirectory=", script)
                self.assertNotIn("component.createOperations()", script)
                self.assertNotIn("addElevatedOperation(", script)
                self.assertNotIn("Extract", script)
                self.assertNotIn("ManagedCode", script)
                self.assertEqual(
                    script.count('component.addOperation("Execute"'),
                    2 if failing else 1,
                )
        self.assertEqual(
            json.loads((self.target/"fixture-receipt.json").read_text("utf8")),
            receipt,
        )

    def test_no_existing_output_directory_can_be_reused(self):
        render(self.target, SOURCE)
        with self.assertRaisesRegex(ValueError, "NEW_DIRECT_OS_TEMP_ROOT"):
            render(self.target, SOURCE)

    def test_does_not_write_to_repo_or_nested_or_foreign_root(self):
        with self.assertRaisesRegex(ValueError, "NEW_DIRECT_OS_TEMP_ROOT"):
            render(SOURCE / "unsafe-qt-target", SOURCE)
        with self.assertRaisesRegex(ValueError, "NEW_DIRECT_OS_TEMP_ROOT"):
            render(self.target / "nested-qt-target", SOURCE)
        self.assertFalse((SOURCE / "unsafe-qt-target").exists())
        self.assertFalse(self.target.exists())

    def test_rejects_wrong_platform_and_missing_engine(self):
        foreign = ("linux-x86_64" if os.name == "nt"
                   else "windows-x86_64")
        with self.assertRaisesRegex(ValueError, "HOST_PLATFORM_MISMATCH"):
            render(self.target, SOURCE, platform=foreign)
        self.assertFalse(self.target.exists())
        with self.assertRaisesRegex(ValueError, "EXISTING_SHARED_ENGINE_REQUIRED"):
            render(self.target, self.target / "missing-source")
        self.assertFalse(self.target.exists())

    def test_system_python_alias_resolves_to_actual_interpreter(self):
        receipt = render(self.target, SOURCE, python=Path(sys.executable))
        self.assertEqual(Path(receipt["python_executable"]),
                         Path(sys.executable).resolve())
    def test_rejects_missing_python_executable(self):
        with self.assertRaisesRegex(ValueError, "EXISTING_PYTHON_EXE_REQUIRED"):
            render(self.target, SOURCE, python=self.target/"missing-python")
        self.assertFalse(self.target.exists())


if __name__ == "__main__":
    unittest.main()
