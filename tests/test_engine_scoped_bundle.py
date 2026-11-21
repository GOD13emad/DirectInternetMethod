"""Pinned reusable build-scope materialization, code-only and non-elevated."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

from installer_engine.__main__ import main as engine_cli
from installer_engine.engine import Engine, EngineError, hash_file
from installer_engine.scoped_bundle import materialize_scope_bundle, STATUS

PLATFORM = "windows-x86_64" if sys.platform == "win32" else "linux-x86_64"


class ScopedBundleTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="dim-scoped-bundle-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.source = self.base / "source"
        self.layout = self.base / "layout.json"
        self.destination = self.base / "scope"
        (self.source / "payload" / "system").mkdir(parents=True)
        (self.source / "payload" / "system" / "control.sh").write_bytes(
            b"#!/bin/sh\necho SCOPED_SYNTHETIC\n")
        (self.source / "payload" / "README.md").write_bytes(b"NOT_MAPPED_USER_DATA")
        rows = []
        for relative in ("system/control.sh", "README.md"):
            src = self.source / "payload" / relative
            rows.append({"path": relative, "sha256": hash_file(src),
                         "bytes": src.stat().st_size, "mode": 0o755 if relative.endswith(".sh") else 0o644})
        self.manifest = {"schema": 1, "product": "Direct Internet Method",
                         "version": "1.5.7", "platform": PLATFORM, "files": rows}
        self.source_pin = self.write_json(self.source / "manifest.json", self.manifest)
        self.layout_doc = {"schema": 1, "product": "Direct Internet Method",
                           "version": "1.5.7", "platform": PLATFORM, "files": [
                {"scope": "privileged", "source": "system/control.sh",
                 "target": "bin/control.sh", "mode": 0o755}]}
        self.layout_pin = self.write_json(self.layout, self.layout_doc)

    @staticmethod
    def write_json(path, data):
        raw = (json.dumps(data, sort_keys=True, separators=(",", ":")) +
               "\n").encode("utf-8")
        path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def build(self, **kw):
        return materialize_scope_bundle(
            kw.get("source", self.source),
            kw.get("source_pin", self.source_pin),
            kw.get("layout", self.layout),
            kw.get("layout_pin", self.layout_pin),
            kw.get("scope", "privileged"),
            kw.get("destination", self.destination), PLATFORM)

    def test_build_owned_files_and_engine_cycle_preserves_data(self):
        r = self.build()
        self.assertEqual((r["status"], r["files"]), (STATUS, 1))
        self.assertFalse(r["native_installation_or_rollback_accepted"])
        self.assertFalse((self.destination / "payload" / "README.md").exists())
        root = self.base / "engine-root"
        e = Engine(root, PLATFORM)
        data = root / "data" / "owner.config"
        data.parent.mkdir(parents=True)
        data.write_bytes(b"USER DATA KEEP")
        e.stage(self.destination, r["manifest_sha256"])
        e.activate(lambda: True)  # fixture-only quiescence
        e.commit(lambda: True)  # fixture-only native acceptance
        self.assertEqual(e.verify()["version"], "1.5.7")
        self.assertEqual(data.read_bytes(), b"USER DATA KEEP")

    def test_wrong_out_of_band_source_pin_rejected_without_output(self):
        with self.assertRaisesRegex(EngineError, "MANIFEST_PIN_MISMATCH"):
            self.build(source_pin="0"*64)
        self.assertFalse(self.destination.exists())

    def test_layout_pin_rejected_without_output(self):
        with self.assertRaisesRegex(EngineError, "LAYOUT_PIN_MISMATCH"):
            self.build(layout_pin="0"*64)
        self.assertFalse(self.destination.exists())

    def test_corrupt_content_rejected_before_output(self):
        (self.source / "payload" / "system" / "control.sh").write_bytes(b"TAMPER")
        with self.assertRaisesRegex(EngineError, "PACKAGE_FILE_SHA_MISMATCH"):
            self.build()
        self.assertFalse(self.destination.exists())

    def test_refuse_existing_output_and_keep_foreign_data(self):
        self.destination.mkdir()
        foreign = self.destination / "foreign-user.txt"
        foreign.write_bytes(b"KEEP")
        with self.assertRaisesRegex(EngineError, "SCOPED_DESTINATION_EXISTS"):
            self.build()
        self.assertEqual(foreign.read_bytes(), b"KEEP")

    def test_unknown_scope_rejected(self):
        with self.assertRaisesRegex(EngineError, "SCOPED_UNKNOWN_NAME"):
            self.build(scope="unmapped")
        self.assertFalse(self.destination.exists())

    def test_source_overlap_rejected(self):
        with self.assertRaisesRegex(EngineError, "SCOPED_DESTINATION_OVERLAPS_INPUT"):
            self.build(destination=self.source/"nested")

    def test_no_native_grant_even_after_correct_scope_build(self):
        r = self.build()
        self.assertFalse(r["native_installation_or_rollback_accepted"])
        self.assertEqual(r["scope"], "privileged")

    def cli_options(self):
        return ["materialize-scope", "--platform", PLATFORM, "--bundle",
                str(self.source), "--expected-manifest-sha256", self.source_pin,
                "--layout", str(self.layout), "--layout-sha256", self.layout_pin,
                "--scope", "privileged", "--destination", str(self.destination)]

    def test_cli_materializes_scoped_package_without_native_grant(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = engine_cli(self.cli_options())
        self.assertEqual(rc, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], STATUS)
        self.assertFalse(report["native_installation_or_rollback_accepted"])
        self.assertTrue((self.destination/"manifest.json").is_file())

    def test_cli_rejects_fixture_native_acceptance_flags_on_scoped_build(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = engine_cli(self.cli_options() + ["--accepted"])
        self.assertEqual(rc, 3)
        self.assertIn("SCOPE_MATERIALIZATION_NOT_NATIVE_TRANSACTION", stderr.getvalue())
        self.assertFalse(self.destination.exists())

    def test_cli_verify_refuses_mixed_scoped_build_arguments(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = engine_cli(["verify", "--platform", PLATFORM,
                             "--root", str(self.base/"empty-engine"),
                             "--layout", str(self.layout)])
        self.assertEqual(rc, 3)
        self.assertIn("ARCHIVE_OPTIONS_ONLY_FOR_IMPORT", stderr.getvalue())


    def test_actual_linux_repo_protected_bytes_materialize_code_only(self):
        # Real current checkout bytes, but NOT an independently authenticated
        # private release archive nor a root/systemd installation.
        repo = Path(__file__).resolve().parents[1]
        layout_path = repo / "linux" / "native_layout.json"
        if not layout_path.is_file():
            self.skipTest("complete Linux product tree unavailable")
        layout = json.loads(layout_path.read_text("utf-8"))
        normalized = self.base / "actual-source"
        (normalized / "payload").mkdir(parents=True)
        records = []
        for row in layout["files"]:
            original = repo / "linux" / row["source"]
            if not original.is_file():
                self.skipTest("full Linux source runtime not present")
            data = original.read_bytes()
            destination = normalized / "payload" / row["source"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            records.append({"path": row["source"], "bytes": len(data),
                            "sha256": hashlib.sha256(data).hexdigest(),
                            "mode": row["mode"]})
        doc = {"schema": 1, "product": "Direct Internet Method",
               "version": "1.5.7", "platform": "linux-x86_64", "files": records}
        pin = self.write_json(normalized / "manifest.json", doc)
        scoped = self.base / "real-scope"
        result = materialize_scope_bundle(
            normalized, pin, layout_path, hash_file(layout_path),
            "privileged", scoped, "linux-x86_64")
        self.assertEqual(result["files"], 13)
        self.assertFalse(result["native_installation_or_rollback_accepted"])
        root = self.base / "real-engine"
        e = Engine(root, "linux-x86_64")
        data_path = root / "data" / "custom-sites.json"
        data_path.parent.mkdir(parents=True)
        data_path.write_bytes(b"OWNER_SETTINGS_UNTOUCHED")
        e.stage(scoped, result["manifest_sha256"])
        e.activate(lambda: True)  # synthetic callback, NOT systemd
        e.commit(lambda: True)
        self.assertEqual(e.verify()["files"], 13)
        self.assertEqual(data_path.read_bytes(), b"OWNER_SETTINGS_UNTOUCHED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
