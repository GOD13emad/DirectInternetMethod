"""Offline synthetic Inno R880 fixture renderer regression tests.

No tests invoke ISCC, SCM, UAC, or install anything. This restricts
rendering to two known synthetic files and a throwaway AppId/path.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import uuid
import zipfile

from installer_engine.engine import EngineError
from tools.native_fixtures.windows.render_inno_preflight_fixture import (
    PRODUCTION_APP_ID, build_fixture,
)


@unittest.skipUnless(sys.platform == "win32", "Native Inno path fixture requires Windows")
class InnoFixtureRendererTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="dim-native-render-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.out = self.base / "out"
        self.out.mkdir()
        self.binary = self.base / "frozen-engine-test.exe"
        self.binary.write_bytes(b"UNEXECUTABLE TEST ENGINE, NEVER A REAL BIN")
        self.bin_pin = self.digest(self.binary)
        self.guid = uuid.UUID("F50F2B2A-9C33-4FD2-81C4-5723E3F4C780")

    @staticmethod
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def archive(self, *, version="1.5.7", override=None) -> Path:
        gui = f"FAKE_GUI_{version}_TEST_ONLY".encode("ascii")
        svc = f"NOT_A_SERVICE_{version}_TEST_ONLY".encode("ascii")
        files = [
            {"scope": "user", "file": "app/main.bin",
             "source": "app/main.bin", "bytes": len(gui),
             "sha256": hashlib.sha256(gui).hexdigest()},
            {"scope": "privileged", "file": "bin/service.stub",
             "source": "bin/service.stub", "bytes": len(svc),
             "sha256": hashlib.sha256(svc).hexdigest()},
        ]
        body = {
            "installer-metadata/manifest.json": json.dumps({
                "schema": 2, "product": "Direct Internet Method",
                "version": version, "files": files}).encode(),
            "installer-metadata/RELEASE.json": json.dumps({
                "product": "Direct Internet Method",
                "version": version}).encode(),
            "installer-metadata/unins012.exe": b"FAKE UNINSTALLER",
            "installer-metadata/unins012.dat": b"FAKE LOG",
            "managed/user/app/main.bin": gui,
            "managed/privileged/bin/service.stub": svc,
        }
        if override:
            body.update(override)
        archive = self.base / "source.zip"
        with zipfile.ZipFile(archive, "w") as z:
            for name, data in body.items():
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                z.writestr(info, data)
        return archive

    def render(self, archive=None, pin=None, app_id=None, dest=None,
               root=r"C:\DIM_UE_TEST_ISOLATED\app"):
        archive = archive or self.archive()
        return build_fixture(
            archive, self.digest(archive) if pin is None else pin,
            self.binary, self.bin_pin, self.out if dest is None else dest,
            "small-157", self.guid if app_id is None else app_id, root
        )

    def test_render_valid_fixture_has_preinstall_and_is_not_native_proof(self):
        receipt = self.render()
        content = Path(receipt["fixture_script"]).read_text("utf-8")
        self.assertEqual(
            receipt["status"], "PASS_RENDERED_SYNTHETIC_NATIVE_INNO_FIXTURE_SOURCE_ONLY")
        self.assertFalse(receipt["native_install_or_rollback_accepted"])
        self.assertFalse(receipt["publisher_authenticated"])
        self.assertIn("function PrepareToInstall", content)
        self.assertIn("ExtractTemporaryFile('dim-ue-preflight.exe')", content)
        self.assertIn("archive-sha256", content)
        self.assertIn("Flags: dontcopy noencryption", content)
        self.assertIn("PrivilegesRequired=lowest", content)
        self.assertNotIn(str(PRODUCTION_APP_ID).upper(), content)
        self.assertEqual(content.count("AppId="), 1)
        self.assertNotIn("@SOURCE_ZIP@", content)
        self.assertEqual(
            self.digest(Path(receipt["fixture_script"])),
            receipt["fixture_script_sha256"]
        )

    def test_archive_pin_is_independent_fail_closed(self):
        p = self.archive()
        with self.assertRaisesRegex(EngineError, "INNO_SOURCE_ZIP_PIN_INVALID"):
            self.render(p, "0" * 64)
        self.assertEqual(list(self.out.iterdir()), [])

    def test_frozen_engine_pin_is_independent_fail_closed(self):
        p = self.archive()
        with self.assertRaisesRegex(EngineError, "INNO_FROZEN_ENGINE_PIN_INVALID"):
            build_fixture(p, self.digest(p), self.binary, "f" * 64,
                          self.out, "small-157", self.guid,
                          r"C:\DIM_UE_TEST_ISOLATED\app")
        self.assertEqual(list(self.out.iterdir()), [])

    def test_production_app_id_rejected(self):
        with self.assertRaisesRegex(EngineError, "FIXTURE_MUST_NOT_USE_PRODUCTION_APP_ID"):
            self.render(app_id=PRODUCTION_APP_ID)

    def test_real_product_content_rejected_even_if_archived_and_pinned(self):
        p = self.archive(override={"managed/user/app/main.bin": b"REAL BYTES"})
        with self.assertRaisesRegex(EngineError, "ARCHIVE_MEMBER_(SHA|LENGTH)_MISMATCH"):
            self.render(archive=p)
        self.assertEqual(list(self.out.iterdir()), [])

    def test_non_disposable_root_rejected(self):
        with self.assertRaisesRegex(EngineError, "FIXTURE_ROOT_MUST_BE_DISPOSABLE"):
            self.render(root=r"C:\Program Files\DirectInternetMethod")

    def test_unsafe_path_injection_rejected(self):
        with self.assertRaisesRegex(EngineError, "INNO_UNSAFE_LITERAL"):
            self.render(root='C:\\DIM_UE_TEST"; Executes=anything')

    def test_existing_output_refuses_clobber(self):
        result = self.render()
        with self.assertRaisesRegex(EngineError, "INNO_FIXTURE_OUTPUT_ALREADY_EXISTS"):
            self.render()
        self.assertTrue(Path(result["fixture_script"]).exists())

    def test_extra_real_product_file_forbidden(self):
        p = self.archive(override={"managed/user/app/real.exe": b"FORBIDDEN"})
        with self.assertRaisesRegex(EngineError, "ARCHIVE_EXTRA_OR_MISSING_MEMBER"):
            self.render(archive=p)


if __name__ == "__main__":
    unittest.main(verbosity=2)
