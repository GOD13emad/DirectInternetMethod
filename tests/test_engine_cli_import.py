"""Offline frozen CLI source-import contract, without native OS mutation."""
from __future__ import annotations
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import os
import stat
import sys
import tempfile
import unittest
import zipfile

from installer_engine.__main__ import main
from installer_engine.engine import read_package


class OfflineImportCLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dim-engine-cli-import-")
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.platform = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
        self.kind = "windows-managed" if os.name == "nt" else "linux-distribution"

    def invoke(self, args):
        output, err = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(err):
            exit_code = main(args)
        return exit_code, json.loads(output.getvalue() if not exit_code else err.getvalue())

    def source(self):
        data = b"fixture payload only"
        file = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        if os.name == "nt":
            items = {
                "installer-metadata/manifest.json": json.dumps({
                    "schema": 2, "product": "Direct Internet Method",
                    "version": "1.5.7",
                    "files": [
                        {"scope": "user", "file": "app/main.bin",
                         "source": "app/main.bin", **file},
                        {"scope": "privileged", "file": "app/native.stub",
                         "source": "app/native.stub", **file}
                    ]}).encode(),
                "installer-metadata/RELEASE.json":
                    b'{"product":"Direct Internet Method","version":"1.5.7"}',
                "installer-metadata/unins017.exe": b"not an actual uninstaller",
                "installer-metadata/unins017.dat": b"not an actual registry log",
                "managed/user/app/main.bin": data,
                "managed/privileged/app/native.stub": data
            }
        else:
            prefix = "Package_1.5.7/"
            items = {
                prefix + "PACKAGE_MANIFEST.json": json.dumps({
                    "schema": 1, "product": "Direct Internet Method",
                    "version": "1.5.7", "platform": "linux-x86_64",
                    "files": [{"file": "app/main.bin", **file}]}).encode(),
                prefix + "SHA256SUMS.txt": b"not a publisher signature",
                prefix + "app/main.bin": data
            }
        source = self.dir/"source.zip"
        with zipfile.ZipFile(source, "w") as z:
            for name, raw in items.items():
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                z.writestr(info, raw)
        return source, hashlib.sha256(source.read_bytes()).hexdigest()

    def options(self, file, pin):
        return ["--platform",self.platform,"--archive",str(file),
                "--archive-sha256",pin,"--archive-kind",self.kind,
                "--destination",str(self.dir/"normalized")]

    def test_valid_pinned_archive_import_roundtrip(self):
        f,p=self.source()
        rc,result=self.invoke(["import-archive",*self.options(f,p)])
        self.assertEqual(rc,0,result)
        self.assertEqual(result["status"],"PASS_IMPORTED_VERIFIED_CODE_BUNDLE_ONLY")
        manifest=read_package(self.dir/"normalized",
                              result["normalized_manifest_sha256"],self.platform)
        self.assertEqual(manifest["version"],"1.5.7")

    def test_wrong_archive_pin_fails_closed(self):
        f,_=self.source()
        rc,result=self.invoke(["import-archive",*self.options(f,"0"*64)])
        self.assertEqual((rc,result["status"]),(3,"FAIL_CLOSED"))
        self.assertFalse((self.dir/"normalized").exists())

    def test_import_never_accepts_native_assertion_flags(self):
        f,p=self.source()
        rc,result=self.invoke(["import-archive",*self.options(f,p),"--accepted"])
        self.assertEqual((rc,result["status"]),(3,"FAIL_CLOSED"))
        self.assertIn("NOT_AN_INSTALL_TRANSACTION",result["reason"])
        self.assertFalse((self.dir/"normalized").exists())

    def test_foreign_os_platform_refused(self):
        f,p=self.source()
        foreign="windows-x86_64" if os.name != "nt" else "linux-x86_64"
        args=["import-archive",*self.options(f,p)]
        args[args.index("--platform")+1]=foreign
        rc,result=self.invoke(args)
        self.assertEqual((rc,result["status"]),(3,"FAIL_CLOSED"))
        self.assertFalse((self.dir/"normalized").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
