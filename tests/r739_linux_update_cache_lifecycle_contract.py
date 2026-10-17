#!/usr/bin/env python3
"""R739: verify production Linux update installer never leaves new cache or code debris.

All HTTPS downloads and installer invocations are replaced by explicit in-memory
fixtures inside a disposable HOME; no real operating-system service, network,
release publication, user state or installer is touched.
"""
from __future__ import annotations

import ast
import hashlib
import io
import json
import os
import pathlib
import stat
import tempfile
import types
import unittest
import zipfile
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "linux/app/direct_internet_method.py").read_text("utf-8-sig")
TREE = ast.parse(SOURCE)
METHOD = [n for n in TREE.body if isinstance(n, ast.FunctionDef) and
          n.name == "download_and_install_update"]
assert len(METHOD) == 1, "R739_ONE_PRODUCTION_UPDATE_FUNCTION_REQUIRED"
fn_scope = {
    "pathlib": pathlib, "tempfile": tempfile, "hashlib": hashlib,
    "json": json, "zipfile": zipfile, "os": os, "stat": stat,
    "re": __import__("re"),
}
exec(compile(ast.Module(body=METHOD, type_ignores=[]), "installed_linux_updater_real_function", "exec"), fn_scope)
install = fn_scope["download_and_install_update"]

VERSION = "1.5.6"
ARCHIVE_NAME = f"DirectInternetMethod_{VERSION}_Linux_x86_64.zip"
PREFIX = ARCHIVE_NAME.removesuffix(".zip") + "/"

def build_zip(kind="good"):
    source = {"install.sh": b"#!/bin/bash\nexit 0\n"}
    source.update({f"app/fixture{i:02d}.bin": f"fixture-{i}\n".encode()
                   for i in range(26)})
    if kind == "missing_installer":
        source["another_installer.sh"] = source.pop("install.sh")
    rows = [{"file": key, "bytes": len(raw),
             "sha256": hashlib.sha256(raw).hexdigest().upper()}
            for key, raw in source.items()]
    manifest = {"schema": 1, "product": "Direct Internet Method",
                "platform": "linux-x86_64", "version": VERSION, "files": rows}
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", compression=zipfile.ZIP_STORED) as z:
        for key, data in source.items():
            zi = zipfile.ZipInfo(PREFIX + key)
            if kind == "symlink" and key == "app/fixture00.bin":
                zi.create_system = 3
                zi.external_attr = ((stat.S_IFLNK | 0o777) << 16)
            z.writestr(zi, data)
        z.writestr(PREFIX + "PACKAGE_MANIFEST.json",
                   json.dumps(manifest).encode())
        z.writestr(PREFIX + "SHA256SUMS.txt",
                   "".join(f"{r['sha256']}  {r['file']}\n" for r in rows))
        if kind == "traversal":
            z.writestr(PREFIX + "../escape.txt", b"should-never-extract")
        if kind == "duplicate":
            z.writestr(PREFIX + "install.sh", b"bad-extra-installer")
    return memory.getvalue()

class CacheTruth(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="r739-updater-real-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.home = pathlib.Path(self.temp.name) / "home"
        self.home.mkdir()
        self.cache = self.home / ".cache/DirectInternetMethod/updates"
        self.bad_kind = "good"
        self.payload = build_zip()
        self.sums_raw = hashlib.sha256(self.payload).hexdigest().upper() + "  " + ARCHIVE_NAME + "\n"
        self.sums = self.sums_raw.encode()
        self.info = {
            "version": VERSION, "tag": "v"+VERSION,
            "asset": {"name": ARCHIVE_NAME, "url": "fixture://zip",
                      "digest": "sha256:" + hashlib.sha256(self.payload).hexdigest()},
            "sums": {"name": "SHA256SUMS.txt", "url": "fixture://sums",
                     "digest": "sha256:" + hashlib.sha256(self.sums).hexdigest()},
        }
        self.install_calls = []
        def fake_download(url, path):
            data = self.sums if url == "fixture://sums" else self.payload
            if url not in ("fixture://sums", "fixture://zip"):
                raise AssertionError("NON_FIXTURE_DOWNLOAD_ATTEMPT")
            pathlib.Path(path).write_bytes(data)
        def fake_run(argv, **kwargs):
            self.install_calls.append(list(argv))
            target = pathlib.Path(argv[1])
            assert argv[0] == "bash" and target.is_file()
            assert target.read_bytes().startswith(b"#!/bin/bash\n")
            return types.SimpleNamespace(returncode=0, stdout="INSTALLER_MOCK_PASS\n", stderr="")
        fn_scope["_download"] = fake_download
        fn_scope["subprocess"] = types.SimpleNamespace(run=fake_run)
        self.home_patch = mock.patch.object(pathlib.Path, "home", return_value=self.home)
        self.home_patch.start()
        self.addCleanup(self.home_patch.stop)

    def assert_no_new_residue(self):
        self.assertFalse(self.cache.exists() and any(self.cache.iterdir()),
                         "R739_NEW_CACHE_DEBRIS_MUST_BE_EMPTY_AFTER_ANY_RESULT")
        self.assertFalse(any(self.home.rglob("install.sh")),
                         "R739_EXTRACTED_INSTALLER_REMAINS")

    def test_01_good_release_installer_returns_and_cleans_all_cache(self):
        result = install(self.info)
        self.assertEqual(result, "INSTALLER_MOCK_PASS")
        self.assertEqual(len(self.install_calls), 1)
        self.assert_no_new_residue()

    def test_02_preexisting_unrelated_file_is_preserved(self):
        self.cache.mkdir(parents=True)
        keep = self.cache / "unrelated-user-file"
        keep.write_bytes(b"KEEP_USER_DATA")
        self.assertEqual(install(self.info), "INSTALLER_MOCK_PASS")
        self.assertEqual(keep.read_bytes(), b"KEEP_USER_DATA")
        self.assertEqual(sorted(x.name for x in self.cache.iterdir()), [keep.name])

    def test_03_checksum_list_digest_mismatch_cleans(self):
        self.sums += b"tampered\n"
        with self.assertRaises(RuntimeError):
            install(self.info)
        self.assertEqual(self.install_calls, [])
        self.assert_no_new_residue()

    def test_04_zip_sha256_mismatch_cleans(self):
        self.payload += b"tamper"
        with self.assertRaises(RuntimeError):
            install(self.info)
        self.assertEqual(self.install_calls, [])
        self.assert_no_new_residue()

    def test_05_installer_failure_also_cleans(self):
        def failed(argv, **kwargs):
            return types.SimpleNamespace(returncode=1, stdout="", stderr="MOCK_INSTALL_FAILED")
        fn_scope["subprocess"] = types.SimpleNamespace(run=failed)
        with self.assertRaisesRegex(RuntimeError, "MOCK_INSTALL_FAILED"):
            install(self.info)
        self.assert_no_new_residue()

    def test_06_missing_expected_root_installer_refused(self):
        self.payload = build_zip("missing_installer")
        self.info["asset"]["digest"] = "sha256:" + hashlib.sha256(self.payload).hexdigest()
        self.sums = (hashlib.sha256(self.payload).hexdigest().upper() + "  " + ARCHIVE_NAME + "\n").encode()
        self.info["sums"]["digest"] = "sha256:" + hashlib.sha256(self.sums).hexdigest()
        with self.assertRaises(RuntimeError):
            install(self.info)
        self.assertEqual(self.install_calls, [])
        self.assert_no_new_residue()

    def test_07_symlink_member_refused_even_with_correct_zip_sha(self):
        self.payload = build_zip("symlink")
        self.info["asset"]["digest"] = "sha256:" + hashlib.sha256(self.payload).hexdigest()
        self.sums = (hashlib.sha256(self.payload).hexdigest().upper() + "  " + ARCHIVE_NAME + "\n").encode()
        self.info["sums"]["digest"] = "sha256:" + hashlib.sha256(self.sums).hexdigest()
        with self.assertRaises(RuntimeError):
            install(self.info)
        self.assertEqual(self.install_calls, [])
        self.assert_no_new_residue()

    def test_08_wrong_or_traversal_asset_name_rejected_before_download(self):
        self.info["asset"]["name"] = "../unrelated-file.zip"
        with self.assertRaises(RuntimeError):
            install(self.info)
        self.assertEqual(self.install_calls, [])
        self.assert_no_new_residue()

    def test_09_bad_zip_member_traversal_refused(self):
        self.payload = build_zip("traversal")
        self.info["asset"]["digest"] = "sha256:" + hashlib.sha256(self.payload).hexdigest()
        self.sums = (hashlib.sha256(self.payload).hexdigest().upper() + "  " + ARCHIVE_NAME + "\n").encode()
        self.info["sums"]["digest"] = "sha256:" + hashlib.sha256(self.sums).hexdigest()
        with self.assertRaises(RuntimeError):
            install(self.info)
        self.assertEqual(self.install_calls, [])
        self.assert_no_new_residue()

    @unittest.skipUnless(hasattr(os, "symlink"), "host cannot make symlinks")
    def test_10_symlink_cache_root_refused_without_outside_writes(self):
        outside = self.home / "outside"
        outside.mkdir()
        self.cache.parent.mkdir(parents=True)
        try:
            self.cache.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Host policy prohibits symlink creation; exercised on Linux CI")
        with self.assertRaises(Exception):
            install(self.info)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(self.install_calls, [])

    def test_11_duplicate_zip_member_refused(self):
        self.payload = build_zip("duplicate")
        self.info["asset"]["digest"] = "sha256:" + hashlib.sha256(self.payload).hexdigest()
        self.sums = (hashlib.sha256(self.payload).hexdigest().upper() + "  " + ARCHIVE_NAME + "\n").encode()
        self.info["sums"]["digest"] = "sha256:" + hashlib.sha256(self.sums).hexdigest()
        with self.assertRaises(RuntimeError):
            install(self.info)
        self.assertEqual(self.install_calls, [])
        self.assert_no_new_residue()

    def test_12_repeated_installs_do_not_accumulate_tmp_dirs(self):
        for i in range(3):
            self.assertEqual(install(self.info), "INSTALLER_MOCK_PASS")
            self.assert_no_new_residue()
        self.assertEqual(len(self.install_calls), 3)

if __name__ == "__main__":
    unittest.main(verbosity=1)
    print("R739_REAL_PRODUCTION_LINUX_UPDATER_CACHE_SECURITY_12_TESTS_PASS")
