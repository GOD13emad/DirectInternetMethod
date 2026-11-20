"""Portable, negative-first tests of independently pinned source ZIP ingestion.

All fixtures are tiny and temporary. No real installer, Service Manager,
registry, root/systemd or owner application state is touched.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
import warnings
import zipfile

from installer_engine.archive_import import import_pinned_archive
from installer_engine.engine import Engine, EngineError, read_package


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ArchiveImportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="dim-source-import-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)

    def _zip(self, name, members, executable=()):
        path = self.home / name
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for key, content in members.items():
                info = zipfile.ZipInfo(key)
                info.create_system = 3
                permissions = 0o755 if key in executable else 0o644
                info.external_attr = (stat.S_IFREG | permissions) << 16
                z.writestr(info, content)
        return path

    def windows_members(self):
        a, b = b"GUI", b"SERVICE"
        document = {
            "schema": 2, "product":"Direct Internet Method", "version":"1.5.6",
            "files":[
                {"scope":"user","file":"app/DirectInternetMethod.exe",
                 "source":"app/DirectInternetMethod.exe",
                 "bytes":len(a),"sha256":digest(a)},
                {"scope":"privileged","file":"app/DirectInternetMethod.Service.exe",
                 "source":"app/DirectInternetMethod.Service.exe",
                 "bytes":len(b),"sha256":digest(b)},
            ],
        }
        return {
            "installer-metadata/manifest.json":json.dumps(document).encode(),
            "installer-metadata/RELEASE.json":b'{"version":"1.5.6"}',
            "installer-metadata/unins001.exe":b"mock Inno metadata",
            "installer-metadata/unins001.dat":b"mock Inno log",
            "managed/user/app/DirectInternetMethod.exe":a,
            "managed/privileged/app/DirectInternetMethod.Service.exe":b,
        }

    def linux_members(self):
        a, b = b"#!/bin/sh\nexit 0\n", b"README"
        prefix = "DIM_1.5.7_Linux_x86_64/"
        doc = {
            "schema":1,"product":"Direct Internet Method","version":"1.5.7",
            "platform":"linux-x86_64",
            "files":[{"file":"install.sh","bytes":len(a),"sha256":digest(a)},
                     {"file":"README.md","bytes":len(b),"sha256":digest(b)}]
        }
        return {
            prefix+"PACKAGE_MANIFEST.json":json.dumps(doc).encode(),
            prefix+"SHA256SUMS.txt":b"fixed by archive pin",
            prefix+"install.sh":a,
            prefix+"README.md":b,
        }

    def _import(self, members, kind, name="fixture.zip", *, executable=()):
        source = self._zip(name, members, executable=executable)
        target = self.home / (name + ".normalized")
        report = import_pinned_archive(source, digest(source.read_bytes()), target, kind)
        self.assertTrue(target.is_dir())
        self.assertFalse(report["native_installer_or_service_registered"])
        self.assertEqual(read_package(target, report["normalized_manifest_sha256"],
                                      report["platform"])["version"],report["version"])
        return report,target

    def test_windows_managed_archive_both_scopes_stage_commit_uninstall(self):
        report,bundle=self._import(self.windows_members(),"windows-managed")
        self.assertEqual((report["files"],report["version"],report["bytes"]),
                         (2,"1.5.6",10))
        root=self.home/"test_install"
        e=Engine(root,"windows-x86_64")
        e.stage(bundle,report["normalized_manifest_sha256"])
        e.activate(lambda:True)
        e.commit(lambda:True)
        self.assertEqual(e.verify()["files"],2)
        data=root/"data"/"user.settings";data.parent.mkdir()
        data.write_bytes(b"KEEP")
        e.prepare_uninstall(lambda:True)
        e.finish_uninstall(lambda:True)
        self.assertEqual(e.verify()["status"],"EMPTY")
        self.assertEqual(data.read_bytes(),b"KEEP")

    def test_linux_package_preserves_script_executable_metadata(self):
        members=self.linux_members()
        script=next(k for k in members if k.endswith("/install.sh"))
        report,bundle=self._import(members,"linux-distribution",
                                   executable=(script,))
        self.assertEqual(report["files"],2)
        normalized=json.loads((bundle/"manifest.json").read_text())
        modes={r["path"]:r["mode"] for r in normalized["files"]}
        self.assertEqual(modes["install.sh"],0o755)
        self.assertEqual(modes["README.md"],0o644)

    def test_reject_archive_pin_mismatch(self):
        source=self._zip("wrong-pin.zip",self.linux_members())
        with self.assertRaisesRegex(EngineError,"ARCHIVE_PIN_MISMATCH"):
            import_pinned_archive(source,"0"*64,self.home/"normalized","linux-distribution")

    def test_reject_tampered_windows_member_even_with_valid_outer_zip_pin(self):
        members=self.windows_members()
        members["managed/user/app/DirectInternetMethod.exe"]=b"BAD"
        source=self._zip("bad-member.zip",members)
        with self.assertRaisesRegex(EngineError,"ARCHIVE_MEMBER_SHA_MISMATCH"):
            import_pinned_archive(source,digest(source.read_bytes()),
                                  self.home/"normalized","windows-managed")
        self.assertFalse((self.home/"normalized").exists())

    def test_reject_undeclared_zip_member(self):
        members=self.linux_members()
        members["DIM_1.5.7_Linux_x86_64/extras/private.key"]=b"unknown"
        source=self._zip("extra.zip",members)
        with self.assertRaisesRegex(EngineError,"ARCHIVE_EXTRA_OR_MISSING_MEMBER"):
            import_pinned_archive(source,digest(source.read_bytes()),
                                  self.home/"normalized","linux-distribution")

    def test_reject_zip_traversal_member(self):
        members=self.windows_members()
        members["../../outside.txt"]=b"junk"
        source=self._zip("traversal.zip",members)
        with self.assertRaisesRegex(EngineError,"ARCHIVE_TRAVERSAL_MEMBER"):
            import_pinned_archive(source,digest(source.read_bytes()),
                                  self.home/"normalized","windows-managed")

    def test_reject_zip_symlink_member(self):
        members=self.linux_members()
        source=self.home/"bad-link.zip"
        with zipfile.ZipFile(source,"w") as z:
            for k,v in members.items():
                info=zipfile.ZipInfo(k)
                info.create_system=3
                info.external_attr=(stat.S_IFLNK|0o777)<<16 if k.endswith("install.sh") else (stat.S_IFREG|0o644)<<16
                z.writestr(info,v)
        with self.assertRaisesRegex(EngineError,"ARCHIVE_SYMLINK_MEMBER"):
            import_pinned_archive(source,digest(source.read_bytes()),
                                  self.home/"normalized","linux-distribution")

    def test_reject_mode_suid_in_linux_package(self):
        members=self.linux_members()
        source=self.home/"privileged-mode.zip"
        with zipfile.ZipFile(source,"w") as z:
            for k,v in members.items():
                info=zipfile.ZipInfo(k)
                info.create_system=3
                info.external_attr=(stat.S_IFREG|0o4755)<<16 if k.endswith("install.sh") else (stat.S_IFREG|0o644)<<16
                z.writestr(info,v)
        with self.assertRaisesRegex(EngineError,"ARCHIVE_PRIVILEGED_MODE_FORBIDDEN"):
            import_pinned_archive(source,digest(source.read_bytes()),
                                  self.home/"normalized","linux-distribution")

    def test_reject_duplicate_member(self):
        members=self.windows_members()
        source=self.home/"duplicate.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore",UserWarning)
            with zipfile.ZipFile(source,"w") as z:
                for k,v in members.items():z.writestr(k,v)
                z.writestr("managed/user/app/DirectInternetMethod.exe",b"GUI")
        with self.assertRaisesRegex(EngineError,"ARCHIVE_DUPLICATE_MEMBER"):
            import_pinned_archive(source,digest(source.read_bytes()),
                                  self.home/"normalized","windows-managed")

    def test_reject_destination_that_already_exists(self):
        source=self._zip("dest-exists.zip",self.windows_members())
        target=self.home/"already"
        target.mkdir()
        (target/"owner.txt").write_text("FOREIGN")
        with self.assertRaisesRegex(EngineError,"BUNDLE_DESTINATION_ALREADY_EXISTS"):
            import_pinned_archive(source,digest(source.read_bytes()),target,
                                  "windows-managed")
        self.assertEqual((target/"owner.txt").read_text(),"FOREIGN")


if __name__=="__main__":
    unittest.main(verbosity=2)
