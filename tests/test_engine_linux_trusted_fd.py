"""R898 actual Linux kernel openat2+fd anchored protected source verification.

These read-only tests run as an unprivileged Linux user. A valid digest here
is not a publisher signature or an authorization to install or elevate.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from installer_engine.engine import EngineError
from installer_engine import linux_trusted_fd as fdlogic
from installer_engine.linux_trusted_fd import TrustedLinuxRootFD


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "Linux native file descriptor fixture only")
class LinuxTrustedFDTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.public_file = Path("/usr/share/common-licenses/GPL-3")
        if not cls.public_file.is_file() or cls.public_file.is_symlink():
            raise unittest.SkipTest("Expected non-symlink public Linux license missing")
        cls.expected = hashlib.sha256(cls.public_file.read_bytes()).hexdigest()
        cls.length = cls.public_file.stat().st_size

    def test_actual_kernel_openat2_pin_public_root_file(self):
        with TrustedLinuxRootFD(self.public_file.parent) as root:
            result = root.read_pinned_member(
                self.public_file.name, self.expected, self.length)
        self.assertEqual(result["sha256"], self.expected)
        self.assertEqual(result["bytes"], self.length)
        self.assertFalse(result["native_installation_accepted"])
        self.assertFalse(result["publisher_authenticated"])
        self.assertIn("NOT_AUTHORIZATION", result["status"])

    def test_actual_root_owned_nested_directory_open_and_pin(self):
        with TrustedLinuxRootFD("/usr/share") as root:
            result = root.read_pinned_member(
                "common-licenses/GPL-3", self.expected, self.length)
        self.assertEqual(result["sha256"], self.expected)
        self.assertFalse(result["native_installation_accepted"])

    def test_world_writable_intermediate_parent_refused_before_read(self):
        with TrustedLinuxRootFD("/") as root:
            # /tmp is normally sticky but world writable. A policy source
            # must not reside under a replaceable untrusted ancestor.
            with self.assertRaisesRegex(
                    EngineError, "TRUSTED_FD_UNSAFE_DIRECTORY_COMPONENT"):
                root.read_pinned_member("tmp/irrelevant-synthetic-file",
                                        "0" * 64, 0)

    def test_wrong_external_digest_refused(self):
        with TrustedLinuxRootFD(self.public_file.parent) as root:
            with self.assertRaisesRegex(EngineError, "MEMBER_PIN_MISMATCH"):
                root.read_pinned_member(self.public_file.name, "0" * 64,
                                        self.length)

    def test_wrong_external_size_refused(self):
        with TrustedLinuxRootFD(self.public_file.parent) as root:
            with self.assertRaisesRegex(EngineError, "MEMBER_SIZE_MISMATCH"):
                root.read_pinned_member(self.public_file.name, self.expected,
                                        self.length + 1)

    def test_unpinned_file_and_invalid_digest_refused(self):
        with TrustedLinuxRootFD(self.public_file.parent) as root:
            with self.assertRaisesRegex(EngineError, "TRUSTED_FD_EXPECTED_PIN"):
                root.read_pinned_member(self.public_file.name, "not-a-hash",
                                        self.length)
            with self.assertRaisesRegex(EngineError, "TRUSTED_FD_EXPECTED_SIZE"):
                root.read_pinned_member(self.public_file.name, self.expected, -1)

    def test_beneath_escape_and_absolute_member_refused(self):
        with TrustedLinuxRootFD(self.public_file.parent) as root:
            for candidate in ("../etc/passwd", "/etc/passwd", "sub/../../evil",
                              "foo//bar", "./GPL-3", "NUL"):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(EngineError):
                        root.read_pinned_member(candidate,self.expected,self.length)

    def test_user_writable_parent_rejected_without_touching_files(self):
        with tempfile.TemporaryDirectory(prefix="dim-r898-dirfd-") as d:
            fake_root = Path(d)/"supposed-protected"
            fake_root.mkdir()
            fixture = fake_root/"owned-by-user.txt"
            fixture.write_text("Do not touch")
            with self.assertRaises(EngineError):
                TrustedLinuxRootFD(fake_root)
            self.assertEqual(fixture.read_text(),"Do not touch")

    def test_symlink_directory_component_rejected(self):
        with tempfile.TemporaryDirectory(prefix="dim-r898-symlink-") as d:
            dest=Path(d)/"target"
            dest.mkdir()
            link=Path(d)/"link"
            link.symlink_to(dest, target_is_directory=True)
            with self.assertRaises(EngineError):
                TrustedLinuxRootFD(link)
            self.assertTrue(link.is_symlink())

    def test_openat2_symlink_file_and_intermediate_rejected(self):
        with tempfile.TemporaryDirectory(prefix="dim-r898-openat2-") as d:
            directory=Path(d)
            (directory/"owned.txt").write_bytes(b"FIXTURE")
            (directory/"other").mkdir()
            (directory/"other"/"b.bin").write_bytes(b"STAY")
            (directory/"shortcut").symlink_to(directory/"other",
                                              target_is_directory=True)
            (directory/"alias.txt").symlink_to(directory/"owned.txt")
            base=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                for value in ("alias.txt", "shortcut/b.bin"):
                    with self.subTest(value=value):
                        with self.assertRaisesRegex(
                                EngineError,"TRUSTED_FD_MEMBER_OPEN_REFUSED"):
                            fdlogic._openat2_beneath(base,value)
                fd=fdlogic._openat2_beneath(base,"owned.txt")
                try:
                    self.assertEqual(os.read(fd,7),b"FIXTURE")
                finally:
                    os.close(fd)
            finally:
                os.close(base)

    def test_openat2_descriptor_identity_survives_directory_rename(self):
        with tempfile.TemporaryDirectory(prefix="dim-r898-rename-") as d:
            parent=Path(d)
            original=parent/"original"
            renamed=parent/"renamed"
            original.mkdir()
            payload=original/"payload.bin"
            payload.write_bytes(b"ORIGINAL_INODE")
            fd=os.open(original,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                original.rename(renamed)
                original.mkdir()
                (original/"payload.bin").write_bytes(b"ATTACKER_NEW_PATH")
                readfd=fdlogic._openat2_beneath(fd,"payload.bin")
                try:
                    self.assertEqual(os.read(readfd,64),b"ORIGINAL_INODE")
                finally:
                    os.close(readfd)
            finally:
                os.close(fd)

    def test_nonexistent_kernel_syscall_does_not_fallback(self):
        with TrustedLinuxRootFD(self.public_file.parent) as root:
            with mock.patch.object(fdlogic, "_openat2_beneath",
                                   side_effect=EngineError("TRUSTED_FD_OPENAT2_NOT_SUPPORTED")):
                with self.assertRaisesRegex(EngineError,"OPENAT2_NOT_SUPPORTED"):
                    root.read_pinned_member(
                        self.public_file.name,self.expected,self.length)

    def test_closed_root_fd_refuses_file_read(self):
        root=TrustedLinuxRootFD(self.public_file.parent)
        root.close()
        with self.assertRaisesRegex(EngineError,"TRUSTED_FD_CLOSED"):
            root.read_pinned_member(
                self.public_file.name,self.expected,self.length)


if __name__=="__main__":
    unittest.main()
