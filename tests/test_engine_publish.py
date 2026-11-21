"""Cross-platform adversarial no-clobber directory publishing."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from installer_engine.engine import EngineError
from installer_engine.publish import publish_new_directory, _rename_noreplace


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="dim-publish-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.src = self.root / "private-staging"
        self.dst = self.root / "published"
        self.src.mkdir()
        (self.src / "code.bin").write_bytes(b"PINNED_FIXTURE")

    def test_new_destination_published_atomically(self):
        publish_new_directory(self.src, self.dst)
        self.assertFalse(self.src.exists())
        self.assertEqual((self.dst/"code.bin").read_bytes(), b"PINNED_FIXTURE")

    def test_preexisting_empty_destination_preserved(self):
        self.dst.mkdir()
        with self.assertRaisesRegex(EngineError, "BUNDLE_DESTINATION_ALREADY_EXISTS"):
            publish_new_directory(self.src, self.dst)
        self.assertTrue(self.dst.is_dir())
        self.assertTrue(self.src.exists())

    def test_preexisting_foreign_directory_preserved(self):
        self.dst.mkdir()
        (self.dst/"user-settings").write_bytes(b"FOREIGN")
        with self.assertRaisesRegex(EngineError, "BUNDLE_DESTINATION_ALREADY_EXISTS"):
            publish_new_directory(self.src, self.dst)
        self.assertEqual((self.dst/"user-settings").read_bytes(), b"FOREIGN")
        self.assertTrue(self.src.exists())

    def test_existing_foreign_file_preserved(self):
        self.dst.write_bytes(b"FOREIGN")
        with self.assertRaisesRegex(EngineError, "BUNDLE_DESTINATION_ALREADY_EXISTS"):
            publish_new_directory(self.src, self.dst)
        self.assertEqual(self.dst.read_bytes(), b"FOREIGN")

    def test_cross_parent_rejected(self):
        self.dst = self.root / "other" / "published"
        self.dst.parent.mkdir()
        with self.assertRaisesRegex(EngineError, "ATOMIC_NOREPLACE_DIRECTORY_PAIR_INVALID"):
            publish_new_directory(self.src, self.dst)
        self.assertTrue(self.src.exists())

    def test_destination_appears_after_preflight_and_before_syscall(self):
        real = _rename_noreplace

        def inject(src, dst):
            dst.mkdir()
            (dst/"foreign").write_bytes(b"DO_NOT_REPLACE")
            return real(src, dst)

        with mock.patch("installer_engine.publish._rename_noreplace",
                        side_effect=inject):
            with self.assertRaises(EngineError):
                publish_new_directory(self.src, self.dst)
        self.assertEqual((self.dst/"foreign").read_bytes(), b"DO_NOT_REPLACE")
        self.assertTrue(self.src.exists())

    @unittest.skipIf(os.name == "nt", "Windows symlink privilege not assumed")
    def test_preexisting_symlink_refused(self):
        self.dst.symlink_to(self.src, target_is_directory=True)
        with self.assertRaises(EngineError):
            publish_new_directory(self.src, self.dst)
        self.assertTrue(self.src.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
