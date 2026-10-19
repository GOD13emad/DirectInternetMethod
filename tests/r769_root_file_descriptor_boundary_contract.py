#!/usr/bin/env python3
"""Rootless R769 path-taint regression: no real installation, no privilege, no network."""
import hashlib
import importlib.util
import pathlib
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE=ROOT/"linux/system/protected_upgrade_transaction.py"
SPEC=importlib.util.spec_from_file_location("r769_root_tx",SOURCE)
MOD=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

class SecureFileAccess(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="r769-userowned-",dir=str(ROOT))
        self.root=pathlib.Path(self.temp.name)
        self.trusted=self.root/"actual"
        self.trusted.mkdir()
        self.payload=self.trusted/"payload"
        self.payload.write_bytes(b"FAKE_STATIC_ROOT_PAYLOAD")
        self.alias=self.root/"redirected"
        self.alias.symlink_to(self.trusted,target_is_directory=True)
        self.target=self.alias/"payload"
        self.assertTrue(self.target.is_file())
        self.assertFalse(self.target.is_symlink())

    def tearDown(self):
        self.temp.cleanup()

    def test_symlink_parent_hash_must_fail_closed(self):
        with self.assertRaisesRegex(RuntimeError,"FAIL_CLOSED_UNSAFE_PARENT_COMPONENT"):
            MOD.hash_file(self.target)

    def test_symlink_parent_regular_stat_must_fail_closed(self):
        with self.assertRaisesRegex(RuntimeError,"FAIL_CLOSED_UNSAFE_PARENT_COMPONENT"):
            MOD.no_symlink_regular(self.target,owner=False)

    def test_valid_private_file_preserves_hash_and_stat(self):
        self.assertEqual(MOD.hash_file(self.payload),hashlib.sha256(self.payload.read_bytes()).hexdigest().upper())
        info=MOD.no_symlink_regular(self.payload,owner=False)
        self.assertEqual(info.st_size,len(self.payload.read_bytes()))

    def test_large_root_static_binary_streams_safely(self):
        # 8 MiB file exercises legitimate static 'ctrld' size without reading OS root.
        large=self.root/"large-static"
        with large.open("wb") as writer:
            writer.write(b"X"*(8*1024*1024))
        self.assertEqual(MOD.hash_file(large),hashlib.sha256(large.read_bytes()).hexdigest().upper())

if __name__=="__main__":
    unittest.main(verbosity=2)
