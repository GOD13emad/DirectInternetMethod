#!/usr/bin/env python3
"""R795 lexical input guard for pinned file leaf. Isolated, unprivileged, no network."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sp=importlib.util.spec_from_file_location("dim_r795",ROOT/"linux/system/protected_upgrade_transaction.py")
m=importlib.util.module_from_spec(sp)
sp.loader.exec_module(m)

class FilenameContract(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix="dim-r795-user-",dir=str(ROOT))
        self.d=Path(self.tmp.name)
    def tearDown(self):
        self.tmp.cleanup()
    def test_normal_known_name_still_opened(self):
        p=self.d/"protected_install.json"
        p.write_bytes(b"source identity")
        with m.verified_regular_fd(p) as (fd,stat_result):
            self.assertEqual(stat_result.st_size,15)
            import os
            self.assertEqual(os.read(fd,15),b"source identity")
    def test_hostile_or_ambiguous_leaf_rejected(self):
        for name in ("hidden file", ".private", "contains\nnewline",
                     "semicolon;name", "dollar$name", "wild*name",
                     "other\\slash", "unicodé", "a"*129):
            with self.subTest(name=repr(name)):
                p=self.d/name
                p.write_bytes(b"foreign file")
                with self.assertRaisesRegex(RuntimeError,"FAIL_CLOSED_UNSAFE_FILE_COMPONENT"):
                    with m.verified_regular_fd(p):
                        self.fail("UNSAFE_LEAF_OPENED")
                self.assertEqual(p.read_bytes(),b"foreign file")
    def test_regex_valid_but_non_allowlisted_name_rejected(self):
        p=self.d/"unexpected-but-valid-name.txt"
        p.write_bytes(b"foreign contents")
        with self.assertRaisesRegex(RuntimeError,"FAIL_CLOSED_UNSAFE_FILE_COMPONENT"):
            with m.verified_regular_fd(p):
                self.fail("UNALLOWLISTED_FILE_OPENED")
        self.assertEqual(p.read_bytes(),b"foreign contents")
    def test_symlink_parent_still_rejected(self):
        t=self.d/"actual"
        t.mkdir()
        p=t/"allowed_file"
        p.write_bytes(b"okay")
        link=self.d/"linkdir"
        link.symlink_to(t,target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError,"FAIL_CLOSED_UNSAFE_PARENT_COMPONENT"):
            with m.verified_regular_fd(link/"allowed_file"):
                self.fail("SYMLINK_PARENT_FOLLOWED")

if __name__=="__main__":
    unittest.main(verbosity=2)
