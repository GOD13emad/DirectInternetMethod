"""R897 Linux read-only protected directory ownership chain fixture.

Verifies trust cannot be inferred from an apparently root-owned leaf when
one ancestor is user/group/other writable or reparse/symlink managed.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from installer_engine.engine import EngineError
from installer_engine.native_observe import observe_linux


@unittest.skipUnless(os.name == "posix", "Linux POSIX native custody observation")
class NativeProtectedPathCustodyTests(unittest.TestCase):
    def probe(self, path):
        unit={"unit":"dummy-example.service","LoadState":"not-found",
              "ActiveState":"inactive"}
        with mock.patch("installer_engine.native_observe._unit_observation",
                        return_value=unit):
            return observe_linux(path,["dummy-example.service"])

    def test_existing_root_path_has_trusted_ancestor_chain(self):
        # Pure read-only observation; / is the only platform-universal
        # identity on POSIX and we do NOT accept '/' as a product install path.
        if os.stat("/").st_uid != 0 or (stat.S_IMODE(os.stat("/").st_mode)&0o022):
            self.skipTest("OS root directory not root-owned and nonwritable")
        report=self.probe("/")
        self.assertTrue(report["protected_root_ancestor_chain_trusted"])
        self.assertIsNone(report["unsafe_ancestor"])
        self.assertFalse(report["native_installation_or_rollback_accepted"])

    def test_spoofed_root_owned_leaf_under_world_writable_parent_rejected(self):
        with tempfile.TemporaryDirectory(prefix="dim-r897-path-") as t:
            fake_leaf=Path(t)/"fake-root-owned"
            leaf_lstat=Path.lstat
            def spoof(self,*args,**kwargs):
                if self == fake_leaf:
                    return SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o755)
                return leaf_lstat(self,*args,**kwargs)
            with mock.patch.object(Path,"lstat",new=spoof):
                report=self.probe(fake_leaf)
            self.assertFalse(report["protected_root_ancestor_chain_trusted"])
            self.assertFalse(report["protected_root_safe_ownership_observed"])
            self.assertNotEqual(report["unsafe_ancestor"],str(fake_leaf))
            self.assertEqual(report["protected_root_uid"],0)

    def test_actual_user_owned_leaf_in_tmp_rejected(self):
        with tempfile.TemporaryDirectory(prefix="dim-r897-user-") as t:
            report=self.probe(t)
        self.assertFalse(report["protected_root_ancestor_chain_trusted"])
        self.assertIsNotNone(report["unsafe_ancestor"])

    def test_missing_root_refused_without_creating_it(self):
        with tempfile.TemporaryDirectory(prefix="dim-r897-missing-") as t:
            root=Path(t)/"DO_NOT_CREATE"
            report=self.probe(root)
            self.assertFalse(report["protected_root_safe_ownership_observed"])
            self.assertEqual(report["protected_root_uid"],None)
            self.assertFalse(root.exists())

    def test_existing_symlink_path_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="dim-r897-link-") as t:
            target=Path(t)/"target"
            target.mkdir()
            link=Path(t)/"link"
            link.symlink_to(target,target_is_directory=True)
            with self.assertRaisesRegex(EngineError,"LINK_PATH_REFUSED"):
                self.probe(link)

    def test_native_unit_observation_is_still_readonly(self):
        with tempfile.TemporaryDirectory(prefix="dim-r897-systemd-") as t:
            report=self.probe(t)
        self.assertEqual(report["units"][0]["unit"],"dummy-example.service")
        self.assertFalse(report["native_installation_or_rollback_accepted"])


if __name__=="__main__":
    unittest.main()
