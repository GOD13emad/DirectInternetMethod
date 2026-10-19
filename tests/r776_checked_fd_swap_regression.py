#!/usr/bin/env python3
"""R776 negative-first deterministic metadata/manifest TOCTOU read regression.

Scratch-owned fake root only; no elevated privileges, installed files or network.
A controlled file swap occurs immediately after an existing validity check.
"""
import importlib.util
from contextlib import contextmanager
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "dim_r776_toc", ROOT / "linux/system/protected_upgrade_transaction.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

def write_json(p, data, mode=0o644):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, sort_keys=True) + "\n", encoding="utf-8")
    p.chmod(mode)

class SwappedPathAfterCheck(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="r776-fakeroot-", dir=str(ROOT))
        self.home = pathlib.Path(self.tmp.name)
        self.root = self.home / "fake"
        self.tx = mod.RootTransaction(self.root)
        self.meta = self.tx.meta
        self.good = {
            "schema": 1, "version": mod.CURRENT_BACKEND_VERSION,
            "uid": 1000, "user": "trusted", "home": "/home/trusted"
        }
        self.evil = dict(self.good, user="attacker", home="/home/attacker")
        write_json(self.meta, self.good)
        self.malicious_meta = self.home / "user-controlled-meta.json"
        write_json(self.malicious_meta, self.evil)
        marker = self.root / "etc/directinternetmethod.uid"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("1000\n", encoding="utf-8")
        self.manifest = self.tx.pending / "manifest.json"
        self.good_manifest = {
            "schema": mod.SCHEMA, "revision": "R519",
            "fromVersion": mod.CURRENT_BACKEND_VERSION,
            "toVersion": mod.TARGET_VERSION, "phase": "STAGED",
            "files": {name: {} for name,*_ in mod.FILES},
        }
        self.evil_manifest = dict(self.good_manifest, phase="COMMITTED")
        write_json(self.manifest, self.good_manifest, mode=0o600)
        self.malicious_manifest = self.home / "user-controlled-manifest.json"
        write_json(self.malicious_manifest, self.evil_manifest, mode=0o600)

    def tearDown(self):
        self.tmp.cleanup()

    def swap_during_check(self, target, replacement):
        original = mod.no_symlink_regular
        called = []
        def check_and_swap(p, owner=True):
            st = original(p, owner)
            if pathlib.Path(p) == target:
                called.append(True)
                target.rename(target.with_name(target.name + ".original"))
                target.symlink_to(replacement)
            return st
        mod.no_symlink_regular = check_and_swap
        return original, called

    def test_legacy_metadata_mode_error_is_preserved(self):
        self.meta.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, "METADATA_MODE"):
            self.tx.original_metadata()
    def test_valid_unmodified_metadata(self):
        self.assertEqual(self.tx.original_metadata(), self.good)

    def test_valid_unmodified_manifest(self):
        self.assertEqual(self.tx.manifest()["phase"], "STAGED")

    def test_metadata_swap_does_not_accept_unvalidated_path(self):
        original, called = self.swap_during_check(self.meta, self.malicious_meta)
        try:
            try:
                result = self.tx.original_metadata()
            except RuntimeError:
                return
            self.assertNotEqual(result["home"], "/home/attacker",
                                "R776_TOCTOU_WRONG_METADATA_ACCEPTED")
        finally:
            mod.no_symlink_regular = original

    def test_manifest_swap_does_not_accept_unvalidated_path(self):
        original, called = self.swap_during_check(self.manifest, self.malicious_manifest)
        try:
            try:
                result = self.tx.manifest()
            except RuntimeError:
                return
            self.assertNotEqual(result["phase"], "COMMITTED",
                                "R776_TOCTOU_WRONG_MANIFEST_ACCEPTED")
        finally:
            mod.no_symlink_regular = original

    def swap_after_inode_is_open(self, target, replacement):
        """Model a rename/symlink race AFTER the source inode is pinned."""
        original = mod.verified_regular_fd
        swapped = []
        @contextmanager
        def open_and_swap(path):
            with original(path) as (fd, st):
                if pathlib.Path(path) == target:
                    swapped.append(True)
                    target.rename(target.with_name(target.name + ".pinned"))
                    target.symlink_to(replacement)
                yield fd, st
        mod.verified_regular_fd = open_and_swap
        return original, swapped

    def test_original_metadata_read_remains_on_pinned_inode(self):
        original, switched = self.swap_after_inode_is_open(self.meta, self.malicious_meta)
        try:
            self.assertEqual(self.tx.original_metadata(), self.good)
            self.assertEqual(switched, [True])
        finally:
            mod.verified_regular_fd = original

    def test_manifest_read_remains_on_pinned_inode(self):
        original, switched = self.swap_after_inode_is_open(
            self.manifest, self.malicious_manifest)
        try:
            self.assertEqual(self.tx.manifest()["phase"], "STAGED")
            self.assertEqual(switched, [True])
        finally:
            mod.verified_regular_fd = original

if __name__ == "__main__":
    unittest.main(verbosity=2)
