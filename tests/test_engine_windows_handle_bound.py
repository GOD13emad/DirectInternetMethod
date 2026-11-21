"""Windows held-file-handle native read-only SHA and pathname consistency.

No SCM, UAC, service change, protected file write, or release acceptance.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from installer_engine.engine import EngineError
from installer_engine.windows_handle_bound import read_windows_pinned_file


@unittest.skipUnless(os.name == "nt", "Windows native handles required")
class WindowsNativeHandleVerification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "owned.bin"
        self.body = b"WIN32-HELD-HANDLE-READ-ONLY-TEST\x00" * 512
        self.path.write_bytes(self.body)
        self.pin = hashlib.sha256(self.body).hexdigest()

    def test_valid_exact_handle_readback_no_native_authorization(self):
        result = read_windows_pinned_file(self.path, len(self.body), self.pin)
        self.assertEqual(result["sha256"], self.pin)
        self.assertTrue(result["held_handle_hash_verified"])
        self.assertFalse(result["native_installation_accepted"])
        self.assertFalse(result["protected_write_performed"])
        self.assertFalse(result["publisher_authenticated"])
        self.assertEqual(self.path.read_bytes(), self.body)

    def test_hash_tamper_denied(self):
        with self.assertRaisesRegex(EngineError, "WIN32_HANDLE_PIN_MISMATCH"):
            read_windows_pinned_file(self.path, len(self.body), "0" * 64)

    def test_size_tamper_denied(self):
        with self.assertRaisesRegex(EngineError, "WIN32_HANDLE_SIZE_MISMATCH"):
            read_windows_pinned_file(self.path, len(self.body) + 1, self.pin)

    def test_unrecognized_native_path_denied(self):
        with self.assertRaisesRegex(EngineError, "WIN32_HANDLE_LOCAL_CANONICAL_PATH_REQUIRED"):
            read_windows_pinned_file(Path("relative.bin"), 1, "0" * 64)

    def test_parent_directory_is_not_regular_file(self):
        with self.assertRaisesRegex(EngineError, "WIN32_HANDLE_(OPEN_DENIED_OR_SHARING_CONFLICT|REPARSE_DIRECTORY_OR_LINK)"):
            read_windows_pinned_file(Path(self.tmp.name), 0, hashlib.sha256(b"").hexdigest())

    def test_reparse_link_rejected_where_supported(self):
        link = Path(self.tmp.name) / "link.bin"
        try:
            link.symlink_to(self.path)
        except (OSError, NotImplementedError):
            self.skipTest("native symlink creation requires OS privilege")
        with self.assertRaisesRegex(EngineError, "WIN32_HANDLE_REPARSE_DIRECTORY_OR_LINK"):
            read_windows_pinned_file(link, len(self.body), self.pin)

    def test_readonly_share_mode_denies_concurrent_file_replacement(self):
        from installer_engine.windows_handle_bound import _windows_api
        import ctypes
        api = _windows_api()
        replacement = Path(self.tmp.name) / "replacement.bin"
        replacement.write_bytes(b"foreign")
        handle = api.CreateFileW(str(self.path), 0x80000000, 0x00000001,
                                 None, 3, 0x00200000, None)
        self.assertNotIn(handle, (None, ctypes.c_void_p(-1).value))
        try:
            with self.assertRaises((PermissionError, OSError)):
                os.replace(replacement, self.path)
            self.assertEqual(self.path.read_bytes(), self.body)
            self.assertEqual(replacement.read_bytes(), b"foreign")
        finally:
            self.assertTrue(api.CloseHandle(handle))

    def test_runtime_bound_cannot_be_weakened_by_caller(self):
        with self.assertRaisesRegex(EngineError, "WIN32_HANDLE_EXPECTED_SIZE_OR_SHA_INVALID"):
            read_windows_pinned_file(self.path, 1 << 31, self.pin)
