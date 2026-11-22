"""Win32 read-only file handle-bound manifest attestation primitive.

Holds the *opened* file through hashing; denies share-write/share-delete,
reparse final files and unexpected final names. A pointer to a prior manifest
does NOT authenticate the publisher or authorize privileged writes. An attacker
with authority to replace protected directories still needs a separate OS-
authorized broker, ACL checks and independent deployment pin.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import functools
import hashlib
import os
from pathlib import Path
import re
import stat

from .engine import EngineError, require

_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_SHA = re.compile(r"[a-fA-F0-9]{64}\Z")


class _FILETIME(ctypes.Structure):
    _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]


class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("attributes", wintypes.DWORD),
        ("created", _FILETIME),
        ("accessed", _FILETIME),
        ("modified", _FILETIME),
        ("volume_serial", wintypes.DWORD),
        ("size_high", wintypes.DWORD),
        ("size_low", wintypes.DWORD),
        ("links", wintypes.DWORD),
        ("file_index_high", wintypes.DWORD),
        ("file_index_low", wintypes.DWORD),
    ]


@functools.lru_cache(maxsize=1)
def _windows_api():
    require(os.name == "nt", "WIN32_NATIVE_HANDLE_REQUIRED")
    dll = ctypes.WinDLL("kernel32", use_last_error=True)
    dll.CreateFileW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    dll.CreateFileW.restype = wintypes.HANDLE
    dll.GetFileInformationByHandle.argtypes = (
        wintypes.HANDLE, ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION))
    dll.GetFileInformationByHandle.restype = wintypes.BOOL
    dll.GetFinalPathNameByHandleW.argtypes = (
        wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
    dll.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    dll.CloseHandle.argtypes = (wintypes.HANDLE,)
    dll.CloseHandle.restype = wintypes.BOOL
    return dll


def _normalized(path: str) -> str:
    # Only local absolute drive paths are supported, not SMB/UNC, Volume GUID,
    # device namespaces, relative paths or caller-controlled alternate streams.
    import ntpath
    require(type(path) is str and bool(re.fullmatch(
        r"[a-zA-Z]:\\[^:*?<>|]*", path)) and not any(
        part in (".", "..", "") for part in path[3:].split("\\") if part),
        "WIN32_HANDLE_LOCAL_CANONICAL_PATH_REQUIRED")
    return ntpath.normcase(ntpath.normpath(path))


def _identity(api, handle) -> tuple:
    info = _BY_HANDLE_FILE_INFORMATION()
    require(bool(api.GetFileInformationByHandle(handle, ctypes.byref(info))),
            "WIN32_HANDLE_INFORMATION_UNAVAILABLE")
    require(not (info.attributes & (_FILE_ATTRIBUTE_REPARSE_POINT |
                                    _FILE_ATTRIBUTE_DIRECTORY)) and
            info.links >= 1, "WIN32_HANDLE_REPARSE_DIRECTORY_OR_LINK")
    return (
        int(info.volume_serial), int(info.file_index_high),
        int(info.file_index_low), int(info.size_high) << 32 | int(info.size_low),
        int(info.modified.high), int(info.modified.low),
        int(info.attributes),
    )


def _final_name(api, handle) -> str:
    buf = ctypes.create_unicode_buffer(32768)
    length = api.GetFinalPathNameByHandleW(handle, buf, len(buf), 0)
    require(0 < length < len(buf), "WIN32_HANDLE_FINAL_PATH_UNAVAILABLE")
    actual = buf.value
    require(actual.startswith("\\\\?\\") and not actual.startswith(
        "\\\\?\\UNC\\"), "WIN32_HANDLE_UNEXPECTED_DEVICE_PATH")
    return _normalized(actual[4:])


def read_windows_pinned_file(path: str | Path, expected_bytes: int,
                             expected_sha256: str, *,
                             _include_bytes: bool = False) -> dict:
    """Read immutable content through the one opened Win32 handle.

    This does not grant OS/native installer acceptance; the independently
    verified source pin still must come from a trusted release authority.
    """
    require(os.name == "nt", "WIN32_NATIVE_HANDLE_REQUIRED")
    require(type(expected_bytes) is int and 0 <= expected_bytes <= 1 << 30 and
            type(expected_sha256) is str and
            _SHA.fullmatch(expected_sha256) is not None,
            "WIN32_HANDLE_EXPECTED_SIZE_OR_SHA_INVALID")
    require(type(_include_bytes) is bool,
            "WIN32_HANDLE_CONTENT_MODE_INVALID")
    if _include_bytes:
        require(expected_bytes <= 65536,
                "WIN32_HANDLE_SMALL_FILE_LIMIT")
    name = str(path)
    canonical = _normalized(name)
    api = _windows_api()
    handle = api.CreateFileW(name, _GENERIC_READ, _FILE_SHARE_READ, None,
                             _OPEN_EXISTING, _FILE_FLAG_OPEN_REPARSE_POINT, None)
    require(handle not in (None, _INVALID_HANDLE_VALUE),
            "WIN32_HANDLE_OPEN_DENIED_OR_SHARING_CONFLICT")
    try:
        identity = _identity(api, handle)
        require(identity[3] == expected_bytes, "WIN32_HANDLE_SIZE_MISMATCH")
        require(_final_name(api, handle) == canonical,
                "WIN32_HANDLE_FINAL_PATH_MISMATCH")
        # ReadFile uses the existing locked handle, rather than reopening
        # the pathname via Python. The open share mode excludes any other
        # writer/deleter during this operation; existing writers reject open.
        api.ReadFile.argtypes = (
            wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p)
        api.ReadFile.restype = wintypes.BOOL
        digest = hashlib.sha256()
        total = 0
        pieces = [] if _include_bytes else None
        buf = ctypes.create_string_buffer(65536 if _include_bytes else 1 << 20)
        count = wintypes.DWORD()
        while True:
            require(bool(api.ReadFile(handle, buf, len(buf),
                                      ctypes.byref(count), None)),
                    "WIN32_HANDLE_READ_FAILED")
            if count.value == 0:
                break
            total += count.value
            require(total <= expected_bytes, "WIN32_HANDLE_EXCEEDED_EXPECTED")
            part = buf.raw[:count.value]
            digest.update(part)
            if pieces is not None:
                pieces.append(part)
        require(total == expected_bytes and
                digest.hexdigest() == expected_sha256.lower(),
                "WIN32_HANDLE_PIN_MISMATCH")
        require(_identity(api, handle) == identity,
                "WIN32_HANDLE_CHANGED_DURING_READ")
        result = {
            "status": "WIN32_OPEN_HANDLE_SHA_VALIDATED_NOT_NATIVE_AUTHORITY",
            "bytes": total, "sha256": digest.hexdigest(),
            "held_handle_hash_verified": True,
            "publisher_authenticated": False,
            "native_installation_accepted": False,
            "protected_write_performed": False,
        }
        if pieces is not None:
            result["content"] = b"".join(pieces)
        return result
    finally:
        api.CloseHandle(handle)


def read_windows_pinned_small_file(path: str | Path, expected_bytes: int,
                                   expected_sha256: str) -> bytes:
    """Return <=64 KiB from the SAME verified open Win32 handle.

    Bound the read before opening, reject reparse/sharing races, and check the
    final path, digest and handle identity. OS ACLs, trusted publisher pins,
    trusted service identity and native authorization are SEPARATE gates.
    """
    return read_windows_pinned_file(
        path, expected_bytes, expected_sha256, _include_bytes=True
    )["content"]
