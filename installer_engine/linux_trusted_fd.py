"""Linux *read-only* directory-fd-bound file verification primitive.

This is NOT a privileged installer, publisher signature or authorization token.
It is a safe input primitive for a future OS-authorized native broker, which
must itself be installed from trusted code/policy with exact release pins.

Design:
  - Open "/" and walk EVERY directory component via O_DIRECTORY|O_NOFOLLOW.
  - fstat the opened DIRECTORY DESCRIPTORS, not pathname stat/lstat.
  - Require root owner and no group/other write on the complete chain.
  - Open members relative to the pinned final dirfd with Linux openat2(2),
    RESOLVE_BENEATH|NO_SYMLINKS|NO_MAGICLINKS; NO unsafe fallback.
  - Hash and validate a regular root-owned, non-group/other-writable file
    from the opened FILE DESCRIPTOR, including identity/mtime checks.
  - Does not write, register services, run commands, elevate, or accept builds.

Passing this check is necessary but not sufficient for privileged installation:
OS authorization, signed trusted policy, native service/reboot/rollback and
publisher provenance remain separately required.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import os
from pathlib import Path, PurePosixPath
import platform
import stat
import sys

from .engine import EngineError, SHA_RE, MAX_FILE_BYTES, relpath, require

# SYS_openat2 = 437 on Linux x86_64 and aarch64. Only the project's
# linux-x86_64 platform is approved here. No blind fallback to open().
_SYS_OPENAT2_X86_64 = 437
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_BENEATH = 0x08
_RESOLVE_LOCKDOWN = (
    _RESOLVE_NO_MAGICLINKS | _RESOLVE_NO_SYMLINKS | _RESOLVE_BENEATH
)
_DIRECTORY_FLAGS = (
    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
    getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) |
    getattr(os, "O_NONBLOCK", 0)
)
_FILE_FLAGS = (
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
    getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
)


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


def _linux_only() -> None:
    require(sys.platform == "linux" and platform.machine().lower() in
            ("x86_64", "amd64"), "TRUSTED_FD_LINUX_X86_64_ONLY")


def _dir_ok(fd: int) -> os.stat_result:
    identity = os.fstat(fd)
    require(stat.S_ISDIR(identity.st_mode) and identity.st_uid == 0 and
            stat.S_IMODE(identity.st_mode) & 0o022 == 0,
            "TRUSTED_FD_UNSAFE_DIRECTORY_COMPONENT")
    return identity


def _openat2_beneath(dirfd: int, relative: str) -> int:
    """Only a narrow internal read-only openat2 wrapper; never a shell runner."""
    _linux_only()
    # The same portable path rules as the Engine's archive member namespace.
    parts = relpath(relative)
    name = "/".join(parts).encode("ascii")
    how = _OpenHow(_FILE_FLAGS, 0, _RESOLVE_LOCKDOWN)
    libc = ctypes.CDLL(None, use_errno=True)
    fn = libc.syscall
    fn.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_char_p,
                   ctypes.POINTER(_OpenHow), ctypes.c_size_t]
    fn.restype = ctypes.c_long
    fd = fn(_SYS_OPENAT2_X86_64, dirfd, name, ctypes.byref(how),
            ctypes.sizeof(how))
    if fd < 0:
        err = ctypes.get_errno()
        if err in (errno.ENOSYS, errno.EINVAL):
            raise EngineError("TRUSTED_FD_OPENAT2_NOT_SUPPORTED")
        # Never silently fall back to ordinary path-based open(), even on
        # kernel/filesystem failure or a resolution race.
        raise EngineError("TRUSTED_FD_MEMBER_OPEN_REFUSED") from OSError(
            err, os.strerror(err), relative)
    return int(fd)


def _open_owned_member(rootfd: int, relative: str) -> int:
    """Open an immutable member via independently verified parent handles.

    A parent under the trusted root could itself be group/world writable;
    openat2's symlink containment is NOT a substitute for checking each
    intermediate directory's ownership and mode. Hold every parent handle
    while moving to the next component, then open the final basename.
    """
    parts = relpath(relative)
    current = os.dup(rootfd)
    try:
        _dir_ok(current)
        for name in parts[:-1]:
            try:
                following = os.open(name, _DIRECTORY_FLAGS, dir_fd=current)
            except OSError as exc:
                raise EngineError("TRUSTED_FD_MEMBER_PARENT_OPEN_REFUSED") from exc
            try:
                _dir_ok(following)
            except BaseException:
                os.close(following)
                raise
            os.close(current)
            current = following
        return _openat2_beneath(current, parts[-1])
    finally:
        os.close(current)


class TrustedLinuxRootFD:
    """An opened, stable, read-only identity to a root-owned directory chain.

    A valid instance alone is NOT a trusted-publisher or OS privilege token.
    Its methods never permit writes. The final native installer must retain
    and use verified handles for every protected write, not reopen path strings.
    """

    def __init__(self, directory: str | Path):
        _linux_only()
        self._fd = -1
        self.path = Path(directory)
        require(self.path.is_absolute() and not (
            ".." in self.path.parts or "." in self.path.parts),
            "TRUSTED_FD_ROOT_ABSOLUTE_REQUIRED")
        # Do not canonicalize symlinks using resolve(); each component must be
        # opened and checked independently with O_NOFOLLOW.
        try:
            current = os.open("/", _DIRECTORY_FLAGS)
            _dir_ok(current)
            for part in self.path.parts[1:]:
                require(part not in ("", ".", ".."), "TRUSTED_FD_ROOT_COMPONENT")
                try:
                    next_fd = os.open(part, _DIRECTORY_FLAGS, dir_fd=current)
                    _dir_ok(next_fd)
                except BaseException:
                    if "next_fd" in locals():
                        os.close(next_fd)
                    raise
                os.close(current)
                current = next_fd
                del next_fd
            self._fd = current
        except OSError as exc:
            if "current" in locals():
                os.close(current)
            raise EngineError("TRUSTED_FD_ANCESTOR_OPEN_REFUSED") from exc
        except BaseException:
            if "current" in locals():
                os.close(current)
            raise

    def __enter__(self) -> "TrustedLinuxRootFD":
        require(self._fd >= 0, "TRUSTED_FD_CLOSED")
        return self

    def __exit__(self, _kind, _value, _tb) -> None:
        self.close()

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1

    def read_pinned_member(self, relative: str, expected_sha256: str,
                           expected_bytes: int, *,
                           max_bytes: int = MAX_FILE_BYTES) -> dict:
        """Verify an immutable-policy-pinned member without reopening paths.

        No bytes are returned, stored, executed or installed. This API is for
        verified identity and provenance inputs to future native adapters.
        """
        require(self._fd >= 0, "TRUSTED_FD_CLOSED")
        require(type(expected_sha256) is str and
                SHA_RE.fullmatch(expected_sha256) is not None,
                "TRUSTED_FD_EXPECTED_PIN")
        require(type(expected_bytes) is int and 0 <= expected_bytes <= max_bytes <= MAX_FILE_BYTES,
                "TRUSTED_FD_EXPECTED_SIZE")
        fd = _open_owned_member(self._fd, relative)
        try:
            before = os.fstat(fd)
            require(stat.S_ISREG(before.st_mode) and
                    before.st_uid == 0 and
                    stat.S_IMODE(before.st_mode) & 0o022 == 0,
                    "TRUSTED_FD_MEMBER_NOT_ROOT_OWNED_REGULAR")
            require(before.st_size == expected_bytes,
                    "TRUSTED_FD_MEMBER_SIZE_MISMATCH")
            h = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(fd, min(1 << 20, max_bytes + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                require(size <= max_bytes, "TRUSTED_FD_MEMBER_EXCEEDS_BOUND")
                h.update(chunk)
            after = os.fstat(fd)
            require((before.st_dev, before.st_ino, before.st_size,
                     before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns),
                    "TRUSTED_FD_FILE_MUTATED_DURING_READ")
            require(size == expected_bytes and
                    h.hexdigest() == expected_sha256.lower(),
                    "TRUSTED_FD_MEMBER_PIN_MISMATCH")
            return {
                "status": "READ_ONLY_PINNED_ROOT_FILE_VERIFIED_NOT_AUTHORIZATION",
                "sha256": h.hexdigest(), "bytes": size,
                "native_installation_accepted": False,
                "publisher_authenticated": False,
            }
        finally:
            os.close(fd)
