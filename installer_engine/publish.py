"""No-clobber directory publish for user-local bundle staging.

Linux renameat2(RENAME_NOREPLACE) prevents TOCTOU overwrite of even an empty
foreign destination directory. Windows os.rename has no-overwrite semantics.
No fallback to check-then-rename on unsupported POSIX filesystems.

NOT a privilege boundary: parent directory/path identity and ACLs still require
a trusted native adapter for Administrator/root installation operations.
"""
from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path
import sys

from .engine import EngineError, durable_dir, no_links, require

_AT_FDCWD = -100
_RENAME_NOREPLACE = 1


def _rename_noreplace(source: Path, destination: Path) -> None:
    if sys.platform == "linux":
        libc = ctypes.CDLL(None, use_errno=True)
        fn = getattr(libc, "renameat2", None)
        require(fn is not None, "ATOMIC_NOREPLACE_NOT_SUPPORTED")
        fn.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint)
        fn.restype = ctypes.c_int
        result = fn(_AT_FDCWD, os.fsencode(source),
                    _AT_FDCWD, os.fsencode(destination), _RENAME_NOREPLACE)
        if result != 0:
            code = ctypes.get_errno()
            if code in (errno.EEXIST, errno.ENOTEMPTY):
                raise EngineError("BUNDLE_DESTINATION_ALREADY_EXISTS")
            if code in (errno.EINVAL, errno.ENOSYS,
                        getattr(errno, "EOPNOTSUPP", 95)):
                raise EngineError("ATOMIC_NOREPLACE_NOT_SUPPORTED")
            raise OSError(code, os.strerror(code), str(destination))
    elif os.name == "nt":
        # Python's Windows os.rename refuses an existing target.
        os.rename(source, destination)
    else:
        raise EngineError("ATOMIC_NOREPLACE_NOT_SUPPORTED")


def publish_new_directory(source: Path, destination: Path) -> None:
    source = Path(source).absolute()
    destination = Path(destination).absolute()
    no_links(source)
    no_links(destination)
    require(source.is_dir() and source.parent == destination.parent and
            destination.parent.is_dir() and source != destination,
            "ATOMIC_NOREPLACE_DIRECTORY_PAIR_INVALID")
    require(not destination.exists() and not destination.is_symlink(),
            "BUNDLE_DESTINATION_ALREADY_EXISTS")
    try:
        _rename_noreplace(source, destination)
    except FileExistsError as exc:
        raise EngineError("BUNDLE_DESTINATION_ALREADY_EXISTS") from exc
    durable_dir(destination.parent)
