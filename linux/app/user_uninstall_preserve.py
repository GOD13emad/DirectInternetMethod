#!/usr/bin/env python3
"""Fail-closed Direct Internet Method uninstall of owned program files ONLY.

Protected backend removal must finish first. Never remove user settings,
custom hosts, adult coverage state, scoped strategy, router providers or logs.
Never recursively delete the mixed application/data directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat
import sys

CODE_NAMES = frozenset({
    "direct_internet_method.py", "router_gateway.py", "router_gateway_core.py",
    "direct-internet-method.svg", "uninstall.sh", "user_uninstall_preserve.py",
    "user_update_transaction.py",
})
EXTERNAL_NAMES = frozenset({
    ".local/bin/direct-internet-method",
    ".local/bin/direct-internet-method-uninstall",
    ".local/share/applications/io.github.god13emad.DirectInternetMethod.desktop",
    ".local/share/icons/hicolor/scalable/apps/direct-internet-method.svg",
})
APPNAME = "DirectInternetMethod"


def ensure(ok, error):
    if not ok:
        raise RuntimeError(error)


def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def load_owned():
    home = pathlib.Path.home()
    app = home / ".local/share" / APPNAME
    ensure(os.geteuid() != 0 and not app.is_symlink() and app.is_dir(),
           "UNINSTALL_OWNER_HOME_INVALID")
    meta = app / "INSTALL.json"
    ensure(meta.is_file() and not meta.is_symlink(), "UNINSTALL_INSTALL_METADATA_MISSING")
    doc = json.loads(meta.read_text(encoding="utf8"))
    ensure(doc.get("schema") == 2 and doc.get("version") == "1.5.4",
           "UNINSTALL_MANIFEST_OWNER_VERSION_UNVERIFIED")
    codes = doc.get("managedCodeSha256")
    launchers = doc.get("managedLaunchersSha256")
    ensure(isinstance(codes, dict) and set(codes) <= CODE_NAMES and
           set(CODE_NAMES - {"user_uninstall_preserve.py"}) <= set(codes),
           "UNINSTALL_MANAGED_CODE_MANIFEST_UNKNOWN")
    ensure(isinstance(launchers, dict) and set(launchers) <= EXTERNAL_NAMES,
           "UNINSTALL_EXTERNAL_SHORTCUTS_MANIFEST_UNKNOWN")
    tracked = {}
    for rel, expected in codes.items():
        p = app / rel
        ensure(p.is_file() and not p.is_symlink() and not p.parent.is_symlink() and
               p.stat().st_uid == os.getuid() and sha(p) == expected,
               "UNINSTALL_CODE_FOREIGN_CHANGE_PRESERVED:" + rel)
        tracked[str(p)] = (p, expected)
    for rel, expected in launchers.items():
        p = home / rel
        ensure(p.is_file() and not p.is_symlink() and not p.parent.is_symlink() and
               p.stat().st_uid == os.getuid() and sha(p) == expected,
               "UNINSTALL_SHORTCUT_FOREIGN_CHANGE_PRESERVED:" + rel)
        tracked[str(p)] = (p, expected)
    # Any metadata altered by other software is not destroyed without an exact
    # owner check. The program metadata itself is not personal configuration.
    ensure(meta.stat().st_uid == os.getuid(), "INSTALL_METADATA_FOREIGN_OWNER")
    return app, meta, tracked


def verify():
    app, meta, tracked = load_owned()
    print(json.dumps({"status": "PASS_OWNED_FILES_IDENTIFIED_NO_MUTATION",
                      "managedExecutableFiles": len(tracked),
                      "userSettingsPreserved": True,
                      "externalRootRequiresRemovalFirst": True}))


def remove_known_files(app, meta, tracked):
    """Pure owned-file step, callable with a disposable HOME in tests.
    Production only calls it after independently verified backend removal."""
    for path, expected in tracked.values():
        ensure(path.is_file() and not path.is_symlink() and sha(path) == expected,
               "PROGRAM_FILE_CHANGED_AFTER_PRECHECK:" + str(path))
    for path, _ in tracked.values():
        path.unlink()
    # User data remains, including mutable router providers and runtime logs.
    meta.unlink()
    return len(tracked)


def remove_after_backend():
    app, meta, files = load_owned()
    root = pathlib.Path("/usr/lib/directinternetmethod")
    record = pathlib.Path("/var/lib/directinternetmethod/install.json")
    ensure(not (root / "control.sh").exists() and not record.exists(),
           "PROTECTED_BACKEND_STILL_PRESENT_REFUSE_USER_CODE_REMOVAL")
    count = remove_known_files(app, meta, files)
    print(json.dumps({"status": "PASS_OWNED_PROGRAM_FILES_REMOVED",
                      "userDataDirectoryPreserved": str(app),
                      "userSettingsDeleted": False,
                      "onlyOwnedFilesTouched": True}))


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--verify", action="store_true")
    group.add_argument("--remove-after-backend", action="store_true")
    args = parser.parse_args()
    if args.verify:
        verify()
    else:
        remove_after_backend()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("DIM_UNINSTALL_FAIL_CLOSED:" + str(exc), file=sys.stderr)
        sys.exit(86)
