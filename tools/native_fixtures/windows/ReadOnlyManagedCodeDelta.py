#!/usr/bin/env python3
"""Read-only Windows installed-code delta observation (NOT install authority).

The historical baseline archive hash and target source manifest hash MUST be
pinned independently. Neither local file hashes nor a successful comparison
authorize Inno, SCM, UAC, service control, privileged writes, or publication.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import zipfile

# Source checkout, not arbitrary working-directory import.
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from installer_engine.engine import EngineError, relpath, require
from installer_engine.native_delta import compare_managed_code_delta
from installer_engine.native_plan import windows_scoped_plan

BASELINE_MEMBER = "installer-metadata/manifest.json"
STATUS = "READ_ONLY_WINDOWS_INSTALLED_CODE_DELTA_NOT_NATIVE_INSTALLATION"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fd:
        for block in iter(lambda: fd.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DELTA_DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def strict_json(raw: bytes) -> dict:
    require(type(raw) is bytes and 0 < len(raw) <= 1024 * 1024,
            "DELTA_JSON_SIZE")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError) as exc:
        raise EngineError("DELTA_BAD_JSON") from exc
    require(type(document) is dict, "DELTA_JSON_NOT_OBJECT")
    return document


def no_reparse_ancestry(path: Path) -> None:
    """Inspect every existing path component, not only the final file."""
    current = path.absolute()
    while True:
        try:
            info = current.lstat()
        except (OSError, ValueError) as exc:
            raise EngineError("DELTA_PATH_UNREADABLE") from exc
        require(not stat.S_ISLNK(info.st_mode) and
                not (getattr(info, "st_file_attributes", 0) &
                     getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)),
                "DELTA_REPARSE_OR_LINK_IN_ANCESTRY")
        parent = current.parent
        if parent == current:
            break
        current = parent


def inventory(source: dict, *, measured: bool, user_root: Path,
              privileged_root: Path) -> dict:
    plan = windows_scoped_plan(source)
    scopes = []
    for name, manifest in plan.scopes:
        base = user_root if name == "user" else privileged_root
        if measured:
            no_reparse_ancestry(base)
            require(base.is_dir(), "DELTA_INSTALLED_ROOT_NOT_DIRECTORY")
        files = []
        for entry in manifest["files"]:
            row = dict(entry)
            if measured:
                parts = relpath(entry["path"])
                path = base.joinpath(*parts)
                no_reparse_ancestry(path)
                require(path.is_file(), "DELTA_INSTALLED_FILE_MISSING")
                info = path.stat()
                row["bytes"] = info.st_size
                row["sha256"] = sha256_file(path)
            files.append(row)
        scopes.append({"name": name, "files": files})
    return {"schema": 1, "product": source["product"],
            "version": source["version"], "platform": plan.platform,
            "scopes": scopes}


def observe(archive: Path, archive_sha: str, old_manifest_sha: str,
            target: Path, target_sha: str, user_root: Path,
            privileged_root: Path) -> dict:
    for pin in (archive_sha, old_manifest_sha, target_sha):
        require(type(pin) is str and len(pin) == 64 and
                all(c in "0123456789abcdefABCDEF" for c in pin),
                "DELTA_PIN_FORMAT")
    for path in (archive, target):
        no_reparse_ancestry(path)
        require(path.is_file(), "DELTA_INPUT_FILE_MISSING")
    require(sha256_file(archive) == archive_sha.lower(),
            "DELTA_BASELINE_ARCHIVE_PIN_MISMATCH")
    with zipfile.ZipFile(archive) as zf:
        require(zf.namelist().count(BASELINE_MEMBER) == 1,
                "DELTA_ARCHIVE_MANIFEST_AMBIGUOUS")
        info = zf.getinfo(BASELINE_MEMBER)
        require(0 < info.file_size <= 1024 * 1024,
                "DELTA_ARCHIVE_MANIFEST_SIZE")
        baseline_bytes = zf.read(BASELINE_MEMBER)
        require(len(baseline_bytes) == info.file_size,
                "DELTA_ARCHIVE_MANIFEST_LENGTH_DRIFT")
    require(hashlib.sha256(baseline_bytes).hexdigest() ==
            old_manifest_sha.lower(), "DELTA_BASELINE_MANIFEST_PIN_MISMATCH")
    require(0 < target.stat().st_size <= 1024 * 1024,
            "DELTA_TARGET_MANIFEST_SIZE")
    target_bytes = target.read_bytes()
    require(hashlib.sha256(target_bytes).hexdigest() == target_sha.lower(),
            "DELTA_TARGET_MANIFEST_PIN_MISMATCH")
    previous = strict_json(baseline_bytes)
    future = strict_json(target_bytes)
    native_plan = windows_scoped_plan(future)
    old_inventory = inventory(previous, measured=False,
                              user_root=user_root, privileged_root=privileged_root)
    # The installed metadata file itself must match the separately pinned
    # original archive; never trust a user's supplied local manifest.
    installed_manifest = user_root / "manifest.json"
    no_reparse_ancestry(installed_manifest)
    require(installed_manifest.is_file() and
            sha256_file(installed_manifest) == old_manifest_sha.lower(),
            "DELTA_INSTALLED_MANIFEST_BASELINE_DRIFT")
    observed = inventory(previous, measured=True,
                         user_root=user_root, privileged_root=privileged_root)
    delta = compare_managed_code_delta(native_plan, old_inventory, observed)
    return {"status": STATUS, "installed_version": previous["version"],
            "target_version": future["version"],
            "archive_sha256": archive_sha.lower(),
            "installed_manifest_sha256": old_manifest_sha.lower(),
            "target_manifest_sha256": target_sha.lower(),
            "old_file_count": sum(len(s["files"]) for s in old_inventory["scopes"]),
            "stats": delta["stats"], "scopes": delta["scopes"],
            "publisher_authenticated": False,
            "native_installation_accepted": False,
            "privileged_broker_implemented": False,
            "protected_write_performed": False,
            "os_trusted_handle_readback": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--old-manifest-sha256", required=True)
    parser.add_argument("--target-manifest", type=Path, required=True)
    parser.add_argument("--target-sha256", required=True)
    parser.add_argument("--user-root", type=Path, required=True)
    parser.add_argument("--privileged-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = observe(args.archive, args.archive_sha256,
                         args.old_manifest_sha256,
                         args.target_manifest, args.target_sha256,
                         args.user_root, args.privileged_root)
    except (EngineError, OSError, ValueError, zipfile.BadZipFile) as exc:
        print(json.dumps({"status": "FAIL_CLOSED_READ_ONLY_DELTA",
                          "reason": str(exc),
                          "native_installation_accepted": False},
                         sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
