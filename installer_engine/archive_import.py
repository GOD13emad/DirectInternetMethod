"""Deterministic, offline, hash-pinned import of DIM distribution ZIP formats.

This is a *package ingestion* adapter, not a native OS installer. It never
touches system services, DNS, Inno registration, systemd or user state. Both
archive formats are normalized to the same portable Engine bundle contract.
An OS-privileged adapter still needs to authenticate the publisher and
coordinate actual user/privileged install roots, registration and rollback.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import zipfile

from .engine import (
    EngineError, MAX_FILES, MAX_MANIFEST_BYTES, PRODUCT, SHA_RE,
    hash_file, manifest_schema, no_links, relpath, require,
)
from .native_plan import windows_scoped_plan, linux_distribution_plan

WINDOWS_METADATA = frozenset({
    "installer-metadata/manifest.json",
    "installer-metadata/RELEASE.json",
    "installer-metadata/unins001.exe",
    "installer-metadata/unins001.dat",
})
MAX_TOTAL_BYTES = 3 << 30


def _strict_json(raw: bytes) -> dict:
    require(len(raw) <= MAX_MANIFEST_BYTES, "ARCHIVE_MANIFEST_TOO_LARGE")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "ARCHIVE_DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError) as exc:
        raise EngineError("ARCHIVE_MANIFEST_NOT_JSON") from exc
    require(type(result) is dict, "ARCHIVE_MANIFEST_NOT_OBJECT")
    return result


def _archive_index(z: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    entries = {}
    for info in z.infolist():
        name = info.filename
        require(type(name) is str and not info.is_dir(), "ARCHIVE_DIRECTORY_MEMBER")
        require("\\" not in name and ":" not in name and
                not name.startswith(("/", "\\")) and "\x00" not in name,
                "ARCHIVE_UNSAFE_MEMBER")
        require(not any(p in ("", ".", "..") for p in name.split("/")),
                "ARCHIVE_TRAVERSAL_MEMBER")
        require(stat.S_IFMT(info.external_attr >> 16) != stat.S_IFLNK,
                "ARCHIVE_SYMLINK_MEMBER")
        require(name not in entries, "ARCHIVE_DUPLICATE_MEMBER")
        entries[name] = info
    require(len(entries) <= MAX_FILES + 12, "ARCHIVE_MEMBER_LIMIT")
    return entries


def _source_layout(z: zipfile.ZipFile, index: dict, kind: str) -> tuple[dict, list[tuple[str, str, dict]], set[str]]:
    if kind == "windows-managed":
        require(WINDOWS_METADATA.issubset(index), "WINDOWS_INSTALLER_METADATA_MISSING")
        original = _strict_json(z.read(index["installer-metadata/manifest.json"]))
        native = windows_scoped_plan(original)
        files = []
        for scope, manifest in native.scopes:
            for row in manifest["files"]:
                name = scope + "/" + row["path"]
                files.append(("managed/" + name, name, row))
        expected = set(WINDOWS_METADATA) | {item[0] for item in files}
        out = {"schema":1, "product":PRODUCT, "version":native.version,
               "platform":"windows-x86_64", "files":[item[2] | {"path":item[1]}
                                                   for item in files]}
    elif kind == "linux-distribution":
        candidates = [n for n in index if n.endswith("/PACKAGE_MANIFEST.json")]
        require(len(candidates) == 1, "LINUX_PACKAGE_MANIFEST_AMBIGUOUS")
        marker = candidates[0]
        prefix = marker[:-len("PACKAGE_MANIFEST.json")]
        require(prefix and "/" in prefix and
                prefix.count("/") == 1, "LINUX_PREFIX_NOT_SINGLE_ROOT")
        original = _strict_json(z.read(index[marker]))
        native = linux_distribution_plan(original)
        manifest = dict(native.scopes)["distribution"]
        files = [(prefix + row["path"], row["path"], row)
                 for row in manifest["files"]]
        # The Linux archive records executable script/mode bits independently
        # of its source-manifest SHA records. Retain only safe 0644/0755 modes,
        # never SUID/SGID bits or arbitrary ownership from the ZIP.
        for member, _, row in files:
            original_mode = stat.S_IMODE(index[member].external_attr >> 16)
            require(original_mode & 0o6000 == 0, "ARCHIVE_PRIVILEGED_MODE_FORBIDDEN")
            row["mode"] = 0o755 if original_mode & 0o111 else 0o644
        expected = {marker, prefix + "SHA256SUMS.txt"} | {item[0] for item in files}
        out = manifest
    else:
        raise EngineError("UNKNOWN_ARCHIVE_FORMAT")
    require(set(index) == expected, "ARCHIVE_EXTRA_OR_MISSING_MEMBER")
    require(len(files) == len(set(x[1].casefold() for x in files)),
            "ARCHIVE_CASEFOLD_MANAGED_COLLISION")
    manifest_schema(out)
    total = sum(row["bytes"] for _, _, row in files)
    require(total <= MAX_TOTAL_BYTES, "ARCHIVE_EXTRACT_TOTAL_LIMIT")
    return out, files, expected


def import_pinned_archive(archive: Path | str, pin: str,
                          destination: Path | str, kind: str) -> dict:
    """Write an Engine-readable package in a new, private destination.

    The supplied archive SHA-256 MUST originate independently from a trusted
    release/owner, not from a self-reported archive manifest. The returned
    normalized manifest SHA-256 is a content locator, not a publisher
    signature or native service acceptance. Never run as administrator on an
    untrusted user-writable staging parent.
    """
    require(isinstance(pin, str) and SHA_RE.fullmatch(pin) is not None,
            "OUT_OF_BAND_ARCHIVE_SHA_REQUIRED")
    source = Path(archive).absolute()
    dest = Path(destination).absolute()
    no_links(source)
    require(source.is_file(), "ARCHIVE_NOT_REGULAR_FILE")
    require(hash_file(source).lower() == pin.lower(), "ARCHIVE_PIN_MISMATCH")
    no_links(dest)
    require(not dest.exists() and not dest.is_symlink(),
            "BUNDLE_DESTINATION_ALREADY_EXISTS")
    require(dest.parent.is_dir() and dest.name not in (".", ".."),
            "BUNDLE_DESTINATION_PARENT_MISSING")
    temp = Path(tempfile.mkdtemp(prefix=".dim-import-only-", dir=dest.parent))
    published = False
    try:
        with zipfile.ZipFile(source) as z:
            index = _archive_index(z)
            manifest, files, _ = _source_layout(z, index, kind)
            payload = temp/"payload"
            payload.mkdir(mode=0o700)
            for member, path, row in files:
                relpath(path)
                info = index[member]
                require(info.file_size == row["bytes"],
                        "ARCHIVE_MEMBER_LENGTH_MISMATCH")
                dst = payload.joinpath(*relpath(path))
                dst.parent.mkdir(parents=True, exist_ok=True)
                no_links(dst, until=temp)
                checksum = hashlib.sha256()
                length = 0
                with z.open(info, "r") as inp, dst.open("xb") as out:
                    while True:
                        block = inp.read(1 << 20)
                        if not block:
                            break
                        length += len(block)
                        require(length <= row["bytes"], "ARCHIVE_MEMBER_BOMB")
                        checksum.update(block)
                        out.write(block)
                    out.flush()
                    os.fsync(out.fileno())
                require(length == row["bytes"] and
                        checksum.hexdigest() == row["sha256"].lower(),
                        "ARCHIVE_MEMBER_SHA_MISMATCH")
                os.chmod(dst, row["mode"])
        mf = temp/"manifest.json"
        raw_manifest = (json.dumps(manifest,sort_keys=True,separators=(",",":"))+"\n").encode("utf-8")
        with mf.open("xb") as f:
            f.write(raw_manifest)
            f.flush()
            os.fsync(f.fileno())
        normalized_pin = hash_file(mf)
        require(hash_file(source).lower() == pin.lower(),
                "ARCHIVE_SOURCE_CHANGED_DURING_IMPORT")
        no_links(dest)
        require(not dest.exists(), "BUNDLE_DESTINATION_RACE")
        temp.rename(dest)
        published = True
        return {
            "status": "PASS_IMPORTED_VERIFIED_CODE_BUNDLE_ONLY",
            "kind": kind,
            "version": manifest["version"],
            "platform": manifest["platform"],
            "source_sha256": pin.lower(),
            "normalized_manifest_sha256": normalized_pin,
            "files": len(files),
            "bytes": sum(r["bytes"] for _, _, r in files),
            "native_installer_or_service_registered": False,
        }
    finally:
        if not published and temp.is_dir() and not temp.is_symlink():
            shutil.rmtree(temp)
