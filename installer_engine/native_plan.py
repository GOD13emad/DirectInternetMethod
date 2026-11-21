"""Pure cross-platform manifest projection for a future trusted native adapter.

A projected source package is NOT an installation and must never be used as a
privilege grant. The Windows manifest describes installed user/privileged
scopes, whereas the Linux archive manifest describes DISTRIBUTION CONTENTS,
not user/root-installed destinations. The distinction is deliberately typed
and fail-closed, avoiding per-host path and service assumptions.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
import re

from .engine import (
    EngineError, MAX_FILES, MAX_FILE_BYTES, PRODUCT, SHA_RE,
    manifest_schema, relpath, require, version,
)


@dataclass(frozen=True)
class NativePlan:
    product: str
    version: str
    platform: str
    source_kind: str
    scopes: tuple[tuple[str, dict[str, Any]], ...]
    native_adapter_accepted: bool = False

    def require_ready_for_native_install(self) -> None:
        """No source-only plan can prove OS registration or service health."""
        raise EngineError("NATIVE_ADAPTER_REGISTRATION_AND_ROLLBACK_REQUIRED")


def _row(path: object, length: object, checksum: object) -> dict[str, Any]:
    require(isinstance(path, str), "PLAN_INVALID_FILE_PATH")
    relpath(path)
    require(type(length) is int and 0 <= length <= MAX_FILE_BYTES,
            "PLAN_INVALID_BYTES")
    require(isinstance(checksum, str) and SHA_RE.fullmatch(checksum) is not None,
            "PLAN_INVALID_DIGEST")
    return {"path": path, "bytes": length,
            "sha256": checksum.lower(), "mode": 0o644}


def _manifest(platform: str, release: str, files: list[dict]) -> dict:
    out = {"schema": 1, "product": PRODUCT, "version": release,
           "platform": platform, "files": files}
    return manifest_schema(out, platform=platform)


def windows_scoped_plan(source: dict) -> NativePlan:
    """Normalize *real* Windows manifest schema 2 into two separate scopes.

    Scopes must be installed by a trusted Inno/SCM adapter with explicit native
    rollback. The single-slot kernel cannot atomically replace files across
    LocalAppData and Program Files and this function never claims it can.
    Source paths are metadata only: they may refer to repository-adjacent
    build sources, but must be separately resolved and SHA-verified by a
    trusted build-time packaging step before executing privileged code.
    """
    require(type(source) is dict, "WINDOWS_SOURCE_NOT_OBJECT")
    require(source.get("schema") == 2 and type(source.get("schema")) is int,
            "WINDOWS_SOURCE_SCHEMA")
    require(source.get("product") == PRODUCT, "WINDOWS_SOURCE_PRODUCT")
    release = source.get("version")
    version(release)
    entries = source.get("files")
    require(type(entries) is list and 1 <= len(entries) <= MAX_FILES,
            "WINDOWS_FILES_COUNT")
    rows: dict[str, list[dict]] = {"user": [], "privileged": []}
    source_names: set[tuple[str, str]] = set()
    for item in entries:
        require(type(item) is dict and set(item) ==
                {"scope", "file", "source", "bytes", "sha256"},
                "WINDOWS_SOURCE_FILE_KEYS")
        scope = item["scope"]
        require(isinstance(scope, str) and scope in rows, "WINDOWS_SCOPE_NOT_SUPPORTED")
        path = item["file"]
        projected = _row(path, item["bytes"], item["sha256"])
        name = item["source"]
        require(isinstance(name, str) and 0 < len(name) <= 500 and
                not name.startswith(("/", "\\")) and
                not re.match(r"^[a-zA-Z]:", name) and
                "\x00" not in name and "\\" not in name,
                "WINDOWS_SOURCE_LOCATION_INVALID")
        # A source can be ../repo-relative for packaging; never treat as
        # an install target or as proof the source is inside a trusted root.
        key = (scope, projected["path"].casefold())
        require(key not in source_names, "WINDOWS_SCOPE_DUPLICATE_OR_CASEFOLD")
        source_names.add(key)
        rows[scope].append(projected)
    require(rows["user"] and rows["privileged"],
            "WINDOWS_NATIVE_TWO_SCOPE_LAYOUT_REQUIRED")
    return NativePlan(PRODUCT, release, "windows-x86_64",
                      "INSTALLED_SCOPES_NEED_INNO_SCM",
                      (("user", _manifest("windows-x86_64", release, rows["user"])),
                       ("privileged", _manifest("windows-x86_64", release,
                                                rows["privileged"]))))


def linux_distribution_plan(source: dict) -> NativePlan:
    """Validate Linux ZIP source files, *not* its installed user/root mapping."""
    require(type(source) is dict and set(source) ==
            {"schema", "product", "version", "platform", "files"},
            "LINUX_SOURCE_KEYS")
    require(type(source["schema"]) is int and source["schema"] == 1 and
            source["product"] == PRODUCT and
            source["platform"] == "linux-x86_64", "LINUX_SOURCE_IDENTITY")
    release = source["version"]
    version(release)
    entries = source["files"]
    require(type(entries) is list and 1 <= len(entries) <= MAX_FILES,
            "LINUX_SOURCE_FILES_COUNT")
    rows = []
    for entry in entries:
        require(type(entry) is dict and set(entry) ==
                {"file", "bytes", "sha256"}, "LINUX_SOURCE_FILE_KEYS")
        rows.append(_row(entry["file"], entry["bytes"], entry["sha256"]))
    return NativePlan(PRODUCT, release, "linux-x86_64",
                      "DISTRIBUTION_SOURCE_NOT_NATIVE_INSTALLED_ROOTS",
                      (("distribution", _manifest("linux-x86_64", release, rows)),))
