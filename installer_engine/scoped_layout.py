"""Pinned declarative source-to-managed-scope layout for native adapters.

A source manifest lists package bytes; a separate independently SHA-pinned
layout declares which of those bytes belong in each managed code scope.
No operating-system directory, service unit, ACL or package registration is
created by this compiler. This is NOT proof of a native installation.
"""
from __future__ import annotations

import json
import re

from .engine import (
    EngineError, MAX_FILES, PRODUCT, PLATFORMS, SHA_RE, hash_bytes,
    manifest_schema, relpath, require, version,
)
from .native_plan import NativePlan


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    out = {}
    for key, value in pairs:
        require(key not in out, "LAYOUT_DUPLICATE_JSON_KEY")
        out[key] = value
    return out


def compile_scoped_layout(source_manifest: dict, layout_bytes: bytes,
                          expected_layout_sha256: str) -> NativePlan:
    """Build code-only manifests; never infer privilege or filesystem roots.

    expected_layout_sha256 must be supplied out-of-band by a trusted packaging
    layer. A hash read from the same untrusted archive is not an authentication
    guarantee.
    """
    require(type(expected_layout_sha256) is str and
            SHA_RE.fullmatch(expected_layout_sha256) is not None,
            "LAYOUT_OUT_OF_BAND_PIN_REQUIRED")
    require(type(layout_bytes) is bytes and 0 < len(layout_bytes) < 1 << 20,
            "LAYOUT_INPUT_INVALID")
    require(hash_bytes(layout_bytes) == expected_layout_sha256.lower(),
            "LAYOUT_PIN_MISMATCH")
    try:
        layout = json.loads(layout_bytes.decode("utf-8"),
                            object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError) as exc:
        raise EngineError("LAYOUT_JSON_INVALID") from exc
    require(type(layout) is dict and
            set(layout) == {"schema", "product", "version", "platform", "files"},
            "LAYOUT_SCHEMA_KEYS")
    require(type(layout["schema"]) is int and layout["schema"] == 1 and
            layout["product"] == PRODUCT, "LAYOUT_IDENTITY")
    target_version = layout["version"]
    version(target_version)
    platform = layout["platform"]
    require(platform in PLATFORMS, "LAYOUT_PLATFORM_INVALID")

    require(type(source_manifest) is dict and
            set(source_manifest) == {"schema", "product", "version", "platform", "files"} and
            type(source_manifest["schema"]) is int and source_manifest["schema"] == 1 and
            source_manifest["product"] == PRODUCT and
            source_manifest["version"] == target_version and
            source_manifest["platform"] == platform,
            "LAYOUT_SOURCE_VERSION_PLATFORM_MISMATCH")
    source_rows = source_manifest["files"]
    require(type(source_rows) is list and 1 <= len(source_rows) <= MAX_FILES,
            "LAYOUT_SOURCE_FILES_INVALID")
    by_source = {}
    for row in source_rows:
        require(type(row) is dict and set(row) == {"file", "bytes", "sha256"},
                "LAYOUT_SOURCE_FILE_SCHEMA")
        src = row["file"]
        relpath(src)
        key = src.casefold()
        require(key not in by_source, "LAYOUT_SOURCE_CASEFOLD_COLLISION")
        require(type(row["bytes"]) is int and 0 <= row["bytes"] <= (1 << 30) and
                type(row["sha256"]) is str and SHA_RE.fullmatch(row["sha256"]),
                "LAYOUT_SOURCE_FILE_IDENTITY_INVALID")
        by_source[key] = row

    files = layout["files"]
    require(type(files) is list and 1 <= len(files) <= MAX_FILES,
            "LAYOUT_FILE_COUNT")
    rows = {}
    used_source = set()
    used_target = set()
    for item in files:
        require(type(item) is dict and
                set(item) == {"scope", "source", "target", "mode"},
                "LAYOUT_MAPPING_SCHEMA")
        scope, src, dest, mode = (item["scope"], item["source"],
                                  item["target"], item["mode"])
        require(type(scope) is str and
                re.fullmatch(r"[a-z][a-z0-9_-]{0,23}", scope) is not None,
                "LAYOUT_SCOPE_NAME")
        relpath(src)
        relpath(dest)
        require(type(mode) is int and mode in (0o644, 0o755),
                "LAYOUT_FILE_MODE_INVALID")
        key = src.casefold()
        require(key in by_source and key not in used_source,
                "LAYOUT_SOURCE_MISSING_OR_REUSED")
        destination_key = (scope.casefold(), dest.casefold())
        require(destination_key not in used_target, "LAYOUT_DESTINATION_COLLISION")
        used_source.add(key)
        used_target.add(destination_key)
        row = by_source[key]
        rows.setdefault(scope, []).append({
            "path": dest, "bytes": row["bytes"],
            "sha256": row["sha256"].lower(), "mode": mode
        })
    scopes = tuple((scope, manifest_schema({
        "schema": 1, "product": PRODUCT, "version": target_version,
        "platform": platform, "files": entries,
    }, platform=platform)) for scope, entries in sorted(rows.items()))
    return NativePlan(PRODUCT, target_version, platform,
                      "PINNED_CODE_LAYOUT_REQUIRES_TRUSTED_NATIVE_ADAPTER",
                      scopes)
