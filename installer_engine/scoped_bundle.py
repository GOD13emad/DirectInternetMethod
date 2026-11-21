"""Materialize one scope package from independently pinned normalized source.

This code is a USER-LOCAL BUILD/QA HELPER, NOT A PRIVILEGED INSTALLER.
It cannot register services, elevate or accept a native transaction. Final
physical destination mapping and OS metadata need a trusted native adapter.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile

from .engine import (
    EngineError, hash_bytes, hash_file, no_links, read_package, regular,
    relpath, require,
)
from .scoped_layout import compile_scoped_layout, _unique_pairs
from .publish import publish_new_directory

STATUS = "SCOPED_BUILD_ONLY_NOT_NATIVE_INSTALL"


def materialize_scope_bundle(source_bundle: Path | str,
                             source_manifest_pin: str,
                             layout_path: Path | str, layout_pin: str,
                             scope_name: str, destination: Path | str,
                             platform: str) -> dict:
    """Make a byte-verified portable engine bundle from one declarative scope.

    Only use on non-elevated packaging/QA roots with no foreign data. Input
    content and layout must have INDEPENDENT trustworthy out-of-band pins.
    """
    source = Path(source_bundle).absolute()
    layout_file = Path(layout_path).absolute()
    target = Path(destination).absolute()
    no_links(source)
    no_links(layout_file)
    no_links(target)
    require(regular(layout_file) and 0 < layout_file.stat().st_size < 1 << 20,
            "SCOPED_LAYOUT_FILE_INVALID")
    require(target.parent.is_dir() and not target.exists() and
            not target.is_symlink(), "SCOPED_DESTINATION_EXISTS_OR_MISSING_PARENT")
    require(not any((a == b or a in b.parents or b in a.parents)
                    for a, b in ((source, target), (layout_file, target))),
            "SCOPED_DESTINATION_OVERLAPS_INPUT")

    normalized = read_package(source, source_manifest_pin, platform)
    distribution = {
        "schema": 1, "product": normalized["product"],
        "version": normalized["version"], "platform": normalized["platform"],
        "files": [{"file": f["path"], "bytes": f["bytes"],
                   "sha256": f["sha256"]} for f in normalized["files"]]
    }
    data = layout_file.read_bytes()
    plan = compile_scoped_layout(distribution, data, layout_pin)
    scopes = dict(plan.scopes)
    require(type(scope_name) is str and scope_name in scopes,
            "SCOPED_UNKNOWN_NAME")
    doc = scopes[scope_name]
    layout = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs)
    mapping = {e["target"]: e["source"] for e in layout["files"]
               if e["scope"] == scope_name}
    require(set(mapping) == {f["path"] for f in doc["files"]},
            "SCOPED_MISSING_DESTINATION_MAPPING")

    # A private unpredictable staging root, not a public install path.
    stage = Path(tempfile.mkdtemp(prefix=".dim-scope-build-", dir=target.parent))
    try:
        payload = stage / "payload"
        payload.mkdir(mode=0o700)
        for entry in doc["files"]:
            original = source / "payload"
            original = original.joinpath(*relpath(mapping[entry["path"]]))
            dest = payload.joinpath(*relpath(entry["path"]))
            no_links(original)
            require(regular(original), "SCOPED_SOURCE_NOT_REGULAR")
            require(original.stat().st_size == entry["bytes"] and
                    hash_file(original) == entry["sha256"],
                    "SCOPED_SOURCE_CHANGED")
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            h = hashlib.sha256()
            total = 0
            with original.open("rb") as inp, dest.open("xb") as out:
                while True:
                    chunk = inp.read(1 << 20)
                    if not chunk:
                        break
                    total += len(chunk)
                    require(total <= entry["bytes"], "SCOPED_SOURCE_GREW")
                    h.update(chunk)
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            require(total == entry["bytes"] and h.hexdigest() == entry["sha256"],
                    "SCOPED_COPY_MISMATCH")
            if os.name == "posix":
                dest.chmod(entry["mode"])
        manifest = (json.dumps(doc, sort_keys=True, separators=(",", ":")) +
                    "\n").encode("utf-8")
        with (stage / "manifest.json").open("xb") as f:
            f.write(manifest)
            f.flush()
            os.fsync(f.fileno())
        pin = hash_bytes(manifest)
        read_package(stage, pin, platform)
        require(not target.exists() and not target.is_symlink(),
                "SCOPED_DESTINATION_APPEARED")
        # No-clobber is atomic on Linux/Windows, but parent/ACL trust is NOT
        # a native privilege boundary; this remains a user-local build helper.
        publish_new_directory(stage, target)
        return {"status": STATUS, "platform": platform,
                "scope": scope_name, "version": doc["version"],
                "files": len(doc["files"]), "manifest_sha256": pin,
                "native_installation_or_rollback_accepted": False}
    finally:
        if stage.exists() and not stage.is_symlink():
            shutil.rmtree(stage)
