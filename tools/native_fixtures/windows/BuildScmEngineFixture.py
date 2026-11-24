"""Disposable, hash-pinned Windows SCM + frozen Engine fixture materializer.

Builds code-only Engine bundles from two separately compiled synthetic
ServiceBase executables. The 'bad-157' payload is intentionally invalid
and tests rollback following an actual SCM start failure in Windows Sandbox.
No Windows service or installed application is modified by this builder.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make(root: Path, name: str, version: str, data: bytes) -> str:
    dest = root / name
    dest.mkdir(parents=True, exist_ok=False)
    p = dest / "payload" / "app"
    p.mkdir(parents=True, exist_ok=False)
    (p / "FixtureService.exe").write_bytes(data)
    doc = {
        "schema": 1, "product": "Direct Internet Method",
        "version": version, "platform": "windows-x86_64",
        "files": [{
            "path": "app/FixtureService.exe", "bytes": len(data),
            "sha256": sha(data), "mode": 0o644,
        }],
    }
    raw = (json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (dest / "manifest.json").write_bytes(raw)
    return sha(raw)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--old", type=Path, required=True)
    parser.add_argument("--new", type=Path, required=True)
    parser.add_argument("--old-sha256", required=True)
    parser.add_argument("--new-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    old, new = args.old.read_bytes(), args.new.read_bytes()
    if (sha(old) != args.old_sha256.lower() or
            sha(new) != args.new_sha256.lower() or old == new):
        raise SystemExit("FAIL_SOURCE_SHA_OR_VERSION")
    if args.output.exists():
        raise SystemExit("FAIL_DESTINATION_EXISTS")
    args.output.mkdir(parents=True, exist_ok=False)
    pins = {
        "schema": 1,
        "fixture_name": "DIMR887IsolatedFixtureSvc",
        "platform": "windows-x86_64",
        "old_binary_sha256": sha(old),
        "new_binary_sha256": sha(new),
        "old_manifest_sha256": make(args.output, "old156", "1.5.6", old),
        "bad_manifest_sha256": make(args.output, "bad157", "1.5.7",
                                     b"NOT_A_VALID_WINDOWS_SERVICE_BINARY"),
        "new_manifest_sha256": make(args.output, "new157", "1.5.7", new),
    }
    (args.output / "pins.json").write_text(
        json.dumps(pins, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(pins, sort_keys=True))


if __name__ == "__main__":
    main()
