"""R891 independently pinned synthetic two-scope SCM package builder.

Build-time ONLY. No service, registry, host system files or live installation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def write_bundle(base: Path, key: str, version: str,
                 path: str, content: bytes) -> str:
    folder = base / key
    file = folder / "payload" / path
    file.parent.mkdir(parents=True, exist_ok=False)
    file.write_bytes(content)
    doc = {"schema": 1, "product": "Direct Internet Method",
           "version": version, "platform": "windows-x86_64",
           "files": [{"path": path, "bytes": len(content),
                      "sha256": digest(content), "mode": 0o644}]}
    raw = (json.dumps(doc, separators=(",", ":"), sort_keys=True) + "\n").encode()
    (folder / "manifest.json").write_bytes(raw)
    return digest(raw)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--old", type=Path, required=True)
    p.add_argument("--new", type=Path, required=True)
    p.add_argument("--old-sha256", required=True)
    p.add_argument("--new-sha256", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    old = a.old.read_bytes()
    new = a.new.read_bytes()
    if (digest(old) != a.old_sha256.lower() or
            digest(new) != a.new_sha256.lower() or old == new):
        raise SystemExit("FIXTURE_SOURCE_PIN_MISMATCH")
    if a.output.exists() or a.output.is_symlink():
        raise SystemExit("FIXTURE_DESTINATION_ALREADY_EXISTS")
    a.output.mkdir(parents=True)
    specs = [
        ("code_1_5_6", "1.5.6", "app/FixtureService.exe", old),
        ("user_1_5_6", "1.5.6", "app/UserCode.txt", b"OWNER_USER_CODE_156"),
        ("code_157_bad", "1.5.7", "app/FixtureService.exe",
         b"NOT_A_VALID_WINDOWS_SERVICE_BINARY"),
        ("user_157_bad", "1.5.7", "app/UserCode.txt", b"OWNER_USER_CODE_BAD"),
        ("code_1_5_7", "1.5.7", "app/FixtureService.exe", new),
        ("user_1_5_7", "1.5.7", "app/UserCode.txt", b"OWNER_USER_CODE_157"),
    ]
    pins = {
        "schema": 1, "scope": "SYNTHETIC_R891",
        "service_name": "DIMR887IsolatedFixtureSvc",
        "binary_sha256_old": digest(old),
        "binary_sha256_new": digest(new),
        "manifest_sha256": {
            key: write_bundle(a.output, key, ver, file, content)
            for key, ver, file, content in specs
        },
    }
    (a.output / "pins.json").write_text(
        json.dumps(pins, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(pins, sort_keys=True))


if __name__ == "__main__":
    main()
