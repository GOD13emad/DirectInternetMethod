"""Exercise the frozen engine without using host Python as its runtime.

This smoke check creates only an isolated synthetic payload and fixture root.
The caller supplies a locally built PyInstaller executable, not a product setup.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def run(binary: Path, action: str, root: Path, platform: str, *options: str) -> dict:
    command = [str(binary), action, "--root", str(root), "--platform", platform, *options]
    process = subprocess.run(command, cwd=root.parent, capture_output=True,
                             text=True, timeout=70, check=False)
    if process.returncode:
        raise AssertionError(f"{action}: exit={process.returncode}, "
                             f"stderr={process.stderr[-500:]}")
    result = json.loads(process.stdout.strip())
    assert isinstance(result, dict) and result.get("status"), result
    return result


def main() -> None:
    assert len(sys.argv) == 2, "Supply the exact frozen executable"
    binary = Path(sys.argv[1]).resolve(strict=True)
    platform = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    with tempfile.TemporaryDirectory(prefix="dim-frozen-engine-") as td:
        home = Path(td)
        root = home / "installation"
        bundle = home / "bundle"
        payload = bundle / "payload" / "app"
        payload.mkdir(parents=True)
        body = b"DIM PORTABLE TEST PAYLOAD -- NO REAL SERVICE"
        (payload / "main.bin").write_bytes(body)
        manifest = {"schema": 1, "product": "Direct Internet Method",
                    "version": "1.5.7", "platform": platform,
                    "files": [{"path": "app/main.bin", "bytes": len(body),
                               "sha256": hashlib.sha256(body).hexdigest(),
                               "mode": 0o644}]}
        source = bundle / "manifest.json"
        source.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        assert run(binary, "verify", root, platform)["status"] == "EMPTY"
        assert run(binary, "stage", root, platform, "--bundle", str(bundle),
                   "--expected-manifest-sha256", digest)["version"] == "1.5.7"
        run(binary, "activate", root, platform, "--quiesced")
        run(binary, "commit", root, platform, "--accepted")
        assert run(binary, "verify", root, platform)["version"] == "1.5.7"
        data = root / "data" / "owner.settings"
        data.parent.mkdir(parents=True)
        data.write_bytes(b"DO NOT DELETE MY SETTINGS")
        run(binary, "uninstall-prepare", root, platform, "--quiesced")
        run(binary, "uninstall-commit", root, platform, "--native-unregistered")
        assert run(binary, "verify", root, platform)["status"] == "EMPTY"
        assert data.read_bytes() == b"DO NOT DELETE MY SETTINGS"
        assert not (root / "current").exists()
        print("PASS_FROZEN_GENERAL_ENGINE_FIXTURE_INSTALL_UNINSTALL_PRESERVE")


if __name__ == "__main__":
    main()
