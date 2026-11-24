"""Native frozen-executable smoke for offline archive import and code-only lifecycle.

All writes are contained in a disposable temporary fixture, not native
Windows Service, Registry, DNS, systemd, or an installed application.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import zipfile


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def invoke(exe: Path, cwd: Path, action: str, platform: str,
           *options: str, fail: bool = False) -> dict:
    command = [str(exe), action, "--platform", platform, *options]
    p = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                       timeout=90, check=False)
    if fail:
        assert p.returncode == 3 and "FAIL_CLOSED" in p.stderr, (p.returncode, p.stderr)
        return json.loads(p.stderr)
    if p.returncode:
        raise AssertionError(f"{action} exit={p.returncode}, err={p.stderr[-500:]}")
    doc = json.loads(p.stdout.strip())
    assert isinstance(doc, dict) and doc.get("status"), doc
    return doc


def zip_source(path: Path, platform: str) -> tuple[str, int]:
    is_windows = platform.startswith("windows")
    data = b"DIM SYNTHETIC CONTENT, NEVER AN INSTALLED SERVICE"
    manifest = {
        "schema": 1, "product": "Direct Internet Method",
        "version": "1.5.7", "platform": platform,
        "files": [{"file": "app/main.bin", "bytes": len(data),
                   "sha256": sha(data)}]}
    members = {}
    if is_windows:
        secondary = b"NATIVE SERVICE IS NOT REGISTERED IN THIS TEST"
        files = [
            {"scope": "user", "file": "app/main.bin", "source": "app/main.bin",
             "bytes": len(data), "sha256": sha(data)},
            {"scope": "privileged", "file": "bin/service.stub",
             "source": "bin/service.stub", "bytes": len(secondary),
             "sha256": sha(secondary)}
        ]
        windows_manifest = {"schema": 2, "product": "Direct Internet Method",
                            "version": "1.5.7", "files": files}
        members = {
            "installer-metadata/manifest.json":
                json.dumps(windows_manifest).encode(),
            "installer-metadata/RELEASE.json":
                b'{"product":"Direct Internet Method","version":"1.5.7"}',
            "installer-metadata/unins042.exe": b"fake uninstaller fixture",
            "installer-metadata/unins042.dat": b"fake log fixture",
            "managed/user/app/main.bin": data,
            "managed/privileged/bin/service.stub": secondary,
        }
        count = 2
    else:
        prefix = "DIM_1.5.7_Linux_x86_64/"
        members = {
            prefix + "PACKAGE_MANIFEST.json": json.dumps(manifest).encode(),
            prefix + "SHA256SUMS.txt": b"archive pin supplied independently",
            prefix + "app/main.bin": data,
        }
        count = 1
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name, content in members.items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            z.writestr(info, content)
    return sha(path.read_bytes()), count


def main() -> None:
    assert len(sys.argv) == 2
    binary = Path(sys.argv[1]).resolve(strict=True)
    platform = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    kind = "windows-managed" if os.name == "nt" else "linux-distribution"
    with tempfile.TemporaryDirectory(prefix="dim-frozen-generic-source-") as td:
        home = Path(td)
        # Same frozen portable executable exercises the full two-scope
        # install/upgrade/failure-rollback/uninstall protocol on BOTH OSs.
        universal = invoke(binary, home, "universal-selftest", platform)
        assert universal["status"] == "PASS_UNIVERSAL_TRANSACTION_FIXTURE"
        assert all(universal[k] == "PASS" for k in (
            "fresh_install", "in_place_upgrade",
            "incomplete_native_update_rollback",
            "uninstall_preserves_owner_data"))
        assert universal["native_product_install_accepted"] is False
        assert universal["power_cut_accepted"] is False
        invoke(binary, home, "universal-selftest", platform,
               "--root", str(home / "foreign-install-path"), fail=True)
        assert not (home / "foreign-install-path").exists()
        zip_file = home / "source.zip"
        normalized = home / "normalized"
        root = home / "engine-root"
        archive_pin, expected_files = zip_source(zip_file, platform)
        options = ("--archive", str(zip_file), "--archive-sha256", archive_pin,
                   "--archive-kind", kind, "--destination", str(normalized))
        invoke(binary, home, "import-archive", platform,
               "--archive", str(zip_file), "--archive-sha256", "0" * 64,
               "--archive-kind", kind, "--destination", str(normalized),
               fail=True)
        assert not normalized.exists(), "bad archive pin must never publish output"
        result = invoke(binary, home, "import-archive", platform, *options)
        assert result["status"] == "PASS_IMPORTED_VERIFIED_CODE_BUNDLE_ONLY"
        assert result["files"] == expected_files and not result[
            "native_installer_or_service_registered"]
        manifest_pin = result["normalized_manifest_sha256"]
        # Same pinned source bytes -> one scope-specific code bundle using the
        # frozen CLI, not host Python or native service registration.
        normalized_doc = json.loads((normalized / "manifest.json").read_text("utf-8"))
        selected = normalized_doc["files"][0]
        layout = home / "scope-layout.json"
        layout_doc = {
            "schema": 1, "product": normalized_doc["product"],
            "version": normalized_doc["version"], "platform": platform,
            "files": [{"scope": "fixture", "source": selected["path"],
                       "target": "bin/synthetic-stub.bin",
                       "mode": selected["mode"]}],
        }
        layout_bytes = (json.dumps(layout_doc, sort_keys=True,
                                   separators=(",", ":")) + "\n").encode("utf-8")
        layout.write_bytes(layout_bytes)
        scoped = home / "scoped"
        scope_args = ("--bundle", str(normalized),
                      "--expected-manifest-sha256", manifest_pin,
                      "--layout", str(layout), "--scope", "fixture",
                      "--destination", str(scoped))
        invoke(binary, home, "materialize-scope", platform, *scope_args,
               "--layout-sha256", "0" * 64, fail=True)
        assert not scoped.exists(), "bad independent scope-layout pin must not write"
        scope_result = invoke(binary, home, "materialize-scope", platform,
                              *scope_args, "--layout-sha256", sha(layout_bytes))
        assert scope_result["status"] == "SCOPED_BUILD_ONLY_NOT_NATIVE_INSTALL"
        assert scope_result["files"] == 1 and not scope_result[
            "native_installation_or_rollback_accepted"]
        assert sha((scoped / "payload" / "bin" /
                    "synthetic-stub.bin").read_bytes()) == selected["sha256"]
        assert not (scoped / "payload" / "README.md").exists()
        args = ("--root", str(root))
        assert invoke(binary, home, "verify", platform, *args)["status"] == "EMPTY"
        invoke(binary, home, "stage", platform, *args, "--bundle", str(normalized),
               "--expected-manifest-sha256", manifest_pin)
        invoke(binary, home, "activate", platform, *args, "--quiesced")
        invoke(binary, home, "commit", platform, *args, "--accepted")
        verified = invoke(binary, home, "verify", platform, *args)
        assert verified["files"] == expected_files and verified["version"] == "1.5.7"
        data = root / "data" / "owner.settings"
        data.parent.mkdir()
        data.write_bytes(b"OWNER CONFIG STAYS - NEVER A MANAGED PAYLOAD")
        invoke(binary, home, "uninstall-prepare", platform, *args, "--quiesced")
        invoke(binary, home, "uninstall-commit", platform,
               *args, "--native-unregistered")
        assert invoke(binary, home, "verify", platform, *args)["status"] == "EMPTY"
        assert data.read_bytes() == b"OWNER CONFIG STAYS - NEVER A MANAGED PAYLOAD"
        assert not (root / "current").exists()
        print("PASS_FROZEN_GENERAL_ENGINE_FIXTURE_INSTALL_UNINSTALL_PRESERVE")
        print("PASS_FROZEN_GENERIC_SHA_PINNED_ARCHIVE_IMPORT_AND_LIFECYCLE")


if __name__ == "__main__":
    main()
