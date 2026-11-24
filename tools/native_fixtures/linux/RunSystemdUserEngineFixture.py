"""R889 isolated Linux systemd --user + Engine lifecycle; NO root or DIM units."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

from installer_engine.engine import Engine, hash_bytes


def must(value, label):
    if not value:
        raise RuntimeError(label)


def ctl(*args, strict=True):
    p = subprocess.run(["systemctl", "--user", *args], text=True,
                       capture_output=True, timeout=20)
    if strict and p.returncode:
        raise RuntimeError("SYSTEMCTL_" + args[0] + "_" + p.stderr[-200:])
    return p


def state(unit, key="ActiveState"):
    return ctl("show", "-p", key, "--value", unit, strict=False).stdout.strip()


def package(parent, name, version, code):
    folder = parent / name
    binary = folder / "payload" / "app" / "fixture.sh"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(code)
    binary.chmod(0o755)
    manifest = {"schema": 1, "product": "Direct Internet Method",
                "version": version, "platform": "linux-x86_64",
                "files": [{"path": "app/fixture.sh", "bytes": len(code),
                           "sha256": hash_bytes(code), "mode": 0o755}]}
    raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (folder / "manifest.json").write_bytes(raw)
    return folder, hash_bytes(raw)


def main():
    must(sys.platform.startswith("linux") and os.geteuid() != 0,
         "ONLY_NONROOT_LINUX_USER")
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    must(runtime and Path(runtime, "bus").is_socket(),
         "NO_USER_BUS")
    must(ctl("show", "-p", "Version", "--value", strict=False).returncode == 0,
         "NO_USER_SYSTEMD_MANAGER")
    name = "dim-r889-engine-fixture-" + uuid.uuid4().hex[:12] + ".service"
    link = Path(runtime) / "systemd" / "user" / name
    must(not link.exists() and not link.is_symlink(),
         "UNIT_NAME_CONFLICT")
    stages = []
    with tempfile.TemporaryDirectory(prefix="dim-r889-engine-user-") as td:
        temp = Path(td)
        root = temp / "engine"
        service = root / "current" / "app" / "fixture.sh"
        marker = temp / "version.txt"
        owner = root / "data" / "owner.settings"
        unitfile = temp / name
        unitfile.write_text(
            "[Unit]\nDescription=DIM R889 user-only fixture\n"
            "[Service]\nType=simple\nRestart=no\nTimeoutStopSec=5\n"
            f"ExecStart={service} {marker}\n", encoding="utf-8")
        pkg = temp / "source"
        pkg.mkdir()
        def code(version):
            return (f"#!/bin/sh\nprintf '%s' '{version}' > \"$1\"\n"
                    "exec /usr/bin/sleep 180\n").encode()
        old = package(pkg, "old", "1.5.6", code("1.5.6"))
        bad = package(pkg, "bad", "1.5.7", b"#!/bin/sh\nexit 47\n")
        good = package(pkg, "good", "1.5.7", code("1.5.7"))
        engine = Engine(root, "linux-x86_64")

        def stopped():
            return state(name) != "active"

        def active(version):
            return (state(name) == "active" and marker.is_file()
                    and marker.read_text() == version)

        def start(version):
            ctl("start", name)
            for _ in range(40):
                if active(version):
                    return
                time.sleep(.25)
            raise RuntimeError("START_MISMATCH_" + version)

        def stop():
            ctl("stop", name)
            must(stopped(), "STOP_NOT_CONFIRMED")

        def stage(entry):
            engine.stage(*entry)
            engine.activate(stopped)

        try:
            must(state(name, "LoadState") == "not-found",
                 "UNIT_ALREADY_LOADED")
            ctl("link", "--runtime", str(unitfile))
            must(link.is_symlink() and link.resolve() == unitfile.resolve(),
                 "RUNTIME_UNIT_LINK_UNTRUSTED")
            ctl("daemon-reload")
            stages.append("RUNTIME_ONLY_SYSTEMD_USER_UNIT_REGISTERED")

            stage(old)
            start("1.5.6")
            engine.commit(lambda: active("1.5.6"))
            must(engine.verify()["version"] == "1.5.6", "COMMIT_156_FAILED")
            stages.append("SYSTEMD_156_AND_ENGINE_COMMIT")

            owner.parent.mkdir(parents=True)
            owner.write_bytes(b"SYNTHETIC_OWNER_SETTINGS_KEEP")
            owner_sha = hashlib.sha256(owner.read_bytes()).hexdigest()
            stop()
            stage(bad)
            ctl("start", name, strict=False)
            for _ in range(40):
                if state(name) in ("failed", "inactive"):
                    break
                time.sleep(.25)
            must(state(name) != "active", "BAD_UNIT_UNEXPECTEDLY_ACTIVE")
            engine.rollback(stopped)
            must(engine.verify()["version"] == "1.5.6", "ROLLBACK_FAILED")
            ctl("reset-failed", name, strict=False)
            start("1.5.6")
            must(hashlib.sha256(owner.read_bytes()).hexdigest() == owner_sha,
                 "OWNER_CHANGED_AFTER_ROLLBACK")
            stages.append("SYSTEMD_FAILED_START_ENGINE_ROLLBACK")

            stop()
            stage(good)
            start("1.5.7")
            engine.commit(lambda: active("1.5.7"))
            must(engine.verify()["version"] == "1.5.7", "COMMIT_157_FAILED")
            stages.append("SYSTEMD_157_AND_ENGINE_COMMIT")

            stop()
            engine.prepare_uninstall(stopped)
            must(link.is_symlink() and link.resolve() == unitfile.resolve(),
                 "FOREIGN_SYSTEMD_LINK")
            link.unlink()
            ctl("daemon-reload")
            ctl("reset-failed", name, strict=False)
            engine.finish_uninstall(lambda: not link.exists() and stopped())
            must(engine.verify()["status"] == "EMPTY", "UNINSTALL_NOT_EMPTY")
            must(hashlib.sha256(owner.read_bytes()).hexdigest() == owner_sha,
                 "OWNER_DATA_REMOVED")
            stages.append("SYSTEMD_USER_UNREGISTERED_AND_ENGINE_UNINSTALL")

            print(json.dumps({"schema": 1,
                              "status": "PASS_ISOLATED_SYSTEMD_USER_ENGINE_FIXTURE",
                              "native_root_systemd_polkit_install_accepted": False,
                              "scope": "user-only synthetic", "unit": name,
                              "stages": stages, "owner_sha256": owner_sha,
                              "old_pin": old[1], "bad_pin": bad[1],
                              "new_pin": good[1]}, sort_keys=True))
        finally:
            ctl("stop", name, strict=False)
            if link.is_symlink() and link.resolve() == unitfile.resolve():
                link.unlink()
            ctl("reset-failed", name, strict=False)
            ctl("daemon-reload", strict=False)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"schema": 1,
                          "status": "FAIL_CLOSED_ISOLATED_SYSTEMD_USER_ENGINE",
                          "reason": str(exc),
                          "native_root_systemd_polkit_install_accepted": False},
                         sort_keys=True), file=sys.stderr)
        raise SystemExit(3)
