"""R890: two physical user-owned code roots + real systemd --user lifecycle.

This is intentionally UNPRIVILEGED. Neither physical root is a system root.
Service state is checked for the isolated runtime unit, but callbacks remain
fixture assertions, not trusted privileged OS acceptance evidence.
"""
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

from installer_engine.engine import Engine, EngineError, hash_bytes
from installer_engine.two_scope import TwoScopeFixtureCoordinator


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def systemctl(*arguments, check=True):
    proc = subprocess.run(["systemctl", "--user", *arguments], capture_output=True,
                          text=True, timeout=20)
    if check and proc.returncode != 0:
        raise RuntimeError("SYSTEMD_" + arguments[0] + "_FAIL:" + proc.stderr[-200:])
    return proc


def unit_state(name, property="ActiveState"):
    return systemctl("show", "-p", property, "--value", name,
                     check=False).stdout.strip()


def bundle(parent, label, scope, version, data, mode):
    folder = parent / label
    file = folder / "payload" / "app" / ("service.sh" if scope == "code" else "user.bin")
    file.parent.mkdir(parents=True, exist_ok=False)
    file.write_bytes(data)
    file.chmod(mode)
    rel = file.relative_to(folder / "payload").as_posix()
    manifest = {"schema": 1, "product": "Direct Internet Method",
                "version": version, "platform": "linux-x86_64",
                "files": [{"path": rel, "bytes": len(data),
                           "sha256": hash_bytes(data), "mode": mode}]}
    raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    (folder / "manifest.json").write_bytes(raw)
    return folder, hash_bytes(raw)


def main():
    require(sys.platform == "linux" and os.geteuid() != 0, "LINUX_UNPRIVILEGED_REQUIRED")
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", "/nonexistent"))
    require((runtime / "bus").is_socket(), "USER_BUS_REQUIRED")
    require(systemctl("show", "-p", "Version", "--value",
                      check=False).returncode == 0, "USER_SYSTEMD_UNAVAILABLE")
    unit = "dim-r890-dualscope-" + uuid.uuid4().hex[:12] + ".service"
    symlink = runtime / "systemd" / "user" / unit
    require(not symlink.exists() and not symlink.is_symlink(), "UNIT_CONFLICT")
    stages = []
    with tempfile.TemporaryDirectory(prefix="dim-r890-user-dual-") as scratch:
        root = Path(scratch)
        code_root = root / "code"
        user_root = root / "user"
        native = root / "journal"
        marker = root / "active-version.txt"
        owned = user_root / "data" / "user.config"
        service = code_root / "current" / "app" / "service.sh"
        unit_file = root / unit
        unit_file.write_text(
            "[Unit]\nDescription=R890 synthetic dual-scope fixture\n"
            "[Service]\nType=simple\nRestart=no\nTimeoutStopSec=5\n"
            f"ExecStart={service} {marker}\n", encoding="utf-8")
        package_root = root / "packages"
        package_root.mkdir()
        def svc_version(ver):
            return (f"#!/bin/sh\nprintf '%s' '{ver}' > \"$1\"\n"
                    "exec /usr/bin/sleep 180\n").encode()
        def packages(ver, *, bad_service=False):
            code = (b"#!/bin/sh\nexit 42\n" if bad_service else svc_version(ver))
            return {
                "code": bundle(package_root, "c" + ver.replace(".", "_") +
                               ("bad" if bad_service else ""), "code", ver, code, 0o755),
                "user": bundle(package_root, "u" + ver.replace(".", "_") +
                               ("bad" if bad_service else ""), "user", ver,
                               ("USER_CODE_" + ver).encode(), 0o644),
            }
        old = packages("1.5.6")
        bad = packages("1.5.7", bad_service=True)
        good = packages("1.5.7")
        coord = TwoScopeFixtureCoordinator(native, "linux-x86_64",
                                           {"code": code_root, "user": user_root})

        def stopped():
            return unit_state(unit) != "active"

        def running(ver):
            return (unit_state(unit) == "active" and marker.is_file()
                    and marker.read_text("utf-8") == ver)

        def wait_running(ver):
            for _ in range(50):
                if running(ver):
                    return
                time.sleep(.2)
            raise RuntimeError("NATIVE_RUNTIME_VERSION_WRONG_" + ver)

        def start(ver):
            systemctl("start", unit)
            wait_running(ver)

        def stop():
            systemctl("stop", unit)
            require(stopped(), "UNIT_NOT_STOPPED")

        def stage_active(src):
            coord.prepare(src)
            coord.activate(stopped)

        def assert_scopes(ver):
            states = {key: Engine(path, "linux-x86_64").verify()
                      for key, path in (("code", code_root), ("user", user_root))}
            require(all(state["version"] == ver for state in states.values()),
                    "DUAL_ROOT_VERSION_DIVERGENCE")
            require(not coord.path.exists(), "COORDINATOR_JOURNAL_STILL_ACTIVE")

        try:
            require(unit_state(unit, "LoadState") == "not-found",
                    "USER_UNIT_ALREADY_LOADED")
            systemctl("link", "--runtime", str(unit_file))
            require(symlink.is_symlink() and
                    symlink.resolve() == unit_file.resolve(), "USER_UNIT_LINK_TAMPERED")
            systemctl("daemon-reload")
            stages.append("REAL_USER_SYSTEMD_RUNTIME_UNIT")

            stage_active(old)
            start("1.5.6")
            coord.finalize(lambda: running("1.5.6"))  # fixture callback, not trust
            assert_scopes("1.5.6")
            stages.append("TWO_ROOTS_INITIAL_156_NATIVE_RUNNING")

            owned.parent.mkdir(parents=True)
            owned.write_bytes(b"OWNER_DATA_UNCHANGED_R890")
            owner_pin = hashlib.sha256(owned.read_bytes()).hexdigest()

            stop()
            stage_active(bad)
            systemctl("start", unit, check=False)
            for _ in range(50):
                if unit_state(unit) in ("failed", "inactive"):
                    break
                time.sleep(.2)
            require(not running("1.5.7"), "BROKEN_NATIVE_SERVICE_STARTED")
            coord.abort(stopped)
            assert_scopes("1.5.6")
            systemctl("reset-failed", unit, check=False)
            start("1.5.6")
            require(hashlib.sha256(owned.read_bytes()).hexdigest() == owner_pin,
                    "OWNER_CHANGED_ON_ROLLBACK")
            stages.append("BAD_NATIVE_START_ABORT_BOTH_SCOPES_RESTORE_156")

            stop()
            stage_active(good)
            start("1.5.7")
            try:
                coord.finalize(lambda: running("1.5.7"), fault_after="code")
            except EngineError as e:
                require("FIXTURE_INJECTED_AFTER_FINALIZE" in str(e),
                        "UNEXPECTED_FINALIZATION_FAILURE")
            else:
                raise RuntimeError("MISSING_FINALIZE_INJECTION")
            require(coord._journal()["phase"] == "finalizing",
                    "FORWARD_JOURNAL_MISSING")
            try:
                coord.abort(stopped)
            except EngineError as e:
                require("FORWARD_RECOVERY_REQUIRED" in str(e),
                        "ILLEGAL_ROLLBACK_AFTER_FIRST_COMMIT")
            else:
                raise RuntimeError("ILLEGAL_ABORT_ACCEPTED")
            # Fresh object simulates a subsequent new process replay.
            coord = TwoScopeFixtureCoordinator(native, "linux-x86_64",
                                               {"code": code_root, "user": user_root})
            coord.finalize(lambda: running("1.5.7"))
            assert_scopes("1.5.7")
            require(hashlib.sha256(owned.read_bytes()).hexdigest() == owner_pin,
                    "OWNER_CHANGED_DURING_FORWARD_RECOVERY")
            stages.append("INTERRUPTED_COMMIT_FORWARD_REPLAY_BOTH_ROOTS_157")

            stop()
            for path in (code_root, user_root):
                Engine(path, "linux-x86_64").prepare_uninstall(stopped)
            require(symlink.is_symlink() and
                    symlink.resolve() == unit_file.resolve(),
                    "OWNED_USER_UNIT_LINK_CHANGED")
            symlink.unlink()
            systemctl("daemon-reload")
            systemctl("reset-failed", unit, check=False)
            for path in (code_root, user_root):
                eng = Engine(path, "linux-x86_64")
                eng.finish_uninstall(lambda: not symlink.exists() and stopped())
                require(eng.verify()["status"] == "EMPTY", "UNINSTALL_NOT_EMPTY")
            require(hashlib.sha256(owned.read_bytes()).hexdigest() == owner_pin,
                    "OWNER_REMOVED_DURING_UNINSTALL")
            stages.append("USER_UNIT_UNLINKED_TWO_CODE_ROOTS_CLEANED")

            print(json.dumps({
                "schema": 1, "status": "PASS_R890_TWO_USER_ROOTS_NATIVE_SYSTEMD_FIXTURE",
                "native_privileged_install_accepted": False,
                "unit": unit, "stages": stages, "owner_sha256": owner_pin,
                "scope": "two user-owned roots, simulated protected code, no root/polkit",
            }, sort_keys=True))
        finally:
            systemctl("stop", unit, check=False)
            if symlink.is_symlink() and symlink.resolve() == unit_file.resolve():
                symlink.unlink()
            systemctl("reset-failed", unit, check=False)
            systemctl("daemon-reload", check=False)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(json.dumps({"schema": 1,
                          "status": "FAIL_CLOSED_R890_TWO_USER_ROOTS",
                          "native_privileged_install_accepted": False,
                          "reason": str(e)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(3)
