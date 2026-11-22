"""R928: exact UniversalFixtureInstaller against one real isolated systemd --user unit.

Non-root, TEMP-only synthetic native adapter. It exercises the *same*
transaction journal used by the cross-OS engine with a genuine systemd
service, including live service state and successful previous-version
restart after a failed new service. NEVER deploy this adapter: metadata and
receipts are user-owned and contain NO publisher, root/polkit or OS trust.
"""
from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

from installer_engine.engine import (
    Engine, EngineError, atomic_json, hash_bytes, require,
)
from installer_engine.native_receipt import intent_sha256
from installer_engine.universal_install import UniversalFixtureInstaller
from tools.native_fixtures.linux.RunSystemdDualScopeFixture import (
    bundle, systemctl, unit_state,
)

PLATFORM = "linux-x86_64"
STATUS = "PASS_R928_SHARED_UNIVERSAL_NATIVE_USER_SYSTEMD_FIXTURE_ONLY"


def must(ok: bool, reason: str) -> None:
    if not ok:
        raise RuntimeError(reason)


def receipt(intent: dict, status: str) -> dict:
    return {"schema": 1, "status": status,
            "intent_sha256": intent_sha256(intent)}


class SystemdUserFixtureAdapter:
    """A *nonprivileged* synthetic adapter; unit linked under runtime bus only."""

    def __init__(self, temp: Path, unit: str, unit_file: Path,
                 code_root: Path, user_root: Path, marker: Path):
        self.temp = temp
        self.unit = unit
        self.unit_file = unit_file
        self.code_root = code_root
        self.user_root = user_root
        self.marker = marker
        self.link = Path(os.environ["XDG_RUNTIME_DIR"]) / "systemd/user" / unit
        self.meta = temp / "synthetic-native-state.json"
        self.receipt_path = temp / "synthetic-native-receipt.json"
        self.inject_post_resume = False
        self.require_scope_version = True
        if not self.meta.exists():
            atomic_json(self.meta, {"schema": 1, "version": None,
                                    "should_run": False,
                                    "resume_starts": 0})
        must(self.unit.startswith("dim-r928-universal-") and
             self.unit.endswith(".service"), "USER_UNIT_IDENTITY_INVALID")
        must(self.unit_file.parent == self.temp and
             self.marker.parent == self.temp,
             "FOREIGN_FIXTURE_PATH")
        must(not self.meta.is_symlink() and
             not self.receipt_path.is_symlink(), "NATIVE_SYMLINK_FORBIDDEN")

    def _state(self) -> dict:
        data = json.loads(self.meta.read_text(encoding="utf8"))
        must(type(data) is dict and set(data) ==
             {"schema", "version", "should_run", "resume_starts"} and
             data["schema"] == 1 and type(data["should_run"]) is bool and
             type(data["resume_starts"]) is int, "SYNTHETIC_META_INVALID")
        return data

    def _set(self, **kwargs) -> None:
        data = self._state()
        data.update(kwargs)
        atomic_json(self.meta, data)

    def _linked(self) -> bool:
        if not self.link.is_symlink():
            return False
        must(self.link.resolve() == self.unit_file.resolve(),
             "SYSTEMD_UNIT_SYMLINK_TAMPERED")
        return True

    def _register(self) -> None:
        if self._linked():
            return
        must(not self.link.exists() and not self.link.is_symlink() and
             unit_state(self.unit, "LoadState") == "not-found",
             "FOREIGN_SYSTEMD_UNIT_COLLISION")
        systemctl("link", "--runtime", str(self.unit_file))
        must(self._linked(), "SYSTEMD_UNIT_LINK_FAILED")
        systemctl("daemon-reload")
        must(unit_state(self.unit, "LoadState") == "loaded",
             "SYSTEMD_UNIT_NOT_LOADED")

    def _unregister(self) -> None:
        must(self.quiesced(), "SYSTEMD_NOT_STOPPED")
        if self._linked():
            self.link.unlink()
        must(not self.link.exists() and not self.link.is_symlink(),
             "SYSTEMD_UNIT_STILL_LINKED")
        systemctl("daemon-reload")
        systemctl("reset-failed", self.unit, check=False)

    def _running(self, version: str) -> bool:
        if unit_state(self.unit, "ActiveState") != "active":
            return False
        if not self.marker.is_file() or self.marker.is_symlink():
            return False
        pid = unit_state(self.unit, "MainPID")
        try:
            reported_version, reported_pid = self.marker.read_text("utf8").splitlines()
        except (OSError, ValueError):
            return False
        return (reported_version == version and reported_pid == pid and
                pid.isdigit() and int(pid) > 0)

    def _wait_running(self, version: str) -> bool:
        for _ in range(35):
            if self._running(version):
                return True
            if unit_state(self.unit, "ActiveState") in ("failed", "inactive"):
                return False
            time.sleep(.1)
        return False

    def _code_versions(self) -> set:
        return {
            Engine(path, PLATFORM).verify().get("version")
            for path in (self.code_root, self.user_root)
        }

    def _receipt(self, intent: dict, status: str) -> None:
        atomic_json(self.receipt_path, receipt(intent, status))

    def _receipt_bytes(self, intent: dict, status: str) -> bytes | None:
        if not self.receipt_path.exists():
            return None
        record = json.loads(self.receipt_path.read_text("utf8"))
        if record != receipt(intent, status):
            return None
        if (status == "completed" and intent["operation"] != "uninstall"
                and not self._running(intent["new"])):
            return None
        if status == "completed" and intent["operation"] == "uninstall":
            if self._linked() or not self.quiesced():
                return None
        if status == "restored":
            state = self._state()
            if state["version"] != intent["old"] or (
                    state["should_run"] and
                    not self._running(intent["old"])):
                return None
            if not state["should_run"] and not self.quiesced():
                return None
            if state["version"] is not None and not self._linked():
                return None
        return self.receipt_path.read_bytes()

    def snapshot(self) -> bytes:
        v = self.observed_version()
        state = {"schema": 1, "version": v,
                 "running": self._running(v) if v is not None else False,
                 "linked": self._linked()}
        return (json.dumps(state, sort_keys=True, separators=(",", ":")) +
                "\n").encode("utf8")

    def observed_version(self) -> str | None:
        return self._state()["version"]

    def quiesced(self) -> bool:
        return unit_state(self.unit, "ActiveState") != "active" and (
            unit_state(self.unit, "MainPID") in ("0", ""))

    def quiesce(self) -> None:
        if not self.quiesced():
            systemctl("stop", self.unit)
        must(self.quiesced(), "SYSTEMD_UNIT_NOT_QUIESCED")
        systemctl("reset-failed", self.unit, check=False)

    def apply(self, target_version: str, intent: dict) -> None:
        must(self.quiesced() and self._linked(),
             "SYSTEMD_APPLY_REQUIRED_STOPPED_LINKED")
        must(self._code_versions() == {target_version},
             "CODE_NOT_READY_FOR_NATIVE_START")
        self.receipt_path.unlink(missing_ok=True)
        self._set(version=target_version, should_run=True)
        self.marker.unlink(missing_ok=True)
        systemctl("start", self.unit, check=False)
        if not self._wait_running(target_version):
            raise EngineError("SYNTHETIC_REAL_SYSTEMD_POSTINSTALL_FAILURE")
        self._receipt(intent, "completed")

    def completed(self, intent: dict) -> bytes | None:
        return self._receipt_bytes(intent, "completed")

    def restore(self, snapshot: bytes, intent: dict) -> None:
        self.quiesce()
        try:
            prev = json.loads(snapshot.decode("utf8"))
        except (UnicodeError, ValueError) as e:
            raise EngineError("SYNTHETIC_PREIMAGE_INVALID") from e
        must(type(prev) is dict and set(prev) ==
             {"schema", "version", "running", "linked"} and
             prev["schema"] == 1 and type(prev["running"]) is bool and
             type(prev["linked"]) is bool and
             prev["version"] == intent["old"],
             "SYNTHETIC_PREIMAGE_IDENTITY_CHANGED")
        self.receipt_path.unlink(missing_ok=True)
        if prev["linked"]:
            self._register()
        else:
            self._unregister()
        self._set(version=prev["version"], should_run=prev["running"])

    def resume_restored(self, old_version: str | None, intent: dict) -> None:
        state = self._state()
        must(state["version"] == old_version and
             self._code_versions() == {old_version},
             "NATIVE_RESTART_BEFORE_TWO_OLD_SCOPES")
        if state["should_run"]:
            must(old_version is not None and self._linked(),
                 "OLD_NATIVE_SERVICE_NOT_REGISTERED")
            if not self._running(old_version):
                must(self.quiesced(), "UNEXPECTED_FOREIGN_ACTIVE_UNIT")
                self.marker.unlink(missing_ok=True)
                systemctl("start", self.unit)
                must(self._wait_running(old_version),
                     "OLD_NATIVE_RUNTIME_NOT_HEALTHY")
                self._set(resume_starts=state["resume_starts"] + 1)
        else:
            must(self.quiesced(), "OLD_SERVICE_WAS_STOPPED")
        self._receipt(intent, "restored")
        if self.inject_post_resume:
            raise EngineError("FIXTURE_CRASH_AFTER_NATIVE_RESTORE_RECEIPT")

    def restored(self, intent: dict) -> bytes | None:
        return self._receipt_bytes(intent, "restored")

    def unregister(self, intent: dict) -> None:
        must(self.quiesced(), "NATIVE_UNINSTALL_NOT_QUIESCED")
        self.receipt_path.unlink(missing_ok=True)
        self._unregister()
        self._set(version=None, should_run=False)
        self._receipt(intent, "completed")

    def uninstall_completed(self, intent: dict) -> bytes | None:
        return self._receipt_bytes(intent, "completed")

    def cleanup(self) -> None:
        systemctl("stop", self.unit, check=False)
        if self.link.is_symlink() and self.link.resolve() == self.unit_file.resolve():
            self.link.unlink()
        systemctl("reset-failed", self.unit, check=False)
        systemctl("daemon-reload", check=False)


def _child_replay_after_restoration(root_string: str, unit: str, sender) -> None:
    """Independent process, not a second in-memory orchestrator object."""
    try:
        root = Path(root_string).absolute()
        must(root.parent.resolve() == Path(tempfile.gettempdir()).resolve()
             and root.name.startswith("dim-r928-universal-user-"),
             "CHILD_ONLY_OWNED_OS_TEMP_ROOT")
        must(unit.startswith("dim-r928-universal-") and
             unit.endswith(".service") and
             (root/unit).is_file(), "CHILD_ONLY_SYNTHETIC_UNIT")
        must(root.stat().st_uid == os.geteuid(),
             "CHILD_ROOT_OWNER_INVALID")
        code, user = root/"code", root/"user"
        native = SystemdUserFixtureAdapter(
            root, unit, root/unit, code, user, root/"native-running.marker")
        tx = UniversalFixtureInstaller(
            root/"journal", PLATFORM, {"code": code, "user": user}, native)
        result = tx.recover()
        sender.send({"status": "PASS_CHILD_NATIVE_RECEIPT_REPLAY",
                     "pid": os.getpid(), "version": result["version"],
                     "resume_starts": native._state()["resume_starts"]})
    except Exception as exc:
        sender.send({"status": "FAIL_CHILD_NATIVE_RECEIPT_REPLAY",
                     "pid": os.getpid(), "reason": str(exc)})
        raise
    finally:
        sender.close()


def main() -> None:
    must(sys.platform.startswith("linux") and os.geteuid() != 0,
         "R928_NON_ROOT_LINUX_REQUIRED")
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", "/nonexistent"))
    must((runtime / "bus").is_socket(), "R928_USER_SYSTEMD_BUS_REQUIRED")
    must(systemctl("show", "-p", "Version", "--value",
                   check=False).returncode == 0,
         "R928_USER_SYSTEMD_UNAVAILABLE")
    steps = []
    unit = "dim-r928-universal-" + uuid.uuid4().hex[:12] + ".service"
    link = runtime / "systemd/user" / unit
    must(not link.exists() and not link.is_symlink(),
         "R928_UNIT_ALREADY_EXISTS")
    with tempfile.TemporaryDirectory(prefix="dim-r928-universal-user-") as folder:
        root = Path(folder)
        code_root, user_root = root/"code", root/"user"
        unit_file, marker = root/unit, root/"native-running.marker"
        service = code_root/"current/app/service.sh"
        unit_file.write_text(
            "[Unit]\nDescription=DIM R928 isolated universal systemd user fixture\n"
            "[Service]\nType=simple\nRestart=no\nTimeoutStopSec=5\n"
            f"ExecStart={service} {marker}\n", encoding="utf8")
        packages_dir = root/"source"
        packages_dir.mkdir()

        def sources(version: str, *, broken=False):
            tag = version.replace(".", "_") + ("_broken" if broken else "")
            shell = (b"#!/bin/sh\nexit 47\n" if broken else
                     ("#!/bin/sh\nprintf '%s\\n%s\\n' '" + version +
                      "' \"$$\" > \"$1\"\nexec /usr/bin/sleep 180\n").encode())
            return {
                "code": bundle(packages_dir, "code"+tag, "code", version,
                               shell, 0o755),
                "user": bundle(packages_dir, "user"+tag, "user", version,
                               ("SYNTHETIC_USER_CODE_"+version).encode(),
                               0o644)
            }

        adapter = SystemdUserFixtureAdapter(root, unit, unit_file,
                                            code_root, user_root, marker)

        def engine(native=None):
            return UniversalFixtureInstaller(root/"journal", PLATFORM,
                       {"code": code_root, "user": user_root},
                       native or adapter)

        def code_versions():
            return adapter._code_versions()

        try:
            adapter._register()
            must(link.is_symlink() and link.resolve() == unit_file.resolve(),
                 "FOREIGN_RUNTIME_UNIT_LINK")
            steps.append("ISOLATED_SYSTEMD_USER_UNIT_LINKED")

            tx = engine()
            tx.begin(sources("1.5.6"))
            tx.activate()
            must(adapter._running("1.5.6"), "NATIVE_156_NOT_RUNNING")
            tx.commit()
            must(code_versions() == {"1.5.6"}, "OLD_CODE_NOT_COMMITTED")
            steps.append("UNIVERSAL_FRESH_INSTALL_REAL_SYSTEMD_RUNNING")

            owner = user_root/"data"/"settings.json"
            owner.parent.mkdir()
            owner.write_bytes(b"OWNER_CONFIG_PRESERVED_R928")
            owner_sha = hashlib.sha256(owner.read_bytes()).hexdigest()

            tx.begin(sources("1.5.7", broken=True))
            try:
                tx.activate()
            except EngineError as e:
                must("SYNTHETIC_REAL_SYSTEMD_POSTINSTALL_FAILURE" in str(e),
                     "NATIVE_FAILURE_WRONG_REASON")
            else:
                raise RuntimeError("EXPECTED_REAL_SYSTEMD_POSTINSTALL_FAILURE")
            must(adapter.observed_version() == "1.5.7" and
                 not adapter._running("1.5.7"), "NATIVE_FAILURE_NOT_REPRODUCED")
            engine().recover()
            must(code_versions() == {"1.5.6"} and
                 adapter._running("1.5.6"), "NATIVE_ROLLBACK_OLD_RUNTIME_FAILED")
            steps.append("FAILED_NATIVE_SERVICE_ROLLBACK_TWO_SCOPES_OLD_RESTARTED")

            tx.begin(sources("1.5.7"))
            tx.activate()
            tx.commit()
            must(code_versions() == {"1.5.7"} and
                 adapter._running("1.5.7"), "NATIVE_157_NOT_COMMITTED")
            steps.append("UNIVERSAL_UPDATE_NATIVE_157_RUNNING")

            tx.begin_uninstall()
            must(adapter.quiesced(), "UNINSTALL_DID_NOT_STOP_RUNNING_UNIT")
            must(adapter._state()["version"] == "1.5.7",
                 "UNINSTALL_NATIVE_VERSION_CHANGED_BEFORE_UNREGISTER")
            tx.apply_uninstall()
            must(not adapter._linked(), "UNINSTALL_DID_NOT_UNLINK_UNIT")
            adapter.inject_post_resume = True
            try:
                tx.abort_uninstall()
            except EngineError as e:
                must("FIXTURE_CRASH_AFTER_NATIVE_RESTORE_RECEIPT" in str(e),
                     "RESTORE_INTERRUPTION_WRONG_REASON")
            else:
                raise RuntimeError("EXPECTED_RESTORE_RECEIPT_INTERRUPTION")
            must(engine()._load()["phase"] == "uninstall-restoring-native",
                 "RESTORATION_JOURNAL_MISSING")
            start_count = adapter._state()["resume_starts"]
            must(start_count >= 2 and adapter._running("1.5.7"),
                 "OLD_RUNTIME_NOT_RESUMED")
            ctx = mp.get_context("spawn")
            recv, send = ctx.Pipe(duplex=False)
            child = ctx.Process(
                target=_child_replay_after_restoration,
                args=(str(root), unit, send))
            child.start()
            send.close()
            child.join(timeout=45)
            if child.is_alive():
                child.terminate()  # Only the newly created fixture child.
                child.join(timeout=10)
                raise RuntimeError("ISOLATED_RECOVERY_CHILD_TIMED_OUT")
            must(child.exitcode == 0 and recv.poll(timeout=1),
                 "INDEPENDENT_RECOVERY_PROCESS_DID_NOT_COMPLETE")
            child_result = recv.recv()
            recv.close()
            must(child_result["status"] == "PASS_CHILD_NATIVE_RECEIPT_REPLAY"
                 and child_result["pid"] != os.getpid()
                 and child_result["version"] == "1.5.7"
                 and child_result["resume_starts"] == start_count,
                 "RESTORE_REPLAY_CROSSES_PROCESS_BUT_LOST_IDENTITY")
            must(adapter._state()["resume_starts"] == start_count and
                 code_versions() == {"1.5.7"} and
                 adapter._running("1.5.7"),
                 "PROCESS_BOUNDARY_DUPLICATE_RESTART_OR_LOST_RUNTIME")
            steps.append("REAL_SEPARATE_PROCESS_RECOVERY_WITHOUT_SECOND_RESTART")

            tx.begin_uninstall()
            tx.apply_uninstall()
            tx.finish_uninstall()
            must(code_versions() == {None} and not adapter._linked() and
                 adapter.observed_version() is None,
                 "NATIVE_FINAL_UNINSTALL_INCOMPLETE")
            must(hashlib.sha256(owner.read_bytes()).hexdigest() == owner_sha,
                 "OWNER_CONFIG_CHANGED")
            steps.append("REAL_SYSTEMD_USER_UNINSTALL_AND_OWNER_DATA_PRESERVED")

            print(json.dumps({
                "schema": 1, "status": STATUS, "unit": unit,
                "stages": steps, "owner_sha256": owner_sha,
                "systemd_user_native_observation": True,
                "native_root_systemd_polkit_install_accepted": False,
                "os_protected_native_receipt_accepted": False,
                "publisher_authenticated": False,
                "native_product_rollback_accepted": False,
                "host_reboot_accepted": False
            }, sort_keys=True))
        finally:
            adapter.cleanup()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(json.dumps({"schema": 1,
                          "status": "FAIL_CLOSED_R928_UNIVERSAL_USER_SYSTEMD",
                          "native_root_systemd_polkit_install_accepted": False,
                          "error": str(e)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(3)
