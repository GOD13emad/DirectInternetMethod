"""R930: ONE existing universal transaction kernel + REAL synthetic Inno AND SCM.

Strictly a fresh, network-disabled disposable Windows Sandbox SYSTEM guest.
No real DIM identity, no host software mutation. Reuses R929 exact native Inno
adapter and the R927 universal journal, adding a synthetic Windows SCM SERVICE
observation through one narrowly-scoped fixture adapter. User-controlled test
receipts are NOT publisher/OS authentication or a product release.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import winreg

from installer_engine.engine import EngineError, atomic_json, hash_bytes
from installer_engine.native_receipt import intent_sha256
from tools.native_fixtures.windows.RunUniversalInnoSandboxFixture import (
    INPUT, OUTPUT, ROOT, guest_guard, SyntheticNativeInnoAdapter,
    engine, sha, source as generic_source,
)

REPORT = OUTPUT / "r930-native-inno-scm.json"
SERVICE = "DIMR887IsolatedFixtureSvc"
MARKER = Path(r"C:\ProgramData\DIM_R887_SCMSandboxFixture\active-version.txt")
BIN = ROOT / "code/current/app/FixtureService.exe"
SC = Path(os.environ["SystemRoot"]) / "System32/sc.exe"
KIND = r"SYSTEM\CurrentControlSet\Services" + "\\" + SERVICE
PLATFORM = "windows-x86_64"


def must(ok: bool, reason: str) -> None:
    if not ok:
        raise EngineError(reason)


def sc(*args: str, allow_fail=False) -> subprocess.CompletedProcess:
    must(SC.is_file(), "R930_SC_BINARY_MISSING")
    p = subprocess.run([str(SC), *args], capture_output=True,
                       text=True, timeout=40)
    if not allow_fail:
        must(p.returncode == 0,
             "R930_SC_" + args[0].upper() + "_EXIT_" + str(p.returncode) +
             "_" + p.stdout[-180:] + p.stderr[-150:])
    return p


def scm_state() -> str | None:
    p = sc("queryex", SERVICE, allow_fail=True)
    if p.returncode != 0:
        must("1060" in (p.stdout + p.stderr) or p.returncode == 1060,
             "R930_UNKNOWN_SCM_QUERY_ERROR")
        return None
    match = re.search(r"STATE\s*:\s*[0-9]+\s+([A-Z_]+)", p.stdout)
    must(match is not None, "R930_SCM_STATE_PARSE_INVALID")
    return match.group(1)


def scm_config() -> dict | None:
    if scm_state() is None:
        return None
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KIND, 0,
                        winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        return {
            "image": winreg.QueryValueEx(key, "ImagePath")[0],
            "object": winreg.QueryValueEx(key, "ObjectName")[0],
            "type": winreg.QueryValueEx(key, "Type")[0],
            "start": winreg.QueryValueEx(key, "Start")[0],
        }


class ScmInnoFixtureAdapter(SyntheticNativeInnoAdapter):
    """Native Windows SCM+Inno fixture only; same R927 universal protocol."""

    def __init__(self, root: Path):
        super().__init__(root)
        must(root == ROOT and SERVICE == "DIMR887IsolatedFixtureSvc" and
             MARKER.parent.name == "DIM_R887_SCMSandboxFixture" and
             BIN == ROOT / "code/current/app/FixtureService.exe",
             "R930_SYNTHETIC_SERVICE_IDENTITY_CHANGED")
        pins_file = INPUT / "scm-pins.json"
        must(pins_file.is_file(), "R930_PINNED_SERVICE_BUILDS_MISSING")
        pins = json.loads(pins_file.read_text("utf8"))
        must(type(pins) is dict and set(pins) == {
            "schema", "scope", "name", "old_sha256", "new_sha256"
        } and pins["schema"] == 1 and
            pins["scope"] == "R930_SYNTHETIC_SCM_ONLY" and
            pins["name"] == SERVICE, "R930_SERVICE_PIN_SCHEMA_CHANGED")
        self.service_sha = {
            "1.5.6": pins["old_sha256"].lower(),
            "1.5.7": pins["new_sha256"].lower(),
        }
        for version, name in (("1.5.6", "ScmFixture-1.5.6.exe"),
                              ("1.5.7", "ScmFixture-1.5.7.exe")):
            expected = self.service_sha[version]
            path = INPUT / name
            must(re.fullmatch("[0-9a-f]{64}", expected) is not None and
                 path.is_file() and sha(path) == expected,
                 "R930_SERVICE_SOURCE_SHA_CHANGED")
        self.runtime_state = root / "scm-restoration-state.json"
        self.inject_fail_inno = False
        self.inject_fail_scm = False
        self.fail_after_restored_receipt = False

    def _service_config(self) -> dict | None:
        found = scm_config()
        if found is None:
            return None
        must(found["type"] == 16 and found["start"] == 3 and
             found["object"].lower() in ("localsystem", "nt authority\\system"),
             "R930_SERVICE_CONFIG_NOT_LOCAL_SYSTEM_DEMAND_OWN_PROCESS")
        exact = found["image"].strip().strip('"')
        must(Path(exact).resolve() == BIN.resolve(),
             "R930_SERVICE_BINARY_IS_NOT_OWNED_FIXTURE_PATH")
        return found

    def quiesced(self) -> bool:
        state = scm_state()
        return state in (None, "STOPPED")

    def quiesce(self) -> None:
        state = scm_state()
        if state is None or state == "STOPPED":
            return
        must(state in ("RUNNING", "START_PENDING", "STOP_PENDING"),
             "R930_UNKNOWN_ACTIVE_SCM_STATE")
        if state != "STOP_PENDING":
            sc("stop", SERVICE, allow_fail=True)
        must(self._wait_state("STOPPED"), "R930_SCM_NOT_QUIESCED")

    def _wait_state(self, expected: str, *, seconds: float = 15) -> bool:
        for _ in range(int(seconds * 5)):
            if scm_state() == expected:
                return True
            time.sleep(.2)
        return False

    def _running(self, version: str) -> bool:
        if scm_state() != "RUNNING" or not self._service_config():
            return False
        if not BIN.is_file() or BIN.is_symlink() or sha(BIN) != self.service_sha[version]:
            return False
        if not MARKER.is_file() or MARKER.is_symlink():
            return False
        return MARKER.read_text("utf8").strip() == version

    def _register(self) -> None:
        if scm_state() is None:
            # SCM registration before restoring an uninstalled code slot is
            # required; service start is forbidden until BOTH slots return.
            sc("create", SERVICE, "binPath=", str(BIN), "start=", "demand",
               "obj=", "LocalSystem", "DisplayName=",
               "DIM R930 Isolated Universal SCM Fixture")
        must(self._service_config() is not None,
             "R930_SCM_NATIVE_IDENTITY_NOT_REGISTERED")

    def _delete(self) -> None:
        if scm_state() is None:
            return
        self.quiesce()
        sc("delete", SERVICE)
        must(self._wait_state_absent(), "R930_SCM_SERVICE_NOT_DELETED")

    def _wait_state_absent(self) -> bool:
        for _ in range(75):
            if scm_state() is None:
                return True
            time.sleep(.2)
        return False

    def _start(self, version: str) -> bool:
        must(self.quiesced() and self._service_config() is not None,
             "R930_SCM_START_IDENTITY_OR_STATE_INVALID")
        MARKER.unlink(missing_ok=True)
        started = sc("start", SERVICE, allow_fail=True)
        if started.returncode != 0:
            return False
        if not self._wait_state("RUNNING"):
            return False
        for _ in range(55):
            if self._running(version):
                return True
            if scm_state() != "RUNNING":
                return False
            time.sleep(.2)
        return False

    def snapshot(self) -> bytes:
        info = json.loads(super().snapshot().decode("utf8"))
        state = scm_state()
        must((info["version"] is None) == (state is None),
             "R930_INNO_SCM_PREIMAGE_IDENTITY_CONFLICT")
        if state is not None:
            must(self._service_config() is not None, "R930_SERVICE_CONFIG_INVALID")
            must(state in ("RUNNING", "STOPPED"), "R930_NATIVE_SNAPSHOT_PENDING")
            if state == "RUNNING":
                must(self._running(info["version"]),
                     "R930_SCM_RUNNING_CODE_NOT_EXPECTED")
        info["service_exists"] = state is not None
        info["service_running"] = state == "RUNNING"
        return (json.dumps(info, sort_keys=True, separators=(",", ":")) +
                "\n").encode("utf8")

    def apply(self, target_version: str, intent: dict) -> None:
        must(self.quiesced() and
             self._code_versions() == {target_version},
             "R930_NEW_MANAGED_CODE_NOT_QUIESCED_AND_PINNED")
        self.receipt_path.unlink(missing_ok=True)
        binary = self.setup["bad" if self.inject_fail_inno else target_version]
        bad_inno = self.inject_fail_inno
        self.inject_fail_inno = False
        exit_code = self._run(binary)
        must(self._native(target_version),
             "R930_INNO_POSTINSTALL_NATIVE_IDENTITY_CHANGED")
        if bad_inno:
            must(exit_code == 67, "R930_EXPECTED_INNO_FAULT_67_MISSING")
            raise EngineError("R930_NATIVE_INNO_POSTINSTALL_FAULT")
        must(exit_code == 0, "R930_NATIVE_INNO_SETUP_FAILED")
        self._register()
        if self.inject_fail_scm:
            self.inject_fail_scm = False
            must(not self._start(target_version),
                 "R930_BAD_SCM_BINARY_UNEXPECTEDLY_STARTED")
            raise EngineError("R930_NATIVE_SCM_START_FAULT")
        must(self._start(target_version), "R930_SCM_START_OR_HEALTH_FAILED")
        atomic_json(self.receipt_path, {
            "schema": 1, "status": "completed",
            "intent_sha256": intent_sha256(intent),
        })

    def completed(self, intent: dict) -> bytes | None:
        item = super().completed(intent)
        if item is None:
            return None
        must(self._running(intent["new"]),
             "R930_COMPLETION_RECEIPT_NATIVE_SCM_NOT_RUNNING")
        return item

    def restore(self, snapshot: bytes, intent: dict) -> None:
        try:
            doc = json.loads(snapshot.decode("utf8"))
        except (UnicodeError, ValueError) as ex:
            raise EngineError("R930_NATIVE_PREIMAGE_ENCODING_INVALID") from ex
        must(type(doc) is dict and set(doc) ==
             {"schema", "version", "service_exists", "service_running"} and
             doc["schema"] == 1 and doc["version"] == intent["old"] and
             type(doc["service_exists"]) is bool and
             type(doc["service_running"]) is bool and
             not (doc["service_running"] and not doc["service_exists"]),
             "R930_NATIVE_PREIMAGE_SCHEMA_INVALID")
        self.quiesce()
        # Must restore native Inno registration without launching old SCM first.
        inno_preimage = (json.dumps({
            "schema": 1, "version": doc["version"]
        }, sort_keys=True, separators=(",", ":")) + "\n").encode("utf8")
        if not doc["service_exists"]:
            self._delete()
        super().restore(inno_preimage, intent)
        if doc["service_exists"]:
            self._register()
        must((scm_state() is not None) == doc["service_exists"] and
             self.quiesced(), "R930_NATIVE_REGISTRATION_NOT_QUIESCED")
        atomic_json(self.runtime_state, {
            "schema": 1, "service_exists": doc["service_exists"],
            "should_run": doc["service_running"],
            "old_version": doc["version"],
        })

    def _previous_state(self) -> dict:
        must(self.runtime_state.is_file() and
             not self.runtime_state.is_symlink(),
             "R930_NATIVE_RESTORATION_PREIMAGE_MISSING")
        doc = json.loads(self.runtime_state.read_text("utf8"))
        must(type(doc) is dict and set(doc) ==
             {"schema", "service_exists", "should_run", "old_version"} and
             doc["schema"] == 1 and
             type(doc["service_exists"]) is bool and
             type(doc["should_run"]) is bool and
             not (doc["should_run"] and not doc["service_exists"]),
             "R930_RESTORATION_STATE_INVALID")
        return doc

    def resume_restored(self, old_version: str | None, intent: dict) -> None:
        state = self._previous_state()
        must(state["old_version"] == old_version and
             self._code_versions() == {old_version} and
             self._native(old_version), "R930_OLD_CODE_OR_INNO_NOT_RESTORED")
        if state["service_exists"]:
            must(self._service_config() is not None,
                 "R930_RESTORED_SCM_NOT_REGISTERED")
        if state["should_run"]:
            must(old_version is not None, "R930_OLD_VERSION_MISSING")
            if not self._running(old_version):
                must(self._start(old_version),
                     "R930_PREVIOUS_SERVICE_RESUME_FAILED")
        else:
            must(self.quiesced(), "R930_PREVIOUS_SERVICE_SHOULD_BE_STOPPED")
        self._bump_native_resume()
        atomic_json(self.receipt_path, {
            "schema": 1, "status": "restored",
            "intent_sha256": intent_sha256(intent),
        })
        if self.fail_after_restored_receipt:
            raise EngineError("R930_AFTER_NATIVE_RESTORED_PROCESS_BREAK")

    def restored(self, intent: dict) -> bytes | None:
        item = super().restored(intent)
        if item is None:
            return None
        state = self._previous_state()
        must(state["old_version"] == intent["old"] and
             state["service_exists"] == (scm_state() is not None) and
             (self._running(intent["old"]) if state["should_run"]
              else self.quiesced()), "R930_RESTORED_SCM_HEALTH_NOT_ACCEPTED")
        return item

    def unregister(self, intent: dict) -> None:
        must(self.quiesced(), "R930_NATIVE_UNINSTALL_NOT_QUIESCED")
        self.receipt_path.unlink(missing_ok=True)
        self._delete()
        super().unregister(intent)
        must(scm_state() is None and self._native(None),
             "R930_NATIVE_UNINSTALL_SCM_OR_INNO_STILL_PRESENT")

    def uninstall_completed(self, intent: dict) -> bytes | None:
        item = super().uninstall_completed(intent)
        if item is None:
            return None
        must(scm_state() is None and self._native(None),
             "R930_NATIVE_UNINSTALL_RECEIPT_SCM_REMAINED")
        return item


def bundle(root: Path, key: str, ver: str,
           scope: str, payload: bytes) -> tuple[Path, str]:
    folder = root/"packages"/key
    binary = folder/"payload"/"app"/(
        "FixtureService.exe" if scope == "code" else "OwnerCode.txt")
    binary.parent.mkdir(parents=True)
    binary.write_bytes(payload)
    doc = {
        "schema": 1, "product": "Direct Internet Method",
        "version": ver, "platform": PLATFORM,
        "files": [{"path": "app/"+binary.name, "bytes": len(payload),
                   "sha256": hash_bytes(payload), "mode": 0o644}],
    }
    manifest = folder/"manifest.json"
    manifest.write_text(json.dumps(doc, sort_keys=True) + "\n", "utf8")
    return folder, hash_bytes(manifest.read_bytes())


def packages(root: Path, ver: str, key: str, *, bad_service=False):
    if bad_service:
        svc = b"NOT_A_WINDOWS_SERVICE_BINARY_R930"
    else:
        name = ("ScmFixture-1.5.6.exe" if ver == "1.5.6"
                else "ScmFixture-1.5.7.exe")
        svc = (INPUT/name).read_bytes()
    return {"code": bundle(root, key+"-code", ver, "code", svc),
            "user": bundle(root, key+"-user", ver, "user",
                           ("SYNTHETIC_OWNER_MANAGED_CODE_"+key).encode())}


def universal(adapter: ScmInnoFixtureAdapter):
    return engine(adapter)


def replay() -> int:
    guest_guard(first=False)
    must(ROOT.is_dir() and not REPORT.exists(), "R930_REPLAY_ROOT_UNSAFE")
    adapter = ScmInnoFixtureAdapter(ROOT)
    tx = universal(adapter)
    result = tx.recover()
    print(json.dumps({
        "status": "R930_RECOVERY_IN_SEPARATE_PROCESS",
        "pid": os.getpid(), "version": result["version"],
        "resume_observations":
            adapter._metadata()["native_resume_observations"]
    }))
    return 0


def main() -> int:
    if sys.argv[1:] == ["--replay"]:
        return replay()
    guest_guard(first=True)
    must(scm_state() is None and not MARKER.parent.exists() and
         not REPORT.exists(), "R930_SCM_PRIOR_FIXTURE_PRESENT")
    ROOT.mkdir()
    adapter = ScmInnoFixtureAdapter(ROOT)
    stages = []
    try:
        tx = universal(adapter)
        tx.begin(packages(ROOT, "1.5.6", "old"))
        tx.activate()
        tx.commit()
        must(adapter._native("1.5.6") and
             adapter._running("1.5.6") and
             adapter._code_versions() == {"1.5.6"},
             "R930_156_NATIVE_SCM_INNO_NOT_COMMITTED")
        stages.append("ONE_CORE_REAL_INNO_HKLM_AND_SCM_156_STARTED")

        owner = ROOT/"user"/"data"/"settings.json"
        owner.parent.mkdir()
        owner.write_bytes(b"OWNER_SETTINGS_NEVER_DELETE_R930")
        owner_sha = sha(owner)

        adapter.inject_fail_inno = True
        tx.begin(packages(ROOT, "1.5.7", "inno-broken"))
        try:
            tx.activate()
        except EngineError as ex:
            must("R930_NATIVE_INNO_POSTINSTALL_FAULT" in str(ex),
                 "R930_UNEXPECTED_INNO_FAILURE_REASON")
        else:
            raise EngineError("R930_INNO_FAULT_NOT_INJECTED")
        must(adapter._native("1.5.7") and
             adapter.completed(tx._intent(tx._load())) is None,
             "R930_INNO_FAILURE_WAS_FALSLEY_ACCEPTED")
        universal(adapter).recover()
        must(adapter._native("1.5.6") and
             adapter._running("1.5.6") and
             adapter._code_versions() == {"1.5.6"},
             "R930_INNO_FAULT_ROLLBACK_INCOMPLETE")
        stages.append("INNO_EXIT67_ROLLBACK_OLD_INNO_SCM_BOTH_CODE_SCOPES")

        adapter.inject_fail_scm = True
        tx.begin(packages(ROOT, "1.5.7", "scm-broken", bad_service=True))
        try:
            tx.activate()
        except EngineError as ex:
            must("R930_NATIVE_SCM_START_FAULT" in str(ex),
                 "R930_UNEXPECTED_SCM_FAILURE_REASON")
        else:
            raise EngineError("R930_BAD_SCM_BINARY_SHOULD_FAIL")
        must(adapter._native("1.5.7") and
             adapter.completed(tx._intent(tx._load())) is None,
             "R930_SCM_FAILURE_WAS_FALSE_COMPLETED")
        universal(adapter).recover()
        must(adapter._native("1.5.6") and
             adapter._running("1.5.6") and
             adapter._code_versions() == {"1.5.6"},
             "R930_SCM_FAULT_ROLLBACK_INCOMPLETE")
        stages.append("SCM_START_FAILURE_ROLLBACK_OLD_INNO_SCM_BOTH_CODE_SCOPES")

        tx.begin(packages(ROOT, "1.5.7", "good"))
        tx.activate()
        tx.commit()
        must(adapter._native("1.5.7") and adapter._running("1.5.7") and
             adapter._code_versions() == {"1.5.7"},
             "R930_NATIVE_157_SCM_INNO_COMMIT_FAILED")
        stages.append("NATIVE_157_INNO_AND_SCM_HEALTHY_COMMITTED")

        tx.begin_uninstall()
        must(adapter.quiesced(), "R930_UNINSTALL_DID_NOT_STOP_NATIVE_SVC")
        tx.apply_uninstall()
        must(adapter._native(None) and scm_state() is None,
             "R930_NATIVE_UNINSTALL_INNO_SCM_NOT_REMOVED")
        adapter.fail_after_restored_receipt = True
        try:
            tx.abort_uninstall()
        except EngineError as ex:
            must("R930_AFTER_NATIVE_RESTORED_PROCESS_BREAK" in str(ex),
                 "R930_EXPECTED_RESTORATION_BREAK_WRONG")
        else:
            raise EngineError("R930_RESTORE_PROCESS_BREAK_MISSING")
        prior_resume = adapter._metadata()["native_resume_observations"]
        must(universal(adapter)._load()["phase"] ==
             "uninstall-restoring-native", "R930_RESTORED_JOURNAL_MISSING")
        p = subprocess.run([sys.executable, "--replay"],
                           capture_output=True, text=True, timeout=90)
        must(p.returncode == 0,
             "R930_REPLAY_OS_PROCESS_FAILED_"+p.stderr[-300:])
        child = json.loads(p.stdout.strip().splitlines()[-1])
        must(child["status"] == "R930_RECOVERY_IN_SEPARATE_PROCESS" and
             child["pid"] != os.getpid() and
             child["resume_observations"] == prior_resume and
             adapter._native("1.5.7") and adapter._running("1.5.7") and
             adapter._code_versions() == {"1.5.7"},
             "R930_PROCESS_REPLAY_DUPLICATED_SCM_START_OR_LOST_STATE")
        stages.append("SEPARATE_PROCESS_NATIVE_RESTORED_RECEIPT_NO_DOUBLE_START")

        tx.begin_uninstall()
        tx.apply_uninstall()
        tx.finish_uninstall()
        must(scm_state() is None and adapter._native(None) and
             adapter._code_versions() == {None} and
             sha(owner) == owner_sha,
             "R930_FINAL_UNINSTALL_OR_OWNER_DATA_FAILED")
        stages.append("SCM_INNO_NATIVE_UNINSTALL_BOTH_CODE_SCOPES_OWNER_PRESERVED")

        report = {
            "schema": 1,
            "status": "PASS_R930_SHARED_UNIVERSAL_NATIVE_SCM_INNO_GUEST",
            "stages": stages, "owner_sha256": owner_sha,
            "native_inno_hklm_observed": True,
            "native_scm_service_observed": True,
            "native_scm_identity": SERVICE,
            "separate_os_process_replay": True,
            "real_product_install_accepted": False,
            "publisher_authenticated": False,
            "protected_recovery_authority_accepted": False,
            "hard_reboot_accepted": False,
            "linux_root_polkit_accepted": False,
        }
        atomic_json(REPORT, report)
        print(json.dumps(report, sort_keys=True))
        return 0
    except BaseException as exc:
        report = {
            "schema": 1, "status": "FAIL_CLOSED_R930_SCM_INNO",
            "stages": stages, "error": str(exc),
            "real_product_install_accepted": False,
        }
        if OUTPUT.is_dir():
            atomic_json(REPORT, report)
        print(json.dumps(report, sort_keys=True), file=sys.stderr)
        return 3
    finally:
        # Cleanup only the single synthetic service. Preserve native failure
        # receipt for analysis; isolated Windows Sandbox destruction is final.
        try:
            adapter.quiesce()
            adapter._delete()
        except BaseException:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
