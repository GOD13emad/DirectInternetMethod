"""R982 disposable Windows VM: REAL Inno install failure through shared R981 broker.

This is NOT a production privileged service or installer. The native adapter
here is test-only, cannot be invoked on a physical host, and the two managed
journal code scopes are synthetic. It intentionally reuses the existing single
universal coordinator and replay ledger, with no native commands from input.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch
if os.name == "nt":
    import winreg

# Executed as a reviewed VM file, not an installed pip package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from installer_engine.broker_replay import BrokerReplayFixtureLedger
from installer_engine.engine import EngineError, atomic_json, require
from installer_engine.native_receipt import intent_sha256
from installer_engine.native_plan import NativePlan
from installer_engine.universal_install import UniversalFixtureInstaller
from tests.test_engine_universal_install import UniversalInstallCrossPlatform

APP_ID = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}_is1"
SERVICE = "DirectInternetMethodSvc"
OLD_SETUP_SHA = "FFB9A2AE19C2E89338EE12EE8DA133F5A16DBF4DCF961678C33D77D0C3843133"
OLD_GUI_SHA = "BE9C78C0B5C007B4A46480D423079C219006B730D9589279AA466B0F14BCF00F"
OLD_SVC_SHA = "2AE7EA11A94BFA3187BC7CDF63A37CB5CD5B55C313C3966330FD280ECC9ECE41"
STATUS = "R982_REAL_INNO_FAILED_OLD_RESTORED_VIA_COMMON_BROKER"
REPORT_NAME = "R982_REAL_NATIVE_BROKER_VM_RESULT.json"


def _guard() -> tuple[Path, Path, str]:
    # Do not construct mutable paths or load config until this exact host gate.
    expected = os.environ.get("GITHUB_SHA", "")
    required = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_REPOSITORY": "GOD13emad/DirectInternetMethod",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/feature/universal-install-engine",
        "R980_EXPECTED_SHA": expected,
        "R982_EXPECTED_SHA": expected,
    }
    if (os.name != "nt" or len(expected) != 40
            or any(c not in "0123456789abcdef" for c in expected)
            or any(os.environ.get(k) != v for k, v in required.items())
            or not os.environ.get("GITHUB_WORKSPACE")
            or not os.environ.get("RUNNER_TEMP")):
        raise RuntimeError("R982_DISPOSABLE_REVIEWED_VM_ONLY")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    if (subprocess.run(["git", "-C", str(workspace), "rev-parse", "HEAD"],
                       capture_output=True, text=True, check=True).stdout.strip()
            != expected or not bool(ctypes.windll.shell32.IsUserAnAdmin())):
        raise RuntimeError("R982_DISPOSABLE_REVIEWED_VM_ONLY")
    qa = temp / "DIM_R980_REAL_POSTFAIL"
    if not qa.is_dir() or qa.is_symlink():
        raise RuntimeError("R982_DISPOSABLE_REVIEWED_VM_ONLY")
    return workspace, qa, expected


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def _pin(path: Path, sha: str) -> None:
    if not path.is_file() or path.is_symlink() or _sha(path) != sha:
        raise EngineError("R982_RECOVERY_ASSET_SHA_MISMATCH")


def _version() -> str | None:
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, APP_ID, 0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            return winreg.QueryValueEx(key, "DisplayVersion")[0]
    except FileNotFoundError:
        return None


def _service_state() -> str:
    result = subprocess.run(["sc.exe", "query", SERVICE], capture_output=True,
                            text=True, timeout=25)
    if result.returncode != 0:
        return "MISSING"
    output = result.stdout.upper()
    if "RUNNING" in output:
        return "RUNNING"
    if "STOPPED" in output:
        return "STOPPED"
    return "OTHER"


def _wait_state(state: str, *, seconds: float = 60) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if _service_state() == state:
            return
        time.sleep(1)
    raise EngineError("R982_REAL_NATIVE_SERVICE_STATE_" + state + "_NOT_REACHED")


def _stop_service() -> None:
    if _service_state() == "STOPPED":
        return
    subprocess.run(["sc.exe", "stop", SERVICE],
                   capture_output=True, text=True, timeout=30)
    _wait_state("STOPPED")


def _start_service() -> None:
    if _service_state() != "RUNNING":
        subprocess.run(["sc.exe", "start", SERVICE], capture_output=True,
                       text=True, timeout=30)
    _wait_state("RUNNING")


def _setup(path: Path) -> int:
    result = subprocess.run([
        str(path), "/VERYSILENT", "/SUPPRESSMSGBOXES",
        "/NORESTART", "/NORESTARTAPPLICATIONS", "/CLOSEAPPLICATIONS", "/SP-",
    ], timeout=600)
    return int(result.returncode)


class RealInnoVmAdapter:
    """No added native authority. Only pinned test-VM SCM/Inno callbacks."""

    def __init__(self, qa: Path, *, new_gui: str, new_service: str,
                 failed_setup_sha: str, recovery_observation: dict | None = None):
        self.qa = qa
        self.old_setup = qa / "DirectInternetMethod_1.5.4_Windows_Setup.exe"
        if os.environ.get("R992_PROTECTED_RECOVERY_MEDIA") == "true":
            require(not self.old_setup.exists() and not self.old_setup.is_symlink(),
                    "R992_DUPLICATE_UNPROTECTED_PRIOR_MEDIA")
            self.old_setup = (Path(os.environ["ProgramFiles"]) /
                              "DirectInternetMethod" / "Privileged" /
                              "UpdateTransactions" /
                              "DirectInternetMethod-recovery-1.5.4.exe")
        self.failed_setup = qa / "R980_FAILED_PRODUCT_SETUP.exe"
        self.gui = Path(os.environ["LOCALAPPDATA"]) / "Programs" / "DirectInternetMethod" / "app" / "DirectInternetMethod.exe"
        self.service = Path(os.environ["ProgramFiles"]) / "DirectInternetMethod" / "Privileged" / "app" / "DirectInternetMethod.Service.exe"
        self.new_gui = new_gui
        self.new_service = new_service
        self.failed_setup_sha = failed_setup_sha
        self.failed_exit = None
        self.after_failure = None
        self.restored_receipt = None
        self.old_setup_run = False
        # Exact public old Setup is independently pinned at two read boundaries.
        _pin(self.old_setup, OLD_SETUP_SHA)
        _pin(self.failed_setup, failed_setup_sha)
        if recovery_observation is None:
            require(_version() == "1.5.4" and
                    _sha(self.gui) == OLD_GUI_SHA and
                    _sha(self.service) == OLD_SVC_SHA and
                    _service_state() == "RUNNING",
                    "R982_NATIVE_BASELINE_IDENTITY_INVALID")
        else:
            # The recovery process never executed the failed installation.
            # Its live native observations must match the durable failure
            # observation checked against the existing transaction intent.
            require(_version() == "1.5.7" and
                    _sha(self.gui) == self.new_gui and
                    _sha(self.service) == self.new_service,
                    "R983_NATIVE_STATE_CHANGED_AFTER_CHILD_EXIT")
            self.failed_exit = recovery_observation["installer_exit_code"]
            self.after_failure = {
                key: recovery_observation[key] for key in (
                    "registered_version", "gui_sha256", "service_sha256",
                    "installer_exit_code")
            }

    def snapshot(self) -> bytes:
        # Bounded metadata preimage, NOT complete SCM/ACL/Inno OS preimage.
        doc = {"schema": 1, "version": _version(), "gui": _sha(self.gui),
               "service": _sha(self.service), "old_setup": OLD_SETUP_SHA}
        return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()

    def observed_version(self) -> str | None:
        return _version()

    def quiesce(self) -> None:
        _stop_service()

    def quiesced(self) -> bool:
        return _service_state() == "STOPPED"

    def apply(self, target_version: str, intent: dict) -> None:
        require(target_version == "1.5.7" and
                intent["old"] == "1.5.4" and
                intent["operation"] == "upgrade" and
                intent["new"] == target_version,
                "R982_NATIVE_APPLY_TARGET_INVALID")
        _pin(self.old_setup, OLD_SETUP_SHA)
        _pin(self.failed_setup, self.failed_setup_sha)
        self.failed_exit = _setup(self.failed_setup)
        self.after_failure = {
            "registered_version": _version(),
            "gui_sha256": _sha(self.gui),
            "service_sha256": _sha(self.service),
            "installer_exit_code": self.failed_exit,
        }
        require(self.failed_exit == 67 and
                self.after_failure["registered_version"] == "1.5.7" and
                self.after_failure["gui_sha256"] == self.new_gui and
                self.after_failure["service_sha256"] == self.new_service,
                "R982_REAL_INNO_POSTINSTALL_FAILURE_NOT_REPRODUCED")
        # The production 1.5.7 is installed partially despite the error.
        raise EngineError("R982_EXPECTED_INNO_POSTINSTALL_FAILURE")

    def completed(self, intent: dict) -> bytes | None:
        # A raised Inno postinstall exception did NOT issue ssDone.
        return None

    def restore(self, snapshot: bytes, intent: dict) -> None:
        doc = json.loads(snapshot)
        require(doc == {"schema": 1, "version": "1.5.4",
                        "gui": OLD_GUI_SHA, "service": OLD_SVC_SHA,
                        "old_setup": OLD_SETUP_SHA} and
                intent["old"] == "1.5.4" and
                self.after_failure is not None,
                "R982_NATIVE_RESTORE_PREIMAGE_DRIFT")
        _pin(self.old_setup, OLD_SETUP_SHA)
        if _setup(self.old_setup) != 0:
            raise EngineError("R982_NATIVE_PINNED_OLD_SETUP_RESTORE_FAILED")
        self.old_setup_run = True
        # Keep native old service quiescent while the ONE shared engine
        # restores both simulated code scopes; resume happens afterward.
        _stop_service()
        require(_version() == "1.5.4" and
                _sha(self.gui) == OLD_GUI_SHA and
                _sha(self.service) == OLD_SVC_SHA,
                "R982_NATIVE_OLD_BINARY_RESTORE_NOT_VERIFIED")

    def resume_restored(self, old_version: str | None, intent: dict) -> None:
        require(old_version == "1.5.4" and self.old_setup_run,
                "R982_NATIVE_PREIMAGE_NOT_REINSTATED")
        _start_service()
        require(_version() == "1.5.4" and
                _sha(self.gui) == OLD_GUI_SHA and
                _sha(self.service) == OLD_SVC_SHA,
                "R982_NATIVE_RESTORED_SERVICE_OR_BYTES_DRIFT")
        self.restored_receipt = json.dumps(
            {"schema": 1, "status": "restored",
             "intent_sha256": intent_sha256(intent)},
            sort_keys=True, separators=(",", ":")
        ).encode()

    def restored(self, intent: dict) -> bytes | None:
        # This receipt is synthetic, minted by the guest QA adapter.
        # It is NOT publisher-authenticated or independently OS protected.
        return self.restored_receipt

    def unregister(self, intent: dict) -> None:
        raise EngineError("R982_UNINSTALL_NOT_SUPPORTED")

    def uninstall_completed(self, intent: dict) -> bytes | None:
        return None


def _validate_crash_observation(observation: dict, identity: str,
                                cfg: dict) -> dict:
    """Test-only durable observation; this is NOT an OS-authenticated receipt."""
    expected = {
        "schema": 1, "intent_sha256": identity,
        "failed_setup_sha": cfg["failed_setup_sha"],
        "registered_version": "1.5.7",
        "gui_sha256": cfg["new_gui"],
        "service_sha256": cfg["new_service"],
        "installer_exit_code": 67,
    }
    require(type(observation) is dict and
            type(observation.get("schema")) is int and
            type(observation.get("installer_exit_code")) is int and
            observation == expected, "R983_CRASH_OBSERVATION_INVALID")
    return observation


class CrashAfterApplyAdapter(RealInnoVmAdapter):
    """Exit this QA child without unwinding the broker's transaction stack."""

    def __init__(self, qa: Path, base: Path, **kwargs):
        super().__init__(qa, **kwargs)
        self.base = base

    def apply(self, target_version: str, intent: dict) -> None:
        try:
            super().apply(target_version, intent)
        except EngineError as exc:
            if str(exc) != "R982_EXPECTED_INNO_POSTINSTALL_FAILURE":
                raise
            observation = dict(self.after_failure, schema=1,
                               intent_sha256=intent_sha256(intent),
                               failed_setup_sha=self.failed_setup_sha)
            _validate_crash_observation(observation, intent_sha256(intent), {
                "new_gui": self.new_gui, "new_service": self.new_service,
                "failed_setup_sha": self.failed_setup_sha,
            })
            atomic_json(self.base / "r983-native-failure.json", observation)
            # Deliberately bypass Python exception handlers and finally
            # blocks, only after the real installer has already exited.
            os._exit(79)
        raise EngineError("R983_CHILD_NATIVE_FAILURE_NOT_OBSERVED")


def _read_crash_dispatch(qa: Path, name: str, expected_pin: str | None = None):
    require(name.startswith("dim-universal-") and Path(name).name == name,
            "R983_CHILD_BASE_INVALID")
    base = qa / name
    require(base.is_dir() and not base.is_symlink() and
            base.resolve().parent == qa.resolve(), "R983_CHILD_BASE_INVALID")
    inp = base / "r983-dispatch.json"
    require(inp.is_file() and not inp.is_symlink() and
            0 < inp.stat().st_size <= 65536, "R983_CHILD_DISPATCH_MISSING")
    raw = inp.read_bytes()
    if expected_pin is not None:
        require(hashlib.sha256(raw).hexdigest() == expected_pin,
                "R986_DISPATCH_PIN_MISMATCH")
    payload = json.loads(raw)
    require(type(payload) is dict and set(payload) ==
            {"platform", "product", "version", "scopes", "pb", "pin",
             "rb", "intent", "sources"} and
            payload["platform"] == "windows-x86_64" and
            payload["product"] == "Direct Internet Method" and
            payload["version"] == "1.5.7" and
            set(payload["sources"]) == {"protected", "user"},
            "R983_CHILD_PLAN_INVALID")
    sources = {}
    for scope, row in payload["sources"].items():
        folder, digest = row
        require(folder == f"bundle-{scope}-1.5.7",
                "R983_CHILD_SOURCE_NAME_DRIFT")
        sources[scope] = (base / folder, digest)
    plan = NativePlan(payload["product"], payload["version"],
                      payload["platform"],
                      "PINNED_CODE_LAYOUT_REQUIRES_TRUSTED_NATIVE_ADAPTER",
                      tuple((name, manifest) for name, manifest in payload["scopes"]))
    pb, rb = bytes.fromhex(payload["pb"]), bytes.fromhex(payload["rb"])
    require(hashlib.sha256(pb).hexdigest() == payload["pin"],
            "R986_DISPATCH_PIN_MISMATCH")
    return base, plan, pb, payload["pin"], rb, payload["intent"], sources


def _run_crash_child(qa: Path, cfg: dict, name: str) -> int:
    base, plan, pb, pin, rb, intent, sources = _read_crash_dispatch(qa, name)
    adapter = CrashAfterApplyAdapter(qa, base,
        new_gui=cfg["new_gui"], new_service=cfg["new_service"],
        failed_setup_sha=cfg["failed_setup_sha"])
    core = UniversalFixtureInstaller(base / "managed-journal", plan.platform,
        {"protected": base / "managed-protected", "user": base / "managed-user"},
        adapter)
    ledger = BrokerReplayFixtureLedger(base / "r982-ledger", plan.platform)
    core.execute_broker_bound(ledger, plan, pb, pin, rb, intent, sources)
    raise EngineError("R983_CHILD_DID_NOT_EXIT_AT_NATIVE_FAILURE")


def _run_recovery_worker(qa: Path, cfg: dict, name: str,
                         dispatch_pin: str) -> int:
    # A fresh interpreter reconstructs every transaction argument from disk.
    # The parent pin is fixture integrity only, not OS/publisher authority.
    base, plan, pb, pin, rb, intent, _ = _read_crash_dispatch(
        qa, name, dispatch_pin)
    report = base / "r986-recovery.json"
    require(not report.exists() and not report.is_symlink(),
            "R986_RECOVERY_WORKER_REPLAY_DENIED")
    observation_path = base / "r983-native-failure.json"
    require(observation_path.is_file() and not observation_path.is_symlink() and
            0 < observation_path.stat().st_size <= 65536,
            "R983_CRASH_OBSERVATION_MISSING")
    observation = _validate_crash_observation(
        json.loads(observation_path.read_text(encoding="utf-8")),
        intent_sha256(intent), cfg)
    recovery = RealInnoVmAdapter(qa, new_gui=cfg["new_gui"],
                                 new_service=cfg["new_service"],
                                 failed_setup_sha=cfg["failed_setup_sha"],
                                 recovery_observation=observation)
    roots = {"protected": base / "managed-protected", "user": base / "managed-user"}
    reopened = UniversalFixtureInstaller(base / "managed-journal", plan.platform,
                                        roots, recovery)
    ledger = BrokerReplayFixtureLedger(base / "r982-ledger", plan.platform)
    pending = reopened._load()
    require(pending["phase"] == "activated" and reopened._intent(pending) == intent and
            ledger.inspect_fixture()["active_phase"] == "applying",
            "R983_PERSISTED_INTENT_DRIFT")
    require(reopened._native_complete(pending) is False,
            "R983_UNEXPECTED_NATIVE_COMPLETION_RECEIPT")
    result = reopened.recover_broker_bound(ledger, plan, pb, pin, rb)
    require(result["version"] == "1.5.4" and
            recovery.old_setup_run and recovery.failed_exit == 67 and
            not reopened.journal.exists() and
            ledger.inspect_fixture()["active_phase"] is None and
            ledger.inspect_fixture()["used_ids"] == 1,
            "R983_RECOVERY_NOT_FINAL")
    atomic_json(report, {"schema": 1, "worker_pid": os.getpid(),
                         "dispatch_sha256": dispatch_pin,
                         "intent_sha256": intent_sha256(intent),
                         "old_setup_run": True, "after_failure": recovery.after_failure})
    print("R986_FRESH_RECOVERY_PROCESS_CONFIRMED")
    return 0



def _run_os_scheduled_recovery(workspace: Path, qa: Path, base: Path,
                               dispatch_pin: str, source: str) -> dict:
    """One-shot original-user Windows scheduler VM probe, NOT a production broker.

    Do not run native Setup as SYSTEM: its user shell folders differ from the
    actual installed GUI owner. S4U preserves the original runner SID without
    storing a password; it cannot use network resources or encrypted files.
    """
    require(os.name == "nt" and
            os.environ.get("R992_PROTECTED_RECOVERY_MEDIA") == "true" and
            os.environ.get("R984_NATIVE_PREIMAGE") == "true" and
            os.environ.get("R983_CRASH_RECOVERY") == "true" and
            os.environ.get("GITHUB_SHA") == source and
            base.resolve().parent == qa.resolve(),
            "R993_REQUIRES_REVIEWED_R992_NATIVE_VM")
    from csv import reader as csv_reader
    from re import fullmatch
    who = subprocess.run(["whoami.exe", "/user", "/fo", "csv", "/nh"],
                         capture_output=True, text=True, check=True, timeout=15)
    identity = list(csv_reader(who.stdout.strip().splitlines()))
    require(len(identity) == 1 and len(identity[0]) == 2 and
            bool(fullmatch(r"S-1-5-21-(?:\d+-){3}\d+", identity[0][1])),
            "R993_EXPECTED_OWNER_SID_MISSING")
    owner, owner_sid = identity[0]
    runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    protected = Path(os.environ["ProgramFiles"]) / "DirectInternetMethod" / "Privileged" / "UpdateTransactions"
    require(protected.is_dir() and not protected.is_symlink() and
            protected.resolve() == protected and
            (protected / "DirectInternetMethod-recovery-1.5.4.exe").is_file(),
            "R993_PROTECTED_RECOVERY_SOURCE_REQUIRED")
    launcher = workspace / "tests" / "r993_windows_os_scheduled_recovery_vm.ps1"
    cfg = protected / "R993RecoveryConfig.json"
    task_script = protected / "R993ProtectedRecoveryHarness.ps1"
    receipt = base / "r993-system-task-receipt.json"
    require(launcher.is_file() and not launcher.is_symlink() and
            not cfg.exists() and not cfg.is_symlink() and
            not task_script.exists() and not task_script.is_symlink() and
            not receipt.exists() and not receipt.is_symlink(),
            "R993_FRESH_SCHEDULED_SLOT_REQUIRED")
    task_name = "DIMR993VM-" + source[:12]
    atomic_json(cfg, {
        "schema": 1, "source": source,
        "name": base.name, "dispatchPin": dispatch_pin,
        "scriptSha": _sha(launcher).lower(),
        "pythonScriptSha": _sha(Path(__file__)).lower(),
        "taskName": task_name, "ownerSid": owner_sid, "ownerName": owner,
        "workspace": str(workspace), "runnerTemp": str(runner),
        "python": sys.executable, "localAppData": os.environ["LOCALAPPDATA"],
    })
    cmd = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(launcher)]
    def task_call(mode: str, timeout: float = 55) -> subprocess.CompletedProcess:
        return subprocess.run(cmd + ["-Mode", mode, "-Config", str(cfg)],
                              cwd=workspace, text=True, capture_output=True,
                              timeout=timeout)
    success = False
    try:
        registration = task_call("Register", 120)
        require(registration.returncode == 0 and
                "R993_TASK_CREATED" in registration.stdout,
                "R993_TASK_REGISTRATION_FAILED:" +
                registration.stderr[-1200:])
        deadline = time.monotonic() + 540
        result = None
        while time.monotonic() < deadline:
            if receipt.is_file() and not receipt.is_symlink():
                status = task_call("Inspect")
                if (status.returncode == 0 and
                        "R993_TASK_STATUS" in status.stdout):
                    lines = [line for line in status.stdout.splitlines()
                             if line.startswith("{") and "lastTaskResult" in line]
                    if len(lines) == 1:
                        info = json.loads(lines[0])
                        if info["lastTaskResult"] == 0:
                            result = info
                            break
            time.sleep(1)
        require(result is not None, "R993_OS_TIMED_TASK_DID_NOT_RECOVER")
        require(result["identity"] == owner_sid and
                result["logonType"] == "S4U" and
                result["runLevel"] == "Highest",
                "R993_TASK_PRINCIPAL_DRIFT")
        require(receipt.is_file() and not receipt.is_symlink() and
                0 < receipt.stat().st_size <= 8192,
                "R993_TASK_RECEIPT_MISSING")
        observed = json.loads(receipt.read_text(encoding="utf-8"))
        require(type(observed) is dict and
                set(observed) == {"schema", "source", "taskName", "sid",
                                  "launcherPid", "workerExit", "dispatchPin",
                                  "action"} and
                observed["schema"] == 1 and
                observed["source"] == source and
                observed["taskName"] == task_name and
                observed["sid"] == owner_sid and
                observed["sid"] != "S-1-5-18" and
                type(observed["launcherPid"]) is int and
                observed["launcherPid"] > 0 and
                observed["launcherPid"] != os.getpid() and
                observed["workerExit"] == 0 and
                observed["dispatchPin"] == dispatch_pin and
                observed["action"] == "R986_COMMON_RECOVER_BY_OS_TASK_S4U",
                "R993_OS_TASK_NOT_SAME_AS_OBSERVER")
        success = True
        print("R993_SCHEDULED_OS_RECEIPT_VERIFIED")
        return observed
    except Exception as exc:
        # Always preserve the root failure even if a cleanup guard also fails.
        print("R993_ORIGINAL_VM_FAILURE=" + str(exc), file=sys.stderr)
        raise
    finally:
        # No orphaned task on the runner. Never silently remove a task with
        # a different SID or action to conceal a failed registration.
        cleanup = task_call("Remove", 55)
        if (cleanup.returncode != 0 or
                "R993_TASK_OWNED_CLEANUP_PASS" not in cleanup.stdout or
                cfg.exists() or task_script.exists()):
            print("R993_TASK_CLEANUP_FAILED:" + cleanup.stderr[-1200:],
                  file=sys.stderr)
            raise EngineError("R993_TASK_CLEANUP_FAILED")


def _recover_after_child_exit(workspace: Path, qa: Path, cfg: dict,
                              fixture, plan, pb, pin, rb, intent,
                              sources, ledger):
    base = fixture.base
    require(base.resolve().parent == qa.resolve(), "R983_CHILD_BASE_INVALID")
    dispatch = base / "r983-dispatch.json"
    atomic_json(dispatch, {
        "platform": plan.platform, "product": plan.product,
        "version": plan.version, "scopes": list(plan.scopes),
        "pb": pb.hex(), "pin": pin, "rb": rb.hex(), "intent": intent,
        "sources": {name: [folder.name, digest]
                    for name, (folder, digest) in sources.items()},
    })
    dispatch_pin = hashlib.sha256(dispatch.read_bytes()).hexdigest()
    child = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "--r983-child", base.name],
        cwd=workspace, timeout=720)
    require(child.returncode == 79, "R983_CHILD_DID_NOT_EXIT_AT_NATIVE_FAILURE")
    # Validate dispatch and state before invoking the separate worker. The
    # parent does not call restore, resume_restored or recover_broker_bound.
    _read_crash_dispatch(qa, base.name, dispatch_pin)
    pending = fixture.core._load()
    require(pending["phase"] == "activated" and
            fixture.core._intent(pending) == intent and
            ledger.inspect_fixture()["active_phase"] == "applying",
            "R983_PERSISTED_INTENT_DRIFT")
    command = [sys.executable, str(Path(__file__).resolve()), "--r986-recover",
               base.name, dispatch_pin]
    task_evidence = None
    if os.environ.get("R993_OS_SCHEDULED_RECOVERY") == "true":
        task_evidence = _run_os_scheduled_recovery(
            workspace, qa, base, dispatch_pin, os.environ["GITHUB_SHA"])
    else:
        worker = subprocess.run(command, cwd=workspace, timeout=720)
        require(worker.returncode == 0, "R986_RECOVERY_WORKER_FAILED")
    report = base / "r986-recovery.json"
    require(report.is_file() and not report.is_symlink() and
            0 < report.stat().st_size <= 65536, "R986_RECOVERY_REPORT_MISSING")
    evidence = json.loads(report.read_text(encoding="utf-8"))
    require(type(evidence) is dict and set(evidence) ==
            {"schema", "worker_pid", "dispatch_sha256", "intent_sha256",
             "old_setup_run", "after_failure"} and
            type(evidence["schema"]) is int and evidence["schema"] == 1 and
            type(evidence["worker_pid"]) is int and evidence["worker_pid"] > 0 and
            evidence["worker_pid"] != os.getpid() and
            evidence["dispatch_sha256"] == dispatch_pin and
            evidence["intent_sha256"] == intent_sha256(intent) and
            evidence["old_setup_run"] is True,
            "R986_RECOVERY_REPORT_INVALID")
    expected = _validate_crash_observation(
        json.loads((base / "r983-native-failure.json").read_text(encoding="utf-8")),
        intent_sha256(intent), cfg)
    require(evidence["after_failure"] == {k: expected[k] for k in
            ("registered_version", "gui_sha256", "service_sha256", "installer_exit_code")},
            "R986_RECOVERY_REPORT_OBSERVATION_DRIFT")
    # Independently confirm tombstone, code state and native postflight in
    # main. A second recovery request must fail without repeating Inno.
    replay = subprocess.run(command, cwd=workspace, timeout=30,
                            capture_output=True, text=True)
    require(replay.returncode == 31 and
            "R986_RECOVERY_WORKER_REPLAY_DENIED" in replay.stderr,
            "R986_RECOVERY_REPLAY_NOT_DENIED")
    require(not fixture.core.journal.exists() and
            ledger.inspect_fixture()["active_phase"] is None and
            ledger.inspect_fixture()["used_ids"] == 1,
            "R983_RECOVERY_NOT_FINAL")
    if task_evidence is not None:
        evidence["r993_task"] = task_evidence
    print("R983_REAL_NATIVE_CHILD_EXIT_RESTORED")
    return evidence


def main() -> int:
    workspace, qa, source = _guard()
    report = qa / REPORT_NAME
    if report.exists() or report.is_symlink():
        raise EngineError("R982_RECOVERY_REPORT_REPLAY_REFUSED")
    build = json.loads((Path(os.environ["RUNNER_TEMP"]) /
                        "DIM_R846_NATIVE" / "BUILD_R846.json").read_text())
    config_file = qa / "R982_RECOVERY_INPUTS.json"
    if config_file.is_symlink() or not config_file.is_file():
        raise EngineError("R982_RECOVERY_INPUTS_NOT_PINNED")
    cfg = json.loads(config_file.read_text())
    require(set(cfg) == {"source", "new_gui", "new_service", "failed_setup_sha"}
            and cfg["source"] == source and build["head"] == source and
            cfg["new_gui"] == build["guiSha"] and
            cfg["new_service"] == build["serviceSha"] and
            all(isinstance(cfg[x], str) and len(cfg[x]) == 64 and
                all(c in "0123456789ABCDEF" for c in cfg[x])
                for x in ("new_gui", "new_service", "failed_setup_sha")),
            "R982_NATIVE_CANDIDATE_PINS_DRIFT")
    crash_mode = os.environ.get("R983_CRASH_RECOVERY", "false")
    require(crash_mode in ("true", "false"), "R983_CRASH_MODE_INVALID")
    media_mode = os.environ.get("R992_PROTECTED_RECOVERY_MEDIA", "false")
    require(media_mode in ("true", "false", ""), "R992_MEDIA_MODE_INVALID")
    require(media_mode != "true" or
            (crash_mode == "true" and os.environ.get("R984_NATIVE_PREIMAGE") == "true"),
            "R992_REQUIRES_REVIEWED_R983_R984_NATIVE_MODE")
    scheduler_mode = os.environ.get("R993_OS_SCHEDULED_RECOVERY", "false")
    require(scheduler_mode in ("true", "false", ""), "R993_MODE_INVALID")
    require(scheduler_mode != "true" or
            (media_mode == "true" and crash_mode == "true"),
            "R993_REQUIRES_R992_PROTECTED_MEDIA")
    if len(sys.argv) != 1:
        require(crash_mode == "true", "R983_CHILD_MODE_DENIED")
        if len(sys.argv) == 3 and sys.argv[1] == "--r983-child":
            return _run_crash_child(qa, cfg, sys.argv[2])
        if len(sys.argv) == 4 and sys.argv[1] == "--r986-recover":
            return _run_recovery_worker(qa, cfg, sys.argv[2], sys.argv[3])
        raise EngineError("R983_CHILD_MODE_DENIED")
    adapter = RealInnoVmAdapter(
        qa, new_gui=cfg["new_gui"],
        new_service=cfg["new_service"],
        failed_setup_sha=cfg["failed_setup_sha"])
    # Disposable code scopes are synthetic. The REAL native callbacks above
    # are used only by the already accepted R981 single-writer broker.
    fixture = UniversalInstallCrossPlatform(
        "test_policy_bound_request_survives_real_coordinator_journal")
    if crash_mode == "true":
        # Child paths are restricted to one disposable, existing QA root.
        with patch.object(tempfile, "tempdir", str(qa)):
            fixture.setUp()
    else:
        fixture.setUp()
    try:
        fixture.cycle("1.5.4")
        require(isinstance(fixture.core, UniversalFixtureInstaller),
                "R982_SHARED_TRANSACTION_ENGINE_REQUIRED")
        fixture.adapter = adapter
        fixture.core.adapter = adapter
        fixture.adapter.check_code_restored = lambda old: set(fixture.state().values()) == {old}
        plan, pb, pin, rb, intent, sources = fixture.broker_bound_install_inputs()
        native_sha = hashlib.sha256(adapter.snapshot()).hexdigest()
        intent = dict(intent, old="1.5.4", operation="upgrade",
                      preimage_sha256=native_sha)
        request = json.loads(rb)
        request["operation"] = "upgrade"
        rb = json.dumps(request, sort_keys=True).encode()
        policy = json.loads(pb)
        policy["operation"] = "upgrade"
        policy["request_sha256"] = hashlib.sha256(rb).hexdigest()
        pb = json.dumps(policy, sort_keys=True).encode()
        pin = hashlib.sha256(pb).hexdigest()
        ledger = BrokerReplayFixtureLedger(fixture.base / "r982-ledger",
                                           fixture.platform)
        fail_closed = False
        recovery_evidence = None
        if crash_mode == "true":
            recovery_evidence = _recover_after_child_exit(
                workspace, qa, cfg, fixture, plan, pb, pin, rb, intent,
                sources, ledger)
            fail_closed = True
        else:
            try:
                fixture.core.execute_broker_bound(
                    ledger, plan, pb, pin, rb, intent, sources)
            except EngineError as exc:
                if str(exc) == "UNIVERSAL_BROKER_NATIVE_FAILURE_AUTO_ABORTED_FIXTURE_ONLY":
                    fail_closed = True
                else:
                    raise
        after_failure = (recovery_evidence["after_failure"] if recovery_evidence
                         else adapter.after_failure)
        old_setup_run = (recovery_evidence["old_setup_run"] if recovery_evidence
                         else adapter.old_setup_run)
        require(fail_closed and old_setup_run and
                after_failure is not None and
                after_failure["installer_exit_code"] == 67 and
                _service_state() == "RUNNING" and
                _version() == "1.5.4" and
                _sha(adapter.gui) == OLD_GUI_SHA and
                _sha(adapter.service) == OLD_SVC_SHA and
                set(fixture.state().values()) == {"1.5.4"} and
                not fixture.core.journal.exists() and
                ledger.inspect_fixture()["used_ids"] == 1 and
                ledger.inspect_fixture()["active_phase"] is None,
                "R982_COMMON_BROKER_NATIVE_COMPENSATION_INCOMPLETE")
        data = {
            "schema": 1, "status": STATUS, "source": source,
            "real_product_failed_setup_exit": after_failure["installer_exit_code"],
            "after_failure": after_failure,
            "old_restore_setup_sha256": OLD_SETUP_SHA,
            "r992_protected_recovery_media": media_mode == "true",
            "old_restored_version": _version(),
            "old_restored_gui_sha256": _sha(adapter.gui),
            "old_restored_service_sha256": _sha(adapter.service),
            "service_running": _service_state() == "RUNNING",
            "common_broker_replay_tombstoned": True,
            "common_code_scopes": "SYNTHETIC_ONLY",
            "real_inno_native_restore_invoked_by_common_fixture": True,
            "publisher_authenticated": False,
            "native_production_broker_accepted": False,
            "native_full_preimage_accepted": False,
            "powercut_accepted": False,
            "physical_host_tested": False,
        }
        if crash_mode == "true":
            data["r983_child_exit"] = 79
            data["r983_reopened_common_broker_recovered"] = True
            data["r983_crash_scope"] = "AFTER_REAL_INNO_EXIT_BEFORE_COMPENSATION"
            data["r983_os_service_supervisor_accepted"] = False
            data["r983_reboot_accepted"] = False
            data["r986_fresh_recovery_process"] = True
            data["r986_recovery_worker_pid"] = recovery_evidence["worker_pid"]
            data["r986_observer_pid"] = os.getpid()
            data["r986_recovery_replay_denied"] = True
            data["r986_dispatch_sha256"] = recovery_evidence["dispatch_sha256"]
            data["r986_os_supervisor_accepted"] = False
            if scheduler_mode == "true":
                task = recovery_evidence["r993_task"]
                data["r993_os_scheduled_recovery"] = True
                data["r993_task_name"] = task["taskName"]
                data["r993_task_sid"] = task["sid"]
                data["r993_task_launcher_pid"] = task["launcherPid"]
                data["r993_task_worker_exit"] = task["workerExit"]
                data["r993_os_supervisor_accepted"] = False
                data["r993_reboot_accepted"] = False
        report.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        print("R982_REAL_NATIVE_STATUS=" + STATUS)
        return 0
    finally:
        fixture.doCleanups()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        # Do not suppress real failed or uncertain transactions.
        print("R982_DISPOSABLE_VM_FAILURE=" + str(exc), file=sys.stderr)
        raise SystemExit(31)
