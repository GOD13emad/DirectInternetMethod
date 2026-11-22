"""R929: exact universal installer engine + REAL synthetic Inno in Windows Sandbox.

This self-contained PyInstaller fixture MUST run only as SYSTEM in a disposable
Windows Sandbox with three SHA-pinned, unrelated synthetic Inno Setup EXEs.
It NEVER installs/removes the product, creates SCM services or changes DNS,
routing, host registry or Tailscale. Native Inno/HKLM observation is real
INSIDE THE GUEST; receipt storage is user/test-controlled and NOT authority.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import winreg

from installer_engine.engine import (
    Engine, EngineError, atomic_json, hash_bytes, require, validate_slot,
)
from installer_engine.native_receipt import intent_sha256
from installer_engine.universal_install import UniversalFixtureInstaller

INPUT = Path(r"C:\DIMR929\input")
OUTPUT = Path(r"C:\DIMR929\output")
ROOT = Path(r"C:\DIMR929\work")
REPORT = OUTPUT / "r929-native-universal-inno.json"
APP_ID = "{BE452737-93D8-4693-930C-C0ABFF932924}"
NAME = "DIM R924 Synthetic Post-Failure Fixture"
REG = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + APP_ID + "_is1"
PLATFORM = "windows-x86_64"
INSTALL = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "DIM_R924_Synthetic_Inno"
MARKER = INSTALL / "code.fixture"


def must(ok: bool, reason: str) -> None:
    if not ok:
        raise EngineError(reason)


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def registry() -> dict | None:
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, REG, 0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            return {
                "name": winreg.QueryValueEx(key, "DisplayName")[0],
                "version": winreg.QueryValueEx(key, "DisplayVersion")[0],
                "uninstall": winreg.QueryValueEx(key, "UninstallString")[0],
            }
    except FileNotFoundError:
        return None


def guest_guard(*, first: bool) -> None:
    must(os.name == "nt" and sys.platform == "win32",
         "R929_WINDOWS_ONLY")
    who = subprocess.run(["whoami", "/user"], capture_output=True,
                         text=True, timeout=12)
    must(who.returncode == 0 and "S-1-5-18" in who.stdout,
         "R929_SYSTEM_GUEST_ID_REQUIRED")
    must(Path(r"C:\Users\WDAGUtilityAccount").is_dir(),
         "R929_WIN_SANDBOX_ID_REQUIRED")
    must(INPUT.is_dir() and OUTPUT.is_dir() and
         (INPUT/"fixture.json").is_file() and
         (INPUT/"inno-pins.json").is_file(),
         "R929_GUEST_INPUT_OUTPUT_REQUIRED")
    must(not (Path(os.environ["ProgramFiles"]) / "DirectInternetMethod").exists(),
         "R929_REAL_PRODUCT_PRESENT_REFUSE")
    if first:
        must(not ROOT.exists() and not REPORT.exists() and
             registry() is None and not INSTALL.exists(),
             "R929_GUEST_FIXTURE_PREEXISTS")


class SyntheticNativeInnoAdapter:
    """Inno native observation; no service lifecycle or publisher authority."""

    def __init__(self, root: Path):
        self.root = root
        self.receipt_path = root/"native-receipt.json"
        self.meta = root/"native-restore-count.json"
        self.fail_next_new = False
        self.fail_after_restored_receipt = False
        must(root == ROOT and root.is_dir() and
             not self.receipt_path.is_symlink() and
             not self.meta.is_symlink(),
             "R929_ADAPTER_UNSAFE_FIXTURE_ROOT")
        fixture = json.loads((INPUT/"fixture.json").read_text("utf8"))
        pins = json.loads((INPUT/"inno-pins.json").read_text("utf8"))
        must(fixture["schema"] == 1 and pins["schema"] == 1 and
             fixture["scope"] == "R924_SYNTHETIC_INNO_FAILURE_ONLY" and
             pins["scope"] == "R929_SYNTHETIC_INNO_THREE_PACKAGES" and
             fixture["app_id"] == APP_ID and pins["app_id"] == APP_ID,
             "R929_NATIVE_INPUT_SCOPE_INVALID")
        self.marker_sha = {
            "1.5.6": fixture["old_marker_sha256"],
            "1.5.7": fixture["new_marker_sha256"],
        }
        self.setup = {
            "1.5.6": INPUT/"R924_Inno_1_5_6.exe",
            "bad": INPUT/"R924_Inno_1_5_7.exe",
            "1.5.7": INPUT/"R929_Inno_1_5_7_good.exe",
        }
        for key, field in (("1.5.6", "old"), ("bad", "failed"),
                           ("1.5.7", "good")):
            must(re.fullmatch("[0-9a-fA-F]{64}", pins[field]) is not None and
                 self.setup[key].is_file() and
                 sha(self.setup[key]).lower() == pins[field].lower(),
                 "R929_SHA_PINNED_INNO_PACKAGE_DRIFT")
        if not self.meta.exists():
            atomic_json(self.meta, {"schema": 1, "native_resume_observations": 0})

    def _metadata(self) -> dict:
        doc = json.loads(self.meta.read_text("utf8"))
        must(type(doc) is dict and set(doc) ==
             {"schema", "native_resume_observations"} and
             doc["schema"] == 1 and
             type(doc["native_resume_observations"]) is int,
             "R929_NATIVE_OBSERVATION_COUNTER_INVALID")
        return doc

    def _bump_native_resume(self) -> None:
        doc = self._metadata()
        doc["native_resume_observations"] += 1
        atomic_json(self.meta, doc)

    def _run(self, path: Path, *, uninstall=False) -> int:
        must(path.is_file() and not path.is_symlink(), "R929_SETUP_NOT_FILE")
        args = ([str(path), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"]
                if uninstall else
                [str(path), "/VERYSILENT", "/SUPPRESSMSGBOXES",
                 "/NORESTART", "/SP-", "/NOCLOSEAPPLICATIONS"])
        proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
        return proc.returncode

    def _native(self, expected: str | None) -> bool:
        reg = registry()
        if expected is None:
            return reg is None and not MARKER.exists()
        if reg is None or reg["name"] != NAME or reg["version"] != expected:
            return False
        if (not MARKER.is_file() or MARKER.is_symlink() or
                sha(MARKER) != self.marker_sha[expected]):
            return False
        return True

    def _native_version(self) -> str | None:
        found = registry()
        if found is None:
            must(not MARKER.exists(), "R929_ORPHAN_NATIVE_MARKER")
            return None
        must(found["name"] == NAME and
             found["version"] in self.marker_sha,
             "R929_FOREIGN_APPID_REGISTRATION")
        return found["version"]

    def _code_versions(self) -> set:
        values = set()
        for path in (ROOT/"code", ROOT/"user"):
            engine = Engine(path, PLATFORM)
            with engine.locked():
                active = engine._installed()
                pending = engine._pending()
                if pending is not None:
                    must(active is not None and
                         active["manifest_sha256"] ==
                         pending["new"]["manifest_sha256"],
                         "R929_ACTIVE_PENDING_MANIFEST_DRIFT")
                if active is None:
                    values.add(None)
                else:
                    validate_slot(engine.current, active["manifest"])
                    values.add(active["manifest"]["version"])
        return values

    def snapshot(self) -> bytes:
        ver = self._native_version()
        must(self._native(ver), "R929_SNAPSHOT_NATIVE_STATE_INVALID")
        return (json.dumps({"schema": 1, "version": ver},
                           sort_keys=True, separators=(",", ":")) +
                "\n").encode("utf8")

    def observed_version(self) -> str | None:
        return self._native_version()

    def quiesced(self) -> bool:
        # No synthetic SCM service is created by this Inno-only fixture.
        return True

    def quiesce(self) -> None:
        return None

    def apply(self, target_version: str, intent: dict) -> None:
        must(self._code_versions() == {target_version},
             "R929_CODE_SLOTS_NOT_ACTIVATED")
        must(self.quiesced(), "R929_UNQUIESCED")
        self.receipt_path.unlink(missing_ok=True)
        use_bad = target_version == "1.5.7" and self.fail_next_new
        self.fail_next_new = False
        exe = self.setup["bad" if use_bad else target_version]
        exit_code = self._run(exe)
        must(self._native(target_version),
             "R929_NATIVE_SETUP_DID_NOT_INSTALL_EXPECTED_VERSION")
        if use_bad:
            must(exit_code == 67, "R929_EXPECTED_NATIVE_POSTINSTALL_EXIT67")
            raise EngineError("R929_INJECTED_NATIVE_INNO_POSTINSTALL_EXIT67")
        must(exit_code == 0, "R929_NATIVE_SETUP_EXIT_NONZERO")
        atomic_json(self.receipt_path, {
            "schema": 1, "status": "completed",
            "intent_sha256": intent_sha256(intent),
        })

    def _receipt_bytes(self, intent: dict, state: str) -> bytes | None:
        if not self.receipt_path.exists():
            return None
        payload = json.loads(self.receipt_path.read_text("utf8"))
        if payload != {"schema": 1, "status": state,
                       "intent_sha256": intent_sha256(intent)}:
            return None
        desired = intent["old"] if state == "restored" else intent["new"]
        must(self._native(desired), "R929_NATIVE_RECEIPT_REGISTRATION_DRIFT")
        return self.receipt_path.read_bytes()

    def completed(self, intent: dict) -> bytes | None:
        return self._receipt_bytes(intent, "completed")

    def _uninstall_native(self) -> None:
        found = registry()
        if found is None:
            must(not MARKER.exists(), "R929_ORPHAN_MARKER_BEFORE_UNINSTALL")
            return
        raw = found["uninstall"].strip()
        match = re.fullmatch(r'"([^"]+)"', raw)
        must(match is not None, "R929_UNINSTALL_STRING_UNSUPPORTED")
        exe = Path(match.group(1))
        must(exe.parent.resolve() == INSTALL.resolve() and
             re.fullmatch(r"unins[0-9]+\.exe", exe.name, re.IGNORECASE)
             is not None and exe.is_file(),
             "R929_NATIVE_UNINSTALLER_NOT_IN_OWNED_FOLDER")
        must(self._run(exe, uninstall=True) == 0,
             "R929_NATIVE_UNINSTALL_EXIT_NONZERO")
        must(self._native(None), "R929_NATIVE_UNINSTALL_LEFT_CODE_OR_REGISTRY")

    def restore(self, snapshot: bytes, intent: dict) -> None:
        try:
            doc = json.loads(snapshot.decode("utf8"))
        except (UnicodeError, ValueError) as e:
            raise EngineError("R929_NATIVE_PREIMAGE_PARSE_INVALID") from e
        must(type(doc) is dict and set(doc) == {"schema", "version"} and
             type(doc["schema"]) is int and doc["schema"] == 1 and
             doc["version"] == intent["old"],
             "R929_NATIVE_PREIMAGE_OLD_VERSION_DRIFT")
        self.receipt_path.unlink(missing_ok=True)
        if doc["version"] is None:
            self._uninstall_native()
        else:
            must(self._run(self.setup[doc["version"]]) == 0,
                 "R929_PINNED_OLD_SETUP_RESTORE_FAILED")
        must(self._native(doc["version"]),
             "R929_PREVIOUS_NATIVE_REGISTRATION_NOT_RESTORED")

    def resume_restored(self, old_version: str | None, intent: dict) -> None:
        must(self._code_versions() == {old_version} and
             self._native(old_version),
             "R929_NATIVE_RESTORE_BEFORE_OLD_CODE_READY")
        self._bump_native_resume()
        atomic_json(self.receipt_path, {
            "schema": 1, "status": "restored",
            "intent_sha256": intent_sha256(intent),
        })
        if self.fail_after_restored_receipt:
            raise EngineError("R929_INJECTED_PROCESS_INTERRUPTION_AFTER_RESTORED")

    def restored(self, intent: dict) -> bytes | None:
        return self._receipt_bytes(intent, "restored")

    def unregister(self, intent: dict) -> None:
        self.receipt_path.unlink(missing_ok=True)
        self._uninstall_native()
        atomic_json(self.receipt_path, {
            "schema": 1, "status": "completed",
            "intent_sha256": intent_sha256(intent),
        })

    def uninstall_completed(self, intent: dict) -> bytes | None:
        return self._receipt_bytes(intent, "completed")


def source(root: Path, version: str, kind: str) -> dict:
    out = {}
    for scope in ("code", "user"):
        folder = root/"packages"/(kind+"-"+scope)
        payload = folder/"payload"/"app"/"code.fixture"
        payload.parent.mkdir(parents=True)
        raw = (scope+"|"+kind+"|"+version).encode("ascii")
        payload.write_bytes(raw)
        manifest = {
            "schema": 1, "product": "Direct Internet Method",
            "version": version, "platform": PLATFORM,
            "files": [{"path": "app/code.fixture", "bytes": len(raw),
                       "sha256": hash_bytes(raw), "mode": 0o644}],
        }
        manifest_file = folder/"manifest.json"
        manifest_file.write_text(
            json.dumps(manifest, sort_keys=True) + "\n", encoding="utf8")
        out[scope] = (folder, hash_bytes(manifest_file.read_bytes()))
    return out


def engine(native: SyntheticNativeInnoAdapter) -> UniversalFixtureInstaller:
    return UniversalFixtureInstaller(ROOT/"journal", PLATFORM,
                    {"code": ROOT/"code", "user": ROOT/"user"}, native)


def replay() -> int:
    guest_guard(first=False)
    must(ROOT.is_dir(), "R929_RECOVERY_ROOT_MISSING")
    native = SyntheticNativeInnoAdapter(ROOT)
    tx = engine(native)
    result = tx.recover()
    print(json.dumps({"status": "R929_RECOVERY_IN_SEPARATE_PROCESS",
                      "pid": os.getpid(), "version": result["version"],
                      "native_resume_observations":
                          native._metadata()["native_resume_observations"]}))
    return 0


def main() -> int:
    if sys.argv[1:] == ["--replay"]:
        return replay()
    guest_guard(first=True)
    ROOT.mkdir(parents=False)
    native = SyntheticNativeInnoAdapter(ROOT)
    stages: list[str] = []
    try:
        tx = engine(native)
        tx.begin(source(ROOT, "1.5.6", "old"))
        tx.activate()
        tx.commit()
        must(native._native("1.5.6") and
             native._code_versions() == {"1.5.6"},
             "R929_NATIVE_OLD_COMMIT_FAILED")
        stages.append("SHARED_CORE_AND_REAL_INNO_156_INSTALLED")

        owner = ROOT/"user"/"data"/"settings.json"
        owner.parent.mkdir()
        owner.write_bytes(b"OWNER_CONFIG_R929_PRESERVE")
        owner_sha = sha(owner)

        native.fail_next_new = True
        tx.begin(source(ROOT, "1.5.7", "newbad"))
        try:
            tx.activate()
        except EngineError as exc:
            must("R929_INJECTED_NATIVE_INNO_POSTINSTALL_EXIT67" in str(exc),
                 "R929_FAILURE_REASON_WRONG")
        else:
            raise EngineError("R929_EXPECTED_INNO_FAULT_NOT_REPRODUCED")
        must(native._native("1.5.7") and
             native.completed(tx._intent(tx._load())) is None,
             "R929_INNO_FAILURE_FALSE_COMPLETION")
        engine(native).recover()
        must(native._native("1.5.6") and
             native._code_versions() == {"1.5.6"},
             "R929_SHARED_ENGINE_NATIVE_ROLLBACK_FAILED")
        stages.append("INNO_POSTINSTALL_EXIT67_ROLLBACK_OLD_NATIVE_AND_TWO_SCOPES")

        tx.begin(source(ROOT, "1.5.7", "newgood"))
        tx.activate()
        tx.commit()
        must(native._native("1.5.7") and
             native._code_versions() == {"1.5.7"},
             "R929_NATIVE_NEW_COMMIT_FAILED")
        stages.append("SHA_PINNED_NEW_INNO_AND_TWO_SCOPES_COMMITTED")

        tx.begin_uninstall()
        tx.apply_uninstall()
        must(native._native(None), "R929_SYNTHETIC_INNO_UNINSTALL_FAILED")
        native.fail_after_restored_receipt = True
        try:
            tx.abort_uninstall()
        except EngineError as exc:
            must("R929_INJECTED_PROCESS_INTERRUPTION_AFTER_RESTORED" in str(exc),
                 "R929_RESTORE_INTERRUPTION_WRONG_REASON")
        else:
            raise EngineError("R929_MISSING_AFTER_RESTORE_INTERRUPTION")
        original_count = native._metadata()["native_resume_observations"]
        must(engine(native)._load()["phase"] ==
             "uninstall-restoring-native", "R929_RESTORE_JOURNAL_NOT_DURABLE")
        proc = subprocess.run([sys.executable, "--replay"],
                              capture_output=True, text=True, timeout=90)
        must(proc.returncode == 0, "R929_INDEPENDENT_PROCESS_RECOVERY_FAILED:"+
             proc.stderr[-500:])
        child = json.loads(proc.stdout.strip().splitlines()[-1])
        must(child["status"] == "R929_RECOVERY_IN_SEPARATE_PROCESS" and
             child["pid"] != os.getpid() and
             child["native_resume_observations"] == original_count and
             native._native("1.5.7") and
             native._code_versions() == {"1.5.7"},
             "R929_NATIVE_RECOVERY_RESTARTED_OR_LOST_NATIVE_STATE")
        stages.append("SEPARATE_PROCESS_RESTORED_RECEIPT_REPLAY_NO_DUPLICATE")

        tx.begin_uninstall()
        tx.apply_uninstall()
        tx.finish_uninstall()
        must(native._native(None) and
             native._code_versions() == {None} and
             sha(owner) == owner_sha,
             "R929_NATIVE_FINAL_UNINSTALL_OR_OWNER_DATA_FAILED")
        stages.append("INNO_UNINSTALL_AND_TWO_SCOPES_EMPTY_OWNER_DATA_PRESERVED")

        report = {
            "schema": 1,
            "status": "PASS_R929_ISOLATED_INNO_SHARED_UNIVERSAL_ENGINE",
            "stages": stages, "owner_sha256": owner_sha,
            "native_inno_registry_observed": True,
            "separate_python_process_replay": True,
            "native_scm_service_accepted": False,
            "real_product_rollback_accepted": False,
            "publisher_authenticated": False,
            "host_reboot_accepted": False,
            "native_os_broker_accepted": False,
        }
        atomic_json(REPORT, report)
        print(json.dumps(report, sort_keys=True))
        return 0
    except BaseException as exc:
        report = {"schema": 1, "status": "FAIL_R929_NATIVE_INNO",
                  "stages": stages, "error": str(exc),
                  "native_scm_service_accepted": False,
                  "real_product_rollback_accepted": False}
        if OUTPUT.is_dir():
            atomic_json(REPORT, report)
        print(json.dumps(report, sort_keys=True), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
