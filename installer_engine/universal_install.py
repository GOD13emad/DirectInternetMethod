"""One cross-platform transaction protocol over the existing shared code kernel.

All steps and recovery states are OS-neutral. A native adapter implements
platform-specific SCM/Inno or systemd/Polkit operations independently.
NO authorized production native adapter exists in this module. Passing this
fixture's tests does not authenticate an OS principal, publisher or service,
or prove live product install, native rollback or Windows power-loss durability.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from functools import wraps
from pathlib import Path
from typing import Mapping, Protocol, runtime_checkable

from .engine import (
    Engine, EngineError, atomic_json, durable_dir, load_json, require,
    version,
)
from .two_scope import TwoScopeFixtureCoordinator
from .two_scope_uninstall import TwoScopeUninstallFixtureCoordinator
from .native_receipt import (validate_intent, verify_completion_receipt,
                             verify_restoration_receipt)

MAX_SNAPSHOT = 65536
UPDATE_PHASES = frozenset(("preparing", "staged", "activated", "finalizing",
                           "restoring-code", "restoring-native"))
UNINSTALL_PHASES = frozenset(("uninstall-preparing", "uninstall-prepared",
                              "uninstall-finalizing",
                              "uninstall-restoring-code",
                              "uninstall-restoring-native"))
PHASES = UPDATE_PHASES | UNINSTALL_PHASES


@runtime_checkable
class NativeAdapter(Protocol):
    """FIXTURE ONLY. OS privilege and source trust must be established elsewhere."""

    def snapshot(self) -> bytes: ...
    def observed_version(self) -> str | None: ...
    def quiesced(self) -> bool: ...
    def apply(self, target_version: str, intent: dict) -> None: ...
    def completed(self, intent: dict) -> bytes | None: ...
    def restore(self, snapshot: bytes, intent: dict) -> None: ...
    def unregister(self, intent: dict) -> None: ...
    def uninstall_completed(self, intent: dict) -> bytes | None: ...
    def resume_restored(self, old_version: str | None, intent: dict) -> None: ...
    def restored(self, intent: dict) -> bytes | None: ...


def _serialized(method):
    """Single-writer lock over an entire multi-scope operation, not one file."""
    @wraps(method)
    def run(self, *args, **kwargs):
        with self.guard.locked():
            return method(self, *args, **kwargs)
    return run

class UniversalFixtureInstaller:
    """One API for install/upgrade/abort/recover/uninstall across both OSs.

    Exactly two managed-code scopes: independently privileged and owner.
    User data is always outside these owned code-only roots. No unprivileged
    callback constitutes native authority. Snapshot storage in this fixture
    is NOT suitable for real OS credentials, confidential settings or ACLs.
    """

    def __init__(self, journal_root: Path | str, platform: str,
                 roots: Mapping[str, Path | str], adapter: NativeAdapter):
        require(isinstance(adapter, NativeAdapter),
                "UNIVERSAL_NATIVE_ADAPTER_INTERFACE_REQUIRED")
        self.guard = Engine(Path(journal_root).absolute() / ".universal-operation-guard", platform)
        self.code = TwoScopeFixtureCoordinator(journal_root, platform, roots)
        self.uninstall = TwoScopeUninstallFixtureCoordinator(
            journal_root, platform, roots)
        self.adapter = adapter
        self.platform = platform
        self.journal = self.code.control.state / "universal_install.json"

    @staticmethod
    def _snapshot(raw: bytes) -> tuple[str, str]:
        require(type(raw) is bytes and 0 < len(raw) <= MAX_SNAPSHOT,
                "UNIVERSAL_NATIVE_PREIMAGE_BYTES_INVALID")
        return (base64.b64encode(raw).decode("ascii"),
                hashlib.sha256(raw).hexdigest())

    def _load(self) -> dict:
        require(self.journal.exists() and not self.journal.is_symlink(),
                "UNIVERSAL_TRANSACTION_MISSING")
        doc = load_json(self.journal)
        require(type(doc) is dict and
                set(doc) == {"schema", "platform", "phase", "old", "new",
                             "preimage_b64", "preimage_sha256",
                             "request_id", "scope_pins"} and
                type(doc["schema"]) is int and doc["schema"] == 2 and
                doc["platform"] == self.platform and
                type(doc["phase"]) is str and doc["phase"] in PHASES and
                type(doc["preimage_b64"]) is str and
                type(doc["preimage_sha256"]) is str,
                "UNIVERSAL_TRANSACTION_SCHEMA_INVALID")
        require(doc["old"] is None or type(doc["old"]) is str,
                "UNIVERSAL_OLD_VERSION_TYPE_INVALID")
        if doc["old"] is not None:
            version(doc["old"])
        if doc["phase"] in UPDATE_PHASES:
            require(type(doc["new"]) is str,
                    "UNIVERSAL_NEW_VERSION_TYPE_INVALID")
            version(doc["new"])
            require(doc["old"] is None or
                    version(doc["new"]) > version(doc["old"]),
                    "UNIVERSAL_NONMONOTONIC_UPDATE")
        else:
            require(doc["old"] is not None and doc["new"] is None,
                    "UNIVERSAL_UNINSTALL_OLD_IDENTITY_REQUIRED")
        try:
            raw = base64.b64decode(doc["preimage_b64"].encode("ascii"),
                                   validate=True)
        except (ValueError, UnicodeError) as exc:
            raise EngineError("UNIVERSAL_PREIMAGE_ENCODING_INVALID") from exc
        require(self._snapshot(raw) ==
                (doc["preimage_b64"], doc["preimage_sha256"]),
                "UNIVERSAL_PREIMAGE_SHA_INVALID")
        self._intent(doc)
        # Cross-check the top-level pinned manifests with coordinator state.
        if doc["phase"] in UPDATE_PHASES and self.code.path.exists():
            rows = self.code._journal()["scopes"]
            expected = [{"name": row["name"],
                         "manifest_sha256": row["new"]["pin"]}
                        for row in rows]
            require(expected == doc["scope_pins"],
                    "UNIVERSAL_SCOPE_MANIFEST_PIN_DRIFT")
        if (doc["phase"] in UNINSTALL_PHASES and
                self.uninstall.uninstall_path.exists()):
            rows = self.uninstall._uninstall_journal()["scopes"]
            expected = [{"name": row["name"],
                         "manifest_sha256": row["old"]["pin"]}
                        for row in rows]
            require(expected == doc["scope_pins"],
                    "UNIVERSAL_SCOPE_MANIFEST_PIN_DRIFT")
        return doc

    def _intent(self, doc: dict) -> dict:
        """Exact native request identity for all adapters, never a privilege grant."""
        kind = ("uninstall" if doc["phase"] in UNINSTALL_PHASES
                else "upgrade" if doc["old"] is not None else "install")
        intent = {"schema": 1, "request_id": doc["request_id"],
                  "platform": doc["platform"], "operation": kind,
                  "old": doc["old"], "new": doc["new"],
                  "preimage_sha256": doc["preimage_sha256"],
                  "scope_pins": doc["scope_pins"]}
        validate_intent(intent)
        require([row["name"] for row in intent["scope_pins"]] ==
                list(self.code.names) and intent["platform"] == self.platform,
                "UNIVERSAL_INTENT_SCOPE_OR_PLATFORM_DRIFT")
        return intent

    def _native_complete(self, doc: dict) -> bool:
        intent = self._intent(doc)
        return verify_completion_receipt(intent, self.adapter.completed(intent))

    def _native_uninstalled(self, doc: dict) -> bool:
        intent = self._intent(doc)
        return verify_completion_receipt(
            intent, self.adapter.uninstall_completed(intent))

    def _native_restored(self, doc: dict) -> bool:
        intent = self._intent(doc)
        return verify_restoration_receipt(
            intent, self.adapter.restored(intent))

    def _write(self, doc: dict) -> None:
        with self.code.control.locked():
            atomic_json(self.journal, doc)

    def _remove(self) -> None:
        with self.code.control.locked():
            require(self.journal.exists() and not self.journal.is_symlink(),
                    "UNIVERSAL_JOURNAL_DISAPPEARED")
            self.journal.unlink()
            durable_dir(self.code.control.state)

    def _consistent_old(self) -> str | None:
        versions = []
        for name in self.code.names:
            state = Engine(self.code.roots[name], self.platform).verify()
            versions.append(state.get("version") if state["status"] != "EMPTY"
                            else None)
        require(versions[0] == versions[1],
                "UNIVERSAL_SCOPES_VERSION_DIVERGED")
        return versions[0]

    def _capture(self, old: str | None) -> tuple[str, str]:
        require(self.adapter.observed_version() == old,
                "UNIVERSAL_NATIVE_OLD_VERSION_DRIFT")
        out = self._snapshot(self.adapter.snapshot())
        require(self.adapter.observed_version() == old,
                "UNIVERSAL_NATIVE_CHANGED_DURING_SNAPSHOT")
        return out

    def _no_active(self) -> None:
        require(not self.journal.exists() and not self.journal.is_symlink() and
                not self.code.path.exists() and
                not self.code.path.is_symlink() and
                not self.uninstall.uninstall_path.exists() and
                not self.uninstall.uninstall_path.is_symlink(),
                "UNIVERSAL_UNRESOLVED_TRANSACTION")

    @_serialized
    def begin(self, sources: Mapping[str, tuple[Path | str, str]]) -> dict:
        self._no_active()
        old = self._consistent_old()
        raw_b64, sha = self._capture(old)
        require(type(sources) is dict and set(sources) == set(self.code.names),
                "UNIVERSAL_SCOPE_SOURCE_MAP_INVALID")
        from .engine import read_package
        rows = [read_package(Path(sources[name][0]).absolute(),
                             sources[name][1], self.platform)
                for name in self.code.names]
        new = rows[0]["version"]
        require(all(item["version"] == new for item in rows),
                "UNIVERSAL_PACKAGE_VERSION_SPLIT")
        require(old is None or version(new) > version(old),
                "UNIVERSAL_PACKAGE_NOT_NEWER")
        record = {"schema": 2, "platform": self.platform,
                  "phase": "preparing", "old": old, "new": new,
                  "request_id": secrets.token_hex(16),
                  "scope_pins": [{"name": name,
                                  "manifest_sha256": sources[name][1].lower()}
                                 for name in self.code.names],
                  "preimage_b64": raw_b64, "preimage_sha256": sha}
        self._intent(record)
        self._write(record)
        self.code.prepare(sources)
        record["phase"] = "staged"
        self._write(record)
        return {"status": "UNIVERSAL_TWO_SCOPE_STAGED_FIXTURE", "version": new}

    @_serialized
    def activate(self) -> dict:
        doc = self._load()
        require(doc["phase"] == "staged", "UNIVERSAL_NOT_STAGED")
        require(self.adapter.quiesced() is True,
                "UNIVERSAL_NATIVE_NOT_QUIESCED")
        self.code.activate(self.adapter.quiesced)
        doc["phase"] = "activated"
        self._write(doc)  # Persist before touching native registration.
        self.adapter.apply(doc["new"], self._intent(doc))
        return {"status": "UNIVERSAL_NATIVE_APPLY_UNVERIFIED_FIXTURE",
                "version": doc["new"]}

    @_serialized
    def commit(self, *, fault_after: str | None = None) -> dict:
        doc = self._load()
        require(doc["phase"] in ("activated", "finalizing"),
                "UNIVERSAL_NOT_ACTIVATED")
        # Registry or unit version alone may predate a postinstall failure.
        require(self._native_complete(doc) is True,
                "UNIVERSAL_NATIVE_COMPLETION_RECEIPT_MISSING")
        require(self.adapter.observed_version() == doc["new"],
                "UNIVERSAL_NATIVE_TARGET_NOT_INSTALLED")
        if doc["phase"] != "finalizing":
            doc["phase"] = "finalizing"
            self._write(doc)
        result = self.code.finalize(
            lambda: self._native_complete(doc) is True
            and self.adapter.observed_version() == doc["new"],
            fault_after=fault_after)
        self._remove()
        return {"status": "UNIVERSAL_TWO_SCOPE_COMMIT_FIXTURE_ONLY",
                "version": result["version"],
                "native_product_installation_accepted": False}

    @_serialized
    def abort(self) -> dict:
        doc = self._load()
        require(doc["phase"] in UPDATE_PHASES,
                "UNIVERSAL_UPDATE_TRANSACTION_REQUIRED")
        require(doc["phase"] != "finalizing",
                "UNIVERSAL_FORWARD_REPLAY_REQUIRED")
        intent = self._intent(doc)
        if doc["phase"] != "restoring-native":
            require(self.adapter.quiesced() is True,
                    "UNIVERSAL_NATIVE_NOT_QUIESCED")
            if doc["phase"] != "restoring-code":
                doc["phase"] = "restoring-code"
                self._write(doc)
            # Native identity/registration restored while service STOPPED.
            raw = base64.b64decode(doc["preimage_b64"].encode("ascii"))
            self.adapter.restore(raw, intent)
            require(self.adapter.observed_version() == doc["old"],
                    "UNIVERSAL_NATIVE_RESTORE_NOT_VERIFIED")
            if self.code.path.exists():
                self.code.abort(self.adapter.quiesced)
            require(self._consistent_old() == doc["old"],
                    "UNIVERSAL_CODE_PREIMAGE_NOT_RESTORED")
            # Durable boundary before restarting the OLD service.
            doc["phase"] = "restoring-native"
            self._write(doc)
        else:
            require(self._consistent_old() == doc["old"],
                    "UNIVERSAL_CODE_PREIMAGE_NOT_RESTORED")
        # On replay after a process exit, a matching restored receipt means
        # the old native runtime was already resumed; do not start twice.
        if not self._native_restored(doc):
            self.adapter.resume_restored(doc["old"], intent)
        require(self._native_restored(doc) is True,
                "UNIVERSAL_NATIVE_RESTORE_HEALTH_NOT_VERIFIED")
        require(self.adapter.observed_version() == doc["old"],
                "UNIVERSAL_NATIVE_RESTORED_VERSION_CHANGED")
        self._remove()
        return {"status": "UNIVERSAL_TWO_SCOPE_ABORT_FIXTURE_ONLY",
                "version": doc["old"],
                "native_product_rollback_accepted": False}

    @_serialized
    def begin_uninstall(self) -> dict:
        self._no_active()
        old = self._consistent_old()
        require(old is not None, "UNIVERSAL_NOT_INSTALLED")
        raw_b64, sha = self._capture(old)
        scope_pins = []
        for name in self.code.names:
            snapshot = self.code._snapshot(name)
            require(snapshot is not None and snapshot["version"] == old,
                    "UNIVERSAL_UNINSTALL_SOURCE_CHANGED")
            scope_pins.append({"name": name,
                               "manifest_sha256": snapshot["pin"]})
        record = {"schema": 2, "platform": self.platform,
                  "phase": "uninstall-preparing", "old": old, "new": None,
                  "request_id": secrets.token_hex(16),
                  "scope_pins": scope_pins,
                  "preimage_b64": raw_b64, "preimage_sha256": sha}
        self._intent(record)
        self._write(record)
        self.uninstall.prepare(self.adapter.quiesced)
        record["phase"] = "uninstall-prepared"
        self._write(record)
        return {"status": "UNIVERSAL_UNINSTALL_PREPARED_FIXTURE",
                "version": old}

    @_serialized
    def apply_uninstall(self) -> dict:
        doc = self._load()
        require(doc["phase"] == "uninstall-prepared",
                "UNIVERSAL_UNINSTALL_NOT_PREPARED")
        require(self.adapter.quiesced() is True,
                "UNIVERSAL_NATIVE_NOT_QUIESCED")
        self.adapter.unregister(self._intent(doc))
        return {"status": "UNIVERSAL_NATIVE_UNREGISTER_UNVERIFIED_FIXTURE"}

    @_serialized
    def finish_uninstall(self, *, fault_after: str | None = None) -> dict:
        doc = self._load()
        require(doc["phase"] in ("uninstall-prepared", "uninstall-finalizing"),
                "UNIVERSAL_UNINSTALL_NOT_READY")
        require(self._native_uninstalled(doc) is True and
                self.adapter.observed_version() is None,
                "UNIVERSAL_NATIVE_UNINSTALL_RECEIPT_MISSING")
        if doc["phase"] != "uninstall-finalizing":
            doc["phase"] = "uninstall-finalizing"
            self._write(doc)
        self.uninstall.finish(
            lambda: self._native_uninstalled(doc) is True
            and self.adapter.observed_version() is None,
            fault_after=fault_after)
        require(self._consistent_old() is None,
                "UNIVERSAL_UNINSTALL_SCOPES_NOT_EMPTY")
        self._remove()
        return {"status": "UNIVERSAL_UNINSTALL_COMPLETE_FIXTURE_ONLY",
                "native_product_uninstall_accepted": False}

    @_serialized
    def abort_uninstall(self) -> dict:
        doc = self._load()
        require(doc["phase"] in UNINSTALL_PHASES and
                doc["phase"] != "uninstall-finalizing",
                "UNIVERSAL_UNINSTALL_FORWARD_REPLAY_REQUIRED")
        intent = self._intent(doc)
        if doc["phase"] != "uninstall-restoring-native":
            require(self.adapter.quiesced() is True,
                    "UNIVERSAL_NATIVE_NOT_QUIESCED")
            if doc["phase"] != "uninstall-restoring-code":
                doc["phase"] = "uninstall-restoring-code"
                self._write(doc)
            raw = base64.b64decode(doc["preimage_b64"].encode("ascii"))
            self.adapter.restore(raw, intent)
            require(self.adapter.observed_version() == doc["old"],
                    "UNIVERSAL_NATIVE_RESTORE_NOT_VERIFIED")
            if self.uninstall.uninstall_path.exists():
                self.uninstall.abort(
                    self.adapter.quiesced,
                    lambda: self.adapter.observed_version() == doc["old"])
            require(self._consistent_old() == doc["old"],
                    "UNIVERSAL_UNINSTALL_ABORT_CODE_DRIFT")
            doc["phase"] = "uninstall-restoring-native"
            self._write(doc)
        else:
            require(self._consistent_old() == doc["old"],
                    "UNIVERSAL_UNINSTALL_ABORT_CODE_DRIFT")
        if not self._native_restored(doc):
            self.adapter.resume_restored(doc["old"], intent)
        require(self._native_restored(doc) is True,
                "UNIVERSAL_NATIVE_RESTORE_HEALTH_NOT_VERIFIED")
        require(self.adapter.observed_version() == doc["old"],
                "UNIVERSAL_NATIVE_RESTORED_VERSION_CHANGED")
        self._remove()
        return {"status": "UNIVERSAL_UNINSTALL_ABORT_FIXTURE_ONLY",
                "version": doc["old"],
                "native_product_rollback_accepted": False}

    def recover(self) -> dict:
        """Replay forward only after explicit native receipt; otherwise abort."""
        doc = self._load()
        if doc["phase"] in UNINSTALL_PHASES:
            if doc["phase"] == "uninstall-finalizing":
                return self.finish_uninstall()
            return self.abort_uninstall()
        if doc["phase"] == "finalizing":
            return self.commit()
        return self.abort()
