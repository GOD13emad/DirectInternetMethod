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
from functools import wraps
from pathlib import Path
from typing import Mapping, Protocol, runtime_checkable

from .engine import (
    Engine, EngineError, atomic_json, durable_dir, load_json, require,
    version,
)
from .two_scope import TwoScopeFixtureCoordinator
from .two_scope_uninstall import TwoScopeUninstallFixtureCoordinator

MAX_SNAPSHOT = 65536
UPDATE_PHASES = frozenset(("preparing", "staged", "activated", "finalizing"))
UNINSTALL_PHASES = frozenset(("uninstall-preparing", "uninstall-prepared",
                              "uninstall-finalizing"))
PHASES = UPDATE_PHASES | UNINSTALL_PHASES


@runtime_checkable
class NativeAdapter(Protocol):
    """FIXTURE ONLY. OS privilege and source trust must be established elsewhere."""

    def snapshot(self) -> bytes: ...
    def observed_version(self) -> str | None: ...
    def quiesced(self) -> bool: ...
    def apply(self, target_version: str) -> None: ...
    def completed(self, target_version: str) -> bool: ...
    def restore(self, snapshot: bytes) -> None: ...
    def unregister(self) -> None: ...
    def uninstall_completed(self) -> bool: ...


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
                             "preimage_b64", "preimage_sha256"} and
                type(doc["schema"]) is int and doc["schema"] == 1 and
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
        return doc

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
        record = {"schema": 1, "platform": self.platform,
                  "phase": "preparing", "old": old, "new": new,
                  "preimage_b64": raw_b64, "preimage_sha256": sha}
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
        self.adapter.apply(doc["new"])
        return {"status": "UNIVERSAL_NATIVE_APPLY_UNVERIFIED_FIXTURE",
                "version": doc["new"]}

    @_serialized
    def commit(self, *, fault_after: str | None = None) -> dict:
        doc = self._load()
        require(doc["phase"] in ("activated", "finalizing"),
                "UNIVERSAL_NOT_ACTIVATED")
        # Registry or unit version alone may predate a postinstall failure.
        require(self.adapter.completed(doc["new"]) is True,
                "UNIVERSAL_NATIVE_COMPLETION_RECEIPT_MISSING")
        require(self.adapter.observed_version() == doc["new"],
                "UNIVERSAL_NATIVE_TARGET_NOT_INSTALLED")
        if doc["phase"] != "finalizing":
            doc["phase"] = "finalizing"
            self._write(doc)
        result = self.code.finalize(
            lambda: self.adapter.completed(doc["new"]) is True
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
        require(self.adapter.quiesced() is True,
                "UNIVERSAL_NATIVE_NOT_QUIESCED")
        raw = base64.b64decode(doc["preimage_b64"].encode("ascii"))
        self.adapter.restore(raw)
        require(self.adapter.observed_version() == doc["old"],
                "UNIVERSAL_NATIVE_RESTORE_NOT_VERIFIED")
        if self.code.path.exists():
            self.code.abort(self.adapter.quiesced)
        require(self._consistent_old() == doc["old"],
                "UNIVERSAL_CODE_PREIMAGE_NOT_RESTORED")
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
        record = {"schema": 1, "platform": self.platform,
                  "phase": "uninstall-preparing", "old": old, "new": None,
                  "preimage_b64": raw_b64, "preimage_sha256": sha}
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
        self.adapter.unregister()
        return {"status": "UNIVERSAL_NATIVE_UNREGISTER_UNVERIFIED_FIXTURE"}

    @_serialized
    def finish_uninstall(self, *, fault_after: str | None = None) -> dict:
        doc = self._load()
        require(doc["phase"] in ("uninstall-prepared", "uninstall-finalizing"),
                "UNIVERSAL_UNINSTALL_NOT_READY")
        require(self.adapter.uninstall_completed() is True and
                self.adapter.observed_version() is None,
                "UNIVERSAL_NATIVE_UNINSTALL_RECEIPT_MISSING")
        if doc["phase"] != "uninstall-finalizing":
            doc["phase"] = "uninstall-finalizing"
            self._write(doc)
        self.uninstall.finish(
            lambda: self.adapter.uninstall_completed() is True
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
        require(doc["phase"] in ("uninstall-preparing", "uninstall-prepared"),
                "UNIVERSAL_UNINSTALL_FORWARD_REPLAY_REQUIRED")
        require(self.adapter.quiesced() is True,
                "UNIVERSAL_NATIVE_NOT_QUIESCED")
        raw = base64.b64decode(doc["preimage_b64"].encode("ascii"))
        self.adapter.restore(raw)
        require(self.adapter.observed_version() == doc["old"],
                "UNIVERSAL_NATIVE_RESTORE_NOT_VERIFIED")
        if self.uninstall.uninstall_path.exists():
            self.uninstall.abort(
                self.adapter.quiesced,
                lambda: self.adapter.observed_version() == doc["old"])
        require(self._consistent_old() == doc["old"],
                "UNIVERSAL_UNINSTALL_ABORT_CODE_DRIFT")
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
