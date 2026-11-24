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
    def quiesce(self) -> None: ...
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

    def _bind_expected_intent(self, record: dict, expected_intent: dict | None) -> None:
        """Bind the broker-reserved identity before journaling or mutation.

        Caller supplies an independently established intent; equality is not
        authorization or replay prevention. The adapter/broker remains
        responsible for trusted policy, locking its inputs and reserving IDs.
        Legacy fixture callers can still request a random local identity.
        """
        if expected_intent is not None:
            validate_intent(expected_intent)
            record["request_id"] = expected_intent["request_id"]
            require(self._intent(record) == expected_intent,
                    "UNIVERSAL_EXPECTED_INTENT_DRIFT")
        else:
            record["request_id"] = secrets.token_hex(16)
            self._intent(record)

    @_serialized
    def begin(self, sources: Mapping[str, tuple[Path | str, str]], *,
              expected_intent: dict | None = None) -> dict:
        return self._begin_locked(sources, expected_intent=expected_intent)

    def _begin_locked(self, sources: Mapping[str, tuple[Path | str, str]], *,
              expected_intent: dict | None = None) -> dict:
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
                  "scope_pins": [{"name": name,
                                  "manifest_sha256": sources[name][1].lower()}
                                 for name in self.code.names],
                  "preimage_b64": raw_b64, "preimage_sha256": sha}
        self._bind_expected_intent(record, expected_intent)
        self._write(record)
        self.code.prepare(sources)
        record["phase"] = "staged"
        self._write(record)
        return {"status": "UNIVERSAL_TWO_SCOPE_STAGED_FIXTURE", "version": new}

    @_serialized
    def activate(self) -> dict:
        return self._activate_locked()

    def _activate_locked(self) -> dict:
        doc = self._load()
        require(doc["phase"] == "staged", "UNIVERSAL_NOT_STAGED")
        self.adapter.quiesce()
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
        return self._commit_locked(fault_after=fault_after)

    def _commit_locked(self, *, fault_after: str | None = None,
                        before_remove=None) -> dict:
        doc = self._load()
        require(doc["phase"] in ("activated", "finalizing"),
                "UNIVERSAL_NOT_ACTIVATED")
        # Registry or unit version alone may predate a postinstall failure.
        require(self._native_complete(doc) is True,
                "UNIVERSAL_NATIVE_COMPLETION_RECEIPT_MISSING")
        require(self.adapter.observed_version() == doc["new"],
                "UNIVERSAL_NATIVE_TARGET_NOT_INSTALLED")
        if doc["phase"] != "finalizing":
            require(self.code.path.exists(), "UNIVERSAL_CODE_JOURNAL_MISSING")
            doc["phase"] = "finalizing"
            self._write(doc)
        if self.code.path.exists():
            self.code.finalize(
                lambda: self._native_complete(doc) is True
                and self.adapter.observed_version() == doc["new"],
                fault_after=fault_after)
        else:
            require(not self.code.path.is_symlink() and
                    not self.uninstall.uninstall_path.exists() and
                    not self.uninstall.uninstall_path.is_symlink(),
                    "UNIVERSAL_FINALIZED_JOURNAL_DRIFT")
            for row in doc["scope_pins"]:
                require(self.code._snapshot(row["name"]) ==
                        {"version": doc["new"], "pin": row["manifest_sha256"]},
                        "UNIVERSAL_FINALIZED_SCOPE_PIN_DRIFT")
        if before_remove is not None:
            before_remove("completed_synthetic")
        self._remove()
        return {"status": "UNIVERSAL_TWO_SCOPE_COMMIT_FIXTURE_ONLY",
                "version": doc["new"],
                "native_product_installation_accepted": False}

    @_serialized
    def abort(self) -> dict:
        return self._abort_locked()

    def _abort_locked(self, *, before_remove=None) -> dict:
        doc = self._load()
        require(doc["phase"] in UPDATE_PHASES,
                "UNIVERSAL_UPDATE_TRANSACTION_REQUIRED")
        require(doc["phase"] != "finalizing",
                "UNIVERSAL_FORWARD_REPLAY_REQUIRED")
        intent = self._intent(doc)
        if doc["phase"] != "restoring-native":
            self.adapter.quiesce()
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
        if before_remove is not None:
            before_remove("aborted_synthetic")
        self._remove()
        return {"status": "UNIVERSAL_TWO_SCOPE_ABORT_FIXTURE_ONLY",
                "version": doc["old"],
                "native_product_rollback_accepted": False}

    @_serialized
    def begin_uninstall(self, *, expected_intent: dict | None = None) -> dict:
        return self._begin_uninstall_locked(expected_intent=expected_intent)

    def _begin_uninstall_locked(self, *, expected_intent: dict | None = None) -> dict:
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
                  "scope_pins": scope_pins,
                  "preimage_b64": raw_b64, "preimage_sha256": sha}
        self._bind_expected_intent(record, expected_intent)
        self._write(record)
        # Capture native running/stopped state BEFORE stopping the runtime.
        self.adapter.quiesce()
        require(self.adapter.quiesced() is True,
                "UNIVERSAL_NATIVE_NOT_QUIESCED")
        self.uninstall.prepare(self.adapter.quiesced)
        record["phase"] = "uninstall-prepared"
        self._write(record)
        return {"status": "UNIVERSAL_UNINSTALL_PREPARED_FIXTURE",
                "version": old}

    @_serialized
    def apply_uninstall(self) -> dict:
        return self._apply_uninstall_locked()

    def _apply_uninstall_locked(self) -> dict:
        doc = self._load()
        require(doc["phase"] == "uninstall-prepared",
                "UNIVERSAL_UNINSTALL_NOT_PREPARED")
        require(self.adapter.quiesced() is True,
                "UNIVERSAL_NATIVE_NOT_QUIESCED")
        self.adapter.unregister(self._intent(doc))
        return {"status": "UNIVERSAL_NATIVE_UNREGISTER_UNVERIFIED_FIXTURE"}

    @_serialized
    def finish_uninstall(self, *, fault_after: str | None = None) -> dict:
        return self._finish_uninstall_locked(fault_after=fault_after)

    def _finish_uninstall_locked(self, *, fault_after: str | None = None,
                        before_remove=None) -> dict:
        doc = self._load()
        require(doc["phase"] in ("uninstall-prepared", "uninstall-finalizing"),
                "UNIVERSAL_UNINSTALL_NOT_READY")
        require(self._native_uninstalled(doc) is True and
                self.adapter.observed_version() is None,
                "UNIVERSAL_NATIVE_UNINSTALL_RECEIPT_MISSING")
        if doc["phase"] != "uninstall-finalizing":
            require(self.uninstall.uninstall_path.exists(),
                    "UNIVERSAL_UNINSTALL_JOURNAL_MISSING")
            doc["phase"] = "uninstall-finalizing"
            self._write(doc)
        if self.uninstall.uninstall_path.exists():
            self.uninstall.finish(
                lambda: self._native_uninstalled(doc) is True
                and self.adapter.observed_version() is None,
                fault_after=fault_after)
        else:
            require(not self.uninstall.uninstall_path.is_symlink() and
                    not self.code.path.exists() and not self.code.path.is_symlink(),
                    "UNIVERSAL_FINALIZED_JOURNAL_DRIFT")
        require(self._consistent_old() is None,
                "UNIVERSAL_UNINSTALL_SCOPES_NOT_EMPTY")
        if before_remove is not None:
            before_remove("completed_synthetic")
        self._remove()
        return {"status": "UNIVERSAL_UNINSTALL_COMPLETE_FIXTURE_ONLY",
                "native_product_uninstall_accepted": False}

    @_serialized
    def abort_uninstall(self) -> dict:
        return self._abort_uninstall_locked()

    def _abort_uninstall_locked(self, *, before_remove=None) -> dict:
        doc = self._load()
        require(doc["phase"] in UNINSTALL_PHASES and
                doc["phase"] != "uninstall-finalizing",
                "UNIVERSAL_UNINSTALL_FORWARD_REPLAY_REQUIRED")
        intent = self._intent(doc)
        if doc["phase"] != "uninstall-restoring-native":
            self.adapter.quiesce()
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
        if before_remove is not None:
            before_remove("aborted_synthetic")
        self._remove()
        return {"status": "UNIVERSAL_UNINSTALL_ABORT_FIXTURE_ONLY",
                "version": doc["old"],
                "native_product_rollback_accepted": False}

    @_serialized
    def recover(self) -> dict:
        """Replay forward only after explicit native receipt; otherwise abort."""
        return self._recover_locked()

    def _recover_locked(self, *, before_remove=None) -> dict:
        doc = self._load()
        if doc["phase"] in UNINSTALL_PHASES:
            if doc["phase"] == "uninstall-finalizing":
                return self._finish_uninstall_locked(before_remove=before_remove)
            return self._abort_uninstall_locked(before_remove=before_remove)
        if doc["phase"] == "finalizing":
            return self._commit_locked(before_remove=before_remove)
        return self._abort_locked(before_remove=before_remove)

    def _broker_admission_readonly(self, action: str,
                                   expected_intent: dict, sources) -> None:
        """Preflight BEFORE durable replay moves to applying.

        This cannot authenticate a policy, installed broker, or publisher.
        Re-run all state/source checks in the ordinary transaction afterward
        to reject any intervening package or native state drift.
        """
        old = self._consistent_old()
        _, preimage_sha = self._capture(old)
        require(expected_intent["old"] == old and
                expected_intent["preimage_sha256"] == preimage_sha,
                "UNIVERSAL_BROKER_PREIMAGE_DRIFT")
        if action == "uninstall":
            require(old is not None and expected_intent["new"] is None,
                    "UNIVERSAL_BROKER_UNINSTALL_BASELINE_INVALID")
            pins = []
            for name in self.code.names:
                item = self.code._snapshot(name)
                require(item is not None and item["version"] == old,
                        "UNIVERSAL_BROKER_UNINSTALL_SCOPE_DRIFT")
                pins.append({"name": name,
                             "manifest_sha256": item["pin"]})
            require(pins == expected_intent["scope_pins"],
                    "UNIVERSAL_BROKER_UNINSTALL_SCOPE_DRIFT")
        else:
            from .engine import read_package
            require(type(sources) is dict and
                    set(sources) == set(self.code.names),
                    "UNIVERSAL_BROKER_SOURCE_MAP_INVALID")
            packages = [read_package(Path(sources[name][0]).absolute(),
                                     sources[name][1], self.platform)
                        for name in self.code.names]
            target = expected_intent["new"]
            require(all(doc["version"] == target for doc in packages) and
                    (old is None or version(target) > version(old)),
                    "UNIVERSAL_BROKER_TARGET_VERSION_DRIFT")
            pins = [{"name": name, "manifest_sha256": sources[name][1].lower()}
                    for name in self.code.names]
            require(pins == expected_intent["scope_pins"],
                    "UNIVERSAL_BROKER_SOURCE_PIN_DRIFT")

    @_serialized
    def execute_broker_bound(self, ledger, plan, policy_bytes: bytes,
                             policy_pin: str, request_bytes: bytes,
                             expected_intent: dict, sources=None) -> dict:
        """One serialized dispatch of an exact reserved broker request.

        The existing replay ledger and this fixture's native adapter have
        NO OS authority. This API does not accept arbitrary commands or
        acquire privileges. Production must independently authenticate the
        policy, replay ledger and caller, and restrict all mutation to this
        entry point. Unknown outcomes remain reserved for reconciliation.
        """
        from .broker_replay import BrokerReplayFixtureLedger
        from .broker_intent import compare_native_transaction_policy_intent
        require(type(ledger) is BrokerReplayFixtureLedger and
                ledger.control.platform == self.platform,
                "UNIVERSAL_BROKER_LEDGER_REQUIRED")
        binding = compare_native_transaction_policy_intent(
            plan, policy_bytes, policy_pin, request_bytes, expected_intent)
        require(binding["platform"] == self.platform,
                "UNIVERSAL_BROKER_PLATFORM_DRIFT")
        self._no_active()
        action = binding["operation"]
        require((action == "uninstall" and sources is None) or
                (action != "uninstall" and type(sources) is dict),
                "UNIVERSAL_BROKER_SOURCE_MAP_INVALID")
        identity = (binding["request_id"], binding["request_sha256"],
                    binding["policy_sha256"])
        ledger.reserve(plan, policy_bytes, policy_pin, request_bytes)
        # Preserve replay/tombstone precedence, then preflight before
        # applying. On ordinary rejection, tombstone the reserved request
        # without native calls. A hard crash preserves R967 recovery.
        try:
            self._broker_admission_readonly(action, expected_intent, sources)
        except Exception:
            ledger.close_fixture(*identity, outcome="aborted_synthetic",
                                 expected_phase="reserved")
            raise
        ledger.mark_applying_fixture(*identity)
        def terminal(outcome):
            ledger.mark_terminal_fixture(*identity, outcome=outcome)
        # Never close or automatically retry on an exception. The journal
        # and reservation must remain available to exact recovery.
        if action == "uninstall":
            self._begin_uninstall_locked(expected_intent=expected_intent)
            self._apply_uninstall_locked()
            result = self._finish_uninstall_locked(before_remove=terminal)
        else:
            self._begin_locked(sources, expected_intent=expected_intent)
            self._activate_locked()
            result = self._commit_locked(before_remove=terminal)
        ledger.close_fixture(*identity, outcome="completed_synthetic")
        return result

    @_serialized
    def recover_broker_bound(self, ledger, plan, policy_bytes: bytes,
                             policy_pin: str, request_bytes: bytes) -> dict:
        """Reconcile ONLY the matching active reservation and durable journal.

        Without a journal, a never-applied reservation can be aborted, or
        an already persisted terminal result can be retired. An applying
        reservation remains ambiguous and must not be inferred or retried.
        """
        from .broker_replay import BrokerReplayFixtureLedger
        from .broker_intent import compare_native_transaction_policy_intent
        require(type(ledger) is BrokerReplayFixtureLedger and
                ledger.control.platform == self.platform,
                "UNIVERSAL_BROKER_LEDGER_REQUIRED")
        from .broker_intent import compare_pinned_policy_intent
        binding = compare_pinned_policy_intent(
            plan, policy_bytes, policy_pin, request_bytes)
        require(binding["platform"] == self.platform,
                "UNIVERSAL_BROKER_PLATFORM_DRIFT")
        identity = (binding["request_id"], binding["request_sha256"],
                    binding["policy_sha256"])
        active = ledger.recover(*identity)
        phase = active["phase"]
        terminals = ("completed_synthetic", "aborted_synthetic")
        if not self.journal.exists():
            require(phase in terminals or phase == "reserved",
                    "UNIVERSAL_BROKER_NO_JOURNAL_RECONCILE")
            self._no_active()
            if phase == "reserved":
                # The serialized dispatcher has not crossed mark_applying.
                # Compare-and-close under the ledger lock, never invoke native
                # callbacks and retain the request ID in replay history.
                ledger.close_fixture(*identity, outcome="aborted_synthetic",
                                     expected_phase="reserved")
                return {"status": "UNIVERSAL_BROKER_RESERVED_ABORTED_FIXTURE_ONLY",
                        "outcome": "aborted_synthetic",
                        "native_product_installation_accepted": False}
            ledger.close_fixture(*identity, outcome=phase, expected_phase=phase)
            return {"status": "UNIVERSAL_BROKER_TERMINAL_RECONCILED_FIXTURE_ONLY",
                    "outcome": phase, "native_product_installation_accepted": False}
        doc = self._load()
        compare_native_transaction_policy_intent(
            plan, policy_bytes, policy_pin, request_bytes, self._intent(doc))
        forward = doc["phase"] in ("finalizing", "uninstall-finalizing")
        outcome = "completed_synthetic" if forward else "aborted_synthetic"
        require(phase in ("applying", outcome),
                "UNIVERSAL_BROKER_RECOVERY_PHASE_DRIFT")
        def terminal(observed):
            require(observed == outcome, "UNIVERSAL_BROKER_TERMINAL_DRIFT")
            ledger.mark_terminal_fixture(*identity, outcome=observed)
        result = self._recover_locked(before_remove=terminal)
        ledger.close_fixture(*identity, outcome=outcome)
        return result
