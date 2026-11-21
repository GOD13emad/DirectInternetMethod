"""Crash-aware TWO-SCOPE CODE-ONLY uninstall coordinator, offline fixture.

A native adapter must first quiesce services, then unregister ALL native
identities (Inno/SCM or systemd/polkit) before allowing finish().  Callbacks
remain untrusted fixture assertions. In particular, no callback is an OS
authorization token or publisher proof.

Protocol:
  prepare: record old identity -> park both code slots
  abort: permitted only while external registration is still present
  finish: native unregistration observed -> durable forward-only phase ->
          clean both code scopes; replay after one scope was removed
The 'finishing' boundary is irrevocable even when no code was yet removed.
No cross-filesystem atomicity is claimed. User data is NEVER removed.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Mapping

from .engine import (
    Engine, EngineError, atomic_json, durable_dir, load_json,
    require, validate_slot,
)
from .two_scope import TwoScopeFixtureCoordinator


class TwoScopeUninstallFixtureCoordinator(TwoScopeFixtureCoordinator):
    """Independent uninstall journal built on the same deterministic scope map."""

    def __init__(self, journal_root: Path | str, platform: str,
                 roots: Mapping[str, Path | str]):
        super().__init__(journal_root, platform, roots)
        self.uninstall_path = self.control.state / "two_scope_uninstall.json"

    def _check_no_upgrade(self) -> None:
        require(not self.path.exists() and not self.path.is_symlink(),
                "COORDINATOR_UPGRADE_ACTIVE")

    def _uninstall_journal(self) -> dict:
        require(self.uninstall_path.exists() and not self.uninstall_path.is_symlink(),
                "COORDINATOR_UNINSTALL_TRANSACTION_MISSING")
        doc = load_json(self.uninstall_path)
        require(type(doc) is dict and
                set(doc) == {"schema", "phase", "platform", "scopes"} and
                type(doc["schema"]) is int and doc["schema"] == 1 and
                doc["phase"] in {"preparing", "prepared", "finishing"} and
                doc["platform"] == self.platform,
                "COORDINATOR_UNINSTALL_JOURNAL_SCHEMA")
        entries = doc["scopes"]
        require(type(entries) is list and len(entries) == 2,
                "COORDINATOR_UNINSTALL_SCOPE_COUNT")
        require([e.get("name") if type(e) is dict else None for e in entries] ==
                list(self.names), "COORDINATOR_UNINSTALL_SCOPE_ORDER")
        for e in entries:
            require(type(e) is dict and set(e) == {"name", "path", "old"},
                    "COORDINATOR_UNINSTALL_ENTRY_SCHEMA")
            require(e["path"] == str(self.roots[e["name"]]),
                    "COORDINATOR_UNINSTALL_PATH_CHANGED")
            old = e["old"]
            require(type(old) is dict and set(old) == {"version", "pin"} and
                    type(old["pin"]) is str and len(old["pin"]) == 64 and
                    all(c in "0123456789abcdef" for c in old["pin"]),
                    "COORDINATOR_UNINSTALL_PIN_INVALID")
            from .engine import version
            version(old["version"])
        require(len({e["old"]["version"] for e in entries}) == 1,
                "COORDINATOR_UNINSTALL_VERSION_DRIFT")
        return doc

    @staticmethod
    def _true(callback: Callable[[], bool], error: str) -> None:
        require(callable(callback) and callback() is True, error)

    def _preflight(self, journal: dict, *, accepting: bool) -> None:
        """Validate BOTH scopes before any irreversible file deletion."""
        for entry in journal["scopes"]:
            engine = Engine(self.roots[entry["name"]], self.platform)
            with engine.locked():
                require(engine._pending() is None and not engine.staging.exists(),
                        "COORDINATOR_UNINSTALL_UPDATE_CONFLICT")
                transaction = engine._uninstall()
                if transaction is None:
                    require(not engine.current.is_symlink() and
                            not engine.previous.is_symlink(),
                            "COORDINATOR_UNINSTALL_FOREIGN_LINK")
                    if accepting:
                        require(journal["phase"] == "finishing" and
                                not engine.current.exists() and
                                not engine.previous.exists() and
                                engine._installed() is None,
                                "COORDINATOR_UNINSTALL_FINISH_AMBIGUOUS")
                    else:
                        require(not engine.previous.exists() and
                                self._id(engine._installed()) == entry["old"],
                                "COORDINATOR_UNINSTALL_OLD_IDENTITY_DRIFT")
                        state = engine._installed()
                        validate_slot(engine.current, state["manifest"])
                else:
                    require(self._id(transaction["old"]) == entry["old"],
                            "COORDINATOR_UNINSTALL_FOREIGN_JOURNAL")
                    require(not engine.current.exists(),
                            "COORDINATOR_UNINSTALL_CURRENT_SLOT_PRESENT")
                    if accepting:
                        require(transaction["phase"] in {"prepared", "accepted"},
                                "COORDINATOR_UNINSTALL_PHASE_INVALID")
                        if transaction["phase"] == "prepared":
                            require(engine._installed() == transaction["old"] and
                                    engine.previous.exists(),
                                    "COORDINATOR_UNINSTALL_PREPARED_STATE_DRIFT")
                            validate_slot(engine.previous,
                                          transaction["old"]["manifest"])
                        else:
                            # A partially removed previous slot cannot be
                            # silently treated as an intact package. Fail closed.
                            require(not engine.previous.exists() or
                                    self._slot_intact(engine, transaction),
                                    "COORDINATOR_UNINSTALL_ACCEPTED_PARTIAL_SLOT")
                    else:
                        require(transaction["phase"] == "prepared" and
                                engine._installed() == transaction["old"],
                                "COORDINATOR_UNINSTALL_NOT_ABORTABLE")
                        if engine.previous.exists():
                            validate_slot(engine.previous,
                                          transaction["old"]["manifest"])
                        else:
                            validate_slot(engine.current,
                                          transaction["old"]["manifest"])

    @staticmethod
    def _slot_intact(engine: Engine, transaction: dict) -> bool:
        try:
            validate_slot(engine.previous, transaction["old"]["manifest"])
        except EngineError:
            return False
        return True

    def prepare(self, quiescent: Callable[[], bool],
                *, fault_after: str | None = None) -> dict:
        require(fault_after is None or fault_after in self.names,
                "COORDINATOR_UNINSTALL_FAULT_NAME")
        with self.control.locked():
            self._check_no_upgrade()
            require(not self.uninstall_path.exists() and
                    not self.uninstall_path.is_symlink(),
                    "COORDINATOR_UNINSTALL_ALREADY_ACTIVE")
            self._true(quiescent, "COORDINATOR_UNINSTALL_SERVICE_NOT_QUIESCENT")
            entries = []
            for name in self.names:
                snapshot = self._snapshot(name)  # Engine.verify() + hash validation
                require(snapshot is not None,
                        "COORDINATOR_UNINSTALL_SCOPE_NOT_INSTALLED")
                entries.append({"name": name,
                                "path": str(self.roots[name]),
                                "old": snapshot})
            require(len({entry["old"]["version"] for entry in entries}) == 1,
                    "COORDINATOR_UNINSTALL_VERSION_DRIFT")
            journal = {"schema": 1, "phase": "preparing",
                       "platform": self.platform, "scopes": entries}
            atomic_json(self.uninstall_path, journal)
            for name in self.names:
                Engine(self.roots[name], self.platform).prepare_uninstall(lambda: True)
                if fault_after == name:
                    raise EngineError("FIXTURE_INJECTED_AFTER_UNINSTALL_PREPARE_" + name)
            journal["phase"] = "prepared"
            atomic_json(self.uninstall_path, journal)
            return {"status": "PASS_BOTH_SCOPES_UNINSTALL_PREPARED",
                    "version": entries[0]["old"]["version"]}

    def abort(self, quiescent: Callable[[], bool],
              native_still_registered: Callable[[], bool]) -> dict:
        with self.control.locked():
            self._check_no_upgrade()
            journal = self._uninstall_journal()
            require(journal["phase"] in {"preparing", "prepared"},
                    "COORDINATOR_UNINSTALL_FORWARD_ONLY")
            self._true(quiescent, "COORDINATOR_UNINSTALL_SERVICE_NOT_QUIESCENT")
            self._true(native_still_registered,
                       "COORDINATOR_UNINSTALL_NATIVE_REGISTRATION_NOT_PRESENT")
            self._preflight(journal, accepting=False)
            for entry in journal["scopes"]:
                e = Engine(self.roots[entry["name"]], self.platform)
                with e.locked():
                    transaction = e._uninstall()
                if transaction is not None:
                    e.abort_uninstall(lambda: True)
                require(self._snapshot(entry["name"]) == entry["old"],
                        "COORDINATOR_UNINSTALL_RESTORE_MISMATCH")
            self.uninstall_path.unlink()
            durable_dir(self.control.state)
            return {"status": "PASS_BOTH_SCOPES_UNINSTALL_ABORTED"}

    def finish(self, native_unregistered: Callable[[], bool],
               *, fault_after: str | None = None) -> dict:
        require(fault_after is None or fault_after in self.names,
                "COORDINATOR_UNINSTALL_FAULT_NAME")
        with self.control.locked():
            self._check_no_upgrade()
            journal = self._uninstall_journal()
            require(journal["phase"] in {"prepared", "finishing"},
                    "COORDINATOR_UNINSTALL_NOT_PREPARED")
            self._true(native_unregistered,
                       "COORDINATOR_UNINSTALL_NATIVE_NOT_UNREGISTERED")
            self._preflight(journal, accepting=True)
            if journal["phase"] == "prepared":
                journal["phase"] = "finishing"
                atomic_json(self.uninstall_path, journal)
            for entry in journal["scopes"]:
                e = Engine(self.roots[entry["name"]], self.platform)
                with e.locked():
                    tx = e._uninstall()
                if tx is not None:
                    e.finish_uninstall(lambda: True)
                require(e.verify()["status"] == "EMPTY",
                        "COORDINATOR_UNINSTALL_NOT_EMPTY")
                if fault_after == entry["name"]:
                    raise EngineError(
                        "FIXTURE_INJECTED_AFTER_UNINSTALL_FINISH_" + entry["name"])
            self.uninstall_path.unlink()
            durable_dir(self.control.state)
            return {"status": "PASS_BOTH_SCOPES_CODE_ONLY_UNINSTALLED",
                    "data_preserved_by_engine": True}
