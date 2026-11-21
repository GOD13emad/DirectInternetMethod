"""Crash-recoverable coordination of independently managed code scopes.

PROTOTYPE ONLY. This coordinates Engine *file* transactions, not a native
Windows Inno/SCM or Linux root/systemd installation. A native adapter must
quiesce affected services, verify registration, and prove acceptance through
OS APIs. A callback returning True is insufficient native evidence.

There is no cross-volume atomic rename: before finalization, all pending
scopes may be rolled back; once finalization begins, it must be replayed
FORWARD to converge, never rolled back after one old slot is removed.
"""
from __future__ import annotations

from pathlib import Path
import re
from typing import Callable, Mapping

from .engine import (
    Engine, EngineError, atomic_json, durable_dir, hash_file, load_json,
    no_links, read_package, require, validate_slot, version,
)


class TwoScopeFixtureCoordinator:
    """Deterministic dual-scope file-only coordinator for offline V&V."""

    def __init__(self, journal_root: Path | str, platform: str,
                 roots: Mapping[str, Path | str]):
        require(type(roots) is dict and len(roots) == 2,
                "EXACTLY_TWO_SCOPES_REQUIRED")
        require(all(isinstance(name, str) and
                    re.fullmatch(r"[a-z][a-z0-9_-]{0,23}", name)
                    for name in roots), "INVALID_SCOPE_NAME")
        require(len({name.casefold() for name in roots}) == 2,
                "SCOPE_NAME_COLLISION")
        self.platform = platform
        self.journal_root = Path(journal_root).absolute()
        self.roots = {k: Path(v).absolute() for k, v in roots.items()}
        all_roots = [self.journal_root, *self.roots.values()]
        for p in all_roots:
            no_links(p)
        for i, first in enumerate(all_roots):
            for second in all_roots[i+1:]:
                require(first != second and first not in second.parents and
                        second not in first.parents, "COORDINATOR_SCOPE_ROOT_OVERLAP")
        require(len({str(v).casefold() for v in all_roots}) == 3,
                "COORDINATOR_ROOT_CASEFOLD_COLLISION")
        self.names = tuple(sorted(self.roots))
        self.control = Engine(self.journal_root, platform)
        self.path = self.control.state / "two_scope.json"

    def _journal(self) -> dict:
        require(self.path.exists(), "COORDINATOR_TRANSACTION_MISSING")
        doc = load_json(self.path)
        require(set(doc) == {"schema", "phase", "platform", "scopes"} and
                type(doc["schema"]) is int and doc["schema"] == 1 and
                doc["phase"] in ("staging", "staged", "activating",
                                 "activated", "finalizing") and
                doc["platform"] == self.platform, "COORDINATOR_JOURNAL_SCHEMA")
        entries = doc["scopes"]
        require(type(entries) is list and len(entries) == 2,
                "COORDINATOR_JOURNAL_SCOPE_COUNT")
        require(all(type(e) is dict for e in entries),
                "COORDINATOR_JOURNAL_SCOPE_ENTRY_TYPE")
        require([e.get("name") for e in entries] == list(self.names),
                "COORDINATOR_JOURNAL_SCOPE_ORDER")
        for entry in entries:
            require(type(entry) is dict and
                    set(entry) == {"name", "path", "old", "new"},
                    "COORDINATOR_ENTRY_SCHEMA")
            require(entry["path"] == str(self.roots[entry["name"]]),
                    "COORDINATOR_PATH_TAMPERED")
            for side in ("old", "new"):
                v = entry[side]
                if side == "old" and v is None:
                    continue
                require(type(v) is dict and set(v) == {"version", "pin"} and
                        type(v["pin"]) is str and len(v["pin"]) == 64 and
                        all(c in "0123456789abcdef" for c in v["pin"]),
                        "COORDINATOR_STATE_PIN_INVALID")
                version(v["version"])
        require(len({e["new"]["version"] for e in entries}) == 1,
                "COORDINATOR_NEW_VERSION_CONFLICT")
        return doc

    @staticmethod
    def _id(state: dict | None) -> dict | None:
        if state is None:
            return None
        return {"version": state["manifest"]["version"],
                "pin": state["manifest_sha256"]}

    def _snapshot(self, name: str) -> dict | None:
        e = Engine(self.roots[name], self.platform)
        e.verify()
        with e.locked():
            return self._id(e._installed())

    def prepare(self, sources: Mapping[str, tuple[Path | str, str]],
                *, fault_after: str | None = None) -> dict:
        require(type(sources) is dict and set(sources) == set(self.names),
                "SCOPE_SOURCE_KEYS_REQUIRED")
        require(fault_after is None or fault_after in self.names,
                "INVALID_FAULT_SCOPE")
        with self.control.locked():
            require(not self.path.exists() and not self.path.is_symlink(),
                    "COORDINATOR_ACTIVE_TRANSACTION")
            entries = []
            for name in self.names:
                source, pin = sources[name]
                old = self._snapshot(name)
                new = read_package(Path(source).absolute(), pin, self.platform)
                require(old is None or
                        version(new["version"]) > version(old["version"]),
                        "COORDINATOR_DOWNGRADE_OR_SAME_VERSION")
                entries.append({"name": name, "path": str(self.roots[name]),
                                "old": old,
                                "new": {"version": new["version"],
                                        "pin": pin.lower()}})
            require(len({entry["new"]["version"] for entry in entries}) == 1,
                    "COORDINATOR_NEW_VERSION_CONFLICT")
            journal = {"schema": 1, "phase": "staging",
                       "platform": self.platform, "scopes": entries}
            atomic_json(self.path, journal)
            for name in self.names:
                source, pin = sources[name]
                Engine(self.roots[name], self.platform).stage(source, pin)
                if name == fault_after:
                    raise EngineError("FIXTURE_INJECTED_AFTER_STAGE_" + name)
            journal["phase"] = "staged"
            atomic_json(self.path, journal)
            return {"status": "PASS_BOTH_SCOPES_STAGED",
                    "version": entries[0]["new"]["version"]}

    def activate(self, quiesced: Callable[[], bool],
                 *, fault_after: str | None = None) -> dict:
        require(fault_after is None or fault_after in self.names,
                "INVALID_FAULT_SCOPE")
        with self.control.locked():
            journal = self._journal()
            require(journal["phase"] == "staged", "COORDINATOR_NOT_STAGED")
            require(callable(quiesced) and quiesced() is True,
                    "NATIVE_QUIESCENCE_NOT_PROVEN")
            journal["phase"] = "activating"
            atomic_json(self.path, journal)
            for name in self.names:
                Engine(self.roots[name], self.platform).activate(lambda: True)
                if name == fault_after:
                    raise EngineError("FIXTURE_INJECTED_AFTER_ACTIVATE_" + name)
            journal["phase"] = "activated"
            atomic_json(self.path, journal)
            return {"status": "PASS_BOTH_SCOPES_ACTIVATED_PENDING_NATIVE",
                    "version": journal["scopes"][0]["new"]["version"]}

    def abort(self, quiesced: Callable[[], bool]) -> dict:
        with self.control.locked():
            journal = self._journal()
            require(journal["phase"] in ("staging", "staged",
                                         "activating", "activated"),
                    "COORDINATOR_FORWARD_RECOVERY_REQUIRED")
            require(callable(quiesced) and quiesced() is True,
                    "NATIVE_QUIESCENCE_NOT_PROVEN")
            for entry in journal["scopes"]:
                engine = Engine(self.roots[entry["name"]], self.platform)
                with engine.locked():
                    pending = engine._pending()
                    if pending is not None:
                        require(self._id(pending["new"]) == entry["new"] and
                                self._id(pending["old"]) == entry["old"],
                                "COORDINATOR_FOREIGN_PENDING_TRANSACTION")
                if pending is not None:
                    engine.rollback(lambda: True)
                require(self._snapshot(entry["name"]) == entry["old"],
                        "COORDINATOR_OLD_STATE_NOT_RESTORED")
            self.path.unlink()
            durable_dir(self.control.state)
            return {"status": "PASS_BOTH_SCOPES_ROLLED_BACK"}

    def finalize(self, native_accepted: Callable[[], bool],
                 *, fault_after: str | None = None) -> dict:
        """File cleanup after external native acceptance, not proof of it.

        A partially finalized transaction can only converge forward after
        independent native acceptance is re-established by the caller.
        """
        require(fault_after is None or fault_after in self.names,
                "INVALID_FAULT_SCOPE")
        with self.control.locked():
            journal = self._journal()
            require(journal["phase"] in ("activated", "finalizing"),
                    "COORDINATOR_NOT_ACTIVATED")
            require(callable(native_accepted) and native_accepted() is True,
                    "NATIVE_ACCEPTANCE_NOT_PROVEN")
            for entry in journal["scopes"]:
                engine = Engine(self.roots[entry["name"]], self.platform)
                with engine.locked():
                    pending = engine._pending()
                    if pending is not None:
                        require(self._id(pending["new"]) == entry["new"] and
                                self._id(pending["old"]) == entry["old"] and
                                self._id(engine._installed()) == entry["new"] and
                                not engine.staging.exists(),
                                "COORDINATOR_NOT_ACTIVATED_CONSISTENTLY")
                        # Verify ALL active slots before the first irreversible
                        # old-slot deletion; otherwise scope A could commit and
                        # scope B fail integrity, preventing a global rollback.
                        validate_slot(engine.current, pending["new"]["manifest"])
                    else:
                        # A prior finalize replay may already have removed the
                        # previous slot. Do not reacquire this Windows byte-lock
                        # recursively, which would fail with LOCK_NBLCK.
                        current = engine._installed()
                        require(journal["phase"] == "finalizing" and
                                self._id(current) == entry["new"] and
                                not engine.staging.exists() and
                                not engine.previous.exists(),
                                "COORDINATOR_COMMIT_STATE_AMBIGUOUS")
                        validate_slot(engine.current, current["manifest"])
            if journal["phase"] == "activated":
                journal["phase"] = "finalizing"
                atomic_json(self.path, journal)
            for entry in journal["scopes"]:
                engine = Engine(self.roots[entry["name"]], self.platform)
                with engine.locked():
                    pending = engine._pending()
                if pending is not None:
                    engine.commit(lambda: True)
                require(self._snapshot(entry["name"]) == entry["new"],
                        "COORDINATOR_FINAL_PIN_MISMATCH")
                if entry["name"] == fault_after:
                    raise EngineError("FIXTURE_INJECTED_AFTER_FINALIZE_" +
                                      entry["name"])
            self.path.unlink()
            durable_dir(self.control.state)
            return {"status": "PASS_BOTH_SCOPES_COMMITTED_CODE_ONLY",
                    "version": journal["scopes"][0]["new"]["version"]}
