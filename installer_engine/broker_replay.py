"""Durable *fixture-only* broker request-id ledger; no privilege authority.

This narrow state machine supplements the read-only broker policy/intent
contract. It does not execute native installation, create services, elevate,
authenticate a publisher, or authorize a user to write to a protected root.
In a real broker the ledger directory MUST be installed under an independently
trusted OS-protected identity and all reads/writes must be handle-bound and
OS-authorized; pathname-based Engine locking alone is NOT that identity.

A request cannot be run twice; a crash after durable reserve/applying instead
requires explicit exact request+policy identity recovery. Used IDs are never
silently evicted. When 256 slots are used the fixture fails closed and needs
a separately authenticated policy epoch rotation (NOT implemented here).

The atomic_json primitive uses fsync and directory fsync on POSIX; Windows
power-loss crash consistency, hostile path replacement and host hard reboot
remain open distinct acceptance gates.
"""
from __future__ import annotations

from pathlib import Path
import re

from .broker_intent import compare_pinned_policy_intent
from .engine import Engine, EngineError, SHA_RE, atomic_json, load_json, require
from .native_plan import NativePlan

MAX_USED_REQUEST_IDS = 256
_ID = re.compile(r"[a-f0-9]{32}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_PHASES = frozenset(("reserved", "applying"))
STATUS = "REPLAY_FIXTURE_STATE_ONLY_NO_OS_AUTHORIZATION"


class BrokerReplayFixtureLedger:
    """Single-writer, user-owned test replay ledger, NOT a privileged adapter."""

    def __init__(self, root: str | Path, platform: str):
        self.control = Engine(root, platform)
        self.path = self.control.state / "broker-replay.json"

    def _load(self) -> dict:
        require(not self.path.is_symlink(), "BROKER_REPLAY_SYMLINK_STATE")
        if not self.path.exists():
            return {"schema": 1, "platform": self.control.platform,
                    "used_request_ids": [], "active": None}
        doc = load_json(self.path)
        require(set(doc) == {"schema", "platform", "used_request_ids", "active"} and
                type(doc["schema"]) is int and doc["schema"] == 1 and
                doc["platform"] == self.control.platform,
                "BROKER_REPLAY_SCHEMA_OR_PLATFORM")
        used = doc["used_request_ids"]
        require(type(used) is list and len(used) <= MAX_USED_REQUEST_IDS and
                all(type(key) is str and _ID.fullmatch(key) for key in used) and
                len(set(used)) == len(used),
                "BROKER_REPLAY_USED_IDS_INVALID")
        active = doc["active"]
        if active is not None:
            require(type(active) is dict and
                    set(active) == {"request_id", "request_sha256",
                                    "policy_sha256", "version", "operation",
                                    "phase"},
                    "BROKER_REPLAY_ACTIVE_SCHEMA")
            require(type(active["request_id"]) is str and
                    _ID.fullmatch(active["request_id"]) and
                    active["request_id"] in used,
                    "BROKER_REPLAY_ACTIVE_ID_NOT_RESERVED")
            require(all(type(active[name]) is str and
                        _SHA.fullmatch(active[name])
                        for name in ("request_sha256", "policy_sha256")),
                    "BROKER_REPLAY_ACTIVE_PIN_INVALID")
            require(type(active["phase"]) is str and
                    active["phase"] in _PHASES,
                    "BROKER_REPLAY_PHASE_INVALID")
            require(type(active["operation"]) is str and
                    active["operation"] in ("install", "upgrade", "uninstall"),
                    "BROKER_REPLAY_OPERATION_INVALID")
            from .engine import version
            version(active["version"])
        return doc

    @staticmethod
    def _report(status: str, request_id: str, phase: str) -> dict:
        return {"status": status, "request_id": request_id, "phase": phase,
                "native_installation_accepted": False,
                "publisher_authenticated": False,
                "privileged_broker_implemented": False}

    def reserve(self, plan: NativePlan, policy_bytes: bytes,
                externally_trusted_policy_sha256: str, request_bytes: bytes,
                *, fault_after_save: bool = False) -> dict:
        """Durably reserve a synthetically policy-bound ID *once*.

        Caller-provided policy pin is not a trusted publisher or OS authority.
        A crash AFTER atomic save must be recovered, NOT rerun as a new job.
        """
        intent = compare_pinned_policy_intent(
            plan, policy_bytes, externally_trusted_policy_sha256,
            request_bytes)
        require(intent["native_installation_accepted"] is False,
                "BROKER_REPLAY_NATIVE_ACCEPTANCE_NOT_ALLOWED")
        with self.control.locked():
            doc = self._load()
            require(doc["active"] is None, "BROKER_REPLAY_ACTIVE_FIRST_RECOVER")
            rid = intent["request_id"]
            require(rid not in doc["used_request_ids"],
                    "BROKER_REPLAY_REQUEST_ID_ALREADY_USED")
            require(len(doc["used_request_ids"]) < MAX_USED_REQUEST_IDS,
                    "BROKER_REPLAY_HISTORY_CAPACITY_EXHAUSTED")
            doc["used_request_ids"].append(rid)
            doc["active"] = {
                "request_id": rid,
                "request_sha256": intent["request_sha256"],
                "policy_sha256": intent["policy_sha256"],
                "operation": intent["operation"],
                "version": intent["version"],
                "phase": "reserved",
            }
            atomic_json(self.path, doc)
            if fault_after_save:
                raise EngineError("FIXTURE_INJECTED_AFTER_DURABLE_RESERVE")
            return self._report(STATUS, rid, "reserved")

    def _active_exact(self, doc: dict, request_id: str,
                      request_sha256: str, policy_sha256: str) -> dict:
        require(type(request_id) is str and
                _ID.fullmatch(request_id) is not None,
                "BROKER_REPLAY_ID_REQUIRED")
        require(type(request_sha256) is str and
                _SHA.fullmatch(request_sha256) is not None and
                type(policy_sha256) is str and
                _SHA.fullmatch(policy_sha256) is not None,
                "BROKER_REPLAY_EXACT_PINS_REQUIRED")
        active = doc["active"]
        require(active is not None and
                active["request_id"] == request_id and
                active["request_sha256"] == request_sha256 and
                active["policy_sha256"] == policy_sha256,
                "BROKER_REPLAY_EXACT_ACTIVE_IDENTITY_REQUIRED")
        return active

    def recover(self, request_id: str, request_sha256: str,
                policy_sha256: str) -> dict:
        with self.control.locked():
            doc = self._load()
            active = self._active_exact(
                doc, request_id, request_sha256, policy_sha256)
            return self._report("RECOVERY_REQUIRED_NOT_NEW_PRIVILEGED_WORK",
                                request_id, active["phase"])

    def mark_applying_fixture(self, request_id: str, request_sha256: str,
                              policy_sha256: str, *,
                              fault_after_save: bool = False) -> dict:
        with self.control.locked():
            doc = self._load()
            active = self._active_exact(
                doc, request_id, request_sha256, policy_sha256)
            require(active["phase"] == "reserved",
                    "BROKER_REPLAY_ALREADY_APPLYING_USE_RECOVER")
            active["phase"] = "applying"
            atomic_json(self.path, doc)
            if fault_after_save:
                raise EngineError("FIXTURE_INJECTED_AFTER_DURABLE_APPLYING")
            return self._report(STATUS, request_id, "applying")

    def close_fixture(self, request_id: str, request_sha256: str,
                      policy_sha256: str, *, outcome: str) -> dict:
        """Tombstone request ID in bounded synthetic history; no native PASS."""
        require(type(outcome) is str and
                outcome in ("completed_synthetic", "aborted_synthetic"),
                "BROKER_REPLAY_FIXTURE_OUTCOME_INVALID")
        with self.control.locked():
            doc = self._load()
            active = self._active_exact(
                doc, request_id, request_sha256, policy_sha256)
            require(active["phase"] == "applying" or
                    outcome == "aborted_synthetic",
                    "BROKER_REPLAY_SYNTHETIC_COMPLETION_NOT_APPLYING")
            doc["active"] = None
            atomic_json(self.path, doc)
            return self._report(
                "FIXTURE_REQUEST_TOMBSTONED_NO_NATIVE_ACCEPTANCE",
                request_id, outcome)

    def inspect_fixture(self) -> dict:
        with self.control.locked():
            doc = self._load()
            return {"status": STATUS,
                    "used_ids": len(doc["used_request_ids"]),
                    "active_phase": None if doc["active"] is None
                    else doc["active"]["phase"],
                    "native_installation_accepted": False}
