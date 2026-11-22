"""Shared, OS-neutral transaction identity and native completion receipt contract.

A receipt MUST be delivered by an independently authenticated native adapter;
parsing and matching this digest is NOT a signature, publisher proof, OS
permission, Inno ssDone or systemd health check. The fixture tests fabricate
receipts on purpose. Privileged bridges must mint their own receipts after
checking native state and protect them across process restarts.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re

from .engine import EngineError, PLATFORMS, require, version

_SHA = re.compile(r"[a-f0-9]{64}\Z")
_RID = re.compile(r"[a-f0-9]{32}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,23}\Z")
MAX_RECEIPT_BYTES = 2048


def validate_intent(intent: object) -> dict:
    require(type(intent) is dict and set(intent) == {
        "schema", "request_id", "platform", "operation", "old", "new",
        "preimage_sha256", "scope_pins"
    } and type(intent["schema"]) is int and intent["schema"] == 1,
        "NATIVE_INTENT_SCHEMA_INVALID")
    require(type(intent["request_id"]) is str and
            _RID.fullmatch(intent["request_id"]) is not None,
            "NATIVE_INTENT_REQUEST_ID_INVALID")
    require(type(intent["platform"]) is str and
            intent["platform"] in PLATFORMS,
            "NATIVE_INTENT_PLATFORM_INVALID")
    require(type(intent["operation"]) is str and
            intent["operation"] in {"install", "upgrade", "uninstall"},
            "NATIVE_INTENT_OPERATION_INVALID")
    require(type(intent["preimage_sha256"]) is str and
            _SHA.fullmatch(intent["preimage_sha256"]) is not None,
            "NATIVE_INTENT_PREIMAGE_PIN_INVALID")
    old, new = intent["old"], intent["new"]
    if old is not None:
        require(type(old) is str, "NATIVE_INTENT_OLD_INVALID")
        version(old)
    if new is not None:
        require(type(new) is str, "NATIVE_INTENT_NEW_INVALID")
        version(new)
    if intent["operation"] == "install":
        require(old is None and new is not None,
                "NATIVE_INTENT_FRESH_INSTALL_INVALID")
    elif intent["operation"] == "upgrade":
        require(old is not None and new is not None and
                version(new) > version(old),
                "NATIVE_INTENT_UPGRADE_INVALID")
    else:
        require(old is not None and new is None,
                "NATIVE_INTENT_UNINSTALL_INVALID")
    pins = intent["scope_pins"]
    require(type(pins) is list and len(pins) == 2,
            "NATIVE_INTENT_TWO_SCOPES_REQUIRED")
    for row in pins:
        require(type(row) is dict and set(row) == {
            "name", "manifest_sha256"
        } and type(row["name"]) is str and
            _NAME.fullmatch(row["name"]) is not None and
            type(row["manifest_sha256"]) is str and
            _SHA.fullmatch(row["manifest_sha256"]) is not None,
            "NATIVE_INTENT_SCOPE_INVALID")
    require(pins[0]["name"] < pins[1]["name"],
            "NATIVE_INTENT_SCOPE_ORDER_INVALID")
    return intent


def intent_sha256(intent: dict) -> str:
    validate_intent(intent)
    canonical = json.dumps(intent, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    out = {}
    for key, value in pairs:
        require(key not in out, "NATIVE_RECEIPT_DUPLICATE_FIELD")
        out[key] = value
    return out


def verify_native_receipt(intent: dict, receipt: bytes | None,
                          *, expected_status: str = "completed") -> bool:
    """Fail closed: no receipt -> False; wrong/malformed/stale -> EngineError.

    Exact digest binds request ID, operation, platform, version transition,
    old native snapshot SHA and BOTH pinned managed code scope manifests.
    """
    require(expected_status in {"completed", "restored"},
            "NATIVE_RECEIPT_EXPECTED_STATUS_INVALID")
    if receipt is None:
        return False
    require(type(receipt) is bytes and
            0 < len(receipt) <= MAX_RECEIPT_BYTES,
            "NATIVE_RECEIPT_SIZE_INVALID")
    try:
        parsed = json.loads(receipt.decode("utf-8"),
                            object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError) as exc:
        raise EngineError("NATIVE_RECEIPT_PARSE_INVALID") from exc
    require(type(parsed) is dict and set(parsed) == {
        "schema", "intent_sha256", "status"
    } and type(parsed["schema"]) is int and parsed["schema"] == 1 and
        parsed["status"] == expected_status and
        type(parsed["intent_sha256"]) is str and
        _SHA.fullmatch(parsed["intent_sha256"]) is not None,
        "NATIVE_RECEIPT_SCHEMA_INVALID")
    require(hmac.compare_digest(parsed["intent_sha256"],
                                intent_sha256(intent)),
            "NATIVE_RECEIPT_INTENT_MISMATCH")
    return True


def verify_completion_receipt(intent: dict, receipt: bytes | None) -> bool:
    return verify_native_receipt(intent, receipt, expected_status="completed")


def verify_restoration_receipt(intent: dict, receipt: bytes | None) -> bool:
    return verify_native_receipt(intent, receipt, expected_status="restored")