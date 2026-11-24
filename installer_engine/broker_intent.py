"""OS-independent, read-only *broker intent* / protected policy contract.

Two separate inputs MUST be bound:
  - An externally pinned policy, destined to live under a trusted native
    Administrator/root-owned installed-broker identity (not a user CLI flag).
  - The exact, replay-identifiable request bytes and two code-only manifests.

This module never grants privilege, launches commands, writes code, starts a
service, accepts a native transaction, or authenticates a publisher. Passing
a caller-controlled "expected SHA" is NOT policy authenticity. The eventual
native adapter must acquire the out-of-band policy from a protected OS trust
root by validated directory/file handles, enforce replay and platform
authorization and execute only separately approved service operations.
"""
from __future__ import annotations

import json
import re
from typing import Any

from .engine import (
    EngineError, PRODUCT, PLATFORMS, SHA_RE, hash_bytes,
    manifest_schema, require, version,
)
from .native_plan import NativePlan


MAX_POLICY_BYTES = 65536
MAX_REQUEST_BYTES = 65536
BROKER_STATUS = "READONLY_BROKER_INTENT_BOUND_NOT_NATIVE_AUTHORIZED"
_ALLOWED_OPERATIONS = frozenset(("install", "upgrade", "uninstall"))
_ALLOWED_SOURCE_KINDS = frozenset((
    "INSTALLED_SCOPES_NEED_INNO_SCM",
    "PINNED_CODE_LAYOUT_REQUIRES_TRUSTED_NATIVE_ADAPTER",
))
_NAME_RE = re.compile(r"[a-z][a-z0-9_-]{0,23}\Z")
_REQUEST_ID_RE = re.compile(r"[a-f0-9]{32}(?:[a-f0-9]{32})?\Z")


def _unique_pairs(items: list[tuple[str, Any]]) -> dict:
    out = {}
    for key, val in items:
        require(key not in out, "BROKER_DUPLICATE_JSON_KEY")
        out[key] = val
    return out


def _read(raw: bytes, *, maximum: int, label: str) -> dict:
    require(type(raw) is bytes and 0 < len(raw) <= maximum,
            "BROKER_" + label + "_BYTES_INVALID")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError) as exc:
        raise EngineError("BROKER_" + label + "_MALFORMED") from exc
    require(type(document) is dict, "BROKER_" + label + "_NOT_OBJECT")
    return document


def _scope_rows(scopes: object, *, policy: bool) -> tuple[dict, dict]:
    require(type(scopes) is list and len(scopes) == 2,
            "BROKER_TWO_SCOPE_LIST_REQUIRED")
    expected = {"name", "manifest_sha256", "role"} if policy else {
        "name", "manifest_sha256"
    }
    rows: list[dict] = []
    for row in scopes:
        require(type(row) is dict and set(row) == expected,
                "BROKER_SCOPE_KEYS_INVALID")
        name, digest = row["name"], row["manifest_sha256"]
        require(type(name) is str and _NAME_RE.fullmatch(name) is not None,
                "BROKER_SCOPE_NAME_INVALID")
        require(type(digest) is str and SHA_RE.fullmatch(digest) is not None,
                "BROKER_SCOPE_PIN_INVALID")
        if policy:
            require(type(row["role"]) is str and
                    row["role"] in ("protected", "user"),
                    "BROKER_SCOPE_ROLE_INVALID")
        rows.append(row)
    require(rows[0]["name"] < rows[1]["name"] and
            rows[0]["name"].casefold() != rows[1]["name"].casefold(),
            "BROKER_SCOPE_SORT_DUPLICATE_INVALID")
    if policy:
        require({r["role"] for r in rows} == {"protected", "user"},
                "BROKER_EXACT_ONE_PROTECTED_ONE_USER")
    return rows[0], rows[1]


def _plan_pins(plan: NativePlan) -> tuple[dict, dict]:
    require(isinstance(plan, NativePlan) and
            plan.source_kind in _ALLOWED_SOURCE_KINDS and
            plan.platform in PLATFORMS and
            plan.product == PRODUCT and
            plan.native_adapter_accepted is False,
            "BROKER_PLAN_UNTRUSTED_SOURCE_KIND")
    version(plan.version)
    require(type(plan.scopes) is tuple and len(plan.scopes) == 2,
            "BROKER_PLAN_NOT_TWO_SCOPES")
    rows = []
    for name, manifest in plan.scopes:
        require(type(name) is str and _NAME_RE.fullmatch(name) is not None,
                "BROKER_PLAN_SCOPE_NAME")
        require(type(manifest) is dict and
                manifest_schema(manifest, platform=plan.platform) is not None and
                manifest["product"] == PRODUCT and
                manifest["version"] == plan.version,
                "BROKER_PLAN_SOURCE_IDENTITY_DRIFT")
        raw = (json.dumps(manifest, separators=(",", ":"), sort_keys=True) +
               "\n").encode("utf-8")
        rows.append({"name": name, "manifest_sha256": hash_bytes(raw)})
    rows.sort(key=lambda row: row["name"])
    require(rows[0]["name"] < rows[1]["name"] and
            rows[0]["name"].casefold() != rows[1]["name"].casefold(),
            "BROKER_PLAN_SCOPE_COLLISION")
    return rows[0], rows[1]


def compare_pinned_policy_intent(
    plan: NativePlan, protected_policy_bytes: bytes,
    externally_trusted_policy_sha256: str, client_request_bytes: bytes
) -> dict:
    """Validate exact *intent*, NOT native acceptance or signer authority.

    The caller MUST NOT supply/choose the out-of-band policy pin in production.
    No result of this function may be used alone as a privileged OS decision.
    """
    require(type(externally_trusted_policy_sha256) is str and
            SHA_RE.fullmatch(externally_trusted_policy_sha256) is not None,
            "BROKER_OUT_OF_BAND_POLICY_SHA_REQUIRED")
    require(type(protected_policy_bytes) is bytes and
            0 < len(protected_policy_bytes) <= MAX_POLICY_BYTES,
            "BROKER_POLICY_BYTES_INVALID")
    require(hash_bytes(protected_policy_bytes) == externally_trusted_policy_sha256.lower(),
            "BROKER_PROTECTED_POLICY_PIN_MISMATCH")
    policy = _read(protected_policy_bytes, maximum=MAX_POLICY_BYTES,
                   label="POLICY")
    request = _read(client_request_bytes, maximum=MAX_REQUEST_BYTES,
                    label="REQUEST")
    require(type(policy.get("schema")) is int and policy["schema"] == 1 and
            set(policy) == {"schema", "product", "platform", "version",
                            "operation", "request_sha256", "scopes"},
            "BROKER_POLICY_SCHEMA")
    require(type(request.get("schema")) is int and request["schema"] == 1 and
            set(request) == {"schema", "product", "platform", "version",
                             "operation", "request_id", "scopes"},
            "BROKER_REQUEST_SCHEMA")
    require(type(request["request_id"]) is str and
            _REQUEST_ID_RE.fullmatch(request["request_id"]) is not None,
            "BROKER_REQUEST_ID_INVALID")
    for label, doc in (("POLICY", policy), ("REQUEST", request)):
        require(doc["product"] == PRODUCT and
                type(doc["platform"]) is str and doc["platform"] in PLATFORMS and
                type(doc["version"]) is str and
                type(doc["operation"]) is str and
                doc["operation"] in _ALLOWED_OPERATIONS,
                "BROKER_" + label + "_IDENTITY_INVALID")
        version(doc["version"])
    require(type(policy["request_sha256"]) is str and
            SHA_RE.fullmatch(policy["request_sha256"]) is not None and
            hash_bytes(client_request_bytes) == policy["request_sha256"].lower(),
            "BROKER_REQUEST_BYTES_NOT_POLICY_PINNED")
    require((policy["product"], policy["platform"], policy["version"],
             policy["operation"]) ==
            (request["product"], request["platform"], request["version"],
             request["operation"]),
            "BROKER_POLICY_REQUEST_IDENTITY_DRIFT")
    require((plan.product, plan.platform, plan.version) ==
            (policy["product"], policy["platform"], policy["version"]),
            "BROKER_PLAN_POLICY_IDENTITY_DRIFT")
    trusted = _scope_rows(policy["scopes"], policy=True)
    requested = _scope_rows(request["scopes"], policy=False)
    derived = _plan_pins(plan)
    require(all((a["name"], a["manifest_sha256"].lower()) ==
                (b["name"], b["manifest_sha256"].lower()) ==
                (c["name"], c["manifest_sha256"].lower())
                for a, b, c in zip(trusted, requested, derived)),
            "BROKER_POLICY_REQUEST_PLAN_SCOPE_PIN_DRIFT")
    return {
        "status": BROKER_STATUS,
        "platform": plan.platform,
        "version": plan.version,
        "operation": request["operation"],
        "request_id": request["request_id"],
        "policy_sha256": hash_bytes(protected_policy_bytes),
        "request_sha256": hash_bytes(client_request_bytes),
        "native_installation_accepted": False,
        "publisher_authenticated": False,
        "privileged_broker_implemented": False,
    }


def compare_linux_fd_pinned_intent(
    plan: NativePlan,
    linux_root_handle: object,
    policy_member: str,
    externally_trusted_policy_sha256: str,
    expected_policy_bytes: int,
    client_request_bytes: bytes,
) -> dict:
    """OS-bound *read-only* Linux policy+intent preflight.

    The root directory must already have been acquired from an Admin/root
    controlled location. No user-supplied path or SHA can constitute a native
    OS authorization, and this method intentionally returns acceptance=False.
    """
    from .linux_trusted_fd import TrustedLinuxRootFD
    require(isinstance(linux_root_handle, TrustedLinuxRootFD),
            "BROKER_LINUX_ROOT_HANDLE_REQUIRED")
    require(isinstance(plan, NativePlan) and
            plan.platform == "linux-x86_64",
            "BROKER_LINUX_TARGET_REQUIRED")
    raw_policy = linux_root_handle.read_pinned_small_file(
        policy_member, externally_trusted_policy_sha256,
        expected_policy_bytes)
    result = compare_pinned_policy_intent(
        plan, raw_policy, externally_trusted_policy_sha256,
        client_request_bytes)
    require(result["native_installation_accepted"] is False and
            result["privileged_broker_implemented"] is False,
            "BROKER_UNEXPECTED_NATIVE_AUTHORITY")
    return result


def compare_native_transaction_policy_intent(
    plan: NativePlan, protected_policy_bytes: bytes,
    externally_trusted_policy_sha256: str, client_request_bytes: bytes,
    native_transaction_intent: dict,
) -> dict:
    """Bind R899 broker request to the SAME R926 transaction identity.

    This is a read-only, OS-neutral consistency check. The native intent
    MUST originate from the installer's actual verified durable journal,
    not from client JSON. That provenance and the policy pin's ownership
    MUST be established by a trusted OS adapter; this function does neither.
    In particular, matched hashes cannot mint a native completion receipt.
    """
    from .native_receipt import validate_intent, intent_sha256

    result = compare_pinned_policy_intent(
        plan, protected_policy_bytes, externally_trusted_policy_sha256,
        client_request_bytes)
    validate_intent(native_transaction_intent)
    request = _read(client_request_bytes, maximum=MAX_REQUEST_BYTES,
                    label="REQUEST")
    require(request["request_id"] == native_transaction_intent["request_id"],
            "BROKER_NATIVE_REQUEST_ID_DRIFT")
    require((request["platform"], request["operation"]) ==
            (native_transaction_intent["platform"],
             native_transaction_intent["operation"]),
            "BROKER_NATIVE_TRANSITION_DRIFT")
    target_version = (native_transaction_intent["new"]
                      if native_transaction_intent["new"] is not None
                      else native_transaction_intent["old"])
    require(request["version"] == target_version,
            "BROKER_NATIVE_RELEASE_DRIFT")
    require(request["scopes"] == native_transaction_intent["scope_pins"],
            "BROKER_NATIVE_SCOPE_PIN_DRIFT")
    require(result["native_installation_accepted"] is False and
            result["publisher_authenticated"] is False,
            "BROKER_NATIVE_AUTHORITY_UNEXPECTED")
    return {
        **result,
        "status": "READONLY_BROKER_NATIVE_TRANSACTION_BOUND_NOT_AUTHORIZED",
        "native_intent_sha256": intent_sha256(native_transaction_intent),
    }
