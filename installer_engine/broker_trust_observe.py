"""Read-only Linux native broker trust snapshot, not privileged authorization.

Observe two distinct, root-owned, non-writable files (policy + replay ledger)
through the SAME pinned root directory descriptor with openat2. Reuse the
strict R899 policy/request/two-scope and R901 replay schema validators.

The caller-provided hashes are SYNTHETIC FIXTURE PINS until a trusted
publisher/installed-broker authority provisions them; no app-supplied pin or
successful observation may authorize privileged writes or service control.

This module has NO writes, systemctl/SCM commands, environment trust, privilege
escalation, replay mutation or dynamic executable loading.
"""
from __future__ import annotations

from .broker_intent import (compare_linux_fd_pinned_intent,
                            compare_pinned_policy_intent)
from .broker_replay import parse_replay_snapshot
from .engine import EngineError, require
from .linux_trusted_fd import TrustedLinuxRootFD
from .native_plan import NativePlan
from .windows_handle_bound import (_normalized as _windows_canonical,
                                   read_windows_pinned_small_file)

STATUS = "READ_ONLY_OS_PROTECTED_POLICY_AND_REPLAY_SNAPSHOT_NOT_AUTHORIZATION"
WINDOWS_STATUS = "WIN32_HELD_POLICY_REPLAY_SNAPSHOT_NOT_OS_AUTHORIZED"


def observe_linux_policy_replay_snapshot(
    plan: NativePlan, protected_root: TrustedLinuxRootFD,
    policy_member: str, policy_sha256: str, policy_bytes: int,
    ledger_member: str, ledger_sha256: str, ledger_bytes: int,
    client_request: bytes,
) -> dict:
    """Verify a protected preexisting active request, never process it.

    This is only the observation half of a future OS-authorized native
    broker. A trusted deployment must hard-pin the policy and journal member
    identities outside the untrusted client. The ledger needs a separately
    OS-protected, atomic, handle-bound writer, which does not exist here.
    """
    require(type(protected_root) is TrustedLinuxRootFD,
            "BROKER_SNAPSHOT_TRUSTED_ROOT_HANDLE_REQUIRED")
    require(type(policy_member) is str and type(ledger_member) is str and
            policy_member != ledger_member,
            "BROKER_SNAPSHOT_DISTINCT_MEMBERS_REQUIRED")
    intent = compare_linux_fd_pinned_intent(
        plan, protected_root, policy_member, policy_sha256,
        policy_bytes, client_request)
    return _match_active_snapshot(
        intent, protected_root.read_pinned_small_file(
            ledger_member, ledger_sha256, ledger_bytes),
        ledger_sha256, "linux-x86_64", STATUS)


def _match_active_snapshot(intent: dict, ledger: bytes, ledger_sha256: str,
                           platform: str, status: str) -> dict:
    """Common strict identity check; read-only even for a valid active entry."""
    snapshot = parse_replay_snapshot(ledger, platform)
    active = snapshot["active"]
    require(type(active) is dict, "BROKER_SNAPSHOT_NO_ACTIVE_REQUEST")
    require(active["request_id"] == intent["request_id"] and
            active["request_sha256"] == intent["request_sha256"] and
            active["policy_sha256"] == intent["policy_sha256"] and
            active["version"] == intent["version"] and
            active["operation"] == intent["operation"],
            "BROKER_SNAPSHOT_POLICY_REPLAY_IDENTITY_DRIFT")
    require(active["phase"] in ("reserved", "applying"),
            "BROKER_SNAPSHOT_PHASE_INVALID")
    return {
        "status": status,
        "request_id": intent["request_id"],
        "phase": active["phase"],
        "policy_sha256": intent["policy_sha256"],
        "request_sha256": intent["request_sha256"],
        "ledger_sha256": ledger_sha256.lower(),
        "native_installation_accepted": False,
        "publisher_authenticated": False,
        "privileged_broker_implemented": False,
        "protected_write_performed": False,
    }


def observe_windows_policy_replay_snapshot(
    plan: NativePlan,
    policy_path: str, policy_sha256: str, policy_bytes: int,
    ledger_path: str, ledger_sha256: str, ledger_bytes: int,
    client_request: bytes,
) -> dict:
    """Windows parity with Linux's read-only pinned policy/replay observation.

    Reads each file through a real Win32 handle with denied writer/deleter
    sharing, rejects symlinks/reparse points and checks final file identity.
    Paths, file SHA pins and request are supplied by the caller here: passing
    does NOT authenticate their origin or OS-protect their parent directories.
    A future independently provisioned SCM broker MUST supply protected
    policy identity, ACLs, replay write authority and authenticated receipts.
    """
    require(isinstance(plan, NativePlan) and plan.platform == "windows-x86_64",
            "BROKER_WINDOWS_TARGET_REQUIRED")
    require(type(policy_path) is str and type(ledger_path) is str and
            _windows_canonical(policy_path) != _windows_canonical(ledger_path),
            "BROKER_SNAPSHOT_DISTINCT_MEMBERS_REQUIRED")
    policy = read_windows_pinned_small_file(
        policy_path, policy_bytes, policy_sha256)
    intent = compare_pinned_policy_intent(
        plan, policy, policy_sha256, client_request)
    ledger = read_windows_pinned_small_file(
        ledger_path, ledger_bytes, ledger_sha256)
    result = _match_active_snapshot(
        intent, ledger, ledger_sha256, "windows-x86_64", WINDOWS_STATUS)
    result["os_protected_parent_verified"] = False
    return result
