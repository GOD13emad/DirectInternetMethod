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

from .broker_intent import compare_linux_fd_pinned_intent
from .broker_replay import parse_replay_snapshot
from .engine import EngineError, require
from .linux_trusted_fd import TrustedLinuxRootFD
from .native_plan import NativePlan

STATUS = "READ_ONLY_OS_PROTECTED_POLICY_AND_REPLAY_SNAPSHOT_NOT_AUTHORIZATION"


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
    snapshot = parse_replay_snapshot(
        protected_root.read_pinned_small_file(
            ledger_member, ledger_sha256, ledger_bytes),
        "linux-x86_64")
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
        "status": STATUS,
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
