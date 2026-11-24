#!/usr/bin/env python3
"""R938 synthetic Linux systemd root broker receipt parity fixture.

Real systemd system service, kernel SO_PEERCRED, root-only ledger/receipt.
The ROOT service does not import or execute project installation code, install
DIM, authorize a publisher, or invoke a shell for client-provided content.
Only the independently run non-root prepare/verify commands use shared R899,
R901 and R926 Python contracts. Never deploy this fixture as a broker.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

MAX_PACKET = 65536
ROOT_NAME = "/run/dim-r938-synthetic-systemd-broker"
UNIT = "dim-r938-synthetic-broker.service"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_json(path: Path) -> dict:
    raw = path.read_bytes()
    if len(raw) > MAX_PACKET:
        raise ValueError("R938_OVERSIZED_INPUT")
    return json.loads(raw)


def exact_root(root: Path) -> None:
    if str(root) != ROOT_NAME or root.is_symlink():
        raise ValueError("R938_NONCANONICAL_OS_FIXTURE_ROOT")


def atomic_root_json(path: Path, document: dict) -> None:
    if os.geteuid() != 0:
        raise PermissionError("R938_ROOT_REQUIRED")
    if path.is_symlink():
        raise ValueError("R938_UNSAFE_STATE_LEAF")
    fd, tmp = tempfile.mkstemp(prefix=".r938.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical(document) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        dfd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def recv_exact(conn: socket.socket, size: int) -> bytes:
    out = bytearray()
    while len(out) < size:
        piece = conn.recv(size - len(out))
        if not piece:
            raise ValueError("R938_TRUNCATED_PACKET")
        out.extend(piece)
    return bytes(out)


def request(conn: socket.socket) -> bytes:
    n = struct.unpack("<I", recv_exact(conn, 4))[0]
    if n < 1 or n > MAX_PACKET:
        raise ValueError("R938_REQUEST_LENGTH_DENIED")
    return recv_exact(conn, n)


def send(conn: socket.socket, payload: dict) -> None:
    blob = canonical(payload)
    conn.sendall(struct.pack("<I", len(blob)) + blob)


def verify_pinned_native_contract(inputs: Path, meta: dict) -> dict:
    """Verify R899 and R926 together from independently root-custodied inputs.

    In the native R940 service all input files and the code importing this
    function must already be root-owned and non-writable by the socket peer.
    A test-generated pin cannot authenticate an actual publisher.
    """
    from installer_engine.broker_intent import (
        compare_native_transaction_policy_intent, _unique_pairs)
    from installer_engine.native_plan import NativePlan

    def unique_document(name: str) -> dict:
        raw = (inputs / name).read_bytes()
        if not 0 < len(raw) <= MAX_PACKET:
            raise ValueError("R946_INPUT_BYTES_INVALID_" + name)
        doc = json.loads(raw, object_pairs_hook=_unique_pairs)
        if type(doc) is not dict:
            raise ValueError("R946_INPUT_OBJECT_REQUIRED_" + name)
        return doc

    plan_bytes = (inputs / "native-plan.json").read_bytes()
    if digest(plan_bytes) != meta.get("native_plan_sha256"):
        raise ValueError("R946_NATIVE_PLAN_PIN_DRIFT")
    doc = unique_document("native-plan.json")
    if (set(doc) != {"schema", "product", "platform", "version",
                     "source_kind", "scopes"} or
            type(doc["schema"]) is not int or doc["schema"] != 1 or
            type(doc["scopes"]) is not list or len(doc["scopes"]) != 2 or
            any(type(item) is not dict or
                set(item) != {"name", "manifest"} for item in doc["scopes"])):
        raise ValueError("R946_NATIVE_PLAN_SCHEMA_INVALID")
    plan = NativePlan(
        doc["product"], doc["version"], doc["platform"], doc["source_kind"],
        tuple((item["name"], item["manifest"]) for item in doc["scopes"]))
    native = unique_document("native-intent.json")
    if digest(canonical(native)) != meta["native_intent_sha256"]:
        raise ValueError("R946_NATIVE_INTENT_PIN_DRIFT")
    policy = (inputs / "broker-policy.json").read_bytes()
    request_bytes = (inputs / "broker-request.json").read_bytes()
    result = compare_native_transaction_policy_intent(
        plan, policy, meta["policy_sha256"], request_bytes, native)
    if (result["native_intent_sha256"] != meta["native_intent_sha256"]
            or result["request_sha256"] != meta["request_sha256"]
            or result["native_installation_accepted"]):
        raise ValueError("R946_ROOT_BROKER_CONTRACT_INCONSISTENT")
    return result


def prepare(directory: Path, polkit_action: str | None = None) -> None:
    from installer_engine.broker_intent import compare_native_transaction_policy_intent
    from installer_engine.engine import hash_bytes
    from installer_engine.native_receipt import validate_intent, intent_sha256
    from tests.test_engine_broker_intent import (
        fixture_contract, fixture_plan, canonical as broker_canonical,
    )
    if directory.exists():
        raise ValueError("R938_PREPARE_FRESH_DIRECTORY_REQUIRED")
    directory.mkdir(mode=0o700)
    if polkit_action is not None:
        from installer_engine.linux_polkit_authorization import ACTION_RE
        if (not isinstance(polkit_action, str) or
                ACTION_RE.fullmatch(polkit_action) is None):
            raise ValueError("R940_OS_POLKIT_ACTION_INVALID")
    plan, policy, req, _, _ = fixture_contract(fixture_plan("linux-x86_64"))
    # Exactly the SAME full native 256-bit request identifier used by Inno
    # and the existing Windows SCM broker. This is a deterministic isolated
    # test identity, NOT independent installed publisher authorization.
    req["request_id"] = "0123456789abcdef" * 4
    rb = broker_canonical(req)
    policy["request_sha256"] = digest(rb)
    pb = broker_canonical(policy)
    native = {
        "schema": 1, "request_id": req["request_id"],
        "platform": "linux-x86_64", "operation": "upgrade",
        "old": "1.5.6", "new": "1.5.7",
        "preimage_sha256": digest(b"R938_SYNTHETIC_SYSTEMD_PREIMAGE"),
        "scope_pins": req["scopes"],
    }
    validate_intent(native)
    # One exact broker request ID and manifest identity for the R926 native
    # intent; this source check is not a root/publisher authorization.
    binding = compare_native_transaction_policy_intent(
        plan, pb, hash_bytes(pb), rb, native)
    if binding["native_installation_accepted"]:
        raise ValueError("R938_SYNTHETIC_POLICY_NOT_PRODUCTION")
    metadata = {
        "schema": 1, "fixture_only": True,
        "expected_peer_uid": os.getuid(), "request_id": req["request_id"],
        "request_sha256": digest(rb), "policy_sha256": digest(pb),
        "native_intent_sha256": intent_sha256(native),
        "native_product_installation_accepted": False,
        "production_privileged_broker_implemented": False,
        "publisher_authenticated": False,
    }
    if polkit_action is not None:
        # Copied under Root ownership by the isolated CI setup. Never sourced
        # from a socket client. No production publisher is authenticated.
        metadata["polkit_action"] = polkit_action
        synthetic_plan = {
            "schema": 1, "product": plan.product,
            "platform": plan.platform, "version": plan.version,
            "source_kind": plan.source_kind,
            "scopes": [{"name": name, "manifest": manifest}
                       for name, manifest in plan.scopes],
        }
        plan_raw = canonical(synthetic_plan)
        metadata["native_plan_sha256"] = digest(plan_raw)
    payloads = {
        "broker-request.json": rb, "broker-policy.json": pb,
        "native-intent.json": canonical(native),
        "contract.json": canonical(metadata),
    }
    if polkit_action is not None:
        payloads["native-plan.json"] = plan_raw
    for name, value in payloads.items():
        (directory / name).write_bytes(value)
    print(canonical({"status": "R938_SYNTHETIC_INPUTS_READY",
                     "request_sha256": digest(rb),
                     "native_intent_sha256": intent_sha256(native)}).decode())


def check_service_identity() -> None:
    if os.geteuid() != 0:
        raise PermissionError("R938_SERVICE_IS_NOT_ROOT")
    for attempt in range(50):
        result = subprocess.run(["/usr/bin/systemctl", "show", "--property=MainPID",
                                 "--value", UNIT],
                                capture_output=True, text=True, timeout=3)
        if result.returncode == 0 and result.stdout.strip() == str(os.getpid()):
            return
        time.sleep(0.1)
    raise ValueError("R938_SYSTEMD_MAINPID_NOT_OWN_PROCESS")


def serve(root: Path) -> None:
    exact_root(root)
    check_service_identity()
    root_info = os.lstat(root)
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0
            or stat.S_IMODE(root_info.st_mode) != 0o711):
        raise PermissionError("R938_ROOT_DIRECTORY_CUSTODY_INVALID")
    for part, mode in [("state", 0o700), ("inputs", 0o700), ("public", 0o711)]:
        node = root / part
        info = os.lstat(node)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or
                stat.S_IMODE(info.st_mode) != mode):
            raise PermissionError("R938_OS_PROTECTED_ROOT_INVALID_" + part)
    meta = read_json(root / "inputs/contract.json")
    if (meta["schema"] != 1 or meta["fixture_only"] is not True
            or meta["native_product_installation_accepted"] is not False
            or not 0 < meta["expected_peer_uid"] < 2**32):
        raise ValueError("R938_SYNTHETIC_POLICY_INVALID")
    action = meta.get("polkit_action")
    # A disconnected client may leave /proc before pkcheck can inspect its
    # identity. That is a DENIED request, not a fatal root-service exception.
    denied_exceptions = (ValueError, KeyError, OSError, TypeError)
    if action is not None:
        from installer_engine.linux_polkit_authorization import ACTION_RE
        if not isinstance(action, str) or ACTION_RE.fullmatch(action) is None:
            raise ValueError("R940_ROOT_POLICY_ACTION_INVALID")
        contract_info = os.lstat(root / "inputs/contract.json")
        if (not stat.S_ISREG(contract_info.st_mode) or
                contract_info.st_uid != 0 or
                stat.S_IMODE(contract_info.st_mode) != 0o400):
            raise PermissionError("R940_ROOT_ACTION_METADATA_UNTRUSTED")
        from installer_engine.linux_polkit_authorization import (
            observe_linux_polkit_authorization)
        from installer_engine.engine import EngineError
        denied_exceptions += (EngineError,)
        # Actual root service verifies plan, policy and native intent from
        # root-only input bytes. The nonroot prepare check is not sufficient.
        plan_node = root / "inputs/native-plan.json"
        plan_stat = os.lstat(plan_node)
        if (not stat.S_ISREG(plan_stat.st_mode) or plan_stat.st_uid != 0
                or stat.S_IMODE(plan_stat.st_mode) != 0o400):
            raise PermissionError("R946_NATIVE_PLAN_NOT_ROOT_CUSTODIED")
        verify_pinned_native_contract(root / "inputs", meta)
    for name, pinned in (("broker-request.json", meta["request_sha256"]),
                         ("broker-policy.json", meta["policy_sha256"]),
                         ("native-intent.json", meta["native_intent_sha256"])):
        content = (root / "inputs" / name).read_bytes()
        if name == "native-intent.json":
            content = canonical(json.loads(content))
        if digest(content) != pinned:
            raise ValueError("R938_PINNED_INPUT_CHANGED_" + name)
    ledger = root / "state/broker-replay.json"
    receipt = root / "state/native-completed-receipt.json"
    if not ledger.exists():
        atomic_root_json(ledger, {"schema": 1, "platform": "linux-x86_64",
                                  "used_request_ids": [], "active": None})
    sock_path = root / "public/broker.sock"
    if sock_path.exists() or sock_path.is_symlink():
        previous = os.lstat(sock_path)
        if not stat.S_ISSOCK(previous.st_mode) or previous.st_uid != 0:
            raise ValueError("R938_FOREIGN_SOCKET_EXISTS")
        # Restart only after the genuine transient systemd unit replaced its PID.
        sock_path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(sock_path))
        os.chmod(sock_path, 0o666)
        server.listen(3)
        server.settimeout(90)
        while True:
            with server.accept()[0] as conn:
                conn.settimeout(5)
                try:
                    pid, uid, gid = struct.unpack("3i", conn.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    # Kernel identity, never uid/pid from request bytes.
                    if uid != meta["expected_peer_uid"] or pid <= 1:
                        send(conn, {"status": "DENIED", "reason": "R938_KERNEL_UID_DENIED"})
                        continue
                    if action is not None:
                        # Real OS polkit verdict for the *live socket peer*.
                        # No request JSON may select the action or grant access.
                        verdict = observe_linux_polkit_authorization(conn, action)
                        if not verdict.get("polkit_authorized", False):
                            send(conn, {"status": "DENIED",
                                        "reason": "R940_OS_POLKIT_DENIED"})
                            continue
                    raw = request(conn)
                    if digest(raw) != meta["request_sha256"]:
                        send(conn, {"status": "DENIED", "reason": "R938_REQUEST_SHA_MISMATCH"})
                        continue
                    body = json.loads(raw)
                    if body["request_id"] != meta["request_id"]:
                        send(conn, {"status": "DENIED", "reason": "R938_REQUEST_ID_DENIED"})
                        continue
                    state = read_json(ledger)
                    if (state["schema"] != 1 or state["platform"] != "linux-x86_64"
                            or not isinstance(state["used_request_ids"], list)
                            or state["active"] is not None):
                        send(conn, {"status": "DENIED", "reason": "R938_LEDGER_UNSAFE"})
                        continue
                    if meta["request_id"] in state["used_request_ids"]:
                        send(conn, {"status": "DENIED", "reason": "R938_REQUEST_REPLAY_DENIED"})
                        continue
                    state["used_request_ids"].append(meta["request_id"])
                    identity = {
                        "request_id": meta["request_id"],
                        "request_sha256": meta["request_sha256"],
                        "policy_sha256": meta["policy_sha256"],
                        "version": "1.5.7", "operation": "upgrade",
                        "phase": "reserved",
                    }
                    state["active"] = identity
                    atomic_root_json(ledger, state)
                    identity["phase"] = "applying"
                    atomic_root_json(ledger, state)
                    check_service_identity()
                    # Completion attests ONLY this synthetic service's PID/health.
                    atomic_root_json(receipt, {"schema": 1, "status": "completed",
                                    "intent_sha256": meta["native_intent_sha256"]})
                    state["active"] = None
                    atomic_root_json(ledger, state)
                    send(conn, {"status": "COMPLETED_SYNTHETIC_SYSTEMD_POSTFLIGHT",
                                "kernel_peer_uid": uid, "server_euid": os.geteuid(),
                                "service_pid": os.getpid(),
                                "polkit_authorized": action is not None,
                                "native_product_installation_accepted": False})
                except denied_exceptions as error:
                    try:
                        send(conn, {"status": "DENIED", "reason": "R938_FAIL_CLOSED"})
                    except OSError:
                        pass


def client(directory: Path, root: Path, mode: str) -> None:
    exact_root(root)
    raw = (directory / "broker-request.json").read_bytes()
    if mode == "tampered":
        raw = raw[:-1] + (b" " if raw[-1:] != b" " else b"\n")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(8)
        conn.connect(str(root / "public/broker.sock"))
        conn.sendall(struct.pack("<I", len(raw)) + raw)
        response = json.loads(request(conn))
    if mode == "good":
        expected = "COMPLETED_SYNTHETIC_SYSTEMD_POSTFLIGHT"
    else:
        expected = ("R940_OS_POLKIT_DENIED" if mode == "polkit-denied"
                    else "R938_REQUEST_SHA_MISMATCH" if mode == "tampered"
                    else "R938_KERNEL_UID_DENIED" if mode == "wrong-uid"
                    else "R938_REQUEST_REPLAY_DENIED")
        if response.get("reason") != expected:
            raise ValueError("R938_CLIENT_DENIAL_MISMATCH_" + repr(response))
        expected = "DENIED"
    if response["status"] != expected:
        raise ValueError("R938_CLIENT_STATUS_MISMATCH_" + repr(response))
    if mode == "good" and (response["kernel_peer_uid"] != os.getuid()
                           or response["server_euid"] != 0
                           or response["native_product_installation_accepted"]):
        raise ValueError("R938_OS_CLIENT_SERVICE_IDENTITY_MISMATCH")
    print(canonical({"mode": mode, **response}).decode())


def verify(directory: Path, output: Path) -> None:
    from installer_engine.native_receipt import verify_completion_receipt
    from installer_engine.broker_replay import parse_replay_snapshot
    native = read_json(directory / "native-intent.json")
    receipt = (output / "native-completed-receipt.json").read_bytes()
    if not verify_completion_receipt(native, receipt):
        raise ValueError("R938_NATIVE_RECEIPT_INVALID")
    ledger = parse_replay_snapshot((output / "broker-replay.json").read_bytes(),
                                   "linux-x86_64")
    if (ledger["active"] is not None or
            ledger["used_request_ids"] != [native["request_id"]]):
        raise ValueError("R938_NATIVE_ROOT_REPLAY_DRIFT")
    meta = read_json(directory / "contract.json")
    polkit_mode = "polkit_action" in meta
    checks = {}
    for stage, wanted in (("good", "COMPLETED_SYNTHETIC_SYSTEMD_POSTFLIGHT"),
                          ("tampered", "R938_REQUEST_SHA_MISMATCH"),
                          ("replay", "R938_REQUEST_REPLAY_DENIED"),
                          ("wrong-uid", "R938_KERNEL_UID_DENIED"),
                          ("replay-postrestart", "R938_REQUEST_REPLAY_DENIED")):
        result = read_json(output / (stage + ".json"))
        if (result["status"] if stage == "good" else result["reason"]) != wanted:
            raise ValueError("R938_CLIENT_PHASE_MISMATCH_" + stage)
        checks[stage] = "PASS"
        if stage == "good" and (result.get("polkit_authorized", False)
                                is not polkit_mode):
            raise ValueError("R940_NATIVE_OS_POLKIT_RESULT_MISMATCH")
    if polkit_mode:
        no_policy = read_json(output / "polkit-denied.json")
        if (no_policy.get("reason") != "R940_OS_POLKIT_DENIED"
                or no_policy.get("status") != "DENIED"):
            raise ValueError("R940_OS_POLKIT_DEFAULT_DENY_NOT_PROVEN")
        checks["polkit-denied"] = "PASS"
    print(canonical({
        "schema": 1, "status": "PASS_R938_SYNTHETIC_ROOT_SYSTEMD_BROKER_REPLAY",
        "stages": checks, "root_owned_state_replay": True,
        "native_receipt_sha256": digest(receipt),
        "root_ledger_sha256": digest((output / "broker-replay.json").read_bytes()),
        "native_product_installation_accepted": False,
        "production_privileged_broker_implemented": False,
        "publisher_authenticated": False,
        "hard_powercut_reboot_accepted": False,
        "real_two_scope_app_upgrade_accepted": False,
        "polkit_authorized": polkit_mode,
        "os_vendor_policy_allow_and_deny_proved": polkit_mode,
    }).decode())


def main() -> None:
    parser = argparse.ArgumentParser()
    modes = parser.add_subparsers(dest="action", required=True)
    for name in ("prepare", "serve", "client", "verify"):
        p = modes.add_parser(name)
        if name in ("prepare", "client", "verify"):
            p.add_argument("--input", type=Path, required=True)
        if name in ("serve", "client"):
            p.add_argument("--root", type=Path, required=True)
        if name == "prepare":
            p.add_argument("--polkit-action")
        if name == "client":
            p.add_argument("--mode", choices=("good", "tampered", "replay", "wrong-uid",
                                              "polkit-denied"),
                           required=True)
        if name == "verify":
            p.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "prepare":
        prepare(args.input, args.polkit_action)
    elif args.action == "serve":
        serve(args.root)
    elif args.action == "client":
        client(args.input, args.root, args.mode)
    else:
        verify(args.input, args.output)


if __name__ == "__main__":
    main()
