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


def prepare(directory: Path) -> None:
    from installer_engine.broker_intent import compare_pinned_policy_intent
    from installer_engine.engine import hash_bytes
    from installer_engine.native_receipt import validate_intent, intent_sha256
    from tests.test_engine_broker_intent import fixture_contract, fixture_plan
    if directory.exists():
        raise ValueError("R938_PREPARE_FRESH_DIRECTORY_REQUIRED")
    directory.mkdir(mode=0o700)
    plan, policy, req, pb, rb = fixture_contract(fixture_plan("linux-x86_64"))
    binding = compare_pinned_policy_intent(plan, pb, hash_bytes(pb), rb)
    if binding["native_installation_accepted"]:
        raise ValueError("R938_SYNTHETIC_POLICY_NOT_PRODUCTION")
    native = {
        "schema": 1, "request_id": req["request_id"],
        "platform": "linux-x86_64", "operation": "upgrade",
        "old": "1.5.6", "new": "1.5.7",
        "preimage_sha256": digest(b"R938_SYNTHETIC_SYSTEMD_PREIMAGE"),
        "scope_pins": req["scopes"],
    }
    validate_intent(native)
    metadata = {
        "schema": 1, "fixture_only": True,
        "expected_peer_uid": os.getuid(), "request_id": req["request_id"],
        "request_sha256": digest(rb), "policy_sha256": digest(pb),
        "native_intent_sha256": intent_sha256(native),
        "native_product_installation_accepted": False,
        "production_privileged_broker_implemented": False,
        "publisher_authenticated": False,
    }
    for name, value in {
        "broker-request.json": rb, "broker-policy.json": pb,
        "native-intent.json": canonical(native),
        "contract.json": canonical(metadata),
    }.items():
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
                                "native_product_installation_accepted": False})
                except (ValueError, KeyError, OSError, TypeError) as error:
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
        expected = ("R938_REQUEST_SHA_MISMATCH" if mode == "tampered"
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
        "polkit_authorized": False,
    }).decode())


def main() -> None:
    parser = argparse.ArgumentParser()
    modes = parser.add_subparsers(dest="mode", required=True)
    for name in ("prepare", "serve", "client", "verify"):
        p = modes.add_parser(name)
        if name in ("prepare", "client", "verify"):
            p.add_argument("--input", type=Path, required=True)
        if name in ("serve", "client"):
            p.add_argument("--root", type=Path, required=True)
        if name == "client":
            p.add_argument("--mode", choices=("good", "tampered", "replay", "wrong-uid"),
                           required=True)
        if name == "verify":
            p.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args.input)
    elif args.mode == "serve":
        serve(args.root)
    elif args.mode == "client":
        client(args.input, args.root, args.mode)
    else:
        verify(args.input, args.output)


if __name__ == "__main__":
    main()
