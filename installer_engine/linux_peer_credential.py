"""Linux native AF_UNIX peer credential observation, never OS authorization.

Reuse kernel SO_PEERCRED (unix(7)), not an invented identity protocol. It is
a connect-time PID/UID/GID observation. For a real privileged broker this
MUST be combined with an independently installed system D-Bus/polkit action,
stable subject (bus sender or pid,start_time,uid), native protected replay
writer and verified completion receipt. Client-supplied numbers cannot grant
authority and PID recycling is not resolved by this snapshot alone.

No writes, root invocation, system bus call, credential secrets, or services.
"""
from __future__ import annotations

import socket
import struct
import sys

from .engine import require

STATUS = "LINUX_AF_UNIX_KERNEL_PEER_CREDENTIALS_READONLY_NOT_AUTHORIZED"
_CRED_SIZE = struct.calcsize("=iii")


def observe_linux_peer_credentials(
    connection: socket.socket,
    *, expected_uid: int | None = None, expected_pid: int | None = None
) -> dict:
    """Get immutable at-connect kernel credentials, not client JSON identity.

    expected_uid and expected_pid are diagnostic comparisons only, not grants.
    """
    require(sys.platform.startswith("linux") and
            hasattr(socket, "SO_PEERCRED"), "LINUX_OS_PEERCRED_REQUIRED")
    require(isinstance(connection, socket.socket) and
            connection.family == socket.AF_UNIX and
            connection.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) ==
            socket.SOCK_STREAM, "LINUX_PEER_UNIX_STREAM_REQUIRED")
    require(expected_uid is None or
            (type(expected_uid) is int and expected_uid >= 0),
            "LINUX_PEER_EXPECTED_UID_INVALID")
    require(expected_pid is None or
            (type(expected_pid) is int and expected_pid > 0),
            "LINUX_PEER_EXPECTED_PID_INVALID")
    try:
        raw = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, _CRED_SIZE)
    except OSError as exc:
        from .engine import EngineError
        raise EngineError("LINUX_PEER_OS_CREDENTIALS_UNAVAILABLE") from exc
    require(type(raw) is bytes and len(raw) == _CRED_SIZE,
            "LINUX_PEER_OS_CREDENTIALS_SIZE_INVALID")
    pid, uid, gid = struct.unpack("=iii", raw)
    require(pid > 0 and uid >= 0 and gid >= 0,
            "LINUX_PEER_OS_CREDENTIALS_UNTRUSTED")
    require(expected_uid is None or uid == expected_uid,
            "LINUX_PEER_UID_MISMATCH")
    require(expected_pid is None or pid == expected_pid,
            "LINUX_PEER_PID_MISMATCH")
    return {
        "status": STATUS,
        "kernel_peer_pid": pid,
        "kernel_peer_uid": uid,
        "kernel_peer_gid": gid,
        "peer_credentials_native_kernel": True,
        "polkit_authorized": False,
        "system_bus_sender_authenticated": False,
        "privileged_broker_implemented": False,
        "protected_replay_writer_implemented": False,
        "publisher_authenticated": False,
        "native_installation_accepted": False,
    }
