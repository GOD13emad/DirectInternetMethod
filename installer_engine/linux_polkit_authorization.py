"""Linux OS polkit authorization boundary for an installed privileged broker.

Uses the vendor pkcheck interface (not a home-built polkit protocol). Call only
from an already authenticated, independently installed root-owned broker with
a protected, publisher-approved action ID. The client never supplies action ID,
expected UID or a trusted policy pin.

SO_PEERCRED/ProcFS subject -> pkcheck pid,start-time,uid. This is *one*
authorization decision while the actual socket peer is alive; not a
publisher signature, service installation, receipt or an enduring grant.
A root broker must still pin sources, enforce replay and verify native effects.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import socket
import subprocess
import sys

from .engine import EngineError, require
from .linux_peer_credential import observe_linux_peer_credentials

STATUS = "LINUX_OS_POLKIT_AUTH_CHECK_NOT_PRODUCT_INSTALL"
ACTION_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+){2,}\Z")
PKCHECK = "/usr/bin/pkcheck"


def _subject_proc(pid: int) -> tuple[int, int]:
    """Read kernel proc starttime and current real/effective UID for same PID.

    /proc/PID/stat field 22 is index 19 of fields AFTER closing command ')'.
    Parsing whitespace directly is invalid because comm may contain spaces.
    Fail closed if process exits or the kernel facts cannot be read.
    """
    require(type(pid) is int and pid > 1, "LINUX_POLKIT_PID_INVALID")
    try:
        raw = (Path("/proc") / str(pid) / "stat").read_text("utf-8")
        end = raw.rfind(") ")
        require(end > 0 and raw[:raw.index("(")].strip() == str(pid),
                "LINUX_POLKIT_PROC_STAT_UNTRUSTED")
        tail = raw[end + 2:].split()
        require(len(tail) > 19, "LINUX_POLKIT_PROC_STAT_SHORT")
        start = int(tail[19])
        status = (Path("/proc") / str(pid) / "status").read_text("utf-8")
        line = next(row for row in status.splitlines()
                    if row.startswith("Uid:"))
        fields = line.split()
        require(len(fields) == 5, "LINUX_POLKIT_PROC_UID_FIELDS")
        real, effective = int(fields[1]), int(fields[2])
    except (OSError, UnicodeError, ValueError, StopIteration) as exc:
        raise EngineError("LINUX_POLKIT_PROC_SUBJECT_UNAVAILABLE") from exc
    require(start > 0 and real >= 0 and effective >= 0 and
            real == effective, "LINUX_POLKIT_PROC_UID_UNSAFE")
    return start, real


def observe_linux_polkit_authorization(peer: socket.socket,
                                       installed_action_id: str,
                                       *, allow_user_interaction: bool = False
                                       ) -> dict:
    """Ask polkit about this *live* kernel-identified peer, not request JSON.

    A non-root caller can invoke this for a read-only negative probe. In an
    installed root broker the action ID MUST come from protected installation
    metadata; an arbitrary action ID chosen by a caller does not grant trust.
    OS polkit policy, not this function, controls whether authorization passes.
    """
    require(sys.platform.startswith("linux") and os.name == "posix",
            "LINUX_POLKIT_OS_REQUIRED")
    require(type(installed_action_id) is str and
            ACTION_RE.fullmatch(installed_action_id) is not None and
            len(installed_action_id) <= 160,
            "LINUX_POLKIT_INSTALLED_ACTION_ID_INVALID")
    require(type(allow_user_interaction) is bool,
            "LINUX_POLKIT_INTERACTION_OPTION_INVALID")

    peer_data = observe_linux_peer_credentials(peer)
    pid = peer_data["kernel_peer_pid"]
    uid = peer_data["kernel_peer_uid"]
    start, current_uid = _subject_proc(pid)
    require(current_uid == uid, "LINUX_POLKIT_OS_PEER_UID_DRIFT")
    args = [PKCHECK, "--action-id", installed_action_id, "--process",
            f"{pid},{start},{uid}"]
    if allow_user_interaction:
        args.append("--allow-user-interaction")
    try:
        p = subprocess.run(
            args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False, timeout=6,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        # No installed polkit executable/daemon, hung check, or process error
        # is *never* authorization.
        return {
            "status": STATUS, "polkit_authorized": False,
            "reason": "LINUX_POLKIT_NATIVE_CHECK_UNAVAILABLE",
            "native_installation_accepted": False,
            "publisher_authenticated": False,
            "privileged_broker_implemented": False,
        }
    # Race check: reject exited/replaced process and credential transitions.
    after_start, after_uid = _subject_proc(pid)
    require((after_start, after_uid) == (start, uid),
            "LINUX_POLKIT_SUBJECT_CHANGED_DURING_CHECK")
    require(p.returncode in (0, 1, 2, 3, 126, 127),
            "LINUX_POLKIT_UNEXPECTED_EXIT_STATUS")
    return {
        "status": STATUS, "peer_credentials_native_kernel": True,
        "system_bus_sender_authenticated": False,
        "kernel_peer_pid": pid, "kernel_peer_uid": uid,
        "pid_start_time_ticks": start,
        "polkit_action": installed_action_id,
        "polkit_authorized": p.returncode == 0,
        "polkit_result_code": p.returncode,
        "native_installation_accepted": False,
        "publisher_authenticated": False,
        "privileged_broker_implemented": False,
    }
