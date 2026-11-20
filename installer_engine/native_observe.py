"""Read-only native platform observations for future trusted installer adapters.

These probes cannot install/uninstall a service, elevate privileges, certify
publisher provenance or prove an upgrade. Their return values MUST NOT be
used as an authorization token for TwoScopeFixtureCoordinator.finalize().
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Sequence

from .engine import EngineError, no_links, require, version

IDENTITY = "OBSERVATION_ONLY_NOT_NATIVE_INSTALL_ACCEPTANCE"
SERVICE_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,100}\Z")
APPID_RE = re.compile(r"\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}\Z")
UNIT_NAME_RE = re.compile(r"[A-Za-z0-9_.@-]+\.service\Z")


def _service(name: str) -> dict:
    """Windows SCM QueryServiceStatus, not locale-dependent sc.exe parsing."""
    require(os.name == "nt", "WINDOWS_SCM_HOST_REQUIRED")
    require(isinstance(name, str) and SERVICE_NAME_RE.fullmatch(name) is not None,
            "SCM_NAME_INVALID")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
                                     wintypes.DWORD]
    advapi.OpenSCManagerW.restype = wintypes.HANDLE
    advapi.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR,
                                   wintypes.DWORD]
    advapi.OpenServiceW.restype = wintypes.HANDLE

    class SERVICE_STATUS(ctypes.Structure):
        _fields_ = [("dwServiceType", wintypes.DWORD),
                    ("dwCurrentState", wintypes.DWORD),
                    ("dwControlsAccepted", wintypes.DWORD),
                    ("dwWin32ExitCode", wintypes.DWORD),
                    ("dwServiceSpecificExitCode", wintypes.DWORD),
                    ("dwCheckPoint", wintypes.DWORD),
                    ("dwWaitHint", wintypes.DWORD)]

    advapi.QueryServiceStatus.argtypes = [wintypes.HANDLE,
                                         ctypes.POINTER(SERVICE_STATUS)]
    advapi.QueryServiceStatus.restype = wintypes.BOOL
    advapi.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    advapi.CloseServiceHandle.restype = wintypes.BOOL

    manager = advapi.OpenSCManagerW(None, None, 0x0001)
    require(bool(manager), "SCM_MANAGER_READ_DENIED")
    try:
        service = advapi.OpenServiceW(manager, name, 0x0004)
        if not service:
            err = ctypes.get_last_error()
            if err == 1060:
                return {"exists": False, "state": "MISSING"}
            raise EngineError("SCM_SERVICE_READ_DENIED_OR_UNAVAILABLE:" + str(err))
        try:
            result = SERVICE_STATUS()
            require(bool(advapi.QueryServiceStatus(service, ctypes.byref(result))),
                    "SCM_QUERY_STATUS_FAILED")
            states = {1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING",
                      4: "RUNNING", 5: "CONTINUE_PENDING", 6: "PAUSE_PENDING",
                      7: "PAUSED"}
            return {"exists": True,
                    "state": states.get(result.dwCurrentState, "UNKNOWN"),
                    "numeric_state": int(result.dwCurrentState)}
        finally:
            advapi.CloseServiceHandle(service)
    finally:
        advapi.CloseServiceHandle(manager)


def observe_windows(app_id: str, service_name: str) -> dict:
    require(os.name == "nt", "WINDOWS_NATIVE_HOST_REQUIRED")
    require(isinstance(app_id, str) and APPID_RE.fullmatch(app_id) is not None,
            "APP_ID_FORMAT_INVALID")
    from winreg import (HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ,
                        KEY_WOW64_64KEY, OpenKey, QueryValueEx)
    path = ("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" +
            app_id + "_is1")
    registrations = []
    for hive_name, hive in (("HKLM", HKEY_LOCAL_MACHINE),
                            ("HKCU", HKEY_CURRENT_USER)):
        try:
            with OpenKey(hive, path, 0, KEY_READ | KEY_WOW64_64KEY) as k:
                def read(key):
                    try:
                        return QueryValueEx(k, key)[0]
                    except FileNotFoundError:
                        return None
                name = read("DisplayName")
                release = read("DisplayVersion")
                if release is not None:
                    version(release)
                registrations.append({
                    "hive": hive_name, "display_name": name,
                    "display_version": release,
                    "uninstall_command_present": bool(read("UninstallString")),
                })
        except FileNotFoundError:
            continue
    return {
        "status": IDENTITY,
        "platform": "windows-x86_64",
        "service": _service(service_name),
        "registrations": registrations,
        "multiple_registration_roots": len(registrations) != 1,
        "publisher_authenticated": False,
        "native_installation_or_rollback_accepted": False,
    }


def _unit_observation(unit: str, *, systemctl: str = "/usr/bin/systemctl") -> dict:
    require(isinstance(unit, str) and UNIT_NAME_RE.fullmatch(unit) is not None,
            "SYSTEMD_UNIT_NAME_INVALID")
    # A read-only subprocess invocation: no daemon-reload, start, stop or sudo.
    proc = subprocess.run([systemctl, "show", "--no-pager", "--property=LoadState",
                           "--property=ActiveState", unit],
                          capture_output=True, text=True, check=False, timeout=8)
    require(proc.returncode == 0, "SYSTEMD_READ_FAILED:" + unit)
    fields = {}
    for line in proc.stdout.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in {"LoadState", "ActiveState"}:
            require(key not in fields, "SYSTEMD_DUPLICATE_FIELD")
            fields[key] = value
    require(set(fields) == {"LoadState", "ActiveState"},
            "SYSTEMD_INCOMPLETE_OBSERVATION")
    return fields | {"unit": unit}


def observe_linux(protected_root: Path | str, units: Sequence[str]) -> dict:
    require(os.name == "posix", "LINUX_NATIVE_HOST_REQUIRED")
    require(type(units) in (tuple, list) and 1 <= len(units) <= 8,
            "SYSTEMD_UNITS_REQUIRED")
    require(len(set(units)) == len(units), "SYSTEMD_DUPLICATE_UNITS")
    p = Path(protected_root).absolute()
    no_links(p)
    try:
        info = p.lstat()
        owner = int(info.st_uid)
        mode = stat.S_IMODE(info.st_mode)
        trusted = bool(stat.S_ISDIR(info.st_mode) and owner == 0 and
                       not mode & 0o022 and not p.is_symlink())
    except FileNotFoundError:
        owner, mode, trusted = None, None, False
    statuses = [_unit_observation(u) for u in units]
    return {
        "status": IDENTITY,
        "platform": "linux-x86_64",
        "protected_root": str(p),
        "protected_root_uid": owner,
        "protected_root_mode": mode,
        "protected_root_safe_ownership_observed": trusted,
        "units": statuses,
        "publisher_authenticated": False,
        "native_installation_or_rollback_accepted": False,
    }
