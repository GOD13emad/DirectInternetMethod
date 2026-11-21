"""Read-only native OS postflight readiness checks.

This module deliberately NEVER authorizes transaction commit, elevation,
uninstallation, or publishing. Native system state is external evidence, not
an attacker-provided boolean or proof of trusted package provenance.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path

from .engine import EngineError, require, version
from .native_observe import (
    SERVICE_NAME_RE, observe_windows, observe_linux,
)

READINESS = "NATIVE_READONLY_CONSISTENCY_ONLY_NOT_TRANSACTION_ACCEPTANCE"


def windows_service_configuration(service_name: str) -> dict:
    """Query SCM binary command and account via QueryServiceConfigW (read-only)."""
    require(os.name == "nt", "WINDOWS_NATIVE_HOST_REQUIRED")
    require(isinstance(service_name, str) and
            SERVICE_NAME_RE.fullmatch(service_name) is not None,
            "SCM_NAME_INVALID")

    class CONFIG(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wintypes.DWORD),
            ("dwStartType", wintypes.DWORD),
            ("dwErrorControl", wintypes.DWORD),
            ("lpBinaryPathName", wintypes.LPWSTR),
            ("lpLoadOrderGroup", wintypes.LPWSTR),
            ("dwTagId", wintypes.DWORD),
            ("lpDependencies", wintypes.LPWSTR),
            ("lpServiceStartName", wintypes.LPWSTR),
            ("lpDisplayName", wintypes.LPWSTR),
        ]

    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    api.OpenSCManagerW.restype = wintypes.HANDLE
    api.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
    api.OpenServiceW.restype = wintypes.HANDLE
    api.QueryServiceConfigW.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    api.QueryServiceConfigW.restype = wintypes.BOOL
    api.CloseServiceHandle.argtypes = [wintypes.HANDLE]
    api.CloseServiceHandle.restype = wintypes.BOOL

    manager = api.OpenSCManagerW(None, None, 0x0001)
    require(bool(manager), "SCM_MANAGER_READ_DENIED")
    try:
        service = api.OpenServiceW(manager, service_name, 0x0001)
        require(bool(service), "SCM_CONFIG_READ_DENIED_OR_MISSING")
        try:
            needed = wintypes.DWORD(0)
            first = api.QueryServiceConfigW(service, None, 0, ctypes.byref(needed))
            require(not first and ctypes.get_last_error() == 122 and
                    0 < needed.value <= (1 << 20), "SCM_CONFIG_BUFFER_INVALID")
            buffer = ctypes.create_string_buffer(needed.value)
            success = api.QueryServiceConfigW(service, buffer, needed.value,
                                               ctypes.byref(needed))
            require(bool(success), "SCM_CONFIG_QUERY_FAILED")
            conf = ctypes.cast(buffer, ctypes.POINTER(CONFIG)).contents
            return {
                "binary_command": conf.lpBinaryPathName or "",
                "service_account": conf.lpServiceStartName or "",
                "service_type": int(conf.dwServiceType),
                "start_type": int(conf.dwStartType),
            }
        finally:
            api.CloseServiceHandle(service)
    finally:
        api.CloseServiceHandle(manager)


def windows_readiness(app_id: str, service_name: str, *,
                      expected_version: str, expected_binary_command: str,
                      required_service_state: str = "RUNNING") -> dict:
    """Compare independent SCM and Inno facts; not an authorization token."""
    version(expected_version)
    require(isinstance(expected_binary_command, str) and
            expected_binary_command.strip() != "", "EXPECTED_SCM_COMMAND_REQUIRED")
    require(required_service_state in ("RUNNING", "STOPPED"),
            "INVALID_EXPECTED_SERVICE_STATE")
    observation = observe_windows(app_id, service_name)
    config = windows_service_configuration(service_name)
    registrations = observation["registrations"]
    require(observation["service"]["exists"] is True,
            "SCM_SERVICE_MISSING")
    require(observation["service"]["state"] == required_service_state,
            "SCM_SERVICE_STATE_MISMATCH")
    require(config["binary_command"] == expected_binary_command,
            "SCM_BINARY_COMMAND_MISMATCH")
    require(len(registrations) == 1, "INNO_REGISTRATION_COUNT_MISMATCH")
    reg = registrations[0]
    require(reg["display_name"] == "Direct Internet Method" and
            reg["display_version"] == expected_version and
            reg["uninstall_command_present"] is True,
            "INNO_REGISTRATION_IDENTITY_MISMATCH")
    return {"status": READINESS, "platform": "windows-x86_64",
            "version": expected_version, "service": observation["service"],
            "scm_config": config, "registrations": registrations,
            "native_installation_or_rollback_accepted": False}


def linux_readiness(protected_root: Path | str, units: list[str] | tuple[str, ...],
                    *, required_active_units: tuple[str, ...] = ()) -> dict:
    """Read systemd and protected-root ownership, without service mutations."""
    require(type(required_active_units) is tuple and
            len(set(required_active_units)) == len(required_active_units),
            "EXPECTED_ACTIVE_UNITS_INVALID")
    observation = observe_linux(protected_root, units)
    require(observation["protected_root_safe_ownership_observed"] is True,
            "LINUX_PROTECTED_ROOT_UNTRUSTED")
    states = {entry["unit"]: entry for entry in observation["units"]}
    require(all(entry["LoadState"] == "loaded" for entry in states.values()),
            "SYSTEMD_UNIT_NOT_LOADED")
    require(all(u in states for u in required_active_units),
            "EXPECTED_ACTIVE_UNIT_NOT_OBSERVED")
    require(all(states[u]["ActiveState"] == "active" for u in required_active_units),
            "SYSTEMD_UNIT_NOT_ACTIVE")
    return {"status": READINESS, "platform": "linux-x86_64",
            "protected_root": observation["protected_root"],
            "units": observation["units"],
            "native_installation_or_rollback_accepted": False}
