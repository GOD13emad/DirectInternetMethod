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
    require(observation.get("protected_root_ancestor_chain_trusted") is True,
            "LINUX_PROTECTED_ROOT_PARENT_UNTRUSTED")
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


def two_scope_code_postflight(plan: object, roots: dict,
                              native_intent: dict,
                              *, journal_path: Path | str,
                              expected_uids: dict | None = None) -> dict:
    """R947: read the exact 2 active code scopes BEFORE native receipt/commit.

    This verifies the real managed on-disk bytes against the existing pinned
    NativePlan, durable transaction journal and R926 identity, including POSIX file modes.
    It MUST be called under an independently OS-authorized broker's transaction
    lock with roots/pins supplied from trusted installed policy, NOT a client.
    It does not check systemd/SCM, publisher origin, privilege, reboot,
    journal authenticity or native completion. It CANNOT authorize commit.
    """
    import stat
    import base64
    from .broker_intent import _plan_pins
    from .engine import Engine, no_links, load_json, validate_slot, hash_bytes
    from .native_plan import NativePlan
    from .native_receipt import validate_intent, intent_sha256

    require(isinstance(plan, NativePlan) and
            plan.platform in ("linux-x86_64", "windows-x86_64") and
            len(plan.scopes) == 2,
            "R947_TWO_SCOPE_PLAN_REQUIRED")
    validate_intent(native_intent)
    require(native_intent["operation"] in ("install", "upgrade") and
            native_intent["platform"] == plan.platform and
            native_intent["new"] == plan.version,
            "R947_TRANSACTION_TARGET_DRIFT")
    # A file digest and caller-supplied native_intent are insufficient:
    # bind both to the independently identified live durable transaction.
    # The caller MUST supply an OS-protected journal location; this function
    # observes its bytes but cannot certify its UID/ACL or publisher origin.
    jpath = Path(journal_path).absolute()
    no_links(jpath)
    require(jpath.is_file(), "R947_LIVE_JOURNAL_REQUIRED")
    checkpoint = load_json(jpath)
    require(type(checkpoint) is dict and
            set(checkpoint) == {"schema", "platform", "phase", "old", "new",
                                "preimage_b64", "preimage_sha256",
                                "request_id", "scope_pins"} and
            type(checkpoint["schema"]) is int and checkpoint["schema"] == 2 and
            checkpoint["phase"] in ("activated", "finalizing"),
            "R947_LIVE_JOURNAL_NOT_ACTIVATED")
    try:
        original = base64.b64decode(
            checkpoint["preimage_b64"].encode("ascii"), validate=True)
    except (ValueError, AttributeError, UnicodeError) as exc:
        raise EngineError("R947_LIVE_JOURNAL_PREIMAGE_INVALID") from exc
    require(len(original) <= 65536 and
            hash_bytes(original) == checkpoint["preimage_sha256"],
            "R947_LIVE_JOURNAL_PREIMAGE_INVALID")
    require(all(checkpoint[field] == native_intent[field] for field in
                ("platform", "old", "new", "request_id",
                 "scope_pins", "preimage_sha256")) and
            native_intent["operation"] ==
                ("upgrade" if checkpoint["old"] is not None else "install"),
            "R947_LIVE_JOURNAL_INTENT_DRIFT")
    pins = list(_plan_pins(plan))
    require(native_intent["scope_pins"] == pins,
            "R947_TRANSACTION_MANIFEST_PIN_DRIFT")
    names = {name for name, _ in plan.scopes}
    require(type(roots) is dict and set(roots) == names,
            "R947_SCOPE_ROOTS_REQUIRED")
    if expected_uids is not None:
        require(os.name == "posix" and type(expected_uids) is dict and
                set(expected_uids) == names and
                all(type(uid) is int and uid >= 0 for uid in expected_uids.values()),
                "R947_EXPECTED_OWNER_IDS_INVALID")
    locations = {name: Path(roots[name]).absolute() for name in names}
    require(len(set(locations.values())) == 2 and
            all(x != y and x not in y.parents and y not in x.parents
                for x in locations.values() for y in locations.values() if x != y),
            "R947_SCOPE_ROOT_OVERLAP")
    rows = []
    for name, manifest in sorted(plan.scopes):
        root = locations[name]
        no_links(root)
        require(root.is_dir(), "R947_INSTALLED_SCOPE_MISSING")
        engine = Engine(root, plan.platform)
        no_links(engine.installed)
        no_links(engine.current)
        require(engine.installed.is_file(), "R947_MANAGED_REGISTRATION_MISSING")
        installed = load_json(engine.installed)
        require(type(installed) is dict and
                set(installed) == {"schema", "manifest", "manifest_sha256"} and
                installed["schema"] == 1 and
                installed["manifest_sha256"] == next(
                    row["manifest_sha256"] for row in pins if row["name"] == name) and
                installed["manifest"] == manifest,
                "R947_ACTIVE_REGISTRATION_OR_MANIFEST_DRIFT")
        # Unlike Engine.verify(), this is safe while an update is activated
        # and awaiting native completion: previous and pending still exist.
        validate_slot(engine.current, manifest)
        for entry in manifest["files"]:
            member = engine.current / entry["path"]
            no_links(member)
            info = member.lstat()
            if os.name == "posix":
                require(stat.S_IMODE(info.st_mode) == entry["mode"],
                        "R947_MANAGED_FILE_MODE_DRIFT")
            if expected_uids is not None:
                require(info.st_uid == expected_uids[name],
                        "R947_MANAGED_FILE_OWNER_DRIFT")
        if expected_uids is not None:
            require(root.lstat().st_uid == expected_uids[name] and
                    engine.current.lstat().st_uid == expected_uids[name],
                    "R947_SCOPE_ROOT_OWNER_DRIFT")
        rows.append({"scope": name, "files": len(manifest["files"]),
                     "manifest_sha256": installed["manifest_sha256"]})
    return {"status": "R947_READONLY_ACTIVATED_CODE_POSTFLIGHT_ONLY",
            "platform": plan.platform, "version": plan.version,
            "native_intent_sha256": intent_sha256(native_intent),
            "scopes": rows,
            "native_installation_accepted": False,
            "publisher_authenticated": False,
            "os_native_registration_verified": False}


def two_scope_native_postflight(
    plan: object, roots: dict, native_intent: dict, *,
    journal_path: Path | str, expected_uids: dict | None = None,
    linux_units: tuple[str, ...] = (),
    linux_required_active_units: tuple[str, ...] = (),
    windows_app_id: str | None = None,
    windows_service_name: str | None = None,
    windows_expected_binary_command: str | None = None,
    windows_required_service_state: str = "RUNNING",
) -> dict:
    """R950: combine *independent OS observations* with active code/journal.

    Neither OS registration nor matching code confers an installer authority.
    A future protected broker must own all inputs, journal, policy and receipt
    storage, observe state under its transaction lock, and authorize its
    publisher independently before considering native completion.
    """
    from .native_plan import NativePlan
    require(isinstance(plan, NativePlan), "R950_PINNED_NATIVE_PLAN_REQUIRED")
    if plan.platform == "linux-x86_64":
        require(os.name == "posix" and type(linux_units) is tuple and
                bool(linux_units) and
                windows_app_id is None and windows_service_name is None and
                windows_expected_binary_command is None,
                "R950_LINUX_NATIVE_PARAMETERS_INVALID")
    elif plan.platform == "windows-x86_64":
        require(os.name == "nt" and not linux_units and
                not linux_required_active_units and
                all(isinstance(value, str) and value for value in
                    (windows_app_id, windows_service_name,
                     windows_expected_binary_command)),
                "R950_WINDOWS_NATIVE_PARAMETERS_INVALID")
    else:
        raise EngineError("R950_UNSUPPORTED_NATIVE_PLATFORM")

    code = two_scope_code_postflight(
        plan, roots, native_intent, journal_path=journal_path,
        expected_uids=expected_uids)
    if plan.platform == "linux-x86_64":
        protected = "privileged" if "privileged" in roots else "protected"
        require(protected in roots, "R950_PROTECTED_SCOPE_REQUIRED")
        observed = linux_readiness(
            roots[protected], list(linux_units),
            required_active_units=linux_required_active_units)
    else:
        observed = windows_readiness(
            windows_app_id, windows_service_name,
            expected_version=plan.version,
            expected_binary_command=windows_expected_binary_command,
            required_service_state=windows_required_service_state)
    require(code["native_installation_accepted"] is False and
            observed.get("native_installation_or_rollback_accepted") is False,
            "R950_NATIVE_OBSERVATION_MUST_NOT_AUTHORIZE")
    return {
        "status": "R950_COMBINED_CODE_AND_OS_POSTFLIGHT_READONLY_ONLY",
        "platform": plan.platform,
        "version": plan.version,
        "native_intent_sha256": code["native_intent_sha256"],
        "code": code,
        "native": observed,
        "native_installation_accepted": False,
        "publisher_authenticated": False,
    }


def windows_flat_native_postflight(
    build_manifest: Path | str, manifest_sha256: str,
    user_root: Path | str, privileged_root: Path | str,
) -> dict:
    """Observe the existing native Inno layout, without imposing slot paths.

    The manifest pin must originate from an independent build/release record.
    The only product-defined mutable manifest member is providers.json;
    its preservation is a separate native upgrade check, not a code hash.
    This observer does not authorize writes, attest ACLs or issue receipts.
    """
    import json
    from .engine import (MAX_MANIFEST_BYTES, hash_bytes, no_links,
                         regular, relpath)
    from .native_plan import windows_scoped_plan
    from .windows_handle_bound import read_windows_pinned_file

    require(os.name == "nt", "WINDOWS_NATIVE_HOST_REQUIRED")
    source = Path(build_manifest).absolute()
    no_links(source)
    require(regular(source), "R952_BUILD_MANIFEST_MISSING")
    with source.open("rb") as stream:
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
    require(0 < len(raw) <= MAX_MANIFEST_BYTES and
            hash_bytes(raw) == manifest_sha256.lower(),
            "R952_BUILD_MANIFEST_PIN_MISMATCH")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "DUPLICATE_JSON_KEY:" + key)
            result[key] = value
        return result

    plan = windows_scoped_plan(json.loads(raw, object_pairs_hook=unique))
    roots = {"user": Path(user_root).absolute(),
             "privileged": Path(privileged_root).absolute()}
    a, b = roots.values()
    require(a != b and a not in b.parents and b not in a.parents,
            "R952_SCOPE_ROOT_OVERLAP")
    for root in roots.values():
        no_links(root)
        require(root.is_dir(), "R952_INSTALLED_ROOT_MISSING")
    # The build manifest bytes are pinned independently of the installed copy.
    installed_manifest = a / "manifest.json"
    no_links(installed_manifest)
    read_windows_pinned_file(installed_manifest, len(raw), manifest_sha256)

    counts = {}
    mutable = []
    for name, manifest in plan.scopes:
        count = 0
        for item in manifest["files"]:
            target = roots[name].joinpath(*relpath(item["path"]))
            no_links(target)
            require(regular(target), "R952_INSTALLED_MEMBER_MISSING")
            if name == "user" and item["path"] == "app/router_gateway/providers.json":
                mutable.append(item["path"])
                continue
            read_windows_pinned_file(target, item["bytes"], item["sha256"])
            count += 1
        counts[name] = count

    # Inno uses sc.exe create/config with the fixed service executable path.
    # Accept ONLY the two equivalent exact quoted/unquoted binary commands;
    # never accept appended arguments, alternate executable or a foreign path.
    service = "DirectInternetMethodSvc"
    executable = str(b / "app" / "DirectInternetMethod.Service.exe")
    config = windows_service_configuration(service)
    command = config["binary_command"]
    require(command in (executable, '"' + executable + '"'),
            "SCM_BINARY_COMMAND_MISMATCH")
    native = windows_readiness(
        "{B5388E8B-9AF3-41F4-87E2-01C9601A36CB}", service,
        expected_version=plan.version, expected_binary_command=command)
    require(native["registrations"][0]["hive"] == "HKLM" and
            native["scm_config"]["service_account"].casefold() == "localsystem" and
            native["scm_config"]["start_type"] == 2,
            "R952_NATIVE_SERVICE_IDENTITY_MISMATCH")
    return {
        "status": "R952_WINDOWS_FLAT_NATIVE_READONLY",
        "version": plan.version,
        "manifest_sha256": manifest_sha256.lower(),
        "verified_immutable_files": counts,
        "mutable_owner_members_not_hashed_to_source": mutable,
        "native": native,
        "publisher_authenticated": False,
        "native_installation_accepted": False,
    }
