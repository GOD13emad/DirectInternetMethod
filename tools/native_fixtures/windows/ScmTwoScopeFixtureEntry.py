"""R891 Windows Sandbox ONLY: two-scope fixture orchestration with SCM reads.

NOT a production privileged native adapter. Real SCM state and configured
binary are checked using Windows APIs, but neither publisher trust nor
Windows Inno/AppId, ACL, UAC or native rollback are thereby established.
Paths use unique synthetic fixture identities outside installed DIM.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from installer_engine.engine import Engine, EngineError, hash_file, require, validate_slot
from installer_engine.native_observe import _service
from installer_engine.native_readiness import windows_service_configuration
from installer_engine.two_scope import TwoScopeFixtureCoordinator

SERVICE = "DIMR887IsolatedFixtureSvc"
PLATFORM = "windows-x86_64"
FLAG = "SCM_READONLY_FIXTURE_OBSERVATION_NOT_TRUSTED_ACCEPTANCE"


def roots():
    require(sys.platform == "win32", "WINDOWS_ONLY_FIXTURE")
    programdata = os.environ.get("PROGRAMDATA")
    localappdata = os.environ.get("LOCALAPPDATA")
    require(bool(programdata and localappdata),
            "FIXTURE_ENVIRONMENT_ROOT_MISSING")
    program = Path(programdata).absolute()
    user = Path(localappdata).absolute()
    # Names intentionally cannot target any production DIM path.
    code = program / "DIM_R891_Isolated_Code"
    ledger = program / "DIM_R891_Isolated_Journal"
    usr = user / "DIM_R891_Isolated_UserCode"
    return ledger, {"code": code, "user": usr}


def observed(expected: str) -> bool:
    ledger, dirs = roots()
    service = _service(SERVICE)
    if expected == "quiescent":
        return service["state"] in ("STOPPED", "MISSING")
    if expected == "unregistered":
        return service["exists"] is False
    if service["state"] != "RUNNING":
        return False
    config = windows_service_configuration(SERVICE)
    expected_command = str(dirs["code"] / "current" / "app" / "FixtureService.exe")
    if config["binary_command"] != expected_command:
        return False
    if config["service_account"] not in ("LocalSystem", "NT AUTHORITY\\SYSTEM"):
        return False
    code = Engine(dirs["code"], PLATFORM)
    user = Engine(dirs["user"], PLATFORM)
    # A pending ACTIVE transaction cannot call Engine.verify(); inspect
    # its exact new manifest under the Engine lock instead.
    manifests = {}
    for name, engine in (("code", code), ("user", user)):
        with engine.locked():
            pending = engine._pending()
            installed = pending["new"] if pending is not None else engine._installed()
            if installed is None or installed["manifest"]["version"] != expected:
                return False
            validate_slot(engine.current, installed["manifest"])
            manifests[name] = installed["manifest"]
    files = manifests["code"]["files"]
    if len(files) != 1 or files[0]["path"] != "app/FixtureService.exe":
        return False
    binary = dirs["code"] / "current" / "app" / "FixtureService.exe"
    if hash_file(binary) != files[0]["sha256"]:
        return False
    return True


def main(args=None):
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=(
        "prepare", "activate", "abort", "finalize", "verify",
        "uninstall-prepare", "uninstall-commit"))
    p.add_argument("--source", type=Path)
    p.add_argument("--version")
    p.add_argument("--fault-after", choices=("code",))
    p.add_argument("--bad-fixture", action="store_true")
    arguments = p.parse_args(args)
    ledger, dirs = roots()
    coord = TwoScopeFixtureCoordinator(ledger, PLATFORM, dirs)
    op = arguments.action

    if op == "prepare":
        require(arguments.source is not None and arguments.version in ("1.5.6", "1.5.7")
                and (not arguments.bad_fixture or arguments.version == "1.5.7"),
                "SYNTHETIC_SOURCE_AND_VERSION_REQUIRED")
        source = arguments.source.absolute()
        require(source.is_dir(), "FIXTURE_SOURCE_ROOT_NOT_DIRECTORY")
        pins = json.loads((source / "pins.json").read_text("utf-8"))
        require(pins.get("schema") == 1 and pins.get("scope") == "SYNTHETIC_R891",
                "FIXTURE_PINS_INVALID")
        label = arguments.version.replace(".", "_")
        codekey = "code_" + label
        userkey = "user_" + label
        if arguments.bad_fixture and arguments.version == "1.5.7":
            codekey = "code_157_bad"
            userkey = "user_157_bad"
        sources = {}
        for name, key in (("code", codekey), ("user", userkey)):
            sources[name] = (source/key, pins["manifest_sha256"][key])
        result = coord.prepare(sources)
    elif op == "activate":
        require(arguments.source is None and arguments.version is None,
                "ACTIVATION_OPTIONS_REFUSED")
        result = coord.activate(lambda: observed("quiescent"))
    elif op == "abort":
        result = coord.abort(lambda: observed("quiescent"))
    elif op == "finalize":
        require(arguments.version in ("1.5.6", "1.5.7"),
                "NATIVE_RUNNING_VERSION_REQUIRED")
        result = coord.finalize(lambda: observed(arguments.version),
                                fault_after=arguments.fault_after)
    elif op == "verify":
        states = {name: Engine(path, PLATFORM).verify()
                  for name, path in dirs.items()}
        phase = coord._journal()["phase"] if coord.path.exists() else None
        result = {"status": "FIXTURE_DUAL_SCOPE_OBSERVATION_ONLY",
                  "phase": phase,
                  "scopes": {k: {"status": v["status"],
                                 "version": v.get("version")}
                             for k, v in states.items()},
                  "native_acceptance": False,
                  "service": _service(SERVICE)}
    elif op == "uninstall-prepare":
        require(observed("quiescent"), "NATIVE_QUIESCENCE_NOT_OBSERVED")
        result = {name: Engine(path, PLATFORM).prepare_uninstall(
            lambda: observed("quiescent")) for name, path in dirs.items()}
    else:
        require(observed("unregistered"), "NATIVE_UNREGISTRATION_NOT_OBSERVED")
        result = {name: Engine(path, PLATFORM).finish_uninstall(
            lambda: observed("unregistered")) for name, path in dirs.items()}

    print(json.dumps({"status": FLAG, "result": result,
                      "native_product_install_accepted": False},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EngineError, ValueError, KeyError, OSError) as exc:
        print(json.dumps({"status": "FAIL_CLOSED_R891_SYNTHETIC_SCM_DUAL_SCOPE",
                          "reason": str(exc), "native_product_install_accepted": False}),
              file=sys.stderr)
        raise SystemExit(3)
