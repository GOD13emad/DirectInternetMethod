"""R893 Windows Sandbox-only coordinated uninstall with native Inno/SCM readback.

Imports R892 native postflight fixture, adds crash-aware two-scope uninstall.
This is deliberately not an authenticated privileged production adapter.
The executable always returns native_product_install_accepted=False.
"""
from __future__ import annotations

import argparse
import json
import sys

import ScmInnoTwoScopeFixtureEntry as inno
import ScmTwoScopeFixtureEntry as base
from installer_engine.engine import EngineError, require
from installer_engine.native_observe import observe_windows
from installer_engine.two_scope_uninstall import TwoScopeUninstallFixtureCoordinator

FLAG = "SCM_INNO_COORDINATED_UNINSTALL_FIXTURE_OBSERVATION_ONLY"


def installed_and_quiescent(expected_version: str) -> bool:
    obs = observe_windows(inno.APP_ID, base.SERVICE)
    registrations = obs["registrations"]
    svc = obs["service"]
    return (svc["exists"] is True and svc["state"] == "STOPPED" and
            len(registrations) == 1 and registrations[0]["hive"] == "HKLM" and
            registrations[0]["display_name"] == inno.APP_NAME and
            registrations[0]["display_version"] == expected_version and
            registrations[0]["uninstall_command_present"] is True)


def run(args=None) -> int:
    argv = list(sys.argv[1:] if args is None else args)
    if not argv or argv[0] not in (
            "coordinated-uninstall-prepare",
            "coordinated-uninstall-abort",
            "coordinated-uninstall-finish"):
        return base.main(argv)
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=(
        "coordinated-uninstall-prepare",
        "coordinated-uninstall-abort",
        "coordinated-uninstall-finish"))
    p.add_argument("--fault-after", choices=("code",))
    a = p.parse_args(argv)
    ledger, roots = base.roots()
    co = TwoScopeUninstallFixtureCoordinator(ledger, base.PLATFORM, roots)
    if a.action == "coordinated-uninstall-prepare":
        result = co.prepare(lambda: installed_and_quiescent("1.5.7"),
                            fault_after=a.fault_after)
    elif a.action == "coordinated-uninstall-abort":
        require(a.fault_after is None, "ABORT_FAULT_OPTION_REFUSED")
        old_version = co._uninstall_journal()["scopes"][0]["old"]["version"]
        result = co.abort(
            lambda: base.observed("quiescent"),
            lambda: installed_and_quiescent(old_version))
    else:
        # Require native SCM AND Inno deregistration. No boolean from an
        # attacker-supplied CLI flag can bypass these read-only checks.
        result = co.finish(lambda: base.observed("unregistered"),
                           fault_after=a.fault_after)
    print(json.dumps({"status": FLAG, "result": result,
                      "native_product_install_accepted": False},sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(run())
    except (EngineError, OSError, ValueError, KeyError) as err:
        print(json.dumps({
            "status": "FAIL_CLOSED_R893_SYNTHETIC_NATIVE_COORDINATED_UNINSTALL",
            "reason": str(err), "native_product_install_accepted": False
        }, sort_keys=True), file=sys.stderr)
        raise SystemExit(3)
