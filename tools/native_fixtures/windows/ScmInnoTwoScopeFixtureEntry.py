"""R892 fixture-only Inno registry observation alongside synthetic SCM two-scope.

No privilege token, no publisher validation, no native production acceptance.
The SCM and installed code checks are delegated to the R891 read-only adapter.
"""
from __future__ import annotations

import json
import sys

import ScmTwoScopeFixtureEntry as base
from installer_engine.native_observe import observe_windows
from installer_engine.engine import require

APP_ID = "{E8039748-26D7-4E64-ACEF-3E24B708B9A2}"
APP_NAME = "DIM R892 Isolated Inno Registry Fixture"

_original = base.observed


def registered(expected: str) -> bool:
    obs = observe_windows(APP_ID, base.SERVICE)
    rows = obs["registrations"]
    if expected == "quiescent":
        # Service stop may happen during uninstall before Inno removal.
        return _original(expected)
    if expected == "unregistered":
        return _original(expected) and len(rows) == 0
    return (_original(expected) and len(rows) == 1 and
            rows[0]["hive"] == "HKLM" and
            rows[0]["display_name"] == APP_NAME and
            rows[0]["display_version"] == expected and
            rows[0]["uninstall_command_present"] is True)


base.observed = registered

if __name__ == "__main__":
    try:
        raise SystemExit(base.main())
    except (ValueError, KeyError, OSError) as err:
        print(json.dumps({
            "status": "FAIL_CLOSED_R892_INNO_SCM_TWO_SCOPE",
            "native_product_install_accepted": False,
            "reason": str(err)
        }), file=sys.stderr)
        raise SystemExit(3)
