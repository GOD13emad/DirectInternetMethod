"""CLI for portable transaction kernel; platform registration remains native."""
from __future__ import annotations
import argparse
import json
import platform as sys_platform
from pathlib import Path
import sys
from .engine import Engine, EngineError


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Direct Internet Method portable installation transaction kernel")
    parser.add_argument("action", choices=("verify", "stage", "activate", "commit", "rollback"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--platform", choices=("linux-x86_64", "windows-x86_64"), required=True)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--quiesced", action="store_true", help="adapter has stopped/verified all product processes")
    parser.add_argument("--accepted", action="store_true", help="adapter verified native registration, service health and data")
    a = parser.parse_args(argv)
    try:
        runtime = "windows" if sys.platform == "win32" else "linux"
        if not a.platform.startswith(runtime):
            raise EngineError("TARGET_PLATFORM_NOT_THIS_HOST")
        e = Engine(a.root, a.platform)
        if a.action == "stage":
            if not a.bundle or not a.expected_manifest_sha256:
                raise EngineError("BUNDLE_AND_OUT_OF_BAND_SHA_REQUIRED")
            out = e.stage(a.bundle, a.expected_manifest_sha256)
        elif a.action == "verify":
            out = e.verify()
        elif a.action == "activate":
            out = e.activate(lambda: a.quiesced)
        elif a.action == "commit":
            out = e.commit(lambda: a.accepted)
        else:
            out = e.rollback(lambda: a.quiesced)
        print(json.dumps(out, sort_keys=True))
        return 0
    except (EngineError, OSError, ValueError) as exc:
        print(json.dumps({"status": "FAIL_CLOSED", "reason": str(exc)}), file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
