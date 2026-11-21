"""Portable offline transaction CLI; native registration remains a separate gate.

Importing a SHA-pinned source ZIP does not grant OS installation authority.
Flags used to simulate quiescence/native acceptance are fixture-only until
a trusted native adapter produces independent platform evidence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import zipfile

from .archive_import import import_pinned_archive
from .scoped_bundle import materialize_scope_bundle
from .engine import Engine, EngineError


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Direct Internet Method portable installation transaction kernel")
    parser.add_argument("action", choices=(
        "verify", "stage", "activate", "commit", "rollback",
        "uninstall-prepare", "uninstall-commit", "uninstall-abort",
        "import-archive", "materialize-scope"))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--platform",
                        choices=("linux-x86_64", "windows-x86_64"), required=True)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--expected-manifest-sha256")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--archive-sha256")
    parser.add_argument("--archive-kind",
                        choices=("windows-managed", "linux-distribution"))
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--layout", type=Path)
    parser.add_argument("--layout-sha256")
    parser.add_argument("--scope")
    parser.add_argument("--quiesced", action="store_true",
                        help="FIXTURE ONLY: trusted adapter must prove stopped processes")
    parser.add_argument("--accepted", action="store_true",
                        help="FIXTURE ONLY: not proof of registered native service")
    parser.add_argument("--native-unregistered", action="store_true",
                        help="FIXTURE ONLY: not proof of native service removal")
    a = parser.parse_args(argv)
    try:
        runtime = "windows" if sys.platform == "win32" else "linux"
        if not a.platform.startswith(runtime):
            raise EngineError("TARGET_PLATFORM_NOT_THIS_HOST")
        if a.action == "import-archive":
            if (a.root or a.bundle or a.layout or a.layout_sha256 or a.scope or
                    a.quiesced or a.accepted or a.native_unregistered):
                raise EngineError("ARCHIVE_IMPORT_NOT_AN_INSTALL_TRANSACTION")
            if not all((a.archive, a.archive_sha256, a.archive_kind, a.destination)):
                raise EngineError("ARCHIVE_SOURCE_PIN_KIND_DESTINATION_REQUIRED")
            if (a.archive_kind == "windows-managed") != (runtime == "windows"):
                raise EngineError("ARCHIVE_KIND_NOT_FOR_THIS_HOST")
            out = import_pinned_archive(a.archive, a.archive_sha256,
                                        a.destination, a.archive_kind)
            if out["platform"] != a.platform:
                raise EngineError("ARCHIVE_IMPORTED_PLATFORM_MISMATCH")
        elif a.action == "materialize-scope":
            if (a.root or a.archive or a.archive_sha256 or a.archive_kind or
                    a.quiesced or a.accepted or a.native_unregistered):
                raise EngineError("SCOPE_MATERIALIZATION_NOT_NATIVE_TRANSACTION")
            if not all((a.bundle, a.expected_manifest_sha256, a.layout,
                        a.layout_sha256, a.scope, a.destination)):
                raise EngineError("SCOPE_SOURCE_LAYOUT_PINS_AND_DESTINATION_REQUIRED")
            out = materialize_scope_bundle(
                a.bundle, a.expected_manifest_sha256, a.layout,
                a.layout_sha256, a.scope, a.destination, a.platform)
        else:
            if (a.archive or a.archive_sha256 or a.archive_kind or a.destination or
                    a.layout or a.layout_sha256 or a.scope):
                raise EngineError("ARCHIVE_OPTIONS_ONLY_FOR_IMPORT")
            if a.root is None:
                raise EngineError("INSTALLATION_ROOT_REQUIRED")
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
            elif a.action == "rollback":
                out = e.rollback(lambda: a.quiesced)
            elif a.action == "uninstall-prepare":
                out = e.prepare_uninstall(lambda: a.quiesced)
            elif a.action == "uninstall-abort":
                out = e.abort_uninstall(lambda: a.quiesced)
            else:
                out = e.finish_uninstall(lambda: a.native_unregistered)
        print(json.dumps(out, sort_keys=True))
        return 0
    except (EngineError, OSError, ValueError, zipfile.BadZipFile,
            zipfile.LargeZipFile, EOFError, KeyError, TypeError) as exc:
        print(json.dumps({"status": "FAIL_CLOSED", "reason": str(exc)}),
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
