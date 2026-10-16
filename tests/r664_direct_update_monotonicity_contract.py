#!/usr/bin/env python3
"""Private Windows RC1 -> future public Stable update release-path contract.

Source-only, no OS/registry/network mutation. The current Windows private RC1
pilot is installed as 1.5.5-rc1 with AssemblyVersion 1.5.5.0 on two hosts.
The original GUI/Service both compare GitHub vX.Y.Z numerically using .NET
System.Version; a published v1.5.5 therefore would NOT trigger a direct update.
"""
from __future__ import annotations
import ast
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
audit = ROOT / "tests" / "release_metadata_audit.py"
tree = ast.parse(audit.read_text(encoding="utf-8-sig"))
nodes = [x for x in tree.body if isinstance(x, ast.FunctionDef)
         and x.name == "require_public_stable_forward_update_from_rc155"]
assert len(nodes) == 1, "MONOTONIC_RELEASE_GUARD_NOT_UNIQUE"
isolated = ast.Module(body=nodes, type_ignores=[])
scope = {"re": re}
exec(compile(isolated, str(audit), "exec"), scope)
guard = scope["require_public_stable_forward_update_from_rc155"]

for version in ("1.5.1", "1.5.3", "1.5.4", "1.5.6", "1.5.7", "2.0.0"):
    guard(version)
for version in ("1.5.5", "1.5.5-rc1", "v1.5.5", "1.5.5.0", "1.5.5junk"):
    try:
        guard(version)
    except SystemExit as exc:
        assert str(exc), version
    else:
        raise AssertionError("UNSAFE_VERSION_WAS_NOT_REJECTED:" + version)

win_release = json.loads((ROOT / "windows/RELEASE.json").read_text("utf-8-sig"))
if win_release.get("version") == "1.5.5-rc1":
    for rel in ("windows/gui/DirectInternetMethod.csproj",
                "windows/service/DirectInternetMethod.Service.csproj"):
        source = (ROOT / rel).read_text("utf-8-sig")
        assert "<AssemblyVersion>1.5.5.0</AssemblyVersion>" in source, rel
    gui = (ROOT / "windows/gui/UpdateClient.cs").read_text("utf-8-sig")
    service = (ROOT / "windows/service/Program.cs").read_text("utf-8-sig")
    assert "latest <= current" in gui, "GUI_UPDATER_COMPARISON_CHANGED_REVALIDATE_GUARD"
    assert "latest <= CurrentVersion" in service, "SERVICE_UPDATER_COMPARISON_CHANGED_REVALIDATE_GUARD"
    assert 'Version.TryParse(clean, out var latest)' in gui
    assert 'Version.TryParse(clean, out var latest)' in service
print("PASS_R664_PUBLIC_MONOTONIC_PROMOTION_GUARD_NEGATIVE_AND_POSITIVE_FIXTURES")