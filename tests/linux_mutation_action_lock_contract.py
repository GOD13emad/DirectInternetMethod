#!/usr/bin/env python3
"""Fail-closed exclusive Start/Stop/Recovery locking on a temporary mock lockfile.

No helper entrypoint, networking, root-owned files, or system service executed.
"""
from __future__ import annotations
import os
import pathlib
import re
import shlex
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "linux/app/direct_method_helper.sh").read_text(encoding="utf-8")


def function(name: str) -> str:
    matches = re.findall(r"^" + re.escape(name) + r"\(\)\{\n.*?^\}\n", SOURCE, re.S | re.M)
    assert len(matches) == 1, (name, "MISSING_OR_AMBIGUOUS_FUNCTION")
    return matches[0]


guard = function("acquire_action_lock")
assert 'local lock_path="/run/directinternetmethod-action.lock"' in guard
assert 'flock -n "$DIM_ACTION_LOCK_FD"' in guard
assert "ACTION_ALREADY_RUNNING" in guard
assert "ACTION_LOCK_UNAVAILABLE" in guard
assert '[ -L "$lock_path" ]' in guard

for action in ("stop", "recovery", "start"):
    matches = re.findall(
        r"^  " + action + r"\)\n.*?^    ;;\n", SOURCE, re.M | re.S
    )
    assert len(matches) == 1, ("ACTION_CASE_NOT_UNIQUE", action)
    branch = matches[0]
    a = branch.index("require_root")
    b = branch.index("acquire_action_lock")
    assert a < b, ("LOCK_BEFORE_PRIVILEGE_OR_MISSING", action)
    if action == "start":
        assert b < branch.index("trap rollback_on_exit EXIT"), "START_TRAP_PRECEDES_LOCK"
    elif action == "stop":
        assert b < branch.index('if [ ! -f "$STATE" ]'), "STOP_STATE_MUTATION_BEFORE_LOCK"
    else:
        assert b < branch.index('if [ -f "$STATE" ]'), "RECOVERY_STATE_ACTION_BEFORE_LOCK"
print("PASS start/stop/recovery acquire the same mandatory lock before mutation")

with tempfile.TemporaryDirectory(prefix="dim_action_lock_qa_") as tmp:
    lock = pathlib.Path(tmp) / "action.lock"
    expected = pathlib.Path(tmp) / "do-not-modify.txt"
    expected.write_text("SAFE_ORIGINAL\n", encoding="utf-8")
    fragment = guard.replace(
        'local lock_path="/run/directinternetmethod-action.lock"',
        'local lock_path=' + shlex.quote(str(lock)),
    )
    assert fragment != guard and str(lock) in fragment
    env = os.environ.copy()
    script = (
        "set -euo pipefail\n"
        "DIM_ACTION_LOCK_FD=''\n" + fragment +
        "\nacquire_action_lock\nprintf 'LOCK_ACQUIRED\\n'\n"
    )
    holder = subprocess.Popen(
        ["bash", "-c", script + "sleep 0.6\n"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "LOCK_ACQUIRED", "HOLDER_COULD_NOT_LOCK"
        assert holder.poll() is None, "HOLDER_EXITED_EARLY"
        contender = subprocess.run(
            ["bash", "-c", script],
            capture_output=True, text=True, timeout=5, env=env,
        )
        assert contender.returncode == 86, ("CONCURRENT_MUTATION_ACCEPTED", contender.returncode, contender.stdout, contender.stderr)
        assert "ACTION_ALREADY_RUNNING" in contender.stderr
        print("PASS overlapping mutating actions fail closed with ACTION_ALREADY_RUNNING")
    finally:
        holder.wait(timeout=5)
        assert holder.returncode == 0, holder.stderr.read() if holder.stderr else ""
    again = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=5, env=env)
    assert again.returncode == 0 and "LOCK_ACQUIRED" in again.stdout, (again.returncode,again.stderr)
    assert lock.stat().st_mode & 0o777 == 0o600, "LOCKFILE_NOT_PRIVATE"
    assert expected.read_text(encoding="utf-8") == "SAFE_ORIGINAL\n"
    print("PASS lock released automatically after first action exits; mode 0600")

    # An unexpected symlink must be refused before it is opened or truncated.
    lock.unlink()
    lock.symlink_to(expected)
    symlink_check = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, timeout=5, env=env
    )
    assert symlink_check.returncode == 85, (symlink_check.returncode,symlink_check.stdout,symlink_check.stderr)
    assert "ACTION_LOCK_UNAVAILABLE" in symlink_check.stderr
    assert expected.read_text(encoding="utf-8") == "SAFE_ORIGINAL\n"
    print("PASS unsafe lock symlink is refused without touching target")

print("PASS 4/4 mutating action lock gates; no production network or OS files changed")
