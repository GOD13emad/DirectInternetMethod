#!/usr/bin/env python3
"""Negative-first result propagation contract for Linux failed-Start EXIT trap.

Isolated Bash only; no nft, network or real processes/services invoked.
"""
from __future__ import annotations
from pathlib import Path
import re
import subprocess

root=Path(__file__).resolve().parents[1]
source=(root/"linux/app/direct_method_helper.sh").read_text(encoding="utf-8")
fragments=re.findall(r"^rollback_on_exit\(\)\{\n.*?^\}\n", source, re.M | re.S)
assert len(fragments)==1, "ROLLBACK_TRAP_NOT_UNIQUE"
fn=fragments[0]

CASES=[
 ("rollback_failure_after_success_code", "start", 0, 0, 83, 83, True),
 ("rollback_failure_after_start_error", "start", 0, 72, 83, 83, True),
 ("rollback_success_after_start_error", "start", 0, 72, 0, 72, False),
 ("uncommitted_start_exit0", "start", 0, 0, 0, 87, True),
 ("successful_committed_start", "start", 1, 0, 83, 0, False),
 ("status_exit0_skips_rollback", "status", 0, 0, 83, 0, False),
]
for name,action,committed,original,rollback,expected,need_diagnostic in CASES:
    program=(
        "set -euo pipefail\n"+
        "ACTION="+action+"\n"+
        "START_COMMITTED="+str(committed)+"\n"+
        "cleanup_transient(){ set +e; printf 'MOCK_ROLLBACK_CALLED\\n' >&2; return "+str(rollback)+"; }\n"+
        fn+
        "\ntrap rollback_on_exit EXIT\n"+
        "exit "+str(original)+"\n"
    )
    run=subprocess.run(["bash","-c",program],text=True,capture_output=True,timeout=5)
    assert run.returncode==expected,(
        name, "INCORRECT_EXIT_CODE", run.returncode, expected, run.stderr,
    )
    if need_diagnostic:
        needed="START_NOT_COMMITTED" if name=="uncommitted_start_exit0" else "START_ROLLBACK_FAILED"
        assert needed in run.stderr,(name,"ROLLBACK_DIAGNOSTIC_MISSING",run.stderr)
    else:
        assert "START_ROLLBACK_FAILED" not in run.stderr,(name,"FALSE_FAILURE")
    if action=="start" and not committed:
        assert "MOCK_ROLLBACK_CALLED" in run.stderr,(name,"ROLLBACK_SKIPPED")
    else:
        assert "MOCK_ROLLBACK_CALLED" not in run.stderr,(name,"UNEXPECTED_ROLLBACK")
    assert '{"ok":true' not in run.stdout, (name,"FALSE_SUCCESS_OUTPUT")
    print("PASS",name,"exit",run.returncode)
print(f"PASS {len(CASES)}/{len(CASES)} isolated EXIT-trap result gates; no network operations")
