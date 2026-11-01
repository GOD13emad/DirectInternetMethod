#!/usr/bin/env python3
"""R709 install.sh prevents its Python helper from leaving staged .pyc cache.

Negative-first exact source prefix plus rootless interpreter probe. This test
never runs the real installer, pkexec, nft, systemctl, DNS or network utilities.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import sys
import shlex

ROOT=Path(__file__).resolve().parents[1]
installer=(ROOT/"linux/install.sh").read_text(encoding="utf-8-sig")
needle="export PYTHONDONTWRITEBYTECODE=1"
assert installer.count(needle)==1,"USER_INSTALLER_BYTECODE_OPT_OUT_NOT_UNIQUE"
prefix=installer.split('HERE="$(cd "$(dirname "$0")" && pwd)"',1)
assert len(prefix)==2,"INSTALLER_SOURCE_PREFIX_CHANGED"
assert needle in prefix[0] and prefix[0].index(needle)>prefix[0].index("umask 077")
assert 'pkexec /bin/bash "$HERE/system/upgrade_system.sh"' in installer,"PROTECTED_ROOT_AUTH_REMOVED"
assert 'R519_CANDIDATE_PENDING_NATIVE_ROOT_USER_COMMIT' in installer,"UNCOMMITTED_SAFETY_SEMANTICS_CHANGED"
assert 'python3 "$USER_TRANSACTION" --rollback' in installer,"USER_ROLLBACK_REMOVED"
if sys.platform.startswith("linux"):
    with tempfile.TemporaryDirectory(prefix="dim-r709-no-bytecode-") as td:
        path=Path(td)
        module=path/"dim_r709_probe.py"
        module.write_text("VALUE='ok'\n",encoding="utf-8")
        pycode='import dim_r709_probe; assert dim_r709_probe.VALUE=="ok"'
        script="set -euo pipefail\n"+prefix[0]+"\nPYTHONPATH="+shlex.quote(td)+" python3 -c "+shlex.quote(pycode)+"\n"
        env=os.environ.copy()
        env.pop("PYTHONDONTWRITEBYTECODE",None)
        p=subprocess.run(["bash","-c",script],text=True,capture_output=True,
                         check=False,timeout=10,env=env)
        assert p.returncode==0,(p.stdout,p.stderr)
        assert not (path/"__pycache__").exists(),"CANDIDATE_EXTRACTED_PATH_WOULD_ACCUMULATE_PYC"
    print("R709_NATIVE_INSTALLER_EXPORTED_ENV_IMPORT_NO_PYC_CACHE=PASS")
print("R709_INSTALLER_SOURCE_GUARDED_NO_BYTECODE_CACHE=PASS")
