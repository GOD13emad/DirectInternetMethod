#!/usr/bin/env python3
"""R567: exact production installer auth-denial branch with native User stage/rollback.

Hosted ephemeral GitHub Ubuntu ONLY. Exercise original source snippets of
rollback_failed_install, backend_matches_current and the single Polkit gate in
a real unprivileged runner process. Native v1.5.4 user and protected v1.5.2
baselines are bytes from the official published release. Polkit is a *shell
function stub that returns 126*; no admin prompt or privileged upgrade is
performed. A refused request MUST restore the staged User transaction exactly,
without a second prompt, protected source mutation, DNS, or user data changes.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import textwrap
BASE=Path(__file__).resolve().parents[1]
R528=BASE/"tests/r528_ephemeral_native_root_cli_contract.py"
R529=BASE/"tests/r529_ephemeral_root_user_transaction.py"
ARCHIVE="EAF1AE50924FE9D8B440044C7BFB3232A51EB912786A235CC70FB2E2911E6291"

def require(v,code):
    if not v: raise RuntimeError("R567_DENIED_AUTH_FAIL_CLOSED_"+code)

def sha(path):
    h=hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda:f.read(1048576),b""):h.update(b)
    return h.hexdigest().upper()

def imported(path,label):
    spec=importlib.util.spec_from_file_location(label,path)
    require(spec is not None and spec.loader is not None,"IMPORT_"+label)
    out=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(out)
    return out

def excerpt(data,start,following):
    require(data.count(start)==1,"EXPECTED_SINGLE_"+str(len(start)))
    tail=data.split(start,1)[1]
    require(tail.count(following)==1,"END_ANCHOR_"+str(len(following)))
    return start+tail.split(following,1)[0]

def hosted():
    require(os.geteuid()==0 and sys.platform=="linux","ROOT_HOSTED")
    e=os.environ
    require(e.get("CI")=="true" and e.get("GITHUB_ACTIONS")=="true" and
        e.get("RUNNER_ENVIRONMENT")=="github-hosted" and
        e.get("GITHUB_REPOSITORY")=="GOD13emad/DirectInternetMethod" and
        Path(e.get("GITHUB_WORKSPACE","")).resolve()==BASE,
        "FRESH_GITHUB_VM_ONLY")
    runner=pwd.getpwnam("runner")
    require(runner.pw_dir=="/home/runner" and runner.pw_uid>0,"RUNNER")
    for p in ("/var/lib/directinternetmethod","/usr/lib/directinternetmethod",
              "/home/runner/.local/share/DirectInternetMethod",
              "/home/runner/.local/state/DirectInternetMethod"):
        require(not Path(p).exists(),"INITIAL_FOREIGN_INSTALL_"+Path(p).name)
    return runner

def main():
    runner=hosted()
    r528=imported(R528,"r567_r528")
    r529=imported(R529,"r567_r529")
    rootmod=r528.module()
    stable,pkg,temp,user=r528.prerequisites()
    require(user.pw_uid==runner.pw_uid and sha(pkg)==ARCHIVE,"PINNED_ARCHIVE")
    r529.require_clean_home(user)
    extracted=r528.stage_exact_candidate(pkg,temp)
    r529.make_source_runner_owned(extracted,user)
    app,original,priv=r529.prepare_user_from_official(stable,user)
    protected=r528.seed_real_protected_root(stable,user,rootmod)
    dns={name:sha(name) for name in ("/etc/resolv.conf","/etc/hosts")}
    symlink=os.readlink("/etc/resolv.conf") if Path("/etc/resolv.conf").is_symlink() else None
    user_tx=extracted/"app/user_update_transaction.py"
    installer=extracted/"install.sh"
    source=installer.read_text(encoding="utf8")
    require(source.startswith("#!/usr/bin/env bash\nset -euo pipefail\n"),
            "INSTALLER_IDENTITY")
    rollback=excerpt(source,"rollback_failed_install() {","\n\nfor c in ")
    backend=excerpt(source,"backend_matches_current() {",
                    "\n\n# Administrative authorization is required only")
    auth=excerpt(source,"# Administrative authorization is required only",
                 "\nbackend_matches_current || ")
    require(auth.count("pkexec /bin/bash")==2 and
            'ROOT_UPGRADE_STAGED=1' in auth,"POLKIT_BRANCH_PROVENANCE")
    require("pkexec /usr/bin/python3" in rollback and
            'if [ "$ROOT_UPGRADE_STAGED" -eq 1 ]' in rollback,
            "ROLLBACK_PROVENANCE")
    require(rootmod.RootTransaction().status()["status"]=="NO_PENDING_UPGRADE",
            "PROTECTED_PRESTATE")
    r529.as_runner(user,user_tx,"--stage","--source",extracted)
    pending=Path(user.pw_dir)/".local/state/DirectInternetMethod/update-pending"
    require((pending/"manifest.json").is_file(),"USER_STAGE_MISSING")
    r529.unchanged_records(original)
    r529.unchanged_records(priv)
    # Only Bash *functions* from original installed package are executed;
    # the counterfeit "pkexec" function cannot invoke privileged actions.
    script=(
      "set -euo pipefail\n"
      "HERE="+subprocess.list2cmdline([str(extracted)])+"\n"
      "USER_TRANSACTION="+subprocess.list2cmdline([str(user_tx)])+"\n"
      "ROOT_TRANSACTION="+subprocess.list2cmdline([str(extracted/"system/protected_upgrade_transaction.py")])+"\n"
      "ROOT_UPGRADE_STAGED=0\nTRANSACTION_ACTIVE=1\n"
      "pkexec() { printf 'R567_POLKIT_DENIED_BY_OWNER\\n' >&2; return 126; }\n"
      +rollback+"\n\n"+backend+"\n\n"
      "trap 'rollback_failed_install \"$?\"' ERR\n"
      "trap 'rollback_failed_install 130' INT\n"
      "trap 'rollback_failed_install 143' TERM\n"
      "trap 'rollback_failed_install 129' HUP\n"
      +auth+"\n"
      "printf 'R567_DANGER_UNREACHABLE_AFTER_AUTH_DENIAL\\n'\n"
    )
    process=subprocess.run(
      ["/usr/sbin/runuser","-u",user.pw_name,"--","/usr/bin/env",
       "HOME="+user.pw_dir,"PYTHONDONTWRITEBYTECODE=1",
       "/bin/bash","-c",script],capture_output=True,text=True,timeout=30,check=False)
    require(process.returncode==126,"WRONG_REFUSAL_EXIT_"+str(process.returncode))
    require(process.stderr.count("R567_POLKIT_DENIED_BY_OWNER")==1,
            "MULTIPLE_PRIVILEGED_REQUESTS_ON_DENIAL")
    require("R567_DANGER_UNREACHABLE_AFTER_AUTH_DENIAL" not in process.stdout,
            "INSTALLER_IGNORED_AUTH_REFUSAL")
    require(not pending.exists() and
            rootmod.RootTransaction().status()["status"]=="NO_PENDING_UPGRADE",
            "PENDING_LEFT_AFTER_REFUSED_AUTH")
    r529.unchanged_records(original)
    r529.unchanged_records(priv)
    for name,expected in protected.items():
        require(sha(name).lower()==expected,"ROOT_MUTATION_"+Path(name).name)
    for name,expected in dns.items():
        require(sha(name)==expected,"NETWORK_MUTATION_"+Path(name).name)
    require((os.readlink("/etc/resolv.conf") if
            Path("/etc/resolv.conf").is_symlink() else None)==symlink,
            "RESOLVER_SYMLINK_MUTATION")
    require(not Path("/var/lib/directinternetmethod/upgrade-guard").exists(),
            "AUTH_REFUSAL_CREATED_ROOT_GUARD")
    require(json.loads((app/"INSTALL.json").read_text())["version"]=="1.5.4",
            "USER_VERSION_NOT_ROLLED_BACK")
    require(json.loads(Path("/var/lib/directinternetmethod/install.json").read_text())["version"]=="1.5.2",
            "ROOT_VERSION_UNEXPECTED")
    print(json.dumps({"revision":"R567",
        "status":"PASS_HOSTED_SINGLE_POLKIT_DENIAL_USER_ROLLBACK",
        "productionInstallerOriginalAuthorizationBranch":True,
        "nativeUnprivilegedTransactionStaged":True,
        "officialStableRootAndUserBytesRestored":True,
        "singleDeniedAuthorizationAttempt":True,
        "correctDeniedExitCode":126,
        "rootGuardAndRootPendingAbsent":True,
        "privateSettingsPreserved":True,
        "dnsAndHostsUnchanged":True,
        "physicalOwnerHostUntouched":True,
        "syntheticPolkitDenialOnly":True,
        "actualAdminDialogOpened":False},sort_keys=True))

if __name__=="__main__":
    try:main()
    except BaseException as exc:
        print(json.dumps({"revision":"R567","status":"FAIL_CLOSED",
              "reason":str(exc)[:500]}),file=sys.stderr)
        raise SystemExit(96)
