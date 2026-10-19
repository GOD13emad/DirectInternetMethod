#!/usr/bin/env python3
"""R566: systemd native missed-calendar catch-up, runner only.

Exercises actual exact production timer directives OnActiveSec=480s,
OnCalendar=<fixed UTC> and Persistent=true. A different, uniquely named
synthetic one-shot systemd service writes only in /run on disposable
GitHub-hosted Ubuntu. No DIM installed application, network, Tailscale,
DNS, user-owned files, releases or root upgrade changes.
"""
from __future__ import annotations
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
GUARD=ROOT/"linux/system/upgrade_guard.py"
PIN_GUARD="A4FE303415AE91DED41B2D718040C1A928179DD92BF0ABE601627C479F3DEDFD"

def need(value,reason):
    if not value:raise RuntimeError("R566_SYSTEMD_FAIL_CLOSED_"+reason)

# This disposable Root systemd test must not become a generic command
# launcher. Only known unit operations, under the one absolute OS-owned
# systemctl executable, are permitted; all variable unit IDs are numeric.
UNIT_RE=re.compile(r"dim-r566-catchup-[0-9]{1,29}\.(?:timer|service)\Z")


def run(*args,timeout=12):
    need(len(args)>=2 and all(type(item) is str for item in args) and
         args[0]=="/usr/bin/systemctl","UNTRUSTED_COMMAND_ORIGIN")
    program=Path("/usr/bin/systemctl")
    need(program.is_file() and not program.is_symlink() and
         program.stat().st_uid==0 and not program.stat().st_mode & 0o022,
         "UNTRUSTED_SYSTEMCTL_BINARY")
    action=args[1]
    if action=="daemon-reload":
        need(args==("/usr/bin/systemctl","daemon-reload"),
             "INVALID_DAEMON_RELOAD_ARGUMENTS")
    elif action in ("start","stop"):
        need(len(args)==3 and bool(UNIT_RE.fullmatch(args[2])),
             "INVALID_SYSTEMD_UNIT_ARGUMENTS")
    elif action=="show":
        need(len(args)==6 and bool(UNIT_RE.fullmatch(args[2])) and
             args[3:]==("-p","ActiveState","--value"),
             "INVALID_SYSTEMD_SHOW_ARGUMENTS")
    else:
        need(False,"UNTRUSTED_SYSTEMCTL_ACTION")
    p=subprocess.run(("/usr/bin/systemctl",*args[1:]),text=True,
                     capture_output=True,timeout=timeout,check=False)
    need(p.returncode==0,"COMMAND_"+str(p.returncode)+"_"+p.stderr[-170:].replace(" ","_"))
    return p.stdout.strip()

def preflight():
    need(os.geteuid()==0 and sys.platform=="linux","ROOT")
    env=os.environ
    need(env.get("GITHUB_ACTIONS")=="true" and env.get("CI")=="true" and
         env.get("RUNNER_ENVIRONMENT")=="github-hosted" and
         env.get("GITHUB_REPOSITORY")=="GOD13emad/DirectInternetMethod" and
         env.get("GITHUB_WORKSPACE")==str(ROOT) and
         ROOT==Path("/home/runner/work/DirectInternetMethod/DirectInternetMethod"),
         "HOSTED_RUNNER_ONLY")
    need(Path("/proc/1/comm").read_text().strip()=="systemd","SYSTEMD_PID_ONE")
    need(hashlib.sha256(GUARD.read_bytes()).hexdigest().upper()==PIN_GUARD,"PINNED_GUARD")
    spec=importlib.util.spec_from_file_location("r566_exact_production_guard",GUARD)
    need(spec is not None and spec.loader is not None,"IMPORT")
    x=importlib.util.module_from_spec(spec);spec.loader.exec_module(x)
    return x

def main():
    guard=preflight()
    identity=os.environ["GITHUB_RUN_ID"]
    need(identity.isdecimal() and len(identity)<30,"RUN_ID")
    # Fixed, fail-closed unit ID on a fresh disposable VM; the GitHub run
    # identifier is checked for provenance but never enters a privileged
    # filesystem pathname or systemd unit name.
    name="dim-r566-catchup-784"
    service=Path("/etc/systemd/system")/(name+".service")
    timer=Path("/etc/systemd/system")/(name+".timer")
    for target in (service,timer):
        need(not target.exists() and not target.is_symlink(),"FOREIGN_SYSTEMD_UNIT")
    with tempfile.TemporaryDirectory(prefix="dim-r566-784-",dir="/run") as directory:
        root=Path(directory)
        os.chmod(root,0o700)
        marker=root/"fired.json"
        worker=root/"worker.py"
        worker.write_text(
            "from pathlib import Path\n"
            "import json,os,time\n"
            "out=Path("+repr(str(marker))+")\n"
            "fd=os.open(out,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)\n"
            "with os.fdopen(fd,'w') as f:\n"
            " f.write(json.dumps({'pid':os.getpid(),'utc':time.time()})+'\\n')\n"
            " f.flush();os.fsync(f.fileno())\n",
            encoding="utf-8")
        os.chmod(worker,0o500)
        deadline=int(time.time())+12
        original_service,original_timer=guard.unit_templates(deadline)
        replacement=original_service.replace(
            ("ExecStart=/usr/bin/python3 -B "+str(guard.WORKER)+" rollback").encode(),
            ("ExecStart=/usr/bin/python3 -B "+str(worker)).encode())
        replacement_timer=original_timer.replace(
            ("Unit="+guard.UNIT+".service").encode(),("Unit="+name+".service").encode())
        need(replacement!=original_service and replacement_timer!=original_timer,
             "EXPECTED_TEST_ONLY_IDENTITY_REPLACEMENTS")
        need(b"OnActiveSec=480s\n" in replacement_timer and
             b"Persistent=true\n" in replacement_timer and
             b"OnCalendar=" in replacement_timer,"PRODUCTION_TIMER_SEMANTICS")
        service.write_bytes(replacement);timer.write_bytes(replacement_timer)
        enabled=False
        try:
            run("/usr/bin/systemctl","daemon-reload")
            run("/usr/bin/systemctl","start",name+".timer")
            need(run("/usr/bin/systemctl","show",name+".timer",
                     "-p","ActiveState","--value")=="active","TIMER_STARTED")
            need(not marker.exists(),"EARLY_TRIGGER")
            time.sleep(1)
            run("/usr/bin/systemctl","stop",name+".timer")
            need(not marker.exists(),"TRIGGER_WHILE_INITIAL_TIMER_ACTIVE")
            need(run("/usr/bin/systemctl","show",name+".timer",
                     "-p","ActiveState","--value")=="inactive","TIMER_STOPPED")
            wait=deadline+2-time.time()
            if wait>0:time.sleep(wait)
            need(not marker.exists(),"TRIGGER_WHILE_TIMER_STOPPED")
            started=time.monotonic()
            run("/usr/bin/systemctl","start",name+".timer")
            while time.monotonic()-started<8 and not marker.exists():
                time.sleep(0.15)
            need(marker.is_file() and not marker.is_symlink(),
                 "PERSISTENT_MISSED_CALENDAR_CATCHUP_NOT_FIRED")
            payload=json.loads(marker.read_text())
            need(type(payload.get("pid")) is int and type(payload.get("utc")) in (int,float),
                 "BAD_SERVICE_RECEIPT")
            need(time.monotonic()-started<8,"MISSED_CATCHUP_DEADLINE")
            print(json.dumps({
                "revision":"R566","status":"PASS_EPHEMERAL_SYSTEMD_PERSISTENT_MISSED_CALENDAR_CATCHUP",
                "identity":"GITHUB_HOSTED_ONLY","productionGuardSha256":PIN_GUARD,
                "productionUnitDirectiveIdentity":True,
                "triggeredWhileInactive":False,
                "triggeredAfterReactivation":True,
                "elapsedSeconds":round(time.monotonic()-started,3),
                "deadlineUnix":deadline,
                "actualFullRebootTested":False,
                "realUserMachineChanged":False,
                "networkOrTailscaleChanged":False
            },sort_keys=True))
        finally:
            subprocess.run(["/usr/bin/systemctl","stop",name+".timer"],
                           capture_output=True,text=True,timeout=10,check=False)
            subprocess.run(["/usr/bin/systemctl","stop",name+".service"],
                           capture_output=True,text=True,timeout=10,check=False)
            for target,want in ((service,replacement),(timer,replacement_timer)):
                if target.is_file() and not target.is_symlink() and target.read_bytes()==want:
                    target.unlink()
            subprocess.run(["/usr/bin/systemctl","daemon-reload"],
                           capture_output=True,text=True,timeout=10,check=False)

if __name__=="__main__":
    try:main()
    except BaseException as exc:
        print(json.dumps({"revision":"R566","status":"FAIL_CLOSED",
            "reason":str(exc)[:400]}),file=sys.stderr)
        raise SystemExit(96)
