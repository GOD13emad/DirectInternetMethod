#!/usr/bin/env python3
"""R782 real-UID0/bootstrap content test on disposable original GitHub runner ONLY.

Never execute product install/upgrade/rollback, pkexec, systemctl, DNS or network
commands. PKEXEC_UID is simulated solely for ownership validation: this is
NOT native Polkit authentication acceptance.
"""
from __future__ import annotations
import hashlib
import importlib.util
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import zipfile

BASE = Path(__file__).resolve().parents[1]
PIN_ENTRY = "DD878D594830A3C1A85283E3399BF96B42B9FBC02AF68D993DE5507D605577D8"
PIN_ZIP = "C02A7CEAED5D4764250C7416D8E51A4BB92BE17FC4CA936EA349113AE733BD3A"
ENTRY = Path("/usr/local/libexec/directinternetmethod/privileged_entry.py")
SOURCE = BASE / "tools/security/privileged_entry.py"
PKG = "DirectInternetMethod_1.5.5-rc1_Linux_x86_64"
ARCHIVE = BASE / "delivery" / (PKG + ".zip")
# This is a disposable original-repository GitHub VM, not an arbitrary path
# derived from RUNNER_TEMP or another user-provided environment variable.
EXPECTED_WORKSPACE = Path("/home/runner/work/DirectInternetMethod/DirectInternetMethod")
OWNED_SCRATCH = Path("/run/dim-r782-one-time-trusted-root-fixture")

def need(yes: bool, code: str):
    if not yes:
        raise RuntimeError("R782_FAIL_CLOSED_" + code)

def sha_file(p: Path):
    return hashlib.sha256(p.read_bytes()).hexdigest().upper()

def guard():
    e = os.environ
    need(sys.platform == "linux" and os.geteuid() == 0, "REAL_ROOT_REQUIRED")
    need(e.get("CI") == "true" and e.get("GITHUB_ACTIONS") == "true" and
         e.get("GITHUB_REPOSITORY") == "GOD13emad/DirectInternetMethod" and
         e.get("RUNNER_ENVIRONMENT") == "github-hosted", "ORIGINAL_HOSTED_ONLY")
    need(e.get("GITHUB_REF") == "refs/heads/security/r776-pinned-root-read-qa" and
         e.get("GITHUB_SHA") and len(e["GITHUB_SHA"]) == 40,
         "REVIEW_ONLY_BRANCH_AND_EXACT_COMMIT")
    need(e.get("GITHUB_WORKSPACE") == str(EXPECTED_WORKSPACE) and
         BASE == EXPECTED_WORKSPACE and BASE.is_dir(),
         "WORKSPACE_NOT_OWNED")
    commit = subprocess.run(["/usr/bin/git", "-C", str(BASE), "rev-parse", "HEAD"],
                            check=True, capture_output=True, text=True).stdout.strip()
    need(commit == e["GITHUB_SHA"], "CHECKED_OUT_COMMIT_DIFFERENT")
    need(Path("/run").is_dir() and Path("/run").lstat().st_uid == 0 and
         not (Path("/run").lstat().st_mode & 0o022), "ROOT_RUN_PARENT")
    need(not OWNED_SCRATCH.exists() and not OWNED_SCRATCH.is_symlink(),
         "NO_FOREIGN_SCRATCH")
    temp = OWNED_SCRATCH
    runner = pwd.getpwnam("runner")
    need(runner.pw_uid > 0 and runner.pw_dir == "/home/runner", "REAL_HOSTED_RUNNER")
    need(not ENTRY.exists() and not ENTRY.is_symlink(), "FOREIGN_ENTRY_PRESENT")
    need(not ENTRY.parent.exists() and not ENTRY.parent.is_symlink(),
         "FOREIGN_TRUST_DIRECTORY")
    for candidate in ("/usr/lib/directinternetmethod",
                      "/var/lib/directinternetmethod/install.json",
                      "/var/lib/directinternetmethod/upgrade-guard"):
        need(not Path(candidate).exists(), "NOT_DISPOSABLE_FRESH_BACKEND")
    need(SOURCE.is_file() and ARCHIVE.is_file() and
         sha_file(SOURCE) == PIN_ENTRY and sha_file(ARCHIVE) == PIN_ZIP,
         "PINNED_QA_SOURCE_DIFFERENT")
    return temp, runner.pw_uid

def trusted_provision():
    # Only on a guarded disposable GitHub VM, not a personal Linux host.
    upper = ENTRY.parent.parent
    created_upper = False
    if not upper.exists():
        upper.mkdir(mode=0o755)
        created_upper = True
    for part in (Path("/usr"), Path("/usr/local"), upper):
        st = part.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_gid == 0 and
             not (st.st_mode & 0o022), "UNTRUSTED_HOSTED_ANCESTOR")
    ENTRY.parent.mkdir(mode=0o755)
    fd = os.open(ENTRY, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500)
    with os.fdopen(fd, "wb") as stream:
        stream.write(SOURCE.read_bytes())
        stream.flush()
        os.fsync(stream.fileno())
        os.fchmod(stream.fileno(), 0o500)
    st = ENTRY.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_gid == 0 and
         st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o500 and
         sha_file(ENTRY) == PIN_ENTRY, "NATIVE_OWNED_EXECUTABLE_IDENTITY")
    return created_upper

def package_fixture(temp: Path, uid: int):
    d = temp / "dim-r782-exact-reviewed-fixture"
    need(not d.exists() and not d.is_symlink(), "EXISTING_TEMP_FIXTURE")
    d.mkdir(mode=0o700)
    with zipfile.ZipFile(ARCHIVE) as z:
        records = z.infolist()
        need(len(records) == 30, "ARCHIVE_INVENTORY")
        for item in records:
            parts = item.filename.split("/")
            need(parts[0] == PKG and ".." not in parts and
                 not stat.S_ISLNK(item.external_attr >> 16), "ARCHIVE_MEMBER_UNSAFE")
        z.extractall(d)
    package = d / PKG
    for path in package.rglob("*"):
        os.chown(path, uid, -1)
    os.chown(package, uid, -1)
    need(package.stat().st_uid == uid, "REAL_PACKAGE_USER_OWNER")
    return d, package

def native_root_snapshot(helper, package: Path, uid: int, temp: Path):
    owned = temp / "dim-r782-frozen-root-only"
    need(not owned.exists() and not owned.is_symlink(), "FOREIGN_ROOT_STAGING")
    owned.mkdir(mode=0o700)
    try:
        freeze = helper.freeze_package(package, owned, uid)
        need(freeze.stat().st_uid == uid and
             stat.S_IMODE(freeze.stat().st_mode) == 0o500, "STAGED_LEAF_IDENTITY")
        for name in ("system/upgrade_system.sh", "system/install_system.sh",
                     "system/upgrade_guard.py", "app/user_update_transaction.py"):
            path = freeze / name
            need(path.stat().st_uid == 0 and sha_file(path) == sha_file(package / name),
                 "STAGED_PRIVILEGED_CODE_BYTE_MISMATCH")
        print("R782_ROOT_OWNED_PINNED_STAGING_PASS_NO_INSTALL")
    finally:
        shutil.rmtree(owned)

def reject_drifted_manifest(package: Path, uid: int):
    manifest = package / "PACKAGE_MANIFEST.json"
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    old_dirs = set(Path("/run").glob("dim-trusted-root-*"))
    env = {"PKEXEC_UID": str(uid), "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
           "HOME": "/root", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1"}
    outcome = subprocess.run(["/usr/bin/python3", "-I", str(ENTRY),
                              "--action", "upgrade", "--source", str(package)],
                             env=env, cwd="/", text=True, capture_output=True,
                             timeout=10, check=False)
    need(outcome.returncode == 86 and
         "R781_REJECT_TRUSTED_MANIFEST_DIGEST" in outcome.stderr,
         "SIMULATED_AUTH_CORRUPTED_MANIFEST_FAILED_OPEN")
    need(set(Path("/run").glob("dim-trusted-root-*")) == old_dirs,
         "TEMP_ROOT_DIR_LEAKED")
    need(not Path("/var/lib/directinternetmethod/install.json").exists(),
         "REAL_BACKEND_TOUCHED")
    print("R782_REAL_ROOT_ENTRY_CORRUPTED_MANIFEST_FAIL_CLOSED")

def main():
    temp, uid = guard()
    scratch = None
    created_upper = False
    parent_created = False
    private_created = False
    try:
        temp.mkdir(mode=0o700)
        private_created = True
        st = temp.lstat()
        need(st.st_uid == 0 and stat.S_IMODE(st.st_mode) == 0o700 and
             stat.S_ISDIR(st.st_mode), "OWNED_SCRATCH_IDENTITY")
        created_upper = trusted_provision()
        parent_created = True
        os.environ["PKEXEC_UID"] = str(uid)  # SIMULATION; no native auth conclusion
        spec = importlib.util.spec_from_file_location("reviewed_root_entry", ENTRY)
        assert spec and spec.loader
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        helper.check_trusted_entry()
        scratch, package = package_fixture(temp, uid)
        native_root_snapshot(helper, package, uid, temp)
        reject_drifted_manifest(package, uid)
        print("R782_EPHEMERAL_ROOT_OWNERSHIP_AND_MANIFEST_GATE_PASS")
    finally:
        if scratch is not None:
            need(scratch.parent == temp and scratch.name == "dim-r782-exact-reviewed-fixture",
                 "SCRATCH_SCOPE")
            shutil.rmtree(scratch)
        if parent_created:
            need(ENTRY.is_file() and ENTRY.lstat().st_uid == 0 and
                 sha_file(ENTRY) == PIN_ENTRY, "TRUSTED_ENTRY_CLEANUP_IDENTITY")
            ENTRY.unlink()
            ENTRY.parent.rmdir()
        if created_upper:
            ENTRY.parent.parent.rmdir()
        if private_created:
            st = temp.lstat()
            need(temp == OWNED_SCRATCH and st.st_uid == 0 and
                 stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700,
                 "CLEANUP_EXACT_OWNED_SCRATCH")
            temp.rmdir()
        need(not ENTRY.exists() and not temp.exists() and
             not Path("/var/lib/directinternetmethod/install.json").exists(),
             "POST_CLEANUP_NO_PRODUCT_MUTATION")

if __name__ == "__main__":
    main()
