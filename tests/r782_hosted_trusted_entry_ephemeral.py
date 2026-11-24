#!/usr/bin/env python3
"""R782 real-UID0/bootstrap content test on disposable original GitHub runner ONLY.

Historical path tests only admission. R963 exact reviewed feature dispatch
also tests the real fresh-install/owner reinstall/removal lifecycle without
starting any product network units. PKEXEC_UID is simulated in the guarded
VM, NOT native Polkit authentication acceptance.
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
PIN_ENTRY = "D0181C15C54B90A3B6E03FBFBE32148341037AB60CF4D6788B6A72140304340F"
PIN_ZIP = "A8356107C5DE6529E8270D1EE404A7D8A629040BD0D17F3F83C61C390790655D"
ENTRY = Path("/usr/local/libexec/directinternetmethod/privileged_entry.py")
SOURCE = BASE / "tools/security/privileged_entry.py"
PKG = "DirectInternetMethod_1.5.6_Linux_x86_64"
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
    historical = e.get("GITHUB_REF") == "refs/heads/prep/r803-forward-156-native-gates"
    reviewed = (e.get("GITHUB_REF") == "refs/heads/feature/universal-install-engine" and
                e.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and
                e.get("R962_EXPECTED_SHA") == e.get("GITHUB_SHA"))
    need((historical or reviewed) and e.get("GITHUB_SHA") and
         len(e["GITHUB_SHA"]) == 40 and
         all(c in "0123456789abcdef" for c in e["GITHUB_SHA"]),
         "REVIEW_ONLY_BRANCH_AND_EXACT_COMMIT")
    # Historical pins are preserved; this reviewed feature candidate has
    # its own independently checked frozen package and bootstrap digest.
    global PIN_ENTRY, PIN_ZIP, PKG, ARCHIVE
    if reviewed:
        PIN_ENTRY = "346D99B8D0745C2F42D24EE835FC3C6A8646AE705E04C41640BDFC6BA196B4C5"
        PIN_ZIP = "298C4D3B9AE5C8B0709EDFFCAE665FB66A84A47BBDB2564E4E92356903738FCD"
        PKG = "DirectInternetMethod_1.5.7_Linux_x86_64"
        ARCHIVE = BASE / "delivery" / (PKG + ".zip")
    need(e.get("GITHUB_WORKSPACE") == str(EXPECTED_WORKSPACE) and
         BASE == EXPECTED_WORKSPACE and BASE.is_dir(),
         "WORKSPACE_NOT_OWNED")
    commit = subprocess.run(["/usr/bin/git", "-c", "safe.directory=" + str(EXPECTED_WORKSPACE), "-C", str(BASE), "rev-parse", "HEAD"],
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
    if os.environ.get("GITHUB_REF") == "refs/heads/feature/universal-install-engine":
        # Native administrator-local provisioning, not a Debian package.
        # No execution from the user-writable source; verify the protected copy.
        import tempfile
        with tempfile.TemporaryDirectory(prefix=".dim-bootstrap-", dir=ENTRY.parent) as d:
            staged = Path(d) / ENTRY.name
            subprocess.run(["/usr/bin/install", "-o", "root", "-g", "root",
                            "-m", "0500", "--", str(SOURCE), str(staged)], check=True)
            st = staged.lstat()
            need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_gid == 0
                 and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == 0o500
                 and sha_file(staged) == PIN_ENTRY, "R965_PROTECTED_COPY_PIN")
            with staged.open("rb") as stream:
                os.fsync(stream.fileno())
            subprocess.run(["/usr/bin/ln", "-T", "--", str(staged), str(ENTRY)], check=True)
            # A second publish must fail, retaining the exact installed inode.
            inode = ENTRY.stat().st_ino
            duplicate = subprocess.run(["/usr/bin/ln", "-T", "--", str(staged), str(ENTRY)],
                                       capture_output=True, check=False)
            need(duplicate.returncode != 0 and ENTRY.stat().st_ino == inode,
                 "R965_NATIVE_NO_CLOBBER")
        print("R965_NATIVE_INSTALL_PINNED_COPY_NO_CLOBBER_PASS")
    else:
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


def reviewed_fresh_lifecycle(package: Path, uid: int, helper):
    """Actual existing installer phases; only in the guarded disposable VM."""
    import json
    from dataclasses import asdict
    sys.path.insert(0, str(BASE))
    from installer_engine.scoped_layout import compile_scoped_layout
    from installer_engine.native_readiness import linux_flat_scope_postflight, linux_readiness

    need(os.environ.get("GITHUB_REF") == "refs/heads/feature/universal-install-engine" and
         os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and
         os.environ.get("R962_EXPECTED_SHA") == os.environ.get("GITHUB_SHA"),
         "R963_REVIEWED_DISPATCH_ONLY")
    user = pwd.getpwuid(uid)
    home = Path(user.pw_dir)
    app = home / ".local/share/DirectInternetMethod"
    pending = home / ".local/state/DirectInternetMethod/update-pending"
    root = Path("/usr/lib/directinternetmethod")
    metadata = Path("/var/lib/directinternetmethod/install.json")
    units = tuple("directinternetmethod-" + action + ".service"
                  for action in ("start", "stop", "recovery"))
    unit_paths = [Path("/etc/systemd/system") / unit for unit in units]
    rule = Path("/etc/polkit-1/rules.d/49-directinternetmethod.rules")
    uid_file = Path("/etc/directinternetmethod.uid")
    clean = [app, pending.parent, root, metadata.parent, rule, uid_file,
             Path("/etc/directinternetmethod.conf"),
             home / ".local/bin/direct-internet-method",
             home / ".local/bin/direct-internet-method-uninstall",
             home / ".local/share/applications/io.github.god13emad.DirectInternetMethod.desktop",
             home / ".local/share/icons/hicolor/scalable/apps/direct-internet-method.svg",
             home / "Desktop/Direct Internet Method.desktop", *unit_paths,
             Path("/run/directinternetmethod-selective"),
             Path("/run/directinternetmethod-encrypted"),
             Path("/run/directinternetmethod-encrypted-ctrld.toml"),
             Path("/sys/class/net/dimesd0")]
    need(all(not p.exists() and not p.is_symlink() for p in clean), "R963_FRESH_TARGETS")
    need(rule.parent.is_dir() and not rule.parent.is_symlink(), "R963_POLKIT_RULES_DIRECTORY")
    manifest = json.loads((package / "PACKAGE_MANIFEST.json").read_bytes())
    plan = compile_scoped_layout(manifest, (BASE / "linux/native_layout.json").read_bytes(),
                                 "b423f13fb8c03ade801fe09ad70aaf64ca485d3f6b9e51092108a083d3f5e1b8")
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root",
           "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1", "PKEXEC_UID": str(uid)}
    user_env = {"PATH": env["PATH"], "HOME": str(home), "LANG": "C",
                "PYTHONDONTWRITEBYTECODE": "1", "USER": user.pw_name,
                "LOGNAME": user.pw_name}
    def checked(args, *, owner=False, stdin=None, limit=180):
        command = (["/usr/sbin/runuser", "-u", user.pw_name, "--", "/usr/bin/env", "-i",
                    *[key + "=" + value for key, value in user_env.items()]] + args
                   if owner else args)
        out = subprocess.run(command, cwd="/", env=env, input=stdin, capture_output=True,
                             text=True, timeout=limit, check=False)
        need(out.returncode == 0, "R963_COMMAND_FAILED_" + str(out.returncode) +
             "_" + out.stderr[-1500:] + "_" + out.stdout[-1000:])
        return out.stdout

    resolver = Path("/etc/resolv.conf")
    baseline = (sha_file(resolver), os.readlink(resolver) if resolver.is_symlink() else None)
    package.parent.chmod(0o711)
    package.parent.parent.chmod(0o711)
    try:
        # Check genuine user dependencies BEFORE any product mutation.
        checked(["/usr/bin/python3", "-c",
                 "import gi; gi.require_version('Gtk','4.0'); gi.require_version('Adw','1')"],
                owner=True)
        checked(["/bin/bash", "-c", "for c in python3 sha256sum pkexec systemctl nft busctl ip curl getent; do command -v \"$c\" || exit 3; done"],
                owner=True)
        # R964: an orphaned native registration is not a fresh host.
        # Create ONLY a disposable sentinel in the already verified empty VM.
        sentinel = b"R964_QA_FOREIGN_UID_RECORD\n"
        fd = os.open(uid_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(sentinel)
        try:
            rejected = subprocess.run(
                ["/usr/bin/python3", "-I", str(ENTRY), "--action", "install",
                 "--source", str(package)], cwd="/", env=env,
                capture_output=True, text=True, timeout=30)
            need(rejected.returncode == 86 and
                 "R781_REJECT_FRESH_TARGET_OCCUPIED:" in rejected.stderr,
                 "R964_FOREIGN_TARGET_NOT_REJECTED")
            need(uid_file.read_bytes() == sentinel and not root.exists() and
                 not metadata.parent.exists() and
                 all(not p.exists() for p in unit_paths),
                 "R964_FOREIGN_TARGET_OR_BACKEND_MUTATED")
        finally:
            need(not uid_file.is_symlink() and uid_file.read_bytes() == sentinel,
                 "R964_SENTINEL_IDENTITY")
            uid_file.unlink()
        # Kernel flock must reject a second real bootstrap invocation.
        with helper.bootstrap_lock():
            busy = subprocess.run(
                ["/usr/bin/python3", "-I", str(ENTRY), "--action", "install",
                 "--source", str(package)], cwd="/", env=env,
                capture_output=True, text=True, timeout=15)
            need(busy.returncode == 86 and
                 "R781_REJECT_BOOTSTRAP_BUSY" in busy.stderr and not root.exists(),
                 "R964_CONCURRENT_BOOTSTRAP_NOT_REJECTED")
        print("R964_REAL_BOOTSTRAP_FOREIGN_REGISTRATION_PRESERVED")
        print("R964_REAL_BOOTSTRAP_CONCURRENT_REQUEST_REJECTED")
        # Same protected executable, same frozen package, simulated authorization
        # identity ONLY in this VM. The production install_system.sh is unmodified.
        output = checked(["/usr/bin/python3", "-I", str(ENTRY), "--action", "install",
                          "--source", str(package)])
        need('"systemBackend":"installed"' in output, "R963_ROOT_INSTALL_OUTPUT")
        record = json.loads(metadata.read_bytes())
        need(record["version"] == "1.5.7" and record["uid"] == uid and
             record["home"] == str(home), "R963_ROOT_INSTALL_METADATA")
        root_report = linux_flat_scope_postflight(plan, "privileged", root)
        need(root_report["files"] == 13, "R963_ROOT_13_FILES")
        def check_units():
            observed = linux_readiness(root, units)
            need(len(observed["units"]) == 3 and all(
                x["ActiveState"] == "inactive" for x in observed["units"]),
                "R963_REGISTERED_UNITS_NOT_INACTIVE")
            need(all(p.stat().st_uid == 0 and not p.is_symlink() for p in unit_paths) and
                 rule.stat().st_uid == 0 and not rule.is_symlink() and
                 uid_file.read_text().strip() == str(uid), "R963_NATIVE_REGISTRATION_OWNERSHIP")
        check_units()
        # Execute the actual owner installer. The verified backend matches,
        # so the production script must take its no-elevation path.
        def user_install():
            output = checked(["/bin/bash", str(package / "install.sh")], owner=True)
            need("Protected backend already matches current package" in output and
                 "R519_CANDIDATE_FRESH_USER_CODE_COMMITTED" in output,
                 "R963_OWNER_INSTALL_NOT_COMMITTED")
            need(not pending.exists() and not pending.is_symlink(), "R963_PENDING_RETAINED")
            info = json.loads((app / "INSTALL.json").read_bytes())
            need(info["version"] == "1.5.7" and info["protectedBackendVersion"] == "1.5.7",
                 "R963_OWNER_INSTALL_METADATA")
            code = ("import json,sys; from installer_engine.native_plan import NativePlan; "
                    "from installer_engine.native_readiness import linux_flat_scope_postflight; "
                    "d=json.load(sys.stdin); d['scopes']=tuple((n,m) for n,m in d['scopes']); "
                    "print(json.dumps(linux_flat_scope_postflight(NativePlan(**d),'user',sys.argv[1])))")
            user_output = checked(["/usr/bin/python3", "-B", "-c",
                                   "import sys;sys.path.insert(0," + repr(str(BASE)) + ");" + code,
                                   str(app)], owner=True, stdin=json.dumps(asdict(plan)))
            report = json.loads(user_output)
            need(report["files"] == 8 and report["observed_uid"] == uid,
                 "R963_OWNER_8_FILES")
        user_install()
        private = app / "settings.json"
        checked(["/usr/bin/python3", "-c",
                 "from pathlib import Path; Path.home().joinpath('.local/share/DirectInternetMethod/settings.json').write_bytes(b'{\"r963Private\":true}\\n')"],
                owner=True)
        private_sha = sha_file(private)
        root_sha = sha_file(metadata)
        user_install()
        need(sha_file(private) == private_sha and sha_file(metadata) == root_sha,
             "R963_REINSTALL_PRESERVES_OWNER_AND_ROOT")
        check_units()
        # Existing real uninstall phases, root first; no product service starts.
        uninstall = app / "user_uninstall_preserve.py"
        checked(["/usr/bin/python3", str(uninstall), "--verify"], owner=True)
        need(sha_file(root / "uninstall_system.sh") ==
             sha_file(package / "system/uninstall_system.sh"), "R963_ROOT_UNINSTALL_PIN")
        checked(["/bin/bash", str(root / "uninstall_system.sh")])
        checked(["/usr/bin/python3", str(uninstall), "--remove-after-backend"], owner=True)
        need(not root.exists() and not metadata.exists() and
             all(not p.exists() and not p.is_symlink() for p in [*unit_paths, rule, uid_file]) and
             not (app / "INSTALL.json").exists() and sha_file(private) == private_sha,
             "R963_REAL_UNINSTALL_OWNER_DATA_PRESERVED")
        need((sha_file(resolver), os.readlink(resolver) if resolver.is_symlink() else None)
             == baseline, "R963_RESOLVER_UNCHANGED")
        print("R963_NATIVE_FRESH_INSTALL_REINSTALL_UNINSTALL_21_FILES_PASS_NO_PRODUCT_UNIT_START")
    finally:
        package.parent.chmod(0o700)
        package.parent.parent.chmod(0o700)


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
        original_manifest = (package / "PACKAGE_MANIFEST.json").read_bytes()
        reject_drifted_manifest(package, uid)
        print("R782_EPHEMERAL_ROOT_OWNERSHIP_AND_MANIFEST_GATE_PASS")
        if os.environ.get("GITHUB_REF") == "refs/heads/feature/universal-install-engine":
            (package / "PACKAGE_MANIFEST.json").write_bytes(original_manifest)
            reviewed_fresh_lifecycle(package, uid, helper)
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
