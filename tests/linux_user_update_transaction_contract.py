#!/usr/bin/env python3
"""R401 negative-first real filesystem fixtures: no protected system service, network
or installed-user-app mutations. Tests one-slot code transaction and data preservation.
Runs on Linux as an unprivileged user with a temporary HOME.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TX = ROOT / "linux/app/user_update_transaction.py"
UNINSTALL = ROOT / "linux/app/user_uninstall_preserve.py"

spec = importlib.util.spec_from_file_location("dim_tx", TX)
tx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tx)

def need(value, detail):
    assert value, detail

def digest(data):
    return hashlib.sha256(data).hexdigest()

def calls(home, source, command, success=True):
    env = dict(os.environ, HOME=str(home), PYTHONDONTWRITEBYTECODE="1")
    args = [sys.executable, "-B", str(TX), command]
    if command in ("--stage", "--apply"):
        args += ["--source", str(source)]
    p = subprocess.run(args, env=env, text=True, capture_output=True, timeout=8)
    if success:
        need(p.returncode == 0, f"EXPECTED_PASS:{command}:{p.stderr}")
    else:
        need(p.returncode != 0 and "FAIL_CLOSED" in p.stderr, f"NEGATIVE_WRONGLY_PASSED:{command}")
    return p

def source_tree(tmp, tag):
    src = tmp / ("source-" + tag)
    for origin, rel, mode in tx.FILES:
        p = src / origin
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(f"version-{tag}:{rel}\n".encode("utf8"))
        p.chmod(mode)
    provider = src / tx.PROVIDER_SOURCE
    provider.parent.mkdir(parents=True, exist_ok=True)
    provider.write_bytes(f'{{"version":"{tag}"}}\n'.encode())
    return src

def initial(tmp, tag="1.5.1", managed_provider=False):
    home = tmp / "home"
    home.mkdir(parents=True)
    app = home / ".local/share/DirectInternetMethod"
    app.mkdir(parents=True)
    oldfiles = {}
    for _, rel, _ in tx.FILES:
        p = app / rel
        p.write_bytes(f"old-{tag}:{rel}\n".encode())
        oldfiles[rel] = p.read_bytes()
    provider = app / tx.PROVIDERS
    provider.parent.mkdir(parents=True)
    provider.write_bytes(b'{"userCustomizedProvider":"keep"}\n')
    user = {
        "settings.json": b'{"userOption": true}\n',
        "scope.txt": b"targeted\n",
        "strategy.txt": b"strong\n",
        "custom-hosts.txt": b"private.example\n",
        "adult-enabled.txt": b"0\n",
        "adult-hosts.txt": b"user-catalog-preserve\n",
    }
    for name, body in user.items():
        (app / name).write_bytes(body)
    record = {
        "schema": 2,
        "version": tag,
        "managedProviderSha256": digest(provider.read_bytes()) if managed_provider else None,
        "managedCodeSha256": {k: digest(v) for k, v in oldfiles.items()},
        "managedLaunchersSha256": {},
    }
    (app / tx.METADATA).write_text(json.dumps(record) + "\n")
    oldfiles[tx.METADATA] = (app / tx.METADATA).read_bytes()
    return home, app, oldfiles, user, provider.read_bytes()

def metadata(home, source):
    app = home / ".local/share/DirectInternetMethod"
    manifest = json.loads((home / ".local/state/DirectInternetMethod/update-pending/manifest.json").read_text())
    new = {
        "schema": 2, "version": "1.5.2",
        "managedProviderSha256": manifest["providerSha"],
        "managedCodeSha256": {k:v["sha"] for k,v in manifest["managed"].items()
                              if k != tx.PROVIDERS},
        "managedLaunchersSha256": {},
    }
    (app / tx.METADATA).write_text(json.dumps(new)+"\n")
    return manifest

def unchanged_data(app, user):
    for name, expected in user.items():
        need((app / name).read_bytes() == expected, "USER_SETTINGS_CHANGED:" + name)

with tempfile.TemporaryDirectory(prefix="dim-r401-sourceonly-") as temp:
    tmp = pathlib.Path(temp)
    src = source_tree(tmp, "new")
    tests = 0
    # Normal data-preserving in-place update when Router Gateway data is custom.
    home, app, original, user, provider = initial(tmp/"case1")
    calls(home, src, "--stage")
    calls(home, src, "--apply")
    record = metadata(home, src)
    need(record["providerManaged"] is False, "UNKNOWN_PROVIDER_WAS_NOT_PRESERVED")
    calls(home, src, "--commit")
    need(not (home / ".local/state/DirectInternetMethod/update-pending").exists(), "EXTRA_ROLLBACK_SLOT_AFTER_ACCEPTED_UPDATE")
    unchanged_data(app, user)
    need((app / tx.PROVIDERS).read_bytes() == provider, "CUSTOM_ROUTER_PROVIDER_LOST")
    need((app / "direct_internet_method.py").read_bytes() != original["direct_internet_method.py"], "CODE_NOT_UPDATED_IN_PLACE")
    need(len(list((home / ".local/share").glob("DirectInternetMethod-backup-*"))) == 0,
         "TIMESTAMPED_SNAPSHOT_CREATED")
    tests += 1
    # Idempotent same version does not accumulate a dated previous version.
    calls(home, src, "--stage")
    calls(home, src, "--apply")
    metadata(home, src)
    calls(home, src, "--commit")
    unchanged_data(app, user)
    need(len(list((home / ".local/state/DirectInternetMethod").rglob("update-pending"))) == 0, "SECOND_SLOT_REMAINS")
    tests += 1
    # Exact explicitly vendor-owned provider may refresh safely, unlike custom.
    home2, app2, old2, user2, provider2 = initial(tmp/"case2", managed_provider=True)
    calls(home2, src, "--stage")
    calls(home2, src, "--apply")
    m2 = metadata(home2, src)
    need(m2["providerManaged"] is True and (app2 / tx.PROVIDERS).read_bytes() != provider2,
         "PINNED_MANAGED_PROVIDER_NOT_UPDATED")
    calls(home2, src, "--commit")
    unchanged_data(app2, user2)
    tests += 1
    # Negative: refuse re-entry if an interrupted transaction occupies slot.
    home3, app3, old3, user3, _ = initial(tmp/"case3")
    calls(home3, src, "--stage")
    calls(home3, src, "--stage", False)
    calls(home3, src, "--rollback")
    need((app3 / "direct_internet_method.py").read_bytes() == old3["direct_internet_method.py"], "REENTRY_CHANGED_BASELINE")
    unchanged_data(app3, user3)
    tests += 1
    # Negative: concurrent changes to managed code refuse overwrite.
    calls(home3, src, "--stage")
    changed = app3 / "direct_internet_method.py"
    changed.write_bytes(b"foreign-owner-edits\n")
    calls(home3, src, "--apply", False)
    need(changed.read_bytes() == b"foreign-owner-edits\n", "FOREIGN_PROGRAM_EDIT_WAS_DESTROYED")
    changed.write_bytes(old3["direct_internet_method.py"])
    calls(home3, src, "--rollback")
    tests += 1
    # Real rollback after managed code and metadata were changed: old bytes exact.
    calls(home3, src, "--stage")
    calls(home3, src, "--apply")
    metadata(home3, src)
    calls(home3, src, "--rollback")
    for name, body in old3.items():
        need((app3 / name).read_bytes() == body, "OLD_FILE_BYTE_NOT_RESTORED:" + name)
    unchanged_data(app3, user3)
    tests += 1
    # Negative: preserved personal setting symlink is not followed or replaced.
    home4, app4, old4, user4, _ = initial(tmp/"case4")
    external = home4 / "external-user-data"
    external.write_bytes(b"PRIVATE_DO_NOT_READ_OR_DELETE\n")
    (app4 / "settings.json").unlink()
    (app4 / "settings.json").symlink_to(external)
    calls(home4, src, "--stage", False)
    need(external.read_bytes() == b"PRIVATE_DO_NOT_READ_OR_DELETE\n", "SYMLINK_TARGET_CHANGED")
    tests += 1
    # Negative: file changed by another actor after stage must not be committed.
    home5, app5, old5, user5, _ = initial(tmp/"case5")
    calls(home5, src, "--stage")
    calls(home5, src, "--apply")
    metadata(home5, src)
    (app5 / "settings.json").write_bytes(b"CONCURRENT_USER_EDIT\n")
    calls(home5, src, "--commit", False)
    need((home5 / ".local/state/DirectInternetMethod/update-pending").exists(),
         "UNSAFE_AUTO_REMOVAL_OF_UNRESOLVED_TRANSACTION")
    need((app5 / "settings.json").read_bytes() == b"CONCURRENT_USER_EDIT\n", "USER_CONCURRENT_EDIT_DELETED")
    tests += 1
    # Negative: a foreign edit to the LAST managed program file must reject the
    # entire apply before changing the FIRST managed file. No partial mutation.
    home6, app6, old6, user6, _ = initial(tmp/"case6")
    calls(home6, src, "--stage")
    late = app6 / "user_update_transaction.py"
    late.write_bytes(b"FOREIGN_LATE_CODE_MUST_BE_PRESERVED\n")
    calls(home6, src, "--apply", False)
    need((app6 / "direct_internet_method.py").read_bytes() ==
         old6["direct_internet_method.py"], "PARTIAL_APPLICATION_PREVALIDATION_FAILED")
    need(late.read_bytes() == b"FOREIGN_LATE_CODE_MUST_BE_PRESERVED\n",
         "FOREIGN_LATE_CODE_WAS_OVERWRITTEN")
    late.write_bytes(old6["user_update_transaction.py"])
    calls(home6, src, "--rollback")
    unchanged_data(app6, user6)
    tests += 1
    # Negative: a new user edit after apply must block rollback BEFORE any
    # executable bytes change; the user edit must remain intact.
    home7, app7, old7, user7, _ = initial(tmp/"case7")
    calls(home7, src, "--stage")
    calls(home7, src, "--apply")
    metadata(home7, src)
    before_code = (app7 / "direct_internet_method.py").read_bytes()
    (app7 / "settings.json").write_bytes(b"NEW_USER_SETTING_KEEP\n")
    calls(home7, src, "--rollback", False)
    need((app7 / "direct_internet_method.py").read_bytes() == before_code,
         "ROLLBACK_MUTATED_CODE_BEFORE_REJECTING_USER_CONFIG_CHANGE")
    need((app7 / "settings.json").read_bytes() == b"NEW_USER_SETTING_KEEP\n",
         "ROLLBACK_OVERWROTE_USER_SETTING")
    (app7 / "settings.json").write_bytes(user7["settings.json"])
    calls(home7, src, "--rollback")
    unchanged_data(app7, user7)
    tests += 1
    # Accepted legacy v1.5.2 install can contain the EXACT public v1.5.1
    # uninstall.sh and v1.5.2 GUI; this is approved source provenance, not
    # a reason to leave duplicate installed versions.
    legacy = {
        rel: {"exists": True, "sha": next(iter(hashes)), "mode": 0o755}
        for rel, hashes in tx.OFFICIAL_LEGACY_SHA.items()
    }
    legacy["direct_internet_method.py"]["sha"] = (
        "613f878f989c6598d7ad25b82a75d37e727c557ad9a8c36f82cf0953d7567f99")
    legacy["uninstall.sh"]["sha"] = (
        "a6ba8ad80c7f7da73dd53d24b5985d5747a3724774f303f8cfb7ad8fbdab6431")
    tx.verify_installed_code_provenance({"schema": 2, "version": "1.5.2"}, legacy)
    tests += 1
    # Unknown user-modified executable must NOT be silently overwritten,
    # even if metadata merely names the old product version.
    modified = {key: dict(value) for key, value in legacy.items()}
    modified["uninstall.sh"]["sha"] = "0"*64
    try:
        tx.verify_installed_code_provenance({"schema": 2, "version": "1.5.2"}, modified)
    except RuntimeError as error:
        need("UNKNOWN_LEGACY_PROGRAM_PRESERVE" in str(error),
             "UNEXPECTED_LEGACY_FILE_REJECTION")
    else:
        raise AssertionError("UNKNOWN_CUSTOM_PROGRAM_FILE_FALSE_ACCEPTED")
    tests += 1
    # Single explicit application uninstall never deletes the mixed data directory.
    install_source = (ROOT / "linux/install.sh").read_text()
    uninstall_source = (ROOT / "linux/uninstall.sh").read_text()
    need("DirectInternetMethod-backup-$(date" not in install_source, "OLD_TIME_BACKUP_GENERATOR_PRESENT")
    need('rm -rf "$APP"' not in uninstall_source and
         "user_uninstall_preserve.py" in uninstall_source and
         "--remove-after-backend" in uninstall_source and
         "--verify" in uninstall_source, "DESTRUCTIVE_UNINSTALL_CONTRACT_REGRESSION")
    need("user_update_transaction.py" in install_source and
         "--stage" in install_source and "--commit" in install_source and
         "--rollback" in install_source, "TRANSACTION_LIFECYCLE_CONTRACT_MISSING")
    tests += 1
    # Negative uninstall: a live protected backend cannot be removed by a
    # rootless isolated fixture, and settings/metadata stay intact.
    env = dict(os.environ, HOME=str(home), PYTHONDONTWRITEBYTECODE="1")
    process = subprocess.run([sys.executable,"-B",str(UNINSTALL),"--verify"],
                             env=env,text=True,capture_output=True,timeout=8)
    need(process.returncode == 0, "UNINSTALL_MANAGED_HASH_PRECHECK_FAILED:" + process.stderr)
    tests += 1
    # Negative: the public uninstall CLI refuses to remove user code while the
    # actual protected backend remains; no fixture config may be harmed.
    if (pathlib.Path("/usr/lib/directinternetmethod/control.sh").exists() or
        pathlib.Path("/var/lib/directinternetmethod/install.json").exists()):
        negative = subprocess.run([sys.executable, "-B", str(UNINSTALL), "--remove-after-backend"],
                                  env=env, text=True, capture_output=True, timeout=8)
        need(negative.returncode != 0 and "PROTECTED_BACKEND_STILL_PRESENT" in negative.stderr,
             "UNINSTALL_PROTECTED_BACKEND_FAIL_CLOSED_MISSED")
        unchanged_data(app, user)
    else:
        # A clean ephemeral CI host has no protected backend to guard against.
        # Verify the production code includes the fail-closed root-state gate.
        uninstall_source = UNINSTALL.read_text(encoding="utf8")
        need("PROTECTED_BACKEND_STILL_PRESENT_REFUSE_USER_CODE_REMOVAL" in uninstall_source,
             "CLEAN_RUNNER_MISSING_PROTECTED_BACKEND_GUARD")
    tests += 1
    # Independently exercise the pure OWNED file deletion step against a fake
    # HOME. It may remove only hashes recorded for managed code, preserving
    # custom Router Gateway providers, all personal settings and runtime logs.
    pure = """
import importlib.util,pathlib,sys
z=importlib.util.spec_from_file_location("dimuninstall",sys.argv[1]);m=importlib.util.module_from_spec(z);z.loader.exec_module(m)
app,meta,known=m.load_owned()
assert len(known)>=7
n=m.remove_known_files(app,meta,known)
assert n>=7
print("PASS_PURE_OWNED_UNINSTALL",n)
"""
    custom_launcher=home / ".local/bin/direct-internet-method"
    custom_launcher.parent.mkdir(parents=True, exist_ok=True)
    custom_launcher.write_bytes(b"USER_MODIFIED_LAUNCHER_MUST_NOT_BE_REMOVED\n")
    pure_run=subprocess.run([sys.executable, "-B", "-c", pure, str(UNINSTALL)],
                            env=env, text=True, capture_output=True, timeout=8)
    need(pure_run.returncode == 0, "OWNED_UNINSTALL_SANDBOX_FAILURE:" + pure_run.stderr)
    unchanged_data(app, user)
    need((app / tx.PROVIDERS).read_bytes() == provider, "UNINSTALL_DESTROYED_CUSTOM_ROUTER_PROVIDER")
    need(not (app / "direct_internet_method.py").exists() and
         not (app / "INSTALL.json").exists(), "UNINSTALL_DID_NOT_REMOVE_OWNED_CODE")
    need(app.exists(), "USER_DATA_DIRECTORY_REMOVED")
    need(custom_launcher.read_bytes()==b"USER_MODIFIED_LAUNCHER_MUST_NOT_BE_REMOVED\n",
         "UNINSTALL_REMOVED_UNTRACKED_CUSTOM_LAUNCHER")
    tests += 1
    need(all(x in install_source for x in (
        'if [ ! -e "$BIN/direct-internet-method" ]',
        'if [ ! -e "$DESKTOP_FILE" ]',
        'if [ ! -e "$ICONS/direct-internet-method.svg" ]',
        'p.read_bytes()==expected',
        '"managedLaunchersSha256":launchers')),
        "INSTALL_UPGRADE_MIGHT_OVERWRITE_CUSTOM_USER_LAUNCHER")
    tests += 1

print("PASS_LINUX_ONE_INSTALL_DATA_PRESERVING_TRANSACTION_NEGATIVE_FIRST_FIXTURES:",tests,"/",tests)
