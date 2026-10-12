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
    # Mirror actual public ZIP: linux/ and router_gateway/ are siblings.
    src = tmp / ("source-" + tag) / "linux"
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

    # Real-package regression: missing sibling provider source refuses stage.
    missing_src = source_tree(tmp, "missing-provider")
    (missing_src / tx.PROVIDER_SOURCE).unlink()
    missing_home, missing_app, _, missing_user, _ = initial(tmp / "case-missing-provider")
    calls(missing_home, missing_src, "--stage", False)
    need(not (missing_home / ".local/state/DirectInternetMethod/update-pending").exists(),
         "MISSING_REAL_PACKAGE_PROVIDER_CREATED_PENDING_TRANSACTION")
    unchanged_data(missing_app, missing_user)
    tests += 1

print("PASS_LINUX_ONE_INSTALL_DATA_PRESERVING_TRANSACTION_NEGATIVE_FIRST_FIXTURES:",tests,"/",tests)


# R421 regression: execute the ACTUAL metadata heredoc from install.sh against
# a disposable HOME, replacing ONLY the root-owned backend lookup with a fixture.
# Never install, elevate, change the host network, or touch a real user profile.
with tempfile.TemporaryDirectory(prefix="dim-r421-f415-") as td:
    sandbox = pathlib.Path(td)
    fake_home = sandbox / "home"
    fake_app = fake_home / ".local/share/DirectInternetMethod"
    fake_app.mkdir(parents=True)
    fake_router = fake_app / "router_gateway"
    fake_router.mkdir()
    custom_provider = fake_router / "providers.json"
    custom_provider.write_bytes(b'{"customService":"KEEP_ORIGINAL"}\n')
    user_setting = fake_app / "settings.json"
    user_setting.write_bytes(b'{"custom":true}\n')
    (fake_app / "direct-internet-method.svg").write_bytes(b"<svg/>")
    pending = fake_home / ".local/state/DirectInternetMethod/update-pending"
    pending.mkdir(parents=True)
    (pending / "manifest.json").write_text(json.dumps({
        "providerSha": "a" * 64,
        "providerManaged": False,
        "managed": {"direct_internet_method.py": {"sha": "b" * 64},
                    "router_gateway/providers.json": {"sha": "c" * 64}},
    }))
    protected = sandbox / "fake-protected-backend.json"
    protected.write_text(json.dumps({"version": "1.5.2"}))
    old_metadata = b'{"schema":2,"version":"1.5.1"}\n'
    metadata_path = fake_app / "INSTALL.json"
    metadata_path.write_bytes(old_metadata)
    launcher_before = (fake_app / "direct-internet-method.svg").read_bytes()
    provider_before = custom_provider.read_bytes()
    settings_before = user_setting.read_bytes()
    marker = 'python3 - "$APP/INSTALL.json" "$USER_TRANSACTION" <<' + "'PY'\n"
    need(install_source.count(marker) == 1, "F415_WRITER_HEREDOC_MISSING_OR_DUPLICATE")
    inline = install_source.split(marker, 1)[1].split("\nPY\n", 1)[0] + "\n"
    backend_lookup = 'protected=json.loads(pathlib.Path("/var/lib/directinternetmethod/install.json").read_text(encoding="utf-8"))'
    need(inline.count(backend_lookup) == 1, "F415_BACKEND_LOOKUP_DRIFT")
    inline = inline.replace(backend_lookup,
                            'protected=json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))')
    need("transaction_helper.atomic_bytes(" in inline and ".write_text(json.dumps(" not in inline,
         "F415_DIRECT_METADATA_TRUNCATION_REGRESSION")
    compile(inline, "R421_INSTALL_METADATA_HEREDOC", "exec")
    fixture_env = dict(os.environ, HOME=str(fake_home), PYTHONDONTWRITEBYTECODE="1")
    def run_inline():
        return subprocess.run(
            [sys.executable, "-B", "-", str(metadata_path), str(TX), str(protected)],
            input=inline, text=True, capture_output=True,
            env=fixture_env, timeout=10)
    # Fail-closed stale atomic stage never overwrites either item.
    stage_path = fake_app / ".INSTALL.json.dim-update-stage"
    stage_path.write_bytes(b"FOREIGN_OR_INTERRUPTED_STAGE_KEEP")
    negative = run_inline()
    need(negative.returncode != 0 and "STALE_ATOMIC_TEMP" in negative.stderr,
         "F415_STALE_STAGE_WRONGLY_ACCEPTED:" + negative.stderr)
    need(metadata_path.read_bytes() == old_metadata and
         stage_path.read_bytes() == b"FOREIGN_OR_INTERRUPTED_STAGE_KEEP",
         "F415_STALE_STAGE_WAS_MODIFIED")
    stage_path.unlink()  # Only our owned disposable test file.
    # Symlink attempt must be rejected without modifying the foreign target.
    foreign = sandbox / "foreign-metadata.json"
    foreign.write_bytes(b"FOREIGN_TARGET_KEEP")
    metadata_path.unlink()
    metadata_path.symlink_to(foreign)
    rejected = run_inline()
    need(rejected.returncode != 0 and "FOREIGN_MANAGED_FILE_OR_SYMLINK" in rejected.stderr,
         "F415_SYMLINK_WAS_NOT_REJECTED:" + rejected.stderr)
    need(foreign.read_bytes() == b"FOREIGN_TARGET_KEEP" and metadata_path.is_symlink(),
         "F415_SYMLINK_TARGET_CHANGED")
    metadata_path.unlink()
    metadata_path.write_bytes(old_metadata)
    # Positive path replaces metadata once, preserves custom data and is private.
    accepted = run_inline()
    need(accepted.returncode == 0, "F415_ATOMIC_METADATA_WRITE_FAILED:" + accepted.stderr)
    doc = json.loads(metadata_path.read_text(encoding="utf-8"))
    need(doc["version"] == "1.5.2" and doc["schema"] == 2
         and doc["managedCodeSha256"] == {"direct_internet_method.py": "b" * 64}
         and doc["preservedCustomProviderData"] is True,
         "F415_METADATA_POSTCONDITION_INVALID")
    need(metadata_path.stat().st_mode & 0o777 == 0o600,
         "F415_METADATA_PERMISSIONS_NOT_PRIVATE")
    need(not stage_path.exists(), "F415_ATOMIC_STAGE_LEFT_ON_SUCCESS")
    need(custom_provider.read_bytes() == provider_before and
         user_setting.read_bytes() == settings_before and
         (fake_app / "direct-internet-method.svg").read_bytes() == launcher_before,
         "F415_ATOMIC_WRITER_CHANGED_MUTABLE_USER_DATA")
    print("PASS_F415_METADATA_ATOMIC_INSTALL_INLINE:", 3, "/", 3)


# R423 F418: real SIGKILL during actual atomic_bytes(). Explicit one-file
# recover requires exact operator-known stage SHA, a valid pending manifest,
# exact managed code, unchanged old metadata and intact user configuration.
with tempfile.TemporaryDirectory(prefix="dim-r423-real-sigkill-") as td:
    case = pathlib.Path(td)
    source = source_tree(case, "r423")
    home, app, old, user, provider_before = initial(case / "installed")
    calls(home, source, "--stage")
    calls(home, source, "--apply")
    pending = home / ".local/state/DirectInternetMethod/update-pending"
    manifest = json.loads((pending / "manifest.json").read_text(encoding="utf-8"))
    doc = {
        "schema": 2,
        "product": "Direct Internet Method",
        "version": "1.5.2",
        "platform": "linux-x86_64",
        "installedUtc": "2026-10-12T00:00:00Z",
        "networkMutationOnInstall": False,
        "normalRunRequiresAdmin": False,
        "systemBackend": "/usr/lib/directinternetmethod",
        "protectedBackendVersion": "1.5.2",
        "protectedBackendByteCompatible": True,
        "onlineUpdate": "GitHub latest release + SHA256SUMS verification",
        "managedProviderSha256": manifest["providerSha"],
        "preservedCustomProviderData": not manifest["providerManaged"],
        "managedCodeSha256": {k: v["sha"] for k, v in manifest["managed"].items()
                              if k != tx.PROVIDERS},
        "managedLaunchersSha256": {},
        "updateMode": "IN_PLACE_SINGLE_INSTALL_DATA_PRESERVED",
    }
    intended = (json.dumps(doc, indent=2) + "\n").encode("utf-8")
    payload = case / "intended.json"
    payload.write_bytes(intended)
    install_record = app / tx.METADATA
    stage_path = app / ".INSTALL.json.dim-update-stage"
    env = dict(os.environ, HOME=str(home), PYTHONDONTWRITEBYTECODE="1")
    child = r'''
import importlib.util, os, pathlib, signal, sys
spec = importlib.util.spec_from_file_location("dim_crash_helper", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
def crash_before_replace(source, destination):
    os.kill(os.getpid(), signal.SIGKILL)
m.os.replace = crash_before_replace
m.atomic_bytes(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]).read_bytes(), 0o600)
'''
    killed = subprocess.run([sys.executable, "-B", "-c", child, str(TX),
                              str(install_record), str(payload)],
                             env=env, text=True, capture_output=True, timeout=10)
    need(killed.returncode == -9, "F418_DID_NOT_REAL_SIGKILL:" + str(killed.returncode))
    need(stage_path.is_file() and stage_path.read_bytes() == intended,
         "F418_SIGKILL_STAGE_MISSING_OR_CHANGED")
    need(install_record.read_bytes() == old[tx.METADATA],
         "F418_SIGKILL_DAMAGED_ORIGINAL_METADATA")
    digest_stage = digest(intended)
    def recover(sha, positive=False):
        result = subprocess.run([sys.executable, "-B", str(TX),
                                 "--recover-metadata-stage", "--expected-stage-sha256", sha],
                                env=env, text=True, capture_output=True, timeout=10)
        if positive:
            need(result.returncode == 0 and "PASS_EXACT_OWNED" in result.stdout,
                 "F418_VALID_STAGE_NOT_RECOVERED:" + result.stderr)
        else:
            need(result.returncode != 0 and "FAIL_CLOSED" in result.stderr,
                 "F418_UNTRUSTED_STAGE_FALSE_ACCEPTED")
        return result
    cases = 0
    recover("0" * 64)
    need(stage_path.read_bytes() == intended, "F418_WRONG_DIGEST_REMOVED_STAGE")
    cases += 1
    stage_path.chmod(0o644)
    recover(digest_stage)
    need(stage_path.is_file(), "F418_NONPRIVATE_STAGE_REMOVED")
    stage_path.chmod(0o600)
    cases += 1
    stage_path.write_bytes(b'{"partial":')
    recover(digest_stage)
    need(stage_path.read_bytes() == b'{"partial":', "F418_PARTIAL_STAGE_REMOVED")
    stage_path.write_bytes(intended)
    stage_path.chmod(0o600)
    cases += 1
    foreign = case / "foreign-not-ours"
    foreign.write_bytes(b"FOREIGN_CONTENT_MUST_SURVIVE")
    stage_path.unlink()
    stage_path.symlink_to(foreign)
    recover(digest_stage)
    need(foreign.read_bytes() == b"FOREIGN_CONTENT_MUST_SURVIVE" and
         stage_path.is_symlink(), "F418_SYMLINK_FOLLOWED_OR_DELETED")
    stage_path.unlink()
    stage_path.write_bytes(intended)
    stage_path.chmod(0o600)
    cases += 1
    original = install_record.read_bytes()
    install_record.write_bytes(b"FOREIGN_CONCURRENT_METADATA")
    recover(digest_stage)
    need(stage_path.is_file() and install_record.read_bytes() ==
         b"FOREIGN_CONCURRENT_METADATA", "F418_CONCURRENT_METADATA_LOST")
    install_record.write_bytes(original)
    cases += 1
    managed = app / "direct_internet_method.py"
    managed_bytes = managed.read_bytes()
    managed.write_bytes(b"OTHER_ACTOR_CODE")
    recover(digest_stage)
    need(managed.read_bytes() == b"OTHER_ACTOR_CODE" and stage_path.is_file(),
         "F418_FOREIGN_MANAGED_CODE_UNSAFE_RECOVERY")
    managed.write_bytes(managed_bytes)
    cases += 1
    settings = app / "settings.json"
    original_settings = settings.read_bytes()
    settings.write_bytes(b"USER_UPDATED_SETTINGS")
    recover(digest_stage)
    need(settings.read_bytes() == b"USER_UPDATED_SETTINGS" and stage_path.is_file(),
         "F418_USER_EDIT_NOT_PRESERVED")
    settings.write_bytes(original_settings)
    cases += 1
    compromised = dict(doc)
    compromised["managedCodeSha256"] = {"direct_internet_method.py": "0"*64}
    stage_path.write_bytes((json.dumps(compromised) + "\n").encode())
    stage_path.chmod(0o600)
    recover(digest(stage_path.read_bytes()))
    need(stage_path.is_file(), "F418_FOREIGN_DOCUMENT_WITH_DIGEST_WRONGLY_REMOVED")
    stage_path.write_bytes(intended)
    stage_path.chmod(0o600)
    cases += 1
    recover(digest_stage, positive=True)
    need(not stage_path.exists() and pending.is_dir(),
         "F418_ONLY_OWNED_STAGE_SHOULD_BE_REMOVED_PENDING_MUST_REMAIN")
    need(install_record.read_bytes() == old[tx.METADATA],
         "F418_RECOVERY_OVERWROTE_OLD_METADATA")
    need((app / tx.PROVIDERS).read_bytes() == provider_before,
         "F418_RECOVERY_CHANGED_CUSTOM_PROVIDER")
    unchanged_data(app, user)
    cases += 1
    # Explicit rollback after safe stage attestation restores EVERY old program
    # file, original INSTALL.json and all personal settings without duplicate
    # directories or app/backend/network mutations.
    calls(home, source, "--rollback")
    for name, previous in old.items():
        need((app / name).read_bytes() == previous,
             "F418_ROLLBACK_OLD_BYTES_DRIFT:" + name)
    unchanged_data(app, user)
    need((app / tx.PROVIDERS).read_bytes() == provider_before and
         not pending.exists(), "F418_ROLLBACK_USER_DATA_OR_SLOT_FAILED")
    cases += 1
    # With no pending transaction, an arbitrary new staged file can never
    # trigger cleanup (even with its SHA supplied by the caller).
    stage_path.write_bytes(intended)
    stage_path.chmod(0o600)
    recover(digest_stage)
    need(stage_path.read_bytes() == intended, "F418_NO_PENDING_STAGE_REMOVED")
    cases += 1
    print("PASS_F418_SIGKILL_ATTESTED_STAGE_RECOVERY_NEGATIVE_FIRST:",
          cases, "/", cases, "REAL_SIGKILL_CODE", killed.returncode)
