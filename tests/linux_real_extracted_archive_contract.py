#!/usr/bin/env python3
"""R430: test the actual *extracted ZIP* installer transaction, not a fake linux/ tree.

Run after: python3 build_linux_package.py
Never requests root or mutates installed apps, protected backend, network or services.
All Stage/Apply/Commit/Rollback operations run inside independent disposable HOME.
"""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARCHIVE = (
    pathlib.Path(sys.argv[1]).resolve()
    if len(sys.argv) == 2
    else ROOT / "delivery/DirectInternetMethod_1.5.4_Linux_x86_64.zip"
)
PACKAGE = "DirectInternetMethod_1.5.4_Linux_x86_64"


def need(ok, reason):
    if not ok:
        raise AssertionError("R430_REAL_ARCHIVE:" + reason)


def run(helper, home, command, source=None, pass_expected=True, marker=None):
    args = [sys.executable, "-B", str(helper), command]
    if source is not None:
        args += ["--source", str(source)]
    env = dict(os.environ, HOME=str(home), PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(args, capture_output=True, text=True, env=env, timeout=15)
    if pass_expected:
        need(result.returncode == 0, f"{command}_FAILED:{result.stderr}")
    else:
        need(result.returncode != 0 and "FAIL_CLOSED" in result.stderr,
             f"{command}_DID_NOT_FAIL_CLOSED:{result.stdout}")
        if marker:
            need(marker in result.stderr, "WRONG_REJECTION:" + result.stderr)
    return result


def home_fixture(base):
    home = base / "home"
    app = home / ".local/share/DirectInternetMethod"
    (app / "router_gateway").mkdir(parents=True)
    settings = b'{"customUser":"PRESERVE"}\n'
    provider = b'{"customRouterProvider":"PRESERVE"}\n'
    (app / "settings.json").write_bytes(settings)
    (app / "router_gateway/providers.json").write_bytes(provider)
    return home, app, settings, provider


def metadata(app, home):
    manifest_path = home / ".local/state/DirectInternetMethod/update-pending/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    data = {
        "schema": 2,
        "version": "1.5.4",
        "managedProviderSha256": manifest["providerSha"],
        "managedCodeSha256": {
            key: val["sha"] for key, val in manifest["managed"].items()
            if key != "router_gateway/providers.json"
        },
        "managedLaunchersSha256": {},
    }
    (app / "INSTALL.json").write_bytes((json.dumps(data) + "\n").encode("utf-8"))


def kept(app, user, provider):
    need((app / "settings.json").read_bytes() == user, "SETTINGS_CHANGED")
    need((app / "router_gateway/providers.json").read_bytes() == provider,
         "CUSTOM_PROVIDER_CHANGED")


need(ARCHIVE.is_file() and not ARCHIVE.is_symlink(), "REAL_ZIP_MISSING")
with zipfile.ZipFile(ARCHIVE) as archive:
    need(archive.testzip() is None, "REAL_ZIP_CRC_FAILED")
    records = archive.infolist()
    names = [item.filename for item in records]
    need(len(names) == 24 and len(names) == len(set(names)), "ZIP_MEMBERS_NOT_24_UNIQUE")
    need(all(name.startswith(PACKAGE + "/") and ".." not in
             pathlib.PurePosixPath(name).parts for name in names),
         "ZIP_UNTRUSTED_TRAVERSAL_OR_PACKAGE_ROOT")
    doc = json.loads(archive.read(PACKAGE + "/PACKAGE_MANIFEST.json"))
    need(len(doc["files"]) == 22, "REAL_ZIP_MANIFEST_COUNT_WRONG")
    for row in doc["files"]:
        raw = archive.read(PACKAGE + "/" + row["file"])
        need(hashlib.sha256(raw).hexdigest().upper() == row["sha256"] and
             len(raw) == row["bytes"], "BAD_ZIP_MEMBER_SHA:" + row["file"])

with tempfile.TemporaryDirectory(prefix="dim-r430-real-extracted-") as temporary:
    temp = pathlib.Path(temporary)
    with zipfile.ZipFile(ARCHIVE) as archive:
        archive.extractall(temp)
    source = temp / PACKAGE
    helper = source / "app/user_update_transaction.py"
    need(helper.is_file() and (source / "install.sh").is_file() and
         (source / "app/router_gateway/providers.json").is_file(),
         "EXTRACTED_ZIP_LAYOUT_MISSING")
    checks = 0

    # Real ZIP, not a synthetic repository linux/ directory.
    home, app, user, provider = home_fixture(temp / "case-success")
    run(helper, home, "--stage", source)
    run(helper, home, "--apply", source)
    metadata(app, home)
    run(helper, home, "--commit")
    kept(app, user, provider)
    need(not (home / ".local/state/DirectInternetMethod/update-pending").exists(),
         "BACKUP_SLOT_NOT_CLEARED")
    need((app / "direct_internet_method.py").is_file() and
         (app / "INSTALL.json").is_file(), "EXTRACTED_APP_NOT_INSTALLED")
    checks += 1

    # Correct rollback restores old state in disposable HOME without touching user files.
    home2, app2, user2, provider2 = home_fixture(temp / "case-rollback")
    run(helper, home2, "--stage", source)
    run(helper, home2, "--apply", source)
    metadata(app2, home2)
    run(helper, home2, "--rollback")
    kept(app2, user2, provider2)
    need(not (app2 / "INSTALL.json").exists() and
         not (app2 / "direct_internet_method.py").exists() and
         not (home2 / ".local/state/DirectInternetMethod/update-pending").exists(),
         "ROLLBACK_OLD_CODE_NOT_RESTORED")
    checks += 1

    # Tampering a real extracted member must fail before creating update-pending.
    tamper = source / "app/router_gateway/providers.json"
    original_provider = tamper.read_bytes()
    tamper.write_bytes(b'{"foreignProvider":"DO_NOT_INSTALL"}\n')
    home3, app3, user3, provider3 = home_fixture(temp / "case-tamper")
    run(helper, home3, "--stage", source, False,
        "EXTRACTED_PACKAGE_FILE_DIGEST_CHANGED")
    need(not (home3 / ".local/state/DirectInternetMethod/update-pending").exists(),
         "TAMPER_LEFT_PENDING_SLOT")
    kept(app3, user3, provider3)
    tamper.write_bytes(original_provider)
    checks += 1

    # Foreign symlink in the archive content must never be followed.
    foreign = temp / "foreign-private"
    foreign.write_bytes(b"FOREIGN_MUST_NOT_BE_ACCESSED")
    tamper.unlink()
    tamper.symlink_to(foreign)
    home4, app4, user4, provider4 = home_fixture(temp / "case-symlink")
    run(helper, home4, "--stage", source, False,
        "EXTRACTED_PACKAGE_SYMLINK_OR_MISSING_MEMBER")
    need(foreign.read_bytes() == b"FOREIGN_MUST_NOT_BE_ACCESSED" and
         not (home4 / ".local/state/DirectInternetMethod/update-pending").exists(),
         "FOLLOWED_FOREIGN_SYMLINK")
    kept(app4, user4, provider4)
    tamper.unlink()
    tamper.write_bytes(original_provider)
    checks += 1

    # An unsigned or modified SHA256SUMS is not accepted as exact ZIP provenance.
    sums = source / "SHA256SUMS.txt"
    old_sums = sums.read_bytes()
    sums.write_bytes(b"FOREIGN_SUMS")
    home5, app5, user5, provider5 = home_fixture(temp / "case-sums")
    run(helper, home5, "--stage", source, False,
        "EXTRACTED_PACKAGE_SHA256SUMS_MISMATCH")
    need(not (home5 / ".local/state/DirectInternetMethod/update-pending").exists(),
         "FORGED_SUMS_LEFT_PENDING")
    kept(app5, user5, provider5)
    sums.write_bytes(old_sums)
    checks += 1

    # A directory merely containing the same files but not the package root
    # cannot be mistaken for an accepted extracted release.
    renamed = temp / "unknown-custom-extracted-copy"
    source.rename(renamed)
    helper2 = renamed / "app/user_update_transaction.py"
    home6, app6, user6, provider6 = home_fixture(temp / "case-foreign-layout")
    run(helper2, home6, "--stage", renamed, False,
        "SOURCE_PACKAGE_LAYOUT_NOT_LINUX_OR_EXTRACTED_ZIP")
    kept(app6, user6, provider6)
    checks += 1

    need(checks == 6, "NEGATIVE_FIRST_TEST_COUNT_NOT_6")
    print("PASS_R430_ACTUAL_EXTRACTED_LINUX_ZIP_TRANSACTION:", checks, "/", checks)
    print("PASS_RELEASE_ZIP_22_OF_22_MEMBERS_HASH_VERIFIED")
    print("NO_INSTALLED_HOST_OR_NETWORK_MUTATION")
