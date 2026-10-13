#!/usr/bin/env python3
"""Single-slot, fail-closed in-place user payload transaction for Direct Internet Method.

The executable files and INSTALL.json are managed. Mutable user settings,
custom hosts, strategy, scope, adult data, router data and runtime state are
NEVER removed or overwritten. Code snapshot exists ONLY while uncommitted;
no date-stamped backup proliferation or duplicate installed versions.

--stage / --apply / --commit / --rollback [--source <extracted Linux package>]
The caller must stage BEFORE any protected backend or user code mutation.
A stale/foreign pending transaction blocks new updates until reconciled.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import stat
import sys

FILES = (
    ("app/direct_internet_method.py", "direct_internet_method.py", 0o755),
    ("app/router_gateway.py", "router_gateway.py", 0o755),
    ("app/router_gateway_core.py", "router_gateway_core.py", 0o644),
    ("app/direct-internet-method.svg", "direct-internet-method.svg", 0o644),
    ("uninstall.sh", "uninstall.sh", 0o755),
    ("app/user_uninstall_preserve.py", "user_uninstall_preserve.py", 0o755),
    ("app/user_update_transaction.py", "user_update_transaction.py", 0o755),
)
METADATA = "INSTALL.json"
PROVIDERS = "router_gateway/providers.json"
PROVIDER_SOURCE = "../router_gateway/providers.json"
# Exact public package provenance:
# v1.5.1 Linux ZIP SHA 21FE512444957008DA4D79F540ABCEAD5CC9CB18481F1FF8B620A4B90A9374B8
# v1.5.2 Linux ZIP SHA 0218BEBD0DC8F88670374FF0E12A61D45229A03092C606678C5C00FD81DC2C9E
# Supports an installed 1.5.2 GUI with the official earlier 1.5.1 uninstaller.
# Unrecognized modified program files must never be silently overwritten.
OFFICIAL_LEGACY_SHA = {
    "direct_internet_method.py": frozenset({
        "6567584f96efbe9febcaeb3229b85f444110b92f2d369c1974b3c4eb333f82d8",
        "613f878f989c6598d7ad25b82a75d37e727c557ad9a8c36f82cf0953d7567f99",
    }),
    "router_gateway.py": frozenset({
        "936376d29f05b0e8b37fa6bd8a4cdb3f3160463e138ee4abab43e18aecfc1c86",
    }),
    "router_gateway_core.py": frozenset({
        "7817dd0bae1e42d82a85fcce823e872d30cc4a2e95d515d0c1540a29d7df4a90",
    }),
    "direct-internet-method.svg": frozenset({
        "305a2fa1f5310f9619110e805194846fd191fbe7c90843d3bf7492d8c1d155c3",
    }),
    "uninstall.sh": frozenset({
        "a6ba8ad80c7f7da73dd53d24b5985d5747a3724774f303f8cfb7ad8fbdab6431",
        "4284b55de76b39df46525d4e790ef57f90355ad161d4b07023eff1233beb3048",
    }),
}
MUTABLE = (
    "settings.json", "strategy.txt", "scope.txt", "custom-hosts.txt",
    "adult-enabled.txt", "adult-hosts.txt", "adult-hosts.meta.json",
)


def guard(ok: bool, code: str):
    if not ok:
        raise RuntimeError(code)


def filehash(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def regular_or_missing(path: pathlib.Path) -> bool:
    if path.is_symlink():
        return False
    if not path.exists():
        return True
    return path.is_file() and stat.S_ISREG(path.lstat().st_mode)


def fsync_dir(path: pathlib.Path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_bytes(path: pathlib.Path, data: bytes, mode: int):
    guard(regular_or_missing(path), "FOREIGN_MANAGED_FILE_OR_SYMLINK:" + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    guard(not path.parent.is_symlink(), "SYMLINK_PARENT")
    tmp = path.with_name("." + path.name + ".dim-update-stage")
    guard(not tmp.exists() and not tmp.is_symlink(), "STALE_ATOMIC_TEMP:" + str(tmp))
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        fsync_dir(path.parent)
    except BaseException:
        if tmp.exists() and not tmp.is_symlink():
            tmp.unlink()
        raise


def context():
    home = pathlib.Path.home()
    guard(home.is_absolute() and not home.is_symlink(), "HOME_IDENTITY_UNSAFE")
    guard(os.geteuid() != 0, "REFUSE_ROOT_USER_INSTALL")
    app = home / ".local/share/DirectInternetMethod"
    state = home / ".local/state/DirectInternetMethod"
    pending = state / "update-pending"
    for p in (app, app.parent, state, state.parent, pending):
        guard(not p.is_symlink(), "SYMLINK_PATH_REFUSED:" + str(p))
    guard(not app.exists() or app.is_dir(), "APP_NOT_DIRECTORY")
    guard(not pending.exists() or pending.is_dir(), "PENDING_NOT_DIRECTORY")
    return app, state, pending


def source_files(root: pathlib.Path) -> dict:
    """Accept BOTH the Git repository linux/ source and real extracted Linux ZIP.

    Verify every archive member against the package's own independent manifest
    before staging anything; never resolve unowned symlinks from an archive.
    """
    guard(root.is_absolute() and root.is_dir() and not root.is_symlink() and
          not root.parent.is_symlink(), "SOURCE_PACKAGE_INVALID")
    archive_layout = root.name == "DirectInternetMethod_1.5.4_Linux_x86_64"
    source_layout = root.name == "linux"
    guard(archive_layout or source_layout, "SOURCE_PACKAGE_LAYOUT_NOT_LINUX_OR_EXTRACTED_ZIP")
    if archive_layout:
        manifest_path = root / "PACKAGE_MANIFEST.json"
        sums_path = root / "SHA256SUMS.txt"
        guard(manifest_path.is_file() and not manifest_path.is_symlink() and
              sums_path.is_file() and not sums_path.is_symlink(),
              "EXTRACTED_PACKAGE_MANIFEST_MISSING_OR_SYMLINK")
        try:
            package_doc = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeError) as ex:
            raise RuntimeError("EXTRACTED_PACKAGE_MANIFEST_INVALID_JSON") from ex
        guard(isinstance(package_doc, dict) and package_doc.get("schema") == 1 and
              package_doc.get("product") == "Direct Internet Method" and
              package_doc.get("version") == "1.5.4" and
              package_doc.get("platform") == "linux-x86_64" and
              isinstance(package_doc.get("files"), list) and
              len(package_doc["files"]) == 22, "EXTRACTED_PACKAGE_IDENTITY_WRONG")
        seen = set()
        digest_lines = []
        for item in package_doc["files"]:
            guard(isinstance(item, dict) and
                  set(item) == {"file", "bytes", "sha256"} and
                  isinstance(item["file"], str) and
                  isinstance(item["bytes"], int) and item["bytes"] >= 0 and
                  isinstance(item["sha256"], str) and len(item["sha256"]) == 64 and
                  all(c in "0123456789ABCDEF" for c in item["sha256"]),
                  "EXTRACTED_MANIFEST_ROW_INVALID")
            path = pathlib.PurePosixPath(item["file"])
            guard(not path.is_absolute() and
                  all(part not in ("", ".", "..") for part in path.parts) and
                  path.as_posix() == item["file"] and
                  item["file"] not in seen,
                  "EXTRACTED_MANIFEST_UNSAFE_PATH_OR_DUPLICATE")
            seen.add(item["file"])
            full = root.joinpath(*path.parts)
            guard(full.is_file() and not full.is_symlink() and
                  all(not part.is_symlink() for part in
                      [root.joinpath(*path.parts[:i]) for i in range(1, len(path.parts))]),
                  "EXTRACTED_PACKAGE_SYMLINK_OR_MISSING_MEMBER")
            guard(full.stat().st_size == item["bytes"] and
                  filehash(full).upper() == item["sha256"],
                  "EXTRACTED_PACKAGE_FILE_DIGEST_CHANGED:" + item["file"])
            digest_lines.append(item["sha256"] + "  " + item["file"] + "\n")
        needed = {origin for origin, _, _ in FILES}
        needed.add("app/router_gateway/providers.json")
        guard(needed <= seen, "EXTRACTED_PACKAGE_REQUIRED_FILES_MISSING")
        guard(sums_path.read_text(encoding="utf-8") == "".join(digest_lines),
              "EXTRACTED_PACKAGE_SHA256SUMS_MISMATCH")
        provider = root / "app/router_gateway/providers.json"
    else:
        provider_parent = root.parent / "router_gateway"
        guard(provider_parent.is_dir() and not provider_parent.is_symlink(),
              "PROVIDER_PACKAGE_DIR_UNSAFE")
        provider = provider_parent / "providers.json"
    out = {}
    for origin, dest, mode in FILES:
        p = root / origin
        guard(p.is_file() and not p.is_symlink() and
              not p.parent.is_symlink(), "SOURCE_PAYLOAD_MISSING_OR_SYMLINK:" + origin)
        out[dest] = {"path": p, "sha": filehash(p), "mode": mode}
    guard(provider.is_file() and not provider.is_symlink() and
          not provider.parent.is_symlink(),
          "PROVIDER_SOURCE_MISSING_OR_UNSAFE")
    out[PROVIDERS] = {"path": provider, "sha": filehash(provider), "mode": 0o644}
    return out


def safe_old(path: pathlib.Path, app: pathlib.Path) -> dict:
    guard(path.is_relative_to(app) and not path.parent.is_symlink() and
          regular_or_missing(path), "FOREIGN_OLD_MANAGED_PATH:" + str(path))
    if path.exists():
        guard(path.stat().st_uid == os.getuid(), "FOREIGN_OLD_OWNER")
        return {"exists": True, "sha": filehash(path), "mode": stat.S_IMODE(path.stat().st_mode)}
    return {"exists": False, "sha": None, "mode": None}


def payload_for_stage(src: pathlib.Path, app: pathlib.Path):
    payload = source_files(src)
    old = app / METADATA
    guard(regular_or_missing(old), "INSTALL_METADATA_SYMLINK")
    prior = {}
    if old.exists():
        try:
            prior = json.loads(old.read_text(encoding="utf8"))
            guard(isinstance(prior, dict), "INSTALL_METADATA_NOT_OBJECT")
        except (ValueError, UnicodeError) as ex:
            raise RuntimeError("UNKNOWN_INSTALL_METADATA_PRESERVE") from ex
    providers = app / PROVIDERS
    old_provider = safe_old(providers, app)
    tracked = prior.get("managedProviderSha256")
    provider_is_managed = (not old_provider["exists"] or
                           (isinstance(tracked, str) and tracked.lower() == old_provider["sha"]))
    if not provider_is_managed:
        del payload[PROVIDERS]  # User/unknown provider data stays exactly as found.
    return payload, prior, provider_is_managed


def verify_installed_code_provenance(prior: dict, old: dict):
    """Before overwriting, require a prior managed hash or exact official legacy SHA.

    Older v1.5.1/v1.5.2 install records lack managedCodeSha256. Published
    package hashes supply the only accepted fallback. Unknown edits are
    preserved for explicit owner review instead of silently discarded.
    """
    declared = prior.get("managedCodeSha256", {})
    guard(isinstance(declared, dict), "PRIOR_MANAGED_CODE_PROVENANCE_NOT_OBJECT")
    for rel, info in old.items():
        if rel in (METADATA, PROVIDERS) or not info["exists"]:
            continue
        observed = info["sha"]
        if rel in declared:
            guard(isinstance(declared[rel], str) and
                  declared[rel].lower() == observed,
                  "PRIOR_CODE_MODIFIED_PRESERVE:" + rel)
        else:
            guard(prior.get("schema") == 2 and
                  prior.get("version") in ("1.5.1", "1.5.2") and
                  observed in OFFICIAL_LEGACY_SHA.get(rel, ()),
                  "UNKNOWN_LEGACY_PROGRAM_PRESERVE:" + rel)


def stage(src: pathlib.Path):
    app, state, pending = context()
    guard(not pending.exists(), "UNFINISHED_UPDATE_EXISTS_NO_OVERWRITE")
    payload, prior, providers_managed = payload_for_stage(src, app)
    old = {}
    for relative in list(payload) + [METADATA]:
        old[relative] = safe_old(app / relative, app)
    verify_installed_code_provenance(prior, old)
    for name in MUTABLE:
        guard(regular_or_missing(app / name), "MUTABLE_USER_FILE_SYMLINK:" + name)
    cfg = {name: filehash(app / name) if (app / name).exists() else None for name in MUTABLE}
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    guard(state.stat().st_uid == os.getuid(), "FOREIGN_UPDATE_STATE_OWNER")
    pending.mkdir(mode=0o700)
    try:
        (pending / "old").mkdir(mode=0o700)
        manifest = {
            "schema": 1, "version": "1.5.4",
            "managed": {
                rel: {"sha": row["sha"], "mode": row["mode"]}
                for rel, row in payload.items()
            },
            "old": old,
            "mutable": cfg,
            "providerManaged": providers_managed,
            "providerSha": payload[PROVIDERS]["sha"] if providers_managed else None,
            "previousVersion": prior.get("version"),
        }
        for rel, info in old.items():
            if not info["exists"]:
                continue
            dest = pending / "old" / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(app / rel, dest)
            guard(filehash(dest) == info["sha"], "OLD_CODE_COPY_SHA_DRIFT:" + rel)
            dest.chmod(0o600)
        atomic_bytes(pending / "manifest.json", (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(), 0o600)
        fsync_dir(pending)
        print("PASS_USER_UPDATE_SINGLE_PENDING_SLOT_STAGED")
    except BaseException:
        # A partially-created backup is never overwritten or removed automatically.
        # It remains for manual diagnosis if staging itself fails.
        raise


def load_pending():
    app, state, pending = context()
    manifest_file = pending / "manifest.json"
    guard(pending.is_dir() and not pending.is_symlink() and manifest_file.is_file() and
          not manifest_file.is_symlink(), "PENDING_TRANSACTION_NOT_VALID")
    guard(pending.stat().st_uid == os.getuid(), "PENDING_TRANSACTION_NOT_OWNED")
    data = json.loads(manifest_file.read_text(encoding="utf8"))
    guard(data.get("schema") == 1 and data.get("version") == "1.5.4", "PENDING_TRANSACTION_VERSION_WRONG")
    allowed = {METADATA, *(rel for _, rel, _ in FILES), PROVIDERS}
    guard(set(data["old"]) == set(data["managed"]) | {METADATA} and
          set(data["old"]) <= allowed, "PENDING_FILESET_FOREIGN")
    guard(set(data.get("mutable", {})) == set(MUTABLE), "PENDING_CONFIG_SET_WRONG")
    return app, pending, data


def verify_saved_backups(pending, data):
    expected = {"manifest.json"}
    old_root = pending / "old"
    for rel, info in data["old"].items():
        p = old_root / rel
        if info["exists"]:
            expected.add("old/" + rel)
            guard(p.is_file() and not p.is_symlink() and filehash(p) == info["sha"], "OLD_BACKUP_CHANGED:" + rel)
        else:
            guard(not p.exists() and not p.is_symlink(), "FOREIGN_OLD_BACKUP_PRESENT:" + rel)
    for p in pending.rglob("*"):
        guard(not p.is_symlink() and p.stat().st_uid == os.getuid(), "PENDING_SYMLINK_OR_OTHER_OWNER")
        if p.is_file():
            guard(p.relative_to(pending).as_posix() in expected, "PENDING_FOREIGN_EXTRA_FILE")
        else:
            guard(p.is_dir(), "PENDING_FOREIGN_NODE")


def verify_mutable(app, data):
    for rel, h in data["mutable"].items():
        p = app / rel
        guard(regular_or_missing(p), "MUTABLE_FILE_CHANGED_TYPE:" + rel)
        now = filehash(p) if p.exists() else None
        guard(now == h, "MUTABLE_USER_DATA_CHANGED_CONCURRENTLY:" + rel)


def apply(src: pathlib.Path):
    app, pending, data = load_pending()
    verify_saved_backups(pending, data)
    verify_mutable(app, data)
    source = source_files(src)
    for rel, row in data["managed"].items():
        guard(row["sha"] == source[rel]["sha"], "SOURCE_CHANGED_AFTER_STAGING:" + rel)
    # Validate EVERY destination and source byte BEFORE the first replacement:
    # one late foreign edit must not leave an earlier code file half-upgraded.
    planned = []
    for rel, row in data["managed"].items():
        dest = app / rel
        guard(regular_or_missing(dest) and not dest.parent.is_symlink(),
              "APP_MANAGED_DEST_UNSAFE:" + rel)
        old = data["old"][rel]
        previous = filehash(dest) if dest.exists() else None
        guard(previous in (old["sha"], row["sha"]),
              "FOREIGN_CONCURRENT_CODE_MUTATION:" + rel)
        payload = source[rel]["path"].read_bytes()
        guard(hashlib.sha256(payload).hexdigest() == row["sha"],
              "SOURCE_CHANGED_DURING_APPLY:" + rel)
        planned.append((rel, dest, payload, row["mode"], row["sha"]))
    for rel, dest, payload, mode, expected in planned:
        atomic_bytes(dest, payload, mode)
        guard(filehash(dest) == expected, "APPLY_CODE_POST_SHA_FAILED:" + rel)
    print("PASS_INPLACE_MANAGED_CODE_APPLIED_NO_USER_DATA_MUTATION")


def check_metadata(app, data):
    path = app / METADATA
    guard(path.is_file() and not path.is_symlink(), "INSTALLED_METADATA_MISSING")
    doc = json.loads(path.read_text(encoding="utf8"))
    guard(doc.get("version") == "1.5.4" and doc.get("schema") == 2, "INSTALLED_VERSION_METADATA_NOT_VALID")
    guard(doc.get("managedProviderSha256") == data["providerSha"], "PROVIDER_MANAGED_OWNERSHIP_METADATA_CHANGED")
    expected = {rel: row["sha"] for rel, row in data["managed"].items()
                if rel != PROVIDERS}
    guard(doc.get("managedCodeSha256") == expected,
          "INSTALLED_MANAGED_CODE_METADATA_HASHES_CHANGED")
    guard(isinstance(doc.get("managedLaunchersSha256"), dict),
          "INSTALLED_LAUNCHER_OWNERSHIP_METADATA_MISSING")


def clear_pending(pending, data):
    verify_saved_backups(pending, data)
    # Remove only the helper-created transaction directory with exact known
    # manifest/backups. No user configuration or arbitrary directory is touched.
    shutil.rmtree(pending)
    fsync_dir(pending.parent)


def commit():
    app, pending, data = load_pending()
    verify_saved_backups(pending, data)
    verify_mutable(app, data)
    for rel, row in data["managed"].items():
        p = app / rel
        guard(p.is_file() and not p.is_symlink() and filehash(p) == row["sha"], "INSTALLED_CODE_SHA_WRONG:" + rel)
    check_metadata(app, data)
    clear_pending(pending, data)
    print("PASS_SINGLE_INSTALL_UPDATE_COMMITTED_SETTINGS_PRESERVED_NO_BACKUP_COPIES")


def rollback():
    app, pending, data = load_pending()
    verify_saved_backups(pending, data)
    verify_mutable(app, data)  # Never revert managed code if user data drifted.
    # Refuse touching a destination overwritten by another actor.
    for rel, info in data["old"].items():
        dest = app / rel
        guard(regular_or_missing(dest), "FOREIGN_CODE_TYPE_ON_ROLLBACK:" + rel)
        observed = filehash(dest) if dest.exists() else None
        new_sha = data["managed"][rel]["sha"] if rel in data["managed"] else None
        if rel == METADATA and observed not in (info["sha"], None):
            try:
                doc = json.loads(dest.read_text(encoding="utf8"))
                guard(doc.get("schema") == 2 and doc.get("version") == "1.5.4",
                      "FOREIGN_INSTALL_METADATA_PRESERVED")
            except (UnicodeError, ValueError) as ex:
                raise RuntimeError("UNKNOWN_INSTALL_METADATA_ON_ROLLBACK") from ex
        elif rel != METADATA:
            guard(observed in (info["sha"], new_sha, None), "FOREIGN_CODE_MUTATION_PRESERVED:" + rel)
    for rel, info in reversed(list(data["old"].items())):
        dest = app / rel
        if info["exists"]:
            atomic_bytes(dest, (pending / "old" / rel).read_bytes(), info["mode"])
            guard(filehash(dest) == info["sha"], "ROLLBACK_OLD_CODE_SHA_FAILED:" + rel)
        elif dest.exists():
            dest.unlink()
    verify_mutable(app, data)
    clear_pending(pending, data)
    print("PASS_CODE_ROLLBACK_USER_DATA_UNTOUCHED")



def recover_metadata_stage(expected_sha256: str):
    """Operator-attested cleanup of exactly one interrupted INSTALL.json stage.

    This NEVER commits, installs, rewrites old metadata, deletes user settings
    or auto-resumes a transaction. A foreign/partial/unproven stage stays put.
    Caller must inspect the SHA separately, authorize its exact digest, then
    explicitly run --rollback or review the transaction before further update.
    """
    guard(isinstance(expected_sha256, str) and len(expected_sha256) == 64 and
          all(c in "0123456789abcdefABCDEF" for c in expected_sha256),
          "REQUIRE_EXACT_STAGED_SHA256")
    app, pending, data = load_pending()
    verify_saved_backups(pending, data)
    verify_mutable(app, data)
    # The package code must have been completely applied; otherwise neither
    # rollback nor metadata-stage deletion can be certified safe.
    for rel, info in data["managed"].items():
        dest = app / rel
        guard(dest.is_file() and not dest.is_symlink() and
              not dest.parent.is_symlink() and
              dest.stat().st_uid == os.getuid() and
              filehash(dest) == info["sha"],
              "MANAGED_CODE_NOT_VERIFIED_FOR_STAGE_RECOVERY:" + rel)
    metadata = app / METADATA
    before = data["old"][METADATA]
    guard(regular_or_missing(metadata) and not metadata.parent.is_symlink(),
          "RECOVERY_METADATA_PATH_UNSAFE")
    guard(metadata.exists() == before["exists"],
          "RECOVERY_METADATA_EXISTENCE_CHANGED")
    if before["exists"]:
        guard(metadata.stat().st_uid == os.getuid() and
              filehash(metadata) == before["sha"],
              "RECOVERY_METADATA_PRESTATE_CHANGED")
    tmp = metadata.with_name("." + metadata.name + ".dim-update-stage")
    guard(not tmp.is_symlink() and tmp.exists(),
          "RECOVERY_STAGED_FILE_NOT_REGULAR")
    # No open of a symlink/device/fifo; ensure private and single-link inode.
    first = tmp.lstat()
    guard(stat.S_ISREG(first.st_mode) and first.st_uid == os.getuid() and
          first.st_nlink == 1 and stat.S_IMODE(first.st_mode) == 0o600 and
          0 < first.st_size <= 65536,
          "RECOVERY_STAGE_OWNER_MODE_TYPE_SIZE_INVALID")
    fd = os.open(tmp, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)
        guard((opened.st_dev, opened.st_ino) == (first.st_dev, first.st_ino) and
              stat.S_ISREG(opened.st_mode),
              "RECOVERY_STAGE_INODE_CHANGED")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(65537)
        guard(len(raw) == first.st_size and len(raw) <= 65536,
              "RECOVERY_STAGE_READ_SIZE_CHANGED")
    finally:
        if fd >= 0:
            os.close(fd)
    observed = hashlib.sha256(raw).hexdigest()
    guard(observed == expected_sha256.lower(),
          "RECOVERY_STAGE_SHA256_MISMATCH")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as ex:
        raise RuntimeError("RECOVERY_STAGE_METADATA_NOT_JSON") from ex
    guard(isinstance(doc, dict), "RECOVERY_STAGE_NOT_OBJECT")
    expected_keys = {
        "schema", "product", "version", "platform", "installedUtc",
        "networkMutationOnInstall", "normalRunRequiresAdmin",
        "systemBackend", "protectedBackendVersion",
        "protectedBackendByteCompatible", "onlineUpdate",
        "managedProviderSha256", "preservedCustomProviderData",
        "managedCodeSha256", "managedLaunchersSha256", "updateMode",
    }
    guard(set(doc) == expected_keys and
          doc["schema"] == 2 and doc["product"] == "Direct Internet Method" and
          doc["version"] == "1.5.4" and doc["platform"] == "linux-x86_64" and
          doc["networkMutationOnInstall"] is False and
          doc["normalRunRequiresAdmin"] is False and
          doc["systemBackend"] == "/usr/lib/directinternetmethod" and
          doc["protectedBackendVersion"] in ("1.5.1", "1.5.2", "1.5.3", "1.5.4") and
          doc["protectedBackendByteCompatible"] is True and
          doc["onlineUpdate"] == "GitHub latest release + SHA256SUMS verification" and
          doc["updateMode"] == "IN_PLACE_SINGLE_INSTALL_DATA_PRESERVED",
          "RECOVERY_METADATA_PRODUCTION_IDENTITY_MISMATCH")
    guard(doc["managedProviderSha256"] == data["providerSha"] and
          doc["preservedCustomProviderData"] is (not data["providerManaged"]) and
          doc["managedCodeSha256"] ==
          {k: v["sha"] for k, v in data["managed"].items() if k != PROVIDERS},
          "RECOVERY_STAGE_NOT_TIED_TO_PENDING_MANIFEST")
    stamp = doc["installedUtc"]
    guard(isinstance(stamp, str) and len(stamp) == 20 and
          stamp[4:5] == "-" and stamp[7:8] == "-" and
          stamp[10:11] == "T" and stamp[13:14] == ":" and
          stamp[16:17] == ":" and stamp.endswith("Z"),
          "RECOVERY_STAGE_TIMESTAMP_INVALID")
    launchers = doc["managedLaunchersSha256"]
    known_launchers = {
        ".local/bin/direct-internet-method",
        ".local/bin/direct-internet-method-uninstall",
        ".local/share/applications/io.github.god13emad.DirectInternetMethod.desktop",
        ".local/share/icons/hicolor/scalable/apps/direct-internet-method.svg",
    }
    guard(isinstance(launchers, dict) and set(launchers) <= known_launchers,
          "RECOVERY_STAGE_FOREIGN_LAUNCHER_OWNERSHIP")
    for rel, known_sha in launchers.items():
        owned = pathlib.Path.home() / rel
        guard(isinstance(known_sha, str) and len(known_sha) == 64 and
              owned.is_file() and not owned.is_symlink() and
              owned.stat().st_uid == os.getuid() and
              filehash(owned) == known_sha,
              "RECOVERY_STAGE_LAUNCHER_SHA_CHANGED:" + rel)
    final = tmp.lstat()
    guard((first.st_dev, first.st_ino, first.st_size, first.st_mtime_ns) ==
          (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) and
          not tmp.is_symlink() and filehash(tmp) == observed and
          (not before["exists"] or filehash(metadata) == before["sha"]),
          "RECOVERY_STAGE_CHANGED_DURING_ATTESTATION")
    tmp.unlink()  # ONE exact own-file removal; NEVER rm -rf / wildcard.
    fsync_dir(app)
    print("PASS_EXACT_OWNED_STALE_METADATA_STAGE_CLEARED_PENDING_ROLLBACK_REQUIRED")



def status():
    app, pending, data = load_pending()
    verify_saved_backups(pending, data)
    print(json.dumps({"version": data["version"], "providerManaged": data["providerManaged"],
                      "managedProviderSha256": data["providerSha"],
                      "pending": True, "userFilesPreserved": True}))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=pathlib.Path)
    opts = p.add_mutually_exclusive_group(required=True)
    opts.add_argument("--stage", action="store_true")
    opts.add_argument("--apply", action="store_true")
    opts.add_argument("--commit", action="store_true")
    opts.add_argument("--rollback", action="store_true")
    opts.add_argument("--status", action="store_true")
    opts.add_argument("--recover-metadata-stage", action="store_true")
    p.add_argument("--expected-stage-sha256")
    a = p.parse_args()
    if a.stage or a.apply:
        guard(a.source is not None, "REQUIRE_PACKAGE_SOURCE")
    if a.stage:
        stage(a.source)
    elif a.apply:
        apply(a.source)
    elif a.commit:
        commit()
    elif a.rollback:
        rollback()
    elif a.recover_metadata_stage:
        recover_metadata_stage(a.expected_stage_sha256)
    else:
        status()


if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        print("DIM_USER_TRANSACTION_FAIL_CLOSED:" + str(ex), file=sys.stderr)
        sys.exit(84)
