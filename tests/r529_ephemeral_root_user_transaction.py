#!/usr/bin/env python3
"""R529: native Root + unprivileged User transaction across one disposable VM.

Not a physical network/GUI acceptance. Use exact v1.5.4 published ZIP user and
protected Root code, exact 1.5.6 candidate ZIP, unmodified RootTransaction("/")
and real subprocess-driven user transaction / inline INSTALL.json production
fragment. Both transactions must rollback byte-for-byte. NO live network or
systemd, No Tailscale changes, no installation onto a user's physical computer.
All operations are refused outside a clean GitHub-hosted Ubuntu VM.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import zipfile

BASE = Path(__file__).resolve().parents[1]
R528 = BASE / "tests/r528_ephemeral_native_root_cli_contract.py"
R526 = BASE / "tests/r526_installer_metadata_contract.py"
USER_TX_REL = "app/user_update_transaction.py"
HOME_REL = ".local/share/DirectInternetMethod"
USER_MUTABLE = (
    "settings.json", "strategy.txt", "scope.txt", "custom-hosts.txt",
    "adult-enabled.txt", "adult-hosts.txt", "adult-hosts.meta.json",
    "encrypted-dns-optin.txt", "selective-dns-optin.txt",
)
USER_MAP = (
    ("app/direct_internet_method.py", "direct_internet_method.py", 0o755),
    ("app/router_gateway.py", "router_gateway.py", 0o755),
    ("app/router_gateway_core.py", "router_gateway_core.py", 0o644),
    ("app/direct-internet-method.svg", "direct-internet-method.svg", 0o644),
    ("uninstall.sh", "uninstall.sh", 0o755),
    ("app/user_uninstall_preserve.py", "user_uninstall_preserve.py", 0o755),
    ("app/user_update_transaction.py", "user_update_transaction.py", 0o755),
)

def require(ok, code):
    if not ok:
        raise RuntimeError("R529_FAIL_CLOSED_" + code)

def digest(b):
    return hashlib.sha256(b).hexdigest()

def hash_file(p: Path):
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()

def module(path: Path, label: str):
    spec = importlib.util.spec_from_file_location(label, path)
    require(spec is not None and spec.loader is not None, "IMPORT_" + label)
    instance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(instance)
    return instance

def ownership(path: Path, user, mode: int):
    os.chown(path, user.pw_uid, user.pw_gid)
    os.chmod(path, mode)
    require(path.stat().st_uid == user.pw_uid, "USER_FILE_OWNER")
    require(stat.S_IMODE(path.stat().st_mode) == mode, "USER_FILE_MODE")

def write_owned(path: Path, body: bytes, user, mode: int = 0o600):
    require(not path.exists() and not path.is_symlink(), "UNKNOWN_USER_TARGET_" + path.name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    ownership(path, user, mode)

def require_clean_home(user):
    home = Path(user.pw_dir)
    require(home == Path("/home/runner") and home.is_dir(), "RUNNER_HOME")
    for rel in (HOME_REL, ".local/state/DirectInternetMethod/update-pending",
                ".local/state/DirectInternetMethod"):
        p = home / rel
        require(not p.exists() and not p.is_symlink(),
                "USER_PREEXISTING_STATE_" + p.name)
    require(not (home / ".local/bin/direct-internet-method").exists(), "USER_LAUNCHER_PREEXISTS")

def prepare_user_from_official(stable: Path, user):
    home = Path(user.pw_dir)
    app = home / HOME_REL
    need_dirs = [
        home / ".local", home / ".local/share", app,
        app / "router_gateway",
    ]
    for d in need_dirs:
        if not d.exists():
            d.mkdir(mode=0o700)
            ownership(d, user, 0o700)
        require(d.is_dir() and not d.is_symlink(), "FOREIGN_DIR_" + d.name)
        require(d.stat().st_uid == user.pw_uid or d == home,
                "UNKNOWN_PARENT_OWNER_" + d.name)
    original = {}
    with zipfile.ZipFile(stable) as z:
        pkg = "DirectInternetMethod_1.5.4_Linux_x86_64/"
        for rel, installed, mode in USER_MAP:
            raw = z.read(pkg + rel)
            dest = app / installed
            write_owned(dest, raw, user, mode)
            original[str(dest)] = digest(raw)
        vendor_provider = z.read(pkg + "app/router_gateway/providers.json")
        custom = b'{"r529CustomProvider": true, "owner": "do-not-replace"}\n'
        require(digest(custom) != digest(vendor_provider), "PROVIDER_IS_NOT_CUSTOM")
        provider_path = app / "router_gateway/providers.json"
        write_owned(provider_path, custom, user)
        for name in USER_MUTABLE:
            value = {
                "settings.json": b'{"r529PrivateSettings":true}\n',
                "strategy.txt": b"balanced\n",
                "scope.txt": b"targeted\n",
                "custom-hosts.txt": b"r529-private.example\n",
                "adult-enabled.txt": b"0\n",
                "adult-hosts.txt": b"r529-custom-adult-list\n",
                "adult-hosts.meta.json": b'{"source":"private"}\n',
                "encrypted-dns-optin.txt": b"0\n",
                "selective-dns-optin.txt": b"0\n",
            }[name]
            write_owned(app / name, value, user)
        record = {
            "schema": 2, "product": "Direct Internet Method",
            "version": "1.5.4", "platform": "linux-x86_64",
            "protectedBackendVersion": "1.5.2",
            "managedProviderSha256": digest(vendor_provider),
            "managedCodeSha256": {
                installed: original[str(app / installed)]
                for _, installed, _ in USER_MAP
            },
            "managedLaunchersSha256": {},
            "networkMutationOnInstall": False,
        }
        meta = app / "INSTALL.json"
        old = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode()
        write_owned(meta, old, user)
        original[str(meta)] = digest(old)
    user_data = {
        str(p): hash_file(p)
        for p in [provider_path, *(app / n for n in USER_MUTABLE)]
    }
    return app, original, user_data

def make_source_runner_owned(src: Path, user):
    # The exact R528 archive extraction is from the verified SHA-pinned ZIP,
    # into a disposable path; avoid broad filesystem mutations.
    cur = src
    while cur.name != "DIM_R528_CANDIDATE":
        require(cur.parent != cur, "SOURCE_PATH_ESCAPES_TEMP")
        cur = cur.parent
    for item in sorted([cur, *cur.rglob("*")], key=lambda p: len(p.parts)):
        require(not item.is_symlink(), "SOURCE_EXTRACT_SYMLINK")
        os.chown(item, user.pw_uid, user.pw_gid)
    require(src.stat().st_uid == user.pw_uid, "PINNED_SOURCE_USER_OWNERSHIP")
    require(cur.stat().st_uid == user.pw_uid, "SOURCE_ROOT_USER_OWNERSHIP")

def as_runner(user, program: Path, *args, stdin=None, ok=True):
    require(program.is_file() and not program.is_symlink(), "UNSAFE_PROGRAM")
    cmd = [
        "/usr/sbin/runuser", "-u", user.pw_name, "--",
        "/usr/bin/env", "HOME=" + user.pw_dir,
        "PYTHONDONTWRITEBYTECODE=1", "/usr/bin/python3", "-B", str(program),
        *map(str,args)
    ]
    completed = subprocess.run(
        cmd, input=stdin, text=True,
        capture_output=True, timeout=30, check=False,
    )
    if ok:
        require(completed.returncode == 0,
                "USER_COMMAND_FAILURE_" + completed.stderr[-500:].replace(" ", "_"))
    else:
        require(completed.returncode != 0 and
                ("FAIL_CLOSED" in completed.stderr or "Traceback" in completed.stderr),
                "USER_NEGATIVE_GUARD_NOT_ENFORCED")
    return completed

def as_runner_inline(user, code: str, target: Path, helper: Path):
    cmd = [
        "/usr/sbin/runuser", "-u", user.pw_name, "--",
        "/usr/bin/env", "HOME=" + user.pw_dir,
        "PYTHONDONTWRITEBYTECODE=1", "/usr/bin/python3", "-B", "-",
        str(target), str(helper)
    ]
    result = subprocess.run(cmd, input=code + "\n", text=True,
                            capture_output=True, timeout=30)
    require(result.returncode == 0, "INLINE_METADATA_FAIL_" + result.stderr[-420:].replace(" ", "_"))

def unchanged_records(files):
    for name, expected in files.items():
        p=Path(name)
        require(p.is_file() and hash_file(p)==expected, "USER_ORIGINAL_CHANGED_"+p.name)

def execute():
    # R528's hard guard proves this is a fresh hosted GitHub VM, not a user
    # machine. Production root and HOME must be absent before any writes.
    old, candidate, temp, user = module(R528, "r529_r528_guard").prerequisites()
    r528 = module(R528, "r529_r528_helpers")
    r526 = module(R526, "r529_r526_metadata")
    require_clean_home(user)
    require(Path("/usr/sbin/runuser").is_file(), "RUNUSER_UNAVAILABLE")
    before_network={
        p:hash_file(Path(p)) for p in ("/etc/resolv.conf", "/etc/hosts")
    }
    before_network_link=os.readlink("/etc/resolv.conf") if Path("/etc/resolv.conf").is_symlink() else None
    rootmod = r528.module()
    extracted = r528.stage_exact_candidate(candidate, temp)
    make_source_runner_owned(extracted, user)
    # Byte-pinned user baseline from public v1.5.4 release, not fabricated
    # executable code or old code hashes. User's private settings are seeded
    # and checked independently from executable bytes.
    app, old_user, private = prepare_user_from_official(old, user)
    root_before = r528.seed_real_protected_root(old, user, rootmod)
    tx_script = extracted / USER_TX_REL
    pending = Path(user.pw_dir) / ".local/state/DirectInternetMethod/update-pending"
    root_tx = rootmod.RootTransaction()
    require(root_tx.native and root_tx.root == Path("/"),
            "ROOT_TRANSACTION_IS_NOT_REAL_ABSOLUTE")
    require(root_tx.status()["status"]=="NO_PENDING_UPGRADE", "ROOT_PRESTATE")
    require(not pending.exists(), "USER_PRESTATE_PENDING")
    # User-first staged transaction before any protected root mutation.
    as_runner(user, tx_script, "--stage", "--source", extracted)
    require((pending / "manifest.json").is_file(), "USER_PENDING_STAGE")
    manifest=json.loads((pending / "manifest.json").read_text())
    require(manifest["version"]=="1.5.6" and
            manifest["providerManaged"] is False and
            manifest["providerSha"] is None,
            "CUSTOM_USER_PROVIDER_OWNERSHIP")
    unchanged_records(old_user)
    unchanged_records(private)
    # Protected absolute-root stage/apply with actual root-owned files.
    require(root_tx.stage(extracted)["status"]=="STAGED", "ROOT_STAGE")
    require(root_tx.apply()["status"]=="APPLIED", "ROOT_APPLY")
    require(json.loads(Path("/var/lib/directinternetmethod/install.json").read_text())["version"]=="1.5.6", "ROOT_NEW_METADATA")
    # Real unprivileged User transaction CLI replaces managed code only.
    as_runner(user, tx_script, "--apply", "--source", extracted)
    for rel,row in manifest["managed"].items():
        p=app / rel
        require(p.is_file() and hash_file(p)==row["sha"], "USER_MANAGED_APPLY_"+rel)
    unchanged_records(private)
    # This must NOT be mistaken for completion: metadata not yet activated.
    rejected = as_runner(user, tx_script, "--commit", ok=False)
    require("INSTALLED_VERSION_METADATA_NOT_VALID" in rejected.stderr, "METADATA_COMMIT_GUARD_FAILED")
    require((pending/"manifest.json").is_file(), "PREMATURE_PENDING_REMOVAL")
    unchanged_records(private)
    # Only now run EXACT, unmodified install.sh Python fragment, on real
    # unprivileged user identity against real upgraded root metadata.
    installer=extracted/"install.sh"
    require(installer.is_file() and not installer.is_symlink(), "INSTALLER_INVALID")
    source=installer.read_text(encoding="utf8")
    marker=r526.BEGIN
    end=r526.END
    require(source.count(marker)==1, "INSTALL_METADATA_ENTRY_ANCHOR")
    tail=source.split(marker,1)[1]
    require(tail.count(end)==1, "INSTALL_METADATA_TERMINATOR")
    inline=tail.split(end,1)[0]
    require(len(inline.splitlines())==64 and
            'transaction_helper.atomic_bytes(' in inline and
            'assert protected.get("version") == "1.5.6"' in inline,
            "INSTALLER_METADATA_PROVENANCE_CHANGED")
    as_runner_inline(user,inline,app/"INSTALL.json",tx_script)
    record=json.loads((app/"INSTALL.json").read_text())
    require(record["version"]=="1.5.6" and
            record["protectedBackendVersion"]=="1.5.6",
            "TWO_SIDED_VERSION_METADATA")
    require(record["managedProviderSha256"] is None and
            record["preservedCustomProviderData"] is True and
            record["updateMode"]=="IN_PLACE_SINGLE_INSTALL_DATA_PRESERVED",
            "CUSTOM_PROVIDER_OR_UPDATER_METADATA")
    require(stat.S_IMODE((app/"INSTALL.json").stat().st_mode)==0o600,
            "USER_METADATA_ATOMIC_MODE")
    as_runner(user, tx_script, "--status")
    unchanged_records(private)
    # No release acceptance is claimed; deliberately roll back BOTH sides.
    # User rollback runs first and is verified before protected root rollback.
    as_runner(user, tx_script, "--rollback")
    require(not pending.exists(),"USER_PENDING_LEFT_AFTER_ROLLBACK")
    unchanged_records(old_user)
    unchanged_records(private)
    require(root_tx.rollback()["status"]=="ROLLED_BACK", "ROOT_ROLLBACK")
    for name,expected in root_before.items():
        require(hash_file(Path(name))==expected, "PROTECTED_ROOT_BASELINE_DRIFT_"+Path(name).name)
    for _,_,dest,old_hash,_,_ in rootmod.FILES:
        if old_hash is None:
            require(not (Path("/")/dest).exists(),"NEW_PROTECTED_FILE_LEFT")
    for name,expected in before_network.items():
        require(hash_file(Path(name))==expected, "NETWORK_MUTATED_"+name)
    require((os.readlink("/etc/resolv.conf") if Path("/etc/resolv.conf").is_symlink() else None)==before_network_link,
            "RESOLV_CONF_SYMLINK_MUTATED")
    require(json.loads(Path("/var/lib/directinternetmethod/install.json").read_text())["version"]=="1.5.2", "ROOT_FINAL_OLD_VERSION")
    require(json.loads((app/"INSTALL.json").read_text())["version"]=="1.5.4", "USER_FINAL_OLD_VERSION")
    require(json.loads((BASE/"RELEASE.json").read_text())["version"]=="1.5.4", "PUBLIC_TAG_AUTHORITY")
    print(json.dumps({
      "revision":"R529", "status":"PASS_HOSTED_ROOT_USER_ACTUAL_TRANSACTION",
      "productionMachineTouched":False,"hostedRunner":True,
      "publicStable":"v1.5.4","candidate":"1.5.6",
      "userTransaction":"STAGE_APPLY_INLINE_ATOMIC_METADATA_ROLLBACK",
      "protectedRoot":"ABSOLUTE_ROOT_STAGE_APPLY_ROLLBACK",
      "preVersions":"user1.5.4/root1.5.2",
      "appliedVersion":"both1.5.6",
      "postRollbackVersions":"user1.5.4/root1.5.2",
      "oldUserCodeFilesVerified":len(old_user),
      "protectedRootFilesVerified":len(root_before),
      "mutablePrivateHashesVerified":len(private),
      "userCustomProviderPreserved":True,
      "userCommitBeforeMetadataRejected":True,
      "userPendingSlotCleaned":True,
      "protectedRootSlotRetainedForAudit":root_tx.pending.exists(),
      "networkResolverFilesUnchanged":True,
      "realPhysicalISPEncryptedDNS_GUI_Tailscale":"UNTESTED",
    },sort_keys=True))
    return 0

if __name__=="__main__":
    try:sys.exit(execute())
    except Exception as exc:
        print(json.dumps({"revision":"R529","status":"FAIL_CLOSED",
                          "reason":str(exc)[:700]},sort_keys=True),file=sys.stderr)
        sys.exit(85)
