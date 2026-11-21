"""Platform-independent, one-active-slot installer transaction kernel.

No network, shell, service-manager, UAC, polkit, or executable code is invoked.
A platform adapter must first quiesce the product and verify service health
before committing. `root/current` is the only active code directory; user data
lives outside it (`root/data` or a platform-owned location), never in a slot.

Package layout: manifest.json (pinned SHA-256) + payload/<listed files>.
Pending transactions are durable, bounded, recoverable by explicit rollback;
unowned files, symlinks, foreign state, duplicate names and downgrades fail closed.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
from typing import Callable, Iterator

PRODUCT = "Direct Internet Method"
PLATFORMS = {"windows-x86_64", "linux-x86_64"}
SHA_RE = re.compile(r"[a-fA-F0-9]{64}\Z")
VER_RE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
MAX_FILES = 5000
MAX_FILE_BYTES = 1 << 30
MAX_MANIFEST_BYTES = 1 << 21
WIN_DEVICES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


class EngineError(RuntimeError):
    """An explicit fail-closed precondition or postcondition failure."""


def require(ok: bool, why: str) -> None:
    if not ok:
        raise EngineError(why)


def hash_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def hash_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def version(v: str) -> tuple[int, int, int]:
    require(isinstance(v, str) and VER_RE.fullmatch(v) is not None, "INVALID_VERSION")
    return tuple(map(int, v.split(".")))


def relpath(value: str) -> tuple[str, ...]:
    require(isinstance(value, str) and 0 < len(value) <= 320, "INVALID_MEMBER_NAME")
    require("\\" not in value and ":" not in value and "\x00" not in value, "MEMBER_INVALID_CHAR")
    parts = value.split("/")
    require(all(part not in ("", ".", "..") and not part.endswith((".", " "))
                for part in parts), "MEMBER_UNSAFE_COMPONENT")
    require(not PurePosixPath(value).is_absolute(), "MEMBER_ABSOLUTE")
    # Stable namespace across Windows/Linux: case-fold collisions are rejected.
    # Dot-prefixed package files (e.g. PowerShell .signature.p7s) are valid.
    # Reject the engine control namespace and Git metadata at *any* depth;
    # dot and dot-dot, trailing dots/spaces and alternate streams are already
    # excluded above for Windows/Unix equivalence.
    require(all(re.fullmatch(r"[a-zA-Z0-9_.-]+", part) and
                part.casefold() not in {".dim-engine", ".git"} and
                part.split(".", 1)[0].upper() not in WIN_DEVICES for part in parts),
            "WINDOWS_PORTABLE_NAME_REQUIRED")
    require(parts[0].lower() not in {"data", "state", "current", ".dim-engine"}, "RESERVED_MEMBER")
    return tuple(parts)


def no_links(p: Path, *, until: Path | None = None) -> None:
    """Check existing components without dereferencing a symlink/reparse node."""
    p = p.absolute()
    if until is not None:
        require(p == until or until in p.parents, "PATH_ESCAPES_TRUST_ROOT")
    chain = list(reversed((p, *p.parents)))
    for node in chain:
        if node.exists() or node.is_symlink():
            mode = node.lstat().st_mode
            require(not stat.S_ISLNK(mode), "LINK_PATH_REFUSED:" + str(node))
            if os.name == "nt":
                require(not bool(node.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT),
                        "REPARSE_PATH_REFUSED:" + str(node))


def regular(p: Path) -> bool:
    no_links(p)
    if not p.exists():
        return False
    return stat.S_ISREG(p.lstat().st_mode)


def durable_dir(p: Path) -> None:
    if os.name != "posix":
        return  # Windows directory fsync is not supported: power-loss scope differs.
    fd = os.open(p, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path: Path, obj: dict) -> None:
    no_links(path)
    require(path.parent.is_dir(), "METADATA_PARENT_MISSING")
    temp = path.with_name(path.name + ".writing")
    require(not temp.exists() and not temp.is_symlink(), "STALE_METADATA_TEMP")
    raw = (json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        durable_dir(path.parent)
    except BaseException:
        if temp.exists() and not temp.is_symlink():
            temp.unlink()
        raise


def load_json(path: Path) -> dict:
    require(regular(path) and path.stat().st_size <= MAX_MANIFEST_BYTES, "METADATA_UNREADABLE_OR_LINK")
    # Reject duplicate keys (including duplicated attack-controlled security fields).
    def unique(rows: list) -> dict:
        out: dict = {}
        for key, val in rows:
            require(key not in out, "DUPLICATE_JSON_KEY:" + key)
            out[key] = val
        return out
    try:
        obj = json.loads(path.read_text("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError, OSError) as exc:
        raise EngineError("MALFORMED_JSON") from exc
    require(isinstance(obj, dict), "JSON_NOT_OBJECT")
    return obj


def manifest_schema(doc: dict, *, platform: str | None = None) -> dict:
    require(set(doc) == {"schema", "product", "version", "platform", "files"}, "MANIFEST_KEYS")
    require(type(doc["schema"]) is int and doc["schema"] == 1 and doc["product"] == PRODUCT,
            "MANIFEST_IDENTITY")
    version(doc["version"])
    require(doc["platform"] in PLATFORMS and
            (platform is None or doc["platform"] == platform), "PLATFORM_MISMATCH")
    files = doc["files"]
    require(isinstance(files, list) and 1 <= len(files) <= MAX_FILES, "MANIFEST_FILES_COUNT")
    paths = set()
    for item in files:
        require(type(item) is dict and set(item) == {"path", "sha256", "bytes", "mode"},
                "MANIFEST_FILE_KEYS")
        parts = relpath(item["path"])
        key = "/".join(parts).casefold()
        require(key not in paths, "DUPLICATE_OR_CASEFOLD_PATH")
        paths.add(key)
        require(type(item["bytes"]) is int and 0 <= item["bytes"] <= MAX_FILE_BYTES,
                "INVALID_FILE_LENGTH")
        require(type(item["sha256"]) is str and SHA_RE.fullmatch(item["sha256"]) is not None,
                "INVALID_FILE_DIGEST")
        require(type(item["mode"]) is int and item["mode"] in (0o644, 0o755),
                "INVALID_FILE_MODE")
    return doc


def read_package(bundle: Path, pin: str, platform: str) -> dict:
    require(type(pin) is str and SHA_RE.fullmatch(pin) is not None, "OUT_OF_BAND_SHA_REQUIRED")
    no_links(bundle)
    require(bundle.is_dir(), "BUNDLE_NOT_DIRECTORY")
    manifest = bundle / "manifest.json"
    require(regular(manifest), "MANIFEST_NOT_REGULAR")
    require(hash_file(manifest).lower() == pin.lower(), "MANIFEST_PIN_MISMATCH")
    doc = manifest_schema(load_json(manifest), platform=platform)
    payload = bundle / "payload"
    require(payload.is_dir() and not payload.is_symlink(), "PAYLOAD_DIRECTORY_INVALID")
    expected = {f["path"] for f in doc["files"]}
    actual = set()
    for base, dirs, files in os.walk(payload, followlinks=False):
        for d in dirs:
            p = Path(base) / d
            no_links(p)
            require(p.is_dir(), "PACKAGE_DIRECTORY_FOREIGN")
        for name in files:
            p = Path(base) / name
            require(regular(p), "PACKAGE_FILE_LINK_OR_FOREIGN")
            actual.add(p.relative_to(payload).as_posix())
    require(actual == expected, "PACKAGE_UNDECLARED_OR_MISSING_MEMBER")
    for f in doc["files"]:
        path = payload.joinpath(*relpath(f["path"]))
        require(path.stat().st_size == f["bytes"] and
                hash_file(path) == f["sha256"].lower(), "PACKAGE_FILE_SHA_MISMATCH")
    return doc


def validate_slot(slot: Path, doc: dict) -> None:
    require(slot.is_dir() and not slot.is_symlink(), "ACTIVE_SLOT_NOT_DIRECTORY")
    expected = {row["path"] for row in doc["files"]}
    seen = set()
    for base, dirs, files in os.walk(slot, followlinks=False):
        for name in dirs:
            p = Path(base) / name
            no_links(p)
            require(p.is_dir(), "SLOT_DIRECTORY_FOREIGN")
        for name in files:
            p = Path(base) / name
            require(regular(p), "SLOT_NONREGULAR_FILE")
            seen.add(p.relative_to(slot).as_posix())
    require(seen == expected, "FOREIGN_OR_MISSING_ACTIVE_FILES")
    for row in doc["files"]:
        p = slot.joinpath(*relpath(row["path"]))
        require(p.stat().st_size == row["bytes"] and hash_file(p) == row["sha256"].lower(),
                "INSTALLED_MANAGED_FILE_CHANGED")


def safe_remove_slot(p: Path, doc: dict) -> None:
    if not p.exists():
        return
    validate_slot(p, doc)
    for f in doc["files"]:
        p.joinpath(*relpath(f["path"])).unlink()
    # Remove ONLY known empty parent directories, deepest-first. If extra
    # content appeared after validation rmdir fails rather than destroying it.
    dirs = set()
    for row in doc["files"]:
        directory = p.joinpath(*relpath(row["path"])).parent
        while directory != p:
            dirs.add(directory)
            directory = directory.parent
    for directory in sorted(dirs, key=lambda x: len(x.parts), reverse=True):
        directory.rmdir()
    p.rmdir()



def validate_accepted_uninstall_residual(slot: Path, doc: dict) -> None:
    """Validate the still-present OWNED subset after durable uninstall acceptance.

    Missing manifest files are allowed *only* after the accepted journal
    transition, because a prior process may have already unlinked them.
    Surviving files must still match their manifest hashes exactly; links,
    foreign files and even foreign empty directories are refused. This is
    not an authorization to delete an untrusted install root.
    """
    no_links(slot)
    if not slot.exists():
        return
    require(slot.is_dir(), "UNINSTALL_RESIDUAL_NOT_DIRECTORY")
    declared_files = {row["path"]: row for row in doc["files"]}
    declared_dirs: set[str] = set()
    for path in declared_files:
        parts = relpath(path)
        for i in range(1, len(parts)):
            declared_dirs.add("/".join(parts[:i]))
    seen: set[str] = set()
    for base, dirs, files in os.walk(slot, followlinks=False):
        for name in dirs:
            path = Path(base) / name
            no_links(path)
            require(path.is_dir() and
                    path.relative_to(slot).as_posix() in declared_dirs,
                    "FOREIGN_UNINSTALL_RESIDUAL_DIRECTORY")
        for name in files:
            path = Path(base) / name
            require(regular(path), "UNINSTALL_RESIDUAL_NONREGULAR")
            relative = path.relative_to(slot).as_posix()
            require(relative in declared_files,
                    "FOREIGN_UNINSTALL_RESIDUAL_FILE")
            row = declared_files[relative]
            require(path.stat().st_size == row["bytes"] and
                    hash_file(path) == row["sha256"].lower(),
                    "UNINSTALL_RESIDUAL_FILE_CHANGED")
            seen.add(relative)


def remove_accepted_uninstall_residual(slot: Path, doc: dict) -> None:
    """Replay-safe cleanup only after an accepted uninstall journal exists."""
    validate_accepted_uninstall_residual(slot, doc)
    if not slot.exists():
        return
    directories: set[Path] = set()
    for row in doc["files"]:
        path = slot.joinpath(*relpath(row["path"]))
        no_links(path)
        if path.exists():
            require(regular(path) and path.stat().st_size == row["bytes"] and
                    hash_file(path) == row["sha256"].lower(),
                    "UNINSTALL_RESIDUAL_CHANGED_BEFORE_DELETE")
            path.unlink()
            durable_dir(path.parent)
        directory = path.parent
        while directory != slot:
            directories.add(directory)
            directory = directory.parent
    for directory in sorted(directories, key=lambda d: len(d.parts), reverse=True):
        no_links(directory)
        # A previously interrupted deletion may already have removed this
        # manifest-owned directory. Never recursively delete a foreign tree.
        if directory.exists():
            directory.rmdir()
            durable_dir(directory.parent)
    slot.rmdir()
    durable_dir(slot.parent)


class Engine:
    def __init__(self, root: Path | str, platform: str):
        require(platform in PLATFORMS, "UNKNOWN_PLATFORM")
        self.root = Path(root).absolute()
        self.platform = platform
        self.current = self.root / "current"
        self.state = self.root / ".dim-engine"
        self.staging = self.state / "stage"
        self.previous = self.state / "previous"
        self.installed = self.state / "installed.json"
        self.pending = self.state / "pending.json"
        self.uninstall_journal = self.state / "uninstall.json"

    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        no_links(self.root)
        require(not self.root.exists() or self.root.is_dir(), "INSTALL_ROOT_FOREIGN")
        self.root.mkdir(parents=True, exist_ok=True)
        no_links(self.state)
        require(not self.state.exists() or self.state.is_dir(), "ENGINE_STATE_FOREIGN")
        self.state.mkdir(mode=0o700, exist_ok=True)
        path = self.state / "engine.lock"
        require(not path.is_symlink() and (not path.exists() or regular(path)), "ENGINE_LOCK_FOREIGN")
        with open(path, "a+b") as f:
            f.seek(0, os.SEEK_END)
            if f.tell() == 0:
                f.write(b"\x00")
                f.flush()
            f.seek(0)
            if os.name == "nt":
                import msvcrt
                try:
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise EngineError("TRANSACTION_LOCKED") from exc
            else:
                import fcntl
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise EngineError("TRANSACTION_LOCKED") from exc
            try:
                yield
            finally:
                f.seek(0)
                if os.name == "nt":
                    msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def _installed(self) -> dict | None:
        if not self.installed.exists():
            require(not self.current.exists(), "UNREGISTERED_CURRENT_SLOT")
            return None
        doc = load_json(self.installed)
        require(set(doc) == {"schema", "manifest", "manifest_sha256"} and doc["schema"] == 1,
                "INSTALLED_STATE_SCHEMA")
        manifest_schema(doc["manifest"], platform=self.platform)
        require(type(doc["manifest_sha256"]) is str and
                SHA_RE.fullmatch(doc["manifest_sha256"]) is not None,
                "INSTALLED_PIN_INVALID")
        return doc

    def _pending(self) -> dict | None:
        if not self.pending.exists():
            return None
        doc = load_json(self.pending)
        require(set(doc) == {"schema", "new", "old"} and doc["schema"] == 1,
                "PENDING_SCHEMA")
        for key, value in (("new", doc["new"]), ("old", doc["old"])):
            if key == "old" and value is None:
                continue
            require(type(value) is dict and set(value) ==
                    {"schema", "manifest", "manifest_sha256"} and
                    type(value["schema"]) is int and value["schema"] == 1 and
                    type(value["manifest_sha256"]) is str and
                    SHA_RE.fullmatch(value["manifest_sha256"]) is not None,
                    "PENDING_" + key.upper() + "_SCHEMA_INVALID")
            manifest_schema(value["manifest"], platform=self.platform)
        return doc

    def verify(self) -> dict:
        with self.locked():
            require(self._pending() is None and self._uninstall() is None,
                    "PENDING_REQUIRES_RECOVERY_OR_COMMIT")
            installed = self._installed()
            require(not self.previous.exists() and not self.staging.exists(),
                    "ORPHANED_TRANSACTION_SLOTS")
            if installed is None:
                return {"status": "EMPTY"}
            validate_slot(self.current, installed["manifest"])
            return {"status": "PASS_INSTALLED", "version": installed["manifest"]["version"],
                    "files": len(installed["manifest"]["files"])}

    def stage(self, bundle: Path | str, pin: str) -> dict:
        with self.locked():
            require(self._pending() is None and self._uninstall() is None and
                    not self.staging.exists() and not self.previous.exists(),
                    "UNRECONCILED_PRIOR_TRANSACTION")
            old = self._installed()
            if old is not None:
                validate_slot(self.current, old["manifest"])
            doc = read_package(Path(bundle).absolute(), pin, self.platform)
            if old:
                require(version(doc["version"]) > version(old["manifest"]["version"]),
                        "NOT_STRICTLY_NEWER")
            self.staging.mkdir(mode=0o700)
            try:
                for row in doc["files"]:
                    source = Path(bundle).absolute() / "payload"
                    src = source.joinpath(*relpath(row["path"]))
                    target = self.staging.joinpath(*relpath(row["path"]))
                    target.parent.mkdir(parents=True, exist_ok=True)
                    # Verified before and after copy: fail closed on source mutation.
                    require(hash_file(src) == row["sha256"].lower(), "PACKAGE_SOURCE_CHANGED")
                    with src.open("rb") as inp, target.open("xb") as dst:
                        shutil.copyfileobj(inp, dst)
                        dst.flush()
                        os.fsync(dst.fileno())
                    if os.name == "posix":
                        target.chmod(row["mode"])
                    require(target.stat().st_size == row["bytes"] and
                            hash_file(target) == row["sha256"].lower(), "STAGING_FILE_CHANGED")
                validate_slot(self.staging, doc)
                new = {"schema": 1, "manifest": doc, "manifest_sha256": pin.lower()}
                atomic_json(self.pending, {"schema": 1, "new": new, "old": old})
            except BaseException:
                # Staging failure has not touched active. Retain unknown scratch
                # for inspection; remove only a complete verifiable staged slot.
                if self.staging.exists():
                    try:
                        validate_slot(self.staging, doc)
                        safe_remove_slot(self.staging, doc)
                    except EngineError:
                        pass
                raise
            return {"status": "PASS_STAGED", "version": doc["version"]}

    def activate(self, quiescent: Callable[[], bool], *, fault: str | None = None) -> dict:
        with self.locked():
            require(self._uninstall() is None, "UNINSTALL_TRANSACTION_ACTIVE")
            pending = self._pending()
            require(pending is not None, "NO_STAGED_TRANSACTION")
            require(self.staging.is_dir() and not self.previous.exists(), "STAGED_STATE_NOT_READY")
            require(callable(quiescent) and quiescent() is True, "PRODUCT_NOT_QUIESCED")
            old, new = pending["old"], pending["new"]
            validate_slot(self.staging, new["manifest"])
            require(self._installed() == old, "INSTALLED_STATE_CHANGED_SINCE_STAGING")
            if old:
                validate_slot(self.current, old["manifest"])
                os.rename(self.current, self.previous)
                durable_dir(self.root)
            if fault == "after_old_move":
                raise EngineError("INJECTED_AFTER_OLD_MOVE")
            os.rename(self.staging, self.current)
            durable_dir(self.root)
            if fault == "after_new_move":
                raise EngineError("INJECTED_AFTER_NEW_MOVE")
            validate_slot(self.current, new["manifest"])
            atomic_json(self.installed, new)
            return {"status": "PASS_ACTIVATED_UNCOMMITTED", "version": new["manifest"]["version"]}

    def commit(self, accepted: Callable[[], bool]) -> dict:
        with self.locked():
            require(self._uninstall() is None, "UNINSTALL_TRANSACTION_ACTIVE")
            p = self._pending()
            require(p is not None, "NO_PENDING_TO_COMMIT")
            require(callable(accepted) and accepted() is True, "PLATFORM_ACCEPTANCE_REQUIRED")
            require(not self.staging.exists(), "UNAPPLIED_STAGE_PRESENT")
            validate_slot(self.current, p["new"]["manifest"])
            installed = self._installed()
            require(installed == p["new"], "UNCOMMITTED_METADATA_INVALID")
            if p["old"] is not None:
                # Replay-safe if a crash happened after verified old-slot
                # deletion but before the pending journal was removed.
                if self.previous.exists():
                    safe_remove_slot(self.previous, p["old"]["manifest"])
            else:
                require(not self.previous.exists(), "UNEXPECTED_PREVIOUS_SLOT")
            self.pending.unlink()
            durable_dir(self.state)
            return {"status": "PASS_COMMITTED_ONE_INSTALL", "version": installed["manifest"]["version"]}

    def rollback(self, quiescent: Callable[[], bool]) -> dict:
        with self.locked():
            require(self._uninstall() is None, "UNINSTALL_TRANSACTION_ACTIVE")
            p = self._pending()
            require(p is not None, "NO_PENDING_TO_ROLLBACK")
            require(callable(quiescent) and quiescent() is True, "PRODUCT_NOT_QUIESCED")
            old, new = p["old"], p["new"]
            if self.staging.exists():
                # The old slot might already have moved when a process died.
                # Infer the exact interrupted boundary from verified slots.
                if self.previous.exists():
                    require(old is not None and not self.current.exists(),
                            "AMBIGUOUS_PREVIOUS_AND_STAGE")
                    validate_slot(self.previous, old["manifest"])
                    safe_remove_slot(self.staging, new["manifest"])
                    os.rename(self.previous, self.current)
                    durable_dir(self.root)
                else:
                    if old:
                        validate_slot(self.current, old["manifest"])
                    else:
                        require(not self.current.exists(), "UNEXPECTED_FRESH_CURRENT")
                    safe_remove_slot(self.staging, new["manifest"])
            elif self.previous.exists():
                require(old is not None, "PREVIOUS_FOR_FRESH_INSTALL")
                validate_slot(self.previous, old["manifest"])
                if self.current.exists():
                    safe_remove_slot(self.current, new["manifest"])
                os.rename(self.previous, self.current)
                durable_dir(self.root)
            elif self.current.exists() and old is None:
                # A fresh install can be rolled back after its new slot is live.
                safe_remove_slot(self.current, new["manifest"])
            elif old is not None and self.current.exists():
                # Crash during a prior rollback, after previous -> current but
                # before the pending journal was retired. Only an exactly
                # validated old slot may resume; never infer from filenames.
                validate_slot(self.current, old["manifest"])
                require(self._installed() == old, "ROLLED_BACK_RECEIPT_NOT_OLD")
            elif old is None and not self.current.exists() and not self.staging.exists():
                # Crash during fresh-install rollback, after removing the new
                # slot but before deleting installed.json / pending.json.
                require(not self.previous.exists(), "FRESH_ROLLBACK_HAS_PREVIOUS")
                if self.installed.exists():
                    require(load_json(self.installed) == new, "FRESH_ROLLBACK_RECEIPT_CHANGED")
            else:
                raise EngineError("AMBIGUOUS_ROLLBACK_SLOT_STATE")
            if old:
                atomic_json(self.installed, old)
                validate_slot(self.current, old["manifest"])
            else:
                if self.installed.exists():
                    require(load_json(self.installed) == new, "FOREIGN_FRESH_INSTALL_STATE")
                    self.installed.unlink()
            self.pending.unlink()
            durable_dir(self.state)
            return {"status": "PASS_ROLLED_BACK", "version": old["manifest"]["version"] if old else None}

    def _uninstall(self) -> dict | None:
        if not self.uninstall_journal.exists():
            require(not self.uninstall_journal.is_symlink(), "UNINSTALL_JOURNAL_LINK")
            return None
        doc = load_json(self.uninstall_journal)
        require(set(doc) == {"schema", "old", "phase"} and
                type(doc["schema"]) is int and doc["schema"] == 1 and
                doc["phase"] in ("prepared", "accepted"), "UNINSTALL_JOURNAL_SCHEMA")
        old = doc["old"]
        require(type(old) is dict and set(old) ==
                {"schema", "manifest", "manifest_sha256"} and
                old["schema"] == 1 and type(old["manifest_sha256"]) is str and
                SHA_RE.fullmatch(old["manifest_sha256"]) is not None,
                "UNINSTALL_OLD_STATE_INVALID")
        manifest_schema(old["manifest"], platform=self.platform)
        return doc

    def prepare_uninstall(self, quiescent: Callable[[], bool]) -> dict:
        """Park owned code; native adapter may unregister only after this.

        The first durable journal precedes moving current -> previous. Until
        native unregistration is accepted, abort_uninstall can restore code.
        Mutable root/data and unrelated paths remain untouched.
        """
        with self.locked():
            require(self._pending() is None and self._uninstall() is None,
                    "OTHER_TRANSACTION_ACTIVE")
            require(not self.staging.exists() and not self.previous.exists(),
                    "ORPHANED_TRANSACTION_SLOTS")
            old = self._installed()
            require(old is not None, "NOT_INSTALLED")
            validate_slot(self.current, old["manifest"])
            require(callable(quiescent) and quiescent() is True,
                    "PRODUCT_NOT_QUIESCED")
            atomic_json(self.uninstall_journal,
                        {"schema": 1, "old": old, "phase": "prepared"})
            os.rename(self.current, self.previous)
            durable_dir(self.root)
            return {"status": "PASS_UNINSTALL_PREPARED", "version": old["manifest"]["version"]}

    def abort_uninstall(self, quiescent: Callable[[], bool]) -> dict:
        """Replay-safe cancellation *before* native registration is removed."""
        with self.locked():
            state = self._uninstall()
            require(state is not None and state["phase"] == "prepared",
                    "UNINSTALL_NOT_ABORTABLE")
            require(callable(quiescent) and quiescent() is True,
                    "PRODUCT_NOT_QUIESCED")
            require(self._pending() is None and not self.staging.exists(),
                    "FOREIGN_UPDATE_DURING_UNINSTALL")
            old = state["old"]
            if self.previous.exists():
                require(not self.current.exists(), "BOTH_SLOTS_DURING_UNINSTALL")
                validate_slot(self.previous, old["manifest"])
                os.rename(self.previous, self.current)
                durable_dir(self.root)
            else:
                # The process may have exited after restoring the slot.
                validate_slot(self.current, old["manifest"])
            require(self._installed() == old, "UNINSTALL_INSTALLED_RECEIPT_DRIFT")
            self.uninstall_journal.unlink()
            durable_dir(self.state)
            return {"status": "PASS_UNINSTALL_ABORTED", "version": old["manifest"]["version"]}

    def finish_uninstall(self, native_unregistered: Callable[[], bool]) -> dict:
        """Delete *only* verified owned code after native adapter acceptance.

        'accepted' is persisted before file deletion. A crash even halfway
        through the previous slot's manifest files can replay safely: only
        remaining, independently hash-verified owned files are deleted;
        missing entries may be treated as already removed ONLY after acceptance.
        """
        with self.locked():
            state = self._uninstall()
            require(state is not None, "NO_UNINSTALL_JOURNAL")
            require(callable(native_unregistered) and native_unregistered() is True,
                    "NATIVE_UNREGISTRATION_NOT_PROVEN")
            require(self._pending() is None and not self.staging.exists() and
                    not self.current.exists(), "UNINSTALL_SLOT_CONFLICT")
            old = state["old"]
            if state["phase"] == "prepared":
                require(self.previous.exists(), "UNINSTALL_NOT_PREPARED")
                require(self._installed() == old, "UNINSTALL_INSTALLED_RECEIPT_DRIFT")
                validate_slot(self.previous, old["manifest"])
                atomic_json(self.uninstall_journal,
                            {"schema": 1, "old": old, "phase": "accepted"})
            # 'accepted' has already reached disk. Partial previous slots
            # are expected after process death; never reuse the strict
            # pre-acceptance safe_remove_slot() here.
            remove_accepted_uninstall_residual(self.previous, old["manifest"])
            # After accepted phase a prior process may have finished cleanup
            # and died before deleting the final journal.
            if self.installed.exists():
                require(self._installed() == old, "UNINSTALL_INSTALLED_RECEIPT_DRIFT")
                self.installed.unlink()
                durable_dir(self.state)
            self.uninstall_journal.unlink()
            durable_dir(self.state)
            return {"status": "PASS_UNINSTALLED_CODE_ONLY", "data_preserved": True}
