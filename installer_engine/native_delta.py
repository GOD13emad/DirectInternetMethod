"""Portable, side-effect-free managed CODE delta proposal across native scopes.

Compare an independently supplied prior managed-code inventory and a freshly
observed inventory against a strict NativePlan target. No user data, service
registration, filesystem paths or OS policy are inferred. Crucially: prior
inventory and observed bytes must be authenticated by a future native broker,
not provided by a CLI user. Here they are synthetic/readonly inputs only.

A result is ONLY an engineering migration *proposal*, never an installation,
authorization, root/UAC grant, publisher signature or safe rollback receipt.
"""
from __future__ import annotations

from .engine import (
    EngineError, MAX_FILE_BYTES, PRODUCT, PLATFORMS, SHA_RE,
    manifest_schema, relpath, require, version,
)
from .native_plan import NativePlan

STATUS = "READ_ONLY_MANAGED_CODE_DELTA_NOT_NATIVE_INSTALLATION"
_SUPPORTED_KINDS = frozenset((
    "INSTALLED_SCOPES_NEED_INNO_SCM",
    "PINNED_CODE_LAYOUT_REQUIRES_TRUSTED_NATIVE_ADAPTER",
))


def _inventory(doc: object, *, platform: str, scope_names: set[str]) -> dict:
    require(type(doc) is dict and
            set(doc) == {"schema", "product", "platform", "version", "scopes"} and
            type(doc["schema"]) is int and doc["schema"] == 1 and
            doc["product"] == PRODUCT and doc["platform"] == platform,
            "DELTA_INVENTORY_SCHEMA_OR_IDENTITY")
    require(type(doc["version"]) is str, "DELTA_VERSION_REQUIRED")
    version(doc["version"])
    scopes=doc["scopes"]
    require(type(scopes) is list and len(scopes) == 2,
            "DELTA_TWO_SCOPE_INVENTORY_REQUIRED")
    parsed={}
    for scope in scopes:
        require(type(scope) is dict and set(scope) == {"name", "files"},
                "DELTA_SCOPE_FIELDS_INVALID")
        name=scope["name"]
        require(type(name) is str and name in scope_names and name not in parsed,
                "DELTA_SCOPE_IDENTITY_DRIFT")
        files=scope["files"]
        require(type(files) is list and len(files) <= 4096,
                "DELTA_SCOPE_FILE_BOUNDS")
        records={}
        for f in files:
            require(type(f) is dict and set(f) ==
                    {"path", "bytes", "sha256", "mode"},
                    "DELTA_CODE_FILE_SCHEMA")
            parts=relpath(f["path"])
            key="/".join(parts).casefold()
            require(key not in records, "DELTA_CODE_PATH_DUPLICATE")
            require(type(f["bytes"]) is int and
                    0 <= f["bytes"] <= MAX_FILE_BYTES,
                    "DELTA_CODE_BYTES_INVALID")
            require(type(f["sha256"]) is str and
                    SHA_RE.fullmatch(f["sha256"]) is not None,
                    "DELTA_CODE_HASH_INVALID")
            require(type(f["mode"]) is int and
                    f["mode"] in (0o644,0o755),
                    "DELTA_CODE_MODE_INVALID")
            records[key]=f
        parsed[name]=records
    require(set(parsed)==scope_names, "DELTA_TWO_SCOPE_IDENTITIES_INVALID")
    return parsed


def compare_managed_code_delta(plan: NativePlan, prior: dict,
                               observed: dict) -> dict:
    """Verify exact prior-vs-observed scope inventory; propose target changes.

    *Not* a trusted native readback: the caller must separately pin the prior
    release manifest and measure observed files through OS-trusted handles.
    The result never authorizes any write, even when all hashes agree.
    """
    require(type(plan) is NativePlan and plan.product == PRODUCT and
            plan.platform in PLATFORMS and
            plan.source_kind in _SUPPORTED_KINDS and
            plan.native_adapter_accepted is False and
            type(plan.scopes) is tuple and len(plan.scopes) == 2,
            "DELTA_NATIVE_PLAN_UNTRUSTED")
    version(plan.version)
    names={name for name, _ in plan.scopes}
    require(len(names)==2 and
            all(type(n) is str and n in ("privileged","user","code")
                for n in names),
            "DELTA_NATIVE_SCOPE_NAMES_UNSUPPORTED")
    target={}
    for name, manifest in plan.scopes:
        require(type(manifest) is dict and
                manifest_schema(manifest,platform=plan.platform) is not None and
                manifest["product"] == PRODUCT and
                manifest["version"] == plan.version,
                "DELTA_TARGET_MANIFEST_DRIFT")
        target[name]={x["path"].casefold():x for x in manifest["files"]}
    past=_inventory(prior,platform=plan.platform,scope_names=names)
    actual=_inventory(observed,platform=plan.platform,scope_names=names)
    require(prior["version"]==observed["version"] and
            version(prior["version"]) < version(plan.version),
            "DELTA_BASELINE_RELEASE_MISMATCH_OR_NOT_OLDER")
    stats={"unchanged":0,"replace":0,"create":0}
    changes={}
    for name in sorted(names):
        expected=past[name]
        measured=actual[name]
        require(set(expected)==set(measured),
                "DELTA_PRIOR_CURRENT_CODE_PATH_DRIFT")
        require(set(expected) <= set(target[name]),
                "DELTA_PREVIOUS_MANAGED_CODE_RETIRE_REQUIRES_NATIVE_REVIEW")
        # The verified scope snapshots cover all previously managed entries.
        # Exclude explicit user settings and other non-code paths; their
        # preservation must be validated independently on actual installs.
        for key in expected:
            a,b=expected[key],measured[key]
            require((a["path"].casefold(),a["bytes"],a["sha256"].lower(),a["mode"]) ==
                    (b["path"].casefold(),b["bytes"],b["sha256"].lower(),b["mode"]),
                    "DELTA_INSTALLED_MANAGED_CODE_DRIFT")
        rows=[]
        for key, dst in sorted(target[name].items()):
            if key not in expected:
                action="create"
            else:
                current=expected[key]
                action=("unchanged" if
                        (current["bytes"],current["sha256"].lower(),current["mode"]) ==
                        (dst["bytes"],dst["sha256"].lower(),dst["mode"])
                        else "replace")
            stats[action]+=1
            rows.append({"path":dst["path"],"action":action,
                         "sha256":dst["sha256"].lower()})
        changes[name]=rows
    return {
        "status":STATUS,
        "baseline_version":prior["version"],
        "target_version":plan.version,
        "platform":plan.platform,
        "stats":stats,
        "scopes":changes,
        "native_installation_accepted":False,
        "publisher_authenticated":False,
        "privileged_broker_implemented":False,
        "protected_write_performed":False,
    }
