#!/usr/bin/env bash
# R471: exact-public-152 to exact-private-153 in-place Linux upgrade on disposable GitHub Ubuntu only.
set -euo pipefail
fail(){ echo "R471_FAIL_CLOSED:$1" >&2; exit 88; }
[[ "$CI" == true && "$GITHUB_ACTIONS" == true && "$RUNNER_ENVIRONMENT" == github-hosted &&
   "$RUNNER_OS" == Linux && "$RUNNER_ARCH" == X64 &&
   "$GITHUB_REPOSITORY" == GOD13emad/DirectInternetMethod &&
   "$GITHUB_REF" == refs/heads/qa/r471-linux-native-upgrade-20261013 ]] || fail NOT_DISPOSABLE_HOST
[[ "$(id -u)" != 0 && -n "$RUNNER_TEMP" && -n "$GITHUB_WORKSPACE" ]] || fail WRONG_EXECUTOR
source="$GITHUB_WORKSPACE/candidate"
[[ "$(git -C "$source" rev-parse HEAD)" == eb6a7bf9a7c6a04cef5a85100e805d0575ef9c9a ]] || fail SOURCE_SHA_CHANGED
sudo -n true || fail SUDO_UNAVAILABLE
for p in /usr/lib/directinternetmethod /var/lib/directinternetmethod \
 /etc/directinternetmethod.uid /etc/polkit-1/rules.d/49-directinternetmethod.rules \
 /etc/systemd/system/directinternetmethod-start.service \
 /etc/systemd/system/directinternetmethod-stop.service \
 /etc/systemd/system/directinternetmethod-recovery.service;do
 sudo -n test ! -e "$p" && sudo -n test ! -L "$p" || fail ROOT_PRESTATE_NOT_EMPTY
done
out="$RUNNER_TEMP/DIM_R471_HOSTED"
[[ ! -e "$out" ]] || fail RECEIPT_DIR_ALREADY_EXISTS
mkdir -m 0700 "$out"
logfile="$out/REPORT_R471.log"
touch "$logfile"
log(){ printf '%s\n' "$*" | tee -a "$logfile"; }
net(){ (ip -4 route show table all; ip -6 route show table all; resolvectl dns; resolvectl domain)|sha256sum|cut -d' ' -f1; }
network_before="$(net)"
dir="$RUNNER_TEMP/DIM_R471_ASSETS"
oldzip="$dir/DirectInternetMethod_1.5.2_Linux_x86_64.zip"
newzip="$dir/DirectInternetMethod_1.5.3_Linux_x86_64.zip"
[[ -f "$oldzip" && -f "$newzip" && ! -L "$oldzip" && ! -L "$newzip" ]] || fail MISSING_VERIFIED_GH_ASSETS
[[ "$(sha256sum "$oldzip"|cut -d' ' -f1)" == 53c9fcaddbe96cec9f63505ab20992479c422f3ab9a9e2379898f5a80bf76692 ]] || fail PUBLIC_152_SHA_DIFFERENT
[[ "$(sha256sum "$newzip"|cut -d' ' -f1)" == 680343f86abec2d7b69ce807f4ec5b344789b2d6335c51c068bc49f4650dfc05 ]] || fail PRIVATE_153_SHA_DIFFERENT
[[ "$(stat -c%s "$oldzip")" == 8273837 && "$(stat -c%s "$newzip")" == 8274083 ]] || fail ARTIFACT_SIZES_DIFFER
ex="$RUNNER_TEMP/DIM_R471_EXTRACTED"
[[ ! -e "$ex" ]] || fail EXTRACT_ALREADY_EXISTS
mkdir -m 0700 "$ex"
unzip -q "$oldzip" -d "$ex"
unzip -q "$newzip" -d "$ex"
old="$ex/DirectInternetMethod_1.5.2_Linux_x86_64"
new="$ex/DirectInternetMethod_1.5.3_Linux_x86_64"
[[ -f "$old/system/install_system.sh" && -f "$new/install.sh" && -f "$new/app/user_update_transaction.py" ]] || fail INVALID_ARCHIVE_LAYOUT
home="$ex/disposable-home"
mkdir -m 0700 "$home"
app="$home/.local/share/DirectInternetMethod"
mkdir -p "$app/router_gateway"
printf '{"r471UserSetting":"KEEP"}\n' > "$app/settings.json"
printf '{"r471CustomProvider":"KEEP"}\n' > "$app/router_gateway/providers.json"
settings_sha="$(sha256sum "$app/settings.json"|cut -d' ' -f1)"
provider_sha="$(sha256sum "$app/router_gateway/providers.json"|cut -d' ' -f1)"
attempted=0;removed=0;committed=0
cleanup(){
 rc=$?
 trap - EXIT
 if [[ "$attempted" == 1 && "$removed" == 0 ]];then
  if sudo -n test -f /var/lib/directinternetmethod/install.json;then
   sudo -n /bin/bash "$old/system/uninstall_system.sh" >>"$logfile" 2>&1 && removed=1 || log R471_ROOT_CLEANUP_FAILED
  else log R471_PARTIAL_ROOT_UNRESOLVED_NO_BLIND_CLEANUP;fi
 fi
 [[ "$(net)" == "$network_before" ]] || { log R471_NET_ROUTE_DNS_DRIFT;rc=95; }
 if [[ "$committed" == 1 && "$removed" != 1 ]];then rc=96;log R471_ROOT_REMAINS;fi
 log "RESULT_CODE=$rc"
 exit "$rc"
}
trap cleanup EXIT
log R471_BEGIN_NATIVE_EXACT_SOURCE_UPGRADE
attempted=1
sudo -n /bin/bash "$old/system/install_system.sh" "$old" "$(id -u)" >>"$logfile" 2>&1 || fail V152_BASELINE_ROOT_INSTALL_FAILED
[[ -f /var/lib/directinternetmethod/install.json ]] || fail ROOT_METADATA_MISSING
python3 - <<'PY'
import pathlib,json,os
d=json.loads(pathlib.Path("/var/lib/directinternetmethod/install.json").read_text())
assert d["version"]=="1.5.2" and d["uid"]==os.getuid(),d
print("PASS_R471_ACTUAL_V152_ROOT_METADATA")
PY
HOME="$home" /bin/bash "$old/install.sh" >>"$logfile" 2>&1 || fail V152_BASELINE_USER_INSTALL_FAILED
[[ -f "$app/INSTALL.json" && -f "$app/direct_internet_method.py" ]] || fail V152_USER_PROGRAM_ABSENT
old_gui_sha="$(sha256sum "$app/direct_internet_method.py"|cut -d' ' -f1)"
root_meta_sha="$(sudo -n sha256sum /var/lib/directinternetmethod/install.json|cut -d' ' -f1)"
root_helper_sha="$(sudo -n sha256sum /usr/lib/directinternetmethod/direct_method_helper.sh|cut -d' ' -f1)"
log R471_PUBLIC_V152_ROOT_USER_ACTUAL_INSTALL_PASS
HOME="$home" python3 -B "$new/app/user_update_transaction.py" --source "$new" --stage >>"$logfile" 2>&1 || fail V153_STAGE_FAILED
HOME="$home" python3 -B "$new/app/user_update_transaction.py" --source "$new" --apply >>"$logfile" 2>&1 || fail V153_APPLY_FAILED
HOME="$home" python3 -B "$new/app/user_update_transaction.py" --source "$new" --rollback >>"$logfile" 2>&1 || fail V153_ROLLBACK_FAILED
[[ "$(sha256sum "$app/direct_internet_method.py"|cut -d' ' -f1)" == "$old_gui_sha" ]] || fail V152_USER_CODE_NOT_RESTORED
[[ ! -e "$home/.local/state/DirectInternetMethod/update-pending" ]] || fail ROLLBACK_PENDING_STALE
[[ "$(sha256sum "$app/settings.json"|cut -d' ' -f1)" == "$settings_sha" &&
   "$(sha256sum "$app/router_gateway/providers.json"|cut -d' ' -f1)" == "$provider_sha" ]] || fail USER_CONFIG_CHANGED_ON_ROLLBACK
log R471_REAL_INSTALLED_V153_STAGED_ROLLBACK_PASS
HOME="$home" /bin/bash "$new/install.sh" >>"$logfile" 2>&1 || fail V153_NATIVE_UPGRADE_FAILED
python3 -B - "$app/INSTALL.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
assert d["version"]=="1.5.3" and d["protectedBackendVersion"]=="1.5.2",d
print("PASS_R471_USER_PROGRAM_153_ROOT_BACKEND_152")
PY
[[ "$(sudo -n sha256sum /var/lib/directinternetmethod/install.json|cut -d' ' -f1)" == "$root_meta_sha" ]] || fail ROOT_METADATA_MODIFIED
[[ "$(sudo -n sha256sum /usr/lib/directinternetmethod/direct_method_helper.sh|cut -d' ' -f1)" == "$root_helper_sha" ]] || fail ROOT_HELPER_MUTATED
cmp -s "$new/app/direct_internet_method.py" "$app/direct_internet_method.py" || fail USER_EXACT_NEW_SOURCE_NOT_INSTALLED
[[ "$(sha256sum "$app/settings.json"|cut -d' ' -f1)" == "$settings_sha" &&
   "$(sha256sum "$app/router_gateway/providers.json"|cut -d' ' -f1)" == "$provider_sha" ]] || fail SETTINGS_AND_PROVIDER_NOT_PRESERVED
[[ ! -e "$home/.local/state/DirectInternetMethod/update-pending" ]] || fail COMMIT_PENDING_STALE
HOME="$home" python3 -B "$app/user_uninstall_preserve.py" --verify >>"$logfile" 2>&1 || fail V153_MANAGED_FILES_BAD
log R471_GENUINE_V152_TO_V153_INPLACE_ROOT_UNCHANGED_DATA_PRESERVED
sudo -n /bin/bash "$old/system/uninstall_system.sh" >>"$logfile" 2>&1 || fail OWNED_ROOT_UNINSTALL_FAILED
removed=1
sudo -n test ! -e /usr/lib/directinternetmethod && sudo -n test ! -e /var/lib/directinternetmethod/install.json || fail PROTECTED_RESIDUE
HOME="$home" python3 -B "$app/user_uninstall_preserve.py" --remove-after-backend >>"$logfile" 2>&1 || fail MANAGED_USER_UNINSTALL_FAILED
[[ ! -e "$app/direct_internet_method.py" && ! -e "$app/INSTALL.json" ]] || fail USER_PROGRAM_RESIDUE
[[ "$(sha256sum "$app/settings.json"|cut -d' ' -f1)" == "$settings_sha" &&
   "$(sha256sum "$app/router_gateway/providers.json"|cut -d' ' -f1)" == "$provider_sha" ]] || fail USER_DATA_DELETED
committed=1
log R471_ROOT_USER_NATIVE_UNINSTALL_PRESERVES_DATA
