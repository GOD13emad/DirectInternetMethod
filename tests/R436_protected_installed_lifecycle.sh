#!/usr/bin/env bash
# R436 real root backend + user installer lifecycle on GITHUB-HOSTED disposable Ubuntu only.
set -euo pipefail
fail() { echo "R436_FAIL_CLOSED:$1" >&2; exit 87; }
[[ "$CI" == "true" && "$GITHUB_ACTIONS" == "true" &&
   "$RUNNER_ENVIRONMENT" == "github-hosted" && "$RUNNER_OS" == "Linux" &&
   "$GITHUB_REPOSITORY" == "GOD13emad/DirectInternetMethod" &&
   "$GITHUB_REF" == "refs/heads/audit/r436-linux-protected-guest-acceptance-20261012" ]] ||
   fail NOT_CLEAN_HOSTED_QA
[[ "$(id -u)" != "0" && -n "$GITHUB_WORKSPACE" && -n "$RUNNER_TEMP" ]] ||
   fail WRONG_EXECUTOR
source="$GITHUB_WORKSPACE/candidate"
[[ "$(git -C "$source" rev-parse HEAD)" == "14a3eec378eb75856f6691b7b3edc970507ee61f" ]] ||
   fail SOURCE_SHA_CHANGED
for path in /usr/lib/directinternetmethod /var/lib/directinternetmethod \
    /etc/directinternetmethod.uid /etc/directinternetmethod.conf \
    /etc/polkit-1/rules.d/49-directinternetmethod.rules \
    /etc/systemd/system/directinternetmethod-start.service \
    /etc/systemd/system/directinternetmethod-stop.service \
    /etc/systemd/system/directinternetmethod-recovery.service \
    /run/directinternetmethod-selective/session.json; do
  [[ ! -e "$path" && ! -L "$path" ]] || fail "HOSTED_BASELINE_NOT_CLEAN:$path"
done
sudo -n true || fail GUEST_NATIVE_SUDO_NOT_GRANTED
out="$RUNNER_TEMP/DIM_R436_HOSTED"
[[ ! -e "$out" ]] || fail REPORT_ALREADY_EXISTS
mkdir -m 0700 "$out"
report="$out/REPORT_R436.log"
touch "$report"
log() { printf '%s\n' "$*" | tee -a "$report"; }
export PATH="/usr/bin:/bin:$PATH"
log "START R436 SOURCE=14a3eec378eb75856f6691b7b3edc970507ee61f"
extract="$RUNNER_TEMP/DIM_R436_EXTRACTED"
[[ ! -e "$extract" ]] || fail EXISTING_PACKAGE_EXTRACT
mkdir -m 0700 "$extract"
archive="$source/delivery/DirectInternetMethod_1.5.2_Linux_x86_64.zip"
[[ -f "$archive" && ! -L "$archive" ]] || fail CANDIDATE_ZIP_MISSING
[[ "$(sha256sum "$archive" | cut -d' ' -f1)" == "53c9fcaddbe96cec9f63505ab20992479c422f3ab9a9e2379898f5a80bf76692" ]] ||
   fail CANDIDATE_ZIP_HASH_DRIFT
[[ "$(stat -c%s "$archive")" == "8273837" ]] || fail CANDIDATE_ZIP_BYTES_DRIFT
unzip -q "$archive" -d "$extract"
package="$extract/DirectInternetMethod_1.5.2_Linux_x86_64"
[[ -f "$package/PACKAGE_MANIFEST.json" && -f "$package/system/install_system.sh" ]] ||
   fail WRONG_EXTRACTED_PACKAGE
python3 -B "$source/tests/linux_real_extracted_archive_contract.py" "$archive" >> "$report"
log "PASS_R436_REAL_EXTRACTED_ZIP_6_OF_6"
network_before="$( (ip -j route show table all;ip -j -6 route show table all;cat /etc/resolv.conf) | sha256sum | cut -d' ' -f1)"
root_attempted=0
root_removed=0
cleanup() {
  rc="$?"
  trap - EXIT
  if [[ "$root_attempted" == "1" && "$root_removed" == "0" ]]; then
    installed=/usr/lib/directinternetmethod/uninstall_system.sh
    if [[ -f "$installed" && "$(sha256sum "$installed" | cut -d' ' -f1)" ==
          "$(sha256sum "$package/system/uninstall_system.sh" | cut -d' ' -f1)" ]]; then
      sudo -n /bin/bash "$installed" >> "$report" 2>&1 ||
        log "ROOT_BACKEND_GUEST_CLEANUP_DEGRADED"
    else
      log "ROOT_BACKEND_UNCERTAIN_NOT_DELETED"
    fi
  fi
  network_after="$( (ip -j route show table all;ip -j -6 route show table all;cat /etc/resolv.conf) | sha256sum | cut -d' ' -f1)"
  if [[ "$network_before" != "$network_after" ]]; then
    log "FAIL_R436_DNS_ROUTE_DRIFT"
    rc=94
  fi
  log "RESULT_CODE=$rc"
  exit "$rc"
}
trap cleanup EXIT
root_attempted=1
log "PROTECTED_ROOT_INSTALL_BEGIN"
sudo -n /bin/bash "$package/system/install_system.sh" "$package" "$(id -u)" >> "$report" 2>&1
[[ -f /var/lib/directinternetmethod/install.json &&
   -f /etc/directinternetmethod.uid &&
   "$(cat /etc/directinternetmethod.uid)" == "$(id -u)" ]] || fail BACKEND_METADATA_OR_UID_MISSING
python3 -B - <<'PY'
import pathlib,json,os
m=json.loads(pathlib.Path('/var/lib/directinternetmethod/install.json').read_text())
assert m['schema']==1 and m['version']=='1.5.2' and m['uid']==os.getuid()
print('PASS_R436_LINUX_PROTECTED_ROOT_METADATA_UID')
PY
for pair in \
 "app/direct_method_helper.sh|direct_method_helper.sh" \
 "system/selective_dns.py|selective_dns.py" \
 "system/control.sh|control.sh" \
 "system/uninstall_system.sh|uninstall_system.sh" \
 "runtime/ctrld|runtime/usr/bin/ctrld" \
 "runtime/nfqws|runtime/usr/bin/nfqws" \
 "app/hosts.txt|direct_hosts.txt" \
 "app/adult_hosts_fallback.txt|adult_hosts_fallback.txt" \
 "app/strong_override_hosts.txt|strong_override_hosts.txt"; do
  from="$(printf '%s' "$pair" | cut -d'|' -f1)"
  dest="$(printf '%s' "$pair" | cut -d'|' -f2)"
  [[ -f "$package/$from" && -f "/usr/lib/directinternetmethod/$dest" ]] ||
    fail "PROTECTED_FILE_MISSING:$pair"
  cmp -s "$package/$from" "/usr/lib/directinternetmethod/$dest" ||
    fail "PROTECTED_FILE_HASH_DIFFERS:$pair"
done
for unit in start stop recovery; do
  [[ -f "/etc/systemd/system/directinternetmethod-$unit.service" ]] ||
    fail "SERVICE_UNIT_MISSING:$unit"
done
[[ -f /etc/polkit-1/rules.d/49-directinternetmethod.rules ]] ||
   fail ROOT_POLKIT_RULE_MISSING
log "PASS_R436_PROTECTED_BACKEND_EXACT_SOURCE_BYTES"
home="$extract/disposable-home"
mkdir -m 0700 "$home"
app="$home/.local/share/DirectInternetMethod"
mkdir -p "$app/router_gateway"
printf '%s\n' '{"userSetting":"KEEP"}' > "$app/settings.json"
printf '%s\n' '{"customProvider":"KEEP"}' > "$app/router_gateway/providers.json"
settings_sha="$(sha256sum "$app/settings.json" | cut -d' ' -f1)"
provider_sha="$(sha256sum "$app/router_gateway/providers.json" | cut -d' ' -f1)"
# The byte-identical backend is already installed; user script never requests
# PolicyKit and must not start VPN, DPI engine, ctrld or change the host network.
HOME="$home" /bin/bash "$package/install.sh" >> "$report" 2>&1
[[ -f "$app/INSTALL.json" && -f "$app/direct_internet_method.py" ]] ||
   fail USER_INSTALL_METADATA_OR_BINARY_MISSING
[[ "$(sha256sum "$app/settings.json" | cut -d' ' -f1)" == "$settings_sha" ]] ||
   fail USER_SETTINGS_CHANGED
[[ "$(sha256sum "$app/router_gateway/providers.json" | cut -d' ' -f1)" == "$provider_sha" ]] ||
   fail USER_CUSTOM_PROVIDERS_CHANGED
[[ ! -e "$home/.local/state/DirectInternetMethod/update-pending" ]] ||
   fail ACCUMULATED_PENDING_SLOT
HOME="$home" python3 -B "$app/user_uninstall_preserve.py" --verify >> "$report"
log "PASS_R436_TRUE_ROOT_AND_USER_INSTALL_CUSTOM_DATA_PRESERVED"
sudo -n /bin/bash "$package/system/uninstall_system.sh" >> "$report" 2>&1
root_removed=1
[[ ! -e /usr/lib/directinternetmethod &&
   ! -e /var/lib/directinternetmethod/install.json &&
   ! -e /etc/directinternetmethod.uid &&
   ! -e /etc/polkit-1/rules.d/49-directinternetmethod.rules ]] ||
   fail PROTECTED_BACKEND_CLEANUP_INCOMPLETE
HOME="$home" python3 -B "$app/user_uninstall_preserve.py" --remove-after-backend >> "$report"
[[ ! -e "$app/INSTALL.json" && ! -e "$app/direct_internet_method.py" ]] ||
   fail USER_EXECUTABLES_REMAIN
[[ "$(sha256sum "$app/settings.json" | cut -d' ' -f1)" == "$settings_sha" ]] ||
   fail SETTINGS_LOST_AFTER_UNINSTALL
[[ "$(sha256sum "$app/router_gateway/providers.json" | cut -d' ' -f1)" == "$provider_sha" ]] ||
   fail PROVIDER_LOST_AFTER_UNINSTALL
log "PASS_R436_REAL_HOSTED_ROOT_USER_NATIVE_INSTALL_UNINSTALL_NO_DUPLICATES"
log "PASS_R436_GUEST_SYSTEM_BACKEND_REMOVED"
