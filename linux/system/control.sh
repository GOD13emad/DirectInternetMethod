#!/usr/bin/env bash
set -euo pipefail
ACTION="${1:-}"
case "$ACTION" in start|stop|recovery) ;; *) exit 64;; esac
ROOT=/usr/lib/directinternetmethod
UID_FILE=/etc/directinternetmethod.uid
[ -r "$UID_FILE" ] || { echo "Missing $UID_FILE" >&2; exit 65; }
REQ_UID="$(tr -d '[:space:]' < "$UID_FILE")"
case "$REQ_UID" in ''|*[!0-9]*) exit 66;; esac
PASSWD="$(getent passwd "$REQ_UID" || true)"
[ -n "$PASSWD" ] || { echo "uid not found" >&2; exit 66; }
IFS=: read -r DIM_USER _ DIM_UID DIM_GID _ DIM_HOME _ <<<"$PASSWD"
[ "$DIM_UID" = "$REQ_UID" ] || exit 66
[[ "$DIM_USER" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || exit 66
[[ "$DIM_HOME" =~ ^/[A-Za-z0-9._@/+:-]+$ ]] || exit 66
exec /bin/bash "$ROOT/direct_method_helper.sh" "$ACTION" "$ROOT" "$DIM_UID" "$DIM_GID" "$DIM_HOME/.local/share/DirectInternetMethod"
