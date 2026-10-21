#!/usr/bin/env bash
# uninstall-bootstrap.sh — reverse of install-bootstrap.sh.
#
# Stops + disables the systemd unit, removes the binary, removes the unit
# file, and (optionally) removes the data dir + system user.
#
# By default keeps ${DATA_DIR} so identity/keys survive re-install.  Set
# PURGE_DATA=1 to wipe it too.

set -euo pipefail

VEIL_USER="${VEIL_USER:-veil}"
DATA_DIR="${DATA_DIR:-/var/lib/veil}"
BINARY_PATH="/usr/local/bin/veil-cli"
UNIT_PATH="/etc/systemd/system/veil-bootstrap.service"
PURGE_DATA="${PURGE_DATA:-0}"

say() { printf '\033[1;36m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }

# shellcheck source=bootstrap-paths.sh
source "$(dirname "${BASH_SOURCE[0]}")/bootstrap-paths.sh"
bootstrap_validate_targets "$DATA_DIR" "$VEIL_USER" || exit 1

if [[ "$PURGE_DATA" == 1 ]]; then
    # Refuse arbitrary existing directories even with syntactically valid
    # paths. Older installs have node.toml; new installs also have a marker.
    if [[ -e "$DATA_DIR" && ! -f "$DATA_DIR/.veil-bootstrap-managed" && ! -f "$DATA_DIR/node.toml" ]]; then
        echo 'refusing purge: DATA_DIR is not a recognized bootstrap directory' >&2; exit 1
    fi
    if id "$VEIL_USER" >/dev/null 2>&1 && [[ "$(id -u "$VEIL_USER")" == 0 ]]; then
        echo 'refusing purge of a UID 0 account' >&2; exit 1
    fi
fi

[[ "${EUID}" -eq 0 ]] || { echo "run as root" >&2; exit 1; }

if systemctl list-unit-files | grep -q '^veil-bootstrap\.service'; then
    say "stopping + disabling veil-bootstrap.service"
    systemctl stop veil-bootstrap.service || true
    systemctl disable veil-bootstrap.service || true
fi

if [[ -f "${UNIT_PATH}" ]]; then
    rm -f "${UNIT_PATH}"
    systemctl daemon-reload
    say "removed ${UNIT_PATH}"
fi

if [[ -f "${BINARY_PATH}" ]]; then
    rm -f "${BINARY_PATH}"
    say "removed ${BINARY_PATH}"
fi

if [[ "${PURGE_DATA}" == "1" ]]; then
    say "PURGE_DATA=1 — wiping ${DATA_DIR} and user ${VEIL_USER}"
    rm -rf -- "${DATA_DIR}"
    if id "${VEIL_USER}" >/dev/null 2>&1; then
        userdel -- "${VEIL_USER}" || true
    fi
else
    say "data dir ${DATA_DIR} and user ${VEIL_USER} kept (set PURGE_DATA=1 to remove)"
fi

say "done"
