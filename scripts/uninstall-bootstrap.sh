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
    rm -rf "${DATA_DIR}"
    if id "${VEIL_USER}" >/dev/null 2>&1; then
        userdel "${VEIL_USER}" || true
    fi
else
    say "data dir ${DATA_DIR} and user ${VEIL_USER} kept (set PURGE_DATA=1 to remove)"
fi

say "done"
