#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/bootstrap-paths.sh"
for path in /srv/veil /opt/veil/data /private/tmp/veil; do
    bootstrap_validate_targets "$path" veil
 done
for path in / /var/lib /etc /etc/veil /tmp/../etc /var/lib/veil/../../usr /srv//veil /srv/veil/ /var/lib/veil/.; do
    if bootstrap_validate_targets "$path" veil 2>/dev/null; then echo "accepted unsafe path: $path" >&2; exit 1; fi
 done
for user in root '-root' 'a/b' 'a b'; do
    if bootstrap_validate_targets /var/lib/veil "$user" 2>/dev/null; then echo "accepted unsafe user" >&2; exit 1; fi
 done
printf '%s\n' 'bootstrap path policy checks passed (no system changes)'
