#!/usr/bin/env bash
# Fleet observation snapshot for the veil testnet (read-only).
#
# Pulls daemon metrics + crash/restart/log signals from every inventory host
# via ansible and prints a per-host table plus an ANOMALY summary. Intended to
# be run repeatedly (e.g. every 30 min) after a deploy to watch for regressions.
#
# Usage:  scripts/testnet-observe.sh            # snapshot now
#         scripts/testnet-observe.sh > snap.txt # capture for diffing
#
# Exit code: 0 = no anomalies flagged, 1 = at least one anomaly.
set -uo pipefail
cd "$(dirname "$0")/../ansible" || exit 2

# Remote snapshot: one line of `key=value;...` per host, prefixed by hostname.
REMOTE='
m() { curl -s --max-time 4 http://localhost:19999/metrics 2>/dev/null; }
M="$(m)"
g() { printf "%s" "$M" | awk -v k="$1" "\$1==k{print \$2; f=1} END{if(!f)print \"NA\"}"; }
sessions=$(g veil_active_sessions)
hs_fail=$(g veil_session_handshake_failures_total)
wire_drop=$(g veil_session_wire_dropped_total)
tx_drop=$(g veil_session_tx_drops_total)
rl_drop=$(g veil_rate_limit_drops_total)
ipc_drop=$(g veil_ipc_delivery_drops_total)
relay_drop=$(g veil_dropped_relay_frames_total)
bufpool_drop=$(g veil_bufpool_overflow_drop_total)
rdv_recv=$(g veil_rendezvous_requests_received_total)
veil_restarts=$(systemctl show -p NRestarts --value veil 2>/dev/null || echo NA)
chat_restarts=$(systemctl show -p NRestarts --value chat-node 2>/dev/null || echo NA)
veil_active=$(systemctl is-active veil 2>/dev/null)
chat_active=$(systemctl is-active chat-node 2>/dev/null)
panics=$(grep -rhciE "panic|SIGSEGV|SIGABRT|fatal runtime" /var/log/veil/*.log 2>/dev/null | paste -sd+ - | bc 2>/dev/null || echo 0)
veil_err30=$(journalctl -u veil --since "30 min ago" -p err --no-pager 2>/dev/null | grep -c . )
rss_mb=$(ps -o rss= -C veil-cli 2>/dev/null | awk "{s+=\$1} END{print int(s/1024)}")
# chat rx/tx counters (chat_node prints running totals); take last seen.
chat_tail=$(tail -400 /var/log/veil/chat-node.log 2>/dev/null)
rx=$(printf "%s" "$chat_tail" | grep -oiE "rx[=: ]+[0-9]+" | tail -1 | grep -oE "[0-9]+" )
tx=$(printf "%s" "$chat_tail" | grep -oiE "tx[=: ]+[0-9]+" | tail -1 | grep -oE "[0-9]+" )
printf "sessions=%s;hs_fail=%s;wire_drop=%s;tx_drop=%s;rl_drop=%s;ipc_drop=%s;relay_drop=%s;bufpool_drop=%s;rdv_recv=%s;veil_restarts=%s;chat_restarts=%s;veil=%s;chat=%s;panics=%s;veil_err30=%s;rss_mb=%s;rx=%s;tx=%s\n" \
  "$sessions" "$hs_fail" "$wire_drop" "$tx_drop" "$rl_drop" "$ipc_drop" "$relay_drop" "$bufpool_drop" "$rdv_recv" "$veil_restarts" "$chat_restarts" "$veil_active" "$chat_active" "${panics:-0}" "${veil_err30:-0}" "${rss_mb:-NA}" "${rx:-NA}" "${tx:-NA}"
'

echo "=== testnet observe @ $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
raw=$(ansible all -i inventory.yml -m shell -a "$REMOTE" -o 2>/dev/null)

anomalies=0
printf "%-8s %4s %5s %5s %5s %5s %6s %6s %5s %6s %6s %s\n" \
  HOST SESS HSF WIRE TXDR RLDR IPCDR RELDR PANIC VRST CRST STATE
while IFS= read -r line; do
  host=$(printf "%s" "$line" | awk '{print $1}')
  kv=$(printf "%s" "$line" | grep -oE '[a-z_]+=[^;" ]*' )
  get() { printf "%s" "$kv" | awk -F= -v k="$1" '$1==k{print $2}'; }
  [ -z "$host" ] && continue
  sess=$(get sessions); hsf=$(get hs_fail); wire=$(get wire_drop)
  txd=$(get tx_drop); rld=$(get rl_drop); ipcd=$(get ipc_drop); reld=$(get relay_drop)
  pan=$(get panics); vrst=$(get veil_restarts); crst=$(get chat_restarts)
  va=$(get veil); ca=$(get chat); err30=$(get veil_err30)
  state="${va:-?}/${ca:-?}"
  printf "%-8s %4s %5s %5s %5s %5s %6s %6s %5s %6s %6s %s\n" \
    "$host" "${sess:-?}" "${hsf:-?}" "${wire:-?}" "${txd:-?}" "${rld:-?}" "${ipcd:-?}" "${reld:-?}" "${pan:-?}" "${vrst:-?}" "${crst:-?}" "$state"
  # Anomaly flags
  [ "${pan:-0}" != "0" ] && [ "${pan:-0}" != "NA" ] && { echo "  ANOMALY[$host]: panics=$pan"; anomalies=$((anomalies+1)); }
  [ "${va:-}" != "active" ] && { echo "  ANOMALY[$host]: veil=$va"; anomalies=$((anomalies+1)); }
  [ "${ca:-}" != "active" ] && { echo "  ANOMALY[$host]: chat-node=$ca"; anomalies=$((anomalies+1)); }
  [ "${err30:-0}" -gt 20 ] 2>/dev/null && { echo "  ANOMALY[$host]: veil err logs(30m)=$err30"; anomalies=$((anomalies+1)); }
done <<< "$raw"

echo "--- $anomalies anomaly flag(s) ---"
[ "$anomalies" -eq 0 ]
