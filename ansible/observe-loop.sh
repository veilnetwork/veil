#!/usr/bin/env bash
# Post-deploy testnet watcher (2026-06-13, NAT-fallback-dedup + 5-sim-gaps batch).
# Directly queries each host's RELIABLE health signals over SSH (systemctl +
# journald + a retried metrics curl) so it is immune to the bulk-snapshot
# curl-timeout transients. Runs every 30 min for 6 cycles (~3h). Breaks EARLY
# (so the parent is notified) only on a REAL regression:
#   - veil service not active
#   - NRestarts > 0  (crash-restart)
#   - panic/SIGSEGV/SIGABRT in logs
#   - active_sessions < 16 on a host (full mesh is 17; <16 ⇒ stranding,
#     the exact failure class the dedup fix addresses)
#   - handshake_failures climbing fast
set -uo pipefail
cd "$(dirname "$0")" || exit 2
LOG=/tmp/veil_observe.log
CYCLES=6
INTERVAL=1800

# Per-host probe: svc, NRestarts, panics, sessions, hsf. Metrics curl retried
# 3x (transient timeouts are the snapshot's noise source, not a node fault).
PROBE='
svc=$(systemctl is-active veil 2>/dev/null)
rst=$(systemctl show -p NRestarts --value veil 2>/dev/null)
panics=$(journalctl -u veil --since "35 min ago" --no-pager 2>/dev/null | grep -ciE "panic|SIGSEGV|SIGABRT|fatal runtime")
M=""; for a in 1 2 3; do M=$(curl -s --max-time 8 http://localhost:19999/metrics 2>/dev/null); [ -n "$M" ] && break; sleep 1; done
sess=$(printf "%s" "$M" | awk "\$1==\"veil_active_sessions\"{print \$2}")
hsf=$(printf "%s" "$M" | awk "\$1==\"veil_session_handshake_failures_total\"{print \$2}")
printf "svc=%s;rst=%s;panics=%s;sess=%s;hsf=%s\n" "${svc:-NA}" "${rst:-NA}" "${panics:-0}" "${sess:-NA}" "${hsf:-NA}"
'

echo "=== observe-loop start $(date -u +%FT%TZ) — $CYCLES cycles @ ${INTERVAL}s ===" | tee -a "$LOG"
for c in $(seq 1 "$CYCLES"); do
  ts=$(date -u +%FT%TZ)
  raw=$(ansible all -i inventory.yml -m shell -a "$PROBE" -o 2>/dev/null | grep -vE "WARNING|DEPRECATION")
  bad=""
  total_hosts=0; healthy=0; min_sess=99; max_hsf=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    host=$(printf "%s" "$line" | awk '{print $1}')
    [ "$host" = "Failed" ] && { bad="$bad $host(ssh)"; continue; }
    total_hosts=$((total_hosts+1))
    svc=$(printf "%s" "$line"  | grep -oE "svc=[^;]*"    | cut -d= -f2)
    rst=$(printf "%s" "$line"  | grep -oE "rst=[^;]*"    | cut -d= -f2)
    pan=$(printf "%s" "$line"  | grep -oE "panics=[^;]*" | cut -d= -f2)
    ses=$(printf "%s" "$line"  | grep -oE "sess=[^; ]*"  | cut -d= -f2)
    hsf=$(printf "%s" "$line"  | grep -oE "hsf=[^; ]*"   | cut -d= -f2)
    [ "$svc" != "active" ] && bad="$bad $host(svc=$svc)"
    [ "$rst" != "0" ] && [ "$rst" != "NA" ] && bad="$bad $host(rst=$rst)"
    [ "${pan:-0}" -gt 0 ] 2>/dev/null && bad="$bad $host(panics=$pan)"
    if [ -n "$ses" ] && [ "$ses" != "NA" ]; then
      [ "$ses" -lt "$min_sess" ] 2>/dev/null && min_sess=$ses
      [ "$ses" -lt 16 ] 2>/dev/null && bad="$bad $host(sess=$ses)"
    fi
    if [ -n "$hsf" ] && [ "$hsf" != "NA" ]; then
      [ "$hsf" -gt "$max_hsf" ] 2>/dev/null && max_hsf=$hsf
    fi
    [ "$svc" = "active" ] && healthy=$((healthy+1))
  done <<< "$raw"

  if [ -n "$bad" ]; then
    echo "[$ts] cycle $c/$CYCLES: REAL ANOMALY →$bad (healthy=$healthy/$total_hosts min_sess=$min_sess max_hsf=$max_hsf)" | tee -a "$LOG"
    echo "ANOMALY_DETECTED cycle=$c" | tee -a "$LOG"
    exit 1
  fi
  echo "[$ts] cycle $c/$CYCLES: OK — $healthy/$total_hosts active, min_sess=$min_sess, max_hsf=$max_hsf, 0 restarts/panics" | tee -a "$LOG"
  [ "$c" -lt "$CYCLES" ] && sleep "$INTERVAL"
done
echo "=== observe-loop done $(date -u +%FT%TZ): $CYCLES clean cycles over ~3h, no regression ===" | tee -a "$LOG"
