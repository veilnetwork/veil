#!/usr/bin/env bash
# A/B measurement harness for the iterative-DHT route-discovery fallback.
#
# Captures per-node delivery counters + chat throughput into a CSV, and diffs
# two snapshots into per-node and network-wide deltas + the end-to-end chat
# delivery ratio. Pair with ansible/toggle-dht-fallback.yml; full procedure in
# ansible/RUNBOOK-ab-dht-fallback.md.
#
# Usage:
#   scripts/ab-dht-fallback-snapshot.sh snap <tag>          # labelled snapshot
#   scripts/ab-dht-fallback-snapshot.sh diff <tagA> <tagB>  # window delta
#   scripts/ab-dht-fallback-snapshot.sh hosts               # print host map
#
# Snapshots land in ab-data/<tag>.csv (override with AB_DATA_DIR).
#
# Outcome metric: end-to-end chat delivery ratio = Σ recv / Σ sent across all
# nodes over the window. recursive_relay_{initiated,delivered} are diagnostics
# only — they count DIFFERENT events at different nodes (a node forwards =
# "initiated", terminally delivers = "delivered"), so they are NOT a same-node
# success ratio. The keep-vs-remove call is: does Σrecv/Σsent under chaos drop
# when the fallback is OFF vs ON? If not, the fallback adds nothing.

set -uo pipefail

SSH_OPTS="-o ConnectTimeout=8 -o BatchMode=yes"
DATA_DIR="${AB_DATA_DIR:-ab-data}"
HERE="$(cd "$(dirname "$0")" && pwd)"
AB_INVENTORY="${AB_INVENTORY:-$HERE/../ansible/inventory.yml}"

# Host map (name:ip) is parsed at runtime from the GITIGNORED
# ansible/inventory.yml so no real testnet IPs live in this committed script.
# Override the path with AB_INVENTORY.
HOSTS=()
load_hosts() {
  [ -f "$AB_INVENTORY" ] || {
    echo "inventory not found: $AB_INVENTORY (set AB_INVENTORY)" >&2; exit 1; }
  # Pair each host key (e.g. `node1:`) with the `ansible_host:` line nested
  # under it. Portable awk (no gawk-only match() captures).
  while IFS= read -r line; do HOSTS+=("$line"); done < <(awk '
    /^[[:space:]]+[A-Za-z0-9_-]+:[[:space:]]*$/ { n=$1; sub(/:$/,"",n); last=n }
    /^[[:space:]]*ansible_host:/ { print last ":" $2 }
  ' "$AB_INVENTORY")
  [ "${#HOSTS[@]}" -gt 0 ] || { echo "no hosts parsed from $AB_INVENTORY" >&2; exit 1; }
}

# CSV columns after tag,host,ts: flag,sent,recv then these 9 counters (in order).
HEADER="tag,host,ts,flag,sent,recv,route_miss,rr_init,rr_deliv,send_fail,wire_drop,fb_trig,fb_resolv,fb_miss,fb_skip"

# Remote probe — SINGLE-QUOTED so the local shell never expands the chat-log
# bracket patterns. Sent to remote bash via a here-string.
read -r -d '' REMOTE <<'REMOTE_EOF' || true
cfg=/var/lib/veil/node.toml
log=/var/log/veil/chat-node.log
flag=$(grep -E '^[[:space:]]*dht_fallback_enabled' "$cfg" 2>/dev/null | grep -oE 'true|false' | head -1)
[ -z "$flag" ] && flag=default-true
sent=$(grep -ac '^\[->\]' "$log" 2>/dev/null); sent=${sent:-0}
recv=$(grep -ac '^\[<-\]' "$log" 2>/dev/null); recv=${recv:-0}
t=$(mktemp)
curl -sS --max-time 5 http://127.0.0.1:19999/metrics 2>/dev/null > "$t"
val() { awk -v k="$1" '$1==k{print $2; f=1} END{if(!f)print 0}' "$t"; }
printf '%s,%s,%s' "$flag" "$sent" "$recv"
for k in veil_route_miss_total veil_recursive_relay_initiated_total \
         veil_recursive_relay_delivered_total veil_send_to_failed_total \
         veil_session_wire_dropped_total veil_dht_fallback_triggered_total \
         veil_dht_fallback_resolved_total veil_dht_fallback_miss_total \
         veil_dht_fallback_skipped_backpressure_total; do
  printf ',%s' "$(val "$k")"
done
printf '\n'
rm -f "$t"
REMOTE_EOF

cmd_hosts() { load_hosts; printf '%s\n' "${HOSTS[@]}"; }

cmd_snap() {
  local tag="${1:?usage: snap <tag>}"
  load_hosts
  mkdir -p "$DATA_DIR"
  local out="$DATA_DIR/${tag}.csv"
  local ts; ts=$(date -u +%FT%TZ)
  echo "$HEADER" > "$out"
  printf '%-7s %-6s %5s %6s %6s  %-8s %-8s %-7s\n' host flag sent recv miss rr_init rr_deliv fb_t/r/m
  for hp in "${HOSTS[@]}"; do
    local name="${hp%%:*}" ip="${hp##*:}" line
    line=$(ssh $SSH_OPTS "root@$ip" bash -s <<<"$REMOTE" 2>/dev/null)
    [ -z "$line" ] && line="ERR,,,,,,,,,,,"
    echo "$tag,$name,$ts,$line" >> "$out"
    # pretty row: flag sent recv route_miss rr_init rr_deliv  fb trig/resolv/miss
    IFS=',' read -r flag sent recv miss rri rrd sf wd ft fr fm fs <<<"$line"
    printf '%-7s %-6s %5s %6s %6s  %-8s %-8s %s/%s/%s\n' \
      "$name" "$flag" "$sent" "$recv" "$miss" "$rri" "$rrd" "$ft" "$fr" "$fm"
  done
  echo "wrote $out  (ts=$ts)"
}

cmd_diff() {
  local a="${1:?usage: diff <tagA> <tagB>}" b="${2:?usage: diff <tagA> <tagB>}"
  local fa="$DATA_DIR/${a}.csv" fb="$DATA_DIR/${b}.csv"
  [ -f "$fa" ] || { echo "missing $fa" >&2; exit 1; }
  [ -f "$fb" ] || { echo "missing $fb" >&2; exit 1; }
  echo "delta: $a -> $b   (per node, then network)"
  awk -F, -v A="$a" -v B="$b" '
    FNR==1 { next }                         # skip header
    NR==FNR { flagA[$2]=$4; for(i=5;i<=15;i++) a[$2,i]=$i; next }
    {
      h=$2
      ds=$5-a[h,5]; dr=$6-a[h,6]; dm=$7-a[h,7]; di=$8-a[h,8]; dd=$9-a[h,9]
      dsf=$10-a[h,10]; dwd=$11-a[h,11]; dft=$12-a[h,12]; dfr=$13-a[h,13]
      printf "  %-7s flag %s->%s  sent+%-5d recv+%-4d  route_miss+%-5d rr_init+%-5d rr_deliv+%-4d  send_fail+%d wire_drop+%d  fb_trig+%d fb_resolv+%d\n", \
             h, flagA[h], $4, ds, dr, dm, di, dd, dsf, dwd, dft, dfr
      SS+=ds; SR+=dr; SM+=dm; SI+=di; SD+=dd; SSF+=dsf; SWD+=dwd; SFT+=dft; SFR+=dfr
    }
    END {
      printf "\n  NETWORK  chat sent+%d recv+%d  (lines; send sampled 1:100, recv 1:1000)\n", SS, SR
      printf "           route_miss+%d  rr_init+%d  rr_deliv+%d\n", SM, SI, SD
      printf "           send_to_failed+%d  session_wire_dropped+%d\n", SSF, SWD
      printf "           fb_triggered+%d  fb_resolved+%d\n", SFT, SFR
    }
  ' "$fa" "$fb"
}

case "${1:-}" in
  snap)  shift; cmd_snap "$@" ;;
  diff)  shift; cmd_diff "$@" ;;
  hosts) cmd_hosts ;;
  *) echo "usage: $0 {snap <tag> | diff <tagA> <tagB> | hosts}" >&2; exit 2 ;;
esac
