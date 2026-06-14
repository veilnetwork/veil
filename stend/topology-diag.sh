#!/usr/bin/env bash
# Diagnostic dump: per-node sessions + bans + a route lookup hint.
# Read-only — does not mutate state.

set -euo pipefail
cd "$(dirname "$0")"

CLI=./veil-cli

ID1=$(grep -m1 '^node_id' node1/config.toml | cut -d'"' -f2)
ID2=$(grep -m1 '^node_id' node2/config.toml | cut -d'"' -f2)
ID3=$(grep -m1 '^node_id' node3/config.toml | cut -d'"' -f2)
ID4=$(grep -m1 '^node_id' node4/config.toml | cut -d'"' -f2)
ID5=$(grep -m1 '^node_id' node5/config.toml | cut -d'"' -f2)

short() {
  local id="$1"
  case "$id" in
    "$ID1"*) echo "node1" ;;
    "$ID2"*) echo "node2" ;;
    "$ID3"*) echo "node3" ;;
    "$ID4"*) echo "node4" ;;
    "$ID5"*) echo "node5" ;;
    *) echo "${id:0:8}…" ;;
  esac
}

for n in 1 2 3 4 5; do
  echo
  echo "═══ node$n ═══"
  echo "── sessions list ──"
  $CLI -c node$n/config.toml sessions list 2>/dev/null \
    | sed -n 's/.*link_id="\([^"]*\)".*node_id=Some(NodeId("\([^"]*\)")).*state=\([A-Za-z]*\).*/\1  →  \2  [\3]/p' \
    | while read -r line; do
        link=$(echo "$line" | awk '{print $1}')
        nid=$(echo  "$line" | awk '{print $3}')
        state=$(echo "$line" | awk '{print $4}')
        printf "  %-20s → %s  %s\n" "$link" "$(short $nid)" "$state"
      done
  # Fallback for raw output
  raw=$($CLI -c node$n/config.toml sessions list 2>/dev/null || echo "")
  if [[ -z "$raw" ]]; then
    echo "  (admin socket dead?)"
  elif [[ "$raw" != *"link_id"* ]]; then
    echo "  (no sessions)"
  fi
  echo "── peers banned ──"
  $CLI -c node$n/config.toml peers banned 2>/dev/null \
    | grep -oE 'node_id="[a-f0-9]{64}"' \
    | sed 's/node_id="//; s/"//' \
    | while read -r nid; do printf "  %s  (%s)\n" "$nid" "$(short $nid)"; done
done

echo
echo "═══ Expected topology (5 allowed pairs) ═══"
echo "  node1 ↔ node2, node1 ↔ node5, node2 ↔ node3, node3 ↔ node4, node4 ↔ node5"
echo "  → each node should see 2 sessions; total ends = 10"
