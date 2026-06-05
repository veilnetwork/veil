#!/usr/bin/env bash
# Lift all bans applied by topology-fragment.sh — restore full-mesh.

set -euo pipefail
cd "$(dirname "$0")"

CLI=./veil-cli

ID1=$(grep -m1 '^node_id' node1/config.toml | cut -d'"' -f2)
ID2=$(grep -m1 '^node_id' node2/config.toml | cut -d'"' -f2)
ID3=$(grep -m1 '^node_id' node3/config.toml | cut -d'"' -f2)
ID4=$(grep -m1 '^node_id' node4/config.toml | cut -d'"' -f2)
ID5=$(grep -m1 '^node_id' node5/config.toml | cut -d'"' -f2)

declare -A IDS=( [1]=$ID1 [2]=$ID2 [3]=$ID3 [4]=$ID4 [5]=$ID5 )

BLOCKED=(
  "1 3"
  "1 4"
  "2 4"
  "2 5"
  "3 5"
)

for n in 1 2 3 4 5; do
  if [[ ! -S "node$n/config.sock" ]]; then
    echo "WARN: node$n admin socket not found — bans will persist in node$n/bans.json until next start." >&2
  fi
done

echo "── Lifting bans ──"
for pair in "${BLOCKED[@]}"; do
  read -r a b <<<"$pair"
  echo "  unban node$a ↔ node$b"
  [[ -S "node$a/config.sock" ]] && $CLI -c node$a/config.toml peers unban "${IDS[$b]}" >/dev/null || true
  [[ -S "node$b/config.sock" ]] && $CLI -c node$b/config.toml peers unban "${IDS[$a]}" >/dev/null || true
done

echo
echo "✓ Bans lifted in-process.  bans.json on disk is also updated by the runtime."
echo "  If a node was offline, manually edit its bans.json or re-run after start."
