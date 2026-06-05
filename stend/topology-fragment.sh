#!/usr/bin/env bash
# Force this topology by banning the 5 unwanted pairs:
#
#         node1
#         /   \
#      node2  node5
#        |      |
#      node3 - node4
#
# Allowed (5 pairs):  1-2, 1-5, 2-3, 3-4, 4-5
# Blocked (5 pairs):  1-3, 1-4, 2-4, 2-5, 3-5
#
# `peers ban` is symmetric on the wire (handshake check happens both sides),
# but applying it on BOTH ends prevents either side from initiating reconnect
# after one side ban-rejects.  Existing sessions are killed via `sessions kill`.
#
# Re-run safely — `peers ban` is idempotent.
# To restore: ./topology-restore.sh

set -euo pipefail
cd "$(dirname "$0")"

CLI=./veil-cli

# Discover node IDs from configs (resilient to identity rotation between runs).
ID1=$(grep -m1 '^node_id' node1/config.toml | cut -d'"' -f2)
ID2=$(grep -m1 '^node_id' node2/config.toml | cut -d'"' -f2)
ID3=$(grep -m1 '^node_id' node3/config.toml | cut -d'"' -f2)
ID4=$(grep -m1 '^node_id' node4/config.toml | cut -d'"' -f2)
ID5=$(grep -m1 '^node_id' node5/config.toml | cut -d'"' -f2)

declare -A IDS=( [1]=$ID1 [2]=$ID2 [3]=$ID3 [4]=$ID4 [5]=$ID5 )

# Pairs to BLOCK (a < b convention).
BLOCKED=(
  "1 3"
  "1 4"
  "2 4"
  "2 5"
  "3 5"
)

# Sanity: all 5 admin sockets must be live.
for n in 1 2 3 4 5; do
  if [[ ! -S "node$n/config.sock" ]]; then
    echo "ERROR: node$n admin socket not found — start stend first." >&2
    exit 1
  fi
done

echo "── Step 1/2: applying peers ban (symmetric, both ends per pair) ──"
# Epic 467.1 fix: `peers ban` now also tears down active sessions to the
# banned peer on both sides — separate `sessions kill` is no longer needed.
for pair in "${BLOCKED[@]}"; do
  read -r a b <<<"$pair"
  echo "  ban node$a ↔ node$b"
  $CLI -c node$a/config.toml peers ban "${IDS[$b]}" >/dev/null
  $CLI -c node$b/config.toml peers ban "${IDS[$a]}" >/dev/null
done

echo "── Step 2/2: verification ──"
echo "Remaining sessions per node (header line excluded):"
for n in 1 2 3 4 5; do
  # `sessions list` is TSV with a header.  Each data row starts with '0x'.
  count=$($CLI -c node$n/config.toml sessions list 2>/dev/null | grep -c "^0x" || echo 0)
  bans=$($CLI -c node$n/config.toml peers banned 2>/dev/null | grep -c "^[0-9a-f]\{64\}" || echo 0)
  echo "  node$n: $count active sessions, $bans bans"
done

cat <<EOF

✓ Topology fragmented.  Expected stable state (after ~30s of churn):
  node1: 2 sessions  (node2, node5)
  node2: 2 sessions  (node1, node3)
  node3: 2 sessions  (node2, node4)
  node4: 2 sessions  (node3, node5)
  node5: 2 sessions  (node1, node4)

To exercise FORWARD: send a chat message from node1 → node3.
The path must be node1 → node2 → node3 (no direct link).
Watch node2 logs for 'delivery.forward' to confirm relay.

To restore full mesh:  ./topology-restore.sh
EOF
