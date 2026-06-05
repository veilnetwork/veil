#!/bin/bash
# Phase 6.50.b chaos-ban cycler — exercise the iterative-DHT fallback in
# production by banning а random active session for 600 s every 600 s.
#
# Each cycle:
#   1. Sample one active peer node_id (full 64-hex via `sessions list -v`).
#   2. `sessions ban <peer>` — drops the direct session.  When chat_node
#      next attempts an `app.send` к that peer, dispatcher's
#      DELIVERY_FORWARD path hits route-cache, RouteRequest flood (TTL=7)
#      tries to recover, eventually exhausts retries, the new
#      iterative-DHT fallback fires а RecursiveQuery(FIND_NODE), gets
#      back а signed response, and route_cache repopulates с а multi-hop
#      relay path.  Empirically this should bump
#      `veil_dht_fallback_triggered_total` и (assuming healthy mesh)
#      `veil_dht_fallback_resolved_total`.
#   3. Sleep 600 s.
#   4. `sessions unban <peer>` — direct session re-establishes.
#   5. Pick а NEW random peer (avoiding the just-unbanned one) и repeat.
#
# Cleanup: on SIGTERM/EXIT, unban whatever peer is currently banned so
# the cluster returns to clean state when the operator stops the service.
#
# Self-protect: never bans bootstrap peers (b1/b2/b3) от а bootstrap host
# itself — would lose the only way back if something goes wrong.

set -euo pipefail

CFG=/var/lib/veil/node.toml
CLI=/usr/local/bin/veil-cli
# Ban duration picked uniformly at random per cycle from [PERIOD_MIN, PERIOD_MAX]
# seconds.  Avoids the synchronised-cycle artefact of the fixed-600s version
# where all 8 hosts banned at multiples of 600 s и unbanned simultaneously,
# producing periodic cluster-wide ban storms.  Each cycle also adds а 1-second
# gap between unban and the next ban (i.e. real cycle = N + 1).
PERIOD_MIN=600
PERIOD_MAX=1200
LOG_PREFIX="$(date -u +%FT%TZ) chaos-ban"

# Bootstrap node_ids — NEVER ban these.  Banning а bootstrap kills DHT
# discovery for the host that did it; if 4+ hosts ban the same bootstrap
# at once the whole cluster fragments (observed 2026-05-12 cascade).
BOOTSTRAP_IDS=(
    "5dffa7a4f3d942c467e5373da13f978118987f8a8a5a4a87fe34b8fdd43c5ac3"  # b1
    "256bc205ef4200a70fb88eac7aedf5c2a7db559f587874030c2db565d39b8ad0"  # b2
    "eab61fcea32fba4ebf7dabe61047cdaf37513a94e7e99e5c16b0a87a8c691c7a"  # b3
)

current_banned=""
last_banned=""

cleanup() {
    if [ -n "$current_banned" ]; then
        echo "$LOG_PREFIX cleanup: unbanning $current_banned"
        "$CLI" --config "$CFG" sessions unban "$current_banned" 2>&1 || true
    fi
    exit 0
}
trap cleanup EXIT INT TERM

echo "$LOG_PREFIX started — period=[${PERIOD_MIN},${PERIOD_MAX}]s (random per cycle, +1s gap)"

while true; do
    # Pull active peers, drop the header line, extract full node_id column,
    # exclude bootstrap node_ids (banning them fragments the cluster) AND
    # the just-unbanned peer (avoid same-peer re-ban two cycles in а row),
    # shuffle, pick one.
    exclude_pattern="^(${last_banned}"
    for bid in "${BOOTSTRAP_IDS[@]}"; do
        exclude_pattern="${exclude_pattern}|${bid}"
    done
    exclude_pattern="${exclude_pattern})\$"

    peers=$(
        "$CLI" --config "$CFG" sessions list -v 2>/dev/null \
        | awk 'NR>1 && $2 ~ /^[0-9a-f]{64}$/ {print $2}' \
        | grep -Ev "$exclude_pattern" || true
    )

    if [ -z "$peers" ]; then
        echo "$(date -u +%FT%TZ) chaos-ban: no eligible peers (sessions list empty?), sleeping 60s"
        sleep 60
        continue
    fi

    # `shuf` lives в coreutils on Ubuntu 24.04.
    target=$(echo "$peers" | shuf -n 1)
    current_banned="$target"

    # Random ban duration per cycle, uniform on [PERIOD_MIN, PERIOD_MAX].
    # $RANDOM is 0..32767 — span here is <1000 so modulo skew is negligible.
    span=$((PERIOD_MAX - PERIOD_MIN + 1))
    period=$((PERIOD_MIN + RANDOM % span))

    echo "$(date -u +%FT%TZ) chaos-ban: BAN ${target:0:12}… for ${period}s"
    if ! "$CLI" --config "$CFG" sessions ban "$target"; then
        echo "$(date -u +%FT%TZ) chaos-ban: ban failed for $target — skipping cycle"
        current_banned=""
        sleep 60
        continue
    fi

    sleep "$period"

    echo "$(date -u +%FT%TZ) chaos-ban: UNBAN ${target:0:12}…"
    "$CLI" --config "$CFG" sessions unban "$target" 2>&1 || true
    last_banned="$target"
    current_banned=""

    # +1s gap before the next BAN (user-requested: "через N+1 секунд повторяем")
    # gives sessions а brief breather to re-establish before the next disruption.
    sleep 1
done
