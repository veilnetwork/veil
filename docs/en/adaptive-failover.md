# Adaptive failover

When traffic to a peer or destination starts failing — physical link drop,
intermediate relay crash, on-path filtering — the veil should re-route
automatically.  Three complementary mechanisms combine to give that:

1. **Multi-hop route cache** (always on).  `RouteCache` keeps up to
   `MAX_ROUTES_PER_DST = 4` `next_hop` candidates per destination ranked by
   composite score (RTT + hop count + reputation).  `lookup_all` returns the
   sorted list; `dispatch_delivery` picks the best.

2. **Fast path demotion on session close** (always on).
   When a peer session closes — clean or abnormal — the dispatcher
   immediately calls `RouteCache::demote_via(closed_peer, factor=4.0)`
   which multiplies the score of every cached route through that peer by
   4×.  This pushes them out of the ECMP / multi-path band so alternative
   `next_hop`s win on the very next `lookup_all` call.  Routes are NOT
   removed (the peer might come back); they remain as last-resort
   fallback if everything else is worse.

   Without this hook the next ROUTE_PROBE cycle (5–120 s adaptive
   interval) would be the only score-update path, so failover took tens
   of seconds.  With it: < 1 RTT.

3. **Multi-path delivery** (opt-in, off by default).  Two settings in
   `[routing]`:

       multi_path_enabled = true
       redundant_send = true

   With both ON, latency-sensitive frames (`prio ≤ multi_path_min_priority`)
   are duplicated across the top-2 paths.  Receiver deduplicates by
   `content_id`.  Costs 2× the bandwidth on the affected priorities; gains
   p99 resilience to single-path failure (no perceptible disruption when
   one path drops).

## Operator workflow

Inspect the current routing state for a destination:

```sh
veil-cli node routes <dst_node_id>
```

The header shows the active multi-path settings.  The body lists the
primary `next_hop` plus any alternatives (marked `(alt)`).  After a
session close, alts will have lower scores than the demoted-by-4 primary
within milliseconds.

## When to enable multi-path

Default OFF because it doubles bandwidth on the affected priorities.
Turn it on when:

- The deployment is bandwidth-rich (LAN / data center).
- p99 latency matters more than total cost (interactive / real-time apps).
- The peer mesh has natural redundancy (≥3 well-connected core peers per
  region) so the top-2 paths are genuinely independent.

Don't bother on a 3-node test network: the redundant-send path is just
the same single peer twice, no benefit.

## Verifying

```sh
# Active config visible in the routes header:
veil-cli node routes
# → [routing config] multi-path: ON (paths=2, prio≤1)  |  redundant-send: ON  |  ecmp_band=0.20

# Drill into a specific destination after pulling its session:
veil-cli node routes 4f2a... | head -10
# Watch: primary score should jump 4× the moment the session closes,
# the (alt) entries become the effective best path.
```
