# Adaptive failover

A path to a peer or destination can fail at any moment. The physical link
drops. An intermediate relay crashes. Someone filters the traffic on the wire.
When that happens, Veil should re-route on its own — that automatic re-routing
is what we call *failover*. Three mechanisms work together to deliver it.

1. **Multi-hop route cache** (always on). `RouteCache` keeps up to
   `MAX_ROUTES_PER_DST = 4` `next_hop` candidates for each destination. A
   `next_hop` is the immediate peer a frame is handed to on its way there. The
   cache ranks the candidates by a composite score that blends round-trip time
   (RTT), hop count, and peer reputation. `lookup_all` returns the sorted list;
   `dispatch_delivery` picks the best one.

2. **Fast path demotion on session close** (always on).
   When a session with a peer closes — cleanly or abnormally — the dispatcher
   immediately calls `RouteCache::demote_via(closed_peer, factor=4.0)`. That
   multiplies the score of every cached route through that peer by 4×. The
   penalty pushes those routes out of the ECMP / multi-path band, so the
   alternative `next_hop`s win on the very next `lookup_all` call. (ECMP, equal-
   cost multi-path, is the set of routes close enough in score to be treated as
   equally good.) The routes are NOT deleted — the peer might come back. They
   stay as a last-resort fallback for when everything else is worse.

   Without this hook, the only thing that updates scores is the next
   ROUTE_PROBE cycle. A probe is a periodic measurement packet, and the
   cycle runs on a 5–120 s adaptive interval — so failover took tens of
   seconds. With the hook it takes less than one RTT.

3. **Multi-path delivery** (opt-in, off by default). Two settings in
   `[routing]` control it:

       multi_path_enabled = true
       redundant_send = true

   With both ON, latency-sensitive frames (those with
   `prio ≤ multi_path_min_priority`) are sent twice — once down each of the
   top-2 paths. The receiver throws away the duplicate by matching on
   `content_id`. This costs 2× the bandwidth on the affected priorities. In
   return you get p99 resilience to single-path failure: when one path drops,
   the other already carried the frame, so there is no perceptible disruption.

## Operator workflow

Inspect the current routing state for a destination:

```sh
veil-cli node routes <dst_node_id>
```

The header shows the active multi-path settings. The body lists the primary
`next_hop` plus any alternatives, each marked `(alt)`. After a session closes,
the demoted primary carries its 4× penalty, so within milliseconds the alts
score lower than it — and become the path Veil actually uses.

## When to enable multi-path

It is OFF by default because it doubles bandwidth on the affected priorities.
Turn it on when all of these hold:

- The deployment is bandwidth-rich — a LAN or a data center.
- p99 latency matters more than total cost. Think interactive or real-time
  apps.
- The peer mesh has natural redundancy: at least 3 well-connected core peers
  per region, so the top-2 paths are genuinely independent.

Don't bother on a 3-node test network. There the two "paths" are the same
single peer twice, so you gain nothing.

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
