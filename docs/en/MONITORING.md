# Monitoring Guide

> An operator's reference for watching a running node: what to watch, why it
> matters, and when to raise an alert. Read it alongside
> [OPERATIONS.md](OPERATIONS.md) (deployment) and
> [TROUBLESHOOTING.md](TROUBLESHOOTING.md) (incident response).

## Exporter Setup

A node reports its health as **metrics** — named numbers like "active sessions"
or "failed dials" that you sample over time. Veil exposes them in the format
[Prometheus](https://prometheus.io) reads. Prometheus is a tool that collects
metrics from many machines and stores them so you can chart and alert on them.

To turn the exporter on, add this to `config.toml`:

```toml
[metrics]
listen      = "tcp://127.0.0.1:9090"   # bind URI (scheme required); bind to 0.0.0.0 only behind a firewall
path        = "/metrics"          # default
auth_token  = "abcd1234..."       # optional bearer token; clients send `Authorization: Bearer …`
```

Restart the node, then check that the endpoint answers:

```bash
curl http://127.0.0.1:9090/metrics
# (with token)
curl -H "Authorization: Bearer abcd1234..." http://127.0.0.1:9090/metrics
```

A *scrape* is one read of the endpoint by Prometheus. Each metric appears once
per scrape. The only label attached is `instance`, which Prometheus adds itself
to mark which node the reading came from. Two kinds of metric show up below. A
**counter** only ever climbs — it counts events since startup (here, always a
`u64`). A **gauge** is a current value that can rise or fall, like a fuel gauge;
gauges may be `f64` (Vivaldi coordinates) or `usize`.

## Metric Reference

The sections below are ordered roughly by how often you'll reach for them.

### Liveness / capacity

| Metric | Type | Meaning | Alert if |
|--------|------|---------|----------|
| `veil_active_sessions` | gauge | OVL1 sessions currently established | `> 0.8 × max_concurrent` for 5 m |
| `veil_configured_peers` | gauge | Number of `[[peers]]` entries | sudden drop = config-reload anomaly |
| `veil_inbound_sessions_total` | counter | Cumulative inbound handshakes | rate spike = scan / abuse |
| `veil_outbound_connect_attempts_total` | counter | Cumulative outbound dial attempts | rate spike = peer churn / network instability |
| `veil_outbound_connect_failures_total` | counter | Failed outbound dials | failure-ratio > 50 % over 10 m = upstream peer down |
| `veil_session_handshake_failures_total` | counter | Inbound handshake errors (auth / cipher / proto) | rate spike = scanner or version-skew |

### Routing (the most-watched section)

| Metric | Type | Meaning | Alert if |
|--------|------|---------|----------|
| `veil_route_miss_total` | counter | DELIVERY frames with no route to dst | `> 100/s` for 5 m → mesh fragmentation; check DHT |
| `veil_discovery_triggered_total` | counter | Reactive route discovery (RecursiveQuery) launched | sudden spike correlates with route_miss spike |
| `veil_route_recovery_total` | counter | Successful re-routes after primary hop death | high = unstable upstream peer |
| `veil_route_selection_avg_rtt_ms` | gauge (ms) | Mean RTT of selected next-hop | rising trend = network congestion |
| `veil_network_reachability_score` | gauge (0-100) | Composite reachability metric | `< 50` for 5 m = isolation alarm |

### DHT health

| Metric | Type | Meaning | Alert if |
|--------|------|---------|----------|
| `veil_dht_store_total` | counter | DHT STORE operations served | sudden drop to 0 = mesh isolation |
| `veil_dht_lookup_total` | counter | DHT FIND_VALUE / FIND_NODE served | drop = peers gone |
| `veil_storage_evictions_total` | counter | DHT entries evicted by capacity | high = `max_store_entries` too low |

#### Iterative-DHT fallback (route recovery)

When the node can't route a frame directly, it tries a backup path: an iterative
DHT lookup that hunts for a fresh transport to the destination. (Iterative means
the node walks the DHT hop by hop instead of relying on a cached answer.) These
metrics show how often that backup runs and whether it succeeds — a good early
read on mesh fragmentation:

| Metric | Type | Meaning | Alert if |
|--------|------|---------|----------|
| `veil_dht_fallback_triggered_total` | counter | Iterative-DHT fallbacks launched after a route miss | rising relative to traffic = direct routing degrading |
| `veil_dht_fallback_resolved_total` | counter | Fallbacks that re-resolved a usable transport | should track `triggered`; gap = unresolvable routes |
| `veil_dht_fallback_miss_total` | counter | Fallbacks that found no route | rising = routes unresolvable → mesh fragmentation |
| `veil_dht_fallback_skipped_backpressure_total` | counter | Fallbacks suppressed under backpressure | spikes = fallback being shed under load |
| `veil_dht_fallback_effective_timeout_ms` | gauge (ms) | Current adaptive fallback timeout | unstable swings = congestion / RTT instability |

### Mailbox (offline delivery)

The mailbox holds messages for recipients who are currently offline, to be
handed over once they reconnect.

> Mailbox depth is **not exported to Prometheus**. The one place it shows up is
> the `mailbox_entries` field in the admin HTTP state dump (run
> `veil-cli node metrics`, or read the admin HTTP `/state` endpoint as JSON or
> text). There are no `veil_mailbox_*` counters or gauges.

| Field | Source | Meaning | Watch for |
|-------|--------|---------|-----------|
| `mailbox_entries` | admin HTTP state dump (JSON/text), not Prometheus | Envelopes currently held in the local mailbox store | sustained growth = recipients staying offline / backlog accumulating |

### Congestion / abuse

| Metric | Type | Meaning | Alert if |
|--------|------|---------|----------|
| `veil_rate_limit_drops_total` | counter | Inbound frames dropped by per-peer rate limiter | `> 10/s` for 2 m → DoS or misconfigured peer |
| `veil_backpressure_received_total` | counter | Backpressure signals received from peers | ramp-up = our outbound is congesting downstream |
| `veil_unknown_origin_gossip_rejected_total` | counter | RouteAnnounce/RouteWithdraw frames rejected because `via_node_id` did not match the transport sender (via-spoof) | sustained = malicious relay or version-skew |
| `veil_exit_proxy_dest_denied_total` | counter | Exit-proxy CONNECT targets denied (loopback / private / link-local / metadata) | spike = SSRF-style probing |
| `veil_socks5_accepts_throttled_total` | counter | Inbound SOCKS5 accepts throttled (`MAX_SOCKS_CONCURRENT` saturated) | sustained = overload or abuse |
| `veil_ban_actions_total` | counter | Manual or auto bans applied | spike = under attack |
| `veil_session_tx_drops_total` | counter | Outbound frames dropped (TX queue full) | `> 50/s` for 5 m = overload |
| `veil_session_outbox_drops_total` | counter | Outbox channel saturation drops | similar |
| `veil_ipc_delivery_drops_total` | counter | Local-app channel saturation | app not draining its IPC |

### E2E / crypto

| Metric | Type | Meaning | Alert if |
|--------|------|---------|----------|
| `veil_decrypt_failures_total` | counter | E2E AEAD decrypt errors | sustained = key drift / replay attempt |
| `mlkem_key_age_secs` (admin RPC only) | gauge | Age of local ML-KEM keypair (file mtime) | `> 30 d` → schedule rotation. **Not exposed via Prometheus** — query via `veil-cli node metrics`. |

### Vivaldi coordinates (network distance estimation)

| Metric | Type | Meaning | Alert if |
|--------|------|---------|----------|
| `veil_vivaldi_prediction_error_ms` | gauge (ms) | Mean Vivaldi prediction error | `> 100 ms` → algorithm not converging; check time-sync |
| `veil_vivaldi_coord_x/y/height/error` | gauge | Raw coord state | informational; for debugging |

### Real-time (QUIC realtime)

| Metric | Type | Meaning | Alert if |
|--------|------|---------|----------|
| `veil_rt_frames_rx_total` | counter | Realtime frames received | flat = call setup broken |
| `veil_rt_frames_tx_total` | counter | Realtime frames sent | mismatch with rx → asymmetric loss |
| `veil_rt_seq_gaps_total` | counter | Out-of-order / dropped realtime frames | high = jitter problem |

## Suggested Alert Set

The repo ships a starter [`alerting.yml`](../alerting.yml) you can drop into
Prometheus. Treat the thresholds as a starting point and tune them to your fleet
size — the defaults assume single-host nodes on ordinary hardware.

```yaml
groups:
  - name: veil-critical
    rules:
      - alert: NodeDown
        expr: up{job="veil"} == 0
        for: 1m
        labels: { severity: critical }
        annotations:
          summary: "Veil node {{ $labels.instance }} unreachable"

      - alert: SessionCapacityHigh
        expr: veil_active_sessions / 1000 > 0.8
        for: 5m
        labels: { severity: warning }

      - alert: HighRouteMissRate
        expr: rate(veil_route_miss_total[5m]) > 100
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.instance }} route_miss > 100/s — mesh fragmentation suspected"

      - alert: BackpressureStorm
        expr: rate(veil_rate_limit_drops_total[5m]) > 10
        for: 2m
        labels: { severity: critical }

      - alert: BanStorm
        expr: rate(veil_ban_actions_total[5m]) > 5
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "{{ $labels.instance }} banning > 5 peers/s — under attack or misconfig"

      - alert: NetworkIsolated
        expr: veil_network_reachability_score < 50
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "{{ $labels.instance }} reachability score < 50 — node may be isolated"

      # NOTE: ML-KEM key-age is not currently exposed via Prometheus —
      # only via the admin RPC `veil-cli node metrics` snapshot's
      # `mlkem_key_age_secs` field. Below alert kept as a template
      # for when the metric ships as a Prometheus gauge.
      # - alert: MlKemKeyTooOld
      #   expr: veil_mlkem_key_age_secs > 2592000   # 30 days
      #   for: 1h
      #   labels: { severity: info }
      #   annotations:
      #     summary: "{{ $labels.instance }} ML-KEM key > 30 days — schedule rotation"
```

## Grafana Dashboard

[Grafana](https://grafana.com) draws metrics as charts on a *dashboard* — a
single screen of graphs. A ready-made dashboard ships as JSON at
`docs/grafana/`. To load it, open the Grafana UI → "+" → Import → Upload JSON.
The key panels:

1. **Connectivity** — `active_sessions`, `configured_peers`, reachability
   gauge, outbound failure ratio.
2. **Routing health** — route_miss rate, discovery_triggered rate,
   route_recovery rate, average RTT, route-cache hit ratio (derived).
3. **DHT** — store/lookup rate, evictions rate, contacts in routing
   table (from `node dht routing | wc -l` exec dashboard, or via
   future export).
4. **Mailbox** — `mailbox_entries` depth from the admin HTTP state
   dump (not Prometheus; via an exec/JSON datasource panel).
5. **Abuse** — rate-limit drops, ban actions, unknown-origin gossip
   rejects, exit-proxy denials, SOCKS5 accept throttles.
6. **Crypto / E2E** — decrypt failures rate, ML-KEM key age.

## What to look at first when something is wrong

Work down this list in order. Each step rules out a common cause.

1. **`up{job="veil"}`** — can Prometheus reach the node at all? If not, the node
   may well be alive while its metrics endpoint is bound to the wrong interface.
   Check `[metrics].listen` and your firewall.

2. **`active_sessions`** — does the count match what you expect? A drop usually
   means an upstream peer went down, or someone changed the local config.

3. **`outbound_connect_failures_total / outbound_connect_attempts_total`** — the
   ratio of these two. If it stays high, the node can't reach the outside world:
   suspect DNS, the firewall, or an unreachable bootstrap peer.

4. **`route_miss_total` rate** — if it's high, check `node dht routing` to see
   how full the k-buckets are, then `peers banned` in case you've banned
   something by accident.

5. **`ban_actions_total` rate** — a spike tracks an attack. Run
   `veil-cli peers banned` to see which `node_id`s are being banned, and why.

For a full symptom → diagnosis → fix walkthrough, see
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## CLI snapshot (no Prometheus)

When you just want a quick look and don't have Prometheus set up:

```bash
veil-cli node metrics
# Plain-text dump of every counter/gauge — same content as /metrics
# but human-formatted.  When [metrics] is unset, prints a one-line
# hint instead of 35 zero counters.
```

To follow significant events live, without metrics at all, tail the log:

```bash
journalctl -fu veil-node | grep -E "WARN|ERROR|session.banned|route.discovery.miss|recursive.response.relay_dropped"
```
