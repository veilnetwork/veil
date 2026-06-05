# Monitoring Guide

> Operational reference: what to watch, why, and when to alert.  Companion to
> [OPERATIONS.md](OPERATIONS.md) (deployment) and
> [TROUBLESHOOTING.md](TROUBLESHOOTING.md) (incident response).

## Exporter Setup

Enable the Prometheus exporter in `config.toml`:

```toml
[metrics]
listen      = "tcp://127.0.0.1:9090"   # bind URI (scheme required); bind to 0.0.0.0 only behind a firewall
path        = "/metrics"          # default
auth_token  = "abcd1234..."       # optional bearer token; clients send `Authorization: Bearer …`
```

Restart the node, verify:

```bash
curl http://127.0.0.1:9090/metrics
# (with token)
curl -H "Authorization: Bearer abcd1234..." http://127.0.0.1:9090/metrics
```

Each metric is reported once per scrape, no labels other than the
implicit `instance` Prometheus injects.  All counters are monotonic
`u64`; gauges may be `f64` (Vivaldi coords) or `usize`.

## Metric Reference

Categories ordered by ops-utility.

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

When direct routing misses, the node falls back to an iterative DHT
lookup to re-resolve a transport.  These signals track mesh
fragmentation and fallback health:

| Metric | Type | Meaning | Alert if |
|--------|------|---------|----------|
| `veil_dht_fallback_triggered_total` | counter | Iterative-DHT fallbacks launched after a route miss | rising relative to traffic = direct routing degrading |
| `veil_dht_fallback_resolved_total` | counter | Fallbacks that re-resolved a usable transport | should track `triggered`; gap = unresolvable routes |
| `veil_dht_fallback_miss_total` | counter | Fallbacks that found no route | rising = routes unresolvable → mesh fragmentation |
| `veil_dht_fallback_skipped_backpressure_total` | counter | Fallbacks suppressed under backpressure | spikes = fallback being shed under load |
| `veil_dht_fallback_effective_timeout_ms` | gauge (ms) | Current adaptive fallback timeout | unstable swings = congestion / RTT instability |

### Mailbox (offline delivery)

> Mailbox depth is **not exported to Prometheus**.  The only surfaced
> signal is the `mailbox_entries` field in the admin HTTP state dump
> (`veil-cli node metrics`, or the admin HTTP `/state` JSON/text).
> There are no `veil_mailbox_*` counters or gauges.

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

A starter [`alerting.yml`](../alerting.yml) ships in the repo.  Tune
thresholds for your fleet size; the defaults assume single-host nodes
on commodity hardware.

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
        expr: veil_active_sessions / 65536 > 0.8
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

A reference dashboard JSON ships at `docs/grafana/`.  Import via Grafana
UI → "+" → Import → Upload JSON.  Key panels:

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

1. **`up{job="veil"}`** — is the node even reachable by Prometheus?
   If no — the node may be alive but admin/metrics endpoint is bound to
   a wrong interface; check `[metrics].listen` and firewall.

2. **`active_sessions`** — does it match expectations?  Drop = upstream
   peer outage or local config change.

3. **`outbound_connect_failures_total / outbound_connect_attempts_total`**
   ratio — sustained high failure ratio = DNS / firewall / bootstrap-peer
   reachability issue.

4. **`route_miss_total` rate** — high → check `node dht routing` for
   k-bucket fill, then `peers banned` for unintended bans.

5. **`ban_actions_total` rate** — spike correlates with attack;
   `veil-cli peers banned` to inspect which `node_id`s are getting
   banned and why.

For specific symptom → diagnosis → fix mapping see
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## CLI snapshot (no Prometheus)

For ad-hoc inspection without scraping:

```bash
veil-cli node metrics
# Plain-text dump of every counter/gauge — same content as /metrics
# but human-formatted.  When [metrics] is unset, prints a one-line
# hint instead of 35 zero counters.
```

For real-time tail of significant events without metrics scrape:

```bash
journalctl -fu veil-node | grep -E "WARN|ERROR|session.banned|route.discovery.miss|recursive.response.relay_dropped"
```
