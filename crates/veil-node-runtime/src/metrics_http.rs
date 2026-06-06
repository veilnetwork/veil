//! HTTP metrics exporter for Prometheus scraping.
//!
//! Accepts TCP connections on the configured metrics endpoint and serves:
//! `GET <metrics_path>` — Prometheus text format
//! `GET /admin/health` — JSON health summary
//! `GET /admin/state/dump` — YAML runtime state snapshot

use std::sync::Arc;
use std::time::Duration;
use veil_util::lock;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Semaphore, watch},
    task::JoinHandle,
};

use veil_transport::{
    BoxIoStream, TransportConnection, TransportContext, TransportRegistry, TransportUri,
};

use crate::error::{NodeError, Result};
use veil_observability::{NodeLogger, NodeMetrics};

// ── audit hardening constants ──────────────────────────────
//
// Pre-fix the metrics HTTP server had no read timeout, no concurrent-
// request cap, and optionally no auth (docs/MONITORING.md promised
// `auth_token` but `MetricsConfig` lacked the field). Now:
// * Reads are bounded by [`READ_TIMEOUT`] — slow-loris attackers cannot
// tie up a tokio task indefinitely.
// * Concurrent in-flight serve_connection futures capped by a
// [`Semaphore`] of size [`MAX_CONCURRENT_REQUESTS`] — bursty
// reconnaissance that would otherwise spawn unbounded tasks now
// queues / drops.
// * When `auth_token` is configured, every request must carry a
// matching bearer header (constant-time comparison).
//
// Defaults are conservative; operators that need higher throughput can
// adjust by code change. These values match the doc-published
// expectations.

/// HTTP request read deadline. Real Prometheus scrapes finish requests
/// within a few milliseconds; 5 s is generous and still tight enough to
/// shed slow-loris.
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Max concurrent in-flight HTTP serve futures. When the cap is hit
/// new accepts are dropped (TCP connection closed without serve) so
/// reconnaissance that would spawn a task per connect cannot exhaust
/// memory. 16 covers a typical Prometheus scrape interval (15 s) with
/// healthy headroom.
pub const MAX_CONCURRENT_REQUESTS: usize = 16;

// ── RuntimeSummary ────────────────────────────────────────────────────────────

/// Snapshot of runtime state for health / dump endpoints.
/// All fields are PII-safe (no keys or nonces).
#[derive(Debug, Clone, Default)]
pub struct RuntimeSummary {
    pub role: String,
    pub active_sessions: u64,
    pub mailbox_entries: usize,
    pub discovery_entries: usize,
    pub dht_keys: usize,
    pub neighbor_count: usize,
    pub route_cache_size: usize,
    pub banned_peers: usize,
    pub uptime_secs: u64,
}

// ── spawn_metrics_http ────────────────────────────────────────────────────────

/// Bind the metrics listener and start the accept loop.
///
/// Returns the local address string (for state/logging) and a `JoinHandle`
/// for the background task. The task shuts down cleanly when `shutdown_rx`
/// signals.
///
/// audit: `auth_token` (when `Some`) is constant-time-compared
/// against every request's `Authorization: Bearer …` header. Requests
/// without the matching header get a `401 Unauthorized`. When `None`, all
/// endpoints are unauthenticated (intended for loopback binds).
/// state-size probe. Cheap holder of Arc references to
/// the daemon's in-memory data-structure roots; the metrics HTTP server
/// snapshots their `.len` / byte-count gauges at /metrics scrape time
/// and appends Prometheus lines. Operator visibility into which structs
/// hold the resident heap when chaos-ban-style load creates transient
/// teardown buffers (route_cache demotes, session_outbox backlog
/// chunk_reassembler in-flight, etc.).
///
/// Cloning is cheap (Arc bumps). All accessors take short Mutex locks —
/// must not hold across.await, must not call from hot path. Scrape
/// path is fine: low frequency, bounded work.
#[derive(Clone)]
pub struct RuntimeStateProbe {
    pub live_sessions: Arc<
        std::sync::Mutex<
            std::collections::BTreeMap<crate::types::LinkId, crate::types::SessionInfo>,
        >,
    >,
    pub session_tx_registry: Arc<std::sync::RwLock<veil_session::SessionTxRegistry>>,
    pub session_outbox: Arc<veil_session::SessionOutbox>,
    pub ban_list: Arc<std::sync::Mutex<veil_abuse::BanList>>,
    pub dispatcher: Arc<veil_dispatcher::FrameDispatcher>,
    pub discovered_peers_cache: Arc<std::sync::Mutex<veil_bootstrap::DiscoveredPeerCache>>,
}

impl RuntimeStateProbe {
    /// Render a snapshot as Prometheus exposition lines (appended at
    /// scrape time to the main metrics body). Each gauge name uses the
    /// `veil_state_*` namespace to visually separate "runtime state
    /// gauges" from cumulative counters.
    pub fn render_prometheus(&self) -> String {
        let live_sessions = self.live_sessions.lock().map(|g| g.len()).unwrap_or(0);
        let (tx_registry, tx_queue_total, tx_queue_est_bytes) = self
            .session_tx_registry
            .write()
            .map(|g| (g.len(), g.total_queued(), g.estimated_memory()))
            .unwrap_or((0, 0, 0));
        let outbox = self.session_outbox.len();
        let bans = self.ban_list.lock().map(|g| g.len()).unwrap_or(0);
        let dht_contacts = self.dispatcher.dht.routing_table_node_ids().len();
        let route_cache_dst = self
            .dispatcher
            .route_cache
            .read()
            .map(|g| g.destination_count())
            .unwrap_or(0);
        let route_cache_routes = self
            .dispatcher
            .route_cache
            .read()
            .map(|g| g.total_routes())
            .unwrap_or(0);
        let chunk_transfers = self
            .dispatcher
            .chunk_reassembler
            .lock()
            .map(|g| g.transfer_count())
            .unwrap_or(0);
        let chunk_bytes = self
            .dispatcher
            .chunk_reassembler
            .lock()
            .map(|g| g.buffered_bytes())
            .unwrap_or(0);
        let pending_recursive = self
            .dispatcher
            .pending_recursive
            .lock()
            .map(|g| g.len())
            .unwrap_or(0);
        let peer_observed = self
            .dispatcher
            .peer_observed_addrs
            .read()
            .map(|g| g.len())
            .unwrap_or(0);
        let relay_tunnels = self
            .dispatcher
            .relay_tunnels
            .lock()
            .map(|g| g.len())
            .unwrap_or(0);
        let peer_pubkeys = self
            .dispatcher
            .crypto
            .peer_pubkeys
            .lock()
            .map(|g| g.map_len())
            .unwrap_or(0);
        let discovered_peers = self
            .discovered_peers_cache
            .lock()
            .map(|g| g.len())
            .unwrap_or(0);
        // DHT sub-stores: store (value-store entries), transport_cache
        // lookup_cache — all accessible through KademliaService accessors.
        let dht_store = self.dispatcher.dht.store_len();
        let dht_transport_cache = self.dispatcher.dht.transport_cache_len();
        let dht_lookup_cache = self.dispatcher.dht.lookup_cache_len();

        format!(
            "# HELP veil_state_live_sessions Number of live transport sessions\n\
             # TYPE veil_state_live_sessions gauge\n\
             veil_state_live_sessions {live_sessions}\n\
             # HELP veil_state_session_tx_registry Number of peers with registered tx senders\n\
             # TYPE veil_state_session_tx_registry gauge\n\
             veil_state_session_tx_registry {tx_registry}\n\
             # HELP veil_state_session_tx_queue_total Frames currently queued across all per-peer mpsc senders\n\
             # TYPE veil_state_session_tx_queue_total gauge\n\
             veil_state_session_tx_queue_total {tx_queue_total}\n\
             # HELP veil_state_session_tx_queue_estimated_bytes Worst-case bytes buffered in per-peer mpsc queues (capacity × peers × 16 KiB avg-frame estimate; real frames range from 64 B keepalives to 60 KiB DATA)\n\
             # TYPE veil_state_session_tx_queue_estimated_bytes gauge\n\
             veil_state_session_tx_queue_estimated_bytes {tx_queue_est_bytes}\n\
             # HELP veil_state_session_outbox Number of peers with registered RPC outboxes\n\
             # TYPE veil_state_session_outbox gauge\n\
             veil_state_session_outbox {outbox}\n\
             # HELP veil_state_ban_list Number of banned peers\n\
             # TYPE veil_state_ban_list gauge\n\
             veil_state_ban_list {bans}\n\
             # HELP veil_state_dht_routing_contacts Contacts in DHT routing table\n\
             # TYPE veil_state_dht_routing_contacts gauge\n\
             veil_state_dht_routing_contacts {dht_contacts}\n\
             # HELP veil_state_route_cache_destinations Distinct destinations in route cache\n\
             # TYPE veil_state_route_cache_destinations gauge\n\
             veil_state_route_cache_destinations {route_cache_dst}\n\
             # HELP veil_state_route_cache_routes Total (dst,route) pairs across all destinations\n\
             # TYPE veil_state_route_cache_routes gauge\n\
             veil_state_route_cache_routes {route_cache_routes}\n\
             # HELP veil_state_chunk_reassembler_transfers In-progress chunked transfers\n\
             # TYPE veil_state_chunk_reassembler_transfers gauge\n\
             veil_state_chunk_reassembler_transfers {chunk_transfers}\n\
             # HELP veil_state_chunk_reassembler_bytes Bytes buffered in chunked transfers\n\
             # TYPE veil_state_chunk_reassembler_bytes gauge\n\
             veil_state_chunk_reassembler_bytes {chunk_bytes}\n\
             # HELP veil_state_pending_recursive DHT recursive-query correlator entries\n\
             # TYPE veil_state_pending_recursive gauge\n\
             veil_state_pending_recursive {pending_recursive}\n\
             # HELP veil_state_peer_observed_addrs Observed remote addresses per peer\n\
             # TYPE veil_state_peer_observed_addrs gauge\n\
             veil_state_peer_observed_addrs {peer_observed}\n\
             # HELP veil_state_relay_tunnels Active relay-tunnel bindings\n\
             # TYPE veil_state_relay_tunnels gauge\n\
             veil_state_relay_tunnels {relay_tunnels}\n\
             # HELP veil_state_peer_pubkeys Cached peer public keys (LRU)\n\
             # TYPE veil_state_peer_pubkeys gauge\n\
             veil_state_peer_pubkeys {peer_pubkeys}\n\
             # HELP veil_state_discovered_peers Discovered-peer cache entries\n\
             # TYPE veil_state_discovered_peers gauge\n\
             veil_state_discovered_peers {discovered_peers}\n\
             # HELP veil_state_dht_store DHT value-store entries (replicated keys)\n\
             # TYPE veil_state_dht_store gauge\n\
             veil_state_dht_store {dht_store}\n\
             # HELP veil_state_dht_transport_cache Resolved-transport announcements cached\n\
             # TYPE veil_state_dht_transport_cache gauge\n\
             veil_state_dht_transport_cache {dht_transport_cache}\n\
             # HELP veil_state_dht_lookup_cache In-flight DHT iterative-lookup entries\n\
             # TYPE veil_state_dht_lookup_cache gauge\n\
             veil_state_dht_lookup_cache {dht_lookup_cache}\n",
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn spawn_metrics_http(
    registry: &Arc<TransportRegistry>,
    transport_ctx: Arc<TransportContext>,
    metrics: Arc<NodeMetrics>,
    summary: Arc<std::sync::Mutex<RuntimeSummary>>,
    listen_uri: &str,
    metrics_path: &str,
    auth_token: Option<String>,
    allow_unauthenticated_remote: bool,
    logger: Arc<NodeLogger>,
    shutdown_rx: watch::Receiver<bool>,
    state_probe: RuntimeStateProbe,
) -> Result<(String, JoinHandle<()>)> {
    let uri = TransportUri::parse(listen_uri)?;

    // Non-loopback bind without auth_token publishes role / sessions /
    // mailbox / dht state to the entire network. Behaviour:
    //
    // * `allow_unauthenticated_remote = false` (default) → fail-closed:
    //   refuse to spawn the listener. The operator must either bind to
    //   loopback, set a bearer `auth_token`, OR set the explicit opt-in
    //   flag below if their deployment has a meaningful network boundary
    //   (firewall / Tailscale / VPN) protecting the metrics port.
    //
    // * `allow_unauthenticated_remote = true` → warn-only: keep prior
    //   behaviour, log loudly so accidental flips show in startup logs.
    //   Use this for testnet / homelab where Prometheus runs outside
    //   loopback but the operator owns the network path.
    if auth_token.is_none() && !is_loopback_listen(listen_uri) {
        if !allow_unauthenticated_remote {
            return Err(NodeError::Config(veil_cfg::ConfigError::ValidationFailed(
                format!(
                    "metrics.listen={listen_uri} is non-loopback and auth_token \
                     is not set. /admin/state/dump would expose role/sessions/\
                     mailbox/dht state to anyone who reaches the port. Either:\n\
                     (a) bind to 127.0.0.1 (loopback only), OR\n\
                     (b) set `auth_token` in `[metrics]` config (bearer auth), OR\n\
                     (c) set `allow_unauthenticated_remote_metrics = true` if \
                     your network is firewalled/Tailscale-scoped."
                ),
            )));
        }
        logger.warn(
            "metrics.unauthenticated_remote",
            format!(
                "metrics.listen={listen_uri} but auth_token is not set; opt-in via \
                 `allow_unauthenticated_remote_metrics = true` accepted. \
                 /admin/state/dump exposes role/sessions/mailbox/dht state to \
                 any host that can reach the port — ensure your firewall / \
                 Tailscale scope is correct."
            ),
        );
    }

    let listener = registry.bind(&uri, transport_ctx).await?;
    let local_addr = listener.local_addr();

    let path = metrics_path.to_owned();
    let mut shutdown_rx = shutdown_rx;
    let auth_token = Arc::new(auth_token);
    let request_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS));
    let handle = tokio::spawn(async move {
        let listener = listener;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                accepted = listener.accept() => match accepted {
                    Ok(connection) => {
                        // cap concurrent in-flight requests.
                        // `try_acquire_owned` drops the connection if we
                        // are already at MAX_CONCURRENT_REQUESTS — better
                        // than queueing accepts (would let memory grow on
                        // sustained scrape-DoS).
                        let permit = match request_slots.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                drop(connection);
                                continue;
                            }
                        };
                        let metrics = metrics.clone();
                        let summary = summary.clone();
                        let path = path.clone();
                        let logger = logger.clone();
                        let auth = Arc::clone(&auth_token);
                        let probe = state_probe.clone();
                        tokio::spawn(async move {
                            let _ = serve_connection(connection, metrics, summary, path, auth, logger, Some(probe)).await;
                            drop(permit);
                        });
                    }
                    Err(_) => break,
                }
            }
        }
    });

    Ok((local_addr, handle))
}

/// audit: returns true for `tcp://127.0.0.1:*`
/// `tcp://[::1]:*`, or `tcp://localhost:*`. Used to decide whether
/// the unauth-warning fires on metrics startup.
pub fn is_loopback_listen(uri: &str) -> bool {
    let after_scheme = match uri.split_once("://") {
        Some((_, rest)) => rest,
        None => uri,
    };
    after_scheme.starts_with("127.0.0.1:")
        || after_scheme.starts_with("[::1]:")
        || after_scheme.starts_with("localhost:")
}

/// audit: parse `Authorization: Bearer <token>` from raw
/// HTTP request bytes. Returns the token slice (without the "Bearer "
/// prefix) or `None` if missing/malformed.
///
/// Header parsing is case-insensitive on the field name (per RFC 7230
/// §3.2: header field names are case-insensitive).
pub fn extract_bearer_token(request: &str) -> Option<&str> {
    for line in request.lines() {
        // Skip lines without `:` — including the request-line ("GET... HTTP/1.1")
        // and malformed headers. Use continue (not `?`) so we keep scanning.
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("authorization") {
            let value = value.trim();
            // RFC 6750 §2.1: scheme is case-insensitive.
            if let Some(rest) = value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
            {
                return Some(rest.trim());
            }
        }
    }
    None
}

/// audit: constant-time string comparison for bearer-token
/// validation. Avoids byte-by-byte timing leak that would let an
/// attacker incrementally guess a valid token. Length-mismatch returns
/// false without touching the bytes.
pub fn bearer_token_matches(expected: &str, presented: &str) -> bool {
    use subtle::ConstantTimeEq;
    if expected.len() != presented.len() {
        return false;
    }
    expected.as_bytes().ct_eq(presented.as_bytes()).into()
}

// ── serve_connection ──────────────────────────────────────────────────────────

async fn serve_connection(
    connection: Box<dyn TransportConnection>,
    metrics: Arc<NodeMetrics>,
    summary: Arc<std::sync::Mutex<RuntimeSummary>>,
    path: String,
    auth_token: Arc<Option<String>>,
    logger: Arc<NodeLogger>,
    state_probe: Option<RuntimeStateProbe>,
) -> Result<()> {
    let stream: BoxIoStream = connection.into_stream()?;
    serve_stream(
        stream,
        metrics,
        summary,
        path,
        auth_token,
        logger,
        state_probe,
    )
    .await
}

async fn serve_stream(
    mut stream: BoxIoStream,
    metrics: Arc<NodeMetrics>,
    summary: Arc<std::sync::Mutex<RuntimeSummary>>,
    path: String,
    auth_token: Arc<Option<String>>,
    logger: Arc<NodeLogger>,
    state_probe: Option<RuntimeStateProbe>,
) -> Result<()> {
    let mut buf = vec![0_u8; 4096];
    // audit: bound the read. Slow-loris attackers
    // clients sending incomplete headers (no `\r\n\r\n`) would otherwise
    // hold this future indefinitely. On timeout, drop the connection.
    let read = match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(e.into()),
        Err(_) => {
            // Timeout — log and close.
            logger.warn(
                "metrics.read_timeout",
                format!(
                    "dropped connection after {} s without complete request",
                    READ_TIMEOUT.as_secs()
                ),
            );
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };
    let request = String::from_utf8_lossy(&buf[..read]);
    let first_line = request.lines().next().unwrap_or_default();

    let req_path = first_line.split_whitespace().nth(1).unwrap_or("/");

    // audit: bearer auth. When configured, every request
    // must carry a matching `Authorization: Bearer <token>` header.
    // Constant-time comparison via subtle (peer-controlled timing on
    // single-byte mismatches would leak the token byte-by-byte).
    if let Some(expected) = auth_token.as_ref().as_ref() {
        let presented = extract_bearer_token(&request);
        let ok = match presented {
            Some(t) => bearer_token_matches(expected, t),
            None => false,
        };
        if !ok {
            let body = "unauthorized\n".to_owned();
            let response = format!(
                "HTTP/1.1 401 Unauthorized\r\nwww-authenticate: Bearer\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len(),
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
            logger.info(
                "metrics.serve",
                format!("path={req_path} status=401 reason=unauthorized"),
            );
            return Ok(());
        }
    }

    let (status_code, content_type, body): (&str, &str, String) = if req_path == path
        || req_path == path.trim_end_matches('/')
    {
        // bufpool: append global frame-pool stats to prometheus
        // output AT SCRAPE TIME (cheap — single load of 5 atomics + 3
        // bucket-cached counts). Avoids cross-crate dep between bufpool
        // (must stay a leaf crate) and observability (lower-level than
        // veilcore).
        let pool_stats = veil_bufpool::global().stats();
        let pool_lines = format!(
            "# HELP veil_bufpool_cache_hit_total Pool cache hits\n\
             # TYPE veil_bufpool_cache_hit_total counter\n\
             veil_bufpool_cache_hit_total {}\n\
             # HELP veil_bufpool_fallback_alloc_total Pool cache miss → heap fallback\n\
             # TYPE veil_bufpool_fallback_alloc_total counter\n\
             veil_bufpool_fallback_alloc_total {}\n\
             # HELP veil_bufpool_overflow_drop_total Returns dropped (cache full)\n\
             # TYPE veil_bufpool_overflow_drop_total counter\n\
             veil_bufpool_overflow_drop_total {}\n\
             # HELP veil_bufpool_return_anomaly_total Returns rejected (size mismatch)\n\
             # TYPE veil_bufpool_return_anomaly_total counter\n\
             veil_bufpool_return_anomaly_total {}\n\
             # HELP veil_bufpool_cached_inflight Current buffers cached in pool\n\
             # TYPE veil_bufpool_cached_inflight gauge\n\
             veil_bufpool_cached_inflight {}\n\
             # HELP veil_bufpool_cached_peak Peak cached buffers since start\n\
             # TYPE veil_bufpool_cached_peak gauge\n\
             veil_bufpool_cached_peak {}\n",
            pool_stats.cache_hit_total,
            pool_stats.fallback_alloc_total,
            pool_stats.overflow_drop_total,
            pool_stats.return_anomaly_total,
            pool_stats.cached_inflight,
            pool_stats.cached_peak,
        );
        let mut body = metrics.render_prometheus();
        body.push_str(&pool_lines);
        // state-size gauges (live_sessions, route_cache.size
        // chunk_reassembler.bytes, DHT routing contacts, etc.) — operator
        // visibility into the resident-heap composition.
        if let Some(probe) = &state_probe {
            body.push_str(&probe.render_prometheus());
        }
        ("200 OK", "text/plain; version=0.0.4", body)
    } else if req_path == "/admin/health" {
        let s = lock!(summary).clone();
        let snap = metrics.snapshot();
        let body = format!(
            "{{\"status\":\"ok\",\"uptime_secs\":{},\"active_sessions\":{},\"mailbox_entries\":{},\"banned_peers\":{}}}",
            s.uptime_secs, snap.active_sessions, s.mailbox_entries, s.banned_peers,
        );
        ("200 OK", "application/json", body)
    } else if req_path == "/admin/state/dump" {
        let s = lock!(summary).clone();
        let snap = metrics.snapshot();
        let body = format!(
            "role: {}\nactive_sessions: {}\nmailbox_entries: {}\ndiscovery_entries: {}\ndht_keys: {}\nneighbor_count: {}\nroute_cache_size: {}\nbanned_peers: {}\nuptime_secs: {}\nrate_limit_drops_total: {}\nban_actions_total: {}\n",
            s.role,
            snap.active_sessions,
            s.mailbox_entries,
            s.discovery_entries,
            s.dht_keys,
            s.neighbor_count,
            s.route_cache_size,
            s.banned_peers,
            s.uptime_secs,
            snap.rate_limit_drops_total,
            snap.ban_actions_total,
        );
        ("200 OK", "text/plain", body)
    } else {
        ("404 Not Found", "text/plain", "not found\n".to_owned())
    };

    let response = format!(
        "HTTP/1.1 {status_code}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(response.as_bytes()).await?;
    let _ = stream.shutdown().await;
    logger.info(
        "metrics.serve",
        format!("path={req_path} status={status_code}"),
    );
    Ok(())
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::io::AsyncReadExt;

    use super::*;
    use veil_observability::NodeMetrics;

    fn make_logger() -> Arc<NodeLogger> {
        Arc::new(
            veil_cfg::observability_glue::logger_from_config(&veil_cfg::Config::default()).unwrap(),
        )
    }

    fn make_summary(role: &str) -> Arc<Mutex<RuntimeSummary>> {
        Arc::new(Mutex::new(RuntimeSummary {
            role: role.to_owned(),
            active_sessions: 0,
            mailbox_entries: 5,
            discovery_entries: 0,
            dht_keys: 0,
            neighbor_count: 3,
            route_cache_size: 10,
            banned_peers: 1,
            uptime_secs: 42,
        }))
    }

    /// Send `request` bytes to `serve_stream` and return the full HTTP response.
    ///
    /// Uses a tokio duplex: `a` is the "client" side (we write the request to it and
    /// read the response back), `b` is passed as the server's stream.
    async fn http_request(
        request: &str,
        metrics: Arc<NodeMetrics>,
        summary: Arc<Mutex<RuntimeSummary>>,
        path: &str,
    ) -> String {
        use tokio::io::AsyncWriteExt;
        let (mut client, server) = tokio::io::duplex(8192);
        client.write_all(request.as_bytes()).await.unwrap();
        // Keep client open so serve_stream can write the response back.
        let stream: BoxIoStream = Box::new(server);
        serve_stream(
            stream,
            metrics,
            summary,
            path.to_owned(),
            Arc::new(None),
            make_logger(),
            None,
        )
        .await
        .unwrap();
        // Now read whatever the server wrote back to the client side.
        // After serve_stream shuts down its end, read_to_end will return.
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn health_endpoint_returns_200_with_body() {
        let metrics = Arc::new(NodeMetrics::new());
        let summary = make_summary("core");
        let resp = http_request(
            "GET /admin/health HTTP/1.1\r\nHost: localhost\r\n\r\n",
            metrics,
            summary,
            "/metrics",
        )
        .await;
        assert!(
            resp.contains("HTTP/1.1 200 OK"),
            "expected 200, got: {resp}"
        );
        assert!(resp.contains("\"status\":\"ok\""), "body missing status:ok");
        assert!(resp.contains("\"uptime_secs\":42"), "body missing uptime");
        assert!(
            resp.contains("\"mailbox_entries\":5"),
            "body missing mailbox_entries"
        );
        assert!(
            resp.contains("\"banned_peers\":1"),
            "body missing banned_peers"
        );
    }

    #[tokio::test]
    async fn state_dump_no_pii() {
        let metrics = Arc::new(NodeMetrics::new());
        let summary = make_summary("relay");
        let resp = http_request(
            "GET /admin/state/dump HTTP/1.1\r\nHost: localhost\r\n\r\n",
            metrics,
            summary,
            "/metrics",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200 OK"), "expected 200");
        assert!(resp.contains("role: relay"), "missing role");
        // PII fields must NOT appear
        assert!(!resp.contains("private_key"), "PII: private_key found");
        assert!(!resp.contains("public_key"), "PII: public_key found");
        assert!(!resp.contains("nonce"), "PII: nonce found");
        assert!(!resp.contains("secret"), "PII: secret found");
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_prometheus() {
        let metrics = Arc::new(NodeMetrics::new());
        metrics.inc_ban_actions();
        let summary = make_summary("core");
        let resp = http_request(
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
            metrics,
            summary,
            "/metrics",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200 OK"));
        assert!(resp.contains("veil_ban_actions_total 1"));
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let metrics = Arc::new(NodeMetrics::new());
        let summary = make_summary("leaf");
        let resp = http_request(
            "GET /unknown HTTP/1.1\r\nHost: localhost\r\n\r\n",
            metrics,
            summary,
            "/metrics",
        )
        .await;
        assert!(resp.contains("HTTP/1.1 404 Not Found"));
    }

    // ── audit hardening tests ────────────────────────────

    /// Helper for auth tests: same as `http_request` but takes a
    /// configured auth_token and returns the full response.
    async fn http_request_with_auth(
        request: &str,
        metrics: Arc<NodeMetrics>,
        summary: Arc<Mutex<RuntimeSummary>>,
        path: &str,
        auth_token: Option<String>,
    ) -> String {
        use tokio::io::AsyncWriteExt;
        let (mut client, server) = tokio::io::duplex(8192);
        client.write_all(request.as_bytes()).await.unwrap();
        let stream: BoxIoStream = Box::new(server);
        serve_stream(
            stream,
            metrics,
            summary,
            path.to_owned(),
            Arc::new(auth_token),
            make_logger(),
            None,
        )
        .await
        .unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn phase650b_auth_required_when_token_configured_missing_header_rejected() {
        let metrics = Arc::new(NodeMetrics::new());
        let summary = make_summary("core");
        let resp = http_request_with_auth(
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
            metrics,
            summary,
            "/metrics",
            Some("secret123".to_owned()),
        )
        .await;
        assert!(resp.contains("HTTP/1.1 401 Unauthorized"), "got: {resp}");
        assert!(
            resp.contains("www-authenticate: Bearer"),
            "must hint Bearer"
        );
    }

    #[tokio::test]
    async fn phase650b_auth_correct_token_accepted() {
        let metrics = Arc::new(NodeMetrics::new());
        let summary = make_summary("core");
        let resp = http_request_with_auth(
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer secret123\r\n\r\n",
            metrics,
            summary,
            "/metrics",
            Some("secret123".to_owned()),
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200 OK"), "got: {resp}");
    }

    #[tokio::test]
    async fn phase650b_auth_wrong_token_rejected() {
        let metrics = Arc::new(NodeMetrics::new());
        let summary = make_summary("core");
        let resp = http_request_with_auth(
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrongone\r\n\r\n",
            metrics,
            summary,
            "/metrics",
            Some("secret123".to_owned()),
        )
        .await;
        assert!(resp.contains("HTTP/1.1 401 Unauthorized"), "got: {resp}");
    }

    #[tokio::test]
    async fn phase650b_auth_unset_no_token_required() {
        // When `auth_token` is None (default), all requests pass. Loopback-
        // bind use case.
        let metrics = Arc::new(NodeMetrics::new());
        let summary = make_summary("core");
        let resp = http_request_with_auth(
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
            metrics,
            summary,
            "/metrics",
            None,
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200 OK"), "got: {resp}");
    }

    #[tokio::test]
    async fn phase650b_auth_case_insensitive_header_name() {
        // RFC 7230 §3.2: HTTP header field names are case-insensitive.
        let metrics = Arc::new(NodeMetrics::new());
        let summary = make_summary("core");
        let resp = http_request_with_auth(
            "GET /metrics HTTP/1.1\r\nHost: localhost\r\nauthorization: Bearer secret123\r\n\r\n",
            metrics,
            summary,
            "/metrics",
            Some("secret123".to_owned()),
        )
        .await;
        assert!(resp.contains("HTTP/1.1 200 OK"), "got: {resp}");
    }

    #[test]
    fn phase650b_is_loopback_listen_recognises_local_binds() {
        assert!(is_loopback_listen("tcp://127.0.0.1:9000"));
        assert!(is_loopback_listen("tcp://[::1]:9000"));
        assert!(is_loopback_listen("tcp://localhost:9000"));
        // Non-loopback.
        assert!(!is_loopback_listen("tcp://0.0.0.0:9000"));
        assert!(!is_loopback_listen("tcp://192.168.1.5:9000"));
        assert!(!is_loopback_listen("tcp://example.com:9000"));
    }

    #[test]
    fn phase650b_extract_bearer_token_parses_header() {
        // Standard form.
        assert_eq!(
            extract_bearer_token("GET / HTTP/1.1\r\nAuthorization: Bearer abc123\r\n\r\n"),
            Some("abc123"),
        );
        // Lower-case scheme (RFC 6750: case-insensitive).
        assert_eq!(
            extract_bearer_token("GET / HTTP/1.1\r\nauthorization: bearer xyz\r\n\r\n"),
            Some("xyz"),
        );
        // Missing header.
        assert_eq!(extract_bearer_token("GET / HTTP/1.1\r\n\r\n"), None,);
        // Wrong scheme.
        assert_eq!(
            extract_bearer_token("GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"),
            None,
        );
    }
}
