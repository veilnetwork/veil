use std::{
    collections::VecDeque,
    fs::OpenOptions,
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

/// Number of most-recent route events (miss or recovery) tracked in the
/// sliding-window reachability score.
pub const REACHABILITY_WINDOW: usize = 20;

/// Maximum age of a route event before it's considered stale and ignored
/// when computing the reachability score. Without this, once the cluster
/// experiences a brief partition at startup the window fills with `false`
/// events, the cache then satisfies all subsequent queries (so no fresh
/// events are recorded), and the score remains stuck at 0 indefinitely
/// even though packet delivery is healthy. After this TTL the score
/// drifts back toward 1.0 (the empty-window default — "assume healthy").
pub const REACHABILITY_EVENT_TTL: std::time::Duration = std::time::Duration::from_secs(300);

use veil_types::{LogFormat, LogLevel, LogsConfig};

use std::fmt;

#[derive(Clone)]
pub struct NodeLogger {
    sink: Arc<Mutex<Box<dyn Write + Send>>>,
    level: LogLevel,
    format: LogFormat,
}

impl fmt::Debug for NodeLogger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NodeLogger(level={:?}, format={:?})",
            self.level, self.format
        )
    }
}

#[derive(Clone, Debug)]
pub struct NodeMetrics {
    // ── Transport ────────────────────────────────────────────────────────────
    configured_peers: Arc<AtomicU64>,
    active_sessions: Arc<AtomicU64>,
    inbound_sessions_total: Arc<AtomicU64>,
    outbound_connect_attempts_total: Arc<AtomicU64>,
    outbound_connect_failures_total: Arc<AtomicU64>,
    transport_bytes_rx_total: Arc<AtomicU64>,
    transport_bytes_tx_total: Arc<AtomicU64>,
    // ── Session plane ────────────────────────────────────────────────────────
    session_handshake_failures_total: Arc<AtomicU64>,
    // ── Discovery / DHT ──────────────────────────────────────────────────────
    dht_store_total: Arc<AtomicU64>,
    dht_lookup_total: Arc<AtomicU64>,
    /// Total STORE frames successfully queued during periodic re-replication
    /// across all keys. Healthy: rate ≈ `(records_published × DHT_REPLICATION_K)
    /// / republish_interval` — а sustained shortfall indicates partitioned
    /// routing OR persistent unreachable closest-peers. audit
    /// follow-up: closes the long-standing TODO в `publisher_dht.rs` of
    /// "we have no visibility on whether identity / name records are actually
    /// reaching their K-replica targets".
    replicas_published_total: Arc<AtomicU64>,
    /// Re-replication ticks where the fan-out reached zero remote peers
    /// (key was stored locally but found no replication targets). Spike в
    /// this counter signals partition / single-node situation — operator
    /// alert trigger. Distinct from `replicas_published_total` so а single
    /// "K = 0 fan-out" event is observable even if total throughput stays
    /// healthy on other keys.
    replicas_under_count_total: Arc<AtomicU64>,
    // ── Mesh plane ───────────────────────────────────────────────────────────
    mesh_relay_hops_total: Arc<AtomicU64>,
    // ── Crypto ───────────────────────────────────────────────────────────────
    decrypt_failures_total: Arc<AtomicU64>,
    // ── Session rekey ──────────
    /// `RekeyInit` frames the initiator-side actually pushed onto the wire.
    /// Pairs with `rekey_ack_received_total` for round-trip success rate
    /// (mismatch ⇒ ack lost, session torn down before completion).
    rekey_init_sent_total: Arc<AtomicU64>,
    /// `RekeyInit` frames the responder-side processed. Lower than
    /// `rekey_init_sent_total` of the peer ⇒ frames dropped on the wire
    /// or the responder is processing-starved.
    rekey_init_received_total: Arc<AtomicU64>,
    /// `RekeyAck` frames the responder-side pushed onto the wire.
    rekey_ack_sent_total: Arc<AtomicU64>,
    /// `RekeyAck` frames the initiator-side received and applied.
    rekey_ack_received_total: Arc<AtomicU64>,
    /// AEAD decryption succeeded only via а stashed prev-cipher fallback —
    /// indicates an OLD-encrypted frame in flight during rekey. Healthy
    /// in low numbers (one or two per rekey under chat-load); a sustained
    /// spike means the 30 s grace window is being approached.
    rekey_decrypt_fallback_total: Arc<AtomicU64>,
    /// Prev-cipher entries evicted from the rx ring buffer (FIFO front
    /// pop) before their 30 s grace expired — i.e. the cap of 16 was hit
    /// because rekeys arrived faster than they expired. Non-zero ⇒
    /// session is rekeying back-to-back-to-back, real risk of orphaned
    /// frames triggering session-teardown.
    rekey_grace_cap_evictions_total: Arc<AtomicU64>,
    /// `RekeyKeptInit` frames pushed onto the wire — emitted by the
    /// lower-`node_id` side of а mutual rekey-init collision к signal
    /// the loser к back off. Healthy under burst load (correlates с
    /// rekey-storm risk); persistent non-zero ⇒ both peers crossing
    /// the byte threshold in lockstep often.
    rekey_kept_init_sent_total: Arc<AtomicU64>,
    /// `RekeyKeptInit` frames received and applied (own pending init
    /// reset к Idle, time-threshold trigger pushed forward). Mirrors
    /// peer's `rekey_kept_init_sent_total`.
    rekey_kept_init_received_total: Arc<AtomicU64>,
    // ── Storage lifecycle ──────────────────────────────────────────
    storage_evictions_total: Arc<AtomicU64>,
    // ── Route convergence ──────────────────────────────────────────
    route_miss_total: Arc<AtomicU64>,
    discovery_triggered_total: Arc<AtomicU64>,
    // ── Iterative-DHT route-discovery fallback ───────────────
    /// Count of `try_resolve_and_dial` invocations — fires whenever the
    /// legacy `RouteRequest` flood (TTL=7) exhausts retries без finding а
    /// route и we fall through к the relay-aware `RecursiveQuery(FIND_NODE)`
    /// path. High value indicates the network's diameter exceeds 7 hops
    /// regularly (sparse mesh / partition / pathological topology).
    dht_fallback_triggered_total: Arc<AtomicU64>,
    /// Count of fallbacks that succeeded — `RecursiveResponse` arrived
    /// within the `RECURSIVE_TIMEOUT` budget и dispatcher populated
    /// `route_cache`. Ratio `resolved / triggered` is the **partition
    /// health signal**: > 0.5 = healthy mesh, < 0.2 = fragmentation OR
    /// CPU starvation на the response path.
    dht_fallback_resolved_total: Arc<AtomicU64>,
    /// Count of fallbacks that hit the `RECURSIVE_TIMEOUT` (10 s) without
    /// а response. High value points к either (a) network partition
    /// past the recursive-query TTL=40 hop budget (b) target's
    /// `SignedTransportAnnouncement` absent от DHT, or (c) under-load
    /// daemons dropping responses на the reverse path.
    dht_fallback_miss_total: Arc<AtomicU64>,
    /// route-miss events dropped because
    /// `pending_recursive` was already past the backpressure threshold.
    /// Operator alert trigger when this spikes alongside
    /// `dht_fallback_triggered_total` flatlining — fallback is being
    /// silently disabled и the system is under sustained load.
    dht_fallback_skipped_backpressure_total: Arc<AtomicU64>,
    /// current effective timeout (ms) after
    /// adaptive scaling. Gauge — operator can correlate spikes
    /// (timeout climbed → network is misbehaving) с the miss-rate
    /// panel. Equals baseline `dht_fallback_timeout_ms` when adaptive
    /// is disabled OR conditions are nominal.
    dht_fallback_effective_timeout_ms: Arc<AtomicU64>,
    /// Partition-recovery watchdog ( cascade follow-up):
    /// number of times `BootstrapWatchdog` observed `live_sessions == 0`
    /// for `ZERO_STREAK_THRESHOLD` consecutive ticks и re-dialed the
    /// operator-curated bootstrap list. Should be 0 in а healthy
    /// cluster; non-zero indicates the local node was at some point
    /// fully isolated from every direct peer и recovered via fallback.
    bootstrap_watchdog_retries_total: Arc<AtomicU64>,
    // ── Partition detection ────────────────────────────────────────
    /// Count of route miss events that were followed by a successful recovery.
    route_recovery_total: Arc<AtomicU64>,
    /// Sliding window of the last REACHABILITY_WINDOW route events.
    /// `true` = successful recovery, `false` = persistent miss.
    reachability_window: Arc<Mutex<VecDeque<(std::time::Instant, bool)>>>,
    // ── Adaptive routing metrics ────────────────────────────────
    /// Cumulative RTT of successfully-routed DELIVERY_FORWARD frames (ms).
    route_selection_rtt_sum: Arc<AtomicU64>,
    /// Number of DELIVERY_FORWARD route-selection events with a known RTT.
    route_selection_rtt_count: Arc<AtomicU64>,
    /// Cumulative |vivaldi_estimate - measured_rtt| across ROUTE_REPLY events (ms).
    vivaldi_error_sum: Arc<AtomicU64>,
    /// Number of Vivaldi prediction-error samples.
    vivaldi_error_count: Arc<AtomicU64>,
    /// Local Vivaldi coordinate — f64 fields stored as `to_bits` in AtomicU64
    /// so gauges track the live coord without holding the mutex at export time.
    /// Refreshed by `record_vivaldi_coord` after every `VivaldiCoord::update`.
    vivaldi_coord_x_bits: Arc<AtomicU64>,
    vivaldi_coord_y_bits: Arc<AtomicU64>,
    vivaldi_coord_height_bits: Arc<AtomicU64>,
    vivaldi_coord_error_bits: Arc<AtomicU64>,
    // ── Abuse resistance ─────────────────────────────────────────────────────
    rate_limit_drops_total: Arc<AtomicU64>,
    backpressure_received_total: Arc<AtomicU64>,
    ban_actions_total: Arc<AtomicU64>,
    // ── Real-time transport ───────────────────────────────────────────────────
    /// Total APP_RT_DATA frames received.
    rt_frames_rx_total: Arc<AtomicU64>,
    /// Total APP_RT_DATA frames sent outbound to peers.
    rt_frames_tx_total: Arc<AtomicU64>,
    /// Total APP_RT_DATA sequence-number gaps detected across all streams.
    rt_seq_gaps_total: Arc<AtomicU64>,
    /// Per-stream last-seen RT frame sequence number.
    ///
    /// Key: `u64::from_le_bytes(app_id[..8]) ^ endpoint_id as u64` — a
    /// lightweight heuristic unique enough for gap detection.
    /// Bounded to `RT_SEQ_TRACKER_MAX` entries; entries are dropped when full
    /// rather than tracking new streams (graceful degradation).
    rt_last_seq: Arc<Mutex<std::collections::HashMap<u64, u32>>>,
    // ── Application layer ────────────────────────────────────────────────────
    /// Messages dropped because the endpoint channel buffer was full (backpressure).
    app_msg_channel_full_total: Arc<AtomicU64>,
    /// Messages dropped because the endpoint channel receiver was closed (app disconnected).
    app_msg_channel_closed_total: Arc<AtomicU64>,
    // ── Session queue backpressure ─────────────────────────────────
    /// Frames dropped by `SessionTxRegistry` due to a full per-session channel.
    session_tx_drops_total: Arc<AtomicU64>,
    /// RPC requests dropped by `SessionOutbox` due to a full per-session channel.
    session_outbox_drops_total: Arc<AtomicU64>,
    /// g: frames shed by the per-session `PriorityQueue`
    /// when its aggregate depth would exceed `DEFAULT_MAX_DEPTH`.
    /// Distinct from `session_tx_drops_total` which counts drops at the
    /// mpsc layer one stage upstream — this counter surfaces overflow
    /// of the WRR queue between mpsc и wire write.
    priority_queue_drops_total: Arc<AtomicU64>,
    // ── IPC delivery backpressure ──────────────────────────────────
    /// Frames dropped because the per-IPC-client delivery channel was full.
    ipc_delivery_drops_total: Arc<AtomicU64>,
    // ── Multi-path delivery ───────────────────────────────────────
    /// Total number of parallel path sends triggered by multi-path delivery.
    multi_path_sends_total: Arc<AtomicU64>,
    // ── Chunked transfer ─────────────────────────────────────
    /// Successfully reassembled chunked transfers.
    chunks_reassembled_total: Arc<AtomicU64>,
    // ── Mobile sleep ──────────────────────────────────────────────
    /// Total `SleepAdvertisement` frames that were accepted by the dispatcher.
    sleep_advertisements_accepted_total: Arc<AtomicU64>,
    // ── DHT-routed forwarding ──────────────────────────────
    /// Total RecursiveRelay frames initiated (route cache miss → DHT forwarding).
    recursive_relay_initiated_total: Arc<AtomicU64>,
    /// Total RecursiveRelay frames forwarded (transit hop).
    recursive_relay_forwarded_total: Arc<AtomicU64>,
    /// Total RecursiveRelay frames delivered (destination reached).
    recursive_relay_delivered_total: Arc<AtomicU64>,
    /// Total route cache hit events (successful lookup in relay_forward).
    route_cache_hits_total: Arc<AtomicU64>,
    /// Total ROUTE_ANNOUNCE gossip frames received.
    gossip_announces_rx_total: Arc<AtomicU64>,
    // ── denial/drop counters surfaced by security gates ─────────
    /// RouteAnnounce/RouteWithdraw frames rejected because `via_node_id`
    /// did not match the transport-layer sender (post-461.7 invariant:
    /// relays always re-sign с `via = self`, so divergence is malicious
    /// by construction → Violation).  Metric name retained for dashboard
    /// stability; semantics ара now "via spoof" не the original "quota
    /// drop" (quota field removed 2026-05-22 after design moved past
    /// forward-then-verify).
    unknown_origin_gossip_rejected_total: Arc<AtomicU64>,
    /// Exit-proxy CONNECT targets denied by `is_forbidden_destination`
    /// (loopback/private/link-local/metadata)..
    exit_proxy_dest_denied_total: Arc<AtomicU64>,
    /// SOCKS5 inbound TCP accepts throttled because `MAX_SOCKS_CONCURRENT`
    /// semaphore was saturated..
    socks5_accepts_throttled_total: Arc<AtomicU64>,
    /// GatewayBridge `lift_seen` entries evicted by the hard-cap (LRU
    /// oldest-by-Instant)..
    gateway_lift_seen_evicted_total: Arc<AtomicU64>,
    /// Generic send-to-peer failures in forwarder/delivery hot paths —
    /// incremented when `session_tx_registry.send_to` returns false
    /// (session gone, channel full)..
    send_to_failed_total: Arc<AtomicU64>,
    /// RelayChain frames dropped because the local node is not relay-
    /// capable (`anonymity_x25519_sk` is `None`). -D5: visibility
    /// for "operator forgot to set `[anonymity].relay_capable = true`" vs
    /// "active probing for relay-capable peers" — without a metric, sender
    /// gets silent timeout AND operator log shows nothing actionable.
    dropped_relay_frames_total: Arc<AtomicU64>,
    /// session writes that exceeded `WRITE_PROGRESS_TIMEOUT`
    /// without making progress — a TCP backpressure deadlock signature.
    /// Incremented by the dedicated writer task when its `write_all`
    /// inside the timeout wrapper returns `Err(_)` (timeout elapsed).
    session_write_stalled_total: Arc<AtomicU64>,
    /// outbound wire frames dropped because the
    /// `wire_tx`/`wire_rx` channel between main loop and writer task
    /// was at capacity (`WIRE_CHANNEL_CAPACITY = 256`). Indicates the
    /// writer task is falling behind — either peer is slow draining
    /// our TCP send buffer, or our own host is CPU-bound. Critical
    /// invariant: increment of this counter does NOT block the read
    /// path. When sustained, the session terminates via writer-task
    /// timeout → channel close → main loop sees Err on next push.
    session_wire_dropped_total: Arc<AtomicU64>,
    // ── PoW-Gated Rendezvous (Slice 7) ───────────────────────────
    rendezvous_requests_received_total: Arc<AtomicU64>,
    rendezvous_requests_granted_total: Arc<AtomicU64>,
    rendezvous_requests_rejected_decode_total: Arc<AtomicU64>,
    rendezvous_requests_rejected_verify_total: Arc<AtomicU64>,
    rendezvous_requests_rejected_not_our_target_total: Arc<AtomicU64>,
    rendezvous_requests_rejected_rate_limit_total: Arc<AtomicU64>,
    rendezvous_requests_rejected_concurrency_total: Arc<AtomicU64>,
    rendezvous_requests_rejected_bind_failed_total: Arc<AtomicU64>,
    /// Current snapshot — incremented когда an on-demand listener
    /// is bound, decremented когда its lifecycle retires.  Gauge,
    /// not а counter.
    rendezvous_slots_in_use: Arc<AtomicU64>,
}

#[derive(Clone, Debug, Default)]
pub struct MetricsSnapshot {
    // Transport
    pub configured_peers: u64,
    pub active_sessions: u64,
    pub inbound_sessions_total: u64,
    pub outbound_connect_attempts_total: u64,
    pub outbound_connect_failures_total: u64,
    pub transport_bytes_rx_total: u64,
    pub transport_bytes_tx_total: u64,
    // Session
    pub session_handshake_failures_total: u64,
    // DHT
    pub dht_store_total: u64,
    pub dht_lookup_total: u64,
    pub replicas_published_total: u64,
    pub replicas_under_count_total: u64,
    // Mesh
    pub mesh_relay_hops_total: u64,
    // Crypto
    pub decrypt_failures_total: u64,
    // Session rekey
    pub rekey_init_sent_total: u64,
    pub rekey_init_received_total: u64,
    pub rekey_ack_sent_total: u64,
    pub rekey_ack_received_total: u64,
    pub rekey_decrypt_fallback_total: u64,
    pub rekey_grace_cap_evictions_total: u64,
    pub rekey_kept_init_sent_total: u64,
    pub rekey_kept_init_received_total: u64,
    // Storage lifecycle
    pub storage_evictions_total: u64,
    // Route convergence
    pub route_miss_total: u64,
    pub discovery_triggered_total: u64,
    pub route_recovery_total: u64,
    // Iterative-DHT fallback
    pub dht_fallback_triggered_total: u64,
    pub dht_fallback_resolved_total: u64,
    pub dht_fallback_miss_total: u64,
    pub dht_fallback_skipped_backpressure_total: u64,
    pub dht_fallback_effective_timeout_ms: u64,
    /// Partition-recovery watchdog retry count.
    pub bootstrap_watchdog_retries_total: u64,
    /// Fraction of successful recoveries over the last REACHABILITY_WINDOW
    /// route events. 1.0 = fully reachable, 0.0 = all misses.
    pub network_reachability_score: f64,
    // Adaptive routing
    /// Average RTT of successfully-selected routes (ms, 0 if no samples).
    pub route_selection_avg_rtt: u64,
    /// Average Vivaldi prediction error (ms, 0 if no samples).
    pub vivaldi_prediction_error: u64,
    /// Live local Vivaldi coordinate. Components are
    /// synthetic — only distances are meaningful. `error` → 0 means the
    /// coord has converged. Default = `(0, 0, 0.1, 1.0)` before first update.
    pub vivaldi_coord_x: f64,
    pub vivaldi_coord_y: f64,
    pub vivaldi_coord_height: f64,
    pub vivaldi_coord_error: f64,
    // Abuse
    pub rate_limit_drops_total: u64,
    pub backpressure_received_total: u64,
    pub ban_actions_total: u64,
    // Real-time
    pub rt_frames_rx_total: u64,
    pub rt_frames_tx_total: u64,
    pub rt_seq_gaps_total: u64,
    // Application layer
    pub app_msg_channel_full_total: u64,
    pub app_msg_channel_closed_total: u64,
    // Session queue backpressure
    pub session_tx_drops_total: u64,
    /// g: PriorityQueue overflow drops.
    pub priority_queue_drops_total: u64,
    pub session_outbox_drops_total: u64,
    // IPC delivery backpressure
    pub ipc_delivery_drops_total: u64,
    // Multi-path delivery
    pub multi_path_sends_total: u64,
    // Chunked transfer
    pub chunks_reassembled_total: u64,
    // Mobile sleep
    pub sleep_advertisements_accepted_total: u64,
    // DHT-routed forwarding
    pub recursive_relay_initiated_total: u64,
    pub recursive_relay_forwarded_total: u64,
    pub recursive_relay_delivered_total: u64,
    pub route_cache_hits_total: u64,
    pub gossip_announces_rx_total: u64,
    // Denial/drop counters
    pub unknown_origin_gossip_rejected_total: u64,
    pub exit_proxy_dest_denied_total: u64,
    pub socks5_accepts_throttled_total: u64,
    pub gateway_lift_seen_evicted_total: u64,
    pub send_to_failed_total: u64,
    pub dropped_relay_frames_total: u64,
    pub session_write_stalled_total: u64,
    pub session_wire_dropped_total: u64,
    // ── PoW-Gated Rendezvous (Slice 7) ───────────────────────────
    /// Total `SessionMsg::RequestEphemeralEndpoint` frames received
    /// и handed к the controller.  Includes both granted и
    /// rejected outcomes — denominator для grant-rate calculations.
    pub rendezvous_requests_received_total: u64,
    /// Subset of requests где the controller successfully bound an
    /// on-demand listener и shipped а signed
    /// `EphemeralEndpointResponse` back к the requester.
    pub rendezvous_requests_granted_total: u64,
    /// Requests rejected for malformed wire bytes (decode error).
    /// Counted under `rendezvous_requests_received_total` too.
    pub rendezvous_requests_rejected_decode_total: u64,
    /// Requests rejected at verify (bad sig, PoW below min, replay
    /// outside window, target_node_id ≠ ours).
    pub rendezvous_requests_rejected_verify_total: u64,
    /// Requests rejected because the target_node_id field did не
    /// match our local_node_id (mediator misrouted OR forged request).
    pub rendezvous_requests_rejected_not_our_target_total: u64,
    /// Requests rejected by the per-requester rate limiter.
    pub rendezvous_requests_rejected_rate_limit_total: u64,
    /// Requests rejected by the concurrent-slot semaphore
    /// (max_concurrent in-flight on-demand listeners reached).
    pub rendezvous_requests_rejected_concurrency_total: u64,
    /// Requests где verify + rate-limit + concurrent acquire all
    /// passed но the bind closure itself failed (port pool exhausted,
    /// obfs4 wrapping error, etc.).
    pub rendezvous_requests_rejected_bind_failed_total: u64,
    /// Snapshot gauge: currently-active on-demand listener slots.
    /// Increments when а bind succeeds; decrements when the lifecycle
    /// retires.  Bounded by the operator's `max_concurrent` config.
    pub rendezvous_slots_in_use: u64,
}

impl NodeLogger {
    /// Create a logger that silently discards all output. Useful in tests
    /// (downstream crate test profiles can call this — dropped the
    /// `#[cfg(test)]` gate that previously hid it across crate boundaries).
    pub fn new_noop() -> Self {
        Self {
            sink: Arc::new(Mutex::new(Box::new(io::sink()))),
            level: LogLevel::Error,
            format: LogFormat::Text,
        }
    }

    /// low-level constructor that takes the destructured config
    /// values directly. `NodeLogger::from_config(&Config)` was lifted к
    /// `veilcore::cfg::observability_glue` so this crate stays free of
    /// the cfg layer. Pass `LogsConfig::Stderr` to get the stderr sink;
    /// pass `LogsConfig::File` with `log_file = Some(path)` for a
    /// per-file sink.
    pub fn from_parts(
        logs: LogsConfig,
        log_file: Option<&std::path::Path>,
        level: LogLevel,
        format: LogFormat,
    ) -> std::io::Result<Self> {
        let sink: Box<dyn Write + Send> = match logs {
            LogsConfig::Stderr => Box::new(io::stderr()),
            LogsConfig::File => {
                let path = log_file.ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "global.log_file must be configured when global.logs=file",
                    )
                })?;
                Box::new(OpenOptions::new().create(true).append(true).open(path)?)
            }
        };
        Ok(Self {
            sink: Arc::new(Mutex::new(sink)),
            level,
            format,
        })
    }

    pub fn debug(&self, event: &str, message: impl AsRef<str>) {
        self.log(LogLevel::Debug, event, message.as_ref());
    }

    pub fn info(&self, event: &str, message: impl AsRef<str>) {
        self.log(LogLevel::Info, event, message.as_ref());
    }

    pub fn warn(&self, event: &str, message: impl AsRef<str>) {
        self.log(LogLevel::Warn, event, message.as_ref());
    }

    pub fn error(&self, event: &str, message: impl AsRef<str>) {
        self.log(LogLevel::Error, event, message.as_ref());
    }

    fn log(&self, level: LogLevel, event: &str, message: &str) {
        if level < self.level {
            return;
        }
        let line = match self.format {
            LogFormat::Text => format_log_line(level.as_str(), event, message),
            LogFormat::Json => format_log_json(level.as_str(), event, message),
        };
        if let Ok(mut sink) = self.sink.lock() {
            let _ = sink.write_all(line.as_bytes());
            let _ = sink.write_all(b"\n");
            let _ = sink.flush();
        }
    }
}

impl Default for NodeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeMetrics {
    pub fn new() -> Self {
        macro_rules! counter {
            () => {
                Arc::new(AtomicU64::new(0))
            };
        }
        Self {
            configured_peers: counter!(),
            active_sessions: counter!(),
            inbound_sessions_total: counter!(),
            outbound_connect_attempts_total: counter!(),
            outbound_connect_failures_total: counter!(),
            transport_bytes_rx_total: counter!(),
            transport_bytes_tx_total: counter!(),
            session_handshake_failures_total: counter!(),
            dht_store_total: counter!(),
            dht_lookup_total: counter!(),
            replicas_published_total: counter!(),
            replicas_under_count_total: counter!(),
            mesh_relay_hops_total: counter!(),
            decrypt_failures_total: counter!(),
            rekey_init_sent_total: counter!(),
            rekey_init_received_total: counter!(),
            rekey_ack_sent_total: counter!(),
            rekey_ack_received_total: counter!(),
            rekey_decrypt_fallback_total: counter!(),
            rekey_grace_cap_evictions_total: counter!(),
            rekey_kept_init_sent_total: counter!(),
            rekey_kept_init_received_total: counter!(),
            storage_evictions_total: counter!(),
            route_miss_total: counter!(),
            discovery_triggered_total: counter!(),
            dht_fallback_triggered_total: counter!(),
            dht_fallback_resolved_total: counter!(),
            dht_fallback_miss_total: counter!(),
            dht_fallback_skipped_backpressure_total: counter!(),
            dht_fallback_effective_timeout_ms: counter!(),
            bootstrap_watchdog_retries_total: counter!(),
            route_recovery_total: counter!(),
            reachability_window: Arc::new(Mutex::new(VecDeque::with_capacity(REACHABILITY_WINDOW))),
            route_selection_rtt_sum: counter!(),
            route_selection_rtt_count: counter!(),
            vivaldi_error_sum: counter!(),
            vivaldi_error_count: counter!(),
            vivaldi_coord_x_bits: Arc::new(AtomicU64::new(0f64.to_bits())),
            vivaldi_coord_y_bits: Arc::new(AtomicU64::new(0f64.to_bits())),
            vivaldi_coord_height_bits: Arc::new(AtomicU64::new(0.1f64.to_bits())),
            vivaldi_coord_error_bits: Arc::new(AtomicU64::new(1.0f64.to_bits())),
            rate_limit_drops_total: counter!(),
            backpressure_received_total: counter!(),
            ban_actions_total: counter!(),
            rt_frames_rx_total: counter!(),
            rt_frames_tx_total: counter!(),
            rt_seq_gaps_total: counter!(),
            rt_last_seq: Arc::new(Mutex::new(std::collections::HashMap::new())),
            app_msg_channel_full_total: counter!(),
            app_msg_channel_closed_total: counter!(),
            session_tx_drops_total: counter!(),
            session_outbox_drops_total: counter!(),
            priority_queue_drops_total: counter!(),
            ipc_delivery_drops_total: counter!(),
            multi_path_sends_total: counter!(),
            chunks_reassembled_total: counter!(),
            sleep_advertisements_accepted_total: counter!(),
            recursive_relay_initiated_total: counter!(),
            recursive_relay_forwarded_total: counter!(),
            recursive_relay_delivered_total: counter!(),
            route_cache_hits_total: counter!(),
            gossip_announces_rx_total: counter!(),
            unknown_origin_gossip_rejected_total: counter!(),
            exit_proxy_dest_denied_total: counter!(),
            socks5_accepts_throttled_total: counter!(),
            gateway_lift_seen_evicted_total: counter!(),
            send_to_failed_total: counter!(),
            dropped_relay_frames_total: counter!(),
            session_write_stalled_total: counter!(),
            session_wire_dropped_total: counter!(),
            rendezvous_requests_received_total: counter!(),
            rendezvous_requests_granted_total: counter!(),
            rendezvous_requests_rejected_decode_total: counter!(),
            rendezvous_requests_rejected_verify_total: counter!(),
            rendezvous_requests_rejected_not_our_target_total: counter!(),
            rendezvous_requests_rejected_rate_limit_total: counter!(),
            rendezvous_requests_rejected_concurrency_total: counter!(),
            rendezvous_requests_rejected_bind_failed_total: counter!(),
            rendezvous_slots_in_use: counter!(),
        }
    }

    // `NodeMetrics::from_config(&Config)` was lifted к
    // `veilcore::cfg::observability_glue::metrics_from_config` so this
    // crate stays free of the cfg layer.

    pub fn set_configured_peers(&self, value: usize) {
        self.configured_peers.store(value as u64, Ordering::Relaxed);
    }

    pub fn inc_active_sessions(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active_sessions(&self) {
        self.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_inbound_sessions(&self) {
        self.inbound_sessions_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_outbound_connect_attempts(&self) {
        self.outbound_connect_attempts_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_outbound_connect_failures(&self) {
        self.outbound_connect_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_transport_bytes_rx(&self, value: u64) {
        self.transport_bytes_rx_total
            .fetch_add(value, Ordering::Relaxed);
    }

    pub fn add_transport_bytes_tx(&self, value: u64) {
        self.transport_bytes_tx_total
            .fetch_add(value, Ordering::Relaxed);
    }

    // ── Per-plane increment methods ───────────────────────────────────────────

    pub fn inc_session_handshake_failures(&self) {
        self.session_handshake_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    // ── sleep / wake metrics ──────────────────────────────────────

    /// Increment when a valid `SleepAdvertisement` is applied to the mailbox.
    pub fn inc_sleep_advertisements_accepted(&self) {
        self.sleep_advertisements_accepted_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_dht_store(&self) {
        self.dht_store_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_dht_lookup(&self) {
        self.dht_lookup_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Add `count` to the replica-publish counter. `count` is the number of
    /// STORE frames successfully queued during one re-replication tick (across
    /// one key); summing across all keys per tick is the per-tick fan-out total.
    pub fn add_replicas_published(&self, count: u64) {
        self.replicas_published_total
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Increment when one re-replication attempt found zero remote peers — i.e.
    /// the local DHT routing table had no closest contacts to fan out to.
    pub fn inc_replicas_under_count(&self) {
        self.replicas_under_count_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_mesh_relay_hops(&self) {
        self.mesh_relay_hops_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_decrypt_failures(&self) {
        self.decrypt_failures_total.fetch_add(1, Ordering::Relaxed);
    }

    /// 6.33 visibility slice: per-stage rekey counters surface
    /// the session-rekey state-machine progress в Prometheus так оператор
    /// видит "rekey-init storm without acks" before sessions tear down.
    pub fn inc_rekey_init_sent(&self) {
        self.rekey_init_sent_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rekey_init_received(&self) {
        self.rekey_init_received_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rekey_ack_sent(&self) {
        self.rekey_ack_sent_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rekey_ack_received(&self) {
        self.rekey_ack_received_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Frame decrypted via а stashed prev cipher (rekey-grace fallback).
    pub fn inc_rekey_decrypt_fallback(&self) {
        self.rekey_decrypt_fallback_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Prev-cipher entry evicted from the ring buffer because the cap was
    /// hit — rekeys arrived faster than the 30 s grace expired.
    pub fn inc_rekey_grace_cap_eviction(&self) {
        self.rekey_grace_cap_evictions_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// `RekeyKeptInit` frame pushed onto the wire — emitted by the
    /// lower-`node_id` side of а mutual rekey-init collision к signal
    /// the loser к back off.
    pub fn inc_rekey_kept_init_sent(&self) {
        self.rekey_kept_init_sent_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// `RekeyKeptInit` frame received — own pending init reset to Idle,
    /// time-threshold trigger pushed forward.
    pub fn inc_rekey_kept_init_received(&self) {
        self.rekey_kept_init_received_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_storage_evictions(&self) {
        self.storage_evictions_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_route_miss(&self) {
        self.route_miss_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_discovery_triggered(&self) {
        self.discovery_triggered_total
            .fetch_add(1, Ordering::Relaxed);
    }

    // ── 461.10: denial/drop counters ───────────────────────────

    pub fn inc_unknown_origin_gossip_rejected(&self) {
        self.unknown_origin_gossip_rejected_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_exit_proxy_dest_denied(&self) {
        self.exit_proxy_dest_denied_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_socks5_accepts_throttled(&self) {
        self.socks5_accepts_throttled_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_gateway_lift_seen_evicted(&self) {
        self.gateway_lift_seen_evicted_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_send_to_failed(&self) {
        self.send_to_failed_total.fetch_add(1, Ordering::Relaxed);
    }

    /// D5: RelayChain frame dropped because local node is not
    /// relay-capable (`anonymity_x25519_sk` is `None`).
    pub fn inc_dropped_relay_frames(&self) {
        self.dropped_relay_frames_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// a session write exceeded `WRITE_PROGRESS_TIMEOUT` without
    /// completing — TCP backpressure deadlock signature. Operator alert
    /// trigger for "edge X has stuck sockets" diagnostic.
    pub fn inc_session_write_stalled(&self) {
        self.session_write_stalled_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// outbound wire frame dropped because the
    /// `wire_tx`/`wire_rx` channel was at capacity — writer task is
    /// falling behind. Critical: this never blocks the read path.
    pub fn inc_session_wire_dropped(&self) {
        self.session_wire_dropped_total
            .fetch_add(1, Ordering::Relaxed);
    }

    // ── PoW-Gated Rendezvous (Slice 7) ───────────────────────────

    pub fn inc_rendezvous_requests_received(&self) {
        self.rendezvous_requests_received_total
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_rendezvous_requests_granted(&self) {
        self.rendezvous_requests_granted_total
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_rendezvous_requests_rejected_decode(&self) {
        self.rendezvous_requests_rejected_decode_total
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_rendezvous_requests_rejected_verify(&self) {
        self.rendezvous_requests_rejected_verify_total
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_rendezvous_requests_rejected_not_our_target(&self) {
        self.rendezvous_requests_rejected_not_our_target_total
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_rendezvous_requests_rejected_rate_limit(&self) {
        self.rendezvous_requests_rejected_rate_limit_total
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_rendezvous_requests_rejected_concurrency(&self) {
        self.rendezvous_requests_rejected_concurrency_total
            .fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_rendezvous_requests_rejected_bind_failed(&self) {
        self.rendezvous_requests_rejected_bind_failed_total
            .fetch_add(1, Ordering::Relaxed);
    }
    /// Increment the in-use-slots gauge — called когда an on-demand
    /// listener gets bound + its accept task spawns.
    pub fn inc_rendezvous_slots_in_use(&self) {
        self.rendezvous_slots_in_use.fetch_add(1, Ordering::Relaxed);
    }
    /// Decrement the in-use-slots gauge — called когда an on-demand
    /// listener's accept task exits (TTL OR budget exhausted).
    pub fn dec_rendezvous_slots_in_use(&self) {
        // Saturating sub via CAS loop к avoid underflow на races.
        loop {
            let cur = self.rendezvous_slots_in_use.load(Ordering::Relaxed);
            if cur == 0 {
                return;
            }
            if self
                .rendezvous_slots_in_use
                .compare_exchange(cur, cur - 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }

    /// Record a route recovery (route found after a prior miss).
    pub fn inc_route_recovery(&self) {
        self.route_recovery_total.fetch_add(1, Ordering::Relaxed);
    }

    /// iterative-DHT fallback was triggered — legacy
    /// `RouteRequest` flood had exhausted its retries и we fall through
    /// к the relay-aware `RecursiveQuery(FIND_NODE)` path.
    pub fn inc_dht_fallback_triggered(&self) {
        self.dht_fallback_triggered_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// iterative-DHT fallback resolved — `RecursiveResponse`
    /// arrived within budget и dispatcher populated `route_cache`.
    pub fn inc_dht_fallback_resolved(&self) {
        self.dht_fallback_resolved_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// iterative-DHT fallback timed out without а response.
    pub fn inc_dht_fallback_miss(&self) {
        self.dht_fallback_miss_total.fetch_add(1, Ordering::Relaxed);
    }

    /// route-miss event dropped due к pending-
    /// recursive backpressure (fallback skipped).
    pub fn inc_dht_fallback_skipped_backpressure(&self) {
        self.dht_fallback_skipped_backpressure_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// set the current adaptive-effective timeout
    /// (ms) — exposed as а Prometheus gauge so operators can correlate
    /// timeout climbs с miss-rate spikes.
    pub fn set_dht_fallback_effective_timeout_ms(&self, ms: u64) {
        self.dht_fallback_effective_timeout_ms
            .store(ms, Ordering::Relaxed);
    }

    /// Partition-recovery watchdog re-dialed the bootstrap list.
    pub fn inc_bootstrap_watchdog_retries(&self) {
        self.bootstrap_watchdog_retries_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Push a reachability event into the sliding window and return the
    /// current score (recoveries / window_size).
    ///
    /// `true` = route recovered (success).
    /// `false` = route miss with no recovery (failure).
    ///
    /// The window is capped at `REACHABILITY_WINDOW` entries; older events
    /// are evicted as new ones arrive. Events older than
    /// `REACHABILITY_EVENT_TTL` are also dropped before scoring so a
    /// partition at startup doesn't keep the gauge stuck at 0 once the
    /// cache is warm.
    pub fn record_reachability_event(&self, success: bool) -> f64 {
        let mut window = self
            .reachability_window
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let now = std::time::Instant::now();
        // Drop events older than the TTL.
        while let Some(&(t, _)) = window.front() {
            if now.duration_since(t) > REACHABILITY_EVENT_TTL {
                window.pop_front();
            } else {
                break;
            }
        }
        if window.len() >= REACHABILITY_WINDOW {
            window.pop_front();
        }
        window.push_back((now, success));
        let hits = window.iter().filter(|(_, v)| *v).count();
        hits as f64 / window.len() as f64
    }

    /// Return the current reachability score without pushing a new event.
    /// Stale events past `REACHABILITY_EVENT_TTL` are evicted at read time
    /// so the gauge can recover to 1.0 when no new events occur.
    pub fn reachability_score(&self) -> f64 {
        let mut window = self
            .reachability_window
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let now = std::time::Instant::now();
        while let Some(&(t, _)) = window.front() {
            if now.duration_since(t) > REACHABILITY_EVENT_TTL {
                window.pop_front();
            } else {
                break;
            }
        }
        if window.is_empty() {
            return 1.0; // no data (or all stale) — assume healthy
        }
        let hits = window.iter().filter(|(_, v)| *v).count();
        hits as f64 / window.len() as f64
    }

    /// Record the RTT of a successfully-selected route for avg-RTT tracking.
    pub fn record_route_selection_rtt(&self, rtt_ms: u32) {
        self.route_selection_rtt_sum
            .fetch_add(rtt_ms as u64, Ordering::Relaxed);
        self.route_selection_rtt_count
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record |vivaldi_estimate - measured_rtt| for prediction-error tracking.
    pub fn record_vivaldi_prediction_error(&self, estimate_ms: f64, measured_ms: u32) {
        let err = (estimate_ms - measured_ms as f64).abs() as u64;
        self.vivaldi_error_sum.fetch_add(err, Ordering::Relaxed);
        self.vivaldi_error_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot the local Vivaldi coordinate into metrics so it is visible via
    /// Prometheus and the admin metrics snapshot. Call this after every
    /// `VivaldiCoord::update` and after loading a persisted snapshot.
    ///
    /// takes raw `(x, y, height, error)` instead of a concrete
    /// `VivaldiCoord` so this crate stays free of `node::routing`.
    pub fn record_vivaldi_coord(&self, x: f64, y: f64, height: f64, error: f64) {
        self.vivaldi_coord_x_bits
            .store(x.to_bits(), Ordering::Relaxed);
        self.vivaldi_coord_y_bits
            .store(y.to_bits(), Ordering::Relaxed);
        self.vivaldi_coord_height_bits
            .store(height.to_bits(), Ordering::Relaxed);
        self.vivaldi_coord_error_bits
            .store(error.to_bits(), Ordering::Relaxed);
    }

    pub fn inc_rate_limit_drops(&self) {
        self.rate_limit_drops_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_backpressure_received(&self) {
        self.backpressure_received_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_ban_actions(&self) {
        self.ban_actions_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rt_frames_rx(&self) {
        self.rt_frames_rx_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the outbound APP_RT_DATA frame counter.
    ///
    /// Called from the IPC server `handle_rt_send` path when a
    /// local app's `APP_RT_SEND` frame is dispatched to a remote peer session.
    /// IPC-server only (`#[cfg(unix)]`); silenced on Windows until.
    pub fn inc_rt_frames_tx(&self) {
        self.rt_frames_tx_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the counter for successfully reassembled chunks.
    pub fn inc_chunks_reassembled(&self) {
        self.chunks_reassembled_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Check for a sequence-number gap on an incoming APP_RT_DATA stream and
    /// if a gap is detected, increment `rt_seq_gaps_total`.
    ///
    /// `app_id` and `endpoint_id` identify the stream; `seq` is the frame's
    /// sequence number. The first frame seen on each stream is never a gap.
    ///
    /// A gap is defined as `seq > last_seq + 1` (forward gap / loss).
    /// Out-of-order / duplicate frames (`seq <= last_seq`) are not counted as
    /// gaps here — they are loss-tolerant by design.
    ///
    /// The per-stream table is bounded to `RT_SEQ_TRACKER_MAX` entries;
    /// new streams are silently ignored when the table is full.
    pub fn check_and_count_rt_seq_gap(&self, app_id: &[u8; 32], endpoint_id: u32, seq: u32) {
        const RT_SEQ_TRACKER_MAX: usize = 2048;
        let key =
            u64::from_le_bytes(app_id[..8].try_into().unwrap_or([0u8; 8])) ^ (endpoint_id as u64);
        let mut map = self.rt_last_seq.lock().unwrap_or_else(|p| p.into_inner());
        match map.get_mut(&key) {
            Some(last) => {
                if seq > last.wrapping_add(1) {
                    self.rt_seq_gaps_total.fetch_add(1, Ordering::Relaxed);
                }
                // Always update to the latest seq to stay current.
                if seq > *last || seq < last.wrapping_sub(64) {
                    *last = seq;
                }
            }
            None => {
                if map.len() < RT_SEQ_TRACKER_MAX {
                    map.insert(key, seq);
                }
                // First frame on this stream — no gap to report.
            }
        }
    }

    pub fn inc_app_msg_channel_full(&self) {
        self.app_msg_channel_full_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_app_msg_channel_closed(&self) {
        self.app_msg_channel_closed_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Returns a cloned `Arc` to the session tx-drop counter.
    ///
    /// Pass this to `SessionTxRegistry::with_capacity_and_drop_counter` so
    /// drops are reflected in `NodeMetrics::snapshot`.
    pub fn session_tx_drops_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.session_tx_drops_total)
    }

    /// Returns a cloned `Arc` to the session outbox-drop counter.
    ///
    /// Pass this to `SessionOutbox::with_capacity_and_drop_counter` so drops
    /// are reflected in `NodeMetrics::snapshot`.
    pub fn session_outbox_drops_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.session_outbox_drops_total)
    }

    /// g: returns a cloned `Arc` to the priority-queue
    /// drop counter. Pass this to
    /// `PriorityQueue::with_capacity_and_drop_counter` so overflow
    /// shedding is reflected in Prometheus same-scrape.
    pub fn priority_queue_drops_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.priority_queue_drops_total)
    }

    /// IPC-server only (`#[cfg(unix)]`); silenced on Windows until.
    pub fn inc_ipc_delivery_drops(&self) {
        self.ipc_delivery_drops_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record `n` parallel path sends triggered by multi-path delivery.
    pub fn inc_multi_path_sends(&self, n: u64) {
        self.multi_path_sends_total.fetch_add(n, Ordering::Relaxed);
    }

    // ── DHT-routed forwarding ──────────────────────────────

    pub fn inc_recursive_relay_initiated(&self) {
        self.recursive_relay_initiated_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_recursive_relay_forwarded(&self) {
        self.recursive_relay_forwarded_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_recursive_relay_delivered(&self) {
        self.recursive_relay_delivered_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_route_cache_hits(&self) {
        self.route_cache_hits_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_gossip_announces_rx(&self) {
        self.gossip_announces_rx_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        macro_rules! load {
            ($f:ident) => {
                self.$f.load(Ordering::Relaxed)
            };
        }
        MetricsSnapshot {
            configured_peers: load!(configured_peers),
            active_sessions: load!(active_sessions),
            inbound_sessions_total: load!(inbound_sessions_total),
            outbound_connect_attempts_total: load!(outbound_connect_attempts_total),
            outbound_connect_failures_total: load!(outbound_connect_failures_total),
            transport_bytes_rx_total: load!(transport_bytes_rx_total),
            transport_bytes_tx_total: load!(transport_bytes_tx_total),
            session_handshake_failures_total: load!(session_handshake_failures_total),
            dht_store_total: load!(dht_store_total),
            dht_lookup_total: load!(dht_lookup_total),
            replicas_published_total: load!(replicas_published_total),
            replicas_under_count_total: load!(replicas_under_count_total),
            mesh_relay_hops_total: load!(mesh_relay_hops_total),
            decrypt_failures_total: load!(decrypt_failures_total),
            rekey_init_sent_total: load!(rekey_init_sent_total),
            rekey_init_received_total: load!(rekey_init_received_total),
            rekey_ack_sent_total: load!(rekey_ack_sent_total),
            rekey_ack_received_total: load!(rekey_ack_received_total),
            rekey_decrypt_fallback_total: load!(rekey_decrypt_fallback_total),
            rekey_grace_cap_evictions_total: load!(rekey_grace_cap_evictions_total),
            rekey_kept_init_sent_total: load!(rekey_kept_init_sent_total),
            rekey_kept_init_received_total: load!(rekey_kept_init_received_total),
            storage_evictions_total: load!(storage_evictions_total),
            route_miss_total: load!(route_miss_total),
            discovery_triggered_total: load!(discovery_triggered_total),
            dht_fallback_triggered_total: load!(dht_fallback_triggered_total),
            dht_fallback_resolved_total: load!(dht_fallback_resolved_total),
            dht_fallback_miss_total: load!(dht_fallback_miss_total),
            dht_fallback_skipped_backpressure_total: load!(dht_fallback_skipped_backpressure_total),
            dht_fallback_effective_timeout_ms: load!(dht_fallback_effective_timeout_ms),
            bootstrap_watchdog_retries_total: load!(bootstrap_watchdog_retries_total),
            route_recovery_total: load!(route_recovery_total),
            network_reachability_score: self.reachability_score(),
            route_selection_avg_rtt: self
                .route_selection_rtt_sum
                .load(Ordering::Relaxed)
                .checked_div(self.route_selection_rtt_count.load(Ordering::Relaxed))
                .unwrap_or(0),
            vivaldi_prediction_error: self
                .vivaldi_error_sum
                .load(Ordering::Relaxed)
                .checked_div(self.vivaldi_error_count.load(Ordering::Relaxed))
                .unwrap_or(0),
            vivaldi_coord_x: f64::from_bits(self.vivaldi_coord_x_bits.load(Ordering::Relaxed)),
            vivaldi_coord_y: f64::from_bits(self.vivaldi_coord_y_bits.load(Ordering::Relaxed)),
            vivaldi_coord_height: f64::from_bits(
                self.vivaldi_coord_height_bits.load(Ordering::Relaxed),
            ),
            vivaldi_coord_error: f64::from_bits(
                self.vivaldi_coord_error_bits.load(Ordering::Relaxed),
            ),
            rate_limit_drops_total: load!(rate_limit_drops_total),
            backpressure_received_total: load!(backpressure_received_total),
            ban_actions_total: load!(ban_actions_total),
            rt_frames_rx_total: load!(rt_frames_rx_total),
            rt_frames_tx_total: load!(rt_frames_tx_total),
            rt_seq_gaps_total: load!(rt_seq_gaps_total),
            app_msg_channel_full_total: load!(app_msg_channel_full_total),
            app_msg_channel_closed_total: load!(app_msg_channel_closed_total),
            session_tx_drops_total: load!(session_tx_drops_total),
            session_outbox_drops_total: load!(session_outbox_drops_total),
            priority_queue_drops_total: load!(priority_queue_drops_total),
            ipc_delivery_drops_total: load!(ipc_delivery_drops_total),
            multi_path_sends_total: load!(multi_path_sends_total),
            chunks_reassembled_total: load!(chunks_reassembled_total),
            sleep_advertisements_accepted_total: load!(sleep_advertisements_accepted_total),
            recursive_relay_initiated_total: load!(recursive_relay_initiated_total),
            recursive_relay_forwarded_total: load!(recursive_relay_forwarded_total),
            recursive_relay_delivered_total: load!(recursive_relay_delivered_total),
            route_cache_hits_total: load!(route_cache_hits_total),
            gossip_announces_rx_total: load!(gossip_announces_rx_total),
            unknown_origin_gossip_rejected_total: load!(unknown_origin_gossip_rejected_total),
            exit_proxy_dest_denied_total: load!(exit_proxy_dest_denied_total),
            socks5_accepts_throttled_total: load!(socks5_accepts_throttled_total),
            gateway_lift_seen_evicted_total: load!(gateway_lift_seen_evicted_total),
            send_to_failed_total: load!(send_to_failed_total),
            dropped_relay_frames_total: load!(dropped_relay_frames_total),
            session_write_stalled_total: load!(session_write_stalled_total),
            session_wire_dropped_total: load!(session_wire_dropped_total),
            rendezvous_requests_received_total: load!(rendezvous_requests_received_total),
            rendezvous_requests_granted_total: load!(rendezvous_requests_granted_total),
            rendezvous_requests_rejected_decode_total: load!(
                rendezvous_requests_rejected_decode_total
            ),
            rendezvous_requests_rejected_verify_total: load!(
                rendezvous_requests_rejected_verify_total
            ),
            rendezvous_requests_rejected_not_our_target_total: load!(
                rendezvous_requests_rejected_not_our_target_total
            ),
            rendezvous_requests_rejected_rate_limit_total: load!(
                rendezvous_requests_rejected_rate_limit_total
            ),
            rendezvous_requests_rejected_concurrency_total: load!(
                rendezvous_requests_rejected_concurrency_total
            ),
            rendezvous_requests_rejected_bind_failed_total: load!(
                rendezvous_requests_rejected_bind_failed_total
            ),
            rendezvous_slots_in_use: load!(rendezvous_slots_in_use),
        }
    }

    pub fn render_prometheus(&self) -> String {
        let s = self.snapshot();
        let mut out = String::with_capacity(1024);
        macro_rules! gauge {
            ($name:expr, $val:expr) => {
                out.push_str(&format!("# TYPE {} gauge\n{} {}\n", $name, $name, $val));
            };
        }
        macro_rules! counter {
            ($name:expr, $val:expr) => {
                out.push_str(&format!("# TYPE {} counter\n{} {}\n", $name, $name, $val));
            };
        }
        // Transport
        gauge!("veil_configured_peers", s.configured_peers);
        gauge!("veil_active_sessions", s.active_sessions);
        counter!("veil_inbound_sessions_total", s.inbound_sessions_total);
        counter!(
            "veil_outbound_connect_attempts_total",
            s.outbound_connect_attempts_total
        );
        counter!(
            "veil_outbound_connect_failures_total",
            s.outbound_connect_failures_total
        );
        counter!("veil_transport_bytes_rx_total", s.transport_bytes_rx_total);
        counter!("veil_transport_bytes_tx_total", s.transport_bytes_tx_total);
        // Session
        counter!(
            "veil_session_handshake_failures_total",
            s.session_handshake_failures_total
        );
        // DHT
        counter!("veil_dht_store_total", s.dht_store_total);
        counter!("veil_dht_lookup_total", s.dht_lookup_total);
        counter!("veil_replicas_published_total", s.replicas_published_total);
        counter!(
            "veil_replicas_under_count_total",
            s.replicas_under_count_total
        );
        // Mesh
        counter!("veil_mesh_relay_hops_total", s.mesh_relay_hops_total);
        // Crypto
        counter!("veil_decrypt_failures_total", s.decrypt_failures_total);
        // Session rekey
        counter!("veil_rekey_init_sent_total", s.rekey_init_sent_total);
        counter!(
            "veil_rekey_init_received_total",
            s.rekey_init_received_total
        );
        counter!("veil_rekey_ack_sent_total", s.rekey_ack_sent_total);
        counter!("veil_rekey_ack_received_total", s.rekey_ack_received_total);
        counter!(
            "veil_rekey_decrypt_fallback_total",
            s.rekey_decrypt_fallback_total
        );
        counter!(
            "veil_rekey_grace_cap_evictions_total",
            s.rekey_grace_cap_evictions_total
        );
        counter!(
            "veil_rekey_kept_init_sent_total",
            s.rekey_kept_init_sent_total
        );
        counter!(
            "veil_rekey_kept_init_received_total",
            s.rekey_kept_init_received_total
        );
        // Storage lifecycle
        counter!("veil_storage_evictions_total", s.storage_evictions_total);
        // Route convergence
        counter!("veil_route_miss_total", s.route_miss_total);
        counter!(
            "veil_discovery_triggered_total",
            s.discovery_triggered_total
        );
        counter!("veil_route_recovery_total", s.route_recovery_total);
        // Iterative-DHT fallback
        counter!(
            "veil_dht_fallback_triggered_total",
            s.dht_fallback_triggered_total
        );
        counter!(
            "veil_dht_fallback_resolved_total",
            s.dht_fallback_resolved_total
        );
        counter!("veil_dht_fallback_miss_total", s.dht_fallback_miss_total);
        counter!(
            "veil_dht_fallback_skipped_backpressure_total",
            s.dht_fallback_skipped_backpressure_total
        );
        gauge!(
            "veil_dht_fallback_effective_timeout_ms",
            s.dht_fallback_effective_timeout_ms
        );
        counter!(
            "veil_bootstrap_watchdog_retries_total",
            s.bootstrap_watchdog_retries_total
        );
        gauge!(
            "veil_network_reachability_score",
            s.network_reachability_score
        );
        // Adaptive routing
        gauge!("veil_route_selection_avg_rtt_ms", s.route_selection_avg_rtt);
        gauge!(
            "veil_vivaldi_prediction_error_ms",
            s.vivaldi_prediction_error
        );
        gauge!("veil_vivaldi_coord_x", s.vivaldi_coord_x);
        gauge!("veil_vivaldi_coord_y", s.vivaldi_coord_y);
        gauge!("veil_vivaldi_coord_height", s.vivaldi_coord_height);
        gauge!("veil_vivaldi_coord_error", s.vivaldi_coord_error);
        // Abuse
        counter!("veil_rate_limit_drops_total", s.rate_limit_drops_total);
        counter!(
            "veil_backpressure_received_total",
            s.backpressure_received_total
        );
        counter!("veil_ban_actions_total", s.ban_actions_total);
        // Real-time
        counter!(
            "veil_rt_frames_total",
            s.rt_frames_rx_total + s.rt_frames_tx_total
        );
        counter!("veil_rt_frames_rx_total", s.rt_frames_rx_total);
        counter!("veil_rt_frames_tx_total", s.rt_frames_tx_total);
        counter!("veil_rt_seq_gaps_total", s.rt_seq_gaps_total);
        // Application layer
        counter!(
            "veil_app_msg_channel_full_total",
            s.app_msg_channel_full_total
        );
        counter!(
            "veil_app_msg_channel_closed_total",
            s.app_msg_channel_closed_total
        );
        // Session queue backpressure
        counter!("veil_session_tx_drops_total", s.session_tx_drops_total);
        counter!(
            "veil_session_outbox_drops_total",
            s.session_outbox_drops_total
        );
        counter!(
            "veil_priority_queue_drops_total",
            s.priority_queue_drops_total
        );
        // IPC delivery backpressure
        counter!("veil_ipc_delivery_drops_total", s.ipc_delivery_drops_total);
        // Multi-path delivery
        counter!("veil_multi_path_sends_total", s.multi_path_sends_total);
        // Chunked transfer
        counter!("veil_chunks_reassembled_total", s.chunks_reassembled_total);
        // Mobile sleep
        counter!(
            "veil_sleep_advertisements_accepted_total",
            s.sleep_advertisements_accepted_total
        );
        // DHT-routed forwarding
        counter!(
            "veil_recursive_relay_initiated_total",
            s.recursive_relay_initiated_total
        );
        counter!(
            "veil_recursive_relay_forwarded_total",
            s.recursive_relay_forwarded_total
        );
        counter!(
            "veil_recursive_relay_delivered_total",
            s.recursive_relay_delivered_total
        );
        counter!("veil_route_cache_hits_total", s.route_cache_hits_total);
        counter!(
            "veil_gossip_announces_rx_total",
            s.gossip_announces_rx_total
        );
        // Denial/drop counters
        counter!(
            "veil_unknown_origin_gossip_rejected_total",
            s.unknown_origin_gossip_rejected_total
        );
        counter!(
            "veil_exit_proxy_dest_denied_total",
            s.exit_proxy_dest_denied_total
        );
        counter!(
            "veil_socks5_accepts_throttled_total",
            s.socks5_accepts_throttled_total
        );
        counter!(
            "veil_gateway_lift_seen_evicted_total",
            s.gateway_lift_seen_evicted_total
        );
        counter!("veil_send_to_failed_total", s.send_to_failed_total);
        counter!(
            "veil_dropped_relay_frames_total",
            s.dropped_relay_frames_total
        );
        counter!(
            "veil_session_write_stalled_total",
            s.session_write_stalled_total
        );
        counter!(
            "veil_session_wire_dropped_total",
            s.session_wire_dropped_total
        );
        // ── PoW-Gated Rendezvous (Slice 7) ─────────────────────────
        counter!(
            "veil_rendezvous_requests_received_total",
            s.rendezvous_requests_received_total
        );
        counter!(
            "veil_rendezvous_requests_granted_total",
            s.rendezvous_requests_granted_total
        );
        counter!(
            "veil_rendezvous_requests_rejected_decode_total",
            s.rendezvous_requests_rejected_decode_total
        );
        counter!(
            "veil_rendezvous_requests_rejected_verify_total",
            s.rendezvous_requests_rejected_verify_total
        );
        counter!(
            "veil_rendezvous_requests_rejected_not_our_target_total",
            s.rendezvous_requests_rejected_not_our_target_total
        );
        counter!(
            "veil_rendezvous_requests_rejected_rate_limit_total",
            s.rendezvous_requests_rejected_rate_limit_total
        );
        counter!(
            "veil_rendezvous_requests_rejected_concurrency_total",
            s.rendezvous_requests_rejected_concurrency_total
        );
        counter!(
            "veil_rendezvous_requests_rejected_bind_failed_total",
            s.rendezvous_requests_rejected_bind_failed_total
        );
        gauge!("veil_rendezvous_slots_in_use", s.rendezvous_slots_in_use);
        out
    }
}

fn format_log_line(level: &str, event: &str, message: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "[{}.{:03}] {:<5} {:<18} {}",
        now.as_secs(),
        now.subsec_millis(),
        level,
        event,
        message
    )
}

fn format_log_json(level: &str, event: &str, message: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ts_ms = now.as_millis();
    // Manual JSON serialization — no external crate needed.
    // SECURITY (audit 2026-05-29, log-injection fix): RFC 8259 requires
    // control characters U+0000–U+001F inside JSON strings to be escaped.
    // The previous escape only handled `\` and `"`, so an attacker-
    // controlled field carrying а raw newline/CR (e.g. а peer-supplied
    // name echoed into а log event) could inject forged log lines OR
    // produce malformed JSON що breaks downstream SIEM parsers.  Escape
    // the standard short forms (\n \r \t \" \\ \b \f) and \u00XX for the
    // remaining C0 controls.
    let escape = |s: &str| {
        let mut out = String::with_capacity(s.len() + 8);
        for ch in s.chars() {
            match ch {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{08}' => out.push_str("\\b"),
                '\u{0C}' => out.push_str("\\f"),
                c if (c as u32) < 0x20 => {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => out.push(c),
            }
        }
        out
    };
    format!(
        "{{\"@timestamp\":{ts_ms},\"level\":\"{}\",\"event\":\"{}\",\"message\":\"{}\"}}",
        escape(level),
        escape(event),
        escape(message),
    )
}

// ── Cross-crate trait impls ────────────────────────────────────────
//
// `NodeMetrics` and `NodeLogger` live here, but the traits they implement
// (MeshMetrics, AppMetrics, DhtMetrics, AbuseLogger, UpdateLogger) live in
// the respective domain crates. Co-located in this crate so the orphan
// rule is satisfied — veilcore can pass `Arc<NodeMetrics>` directly
// into trait-typed slots without a wrapper.

impl veil_mesh::MeshMetrics for NodeMetrics {
    fn inc_gateway_lift_seen_evicted(&self) {
        NodeMetrics::inc_gateway_lift_seen_evicted(self)
    }
}

impl veil_app::AppMetrics for NodeMetrics {
    fn inc_app_msg_channel_full(&self) {
        NodeMetrics::inc_app_msg_channel_full(self)
    }
    fn inc_app_msg_channel_closed(&self) {
        NodeMetrics::inc_app_msg_channel_closed(self)
    }
}

impl veil_dht::DhtMetrics for NodeMetrics {
    fn inc_dht_store(&self) {
        NodeMetrics::inc_dht_store(self)
    }
    fn inc_dht_lookup(&self) {
        NodeMetrics::inc_dht_lookup(self)
    }
}

impl veil_update::UpdateLogger for NodeLogger {
    fn info(&self, event: &str, message: &str) {
        NodeLogger::info(self, event, message)
    }
    fn warn(&self, event: &str, message: &str) {
        NodeLogger::warn(self, event, message)
    }
}

impl veil_abuse::AbuseLogger for NodeLogger {
    fn warn(&self, event: &str, message: &str) {
        NodeLogger::warn(self, event, message)
    }
}

impl veil_routing::RoutingLogger for NodeLogger {
    fn warn(&self, event: &str, message: &str) {
        NodeLogger::warn(self, event, message)
    }
    fn info(&self, event: &str, message: &str) {
        NodeLogger::info(self, event, message)
    }
}

impl veil_pex::PexLogger for NodeLogger {
    fn info(&self, event: &str, message: &str) {
        NodeLogger::info(self, event, message)
    }
    fn warn(&self, event: &str, message: &str) {
        NodeLogger::warn(self, event, message)
    }
}

impl veil_proxy::ProxyMetrics for NodeMetrics {
    fn inc_exit_proxy_dest_denied(&self) {
        NodeMetrics::inc_exit_proxy_dest_denied(self)
    }
    fn inc_socks5_accepts_throttled(&self) {
        NodeMetrics::inc_socks5_accepts_throttled(self)
    }
}

impl veil_routing::RoutingMetrics for NodeMetrics {
    fn inc_discovery_triggered(&self) {
        NodeMetrics::inc_discovery_triggered(self)
    }
    fn inc_route_recovery(&self) {
        NodeMetrics::inc_route_recovery(self)
    }
    fn record_reachability_event(&self, success: bool) -> f64 {
        NodeMetrics::record_reachability_event(self, success)
    }
    fn inc_dht_fallback_triggered(&self) {
        NodeMetrics::inc_dht_fallback_triggered(self)
    }
    fn inc_dht_fallback_resolved(&self) {
        NodeMetrics::inc_dht_fallback_resolved(self)
    }
    fn inc_dht_fallback_miss(&self) {
        NodeMetrics::inc_dht_fallback_miss(self)
    }
}

impl veil_ipc::IpcMetrics for NodeMetrics {
    fn inc_ipc_delivery_drops(&self) {
        NodeMetrics::inc_ipc_delivery_drops(self)
    }
    fn inc_rt_frames_tx(&self) {
        NodeMetrics::inc_rt_frames_tx(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// SECURITY (audit 2026-05-29, log-injection regression): control
    /// characters in attacker-controlled fields MUST be escaped so they
    /// cannot inject forged log lines or break JSON parsers downstream.
    #[test]
    fn json_log_escapes_control_chars() {
        let line = format_log_json("info", "evt\nFORGED", "msg\r\nwith\ttabs and \u{01} ctrl");
        // No raw newline/CR/tab survives inside the serialized line.
        assert!(
            !line.contains('\n') && !line.contains('\r') && !line.contains('\t'),
            "raw control chars must not appear in JSON log line: {line:?}"
        );
        // The injected newline becomes the escaped short form.
        assert!(line.contains("evt\\nFORGED"), "newline must be \\n-escaped");
        assert!(
            line.contains("\\u0001"),
            "C0 control must be \\u00XX-escaped"
        );
        // Result is still a single line (the whole point).
        assert_eq!(line.lines().count(), 1, "JSON log must be one line");
    }

    #[test]
    fn from_parts_stderr_succeeds() {
        let logger =
            NodeLogger::from_parts(LogsConfig::Stderr, None, LogLevel::Info, LogFormat::Text)
                .expect("stderr sink ok");
        // smoke: logging to stderr must not panic
        logger.info("test.event", "hello");
    }

    #[test]
    fn from_parts_file_writes_lines() {
        let path = std::env::temp_dir().join(format!(
            "veil-obs-{}-{}.log",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let logger = NodeLogger::from_parts(
            LogsConfig::File,
            Some(&path),
            LogLevel::Info,
            LogFormat::Text,
        )
        .expect("file sink ok");
        logger.info("node.start", "config=/tmp/x");
        let content = fs::read_to_string(&path).expect("log file");
        let _ = fs::remove_file(&path);
        assert!(content.contains("INFO"));
        assert!(content.contains("node.start"));
    }

    #[test]
    fn from_parts_file_requires_path() {
        let err = NodeLogger::from_parts(LogsConfig::File, None, LogLevel::Info, LogFormat::Text)
            .expect_err("must reject File sink without log_file");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn metrics_default_constructs_zeroed_counters() {
        let m = NodeMetrics::new();
        let snap = m.snapshot();
        assert_eq!(snap.dht_store_total, 0);
        assert_eq!(snap.dht_lookup_total, 0);
        assert_eq!(snap.app_msg_channel_full_total, 0);
    }

    #[test]
    fn five_route_misses_drops_reachability_score() {
        let m = NodeMetrics::new();
        let mut last = 1.0_f64;
        for _ in 0..5 {
            last = m.record_reachability_event(false);
        }
        assert!(
            last < 0.2,
            "score after 5 misses {last:.4} should drop below 0.2"
        );
    }

    #[test]
    fn record_vivaldi_coord_round_trips_into_snapshot() {
        let m = NodeMetrics::new();
        m.record_vivaldi_coord(1.5, -2.25, 0.125, 0.5);
        let snap = m.snapshot();
        assert!((snap.vivaldi_coord_x - 1.5).abs() < f64::EPSILON);
        assert!((snap.vivaldi_coord_y + 2.25).abs() < f64::EPSILON);
        assert!((snap.vivaldi_coord_height - 0.125).abs() < f64::EPSILON);
        assert!((snap.vivaldi_coord_error - 0.5).abs() < f64::EPSILON);
    }
}
