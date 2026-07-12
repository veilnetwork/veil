use std::path::{Path, PathBuf};
use std::sync::Arc;
use veil_util::lock;

#[cfg(unix)]
extern crate libc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, watch};

use veil_cfg::{Config, ListenId, PeerId};

use super::NodeRuntime;
use crate::admin_transport::{self, AdminStream};
use crate::error::{NodeError, Result};
use crate::types::{ListenConfigEntry, NodeIdBytes, SessionInfo};

pub const ADMIN_PROTOCOL_VERSION: u32 = 1;

/// Maximum number of DHT entries returned by the `DhtList` admin command.
/// Bounds the response so a large (possibly RocksDB-cold-backed) store is
/// never materialized in full into an admin reply. The response carries a
/// `truncated` flag when the store exceeds this.
pub const MAX_ADMIN_DHT_LIST: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminRequest {
    pub version: u32,
    pub command: AdminCommand,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum AdminCommand {
    Run,
    Stop,
    Restart,
    Reload,
    Show,
    /// Report node liveness: health_tick counter + session count.
    /// Returns `AdminResult::Health`. A stalled event loop is detected when
    /// `tick` has not advanced compared to a previous sample.
    Health,
    Listens,
    Sessions,
    DebugPeerConnect {
        peer_id: PeerId,
    },
    DebugNodeAccept {
        listen_id: ListenId,
    },
    /// Send veil-level pings and stream RTT replies.
    DebugPing {
        /// Hex-encoded 32-byte node_id of the target.
        target: String,
        #[serde(default = "default_ping_count")]
        count: u32,
        #[serde(default = "default_interval_ms")]
        interval_ms: u64,
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
    },
    /// Send veil-level traceroute probes and stream hop replies.
    DebugTrace {
        /// Hex-encoded 32-byte node_id of the target.
        target: String,
        #[serde(default = "default_max_hops")]
        max_hops: u8,
        #[serde(default = "default_timeout_ms")]
        timeout_ms: u64,
    },
    /// Subscribe to live frame capture.
    DebugCapture {
        /// Optional hex node_id filter; `None` = capture all peers.
        filter_node_id: Option<String>,
        /// Optional frame family filter (0=Session, 1=Control, etc.); `None` = all families.
        filter_family: Option<u8>,
        /// Stop after this many frames; `None` = run until disconnect.
        limit: Option<u32>,
    },
    /// Ban a node (persisted across restarts).
    BanNode {
        node_id: String,
    },
    /// Lift a ban applied by BanNode.
    UnbanNode {
        node_id: String,
    },
    /// List all currently active bans.
    ListBans,
    /// Publish a P-Net DHT-replicated ban. Requires `[network].mode =
    /// "private"`, a local membership cert with `admin: true`, and a
    /// loaded identity signing key. Signs a `BanEntry`, fans it out to
    /// the network through DHT replication, and applies to the local
    /// `BanList`. Other members pick up the record on their next P-Net
    /// ban-sync tick (~60 s).
    PNetBan {
        node_id: String,
        reason: Option<String>,
    },
    /// Kill (disconnect) a session by link_id.
    KillSession {
        link_id: u64,
    },
    /// Show bandwidth utilization stats.
    Bandwidth,
    // ── Introspection ────────────────────────────────────────────
    /// Return a snapshot of all runtime metrics counters.
    Metrics,
    /// List all key-value pairs stored in the local DHT store.
    DhtList,
    /// List all contacts in the DHT Kademlia routing table.
    DhtRouting,
    /// Look up a value in the local DHT store by 32-byte hex key.
    DhtGet {
        key: String,
    },
    /// Look up a value in the DHT via a recursive FIND_VALUE walk.
    /// Falls back to the local store first; if not found, sends a
    /// `RecursiveQuery(FIND_VALUE)` to the K closest active session
    /// peers (sorted by XOR distance to the key) and awaits the reply
    /// up to `timeout_ms` milliseconds. Used by the devnet
    /// cross-node smoke test to verify the FIND_VALUE protocol works
    /// end-to-end without going through the IPC stream API.
    DhtRecursiveGet {
        key: String,
        timeout_ms: u64,
    },
    /// **Source-routed app-message send** (audit batch 2026-05-23).
    /// Builds a `DeliveryMsg::RelayPath` frame from an explicit path of
    /// hex node_ids and hands it off to the first hop's session.  Each
    /// intermediate forwards to the next entry in `path`; the terminal
    /// hop decodes the inner `AppSendPayload` and delivers to the local
    /// app registry.  Works in topologies where DHT routing fails
    /// structurally (e.g. 64-node linear chain) because there is no
    /// route-cache / DHT-walk dependency anywhere.
    RelaySend {
        /// Ordered list of hex-encoded 32-byte node_ids.  First entry
        /// = first hop after sender; last entry = ultimate destination.
        path: Vec<String>,
        /// Destination app's `app_id` (64 hex chars).
        app_id: String,
        /// Destination endpoint number.
        endpoint_id: u32,
        /// Payload bytes (hex-encoded).
        data_hex: String,
    },
    /// Store a key-value pair directly in the local DHT (hex key + hex value).
    DhtPut {
        key: String,
        value: String,
    },
    /// store a key-value pair locally AND fan it out to the
    /// K closest live peers in keyspace via replication
    /// path. Used by `bootstrap publish` so the operator's signed
    /// bundle actually propagates over the network instead of staying
    /// on the publisher's local DHT shard only (`DhtPut` is local-
    /// only). Returns `Ack { message: "replicated to N peers" }`.
    DhtPublishReplicated {
        key: String,
        value: String,
    },
    /// resolve a sovereign IdentityDocument from the DHT and
    /// run full cryptographic verification (signature chain, expiry
    /// windows, sig_key_idx bounds, node_id ↔ master_pubkey binding
    /// and substitution check `doc.node_id == requested_node_id`).
    ///
    /// Distinct [`Self::DhtRecursiveGet`] — that one returns raw
    /// bytes the caller must validate manually (and historically did
    /// not, leaving the resolver wide open to forgery / substitution
    /// attacks). This verb is the **only** safe surface for
    /// production callers that need to act on the resolved identity
    /// (e.g. picking a transport from the document's instance list).
    ResolveIdentity {
        node_id: String,
        timeout_ms: u64,
    },
    /// resolve `@name` → ValidatedIdentity, walking the
    /// NameClaim → IdentityDocument chain with full crypto
    /// verification at every step (PoW difficulty, freshness-hour
    /// skew, name-binding, signature against the resolved document's
    /// active subkey). Accepts both `"alice"` and `"@alice"`.
    ResolveName {
        name: String,
        timeout_ms: u64,
    },
    /// probe NAT traversal candidates for a
    /// peer using any connected peer as the signaling coordinator.
    /// Returns the target's `NatProbeReply` candidates, or an error
    /// if no coordinator could reach the target within the timeout.
    /// Operator-facing diagnostic verb — feeds into the future
    /// outbound-dial-failure auto-trigger path.
    NatProbe {
        target_node_id: String,
        per_coordinator_timeout_ms: u64,
    },
    /// List all attachment records in the local discovery directory.
    DiscoveryList,
    /// List all node IDs currently attached to this gateway.
    GatewayList,
    /// leaf-side mesh view — list of auto-discovered
    /// gateways with active/standby status, RTT, battery, freshness.
    /// Source-of-truth for "why am I (not) connected via X" UX.
    MeshStatus,
    /// bootstrap-chain diag — snapshot every defense layer
    /// (operator config, builtin seeds, DNS, discovered-peer cache) so
    /// the operator can see which layer is empty before a censorship
    /// event takes the others down. No probes / no I/O — strictly a
    /// view over already-loaded state.
    BootstrapStatus,
    /// List route cache entries. When `dst_filter` is `Some`, only the
    /// entries for that destination are returned.
    Routes {
        /// Optional destination node-id (64 hex chars). `None` = full cache.
        #[serde(default)]
        dst_filter: Option<String>,
    },
    /// Manually trigger a route discovery search.
    DiscoverySearch,
    // ── Distributed tracing ─────────────────────────────────────
    /// Retrieve all delivery trace hops for a given `trace_id` (decimal or hex
    /// with `0x` prefix) from the in-memory ring buffer.
    TraceQuery {
        trace_id: String,
    },
    // ── PEX ────────────────────────────────────────────────────
    /// Report PEX state: discovered peers, active walks, last walk time.
    PexStatus,
    /// Dump the runtime's non-configured peer table. Returns
    /// everything in `state.peers` whose `source!= Configured` — i.e. the
    /// live equivalent of `peers_discovered.json` without reading from disk.
    PeersDiscovered,
    // ── Hot-standby handoff B5) ─────────────────────────
    /// Manually drive a hot-standby transport swap on a live session.
    /// Spawns a fresh `WarmProbe` that dials `alt_uri`, then runs the
    /// three-frame handoff protocol (stage (d)): `HandoffInit` over the
    /// primary session → peer's `HandoffAck` → `HandoffAttach` on the
    /// new socket → both sides swap without re-handshake.
    ///
    /// Returns `AdminResult::Ack` on success, `AdminResult::err` on any
    /// failure (unknown peer, no active session, dial refused, HandoffAck
    /// timeout, etc.).
    SwapTransport {
        /// Hex-encoded 32-byte node_id of the peer whose session we're
        /// migrating. Must correspond to a live session.
        peer_node_id: String,
        /// Transport URI to dial for the warm socket — e.g.
        /// `tls://peer.example:9906`, `wss://peer.example:8443/veil`.
        /// Should use a scheme different from the primary for any real
        /// benefit, but this is not enforced (operators can use the
        /// command to migrate within the same scheme for testing).
        alt_uri: String,
    },
    // ── Mobile background-mode ────────────────────────────────
    /// Toggle the runtime's `mobile_background_mode` flag. When `true`
    /// per-session keepalive intervals are multiplied by
    /// `mobile.background_keepalive_multiplier` so sessions survive
    /// OS-level app suspension on mobile. Mobile app GUI wrappers
    /// call this from onPause / onResume hooks. No-op on nodes
    /// where `mobile.background_keepalive_multiplier` is 1 (the
    /// non-mobile default). Returns `AdminResult::Ack`.
    SetMobileBackgroundMode {
        enabled: bool,
    },
    // ── Update mechanism status ───────────────────────────────
    /// Snapshot of the update mechanism state. GUI tray icons /
    /// admin dashboards call this to render "configured / not
    /// configured" + "installed version" + "auto-poll cadence"
    /// without grepping logs or re-running (network-touching)
    /// `update check`. Pure read-over-already-loaded-state — no
    /// I/O, no admin socket roundtrip costs.
    UpdateStatus,
    /// Snapshot of mobile-mode runtime state.
    /// Complements `UpdateStatus` — surfaces battery level + the
    /// resolved scaling factors so GUI dashboards can answer
    /// "why is my keepalive 30 min when I expected 30s?". Also
    /// pure read — battery level read from /sys (Linux only;
    /// non-Linux returns AC sentinel 100), runtime flags read
    /// from the in-memory `AtomicBool`, config knobs from
    /// already-loaded `MobileConfig`.
    MobileStatus,
    /// **Push a new config to the running daemon without going through
    /// the filesystem.**  Distinct from [`Self::Reload`] (which
    /// re-reads `self.config_path`):  here the caller supplies the
    /// raw TOML bytes inline, and optionally requests persistence to
    /// disk.  Intended use cases:
    ///
    /// * **Messenger build** — app stores config in a secure
    ///   storage backend (Keychain / EncryptedSharedPreferences / a
    ///   future TPM-sealed store), not on the regular filesystem,
    ///   and pushes the config to the embedded veil daemon at
    ///   startup time with `persist: false`.
    /// * **Server admin** — programmatically applying configs
    ///   generated by orchestration (Terraform output piped to
    ///   `veil-cli admin apply-config -`) without writing
    ///   intermediate files.  Usually `persist: true` so the new
    ///   config survives daemon restarts.
    /// * **Deferred-init startup** — combined with the `--defer-init`
    ///   CLI flag, the daemon boots without an identity, binds only the
    ///   admin socket, and this command provides the actual config
    ///   that promotes the daemon to full operation.
    ///
    /// Validation is performed before applying — a malformed or
    /// invalid config is rejected with `AdminResult::Error` and leaves
    /// the running daemon unchanged.  Network state is fully
    /// re-initialised on apply (same path as [`Self::Reload`]) —
    /// sessions, transports, and services restart with the new config.
    ApplyConfig {
        /// Raw TOML config content. Pre-parse so invalid TOML
        /// gets rejected with a structured error before touching daemon
        /// state.
        toml_content: String,
        /// Whether to persist the new config to the daemon's
        /// configured `config_path` after a successful apply.
        /// `false` keeps the change in-memory only (the daemon
        /// returns to defaults on next restart).  Default `false`
        /// when omitted, matching the messenger use case.
        #[serde(default)]
        persist: bool,
    },
}

pub fn default_per_peer_disabled() -> i64 {
    -1
}
pub fn default_ping_count() -> u32 {
    4
}
pub fn default_interval_ms() -> u64 {
    1000
}
pub fn default_timeout_ms() -> u64 {
    5000
}
pub fn default_max_hops() -> u8 {
    8
}

// Contains `AdminResult`, whose `Metrics` variant carries f64 fields — no Eq.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct AdminResponse {
    pub version: u32,
    pub result: Option<AdminResult>,
    pub error: Option<String>,
}

impl AdminResponse {
    fn ok(result: AdminResult) -> Self {
        Self {
            version: ADMIN_PROTOCOL_VERSION,
            result: Some(result),
            error: None,
        }
    }

    fn err(error: String) -> Self {
        Self {
            version: ADMIN_PROTOCOL_VERSION,
            result: None,
            error: Some(error),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminHealthReport {
    /// Current value of the monotonic health-tick counter.
    /// Incremented once per second by the maintenance loop.
    pub tick: u64,
    /// Number of currently active OVL1 sessions.
    pub sessions: usize,
    /// `"ok"` when the event loop is responsive, `"stalled"` when the tick
    /// counter has not advanced in the last ~5 seconds.
    pub status: String,
}

// `Metrics(AdminMetricsSnapshot)` carries f64 Vivaldi-coord fields, so `Eq`
// can't be derived here — `PartialEq` is still sufficient for equality tests.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdminResult {
    Ack {
        message: String,
    },
    Show(AdminNodeSummary),
    Health(AdminHealthReport),
    Listens {
        listens: Vec<AdminListenEntry>,
    },
    Sessions {
        sessions: Vec<AdminSessionEntry>,
    },
    // ── Diagnostics ───────────────────────────────────────────────
    /// One RTT reply from a ping probe.
    PingReply {
        seq: u32,
        rtt_us: u64,
        peer_id: String,
    },
    /// Final statistics after all ping probes are done.
    PingStats {
        sent: u32,
        received: u32,
        lost: u32,
        rtt_min_us: u64,
        rtt_avg_us: u64,
        rtt_max_us: u64,
    },
    /// One traceroute hop reply.
    TraceHop {
        idx: u8,
        node_id: String,
        rtt_us: u64,
    },
    /// Traceroute finished (all hops collected or timed out).
    TraceDone {
        hops: u8,
    },
    /// Result of [`AdminCommand::RelaySend`] (audit batch 2026-05-23).
    /// `sent` reports whether the **first** hop's session accepted the
    /// frame.  Intermediate-hop drops are invisible — RelayPath is
    /// unidirectional by design.
    RelaySendResult {
        sent: bool,
        first_hop: String,
        hops: u8,
    },
    // ── Introspection ────────────────────────────────────────────
    /// Snapshot of all runtime metric counters.
    Metrics(AdminMetricsSnapshot),
    /// All locally stored DHT key-value pairs.
    DhtEntries {
        entries: Vec<AdminDhtEntry>,
        /// `true` when the local store held more than `MAX_ADMIN_DHT_LIST`
        /// entries and the list was capped (avoids materializing an
        /// unbounded — possibly disk-backed — store into the response).
        #[serde(default)]
        truncated: bool,
    },
    /// All Kademlia routing-table contacts.
    DhtContacts {
        contacts: Vec<AdminDhtContact>,
    },
    /// Result of a local DHT key lookup.
    DhtValue {
        key: String,
        value_hex: Option<String>,
        value_len: usize,
    },
    /// result of a verified identity resolve. All fields
    /// come from a `ValidatedIdentity` produced by
    /// `verify_identity_document` — every byte here has been
    /// signature-checked against the master key. Errors surface as
    /// `AdminResponse::err` instead of this variant.
    ResolvedIdentity {
        node_id: String,
        master_algo: u8,
        active_key_idx: u16,
        active_device_id: String,
    },
    /// result of a NAT-probe coordination round.
    /// `responder_node_id` is the target whose candidates are returned;
    /// `candidates` is the list operator can feed into hole-punching.
    /// Emitted by `AdminCommand::NatProbe`. Errors (no reachable
    /// coordinator, all timed out) surface as `AdminResponse::err`
    /// instead of this variant.
    NatProbeResult {
        responder_node_id: String,
        candidate_count: usize,
        candidates: Vec<AdminNatCandidate>,
    },
    /// All attachment records in the local discovery directory.
    DiscoveryEntries {
        attachments: Vec<AdminAttachmentEntry>,
    },
    /// All node IDs currently attached to this gateway.
    GatewayAttachments {
        nodes: Vec<String>,
    },
    /// leaf-side mesh state — discovered gateways ranked
    /// best-first by composite latency+battery score.
    MeshStatus {
        gateways: Vec<AdminMeshGatewayEntry>,
    },
    /// bootstrap-chain status snapshot.
    BootstrapStatus(AdminBootstrapStatus),
    /// All non-expired route cache entries (filtered by `dst_filter` if set
    /// in the request) plus an effective-multi-path config snapshot so
    /// operators can correlate "what paths exist" with "are alternatives
    /// actually being used".
    Routes {
        routes: Vec<AdminRouteEntry>,
        #[serde(default)]
        multi_path: AdminMultiPathConfig,
    },
    /// Discovery search was triggered.
    DiscoverySearchTriggered,
    // ── Distributed tracing ─────────────────────────────────────
    /// All delivery trace hops matching the queried `trace_id`.
    TraceHops {
        trace_id: String,
        hops: Vec<AdminTraceHop>,
    },
    // ── PEX ────────────────────────────────────────────────────
    /// PEX state snapshot.
    PexStatus {
        discovered_peers: usize,
        active_walks: u32,
        last_walk_secs_ago: Option<u64>,
    },
    /// Runtime non-configured peer table.
    DiscoveredPeers {
        peers: Vec<AdminDiscoveredPeer>,
    },
    // ── Ban management ──────────────────────────────────────────
    BanList {
        bans: Vec<AdminBanEntry>,
    },
    // ── Bandwidth ─────────────────────────────────
    Bandwidth {
        inbound_limit_kbps: i64,
        outbound_limit_kbps: i64,
        inbound_total_bytes: u64,
        inbound_dropped_bytes: u64,
        outbound_total_bytes: u64,
        outbound_dropped_bytes: u64,
        /// b: per-peer byte-rate cap. `-1` when
        /// per-peer enforcement is disabled (default for non-mobile
        /// deployments); positive value = bytes/sec ceiling per peer.
        #[serde(default = "default_per_peer_disabled")]
        per_peer_byte_cap_bytes_per_sec: i64,
        /// b: cumulative bytes admitted by per-peer
        /// limiter since startup / reload. `0` when per-peer
        /// enforcement is disabled (per-peer accounting then falls
        /// through to node-aggregate).
        #[serde(default)]
        per_peer_bytes_allowed_total: u64,
        /// b: cumulative bytes REJECTED by per-peer
        /// limiter — operator-facing decision aid: low/zero =
        /// "cap well-tuned"; constant non-zero = "cap may be
        /// breaking legit traffic, consider raising". `0` when
        /// per-peer enforcement is disabled.
        #[serde(default)]
        per_peer_bytes_dropped_total: u64,
    },
    /// snapshot of the update mechanism state for GUI
    /// integration. All fields read from already-loaded config /
    /// state file at the moment the request is served — no I/O.
    UpdateStatus(AdminUpdateStatus),
    /// snapshot of mobile-mode runtime state.
    /// Battery level + scaling factors + config + currently-effective
    /// values — answers "why is my keepalive at the value I'm seeing".
    MobileStatus(AdminMobileStatus),
    /// One captured frame.
    CaptureFrame {
        ts_us: u64,
        /// `"rx"` or `"tx"`.
        direction: String,
        /// Source node_id (hex). For rx: the peer; for tx: the local node.
        src_id: String,
        /// Destination node_id (hex). For rx: the local node; for tx: the peer.
        dst_id: String,
        family: u8,
        msg_type: u16,
        body_len: u32,
        /// Full frame body encoded as lowercase hex.
        body_hex: String,
        /// `true` when the capture happened on the IPC-side of an
        /// E2E path (pre-encryption plaintext visible to the node itself).
        /// Default `false` for regular transport-level captures.
        #[serde(default)]
        e2e_plaintext: bool,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminNodeSummary {
    pub node_id: String,
    pub role: String,
    pub config_path: String,
    pub admin_socket: String,
    pub foreground_mode: bool,
    pub uptime_secs: u64,
    pub metrics_active: bool,
    /// Metrics endpoint URL with any `?token=...` query stripped before
    /// display: the raw URL may carry an auth token that
    /// shouldn't appear in operator dumps or copy-pasted to chat.
    pub metrics_endpoint: Option<String>,
    pub peers_configured: usize,
    pub sessions_active: usize,
    pub listens_active: usize,
    /// `CARGO_PKG_VERSION` at build time of the running binary
    ///. Lets operators distinguish stale vs. fresh
    /// binaries in the field without rummaging through file mtimes.
    pub version: String,
    /// Compile-time feature flags relevant to ops:
    /// `production-seeds`, `allow-empty-seeds`, `rocksdb-cold`.
    pub build_features: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminListenEntry {
    pub listen_id: String,
    pub listener_handle: Option<String>,
    pub transport: String,
    pub local_addr: Option<String>,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminSessionEntry {
    pub link_id: String,
    pub node_id: Option<String>,
    pub nonce: Option<String>,
    pub matched_peer_id: Option<String>,
    pub source: String,
    pub transport: String,
    pub state: String,
    /// most-recent fully-evaluated per-peer loss rate as an
    /// integer percentage (0..=100). `None` for sessions with an
    /// unknown peer node_id (handshake in progress) or with zero
    /// activity in the last evaluated window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_rate_pct: Option<u16>,
    /// number of samples backing `loss_rate_pct` from the last
    /// fully-evaluated window. Operators should ignore the rate when
    /// samples is small (the dispatcher itself ignores rates below 10
    /// samples in its demote decision).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_samples: Option<u32>,
}

// ── Introspection types ────────────────────────────────────────────

// `vivaldi_coord_*` fields are f64, which rules out `Eq` (non-reflexive on NaN).
// Vivaldi fields never produce NaN in practice, but we still drop `Eq` to keep
// the derive valid — same trade-off as `DhtConfig` (see cfg/model.rs:1024).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct AdminMetricsSnapshot {
    /// `true` when `[metrics]` is configured — counters are only active when enabled.
    /// When `false` all counter fields will be zero.
    pub metrics_enabled: bool,
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
    // Mesh
    pub mesh_relay_hops_total: u64,
    // Crypto
    pub decrypt_failures_total: u64,
    // Storage
    pub storage_evictions_total: u64,
    // Route convergence
    pub route_miss_total: u64,
    pub discovery_triggered_total: u64,
    pub route_recovery_total: u64,
    /// 0.0–1.0 reachability score over last 20 events.
    pub network_reachability_score_pct: u64,
    // Adaptive routing (stored as integer ms to avoid f64 in serde)
    pub route_selection_avg_rtt_ms: u64,
    pub vivaldi_prediction_error_ms: u64,
    // Live local Vivaldi coordinate (synthetic — absolute values are meaningful
    // only as distances between nodes). `error` is a self-estimate of
    // convergence; it tends toward 0 as the coord settles.
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
    // ML-KEM key age
    /// Seconds since the ML-KEM decapsulation-key seed was loaded at node start.
    /// Operators can use this to schedule periodic key rotation.
    pub mlkem_key_age_secs: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminDhtEntry {
    /// Key as lowercase hex (64 chars).
    pub key: String,
    /// Value as lowercase hex.
    pub value_hex: String,
    /// Length of the raw value in bytes.
    pub value_len: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminDhtContact {
    /// Node ID as lowercase hex (64 chars).
    pub node_id: String,
    /// Transport URI.
    pub transport: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminAttachmentEntry {
    /// Announced node ID as lowercase hex.
    pub node_id: String,
    /// Role byte.
    pub role: u8,
    /// epoch
    pub epoch: u32,
    /// expires_at as Unix seconds.
    pub expires_at: u64,
    /// Gateway node IDs (hex) this node is reachable through.
    pub gateways: Vec<String>,
}

/// One NAT candidate as returned by `NatProbe` admin response (
/// Mirrors `veil_proto::control::NatCandidate` but
/// uses string-typed addr for human-readable diagnostic output.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminNatCandidate {
    /// Address family: 4 (IPv4) or 6 (IPv6).
    pub atyp: u8,
    /// Candidate type: 0=host, 1=srflx, 2=relay (RFC 8445 §5.1.2).
    pub candidate_type: u8,
    /// RFC 8445 priority — higher = preferred.
    pub priority: u32,
    /// Address as `host:port` (or `[v6]:port`).
    pub addr: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminBanEntry {
    pub node_id: String,
    pub reason: String,
    pub manual: bool,
    /// Unix-seconds wall-clock time the ban was applied.
    /// `None` for entries restored from pre-468.4 `bans.json`.
    pub banned_at_unix: Option<u64>,
}

/// One entry in the runtime's non-configured peer table.
/// Produced by `AdminCommand::PeersDiscovered`; corresponds to a row in
/// `peers_discovered.json` but read live from in-memory state.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminDiscoveredPeer {
    /// Node ID as lowercase hex (64 chars).
    pub node_id: String,
    /// Transport URI.
    pub transport: String,
    /// `exchanged`, `bootstrap`, `autodiscovered` (configured never shown).
    pub source: String,
    /// Internal numeric peer_id (debug artifact; not stable across reloads).
    pub peer_id: u32,
    /// Whether the peer is marked bootstrap-only (one-shot FIND_NODE).
    pub bootstrap_only: bool,
    /// Public key (base64). Useful for operators to correlate with
    /// `peers_discovered.json` on disk when debugging persistence.
    pub public_key: String,
    /// Handshake nonce (base64).
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminRouteEntry {
    /// Destination node ID as lowercase hex.
    pub dst: String,
    /// Next-hop node ID as lowercase hex.
    pub next_hop: String,
    /// Route score (lower = better, in milliunits).
    pub score: u32,
    /// Hop count (1 = direct peer).
    pub hops: u8,
}

/// one row of `node mesh-status` output — leaf-side view
/// of an auto-discovered gateway. Fields mirror
/// [`crate::runtime::MeshGatewayStatusEntry`] (the runtime
/// snapshot type) but with hex-string node_ids for JSON readability
/// and `Option<u32>` flattened for serde.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct AdminMeshGatewayEntry {
    /// Gateway node id (64 hex chars).
    pub node_id: String,
    /// Dial address from the gateway's mesh beacon.
    pub veil_addr: String,
    /// `true` ⇔ this gateway has a live session right now.
    pub is_active: bool,
    /// Smoothed RTT in ms; `null` when no probe has been recorded.
    pub rtt_smoothed_ms: Option<u32>,
    /// Last self-reported battery level (0 = AC / unknown).
    pub battery_level: u8,
    /// Seconds since the last beacon was received.
    pub last_seen_secs_ago: u64,
    /// Seconds until the discovery cache evicts this entry.
    pub expires_in_secs: u64,
}

/// per-layer status of the bootstrap defense chain. See
/// [`AdminCommand::BootstrapStatus`] for what each layer means and why
/// having multiple healthy layers matters for censorship resistance.
///
/// Field counts are *snapshot at request time* — we don't track
/// historical "was this layer ever populated?", only "is it populated
/// right now?". An empty layer with a configured source (e.g.
/// `dns_domain = Some(_)` but a hypothetical zero DNS reply) shows as
/// configured-but-empty, which is itself useful diagnostic signal.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct AdminBootstrapStatus {
    /// Layer 1: operator-curated `[[bootstrap_peers]]` array.
    pub config_peers: usize,
    /// Layer 2: compile-time `node::bootstrap::builtin_seeds` count.
    pub builtin_seeds: usize,
    /// Layer 3: operator-curated HTTPS URLs returning
    /// JSON bootstrap bundles. Hot-rotatable without binary rebuild.
    /// Surfaced as the count of configured URLs only — we don't probe
    /// at diag time (would require network I/O + TLS handshake), the
    /// operator can `curl -v <URL>` themselves to verify reachability.
    #[serde(default)]
    pub https_urls: usize,
    /// Layer 4: DNS bootstrap domain (`config.global.bootstrap_dns_domain`).
    /// `None` ⇔ operator hasn't configured DNS bootstrap. We *don't*
    /// run a DNS probe here — that would require I/O. Operator can
    /// run `dig TXT _veil._bootstrap.<domain>` themselves.
    pub dns_domain: Option<String>,
    /// Layer 5: discovered-peer cache from prior runs.
    pub discovered_cache: AdminDiscoveredCacheStatus,
    /// Count of layers that currently have ≥1 entry / are configured.
    /// 0 = bootstrap will fail; 1 = single point of censorship; ≥2 =
    /// layered defense. Computed at the handler level so the renderer
    /// doesn't have to re-derive verdict criteria.
    pub healthy_layers: u8,
    /// Total layer count — surfaced so a future binary adding a layer
    /// can render correctly against an older operator UI. Currently 5.
    pub total_layers: u8,
}

/// status of the discovered-peer cache. Pulled
/// out into its own struct because the cache has its own knobs (path
/// in-memory variant) that the operator may want to verify separately.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct AdminDiscoveredCacheStatus {
    /// `true` when the cache has a configured persistence path; `false`
    /// when running in the in-memory variant (entries lost on restart).
    pub persistent: bool,
    /// Path to the cache file, when persistent.
    pub path: Option<String>,
    /// Current entry count. `0` is healthy on a first-run node; only a
    /// concern if the operator expected entries from prior sessions.
    pub entries: usize,
    /// Seconds since the FRESHEST cached entry's last successful
    /// handshake. `None` when the cache is empty. A cache whose
    /// freshest entry is months old is a hint that the node hasn't
    /// connected to anyone via the bootstrap chain in months — likely
    /// all higher layers (operator config, builtin, HTTPS, DNS) are
    /// also failing.
    #[serde(default)]
    pub freshest_secs_ago: Option<u64>,
    /// Seconds since the OLDEST cached entry's last successful
    /// handshake. `None` when the cache is empty. Combined with
    /// `freshest_secs_ago` gives the operator a window of cache age:
    /// "newest contact 2 days ago, oldest contact 45 days ago".
    #[serde(default)]
    pub oldest_secs_ago: Option<u64>,
}

/// snapshot of the update mechanism state.
///
/// Read entirely from already-loaded config + the on-disk
/// installed-version state file — no network I/O, no admin
/// roundtrip cost beyond the IPC ping itself. GUI tray icons /
/// admin dashboards poll this on a timer (or when the user opens
/// the menu) to render "configured / out-of-date / current"
/// without grepping logs or re-running the network-touching
/// `update check`.
///
/// Fields on this struct describe **the operator's intent** plus
/// **what's actually installed** — not the result of any live
/// check. For "is there a newer version available right now"
/// the GUI must call `update check` (network-touching).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct AdminUpdateStatus {
    /// `true` when both `manifest_urls` is non-empty AND
    /// `expected_issuer_pk` is set — the minimum viable
    /// configuration for `update check` to engage. When `false`
    /// the GUI should hide update UI entirely (or render
    /// "operator hasn't enabled update mechanism").
    pub check_configured: bool,
    /// `true` when `check_configured` AND `install_path` AND
    /// `installed_version_path` are all set — the apply path is
    /// fully wired. When `false` but `check_configured` is
    /// `true`, the GUI can offer "check for updates" but must
    /// disable "apply update".
    pub apply_configured: bool,
    /// Number of operator-configured manifest URLs. `0` ⇔
    /// check_configured == false. Surfaced as a count (not
    /// the URLs themselves) so a screenshot / log of the status
    /// command doesn't leak the operator's CDN list.
    pub manifest_url_count: usize,
    /// Configured update poll cadence in seconds. `None` ⇔
    /// auto-poll disabled (manual `update check` only). Mobile
    /// profile sets this to 86_400 (24 h).
    pub check_interval_secs: Option<u64>,
    /// `release_unix` of the currently-installed binary, as
    /// recorded in `installed_version_path`'s state file.
    /// `None` when the state file is missing (fresh install OR
    /// no `installed_version_path` configured). GUI renders
    /// this as YYYY-MM-DD via the same Howard Hinnant inverse
    /// the CLI uses.
    pub installed_release_unix: Option<u64>,
    /// `true` when the runtime's `mobile_background_mode` flag
    /// is set. GUI shows "background mode active"
    /// indicator so the user knows their keepalive cadence has
    /// stretched (and can verify the mobile-app integration is
    /// working as expected).
    pub mobile_background_mode: bool,
}

/// snapshot of mobile-mode runtime state.
///
/// Surfaces both **config knobs** (what the operator declared) AND
/// **resolved values RIGHT NOW** (after `mobile_background_mode`
/// flag + battery level). GUI dashboard / mobile app debugging
/// answers "why is my keepalive 30 min when I expected 30s?" in
/// one round-trip without grepping session-runner logs.
///
/// All fields read from in-memory state OR /sys (Linux battery) —
/// no network I/O. Read at the moment the admin request is
/// served, so flips through `SetMobileBackgroundMode` are visible
/// immediately.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminMobileStatus {
    /// Current `mobile_background_mode` flag.
    /// `true` when GUI wrapper / mobile app called
    /// `SetMobileBackgroundMode { enabled: true }` from onPause.
    pub background_mode: bool,
    /// Configured `mobile.background_keepalive_multiplier`.
    /// Mobile profile sets to 60; non-mobile default 1 (feature off).
    pub background_keepalive_multiplier: u32,
    /// Effective background factor RIGHT NOW: 1 when `background_mode`
    /// is false, otherwise `background_keepalive_multiplier`
    /// clamped to `[1, MAX_BACKGROUND_KEEPALIVE_MULTIPLIER=120]`.
    /// Composes multiplicatively with battery scaling.
    pub background_keepalive_factor: u32,
    /// Current battery reading. `100` = AC / unknown / non-Linux
    /// sentinel — never throttled on this signal by design.
    /// On Linux read from `/sys/class/power_supply/BAT*/capacity`.
    pub battery_level_pct: u8,
    /// Configured `mobile.low_battery_threshold_pct` (
    /// route-probe throttling). `None` disables battery-aware
    /// route-probe throttling entirely.
    pub low_battery_threshold_pct: Option<u8>,
    /// Configured `mobile.low_battery_multiplier`.
    pub low_battery_multiplier: u32,
    /// Effective battery throttle factor for route-probe RIGHT NOW
    ///`1` when threshold disabled OR battery above
    /// threshold OR battery == 0 (AC sentinel), otherwise
    /// `low_battery_multiplier` clamped to
    /// `[1, MAX_LOW_BATTERY_MULTIPLIER=16]`. Note: this is the
    /// **route-probe** factor, separate from the
    /// session-internal **keepalive** battery scaling (—
    /// hardcoded float tiers in SessionRunner; not exposed here
    /// because it's a per-session detail, not a node-wide config).
    pub battery_route_probe_factor: u32,
}

/// snapshot of routing multi-path settings, included with the
/// `Routes` admin response so the operator can tell at a glance whether
/// alternative `next_hop`s in the cache are actually being USED for delivery
/// or are just sitting there waiting to be promoted by ECMP / failover.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct AdminMultiPathConfig {
    /// `routing.multi_path_enabled` — when `true`, frames at priority
    /// ≤ `multi_path_min_priority` are duplicated across `max_parallel_paths`.
    pub multi_path_enabled: bool,
    /// `routing.max_parallel_paths` — fan-out for multi-path delivery.
    pub max_parallel_paths: u8,
    /// `routing.multi_path_min_priority` — priority threshold (lower number
    /// = higher priority; only frames at-or-below this get multi-path).
    pub multi_path_min_priority: u8,
    /// `routing.redundant_send` — duplicate critical frames on the two best
    /// paths. Higher bandwidth, lower p99 latency.
    pub redundant_send: bool,
    /// `routing.ecmp_score_band` — fraction of best score within which
    /// alternative routes are treated as equal-cost.
    pub ecmp_score_band: f64,
}

// ── Distributed tracing types ─────────────────────────────────────

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdminTraceHop {
    /// Peer the frame was received (hex node_id).
    pub from_peer: String,
    /// Peer the frame was forwarded (hex node_id; empty = final delivery).
    pub to_peer: String,
    /// RTT to `to_peer` in milliseconds (0 = unknown).
    pub hop_rtt_ms: u32,
    /// Unix timestamp in milliseconds when this hop was recorded.
    pub timestamp_ms: u64,
}

/// Wait for SIGTERM on Unix; on non-Unix platforms returns a future that
/// never resolves (Ctrl-C covers the shutdown path there).
#[cfg(unix)]
async fn sigterm_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut sig) = signal(SignalKind::terminate()) {
            sig.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    }
    #[cfg(not(unix))]
    std::future::pending::<()>().await;
}

/// Spawn a background task that reloads the runtime on every SIGHUP.
///
/// On non-Unix platforms SIGHUP does not exist; the task simply idles.
#[cfg(unix)]
pub fn spawn_sighup_reloader(runtime: Arc<tokio::sync::Mutex<NodeRuntime>>) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sig = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(_) => return,
            };
            loop {
                sig.recv().await;
                // Use reload_via_arc so the outer lock is released during
                // the 200 ms graceful-shutdown sleep.
                match NodeRuntime::reload_via_arc(Arc::clone(&runtime)).await {
                    Ok(()) => runtime
                        .lock()
                        .await
                        .log_info("node.reload", "config reloaded via SIGHUP"),
                    Err(e) => runtime
                        .lock()
                        .await
                        .log_info("node.reload_error", format!("SIGHUP reload failed: {e}")),
                }
            }
        }
        #[cfg(not(unix))]
        std::future::pending::<()>().await;
    });
}

/// Run the node in foreground mode: start `NodeRuntime`, bind the configured
/// admin endpoint (Unix or TCP), accept admin commands until Ctrl-C / SIGTERM
/// (or an admin-initiated shutdown).
///
/// The admin endpoint backend is selected by `global.admin_socket`
/// (`unix://…` or `tcp://…`). Unix-specific niceties (umask, SIGHUP reload)
/// apply automatically on Unix; on Windows the TCP backend handles all
/// admin traffic and the SIGHUP reloader is a no-op.
pub async fn run_foreground(config_path: impl AsRef<Path>, foreground_mode: bool) -> Result<()> {
    // Convenience wrapper: no external shutdown source. The core loop
    // below still exits on ctrl-c / SIGTERM / admin-server close.
    run_foreground_with_shutdown(config_path, foreground_mode, std::future::pending::<()>()).await
}

/// Start the daemon in **deferred-init mode** — boot with a stub config
/// (ephemeral Ed25519 identity, empty peers / listens) and await a
/// runtime `admin apply-config` to provide the real config.
///
/// Concretely:
/// 1. Generate a fresh per-run Ed25519 keypair and mine its PoW nonce.
/// 2. Build a minimal Config (just `[identity]` + defaults).
/// 3. Create a fresh temp directory (`$TMPDIR/veil-deferred-<pid>-<ts>`)
///    so daemon-owned working files (`mlkem.key`, future `identity_document.bin`)
///    don't collide with existing instances and are reaped by process exit
///    on modern OSes.
/// 4. Write the stub config to `<tmpdir>/node.toml` (atomic-write — the
///    temp dir is only writable by the daemon's UID anyway).
/// 5. Hand off to `run_foreground_with_shutdown` exactly as if a normal
///    config file had been provided.
///
/// **Lifetime of the stub identity**: replaced by the first successful
/// `admin apply-config` call.  Until that arrives, the daemon is on the
/// network under the ephemeral keypair — but without any peers configured and
/// without any listen ports, so no traffic exists to be ascribed to it.
pub async fn run_foreground_deferred() -> Result<()> {
    // Convenience wrapper: no external shutdown source (signals / admin-stop
    // still apply). Embedded hosts (the FFI `veil_node_stop`) want the
    // shutdown-aware variant below.
    run_foreground_deferred_with_shutdown(None, false, std::future::pending::<()>()).await
}

/// As [`run_foreground_deferred`] but awaits an additional `external_shutdown`
/// future alongside the standard signal handlers — so an embedded host (the
/// FFI node runtime) can trigger a graceful stop of a deferred-init node.
/// Without this the deferred node is unstoppable (the bare
/// [`run_foreground_deferred`] hardcodes a `pending()` shutdown).
///
/// `anonymous` arms `[anonymity]` in the stub boot config so the deferred node
/// is actually onion-reachable once its real identity is applied — see
/// [`veil_cfg::build_stub_config_with_ephemeral_identity`] for why this must be
/// set at boot rather than via the later apply-config.
pub async fn run_foreground_deferred_with_shutdown<F>(
    admin_endpoint: Option<String>,
    anonymous: bool,
    external_shutdown: F,
) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    // Build stub config (CPU-heavy — runs PoW search; tolerated because
    // deferred-init is a one-time startup cost).
    let mut stub_config = veil_cfg::build_stub_config_with_ephemeral_identity(anonymous)
        .map_err(crate::error::NodeError::Config)?;

    // Caller-chosen admin endpoint (embedded hosts pick either an ephemeral
    // Unix path or authenticated loopback-TCP discovery URI they can reach with
    // `apply-config`). Otherwise the default derived from the temp config below
    // is used.
    if let Some(endpoint) = &admin_endpoint {
        stub_config.global.admin_socket = Some(endpoint.clone());
    }

    // Per-run temp working dir (mlkem.key + future identity_document.bin land
    // here). Created ATOMICALLY by `tempfile`: `O_EXCL` mkdir, mode 0700, and a
    // getrandom-random name. This closes the deferred-init TOCTOU where a
    // co-tenant on a multi-user host could pre-create a predictable
    // `veil-deferred-{pid}-{ts}` dir — the old `create_dir_all` ACCEPTED a
    // pre-existing dir, and the follow-up `chmod 0700`'s error was IGNORED
    // (`let _ =`), so the daemon could end up writing `identity.private_key`
    // into an attacker-owned, world-readable dir. `tempfile` instead fails if
    // the path exists and sets 0700 in the mkdir itself (no umask window, no
    // ignored error).
    let tmp_dir = tempfile::Builder::new()
        .prefix("veil-deferred-")
        .tempdir()?;

    let config_path = tmp_dir.path().join("node.toml");
    veil_cfg::save_config(&config_path, &stub_config).map_err(crate::error::NodeError::Config)?;

    // Hand off to the normal foreground loop.  `--foreground` is implied
    // — a background-spawned daemon would inherit the temp dir but lose
    // access on parent exit, leaving orphan state.  CLI dispatch
    // enforces the foreground requirement before calling this. `tmp_dir` is
    // held alive until this returns so the dir (and its secrets) persist for
    // the daemon's lifetime, then are scrubbed on graceful shutdown (the old
    // code leaked the dir to OS reap).
    let result = run_foreground_with_shutdown(&config_path, true, external_shutdown).await;
    drop(tmp_dir);
    result
}

/// As [`run_foreground`] but awaits an additional shutdown future alongside
/// the standard signal handlers. uses this so the Windows
/// Service control handler can trigger a graceful stop when SCM sends
/// `ServiceControl::Stop`: the service module passes a future that resolves
/// when its stop channel fires.
pub async fn run_foreground_with_shutdown<F>(
    config_path: impl AsRef<Path>,
    foreground_mode: bool,
    external_shutdown: F,
) -> Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let config_path = config_path.as_ref().to_path_buf();
    let config = veil_cfg::load_config(&config_path)?;
    // Default runtime_dir = config file's parent. Multi-node setups are then
    // self-isolating: each node's config dir hosts its own admin sidecars.
    let endpoint = resolve_admin_endpoint(&config, config_path.parent())?;
    let runtime = Arc::new(Mutex::new(
        NodeRuntime::start(&config_path, foreground_mode).await?,
    ));

    // Reload config on SIGHUP — Unix-only; the helper itself is gated and
    // absent on Windows, so we omit the call entirely there.
    #[cfg(unix)]
    spawn_sighup_reloader(Arc::clone(&runtime));

    prepare_admin_endpoint(&endpoint).await?;
    let (listener, anchor_path) = bind_admin_endpoint(&endpoint).await?;
    runtime
        .lock()
        .await
        .log_info("admin.bind", format!("endpoint={}", anchor_path.display()));
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    // followup: connection cap (defense-in-depth).
    // Token auth + UID gate already block unauthorised connects; this
    // semaphore caps "how many concurrent admin connections a single
    // authorised UID can hold open" so a bug or mis-tooling cannot
    // exhaust resources by spawning hundreds of admin clients. When
    // the cap is hit, the accept loop logs `admin.accept_refused` and
    // drops the connection without spawning a handshake task (saves a
    // task slot relative to the pre-cap behaviour).
    let admin_max_connections = config.global.admin_max_connections;
    let admin_connection_semaphore = Arc::new(tokio::sync::Semaphore::new(admin_max_connections));

    let admin_runtime = Arc::clone(&runtime);
    let anchor_path_clone = anchor_path.clone();
    let config_path_clone = config_path.clone();
    let accept_shutdown_tx = shutdown_tx.clone();
    let semaphore_clone = Arc::clone(&admin_connection_semaphore);
    let mut admin_server = tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_ok() {
                        break;
                    }
                }
                accepted = listener.accept_raw() => {
                    // slow-loris fix: `accept_raw` returns
                    // immediately after kernel `accept(2)`; the 32-byte
                    // token handshake (which can stall up to 3 s on a
                    // malicious connect-and-hang client) runs inside the
                    // spawned task below. Pre-fix, one stalled handshake
                    // blocked the entire admin loop for 3 s × N attempts.
                    let (pending, peer_info) = match accepted {
                        Ok(pair) => pair,
                        Err(e) => {
                            // Per-connection accept errors must not kill
                            // the listener — log at info level and keep
                            // accepting. (Token-handshake errors are
                            // handled in the spawned task; here we only
                            // see kernel-level accept failures, e.g. file
                            // descriptor exhaustion.)
                            admin_runtime.lock().await.log_info(
                                "admin.accept_rejected",
                                format!("error={e}"),
                            );
                            continue;
                        }
                    };
                    // Reject connections from other users BEFORE running
                    // the handshake task — saves a task spawn for the
                    // common-attacker case (cross-user probe). For Unix
                    // this is `SO_PEERCRED` / `getpeereid`; for TCP /
                    // NamedPipe this is presumed-true (token auth gates
                    // access already, but the check is still cheap).
                    if !peer_info.uid_matches_local {
                        continue;
                    }
                    // followup: connection cap. `try_acquire_owned`
                    // on a full semaphore returns Err immediately (no blocking
                    // on the accept loop). Drop the connection and log.
                    let permit = match Arc::clone(&semaphore_clone).try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            admin_runtime.lock().await.log_info(
                                "admin.accept_refused",
                                format!(
                                    "cap={admin_max_connections} concurrent admin connections \
                                     reached — refusing"
                                ),
                            );
                            continue;
                        }
                    };
                    let runtime = Arc::clone(&admin_runtime);
                    let shutdown_tx = accept_shutdown_tx.clone();
                    let anchor = anchor_path_clone.clone();
                    let config_path = config_path_clone.clone();
                    let logger = Arc::clone(&admin_runtime);
                    tokio::spawn(async move {
                        // Permit moves into the spawned task; its drop on
                        // task exit releases the slot. Dropping early
                        // (e.g. on handshake failure) is fine — task ends
                        // immediately and slot frees.
                        let _permit = permit;
                        // complete the token-handshake step
                        // here (off the accept loop). Failures (timeout
                        // mismatch) are logged at info level and drop the
                        // connection silently — a probe or misconfigured
                        // client must not page operators.
                        let stream = match pending.verify().await {
                            Ok(s) => s,
                            Err(e) => {
                                logger.lock().await.log_info(
                                    "admin.handshake_rejected",
                                    format!("error={e}"),
                                );
                                return;
                            }
                        };
                        let _ = handle_admin_connection(stream, runtime, shutdown_tx, anchor, config_path).await;
                    });
                }
            }
        }
    });

    let mut admin_server_finished = false;
    tokio::pin!(external_shutdown);
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = wait_for_sigterm() => {}
        _ = &mut external_shutdown => {}
        _ = &mut admin_server => {
            admin_server_finished = true;
        }
    }

    let _ = shutdown_tx.send(true);
    NodeRuntime::stop_via_arc(Arc::clone(&runtime)).await?;
    if !admin_server_finished {
        admin_server.abort();
        let _ = admin_server.await;
    }
    cleanup_admin_endpoint(&endpoint).await;
    Ok(())
}

/// Cross-platform shim over [`sigterm_signal`]: on non-Unix there's no
/// SIGTERM to await, so we return a pending future. Keeps the select!
/// in `run_foreground` single-shaped across platforms.
async fn wait_for_sigterm() {
    #[cfg(unix)]
    {
        sigterm_signal().await;
    }
    #[cfg(not(unix))]
    {
        std::future::pending::<()>().await;
    }
}

/// Set the admin socket file permissions to `0o600` (owner read/write only).
#[cfg(unix)]
async fn set_socket_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    let _ = tokio::fs::set_permissions(path, perms).await;
}

#[cfg(unix)]
async fn prepare_admin_socket(admin_socket: &Path) -> Result<()> {
    if let Some(parent) = admin_socket.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    if tokio::fs::try_exists(admin_socket).await? {
        if send_request(admin_socket, AdminCommand::Show).await.is_ok() {
            return Err(NodeError::AdminProtocol(format!(
                "admin socket `{}` is already in use by a running node",
                admin_socket.display()
            )));
        }
        let _ = tokio::fs::remove_file(admin_socket).await;
    }

    Ok(())
}

async fn write_admin_request(stream: &mut AdminStream, command: AdminCommand) -> Result<()> {
    let request = serde_json::to_string(&AdminRequest {
        version: ADMIN_PROTOCOL_VERSION,
        command,
    })?;
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    Ok(())
}

/// Send a single admin command and return the response. The `socket_path`
/// is either a Unix-domain socket or a synthetic TCP anchor; dispatch is
/// handled by [`connect_admin_client_any`].
pub async fn send_request(socket_path: &Path, command: AdminCommand) -> Result<AdminResponse> {
    let mut stream = connect_admin_client_any(socket_path).await?;
    write_admin_request(&mut stream, command).await?;
    stream.shutdown().await?;

    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    let read = reader.read_line(&mut line).await?;
    if read == 0 {
        return Err(NodeError::AdminProtocol(
            "admin server closed connection without a response".to_owned(),
        ));
    }
    let response: AdminResponse = serde_json::from_str(line.trim_end())?;
    if response.version != ADMIN_PROTOCOL_VERSION {
        return Err(NodeError::AdminProtocol(format!(
            "unsupported admin protocol version `{}`",
            response.version
        )));
    }
    Ok(response)
}

/// Admin-protocol binding configuration.
///
/// Parsed from `global.admin_socket` at node startup. `Unix` preserves the
/// pre-refactor behaviour. `Tcp` binds a TCP-loopback listener
/// with token authentication; clients discover the port and token from
/// sibling files next to the `admin_socket` URI.
#[derive(Debug, Clone)]
pub enum AdminEndpoint {
    /// Unix domain socket at the given filesystem path.
    Unix(PathBuf),
    /// TCP-loopback on the given bind address. The `runtime_dir` is where
    /// the server writes `admin.port` and `admin.token` so clients can find
    /// the listener.
    Tcp {
        /// Address to bind — typically `127.0.0.1:0` so the kernel picks a port.
        bind_addr: std::net::SocketAddr,
        /// Directory for `admin.port` and `admin.token` files.
        runtime_dir: PathBuf,
    },
    /// Windows NamedPipe at the given pipe name (full
    /// `\\.\pipe\xxx` form). `runtime_dir` holds `admin.pipe` (the name
    /// echoed for client discovery) and `admin.token` files. NamedPipe
    /// shares the `admin.anchor` semantics: no real file at the anchor
    /// clients consult the siblings.
    NamedPipe {
        /// Full pipe name, e.g. `\\.\pipe\veil-admin-1234`.
        /// `#[allow(dead_code)]`: only read on Windows; non-Windows code
        /// paths immediately return `Unsupported` from `bind_admin_endpoint`.
        #[allow(dead_code)]
        pipe_name: String,
        /// Directory for `admin.pipe` and `admin.token` files.
        runtime_dir: PathBuf,
    },
}

// ── endpoint lifecycle helpers ─────────────────────────────────

/// Connect to an admin server by inspecting a generic anchor path.
///
/// The anchor path is whatever `admin_socket_path(&config)` produced:
/// For Unix endpoints, the real socket file.
/// For TCP endpoints, a synthetic path whose parent dir contains
/// [`ADMIN_PORT_FILENAME`] and [`ADMIN_TOKEN_FILENAME`] sidecars.
///
/// TCP takes precedence when its sidecars are present — this matters when
/// Unix sockets can't actually bind (Windows) but leaves a stale anchor file
/// behind.
pub async fn connect_admin_client_any(anchor: &Path) -> Result<AdminStream> {
    // Probe order (per backend, by sidecar presence):
    // 1. TCP (admin.port + admin.token)
    // 2. NamedPipe (admin.pipe + admin.token) — Windows only
    // 3. Unix (anchor IS the socket file)
    if let Some(parent) = anchor.parent() {
        let port_path = parent.join(ADMIN_PORT_FILENAME);
        let token_path = parent.join(ADMIN_TOKEN_FILENAME);
        let port_exists = tokio::fs::try_exists(&port_path).await.unwrap_or(false);
        let token_exists = tokio::fs::try_exists(&token_path).await.unwrap_or(false);
        if port_exists && token_exists {
            let port = admin_transport::read_port_file(&port_path).await?;
            let token = admin_transport::read_token_file(&token_path).await?;
            let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().map_err(|e| {
                NodeError::AdminProtocol(format!(
                    "admin.port at {} parsed into invalid SocketAddr: {e}",
                    port_path.display(),
                ))
            })?;
            return admin_transport::connect_tcp(addr, &token).await;
        }

        // NamedPipe probe.
        #[cfg(windows)]
        {
            let pipe_path = parent.join(ADMIN_PIPE_FILENAME);
            let pipe_exists = tokio::fs::try_exists(&pipe_path).await.unwrap_or(false);
            if pipe_exists && token_exists {
                let pipe_name = tokio::fs::read_to_string(&pipe_path).await.map_err(|e| {
                    NodeError::AdminProtocol(format!("admin.pipe at {}: {e}", pipe_path.display(),))
                })?;
                let token = admin_transport::read_token_file(&token_path).await?;
                return admin_transport::connect_named_pipe(pipe_name.trim(), &token).await;
            }
        }
    }
    // Unix path (or Unix-style anchor that doesn't exist yet — caller sees
    // a clean ConnectionError in that case).
    admin_transport::connect_unix(anchor).await
}

/// Pre-bind cleanup: ensure the endpoint is ready to be bound.
///
/// For Unix: `mkdir -p` the socket parent, check for a live server at the
/// socket file, refuse to clobber it, remove stale socket files.
///
/// For TCP: `mkdir -p` the runtime dir, check for a live server via the
/// sidecars, refuse to clobber, remove stale sidecars.
pub async fn prepare_admin_endpoint(endpoint: &AdminEndpoint) -> Result<()> {
    match endpoint {
        #[cfg(unix)]
        AdminEndpoint::Unix(socket) => prepare_admin_socket(socket).await,
        #[cfg(not(unix))]
        AdminEndpoint::Unix(_) => Err(NodeError::Unsupported(
            "Unix domain sockets are not supported on this platform; \
             configure global.admin_socket = \"tcp://127.0.0.1:0\" instead"
                .to_owned(),
        )),
        AdminEndpoint::Tcp { runtime_dir, .. } => {
            tokio::fs::create_dir_all(runtime_dir).await?;
            let anchor = runtime_dir.join(ADMIN_ANCHOR_FILENAME);
            // Probe for a live server by attempting an admin request; a
            // success means we're about to clobber a running node.
            if admin_endpoint_reachable_raw(runtime_dir).await
                && send_request(&anchor, AdminCommand::Show).await.is_ok()
            {
                return Err(NodeError::AdminProtocol(format!(
                    "admin endpoint at {} is already in use by a running node",
                    runtime_dir.display(),
                )));
            }
            // Stale sidecars from a previous crashed run — remove so the
            // next bind starts with a clean slate.
            let _ = tokio::fs::remove_file(runtime_dir.join(ADMIN_PORT_FILENAME)).await;
            let _ = tokio::fs::remove_file(runtime_dir.join(ADMIN_TOKEN_FILENAME)).await;
            Ok(())
        }
        #[cfg(windows)]
        AdminEndpoint::NamedPipe { runtime_dir, .. } => {
            tokio::fs::create_dir_all(runtime_dir).await?;
            // NamedPipe doesn't have a pre-bind "port" file, only the token
            // and pipe-name sidecars. The `bind_named_pipe` probe at actual
            // bind time will fail with `AlreadyExists` if another server
            // holds the pipe, so there's no pre-flight liveness check here —
            // just sweep stale sidecars.
            let _ = tokio::fs::remove_file(runtime_dir.join(ADMIN_PIPE_FILENAME)).await;
            let _ = tokio::fs::remove_file(runtime_dir.join(ADMIN_TOKEN_FILENAME)).await;
            Ok(())
        }
        #[cfg(not(windows))]
        AdminEndpoint::NamedPipe { .. } => Err(NodeError::Unsupported(
            "NamedPipe admin endpoint is only supported on Windows".to_owned(),
        )),
    }
}

/// Synchronous best-effort check that an admin server appears to be present
/// at `anchor` (the path returned by [`admin_socket_path`]). Used by CLI
/// commands as a friendly preflight before opening a connection.
///
/// Unix endpoint: anchor is the real socket file → returns `anchor.exists`.
/// TCP endpoint: anchor is a synthetic path under `runtime_dir` → returns
/// `true` iff the `admin.port` sidecar exists in the same directory (the
/// server writes it after binding).
///
/// `false` means "definitely not running"; `true` means "probably running"
/// — the actual connect attempt is the source of truth.
pub fn admin_anchor_reachable_sync(anchor: &Path) -> bool {
    if anchor.exists() {
        return true;
    }
    let Some(parent) = anchor.parent() else {
        return false;
    };
    if parent.join(ADMIN_PORT_FILENAME).exists() {
        return true;
    }
    // NamedPipe sidecar is the third backend marker.
    #[cfg(windows)]
    if parent.join(ADMIN_PIPE_FILENAME).exists() {
        return true;
    }
    false
}

/// Whether both TCP sidecars exist under `runtime_dir`. Factored out so
/// [`prepare_admin_endpoint`] can consult it without reparsing config.
async fn admin_endpoint_reachable_raw(runtime_dir: &Path) -> bool {
    let port_ok = tokio::fs::try_exists(runtime_dir.join(ADMIN_PORT_FILENAME))
        .await
        .unwrap_or(false);
    let token_ok = tokio::fs::try_exists(runtime_dir.join(ADMIN_TOKEN_FILENAME))
        .await
        .unwrap_or(false);
    port_ok && token_ok
}

/// Bind the admin listener for the configured endpoint.
///
/// Returns the listener plus the anchor path — the latter is what
/// `handle_admin_connection` uses for socket-file cleanup on
/// `AdminCommand::Restart`. For TCP the anchor doesn't correspond to a
/// real file, so the Restart arm of `handle_admin_connection` gracefully
/// skips the `remove_file` step.
pub async fn bind_admin_endpoint(
    endpoint: &AdminEndpoint,
) -> Result<(admin_transport::AdminListener, PathBuf)> {
    match endpoint {
        #[cfg(unix)]
        AdminEndpoint::Unix(socket) => {
            // SECURITY — audit cycle-2 HIGH: do NOT set a process-wide
            // `libc::umask` around the bind. umask is process-global, so in the
            // multi-threaded async runtime a temporary `umask(0o177)` made
            // concurrent threads create files/dirs without the execute/other
            // bits (directories → `PermissionDenied`, which broke parallel test
            // runs), and an error from `bind_unix` returned via `?` BEFORE the
            // restore leaked the restrictive mask for the whole process. The
            // socket is secured without any global state: `bind_unix` rejects a
            // world/group-writable or symlinked parent (the admin dir is 0o700),
            // and `set_socket_permissions` chmods the socket to 0o600 right
            // after bind.
            let listener = admin_transport::bind_unix(socket)?;
            set_socket_permissions(socket).await;
            Ok((listener, socket.clone()))
        }
        #[cfg(not(unix))]
        AdminEndpoint::Unix(_) => Err(NodeError::Unsupported(
            "Unix domain sockets are not supported on this platform".to_owned(),
        )),
        AdminEndpoint::Tcp {
            bind_addr,
            runtime_dir,
        } => {
            let (listener, local_addr, token) = admin_transport::bind_tcp(*bind_addr).await?;
            std::fs::create_dir_all(runtime_dir)?;
            admin_transport::write_port_file(
                &runtime_dir.join(ADMIN_PORT_FILENAME),
                local_addr.port(),
            )
            .await?;
            admin_transport::write_token_file(&runtime_dir.join(ADMIN_TOKEN_FILENAME), &token)
                .await?;
            Ok((listener, runtime_dir.join(ADMIN_ANCHOR_FILENAME)))
        }
        #[cfg(windows)]
        AdminEndpoint::NamedPipe {
            pipe_name,
            runtime_dir,
        } => {
            let (listener, actual_name, token) = admin_transport::bind_named_pipe(pipe_name)?;
            std::fs::create_dir_all(runtime_dir)?;
            // Write the pipe name (UTF-8) so clients know what to open.
            // Kept as a plain file next to `admin.token`; no permission
            // enforcement (the token file is the secret, not the name).
            std::fs::write(
                runtime_dir.join(ADMIN_PIPE_FILENAME),
                actual_name.as_bytes(),
            )?;
            admin_transport::write_token_file(&runtime_dir.join(ADMIN_TOKEN_FILENAME), &token)
                .await?;
            Ok((listener, runtime_dir.join(ADMIN_ANCHOR_FILENAME)))
        }
        #[cfg(not(windows))]
        AdminEndpoint::NamedPipe { .. } => Err(NodeError::Unsupported(
            "NamedPipe admin endpoint is only supported on Windows".to_owned(),
        )),
    }
}

/// Remove the on-disk traces of the admin endpoint after shutdown.
pub async fn cleanup_admin_endpoint(endpoint: &AdminEndpoint) {
    match endpoint {
        AdminEndpoint::Unix(socket) => {
            let _ = tokio::fs::remove_file(socket).await;
        }
        AdminEndpoint::Tcp { runtime_dir, .. } => {
            let _ = tokio::fs::remove_file(runtime_dir.join(ADMIN_PORT_FILENAME)).await;
            let _ = tokio::fs::remove_file(runtime_dir.join(ADMIN_TOKEN_FILENAME)).await;
        }
        #[cfg(windows)]
        AdminEndpoint::NamedPipe { runtime_dir, .. } => {
            let _ = tokio::fs::remove_file(runtime_dir.join(ADMIN_PIPE_FILENAME)).await;
            let _ = tokio::fs::remove_file(runtime_dir.join(ADMIN_TOKEN_FILENAME)).await;
            // No named-pipe "unlink" needed: the kernel reaps the pipe
            // object once the last server instance is dropped.
        }
        #[cfg(not(windows))]
        AdminEndpoint::NamedPipe { .. } => {
            // Can't bind on non-Windows anyway — nothing to clean.
        }
    }
}

/// Parse `global.admin_socket` into an [`AdminEndpoint`].
///
/// Supported URI forms:
///
/// `unix:///abs/path/to/admin.sock` — Unix domain socket.
/// `tcp://127.0.0.1:0?runtime_dir=/abs/path` — TCP loopback. The
/// `runtime_dir` query parameter is where `admin.port` and `admin.token`
/// are written; if absent, falls back to `$TMPDIR/veil-<pid>` so the
/// test setup and single-node default just work without operator config.
///
/// `config_dir` is the directory to use as default `runtime_dir` for TCP
/// endpoints when no explicit `?runtime_dir=` query is present. Pass
/// `Some(config_path.parent)` from production callers — multi-node
/// setups get auto-isolated sidecars without operator config. `None`
/// falls back to the per-user `runtime_veil_dir` (handy for tests
/// that load `Config` from memory without a backing file).
pub fn resolve_admin_endpoint(config: &Config, config_dir: Option<&Path>) -> Result<AdminEndpoint> {
    // fall back to the derived default when the operator has not
    // configured `global.admin_socket` explicitly. Requires a known config
    // directory so the derived path lands alongside the config; without one
    // we still surface the original error to avoid picking a surprising
    // system location.
    let derived = config
        .global
        .admin_socket
        .is_none()
        .then(|| config_dir.map(veil_cfg::default_admin_socket_uri))
        .flatten();
    let admin_socket = config
        .global
        .admin_socket
        .as_deref()
        .or(derived.as_deref())
        .ok_or_else(|| {
            NodeError::AdminProtocol("global.admin_socket must be configured".to_owned())
        })?;
    // TransportUri::parse does not yet carry query strings for the Tcp
    // variant, so we pre-extract `?runtime_dir=` and strip it
    // before parsing. Once TransportUri learns query params natively this
    // block collapses.
    let (uri_body, query_runtime_dir) = split_admin_uri_query(admin_socket)?;

    // handle `pipe://` ourselves because TransportUri doesn't
    // know about Windows NamedPipes. Form: `pipe://LEAF[?runtime_dir=...]`
    // — the LEAF is the part after `\\.\pipe\` in the actual Windows name
    // chosen by the operator (e.g. `veil-admin`).
    if let Some(rest) = uri_body.strip_prefix("pipe://") {
        // Reject empty leaf or any path/port noise.
        let leaf = rest.split('/').next().unwrap_or("");
        if leaf.is_empty() || leaf.contains(':') || leaf.contains('\\') {
            return Err(NodeError::AdminProtocol(format!(
                "global.admin_socket: pipe:// leaf must be a simple name (got: {admin_socket})"
            )));
        }
        let pipe_name = format!(r"\\.\pipe\{leaf}");
        let runtime_dir = query_runtime_dir
            .map(PathBuf::from)
            .or_else(|| config_dir.map(|p| p.to_path_buf()))
            .unwrap_or_else(veil_cfg::runtime_veil_dir);
        return Ok(AdminEndpoint::NamedPipe {
            pipe_name,
            runtime_dir,
        });
    }

    let uri = veil_transport::TransportUri::parse(uri_body)?;
    match uri {
        veil_transport::TransportUri::Unix { path } => Ok(AdminEndpoint::Unix(path)),
        veil_transport::TransportUri::Tcp { host, port } => {
            // `SocketAddr::parse` needs IPv6 literals in bracket form and does
            // not resolve hostnames, so normalize the loopback aliases (the
            // is_loopback check below still gates the result): `::1` →
            // `[::1]:port` — the bare `::1:port` the old code built failed to
            // parse — and `localhost`/`127.0.0.1` → `127.0.0.1:port`. Mirrors
            // the IPC resolver. (audit cycle-3.)
            let hostport = match host.as_str() {
                "::1" => format!("[::1]:{port}"),
                "localhost" | "127.0.0.1" => format!("127.0.0.1:{port}"),
                other => format!("{other}:{port}"),
            };
            let bind_addr: std::net::SocketAddr = hostport.parse().map_err(|e| {
                NodeError::AdminProtocol(format!(
                    "global.admin_socket: invalid tcp address {host}:{port} — {e}"
                ))
            })?;
            // F6 (defense-in-depth): enforce loopback in the resolver itself, not
            // only in config validation. A direct caller (test, tool, future call
            // site) that bypasses validation must not be able to bind the admin
            // endpoint — which has no network auth beyond a local token file — on
            // a routable address.
            if !bind_addr.ip().is_loopback() {
                return Err(NodeError::AdminProtocol(format!(
                    "global.admin_socket: TCP admin endpoint must bind a loopback \
                     address, got {bind_addr}"
                )));
            }
            // Precedence: explicit `?runtime_dir=` query → caller-provided
            // `config_dir` (sidecars next to the config — multi-node-friendly)
            // → per-platform default [`runtime_veil_dir`] (honours
            // `$VEIL_RUNTIME_DIR` etc.).
            let runtime_dir = query_runtime_dir
                .map(PathBuf::from)
                .or_else(|| config_dir.map(|p| p.to_path_buf()))
                .unwrap_or_else(veil_cfg::runtime_veil_dir);
            Ok(AdminEndpoint::Tcp {
                bind_addr,
                runtime_dir,
            })
        }
        _ => Err(NodeError::AdminProtocol(format!(
            "global.admin_socket must use unix://, tcp://, or pipe:// (got: {admin_socket})"
        ))),
    }
}

/// Strip `?runtime_dir=...` from the URI and return the remaining URI body
/// plus the extracted value. `runtime_dir` is the ONLY accepted query
/// parameter; any other key is an error so a typo like `runtime_dri=` fails
/// loudly instead of silently falling back to the default runtime dir (the
/// query is split off before [`veil_transport::TransportUri`] ever sees it, so
/// it would otherwise never be rejected). (audit cycle-3.)
pub fn split_admin_uri_query(uri: &str) -> Result<(&str, Option<String>)> {
    let Some(q_idx) = uri.find('?') else {
        return Ok((uri, None));
    };
    let (body, query) = uri.split_at(q_idx);
    let query = &query[1..]; // skip the '?'
    let mut runtime_dir = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some(rest) = pair.strip_prefix("runtime_dir=") {
            // Trivial percent-decode for `%2F` etc. is unnecessary here:
            // operators supply filesystem paths verbatim and the URI-level
            // escaping is their responsibility. A future patch can upgrade
            // to `percent_encoding` if real-world paths demand it.
            runtime_dir = Some(rest.to_owned());
        } else {
            let key = pair.split('=').next().unwrap_or(pair);
            return Err(NodeError::AdminProtocol(format!(
                "global.admin_socket: unknown query parameter `{key}` (only `runtime_dir` is supported)"
            )));
        }
    }
    Ok((body, runtime_dir))
}

/// Return the canonical anchor path that clients use to locate the admin
/// server.
///
/// `Unix(path)` → the socket path (unchanged behaviour).
/// `Tcp { runtime_dir.. }` → `runtime_dir/admin.anchor`. The file does
/// not exist on disk; it's a synthetic path whose *parent* directory holds
/// the real sidecar files (`admin.port`, `admin.token`) that clients read
/// at connect time. Keeps the `Path`-based public API usable
/// for TCP endpoints without every caller learning the endpoint enum.
///
/// See [`resolve_admin_endpoint`] for `config_dir` semantics.
pub fn admin_socket_path(config: &Config, config_dir: Option<&Path>) -> Result<PathBuf> {
    match resolve_admin_endpoint(config, config_dir)? {
        AdminEndpoint::Unix(path) => Ok(path),
        AdminEndpoint::Tcp { runtime_dir, .. } => Ok(runtime_dir.join(ADMIN_ANCHOR_FILENAME)),
        AdminEndpoint::NamedPipe { runtime_dir, .. } => Ok(runtime_dir.join(ADMIN_ANCHOR_FILENAME)),
    }
}

/// Filename used as the synthetic anchor for TCP admin endpoints (no file
/// actually exists at this path — clients resolve via its sibling sidecars).
pub const ADMIN_ANCHOR_FILENAME: &str = "admin.anchor";

/// Sidecar filename containing the kernel-assigned TCP port written by the
/// server at bind time.
pub const ADMIN_PORT_FILENAME: &str = "admin.port";

/// Sidecar filename containing the 32-byte hex auth token written by the
/// server at bind time.
pub const ADMIN_TOKEN_FILENAME: &str = "admin.token";

/// sidecar filename containing the Windows pipe name (UTF-8)
/// that clients must open. Paired with `admin.token` for auth. Written by
/// the server at NamedPipe bind time. Not used for Unix/TCP backends.
#[cfg(windows)]
pub const ADMIN_PIPE_FILENAME: &str = "admin.pipe";

/// Read one newline-terminated admin request line, bounded to `max_bytes`
/// (audit cycle-8). Reads incrementally through the buffered reader and stops
/// at the first newline OR the cap, whichever comes first, so the accumulator
/// never exceeds `max_bytes` — a client streaming bytes with no newline cannot
/// exhaust daemon memory. Returns `Ok(None)` for EOF-before-newline, an
/// over-cap request, or non-UTF-8 input (all of which the caller treats as
/// "close the connection"); `Ok(Some(line))` with the newline stripped
/// otherwise.
async fn read_bounded_admin_line<R>(
    reader: &mut R,
    max_bytes: usize,
) -> std::io::Result<Option<String>>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut raw: Vec<u8> = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            break; // EOF before a newline
        }
        if let Some(nl) = available.iter().position(|&b| b == b'\n') {
            raw.extend_from_slice(&available[..nl]);
            reader.consume(nl + 1);
            break;
        }
        let n = available.len();
        raw.extend_from_slice(available);
        reader.consume(n);
        if raw.len() > max_bytes {
            return Ok(None);
        }
    }
    if raw.is_empty() || raw.len() > max_bytes {
        return Ok(None);
    }
    Ok(String::from_utf8(raw).ok())
}

async fn handle_admin_connection(
    stream: AdminStream,
    runtime: Arc<Mutex<NodeRuntime>>,
    shutdown_tx: watch::Sender<bool>,
    admin_socket: PathBuf,
    config_path: PathBuf,
) -> Result<()> {
    let mut reader = BufReader::new(stream);

    // Peek at the first byte to detect binary IPC clients that accidentally
    // connected to the admin socket instead of the IPC socket (app.sock).
    // OVL1 frames start with b"OVL1" (0x4F …); JSON requests start with '{'.
    // If we see anything other than '{' we close immediately so the client gets
    // a clear ConnectionError rather than deadlocking forever.
    {
        use tokio::io::AsyncBufReadExt as _;
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return Ok(());
        }
        if buf[0] != b'{' {
            // Not a JSON admin request — close the connection.
            return Ok(());
        }
    }

    // Audit batch 2026-05-25 phase L + audit cycle-8: bound the admin request
    // body AT READ TIME (see `read_bounded_admin_line`). The largest legitimate
    // admin command (RelaySend with a 16-hop path in hex) clocks ~2 KiB; 64 KiB
    // is generous. An over-cap / EOF-without-newline / non-UTF-8 request returns
    // `None` → we silently close (logging would amplify adversary noise).
    const MAX_ADMIN_REQUEST_BYTES: usize = 64 * 1024;
    let line = match read_bounded_admin_line(&mut reader, MAX_ADMIN_REQUEST_BYTES).await? {
        Some(l) => l,
        None => return Ok(()),
    };

    let request: AdminRequest = serde_json::from_str(line.trim_end())?;
    let outcome = if request.version != ADMIN_PROTOCOL_VERSION {
        AdminConnectionOutcome::Response(AdminResponse::err(format!(
            "unsupported admin protocol version `{}`",
            request.version
        )))
    } else {
        execute_admin_command(
            request.command,
            runtime,
            shutdown_tx.clone(),
            admin_socket.clone(),
        )
        .await
    };

    match outcome {
        AdminConnectionOutcome::Response(response) => {
            let stream = reader.get_mut();
            stream
                .write_all(serde_json::to_string(&response)?.as_bytes())
                .await?;
            stream.write_all(b"\n").await?;
            stream.shutdown().await?;
        }
        AdminConnectionOutcome::Restart { response } => {
            let stream = reader.get_mut();
            stream
                .write_all(serde_json::to_string(&response)?.as_bytes())
                .await?;
            stream.write_all(b"\n").await?;
            stream.shutdown().await?;
            let _ = tokio::fs::remove_file(&admin_socket).await;
            spawn_restart_child(&config_path)?;
            let _ = shutdown_tx.send(true);
        }
        AdminConnectionOutcome::DebugStream { response, session } => {
            let mut stream = reader.into_inner();
            stream
                .write_all(serde_json::to_string(&response)?.as_bytes())
                .await?;
            stream.write_all(b"\n").await?;
            bridge_debug_stream(stream, session).await?;
        }
        AdminConnectionOutcome::Streaming { first, mut rx } => {
            let stream = reader.get_mut();
            // Send the first acknowledgement line.
            stream
                .write_all(serde_json::to_string(&first)?.as_bytes())
                .await?;
            stream.write_all(b"\n").await?;
            // Stream subsequent events until the channel closes.
            while let Some(result) = rx.recv().await {
                let resp = AdminResponse::ok(result);
                stream
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                stream.write_all(b"\n").await?;
            }
            stream.shutdown().await?;
        }
    }
    Ok(())
}

#[allow(clippy::large_enum_variant)]
pub enum AdminConnectionOutcome {
    Response(AdminResponse),
    Restart {
        response: AdminResponse,
    },
    DebugStream {
        response: AdminResponse,
        session: crate::runtime::AttachedDebugSession,
    },
    /// Streaming: send `first` then N results from `rx` until channel closes.
    Streaming {
        first: AdminResponse,
        rx: tokio::sync::mpsc::Receiver<AdminResult>,
    },
}

async fn execute_admin_command(
    command: AdminCommand,
    runtime: Arc<Mutex<NodeRuntime>>,
    shutdown_tx: watch::Sender<bool>,
    admin_socket: PathBuf,
) -> AdminConnectionOutcome {
    // keep a clone of the command + runtime handle so the
    // audit hook at the end of the function can build an event AFTER
    // the dispatcher's match has destructured `command` into its
    // per-variant fields. Both clones are cheap (AdminCommand is
    // small enums; runtime is an Arc).
    let command_for_audit = command.clone();
    let runtime_for_audit = Arc::clone(&runtime);
    let result = match command {
        AdminCommand::Run => Err(NodeError::Unsupported(
            "node.run is only valid as a local CLI entrypoint".to_owned(),
        )),
        AdminCommand::Stop => {
            // Use stop_via_arc so the outer lock is released during the
            // 200 ms graceful-shutdown sleep + persist flushes.
            match NodeRuntime::stop_via_arc(Arc::clone(&runtime)).await {
                Ok(()) => {
                    let _ = shutdown_tx.send(true);
                    Ok(AdminResult::Ack {
                        message: "node stopped".to_owned(),
                    })
                }
                Err(err) => Err(err),
            }
        }
        AdminCommand::Restart => {
            // Use stop_via_arc so the outer lock is released during teardown.
            let result = NodeRuntime::stop_via_arc(Arc::clone(&runtime)).await;
            match result {
                Ok(()) => {
                    // audit before the early return — the
                    // standard end-of-dispatch hook is bypassed by
                    // AdminConnectionOutcome::Restart.
                    let audit = runtime.lock().await.admin_audit.clone();
                    if let Some(audit) = audit {
                        let _ = audit.record(&crate::admin_audit::event(
                            "restart",
                            String::new(),
                            crate::admin_audit::AuditOutcome::ok(),
                        ));
                    }
                    return AdminConnectionOutcome::Restart {
                        response: AdminResponse::ok(AdminResult::Ack {
                            message: "node restarted".to_owned(),
                        }),
                    };
                }
                Err(err) => Err(err),
            }
        }
        AdminCommand::Reload => {
            // Use reload_via_arc so the outer lock is released during the
            // 200 ms graceful-shutdown sleep inside do_stop_tasks.
            match NodeRuntime::reload_via_arc(Arc::clone(&runtime)).await {
                Ok(()) => Ok(AdminResult::Ack {
                    message: "node reloaded".to_owned(),
                }),
                Err(err) => Err(err),
            }
        }
        AdminCommand::Show => {
            let runtime = runtime.lock().await;
            let summary = runtime.summary();
            // scrub `?token=...` (and any query-string) before
            // exposing the metrics endpoint. Operators routinely paste
            // `node show` output into chat / tickets — secret-bearing
            // URLs must not survive that path.
            let metrics_endpoint = summary.metrics_endpoint.map(|url| match url.find('?') {
                Some(q) => format!("{} (query-stripped)", &url[..q]),
                None => url,
            });
            // collect compile-time feature flags relevant to
            // ops. `cfg!(feature = "...")` is evaluated at compile time;
            // disabled features simply omit themselves from the list.
            let mut build_features = Vec::new();
            if cfg!(feature = "production-seeds") {
                build_features.push("production-seeds".to_owned());
            }
            if cfg!(feature = "allow-empty-seeds") {
                build_features.push("allow-empty-seeds".to_owned());
            }
            if cfg!(feature = "rocksdb-cold") {
                build_features.push("rocksdb-cold".to_owned());
            }
            Ok(AdminResult::Show(AdminNodeSummary {
                node_id: summary.node_id.to_string(),
                role: summary.role.to_string(),
                config_path: summary.config_path.display().to_string(),
                admin_socket: admin_socket.display().to_string(),
                foreground_mode: summary.foreground_mode,
                uptime_secs: summary.started_at.elapsed().as_secs(),
                metrics_active: summary.metrics_active,
                metrics_endpoint,
                peers_configured: summary.peers_configured,
                sessions_active: summary.sessions_active,
                listens_active: summary.listens_active,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                build_features,
            }))
        }
        AdminCommand::Health => {
            // Sample the health-tick counter twice with a 1-second gap to
            // detect whether the maintenance loop is still advancing.
            let (tick_before, sessions) = {
                let rt = runtime.lock().await;
                (rt.health_tick(), rt.sessions().len())
            };
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let tick_after = runtime.lock().await.health_tick();
            let status = if tick_after > tick_before {
                "ok"
            } else {
                "stalled"
            }
            .to_owned();
            Ok(AdminResult::Health(AdminHealthReport {
                tick: tick_after,
                sessions,
                status,
            }))
        }
        AdminCommand::Listens => {
            let runtime = runtime.lock().await;
            let listens = runtime
                .listens()
                .into_iter()
                .map(admin_listen_entry)
                .collect();
            Ok(AdminResult::Listens { listens })
        }
        AdminCommand::Sessions => {
            let runtime = runtime.lock().await;
            // pull a single loss-tracker snapshot and join it into
            // each session entry by node_id. Snapshot is cheap (HashMap
            // clone of a few hundred entries at most).
            let loss_by_peer: std::collections::HashMap<NodeIdBytes, (f32, u32)> = runtime
                .loss_tracker_snapshot()
                .into_iter()
                .map(|(p, r, s)| (p, (r, s)))
                .collect();
            let sessions = runtime
                .sessions()
                .into_iter()
                .map(|session| {
                    let mut entry = admin_session_entry(session.clone());
                    if let Some(node_id) = session.node_id.as_ref()
                        && let Some((rate, samples)) = loss_by_peer.get(node_id.as_bytes())
                        && *samples > 0
                    {
                        // Only surface stats when the last window had
                        // samples — keeps the column meaningful.
                        entry.loss_rate_pct = Some((rate * 100.0).round() as u16);
                        entry.loss_samples = Some(*samples);
                    }
                    entry
                })
                .collect();
            Ok(AdminResult::Sessions { sessions })
        }
        AdminCommand::DebugPeerConnect { peer_id } => {
            let access = { runtime.lock().await.access() };
            match access.connect_peer(peer_id).await {
                Ok(session) => {
                    return AdminConnectionOutcome::DebugStream {
                        response: AdminResponse::ok(AdminResult::Ack {
                            message: format!(
                                "debug stream attached: link_id={} source={}",
                                session.link_id, session.source
                            ),
                        }),
                        session,
                    };
                }
                Err(err) => Err(err),
            }
        }
        AdminCommand::DebugNodeAccept { listen_id } => {
            let access = { runtime.lock().await.access() };
            match access.accept_listen(listen_id).await {
                Ok(session) => {
                    return AdminConnectionOutcome::DebugStream {
                        response: AdminResponse::ok(AdminResult::Ack {
                            message: format!(
                                "debug stream attached: link_id={} source={}",
                                session.link_id, session.source
                            ),
                        }),
                        session,
                    };
                }
                Err(err) => Err(err),
            }
        }

        // ── Diagnostics ────────────────────────────────────────────
        AdminCommand::DebugPing {
            target,
            count,
            interval_ms,
            timeout_ms,
        } => {
            let target_id = match resolve_node_target(&runtime, &target).await {
                Ok(id) => id,
                Err(e) => return AdminConnectionOutcome::Response(AdminResponse::err(e)),
            };
            let (event_tx, event_rx) = tokio::sync::mpsc::channel::<AdminResult>(64);
            let access = { runtime.lock().await.access() };
            tokio::spawn(run_debug_ping(
                access,
                target_id,
                count,
                interval_ms,
                timeout_ms,
                event_tx,
            ));
            return AdminConnectionOutcome::Streaming {
                first: AdminResponse::ok(AdminResult::Ack {
                    message: format!("pinging {} ({} packets)", target, count),
                }),
                rx: event_rx,
            };
        }

        AdminCommand::DebugTrace {
            target,
            max_hops,
            timeout_ms,
        } => {
            let target_id = match resolve_node_target(&runtime, &target).await {
                Ok(id) => id,
                Err(e) => return AdminConnectionOutcome::Response(AdminResponse::err(e)),
            };
            let (event_tx, event_rx) = tokio::sync::mpsc::channel::<AdminResult>(64);
            let access = { runtime.lock().await.access() };
            tokio::spawn(run_debug_trace(
                access, target_id, max_hops, timeout_ms, event_tx,
            ));
            return AdminConnectionOutcome::Streaming {
                first: AdminResponse::ok(AdminResult::Ack {
                    message: format!("traceroute to {} (max {} hops)", target, max_hops),
                }),
                rx: event_rx,
            };
        }

        AdminCommand::DebugCapture {
            filter_node_id,
            filter_family,
            limit,
        } => {
            let filter = match filter_node_id.as_deref() {
                Some(s) => match parse_node_id_hex(s).map_err(|e| e.to_string()) {
                    Ok(id) => Some(id),
                    Err(e) => return AdminConnectionOutcome::Response(AdminResponse::err(e)),
                },
                None => None,
            };
            let (event_tx, event_rx) = tokio::sync::mpsc::channel::<AdminResult>(256);
            let capture_rx = {
                let mut rt = runtime.lock().await;
                rt.subscribe_capture()
            };
            tokio::spawn(run_debug_capture(
                capture_rx,
                filter,
                filter_family,
                limit,
                event_tx,
            ));
            return AdminConnectionOutcome::Streaming {
                first: AdminResponse::ok(AdminResult::Ack {
                    message: "capture started".to_owned(),
                }),
                rx: event_rx,
            };
        }
        AdminCommand::BanNode { node_id } => {
            let id = match resolve_node_target(&runtime, &node_id).await {
                Ok(id) => id,
                Err(e) => return AdminConnectionOutcome::Response(AdminResponse::err(e)),
            };
            runtime.lock().await.ban_node(id.into());
            Ok(AdminResult::Ack {
                message: format!("banned {node_id}"),
            })
        }
        AdminCommand::UnbanNode { node_id } => {
            let id = match resolve_node_target(&runtime, &node_id).await {
                Ok(id) => id,
                Err(e) => return AdminConnectionOutcome::Response(AdminResponse::err(e)),
            };
            runtime.lock().await.unban_node(id.into());
            Ok(AdminResult::Ack {
                message: format!("unbanned {node_id}"),
            })
        }
        AdminCommand::PNetBan { node_id, reason } => {
            let id = match resolve_node_target(&runtime, &node_id).await {
                Ok(id) => id,
                Err(e) => return AdminConnectionOutcome::Response(AdminResponse::err(e)),
            };
            let reason = reason.unwrap_or_else(|| "admin ban".to_owned());
            // audit cycle-6 (T7): prepare (sign + local-ban apply) UNDER the
            // lock, drop it, then run the DHT replication fan-out without
            // holding the NodeRuntime mutex across the multi-second network walk.
            let prepared = { runtime.lock().await.prepare_p_net_ban(id, reason.clone()) };
            let result = match prepared {
                Ok(prep) => prep.replicate().await,
                Err(e) => Err(e),
            };
            match result {
                Ok(replicas) => Ok(AdminResult::Ack {
                    message: format!(
                        "p-net ban issued for {node_id}; replicas_sent={replicas}; reason={reason}"
                    ),
                }),
                Err(e) => Err(NodeError::AdminProtocol(format!("p-net ban failed: {e}"))),
            }
        }
        AdminCommand::ListBans => {
            let bans = runtime.lock().await.list_bans();
            Ok(AdminResult::BanList {
                bans: bans
                    .into_iter()
                    .map(|(nid, reason, manual, banned_at_unix)| AdminBanEntry {
                        node_id: nid,
                        reason,
                        manual,
                        banned_at_unix,
                    })
                    .collect(),
            })
        }
        AdminCommand::KillSession { link_id } => {
            let rt = runtime.lock().await;
            // Find the session's node_id from the sessions list.
            let node_id_opt = rt
                .sessions()
                .into_iter()
                .find(|s| s.link_id.get() == link_id)
                .and_then(|s| s.node_id);
            if let Some(nid) = node_id_opt {
                rt.kill_session(nid);
                Ok(AdminResult::Ack {
                    message: format!("killed session link_id=0x{link_id:016x}"),
                })
            } else {
                Ok(AdminResult::Ack {
                    message: format!("session link_id=0x{link_id:016x} not found"),
                })
            }
        }

        AdminCommand::Bandwidth => {
            let rt = runtime.lock().await;
            let (il, ol, itb, idb, otb, odb, ppc, ppa, ppd) = rt.bandwidth_stats();
            Ok(AdminResult::Bandwidth {
                inbound_limit_kbps: il,
                outbound_limit_kbps: ol,
                inbound_total_bytes: itb,
                inbound_dropped_bytes: idb,
                outbound_total_bytes: otb,
                outbound_dropped_bytes: odb,
                per_peer_byte_cap_bytes_per_sec: ppc,
                per_peer_bytes_allowed_total: ppa,
                per_peer_bytes_dropped_total: ppd,
            })
        }

        AdminCommand::SetMobileBackgroundMode { enabled } => {
            let rt = runtime.lock().await;
            rt.set_mobile_background_mode(enabled);
            Ok(AdminResult::Ack {
                message: format!("mobile_background_mode = {enabled}"),
            })
        }

        AdminCommand::UpdateStatus => {
            let rt = runtime.lock().await;
            Ok(AdminResult::UpdateStatus(rt.update_status()))
        }

        AdminCommand::MobileStatus => {
            let rt = runtime.lock().await;
            Ok(AdminResult::MobileStatus(rt.mobile_status()))
        }

        AdminCommand::ApplyConfig {
            toml_content,
            persist,
        } => {
            // Delegate to the via_arc variant so the long-running
            // stop-tasks phase doesn't hold the outer Arc<Mutex<...>>
            // lock — concurrent admin commands (e.g., a Show issued
            // from another shell) stay responsive during the ~200 ms
            // graceful-shutdown phase.
            match NodeRuntime::apply_config_bytes_via_arc(
                Arc::clone(&runtime),
                &toml_content,
                persist,
            )
            .await
            {
                Ok(()) => Ok(AdminResult::Ack {
                    message: if persist {
                        "config applied + persisted".to_owned()
                    } else {
                        "config applied (in-memory only)".to_owned()
                    },
                }),
                Err(err) => Err(err),
            }
        }

        // ── Introspection ─────────────────────────────────────────
        AdminCommand::Metrics => collect_metrics_snapshot(&runtime).await,

        AdminCommand::DhtList => {
            let runtime = runtime.lock().await;
            // Cap the listing so a large (possibly RocksDB-backed) store can't
            // be materialized in full into the admin response.
            let (raw, truncated) = runtime.dht_stored_entries_limited(MAX_ADMIN_DHT_LIST);
            let entries = raw
                .into_iter()
                .map(|(k, v)| AdminDhtEntry {
                    key: node_id_hex(&k),
                    value_hex: bytes_to_hex(&v),
                    value_len: v.len(),
                })
                .collect();
            Ok(AdminResult::DhtEntries { entries, truncated })
        }

        AdminCommand::DhtRouting => {
            let runtime = runtime.lock().await;
            let contacts = runtime
                .dht_contacts()
                .into_iter()
                .map(|c| AdminDhtContact {
                    node_id: node_id_hex(&c.node_id),
                    transport: c.transport,
                })
                .collect();
            Ok(AdminResult::DhtContacts { contacts })
        }

        AdminCommand::DhtGet { key } => {
            let key_bytes = match parse_node_id_hex(&key).map_err(|e| e.to_string()) {
                Ok(b) => b,
                Err(e) => return AdminConnectionOutcome::Response(AdminResponse::err(e)),
            };
            let runtime = runtime.lock().await;
            let value = runtime.dht_get_local(&key_bytes);
            let value_len = value.as_ref().map(|v| v.len()).unwrap_or(0);
            Ok(AdminResult::DhtValue {
                key,
                value_hex: value.map(|v| bytes_to_hex(&v)),
                value_len,
            })
        }

        AdminCommand::DhtRecursiveGet { key, timeout_ms } => {
            let key_bytes = match parse_node_id_hex(&key).map_err(|e| e.to_string()) {
                Ok(b) => b,
                Err(e) => return AdminConnectionOutcome::Response(AdminResponse::err(e)),
            };
            // audit cycle-6 (T7): take an Arc-cloned NodeServices bundle and
            // drop the NodeRuntime lock before the network await (DHT walk), so
            // the recursive get does not serialise other admin commands +
            // reload/health ticks. `dht_recursive_get` now lives on NodeServices.
            let access = { runtime.lock().await.access() };
            let value = access
                .dht_recursive_get(key_bytes, std::time::Duration::from_millis(timeout_ms))
                .await;
            let value_len = value.as_ref().map(|v| v.len()).unwrap_or(0);
            Ok(AdminResult::DhtValue {
                key,
                value_hex: value.map(|v| bytes_to_hex(&v)),
                value_len,
            })
        }

        AdminCommand::RelaySend {
            path,
            app_id,
            endpoint_id,
            data_hex,
        } => {
            use veil_proto::app::AppSendPayload;
            use veil_proto::codec::encode_header;
            use veil_proto::delivery::{MAX_RELAY_PATH_HOPS, RelayPathPayload};
            use veil_proto::family::{DeliveryMsg, FrameFamily};
            use veil_proto::header::{FrameHeader, priority};

            // ── Validate inputs ────────────────────────────────────
            if path.is_empty() {
                return AdminConnectionOutcome::Response(AdminResponse::err(
                    "RelaySend: path must contain at least one hop".to_string(),
                ));
            }
            if path.len() > MAX_RELAY_PATH_HOPS {
                return AdminConnectionOutcome::Response(AdminResponse::err(format!(
                    "RelaySend: path length {} exceeds MAX_RELAY_PATH_HOPS={MAX_RELAY_PATH_HOPS}",
                    path.len()
                )));
            }
            let mut parsed_path = Vec::with_capacity(path.len());
            for (i, p) in path.iter().enumerate() {
                match parse_node_id_hex(p).map_err(|e| e.to_string()) {
                    Ok(b) => parsed_path.push(b),
                    Err(e) => {
                        return AdminConnectionOutcome::Response(AdminResponse::err(format!(
                            "RelaySend: path[{i}] invalid hex node_id: {e}"
                        )));
                    }
                }
            }
            // Audit batch 2026-05-25 phase M: reject self-referential
            // mid-path hops.  An operator-supplied path of the form
            // `[remote, local_node_id, remote2]` causes the routing
            // layer to detect a loop and drop the frame mid-flight,
            // leaving the operator unable to diagnose the silent
            // failure.  Surfacing as a clean error at the admin
            // boundary makes the misconfiguration immediately visible.
            // The first hop CAN legitimately be local_node_id (caller-
            // initiated source-route), so we only check positions ≥ 1.
            {
                let local = runtime.lock().await.access().local_node_id;
                for (i, hop) in parsed_path.iter().enumerate() {
                    if i > 0 && *hop == local {
                        return AdminConnectionOutcome::Response(AdminResponse::err(format!(
                            "RelaySend: path[{i}] is local_node_id (self-loop will be \
                             routing-rejected); only path[0] may be the local node"
                        )));
                    }
                }
            }
            let app_id_bytes = match parse_node_id_hex(&app_id).map_err(|e| e.to_string()) {
                Ok(b) => b,
                Err(e) => {
                    return AdminConnectionOutcome::Response(AdminResponse::err(format!(
                        "RelaySend: app_id invalid hex: {e}"
                    )));
                }
            };
            let data = match parse_hex_bytes(&data_hex) {
                Ok(d) => d,
                Err(e) => {
                    return AdminConnectionOutcome::Response(AdminResponse::err(format!(
                        "RelaySend: data_hex invalid: {e}"
                    )));
                }
            };

            // ── Build inner AppSendPayload ────────────────────────
            let inner = AppSendPayload {
                src_app_id: [0u8; 32],
                app_id: app_id_bytes,
                endpoint_id,
                data: veil_bufpool::pooled_shared_from_vec(data),
            };
            let inner_bytes = inner.encode();

            // ── Wrap in RelayPathPayload + encode frame ───────────
            let relay = RelayPathPayload {
                path: parsed_path.clone(),
                next_hop: 0,
                inner: inner_bytes,
            };
            let body = relay.encode();
            let mut hdr =
                FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::RelayPath as u16);
            hdr.body_len = body.len() as u32;
            hdr.set_priority(priority::INTERACTIVE);
            let mut frame = encode_header(&hdr).to_vec();
            frame.extend_from_slice(&body);

            // ── Send to first hop's session ────────────────────────
            let first_hop = parsed_path[0];
            let runtime_guard = runtime.lock().await;
            let sent = veil_util::rlock!(runtime_guard.access().session_tx_registry).send_to(
                &first_hop,
                priority::INTERACTIVE,
                frame,
            );
            Ok(AdminResult::RelaySendResult {
                sent,
                first_hop: bytes_to_hex(&first_hop),
                hops: parsed_path.len() as u8,
            })
        }

        AdminCommand::ResolveIdentity {
            node_id,
            timeout_ms,
        } => {
            let id_bytes = match parse_node_id_hex(&node_id).map_err(|e| e.to_string()) {
                Ok(b) => b,
                Err(e) => return AdminConnectionOutcome::Response(AdminResponse::err(e)),
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // audit cycle-6 (T7): drop the lock before the network await.
            let access = { runtime.lock().await.access() };
            let result = access
                .resolve_identity_verified(
                    id_bytes,
                    now,
                    std::time::Duration::from_millis(timeout_ms),
                )
                .await;
            match result {
                Ok(v) => Ok(AdminResult::ResolvedIdentity {
                    node_id: bytes_to_hex(&v.node_id),
                    master_algo: v.master_algo,
                    active_key_idx: v.active_key_idx,
                    active_device_id: bytes_to_hex(&v.active_device_id),
                }),
                Err(e) => {
                    return AdminConnectionOutcome::Response(AdminResponse::err(format!(
                        "resolve identity failed: {e}"
                    )));
                }
            }
        }

        AdminCommand::ResolveName { name, timeout_ms } => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            // audit cycle-6 (T7): drop the lock before the network await.
            let access = { runtime.lock().await.access() };
            let result = access
                .resolve_name_verified(&name, now, std::time::Duration::from_millis(timeout_ms))
                .await;
            match result {
                Ok(v) => Ok(AdminResult::ResolvedIdentity {
                    node_id: bytes_to_hex(&v.node_id),
                    master_algo: v.master_algo,
                    active_key_idx: v.active_key_idx,
                    active_device_id: bytes_to_hex(&v.active_device_id),
                }),
                Err(e) => {
                    return AdminConnectionOutcome::Response(AdminResponse::err(format!(
                        "resolve name failed: {e}"
                    )));
                }
            }
        }

        AdminCommand::NatProbe {
            target_node_id,
            per_coordinator_timeout_ms,
        } => {
            let target = match parse_node_id_hex(&target_node_id).map_err(|e| e.to_string()) {
                Ok(b) => b,
                Err(e) => return AdminConnectionOutcome::Response(AdminResponse::err(e)),
            };
            // Empty local_candidates = signaling-only probe; punching is
            // a follow-up slice that will plumb in the node's actual
            // listen addresses + STUN-discovered srflx address. For
            // operator diagnostic the target's candidates are what
            // matters anyway.
            // audit cycle-6 (P10): take an Arc-cloned `NodeServices` bundle and
            // DROP the NodeRuntime lock before the network await, so a
            // multi-second NAT probe does not hold the global runtime mutex
            // (which serialises every other admin command + the SIGHUP reloader
            // and health ticks). `try_nat_traversal` already lives on
            // NodeServices — the NodeRuntime method is just a thin lock-holding
            // wrapper around `self.access().try_nat_traversal(...)`, so this is
            // behaviour-identical.
            let access = { runtime.lock().await.access() };
            let result = access
                .try_nat_traversal(
                    target,
                    Vec::new(),
                    std::time::Duration::from_millis(per_coordinator_timeout_ms),
                )
                .await;
            match result {
                Some(reply) => {
                    use veil_nat::discovery::candidate_to_socket_addr;
                    let candidates: Vec<AdminNatCandidate> = reply
                        .candidates
                        .iter()
                        .map(|c| AdminNatCandidate {
                            atyp: c.atyp,
                            candidate_type: c.candidate_type,
                            priority: c.priority,
                            addr: candidate_to_socket_addr(c)
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "<malformed>".to_owned()),
                        })
                        .collect();
                    Ok(AdminResult::NatProbeResult {
                        responder_node_id: bytes_to_hex(&reply.responder_node_id),
                        candidate_count: candidates.len(),
                        candidates,
                    })
                }
                None => {
                    return AdminConnectionOutcome::Response(AdminResponse::err(format!(
                        "NAT probe to {target_node_id} failed: no coordinator could reach the target \
                         within {per_coordinator_timeout_ms}ms (target may be offline, all \
                         coordinators may lack a session to it, or the probe was lost)",
                    )));
                }
            }
        }

        AdminCommand::DhtPut { key, value } => {
            let key_bytes = match parse_node_id_hex(&key).map_err(|e| e.to_string()) {
                Ok(b) => b,
                Err(e) => return AdminConnectionOutcome::Response(AdminResponse::err(e)),
            };
            let value_bytes = match parse_hex_bytes(&value) {
                Ok(b) => b,
                Err(e) => return AdminConnectionOutcome::Response(AdminResponse::err(e)),
            };
            runtime.lock().await.dht_put_local(key_bytes, value_bytes);
            Ok(AdminResult::Ack {
                message: format!("stored {key}"),
            })
        }

        AdminCommand::DhtPublishReplicated { key, value } => {
            let key_bytes = match parse_node_id_hex(&key).map_err(|e| e.to_string()) {
                Ok(b) => b,
                Err(e) => return AdminConnectionOutcome::Response(AdminResponse::err(e)),
            };
            let value_bytes = match parse_hex_bytes(&value) {
                Ok(b) => b,
                Err(e) => return AdminConnectionOutcome::Response(AdminResponse::err(e)),
            };
            let sent = runtime
                .lock()
                .await
                .dht_publish_replicated(key_bytes, value_bytes);
            Ok(AdminResult::Ack {
                message: format!("stored {key} locally and fanned out to {sent} peer(s)"),
            })
        }

        AdminCommand::DiscoveryList => {
            let runtime = runtime.lock().await;
            let attachments = runtime
                .discovery_all_attachments()
                .into_iter()
                .map(|a| AdminAttachmentEntry {
                    node_id: node_id_hex(&a.node_id),
                    role: a.role,
                    epoch: a.epoch,
                    expires_at: a.expires_at,
                    gateways: a
                        .gateways
                        .iter()
                        .map(|g| node_id_hex(&g.gateway_node_id))
                        .collect(),
                })
                .collect();
            Ok(AdminResult::DiscoveryEntries { attachments })
        }

        AdminCommand::GatewayList => {
            let runtime = runtime.lock().await;
            let nodes = runtime
                .gateway_attached_nodes()
                .into_iter()
                .map(|id| node_id_hex(&id))
                .collect();
            Ok(AdminResult::GatewayAttachments { nodes })
        }

        AdminCommand::MeshStatus => {
            let runtime = runtime.lock().await;
            let gateways = runtime
                .mesh_gateway_status()
                .into_iter()
                .map(|e| AdminMeshGatewayEntry {
                    node_id: node_id_hex(&e.node_id),
                    veil_addr: e.veil_addr,
                    is_active: e.is_active,
                    rtt_smoothed_ms: e.rtt_smoothed_ms,
                    battery_level: e.battery_level,
                    last_seen_secs_ago: e.last_seen_secs_ago,
                    expires_in_secs: e.expires_in_secs,
                })
                .collect();
            Ok(AdminResult::MeshStatus { gateways })
        }

        AdminCommand::BootstrapStatus => {
            let runtime = runtime.lock().await;
            Ok(AdminResult::BootstrapStatus(runtime.bootstrap_status()))
        }

        AdminCommand::Routes { dst_filter } => {
            // Parse optional filter once, up front — bad input shouldn't
            // silently degrade to "show everything".
            let filter_bytes = match dst_filter.as_deref() {
                Some(s) => match parse_node_id_hex(s) {
                    Ok(b) => Some(b),
                    Err(e) => {
                        return AdminConnectionOutcome::Response(AdminResponse::err(format!(
                            "invalid dst_node_id: {e}"
                        )));
                    }
                },
                None => None,
            };
            let rt = runtime.lock().await;
            let routes = rt
                .route_cache_all()
                .into_iter()
                .filter(|(dst, _, _, _)| filter_bytes.is_none_or(|f| *dst == f))
                .map(|(dst, next_hop, score, hops)| AdminRouteEntry {
                    dst: node_id_hex(&dst),
                    next_hop: node_id_hex(&next_hop),
                    score,
                    hops,
                })
                .collect();
            let (mp_en, mp_paths, mp_min_prio, redund, ecmp_band) = rt.multi_path_config();
            Ok(AdminResult::Routes {
                routes,
                multi_path: AdminMultiPathConfig {
                    multi_path_enabled: mp_en,
                    max_parallel_paths: mp_paths,
                    multi_path_min_priority: mp_min_prio,
                    redundant_send: redund,
                    ecmp_score_band: ecmp_band,
                },
            })
        }

        // ── Route discovery ────────────────────────────────────────
        AdminCommand::DiscoverySearch => runtime
            .lock()
            .await
            .trigger_discovery_search()
            .map(|()| AdminResult::DiscoverySearchTriggered),

        // ── distributed tracing ────────────────────────────────────
        AdminCommand::PexStatus => {
            let rt = runtime.lock().await;
            let (peers, walks, last_walk) = rt.pex_status();
            let last_walk_secs_ago = last_walk.map(|t| t.elapsed().as_secs());
            Ok(AdminResult::PexStatus {
                discovered_peers: peers,
                active_walks: walks,
                last_walk_secs_ago,
            })
        }

        AdminCommand::PeersDiscovered => {
            let rt = runtime.lock().await;
            Ok(AdminResult::DiscoveredPeers {
                peers: rt.discovered_peers(),
            })
        }

        AdminCommand::SwapTransport {
            peer_node_id,
            alt_uri,
        } => {
            // cycle-7 (MED): build the self-contained warm-probe config under the
            // runtime lock (fast, sync), then DROP the lock before driving the
            // multi-step handoff (warm-dial + HandoffAck round-trip, with
            // AckTimeout). The old code held the global runtime mutex across the
            // whole .await, stalling every other runtime-lock user for the
            // handoff/ack-timeout duration.
            let prepared = {
                let rt = runtime.lock().await;
                rt.prepare_hot_standby_handoff(&peer_node_id, &alt_uri)
            };
            match prepared {
                Ok(cfg) => {
                    NodeRuntime::run_hot_standby_handoff(cfg)
                        .await
                        .map(|()| AdminResult::Ack {
                            message: format!(
                                "hot-standby handoff triggered for peer={peer_node_id} to {alt_uri}"
                            ),
                        })
                }
                Err(e) => Err(e),
            }
        }

        AdminCommand::TraceQuery { trace_id: id_str } => {
            async move {
                // Accept decimal or `0x`-prefixed hex.
                let trace_id: u64 = if id_str.starts_with("0x") || id_str.starts_with("0X") {
                    u64::from_str_radix(&id_str[2..], 16).map_err(|_| {
                        NodeError::InvalidArgument(format!("invalid trace_id: {id_str}"))
                    })?
                } else {
                    id_str.parse::<u64>().map_err(|_| {
                        NodeError::InvalidArgument(format!("invalid trace_id: {id_str}"))
                    })?
                };
                let hops: Vec<AdminTraceHop> = {
                    let rt = runtime.lock().await;
                    let tb = rt.trace_buffer();
                    lock!(tb).query(trace_id)
                }
                .into_iter()
                .map(|r| AdminTraceHop {
                    from_peer: node_id_hex(&r.from_peer),
                    to_peer: node_id_hex(&r.to_peer),
                    hop_rtt_ms: r.hop_rtt_ms,
                    timestamp_ms: r.timestamp_ms,
                })
                .collect();
                Ok(AdminResult::TraceHops {
                    trace_id: format!("{trace_id:#018x}"),
                    hops,
                })
            }
            .await
        }
    };

    // mutating commands. No-op for read-only
    // commands (`audit_event_for` returns None). Failures to write
    // the audit are logged at warn but do NOT block the response.
    if let Some(event) = audit_event_for(&command_for_audit, &result) {
        let audit = runtime_for_audit.lock().await.admin_audit.clone();
        if let Some(audit) = audit
            && let Err(e) = audit.record(&event)
        {
            log::warn!(
                "admin.audit.write_failed event={} err={e}",
                event.command_kind
            );
        }
    }

    AdminConnectionOutcome::Response(match result {
        Ok(result) => AdminResponse::ok(result),
        Err(err) => AdminResponse::err(err.to_string()),
    })
}

/// build an audit event for `command` using the
/// command's `result`. Returns `None` for read-only commands which
/// don't deserve an audit entry (would only swamp the log under
/// steady-state monitoring polling). The args string is intended to
/// be operator-grep-friendly; it carries the command's input
/// parameters but no secrets.
pub fn audit_event_for(
    command: &AdminCommand,
    result: &Result<AdminResult>,
) -> Option<crate::admin_audit::AuditEvent> {
    use crate::admin_audit::{AuditOutcome, event};
    let outcome = match result {
        Ok(_) => AuditOutcome::ok(),
        Err(err) => AuditOutcome::err(err.to_string()),
    };
    let (kind, args) = match command {
        AdminCommand::Stop => ("stop", String::new()),
        AdminCommand::Reload => ("reload", String::new()),
        AdminCommand::BanNode { node_id } => ("ban_node", format!("node_id={node_id}")),
        AdminCommand::UnbanNode { node_id } => ("unban_node", format!("node_id={node_id}")),
        AdminCommand::PNetBan { node_id, reason } => (
            "p_net_ban",
            format!(
                "node_id={node_id} reason={}",
                reason.as_deref().unwrap_or("<default>"),
            ),
        ),
        AdminCommand::KillSession { link_id } => {
            ("kill_session", format!("link_id=0x{link_id:016x}"))
        }
        AdminCommand::DhtPut { key, value } => {
            ("dht_put", format!("key={key} value_len={}", value.len()))
        }
        AdminCommand::DebugPeerConnect { peer_id } => {
            ("debug_peer_connect", format!("peer_id={peer_id:?}"))
        }
        AdminCommand::DebugNodeAccept { listen_id } => {
            ("debug_node_accept", format!("listen_id={listen_id:?}"))
        }
        AdminCommand::SwapTransport {
            peer_node_id,
            alt_uri,
        } => (
            "swap_transport",
            format!("peer={peer_node_id} alt_uri={alt_uri}"),
        ),
        AdminCommand::ApplyConfig {
            toml_content,
            persist,
        } => (
            "apply_config",
            // Don't log raw config content — may contain identity
            // keys / passphrases / token secrets.  Log just the byte
            // length and persist-flag so audit trail can correlate with
            // expected ops batches without leaking secrets.
            format!("toml_bytes={} persist={persist}", toml_content.len()),
        ),
        // Read-only commands: not audited.
        _ => return None,
    };
    Some(event(kind, args, outcome))
}

// ── Extracted handlers for the larger AdminCommand arms ─────────────────────

async fn collect_metrics_snapshot(runtime: &Arc<Mutex<NodeRuntime>>) -> Result<AdminResult> {
    let runtime = runtime.lock().await;
    let mlkem_key_age_secs = runtime.mlkem_key_age_secs();
    let opt_snap = runtime.metrics_snapshot();
    let metrics_enabled = opt_snap.is_some();
    let snap = opt_snap.unwrap_or_default();
    Ok(AdminResult::Metrics(AdminMetricsSnapshot {
        metrics_enabled,
        configured_peers: snap.configured_peers,
        active_sessions: snap.active_sessions,
        inbound_sessions_total: snap.inbound_sessions_total,
        outbound_connect_attempts_total: snap.outbound_connect_attempts_total,
        outbound_connect_failures_total: snap.outbound_connect_failures_total,
        transport_bytes_rx_total: snap.transport_bytes_rx_total,
        transport_bytes_tx_total: snap.transport_bytes_tx_total,
        session_handshake_failures_total: snap.session_handshake_failures_total,
        dht_store_total: snap.dht_store_total,
        dht_lookup_total: snap.dht_lookup_total,
        mesh_relay_hops_total: snap.mesh_relay_hops_total,
        decrypt_failures_total: snap.decrypt_failures_total,
        storage_evictions_total: snap.storage_evictions_total,
        route_miss_total: snap.route_miss_total,
        discovery_triggered_total: snap.discovery_triggered_total,
        route_recovery_total: snap.route_recovery_total,
        network_reachability_score_pct: (snap.network_reachability_score * 100.0) as u64,
        route_selection_avg_rtt_ms: snap.route_selection_avg_rtt,
        vivaldi_prediction_error_ms: snap.vivaldi_prediction_error,
        vivaldi_coord_x: snap.vivaldi_coord_x,
        vivaldi_coord_y: snap.vivaldi_coord_y,
        vivaldi_coord_height: snap.vivaldi_coord_height,
        vivaldi_coord_error: snap.vivaldi_coord_error,
        rate_limit_drops_total: snap.rate_limit_drops_total,
        backpressure_received_total: snap.backpressure_received_total,
        ban_actions_total: snap.ban_actions_total,
        rt_frames_rx_total: snap.rt_frames_rx_total,
        rt_frames_tx_total: snap.rt_frames_tx_total,
        rt_seq_gaps_total: snap.rt_seq_gaps_total,
        app_msg_channel_full_total: snap.app_msg_channel_full_total,
        app_msg_channel_closed_total: snap.app_msg_channel_closed_total,
        mlkem_key_age_secs,
    }))
}

pub fn admin_listen_entry(listen: ListenConfigEntry) -> AdminListenEntry {
    AdminListenEntry {
        listen_id: listen.listen_id.to_string(),
        listener_handle: listen.listener_handle.map(|value| value.to_string()),
        transport: listen.transport,
        local_addr: listen.local_addr,
        active: listen.active,
    }
}

pub fn admin_session_entry(session: SessionInfo) -> AdminSessionEntry {
    AdminSessionEntry {
        link_id: session.link_id.to_string(),
        node_id: session.node_id.map(|value| value.to_string()),
        nonce: session.nonce,
        matched_peer_id: session.matched_peer_id.map(|value| value.to_string()),
        source: session.source.to_string(),
        transport: session.transport,
        state: session.state.to_string(),
        // loss fields are populated by the Sessions handler after
        // joining the SessionInfo with a loss-tracker snapshot by node_id;
        // this helper builds the base entry, leaving them as None.
        loss_rate_pct: None,
        loss_samples: None,
    }
}

async fn bridge_debug_stream(
    mut admin_stream: AdminStream,
    mut session: crate::runtime::AttachedDebugSession,
) -> Result<()> {
    let (from_admin, to_admin) =
        tokio::io::copy_bidirectional(&mut admin_stream, &mut session.stream).await?;
    if let Some(metrics) = &session.metrics {
        metrics.add_transport_bytes_tx(from_admin);
        metrics.add_transport_bytes_rx(to_admin);
    }
    let _ = session.stream.shutdown().await;
    let _ = admin_stream.shutdown().await;
    Ok(())
}

pub async fn open_peer_debug_stream(socket_path: &Path, peer_id: PeerId) -> Result<AdminStream> {
    open_debug_stream(socket_path, AdminCommand::DebugPeerConnect { peer_id }).await
}

pub async fn open_listen_debug_stream(
    socket_path: &Path,
    listen_id: ListenId,
) -> Result<AdminStream> {
    open_debug_stream(socket_path, AdminCommand::DebugNodeAccept { listen_id }).await
}

async fn open_debug_stream(socket_path: &Path, command: AdminCommand) -> Result<AdminStream> {
    let mut stream = connect_admin_client_any(socket_path).await?;
    write_admin_request(&mut stream, command).await?;

    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    let read = reader.read_line(&mut line).await?;
    if read == 0 {
        return Err(NodeError::AdminProtocol(
            "admin server closed connection without a response".to_owned(),
        ));
    }
    let response: AdminResponse = serde_json::from_str(line.trim_end())?;
    if response.version != ADMIN_PROTOCOL_VERSION {
        return Err(NodeError::AdminProtocol(format!(
            "unsupported admin protocol version `{}`",
            response.version
        )));
    }
    if let Some(error) = response.error {
        return Err(NodeError::AdminProtocol(error));
    }
    Ok(reader.into_inner())
}

/// Spawn a detached child process that re-enters `node run --foreground` with
/// the given config. Used by the `Restart` admin command.
///
/// On Unix the child is moved into its own session via `setsid` so Ctrl-C in
/// the parent's terminal doesn't kill it. On Windows there is no direct
/// `setsid` equivalent; the child is just spawned with inherited stdio
/// disabled — operators that need true detachment should use the Windows
/// Service backend.
pub fn spawn_restart_child(config_path: &Path) -> Result<()> {
    let executable = std::env::current_exe()?;
    let mut command = std::process::Command::new(executable);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .arg("--config")
        .arg(config_path)
        .arg("node")
        .arg("run")
        .arg("--foreground")
        .arg("--daemon-child");

    // scrub env to a PATH/HOME/locale allow-list
    // before spawn. Inherited `LD_PRELOAD`, `LD_LIBRARY_PATH`
    // `RUST_LOG`, `VEIL_*` etc. would all survive on a raw `Command`
    // and could redirect the long-lived daemon's behaviour. See helper
    // doc for full allow-list / rationale.
    veil_util::scrub_command_env(&mut command);
    veil_util::setsid_on_spawn(&mut command);

    command.spawn()?;
    Ok(())
}

// ── Diagnostic helpers ──────────────────────────────────────────────

/// Resolve a target string to a `[u8; 32]` node_id.
///
/// `@name` → DHT name lookup for `name`.
/// Otherwise → hex node_id via `parse_node_id_hex`.
async fn resolve_node_target(
    _runtime: &std::sync::Arc<tokio::sync::Mutex<NodeRuntime>>,
    target: &str,
) -> std::result::Result<[u8; 32], String> {
    if target.starts_with('@') {
        return Err(
            "@name resolution from admin commands is not supported on sovereign-identity \
             nodes; pass the target node_id directly"
                .to_owned(),
        );
    }
    parse_node_id_hex(target).map_err(|e| e.to_string())
}

pub fn node_id_hex(id: &[u8; 32]) -> String {
    veil_util::hex_str(id)
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    veil_util::bytes_to_hex(bytes)
}

pub fn parse_hex_bytes(s: &str) -> std::result::Result<Vec<u8>, String> {
    let s = s.trim_start_matches("0x");
    if !s.len().is_multiple_of(2) {
        return Err(format!("hex string must have even length, got {}", s.len()));
    }
    s.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let pair = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
            u8::from_str_radix(pair, 16).map_err(|e| e.to_string())
        })
        .collect()
}

pub fn parse_node_id_hex(hex: &str) -> Result<[u8; 32]> {
    let bytes = parse_hex_bytes(hex)
        .map_err(|e| NodeError::Config(veil_cfg::ConfigError::ValidationFailed(e)))?;
    bytes.try_into().map_err(|_| {
        NodeError::Config(veil_cfg::ConfigError::ValidationFailed(format!(
            "node_id must be 32 bytes (64 hex chars), got {} chars",
            hex.len()
        )))
    })
}

pub fn now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

async fn run_debug_ping(
    access: crate::runtime::NodeServices,
    target_id: [u8; 32],
    count: u32,
    interval_ms: u64,
    timeout_ms: u64,
    tx: tokio::sync::mpsc::Sender<AdminResult>,
) {
    use veil_proto::codec::encode_header;
    use veil_proto::header::FrameHeader;
    use veil_proto::{DiagMsg, DiagPingPayload, FrameFamily, header::HEADER_SIZE};

    let mut sent = 0u32;
    let mut received = 0u32;
    let mut rtts: Vec<u64> = Vec::new();

    for seq in 0..count {
        let ts_us = now_us();
        let ping = DiagPingPayload {
            seq,
            sender: access.local_node_id(),
            ts_us,
            target: target_id,
            hop_limit: veil_proto::diag::DIAG_DEFAULT_HOP_LIMIT,
        };
        let body = ping.encode();
        let mut hdr = FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::Ping as u16);
        hdr.body_len = body.len() as u32;
        let mut frame = Vec::with_capacity(HEADER_SIZE + body.len());
        frame.extend_from_slice(&encode_header(&hdr));
        frame.extend_from_slice(&body);

        // Register a one-shot channel before sending.
        let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel::<veil_dispatcher::DiagEvent>(1);
        access.register_diag_seq(seq, ev_tx);

        // Send frame to target via session registry.
        access.send_diag_frame(&target_id, frame);

        sent += 1;
        // Wait for reply.
        let reply =
            tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), ev_rx.recv()).await;

        match reply {
            Ok(Some(veil_dispatcher::DiagEvent::Pong {
                echo_ts_us,
                responder,
                ..
            })) => {
                let rtt_us = now_us().saturating_sub(echo_ts_us);
                received += 1;
                rtts.push(rtt_us);
                let _ = tx
                    .send(AdminResult::PingReply {
                        seq,
                        rtt_us,
                        peer_id: node_id_hex(&responder),
                    })
                    .await;
            }
            _ => { /* timeout or channel error — counted as lost */ }
        }

        access.remove_diag_seq(seq);

        if seq + 1 < count {
            tokio::time::sleep(std::time::Duration::from_millis(interval_ms)).await;
        }
    }

    let lost = sent - received;
    let (rtt_min_us, rtt_avg_us, rtt_max_us) = if rtts.is_empty() {
        (0, 0, 0)
    } else {
        let min = *rtts
            .iter()
            .min()
            .expect("rtts non-empty — checked by is_empty() above");
        let max = *rtts
            .iter()
            .max()
            .expect("rtts non-empty — checked by is_empty() above");
        let avg = rtts.iter().sum::<u64>() / rtts.len() as u64;
        (min, avg, max)
    };
    let _ = tx
        .send(AdminResult::PingStats {
            sent,
            received,
            lost,
            rtt_min_us,
            rtt_avg_us,
            rtt_max_us,
        })
        .await;
}

async fn run_debug_trace(
    access: crate::runtime::NodeServices,
    target_id: [u8; 32],
    max_hops: u8,
    timeout_ms: u64,
    tx: tokio::sync::mpsc::Sender<AdminResult>,
) {
    use veil_proto::codec::encode_header;
    use veil_proto::header::FrameHeader;
    use veil_proto::{DiagMsg, DiagTraceProbePayload, FrameFamily, header::HEADER_SIZE};

    let mut hops_received = 0u8;
    for ttl in 1..=max_hops {
        let seq = ttl as u32;
        let ts_us = now_us();
        let probe = DiagTraceProbePayload {
            seq,
            sender: access.local_node_id(),
            ts_us,
            ttl,
            max_hops,
            orig_ttl: ttl,
            target: target_id,
        };
        let body = probe.encode();
        let mut hdr = FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::TraceProbe as u16);
        hdr.body_len = body.len() as u32;
        let mut frame = Vec::with_capacity(HEADER_SIZE + body.len());
        frame.extend_from_slice(&encode_header(&hdr));
        frame.extend_from_slice(&body);

        let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel::<veil_dispatcher::DiagEvent>(1);
        access.register_diag_seq(seq, ev_tx);
        access.send_diag_frame(&target_id, frame);

        let reply =
            tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), ev_rx.recv()).await;

        access.remove_diag_seq(seq);

        match reply {
            Ok(Some(veil_dispatcher::DiagEvent::TraceHop {
                hop_idx,
                node_id,
                echo_ts_us,
                ..
            })) => {
                let rtt_us = now_us().saturating_sub(echo_ts_us);
                hops_received += 1;
                let _ = tx
                    .send(AdminResult::TraceHop {
                        idx: hop_idx,
                        node_id: node_id_hex(&node_id),
                        rtt_us,
                    })
                    .await;
                // Stop as soon as we hear back from the target itself.
                if node_id == target_id {
                    break;
                }
            }
            _ => {
                // Timed out for this TTL — report as * and continue.
                let _ = tx
                    .send(AdminResult::TraceHop {
                        idx: ttl,
                        node_id: "*".to_owned(),
                        rtt_us: 0,
                    })
                    .await;
            }
        }
    }
    let _ = tx
        .send(AdminResult::TraceDone {
            hops: hops_received,
        })
        .await;
}

async fn run_debug_capture(
    mut rx: tokio::sync::broadcast::Receiver<veil_dispatcher::CaptureEvent>,
    filter: Option<[u8; 32]>,
    filter_family: Option<u8>,
    limit: Option<u32>,
    tx: tokio::sync::mpsc::Sender<AdminResult>,
) {
    let mut count = 0u32;
    loop {
        if limit.is_some_and(|lim| count >= lim) {
            break;
        }
        let ev = match rx.recv().await {
            Ok(ev) => ev,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        };
        if filter.is_some_and(|id| ev.peer_id != id) {
            continue;
        }
        if filter_family.is_some_and(|fam| ev.family != fam) {
            continue;
        }
        let (src_id, dst_id) = if ev.inbound {
            (node_id_hex(&ev.peer_id), node_id_hex(&ev.local_id))
        } else {
            (node_id_hex(&ev.local_id), node_id_hex(&ev.peer_id))
        };
        let body_hex = veil_util::hex_str(&ev.body);
        let result = AdminResult::CaptureFrame {
            ts_us: ev.ts_us,
            direction: if ev.inbound {
                "rx".to_owned()
            } else {
                "tx".to_owned()
            },
            src_id,
            dst_id,
            family: ev.family,
            msg_type: ev.msg_type,
            body_len: ev.body_len,
            body_hex,
            e2e_plaintext: ev.e2e_plaintext,
        };
        if tx.send(result).await.is_err() {
            break;
        }
        count += 1;
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    /// audit cycle-8: an admin client streaming bytes with no newline must NOT
    /// be able to grow the read accumulator past the cap; `read_bounded_admin_line`
    /// returns `None` (→ caller closes) instead of buffering it all.
    #[tokio::test]
    async fn admin_request_over_cap_without_newline_is_rejected() {
        let cap = 64 * 1024;
        // 70 KiB of non-newline bytes, never terminated.
        let payload = vec![b'a'; cap + 6 * 1024];
        let mut reader = tokio::io::BufReader::new(&payload[..]);
        let got = super::read_bounded_admin_line(&mut reader, cap)
            .await
            .unwrap();
        assert!(
            got.is_none(),
            "over-cap newline-less request must be rejected, not buffered"
        );
    }

    /// A normal newline-terminated request under the cap round-trips with the
    /// newline stripped.
    #[tokio::test]
    async fn admin_request_normal_line_under_cap_ok() {
        let cap = 64 * 1024;
        let payload = b"{\"version\":1,\"cmd\":\"status\"}\n".to_vec();
        let mut reader = tokio::io::BufReader::new(&payload[..]);
        let got = super::read_bounded_admin_line(&mut reader, cap)
            .await
            .unwrap();
        assert_eq!(got.as_deref(), Some("{\"version\":1,\"cmd\":\"status\"}"));
    }

    use tokio::time::{sleep, timeout};
    #[cfg(unix)]
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    #[cfg(unix)]
    use crate::local_identity::HandshakeIdentity;
    use veil_cfg::{
        self, Config, GlobalConfig, IdentityConfig, ListenConfig, ListenId, LogsConfig, NodeId,
        PeerConfig, PeerId,
    };
    #[cfg(unix)]
    use veil_session::handshake::perform_ovl1_handshake;

    use super::*;

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn admin_socket_request_response() {
        let path = save_admin_config("node-admin-request", config_with_admin_socket()).unwrap();
        let socket =
            admin_socket_path(&veil_cfg::load_config(&path).unwrap(), path.parent()).unwrap();
        let server_path = path.clone();
        let server = tokio::spawn(async move { run_foreground(server_path, true).await });

        wait_for_socket(&socket).await;
        let response = send_request(&socket, AdminCommand::Show).await.unwrap();
        assert!(response.error.is_none());
        assert!(matches!(response.result, Some(AdminResult::Show(_))));

        let _ = send_request(&socket, AdminCommand::Stop).await.unwrap();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(path);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn node_show_returns_summary() {
        let path = save_admin_config("node-admin-show", config_with_admin_socket()).unwrap();
        let socket =
            admin_socket_path(&veil_cfg::load_config(&path).unwrap(), path.parent()).unwrap();
        let server_path = path.clone();
        let server = tokio::spawn(async move { run_foreground(server_path, true).await });

        wait_for_socket(&socket).await;
        let response = send_request(&socket, AdminCommand::Show).await.unwrap();
        let Some(AdminResult::Show(summary)) = response.result else {
            panic!("unexpected show response");
        };
        assert_eq!(summary.peers_configured, 1);
        assert_eq!(summary.listens_active, 1);
        assert_eq!(summary.node_id.len(), 64);

        let _ = send_request(&socket, AdminCommand::Stop).await.unwrap();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(path);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn node_listens_returns_runtime_entries() {
        let path = save_admin_config("node-admin-listens", config_with_admin_socket()).unwrap();
        let socket =
            admin_socket_path(&veil_cfg::load_config(&path).unwrap(), path.parent()).unwrap();
        let server_path = path.clone();
        let server = tokio::spawn(async move { run_foreground(server_path, true).await });

        wait_for_socket(&socket).await;
        let response = send_request(&socket, AdminCommand::Listens).await.unwrap();
        let Some(AdminResult::Listens { listens }) = response.result else {
            panic!("unexpected listens response");
        };
        assert_eq!(listens.len(), 1);
        assert_eq!(listens[0].listen_id, "0x00000001");
        assert!(listens[0].listener_handle.is_some());
        assert!(listens[0].local_addr.is_some());
        assert!(listens[0].active);

        let _ = send_request(&socket, AdminCommand::Stop).await.unwrap();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(path);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn reload_updates_runtime_config() {
        let path = save_admin_config("node-admin-reload", config_with_admin_socket()).unwrap();
        let socket =
            admin_socket_path(&veil_cfg::load_config(&path).unwrap(), path.parent()).unwrap();
        let server_path = path.clone();
        let server = tokio::spawn(async move { run_foreground(server_path, true).await });

        wait_for_socket(&socket).await;
        let response = send_request(&socket, AdminCommand::Listens).await.unwrap();
        let Some(AdminResult::Listens { listens }) = response.result else {
            panic!("unexpected listens response");
        };
        let first_listener_handle = listens[0]
            .listener_handle
            .clone()
            .expect("listener handle assigned");

        let mut updated = veil_cfg::load_config(&path).unwrap();
        updated.listen.push(ListenConfig {
            id: ListenId::new(2),
            transport: "tcp://127.0.0.1:0".to_owned(),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            advertise: None,
            relay: None,
            ..Default::default()
        });
        veil_cfg::save_config(&path, &updated).unwrap();

        let response = send_request(&socket, AdminCommand::Reload).await.unwrap();
        assert_eq!(
            response.result,
            Some(AdminResult::Ack {
                message: "node reloaded".to_owned()
            })
        );

        let response = send_request(&socket, AdminCommand::Listens).await.unwrap();
        let Some(AdminResult::Listens { listens }) = response.result else {
            panic!("unexpected listens response");
        };
        assert_eq!(listens.len(), 2);
        assert_ne!(
            listens[0].listener_handle.as_deref(),
            Some(first_listener_handle.as_str())
        );

        let _ = send_request(&socket, AdminCommand::Stop).await.unwrap();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(path);
    }

    /// **ApplyConfig (Phase 1)**: push a new config to the running daemon
    /// via IPC bytes (no filesystem intermediary).  Verify:
    ///  1. Successful apply returns AdminResult::Ack.
    ///  2. The new listen-entry is reflected in the subsequent Listens query.
    ///  3. With `persist: false` (default), the on-disk file is unchanged.
    ///
    /// Phase Q.5: marked `#[ignore]` for the default suite — same
    /// pattern as the other admin-IPC tests at the bottom of this
    /// module.  Under `cargo test --workspace -- --test-threads=2`
    /// (CI), the current_thread runtime's foreground task occasionally
    /// doesn't reach `bind_admin_endpoint` before `wait_for_socket`
    /// times out, or the ApplyConfig roundtrip races concurrent
    /// build-and-link load.  5/5 isolation runs pass (1.7–30 s; wide
    /// run-time spread itself signals timing-flake).  CI can opt back
    /// in with `--include-ignored` or by running this test specifically
    /// when admin-IPC validation is needed.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    #[ignore]
    async fn apply_config_inmemory_updates_runtime_without_disk_write() {
        let path = save_admin_config("node-admin-apply-cfg", config_with_admin_socket()).unwrap();
        let socket =
            admin_socket_path(&veil_cfg::load_config(&path).unwrap(), path.parent()).unwrap();
        let server_path = path.clone();
        let server = tokio::spawn(async move { run_foreground(server_path, true).await });

        wait_for_socket(&socket).await;

        // Capture the on-disk bytes BEFORE the apply — persist=false
        // must leave them untouched.
        let before_disk = std::fs::read_to_string(&path).unwrap();

        // Build a new config from the loaded one + an extra listen entry.
        let mut updated = veil_cfg::load_config(&path).unwrap();
        updated.listen.push(ListenConfig {
            id: ListenId::new(7),
            transport: "tcp://127.0.0.1:0".to_owned(),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            advertise: None,
            relay: None,
            ..Default::default()
        });
        // Round-trip through veil_cfg::save → read so we get a TOML-shaped string.
        // Use a throwaway temp path so the original `path` stays untouched
        // (we are testing the in-memory apply, not file persistence).
        let scratch = path.with_extension("scratch.toml");
        veil_cfg::save_config(&scratch, &updated).unwrap();
        let toml_content = std::fs::read_to_string(&scratch).unwrap();
        let _ = std::fs::remove_file(&scratch);

        let response = send_request(
            &socket,
            AdminCommand::ApplyConfig {
                toml_content,
                persist: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            response.result,
            Some(AdminResult::Ack {
                message: "config applied (in-memory only)".to_owned(),
            }),
            "apply must succeed and return the in-memory ack variant"
        );

        // The new listen-entry must now be reflected in the daemon's
        // runtime state.
        let response = send_request(&socket, AdminCommand::Listens).await.unwrap();
        let Some(AdminResult::Listens { listens }) = response.result else {
            panic!("unexpected listens response after apply");
        };
        assert_eq!(
            listens.len(),
            2,
            "second listen must appear in the runtime view"
        );

        // On-disk config must be unchanged — `persist: false` invariant.
        let after_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            before_disk, after_disk,
            "persist=false MUST NOT touch the on-disk config",
        );

        let _ = send_request(&socket, AdminCommand::Stop).await.unwrap();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(path);
    }

    /// **ApplyConfig (Phase 1)**: invalid TOML must be rejected
    /// without disrupting the running daemon.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn apply_config_rejects_invalid_toml() {
        let path = save_admin_config("node-admin-apply-bad", config_with_admin_socket()).unwrap();
        let socket =
            admin_socket_path(&veil_cfg::load_config(&path).unwrap(), path.parent()).unwrap();
        let server_path = path.clone();
        let server = tokio::spawn(async move { run_foreground(server_path, true).await });

        wait_for_socket(&socket).await;

        // Garbage that's neither valid TOML nor a valid Config.
        let response = send_request(
            &socket,
            AdminCommand::ApplyConfig {
                toml_content: "\n[broken\nthis is = not = valid".to_owned(),
                persist: false,
            },
        )
        .await
        .unwrap();
        assert!(
            response.error.is_some(),
            "invalid TOML must return error, got {response:?}",
        );

        // Daemon must still respond after the failed apply (no state
        // corruption).
        let response = send_request(&socket, AdminCommand::Show).await.unwrap();
        assert!(matches!(response.result, Some(AdminResult::Show(_))));

        let _ = send_request(&socket, AdminCommand::Stop).await.unwrap();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(path);
    }

    /// **--defer-init (Phase 2)**: stub-config builder produces a valid
    /// Config with an ephemeral identity that passes its own validation.
    /// Without this property, deferred-init startup would refuse to boot.
    ///
    /// Cheap unit test (no daemon spin-up) — just verifies the builder
    /// invariants.  Daemon-level smoke test would require a full
    /// `NodeRuntime::start` call which is heavy for CI and duplicates
    /// coverage from the existing tests below.
    #[test]
    fn defer_init_stub_config_is_valid() {
        let cfg = veil_cfg::build_stub_config_with_ephemeral_identity(false)
            .expect("stub-config builder must succeed under normal pow difficulty");

        // Identity present.
        let id = cfg
            .identity
            .as_ref()
            .expect("stub config must have identity");
        assert!(matches!(id.algo, veil_cfg::SignatureAlgorithm::Ed25519));
        assert!(!id.public_key.is_empty());
        assert!(!id.private_key.is_empty());

        // Stub posture: no peers, no listens, no bootstrap_peers —
        // daemon comes up but doesn't try to touch the network until
        // a real ApplyConfig arrives.
        assert!(cfg.peers.is_empty(), "stub must not configure peers");
        assert!(cfg.listen.is_empty(), "stub must not configure listens");
        assert!(
            cfg.bootstrap_peers.is_empty(),
            "stub must not configure bootstrap peers"
        );

        // Non-anonymous stub: LOCATION anonymity (onion) stays OFF, but
        // `receive_anonymous` (plain rendezvous RECEIVE = reachability) is ALWAYS
        // on so a NAT'd non-anon node can be reached by node_id. It also mints
        // the x25519 key via the boot gate (`relay_capable || receive_anonymous
        // || onion_service`).
        assert!(!cfg.anonymity.onion_service);
        assert!(
            cfg.anonymity.receive_anonymous,
            "stub always enables receive_anonymous (reachability)"
        );

        // Ephemeral node: ALL on-disk persistence is off (no snapshot writes —
        // deniability + no spurious flush errors on the deferred path).
        assert!(
            !cfg.persist_enabled,
            "deferred stub must not persist to disk"
        );

        // Validation passes — that's the whole point of the PoW search
        // in the builder.
        let validation = veil_cfg::validate(&cfg);
        assert!(
            validation.is_valid(),
            "stub config must pass validation: {}",
            validation.format_issues()
        );
    }

    /// `anonymous = true` arms `[anonymity]` in the stub so the deferred node
    /// creates its x25519 key + onion-publish task at boot (the descriptor then
    /// publishes under the real identity applied post-boot). Without this the
    /// boot-time gate leaves the key None and onion is disabled forever.
    #[test]
    fn defer_init_stub_config_anonymous_arms_anonymity() {
        let cfg = veil_cfg::build_stub_config_with_ephemeral_identity(true)
            .expect("anonymous stub-config builder must succeed");
        assert!(
            cfg.anonymity.onion_service,
            "anonymous stub must enable onion_service"
        );
        assert!(
            cfg.anonymity.receive_anonymous,
            "anonymous stub must enable receive_anonymous"
        );
        // Being location-anonymous must NOT silently turn the node into a relay
        // for others' circuits.
        assert!(
            !cfg.anonymity.relay_capable,
            "anonymous stub must not become relay_capable"
        );
        // Ephemeral even when anonymous — persistence stays off.
        assert!(!cfg.persist_enabled);
        // Still a valid, bootable stub.
        let validation = veil_cfg::validate(&cfg);
        assert!(
            validation.is_valid(),
            "anonymous stub config must pass validation: {}",
            validation.format_issues()
        );
    }

    /// **ApplyConfig (Phase 1)** with `persist: true` writes the new
    /// config to `self.config_path` (atomic-write) and a subsequent
    /// `reload` reads the same bytes back.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn apply_config_with_persist_writes_to_disk() {
        let path =
            save_admin_config("node-admin-apply-persist", config_with_admin_socket()).unwrap();
        let socket =
            admin_socket_path(&veil_cfg::load_config(&path).unwrap(), path.parent()).unwrap();
        let server_path = path.clone();
        let server = tokio::spawn(async move { run_foreground(server_path, true).await });

        wait_for_socket(&socket).await;

        let mut updated = veil_cfg::load_config(&path).unwrap();
        updated.listen.push(ListenConfig {
            id: ListenId::new(8),
            transport: "tcp://127.0.0.1:0".to_owned(),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            advertise: None,
            relay: None,
            ..Default::default()
        });
        let scratch = path.with_extension("scratch.toml");
        veil_cfg::save_config(&scratch, &updated).unwrap();
        let toml_content = std::fs::read_to_string(&scratch).unwrap();
        let _ = std::fs::remove_file(&scratch);

        let response = send_request(
            &socket,
            AdminCommand::ApplyConfig {
                toml_content,
                persist: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            response.result,
            Some(AdminResult::Ack {
                message: "config applied + persisted".to_owned(),
            }),
        );

        // Disk reflects the change — reload picks the same 2 listens up.
        let reread = veil_cfg::load_config(&path).unwrap();
        assert_eq!(
            reread.listen.len(),
            2,
            "persist=true must write the new listen entry to disk",
        );

        let _ = send_request(&socket, AdminCommand::Stop).await.unwrap();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(path);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn node_sessions_returns_runtime_entries() {
        let path = save_admin_config("node-admin-sessions", config_with_admin_socket()).unwrap();
        let socket =
            admin_socket_path(&veil_cfg::load_config(&path).unwrap(), path.parent()).unwrap();
        let server_path = path.clone();
        let server = tokio::spawn(async move { run_foreground(server_path, true).await });

        wait_for_socket(&socket).await;

        let listens = send_request(&socket, AdminCommand::Listens).await.unwrap();
        let Some(AdminResult::Listens { listens }) = listens.result else {
            panic!("unexpected listens response");
        };
        let addr = listens[0].local_addr.clone().unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();
        complete_test_handshake(&mut stream).await;
        stream.write_all(b"hello").await.unwrap();

        timeout(Duration::from_secs(2), async {
            loop {
                let response = send_request(&socket, AdminCommand::Sessions).await.unwrap();
                let Some(AdminResult::Sessions { sessions }) = response.result else {
                    panic!("unexpected sessions response");
                };
                if let Some(session) = sessions.first() {
                    assert_eq!(session.source, "inbound(0x00000001)");
                    assert_eq!(session.state, "active");
                    let expected_node_id = test_handshake_identity().node_id.to_string();
                    assert_eq!(session.node_id.as_deref(), Some(expected_node_id.as_str()));
                    return;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let _ = stream.shutdown().await;
        let _ = send_request(&socket, AdminCommand::Stop).await.unwrap();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(path);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "flaky due to race between configured outbound connector and DebugPeerConnect"]
    async fn debug_peer_connect_stream_uses_outbound_peer_source() {
        let peer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_listener.local_addr().unwrap();
        let peer_task = tokio::spawn(async move {
            let (first_stream, _) = peer_listener.accept().await.unwrap();
            let first_task = tokio::spawn(async move {
                let mut stream = first_stream;
                let _runtime_node_id = complete_test_handshake(&mut stream).await;
                let mut buf = [0_u8; 4];
                match stream.read_exact(&mut buf).await {
                    Ok(_) if &buf == b"ping" => {
                        stream.write_all(b"pong").await.unwrap();
                        true
                    }
                    Ok(_) | Err(_) => false,
                }
            });

            let (second_stream, _) = peer_listener.accept().await.unwrap();
            let second_task = tokio::spawn(async move {
                let mut stream = second_stream;
                let _runtime_node_id = complete_test_handshake(&mut stream).await;
                let mut buf = [0_u8; 4];
                match stream.read_exact(&mut buf).await {
                    Ok(_) if &buf == b"ping" => {
                        stream.write_all(b"pong").await.unwrap();
                        true
                    }
                    Ok(_) | Err(_) => false,
                }
            });

            let first_result = first_task.await.unwrap();
            let second_result = second_task.await.unwrap();
            assert!(
                first_result || second_result,
                "expected ping on one peer stream"
            );
        });

        let mut config = config_with_admin_socket();
        config.peers[0].transport = format!("tcp://{peer_addr}");
        let path = save_admin_config("node-admin-debug-peer", config).unwrap();
        let socket =
            admin_socket_path(&veil_cfg::load_config(&path).unwrap(), path.parent()).unwrap();
        let server_path = path.clone();
        let server = tokio::spawn(async move { run_foreground(server_path, true).await });

        wait_for_socket(&socket).await;

        let mut debug_stream = open_peer_debug_stream(&socket, PeerId::new(1))
            .await
            .expect("debug peer stream");
        debug_stream.write_all(b"ping").await.unwrap();

        timeout(Duration::from_secs(2), async {
            loop {
                let response = send_request(&socket, AdminCommand::Sessions).await.unwrap();
                let Some(AdminResult::Sessions { sessions }) = response.result else {
                    panic!("unexpected sessions response");
                };
                if let Some(session) = sessions.iter().find(|session| {
                    session.source == "outbound(0x00000001)" && session.state == "debug_attached"
                }) {
                    assert_eq!(session.source, "outbound(0x00000001)");
                    assert_eq!(session.state, "debug_attached");
                    let expected_node_id = test_handshake_identity().node_id.to_string();
                    assert_eq!(session.node_id.as_deref(), Some(expected_node_id.as_str()));
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let mut buf = [0_u8; 4];
        debug_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        let _ = debug_stream.shutdown().await;
        let _ = send_request(&socket, AdminCommand::Stop).await.unwrap();
        peer_task.await.unwrap();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(path);
    }

    // Audit batch 2026-05-24: probabilistically flaky after Phase E20
    // directional dedup (see comment in
    // runtime/tests.rs::runtime_creates_outbound_session_for_configured_peer).
    // Random sovereign identity vs cached test-peer identity → ~50%
    // policy reject on the test's outbound session.
    #[ignore = "Phase E20 directional dedup makes this probabilistic"]
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn sessions_list_shows_outbound_peer_session() {
        let peer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer_listener.local_addr().unwrap();

        let mut config = config_with_admin_socket();
        config.peers[0].transport = format!("tcp://{peer_addr}");
        let path = save_admin_config("node-admin-outbound-sessions", config).unwrap();
        let socket =
            admin_socket_path(&veil_cfg::load_config(&path).unwrap(), path.parent()).unwrap();
        let server_path = path.clone();
        let server = tokio::spawn(async move { run_foreground(server_path, true).await });

        wait_for_socket(&socket).await;
        let (mut peer_stream, _) = peer_listener.accept().await.unwrap();
        let _runtime_node_id = complete_test_handshake(&mut peer_stream).await;

        timeout(Duration::from_secs(2), async {
            loop {
                let response = send_request(&socket, AdminCommand::Sessions).await.unwrap();
                let Some(AdminResult::Sessions { sessions }) = response.result else {
                    panic!("unexpected sessions response");
                };
                if let Some(session) = sessions
                    .iter()
                    .find(|session| session.source == "outbound(0x00000001)")
                {
                    assert_eq!(session.state, "active");
                    let expected_node_id = test_handshake_identity().node_id.to_string();
                    assert_eq!(session.node_id.as_deref(), Some(expected_node_id.as_str()));
                    return;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let _ = send_request(&socket, AdminCommand::Stop).await.unwrap();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(path);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn debug_node_accept_routes_by_listen_id() {
        let path = save_admin_config("node-admin-debug-listen", config_with_two_listens()).unwrap();
        let socket =
            admin_socket_path(&veil_cfg::load_config(&path).unwrap(), path.parent()).unwrap();
        let server_path = path.clone();
        let server = tokio::spawn(async move { run_foreground(server_path, true).await });

        wait_for_socket(&socket).await;
        let response = send_request(&socket, AdminCommand::Listens).await.unwrap();
        let Some(AdminResult::Listens { listens }) = response.result else {
            panic!("unexpected listens response");
        };
        let listen_one = listens
            .iter()
            .find(|entry| entry.listen_id == "0x00000001")
            .unwrap();
        let listen_two = listens
            .iter()
            .find(|entry| entry.listen_id == "0x00000002")
            .unwrap();

        let socket_clone = socket.clone();
        let mut accept_task =
            tokio::spawn(
                async move { open_listen_debug_stream(&socket_clone, ListenId::new(1)).await },
            );
        sleep(Duration::from_millis(50)).await;

        let mut wrong_stream = TcpStream::connect(listen_two.local_addr.as_ref().unwrap())
            .await
            .unwrap();
        wrong_stream.write_all(b"wrong").await.unwrap();
        assert!(
            timeout(Duration::from_millis(200), &mut accept_task)
                .await
                .is_err()
        );

        sleep(Duration::from_millis(50)).await;
        let mut inbound = TcpStream::connect(listen_one.local_addr.as_ref().unwrap())
            .await
            .unwrap();
        complete_test_handshake(&mut inbound).await;
        inbound.write_all(b"hello").await.unwrap();

        let mut debug_stream = timeout(Duration::from_secs(2), &mut accept_task)
            .await
            .expect("listen debug attach completes")
            .unwrap()
            .unwrap();

        let response = send_request(&socket, AdminCommand::Sessions).await.unwrap();
        let Some(AdminResult::Sessions { sessions }) = response.result else {
            panic!("unexpected sessions response");
        };
        let session = sessions
            .iter()
            .find(|entry| entry.source == "inbound(0x00000001)")
            .expect("listen 1 debug session");
        assert_eq!(session.state, "debug_attached");
        let expected_node_id = test_handshake_identity().node_id.to_string();
        assert_eq!(session.node_id.as_deref(), Some(expected_node_id.as_str()));

        let _ = debug_stream.shutdown().await;
        let _ = inbound.shutdown().await;
        let _ = wrong_stream.shutdown().await;
        let _ = send_request(&socket, AdminCommand::Stop).await.unwrap();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(path);
    }

    /// concurrent admin requests must not deadlock.
    ///
    /// Fires Sessions + Health + Show simultaneously against a running node
    /// and asserts all three complete without stalling.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_admin_requests_do_not_deadlock() {
        let path = save_admin_config("node-admin-concurrent", config_with_admin_socket()).unwrap();
        let socket =
            admin_socket_path(&veil_cfg::load_config(&path).unwrap(), path.parent()).unwrap();
        let server_path = path.clone();
        let server = tokio::spawn(async move { run_foreground(server_path, true).await });
        wait_for_socket(&socket).await;

        // Fire three read-only admin commands concurrently.
        let (r1, r2, r3) = tokio::join!(
            send_request(&socket, AdminCommand::Sessions),
            send_request(&socket, AdminCommand::Show),
            send_request(&socket, AdminCommand::Health),
        );
        assert!(r1.is_ok(), "Sessions: {r1:?}");
        assert!(r2.is_ok(), "Show: {r2:?}");
        assert!(r3.is_ok(), "Health: {r3:?}");

        let _ = send_request(&socket, AdminCommand::Stop).await;
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(path);
    }

    #[cfg(unix)]
    async fn wait_for_socket(socket: &Path) {
        timeout(Duration::from_secs(5), async {
            loop {
                if socket.exists() {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("socket appears");
    }

    #[cfg(unix)]
    fn config_with_admin_socket() -> Config {
        let identity = test_support::valid_identity();
        let node_id = NodeId::from_public_key(identity.algo, &identity.public_key).unwrap();
        let unique = unique_suffix();
        let socket = std::env::temp_dir().join(format!("veil-admin-{unique}.sock"));

        Config {
            global: GlobalConfig {
                admin_socket: Some(format!("unix://{}", socket.display())),
                logs: LogsConfig::Stderr,
                ..GlobalConfig::default()
            },
            identity: Some(IdentityConfig {
                node_id: Some(node_id),
                ..identity
            }),
            peers: vec![PeerConfig {
                peer_id: PeerId::new(1),
                public_key: test_support::valid_identity().public_key,
                nonce: test_support::valid_identity().nonce,
                transport: "tcp://127.0.0.1:9000".to_owned(),
                algo: Default::default(),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                alt_uri: None,
            }],
            listen: vec![ListenConfig {
                id: ListenId::new(1),
                transport: "tcp://127.0.0.1:0".to_owned(),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                advertise: None,
                relay: None,
                ..Default::default()
            }],
            ..Config::default()
        }
    }

    #[cfg(unix)]
    fn config_with_two_listens() -> Config {
        let mut config = config_with_admin_socket();
        config.listen.push(ListenConfig {
            id: ListenId::new(2),
            transport: "tcp://127.0.0.1:0".to_owned(),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            advertise: None,
            relay: None,
            ..Default::default()
        });
        config
    }

    fn save_admin_config(prefix: &str, config: Config) -> veil_cfg::Result<PathBuf> {
        let unique = unique_suffix();
        let path = std::env::temp_dir().join(format!("{prefix}-{unique}.toml"));
        veil_cfg::save_config(&path, &config)?;
        Ok(path)
    }

    fn unique_suffix() -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{nanos}-{counter}")
    }

    #[cfg(unix)]
    fn test_handshake_identity() -> HandshakeIdentity {
        let identity = test_support::valid_identity();
        HandshakeIdentity {
            algo: identity.algo,
            public_key: identity.public_key.clone(),
            private_key: identity.private_key.clone(),
            nonce: identity.nonce.clone(),
            node_id: NodeId::from_public_key(identity.algo, &identity.public_key).unwrap(),
        }
    }

    #[cfg(unix)]
    async fn complete_test_handshake<S>(stream: &mut S) -> NodeId
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        use veil_cfg::NodeRole;
        // client-side fixture; outbound (writes HELLO first).
        perform_ovl1_handshake(
            stream,
            &test_handshake_identity(),
            NodeRole::Core,
            veil_cfg::DiscoveryMode::Public,
            None,
            None,
            None,
            Some([0u8; 32]),
            None,
            None,
            None,
            &[],
            false,
            None,
            None, // P-Net: no network gate in admin test fixture
            None, // S3: no peer_observed_addr in admin test fixture
        )
        .await
        .expect("OVL1 handshake succeeds")
        .node_id
    }

    // ── Admin socket ACL tests ─────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn peer_uid_matches_self() {
        // Bind a temporary admin listener, connect to it, and verify the
        // uid check passes (client is the same process/user as the server).
        let path = std::env::temp_dir().join(format!("veil_uid_test_{}.sock", std::process::id()));
        let listener = crate::admin_transport::bind_unix(&path).unwrap();
        let (accept_result, _) = tokio::join!(
            listener.accept(),
            crate::admin_transport::connect_unix(&path),
        );
        let (_stream, peer_info) = accept_result.unwrap();
        let _ = tokio::fs::remove_file(&path).await;
        assert!(
            peer_info.uid_matches_local,
            "same-uid peer must be accepted"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn admin_socket_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("veil_acl_test_{}.sock", std::process::id()));

        // Bind a socket and set permissions.
        let _listener = tokio::net::UnixListener::bind(&path).unwrap();
        super::set_socket_permissions(&path).await;

        let meta = tokio::fs::metadata(&path).await.unwrap();
        let mode = meta.permissions().mode() & 0o777;
        let _ = tokio::fs::remove_file(&path).await;
        assert_eq!(mode, 0o600, "socket should be mode 0600");
    }

    // ── TCP backend integration tests ───────────────────────────
    //
    // These use a `tcp://127.0.0.1:0` admin endpoint, so they run on any
    // platform — including the Windows host validation path (451.15). They
    // prove the full server ↔ client round-trip through the TCP + token
    // backend, independent of whether Unix domain sockets are available.

    fn config_with_tcp_admin() -> (Config, PathBuf /* runtime_dir */) {
        let identity = test_support::valid_identity();
        let node_id = NodeId::from_public_key(identity.algo, &identity.public_key).unwrap();
        let unique = unique_suffix();
        let runtime_dir = std::env::temp_dir().join(format!("veil-tcp-{unique}"));

        let cfg = Config {
            global: GlobalConfig {
                admin_socket: Some(format!(
                    "tcp://127.0.0.1:0?runtime_dir={}",
                    runtime_dir.display(),
                )),
                logs: LogsConfig::Stderr,
                ..GlobalConfig::default()
            },
            identity: Some(IdentityConfig {
                node_id: Some(node_id),
                ..identity
            }),
            peers: vec![PeerConfig {
                peer_id: PeerId::new(1),
                public_key: test_support::valid_identity().public_key,
                nonce: test_support::valid_identity().nonce,
                transport: "tcp://127.0.0.1:9000".to_owned(),
                algo: Default::default(),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                alt_uri: None,
            }],
            listen: vec![ListenConfig {
                id: ListenId::new(1),
                transport: "tcp://127.0.0.1:0".to_owned(),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                advertise: None,
                relay: None,
                ..Default::default()
            }],
            ..Config::default()
        };
        (cfg, runtime_dir)
    }

    async fn wait_for_tcp_sidecars(runtime_dir: &Path) {
        let port_path = runtime_dir.join(ADMIN_PORT_FILENAME);
        let tok_path = runtime_dir.join(ADMIN_TOKEN_FILENAME);
        timeout(Duration::from_secs(30), async {
            loop {
                if port_path.exists() && tok_path.exists() {
                    break;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("tcp admin sidecars appear");
    }

    // These TCP integration tests pass in isolation (`cargo test -- --ignored
    // admin_tcp`) and under `--test-threads=4` but flake under the default
    // high-parallelism cargo test run: per-test `current_thread` tokio
    // runtimes starve each other for CPU, and the spawned `run_foreground`
    // task occasionally doesn't reach `bind_admin_endpoint` within the 30 s
    // timeout. Marked `#[ignore]` so the default suite stays green; CI runs
    // them explicitly (and Windows-host validation 451.15 runs them as the
    // primary correctness signal).
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "TCP admin integration — run with `--ignored` or on Windows 451.15"]
    async fn admin_tcp_request_response() {
        let (cfg, runtime_dir) = config_with_tcp_admin();
        let path = save_admin_config("node-admin-tcp-request", cfg).unwrap();
        let anchor =
            admin_socket_path(&veil_cfg::load_config(&path).unwrap(), path.parent()).unwrap();
        let server_path = path.clone();
        let server = tokio::spawn(async move { run_foreground(server_path, true).await });

        wait_for_tcp_sidecars(&runtime_dir).await;
        let response = send_request(&anchor, AdminCommand::Show).await.unwrap();
        assert!(response.error.is_none());
        assert!(matches!(response.result, Some(AdminResult::Show(_))));

        let _ = send_request(&anchor, AdminCommand::Stop).await.unwrap();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(path);
        let _ = std::fs::remove_dir_all(&runtime_dir);
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "TCP admin integration — run with `--ignored` or on Windows 451.15"]
    async fn admin_tcp_cleanup_removes_sidecars() {
        let (cfg, runtime_dir) = config_with_tcp_admin();
        let path = save_admin_config("node-admin-tcp-cleanup", cfg).unwrap();
        let anchor =
            admin_socket_path(&veil_cfg::load_config(&path).unwrap(), path.parent()).unwrap();
        let server_path = path.clone();
        let server = tokio::spawn(async move { run_foreground(server_path, true).await });

        wait_for_tcp_sidecars(&runtime_dir).await;
        assert!(runtime_dir.join(ADMIN_PORT_FILENAME).exists());
        assert!(runtime_dir.join(ADMIN_TOKEN_FILENAME).exists());

        let _ = send_request(&anchor, AdminCommand::Stop).await.unwrap();
        server.await.unwrap().unwrap();

        // Sidecars must be removed after shutdown so the next run starts
        // fresh and doesn't confuse probes for a live server.
        assert!(
            !runtime_dir.join(ADMIN_PORT_FILENAME).exists(),
            "admin.port must be cleaned up on shutdown"
        );
        assert!(
            !runtime_dir.join(ADMIN_TOKEN_FILENAME).exists(),
            "admin.token must be cleaned up on shutdown"
        );
        let _ = fs::remove_file(path);
        let _ = std::fs::remove_dir_all(&runtime_dir);
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "TCP admin integration — run with `--ignored` or on Windows 451.15"]
    async fn admin_tcp_rejects_wrong_token() {
        use crate::admin_transport::{self, ADMIN_TOKEN_BYTES, AdminToken};

        let (cfg, runtime_dir) = config_with_tcp_admin();
        let path = save_admin_config("node-admin-tcp-wrongtok", cfg).unwrap();
        let server_path = path.clone();
        let server = tokio::spawn(async move { run_foreground(server_path, true).await });

        wait_for_tcp_sidecars(&runtime_dir).await;
        let port = admin_transport::read_port_file(&runtime_dir.join(ADMIN_PORT_FILENAME))
            .await
            .unwrap();
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

        // Connect with a deliberately wrong token — server must close the
        // connection without serving the admin protocol.
        let wrong = AdminToken::from_bytes([0xAAu8; ADMIN_TOKEN_BYTES]);
        let mut stream = admin_transport::connect_tcp(addr, &wrong).await.unwrap();
        // After the token handshake the server rejects; reading should yield
        // either EOF (0 bytes) or an error. Either way no JSON response.
        let mut buf = [0u8; 8];
        let n = match tokio::time::timeout(
            Duration::from_secs(2),
            tokio::io::AsyncReadExt::read(&mut stream, &mut buf),
        )
        .await
        {
            Ok(Ok(n)) => n,
            Ok(Err(_)) => 0,
            Err(_) => 0,
        };
        assert_eq!(n, 0, "server must close connection on wrong token");

        // Valid admin commands still work via the proper client path.
        let anchor =
            admin_socket_path(&veil_cfg::load_config(&path).unwrap(), path.parent()).unwrap();
        let _ = send_request(&anchor, AdminCommand::Stop).await.unwrap();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(path);
        let _ = std::fs::remove_dir_all(&runtime_dir);
    }

    #[test]
    fn resolve_admin_endpoint_tcp_with_runtime_dir_query() {
        let cfg = Config {
            global: GlobalConfig {
                admin_socket: Some("tcp://127.0.0.1:0?runtime_dir=/tmp/veil-test-rd".to_owned()),
                ..GlobalConfig::default()
            },
            ..Config::default()
        };
        let ep = resolve_admin_endpoint(&cfg, None).unwrap();
        match ep {
            AdminEndpoint::Tcp {
                bind_addr,
                runtime_dir,
            } => {
                assert_eq!(bind_addr.to_string(), "127.0.0.1:0");
                assert_eq!(runtime_dir, PathBuf::from("/tmp/veil-test-rd"));
            }
            other => panic!("expected Tcp endpoint, got {other:?}"),
        }
    }

    #[test]
    fn resolve_admin_endpoint_ipv6_loopback_normalized() {
        // audit cycle-3: `tcp://[::1]:port` must resolve (the old
        // `format!("{host}:{port}")` built `::1:port` which failed to parse).
        let cfg = Config {
            global: GlobalConfig {
                admin_socket: Some("tcp://[::1]:0".to_owned()),
                ..GlobalConfig::default()
            },
            ..Config::default()
        };
        match resolve_admin_endpoint(&cfg, None).unwrap() {
            AdminEndpoint::Tcp { bind_addr, .. } => {
                assert!(bind_addr.ip().is_loopback());
                assert!(bind_addr.is_ipv6(), "[::1] must resolve to an IPv6 addr");
            }
            other => panic!("expected Tcp endpoint, got {other:?}"),
        }
    }

    #[test]
    fn resolve_admin_endpoint_rejects_unknown_query() {
        // A typo like `runtime_dri=` must fail loudly, not silently fall back.
        let cfg = Config {
            global: GlobalConfig {
                admin_socket: Some("tcp://127.0.0.1:0?runtime_dri=/tmp/x".to_owned()),
                ..GlobalConfig::default()
            },
            ..Config::default()
        };
        assert!(resolve_admin_endpoint(&cfg, None).is_err());
    }

    #[test]
    fn resolve_admin_endpoint_unix_roundtrip() {
        let cfg = Config {
            global: GlobalConfig {
                admin_socket: Some("unix:///tmp/veil-test.sock".to_owned()),
                ..GlobalConfig::default()
            },
            ..Config::default()
        };
        let ep = resolve_admin_endpoint(&cfg, None).unwrap();
        assert!(matches!(ep, AdminEndpoint::Unix(_)));
    }

    /// when `global.admin_socket` is unset and a `config_dir` is
    /// known, the resolver derives a default (`<dir>/admin.sock`) rather than
    /// failing with "must be configured".
    #[test]
    #[cfg(unix)]
    fn resolve_admin_endpoint_falls_back_to_default_when_unset() {
        let dir = crate::test_support::scratch_dir("admin-default-fallback");
        let cfg = Config {
            global: GlobalConfig {
                admin_socket: None,
                ..GlobalConfig::default()
            },
            ..Config::default()
        };
        let ep = resolve_admin_endpoint(&cfg, Some(&dir)).expect("default must apply");
        match ep {
            AdminEndpoint::Unix(path) => assert_eq!(path, dir.join("admin.sock")),
            other => panic!("expected Unix endpoint, got {other:?}"),
        }
    }

    /// Without a `config_dir` hint the resolver still fails explicitly — we
    /// don't guess a system-wide location on the operator's behalf.
    #[test]
    fn resolve_admin_endpoint_errors_when_unset_and_no_config_dir() {
        let cfg = Config {
            global: GlobalConfig {
                admin_socket: None,
                ..GlobalConfig::default()
            },
            ..Config::default()
        };
        let err = resolve_admin_endpoint(&cfg, None)
            .expect_err("must error without admin_socket + config_dir");
        assert!(
            matches!(&err, NodeError::AdminProtocol(m) if m.contains("admin_socket")),
            "expected AdminProtocol error, got {err:?}",
        );
    }

    // ── audit_event_for mapper ──────────────────────────────────

    use crate::admin_audit::AuditOutcome;

    #[test]
    fn audit_event_for_returns_none_for_read_only_commands() {
        // Spot-check several read-only commands. None should produce
        // an audit event regardless of outcome.
        let ok_dummy: Result<AdminResult> = Ok(AdminResult::Ack {
            message: String::new(),
        });
        for cmd in [
            AdminCommand::Show,
            AdminCommand::Health,
            AdminCommand::Listens,
            AdminCommand::Sessions,
            AdminCommand::ListBans,
            AdminCommand::DhtList,
            AdminCommand::Bandwidth,
            AdminCommand::Metrics,
            AdminCommand::DhtRouting,
            AdminCommand::PexStatus,
        ] {
            assert!(
                super::audit_event_for(&cmd, &ok_dummy).is_none(),
                "{cmd:?} must not be audited"
            );
        }
    }

    #[test]
    fn audit_event_for_records_mutating_commands_with_outcome() {
        let ok_dummy: Result<AdminResult> = Ok(AdminResult::Ack {
            message: String::new(),
        });
        let err_dummy: Result<AdminResult> = Err(NodeError::AdminProtocol("fake".to_owned()));

        let ok_event = super::audit_event_for(
            &AdminCommand::BanNode {
                node_id: "abc123".to_owned(),
            },
            &ok_dummy,
        )
        .expect("ban_node must be audited");
        assert_eq!(ok_event.command_kind, "ban_node");
        assert_eq!(ok_event.args, "node_id=abc123");
        assert!(matches!(ok_event.outcome, AuditOutcome::Ok { .. }));

        let err_event = super::audit_event_for(
            &AdminCommand::KillSession {
                link_id: 0xdead_beef,
            },
            &err_dummy,
        )
        .expect("kill_session must be audited");
        assert_eq!(err_event.command_kind, "kill_session");
        assert!(err_event.args.contains("0x00000000deadbeef"));
        assert!(
            matches!(err_event.outcome, AuditOutcome::Err { ref message } if message.contains("fake"))
        );
    }

    #[test]
    fn audit_event_for_redacts_dht_value_payload() {
        // Operators who put binary into the DHT shouldn't have it
        // copied verbatim into a JSONL-grep-able audit log; the event
        // records value_len, not the value itself.
        let ok_dummy: Result<AdminResult> = Ok(AdminResult::Ack {
            message: String::new(),
        });
        let event = super::audit_event_for(
            &AdminCommand::DhtPut {
                key: "feed".to_owned(),
                value: "secret-payload-bytes".to_owned(),
            },
            &ok_dummy,
        )
        .expect("dht_put must be audited");
        assert_eq!(event.command_kind, "dht_put");
        assert!(
            !event.args.contains("secret"),
            "args must not echo DhtPut value verbatim, got {:?}",
            event.args
        );
        assert!(event.args.contains("value_len="));
    }
}
