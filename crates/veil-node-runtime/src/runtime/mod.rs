// Audit batch 2026-05-22: module-level allow for two style lints
// that are not actionable without invasive rewrites:
//   * `doc_overindented_list_items` — multi-paragraph numbered lists in
//     module-level docstrings would lose readability if re-indented to
//     match clippy's 3-space rule.
//   * `field_reassign_with_default` — a handful of test fixtures build
//     `Config::default()` then mutate a few listen entries; inlining
//     `..Default::default()` produces less-readable test setup.
#![allow(
    clippy::doc_overindented_list_items,
    clippy::field_reassign_with_default
)]

mod anonymity_state;
mod bootstrap;
mod dht_republish;
mod discovery;
mod ephemeral_rotator;
mod handoff_runtime;
mod identity_loaders;
mod identity_publish;
mod identity_state;
mod ip_slot;
mod ipc_bridges;
mod ipc_server;
mod key_rotation;
mod lifecycle;
mod mailbox_state;
mod maintenance;
mod mesh_gateway;
mod mobile_state;
mod nat_traversal;
mod nickname;
mod node_services;
mod offline_seal;
mod p_net_ban_sync;
pub(crate) mod peer_handshake;
mod persist_tasks;
pub(crate) mod persistence;
mod pex_runtime;
mod push_tasks;
mod rendezvous_binder;
mod resumption_state;
mod routing_health;
mod routing_state;
mod service_tasks;
pub mod services;
mod session_defaults;
pub(crate) mod session_guard;
mod sovereign_republish;
mod space_discovery;
mod suspension_watch;
mod update_check;
mod uri_helpers;
// Phase 2 pre-work (veilcore extraction): `handoff` + `hot_standby`
// moved to `veil_session::` to break session → runtime cycle.
// See `docs/en/PLAN_VEILCORE_EXTRACTION.md`.  Backwards-compat re-
// exports preserved here for existing `crate::runtime::handoff::*`
// / `::hot_standby::*` callers.
pub use veil_session::handoff;
pub use veil_session::hot_standby;
// test-only debug accessors on `NodeRuntime`. All `debug_*`
// methods are consumed exclusively by `sim::scenarios` and integration
// tests — verified by grep across workspace.  Phase 4 (veilcore extraction):
// `#[cfg(test)]` removed so cross-crate tests in veilcore (chaos_sim, scenarios)
// can reach `runtime.debug_*` methods.  Production cost: negligible (methods
// small and not called outside tests).
mod debug;
mod inspect;

use identity_loaders::{build_standalone_sovereign_identity, load_falcon_signer, load_signing_key};
use peer_handshake::{ExpectedPeerIdentity, peer_transport_context, register_connection_session};
use session_guard::SessionGuard;
use uri_helpers::{
    build_relay_node_ids, build_target_labels, is_wildcard_transport,
    nat_candidate_to_transport_uri,
};
use veil_util::{lock, rlock, wlock};

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard, RwLock,
        atomic::{AtomicU32, AtomicU64},
    },
    time::Instant,
};

use tokio::{
    io::AsyncWriteExt,
    sync::{oneshot, watch},
    task::JoinHandle,
};

use veil_cfg::{self, Config};
use veil_transport::{
    BoxIoStream, TransportConnection, TransportContext, TransportRegistry, TransportUri,
};

use crate::error::{NodeError, Result};
use crate::listener_supervisor::{AcceptWaiters, lock_waiters};
use crate::local_identity::HandshakeIdentity;
use crate::metrics_http::RuntimeSummary;
use crate::state::NodeState;
use crate::types::{
    LinkId, ListenConfigEntry, ListenId, ListenerHandle, NodeId, NodeIdBytes, PeerConfigEntry,
    PeerId, SessionInfo, SessionSource, SessionState,
};
use veil_abuse::{BanList, PerPeerLimiter, ViolationTracker};
use veil_app::AppEndpointRegistry;
use veil_dht::KademliaService;
use veil_discovery::DiscoveryService;
use veil_dispatcher::FrameDispatcher;
use veil_gateway::GatewayService;
use veil_mesh::{GatewayBridge, MeshForwarder, NeighborTable, UdpRealm};
use veil_observability::{NodeLogger, NodeMetrics};
use veil_routing::{NeighborScorer, RouteCache, RttTable, VivaldiCoord};
use veil_session::SessionRegistry;

/// Serialisable snapshot of one peer pubkey cache entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PeerPubkeySnapshot {
    #[serde(with = "veil_proto::serde_base64::hex_array")]
    pub node_id: [u8; 32],
    pub algo: u8,
    #[serde(with = "veil_proto::serde_base64::serde_bytes_base64")]
    pub pubkey: Vec<u8>,
}

#[derive(Default)]
pub struct RuntimeTasks {
    listeners: Vec<JoinHandle<()>>,
    peers: Vec<JoinHandle<()>>,
    sessions: Vec<JoinHandle<()>>,
    /// persist tasks (RTT, route-cache) that must survive reconnect events.
    /// Never cleared on session churn — only aborted on full shutdown / drop.
    pub background: Vec<JoinHandle<()>>,
}

/// Sustained probe rate for one target once its burst is spent: one attempt
/// per ten minutes. A peer that has genuinely returned reconnects on its own
/// announcement long before this matters; a peer that never answers costs
/// 6 probes an hour instead of 1140.
const NAT_PROBE_SUSTAINED_PER_SEC: f64 = 1.0 / 600.0;
/// Burst allowed before the sustained rate bites — enough for a real
/// reconnect handshake, which succeeds on the first or second attempt.
const NAT_PROBE_BURST: f64 = 3.0;
/// Forget a target that nobody has probed for this long, so the map cannot
/// grow without bound and a long-absent peer starts from a full burst.
const NAT_PROBE_IDLE_FORGET: std::time::Duration = std::time::Duration::from_secs(3600);

#[derive(Clone)]
pub struct NodeServices {
    registry: Arc<TransportRegistry>,
    transport_ctx: Arc<TransportContext>,
    /// cleanup (post-PR5): identity-domain bundle cloned
    /// (Arc) from NodeRuntime at access time. Pre-cleanup NodeServices
    /// held 7 separate identity fields (local_identity, peer_pubkeys
    /// peer_sovereign_identities, peer_roles, mlkem_ek, peer_mlkem_keys
    /// per_session_mlkem_dk) + sovereign_identity — net 8 sibling fields
    /// cloned individually. Bundling collapses to 1 Arc.
    pub identity: Arc<identity_state::IdentityState>,
    state: Arc<Mutex<NodeState>>,
    /// live-session map (link-level metadata) — moved out of
    /// `NodeState`. Shared with `NodeRuntime.live_sessions`.
    pub live_sessions: Arc<Mutex<std::collections::BTreeMap<LinkId, SessionInfo>>>,
    /// Monotonic per-peer session-close generation. Incremented when a session
    /// runner exits, so higher layers with long-lived handles can notice that a
    /// relay session they were using has churned since the handle was opened.
    pub(crate) session_close_generations: Arc<Mutex<std::collections::HashMap<[u8; 32], u64>>>,
    next_link_id: Arc<AtomicU64>,
    pending_accepts: Arc<Mutex<AcceptWaiters>>,
    pub logger: Arc<NodeLogger>,
    pub metrics: Option<Arc<NodeMetrics>>,
    pub dispatcher: Arc<FrameDispatcher>,
    pub session_registry: Arc<Mutex<veil_session::SessionRegistry>>,
    pub session_tx_registry: Arc<RwLock<veil_session::SessionTxRegistry>>,
    /// Probe back-off keyed by TARGET — see the field of the same name on
    /// the runtime for what it cost in production before it existed.
    pub nat_probe_backoff: Arc<Mutex<PerPeerLimiter>>,
    pub session_outbox: Arc<veil_session::SessionOutbox>,
    /// notification handle that the outbound-connector trips
    /// on close of a synthetic-range gateway session (peer_id ≥ `0xC000_0000`).
    /// `spawn_gateway_autodiscover_loop` waits on this in addition to its
    /// periodic poll so failover lag drops from ~5 s to sub-second.
    pub gateway_failover_notify: Arc<tokio::sync::Notify>,
    /// notification handle fired by mobile-event sink on
    /// `NetworkChanged` (WiFi ↔ Cellular flip). Wakes every
    /// outbound-connector reconnect loop from its sleep so reconnect
    /// attempts fire IMMEDIATELY on the new local interface instead of
    /// waiting for the 30-s pre-check sleep + 30-s+ TCP keepalive
    /// timeout that the old (now-stale) connection takes to surface as
    /// dead. Pairs with `force_reconnect_all_peers` runtime method
    /// which unregisters stale `session_tx_registry` entries to
    /// invalidate `has_session` pre-check + drops sender channels
    /// (causes session-runners to exit on channel-closed branch).
    /// Recovery latency on network change drops from ~30-90 s to ~1-3 s.
    pub force_reconnect_notify: Arc<tokio::sync::Notify>,
    /// P2P mobility slice: connectivity-gain hook (see
    /// `connectivity_gain.rs`) — the outbound connector fires it after
    /// every completed session registration.
    pub connectivity_gain: Arc<crate::connectivity_gain::ConnectivityGain>,
    /// shared push-event bus, mirrored from `NodeRuntime` so
    /// service-task spawn paths (inbound listeners) can publish on it.
    pub event_bus: Arc<veil_ipc::EventBus>,
    /// per-node-id slot registry for outbound-connector tasks.
    /// Each `spawn_outbound_peers` call atomically claims a slot per
    /// `node_id` before spawning a reconnect loop; duplicate claims (same
    /// node_id from a different `PeerSource` — configured / bootstrap /
    /// PEX / gateway-failover / pinned-relay) are dropped silently. The
    /// task removes its slot on exit. Closes a 50-node-stress-test bug
    /// where the gateway-failover poll loop spawned a fresh connector task
    /// every 10 s after a hub peer died, accumulating 20+ parallel tasks
    /// all hammering the same dead address (~290 connect-attempts/sec
    /// aggregate across 49 surviving nodes vs. ~1.5/sec under correct
    /// per-node-id backoff).
    pub outbound_connector_refresh:
        Arc<Mutex<std::collections::HashMap<[u8; 32], watch::Sender<u64>>>>,
    /// same cache as on `NodeRuntime` (see field doc there).
    /// Outbound-connector populates it post-handshake-complete so the
    /// next cold start can use these peers as bootstrap fallbacks.
    pub discovered_peers_cache: Arc<Mutex<veil_bootstrap::DiscoveredPeerCache>>,
    /// finish: anonymity-domain state is shared through
    /// `Arc<AnonymityState>` between `NodeRuntime`, `NodeServices` and
    /// `SessionRuntimeContext` — single source of truth, snapshot
    /// semantics preserved (Arc clone = point-in-time view since the
    /// inner struct is treated immutably; reload swaps a fresh `Arc`
    /// on `NodeRuntime` without disturbing in-flight clones).
    pub anonymity: Arc<anonymity_state::AnonymityState>,
    // cleanup: peer_pubkeys / peer_sovereign_identities
    // / peer_roles / mlkem_ek / peer_mlkem_keys / per_session_mlkem_dk
    // moved into the `identity: Arc<IdentityState>` bundle near top of
    // struct. Reads through `services.identity.<field>`.
    sessions_per_ip: Arc<ip_slot::IpSlotTable>,
    /// Soft-ban shield for source IPs producing pre-protocol garbage handshakes.
    pub scanner_shield: Arc<veil_abuse::scanner_shield::ScannerShield>,
    /// Path to the on-disk config file, used to persist nonce updates.
    config_path: PathBuf,
    /// H10 stage-B (4/N): session-defaults bundle (15 pure-value
    /// config knobs — Duration / u32 / u64 / usize / [u32; 4]) extracted
    /// into [`Arc<SessionDefaults>`]. See `node/runtime/session_defaults.rs`.
    pub defaults: Arc<session_defaults::SessionDefaults>,
    /// RTT probe table — used to decide whether to send an immediate probe.
    pub rtt_table: Arc<Mutex<RttTable>>,
    /// Kademlia DHT service — used by bootstrap task to add discovered contacts.
    pub dht: Arc<KademliaService>,
    /// local node_id bytes — used as FIND_NODE target during bootstrap.
    pub local_node_id: [u8; 32],
    /// NodeRuntime decomposition: mobile / battery-tier
    /// state shared [`Arc<MobileState>`]. Pre-PR3 these were 5
    /// sibling fields (mobile_background_mode + 4 battery_*).
    pub mobile: Arc<mobile_state::MobileState>,
    /// H10 stage-B: session-resumption-domain
    /// state (`ticket_issuer` + `peer_tickets`) extracted into
    /// [`Arc<ResumptionState>`]. See `node/runtime/resumption_state.rs`.
    pub resumption: Arc<resumption_state::ResumptionState>,
    // cleanup: sovereign_identity moved into the
    // `identity: Arc<IdentityState>` bundle near top of struct.
    /// H10 stage-B: hot-standby handoff-domain state
    /// (registry + swap_registry + ack_waiters + controller +
    /// auto-trigger threshold) extracted into [`Arc<HandoffRuntime>`].
    /// See `node/runtime/handoff_runtime.rs`.
    pub handoff: Arc<handoff_runtime::HandoffRuntime>,
    /// peer-algo allow-list copy from `config.session`
    /// consulted at session admit time to reject peers using an algo
    /// the operator has locked out. Empty = accept any supported.
    pub allowed_peer_algos: Vec<veil_cfg::SignatureAlgorithm>,
    /// P-Net Phase 2d: private-network membership gate. Loaded once
    /// from `[network]` config at startup; `None` in public mode.
    pub network_gate: Option<Arc<veil_identity::network_access::NetworkAccessGate>>,
    /// Per-peer verified MembershipCert cache.  Populated at OVL1
    /// handshake-time when `network_gate.verify_peer()` succeeds.
    /// Exposed to IPC consumers (ogate / oproxy) via
    /// `LocalAppMsg::PnetStatusQuery` so apps can gate admission on
    /// the daemon's already-performed verify without maintaining their
    /// own static `allowed_node_ids` list.  Empty in public mode
    /// (gate=None) — IPC queries always reply `has_cert=false`.
    pub verified_peer_certs:
        Arc<std::sync::RwLock<std::collections::HashMap<[u8; 32], veil_types::MembershipCert>>>,
    /// Runtime task registry used to retain responder-side punched sessions.
    tasks: Arc<Mutex<RuntimeTasks>>,
    /// Single-flight registry for explicit call-path hole-punch attempts.
    /// Shared with `NodeRuntime.hole_punch_inflight`.
    hole_punch_inflight: HolePunchInflightMap,
    /// Count of exclusive (slot-holding) punch attempts actually STARTED
    /// through this `NodeServices` — bumped once per non-joining attempt.
    /// Created fresh per `access()` and shared across its clones; lets a
    /// test prove that a concurrent second call for the same peer joined
    /// the in-flight attempt instead of starting a second punch.
    hole_punch_run_count: Arc<AtomicU64>,
}

#[derive(Clone)]
pub struct SessionRuntimeContext {
    /// cleanup: identity-domain bundle cloned (Arc) from
    /// NodeServices at context build. Pre-cleanup SessionRuntimeContext
    /// held 7 separate identity fields + sovereign_identity = 8 sibling
    /// fields, all Arc-clones of the same upstream sources. Bundling
    /// collapses to 1 Arc.
    pub identity: Arc<identity_state::IdentityState>,
    state: Arc<Mutex<NodeState>>,
    /// live-session metadata, co-located with `NodeRuntime.live_sessions`.
    live_sessions: Arc<Mutex<std::collections::BTreeMap<LinkId, SessionInfo>>>,
    /// Shared close-generation map; see [`NodeServices::session_close_generation`].
    pub(crate) session_close_generations: Arc<Mutex<std::collections::HashMap<[u8; 32], u64>>>,
    /// shared push-event bus, mirrored from `NodeRuntime` so
    /// `register_connection_session` can publish `SESSIONS_CHANGED`
    /// on every fresh insert. Cheap to clone (`Arc`).
    pub event_bus: Arc<veil_ipc::EventBus>,
    next_link_id: Arc<AtomicU64>,
    logger: Arc<NodeLogger>,
    metrics: Option<Arc<NodeMetrics>>,
    dispatcher: Arc<FrameDispatcher>,
    session_registry: Arc<Mutex<veil_session::SessionRegistry>>,
    session_tx_registry: Arc<RwLock<veil_session::SessionTxRegistry>>,
    session_outbox: Arc<veil_session::SessionOutbox>,
    // cleanup: peer_pubkeys / peer_sovereign_identities
    // / peer_roles / mlkem_ek / peer_mlkem_keys / per_session_mlkem_dk
    // moved into the `identity: Arc<IdentityState>` bundle near top of
    // struct. Reads through `runtime.identity.<field>`.
    /// finish: shared anonymity state, cloned (Arc)
    /// from `NodeServices` at context build. Reads `.relay_capable` at
    /// handshake time for the `ANONYMITY_RELAY` capability flag.
    anonymity: Arc<anonymity_state::AnonymityState>,
    /// Per-IP session counter: limits inbound connections from a single source IP.
    sessions_per_ip: Arc<ip_slot::IpSlotTable>,
    /// Soft-ban shield for source IPs producing pre-protocol garbage handshakes.
    /// Updated on `ProtoError::InvalidMagic`-class failures; checked at accept.
    pub scanner_shield: Arc<veil_abuse::scanner_shield::ScannerShield>,
    /// H10 stage-B (4/N): session-defaults bundle cloned (Arc)
    /// from NodeServices at session-context build. Reads `keepalive_interval`
    /// / `idle_timeout` / `max_pending_responses` / ... / `max_per_subnet`
    /// through this handle (16 fields collapsed to 1).
    defaults: Arc<session_defaults::SessionDefaults>,
    /// RTT probe table — used to decide whether to send an immediate probe.
    rtt_table: Arc<Mutex<RttTable>>,
    /// Path to the on-disk config file, used to persist nonce updates.
    config_path: PathBuf,
    /// NodeRuntime decomposition: mobile / battery-tier
    /// state cloned (Arc) from NodeServices at session-context build.
    mobile: Arc<mobile_state::MobileState>,
    /// H10 stage-B: session-resumption-domain
    /// state cloned (Arc) from NodeServices at session-context build.
    /// Reads `.ticket_issuer` / `.peer_tickets` through this handle.
    resumption: Arc<resumption_state::ResumptionState>,
    // cleanup: sovereign_identity moved into the
    // `identity: Arc<IdentityState>` bundle near top of struct.
    // d removed the persistent `revocation_cache` field.
    /// H10 stage-B: hot-standby handoff-domain
    /// state cloned (Arc) from NodeServices at session-context build. Reads
    /// `.registry` / `.swap_registry` / `.ack_waiters` / `.controller` /
    /// `.auto_trigger_after_write_errors` through this handle.
    handoff: Arc<handoff_runtime::HandoffRuntime>,
    /// peer-algo allow-list (empty = accept any supported).
    allowed_peer_algos: Vec<veil_cfg::SignatureAlgorithm>,
    /// P-Net Phase 2d: optional private-network membership gate.
    /// `Some` when `[network].mode = "private"` — handshake will
    /// include local cert in HELLO and reject peers without a valid cert.
    /// `None` keeps existing public-veil behaviour.
    pub network_gate: Option<Arc<veil_identity::network_access::NetworkAccessGate>>,
    /// Per-peer verified MembershipCert cache, cloned (Arc) from
    /// NodeServices.  Handshake stores into it on successful
    /// `network_gate.verify_peer()`.
    pub verified_peer_certs:
        Arc<std::sync::RwLock<std::collections::HashMap<[u8; 32], veil_types::MembershipCert>>>,
    /// P2P mobility slice: outbound-connector refresh slots, cloned (Arc)
    /// from `NodeRuntime.outbound_connector_refresh`. Handed into every
    /// `SessionGuard` so a session close instantly wakes the closing
    /// peer's connector loop (see `session_guard.rs`).
    outbound_connector_refresh: Arc<Mutex<std::collections::HashMap<[u8; 32], watch::Sender<u64>>>>,
}

#[derive(Clone)]
pub struct InboundSessionContext {
    runtime: SessionRuntimeContext,
    listen_id: ListenId,
    listener_handle: ListenerHandle,
}

/// Lifetime cap for a transient referral session (one accepted into the
/// headroom above `max_concurrent`). Long enough for the client to receive the
/// on-open peer-gossip sample and dial a freer node, short enough that the
/// headroom frees quickly so the per-node session ceiling stays effectively
/// hard under sustained load.
const REFERRAL_SESSION_TTL: std::time::Duration = std::time::Duration::from_secs(20);

pub struct AttachedDebugSession {
    pub link_id: LinkId,
    pub source: SessionSource,
    pub stream: BoxIoStream,
    /// Unreliable side channel cloned from the same authenticated QUIC
    /// connection before its primary stream was consumed. `None` for TCP,
    /// obfs4, TLS and websocket transports.
    pub quic_datagrams: Option<veil_session::runner::RealtimeLaneOffer>,
    pub metrics: Option<Arc<NodeMetrics>>,
    /// Authenticated peer node_id from the handshake.
    pub peer_id: NodeId,
    /// The peer's Ed25519 public key and PoW nonce, base64, AS PROVEN by this
    /// handshake — not as any row claimed them beforehand.
    ///
    /// Carried because a peer can be met with no prior claim at all. A peer
    /// found on a public index is an address and nothing else; everything
    /// durable this node then says about it has to come from what the other
    /// side proved, and this is where that arrives.
    pub peer_public_key: String,
    pub peer_nonce: String,
    /// The signature algorithm the handshake actually proved, not the one the
    /// caller would otherwise have assumed. `None` when the wire named an
    /// algorithm this build does not know.
    pub peer_algo: Option<veil_cfg::SignatureAlgorithm>,
    /// WHICH DEVICE of `peer_id` this session ends at, when the handshake
    /// proved one (or a resumption ticket named one). `None` for peers with no
    /// sovereign identity, and for a resumption that could not resolve the
    /// device — never guessed.
    pub peer_instance_id: Option<[u8; 16]>,
    /// Session keys derived during the OVL1 handshake.
    pub session_keys: veil_crypto::session_kdf::SessionKeys,
    /// Transport-layer observed address of the peer (as seen by our socket).
    /// `None` for stream transports that do not expose a remote address.
    pub observed_addr: Option<std::net::SocketAddr>,
    /// Reflector port authenticated by the peer's ATTACH advertisement.
    pub udp_reflector_port: Option<u16>,
    /// Public reflector endpoints relayed by the authenticated peer.
    pub shared_udp_reflectors: Vec<std::net::SocketAddr>,
    /// Base64-encoded remote peer public key from the handshake.
    pub public_key: String,
    /// Remote peer nonce string from the handshake.
    pub nonce: String,
    /// remote peer's last-known DHT discoverability preference
    /// extracted from `CapabilitiesPayload.discovery_mode` during the
    /// OVL1 handshake. Stamped into the routing-table `Contact` so
    /// `handle_find_node_v2` can filter the peer out of FIND_NODE responses
    /// if they prefer to stay hidden.
    pub remote_discovery_mode: veil_cfg::DiscoveryMode,
    /// False when the peer advertised `NO_DHT_SERVICE` — stamped into the
    /// routing-table `Contact` so no candidate-selection path picks it.
    ///
    /// Only meaningful when [`Self::remote_caps_stated`] is true.
    pub remote_dht_service: bool,
    /// Whether the two fields above came from the peer's own CAPABILITIES
    /// frame. False on a fast-resumed handshake, which synthesizes a zero
    /// payload that reads as "Public, serves" — the ordinary answer, not a
    /// missing one. Anything writing these into the routing table must treat
    /// false as "no news" and leave the stored stamps alone.
    pub remote_caps_stated: bool,
    /// True when this session was accepted INTO the referral headroom above
    /// `max_concurrent` (the node was already at its data ceiling). Such a
    /// session is transient: it exists only to deliver a peer-gossip sample so
    /// the would-be client can dial a freer node, then its lifetime is capped
    /// (see `REFERRAL_SESSION_TTL`) so the headroom frees and the per-node
    /// ceiling stays effectively hard.
    pub referral: bool,
    /// receiver pre-reserved by
    /// `try_register_unique` in the cap+dup atomic critical section.
    /// The downstream `cache_peer_handshake_state` consumes this
    /// receiver instead of calling `register` again — closing the
    /// TOCTOU window where two concurrent handshakes could both pass
    /// the dup-check and double-register.
    pub reserved_outbox_rx: tokio::sync::mpsc::Receiver<veil_session::PriorityFrame>,
    _guard: SessionGuard,
}

/// per-gateway status row returned by `mesh_gateway_status`.
///
/// Captures everything an operator needs to answer "why am I (not)
/// PoW-Gated Rendezvous endpoint returned by
/// [`NodeRuntime::request_rendezvous_endpoint`].  Caller dials
/// `transport_uri` with the embedded `psk` as the obfs4 pre-shared key;
/// `valid_until_unix` is the wall-clock deadline beyond which the
/// target's on-demand listener will have retired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousEndpoint {
    /// Transport URI to dial (e.g. `"obfs4-tcp://example.com:51237"`).
    pub transport_uri: String,
    /// Per-request 32-byte PSK for the obfs4 handshake.
    pub psk: [u8; 32],
    /// Unix-timestamp expiry of the on-demand listener slot.
    pub valid_until_unix: u64,
}

/// Errors returned by [`NodeRuntime::request_rendezvous_endpoint`].
#[derive(Debug, thiserror::Error)]
pub enum RendezvousClientError {
    #[error("requested PoW difficulty rejected: {0}")]
    BadDifficulty(String),
    #[error("target_node_id != BLAKE3(target_pubkey)")]
    TargetIdentityMismatch,
    #[error("no active session peers to relay through")]
    NoPeers,
    #[error("pending-recursive table at cap; retry later")]
    PendingTableFull,
    #[error("send_to failed for all closest peers")]
    SendFailed,
    #[error("PoW mining failed: {0}")]
    Mining(String),
    #[error("recursive-response wait timed out")]
    Timeout,
    #[error("recursive-response oneshot channel closed without a response")]
    ChannelClosed,
    #[error("response payload was empty")]
    EmptyResponse,
    #[error("response decode failed: {0}")]
    Decode(String),
    #[error("response verify failed: {0}")]
    Verify(String),
}

/// connected via X" without leaking implementation details. All
/// fields are populated from running state — no config file reads.
#[derive(Debug, Clone)]
pub struct MeshGatewayStatusEntry {
    /// Gateway's veil node id.
    pub node_id: [u8; 32],
    /// Dial address advertised in the gateway's mesh beacon.
    pub veil_addr: String,
    /// `true` ⇔ this gateway is currently in the live session set; the
    /// node can route data through it right now. `false` = discovered
    /// but not yet (re-)connected (back-fill in progress, or already
    /// at `mesh.autodiscover_max_concurrent`).
    pub is_active: bool,
    /// EWMA-smoothed RTT in milliseconds, latest value. `None` when
    /// no probe has been recorded yet (auto-discover loop will use
    /// `GATEWAY_RANK_UNKNOWN_RTT_MS = 500` as the default).
    pub rtt_smoothed_ms: Option<u32>,
    /// Gateway's last self-reported battery level from its mesh
    /// beacon. `0` = AC power / unknown (no penalty in ranking);
    /// `1..=100` = percent.
    pub battery_level: u8,
    /// How many seconds ago the most recent beacon was received.
    pub last_seen_secs_ago: u64,
    /// How many seconds until this entry is dropped from the
    /// auto-discover cache (refreshed by every new beacon).
    pub expires_in_secs: u64,
}

// ── quorum policy for verified resolves ───────────────────────────

/// Number of independent replicas the resolver fans out to per
/// verified resolve. Capped at `DHT_REPLICATION_K = 8` (the publish
/// fan-out width); higher values pull from peers further from the
/// keyspace target which won't have the value anyway. 4 gives
/// ~50% replica coverage on a fully-replicated key with low traffic
/// cost (4 frames out, ≤4 responses).
pub const RESOLVE_MAX_REPLICAS: usize = 4;

/// Minimum number of replicas that must return identical bytes
/// before the resolver accepts the result as authoritative. Below
/// this threshold the resolver returns `QuorumDivergence` and lets
/// the caller decide whether to retry with a wider fan-out. 2 is
/// the smallest meaningful threshold for an anti-sybil bar — a
/// single sybil at the closest position can no longer overwrite
/// the resolver's view because it can't fake an identical reply
/// from a *second* peer. 3+ would be stronger but slower under
/// flaky-mobile network conditions where some replicas may not
/// respond in time.
pub const RESOLVE_QUORUM_THRESHOLD: usize = 2;

/// Tally `replicas` by exact-byte equality and return the byte
/// vector that hit `threshold` matches. Returns `None` if no
/// candidate reached the threshold (= `QuorumDivergence`) OR if the
/// list is empty (= `NotFound` — the caller distinguishes the two).
///
/// Single-replica fast path (audit cycle-9): `allow_single_replica` must be set
/// ONLY when a single response is independently trustworthy — i.e. the value is
/// SELF-CERTIFYING and the caller re-verifies it (e.g. an identity document
/// whose `node_id == BLAKE3(master_pk)` is re-checked after this returns). For
/// NON-self-certifying values (NameClaim @name → node_id) the quorum is the
/// ONLY anti-Sybil defense, so `allow_single_replica = false` requires
/// `threshold` agreeing replicas. Previously the `len()==1` bypass was
/// unconditional, justified by a stale comment about the local-store fast path —
/// but `dht_get_replicated` short-circuits a validated LOCAL value before
/// reaching here, so a `len()==1` set here is a single REMOTE response, which a
/// lone (or only-reachable) Sybil could supply to hijack a name.
pub fn pick_quorum_match(
    replicas: &[Vec<u8>],
    threshold: usize,
    allow_single_replica: bool,
) -> Option<Vec<u8>> {
    if allow_single_replica && replicas.len() == 1 {
        return Some(replicas[0].clone());
    }
    let mut tally: std::collections::HashMap<&[u8], usize> = std::collections::HashMap::new();
    for r in replicas {
        *tally.entry(r.as_slice()).or_insert(0) += 1;
    }
    tally
        .into_iter()
        .filter(|(_, c)| *c >= threshold)
        .max_by_key(|(_, c)| *c)
        .map(|(bytes, _)| bytes.to_vec())
}

pub struct NodeRuntime {
    config_path: PathBuf,
    /// Home of this node's identity material, resolved ONCE at construction
    /// from `[global] identity_dir` or, failing that, the config file's
    /// directory.
    ///
    /// It is a field rather than a derivation because it used to be derived —
    /// `config_path.parent()`, written out ten times across this crate. Every
    /// copy agreed only as long as the answer was that one expression; an
    /// identity directory that half the code agrees on is worse than none,
    /// because the loader finds a document where the republisher finds nothing.
    identity_dir: PathBuf,
    foreground_mode: bool,
    registry: Arc<TransportRegistry>,
    transport_ctx: Arc<TransportContext>,
    /// NodeRuntime decomposition: identity-domain
    /// state extracted into [`Arc<IdentityState>`]. Pre-PR5 these
    /// were 8 sibling fields (local_identity, sovereign_identity
    /// peer_pubkeys, peer_sovereign_identities, peer_roles, mlkem_ek
    /// peer_mlkem_keys, per_session_mlkem_dk). See
    /// `node/runtime/identity_state.rs`.
    pub identity: Arc<identity_state::IdentityState>,
    logger: Arc<NodeLogger>,
    metrics: Option<Arc<NodeMetrics>>,
    /// same `Arc` that the `TransportRegistry` records into;
    /// shared with the IPC server so `TransportHintQuery` returns live data.
    hint_registry: Arc<veil_transport::hint_registry::TransportHintRegistry>,
    state: Arc<Mutex<NodeState>>,
    /// Link-level session metadata, keyed by `LinkId` (assigned when a
    /// transport-level connection opens — distinct from the OVL1
    /// `SessionId` which is only known after `SESSION_CONFIRM`). Owns
    /// the transport URI, listener handle, remote address, and session
    /// state. : moved out of `NodeState` since the data is
    /// pure runtime (live sockets), not config-surface state.
    pub live_sessions: Arc<Mutex<std::collections::BTreeMap<LinkId, SessionInfo>>>,
    /// Monotonic per-peer session-close generation, shared with service handles
    /// and session runtime contexts.
    pub(crate) session_close_generations: Arc<Mutex<std::collections::HashMap<[u8; 32], u64>>>,
    /// OVL1 session registry — tracks fully handshaken sessions keyed by
    /// `SessionId` (derived from `SESSION_CONFIRM`). Carries
    /// sovereign-identity outputs (identity proof, capabilities, role)
    /// that `live_sessions` deliberately does not duplicate.
    session_registry: Arc<Mutex<SessionRegistry>>,
    /// Per-session outbox senders — used by the runtime to push frames
    /// (e.g. periodic ROUTE_PROBEs) into active sessions.
    session_tx_registry: Arc<RwLock<veil_session::SessionTxRegistry>>,
    /// Application endpoint demultiplexer.
    app_registry: Arc<AppEndpointRegistry>,
    /// Gateway attachment service — active only for Gateway/Core roles.
    gateway: Arc<GatewayService>,
    /// Static discovery directory — active for all roles (store only for Gateway/Core).
    discovery: Arc<DiscoveryService>,
    /// Kademlia DHT service — active for Core/Gateway roles.
    dht: Arc<KademliaService>,
    /// Control-plane service — ROUTE_PROBE/ROUTE_REPLY, RTT table.
    control_plane: Arc<veil_routing::control_plane::ControlPlaneService>,
    /// Local mesh forwarder — active for Relay/Gateway/Core roles.
    mesh_forwarder: Arc<MeshForwarder>,
    /// Gateway bridge — lifts mesh frames to the veil plane (Gateway/Core only).
    mesh_bridge: Arc<GatewayBridge>,
    /// Optional UDP realm backend — present only when `config.mesh` is set.
    mesh_realm: Option<Arc<UdpRealm>>,
    /// Gateway nodes discovered via mesh beacons.
    autodiscovered_peers: Arc<veil_mesh::AutoDiscoveredPeers>,
    /// trips when a synthetic-range gateway session closes
    /// (peer_id ≥ 0xC000_0000). `spawn_gateway_autodiscover_loop`
    /// awaits this AND a periodic poll — whichever fires first wakes
    /// the loop to re-evaluate slot availability and back-fill. Drives
    /// the < 1 s failover acceptance for gateway redundancy.
    gateway_failover_notify: Arc<tokio::sync::Notify>,
    /// see `NodeServices::force_reconnect_notify`.
    pub force_reconnect_notify: Arc<tokio::sync::Notify>,
    /// P2P mobility slice: connectivity-gain hook — outbound session
    /// establishment fans out to the srflx probe task + (debounced)
    /// `force_reconnect_notify`. See `connectivity_gain.rs`.
    pub connectivity_gain: Arc<crate::connectivity_gain::ConnectivityGain>,
    /// shared push-event bus. IPC server subscribes one
    /// receiver per connected client and emits `LocalAppMsg::Event`
    /// frames on every publish; runtime publishes
    /// `SESSIONS_CHANGED` on every session insert/remove
    /// `MOBILE_TIER_CHANGED` from MobileEventForwarder, and (future)
    /// `IDENTITY_ROTATED` from master-rotation flow.
    /// Held here so every runtime mutation site has a single shared
    /// bus to publish on.
    pub event_bus: Arc<veil_ipc::EventBus>,
    /// per-node-id slot registry for outbound-connector tasks.
    /// Mirrored to `NodeServices` so cross-task spawns dedupe atomically.
    outbound_connector_refresh: Arc<Mutex<std::collections::HashMap<[u8; 32], watch::Sender<u64>>>>,
    /// cache of peers we've successfully OVL1-handshaked
    /// in a prior run. At cold start, `spawn_bootstrap_task` splices
    /// these into the bootstrap-candidate list AFTER the operator's
    /// `[[bootstrap_peers]]` so a censored seed list still has a
    /// fallback. Updated via `record_discovered_peer` on every
    /// handshake-complete; periodically flushed to disk by the
    /// maintenance tick.
    pub discovered_peers_cache: Arc<Mutex<veil_bootstrap::DiscoveredPeerCache>>,
    /// decomposition PR1: anonymity-domain state
    /// (relay_capable / advertised_bps / x25519_sk / rendezvous_publisher_entries)
    /// extracted into a dedicated [`Arc<AnonymityState>`]. See
    /// `node/runtime/anonymity_state.rs` for rationale. Pre-PR1 these
    /// fields lived directly on `NodeRuntime`.
    pub anonymity: Arc<anonymity_state::AnonymityState>,
    // `mobile_background_mode` moved into `MobileState`
    // (see field below: `pub mobile: Arc<MobileState>`).
    /// NodeRuntime decomposition: mailbox-domain state
    /// (`mailbox`, `outbox` handles) extracted into [`Arc<MailboxState>`].
    /// Pre-PR2 these were two sibling fields; collapsing to one bundle
    /// matches the `AnonymityState` PR1 pattern and gives slice-3
    /// follow-ups (per-sender quota counters, capability policy state)
    /// a typed home. See `node/runtime/mailbox_state.rs`.
    pub mailbox_state: Arc<mailbox_state::MailboxState>,
    ///.4 P5b: host for built-in app
    /// services (mailbox, future echo / time-sync etc.). Tasks
    /// inside abort cleanly on Drop; daemon stop calls
    /// `take.shutdown.await` for graceful drain.
    pub builtin_app_host: Option<crate::builtin::BuiltinAppHost>,
    /// NodeRuntime decomposition: routing-domain state
    /// (`rtt_table`, `route_cache`, `neighbor_scorer`, `vivaldi`)
    /// extracted into [`Arc<RoutingState>`]. Pre-PR4 these were 4
    /// sibling fields; bundle-then-Arc collapses them to one. See
    /// `node/runtime/routing_state.rs`. Inner Arcs remain individually
    /// lockable; reload mutates inner values, not swaps the bundle Arc
    /// so downstream Arc-clone holders observe new state automatically.
    pub routing: Arc<routing_state::RoutingState>,
    /// Per-peer rate limiter (shared across all incoming frame paths).
    rate_limiter: Arc<Mutex<PerPeerLimiter>>,
    /// Back-off for NAT-traversal probes, keyed by the TARGET we are trying to
    /// reach — not by the coordinator we ask.
    ///
    /// A probe exists precisely for a peer we cannot dial, so "unreachable" is
    /// not a reason to stop trying; it is the entry condition. Nothing bounded
    /// how long we keep trying, and a target that can never answer — a host
    /// that is switched off, or one on another network whose PSK we will never
    /// speak — was probed forever at the same rate as one that just blipped.
    ///
    /// Measured 24.08 on a production seed: 6093 `nat.probe.forward_failed`
    /// in 5.3 h, 19 a minute, **two thirds of everything the node logged**.
    /// Half the targets were dead hosts of our own fleet; the rest sat on the
    /// test network. Removing their transports stopped the futile dialling and
    /// changed the probe rate by nothing (18.7/min against 19.2), because the
    /// probe is driven by knowing a node_id, not by holding a transport.
    ///
    /// A token bucket rather than a fixed interval so a genuine reconnect can
    /// still burst, while a target that never answers decays to the sustained
    /// rate and stays there.
    nat_probe_backoff: Arc<Mutex<PerPeerLimiter>>,
    /// Ban list — rejected peers are dropped on connect.
    ban_list: Arc<Mutex<BanList>>,
    /// Violation tracker — escalates repeated offences to bans.
    violation_tracker: Arc<Mutex<ViolationTracker>>,
    /// PII-safe runtime snapshot served by /admin/health and /admin/state/dump.
    runtime_summary: Arc<Mutex<RuntimeSummary>>,
    /// OVL1 frame dispatcher — routes post-handshake frames to service planes.
    dispatcher: Arc<FrameDispatcher>,
    next_link_id: Arc<AtomicU64>,
    next_listener_handle: Arc<AtomicU64>,
    pending_accepts: Arc<Mutex<AcceptWaiters>>,
    metrics_path: Option<String>,
    metrics_endpoint: Option<String>,
    shutdown_tx: Option<watch::Sender<bool>>,
    /// Phase 5f Step 3 — keep ephemeral-rotator shutdown senders alive
    /// for the lifetime of the runtime.  Each entry is the watch
    /// sender returned by `spawn_ephemeral_rotator`; dropping it
    /// signals the rotator loop to exit via its internal
    /// `shutdown_rx.changed()` arm.  Holding them prevents the rotators
    /// from exiting immediately on startup.  On stop/reload these senders are
    /// drained into `StopTasksContext` and `do_stop_tasks` sends `true` on each
    /// (graceful exit ahead of the JoinHandle abort), so the list does not
    /// accumulate stale senders across reloads (audit M7).
    ephemeral_rotator_shutdowns: Mutex<Vec<watch::Sender<bool>>>,
    /// Strong handle to the PoW-Gated Rendezvous controller (Slice 5b
    /// of the epic).  Wrapped in `Mutex<Option<...>>` so it can be set
    /// post-construction (after `spawn_listeners` discovers a
    /// `visibility = "stealth"` listener) and cleared explicitly on
    /// `Drop` to break the `controller → binder → dispatcher` cycle
    /// (see `FrameDispatcher::rendezvous_weak`).  `None` when no
    /// stealth listener is configured.
    pub rendezvous_controller: Mutex<Option<Arc<veil_session::rendezvous::RendezvousController>>>,
    tasks: Arc<Mutex<RuntimeTasks>>,
    /// Heartbeat counter incremented every second by the cleanup task.
    /// The health watchdog uses this to detect a stalled event loop.
    health_tick: Arc<AtomicU64>,
    /// RPC outbox — routes FIND_NODE requests from NetworkPeerQuerier to the
    /// appropriate SessionRunner via peer_id.
    session_outbox: Arc<veil_session::SessionOutbox>,
    /// Shared monotonic wire stream-id allocator for cross-node streams, handed
    /// to both the IPC remote-stream path (via the IPC server's
    /// `IpcStreamBridge`) and `VeilConnector`, so the two surfaces never
    /// collide on a `(node_id, wire_stream_id)` key.
    wire_stream_counter: Arc<AtomicU32>,
    // peer_pubkeys / peer_sovereign_identities /
    // peer_roles / mlkem_ek / peer_mlkem_keys / per_session_mlkem_dk
    // moved into the `identity: Arc<IdentityState>` bundle (see field
    // earlier in this struct).
    /// Per-source-IP session counter for inbound connections.
    /// Prevents a single host from exhausting all concurrent session slots.
    sessions_per_ip: Arc<ip_slot::IpSlotTable>,
    /// Soft-ban shield for source IPs that produce pre-protocol garbage
    /// (port scanners, HTTP probes). Checked at the listener accept loop
    /// before spawning a handshake task; updated on `ProtoError::InvalidMagic`
    /// and similar pre-handshake decode errors.
    pub scanner_shield: Arc<veil_abuse::scanner_shield::ScannerShield>,
    /// Pre-spawn cap on concurrent inbound handshake tasks. Capacity =
    /// `max(4 × max_concurrent, 1024)` derived from session defaults at
    /// runtime-start time. The accept loop `try_acquire_owned`s before
    /// `spawn_inbound_session`; permit is held by the spawned task and
    /// drops on handshake completion / failure / timeout. Without this
    /// cap an inbound TCP flood pinned ~5 KB per pending task before the
    /// post-handshake `live_sessions.len >= max_concurrent` gate kicked in.
    pub inbound_handshake_sem: Arc<tokio::sync::Semaphore>,
    /// Permit count `inbound_handshake_sem` was built with (diff-audit M14).
    /// The semaphore can't be resized mid-flight without risking in-flight
    /// handshakes, so reload warns when `session.max_concurrent` changes the
    /// target rather than silently ignoring it.
    pub inbound_handshake_sem_target: usize,
    // The ML-KEM decapsulation seed used to be a field here, deliberately kept
    // outside the `IdentityState` bundle that held its public half — the note
    // said it had "different access patterns". Rotation made that split a
    // liability rather than a tidiness question: the seed and the EK have to
    // move together or the node publishes one and decrypts with the other. Both
    // now live in `identity.mlkem_keys` (a `veil_e2e::MlKemSeedRing`).
    /// Poked when the ML-KEM key rotates, to pull the sovereign republish
    /// forward instead of letting the new EK wait out the 6h tick.
    ///
    /// Without this the retired key would have to stay decrypt-capable for that
    /// extra 6h on top of everything else, and — worse — for those hours the
    /// node would be publishing an EK it had already replaced. The rotation task
    /// only rotates; the republish task owns publishing, and this is the seam.
    pub mlkem_republish_now: Arc<tokio::sync::Notify>,
    /// Poked by the suspension detector (`runtime/suspension_watch.rs`) when
    /// the wall clock has run ahead of CLOCK_MONOTONIC — i.e. the OS suspended
    /// this process without telling anyone. The DHT-republish task's per-key
    /// due times are `Instant`-based, so after a suspension every one of them
    /// is late by the sleep length while remote replica holders expired us on
    /// the wall clock; the poke drops that schedule so every stored key
    /// re-staggers from now, same as a fresh boot.
    pub dht_republish_now: Arc<tokio::sync::Notify>,
    /// Pending diagnostic reply channels: `seq → Sender<DiagEvent>`.
    /// Shared with `FrameDispatcher` so admin handlers can register waiters.
    pub pending_diag: Arc<
        Mutex<
            std::collections::HashMap<u32, tokio::sync::mpsc::Sender<veil_dispatcher::DiagEvent>>,
        >,
    >,
    /// H10 stage-B (4/N): session-defaults bundle (16 pure-value
    /// config knobs derived from config.session / config.gateway /
    /// config.connection) extracted into [`Arc<SessionDefaults>`].
    /// See `node/runtime/session_defaults.rs`. Shared by Arc-clone
    /// with NodeServices and SessionRuntimeContext at boundary builds.
    pub defaults: Arc<session_defaults::SessionDefaults>,
    /// NodeRuntime decomposition: mobile / battery-
    /// tier state extracted into [`Arc<MobileState>`]. Pre-PR3 these
    /// were 5 separate sibling fields (mobile_background_mode plus 4
    /// battery_*). See `node/runtime/mobile_state.rs`.
    pub mobile: Arc<mobile_state::MobileState>,
    /// real-time congestion monitor shared with FrameDispatcher.
    congestion_monitor: Arc<veil_congestion::CongestionMonitor>,
    /// global memory budget manager. Used in health tick for
    /// per-component memory reporting and eviction.
    memory_budget: Arc<crate::memory::MemoryBudget>,
    /// filesystem path for route-cache persistence snapshots.
    /// `None` when persistence is disabled in config.
    cache_persist_path: Option<String>,
    /// filesystem path for RTT table persistence snapshots.
    /// `None` when persistence is disabled in config.
    rtt_persist_path: Option<String>,
    /// Master switch for all on-disk persistence (mirrors `config.persist_enabled`).
    persist_enabled: bool,
    /// ranked list of known Gateway peers for multi-gateway failover.
    gateway_list: Arc<Mutex<veil_gateway::GatewayList>>,
    /// wall-clock instant when the ML-KEM decapsulation-key seed
    /// was loaded (or generated) for this node lifetime. Used as a fallback
    /// for `mlkem_key_age_secs` if the on-disk key file's mtime cannot be
    /// read (which is the authoritative source: it survives restarts so
    /// "key age" tracks keypair lifetime, not process uptime).
    mlkem_key_loaded_at: Instant,
    /// Path to the ML-KEM key PEM on disk. Used by `mlkem_key_age_secs`
    /// to compute key age from file mtime — this is the only signal that
    /// survives daemon restart and actually reflects key lifetime for
    /// rotation planning (rather than process uptime).
    mlkem_key_path: std::path::PathBuf,
    /// channel for on-demand DHT discovery triggers.
    /// Populated by `spawn_discovery_initiator_task`; `None` before that task is spawned.
    discovery_trigger_tx: Arc<Mutex<Option<tokio::sync::mpsc::Sender<()>>>>,
    /// H10 stage-B: session-resumption-domain state extracted into
    /// [`Arc<ResumptionState>`]. `ticket_issuer` is generated at startup and
    /// held for the process lifetime (periodic rotation is intended but not
    /// yet wired); per-peer `peer_tickets` presented in HELLO TLV on
    /// reconnect. See `node/runtime/resumption_state.rs`.
    pub resumption: Arc<resumption_state::ResumptionState>,
    /// H10 stage-B: PEX-domain runtime state extracted into an owned
    /// `PexRuntime` bundle. Plain struct (not `Arc<...>`) because the
    /// `Option<Receiver>` fields require `&mut self` access via
    /// `.take()` at task-spawn time, and `Arc<Mutex<_>>` would add a
    /// lock that nobody contends on. See `node/runtime/pex_runtime.rs`.
    pex: pex_runtime::PexRuntime,
    /// optional sovereign-identity handle loaded from disk at
    // sovereign_identity moved into the `identity:
    // Arc<IdentityState>` bundle. Field doc preserved on
    // IdentityState::sovereign_identity.
    /// H10 stage-B: hot-standby handoff-domain state
    /// (`registry` + `swap_registry` + `ack_waiters` + `controller` +
    /// `auto_trigger_after_write_errors`) extracted into
    /// [`Arc<HandoffRuntime>`]. See `node/runtime/handoff_runtime.rs`.
    pub handoff: Arc<handoff_runtime::HandoffRuntime>,
    /// peer-algo allow-list. Cloned into every
    /// `SessionRuntimeContext` at session-admit time.
    allowed_peer_algos: Vec<veil_cfg::SignatureAlgorithm>,
    /// P-Net Phase 2d: private-network membership gate. Loaded once
    /// from `[network]` config at startup. `Some` → handshake-time
    /// cert exchange + verification; `None` → public-mode behaviour.
    pub network_gate: Option<Arc<veil_identity::network_access::NetworkAccessGate>>,
    /// Per-peer verified MembershipCert cache.  Populated at OVL1
    /// handshake-time when `network_gate.verify_peer()` succeeds,
    /// read by `PnetStatusProvider` for IPC consumer queries.
    pub verified_peer_certs:
        Arc<std::sync::RwLock<std::collections::HashMap<[u8; 32], veil_types::MembershipCert>>>,
    /// Single-flight registry for explicit call-path hole-punch attempts
    /// (real-P2P Stage B): peer node_id → broadcast sender of the
    /// in-flight attempt's outcome. A second `attempt_p2p_hole_punch`
    /// for the same peer subscribes and awaits instead of racing a
    /// parallel punch. Entries are removed by the running attempt's
    /// drop-guard, so a cancelled attempt can never leak a slot.
    hole_punch_inflight: HolePunchInflightMap,
    /// audit log for mutating admin commands. `None`
    /// when the on-disk file couldn't be opened (warned at startup);
    /// admin handlers fall back to no-op auditing in that case.
    pub admin_audit: Option<Arc<crate::admin_audit::AdminAuditLog>>,
}

/// Shared single-flight map for [`NodeServices::attempt_p2p_hole_punch`].
type HolePunchInflightMap = Arc<
    Mutex<
        std::collections::HashMap<
            [u8; 32],
            tokio::sync::broadcast::Sender<veil_ipc::HolePunchOutcome>,
        >,
    >,
>;

/// Failure stage of one initiator-side UDP hole-punch dial
/// (`udp_hole_punch_dial_stages`). Maps 1:1 onto the wire outcomes of
/// the explicit call-path API; the legacy auto-fallback path collapses
/// it back to `Option` and keeps its historical behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HolePunchDialFailure {
    /// NAT traversal disabled or no reflector endpoint sendable.
    NoReflector,
    /// Local socket/mapping unusable, or the peer offered no public
    /// srflx candidate.
    MappingUnusable,
    /// Coordinator candidate/token exchange did not complete.
    SignalingTimeout,
    /// Simultaneous punch never converged inside its deadline.
    PunchTimeout,
    /// Same-socket QUIC promotion failed or ran out of budget.
    QuicFailed,
}

impl From<HolePunchDialFailure> for veil_ipc::HolePunchOutcome {
    fn from(failure: HolePunchDialFailure) -> Self {
        match failure {
            HolePunchDialFailure::NoReflector => Self::NoReflector,
            HolePunchDialFailure::MappingUnusable => Self::MappingUnusable,
            HolePunchDialFailure::SignalingTimeout => Self::SignalingTimeout,
            HolePunchDialFailure::PunchTimeout => Self::PunchTimeout,
            HolePunchDialFailure::QuicFailed => Self::QuicFailed,
        }
    }
}

/// Drop-guard owned by the single in-flight `attempt_p2p_hole_punch`
/// runner for a peer: releases the single-flight slot and broadcasts the
/// outcome to every joiner, even if the running future is cancelled
/// (runtime shutdown) — joiners then observe `PunchTimeout` instead of a
/// closed channel and the slot can never leak.
struct HolePunchInflightGuard {
    map: HolePunchInflightMap,
    peer_node_id: [u8; 32],
    tx: tokio::sync::broadcast::Sender<veil_ipc::HolePunchOutcome>,
    outcome: Option<veil_ipc::HolePunchOutcome>,
}

impl Drop for HolePunchInflightGuard {
    fn drop(&mut self) {
        lock!(self.map).remove(&self.peer_node_id);
        let _ = self.tx.send(
            self.outcome
                .unwrap_or(veil_ipc::HolePunchOutcome::PunchTimeout),
        );
    }
}

impl Drop for NodeRuntime {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }
        // Break the cycle:
        //   dispatcher → rendezvous_weak → controller → binder
        //       → session_ctx → dispatcher
        // Clear the dispatcher's weak ref + drop our strong Arc so the
        // controller's drop chain runs cleanly.  Weak::upgrade() will
        // now return None in any in-flight dispatch task.
        if let Some(dispatcher_weak_lock) =
            self.dispatcher.rendezvous_weak.lock().ok().as_deref_mut()
        {
            *dispatcher_weak_lock = None;
        }
        if let Ok(mut controller_slot) = self.rendezvous_controller.lock() {
            *controller_slot = None;
        }
        let RuntimeTasks {
            listeners,
            peers,
            sessions,
            background,
        } = {
            let mut tasks = lock_tasks(&self.tasks);
            std::mem::take(&mut *tasks)
        };
        for handle in listeners
            .into_iter()
            .chain(peers)
            .chain(sessions)
            .chain(background)
        {
            handle.abort();
        }
    }
}

// ── supervised task spawn ───────────────────────────────────────────

/// Spawn a background task with panic recovery.
///
/// Wraps `fut` in `AssertUnwindSafe::catch_unwind` so a panic inside the
/// task is captured, logged [`NodeLogger`] as `task.panic`, and does not
/// silently take the task off the runtime with only a default-hook WARN.
///
/// The current caller is still responsible for pushing the returned
/// `JoinHandle` into the runtime's task-set so that graceful shutdown awaits it.
/// A spawned task that is aborted when this guard goes.
///
/// The shape a `tokio::spawn` inside a supervised task should have. Aborting
/// the supervisor does not touch what the supervisor itself spawned, so a
/// child that sleeps — a delayed self-check, a debounce — outlives the thing
/// that owned it, and a service that reloads quickly accumulates them
/// (report17 V17-L8). Holding the handle here ties the child's life to the
/// scope that created it, including every early return and abort, which is
/// what an explicit `.abort()` at the end of a loop misses.
///
/// `veil-ipc`'s server keeps its own copy of this for its read-half task;
/// they are not shared because `veil-util`, the crate both could import from,
/// deliberately does not depend on tokio.
pub(crate) struct AbortOnDrop(pub tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub fn supervised_spawn<F>(
    logger: Arc<NodeLogger>,
    task_name: &'static str,
    fut: F,
) -> tokio::task::JoinHandle<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    use futures::FutureExt;
    use std::panic::AssertUnwindSafe;
    tokio::spawn(async move {
        if let Err(panic) = AssertUnwindSafe(fut).catch_unwind().await {
            let msg = if let Some(s) = panic.downcast_ref::<&'static str>() {
                (*s).to_owned()
            } else if let Some(s) = panic.downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string panic payload>".to_owned()
            };
            logger.error("task.panic", format!("task={task_name} panic={msg}"));
        }
    })
}

// Phase 2 pre-work (veilcore extraction): moved to `veil_util`
// so session-side callers can reach it without cycling through runtime.  This
// shim preserves backwards compat for existing
// `crate::runtime::local_battery_level()` callsites.
pub use veil_util::local_battery_level;

// ── Private types for lock-free stop / reload ─────────────────────
//
// Admin commands Stop and Reload can hold `Arc<Mutex<NodeRuntime>>` for several
// seconds (200 ms graceful-shutdown sleep + spawn_blocking persist flushes).
// These context types let admin.rs release the outer lock before the async
// work, so concurrent commands (Sessions, Health, …) are not starved.

/// Arcs and config paths needed to run persist flushes without holding the
/// outer `Arc<Mutex<NodeRuntime>>`. Created synchronously while the lock is
/// held; passed to `do_stop_flushes` which runs after the lock is released.
pub struct StopFlushContext {
    pub cache_persist_path: Option<String>,
    pub rtt_persist_path: Option<String>,
    pub persist_enabled: bool,
    pub config_path: PathBuf,
    pub rtt_table: Arc<Mutex<RttTable>>,
    pub route_cache: Arc<RwLock<RouteCache>>,
    pub logger: Arc<NodeLogger>,
    pub dht: Arc<KademliaService>,
    pub autodiscovered_peers: Arc<veil_mesh::AutoDiscoveredPeers>,
    pub gateway_list: Arc<Mutex<veil_gateway::GatewayList>>,
    pub peer_pubkeys: veil_types::PeerPubkeysCache,
    pub local_vivaldi: Option<Arc<Mutex<veil_routing::VivaldiCoord>>>,
    pub discovered_peers_cache: Arc<Mutex<veil_bootstrap::DiscoveredPeerCache>>,
}

/// Data taken from `NodeRuntime` (including the `shutdown_tx` take) needed to
/// run the task-teardown phase without holding the outer lock. Created
/// synchronously while the lock is held; passed to `do_stop_tasks` which runs
/// after the lock is released.
pub struct StopTasksContext {
    pub session_tx_registry: Arc<RwLock<veil_session::SessionTxRegistry>>,
    pub shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
    pub pending_accepts: Arc<Mutex<AcceptWaiters>>,
    pub tasks: Arc<Mutex<RuntimeTasks>>,
    pub logger: Arc<NodeLogger>,
    /// Audit M7: the ephemeral-rotator shutdown senders, *drained* out of
    /// `NodeRuntime` so `do_stop_tasks` can actually signal them (the previous
    /// code only ever pushed into the list — the "sends `true` on each during
    /// graceful exit" was never implemented, and the Vec grew unbounded across
    /// reloads). Draining empties the source list so a subsequent reload
    /// re-populates it with the new rotators' senders rather than accumulating.
    pub ephemeral_rotator_shutdowns: Vec<tokio::sync::watch::Sender<bool>>,
}

/// Replicate `value` at `key` to the K closest peers in keyspace via a
/// fire-and-forget `RecursiveQuery(STORE)` fan-out (after a local store).
///
/// Advance a per-service onion registration-epoch counter to a value that is
/// BOTH `>= now` (tracks wall-clock) AND strictly greater than any value this
/// counter previously returned (monotonic). B2: R rejects a re-registration
/// whose epoch is not strictly increasing for the same `(cookie, reg_pk)`
/// (`StaleEpoch`), so two onion-service rebuilds in the same wall-clock second —
/// or under a clock that doesn't advance — must still produce increasing
/// epochs. Lock-free CAS; safe to call concurrently on the same counter.
fn next_monotonic_epoch(last_epoch: &std::sync::atomic::AtomicU64, now: u64) -> u64 {
    use std::sync::atomic::Ordering;
    let mut cur = last_epoch.load(Ordering::Acquire);
    loop {
        let next = now.max(cur.saturating_add(1));
        match last_epoch.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break next,
            Err(observed) => cur = observed,
        }
    }
}

/// Shared by [`NodeRuntime::dht_publish_replicated`] and the onion-service
/// descriptor publish on `NodeServices` (diff-audit L5): both need a SYNCHRONOUS
/// replicated store but live on different `impl`s. `send_to` is fire-and-forget;
/// peers without a direct session are skipped (the STORE recursive-forward path
/// handles those hops via greedy walk on receivers we DO have sessions to).
/// Returns the number of peers a frame was enqueued for.
fn dht_publish_replicated_via(
    dht: &KademliaService,
    session_tx_registry: &RwLock<veil_session::SessionTxRegistry>,
    local_node_id: [u8; 32],
    key: [u8; 32],
    value: Vec<u8>,
) -> usize {
    // Local first — always succeeds.
    dht.store_local(key, value.clone());

    // K-closest replicas: skip self. Use the routing table's keyspace ranking,
    // not the live-session set, so we hit the truly closest peers — STORE
    // forwards greedy if we don't have direct sessions to all of them.
    let candidates: Vec<[u8; 32]> = dht
        .find_closest_nodes(&key, veil_proto::budget::DHT_REPLICATION_K)
        .into_iter()
        .filter(|n| *n != local_node_id)
        .collect();
    if candidates.is_empty() {
        return 0;
    }

    // Build the RecursiveQuery(STORE) frame once, clone bytes per send.
    let query_id: [u8; 16] = {
        use rand_core::RngCore;
        let mut id = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut id);
        id
    };
    let q = veil_proto::routing::RecursiveQueryPayload {
        query_id,
        target_key: key,
        reply_to: local_node_id,
        ttl: 40,
        query_type: veil_proto::routing::recursive_query_type::STORE,
        reply_port: 0,
        payload: value,
    };
    let q_bytes = q.encode();
    let mut hdr = veil_proto::header::FrameHeader::new(
        veil_proto::family::FrameFamily::Routing as u8,
        veil_proto::family::RoutingMsg::RecursiveQuery as u16,
    );
    hdr.body_len = q_bytes.len() as u32;
    let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
    frame.extend_from_slice(&q_bytes);

    let mut sent = 0usize;
    let guard = rlock!(session_tx_registry);
    for peer in candidates {
        if guard.send_to(
            &peer,
            veil_proto::header::priority::INTERACTIVE,
            frame.clone(),
        ) {
            sent += 1;
        }
    }
    sent
}

impl NodeRuntime {
    /// The address this node RECEIVES under: mailbox drops, rendezvous ads,
    /// the cookie that ties the two together.
    ///
    /// Not the same question as "who is this node on the wire". The handshake
    /// identity is the `[identity]` keypair and must stay that way — it is what
    /// a peer authenticates against. But a sender seals mail to an IDENTITY,
    /// walking node_id → document → registry → per-device certs, and an
    /// identity with several devices has one address for all of them.
    ///
    /// Today the two coincide for every node in the field: a mined identity is
    /// its own master, and a phrase-provisioned one derives the config key from
    /// the same master the document names, so `BLAKE3(master_pk)` IS the config
    /// node_id. They diverge only once a device is given a transport key of its
    /// own — and at that moment a device that kept receiving under its transport
    /// id would be waiting at an address nobody sends to, while remaining
    /// perfectly reachable-looking from every angle.
    ///
    /// CHANGING THIS MEANS CHANGING BOTH SIDES. The receiver cookie is derived
    /// from this id and must stay bit-for-bit identical to the app-side
    /// publisher's (`MailboxService._deriveCookie`); a mismatch had the two
    /// advertising the same relay under different cookies, and the relay
    /// dropped every introduce as `cookie_unknown` with delivery failing in
    /// silence.
    fn receiver_node_id(&self) -> [u8; 32] {
        match self.identity.sovereign_identity.get() {
            Some(sov) => *sov.node_id(),
            None => *self.identity.local_identity.node_id.as_bytes(),
        }
    }

    pub async fn start(config_path: impl AsRef<Path>, foreground_mode: bool) -> Result<Self> {
        let config_path = config_path.as_ref().to_path_buf();
        let config = veil_cfg::load_config(&config_path)?;

        // Fail fast if the config has structural or identity issues. Under the
        // production-hardening profile (`[global].strict_config_validation`),
        // also treat the risky-but-permitted advisories (push wake-HMAC, mailbox
        // capability tokens, unsigned DHT store, …) as fatal so the daemon
        // refuses to start on an unsafe production posture.
        let validation = if config.global.strict_config_validation {
            veil_cfg::validate_strict(&config)
        } else {
            veil_cfg::validate(&config)
        };
        if !validation.is_valid() {
            return Err(NodeError::Config(veil_cfg::ConfigError::ValidationFailed(
                validation.format_issues(),
            )));
        }

        let logger = Arc::new(veil_cfg::observability_glue::logger_from_config(&config)?);

        #[cfg(windows)]
        if let Err(error) = veil_util::outbound_interface::pin_current_default_interfaces() {
            logger.warn(
                "network.outbound_interface_pin_failed",
                format!("error={error}"),
            );
        }

        // Pin the process address space in RAM against swap-out before
        // loading any key material. `mlockall(MCL_CURRENT | MCL_FUTURE)`
        // covers ALL future allocations, including key bytes inside
        // upstream crates (chacha20poly1305 internal GenericArray,
        // ed25519_dalek SigningKey seed) that cannot be reached with
        // per-buffer wrappers. Linux only; macOS / Windows / *BSD log
        // as "unsupported" and continue with swap risk accepted.
        //
        // Failure path: log a warn but DO NOT refuse to start. Cheap
        // VPS deployments may run without `LimitMEMLOCK=infinity`; refusing
        // to boot would break those deployments. Operators raising
        // sustained-load servers should set `ulimit -l unlimited` (or
        // `LimitMEMLOCK=infinity` in systemd unit) and check the log line
        // confirms `Locked`.
        match veil_util::mlock::try_mlockall_current_future() {
            veil_util::mlock::MlockallOutcome::Locked => {
                logger.info(
                    "node.mlock.success",
                    "process address space pinned in RAM (swap protection active)",
                );
            }
            veil_util::mlock::MlockallOutcome::Unsupported => {
                logger.info(
                    "node.mlock.unsupported",
                    "mlockall not supported on this platform; key material may swap to disk",
                );
            }
            veil_util::mlock::MlockallOutcome::BudgetExhausted { errno_str } => {
                logger.warn(
                    "node.mlock.budget_exhausted",
                    format!(
                        "mlockall failed ({errno_str}): RLIMIT_MEMLOCK too low. \
                         Set `LimitMEMLOCK=infinity` in systemd unit OR `ulimit -l unlimited`. \
                         Key material remains swappable until raised."
                    ),
                );
            }
            veil_util::mlock::MlockallOutcome::PermissionDenied => {
                logger.warn(
                    "node.mlock.permission_denied",
                    "mlockall denied (missing CAP_IPC_LOCK in container?). \
                     Key material remains swappable.",
                );
            }
            veil_util::mlock::MlockallOutcome::Other(msg) => {
                logger.warn(
                    "node.mlock.unexpected_error",
                    format!("mlockall failed: {msg}. Key material remains swappable."),
                );
            }
        }

        let transport_ctx = Arc::new(veil_cfg::transport_glue::context_from_config(&config)?);
        let local_identity = Arc::new(HandshakeIdentity::from_config(&config)?);

        // veil_dir is home to the identity files (`device_identity_sk.bin`,
        // `mlkem.key`) read by the sovereign load and the ML-KEM key resolution.
        // The ML-KEM keypair is resolved AFTER the sovereign auto-load below
        // (not here), because its identity-derived path needs
        // `device_identity_sk.bin`, which the standalone-identity build writes
        // during that auto-load.
        //
        // Normally the config file's own directory. `[global] identity_dir`
        // overrides it, and an EMBEDDED host has to use that: deferred init
        // stages the config in a per-boot temp directory this crate creates and
        // scrubs, so a host that provisions an identity of its own has nowhere
        // to put it and would silently get the degenerate document instead.
        let veil_dir_path = config.identity_dir_for(&config_path);

        // sovereign-identity auto-load. Three paths:
        //
        // 1. `identity_document.bin` exists on disk → load it. Multi-device
        // identity provisioned via `identity create` / `pair-accept` /
        // `restore` lives here.
        //
        // 2. No `identity_document.bin` but the `[identity]` config block
        // has an Ed25519 keypair AND no master keypair has been
        // provisioned → build a degenerate "standalone" document
        // where master_pk == device_pk, persist it to disk, then
        // treat it like any other `IdentityDocument`. This is the
        // default UX for single-device users; the rest of the runtime
        // sees a normal document and doesn't branch on standalone-ness.
        //
        // 3. Falcon-512 nodes (or anything else without an Ed25519
        // `local_signing_key`) fall through to legacy `None` mode —
        // same behaviour as before this commit.
        let sovereign_identity: Option<Arc<veil_identity::sovereign::SovereignIdentity>> = {
            let doc_path = veil_dir_path.join(veil_identity::sovereign::IDENTITY_DOCUMENT_FILE);
            if doc_path.exists() {
                match veil_identity::sovereign::SovereignIdentity::load_from_dir(&veil_dir_path) {
                    Ok(sov) => {
                        logger.info(
                            "node.sovereign_identity.loaded",
                            format!(
                                "node_id={} instance_id={}",
                                veil_util::bytes_to_hex(sov.node_id()),
                                veil_util::bytes_to_hex(&sov.active_instance_id()),
                            ),
                        );
                        Some(Arc::new(sov))
                    }
                    Err(e) if config.global.allow_identity_fallback => {
                        // Explicitly permitted: the operator asked for a node
                        // that comes up even with a broken document, e.g. to
                        // reach `veil-cli identity restore` on a host they
                        // cannot otherwise log into.
                        logger.warn(
                            "node.sovereign_identity.load_failed",
                            format!(
                                "{e} — running as legacy node_id-keyed \
                                 (allow_identity_fallback = true)"
                            ),
                        );
                        None
                    }
                    Err(e) => {
                        // Fail closed. A MISSING document is ordinary and still
                        // starts the node as legacy — that path is untouched.
                        // A document that exists and does not load is a
                        // different thing: the operator provisioned an
                        // identity, it is on disk, and it is broken.
                        //
                        // Continuing ran the node under a DIFFERENT identity
                        // binding than the one its operator installed — peers
                        // see an unrelated legacy node, multi-device pairing
                        // does not apply, and one warning line was the only
                        // trace of the downgrade (audit V-07).
                        logger.error(
                            "node.sovereign_identity.load_failed",
                            format!("{e} — refusing to start as a legacy node"),
                        );
                        return Err(NodeError::Config(veil_cfg::ConfigError::ValidationFailed(
                            format!(
                                "sovereign identity at {} exists but cannot be \
                             loaded: {e}. Re-provision with `veil-cli identity \
                             create`/`restore`, or set \
                             [global].allow_identity_fallback = true to start \
                             as an unrelated legacy node on purpose.",
                                doc_path.display()
                            ),
                        )));
                    }
                }
            } else if config.ephemeral_identity {
                // The deferred boot's `[identity]` is a compiled-in constant.
                // Building a standalone sovereign out of it would write that
                // constant to `device_identity_sk.bin` — and the ML-KEM and
                // X25519 resolves immediately below read exactly that file, so
                // the node's receive keys would be a pure function of a value
                // published in the source tree. Worse, the onion auth-cookie
                // and registration key derive from the same seed, so EVERY
                // deferred node would register at a relay under one shared,
                // world-known cookie.
                //
                // So: no sovereign here. Both key resolves below fall through
                // to their in-memory random branch, and the real identity — the
                // one that arrives with `apply_config` — is what
                // `apply_reload_after_stop` derives from.
                logger.info(
                    "node.sovereign_identity.deferred_skipped",
                    "deferred boot: no sovereign identity built from the placeholder \
                     [identity] — real keys are derived when the identity is applied",
                );
                None
            } else {
                // no document on disk — try the standalone
                // branch. We need an Ed25519 device SK; the config's
                // `[identity]` block carries one for normal nodes.
                build_standalone_sovereign_identity(&veil_dir_path, &config, &logger)
            }
        };

        // ML-KEM-768 mailbox keypair — resolved HERE, after the sovereign
        // auto-load, because the IDENTITY-DERIVED path (the stable-key fix) reads
        // `device_identity_sk.bin`, which the standalone-identity build writes
        // during that auto-load. Resolving it before the load silently fell back
        // to a random per-launch key (the reverse store-and-forward black-hole:
        // a peer's blob sealed to last launch's published EK could not be opened
        // after a restart). An existing persisted `mlkem.key` still wins
        // (operator/seed nodes never rotate); a node with no identity seed
        // (Falcon, or sovereign load failed) falls back to random+persist.
        let mlkem_key_path = veil_dir_path.join("mlkem.key");
        // Passphrase cascade: prompt > env > file > inline. Zeroizing<String>
        // wipes the heap contents when it drops just below.
        let key_passphrase = crate::key_passphrase::resolve_key_passphrase(&config, &logger)?;
        let mlkem_epoch = crate::identity_local::mlkem_dk::rotation_epoch(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            config.global.mlkem_rotation_secs,
        );
        let mlkem_key = crate::identity_local::mlkem_dk::load_or_derive(
            &mlkem_key_path,
            &veil_dir_path,
            key_passphrase.as_deref().map(|p| p.as_str()),
            mlkem_epoch,
            config.ephemeral_identity,
        )?;
        let (mlkem_ek_arr, mlkem_dk_arr) = (mlkem_key.ek, mlkem_key.dk_seed);
        logger.info(
            "node.mlkem_dk.source",
            format!("mlkem dk_seed source={}", mlkem_key.source.as_str()),
        );
        // The key is usable either way, so this is a warning and not a refusal
        // to start — a node down because its config directory is read-only is
        // worse than a node up with a posture problem it has just named. What
        // it must not be is silent: the loader used to discard this error
        // entirely, so an operator who had just turned on a passphrase got a
        // node that started, worked, and kept the seed in plaintext with
        // nothing anywhere saying so (audit report7 V-02).
        if let veil_e2e::MlKemKeyAtRest::PlaintextUpgradeFailed { reason } = &mlkem_key.at_rest {
            logger.warn(
                "node.mlkem_dk.at_rest",
                format!(
                    "a passphrase is configured but {} could NOT be re-encrypted \
                     ({reason}) — the ML-KEM decapsulation seed is still stored in \
                     PLAINTEXT. The node is running on the correct key; fix the \
                     path and restart to complete the upgrade.",
                    mlkem_key_path.display(),
                ),
            );
        }
        let mlkem_key_at_rest = mlkem_key.at_rest.clone();
        drop(key_passphrase);
        // One holder for the keypair, from here down. The seed inside is
        // mlock-pinned (or zeroize-on-drop); the source arrays drop at the end
        // of this statement. The ring starts at the epoch currently in force,
        // not at 0, so a restart resumes the key this node was already
        // publishing; `spawn_mlkem_rotation_task` moves it on from there.
        let mlkem_keys = Arc::new(veil_e2e::MlKemSeedRing::new(
            mlkem_epoch,
            mlkem_dk_arr,
            mlkem_ek_arr,
        ));

        // d removed the persistent RevocationCache; document
        // freshness now relies on `valid_until_unix` alone.

        // shared transport-hint registry — IPC clients query it
        // via `TransportHintQuery` to find which schemes work from this node.
        let hint_registry = Arc::new(veil_transport::hint_registry::TransportHintRegistry::new());
        let registry = Arc::new(
            TransportRegistry::with_defaults().with_hint_registry(
                Arc::clone(&hint_registry) as Arc<dyn veil_transport::TransportHintSink>
            ),
        );
        let started_at = Instant::now();
        let metrics = veil_cfg::observability_glue::metrics_from_config(&config)
            .map(|(metrics, _)| Arc::new(metrics));
        if let Some(metrics) = &metrics {
            metrics.set_configured_peers(config.peers.len());
        }
        let role = config
            .identity
            .as_ref()
            .map(|id| id.role)
            .unwrap_or_default();
        let state = Arc::new(Mutex::new(build_state(
            &config,
            config_path.clone(),
            foreground_mode,
            started_at,
            config.metrics.is_some(),
            None,
        )?));
        // Recorded, not merely logged: whether the key is actually encrypted at
        // rest is a standing property of this node, and a warning scrolled past
        // at startup leaves an operator no way to ask about it later.
        lock_state(&state).mlkem_key_at_rest = mlkem_key_at_rest;

        let local_node_id = *local_identity.node_id.as_bytes();
        let mesh_realm = Self::init_mesh_realm(&config).await;
        // load signing key early so discovery records can be
        // self-authenticating (signed) for cross-DHT replication.
        let local_signing_key = load_signing_key(&config);
        // Falcon-512 identity material for signed V2 records on
        // post-quantum nodes. `None` on Ed25519 nodes — only one algo active
        // at a time.
        let local_falcon_signer = load_falcon_signer(&config);
        let gateway = Arc::new(GatewayService::new_with_lease_ttl(
            role,
            std::time::Duration::from_secs(config.gateway.attachment_lease_ttl_secs),
        ));
        let shared_rtt_table = Arc::new(Mutex::new(RttTable::new(std::time::Duration::from_secs(
            300,
        ))));
        // create Vivaldi arcs here so they can be shared with both DHT and dispatcher.
        let shared_vivaldi = Arc::new(Mutex::new(VivaldiCoord::new()));
        #[allow(clippy::type_complexity)]
        // p: pre-size to MAX_PEER_VIVALDI_CACHE (avoids rehash).
        let shared_peer_vivaldi: Arc<
            std::sync::RwLock<
                std::collections::HashMap<NodeIdBytes, (VivaldiCoord, std::time::Instant)>,
            >,
        > = Arc::new(std::sync::RwLock::new(
            std::collections::HashMap::with_capacity(veil_proto::budget::MAX_PEER_VIVALDI_CACHE),
        ));
        // P-Net Phase 3b: build the auth gate BEFORE the DHT so that
        // STOREs carrying the `PBAN` magic prefix can be verified at
        // ingest time. Public-mode nodes (or nodes with no `[network]`
        // block) leave `network_gate_arc` = None; the DHT path treats
        // that as "reject all PBAN STOREs".
        let network_gate_arc: Option<Arc<veil_identity::network_access::NetworkAccessGate>> =
            if let Some(ref net_cfg) = config.network {
                match veil_identity::network_access::NetworkAccessGate::from_config(net_cfg) {
                    Ok(Some(gate)) => {
                        logger.info(
                            "network.private_mode",
                            format!(
                                "loaded membership cert for network_id={}",
                                net_cfg.network_id.as_deref().unwrap_or("<unset>"),
                            ),
                        );
                        Some(Arc::new(gate))
                    }
                    Ok(None) => None,
                    Err(e) => {
                        return Err(crate::error::NodeError::Config(
                            veil_cfg::ConfigError::ValidationFailed(format!(
                                "[network] gate load failed: {e}"
                            )),
                        ));
                    }
                }
            } else {
                None
            };
        let dht = {
            let mut dht_cfg = config.dht.clone();
            if role == veil_cfg::NodeRole::Core && dht_cfg.k == veil_cfg::DhtConfig::default().k {
                dht_cfg.k = 40;
            }
            let mut svc = KademliaService::with_config(
                local_node_id,
                crate::dht_glue::runtime_config_from(&dht_cfg),
            );
            if role == veil_cfg::NodeRole::Core {
                svc.set_sketch_threshold(128);
            }
            svc.set_rtt_table(Arc::new(crate::dht_glue::RttHintAdapter::new(Arc::clone(
                &shared_rtt_table,
            ))));
            svc.set_coord_oracle(Arc::new(crate::dht_glue::VivaldiOracle::new(
                Arc::clone(&shared_vivaldi),
                Arc::clone(&shared_peer_vivaldi),
            )));
            if let Some(m) = &metrics {
                svc.set_metrics(Arc::clone(m) as Arc<dyn veil_dht::DhtMetrics>);
            }
            if let Some(ref gate) = network_gate_arc {
                svc.set_network_auth_gate(Arc::clone(gate) as Arc<dyn veil_dht::NetworkAuthGate>);
            }
            Arc::new(svc)
        };
        // + backlog re-mint: configure our
        // self-signed transport announcement source. Pre-condition:
        // we have an Ed25519 signing key AND at least one advertised
        // transport. Pure outbound nodes (no listen entries) skip
        // this step — they'll still verify peers' announcements but
        // cannot be `ResolveTransport`'d.
        //
        // Storing (signing_key, transport) pair lets the
        // maintenance tick re-mint the bundle at half-validity, so
        // long-running peers don't go silent ~30 days after startup.
        if let Some(ref sk) = local_signing_key {
            let advertised = build_advertised_transports(&config);
            if let Some(transport) = advertised.into_iter().next() {
                dht.configure_local_announcement_source(Arc::clone(sk), transport);
            }
        }
        // DiscoveryService is created AFTER the DHT so it can
        // publish signed records into it; AppEndpointRegistry's auto_publish
        // then flows through the same DHT-wired DiscoveryService.
        let discovery = {
            let mut svc = DiscoveryService::new(role).with_dht(Arc::clone(&dht));
            if let Some(ref sk) = local_signing_key {
                svc = svc.with_signing_key(Arc::clone(sk));
            }
            if let Some(ref fs) = local_falcon_signer {
                svc = svc.with_falcon_signer(Arc::clone(fs));
            }
            Arc::new(svc)
        };
        let app_registry = Arc::new({
            let r = AppEndpointRegistry::new().with_auto_publish(
                local_node_id,
                Arc::clone(&discovery),
                300,
            );
            if let Some(m) = &metrics {
                r.with_metrics(Arc::clone(m) as Arc<dyn veil_app::AppMetrics>)
            } else {
                r
            }
        });
        let mesh_forwarder = Arc::new(MeshForwarder::new(
            local_node_id,
            role,
            Arc::new(NeighborTable::new()),
        ));
        let control_plane = Arc::new(
            veil_routing::control_plane::ControlPlaneService::with_rtt_table(Arc::clone(
                &shared_rtt_table,
            )),
        );
        let route_cache = Arc::new(RwLock::new(RouteCache::new(
            std::time::Duration::from_secs(config.routing.route_cache_ttl_secs),
        )));
        // b: per-peer byte-rate enforcement. Chained
        // ONLY when operator opted in via `abuse.per_peer_bytes_per_sec`
        // — preserves backwards-compat "no enforcement" default.
        let rate_limiter = {
            let mut limiter = PerPeerLimiter::new(
                config.abuse.rate_limit_fps,
                config.abuse.rate_limit_burst,
                std::time::Duration::from_secs(300),
            );
            if let Some(rate) = config.abuse.per_peer_bytes_per_sec
                && let Some(burst) = config.abuse.resolved_per_peer_byte_burst()
            {
                limiter = limiter.with_byte_rate(rate as f64, burst as f64);
            }
            Arc::new(Mutex::new(limiter))
        };
        let ban_list = Arc::new(Mutex::new(BanList::new()));
        persistence::load_bans(&ban_list, &config_path);
        let violation_tracker = Arc::new(Mutex::new(
            // `.max(1)` makes the threshold provably ≥ 1, which is the
            // only failure precondition of `ViolationTracker::new`
            // (`Err("ban_threshold must be > 0")`). `.expect` is
            // therefore unreachable; keep it as a tripwire so a future
            // refactor that removes the clamp surfaces here, not at
            // runtime.
            ViolationTracker::new(
                config.abuse.ban_threshold.max(1),
                std::time::Duration::from_secs(config.abuse.ban_initial_secs),
                std::time::Duration::from_secs(config.abuse.ban_step_secs),
                std::time::Duration::from_secs(config.abuse.ban_max_secs),
                std::time::Duration::from_secs(600),
            )
            .expect("ban_threshold clamped to >= 1 — invariant in this call site"),
        ));
        // p: pre-size all peer-cache HashMaps to their caps
        // so that inserts up to the cap do not trigger `reserve_rehash`
        // transient allocations. jeprof callgraph showed
        // ~49 MiB of jemalloc dirty pages pinned by these rehash events
        // on bootstrap'e under chaos-ban peer churn. Pre-allocation costs
        // ~80 KiB total upfront in exchange for a flat allocator footprint.
        let peer_pubkeys: veil_types::PeerPubkeysCache = Arc::new(Mutex::new(
            veil_types::PeerLruCache::with_capacity(veil_proto::budget::MAX_PEER_PUBKEYS_CACHE),
        ));
        // persistent peer → sovereign identity binding
        // cache. Lives on the runtime so it survives `reload_with`
        // (the session_registry is wiped on reload but this map
        // is kept). Lets the resumption fast path restore the
        // peer's `ValidatedIdentity` even though the handshake
        // skipped the `IdentityProof` exchange.
        let peer_sovereign_identities: crate::runtime::identity_state::PeerSovereignBindings =
            Arc::new(Mutex::new(std::collections::HashMap::with_capacity(
                veil_proto::budget::MAX_PEER_SOVEREIGN_IDENTITIES,
            )));
        let peer_roles: Arc<Mutex<veil_types::PeerLruCache<u8>>> = Arc::new(Mutex::new(
            veil_types::PeerLruCache::with_capacity(veil_proto::budget::MAX_PEER_PUBKEYS_CACHE),
        ));
        // maps peer_id → flags bitmask from CapabilitiesPayload (CAN_RELAY etc.)
        let peer_cap_flags: Arc<std::sync::RwLock<std::collections::HashMap<NodeIdBytes, u8>>> =
            Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::with_capacity(
                    veil_proto::budget::MAX_PEER_PUBKEYS_CACHE,
                ),
            ));
        let shared_peer_mlkem_keys: Arc<std::sync::RwLock<veil_e2e::PeerMlKemCache>> =
            Arc::new(std::sync::RwLock::new(
                veil_e2e::PeerMlKemCache::with_capacity(veil_proto::budget::MAX_PEER_MLKEM_CACHE),
            ));
        // Verified-cert fast-path cache, shared by the live-E2E + offline-seal
        // ML-KEM resolvers so one DHT walk serves both (kills per-seal walks).
        let shared_peer_mlkem_certs: Arc<
            std::sync::RwLock<crate::mlkem_resolver::PeerMlKemCertCache>,
        > = Arc::new(std::sync::RwLock::new(
            crate::mlkem_resolver::PeerMlKemCertCache::with_capacity(
                veil_proto::budget::MAX_PEER_MLKEM_CACHE,
            ),
        ));
        // The same certificates on disk. Built here beside the RAM cache it
        // backs, and from `config_path` because that is where every other
        // learned-state snapshot this runtime keeps already lives
        // (`peers_discovered.json`, `bans.json`).
        let shared_peer_mlkem_cert_store = Arc::new(crate::mlkem_cert_store::MlKemCertStore::load(
            &config_path,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        ));
        // The device Diffie-Hellman half of the same certificates, kept apart
        // so the frame dispatcher can read it: the dispatcher decides sender
        // provenance synchronously and cannot reach this crate's cert type.
        let shared_peer_ratchet_keys: Arc<std::sync::RwLock<veil_e2e::PeerRatchetKeyCache>> =
            Arc::new(std::sync::RwLock::new(
                veil_e2e::PeerRatchetKeyCache::with_capacity(
                    veil_proto::budget::MAX_PEER_MLKEM_CACHE,
                ),
            ));
        // Built here rather than beside `IdentityState` below, because the
        // frame dispatcher is constructed first and needs the same cell: the
        // ratchet's two ends are a send path in veil-ipc and a receive path in
        // veil-dispatcher, and a conversation only works if both agree which
        // of our devices they are speaking as.
        let sovereign_cell = identity_state::SovereignIdentityCell::new(sovereign_identity.clone());
        // One-to-one ratchet conversations. Empty at start: the state is the
        // host's, and xVeil restores it over the FFI before traffic flows.
        let ratchet_runtime = veil_e2e::RatchetRuntime {
            store: Arc::new(veil_e2e::RatchetStore::new()),
            seed_ring: Arc::new(RwLock::new(Arc::clone(&mlkem_keys))),
            local_node_id: Arc::new(RwLock::new(local_node_id)),
            local_instance_id: sovereign_cell.active_instance_handle(),
            peer_ratchet_keys: Arc::clone(&shared_peer_ratchet_keys),
        };
        // per-session ephemeral ML-KEM DK seeds (key = peer_id, value =
        // SensitiveBytesN<64>-wrapped dk_seed).  Phase 6 slice 6h —
        // values are mlocked while the session is open.
        let shared_per_session_mlkem_dk: Arc<
            Mutex<
                std::collections::HashMap<
                    NodeIdBytes,
                    veil_util::sensitive_bytes::SensitiveBytesN<{ veil_e2e::DK_SEED_BYTES }>,
                >,
            >,
        > = Arc::new(Mutex::new(std::collections::HashMap::with_capacity(
            veil_proto::budget::MAX_PER_SESSION_MLKEM_DK,
        )));
        let shared_pending_diag: Arc<
            Mutex<
                std::collections::HashMap<
                    u32,
                    tokio::sync::mpsc::Sender<veil_dispatcher::DiagEvent>,
                >,
            >,
        > = Arc::new(Mutex::new(std::collections::HashMap::new()));
        // PEX event channel (dispatcher → initiator).
        let (pex_event_tx, pex_event_rx) = tokio::sync::mpsc::channel::<veil_pex::PexEvent>(64);
        // PEX connect channel (initiator → runtime outbound connector).
        let (pex_connect_tx, pex_connect_rx) =
            tokio::sync::mpsc::channel::<Vec<veil_proto::pex::PexPeer>>(16);
        // shared PEX state (dispatcher + initiator + runtime).
        let shared_pex_state: Arc<Mutex<veil_pex::PexState>> =
            Arc::new(Mutex::new(veil_pex::PexState::new()));
        // shared session registry for sovereign routing.
        // Built here so both `FrameDispatcher` (read side) and the
        // `NodeRuntime` struct literal (write side, populated by the
        // handshake) hold the same `Arc` — no double init.
        let shared_session_registry = Arc::new(Mutex::new(veil_session::SessionRegistry::new()));

        // one-shot sovereign-identity publish at startup.
        // When this node was provisioned with an IdentityDocument
        // publish it — plus its single-entry `InstanceRegistry` —
        // to the local DHT shard so peers walking the DHT keyspace
        // can retrieve the signed records without going through the
        // legacy node_id-keyed path. Scheduled periodic republish
        // (every 6h) + on-change republish (rotate/revoke) are the
        // remaining plumbing steps — this one-shot covers the common
        // case of a freshly-started node being immediately queryable.
        // Runs before any outbound session so the first handshake
        // that triggers a resolver query finds the document.
        if let Some(ref sov) = sovereign_identity {
            // Also re-run whenever the identity in force CHANGES — see
            // [`identity_publish`] for the promotion that used to leave the
            // DHT holding a placeholder's records.
            crate::runtime::identity_publish::publish_sovereign_identity(
                sov,
                &dht,
                &mlkem_keys,
                &veil_dir_path,
                // No peers yet at boot — this one is local-only by design.
                None,
                &logger,
            )
            .await;
        }
        let shared_session_tx_registry = Arc::new(RwLock::new(if let Some(m) = &metrics {
            veil_session::SessionTxRegistry::with_capacity_and_drop_counter(
                config.session.tx_queue_depth,
                m.session_tx_drops_counter(),
            )
        } else {
            veil_session::SessionTxRegistry::with_capacity(config.session.tx_queue_depth)
        }));
        // create congestion monitor once; shared with dispatcher and runtime.
        let shared_congestion_monitor = Arc::new(veil_congestion::CongestionMonitor::new(
            config.capacity.clone(),
            config.session.tx_queue_depth,
        ));
        // shared reputation tracker for transit gate.
        let shared_reputation: Arc<Mutex<veil_reputation::ReputationTracker>> =
            Arc::new(Mutex::new(veil_reputation::ReputationTracker::new()));
        let session_outbox = if let Some(m) = &metrics {
            veil_session::SessionOutbox::with_capacity_and_drop_counter(
                config.session.outbox_depth,
                m.session_outbox_drops_counter(),
            )
        } else {
            veil_session::SessionOutbox::with_capacity(config.session.outbox_depth)
        };
        // `local_signing_key` already computed earlier (above `discovery`).
        let listen_transports =
            Arc::new(std::sync::RwLock::new(build_advertised_transports(&config)));
        let shared_route_seen_set = Arc::new(Mutex::new(veil_dispatcher::RouteSeenSet::new(
            std::time::Duration::from_secs(config.routing.route_seen_window_secs),
            config.routing.route_seen_capacity,
        )));
        let shared_announce_seq = Arc::new(AtomicU32::new(0));
        let shared_route_updated = Arc::new(tokio::sync::Notify::new());
        let shared_neighbor_scorer = Arc::new(Mutex::new(NeighborScorer::with_alphas(0.5, 0.1)));
        // shared gateway list (same Arc used by runtime and dispatcher).
        let shared_gateway_list: Arc<Mutex<veil_gateway::GatewayList>> = Arc::new(Mutex::new(
            veil_gateway::GatewayList::new(config.connection.prefer_internet_gateway),
        ));
        // veil proxy stream routing tables (shared with VeilConnector).
        use veil_proxy::veil_connector::{PendingReceiptMap, VeilStreamRxMap};
        let shared_pending_stream_receipts: PendingReceiptMap =
            Arc::new(Mutex::new(std::collections::HashMap::new()));
        let shared_veil_stream_rx: VeilStreamRxMap =
            Arc::new(Mutex::new(std::collections::HashMap::new()));
        // 482.7: anonymity X25519 SK shared between
        // NodeRuntime (which the relay-directory publish task reads
        // via `anonymity_x25519_sk` field) and the dispatcher's
        // RelayChain handler (which peels inbound onion cells).
        // Constructed once, ARC-cloned to both consumers. Only
        // populated when the operator opted in to being a relay —
        // None signals "anonymity disabled, drop RelayChain frames".
        //
        //.4 P0: persisted to disk under
        // `<veil_dir>/device_anonymity_x25519_sk.bin` so push-
        // envelopes sealed by apps survive relay restart. Before T1.4
        // the key was `random_from_rng` on every startup, silently
        // invalidating every sealed envelope already registered with
        // this relay's rendezvous publisher.
        // Generated when the node either RELAYS others' circuits
        // (`relay_capable`) or RECEIVES authenticated anonymous messages
        // (`receive_anonymous`) — both need the key (relaying peels cells;
        // receiving unseals forwarded introduces). The two roles are gated
        // separately downstream: the dispatcher's onion Forward arm + the
        // rendezvous registry stay on `relay_capable`, so a receive-only node
        // never carries others' circuits.
        let anonymity_x25519_sk_for_dispatcher: Option<Arc<x25519_dalek::StaticSecret>> =
            if config.anonymity.relay_capable
                || config.anonymity.receive_anonymous
                || config.anonymity.onion_service
            {
                // Prefer an existing persisted key (long-lived nodes never
                // rotate); else DERIVE deterministically from the identity seed
                // so ephemeral-runtime-dir nodes (xVeil clients recreate
                // veil_dir every session) stop minting a fresh random key each
                // launch — the churned pubkey silently black-holed delivery to
                // peers holding an older ad (anonymity.relay_chain.forward
                // .decrypt_failed). See anonymity_x25519::load_or_derive.
                let (sk, src) = crate::identity_local::anonymity_x25519::load_or_derive(
                    &veil_dir_path,
                    sovereign_identity.is_some(),
                    config.ephemeral_identity,
                )?;
                logger.info(
                    "node.anonymity_x25519.source",
                    format!("anonymity x25519 key source={}", src.as_str()),
                );
                Some(Arc::new(sk))
            } else {
                None
            };

        // One-shot relay-key publish at startup. If this node has an anonymity
        // X25519 key (relay_capable / receive_anonymous / onion_service), publish
        // a signed `RelayKeyRecord` so peers can resolve its relay X25519 by
        // node_id alone (e.g. to advertise it as an always-on mailbox host). The
        // 6h republish task refreshes it; this one-shot makes it resolvable
        // immediately, mirroring the identity/registry/mlkem one-shots above.
        if let (Some(sov), Some(relay_sk)) =
            (&sovereign_identity, &anonymity_x25519_sk_for_dispatcher)
        {
            let relay_pk = x25519_dalek::PublicKey::from(relay_sk.as_ref()).to_bytes();
            let publisher =
                crate::identity_local::publisher_dht::DhtBackedPublisher::new(Arc::clone(&dht));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            match sov.sign_relay_key(relay_pk.to_vec(), now, now + 30 * 86_400, 1) {
                Ok(rec) => {
                    match veil_identity::publish::publish_relay_key(&rec, &publisher).await {
                        Ok(()) => logger.info(
                            "node.sovereign_identity.relay_key_published",
                            format!(
                                "node_id={} relay_x25519 advertised",
                                veil_util::bytes_to_hex(sov.node_id()),
                            ),
                        ),
                        Err(e) => logger.warn(
                            "node.sovereign_identity.relay_key_publish_failed",
                            format!(
                                "node_id={} — relay-key DHT publish failed: {e}",
                                veil_util::bytes_to_hex(sov.node_id()),
                            ),
                        ),
                    }
                }
                Err(e) => logger.warn(
                    "node.sovereign_identity.relay_key_sign_failed",
                    format!(
                        "node_id={} — relay-key signing failed: {e}",
                        veil_util::bytes_to_hex(sov.node_id()),
                    ),
                ),
            }
        }
        //.4 P2: open mailbox if operator
        // opted in. Storage lives at `<veil_dir>/mailbox/blobs.db`
        // (redb). Zero-valued config fields fall through to crate
        // defaults.
        //.4 P4: always-on sender-side outbox
        // for peer-sync. Cheap (idle DB until first put) and decoupled
        // from `mailbox.enabled` — every node sends, so every node
        // benefits from peer-sync retransmits when contacts come back
        // online. Failure to open is non-fatal: outbox stays None and
        // the peer-sync IPC handlers respond with graceful "feature off".
        let outbox_handle: Option<Arc<veil_mailbox::Outbox>> =
            match veil_mailbox::Outbox::open(&veil_dir_path, veil_mailbox::OutboxConfig::default())
            {
                Ok(o) => Some(Arc::new(o)),
                Err(e) => {
                    log::warn!("veil-mailbox: outbox open failed (peer-sync disabled): {e}");
                    None
                }
            };

        let mailbox_handle: Option<Arc<veil_mailbox::Mailbox>> = if config.mailbox.enabled {
            let mb_cfg =
                build_mailbox_runtime_config(&config.mailbox, *local_identity.node_id.as_bytes());
            let mb = veil_mailbox::Mailbox::open(&veil_dir_path, mb_cfg).map_err(|e| {
                crate::error::NodeError::Io(std::io::Error::other(format!(
                    "mailbox open failed: {e}"
                )))
            })?;
            Some(Arc::new(mb))
        } else {
            None
        };
        let dispatcher = Arc::new(FrameDispatcher {
            role,
            gateway: Arc::clone(&gateway),
            discovery: Arc::clone(&discovery),
            dht: Arc::clone(&dht),
            app_registry: Arc::clone(&app_registry),
            stream_table: Arc::new(veil_app::AppStreamTable::new()),
            mesh_forwarder: Arc::clone(&mesh_forwarder),
            chunk_reassembler: Arc::new(Mutex::new(
                veil_dispatcher::envelope_chunks::EnvelopeChunkReassembler::new(),
            )),
            discovery_forwarder: Arc::new(Mutex::new(
                veil_routing::discovery_forwarder::DiscoveryForwarder::with_default_difficulty(
                    local_node_id,
                    role,
                ),
            )),
            control_plane: Arc::clone(&control_plane),
            route_cache: Arc::clone(&route_cache),
            metrics: metrics.clone(),
            logger: Arc::clone(&logger),
            crypto: Arc::new(veil_dispatcher::CryptoContext {
                local_signing_key: local_signing_key.clone(),
                mlkem_keys: Arc::clone(&mlkem_keys),
                peer_mlkem_keys: Arc::clone(&shared_peer_mlkem_keys),
                peer_pubkeys: Arc::clone(&peer_pubkeys),
                peer_roles: Arc::clone(&peer_roles),
                peer_cap_flags: Arc::clone(&peer_cap_flags),
                per_session_mlkem_dk: Arc::clone(&shared_per_session_mlkem_dk),
                ratchet: Some(ratchet_runtime.clone()),
            }),
            abuse: Arc::new(veil_dispatcher::AbuseContext {
                // Role-aware on purpose: a seed is Core and serving others IS
                // its job, so metering it would meter the backbone. Only a
                // leaf — every xVeil client — gets a bill.
                service_budget: Arc::new(veil_dispatcher::service_budget::ServiceBudget::for_role(
                    role,
                    config.dht.service_budget_bytes_per_hour,
                )),
                rate_limiter: Arc::clone(&rate_limiter),
                ban_list: Arc::clone(&ban_list),
                violation_tracker: Arc::clone(&violation_tracker),
                dht_quota: Arc::new(Mutex::new(veil_abuse::DhtQuota::new(
                    veil_proto::budget::MAX_DHT_OPS_PER_PEER_PER_WINDOW,
                    std::time::Duration::from_secs(veil_proto::budget::DHT_QUOTA_WINDOW_SECS),
                ))),
                // per-identity DHT write quota.
                identity_write_quota: Arc::new(
                    veil_abuse::identity_quota::IdentityWriteQuota::default_policy(),
                ),
                pow_challenge_limiter: Arc::new(Mutex::new(veil_abuse::PerPeerLimiter::new(
                    config.pow.challenge_rate,
                    config.pow.challenge_burst,
                    std::time::Duration::from_secs(config.pow.challenge_window_secs),
                ))),
                unsigned_route_request_budget: Arc::new(Mutex::new(
                    veil_abuse::rate_limiter::TokenBucket::new(
                        veil_proto::budget::UNSIGNED_ROUTE_REQUEST_BURST as f64,
                        1.0 / veil_proto::budget::UNSIGNED_ROUTE_REQUEST_REFILL_SECS as f64,
                    ),
                )),
                route_request_forward_budget: Arc::new(Mutex::new(
                    veil_abuse::rate_limiter::TokenBucket::new(
                        veil_proto::budget::ROUTE_REQUEST_FORWARD_BURST as f64,
                        veil_proto::budget::ROUTE_REQUEST_FORWARD_BURST as f64
                            / veil_proto::budget::ROUTE_REQUEST_FORWARD_REFILL_SECS as f64,
                    ),
                )),
                unproven_ratchet_open_budget: Arc::new(Mutex::new(
                    veil_abuse::rate_limiter::TokenBucket::new(
                        veil_proto::budget::UNPROVEN_RATCHET_OPEN_BURST as f64,
                        veil_proto::budget::UNPROVEN_RATCHET_OPEN_BURST as f64
                            / veil_proto::budget::UNPROVEN_RATCHET_OPEN_REFILL_SECS as f64,
                    ),
                )),
                // per-peer quota on new route insertions from RouteResponse.
                dht_contact_quota: Arc::new(Mutex::new(veil_abuse::DhtQuota::new(
                    veil_proto::budget::MAX_NEW_ROUTES_PER_PEER_PER_WINDOW,
                    std::time::Duration::from_secs(veil_proto::budget::DHT_QUOTA_WINDOW_SECS),
                ))),
                // rate-limit AnnounceAttachment to prevent signature-verify DoS.
                announce_attachment_limiter: Arc::new(Mutex::new(veil_abuse::PerPeerLimiter::new(
                    1.0 / 60.0, // 1 per minute steady-state
                    3.0,        // burst: 3 (handles reconnect storms)
                    std::time::Duration::from_secs(600),
                ))),
                //round 7 / : per-peer cap on relay-mode
                // NAT-probe forwards. Closes the amplification surface
                // opened: a peer firing unique `query_id`s
                // fast through us as coordinator would have us forward
                // each one outbound (≈2× bandwidth amplification).
                nat_probe_forward_quota: Arc::new(Mutex::new(veil_abuse::DhtQuota::new(
                    veil_proto::budget::MAX_NAT_PROBE_FORWARDS_PER_PEER_PER_WINDOW,
                    std::time::Duration::from_secs(veil_proto::budget::DHT_QUOTA_WINDOW_SECS),
                ))),
                // RecursiveQuery rate-limit (5/sec sustained, burst 20). Stops a
                // peer flooding distinct query_ids that the existing dedup misses.
                recursive_query_limiter: Arc::new(Mutex::new(veil_abuse::PerPeerLimiter::new(
                    5.0,
                    20.0,
                    std::time::Duration::from_secs(300),
                ))),
                inbound_bandwidth: Arc::new(Mutex::new(veil_abuse::BandwidthGate::new(
                    veil_cfg::NodeCapacityConfig::bandwidth_kbps_to_gate(
                        config.capacity.max_inbound_bandwidth_kbps,
                    ),
                ))),
                outbound_bandwidth: Arc::new(Mutex::new(veil_abuse::BandwidthGate::new(
                    veil_cfg::NodeCapacityConfig::bandwidth_kbps_to_gate(
                        config.capacity.max_outbound_bandwidth_kbps,
                    ),
                ))),
            }),
            local_node_id,
            session_tx_registry: Some(Arc::clone(&shared_session_tx_registry)),
            rendezvous_weak: Arc::new(std::sync::Mutex::new(None)),
            session_registry: Some(Arc::clone(&shared_session_registry)),
            // Filled in-place by the IPC wiring in `service_tasks` once the
            // runtime resolver exists (defect №35 sender-side feedback).
            peer_cert_invalidate: Arc::new(Mutex::new(None)),
            route_seen_set: Arc::clone(&shared_route_seen_set),
            announce_seq: Arc::clone(&shared_announce_seq),
            listen_transports: Arc::clone(&listen_transports),
            own_external_addrs: Arc::new(std::sync::RwLock::new(vec![])),
            relay_node_ids: build_relay_node_ids(&config),
            target_labels: build_target_labels(&config.routing),
            route_updated: Arc::clone(&shared_route_updated),
            pow_difficulty: config.abuse.pow_min_difficulty as u8,
            pow_pending: Arc::new(Mutex::new(veil_dispatcher::PowPendingTable::new())),
            discovery_mode: config.routing.discovery_mode,
            dht_service: config.dht.participate,
            pending_diag: Arc::clone(&shared_pending_diag),
            capture_tx: Arc::new(Mutex::new(None)),
            capture_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            capture_rate_limit: Arc::new(veil_dispatcher_state::CaptureRateLimiter::new()),
            route_miss_tx: Arc::new(Mutex::new(None)),
            // Wired post-construction by `spawn_auth_deliver_handler`.
            auth_deliver_tx: Arc::new(Mutex::new(None)),
            neighbor_scorer: Arc::clone(&shared_neighbor_scorer),
            local_vivaldi: Some(Arc::clone(&shared_vivaldi)),
            peer_vivaldi: Arc::clone(&shared_peer_vivaldi),
            // DELIVERY_FORWARD dedup set.
            // Sized to 100 000 entries with a 60-second TTL so that burst
            // traffic cannot exhaust the cache and reopen a replay window.
            forward_seen_set: Arc::new(Mutex::new(veil_dispatcher::ForwardSeenSet::new(
                std::time::Duration::from_secs(veil_proto::budget::FORWARD_SEEN_SET_TTL_SECS),
                veil_proto::budget::MAX_FORWARD_SEEN_SET_SIZE,
            ))),
            forward_seen_content: Arc::new(Mutex::new(veil_dispatcher::ForwardSeenSet::new(
                std::time::Duration::from_secs(veil_proto::budget::FORWARD_SEEN_SET_TTL_SECS),
                veil_proto::budget::MAX_FORWARD_SEEN_SET_SIZE,
            ))),
            terminal_ack_replay: Arc::new(Mutex::new(veil_dispatcher::ExpiryMap::new(
                std::time::Duration::from_secs(veil_proto::budget::FORWARD_SEEN_SET_TTL_SECS),
                veil_proto::budget::MAX_FORWARD_SEEN_SET_SIZE,
            ))),
            recursive_query_seen: Arc::new(Mutex::new(veil_dispatcher::ExpiryCache::new(
                std::time::Duration::from_secs(30),
                65536,
            ))),
            pending_recursive: Arc::new(Mutex::new(std::collections::HashMap::new())),
            recursive_reverse_path: Arc::new(Mutex::new(std::collections::HashMap::new())),
            // session alias registry (empty; populated by SessionRunner).
            alias_registry: Arc::new(Mutex::new(std::collections::HashMap::new())),
            // NAT traversal — observed peer addresses (empty; populated by on_session_opened).
            // p: pre-size to MAX_PEER_OBSERVED_ADDRS (avoids rehash spikes).
            peer_observed_addrs: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::with_capacity(
                    veil_proto::budget::MAX_PEER_OBSERVED_ADDRS,
                ),
            )),
            local_udp_reflector_port: Arc::new(std::sync::atomic::AtomicU16::new(0)),
            peer_udp_reflectors: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::with_capacity(
                    veil_proto::budget::MAX_PEER_OBSERVED_ADDRS,
                ),
            )),
            // NAT relay tunnel table (empty; populated by NatRelayRequest dispatch).
            relay_tunnels: Arc::new(Mutex::new(std::collections::HashMap::new())),
            // pending NAT-probe waiters (empty; populated by attempt_nat_traversal).
            nat_probe_waiters: Arc::new(Mutex::new(std::collections::HashMap::new())),
            nat_punch_offer_tx: Arc::new(Mutex::new(None)),
            // scale-aware adaptive params. Init from
            // `from_network_size(100)` — the hard floor in
            // `estimate_network_size`. Reload tick refreshes this from
            // the live routing table once peers connect.
            adaptive_params: Arc::new(std::sync::RwLock::new(
                veil_cfg::adaptive::AdaptiveParams::default(),
            )),
            // configurable routing limits.
            max_gossip_hops: config.routing.max_gossip_hops,
            // congestion monitor.
            congestion_monitor: Some(Arc::clone(&shared_congestion_monitor)),
            reputation: Some(Arc::clone(&shared_reputation)),
            // gateway list — provisional initial value; the live list is
            // wired in via the rebuild below.
            gateway_list: Some(Arc::clone(&shared_gateway_list)),
            prefer_internet_gateway: config.connection.prefer_internet_gateway,
            exit_diversification: config.connection.exit_diversification,
            exit_diversification_top_k: config.connection.exit_diversification_top_k,
            // ECMP multipath.
            ecmp_score_band: config.routing.ecmp_score_band,
            redundant_send: config.routing.redundant_send,
            // epidemic broadcast.
            epidemic_seen: Arc::new(Mutex::new(veil_dispatcher::EpidemicSeenSet::new(
                std::time::Duration::from_secs(120),
                4096,
            ))),
            epidemic_fanout: config.routing.epidemic_fanout,
            epidemic_max_payload: config.routing.epidemic_max_payload,
            battery_threshold_low: config.routing.battery_threshold_low,
            battery_threshold_medium: config.routing.battery_threshold_medium,
            battery_penalty_low: config.routing.battery_penalty_low,
            battery_penalty_medium: config.routing.battery_penalty_medium,
            last_sleep_advertisement_ts: Arc::new(AtomicU64::new(0)),
            multi_path_enabled: config.routing.multi_path_enabled,
            max_parallel_paths: config.routing.max_parallel_paths,
            multi_path_min_priority: config.routing.multi_path_min_priority,
            relay_reputation_min_attempts: config.routing.relay_reputation_min_attempts,
            relay_reputation_threshold: config.routing.relay_reputation_threshold,
            relay_reputation_penalty: config.routing.relay_reputation_penalty,
            jitter_penalty_weight: config.routing.jitter_penalty_weight,
            jitter_threshold_ms: config.routing.jitter_threshold_ms,
            narrow_bandwidth_bulk_penalty: config.routing.narrow_bandwidth_bulk_penalty,
            trace_buffer: Arc::new(Mutex::new(veil_dispatcher::TraceBuffer::new(
                config.routing.trace_buffer_size,
            ))),
            pending_ack: Arc::new(Mutex::new(
                veil_dispatcher::pending_ack::PendingAckTracker::new(),
            )),
            // in-line packet loss tracker.
            loss_tracker: Arc::new(veil_routing::loss_tracker::LossTracker::new()),
            // per-origin sequence monotonicity cache.
            route_origin_seq: Arc::new(Mutex::new(std::collections::HashMap::new())),
            route_forward_last: Arc::new(Mutex::new(std::collections::HashMap::new())),
            owned_push_last: Arc::new(Mutex::new(std::collections::HashMap::new())),
            // PoW solver resource limits.
            pow_solver_semaphore: Arc::new(tokio::sync::Semaphore::new(
                veil_proto::budget::MAX_CONCURRENT_POW_SOLVERS,
            )),
            pow_active_difficulty: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pow_challenge_seen: Arc::new(Mutex::new(veil_dispatcher::ExpiryCache::new(
                std::time::Duration::from_secs(veil_proto::budget::POW_CHALLENGE_TTL_SECS),
                veil_proto::budget::MAX_POW_CHALLENGE_SEEN_SIZE,
            ))),
            pending_stream_receipts: Arc::clone(&shared_pending_stream_receipts),
            veil_stream_rx: Arc::clone(&shared_veil_stream_rx),
            // Audit M2: shared with the reload path (`build_reload_dispatcher`)
            // so the dispatcher is wired to the live PEX event channel the same
            // way on cold start and on every reload.
            pex_dispatcher: pex_runtime::build_pex_dispatcher(
                &config,
                local_node_id,
                logger.clone(),
                pex_event_tx.clone(),
            ),
            pex_state: Some(Arc::clone(&shared_pex_state)),
            anonymity_x25519_sk: anonymity_x25519_sk_for_dispatcher.clone(),
            anonymity_relay_capable: config.anonymity.relay_capable,
            // per-node Introduce-frame replay
            // cache. Cheap struct (Mutex<HashMap>); always allocated
            // even on non-anonymity nodes since the cost is one
            // pointer + one Mutex of an empty HashMap.
            introduce_replay_cache: Arc::new(
                veil_anonymity::rendezvous::IntroduceReplayCache::new(),
            ),
            // Δ2-g1: relay-side introduce-forward dedup (TTL 300s, cap 4096).
            circuit_introduce_seen: Arc::new(std::sync::Mutex::new(
                veil_dispatcher::ExpiryCache::new(std::time::Duration::from_secs(300), 4096),
            )),
            // bundle rendezvous-relay capability
            // with general anonymity-relay capability for v1. Both
            // are opt-in [anonymity].relay_capable; operators
            // wanting separation will get a dedicated knob if the
            // memory cost justifies it (default cap is 800 KiB).
            // The rendezvous-relay SERVER role (accept RegisterRendezvous +
            // forward introduces for others) is gated on `relay_capable`, NOT on
            // SK presence — a `receive_anonymous`-only node owns the SK (to
            // unseal its OWN forwarded introduces) but must NOT serve as a
            // rendezvous relay for strangers.
            rendezvous_registry: config
                .anonymity
                .relay_capable
                .then(|| Arc::new(veil_anonymity::rendezvous::RendezvousRegistry::default())),
            // Mailbox relays hold the SEPARATE private fetch-cookie registry
            // (gated on mailbox.enabled, not relay_capable) used to authorize
            // mailbox fetch/ack — never the published rendezvous cookie.
            mailbox_cookie_registry: config.mailbox.enabled.then(|| {
                Arc::new(std::sync::RwLock::new(
                    veil_anonymity::mailbox_cookie_registry::MailboxCookieRegistry::new(
                        veil_anonymity::mailbox_cookie_registry::DEFAULT_MAX_RECEIVERS,
                    ),
                ))
            }),
            // Same relay-capable gate: only relays hold per-hop circuit state.
            circuit_table: config
                .anonymity
                .relay_capable
                .then(|| Arc::new(veil_anonymity::circuit_table::CircuitTable::new())),
            circuit_rendezvous: config.anonymity.relay_capable.then(|| {
                Arc::new(veil_anonymity::circuit_register::CircuitRendezvousRegistry::new())
            }),
            // Origin-side: any receive-capable node (owns the anonymity key) may
            // ORIGINATE circuits to host a location-anonymous service.
            circuit_origin: anonymity_x25519_sk_for_dispatcher
                .is_some()
                .then(|| Arc::new(veil_anonymity::circuit_origin::OriginCircuitTable::new())),
            // onion-stream Phase 1c: per-origin-circuit sinks for byte-stream
            // return cells (empty until `open_data_circuit` registers one).
            stream_recv: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
        });
        // cleanup: pre-build the hot-standby controller and
        // its prerequisite Arcs (handoff_ack_waiters, swap_registry)
        // before the runtime literal so the literal can hold a direct
        // Arc clone instead of a throwaway placeholder that gets
        // replaced post-construction. All inputs are already bound at
        // this point: `registry` (line 1027), `transport_ctx` (line 948)
        // `shared_session_tx_registry` (line 1355), `logger` (line 947).
        let handoff_ack_waiters_arc = Arc::new(crate::runtime::handoff::HandoffAckWaiters::new());
        let swap_registry_arc = Arc::new(crate::runtime::handoff::SessionSwapRegistry::new());
        let hot_standby_controller_arc =
            Arc::new(crate::runtime::hot_standby::HotStandbyController::new(
                Arc::clone(&registry),
                Arc::clone(&transport_ctx),
                Arc::clone(&shared_session_tx_registry),
                Arc::clone(&handoff_ack_waiters_arc),
                Arc::clone(&swap_registry_arc),
                config.hot_standby.clone(),
                Arc::clone(&logger),
            ));
        // Apply per-peer alt_uri from config to the pre-built controller.
        // Pre-cleanup, this loop ran AFTER the runtime literal's
        // placeholder was replaced; running here lets the runtime
        // literal hold an already-populated Arc.
        for peer in &config.peers {
            if let Some(ref uri) = peer.alt_uri
                && let Ok(node_id) = veil_cfg::NodeId::from_public_key(peer.algo, &peer.public_key)
            {
                hot_standby_controller_arc.set_alt_uri(node_id, uri.clone());
            }
        }
        // Built before the literal because the connectivity-gain hook
        // (mobility slice) shares the same Notify with the
        // `force_reconnect_notify` field below.
        let force_reconnect_notify_arc = Arc::new(tokio::sync::Notify::new());
        let mut runtime = Self {
            config_path,
            identity_dir: veil_dir_path.clone(),
            foreground_mode,
            registry,
            transport_ctx,
            // identity bundle built below after the
            // builder so the local closures that need `local_identity`
            // / `mlkem_ek` / etc. above can still reference the local
            // var bindings. See `identity:` field assignment below.
            logger: Arc::clone(&logger),
            metrics: metrics.clone(),
            hint_registry,
            state,
            live_sessions: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            session_close_generations: Arc::new(Mutex::new(std::collections::HashMap::new())),
            session_registry: shared_session_registry,
            app_registry,
            gateway,
            discovery,
            dht,
            control_plane,
            mesh_forwarder,
            // metrics is moved into the field below, so clone here first.
            mesh_bridge: Arc::new(
                GatewayBridge::new(local_node_id, role)
                    .with_metrics(
                        metrics
                            .as_ref()
                            .map(|m| Arc::clone(m) as Arc<dyn veil_mesh::MeshMetrics>),
                    )
                    // The leaf byte quota was built end to end — guard, adapter,
                    // builder — and then never attached here, so a greedy leaf
                    // was only ever counted, never throttled. Share the runtime's
                    // per-peer limiter: it enforces bytes ONLY when the operator
                    // sets `abuse.per_peer_bytes_per_sec`, so an unconfigured node
                    // keeps today's no-enforcement posture and a configured one
                    // finally gets the quota it asked for. `reload` swaps the
                    // limiter's contents behind this same Arc, so the guard picks
                    // up a new config without rebuilding.
                    .with_leaf_bandwidth_quota(Arc::new(
                        crate::mesh_glue::LeafBandwidthGuard::from_limiter(Arc::clone(
                            &rate_limiter,
                        )),
                    )),
            ),
            mesh_realm,
            autodiscovered_peers: Arc::new(veil_mesh::AutoDiscoveredPeers::new()),
            // trips when a synthetic-range gateway session
            // closes, so `spawn_gateway_autodiscover_loop` can wake
            // immediately and back-fill instead of waiting for its
            // periodic poll. Drives the < 1 s failover acceptance bar.
            gateway_failover_notify: Arc::new(tokio::sync::Notify::new()),
            // see field doc comment.
            force_reconnect_notify: Arc::clone(&force_reconnect_notify_arc),
            // mobility slice: outbound-session-established fan-out
            // (srflx re-probe + debounced force_reconnect wake).
            connectivity_gain: Arc::new(crate::connectivity_gain::ConnectivityGain::new(
                force_reconnect_notify_arc,
            )),
            // shared push-event bus. Default capacity (256)
            // — fast subscribers consume events in microseconds; only
            // pathologically slow consumers (Flutter UI mid-paint) ever
            // hit the lag boundary, and they get a one-frame skip
            // rather than a stalled publisher.
            event_bus: Arc::new(veil_ipc::EventBus::new()),
            // empty registry of node_ids with active
            // outbound-connector tasks; populated atomically inside
            // `spawn_outbound_peers`.
            outbound_connector_refresh: Arc::new(Mutex::new(std::collections::HashMap::new())),
            // load cached discovered peers from disk if
            // configured. Missing/corrupt file → empty cache (no
            // panic — first-run case) so node still boots.
            //
            // HMAC the cache against a
            // per-device key stored next to the daemon's veil_dir
            // so a local attacker that rewrites the JSON cannot
            // make us dial peers of their choosing. The key file
            // is auto-generated on first start.
            discovered_peers_cache: Arc::new(Mutex::new({
                let cache_path: Option<std::path::PathBuf> = config
                    .global
                    .discovered_peers_cache_path
                    .as_ref()
                    .map(std::path::PathBuf::from);
                let key_dir = cache_path
                    .as_ref()
                    .and_then(|p| p.parent())
                    .map(|p| p.to_path_buf());
                let hmac_key = key_dir
                    .as_ref()
                    .and_then(|d| veil_bootstrap::load_or_generate_cache_hmac_key(d).ok());
                match (cache_path, hmac_key) {
                    (Some(p), Some(k)) => {
                        veil_bootstrap::DiscoveredPeerCache::load_with_hmac_key(p, k)
                    }
                    (Some(p), None) => veil_bootstrap::DiscoveredPeerCache::load(p),
                    (None, _) => veil_bootstrap::DiscoveredPeerCache::in_memory(),
                }
            })),
            // decomposition PR1: bundle the four
            // anonymity-related fields into a dedicated AnonymityState.
            // Reuses the SAME x25519 Arc that was passed into the
            // dispatcher above, so the publish task (which reads the
            // field on NodeRuntime) and the inbound RelayChain handler
            // (which reads the dispatcher's field) operate on the same
            // key. When relay is disabled, both are None — but we
            // still need *some* SK for `tick_publish_relay_directory_entry`
            // to be a no-op, so fall back to a fresh ephemeral so the
            // type signature stays `Arc<StaticSecret>`. The publish
            // helper's `relay_capable = false` early-return guards
            // against this fallback ever being used.
            anonymity: Arc::new(anonymity_state::AnonymityState::new(
                config.anonymity.relay_capable,
                config.anonymity.advertised_bps,
                anonymity_x25519_sk_for_dispatcher
                    .clone()
                    .unwrap_or_else(|| {
                        Arc::new(x25519_dalek::StaticSecret::random_from_rng(
                            rand_core::OsRng,
                        ))
                    }),
                config.anonymity.onion_service.then(|| {
                    config
                        .anonymity
                        .onion_service_hops
                        .map_or(3, |h| h as usize)
                }),
                // Δ2-h: operator-pinned rendezvous relays, parsed once so
                // select_onion_relay_path can honour them.
                config
                    .anonymity
                    .rendezvous_relays
                    .iter()
                    .filter_map(|s| {
                        <veil_cfg::NodeId as std::str::FromStr>::from_str(s)
                            .ok()
                            .map(|n| *n.as_bytes())
                    })
                    .collect(),
            )),
            mailbox_state: Arc::new(mailbox_state::MailboxState::new(
                mailbox_handle,
                outbox_handle,
            )),
            builtin_app_host: Some(crate::builtin::BuiltinAppHost::new()),
            routing: Arc::new(routing_state::RoutingState::new(
                shared_rtt_table,
                route_cache,
                Arc::clone(&shared_neighbor_scorer),
                Arc::clone(&shared_vivaldi),
            )),
            rate_limiter,
            nat_probe_backoff: Arc::new(Mutex::new(PerPeerLimiter::new(
                NAT_PROBE_SUSTAINED_PER_SEC,
                NAT_PROBE_BURST,
                NAT_PROBE_IDLE_FORGET,
            ))),
            ban_list,
            violation_tracker,
            runtime_summary: Arc::new(Mutex::new(RuntimeSummary {
                role: role.to_string(),
                ..Default::default()
            })),
            dispatcher,
            next_link_id: Arc::new(AtomicU64::new(1)),
            next_listener_handle: Arc::new(AtomicU64::new(1)),
            pending_accepts: Arc::new(Mutex::new(BTreeMap::new())),
            metrics_path: resolve_metrics_path(&config),
            metrics_endpoint: None,
            shutdown_tx: None,
            ephemeral_rotator_shutdowns: Mutex::new(Vec::new()),
            rendezvous_controller: Mutex::new(None),
            tasks: Arc::new(Mutex::new(RuntimeTasks::default())),
            health_tick: Arc::new(AtomicU64::new(0)),
            session_tx_registry: shared_session_tx_registry,
            session_outbox,
            wire_stream_counter: Arc::new(AtomicU32::new(1)),
            // bundle identity-domain fields into one Arc.
            identity: Arc::new(identity_state::IdentityState::new(
                Arc::clone(&local_identity),
                sovereign_cell,
                Arc::clone(&peer_pubkeys),
                Arc::clone(&peer_sovereign_identities),
                Arc::clone(&peer_roles),
                Arc::clone(&mlkem_keys),
                Arc::clone(&shared_peer_mlkem_keys),
                Arc::clone(&shared_peer_mlkem_certs),
                Arc::clone(&shared_peer_mlkem_cert_store),
                Arc::clone(&shared_peer_ratchet_keys),
                Arc::clone(&shared_per_session_mlkem_dk),
            )),
            sessions_per_ip: Arc::new(ip_slot::IpSlotTable::new()),
            scanner_shield: Arc::new(veil_abuse::scanner_shield::ScannerShield::new()),
            // pre-spawn inbound handshake cap. See struct field doc.
            // Derive cap from session defaults `max_concurrent`: 4× the
            // post-handshake session cap, floor 1024.  At default
            // `max_concurrent=512` → 2048 permits; at relay-class
            // `max_concurrent=65_536` → 262144 permits.
            inbound_handshake_sem: Arc::new(tokio::sync::Semaphore::new(
                config.session.max_concurrent.saturating_mul(4).max(1024),
            )),
            inbound_handshake_sem_target: config.session.max_concurrent.saturating_mul(4).max(1024),
            mlkem_republish_now: Arc::new(tokio::sync::Notify::new()),
            dht_republish_now: Arc::new(tokio::sync::Notify::new()),
            pending_diag: Arc::clone(&shared_pending_diag),
            // H10 stage-B (4/N): 16 session-config knobs collapsed
            // into one `Arc<SessionDefaults>`. Same Arc is cloned into
            // NodeServices and SessionRuntimeContext at boundary builds.
            defaults: session_defaults::SessionDefaults::new(
                std::time::Duration::from_secs(config.session.keepalive_interval_secs),
                std::time::Duration::from_secs(config.session.idle_timeout_secs),
                config.session.max_pending_responses,
                std::time::Duration::from_millis(config.session.pending_response_ttl_ms),
                config.session.max_frame_body_bytes,
                config.session.rekey_bytes_threshold,
                config.session.rekey_time_threshold_secs,
                config.session.qos_weights.map(|w| w as u32),
                config.session.max_concurrent,
                config.session.referral_headroom,
                config.session.max_per_ip,
                config.session.max_per_subnet,
                std::time::Duration::from_secs(config.gateway.keepalive_interval_secs),
                std::time::Duration::from_millis(config.connection.reconnect_backoff_min_ms),
                std::time::Duration::from_millis(config.connection.reconnect_backoff_max_ms),
                config.connection.reconnect_quiet_after_failures,
            ),
            // bundled mobile / battery-tier state.
            mobile: Arc::new(mobile_state::MobileState::new(
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
                config.session.battery_keepalive_scale_low,
                config.session.battery_keepalive_scale_medium,
                config.session.battery_threshold_low,
                config.session.battery_threshold_medium,
            )),
            // congestion monitor.
            congestion_monitor: shared_congestion_monitor,
            memory_budget: Arc::new(crate::memory::MemoryBudget::default_budget()),
            // route-cache persistence path (None = disabled).
            cache_persist_path: config.routing.cache_persist_path.clone(),
            // RTT table persistence path (None = disabled).
            rtt_persist_path: config.routing.rtt_persist_path.clone(),
            // Master switch for all persistence.
            persist_enabled: config.persist_enabled,
            // gateway list — same Arc shared with the dispatcher.
            gateway_list: Arc::clone(&shared_gateway_list),
            // record when the ML-KEM key was loaded so the admin
            // metrics endpoint can report key age.
            mlkem_key_loaded_at: Instant::now(),
            mlkem_key_path: mlkem_key_path.clone(),
            // discovery initiator channel — populated by spawn_discovery_initiator_task.
            discovery_trigger_tx: Arc::new(Mutex::new(None)),
            // H10 stage-B: session-resumption bundle —
            // ticket_issuer (fresh host ticket key) + peer_tickets (per-peer
            // cache populated at handshake-complete) wrapped together so the
            // 3 propagation structs (NodeRuntime / NodeServices /
            // SessionRuntimeContext) carry one `Arc<ResumptionState>` instead
            // of two siblings.
            resumption: Arc::new(resumption_state::ResumptionState::new(
                Arc::new(Mutex::new(
                    veil_session::ticket::TicketIssuer::new(
                        veil_session::ticket::TicketKey::generate(),
                    )
                    // The issuer refuses to resume an instance-less ticket from
                    // a peer we already know as a multi-device identity; the
                    // binding cache is what knows that, and it lives here.
                    .with_instance_oracle({
                        let bindings = Arc::clone(&peer_sovereign_identities);
                        Arc::new(move |peer: &[u8; 32]| {
                            lock!(bindings).keys().any(|(id, _)| id == peer)
                        })
                    }),
                )),
                Arc::new(Mutex::new(std::collections::HashMap::new())),
            )),
            // H10 stage-B: PEX bundle — 4 PEX fields collapsed
            // (state + 3 channels) into one owned `PexRuntime`. Receivers
            // remain `Option<...>` inside the bundle so the initiator/
            // connector tasks can `.take()` them at spawn time.
            pex: pex_runtime::PexRuntime::new(
                Arc::clone(&shared_pex_state),
                pex_event_rx,
                pex_connect_tx,
                pex_connect_rx,
            ),
            // sovereign_identity now lives inside the
            // `identity: Arc<IdentityState>` bundle initialised earlier
            // in this literal. Local var consumed by the IdentityState
            // ctor; nothing else to assign here.
            // H10 stage-B: 5 handoff fields collapsed into
            // one `Arc<HandoffRuntime>` bundle. hot_standby_controller_arc
            // is built once before the runtime literal from pre-extracted
            // Arcs (registry / transport_ctx / shared_session_tx_registry
            // / handoff_ack_waiters_arc / swap_registry_arc / logger);
            // pre-cleanup, a throwaway "placeholder" was constructed
            // here and immediately replaced after the literal closed
            // because the real Arcs weren't addressable yet through
            // `runtime.x`.
            handoff: Arc::new(handoff_runtime::HandoffRuntime::new(
                Arc::new(crate::runtime::handoff::HandoffRegistry::new()),
                Arc::clone(&swap_registry_arc),
                Arc::clone(&handoff_ack_waiters_arc),
                Arc::clone(&hot_standby_controller_arc),
                config.hot_standby.auto_trigger_after_write_errors,
            )),
            allowed_peer_algos: config.session.allowed_peer_algos.clone(),
            // P-Net Phase 3b: gate was constructed early so the DHT
            // ingest path could be wired before `Arc::new(svc)`. Stash
            // the same Arc here so the rest of the runtime (handshake,
            // ban-sync) sees the same gate instance.
            network_gate: network_gate_arc.clone(),
            // S2.A part 3: per-peer verified-cert cache. Filled by
            // handshake on successful verify_peer; read by PnetStatusProvider
            // when an IPC consumer (ogate/oproxy) queries a peer's
            // admission state.
            verified_peer_certs: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            // real-P2P Stage B: single-flight registry for explicit
            // call-path hole-punch attempts (peer → in-flight outcome).
            hole_punch_inflight: Arc::new(Mutex::new(std::collections::HashMap::new())),
            // open the admin audit log next to the config
            // file (typically <veil-dir>/admin-audit.log). A
            // failure to open is logged and the runtime continues
            // without auditing — denying node startup because audit
            // disk-space is full would be worse than missing audit
            // entries until disk-space is reclaimed.
            admin_audit: {
                // `config_path` is already moved into one of the
                // earlier fields by name; recover the parent dir
                // from the `veil_dir_path` (computed at line ~738
                // for exactly this kind of derived setup).
                let dir = veil_dir_path.clone();
                match crate::admin_audit::AdminAuditLog::open(&dir) {
                    Ok(a) => Some(Arc::new(a)),
                    Err(e) => {
                        logger.warn(
                            "admin.audit.open_failed",
                            format!("dir={} err={e} — audit disabled", dir.display()),
                        );
                        None
                    }
                }
            },
        };
        // prime the global mobile background-mode
        // multiplier from config so session runners see it on
        // their first keepalive recomputation tick. The flag
        // itself stays false until SetMobileBackgroundMode flips
        // it; this just sets the SCALE that flip applies.
        veil_session::runner::set_mobile_background_keepalive_multiplier(
            config.mobile.background_keepalive_multiplier,
        );
        // deferred : prime the outbound-batch
        // signals. Default config: threshold = None → disabled
        // sentinel; window = None → 0. Both must be configured
        // for coalescing to engage (gated in `current_outbound_batch_window`).
        veil_session::runner::set_mobile_low_battery_threshold_pct(
            config.mobile.low_battery_threshold_pct,
        );
        veil_session::runner::set_mobile_outbound_batch_window_ms(
            config.mobile.outbound_batch_window_ms.unwrap_or(0),
        );
        // The battery-independent opt-in. Without priming it the config field
        // would parse and then do nothing, which is the failure mode the
        // window itself already had.
        veil_session::runner::set_mobile_outbound_batch_always(config.mobile.outbound_batch_always);
        // prime the global session-rotation interval
        // (0 = disabled). Runtime-side clamp ensures any value
        // < 60 gets pushed up to the floor, defending against
        // misconfig OR validation bypass.
        //
        // `[transport.rotation]` is the only knob; `-1`/`-1` disables.
        match config.transport.rotation.resolved_range() {
            Some((min, max)) => veil_session::runner::set_session_rotation_range(min, max),
            None => veil_session::runner::set_session_rotation_range(0, 0),
        }
        // cleanup: hot_standby_controller + per-peer
        // alt_uri now built before the runtime literal (see. above).
        // Pre-cleanup, this block replaced a throwaway placeholder
        // controller; the placeholder is gone, this block with it.
        // –164: restore snapshots only when persistence is globally enabled.
        if config.persist_enabled {
            // restore route cache from snapshot before accepting connections.
            runtime.restore_route_cache_snapshot(&config);
            // restore RTT table from snapshot.
            runtime.restore_rtt_snapshot(&config);
            // restore Vivaldi coordinate.
            runtime.restore_vivaldi_snapshot(&config);
            // restore DHT routing table contacts.
            runtime.restore_dht_routing_snapshot(&config);
            // restore DHT stored values.
            runtime.restore_dht_values_snapshot(&config);
            // restore autodiscovered peers.
            runtime.restore_autodiscover_snapshot(&config);
            // restore gateway list; then rebuild from config (config entries take precedence).
            runtime.restore_gateway_list_snapshot(&config);
            // restore peer pubkeys cache.
            runtime.restore_peer_pubkeys_snapshot(&config);
            //restore peer transport announcements.
            runtime.restore_transport_announcements_snapshot(&config);
        } // end if config.persist_enabled
        // populate gateway list from configured peers (always, regardless of persist).
        runtime.rebuild_gateway_list_from_state();
        runtime.logger.info(
            "node.start",
            format!("config={}", runtime.config_path.display()),
        );
        // every background task the runtime keeps alive lives in
        // `RuntimeService::ALL`; both start and reload walk that list so they
        // cannot drift out of sync. The dispatch table lives in
        // `spawn_service`.
        runtime.spawn_all_services(&config).await?;
        // onion-stream Phase 1d: publish a services view for the embedded FFI to
        // drive pinned stream circuits in-process (the IPC surface has none).
        crate::runtime::services::publish_embedded_services(runtime.access());
        Ok(runtime)
    }

    // ── multi-gateway failover ──────────────────────────────────────

    /// Populate the gateway list from the current state.peers entries.
    ///
    /// All non-bootstrap configured peers are added with
    /// `BASE_SCORE_CONFIGURED`. Autodiscovered peers (bootstrap_only, peer_id
    /// ≥ 0xC000_0000) are expected to arrive through `upsert` calls in the
    /// beacon receive path.
    fn rebuild_gateway_list_from_state(&self) {
        use veil_gateway::BASE_SCORE_CONFIGURED;
        let peers = self.peers();
        let mut gl = lock!(self.gateway_list);
        for p in &peers {
            if p.bootstrap_only {
                continue;
            } // skip bootstrap and autodiscovered
            gl.upsert(
                *p.node_id.as_bytes(),
                p.transport.clone(),
                BASE_SCORE_CONFIGURED,
                true, /* assume internet until learned otherwise */
            );
        }
    }

    /// Spawn the on-demand DHT discovery initiator task.
    ///
    /// Listens for trigger signals sent [`trigger_discovery_search`]. On
    /// each signal, runs `FIND_NODE(local_node_id)` over the network to refresh
    /// Kademlia routing table buckets. The channel sender is stored in
    /// `discovery_trigger_tx` so the admin API can reach it.
    // (is_self_authenticating lives at module level, below.)
    fn spawn_discovery_initiator_task(&mut self) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();

        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(4);
        *lock!(self.discovery_trigger_tx) = Some(tx);

        let dht = Arc::clone(&self.dht);
        let session_outbox = Arc::clone(&self.session_outbox);
        let local_node_id = *self.identity.local_identity.node_id.as_bytes();
        let metrics = self.metrics.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Ok(_) = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { break; }
                    }
                    msg = rx.recv() => {
                        if msg.is_none() { break; } // channel closed
                        if let Some(m) = &metrics { m.inc_discovery_triggered(); }
                        // FIND_NODE(self) causes every contacted peer to return its
                        // k closest contacts, filling in Kademlia routing table buckets.
                        let _ = dht.find_node_iterative_network(
                            local_node_id,
                            Arc::clone(&session_outbox) as Arc<dyn veil_dht::FrameRouter>,
                        ).await;
                    }
                }
            }
        });
        lock_tasks(&self.tasks).background.push(handle);
    }

    fn spawn_outbound_peers(&mut self) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let handles = crate::outbound_connector::spawn_outbound_peers(
            self.peers(),
            &self.access(),
            shutdown_tx,
        );
        lock_tasks(&self.tasks).peers.extend(handles);
        // Load previously-discovered peers from disk.
        persistence::load_discovered_peers(
            &self.config_path,
            &self.state,
            &self.access(),
            shutdown_tx,
        );
    }

    /// Spawn persistent connections to all pinned relay nodes.
    ///
    /// Pinned relays use the same reconnect loop as regular peers but are
    /// configured separately from `config.peers` to signal that the connection
    /// MUST always be maintained.
    fn spawn_pinned_relays(&mut self, config: &veil_cfg::Config) {
        if config.pinned_relays.is_empty() {
            return;
        }
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let entries: Vec<PeerConfigEntry> = config
            .pinned_relays
            .iter()
            .enumerate()
            .filter_map(|(i, relay)| {
                let node_id =
                    veil_cfg::NodeId::from_public_key(relay.algo, &relay.public_key).ok()?;
                // Synthetic peer_id in the pinned-relay window (cycle-7 M3:
                // disjoint from PEX / gateway-failover, which used to share
                // 0xD000_0000). See `types::synthetic_peer_id`.
                let peer_id = veil_cfg::PeerId::new(
                    crate::types::synthetic_peer_id::PINNED_RELAY_BASE.wrapping_add(i as u32),
                );
                Some(PeerConfigEntry {
                    peer_id,
                    node_id,
                    public_key: relay.public_key.clone(),
                    nonce: relay.nonce.clone(),
                    transport: relay.transport.clone(),
                    algo: relay.algo,
                    tls_cert: relay.tls_cert.clone(),
                    tls_key: None,
                    tls_ca_cert: relay.tls_ca_cert.clone(),
                    bootstrap_only: false,
                    source: crate::types::PeerSource::Configured,
                })
            })
            .collect();
        // cycle-7 M2: register pinned relays in `state.peers` BEFORE spawning
        // their connectors — every other `spawn_outbound_peers` caller does
        // this. The connector itself dials from the captured `PeerConfigEntry`,
        // so the connection worked without it, but the missing insert left
        // pinned relays invisible to peer enumeration / admin status / any path
        // that re-resolves a peer's config from `state.peers`.
        {
            let mut st = self.lock_state();
            for entry in &entries {
                st.peers.insert(entry.peer_id, entry.clone());
            }
        }
        let handles =
            crate::outbound_connector::spawn_outbound_peers(entries, &self.access(), shutdown_tx);
        lock_tasks(&self.tasks).peers.extend(handles);
    }

    fn lock_state(&self) -> MutexGuard<'_, NodeState> {
        lock_state(&self.state)
    }

    pub fn log_info(&self, event: &str, message: impl AsRef<str>) {
        self.logger.info(event, message);
    }

    /// Return the current value of the monotonic health-tick counter.
    /// Incremented once per second by the maintenance loop; used by the
    /// `AdminCommand::Health` handler to detect a stalled event loop.
    pub fn health_tick(&self) -> u64 {
        self.health_tick.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Return the shared trace-hop ring buffer.
    pub fn trace_buffer(&self) -> Arc<std::sync::Mutex<veil_dispatcher::TraceBuffer>> {
        Arc::clone(&self.dispatcher.trace_buffer)
    }

    /// A clone of the route-miss channel sender — the same channel the delivery
    /// path signals when it forwards to a destination with no cached route.
    /// `None` before the route-miss-handler service has installed its receiver.
    /// Introspection seam: lets sim scenarios drive the real route-miss →
    /// RouteRequest → iterative-DHT-fallback chain without an app-send-to-node
    /// primitive (the harness has none).
    pub fn route_miss_sender(&self) -> Option<veil_dispatcher::RouteMissTx> {
        lock!(self.dispatcher.route_miss_tx).as_ref().cloned()
    }

    // ── Introspection ─────────────────────────────────────────────

    /// Return a snapshot of all runtime metrics counters, or `None` if metrics
    /// are not configured.
    pub fn metrics_snapshot(&self) -> Option<veil_observability::MetricsSnapshot> {
        self.metrics.as_ref().map(|m| m.snapshot())
    }

    /// Seconds since the ML-KEM keypair was created — measured from the on-disk
    /// PEM file's mtime, which survives daemon restart (so this metric
    /// genuinely reflects keypair lifetime for rotation planning).
    /// Falls back to "seconds since load in this process" if file metadata
    /// cannot be read (e.g. permission error, deleted underneath us).
    pub fn mlkem_key_age_secs(&self) -> u64 {
        if let Ok(meta) = std::fs::metadata(&self.mlkem_key_path)
            && let Ok(modified) = meta.modified()
            && let Ok(age) = std::time::SystemTime::now().duration_since(modified)
        {
            return age.as_secs();
        }
        self.mlkem_key_loaded_at.elapsed().as_secs()
    }

    /// Return all locally stored DHT key-value pairs.
    pub fn dht_stored_entries(&self) -> Vec<([u8; 32], Vec<u8>)> {
        self.dht.stored_entries()
    }

    /// Bounded variant for operator introspection: streams key IDs and peeks
    /// at most `max` values (no full-store / cold-tier materialization).
    /// Returns `(entries, truncated)` where `truncated` is `true` when the
    /// store held more than `max` keys.
    #[allow(clippy::type_complexity)] // (entries, truncated): a 2-field admin-introspection tuple; an alias obscures more than it clarifies
    pub fn dht_stored_entries_limited(&self, max: usize) -> (Vec<([u8; 32], Vec<u8>)>, bool) {
        let keys = self.dht.stored_key_ids();
        let truncated = keys.len() > max;
        let entries = keys
            .into_iter()
            .take(max)
            .filter_map(|k| self.dht.peek_value(&k).map(|v| (k, v)))
            .collect();
        (entries, truncated)
    }

    /// Return all contacts in the DHT Kademlia routing table.
    pub fn dht_contacts(&self) -> Vec<veil_dht::routing::Contact> {
        self.dht.routing_table_contacts()
    }

    /// Look up a value in the local DHT store by key.
    pub fn dht_get_local(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.dht.get_local(key)
    }

    /// Store a key-value pair directly in the local DHT node store.
    pub fn dht_put_local(&self, key: [u8; 32], value: Vec<u8>) {
        self.dht.store_local(key, value);
    }

    /// publish `value` at `key` to the local DHT shard AND
    /// fan it out to the K closest live peers in keyspace as
    /// `RecursiveQuery(STORE)`. Without this, a node going offline
    /// takes its published values with it once chunked route-cache
    /// TTLs expire — anti-censorship-resistance, since the user's
    /// `IdentityDocument` / `NameClaim` becomes unresolvable as soon
    /// as their phone screen locks. See [TASKS.md] for the
    /// full design discussion.
    ///
    /// Best-effort: per-replica failures are logged but don't fail
    /// the publish. The local store always succeeds; remote
    /// replicas catch up via the periodic re-replication tick.
    ///
    /// Returns the count of successful sends — useful for metrics +
    /// tests but rarely actionable on the publish path.
    pub fn dht_publish_replicated(&self, key: [u8; 32], value: Vec<u8>) -> usize {
        dht_publish_replicated_via(
            &self.dht,
            &self.session_tx_registry,
            *self.identity.local_identity.node_id.as_bytes(),
            key,
            value,
        )
    }

    /// PoW-Gated Rendezvous initiator helper — Slice 9 follow-up of
    /// the epic (closes the response-await gap left out of Slice 4
    /// scope, where the SDK shipped only the build/parse primitives
    /// without the dispatch + correlation glue).
    ///
    /// Flow:
    /// 1. Build a signed `RequestEphemeralEndpointPayload` (mines PoW
    ///    at `pow_difficulty` against the canonical form)
    /// 2. Wrap in `RecursiveQuery{query_type=RENDEZVOUS_REQUEST}` with a
    ///    fresh 16-byte `query_id` and `target_key = target_node_id`
    /// 3. Register a `PendingRecursive` entry under `query_id` so
    ///    the existing `handle_recursive_response` arm fires our
    ///    oneshot when the matching response arrives
    /// 4. Ship the encoded frame to the closest active session peers
    ///    (sorted by XOR distance to `target_node_id`)
    /// 5. Await the oneshot up to `timeout`
    /// 6. Validate the recursive response:
    ///    a. `responder_pubkey == target_pubkey` (binding to the
    ///       expected target identity)
    ///    b. Outer envelope sig verify under `target_pubkey` over
    ///       `query_id || payload`
    ///    c. Inner `EphemeralEndpointResponsePayload` runs through
    ///       `verify_ephemeral_endpoint_response` (identity binding,
    ///       requester echo, TTL)
    /// 7. Return the recovered `(transport_uri, psk, valid_until_unix)`
    ///    triple — caller dials the URI with the embedded PSK
    pub async fn request_rendezvous_endpoint(
        &self,
        target_node_id: [u8; 32],
        target_pubkey: [u8; 32],
        requester_signing_key: &ed25519_dalek::SigningKey,
        pow_difficulty: u32,
        timeout: std::time::Duration,
    ) -> std::result::Result<RendezvousEndpoint, RendezvousClientError> {
        use ed25519_dalek::VerifyingKey;
        use veil_proto::rendezvous::{
            EphemeralEndpointResponsePayload, MAX_POW_DIFFICULTY, MIN_POW_DIFFICULTY,
            RequestEphemeralEndpointPayload, mine_pow_nonce_cancellable,
            sign_request_ephemeral_endpoint, verify_ephemeral_endpoint_response,
        };

        if pow_difficulty < MIN_POW_DIFFICULTY {
            return Err(RendezvousClientError::BadDifficulty(format!(
                "{pow_difficulty} below min {MIN_POW_DIFFICULTY}",
            )));
        }
        if pow_difficulty > MAX_POW_DIFFICULTY {
            return Err(RendezvousClientError::BadDifficulty(format!(
                "{pow_difficulty} above max {MAX_POW_DIFFICULTY}",
            )));
        }
        // Sanity: target_node_id MUST equal BLAKE3(target_pubkey).
        let expected_nid = *blake3::hash(&target_pubkey).as_bytes();
        if expected_nid != target_node_id {
            return Err(RendezvousClientError::TargetIdentityMismatch);
        }

        // Pick closest active peers to forward to.
        let mut peers: Vec<[u8; 32]> = rlock!(self.session_tx_registry).peer_ids();
        if peers.is_empty() {
            return Err(RendezvousClientError::NoPeers);
        }
        peers.sort_by_key(|pid| {
            let mut xor = [0u8; 32];
            for i in 0..32 {
                xor[i] = pid[i] ^ target_node_id[i];
            }
            xor
        });

        // Stage 1: build the inner request, mine the PoW off the async
        // executor, then sign.
        //
        // Mining is CPU-bound (≈2^pow_difficulty BLAKE3 hashes — up to several
        // seconds at production difficulties of 24-28 bits) and previously ran
        // inline, stalling the runtime worker thread for its whole duration.
        // Run it on the blocking pool, bounded by the operation `deadline`,
        // with a cancel flag so a timed-out mine actually stops instead of
        // orphaning a thread that keeps hashing to completion.  `pow_difficulty`
        // is already range-checked above (MIN..=MAX), which caps expected work.
        let deadline = tokio::time::Instant::now() + timeout;
        let requester_pk = requester_signing_key.verifying_key().to_bytes();
        let timestamp_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let draft = RequestEphemeralEndpointPayload {
            target_node_id,
            requester_pubkey: requester_pk,
            timestamp_unix,
            pow_difficulty,
            pow_nonce: 0,
            requester_sig: [0u8; 64],
        };
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mined_nonce = {
            let cancel_task = std::sync::Arc::clone(&cancel);
            let mut mining_draft = draft;
            let handle = tokio::task::spawn_blocking(move || {
                mine_pow_nonce_cancellable(&mut mining_draft, &cancel_task)
                    .map(|opt| opt.map(|_attempts| mining_draft.pow_nonce))
            });
            match tokio::time::timeout_at(deadline, handle).await {
                Ok(Ok(Ok(Some(nonce)))) => nonce,
                // `None` only if `cancel` was set, which happens solely on the
                // timeout path below — so this arm is effectively dead, but it
                // keeps the match exhaustive without an unwrap.
                Ok(Ok(Ok(None))) => return Err(RendezvousClientError::Timeout),
                Ok(Ok(Err(e))) => {
                    return Err(RendezvousClientError::Mining(format!("{e}")));
                }
                Ok(Err(join_err)) => {
                    return Err(RendezvousClientError::Mining(format!(
                        "solver task failed: {join_err}"
                    )));
                }
                Err(_elapsed) => {
                    // Signal the detached blocking thread to stop hashing.
                    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    return Err(RendezvousClientError::Timeout);
                }
            }
        };
        let signed = sign_request_ephemeral_endpoint(
            target_node_id,
            requester_pk,
            timestamp_unix,
            pow_difficulty,
            mined_nonce,
            requester_signing_key,
        );
        let inner_bytes = signed.encode().to_vec();

        // Stage 2: wrap in RecursiveQuery + register pending.
        let local_node_id = *self.identity.local_identity.node_id.as_bytes();
        let query_id: [u8; 16] = {
            use rand_core::RngCore;
            let mut id = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut id);
            id
        };
        let q = veil_proto::routing::RecursiveQueryPayload {
            query_id,
            target_key: target_node_id,
            reply_to: local_node_id,
            ttl: veil_proto::budget::MAX_RECURSIVE_RELAY_HOPS,
            query_type: veil_proto::routing::recursive_query_type::RENDEZVOUS_REQUEST,
            reply_port: 0,
            payload: inner_bytes,
        };
        let q_bytes = q.encode();
        let mut hdr = veil_proto::header::FrameHeader::new(
            veil_proto::family::FrameFamily::Routing as u8,
            veil_proto::family::RoutingMsg::RecursiveQuery as u16,
        );
        hdr.body_len = q_bytes.len() as u32;
        let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
        frame.extend_from_slice(&q_bytes);

        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        {
            use veil_proto::budget::MAX_PENDING_RECURSIVE;
            let mut m = lock!(self.dispatcher.pending_recursive);
            m.retain(|_, p| !p.tx.is_closed());
            if m.len() >= MAX_PENDING_RECURSIVE {
                return Err(RendezvousClientError::PendingTableFull);
            }
            m.insert(
                query_id,
                veil_dispatcher::PendingRecursive {
                    target_key: target_node_id,
                    query_type: veil_proto::routing::recursive_query_type::RENDEZVOUS_REQUEST,
                    tx,
                },
            );
        }

        // Stage 3: send to top-2 closest peers (matches dht_recursive_get
        // fan-out — gives redundancy without noisy duplication).
        {
            let guard = rlock!(self.session_tx_registry);
            let mut sent = 0;
            for pid in peers.iter().take(2) {
                if guard.send_to(
                    pid,
                    veil_proto::header::priority::INTERACTIVE,
                    frame.clone(),
                ) {
                    sent += 1;
                }
            }
            if sent == 0 {
                return Err(RendezvousClientError::SendFailed);
            }
        }

        // Stage 4: await response + dispatcher's outer-envelope sig was
        // ALREADY verified in `handle_recursive_response` (line 2369-2383
        // — `claimed_responder_id == BLAKE3(responder_pubkey)` +
        // ed25519 sig over `query_id || payload`).  So `payload` here
        // is trusted-from-the-claimed-responder, but we still must:
        // (a) confirm the responder_pubkey we expected matched, and
        // (b) verify the INNER `EphemeralEndpointResponsePayload`.
        //
        // Subtle: `handle_recursive_response` doesn't pass the
        // responder_pubkey back through the oneshot — only `resp.payload`.
        // So we cannot enforce (a) here.  Inner sig + identity-binding
        // checks below close the gap: inner is sig'd by target_sk and
        // the identity binding ensures BLAKE3(inner_responder) ==
        // target_node_id.  A wrong-target response would fail the
        // inner verify.  Defense-in-depth — the outer envelope's sig
        // helps mediators reject forgeries at relay time, but the
        // initiator's source-of-truth is the inner identity binding.
        // Share the operation `deadline` with the mining stage: the network
        // wait gets whatever time remains after mining, so total wall-clock is
        // bounded by `timeout` rather than (mining + timeout).
        let payload = match tokio::time::timeout_at(deadline, rx).await {
            Ok(Ok(p)) if !p.is_empty() => p,
            Ok(Ok(_)) => {
                // Empty payload — controller sent a nominal response with
                // empty body (shouldn't happen in well-formed flow).
                return Err(RendezvousClientError::EmptyResponse);
            }
            Ok(Err(_)) => return Err(RendezvousClientError::ChannelClosed),
            Err(_) => return Err(RendezvousClientError::Timeout),
        };

        let inner = EphemeralEndpointResponsePayload::decode(&payload)
            .map_err(|e| RendezvousClientError::Decode(format!("inner: {e}")))?;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        verify_ephemeral_endpoint_response(&inner, &target_pubkey, &requester_pk, now_unix)
            .map_err(|e| RendezvousClientError::Verify(format!("inner: {e}")))?;
        // Defense-in-depth: also enforce target_pubkey is the right
        // shape (already covered by verify_ephemeral_endpoint_response
        // through `from_bytes` but we double-check).
        let _ = VerifyingKey::from_bytes(&target_pubkey)
            .map_err(|e| RendezvousClientError::Verify(format!("bad target_pubkey: {e}")))?;

        Ok(RendezvousEndpoint {
            transport_uri: inner.transport_uri,
            psk: inner.psk,
            valid_until_unix: inner.valid_until_unix,
        })
    }

    /// try NAT traversal toward `target_node_id`
    /// using ANY currently-connected peer as the signaling
    /// coordinator. This is the high-level driver that operators +
    /// (forthcoming) outbound-dial-failure auto-trigger use to
    /// discover the target's candidates without having to pick a
    /// specific coordinator by hand.
    ///
    /// Picks coordinators in keyspace-distance order from `target_node_id`
    /// (closer-to-target peers are more likely to ALSO have a session
    /// to the target). Tries each coordinator with a short per-call
    /// timeout — first success wins, returns `Some(reply)`. Returns
    /// `None` if every connected peer either lacks a session to the
    /// target or doesn't reply within `per_coordinator_timeout`.
    ///
    /// Self-skip: never picks the local node as coordinator (would be
    /// a no-op self-loop). Target-skip: never picks `target_node_id`
    /// itself as coordinator (probing the target through itself is
    /// nonsensical).
    ///
    /// This method does NOT do UDP hole-punching — it's the signaling
    /// driver only. The returned `NatProbeReplyPayload.candidates`
    /// feed into the puncher in a follow-up slice.
    pub async fn try_nat_traversal(
        &self,
        target_node_id: [u8; 32],
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        per_coordinator_timeout: std::time::Duration,
    ) -> Option<veil_proto::control::NatProbeReplyPayload> {
        // Implementation lives on `NodeServices` so the production
        // outbound-dial path can call it
        // directly without going through this thin public wrapper.
        self.access()
            .try_nat_traversal(target_node_id, local_candidates, per_coordinator_timeout)
            .await
    }

    /// Thin wrapper over [`NodeServices::dht_recursive_get`]. audit cycle-6
    /// (T7): the implementation moved to `NodeServices` so the admin handler
    /// can run it on an Arc-cloned bundle without holding the runtime lock
    /// across the network await; this wrapper preserves the `NodeRuntime`-
    /// receiver call sites (sim scenarios).
    pub async fn dht_recursive_get(
        &self,
        key: [u8; 32],
        timeout: std::time::Duration,
    ) -> Option<Vec<u8>> {
        self.access().dht_recursive_get(key, timeout).await
    }

    /// Thin wrapper over [`NodeServices::resolve_identity_verified`] (see
    /// `dht_recursive_get` above for why the impl lives on NodeServices).
    pub async fn resolve_identity_verified(
        &self,
        node_id: [u8; 32],
        now_unix_secs: u64,
        timeout: std::time::Duration,
    ) -> std::result::Result<
        veil_identity::verify::ValidatedIdentity,
        veil_identity::resolver::ResolveError,
    > {
        self.access()
            .resolve_identity_verified(node_id, now_unix_secs, timeout)
            .await
    }

    /// Thin wrapper over [`NodeServices::resolve_name_verified`] (see
    /// `dht_recursive_get` above for why the impl lives on NodeServices).
    pub async fn resolve_name_verified(
        &self,
        name: &str,
        now_unix_secs: u64,
        timeout: std::time::Duration,
    ) -> std::result::Result<
        veil_identity::verify::ValidatedIdentity,
        veil_identity::resolver::ResolveError,
    > {
        self.access()
            .resolve_name_verified(name, now_unix_secs, timeout)
            .await
    }

    /// send a relay-mode `NatProbeRequest` through `coordinator`
    /// addressed at `target_node_id`, and await the matching
    /// `NatProbeReply` carrying the target's NAT candidates.
    ///
    /// This implements the SIGNALING half of NAT traversal — it does
    /// NOT do the actual UDP hole-punching. Returns the candidates the
    /// target advertised so the caller can drive the punch/dial directly
    /// (see `attempt_nat_traversal_via` / `nat_fallback_dial`). Returns
    /// `None` on timeout.
    ///
    /// Semantics:
    /// 1. Build a fresh `session_token` (16-bit random).
    /// 2. Register a oneshot under the token in `nat_probe_waiters`
    ///    so the dispatcher's `NatProbeReply` handler can wake us
    ///    when the matching reply arrives.
    /// 3. Build a `NatProbeRequestPayload` with `target_node_id`
    ///    = the peer we want to reach (relay mode), and our local
    ///    candidates.
    /// 4. Send the request frame to `coordinator` over the existing
    ///    session. Coordinator forwards dispatcher
    ///    logic. Target responds with its candidates and a reply
    ///    whose `final_target_node_id == our_node_id`.
    /// 5. Reply walks back: target → coordinator (forwards) → us.
    /// 6. Dispatcher fires our oneshot. We collect the reply +
    ///    drop the waiter.
    ///
    /// `local_candidates` should be the node's known interface
    /// addresses (host candidates) — caller wraps `NatCandidate` from
    /// `veil_proto::control` for whatever `SocketAddr`s it knows
    /// about. Empty Vec is allowed but defeats the purpose (the
    /// target wouldn't know where to send punch packets).
    pub async fn attempt_nat_traversal_via(
        &self,
        target_node_id: [u8; 32],
        coordinator_node_id: [u8; 32],
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        timeout: std::time::Duration,
    ) -> Option<veil_proto::control::NatProbeReplyPayload> {
        // Implementation lives on `NodeServices`; see `try_nat_traversal`.
        self.access()
            .attempt_nat_traversal_via(
                target_node_id,
                coordinator_node_id,
                local_candidates,
                timeout,
            )
            .await
    }

    /// drive NAT signaling toward `target_node_id`
    /// and promote the resulting candidate list into a priority-ordered
    /// vector of `TransportUri`s built by substituting the candidate's
    /// IP+port into the caller-supplied `template_uri`.
    ///
    /// The motivating scenario is **stale-bootstrap recovery**: a
    /// budget Android phone learned `peer X = tls://2.3.4.5:443` from
    /// the seed bundle weeks ago, but X has since rotated cellular
    /// IPs (typical for CGN-NAT operators that recycle the public
    /// pool every few hours). Direct dial against the cached URI
    /// fails. already gives us the signaling driver
    /// (`try_nat_traversal`); this method bolts the URI-rewrite step
    /// on top so the caller doesn't have to re-implement
    /// `NatCandidate → TransportUri` mapping on every fallback path.
    ///
    /// Why TLS *template*, not bare TCP: the candidate is just an
    /// IP+port pair, but the peer's identity is pinned to the SNI
    /// (and to ALPN'd OVL1). Building a fresh `tcp://` URI would
    /// downgrade the connection to plaintext and fail the veil
    /// handshake. The template carries scheme + crypto envelope
    /// forward; only host+port get rewritten.
    ///
    /// Why this method does NOT auto-attach the connection: the
    /// runtime's outbound-dial path is the production hot loop +
    /// owns peer-state mutation rules. Wiring auto-fallback into
    /// it is 's job (outbound-dial-failure auto-trigger).
    /// is intentionally compute-only: signaling + URI
    /// rewrite, no `registry.connect` call. Caller can iterate the
    /// returned URIs and pick whichever connect path it owns.
    ///
    /// Returns an empty Vec when:
    /// * signaling timed out (no coordinator reachable, target
    ///   unreachable through any coordinator);
    /// * the reply contained zero candidates;
    /// * every candidate's `atyp`/`addr` was malformed; or
    /// * the template URI is a variant where NAT is not meaningful
    ///   (`Unix`, `Socks*`, `Ws*`).
    pub async fn try_nat_traversal_promote_uris(
        &self,
        target_node_id: [u8; 32],
        template_uri: &veil_transport::TransportUri,
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        per_coordinator_timeout: std::time::Duration,
    ) -> Vec<veil_transport::TransportUri> {
        // Implementation lives on `NodeServices`; see `try_nat_traversal`.
        self.access()
            .try_nat_traversal_promote_uris(
                target_node_id,
                template_uri,
                local_candidates,
                per_coordinator_timeout,
            )
            .await
    }

    /// send an anonymous message to `target` via
    /// an N-hop onion-routed circuit. Closes the end-to-end SEND
    /// pipeline shipped across –6:
    ///
    /// 1. Snapshot candidate node_ids from local routing table.
    /// 2. Fetch each candidate's relay-directory entry from local
    ///    DHT cache (`dht_get_local(relay_directory_dht_key(...))`).
    /// 3. `discover_relay_hops` filters by signature + freshness
    /// + node_id-matches-DHT-key (anti-impersonation).
    /// 4. `build_outbound_anonymous_cell` picks `hop_count - 1`
    ///    relays (latency-aware via Vivaldi when available)
    ///    appends `target` as final hop, builds 512 B cell.
    /// 5. Cell hits the wire as a `RelayChain::Hop` frame to the
    ///    first hop's session.
    ///
    /// `hop_count` semantics: TOTAL hops INCLUDING target. See
    /// [`veil_anonymity::sender::build_outbound_anonymous_cell`]
    /// for the full hop-count → payload-budget mapping.
    ///
    /// `target_x25519_pk` must be the target's anonymity-hop key
    /// distinct from their OVL1 session-ECDH key. Caller obtains
    /// it through whatever mechanism fits the deployment: DHT
    /// lookup of the target's relay-directory entry (when the
    /// target is itself relay-capable), out-of-band exchange
    /// sovereign-identity bundle, etc.
    ///
    /// `target_app_id` + `target_endpoint_id` address the destination
    /// app endpoint at the receiver — same model as direct delivery
    /// (`AppMsg::AppSend`). Receiver's Final-hop dispatcher decodes
    /// the payload as an [`veil_proto::AppDeliverPayload`] and feeds
    /// it into the local `AppEndpointRegistry`
    /// so any IPC client bound to that endpoint receives the message
    /// through its existing `IncomingMessage` channel. No special
    /// "anonymity inbox" — apps don't need to know the message
    /// arrived through onion.
    ///
    /// `src_app_id` is the sender's app handle that the receiver sees
    /// in `IncomingMessage.src_app_id`. Pass `[0u8; 32]` to identify
    /// as "anonymous app" (receiver can identify only by content).
    /// `src_node_id` always wire'd as `[0u8; 32]` — the whole
    /// point of anonymity is to hide the sender's node_id; circuit
    /// design ensures the relays don't know it either.
    ///
    /// Errors out (without sending anything) when:
    /// * `hop_count == 0` or `> 5` (cell budget)
    /// * `data` (after AppDeliverPayload framing) exceeds the
    ///   per-hop-count cap
    /// * fewer than `hop_count - 1` usable relays found in our
    ///   local routing table + DHT cache.
    // chore: 8-arg signature — destination+payload+anonymity
    // shape is conceptually one tuple; refactoring into a struct adds
    // boilerplate without ergonomic gain. Explicit allow.
    #[allow(clippy::too_many_arguments)]
    pub fn send_anonymous(
        &self,
        target_node_id: [u8; 32],
        target_x25519_pk: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        src_app_id: [u8; 32],
        data: &[u8],
        hop_count: usize,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        self.access().send_anonymous(
            target_node_id,
            target_x25519_pk,
            target_app_id,
            target_endpoint_id,
            src_app_id,
            data,
            hop_count,
        )
    }

    /// Authenticated anonymous send (Epic 482 authenticated-onion v1).
    ///
    /// Like [`send_anonymous`], the source-routed onion hides the sender's
    /// network LOCATION from every relay on the path. UNLIKE it, the
    /// final-hop payload is an [`veil_proto::AuthAppDeliver`] carrying the
    /// sender's sovereign `node_id` plus a per-message identity-subkey
    /// signature (Ed25519 / Falcon-512), so the recipient can
    /// cryptographically verify WHO sent the message. The domain-separated
    /// signature binds `dst_node_id` (no re-targeting), `timestamp`
    /// (freshness) and a random `nonce` (replay) — see
    /// `veil_identity::auth_deliver::verify_auth_deliver`.
    ///
    /// One-way (sender → recipient); replies require the separate
    /// rendezvous flow. Requires a loaded sovereign identity, otherwise
    /// returns [`veil_anonymity::sender::SenderError::MissingSenderIdentity`].
    pub fn send_anonymous_authenticated(
        &self,
        target_node_id: [u8; 32],
        target_x25519_pk: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        data: &[u8],
        hop_count: usize,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        use rand_core::RngCore;

        let sovereign = self
            .identity
            .sovereign_identity
            .get()
            .ok_or(veil_anonymity::sender::SenderError::MissingSenderIdentity)?;

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Random per-message nonce — the recipient's replay cache keys on
        // (sender_node_id, nonce), so a fresh nonce each send is what makes
        // an intercepted-and-replayed cell detectable.
        let nonce = rand_core::OsRng.next_u64();

        let auth = sovereign.sign_auth_deliver(
            target_node_id,
            target_app_id,
            target_endpoint_id,
            now_unix,
            nonce,
            data.to_vec(),
            Vec::new(), // direct onion path: no reply blocks (r3 wires rendezvous replies)
        );
        let auth_bytes = auth.encode();
        // Final-hop tag byte: kind = APP_DELIVER_AUTH tells the receiver
        // dispatcher to decode an `AuthAppDeliver` (not a plain
        // `AppDeliverPayload`) and run sender verification before delivery.
        let mut payload_bytes = Vec::with_capacity(1 + auth_bytes.len());
        payload_bytes.push(veil_anonymity::rendezvous::final_hop_kind::APP_DELIVER_AUTH);
        payload_bytes.extend_from_slice(&auth_bytes);

        self.access().send_anonymous_onion(
            &payload_bytes,
            target_node_id,
            target_x25519_pk,
            hop_count,
        )
    }

    /// register an `auth_cookie` with the named
    /// rendezvous-relay node so inbound `IntroducePayload` frames
    /// matching that cookie are forwarded to us over the established
    /// OVL1 session.
    ///
    /// Caller MUST already have a live session to `rendezvous_node_id`
    /// — typically by adding it as a configured peer or by dialing
    /// out via `connect_peer(...)`. Without a session this is a
    /// silent no-op (no synchronous error — receiver learns from
    /// "no traffic flowing" timeout). Receiver's anonymity_x25519_pk
    /// is sent for audit/log purposes; the actual decryption uses
    /// the local `anonymity_x25519_sk`.
    ///
    /// Caller is responsible for periodically republishing the
    /// matching `RendezvousAd` to DHT with this cookie + this rendezvous'
    /// node_id + `receiver_x25519_pk`.
    pub fn register_with_rendezvous(&self, rendezvous_node_id: NodeId, auth_cookie: [u8; 16]) {
        use veil_anonymity::rendezvous::RegisterRendezvousPayload;
        use veil_proto::{
            codec::encode_header,
            family::{FrameFamily, RelayChainMsg},
            header::FrameHeader,
        };
        let receiver_x25519_pk =
            x25519_dalek::PublicKey::from(self.anonymity.x25519_sk.as_ref()).to_bytes();
        let req = RegisterRendezvousPayload {
            receiver_x25519_pk,
            auth_cookie,
        };
        let body = req.encode();
        let mut hdr = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::RegisterRendezvous as u16,
        );
        hdr.body_len = body.len() as u32;
        hdr.set_priority(veil_proto::priority::INTERACTIVE);
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(&body);
        if let Some(ref reg) = self.dispatcher.session_tx_registry {
            let guard = wlock!(reg);
            let _ = guard.send_to(
                rendezvous_node_id.as_bytes(),
                veil_proto::priority::INTERACTIVE,
                frame,
            );
        }
    }

    /// send an anonymous message via a rendezvous
    /// relay. Solves the CGN-NAT receiver problem: receiver does NOT
    /// need direct inbound reachability — only an outbound session to
    /// the rendezvous, which the receiver opens normally.
    ///
    /// `ad` carries everything the sender needs: rendezvous_node_id
    /// receiver_node_id, auth_cookie, receiver_x25519_pk. Sender
    /// builds an Introduce ciphertext encrypted to receiver_x25519_pk
    /// (rendezvous CANNOT decrypt — only the receiver can)
    /// wraps it as IntroducePayload, and sends through onion-routed
    /// Final-hop = rendezvous_node_id.
    ///
    /// Caller MUST verify `ad` (signature + freshness) before calling
    /// this — `verify_rendezvous_ad` + `is_currently_valid`. This
    /// helper trusts the caller did the verify.
    pub fn send_via_rendezvous(
        &self,
        ad: &veil_anonymity::rendezvous::RendezvousAd,
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        src_app_id: [u8; 32],
        data: &[u8],
        hop_count: usize,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        use veil_anonymity::rendezvous::final_hop_kind;

        // Step 1: build inner AppDeliverPayload (the bytes the
        // receiver's app eventually consumes). src_node_id zero —
        // anonymity guarantee.
        let app_deliver = veil_proto::AppDeliverPayload {
            src_node_id: [0u8; 32],
            src_app_id,
            app_id: target_app_id,
            endpoint_id: target_endpoint_id,
            data: veil_bufpool::pooled_shared_from_vec(data.to_vec()),
            reply_id: 0,
            // Sender-written, therefore worthless as a trust signal: the
            // receiver's final-hop handler decides provenance itself and
            // ignores this byte. Stated as `Claimed` so the wire never carries
            // a claim of proof.
            provenance: veil_proto::SenderProvenance::Claimed,
        };
        // Tag the sealed plaintext so the receiver can distinguish a plain
        // delivery from an authenticated one (`send_via_rendezvous_authenticated`
        // tags APP_DELIVER_AUTH). The tag is INSIDE the seal, so the rendezvous
        // relay never sees it.
        let app_deliver_bytes = app_deliver.encode();
        let mut sealed_plaintext = Vec::with_capacity(1 + app_deliver_bytes.len());
        sealed_plaintext.push(final_hop_kind::APP_DELIVER);
        sealed_plaintext.extend_from_slice(&app_deliver_bytes);

        self.access()
            // by-node_id unauthenticated send: recipient may be session-backed,
            // keep the real cleartext receiver id (L3).
            .send_sealed_introduce(ad, &sealed_plaintext, hop_count, false)
    }

    /// register a rendezvous publication. The
    /// runtime's maintenance tick will sign + DHT-store the
    /// corresponding `RendezvousAd` periodically (half-life refresh)
    /// so senders looking up `rendezvous_ad_dht_key(local_node_id)`
    /// always see a fresh entry.
    ///
    /// Caller MUST also have an OVL1 session open to `rendezvous_node_id`
    /// and have called `register_with_rendezvous` to register the cookie
    /// on the rendezvous side. This API only wires the DHT-publish
    /// half; the OVL1-session half is the caller's responsibility.
    ///
    /// Idempotent: registering a second entry with the same
    /// `(rendezvous_node_id, auth_cookie)` replaces the validity
    /// window in-place rather than duplicating.
    pub fn register_rendezvous_publisher(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
        validity_window_secs: u64,
    ) -> bool {
        self.register_rendezvous_publisher_with_push(
            rendezvous_node_id,
            auth_cookie,
            validity_window_secs,
            Vec::new(),
        )
    }

    /// Register this node as a LOCATION-anonymous service (onion-registration,
    /// the prod entry point). Picks a rendezvous relay R + `hop_count - 1`
    /// intermediate relays from the local relay directory, builds an onion
    /// circuit to R (registering a fresh cookie over it — `register_onion_circuit`,
    /// so R never learns our location), and publishes a `RendezvousAd` at
    /// (R, cookie, our x25519) so clients can reach us. The circuit is kept alive
    /// by the maintenance tick. `hop_count` is the circuit length (≥ 2 to hide
    /// our location from R itself; clamped to ≥ 2). Returns the published cookie.
    pub fn register_onion_service(
        &self,
        hop_count: usize,
    ) -> std::result::Result<[u8; 16], veil_types::AnonOnionSendError> {
        self.access().register_onion_service(hop_count)
    }

    /// Register a location-anonymous service under a random APPLICATION-owned
    /// Ed25519 identity instead of this node's sovereign identity. The public
    /// key is a `.onion`-like capability address: DHT records are blinded per
    /// period and reveal neither this node_id nor the sovereign public key.
    /// The seed stays zeroizing inside the runtime until withdrawn.
    pub fn register_ephemeral_onion_service(
        &self,
        identity_seed: zeroize::Zeroizing<[u8; 32]>,
        hop_count: usize,
    ) -> std::result::Result<[u8; 32], veil_types::AnonOnionSendError> {
        self.access()
            .register_ephemeral_onion_service(identity_seed, hop_count)
    }

    pub fn register_ephemeral_onion_service_with_provider_slot(
        &self,
        identity_seed: zeroize::Zeroizing<[u8; 32]>,
        hop_count: usize,
        provider_slot: u8,
    ) -> std::result::Result<[u8; 32], veil_types::AnonOnionSendError> {
        self.access()
            .register_ephemeral_onion_service_with_provider_slot(
                identity_seed,
                hop_count,
                provider_slot,
            )
    }

    /// Stop refreshing a previously registered ephemeral service. Existing
    /// descriptors/circuits age out naturally; the application must also drop
    /// capability requests immediately so revoke has no response oracle.
    pub fn withdraw_ephemeral_onion_service(&self, identity_vk: [u8; 32]) -> bool {
        self.access().withdraw_ephemeral_onion_service(identity_vk)
    }

    /// Send an authenticated anonymous message to a location-anonymous service
    /// addressed by its Ed25519 IDENTITY key, resolving its unlinkable blinded
    /// descriptor. See [`NodeServices::send_to_onion_service`].
    pub async fn send_to_onion_service(
        &self,
        service_identity_vk: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        data: &[u8],
        hop_count: usize,
        reply: Option<([u8; 32], u32)>,
    ) -> std::result::Result<(), veil_types::AnonOnionSendError> {
        self.access()
            .send_to_onion_service(
                service_identity_vk,
                target_app_id,
                target_endpoint_id,
                data,
                hop_count,
                reply,
            )
            .await
    }

    /// Send to a location-anonymous service by identity WITHOUT revealing the
    /// sender (`src_node_id = [0; 32]` at the service). See
    /// [`NodeServices::send_to_onion_service_anonymous`].
    pub async fn send_to_onion_service_anonymous(
        &self,
        service_identity_vk: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        src_app_id: [u8; 32],
        data: &[u8],
        hop_count: usize,
    ) -> std::result::Result<(), veil_types::AnonOnionSendError> {
        self.access()
            .send_to_onion_service_anonymous(
                service_identity_vk,
                target_app_id,
                target_endpoint_id,
                src_app_id,
                data,
                hop_count,
            )
            .await
    }

    /// same as [`Self::register_rendezvous_publisher`] but
    /// associates a sealed push envelope with the publication. The
    /// envelope (FCM/APNs token sealed for a trusted push-relay) is
    /// embedded in every signed ad refresh until [`Self::set_rendezvous_push_envelope`]
    /// updates it OR the entry is unregistered. Empty `push_envelope`
    /// is equivalent to the no-push API.
    ///
    /// Returns whether the registry now holds this entry: the publisher slots
    /// are bounded, and a registration past them would be cloned on every
    /// publish tick and never signed.
    pub fn register_rendezvous_publisher_with_push(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
        validity_window_secs: u64,
        push_envelope: Vec<u8>,
    ) -> bool {
        let entry = veil_anonymity::rendezvous::RendezvousPublisherEntry {
            rendezvous_node_id,
            auth_cookie,
            validity_window_secs,
            push_envelope,
            // .10 slice 4.3.2: defaults to empty (HMAC opt-out — receiver
            // upgrades via a separate IPC call wired in slice 4.3.3).
            wake_hmac_envelope: Vec::new(),
            // Defaults to "no relay key advertised"; the receiver upgrades via
            // `set_rendezvous_relay_kem` once it knows the relay's KEM pubkey.
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: Vec::new(),
            // Plain rendezvous receiver — signed under the sovereign identity.
            ephemeral_ad_identity: None,
            rendezvous_kem_valid_until_unix: 0,
        };
        // THROUGH THE ONE ADMISSION. This kept its own copy of "replace or
        // push", which meant it kept none of what that helper had been taught:
        // the slot bound (past it, an entry is cloned on every publish tick and
        // never signed), and the rule that a KEM-less re-registration must not
        // erase the key the app supplied — the erasure this very entry commits,
        // since it registers with `rendezvous_kem_pk: Vec::new()` and the
        // comment above it says the key arrives separately (report21 V18-L1).
        //
        // `insert_publisher_entry` refuses when the slots are full, and a
        // refusal is reported rather than silently pushed past.
        let mut entries = lock!(self.anonymity.rendezvous_publisher_entries);
        if !service_tasks::insert_publisher_entry(&mut entries, entry) {
            self.logger.info(
                "anonymity.rendezvous_publisher.no_slot",
                format!(
                    "a publisher registration took no slot (all {} in use); it \
                     would never have been published",
                    veil_anonymity::rendezvous::MAX_RENDEZVOUS_AD_SLOTS,
                ),
            );
            return false;
        }
        true
    }

    /// update only the push envelope on an existing
    /// rendezvous-publisher entry (matched by `rendezvous_node_id` +
    /// `auth_cookie`). Returns `true` if the entry was found and
    /// updated; `false` if no matching entry exists (caller should
    /// register first). Use this when the FCM/APNs token rotates or
    /// the user toggles push notifications on/off — pass empty `Vec`
    /// to clear push without disrupting the rendezvous publication.
    pub fn set_rendezvous_push_envelope(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
        push_envelope: Vec<u8>,
    ) -> bool {
        let mut entries = lock!(self.anonymity.rendezvous_publisher_entries);
        if let Some(entry) = entries
            .iter_mut()
            .find(|e| e.rendezvous_node_id == rendezvous_node_id && e.auth_cookie == auth_cookie)
        {
            entry.push_envelope = push_envelope;
            true
        } else {
            false
        }
    }

    /// Update only the wake-HMAC envelope on an existing rendezvous-
    /// publisher entry (Epic 489.10 slice 4.3.4 — analog to
    /// [`Self::set_rendezvous_push_envelope`]).  Matched by
    /// `(rendezvous_node_id, auth_cookie)`.  Returns `true` if the
    /// entry was found and updated; `false` if no matching entry
    /// exists (caller should register first).
    ///
    /// Use when the receiver's [`veil_crypto::wake_hmac::WakeHmacKey`]
    /// rotates (identity-epoch change OR opt-in / opt-out of HMAC
    /// wakeup).  Pass empty `Vec` to clear the envelope without disrupting
    /// the rendezvous publication (receiver falls back to the legacy
    /// rate-limited wake path).
    pub fn set_rendezvous_wake_hmac_envelope(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
        wake_hmac_envelope: Vec<u8>,
    ) -> bool {
        let mut entries = lock!(self.anonymity.rendezvous_publisher_entries);
        if let Some(entry) = entries
            .iter_mut()
            .find(|e| e.rendezvous_node_id == rendezvous_node_id && e.auth_cookie == auth_cookie)
        {
            entry.wake_hmac_envelope = wake_hmac_envelope;
            true
        } else {
            false
        }
    }

    /// Set the rendezvous RELAY's KEM key on an existing publisher entry
    /// (matched by `(rendezvous_node_id, auth_cookie)`), so the next signed ad
    /// refresh advertises it (v5 `rendezvous_kem_*`) and senders can anonymously
    /// deposit a mailbox PUT directly at the relay. `algo = 0` is X25519; `pk`
    /// is the relay's 32-byte X25519 pubkey (the same key the receiver sealed
    /// its push envelope to). Pass `(0, vec![])` to clear it (senders fall back
    /// to the live rendezvous path). Returns `true` if the entry was found.
    pub fn set_rendezvous_relay_kem(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
        relay_kem_algo: u8,
        relay_kem_pk: Vec<u8>,
    ) -> bool {
        let mut entries = lock!(self.anonymity.rendezvous_publisher_entries);
        if let Some(entry) = entries
            .iter_mut()
            .find(|e| e.rendezvous_node_id == rendezvous_node_id && e.auth_cookie == auth_cookie)
        {
            // The key, its algorithm AND its expiry move together, because
            // this call cannot say when the NEW key dies: leaving the old
            // stamp behind advertises a fresh key under the lifetime of the
            // one it replaced, which is the defect fixed in 0.11.3 arriving
            // through a different door (report21 V18-L1). Zero means "nobody
            // said", and the ad then runs on its own window until the caller
            // that knows the answer supplies it.
            let rotated = entry.rendezvous_kem_pk != relay_kem_pk;
            entry.rendezvous_kem_algo = relay_kem_algo;
            entry.rendezvous_kem_pk = relay_kem_pk;
            if rotated {
                entry.rendezvous_kem_valid_until_unix = 0;
            }
            true
        } else {
            false
        }
    }

    /// drop a rendezvous publication. Stops the
    /// maintenance tick from refreshing the corresponding ad; the
    /// existing ad in DHT will lapse naturally on `valid_until`.
    /// Returns `true` if the entry was found and removed.
    pub fn unregister_rendezvous_publisher(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
    ) -> bool {
        let mut entries = lock!(self.anonymity.rendezvous_publisher_entries);
        let before = entries.len();
        entries.retain(|e| {
            !(e.rendezvous_node_id == rendezvous_node_id && e.auth_cookie == auth_cookie)
        });
        before != entries.len()
    }

    /// Return all live attachment records from the local discovery directory.
    pub fn discovery_all_attachments(
        &self,
    ) -> Vec<veil_proto::discovery::AnnounceAttachmentPayload> {
        use veil_discovery::directory::all_attachments_alive;
        let dir = lock!(self.discovery.dir);
        all_attachments_alive(&dir)
    }

    /// test-only helper to publish an `AppEndpointEntry` through
    /// the local [`DiscoveryService`]. Goes through the normal path:
    /// local directory + (if role permits + DHT wired) signed DHT STORE.
    pub fn announce_local_app_endpoint(
        &self,
        entry: veil_discovery::directory::AppEndpointEntry,
    ) -> std::result::Result<(), String> {
        self.discovery
            .announce_app_endpoint(entry)
            .map_err(|e| e.to_string())
    }

    /// test-only helper to look up an `AppEndpointEntry` through
    /// the local [`DiscoveryService`]. Local-cache fast path + DHT fallback
    /// (with signature verification on signed-format records).
    pub fn lookup_local_app_endpoint(
        &self,
        node_id: [u8; 32],
        app_id: [u8; 32],
        endpoint_id: u32,
    ) -> veil_proto::discovery::AppEndpointResponse {
        self.discovery
            .handle_get_app_endpoint(veil_proto::discovery::GetAppEndpointPayload {
                node_id,
                app_id,
                endpoint_id,
            })
    }

    /// Return all node IDs currently attached to this gateway.
    pub fn gateway_attached_nodes(&self) -> Vec<[u8; 32]> {
        self.gateway.attached_nodes()
    }

    /// snapshot the leaf-side view of mesh state for the
    /// `node mesh-status` admin command. Returns one entry per
    /// auto-discovered gateway with everything an operator needs to
    /// answer "why am I (not) connected via X":
    /// * `is_active` — currently in `session_tx_registry`'s live set
    ///   so traffic actually flows through it.
    /// * `rtt_smoothed_ms` — pulled from `RttTable` (latest probe).
    /// * `battery_level` — the gateway's last self-reported beacon
    ///   value (`MeshBeaconPayload.battery_level`); 0 means
    ///   "AC / unknown".
    /// * `last_seen_secs_ago` / `expires_in_secs` — discovery entry
    ///   freshness.
    ///
    /// Sorted by `composite_score` ascending (best first), matching
    /// the ranking the auto-discover loop uses to pick which gateway
    /// to dial next. Empty when no `[mesh]` section is configured or
    /// the beacon receiver hasn't seen any gateways yet.
    pub fn mesh_gateway_status(&self) -> Vec<MeshGatewayStatusEntry> {
        let live_set = rlock!(self.session_tx_registry).active_node_ids();
        let live_gws = self.autodiscovered_peers.live_gateways();
        let rtt = lock!(self.routing.rtt_table);
        let now = std::time::Instant::now();

        let mut entries: Vec<MeshGatewayStatusEntry> = live_gws
            .into_iter()
            .map(|gw| {
                let probe = rtt.get(&gw.node_id);
                let rtt_smoothed_ms = probe.map(|p| p.rtt_smoothed);
                let battery_level = probe.map(|p| p.battery_level).unwrap_or(0);
                MeshGatewayStatusEntry {
                    node_id: gw.node_id,
                    veil_addr: gw.veil_addr,
                    is_active: live_set.contains(&gw.node_id),
                    rtt_smoothed_ms,
                    battery_level,
                    last_seen_secs_ago: now.saturating_duration_since(gw.last_seen).as_secs(),
                    expires_in_secs: gw.expires_at.saturating_duration_since(now).as_secs(),
                }
            })
            .collect();

        // Mirror the ranking used by `spawn_gateway_autodiscover_loop`:
        // best score first. See `gateway_score` in `mesh_gateway.rs`.
        entries.sort_by(|a, b| {
            let score = |e: &MeshGatewayStatusEntry| -> f64 {
                let rtt_ms = e.rtt_smoothed_ms.unwrap_or(500) as f64;
                let battery_penalty = if e.battery_level == 0 {
                    0.0
                } else {
                    (100u8.saturating_sub(e.battery_level)) as f64
                };
                rtt_ms + 5.0 * battery_penalty
            };
            score(a)
                .partial_cmp(&score(b))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        entries
    }

    /// Return `(dst, next_hop, score, hop_count)` for every non-expired route.
    pub fn route_cache_all(&self) -> Vec<veil_routing::cache::RouteSnapshot> {
        rlock!(self.routing.route_cache).all_routes_with_score()
    }

    /// snapshot the effective multi-path routing config for
    /// the admin `Routes` introspection. Mirrors the `[routing]` knobs
    /// that determine whether alternative `next_hop`s are actually used.
    /// Source of truth is `FrameDispatcher` — these fields are populated
    /// from `veil_cfg::RoutingConfig` at runtime construction and reload.
    pub fn multi_path_config(&self) -> (bool, u8, u8, bool, f64) {
        (
            self.dispatcher.multi_path_enabled,
            self.dispatcher.max_parallel_paths,
            self.dispatcher.multi_path_min_priority,
            self.dispatcher.redundant_send,
            self.dispatcher.ecmp_score_band,
        )
    }

    /// bootstrap-chain diag. Reads the persisted config off
    /// disk so the snapshot reflects edits the operator made since
    /// startup (no admin reload needed). Then derives:
    ///
    /// * Layer 1: `[[bootstrap_peers]]` count from config.
    /// * Layer 2: `node::bootstrap::builtin_seeds` count.
    /// * Layer 3: `global.bootstrap_dns_domain` (presence only — no
    ///   DNS probe; the operator can run `dig` themselves and a probe
    ///   here would block the admin handler on network I/O).
    /// * Layer 4: in-memory snapshot of the `DiscoveredPeerCache`.
    ///
    /// `healthy_layers` counts a layer as healthy if it has ≥1 entry
    /// (1, 2, 4) or is configured (3 — DNS). We can't tell from this
    /// snapshot whether DNS *resolves* without an actual probe; an
    /// empty DNS-domain string is the only failure we surface here.
    pub fn bootstrap_status(&self) -> crate::admin::AdminBootstrapStatus {
        use crate::admin::{AdminBootstrapStatus, AdminDiscoveredCacheStatus};

        let (
            config_peers,
            dns_domain,
            https_urls,
            announces_publicly,
            meeting_points,
            meeting_policy,
        ) = match veil_cfg::load_config(&self.config_path) {
            Ok(c) => (
                c.bootstrap_peers.len(),
                c.global
                    .bootstrap_dns_domain
                    .clone()
                    .filter(|s| !s.trim().is_empty()),
                c.global.bootstrap_https_urls.len(),
                c.global.bootstrap,
                c.global.meeting_points.clone(),
                c.global.meeting_policy,
            ),
            // Reload failure shouldn't bring down the diag — fall back
            // to "0 / None" so the operator at least sees the cache and
            // builtin counts. A separate err log surfaces the cause.
            Err(e) => {
                self.logger.warn(
                    "bootstrap.status.config_load_failed",
                    format!("falling back to in-runtime view: {e}"),
                );
                // False on a read failure, and that is the safe direction:
                // claiming "I announce" when the config could not be read
                // would tell an operator they are visible when nobody knows.
                (
                    0,
                    None,
                    0,
                    false,
                    veil_cfg::MeetingPoints::Preset(veil_cfg::MeetingPointsPreset::Off),
                    veil_cfg::MeetingPolicy::default(),
                )
            }
        };

        let builtin_seeds = veil_bootstrap::builtin_seeds().len();

        let cache_guard = lock!(self.discovered_peers_cache);
        let cache_path_str = {
            let p = cache_guard.path();
            (!p.as_os_str().is_empty()).then(|| p.display().to_string())
        };
        let persistent = cache_path_str.is_some();
        let cache_entries = cache_guard.len();
        let timestamp_range = cache_guard.timestamp_range();
        drop(cache_guard);
        // Compute relative ages from the wall-clock at request time.
        // Unix-epoch arithmetic uses saturating_sub so a clock skew
        // (NTP just stepped backwards, or a peer's `last_seen_unix`
        // is in the future for any reason) renders as `0` rather
        // than panicking.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (oldest_secs_ago, freshest_secs_ago) = match timestamp_range {
            Some((oldest, freshest)) => (
                Some(now_unix.saturating_sub(oldest)),
                Some(now_unix.saturating_sub(freshest)),
            ),
            None => (None, None),
        };
        let discovered_cache = AdminDiscoveredCacheStatus {
            persistent,
            path: cache_path_str,
            entries: cache_entries,
            freshest_secs_ago,
            oldest_secs_ago,
        };

        let healthy_layers = (config_peers > 0) as u8
            + (builtin_seeds > 0) as u8
            + (https_urls > 0) as u8
            + dns_domain.is_some() as u8
            + (discovered_cache.entries > 0) as u8
            + meeting_points.enabled().len() as u8;

        AdminBootstrapStatus {
            config_peers,
            builtin_seeds,
            https_urls,
            dns_domain,
            discovered_cache,
            healthy_layers,
            total_layers: 5 + veil_cfg::MeetingPoint::ALL.len() as u8,
            announces_publicly,
            meeting_points_enabled: meeting_points.enabled().len() as u8,
            meeting_points: meeting_points.to_string(),
            meeting_policy: meeting_policy.to_string(),
        }
    }

    // ── Route discovery ────────────────────────────────────────────

    /// stage (b) B5: driver for the admin
    /// `node swap-transport` command. Parses `peer_node_id` as
    /// 64-hex, confirms the peer has a live session (by looking up
    /// its session_id + tx_key in the session registry), then spawns
    /// a one-shot warm probe that dials `alt_uri` and runs the
    /// three-frame handoff protocol.
    ///
    /// Success = runtime emitted HandoffInit, peer ack-ed, warm
    /// HandoffAttach was written, and both sides swapped.
    ///
    /// Errors: invalid hex, unknown peer, no active session, dial
    /// refused, ack timeout, swap-channel lost. All are mapped to
    /// `NodeError::InvalidArgument` / `Unsupported` so the admin
    /// response carries a human-readable diagnosis.
    /// Build the warm-probe config for an admin-driven hot-standby handoff.
    ///
    /// cycle-7 (MED): split out of the old `initiate_hot_standby_handoff` so the
    /// SwapTransport admin handler can DROP the global runtime lock BEFORE
    /// driving the multi-step handoff (see [`Self::run_hot_standby_handoff`]).
    /// This prep is purely synchronous (parse + swap-registry lookup + Arc
    /// clones into a self-contained `WarmProbeConfig`); the old code held the
    /// runtime mutex across the handoff's warm-dial + HandoffAck round-trip
    /// (with AckTimeout), stalling every other runtime-lock user for seconds.
    pub(crate) fn prepare_hot_standby_handoff(
        &self,
        peer_node_id_hex: &str,
        alt_uri: &str,
    ) -> crate::error::Result<veil_session::warm_probe::WarmProbeConfig> {
        use crate::error::NodeError;
        use veil_session::warm_probe::WarmProbeConfig;
        use veil_transport::TransportUri;

        // Parse peer_node_id (64 hex → 32 bytes).
        let peer_id_bytes: [u8; 32] = {
            let trimmed = peer_node_id_hex
                .strip_prefix("0x")
                .unwrap_or(peer_node_id_hex);
            if trimmed.len() != 64 {
                return Err(NodeError::InvalidArgument(format!(
                    "peer_node_id must be 64 hex chars, got {} in {peer_node_id_hex:?}",
                    trimmed.len(),
                )));
            }
            let mut buf = [0u8; 32];
            for (i, b) in buf.iter_mut().enumerate() {
                let hi = (trimmed.as_bytes()[i * 2] as char).to_digit(16);
                let lo = (trimmed.as_bytes()[i * 2 + 1] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => *b = ((h << 4) | l) as u8,
                    _ => {
                        return Err(NodeError::InvalidArgument(format!(
                            "peer_node_id contains non-hex chars: {peer_node_id_hex:?}"
                        )));
                    }
                }
            }
            buf
        };

        // Parse alt_uri.
        let alt = TransportUri::parse(alt_uri)
            .map_err(|e| NodeError::InvalidArgument(format!("invalid alt_uri {alt_uri:?}: {e}")))?;

        // Resolve the peer to a live session via the swap registry's
        // secondary peer-index — this always reflects the CURRENTLY
        // running runner (registered at its spawn, unregistered at its
        // drop), avoiding the handshake-race divergence that
        // `SessionRegistry::get_by_peer_id` exhibits when outbound +
        // inbound race and dedup picks different sides.
        let session_id = self
            .handoff
            .swap_registry
            .session_id_for_peer(&peer_id_bytes.into())
            .ok_or_else(|| {
                NodeError::InvalidArgument(format!(
                    "no live session with hot-standby registration for peer={peer_node_id_hex}"
                ))
            })?;
        let tx_key = self
            .handoff
            .swap_registry
            .tx_key(&session_id)
            .ok_or_else(|| {
                NodeError::Unsupported(
                    "session has swap-registry entry but no tx_key — inconsistent state".into(),
                )
            })?;

        // Build probe config and drive the one-shot.
        let cfg = WarmProbeConfig {
            session_id,
            peer_id: peer_id_bytes.into(),
            tx_key,
            alt_uri: alt,
            transport_registry: Arc::clone(&self.registry),
            transport_ctx: Arc::clone(&self.transport_ctx),
            session_tx_registry: Arc::clone(&self.session_tx_registry),
            handoff_ack_waiters: Arc::clone(&self.handoff.ack_waiters),
            swap_registry: Arc::clone(&self.handoff.swap_registry),
            // Admin-driven swap uses defaults; the `enabled` field is
            // not consulted here (the command itself is the opt-).
            // Timeouts and max_swaps_per_minute are still honored.
            hot_standby: veil_cfg::HotStandbyConfig::default(),
        };
        Ok(cfg)
    }

    /// Drive an admin-prepared hot-standby handoff to completion. Associated
    /// fn (no `&self`) so it runs WITHOUT the runtime lock held — the
    /// `WarmProbeConfig` is fully self-contained (Arc clones made under the
    /// lock in `prepare_hot_standby_handoff`). cycle-7 (MED).
    pub(crate) async fn run_hot_standby_handoff(
        cfg: veil_session::warm_probe::WarmProbeConfig,
    ) -> crate::error::Result<()> {
        use crate::error::NodeError;
        use veil_session::warm_probe::{WarmProbeError, spawn_warm_probe};
        let handle = spawn_warm_probe(cfg);
        handle.initiate_handoff().await.map_err(|e| match e {
            WarmProbeError::Dial(msg) => NodeError::Unsupported(format!("warm dial failed: {msg}")),
            WarmProbeError::PrimarySendFailed => {
                NodeError::Unsupported("primary session outbox not reachable".into())
            }
            WarmProbeError::AckTimeout(d) => {
                NodeError::Unsupported(format!("HandoffAck timeout after {d:?}"))
            }
            WarmProbeError::AttachWrite(msg) => {
                NodeError::Unsupported(format!("HandoffAttach write: {msg}"))
            }
            WarmProbeError::RunnerGone => {
                NodeError::Unsupported("session runner exited during handoff".into())
            }
            WarmProbeError::ProbeGone => {
                NodeError::Unsupported("warm probe task exited unexpectedly".into())
            }
        })
    }

    /// Signal the discovery initiator to run a search immediately.
    ///
    /// Returns `Err(NodeError::Unsupported)` until wires up the
    /// discovery initiator background task.
    ///
    pub fn trigger_discovery_search(&self) -> crate::error::Result<()> {
        let guard = lock!(self.discovery_trigger_tx);
        match guard.as_ref() {
            Some(tx) => {
                // Non-blocking: if the buffer is full the node is already
                // processing a refresh — silently drop the duplicate request.
                let _ = tx.try_send(());
                Ok(())
            }
            None => Err(crate::error::NodeError::Unsupported(
                "discovery initiator not yet started".into(),
            )),
        }
    }

    /// app-endpoint registry handle for binding local
    /// endpoints (sim integration tests + future IPC code paths).
    /// Receivers `register(app_id, endpoint_id, capacity)` here to
    /// receive `AppMessage::Deliver` from both direct delivery and
    /// onion-routed Final-hop delivery.
    pub fn app_registry(&self) -> &Arc<AppEndpointRegistry> {
        &self.app_registry
    }

    /// the anonymity X25519 public key, derived from the
    /// per-startup secret. Returns `Some` ONLY when the operator opted
    /// in to `[anonymity].relay_capable = true` (which makes the node
    /// eligible as a circuit hop AND publishes a signed relay-directory
    /// entry AND lets the dispatcher actually decrypt incoming onion
    /// frames addressed to this key). Returns `None` for non-relay
    /// nodes — the dispatcher's `anonymity_x25519_sk: Option<...>` is
    /// the gate that actually decrypts inbound onions, so leaking the
    /// pubkey for non-relays would mislead senders into encrypting
    /// messages that the receiver's dispatcher would silently drop.
    pub fn anonymity_x25519_pk(&self) -> Option<[u8; 32]> {
        if self.dispatcher.anonymity_x25519_sk.is_some() {
            Some(x25519_dalek::PublicKey::from(self.anonymity.x25519_sk.as_ref()).to_bytes())
        } else {
            None
        }
    }

    /// Return all anycast service tags this node is advertising in the DHT.
    ///
    /// Returns `(service_tag_hex, candidate_count)` pairs.
    /// PEX status snapshot for the admin socket.
    pub fn pex_status(&self) -> (usize, u32, Option<std::time::Instant>) {
        let state = lock!(self.pex.state);
        (
            state.public_peer_count(),
            state.active_walks,
            state.last_walk_at,
        )
    }

    /// tear down every active session and wake all
    /// outbound-connector loops so they re-handshake immediately on the
    /// new local interface. Called from `MobileEventForwarder::network_changed`
    /// when the OS reports a Wi-Fi ↔ cellular flip — recovery latency
    /// drops from ~30-90 s (TCP keepalive timeout) to ~1-3 s (new TCP
    /// RT + SESSION_TICKET resume RT). Returns the number of peers
    /// whose sessions were unregistered.
    pub fn force_reconnect_all_peers(&self) -> usize {
        let peer_ids: Vec<[u8; 32]> = {
            let reg = rlock!(self.session_tx_registry);
            reg.active_node_ids().into_iter().collect()
        };
        let count = {
            let mut reg = wlock!(self.session_tx_registry);
            for pid in &peer_ids {
                reg.unregister(pid);
            }
            peer_ids.len()
        };
        self.force_reconnect_notify.notify_waiters();
        if count > 0 {
            self.logger.info(
                "force_reconnect_all_peers",
                format!("unregistered={count} (network-change recovery)"),
            );
        }
        count
    }

    /// In-memory equivalent of `peers_discovered.json`: everything in
    /// `state.peers` whose `source!= Configured`.
    pub fn discovered_peers(&self) -> Vec<crate::admin::AdminDiscoveredPeer> {
        let state = lock_state(&self.state);
        state
            .peers
            .values()
            .filter(|e| !matches!(e.source, crate::types::PeerSource::Configured))
            .map(|e| crate::admin::AdminDiscoveredPeer {
                node_id: e.node_id.to_string(),
                transport: e.transport.clone(),
                source: e.source.to_string(),
                peer_id: e.peer_id.get(),
                bootstrap_only: e.bootstrap_only,
                public_key: e.public_key.clone(),
                nonce: e.nonce.clone(),
            })
            .collect()
    }
}

impl NodeRuntime {
    /// Subscribe to live frame capture events from the dispatcher.
    ///
    /// If no capture is currently active, this activates it (creates the
    /// broadcast channel and installs it in the dispatcher). Multiple
    /// concurrent subscribers are supported (broadcast semantics).
    pub fn subscribe_capture(
        &mut self,
    ) -> tokio::sync::broadcast::Receiver<veil_dispatcher::CaptureEvent> {
        let mut slot = lock!(self.dispatcher.capture_tx);
        if let Some(ref tx) = *slot {
            return tx.subscribe();
        }
        // First subscriber — create the broadcast channel and install it in the
        // shared slot. All running sessions share the same Arc<Mutex<Option<…>>>
        // so they will see the new sender immediately.
        let (tx, rx) = tokio::sync::broadcast::channel(512);
        *slot = Some(tx);
        // Flip the fast-path flag so dispatch skips the mutex on every frame.
        self.dispatcher
            .capture_active
            .store(true, std::sync::atomic::Ordering::Release);
        rx
    }
}

pub fn build_state(
    config: &Config,
    config_path: PathBuf,
    foreground_mode: bool,
    started_at: Instant,
    metrics_active: bool,
    metrics_endpoint: Option<String>,
) -> Result<NodeState> {
    let identity = config
        .identity
        .as_ref()
        .ok_or(veil_cfg::ConfigError::MissingIdentityField("Identity"))?;
    let node_id = identity.node_id.unwrap_or(NodeId::from_public_key(
        identity.algo,
        &identity.public_key,
    )?);
    let role = identity.role;

    let peers = config
        .peers
        .iter()
        .map(|peer| {
            Ok(PeerConfigEntry {
                peer_id: peer.peer_id,
                node_id: NodeId::from_public_key(peer.algo, &peer.public_key)?,
                public_key: peer.public_key.clone(),
                nonce: peer.nonce.clone(),
                transport: peer.transport.clone(),
                algo: peer.algo,
                tls_cert: peer.tls_cert.clone(),
                tls_key: peer.tls_key.clone(),
                tls_ca_cert: peer.tls_ca_cert.clone(),
                bootstrap_only: false,
                source: crate::types::PeerSource::Configured,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let listens = config
        .listen
        .iter()
        .map(|listen| ListenConfigEntry {
            listen_id: listen.id,
            listener_handle: None,
            transport: listen.transport.clone(),
            advertise: listen.advertise.clone(),
            relay: listen.relay.clone(),
            tls_cert: listen.tls_cert.clone(),
            tls_key: listen.tls_key.clone(),
            tls_ca_cert: listen.tls_ca_cert.clone(),
            psk_file: listen.psk_file.clone(),
            visibility: listen.visibility.clone(),
            allowlist_node_ids: listen.allowlist_node_ids.clone(),
            group_label: listen.group_label.clone(),
            ephemeral: listen.ephemeral.clone(),
            on_demand: listen.on_demand.clone(),
            local_addr: None,
            active: false,
        })
        .collect::<Vec<_>>();

    Ok(NodeState::new(
        node_id,
        role,
        config_path,
        foreground_mode,
        started_at,
        metrics_active,
        metrics_endpoint,
        peers,
        listens,
    ))
}

pub fn spawn_inbound_session(
    inbound: InboundSessionContext,
    connection: Box<dyn veil_transport::TransportConnection>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // B5: Ok(None) means the inbound connection was bound
        // to an existing session via HandoffAttach — no new runner to
        // spawn, the existing one picked up the warm socket. Ok(Some)
        // is the normal fresh-session path.
        if let Ok(Some(session)) = register_connection_session(
            inbound.runtime.clone(),
            SessionSource::Inbound(inbound.listen_id),
            None,
            Some(inbound.listener_handle),
            SessionState::Active,
            connection,
            false,
        )
        .await
        {
            let dispatcher = Arc::clone(&inbound.runtime.dispatcher);
            let ban_list = Arc::clone(&dispatcher.abuse.ban_list);
            let violation_tracker = Arc::clone(&dispatcher.abuse.violation_tracker);
            // Both ciphers use is_tx=true (same dir_salt) so that the local tx_cipher
            // and the remote rx_cipher — which share the same key — use identical
            // nonces and can decrypt each other's output. Since tx_key!= rx_key
            // there is no nonce collision between the two directions.
            let (tx_cipher, rx_cipher, session_id, raw_tx_key, raw_rx_key) = {
                let keys = session.session_keys;
                let tx_key = keys.tx_key;
                let rx_key = keys.rx_key;
                (
                    Some(veil_crypto::session_cipher::SessionCipher::new(
                        &tx_key, true,
                    )),
                    Some(veil_crypto::session_cipher::SessionCipher::new(
                        &rx_key, true,
                    )),
                    keys.session_id,
                    tx_key,
                    rx_key,
                )
            };
            let peer_id = session.peer_id;
            // session resumption is always enabled post-removal
            // of NegotiatedCapabilities. Issue a ticket unconditionally.
            //
            // The ticket names WHICH DEVICE of the peer it was issued to. It
            // used to be hardcoded `[0; 16]`, and that sentinel is the reason a
            // resumed session could not tell one device of an identity from
            // another: with no device in the ticket, the fast path fell back to
            // a per-peer binding that every sibling overwrote in turn. `None`
            // (peer proved no sovereign identity, or the resumption could not
            // resolve a device) keeps the sentinel, which the issuer now reads
            // as "do not resume this if the peer has known devices".
            let peer_instance = session.peer_instance_id.unwrap_or([0u8; 16]);
            let ticket_to_send = {
                let blob = lock!(inbound.runtime.resumption.ticket_issuer).issue_for_instance(
                    session_id,
                    peer_id,
                    peer_instance,
                    raw_tx_key,
                    raw_rx_key,
                );
                Some(blob)
            };
            // consume the receiver pre-reserved
            // by `try_register_unique` in the cap+dup atomic critical
            // section. Replaces the old second-register pattern that
            // had a TOCTOU window between dup-check and registration.
            let is_referral = session.referral;
            let outbox_rx = session.reserved_outbox_rx;
            let rpc_rx = inbound
                .runtime
                .session_outbox
                .register_owned(peer_id, session_id);
            let mut runner = veil_session::runner::SessionRunner {
                stream: session.stream,
                quic_datagrams: session.quic_datagrams,
                peer_id: *peer_id.as_bytes(),
                dispatcher,
                logger: Arc::clone(&inbound.runtime.logger),
                metrics: inbound.runtime.metrics.clone(),
                ban_list,
                violation_tracker,
                crypto: veil_session::runner::CryptoState {
                    tx_cipher,
                    rx_cipher,
                    peer_mlkem_keys: Some(Arc::clone(&inbound.runtime.identity.peer_mlkem_keys)),
                    per_session_mlkem_dk: Some(Arc::clone(
                        &inbound.runtime.identity.per_session_mlkem_dk,
                    )),
                },
                outbox: Some(outbox_rx),
                rpc_outbox: Some(rpc_rx),
                keepalive_interval: inbound.runtime.defaults.keepalive_interval,
                idle_timeout: inbound.runtime.defaults.idle_timeout,
                max_pending_responses: inbound.runtime.defaults.max_pending_responses,
                pending_response_ttl: inbound.runtime.defaults.pending_response_ttl,
                max_frame_body: inbound.runtime.defaults.max_frame_body,
                rekey: veil_session::runner::RekeyConfig {
                    bytes_threshold: inbound.runtime.defaults.rekey_bytes_threshold,
                    time_threshold_secs: inbound.runtime.defaults.rekey_time_threshold_secs,
                },
                qos_weights: inbound.runtime.defaults.qos_weights,
                session_id,
                local_node_id: inbound.runtime.dispatcher.local_node_id,
                mobile: veil_session::runner::MobileConfig {
                    base_keepalive_interval: inbound.runtime.defaults.keepalive_interval,
                    battery_keepalive_scale_low: inbound.runtime.mobile.battery_keepalive_scale_low,
                    battery_keepalive_scale_medium: inbound
                        .runtime
                        .mobile
                        .battery_keepalive_scale_medium,
                    battery_threshold_low: inbound.runtime.mobile.battery_threshold_low,
                    battery_threshold_medium: inbound.runtime.mobile.battery_threshold_medium,
                },
                ticket_to_send,
                peer_tickets: Some(Arc::clone(&inbound.runtime.resumption.peer_tickets)),
                // stage (d): raw keys are needed by the handoff
                // path on BOTH sides of a session so that the runner can
                // stash rx_key into HandoffRegistry entries and seal the
                // HandoffAttach HMAC with tx_key. Previously server-only
                // `None` was fine (the field was client-only for ticket
                // issuance). Populated here verbatim from the handshake's
                // derived keys.
                raw_session_keys: Some((raw_tx_key, raw_rx_key, session_id)),
                peer_public_key: None,
                peer_nonce: None,
                hot_standby: veil_session::runner::HotStandbyState {
                    swap_registry: None,
                    swap_rx: None,
                    handoff_registry: Some(Arc::clone(&inbound.runtime.handoff.registry)),
                    handoff_ack_waiters: Some(Arc::clone(&inbound.runtime.handoff.ack_waiters)),
                    controller: Some(Arc::clone(&inbound.runtime.handoff.controller)),
                    auto_trigger_after_write_errors: inbound
                        .runtime
                        .handoff
                        .auto_trigger_after_write_errors,
                },
                // Inbound side: we accepted a connection but don't have a
                // dialable URI for the peer (their source IP+port is
                // ephemeral — see `inbound_transport` doc below).  Rotation-
                // initiation always comes from the outbound side, so leaving
                // this `None` is correct (server side accepts handoffs but
                // doesn't initiate them).
                primary_uri: None,
            };
            // add the handshaken peer to our DHT routing
            // table so recursive FIND_NODE queries see it as a candidate
            // next-hop — otherwise direct-peer lookups miss and
            // split-horizon drops the query with next_hops=0.
            // For inbound connections we don't know the peer's advertised
            // transport URI, so use the observed socket address as a
            // best-effort placeholder (DHT lookups pivot on node_id, not
            // transport, so this is only used for bucket-eviction eligibility).
            let inbound_transport = session
                .observed_addr
                .map(|a| format!("tcp://{a}"))
                .unwrap_or_default();
            // stamp the peer's last-known `discovery_mode` so
            // `handle_find_node_v2` can filter them out of FIND_NODE responses
            // if they prefer to stay hidden from DHT-walks.
            inbound.runtime.dispatcher.dht.add_contact_trusted(
                veil_dht::routing::Contact::from_handshake(
                    *peer_id.as_bytes(),
                    inbound_transport.clone(),
                    session
                        .remote_caps_stated
                        .then_some((session.remote_discovery_mode, session.remote_dht_service)),
                ),
            );
            // promote any unverified candidate for this
            // peer_id into the verified routing table — handshake
            // completion is the proof of node_id/key ownership the
            // 2-tier scheme requires.
            let _promoted = inbound
                .runtime
                .dispatcher
                .dht
                .promote_contact_if_pending(peer_id.as_bytes());
            inbound.runtime.logger.info(
                "dht.peer_added",
                format!(
                    "inbound handshake → peer={} transport={}",
                    veil_util::hex_short(peer_id.as_bytes()),
                    veil_util::redact_addr_for_log(&inbound_transport),
                ),
            );
            inbound.runtime.dispatcher.on_session_opened(
                *peer_id.as_bytes(),
                session.observed_addr,
                session.udp_reflector_port,
                &session.shared_udp_reflectors,
            );
            //gossip our self-signed transport
            // announcement to the new peer so they can return it to
            // future walkers asking `ResolveTransport(local_node_id)`.
            // Fire-and-forget — failure to deliver just means they'll
            // serve `not_found` for us until the next handshake.
            send_local_announcement(
                &inbound.runtime.dispatcher.dht,
                &inbound.runtime.session_outbox,
                *peer_id.as_bytes(),
            );
            // 145.3: immediately probe inbound peers we already know.
            NodeRuntime::send_startup_probe_if_known(
                &inbound.runtime.rtt_table,
                &inbound.runtime.session_tx_registry,
                peer_id,
                false, // inbound — probe only if we have prior contact history
            );
            // stage (d) Task 4a: register the runner's swap_rx
            // in the runtime's session_id → swap_tx map. Guard is held
            // for the lifetime of the runner; its Drop clears the entry
            // when the session exits (any path, including panic), so
            // accept-side lookups on a dead session fail fast.
            let _swap_guard = runner.register_swap_channel(&inbound.runtime.handoff.swap_registry);
            if is_referral {
                // Transient referral session (accepted into the headroom above
                // max_concurrent): cap its lifetime so the headroom frees and
                // the per-node data ceiling stays effectively hard. The timeout
                // cancels the run() future, but the cleanup below STILL executes
                // (graceful — unlike a task abort, so no stale tx_registry /
                // dispatcher per-peer state). The client received a peer-gossip
                // sample on session-open and migrates to a freer node.
                let _ = tokio::time::timeout(REFERRAL_SESSION_TTL, runner.run()).await;
            } else {
                runner.run().await;
            }
            drop(_swap_guard);
            // Owner-aware teardown: our own registrations go
            // unconditionally, the peer-wide state only if this session
            // is still the peer's owner. A reconnect that replaced us
            // owns that state now. See `session_guard::release_session`.
            session_guard::release_session(
                session_guard::SessionRelease {
                    session_tx_registry: &inbound.runtime.session_tx_registry,
                    session_outbox: &inbound.runtime.session_outbox,
                    session_close_generations: &inbound.runtime.session_close_generations,
                    identity: &inbound.runtime.identity,
                    dispatcher: &inbound.runtime.dispatcher,
                    logger: &inbound.runtime.logger,
                },
                peer_id,
                &session_id,
                is_referral,
            );
            let _ = runner.stream.shutdown().await;
        }
    })
}

// oncurrency-the legacy
// `decrement_ip_slot` helper has been replaced by the `IpSlotGuard`
// RAII type below. All synchronous error-returns and async-
// cancellation paths now release the slot via Drop, eliminating
// the leak vector documented in the original audit.

// d removed `sovereign_cache_revoked` — the persistent
// revocation cache it consulted is gone. Cached sovereign bindings
// from the resumption fast path are now trusted unconditionally; a
// compromised subkey is mitigated by the document's short
// `valid_until_unix` window (the next full handshake re-verifies the
// document and rejects expired ones).

pub fn listen_transport_context(
    base: &TransportContext,
    listen: &ListenConfigEntry,
) -> Result<TransportContext> {
    let mut ctx = base.clone();
    if let Some(path) = listen.tls_ca_cert.as_deref() {
        ctx = ctx.with_trusted_certificates_from_file(Path::new(path))?;
    }
    if let (Some(cert), Some(key)) = (listen.tls_cert.as_deref(), listen.tls_key.as_deref()) {
        ctx = ctx.with_server_identity_from_files(Path::new(cert), Path::new(key))?;
    }
    // Per-listener PSK override.  When the listen entry specifies its
    // own `psk_file`, load that 32-byte PSK and override the cloned ctx's
    // `obfs4_psk`.  `Obfs4TcpTransport::bind` will then use the
    // listener-specific PSK for verifying inbound MACs.  When not set,
    // the global PSK from `transport.obfs4_psk_file` is preserved.
    if let Some(ref path) = listen.psk_file {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as BASE64;
        let raw = std::fs::read_to_string(path).map_err(|e| {
            veil_cfg::ConfigError::ValidationFailed(format!(
                "listen {} psk_file: read {}: {e}",
                listen.listen_id,
                path.display()
            ))
        })?;
        let decoded = BASE64.decode(raw.trim()).map_err(|e| {
            veil_cfg::ConfigError::ValidationFailed(format!(
                "listen {} psk_file: invalid base64 in {}: {e}",
                listen.listen_id,
                path.display()
            ))
        })?;
        if decoded.len() != 32 {
            return Err(veil_cfg::ConfigError::ValidationFailed(format!(
                "listen {} psk_file: expected 32 bytes, got {} in {}",
                listen.listen_id,
                decoded.len(),
                path.display()
            ))
            .into());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        ctx.obfs4_psk = Some(std::sync::Arc::new(key));
    }
    Ok(ctx)
}

/// Option C (obfs4 PSK): derive a listener's anti-probe `node_id_mac_key` from
/// the node's **public** identity (`vk` + `node_id`) when no explicit PSK is
/// configured. A client derives the SAME key from the invite's `vk`/`nid`, so
/// the handshake succeeds with nothing secret generated, stored, or shared.
///
/// Returns `None` — leaving any configured PSK / disabling obfs4 — when:
/// - the listener already has a PSK (explicit `psk_file` is the legacy override),
/// - the transport isn't obfs4, or
/// - the identity isn't Ed25519. The invite path is Ed25519-only
///   ([`veil_invite::create_bundle`] signs with ed25519-dalek), so a PQ node has
///   no matching invite to agree with; such an operator must set `psk_file`.
///
/// `node_id` MUST equal `BLAKE3(STANDARD-decode(public_key_b64))` — the same
/// `vk`/`nid` an invite embeds — which holds for a node's own identity by
/// construction ([`veil_cfg::NodeId::from_public_key`]).
pub(crate) fn derive_listener_obfs4_psk(
    transport: &str,
    already_has_psk: bool,
    algo: veil_cfg::SignatureAlgorithm,
    public_key_b64: &str,
    node_id: &[u8; 32],
) -> Option<[u8; 32]> {
    use base64::Engine as _;
    if already_has_psk
        || algo != veil_cfg::SignatureAlgorithm::Ed25519
        || !transport.starts_with("obfs4")
    {
        return None;
    }
    let vk = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64)
        .ok()?;
    Some(veil_obfs4::NodeIdMacKey::derive_from_identity(&vk, node_id).0)
}

#[cfg(test)]
mod listen_visibility_tests {
    use super::*;
    use veil_cfg::{Config, ListenConfig, ListenId, Visibility};

    fn make_listen(id: u32, transport: &str, advertise: &str, vis: Visibility) -> ListenConfig {
        ListenConfig {
            id: ListenId::new(id),
            transport: transport.to_owned(),
            advertise: Some(advertise.to_owned()),
            visibility: vis,
            ..Default::default()
        }
    }

    // ── Option C: identity-derived obfs4 PSK ─────────────────────────────────

    /// A sample Ed25519 vk (b64) + its node_id, matching the invite invariant.
    fn sample_identity() -> (String, [u8; 32]) {
        use base64::Engine as _;
        let vk = [0x11u8; 32];
        let vk_b64 = base64::engine::general_purpose::STANDARD.encode(vk);
        let node_id =
            *veil_cfg::NodeId::from_public_key(veil_cfg::SignatureAlgorithm::Ed25519, &vk_b64)
                .expect("valid ed25519 pubkey")
                .as_bytes();
        (vk_b64, node_id)
    }

    #[test]
    fn derive_obfs4_psk_matches_invite_derivation() {
        use base64::Engine as _;
        let (vk_b64, node_id) = sample_identity();
        let got = derive_listener_obfs4_psk(
            "obfs4-tcp://0.0.0.0:5556",
            false,
            veil_cfg::SignatureAlgorithm::Ed25519,
            &vk_b64,
            &node_id,
        )
        .expect("ed25519 obfs4 listener with no psk must derive");
        // Must equal the key a client derives from the invite's vk/node_id.
        let vk = base64::engine::general_purpose::STANDARD
            .decode(&vk_b64)
            .unwrap();
        let expect = veil_obfs4::NodeIdMacKey::derive_from_identity(&vk, &node_id).0;
        assert_eq!(got, expect, "server and invite must derive the same key");
    }

    #[test]
    fn derive_obfs4_psk_none_cases() {
        let (vk_b64, node_id) = sample_identity();
        // Already has an explicit PSK → don't override.
        assert!(
            derive_listener_obfs4_psk(
                "obfs4-tcp://0.0.0.0:5556",
                true,
                veil_cfg::SignatureAlgorithm::Ed25519,
                &vk_b64,
                &node_id,
            )
            .is_none(),
            "explicit psk_file must not be overridden"
        );
        // Non-obfs4 transport → no anti-probe key needed.
        assert!(
            derive_listener_obfs4_psk(
                "tcp://0.0.0.0:5556",
                false,
                veil_cfg::SignatureAlgorithm::Ed25519,
                &vk_b64,
                &node_id,
            )
            .is_none(),
            "non-obfs4 transport must not derive"
        );
        // PQ identity → no Ed25519 invite to agree with.
        assert!(
            derive_listener_obfs4_psk(
                "obfs4-tcp://0.0.0.0:5556",
                false,
                veil_cfg::SignatureAlgorithm::Falcon512,
                &vk_b64,
                &node_id,
            )
            .is_none(),
            "PQ identity must not derive (invite path is Ed25519-only)"
        );
    }

    #[test]
    fn public_listener_advertised() {
        let mut cfg = Config::default();
        cfg.listen = vec![make_listen(
            1,
            "obfs4-tcp://0.0.0.0:5556",
            "obfs4-tcp://1.2.3.4:5556",
            Visibility::Public,
        )];
        let ads = build_advertised_transports(&cfg);
        assert_eq!(ads, vec!["obfs4-tcp://1.2.3.4:5556".to_owned()]);
    }

    #[test]
    fn trusted_listener_not_advertised() {
        let mut cfg = Config::default();
        cfg.listen = vec![make_listen(
            1,
            "obfs4-tcp://0.0.0.0:7777",
            "obfs4-tcp://1.2.3.4:7777",
            Visibility::Trusted,
        )];
        let ads = build_advertised_transports(&cfg);
        assert!(ads.is_empty(), "trusted listener must NOT advertise");
    }

    #[test]
    fn hidden_listener_not_advertised() {
        let mut cfg = Config::default();
        cfg.listen = vec![make_listen(
            1,
            "obfs4-tcp://0.0.0.0:7777",
            "obfs4-tcp://1.2.3.4:7777",
            Visibility::Hidden,
        )];
        let ads = build_advertised_transports(&cfg);
        assert!(ads.is_empty(), "hidden listener must NOT advertise");
    }

    /// Mixed config: public listener advertised, trusted listener skipped.
    /// Demonstrates the common deployment where node hosts SIMULTANEOUSLY
    /// a public listener (for general network) + a family-only listener
    /// (for relatives, not gossiped).
    #[test]
    fn mixed_visibility_only_advertises_public() {
        let mut cfg = Config::default();
        cfg.listen = vec![
            make_listen(
                1,
                "obfs4-tcp://0.0.0.0:5556",
                "obfs4-tcp://1.2.3.4:5556",
                Visibility::Public,
            ),
            make_listen(
                2,
                "obfs4-tcp://0.0.0.0:7777",
                "obfs4-tcp://1.2.3.4:7777",
                Visibility::Trusted,
            ),
            make_listen(
                3,
                "obfs4-tcp://0.0.0.0:9999",
                "obfs4-tcp://1.2.3.4:9999",
                Visibility::Hidden,
            ),
        ];
        let ads = build_advertised_transports(&cfg);
        assert_eq!(
            ads,
            vec!["obfs4-tcp://1.2.3.4:5556".to_owned()],
            "only public listener should advertise"
        );
    }
}

#[cfg(test)]
mod listen_psk_tests {
    use super::*;
    use crate::types::{ListenConfigEntry, ListenId};
    use veil_cfg::Visibility;

    fn write_psk_file(content: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let pid = std::process::id();
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("veil-listen-psk-test-{pid}-{n}.b64"));
        std::fs::write(&path, content).expect("write tmp psk");
        path
    }

    fn make_entry(psk_file: Option<std::path::PathBuf>) -> ListenConfigEntry {
        ListenConfigEntry {
            listen_id: ListenId::new(1),
            listener_handle: None,
            transport: "obfs4-tcp://0.0.0.0:5556".to_owned(),
            advertise: None,
            relay: None,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            psk_file,
            visibility: Visibility::Public,
            allowlist_node_ids: vec![],
            group_label: None,
            ephemeral: None,
            on_demand: None,
            local_addr: None,
            active: false,
        }
    }

    /// Without `psk_file`, derived ctx keeps the base's `obfs4_psk`.
    #[test]
    fn no_psk_file_preserves_base_psk() {
        let mut base = TransportContext::for_debug().expect("debug ctx");
        let base_psk = [0xAA; 32];
        base.obfs4_psk = Some(std::sync::Arc::new(base_psk));
        let entry = make_entry(None);
        let ctx = listen_transport_context(&base, &entry).expect("ctx ok");
        assert_eq!(
            ctx.obfs4_psk.as_deref().copied(),
            Some(base_psk),
            "base PSK preserved when listener has no psk_file"
        );
    }

    /// With `psk_file` set, derived ctx uses the loaded PSK (NOT base).
    #[test]
    fn psk_file_overrides_base() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as BASE64;
        let listener_psk = [0xBB; 32];
        let path = write_psk_file(&BASE64.encode(listener_psk));
        let mut base = TransportContext::for_debug().expect("debug ctx");
        base.obfs4_psk = Some(std::sync::Arc::new([0xAA; 32]));
        let entry = make_entry(Some(path.clone()));
        let ctx = listen_transport_context(&base, &entry).expect("ctx ok");
        assert_eq!(
            ctx.obfs4_psk.as_deref().copied(),
            Some(listener_psk),
            "listener-specific PSK overrides base"
        );
        std::fs::remove_file(path).ok();
    }

    /// PSK file with wrong length → error (not silent fallback).
    #[test]
    fn psk_file_wrong_length_rejected() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as BASE64;
        // Only 16 bytes — half the required size.
        let path = write_psk_file(&BASE64.encode([0xCC; 16]));
        let base = TransportContext::for_debug().expect("debug ctx");
        let entry = make_entry(Some(path.clone()));
        let err =
            listen_transport_context(&base, &entry).expect_err("must reject wrong-length PSK");
        let msg = format!("{err}");
        assert!(msg.contains("expected 32 bytes"), "got: {msg}");
        std::fs::remove_file(path).ok();
    }

    /// PSK file with invalid base64 → error.
    #[test]
    fn psk_file_invalid_base64_rejected() {
        let path = write_psk_file("!!!not valid base64!!!");
        let base = TransportContext::for_debug().expect("debug ctx");
        let entry = make_entry(Some(path.clone()));
        let err = listen_transport_context(&base, &entry).expect_err("must reject invalid base64");
        let msg = format!("{err}");
        assert!(msg.contains("invalid base64"), "got: {msg}");
        std::fs::remove_file(path).ok();
    }
}

pub fn lock_state(state: &Arc<Mutex<NodeState>>) -> MutexGuard<'_, NodeState> {
    lock!(state)
}

/// Anti-censorship AS-diversity extractor: snapshots already-dialed
/// peers' IPs from `discovered_peers_cache` and builds a node_id → prefix
/// map.  Returned Strings have the form `"v4:a.b"` (first 16 bits of
/// IPv4) or `"v6:xxxx:yyyy"` (first 32 bits of IPv6).  Unknown peers
/// (never not dialed) absent from the map — `pick_circuit_hops_*_with_diversity`
/// degrades gracefully on None keys.
///
/// Anti-censorship Epic 482.x wire-up: closes "adversary controls 3+
/// relays in one /16" vector — picker enforces distinct /16s even
/// when relay-directory wire format doesn't carry IP/ASN.  See
/// `crates/veil-anonymity/src/sender.rs::build_outbound_anonymous_cell_with_diversity`
/// for the consumer side.
pub fn build_as_diversity_map(
    discovered_peers_cache: &Arc<Mutex<veil_bootstrap::DiscoveredPeerCache>>,
) -> std::collections::HashMap<[u8; 32], String> {
    use veil_transport::TransportUri;
    let mut map = std::collections::HashMap::new();
    let cache = lock!(discovered_peers_cache);
    for peer in cache.snapshot() {
        // `BootstrapPeer.public_key` is base64; we need node_id (raw
        // 32 bytes) for the map key.  Derive node_id = BLAKE3(pubkey).
        let pk_b64 = peer.public_key.as_str();
        use base64::{Engine, engine::general_purpose::STANDARD};
        let pk_bytes = match STANDARD.decode(pk_b64) {
            Ok(b) if b.len() == 32 => b,
            _ => continue,
        };
        let node_id: [u8; 32] = *blake3::hash(&pk_bytes).as_bytes();

        // Extract IP host from the transport URI and derive a prefix key.
        let Ok(uri) = TransportUri::parse(&peer.transport) else {
            continue;
        };
        let Some(host) = uri.host() else { continue };
        // Try IPv4 first, then IPv6.
        if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
            let octets = v4.octets();
            map.insert(node_id, format!("v4:{}.{}", octets[0], octets[1]));
        } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
            let seg = v6.segments();
            map.insert(node_id, format!("v6:{:04x}:{:04x}", seg[0], seg[1]));
        }
        // Hostname (non-numeric) — skip; resolving to IP would need
        // a live DNS lookup which does not fit into the in-memory closure path.
    }
    map
}

pub fn lock_tasks(tasks: &Arc<Mutex<RuntimeTasks>>) -> MutexGuard<'_, RuntimeTasks> {
    lock!(tasks)
}

/// Push a session handle, pruning finished handles inline when the vec
/// exceeds a threshold to prevent unbounded growth between cleanup ticks.
pub fn push_session_handle(tasks: &Arc<Mutex<RuntimeTasks>>, handle: tokio::task::JoinHandle<()>) {
    let mut t = lock_tasks(tasks);
    if t.sessions.len() >= 256 {
        t.sessions.retain(|h| !h.is_finished());
    }
    t.sessions.push(handle);
}

///build + send a one-way `AnnounceTransport`
/// frame carrying our self-signed transport announcement to `peer_id`.
///
/// Called from both inbound and outbound handshake-complete paths so
/// every peer with whom we share a session learns our signed
/// transport URI and can return it when other walkers do
/// `ResolveTransport(local_node_id)`. No-op when the local node has
/// no announcement (pure outbound clients).
pub fn send_local_announcement(
    dht: &Arc<veil_dht::kademlia::KademliaService>,
    session_outbox: &Arc<veil_session::SessionOutbox>,
    peer_id: [u8; 32],
) {
    let Some(announcement) = dht.local_announcement() else {
        return;
    };
    let body = announcement.encode();
    let mut hdr = veil_proto::header::FrameHeader::new(
        veil_proto::family::FrameFamily::Discovery as u8,
        veil_proto::family::DiscoveryMsg::AnnounceTransport as u16,
    );
    hdr.body_len = body.len() as u32;
    let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
    frame.extend_from_slice(&body);
    let _ = session_outbox.send_oneway(peer_id, frame);
}

/// Derive a 32-byte node_id from a `BootstrapPeer`'s public key.
///
/// Replicates the `NodeId::from_public_key` computation:
/// `node_id = BLAKE3(base64_decode(public_key))`.
/// Returns `None` if the public_key is not valid base64.
pub fn derive_node_id_from_bootstrap_peer(bp: &veil_cfg::BootstrapPeer) -> Option<[u8; 32]> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let key_bytes = STANDARD.decode(&bp.public_key).ok()?;
    Some(*blake3::hash(&key_bytes).as_bytes())
}

pub fn resolve_metrics_path(config: &Config) -> Option<String> {
    config
        .metrics
        .as_ref()
        .and_then(|cfg| cfg.path.clone())
        .or_else(|| config.metrics.as_ref().map(|_| "/metrics".to_owned()))
}

/// Build the list of transport addresses to advertise in `RouteResponse`.
///
/// For each listen entry: use `advertise` when set, otherwise fall back to
/// `transport`. This lets a node bind on `ws://127.0.0.1:7001` while telling
/// peers to connect via `wss://nginx.example.com:443/veil`.
pub fn build_advertised_transports(config: &Config) -> Vec<String> {
    config
        .listen
        .iter()
        .filter(|l| {
            // **Visibility gate** (Phase 3): only `Public` listeners get
            // their transports advertised through PEX + DHT (`SignedTransport-
            // Announcement` publish + `ResolveTransport` responses).
            // `Trusted` and `Hidden` listeners stay invisible on the
            // network — peers learn about them only through invite-bundles.
            l.visibility.is_advertisable()
        })
        .filter_map(|l| {
            // Prefer the explicit advertise URI when set; otherwise fall back
            // to the bind transport — but ONLY if the bind isn't on a wildcard
            // host. Advertising `tcp://0.0.0.0:5555` poisons PEX: any peer
            // receiving the entry will dial 0.0.0.0:5555 on its own host
            // which routes to its own listener and produces a stream of
            // `peer.identity_mismatch` warnings (the local listener answers
            // with its own node_id, not the gossipped one). Skip silently;
            // operators who need a public address should set [[listen]].advertise.
            if let Some(adv) = &l.advertise {
                Some(adv.clone())
            } else if is_wildcard_transport(&l.transport) {
                None
            } else {
                Some(l.transport.clone())
            }
        })
        .collect()
}

/// Translate the operator-facing `MailboxConfig` (every `0` field acts as
/// "use the safe default") into the crate-internal `veil_mailbox::MailboxConfig`.
///
/// Sentinel rule: any field left at `0` in the operator config is replaced
/// with the crate's `DEFAULT_*` constant. To disable a quota an operator
/// must set an explicit non-zero value (e.g. `u64::MAX` for per-sender).
/// Pre-fix `quota_per_sender_bytes == 0` mapped to `u64::MAX`, which made
/// the default-config deployment silently unsafe — one OVL1 sender could
/// fill a receiver's 100 MiB cap in ~2 min.
pub fn build_mailbox_runtime_config(
    cfg: &veil_cfg::MailboxConfig,
    local_node_id: [u8; 32],
) -> veil_mailbox::MailboxConfig {
    veil_mailbox::MailboxConfig {
        quota_per_receiver_bytes: if cfg.quota_per_receiver_bytes == 0 {
            veil_mailbox::DEFAULT_QUOTA_PER_RECEIVER_BYTES
        } else {
            cfg.quota_per_receiver_bytes
        },
        quota_global_bytes: if cfg.quota_global_bytes == 0 {
            veil_mailbox::DEFAULT_QUOTA_GLOBAL_BYTES
        } else {
            cfg.quota_global_bytes
        },
        ttl_secs: if cfg.ttl_secs == 0 {
            veil_mailbox::DEFAULT_TTL_SECS
        } else {
            cfg.ttl_secs
        },
        rate_limit_per_minute: if cfg.rate_limit_per_minute == 0 {
            veil_mailbox::DEFAULT_RATE_LIMIT_PER_MINUTE
        } else {
            cfg.rate_limit_per_minute
        },
        require_capability_token: cfg.require_capability_token,
        quota_per_sender_bytes: if cfg.quota_per_sender_bytes == 0 {
            veil_mailbox::DEFAULT_QUOTA_PER_SENDER_BYTES
        } else {
            cfg.quota_per_sender_bytes
        },
        local_node_id,
    }
}

#[cfg(test)]
mod mailbox_cfg_translation_tests {
    use super::*;

    #[test]
    fn zero_per_sender_quota_maps_to_safe_default_not_unlimited() {
        let mut cfg = veil_cfg::MailboxConfig::default();
        cfg.quota_per_sender_bytes = 0;
        let mb = build_mailbox_runtime_config(&cfg, [0u8; 32]);
        assert_eq!(
            mb.quota_per_sender_bytes,
            veil_mailbox::DEFAULT_QUOTA_PER_SENDER_BYTES,
            "operator default (0) must produce safe quota, NOT u64::MAX"
        );
        assert_ne!(
            mb.quota_per_sender_bytes,
            u64::MAX,
            "regression guard: pre-fix 0 mapped to u64::MAX, which silently disabled the cap"
        );
    }

    #[test]
    fn explicit_per_sender_quota_is_preserved() {
        let mut cfg = veil_cfg::MailboxConfig::default();
        cfg.quota_per_sender_bytes = 5 * 1024 * 1024;
        let mb = build_mailbox_runtime_config(&cfg, [0u8; 32]);
        assert_eq!(mb.quota_per_sender_bytes, 5 * 1024 * 1024);
    }

    #[test]
    fn explicit_u64_max_per_sender_quota_disables_cap() {
        let mut cfg = veil_cfg::MailboxConfig::default();
        cfg.quota_per_sender_bytes = u64::MAX;
        let mb = build_mailbox_runtime_config(&cfg, [0u8; 32]);
        assert_eq!(
            mb.quota_per_sender_bytes,
            u64::MAX,
            "operator must still be able to disable explicitly by setting u64::MAX"
        );
    }

    #[test]
    fn other_zero_fields_still_use_their_defaults() {
        let cfg = veil_cfg::MailboxConfig::default();
        let mb = build_mailbox_runtime_config(&cfg, [0u8; 32]);
        assert_eq!(
            mb.quota_per_receiver_bytes,
            veil_mailbox::DEFAULT_QUOTA_PER_RECEIVER_BYTES
        );
        assert_eq!(
            mb.quota_global_bytes,
            veil_mailbox::DEFAULT_QUOTA_GLOBAL_BYTES
        );
        assert_eq!(mb.ttl_secs, veil_mailbox::DEFAULT_TTL_SECS);
        assert_eq!(
            mb.rate_limit_per_minute,
            veil_mailbox::DEFAULT_RATE_LIMIT_PER_MINUTE
        );
    }
}

#[cfg(test)]
mod onion_epoch_tests {
    use super::next_monotonic_epoch;
    use std::sync::atomic::AtomicU64;

    #[test]
    fn epoch_strictly_increases_within_same_second() {
        // B2 regression: two onion-service rebuilds in the SAME wall-clock
        // second must still produce strictly-increasing registration epochs, or
        // R drops the rebuild as StaleEpoch and the service strands on a stale
        // circuit. (Pre-fix, epoch == raw unix seconds, so both rebuilds emitted
        // the same value.)
        let c = AtomicU64::new(0);
        let e1 = next_monotonic_epoch(&c, 1000);
        let e2 = next_monotonic_epoch(&c, 1000); // same second
        let e3 = next_monotonic_epoch(&c, 1000); // same second
        assert_eq!(e1, 1000, "first epoch tracks wall-clock");
        assert!(e2 > e1, "{e2} must be strictly > {e1}");
        assert!(e3 > e2, "{e3} must be strictly > {e2}");
    }

    #[test]
    fn epoch_tracks_wall_clock_when_it_advances() {
        let c = AtomicU64::new(0);
        let _ = next_monotonic_epoch(&c, 1000);
        let later = next_monotonic_epoch(&c, 5000);
        assert_eq!(later, 5000, "a real clock jump is reflected, not just +1");
    }

    #[test]
    fn epoch_never_regresses_on_clock_rewind() {
        // A backward clock (NTP step) must not produce a non-increasing epoch.
        let c = AtomicU64::new(0);
        let high = next_monotonic_epoch(&c, 9000);
        let rewound = next_monotonic_epoch(&c, 3000); // clock went backwards
        assert!(
            rewound > high,
            "{rewound} must still be > {high} after rewind"
        );
    }
}

#[cfg(test)]
mod tests;

/// Stable, non-resolvable cleartext receiver-id for a CIRCUIT-BACKED introduce
/// (diff-audit L3). A location-anonymous service is routed by R using the cookie
/// alone — R never forwards `receiver_node_id` down the circuit and the service
/// never sees it — but R DOES read the cleartext `receiver_node_id` of the
/// introduce it receives, and the real value is the service's transport node_id,
/// which R can resolve to the service's location via DHT/PEX. Substitute a
/// per-service-stable pseudo-id derived from the cookie: it looks like any
/// node_id (so R cannot fingerprint circuit-backed introduces by it, nor tell
/// them apart from session-backed ones for an unknown cookie) and resolves to
/// nothing. The AuthDeliver signature still binds the REAL receiver_node_id
/// inside the seal, which the service verifies against its own node_id.
fn circuit_backed_cleartext_id(cookie: &[u8; 16]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"veil.rendezvous.cleartext-id.v1\0");
    h.update(cookie);
    *h.finalize().as_bytes()
}

/// Plaintext bytes one sealed introduce can carry at `hop_count` hops — the
/// budget every rendezvous send packs into.
///
/// It is bounded by the 512-byte ANONYMOUS cell
/// ([`veil_anonymity::cell::CELL_SIZE`]) that carries the sender → rendezvous
/// leg, minus the per-hop onion overhead, the fixed `IntroducePayload` header
/// and the seal's own overhead. At 3 hops that is 156 bytes.
///
/// The receiver's leg is NOT this cell: the rendezvous forwards each sealed
/// introduce inside one fixed [`veil_anonymity::circuit_data::CIRCUIT_PAYLOAD_BYTES`]
/// circuit-data cell (16 KiB since the 2026-07-02 bump). Nothing ties the two
/// numbers together, which is why a 135-byte fragment costs 16 KiB inbound —
/// see the guard test beside this function.
fn introduce_plaintext_budget(hop_count: usize) -> Option<usize> {
    use veil_anonymity::rendezvous::{
        INTRODUCE_OVERHEAD, IntroducePayload, MAX_INTRODUCE_CIPHERTEXT,
    };
    let final_budget = veil_anonymity::packet::max_payload_for_hops(hop_count)?;
    let ciphertext_budget = final_budget
        .saturating_sub(1 + IntroducePayload::FIXED_SIZE)
        .min(MAX_INTRODUCE_CIPHERTEXT);
    Some(ciphertext_budget.saturating_sub(INTRODUCE_OVERHEAD))
}

/// Signed-blob bytes one `AuthDeliverFragment` carries at `hop_count` hops:
/// [`introduce_plaintext_budget`] minus the final-hop kind tag and the fragment
/// header. This is the unit a multi-fragment message is cut into, and each
/// fragment travels as its OWN introduce — so it is also the useful payload of
/// one circuit-data cell on the receiving side.
fn introduce_fragment_chunk_size(hop_count: usize) -> Option<usize> {
    Some(
        introduce_plaintext_budget(hop_count)?
            .saturating_sub(1 + veil_proto::AuthDeliverFragment::HEADER_SIZE),
    )
}

/// A message needing at least this many fragments counts as bulk.
const BULK_FRAGMENT_THRESHOLD: usize = 3;
/// Copies of each fragment a bulk message sends down a single relay.
const BULK_REDUNDANCY: usize = 3;

/// How many copies of each fragment to put on the wire.
///
/// Redundancy exists for ONE reason: reassembly is all-or-nothing, so at F
/// independently-lost fragments the odds collapse as (1-p)^F — a 27-fragment
/// bulk chunk at p≈0.27 delivers ~0.01% on a single copy. Sending each fragment
/// `redundancy` times and de-duping by (msg_id, frag_idx) lifts per-fragment
/// delivery to 1-p^redundancy.
///
/// A ONE-fragment message has no reassembly to protect, so copies buy only a
/// retry — and every caller on this path already owns one. That is not an
/// assumption: the reply block is deliberately non-consuming ("stays valid
/// until TTL so the app can retry if this reply's cell is dropped"), and the
/// mailbox FETCH it serves is idempotent and non-destructive, re-fetched every
/// drain round until the receiver acks. So the copies were re-sending something
/// that was going to be re-requested three seconds later anyway.
///
/// It mattered because the reply path asks for 3 explicitly. Until the
/// 2026-08-07 cell bump a ~6 KB mailbox reply was 46 fragments and the request
/// was right; afterwards the same reply is a single fragment, and 3 copies of
/// one 16 KiB circuit cell became the largest remaining term in the measured
/// cost per delivered message (~341 KB for seven bytes of text).
///
/// `parallel` means several distinct relays are available AND the message
/// fragments: spread one copy of each fragment across them for aggregate
/// throughput instead of funnelling copies through one.
fn onion_send_redundancy(
    requested: usize,
    frag_count: usize,
    parallel: bool,
    relay_count: usize,
) -> usize {
    if parallel {
        log::debug!(
            "onion bulk send: {frag_count} fragments round-robined across \
             {relay_count} rendezvous relays (parallel endpoints, redundancy 1)",
        );
        return 1;
    }
    if frag_count <= 1 {
        return 1;
    }
    if frag_count >= BULK_FRAGMENT_THRESHOLD {
        return requested.max(BULK_REDUNDANCY);
    }
    requested
}

/// Map a low-level onion `SenderError` to the IPC-facing `AnonOnionSendError`.
fn map_sender_err(e: veil_anonymity::sender::SenderError) -> veil_types::AnonOnionSendError {
    use veil_types::AnonOnionSendError;
    match e {
        veil_anonymity::sender::SenderError::MissingSenderIdentity => {
            AnonOnionSendError::NoIdentity
        }
        veil_anonymity::sender::SenderError::InsufficientRelayCandidates { .. } => {
            AnonOnionSendError::NoRelays
        }
        veil_anonymity::sender::SenderError::PayloadTooLarge { .. } => {
            AnonOnionSendError::PayloadTooLarge
        }
        _ => AnonOnionSendError::NoRelays,
    }
}

/// A pinned stateful onion circuit for an anonymous byte-stream (Phase 1b of the
/// onion-stream speedup). Built ONCE — the setup envelope installs a per-hop XOR
/// key at each relay — then carries cheap fixed-size `CircuitData` cells with NO
/// per-cell ECDH and NO per-cell signature. (The per-cell circuit build + sign/
/// verify of the datagram path is what inflates the RTT and drives the spurious-
/// recovery slowdown the byte-stream hits.) This node is the ORIGINATOR: it
/// sends FORWARD cells toward the terminus and opens RETURN cells via the
/// dispatcher origin table. ADDITIVE — no existing anonymous-send path changes.
pub struct DataCircuit {
    first_hop: [u8; 32],
    relay_path: Vec<[u8; 32]>,
    origin_circuit_id: u32,
    /// Per-hop keys, first-hop → terminus order (wraps each FORWARD cell).
    keys: Vec<[u8; 32]>,
    /// Next FORWARD seq. 0 is reserved (the wire numbers from 1), so the first
    /// allocation returns 1. NEVER wraps — a reused seq reuses an XOR keystream
    /// (breaks confidentiality); exhaustion returns `None` so the caller rotates
    /// the circuit (in practice the 600 s origin-table TTL rotates first).
    next_seq: std::sync::atomic::AtomicU32,
    confirmed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Size of every cell on this circuit — the number its setup negotiated.
    cell_bytes: veil_anonymity::circuit_data::CircuitCellBytes,
}

/// Detailed local enqueue result for pinned circuit DATA. This is intentionally
/// more precise than the public anonymous-send IPC error: onion streams need to
/// distinguish a broken/missing first-hop route from a merely full local
/// session TX queue, otherwise local backpressure becomes fake packet loss and
/// collapses the stream congestion window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataCircuitSendError {
    NoRelays,
    QueueFull,
    PayloadTooLarge,
}

impl From<DataCircuitSendError> for veil_types::AnonOnionSendError {
    fn from(value: DataCircuitSendError) -> Self {
        match value {
            DataCircuitSendError::NoRelays | DataCircuitSendError::QueueFull => {
                veil_types::AnonOnionSendError::NoRelays
            }
            DataCircuitSendError::PayloadTooLarge => {
                veil_types::AnonOnionSendError::PayloadTooLarge
            }
        }
    }
}

impl DataCircuit {
    /// The originator-link circuit id (return cells carry it; also the splice key
    /// at R once the rendezvous-splice path lands).
    pub fn origin_circuit_id(&self) -> u32 {
        self.origin_circuit_id
    }

    /// First hop's node id (return cells arrive from here).
    pub fn first_hop(&self) -> [u8; 32] {
        self.first_hop
    }

    /// Full origin relay path, first hop → terminus.
    pub fn relay_path(&self) -> &[[u8; 32]] {
        &self.relay_path
    }

    /// Whether the terminus's `CircuitBuilt` ACK has confirmed the whole path.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The shared confirmed flag itself (the same cell the dispatcher sets on
    /// the `CircuitBuilt` ACK). The stream layer hands it to the circuit's
    /// return-cell feed so a loopback splice-probe echo can confirm the path
    /// when the one-shot ACK was lost on a lossy WAN.
    pub fn confirmed_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.confirmed)
    }

    /// Allocate the next FORWARD seq (1, 2, 3, …); `None` once the 32-bit space
    /// is exhausted (never wrap — XOR keystream reuse).
    fn alloc_seq(&self) -> Option<u32> {
        let prev = self
            .next_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        prev.checked_add(1)
    }
}

/// What a caller gets back from registering an onion circuit: which
/// registration it made, and the flag the relay's `CircuitBuilt` ACK flips.
struct OnionRegistration {
    id: u64,
    confirmed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// A number no other registration in this process has had.
///
/// The cookie could not serve: it is derived per (identity, period, slot), so
/// withdraw-and-register-again inside one period hands the new registration
/// the old one's cookie (report20 V18-M5).
fn next_onion_registration() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// The pseudo identity a service's ad is signed under: derived from its
/// registration keypair, never from the sovereign node id, so the ad does not
/// link the node to its live rendezvous point.
fn ephemeral_ad_identity_for(
    reg_keypair: &veil_crypto::GeneratedKeyPair,
) -> Option<veil_anonymity::rendezvous::EphemeralAdIdentity> {
    veil_anonymity::rendezvous::EphemeralAdIdentity::from_b64_keypair(
        reg_keypair.public_key.clone(),
        reg_keypair.private_key.clone(),
        veil_types::SignatureAlgorithm::Ed25519,
    )
}

/// Is this registration still on the books?
///
/// The question a deferred publish has to ask before it runs: `withdraw`
/// removes the entry and returns, while the publish waiting on the circuit ACK
/// carried neither a cancellation nor any notion of which registration it
/// belonged to — so it re-added the publisher and put fresh ciphertext in the
/// DHT for a service the owner had revoked (report17 V17-M7). Asked by
/// registration number, not by cookie: a later registration of the same
/// identity in the same period has the same cookie (report20 V18-M5).
fn service_with_registration_present(
    services: &[crate::runtime::anonymity_state::OnionServiceEntry],
    registration: u64,
) -> bool {
    services.iter().any(|e| e.registration == registration)
}

/// Write `registration`'s publisher row, if it is still registered — and hold
/// the services lock across BOTH, so a withdraw cannot fit between the
/// question and the row.
///
/// `publish_row` takes the publishers lock inside. Services-then-publishers
/// is the order `withdraw_ephemeral_service` and the circuit registration
/// already use, and no path takes the two the other way round, so this
/// nesting cannot invert. What must NOT run under here is the DHT write of
/// the blinded descriptor: that is the caller's next step, after the lock is
/// gone. A withdraw landing in that gap leaves a descriptor in the DHT until
/// it ages out — which is what a withdraw after an ordinary publish leaves
/// too, and all a DHT without delete can offer. It leaves no ROW, and the row
/// was the part that was re-signed forever.
fn publish_row_if_registered(
    services: &std::sync::Mutex<Vec<crate::runtime::anonymity_state::OnionServiceEntry>>,
    registration: u64,
    publish_row: impl FnOnce(),
) -> bool {
    let services = lock!(services);
    if !service_with_registration_present(&services, registration) {
        return false;
    }
    publish_row();
    drop(services);
    true
}

/// Drop the publisher rows keyed by these `(relay, cookie)` pairs.
fn remove_publisher_rows(
    publishers: &std::sync::Mutex<Vec<veil_anonymity::rendezvous::RendezvousPublisherEntry>>,
    keys: &[([u8; 32], [u8; 16])],
) {
    lock!(publishers).retain(|entry| {
        !keys.iter().any(|(relay, cookie)| {
            entry.rendezvous_node_id == *relay && entry.auth_cookie == *cookie
        })
    });
}

/// Move a service's publisher row from the `(relay, cookie)` it was written
/// under to the one its entry now has, keeping the ad signed by the identity
/// that goes with the new key. `false` when no such row exists — a service
/// that never got a slot, or one whose row was already dropped.
fn rekey_publisher_row(
    publishers: &mut [veil_anonymity::rendezvous::RendezvousPublisherEntry],
    was: ([u8; 32], [u8; 16]),
    now: ([u8; 32], [u8; 16]),
    identity: Option<veil_anonymity::rendezvous::EphemeralAdIdentity>,
) -> bool {
    if was == now {
        return publishers
            .iter()
            .any(|e| e.rendezvous_node_id == was.0 && e.auth_cookie == was.1);
    }
    let Some(row) = publishers
        .iter_mut()
        .find(|e| e.rendezvous_node_id == was.0 && e.auth_cookie == was.1)
    else {
        return false;
    };
    row.rendezvous_node_id = now.0;
    row.auth_cookie = now.1;
    if row.ephemeral_ad_identity.is_some() {
        row.ephemeral_ad_identity = identity;
    }
    true
}

/// Stop hosting every ephemeral service of `identity_vk`, and take their
/// publisher rows with them.
///
/// The services lock is HELD across the row removal. The cookie is derived
/// per (identity, period), not minted per registration, so a withdraw and a
/// re-registration inside one period produce the same `(relay, cookie)`.
/// Letting go of `services` between the two steps opened a window in which a
/// re-registration could put its entry back and this would then delete the
/// publisher row it had just made — a service registered and never
/// advertised, silently (report20 V18-M5). Services-then-publishers is the
/// order the circuit registration and `publish_row_if_registered` use too.
fn withdraw_ephemeral_service(
    services: &std::sync::Mutex<Vec<crate::runtime::anonymity_state::OnionServiceEntry>>,
    publishers: &std::sync::Mutex<Vec<veil_anonymity::rendezvous::RendezvousPublisherEntry>>,
    identity_vk: [u8; 32],
) -> bool {
    let mut services = lock!(services);
    let mut removed = Vec::new();
    services.retain(|entry| {
        let matches = entry.ephemeral
            && entry
                .descriptor_identity_seed
                .as_deref()
                .map(|seed| {
                    veil_crypto::key_blinding::ed25519_public_from_seed(seed) == identity_vk
                })
                .unwrap_or(false);
        if matches && let Some(&relay) = entry.relay_path.last() {
            removed.push((relay, entry.cookie));
        }
        !matches
    });
    if !removed.is_empty() {
        remove_publisher_rows(publishers, &removed);
    }
    drop(services);
    !removed.is_empty()
}

/// Take one of `max` waiter slots, or refuse.
///
/// Each waiter is a detached thread sleeping up to three seconds. `withdraw`
/// frees the SERVICE slot immediately and leaves the waiter behind, so the cap
/// on services bounded nothing: register-then-withdraw in a loop grew threads
/// without limit (report17 V17-M7).
fn claim_confirm_waiter(pending: &std::sync::atomic::AtomicUsize, max: usize) -> bool {
    // `fetch_add` then give back on refusal: two callers racing at the
    // boundary both see the raised value, so neither is admitted over the cap.
    if pending.fetch_add(1, std::sync::atomic::Ordering::AcqRel) >= max {
        pending.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        return false;
    }
    true
}

#[cfg(test)]
mod deferred_publish_tests {
    use super::{
        claim_confirm_waiter, publish_row_if_registered, rekey_publisher_row,
        service_with_registration_present, withdraw_ephemeral_service,
    };
    use crate::runtime::anonymity_state::OnionServiceEntry;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Mutex};
    use veil_anonymity::rendezvous::RendezvousPublisherEntry;

    const RELAY: [u8; 32] = [0x11; 32];

    fn seed() -> Arc<zeroize::Zeroizing<[u8; 32]>> {
        Arc::new(zeroize::Zeroizing::new([0x42; 32]))
    }

    fn identity_vk() -> [u8; 32] {
        veil_crypto::key_blinding::ed25519_public_from_seed(&seed())
    }

    fn entry(registration: u64, cookie: [u8; 16]) -> OnionServiceEntry {
        OnionServiceEntry {
            relay_path: vec![RELAY],
            cookie,
            registration,
            built_unix: 0,
            reg_keypair: veil_crypto::GeneratedKeyPair {
                public_key: String::new(),
                private_key: String::new(),
                algo: veil_types::SignatureAlgorithm::Ed25519,
            },
            confirmed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            registration_epoch: Arc::new(AtomicU64::new(0)),
            descriptor_identity_seed: Some(seed()),
            descriptor_provider_slot: None,
            ephemeral: true,
        }
    }

    fn row(relay: [u8; 32], cookie: [u8; 16]) -> RendezvousPublisherEntry {
        RendezvousPublisherEntry {
            rendezvous_node_id: relay,
            auth_cookie: cookie,
            validity_window_secs: 60,
            push_envelope: Vec::new(),
            wake_hmac_envelope: Vec::new(),
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: Vec::new(),
            rendezvous_kem_valid_until_unix: 0,
            ephemeral_ad_identity: None,
        }
    }

    /// A publish waiting on a circuit ACK must not run for a service that has
    /// been withdrawn in the meantime — and a service registered AGAIN in the
    /// same period is not the one it waited for.
    ///
    /// `withdraw` drops the entry and returns; the waiter used to carry no
    /// notion of which registration it belonged to (report17 V17-M7), and
    /// then asked by cookie — which the successor shares, because the cookie
    /// is derived per (identity, period), not minted per registration
    /// (report20 V18-M5).
    #[test]
    fn a_re_registration_with_the_same_cookie_is_not_the_old_registration() {
        let cookie = [0xAB; 16];
        let mut services = vec![entry(1, cookie)];
        assert!(
            service_with_registration_present(&services, 1),
            "premise: the registration is live while the publish waits"
        );

        // Withdrawn while the ACK was outstanding.
        services.retain(|e| e.registration != 1);
        assert!(
            !service_with_registration_present(&services, 1),
            "a revoked service is still publishable"
        );

        // Registered again inside the same period: the SAME cookie, its own
        // registration.
        services.push(entry(2, cookie));
        assert!(
            !service_with_registration_present(&services, 1),
            "the waiter for a withdrawn registration was satisfied by its \
             successor, which shares its cookie — and would write a row for \
             the OLD relay"
        );
        assert!(
            service_with_registration_present(&services, 2),
            "vacuity: the successor itself is registered"
        );
    }

    /// A withdraw cannot fit between "is it still registered?" and the row.
    ///
    /// The publish answers its question and writes the row under the same
    /// lock; a withdraw arriving in between waits, then removes the row it
    /// finds. With the lock let go in between, the withdraw ran in the gap
    /// and the row went in after it — re-signed every tick for a service that
    /// was gone (report20 V18-M5).
    #[test]
    fn a_withdraw_cannot_slip_between_the_question_and_the_row() {
        let cookie = [0xAB; 16];
        let services = Arc::new(Mutex::new(vec![entry(7, cookie)]));
        let publishers: Arc<Mutex<Vec<RendezvousPublisherEntry>>> =
            Arc::new(Mutex::new(Vec::new()));
        // Meets once the publish has its answer and the withdraw is about to
        // start.
        let asked = Arc::new(Barrier::new(2));

        let publish = {
            let services = Arc::clone(&services);
            let publishers = Arc::clone(&publishers);
            let asked = Arc::clone(&asked);
            std::thread::spawn(move || {
                publish_row_if_registered(&services, 7, || {
                    asked.wait();
                    // Give the withdraw every chance to go first.
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    publishers.lock().unwrap().push(row(RELAY, cookie));
                })
            })
        };
        asked.wait();
        let withdrawn = withdraw_ephemeral_service(&services, &publishers, identity_vk());
        assert!(withdrawn, "premise: the service was registered");
        assert!(
            publish.join().unwrap(),
            "premise: the publish found its registration live"
        );
        assert!(
            publishers.lock().unwrap().is_empty(),
            "a withdraw fitted between the question and the row: the row of \
             a withdrawn service is left behind for every tick to re-sign"
        );
        assert!(services.lock().unwrap().is_empty());
    }

    /// A withdraw takes its own rows and nobody else's.
    #[test]
    fn a_withdraw_takes_only_its_own_rows() {
        let mine = [0xAB; 16];
        let theirs = [0xEF; 16];
        let mut other = entry(9, theirs);
        other.descriptor_identity_seed = Some(Arc::new(zeroize::Zeroizing::new([0x43; 32])));
        let services = Mutex::new(vec![entry(8, mine), other]);
        let publishers = Mutex::new(vec![row(RELAY, mine), row(RELAY, theirs)]);

        assert!(withdraw_ephemeral_service(
            &services,
            &publishers,
            identity_vk()
        ));
        {
            let rows = publishers.lock().unwrap();
            assert_eq!(rows.len(), 1, "a withdraw took another service's row");
            assert_eq!(rows[0].auth_cookie, theirs);
            assert_eq!(services.lock().unwrap().len(), 1);
        }
        // Nothing left to withdraw says so.
        assert!(!withdraw_ephemeral_service(
            &services,
            &publishers,
            identity_vk()
        ));
    }

    /// A rebuild that re-selects the path or crosses a period boundary changes
    /// the entry's `(relay, cookie)`; the row has to come along, or the
    /// withdraw can no longer find it.
    #[test]
    fn a_rebuilt_entry_takes_its_publisher_row_along() {
        let was = (RELAY, [0xAB; 16]);
        let now = ([0x22; 32], [0xCD; 16]);
        let mut publishers = vec![row(was.0, was.1)];
        assert!(rekey_publisher_row(&mut publishers, was, now, None));
        assert_eq!(publishers.len(), 1, "the rebuild duplicated the row");
        assert_eq!(
            (publishers[0].rendezvous_node_id, publishers[0].auth_cookie),
            now,
            "the row still carries the (relay, cookie) its entry no longer \
             has: withdraw cannot find it and the tick re-signs it"
        );

        // And the withdraw finds it under the new key.
        let rebuilt = {
            let mut e = entry(3, now.1);
            e.relay_path = vec![now.0];
            e
        };
        let services = Mutex::new(vec![rebuilt]);
        let publishers = Mutex::new(publishers);
        assert!(withdraw_ephemeral_service(
            &services,
            &publishers,
            identity_vk()
        ));
        assert!(
            publishers.lock().unwrap().is_empty(),
            "the rebuilt service's row survived its withdraw"
        );

        // Nothing to move is reported as such; an unchanged key is a no-op
        // that still answers whether the row exists.
        let mut none: Vec<RendezvousPublisherEntry> = Vec::new();
        assert!(!rekey_publisher_row(&mut none, was, now, None));
        let mut same = vec![row(was.0, was.1)];
        assert!(rekey_publisher_row(&mut same, was, was, None));
        assert_eq!((same[0].rendezvous_node_id, same[0].auth_cookie), was);
    }

    /// The waiters are bounded, because nothing else bounds them.
    ///
    /// Each is a detached thread sleeping up to three seconds; `withdraw`
    /// frees the SERVICE slot at once and leaves the thread, so the cap of
    /// eight services bounded nothing at all.
    #[test]
    fn confirm_waiters_are_capped_and_the_slot_comes_back() {
        let pending = AtomicUsize::new(0);
        const MAX: usize = 3;

        for i in 0..MAX {
            assert!(
                claim_confirm_waiter(&pending, MAX),
                "waiter {i} was refused inside the cap"
            );
        }
        assert!(
            !claim_confirm_waiter(&pending, MAX),
            "an unbounded number of waiters can be created"
        );
        assert_eq!(
            pending.load(Ordering::Acquire),
            MAX,
            "a refused claim left its slot taken, so the cap ratchets down to \
             zero and every publish becomes immediate"
        );

        // One finishes; the slot is usable again.
        pending.fetch_sub(1, Ordering::AcqRel);
        assert!(claim_confirm_waiter(&pending, MAX));
    }

    /// And the deferred publish actually ASKS both questions — on both of
    /// its paths, with the row written by the same call that asks.
    /// Find a function's DEFINITION, not any mention of its name.
    ///
    /// A guard that searches a whole file for `"fn foo("` matches this test
    /// module's own text too, and one that finds its own assertion string
    /// passes while measuring nothing. That is not hypothetical: when
    /// `maintain_onion_circuits` moved to `node_services.rs`, the guard below
    /// went on passing against the literal inside its own `assert!`.
    ///
    /// Anchoring on the newline and the indentation a definition is written
    /// with is what tells the two apart — a mention inside a test lives in a
    /// string literal, several levels in. Cutting the file at `#[cfg(test)]`
    /// would not do here: `mod.rs` interleaves test modules with production
    /// code, so the first one is nowhere near the end.
    /// Returned with `//` lines stripped, so a call somebody commented out
    /// does not read as a call. Measured: commenting the `rekey_publisher_row`
    /// block left the guard below green, because the text was still there.
    fn definition(src: &'static str, indent: &str, name: &str) -> String {
        let needle = format!("\n{indent}{name}");
        let at = src
            .find(&needle)
            .unwrap_or_else(|| panic!("{name} moved; this guard is aimed at nothing"));
        let body = &src[at + 1..];
        let end = body
            .find(&format!("\n{indent}}}\n"))
            .expect("no end of function");
        body[..end]
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_deferred_publish_checks_the_cap_and_the_withdrawal() {
        let body = definition(
            include_str!("node_services.rs"),
            "    ",
            "fn publish_after_circuit_confirmed",
        );

        assert!(
            body.contains("claim_confirm_waiter(&pending, MAX_PENDING)"),
            "the waiters are unbounded again"
        );
        assert_eq!(
            body.matches("publish_row_if_registered(").count(),
            2,
            "one of the two publish paths no longer asks, under the lock, \
             whether the registration is still there"
        );
        assert_eq!(
            body.matches("publish_row(").count(),
            2,
            "a row is written somewhere other than inside \
             publish_row_if_registered"
        );
    }

    /// The rebuild moves the row with the entry, and the withdraw removes
    /// rows before it lets go of the services lock.
    #[test]
    fn the_rebuild_and_the_withdraw_keep_rows_with_their_entries() {
        // Two files now: the circuit maintenance is a `NodeServices` method
        // and the withdraw is a free function that stayed behind.
        assert!(
            definition(
                include_str!("node_services.rs"),
                "    ",
                "pub fn maintain_onion_circuits(",
            )
            .contains("rekey_publisher_row("),
            "a rebuild that re-selects the path or crosses a period boundary \
             leaves the publisher row under the old (relay, cookie), where \
             withdraw cannot find it"
        );

        let withdraw = definition(include_str!("mod.rs"), "", "fn withdraw_ephemeral_service(");
        let rows = withdraw
            .find("remove_publisher_rows(")
            .expect("the withdraw no longer removes rows");
        let unlock = withdraw
            .find("drop(services)")
            .expect("the withdraw no longer holds the services lock explicitly");
        assert!(
            rows < unlock,
            "the withdraw lets go of the services lock before removing the \
             rows: a re-registration fits in between and loses its row"
        );
    }
}
