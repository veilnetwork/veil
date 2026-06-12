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
mod dht_republish;
mod ephemeral_rotator;
mod handoff_runtime;
mod identity_loaders;
mod identity_state;
mod ip_slot;
mod lifecycle;
mod mailbox_state;
mod maintenance;
mod mesh_gateway;
mod mobile_state;
mod p_net_ban_sync;
mod peer_handshake;
mod persist_tasks;
mod persistence;
mod pex_runtime;
mod rendezvous_binder;
mod resumption_state;
mod routing_health;
mod routing_state;
mod service_tasks;
mod services;
mod session_defaults;
mod session_guard;
mod sovereign_republish;
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
    next_link_id: Arc<AtomicU64>,
    pending_accepts: Arc<Mutex<AcceptWaiters>>,
    pub logger: Arc<NodeLogger>,
    pub metrics: Option<Arc<NodeMetrics>>,
    pub dispatcher: Arc<FrameDispatcher>,
    pub session_registry: Arc<Mutex<veil_session::SessionRegistry>>,
    pub session_tx_registry: Arc<RwLock<veil_session::SessionTxRegistry>>,
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
    pub outbound_connector_node_ids: Arc<Mutex<std::collections::HashSet<[u8; 32]>>>,
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
    pub metrics: Option<Arc<NodeMetrics>>,
    /// Authenticated peer node_id from the handshake.
    pub peer_id: NodeId,
    /// Session keys derived during the OVL1 handshake.
    pub session_keys: veil_crypto::session_kdf::SessionKeys,
    /// Transport-layer observed address of the peer (as seen by our socket).
    /// `None` for stream transports that do not expose a remote address.
    pub observed_addr: Option<std::net::SocketAddr>,
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
    outbound_connector_node_ids: Arc<Mutex<std::collections::HashSet<[u8; 32]>>>,
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
    /// ML-KEM-768 decapsulation-key seed (private, 64 bytes).
    /// (Stays outside the IdentityState bundle: it's the local-only
    /// secret half of mlkem_ek and has different access patterns —
    /// only the dispatcher reads it, never cloned into per-session
    /// contexts.)
    ///
    /// Phase 6 slice 6g — backed by `SensitiveBytesN<64>` (mlocked when
    /// `RLIMIT_MEMLOCK` permits, zeroize-on-drop fallback otherwise).
    /// See `FrameDispatcher::mlkem_dk_seed` rustdoc for threat model
    /// and why pinning matters more here than for session-scoped keys.
    pub mlkem_dk_seed:
        Arc<veil_util::sensitive_bytes::SensitiveBytesN<{ veil_e2e::DK_SEED_BYTES }>>,
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
    /// [`Arc<ResumptionState>`]. `ticket_issuer` rotated every
    /// `TICKET_KEY_ROTATION_SECS` seconds; per-peer `peer_tickets`
    /// presented in HELLO TLV on reconnect. See
    /// `node/runtime/resumption_state.rs`.
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
    /// audit log for mutating admin commands. `None`
    /// when the on-disk file couldn't be opened (warned at startup);
    /// admin handlers fall back to no-op auditing in that case.
    pub admin_audit: Option<Arc<crate::admin_audit::AdminAuditLog>>,
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

impl NodeRuntime {
    pub async fn start(config_path: impl AsRef<Path>, foreground_mode: bool) -> Result<Self> {
        let config_path = config_path.as_ref().to_path_buf();
        let config = veil_cfg::load_config(&config_path)?;

        // Fail fast if the config has structural or identity issues.
        let validation = veil_cfg::validate(&config);
        if !validation.is_valid() {
            return Err(NodeError::Config(veil_cfg::ConfigError::ValidationFailed(
                validation.format_issues(),
            )));
        }

        let logger = Arc::new(veil_cfg::observability_glue::logger_from_config(&config)?);

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

        // 62.3: ML-KEM-768 keypair — load from disk or generate at first run.
        let veil_dir_path = config_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .to_path_buf();
        let mlkem_key_path = veil_dir_path.join("mlkem.key");
        // Resolve passphrase via the priority cascade: prompt > env > file >
        // inline. Wrapped in Zeroizing<String> so the heap contents are wiped
        // when this binding drops at end of `start`.
        let key_passphrase = crate::key_passphrase::resolve_key_passphrase(&config, &logger)?;
        let (mlkem_ek_arr, mlkem_dk_arr) = veil_e2e::load_or_generate_mlkem_key_encrypted(
            &mlkem_key_path,
            key_passphrase.as_deref().map(|p| p.as_str()),
        )
        .map_err(|e| crate::error::NodeError::InvalidArgument(format!("{e}")))?;
        // Explicit drop here documents the intent: passphrase no longer needed
        // after Argon2-derive completed inside the loader. Zeroizing's Drop
        // wipes the String's heap allocation on this line.
        drop(key_passphrase);
        let mlkem_ek = Arc::new(mlkem_ek_arr);
        // Phase 6 slice 6g — wrap the long-lived DK seed in a
        // SensitiveBytesN<64> wrapper so the bytes are mlock-pinned
        // (or zeroize-on-drop fallback) for the process lifetime.  The
        // raw `[u8; 64]` from `load_or_generate_mlkem_key_encrypted`
        // gets copied into the mlocked storage and the source array
        // goes out of scope at the end of this statement (stack drop).
        let mlkem_dk_seed = Arc::new(veil_util::sensitive_bytes::SensitiveBytesN::<
            { veil_e2e::DK_SEED_BYTES },
        >::from_bytes(mlkem_dk_arr));

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
                    Err(e) => {
                        // Log and continue as legacy — a corrupt identity
                        // file should not block node startup. Operator
                        // intervention required to re-provision via
                        // `veil-cli identity create`.
                        logger.warn(
                            "node.sovereign_identity.load_failed",
                            format!("{e} — running as legacy node_id-keyed"),
                        );
                        None
                    }
                }
            } else {
                // no document on disk — try the standalone
                // branch. We need an Ed25519 device SK; the config's
                // `[identity]` block carries one for normal nodes.
                build_standalone_sovereign_identity(&veil_dir_path, &config, &logger)
            }
        };

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
        let peer_sovereign_identities: Arc<
            Mutex<std::collections::HashMap<[u8; 32], veil_identity::verify::ValidatedIdentity>>,
        > = Arc::new(Mutex::new(std::collections::HashMap::with_capacity(
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
            let publisher =
                crate::identity_local::publisher_dht::DhtBackedPublisher::new(Arc::clone(&dht));
            match veil_identity::publish::publish_identity_document(
                &sov.document, &publisher,
            ).await {
                Ok(()) => logger.info(
                    "node.sovereign_identity.published",
                    format!(
                        "node_id={} valid_until_unix={}",
                        veil_util::bytes_to_hex(sov.node_id()),
                        sov.document.valid_until_unix,
                    ),
                ),
                Err(e) => logger.warn(
                    "node.sovereign_identity.publish_failed",
                    format!(
                        "node_id={} — DHT publish failed: {e} (peers may not find this identity until republish)",
                        veil_util::bytes_to_hex(sov.node_id()),
                    ),
                ),
            }

            // InstanceRegistry publish: advertise this node's single
            // instance so peers can locate it by (node_id
            // instance_id). For MVP, `reg_version = 1` on every
            // fresh startup — peers tie-break on (version, sig) so
            // republishing the same version is benign. Future:
            // persist + monotonically bump reg_version across
            // restarts, and extend the entry list when paired
            // devices (462.30) join the identity.
            let instance_entry = veil_identity::publish::build_instance_entry(
                sov.active_instance_id(),
                sov.sig_key_idx,
                String::new(), // label empty for MVP; CLI flag to set it is follow-up
                0,             // last_seen_unix_ms — populated by subsequent republishes
            );
            let registry = sov.build_and_sign_registry(1, vec![instance_entry]);
            match veil_identity::publish::publish_instance_registry(&registry, &publisher).await {
                Ok(()) => logger.info(
                    "node.sovereign_identity.registry_published",
                    format!(
                        "node_id={} reg_version={} instances={}",
                        veil_util::bytes_to_hex(sov.node_id()),
                        registry.reg_version,
                        registry.instances.len(),
                    ),
                ),
                Err(e) => logger.warn(
                    "node.sovereign_identity.registry_publish_failed",
                    format!(
                        "node_id={} — registry DHT publish failed: {e}",
                        veil_util::bytes_to_hex(sov.node_id()),
                    ),
                ),
            }

            // per-instance ML-KEM cert — binds this node's
            // ML-KEM-768 encapsulation key (already loaded or generated
            // at startup into `mlkem_ek`) to the active identity subkey.
            // Peers resolving this identity can E2E-encrypt toward
            // `(node_id, instance_id)` without a separate X3DH-style
            // prekey fetch. `cert_version = 1` for MVP (parallels
            // `reg_version` above — future persist + bump). Validity
            // window: 30 days from startup, per spec.
            let cert_valid_from = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let cert_valid_until = cert_valid_from + 30 * 86_400;
            match sov.sign_mlkem_cert(
                mlkem_ek.as_slice().to_vec(),
                cert_valid_from,
                cert_valid_until,
                1,
            ) {
                Ok(cert) => {
                    match veil_identity::publish::publish_mlkem_cert(&cert, &publisher).await {
                        Ok(()) => logger.info(
                            "node.sovereign_identity.mlkem_cert_published",
                            format!(
                                "node_id={} instance_id={} cert_version={}",
                                veil_util::bytes_to_hex(sov.node_id()),
                                veil_util::bytes_to_hex(&sov.active_instance_id()),
                                cert.cert_version,
                            ),
                        ),
                        Err(e) => logger.warn(
                            "node.sovereign_identity.mlkem_cert_publish_failed",
                            format!(
                                "node_id={} — ML-KEM cert DHT publish failed: {e}",
                                veil_util::bytes_to_hex(sov.node_id()),
                            ),
                        ),
                    }
                }
                Err(e) => logger.warn(
                    "node.sovereign_identity.mlkem_cert_sign_failed",
                    format!(
                        "node_id={} — ML-KEM cert signing failed: {e}",
                        veil_util::bytes_to_hex(sov.node_id()),
                    ),
                ),
            }

            // publish any persisted NameClaim files the user
            // has claimed via `veil-cli identity claim-name`. Scan is
            // tolerant — a corrupt file doesn't block the rest. Empty
            // directory (fresh node, no names) is a clean no-op.
            match veil_identity::sovereign::load_persisted_name_claims(&veil_dir_path) {
                Ok(claims) if !claims.is_empty() => {
                    for claim in &claims {
                        match veil_identity::publish::publish_name_claim(claim, &publisher).await {
                            Ok(()) => logger.info(
                                "node.sovereign_identity.name_claim_published",
                                format!(
                                    "node_id={} name=\"{}\"",
                                    veil_util::bytes_to_hex(sov.node_id()),
                                    claim.name,
                                ),
                            ),
                            Err(e) => logger.warn(
                                "node.sovereign_identity.name_claim_publish_failed",
                                format!(
                                    "node_id={} name=\"{}\" — publish failed: {e}",
                                    veil_util::bytes_to_hex(sov.node_id()),
                                    claim.name,
                                ),
                            ),
                        }
                    }
                }
                Ok(_) => {
                    // No claims persisted — normal on a fresh node.
                }
                Err(e) => logger.warn(
                    "node.sovereign_identity.name_claims_scan_failed",
                    format!(
                        "node_id={} — name_claims scan failed: {e}",
                        veil_util::bytes_to_hex(sov.node_id()),
                    ),
                ),
            }
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
                let sk = crate::identity_local::anonymity_x25519::load_or_create(&veil_dir_path)?;
                Some(Arc::new(sk))
            } else {
                None
            };
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
                mlkem_ek: Arc::clone(&mlkem_ek),
                mlkem_dk_seed: Arc::clone(&mlkem_dk_seed),
                peer_mlkem_keys: Arc::clone(&shared_peer_mlkem_keys),
                peer_pubkeys: Arc::clone(&peer_pubkeys),
                peer_roles: Arc::clone(&peer_roles),
                peer_cap_flags: Arc::clone(&peer_cap_flags),
                per_session_mlkem_dk: Arc::clone(&shared_per_session_mlkem_dk),
            }),
            abuse: Arc::new(veil_dispatcher::AbuseContext {
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
            route_seen_set: Arc::clone(&shared_route_seen_set),
            announce_seq: Arc::clone(&shared_announce_seq),
            listen_transports: Arc::clone(&listen_transports),
            relay_node_ids: build_relay_node_ids(&config),
            target_labels: build_target_labels(&config.routing),
            route_updated: Arc::clone(&shared_route_updated),
            pow_difficulty: config.abuse.pow_min_difficulty as u8,
            pow_pending: Arc::new(Mutex::new(veil_dispatcher::PowPendingTable::new())),
            discovery_mode: config.routing.discovery_mode,
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
            vvsync_seen: Arc::new(Mutex::new(veil_dispatcher::ExpiryCache::new(
                std::time::Duration::from_secs(veil_proto::budget::VVSYNC_MIN_INTERVAL_SECS),
                veil_proto::budget::MAX_VVSYNC_SEEN_SIZE,
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
            // NAT relay tunnel table (empty; populated by NatRelayRequest dispatch).
            relay_tunnels: Arc::new(Mutex::new(std::collections::HashMap::new())),
            // pending NAT-probe waiters (empty; populated by attempt_nat_traversal).
            nat_probe_waiters: Arc::new(Mutex::new(std::collections::HashMap::new())),
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
        let mut runtime = Self {
            config_path,
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
            session_registry: shared_session_registry,
            app_registry,
            gateway,
            discovery,
            dht,
            control_plane,
            mesh_forwarder,
            // metrics is moved into the field below, so clone here first.
            mesh_bridge: Arc::new(
                GatewayBridge::new(local_node_id, role).with_metrics(
                    metrics
                        .as_ref()
                        .map(|m| Arc::clone(m) as Arc<dyn veil_mesh::MeshMetrics>),
                ),
            ),
            mesh_realm,
            autodiscovered_peers: Arc::new(veil_mesh::AutoDiscoveredPeers::new()),
            // trips when a synthetic-range gateway session
            // closes, so `spawn_gateway_autodiscover_loop` can wake
            // immediately and back-fill instead of waiting for its
            // periodic poll. Drives the < 1 s failover acceptance bar.
            gateway_failover_notify: Arc::new(tokio::sync::Notify::new()),
            // see field doc comment.
            force_reconnect_notify: Arc::new(tokio::sync::Notify::new()),
            // shared push-event bus. Default capacity (256)
            // — fast subscribers consume events in microseconds; only
            // pathologically slow consumers (Flutter UI mid-paint) ever
            // hit the lag boundary, and they get a one-frame skip
            // rather than a stalled publisher.
            event_bus: Arc::new(veil_ipc::EventBus::new()),
            // empty registry of node_ids with active
            // outbound-connector tasks; populated atomically inside
            // `spawn_outbound_peers`.
            outbound_connector_node_ids: Arc::new(Mutex::new(std::collections::HashSet::new())),
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
            // bundle 8 identity-domain fields into one Arc.
            identity: Arc::new(identity_state::IdentityState::new(
                Arc::clone(&local_identity),
                sovereign_identity.clone(),
                Arc::clone(&peer_pubkeys),
                Arc::clone(&peer_sovereign_identities),
                Arc::clone(&peer_roles),
                Arc::clone(&mlkem_ek),
                Arc::clone(&shared_peer_mlkem_keys),
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
            mlkem_dk_seed,
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
                Arc::new(Mutex::new(veil_session::ticket::TicketIssuer::new(
                    veil_session::ticket::TicketKey::generate(),
                ))),
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
        // prime the global session-rotation interval
        // (0 = disabled). Runtime-side clamp ensures any value
        // < 60 gets pushed up to the floor, defending against
        // misconfig OR validation bypass.
        //
        // Precedence (mirrors the reload path in lifecycle.rs):
        //   1. `[transport.rotation]` range knob (new) — preferred.
        //   2. `session.max_age_secs` (deprecated single-value) —
        //      back-compat fallback only when the new section is
        //      disabled (`-1`/`-1`) AND legacy field is set.
        if let Some((min, max)) = config.transport.rotation.resolved_range() {
            veil_session::runner::set_session_rotation_range(min, max);
            if config.session.max_age_secs.is_some() {
                runtime.logger.warn(
                    "config.session.max_age_secs.shadowed",
                    "session.max_age_secs is set but [transport.rotation] takes precedence — \
                     remove session.max_age_secs from the config to silence this warning",
                );
            }
        } else if let Some(secs) = config.session.max_age_secs {
            runtime.logger.warn(
                "config.session.max_age_secs.deprecated",
                format!(
                    "session.max_age_secs={secs} is DEPRECATED — migrate to the \
                     [transport.rotation] section (min_lifetime_secs + max_lifetime_secs, \
                     -1 on both for disable) for range-based jitter that defeats \
                     fleet-correlation DPI fingerprinting"
                ),
            );
            veil_session::runner::set_session_max_age_secs(secs);
        } else {
            veil_session::runner::set_session_rotation_range(0, 0);
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
        // Local first — always succeeds.
        self.dht.store_local(key, value.clone());

        // K-closest replicas: skip self, skip dead sessions. Use the
        // routing table's keyspace ranking, not the live-session set
        // so we hit the truly closest peers in the network — STORE
        // forwards greedy if we don't have direct sessions to all of
        // them.
        let local_node_id = *self.identity.local_identity.node_id.as_bytes();
        let candidates: Vec<[u8; 32]> = self
            .dht
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

        // Fan-out — send_to is fire-and-forget on the session_tx
        // registry. Peers without a direct session are silently
        // skipped (the STORE recursive-forward path handles those
        // hops via greedy walk on receivers we DO have sessions).
        let mut sent = 0usize;
        let guard = rlock!(self.session_tx_registry);
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
        // Wrap data in `AppDeliverPayload` so the receiver's
        // Final-hop dispatcher can route to the addressed endpoint.
        // src_node_id stays zero — anonymity guarantees the receiver
        // does NOT learn the sender's node identity at this layer
        // (replies require a separate rendezvous flow).
        let deliver_payload = veil_proto::AppDeliverPayload {
            src_node_id: [0u8; 32],
            src_app_id,
            app_id: target_app_id,
            endpoint_id: target_endpoint_id,
            data: veil_bufpool::pooled_shared_from_vec(data.to_vec()),
            reply_id: 0,
        };
        let deliver_bytes = deliver_payload.encode();
        // Final-hop tag byte: kind = APP_DELIVER
        // tells the receiver dispatcher to route locally vs forward
        // through a rendezvous-relay flow.
        let mut payload_bytes = Vec::with_capacity(1 + deliver_bytes.len());
        payload_bytes.push(veil_anonymity::rendezvous::final_hop_kind::APP_DELIVER);
        payload_bytes.extend_from_slice(&deliver_bytes);

        self.send_anonymous_onion(&payload_bytes, target_node_id, target_x25519_pk, hop_count)
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
            .as_ref()
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
            None, // direct onion path: no reply block (r3 wires rendezvous replies)
        );
        let auth_bytes = auth.encode();
        // Final-hop tag byte: kind = APP_DELIVER_AUTH tells the receiver
        // dispatcher to decode an `AuthAppDeliver` (not a plain
        // `AppDeliverPayload`) and run sender verification before delivery.
        let mut payload_bytes = Vec::with_capacity(1 + auth_bytes.len());
        payload_bytes.push(veil_anonymity::rendezvous::final_hop_kind::APP_DELIVER_AUTH);
        payload_bytes.extend_from_slice(&auth_bytes);

        self.send_anonymous_onion(&payload_bytes, target_node_id, target_x25519_pk, hop_count)
    }

    /// Common onion-send path shared by [`send_anonymous`] (un-authenticated)
    /// and [`send_anonymous_authenticated`]. `payload` is the already-assembled
    /// final-hop blob: a `final_hop_kind` tag byte followed by the
    /// kind-specific body. This helper owns candidate selection, relay
    /// discovery/verify, AS-diversity + reputation-weighted circuit picking,
    /// the onion wrap, and the fire-and-forget first-hop send.
    fn send_anonymous_onion(
        &self,
        payload: &[u8],
        target_node_id: [u8; 32],
        target_x25519_pk: [u8; 32],
        hop_count: usize,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        use veil_anonymity::{
            directory::{
                DEFAULT_FRESHNESS_WINDOW_SECS, discover_relay_hops, relay_directory_dht_key,
            },
            sender::{
                DiversityOutcome,
                build_outbound_anonymous_cell_with_diversity_reported_and_reputation,
            },
        };

        // W0 measurement (anonymity-preserving plan): time the SELECTION phase
        // (candidate snapshot + relay discovery/verify + diversity map) vs the
        // BUILD phase (pick + onion wrap) to decide whether selection dominates
        // the per-send overhead (gates W2 selection-input caching). Local timing
        // of our OWN send — nothing is transmitted, no peer correlation; emitted
        // at debug level (off by default).
        let t_select = std::time::Instant::now();

        // Step 1: snapshot candidates from local DHT routing table.
        // We could also pull from PEX-discovered peers or the live-
        // sessions registry, but routing table is the canonical
        // "peers we already know about" set + matches the security
        // story (anonymity layer must not consult sources that an
        // attacker can poison faster than DHT).
        let candidate_node_ids: Vec<[u8; 32]> = self
            .dht
            .routing_table_contacts()
            .into_iter()
            .map(|c| c.node_id)
            .collect();

        // Step 2 + 3: fetch + verify + filter via discovery helper.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dht = Arc::clone(&self.dht);
        let usable_relays = discover_relay_hops(
            &candidate_node_ids,
            |node_id| dht.get_local(&relay_directory_dht_key(node_id)),
            now_unix,
            DEFAULT_FRESHNESS_WINDOW_SECS,
        );

        // Step 4: build the cell. RTT estimator pulls from Vivaldi
        // when local coords have converged; falls back to None
        // (which the picker handles by sorting unknown-RTT to last).
        let local_vivaldi = self.dispatcher.local_vivaldi.clone();
        let peer_vivaldi = Arc::clone(&self.dispatcher.peer_vivaldi);
        let rtt_estimator = move |node_id: &[u8; 32]| -> Option<u32> {
            // Vivaldi distance estimate: Euclidean distance between
            // local + peer coords, scaled. When either coord is
            // unknown, return None (picker treats as worst-priority).
            let local = local_vivaldi.as_ref()?;
            let peer_map = rlock!(peer_vivaldi);
            let (peer_coord, _) = peer_map.get(node_id)?;
            let local_guard = lock!(local);
            let estimated_ms = local_guard.distance_estimate(peer_coord) * 1000.0;
            // Sanity: clamp to u32 range. Vivaldi can return
            // negative or NaN values during convergence — treat as
            // unknown (None) so picker doesn't sort by garbage.
            if !estimated_ms.is_finite() || estimated_ms < 0.0 {
                return None;
            }
            Some(estimated_ms.min(u32::MAX as f64) as u32)
        };

        // Anti-censorship AS-diversity extractor — snapshots already-
        // dialed peers' IPs from discovered_peers_cache + builds a
        // node_id → /16 (IPv4) / /32 (IPv6) prefix map.  Used by the
        // circuit picker to enforce "no two hops in the same /16" even
        // when relay-directory wire format doesn't carry IP/ASN.
        // Unknown relays get `None` (graceful degradation —
        // picker accepts them without a diversity gate).
        let diversity_map = build_as_diversity_map(&self.discovered_peers_cache);
        let diversity_key_of =
            move |node_id: &[u8; 32]| -> Option<String> { diversity_map.get(node_id).cloned() };

        // Downweight relays with recorded failures (Epic 482.3/482.4 Phase A):
        // a misbehaving relay's effective RTT is bumped by its penalty so it
        // sorts behind viable alternatives.
        let relay_reputation = Arc::clone(&self.anonymity.relay_reputation);
        let reputation_penalty_ms =
            move |node_id: &[u8; 32]| -> u32 { relay_reputation.rtt_penalty_ms(*node_id) };
        let select_us = t_select.elapsed().as_micros();
        let t_build = std::time::Instant::now();
        let ((first_hop_node_id, cell), diversity) =
            build_outbound_anonymous_cell_with_diversity_reported_and_reputation(
                payload,
                &usable_relays,
                rtt_estimator,
                diversity_key_of,
                reputation_penalty_ms,
                target_node_id,
                target_x25519_pk,
                hop_count,
            )?;
        // W0 measurement: selection (candidate prep + discovery + diversity map)
        // vs build (pick + onion wrap). The anonymity-preserving plan expects
        // selection to dominate → justifies W2 selection-input caching.
        log::debug!(
            "anonymity.send.timing select_us={select_us} build_us={} \
             payload={} hops={hop_count} candidates={} usable={}",
            t_build.elapsed().as_micros(),
            payload.len(),
            candidate_node_ids.len(),
            usable_relays.len(),
        );
        if diversity == DiversityOutcome::DegradedToLatency {
            // AS-correlation protection was silently lost — surface it so an
            // operator can see when circuits aren't netblock-diverse. (cycle-8 F4.)
            log::warn!(
                "anonymity.circuit.diversity_degraded hop_count={hop_count} \
                 candidates={} — no AS-diverse relay set; fell back to latency-only",
                usable_relays.len()
            );
        }

        // Step 5: hit the wire. RelayChain::Hop frame to first hop's
        // session. If first_hop has no live session, the send is a
        // silent drop — caller learns from app-layer timeout, NOT
        // from a synchronous error (which would leak whether the
        // first hop is reachable to a sender-side observer).
        use veil_proto::{
            codec::encode_header,
            family::{FrameFamily, RelayChainMsg},
            header::FrameHeader,
        };
        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
        hdr.body_len = cell.len() as u32;
        hdr.set_priority(veil_proto::priority::INTERACTIVE);
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(&cell);
        if let Some(ref reg) = self.dispatcher.session_tx_registry {
            let guard = wlock!(reg);
            let sent = guard.send_to(&first_hop_node_id, veil_proto::priority::INTERACTIVE, frame);
            drop(guard);
            if !sent {
                // Signal 1 (Epic 482.3/482.4 Phase A): the chosen anonymity
                // first hop has no live session — record it so the picker
                // downweights it next time. This is per-sender-LOCAL memory and
                // changes NO external behaviour (we still return Ok, no
                // synchronous error), so it does not leak first-hop reachability
                // to a sender-side observer (the reason this stays fire-and-forget).
                self.anonymity
                    .relay_reputation
                    .record_failure(first_hop_node_id);
            }
        }
        Ok(())
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
            .send_sealed_introduce(ad, &sealed_plaintext, hop_count)
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
    ) {
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

    /// same as [`Self::register_rendezvous_publisher`] but
    /// associates a sealed push envelope with the publication. The
    /// envelope (FCM/APNs token sealed for a trusted push-relay) is
    /// embedded in every signed ad refresh until [`Self::set_rendezvous_push_envelope`]
    /// updates it OR the entry is unregistered. Empty `push_envelope`
    /// is equivalent to the no-push API.
    pub fn register_rendezvous_publisher_with_push(
        &self,
        rendezvous_node_id: [u8; 32],
        auth_cookie: [u8; 16],
        validity_window_secs: u64,
        push_envelope: Vec<u8>,
    ) {
        let entry = veil_anonymity::rendezvous::RendezvousPublisherEntry {
            rendezvous_node_id,
            auth_cookie,
            validity_window_secs,
            push_envelope,
            // .10 slice 4.3.2: defaults to empty (HMAC opt-out — receiver
            // upgrades via a separate IPC call wired in slice 4.3.3).
            wake_hmac_envelope: Vec::new(),
        };
        let mut entries = lock!(self.anonymity.rendezvous_publisher_entries);
        // Replace existing entry with same (rendezvous, cookie) pair.
        if let Some(pos) = entries.iter().position(|e| {
            e.rendezvous_node_id == rendezvous_node_id && e.auth_cookie == auth_cookie
        }) {
            entries[pos] = entry;
        } else {
            entries.push(entry);
        }
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
    pub fn route_cache_all(&self) -> Vec<([u8; 32], [u8; 32], u32, u8)> {
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

        let (config_peers, dns_domain, https_urls) = match veil_cfg::load_config(&self.config_path)
        {
            Ok(c) => (
                c.bootstrap_peers.len(),
                c.global
                    .bootstrap_dns_domain
                    .clone()
                    .filter(|s| !s.trim().is_empty()),
                c.global.bootstrap_https_urls.len(),
            ),
            // Reload failure shouldn't bring down the diag — fall back
            // to "0 / None" so the operator at least sees the cache and
            // builtin counts. A separate err log surfaces the cause.
            Err(e) => {
                self.logger.warn(
                    "bootstrap.status.config_load_failed",
                    format!("falling back to in-runtime view: {e}"),
                );
                (0, None, 0)
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
            + (discovered_cache.entries > 0) as u8;

        AdminBootstrapStatus {
            config_peers,
            builtin_seeds,
            https_urls,
            dns_domain,
            discovered_cache,
            healthy_layers,
            total_layers: 5,
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

impl NodeServices {
    pub async fn dht_get_replicated(
        &self,
        key: [u8; 32],
        n_replicas: usize,
        timeout: std::time::Duration,
        // F1 (DHT cache-poisoning): a local cache value is an OPTIMIZATION, not a
        // trust boundary. The identity-family STORE path stores NM/ID/IR/MC
        // bytes after STRUCTURAL decode only (verification is deferred to read),
        // so a peer can park a structurally-valid but cryptographically-invalid
        // value under a target key. The single-replica local fast path then
        // short-circuits remote quorum and the resolver fails verification with
        // no fallback — a targeted resolve DoS (and, for names, a quorum bypass).
        // The fast path is now taken ONLY when `validate` accepts the local
        // bytes; otherwise we fall through to remote quorum (the resolver's
        // post-quorum `store_local` then repairs the poisoned shard). Pass
        // `|_| true` to preserve the old unconditional fast path.
        validate: impl Fn(&[u8]) -> bool,
    ) -> Vec<Vec<u8>> {
        // Validated local fast path. A local value that fails `validate`
        // (poisoned / unverifiable) does NOT short-circuit — it falls through to
        // the remote quorum below.
        if let Some(value) = self.dht.get_local(&key)
            && validate(&value)
        {
            return vec![value];
        }
        let n = n_replicas.clamp(1, veil_proto::budget::DHT_REPLICATION_K);

        let mut peers: Vec<[u8; 32]> = rlock!(self.session_tx_registry).peer_ids();
        if peers.is_empty() {
            return Vec::new();
        }
        peers.sort_by_key(|pid| {
            let mut xor = [0u8; 32];
            for i in 0..32 {
                xor[i] = pid[i] ^ key[i];
            }
            xor
        });
        let targets: Vec<[u8; 32]> = peers.into_iter().take(n).collect();
        if targets.is_empty() {
            return Vec::new();
        }

        let local_node_id = *self.identity.local_identity.node_id.as_bytes();

        // Per-target: fresh query_id, oneshot, encoded frame. We
        // build them all up-front so the registration / send batch
        // is mostly lock-free at the call site.
        struct PerTarget {
            rx: tokio::sync::oneshot::Receiver<Vec<u8>>,
            frame: Vec<u8>,
            peer: [u8; 32],
        }
        let mut work: Vec<PerTarget> = Vec::with_capacity(targets.len());
        for peer in &targets {
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
                query_type: veil_proto::routing::recursive_query_type::FIND_VALUE,
                reply_port: 0,
                payload: vec![],
            };
            let q_bytes = q.encode();
            let mut hdr = veil_proto::header::FrameHeader::new(
                veil_proto::family::FrameFamily::Routing as u8,
                veil_proto::family::RoutingMsg::RecursiveQuery as u16,
            );
            hdr.body_len = q_bytes.len() as u32;
            let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
            frame.extend_from_slice(&q_bytes);

            // oncurrency-register the pending
            // entry FIRST, then push to `work`. The previous order
            // pushed `(tx, rx, frame)` into `work`, then on cap-hit
            // BROKE without registering the tx — leaving the rx
            // waiting for a response that the dispatcher could never
            // route back (no matching entry in `pending_recursive`).
            // Originator silently timed out instead of failing fast.
            // Now: if cap is hit before registering, drop the just-
            // created tx/rx pair and break without polluting `work`.
            use veil_proto::budget::MAX_PENDING_RECURSIVE;
            let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
            {
                let mut m = lock!(self.dispatcher.pending_recursive);
                m.retain(|_, p| !p.tx.is_closed());
                if m.len() >= MAX_PENDING_RECURSIVE {
                    // Out of pending slots — drop tx/rx, do not push
                    // to `work`, work with whatever was registered
                    // before this iteration.
                    break;
                }
                m.insert(
                    query_id,
                    veil_dispatcher::PendingRecursive {
                        target_key: key,
                        query_type: veil_proto::routing::recursive_query_type::FIND_VALUE,
                        tx,
                    },
                );
            }
            work.push(PerTarget {
                rx,
                frame,
                peer: *peer,
            });
        }

        // Fan-out: send each peer their own query_id'd frame.
        {
            let guard = rlock!(self.session_tx_registry);
            for w in &work {
                guard.send_to(
                    &w.peer,
                    veil_proto::header::priority::INTERACTIVE,
                    w.frame.clone(),
                );
            }
        }

        // Collect: race every oneshot against the shared deadline.
        // Use `tokio::select!` over a `FuturesUnordered` so peers that
        // respond fast contribute to the tally even if a sybil sits
        // at the top of the closest list and never replies.
        let deadline = tokio::time::Instant::now() + timeout;
        let mut futs: futures::stream::FuturesUnordered<_> = work
            .into_iter()
            .map(|w| async move { tokio::time::timeout_at(deadline, w.rx).await })
            .collect();

        let mut out: Vec<Vec<u8>> = Vec::new();
        use futures::StreamExt;
        while let Some(res) = futs.next().await {
            if let Ok(Ok(payload)) = res
                && !payload.is_empty()
            {
                out.push(payload);
            }
        }
        out
    }

    // ── audit cycle-6 (T7): admin network ops relocated here from
    // `impl NodeRuntime` so the admin handlers can run them on an
    // Arc-cloned `access()` bundle WITHOUT holding the NodeRuntime mutex
    // across the multi-second network await (DHT walk / identity+name
    // resolution). `self.{dht,dispatcher,identity,session_tx_registry}`
    // resolve identically on NodeServices. ──────────────────────────────
    pub async fn dht_recursive_get(
        &self,
        key: [u8; 32],
        timeout: std::time::Duration,
    ) -> Option<Vec<u8>> {
        // Local fast path.
        if let Some(value) = self.dht.get_local(&key) {
            return Some(value);
        }

        // Pick K closest active session peers; bail if we have no
        // peers to forward (can't do a recursive walk solo).
        let mut peers: Vec<[u8; 32]> = rlock!(self.session_tx_registry).peer_ids();
        if peers.is_empty() {
            return None;
        }
        peers.sort_by_key(|pid| {
            let mut xor = [0u8; 32];
            for i in 0..32 {
                xor[i] = pid[i] ^ key[i];
            }
            xor
        });

        // Build the RecursiveQuery frame with a fresh 16-byte query_id.
        let local_node_id = *self.identity.local_identity.node_id.as_bytes();
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
            query_type: veil_proto::routing::recursive_query_type::FIND_VALUE,
            reply_port: 0,
            payload: vec![],
        };
        let q_bytes = q.encode();
        let mut hdr = veil_proto::header::FrameHeader::new(
            veil_proto::family::FrameFamily::Routing as u8,
            veil_proto::family::RoutingMsg::RecursiveQuery as u16,
        );
        hdr.body_len = q_bytes.len() as u32;
        let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
        frame.extend_from_slice(&q_bytes);

        // Register a oneshot so the dispatcher's response handler can
        // wake us when the matching RecursiveResponse arrives.
        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        {
            use veil_proto::budget::MAX_PENDING_RECURSIVE;
            let mut m = lock!(self.dispatcher.pending_recursive);
            m.retain(|_, p| !p.tx.is_closed());
            if m.len() >= MAX_PENDING_RECURSIVE {
                return None;
            }
            m.insert(
                query_id,
                veil_dispatcher::PendingRecursive {
                    target_key: key,
                    query_type: veil_proto::routing::recursive_query_type::FIND_VALUE,
                    tx,
                },
            );
        }

        // Forward to top-2 closest peers.
        {
            let guard = rlock!(self.session_tx_registry);
            for pid in peers.iter().take(2) {
                guard.send_to(
                    pid,
                    veil_proto::header::priority::INTERACTIVE,
                    frame.clone(),
                );
            }
        }

        // Await the response or timeout.
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(payload)) if !payload.is_empty() => Some(payload),
            _ => None,
        }
    }

    pub async fn resolve_identity_verified(
        &self,
        node_id: [u8; 32],
        now_unix_secs: u64,
        timeout: std::time::Duration,
    ) -> std::result::Result<
        veil_identity::verify::ValidatedIdentity,
        veil_identity::resolver::ResolveError,
    > {
        use veil_identity::resolver::{MAX_MIGRATION_CHAIN_DEPTH, ResolveError};

        // walk any MigrationCert chain rooted at the
        // requested `node_id` until either a steady-state document is
        // reached or the depth/cycle bounds are hit. Each hop's cert
        // signature is verified against the CURRENT document's master
        // pubkey, so a sybil who only controls the DHT cannot forge a
        // migration — they'd need the old master's secret to mint a
        // cert binding their own pubkey.
        let mut current_node_id = node_id;
        let mut visited: Vec<[u8; 32]> = vec![current_node_id];

        for hop in 0..=MAX_MIGRATION_CHAIN_DEPTH {
            let (validated, _doc) = self
                .resolve_one_identity_doc(current_node_id, now_unix_secs, timeout)
                .await?;

            // Look for a migration cert published under this node_id.
            // No cert ⇒ steady state, return.
            let cert = match self
                .fetch_best_migration_cert_for(current_node_id, now_unix_secs, timeout)
                .await?
            {
                Some(c) => c,
                None => return Ok(validated),
            };

            if hop == MAX_MIGRATION_CHAIN_DEPTH {
                return Err(ResolveError::MigrationChainTooDeep {
                    max_depth: MAX_MIGRATION_CHAIN_DEPTH,
                });
            }

            let next = cert.new_node_id;
            if visited.iter().any(|n| n == &next) {
                return Err(ResolveError::MigrationChainCycle {
                    hop: hop + 1,
                    node_id: next,
                });
            }
            visited.push(next);
            current_node_id = next;
        }
        unreachable!("migration-chain loop must return inside the body");
    }

    async fn resolve_one_identity_doc(
        &self,
        node_id: [u8; 32],
        now_unix_secs: u64,
        timeout: std::time::Duration,
    ) -> std::result::Result<
        (
            veil_identity::verify::ValidatedIdentity,
            veil_proto::identity_document::IdentityDocument,
        ),
        veil_identity::resolver::ResolveError,
    > {
        use veil_identity::resolver::ResolveError;
        use veil_identity::verify::verify_identity_document;
        use veil_proto::identity_document::IdentityDocument;

        let key = IdentityDocument::dht_key(&node_id);

        // quorum policy preserved verbatim — N replicas
        // queried, ≥QUORUM matches required, anti-sybil at resolve.
        let replicas = self
            .dht_get_replicated(key, RESOLVE_MAX_REPLICAS, timeout, |bytes| {
                // Self-validating: a forged document cannot have
                // node_id == BLAKE3(its master), so a local doc that decodes for
                // `node_id` AND verifies is authoritative — trust the fast path.
                matches!(IdentityDocument::decode(bytes), Ok(d)
                    if d.node_id == node_id
                        && verify_identity_document(&d, now_unix_secs).is_ok())
            })
            .await;
        // Identity documents are self-certifying: each replica was already
        // filtered through `verify_identity_document` + `node_id == BLAKE3`
        // above, so a single verified replica is independently trustworthy →
        // allow_single_replica = true. (audit cycle-9.)
        let bytes =
            pick_quorum_match(&replicas, RESOLVE_QUORUM_THRESHOLD, true).ok_or_else(|| {
                if replicas.is_empty() {
                    ResolveError::IdentityNotFound(node_id)
                } else {
                    ResolveError::QuorumDivergence {
                        queried: replicas.len(),
                        best: replicas.iter().filter(|r| **r == replicas[0]).count(),
                        required: RESOLVE_QUORUM_THRESHOLD,
                    }
                }
            })?;
        // Cache-poison fix: overwrite the local DHT shard
        // with the quorum-winning bytes.
        self.dht.store_local(key, bytes.clone());
        let doc = IdentityDocument::decode(&bytes)
            .map_err(|e| ResolveError::IdentityDocMalformed(e.to_string()))?;
        if doc.node_id != node_id {
            return Err(ResolveError::IdentityDocMalformed(format!(
                "DHT returned IdentityDocument for {} but resolver \
                 asked for {}",
                veil_util::hex_short(&doc.node_id),
                veil_util::hex_short(&node_id),
            )));
        }
        let validated = verify_identity_document(&doc, now_unix_secs)
            .map_err(ResolveError::IdentityDocInvalid)?;
        Ok((validated, doc))
    }

    async fn fetch_best_migration_cert_for(
        &self,
        old_node_id: [u8; 32],
        now_unix_secs: u64,
        timeout: std::time::Duration,
    ) -> std::result::Result<
        Option<veil_identity::migration::MigrationCert>,
        veil_identity::resolver::ResolveError,
    > {
        use veil_identity::migration::{
            MigrationCert, decode_migration_cert, migration_cert_dht_key, pubkey_bytes_to_b64,
            verify_migration_cert,
        };
        use veil_identity::resolver::ResolveError;
        use veil_proto::identity_document::{
            ALGO_ED25519, ALGO_ED25519_FALCON512_HYBRID, ALGO_FALCON512, IdentityDocument,
        };

        // Tier-ranking helper duplicated locally (it lives privately in
        // both migration.rs and resolver.rs; keeping a 5-line copy beats
        // making the function pub).
        fn tier_rank(algo: u8) -> u8 {
            match algo {
                ALGO_ED25519 => 1,
                ALGO_FALCON512 => 2,
                ALGO_ED25519_FALCON512_HYBRID => 3,
                _ => 0,
            }
        }

        let cert_key = migration_cert_dht_key(&old_node_id);

        // Need the OLD master pubkey to verify cert signatures. The
        // previous hop's resolve_one_identity_doc just mirrored the
        // current document into the local store; pull it back for
        // free (no second quorum round-trip). Fetched BEFORE the replica
        // query so the fast-path validator (F1) can verify a local cert.
        let doc_key = IdentityDocument::dht_key(&old_node_id);
        let old_master_b64 = match self.dht.get_local(&doc_key) {
            Some(bytes) => match IdentityDocument::decode(&bytes) {
                Ok(doc) => pubkey_bytes_to_b64(&doc.master_pubkey),
                Err(_) => return Ok(None), // local cache corrupt; treat as no cert
            },
            None => return Ok(None), // no current doc → can't verify cert
        };

        let replicas = self
            .dht_get_replicated(cert_key, RESOLVE_MAX_REPLICAS, timeout, |bytes| {
                // Verify the local cert against the old master before trusting the
                // fast path (F1); a poisoned/unverifiable local cert falls through
                // to remote quorum instead of hiding a real published migration.
                matches!(decode_migration_cert(bytes), Ok(c)
                    if verify_migration_cert(&c, &old_master_b64, now_unix_secs).is_ok())
            })
            .await;
        if replicas.is_empty() {
            return Ok(None);
        }

        let mut best: Option<MigrationCert> = None;
        let mut first_decode_err: Option<String> = None;
        for blob in &replicas {
            let cert = match decode_migration_cert(blob) {
                Ok(c) => c,
                Err(e) => {
                    if first_decode_err.is_none() {
                        first_decode_err = Some(e.to_string());
                    }
                    continue;
                }
            };
            if verify_migration_cert(&cert, &old_master_b64, now_unix_secs).is_err() {
                continue;
            }
            best = match best {
                None => Some(cert),
                Some(prev) => {
                    let prev_tier = tier_rank(prev.new_master_algo);
                    let cur_tier = tier_rank(cert.new_master_algo);
                    if cur_tier > prev_tier
                        || (cur_tier == prev_tier && cert.issued_at_unix > prev.issued_at_unix)
                    {
                        Some(cert)
                    } else {
                        Some(prev)
                    }
                }
            };
        }

        if best.is_none()
            && let Some(msg) = first_decode_err
        {
            return Err(ResolveError::MigrationCertMalformed(msg));
        }
        // All replicas signed but none verified — treat as "no
        // migration published" (defence against a sybil spamming
        // junk under the cert key to stall name resolution).
        Ok(best)
    }

    pub async fn resolve_name_verified(
        &self,
        name: &str,
        now_unix_secs: u64,
        timeout: std::time::Duration,
    ) -> std::result::Result<
        veil_identity::verify::ValidatedIdentity,
        veil_identity::resolver::ResolveError,
    > {
        use veil_identity::resolver::{
            IdentityLookup, LookupError, NameLookup, NameResolver, ResolveError,
        };
        use veil_proto::name_claim_v2::{NameClaim, normalize_name};

        // Allow callers to pass either `"alice"` or `"@alice"` — the
        // user-facing handle convention (`@alice`) and the wire-level
        // claim name (`alice`) are the same string with the leading
        // sigil stripped. `normalize_name` does NOT strip it because
        // the `@` is invalid in a wire claim — handle it at the
        // resolver boundary so production callers don't need to know.
        let stripped = name.trim().strip_prefix('@').unwrap_or(name.trim());
        let normalized =
            normalize_name(stripped).map_err(|e| ResolveError::InvalidName(e.to_string()))?;
        let claim_key = NameClaim::dht_key(&normalized);
        // A NameClaim binds a name to the SOVEREIGN node_id of the signer
        // (`sign_name_claim` lives on `SovereignIdentity`), NOT the handshake /
        // PoW `local_identity`. A legacy (node_id-keyed) node has no sovereign
        // identity and never publishes a name, so it always falls through to
        // remote quorum.
        let our_sovereign_id = self
            .identity
            .sovereign_identity
            .as_ref()
            .map(|s| *s.node_id());
        // A name WE published is locally authoritative and needs NO remote
        // corroboration: quorum exists to stop a sybil forging a claim for
        // SOMEONE ELSE's name, but a NameClaim can only bind a name to the
        // sovereign node_id whose key signed it (re-verified by
        // `verify_name_claim` below), so a self-published claim (node_id ==
        // our sovereign id) is self-evidently ours. Resolve it straight from
        // the local store so an isolated / offline / sparse-network node can
        // always resolve its own @name.
        //
        // (cycle-10: the cycle-9 anti-sybil quorum gate over-corrected — the
        // `dht_get_replicated` local fast path returned the self-published value
        // as a single-element set, which then flowed into the ≥2 quorum check
        // below and was rejected as a "single remote response". The cycle-9
        // local-fast-path validator ALSO compared against `local_identity`, the
        // wrong identity for a sovereign-signed claim, so the fast path never
        // even fired for sovereign nodes. The fix distinguishes replica ORIGIN —
        // local-self vs remote — and compares against the SOVEREIGN id. A
        // poisoned local entry forging `@bob → our_sovereign_id` would resolve
        // to OUR identity, not the attacker's, and `verify_name_claim` below
        // rejects it unless the claim is signed by our key — which only we hold.)
        let self_published = our_sovereign_id.and_then(|our_id| {
            self.dht.get_local(&claim_key).filter(|bytes| {
                matches!(NameClaim::decode(bytes), Ok(c)
                    if c.name == normalized && c.node_id == our_id)
            })
        });
        let claim_bytes = if let Some(bytes) = self_published {
            bytes
        } else {
            // Remote name: NameClaim is NON-self-certifying (a self-consistent
            // forged claim @name -> attacker, signed by attacker, passes any
            // crypto self-check), so remote quorum is the only defense and a
            // single remote response must NOT be accepted → allow_single_replica
            // = false. (audit cycle-9 — closes the single-remote-responder name
            // hijack.) The local fast path inside `dht_get_replicated` is gated to
            // our sovereign id, which is false (or absent) for a remote name, so
            // it correctly falls through to the remote fan-out.
            let claim_replicas = self
                .dht_get_replicated(claim_key, RESOLVE_MAX_REPLICAS, timeout, |bytes| {
                    matches!((our_sovereign_id, NameClaim::decode(bytes)),
                        (Some(our_id), Ok(c))
                            if c.name == normalized && c.node_id == our_id)
                })
                .await;
            pick_quorum_match(&claim_replicas, RESOLVE_QUORUM_THRESHOLD, false).ok_or_else(
                || {
                    if claim_replicas.is_empty() {
                        ResolveError::NameNotFound
                    } else {
                        ResolveError::QuorumDivergence {
                            queried: claim_replicas.len(),
                            best: claim_replicas
                                .iter()
                                .filter(|r| **r == claim_replicas[0])
                                .count(),
                            required: RESOLVE_QUORUM_THRESHOLD,
                        }
                    }
                },
            )?
        };
        // same cache-poisoning fix as identity resolve —
        // overwrite local with the quorum-winning bytes so a sybil's
        // first-arriving forgery doesn't linger in the local store.
        self.dht.store_local(claim_key, claim_bytes.clone());
        let claim = NameClaim::decode(&claim_bytes)
            .map_err(|e| ResolveError::NameClaimMalformed(e.to_string()))?;
        if claim.name != normalized {
            return Err(ResolveError::NameClaimMalformed(format!(
                "DHT returned claim for {} but resolver asked for {}",
                claim.name, normalized,
            )));
        }
        let validated = self
            .resolve_identity_verified(claim.node_id, now_unix_secs, timeout)
            .await?;

        // Reuse the crypto path in `NameResolver::verify_name_claim`
        // via a stub backend (the verify method is pure — no fetch
        // no cache write).
        struct StubBackend;
        #[async_trait::async_trait]
        impl NameLookup for StubBackend {
            async fn fetch_name_claim(
                &self,
                _: &[u8; 32],
            ) -> std::result::Result<Option<Vec<u8>>, LookupError> {
                Err(LookupError::new("stub backend"))
            }
        }
        #[async_trait::async_trait]
        impl IdentityLookup for StubBackend {
            async fn fetch_identity_document(
                &self,
                _: &[u8; 32],
            ) -> std::result::Result<Option<Vec<u8>>, LookupError> {
                Err(LookupError::new("stub backend"))
            }
        }
        let resolver = NameResolver::new(StubBackend);
        // Re-decode the document from its canonical bytes so
        // `verify_name_claim` has the same `IdentityDocument` shape
        // it expects (the validated wrapper exposes node_id but not
        // the full doc). Cheap on a single resolve.
        let doc_key = veil_proto::identity_document::IdentityDocument::dht_key(&validated.node_id);
        // The doc bytes were already quorum-validated by
        // `resolve_identity_verified` above — but `verify_name_claim`
        // needs the full `IdentityDocument` shape. Trust the local
        // store: when `resolve_identity_verified` succeeded, the
        // dispatcher mirrored the response into our local DHT shard
        // (see routing.rs FIND_VALUE response handler), so a local
        // get is enough and avoids a second quorum round-trip.
        let doc_bytes = self
            .dht
            .get_local(&doc_key)
            .ok_or(ResolveError::IdentityNotFound(validated.node_id))?;
        let doc = veil_proto::identity_document::IdentityDocument::decode(&doc_bytes)
            .map_err(|e| ResolveError::IdentityDocMalformed(e.to_string()))?;
        resolver.verify_name_claim(&claim, &doc, now_unix_secs)?;
        Ok(validated)
    }

    pub async fn connect_peer(&self, peer_id: PeerId) -> Result<AttachedDebugSession> {
        self.connect_peer_with_state(peer_id, SessionState::DebugAttached)
            .await
    }

    pub async fn connect_peer_active(&self, peer_id: PeerId) -> Result<AttachedDebugSession> {
        self.connect_peer_with_state(peer_id, SessionState::Active)
            .await
    }

    /// try NAT traversal toward `target_node_id`
    /// using ANY currently-connected peer as the signaling coordinator.
    /// See `NodeRuntime::try_nat_traversal` for the full doc-comment;
    /// the actual logic lives here on `NodeServices` so the
    /// auto-trigger path (`nat_fallback_dial`) can call it directly
    /// without going through a public-API forwarder.
    pub async fn try_nat_traversal(
        &self,
        target_node_id: [u8; 32],
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        per_coordinator_timeout: std::time::Duration,
    ) -> Option<veil_proto::control::NatProbeReplyPayload> {
        let local_node_id = *self.identity.local_identity.node_id.as_bytes();
        let mut candidates: Vec<[u8; 32]> = rlock!(self.session_tx_registry)
            .peer_ids()
            .into_iter()
            .filter(|p| *p != local_node_id && *p != target_node_id)
            .collect();
        if candidates.is_empty() {
            return None;
        }
        candidates.sort_by_key(|pid| {
            let mut xor = [0u8; 32];
            for i in 0..32 {
                xor[i] = pid[i] ^ target_node_id[i];
            }
            xor
        });
        const MAX_COORDINATOR_ATTEMPTS: usize = 4;
        for coordinator in candidates.into_iter().take(MAX_COORDINATOR_ATTEMPTS) {
            if let Some(reply) = self
                .attempt_nat_traversal_via(
                    target_node_id,
                    coordinator,
                    local_candidates.clone(),
                    per_coordinator_timeout,
                )
                .await
            {
                return Some(reply);
            }
        }
        None
    }

    /// signaling driver — see `NodeRuntime::attempt_nat_traversal_via`.
    pub async fn attempt_nat_traversal_via(
        &self,
        target_node_id: [u8; 32],
        coordinator_node_id: [u8; 32],
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        timeout: std::time::Duration,
    ) -> Option<veil_proto::control::NatProbeReplyPayload> {
        use veil_proto::codec::encode_header;
        use veil_proto::control::NatProbeRequestPayload;
        use veil_proto::family::{ControlMsg, FrameFamily};
        use veil_proto::header::{FrameHeader, HEADER_SIZE};

        let local_node_id = *self.identity.local_identity.node_id.as_bytes();

        let (tx, rx) = tokio::sync::oneshot::channel::<veil_proto::control::NatProbeReplyPayload>();
        // oncurrency-allocate a session_token
        // that does not collide with any in-flight waiter. Without
        // this, two concurrent NAT-probe requests landing on the same
        // u32 random value silently overwrite each other in
        // `nat_probe_waiters` — the prior requester's `tx` is dropped
        // and they time out without diagnostic. Birthday-bound at
        // u32 means ~65K concurrent waiters before 50% collision risk;
        // production-class relays can hit that under sustained load.
        // The retry loop is bounded — at MAX_NAT_PROBE_WAITERS we
        // refuse the request rather than spin forever.
        let session_token: u32 = {
            use rand_core::RngCore;
            use veil_proto::budget::MAX_NAT_PROBE_WAITERS;
            let mut waiters = lock!(self.dispatcher.nat_probe_waiters);
            waiters.retain(|_, sender| !sender.is_closed());
            if waiters.len() >= MAX_NAT_PROBE_WAITERS {
                return None;
            }
            // Try a random value; on the off chance of a collision
            // re-roll up to MAX_NAT_PROBE_WAITERS times (the cap above
            // means at least one slot is free, so we WILL find one).
            let mut tok = rand_core::OsRng.next_u32();
            for _ in 0..MAX_NAT_PROBE_WAITERS {
                if !waiters.contains_key(&tok) {
                    break;
                }
                tok = rand_core::OsRng.next_u32();
            }
            waiters.insert(tok, tx);
            tok
        };

        let request = NatProbeRequestPayload {
            initiator_node_id: local_node_id,
            target_node_id,
            session_token,
            candidates: local_candidates,
        };
        let body = request.encode();
        let mut hdr = FrameHeader::new(
            FrameFamily::Control as u8,
            ControlMsg::NatProbeRequest as u16,
        );
        hdr.body_len = body.len() as u32;
        let mut frame = Vec::with_capacity(HEADER_SIZE + body.len());
        frame.extend_from_slice(&encode_header(&hdr));
        frame.extend_from_slice(&body);

        {
            let guard = rlock!(self.session_tx_registry);
            if !guard.send_to(
                &coordinator_node_id,
                veil_proto::header::priority::INTERACTIVE,
                frame,
            ) {
                lock!(self.dispatcher.nat_probe_waiters).remove(&session_token);
                return None;
            }
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(reply)) => Some(reply),
            _ => {
                lock!(self.dispatcher.nat_probe_waiters).remove(&session_token);
                None
            }
        }
    }

    /// signaling + URI promotion — see
    /// `NodeRuntime::try_nat_traversal_promote_uris`.
    pub async fn try_nat_traversal_promote_uris(
        &self,
        target_node_id: [u8; 32],
        template_uri: &veil_transport::TransportUri,
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        per_coordinator_timeout: std::time::Duration,
    ) -> Vec<veil_transport::TransportUri> {
        let Some(reply) = self
            .try_nat_traversal(target_node_id, local_candidates, per_coordinator_timeout)
            .await
        else {
            return Vec::new();
        };
        let mut sorted = reply.candidates;
        sorted.sort_by_key(|c| std::cmp::Reverse(c.priority));
        sorted
            .iter()
            .filter_map(|c| nat_candidate_to_transport_uri(c, template_uri))
            .collect()
    }

    /// drive NAT-traversal signaling on the
    /// initiator side and try each promoted candidate URI as a real
    /// transport dial. Returns `Some(connection)` on the first
    /// success, `None` if signaling fails or every candidate fails to
    /// dial. Cheap-bail conditions (no connected peers / unsupported
    /// URI variant) are checked before signaling so we don't waste a
    /// 5-second round-trip on a doomed attempt.
    ///
    /// Why this lives in `NodeServices` and not inline in
    /// `connect_peer_with_state`:
    /// * Encapsulates the policy (timeout, candidate cap
    ///   coordinator-availability check) in one place so it's
    ///   reviewable + tunable independently of the dial state
    ///   machine.
    /// * Lets future tests stub it out via the runtime's existing
    ///   debug accessors if needed.
    ///
    /// Per-attempt timeout: signaling is bounded at 3s (
    /// auto-coordinator default); each candidate dial is bounded
    /// implicitly by the registry's own connect timeout — we don't
    /// add a second layer. Total worst-case latency for the
    /// fallback path is ~3s + (N candidates × per-dial timeout)
    /// which sits inside the outbound-connector's exponential-
    /// backoff loop without blowing past its `backoff_max`.
    ///
    /// Candidate cap: at most 4 promoted URIs are attempted, in RFC
    /// 8445 priority order (host → srflx → relay). Without a cap a
    /// peer that advertises 50 host candidates (e.g., a server with
    /// many interfaces) would burn the full backoff window on
    /// fallback attempts and starve the next real backoff cycle.
    async fn nat_fallback_dial(
        &self,
        peer: &crate::types::PeerConfigEntry,
        primary_uri: &TransportUri,
        peer_ctx: Arc<veil_transport::TransportContext>,
    ) -> Option<Box<dyn TransportConnection>> {
        // Cheap-bail #1: primary URI scheme must be promotable. No
        // point running signaling to learn the peer's IP if we can't
        // build a connectable URI from it (`with_host_port` returns
        // None for Unix/Socks/Ws*).
        primary_uri.with_host_port("0.0.0.0".into(), 0)?;

        // Cheap-bail #2: signaling needs at least one connected peer
        // to act as a coordinator. `try_nat_traversal` would also
        // return None in this case, but going through the full path
        // for an inevitable miss wastes log lines.
        let connected_peer_count = rlock!(self.session_tx_registry).peer_ids().len();
        if connected_peer_count == 0 {
            return None;
        }

        // Build our own host candidates from the dispatcher's known
        // listen transports (same source-of-truth used by the
        // dispatcher's echo-bugfix path so the wire is
        // symmetric).
        let local_candidates = veil_dispatcher::build_own_host_candidates(
            &self
                .dispatcher
                .listen_transports
                .read()
                .unwrap_or_else(|p| p.into_inner()),
        );

        let promoted = self
            .try_nat_traversal_promote_uris(
                *peer.node_id.as_bytes(),
                primary_uri,
                local_candidates,
                std::time::Duration::from_secs(3),
            )
            .await;
        if promoted.is_empty() {
            return None;
        }

        const MAX_FALLBACK_DIAL_ATTEMPTS: usize = 4;
        for candidate_uri in promoted.into_iter().take(MAX_FALLBACK_DIAL_ATTEMPTS) {
            match self
                .registry
                .connect(&candidate_uri, Arc::clone(&peer_ctx))
                .await
            {
                Ok(connection) => return Some(connection),
                Err(_) => continue, // try next candidate
            }
        }
        None
    }

    /// Anti-censorship: wrap a failed-direct dial through an operator-
    /// configured SOCKS proxy (typically local Tor on
    /// `socks5://127.0.0.1:9050`).  Closes #22/#23/#27 partially —
    /// Tor's exit nodes are in diverse ASes by design, so an AS-level
    /// block on the operator's host is bypassed via the proxy hop.
    ///
    /// Returns `None` if:
    /// * `transport.outbound_socks_fallback_proxy` is unset (default —
    ///   feature opt-in)
    /// * the primary URI's scheme cannot be wrapped in SOCKS
    ///   (`Self::Quic`, `Self::Unix`, etc. — SOCKS5 is a TCP-only
    ///   transport)
    /// * the proxy URL is unparseable as a SOCKS URI
    /// * the proxy itself fails to connect (logged, returns None)
    async fn socks_fallback_dial(
        &self,
        primary_uri: &TransportUri,
        peer_ctx: Arc<veil_transport::TransportContext>,
    ) -> Option<Box<dyn TransportConnection>> {
        let proxy_str = peer_ctx.outbound_socks_fallback_proxy.as_ref()?;
        let (proxy_host, proxy_port, target_host, target_port) =
            crate::socks_fallback::compose_socks_fallback(proxy_str, primary_uri)?;

        // Construct a `socks://<proxy>/<target_host>:<target_port>`
        // URI and dial via the existing SOCKS transport.
        let socks_uri_str = format!(
            "socks://{}:{}/{}:{}",
            proxy_host, proxy_port, target_host, target_port,
        );
        let socks_uri = TransportUri::parse(&socks_uri_str).ok()?;

        self.logger.info(
            "peer.connect.socks_fallback_dial",
            format!(
                "primary={} proxy={proxy_host}:{proxy_port}",
                veil_util::redact_addr_for_log(&primary_uri.to_string()),
            ),
        );

        match self.registry.connect(&socks_uri, peer_ctx).await {
            Ok(connection) => Some(connection),
            Err(e) => {
                self.logger.warn(
                    "peer.connect.socks_fallback_failed",
                    format!("proxy={proxy_host}:{proxy_port} error={e}"),
                );
                None
            }
        }
    }

    fn make_session_context(&self) -> SessionRuntimeContext {
        SessionRuntimeContext {
            identity: Arc::clone(&self.identity),
            state: Arc::clone(&self.state),
            live_sessions: Arc::clone(&self.live_sessions),
            event_bus: Arc::clone(&self.event_bus),
            next_link_id: Arc::clone(&self.next_link_id),
            logger: Arc::clone(&self.logger),
            metrics: self.metrics.clone(),
            dispatcher: Arc::clone(&self.dispatcher),
            session_registry: Arc::clone(&self.session_registry),
            session_tx_registry: Arc::clone(&self.session_tx_registry),
            session_outbox: Arc::clone(&self.session_outbox),
            anonymity: Arc::clone(&self.anonymity),
            sessions_per_ip: Arc::clone(&self.sessions_per_ip),
            scanner_shield: Arc::clone(&self.scanner_shield),
            defaults: Arc::clone(&self.defaults),
            // NodeServices carries its own rtt_table clone (not via the
            // RoutingState bundle, which lives on NodeRuntime only).
            rtt_table: Arc::clone(&self.rtt_table),
            config_path: self.config_path.clone(),
            mobile: Arc::clone(&self.mobile),
            resumption: Arc::clone(&self.resumption),
            handoff: Arc::clone(&self.handoff),
            allowed_peer_algos: self.allowed_peer_algos.clone(),
            network_gate: self.network_gate.as_ref().map(Arc::clone),
            verified_peer_certs: Arc::clone(&self.verified_peer_certs),
        }
    }

    async fn connect_peer_with_state(
        &self,
        peer_id: PeerId,
        session_state: SessionState,
    ) -> Result<AttachedDebugSession> {
        let peer = lock_state(&self.state)
            .peers
            .get(&peer_id)
            .cloned()
            .ok_or_else(|| NodeError::AdminProtocol(format!("unknown peer_id `{peer_id}`")))?;
        self.logger.info(
            "peer.connect.attempt",
            format!(
                "peer_id={} transport={}",
                peer_id,
                veil_util::redact_addr_for_log(&peer.transport),
            ),
        );
        let session_ctx = self.make_session_context();
        if let Some(metrics) = &session_ctx.metrics {
            metrics.inc_outbound_connect_attempts();
        }
        let uri = TransportUri::parse(&peer.transport)?;
        let peer_ctx = Arc::new(peer_transport_context(&self.transport_ctx, &peer)?);
        let connection = match self.registry.connect(&uri, Arc::clone(&peer_ctx)).await {
            Ok(connection) => connection,
            Err(primary_err) => {
                // NAT-traversal auto-trigger on
                // outbound-dial failure. Only fires for production
                // (`SessionState::Active`) outbound dials — admin
                // `connect_peer` (DebugAttached) is operator-driven
                // diagnostic, not a path that should silently fall back
                // through signaling. Also skipped if no peer is
                // currently connected (no coordinator candidate, so
                // signaling has nowhere to go) or if the primary URI
                // is a variant that `with_host_port` can't promote
                // (Unix/Socks/Ws — there's nothing meaningful to
                // substitute the peer's IP candidate into).
                let primary_err_str = primary_err.to_string();
                if matches!(session_state, SessionState::Active) {
                    if let Some(connection) = self
                        .nat_fallback_dial(&peer, &uri, Arc::clone(&peer_ctx))
                        .await
                    {
                        self.logger.info(
                            "peer.connect.nat_fallback_success",
                            format!("peer_id={peer_id} primary_err={primary_err_str}",),
                        );
                        if let Some(metrics) = &session_ctx.metrics {
                            metrics.inc_outbound_connect_attempts();
                        }
                        connection
                    } else if let Some(connection) = self.socks_fallback_dial(&uri, peer_ctx).await
                    {
                        // Anti-censorship: operator-configured SOCKS
                        // fallback (typically local Tor) succeeded
                        // when both direct and NAT-traversal failed.
                        self.logger.info(
                            "peer.connect.socks_fallback_success",
                            format!("peer_id={peer_id} primary_err={primary_err_str}"),
                        );
                        if let Some(metrics) = &session_ctx.metrics {
                            metrics.inc_outbound_connect_attempts();
                        }
                        connection
                    } else {
                        if let Some(metrics) = &session_ctx.metrics {
                            metrics.inc_outbound_connect_failures();
                        }
                        self.logger.warn(
                            "peer.connect.failure",
                            format!("peer_id={peer_id} error={primary_err_str}"),
                        );
                        return Err(NodeError::Transport(primary_err));
                    }
                } else {
                    if let Some(metrics) = &session_ctx.metrics {
                        metrics.inc_outbound_connect_failures();
                    }
                    self.logger.warn(
                        "peer.connect.failure",
                        format!("peer_id={peer_id} error={primary_err_str}"),
                    );
                    return Err(NodeError::Transport(primary_err));
                }
            }
        };
        self.logger
            .info("peer.connect.success", format!("peer_id={peer_id}"));
        // Outbound sessions never hit the handoff-bound path (that branch
        // is inbound-only), so `Ok(None)` here is a defensive impossibility.
        register_connection_session(
            session_ctx,
            SessionSource::Outbound(peer_id),
            Some(ExpectedPeerIdentity {
                peer_id,
                public_key: peer.public_key,
                node_id: peer.node_id,
                nonce: peer.nonce,
            }),
            None,
            session_state,
            connection,
        )
        .await?
        .ok_or_else(|| {
            NodeError::AdminProtocol(
                "register_connection_session returned None on an outbound path — impossible".into(),
            )
        })
    }

    pub async fn accept_listen(&self, listen_id: ListenId) -> Result<AttachedDebugSession> {
        {
            let state = lock_state(&self.state);
            let listen = state.listens.get(&listen_id).ok_or_else(|| {
                NodeError::AdminProtocol(format!("unknown listen_id `{listen_id}`"))
            })?;
            if !listen.active {
                return Err(NodeError::AdminProtocol(format!(
                    "listen `{listen_id}` is not active"
                )));
            }
        }

        let (tx, rx) = oneshot::channel();
        lock_waiters(&self.pending_accepts)
            .entry(listen_id)
            .or_default()
            .push_back(tx);
        let (listener_handle, connection) = rx.await.map_err(|_| {
            NodeError::AdminProtocol(format!(
                "listen `{listen_id}` stopped before a debug session was attached"
            ))
        })?;
        // DebugAttached inbound — operator explicitly attached via admin;
        // a handoff-bound outcome on this path means the debug attach got
        // hijacked by a live session's warm standby, which is surprising
        // but not fatal. Surface it as an admin-protocol error so the
        // operator sees what happened.
        register_connection_session(
            self.make_session_context(),
            SessionSource::Inbound(listen_id),
            None,
            Some(listener_handle),
            SessionState::DebugAttached,
            connection,
        )
        .await?
        .ok_or_else(|| {
            NodeError::AdminProtocol(
                "inbound connection was bound to an existing session via hot-standby handoff; \
             no debug session produced"
                    .into(),
            )
        })
    }

    // ── Diagnostic helpers ─────────────────────────────────────────

    /// The local node's 32-byte ID.
    pub fn local_node_id(&self) -> [u8; 32] {
        *self.identity.local_identity.node_id.as_bytes()
    }

    /// Register a channel that will receive the next Pong/TraceHop for `seq`.
    ///
    /// Closed-receiver entries are evicted before inserting. If the map is
    /// still at `MAX_PENDING_DIAG` after eviction, the new entry is silently
    /// dropped to prevent unbounded growth from admin command abuse.
    pub fn register_diag_seq(
        &self,
        seq: u32,
        tx: tokio::sync::mpsc::Sender<veil_dispatcher::DiagEvent>,
    ) {
        use veil_proto::budget::MAX_PENDING_DIAG;
        let mut map = lock!(self.dispatcher.pending_diag);
        // Evict entries whose receiver has already been dropped.
        map.retain(
            |_, sender: &mut tokio::sync::mpsc::Sender<veil_dispatcher::DiagEvent>| {
                !sender.is_closed()
            },
        );
        if map.len() < MAX_PENDING_DIAG {
            map.insert(seq, tx);
        }
    }

    /// Remove the pending channel for `seq` (cleanup after timeout or receipt).
    pub fn remove_diag_seq(&self, seq: u32) {
        lock!(self.dispatcher.pending_diag).remove(&seq);
    }

    /// Send a pre-encoded Diag frame to a target node via session registry.
    pub fn send_diag_frame(&self, target_id: &[u8; 32], frame: Vec<u8>) {
        // Snapshot the route-cache fallback hop BEFORE taking the registry, to
        // preserve the canonical lock order (route_cache → session_tx_registry;
        // documented in veil-dispatcher lib.rs). The lookup returns an owned
        // value and the route_cache guard is dropped immediately, so the two
        // guards never coexist (the previous order held the registry across the
        // route_cache read — the inversion the workspace was audited to avoid).
        let fallback_hop = rlock!(self.dispatcher.route_cache).lookup(target_id);
        let reg = rlock!(self.session_tx_registry);
        if !reg.send_to(
            target_id,
            veil_proto::header::priority::INTERACTIVE,
            frame.clone(),
        ) {
            // No direct session — use the pre-computed route-cache hop.
            if let Some(hop) = fallback_hop {
                reg.send_to(&hop, veil_proto::header::priority::INTERACTIVE, frame);
            }
        }
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
            // audit MEDIUM: peer_instance_id is hardcoded to [0; 16] until
            // sovereign-identity multi-instance metadata passes through
            // handshake. When the handshake delivers peer's device/instance
            // ID, replace `[0u8; 16]` with the real value to avoid AEAD nonce
            // reuse risk when two instances of the same identity resume
            // concurrently. See `TicketIssuer::issue_for_instance` docstring.
            let ticket_to_send = {
                let blob = lock!(inbound.runtime.resumption.ticket_issuer)
                    .issue_for_instance(session_id, peer_id, [0u8; 16], raw_tx_key, raw_rx_key);
                Some(blob)
            };
            // consume the receiver pre-reserved
            // by `try_register_unique` in the cap+dup atomic critical
            // section. Replaces the old second-register pattern that
            // had a TOCTOU window between dup-check and registration.
            let is_referral = session.referral;
            let outbox_rx = session.reserved_outbox_rx;
            let rpc_rx = inbound.runtime.session_outbox.register(peer_id);
            let mut runner = veil_session::runner::SessionRunner {
                stream: session.stream,
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
                veil_dht::routing::Contact::with_mode(
                    *peer_id.as_bytes(),
                    inbound_transport.clone(),
                    session.remote_discovery_mode,
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
            inbound
                .runtime
                .dispatcher
                .on_session_opened(*peer_id.as_bytes(), session.observed_addr);
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
            // oncurrency-unregister tx-channel
            // BEFORE notifying the dispatcher. The previous order
            // (`on_session_closed` → unregister) left a window where
            // dispatcher hooks could look up `session_tx_registry` for
            // the closing peer and find a still-live channel that would
            // never be drained — frames silently dropped. New order
            // ensures the channel is gone before any close-handler runs.
            wlock!(inbound.runtime.session_tx_registry).unregister(peer_id.as_bytes());
            inbound.runtime.session_outbox.unregister(peer_id);
            // Evict ML-KEM key for this peer so stale keys don't persist.
            wlock!(inbound.runtime.identity.peer_mlkem_keys).remove(peer_id.as_bytes());
            // Evict per-session ephemeral DK so stale keys don't persist.
            lock!(inbound.runtime.identity.per_session_mlkem_dk).remove(peer_id.as_bytes());
            // Now safe to notify dispatcher: any `session_tx_registry`
            // lookups in the close-handler path will return None.
            inbound
                .runtime
                .dispatcher
                .on_session_closed(peer_id, is_referral);
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
mod tests;

impl NodeServices {
    /// Register a LOCATION-anonymous service (onion-registration b5b-runtime):
    /// build an onion circuit whose terminus is the rendezvous relay R
    /// (`relay_path.last()`), and register `cookie` AT R over that circuit —
    /// piggy-backed as the circuit-setup terminus payload — so R binds the cookie
    /// to the return circuit WITHOUT learning this node's location. Introduces a
    /// client sends to (R, cookie) are then forwarded back DOWN the circuit and
    /// opened here.
    ///
    /// `relay_path` is the full hop list first→terminus; each hop's X25519 key is
    /// resolved from the LOCAL relay-directory shard (publish/mirror it first).
    /// The caller separately publishes a `RendezvousAd` pointing at (R, cookie,
    /// our x25519) so clients can find the service — this method does NOT
    /// session-register (that is the leak it avoids).
    ///
    /// NOTE (§3.B): the ad does not yet COMMIT to the registration key, so the
    /// anti-squat guarantee is first-wins only; binding `reg_pk` into the ad is a
    /// follow-up. Maintenance (rebuild on TTL) is also a follow-up — v1 builds
    /// once.
    fn build_onion_circuit_once(
        &self,
        relay_path: &[[u8; 32]],
        cookie: [u8; 16],
    ) -> std::result::Result<(), veil_types::AnonOnionSendError> {
        use base64::Engine;
        use veil_anonymity::circuit_origin::{OriginHop, build_origin_circuit};
        use veil_anonymity::circuit_register::CircuitRegisterPayload;
        use veil_anonymity::directory::{decode_entry, relay_directory_dht_key};
        use veil_types::AnonOnionSendError;

        if relay_path.is_empty() {
            return Err(AnonOnionSendError::NoRelays);
        }
        // Receive-capable only: we must own the origin table (to open returns).
        let Some(origin_table) = &self.dispatcher.circuit_origin else {
            return Err(AnonOnionSendError::NoIdentity);
        };

        // Resolve each hop's anonymity X25519 key from the local directory.
        let mut hops = Vec::with_capacity(relay_path.len());
        for nid in relay_path {
            let bytes = self
                .dht
                .get_local(&relay_directory_dht_key(nid))
                .ok_or(AnonOnionSendError::NoRelays)?;
            let entry = decode_entry(&bytes).map_err(|_| AnonOnionSendError::NoRelays)?;
            hops.push(OriginHop {
                node_id: *nid,
                pubkey: entry.x25519_pk,
            });
        }

        // Fresh Ed25519 registration key; sign the cookie binding.
        let kp = veil_crypto::generate_keypair(veil_types::SignatureAlgorithm::Ed25519);
        let reg_pk: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&kp.public_key)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(AnonOnionSendError::NoIdentity)?;
        let msg = CircuitRegisterPayload::signing_bytes(&cookie, &reg_pk);
        let sig = veil_crypto::sign_message(
            veil_types::SignatureAlgorithm::Ed25519,
            &kp.public_key,
            &kp.private_key,
            &msg,
        )
        .map_err(|_| AnonOnionSendError::NoIdentity)?;
        let reg = CircuitRegisterPayload {
            cookie,
            reg_pk,
            signature: sig,
        };

        // Build the origin circuit with the registration as terminus payload.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (setup, origin) = build_origin_circuit(&hops, &reg.encode(), now)
            .map_err(|_| AnonOnionSendError::NoRelays)?;
        let first_hop = origin.first_hop;
        if !origin_table.insert(std::sync::Arc::new(origin)) {
            return Err(AnonOnionSendError::NoRelays); // origin table full
        }

        // Send the CircuitBuild envelope to the first hop over its session.
        self.send_relay_chain_frame(
            &first_hop,
            veil_proto::family::RelayChainMsg::CircuitBuild,
            &setup,
        );
        Ok(())
    }

    /// Register this node as a LOCATION-anonymous service (the prod entry point):
    /// pick a rendezvous relay R + `hop_count - 1` intermediate hops from the
    /// local relay directory, build an onion circuit to R (registering a fresh
    /// cookie over it — R never learns our location), and publish a
    /// `RendezvousAd` at (R, cookie, our x25519). The maintenance tick keeps the
    /// circuit alive. `hop_count` is clamped to ≥ 2 so R itself can't see us.
    /// Returns the published cookie.
    /// Pick an onion relay path first→terminus: a connected+published rendezvous
    /// relay R (the terminus = `relay_path.last()`) + `hop_count - 1` intermediate
    /// published relays from the local directory, distinct from R. `hop_count` is
    /// clamped to ≥ 2 so R itself can't see us. Errors `NoRelays` when there
    /// aren't enough published relays.
    pub(crate) fn select_onion_relay_path(
        &self,
        hop_count: usize,
    ) -> std::result::Result<Vec<[u8; 32]>, veil_types::AnonOnionSendError> {
        use veil_anonymity::directory::{
            DEFAULT_FRESHNESS_WINDOW_SECS, discover_relay_hops, relay_directory_dht_key,
        };
        use veil_types::AnonOnionSendError;

        let hop_count = hop_count.max(2);
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let r = service_tasks::pick_rendezvous_relay(&self.live_sessions, &self.dht, &[])
            .ok_or(AnonOnionSendError::NoRelays)?;
        let candidates: Vec<[u8; 32]> = self
            .dht
            .routing_table_contacts()
            .into_iter()
            .map(|c| c.node_id)
            .filter(|n| *n != r)
            .collect();
        let dht = std::sync::Arc::clone(&self.dht);
        let mids: Vec<[u8; 32]> = discover_relay_hops(
            &candidates,
            |n| dht.get_local(&relay_directory_dht_key(n)),
            now_unix,
            DEFAULT_FRESHNESS_WINDOW_SECS,
        )
        .into_iter()
        .map(|d| d.hop.node_id)
        .take(hop_count - 1)
        .collect();
        if mids.len() < hop_count - 1 {
            return Err(AnonOnionSendError::NoRelays); // not enough relays to hide from R
        }
        let mut relay_path = mids;
        relay_path.push(r);
        Ok(relay_path)
    }

    pub fn register_onion_service(
        &self,
        hop_count: usize,
    ) -> std::result::Result<[u8; 16], veil_types::AnonOnionSendError> {
        use rand_core::{OsRng, RngCore};
        use veil_anonymity::directory::DEFAULT_FRESHNESS_WINDOW_SECS;

        let relay_path = self.select_onion_relay_path(hop_count)?;
        let r = *relay_path.last().expect("non-empty relay path");
        let mut cookie = [0u8; 16];
        OsRng.fill_bytes(&mut cookie);

        // Build + register the circuit (no session register — that is the leak),
        // then publish the ad so clients can find us.
        self.register_onion_circuit(&relay_path, cookie)?;
        service_tasks::rendezvous_register_publisher(
            &self.anonymity,
            &r,
            cookie,
            DEFAULT_FRESHNESS_WINDOW_SECS,
        );
        Ok(cookie)
    }

    /// Register a location-anonymous service: build its onion circuit + record it
    /// so the maintenance tick keeps it alive ([`Self::maintain_onion_circuits`]).
    /// `relay_path` is first→terminus (terminus = rendezvous relay R); each hop's
    /// X25519 key is resolved from the local relay-directory shard. The caller
    /// separately publishes a `RendezvousAd` at (R, cookie, our x25519) — this
    /// does NOT session-register (the location leak it avoids). See the
    /// onion-registration design doc.
    pub fn register_onion_circuit(
        &self,
        relay_path: &[[u8; 32]],
        cookie: [u8; 16],
    ) -> std::result::Result<(), veil_types::AnonOnionSendError> {
        self.build_onion_circuit_once(relay_path, cookie)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut svcs = lock!(self.anonymity.onion_services);
        // Replace any prior entry for the same cookie (re-register), else push.
        svcs.retain(|e| e.cookie != cookie);
        svcs.push(anonymity_state::OnionServiceEntry {
            relay_path: relay_path.to_vec(),
            cookie,
            built_unix: now,
        });
        Ok(())
    }

    /// Maintenance: rebuild any hosted onion-service circuit that is older than
    /// half the relay circuit TTL, so it never lapses. Called from the
    /// maintenance tick. Best-effort — a rebuild that fails (e.g. a hop's
    /// directory entry not currently cached) is retried next tick.
    pub fn maintain_onion_circuits(&self, now_unix: u64) {
        // Config-driven auto-start: if `[anonymity].onion_service` is on and we
        // haven't registered yet, do so now (once relays are available). Builds
        // once; the rebuild loop below keeps it alive.
        if let Some(hops) = self.anonymity.onion_service_hops
            && lock!(self.anonymity.onion_services).is_empty()
        {
            let _ = self.register_onion_service(hops);
        }

        // Refresh at half the relay-side circuit idle TTL (300 s) → 150 s.
        const REFRESH_SECS: u64 = veil_anonymity::circuit_table::DEFAULT_CIRCUIT_TTL_SECS / 2;
        let due: Vec<([u8; 16], Vec<[u8; 32]>)> = {
            let svcs = lock!(self.anonymity.onion_services);
            svcs.iter()
                .filter(|e| now_unix.saturating_sub(e.built_unix) >= REFRESH_SECS)
                .map(|e| (e.cookie, e.relay_path.clone()))
                .collect()
        };
        for (cookie, relay_path) in due {
            if self.build_onion_circuit_once(&relay_path, cookie).is_ok() {
                let mut svcs = lock!(self.anonymity.onion_services);
                if let Some(e) = svcs.iter_mut().find(|e| e.cookie == cookie) {
                    e.built_unix = now_unix;
                }
            }
        }
    }

    /// Build + enqueue one `RelayChain::<msg>` control frame to `peer`'s session.
    fn send_relay_chain_frame(
        &self,
        peer: &[u8; 32],
        msg: veil_proto::family::RelayChainMsg,
        body: &[u8],
    ) {
        use veil_proto::{codec::encode_header, family::FrameFamily, header::FrameHeader};
        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, msg as u16);
        hdr.body_len = body.len() as u32;
        hdr.set_priority(veil_proto::priority::INTERACTIVE);
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(body);
        let guard = wlock!(self.session_tx_registry);
        let _ = guard.send_to(peer, veil_proto::priority::INTERACTIVE, frame);
    }

    /// Authenticated rendezvous send (Epic 482 v1, "any recipient"): like
    /// [`send_via_rendezvous`] but the sealed payload is a per-message Ed25519/
    /// Falcon-signed [`veil_proto::AuthAppDeliver`], so the recipient
    /// cryptographically verifies WHO sent it. A signed message rarely fits one
    /// onion cell, so it is sign-whole-then-fragmented across multiple
    /// introduces (`AuthDeliverFragment`); the recipient reassembles + verifies
    /// once. Requires a loaded sovereign identity. One-way (sender → recipient).
    pub fn send_via_rendezvous_authenticated(
        &self,
        ad: &veil_anonymity::rendezvous::RendezvousAd,
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        data: &[u8],
        hop_count: usize,
        // When `Some((reply_app_id, reply_endpoint_id))`, attach a one-time
        // reply block so the recipient can reply WITHOUT us publishing a public
        // ad (presence-leak mitigation): we register R-locally with a rendezvous
        // relay under a fresh cookie and embed the sealed reply path.
        reply: Option<([u8; 32], u32)>,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        use rand_core::RngCore;
        use veil_anonymity::rendezvous::final_hop_kind;

        let sovereign = self
            .identity
            .sovereign_identity
            .as_ref()
            .ok_or(veil_anonymity::sender::SenderError::MissingSenderIdentity)?;

        // Optionally set up an ephemeral reply path (no public ad).
        let reply_block = match reply {
            Some((reply_app_id, reply_endpoint_id)) => {
                // We must own the anonymity key to unseal the eventual reply —
                // i.e. be receive-capable (`receive_anonymous`/`relay_capable`).
                let x25519_pk = match self.dispatcher.anonymity_x25519_sk.as_ref() {
                    Some(sk) => x25519_dalek::PublicKey::from(sk.as_ref()).to_bytes(),
                    None => {
                        return Err(veil_anonymity::sender::SenderError::MissingReplyCapability);
                    }
                };
                // Register the reply cookie over an ONION CIRCUIT to R_a (not a
                // direct session), so R_a never learns OUR location either (1c) —
                // the same location-hiding the onion-service registration gives.
                // No ad is published: the signed reply block IS the private
                // descriptor sent to the replier. Ephemeral (build-once, no
                // maintenance entry) — the reply happens within the block's TTL.
                const REPLY_CIRCUIT_HOPS: usize = 2;
                let relay_path =
                    self.select_onion_relay_path(REPLY_CIRCUIT_HOPS)
                        .map_err(|_| {
                            veil_anonymity::sender::SenderError::InsufficientRelayCandidates {
                                need: REPLY_CIRCUIT_HOPS,
                                have: 0,
                            }
                        })?;
                let relay = *relay_path.last().expect("non-empty relay path");
                let mut cookie = [0u8; 16];
                rand_core::OsRng.fill_bytes(&mut cookie);
                self.build_onion_circuit_once(&relay_path, cookie)
                    .map_err(|_| {
                        veil_anonymity::sender::SenderError::InsufficientRelayCandidates {
                            need: REPLY_CIRCUIT_HOPS,
                            have: 0,
                        }
                    })?;
                Some(veil_proto::ReplyBlock {
                    rendezvous_node_id: relay,
                    auth_cookie: cookie,
                    x25519_pk,
                    reply_app_id,
                    reply_endpoint_id,
                    // Circuit-backed: R_a forwards the reply DOWN our circuit by
                    // COOKIE alone, so this transport id is now unused on the
                    // circuit path (kept for wire compatibility / the legacy
                    // session path).
                    receiver_node_id: *self.identity.local_identity.node_id.as_bytes(),
                })
            }
            None => None,
        };

        // Build + sign the whole message. dst = the ad's receiver_node_id (bound
        // by the signature; the verifier reconstructs it as its own node_id).
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let nonce = rand_core::OsRng.next_u64();
        let auth = sovereign.sign_auth_deliver(
            ad.receiver_node_id,
            target_app_id,
            target_endpoint_id,
            now_unix,
            nonce,
            data.to_vec(),
            reply_block,
        );
        let auth_bytes = auth.encode();
        if auth_bytes.len() > veil_proto::MAX_AUTH_DELIVER_MSG_BYTES {
            return Err(veil_anonymity::sender::SenderError::PayloadTooLarge {
                hop_count,
                got: data.len(),
                max: veil_proto::MAX_AUTH_DELIVER_MSG_BYTES,
            });
        }

        // Largest signed-blob chunk that fits one fragment at this hop_count:
        //   Final-hop budget − [1 onion tag] − IntroducePayload fixed − introduce
        //   overhead − [1 inner tag] − fragment header.
        let final_budget = veil_anonymity::packet::max_payload_for_hops(hop_count).ok_or(
            veil_anonymity::sender::SenderError::HopCountExceedsCellBudget {
                hop_count,
                max: veil_anonymity::packet::MAX_HOPS_PER_CELL,
            },
        )?;
        let ciphertext_budget = final_budget
            .min(
                veil_anonymity::rendezvous::MAX_INTRODUCE_CIPHERTEXT
                    + 1
                    + veil_anonymity::rendezvous::IntroducePayload::FIXED_SIZE,
            )
            .saturating_sub(1 + veil_anonymity::rendezvous::IntroducePayload::FIXED_SIZE);
        let chunk_size = ciphertext_budget
            .saturating_sub(veil_anonymity::rendezvous::INTRODUCE_OVERHEAD)
            .saturating_sub(1 + veil_proto::AuthDeliverFragment::HEADER_SIZE);
        if chunk_size == 0 {
            return Err(veil_anonymity::sender::SenderError::PayloadTooLarge {
                hop_count,
                got: data.len(),
                max: 0,
            });
        }
        let frag_count = auth_bytes.len().div_ceil(chunk_size).max(1);
        if frag_count > veil_proto::MAX_AUTH_DELIVER_FRAGMENTS as usize {
            return Err(veil_anonymity::sender::SenderError::PayloadTooLarge {
                hop_count,
                got: data.len(),
                max: chunk_size * veil_proto::MAX_AUTH_DELIVER_FRAGMENTS as usize,
            });
        }
        let mut msg_id = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut msg_id);

        // Each fragment: [APP_DELIVER_AUTH tag][AuthDeliverFragment] → sealed +
        // onion-routed to the rendezvous independently.
        for (idx, chunk) in auth_bytes.chunks(chunk_size).enumerate() {
            let frag = veil_proto::AuthDeliverFragment {
                msg_id,
                frag_count: frag_count as u16,
                frag_idx: idx as u16,
                chunk: chunk.to_vec(),
            };
            let frag_bytes = frag.encode();
            let mut sealed_plaintext = Vec::with_capacity(1 + frag_bytes.len());
            sealed_plaintext.push(final_hop_kind::APP_DELIVER_AUTH);
            sealed_plaintext.extend_from_slice(&frag_bytes);
            self.send_sealed_introduce(ad, &sealed_plaintext, hop_count)?;
        }
        Ok(())
    }

    /// Resolve the recipient's `RendezvousAd` and send an authenticated
    /// anonymous message to it (Epic 482 v1, "any recipient"). This is the
    /// production entry point behind the IPC `anonymous_authenticated` flag.
    /// Fetches + verifies the ad from the DHT (recursive, across replica slots),
    /// pre-resolves the rendezvous relay's directory entry into the local shard
    /// (so the onion build can reach it instead of silent-dropping), then
    /// signs/fragments/sends via [`Self::send_via_rendezvous_authenticated`].
    /// Errors are local/pre-transmit; once the cell is on the wire it is
    /// fire-and-forget (no end-to-end ACK).
    pub async fn send_anonymous_authenticated_to(
        &self,
        receiver_node_id: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        data: &[u8],
        hop_count: usize,
        // `Some((reply_app_id, reply_endpoint_id))` attaches a one-time reply
        // block (see `send_via_rendezvous_authenticated`).
        reply: Option<([u8; 32], u32)>,
    ) -> std::result::Result<(), veil_types::AnonOnionSendError> {
        use veil_anonymity::rendezvous::{
            MAX_RENDEZVOUS_AD_SLOTS, decode_rendezvous_ad, is_currently_valid,
            rendezvous_ad_dht_key_at, verify_rendezvous_ad,
        };
        use veil_types::AnonOnionSendError;

        const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        if self.identity.sovereign_identity.is_none() {
            return Err(AnonOnionSendError::NoIdentity);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Resolve the best currently-valid ad across the recipient's replica
        // slots. verify_rendezvous_ad binds receiver_node_id↔issuer_pk; we also
        // reject an ad replicated into the wrong slot.
        let mut chosen: Option<veil_anonymity::rendezvous::RendezvousAd> = None;
        for idx in 0..MAX_RENDEZVOUS_AD_SLOTS {
            let key = rendezvous_ad_dht_key_at(&receiver_node_id, idx);
            let Some(bytes) = self.dht_recursive_get(key, RESOLVE_TIMEOUT).await else {
                continue;
            };
            let Ok(ad) = decode_rendezvous_ad(&bytes) else {
                continue;
            };
            if verify_rendezvous_ad(&ad).is_err()
                || ad.receiver_node_id != receiver_node_id
                || is_currently_valid(&ad, now).is_err()
            {
                continue;
            }
            chosen = Some(ad);
            break;
        }
        let Some(ad) = chosen else {
            return Err(AnonOnionSendError::NoRendezvous);
        };

        // Pre-resolve the rendezvous relay's directory entry into our local DHT
        // shard so `send_via_rendezvous_authenticated`'s `get_local` lookup finds
        // it (otherwise that path silent-drops when the entry isn't organically
        // cached — review fix).
        let relay_key = veil_anonymity::directory::relay_directory_dht_key(&ad.rendezvous_node_id);
        if self.dht.get_local(&relay_key).is_none()
            && let Some(bytes) = self.dht_recursive_get(relay_key, RESOLVE_TIMEOUT).await
        {
            self.dht.store_local(relay_key, bytes);
        }

        self.send_via_rendezvous_authenticated(
            &ad,
            target_app_id,
            target_endpoint_id,
            data,
            hop_count,
            reply,
        )
        .map_err(|e| match e {
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
        })
    }

    /// Reply to a previously-received authenticated message via its one-time
    /// reply block. `reply_id` is the opaque handle the recipient app got
    /// alongside the inbound message; we look the daemon-side block up,
    /// reconstruct the original sender's rendezvous path from it, and send an
    /// authenticated anonymous message back — WITHOUT either side publishing a
    /// public ad (the whole point of the reply channel: no presence leak).
    ///
    /// The reply itself carries no further reply block (`reply = None`): a v1
    /// reply is terminal. The block is NON-consuming and valid until its TTL (1b),
    /// so a reply whose cell the network drops can be RETRIED with the same
    /// `reply_id`; delivery is at-least-once (the recipient de-dups). An unknown
    /// or TTL-expired id fails with `NoRendezvous`.
    pub async fn send_reply(
        &self,
        reply_id: u64,
        data: &[u8],
        hop_count: usize,
    ) -> std::result::Result<(), veil_types::AnonOnionSendError> {
        use veil_types::AnonOnionSendError;

        const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        if self.identity.sovereign_identity.is_none() {
            return Err(AnonOnionSendError::NoIdentity);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Look up the reply block (NON-consuming — stays valid until TTL so the
        // app can retry if this reply's cell is dropped; 1b). gone/expired → no
        // reply path.
        let Some(block) = self.anonymity.reply_block_store.peek(reply_id, now) else {
            return Err(AnonOnionSendError::NoRendezvous);
        };

        // Reconstruct the original sender's rendezvous path as a synthetic ad.
        // Only the four routing fields are read downstream
        // (`send_via_rendezvous_authenticated` → `send_sealed_introduce`); the
        // signed-ad fields are irrelevant here because the path came from a
        // signature-bound reply block, not a DHT lookup, so it needs no
        // re-verification. Validity bounds are set wide-open for the same reason.
        let ad = veil_anonymity::rendezvous::RendezvousAd {
            receiver_node_id: block.receiver_node_id,
            rendezvous_node_id: block.rendezvous_node_id,
            auth_cookie: block.auth_cookie,
            receiver_x25519_pk: block.x25519_pk,
            valid_from_unix: 0,
            valid_until_unix: u64::MAX,
            issuer_pk: String::new(),
            issuer_algo: veil_types::SignatureAlgorithm::Ed25519,
            signature: Vec::new(),
            push_envelope: Vec::new(),
            capability_token: Vec::new(),
            wake_hmac_envelope: Vec::new(),
            // Inert: the synthetic ad is never re-encoded or verified.
            wire_version: 0,
        };

        // Pre-resolve the reply relay's directory entry into our local shard so
        // the onion build can reach it (same fix as `send_anonymous_*_to`).
        let relay_key = veil_anonymity::directory::relay_directory_dht_key(&ad.rendezvous_node_id);
        if self.dht.get_local(&relay_key).is_none()
            && let Some(bytes) = self.dht_recursive_get(relay_key, RESOLVE_TIMEOUT).await
        {
            self.dht.store_local(relay_key, bytes);
        }

        self.send_via_rendezvous_authenticated(
            &ad,
            block.reply_app_id,
            block.reply_endpoint_id,
            data,
            hop_count,
            None,
        )
        .map_err(|e| match e {
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
        })
    }

    /// Seal `sealed_plaintext` (which already carries its `final_hop_kind` tag)
    /// to the ad's recipient, wrap it as an `IntroducePayload`, and onion-route
    /// it to the rendezvous relay as the Final hop. Shared by the plain
    /// ([`send_via_rendezvous`]) and authenticated
    /// ([`send_via_rendezvous_authenticated`]) rendezvous paths.
    fn send_sealed_introduce(
        &self,
        ad: &veil_anonymity::rendezvous::RendezvousAd,
        sealed_plaintext: &[u8],
        hop_count: usize,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        use veil_anonymity::rendezvous::{IntroducePayload, encrypt_introduce, final_hop_kind};

        // Step 2: seal to receiver_x25519_pk. Rendezvous cannot read
        // this — only the receiver after their `decrypt_introduce`.
        // encrypt_introduce only fails on AEAD library error (vanishingly
        // rare); treat as PayloadTooLarge for surface-level error
        // reporting (caller's recourse is the same: shrink payload or
        // retry).
        let ciphertext =
            encrypt_introduce(sealed_plaintext, &ad.receiver_x25519_pk).map_err(|_| {
                veil_anonymity::sender::SenderError::PayloadTooLarge {
                    hop_count,
                    got: sealed_plaintext.len(),
                    max: 0,
                }
            })?;

        // Step 3: wrap as IntroducePayload.
        let intro = IntroducePayload {
            receiver_node_id: ad.receiver_node_id,
            auth_cookie: ad.auth_cookie,
            ciphertext,
        };
        let intro_bytes =
            intro
                .encode()
                .map_err(|_| veil_anonymity::sender::SenderError::PayloadTooLarge {
                    hop_count,
                    got: sealed_plaintext.len(),
                    max: 0,
                })?;

        // Step 4: prepend final-hop kind tag.
        let mut payload_bytes = Vec::with_capacity(1 + intro_bytes.len());
        payload_bytes.push(final_hop_kind::INTRODUCE);
        payload_bytes.extend_from_slice(&intro_bytes);

        // Step 5: build + dispatch the onion cell with rendezvous_node_id
        // as the Final-hop target. Rendezvous's anonymity_x25519_pk
        // is needed for the outermost onion layer; we look it up from
        // its directory entry (shipped in).
        use veil_anonymity::{
            directory::{
                DEFAULT_FRESHNESS_WINDOW_SECS, discover_relay_hops, relay_directory_dht_key,
            },
            sender::{
                DiversityOutcome,
                build_outbound_anonymous_cell_with_diversity_reported_and_reputation,
            },
        };
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Resolve rendezvous's directory entry to fetch its x25519_pk.
        let dht = Arc::clone(&self.dht);
        let candidates = vec![ad.rendezvous_node_id];
        let resolved = discover_relay_hops(
            &candidates,
            |node_id| dht.get_local(&relay_directory_dht_key(node_id)),
            now_unix,
            DEFAULT_FRESHNESS_WINDOW_SECS,
        );
        let rendezvous_relay = match resolved.into_iter().next() {
            Some(r) => r,
            None => {
                // Rendezvous not in our DHT cache — same silent-drop
                // semantics as `send_anonymous` first-hop unreachable.
                return Ok(());
            }
        };

        // Snapshot relay candidates (excluding rendezvous itself —
        // rendezvous is the Final-hop, not a middle-hop).
        // W0 measurement: time selection vs build (see send_anonymous).
        let t_select = std::time::Instant::now();
        let candidate_node_ids: Vec<[u8; 32]> = self
            .dht
            .routing_table_contacts()
            .into_iter()
            .map(|c| c.node_id)
            .filter(|nid| *nid != ad.rendezvous_node_id)
            .collect();
        let usable_relays = discover_relay_hops(
            &candidate_node_ids,
            |node_id| dht.get_local(&relay_directory_dht_key(node_id)),
            now_unix,
            DEFAULT_FRESHNESS_WINDOW_SECS,
        );

        // Vivaldi-based RTT estimator (same shape as send_anonymous).
        let local_vivaldi = self.dispatcher.local_vivaldi.clone();
        let peer_vivaldi = Arc::clone(&self.dispatcher.peer_vivaldi);
        let rtt_estimator = move |node_id: &[u8; 32]| -> Option<u32> {
            let local = local_vivaldi.as_ref()?;
            let peer_map = rlock!(peer_vivaldi);
            let (peer_coord, _) = peer_map.get(node_id)?;
            let local_guard = lock!(local);
            let estimated_ms = local_guard.distance_estimate(peer_coord) * 1000.0;
            if !estimated_ms.is_finite() || estimated_ms < 0.0 {
                return None;
            }
            Some(estimated_ms.min(u32::MAX as f64) as u32)
        };

        // Anti-censorship AS-diversity extractor (same shape as
        // send_anonymous) — see the helper comments in that function.
        let diversity_map = build_as_diversity_map(&self.discovered_peers_cache);
        let diversity_key_of =
            move |node_id: &[u8; 32]| -> Option<String> { diversity_map.get(node_id).cloned() };

        // Downweight relays with recorded failures (Epic 482.3/482.4 Phase A) —
        // see send_anonymous for rationale.
        let relay_reputation = Arc::clone(&self.anonymity.relay_reputation);
        let reputation_penalty_ms =
            move |node_id: &[u8; 32]| -> u32 { relay_reputation.rtt_penalty_ms(*node_id) };
        let select_us = t_select.elapsed().as_micros();
        let t_build = std::time::Instant::now();
        let ((first_hop_node_id, cell), diversity) =
            build_outbound_anonymous_cell_with_diversity_reported_and_reputation(
                &payload_bytes,
                &usable_relays,
                rtt_estimator,
                diversity_key_of,
                reputation_penalty_ms,
                ad.rendezvous_node_id,
                rendezvous_relay.hop.pubkey,
                hop_count,
            )?;
        // W0 measurement (see send_anonymous).
        log::debug!(
            "anonymity.rendezvous.timing select_us={select_us} build_us={} \
             payload={} hops={hop_count} candidates={} usable={}",
            t_build.elapsed().as_micros(),
            payload_bytes.len(),
            candidate_node_ids.len(),
            usable_relays.len(),
        );
        if diversity == DiversityOutcome::DegradedToLatency {
            log::warn!(
                "anonymity.rendezvous.diversity_degraded hop_count={hop_count} \
                 candidates={} — no AS-diverse relay set; fell back to latency-only",
                usable_relays.len()
            );
        }

        use veil_proto::{
            codec::encode_header,
            family::{FrameFamily, RelayChainMsg},
            header::FrameHeader,
        };
        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
        hdr.body_len = cell.len() as u32;
        hdr.set_priority(veil_proto::priority::INTERACTIVE);
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(&cell);
        if let Some(ref reg) = self.dispatcher.session_tx_registry {
            let guard = wlock!(reg);
            let sent = guard.send_to(&first_hop_node_id, veil_proto::priority::INTERACTIVE, frame);
            drop(guard);
            if !sent {
                // Signal 1 (Phase A): chosen anonymity first hop has no live
                // session — record it (per-sender-local, no external behaviour
                // change). See send_anonymous.
                self.anonymity
                    .relay_reputation
                    .record_failure(first_hop_node_id);
            }
        }
        Ok(())
    }
}
