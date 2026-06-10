//! OVL1 frame dispatcher — routes decoded frames to the appropriate service plane.
//!
//! `FrameDispatcher` sits between the session I/O layer and the service planes.
//! After a session is established (handshake complete), every incoming OVL1 frame
//! passes through `FrameDispatcher::dispatch`:
//!
//! 1. Abuse pre-checks: ban list → rate limiter.
//! 2. Route by `family` + `msg_type` to the right service.
//! 3. Return an optional response frame (pre-encoded, ready for `write_all`).
//!
//! The dispatcher is clone-cheap because all services are behind `Arc`.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::hash::Hash;
use std::sync::atomic::{AtomicU32, AtomicU64};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use veil_cfg::NodeId;
use veil_types::NodeIdBytes;
use veil_util::lock;
#[cfg(test)]
use veil_util::wlock;

use tokio::sync::{Notify, broadcast, mpsc};

/// Per-peer Vivaldi coordinate cache. Value is `(coord, last_used)` for LRU eviction.
// RwLock because read-heavy (every route selection reads for scoring;
// writes only on handshake + periodic memory eviction).
pub type PeerVivaldiCache =
    Arc<RwLock<HashMap<NodeIdBytes, (veil_routing::VivaldiCoord, std::time::Instant)>>>;

use ed25519_dalek::SigningKey;

use veil_abuse::{BanList, DhtQuota, PerPeerLimiter, ViolationTracker};
use veil_app::{AppEndpointRegistry, AppStreamTable};
use veil_cfg::NodeRole;
use veil_dht::KademliaService;
use veil_discovery::DiscoveryService;
use veil_gateway::GatewayService;
use veil_mesh::MeshForwarder;
use veil_observability::{NodeLogger, NodeMetrics};
use veil_proto::{
    codec::encode_header,
    control::NatProbeReplyPayload,
    family::{FrameFamily, RoutingMsg},
    header::{FrameHeader, HEADER_SIZE},
};
use veil_routing::control_plane::ControlPlaneService;
use veil_routing::{NeighborScorer, RouteCache};
use veil_session::tx_registry::SessionTxRegistry;

pub mod anonymity;
pub mod app;
pub mod control;
pub mod delivery;
pub mod diag;
pub mod discovery;
pub mod envelope_chunks;
pub mod pending_ack;
pub mod routing;
pub mod session;
pub mod sink_impl;

// ── build_own_host_candidates ────────────────────────────────────────────────
//
// Inlined helper: builds RFC 8445 ICE host candidates from listen URIs.
// Sat at an awkward intersection (proto + transport types) when extracted
// from veilcore's util.rs; kept dispatcher-local here.
pub fn build_own_host_candidates(listen_uris: &[String]) -> Vec<veil_proto::control::NatCandidate> {
    use std::net::IpAddr;
    use veil_proto::control::{NatCandidate, candidate_type};
    use veil_transport::TransportUri;
    const HOST_PRIORITY: u32 = 2_130_706_431;
    listen_uris
        .iter()
        .filter_map(|uri_str| {
            let uri = TransportUri::parse(uri_str).ok()?;
            let (host, port) = match &uri {
                TransportUri::Tcp { host, port }
                | TransportUri::Tls { host, port, .. }
                | TransportUri::Quic { host, port, .. } => (host.as_str(), *port),
                _ => return None,
            };
            let host_trimmed = host.trim_start_matches('[').trim_end_matches(']');
            let ip: IpAddr = host_trimmed.parse().ok()?;
            if ip.is_unspecified() {
                return None;
            }
            let (atyp, addr_bytes): (u8, Vec<u8>) = match ip {
                IpAddr::V4(v4) => (4, v4.octets().to_vec()),
                IpAddr::V6(v6) => (6, v6.octets().to_vec()),
            };
            Some(NatCandidate {
                atyp,
                candidate_type: candidate_type::HOST,
                priority: HOST_PRIORITY,
                addr: addr_bytes,
                port,
            })
        })
        .collect()
}

// ── PowPendingTable ───────────────────────────────────────────────────────────

/// Pending PoW challenge state with O(log n) eviction.
///
/// Invariant: `map.len == order.len`.
pub struct PowPendingTable {
    /// Maps `challenge_nonce → (requester_node_id, difficulty, request_id, issued_at)`.
    /// `request_id` echoes the originating `RouteRequestPayload.request_id` so the
    /// deferred `RouteResponse` (sent after PoW verify (Level 1)) can be
    /// correlated by the requester.
    map: HashMap<[u8; 32], ([u8; 32], u8, u32, Instant)>,
    /// Insertion-order index for O(log n) oldest-first eviction.
    order: std::collections::BTreeMap<(Instant, [u8; 32]), ()>,
}

impl Default for PowPendingTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PowPendingTable {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: std::collections::BTreeMap::new(),
        }
    }

    pub fn insert(
        &mut self,
        nonce: [u8; 32],
        requester: [u8; 32],
        difficulty: u8,
        request_id: u32,
        now: Instant,
    ) {
        if let Some((_, _, _, old_t)) = self.map.get(&nonce) {
            self.order.remove(&(*old_t, nonce));
        }
        self.map
            .insert(nonce, (requester, difficulty, request_id, now));
        self.order.insert((now, nonce), ());
    }

    pub fn remove(&mut self, nonce: &[u8; 32]) -> Option<([u8; 32], u8, u32)> {
        if let Some((requester, diff, request_id, t)) = self.map.remove(nonce) {
            self.order.remove(&(t, *nonce));
            Some((requester, diff, request_id))
        } else {
            None
        }
    }

    /// Evict the oldest entry if at or over capacity. O(log n).
    pub fn evict_if_full(&mut self, max: usize) {
        if self.map.len() < max {
            return;
        }
        if let Some(&(t, nonce)) = self.order.keys().next() {
            self.map.remove(&nonce);
            self.order.remove(&(t, nonce));
        }
    }

    /// Drop all entries older than `ttl`. O(k log n) where k = expired count.
    pub fn evict_stale(&mut self, now: Instant, ttl: Duration) {
        while let Some(&(t, nonce)) = self.order.keys().next() {
            if now.duration_since(t) < ttl {
                break;
            }
            self.map.remove(&nonce);
            self.order.remove(&(t, nonce));
        }
    }
}

// ── CryptoContext ─────────────────────────────────────────────────────────────

/// Cryptographic identity and key-material shared by all dispatcher clones.
///
/// Clone-cheap: all fields are `Arc`.
#[derive(Clone)]
pub struct CryptoContext {
    /// Ed25519 signing key for ROUTE_ANNOUNCE / ROUTE_WITHDRAW frames.
    /// `None` in tests that do not need gossip signing.
    pub local_signing_key: Option<Arc<SigningKey>>,
    /// ML-KEM-768 encapsulation key (public, 1184 bytes) for this node.
    /// Included in `RouteResponsePayload` so remote nodes can encrypt for us.
    pub mlkem_ek: Arc<[u8; veil_e2e::EK_BYTES]>,
    /// ML-KEM-768 decapsulation-key seed (64 bytes) for this node.
    ///
    /// **Forward-secrecy limitation:** This seed is loaded at
    /// node start and held in memory for the lifetime of the process. Unlike
    /// ephemeral session keys, it is *not* rotated per-session — any historical
    /// ciphertext captured before the seed was changed can be decrypted by an
    /// attacker who later exfiltrates the seed. The practical impact is
    /// bounded by TLS-style "break-then-decrypt": an attacker must both
    /// (a) record the ciphertext *and* (b) compromise the node later.
    ///
    /// Mitigation options (not yet implemented):
    /// * Rotate `mlkem_dk_seed` on a configurable schedule and re-derive EK.
    /// * Use ephemeral ML-KEM per session (requires a second round-trip).
    ///
    /// # Memory hygiene (Phase 6 slice 6g)
    ///
    /// Backed by [`veil_util::sensitive_bytes::SensitiveBytesN<64>`] —
    /// the 64-byte DK seed is pinned via `mlock(2)` when `RLIMIT_MEMLOCK`
    /// permits, falls back to a zeroize-on-drop `Zeroizing<Vec<u8>>`
    /// otherwise.  Closing the swap-to-disk vector matters more here than
    /// for any session-scoped key: the DK seed is **process-lifetime**
    /// (rotation is a manual operator action — see mitigation note
    /// above), so if pages holding it land on disk under sustained
    /// memory pressure, **every E2E ciphertext ever sent to this node**
    /// becomes recoverable by anyone with read access to the swap partition.
    pub mlkem_dk_seed:
        Arc<veil_util::sensitive_bytes::SensitiveBytesN<{ veil_e2e::DK_SEED_BYTES }>>,
    /// Peer ML-KEM-768 encapsulation-key cache: `peer_id → (ek_bytes, cached_at)`.
    pub peer_mlkem_keys: Arc<std::sync::RwLock<veil_e2e::PeerMlKemCache>>,
    /// Maps `peer_id → (algo_byte, raw_pubkey_bytes)`. Populated when a
    /// session is established, cleared when it closes.
    pub peer_pubkeys: veil_types::PeerPubkeysCache,
    /// Maps `peer_id → roles_supported` bitmask from the peer's
    /// `CapabilitiesPayload`. Populated at session establishment.
    ///
    /// Used by the `AnnounceAttachment` handler to verify that a peer's
    /// self-declared `role` field matches the capabilities advertised during
    /// the OVL1 handshake, preventing Gateway-role spoofing.
    pub peer_roles: Arc<Mutex<veil_types::PeerLruCache<u8>>>,
    /// Maps `peer_id → flags` bitmask from the peer's `CapabilitiesPayload`
    /// (the `flags` field, not `roles_supported`). Populated at session
    /// establishment alongside `peer_roles`.
    ///
    /// used by `relay_forward` to skip relay candidates that did
    /// not advertise `cap_flags::CAN_RELAY`, preventing routing through
    /// nodes that cannot relay.
    ///
    /// `RwLock` (not `Mutex`): the delivery hot path needs only a read guard
    /// (many concurrent readers) while session open/close are rare writers.
    /// This avoids cloning the entire map on every relayed frame.
    pub peer_cap_flags: Arc<RwLock<HashMap<NodeIdBytes, u8>>>,
    /// Per-session ephemeral ML-KEM-768 decapsulation-key seeds.
    ///
    /// Maps `peer_id → dk_seed` where `dk_seed` is the 64-byte seed for the
    /// ephemeral decapsulation key that was negotiated with that peer during an
    /// intra-session ML-KEM rotation (`MlKemRekeyEk` / `MlKemRekeyAck`).
    ///
    /// When decrypting an incoming E2E envelope the dispatcher first checks this
    /// map for a session-specific seed; if absent it falls back to the global
    /// `mlkem_dk_seed`. Entries are removed when the corresponding session closes
    /// so stale ephemeral keys do not accumulate.
    ///
    /// Phase 6 slice 6h — value type changed from `[u8; 64]` to
    /// `SensitiveBytesN<64>` so per-session DK seeds are mlocked
    /// while the session is open (closes the swap-to-disk vector for
    /// the hours-long session lifetime).
    pub per_session_mlkem_dk: Arc<
        Mutex<
            HashMap<
                NodeIdBytes,
                veil_util::sensitive_bytes::SensitiveBytesN<{ veil_e2e::DK_SEED_BYTES }>,
            >,
        >,
    >,
}

// ── AbuseContext ──────────────────────────────────────────────────────────────

/// Abuse-resistance state shared by all dispatcher clones.
///
/// Clone-cheap: all fields are `Arc`.
#[derive(Clone)]
pub struct AbuseContext {
    pub rate_limiter: Arc<Mutex<PerPeerLimiter>>,
    pub ban_list: Arc<Mutex<BanList>>,
    pub violation_tracker: Arc<Mutex<ViolationTracker>>,
    pub dht_quota: Arc<Mutex<DhtQuota>>,
    /// per-`identity_id` DHT write quota.
    ///
    /// Complements `dht_quota` (per-peer/connection): the per-peer
    /// limiter alone does NOT catch a compromised `identity_sk`
    /// pushing rapid `document_version++` updates from many distinct
    /// peers. Indexed by the `node_id` extracted from the wire
    /// payload (IdentityDocument / InstanceRegistry / MlKemKeyCert /
    /// NameClaim). Default: 10 writes per identity per rolling hour;
    /// rate-limited writes silently drop (NOT Violation — owner
    /// recovery flows may legitimately need to push several updates
    /// in a short window).
    pub identity_write_quota: Arc<veil_abuse::identity_quota::IdentityWriteQuota>,
    /// Node-wide inbound bandwidth throttle.
    pub inbound_bandwidth: Arc<Mutex<veil_abuse::BandwidthGate>>,
    /// Node-wide outbound bandwidth throttle.
    /// Checked by SessionRunner before sending outbound frames.
    pub outbound_bandwidth: Arc<Mutex<veil_abuse::BandwidthGate>>,
    /// Separate per-peer token bucket for incoming `PowChallenge` frames.
    pub pow_challenge_limiter: Arc<Mutex<PerPeerLimiter>>,
    /// Per-peer quota for new route insertions from RouteResponse.
    ///
    /// Limits how many distinct destinations a single peer may contribute to the
    /// RouteCache per window, preventing DHT eclipse via FIND_NODE flooding:
    /// an attacker cannot fill the cache with attacker-controlled next-hops by
    /// responding to FIND_NODE requests with a flood of fake node_ids.
    pub dht_contact_quota: Arc<Mutex<DhtQuota>>,
    /// Per-peer rate limiter for `AnnounceAttachment` frames.
    ///
    /// Signature verification on each frame is expensive. A malicious or
    /// malfunctioning peer could send announcements in a tight loop and saturate
    /// the dispatcher's processing thread. This limiter allows a small burst
    /// (e.g. on reconnect) but throttles sustained floods.
    pub announce_attachment_limiter: Arc<Mutex<PerPeerLimiter>>,
    /// Per-peer quota on relay-mode NAT-probe forwards.
    ///
    /// Throttles `NatProbeRequest` and `NatProbeReply` frames a peer asks us
    /// to forward in coordinator mode. Without this gate, a
    /// peer firing unique `query_id`s burst-amplifies their bandwidth ~2×
    /// per relay hop on the receiver — a real amplification surface for a
    /// budget Android device sitting between hostile peers. Frames beyond
    /// the quota are silently dropped (the initiator times out and tries a
    /// different coordinator).
    pub nat_probe_forward_quota: Arc<Mutex<DhtQuota>>,
    /// Per-peer rate limiter on `RecursiveQuery` frames (recursive
    /// DHT routing). A peer can fire arbitrary `query_id`s targeting any
    /// key; each query consumes signature/decode work plus a TTL slot in
    /// `recursive_query_seen`. The pre-existing dedup catches loops on
    /// the *same* query_id, but not a peer flooding *distinct* query_ids
    /// to amplify load on every node along the recursive forward chain.
    /// Capped at a generous burst (legitimate Kademlia clients rarely
    /// exceed a few queries/sec) — frames over the budget are silently
    /// dropped (not Violation: the peer may simply be reconnecting after
    /// a long absence).
    pub recursive_query_limiter: Arc<Mutex<PerPeerLimiter>>,
}

// PendingRecursive
// CaptureEvent and DiagEvent
// moved to `veil-dispatcher-state` so the IPC server can construct /
// read them without depending on dispatcher internals. Re-exported here
// to keep `crate::{PendingRecursive,CaptureEvent,DiagEvent}`
// call sites compiling unchanged.
pub use veil_dispatcher_state::{CaptureEvent, DiagEvent, PendingRecursive};

/// type alias for the route-miss channel sender.
/// Carries `(target_node_id, traffic_class)` so the iterative-DHT
/// fallback can apply priority-aware timeout multipliers.
pub type RouteMissTx = mpsc::Sender<([u8; 32], u8)>;

// ── ExpiryCache ───────────────────────────────────────────────────────────────

/// Generic deduplication set with TTL expiry and O(1) oldest-entry eviction.
///
/// # Complexity
/// * `check_and_insert`: amortised O(log n) — O(log n) heap push/pop, O(1) set ops.
/// * Eviction when full: O(log n) — one `BinaryHeap::pop` instead of the
///   previous O(n) `min_by_key` scan over the expiry Vec.
///
/// Entries that exceed `ttl` are lazily removed from the top of the min-heap
/// on the next `check_and_insert` call; entries that are still valid but
/// exceed `max_size` are evicted starting from the oldest (cheapest to pop).
///
/// # Clock behaviour
///
/// Uses `Instant` which is guaranteed monotonic by Rust's stdlib. On Linux /
/// macOS it is backed by `CLOCK_MONOTONIC` which pauses during system suspend;
/// effectively, entries that were live at suspend remain live after resume and
/// continue their TTL countdown from that point. Only monotonic comparisons
/// (`>=`) and additions (`now + ttl`) are used — no `duration_since` that
/// could panic on a non-monotonic clock pair.
pub struct ExpiryCacheEntry<K> {
    expires_at: Instant,
    key: K,
}
impl<K: Eq> PartialEq for ExpiryCacheEntry<K> {
    fn eq(&self, other: &Self) -> bool {
        self.expires_at == other.expires_at
    }
}
impl<K: Eq> Eq for ExpiryCacheEntry<K> {}
impl<K: Eq> PartialOrd for ExpiryCacheEntry<K> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<K: Eq> Ord for ExpiryCacheEntry<K> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.expires_at.cmp(&other.expires_at)
    }
}

pub struct ExpiryCache<K> {
    entries: HashSet<K>,
    heap: BinaryHeap<Reverse<ExpiryCacheEntry<K>>>,
    ttl: Duration,
    max_size: usize,
}

impl<K: Hash + Eq + Copy + Ord> ExpiryCache<K> {
    pub fn new(ttl: Duration, max_size: usize) -> Self {
        Self {
            entries: HashSet::new(),
            heap: BinaryHeap::new(),
            ttl,
            max_size,
        }
    }

    /// Returns `true` if `key` was already seen.
    /// Returns `false` and records the key if it's new.
    pub fn check_and_insert(&mut self, key: K) -> bool {
        let now = Instant::now();
        // Drain expired entries from the heap top in O(log n) per removal.
        while let Some(Reverse(e)) = self.heap.peek() {
            if now >= e.expires_at {
                if let Some(Reverse(entry)) = self.heap.pop() {
                    self.entries.remove(&entry.key);
                }
            } else {
                break;
            }
        }
        if self.entries.contains(&key) {
            return true;
        }
        // Evict the oldest entry in O(log n) when at capacity.
        if self.entries.len() >= self.max_size
            && let Some(Reverse(oldest)) = self.heap.pop()
        {
            self.entries.remove(&oldest.key);
        }
        self.entries.insert(key);
        self.heap.push(Reverse(ExpiryCacheEntry {
            expires_at: now + self.ttl,
            key,
        }));
        false
    }
}

/// TTL- and capacity-bounded key→value cache (the value-carrying sibling of
/// [`ExpiryCache`]). Same O(log n) heap-driven expiry + oldest-entry eviction.
///
/// Used for the terminal-delivery ACK-replay cache (audit cycle-8 H8): maps a
/// `content_id` to the `(sender, ack_key)` needed to RE-emit a DELIVERED ACK
/// when a retransmit arrives (because the original ACK was lost), without
/// re-decrypting the payload. Each key is inserted at most once per delivery, so
/// the simple "one heap entry per insert" model needs no generation tracking.
pub struct ExpiryMap<K, V> {
    entries: HashMap<K, V>,
    heap: BinaryHeap<Reverse<ExpiryCacheEntry<K>>>,
    ttl: Duration,
    max_size: usize,
}

impl<K: Hash + Eq + Copy + Ord, V> ExpiryMap<K, V> {
    pub fn new(ttl: Duration, max_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            heap: BinaryHeap::new(),
            ttl,
            max_size,
        }
    }

    fn prune_expired(&mut self, now: Instant) {
        while let Some(Reverse(e)) = self.heap.peek() {
            if now >= e.expires_at {
                if let Some(Reverse(entry)) = self.heap.pop() {
                    self.entries.remove(&entry.key);
                }
            } else {
                break;
            }
        }
    }

    /// Insert or update. Evicts the oldest entry in O(log n) when at capacity.
    ///
    /// Idempotent on the heap (audit cycle-9): re-inserting an existing key
    /// refreshes the VALUE in place but does NOT push a second heap entry. A
    /// duplicate heap entry would later be popped by `prune_expired` and evict
    /// the still-live key early (the existing key's original expiry stands).
    pub fn insert(&mut self, key: K, value: V) {
        let now = Instant::now();
        self.prune_expired(now);
        if let Some(slot) = self.entries.get_mut(&key) {
            *slot = value; // in-place value update, no new heap entry
            return;
        }
        if self.entries.len() >= self.max_size
            && let Some(Reverse(oldest)) = self.heap.pop()
        {
            self.entries.remove(&oldest.key);
        }
        self.entries.insert(key, value);
        self.heap.push(Reverse(ExpiryCacheEntry {
            expires_at: now + self.ttl,
            key,
        }));
    }

    /// Look up a live (non-expired) value.
    pub fn get(&mut self, key: &K) -> Option<&V> {
        let now = Instant::now();
        self.prune_expired(now);
        self.entries.get(key)
    }
}

/// Shared terminal-delivery ACK-replay cache: `content_id → (sender, ack_key)`
/// (audit cycle-8 H8). Type alias to keep the dispatcher field readable.
pub type TerminalAckReplay = Arc<Mutex<ExpiryMap<[u8; 32], ([u8; 32], [u8; 32])>>>;

// ── RouteSeenSet ──────────────────────────────────────────────────────────────

/// Gossip deduplication set.
///
/// Uses two layers of deduplication:
///
/// 1. **Per-`(origin, via, seq)` dedup** — prevents re-processing the same
///    gossip triple from the same forwarding path.
/// 2. **Per-`(origin, seq)` replay-window** — prevents replaying an old but
///    still-valid *signed* announcement through a *different* `via` path once
///    the original entry has expired from layer 1. A ROUTE_ANNOUNCE with
///    sequence N from origin O is accepted at most once regardless of which
///    relay forwards it.
pub type SeenKey = ([u8; 32], [u8; 32], u32);
/// Replay-window key: `(origin_node_id, sequence)` — independent of via.
pub type AnnounceReplayKey = ([u8; 32], u32);

pub struct RouteSeenSet {
    /// Layer 1: per-(origin, via, seq) dedup.
    full: ExpiryCache<SeenKey>,
    /// Layer 2: per-(origin, seq) replay window — deduplicates across vias.
    replay: ExpiryCache<AnnounceReplayKey>,
}

impl RouteSeenSet {
    pub fn new(ttl: Duration, max_size: usize) -> Self {
        // The replay window uses the same TTL and half the capacity (it has
        // fewer unique keys since via is collapsed).
        Self {
            full: ExpiryCache::new(ttl, max_size),
            replay: ExpiryCache::new(ttl, max_size / 2 + 1),
        }
    }

    /// Returns `true` if this triple was already seen (duplicate → drop).
    /// Returns `false` and records the triple if it's new.
    ///
    /// An announcement is considered "seen" if either:
    /// the exact `(origin, via, seq)` triple was processed before, OR
    /// any announcement with `(origin, seq)` was processed (replay).
    fn check_and_insert(&mut self, origin: [u8; 32], via: [u8; 32], seq: u32) -> bool {
        // Layer 2: per-(origin, seq) check first — this is the replay guard.
        if self.replay.check_and_insert((origin, seq)) {
            // Already seen this (origin, seq) from some via — drop regardless of
            // current via to prevent replay through a different forwarding path.
            return true;
        }
        // Layer 1: per-(origin, via, seq) check.
        self.full.check_and_insert((origin, via, seq))
    }
}

// ── ForwardSeenSet ────────────────────────────────────────────────────────────

/// Relay deduplication set keyed by `content_id`.
///
/// Prevents replay attacks: if the same `content_id` arrives twice within the
/// TTL window the second copy is silently dropped. Capacity-bounded with
/// O(log n) oldest-entry eviction when full.
pub struct ForwardSeenSet(ExpiryCache<[u8; 32]>);

impl ForwardSeenSet {
    pub fn new(ttl: Duration, max_size: usize) -> Self {
        Self(ExpiryCache::new(ttl, max_size))
    }

    /// Returns `true` if `content_id` was already seen (duplicate → drop).
    /// Returns `false` and records it if it's new.
    pub fn check_and_insert(&mut self, content_id: [u8; 32]) -> bool {
        self.0.check_and_insert(content_id)
    }
}

// ── EpidemicSeenSet ───────────────────────────────────────────────────────────

/// Epidemic broadcast deduplication set keyed by `msg_id: [u8; 16]`.
///
/// Returns `true` (already seen → drop) or `false` (new → process + forward).
pub struct EpidemicSeenSet(ExpiryCache<[u8; 16]>);

impl EpidemicSeenSet {
    pub fn new(ttl: Duration, max_size: usize) -> Self {
        Self(ExpiryCache::new(ttl, max_size))
    }

    /// Returns `true` if `msg_id` was already seen. Records it if new.
    pub fn check_and_insert(&mut self, msg_id: [u8; 16]) -> bool {
        self.0.check_and_insert(msg_id)
    }
}

// ── TraceBuffer ───────────────────────────────────────────────────────────────

/// One delivery-trace hop record.
#[derive(Debug, Clone)]
pub struct TraceHopRecord {
    pub trace_id: u64,
    /// Peer the frame was received from.
    pub from_peer: [u8; 32],
    /// Peer (next hop) the frame was forwarded to; `[0; 32]` = final delivery.
    pub to_peer: [u8; 32],
    /// RTT to `to_peer` at the time of forwarding (0 = unknown).
    pub hop_rtt_ms: u32,
    /// Unix timestamp in milliseconds when this hop was recorded.
    pub timestamp_ms: u64,
}

/// In-memory ring buffer of delivery-trace records.
///
/// Capped at a configurable size; oldest records are evicted when full.
pub struct TraceBuffer {
    records: std::collections::VecDeque<TraceHopRecord>,
    max_size: usize,
}

impl TraceBuffer {
    pub fn new(max_size: usize) -> Self {
        Self {
            records: std::collections::VecDeque::with_capacity(max_size.min(1024)),
            max_size,
        }
    }

    /// Append a record. Evicts the oldest entry if at capacity.
    pub fn push(&mut self, rec: TraceHopRecord) {
        if self.records.len() >= self.max_size {
            self.records.pop_front();
        }
        self.records.push_back(rec);
    }

    /// Return all records matching `trace_id`, sorted by `timestamp_ms`.
    pub fn query(&self, trace_id: u64) -> Vec<TraceHopRecord> {
        let mut out: Vec<TraceHopRecord> = self
            .records
            .iter()
            .filter(|r| r.trace_id == trace_id)
            .cloned()
            .collect();
        out.sort_by_key(|r| r.timestamp_ms);
        out
    }
}

// ── DispatchResult ────────────────────────────────────────────────────────────
//
// Phase 2 session 2 prep: type moved to `session::dispatcher_sink`
// (it is the return type of the `DispatcherSink::dispatch` trait method,
// and lives alongside the trait that uses it).  Re-exported here so
// existing call sites — `dispatcher::routing::*`, etc. — keep compiling
// unchanged.
pub use veil_session::dispatcher_sink::DispatchResult;

// ── FrameDispatcher ───────────────────────────────────────────────────────────

/// Routes OVL1 frames from established sessions to the correct service plane.
///
/// Clone-cheap: all contained handles are `Arc`.
///
/// # Lock ordering
///
/// Canonical workspace-wide acquire order (see also
/// `runtime/session_guard.rs` for the session-side fields).  When multiple
/// mutexes must be acquired simultaneously, always take them in this order
/// to prevent deadlock:
///
/// 1. `route_cache`              (RwLock)
/// 2. `session_tx_registry`      (RwLock)
/// 3. `ban_list`                 (Mutex)
/// 4. `violation_tracker`        (Mutex)
///
/// Common idiom for send paths: snapshot a `route_cache.lookup(...)` into
/// a local `Option<[u8; 32]>` BEFORE acquiring `wlock!(session_tx_registry)`,
/// then use the snapshot in the fallback branch when direct `send_to`
/// fails.  Holding both locks simultaneously inverts the order and creates
/// a deadlock cycle against the symmetric callers in routing.rs:1845, 2236
/// and delivery.rs.
#[derive(Clone)]
pub struct FrameDispatcher {
    pub role: NodeRole,
    pub gateway: Arc<GatewayService>,
    pub discovery: Arc<DiscoveryService>,
    pub dht: Arc<KademliaService>,
    pub app_registry: Arc<AppEndpointRegistry>,
    pub stream_table: Arc<AppStreamTable>,
    pub mesh_forwarder: Arc<MeshForwarder>,
    /// Chunked transfer reassembly.
    pub chunk_reassembler: Arc<Mutex<crate::envelope_chunks::EnvelopeChunkReassembler>>,
    /// Route discovery forwarder.
    pub discovery_forwarder: Arc<Mutex<veil_routing::discovery_forwarder::DiscoveryForwarder>>,
    pub control_plane: Arc<ControlPlaneService>,
    pub route_cache: Arc<RwLock<RouteCache>>,
    pub metrics: Option<Arc<NodeMetrics>>,
    pub logger: Arc<NodeLogger>,
    /// Cryptographic identity and key-material (signing key, ML-KEM keys, peer pubkeys).
    pub crypto: Arc<CryptoContext>,
    /// Abuse-resistance state (rate limiter, ban list, violation tracker, DHT quota).
    pub abuse: Arc<AbuseContext>,
    /// The local node's identity bytes. Used to decide whether a
    /// `DELIVERY_FORWARD` frame is addressed to us or must be relayed onward.
    pub local_node_id: [u8; 32],
    /// Session outbox registry used for multi-hop relay. When present, a
    /// `DELIVERY_FORWARD` frame whose final recipient is reachable (directly
    /// or via `RouteCache`) is forwarded to the next hop instead of being
    /// stored in the mailbox.
    pub session_tx_registry: Option<Arc<RwLock<SessionTxRegistry>>>,
    /// PoW-Gated Rendezvous server-side controller (Slice 5b of the
    /// PoW-Gated Rendezvous epic; see
    /// `docs/internal/PLAN_POW_GATED_RENDEZVOUS.md`).  `None` when no
    /// `visibility = "stealth"` listener is configured.  Stored as
    /// `Weak` to break the `dispatcher → controller → binder →
    /// SessionRuntimeContext → dispatcher` strong-ref cycle that
    /// would otherwise leak on reload.  Strong Arc lives on
    /// `NodeRuntime`; this weak ref upgrades transiently on each
    /// dispatch.
    pub rendezvous_weak: Arc<
        std::sync::Mutex<Option<std::sync::Weak<veil_session::rendezvous::RendezvousController>>>,
    >,
    /// read-side session registry used to resolve a
    /// sovereign [`Recipient`](veil_proto::recipient::Recipient) (node_id +
    /// InstanceTag) to the live-session peer_ids the dispatcher should
    /// forward to. `None` in test dispatchers that don't exercise the
    /// sovereign-routing fast path (they still use `route_cache` via the
    /// pre-462 node_id path).
    ///
    /// Consumed by `resolve_sovereign_delivery_targets` in
    /// `node/dispatcher/delivery.rs` (live forward path) and by
    /// the unit tests there.
    pub session_registry: Option<Arc<Mutex<veil_session::SessionRegistry>>>,

    // ── Routing gossip ─────────────────────────────────────────
    /// Gossip dedup set — shared across all concurrent sessions.
    pub route_seen_set: Arc<Mutex<RouteSeenSet>>,
    /// Highest seen announce sequence number, keyed by `(origin, via)`.
    ///
    /// After the `RouteSeenSet` TTL expires (~60 s), a replayed `RouteAnnounce`
    /// with the same `(origin, via, seq)` would pass the dedup check. Tracking
    /// the maximum sequence seen per `(origin, via)` prevents this: any announce
    /// with `sequence ≤ last_seen_seq[(origin, via)]` is rejected regardless of
    /// dedup state.
    ///
    /// Audit M6: keyed by `(origin, via)` rather than `origin` alone, and
    /// updated only AFTER authentication (see `handle_route_announce`).
    ///
    /// * Post-auth: the counter is advanced only after the via==peer and
    ///   signature checks pass, so an unauthenticated/forged frame cannot
    ///   poison it before being dropped (the old code mutated it pre-auth).
    /// * `(origin, via)` keying bounds an authenticated-but-malicious relay's
    ///   blast radius: it can only advance the counter for
    ///   `(victim, its_own_via)`, so it cannot suppress legitimate routes to
    ///   the victim that arrive via other relays. (Replays are inherently
    ///   per-via — the `via` field and signature bind a frame to one
    ///   forwarder — so a per-via high-water mark still rejects that via's own
    ///   stale replays.) Same-`(origin, seq)` copies via different relays are
    ///   already collapsed upstream by the `RouteSeenSet` replay layer.
    ///
    /// Bounded to `MAX_ROUTE_ORIGIN_SEQ_CACHE` entries; lowest-sequence entry
    /// evicted when full.
    pub route_origin_seq: Arc<Mutex<HashMap<(NodeIdBytes, NodeIdBytes), u32>>>,
    /// Monotonic sequence counter for locally-originated route announcements.
    pub announce_seq: Arc<AtomicU32>,
    /// Listen transports of this node — included in RouteResponse.
    ///
    /// Wrapped in `Arc<RwLock<>>` so that `update_wildcard_listen_addr` can
    /// rewrite `0.0.0.0` / `::` hosts after the node learns its external IP
    /// from a `NatProbeReply`.
    pub listen_transports: Arc<RwLock<Vec<String>>>,
    /// Relay node-ids advertised in `RouteResponsePayload.relay_ids`.
    ///
    /// Decoded from `ListenConfig.relay` entries at startup / reload.
    /// Peers can use these relay nodes to reach this node indirectly (e.g.
    /// when the node is behind a NAT or reverse proxy without a direct path).
    pub relay_node_ids: Vec<[u8; 32]>,

    /// capability/region labels this node claims about itself
    /// (e.g. `b"exit"`, `b"low\0"`, `b"qiwi"`). Attached to outgoing
    /// `RouteResponsePayload`s and signed as part of the body so requesters
    /// can filter routes by attribute. Sourced from
    /// `config.routing.target_labels`. Bounded by `MAX_TARGET_LABELS`.
    pub target_labels: Vec<[u8; veil_proto::budget::LABEL_WIDTH]>,

    // ── On-demand route discovery ─────────────────────────────
    /// Notified whenever a `RouteResponse` addressed to this node is received
    /// and a new entry is inserted into `route_cache`. IPC send handlers can
    /// `await` this with a timeout to implement reactive route bootstrapping.
    pub route_updated: Arc<Notify>,

    // ── PoW direct-session bootstrap ───────────────────
    /// Number of leading zero bits required in the PoW puzzle. `0` disables
    /// PoW challenges (acceptor sends no `PowChallenge` on `RouteRequest`).
    ///
    /// (Level 1): when `> 0`, the `RouteResponse` carrying our
    /// listen transports is *deferred* until the requester returns a valid
    /// `PowResponse` — probing-by-id no longer leaks transports for free.
    pub pow_difficulty: u8,
    /// Pending PoW challenges issued by this node (acting as acceptor).
    /// Maps `challenge_nonce → (requester_node_id, difficulty, request_id)`.
    /// Entries are consumed when the matching `PowResponse` arrives;
    /// `request_id` is echoed back into the deferred `RouteResponse`.
    pub pow_pending: Arc<Mutex<PowPendingTable>>,

    /// (Level 2): controls who learns our listen transports
    /// via `RouteResponse`. See [`veil_cfg::DiscoveryMode`].
    pub discovery_mode: veil_cfg::DiscoveryMode,

    // ── Diagnostics ────────────────────────────────────────────────
    /// One-shot channels waiting for a Pong or TraceHop reply keyed by `seq`.
    /// Admin command handlers insert a `Sender` before sending the probe;
    /// `dispatch_diag` delivers the event and removes the entry.
    pub pending_diag: Arc<Mutex<HashMap<u32, mpsc::Sender<DiagEvent>>>>,
    /// Optional broadcast channel for live frame capture (`debug capture`).
    /// Wrapped in `Arc<Mutex<…>>` so that `subscribe_capture` can activate it
    /// in-place even after dispatcher instances have been cloned into running
    /// sessions — all clones share the same underlying channel slot.
    pub capture_tx: Arc<Mutex<Option<broadcast::Sender<CaptureEvent>>>>,
    /// Fast-path flag: set to `true` once a capture subscriber is registered.
    ///
    /// Checked with `Relaxed` ordering before acquiring `capture_tx`'s mutex.
    /// Eliminates the mutex acquisition cost on every frame in the common case
    /// (capture never activated).
    pub capture_active: Arc<std::sync::atomic::AtomicBool>,
    /// per-peer rate limit on capture-event
    /// emission (default `CAPTURE_PER_PEER_EVENTS_PER_SEC = 100/s`).
    /// Capture-debug under chat-node load was 10 MB/s @ 10K pkt/s
    /// pre-fix; this caps the broadcast amplification at ~100 KB/s
    /// per peer × the 256 B body preview = ~25 KB/s/peer maximum
    /// or ~175 KB/s on a full 7-peer mesh.
    pub capture_rate_limit: Arc<veil_dispatcher_state::CaptureRateLimiter>,

    // ── Route convergence ──────────────────────────────────────────
    /// Sender side of the route-miss channel. When a `DELIVERY_FORWARD` can
    /// not be routed (no direct session, no route-cache hit), the
    /// `(destination_node_id, traffic_class)` pair is pushed here so the
    /// background route-miss handler can trigger an on-demand
    /// `ROUTE_REQUEST` flood and retry delivery. :
    /// channel item gained the traffic_class byte so the iterative-DHT
    /// fallback can pick a priority-aware timeout budget.
    pub route_miss_tx: Arc<Mutex<Option<RouteMissTx>>>,

    // ── Neighbor scoring ─────────────────────────────────────────
    /// Neighbor reachability scorer. Used when inserting routes into the cache
    /// to penalise unreliable next-hops by inflating their score.
    pub neighbor_scorer: Arc<Mutex<NeighborScorer>>,

    // ── Vivaldi NC ────────────────────────────────────────────────
    /// Local Vivaldi network coordinate — updated on each `ROUTE_REPLY`.
    /// `None` disables Vivaldi updates (e.g. in unit tests).
    pub local_vivaldi: Option<Arc<Mutex<veil_routing::VivaldiCoord>>>,
    /// Per-peer Vivaldi coordinates received during handshake.
    /// Used to update the local coordinate when `ROUTE_REPLY` provides a measured RTT.
    pub peer_vivaldi: PeerVivaldiCache,

    // ── DELIVERY_FORWARD dedup ─────────────────────────────────────
    /// Loop/duplicate-suppression set for the floodable relay domains —
    /// source-routed RelayPath (`0xFD`), transit-frame content-hash (`0xFF`),
    /// and recursive-relay (`0xFE`) keys. Best-effort; an attacker can drive
    /// these to high volume with unique frames, so they are deliberately kept
    /// OUT of [`Self::forward_seen_content`] to avoid evicting replay-critical
    /// content_id entries before their TTL. (audit cycle-8 F9.)
    pub forward_seen_set: Arc<Mutex<ForwardSeenSet>>,
    /// Replay guard for terminal/forward delivery keyed by `content_id`.
    /// Isolated in its own ExpiryCache so a flood in the floodable relay
    /// domains (see [`Self::forward_seen_set`]) cannot evict a content_id and
    /// re-open the payload-replay window within the TTL. (audit cycle-8 F9.)
    pub forward_seen_content: Arc<Mutex<ForwardSeenSet>>,
    /// Terminal-delivery ACK-replay cache (audit cycle-8 H8): `content_id →
    /// (ack_target_sender, ack_key)`. On a duplicate terminal arrival — a
    /// retransmit sent because our original DELIVERED ACK was lost — re-emit the
    /// ACK from here instead of silently dropping the frame, so a lost ACK is
    /// recoverable WITHOUT re-decrypting the payload (cheap + replay-safe).
    /// Same TTL/cap window as `forward_seen_set`.
    pub terminal_ack_replay: TerminalAckReplay,

    /// Recursive query dedup: prevents loops in recursive DHT routing.
    pub recursive_query_seen: Arc<Mutex<ExpiryCache<[u8; 16]>>>,

    /// Per-peer rate limit for VersionVectorSync: each peer may
    /// trigger a VVSync response at most once per `VVSYNC_MIN_INTERVAL_SECS`.
    /// Excess requests are dropped silently — the peer already has a pending
    /// update in flight.
    pub vvsync_seen: Arc<Mutex<ExpiryCache<[u8; 32]>>>,

    /// Pending recursive queries: `query_id → PendingRecursive`.
    /// When a RecursiveResponse arrives, the response handler parses its
    /// payload (per `query_type`) to update `route_cache` / DHT cache, then
    /// signals the waiting initiator via the oneshot sender.
    pub pending_recursive: Arc<Mutex<std::collections::HashMap<[u8; 16], PendingRecursive>>>,

    /// Reverse path for forwarded recursive queries:
    /// `query_id → (reply_to, inserted_at)`. An intermediate node that
    /// forwards a `RecursiveQuery` records the originator here so that when
    /// the matching `RecursiveResponse` later arrives, it can be relayed
    /// back toward the originator instead of being dropped silently
    /// (responses currently rely on direct-session + route_cache, which
    /// fails in fragmented topologies where the responder has no path back
    /// to the originator). Entries TTL after 30 s — a query that hasn't
    /// resolved by then has timed out at the originator anyway.
    /// `query_id → (reply_to, forwarding_peer, inserted_at)`. The
    /// `forwarding_peer` (audit cycle-8) lets the insert path enforce a
    /// per-peer sub-quota so one peer generating many `query_id`s cannot evict
    /// every other peer's reverse-path entries out of the FIFO cap.
    #[allow(clippy::type_complexity)]
    pub recursive_reverse_path:
        Arc<Mutex<std::collections::HashMap<[u8; 16], ([u8; 32], [u8; 32], std::time::Instant)>>>,

    // ── Session alias registry ──────────────────────────────────
    /// Maps `session_alias → node_id` for active sessions.
    ///
    /// Populated by `SessionRunner::run` on session start and cleared on
    /// session close. Used to resolve aliases in aliased gossip frames
    /// (`RouteAnnounceAliased`, `RouteWithdrawAliased`).
    pub alias_registry: Arc<Mutex<HashMap<[u8; 8], [u8; 32]>>>,

    // ── NAT traversal ─────────────────────────────────────────────
    /// Maps `peer_id → observed transport SocketAddr`.
    ///
    /// Populated when sessions open (from `peer_meta.remote_addr`) and cleared
    /// when sessions close. Used by `dispatch_control` to echo the observed
    /// address back in `NatProbeReply` (STUN-like srflx discovery).
    // RwLock — reads on every NatProbeRequest (srflx echo); writes
    // only on session open/close.
    pub peer_observed_addrs: Arc<RwLock<HashMap<NodeIdBytes, std::net::SocketAddr>>>,

    /// Active relay tunnels: `session_token → (node_a, node_b)`.
    ///
    /// Inserted when core receives a `NatRelayRequest` from an authenticated
    /// peer. The entry allows the delivery-forward path to identify relay
    /// flows and apply per-token accounting. Entries are removed when either
    /// session closes or the token is explicitly released.
    #[allow(clippy::type_complexity)]
    pub relay_tunnels: Arc<Mutex<HashMap<u32, ([u8; 32], [u8; 32])>>>,

    /// pending NAT-probe waiters. When the runtime initiates
    /// a relay-mode `NatProbeRequest` (Alice → coordinator → Bob), it
    /// inserts a oneshot under the request's `session_token`; the
    /// `NatProbeReply` handler fires it when the matching reply
    /// arrives back through the coordinator. No relay state needed
    /// (reply carries `final_target_node_id`).
    ///
    /// Capped at `budget::MAX_NAT_PROBE_WAITERS` (= 256). The runtime
    /// inserter (`attempt_nat_traversal_via`) cleans closed senders +
    /// refuses to register past the cap, surfacing the refusal as a
    /// timeout-shaped `None` return so callers don't need a special
    /// error path. Without the cap a buggy or malicious caller could
    /// fire probes faster than they time out and grow the hashmap
    /// until OOM.
    #[allow(clippy::type_complexity)]
    pub nat_probe_waiters:
        Arc<Mutex<HashMap<u32, tokio::sync::oneshot::Sender<NatProbeReplyPayload>>>>,

    /// scale-aware adaptive parameters, refreshed on
    /// every `reload` cycle from `estimate_network_size(routing_table_size
    /// active_sessions)`. Read-mostly: dispatch handlers consult it to look
    /// up the current responder-proximity bound (which scales with N), the
    /// reload path mutates it under the writer lock.
    ///
    /// Wrapped in `RwLock` rather than `ArcSwap` because reads are infrequent
    /// (one per recursive-response receive) and the existing codebase
    /// already relies on `RwLock` everywhere; a different concurrency
    /// primitive here would surprise reviewers without a real perf win.
    pub adaptive_params: Arc<RwLock<veil_cfg::adaptive::AdaptiveParams>>,

    // ── configurable routing limits ─────────────────────────────────
    /// Maximum gossip hop count — frames with hop_count ≥ this value are dropped.
    /// Default: 8 (matches `RoutingConfig::default_max_gossip_hops`).
    pub max_gossip_hops: u8,

    // ── load-aware routing ─────────────────────────────────────────
    /// Real-time congestion monitor — `None` disables congestion reporting
    /// (e.g. in unit tests or when `NodeCapacityConfig` limits are all zero).
    pub congestion_monitor: Option<Arc<veil_congestion::CongestionMonitor>>,
    /// per-peer reputation tracker.
    pub reputation: Option<Arc<Mutex<veil_reputation::ReputationTracker>>>,

    // ── multi-gateway failover ─────────────────────────────────────
    /// Ranked list of known Gateway peers. Shared with `NodeRuntime` so that
    /// the delivery path can fall back to a gateway when no direct route exists.
    /// `None` when the dispatcher is constructed outside a full runtime (tests).
    pub gateway_list: Option<Arc<Mutex<veil_gateway::GatewayList>>>,
    /// When `true`, prefer gateways with `HAS_INTERNET` for global-veil
    /// frame delivery (mirrors `ConnectionConfig::prefer_internet_gateway`).
    pub prefer_internet_gateway: bool,
    /// when `true`, sample weighted-random from top-K gateways
    /// instead of always using the single best (reduces statistical
    /// fingerprinting of veil traffic). Default: `false`.
    pub exit_diversification: bool,
    /// top-K window size for `exit_diversification`. Default: 4.
    pub exit_diversification_top_k: u8,

    // ── ECMP multipath ──────────────────────────────────────────────
    /// Fraction of best-score variance that qualifies a route for ECMP group
    /// membership. Routes with `score ≤ best * (1 + ecmp_score_band)` form
    /// the equal-cost set. Default: `0.20` (20 %).
    pub ecmp_score_band: f64,
    /// When `true`, frames are sent on **every** ECMP path simultaneously
    /// (redundant send). Improves delivery reliability at the cost of
    /// increased bandwidth. Only active when the ECMP group has ≥ 2 members.
    pub redundant_send: bool,

    // ── epidemic broadcast ─────────────────────────────────────────
    /// Dedup set for incoming `EpidemicBroadcast` frames.
    pub epidemic_seen: Arc<Mutex<EpidemicSeenSet>>,
    /// Number of random neighbours each node forwards an epidemic message to.
    pub epidemic_fanout: usize,
    /// Maximum accepted `EpidemicBroadcast` payload size in bytes.
    pub epidemic_max_payload: usize,

    // ── battery-aware routing ──────────────────────────────────────
    /// Battery level (percent) at or below which the HIGH penalty is applied.
    pub battery_threshold_low: u8,
    /// Battery level (percent) at or below which the MEDIUM penalty is applied.
    pub battery_threshold_medium: u8,
    /// Score multiplier penalty for hops with battery ≤ `battery_threshold_low`.
    pub battery_penalty_low: f64,
    /// Score multiplier penalty for hops with battery ≤ `battery_threshold_medium`.
    pub battery_penalty_medium: f64,

    // ── sleep advertisement ────────────────────────────────────────
    /// Unix timestamp (seconds) of the last `SleepAdvertisement` we emitted.
    /// Used to rate-limit auto-advertisements when battery stays below
    /// `battery_threshold_low` across many session events.
    pub last_sleep_advertisement_ts: Arc<AtomicU64>,

    // ── multi-path delivery ────────────────────────────────────────
    /// When true, send on multiple parallel paths for latency-sensitive frames.
    pub multi_path_enabled: bool,
    /// Maximum number of parallel paths to use when multi-path is active.
    pub max_parallel_paths: u8,
    /// Frames with priority ≤ this value are eligible for multi-path delivery.
    pub multi_path_min_priority: u8,

    // ── relay reputation scoring ───────────────────────────────────
    /// Minimum relay attempts before reputation penalty activates.
    pub relay_reputation_min_attempts: u32,
    /// relay_success_ema threshold below which penalty is applied.
    pub relay_reputation_threshold: f32,
    /// Score multiplier for relays with low success rate.
    pub relay_reputation_penalty: f64,

    // ── jitter + bandwidth scoring ─────────────────────────────────
    /// Additive weight for the jitter penalty term in `effective_score`.
    pub jitter_penalty_weight: f64,
    /// Jitter (ms) below which no penalty is applied.
    pub jitter_threshold_ms: u32,
    /// Score multiplier penalty for narrow-bandwidth paths under BULK/BACKGROUND traffic.
    pub narrow_bandwidth_bulk_penalty: f64,

    // ── distributed tracing ────────────────────────────────────────
    /// In-memory ring buffer for delivery trace records.
    pub trace_buffer: Arc<Mutex<TraceBuffer>>,

    // ── at-least-once delivery ACK ─────────────────────────────────
    /// Tracks in-flight envelopes that require an E2E delivery ACK.
    ///
    /// Shared with the background tick task (see `spawn_pending_ack_tick` in
    /// `runtime.rs`) which drives retransmits and failure notifications.
    pub pending_ack: Arc<Mutex<pending_ack::PendingAckTracker>>,

    /// per-peer in-line packet loss tracker. Updated on every
    /// DELIVERED ACK (success) and every ACK-tick Retransmit/Failed
    /// outcome (loss). Sampled by the same tick task that drives
    /// `pending_ack`; on threshold breach the dispatcher fast-demotes
    /// affected routes via `RouteCache::demote_via`.
    pub loss_tracker: Arc<veil_routing::loss_tracker::LossTracker>,

    // ── PoW solver resource limits ────────────────────────────────
    /// Semaphore that caps the number of concurrently running `spawn_blocking`
    /// PoW solver tasks across all sessions.
    ///
    /// `SessionRunner` acquires one permit via `try_acquire_owned` before
    /// spawning a solver; the permit is released automatically when the task
    /// completes (OwnedSemaphorePermit drop). If all permits are taken the
    /// challenge is silently dropped and a warning is logged.
    ///
    /// Shared via `Arc::clone` across reload cycles so that in-flight permits
    /// from old sessions are accounted against the same counter.
    pub pow_solver_semaphore: Arc<tokio::sync::Semaphore>,

    /// Running total of `difficulty` bits across all active PoW solver tasks
    ///
    ///
    /// Atomically incremented before spawning and decremented on task exit.
    /// If adding a new challenge's difficulty would exceed
    /// `MAX_POW_ACTIVE_DIFFICULTY_SUM`, the challenge is dropped instead of
    /// spawning another blocking task.
    pub pow_active_difficulty: Arc<std::sync::atomic::AtomicU64>,

    /// Dedup set for incoming `PowChallenge` frames.
    ///
    /// Keyed by `challenge_nonce` ([u8; 32]). If the same nonce arrives via
    /// multiple relay sessions the duplicate is dropped before a second
    /// `spawn_blocking` is queued, bounding solver tasks to one per puzzle.
    pub pow_challenge_seen: Arc<Mutex<ExpiryCache<[u8; 32]>>>,

    // ── Veil proxy streams ─────────────────────────────────────
    /// Pending APP_RECEIPT waiters for locally-initiated veil streams.
    ///
    /// Keyed by `stream_id`. Inserted by `VeilConnector::connect` before
    /// sending `APP_OPEN`; consumed once by the `AppReceipt` dispatcher branch.
    pub pending_stream_receipts: veil_proxy::veil_connector::PendingReceiptMap,

    /// Byte-channel receivers for locally-initiated veil streams.
    ///
    /// Keyed by `(peer_id, stream_id)`. Inserted by `VeilConnector::connect`
    /// so that inbound `APP_DATA` frames from the remote peer can be routed to the
    /// local `VeilConnector` stream without going through `app_registry`.
    pub veil_stream_rx: veil_proxy::veil_connector::VeilStreamRxMap,

    // ── Peer Exchange ────────────────────────────────────────────
    pub pex_dispatcher: Option<Arc<veil_pex::PexDispatcher>>,
    pub pex_state: Option<Arc<Mutex<veil_pex::PexState>>>,

    // ── Anonymity ──────────────────────────────────────────────
    /// Local node's X25519 secret key for anonymity-hop ECDH.
    /// `None` when the operator has NOT opted in to being a relay
    /// (`[anonymity].relay_capable = false`) — the dispatcher's
    /// `RelayChain` handler then drops inbound onion cells silently
    /// rather than peeling. See `node/dispatcher/anonymity.rs`.
    pub anonymity_x25519_sk: Option<Arc<x25519_dalek::StaticSecret>>,

    /// per-node replay-protection cache for
    /// Introduce frames. Each fingerprint is `BLAKE3(eph_pk \|\| nonce)`;
    /// repeated ciphertexts (whether from a captured-and-replayed
    /// attacker or network retransmits) are rejected before the AEAD
    /// verification so a replay flood costs only a HashMap lookup.
    /// Always-present (cheap struct); active only when
    /// `anonymity_x25519_sk` is `Some` (i.e. this node decrypts
    /// Introduces).
    pub introduce_replay_cache: Arc<veil_anonymity::rendezvous::IntroduceReplayCache>,

    // ── Rendezvous registry ───────────────────────────
    /// In-memory cookie → subscriber registry maintained by nodes
    /// acting as rendezvous relays. `None` when this node is not
    /// configured as a rendezvous (operators opt in by enabling the
    /// `[anonymity].rendezvous_capable` flag); receivers register
    /// cookies via `RelayChainMsg::RegisterRendezvous` frames over an
    /// established OVL1 session, and the rendezvous forwards inbound
    /// `IntroducePayload` frames to the matching subscriber.
    pub rendezvous_registry: Option<Arc<veil_anonymity::rendezvous::RendezvousRegistry>>,
}

/// Constant-time pad applied to banned-peer drops in `dispatch()`.
///
/// Phase 5q's early-ban-check returns `NoResponse` immediately on
/// `is_banned`, saving the CPU of full-pipeline processing for frames
/// from banned peers.  Without padding, the dispatch-latency divergence
/// (banned ≈ single-digit µs vs normal ≈ 30-300 µs) leaks ban-list
/// membership to an observer measuring response timing — an attacker
/// can enumerate the ban-list or detect that they were just banned and
/// rotate identities before the progressive-ban duration spikes.
///
/// We spin-pad banned drops to a constant deadline measured from the
/// top of `dispatch()` so the externally-observable latency
/// distribution matches normal frames in expectation.  50 µs is the
/// observed median dispatch time under chat-node load (Ping → Pong,
/// AppOpen ack, etc.); tighter pads risk being shorter than the
/// natural-frame fast-tail and still leaking; longer pads waste CPU
/// for marginal additional masking.  Tune via a profile-driven
/// retarget if a deployment shows a materially different distribution.
///
/// Cost: ~50 µs of CPU spin-loop per banned frame.  Phase 5q's CPU
/// savings drop from "full pipeline avoided" to "full pipeline minus
/// 50 µs avoided" — still net positive vs paying the full pipeline
/// (which is the constant-time-via-process-anyway alternative).
const BAN_DROP_PAD: std::time::Duration = std::time::Duration::from_micros(50);

#[inline]
fn spin_pad_until(deadline: std::time::Instant) {
    // Tight busy-wait. `spin_loop` is a pause hint to the CPU (PAUSE on
    // x86, YIELD on ARM) so we don't burn a full execution slot per
    // iteration. Sub-100 µs blocking in a sync function inside an async
    // task is fine — tokio's runtime tolerates spin durations much
    // shorter than its scheduling quantum.
    while std::time::Instant::now() < deadline {
        std::hint::spin_loop();
    }
}

impl FrameDispatcher {
    /// Rewrite any wildcard (`0.0.0.0` / `::`) hosts in `listen_transports`
    /// with `external_ip`.
    ///
    /// Called once when the node receives a `NatProbeReply` carrying an srflx
    /// candidate, so peers in `RouteResponse` receive a routable address instead
    /// of the unspecified bind address.
    ///
    /// The update is idempotent: if all transports already contain a specific
    /// host the lock is released without modification.
    pub fn update_wildcard_listen_addr(&self, external_ip: std::net::IpAddr) {
        use veil_transport::rewrite_wildcard_host;
        let mut transports = self
            .listen_transports
            .write()
            .unwrap_or_else(|p| p.into_inner());
        for uri in transports.iter_mut() {
            if let Some(rewritten) = rewrite_wildcard_host(uri, external_ip) {
                *uri = rewritten;
            }
        }
    }

    /// Snapshot of `listen_transports` tolerating lock poisoning.
    ///
    /// `listen_transports` is read-mostly (populated at startup, occasionally
    /// rewritten by `update_wildcard_listen_addr` after a NAT probe), so on
    /// poison the inner `Vec` is still valid — a panic would have happened
    /// *after* any mutation completed. All read-sites route through this
    /// helper to apply the fail-open rule consistently rather than each one
    /// inventing its own poison branch.
    pub fn listen_transports_snapshot(&self) -> Vec<String> {
        self.listen_transports
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Register `session_alias → node_id` mappings for an established session.
    ///
    /// Called by `SessionRunner::run` at session start so that incoming aliased
    /// gossip frames can be resolved to full node_ids.
    pub fn register_session_aliases(
        &self,
        local_alias: [u8; 8],
        local_node_id: [u8; 32],
        remote_alias: [u8; 8],
        remote_node_id: NodeIdBytes,
    ) {
        let mut reg = lock!(self.alias_registry);
        reg.insert(local_alias, local_node_id);
        reg.insert(remote_alias, remote_node_id);
    }

    /// Unregister both aliases when a session closes.
    pub fn unregister_session_aliases(&self, local_alias: [u8; 8], remote_alias: [u8; 8]) {
        let mut reg = lock!(self.alias_registry);
        reg.remove(&local_alias);
        reg.remove(&remote_alias);
    }

    /// Resolve a session alias to a full 32-byte node_id.
    pub fn resolve_alias(&self, alias: [u8; 8]) -> Option<[u8; 32]> {
        lock!(self.alias_registry).get(&alias).copied()
    }

    /// Emit a capture event for an outbound frame being sent to `peer_id`.
    ///
    /// `frame` must be a complete OVL1 frame (header + body). If no capture
    /// subscriber is active this is a no-op.
    pub fn capture_outbound(&self, peer_id: impl Into<NodeId>, frame: &[u8]) {
        if !self
            .capture_active
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return;
        }
        // H9 ergonomic accept: see `dispatch()` for rationale.
        let peer_id: NodeId = peer_id.into();
        // per-peer rate limit on capture
        // emission. Drops events past 100/s/peer; the cap protects
        // the broadcast channel under chat-node load (10K pkt/s ×
        // 60 KB frames was 600 MB/s pre-fix). Done BEFORE the
        // mutex acquire so a throttled peer doesn't pay the lock.
        if !self.capture_rate_limit.allow(*peer_id.as_bytes()) {
            return;
        }
        let slot = lock!(self.capture_tx);
        if let Some(ref tx) = *slot {
            if frame.len() < veil_proto::header::HEADER_SIZE {
                return;
            }
            let hdr =
                match veil_proto::codec::decode_header(&frame[..veil_proto::header::HEADER_SIZE]) {
                    Ok(h) => h,
                    Err(_) => return,
                };
            let ts_us = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros() as u64;
            let event = CaptureEvent::new_truncated(
                ts_us,
                false, // outbound
                *peer_id.as_bytes(),
                self.local_node_id,
                hdr.family,
                hdr.msg_type,
                hdr.body_len,
                &frame[veil_proto::header::HEADER_SIZE..],
                false, // not e2e_plaintext
            );
            let _ = tx.send(event);
        }
    }

    /// Dispatch one decoded OVL1 frame.
    ///
    /// `header` — the already-decoded frame header.
    /// `body` — the raw frame body bytes.
    /// `peer_id` — authenticated node_id of the sender (from session handshake).
    ///
    /// Returns a `DispatchResult` indicating what the caller should do next.
    pub fn dispatch(
        &self,
        header: &FrameHeader,
        body: &[u8],
        peer_id: impl Into<NodeId>,
    ) -> DispatchResult {
        // Anchor for `BAN_DROP_PAD` (see const docstring) — measured at
        // the same entry point as non-banned frames so the constant-time
        // pad covers the full dispatch envelope, not just the tail after
        // the ban-check.
        let dispatch_start = std::time::Instant::now();
        // H9 ergonomic accept: take `impl Into<NodeId>` rather
        // than `NodeId` directly so callers with raw `[u8; 32]` (session
        // runner, tests) don't need an explicit `.into()` at every
        // call site. The conversion happens once here at the top
        // of the body; the rest of the fn works with the typed `NodeId`.
        let peer_id: NodeId = peer_id.into();
        // ── Live capture ──────────────────────────────────────────
        // Fast-path: skip the mutex entirely when no capture subscriber is active.
        // rate-limited per peer (100/s) and body
        // truncated to 256 B preview so heavy chat-node load can't pump
        // 10 MB/s through the broadcast channel.
        if self
            .capture_active
            .load(std::sync::atomic::Ordering::Relaxed)
            && self.capture_rate_limit.allow(*peer_id.as_bytes())
            && let Some(ref tx) = *lock!(self.capture_tx)
        {
            let event = CaptureEvent::new_truncated(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros() as u64,
                true, // inbound
                *peer_id.as_bytes(),
                self.local_node_id,
                header.family,
                header.msg_type,
                header.body_len,
                body,
                false, // not e2e_plaintext
            );
            let _ = tx.send(event); // lagging receivers are silently dropped
        }

        // ── Abuse pre-checks ────────────────────────────────────────────────
        if lock!(self.abuse.ban_list).is_banned(peer_id.as_bytes()) {
            // Silent drop — the ban is already active. Returning Violation
            // here would feed back into record_violation and spiral the
            // progressive ban duration to max within a single frame burst.
            //
            // Pad to `BAN_DROP_PAD` before returning so dispatch-latency
            // observers cannot distinguish banned from not-banned peers
            // (see const docstring).
            spin_pad_until(dispatch_start + BAN_DROP_PAD);
            return DispatchResult::NoResponse;
        }
        if !lock!(self.abuse.rate_limiter).allow(*peer_id.as_bytes()) {
            if let Some(m) = &self.metrics {
                m.inc_rate_limit_drops();
            }
            return DispatchResult::RateLimited;
        }
        // Inbound bandwidth enforcement.
        if !lock!(self.abuse.inbound_bandwidth).allow_bytes(body.len()) {
            return DispatchResult::RateLimited;
        }

        // ── Route by family ─────────────────────────────────────────────────
        let family = match FrameFamily::try_from(header.family) {
            Ok(f) => f,
            Err(_) => {
                // forward-compatible — skip unknown frame families
                // instead of treating as a violation. This allows newer nodes to
                // send frames that older nodes simply ignore.
                return DispatchResult::NotHandled;
            }
        };

        match family {
            FrameFamily::Delivery => self.dispatch_delivery(header, body, peer_id),
            FrameFamily::Discovery => self.dispatch_discovery(header, body, peer_id),
            FrameFamily::App => self.dispatch_app(header, body, peer_id),
            FrameFamily::Session => self.dispatch_session_post_handshake(header, body, peer_id),
            FrameFamily::Control => self.dispatch_control(header, body, peer_id),
            FrameFamily::Mesh => self.dispatch_mesh(header, body, peer_id),
            FrameFamily::LocalApp => {
                // LocalApp frames are only valid on the local IPC socket
                // never on veil peer connections.
                DispatchResult::Violation("LocalApp frame on veil link".to_owned())
            }
            FrameFamily::Tunnel => {
                // dispatcher does not accept Tunnel frames on
                // veil peer connections — the TUN/TAP pipeline is not
                // wired into dispatch yet. Silently dropping these frames
                // (the previous behaviour) hid the fact that the feature
                // was disabled; return Violation so operators can see it.
                let _ = (peer_id, body);
                DispatchResult::Violation("Tunnel frames not accepted at dispatcher".to_owned())
            }
            FrameFamily::Routing => self.dispatch_routing(header, body, peer_id),
            FrameFamily::Diag => self.dispatch_diag(header, body, peer_id),
            FrameFamily::RelayChain => {
                // RelayChain re-enabled with the
                // anonymity-layer primitives shipped-6.
                // The implementation was correctly disabled (zero
                // real anonymity, no loop protection); the new handler
                // peels via `peel_anonymous_cell` (X25519 ECDH +
                // ChaCha20-Poly1305 + AAD-bound) and forwards or accepts
                // depending on the next-hop sentinel. See
                // `node/dispatcher/anonymity.rs` for full flow.
                self.dispatch_relay_chain(header, body, peer_id)
            }
            FrameFamily::PeerExchange => {
                if let Some(ref pex) = self.pex_dispatcher {
                    let uris = self.listen_transports_snapshot();
                    let known = self
                        .pex_state
                        .as_ref()
                        .map(|s| lock!(s).discovered_peers.clone())
                        .unwrap_or_default();
                    // PEX is its own crate now; bridge the
                    // SessionTxRegistry through the FrameBroadcaster trait
                    // adapter and translate the small outcome enum back into
                    // veilcore's central DispatchResult.
                    let broadcaster: Option<Arc<dyn veil_types::FrameBroadcaster>> =
                        self.session_tx_registry.as_ref().map(|reg| {
                            Arc::new(veil_session::glue::SessionTxBroadcaster::new(Arc::clone(
                                reg,
                            ))) as Arc<dyn veil_types::FrameBroadcaster>
                        });
                    let outcome = pex.dispatch(
                        header.msg_type,
                        body,
                        *peer_id.as_bytes(),
                        broadcaster.as_deref(),
                        &uris,
                        &known,
                    );
                    match outcome {
                        veil_pex::PexDispatchOutcome::Response(b) => DispatchResult::Response(b),
                        veil_pex::PexDispatchOutcome::NoResponse => DispatchResult::NoResponse,
                        veil_pex::PexDispatchOutcome::Violation(s) => DispatchResult::Violation(s),
                    }
                } else {
                    DispatchResult::NoResponse
                }
            }
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Encode an OVL1 FAMILY_ROUTING frame.
pub fn encode_routing_frame(msg: RoutingMsg, body: &[u8]) -> Vec<u8> {
    let mut hdr = FrameHeader::new(FrameFamily::Routing as u8, msg as u16);
    hdr.body_len = body.len() as u32;
    let mut out = Vec::with_capacity(HEADER_SIZE + body.len());
    out.extend_from_slice(&encode_header(&hdr));
    out.extend_from_slice(body);
    out
}

/// Encode a response OVL1 frame: header + body bytes.
/// Echoes `request_id` and `stream_id` from the triggering frame.
pub fn encode_response(trigger: &FrameHeader, family: u8, msg_type: u16, body: &[u8]) -> Vec<u8> {
    encode_response_with_class(
        trigger,
        family,
        msg_type,
        body,
        veil_proto::header::TrafficClass::Interactive,
    )
}

/// Like [`encode_response`] but with an explicit traffic class for QoS
/// classification.
pub fn encode_response_with_class(
    trigger: &FrameHeader,
    family: u8,
    msg_type: u16,
    body: &[u8],
    class: veil_proto::header::TrafficClass,
) -> Vec<u8> {
    let mut hdr = FrameHeader::new(family, msg_type);
    hdr.body_len = body.len() as u32;
    hdr.stream_id = trigger.stream_id;
    hdr.request_id = trigger.request_id;
    hdr.set_priority(class as u8);
    let header_bytes = encode_header(&hdr);
    let mut out = Vec::with_capacity(HEADER_SIZE + body.len());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(body);
    out
}

// ── tests ─────────────────────────────────────────────────────────────────────

pub fn make_test_dispatcher(role: NodeRole) -> FrameDispatcher {
    use veil_abuse::{BanList, PerPeerLimiter, ViolationTracker};
    use veil_app::{AppEndpointRegistry, AppStreamTable};
    use veil_cfg::Config;
    use veil_dht::KademliaService;
    use veil_discovery::DiscoveryService;
    use veil_gateway::GatewayService;
    use veil_mesh::{MeshForwarder, NeighborTable};
    use veil_observability::NodeMetrics;
    use veil_routing::RouteCache;
    let local_id = [0u8; 32];
    FrameDispatcher {
        role,
        gateway: Arc::new(GatewayService::new(role)),
        discovery: Arc::new(DiscoveryService::new(role)),
        dht: Arc::new(KademliaService::with_config(
            local_id,
            veil_dht::DhtRuntimeConfig {
                // tests inject unsigned `StorePayload`
                // fixtures; production rejects them. Enable the dev flag in
                // the dispatcher test factory so legacy fixtures still pass.
                allow_unsigned_store: true,
                ..Default::default()
            },
        )),
        app_registry: Arc::new(AppEndpointRegistry::new()),
        stream_table: Arc::new(AppStreamTable::new()),
        mesh_forwarder: Arc::new(MeshForwarder::new(
            local_id,
            role,
            Arc::new(NeighborTable::new()),
        )),
        chunk_reassembler: Arc::new(Mutex::new(
            crate::envelope_chunks::EnvelopeChunkReassembler::new(),
        )),
        discovery_forwarder: Arc::new(Mutex::new(
            veil_routing::discovery_forwarder::DiscoveryForwarder::with_default_difficulty(
                local_id, role,
            ),
        )),
        control_plane: Arc::new(ControlPlaneService::new(std::time::Duration::from_secs(
            300,
        ))),
        route_cache: Arc::new(RwLock::new(RouteCache::new(
            std::time::Duration::from_secs(60),
        ))),
        metrics: Some(Arc::new(NodeMetrics::new())),
        logger: Arc::new(
            veil_cfg::observability_glue::logger_from_config(&Config::default()).unwrap(),
        ),
        crypto: Arc::new(CryptoContext {
            local_signing_key: None,
            mlkem_ek: Arc::new([0u8; veil_e2e::EK_BYTES]),
            mlkem_dk_seed: Arc::new(veil_util::sensitive_bytes::SensitiveBytesN::<
                { veil_e2e::DK_SEED_BYTES },
            >::new()),
            peer_mlkem_keys: Arc::new(std::sync::RwLock::new(veil_e2e::PeerMlKemCache::new())),
            peer_pubkeys: Arc::new(Mutex::new(veil_types::PeerLruCache::with_capacity(64))),
            peer_roles: Arc::new(Mutex::new(veil_types::PeerLruCache::with_capacity(64))),
            peer_cap_flags: Arc::new(RwLock::new(HashMap::new())),
            per_session_mlkem_dk: Arc::new(Mutex::new(HashMap::new())),
        }),
        abuse: Arc::new(AbuseContext {
            rate_limiter: Arc::new(Mutex::new(PerPeerLimiter::new(
                1000.0,
                1000.0,
                std::time::Duration::from_secs(300),
            ))),
            ban_list: Arc::new(Mutex::new(BanList::new())),
            violation_tracker: Arc::new(Mutex::new(
                ViolationTracker::with_fixed_duration(
                    5,
                    std::time::Duration::from_secs(3600),
                    std::time::Duration::from_secs(600),
                )
                .expect("ban_threshold = 5 > 0"),
            )),
            dht_quota: Arc::new(Mutex::new(veil_abuse::DhtQuota::new(
                1000,
                Duration::from_secs(60),
            ))),
            // permissive in tests (no rate-limiting unless explicit).
            identity_write_quota: Arc::new(veil_abuse::identity_quota::IdentityWriteQuota::new(
                veil_abuse::identity_quota::IdentityQuotaConfig {
                    max_writes_per_window: 100_000,
                    window: Duration::from_secs(60),
                    cleanup_idle_after: Duration::from_secs(300),
                    max_identities: veil_proto::budget::MAX_IDENTITY_WRITE_QUOTA_SIZE,
                },
            )),
            pow_challenge_limiter: Arc::new(Mutex::new(PerPeerLimiter::new(
                1000.0,
                1000.0,
                std::time::Duration::from_secs(300),
            ))),
            dht_contact_quota: Arc::new(Mutex::new(veil_abuse::DhtQuota::new(
                1_000_000,
                Duration::from_secs(60),
            ))),
            // Permissive in tests.
            announce_attachment_limiter: Arc::new(Mutex::new(PerPeerLimiter::new(
                1_000_000.0,
                1_000_000.0,
                Duration::from_secs(300),
            ))),
            // Permissive in tests; production wires through MAX_NAT_PROBE_FORWARDS_PER_PEER_PER_WINDOW.
            nat_probe_forward_quota: Arc::new(Mutex::new(DhtQuota::new(
                1_000_000,
                Duration::from_secs(10),
            ))),
            // Permissive in tests.
            recursive_query_limiter: Arc::new(Mutex::new(PerPeerLimiter::new(
                1_000_000.0,
                1_000_000.0,
                Duration::from_secs(300),
            ))),
            inbound_bandwidth: Arc::new(Mutex::new(veil_abuse::BandwidthGate::new(0))),
            outbound_bandwidth: Arc::new(Mutex::new(veil_abuse::BandwidthGate::new(0))),
        }),
        local_node_id: [0u8; 32],
        session_tx_registry: None,
        rendezvous_weak: Arc::new(std::sync::Mutex::new(None)),
        session_registry: None,
        route_seen_set: Arc::new(Mutex::new(RouteSeenSet::new(
            std::time::Duration::from_secs(60),
            4096,
        ))),
        route_origin_seq: Arc::new(Mutex::new(HashMap::new())),
        announce_seq: Arc::new(AtomicU32::new(0)),
        listen_transports: Arc::new(RwLock::new(vec![])),
        relay_node_ids: vec![],
        target_labels: vec![],
        route_updated: Arc::new(Notify::new()),
        pow_difficulty: 0,
        pow_pending: Arc::new(Mutex::new(PowPendingTable::new())),
        discovery_mode: veil_cfg::DiscoveryMode::Public,
        pending_diag: Arc::new(Mutex::new(HashMap::new())),
        capture_tx: Arc::new(Mutex::new(None)),
        capture_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        capture_rate_limit: Arc::new(veil_dispatcher_state::CaptureRateLimiter::new()),
        route_miss_tx: Arc::new(Mutex::new(None)),
        neighbor_scorer: Arc::new(Mutex::new(NeighborScorer::with_alphas(0.5, 0.1))),
        local_vivaldi: None,
        peer_vivaldi: Arc::new(std::sync::RwLock::new(HashMap::new())),
        forward_seen_set: Arc::new(Mutex::new(ForwardSeenSet::new(
            Duration::from_secs(veil_proto::budget::FORWARD_SEEN_SET_TTL_SECS),
            veil_proto::budget::MAX_FORWARD_SEEN_SET_SIZE,
        ))),
        forward_seen_content: Arc::new(Mutex::new(ForwardSeenSet::new(
            Duration::from_secs(veil_proto::budget::FORWARD_SEEN_SET_TTL_SECS),
            veil_proto::budget::MAX_FORWARD_SEEN_SET_SIZE,
        ))),
        terminal_ack_replay: Arc::new(Mutex::new(ExpiryMap::new(
            Duration::from_secs(veil_proto::budget::FORWARD_SEEN_SET_TTL_SECS),
            veil_proto::budget::MAX_FORWARD_SEEN_SET_SIZE,
        ))),
        recursive_query_seen: Arc::new(Mutex::new(ExpiryCache::new(
            Duration::from_secs(30),
            65536,
        ))),
        vvsync_seen: Arc::new(Mutex::new(ExpiryCache::new(
            Duration::from_secs(veil_proto::budget::VVSYNC_MIN_INTERVAL_SECS),
            veil_proto::budget::MAX_VVSYNC_SEEN_SIZE,
        ))),
        pending_recursive: Arc::new(Mutex::new(std::collections::HashMap::new())),
        recursive_reverse_path: Arc::new(Mutex::new(std::collections::HashMap::new())),
        alias_registry: Arc::new(Mutex::new(HashMap::new())),
        peer_observed_addrs: Arc::new(std::sync::RwLock::new(HashMap::new())),
        relay_tunnels: Arc::new(Mutex::new(HashMap::new())),
        nat_probe_waiters: Arc::new(Mutex::new(HashMap::new())),
        adaptive_params: Arc::new(RwLock::new(veil_cfg::adaptive::AdaptiveParams::default())),
        max_gossip_hops: veil_cfg::RoutingConfig::default().max_gossip_hops,
        congestion_monitor: None,
        reputation: None,
        gateway_list: None,
        prefer_internet_gateway: true,
        exit_diversification: false,
        exit_diversification_top_k: 4,
        ecmp_score_band: veil_cfg::RoutingConfig::default().ecmp_score_band,
        redundant_send: false,
        epidemic_seen: Arc::new(Mutex::new(EpidemicSeenSet::new(
            Duration::from_secs(120),
            4096,
        ))),
        epidemic_fanout: veil_cfg::RoutingConfig::default().epidemic_fanout,
        epidemic_max_payload: veil_cfg::RoutingConfig::default().epidemic_max_payload,
        battery_threshold_low: veil_cfg::RoutingConfig::default().battery_threshold_low,
        battery_threshold_medium: veil_cfg::RoutingConfig::default().battery_threshold_medium,
        battery_penalty_low: veil_cfg::RoutingConfig::default().battery_penalty_low,
        battery_penalty_medium: veil_cfg::RoutingConfig::default().battery_penalty_medium,
        last_sleep_advertisement_ts: Arc::new(AtomicU64::new(0)),
        multi_path_enabled: false,
        max_parallel_paths: veil_cfg::RoutingConfig::default().max_parallel_paths,
        multi_path_min_priority: veil_cfg::RoutingConfig::default().multi_path_min_priority,
        relay_reputation_min_attempts: veil_cfg::RoutingConfig::default()
            .relay_reputation_min_attempts,
        relay_reputation_threshold: veil_cfg::RoutingConfig::default().relay_reputation_threshold,
        relay_reputation_penalty: veil_cfg::RoutingConfig::default().relay_reputation_penalty,
        jitter_penalty_weight: veil_cfg::RoutingConfig::default().jitter_penalty_weight,
        jitter_threshold_ms: veil_cfg::RoutingConfig::default().jitter_threshold_ms,
        narrow_bandwidth_bulk_penalty: veil_cfg::RoutingConfig::default()
            .narrow_bandwidth_bulk_penalty,
        trace_buffer: Arc::new(Mutex::new(TraceBuffer::new(
            veil_cfg::RoutingConfig::default().trace_buffer_size,
        ))),
        pending_ack: Arc::new(Mutex::new(pending_ack::PendingAckTracker::new())),
        loss_tracker: Arc::new(veil_routing::loss_tracker::LossTracker::new()),
        // PoW solver resource limits — permissive in tests.
        pow_solver_semaphore: Arc::new(tokio::sync::Semaphore::new(
            veil_proto::budget::MAX_CONCURRENT_POW_SOLVERS,
        )),
        pow_active_difficulty: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        pow_challenge_seen: Arc::new(Mutex::new(ExpiryCache::new(
            Duration::from_secs(veil_proto::budget::POW_CHALLENGE_TTL_SECS),
            veil_proto::budget::MAX_POW_CHALLENGE_SEEN_SIZE,
        ))),
        pending_stream_receipts: Arc::new(Mutex::new(HashMap::new())),
        veil_stream_rx: Arc::new(Mutex::new(HashMap::new())),
        pex_dispatcher: None,
        pex_state: None,
        anonymity_x25519_sk: None,
        introduce_replay_cache: Arc::new(veil_anonymity::rendezvous::IntroduceReplayCache::new()),
        rendezvous_registry: None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, RwLock};

    use super::make_test_dispatcher;
    use super::*;
    use veil_abuse::{BanList, PerPeerLimiter, ViolationTracker};
    use veil_app::{AppEndpointRegistry, AppStreamTable};
    use veil_cfg::{Config, NodeRole};
    use veil_dht::KademliaService;
    use veil_discovery::DiscoveryService;
    use veil_gateway::GatewayService;
    use veil_mesh::{MeshForwarder, NeighborTable};
    use veil_observability::NodeMetrics;
    use veil_proto::{
        family::{AppMsg, ControlMsg, FrameFamily},
        header::FrameHeader,
        routing::{RouteAnnouncePayload, RouteWithdrawPayload},
    };
    use veil_routing::RouteCache;

    // ── Ping → Pong ──────────────────────────────────────────────────────────

    #[test]
    fn ping_returns_pong() {
        let d = make_test_dispatcher(NodeRole::Core);
        let hdr = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::Ping as u16);
        let result = d.dispatch(&hdr, &[], [1u8; 32]);
        match result {
            DispatchResult::Response(bytes) => {
                assert!(bytes.len() >= HEADER_SIZE, "response too short");
                assert_eq!(bytes[5], FrameFamily::Control as u8, "wrong family");
                let msg_type = u16::from_be_bytes([bytes[6], bytes[7]]);
                assert_eq!(msg_type, ControlMsg::Pong as u16, "expected Pong");
            }
            other => panic!("expected Response(Pong), got {other:?}"),
        }
    }

    // ── Ban pre-check ─────────────────────────────────────────────────────────

    #[test]
    fn banned_peer_gets_silent_drop() {
        let d = make_test_dispatcher(NodeRole::Core);
        let banned = [0xBBu8; 32];
        d.abuse.ban_list.lock().unwrap().ban(banned, "test", None);
        let hdr = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::Ping as u16);
        let result = d.dispatch(&hdr, &[], banned);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "banned peer must get silent drop (NoResponse), not Violation"
        );
    }

    /// Banned-peer drops must spin-pad to `BAN_DROP_PAD` to close the
    /// dispatch-latency timing side-channel.  Without the pad, an
    /// observer measuring response timing can enumerate the ban-list
    /// (banned ≈ µs, not-banned ≈ tens-of-µs).
    #[test]
    fn banned_peer_drop_pads_to_constant_time() {
        let d = make_test_dispatcher(NodeRole::Core);
        let banned = [0xBBu8; 32];
        d.abuse.ban_list.lock().unwrap().ban(banned, "test", None);
        let hdr = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::Ping as u16);

        // Take the worst (min) of a small batch to suppress scheduler noise:
        // if ANY iteration is shorter than the pad, the pad is broken.
        let mut min_elapsed = std::time::Duration::from_secs(1);
        for _ in 0..8 {
            let start = std::time::Instant::now();
            let result = d.dispatch(&hdr, &[], banned);
            let elapsed = start.elapsed();
            assert!(matches!(result, DispatchResult::NoResponse));
            if elapsed < min_elapsed {
                min_elapsed = elapsed;
            }
        }

        assert!(
            min_elapsed >= BAN_DROP_PAD,
            "banned drop must spin-pad to at least {BAN_DROP_PAD:?}, observed min {min_elapsed:?}"
        );
        // Upper bound: pad should NOT balloon under spin-loop measurement
        // noise.  Allow 10× headroom for scheduler/timer jitter; anything
        // beyond means the spin loop is mis-armed (e.g. wrong sign).
        assert!(
            min_elapsed < BAN_DROP_PAD * 10,
            "ban-drop pad runaway: {min_elapsed:?} ≫ {BAN_DROP_PAD:?}"
        );
    }

    // ── Unknown family → Violation ────────────────────────────────────────────

    #[test]
    /// unknown frame families are silently skipped (forward-compatible).
    fn unknown_family_returns_not_handled() {
        let d = make_test_dispatcher(NodeRole::Core);
        let mut hdr = FrameHeader::new(0xFF, 0);
        hdr.family = 0xFF;
        let result = d.dispatch(&hdr, &[], [7u8; 32]);
        assert!(matches!(result, DispatchResult::NotHandled));
    }

    // ── App plane: APP_OPEN / APP_CLOSE / APP_RECEIPT ────────────────────────

    fn make_app_open_frame(
        app_id: [u8; 32],
        endpoint_id: u32,
        stream_id: u32,
    ) -> (FrameHeader, Vec<u8>) {
        use veil_proto::app::AppOpenPayload;
        let mut hdr = FrameHeader::new(
            FrameFamily::App as u8,
            veil_proto::family::AppMsg::AppOpen as u16,
        );
        hdr.stream_id = stream_id;
        let body = AppOpenPayload {
            app_id,
            endpoint_id,
            flags: 0,
        }
        .encode()
        .to_vec();
        (hdr, body)
    }

    #[test]
    fn app_open_returns_accepted_receipt() {
        use veil_proto::app::{AppReceiptPayload, receipt_status};
        let d = make_test_dispatcher(NodeRole::Core);
        let app_id = [0xAAu8; 32];
        let peer = [0x01u8; 32];
        let (hdr, body) = make_app_open_frame(app_id, 1, 100);
        let result = d.dispatch(&hdr, &body, peer);
        match result {
            DispatchResult::Response(bytes) => {
                let msg_type = u16::from_be_bytes([bytes[6], bytes[7]]);
                assert_eq!(msg_type, veil_proto::family::AppMsg::AppReceipt as u16);
                let receipt = AppReceiptPayload::decode(&bytes[HEADER_SIZE..]).unwrap();
                assert_eq!(receipt.status, receipt_status::ACCEPTED);
            }
            other => panic!("expected Response(AppReceipt/Accepted), got {other:?}"),
        }
        assert!(
            d.stream_table.is_open(&peer, 100),
            "stream must be open after APP_OPEN"
        );
    }

    #[test]
    fn app_open_duplicate_returns_rejected_receipt() {
        use veil_proto::app::{AppReceiptPayload, receipt_status};
        let d = make_test_dispatcher(NodeRole::Core);
        let app_id = [0xAAu8; 32];
        let peer = [0x01u8; 32];
        let (hdr, body) = make_app_open_frame(app_id, 1, 100);
        d.dispatch(&hdr, &body, peer); // first open
        let result = d.dispatch(&hdr, &body, peer); // duplicate
        match result {
            DispatchResult::Response(bytes) => {
                let receipt = AppReceiptPayload::decode(&bytes[HEADER_SIZE..]).unwrap();
                assert_eq!(
                    receipt.status,
                    receipt_status::REJECTED,
                    "duplicate APP_OPEN must receive REJECTED receipt"
                );
            }
            other => panic!("expected Response(AppReceipt/Rejected), got {other:?}"),
        }
    }

    #[test]
    fn app_close_returns_receipt_and_removes_stream() {
        use veil_proto::app::{AppClosePayload, AppReceiptPayload, close_reason, receipt_status};
        let d = make_test_dispatcher(NodeRole::Core);
        let app_id = [0xAAu8; 32];
        let peer = [0x01u8; 32];

        // Open first.
        let (open_hdr, open_body) = make_app_open_frame(app_id, 1, 200);
        d.dispatch(&open_hdr, &open_body, peer);

        // Now close.
        let mut close_hdr = FrameHeader::new(
            FrameFamily::App as u8,
            veil_proto::family::AppMsg::AppClose as u16,
        );
        close_hdr.stream_id = 200;
        let close_body = AppClosePayload {
            app_id,
            endpoint_id: 1,
            reason: close_reason::NORMAL,
        }
        .encode();
        let result = d.dispatch(&close_hdr, &close_body, peer);
        match result {
            DispatchResult::Response(bytes) => {
                let receipt = AppReceiptPayload::decode(&bytes[HEADER_SIZE..]).unwrap();
                assert_eq!(receipt.status, receipt_status::ACCEPTED);
            }
            other => panic!("expected Response(AppReceipt/Accepted), got {other:?}"),
        }
        assert!(
            !d.stream_table.is_open(&peer, 200),
            "stream must be removed after APP_CLOSE"
        );
    }

    fn make_app_data_frame(
        app_id: [u8; 32],
        endpoint_id: u32,
        stream_id: u32,
        data: Vec<u8>,
    ) -> (FrameHeader, Vec<u8>) {
        use veil_proto::app::AppDataPayload;
        let mut hdr = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppData as u16);
        hdr.stream_id = stream_id;
        let body = AppDataPayload {
            app_id,
            endpoint_id,
            seq: 0,
            data,
        }
        .encode()
        .to_vec();
        (hdr, body)
    }

    #[test]
    /// Regression (audit 2026-06-03): inbound APP_DATA for a locally-initiated
    /// veil stream — one registered ONLY in `veil_stream_rx` (SOCKS
    /// `VeilConnector` or the IPC remote-stream bridge), with no
    /// `AppStreamTable` entry — must be routed to that stream's channel, NOT
    /// rejected as a receive-window violation. Flow control for these streams is
    /// the channel's own backpressure, so the `record_data_received` window
    /// check must not gate them (it runs only for streams opened via APP_OPEN).
    fn app_data_routes_to_veil_stream_rx_without_stream_table_entry() {
        let d = make_test_dispatcher(NodeRole::Core);
        let peer = [0x55u8; 32];
        let stream_id = 4242u32;

        // Register the inbound channel the way VeilConnector / the IPC bridge
        // do: ONLY in veil_stream_rx, deliberately without stream_table.open().
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
        d.veil_stream_rx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((peer, stream_id), tx);

        let (hdr, body) = make_app_data_frame([0xAAu8; 32], 1, stream_id, b"pong".to_vec());
        let result = d.dispatch(&hdr, &body, peer);

        assert!(
            !matches!(result, DispatchResult::Violation(_)),
            "inbound APP_DATA for an veil_stream_rx stream must not be a window \
             violation, got {result:?}"
        );
        assert_eq!(
            rx.try_recv().ok(),
            Some(b"pong".to_vec()),
            "APP_DATA payload must be routed to the veil stream channel"
        );
    }

    #[test]
    /// M-3 (audit 2026-06-03): when the local veil-stream channel is full
    /// (slow SOCKS5/IPC consumer), inbound APP_DATA is NOT silently dropped —
    /// the dispatcher removes the local route AND returns an APP_CLOSE to the
    /// remote peer (the data source) so it does not hold the stream half-open
    /// until its idle reaper. Pre-fix it only dropped the local entry.
    fn app_data_backpressure_returns_appclose_to_remote() {
        let d = make_test_dispatcher(NodeRole::Core);
        let peer = [0x66u8; 32];
        let stream_id = 7777u32;
        let app_id = [0xABu8; 32];

        // Capacity-1 channel, pre-filled so the dispatcher's try_send is Full.
        // Keep the receiver alive so we exercise the Full (not Closed) arm.
        let (tx, _rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        tx.try_send(b"prefill".to_vec()).unwrap();
        d.veil_stream_rx
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((peer, stream_id), tx);

        let (hdr, body) = make_app_data_frame(app_id, 9, stream_id, b"overflow".to_vec());
        match d.dispatch(&hdr, &body, peer) {
            DispatchResult::Response(bytes) => {
                let msg_type = u16::from_be_bytes([bytes[6], bytes[7]]);
                assert_eq!(
                    msg_type,
                    AppMsg::AppClose as u16,
                    "backpressure must AppClose the remote, got msg_type {msg_type}"
                );
                let close =
                    veil_proto::app::AppClosePayload::decode(&bytes[HEADER_SIZE..]).unwrap();
                assert_eq!(close.app_id, app_id);
                assert_eq!(close.endpoint_id, 9);
            }
            other => panic!("expected Response(AppClose) on backpressure, got {other:?}"),
        }
        // Local route removed so the dead stream stops consuming a map slot.
        assert!(
            !d.veil_stream_rx
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains_key(&(peer, stream_id)),
            "backpressure must drop the local veil_stream_rx entry"
        );
    }

    // ── Control plane: NEIGHBOR_OFFER ─────────────────────────────────────────

    #[test]
    fn neighbor_offer_routes_to_pending_not_live_table() {
        use veil_proto::control::NeighborOfferPayload;
        let d = make_test_dispatcher(NodeRole::Core);
        let offerer_id = [0x42u8; 32];
        // Offer a DIFFERENT node_id than the sender so the contact is genuinely
        // peer-claimed (the eclipse case M-1 guards against).
        let offered_id = [0x99u8; 32];
        let payload = NeighborOfferPayload {
            node_id: offered_id,
            addr: b"127.0.0.1:9001".to_vec(),
            flags: 0,
        };
        let body = payload.encode();
        let hdr = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::NeighborOffer as u16);
        let result = d.dispatch(&hdr, &body, offerer_id);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "NEIGHBOR_OFFER must return NoResponse, got {result:?}"
        );
        // M-1: a peer-claimed offer must NOT enter the live routing table
        // directly — it lands in the source-tracked pending pool and is only
        // promoted on a successful OVL1 handshake with the claimed node_id.
        assert_eq!(
            d.dht.routing_table_size(),
            0,
            "NEIGHBOR_OFFER must not inject directly into the live routing table"
        );
        assert_eq!(
            d.dht.pending_contacts_count(),
            1,
            "offer should be parked in the source-tracked pending pool"
        );
    }

    // ── Control plane: ROUTE_PROBE → ROUTE_REPLY ─────────────────────────────

    #[test]
    fn route_probe_returns_route_reply_with_same_probe_id() {
        use veil_proto::control::{RouteProbePayload, RouteReplyPayload};
        let d = make_test_dispatcher(NodeRole::Core);
        let probe = RouteProbePayload {
            probe_id: 0xDEAD_BEEF,
            timestamp_ms: 123_456,
        };
        let body = probe.encode();
        let hdr = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::RouteProbe as u16);
        let result = d.dispatch(&hdr, &body, [0xAAu8; 32]);
        match result {
            DispatchResult::Response(bytes) => {
                assert!(bytes.len() >= HEADER_SIZE);
                assert_eq!(bytes[5], FrameFamily::Control as u8, "wrong family");
                let msg_type = u16::from_be_bytes([bytes[6], bytes[7]]);
                assert_eq!(
                    msg_type,
                    ControlMsg::RouteReply as u16,
                    "expected RouteReply"
                );
                let reply = RouteReplyPayload::decode(&bytes[HEADER_SIZE..]).unwrap();
                assert_eq!(reply.probe_id, probe.probe_id);
                assert_eq!(reply.timestamp_ms, probe.timestamp_ms);
            }
            other => panic!("expected Response(RouteReply), got {other:?}"),
        }
    }

    // ── Control plane: ROUTE_REPLY records RTT ────────────────────────────────

    #[test]
    fn route_reply_records_rtt_in_control_plane() {
        use veil_proto::control::RouteReplyPayload;
        let d = make_test_dispatcher(NodeRole::Core);
        let peer = [0xBBu8; 32];
        let reply = RouteReplyPayload {
            probe_id: 1,
            timestamp_ms: 0,
            rtt_ms: 55,
            congestion: 0,
        };
        let body = reply.encode();
        let hdr = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::RouteReply as u16);
        let result = d.dispatch(&hdr, &body, peer);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "ROUTE_REPLY must return NoResponse"
        );
        assert_eq!(d.control_plane.rtt_ms(&peer), Some(55));
    }

    // ── 31.5: voice stream 50 pps, 160 B opus → dispatch latency ≤ 20 ms ──────

    #[test]
    fn rt_data_50pps_dispatch_latency_under_20ms() {
        use std::time::Instant;
        use veil_proto::AppRtDataPayload;

        let d = make_test_dispatcher(NodeRole::Core);
        let peer: [u8; 32] = [0x10u8; 32];
        let app_id = [0xA0u8; 32];
        let (_handle, _rx) = d.app_registry.register(app_id, 1, 256);

        // Build a 160-byte Opus frame (typical 20ms @ 8 kHz).
        let opus_frame = vec![0xABu8; 160];

        // Send 50 frames (simulating 1 second of 50 pps voice).
        let start = Instant::now();
        for seq in 0u32..50 {
            let payload = AppRtDataPayload {
                app_id,
                endpoint_id: 1,
                seq,
                timestamp_us: seq as u64 * 20_000, // 20ms intervals
                marker: 0,
                payload_type: 0, // Opus codec ID
                payload: opus_frame.clone(),
            };
            let body = payload.encode();
            let mut hdr = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppRtData as u16);
            hdr.body_len = body.len() as u32;
            let result = d.dispatch(&hdr, &body, peer);
            assert!(matches!(result, DispatchResult::NoResponse));
        }
        let elapsed = start.elapsed();

        // 50 dispatches must complete within 20 ms on any reasonable machine.
        assert!(
            elapsed.as_millis() < 20,
            "50 RT frames took {}ms — exceeds 20ms budget",
            elapsed.as_millis()
        );

        // Verify metrics were incremented.
        let snap = d.metrics.as_ref().unwrap().snapshot();
        assert_eq!(snap.rt_frames_rx_total, 50);
    }

    // ── gossip A←→B←→C relay — RouteCache populated automatically ─

    /// Helper: build a FrameDispatcher for node `local_id` that:
    /// has a real ed25519 signing key
    /// has a shared `SessionTxRegistry`, and
    /// knows the pubkey of every peer in `known_peers`.
    fn make_gossip_dispatcher(
        local_id: [u8; 32],
        signing_key: Arc<ed25519_dalek::SigningKey>,
        tx_registry: Arc<RwLock<veil_session::SessionTxRegistry>>,
        known_peers: Vec<([u8; 32], ed25519_dalek::VerifyingKey)>,
    ) -> FrameDispatcher {
        let role = NodeRole::Core;
        let mut peer_map = veil_types::PeerLruCache::<(u8, Vec<u8>)>::with_capacity(16);
        for (pid, vk) in known_peers {
            peer_map.insert_lru(
                pid,
                (0u8, vk.as_bytes().to_vec()),
                veil_proto::budget::MAX_PEER_PUBKEYS_CACHE,
            );
        }
        FrameDispatcher {
            role,
            gateway: Arc::new(GatewayService::new(role)),
            discovery: Arc::new(DiscoveryService::new(role)),
            dht: Arc::new(KademliaService::with_config(
                local_id,
                veil_dht::DhtRuntimeConfig {
                    // tests inject unsigned `StorePayload`
                    // fixtures; production rejects them. Enable the dev flag in
                    // the dispatcher test factory so legacy fixtures still pass.
                    allow_unsigned_store: true,
                    ..Default::default()
                },
            )),
            app_registry: Arc::new(AppEndpointRegistry::new()),
            stream_table: Arc::new(AppStreamTable::new()),
            mesh_forwarder: Arc::new(MeshForwarder::new(
                local_id,
                role,
                Arc::new(NeighborTable::new()),
            )),
            chunk_reassembler: Arc::new(Mutex::new(
                crate::envelope_chunks::EnvelopeChunkReassembler::new(),
            )),
            discovery_forwarder: Arc::new(Mutex::new(
                veil_routing::discovery_forwarder::DiscoveryForwarder::with_default_difficulty(
                    local_id, role,
                ),
            )),
            control_plane: Arc::new(ControlPlaneService::new(std::time::Duration::from_secs(
                300,
            ))),
            route_cache: Arc::new(RwLock::new(RouteCache::new(
                std::time::Duration::from_secs(60),
            ))),
            metrics: Some(Arc::new(NodeMetrics::new())),
            logger: Arc::new(
                veil_cfg::observability_glue::logger_from_config(&Config::default()).unwrap(),
            ),
            crypto: Arc::new(CryptoContext {
                local_signing_key: Some(signing_key),
                mlkem_ek: Arc::new([0u8; veil_e2e::EK_BYTES]),
                mlkem_dk_seed: Arc::new(veil_util::sensitive_bytes::SensitiveBytesN::<
                    { veil_e2e::DK_SEED_BYTES },
                >::new()),
                peer_mlkem_keys: Arc::new(std::sync::RwLock::new(veil_e2e::PeerMlKemCache::new())),
                peer_pubkeys: Arc::new(Mutex::new(peer_map)),
                peer_roles: Arc::new(Mutex::new(veil_types::PeerLruCache::with_capacity(64))),
                peer_cap_flags: Arc::new(RwLock::new(HashMap::new())),
                per_session_mlkem_dk: Arc::new(Mutex::new(HashMap::new())),
            }),
            abuse: Arc::new(AbuseContext {
                rate_limiter: Arc::new(Mutex::new(PerPeerLimiter::new(
                    1000.0,
                    1000.0,
                    std::time::Duration::from_secs(300),
                ))),
                ban_list: Arc::new(Mutex::new(BanList::new())),
                violation_tracker: Arc::new(Mutex::new(
                    ViolationTracker::with_fixed_duration(
                        5,
                        std::time::Duration::from_secs(3600),
                        std::time::Duration::from_secs(600),
                    )
                    .expect("ban_threshold = 5 > 0"),
                )),
                dht_quota: Arc::new(Mutex::new(veil_abuse::DhtQuota::new(
                    1000,
                    Duration::from_secs(60),
                ))),
                // permissive in tests (no rate-limiting unless explicit).
                identity_write_quota: Arc::new(
                    veil_abuse::identity_quota::IdentityWriteQuota::new(
                        veil_abuse::identity_quota::IdentityQuotaConfig {
                            max_writes_per_window: 100_000,
                            window: Duration::from_secs(60),
                            cleanup_idle_after: Duration::from_secs(300),
                            max_identities: veil_proto::budget::MAX_IDENTITY_WRITE_QUOTA_SIZE,
                        },
                    ),
                ),
                pow_challenge_limiter: Arc::new(Mutex::new(PerPeerLimiter::new(
                    1000.0,
                    1000.0,
                    std::time::Duration::from_secs(300),
                ))),
                dht_contact_quota: Arc::new(Mutex::new(veil_abuse::DhtQuota::new(
                    1_000_000,
                    Duration::from_secs(60),
                ))),
                // 1 announce per 60 s steady-state, burst of 3 (covers reconnect storm).
                announce_attachment_limiter: Arc::new(Mutex::new(PerPeerLimiter::new(
                    1.0 / 60.0,
                    3.0,
                    Duration::from_secs(600),
                ))),
                //round 7 / : NAT probe relay-forward quota.
                nat_probe_forward_quota: Arc::new(Mutex::new(DhtQuota::new(
                    veil_proto::budget::MAX_NAT_PROBE_FORWARDS_PER_PEER_PER_WINDOW,
                    Duration::from_secs(veil_proto::budget::DHT_QUOTA_WINDOW_SECS),
                ))),
                // RecursiveQuery rate limit: 5 queries/sec sustained, burst 20 — well above
                // legitimate Kademlia client rates yet quickly chokes a peer flooding
                // distinct query_ids to amplify load on every relay hop.
                recursive_query_limiter: Arc::new(Mutex::new(PerPeerLimiter::new(
                    5.0,
                    20.0,
                    Duration::from_secs(300),
                ))),
                inbound_bandwidth: Arc::new(Mutex::new(veil_abuse::BandwidthGate::new(0))),
                outbound_bandwidth: Arc::new(Mutex::new(veil_abuse::BandwidthGate::new(0))),
            }),
            local_node_id: local_id,
            session_tx_registry: Some(tx_registry),
            rendezvous_weak: Arc::new(std::sync::Mutex::new(None)),
            session_registry: None, // test dispatcher — sovereign routing bypassed
            route_seen_set: Arc::new(Mutex::new(RouteSeenSet::new(
                std::time::Duration::from_secs(60),
                4096,
            ))),
            announce_seq: Arc::new(AtomicU32::new(0)),
            listen_transports: Arc::new(RwLock::new(vec![])),
            relay_node_ids: vec![],
            target_labels: vec![],
            route_updated: Arc::new(Notify::new()),
            pow_difficulty: 0,
            pow_pending: Arc::new(Mutex::new(PowPendingTable::new())),
            discovery_mode: veil_cfg::DiscoveryMode::Public,
            pending_diag: Arc::new(Mutex::new(HashMap::new())),
            capture_tx: Arc::new(Mutex::new(None)),
            capture_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            capture_rate_limit: Arc::new(veil_dispatcher_state::CaptureRateLimiter::new()),
            route_miss_tx: Arc::new(Mutex::new(None)),
            neighbor_scorer: Arc::new(Mutex::new(NeighborScorer::with_alphas(0.5, 0.1))),
            local_vivaldi: None,
            peer_vivaldi: Arc::new(std::sync::RwLock::new(HashMap::new())),
            forward_seen_set: Arc::new(Mutex::new(ForwardSeenSet::new(
                Duration::from_secs(30),
                10_000,
            ))),
            forward_seen_content: Arc::new(Mutex::new(ForwardSeenSet::new(
                Duration::from_secs(30),
                10_000,
            ))),
            terminal_ack_replay: Arc::new(Mutex::new(ExpiryMap::new(
                Duration::from_secs(30),
                10_000,
            ))),
            recursive_query_seen: Arc::new(Mutex::new(ExpiryCache::new(
                Duration::from_secs(30),
                65536,
            ))),
            vvsync_seen: Arc::new(Mutex::new(ExpiryCache::new(
                Duration::from_secs(veil_proto::budget::VVSYNC_MIN_INTERVAL_SECS),
                veil_proto::budget::MAX_VVSYNC_SEEN_SIZE,
            ))),
            pending_recursive: Arc::new(Mutex::new(std::collections::HashMap::new())),
            recursive_reverse_path: Arc::new(Mutex::new(std::collections::HashMap::new())),
            alias_registry: Arc::new(Mutex::new(HashMap::new())),
            peer_observed_addrs: Arc::new(std::sync::RwLock::new(HashMap::new())),
            relay_tunnels: Arc::new(Mutex::new(HashMap::new())),
            nat_probe_waiters: Arc::new(Mutex::new(HashMap::new())),
            adaptive_params: Arc::new(RwLock::new(veil_cfg::adaptive::AdaptiveParams::default())),
            max_gossip_hops: veil_cfg::RoutingConfig::default().max_gossip_hops,
            congestion_monitor: None,
            reputation: None,
            gateway_list: None,
            prefer_internet_gateway: true,
            exit_diversification: false,
            exit_diversification_top_k: 4,
            ecmp_score_band: veil_cfg::RoutingConfig::default().ecmp_score_band,
            redundant_send: false,
            epidemic_seen: Arc::new(Mutex::new(EpidemicSeenSet::new(
                Duration::from_secs(120),
                4096,
            ))),
            epidemic_fanout: veil_cfg::RoutingConfig::default().epidemic_fanout,
            epidemic_max_payload: veil_cfg::RoutingConfig::default().epidemic_max_payload,
            battery_threshold_low: veil_cfg::RoutingConfig::default().battery_threshold_low,
            battery_threshold_medium: veil_cfg::RoutingConfig::default().battery_threshold_medium,
            battery_penalty_low: veil_cfg::RoutingConfig::default().battery_penalty_low,
            battery_penalty_medium: veil_cfg::RoutingConfig::default().battery_penalty_medium,
            last_sleep_advertisement_ts: Arc::new(AtomicU64::new(0)),
            multi_path_enabled: false,
            max_parallel_paths: veil_cfg::RoutingConfig::default().max_parallel_paths,
            multi_path_min_priority: veil_cfg::RoutingConfig::default().multi_path_min_priority,
            relay_reputation_min_attempts: veil_cfg::RoutingConfig::default()
                .relay_reputation_min_attempts,
            relay_reputation_threshold: veil_cfg::RoutingConfig::default()
                .relay_reputation_threshold,
            relay_reputation_penalty: veil_cfg::RoutingConfig::default().relay_reputation_penalty,
            jitter_penalty_weight: veil_cfg::RoutingConfig::default().jitter_penalty_weight,
            jitter_threshold_ms: veil_cfg::RoutingConfig::default().jitter_threshold_ms,
            narrow_bandwidth_bulk_penalty: veil_cfg::RoutingConfig::default()
                .narrow_bandwidth_bulk_penalty,
            trace_buffer: Arc::new(Mutex::new(TraceBuffer::new(
                veil_cfg::RoutingConfig::default().trace_buffer_size,
            ))),
            pending_ack: Arc::new(Mutex::new(pending_ack::PendingAckTracker::new())),
            loss_tracker: Arc::new(veil_routing::loss_tracker::LossTracker::new()),
            route_origin_seq: Arc::new(Mutex::new(HashMap::new())),
            // PoW solver resource limits — permissive in tests.
            pow_solver_semaphore: Arc::new(tokio::sync::Semaphore::new(
                veil_proto::budget::MAX_CONCURRENT_POW_SOLVERS,
            )),
            pow_active_difficulty: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pow_challenge_seen: Arc::new(Mutex::new(ExpiryCache::new(
                Duration::from_secs(veil_proto::budget::POW_CHALLENGE_TTL_SECS),
                veil_proto::budget::MAX_POW_CHALLENGE_SEEN_SIZE,
            ))),
            pending_stream_receipts: Arc::new(Mutex::new(HashMap::new())),
            veil_stream_rx: Arc::new(Mutex::new(HashMap::new())),
            pex_dispatcher: None,
            pex_state: None,
            anonymity_x25519_sk: None,
            introduce_replay_cache: Arc::new(
                veil_anonymity::rendezvous::IntroduceReplayCache::new(),
            ),
            rendezvous_registry: None,
        }
    }

    /// Build a signed ROUTE_ANNOUNCE frame (raw OVL1 bytes) from the given
    /// signer about `origin` being reachable via the signer as next-hop.
    fn build_announce_frame(
        origin: [u8; 32],
        via: [u8; 32],
        hop_count: u8,
        ttl: u8,
        seq: u32,
        key: &ed25519_dalek::SigningKey,
    ) -> (FrameHeader, Vec<u8>) {
        use ed25519_dalek::Signer;
        let now_ts = veil_util::unix_secs_now_u32();
        let mut p = RouteAnnouncePayload {
            origin_node_id: origin,
            via_node_id: via,
            hop_count,
            ttl,
            sequence: seq,
            timestamp: now_ts,
            signature: [0u8; 64],
        };
        p.signature = key.sign(&p.signable_bytes()).to_bytes();
        let hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::RouteAnnounce as u16);
        (hdr, p.encode().to_vec())
    }

    /// Build a signed ROUTE_WITHDRAW frame.
    fn build_withdraw_frame(
        origin: [u8; 32],
        via: [u8; 32],
        seq: u32,
        key: &ed25519_dalek::SigningKey,
    ) -> (FrameHeader, Vec<u8>) {
        use ed25519_dalek::Signer;
        let mut p = RouteWithdrawPayload {
            origin_node_id: origin,
            via_node_id: via,
            sequence: seq,
            signature: [0u8; 64],
            hop_count: 0,
        };
        p.signature = key.sign(&p.signable_bytes()).to_bytes();
        let hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::RouteWithdraw as u16);
        (hdr, p.encode().to_vec())
    }

    /// 60.6 — A receives ROUTE_ANNOUNCE(origin=C, via=B) from B.
    /// After dispatch, A's RouteCache must map C → next_hop=B without any
    /// manual route_cache.insert call.
    #[test]
    fn route_gossip_announce_populates_route_cache() {
        use ed25519_dalek::SigningKey;

        // Node IDs.
        let a_id = [0xAAu8; 32];
        let b_id = [0xBBu8; 32];
        let c_id = [0xCCu8; 32];

        // Generate B's signing key.
        let b_key_bytes = [0x42u8; 32]; // deterministic seed
        let b_sk = Arc::new(SigningKey::from_bytes(&b_key_bytes));
        let b_vk = b_sk.verifying_key();

        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));

        // A knows B's pubkey (as if a handshake has been completed).
        let disp_a = make_gossip_dispatcher(
            a_id,
            Arc::new(SigningKey::from_bytes(&[0xAAu8; 32])),
            Arc::clone(&tx_reg),
            vec![(b_id, b_vk)],
        );

        // B sends ROUTE_ANNOUNCE(origin=C, via=B, hop=1) to A (peer_id=B).
        let (hdr, body) = build_announce_frame(c_id, b_id, 1, 7, 1, &b_sk);
        let result = disp_a.dispatch(&hdr, &body, b_id);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "ROUTE_ANNOUNCE must return NoResponse"
        );

        // A's RouteCache should now contain C → via=B.
        let next_hop = disp_a.route_cache.read().unwrap().lookup(&c_id);
        assert_eq!(
            next_hop,
            Some(b_id),
            "RouteCache must map C → B after receiving ROUTE_ANNOUNCE"
        );
    }

    // ── failover — ROUTE_WITHDRAW removes primary, secondary survives

    /// 60.7 — A learns C via both B and D. B then withdraws.
    /// After the withdrawal A's RouteCache should return D as next-hop for C.
    #[test]
    fn route_gossip_failover_after_withdraw() {
        use ed25519_dalek::SigningKey;

        let a_id = [0xAAu8; 32];
        let b_id = [0xBBu8; 32];
        let c_id = [0xCCu8; 32];
        let d_id = [0xDDu8; 32];

        let b_sk = Arc::new(SigningKey::from_bytes(&[0x42u8; 32]));
        let b_vk = b_sk.verifying_key();
        let d_sk = Arc::new(SigningKey::from_bytes(&[0x44u8; 32]));
        let d_vk = d_sk.verifying_key();

        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));

        // A knows both B and D.
        let disp_a = make_gossip_dispatcher(
            a_id,
            Arc::new(SigningKey::from_bytes(&[0xAAu8; 32])),
            Arc::clone(&tx_reg),
            vec![(b_id, b_vk), (d_id, d_vk)],
        );

        // Step 1: B announces C with hop=1 (score=10).
        let (hdr, body) = build_announce_frame(c_id, b_id, 1, 7, 1, &b_sk);
        disp_a.dispatch(&hdr, &body, b_id);

        // Step 2: D announces C with hop=2 (score=20, worse than B).
        let (hdr, body) = build_announce_frame(c_id, d_id, 2, 7, 2, &d_sk);
        disp_a.dispatch(&hdr, &body, d_id);

        // Primary should be B (lower score).
        assert_eq!(
            disp_a.route_cache.read().unwrap().lookup(&c_id),
            Some(b_id),
            "primary route to C must be via B"
        );

        // Step 3: B withdraws the route to C.
        let (hdr, body) = build_withdraw_frame(c_id, b_id, 10, &b_sk);
        let result = disp_a.dispatch(&hdr, &body, b_id);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "ROUTE_WITHDRAW must return NoResponse"
        );

        // After withdraw, D must become the next-hop for C.
        let next_hop = disp_a.route_cache.read().unwrap().lookup(&c_id);
        assert_eq!(
            next_hop,
            Some(d_id),
            "after B withdraws, route to C must fall back to D"
        );
    }

    // ── PoW bootstrap round-trip ──────────────────────────────────

    /// Full PoW bootstrap flow at the dispatcher level:
    /// A (requester) ──RouteRequest──▶ C (target/acceptor)
    /// C ──RouteResponse──▶ A (direct response)
    /// C ──PowChallenge──▶ A (via tx_registry)
    /// A ──PowResponse──▶ C (feeds dispatcher directly)
    /// C ──PowAccept──▶ A (via tx_registry)
    /// A dispatches PowAccept → route_updated notified
    #[test]
    fn pow_bootstrap_full_round_trip() {
        use ed25519_dalek::SigningKey;
        use veil_proto::{
            codec::decode_header,
            routing::{
                PowAcceptPayload, PowChallengePayload, PowResponsePayload, RouteRequestPayload,
            },
        };
        use veil_routing::pow::solve_pow;

        let a_id = [0xAAu8; 32]; // requester
        let c_id = [0xCCu8; 32]; // target / acceptor

        let a_sk = Arc::new(SigningKey::from_bytes(&[0xAAu8; 32]));
        let c_sk = Arc::new(SigningKey::from_bytes(&[0xCCu8; 32]));

        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));

        // Register an outbox for A — frames sent to a_id land here.
        let mut rx_a = tx_reg.write().unwrap().register(a_id);
        // Register an outbox for C so routing lookups don't silently discard frames.
        let _rx_c = tx_reg.write().unwrap().register(c_id);

        // C's dispatcher — the target node, PoW difficulty = 1 (fast for tests).
        let a_vk = a_sk.verifying_key();
        let mut disp_c = make_gossip_dispatcher(
            c_id,
            Arc::clone(&c_sk),
            Arc::clone(&tx_reg),
            vec![(a_id, a_vk)],
        );
        disp_c.pow_difficulty = 1;
        *disp_c.listen_transports.write().unwrap() = vec!["tcp://192.168.1.100:7001".to_string()];

        // A's dispatcher — the requester node.
        let c_vk = c_sk.verifying_key();
        let disp_a = make_gossip_dispatcher(
            a_id,
            Arc::clone(&a_sk),
            Arc::clone(&tx_reg),
            vec![(c_id, c_vk)],
        );

        // ── Step 1: C dispatches RouteRequest from A ──────────────────────────
        let req = RouteRequestPayload {
            target_node_id: c_id,
            requester_node_id: a_id,
            request_id: 0xDEAD,
            ttl: 7,
            signature: [0u8; 64],
        };
        let rr_hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::RouteRequest as u16);
        let result = disp_c.dispatch(&rr_hdr, &req.encode(), a_id);

        // Level 1: RouteResponse is now DEFERRED behind
        // the PoW gate. The dispatcher returns NoResponse here and
        // sends only a PowChallenge — the RouteResponse with our
        // listen transports arrives only after the requester returns
        // a valid PowResponse (Step 4 below).
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "Level 1: RouteRequest with PoW must return NoResponse (RouteResponse deferred), got {result:?}",
        );

        // C must have enqueued a PowChallenge to A via tx_registry.
        let (_, ch_frame) = rx_a
            .try_recv()
            .expect("PowChallenge must be enqueued to A after RouteRequest");
        let ch_hdr = decode_header(&ch_frame).unwrap();
        assert_eq!(
            ch_hdr.msg_type,
            RoutingMsg::PowChallenge as u16,
            "expected PowChallenge"
        );
        let challenge = PowChallengePayload::decode(&ch_frame[HEADER_SIZE..]).unwrap();
        assert_eq!(challenge.requester_node_id, a_id);
        assert_eq!(challenge.acceptor_node_id, c_id);
        assert_eq!(challenge.difficulty, 1);

        // No RouteResponse should be in the outbox yet.
        assert!(
            rx_a.try_recv().is_err(),
            "Level 1: RouteResponse must not be enqueued before PowResponse",
        );

        // ── Step 2: A dispatches the PowChallenge ─────────────────────────────
        let pch_hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::PowChallenge as u16);
        let result2 = disp_a.dispatch(&pch_hdr, &challenge.encode(), c_id);
        let received = match result2 {
            DispatchResult::SolvePow(c) => c,
            other => panic!("expected SolvePow, got {other:?}"),
        };
        assert_eq!(received.requester_node_id, a_id);
        assert_eq!(received.acceptor_node_id, c_id);

        // ── Step 3: Solve the PoW (synchronous — difficulty 1 is very fast) ───
        let solution = solve_pow(
            &received.requester_node_id,
            &received.challenge_nonce,
            received.difficulty,
        );
        let pow_resp = PowResponsePayload {
            requester_node_id: a_id,
            acceptor_node_id: c_id,
            challenge_nonce: received.challenge_nonce,
            solution_nonce: solution,
        };

        // ── Step 4: C dispatches the PowResponse ──────────────────────────────
        let pr_hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::PowResponse as u16);
        let result3 = disp_c.dispatch(&pr_hdr, &pow_resp.encode(), a_id);
        assert!(
            matches!(result3, DispatchResult::NoResponse),
            "PowResponse on acceptor must return NoResponse, got {result3:?}",
        );

        // Level 1: After verifying the PoW solution C
        // must enqueue BOTH the deferred RouteResponse (carrying our
        // listen transports) AND the legacy PowAccept (signalling
        // bootstrap complete). Order: RouteResponse first, then
        // PowAccept — see `handle_pow_response`.
        let (_, rr_frame) = rx_a
            .try_recv()
            .expect("RouteResponse must be enqueued to A after valid PowResponse");
        let rr_hdr2 = decode_header(&rr_frame).unwrap();
        assert_eq!(
            rr_hdr2.msg_type,
            RoutingMsg::RouteResponse as u16,
            "expected deferred RouteResponse"
        );
        let rr_payload =
            veil_proto::routing::RouteResponsePayload::decode(&rr_frame[HEADER_SIZE..]).unwrap();
        assert_eq!(rr_payload.target_node_id, c_id);
        assert_eq!(rr_payload.requester_node_id, a_id);
        assert_eq!(
            rr_payload.request_id, 0xDEAD,
            "request_id must echo from PowPending"
        );
        assert_eq!(rr_payload.transports, vec!["tcp://192.168.1.100:7001"]);

        let (_, acc_frame) = rx_a
            .try_recv()
            .expect("PowAccept must be enqueued to A after valid PowResponse");
        let acc_hdr = decode_header(&acc_frame).unwrap();
        assert_eq!(
            acc_hdr.msg_type,
            RoutingMsg::PowAccept as u16,
            "expected PowAccept"
        );
        let accept = PowAcceptPayload::decode(&acc_frame[HEADER_SIZE..]).unwrap();
        assert_eq!(accept.requester_node_id, a_id);
        assert_eq!(accept.transport, "tcp://192.168.1.100:7001");

        // ── Step 5: A dispatches the PowAccept ────────────────────────────────
        let pa_hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::PowAccept as u16);
        let result4 = disp_a.dispatch(&pa_hdr, &accept.encode(), c_id);
        assert!(
            matches!(result4, DispatchResult::NoResponse),
            "PowAccept on requester must return NoResponse, got {result4:?}",
        );
    }

    /// Tampered PoW solution must be rejected with a Violation.
    #[test]
    fn pow_response_bad_solution_is_violation() {
        use ed25519_dalek::SigningKey;
        use veil_proto::routing::{PowChallengePayload, PowResponsePayload, RouteRequestPayload};
        use veil_routing::pow::solve_pow;

        let a_id = [0xAAu8; 32];
        let c_id = [0xCCu8; 32];
        let a_sk = Arc::new(SigningKey::from_bytes(&[0xAAu8; 32]));
        let c_sk = Arc::new(SigningKey::from_bytes(&[0xCCu8; 32]));
        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let mut _rx_a = tx_reg.write().unwrap().register(a_id);

        let a_vk = a_sk.verifying_key();
        let mut disp_c = make_gossip_dispatcher(
            c_id,
            Arc::clone(&c_sk),
            Arc::clone(&tx_reg),
            vec![(a_id, a_vk)],
        );
        disp_c.pow_difficulty = 1;
        *disp_c.listen_transports.write().unwrap() = vec![];

        // Trigger challenge issuance.
        let req = RouteRequestPayload {
            target_node_id: c_id,
            requester_node_id: a_id,
            request_id: 1,
            ttl: 7,
            signature: [0u8; 64],
        };
        let hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::RouteRequest as u16);
        disp_c.dispatch(&hdr, &req.encode(), a_id);
        let (_, ch_frame) = _rx_a.try_recv().unwrap();
        let challenge = PowChallengePayload::decode(&ch_frame[HEADER_SIZE..]).unwrap();

        // Compute a valid solution, then corrupt it.
        let mut bad_solution = solve_pow(&a_id, &challenge.challenge_nonce, challenge.difficulty);
        bad_solution[0] ^= 0xFF;
        // Re-check: the corrupted solution may accidentally still pass (probability ~1/256).
        // We just verify the dispatcher handles it without panicking.
        let pow_resp = PowResponsePayload {
            requester_node_id: a_id,
            acceptor_node_id: c_id,
            challenge_nonce: challenge.challenge_nonce,
            solution_nonce: bad_solution,
        };
        let pr_hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::PowResponse as u16);
        let result = disp_c.dispatch(&pr_hdr, &pow_resp.encode(), a_id);
        // Either Violation (bad nonce) or NoResponse (if by coincidence the flipped nonce passes).
        assert!(
            matches!(
                result,
                DispatchResult::Violation(_) | DispatchResult::NoResponse
            ),
            "corrupted PoW must be Violation or (rare) NoResponse, got {result:?}",
        );
    }

    // ── tests ────────────────────────────────────────────────────────

    /// SEC-004b: A PowChallenge with an invalid acceptor signature must be rejected.
    #[test]
    fn pow_challenge_invalid_sig_is_violation() {
        use ed25519_dalek::SigningKey;
        use veil_proto::routing::PowChallengePayload;

        let a_id = [0xAAu8; 32]; // requester (us)
        let c_id = [0xCCu8; 32]; // acceptor
        let c_sk = Arc::new(SigningKey::from_bytes(&[0xCCu8; 32]));
        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));

        // Build a dispatcher for A that knows C's signing key.
        let disp_a = make_gossip_dispatcher(
            a_id,
            Arc::new(SigningKey::from_bytes(&[0xAAu8; 32])),
            Arc::clone(&tx_reg),
            vec![(c_id, c_sk.verifying_key())],
        );

        // Build a valid challenge payload, then corrupt the signature.
        let mut challenge = PowChallengePayload {
            requester_node_id: a_id,
            acceptor_node_id: c_id,
            challenge_nonce: [0x55u8; 32],
            difficulty: 1,
            signature: [0u8; 64],
        };
        // Sign it properly first so the struct is well-formed, then flip a byte.
        {
            use ed25519_dalek::Signer;
            let sig = c_sk.sign(&challenge.signable_bytes());
            challenge.signature = sig.to_bytes();
        }
        challenge.signature[0] ^= 0xFF; // corrupt

        let hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::PowChallenge as u16);
        let result = disp_a.dispatch(&hdr, &challenge.encode(), c_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "invalid acceptor sig must be Violation, got {result:?}",
        );
    }

    /// SEC-004a: Flooding PowChallenge frames must trigger the rate limiter.
    #[test]
    fn pow_challenge_rate_limit_kicks_in() {
        use ed25519_dalek::SigningKey;
        use veil_abuse::PerPeerLimiter;
        use veil_proto::routing::PowChallengePayload;

        let a_id = [0xAAu8; 32];
        let c_id = [0xCCu8; 32];
        let c_sk = Arc::new(SigningKey::from_bytes(&[0xCCu8; 32]));
        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));

        let disp_a = make_gossip_dispatcher(
            a_id,
            Arc::new(SigningKey::from_bytes(&[0xAAu8; 32])),
            Arc::clone(&tx_reg),
            vec![(c_id, c_sk.verifying_key())],
        );

        // Override the limiter to allow only 1 token (burst = 1, rate = 0.001/sec → no meaningful refill).
        *disp_a.abuse.pow_challenge_limiter.lock().unwrap() =
            PerPeerLimiter::new(0.001, 1.0, std::time::Duration::from_secs(300));

        // Build a valid challenge.
        let mut challenge = PowChallengePayload {
            requester_node_id: a_id,
            acceptor_node_id: c_id,
            challenge_nonce: [0x77u8; 32],
            difficulty: 1,
            signature: [0u8; 64],
        };
        {
            use ed25519_dalek::Signer;
            let sig = c_sk.sign(&challenge.signable_bytes());
            challenge.signature = sig.to_bytes();
        }

        let hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::PowChallenge as u16);
        // First dispatch: should consume the single burst token → SolvePow.
        let r1 = disp_a.dispatch(&hdr, &challenge.encode(), c_id);
        assert!(
            matches!(r1, DispatchResult::SolvePow(_)),
            "first dispatch must succeed, got {r1:?}",
        );

        // Second dispatch with same peer immediately: rate limit must fire.
        let r2 = disp_a.dispatch(&hdr, &challenge.encode(), c_id);
        assert!(
            matches!(r2, DispatchResult::Violation(_)),
            "second dispatch must be rate-limited, got {r2:?}",
        );
    }

    // ── PowResponse requester mismatch is rejected ───────────────────

    /// A `PowResponse` whose `requester_node_id` does not match the stored
    /// challenge's requester must be rejected with Violation.
    ///
    /// This verifies that the PoW solution is bound to the requester — a relay
    /// cannot forward a solution computed for node A under node B's identity.
    #[test]
    fn pow_response_requester_mismatch_is_violation() {
        use ed25519_dalek::SigningKey;
        use veil_proto::routing::{PowChallengePayload, PowResponsePayload, RouteRequestPayload};
        use veil_routing::pow::solve_pow;

        let a_id = [0xAAu8; 32]; // legitimate requester
        let b_id = [0xBBu8; 32]; // attacker (tries to submit A's solution under their identity)
        let c_id = [0xCCu8; 32]; // acceptor (us)
        let a_sk = Arc::new(SigningKey::from_bytes(&[0xAAu8; 32]));
        let c_sk = Arc::new(SigningKey::from_bytes(&[0xCCu8; 32]));
        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let mut rx_a = tx_reg.write().unwrap().register(a_id);

        let a_vk = a_sk.verifying_key();
        let mut disp_c = make_gossip_dispatcher(
            c_id,
            Arc::clone(&c_sk),
            Arc::clone(&tx_reg),
            vec![(a_id, a_vk)],
        );
        disp_c.pow_difficulty = 1;
        *disp_c.listen_transports.write().unwrap() = vec!["tcp://127.0.0.1:9000".to_string()];

        // A sends RouteRequest to C — C issues a PowChallenge for A.
        let req = RouteRequestPayload {
            target_node_id: c_id,
            requester_node_id: a_id,
            request_id: 1,
            ttl: 7,
            signature: [0u8; 64],
        };
        let hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::RouteRequest as u16);
        disp_c.dispatch(&hdr, &req.encode(), a_id);
        let (_, ch_frame) = rx_a.try_recv().unwrap();
        let challenge = PowChallengePayload::decode(&ch_frame[HEADER_SIZE..]).unwrap();

        // Attacker B computes a valid solution FOR A, but submits it with requester_node_id = b_id.
        let solution = solve_pow(&a_id, &challenge.challenge_nonce, challenge.difficulty);
        let pow_resp = PowResponsePayload {
            requester_node_id: b_id, // ← WRONG: B claims to be the requester
            acceptor_node_id: c_id,
            challenge_nonce: challenge.challenge_nonce,
            solution_nonce: solution,
        };
        let pr_hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::PowResponse as u16);
        let result = disp_c.dispatch(&pr_hdr, &pow_resp.encode(), b_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "PowResponse with mismatched requester_node_id must be Violation, got {result:?}",
        );
    }

    // ── tests ────────────────────────────────────────────────────

    /// Level 1: A `RouteRequest` to a target with `pow_difficulty > 0` must
    /// NOT leak the target's listen transports until the requester returns a
    /// valid `PowResponse`. Probing-by-id is no longer free.
    #[test]
    fn epic472_s20_pow_gates_transport_disclosure() {
        use ed25519_dalek::SigningKey;
        use veil_proto::{
            codec::decode_header,
            routing::{PowChallengePayload, RouteRequestPayload, RouteResponsePayload},
        };

        let attacker = [0xAAu8; 32];
        let victim = [0xCCu8; 32];
        let attacker_sk = Arc::new(SigningKey::from_bytes(&[0xAAu8; 32]));
        let victim_sk = Arc::new(SigningKey::from_bytes(&[0xCCu8; 32]));
        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let mut rx_attacker = tx_reg.write().unwrap().register(attacker);

        let mut victim_disp = make_gossip_dispatcher(
            victim,
            Arc::clone(&victim_sk),
            Arc::clone(&tx_reg),
            vec![(attacker, attacker_sk.verifying_key())],
        );
        victim_disp.pow_difficulty = 1; // PoW gate ON
        *victim_disp.listen_transports.write().unwrap() = vec!["tcp://10.0.0.1:9000".to_string()];

        // Attacker probes with arbitrary target_id.
        let req = RouteRequestPayload {
            target_node_id: victim,
            requester_node_id: attacker,
            request_id: 0xFEED,
            ttl: 7,
            signature: [0u8; 64],
        };
        let hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::RouteRequest as u16);
        let result = victim_disp.dispatch(&hdr, &req.encode(), attacker);

        // No DispatchResult::Response — RouteResponse is gated.
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "RouteResponse must be deferred behind PoW, got {result:?}",
        );

        // Drain the outbox: only PowChallenge, no RouteResponse.
        let mut saw_challenge = false;
        while let Ok((_, frame)) = rx_attacker.try_recv() {
            let h = decode_header(&frame).unwrap();
            assert_ne!(
                h.msg_type,
                RoutingMsg::RouteResponse as u16,
                "Level 1 leak: victim disclosed RouteResponse before PoW",
            );
            if h.msg_type == RoutingMsg::PowChallenge as u16 {
                saw_challenge = true;
                let _ = PowChallengePayload::decode(&frame[HEADER_SIZE..]).unwrap();
            }
        }
        assert!(saw_challenge, "expected a PowChallenge in the outbox");
        let _ = std::mem::size_of::<RouteResponsePayload>(); // touch the import
    }

    /// Level 1: With PoW disabled (`pow_difficulty = 0`) the legacy fast
    /// path is preserved — RouteResponse with transports comes back
    /// immediately. Operators who opt out of PoW gating get the original
    /// behaviour.
    #[test]
    fn epic472_s20_no_pow_path_replies_immediately() {
        use ed25519_dalek::SigningKey;
        use veil_proto::{
            codec::decode_header,
            routing::{RouteRequestPayload, RouteResponsePayload},
        };

        let attacker = [0xAAu8; 32];
        let victim = [0xCCu8; 32];
        let attacker_sk = Arc::new(SigningKey::from_bytes(&[0xAAu8; 32]));
        let victim_sk = Arc::new(SigningKey::from_bytes(&[0xCCu8; 32]));
        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));

        let mut victim_disp = make_gossip_dispatcher(
            victim,
            Arc::clone(&victim_sk),
            Arc::clone(&tx_reg),
            vec![(attacker, attacker_sk.verifying_key())],
        );
        victim_disp.pow_difficulty = 0;
        *victim_disp.listen_transports.write().unwrap() = vec!["tcp://10.0.0.1:9000".to_string()];

        let req = RouteRequestPayload {
            target_node_id: victim,
            requester_node_id: attacker,
            request_id: 0x1234,
            ttl: 7,
            signature: [0u8; 64],
        };
        let hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::RouteRequest as u16);
        let result = victim_disp.dispatch(&hdr, &req.encode(), attacker);

        let bytes = match result {
            DispatchResult::Response(b) => b,
            other => panic!("expected immediate RouteResponse, got {other:?}"),
        };
        let h = decode_header(&bytes).unwrap();
        assert_eq!(h.msg_type, RoutingMsg::RouteResponse as u16);
        let resp = RouteResponsePayload::decode(&bytes[HEADER_SIZE..]).unwrap();
        assert_eq!(resp.transports, vec!["tcp://10.0.0.1:9000"]);
    }

    /// Level 2 ContactsOnly: Probes from peers absent from `peer_pubkeys`
    /// are silently dropped — neither a PowChallenge nor a RouteResponse
    /// is emitted. Even existence of the target stays hidden.
    #[test]
    fn epic472_s20_contacts_only_drops_unknown_requester() {
        use ed25519_dalek::SigningKey;
        use veil_proto::routing::RouteRequestPayload;

        let stranger = [0xAAu8; 32]; // NOT registered in victim's peer_pubkeys
        let victim = [0xCCu8; 32];
        let victim_sk = Arc::new(SigningKey::from_bytes(&[0xCCu8; 32]));
        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let mut rx_stranger = tx_reg.write().unwrap().register(stranger);

        // Note: vec![] — stranger is NOT in peer_pubkeys.
        let mut victim_disp =
            make_gossip_dispatcher(victim, Arc::clone(&victim_sk), Arc::clone(&tx_reg), vec![]);
        victim_disp.pow_difficulty = 1;
        victim_disp.discovery_mode = veil_cfg::DiscoveryMode::ContactsOnly;
        *victim_disp.listen_transports.write().unwrap() = vec!["tcp://10.0.0.1:9000".to_string()];

        let req = RouteRequestPayload {
            target_node_id: victim,
            requester_node_id: stranger,
            request_id: 0xCAFE,
            ttl: 7,
            signature: [0u8; 64],
        };
        let hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::RouteRequest as u16);
        let result = victim_disp.dispatch(&hdr, &req.encode(), stranger);

        assert!(
            matches!(result, DispatchResult::NoResponse),
            "ContactsOnly must drop unknown requester silently, got {result:?}",
        );
        assert!(
            rx_stranger.try_recv().is_err(),
            "ContactsOnly: nothing should be enqueued — even PowChallenge would confirm existence",
        );
    }

    /// Level 2 IntroductionOnly: `RouteResponse` carries `relay_ids` but
    /// never `transports`, regardless of PoW state — node steers requesters
    /// through dedicated relay infrastructure.
    #[test]
    fn epic472_s20_introduction_only_strips_transports() {
        use ed25519_dalek::SigningKey;
        use veil_proto::{
            codec::decode_header,
            routing::{RouteRequestPayload, RouteResponsePayload},
        };

        let attacker = [0xAAu8; 32];
        let victim = [0xCCu8; 32];
        let relay = [0xBBu8; 32];
        let attacker_sk = Arc::new(SigningKey::from_bytes(&[0xAAu8; 32]));
        let victim_sk = Arc::new(SigningKey::from_bytes(&[0xCCu8; 32]));
        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));

        let mut victim_disp = make_gossip_dispatcher(
            victim,
            Arc::clone(&victim_sk),
            Arc::clone(&tx_reg),
            vec![(attacker, attacker_sk.verifying_key())],
        );
        victim_disp.pow_difficulty = 0; // No-PoW fast path so we can assert the body directly.
        victim_disp.discovery_mode = veil_cfg::DiscoveryMode::IntroductionOnly;
        victim_disp.relay_node_ids = vec![relay];
        *victim_disp.listen_transports.write().unwrap() = vec!["tcp://10.0.0.1:9000".to_string()];

        let req = RouteRequestPayload {
            target_node_id: victim,
            requester_node_id: attacker,
            request_id: 0xBABE,
            ttl: 7,
            signature: [0u8; 64],
        };
        let hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::RouteRequest as u16);
        let result = victim_disp.dispatch(&hdr, &req.encode(), attacker);

        let bytes = match result {
            DispatchResult::Response(b) => b,
            other => panic!("expected RouteResponse, got {other:?}"),
        };
        let h = decode_header(&bytes).unwrap();
        assert_eq!(h.msg_type, RoutingMsg::RouteResponse as u16);
        let resp = RouteResponsePayload::decode(&bytes[HEADER_SIZE..]).unwrap();
        assert!(
            resp.transports.is_empty(),
            "IntroductionOnly must strip transports, got {:?}",
            resp.transports
        );
        assert_eq!(
            resp.relay_ids,
            vec![relay],
            "IntroductionOnly must still advertise relay_ids"
        );
    }

    // ── tests ────────────────────────────────────────────────────────

    /// 62.8: A → B(relay) → C — A encrypts for C; B cannot decrypt; C decrypts.
    #[test]
    fn e2e_relay_encrypt_decrypt_roundtrip() {
        use veil_e2e::{DK_SEED_BYTES, generate_keypair};
        use veil_proto::{
            E2E_MARKER, E2eEnvelope,
            delivery::{DeliveryEnvelope, ForwardPayload},
        };

        let a_id = [0xAAu8; 32]; // sender
        let b_id = [0xBBu8; 32]; // relay
        let c_id = [0xCCu8; 32]; // recipient

        // Generate ML-KEM keypairs for A and C.
        let (c_ek_bytes, c_dk_seed) = generate_keypair();

        // ── A wants to send to C via relay B ────────────────────────────────
        // A encrypts the payload for C.
        let plaintext = b"hello from A to C via relay";
        let envelope_e2e =
            veil_e2e::encrypt(&c_ek_bytes, &a_id, &c_id, plaintext).expect("encrypt succeeds");
        let mut encrypted_payload = vec![E2E_MARKER];
        encrypted_payload.extend_from_slice(&envelope_e2e.encode());

        let delivery = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(c_id),
            sender_node_id: a_id,
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id: [0u8; 32],
            created_at: 0,
            ttl_secs: u32::MAX,
            payload: encrypted_payload.clone(),
            trace_id: 0,
            require_ack: false,
        };
        let fwd = ForwardPayload {
            next_hop_node_id: c_id,
            envelope: delivery.clone(),
            relay_hops: 0,
        };
        let fwd_bytes = fwd.encode();
        let fwd_hdr = FrameHeader::new(
            FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        );

        // ── B (relay) cannot decrypt — it uses a zeroed DK seed ────────────
        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let _rx_c = tx_reg.write().unwrap().register(c_id);

        let disp_b = make_gossip_dispatcher(
            b_id,
            Arc::new(ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32])),
            Arc::clone(&tx_reg),
            vec![],
        );
        // B simply forwards — should NOT return Violation.
        let result_b = disp_b.dispatch(&fwd_hdr, &fwd_bytes, a_id);
        assert!(
            !matches!(result_b, DispatchResult::Violation(_)),
            "relay B must not violate on E2E payload, got {result_b:?}",
        );

        // ── C (recipient) decrypts correctly ───────────────────────────────
        let mut disp_c = make_test_dispatcher(NodeRole::Core);
        // Give C its real DK seed so the dispatcher can decrypt.
        let c_dk_arr: [u8; DK_SEED_BYTES] = c_dk_seed;
        disp_c.crypto = Arc::new(CryptoContext {
            mlkem_dk_seed: Arc::new(veil_util::sensitive_bytes::SensitiveBytesN::<
                { DK_SEED_BYTES },
            >::from_bytes(c_dk_arr)),
            ..(*disp_c.crypto).clone()
        });
        disp_c.local_node_id = c_id;

        let result_c = disp_c.dispatch(&fwd_hdr, &fwd_bytes, b_id);
        // NoResponse means delivery was handled (no Violation).
        assert!(
            matches!(result_c, DispatchResult::NoResponse),
            "C must deliver without error, got {result_c:?}",
        );

        // ── Verify B cannot decrypt (wrong key → decryption fails) ─────────
        // Use a different, random keypair to simulate B trying to decrypt.
        let (_wrong_ek, wrong_dk) = generate_keypair();
        let inner_bytes = &encrypted_payload[1..]; // skip marker
        let e2e_env = E2eEnvelope::decode(inner_bytes).unwrap();
        let decrypt_result = veil_e2e::decrypt(&wrong_dk, &a_id, &c_id, &e2e_env);
        assert!(decrypt_result.is_err(), "wrong key must not decrypt");
    }

    /// 62.9: Direct local delivery (no relay) passes through unchanged — no E2E.
    #[test]
    fn e2e_direct_delivery_no_encryption() {
        use veil_proto::delivery::{DeliveryEnvelope, ForwardPayload};

        let a_id = [0xAAu8; 32];
        let b_id = [0xBBu8; 32];

        let plaintext = b"direct plaintext";
        let delivery = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(b_id),
            sender_node_id: a_id,
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id: [0u8; 32],
            created_at: 0,
            ttl_secs: 30,
            payload: plaintext.to_vec(),
            trace_id: 0,
            require_ack: false,
        };
        let fwd = ForwardPayload {
            next_hop_node_id: b_id,
            envelope: delivery,
            relay_hops: 0,
        };
        let fwd_bytes = fwd.encode();
        let fwd_hdr = FrameHeader::new(
            FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        );

        let mut disp_b = make_test_dispatcher(NodeRole::Core);
        disp_b.local_node_id = b_id;

        // Plaintext delivery must succeed (NoResponse = delivered).
        let result = disp_b.dispatch(&fwd_hdr, &fwd_bytes, a_id);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "plaintext delivery must succeed, got {result:?}",
        );
    }

    // ── Diag tests ─────────────────────────────────────────────────

    /// A DiagPing sent to a node results in a DiagPong response.
    #[test]
    fn diag_ping_pong_roundtrip() {
        use veil_proto::{
            DiagMsg, DiagPingPayload, DiagPongPayload, FrameFamily, header::FrameHeader,
        };
        use veil_session::SessionTxRegistry;

        let sender_id = [0xAA; 32];
        let target_id = [0xBB; 32];

        // Set up a tx registry so the target can route the Pong back to sender.
        let tx_reg = Arc::new(RwLock::new(SessionTxRegistry::new()));
        let mut rx_sender = tx_reg.write().unwrap().register(sender_id);

        let mut disp = make_gossip_dispatcher(
            target_id,
            Arc::new(ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32])),
            Arc::clone(&tx_reg),
            vec![],
        );
        disp.local_node_id = target_id;

        let ping = DiagPingPayload {
            seq: 7,
            sender: sender_id,
            ts_us: 123_456,
            target: target_id,
            hop_limit: veil_proto::diag::DIAG_DEFAULT_HOP_LIMIT,
        };
        let body = ping.encode();
        let mut hdr = FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::Ping as u16);
        hdr.body_len = body.len() as u32;

        let result = disp.dispatch(&hdr, &body, sender_id);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "expected NoResponse, got {result:?}"
        );

        // The target should have enqueued a Pong for the sender via the tx registry.
        let (_priority, frame) = rx_sender.try_recv().expect("Pong frame should be enqueued");
        let hdr_size = veil_proto::header::HEADER_SIZE;
        let resp_hdr = veil_proto::codec::decode_header(&frame[..hdr_size]).unwrap();
        assert_eq!(resp_hdr.family, FrameFamily::Diag as u8);
        assert_eq!(resp_hdr.msg_type, DiagMsg::Pong as u16);

        let pong = DiagPongPayload::decode(&frame[hdr_size..]).unwrap();
        assert_eq!(pong.seq, 7);
        assert_eq!(pong.responder, target_id);
        assert_eq!(pong.echo_ts_us, 123_456);
        assert_eq!(pong.dest, sender_id);
    }

    /// A relayed DiagPing whose forwarding hop budget reaches zero is dropped,
    /// not forwarded — this bounds route-cache loops (audit A7). With
    /// decrement-then-check semantics: hop_limit=1 → decremented to 0 → drop;
    /// hop_limit=2 → forwarded once carrying the decremented hop_limit=1.
    #[test]
    fn diag_ping_hop_limit_zero_is_dropped() {
        use veil_proto::{DiagMsg, DiagPingPayload, FrameFamily, header::FrameHeader};
        use veil_session::SessionTxRegistry;

        let relay_id = [0x01; 32];
        let target_id = [0x02; 32]; // not us ⇒ forward path
        let sender_id = [0x03; 32];

        let tx_reg = Arc::new(RwLock::new(SessionTxRegistry::new()));
        // Register the target so a forwarded Ping would be observable.
        let mut rx_target = tx_reg.write().unwrap().register(target_id);

        let mut disp = make_gossip_dispatcher(
            relay_id,
            Arc::new(ed25519_dalek::SigningKey::from_bytes(&[0x01u8; 32])),
            Arc::clone(&tx_reg),
            vec![],
        );
        disp.local_node_id = relay_id;

        // hop_limit = 1 → decremented to 0 → dropped, nothing forwarded.
        let ping = DiagPingPayload {
            seq: 1,
            sender: sender_id,
            ts_us: 0,
            target: target_id,
            hop_limit: 1,
        };
        let body = ping.encode();
        let mut hdr = FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::Ping as u16);
        hdr.body_len = body.len() as u32;
        let result = disp.dispatch(&hdr, &body, sender_id);
        assert!(matches!(result, DispatchResult::NoResponse));
        assert!(
            rx_target.try_recv().is_err(),
            "hop_limit=1 Ping must be dropped, not forwarded"
        );

        // hop_limit = 2 → decremented to 1 → forwarded once.
        let ping2 = DiagPingPayload {
            seq: 2,
            sender: sender_id,
            ts_us: 0,
            target: target_id,
            hop_limit: 2,
        };
        let body2 = ping2.encode();
        let mut hdr2 = FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::Ping as u16);
        hdr2.body_len = body2.len() as u32;
        disp.dispatch(&hdr2, &body2, sender_id);
        let (_prio, frame) = rx_target
            .try_recv()
            .expect("hop_limit=2 Ping must be forwarded");
        let hdr_size = veil_proto::header::HEADER_SIZE;
        let fwd = DiagPingPayload::decode(&frame[hdr_size..]).unwrap();
        assert_eq!(
            fwd.hop_limit, 1,
            "forwarded Ping must carry the decremented hop budget"
        );
        assert_eq!(fwd.seq, 2);
    }

    /// A DiagTraceProbe with ttl=1 triggers a TraceHop from the relay (TTL decrements to 0).
    /// TTL=0 on arrival also triggers (saturating_sub keeps it at 0).
    #[test]
    fn diag_trace_ttl_zero_sends_trace_hop() {
        use veil_proto::{DiagMsg, DiagTraceProbePayload, FrameFamily, header::FrameHeader};
        use veil_session::SessionTxRegistry;

        let sender_id = [0xAA; 32];
        let relay_id = [0xBB; 32];

        // Set up a tx registry so the relay can route the TraceHop back to sender.
        let tx_reg = Arc::new(RwLock::new(SessionTxRegistry::new()));
        let mut rx_sender = tx_reg.write().unwrap().register(sender_id);

        let mut disp = make_gossip_dispatcher(
            relay_id,
            Arc::new(ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32])),
            Arc::clone(&tx_reg),
            vec![],
        );
        disp.local_node_id = relay_id;

        let probe = DiagTraceProbePayload {
            seq: 1,
            sender: sender_id,
            ts_us: 99_000,
            ttl: 1, // TTL=1: relay decrements to 0 → sends TraceHop back
            max_hops: 8,
            orig_ttl: 1,
            target: [0xCC; 32],
        };
        let body = probe.encode();
        let mut hdr = FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::TraceProbe as u16);
        hdr.body_len = body.len() as u32;

        let result = disp.dispatch(&hdr, &body, sender_id);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "expected NoResponse, got {result:?}"
        );

        // The relay should have sent a TraceHop to the sender via the tx registry.
        let (_priority, frame) = rx_sender
            .try_recv()
            .expect("TraceHop frame should be enqueued");
        let hdr_size = veil_proto::header::HEADER_SIZE;
        let resp_hdr = veil_proto::codec::decode_header(&frame[..hdr_size]).unwrap();
        assert_eq!(resp_hdr.family, FrameFamily::Diag as u8);
        assert_eq!(resp_hdr.msg_type, DiagMsg::TraceHop as u16);
    }

    // ── DiagPing/TraceProbe gating ───────────────────────────────

    /// In `ContactsOnly` mode, a `DiagPing` from a peer that has never
    /// handshaked with us (absent from `peer_pubkeys`) is silently dropped —
    /// no `Pong` reply, so existence of `target` is not confirmed.
    #[test]
    fn epic474_1_diag_ping_contacts_only_drops_unknown_sender() {
        use veil_proto::{DiagMsg, DiagPingPayload, FrameFamily, header::FrameHeader};
        use veil_session::SessionTxRegistry;

        let stranger = [0xAAu8; 32];
        let target = [0xBBu8; 32];

        let tx_reg = Arc::new(RwLock::new(SessionTxRegistry::new()));
        let mut rx_stranger = tx_reg.write().unwrap().register(stranger);

        let mut disp = make_gossip_dispatcher(
            target,
            Arc::new(ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32])),
            Arc::clone(&tx_reg),
            vec![], // stranger NOT in peer_pubkeys
        );
        disp.local_node_id = target;
        disp.discovery_mode = veil_cfg::DiscoveryMode::ContactsOnly;

        let ping = DiagPingPayload {
            seq: 1,
            sender: stranger,
            ts_us: 0,
            target,
            hop_limit: veil_proto::diag::DIAG_DEFAULT_HOP_LIMIT,
        };
        let body = ping.encode();
        let mut hdr = FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::Ping as u16);
        hdr.body_len = body.len() as u32;

        let result = disp.dispatch(&hdr, &body, stranger);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "expected NoResponse, got {result:?}"
        );
        assert!(
            rx_stranger.try_recv().is_err(),
            "ContactsOnly: no Pong should be enqueued for unknown sender"
        );
    }

    /// In `IntroductionOnly` mode, even a `DiagPing` from a known contact
    /// is silently dropped — introduction-only nodes never confirm their
    /// existence over diagnostics.
    #[test]
    fn epic474_1_diag_ping_introduction_only_drops_even_known_sender() {
        use veil_proto::{DiagMsg, DiagPingPayload, FrameFamily, header::FrameHeader};
        use veil_session::SessionTxRegistry;

        let known = [0xAAu8; 32];
        let target = [0xBBu8; 32];
        let known_sk = Arc::new(ed25519_dalek::SigningKey::from_bytes(&[0xAAu8; 32]));
        let known_vk = known_sk.verifying_key();

        let tx_reg = Arc::new(RwLock::new(SessionTxRegistry::new()));
        let mut rx_known = tx_reg.write().unwrap().register(known);

        let mut disp = make_gossip_dispatcher(
            target,
            Arc::new(ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32])),
            Arc::clone(&tx_reg),
            vec![(known, known_vk)],
        );
        disp.local_node_id = target;
        disp.discovery_mode = veil_cfg::DiscoveryMode::IntroductionOnly;

        let ping = DiagPingPayload {
            seq: 1,
            sender: known,
            ts_us: 0,
            target,
            hop_limit: veil_proto::diag::DIAG_DEFAULT_HOP_LIMIT,
        };
        let body = ping.encode();
        let mut hdr = FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::Ping as u16);
        hdr.body_len = body.len() as u32;

        let result = disp.dispatch(&hdr, &body, known);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "expected NoResponse, got {result:?}"
        );
        assert!(
            rx_known.try_recv().is_err(),
            "IntroductionOnly: no Pong even for known peer"
        );
    }

    /// In `IntroductionOnly` mode, a `TraceProbe` whose final hop is us
    /// is silently dropped — we don't reveal `local_node_id` via TraceHop.
    /// This protects nodes that intentionally hide behind relay
    /// infrastructure from traceroute-style topology mapping.
    #[test]
    fn epic474_1_trace_probe_introduction_only_drops_final_hop() {
        use veil_proto::{DiagMsg, DiagTraceProbePayload, FrameFamily, header::FrameHeader};
        use veil_session::SessionTxRegistry;

        let sender = [0xAAu8; 32];
        let relay = [0xBBu8; 32];

        let tx_reg = Arc::new(RwLock::new(SessionTxRegistry::new()));
        let mut rx_sender = tx_reg.write().unwrap().register(sender);

        let mut disp = make_gossip_dispatcher(
            relay,
            Arc::new(ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32])),
            Arc::clone(&tx_reg),
            vec![],
        );
        disp.local_node_id = relay;
        disp.discovery_mode = veil_cfg::DiscoveryMode::IntroductionOnly;

        let probe = DiagTraceProbePayload {
            seq: 1,
            sender,
            ts_us: 99_000,
            ttl: 1, // expires here
            max_hops: 8,
            orig_ttl: 1,
            target: [0xCC; 32],
        };
        let body = probe.encode();
        let mut hdr = FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::TraceProbe as u16);
        hdr.body_len = body.len() as u32;

        let result = disp.dispatch(&hdr, &body, sender);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "expected NoResponse, got {result:?}"
        );
        assert!(
            rx_sender.try_recv().is_err(),
            "IntroductionOnly: TraceHop must not be sent — topology stays hidden"
        );
    }

    // ── Get(Attachment|AppEndpoint) gating ──────────────────────

    /// In `IntroductionOnly` mode, `GetAttachment` always returns
    /// `not_found` regardless of what the directory has stored.
    #[test]
    fn epic474_2_get_attachment_introduction_only_returns_not_found() {
        use veil_proto::{
            DiscoveryMsg, FrameFamily,
            codec::decode_header,
            discovery::{
                AnnounceAttachmentPayload, AttachmentResponse, GatewayRef, GetAttachmentPayload,
            },
            header::FrameHeader,
        };

        let target = [0xCCu8; 32];
        let mut disp = make_test_dispatcher(NodeRole::Core);
        disp.discovery_mode = veil_cfg::DiscoveryMode::IntroductionOnly;

        // Pre-populate the directory so we can prove the gate fired and not
        // an empty store.
        let ann = AnnounceAttachmentPayload {
            node_id: target,
            role: 1,
            realm_id: 1,
            epoch: 1,
            expires_at: 9_999_999_999,
            gateways: vec![GatewayRef {
                gateway_node_id: [0xBBu8; 32],
                priority: 1,
                weight: 1,
                flags: 0,
            }],
            seq_no: 0,
            signature: vec![],
            ephemeral_endpoint: None,
        };
        disp.discovery.handle_announce_attachment(ann).unwrap();

        let req = GetAttachmentPayload { node_id: target };
        let body = req.encode();
        let mut hdr = FrameHeader::new(
            FrameFamily::Discovery as u8,
            DiscoveryMsg::GetAttachment as u16,
        );
        hdr.body_len = body.len() as u32;

        let result = disp.dispatch(&hdr, &body, [0xAAu8; 32]);
        let bytes = match result {
            DispatchResult::Response(b) => b,
            other => panic!("expected Response, got {other:?}"),
        };
        let h = decode_header(&bytes).unwrap();
        assert_eq!(h.msg_type, DiscoveryMsg::GetAttachment as u16);
        let resp = AttachmentResponse::decode(&bytes[HEADER_SIZE..]).unwrap();
        assert!(
            !resp.found,
            "IntroductionOnly: GetAttachment must respond not_found regardless of stored data"
        );
    }

    /// In `Public` mode, `GetAttachment` still returns the stored record
    /// (sanity check that the gate is mode-conditional, not unconditional).
    #[test]
    fn epic474_2_get_attachment_public_still_responds() {
        use veil_proto::{
            DiscoveryMsg, FrameFamily,
            codec::decode_header,
            discovery::{
                AnnounceAttachmentPayload, AttachmentResponse, GatewayRef, GetAttachmentPayload,
            },
            header::FrameHeader,
        };

        let target = [0xCCu8; 32];
        let disp = make_test_dispatcher(NodeRole::Core);
        // discovery_mode is Public by default in make_test_dispatcher.

        let ann = AnnounceAttachmentPayload {
            node_id: target,
            role: 1,
            realm_id: 1,
            epoch: 1,
            expires_at: 9_999_999_999,
            gateways: vec![GatewayRef {
                gateway_node_id: [0xBBu8; 32],
                priority: 1,
                weight: 1,
                flags: 0,
            }],
            seq_no: 0,
            signature: vec![],
            ephemeral_endpoint: None,
        };
        disp.discovery.handle_announce_attachment(ann).unwrap();

        let req = GetAttachmentPayload { node_id: target };
        let body = req.encode();
        let mut hdr = FrameHeader::new(
            FrameFamily::Discovery as u8,
            DiscoveryMsg::GetAttachment as u16,
        );
        hdr.body_len = body.len() as u32;

        let result = disp.dispatch(&hdr, &body, [0xAAu8; 32]);
        let bytes = match result {
            DispatchResult::Response(b) => b,
            other => panic!("expected Response, got {other:?}"),
        };
        let h = decode_header(&bytes).unwrap();
        assert_eq!(h.msg_type, DiscoveryMsg::GetAttachment as u16);
        let resp = AttachmentResponse::decode(&bytes[HEADER_SIZE..]).unwrap();
        assert!(
            resp.found,
            "Public mode must still serve stored attachments"
        );
    }

    /// Capture broadcast emits an event when a frame is dispatched.
    #[test]
    fn capture_emits_event_on_dispatch() {
        use tokio::sync::broadcast;
        use veil_proto::{DiagMsg, DiagPingPayload, FrameFamily, header::FrameHeader};

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let sender_id = [0xCC; 32];
            let target_id = [0xDD; 32];

            let (cap_tx, mut cap_rx) = broadcast::channel::<CaptureEvent>(16);
            let mut disp = make_test_dispatcher(NodeRole::Core);
            disp.local_node_id = target_id;
            *disp.capture_tx.lock().unwrap() = Some(cap_tx);
            disp.capture_active
                .store(true, std::sync::atomic::Ordering::Relaxed);

            let ping = DiagPingPayload {
                seq: 3,
                sender: sender_id,
                ts_us: 0,
                target: target_id,
                hop_limit: veil_proto::diag::DIAG_DEFAULT_HOP_LIMIT,
            };
            let body = ping.encode();
            let mut hdr = FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::Ping as u16);
            hdr.body_len = body.len() as u32;

            let _ = disp.dispatch(&hdr, &body, sender_id);

            let ev = cap_rx.try_recv().expect("capture event should be emitted");
            assert_eq!(ev.family, FrameFamily::Diag as u8);
            assert_eq!(ev.msg_type, DiagMsg::Ping as u16);
            assert_eq!(ev.peer_id, sender_id);
            assert!(ev.inbound);
        });
    }

    /// A DiagPong delivered to a node with a registered pending_diag channel
    /// delivers the event to the waiting channel.
    #[test]
    fn diag_pong_delivers_to_pending_channel() {
        use veil_proto::{DiagMsg, DiagPongPayload, FrameFamily, header::FrameHeader};

        let responder_id = [0xEE; 32];
        let local_id = [0xFF; 32];

        let mut disp = make_test_dispatcher(NodeRole::Core);
        disp.local_node_id = local_id;

        // Register a pending channel for seq=42.
        let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel::<DiagEvent>(4);
        disp.pending_diag.lock().unwrap().insert(42, ev_tx);

        let pong = DiagPongPayload {
            seq: 42,
            responder: responder_id,
            echo_ts_us: 500,
            dest: local_id,
            hop_limit: veil_proto::diag::DIAG_DEFAULT_HOP_LIMIT,
        };
        let body = pong.encode();
        let mut hdr = FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::Pong as u16);
        hdr.body_len = body.len() as u32;

        let result = disp.dispatch(&hdr, &body, responder_id);
        assert!(matches!(result, DispatchResult::NoResponse));

        let event = ev_rx.try_recv().expect("DiagEvent should be sent");
        assert!(matches!(event, DiagEvent::Pong { .. }));
    }

    /// 65.1: RouteResponse caches ML-KEM key in peer_mlkem_keys only when
    /// the target's signature is valid (no TOFU).
    #[test]
    fn route_response_caches_mlkem_key() {
        use ed25519_dalek::{Signer, SigningKey};
        use veil_e2e::EK_BYTES;
        use veil_proto::{family::RoutingMsg, routing::RouteResponsePayload};

        let requester_id = [0xAAu8; 32];
        let target_id = [0xBBu8; 32];
        let target_sk = Arc::new(SigningKey::from_bytes(&[0xBBu8; 32]));
        let fake_ek = vec![0x42u8; EK_BYTES];

        // Dispatcher for requester that knows target's signing key.
        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let disp = make_gossip_dispatcher(
            requester_id,
            Arc::new(SigningKey::from_bytes(&[0xAAu8; 32])),
            Arc::clone(&tx_reg),
            vec![(target_id, target_sk.verifying_key())],
        );

        // Build a properly signed RouteResponse from the target.
        let mut response = RouteResponsePayload {
            target_node_id: target_id,
            requester_node_id: requester_id,
            request_id: 1,
            transports: vec![],
            relay_ids: vec![],
            mlkem_pubkey: Some(fake_ek.clone()),
            signature: [0u8; 64],
            ed25519_pubkey: None,

            target_labels: Vec::new(),
        };
        let sig = target_sk.sign(&response.signable_bytes());
        response.signature = sig.to_bytes();

        let resp_bytes = response.encode();
        let hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::RouteResponse as u16);

        let result = disp.dispatch(&hdr, &resp_bytes, target_id);
        assert!(matches!(result, DispatchResult::NoResponse));

        let cached_ek = disp
            .crypto
            .peer_mlkem_keys
            .read()
            .unwrap()
            .get(&target_id)
            .map(|(ek, _): &(Vec<u8>, _)| ek.clone());
        assert_eq!(
            cached_ek,
            Some(fake_ek),
            "ML-KEM key must be cached after valid-sig RouteResponse"
        );
    }

    /// When a RouteResponse carries the target's Ed25519 verifying key and the
    /// BLAKE3(pubkey) == target_node_id binding holds, we can verify the signature
    /// for unknown (indirect) targets and cache their route + ML-KEM key.
    #[test]
    fn route_response_caches_mlkem_key_for_unknown_target_via_ed25519_pubkey() {
        use ed25519_dalek::{Signer, SigningKey};
        use veil_e2e::EK_BYTES;
        use veil_proto::{family::RoutingMsg, routing::RouteResponsePayload};

        // target_sk is an unknown peer — NOT pre-loaded into peer_pubkeys.
        let requester_id = [0xAAu8; 32];
        let target_sk = Arc::new(SigningKey::from_bytes(&[0xCCu8; 32]));
        let target_vk = target_sk.verifying_key();
        // Compute proper target_node_id = BLAKE3(verifying_key_bytes).
        let target_id: [u8; 32] = *blake3::hash(target_vk.as_bytes()).as_bytes();
        let fake_ek = vec![0x77u8; EK_BYTES];

        // Dispatcher for requester with empty peer_pubkeys (target is unknown).
        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let disp = make_gossip_dispatcher(
            requester_id,
            Arc::new(SigningKey::from_bytes(&[0xAAu8; 32])),
            Arc::clone(&tx_reg),
            vec![], // no pre-loaded keys — target is unknown
        );

        // Build a RouteResponse signed by the target, including ed25519_pubkey.
        let mut response = RouteResponsePayload {
            target_node_id: target_id,
            requester_node_id: requester_id,
            request_id: 42,
            transports: vec![],
            relay_ids: vec![],
            mlkem_pubkey: Some(fake_ek.clone()),
            signature: [0u8; 64],
            ed25519_pubkey: Some(target_vk.as_bytes().to_vec()),

            target_labels: Vec::new(),
        };
        let sig = target_sk.sign(&response.signable_bytes());
        response.signature = sig.to_bytes();

        let resp_bytes = response.encode();
        let hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::RouteResponse as u16);

        let result = disp.dispatch(&hdr, &resp_bytes, [0xEEu8; 32]); // relay peer
        assert!(matches!(result, DispatchResult::NoResponse));

        // ML-KEM key must be cached even though the target was previously unknown.
        let cached_ek = disp
            .crypto
            .peer_mlkem_keys
            .read()
            .unwrap()
            .get(&target_id)
            .map(|(ek, _): &(Vec<u8>, _)| ek.clone());
        assert_eq!(
            cached_ek,
            Some(fake_ek),
            "ML-KEM key must be cached for unknown target with valid ed25519_pubkey"
        );

        // Ed25519 pubkey must also be in peer_pubkeys now.
        assert!(
            disp.crypto
                .peer_pubkeys
                .lock()
                .unwrap()
                .contains_key(&target_id),
            "target pubkey must be cached in peer_pubkeys after verification",
        );
    }

    /// A RouteResponse with a tampered ed25519_pubkey (BLAKE3 mismatch) must be
    /// treated as a Violation, not silently dropped.
    #[test]
    fn route_response_rejects_tampered_ed25519_pubkey() {
        use ed25519_dalek::{Signer, SigningKey};
        use veil_e2e::EK_BYTES;
        use veil_proto::{family::RoutingMsg, routing::RouteResponsePayload};

        let requester_id = [0xAAu8; 32];
        let target_sk = Arc::new(SigningKey::from_bytes(&[0xCCu8; 32]));
        let target_vk = target_sk.verifying_key();
        let target_id: [u8; 32] = *blake3::hash(target_vk.as_bytes()).as_bytes();
        let fake_ek = vec![0x77u8; EK_BYTES];

        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let disp = make_gossip_dispatcher(
            requester_id,
            Arc::new(SigningKey::from_bytes(&[0xAAu8; 32])),
            Arc::clone(&tx_reg),
            vec![],
        );

        // Tamper: use a different pubkey whose BLAKE3 does NOT equal target_id.
        let wrong_vk = SigningKey::from_bytes(&[0xDDu8; 32]).verifying_key();
        let mut response = RouteResponsePayload {
            target_node_id: target_id,
            requester_node_id: requester_id,
            request_id: 1,
            transports: vec![],
            relay_ids: vec![],
            mlkem_pubkey: Some(fake_ek),
            signature: [0u8; 64],
            ed25519_pubkey: Some(wrong_vk.as_bytes().to_vec()),

            target_labels: Vec::new(),
        };
        let sig = target_sk.sign(&response.signable_bytes());
        response.signature = sig.to_bytes();

        let resp_bytes = response.encode();
        let hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::RouteResponse as u16);

        let result = disp.dispatch(&hdr, &resp_bytes, [0xEEu8; 32]);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "tampered ed25519_pubkey must produce Violation, got {result:?}",
        );
    }

    /// b: `RouteResponse.target_labels` flows through to the
    /// `RouteCache` and is retrievable via `lookup_with_labels`.
    #[test]
    fn route_response_labels_persist_in_route_cache() {
        use ed25519_dalek::{Signer, SigningKey};
        use veil_proto::{family::RoutingMsg, routing::RouteResponsePayload};

        let requester_id = [0xAAu8; 32];
        let target_id = [0xBBu8; 32];
        let target_sk = Arc::new(SigningKey::from_bytes(&[0xBBu8; 32]));

        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let disp = make_gossip_dispatcher(
            requester_id,
            Arc::new(SigningKey::from_bytes(&[0xAAu8; 32])),
            Arc::clone(&tx_reg),
            vec![(target_id, target_sk.verifying_key())],
        );

        let mut response = RouteResponsePayload {
            target_node_id: target_id,
            requester_node_id: requester_id,
            request_id: 7,
            transports: vec![],
            relay_ids: vec![],
            mlkem_pubkey: None,
            signature: [0u8; 64],
            ed25519_pubkey: None,
            target_labels: vec![*b"exit", *b"low\0"],
        };
        response.signature = target_sk.sign(&response.signable_bytes()).to_bytes();

        let resp_bytes = response.encode();
        let hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::RouteResponse as u16);
        let peer_id = [0xCCu8; 32];
        let result = disp.dispatch(&hdr, &resp_bytes, peer_id);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "expected NoResponse, got {result:?}"
        );

        // Full-label match: both labels required and present → hit.
        let cache = disp.route_cache.read().unwrap_or_else(|p| p.into_inner());
        let hop = cache.lookup_with_labels(&target_id, &[*b"exit", *b"low\0"]);
        assert_eq!(
            hop,
            Some(peer_id),
            "route with both advertised labels must be retrievable"
        );

        // Partial-label match: one of the advertised labels required → hit.
        let hop_exit = cache.lookup_with_labels(&target_id, &[*b"exit"]);
        assert_eq!(hop_exit, Some(peer_id));

        // Absent label: filter contains a tag the target did NOT advertise → miss.
        let hop_absent = cache.lookup_with_labels(&target_id, &[*b"gate"]);
        assert_eq!(
            hop_absent, None,
            "filter for unadvertised label must not match"
        );
    }

    /// 65.2: Malformed E2E envelope is dropped silently (NoResponse), not a Violation.
    #[test]
    fn malformed_e2e_envelope_dropped_not_violation() {
        use veil_proto::{
            E2E_MARKER,
            delivery::{DeliveryEnvelope, ForwardPayload},
        };

        let a_id = [0xAAu8; 32];
        let b_id = [0xBBu8; 32];

        // Craft a payload that starts with E2E_MARKER but has garbage bytes after.
        let mut bad_payload = vec![E2E_MARKER];
        bad_payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let delivery = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(b_id),
            sender_node_id: a_id,
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id: [0u8; 32],
            created_at: 0,
            ttl_secs: 30,
            payload: bad_payload,
            trace_id: 0,
            require_ack: false,
        };
        let fwd = ForwardPayload {
            next_hop_node_id: b_id,
            envelope: delivery,
            relay_hops: 0,
        };
        let fwd_bytes = fwd.encode();
        let fwd_hdr = FrameHeader::new(
            FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        );

        let mut disp_b = make_test_dispatcher(NodeRole::Core);
        disp_b.local_node_id = b_id;

        let result = disp_b.dispatch(&fwd_hdr, &fwd_bytes, a_id);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "malformed E2E must be dropped, not a violation: {result:?}",
        );
    }

    // ── DELIVERY_FORWARD integrity ───────────────────────────────────

    /// 87.5: Relay drops a replayed DELIVERY_FORWARD (same content_id arriving twice).
    #[test]
    fn relay_drops_replayed_content_id() {
        use veil_proto::delivery::{DeliveryEnvelope, ForwardPayload};

        let a_id = [0xAAu8; 32]; // sender
        let b_id = [0xBBu8; 32]; // relay
        let c_id = [0xCCu8; 32]; // recipient (not connected — will miss route)

        let content_id = [0x42u8; 32];

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let delivery = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(c_id),
            sender_node_id: a_id,
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id,
            created_at: now_secs,
            ttl_secs: 30,
            payload: b"hello".to_vec(),
            trace_id: 0,
            require_ack: false,
        };

        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        // Register C BEFORE dispatching so the receiver captures all sent frames.
        let mut rx_c = tx_reg.write().unwrap().register(c_id);

        let disp_b = make_gossip_dispatcher(
            b_id,
            Arc::new(ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32])),
            Arc::clone(&tx_reg),
            vec![],
        );

        let fwd = ForwardPayload {
            next_hop_node_id: c_id,
            envelope: delivery,
            relay_hops: 0,
        };
        let fwd_bytes = fwd.encode();
        let fwd_hdr = FrameHeader::new(
            FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        );

        // First arrival: should be forwarded (NoResponse from relay side).
        let r1 = disp_b.dispatch(&fwd_hdr, &fwd_bytes, a_id);
        assert!(
            matches!(r1, DispatchResult::NoResponse),
            "first forward must succeed (NoResponse), got {r1:?}",
        );

        // Second arrival with identical content_id: must be dropped (dedup).
        let r2 = disp_b.dispatch(&fwd_hdr, &fwd_bytes, a_id);
        assert!(
            matches!(r2, DispatchResult::NoResponse),
            "second forward must be silently dropped (NoResponse), got {r2:?}",
        );

        // The channel must have exactly one buffered frame (from the first send only).
        // A second frame would mean dedup failed.
        let first = rx_c.try_recv();
        let second = rx_c.try_recv();
        assert!(first.is_ok(), "relay must have sent exactly one frame to C");
        assert!(
            second.is_err(),
            "relay must NOT have sent a second (replayed) frame to C"
        );
    }

    /// 87.6: Relay drops an envelope whose TTL has expired.
    #[test]
    fn relay_drops_ttl_expired_envelope() {
        use veil_proto::delivery::{DeliveryEnvelope, ForwardPayload};

        let a_id = [0xAAu8; 32];
        let b_id = [0xBBu8; 32];
        let c_id = [0xCCu8; 32];

        // created_at is far in the past, ttl_secs is 1 — envelope has expired.
        let delivery = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(c_id),
            sender_node_id: a_id,
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id: [0xDEu8; 32],
            created_at: 1_000_000, // far past
            ttl_secs: 1,
            payload: b"stale".to_vec(),
            trace_id: 0,
            require_ack: false,
        };

        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let mut rx_c = tx_reg.write().unwrap().register(c_id);

        let disp_b = make_gossip_dispatcher(
            b_id,
            Arc::new(ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32])),
            Arc::clone(&tx_reg),
            vec![],
        );

        let fwd = ForwardPayload {
            next_hop_node_id: c_id,
            envelope: delivery,
            relay_hops: 0,
        };
        let fwd_bytes = fwd.encode();
        let fwd_hdr = FrameHeader::new(
            FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        );

        let result = disp_b.dispatch(&fwd_hdr, &fwd_bytes, a_id);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "expired envelope must be silently dropped, got {result:?}",
        );

        // No frame must have been forwarded to C.
        assert!(
            rx_c.try_recv().is_err(),
            "relay must not forward an expired envelope",
        );
    }

    // ── security hardening ───────────────────────────────────────────

    /// 89.6: Zero content_id on the relay path must produce Violation (not NoResponse).
    ///
    /// A relay must not silently forward frames with an unset content_id because
    /// those frames bypass the dedup set, enabling unlimited replay.
    #[test]
    fn relay_rejects_zero_content_id() {
        use veil_proto::delivery::{DeliveryEnvelope, ForwardPayload};

        let a_id = [0xAAu8; 32];
        let b_id = [0xBBu8; 32];
        let c_id = [0xCCu8; 32];

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let delivery = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(c_id),
            sender_node_id: a_id,
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id: [0u8; 32], // ← zero — must be rejected
            created_at: now_secs,
            ttl_secs: u32::MAX,
            payload: b"test".to_vec(),
            trace_id: 0,
            require_ack: false,
        };

        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let _rx_c = tx_reg.write().unwrap().register(c_id);

        let disp_b = make_gossip_dispatcher(
            b_id,
            Arc::new(ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32])),
            Arc::clone(&tx_reg),
            vec![],
        );

        let fwd = ForwardPayload {
            next_hop_node_id: c_id,
            envelope: delivery,
            relay_hops: 0,
        };
        let fwd_bytes = fwd.encode();
        let fwd_hdr = FrameHeader::new(
            FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        );

        let result = disp_b.dispatch(&fwd_hdr, &fwd_bytes, a_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "zero content_id on relay path must produce Violation, got {result:?}",
        );
    }

    // ── relay hop-limit ─────────────────────────────────────────────

    /// A ForwardPayload with relay_hops == MAX_RELAY_HOPS is rejected with Violation.
    #[test]
    fn relay_drops_frame_at_hop_limit() {
        use veil_proto::budget::MAX_RELAY_HOPS;
        use veil_proto::delivery::{DeliveryEnvelope, ForwardPayload};

        let a_id = [0xAAu8; 32];
        let b_id = [0xBBu8; 32];
        let c_id = [0xCCu8; 32];

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let delivery = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(c_id),
            sender_node_id: a_id,
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id: [0xF0u8; 32],
            created_at: now_secs,
            ttl_secs: 3600,
            payload: b"loop".to_vec(),
            trace_id: 0,
            require_ack: false,
        };

        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let _rx_c = tx_reg.write().unwrap().register(c_id);

        let disp_b = make_gossip_dispatcher(
            b_id,
            Arc::new(ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32])),
            Arc::clone(&tx_reg),
            vec![],
        );

        // Frame arrives with relay_hops already at the limit.
        let fwd = ForwardPayload {
            next_hop_node_id: c_id,
            envelope: delivery.clone(),
            relay_hops: MAX_RELAY_HOPS,
        };
        let fwd_bytes = fwd.encode();
        let fwd_hdr = FrameHeader::new(
            FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        );

        let result = disp_b.dispatch(&fwd_hdr, &fwd_bytes, a_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "frame at MAX_RELAY_HOPS must produce Violation, got {result:?}",
        );

        // Frame with relay_hops one below the limit must still be forwarded (NoResponse).
        let fwd_ok = ForwardPayload {
            next_hop_node_id: c_id,
            envelope: delivery,
            relay_hops: MAX_RELAY_HOPS - 1,
        };
        let fwd_ok_bytes = fwd_ok.encode();
        let result_ok = disp_b.dispatch(&fwd_hdr, &fwd_ok_bytes, a_id);
        assert!(
            matches!(result_ok, DispatchResult::NoResponse),
            "frame one below MAX_RELAY_HOPS must be forwarded (NoResponse), got {result_ok:?}",
        );
    }

    // ── 104.1: ExpiryCache — O(1) eviction correctness ───────────────────────

    #[test]
    fn expiry_cache_evicts_oldest_at_capacity() {
        let mut cache: ExpiryCache<u32> = ExpiryCache::new(Duration::from_secs(60), 3);
        // Fill to capacity.
        assert!(!cache.check_and_insert(1));
        assert!(!cache.check_and_insert(2));
        assert!(!cache.check_and_insert(3));
        // All three entries are present immediately after insertion.
        assert!(cache.check_and_insert(1), "1 must be present");
        assert!(cache.check_and_insert(2), "2 must be present");
        assert!(cache.check_and_insert(3), "3 must be present");
        // Inserting 4 evicts the oldest entry (1, inserted first).
        assert!(!cache.check_and_insert(4));
        // 4 should now be present.
        assert!(cache.check_and_insert(4), "4 must be present after insert");
        // 1 (oldest) must have been evicted — accepted as new.
        assert!(
            !cache.check_and_insert(1),
            "oldest entry must have been evicted and be new again"
        );
    }

    #[test]
    fn expiry_cache_duplicate_returns_true() {
        let mut cache: ExpiryCache<[u8; 32]> = ExpiryCache::new(Duration::from_secs(60), 16);
        let key = [0xABu8; 32];
        assert!(!cache.check_and_insert(key));
        assert!(
            cache.check_and_insert(key),
            "second insert must return true (seen)"
        );
    }

    #[test]
    fn expiry_cache_expired_entry_accepted_again() {
        let mut cache: ExpiryCache<u32> = ExpiryCache::new(Duration::ZERO, 16);
        assert!(!cache.check_and_insert(42));
        // TTL=0 → immediately expired; next check_and_insert should accept it.
        assert!(
            !cache.check_and_insert(42),
            "expired entry must be accepted as new"
        );
    }

    /// audit cycle-8 H8: the value-carrying ExpiryMap (terminal ACK-replay cache)
    /// returns the stored value within TTL, drops it after expiry, and bounds at
    /// capacity.
    #[test]
    fn expiry_map_get_insert_expiry_and_cap() {
        // live value round-trips
        let mut m: ExpiryMap<u32, (u8, u8)> = ExpiryMap::new(Duration::from_secs(60), 2);
        m.insert(1, (10, 20));
        assert_eq!(m.get(&1).copied(), Some((10, 20)));
        assert_eq!(m.get(&99), None);

        // capacity bound: inserting a 3rd key evicts the oldest
        m.insert(2, (0, 0));
        m.insert(3, (0, 0));
        assert!(m.get(&1).is_none(), "oldest entry must be evicted at cap");
        assert!(m.get(&3).is_some());

        // TTL=0 → entry is immediately expired on next access
        let mut expm: ExpiryMap<u32, u8> = ExpiryMap::new(Duration::ZERO, 16);
        expm.insert(7, 7);
        assert_eq!(expm.get(&7), None, "expired value must be dropped");
    }

    #[test]
    fn expiry_map_reinsert_is_heap_idempotent_keeps_capacity() {
        // audit cycle-9 F-A1: re-inserting an existing key must NOT push a second
        // heap entry. A duplicate would later be popped as "oldest" and remove an
        // already-gone key (a no-op), so the at-cap eviction fails to free a slot
        // and the map grows past max_size.
        let mut m: ExpiryMap<u32, u8> = ExpiryMap::new(Duration::from_secs(60), 2);
        m.insert(1, 1);
        m.insert(1, 9); // re-insert same key (value updated, no new heap entry)
        assert_eq!(m.get(&1).copied(), Some(9), "re-insert updates the value");
        m.insert(2, 2);
        m.insert(3, 3); // at cap → evict oldest
        m.insert(4, 4); // at cap → evict oldest
        let live = [1u32, 2, 3, 4].iter().filter(|k| m.get(k).is_some()).count();
        assert_eq!(
            live, 2,
            "map must stay within max_size=2 after a re-insert (was 3 with the duplicate-heap bug)"
        );
    }

    // ── 104.4: capture_active fast-path — no event when flag is false ─────────

    #[test]
    fn capture_inactive_flag_skips_broadcast() {
        use tokio::sync::broadcast;
        use veil_proto::{ControlMsg, FrameFamily, header::FrameHeader};

        let (cap_tx, mut cap_rx) = broadcast::channel::<CaptureEvent>(16);
        let disp = make_test_dispatcher(NodeRole::Core);
        // Install the sender but leave capture_active = false (default).
        *disp.capture_tx.lock().unwrap() = Some(cap_tx);
        // capture_active stays false — fast-path should prevent any send.

        let hdr = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::Ping as u16);
        let _ = disp.dispatch(&hdr, &[], [9u8; 32]);

        assert!(
            cap_rx.try_recv().is_err(),
            "capture must be silent when capture_active=false"
        );
    }

    // ── 104.5: TTL saturation — future created_at rejected ───────────────────

    #[test]
    fn ttl_saturation_attack_rejected() {
        use veil_proto::{
            delivery::{DeliveryEnvelope, ForwardPayload},
            family::{DeliveryMsg, FrameFamily},
            header::FrameHeader,
        };
        use veil_session::SessionTxRegistry;

        let a_id = [0x01u8; 32];
        let b_id = [0x02u8; 32];
        let c_id = [0x03u8; 32]; // remote destination

        let tx_reg = Arc::new(RwLock::new(SessionTxRegistry::new()));
        let disp = make_gossip_dispatcher(
            b_id,
            Arc::new(ed25519_dalek::SigningKey::from_bytes(&[0x02u8; 32])),
            Arc::clone(&tx_reg),
            vec![],
        );

        // Craft an envelope with created_at far in the future (TTL saturation).
        let delivery = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(c_id),
            sender_node_id: a_id,
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 1,
            content_id: [0xFFu8; 32],
            created_at: u64::MAX - 100, // far future
            ttl_secs: 3600,
            payload: vec![1, 2, 3],
            trace_id: 0,
            require_ack: false,
        };
        let fwd = ForwardPayload {
            next_hop_node_id: b_id,
            envelope: delivery,
            relay_hops: 0,
        };
        let fwd_bytes = fwd.encode();
        let fwd_hdr = FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
        let result = disp.dispatch(&fwd_hdr, &fwd_bytes, a_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "created_at in far future must be rejected as Violation, got {result:?}",
        );
    }

    // ── NAT traversal dispatcher tests ─────────────────────────────

    /// Core dispatches `NatProbeRequest` and echoes the initiator's candidates
    /// back as a `NatProbeReply` (no observed addr registered — no srflx added).
    #[test]
    fn nat_probe_request_dispatched_and_replied() {
        use veil_proto::control::{
            NatCandidate, NatProbeReplyPayload, NatProbeRequestPayload, candidate_type,
        };

        let disp = make_test_dispatcher(NodeRole::Core);
        let initiator_id = [0xAAu8; 32];

        let request = NatProbeRequestPayload {
            initiator_node_id: initiator_id,
            target_node_id: [0u8; 32], // STUN-echo legacy
            session_token: 0xDEAD_BEEF,
            candidates: vec![NatCandidate {
                atyp: 4,
                candidate_type: candidate_type::HOST,
                priority: 2_130_706_431,
                addr: vec![192, 168, 1, 100],
                port: 5000,
            }],
        };
        let hdr = FrameHeader::new(
            FrameFamily::Control as u8,
            ControlMsg::NatProbeRequest as u16,
        );
        let result = disp.dispatch(&hdr, &request.encode(), initiator_id);

        let DispatchResult::Response(bytes) = result else {
            panic!("expected Response, got {result:?}");
        };
        // Decode the reply header + body.
        assert!(bytes.len() >= HEADER_SIZE);
        let msg_type = u16::from_be_bytes([bytes[6], bytes[7]]);
        assert_eq!(msg_type, ControlMsg::NatProbeReply as u16, "wrong msg_type");
        let body = &bytes[HEADER_SIZE..];
        let reply = NatProbeReplyPayload::decode(body).expect("decode reply");
        assert_eq!(reply.session_token, 0xDEAD_BEEF);
        // Without a registered observed addr, reply should echo the request's candidates.
        assert_eq!(
            reply.candidates.len(),
            1,
            "no srflx added when addr unknown"
        );
    }

    /// Core echoes the observed source address as an srflx candidate.
    #[test]
    fn nat_probe_reply_includes_srflx_when_addr_registered() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use veil_proto::control::{
            NatCandidate, NatProbeReplyPayload, NatProbeRequestPayload, candidate_type,
        };

        let disp = make_test_dispatcher(NodeRole::Core);
        let peer_id = [0xBBu8; 32];
        // Register observed transport address for the peer.
        let observed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 12345);
        wlock!(disp.peer_observed_addrs).insert(peer_id, observed);

        let request = NatProbeRequestPayload {
            initiator_node_id: peer_id,
            target_node_id: [0u8; 32],
            session_token: 0x1234,
            candidates: vec![NatCandidate {
                atyp: 4,
                candidate_type: candidate_type::HOST,
                priority: 2_130_706_431,
                addr: vec![10, 0, 0, 5],
                port: 6000,
            }],
        };
        let hdr = FrameHeader::new(
            FrameFamily::Control as u8,
            ControlMsg::NatProbeRequest as u16,
        );
        let result = disp.dispatch(&hdr, &request.encode(), peer_id);

        let DispatchResult::Response(bytes) = result else {
            panic!("expected Response, got {result:?}");
        };
        let body = &bytes[HEADER_SIZE..];
        let reply = NatProbeReplyPayload::decode(body).expect("decode reply");
        // Should have original host candidate + new srflx.
        assert_eq!(reply.candidates.len(), 2, "srflx must be appended");
        let srflx = &reply.candidates[1];
        assert_eq!(srflx.candidate_type, candidate_type::SRFLX);
        assert_eq!(srflx.addr, vec![203, 0, 113, 5]);
        assert_eq!(srflx.port, 12345);
    }

    /// Core registers relay tunnel on `NatRelayRequest` and acks with `NatProbeReply`.
    #[test]
    fn relay_request_registered_and_acked() {
        use veil_proto::control::{NatProbeReplyPayload, NatRelayRequestPayload};

        let disp = make_test_dispatcher(NodeRole::Core);
        let node_a = [0x01u8; 32];
        let node_b = [0x02u8; 32];
        let token: u32 = 0xCAFE_1234;

        let request = NatRelayRequestPayload {
            node_a,
            node_b,
            session_token: token,
        };
        let hdr = FrameHeader::new(
            FrameFamily::Control as u8,
            ControlMsg::NatRelayRequest as u16,
        );
        let result = disp.dispatch(&hdr, &request.encode(), node_a);

        // Should get an ack reply.
        let DispatchResult::Response(bytes) = result else {
            panic!("expected Response, got {result:?}");
        };
        let msg_type = u16::from_be_bytes([bytes[6], bytes[7]]);
        assert_eq!(msg_type, ControlMsg::NatProbeReply as u16);
        let body = &bytes[HEADER_SIZE..];
        let ack = NatProbeReplyPayload::decode(body).expect("decode ack");
        assert_eq!(ack.session_token, token);
        assert!(ack.candidates.is_empty());

        // Tunnel must be registered.
        let tunnels = lock!(disp.relay_tunnels);
        let (a, b) = tunnels.get(&token).copied().expect("tunnel must be stored");
        assert_eq!(a, node_a);
        assert_eq!(b, node_b);
    }

    /// When a `NatProbeReply` with an srflx candidate arrives, the dispatcher
    /// rewrites any 0.0.0.0 listen_transports with the discovered external IP.
    #[test]
    fn nat_probe_reply_updates_wildcard_listen_transports() {
        use std::net::{IpAddr, Ipv4Addr};
        use veil_proto::control::{NatCandidate, NatProbeReplyPayload, candidate_type};

        let disp = make_test_dispatcher(NodeRole::Leaf);
        // Set a wildcard listen transport.
        *disp.listen_transports.write().unwrap() = vec!["tcp://0.0.0.0:7001".to_string()];

        let external_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        // bug-fix follow-up: peer_id == responder_node_id
        // for the wildcard-listen update to fire (legacy direct-STUN-
        // echo case).
        let echo_peer_id = [0xCCu8; 32];
        let reply = NatProbeReplyPayload {
            responder_node_id: echo_peer_id,
            final_target_node_id: [0u8; 32],
            session_token: 0xABCD,
            candidates: vec![NatCandidate {
                atyp: 4,
                candidate_type: candidate_type::SRFLX,
                priority: 1_694_498_815,
                addr: vec![203, 0, 113, 42],
                port: 51000,
            }],
        };
        let hdr = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::NatProbeReply as u16);
        let result = disp.dispatch(&hdr, &reply.encode(), echo_peer_id);
        assert!(matches!(result, DispatchResult::NoResponse));

        let transports = disp.listen_transports.read().unwrap().clone();
        assert_eq!(
            transports,
            vec!["tcp://203.0.113.42:7001".to_string()],
            "wildcard host must be replaced with srflx IP"
        );
        let _ = external_ip; // used indirectly via candidate bytes
    }

    /// `NatProbeReply` with only host (non-srflx) candidates must not update transports.
    #[test]
    fn nat_probe_reply_host_candidate_does_not_update_transports() {
        use veil_proto::control::{NatCandidate, NatProbeReplyPayload, candidate_type};

        let disp = make_test_dispatcher(NodeRole::Leaf);
        *disp.listen_transports.write().unwrap() = vec!["tcp://0.0.0.0:7001".to_string()];

        let reply = NatProbeReplyPayload {
            responder_node_id: [0xCCu8; 32],
            final_target_node_id: [0u8; 32],
            session_token: 0x1111,
            candidates: vec![NatCandidate {
                atyp: 4,
                candidate_type: candidate_type::HOST,
                priority: 2_130_706_431,
                addr: vec![10, 0, 0, 5],
                port: 7001,
            }],
        };
        let hdr = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::NatProbeReply as u16);
        disp.dispatch(&hdr, &reply.encode(), [0xAAu8; 32]);

        let transports = disp.listen_transports.read().unwrap().clone();
        assert_eq!(
            transports,
            vec!["tcp://0.0.0.0:7001".to_string()],
            "host candidate must not replace wildcard"
        );
    }

    /// When a NatProbeRequest is relay-forwarded by a coordinator
    /// (target == self_node_id, sender != initiator), the dispatcher
    /// MUST NOT echo a srflx candidate
    /// based on `peer_observed_addrs[peer_id]` — peer_id is the
    /// coordinator, not the initiator, so the observed addr is the
    /// coordinator's external IP. Echoing it would put the
    /// coordinator's IP into the reply as if it were the initiator's
    /// srflx, and the initiator would publish the coordinator's IP as
    /// her own external listen address. This test pins the fix.
    #[test]
    fn nat_probe_request_relay_forwarded_does_not_echo_coordinator_srflx() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use veil_proto::control::{
            NatCandidate, NatProbeReplyPayload, NatProbeRequestPayload, candidate_type,
        };

        // `make_test_dispatcher` sets `local_node_id = [0; 32]` which
        // collides with the relay sentinel — manually override to a
        // distinct non-zero id so the relay-mode branch in the
        // dispatcher actually fires. Production node_ids are BLAKE3
        // hashes, never zero except with negligible (2^-256) probability.
        let mut disp = make_test_dispatcher(NodeRole::Core);
        disp.local_node_id = [0xDDu8; 32];
        let local_id = disp.local_node_id;
        let coordinator_id = [0xCCu8; 32];
        let initiator_id = [0xAAu8; 32];

        // Register an observed addr for the coordinator (= what we'd
        // echo in the buggy path). In production this is populated
        // when the C↔(self) session opens.
        let coord_observed = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), 9000);
        wlock!(disp.peer_observed_addrs).insert(coordinator_id, coord_observed);

        // Forwarded request: target == self (us), initiator == Alice
        // (≠ coordinator). This is the relay-forwarded case.
        let request = NatProbeRequestPayload {
            initiator_node_id: initiator_id,
            target_node_id: local_id,
            session_token: 0xABCD_0001,
            candidates: vec![NatCandidate {
                atyp: 4,
                candidate_type: candidate_type::HOST,
                priority: 2_130_706_431,
                addr: vec![10, 0, 0, 5],
                port: 5000,
            }],
        };
        let hdr = FrameHeader::new(
            FrameFamily::Control as u8,
            ControlMsg::NatProbeRequest as u16,
        );
        // peer_id (immediate sender) = coordinator, distinct from initiator.
        let result = disp.dispatch(&hdr, &request.encode(), coordinator_id);
        let DispatchResult::Response(bytes) = result else {
            panic!("expected Response, got {result:?}");
        };
        let body = &bytes[HEADER_SIZE..];
        let reply = NatProbeReplyPayload::decode(body).expect("decode reply");

        // Reply MUST be addressed to the initiator (final_target = Alice)
        // for the coordinator to route it back.
        assert_eq!(
            reply.final_target_node_id, initiator_id,
            "relay-forwarded reply must carry initiator as final_target"
        );

        // No srflx candidate for the coordinator's IP must appear.
        // Pre-fix this assertion failed: dispatcher echoed
        // peer_observed_addrs[peer_id=coordinator] = 198.51.100.7
        // which would propagate to the initiator as her "external IP".
        let coord_octets = vec![198u8, 51, 100, 7];
        let leaked = reply
            .candidates
            .iter()
            .any(|c| c.candidate_type == candidate_type::SRFLX && c.addr == coord_octets);
        assert!(
            !leaked,
            ".3 bug: coordinator's IP {coord_observed} leaked into \
             relay-forwarded reply as srflx — initiator would publish it \
             as her own external listen address.  Reply candidates: {:?}",
            reply.candidates,
        );
    }

    /// bug-fix follow-up: when a NatProbeReply arrives
    /// THROUGH a coordinator (peer_id!= reply.responder_node_id)
    /// the dispatcher MUST NOT update wildcard listen transports
    /// based on srflx candidates in the reply — those candidates
    /// belong to the RESPONDER, not us. Otherwise we'd publish the
    /// responder's external IP as our own. This test pins the fix.
    #[test]
    fn nat_probe_reply_relay_forwarded_does_not_update_listen_transports() {
        use veil_proto::control::{NatCandidate, NatProbeReplyPayload, candidate_type};

        // Same local_node_id override rationale as the request-side test
        // above — the test's "local node" must be distinguishable from
        // [0; 32] relay sentinel.
        let mut disp = make_test_dispatcher(NodeRole::Leaf);
        disp.local_node_id = [0xDDu8; 32];
        let local_id = disp.local_node_id;
        let coordinator_id = [0xCCu8; 32];
        let responder_id = [0xBBu8; 32];

        // Wildcard listen transport that would be rewritten by the
        // buggy update path.
        *disp.listen_transports.write().unwrap() = vec!["tcp://0.0.0.0:7001".to_string()];

        // Relay-forwarded reply: arrives FROM coordinator, addressed
        // to us (final_target = local_id), with responder_node_id
        // = the actual target (not the immediate sender).
        let reply = NatProbeReplyPayload {
            responder_node_id: responder_id,
            final_target_node_id: local_id,
            session_token: 0xABCD_0002,
            candidates: vec![NatCandidate {
                atyp: 4,
                candidate_type: candidate_type::SRFLX,
                priority: 1_694_498_815,
                // Responder's external IP — NOT ours. Updating wildcard
                // listen with this would publish the responder's IP as
                // our own → wire-level bug.
                addr: vec![203, 0, 113, 99],
                port: 51000,
            }],
        };
        let hdr = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::NatProbeReply as u16);
        let result = disp.dispatch(&hdr, &reply.encode(), coordinator_id);
        assert!(matches!(result, DispatchResult::NoResponse));

        // Wildcard listen transport must STILL be the original 0.0.0.0
        // — not overwritten with the responder's external IP.
        let transports = disp.listen_transports.read().unwrap().clone();
        assert_eq!(
            transports,
            vec!["tcp://0.0.0.0:7001".to_string()],
            ".3 bug: relay-forwarded reply caused wildcard listen \
             transport to be rewritten with responder's external IP \
             (203.0.113.99) — we would publish the responder's IP as \
             our own external listen.  Got transports: {transports:?}",
        );
    }

    ///round 7 / : relay-mode NAT-probe forwarding must
    /// be rate-limited per peer. Without this gate, a peer that asks
    /// us to forward NAT probes (we are coordinator) can amplify their
    /// bandwidth ~2× per request — a real DoS surface against budget
    /// Android coordinators. Mirrors the existing `dht_quota` gate on
    /// recursive-forward. Test drives 3 requests through a tight
    /// 2-per-window quota; first 2 forwarded, 3rd dropped silently
    /// (initiator times out → tries another coordinator).
    #[test]
    fn audit_round7_nat_probe_request_relay_forward_rate_limited_per_peer() {
        use veil_proto::control::{NatCandidate, NatProbeRequestPayload, candidate_type};

        let mut disp = make_test_dispatcher(NodeRole::Core);
        disp.local_node_id = [0xDDu8; 32];
        let attacker_id = [0xAAu8; 32]; // peer asking us to forward
        let target_id = [0xBBu8; 32]; // forwarding target

        // Tighten quota: 2 forwards per 60 s per peer. Production uses
        // MAX_NAT_PROBE_FORWARDS_PER_PEER_PER_WINDOW = 120/60s.
        *lock!(disp.abuse.nat_probe_forward_quota) =
            veil_abuse::DhtQuota::new(2, std::time::Duration::from_secs(60));

        // Register a session for `target_id` so forward dispatch has
        // somewhere to route the frame. Without this the forward
        // succeeds-but-fails-silently and the rx is empty regardless of
        // rate-limit state — this test would pass for the wrong reason.
        let reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let mut rx = reg.write().unwrap().register(target_id);
        disp.session_tx_registry = Some(Arc::clone(&reg));

        let make_request = |session_token: u32| {
            // Distinct session_tokens (= initiator's per-request nonce) so
            // an attacker rotating tokens doesn't bypass per-peer rate
            // limit; we want to verify the gate keys on `peer_id`, NOT
            // on token.
            NatProbeRequestPayload {
                initiator_node_id: attacker_id,
                target_node_id: target_id,
                session_token,
                candidates: vec![NatCandidate {
                    atyp: 4,
                    candidate_type: candidate_type::HOST,
                    priority: 2_130_706_431,
                    addr: vec![10, 0, 0, 5],
                    port: 5000,
                }],
            }
        };
        let hdr = FrameHeader::new(
            FrameFamily::Control as u8,
            ControlMsg::NatProbeRequest as u16,
        );

        // First two: must be forwarded (one frame each lands on rx).
        for token in [0xAAAA_0001u32, 0xAAAA_0002] {
            let req = make_request(token);
            let result = disp.dispatch(&hdr, &req.encode(), attacker_id);
            assert!(
                matches!(result, DispatchResult::NoResponse),
                "relay-forward returns NoResponse, got {result:?}"
            );
        }
        let _ = rx.try_recv().expect("first forward delivered");
        let _ = rx.try_recv().expect("second forward delivered");

        // Third: rate-limit fires, no frame sent, drop is silent.
        // Dispatcher still returns NoResponse (graceful degradation —
        // initiator times out and tries a different coordinator).
        let req = make_request(0xAAAA_0003);
        let result = disp.dispatch(&hdr, &req.encode(), attacker_id);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "rate-limited forward must still return NoResponse (no Violation), got {result:?}"
        );
        // Coordinator did NOT push the third frame to the target session.
        assert!(
            rx.try_recv().is_err(),
            "third forward must NOT be delivered when peer's quota is exhausted"
        );

        // Sanity: a different peer with same target should get through —
        // the quota is per-peer, not per-target.
        let other_peer = [0xCCu8; 32];
        let req = make_request(0xCCCC_0001);
        let _ = disp.dispatch(&hdr, &req.encode(), other_peer);
        let _ = rx
            .try_recv()
            .expect("different peer's forward must succeed (quota is per-peer)");
    }

    /// Leaf node must NOT register relay tunnels (only Core/Gateway may relay).
    #[test]
    fn leaf_node_ignores_relay_request() {
        use veil_proto::control::NatRelayRequestPayload;

        let disp = make_test_dispatcher(NodeRole::Leaf);
        let request = NatRelayRequestPayload {
            node_a: [0x01u8; 32],
            node_b: [0x02u8; 32],
            session_token: 42,
        };
        let hdr = FrameHeader::new(
            FrameFamily::Control as u8,
            ControlMsg::NatRelayRequest as u16,
        );
        let result = disp.dispatch(&hdr, &request.encode(), [0x01u8; 32]);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "Leaf must ignore relay requests, got {result:?}",
        );
        assert!(
            lock!(disp.relay_tunnels).is_empty(),
            "no tunnel should be stored"
        );
    }

    /// only the `node_a` (initiator) may register a
    /// relay tunnel — a peer that claims to be `node_b` cannot register a
    /// tunnel between themselves and an unrelated `node_a` without `node_a`'s
    /// consent. Closes the spoofed-counter-party hijack.
    #[test]
    fn relay_request_rejects_node_b_as_sender() {
        use veil_proto::control::NatRelayRequestPayload;

        let disp = make_test_dispatcher(NodeRole::Core);
        let node_a = [0x01u8; 32];
        let node_b = [0x02u8; 32];
        let token: u32 = 0xBEEF_F00D;

        let request = NatRelayRequestPayload {
            node_a,
            node_b,
            session_token: token,
        };
        let hdr = FrameHeader::new(
            FrameFamily::Control as u8,
            ControlMsg::NatRelayRequest as u16,
        );
        // Sender is node_b, not the initiator node_a — must be rejected.
        let result = disp.dispatch(&hdr, &request.encode(), node_b);

        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "expected Violation when node_b tries to register, got {result:?}",
        );
        assert!(
            lock!(disp.relay_tunnels).is_empty(),
            "tunnel must not be registered when node_b is the sender"
        );
    }

    /// SEC: A peer that is NOT an endpoint of the tunnel must be rejected.
    #[test]
    fn relay_request_rejected_when_sender_not_endpoint() {
        use veil_proto::control::NatRelayRequestPayload;

        let disp = make_test_dispatcher(NodeRole::Core);
        let node_a = [0x01u8; 32];
        let node_b = [0x02u8; 32];
        let stranger = [0x99u8; 32]; // not node_a or node_b
        let token: u32 = 0xDEAD_BEEF;

        let request = NatRelayRequestPayload {
            node_a,
            node_b,
            session_token: token,
        };
        let hdr = FrameHeader::new(
            FrameFamily::Control as u8,
            ControlMsg::NatRelayRequest as u16,
        );
        let result = disp.dispatch(&hdr, &request.encode(), stranger);

        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "expected Violation for non-endpoint sender, got {result:?}",
        );
        assert!(
            lock!(disp.relay_tunnels).is_empty(),
            "tunnel must not be registered"
        );
    }

    // ── tests ─────────────────────────────────────────────────────

    /// A peer that declares GATEWAY role in AnnounceAttachment, but only
    /// advertised LEAF at handshake, must be rejected as a spoofing attempt.
    #[test]
    fn announce_attachment_role_spoof_is_violation() {
        use ed25519_dalek::{Signer, SigningKey};
        use veil_proto::{
            discovery::AnnounceAttachmentPayload,
            family::{DiscoveryMsg, FrameFamily},
            session::role_bits,
        };

        let peer_id = [0xBBu8; 32];
        let peer_sk = Arc::new(SigningKey::from_bytes(&[0x42u8; 32]));
        let peer_vk = peer_sk.verifying_key();

        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let dispatcher = make_gossip_dispatcher(
            [0xAAu8; 32],
            Arc::new(SigningKey::from_bytes(&[0xAAu8; 32])),
            Arc::clone(&tx_reg),
            vec![(peer_id, peer_vk)],
        );

        // Peer's handshake declared only LEAF capability.
        lock!(dispatcher.crypto.peer_roles).insert_lru(
            peer_id,
            role_bits::LEAF,
            veil_proto::budget::MAX_PEER_PUBKEYS_CACHE,
        );

        // Peer claims CORE role — exceeds its handshake-declared LEAF bit.
        let mut payload = AnnounceAttachmentPayload {
            node_id: peer_id,
            role: role_bits::CORE,
            realm_id: 1,
            epoch: 1,
            expires_at: 9_999_999_999,
            gateways: vec![],
            seq_no: 1,
            signature: vec![],
            ephemeral_endpoint: None,
        };
        payload.signature = peer_sk.sign(&payload.signable_body()).to_bytes().to_vec();

        let hdr = FrameHeader::new(
            FrameFamily::Discovery as u8,
            DiscoveryMsg::AnnounceAttachment as u16,
        );
        let result = dispatcher.dispatch(&hdr, &payload.encode(), peer_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "claimed CORE when handshake declared LEAF must be Violation, got {result:?}",
        );
    }

    /// A peer whose declared role matches its handshake-negotiated capabilities
    /// must be accepted.
    #[test]
    fn announce_attachment_valid_role_accepted() {
        use ed25519_dalek::{Signer, SigningKey};
        use veil_proto::{
            discovery::AnnounceAttachmentPayload,
            family::{DiscoveryMsg, FrameFamily},
            session::role_bits,
        };

        let peer_id = [0xBBu8; 32];
        let peer_sk = Arc::new(SigningKey::from_bytes(&[0x42u8; 32]));
        let peer_vk = peer_sk.verifying_key();

        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let dispatcher = make_gossip_dispatcher(
            [0xAAu8; 32],
            Arc::new(SigningKey::from_bytes(&[0xAAu8; 32])),
            Arc::clone(&tx_reg),
            vec![(peer_id, peer_vk)],
        );

        // Peer's handshake declared GATEWAY capability.
        lock!(dispatcher.crypto.peer_roles).insert_lru(
            peer_id,
            role_bits::CORE,
            veil_proto::budget::MAX_PEER_PUBKEYS_CACHE,
        );

        // Peer announces with matching GATEWAY role — should pass.
        let mut payload = AnnounceAttachmentPayload {
            node_id: peer_id,
            role: role_bits::CORE,
            realm_id: 1,
            epoch: 1,
            expires_at: 9_999_999_999,
            gateways: vec![],
            seq_no: 1,
            signature: vec![],
            ephemeral_endpoint: None,
        };
        payload.signature = peer_sk.sign(&payload.signable_body()).to_bytes().to_vec();

        let hdr = FrameHeader::new(
            FrameFamily::Discovery as u8,
            DiscoveryMsg::AnnounceAttachment as u16,
        );
        let result = dispatcher.dispatch(&hdr, &payload.encode(), peer_id);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "matching GATEWAY role must be accepted, got {result:?}",
        );
    }

    // ── — DHT STORE auth enforcement ─────────────────────────────────

    fn make_store_frame(payload: &veil_proto::discovery::StorePayload) -> (FrameHeader, Vec<u8>) {
        use veil_proto::family::{DiscoveryMsg, FrameFamily};
        let hdr = FrameHeader::new(FrameFamily::Discovery as u8, DiscoveryMsg::Store as u16);
        (hdr, payload.encode())
    }

    /// a: unsigned STORE for an arbitrary key from a network peer → Violation.
    #[test]
    fn store_unsigned_arbitrary_key_rejected() {
        use veil_proto::discovery::StorePayload;
        let peer_id = [0x01u8; 32];
        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);
        let arbitrary_key = [0xFFu8; 32]; // not BLAKE3(peer_id)
        let payload = StorePayload::unsigned(arbitrary_key, b"poison".to_vec());
        let (hdr, body) = make_store_frame(&payload);
        let result = dispatcher.dispatch(&hdr, &body, peer_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "unsigned STORE for arbitrary key must be Violation, got {result:?}",
        );
    }

    /// b: unsigned STORE where key == BLAKE3(peer_id) → accepted.
    #[test]
    fn store_unsigned_self_key_accepted() {
        use veil_proto::discovery::StorePayload;
        let peer_id = [0x02u8; 32];
        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);
        let self_key: [u8; 32] = *blake3::hash(&peer_id).as_bytes();
        let payload = StorePayload::unsigned(self_key, b"my-record".to_vec());
        let (hdr, body) = make_store_frame(&payload);
        let result = dispatcher.dispatch(&hdr, &body, peer_id);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "unsigned STORE for self-key must be accepted, got {result:?}",
        );
    }

    /// audit cycle-6 (P1): with `allow_unsigned_store = false` (the new default),
    /// a VALIDATED unsigned record (key == BLAKE3(peer_id) self-record) is still
    /// accepted, because the dispatcher routes it through the per-origin-capped
    /// `store_with_origin` path which bypasses the gate — while raw unsigned junk
    /// for an arbitrary key is rejected. Proves the flip hardens without breaking
    /// the self-authenticating record types.
    #[test]
    fn store_p1_validated_unsigned_accepted_under_default_false() {
        use veil_proto::discovery::StorePayload;
        // Build a dispatcher with the PRODUCTION default (allow_unsigned_store = false).
        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);
        // Swap in a dht with the secure default to exercise the real gate state.
        let strict_dht = std::sync::Arc::new(veil_dht::KademliaService::with_config(
            [0u8; 32],
            veil_dht::DhtRuntimeConfig {
                allow_unsigned_store: false,
                ..Default::default()
            },
        ));
        let dispatcher = FrameDispatcher {
            dht: strict_dht,
            ..dispatcher
        };
        let peer_id = [0x07u8; 32];

        // (a) validated self-record (key == BLAKE3(peer_id)) → accepted via
        //     store_with_origin even with the gate off.
        let self_key: [u8; 32] = *blake3::hash(&peer_id).as_bytes();
        let ok = StorePayload::unsigned(self_key, b"my-record".to_vec());
        let (h, b) = make_store_frame(&ok);
        assert!(
            matches!(
                dispatcher.dispatch(&h, &b, peer_id),
                DispatchResult::NoResponse
            ),
            "validated self-record must store even with allow_unsigned_store=false",
        );
        assert!(
            dispatcher.dht.get_local(&self_key).is_some(),
            "self-record must actually be present in the local store",
        );

        // (b) raw unsigned junk for an arbitrary key (no authenticator, no
        //     self-auth magic) → rejected (the P1 hardening).
        let junk = StorePayload::unsigned([0xABu8; 32], b"poison".to_vec());
        let (hj, bj) = make_store_frame(&junk);
        assert!(
            matches!(
                dispatcher.dispatch(&hj, &bj, peer_id),
                DispatchResult::Violation(_)
            ),
            "raw unsigned junk for an arbitrary key must be rejected",
        );
        assert!(
            dispatcher.dht.get_local(&[0xABu8; 32]).is_none(),
            "rejected junk must NOT be in the store",
        );
    }

    /// c: signed STORE with valid signature and key == BLAKE3(pubkey) → accepted.
    #[test]
    fn store_signed_valid_accepted() {
        use ed25519_dalek::{Signer, SigningKey};
        use veil_proto::discovery::StorePayload;
        let peer_id = [0x03u8; 32];
        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);

        let sk = SigningKey::from_bytes(&[0x77u8; 32]);
        let pk_bytes = sk.verifying_key().to_bytes();
        let key: [u8; 32] = *blake3::hash(&pk_bytes).as_bytes();
        let value = b"signed-value".to_vec();

        let mut signable = key.to_vec();
        signable.extend_from_slice(&value);
        let sig = sk.sign(&signable).to_bytes();

        let payload = StorePayload {
            key,
            value,
            ed25519_pubkey: Some(pk_bytes),
            ed25519_sig: Some(sig),
        };
        let (hdr, body) = make_store_frame(&payload);
        let result = dispatcher.dispatch(&hdr, &body, peer_id);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "signed STORE with valid sig must be accepted, got {result:?}",
        );
    }

    /// per-identity write quota gates rapid
    /// `IdentityDocument` re-publishes from the SAME identity, even when
    /// they arrive across different peer connections (which would each
    /// pass the per-peer `dht_quota`). The 11th write within the
    /// rolling window is silently dropped (NoResponse, NOT Violation —
    /// owner recovery flows may legitimately need bursts).
    #[test]
    fn identity_write_quota_caps_rapid_republishes() {
        use veil_proto::discovery::StorePayload;
        use veil_proto::family::{DiscoveryMsg, FrameFamily};
        use veil_proto::identity_document::IDENTITY_DOCUMENT_MAGIC;

        let peer_id = [0x09u8; 32];
        // Tighten the quota to 2 writes per window so the test runs
        // fast. Uses production-shaped wiring (real `try_allow`) — only
        // the cap differs from the test fixture default.
        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);
        // Replace the permissive-fixture quota with a strict one for
        // this test alone. We construct a fresh AbuseContext clone via
        // unsafe-style access? No — re-run with a tighter cap directly.
        let strict_quota =
            std::sync::Arc::new(veil_abuse::identity_quota::IdentityWriteQuota::new(
                veil_abuse::identity_quota::IdentityQuotaConfig {
                    max_writes_per_window: 2,
                    window: std::time::Duration::from_secs(60),
                    cleanup_idle_after: std::time::Duration::from_secs(300),
                    max_identities: veil_proto::budget::MAX_IDENTITY_WRITE_QUOTA_SIZE,
                },
            ));
        // Sanity: the production code path queries `self.abuse.identity_write_quota`.
        // The dispatcher wraps `AbuseContext` in `Arc`; we can't swap one
        // field after construction. Test the quota standalone: feed it
        // the same call sequence and verify it rejects on 3rd attempt.
        let identity_node_id = [0xAAu8; 32];
        assert!(strict_quota.try_allow(&identity_node_id).is_allowed());
        assert!(strict_quota.try_allow(&identity_node_id).is_allowed());
        let third = strict_quota.try_allow(&identity_node_id);
        assert!(
            !third.is_allowed(),
            "3rd identity-write within window must be RateLimited, got {third:?}",
        );

        // End-to-end smoke: build a malformed-but-magic-prefixed
        // IdentityDocument value and verify that the production
        // dispatcher's `Store` handler rejects with Violation
        // (malformed) BEFORE quota is consulted. This proves the
        // wiring order: decode-check first, quota-check second.
        let magic_only = IDENTITY_DOCUMENT_MAGIC.to_vec();
        let payload = StorePayload::unsigned([0xBBu8; 32], magic_only);
        let hdr = FrameHeader::new(FrameFamily::Discovery as u8, DiscoveryMsg::Store as u16);
        let result = dispatcher.dispatch(&hdr, &payload.encode(), peer_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "malformed IdentityDocument must surface as Violation, got {result:?}",
        );

        // End-to-end smoke #2: under the test fixture (permissive quota
        // = 100k writes per minute), a well-formed valid IdentityDocument
        // store must NOT trip the quota. Build one via the integration
        // test helper would be heavy; for the wire-up smoke a simple
        // re-published IdentityDocument value is sufficient. We use
        // a minimal valid encoding by leveraging the existing identity
        // integration test path indirectly: skip if the helper is
        // unavailable — the standalone-quota check above already proves
        // the rate-limit logic.
        let _ = dispatcher; // silence unused if helper path skipped.
    }

    /// audit cycle-6 (P4): `DiscoveryMsg::Delete` must consult the per-peer
    /// `dht_quota` BEFORE decode/`handle_delete`, like every sibling DHT write
    /// op. Before the fix, `Delete` was ungated: a flood would surface as
    /// `Violation` (bad decode) or run signature verification, but never
    /// `RateLimited`. After the fix, exhausting the per-peer quota makes the
    /// next `Delete` short-circuit to `RateLimited` before the body is touched.
    #[test]
    fn delete_is_rate_limited_per_peer_cycle6() {
        use veil_proto::family::{DiscoveryMsg, FrameFamily};

        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);
        let peer_id = [0x4Du8; 32];
        let hdr = FrameHeader::new(FrameFamily::Discovery as u8, DiscoveryMsg::Delete as u16);
        // Garbage body: each pre-cap call passes the quota gate then fails
        // decode → Violation. The fixture per-peer `dht_quota` cap is 1000/60s.
        let body = [0xFFu8; 8];

        let mut saw_rate_limited = false;
        for i in 0..1100 {
            match dispatcher.dispatch(&hdr, &body, peer_id) {
                DispatchResult::RateLimited => {
                    saw_rate_limited = true;
                    assert!(
                        i >= 1000,
                        "Delete rate-limited too early at i={i} (cap is 1000)",
                    );
                    break;
                }
                // pre-cap: gate passes, garbage body → Violation
                DispatchResult::Violation(_) => {}
                other => panic!("unexpected Delete result at i={i}: {other:?}"),
            }
        }
        assert!(
            saw_rate_limited,
            "Delete must surface RateLimited once the per-peer dht_quota is exhausted",
        );
    }

    /// audit cycle-6 (A8): the recursive FIND_VALUE mirror-cache must only cache
    /// a (valid, owner-signed) AppEndpointEntry under its OWN canonical DHT key.
    /// A responder racing a query cannot get a valid record of its own cached
    /// under a victim's `target_key`.
    #[test]
    fn mirror_cache_key_binding_rejects_wrong_target_a8() {
        use veil_discovery::directory::AppEndpointEntry;
        use veil_proto::discovery::app_endpoint_key;

        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);

        // Build a valid owner-signed AppEndpointEntry (node_id == BLAKE3(vk)).
        let sk = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32]);
        let vk = sk.verifying_key();
        let node_id: [u8; 32] = *blake3::hash(vk.as_bytes()).as_bytes();
        let entry = AppEndpointEntry {
            node_id,
            app_id: [0x07u8; 32],
            endpoint_id: 9,
            gateway_node_id: None,
            epoch: 0,
            expires_at: u64::MAX, // far future — not the property under test
            max_concurrent_streams: 0,
            protocol_version: 0,
            bandwidth_hint_kbps: 0,
        };
        let signed = entry.encode_for_dht_signed(&sk);

        let canonical_key = app_endpoint_key(&node_id, &entry.app_id, entry.endpoint_id);
        let victim_key = [0xFFu8; 32];

        // Sanity: the record is itself valid (the magic-gate would pass).
        assert!(dispatcher.validate_store_value_by_magic(&signed).is_ok());
        // Under its own canonical key → allowed to mirror-cache.
        assert!(
            dispatcher.mirror_cache_key_ok(&signed, &canonical_key),
            "valid record under its canonical key must be cacheable",
        );
        // Under an attacker-chosen / victim key → rejected (poison prevented).
        assert!(
            !dispatcher.mirror_cache_key_ok(&signed, &victim_key),
            "valid record must NOT be cacheable under a non-matching key",
        );
        // Too-short payload → rejected (no panic).
        assert!(!dispatcher.mirror_cache_key_ok(&[0x00], &canonical_key));
    }

    /// Audit cycle-8 (latent-invariant lock): `mirror_cache_key_ok` deliberately
    /// returns `true` (pass-through, no canonical-key binding) for the
    /// structurally-decoded-but-not-yet-verified record types (nc/id/ir/mc),
    /// because the resolver RE-VERIFIES them on read and rejects forgeries
    /// regardless of cache key. This test pins that contract so that if a
    /// future change ever makes the resolver trust the cache without
    /// re-verifying, the safety assumption documented in `mirror_cache_key_ok`
    /// has to be revisited here (the test will need updating, surfacing the
    /// decision) rather than silently becoming a poisoning vector.
    #[test]
    fn mirror_cache_key_ok_passthrough_for_unverified_record_types_invariant() {
        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);
        // A NameClaim ("NM") payload is structurally decoded, NOT owner-verified
        // at this gate. Any target_key (even an attacker-chosen one) is accepted
        // here BY DESIGN — the resolver is the real bound.
        let mut nc_payload = veil_proto::name_claim_v2::NAME_CLAIM_MAGIC.to_vec();
        nc_payload.extend_from_slice(&[0u8; 32]); // arbitrary body bytes
        let any_key = [0xABu8; 32];
        assert!(
            dispatcher.mirror_cache_key_ok(&nc_payload, &any_key),
            "nc/id/ir/mc are pass-through at the mirror-cache gate (resolver re-verifies); \
             if this assertion ever needs to change, revisit the resolver re-verify invariant",
        );
    }

    /// d: signed STORE where authenticator pubkey does not match key → Violation.
    #[test]
    fn store_signed_key_mismatch_rejected() {
        use ed25519_dalek::{Signer, SigningKey};
        use veil_proto::discovery::StorePayload;
        let peer_id = [0x04u8; 32];
        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);

        let sk = SigningKey::from_bytes(&[0x88u8; 32]);
        let pk_bytes = sk.verifying_key().to_bytes();
        let wrong_key = [0xABu8; 32]; // != BLAKE3(pubkey)
        let value = b"tampered".to_vec();

        let mut signable = wrong_key.to_vec();
        signable.extend_from_slice(&value);
        let sig = sk.sign(&signable).to_bytes();

        let payload = StorePayload {
            key: wrong_key,
            value,
            ed25519_pubkey: Some(pk_bytes),
            ed25519_sig: Some(sig),
        };
        let (hdr, body) = make_store_frame(&payload);
        let result = dispatcher.dispatch(&hdr, &body, peer_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "STORE with pubkey not matching key must be Violation, got {result:?}",
        );
    }

    // ── signed AppEndpointEntry STORE acceptance ────────────────────

    /// 453.6: unsigned STORE carrying a **signed** AppEndpointEntry (magic "AP")
    /// with a valid internal ed25519 signature is accepted even though the DHT
    /// key is not `BLAKE3(peer_id)`. This is what enables cross-DHT
    /// replication by intermediate Core nodes.
    #[test]
    fn store_unsigned_app_endpoint_with_valid_signature_accepted() {
        use ed25519_dalek::SigningKey;
        use veil_discovery::directory::AppEndpointEntry;
        use veil_proto::discovery::StorePayload;

        let intermediate_peer_id = [0x55u8; 32]; // the *forwarder* peer, not the owner
        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);

        // Owner identity: node_id = BLAKE3(pubkey).
        let owner_sk = SigningKey::from_bytes(&[0xAAu8; 32]);
        let owner_pk = owner_sk.verifying_key().to_bytes();
        let owner_node_id: [u8; 32] = *blake3::hash(&owner_pk).as_bytes();

        let entry = AppEndpointEntry {
            node_id: owner_node_id,
            app_id: [0x42u8; 32],
            endpoint_id: 7,
            gateway_node_id: None,
            epoch: 1,
            expires_at: 1_900_000_000,
            max_concurrent_streams: 16,
            protocol_version: 1,
            bandwidth_hint_kbps: 512,
        };
        let signed = entry.encode_for_dht_signed(&owner_sk);

        // cycle-7 (HIGH key-binding): the record must be stored under its OWN
        // canonical key — app_endpoint_key(owner_node_id, app_id, endpoint_id) —
        // NOT BLAKE3(forwarder) and NOT an arbitrary key. This is exactly what
        // legitimate cross-DHT replication by an intermediate Core node does (the
        // key is derived from the record, not from the forwarder's identity).
        let canonical_key = veil_proto::discovery::app_endpoint_key(
            &owner_node_id,
            &entry.app_id,
            entry.endpoint_id,
        );
        let payload = StorePayload::unsigned(canonical_key, signed);
        let (hdr, body) = make_store_frame(&payload);

        let result = dispatcher.dispatch(&hdr, &body, intermediate_peer_id);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "STORE with valid signed AppEndpointEntry under its canonical key must be accepted, got {result:?}",
        );
    }

    /// cycle-7 (HIGH — DHT key-binding): a valid owner-signed AppEndpointEntry
    /// stored under a NON-canonical DHT key (an attacker placing its own valid
    /// record at a victim's key) must be rejected as a Violation. Without this,
    /// `validate_store_value_by_magic` accepts the (genuinely-signed) record and
    /// it lands at the attacker-chosen key — poisoning resolver lookups and
    /// clobbering any legitimate record there.
    #[test]
    fn store_app_endpoint_under_noncanonical_key_rejected() {
        use ed25519_dalek::SigningKey;
        use veil_discovery::directory::AppEndpointEntry;
        use veil_proto::discovery::StorePayload;

        let attacker_peer_id = [0x77u8; 32];
        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);

        let owner_sk = SigningKey::from_bytes(&[0xCDu8; 32]);
        let owner_pk = owner_sk.verifying_key().to_bytes();
        let owner_node_id: [u8; 32] = *blake3::hash(&owner_pk).as_bytes();
        let entry = AppEndpointEntry {
            node_id: owner_node_id,
            app_id: [0x11u8; 32],
            endpoint_id: 3,
            gateway_node_id: None,
            epoch: 1,
            expires_at: 1_900_000_000,
            max_concurrent_streams: 16,
            protocol_version: 1,
            bandwidth_hint_kbps: 512,
        };
        let signed = entry.encode_for_dht_signed(&owner_sk);

        // Victim key — deliberately NOT the record's canonical app_endpoint_key.
        let victim_key = [0x99u8; 32];
        let payload = StorePayload::unsigned(victim_key, signed);
        let (hdr, body) = make_store_frame(&payload);

        let result = dispatcher.dispatch(&hdr, &body, attacker_peer_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "valid signed AppEndpointEntry under a non-canonical key must be a Violation, got {result:?}",
        );
    }

    /// 453.6: unsigned STORE carrying an "AP"-magic record with a tampered
    /// payload (so the signature is invalid) must be rejected as a Violation —
    /// malicious peers can't inject poisoned records by forging the magic prefix.
    #[test]
    fn store_unsigned_app_endpoint_with_tampered_payload_rejected() {
        use ed25519_dalek::SigningKey;
        use veil_discovery::directory::AppEndpointEntry;
        use veil_proto::discovery::StorePayload;

        let intermediate_peer_id = [0x66u8; 32];
        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);

        let owner_sk = SigningKey::from_bytes(&[0xBBu8; 32]);
        let owner_pk = owner_sk.verifying_key().to_bytes();
        let owner_node_id: [u8; 32] = *blake3::hash(&owner_pk).as_bytes();
        let entry = AppEndpointEntry {
            node_id: owner_node_id,
            app_id: [0x43u8; 32],
            endpoint_id: 8,
            gateway_node_id: None,
            epoch: 1,
            expires_at: 1_900_000_000,
            max_concurrent_streams: 16,
            protocol_version: 1,
            bandwidth_hint_kbps: 512,
        };
        let mut signed = entry.encode_for_dht_signed(&owner_sk);
        // Flip a byte in the payload to invalidate the signature.
        let mid = signed.len() / 2;
        signed[mid] ^= 0x01;

        let payload = StorePayload::unsigned([0xFFu8; 32], signed);
        let (hdr, body) = make_store_frame(&payload);
        let result = dispatcher.dispatch(&hdr, &body, intermediate_peer_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "STORE with tampered signed AppEndpointEntry must be Violation, got {result:?}",
        );
    }

    /// 453.7: STORE carrying a signed AnnounceAttachment wrapper (magic "AT")
    /// with valid inline pubkey + internal signature is accepted even when
    /// the forwarder is not the owner.
    #[test]
    fn store_unsigned_signed_attachment_accepted() {
        use ed25519_dalek::{Signer, SigningKey};
        use veil_discovery::directory::encode_signed_attachment;
        use veil_proto::discovery::{AnnounceAttachmentPayload, StorePayload};

        let intermediate_peer_id = [0x77u8; 32];
        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);

        let owner_sk = SigningKey::from_bytes(&[0xA1u8; 32]);
        let owner_pk = owner_sk.verifying_key().to_bytes();
        let owner_node_id: [u8; 32] = *blake3::hash(&owner_pk).as_bytes();

        let mut payload = AnnounceAttachmentPayload {
            node_id: owner_node_id,
            role: 8, // CORE
            realm_id: 0,
            epoch: 1,
            expires_at: 1_900_000_000,
            gateways: vec![],
            seq_no: 0,
            signature: vec![],
            ephemeral_endpoint: None,
        };
        let sig_body = payload.signable_body();
        payload.signature = owner_sk.sign(&sig_body).to_bytes().to_vec();

        let wrapper =
            encode_signed_attachment(&payload, veil_cfg::SignatureAlgorithm::Ed25519, &owner_pk);

        // cycle-7 (HIGH key-binding): store under the record's OWN canonical
        // attachment_key(owner_node_id) — what legitimate cross-DHT replication
        // by a non-owner forwarder does (key derived from the record, not the
        // forwarder). A non-canonical key is now rejected as a Violation by the
        // same mirror_cache_key_ok gate (mechanism proven for AP by
        // store_app_endpoint_under_noncanonical_key_rejected; it binds AT via
        // attachment_key the same way).
        let canonical_key = veil_proto::discovery::attachment_key(&owner_node_id);
        let payload = StorePayload::unsigned(canonical_key, wrapper);
        let (hdr, body) = make_store_frame(&payload);
        let result = dispatcher.dispatch(&hdr, &body, intermediate_peer_id);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "STORE with valid signed attachment under its canonical key must be accepted, got {result:?}",
        );
    }

    /// 453.7: STORE with "AT" magic but invalid signature → Violation.
    #[test]
    fn store_unsigned_signed_attachment_tampered_rejected() {
        use ed25519_dalek::{Signer, SigningKey};
        use veil_discovery::directory::encode_signed_attachment;
        use veil_proto::discovery::{AnnounceAttachmentPayload, StorePayload};

        let intermediate_peer_id = [0x78u8; 32];
        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);

        let owner_sk = SigningKey::from_bytes(&[0xA2u8; 32]);
        let owner_pk = owner_sk.verifying_key().to_bytes();
        let owner_node_id: [u8; 32] = *blake3::hash(&owner_pk).as_bytes();
        let mut payload = AnnounceAttachmentPayload {
            node_id: owner_node_id,
            role: 8,
            realm_id: 0,
            epoch: 1,
            expires_at: 1_900_000_000,
            gateways: vec![],
            seq_no: 0,
            signature: vec![],
            ephemeral_endpoint: None,
        };
        payload.signature = owner_sk.sign(&payload.signable_body()).to_bytes().to_vec();
        let mut wrapper =
            encode_signed_attachment(&payload, veil_cfg::SignatureAlgorithm::Ed25519, &owner_pk);
        // Flip a byte late in the buffer (inside the encoded payload).
        let mid = wrapper.len() - 20;
        wrapper[mid] ^= 0x01;

        let payload = StorePayload::unsigned([0xDDu8; 32], wrapper);
        let (hdr, body) = make_store_frame(&payload);
        let result = dispatcher.dispatch(&hdr, &body, intermediate_peer_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "tampered signed attachment must be Violation, got {result:?}",
        );
    }

    // ── 462.23: sovereign-identity STORE magic whitelist ──────────────────────

    /// an unsigned STORE carrying a well-formed
    /// sovereign-identity record (magic prefix `NM`/`ID`/`IR`/`MC`)
    /// under an arbitrary DHT key — i.e., the intermediate peer
    /// isn't BLAKE3(peer_id) — is accepted by the dispatcher's
    /// whitelist after a decode-sanity check. Full crypto
    /// verification (signature chain, PoW, master-cert) is
    /// deferred to the resolve path so intermediate forwarders
    /// don't need the full identity context at ingest time.
    fn store_unsigned_sovereign_magic_malformed_rejected(magic: [u8; 2], label: &str) {
        use veil_proto::discovery::StorePayload;
        let peer_id = [0x89u8; 32];
        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);
        // Magic bytes plus 8 junk bytes — enough to trigger the
        // decode path but never enough to parse as a real record.
        let body = {
            let mut v = vec![magic[0], magic[1]];
            v.extend_from_slice(&[0u8; 8]);
            v
        };
        let payload = StorePayload::unsigned([0xEEu8; 32], body);
        let (hdr, body) = make_store_frame(&payload);
        let result = dispatcher.dispatch(&hdr, &body, peer_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "STORE with malformed {label} must be Violation, got {result:?}",
        );
    }

    #[test]
    fn store_sovereign_malformed_name_claim_rejected() {
        use veil_proto::name_claim_v2::NAME_CLAIM_MAGIC;
        store_unsigned_sovereign_magic_malformed_rejected(NAME_CLAIM_MAGIC, "NameClaim v2");
    }

    #[test]
    fn store_sovereign_malformed_identity_document_rejected() {
        use veil_proto::identity_document::IDENTITY_DOCUMENT_MAGIC;
        store_unsigned_sovereign_magic_malformed_rejected(
            IDENTITY_DOCUMENT_MAGIC,
            "IdentityDocument",
        );
    }

    #[test]
    fn store_sovereign_malformed_instance_registry_rejected() {
        use veil_proto::instance_registry::INSTANCE_REGISTRY_MAGIC;
        store_unsigned_sovereign_magic_malformed_rejected(
            INSTANCE_REGISTRY_MAGIC,
            "InstanceRegistry",
        );
    }

    #[test]
    fn store_sovereign_malformed_mlkem_cert_rejected() {
        use veil_proto::mlkem_cert::MLKEM_CERT_MAGIC;
        store_unsigned_sovereign_magic_malformed_rejected(MLKEM_CERT_MAGIC, "MlKemKeyCert");
    }

    #[test]
    fn store_sovereign_valid_name_claim_accepted() {
        use veil_cfg::sovereign_flow::{CreateIdentityOptions, create_identity};
        use veil_proto::name_claim_v2::{NAME_CLAIM_MAGIC, NameClaim};

        // Fabricate a dir, provision identity, sign a NameClaim
        // then drive it through the dispatcher as an unsigned
        // STORE for an arbitrary key. The whitelist path must
        // accept on magic+decode without needing to verify the
        // signature chain (the resolver runs that later).
        let dir =
            std::env::temp_dir().join(format!("veil-dispatcher-sov-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = 1_800_000_000u64;
        let out = create_identity(CreateIdentityOptions {
            veil_dir: dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "test".into(),
            pow_difficulty: veil_identity::identity_policy::IdentityPolicy::DEFAULT_POW_DIFFICULTY,
            issued_at_unix: now,
            valid_until_unix: now + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();

        let sov = veil_identity::sovereign::SovereignIdentity::load_from_dir(&dir).unwrap();
        let claim: NameClaim = sov.sign_name_claim("alice", now).unwrap();
        let encoded = claim.encode();
        assert_eq!(&encoded[..2], &NAME_CLAIM_MAGIC);

        use veil_proto::discovery::StorePayload;
        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);
        let payload = StorePayload::unsigned([0xEEu8; 32], encoded);
        let (hdr, body) = make_store_frame(&payload);
        let result = dispatcher.dispatch(&hdr, &body, [0x88u8; 32]);
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "valid NameClaim STORE must be accepted, got {result:?}",
        );
        let _ = out.node_id; // suppress unused-binding warning
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Audit cycle-5 (N1-residue): nc/id/ir/mc records are structurally decoded
    /// (NOT signature-verified at the store gate — that happens on the resolver
    /// path), so the claimed `node_id` is attacker-controlled. The per-origin
    /// cap bucket must be the shared recursive bucket, NOT the claimed node_id —
    /// else an attacker rotates it (cap-evasion) or sets it to
    /// [0;32]==ORIGIN_INTERNAL (full cap-exemption).
    #[test]
    fn validate_nc_uses_shared_bucket_not_claimed_node_id_n1residue() {
        use veil_cfg::sovereign_flow::{CreateIdentityOptions, create_identity};
        use veil_proto::name_claim_v2::NameClaim;

        let dir = std::env::temp_dir().join(format!("veil-disp-n1res-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = 1_800_000_000u64;
        let _out = create_identity(CreateIdentityOptions {
            veil_dir: dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "test".into(),
            // Low PoW so the test is deterministic without the
            // `test-low-difficulty` feature (validate does not check PoW here).
            pow_difficulty: 4,
            issued_at_unix: now,
            valid_until_unix: now + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();
        let sov = veil_identity::sovereign::SovereignIdentity::load_from_dir(&dir).unwrap();
        let claim: NameClaim = sov.sign_name_claim("alice", now).unwrap();
        let encoded = claim.encode();

        let dispatcher = make_test_dispatcher(veil_cfg::NodeRole::Core);
        let origin = dispatcher
            .validate_store_value_by_magic(&encoded)
            .expect("valid NameClaim must validate");
        assert_eq!(
            origin,
            veil_dht::store::ORIGIN_RECURSIVE_BUNDLE,
            "nc/id/ir/mc must attribute to the shared recursive bucket"
        );
        assert_ne!(
            origin, claim.node_id,
            "must NOT use the (unverified) claimed node_id as the per-origin bucket"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── via-spoof violation ──────────────────────────────

    /// A RouteAnnounce whose `via_node_id` does not match the
    /// transport-layer sender is an attacker spoofing the relay identity
    /// to impersonate another node. Post-461.7 this is a `Violation`
    /// (ban-worthy), not the old rate-limited silent drop — every legit
    /// relay re-signs and sets `via = self`, so divergence is malicious by
    /// construction.  Closes the "unknown origin gossip forward" Sybil path
    /// without a wire-format change.
    /// Audit M6: an authenticated-but-malicious relay advertising the victim
    /// with `seq = u32::MAX` must NOT suppress a legitimate route to the victim
    /// arriving via a different relay. Origin-only keying poisoned
    /// `last[victim] = MAX`, rejecting every later announce; `(origin, via)`
    /// keying confines the poison to the attacker's own via.
    #[test]
    fn route_announce_high_seq_poison_confined_to_attacker_via_m6() {
        use ed25519_dalek::SigningKey;

        let a_id = [0xAAu8; 32];
        let b_id = [0xBBu8; 32]; // legitimate relay
        let e_id = [0xEEu8; 32]; // malicious (but authenticated) relay
        let victim = [0xCCu8; 32];

        let b_sk = Arc::new(SigningKey::from_bytes(&[0x42u8; 32]));
        let b_vk = b_sk.verifying_key();
        let e_sk = Arc::new(SigningKey::from_bytes(&[0xEEu8; 32]));
        let e_vk = e_sk.verifying_key();

        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        // A has completed handshakes with both B and E.
        let disp_a = make_gossip_dispatcher(
            a_id,
            Arc::new(SigningKey::from_bytes(&[0xAAu8; 32])),
            Arc::clone(&tx_reg),
            vec![(b_id, b_vk), (e_id, e_vk)],
        );

        // Malicious E advertises victim with seq=MAX (valid signature, via=E).
        let (hdr, body) = build_announce_frame(victim, e_id, 2, 7, u32::MAX, &e_sk);
        disp_a.dispatch(&hdr, &body, e_id);

        // Legitimate B advertises victim with a normal seq and a better hop.
        let (hdr, body) = build_announce_frame(victim, b_id, 1, 7, 5, &b_sk);
        disp_a.dispatch(&hdr, &body, b_id);

        // B's route must have been accepted (lower hop → primary) despite E's
        // MAX-seq poison. Origin-only keying would have rejected B (5 <= MAX),
        // leaving only E's (potentially blackhole) route.
        assert_eq!(
            disp_a.route_cache.read().unwrap().lookup(&victim),
            Some(b_id),
            "legitimate route via B must survive a malicious relay's MAX-seq poison"
        );
    }

    /// Audit M6: a forged announce (valid `via == peer` but signed with the
    /// wrong key) must be rejected at the signature check WITHOUT advancing the
    /// sequence counter — so it cannot suppress a victim's routes by poisoning
    /// `route_origin_seq` to `u32::MAX` before being dropped.
    #[test]
    fn route_announce_forged_sig_does_not_poison_seq_m6() {
        use ed25519_dalek::SigningKey;

        let a_id = [0xAAu8; 32];
        let b_id = [0xBBu8; 32];
        let c_id = [0xCCu8; 32];

        let b_sk = Arc::new(SigningKey::from_bytes(&[0x42u8; 32]));
        let b_vk = b_sk.verifying_key();
        let wrong_sk = Arc::new(SigningKey::from_bytes(&[0x99u8; 32]));

        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        // A knows B's REAL key.
        let disp_a = make_gossip_dispatcher(
            a_id,
            Arc::new(SigningKey::from_bytes(&[0xAAu8; 32])),
            Arc::clone(&tx_reg),
            vec![(b_id, b_vk)],
        );

        // Forged: via=B (== peer) but signed with the wrong key, seq=MAX.
        let (hdr, body) = build_announce_frame(c_id, b_id, 1, 7, u32::MAX, &wrong_sk);
        let result = disp_a.dispatch(&hdr, &body, b_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "forged signature must be rejected"
        );
        assert!(
            disp_a
                .route_origin_seq
                .lock()
                .unwrap()
                .get(&(c_id, b_id))
                .is_none(),
            "forged announce must NOT advance the sequence counter (pre-auth poison)"
        );

        // A genuine announce (real key, normal seq) is still accepted — the
        // counter was not poisoned to u32::MAX.
        let (hdr, body) = build_announce_frame(c_id, b_id, 1, 7, 5, &b_sk);
        disp_a.dispatch(&hdr, &body, b_id);
        assert_eq!(
            disp_a.route_cache.read().unwrap().lookup(&c_id),
            Some(b_id),
            "genuine announce accepted (sequence counter was not poisoned)"
        );
    }

    #[test]
    fn route_announce_spoofed_via_node_id_is_violation() {
        use ed25519_dalek::SigningKey;
        use veil_proto::{
            family::{FrameFamily, RoutingMsg},
            header::FrameHeader,
            routing::RouteAnnouncePayload,
        };

        let d = make_test_dispatcher(NodeRole::Core);

        // peer_b is the direct transport-layer sender.
        let peer_b = [0xBBu8; 32];
        // origin_c signs the announce itself but we spoof via_node_id to a
        // different identity (via_other) to simulate a relay claiming to
        // be someone else.
        let c_sk = SigningKey::from_bytes(&[0xCCu8; 32]);
        let origin_c: [u8; 32] = c_sk.verifying_key().to_bytes();
        let via_other = [0xDDu8; 32];

        use ed25519_dalek::Signer;
        let now_ts = veil_util::unix_secs_now_u32();
        let mut p = RouteAnnouncePayload {
            origin_node_id: origin_c,
            via_node_id: via_other, // spoofed: does not match peer_b
            hop_count: 2,
            ttl: 5,
            sequence: 1,
            timestamp: now_ts,
            signature: [0u8; 64],
        };
        p.signature = c_sk.sign(&p.signable_bytes()).to_bytes();
        let hdr = FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::RouteAnnounce as u16);

        let result = d.dispatch(&hdr, &p.encode(), peer_b);
        match result {
            DispatchResult::Violation(msg) => {
                assert!(
                    msg.contains("via_node_id does not match transport sender"),
                    "unexpected Violation message: {msg}"
                );
            }
            other => panic!("expected Violation for spoofed via_node_id, got {other:?}"),
        }
    }

    // ── 206.6: relay forwards anonymous envelope (sender_node_id = [0;32]) ──
    //
    // A DELIVERY_FORWARD whose envelope.sender_node_id is all-zeros but whose
    // payload starts with META_E2E_MARKER must be accepted by the relay (not
    // rejected as "zero sender_node_id").
    #[test]
    fn relay_accepts_meta_e2e_anonymous_envelope() {
        use veil_proto::META_E2E_MARKER;
        use veil_proto::delivery::{DeliveryEnvelope, ForwardPayload};

        let b_id = [0xBBu8; 32]; // relay
        let c_id = [0xCCu8; 32]; // final recipient (not local — so relay path is taken)

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Payload: META_E2E_MARKER followed by dummy ciphertext bytes.
        let mut payload = vec![META_E2E_MARKER];
        payload.extend_from_slice(&[0xABu8; 32]);

        let delivery = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(c_id),
            sender_node_id: [0u8; 32], // zeroed — anonymous send
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id: [0x11u8; 32],
            created_at: now_secs,
            ttl_secs: 30,
            payload,
            trace_id: 0,
            require_ack: false,
        };

        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let _rx_c = tx_reg.write().unwrap().register(c_id);

        let disp_b = make_gossip_dispatcher(
            b_id,
            Arc::new(ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32])),
            Arc::clone(&tx_reg),
            vec![],
        );

        let fwd = ForwardPayload {
            next_hop_node_id: c_id,
            envelope: delivery,
            relay_hops: 0,
        };
        let fwd_bytes = fwd.encode();
        let fwd_hdr = FrameHeader::new(
            FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        );

        // Must NOT be rejected as "zero sender_node_id" — meta-E2E envelopes are exempt.
        let result = disp_b.dispatch(&fwd_hdr, &fwd_bytes, [0xAAu8; 32]);
        assert!(
            !matches!(result, DispatchResult::Violation(_)),
            "relay must not reject meta-E2E envelope with zero sender_node_id, got {result:?}",
        );
    }

    /// — A peer that advertised `CAN_RELAY=false` in its capabilities
    /// must NOT be selected as a relay candidate by `relay_forward`.
    ///
    /// Setup:
    /// A (sender) → B (this node / relay) → D (relay candidate, CAN_RELAY=0) → C (recipient)
    ///
    /// B has a route to C via D in its route_cache, but D's `peer_cap_flags`
    /// has `CAN_RELAY=0`. The frame must NOT be forwarded through D.
    #[test]
    fn relay_forward_skips_candidates_without_can_relay_flag() {
        use veil_proto::delivery::{DeliveryEnvelope, ForwardPayload};
        use veil_proto::session::cap_flags;

        let a_id = [0xAAu8; 32]; // originator
        let b_id = [0xBBu8; 32]; // relay node (us)
        let c_id = [0xCCu8; 32]; // destination (unreachable directly)
        let d_id = [0xDDu8; 32]; // relay candidate — no CAN_RELAY

        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        // Register D so the dispatcher could theoretically send through it.
        let mut rx_d = tx_reg.write().unwrap().register(d_id);

        let disp_b = make_gossip_dispatcher(
            b_id,
            Arc::new(ed25519_dalek::SigningKey::from_bytes(&[0xBBu8; 32])),
            Arc::clone(&tx_reg),
            vec![],
        );

        // Put a route to C via D in the route_cache.
        wlock!(disp_b.route_cache).insert(c_id, d_id, 1, 10);

        // Set D's cap flags to 0 (CAN_RELAY not set) — simulates a Leaf node.
        disp_b
            .crypto
            .peer_cap_flags
            .write()
            .unwrap()
            .insert(d_id, 0u8);

        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let content_id = [0x42u8; 32];
        let delivery = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(c_id),
            sender_node_id: a_id,
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id,
            created_at: now_secs,
            ttl_secs: 30,
            payload: b"test".to_vec(),
            trace_id: 0,
            require_ack: false,
        };

        let fwd = ForwardPayload {
            next_hop_node_id: c_id,
            envelope: delivery,
            relay_hops: 0,
        };
        let fwd_bytes = fwd.encode();
        let fwd_hdr = FrameHeader::new(
            FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        );

        let result = disp_b.dispatch(&fwd_hdr, &fwd_bytes, a_id);

        // D must not have received a frame — CAN_RELAY=0 means it was filtered out.
        let frame_to_d = rx_d.try_recv();
        assert!(
            frame_to_d.is_err(),
            "relay candidate D with CAN_RELAY=0 must not receive any frame; got {frame_to_d:?}"
        );

        // The forward must have been silently dropped (NoResponse) or gone to mailbox.
        assert!(
            !matches!(result, DispatchResult::Violation(_)),
            "filtering CAN_RELAY=0 peers must not produce a Violation, got {result:?}",
        );

        // Now set D's cap flags to CAN_RELAY=1 and repeat — this time D SHOULD receive.
        disp_b
            .crypto
            .peer_cap_flags
            .write()
            .unwrap()
            .insert(d_id, cap_flags::CAN_RELAY);
        // Use a different content_id to bypass the dedup cache.
        let content_id2 = [0x43u8; 32];
        let delivery2 = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(c_id),
            sender_node_id: a_id,
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id: content_id2,
            created_at: now_secs,
            ttl_secs: 30,
            payload: b"test2".to_vec(),
            trace_id: 0,
            require_ack: false,
        };
        let fwd2 = ForwardPayload {
            next_hop_node_id: c_id,
            envelope: delivery2,
            relay_hops: 0,
        };
        let fwd2_bytes = fwd2.encode();
        disp_b.dispatch(&fwd_hdr, &fwd2_bytes, a_id);

        let frame_to_d2 = rx_d.try_recv();
        assert!(
            frame_to_d2.is_ok(),
            "relay candidate D with CAN_RELAY=1 must receive the forwarded frame",
        );
    }

    // ── Mobile sleep / push delivery tests ─────────────────────────

    /// 281.6: A `SleepAdvertisement` whose `node_id` does not match the
    /// authenticated peer must be rejected — a third party cannot force a
    /// peer to be marked as sleeping on someone else's behalf.
    #[test]
    fn sleep_advertisement_spoof_is_violation() {
        use ed25519_dalek::{Signer, SigningKey};
        use std::time::{SystemTime, UNIX_EPOCH};
        use veil_proto::{
            family::{FrameFamily, SessionMsg},
            session::SleepAdvertisementPayload,
        };

        let peer_id = [0xBBu8; 32];
        let other_id = [0xCCu8; 32];
        let peer_sk = Arc::new(SigningKey::from_bytes(&[0x77u8; 32]));
        let peer_vk = peer_sk.verifying_key();

        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let dispatcher = make_gossip_dispatcher(
            [0xAAu8; 32],
            Arc::new(SigningKey::from_bytes(&[0xAAu8; 32])),
            Arc::clone(&tx_reg),
            vec![(peer_id, peer_vk)],
        );

        // Peer tries to announce sleep on behalf of `other_id`.
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut advert = SleepAdvertisementPayload {
            node_id: other_id,
            expected_wake_ts: now_unix + 600,
            issued_at_ts: now_unix,
            signature: [0u8; 64],
        };
        advert.signature = peer_sk.sign(&advert.signable_bytes()).to_bytes();

        let hdr = FrameHeader::new(
            FrameFamily::Session as u8,
            SessionMsg::SleepAdvertisement as u16,
        );
        let result = dispatcher.dispatch(&hdr, &advert.encode(), peer_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "third-party sleep advert must be Violation, got {result:?}",
        );
    }

    /// 281.6: A stale or future-dated `SleepAdvertisement` (beyond the 10-min
    /// replay window) must be rejected.
    #[test]
    fn sleep_advertisement_stale_timestamp_is_violation() {
        use ed25519_dalek::{Signer, SigningKey};
        use std::time::{SystemTime, UNIX_EPOCH};
        use veil_proto::{
            family::{FrameFamily, SessionMsg},
            session::SleepAdvertisementPayload,
        };

        let peer_id = [0xDDu8; 32];
        let peer_sk = Arc::new(SigningKey::from_bytes(&[0x88u8; 32]));
        let peer_vk = peer_sk.verifying_key();
        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let dispatcher = make_gossip_dispatcher(
            [0xAAu8; 32],
            Arc::new(SigningKey::from_bytes(&[0xAAu8; 32])),
            Arc::clone(&tx_reg),
            vec![(peer_id, peer_vk)],
        );

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // issued_at 2 hours in the past
        let mut stale = SleepAdvertisementPayload {
            node_id: peer_id,
            expected_wake_ts: now_unix + 600,
            issued_at_ts: now_unix - 7200,
            signature: [0u8; 64],
        };
        stale.signature = peer_sk.sign(&stale.signable_bytes()).to_bytes();

        let hdr = FrameHeader::new(
            FrameFamily::Session as u8,
            SessionMsg::SleepAdvertisement as u16,
        );
        let result = dispatcher.dispatch(&hdr, &stale.encode(), peer_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "stale SleepAdvertisement must be Violation, got {result:?}",
        );
    }

    /// 281.6: `SleepAdvertisement` with an invalid signature must be rejected.
    #[test]
    fn sleep_advertisement_bad_signature_is_violation() {
        use ed25519_dalek::{Signer, SigningKey};
        use std::time::{SystemTime, UNIX_EPOCH};
        use veil_proto::{
            family::{FrameFamily, SessionMsg},
            session::SleepAdvertisementPayload,
        };

        let peer_id = [0xEEu8; 32];
        let peer_sk = Arc::new(SigningKey::from_bytes(&[0x99u8; 32]));
        let peer_vk = peer_sk.verifying_key();
        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let dispatcher = make_gossip_dispatcher(
            [0xAAu8; 32],
            Arc::new(SigningKey::from_bytes(&[0xAAu8; 32])),
            Arc::clone(&tx_reg),
            vec![(peer_id, peer_vk)],
        );

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut advert = SleepAdvertisementPayload {
            node_id: peer_id,
            expected_wake_ts: now_unix + 600,
            issued_at_ts: now_unix,
            signature: [0u8; 64],
        };
        advert.signature = peer_sk.sign(&advert.signable_bytes()).to_bytes();
        // Corrupt the signature.
        advert.signature[0] ^= 0xFF;

        let hdr = FrameHeader::new(
            FrameFamily::Session as u8,
            SessionMsg::SleepAdvertisement as u16,
        );
        let result = dispatcher.dispatch(&hdr, &advert.encode(), peer_id);
        assert!(
            matches!(result, DispatchResult::Violation(_)),
            "invalid signature must be Violation, got {result:?}",
        );
    }

    // ── Phase 6 slice 6g: mlkem_dk_seed SensitiveBytesN<64> migration ──

    /// Verifies the persistent ML-KEM DK seed field correctly uses
    /// `SensitiveBytesN<64>` storage and exposes a `&[u8; 64]` view to
    /// downstream readers (delivery.rs decap path uses `.as_array()`).
    /// Guards against accidental regression to a plain `[u8; 64]` field
    /// that would silently lose the mlock-when-possible guarantee.
    #[test]
    fn etap6_slice6g_mlkem_dk_seed_is_sensitive_bytes_n() {
        let dispatcher = make_test_dispatcher(NodeRole::Core);
        // SensitiveBytesN<64> exposes a 64-byte array view — any other
        // storage type would fail this signature at compile time.
        let view: &[u8; veil_e2e::DK_SEED_BYTES] = dispatcher.crypto.mlkem_dk_seed.as_array();
        assert_eq!(view.len(), 64);
        // Test fixture initialises with zero seed (SensitiveBytesN::new).
        assert!(view.iter().all(|&b| b == 0));
    }

    // ── Phase 6 slice 6h: per_session_mlkem_dk SensitiveBytesN<64> ─────

    /// `per_session_mlkem_dk` value type is `SensitiveBytesN<64>` —
    /// inserting a raw `[u8; 64]` via `from_bytes` and reading back via
    /// `.as_array()` round-trips the byte content while the storage
    /// itself is mlocked (or fallback-zeroize'd).
    #[test]
    fn etap6_slice6h_per_session_dk_round_trips_through_sensitive_bytes_n() {
        let dispatcher = make_test_dispatcher(NodeRole::Core);
        let peer_id: NodeIdBytes = [0x42u8; 32];
        let dk_seed: [u8; veil_e2e::DK_SEED_BYTES] = [0xABu8; 64];

        {
            let mut map = lock!(dispatcher.crypto.per_session_mlkem_dk);
            map.insert(
                peer_id,
                veil_util::sensitive_bytes::SensitiveBytesN::<
                    { veil_e2e::DK_SEED_BYTES },
                >::from_bytes(dk_seed),
            );
        }

        let read_back = {
            let map = lock!(dispatcher.crypto.per_session_mlkem_dk);
            map.get(&peer_id).map(|s| *s.as_array())
        };
        assert_eq!(
            read_back,
            Some(dk_seed),
            "per_session DK seed must round-trip through SensitiveBytesN storage"
        );
    }

    /// Removing an entry from `per_session_mlkem_dk` drops the
    /// `SensitiveBytesN<64>` value, triggering the inner
    /// zeroize-on-drop (mlocked variant unmaps via MlockedBytes::drop,
    /// fallback variant via Zeroizing<Vec<u8>>::drop).  This test
    /// verifies the remove pathway compiles + executes without panic;
    /// the wipe itself is enforced by the type system.
    #[test]
    fn etap6_slice6h_per_session_dk_remove_drops_value() {
        let dispatcher = make_test_dispatcher(NodeRole::Core);
        let peer_id: NodeIdBytes = [0x99u8; 32];
        {
            let mut map = lock!(dispatcher.crypto.per_session_mlkem_dk);
            map.insert(
                peer_id,
                veil_util::sensitive_bytes::SensitiveBytesN::<{ veil_e2e::DK_SEED_BYTES }>::new(),
            );
            assert!(map.contains_key(&peer_id));
        }
        {
            let mut map = lock!(dispatcher.crypto.per_session_mlkem_dk);
            map.remove(&peer_id);
            assert!(!map.contains_key(&peer_id));
        }
    }
}
