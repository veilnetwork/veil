//! Kademlia DHT service (core-only).
//!
//! This is an **in-process** Kademlia implementation. It stores values
//! locally using the `StaticDirectory` and answers FIND_NODE /
//! FIND_VALUE / STORE / DELETE requests.
//!
//! # Network I/O
//!
//! `KademliaService` answers local FIND_NODE / FIND_VALUE / STORE / DELETE
//! requests against its own store, AND drives cross-node iterative lookups (the
//! multi-hop "closest-node walk") through the `network_querier` / `iterative`
//! glue — see `find_node_iterative_network`, `find_value_iterative_network`,
//! `find_all_values_network`, and `publish_to_network`. The transport layer
//! supplies the per-hop query transport; the walk logic lives here.
//!
//! # Role enforcement
//!
//! Only `NodeRole::Core` participates in DHT ownership. `Gateway` may store
//! attachment records on behalf of their leaves (bridging to core via
//! `DiscoveryService`). `Leaf` and `Relay` cannot store.

use std::{
    sync::atomic::{AtomicU32, Ordering},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use veil_util::lock;

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

use veil_proto::discovery::{
    DeletePayload, FindNodeV2Payload, FindNodeV2Response, FindValuePayload, FindValueResponse,
    ResolveTransportPayload, ResolveTransportResponse, StorePayload,
};

use veil_types::NodeIdBytes;

use super::routing::{Contact, RoutingTable, xor_distance};
use crate::traits::{CoordinateOracle, DhtMetrics, DhtRuntimeConfig, FrameRouter, RttHint};

// ── DhtValueSnapshot ─────────────────────────────────────────────────────────

/// One stored DHT key-value pair, serialisable for persistence.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DhtValueSnapshot {
    #[serde(with = "hex_array")]
    pub key: [u8; 32],
    #[serde(with = "serde_bytes_base64")]
    pub value: Vec<u8>,
}

// c: serde helpers moved to `proto::serde_base64` so wire-format
// definitions in proto can reference them without importing from `node::dht`.
pub(crate) use veil_proto::serde_base64::{hex_array, serde_bytes_base64};

// ── KademliaError ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KademliaError {
    /// Generic "the daemon refused this request" — kept for backwards
    /// compatibility with callers that match against the unit variant.
    /// New code should prefer one of the more specific variants below
    /// so logs / metrics can distinguish accidental misconfiguration
    /// from active attack patterns.
    NotAllowed,
    /// `[dht] participate = false` —
    /// node is configured not to act as a DHT storage peer. Not an
    /// attack indicator; expected on leaf-only deployments.
    DhtParticipationDisabled,
    /// STORE/FIND_VALUE for a key outside this
    /// node's local shard set with `shard_filtering = true` enabled.
    /// Not an attack indicator; expected when a peer is asking the
    /// wrong node. Caller should retry against a peer whose
    /// `node_id[0]` is closer to the key's shard prefix.
    NotInLocalShard,
    /// STORE arrived without an authenticator
    /// (no `ed25519_pubkey`/`ed25519_sig`) and the runtime config has
    /// `allow_unsigned_store = false`. Possible attack indicator —
    /// any peer in the shard could otherwise fill `TieredStore` with
    /// arbitrary `(key, value)` and evict honest records.
    UnsignedStoreRejected,
    /// DELETE used an unsupported algo byte
    /// (neither Ed25519 nor Falcon-512). Possible attack indicator
    /// (probing for downgrade) or a future-version peer.
    UnsupportedDeleteAlgo,
    /// DELETE's `BLAKE3(pubkey)!= key`.
    /// Definite attack indicator — caller is trying to delete a
    /// record they don't own.
    DeleteOwnershipMismatch,
    /// STORE/DELETE rejected: the ed25519/falcon signature is present
    /// but invalid, or the public key does not derive to the claimed
    /// DHT key. Distinct from `UnsignedStoreRejected` (no sig at
    /// all) — this means a sig was supplied but doesn't verify.
    InvalidSignature,
    /// STORE carried a P-Net `PBAN` magic prefix but the configured
    /// `NetworkAuthGate` rejected it (decode failure, wrong network,
    /// invalid chain-of-trust signature, or key ≠ derived ban-DHT key).
    /// Distinct from `InvalidSignature` so the receiver side can spot
    /// ban-record attacks separately from generic Ed25519 STORE abuse.
    /// Also returned when a PBAN-prefixed STORE arrives but no auth gate
    /// is wired (public-mode node should not receive these).
    InvalidNetworkRecord,
    /// STORE rejected: the originating signer is already holding more
    /// bytes than the configured `[dht] per_origin_max_bytes` cap allows
    /// (Phase 11e).  Possible attack indicator — a single signer trying
    /// to occupy more storage than the per-origin budget permits.  Honest
    /// signers normally hold a handful of records (NameClaim +
    /// IdentityDocument + a small fan-out of AppEndpointEntry), so
    /// hitting this cap reliably means the signer is misbehaving.  Cap
    /// is enforced locally — a peer that hits the cap on one node can
    /// still place records on other nodes whose limits are higher.
    PerOriginByteCapExceeded,
}

impl std::fmt::Display for KademliaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAllowed => write!(f, "DHT request refused"),
            Self::DhtParticipationDisabled => write!(
                f,
                "DHT participation is disabled on this node ([dht] participate = false)"
            ),
            Self::NotInLocalShard => {
                write!(f, "DHT request key is outside this node's local shard set")
            }
            Self::UnsignedStoreRejected => write!(
                f,
                "STORE rejected: unsigned authenticator + allow_unsigned_store=false"
            ),
            Self::UnsupportedDeleteAlgo => {
                write!(f, "DELETE rejected: unsupported signature algo byte")
            }
            Self::DeleteOwnershipMismatch => {
                write!(f, "DELETE rejected: BLAKE3(pubkey) does not match key")
            }
            Self::InvalidSignature => write!(
                f,
                "STORE/DELETE rejected: invalid or malformed ownership signature"
            ),
            Self::InvalidNetworkRecord => write!(
                f,
                "STORE rejected: P-Net ban record failed gate verification (or no gate wired)"
            ),
            Self::PerOriginByteCapExceeded => write!(
                f,
                "STORE rejected: signer's per-origin byte cap exceeded ([dht] per_origin_max_bytes)"
            ),
        }
    }
}

/// One-shot deprecation warning emitted the first time a STORE is
/// accepted via the legacy `allow_unsigned_store = true` path.  Logged
/// at `warn` so operators see it in normal cleanup-tick noise; subsequent
/// unsigned STOREs are silent to avoid log spam.  Migration plan: once
/// inner-sig deployments transition to explicit STORE-level signatures
/// the default for `allow_unsigned_store` will flip to `false`.
fn warn_unsigned_store_once() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static WARNED: AtomicBool = AtomicBool::new(false);
    if !WARNED.swap(true, Ordering::Relaxed) {
        log::warn!(
            "[dht] accepted unsigned STORE via allow_unsigned_store=true (legacy path) — \
             plan migration to signed STOREs; see docs/OPERATIONS.md → 'Phase 11e migration'"
        );
    }
}

// ── KademliaService ───────────────────────────────────────────────────────────

/// In-process Kademlia service for a core node.
///
/// Clone-cheap: inner state is behind `Arc<Mutex<_>>`.
#[derive(Clone)]
pub struct KademliaService {
    inner: Arc<Mutex<KademliaInner>>,
    /// Whether this node accepts STORE / DELETE operations.
    /// Defaults to `true`; can be disabled via `[dht] participate = false` in config.
    participate: bool,
    /// Optional shared RTT-hint surface used as a tie-breaker in `find_closest`.
    rtt_table: Option<Arc<dyn RttHint>>,
    /// Optional Vivaldi-distance oracle (combines local + per-peer coords).
    coord_oracle: Option<Arc<dyn CoordinateOracle>>,
    /// Monotonic request-ID counter for outbound STORE frames.
    /// Starts at `0x8000_0000` so it does not collide with reply IDs (which
    /// start near zero).
    store_req_id: Arc<AtomicU32>,
    /// Runtime DHT tuning parameters (k, alpha, max_rounds, find_node_timeout_ms).
    dht_config: DhtRuntimeConfig,
    /// Optional metrics handle — wired by the runtime after construction.
    metrics: Option<Arc<dyn DhtMetrics>>,
    /// shared client-side cache for `node_id → transport`
    /// mappings observed via prior `ResolveTransport` responses. Every
    /// `NetworkPeerQuerier` constructed inside this service shares this
    /// cache so a warm entry from one DHT-walk benefits subsequent walks.
    /// The maintenance task calls `evict_stale` on it periodically.
    transport_cache: Arc<Mutex<super::transport_cache::TransportCache>>,
    /// per-node bounded LRU cache for FIND_NODE iterative
    /// results. Cold lookup at trillion scale ≈ 4 seconds (O(log N)
    /// round-trips × per-hop RTT); cache hit ≈ 0. Critical for
    /// interactive UX when same target is queried repeatedly (e.g.
    /// popular relay's `relay_directory_dht_key`).
    /// Bounded LRU with TTL — see [`super::lookup_cache::LookupCache`].
    lookup_cache: Arc<Mutex<super::lookup_cache::LookupCache>>,
    ///our own self-signed transport
    /// announcement. Initialised by the runtime at startup via
    /// [`Self::configure_local_announcement_source`]; read on every
    /// handshake-complete so we can gossip it to the new peer via
    /// `AnnounceTransport`. `None` only on transient nodes that have
    /// no advertised listening transport (pure outbound clients) —
    /// those still verify peers' announcements but never publish their own.
    local_announcement: Arc<Mutex<Option<veil_proto::discovery::SignedTransportAnnouncement>>>,
    /// backlog: signing key + transport URI used to mint
    /// `local_announcement`. Stored so the maintenance tick can
    /// re-mint a fresh announcement before the existing one expires
    /// (see [`Self::maybe_remint_local_announcement`]). Without
    /// re-minting, a long-running peer goes silent in
    /// `ResolveTransport` responses ~30 days after startup, which a
    /// patient censor can wait out — re-mint happens at half-validity
    /// (~15 days), giving every long-lived peer a fresh signature
    /// + an `AnnounceTransport` re-gossip to all live sessions.
    local_announcement_source: LocalAnnouncementSource,
    /// P-Net authentication gate. When wired (private-mode node), STORE
    /// payloads whose value carries the `PBAN` magic prefix are routed
    /// here for chain-of-trust verification instead of the standard
    /// Ed25519 signed-STORE path. Public-mode nodes leave this `None`,
    /// which rejects all PBAN-prefixed STOREs as
    /// `KademliaError::InvalidNetworkRecord`.
    network_auth_gate: Option<Arc<dyn super::traits::NetworkAuthGate>>,
}

/// backlog: optional source material for re-minting the
/// local node's `AnnounceTransport`. `Some((sk, transport_uri))`
/// when the runtime threaded the identity SK + transport URI in;
/// `None` otherwise (no re-mint task wired). Wrapped in Arc<Mutex>
/// so the maintenance tick can read without contending on the main
/// kademlia state lock.
type LocalAnnouncementSource = Arc<Mutex<Option<(Arc<ed25519_dalek::SigningKey>, String)>>>;

/// Default TTL for stored DHT values (1 hour).
pub const DEFAULT_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug)]
struct KademliaInner {
    routing: RoutingTable,
    ///per-peer self-signed transport
    /// announcements, indexed by `node_id`. Populated by the
    /// `AnnounceTransport` handler when an inbound peer gossips its
    /// announcement (verified before insert). Returned verbatim by
    /// `handle_resolve_transport` so the requester can verify the
    /// signature themselves and bind transport ↔ identity. Capped at
    /// `K_BUCKET_SIZE × MAX_BUCKETS = 20 × 256 ≈ 5120` entries by
    /// virtue of the routing table eviction (we drop the announcement
    /// when the routing-table contact is evicted — see
    /// `prune_orphan_announcements`).
    transport_announcements:
        std::collections::HashMap<[u8; 32], veil_proto::discovery::SignedTransportAnnouncement>,
    /// Tiered key-value store: hot HashMap + cold HashMap with
    /// LRU promotion. Replaces the previous flat HashMap + BTreeMap pair.
    store: super::store::TieredStore,
    /// 2-tier routing — unverified candidate contacts from
    /// FIND_NODE responses, NeighborOffer frames, and other peer-
    /// controlled sources. An entry here is NOT in the main routing
    /// table and will NOT be returned from `find_closest`. Promotion
    /// to the main table happens via `promote_contact_if_pending`
    /// called from the handshake-completion path — at that point the
    /// peer has proven it owns the claimed node_id (OVL1 sig-verify
    /// on KeyAgreement), so trusting its reachability is safe.
    ///
    /// Capped at `PENDING_CONTACTS_CAP` to bound adversarial growth;
    /// FIFO eviction when full. Entries that never get promoted
    /// eventually fall out of the cap when legitimate peers churn in.
    pending_contacts: std::collections::HashMap<[u8; 32], Contact>,
    /// Insertion-order queue used to evict the oldest pending contact
    /// when `pending_contacts` reaches `PENDING_CONTACTS_CAP`.
    pending_order: std::collections::VecDeque<[u8; 32]>,
    /// track which source peer introduced each pending
    /// contact, so we can enforce a per-source quota. Without this
    /// a single Sybil peer can fill the global `PENDING_CONTACTS_CAP`
    /// (1024) with claimed (node_id, transport) pairs and eclipse the
    /// honest peers' contributions until churn evicts them.
    pending_source_of: std::collections::HashMap<[u8; 32], [u8; 32]>,
    /// per-source pending-contact counter. Bumped on
    /// `add_contact_unverified_from`, decremented on promote/evict.
    pending_per_source: std::collections::HashMap<[u8; 32], u32>,
}

/// maximum number of unverified contacts we'll hold in
/// the pending-promotion map. Tuned to be large enough for normal
/// churn during bootstrap (a few dozen FIND_NODE responses × K
/// contacts each) but small enough to cap adversarial memory growth
/// at < 100 KiB (`32 + ~120` bytes per entry × 1024).
const PENDING_CONTACTS_CAP: usize = 1024;

/// per-source quota inside `PENDING_CONTACTS_CAP`.
/// Honest bootstrap chains rarely deliver more than ~K=20 contacts
/// per FIND_NODE response, so 16 per source is enough for normal
/// recursion while ensuring a single Sybil source can occupy at most
/// `MAX_PENDING_PER_SOURCE / PENDING_CONTACTS_CAP = 1.5%` of the map.
const MAX_PENDING_PER_SOURCE: u32 = 16;

impl KademliaInner {
    fn new(
        routing: RoutingTable,
        max_store_entries: usize,
        max_store_bytes: Option<u64>,
        per_origin_max_bytes: Option<u64>,
        cold_store_path: Option<&str>,
    ) -> Self {
        // Hot tier = 25% of capacity, cold tier = 75%.
        let hot_cap = (max_store_entries / 4).max(64);
        let cold_cap = max_store_entries.saturating_sub(hot_cap);
        // `cold_store_path` (when set + the `rocksdb-cold` feature is built)
        // swaps the in-memory cold tier for a disk-backed RocksDB store; on a
        // missing feature or open failure it logs and falls back to in-memory.
        let mut store = super::store::build_tiered_store(hot_cap, cold_cap, cold_store_path);
        if let Some(cap) = max_store_bytes {
            store = store.with_max_bytes(cap);
        }
        if let Some(cap) = per_origin_max_bytes {
            store = store.with_per_origin_max_bytes(cap);
        }
        Self {
            routing,
            transport_announcements: std::collections::HashMap::new(),
            store,
            pending_contacts: std::collections::HashMap::new(),
            pending_order: std::collections::VecDeque::new(),
            pending_source_of: std::collections::HashMap::new(),
            pending_per_source: std::collections::HashMap::new(),
        }
    }

    /// Insert or overwrite a key (delegates to TieredStore).  Internal
    /// path — bypasses the per-origin cap (uses [`ORIGIN_INTERNAL`]).
    fn store_insert(&mut self, key: [u8; 32], value: Vec<u8>) {
        self.store.put(key, value);
    }

    /// Insert or overwrite a key from a wire-level STORE, carrying the
    /// originating signer id (Phase 11e).  Returns `true` on accept,
    /// `false` if refused by the per-origin byte cap.
    fn store_insert_with_origin(
        &mut self,
        key: [u8; 32],
        value: Vec<u8>,
        origin: [u8; 32],
    ) -> bool {
        self.store.put_with_origin(key, value, origin)
    }

    /// Remove a key.
    fn store_remove(&mut self, key: &[u8; 32]) {
        self.store.remove(key);
    }

    /// Remove expired entries from both tiers.
    ///
    /// DHT TTL eviction is purely age-based (record-level expiry is enforced
    /// elsewhere on read/store), so use the age-only path: it skips the
    /// cold-tier value materialization that a value-predicate would force
    /// (audit cycle-8 — the old `|_| false` predicate scanned the entire
    /// RocksDB value set into RAM every cleanup tick for a no-op filter).
    fn retain_fresh(&mut self, now: Instant, ttl: Duration) {
        self.store.retain_fresh_age_only(now, ttl);
    }

    /// Test helper: insert with an arbitrary timestamp.
    #[cfg(test)]
    fn store_insert_raw(&mut self, key: [u8; 32], value: Vec<u8>, ts: Instant) {
        self.store.put_at(key, value, ts);
    }
}

impl KademliaService {
    pub fn new(local_id: [u8; 32]) -> Self {
        Self::with_config(local_id, DhtRuntimeConfig::default())
    }

    /// Participation is controlled by `dht_config.participate` (role-independent).
    pub fn with_config(local_id: [u8; 32], dht_config: DhtRuntimeConfig) -> Self {
        let participate = dht_config.participate;
        let inner = KademliaInner::new(
            RoutingTable::with_k(local_id, dht_config.k as usize),
            dht_config.max_store_entries,
            dht_config.max_store_bytes,
            dht_config.per_origin_max_bytes,
            dht_config.cold_store_path.as_deref(),
        );
        Self {
            inner: Arc::new(Mutex::new(inner)),
            participate,
            rtt_table: None,
            coord_oracle: None,
            store_req_id: Arc::new(AtomicU32::new(0x8000_0000)),
            dht_config,
            metrics: None,
            transport_cache: Arc::new(Mutex::new(super::transport_cache::TransportCache::new())),
            lookup_cache: Arc::new(Mutex::new(super::lookup_cache::LookupCache::with_defaults())),
            local_announcement: Arc::new(Mutex::new(None)),
            local_announcement_source: Arc::new(Mutex::new(None)),
            network_auth_gate: None,
        }
    }

    /// Wire the P-Net authentication gate. Call once at startup if
    /// `[network].mode = "private"`. Cloning is cheap (`Arc<dyn …>`);
    /// the gate's `verify_ban_record` runs on every STORE whose value
    /// begins with `PBAN`.
    pub fn set_network_auth_gate(&mut self, gate: Arc<dyn super::traits::NetworkAuthGate>) {
        self.network_auth_gate = Some(gate);
    }

    /// Set whether this node accepts STORE / DELETE operations.
    pub fn set_participate(&mut self, participate: bool) {
        self.participate = participate;
    }

    /// Returns a reference to the DHT configuration for this service.
    pub fn dht_config(&self) -> &DhtRuntimeConfig {
        &self.dht_config
    }

    /// Configured k-bucket size (K parameter).
    pub fn k(&self) -> usize {
        self.dht_config.k as usize
    }

    /// shared client-side `TransportCache` used by every
    /// DHT-walk on this service. Exposed so the runtime's maintenance tick
    /// can call `evict_stale` on it without keeping a separate Arc.
    pub fn transport_cache(&self) -> Arc<Mutex<super::transport_cache::TransportCache>> {
        Arc::clone(&self.transport_cache)
    }

    /// metrics-only accessors for the heap-resident DHT
    /// substructures. Operators watch these to correlate RSS with logical
    /// growth of the DHT state machine. Cheap O(1) locks.
    pub fn store_len(&self) -> usize {
        lock!(self.inner).store.len()
    }
    pub fn transport_cache_len(&self) -> usize {
        lock!(self.transport_cache).len()
    }
    pub fn lookup_cache_len(&self) -> usize {
        lock!(self.lookup_cache).len()
    }

    ///local node id. Outbound walkers bind
    /// it into the `ResolveTransport` PoW solution so the responder can
    /// verify the work was done by *this* node — and not reused from a
    /// different requester's prior solution.
    pub fn local_node_id(&self) -> [u8; 32] {
        *lock!(self.inner).routing.local_id()
    }

    ///set our self-signed transport
    /// announcement. Lower-level setter used by tests and by callers
    /// that own the bundle directly; production startup goes through
    /// [`Self::configure_local_announcement_source`] so the maintenance
    /// tick can re-mint before expiry.
    pub fn set_local_announcement(
        &self,
        announcement: veil_proto::discovery::SignedTransportAnnouncement,
    ) {
        *lock!(self.local_announcement) = Some(announcement);
    }

    /// backlog: configure the signing source used (re-)mint
    /// the local transport announcement. Sets the initial bundle
    /// (expiry = `now + ANNOUNCEMENT_VALIDITY_SECS`) AND retains the
    /// `SigningKey + transport` pair so the maintenance tick can call
    /// [`Self::maybe_remint_local_announcement`] when the bundle nears
    /// expiry.
    ///
    /// Idempotent — calling again overwrites the source AND the bundle.
    pub fn configure_local_announcement_source(
        &self,
        signing_key: Arc<ed25519_dalek::SigningKey>,
        transport: String,
    ) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let expiry = now + veil_proto::discovery::ANNOUNCEMENT_VALIDITY_SECS;
        let announcement = veil_proto::discovery::sign_transport_announcement(
            &signing_key,
            transport.clone(),
            expiry,
        );
        *lock!(self.local_announcement) = Some(announcement);
        *lock!(self.local_announcement_source) = Some((signing_key, transport));
    }

    /// backlog: re-mint the local announcement iff its
    /// remaining validity is `≤ ANNOUNCEMENT_VALIDITY_SECS / 2`.
    /// Called from the maintenance tick on every iteration; cheap
    /// no-op when the existing bundle is fresh, ~50 µs (one
    /// Ed25519 sign) when re-minting is needed.
    ///
    /// Returns `Some(new_announcement)` when re-minted (so the caller
    /// can re-gossip via `AnnounceTransport` to all live sessions)
    /// or `None` when the bundle is still fresh enough OR when no
    /// signing source is configured (pure outbound clients).
    pub fn maybe_remint_local_announcement(
        &self,
        now_unix: u64,
    ) -> Option<veil_proto::discovery::SignedTransportAnnouncement> {
        // Snapshot source + current bundle; release locks before the
        // signature computation (sign_transport_announcement is pure
        // CPU but we want to avoid holding two mutexes during it).
        let source = lock!(self.local_announcement_source).clone()?;
        let current_expiry = lock!(self.local_announcement).as_ref()?.expiry_unix;
        let remaining = current_expiry.saturating_sub(now_unix);
        if remaining > veil_proto::discovery::ANNOUNCEMENT_VALIDITY_SECS / 2 {
            return None;
        }
        let (sk, transport) = source;
        let new_expiry = now_unix + veil_proto::discovery::ANNOUNCEMENT_VALIDITY_SECS;
        let new_ann =
            veil_proto::discovery::sign_transport_announcement(&sk, transport, new_expiry);
        *lock!(self.local_announcement) = Some(new_ann.clone());
        Some(new_ann)
    }

    ///clone of the current local
    /// announcement, ready to gossip. `None` if the runtime hasn't
    /// configured one (e.g. pure outbound clients with no listening
    /// transport — they verify peers' announcements but never publish).
    pub fn local_announcement(&self) -> Option<veil_proto::discovery::SignedTransportAnnouncement> {
        lock!(self.local_announcement).clone()
    }

    ///verify and store an inbound peer's
    /// signed transport announcement. Returns `true` iff the bundle
    /// passed verification (signature, pubkey ↔ node_id binding
    /// non-expired); rejected announcements are silently dropped.
    ///
    /// `now_unix` is supplied so callers can use a deterministic clock
    /// in tests. Production callers pass current Unix-seconds.
    pub fn store_transport_announcement(
        &self,
        announcement: veil_proto::discovery::SignedTransportAnnouncement,
        now_unix: u64,
    ) -> bool {
        if !veil_proto::discovery::verify_transport_announcement(&announcement, now_unix) {
            return false;
        }
        let node_id = announcement.node_id;
        let mut inner = lock!(self.inner);
        inner.transport_announcements.insert(node_id, announcement);
        true
    }

    ///observability — count of stored
    /// peer announcements. Used by `node show` / metrics.
    pub fn transport_announcements_count(&self) -> usize {
        lock!(self.inner).transport_announcements.len()
    }

    ///snapshot every stored
    /// `SignedTransportAnnouncement` for on-disk persistence. Includes
    /// all entries regardless of expiry — `restore_transport_announcements`
    /// re-verifies on load and drops stale ones.
    pub fn snapshot_transport_announcements(
        &self,
    ) -> Vec<veil_proto::discovery::SignedTransportAnnouncement> {
        lock!(self.inner)
            .transport_announcements
            .values()
            .cloned()
            .collect()
    }

    ///bulk-restore announcements from an
    /// on-disk snapshot. Each entry is verified independently
    /// (`verify_transport_announcement`); signature failures, pubkey-binding
    /// mismatches, and expired entries are silently dropped. Returns
    /// `(inserted, rejected)` so the caller can log restore stats.
    ///
    /// `now_unix` is supplied so tests can use a deterministic clock.
    pub fn restore_transport_announcements(
        &self,
        snapshot: Vec<veil_proto::discovery::SignedTransportAnnouncement>,
        now_unix: u64,
    ) -> (usize, usize) {
        let mut inserted = 0usize;
        let mut rejected = 0usize;
        let mut inner = lock!(self.inner);
        for ann in snapshot {
            if !veil_proto::discovery::verify_transport_announcement(&ann, now_unix) {
                rejected += 1;
                continue;
            }
            let node_id = ann.node_id;
            inner.transport_announcements.insert(node_id, ann);
            inserted += 1;
        }
        (inserted, rejected)
    }

    ///drop announcements whose `node_id`
    /// no longer has a routing-table entry — bounds memory under
    /// adversarial churn. Cheap O(n). Called from the maintenance
    /// tick alongside `tick_evict_transport_cache`.
    pub fn prune_orphan_announcements(&self) -> usize {
        let mut inner = lock!(self.inner);
        let before = inner.transport_announcements.len();
        let mut to_remove = Vec::new();
        for nid in inner.transport_announcements.keys() {
            if !inner.routing.contains(nid) {
                to_remove.push(*nid);
            }
        }
        for nid in to_remove {
            inner.transport_announcements.remove(&nid);
        }
        before - inner.transport_announcements.len()
    }

    /// Set the sketch bucket threshold.
    /// Buckets with index `< threshold` are capped at 1 contact.
    pub fn set_sketch_threshold(&self, threshold: usize) {
        lock!(self.inner).routing.set_sketch_threshold(threshold);
    }

    /// Wire observability metrics into this service.
    pub fn set_metrics(&mut self, metrics: Arc<dyn DhtMetrics>) {
        self.metrics = Some(metrics);
    }

    /// Attach an [`RttHint`] so that `find_closest` can use RTT as a
    /// tie-breaker when multiple contacts have equal XOR distance.
    pub fn set_rtt_table(&mut self, rtt_table: Arc<dyn RttHint>) {
        self.rtt_table = Some(rtt_table);
    }

    /// Attach a Vivaldi coordinate oracle for topology-aware DHT ranking.
    ///
    /// When set, the `handle_find_node_v2` / `handle_find_value` paths rank
    /// peers using `composite = xor_distance × (1 + vivaldi_weight × factor)`
    /// where `factor = oracle.estimated_distance(peer) / 100.0`.
    pub fn set_coord_oracle(&mut self, oracle: Arc<dyn CoordinateOracle>) {
        self.coord_oracle = Some(oracle);
    }

    fn can_participate(&self) -> bool {
        self.participate
    }

    // ── handlers ─────────────────────────────────────────────────────────
    //
    // V1 `handle_find_node` was removed (475.6) —
    // V1 leaked transports en masse and is no longer a supported wire
    // type. All FIND_NODE traffic goes through V2 + ResolveTransport.
    // The Vivaldi/RTT-aware ranking that lived on V1 was hoisted into
    // [`Self::ranked_public_contacts`] so V2 + FIND_VALUE share it.

    /// Internal helper used by `handle_find_node_v2` and the
    /// not-found branch of `handle_find_value`. Returns the closest
    /// Public-only contacts to `target`, sorted by composite Vivaldi
    /// score (or RTT tie-breaker, falling back to pure XOR), and
    /// capped at `min(k_requested, K_dht, ceil(n_public / 2))`
    ///
    ///
    /// Was extracted from V1 `handle_find_node` when
    /// (475.6) deleted that handler — keeping the ranking logic on the
    /// V2 path preserves topology-aware routing that operators
    /// configure via `[dht] vivaldi_weight`.
    fn ranked_public_contacts(&self, target: &[u8; 32], k_requested: usize) -> Vec<Contact> {
        let inner = lock!(self.inner);
        let mut contacts: Vec<Contact> = inner
            .routing
            .find_closest(target, self.k())
            .into_iter()
            .filter(|c| matches!(c.discovery_mode(), veil_types::DiscoveryMode::Public))
            .cloned()
            .collect();

        let vivaldi_weight = self.dht_config.vivaldi_weight;
        let use_vivaldi = vivaldi_weight != 0.0 && self.coord_oracle.is_some();

        if let (true, Some(oracle)) = (use_vivaldi, self.coord_oracle.as_ref()) {
            let composite_score = |c: &Contact| -> f64 {
                let xor = xor_distance(&c.node_id, target);
                // P7: avoid `try_into.unwrap` panic-path —
                // `xor_distance` returns `[u8; 32]` so the first 8 bytes
                // always fit, but a future signature change would silently
                // turn this into a release-time `abort`. Direct copy is
                // panic-free regardless.
                let mut xor8 = [0u8; 8];
                xor8.copy_from_slice(&xor[..8]);
                let xor_f64 = u64::from_be_bytes(xor8) as f64;
                let vivaldi_factor = oracle
                    .estimated_distance(&c.node_id)
                    .map(|d| d / 100.0)
                    .unwrap_or(0.0)
                    .max(0.0);
                xor_f64 * (1.0 + vivaldi_weight * vivaldi_factor)
            };
            contacts.sort_by(|a, b| {
                composite_score(a)
                    .partial_cmp(&composite_score(b))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        } else if let Some(rtt_hint) = &self.rtt_table {
            contacts.sort_by(|a, b| {
                let rtt_a = rtt_hint.rtt_ms(&a.node_id).unwrap_or(u32::MAX);
                let rtt_b = rtt_hint.rtt_ms(&b.node_id).unwrap_or(u32::MAX);
                rtt_a.cmp(&rtt_b)
            });
        }

        // cap = min(K_requested, K_dht_default, ceil(N_public / 2)).
        let n_public = contacts.len();
        let half_cap = n_public.div_ceil(2).max(1);
        let limit = k_requested.min(self.k()).min(half_cap);
        contacts.truncate(limit);
        contacts
    }

    /// — handle `FIND_NODE_V2`.
    ///
    /// Filter + cap rules (Public-only +
    /// `min(K, ceil(N_public / 2))`), ranking from
    /// [`Self::ranked_public_contacts`] (Vivaldi → RTT → XOR).
    /// Response carries **node_ids only** — no transports. Caller
    /// must follow up with [`Self::handle_resolve_transport`] for any
    /// node_id whose transport URL is needed.
    pub fn handle_find_node_v2(&self, payload: FindNodeV2Payload) -> FindNodeV2Response {
        let contacts = self.ranked_public_contacts(&payload.target, payload.k as usize);
        FindNodeV2Response {
            node_ids: contacts.into_iter().map(|c| c.node_id).collect(),
        }
    }

    /// — handle `RESOLVE_TRANSPORT`.
    ///
    /// Per-node-id transport lookup with privacy filter and PoW gate.
    /// Returns the transport URL iff **all** of:
    /// 1. The requester's PoW solution covers
    ///    `(requester_node_id, payload.node_id, payload.time_bucket
    /// payload.pow_nonce)` at ≥ `RESOLVE_POW_DIFFICULTY` leading
    ///    zero bits — see [`veil_proto::discovery::verify_resolve_pow`].
    /// 2. The requester's `time_bucket` is within
    ///    `RESOLVE_POW_TIME_WINDOW_BUCKETS` of our own current bucket
    ///    (limits replay window to ~120 s).
    /// 3. We have a `Contact` for `node_id` in the routing table.
    /// 4. That contact's `discovery_mode == Public`.
    ///
    /// Any failure returns `not_found` — folding all rejection reasons
    /// together so the responder reveals nothing about *which* check
    /// failed. In particular, a missing-or-invalid PoW is silently
    /// answered as `not_found` rather than escalated to a `Violation`:
    /// the verification cost is one BLAKE3 hash (~1 µs), so the
    /// per-peer rate limiter on the dispatcher already bounds CPU spend
    /// from a misbehaving peer; raising it would just create a
    /// false-positive eviction path under client/server clock drift.
    ///
    ///the response now carries the target's
    /// **self-signed** transport announcement (sent to us via
    /// `AnnounceTransport`). A malicious resolver can still lie by
    /// returning `not_found`, but cannot fabricate a transport for
    /// any peer whose announcement they don't actually hold.
    pub fn handle_resolve_transport(
        &self,
        requester_node_id: [u8; 32],
        payload: ResolveTransportPayload,
    ) -> ResolveTransportResponse {
        let not_found = || ResolveTransportResponse {
            node_id: payload.node_id,
            announcement: None,
        };
        // ── PoW gate: time-bucket freshness ──────────────────────────
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let now_bucket = (now_secs / veil_proto::discovery::RESOLVE_POW_BUCKET_SECONDS) as i64;
        let req_bucket = payload.time_bucket as i64;
        if (req_bucket - now_bucket).abs() > veil_proto::discovery::RESOLVE_POW_TIME_WINDOW_BUCKETS
        {
            return not_found();
        }
        // ── PoW gate: solution validity ──────────────────────────────
        if !veil_proto::discovery::verify_resolve_pow(
            &requester_node_id,
            &payload.node_id,
            payload.time_bucket,
            &payload.pow_nonce,
        ) {
            return not_found();
        }
        // ── Privacy filter + announcement lookup ─────────────────────
        // Two checks:
        // 1. The Contact for `node_id` exists and is Public. Without
        // this we'd serve announcements for ContactsOnly /
        // IntroductionOnly peers — they opted out of DHT-walk
        // visibility, so reveal nothing (not even existence).
        // 2. We hold a self-signed announcement for that `node_id`.
        // The announcement also carries an `expiry_unix`; we
        // re-verify it here so an expired entry can't be served
        // even though it's still in our hashmap (the maintenance
        // tick eventually evicts it via `prune_orphan_announcements`
        // but we don't trust it to have run recently).
        let inner = lock!(self.inner);
        let is_public = inner
            .routing
            .find_closest(&payload.node_id, self.k())
            .into_iter()
            .find(|c| c.node_id == payload.node_id)
            .is_some_and(|c| matches!(c.discovery_mode(), veil_types::DiscoveryMode::Public));
        if !is_public {
            return not_found();
        }
        match inner.transport_announcements.get(&payload.node_id) {
            Some(ann) if veil_proto::discovery::verify_transport_announcement(ann, now_secs) => {
                ResolveTransportResponse {
                    node_id: payload.node_id,
                    announcement: Some(ann.clone()),
                }
            }
            _ => not_found(),
        }
    }

    /// Handle FIND_VALUE: return the value if stored locally, else the closest
    /// nodes' **node_ids only** (no transports), at full parity with
    /// [`Self::handle_find_node_v2`].
    ///
    /// SECURITY (C-06): the closest-nodes fallback previously returned full
    /// `NodeContact`s including each Public peer's transport URL, with NO PoW
    /// gate — so an attacker could send FIND_VALUE for random/non-existent
    /// keys and harvest `(node_id, transport)` pairs for free, re-opening the
    /// mass transport-enumeration that the FIND_NODE-v2 + `ResolveTransport`
    /// redesign was built to eliminate. We now return node_ids only; the
    /// requester resolves transports via the PoW-gated `ResolveTransport`
    /// (see `network_querier`), exactly as the V2 FIND_NODE path does.
    pub fn handle_find_value(&self, payload: FindValuePayload) -> FindValueResponse {
        // Try the local store first. Drop the inner lock immediately so
        // `ranked_public_contacts` can re-acquire it for the fallback path.
        let local_value = {
            let mut inner = lock!(self.inner);
            inner.store.get(&payload.key).cloned()
        };
        if let Some(v) = local_value {
            FindValueResponse::Value(v)
        } else {
            let contacts = self.ranked_public_contacts(&payload.key, self.k());
            FindValueResponse::Nodes(
                contacts
                    .iter()
                    .map(|c| veil_proto::discovery::NodeContact {
                        node_id: c.node_id,
                        // node_id-only — transport resolved via PoW-gated ResolveTransport.
                        transport: String::new(),
                    })
                    .collect(),
            )
        }
    }

    /// Handle STORE: persist a key-value pair with current timestamp.
    ///
    /// If the payload carries an Ed25519 authenticator extension
    /// the signature is verified before storing. A STORE whose `ed25519_pubkey` is
    /// `Some` MUST satisfy two conditions:
    ///
    /// 1. `BLAKE3(pubkey) == payload.key` — the key is derived from the owner's pubkey.
    /// 2. The Ed25519 signature is valid over `payload.signable_bytes` (`key || value`).
    ///
    /// payloads without `(ed25519_pubkey
    /// ed25519_sig)` are rejected by default with
    /// [`KademliaError::NotAllowed`]. Set
    /// `dht_config.allow_unsigned_store = true` (development /
    /// test-only fixtures) to accept unsigned records. Production
    /// `DhtConfig` should leave this off so a misbehaving peer cannot
    /// fill the `TieredStore` with arbitrary `(key, value)` entries
    /// and evict honest records.
    pub fn handle_store(&self, payload: StorePayload) -> Result<(), KademliaError> {
        if !self.can_participate() {
            return Err(KademliaError::DhtParticipationDisabled);
        }
        // shard filtering — reject stores for keys outside local shards.
        if self.dht_config.shard_filtering {
            let local_id = *lock!(self.inner).routing.local_id();
            if !super::shard::is_local_shard(&local_id, super::shard::shard_of(&payload.key)) {
                return Err(KademliaError::NotInLocalShard);
            }
        }
        // P-Net ban-record fast path. Values that start with the `PBAN`
        // magic prefix are routed to the configured `NetworkAuthGate`
        // instead of the standard Ed25519 signed-STORE check. The gate
        // owns full chain-of-trust verification (cert sig + admin sig +
        // key derives of ban target). Public-mode nodes leave the gate
        // unset, in which case PBAN-prefixed STOREs are rejected.
        if payload.value.len() >= 4 && &payload.value[..4] == b"PBAN" {
            let Some(gate) = self.network_auth_gate.as_ref() else {
                return Err(KademliaError::InvalidNetworkRecord);
            };
            if !gate.verify_ban_record(&payload.key, &payload.value) {
                return Err(KademliaError::InvalidNetworkRecord);
            }
            // Ban records use `store_insert` (ORIGIN_INTERNAL), which
            // deliberately bypasses the per-origin byte cap: the auth gate
            // above already gates these to admins with a valid chain of
            // trust, so a per-origin bucket here would only risk *refusing*
            // legitimate bans (PerOriginByteCapExceeded). They DO still count
            // against the global byte cap and can be reached by oldest-entry
            // eviction under store pressure — that residual is bounded by
            // periodic DHT republish of live ban records (and replication
            // across the key's shard), not a reserved sticky partition.
            let mut inner = lock!(self.inner);
            inner.store_insert(payload.key, payload.value);
            if let Some(m) = &self.metrics {
                m.inc_dht_store();
            }
            return Ok(());
        }
        // signed-STORE enforcement.  `origin` selects the per-origin
        // accounting bucket (Phase 11e) — signed STOREs use the signer
        // pubkey, legacy unsigned STOREs share the `ORIGIN_UNSIGNED`
        // bucket.
        let origin = match (
            payload.ed25519_pubkey.as_ref(),
            payload.ed25519_sig.as_ref(),
        ) {
            (Some(pk_bytes), Some(sig_bytes)) => {
                if !verify_store_ownership(&payload.key, &payload.value, pk_bytes, sig_bytes) {
                    return Err(KademliaError::InvalidSignature);
                }
                *pk_bytes
            }
            (None, None) => {
                if !self.dht_config.allow_unsigned_store {
                    return Err(KademliaError::UnsignedStoreRejected);
                }
                // Dev/test/legacy fixture path — log a deprecation hint
                // once per process so operators running with the legacy
                // inner-sig deployment pattern know they should plan a
                // migration to explicit STORE-level signatures.
                warn_unsigned_store_once();
                super::store::ORIGIN_UNSIGNED
            }
            // Half-set authenticator (one of pk/sig present, the other
            // missing) is malformed and never legitimate.
            _ => return Err(KademliaError::InvalidSignature),
        };
        let mut inner = lock!(self.inner);

        let accepted = inner.store_insert_with_origin(payload.key, payload.value, origin);
        if !accepted {
            return Err(KademliaError::PerOriginByteCapExceeded);
        }
        if let Some(m) = &self.metrics {
            m.inc_dht_store();
        }
        Ok(())
    }

    /// Handle DELETE: remove a key-value pair.
    ///
    /// Requires Ed25519 signature from the key owner. The pubkey in the payload
    /// must match the `node_id` derived from the DHT key (or be the signer of
    /// the original STORE record). Without this check, any peer could delete
    /// arbitrary entries.
    pub fn handle_delete(&self, payload: DeletePayload) -> Result<(), KademliaError> {
        if !self.can_participate() {
            return Err(KademliaError::DhtParticipationDisabled);
        }
        // Accept every signature algorithm the canonical wire mapping
        // supports (Ed25519 0/1, Falcon-512 2, hybrid Ed25519+Falcon 3/4)
        // so that hybrid-identity nodes — the recommended long-term PQ
        // identity type — can delete their own DHT records, not just
        // Ed25519/Falcon-512 owners. `verify_message` already handles all
        // four algos; the prior `{0,2}`-only match left hybrid (and
        // canonical-wire-byte-1 Ed25519) records undeletable until TTL
        // expiry. Unknown bytes still map to `UnsupportedDeleteAlgo`.
        let algo = veil_types::SignatureAlgorithm::from_wire_byte(payload.algo)
            .ok_or(KademliaError::UnsupportedDeleteAlgo)?;
        use base64::Engine as _;
        let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(&payload.public_key);
        if veil_crypto::verify_message(
            algo,
            &pubkey_b64,
            payload.signable_bytes(),
            &payload.signature,
        )
        .is_err()
        {
            return Err(KademliaError::InvalidSignature);
        }
        // Only allow DELETE when BLAKE3(pubkey) == key (self-owned keys).
        // node_id derivation uses BLAKE3(pubkey) identically for both algos.
        let expected_key: [u8; 32] = *blake3::hash(&payload.public_key).as_bytes();
        if expected_key != payload.key {
            return Err(KademliaError::DeleteOwnershipMismatch);
        }
        lock!(self.inner).store_remove(&payload.key);
        Ok(())
    }

    /// Store a value directly by key (bypasses role check — for internal use).
    ///
    /// Used by the mailbox DHT replication path to persist envelope bytes
    /// without going through the full wire-protocol `StorePayload` path.
    pub fn store_local(&self, key: [u8; 32], value: Vec<u8>) {
        let mut inner = lock!(self.inner);

        inner.store_insert(key, value);
        if let Some(m) = &self.metrics {
            m.inc_dht_store();
        }
    }

    /// Store a value attributed to a caller-derived `origin` accounting bucket,
    /// applying the per-origin byte cap (`[dht] per_origin_max_bytes`).
    ///
    /// Audit N1: used by the recursive-plane STORE handler so a remotely
    /// initiated STORE is subject to the SAME per-origin byte accounting as the
    /// direct wire-protocol path (`handle_store`). Unlike [`Self::store_local`]
    /// (which writes as `ORIGIN_INTERNAL` and is exempt from the cap), this
    /// charges the bytes to `origin`. Returns `true` on accept, `false` when the
    /// per-origin cap would be exceeded (caller drops the value).
    pub fn store_with_origin(&self, key: [u8; 32], value: Vec<u8>, origin: [u8; 32]) -> bool {
        let mut inner = lock!(self.inner);
        let accepted = inner.store_insert_with_origin(key, value, origin);
        if accepted && let Some(m) = &self.metrics {
            m.inc_dht_store();
        }
        accepted
    }

    /// Retrieve a stored value by key (local lookup only, no network walk).
    ///
    /// Returns `None` if the key is not present in the local store.
    pub fn get_local(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some(m) = &self.metrics {
            m.inc_dht_lookup();
        }
        let mut inner = lock!(self.inner);
        inner.store.get(key).cloned()
    }

    /// Like [`Self::get_local`] but also returns the value's hot-tier
    /// `inserted_at` timestamp.  Audit batch 2026-05-25 phase N: used
    /// by anycast resolve to enforce per-record TTL without a wire-format
    /// extension — caller computes `now.duration_since(inserted_at)`
    /// and compares to the record-level `ttl` field carried inside the
    /// stored value.
    pub fn get_local_with_meta(&self, key: &[u8; 32]) -> Option<(Vec<u8>, std::time::Instant)> {
        if let Some(m) = &self.metrics {
            m.inc_dht_lookup();
        }
        let mut inner = lock!(self.inner);
        inner.store.get_with_meta(key).map(|(v, t)| (v.clone(), t))
    }

    /// (test-support): remove a key from the local store
    /// without going through the wire-protocol `Delete` path. Used
    /// by sim tests that need a deterministic "node has no local
    /// copy" precondition before exercising the network walk.
    pub fn delete_local(&self, key: &[u8; 32]) {
        let mut inner = lock!(self.inner);
        inner.store.remove(key);
    }

    /// Enumerate all stored (key, value) pairs — snapshot/migration. NOTE:
    /// this materializes the entire store (incl. a RocksDB cold tier) into
    /// RAM; the republish driver uses [`Self::stored_keys`] +
    /// [`Self::peek_value`] instead to avoid that per-tick cost (cycle-7 M4).
    pub fn stored_entries(&self) -> Vec<([u8; 32], Vec<u8>)> {
        lock!(self.inner).store.iter().into_iter().collect()
    }

    /// Enumerate all stored key IDs without materializing values (audit
    /// cycle-7 M4). Pairs with [`Self::peek_value`] for the republish driver.
    /// (Distinct from [`Self::stored_keys`], which returns just the count.)
    pub fn stored_key_ids(&self) -> Vec<[u8; 32]> {
        lock!(self.inner).store.iter_keys()
    }

    /// Read one stored value by key without promoting a cold-tier hit to hot
    /// (see [`super::store::TieredStore::peek`]).
    pub fn peek_value(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        lock!(self.inner).store.peek(key)
    }

    /// Handle a NEIGHBOR_OFFER from an authenticated peer `source`.
    ///
    /// The `addr` bytes are interpreted as a UTF-8 transport string (e.g.
    /// "127.0.0.1:9000"); non-UTF-8 bytes are base64-encoded as a fallback.
    ///
    /// The offered `(node_id, transport)` is peer-claimed and unverified, so it
    /// goes through the source-tracked pending pool (`add_contact_unverified_from`)
    /// — NOT straight into the live routing table — and is promoted only on a
    /// successful OVL1 handshake with the claimed `node_id`. This matches the
    /// FIND_NODE-response and PEX-walk ingress paths and closes an
    /// eclipse/route-poisoning vector where a peer could inject a
    /// `victim_node_id → attacker_endpoint` mapping directly into the table.
    pub fn handle_neighbor_offer(
        &self,
        source: NodeIdBytes,
        payload: &veil_proto::control::NeighborOfferPayload,
    ) {
        let transport = String::from_utf8(payload.addr.clone()).unwrap_or_else(|e| {
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, e.into_bytes())
        });
        let contact = Contact::new(payload.node_id, transport);
        self.add_contact_unverified_from(source, contact);
    }

    /// Add a node to the routing table (called when a peer is heard).
    pub fn add_contact(&self, contact: Contact) {
        lock!(self.inner).routing.insert(contact);
    }

    /// add an unverified contact to the pending-promotion
    /// map. Use for any contact whose `node_id`/`transport` came from
    /// an untrusted source (FIND_NODE response body, NeighborOffer
    /// frame, PEX walk). The entry is NOT in the main routing table
    /// and does NOT appear in `find_closest`; a subsequent successful
    /// OVL1 handshake with this `node_id` calls
    /// [`Self::promote_contact_if_pending`] to move it into the
    /// real table. FIFO-evicts the oldest pending when the map
    /// reaches `PENDING_CONTACTS_CAP` (1024).
    pub fn add_contact_unverified(&self, contact: Contact) {
        // Internal/trusted path (e.g. our own outbound handshake feed).
        // Source-tracked at the all-zero `node_id` so accounting still
        // works but the per-source cap won't ever bite trusted feeds.
        self.add_contact_unverified_from([0u8; 32], contact);
    }

    /// source-tracked sibling of `add_contact_unverified`.
    /// Use this from any path where the contact came from a peer's
    /// wire-frame (FIND_NODE responses, NeighborOffer, etc.) so a
    /// single Sybil source cannot fill the pending pool with claimed
    /// (node_id, transport) pairs and eclipse honest peers' contributions.
    pub fn add_contact_unverified_from(&self, source: NodeIdBytes, contact: Contact) {
        let mut inner = lock!(self.inner);
        let node_id = contact.node_id;
        // Skip if already verified (in main routing table).
        if inner.routing.contains(&node_id) {
            return;
        }
        // source-tracked quota enforcement. Source
        // [0;0;...] is the trusted-internal sentinel (see
        // `add_contact_unverified`) and bypasses the per-source cap.
        // Read the current count up-front so we don't fight the borrow
        // checker in the entry-match below.
        let is_trusted_source = source == [0u8; 32];
        let already_present = inner.pending_contacts.contains_key(&node_id);
        if !is_trusted_source && !already_present {
            let cur = inner.pending_per_source.get(&source).copied().unwrap_or(0);
            if cur >= MAX_PENDING_PER_SOURCE {
                return; // silent drop — peer is over its quota
            }
        }
        if already_present {
            // Overwrite transport but keep position in the eviction queue
            // and the per-source attribution. An update from the same
            // source doesn't bump its counter; a different source taking
            // over an existing entry is rare enough to ignore.
            inner.pending_contacts.insert(node_id, contact);
            return;
        }
        // Vacant insert: push, attribute, bump counter, then enforce the
        // global cap.
        inner.pending_contacts.insert(node_id, contact);
        inner.pending_order.push_back(node_id);
        inner.pending_source_of.insert(node_id, source);
        if !is_trusted_source {
            *inner.pending_per_source.entry(source).or_insert(0) += 1;
        }
        // FIFO-evict the oldest entry if the global cap is reached.
        // Decrement the evicted entry's source counter to keep
        // pending_per_source in sync.
        if inner.pending_contacts.len() > PENDING_CONTACTS_CAP
            && let Some(evict) = inner.pending_order.pop_front()
        {
            inner.pending_contacts.remove(&evict);
            let evict_source_opt = inner.pending_source_of.remove(&evict);
            if let Some(evict_source) = evict_source_opt
                && evict_source != [0u8; 32]
                && let Some(c) = inner.pending_per_source.get_mut(&evict_source)
            {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    inner.pending_per_source.remove(&evict_source);
                }
            }
        }
    }

    /// promote a pending contact into the verified routing
    /// table. Called from the OVL1 handshake-complete path — at
    /// that point the peer has signed its ephemeral key with the
    /// long-term key bound to `node_id`, proving reachability and
    /// identity. Returns `true` if a promotion happened.
    pub fn promote_contact_if_pending(&self, node_id: &NodeIdBytes) -> bool {
        let mut inner = lock!(self.inner);
        if let Some(contact) = inner.pending_contacts.remove(node_id) {
            // Remove from eviction queue.
            if let Some(pos) = inner.pending_order.iter().position(|k| k == node_id) {
                inner.pending_order.remove(pos);
            }
            // free the per-source slot so the introducing
            // peer can sponsor another contact.
            if let Some(source) = inner.pending_source_of.remove(node_id)
                && source != [0u8; 32]
                && let Some(c) = inner.pending_per_source.get_mut(&source)
            {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    inner.pending_per_source.remove(&source);
                }
            }
            inner.routing.insert_trusted(contact);
            return true;
        }
        false
    }

    /// observability — how many unverified candidates are
    /// currently held in the pending map. Used by `node show` and
    /// metrics exporters to monitor eclipse-attack pressure.
    pub fn pending_contacts_count(&self) -> usize {
        lock!(self.inner).pending_contacts.len()
    }

    /// Add a contact bypassing the per-bucket rate limit.
    /// Use only for sources that have already proven their identity —
    /// e.g. a peer we just completed an OVL1 handshake with. Without
    /// this, several concurrent handshakes inside the same 1-second
    /// window race and only one peer ends up in the routing table
    /// breaking downstream `find_closest_nodes` and recursive routing.
    pub fn add_contact_trusted(&self, contact: Contact) {
        lock!(self.inner).routing.insert_trusted(contact);
    }

    /// Remove a node from the routing table.
    pub fn remove_contact(&self, node_id: &NodeIdBytes) {
        lock!(self.inner).routing.remove(node_id);
    }

    // ── queries ───────────────────────────────────────────────────────────

    pub fn routing_table_size(&self) -> usize {
        lock!(self.inner).routing.total_contacts()
    }

    /// Return all contacts currently in the routing table (cloned).
    pub fn routing_table_contacts(&self) -> Vec<super::routing::Contact> {
        lock!(self.inner).routing.all_contacts()
    }

    /// cheap accessor that returns just node_ids
    /// (no `String` clones). At 65 K contacts this is ~2 MB instead of
    /// ~13 MB and reduces lock-hold time proportionally.
    pub fn routing_table_node_ids(&self) -> Vec<[u8; 32]> {
        lock!(self.inner).routing.node_ids()
    }

    /// Return the `k` closest node IDs to `target` from the routing table.
    pub fn find_closest_nodes(&self, target: &[u8; 32], k: usize) -> Vec<[u8; 32]> {
        lock!(self.inner)
            .routing
            .find_closest(target, k)
            .into_iter()
            .map(|c| c.node_id)
            .collect()
    }

    /// return the `k` closest contacts (node_id + transport)
    /// from the routing table. Used to seed `find_node_iterative` walks
    /// from the iterative-DHT route-discovery fallback (long-chain
    /// reach extension). Heavier than [`find_closest_nodes`] because it
    /// clones the transport string per contact; not on the hot path.
    pub fn find_closest_contacts(
        &self,
        target: &[u8; 32],
        k: usize,
    ) -> Vec<super::routing::Contact> {
        lock!(self.inner)
            .routing
            .find_closest(target, k)
            .into_iter()
            .cloned()
            .collect()
    }

    /// same as [`Self::find_closest_nodes`] but also returns
    /// the peer's last-known transport URI alongside its node_id. Used
    /// by the K-closest replication path to compute IP-subnet diversity
    /// — without the transport URI we can't tell whether the K replicas
    /// land on different ASNs / subnets or all under one attacker-
    /// controlled cluster.
    pub fn find_closest_with_transport(
        &self,
        target: &[u8; 32],
        k: usize,
    ) -> Vec<([u8; 32], String)> {
        lock!(self.inner)
            .routing
            .find_closest(target, k)
            .into_iter()
            .map(|c| (c.node_id, c.transport.clone()))
            .collect()
    }

    /// same as [`Self::find_closest_nodes`] but pre-filtered to
    /// peers with `discovery_mode == Public` and capped at
    /// `min(k, ceil(N_public / 2))` so a single response cannot leak more
    /// than ~50% of our Public-neighbor set. Use this for any path that
    /// builds a wire response containing node_ids (FIND_NODE responses
    /// RecursiveQuery/FIND_NODE answers). Internal routing decisions
    /// (next-hop selection, NeighborOffer) keep using
    /// `find_closest_nodes` — those don't leak existence to the network.
    pub fn find_closest_public_node_ids(&self, target: &[u8; 32], k: usize) -> Vec<[u8; 32]> {
        let public: Vec<_> = lock!(self.inner)
            .routing
            .find_closest(target, self.k())
            .into_iter()
            .filter(|c| matches!(c.discovery_mode(), veil_types::DiscoveryMode::Public))
            .map(|c| c.node_id)
            .collect();
        let half_cap = public.len().div_ceil(2).max(1);
        let limit = k.min(self.k()).min(half_cap);
        public.into_iter().take(limit).collect()
    }

    /// Restore routing table contacts from a persisted snapshot.
    pub fn restore_routing_contacts(&self, contacts: Vec<super::routing::Contact>) {
        lock!(self.inner).routing.restore(contacts);
    }

    pub fn stored_keys(&self) -> usize {
        lock!(self.inner).store.len()
    }

    /// Return all stored (key, value) pairs as a snapshot for persistence.
    pub fn snapshot_values(&self) -> Vec<DhtValueSnapshot> {
        let inner = lock!(self.inner);
        // U2: when the cold tier is durable (RocksDB persists across restart and
        // is re-opened by `build_tiered_store`), the JSON value snapshot only
        // needs the volatile HOT tier — materialising the entire cold value set
        // every 120 s would defeat the disk tier and risk an OOM on a large
        // store. When the cold tier is in-memory (no path / no rocksdb-cold) it
        // is volatile, so the snapshot must include BOTH tiers or cold entries
        // would be lost on restart.
        let entries = if inner.store.cold_is_durable() {
            inner.store.iter_hot()
        } else {
            inner.store.iter()
        };
        entries
            .into_iter()
            .map(|(k, v)| DhtValueSnapshot { key: k, value: v })
            .collect()
    }

    /// Restore stored values from a persisted snapshot.
    ///
    /// Skips if `self.participate` is `false`. Does not overwrite existing
    /// entries so live values always win over restored ones.
    pub fn restore_values(&self, entries: Vec<DhtValueSnapshot>) {
        if !self.participate {
            return;
        }
        let mut inner = lock!(self.inner);
        for e in entries {
            if !inner.store.contains(&e.key) {
                inner.store_insert(e.key, e.value);
            }
        }
    }

    /// Remove DHT entries whose TTL has elapsed.
    ///
    /// `ttl` defaults [`DEFAULT_TTL`] when `None` is passed.
    pub fn cleanup_expired(&self, now: Instant) {
        lock!(self.inner).retain_fresh(now, DEFAULT_TTL);
    }

    /// Iterative Kademlia FIND_VALUE lookup using live OVL1 sessions.
    ///
    /// Seeds from the local routing table + active-session peers, then walks the
    /// network via [`NetworkPeerQuerier`] (real FIND_VALUE frames). Checks the
    /// local store first (cheap hit).
    ///
    /// Does NOT cache the result: the value is attacker-supplied until the
    /// CALLER verifies it (e.g. a signed relay-directory entry — verify its
    /// signature before trusting/persisting it). Returns the raw bytes or `None`.
    pub async fn find_value_iterative_network(
        &self,
        key: [u8; 32],
        outbox: Arc<dyn FrameRouter>,
    ) -> Option<Vec<u8>> {
        if let Some(v) = self.get_local(&key) {
            return Some(v);
        }
        let mut seeds: Vec<Contact> = {
            let inner = lock!(self.inner);
            inner
                .routing
                .find_closest(&key, self.k())
                .into_iter()
                .cloned()
                .collect()
        };
        let mut seed_ids: std::collections::HashSet<[u8; 32]> =
            seeds.iter().map(|c| c.node_id).collect();
        for peer_id in outbox.peer_ids() {
            if seed_ids.insert(peer_id) {
                seeds.push(Contact::new(peer_id, ""));
            }
        }
        let timeout = Duration::from_millis(self.dht_config.find_node_timeout_ms);
        let querier = super::network_querier::NetworkPeerQuerier::with_cache(
            Arc::clone(&outbox),
            self.dht_config.k,
            timeout,
            Arc::clone(&self.transport_cache),
            self.local_node_id(),
        );
        let params = super::iterative::IterativeParams::from(&self.dht_config);
        super::iterative::find_value_iterative(key, seeds, &querier, |k| self.get_local(k), &params)
            .await
    }

    /// Iterative Kademlia FIND_NODE lookup using live OVL1 sessions.
    ///
    /// Seeds from the local routing table, then queries peers via
    /// [`NetworkPeerQuerier`] (real FIND_NODE frames over active sessions).
    ///
    /// Returns up to K contacts closest to `target`.
    pub async fn find_node_iterative_network(
        &self,
        target: [u8; 32],
        outbox: Arc<dyn FrameRouter>,
    ) -> Vec<Contact> {
        // short-circuit on cache hit. At trillion scale a
        // cold lookup is O(log N) round-trips ≈ 4 seconds; a hit is ≈ 0.
        // The cache is bounded LRU with TTL so stale routing-table state
        // doesn't persist past `DEFAULT_LOOKUP_CACHE_TTL`.
        if let Some(cached) = lock!(self.lookup_cache).get(&target) {
            return cached;
        }

        let mut seeds: Vec<Contact> = {
            let inner = lock!(self.inner);
            inner
                .routing
                .find_closest(&target, self.k())
                .into_iter()
                .cloned()
                .collect()
        };
        // Also seed from all peers with active sessions so nodes not yet in the
        // routing table (or not XOR-close to the target) are still reachable.
        // Use HashSet for O(1) dedup (was O(n²) with linear any).
        let mut seed_ids: std::collections::HashSet<[u8; 32]> =
            seeds.iter().map(|c| c.node_id).collect();
        for peer_id in outbox.peer_ids() {
            if seed_ids.insert(peer_id) {
                seeds.push(Contact::new(peer_id, ""));
            }
        }
        let timeout = Duration::from_millis(self.dht_config.find_node_timeout_ms);
        let querier = super::network_querier::NetworkPeerQuerier::with_cache(
            Arc::clone(&outbox),
            self.dht_config.k,
            timeout,
            Arc::clone(&self.transport_cache),
            self.local_node_id(),
        );
        let params = super::iterative::IterativeParams::from(&self.dht_config);
        let result = super::iterative::find_node_iterative(target, seeds, &querier, &params).await;
        // Cache the result (including empty-result negative caching —
        // saves us from immediately re-walking when a target genuinely
        // has no contacts in our reachable network slice).
        lock!(self.lookup_cache).insert(target, result.clone());
        result
    }

    /// Store a value locally **and** replicate it to the K closest network peers.
    ///
    /// First stores the value locally (if the node role permits), then performs an
    /// iterative FIND_NODE to locate the K closest peers and sends each a STORE frame.
    ///
    /// Returns the number of STORE frames successfully queued for transmission to
    /// remote peers (NOT including the local store). Returns 0 when the lookup
    /// produced no remote contacts (DHT is partitioned / single-node). Used by the
    /// periodic re-replication task for observability — a sustained fan-out count
    /// well below `DHT_REPLICATION_K` indicates either a partitioned routing table
    /// OR persistent unreachable closest-peers, both of which warrant operator
    /// attention. Note: success here means "frame queued on the outbox", not
    /// "STORE acknowledged by the receiver" — the design is fire-and-forget by
    /// requirement (acks would slow re-publish to RTT × K and create a DoS
    /// amplifier on slow peers).
    pub async fn store_replicated(
        &self,
        key: [u8; 32],
        value: Vec<u8>,
        outbox: Arc<dyn FrameRouter>,
    ) -> Result<usize, KademliaError> {
        // Store locally. audit cycle-6 (P1): use `store_local` (trusted internal
        // write, ORIGIN_INTERNAL) rather than `handle_store` — this is the node's
        // OWN replication decision for an already-validated self-authenticating
        // record (all callers: `p_net_ban_sync` signs+verifies first and applies
        // the ban to its BanList separately; `dht_republish` filters to
        // `is_self_authenticating_dht_value`; `debug` is an operator command). It
        // must NOT be subject to the `allow_unsigned_store` gate, which now
        // defaults to false and would otherwise reject this local copy.
        self.store_local(key, value.clone());

        // Find K closest peers.
        let closest = self
            .find_node_iterative_network(key, Arc::clone(&outbox))
            .await;

        // Send STORE to each of them via the outbox. Count successes for the
        // observability return value (operator-visible "did the fan-out actually
        // reach K peers?" metric).
        let mut sent = 0usize;
        for contact in closest {
            let request_id = self.store_req_id.fetch_add(1, Ordering::Relaxed);
            let payload = StorePayload::unsigned(key, value.clone());
            let body = payload.encode();
            let mut hdr = veil_proto::header::FrameHeader::new(
                veil_proto::family::FrameFamily::Discovery as u8,
                veil_proto::family::DiscoveryMsg::Store as u16,
            );
            hdr.body_len = body.len() as u32;
            hdr.request_id = request_id;
            let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
            frame.extend_from_slice(&body);
            // Fire-and-forget: drop the response channel (we don't wait for an ack).
            // `send_request` returns Some(receiver) when the frame was accepted
            // onto the outbox; None when there is no live session for the peer
            // and the replica is genuinely lost on this round.
            if outbox
                .send_request(contact.node_id, request_id, frame)
                .is_some()
            {
                sent += 1;
            }
        }

        Ok(sent)
    }
}

// ── DHT STORE ownership verification ─────────────────────

/// Verify that a STORE payload's authenticator extension is valid.
///
/// Returns `true` iff both conditions hold:
/// 1. `BLAKE3(pubkey) == key` — the DHT key is derived from the owner's Ed25519 public key.
/// 2. The 64-byte Ed25519 signature is valid over `key || value`.
///
/// This function is intentionally standalone (not a method) so it can be unit-tested
/// independently of `KademliaService`.
fn verify_store_ownership(
    key: &[u8; 32],
    value: &[u8],
    pk_bytes: &[u8; 32],
    sig_bytes: &[u8; 64],
) -> bool {
    // Condition 1: key derivation check.
    let derived_key = *blake3::hash(pk_bytes).as_bytes();
    if derived_key != *key {
        return false;
    }
    // Condition 2: signature verification over key || value.
    let verifying_key = match VerifyingKey::from_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let signature = match Signature::from_slice(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut msg = Vec::with_capacity(32 + value.len());
    msg.extend_from_slice(key);
    msg.extend_from_slice(value);
    verifying_key.verify(&msg, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iterative::{FindValueResult, PeerQuerier};
    use crate::routing::Contact;
    use veil_proto::discovery::{DeletePayload, FindValuePayload, StorePayload, attachment_key};

    /// integration test: 3-node topology using in-process querier.
    ///
    /// Topology:
    /// Node A (initiator): knows only node B.
    /// Node B: knows node A and node C; does not hold the value.
    /// Node C: knows node A and node B; holds the stored value.
    ///
    /// Node C's FIND_VALUE is discovered via a 2-hop walk: A → B → C.
    /// This tests the iterative FIND_VALUE algorithm end-to-end without
    /// real network transport.
    #[tokio::test]
    async fn networked_store_replication_three_nodes() {
        use crate::iterative::find_value_iterative;
        use std::collections::HashMap;
        use std::future::Future;
        use std::pin::Pin;
        use std::sync::{Arc, Mutex};

        let node_a = [0x0Au8; 32];
        let node_b = [0x0Bu8; 32];
        let node_c = [0x0Cu8; 32];

        let key = [0xCCu8; 32];
        let value = b"replicated-dht-value".to_vec();

        // Simulate a store at node C.
        let svc_c = make_test_kademlia_service(node_c);
        svc_c
            .handle_store(StorePayload::unsigned(key, value.clone()))
            .unwrap();

        // Each node's routing table:
        // A knows B.
        let mut rt_a = crate::routing::RoutingTable::new(node_a);
        rt_a.insert(Contact::new(node_b, "tcp://b:9001"));

        // B knows A and C.
        let mut rt_b = crate::routing::RoutingTable::new(node_b);
        rt_b.insert(Contact::new(node_a, "tcp://a:9000"));
        rt_b.insert(Contact::new(node_c, "tcp://c:9002"));

        // C knows A and B (and holds the value — represented by svc_c).
        let mut rt_c = crate::routing::RoutingTable::new(node_c);
        rt_c.insert(Contact::new(node_a, "tcp://a:9000"));
        rt_c.insert(Contact::new(node_b, "tcp://b:9001"));

        // Custom querier: routes find_node via routing tables; find_value at C
        // returns the stored value, at B returns closest nodes (C).
        struct ThreeNodeQuerier {
            node_b: [u8; 32],
            node_c: [u8; 32],
            key: [u8; 32],
            value: Vec<u8>,
            routing: Arc<Mutex<HashMap<[u8; 32], crate::routing::RoutingTable>>>,
        }

        impl PeerQuerier for ThreeNodeQuerier {
            fn find_node<'a>(
                &'a self,
                peer_id: [u8; 32],
                target: [u8; 32],
            ) -> Pin<Box<dyn Future<Output = Vec<Contact>> + Send + 'a>> {
                let routing = Arc::clone(&self.routing);
                Box::pin(async move {
                    let guard = routing.lock().unwrap();
                    match guard.get(&peer_id) {
                        Some(rt) => rt
                            .find_closest(&target, crate::routing::K)
                            .into_iter()
                            .cloned()
                            .collect(),
                        None => vec![],
                    }
                })
            }

            fn find_value<'a>(
                &'a self,
                peer_id: [u8; 32],
                key: [u8; 32],
            ) -> Pin<Box<dyn Future<Output = FindValueResult> + Send + 'a>> {
                let node_b = self.node_b;
                let node_c = self.node_c;
                let stored_key = self.key;
                let value = self.value.clone();
                let routing = Arc::clone(&self.routing);
                Box::pin(async move {
                    if peer_id == node_c && key == stored_key {
                        // C holds the value.
                        FindValueResult::Value(value)
                    } else {
                        // B (and others) redirect to closest nodes.
                        let guard = routing.lock().unwrap();
                        let contacts = match guard.get(&peer_id) {
                            Some(rt) => rt
                                .find_closest(&key, crate::routing::K)
                                .into_iter()
                                .cloned()
                                .collect(),
                            None => vec![],
                        };
                        // Suppress unused variable warnings.
                        let _ = node_b;
                        FindValueResult::Nodes(contacts)
                    }
                })
            }
        }

        let mut routing_map = HashMap::new();
        routing_map.insert(node_b, rt_b);
        routing_map.insert(node_c, rt_c);

        let querier = ThreeNodeQuerier {
            node_b,
            node_c,
            key,
            value: value.clone(),
            routing: Arc::new(Mutex::new(routing_map)),
        };

        // A's seed is only B.
        let seeds_from_a = vec![Contact::new(node_b, "tcp://b:9001")];

        let result = find_value_iterative(
            key,
            seeds_from_a,
            &querier,
            |_| None,
            &crate::iterative::IterativeParams::default(),
        )
        .await;
        assert_eq!(
            result,
            Some(value),
            "FIND_VALUE must traverse A→B→C to retrieve the stored value",
        );

        // Verify the local store at C is intact.
        assert_eq!(svc_c.stored_keys(), 1);
    }

    fn service(seed: u8) -> KademliaService {
        make_test_kademlia_service([seed; 32])
    }

    /// test-only constructor that enables
    /// `allow_unsigned_store` so the legacy unsigned-STORE fixtures
    /// in this module keep working without crypto setup. Production
    /// callers MUST use `KademliaService::new(...)` (which leaves the
    /// flag at its secure default `false`).
    fn make_test_kademlia_service(local_id: [u8; 32]) -> KademliaService {
        KademliaService::with_config(
            local_id,
            DhtRuntimeConfig {
                allow_unsigned_store: true,
                ..DhtRuntimeConfig::default()
            },
        )
    }

    // ── 2-tier routing (unverified / verified) ─────────────

    #[test]
    fn add_contact_unverified_stays_out_of_main_routing_table() {
        let svc = service(0);
        let peer = [0xAAu8; 32];
        svc.add_contact_unverified(Contact::new(peer, "tcp://evil:1"));
        assert_eq!(svc.pending_contacts_count(), 1);
        assert_eq!(
            svc.routing_table_size(),
            0,
            "unverified contact must NOT enter the main routing table"
        );
        // find_closest must not return it either.
        assert!(
            svc.find_closest_nodes(&peer, 16).is_empty(),
            "unverified contact must be invisible to find_closest"
        );
    }

    #[test]
    fn neighbor_offer_routes_through_pending_pool() {
        // A peer-claimed NeighborOffer must NOT land directly in the live
        // routing table (eclipse/route-poisoning vector); it goes through the
        // source-tracked pending pool like every other untrusted-contact ingress.
        let svc = service(0);
        let source = [0x11u8; 32];
        let offered = [0xAAu8; 32];
        let payload = veil_proto::control::NeighborOfferPayload {
            node_id: offered,
            addr: b"tcp://attacker:1".to_vec(),
            flags: 0,
        };
        svc.handle_neighbor_offer(source, &payload);
        assert_eq!(
            svc.routing_table_size(),
            0,
            "NeighborOffer must NOT enter the live routing table directly"
        );
        assert_eq!(
            svc.pending_contacts_count(),
            1,
            "offer must land in the source-tracked pending pool"
        );
        assert!(
            svc.find_closest_nodes(&offered, 16).is_empty(),
            "unverified offer must be invisible to find_closest"
        );
    }

    #[test]
    fn promote_contact_if_pending_moves_to_verified() {
        let svc = service(0);
        let peer = [0xBBu8; 32];
        svc.add_contact_unverified(Contact::new(peer, "tcp://good:1"));
        assert_eq!(svc.pending_contacts_count(), 1);
        assert_eq!(svc.routing_table_size(), 0);

        let promoted = svc.promote_contact_if_pending(&peer);
        assert!(
            promoted,
            "promote must return true when a pending entry was moved"
        );
        assert_eq!(svc.pending_contacts_count(), 0);
        assert_eq!(
            svc.routing_table_size(),
            1,
            "verified contact is now in the routing table"
        );

        // Idempotent: second promote returns false.
        assert!(
            !svc.promote_contact_if_pending(&peer),
            "second promote with no pending entry returns false"
        );
    }

    #[test]
    fn unverified_contact_already_verified_is_ignored() {
        let svc = service(0);
        let peer = [0xCCu8; 32];
        // Peer is already verified (e.g. directly-handshaked).
        svc.add_contact_trusted(Contact::new(peer, "tcp://verified:1"));
        assert_eq!(svc.routing_table_size(), 1);
        // Unverified add for the same peer is a no-op.
        svc.add_contact_unverified(Contact::new(peer, "tcp://impostor:1"));
        assert_eq!(
            svc.pending_contacts_count(),
            0,
            "already-verified peer must not create a pending entry"
        );
        assert_eq!(svc.routing_table_size(), 1);
    }

    #[test]
    fn pending_contacts_cap_fifo_evicts_oldest() {
        let svc = service(0);
        // Insert PENDING_CONTACTS_CAP + 1 entries to trigger one eviction.
        for i in 0..(PENDING_CONTACTS_CAP + 1) {
            let mut peer = [0u8; 32];
            // Generate a unique peer_id per iteration; upper 3 bytes
            // are the loop counter to stay under 1024 unique values.
            peer[0] = ((i >> 8) & 0xFF) as u8;
            peer[1] = (i & 0xFF) as u8;
            peer[2] = 0x01; // avoid colliding with the local_id=[0; 32]
            svc.add_contact_unverified(Contact::new(peer, "tcp://c:1"));
        }
        assert_eq!(
            svc.pending_contacts_count(),
            PENDING_CONTACTS_CAP,
            "pending map must be capped at PENDING_CONTACTS_CAP"
        );
    }

    #[test]
    fn store_and_find_value() {
        let svc = service(0);
        let key = attachment_key(&[1u8; 32]);
        svc.handle_store(StorePayload::unsigned(key, b"record".to_vec()))
            .unwrap();
        let resp = svc.handle_find_value(FindValuePayload { key });
        assert!(matches!(resp, FindValueResponse::Value(v) if v == b"record"));
    }

    #[test]
    fn find_value_unknown_key_returns_nodes() {
        let svc = service(0);
        svc.add_contact(Contact::new([1u8; 32], "tcp://peer1:9000"));
        let key = [0xFFu8; 32];
        let resp = svc.handle_find_value(FindValuePayload { key });
        // C-06: the closest-nodes fallback returns node_ids only — it must NOT
        // leak peer transports (anti-enumeration parity with FIND_NODE-v2; the
        // requester resolves transports via the PoW-gated ResolveTransport).
        match resp {
            FindValueResponse::Nodes(nodes) => {
                assert!(!nodes.is_empty(), "expected closest-nodes fallback");
                for n in &nodes {
                    assert!(
                        n.transport.is_empty(),
                        "FIND_VALUE leaked a transport: {:?}",
                        n.transport
                    );
                }
            }
            FindValueResponse::Value(_) => panic!("unexpected local hit"),
        }
    }

    #[test]
    fn delete_removes_key_ed25519() {
        use ed25519_dalek::{Signer, SigningKey};
        let svc = service(0);
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let key: [u8; 32] = *blake3::hash(&pk).as_bytes();
        svc.handle_store(StorePayload::unsigned(key, b"v".to_vec()))
            .unwrap();
        let sig = sk.sign(&key).to_bytes().to_vec();
        svc.handle_delete(DeletePayload {
            key,
            algo: 0,
            public_key: pk,
            signature: sig,
        })
        .unwrap();
        assert_eq!(svc.stored_keys(), 0);
    }

    #[test]
    fn delete_removes_key_falcon512() {
        use pqcrypto_falcon::falcon512;
        use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
        let svc = service(0);
        let (pk, sk) = falcon512::keypair();
        let pk_bytes = pk.as_bytes().to_vec();
        let key: [u8; 32] = *blake3::hash(&pk_bytes).as_bytes();
        svc.handle_store(StorePayload::unsigned(key, b"v".to_vec()))
            .unwrap();
        let sig = falcon512::detached_sign(&key, &sk);
        let sig_bytes = sig.as_bytes().to_vec();
        svc.handle_delete(DeletePayload {
            key,
            algo: 2,
            public_key: pk_bytes,
            signature: sig_bytes,
        })
        .unwrap();
        assert_eq!(svc.stored_keys(), 0);
    }

    #[test]
    fn delete_removes_key_ed25519_canonical_wire_byte() {
        // Wire-byte 1 is canonical Ed25519 (0 is the legacy alias). The
        // prior {0,2}-only dispatch rejected 1 even though `from_wire_byte`
        // maps it to Ed25519.
        use ed25519_dalek::{Signer, SigningKey};
        let svc = service(0);
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let key: [u8; 32] = *blake3::hash(&pk).as_bytes();
        svc.handle_store(StorePayload::unsigned(key, b"v".to_vec()))
            .unwrap();
        let sig = sk.sign(&key).to_bytes().to_vec();
        svc.handle_delete(DeletePayload {
            key,
            algo: 1,
            public_key: pk,
            signature: sig,
        })
        .unwrap();
        assert_eq!(svc.stored_keys(), 0);
    }

    #[test]
    fn delete_removes_key_hybrid512() {
        use base64::Engine as _;
        use veil_types::SignatureAlgorithm;
        let svc = service(0);
        let kp = veil_crypto::generate_keypair(SignatureAlgorithm::Ed25519Falcon512Hybrid);
        let pk_bytes = base64::engine::general_purpose::STANDARD
            .decode(&kp.public_key)
            .unwrap();
        let key: [u8; 32] = *blake3::hash(&pk_bytes).as_bytes();
        svc.handle_store(StorePayload::unsigned(key, b"v".to_vec()))
            .unwrap();
        let sig = veil_crypto::sign_message(
            SignatureAlgorithm::Ed25519Falcon512Hybrid,
            &kp.public_key,
            &kp.private_key,
            &key,
        )
        .unwrap();
        svc.handle_delete(DeletePayload {
            key,
            algo: 3,
            public_key: pk_bytes,
            signature: sig,
        })
        .unwrap();
        assert_eq!(svc.stored_keys(), 0);
    }

    #[test]
    fn delete_removes_key_hybrid1024() {
        use base64::Engine as _;
        use veil_types::SignatureAlgorithm;
        let svc = service(0);
        let kp = veil_crypto::generate_keypair(SignatureAlgorithm::Ed25519Falcon1024Hybrid);
        let pk_bytes = base64::engine::general_purpose::STANDARD
            .decode(&kp.public_key)
            .unwrap();
        // 32 (ed25519) + 1793 (falcon-1024) = 1825 bytes — exceeds the old
        // 1600-byte DELETE pubkey cap, now covered by MAX_SIGNATURE_PUBKEY_BYTES.
        assert_eq!(pk_bytes.len(), 1825);
        let key: [u8; 32] = *blake3::hash(&pk_bytes).as_bytes();
        svc.handle_store(StorePayload::unsigned(key, b"v".to_vec()))
            .unwrap();
        let sig = veil_crypto::sign_message(
            SignatureAlgorithm::Ed25519Falcon1024Hybrid,
            &kp.public_key,
            &kp.private_key,
            &key,
        )
        .unwrap();
        svc.handle_delete(DeletePayload {
            key,
            algo: 4,
            public_key: pk_bytes,
            signature: sig,
        })
        .unwrap();
        assert_eq!(svc.stored_keys(), 0);
    }

    #[test]
    fn delete_rejected_without_valid_signature() {
        let svc = service(0);
        let key = [5u8; 32];
        svc.handle_store(StorePayload::unsigned(key, b"v".to_vec()))
            .unwrap();
        // Wrong pubkey: BLAKE3(pubkey)!= key — this fails sig verify
        // first (the `[0u8; 64]` signature is invalid for any pubkey)
        // so we land in `InvalidSignature` rather than the pubkey-key
        // mismatch branch. error variants split.
        let err = svc
            .handle_delete(DeletePayload {
                key,
                algo: 0,
                public_key: vec![0u8; 32],
                signature: vec![0u8; 64],
            })
            .unwrap_err();
        assert_eq!(err, KademliaError::InvalidSignature);
    }

    #[test]
    fn delete_rejected_unknown_algo() {
        let svc = service(0);
        let err = svc
            .handle_delete(DeletePayload {
                key: [0u8; 32],
                algo: 99,
                public_key: vec![],
                signature: vec![],
            })
            .unwrap_err();
        assert_eq!(err, KademliaError::UnsupportedDeleteAlgo);
    }

    #[test]
    fn participate_false_rejects_store() {
        let mut svc = make_test_kademlia_service([0u8; 32]);
        svc.set_participate(false);
        let err = svc
            .handle_store(StorePayload::unsigned([0u8; 32], vec![]))
            .unwrap_err();
        assert_eq!(err, KademliaError::DhtParticipationDisabled);
    }

    #[test]
    fn leaf_can_store_by_default() {
        // With participate=true (default), any role can store.
        let svc = make_test_kademlia_service([0u8; 32]);
        svc.handle_store(StorePayload::unsigned([0u8; 32], b"v".to_vec()))
            .unwrap();
        assert_eq!(svc.stored_keys(), 1);
    }

    #[test]
    fn find_node_returns_closest() {
        let svc = service(0);
        svc.add_contact(Contact::new([1u8; 32], "tcp://1:9000"));
        svc.add_contact(Contact::new([2u8; 32], "tcp://2:9000"));
        svc.add_contact(Contact::new([3u8; 32], "tcp://3:9000"));

        let resp = svc.handle_find_node_v2(FindNodeV2Payload {
            target: [1u8; 32],
            k: 2,
        });
        assert!(!resp.node_ids.is_empty(), "expected ≥1 returned node");
        // Closest node [1;32] is [1;32] itself.
        assert_eq!(resp.node_ids[0], [1u8; 32]);
    }

    /// — RTT tie-breaker: when two peers are equidistant from target
    /// the one with lower RTT should appear first. Same property holds on
    /// the V2 path via the shared `ranked_public_contacts` helper (
    /// 475.6 ported the ranking from V1).
    #[test]
    fn rtt_tiebreaker_prefers_lower_latency_peer() {
        use std::collections::HashMap;
        use std::sync::Arc;

        struct StubRtt(HashMap<[u8; 32], u32>);
        impl RttHint for StubRtt {
            fn rtt_ms(&self, peer: &[u8; 32]) -> Option<u32> {
                self.0.get(peer).copied()
            }
        }

        let node_a = [0x01u8; 32];
        let node_b = [0x02u8; 32];
        let mut m = HashMap::new();
        m.insert(node_a, 10u32);
        m.insert(node_b, 100u32);
        let rtt_hint: Arc<dyn RttHint> = Arc::new(StubRtt(m));

        let mut svc = make_test_kademlia_service([0u8; 32]);
        svc.set_rtt_table(rtt_hint);
        svc.add_contact(Contact::new(node_a, "tcp://a:9000"));
        svc.add_contact(Contact::new(node_b, "tcp://b:9000"));

        // Request 2 closest nodes; half-cap returns ceil(2/2)=1.
        // The single returned node must be A (lower RTT — wins the sort).
        let resp = svc.handle_find_node_v2(FindNodeV2Payload {
            target: [0u8; 32],
            k: 2,
        });
        assert!(
            !resp.node_ids.is_empty(),
            "expected at least one Public peer"
        );
        assert_eq!(
            resp.node_ids[0], node_a,
            "lower-RTT node should be ranked first"
        );
    }

    /// — Vivaldi-aware DHT ranking: a topologically-close peer with a
    /// slightly larger XOR distance is preferred over a far peer with a smaller
    /// XOR. Validates the V2 path picks up the Vivaldi sort hoisted in
    /// (475.6).
    #[test]
    fn vivaldi_topology_aware_ranking() {
        use std::collections::HashMap;
        use std::sync::Arc;

        struct StubOracle(HashMap<[u8; 32], f64>);
        impl CoordinateOracle for StubOracle {
            fn estimated_distance(&self, peer: &[u8; 32]) -> Option<f64> {
                self.0.get(peer).copied()
            }
        }

        let local_id = [0x00u8; 32];
        let node_a = [0x01u8; 32];
        let node_b = [0x02u8; 32];
        let target = [0x00u8; 32];

        let mut distances = HashMap::new();
        distances.insert(node_a, 500.0);
        distances.insert(node_b, 5.0);
        let oracle: Arc<dyn CoordinateOracle> = Arc::new(StubOracle(distances));

        let cfg = DhtRuntimeConfig {
            vivaldi_weight: 0.3,
            ..Default::default()
        };
        let mut svc = KademliaService::with_config(local_id, cfg);
        svc.set_coord_oracle(oracle);
        svc.add_contact(Contact::new(node_a, "tcp://a:9000"));
        svc.add_contact(Contact::new(node_b, "tcp://b:9000"));

        let resp = svc.handle_find_node_v2(FindNodeV2Payload { target, k: 2 });
        assert!(!resp.node_ids.is_empty());
        assert_eq!(
            resp.node_ids[0], node_b,
            "topology-close node_b must rank before far node_a"
        );
    }

    /// Audit N1: `store_with_origin` (the path the recursive STORE handler now
    /// uses) must enforce the per-origin byte cap, so a single signer cannot
    /// flood the local store past the cap via the recursive plane — unlike
    /// `store_local`, which writes as ORIGIN_INTERNAL and is exempt.
    #[test]
    fn store_with_origin_enforces_per_origin_cap_n1() {
        let cfg = DhtRuntimeConfig {
            per_origin_max_bytes: Some(100),
            ..Default::default()
        };
        let svc = KademliaService::with_config([1u8; 32], cfg);
        let origin = [0xABu8; 32];

        // First store (60 B) is under the 100-B per-origin cap → accepted.
        assert!(svc.store_with_origin([10u8; 32], vec![0u8; 60], origin));
        // Second store for the SAME origin would total 120 B > cap → rejected.
        assert!(!svc.store_with_origin([11u8; 32], vec![0u8; 60], origin));
        assert!(
            svc.get_local(&[11u8; 32]).is_none(),
            "over-cap value must not be stored"
        );
        // A DIFFERENT origin has its own bucket → accepted.
        assert!(svc.store_with_origin([12u8; 32], vec![0u8; 60], [0xCDu8; 32]));
        // store_local (ORIGIN_INTERNAL) remains exempt from the per-origin cap.
        svc.store_local([13u8; 32], vec![0u8; 10_000]);
        assert!(
            svc.get_local(&[13u8; 32]).is_some(),
            "internal write must stay exempt from the per-origin cap"
        );
    }

    /// — vivaldi_weight=0.0 falls back to pure XOR order.
    #[test]
    fn vivaldi_weight_zero_preserves_xor_order() {
        use std::collections::HashMap;
        use std::sync::Arc;

        struct StubOracle(HashMap<[u8; 32], f64>);
        impl CoordinateOracle for StubOracle {
            fn estimated_distance(&self, peer: &[u8; 32]) -> Option<f64> {
                self.0.get(peer).copied()
            }
        }

        let local_id = [0x00u8; 32];
        let node_a = [0x01u8; 32];
        let node_b = [0x02u8; 32];
        let target = [0x00u8; 32];

        let mut distances = HashMap::new();
        distances.insert(node_a, 9999.0);
        distances.insert(node_b, 1.0);
        let oracle: Arc<dyn CoordinateOracle> = Arc::new(StubOracle(distances));

        let cfg = DhtRuntimeConfig {
            vivaldi_weight: 0.0,
            ..Default::default()
        };
        let mut svc = KademliaService::with_config(local_id, cfg);
        svc.set_coord_oracle(oracle);
        svc.add_contact(Contact::new(node_a, "tcp://a:9000"));
        svc.add_contact(Contact::new(node_b, "tcp://b:9000"));

        // half-cap: 1 of 2 returned; must be XOR-closest (node_a).
        let resp = svc.handle_find_node_v2(FindNodeV2Payload { target, k: 2 });
        assert!(!resp.node_ids.is_empty());
        assert_eq!(
            resp.node_ids[0], node_a,
            "pure XOR order must be preserved when vivaldi_weight=0"
        );
    }

    #[test]
    fn cleanup_expired_removes_old_entries() {
        let svc = service(0);
        let key = [0xABu8; 32];

        // Insert at "now"; advance the cleanup clock by 2 × DEFAULT_TTL so the
        // entry counts as expired. Avoids `Instant - Duration` underflow on
        // platforms where `Instant` is rooted at boot (Windows).
        let inserted_at = Instant::now();
        {
            let mut inner = svc.inner.lock().unwrap();
            inner.store_insert_raw(key, b"old".to_vec(), inserted_at);
        }
        assert_eq!(svc.stored_keys(), 1);

        svc.cleanup_expired(inserted_at + Duration::from_secs(7200));
        assert_eq!(svc.stored_keys(), 0, "expired entry should be evicted");
    }

    #[test]
    fn cleanup_does_not_remove_fresh_entries() {
        let svc = service(0);
        let key = [0xABu8; 32];
        svc.handle_store(StorePayload::unsigned(key, b"fresh".to_vec()))
            .unwrap();

        svc.cleanup_expired(Instant::now());
        assert_eq!(svc.stored_keys(), 1, "fresh entry must survive cleanup");
    }

    // ── DHT stored-values snapshot/restore ──────────────────────────

    #[test]
    fn values_snapshot_restore_roundtrip() {
        let src = service(1);
        let k1 = [0x11u8; 32];
        let k2 = [0x22u8; 32];
        src.handle_store(StorePayload::unsigned(k1, b"alpha".to_vec()))
            .unwrap();
        src.handle_store(StorePayload::unsigned(k2, b"beta".to_vec()))
            .unwrap();

        let snap = src.snapshot_values();
        assert_eq!(snap.len(), 2, "snapshot must capture all stored entries");

        let dst = service(2);
        dst.restore_values(snap);
        assert_eq!(
            dst.stored_keys(),
            2,
            "restored service must hold both entries"
        );
        assert!(
            matches!(dst.handle_find_value(FindValuePayload { key: k1 }),
            FindValueResponse::Value(v) if v == b"alpha")
        );
        assert!(
            matches!(dst.handle_find_value(FindValuePayload { key: k2 }),
            FindValueResponse::Value(v) if v == b"beta")
        );
    }

    #[test]
    fn restore_does_not_overwrite_existing_value() {
        let svc = service(3);
        let key = [0x33u8; 32];
        svc.handle_store(StorePayload::unsigned(key, b"live".to_vec()))
            .unwrap();

        // Restore with a different value for the same key — live value must win.
        let stale = vec![DhtValueSnapshot {
            key,
            value: b"stale".to_vec(),
        }];
        svc.restore_values(stale);

        assert!(
            matches!(svc.handle_find_value(FindValuePayload { key }),
            FindValueResponse::Value(v) if v == b"live"),
            "restore must not overwrite an existing live entry"
        );
    }

    #[test]
    fn restore_values_noop_when_participate_false() {
        let mut svc = service(4);
        svc.set_participate(false);
        let snap = vec![DhtValueSnapshot {
            key: [0x44u8; 32],
            value: b"v".to_vec(),
        }];
        svc.restore_values(snap);
        assert_eq!(
            svc.stored_keys(),
            0,
            "restore must be a no-op when participate=false"
        );
    }

    #[test]
    fn values_snapshot_json_roundtrip() {
        let svc = service(5);
        let key = [0x55u8; 32];
        svc.handle_store(StorePayload::unsigned(key, vec![1, 2, 3]))
            .unwrap();
        let snap = svc.snapshot_values();

        let json = serde_json::to_string(&snap).expect("serialize");
        let loaded: Vec<DhtValueSnapshot> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].key, key);
        assert_eq!(loaded[0].value, vec![1, 2, 3]);
    }

    // ── DHT STORE ownership verification tests ─────────────────────

    /// Build a signed StorePayload using an ephemeral Ed25519 keypair.
    /// The key is `BLAKE3(pubkey)` and the signature covers `key || value`.
    fn signed_store_payload(value: &[u8]) -> (StorePayload, ed25519_dalek::SigningKey) {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let signing_key = SigningKey::generate(&mut OsRng);
        let pk_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
        let key = *blake3::hash(&pk_bytes).as_bytes();
        let mut msg = Vec::with_capacity(32 + value.len());
        msg.extend_from_slice(&key);
        msg.extend_from_slice(value);
        use ed25519_dalek::Signer as _;
        let sig: [u8; 64] = signing_key.sign(&msg).to_bytes();
        let payload = StorePayload {
            key,
            value: value.to_vec(),
            ed25519_pubkey: Some(pk_bytes),
            ed25519_sig: Some(sig),
        };
        (payload, signing_key)
    }

    #[test]
    fn signed_store_accepted() {
        let svc = service(0);
        let (payload, _) = signed_store_payload(b"hello");
        svc.handle_store(payload)
            .expect("valid signed STORE must be accepted");
    }

    #[test]
    fn unsigned_store_accepted_with_dev_flag() {
        // unsigned payloads (no pubkey) are
        // accepted ONLY when `dht_config.allow_unsigned_store == true`.
        // The test helper sets that flag (legacy fixtures predate the
        // signed-STORE invariant); production keeps the flag off.
        let svc = service(0);
        let key = [0xABu8; 32];
        svc.handle_store(StorePayload::unsigned(key, b"raw".to_vec()))
            .expect("unsigned STORE must be accepted under dev flag");
    }

    /// production-default `KademliaService`
    /// (no `allow_unsigned_store` opt-) rejects unsigned STOREs
    /// with `KademliaError::UnsignedStoreRejected` (split out from
    /// the catch-all `NotAllowed` in batch-6h). Closes the
    /// fill-the-store-with-junk attack vector.
    #[test]
    fn phase647_h23_unsigned_store_rejected_by_default() {
        let svc = KademliaService::new([0u8; 32]);
        let key = [0xCDu8; 32];
        let err = svc
            .handle_store(StorePayload::unsigned(key, b"junk".to_vec()))
            .expect_err("unsigned STORE must be rejected by default");
        assert_eq!(err, KademliaError::UnsignedStoreRejected);
        assert_eq!(
            svc.stored_keys(),
            0,
            "rejected STORE must NOT land in the local store"
        );
    }

    /// half-set authenticator (pubkey present
    /// but signature missing, or vice-versa) is rejected as malformed
    /// — never legitimate.
    #[test]
    fn phase647_h23_half_set_authenticator_rejected() {
        let svc = KademliaService::new([0u8; 32]);
        let key = [0xCDu8; 32];
        let mut payload = StorePayload::unsigned(key, b"hi".to_vec());
        // Half-set: pubkey present, signature absent.
        payload.ed25519_pubkey = Some([0u8; 32]);
        payload.ed25519_sig = None;
        let err = svc.handle_store(payload).unwrap_err();
        assert_eq!(err, KademliaError::InvalidSignature);
    }

    #[test]
    fn wrong_signature_rejected() {
        let svc = service(0);
        let (mut payload, _) = signed_store_payload(b"hello");
        // Corrupt the last byte of the signature.
        if let Some(ref mut sig) = payload.ed25519_sig {
            sig[63] ^= 0xFF;
        }
        let err = svc.handle_store(payload).unwrap_err();
        assert_eq!(err, KademliaError::InvalidSignature);
    }

    #[test]
    fn wrong_key_derivation_rejected() {
        // Pubkey is correct but the DHT key is NOT BLAKE3(pubkey).
        let svc = service(0);
        let (mut payload, _) = signed_store_payload(b"hello");
        // Replace key with something else — derivation check must fail.
        payload.key = [0x42u8; 32];
        let err = svc.handle_store(payload).unwrap_err();
        assert_eq!(err, KademliaError::InvalidSignature);
    }

    #[test]
    fn verify_store_ownership_fn_roundtrip() {
        use ed25519_dalek::{Signer as _, SigningKey};
        use rand_core::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let pk: [u8; 32] = sk.verifying_key().to_bytes();
        let key = *blake3::hash(&pk).as_bytes();
        let value = b"payload";
        let mut msg = key.to_vec();
        msg.extend_from_slice(value);
        let sig: [u8; 64] = sk.sign(&msg).to_bytes();
        assert!(verify_store_ownership(&key, value, &pk, &sig));
        // Mutated value must fail.
        assert!(!verify_store_ownership(&key, b"other", &pk, &sig));
    }

    /// Vivaldi-aware find_node returns closer peers first when
    /// vivaldi_weight > 0.
    #[test]
    fn vivaldi_biased_find_node_prefers_closer_peers() {
        use std::collections::HashMap;

        struct StubOracle(HashMap<[u8; 32], f64>);
        impl CoordinateOracle for StubOracle {
            fn estimated_distance(&self, peer: &[u8; 32]) -> Option<f64> {
                self.0.get(peer).copied()
            }
        }

        let local_id = [0x00u8; 32];
        let cfg = DhtRuntimeConfig {
            vivaldi_weight: 0.5,
            ..DhtRuntimeConfig::default()
        };
        let mut svc = KademliaService::with_config(local_id, cfg);

        // Peer A: XOR-close, Vivaldi-far (~283 units). Peer B: XOR-close, Vivaldi-near (~14 units).
        let a = [0x01u8; 32];
        svc.add_contact(Contact::new(a, "tcp://a:1"));
        let b = [0x02u8; 32];
        svc.add_contact(Contact::new(b, "tcp://b:1"));

        let mut distances = HashMap::new();
        distances.insert(a, ((200.0_f64).powi(2) + (200.0_f64).powi(2)).sqrt());
        distances.insert(b, ((10.0_f64).powi(2) + (10.0_f64).powi(2)).sqrt());
        svc.set_coord_oracle(Arc::new(StubOracle(distances)));

        let target = [0x03u8; 32];
        let resp =
            svc.handle_find_node_v2(veil_proto::discovery::FindNodeV2Payload { target, k: 2 });
        assert!(!resp.node_ids.is_empty());
        assert_eq!(resp.node_ids[0], b, "Vivaldi-near peer B should rank first");
    }

    // ── discovery_mode filter + half-cap on FIND_NODE ─────────

    /// Peers whose `discovery_mode!= Public` must be excluded from
    /// FIND_NODE responses, even when XOR-closer than Public alternatives.
    #[test]
    fn epic474_4_find_node_filters_non_public_peers() {
        let svc = make_test_kademlia_service([0u8; 32]);
        // 4 Public peers + 2 ContactsOnly + 1 IntroductionOnly.
        for i in 0..4 {
            let id = [0x10u8 + i; 32];
            svc.add_contact(Contact::with_mode(
                id,
                format!("tcp://pub-{i}:1"),
                veil_types::DiscoveryMode::Public,
            ));
        }
        for i in 0..2 {
            let id = [0x20u8 + i; 32];
            svc.add_contact(Contact::with_mode(
                id,
                format!("tcp://co-{i}:1"),
                veil_types::DiscoveryMode::ContactsOnly,
            ));
        }
        let intro_id = [0x30u8; 32];
        svc.add_contact(Contact::with_mode(
            intro_id,
            "tcp://intro:1",
            veil_types::DiscoveryMode::IntroductionOnly,
        ));

        let target = [0xFFu8; 32];
        let resp =
            svc.handle_find_node_v2(veil_proto::discovery::FindNodeV2Payload { target, k: 20 });
        let ids: std::collections::HashSet<[u8; 32]> = resp.node_ids.iter().copied().collect();

        // No ContactsOnly / IntroductionOnly peer must appear.
        for i in 0..2 {
            assert!(
                !ids.contains(&[0x20u8 + i; 32]),
                "ContactsOnly peer 0x{:02x} must not be in FIND_NODE response",
                0x20 + i
            );
        }
        assert!(
            !ids.contains(&intro_id),
            "IntroductionOnly peer must not be in FIND_NODE response"
        );

        // Only Public peers should be present (capped at 50% rule — see next test).
        for id in &ids {
            assert!(
                id[0] == 0x10 || id[0] == 0x11 || id[0] == 0x12 || id[0] == 0x13,
                "non-Public peer leaked: {:?}",
                id
            );
        }
    }

    /// Half-cap rule: a single FIND_NODE response must not disclose more
    /// than `ceil(N_public / 2)` Public peers — limits per-query
    /// enumeration cost for a censorship-resistance attacker.
    #[test]
    fn epic474_4_find_node_caps_at_half_of_public_set() {
        let svc = make_test_kademlia_service([0u8; 32]);
        // 5 Public peers — half-cap = ceil(5/2) = 3.
        for i in 0..5u8 {
            let id = [0x10u8 + i; 32];
            svc.add_contact(Contact::with_mode(
                id,
                format!("tcp://p{i}:1"),
                veil_types::DiscoveryMode::Public,
            ));
        }

        let target = [0xFFu8; 32];
        let resp =
            svc.handle_find_node_v2(veil_proto::discovery::FindNodeV2Payload { target, k: 20 });
        assert!(
            resp.node_ids.len() <= 3,
            "must return at most ceil(5/2) = 3 Public peers, got {}",
            resp.node_ids.len(),
        );
    }

    /// Edge case: with 1 Public peer, the half-cap (ceil(1/2) = 1) still
    /// returns that single peer — Kademlia connectivity is preserved
    /// for sparsely-populated routing tables.
    #[test]
    fn epic474_4_find_node_single_public_peer_still_returned() {
        let svc = make_test_kademlia_service([0u8; 32]);
        let pub_id = [0x10u8; 32];
        svc.add_contact(Contact::with_mode(
            pub_id,
            "tcp://p:1",
            veil_types::DiscoveryMode::Public,
        ));
        // Plus an IntroductionOnly peer that should be ignored.
        svc.add_contact(Contact::with_mode(
            [0x30u8; 32],
            "tcp://i:1",
            veil_types::DiscoveryMode::IntroductionOnly,
        ));

        let target = [0xFFu8; 32];
        let resp =
            svc.handle_find_node_v2(veil_proto::discovery::FindNodeV2Payload { target, k: 20 });
        assert_eq!(resp.node_ids.len(), 1);
        assert_eq!(resp.node_ids[0], pub_id);
    }

    /// `find_closest_public_node_ids` (used by RecursiveQuery answer path)
    /// applies the same Public-only filter and half-cap as `handle_find_node`.
    #[test]
    fn epic474_4_find_closest_public_node_ids_matches_filter_semantics() {
        let svc = make_test_kademlia_service([0u8; 32]);
        for i in 0..4u8 {
            svc.add_contact(Contact::with_mode(
                [0x10u8 + i; 32],
                format!("tcp://p{i}:1"),
                veil_types::DiscoveryMode::Public,
            ));
        }
        svc.add_contact(Contact::with_mode(
            [0x20u8; 32],
            "tcp://co:1",
            veil_types::DiscoveryMode::ContactsOnly,
        ));

        let target = [0xFFu8; 32];
        let result = svc.find_closest_public_node_ids(&target, 20);
        // 4 Public → ceil(4/2) = 2.
        assert!(result.len() <= 2, "got {}", result.len());
        for id in &result {
            assert!(
                id[0] == 0x10 || id[0] == 0x11 || id[0] == 0x12 || id[0] == 0x13,
                "non-Public id leaked: {:?}",
                id
            );
        }
    }

    /// Backward-compat: legacy `Contact::new` defaults `discovery_mode = Public`
    /// so pre-refactor routing-table snapshots and code paths behave
    /// the same as before — no peer gets accidentally hidden after upgrade.
    #[test]
    fn epic474_4_legacy_contact_new_defaults_to_public() {
        let svc = make_test_kademlia_service([0u8; 32]);
        for i in 0..3u8 {
            svc.add_contact(Contact::new([0x10u8 + i; 32], format!("tcp://p{i}:1")));
        }
        let target = [0xFFu8; 32];
        let resp =
            svc.handle_find_node_v2(veil_proto::discovery::FindNodeV2Payload { target, k: 20 });
        // 3 Public → ceil(3/2) = 2 returned.
        assert!(
            resp.node_ids.len() == 2,
            "legacy Contact::new must default to Public; got {} (cap kicks in)",
            resp.node_ids.len()
        );
    }

    // ── V2 + ResolveTransport handler tests ─────────────

    /// `handle_find_node_v2` returns node_ids only (no transports), with
    /// the same Public-only filter and half-cap as V1.
    #[test]
    fn epic475_find_node_v2_strips_transports_and_filters() {
        let svc = make_test_kademlia_service([0u8; 32]);
        for i in 0..4u8 {
            svc.add_contact(Contact::with_mode(
                [0x10u8 + i; 32],
                format!("tcp://pub-{i}:1"),
                veil_types::DiscoveryMode::Public,
            ));
        }
        svc.add_contact(Contact::with_mode(
            [0x20u8; 32],
            "tcp://co:1",
            veil_types::DiscoveryMode::ContactsOnly,
        ));

        let resp = svc.handle_find_node_v2(veil_proto::discovery::FindNodeV2Payload {
            target: [0xFFu8; 32],
            k: 20,
        });
        // 4 Public → cap = ceil(4/2) = 2.
        assert_eq!(
            resp.node_ids.len(),
            2,
            "V2 must apply the same half-cap as V1; got {} ids",
            resp.node_ids.len()
        );
        for nid in &resp.node_ids {
            assert!(
                matches!(nid[0], 0x10..=0x13),
                "ContactsOnly peer 0x{:02x} must not appear in V2 response",
                nid[0]
            );
        }
    }

    /// Helper for tests: build a fully-mined ResolveTransport
    /// payload for a given (requester, target) pair using the current
    /// time bucket. Panics if mining fails (extremely unlikely at the
    /// default 16-bit difficulty within 1 M attempts).
    fn fresh_resolve_payload(
        requester: [u8; 32],
        target: [u8; 32],
    ) -> veil_proto::discovery::ResolveTransportPayload {
        let (time_bucket, pow_nonce) =
            veil_proto::discovery::mine_resolve_pow_now(&requester, &target)
                .expect("PoW mining must succeed");
        veil_proto::discovery::ResolveTransportPayload {
            node_id: target,
            time_bucket,
            pow_nonce,
        }
    }

    /// Helper for / tests: produce a fresh
    /// `(node_id, SigningKey, SignedTransportAnnouncement)` tuple
    /// where `node_id == BLAKE3(signing_key.verifying_key)`.
    fn fresh_signed_peer(
        transport: &str,
    ) -> (
        [u8; 32],
        ed25519_dalek::SigningKey,
        veil_proto::discovery::SignedTransportAnnouncement,
    ) {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiry = now + 600; // 10 minutes
        let ann =
            veil_proto::discovery::sign_transport_announcement(&sk, transport.to_owned(), expiry);
        (ann.node_id, sk, ann)
    }

    /// `handle_resolve_transport` returns the **signed** announcement
    /// for a known Public peer when the request carries a valid PoW
    /// solution and we have the announcement stored locally.
    #[test]
    fn epic475_resolve_transport_returns_known_public_peer() {
        let svc = make_test_kademlia_service([0u8; 32]);
        let requester = [0xAAu8; 32];
        let (target, _sk, ann) = fresh_signed_peer("tcp://10.0.0.7:9000");
        svc.add_contact(Contact::with_mode(
            target,
            "tcp://10.0.0.7:9000",
            veil_types::DiscoveryMode::Public,
        ));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            svc.store_transport_announcement(ann, now),
            "valid announcement must store"
        );

        let resp =
            svc.handle_resolve_transport(requester, fresh_resolve_payload(requester, target));
        assert_eq!(resp.node_id, target);
        let returned = resp
            .announcement
            .expect("Public peer with stored announcement must be served");
        assert_eq!(returned.transport, "tcp://10.0.0.7:9000");
        assert_eq!(returned.node_id, target);
        // The bundle must verify — defence-in-depth (the handler already verified before sending).
        assert!(veil_proto::discovery::verify_transport_announcement(
            &returned, now
        ));
    }

    /// `handle_resolve_transport` returns `not_found` for a peer that
    /// exists in our routing table but is `ContactsOnly` — the resolver
    /// must not reveal even existence of non-Public peers, even if we
    /// happen to have a (cached) signed announcement for them.
    #[test]
    fn epic475_resolve_transport_hides_contacts_only_peer() {
        let svc = make_test_kademlia_service([0u8; 32]);
        let requester = [0xAAu8; 32];
        let (private, _sk, ann) = fresh_signed_peer("tcp://10.0.0.55:9000");
        svc.add_contact(Contact::with_mode(
            private,
            "tcp://10.0.0.55:9000",
            veil_types::DiscoveryMode::ContactsOnly,
        ));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let _ = svc.store_transport_announcement(ann, now);

        let resp =
            svc.handle_resolve_transport(requester, fresh_resolve_payload(requester, private));
        assert_eq!(resp.node_id, private);
        assert!(
            resp.announcement.is_none(),
            "ContactsOnly peer must return not_found even with announcement stored"
        );
    }

    /// `handle_resolve_transport` returns `not_found` for a node_id that
    /// is not in our routing table at all.
    #[test]
    fn epic475_resolve_transport_unknown_node_id_not_found() {
        let svc = make_test_kademlia_service([0u8; 32]);
        let requester = [0xAAu8; 32];
        // Add some unrelated peers so the routing table is non-empty.
        svc.add_contact(Contact::with_mode(
            [0x10u8; 32],
            "tcp://a:1",
            veil_types::DiscoveryMode::Public,
        ));

        let resp =
            svc.handle_resolve_transport(requester, fresh_resolve_payload(requester, [0xFFu8; 32]));
        assert!(
            resp.announcement.is_none(),
            "unknown node_id must return not_found"
        );
    }

    /// `handle_resolve_transport` also hides `IntroductionOnly` peers.
    #[test]
    fn epic475_resolve_transport_hides_introduction_only_peer() {
        let svc = make_test_kademlia_service([0u8; 32]);
        let requester = [0xAAu8; 32];
        let (intro, _sk, ann) = fresh_signed_peer("tcp://10.0.0.66:9000");
        svc.add_contact(Contact::with_mode(
            intro,
            "tcp://10.0.0.66:9000",
            veil_types::DiscoveryMode::IntroductionOnly,
        ));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let _ = svc.store_transport_announcement(ann, now);

        let resp = svc.handle_resolve_transport(requester, fresh_resolve_payload(requester, intro));
        assert!(
            resp.announcement.is_none(),
            "IntroductionOnly peer must return not_found"
        );
    }

    ///a Public peer with **no stored announcement** still
    /// returns `not_found` — the resolver only serves what it has been
    /// gossiped, never synthesizes signatures.
    #[test]
    fn epic475_4c_resolve_transport_public_without_announcement_returns_not_found() {
        let svc = make_test_kademlia_service([0u8; 32]);
        let requester = [0xAAu8; 32];
        let target = [0x42u8; 32];
        // Add the Public Contact but *don't* call store_transport_announcement.
        svc.add_contact(Contact::with_mode(
            target,
            "tcp://10.0.0.7:9000",
            veil_types::DiscoveryMode::Public,
        ));

        let resp =
            svc.handle_resolve_transport(requester, fresh_resolve_payload(requester, target));
        assert!(
            resp.announcement.is_none(),
            "no stored announcement → not_found, even for Public peer"
        );
    }

    ///an **expired** stored announcement is not served — the
    /// resolver must not relay stale signatures past their expiry.
    #[test]
    fn epic475_4c_resolve_transport_drops_expired_announcement() {
        let svc = make_test_kademlia_service([0u8; 32]);
        let requester = [0xAAu8; 32];
        let (target, sk, _live_ann) = fresh_signed_peer("tcp://10.0.0.7:9000");
        svc.add_contact(Contact::with_mode(
            target,
            "tcp://10.0.0.7:9000",
            veil_types::DiscoveryMode::Public,
        ));

        // Sign for `now + 1` so it's valid at insert-time but expired by handler-time.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let short_ann = veil_proto::discovery::sign_transport_announcement(
            &sk,
            "tcp://10.0.0.7:9000".to_owned(),
            now + 1,
        );
        assert!(
            svc.store_transport_announcement(short_ann, now),
            "live insert must succeed"
        );

        // Sleep just past expiry.
        std::thread::sleep(std::time::Duration::from_millis(1_500));

        let resp =
            svc.handle_resolve_transport(requester, fresh_resolve_payload(requester, target));
        assert!(
            resp.announcement.is_none(),
            "expired announcement must not be served"
        );
    }

    ///`store_transport_announcement` rejects an announcement
    /// whose pubkey doesn't match its claimed `node_id` — defence
    /// against malicious AnnounceTransport gossip from a peer trying to
    /// pollute our store with bogus entries for someone else's node_id.
    #[test]
    fn epic475_4c_store_rejects_pubkey_node_id_mismatch() {
        let svc = make_test_kademlia_service([0u8; 32]);
        let (_target, _sk, ann) = fresh_signed_peer("tcp://10.0.0.7:9000");
        let mut tampered = ann.clone();
        tampered.node_id = [0xEEu8; 32]; // detach node_id from pubkey
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            !svc.store_transport_announcement(tampered, now),
            "node_id ≠ BLAKE3(pubkey) must fail verify_announcement → reject store"
        );
    }

    ///`prune_orphan_announcements` drops entries whose
    /// `node_id` no longer has a routing-table contact — bounds memory
    /// under churn.
    #[test]
    fn epic475_4c_prune_orphan_announcements_drops_evicted_peers() {
        let svc = make_test_kademlia_service([0u8; 32]);
        let (target, _sk, ann) = fresh_signed_peer("tcp://10.0.0.7:9000");
        // Don't add Contact — store, then prune; the entry should be evicted.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(svc.store_transport_announcement(ann, now));
        assert_eq!(svc.transport_announcements_count(), 1);
        assert_eq!(svc.prune_orphan_announcements(), 1, "must drop the orphan");
        assert_eq!(svc.transport_announcements_count(), 0);
        // No-op when nothing to prune.
        assert_eq!(svc.prune_orphan_announcements(), 0);
        let _ = target;
    }

    // ── persistence snapshot/restore tests ──

    ///snapshot → restore roundtrip preserves every valid
    /// announcement. Simulates a clean restart where the on-disk file
    /// holds N entries from the previous run.
    #[test]
    fn epic475_3b_snapshot_restore_roundtrip() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Source service: store 3 distinct signed announcements.
        let src = make_test_kademlia_service([0u8; 32]);
        let (id_a, _sk_a, ann_a) = fresh_signed_peer("tcp://node-a:9000");
        let (id_b, _sk_b, ann_b) = fresh_signed_peer("tcp://node-b:9000");
        let (id_c, _sk_c, ann_c) = fresh_signed_peer("tcp://node-c:9000");
        assert!(src.store_transport_announcement(ann_a, now));
        assert!(src.store_transport_announcement(ann_b, now));
        assert!(src.store_transport_announcement(ann_c, now));
        assert_eq!(src.transport_announcements_count(), 3);

        // Snapshot → JSON → bytes → JSON → snapshot, mimicking
        // `flush_transport_announcements_snapshot_sync` + restore.
        let snap = src.snapshot_transport_announcements();
        let json = serde_json::to_vec(&snap).expect("serde");
        let restored: Vec<veil_proto::discovery::SignedTransportAnnouncement> =
            serde_json::from_slice(&json).expect("deserde");

        // Restore into a fresh service.
        let dst = make_test_kademlia_service([0u8; 32]);
        let (inserted, rejected) = dst.restore_transport_announcements(restored, now);
        assert_eq!(inserted, 3);
        assert_eq!(rejected, 0);
        assert_eq!(dst.transport_announcements_count(), 3);
        // Confirm specific ids are present.
        for id in [id_a, id_b, id_c] {
            assert!(
                lock!(dst.inner).transport_announcements.contains_key(&id),
                "missing id {:?}",
                &id[..4]
            );
        }
    }

    ///restore drops expired entries silently — a node that
    /// was offline for > ANNOUNCEMENT_VALIDITY_SECS shouldn't serve
    /// stale signatures after restart.
    #[test]
    fn epic475_3b_restore_drops_expired_entries() {
        // Sign for `now - 1` so the announcement is already expired
        // by the time `restore_transport_announcements(now)` runs.
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sk = SigningKey::generate(&mut OsRng);

        // One valid + one expired.
        let valid = veil_proto::discovery::sign_transport_announcement(
            &sk,
            "tcp://node:9000".to_owned(),
            now + 600,
        );
        // Generate a separate key for the expired one so node_ids differ.
        let sk_expired = SigningKey::generate(&mut OsRng);
        let expired = veil_proto::discovery::sign_transport_announcement(
            &sk_expired,
            "tcp://expired:9000".to_owned(),
            now.saturating_sub(10),
        );

        let dst = make_test_kademlia_service([0u8; 32]);
        let (inserted, rejected) =
            dst.restore_transport_announcements(vec![valid.clone(), expired], now);
        assert_eq!(inserted, 1, "valid entry must restore");
        assert_eq!(rejected, 1, "expired entry must be dropped");
        assert!(
            lock!(dst.inner)
                .transport_announcements
                .contains_key(&valid.node_id)
        );
    }

    // ── backlog: local-announcement re-mint tests ────────────

    /// Re-mint is a no-op when no signing source is configured (pure
    /// outbound clients): nothing to mint with.
    #[test]
    fn epic475_remint_no_source_returns_none() {
        let svc = make_test_kademlia_service([0u8; 32]);
        assert!(svc.maybe_remint_local_announcement(1_700_000_000).is_none());
        assert!(
            svc.local_announcement().is_none(),
            "no source → still no local announcement"
        );
    }

    /// Re-mint is a no-op when the existing announcement still has
    /// > ANNOUNCEMENT_VALIDITY_SECS / 2 of validity remaining.
    #[test]
    fn epic475_remint_fresh_announcement_skipped() {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let svc = make_test_kademlia_service([0u8; 32]);
        let sk = Arc::new(SigningKey::generate(&mut OsRng));
        svc.configure_local_announcement_source(Arc::clone(&sk), "tcp://node:9000".to_owned());

        let initial = svc.local_announcement().expect("source configures bundle");
        // Just-after-configure: the bundle has full validity, so checking now must skip.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            svc.maybe_remint_local_announcement(now).is_none(),
            "fresh announcement must not re-mint"
        );
        // Bundle unchanged.
        assert_eq!(svc.local_announcement(), Some(initial));
    }

    /// Re-mint fires when remaining validity is at or below half;
    /// the new bundle has a fresh expiry and verifies.
    #[test]
    fn epic475_remint_half_expired_triggers_remint() {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let svc = make_test_kademlia_service([0u8; 32]);
        let sk = Arc::new(SigningKey::generate(&mut OsRng));
        svc.configure_local_announcement_source(Arc::clone(&sk), "tcp://node:9000".to_owned());

        let initial = svc.local_announcement().unwrap();
        let initial_expiry = initial.expiry_unix;

        // Move "now" forward to just past half-validity: remaining ≤ half.
        let half = veil_proto::discovery::ANNOUNCEMENT_VALIDITY_SECS / 2;
        let mock_now = initial_expiry.saturating_sub(half) + 1;

        let new_ann = svc
            .maybe_remint_local_announcement(mock_now)
            .expect("must re-mint at half-validity");
        // Fresh expiry = mock_now + full validity, and strictly later than initial.
        assert_eq!(
            new_ann.expiry_unix,
            mock_now + veil_proto::discovery::ANNOUNCEMENT_VALIDITY_SECS,
        );
        assert!(new_ann.expiry_unix > initial_expiry);
        // Same node_id (same pubkey), but a different signature
        // (different message → different sig).
        assert_eq!(new_ann.node_id, initial.node_id);
        assert_ne!(new_ann.signature, initial.signature);
        // Re-minted bundle verifies at the new "now".
        assert!(veil_proto::discovery::verify_transport_announcement(
            &new_ann, mock_now
        ));
        // KademliaService now holds the new bundle (the re-mint was applied in place).
        assert_eq!(
            svc.local_announcement().unwrap().expiry_unix,
            new_ann.expiry_unix
        );
    }

    /// Re-mint is idempotent within the same minute: a second call
    /// immediately after a successful re-mint should NOT re-mint
    /// again (the new bundle has full validity left).
    #[test]
    fn epic475_remint_idempotent_after_remint() {
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        let svc = make_test_kademlia_service([0u8; 32]);
        let sk = Arc::new(SigningKey::generate(&mut OsRng));
        svc.configure_local_announcement_source(Arc::clone(&sk), "tcp://node:9000".to_owned());

        let initial_expiry = svc.local_announcement().unwrap().expiry_unix;
        let half = veil_proto::discovery::ANNOUNCEMENT_VALIDITY_SECS / 2;
        let mock_now = initial_expiry.saturating_sub(half) + 1;

        let _first = svc
            .maybe_remint_local_announcement(mock_now)
            .expect("first call re-mints");
        let second = svc.maybe_remint_local_announcement(mock_now);
        assert!(
            second.is_none(),
            "fresh post-re-mint bundle must not re-mint again at the same `now`"
        );
    }

    ///tampered entries (signature won't verify, or
    /// pubkey↔node_id mismatch) are silently dropped on restore — the
    /// on-disk file is **not** a trust boundary; signatures are. An
    /// attacker who edits the file can downgrade availability but
    /// cannot inject forged transports.
    #[test]
    fn epic475_3b_restore_drops_tampered_entries() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (_target, _sk, ann) = fresh_signed_peer("tcp://node:9000");
        let mut tampered = ann.clone();
        tampered.transport = "tcp://attacker:9000".to_owned(); // breaks signature

        let dst = make_test_kademlia_service([0u8; 32]);
        let (inserted, rejected) =
            dst.restore_transport_announcements(vec![ann.clone(), tampered], now);
        assert_eq!(inserted, 1);
        assert_eq!(rejected, 1);
        // The valid one survived.
        assert!(
            lock!(dst.inner)
                .transport_announcements
                .contains_key(&ann.node_id)
        );
    }

    // ── PoW-gate tests ─────────────────────

    /// PoW gate: a request with an unmined `pow_nonce` (zero) must be
    /// rejected as `not_found` even when the target is a known Public
    /// peer. This protects against attackers skipping the PoW work.
    #[test]
    fn epic475_4b_resolve_transport_rejects_invalid_pow() {
        let svc = make_test_kademlia_service([0u8; 32]);
        let target = [0x42u8; 32];
        let requester = [0xAAu8; 32];
        svc.add_contact(Contact::with_mode(
            target,
            "tcp://10.0.0.7:9000",
            veil_types::DiscoveryMode::Public,
        ));

        // Build a payload with a fresh time_bucket but an unmined nonce.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let time_bucket = (now_secs / veil_proto::discovery::RESOLVE_POW_BUCKET_SECONDS) as u32;
        let payload = veil_proto::discovery::ResolveTransportPayload {
            node_id: target,
            time_bucket,
            pow_nonce: [0u8; 16], // unmined; overwhelmingly unlikely to satisfy difficulty
        };

        let resp = svc.handle_resolve_transport(requester, payload);
        assert!(
            resp.announcement.is_none(),
            "request with unmined PoW must be rejected as not_found"
        );
    }

    /// PoW gate: a request with a stale `time_bucket` (more than the
    /// allowed window in the past) must be rejected even with a valid
    /// solution for that bucket. Bounds replay window.
    #[test]
    fn epic475_4b_resolve_transport_rejects_stale_time_bucket() {
        let svc = make_test_kademlia_service([0u8; 32]);
        let target = [0x42u8; 32];
        let requester = [0xAAu8; 32];
        svc.add_contact(Contact::with_mode(
            target,
            "tcp://10.0.0.7:9000",
            veil_types::DiscoveryMode::Public,
        ));

        // Pick a bucket far in the past and mine a valid solution for it.
        let stale_bucket = 1_000u32; // ~17 minutes
        let pow_nonce =
            veil_proto::discovery::mine_resolve_pow(&requester, &target, stale_bucket, 1_000_000)
                .expect("mine for stale bucket");
        let payload = veil_proto::discovery::ResolveTransportPayload {
            node_id: target,
            time_bucket: stale_bucket,
            pow_nonce,
        };

        let resp = svc.handle_resolve_transport(requester, payload);
        assert!(
            resp.announcement.is_none(),
            "request with stale time_bucket must be rejected even with valid PoW"
        );
    }

    /// PoW gate: a solution mined for one (requester, target) pair must
    /// not satisfy a different requester's request — domain-separation
    /// + binding prevents cross-requester PoW reuse.
    #[test]
    fn epic475_4b_resolve_transport_rejects_pow_bound_to_different_requester() {
        let svc = make_test_kademlia_service([0u8; 32]);
        let target = [0x42u8; 32];
        let alice = [0xAAu8; 32];
        let bob = [0xBBu8; 32];
        svc.add_contact(Contact::with_mode(
            target,
            "tcp://10.0.0.7:9000",
            veil_types::DiscoveryMode::Public,
        ));

        // Alice mines a solution (alice, target) — Bob then tries
        // to reuse it as (bob, target).
        let alice_payload = fresh_resolve_payload(alice, target);
        let bob_attempt = veil_proto::discovery::ResolveTransportPayload {
            node_id: alice_payload.node_id,
            time_bucket: alice_payload.time_bucket,
            pow_nonce: alice_payload.pow_nonce,
        };

        let resp = svc.handle_resolve_transport(bob, bob_attempt);
        assert!(
            resp.announcement.is_none(),
            "Alice's PoW must not be accepted from Bob's session"
        );
    }

    /// PoW gate: a solution mined for one *target* must not satisfy a
    /// request for a different target — prevents an attacker who has
    /// mined one solution from reusing it to enumerate other peers.
    #[test]
    fn epic475_4b_resolve_transport_rejects_pow_bound_to_different_target() {
        let svc = make_test_kademlia_service([0u8; 32]);
        let t1 = [0x42u8; 32];
        let t2 = [0x43u8; 32];
        let requester = [0xAAu8; 32];
        svc.add_contact(Contact::with_mode(
            t1,
            "tcp://10.0.0.7:9000",
            veil_types::DiscoveryMode::Public,
        ));
        svc.add_contact(Contact::with_mode(
            t2,
            "tcp://10.0.0.8:9000",
            veil_types::DiscoveryMode::Public,
        ));

        let solved_for_t1 = fresh_resolve_payload(requester, t1);
        let attempt = veil_proto::discovery::ResolveTransportPayload {
            node_id: t2, // different target
            time_bucket: solved_for_t1.time_bucket,
            pow_nonce: solved_for_t1.pow_nonce,
        };

        let resp = svc.handle_resolve_transport(requester, attempt);
        assert!(
            resp.announcement.is_none(),
            "PoW for target t1 must not be accepted for target t2"
        );
    }
}
