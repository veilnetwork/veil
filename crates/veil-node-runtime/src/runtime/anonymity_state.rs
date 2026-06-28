//! decomposition PR1: anonymity-related runtime state
//! extracted into a dedicated [`Arc<AnonymityState>`].
//!
//! ## Why a dedicated struct
//!
//! `NodeRuntime` previously held four anonymity-related fields directly
//! (`anonymity_relay_capable`, `anonymity_advertised_bps`
//! `anonymity_x25519_sk`, `rendezvous_publisher_entries`). Lock-order
//! across the runtime's >15 lockable fields was documented at
//! `node/runtime/mod.rs:4488-4499` but enforced only by review.
//! Lifting domain-grouped state into [`Arc<DomainState>`] structs
//! makes cross-domain ordering impossible-by-construction (each domain
//! owns its own locks; no shared parent lock to acquire in a wrong order).
//!
//! ## Migration surface
//!
//! Each method that used to read `self.anonymity_*` now reads
//! `self.anonymity.*` — a pure rename refactor (no behaviour change).
//! Mutation of `relay_capable` and `advertised_bps` happens only via
//! `reload`, which atomically swaps the `Arc<AnonymityState>` on the
//! parent runtime; in-flight handshakes/maintenance ticks holding a
//! pre-reload `Arc` continue with their snapshot until they next refresh
//! which matches existing semantics (the old direct fields were also
//! read-once per loop iteration).

use std::sync::{Arc, Mutex};

use veil_anonymity::relay_reputation::RelayReputation;
use veil_anonymity::rendezvous::{RendezvousAd, RendezvousPublisherEntry, is_currently_valid};

/// Default TTL for a stored reply block — the brick-4 freshness window.
pub const DEFAULT_REPLY_BLOCK_TTL_SECS: u64 = 300;
/// Default cap on concurrently-stored reply blocks (FIFO-evicted).
pub const DEFAULT_REPLY_BLOCK_CAP: usize = 4096;

/// How long a sender may reuse a network-validated rendezvous route before it
/// must ask the DHT replicas again.  This is deliberately much shorter than a
/// signed ad's validity window: an ad can remain cryptographically valid after
/// its receiver reconnects and moves to a different rendezvous relay, but that
/// old relay no longer has the cookie registration and drops every introduce.
pub const RENDEZVOUS_RESOLVE_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(15);

/// Bound the per-recipient route cache independently of DHT storage limits.
const MAX_RENDEZVOUS_RESOLVE_CACHE: usize = 1024;

#[derive(Clone)]
struct CachedRendezvousAds {
    ads: Vec<RendezvousAd>,
    checked_at: std::time::Instant,
}

/// Short-lived cache of ads that were compared across independent DHT
/// replicas.  The ordinary Kademlia local store cannot serve this purpose: it
/// keeps one still-valid value per key and therefore used to pin a sender to an
/// old `(relay, cookie)` for the ad's entire TTL after receiver relay rotation.
pub struct RendezvousResolveCache {
    inner: Mutex<std::collections::HashMap<[u8; 32], CachedRendezvousAds>>,
    refresh_locks: Mutex<std::collections::HashMap<[u8; 32], Arc<tokio::sync::Mutex<()>>>>,
    ttl: std::time::Duration,
    cap: usize,
}

impl RendezvousResolveCache {
    pub fn new() -> Self {
        Self::with_params(RENDEZVOUS_RESOLVE_CACHE_TTL, MAX_RENDEZVOUS_RESOLVE_CACHE)
    }

    fn with_params(ttl: std::time::Duration, cap: usize) -> Self {
        Self {
            inner: Mutex::new(std::collections::HashMap::new()),
            refresh_locks: Mutex::new(std::collections::HashMap::new()),
            ttl,
            cap: cap.max(1),
        }
    }

    /// Coalesce a burst of sends to the same recipient into one network
    /// refresh. Content chunks are intentionally numerous; without this
    /// single-flight lock, an expired route cache could launch one DHT fan-out
    /// per chunk before the first refresh completed.
    pub async fn lock_refresh(&self, receiver: [u8; 32]) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.refresh_locks.lock().unwrap_or_else(|p| p.into_inner());
            if locks.len() >= self.cap && !locks.contains_key(&receiver) {
                // Entries are tiny and only coordinate transient work. Prefer
                // dropping an unlocked handle over unbounded growth; a guard
                // already held elsewhere retains its Arc and remains valid.
                if let Some(id) = locks
                    .iter()
                    .find(|(_, lock)| Arc::strong_count(lock) == 1)
                    .map(|(id, _)| *id)
                {
                    locks.remove(&id);
                }
            }
            Arc::clone(
                locks
                    .entry(receiver)
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        lock.lock_owned().await
    }

    /// Return a recently network-validated route set, filtering out ads whose
    /// signed validity ended while the cache entry was resident.
    pub fn get(&self, receiver: &[u8; 32], now_unix: u64) -> Option<Vec<RendezvousAd>> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let entry = inner.get(receiver)?;
        if entry.checked_at.elapsed() >= self.ttl {
            inner.remove(receiver);
            return None;
        }
        let ads: Vec<_> = entry
            .ads
            .iter()
            .filter(|ad| is_currently_valid(ad, now_unix).is_ok())
            .cloned()
            .collect();
        if ads.is_empty() {
            inner.remove(receiver);
            None
        } else {
            Some(ads)
        }
    }

    pub fn put(&self, receiver: [u8; 32], ads: Vec<RendezvousAd>) {
        if ads.is_empty() {
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if inner.len() >= self.cap
            && !inner.contains_key(&receiver)
            && let Some(oldest) = inner
                .iter()
                .min_by_key(|(_, entry)| entry.checked_at)
                .map(|(id, _)| *id)
        {
            inner.remove(&oldest);
            self.refresh_locks
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&oldest);
        }
        inner.insert(
            receiver,
            CachedRendezvousAds {
                ads,
                checked_at: std::time::Instant::now(),
            },
        );
    }
}

impl Default for RendezvousResolveCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Bounded, TTL'd store of one-time reply blocks (reply-channel). The
/// auth-deliver task inserts a block when a verified message carries a reply
/// path and surfaces a non-zero `reply_id` to the recipient app; the reply-send
/// path takes the block back by `reply_id`. The block stays daemon-side — it
/// never crosses the IPC/FFI boundary (the app only ever sees the opaque id).
pub struct ReplyBlockStore {
    inner: Mutex<ReplyStoreState>,
    cap: usize,
    ttl_secs: u64,
}

#[derive(Default)]
struct ReplyStoreState {
    /// reply_id → (block, expiry_unix, owner_app_id). The reply's routing (relay,
    /// cookie, receiver transport node_id) lives inside the signed `ReplyBlock`
    /// itself. `owner_app_id` is the local app that RECEIVED the message (and was
    /// handed this `reply_id`); only that app may reply through it (diff-audit
    /// D3) — without the binding, any local app that guessed/observed a reply_id
    /// (a small monotonic u64) could reply through another app's channel.
    map: std::collections::HashMap<u64, (veil_proto::ReplyBlock, u64, [u8; 32])>,
    /// Insertion order (front = oldest) for TTL-GC + FIFO cap-evict.
    order: std::collections::VecDeque<u64>,
    /// Monotonic id allocator; never hands out 0 (0 = "no reply").
    next_id: u64,
}

impl ReplyBlockStore {
    pub fn new() -> Self {
        Self::with_params(DEFAULT_REPLY_BLOCK_TTL_SECS, DEFAULT_REPLY_BLOCK_CAP)
    }

    pub fn with_params(ttl_secs: u64, cap: usize) -> Self {
        Self {
            inner: Mutex::new(ReplyStoreState {
                next_id: 1,
                ..Default::default()
            }),
            cap: cap.max(1),
            ttl_secs,
        }
    }

    /// GC expired entries from the front (uniform TTL → front is oldest).
    fn gc(state: &mut ReplyStoreState, now_unix: u64) {
        while let Some(&id) = state.order.front() {
            match state.map.get(&id) {
                Some(&(_, exp, _)) if now_unix >= exp => {
                    state.map.remove(&id);
                    state.order.pop_front();
                }
                Some(_) => break,
                None => {
                    state.order.pop_front();
                }
            }
        }
    }

    /// Store `block` owned by `owner_app_id` (the app that received the message),
    /// returning a fresh non-zero `reply_id`. Only `owner_app_id` may later
    /// [`peek`](Self::peek) it (diff-audit D3).
    pub fn store(
        &self,
        block: veil_proto::ReplyBlock,
        owner_app_id: [u8; 32],
        now_unix: u64,
    ) -> u64 {
        let mut s = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Self::gc(&mut s, now_unix);
        while s.map.len() >= self.cap {
            match s.order.pop_front() {
                Some(old) => {
                    s.map.remove(&old);
                }
                None => break,
            }
        }
        let id = s.next_id;
        let next = s.next_id.wrapping_add(1);
        s.next_id = if next == 0 { 1 } else { next };
        s.map.insert(
            id,
            (block, now_unix.saturating_add(self.ttl_secs), owner_app_id),
        );
        s.order.push_back(id);
        id
    }

    /// Peek a block by `reply_id`, if present + unexpired. NON-consuming: the
    /// block stays valid until its TTL so the app can RETRY a reply whose cell
    /// the network dropped (replies are fire-and-forget with no end-to-end ack;
    /// the onion/rendezvous legs can drop ~25% in a lossy sim/network). Delivery
    /// is therefore at-least-once — a recipient may see a duplicate reply if more
    /// than one copy lands, and should de-dup at the app layer. (Was single-use
    /// `take`; relaxed to TTL-bounded multi-use — onion-registration cleanup 1b.)
    /// `requester_app_id` MUST equal the `owner_app_id` the block was stored
    /// under (diff-audit D3) — a mismatch returns `None` (treated as
    /// unknown/expired by the caller), so one local app cannot reply through
    /// another app's reply channel by guessing its (small, monotonic) reply_id.
    pub fn peek(
        &self,
        reply_id: u64,
        requester_app_id: [u8; 32],
        now_unix: u64,
    ) -> Option<veil_proto::ReplyBlock> {
        if reply_id == 0 {
            return None;
        }
        let mut s = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Self::gc(&mut s, now_unix);
        let (block, exp, owner) = s.map.get(&reply_id)?;
        if now_unix >= *exp || *owner != requester_app_id {
            None
        } else {
            Some(block.clone())
        }
    }
}

impl Default for ReplyBlockStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Anonymity-domain state owned by [`NodeRuntime`] and shared as
/// `Arc<AnonymityState>` with maintenance tasks, dispatcher seed, and
/// per-session contexts.
///
/// finish: visibility lifted to `pub` (was `pub`)
/// so `NodeRuntime::anonymity: Arc<AnonymityState>` can carry the type
/// across module boundaries without the `private_interfaces` warning.
pub struct AnonymityState {
    /// cached snapshot of `cfg.anonymity.relay_capable`.
    /// Read at every handshake to set the `ANONYMITY_RELAY` capability
    /// flag. Cached (vs. read from disk per-handshake) to keep the
    /// handshake hot-path cheap; updated on `reload` via a fresh
    /// `Arc<AnonymityState>`.
    pub relay_capable: bool,

    /// cached `advertised_bps` for the relay-directory
    /// entry we periodically publish to DHT. Self-reported
    /// UNVERIFIED. Updated on `reload`.
    pub advertised_bps: u32,

    /// X25519 secret key the node uses for anonymity-hop
    /// ECDH inside [`veil_anonymity::onion::unwrap_at_hop`].
    /// Distinct from the OVL1 session ECDH (fresh ephemeral keypairs per
    /// session) — anonymity hops need a stable pubkey the relay-
    /// directory entry can advertise. Generated fresh at startup;
    /// rotates on restart, which is fine because directory entries are
    /// freshness-bounded (24 h default). Stored in-memory only; no
    /// on-disk persistence (compromise of the disk → loss of past
    /// anonymity, which is the point of forward-secret rotation).
    pub x25519_sk: Arc<x25519_dalek::StaticSecret>,

    /// rendezvous-publisher state. Receivers add
    /// entries via `register_rendezvous_publisher`; the maintenance
    /// tick re-signs + re-stores each `RendezvousAd` to the DHT before
    /// its `valid_until` lapses (half-life refresh). Empty by
    /// default — only receivers that explicitly opt in to
    /// rendezvous-routed inbound delivery touch this.
    pub rendezvous_publisher_entries: Arc<Mutex<Vec<RendezvousPublisherEntry>>>,

    /// Sender-side short-lived, network-validated rendezvous route cache.  It
    /// is shared by the live onion send path and the mailbox-replica IPC lookup
    /// so neither can get pinned to a still-valid but no-longer-live local ad.
    pub rendezvous_resolve_cache: Arc<RendezvousResolveCache>,

    /// Per-node anonymity-relay failure ledger (Epic 482.3/482.4 Phase A).
    /// Records relays observed to misbehave — a chosen first hop with no live
    /// session (send-time), or a relayed delivery that exhausted retransmits
    /// (timeout). The circuit picker consults its `rtt_penalty_ms` so a
    /// misbehaving relay sorts behind viable alternatives. Built once at
    /// startup and shared by `Arc`, so the short-term memory persists for the
    /// process lifetime. Bounded + LRU-evicted; failures only, no decay (see
    /// `veil_anonymity::relay_reputation`).
    pub relay_reputation: Arc<RelayReputation>,

    /// One-time reply blocks (reply-channel). Inserted by the auth-deliver task
    /// when a verified inbound message carries a reply path; consumed by the
    /// reply-send path. Bounded + TTL'd; the block never leaves the daemon.
    pub reply_block_store: Arc<ReplyBlockStore>,

    /// AuthDeliver (sender, nonce) replay cache. PERSISTENT across config reload
    /// (diff-audit Δ2-b): the auth-deliver task is re-spawned on reload, and
    /// before this lived task-locally — so a reload reset the replay window,
    /// briefly re-opening it for captured ciphertexts (the Introduce cache was
    /// already preserved this way; this brings parity). Interior-mutable
    /// (`check_and_record(&self, ..)`), so it shares fine behind `Arc`.
    pub auth_deliver_replay_cache: Arc<veil_identity::auth_deliver::AuthDeliverReplayCache>,

    /// Active location-anonymous services this node hosts (onion-registration):
    /// the `(relay_path, cookie)` + last-build time of each, so the maintenance
    /// tick can REBUILD the circuit before its TTL lapses (the circuit is
    /// otherwise built once and idle-GC'd). Empty unless the node registered an
    /// onion service via `register_onion_circuit`.
    pub onion_services: Arc<Mutex<Vec<OnionServiceEntry>>>,

    /// `Some(hops)` when `[anonymity].onion_service` is enabled — the maintenance
    /// tick auto-registers a location-anonymous service of this circuit length
    /// once relays are available, then keeps it alive. `None` = not hosting.
    pub onion_service_hops: Option<usize>,

    /// Operator-pinned rendezvous relays (`[anonymity].rendezvous_relays`),
    /// parsed to node-ids once at construction. The rendezvous-recipient task
    /// honoured this, but `select_onion_relay_path` (onion-service / reply
    /// circuits) used to ignore it (diff-audit Δ2-h) — empty = auto-pick.
    pub pinned_rendezvous_relays: Vec<[u8; 32]>,
}

/// One hosted onion service to keep alive (see [`AnonymityState::onion_services`]).
#[derive(Clone)]
pub struct OnionServiceEntry {
    /// Hop list first→terminus (terminus = the rendezvous relay R).
    pub relay_path: Vec<[u8; 32]>,
    /// Rendezvous cookie bound to this service's circuit.
    pub cookie: [u8; 16],
    /// Unix secs of the last (re)build, for the refresh cadence.
    pub built_unix: u64,
    /// STABLE Ed25519 registration keypair for this service (diff-audit L1).
    /// Generated ONCE at register time and reused on every rebuild: R's cookie
    /// registry is first-wins anti-squat, so a fresh reg_pk per rebuild would
    /// hit `CookieClaimed` against this service's own prior registration. Reusing
    /// the same reg_pk reaches the registry's same-key refresh path instead.
    pub reg_keypair: veil_crypto::GeneratedKeyPair,

    /// Establishment-confirmation flag of the CURRENT circuit (diff-audit Δ2-d):
    /// shared with the dispatcher's `OriginCircuit`, set when the terminus's
    /// `CircuitBuilt` ACK arrives. The maintenance tick re-selects a fresh relay
    /// path on rebuild if the last circuit was never confirmed (a dead hop or a
    /// pre-Δ2-d terminus) instead of rebuilding the same possibly-dead path.
    /// Replaced on every (re)build with the new circuit's flag.
    pub confirmed: std::sync::Arc<std::sync::atomic::AtomicBool>,

    /// Per-service strictly-monotonic registration freshness counter (B2).
    /// R rejects a re-registration whose epoch is not STRICTLY greater than the
    /// recorded one (M2 replay-hijack defense). The epoch used to be raw
    /// wall-clock seconds, so two rebuilds in the same second — or a clock that
    /// did not advance — produced equal epochs and the second rebuild was
    /// dropped as `StaleEpoch`, silently leaving the service on a stale circuit.
    /// On every (re)build the epoch is advanced to `max(unix_now, prev + 1)`, so
    /// it is monotonic AND still tracks wall-clock. Shared (`Arc`) so the value
    /// persists across rebuilds of this entry.
    pub registration_epoch: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl AnonymityState {
    /// Construct fresh state from operator config + a freshly-generated
    /// X25519 keypair. Caller decides which key (e.g. random, OR
    /// device-stable cached one — see `node/identity/anonymity_x25519.rs`).
    pub fn new(
        relay_capable: bool,
        advertised_bps: u32,
        x25519_sk: Arc<x25519_dalek::StaticSecret>,
        onion_service_hops: Option<usize>,
        pinned_rendezvous_relays: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            relay_capable,
            advertised_bps,
            x25519_sk,
            rendezvous_publisher_entries: Arc::new(Mutex::new(Vec::new())),
            rendezvous_resolve_cache: Arc::new(RendezvousResolveCache::new()),
            relay_reputation: Arc::new(RelayReputation::new()),
            reply_block_store: Arc::new(ReplyBlockStore::new()),
            auth_deliver_replay_cache: Arc::new(
                veil_identity::auth_deliver::AuthDeliverReplayCache::new(),
            ),
            onion_services: Arc::new(Mutex::new(Vec::new())),
            onion_service_hops,
            pinned_rendezvous_relays,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ad(receiver: u8, relay: u8, valid_from: u64, valid_until: u64) -> RendezvousAd {
        RendezvousAd {
            receiver_node_id: [receiver; 32],
            rendezvous_node_id: [relay; 32],
            auth_cookie: [relay; 16],
            receiver_x25519_pk: [3; 32],
            valid_from_unix: valid_from,
            valid_until_unix: valid_until,
            issuer_pk: String::new(),
            issuer_algo: veil_types::SignatureAlgorithm::Ed25519,
            signature: Vec::new(),
            push_envelope: Vec::new(),
            capability_token: Vec::new(),
            wake_hmac_envelope: Vec::new(),
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: Vec::new(),
            wire_version: 5,
        }
    }

    #[test]
    fn rendezvous_resolve_cache_is_short_lived_and_filters_expired_ads() {
        let receiver = [7; 32];
        let cache = RendezvousResolveCache::with_params(std::time::Duration::from_secs(60), 4);
        cache.put(receiver, vec![ad(7, 1, 90, 200), ad(7, 2, 10, 99)]);
        let got = cache.get(&receiver, 100).expect("fresh cache entry");
        assert_eq!(got.len(), 1, "signed-expired ad must be removed");
        assert_eq!(got[0].rendezvous_node_id, [1; 32]);

        let immediately_stale = RendezvousResolveCache::with_params(std::time::Duration::ZERO, 4);
        immediately_stale.put(receiver, vec![ad(7, 3, 90, 200)]);
        assert!(
            immediately_stale.get(&receiver, 100).is_none(),
            "route-cache TTL, not the ad validity window, controls re-resolution"
        );
    }

    fn rb(tag: u8) -> veil_proto::ReplyBlock {
        veil_proto::ReplyBlock {
            rendezvous_node_id: [tag; 32],
            auth_cookie: [tag; 16],
            x25519_pk: [tag; 32],
            reply_app_id: [tag; 32],
            reply_endpoint_id: tag as u32,
            receiver_node_id: [tag ^ 0xFF; 32],
        }
    }

    const OWNER: [u8; 32] = [7u8; 32];

    #[test]
    fn store_peek_is_non_consuming() {
        let s = ReplyBlockStore::new();
        let id = s.store(rb(1), OWNER, 1000);
        assert_ne!(id, 0);
        // NON-consuming (1b): repeated peeks keep returning the block (retry).
        assert_eq!(s.peek(id, OWNER, 1000), Some(rb(1)));
        assert_eq!(s.peek(id, OWNER, 1000), Some(rb(1)));
        // reply_id 0 is never valid.
        assert_eq!(s.peek(0, OWNER, 1000), None);
    }

    #[test]
    fn peek_rejects_wrong_owner_d3() {
        // diff-audit D3: a different local app cannot reply through this block.
        let s = ReplyBlockStore::new();
        let id = s.store(rb(1), OWNER, 1000);
        let other_app = [0x99u8; 32];
        assert_eq!(s.peek(id, other_app, 1000), None, "non-owner rejected");
        // The legitimate owner still resolves it.
        assert_eq!(s.peek(id, OWNER, 1000), Some(rb(1)));
    }

    #[test]
    fn store_expires_after_ttl() {
        let s = ReplyBlockStore::with_params(300, 16);
        let id = s.store(rb(2), OWNER, 1000);
        assert_eq!(s.peek(id, OWNER, 1000 + 299), Some(rb(2)));
        let id2 = s.store(rb(3), OWNER, 2000);
        assert_eq!(
            s.peek(id2, OWNER, 2000 + 300),
            None,
            "expired block is gone"
        );
    }

    #[test]
    fn store_cap_evicts_oldest() {
        let s = ReplyBlockStore::with_params(10_000, 2);
        let id1 = s.store(rb(1), OWNER, 0);
        let _id2 = s.store(rb(2), OWNER, 0);
        let _id3 = s.store(rb(3), OWNER, 0); // over cap → evicts id1
        assert_eq!(s.peek(id1, OWNER, 0), None, "oldest evicted");
    }
}
