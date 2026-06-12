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
use veil_anonymity::rendezvous::RendezvousPublisherEntry;

/// Default TTL for a stored reply block — the brick-4 freshness window.
pub const DEFAULT_REPLY_BLOCK_TTL_SECS: u64 = 300;
/// Default cap on concurrently-stored reply blocks (FIFO-evicted).
pub const DEFAULT_REPLY_BLOCK_CAP: usize = 4096;

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
    /// reply_id → (block, expiry_unix). The reply's routing (relay, cookie,
    /// receiver transport node_id) lives inside the signed `ReplyBlock` itself.
    map: std::collections::HashMap<u64, (veil_proto::ReplyBlock, u64)>,
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
                Some(&(_, exp)) if now_unix >= exp => {
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

    /// Store `block`, returning a fresh non-zero `reply_id`.
    pub fn store(&self, block: veil_proto::ReplyBlock, now_unix: u64) -> u64 {
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
        s.map
            .insert(id, (block, now_unix.saturating_add(self.ttl_secs)));
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
    pub fn peek(&self, reply_id: u64, now_unix: u64) -> Option<veil_proto::ReplyBlock> {
        if reply_id == 0 {
            return None;
        }
        let mut s = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Self::gc(&mut s, now_unix);
        let (block, exp) = s.map.get(&reply_id)?;
        if now_unix >= *exp {
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
    ) -> Self {
        Self {
            relay_capable,
            advertised_bps,
            x25519_sk,
            rendezvous_publisher_entries: Arc::new(Mutex::new(Vec::new())),
            relay_reputation: Arc::new(RelayReputation::new()),
            reply_block_store: Arc::new(ReplyBlockStore::new()),
            onion_services: Arc::new(Mutex::new(Vec::new())),
            onion_service_hops,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn store_peek_is_non_consuming() {
        let s = ReplyBlockStore::new();
        let id = s.store(rb(1), 1000);
        assert_ne!(id, 0);
        // NON-consuming (1b): repeated peeks keep returning the block (retry).
        assert_eq!(s.peek(id, 1000), Some(rb(1)));
        assert_eq!(s.peek(id, 1000), Some(rb(1)));
        // reply_id 0 is never valid.
        assert_eq!(s.peek(0, 1000), None);
    }

    #[test]
    fn store_expires_after_ttl() {
        let s = ReplyBlockStore::with_params(300, 16);
        let id = s.store(rb(2), 1000);
        assert_eq!(s.peek(id, 1000 + 299), Some(rb(2)));
        let id2 = s.store(rb(3), 2000);
        assert_eq!(s.peek(id2, 2000 + 300), None, "expired block is gone");
    }

    #[test]
    fn store_cap_evicts_oldest() {
        let s = ReplyBlockStore::with_params(10_000, 2);
        let id1 = s.store(rb(1), 0);
        let _id2 = s.store(rb(2), 0);
        let _id3 = s.store(rb(3), 0); // over cap → evicts id1
        assert_eq!(s.peek(id1, 0), None, "oldest evicted");
    }
}
