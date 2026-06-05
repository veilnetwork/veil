//! decomposition PR1: anonymity-related runtime state
//! extracted into а dedicated [`Arc<AnonymityState>`].
//!
//! ## Why а dedicated struct
//!
//! `NodeRuntime` previously held four anonymity-related fields directly
//! (`anonymity_relay_capable`, `anonymity_advertised_bps`
//! `anonymity_x25519_sk`, `rendezvous_publisher_entries`). Lock-order
//! across the runtime's >15 lockable fields was documented at
//! `node/runtime/mod.rs:4488-4499` but enforced only by review.
//! Lifting domain-grouped state into [`Arc<DomainState>`] structs
//! makes cross-domain ordering impossible-by-construction (each domain
//! owns its own locks; no shared parent lock к acquire in а wrong order).
//!
//! ## Migration surface
//!
//! Each method that used to read `self.anonymity_*` now reads
//! `self.anonymity.*` — а pure rename refactor (no behaviour change).
//! Mutation of `relay_capable` and `advertised_bps` happens only via
//! `reload`, which atomically swaps the `Arc<AnonymityState>` on the
//! parent runtime; in-flight handshakes/maintenance ticks holding а
//! pre-reload `Arc` continue с their snapshot until they next refresh
//! which matches existing semantics (the old direct fields were also
//! read-once per loop iteration).

use std::sync::{Arc, Mutex};

use veil_anonymity::rendezvous::RendezvousPublisherEntry;

/// Anonymity-domain state owned by [`NodeRuntime`] and shared as
/// `Arc<AnonymityState>` with maintenance tasks, dispatcher seed, и
/// per-session contexts.
///
/// finish: visibility lifted к `pub` (was `pub`)
/// so `NodeRuntime::anonymity: Arc<AnonymityState>` can carry the type
/// across module boundaries without the `private_interfaces` warning.
pub struct AnonymityState {
    /// cached snapshot of `cfg.anonymity.relay_capable`.
    /// Read at every handshake к set the `ANONYMITY_RELAY` capability
    /// flag. Cached (vs. read from disk per-handshake) к keep the
    /// handshake hot-path cheap; updated on `reload` via а fresh
    /// `Arc<AnonymityState>`.
    pub relay_capable: bool,

    /// cached `advertised_bps` для the relay-directory
    /// entry we periodically publish to DHT. Self-reported
    /// UNVERIFIED. Updated on `reload`.
    pub advertised_bps: u32,

    /// X25519 secret key the node uses для anonymity-hop
    /// ECDH inside [`veil_anonymity::onion::unwrap_at_hop`].
    /// Distinct от the OVL1 session ECDH (fresh ephemeral keypairs per
    /// session) — anonymity hops need а stable pubkey the relay-
    /// directory entry can advertise. Generated fresh at startup;
    /// rotates on restart, which is fine because directory entries are
    /// freshness-bounded (24 h default). Stored in-memory only; no
    /// on-disk persistence (compromise of the disk → loss of past
    /// anonymity, which is the point of forward-secret rotation).
    pub x25519_sk: Arc<x25519_dalek::StaticSecret>,

    /// rendezvous-publisher state. Receivers add
    /// entries via `register_rendezvous_publisher`; the maintenance
    /// tick re-signs + re-stores each `RendezvousAd` к the DHT before
    /// its `valid_until` lapses (half-life refresh). Empty by
    /// default — only receivers that explicitly opt in к
    /// rendezvous-routed inbound delivery touch this.
    pub rendezvous_publisher_entries: Arc<Mutex<Vec<RendezvousPublisherEntry>>>,
}

impl AnonymityState {
    /// Construct fresh state from operator config + а freshly-generated
    /// X25519 keypair. Caller decides which key (e.g. random, OR
    /// device-stable cached one — see `node/identity/anonymity_x25519.rs`).
    pub fn new(
        relay_capable: bool,
        advertised_bps: u32,
        x25519_sk: Arc<x25519_dalek::StaticSecret>,
    ) -> Self {
        Self {
            relay_capable,
            advertised_bps,
            x25519_sk,
            rendezvous_publisher_entries: Arc::new(Mutex::new(Vec::new())),
        }
    }
}
