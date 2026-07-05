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
    // Send-path usage marks (receiver → last send-initiated resolve), feeding
    // the background refresh task: only recently-messaged receivers get
    // proactive re-walks, so an idle node adds no DHT load.
    last_send_use: Mutex<std::collections::HashMap<[u8; 32], std::time::Instant>>,
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
            last_send_use: Mutex::new(std::collections::HashMap::new()),
            ttl,
            cap: cap.max(1),
        }
    }

    /// Mark `receiver` as an active send target. Called on every SEND-path
    /// resolve, NOT on background refreshes (those must not keep themselves
    /// alive past the activity window). Bounded by `cap`, oldest-use eviction.
    pub fn note_send_use(&self, receiver: [u8; 32]) {
        let mut uses = self.last_send_use.lock().unwrap_or_else(|p| p.into_inner());
        if uses.len() >= self.cap
            && !uses.contains_key(&receiver)
            && let Some(oldest) = uses.iter().min_by_key(|(_, t)| **t).map(|(id, _)| *id)
        {
            uses.remove(&oldest);
        }
        uses.insert(receiver, std::time::Instant::now());
    }

    /// Receivers that (a) were send-resolved within `active_window` and
    /// (b) whose cache entry is missing or expires within `refresh_ahead`.
    /// These are the targets the background refresh task should re-walk NOW so
    /// the next send finds a warm cache instead of paying the synchronous DHT
    /// walk (up to its full multi-second timeout). Stale usage marks are pruned
    /// here, so a peer the app stopped messaging drops out of the refresh set
    /// after `active_window`.
    pub fn refresh_candidates(
        &self,
        active_window: std::time::Duration,
        refresh_ahead: std::time::Duration,
    ) -> Vec<[u8; 32]> {
        let active: Vec<[u8; 32]> = {
            let mut uses = self.last_send_use.lock().unwrap_or_else(|p| p.into_inner());
            uses.retain(|_, t| t.elapsed() < active_window);
            uses.keys().copied().collect()
        };
        if active.is_empty() {
            return Vec::new();
        }
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        active
            .into_iter()
            .filter(|receiver| {
                inner
                    .get(receiver)
                    .is_none_or(|entry| entry.checked_at.elapsed() + refresh_ahead >= self.ttl)
            })
            .collect()
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

impl RendezvousResolveCache {
    /// Drop a receiver's cached route so the NEXT send re-compares independent
    /// DHT replicas even inside the TTL. Used by the sender-side stall detector:
    /// repeated un-answered sends mean the cached (relay, cookie) may be a
    /// black hole (`cookie_unknown` at the relay is deliberately silent), so
    /// waiting out the TTL just re-fires into it.
    pub fn remove(&self, receiver: &[u8; 32]) {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(receiver);
    }
}

// ── Sender-side anonymous-delivery stall detector ────────────────────────────

/// Consecutive un-answered anonymous sends to one receiver before the route is
/// treated as stalled. Kept small: a healthy peer answers the very first
/// send (delivery-ACK via the attached reply block or a live frame).
pub const ANON_SEND_STALL_THRESHOLD: u32 = 3;
/// Minimum age of the oldest un-answered send before the stall verdict can
/// trip — a burst of content chunks legitimately outruns the first ACK.
pub const ANON_SEND_STALL_MIN_SECS: u64 = 8;
/// How long one stall verdict stays in force before the cache is invalidated
/// again (bounds forced re-resolves to one per window while stalled).
pub const ANON_SEND_WIDEN_SECS: u64 = 60;
/// Consecutive widen windows a peer may open WITHOUT a reply-circuit answer
/// before we GIVE UP widening it. Widening helps a FLAPPY live path (a
/// cookie_unknown race a fresh relay resolves); a path that stays silent
/// across this many windows is genuinely dead here (a DHT/registration
/// completeness wall widening cannot cross), so continuing only adds onion
/// load with no benefit — back off and let the mailbox + wake path carry
/// delivery. A reply-circuit answer at any point clears the streak.
pub const ANON_SEND_MAX_WIDEN_WINDOWS: u32 = 3;
/// Rest period after giving up: no widen, no forced re-resolve. Bounds the
/// cost on a dead path to a short burst every this often (the path may have
/// recovered by then, so we retry).
pub const ANON_SEND_DORMANT_SECS: u64 = 600;
/// Bound on tracked receivers (LRU-ish evict of the stalest entry).
const MAX_STALL_ENTRIES: usize = 512;

/// Verdict of [`AnonSendStallTracker::note_send`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StallVerdict {
    /// Widen this send's introduce fan-out with connected relay candidates —
    /// the receiver may be live-registered at a relay its resolvable ads
    /// don't name (stale ad / incomplete DHT propagation).
    pub widen: bool,
    /// Also drop the receiver's resolve-cache entry (at most once per
    /// [`ANON_SEND_WIDEN_SECS`]) so this send re-compares fresh replicas.
    pub invalidate_cache: bool,
}

#[derive(Default, Clone, Copy)]
struct StallEntry {
    unanswered: u32,
    first_unix: u64,
    widen_until: u64,
    /// Widen windows opened since the last reply-circuit answer.
    widen_windows: u32,
    /// While > now, the peer is in the give-up rest period: no widen, no
    /// forced re-resolve (see [`ANON_SEND_DORMANT_SECS`]).
    dormant_until: u64,
}

/// Detects the "sender keeps introducing into a black hole" failure the
/// fire-and-forget introduce path cannot see directly: the relay drops an
/// introduce whose (receiver, cookie) has no live registration WITHOUT any
/// signal to the sender (`cookie_unknown` is silent by design — surfacing it
/// would leak subscriber sets to probes). The only sender-observable truth is
/// the ABSENCE of any verified inbound from that receiver while our sends to
/// it pile up — their delivery-ACKs, replies and re-requests all arrive as
/// verified `AuthAppDeliver`s. Tracked per receiver; a verified inbound clears
/// the streak ([`note_answer`], hooked into the auth-deliver verify task).
pub struct AnonSendStallTracker {
    inner: Mutex<std::collections::HashMap<[u8; 32], StallEntry>>,
}

impl AnonSendStallTracker {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Record one more anonymous send toward `receiver` and judge the route.
    pub fn note_send(&self, receiver: [u8; 32], now_unix: u64) -> StallVerdict {
        let mut m = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if m.len() >= MAX_STALL_ENTRIES
            && !m.contains_key(&receiver)
            && let Some(stalest) = m
                .iter()
                .min_by_key(|(_, e)| e.first_unix)
                .map(|(id, _)| *id)
        {
            m.remove(&stalest);
        }
        let e = m.entry(receiver).or_default();
        // Gave up on this peer recently — rest (no widen) so a genuinely-dead
        // live path doesn't keep loading the node. Still count the send so the
        // streak is warm when the rest period ends.
        if e.dormant_until > now_unix {
            if e.unanswered == 0 {
                e.first_unix = now_unix;
            }
            e.unanswered = e.unanswered.saturating_add(1);
            // Bounded RESOLVE PROBE while dormant (one cache invalidate per
            // [`ANON_SEND_WIDEN_SECS`], no widen): a receiver that comes BACK
            // republishes its ad within seconds, but a fully-suppressed rest
            // period kept introducing into the DEAD cached route for up to
            // [`ANON_SEND_DORMANT_SECS`] — observed as minutes of silent
            // drops AFTER the receiver had recovered. The probe re-compares
            // fresh replicas; a live receiver's route then heals on the very
            // next send (and its answer dissolves the streak), while a
            // still-dead peer costs one DHT resolve per window instead of
            // widened onion bursts. `widen_until` is dead state inside
            // dormant (peek gates widen on `dormant_until <= now`), so it is
            // reused as the probe timer.
            let probe = e.widen_until <= now_unix;
            if probe {
                e.widen_until = now_unix + ANON_SEND_WIDEN_SECS;
            }
            return StallVerdict {
                widen: false,
                invalidate_cache: probe,
            };
        }
        if e.dormant_until != 0 {
            // Dormant just expired — clear it AND the probe timer that
            // borrowed `widen_until`, so a leftover probe deadline can't
            // masquerade as an active widen window.
            e.dormant_until = 0;
            e.widen_until = 0;
        }
        if e.unanswered == 0 {
            e.first_unix = now_unix;
        }
        e.unanswered = e.unanswered.saturating_add(1);
        if e.widen_until > now_unix {
            // Already stalled this window: keep widening, no fresh invalidate.
            return StallVerdict {
                widen: true,
                invalidate_cache: false,
            };
        }
        if e.unanswered >= ANON_SEND_STALL_THRESHOLD
            && now_unix.saturating_sub(e.first_unix) >= ANON_SEND_STALL_MIN_SECS
        {
            e.widen_windows = e.widen_windows.saturating_add(1);
            if e.widen_windows > ANON_SEND_MAX_WIDEN_WINDOWS {
                // Widened this many windows and still no reply-circuit answer —
                // the live path is dead here, not flappy. Back off: the mailbox
                // + wake path carries delivery without loading the node.
                e.dormant_until = now_unix + ANON_SEND_DORMANT_SECS;
                e.widen_windows = 0;
                e.widen_until = 0;
                e.unanswered = 0;
                return StallVerdict {
                    widen: false,
                    invalidate_cache: false,
                };
            }
            e.widen_until = now_unix + ANON_SEND_WIDEN_SECS;
            return StallVerdict {
                widen: true,
                invalidate_cache: true,
            };
        }
        StallVerdict {
            widen: false,
            invalidate_cache: false,
        }
    }

    /// Read the CURRENT verdict for `receiver` without recording a send.
    /// Used by sends that attach NO reply block (sync beacons, acks, content
    /// chunks): the peer is not expected to answer those promptly, so counting
    /// them as "unanswered" made a quiet-but-healthy route look stalled (a
    /// beacon every ~20s re-tripped the verdict on a fixed cadence forever).
    /// They still RIDE an active widen window — only reply-expecting sends
    /// drive the accounting, because their delivery-ACK returns over the
    /// sender's own reply circuit and is therefore a true me→R health probe.
    pub fn peek(&self, receiver: &[u8; 32], now_unix: u64) -> StallVerdict {
        let m = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        StallVerdict {
            // `dormant_until == 0` (never dormant, or cleared by the first
            // post-dormant `note_send`): while a dormant stamp is present —
            // active OR just expired — `widen_until` may be the borrowed
            // resolve-probe deadline, not a widen window.
            widen: m
                .get(receiver)
                .is_some_and(|e| e.dormant_until == 0 && e.widen_until > now_unix),
            invalidate_cache: false,
        }
    }

    /// A VERIFIED inbound from `sender` proves the route from them works (and
    /// their ACKs are how our own sends are answered) — clear their streak.
    pub fn note_answer(&self, sender: &[u8; 32]) {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(sender);
    }
}

impl Default for AnonSendStallTracker {
    fn default() -> Self {
        Self::new()
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

    /// Single-flight guard for cold relay-directory warming on stream circuit
    /// open. A file download can start several parallel stream workers; without
    /// coalescing, each worker probes the same relay-directory DHT keys at once
    /// and legitimate traffic can trip recursive-query abuse limits.
    pub stream_relay_directory_warm_lock: Arc<tokio::sync::Mutex<()>>,

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

    /// Sender-side anonymous-delivery stall detector (see
    /// [`AnonSendStallTracker`]): trips a forced re-resolve + widened introduce
    /// fan-out when repeated sends to a receiver draw no verified inbound.
    /// Short-term memory only; resetting on config reload is acceptable.
    pub send_stall: Arc<AnonSendStallTracker>,
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
            stream_relay_directory_warm_lock: Arc::new(tokio::sync::Mutex::new(())),
            relay_reputation: Arc::new(RelayReputation::new()),
            reply_block_store: Arc::new(ReplyBlockStore::new()),
            auth_deliver_replay_cache: Arc::new(
                veil_identity::auth_deliver::AuthDeliverReplayCache::new(),
            ),
            onion_services: Arc::new(Mutex::new(Vec::new())),
            onion_service_hops,
            pinned_rendezvous_relays,
            send_stall: Arc::new(AnonSendStallTracker::new()),
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

    #[test]
    fn refresh_candidates_only_active_and_near_expiry() {
        let cache = RendezvousResolveCache::with_params(std::time::Duration::from_secs(60), 4);
        let window = std::time::Duration::from_secs(300);
        let margin = std::time::Duration::from_secs(6);
        let receiver = [7; 32];

        // Never send-resolved → not a candidate even with an empty cache.
        assert!(cache.refresh_candidates(window, margin).is_empty());

        // Active but no cache entry → immediate candidate (first walk failed
        // or entry got invalidated — the refresher should retry).
        cache.note_send_use(receiver);
        assert_eq!(cache.refresh_candidates(window, margin), vec![receiver]);

        // Fresh entry well inside TTL−margin → nothing to do.
        cache.put(receiver, vec![ad(7, 1, 90, 200)]);
        assert!(cache.refresh_candidates(window, margin).is_empty());

        // Entry aged past TTL−margin → candidate again. Model by shrinking
        // the margin window instead of sleeping: margin ≥ ttl makes any
        // entry age qualify.
        assert_eq!(
            cache.refresh_candidates(window, std::time::Duration::from_secs(60)),
            vec![receiver],
            "entry expiring within the refresh-ahead margin must re-walk"
        );

        // Activity window elapsed → receiver drains out of the proactive set
        // (zero idle DHT load). ZERO window drops every mark.
        assert!(
            cache
                .refresh_candidates(std::time::Duration::ZERO, std::time::Duration::from_secs(60))
                .is_empty(),
            "inactive receivers must not be refreshed"
        );
        // ...and stays drained on the next normal-window call (marks pruned).
        assert!(
            cache
                .refresh_candidates(window, std::time::Duration::from_secs(60))
                .is_empty()
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

    #[test]
    fn stall_tracker_trips_after_threshold_and_min_age() {
        let t = AnonSendStallTracker::new();
        let r = [7u8; 32];
        // Two quick sends: below the count threshold.
        assert!(!t.note_send(r, 100).widen);
        assert!(!t.note_send(r, 101).widen);
        // Third send but still inside the min-age window: not yet.
        assert!(!t.note_send(r, 102).widen);
        // Past the min age with the streak intact: trips, invalidates once.
        let v = t.note_send(r, 100 + ANON_SEND_STALL_MIN_SECS);
        assert!(v.widen && v.invalidate_cache);
        // Subsequent sends inside the window keep widening WITHOUT another
        // cache invalidation (bounds forced re-resolves).
        let v2 = t.note_send(r, 101 + ANON_SEND_STALL_MIN_SECS);
        assert!(v2.widen && !v2.invalidate_cache);
        // After the widen window lapses and the streak persists, it re-trips
        // with a fresh invalidation.
        let v3 = t.note_send(r, 102 + ANON_SEND_STALL_MIN_SECS + ANON_SEND_WIDEN_SECS);
        assert!(v3.widen && v3.invalidate_cache);
    }

    #[test]
    fn stall_tracker_clears_on_verified_answer() {
        let t = AnonSendStallTracker::new();
        let r = [8u8; 32];
        for i in 0..5 {
            t.note_send(r, 100 + i);
        }
        assert!(t.note_send(r, 100 + ANON_SEND_STALL_MIN_SECS + 5).widen);
        // A verified inbound from the peer resets everything.
        t.note_answer(&r);
        assert!(!t.note_send(r, 200 + ANON_SEND_STALL_MIN_SECS).widen);
    }

    #[test]
    fn stall_tracker_gives_up_after_max_widen_windows() {
        let t = AnonSendStallTracker::new();
        let r = [11u8; 32];
        // Drive one widen window per WIDEN_SECS with no reply-circuit answer.
        // The first ANON_SEND_MAX_WIDEN_WINDOWS windows widen; the next one
        // gives up (dormant), so widen goes false.
        let mut now = 100u64;
        // Prime the streak past threshold + min-age so the first note_send trips.
        t.note_send(r, now);
        t.note_send(r, now + 1);
        now += ANON_SEND_STALL_MIN_SECS;
        let mut widened = 0;
        let mut gave_up = false;
        for _ in 0..(ANON_SEND_MAX_WIDEN_WINDOWS + 2) {
            let v = t.note_send(r, now);
            if v.widen {
                widened += 1;
            } else {
                gave_up = true;
                break;
            }
            now += ANON_SEND_WIDEN_SECS + 1; // advance to the next window
        }
        assert_eq!(widened, ANON_SEND_MAX_WIDEN_WINDOWS);
        assert!(gave_up, "must stop widening after the window cap");
        // During the rest period peek does NOT widen even though a stale
        // widen_until might linger.
        assert!(!t.peek(&r, now).widen);
        // A reply-circuit answer clears the give-up state — widening can resume.
        t.note_answer(&r);
        t.note_send(r, now);
        t.note_send(r, now + 1);
        let v = t.note_send(r, now + ANON_SEND_STALL_MIN_SECS);
        assert!(v.widen, "a reply-circuit answer must re-enable widening");
    }

    #[test]
    fn stall_tracker_peek_reads_without_counting() {
        let t = AnonSendStallTracker::new();
        let r = [10u8; 32];
        // Any number of reply-less sends must never trip the verdict on their
        // own (a sync beacon every ~20s is legitimately unanswered).
        for i in 0..50 {
            assert!(!t.peek(&r, 100 + i).widen);
        }
        // Reply-expecting sends drive the accounting as before…
        for i in 0..3 {
            t.note_send(r, 200 + i);
        }
        assert!(t.note_send(r, 200 + ANON_SEND_STALL_MIN_SECS).widen);
        // …and once tripped, reply-less sends RIDE the widen window via peek.
        let v = t.peek(&r, 201 + ANON_SEND_STALL_MIN_SECS);
        assert!(v.widen && !v.invalidate_cache);
        // After the window lapses with no further reply-expecting sends, peek
        // returns to normal (no self-re-tripping).
        assert!(
            !t.peek(&r, 200 + ANON_SEND_STALL_MIN_SECS + ANON_SEND_WIDEN_SECS + 1)
                .widen
        );
    }

    #[test]
    fn stall_tracker_dormant_probes_resolve_once_per_window() {
        let t = AnonSendStallTracker::new();
        let r = [12u8; 32];
        // Drive into dormant: prime + exhaust the widen-window cap.
        let mut now = 100u64;
        t.note_send(r, now);
        t.note_send(r, now + 1);
        now += ANON_SEND_STALL_MIN_SECS;
        for _ in 0..=ANON_SEND_MAX_WIDEN_WINDOWS {
            t.note_send(r, now);
            now += ANON_SEND_WIDEN_SECS + 1;
        }
        // We are dormant. The FIRST dormant send probes (cache invalidate, so
        // the next send re-compares fresh replicas — a receiver that came back
        // republishes within seconds and the route heals immediately) but
        // never widens.
        let v = t.note_send(r, now);
        assert!(!v.widen && v.invalidate_cache, "first dormant send probes");
        // Further sends inside the same probe window stay fully quiet.
        let v = t.note_send(r, now + 1);
        assert!(!v.widen && !v.invalidate_cache);
        let v = t.note_send(r, now + ANON_SEND_WIDEN_SECS - 1);
        assert!(!v.widen && !v.invalidate_cache);
        // Next window → next probe. Bounded: one resolve per window, not one
        // per send.
        let v = t.note_send(r, now + ANON_SEND_WIDEN_SECS + 1);
        assert!(!v.widen && v.invalidate_cache, "one probe per window");
        // peek during dormant must not mistake the borrowed probe timer for an
        // active widen window.
        assert!(!t.peek(&r, now + ANON_SEND_WIDEN_SECS + 2).widen);
        // After dormant expires, the leftover probe deadline must not
        // masquerade as a widen window for reply-LESS sends (peek).
        let after = now + ANON_SEND_DORMANT_SECS + 1;
        assert!(!t.peek(&r, after).widen);
        // The dormant-counted streak is deliberately kept WARM: the first
        // reply-expecting send after the rest period trips a fresh widen
        // window immediately (with a fresh re-resolve), instead of waiting
        // out threshold + min-age again.
        let v = t.note_send(r, after);
        assert!(
            v.widen && v.invalidate_cache,
            "post-dormant send retries promptly on a warm streak"
        );
    }

    #[test]
    fn resolve_cache_remove_forces_refresh() {
        let c = RendezvousResolveCache::new();
        let r = [9u8; 32];
        c.put(r, vec![ad(9, 1, 0, 100)]);
        assert!(c.get(&r, 50).is_some());
        c.remove(&r);
        assert!(c.get(&r, 50).is_none(), "removed entry must not serve");
    }
}
