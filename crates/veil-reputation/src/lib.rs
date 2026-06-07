//! Per-identity reputation tracking.
//!
//! Each node maintains a local reputation score for every counterparty
//! it has interacted with. The score accumulates:
//!
//! **Uptime** — seconds the counterparty has maintained a continuous session.
//! **Successful relays** — DELIVERY_FORWARD frames that were relayed and
//! eventually delivered (confirmed by delivery ACK or lack of NACK).
//! *(Vouching removed — premature without DHT gossip integration.)*
//!
//! # Identity-keyed
//!
//! The tracker keys reputation on the counterparty's sovereign
//! `node_id` rather than the session-layer `node_id` (which is the
//! per-device keypair-derived address). This means:
//!
//! **Survives key rotation** — when a peer rotates its `identity_sk`
//! their `node_id` stays the same (it's `BLAKE3(master_pubkey)`)
//! so reputation earned pre-rotation carries through.
//! **Shared across instances** — two devices of the same sovereign
//! identity (laptop + phone) accrue reputation against the SAME
//! ledger; routing decisions for `Recipient::Any` / `::All` see the
//! total identity-level score.
//!
//! Legacy (non-sovereign) peers don't have a validated node_id;
//! callers fall back to the session-layer `node_id` as a degenerate
//! identifier in that case so the behaviour is unchanged for the
//! legacy plane.
//!
//! # Sybil cost
//!
//! A node must accumulate `MIN_REPUTATION_FOR_TRANSIT` before it can serve
//! as a transit relay for RecursiveRelay frames. This prevents freshly-minted
//! Sybil nodes from immediately participating in the data plane. The
//! cost-per-Sybil-identity scales with the per-identity PoW required by
//! `IdentityDocument` provisioning (`DEFAULT_POW_DIFFICULTY`), so an
//! attacker mints a new sovereign identity for every fresh reputation
//! ledger they want — not just a new keypair.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use veil_cfg::NodeId;
use veil_types::NodeIdBytes;

/// Minimum reputation score required to serve as a transit relay.
///
/// Approximately: 100 hours uptime × 1 point/hour + 1000 successful relays × 0.1 points each.
/// ≈ 200 points. A legitimate node accumulates this in ~4 days of normal operation.
pub const MIN_REPUTATION_FOR_TRANSIT: f64 = 200.0;

/// Reputation weights for different contribution types.
const UPTIME_WEIGHT_PER_HOUR: f64 = 1.0;
const RELAY_SUCCESS_WEIGHT: f64 = 0.1;

/// Per-peer reputation entry.
#[derive(Debug, Clone)]
pub struct PeerReputation {
    /// Cumulative uptime in seconds observed from this peer.
    pub uptime_secs: u64,
    /// Number of successfully relayed frames attributed to this peer.
    pub successful_relays: u64,
    /// When the current session started (for uptime accumulation).
    session_start: Option<Instant>,
    /// Last time this entry was updated.
    pub last_updated: Instant,
}

impl PeerReputation {
    fn new() -> Self {
        Self {
            uptime_secs: 0,
            successful_relays: 0,
            session_start: None,
            last_updated: Instant::now(),
        }
    }

    /// Composite reputation score.
    pub fn score(&self) -> f64 {
        let uptime_hours = self.uptime_secs as f64 / 3600.0;
        uptime_hours * UPTIME_WEIGHT_PER_HOUR + self.successful_relays as f64 * RELAY_SUCCESS_WEIGHT
    }

    /// Whether this peer meets the minimum transit reputation threshold.
    pub fn can_transit(&self) -> bool {
        self.score() >= MIN_REPUTATION_FOR_TRANSIT
    }
}

/// Reputation tracker for all known identities.
///
/// keyed on sovereign `node_id` (or, for legacy
/// peers, the session-layer `node_id` as a fall-back). Thread-safe
/// via external `Mutex` wrapping (matches the pattern used by other
/// veil caches like `peer_pubkeys`, `peer_roles`).
#[derive(Debug)]
pub struct ReputationTracker {
    /// Maps `node_id` (or legacy `node_id`) → ledger. The
    /// 32-byte key was previously `peer_id` (session-layer); the
    /// shape stayed identical across the migration so the on-wire
    /// type signatures didn't churn.
    by_identity: HashMap<NodeIdBytes, PeerReputation>,
    max_entries: usize,
}

const DEFAULT_MAX_ENTRIES: usize = 65_536;

impl ReputationTracker {
    pub fn new() -> Self {
        Self {
            by_identity: HashMap::new(),
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }

    /// Notify that a session with `node_id` has been opened.
    /// Caller maps session-layer `peer_id` →
    /// `SessionRegistry::node_id_for_peer` first; legacy peers
    /// pass through their `peer_id` as the degenerate identity.
    pub fn session_opened(&mut self, node_id: NodeId) {
        let entry = self.get_or_create(*node_id.as_bytes());
        entry.session_start = Some(Instant::now());
        entry.last_updated = Instant::now();
    }

    /// Notify that a session with `node_id` has been closed.
    /// Accumulates the uptime from session start to now.
    pub fn session_closed(&mut self, node_id: NodeId) {
        if let Some(entry) = self.by_identity.get_mut(node_id.as_bytes()) {
            if let Some(start) = entry.session_start.take() {
                entry.uptime_secs += start.elapsed().as_secs();
            }
            entry.last_updated = Instant::now();
        }
    }

    /// Record a successful relay forwarding by `node_id`.
    pub fn record_relay_success(&mut self, node_id: NodeId) {
        let entry = self.get_or_create(*node_id.as_bytes());
        entry.successful_relays += 1;
        entry.last_updated = Instant::now();
    }

    /// Get the reputation score for an identity (0.0 if unknown).
    pub fn score(&self, node_id: &NodeId) -> f64 {
        self.by_identity
            .get(node_id.as_bytes())
            .map(|e| e.score())
            .unwrap_or(0.0)
    }

    /// Whether an identity meets the transit threshold.
    pub fn can_transit(&self, node_id: &NodeId) -> bool {
        self.by_identity
            .get(node_id.as_bytes())
            .is_some_and(|e| e.can_transit())
    }

    /// Remove entries whose `last_updated` is older than `stale_threshold`
    /// from the current instant. Called periodically by the runtime cleanup
    /// task so that long-idle identities free their slot —
    /// without this, the LRU cap only triggers when a new identity arrives
    /// leaving 65K stale entries occupying slots on low-churn nodes.
    ///
    /// Returns the number of evicted entries.
    pub fn evict_stale(&mut self, stale_threshold: Duration) -> usize {
        let cutoff = Instant::now().checked_sub(stale_threshold);
        let Some(cutoff) = cutoff else { return 0 };
        let before = self.by_identity.len();
        // Never evict an entry that still has an open session — uptime would
        // be lost. `session_start.is_some` ⇔ session currently open.
        self.by_identity
            .retain(|_, e| e.session_start.is_some() || e.last_updated >= cutoff);
        before - self.by_identity.len()
    }

    /// Number of tracked identities.
    pub fn len(&self) -> usize {
        self.by_identity.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_identity.is_empty()
    }

    fn get_or_create(&mut self, node_id: [u8; 32]) -> &mut PeerReputation {
        if !self.by_identity.contains_key(&node_id) {
            // Evict the least-recently-updated entry if at capacity. Skip
            // entries with an OPEN session (`session_start.is_some()`) — evicting
            // those mid-session would lose their accumulated uptime/score, the
            // same invariant `evict_stale` upholds.
            //
            // NOTE (perf, accepted): this is an O(n) scan that fires only when a
            // NEW identity arrives at capacity. Reachability is gated by OVL1
            // session establishment (PoW-bound), not free packet spam, so the
            // amplification is bounded — unlike the rate-limiter maps that were
            // migrated to O(log n) BTreeSet indices. A correct index here would
            // have to sync `last_updated` across every caller mutation site, so
            // it's deferred rather than risked.
            if self.by_identity.len() >= self.max_entries {
                let oldest = self
                    .by_identity
                    .iter()
                    .filter(|(_, e)| e.session_start.is_none())
                    .min_by_key(|(_, e)| e.last_updated)
                    .map(|(k, _)| *k);
                if let Some(k) = oldest {
                    self.by_identity.remove(&k);
                }
            }
        }
        self.by_identity
            .entry(node_id)
            .or_insert_with(PeerReputation::new)
    }
}

impl Default for ReputationTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_peer_has_zero_score() {
        let rt = ReputationTracker::new();
        let nid: NodeId = [1u8; 32].into();
        assert_eq!(rt.score(&nid), 0.0);
        assert!(!rt.can_transit(&nid));
    }

    #[test]
    fn relay_success_accumulates() {
        let mut rt = ReputationTracker::new();
        let peer: NodeId = [2u8; 32].into();
        for _ in 0..2000 {
            rt.record_relay_success(peer);
        }
        // 2000 × 0.1 = 200.0
        assert_eq!(rt.score(&peer), 200.0);
        assert!(rt.can_transit(&peer));
    }

    #[test]
    fn session_uptime_accumulates() {
        let mut rt = ReputationTracker::new();
        let peer: NodeId = [4u8; 32].into();
        rt.session_opened(peer);
        // Simulate passage of time by manipulating the entry directly.
        rt.by_identity.get_mut(peer.as_bytes()).unwrap().uptime_secs = 360_000; // 100 hours
        assert!((rt.score(&peer) - 100.0).abs() < 0.1);
    }

    #[test]
    fn eviction_at_capacity() {
        let mut rt = ReputationTracker {
            by_identity: HashMap::new(),
            max_entries: 2,
        };
        rt.record_relay_success(NodeId::from([1u8; 32]));
        rt.record_relay_success(NodeId::from([2u8; 32]));
        rt.record_relay_success(NodeId::from([3u8; 32])); // should evict [1] or [2]
        assert_eq!(rt.len(), 2);
    }

    /// headline invariant: reputation is keyed on the
    /// sovereign `node_id`, NOT the per-device `peer_id`. When
    /// a peer rotates its `identity_sk` the per-device session
    /// keypair (and thus `peer_id`) changes but the
    /// master-derived `node_id` is stable, so the reputation
    /// ledger carries through the rotation. Verified directly
    /// here at the tracker layer (the runtime callers map peer_id
    /// → node_id via `SessionRegistry::node_id_for_peer`).
    #[test]
    fn reputation_survives_peer_id_rotation_under_stable_identity() {
        let mut rt = ReputationTracker::new();
        let alice_identity: NodeId = [0xAA; 32].into();

        // Alice racks up 200 relay successes under her stable
        // node_id (worth 20 reputation points).
        for _ in 0..200 {
            rt.record_relay_success(alice_identity);
        }
        assert_eq!(rt.score(&alice_identity), 20.0);

        // Alice rotates her identity_sk — her peer_id changes
        // (would be a different bytes value at the session
        // layer) but the node_id she's known by stays the
        // same. More relay credit accumulates onto the SAME
        // ledger.
        for _ in 0..200 {
            rt.record_relay_success(alice_identity);
        }
        assert_eq!(
            rt.score(&alice_identity),
            40.0,
            "post-rotation relay credits accrue to the same identity ledger",
        );

        // A different identity (carol) has its own ledger —
        // sanity check we didn't accidentally collapse all
        // identities into one.
        let carol_identity: NodeId = [0xCC; 32].into();
        rt.record_relay_success(carol_identity);
        assert_eq!(rt.score(&carol_identity), 0.1);
        assert_eq!(rt.score(&alice_identity), 40.0);

        // Two devices of one identity (laptop + phone) share the
        // ledger by construction — each device's record_relay_success
        // call uses the SAME node_id, so they add to one
        // counter rather than two.
        let bob_identity: NodeId = [0xBB; 32].into();
        // Bob's laptop earns 100 successes:
        for _ in 0..100 {
            rt.record_relay_success(bob_identity);
        }
        // Bob's phone earns another 100 — same ledger:
        for _ in 0..100 {
            rt.record_relay_success(bob_identity);
        }
        assert_eq!(
            rt.score(&bob_identity),
            20.0,
            "multi-device reputation must combine on the node_id ledger",
        );
    }

    #[test]
    fn evict_stale_removes_idle_closed_entries_and_keeps_active() {
        let mut rt = ReputationTracker::new();
        let idle: NodeId = [1u8; 32].into();
        let active: NodeId = [2u8; 32].into();

        // Create two entries, then backdate their last_updated. Use
        // `checked_sub` so the test doesn't panic on platforms where `Instant`
        // is rooted at boot (Windows) and uptime may be < 1 hour. We only
        // need the entry to be ≥ 60 s old (the eviction threshold).
        rt.record_relay_success(idle);
        rt.record_relay_success(active);
        let long_ago = Instant::now()
            .checked_sub(Duration::from_secs(3600))
            .or_else(|| Instant::now().checked_sub(Duration::from_secs(120)))
            .expect("test host uptime must be >= 2 minutes");
        rt.by_identity
            .get_mut(idle.as_bytes())
            .unwrap()
            .last_updated = long_ago;
        rt.by_identity
            .get_mut(active.as_bytes())
            .unwrap()
            .last_updated = long_ago;
        // Mark active as having an open session.
        rt.by_identity
            .get_mut(active.as_bytes())
            .unwrap()
            .session_start = Some(Instant::now());

        let evicted = rt.evict_stale(Duration::from_secs(60));
        assert_eq!(evicted, 1, "idle entry should be evicted");
        assert_eq!(rt.len(), 1);
        assert!(
            rt.by_identity.contains_key(active.as_bytes()),
            "active session must never be evicted"
        );
    }

    #[test]
    fn evict_stale_keeps_fresh_entries() {
        let mut rt = ReputationTracker::new();
        rt.record_relay_success([7u8; 32].into());
        // last_updated = now; threshold 60s → fresh entry stays.
        let evicted = rt.evict_stale(Duration::from_secs(60));
        assert_eq!(evicted, 0);
        assert_eq!(rt.len(), 1);
    }
}
