//! Per-session outbox registry.
//!
//! `SessionTxRegistry` keeps one priority-tagged sender per active session
//! (keyed by `peer_id`). Each frame is tagged with a `u8` priority level
//! (0=REALTIME … 3=BACKGROUND). The matching receiver is handed to the
//! `SessionRunner`, which feeds a `PriorityQueue` for WRR draining.
//!
//! When a session ends, `unregister` removes the sender so dead channels do
//! not accumulate.
//!
//! ## Broadcast allocation strategy
//!
//! Broadcast helpers (`send_to_all*`) accept `Arc<[u8]>` instead of `Vec<u8>`.
//! This avoids cloning the payload N times (once per active session): callers
//! pay one allocation to build the `Arc`, then each channel receive is a
//! cheap reference-count increment.
//!
//! ## Concurrency
//!
//! Outer wrapper is `Arc<RwLock<SessionTxRegistry>>`. Send-path methods
//! (`send_to`, `send_to_arc`, `send_to_all*`, `has_session`, `get_sender`
//! `total_queued`, …) take `&self` and run under the **read** lock — many
//! threads can send to different peers concurrently, bottlenecked only by
//! the underlying tokio mpsc, which is itself lock-free on the sender
//! side. Map-mutation methods (`register`, `unregister`, `evict_lru`
//! `try_register_unique`) take `&mut self` under the **write** lock and
//! serialize against everything else.
//!
//! `last_active` is `HashMap<peer_id, AtomicU64>` so the hot send path
//! updates timestamps via `Relaxed` store without taking the write lock.
//! Closed-channel cleanup is **lazy**: broadcasts detect closed mpsc but
//! cannot remove from the map under a read lock, so eviction defers to
//! the next write-lock op (`prune_closed` runs from register / unregister
//! / evict_lru). Read-path queries (`has_session`, `get_sender`
//! `peer_ids`, `active_node_ids`) filter closed channels inline so callers
//! never observe a stale entry.

use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;

use veil_cfg::NodeId;
use veil_types::NodeIdBytes;

use super::priority_queue::INTERACTIVE;

/// A priority-tagged frame: `(priority, frame_bytes)`.
///
/// `PooledShared` is a refcounted handle whose final drop returns its
/// backing buffer to the global pool's free list instead of the
/// allocator. Producers should build directly into a pooled buffer
/// (`pool.acquire(n).into_shared` — see `node/bufpool.rs`). Legacy
/// `Vec<u8>`-producing call sites bridge through
/// `veil_bufpool::pooled_shared_from_vec`, which wraps the Vec
/// without copying but bypasses pool-reuse on drop — every such bridge
/// is a missed cache-hit downstream.
pub type PriorityFrame = (u8, veil_bufpool::PooledShared);

/// Default capacity for the per-session outbound frame channel.
pub const DEFAULT_TX_QUEUE_DEPTH: usize = 4096;

/// Registry of outbound send channels, one per active session.
#[derive(Debug)]
pub struct SessionTxRegistry {
    senders: HashMap<NodeIdBytes, mpsc::Sender<PriorityFrame>>,
    /// Last send time per peer (Unix milliseconds). `AtomicU64` so the
    /// hot send path can update from `&self` under the outer read lock —
    /// LRU eviction tolerates slight staleness because the maintenance
    /// tick runs at second granularity, not millis.
    last_active: HashMap<NodeIdBytes, AtomicU64>,
    capacity: usize,
    /// Cumulative count of frames dropped because a session channel was full.
    drops_total: Arc<AtomicU64>,
}

impl Default for SessionTxRegistry {
    fn default() -> Self {
        Self {
            senders: HashMap::new(),
            last_active: HashMap::new(),
            capacity: DEFAULT_TX_QUEUE_DEPTH,
            drops_total: Arc::new(AtomicU64::new(0)),
        }
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl SessionTxRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a custom per-session channel capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            senders: HashMap::new(),
            last_active: HashMap::new(),
            capacity,
            drops_total: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Create with a custom capacity and a shared drop counter.
    ///
    /// Pass `NodeMetrics::session_tx_drops_counter` here so that drops are
    /// visible in Prometheus metrics.
    pub fn with_capacity_and_drop_counter(capacity: usize, drops_total: Arc<AtomicU64>) -> Self {
        Self {
            senders: HashMap::new(),
            last_active: HashMap::new(),
            capacity,
            drops_total,
        }
    }

    /// Prune entries whose mpsc channel is closed (peer's SessionRunner
    /// exited). Called from every `&mut self` path so stale senders
    /// don't drift indefinitely under a pure read-heavy workload.
    ///
    /// Audit batch 2026-05-24 (M4): also exposed via the public wrapper
    /// [`Self::prune_closed_external`] so periodic maintenance tasks can
    /// trigger pruning on hosts with pure broadcast workloads (mesh-hub
    /// nodes where `send_to_all*` is hot but `register()` rarely fires).
    /// Without periodic pruning, closed-channel entries accumulate
    /// indefinitely on such hosts.
    fn prune_closed(&mut self) {
        let dead: Vec<NodeIdBytes> = self
            .senders
            .iter()
            .filter_map(|(k, tx)| if tx.is_closed() { Some(*k) } else { None })
            .collect();
        for k in dead {
            self.senders.remove(&k);
            self.last_active.remove(&k);
        }
    }

    /// Public wrapper for [`Self::prune_closed`].  Returns the number
    /// of stale entries removed (for metrics / log output).  Caller must
    /// hold the outer `RwLock` write guard — that's how registry mutation
    /// is gated in the runtime.
    ///
    /// Audit batch 2026-05-24 (M4): add a periodic maintenance task in
    /// the node runtime that calls this every ~60 s so that a mesh-hub
    /// running pure-broadcast traffic never accumulates closed entries.
    pub fn prune_closed_external(&mut self) -> usize {
        let before = self.senders.len();
        self.prune_closed();
        before.saturating_sub(self.senders.len())
    }

    /// Register a new session and return its outbox receiver.
    ///
    /// The caller passes the receiver to `SessionRunner`; frames pushed into
    /// the sender (stored here) are priority-tagged and drained via WRR.
    ///
    /// The channel is bounded to `tx_queue_depth` frames; `send_to*` methods
    /// drop frames when the channel is full rather than blocking.
    pub fn register(&mut self, peer_id: impl Into<NodeId>) -> mpsc::Receiver<PriorityFrame> {
        let peer_id = *peer_id.into().as_bytes();
        self.prune_closed();
        let (tx, rx) = mpsc::channel(self.capacity);
        self.senders.insert(peer_id, tx);
        self.last_active.insert(peer_id, AtomicU64::new(now_ms()));
        rx
    }

    /// Register `peer_id` ONLY if no live session is already attached to
    /// it. Returns the new outbox receiver on success, or `None` if the
    /// peer already has a registered session.
    ///
    /// Closes the cap+dup TOCTOU race where two concurrent handshakes
    /// for the same peer both pass an `active_node_ids.contains(...)`
    /// peek and both register. The atomic check-and-insert under `&mut
    /// self` (taken via the outer `RwLock` write guard in the runtime)
    /// is the canonical commit point for "this peer has a live session";
    /// `unregister` is the canonical destroy point.
    pub fn try_register_unique(
        &mut self,
        peer_id: impl Into<NodeId>,
    ) -> Option<mpsc::Receiver<PriorityFrame>> {
        let peer_id = *peer_id.into().as_bytes();
        self.prune_closed();
        if self.senders.contains_key(&peer_id) {
            return None;
        }
        let (tx, rx) = mpsc::channel(self.capacity);
        self.senders.insert(peer_id, tx);
        self.last_active.insert(peer_id, AtomicU64::new(now_ms()));
        Some(rx)
    }

    /// Direction-aware atomic register with deterministic dedup.
    ///
    /// **Problem**: symmetric outbound dials between two peers A and B race
    /// each other.  Both sides establish handshake successfully → both
    /// receive a "duplicate" inbound mid-completion → both reject their
    /// own inbound → BOTH sides' outbounds symmetrically get killed (peer
    /// closed our outbound = our session sees EOF).  Net: 0 surviving
    /// sessions; immediate reconnect race; loop forever.
    ///
    /// **Solution**: deterministic winner-selection based on
    /// lexicographic `node_id` ordering.  Both sides agree which
    /// underlying TCP connection survives without an explicit negotiation:
    ///
    /// * Convention: pair `(A, B)` with `hex(A) < hex(B)` keeps the
    ///   `A → B` connection.  On A's side this outbound; on B's side inbound.
    /// * Each side accepts only the session that the convention favors
    ///   and rejects the symmetric-direction one BEFORE registering.
    /// * Loser-side caller is signaled to shutdown its transport.
    ///
    /// Returns:
    /// * `Some(rx)` — accepted as the canonical session.  Caller proceeds.
    /// * `None` — caller is the loser; should `shutdown()` the stream.
    pub fn try_register_directional(
        &mut self,
        peer_id: impl Into<NodeId>,
        local_node_id: &NodeIdBytes,
        new_is_outbound: bool,
    ) -> Option<mpsc::Receiver<PriorityFrame>> {
        let peer_id = *peer_id.into().as_bytes();
        self.prune_closed();

        // Determine which direction we should keep for this peer.
        // Smaller-node_id side keeps its outbound; larger keeps its inbound.
        // Both sides reach the same conclusion (lex order is total and symmetric).
        let local_is_smaller = local_node_id.as_slice() < peer_id.as_slice();
        let we_keep_outbound = local_is_smaller;
        let new_matches_policy = we_keep_outbound == new_is_outbound;

        // Policy violation: regardless of existing state, reject.
        // The peer on the other side will accept the symmetric-direction
        // session (which IS policy-compliant from their POV), and both
        // sides converge on the same surviving TCP connection.
        if !new_matches_policy {
            return None;
        }

        // Policy-compliant.  Accept iff no existing session OR existing
        // is stale (closed).  Don't replace a live policy-compliant
        // session — the first to register wins for that direction.
        if let Some(existing) = self.senders.get(&peer_id)
            && !existing.is_closed()
        {
            return None;
        }
        // Stale entry survived prune_closed (rare race) — remove + insert fresh.
        self.senders.remove(&peer_id);
        self.last_active.remove(&peer_id);

        let (tx, rx) = mpsc::channel(self.capacity);
        self.senders.insert(peer_id, tx);
        self.last_active.insert(peer_id, AtomicU64::new(now_ms()));
        Some(rx)
    }

    /// Remove the sender for `peer_id` (called when the session closes).
    pub fn unregister(&mut self, peer_id: &NodeIdBytes) {
        self.senders.remove(peer_id);
        self.last_active.remove(peer_id);
    }

    /// Get a reference to the sender channel for `peer_id`, skipping
    /// closed-channel stragglers that `prune_closed` hasn't reached yet.
    /// Without this filter the outbound-reconnect loop would observe a
    /// dead session as live and skip recovery indefinitely.
    pub fn get_sender(&self, peer_id: &NodeIdBytes) -> Option<&mpsc::Sender<PriorityFrame>> {
        self.senders.get(peer_id).filter(|s| !s.is_closed())
    }

    /// Set of node_ids with currently-registered live sessions. Used
    /// by gateway-failover to pick a gateway that has a live session.
    /// Skips closed-channel stragglers (same lazy-cleanup invariant as
    /// `get_sender`).
    pub fn active_node_ids(&self) -> std::collections::HashSet<NodeIdBytes> {
        self.senders
            .iter()
            .filter_map(|(k, tx)| if !tx.is_closed() { Some(*k) } else { None })
            .collect()
    }

    /// Cheap O(1) presence check for a single peer. Called by the
    /// outbound reconnect loop to avoid initiating a duplicate session
    /// race when an inbound session already exists. Skips closed-channel
    /// stragglers so the loop doesn't gate recovery on a dead session.
    pub fn has_session(&self, peer_id: &NodeIdBytes) -> bool {
        self.senders.get(peer_id).is_some_and(|s| !s.is_closed())
    }

    /// Send `bytes` to every registered session at `INTERACTIVE` priority.
    ///
    /// `bytes` is an `Arc<[u8]>` so the payload is shared across sessions
    /// without copying. Silently drops entries whose receiver has been closed.
    pub fn send_to_all(&self, bytes: veil_bufpool::PooledShared) {
        self.send_to_all_with_priority(INTERACTIVE, bytes);
    }

    /// Send `bytes` to every registered session at the specified priority.
    ///
    /// `&self` so concurrent broadcasts share the read lock. Frames are
    /// dropped (not the session) when a channel is full. Closed channels
    /// are skipped silently — eviction is lazy via `prune_closed` at the
    /// next write-lock op.
    pub fn send_to_all_with_priority(&self, priority: u8, bytes: veil_bufpool::PooledShared) {
        for tx in self.senders.values() {
            match tx.try_send((priority, bytes.clone())) {
                Ok(_) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.drops_total.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // Lazy cleanup — next write-lock op prunes.
                }
            }
        }
    }

    /// Send `bytes` to a specific peer at the given priority.
    ///
    /// Returns `false` if the peer is not registered, the channel is closed
    /// or the channel is full (frame is dropped on overflow).
    pub fn send_to(&self, peer_id: &NodeIdBytes, priority: u8, bytes: Vec<u8>) -> bool {
        // Bridge for legacy Vec-producing call sites — wraps without
        // copy but bypasses pool reuse on drop. Prefer `send_to_arc`
        // when the caller already holds a `PooledShared`.
        self.send_to_arc(
            peer_id,
            priority,
            veil_bufpool::pooled_shared_from_vec(bytes),
        )
    }

    /// `PooledShared`-shaped sibling [`send_to`] for fan-out call
    /// sites that already hold a shared frame buffer (gossip, mailbox
    /// replica fan-out, dispatcher relay). Avoids the `to_vec + Vec →
    /// Pool` round-trip that would allocate a fresh buffer per recipient.
    ///
    /// `&self` so concurrent sends to different peers run in parallel
    /// under the outer `RwLock` read guard; the only serialization point
    /// is the lock-free tokio mpsc per-channel.
    pub fn send_to_arc(
        &self,
        peer_id: &NodeIdBytes,
        priority: u8,
        frame: veil_bufpool::PooledShared,
    ) -> bool {
        let tx = match self.senders.get(peer_id) {
            Some(s) => s,
            None => return false,
        };
        match tx.try_send((priority, frame)) {
            Ok(_) => {
                if let Some(ts) = self.last_active.get(peer_id) {
                    ts.store(now_ms(), Ordering::Relaxed);
                }
                true
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.drops_total.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Stale entry — closed receiver. Cleanup deferred to next
                // write-lock op (prune_closed).
                false
            }
        }
    }

    /// Send `bytes` to every registered session **except** `exclude_peer` at `INTERACTIVE` priority.
    ///
    /// Used for gossip broadcasts so the originating peer does not receive its own announcement.
    pub fn send_to_all_except(
        &self,
        exclude_peer: &NodeIdBytes,
        bytes: veil_bufpool::PooledShared,
    ) {
        self.send_to_all_except_with_priority(exclude_peer, INTERACTIVE, bytes);
    }

    /// Send `bytes` to every registered session **except** `exclude_peer` at the given priority.
    ///
    /// Allows callers to explicitly classify gossip traffic (e.g. routing
    /// announcements use `BACKGROUND`; control keepalives use `REALTIME`).
    pub fn send_to_all_except_with_priority(
        &self,
        exclude_peer: &NodeIdBytes,
        priority: u8,
        bytes: veil_bufpool::PooledShared,
    ) {
        for (peer_id, tx) in self.senders.iter() {
            if peer_id == exclude_peer {
                continue;
            }
            match tx.try_send((priority, bytes.clone())) {
                Ok(_) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.drops_total.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // Lazy cleanup — next write-lock op prunes.
                }
            }
        }
    }

    /// Node-ids of all currently registered live sessions. Skips
    /// closed-channel stragglers (lazy-cleanup invariant).
    pub fn peer_ids(&self) -> Vec<NodeIdBytes> {
        self.senders
            .iter()
            .filter_map(|(k, tx)| if !tx.is_closed() { Some(*k) } else { None })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.senders.len()
    }

    pub fn is_empty(&self) -> bool {
        self.senders.is_empty()
    }

    /// Total frames currently queued across all sessions.
    ///
    /// Computed as `capacity − remaining_capacity` per channel.
    /// Used by the congestion monitor to track TX queue pressure.
    pub fn total_queued(&self) -> usize {
        self.senders
            .values()
            .map(|tx| self.capacity.saturating_sub(tx.capacity()))
            .sum()
    }

    /// Evict the `n` least-recently-active sessions to free memory.
    /// Drops the mpsc sender for the oldest sessions. Reads timestamps
    /// via `AtomicU64::load` so it observes whatever the hot send path
    /// has stored without contention. Returns the count evicted.
    pub fn evict_lru(&mut self, n: usize) -> usize {
        self.prune_closed();
        if n == 0 || self.senders.is_empty() {
            return 0;
        }
        let mut by_activity: Vec<(NodeIdBytes, u64)> = self
            .last_active
            .iter()
            .filter(|(id, _)| self.senders.contains_key(*id))
            .map(|(id, ts)| (*id, ts.load(Ordering::Relaxed)))
            .collect();
        by_activity.sort_by_key(|(_, ts)| *ts);
        let mut evicted = 0;
        for (peer_id, _) in by_activity.into_iter().take(n) {
            self.senders.remove(&peer_id);
            self.last_active.remove(&peer_id);
            evicted += 1;
        }
        evicted
    }

    /// Worst-case memory bound for capacity planning. Returns
    /// `active_sessions × capacity × AVG_FRAME_BYTES`, where
    /// `AVG_FRAME_BYTES = 16 KiB` reflects a typical encrypted IPC chunk
    /// (frame header + ChaCha20-Poly1305 ciphertext for a ~12 KiB
    /// plaintext). Real frames range from ~64 B keepalives to ~60 KiB
    /// DATA — this metric treats every slot as a peak-size frame so
    /// operators tracking RSS-budget headroom get an honest upper
    /// envelope.
    pub fn estimated_memory(&self) -> usize {
        const AVG_FRAME_BYTES: usize = 16 * 1024;
        // saturating_mul chain — defends overflow if some future code
        // grows `capacity` to a huge value.
        self.senders
            .len()
            .saturating_mul(self.capacity)
            .saturating_mul(AVG_FRAME_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_and_send() {
        let mut reg = SessionTxRegistry::new();
        let peer = [1u8; 32];
        let mut rx = reg.register(peer);

        reg.send_to_all(veil_bufpool::pooled_shared_from_vec(b"hello".to_vec()));

        let (prio, msg) = rx.recv().await.unwrap();
        assert_eq!(msg.as_ref(), b"hello");
        assert_eq!(prio, INTERACTIVE);
    }

    #[tokio::test]
    async fn closed_receiver_pruned_on_register() {
        // Broadcast under &self cannot evict closed senders inline —
        // cleanup defers to the next write-lock op (register / unregister
        // / evict_lru) via `prune_closed`. This test pins that invariant.
        let mut reg = SessionTxRegistry::new();
        let peer = [2u8; 32];
        let rx = reg.register(peer);
        drop(rx); // close the receiver
        reg.send_to_all(veil_bufpool::pooled_shared_from_vec(b"probe".to_vec())); // tolerate closed
        // Stale entry survives the read-only broadcast (lazy cleanup):
        assert_eq!(reg.len(), 1);
        // Trigger a write-lock op → prune_closed fires:
        let _rx2 = reg.register([99u8; 32]);
        assert_eq!(reg.len(), 1, "registering a fresh peer prunes [2u8;32]");
    }

    #[tokio::test]
    async fn unregister_removes_entry() {
        let mut reg = SessionTxRegistry::new();
        let peer = [3u8; 32];
        let _rx = reg.register(peer);
        assert_eq!(reg.len(), 1);
        reg.unregister(&peer);
        assert_eq!(reg.len(), 0);
    }

    /// `send_to` under `&self` updates `last_active` via atomic store;
    /// `evict_lru` (`&mut self`) observes the latest timestamp.
    #[tokio::test]
    async fn last_active_updated_by_send_under_shared_self() {
        let mut reg = SessionTxRegistry::new();
        let peer_a = [10u8; 32];
        let peer_b = [11u8; 32];
        let _rx_a = reg.register(peer_a);
        let _rx_b = reg.register(peer_b);
        // Both peers registered at ~same Instant. Send only to B —
        // its last_active bumps; A stays at register-time value.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let bytes = veil_bufpool::pooled_shared_from_vec(b"x".to_vec());
        assert!(reg.send_to_arc(&peer_b, INTERACTIVE, bytes));
        // evict_lru(1) should drop A (older last_active) not B.
        let evicted = reg.evict_lru(1);
        assert_eq!(evicted, 1);
        assert!(!reg.has_session(&peer_a), "older peer A evicted");
        assert!(reg.has_session(&peer_b), "recently-active peer B retained");
    }
}
