//! decomposition : bounded-capacity table tracking
//! in-flight RPC request_id → oneshot::Sender so the runner can match
//! incoming response frames to the originating waiter.
//!
//! Was three duplicated inline blocks in `SessionRunner::run`:
//! * the `rpc_outbox` try_recv drain loop (TTL evict + capacity evict + dedupe + insert)
//! * the `NextInput::RpcRequest` select-arm (TTL evict + capacity evict + dedupe + insert)
//! * the `NextInput::Timer` arm (TTL evict only, for quiet-period housekeeping)
//!
//! Plus the take-on-receipt block in the response-matching path (line ~2577 pre-extraction).
//!
//! **Capacity-evict on both insert paths:** both the drain-loop and the
//! `RpcRequest` select-arm call `evict_oldest_if_at_capacity` before insert,
//! so single-at-a-time arrivals via select! can't transiently push the table
//! past `capacity` (the earlier asymmetry where only the drain loop checked).
//!
//! Invariant: `table.len == deadline_index.len` at all times.
//! Every code path that mutates one of the two backing collections
//! mutates the other in the same call. External callers see only the
//! struct's methods; the internal collections are private.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::Instant;

/// One pending entry: timestamp (used as deadline-index key and for TTL
/// arithmetic) plus the oneshot sender that the runner fulfils when
/// the matching response frame arrives. When a pending entry is
/// evicted (TTL expiry, capacity overflow, dedupe replacement), the
/// sender receives `None` so the awaiting caller can return a
/// well-defined "no response" rather than block forever.
pub type PendingEntry = (Instant, oneshot::Sender<Option<Vec<u8>>>);

pub struct PendingResponseTable {
    table: HashMap<u32, PendingEntry>,
    /// Deadline-ordered index of `(inserted_at, request_id)` —
    /// composite key to survive same-Instant collisions when two
    /// requests are inserted within a single tokio::time tick.
    /// Provides O(log n) front-eviction by deadline.
    deadline_index: BTreeMap<(Instant, u32), ()>,
    capacity: usize,
    ttl: Duration,
}

impl PendingResponseTable {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            table: HashMap::new(),
            deadline_index: BTreeMap::new(),
            capacity,
            ttl,
        }
    }

    /// Test-only accessor; production reads accumulation via
    /// `evict_oldest_if_at_capacity` (which gates on capacity
    /// internally) — no callsite outside tests needs raw length.
    pub fn len(&self) -> usize {
        debug_assert_eq!(
            self.table.len(),
            self.deadline_index.len(),
            "PendingResponseTable invariant: table.len == deadline_index.len"
        );
        self.table.len()
    }

    /// `true` if no pending entry registered.  Companion to [`Self::len`].
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Evict every entry whose insertion `Instant` is older than `ttl`
    /// from `now`. Each evicted waiter receives `None` on its oneshot.
    pub fn evict_expired(&mut self, now: Instant) {
        while let Some(&(t, id)) = self.deadline_index.keys().next() {
            if now.duration_since(t) < self.ttl {
                break;
            }
            self.deadline_index.remove(&(t, id));
            if let Some((_, tx)) = self.table.remove(&id) {
                let _ = tx.send(None);
            }
        }
    }

    /// Evict the single oldest entry if we're at-or-over capacity.
    /// Used by the drain-loop path to avoid unbounded growth when
    /// peers spam request_ids that never get a matching response.
    pub fn evict_oldest_if_at_capacity(&mut self) {
        if self.table.len() < self.capacity {
            return;
        }
        let Some(&(t, id)) = self.deadline_index.keys().next() else {
            return;
        };
        self.deadline_index.remove(&(t, id));
        if let Some((_, tx)) = self.table.remove(&id) {
            let _ = tx.send(None);
        }
    }

    /// Insert `(request_id → response_tx)` at `now`. If there's
    /// already an entry with the same request_id, the existing waiter
    /// receives `None` and the new entry takes over. Same-key dedupe
    /// preserves the invariant that exactly one waiter is alive per
    /// request_id at a time.
    pub fn insert(
        &mut self,
        request_id: u32,
        response_tx: oneshot::Sender<Option<Vec<u8>>>,
        now: Instant,
    ) {
        if let Some((old_t, old_tx)) = self.table.remove(&request_id) {
            self.deadline_index.remove(&(old_t, request_id));
            let _ = old_tx.send(None);
        }
        self.deadline_index.insert((now, request_id), ());
        self.table.insert(request_id, (now, response_tx));
    }

    /// Take the entry for `request_id` — used when a matching response
    /// frame arrives and we need to wake the waiter with `Some(body)`. Returns
    /// `None` if either the request_id was never registered OR was
    /// already evicted (TTL or capacity).
    pub fn take(&mut self, request_id: u32) -> Option<oneshot::Sender<Option<Vec<u8>>>> {
        let (inserted, tx) = self.table.remove(&request_id)?;
        self.deadline_index.remove(&(inserted, request_id));
        Some(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ttl_evict_only_expired_entries_send_none() {
        let mut table = PendingResponseTable::new(10, Duration::from_millis(50));
        let (tx_old, mut rx_old) = oneshot::channel();
        let (tx_fresh, mut rx_fresh) = oneshot::channel();
        let now0 = Instant::now();
        table.insert(1, tx_old, now0);
        // Advance virtual time: tokio Instant::now doesn't move in test
        // automatically; we just pass a later Instant to evict_expired.
        let later = now0 + Duration::from_millis(60);
        table.insert(2, tx_fresh, later);
        table.evict_expired(later);
        // Old entry hit TTL and was evicted; fresh entry remains.
        assert_eq!(table.len(), 1);
        assert!(
            matches!(rx_old.try_recv(), Ok(None)),
            "expired waiter must receive None"
        );
        assert!(
            rx_fresh.try_recv().is_err(),
            "fresh waiter must NOT have been signalled"
        );
    }

    #[tokio::test]
    async fn capacity_evict_drops_oldest() {
        let mut table = PendingResponseTable::new(2, Duration::from_secs(60));
        let (tx0, mut rx0) = oneshot::channel();
        let (tx1, mut _rx1) = oneshot::channel();
        let (tx2, mut _rx2) = oneshot::channel();
        let t0 = Instant::now();
        table.insert(0, tx0, t0);
        table.insert(1, tx1, t0 + Duration::from_millis(1));
        // At capacity — next evict_oldest_if_at_capacity drops id=0.
        table.evict_oldest_if_at_capacity();
        table.insert(2, tx2, t0 + Duration::from_millis(2));
        assert_eq!(table.len(), 2);
        assert!(matches!(rx0.try_recv(), Ok(None)));
        assert!(table.take(1).is_some());
        assert!(table.take(2).is_some());
        assert!(
            table.take(0).is_none(),
            "id 0 was evicted, take must return None"
        );
    }

    #[tokio::test]
    async fn duplicate_insert_replaces_and_signals_old() {
        let mut table = PendingResponseTable::new(10, Duration::from_secs(60));
        let (tx_old, mut rx_old) = oneshot::channel();
        let (tx_new, _rx_new) = oneshot::channel();
        let t = Instant::now();
        table.insert(42, tx_old, t);
        table.insert(42, tx_new, t + Duration::from_millis(1));
        assert_eq!(table.len(), 1, "dedupe keeps single entry per id");
        assert!(
            matches!(rx_old.try_recv(), Ok(None)),
            "displaced waiter must receive None"
        );
    }

    #[tokio::test]
    async fn take_returns_none_for_unknown_id() {
        let mut table = PendingResponseTable::new(10, Duration::from_secs(60));
        assert!(table.take(99).is_none());
    }

    #[tokio::test]
    async fn evict_expired_with_ttl_arithmetic_handles_same_instant_collisions() {
        // Composite key (Instant, request_id) survives same-Instant inserts.
        let mut table = PendingResponseTable::new(10, Duration::from_millis(50));
        let (tx_a, _rx_a) = oneshot::channel();
        let (tx_b, _rx_b) = oneshot::channel();
        let t = Instant::now();
        table.insert(10, tx_a, t);
        table.insert(20, tx_b, t); // SAME Instant
        assert_eq!(
            table.len(),
            2,
            "two ids inserted at same Instant must coexist via composite key"
        );
    }
}
