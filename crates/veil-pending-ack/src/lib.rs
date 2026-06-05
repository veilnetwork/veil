//! Pending-ACK tracker for at-least-once delivery.
//!
//! When the originator sends an envelope with `require_ack = true`, it
//! registers the `content_id` here. If a `DeliveryStatus(DELIVERED)` is
//! received before the deadline the entry is cleared. Otherwise the tracker
//! fires retransmit callbacks until `MAX_DELIVERY_ATTEMPTS` is exhausted
//! at which point the entry transitions to `Failed` and the originator is
//! notified via an application-visible event.
//!
//! lifted out of `veilcore::node::dispatcher::pending_ack` —
//! this tracker has zero coupling to dispatcher internals (only depends on
//! `veil_proto::budget` constants), so it stands as its own crate and
//! unblocks the upcoming veil-ipc extraction whose request handlers
//! call `register` / `ack` / `tick` directly.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use veil_proto::budget::{
    DELIVERY_ACK_TIMEOUT_MS, MAX_DELIVERY_ATTEMPTS, MAX_PENDING_ACK_ENTRIES,
    MAX_PENDING_ACK_PER_PEER,
};

// ── PendingEntry ──────────────────────────────────────────────────────────────

struct PendingEntry {
    /// Raw wire-encoded `ForwardPayload` bytes ready to retransmit.
    /// `Arc` avoids cloning the full frame on every retransmit attempt.
    frame_bytes: Arc<[u8]>,
    /// Direct next-hop to send `frame_bytes` (may be an intermediate relay
    /// NOT the final recipient). This is the node whose session we must use
    /// for `session_tx_registry.send_to` on retransmit.
    next_hop: [u8; 32],
    /// `node_id` of the final recipient. Stored for informational purposes
    /// (e.g. `AckTickOutcome::Failed` so the caller can notify the app).
    dst_node_id: [u8; 32],
    /// `app_id` of the originating IPC client. Used to route the failure
    /// notification back to the sender on permanent failure.
    src_app_id: [u8; 32],
    /// **C-09** — per-message delivery-ACK key, derived from the E2E ML-KEM
    /// shared secret (`veil_e2e::derive_ack_key`). The recipient MACs
    /// `content_id` with it in the DELIVERED frame; the originator verifies that
    /// MAC before crediting relay reputation, so an on-path relay cannot forge a
    /// delivery confirmation. All-zero when no E2E key was established (then the
    /// entry is still cleared on DELIVERED, but no reputation is credited).
    ack_key: [u8; 32],
    /// Attempt counter (1-based: 1 = first send, already counted on register).
    attempts: u32,
    /// Deadline for the current attempt.
    deadline: Instant,
}

// ── PendingAckTracker ─────────────────────────────────────────────────────────

/// Outcome returned by [`PendingAckTracker::tick`] for every timed-out entry.
#[derive(Debug)]
pub enum AckTickOutcome {
    /// Retransmit the envelope (attempt ≤ MAX_DELIVERY_ATTEMPTS).
    Retransmit {
        content_id: [u8; 32],
        /// Direct next-hop session to send `frame_bytes` to.
        /// This is an intermediate relay, NOT the final recipient.
        next_hop: [u8; 32],
        /// Final recipient — for logging / app notification only.
        dst_node_id: [u8; 32],
        frame_bytes: Arc<[u8]>,
        attempt: u32,
    },
    /// All attempts exhausted — notify the application.
    Failed {
        content_id: [u8; 32],
        /// `app_id` of the originator — used to route the failure notification.
        src_app_id: [u8; 32],
        /// Direct next-hop the final attempt was sent through. :
        /// counted as a loss against this peer in the in-line loss tracker.
        next_hop: [u8; 32],
    },
}

/// Tracks in-flight envelopes that require an end-to-end ACK.
#[derive(Default)]
pub struct PendingAckTracker {
    pending: HashMap<[u8; 32], PendingEntry>,
    /// per-peer entry counter for the per-peer cap.
    /// Keyed by `dst_node_id` (final recipient); incremented on register and
    /// decremented on ack / failure / retain-drop.
    per_peer: HashMap<[u8; 32], u32>,
}

impl PendingAckTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a newly sent envelope.
    ///
    /// `next_hop` — the direct session peer the frame was sent (may be an
    /// intermediate relay). Used verbatim in `send_to` on retransmit.
    /// `dst_node_id` — the final recipient (for logging / app notification).
    /// `src_app_id` — the originating IPC client's app_id; used to route the
    /// failure notification back to the sender on permanent failure.
    /// `frame_bytes` — the complete `ForwardPayload` frame (header + body).
    ///
    /// Returns `false` and is a no-op when [`MAX_PENDING_ACK_ENTRIES`] is
    /// reached — the envelope is still sent, just without retransmit tracking.
    pub fn register(
        &mut self,
        content_id: [u8; 32],
        next_hop: [u8; 32],
        dst_node_id: [u8; 32],
        src_app_id: [u8; 32],
        ack_key: [u8; 32],
        frame_bytes: impl Into<Arc<[u8]>>,
    ) -> bool {
        if self.pending.len() >= MAX_PENDING_ACK_ENTRIES {
            return false;
        }
        // enforce per-peer cap before inserting.
        let peer_count = self.per_peer.get(&dst_node_id).copied().unwrap_or(0);
        if (peer_count as usize) >= MAX_PENDING_ACK_PER_PEER {
            return false;
        }
        let deadline = Instant::now() + Duration::from_millis(DELIVERY_ACK_TIMEOUT_MS);
        // When re-registering a
        // content_id that was previously bound to a DIFFERENT
        // `dst_node_id` (e.g. delivery retry redirected to a new peer)
        // decrement the old peer's counter before incrementing the new
        // one. Previously the prior peer's counter stayed inflated
        // until eviction, causing per-peer cap to deny legitimate new
        // registrations.
        let prior = self.pending.insert(
            content_id,
            PendingEntry {
                frame_bytes: frame_bytes.into(),
                next_hop,
                dst_node_id,
                src_app_id,
                ack_key,
                attempts: 1,
                deadline,
            },
        );
        match prior {
            None => {
                // Fresh insert — increment the new peer's counter.
                *self.per_peer.entry(dst_node_id).or_insert(0) += 1;
            }
            Some(prev) if prev.dst_node_id != dst_node_id => {
                // Same content_id rebound to a different peer — net
                // zero on the new peer (it was 0 before, and we add
                // 1 here), but decrement the old peer.
                decrement_peer(&mut self.per_peer, &prev.dst_node_id);
                *self.per_peer.entry(dst_node_id).or_insert(0) += 1;
            }
            Some(_) => {
                // Same peer — counter unchanged.
            }
        }
        true
    }

    /// Acknowledge successful delivery — removes the entry if present.
    pub fn ack(&mut self, content_id: &[u8; 32]) {
        if let Some(entry) = self.pending.remove(content_id) {
            decrement_peer(&mut self.per_peer, &entry.dst_node_id);
        }
    }

    /// Acknowledge successful delivery and return both the relay `next_hop`
    /// (for relay reputation tracking) and the `src_app_id`
    /// (for E2E delivery stage notification to the originating app).
    ///
    /// Returns `Some((next_hop, src_app_id))` if the entry was found and
    /// removed, `None` if unknown or already acknowledged.
    pub fn ack_and_get_info(&mut self, content_id: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
        self.pending.remove(content_id).map(|e| {
            decrement_peer(&mut self.per_peer, &e.dst_node_id);
            (e.next_hop, e.src_app_id)
        })
    }

    /// **C-09** — like [`Self::ack_and_get_info`] but **does not remove** the
    /// entry. Returns `(next_hop, src_app_id, ack_key)`. The caller reads the
    /// stored `ack_key` to verify a DELIVERED MAC *before* deciding to clear the
    /// entry (via [`Self::ack`]) and credit reputation — so a forged ACK whose
    /// MAC fails leaves the pending entry intact (retransmit continues) and
    /// earns nothing.
    pub fn peek_ack_info(&self, content_id: &[u8; 32]) -> Option<([u8; 32], [u8; 32], [u8; 32])> {
        self.pending
            .get(content_id)
            .map(|e| (e.next_hop, e.src_app_id, e.ack_key))
    }

    // cleanup: `peek_src_app_id` removed — ended up
    // using `ack_and_get_info` (consume on DELIVERED) at delivery.rs:1086, so
    // this non-consuming peek had zero non-test callers. Re-introduce из git
    // history if а stage-notification path needs the src_app_id without ACK.

    /// Drive the timer: collect outcomes for all entries whose deadline has
    /// passed. Entries that still have attempts left are rescheduled;
    /// exhausted entries are removed and returned as `Failed`.
    ///
    /// Call this on every `DELIVERY_ACK_CHECK_INTERVAL_MS` tick.
    pub fn tick(&mut self) -> Vec<AckTickOutcome> {
        let now = Instant::now();
        let mut outcomes = Vec::new();
        let timeout = Duration::from_millis(DELIVERY_ACK_TIMEOUT_MS);
        let per_peer = &mut self.per_peer;

        self.pending.retain(|&content_id, entry| {
            if now < entry.deadline {
                return true;
            }
            if entry.attempts >= MAX_DELIVERY_ATTEMPTS {
                outcomes.push(AckTickOutcome::Failed {
                    content_id,
                    src_app_id: entry.src_app_id,
                    next_hop: entry.next_hop,
                });
                // decrement per-peer counter on failure.
                decrement_peer(per_peer, &entry.dst_node_id);
                false
            } else {
                entry.attempts += 1;
                entry.deadline = now + timeout;
                outcomes.push(AckTickOutcome::Retransmit {
                    content_id,
                    next_hop: entry.next_hop,
                    dst_node_id: entry.dst_node_id,
                    frame_bytes: Arc::clone(&entry.frame_bytes),
                    attempt: entry.attempts,
                });
                true
            }
        });

        outcomes
    }

    /// Number of in-flight entries currently tracked.
    pub fn len(&self) -> usize {
        self.pending.len()
    }
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Update the stored `next_hop` for a tracked entry so that future
    /// retransmits target the new relay peer instead of the stale one.
    /// Called after a successful re-route when the original hop is dead.
    pub fn update_next_hop(&mut self, content_id: &[u8; 32], new_hop: [u8; 32]) {
        if let Some(entry) = self.pending.get_mut(content_id) {
            entry.next_hop = new_hop;
        }
    }
}

/// decrement the per-peer counter and prune the
/// entry once it hits zero.
fn decrement_peer(per_peer: &mut HashMap<[u8; 32], u32>, dst_node_id: &[u8; 32]) {
    if let Some(c) = per_peer.get_mut(dst_node_id) {
        *c = c.saturating_sub(1);
        if *c == 0 {
            per_peer.remove(dst_node_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(b: u8) -> [u8; 32] {
        [b; 32]
    }
    fn dst() -> [u8; 32] {
        [0xDD; 32]
    }
    fn hop() -> [u8; 32] {
        [0xEE; 32]
    }
    fn src() -> [u8; 32] {
        [0xAA; 32]
    }

    #[test]
    fn ack_clears_entry() {
        let mut t = PendingAckTracker::new();
        t.register(cid(1), hop(), dst(), src(), [0u8; 32], vec![0xAA]);
        assert_eq!(t.len(), 1);
        t.ack(&cid(1));
        assert!(t.is_empty());
    }

    #[test]
    fn tick_no_timeout_returns_nothing() {
        let mut t = PendingAckTracker::new();
        t.register(cid(2), hop(), dst(), src(), [0u8; 32], vec![]);
        assert!(t.tick().is_empty());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn per_peer_cap_rejects_excess_entries_for_same_peer() {
        let mut t = PendingAckTracker::new();
        let dst_a = [0xAA; 32];
        // Fill exactly to the per-peer cap.
        for i in 0..MAX_PENDING_ACK_PER_PEER {
            assert!(t.register([i as u8; 32], hop(), dst_a, src(), [0u8; 32], vec![]));
        }
        // The next register for the same peer should fail.
        assert!(!t.register([0xFE; 32], hop(), dst_a, src(), [0u8; 32], vec![]));
        // A different peer is still accepted.
        let dst_b = [0xBB; 32];
        assert!(t.register([0xFD; 32], hop(), dst_b, src(), [0u8; 32], vec![]));
    }

    #[test]
    fn ack_releases_per_peer_slot() {
        let mut t = PendingAckTracker::new();
        let dst_a = [0xAA; 32];
        for i in 0..MAX_PENDING_ACK_PER_PEER {
            assert!(t.register([i as u8; 32], hop(), dst_a, src(), [0u8; 32], vec![]));
        }
        assert!(!t.register([0xFE; 32], hop(), dst_a, src(), [0u8; 32], vec![]));
        // Free one slot.
        t.ack(&[0u8; 32]);
        // Now there should be room again.
        assert!(t.register([0xFE; 32], hop(), dst_a, src(), [0u8; 32], vec![]));
    }

    #[test]
    fn tick_retransmits_then_fails() {
        use std::time::Duration;
        let mut t = PendingAckTracker::new();
        t.register(cid(3), hop(), dst(), src(), [0u8; 32], vec![0xBB]);
        if let Some(e) = t.pending.get_mut(&cid(3)) {
            e.deadline = Instant::now() - Duration::from_millis(1);
        }

        let out = t.tick();
        assert_eq!(out.len(), 1);
        assert!(matches!(
            out[0],
            AckTickOutcome::Retransmit { attempt: 2, .. }
        ));
        assert_eq!(t.len(), 1);

        for expected_attempt in 3..=MAX_DELIVERY_ATTEMPTS {
            if let Some(e) = t.pending.get_mut(&cid(3)) {
                e.deadline = Instant::now() - Duration::from_millis(1);
            }
            let out = t.tick();
            assert_eq!(out.len(), 1);
            assert!(
                matches!(out[0], AckTickOutcome::Retransmit { attempt, .. } if attempt == expected_attempt)
            );
        }

        if let Some(e) = t.pending.get_mut(&cid(3)) {
            e.deadline = Instant::now() - Duration::from_millis(1);
        }
        let out = t.tick();
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], AckTickOutcome::Failed { .. }));
        assert!(t.is_empty());
    }
}
