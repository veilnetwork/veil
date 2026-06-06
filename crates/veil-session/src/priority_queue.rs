//! Weighted round-robin priority queue for outgoing frames.
//!
//! Frames are classified into 4 priority levels matching the 2-bit priority
//! field in `FrameHeader.flags`:
//!
//! | Level | Class | Weight |
//! |-------|-------------|--------|
//! | 0 | REALTIME | 8 |
//! | 1 | INTERACTIVE | 4 |
//! | 2 | BULK | 2 |
//! | 3 | BACKGROUND | 1 |
//!
//! Within each WRR round each priority level may emit up to `weight` frames
//! before moving to the next. Higher-priority queues are always polled first
//! within the remaining slots of the current round, so REALTIME traffic cannot
//! be starved by lower-priority floods.

use std::collections::VecDeque;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

// ── Public priority constants ─────────────────────────────────────────────────

pub use veil_proto::header::priority::{BACKGROUND, BULK, INTERACTIVE, REALTIME};

/// Default WRR weights: [REALTIME=8, INTERACTIVE=4, BULK=2, BACKGROUND=1].
pub const DEFAULT_WEIGHTS: [u32; 4] = [8, 4, 2, 1];

/// g: maximum aggregate frames buffered across all four
/// priority levels per session. Above this, lowest-priority frames are
/// shed first; same priority shed front-of-queue (oldest).
///
/// Sized to match the upstream mpsc cap (64 frames in `tx_queue_depth`)
/// and the IPC delivery cap (64) — at chat-load 60 KiB frames × 64 ≈ 4 MiB
/// per session worst case. Without this, the WRR queue grew unbounded
/// whenever the wire writer hiccupped under chaos-ban-style network
/// churn — observed as 300+ MiB RSS on a bootstrap with only 8 outbound
/// connect attempts and all-tiny gauges (the leak sat between the bounded
/// mpsc and the wire, completely unmetered).
///
/// Raised 64 → 1024 to align with `PQ_DRAIN_FRAMES_PER_PASS = 256`. The
/// older cap of 64 was below one drain pass, so `drain_outbox_into_pq`
/// kept shedding mid-priority frames every burst — the upstream mpsc
/// (cap 4096) effectively decimated to 64 on the way to the wire. Cap
/// 1024 at 60 KiB ≈ 60 MiB worst case; production frames are 60-300 B
/// (control) to 64 KiB (data), so steady state is well below this.
pub const DEFAULT_MAX_DEPTH: usize = 1024;

// ── PriorityQueue ─────────────────────────────────────────────────────────────

/// In-process WRR priority queue for outgoing OVL1 frames.
///
/// Frames are stored as `veil_bufpool::PooledShared` so that broadcast callers can share the
/// same backing buffer across sessions without extra copies.
pub struct PriorityQueue {
    queues: [VecDeque<veil_bufpool::PooledShared>; 4],
    weights: [u32; 4],
    /// Remaining slots in the current WRR round for each priority.
    slots: [u32; 4],
    /// g: aggregate frame cap across all priorities.
    max_depth: usize,
    /// g: shared cumulative drop counter — typically
    /// `NodeMetrics::priority_queue_drops_total` so overflow surfaces
    /// in Prometheus the same scrape cycle it happens.
    drops_total: Arc<AtomicU64>,
}

impl PriorityQueue {
    pub fn new(weights: [u32; 4]) -> Self {
        Self::with_capacity(weights, DEFAULT_MAX_DEPTH)
    }

    /// g: construct with a custom aggregate cap. Useful
    /// for tests that need to exercise overflow shedding deterministically.
    pub fn with_capacity(weights: [u32; 4], max_depth: usize) -> Self {
        Self::with_capacity_and_drop_counter(weights, max_depth, Arc::new(AtomicU64::new(0)))
    }

    /// g: construct with a custom cap and a shared
    /// `Arc<AtomicU64>` drop counter (typically
    /// `NodeMetrics::priority_queue_drops_counter` so overflow drops
    /// flow to Prometheus without per-tick polling).
    pub fn with_capacity_and_drop_counter(
        weights: [u32; 4],
        max_depth: usize,
        drops_total: Arc<AtomicU64>,
    ) -> Self {
        debug_assert!(
            weights.iter().any(|&w| w > 0),
            "PriorityQueue: all weights are zero — pop() would always return None"
        );
        Self {
            queues: Default::default(),
            weights,
            slots: weights,
            max_depth,
            drops_total,
        }
    }

    pub fn with_default_weights() -> Self {
        Self::new(DEFAULT_WEIGHTS)
    }

    /// Push a frame at the given priority level (clamped [0, 3]).
    ///
    /// g: when the aggregate depth would exceed
    /// `max_depth`, shed one frame from the lowest non-empty priority
    /// (front-of-queue if same priority) before inserting. This keeps
    /// the queue's memory footprint bounded under sustained wire-stall
    /// pressure while preserving REALTIME/INTERACTIVE frames at the
    /// expense of BULK/BACKGROUND. Drops increment `drops_total` so the
    /// runner can forward them to Prometheus.
    pub fn push(&mut self, priority: u8, frame: veil_bufpool::PooledShared) {
        let p = priority.min(3) as usize;
        if self.len() >= self.max_depth {
            // Shed one frame from the lowest priority that has any
            // queued — prefer victimising lower-priority traffic over
            // dropping the incoming frame outright, so REALTIME/INTERACTIVE
            // stays responsive even when BULK is flooding the queue.
            for shed_p in (0..4).rev() {
                if !self.queues[shed_p].is_empty() {
                    self.queues[shed_p].pop_front();
                    self.drops_total.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }
        self.queues[p].push_back(frame);
    }

    /// g: snapshot the cumulative drop count. Caller
    /// typically reads this for diagnostics; the live Prometheus counter
    /// is updated directly via the shared `Arc<AtomicU64>` passed at
    /// construction.
    pub fn drops_total(&self) -> u64 {
        self.drops_total.load(Ordering::Relaxed)
    }

    /// Pop the next frame following WRR order.
    ///
    /// Returns `None` if all queues are empty. When all slots in the current
    /// round are consumed, the round resets and starts again.
    pub fn pop(&mut self) -> Option<veil_bufpool::PooledShared> {
        if let Some(frame) = self.try_pop_with_current_slots() {
            return Some(frame);
        }
        // All slots exhausted. If queues are empty, nothing to return.
        if self.is_empty() {
            return None;
        }
        // Reset round and try again.
        self.reset_round();
        self.try_pop_with_current_slots()
    }

    fn try_pop_with_current_slots(&mut self) -> Option<veil_bufpool::PooledShared> {
        for p in 0..4 {
            if self.slots[p] > 0 && !self.queues[p].is_empty() {
                self.slots[p] -= 1;
                return self.queues[p].pop_front();
            }
        }
        None
    }

    fn reset_round(&mut self) {
        self.slots = self.weights;
    }

    pub fn is_empty(&self) -> bool {
        self.queues.iter().all(|q| q.is_empty())
    }

    /// Total number of queued frames across all priorities.
    pub fn len(&self) -> usize {
        self.queues.iter().map(|q| q.len()).sum()
    }

    /// Highest priority level (lowest index = highest priority) that
    /// currently has at least one queued frame. Returns `None` when
    /// the queue is empty. Used by deferred
    /// outbound-batching: the session runner peeks the head priority
    /// before draining; if it's strictly above [`INTERACTIVE`] (i.e.
    /// `BULK` or `BACKGROUND`), the runner may defer drain by up
    /// to `MobileConfig::outbound_batch_window_ms` to coalesce
    /// cellular-radio wake-ups.
    ///
    /// Note this does NOT advance the WRR slot counter — it's a pure
    /// inspection of the queue state.
    pub fn peek_priority(&self) -> Option<u8> {
        (0..4u8).find(|&p| !self.queues[p as usize].is_empty())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn arc(bytes: &[u8]) -> veil_bufpool::PooledShared {
        veil_bufpool::pooled_shared_from_vec(bytes.to_vec())
    }

    #[test]
    fn push_and_pop_fifo_single_priority() {
        let mut pq = PriorityQueue::with_default_weights();
        pq.push(REALTIME, arc(b"a"));
        pq.push(REALTIME, arc(b"b"));
        pq.push(REALTIME, arc(b"c"));
        assert_eq!(pq.pop().unwrap().as_ref(), b"a");
        assert_eq!(pq.pop().unwrap().as_ref(), b"b");
        assert_eq!(pq.pop().unwrap().as_ref(), b"c");
        assert!(pq.pop().is_none());
    }

    /// 29.5: REALTIME frames sent before BULK frames when both are enqueued.
    #[test]
    fn realtime_before_bulk_strict_priority() {
        let mut pq = PriorityQueue::with_default_weights();
        // Enqueue BULK first (lower priority).
        for i in 0..3u8 {
            pq.push(BULK, arc(&[0xB0 + i]));
        }
        // Then enqueue REALTIME.
        for i in 0..3u8 {
            pq.push(REALTIME, arc(&[0xA0 + i]));
        }

        // All REALTIME frames should come out before any BULK frame.
        let mut rt_done = false;
        let mut order = Vec::new();
        while let Some(frame) = pq.pop() {
            if frame[0] >= 0xB0 {
                rt_done = true;
            }
            if frame[0] >= 0xA0 && frame[0] < 0xB0 && rt_done {
                panic!("REALTIME frame appeared after a BULK frame");
            }
            order.push(frame[0]);
        }
        // All 6 frames were dequeued.
        assert_eq!(order.len(), 6);
        // First 3 should be REALTIME (0xA0..0xA2).
        for &byte in &order[..3] {
            assert!(
                (0xA0..0xB0).contains(&byte),
                "expected REALTIME, got {byte:#04x}"
            );
        }
        // Last 3 should be BULK (0xB0..0xB2).
        for &byte in &order[3..] {
            assert!(byte >= 0xB0, "expected BULK, got {byte:#04x}");
        }
    }

    #[test]
    fn empty_queue_returns_none() {
        let mut pq = PriorityQueue::with_default_weights();
        assert!(pq.is_empty());
        assert!(pq.pop().is_none());
    }

    #[test]
    fn wrr_cycles_across_all_priorities() {
        // Use weights [2, 2, 2, 2] — equal weighting.
        let mut pq = PriorityQueue::new([2, 2, 2, 2]);
        for p in 0..4u8 {
            for _ in 0..4 {
                pq.push(p, arc(&[p]));
            }
        }
        let mut counts = [0u32; 4];
        while let Some(frame) = pq.pop() {
            counts[frame[0] as usize] += 1;
        }
        // All frames drained.
        assert_eq!(counts, [4, 4, 4, 4]);
    }

    // ── deferred : peek_priority ──────────────────

    #[test]
    fn epic483_5o_peek_priority_empty_returns_none() {
        let pq = PriorityQueue::with_default_weights();
        assert_eq!(pq.peek_priority(), None);
    }

    #[test]
    fn epic483_5o_peek_priority_returns_highest_priority_head() {
        let mut pq = PriorityQueue::with_default_weights();
        pq.push(BACKGROUND, arc(b"bg"));
        assert_eq!(pq.peek_priority(), Some(BACKGROUND));
        pq.push(BULK, arc(b"bulk"));
        assert_eq!(pq.peek_priority(), Some(BULK));
        pq.push(INTERACTIVE, arc(b"i"));
        assert_eq!(pq.peek_priority(), Some(INTERACTIVE));
        pq.push(REALTIME, arc(b"rt"));
        assert_eq!(
            pq.peek_priority(),
            Some(REALTIME),
            "REALTIME beats everything"
        );
    }

    #[test]
    fn epic483_5o_peek_priority_does_not_advance_wrr() {
        let mut pq = PriorityQueue::with_default_weights();
        pq.push(REALTIME, arc(b"rt0"));
        pq.push(REALTIME, arc(b"rt1"));
        // peek 100× — must not advance round-robin slots
        for _ in 0..100 {
            assert_eq!(pq.peek_priority(), Some(REALTIME));
        }
        // First pop returns rt0 (FIFO within priority).
        assert_eq!(pq.pop().unwrap().as_ref(), b"rt0");
        assert_eq!(pq.pop().unwrap().as_ref(), b"rt1");
        assert_eq!(pq.peek_priority(), None);
    }

    #[test]
    fn epic483_5o_peek_returns_priority_after_wrr_pop() {
        // Mixed priorities — verify peek tracks queue state through a
        // pop sequence, never returning a priority that has 0 frames.
        let mut pq = PriorityQueue::with_default_weights();
        pq.push(REALTIME, arc(b"rt"));
        pq.push(BACKGROUND, arc(b"bg"));
        assert_eq!(pq.peek_priority(), Some(REALTIME));
        let _ = pq.pop().unwrap(); // RT drained
        assert_eq!(
            pq.peek_priority(),
            Some(BACKGROUND),
            "after RT drained, peek must report BACKGROUND"
        );
        let _ = pq.pop().unwrap();
        assert_eq!(pq.peek_priority(), None);
    }
}
