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
use std::time::{Duration, Instant};

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
/// Raised 64 → 4096 to align with the upstream per-session outbox and absorb a
/// full high-BDP circuit window without shedding already-admitted frames. The
/// older cap of 64 was below one drain pass, so `drain_outbox_into_pq`
/// kept shedding mid-priority frames every burst — the upstream mpsc
/// (cap 4096) effectively decimated to 64 on the way to the wire. Cap
/// 4096 at 60 KiB is a pessimistic 240 MiB worst case; production frames are
/// overwhelmingly 60–450 B (including circuit data), and the runner drains
/// up to 256 per pass, so steady state is well below this.
pub const DEFAULT_MAX_DEPTH: usize = 4096;

/// A loss-tolerant media frame is useful only while it is fresh.  Keeping a
/// large FIFO here turns TCP fallback congestion into seconds of video replay
/// after the link recovers.  This cap is deliberately independent of the
/// aggregate queue cap. Each process-local class has its own 64-frame budget;
/// forwarded user traffic shares the single neutral INTERACTIVE budget. This
/// prevents a local source burst from evicting another source or transit data.
/// Roughly 64 relay cells cover a few video frames while
/// bounding the amount of stale realtime work retained per session.
pub const LOSSY_REALTIME_MAX_DEPTH: usize = 64;

/// Maximum time a loss-tolerant realtime frame may wait in the reorderable
/// priority queue. Bytes already committed to the socket cannot be recalled,
/// so dropping here is the last point where newest-wins media semantics can be
/// preserved on transports without a QUIC DATAGRAM lane.
pub const LOSSY_REALTIME_MAX_AGE: Duration = Duration::from_millis(500);

struct QueuedFrame {
    frame: veil_bufpool::PooledShared,
    enqueued_at: Option<Instant>,
    lossy_realtime: bool,
    carrier: Option<veil_anonymity::circuit_carrier::Carrier>,
}

// ── PriorityQueue ─────────────────────────────────────────────────────────────

/// In-process WRR priority queue for outgoing OVL1 frames.
///
/// Frames are stored as `veil_bufpool::PooledShared` so that broadcast callers can share the
/// same backing buffer across sessions without extra copies.
pub struct PriorityQueue {
    queues: [VecDeque<QueuedFrame>; 4],
    weights: [u32; 4],
    /// Remaining slots in the current WRR round for each priority.
    slots: [u32; 4],
    /// Endpoint-only rounds when the ordinary scheduler is blocked by a
    /// reliable head. Transit traffic never enters these local slots.
    local_datagram_slots: [u32; 4],
    /// g: aggregate frame cap across all priorities.
    max_depth: usize,
    /// g: shared cumulative drop counter — typically
    /// `NodeMetrics::priority_queue_drops_total` so overflow surfaces
    /// in Prometheus the same scrape cycle it happens.
    drops_total: Arc<AtomicU64>,
    lossy_realtime_len: [usize; 4],
    local_primary_seen: Option<Instant>,
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
            local_datagram_slots: weights,
            max_depth,
            drops_total,
            lossy_realtime_len: [0; 4],
            local_primary_seen: None,
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
        self.push_entry(priority, frame, false, None);
    }

    /// Enqueue a canonical loss-tolerant realtime frame. When its dedicated
    /// budget is full, discard the oldest media frame rather than letting a
    /// reliable-stream fallback replay obsolete RTP after congestion clears.
    pub fn push_lossy_realtime(&mut self, priority: u8, frame: veil_bufpool::PooledShared) {
        if priority.min(3) == REALTIME {
            self.push_lossy(priority, frame);
        } else {
            self.push(priority, frame);
        }
    }

    /// Loss tolerance is independent of queue priority. In particular relayed
    /// datagrams share INTERACTIVE FIFO order with other forwarded user data.
    pub fn push_lossy(&mut self, priority: u8, frame: veil_bufpool::PooledShared) {
        self.push_lossy_with_carrier(priority, frame, None);
    }

    pub(crate) fn push_envelope(
        &mut self,
        envelope: crate::frame_outbox::FrameEnvelope,
        lossy: bool,
    ) {
        let (priority, frame) = envelope.frame;
        if lossy {
            self.push_lossy_with_carrier(priority, frame, envelope.carrier);
        } else {
            self.push_entry(priority, frame, false, envelope.carrier);
        }
    }

    fn push_lossy_with_carrier(
        &mut self,
        priority: u8,
        frame: veil_bufpool::PooledShared,
        carrier: Option<veil_anonymity::circuit_carrier::Carrier>,
    ) {
        let p = priority.min(3) as usize;
        // Lossy capacity is independent for each local producer class. Transit
        // has only INTERACTIVE, so no relay/user role gets a separate budget.
        // At capacity drop the oldest lossy entry of THIS class, preserving
        // its reliable FIFO entries and every other producer's pending work.
        if self.lossy_realtime_len[p] >= LOSSY_REALTIME_MAX_DEPTH {
            let index = self.queues[p]
                .iter()
                .position(|queued| queued.lossy_realtime)
                .expect("lossy class counter requires an entry");
            self.queues[p].remove(index);
            self.lossy_realtime_len[p] -= 1;
            self.drops_total.fetch_add(1, Ordering::Relaxed);
        }
        self.push_entry(priority, frame, true, carrier);
    }

    fn push_entry(
        &mut self,
        priority: u8,
        frame: veil_bufpool::PooledShared,
        lossy_realtime: bool,
        carrier: Option<veil_anonymity::circuit_carrier::Carrier>,
    ) {
        let p = priority.min(3) as usize;
        if self.len() >= self.max_depth {
            // Shed one frame from the lowest priority that has any queued —
            // prefer victimising lower-priority traffic over dropping the
            // incoming frame, so REALTIME/INTERACTIVE stays responsive when
            // BULK floods the queue. Larger index = lower priority, so scan
            // 3→p and only victimise frames AT OR BELOW the incoming frame's
            // priority. If everything queued outranks the incoming frame (e.g.
            // a BACKGROUND cover frame arriving into a queue full of REALTIME
            // data), drop the INCOMING frame instead of inverting priority.
            // (audit cycle-8 F4.)
            let mut shed = false;
            for shed_p in (p..4).rev() {
                if !self.queues[shed_p].is_empty() {
                    if self.queues[shed_p]
                        .pop_front()
                        .is_some_and(|queued| queued.lossy_realtime)
                    {
                        self.lossy_realtime_len[shed_p] -= 1;
                    }
                    self.drops_total.fetch_add(1, Ordering::Relaxed);
                    shed = true;
                    break;
                }
            }
            if !shed {
                // Nothing at-or-below incoming priority to evict — drop it.
                self.drops_total.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        self.queues[p].push_back(QueuedFrame {
            frame,
            enqueued_at: lossy_realtime.then(Instant::now),
            lossy_realtime,
            carrier,
        });
        if lossy_realtime {
            self.lossy_realtime_len[p] += 1;
        }
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
            if self.slots[p] == 0 {
                continue;
            }
            while self.queues[p].front().is_some_and(|queued| {
                queued.lossy_realtime
                    && queued
                        .enqueued_at
                        .is_some_and(|at| at.elapsed() > LOSSY_REALTIME_MAX_AGE)
            }) {
                self.queues[p].pop_front();
                self.lossy_realtime_len[p] -= 1;
                self.drops_total.fetch_add(1, Ordering::Relaxed);
            }
            if let Some(queued) = self.queues[p].pop_front() {
                self.slots[p] -= 1;
                if queued.lossy_realtime {
                    self.lossy_realtime_len[p] -= 1;
                }
                return Some(queued.frame);
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

    pub(crate) fn note_local_primary(&mut self, now: Instant) {
        self.local_primary_seen = Some(now);
    }

    pub(crate) fn local_primary_active(&self, now: Instant) -> bool {
        self.local_primary_seen
            .is_some_and(|at| now.saturating_duration_since(at) < Duration::from_secs(3))
    }

    /// Pop the FIFO head of the REALTIME queue only when `predicate` accepts
    /// it. This does not consume a WRR slot: the frame leaves the ordered
    /// stream scheduler and is carried by an independent realtime lane.
    pub fn pop_realtime_if(
        &mut self,
        predicate: impl FnOnce(&[u8]) -> bool,
    ) -> Option<veil_bufpool::PooledShared> {
        while self.queues[REALTIME as usize]
            .front()
            .is_some_and(|queued| {
                queued.lossy_realtime
                    && queued
                        .enqueued_at
                        .is_some_and(|at| at.elapsed() > LOSSY_REALTIME_MAX_AGE)
            })
        {
            self.queues[REALTIME as usize].pop_front();
            self.lossy_realtime_len[REALTIME as usize] -= 1;
            self.drops_total.fetch_add(1, Ordering::Relaxed);
        }
        let head = self.queues[REALTIME as usize].front()?;
        predicate(&head.frame).then(|| {
            let queued = self.queues[REALTIME as usize]
                .pop_front()
                .expect("REALTIME head checked above");
            if queued.lossy_realtime {
                self.lossy_realtime_len[REALTIME as usize] -= 1;
            }
            queued.frame
        })
    }

    /// Restore a REALTIME frame after a side-channel send could not complete.
    /// The caller has just popped this same frame, so reinsertion cannot exceed
    /// the queue's prior bounded depth.
    pub fn push_realtime_front(&mut self, frame: veil_bufpool::PooledShared) {
        self.push_lossy_front(REALTIME, frame);
    }

    /// Restore a popped datagram to its original queue on transport failure.
    pub fn push_lossy_front(&mut self, priority: u8, frame: veil_bufpool::PooledShared) {
        self.queues[priority.min(3) as usize].push_front(QueuedFrame {
            frame,
            enqueued_at: Some(Instant::now()),
            lossy_realtime: true,
            carrier: None,
        });
        self.lossy_realtime_len[priority.min(3) as usize] += 1;
    }

    /// Select the next frame using the SAME WRR order as the ordered stream,
    /// and remove it only if the datagram transport can carry it. Never search
    /// past a reliable FIFO head for a later datagram: transport separation
    /// must not grant relayed datagrams scheduling priority over other data.
    pub fn pop_datagram_if(
        &mut self,
        predicate: impl FnOnce(&[u8]) -> bool,
    ) -> Option<(u8, veil_bufpool::PooledShared)> {
        self.pop_datagram_envelope_if(predicate)
            .map(|envelope| envelope.frame)
    }

    /// Let independently transported LOCAL sources progress when a reliable
    /// writer stops the ordinary WRR round. Local envelope priorities are not
    /// taken from the wire: forwarded cells always enter INTERACTIVE and cannot
    /// use this path. Keep FIFO within each source and the existing age/cap/drop
    /// accounting; only the local round is independent of reliable writes.
    pub(crate) fn pop_local_datagram_envelope_if(
        &mut self,
        predicate: impl Fn(&[u8]) -> bool,
    ) -> Option<crate::frame_outbox::FrameEnvelope> {
        for attempt in 0..2 {
            for priority in crate::local_datagram_status::LOCAL_DATAGRAM_PRIORITIES {
                let p = priority as usize;
                if self.local_datagram_slots[p] == 0 {
                    continue;
                }
                // Reliable writes and datagrams use separate transports even
                // when the producer gave them the same local queue class.
                // Find only the first local lossy entry; never overtake another
                // local datagram or a relayed cell's ordinary FIFO.
                while let Some(index) = self.queues[p]
                    .iter()
                    .position(|queued| queued.lossy_realtime && queued.carrier.is_none())
                {
                    let head = &self.queues[p][index];
                    if head
                        .enqueued_at
                        .is_some_and(|at| at.elapsed() > LOSSY_REALTIME_MAX_AGE)
                    {
                        self.queues[p].remove(index);
                        self.lossy_realtime_len[p] -= 1;
                        self.drops_total.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    if !predicate(&head.frame) {
                        break;
                    }
                    let queued = self.queues[p].remove(index).expect("entry checked above");
                    self.local_datagram_slots[p] -= 1;
                    self.lossy_realtime_len[p] -= 1;
                    return Some(crate::frame_outbox::FrameEnvelope {
                        frame: (priority, queued.frame),
                        carrier: queued.carrier,
                    });
                }
            }
            if attempt == 0 {
                self.local_datagram_slots = self.weights;
            }
        }
        None
    }

    pub(crate) fn pop_datagram_envelope_if(
        &mut self,
        predicate: impl FnOnce(&[u8]) -> bool,
    ) -> Option<crate::frame_outbox::FrameEnvelope> {
        self.pop_envelope_if(|_, frame| predicate(frame))
    }

    /// Rejecting the selected FIFO head leaves it and its WRR slot intact.
    /// The stream batch can flush before trying this whole frame again.
    pub(crate) fn pop_envelope_if(
        &mut self,
        predicate: impl FnOnce(u8, &[u8]) -> bool,
    ) -> Option<crate::frame_outbox::FrameEnvelope> {
        for attempt in 0..2 {
            for p in 0..4 {
                if self.slots[p] == 0 {
                    continue;
                }
                while self.queues[p].front().is_some_and(|queued| {
                    queued.lossy_realtime
                        && queued
                            .enqueued_at
                            .is_some_and(|at| at.elapsed() > LOSSY_REALTIME_MAX_AGE)
                }) {
                    self.queues[p].pop_front();
                    self.lossy_realtime_len[p] -= 1;
                    self.drops_total.fetch_add(1, Ordering::Relaxed);
                }
                if let Some(head) = self.queues[p].front() {
                    if !predicate(p as u8, &head.frame) {
                        return None;
                    }
                    let queued = self.queues[p].pop_front().expect("head checked above");
                    self.slots[p] -= 1;
                    if queued.lossy_realtime {
                        self.lossy_realtime_len[p] -= 1;
                    }
                    return Some(crate::frame_outbox::FrameEnvelope {
                        frame: (p as u8, queued.frame),
                        carrier: queued.carrier,
                    });
                }
            }
            if attempt == 0 && !self.is_empty() {
                self.reset_round();
            }
        }
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #[test]
    fn rejected_stream_head_preserves_fifo_and_round() {
        let mut pq = super::PriorityQueue::with_default_weights();
        pq.push(3, veil_bufpool::pooled_shared_from_vec(vec![1]));
        pq.push(3, veil_bufpool::pooled_shared_from_vec(vec![2]));
        let slots = pq.slots;
        assert!(pq.pop_envelope_if(|_, _| false).is_none());
        assert_eq!(pq.slots, slots);
        assert_eq!(pq.len(), 2);
        let head = pq.pop_envelope_if(|p, b| p == 3 && b == [1]).unwrap();
        assert_eq!(&*head.frame.1, &[1]);
        assert_eq!(&*pq.pop().unwrap(), &[2]);
    }

    #[test]
    fn local_primary_window_expires_and_refreshes() {
        let mut pq = super::PriorityQueue::with_default_weights();
        let now = std::time::Instant::now();
        assert!(!pq.local_primary_active(now));
        pq.note_local_primary(now);
        assert!(pq.local_primary_active(now + std::time::Duration::from_millis(2999)));
        assert!(!pq.local_primary_active(now + std::time::Duration::from_secs(3)));
        pq.note_local_primary(now + std::time::Duration::from_secs(2));
        assert!(pq.local_primary_active(now + std::time::Duration::from_secs(3)));
    }
    use super::*;

    fn arc(bytes: &[u8]) -> veil_bufpool::PooledShared {
        veil_bufpool::pooled_shared_from_vec(bytes.to_vec())
    }

    #[test]
    fn local_datagram_rounds_progress_with_reliable_backlog() {
        let mut pq = PriorityQueue::with_default_weights();
        pq.push(INTERACTIVE, arc(b"first file"));
        pq.push(INTERACTIVE, arc(b"second file"));
        let ordinary_slots = pq.slots;
        // Refill between rounds so this also checks progress across an idle
        // producer, without relying on a large lossy backlog staying fresh.
        for _ in 0..3 {
            for (priority, count) in [(REALTIME, 8), (BULK, 2), (BACKGROUND, 1)] {
                for _ in 0..count {
                    pq.push_lossy(priority, arc(b"local"));
                }
            }
            for expected in [REALTIME; 8]
                .into_iter()
                .chain([BULK; 2])
                .chain([BACKGROUND])
            {
                let envelope = pq.pop_local_datagram_envelope_if(|_| true).unwrap();
                assert_eq!(envelope.frame.0, expected);
            }
            assert_eq!(pq.slots, ordinary_slots);
        }
        assert_eq!(pq.lossy_realtime_len.iter().sum::<usize>(), 0);
        assert_eq!(pq.drops_total(), 0);
        assert_eq!(&*pq.pop().unwrap(), b"first file");
        assert_eq!(&*pq.pop().unwrap(), b"second file");
    }

    #[test]
    fn local_datagram_round_cannot_promote_transit() {
        let mut pq = PriorityQueue::with_default_weights();
        pq.push(INTERACTIVE, arc(b"reliable"));
        pq.push_lossy(INTERACTIVE, arc(b"transit"));
        assert!(pq.pop_local_datagram_envelope_if(|_| true).is_none());
        assert_eq!(pq.len(), 2);
        assert_eq!(pq.slots, DEFAULT_WEIGHTS);
        assert_eq!(&*pq.pop().unwrap(), b"reliable");
        assert!(pq.pop_local_datagram_envelope_if(|_| true).is_none());
        let envelope = pq.pop_datagram_envelope_if(|_| true).unwrap();
        assert_eq!(envelope.frame.0, INTERACTIVE);
        assert_eq!(&*envelope.frame.1, b"transit");
        assert_eq!(pq.slots[INTERACTIVE as usize], 2);
    }

    #[test]
    fn local_datagram_round_separates_sources_from_reliable_fifo() {
        let mut pq = PriorityQueue::with_default_weights();
        pq.push(REALTIME, arc(b"control1"));
        pq.push_lossy(REALTIME, arc(b"primary1"));
        pq.push(REALTIME, arc(b"control2"));
        pq.push_lossy(REALTIME, arc(b"primary2"));
        pq.push_lossy(BULK, arc(b"secondary"));
        // A refused datagram head may not be skipped for another accepted
        // datagram in that source; other sources still get their own turn.
        let envelope = pq
            .pop_local_datagram_envelope_if(|bytes| bytes != b"primary1")
            .unwrap();
        assert_eq!(&*envelope.frame.1, b"secondary");
        assert!(
            pq.pop_local_datagram_envelope_if(|bytes| bytes != b"primary1")
                .is_none()
        );
        for expected in [b"primary1", b"primary2"] {
            let envelope = pq.pop_local_datagram_envelope_if(|_| true).unwrap();
            assert_eq!(&*envelope.frame.1, expected);
        }
        // Bypassing the independent reliable transport must neither drop nor
        // reorder its controls. The ordinary round remains untouched.
        assert_eq!(pq.slots, DEFAULT_WEIGHTS);
        assert_eq!(&*pq.pop().unwrap(), b"control1");
        assert_eq!(&*pq.pop().unwrap(), b"control2");
        assert!(pq.is_empty());
    }

    #[test]
    fn local_datagram_round_discards_expired_source_heads() {
        let mut pq = PriorityQueue::with_default_weights();
        pq.push(REALTIME, arc(b"reliable"));
        pq.push_lossy(REALTIME, arc(b"stale"));
        pq.queues[REALTIME as usize][1].enqueued_at =
            Some(Instant::now() - LOSSY_REALTIME_MAX_AGE - Duration::from_millis(1));
        pq.push_lossy(BULK, arc(b"fresh"));
        let envelope = pq.pop_local_datagram_envelope_if(|_| true).unwrap();
        assert_eq!(&*envelope.frame.1, b"fresh");
        assert_eq!(pq.lossy_realtime_len.iter().sum::<usize>(), 0);
        assert_eq!(pq.drops_total(), 1);
        assert_eq!(&*pq.pop().unwrap(), b"reliable");
    }

    #[test]
    fn neutral_datagram_cannot_jump_past_reliable_fifo_head() {
        let mut pq = PriorityQueue::with_default_weights();
        pq.push(INTERACTIVE, arc(b"file"));
        pq.push_lossy(INTERACTIVE, arc(b"datagram"));
        assert!(pq.pop_datagram_if(|bytes| bytes == b"datagram").is_none());
        assert_eq!(&*pq.pop().unwrap(), b"file");
        let (priority, frame) = pq.pop_datagram_if(|bytes| bytes == b"datagram").unwrap();
        assert_eq!(priority, INTERACTIVE);
        assert_eq!(&*frame, b"datagram");
        assert!(pq.is_empty());
    }

    #[test]
    fn datagrams_consume_normal_scheduler_slots() {
        let mut pq = PriorityQueue::new([1, 1, 1, 1]);
        pq.push_lossy(INTERACTIVE, arc(b"datagram1"));
        pq.push_lossy(INTERACTIVE, arc(b"datagram2"));
        pq.push(BULK, arc(b"bulk"));
        assert!(
            pq.pop_datagram_if(|bytes| bytes.starts_with(b"datagram"))
                .is_some()
        );
        assert!(
            pq.pop_datagram_if(|bytes| bytes.starts_with(b"datagram"))
                .is_none()
        );
        assert_eq!(&*pq.pop().unwrap(), b"bulk");
        assert_eq!(&*pq.pop().unwrap(), b"datagram2");
    }

    #[test]
    fn neutral_lossy_budget_preserves_reliable_frames() {
        let mut pq = PriorityQueue::with_default_weights();
        pq.push(INTERACTIVE, arc(b"reliable"));
        for i in 0..=LOSSY_REALTIME_MAX_DEPTH {
            pq.push_lossy(INTERACTIVE, arc(&[i as u8]));
        }
        assert_eq!(pq.len(), LOSSY_REALTIME_MAX_DEPTH + 1);
        assert_eq!(pq.drops_total(), 1);
        assert_eq!(&*pq.pop().unwrap(), b"reliable");
        assert_eq!(&*pq.pop().unwrap(), &[1]);
    }

    #[test]
    fn neutral_lossy_frame_expires_without_dropping_reliable_data() {
        let mut pq = PriorityQueue::with_default_weights();
        pq.push_lossy(INTERACTIVE, arc(b"stale"));
        pq.queues[INTERACTIVE as usize][0].enqueued_at =
            Some(Instant::now() - LOSSY_REALTIME_MAX_AGE - Duration::from_millis(1));
        pq.push(INTERACTIVE, arc(b"reliable"));
        assert!(pq.pop_datagram_if(|bytes| bytes == b"stale").is_none());
        assert_eq!(&*pq.pop().unwrap(), b"reliable");
        assert_eq!(pq.drops_total(), 1);
        assert!(pq.is_empty());
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

    #[test]
    fn conditional_realtime_pop_preserves_fifo_and_wrr_slots() {
        let mut pq = PriorityQueue::with_default_weights();
        pq.push(REALTIME, arc(b"rt-a"));
        pq.push(REALTIME, arc(b"rt-b"));
        pq.push(BULK, arc(b"bulk"));

        assert!(pq.pop_realtime_if(|f| f == b"no").is_none());
        let first = pq.pop_realtime_if(|f| f == b"rt-a").unwrap();
        assert_eq!(first.as_ref(), b"rt-a");
        pq.push_realtime_front(first);
        assert_eq!(pq.pop().unwrap().as_ref(), b"rt-a");
        assert_eq!(pq.pop().unwrap().as_ref(), b"rt-b");
    }

    #[test]
    fn lossy_sources_have_independent_capacity_and_preserve_neutral_transit() {
        let mut pq = PriorityQueue::with_default_weights();
        let packet = |p: u8, seq: u16| arc(&[p, (seq >> 8) as u8, seq as u8]);
        // Older primary packets must survive a newer secondary burst and
        // another primary arrival. The former shared cap evicted primary[0].
        for p in [REALTIME, BULK, BACKGROUND, INTERACTIVE] {
            pq.push(p, arc(&[p, 0xff, 0xff])); // reliable entries cannot be shed
            for seq in 0..LOSSY_REALTIME_MAX_DEPTH as u16 {
                pq.push_lossy(p, packet(p, seq));
            }
        }
        assert_eq!(pq.len(), 4 * (LOSSY_REALTIME_MAX_DEPTH + 1));
        assert_eq!(pq.drops_total(), 0);
        for p in [REALTIME, BULK, BACKGROUND, INTERACTIVE] {
            pq.push_lossy(p, packet(p, LOSSY_REALTIME_MAX_DEPTH as u16));
        }
        assert_eq!(pq.drops_total(), 4);
        let mut seen: [Vec<u16>; 4] = Default::default();
        while let Some(frame) = pq.pop() {
            let p = frame[0] as usize;
            seen[p].push(u16::from_be_bytes([frame[1], frame[2]]));
        }
        for lane in seen {
            assert_eq!(
                lane,
                std::iter::once(u16::MAX)
                    .chain(1..=LOSSY_REALTIME_MAX_DEPTH as u16)
                    .collect::<Vec<_>>()
            );
        }
        assert_eq!(pq.lossy_realtime_len, [0; 4]);
    }

    #[test]
    fn lossy_class_counters_survive_restore_expiry_and_aggregate_shedding() {
        let mut pq = PriorityQueue::with_capacity(DEFAULT_WEIGHTS, 4);
        for p in [REALTIME, BULK] {
            pq.push_lossy(p, arc(b"first"));
            pq.push_lossy(p, arc(b"second"));
        }
        let frame = pq.pop_realtime_if(|_| true).unwrap();
        assert_eq!(pq.lossy_realtime_len, [1, 0, 2, 0]);
        pq.push_realtime_front(frame);
        assert_eq!(pq.lossy_realtime_len, [2, 0, 2, 0]);
        pq.push_lossy(BACKGROUND, arc(b"must not evict higher classes"));
        assert_eq!(pq.lossy_realtime_len, [2, 0, 2, 0]);
        pq.push(INTERACTIVE, arc(b"reliable"));
        assert_eq!(pq.lossy_realtime_len, [2, 0, 1, 0]);
        for queued in &mut pq.queues[REALTIME as usize] {
            queued.enqueued_at =
                Some(Instant::now() - LOSSY_REALTIME_MAX_AGE - Duration::from_millis(1));
        }
        assert_eq!(
            &*pq.pop_envelope_if(|_, _| true).unwrap().frame.1,
            b"reliable"
        );
        assert_eq!(pq.lossy_realtime_len, [0, 0, 1, 0]);
        assert_eq!(
            &*pq.pop_local_datagram_envelope_if(|_| true).unwrap().frame.1,
            b"second"
        );
        assert_eq!(pq.lossy_realtime_len, [0; 4]);
        assert_eq!(pq.drops_total(), 4); // incoming, secondary victim, 2 expired
        assert!(pq.is_empty());
    }

    #[test]
    fn lossy_realtime_queue_keeps_newest_frames() {
        let drops = Arc::new(AtomicU64::new(0));
        let mut pq = PriorityQueue::with_capacity_and_drop_counter(
            DEFAULT_WEIGHTS,
            LOSSY_REALTIME_MAX_DEPTH + 8,
            Arc::clone(&drops),
        );
        for i in 0..=LOSSY_REALTIME_MAX_DEPTH {
            pq.push_lossy_realtime(REALTIME, arc(&(i as u16).to_be_bytes()));
        }
        assert_eq!(
            pq.lossy_realtime_len.iter().sum::<usize>(),
            LOSSY_REALTIME_MAX_DEPTH
        );
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(pq.pop().unwrap().as_ref(), 1u16.to_be_bytes());
    }

    #[test]
    fn stale_lossy_realtime_is_dropped_before_reliable_control() {
        let drops = Arc::new(AtomicU64::new(0));
        let mut pq =
            PriorityQueue::with_capacity_and_drop_counter(DEFAULT_WEIGHTS, 8, Arc::clone(&drops));
        pq.push_lossy_realtime(REALTIME, arc(b"old-media"));
        pq.queues[REALTIME as usize]
            .front_mut()
            .unwrap()
            .enqueued_at = Some(Instant::now() - LOSSY_REALTIME_MAX_AGE - Duration::from_millis(1));
        pq.push(REALTIME, arc(b"control"));
        assert_eq!(pq.pop().unwrap().as_ref(), b"control");
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(pq.lossy_realtime_len.iter().sum::<usize>(), 0);
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
    fn cycle8_f4_full_realtime_queue_drops_incoming_background_not_realtime() {
        let drops = Arc::new(AtomicU64::new(0));
        let mut pq =
            PriorityQueue::with_capacity_and_drop_counter(DEFAULT_WEIGHTS, 2, Arc::clone(&drops));
        pq.push(REALTIME, arc(b"rt0"));
        pq.push(REALTIME, arc(b"rt1"));
        // At depth — an incoming BACKGROUND must NOT evict a REALTIME frame.
        pq.push(BACKGROUND, arc(b"bg"));
        assert_eq!(drops.load(Ordering::Relaxed), 1, "incoming bg dropped");
        // Both REALTIME frames survive, in FIFO order; no bg leaked in.
        assert_eq!(pq.pop().unwrap().as_ref(), b"rt0");
        assert_eq!(pq.pop().unwrap().as_ref(), b"rt1");
        assert_eq!(pq.pop(), None);
    }

    #[test]
    fn cycle8_f4_incoming_realtime_sheds_lower_priority_background() {
        let drops = Arc::new(AtomicU64::new(0));
        let mut pq =
            PriorityQueue::with_capacity_and_drop_counter(DEFAULT_WEIGHTS, 2, Arc::clone(&drops));
        pq.push(BACKGROUND, arc(b"bg0"));
        pq.push(BACKGROUND, arc(b"bg1"));
        // Incoming REALTIME outranks queued BACKGROUND → shed oldest bg, admit rt.
        pq.push(REALTIME, arc(b"rt"));
        assert_eq!(drops.load(Ordering::Relaxed), 1, "one bg shed");
        assert_eq!(pq.pop().unwrap().as_ref(), b"rt", "REALTIME served first");
        assert_eq!(pq.pop().unwrap().as_ref(), b"bg1", "oldest bg0 was shed");
        assert_eq!(pq.pop(), None);
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
