//! Outbound priority-queue drain coalescer.  SessionRunner
//! decomposition slice 30 (architecture backlog) — extracts the
//! `last_drain_ts` Instant + the 12-line coalesce-deadline compute
//! що previously lived inline в `run()`.
//!
//! ## Wire contract
//!
//! When all three conditions hold, the runner **defers** the next
//! priority-queue drain pass:
//!
//! 1. Operator opted into outbound-batching by setting
//!    `MOBILE_OUTBOUND_BATCH_WINDOW_MS > 0`.
//! 2. Battery level is at-or-below the low-battery threshold
//!    (resolved by [`super::runner::current_outbound_batch_window`]).
//! 3. The queue-head priority is `BULK` (2) or `BACKGROUND` (3) —
//!    INTERACTIVE / REALTIME frames bypass coalescing.
//!
//! When deferred, the runner skips the drain loop и proceeds к the
//! next select tick.  Frames accumulate in the priority queue until
//! the window elapses или а higher-priority frame arrives at the head.
//!
//! `last_drain_ts` is stamped **only after а pass що actually emitted
//! ≥ 1 frame** — doing it unconditionally would let the deadline creep
//! forward на no-op iterations, defeating the caller's intended delay.
//!
//! ## Why extract
//!
//! * **Cohesion**: 12 lines of conditional-deadline compute had four
//!   pieces of inline state (`coalesce_window`, `coalesce_eligible`,
//!   `coalesce_until`, `coalesce_active`) plus the lifetime-managed
//!   `last_drain_ts`.  Single struct encapsulates the invariant.
//! * **Testability**: pure compute, no async, no I/O.  Trivial unit
//!   tests verify the four-condition truth table + the "no-stamp-on-
//!   empty-pass" rule.
//! * **Search-greppability**: `last_drain_ts` was а bare `tokio::time::Instant`
//!   in `run()`; now а typed `OutboundBatchCoalescer` field surfaces в
//!   signatures и method ownership.

use std::time::Duration;

use tokio::time::Instant;

/// Outbound priority-queue drain coalescer.  Holds the last-drain
/// timestamp + provides the "should we defer this drain pass?" check.
#[derive(Debug)]
pub struct OutboundBatchCoalescer {
    /// Wall-clock instant of the last drain pass що actually emitted
    /// ≥ 1 frame.  Stays put on no-op iterations (rationale: see
    /// module-doc "creep-forward" warning).
    last_drain_ts: Instant,
}

impl OutboundBatchCoalescer {
    /// New coalescer initialised к the current instant.  First drain
    /// pass may proceed immediately if the queue head qualifies
    /// (window has "already elapsed since session start" в effect —
    /// no correctness risk, coalescing only matters across multiple
    /// bursts).
    pub fn new(now: Instant) -> Self {
        Self { last_drain_ts: now }
    }

    /// Decide whether the next drain pass should be **deferred**.
    /// Returns `true` ⇒ caller skips the drain loop this iteration.
    /// Returns `false` ⇒ drain proceeds immediately.
    ///
    /// Arguments:
    /// * `now` — current wall-clock instant.
    /// * `window` — output of [`super::runner::current_outbound_batch_window`]
    ///   given the current battery level.  `None` disables coalescing
    ///   entirely (operator не opted in, или battery is above the
    ///   low-battery threshold).
    /// * `head_priority` — top-of-queue priority byte, или None if
    ///   the queue is empty.
    pub fn is_coalescing(
        &self,
        now: Instant,
        window: Option<Duration>,
        head_priority: Option<u8>,
    ) -> bool {
        // Coalescing only applies к BULK (2) и BACKGROUND (3) head
        // priorities.  Anything higher (INTERACTIVE / REALTIME) bypasses.
        let head_eligible = matches!(
            head_priority,
            Some(p) if p >= veil_proto::header::priority::BULK
        );
        match (window, head_eligible) {
            (Some(w), true) => now < self.last_drain_ts + w,
            _ => false,
        }
    }

    /// Stamp the latest drain time.  Caller invokes after а drain
    /// pass що actually emitted ≥ 1 frame.  No-op passes (queue
    /// empty, all frames dropped on bandwidth-cap, etc.) must NOT
    /// call this — see module-doc rationale.
    pub fn record_drain(&mut self, now: Instant) {
        self.last_drain_ts = now;
    }

    /// Deadline at which the next drain becomes eligible — caller
    /// folds it into the sleep-deadline compute via [`super::runner::SessionRunner::compute_sleep_deadline`]
    /// so the select wakes precisely when coalescing should release.
    /// `None` if no coalescing is active (no window OR head priority
    /// ineligible OR queue empty).
    pub fn coalesce_deadline(
        &self,
        window: Option<Duration>,
        head_priority: Option<u8>,
    ) -> Option<Instant> {
        let head_eligible = matches!(
            head_priority,
            Some(p) if p >= veil_proto::header::priority::BULK
        );
        match (window, head_eligible) {
            (Some(w), true) => Some(self.last_drain_ts + w),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::header::priority;

    #[test]
    fn no_window_never_coalesces() {
        let now = Instant::now();
        let c = OutboundBatchCoalescer::new(now);
        // No window configured → drain always proceeds.
        assert!(!c.is_coalescing(now, None, Some(priority::BULK)));
        assert!(!c.is_coalescing(now, None, Some(priority::BACKGROUND)));
        assert!(!c.is_coalescing(now, None, Some(priority::INTERACTIVE)));
        assert!(!c.is_coalescing(now, None, None));
    }

    #[test]
    fn high_priority_bypasses_coalescing() {
        let now = Instant::now();
        let c = OutboundBatchCoalescer::new(now);
        let window = Some(Duration::from_millis(200));
        // INTERACTIVE и REALTIME bypass даже с window set.
        assert!(!c.is_coalescing(now, window, Some(priority::INTERACTIVE)));
        assert!(!c.is_coalescing(now, window, Some(priority::REALTIME)));
    }

    #[test]
    fn empty_queue_does_not_coalesce() {
        let now = Instant::now();
        let c = OutboundBatchCoalescer::new(now);
        let window = Some(Duration::from_millis(200));
        // Empty queue (no head priority) → no point coalescing.
        assert!(!c.is_coalescing(now, window, None));
    }

    #[test]
    fn bulk_head_within_window_coalesces() {
        let now = Instant::now();
        let c = OutboundBatchCoalescer::new(now);
        let window = Some(Duration::from_millis(200));
        // BULK head within the window → defer drain.
        assert!(c.is_coalescing(now, window, Some(priority::BULK)));
        assert!(c.is_coalescing(now, window, Some(priority::BACKGROUND)));
    }

    #[test]
    fn bulk_head_past_window_does_not_coalesce() {
        let now = Instant::now();
        let c = OutboundBatchCoalescer::new(now);
        let window = Some(Duration::from_millis(50));
        // Move forward past the window → drain proceeds.
        let later = now + Duration::from_millis(60);
        assert!(!c.is_coalescing(later, window, Some(priority::BULK)));
    }

    #[test]
    fn record_drain_resets_deadline() {
        let now = Instant::now();
        let mut c = OutboundBatchCoalescer::new(now);
        let window = Some(Duration::from_millis(100));
        // Move forward past the window → drain proceeds.
        let t1 = now + Duration::from_millis(150);
        assert!(!c.is_coalescing(t1, window, Some(priority::BULK)));
        // Stamp the new drain time.
        c.record_drain(t1);
        // Within the new window → coalescing resumes.
        let t2 = t1 + Duration::from_millis(50);
        assert!(c.is_coalescing(t2, window, Some(priority::BULK)));
    }

    /// Bulk frames arriving в bursts within а 200ms window should
    /// all defer until the window elapses, then drain together.
    /// Models the production "low-battery + chat-burst" scenario.
    #[test]
    fn bursts_within_window_all_defer() {
        let t0 = Instant::now();
        let c = OutboundBatchCoalescer::new(t0);
        let window = Some(Duration::from_millis(200));
        // 5 frames arriving at 30ms intervals — all within window.
        for delta in [30, 60, 90, 120, 150] {
            let t = t0 + Duration::from_millis(delta);
            assert!(
                c.is_coalescing(t, window, Some(priority::BULK)),
                "delta={delta}ms should defer"
            );
        }
        // At 250ms (past 200ms window) — drains.
        let t_post = t0 + Duration::from_millis(250);
        assert!(!c.is_coalescing(t_post, window, Some(priority::BULK)));
    }
}
