//! Per-peer in-line packet loss tracker.
//!
//! Counts ACK successes vs ACK timeouts/retransmits per `next_hop` peer
//! over a sliding window so the dispatcher can fast-demote routes through
//! a flaky peer **before** the next periodic ROUTE_PROBE catches up
//! (probes run on a 5-120 s adaptive interval; this tracker reacts in
//! 5-30 s on production traffic).
//!
//! Hooks into the existing `PendingAckTracker`:
//! * `record_success(peer)` — called on `ack_and_get_info` (DELIVERED ACK).
//! * `record_loss(peer)` — called on `tick` Retransmit/Failed outcomes
//!   (a frame timed out without ACK; `attempt > 1` already implies one
//!   round of loss).
//!
//! The 5-second evaluation tick computes `loss_rate = losses / (losses
//! + successes)` over the last `window_secs`. When `loss_rate > threshold`
//! AND `samples ≥ min_samples` (avoid noise on idle sessions), the caller
//! is expected to invoke `RouteCache::demote_via(peer, factor)`.
//!
//! Why a separate type vs reusing `RttProbe`: probes carry RTT semantics
//! (smoothed_rtt, jitter, vivaldi coords) updated at probe cadence. This
//! is loss-rate over **production frames** at sub-second resolution;
//! mixing the two would require wider mutex contention for what is
//! semantically a counter, not a measurement.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Sliding-window per-peer counter. Re-zeros on `window_secs` boundary
/// — simpler than a true rolling window, costs the same in steady state
/// and the operator-visible loss-rate is still meaningful (last full window).
#[derive(Debug, Clone, Copy)]
pub struct PeerCounters {
    /// Frames acknowledged in the current window.
    pub successes: u32,
    /// Frames that timed out without ACK (retransmit or final fail) in
    /// the current window.
    pub losses: u32,
    /// When the current window started.
    pub window_start: Instant,
    /// Latest computed loss-rate from the *previous* full window
    /// (0.0..=1.0). Surfaced via `node sessions` for operator visibility.
    pub last_loss_rate: f32,
    /// Sample count from the previous full window. Used to decide
    /// whether the rate is statistically meaningful.
    pub last_samples: u32,
}

impl PeerCounters {
    fn new(now: Instant) -> Self {
        Self {
            successes: 0,
            losses: 0,
            window_start: now,
            last_loss_rate: 0.0,
            last_samples: 0,
        }
    }
}

/// Bounded per-peer loss-rate tracker. Concurrency: a single `Mutex`
/// guards the whole map; per-peer locking would over-engineer for a
/// counter that's incremented at most a few thousand times per second
/// (one per delivery ACK) across *all* peers combined.
pub struct LossTracker {
    inner: Mutex<HashMap<[u8; 32], PeerCounters>>,
    /// How long each tally window lasts. When elapsed, counters are
    /// rolled into `last_loss_rate` / `last_samples` and reset.
    window: Duration,
    /// Cap on the number of distinct peers tracked simultaneously.
    /// Prevents unbounded growth if the node sees a churn of one-shot
    /// short-lived peers.
    max_entries: usize,
}

impl LossTracker {
    /// Default 30-second window, 4096-peer cap. See module doc for
    /// rationale.
    pub const DEFAULT_WINDOW_SECS: u64 = 30;
    pub const DEFAULT_MAX_ENTRIES: usize = 4096;

    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            window: Duration::from_secs(Self::DEFAULT_WINDOW_SECS),
            max_entries: Self::DEFAULT_MAX_ENTRIES,
        }
    }

    /// Construct with explicit window and capacity (used by tests for
    /// short windows + low caps so we can exercise rollover quickly).
    pub fn with_capacity(window_secs: u64, max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            window: Duration::from_secs(window_secs),
            max_entries,
        }
    }

    /// Record a successful DELIVERED ACK from `peer` (acting as `next_hop`).
    pub fn record_success(&self, peer: [u8; 32]) {
        self.bump(peer, |c| c.successes = c.successes.saturating_add(1));
    }

    /// Record an ACK timeout (Retransmit or Failed) for a frame whose
    /// `next_hop` was `peer`. Both Retransmit and Failed count as one
    /// loss event — Retransmit means "didn't ack within DELIVERY_ACK_TIMEOUT"
    /// Failed means "exhausted MAX_DELIVERY_ATTEMPTS".
    pub fn record_loss(&self, peer: [u8; 32]) {
        self.bump(peer, |c| c.losses = c.losses.saturating_add(1));
    }

    fn bump(&self, peer: [u8; 32], op: impl FnOnce(&mut PeerCounters)) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        // Cap: when at-cap AND inserting a new peer, drop the entry
        // with the OLDEST `window_start` so eviction is deterministic
        // and predictable. / : previous code
        // tried to find a "truly idle" entry first via `iter.find`
        // but HashMap iter order — while randomised — can still
        // create within-run bias toward whichever peer happens to
        // bucket first. Always picking the oldest window_start
        // gives a fair, deterministic eviction policy that maps
        // naturally to "evict whoever hasn't reported anything
        // recently."
        if !inner.contains_key(&peer)
            && inner.len() >= self.max_entries
            && let Some(oldest) = inner
                .iter()
                .min_by_key(|(_, c)| c.window_start)
                .map(|(k, _)| *k)
        {
            inner.remove(&oldest);
        }
        let entry = inner.entry(peer).or_insert_with(|| PeerCounters::new(now));
        op(entry);
    }

    /// Roll counters into `last_*` and zero them for any peer whose
    /// current window has elapsed. Returns `(peer, loss_rate, samples)`
    /// for every peer whose just-ended window had at least one sample
    /// so the caller can decide which ones to act on.
    ///
    /// Call this from a periodic task at any interval ≤ window_secs;
    /// the rollover happens lazily so calling more often is harmless
    /// (no-op until the window actually elapses).
    pub fn evaluate_window(
        &self,
    ) -> Vec<(
        /*peer*/ [u8; 32],
        /*loss_rate*/ f32,
        /*samples*/ u32,
    )> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let mut out = Vec::new();
        for (peer, counters) in inner.iter_mut() {
            if now.duration_since(counters.window_start) < self.window {
                continue;
            }
            let samples = counters.successes.saturating_add(counters.losses);
            let rate = if samples == 0 {
                0.0
            } else {
                counters.losses as f32 / samples as f32
            };
            counters.last_loss_rate = rate;
            counters.last_samples = samples;
            counters.successes = 0;
            counters.losses = 0;
            counters.window_start = now;
            if samples > 0 {
                out.push((*peer, rate, samples));
            }
        }
        out
    }

    /// Snapshot the most-recent fully-evaluated stats per peer (for the
    /// `node sessions` admin output). Includes peers with zero samples
    /// in the last window so operators see "still tracked, just quiet".
    pub fn snapshot(
        &self,
    ) -> Vec<(
        /*peer*/ [u8; 32],
        /*loss_rate*/ f32,
        /*samples*/ u32,
    )> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        inner
            .iter()
            .map(|(peer, c)| (*peer, c.last_loss_rate, c.last_samples))
            .collect()
    }

    /// Drop the entry for `peer` — called on session close so a stale
    /// loss-rate doesn't influence reconnect decisions.
    pub fn forget(&self, peer: &[u8; 32]) {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(peer);
    }

    /// Test/introspection helper: how many peers are currently tracked.
    /// gated — only consumed by unit tests in this file.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    /// Companion [`Self::len`] — required by clippy's
    /// `len_without_is_empty` lint when `len` is visible, and same
    /// test-only scope.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty()
    }
}

impl Default for LossTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tracker_evaluates_to_nothing() {
        let lt = LossTracker::new();
        assert!(lt.evaluate_window().is_empty());
    }

    #[test]
    fn record_success_then_loss_counts_both() {
        let lt = LossTracker::with_capacity(1, 100);
        let peer = [0xAA; 32];
        for _ in 0..7 {
            lt.record_success(peer);
        }
        for _ in 0..3 {
            lt.record_loss(peer);
        }
        // Wait past window then evaluate.
        std::thread::sleep(Duration::from_millis(1100));
        let evals = lt.evaluate_window();
        assert_eq!(evals.len(), 1);
        let (p, rate, samples) = evals[0];
        assert_eq!(p, peer);
        assert_eq!(samples, 10);
        // 3 losses out of 10 = 0.30
        assert!((rate - 0.30).abs() < 0.01, "expected ≈0.30, got {rate}");
    }

    #[test]
    fn evaluate_skips_in_window_peers() {
        // Default 30s window — record but DON'T sleep → evaluate_window
        // returns nothing (window not elapsed).
        let lt = LossTracker::new();
        lt.record_success([0xBB; 32]);
        lt.record_loss([0xBB; 32]);
        assert!(
            lt.evaluate_window().is_empty(),
            "in-progress window must not produce output"
        );
    }

    #[test]
    fn rollover_resets_counters_for_next_window() {
        let lt = LossTracker::with_capacity(1, 100);
        let peer = [0xCC; 32];
        for _ in 0..10 {
            lt.record_loss(peer);
        }
        std::thread::sleep(Duration::from_millis(1100));
        let evals = lt.evaluate_window();
        assert_eq!(evals[0].2, 10, "first window: 10 losses");

        // Second window — only successes this time.
        for _ in 0..5 {
            lt.record_success(peer);
        }
        std::thread::sleep(Duration::from_millis(1100));
        let evals = lt.evaluate_window();
        assert_eq!(evals[0].2, 5, "second window: counter reset, 5 successes");
        assert_eq!(evals[0].1, 0.0, "no losses → rate 0.0");
    }

    #[test]
    fn forget_removes_peer_immediately() {
        let lt = LossTracker::with_capacity(1, 100);
        let peer = [0xDD; 32];
        lt.record_success(peer);
        assert_eq!(lt.len(), 1);
        lt.forget(&peer);
        assert_eq!(lt.len(), 0);
    }

    #[test]
    fn snapshot_includes_peers_with_no_samples() {
        // After rollover, last_samples may stay non-zero from prior window
        // even if the current window is empty — operators still see them.
        let lt = LossTracker::with_capacity(1, 100);
        let peer = [0xEE; 32];
        for _ in 0..3 {
            lt.record_loss(peer);
        }
        std::thread::sleep(Duration::from_millis(1100));
        let _ = lt.evaluate_window();
        // No new activity in second window — snapshot still shows the
        // peer with last_samples=3, last_loss_rate=1.0.
        let snap = lt.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, peer);
        assert_eq!(snap[0].1, 1.0);
        assert_eq!(snap[0].2, 3);
    }

    #[test]
    fn cap_evicts_idle_peer_when_full() {
        // Cap=3. Insert 3 with no activity, then a 4th peer triggers
        // eviction of one of the idle ones (success+loss == 0).
        let lt = LossTracker::with_capacity(60, 3);
        // Make first three "stale" (no activity at all means they get
        // recorded with init counters but no successes/losses). Use
        // record_success then forget? No — we want stale entries.
        // Trick: insert successfully then immediately reset by direct
        // map manipulation — not exposed. Instead: 3 peers each with
        // 1 success, then evaluate (rolls into last_*, current=0,0)
        // then a 4th peer → one of the now-idle three should be evicted.
        for i in 1u8..=3 {
            let mut k = [0u8; 32];
            k[0] = i;
            lt.record_success(k);
        }
        assert_eq!(lt.len(), 3);
        std::thread::sleep(Duration::from_millis(50)); // not past 60s window
        // bump cap to 3 was already done; just insert a 4th, forces eviction
        lt.record_success([0xFF; 32]);
        // Some peer was evicted; total is still 3 (the cap).
        assert_eq!(lt.len(), 3, "cap must hold");
    }
}
