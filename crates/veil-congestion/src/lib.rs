//! Node congestion monitoring.
//!
//! [`CongestionMonitor`] tracks the current load on this node and exposes:
//!
//! * `score -> f64` — overall congestion in `0.0` (free).. `1.0` (saturated)
//!   computed as `max(relay_ratio, session_ratio, queue_ratio)` over the enabled
//!   dimensions. Using `max` rather than a product correctly identifies
//!   bottleneck resources without underreporting at moderate load.
//!
//! * `score_u8 -> u8` — the score scaled to `0..=255` for wire encoding.
//!
//! * `is_admitting -> bool` — whether the node is currently accepting new
//!   relay sessions. Transitions from `true` to `false` when `score` exceeds
//!   `congestion_high`, and back to `true` only after `score` drops below
//!   `congestion_low` (hysteresis).
//!
//! All mutable state is held inside an [`std::sync::Mutex`] so the monitor can
//! be shared across threads via `Arc<CongestionMonitor>`.

use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use tokio::sync::watch;

use veil_cfg::NodeCapacityConfig;

/// Thread-safe congestion monitor for a single node.
pub struct CongestionMonitor {
    cfg: NodeCapacityConfig,

    // ── Counters updated by the runtime ────────────────────────────────────
    /// Number of active relay sessions (updated by dispatcher).
    relay_sessions: AtomicUsize,
    /// Total active sessions including direct (updated by runtime).
    total_sessions: AtomicUsize,
    /// Current TX queue depth (frames queued across all sessions).
    tx_queue_depth: AtomicUsize,
    /// Maximum TX queue capacity (set once at startup from SessionConfig).
    tx_queue_capacity: AtomicUsize,

    // ── Derived state with hysteresis ──────────────────────────────────────
    /// Whether the node is currently accepting new relay sessions.
    admitting: AtomicBool,
    /// Guards hysteresis state transitions.
    hysteresis: Mutex<HysteresisState>,

    // ── Admitting-state change notifications ──────────────────
    /// Sends `true` when the node starts admitting, `false` when it stops.
    /// Subscribers (e.g. the routing dispatcher) react by withdrawing or
    /// re-announcing the local node in the routing gossip.
    admitting_tx: watch::Sender<bool>,
    /// Public receiver — clone this to subscribe.
    pub admitting_rx: watch::Receiver<bool>,
}

struct HysteresisState {
    /// Last computed score — used to detect transitions without re-computing.
    last_score: f64,
}

impl CongestionMonitor {
    /// Create a new monitor from config. All counters start at zero and the
    /// node starts in the admitting state.
    pub fn new(cfg: NodeCapacityConfig, tx_queue_capacity: usize) -> Self {
        let (admitting_tx, admitting_rx) = watch::channel(true);
        Self {
            cfg,
            relay_sessions: AtomicUsize::new(0),
            total_sessions: AtomicUsize::new(0),
            tx_queue_depth: AtomicUsize::new(0),
            tx_queue_capacity: AtomicUsize::new(tx_queue_capacity),
            admitting: AtomicBool::new(true),
            hysteresis: Mutex::new(HysteresisState { last_score: 0.0 }),
            admitting_tx,
            admitting_rx,
        }
    }

    // ── Counter updates ────────────────────────────────────────────────────

    pub fn set_relay_sessions(&self, n: usize) {
        self.relay_sessions.store(n, Ordering::Relaxed);
        self.update_hysteresis();
    }

    pub fn set_total_sessions(&self, n: usize) {
        self.total_sessions.store(n, Ordering::Relaxed);
        self.update_hysteresis();
    }

    pub fn set_tx_queue_depth(&self, depth: usize) {
        self.tx_queue_depth.store(depth, Ordering::Relaxed);
        self.update_hysteresis();
    }

    // ── Score computation ──────────────────────────────────────────────────

    /// Overall congestion score in `0.0` (free).. `1.0` (saturated).
    ///
    /// `score = max(enabled_factors)` where each factor is
    /// `actual / limit` clamped to `[0.0, 1.0]`.
    pub fn score(&self) -> f64 {
        let mut score = 0.0_f64;

        // Relay session ratio.
        let max_relay = self.cfg.max_relay_sessions;
        if max_relay > 0 {
            let relay = self.relay_sessions.load(Ordering::Relaxed);
            score = score.max((relay as f64 / max_relay as f64).min(1.0));
        }

        // Total session ratio.
        let max_total = self.cfg.max_total_sessions;
        if max_total > 0 {
            let total = self.total_sessions.load(Ordering::Relaxed);
            score = score.max((total as f64 / max_total as f64).min(1.0));
        }

        // TX queue ratio (always enabled when capacity > 0).
        let capacity = self.tx_queue_capacity.load(Ordering::Relaxed);
        if capacity > 0 {
            let depth = self.tx_queue_depth.load(Ordering::Relaxed);
            let queue_ratio = depth as f64 / capacity as f64;
            // Only count queue pressure above the configured watermark.
            let wm = self.cfg.tx_queue_high_watermark;
            if queue_ratio > wm {
                // Map [wm, 1.0] → [0.0, 1.0] so the score rises smoothly
                // once the watermark is crossed.
                let normalized = ((queue_ratio - wm) / (1.0 - wm + f64::EPSILON)).min(1.0);
                score = score.max(normalized);
            }
        }

        score
    }

    /// Score encoded as `u8` (0 = free, 255 = saturated) for wire transmission.
    pub fn score_u8(&self) -> u8 {
        (self.score() * 255.0).round() as u8
    }

    /// Whether this node is currently accepting new relay sessions.
    pub fn is_admitting(&self) -> bool {
        self.admitting.load(Ordering::Relaxed)
    }

    // ── Internal ───────────────────────────────────────────────────────────

    fn update_hysteresis(&self) {
        let score = self.score();
        // Fast path: skip mutex if score hasn't changed significantly.
        let mut state = self.hysteresis.lock().unwrap_or_else(|p| p.into_inner());
        let prev = state.last_score;
        if (score - prev).abs() < 0.005 {
            return;
        }
        state.last_score = score;
        // Hold the hysteresis lock across the admitting transition so the
        // score snapshot, the admitting read/store, and the watch send are one
        // serialized step. If the lock were released first (the old `drop`),
        // two concurrent updaters could interleave the read-modify-write of
        // `admitting` and deliver out-of-order true/false notifications to the
        // routing dispatcher (e.g. a stale `false` arriving after a newer
        // `true`). The watch send is non-blocking, so holding the std Mutex
        // across it cannot stall. `state` is dropped at end of scope.
        let currently_admitting = self.admitting.load(Ordering::Relaxed);
        if currently_admitting && score >= self.cfg.congestion_high {
            self.admitting.store(false, Ordering::Relaxed);
            let _ = self.admitting_tx.send(false);
        } else if !currently_admitting && score <= self.cfg.congestion_low {
            self.admitting.store(true, Ordering::Relaxed);
            let _ = self.admitting_tx.send(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor_with_limits(
        max_relay: usize,
        max_total: usize,
        queue_cap: usize,
    ) -> CongestionMonitor {
        CongestionMonitor::new(
            NodeCapacityConfig {
                max_relay_sessions: max_relay,
                max_total_sessions: max_total,
                max_inbound_bandwidth_kbps: -1,
                max_outbound_bandwidth_kbps: -1,
                tx_queue_high_watermark: 0.8,
                congestion_high: 0.8,
                congestion_low: 0.6,
            },
            queue_cap,
        )
    }

    #[test]
    fn score_zero_when_idle() {
        let m = monitor_with_limits(100, 200, 1000);
        assert_eq!(m.score(), 0.0);
        assert!(m.is_admitting());
    }

    #[test]
    fn score_uses_max_not_product() {
        let m = monitor_with_limits(100, 200, 0);
        m.set_relay_sessions(50); // 0.50
        m.set_total_sessions(100); // 0.50
        // product would be 0.25; max should be 0.50
        let s = m.score();
        assert!((s - 0.5).abs() < 0.01, "expected 0.5 got {s}");
    }

    #[test]
    fn bottleneck_dominates() {
        let m = monitor_with_limits(100, 200, 0);
        m.set_relay_sessions(95); // 0.95
        m.set_total_sessions(10); // 0.05
        let s = m.score();
        assert!((s - 0.95).abs() < 0.01, "expected 0.95 got {s}");
    }

    #[test]
    fn hysteresis_high_to_low() {
        let m = monitor_with_limits(100, 0, 0);
        assert!(m.is_admitting());
        // Cross high threshold → stop admitting.
        m.set_relay_sessions(85);
        assert!(
            !m.is_admitting(),
            "should stop admitting above congestion_high"
        );
        // Drop below high but not below low → still not admitting.
        m.set_relay_sessions(70);
        assert!(!m.is_admitting(), "still congested between low and high");
        // Drop below low → resume admitting.
        m.set_relay_sessions(55);
        assert!(
            m.is_admitting(),
            "should resume admitting below congestion_low"
        );
    }

    #[test]
    fn queue_watermark_not_triggered_below_wm() {
        let m = monitor_with_limits(0, 0, 1000);
        m.set_tx_queue_depth(750); // 75%, below 80% watermark
        assert_eq!(m.score(), 0.0);
    }

    #[test]
    fn queue_watermark_triggered_above_wm() {
        let m = monitor_with_limits(0, 0, 1000);
        m.set_tx_queue_depth(900); // 90%, above 80% watermark
        assert!(m.score() > 0.0);
    }

    #[test]
    fn score_u8_saturates_at_255() {
        let m = monitor_with_limits(10, 0, 0);
        m.set_relay_sessions(10); // 100%
        assert_eq!(m.score_u8(), 255);
    }

    #[test]
    fn unlimited_dims_ignored() {
        // max_relay=0 means disabled; even with sessions the score stays 0
        // (only queue matters, and we set no queue cap)
        let m = monitor_with_limits(0, 0, 0);
        m.set_relay_sessions(9999);
        m.set_total_sessions(9999);
        assert_eq!(m.score(), 0.0);
    }
}
