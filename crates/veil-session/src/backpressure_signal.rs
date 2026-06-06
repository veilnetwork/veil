//! decomposition slice 22: encapsulates the
//! "send a Backpressure signal at most once per cooldown" gate.
//!
//! Was inline in `SessionRunner::run`:
//! ```ignore
//! const BP_SIGNAL_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(1);
//! let mut bp_last_sent: std::time::Instant =
//!     std::time::Instant::now() - BP_SIGNAL_COOLDOWN;
//! // ...
//! if now.duration_since(bp_last_sent) >= BP_SIGNAL_COOLDOWN {
//!     bp_last_sent = now;
//!     /* emit Backpressure frame */
//! }
//! ```
//!
//! Background — backpressure: when a peer exceeds its rate limit, the
//! receiver drops the offending frame and emits one Backpressure control
//! frame back so the peer marks us as congested and redistributes traffic.
//! The cooldown gate prevents spamming Backpressure frames in response
//! to a burst of rate-limited frames — a 1-second window is enough to
//! signal once-per-burst, not enough to saturate the reverse channel.
//!
//! Initial `last_sent = now - cooldown` so the FIRST event always fires
//! (no warm-up period where backpressure is silently swallowed).
//!
//! Why not just a timer arm? Backpressure is event-driven (fires only
//! when some other frame triggered RateLimited dispatch), not
//! periodic. Bundling it with the existing Timer arm would require a
//! state machine to track "do we have a pending BP to emit" — simpler
//! to keep the trigger inline and gate only the cooldown.

use std::time::{Duration, Instant};

/// Cooldown-gated "should-I-emit-Backpressure" predicate.
pub struct BackpressureSignal {
    last_sent: Instant,
    cooldown: Duration,
}

impl BackpressureSignal {
    /// Build with the configured cooldown.  `last_sent` initialised
    /// to `now - cooldown` so [try_arm] returns `true` on the very
    /// first call (no warm-up suppression).
    pub fn new(cooldown: Duration) -> Self {
        Self {
            last_sent: Instant::now() - cooldown,
            cooldown,
        }
    }

    /// Returns `true` if at least [cooldown] has elapsed since
    /// the previous successful arm.  On `true` the internal clock
    /// advances to `now` — subsequent calls within the cooldown
    /// window return `false`.
    pub fn try_arm(&mut self, now: Instant) -> bool {
        if now.duration_since(self.last_sent) >= self.cooldown {
            self.last_sent = now;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// First call always returns true regardless of how soon after
    /// construction it fires (warm-up suppression would be a bug).
    #[test]
    fn first_arm_fires_immediately() {
        let mut bp = BackpressureSignal::new(Duration::from_secs(1));
        let t0 = Instant::now();
        assert!(bp.try_arm(t0), "first arm must succeed immediately");
    }

    /// Two arms within the cooldown window: only the first fires.
    #[test]
    fn arms_within_cooldown_window_are_suppressed() {
        let mut bp = BackpressureSignal::new(Duration::from_secs(1));
        let t0 = Instant::now();
        assert!(bp.try_arm(t0));
        let t1 = t0 + Duration::from_millis(500);
        assert!(
            !bp.try_arm(t1),
            "second arm within 500 ms must be suppressed"
        );
    }

    /// Arming exactly at the cooldown boundary fires (>= cooldown,
    /// not strict >).
    #[test]
    fn arm_at_cooldown_boundary_fires() {
        let mut bp = BackpressureSignal::new(Duration::from_secs(1));
        let t0 = Instant::now();
        assert!(bp.try_arm(t0));
        let t1 = t0 + Duration::from_secs(1);
        assert!(
            bp.try_arm(t1),
            "arm at exactly +cooldown must fire (>= boundary)"
        );
    }

    /// Three arms — at t=0, t=0.7 (suppressed), t=1.0 (fires again).
    /// Verifies the cooldown clock advances on success, not on every call.
    #[test]
    fn cooldown_advances_only_on_successful_arm() {
        let mut bp = BackpressureSignal::new(Duration::from_secs(1));
        let t0 = Instant::now();
        assert!(bp.try_arm(t0));
        let t1 = t0 + Duration::from_millis(700);
        assert!(!bp.try_arm(t1));
        let t2 = t0 + Duration::from_secs(1);
        // t2 is exactly 1s after t0 (the LAST successful arm), not
        // after t1 (suppressed) — must fire.
        assert!(bp.try_arm(t2));
        // Immediately after t2 — within the new cooldown window.
        let t3 = t2 + Duration::from_millis(100);
        assert!(!bp.try_arm(t3));
    }
}
