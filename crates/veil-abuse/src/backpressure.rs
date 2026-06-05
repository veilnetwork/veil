//! AIMD backpressure signal for sender-side rate adaptation.
//!
//! `BackpressureAimd` implements Additive-Increase / Multiplicative-Decrease
//! congestion control as used in TCP:
//!
//! On **success** (no congestion reported): `rate += additive_increase`
//! On **congestion** (backpressure received): `rate *= multiplicative_decrease`
//!
//! The rate is clamped to `[min_rate, max_rate]`.
//!
//! # Wire protocol sketch
//!
//! When a node is overloaded it can reply with a `Backpressure { delay_ms }`
//! control message. The sender passes the signal into `on_congestion` and
//! reduces its send rate. When subsequent frames succeed the sender calls
//! `on_success` to gradually recover.

// ── BackpressureAimd ──────────────────────────────────────────────────────────

/// AIMD rate controller for veil sender nodes.
///
/// Units of `rate` are caller-defined (e.g. frames/sec, bytes/sec, kbps).
/// The `additive_increase` and `multiplicative_decrease` must be tuned to match.
#[derive(Debug, Clone)]
pub struct BackpressureAimd {
    /// Current send rate.
    rate: f64,
    /// Lower bound on rate (never goes below this).
    min_rate: f64,
    /// Upper bound on rate.
    max_rate: f64,
    /// Amount added to `rate` on each successful round-trip.
    additive_increase: f64,
    /// Factor applied to `rate` on each congestion signal (must be < 1.0).
    multiplicative_decrease: f64,
}

impl BackpressureAimd {
    /// Create a new AIMD controller.
    ///
    /// * `initial_rate` — starting rate.
    /// * `min_rate` / `max_rate` — clamp bounds.
    /// * `additive_increase` — per-success addend (typical TCP: 1 MSS/RTT).
    /// * `multiplicative_decrease` — per-congestion multiplier (typical TCP: 0.5).
    pub fn new(
        initial_rate: f64,
        min_rate: f64,
        max_rate: f64,
        additive_increase: f64,
        multiplicative_decrease: f64,
    ) -> Self {
        // Clamp to sane defaults instead of panicking on bad config.
        let min_rate = if min_rate > 0.0 { min_rate } else { 1.0 };
        let max_rate = if max_rate >= min_rate {
            max_rate
        } else {
            min_rate
        };
        let additive_increase = if additive_increase > 0.0 {
            additive_increase
        } else {
            1.0
        };
        let multiplicative_decrease = multiplicative_decrease.clamp(0.01, 0.99);
        Self {
            rate: initial_rate.clamp(min_rate, max_rate),
            min_rate,
            max_rate,
            additive_increase,
            multiplicative_decrease,
        }
    }

    /// Inform the controller that a frame was successfully delivered.
    ///
    /// Rate is increased additively and clamped to `max_rate`.
    pub fn on_success(&mut self) {
        self.rate = (self.rate + self.additive_increase).min(self.max_rate);
    }

    /// Inform the controller that a congestion signal was received.
    ///
    /// Rate is decreased multiplicatively and clamped to `min_rate`.
    pub fn on_congestion(&mut self) {
        self.rate = (self.rate * self.multiplicative_decrease).max(self.min_rate);
    }

    /// Current send rate.
    pub fn rate(&self) -> f64 {
        self.rate
    }

    /// `true` if the rate has been reduced to `min_rate` (fully backed off).
    pub fn is_at_minimum(&self) -> bool {
        (self.rate - self.min_rate).abs() < f64::EPSILON
    }

    /// `true` if the rate is at `max_rate` (fully recovered).
    pub fn is_at_maximum(&self) -> bool {
        (self.rate - self.max_rate).abs() < f64::EPSILON
    }
}

impl Default for BackpressureAimd {
    /// Sensible defaults for an veil node sending at ~100 frames/sec.
    fn default() -> Self {
        Self::new(
            100.0,  // initial_rate: 100 fps
            1.0,    // min_rate: 1 fps
            1000.0, // max_rate: 1000 fps
            1.0,    // additive_increase: +1 fps per success
            0.5,    // multiplicative_decrease: halve on congestion
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aimd() -> BackpressureAimd {
        BackpressureAimd::new(100.0, 1.0, 200.0, 10.0, 0.5)
    }

    #[test]
    fn congestion_halves_rate() {
        let mut a = aimd();
        let before = a.rate();
        a.on_congestion();
        assert!(
            (a.rate() - before * 0.5).abs() < f64::EPSILON,
            "rate should halve: {} -> {}",
            before,
            a.rate()
        );
    }

    #[test]
    fn success_increases_rate_additively() {
        let mut a = aimd();
        let before = a.rate();
        a.on_success();
        assert!(
            (a.rate() - (before + 10.0)).abs() < f64::EPSILON,
            "rate should increase by 10: {} -> {}",
            before,
            a.rate()
        );
    }

    #[test]
    fn rate_clamped_to_max() {
        let mut a = aimd();
        for _ in 0..100 {
            a.on_success();
        }
        assert!(a.rate() <= 200.0, "rate must not exceed max_rate");
        assert!(
            a.is_at_maximum(),
            "should be at maximum after many successes"
        );
    }

    #[test]
    fn rate_clamped_to_min() {
        let mut a = aimd();
        for _ in 0..100 {
            a.on_congestion();
        }
        assert!(a.rate() >= 1.0, "rate must not go below min_rate");
        assert!(
            a.is_at_minimum(),
            "should be at minimum after many congestion signals"
        );
    }

    #[test]
    fn aimd_convergence() {
        // Alternate success/congestion: rate should settle near a stable point.
        let mut a = BackpressureAimd::new(100.0, 1.0, 1000.0, 1.0, 0.5);
        for _ in 0..500 {
            a.on_success(); // +1
            a.on_congestion(); // ×0.5
        }
        // After convergence: rate = (rate + 1) * 0.5 → rate = 1.0 (at minimum boundary?)
        // Actually: at equilibrium: rate = (rate + 1) * 0.5 => 2*rate = rate + 1 => rate = 1.
        // With min=1, rate will bottom out at 1.
        assert!(a.rate() >= 1.0, "converged rate must be >= min_rate");
        assert!(a.rate() <= 10.0, "converged rate must be reasonable");
    }

    #[test]
    fn default_aimd_has_sensible_bounds() {
        let a = BackpressureAimd::default();
        assert!(a.rate() > 0.0);
        assert!(!a.is_at_minimum());
    }
}
