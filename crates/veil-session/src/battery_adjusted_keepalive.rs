//! decomposition : encapsulates the periodic
//! battery-and-background-mode keepalive-interval recompute logic
//!
//!
//! Was inline в the Timer arm of `SessionRunner::run` (~30 LoC):
//! every `BATTERY_CHECK_INTERVAL` (60 s) the runner reads
//! `local_battery_level` + `current_mobile_background_keepalive_factor`
//! и if either changed since the previous tick, recomputes the
//! effective `keepalive_interval` as
//! `base_keepalive_interval × battery_scale × bg_factor`.
//!
//! Battery scale tiers:
//! * `level < threshold_low` → `scale_low` (default 4×)
//! * `level < threshold_medium` → `scale_medium` (default 2×)
//! * else → 1×
//!
//! The closure-based `maybe_recompute` API lets the caller defer the
//! actual `local_battery_level` syscall (which on Linux walks
//! `/sys/class/power_supply`) until the check interval is due AND
//! makes the math unit-testable без а production-IO dependency.
//!
//! Sentinel initialisation:
//! * `last_level = 255` (impossible real reading) → forces recompute
//!   on first check
//! * `last_bg_factor = 0` (real values are always ≥ 1) → forces
//!   recompute on first check

use std::time::Duration;
use tokio::time::Instant;

pub struct BatteryAdjustedKeepalive {
    base_interval: Duration,
    scale_low: f64,
    scale_medium: f64,
    threshold_low: u8,
    threshold_medium: u8,
    next_check: Instant,
    last_level: u8,
    last_bg_factor: u32,
    check_interval: Duration,
}

impl BatteryAdjustedKeepalive {
    /// Battery reading currently in use (last sampled value, or sentinel
    /// 255 if no check has fired yet). Used by the runner для the
    /// outbound-batch deferral gate (`current_outbound_batch_window`).
    pub fn last_level(&self) -> u8 {
        self.last_level
    }

    /// Instant of the next due battery check. Folded into the runner's
    /// `sleep_until` calculation so the timer wakes exactly when this
    /// helper has work к do.
    pub fn next_check(&self) -> Instant {
        self.next_check
    }

    pub fn new(
        base_interval: Duration,
        scale_low: f64,
        scale_medium: f64,
        threshold_low: u8,
        threshold_medium: u8,
        check_interval: Duration,
    ) -> Self {
        Self {
            base_interval,
            scale_low,
            scale_medium,
            threshold_low,
            threshold_medium,
            // Check immediately on first timer fire (matches inline
            // behaviour: `let mut next_battery_check = Instant::now;`).
            next_check: Instant::now(),
            last_level: 255,
            last_bg_factor: 0,
            check_interval,
        }
    }

    /// Wraps the inline pattern:
    /// 1. Если `now < next_check`, return `None` (no work due).
    /// 2. Otherwise, advance `next_check` by `check_interval` и call
    ///    `sample` к get current readings.
    /// 3. Если readings unchanged AND we're not on the first check
    ///    return `None`.
    /// 4. Otherwise, recompute scaled keepalive interval. Returns
    ///    `None` если `base_interval` is zero (keepalive disabled —
    ///    matches the inline guard `if self.base_keepalive_interval
    ///.as_secs > 0`).
    /// 5. Otherwise, return `Some(new_interval)`.
    pub fn maybe_recompute<F>(&mut self, now: Instant, sample: F) -> Option<Duration>
    where
        F: FnOnce() -> (u8, u32),
    {
        if now < self.next_check {
            return None;
        }
        self.next_check = now + self.check_interval;
        let (level, bg_factor) = sample();
        if level == self.last_level && bg_factor == self.last_bg_factor {
            return None;
        }
        self.last_level = level;
        self.last_bg_factor = bg_factor;
        if self.base_interval.is_zero() {
            return None;
        }
        let battery_scale = if level < self.threshold_low {
            self.scale_low
        } else if level < self.threshold_medium {
            self.scale_medium
        } else {
            1.0_f64
        };
        let base_ms = self.base_interval.as_millis() as f64;
        let scaled_ms = base_ms * battery_scale * (bg_factor as f64);
        Some(Duration::from_millis(scaled_ms.round() as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(base: Duration) -> BatteryAdjustedKeepalive {
        BatteryAdjustedKeepalive::new(
            base,
            4.0,
            2.0, // scale_low / scale_medium
            20,
            50, // threshold_low / threshold_medium
            Duration::from_secs(60),
        )
    }

    #[tokio::test]
    async fn first_check_with_low_battery_returns_scaled_low() {
        let mut bk = fixture(Duration::from_secs(30));
        let now = Instant::now();
        // First call: next_check == Instant::now от ::new, so the
        // check fires. level=10 < threshold_low=20 ⇒ scale_low=4×.
        let result = bk.maybe_recompute(now, || (10, 1));
        assert_eq!(
            result,
            Some(Duration::from_secs(120)),
            "30s × 4× = 120s under low battery"
        );
    }

    #[tokio::test]
    async fn medium_battery_uses_scale_medium() {
        let mut bk = fixture(Duration::from_secs(30));
        let now = Instant::now();
        let result = bk.maybe_recompute(now, || (35, 1));
        assert_eq!(
            result,
            Some(Duration::from_secs(60)),
            "30s × 2× = 60s under medium battery"
        );
    }

    #[tokio::test]
    async fn full_battery_no_scaling() {
        let mut bk = fixture(Duration::from_secs(30));
        let now = Instant::now();
        let result = bk.maybe_recompute(now, || (80, 1));
        assert_eq!(
            result,
            Some(Duration::from_secs(30)),
            "full battery + bg_factor=1 ⇒ unscaled"
        );
    }

    #[tokio::test]
    async fn second_check_with_unchanged_readings_returns_none() {
        let mut bk = fixture(Duration::from_secs(30));
        let now = Instant::now();
        let _ = bk.maybe_recompute(now, || (10, 1));
        // Force the check to fire again by advancing now past next_check.
        let later = now + Duration::from_secs(61);
        // Readings unchanged ⇒ no recompute.
        let result = bk.maybe_recompute(later, || (10, 1));
        assert_eq!(
            result, None,
            "unchanged readings must skip recompute even if check is due"
        );
    }

    #[tokio::test]
    async fn check_not_due_returns_none_without_sampling() {
        let mut bk = fixture(Duration::from_secs(30));
        let now = Instant::now();
        let _ = bk.maybe_recompute(now, || (10, 1));
        // Second call с `now` LESS than next_check (next_check =
        // start + 60s, we're calling at start + 5s).
        let early = now + Duration::from_secs(5);
        // Sample closure must not be called when check isn't due.
        let mut sampled = false;
        let result = bk.maybe_recompute(early, || {
            sampled = true;
            (50, 2)
        });
        assert_eq!(result, None);
        assert!(
            !sampled,
            "sample closure must not be invoked when check not due"
        );
    }

    #[tokio::test]
    async fn bg_factor_change_triggers_recompute_even_if_battery_same() {
        let mut bk = fixture(Duration::from_secs(30));
        let now = Instant::now();
        let _ = bk.maybe_recompute(now, || (10, 1));
        let later = now + Duration::from_secs(61);
        // Same battery (10) but bg_factor changed from 1 → 60 (
        // backgrounded multiplier). Result: 30s × 4 × 60 = 7200s.
        let result = bk.maybe_recompute(later, || (10, 60));
        assert_eq!(result, Some(Duration::from_secs(30 * 4 * 60)));
    }

    #[tokio::test]
    async fn zero_base_interval_returns_none_even_when_readings_change() {
        let mut bk = fixture(Duration::ZERO);
        let now = Instant::now();
        // base=0 means keepalive is disabled — recompute must return
        // None matching the inline `if self.base_keepalive_interval
        //.as_secs > 0` guard.
        assert_eq!(bk.maybe_recompute(now, || (10, 1)), None);
    }
}
