//! decomposition : encapsulates
//! session-rotation deadline.
//!
//! Was inline в `SessionRunner::run`:
//! * computed-once initialization with ±10 % jitter
//! * `rotation_enabled` flag derived as `current_session_max_age_secs > 0`
//! * Timer-arm `if let Some(deadline) = session_rotate_at && now >= deadline { return; }`
//!
//! Background — connection-rotation: defeats long-lived
//! TCP+TLS-handshake DPI fingerprints by force-closing every N
//! minutes (jittered). The caller (outbound connector) reconnects
//! naturally via existing reconnect logic; the NEW session gets the
//! same Chrome ClientHello fingerprint, making the rotation pattern
//! indistinguishable от а normal HTTPS browser session ending и а
//! new one starting. No "rotation goodbye" frame — that would
//! itself be а fingerprint; ordinary HTTPS sessions end с а TCP
//! close, not а custom protocol message.
//!
//! Jitter is computed ONCE per session (not per timer tick) so
//! rotation cadence stays predictable для а single session, just
//! unpredictable across the fleet.

use std::time::Duration;
use tokio::time::Instant;

pub struct SessionRotationDeadline {
    deadline: Option<Instant>,
}

impl SessionRotationDeadline {
    /// Compute а rotation deadline.  Reads the globals set by
    /// `set_session_rotation_range` / `set_session_max_age_secs` в
    /// runner.rs (managed by admin/config reload paths).  Returns а
    /// deadline of `None` если rotation is disabled (both bounds 0).
    ///
    /// **Two sampling modes:**
    /// * **Range mode** (both `min > 0` и `max > 0`): deadline drawn
    ///   uniformly из `[min, max]` seconds.  Set by the new
    ///   `[transport.rotation]` config section — wider entropy hides
    ///   the rotation cadence от per-fleet correlation attacks.
    /// * **Point + jitter mode** (only `max > 0`, `min == 0`): legacy
    ///   `±10 %` jitter around `max`.  Backed by the deprecated
    ///   `session.max_age_secs` knob — preserved для back-compat но
    ///   the new range mode is strictly more flexible.
    pub fn compute(now: Instant) -> Self {
        let (min_secs, max_secs) = crate::runner::current_session_rotation_range();
        if max_secs == 0 {
            return Self { deadline: None };
        }
        use rand_core::{OsRng, RngCore};
        let jittered_ms = if min_secs > 0 && min_secs <= max_secs {
            // Range mode: uniform sample в [min_ms, max_ms].
            let min_ms = min_secs.saturating_mul(1000);
            let max_ms = max_secs.saturating_mul(1000);
            let span_ms = max_ms.saturating_sub(min_ms);
            let r = if span_ms == 0 {
                0
            } else {
                OsRng.next_u64() % (span_ms + 1)
            };
            min_ms.saturating_add(r)
        } else {
            // Legacy point + ±10 % jitter mode (back-compat).
            let base_ms = max_secs.saturating_mul(1000);
            let jitter_window_ms = base_ms / 5;
            let r = if jitter_window_ms == 0 {
                0
            } else {
                OsRng.next_u64() % jitter_window_ms
            };
            base_ms
                .saturating_add(r)
                .saturating_sub(jitter_window_ms / 2)
        };
        Self {
            deadline: Some(now + Duration::from_millis(jittered_ms)),
        }
    }

    /// Test-only — production checks rotation via `is_due(now)` only.
    /// Kept under `#[cfg(test)]` к avoid encouraging callers к read
    /// the deadline directly (which would let them race against the
    /// `is_due` check semantics).
    pub fn enabled(&self) -> bool {
        self.deadline.is_some()
    }

    /// The pending deadline instant если rotation is armed, или `None`
    /// when rotation is disabled.  Production callers use this к fold
    /// the rotation wake-up into `compute_sleep_deadline` so the
    /// session loop actually emerges от `await_next_input` at the
    /// rotation instant even in an idle session (Q.7 audit batch).
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// True iff а deadline is set AND `now` has reached it — caller
    /// should `return` от `run` to gracefully close the session.
    pub fn is_due(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|d| now >= d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lock used by the existing `set_session_max_age_secs_pct` tests
    /// в runner.rs's tests module. Re-grabbing the same lock here
    /// keeps slice-7 unit tests serialised с those.
    fn rotation_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::OnceLock;
        static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    struct RotationRestore;
    impl Drop for RotationRestore {
        fn drop(&mut self) {
            // Clear both globals — `set_session_rotation_range(0, 0)`
            // resets max AND min in one call, vs the legacy single-
            // value setter which only touches max (and the runner-
            // level `set_session_max_age_secs` further zeros min as
            // а side-effect — see its doc).  Be explicit к keep the
            // teardown reasoning robust if either setter changes.
            crate::runner::set_session_rotation_range(0, 0);
        }
    }

    #[tokio::test]
    async fn disabled_when_max_age_zero() {
        let _g = rotation_lock();
        let _r = RotationRestore;
        crate::runner::set_session_max_age_secs(0);
        let r = SessionRotationDeadline::compute(Instant::now());
        assert!(!r.enabled());
        assert_eq!(r.deadline(), None);
        assert!(
            !r.is_due(Instant::now() + Duration::from_secs(86_400)),
            "disabled rotation never fires"
        );
    }

    #[tokio::test]
    async fn enabled_with_positive_max_age() {
        let _g = rotation_lock();
        let _r = RotationRestore;
        crate::runner::set_session_max_age_secs(1_800);
        let now = Instant::now();
        let r = SessionRotationDeadline::compute(now);
        assert!(r.enabled());
        let d = r.deadline().unwrap();
        // Jitter is ±10 %, so deadline ∈ (now + 1620 s, now + 1980 s).
        assert!(d > now + Duration::from_secs(1_620));
        assert!(d < now + Duration::from_secs(1_980));
    }

    #[tokio::test]
    async fn is_due_only_after_deadline() {
        let _g = rotation_lock();
        let _r = RotationRestore;
        crate::runner::set_session_max_age_secs(60);
        let start = Instant::now();
        let r = SessionRotationDeadline::compute(start);
        // Should NOT be due immediately.
        assert!(!r.is_due(start));
        // Mid-jitter-window: not due.
        assert!(!r.is_due(start + Duration::from_secs(50)));
        // Far past max jittered deadline: due.
        assert!(r.is_due(start + Duration::from_secs(120)));
    }

    // ── Range-mode tests (new [transport.rotation] knob) ───────────

    #[tokio::test]
    async fn range_mode_deadline_falls_within_min_max() {
        let _g = rotation_lock();
        let _r = RotationRestore;
        // 30 min .. 1 hour — sample several times to verify the
        // uniform draw stays inside the bounds.
        crate::runner::set_session_rotation_range(1_800, 3_600);
        for _ in 0..50 {
            let now = Instant::now();
            let r = SessionRotationDeadline::compute(now);
            let d = r.deadline().expect("range mode must yield а deadline");
            assert!(
                d >= now + Duration::from_secs(1_800),
                "deadline below range floor"
            );
            assert!(
                d <= now + Duration::from_secs(3_601),
                "deadline above range ceiling (allowing 1s slop for sub-ms saturation)"
            );
        }
    }

    #[tokio::test]
    async fn range_mode_equal_min_max_yields_exact_deadline() {
        let _g = rotation_lock();
        let _r = RotationRestore;
        // Degenerate "range" where min == max should behave like а
        // point с no jitter (within ms granularity).
        crate::runner::set_session_rotation_range(600, 600);
        let now = Instant::now();
        let r = SessionRotationDeadline::compute(now);
        let d = r.deadline().expect("non-zero point must yield deadline");
        assert!(d >= now + Duration::from_secs(599));
        assert!(d <= now + Duration::from_secs(601));
    }

    #[tokio::test]
    async fn range_mode_disabled_pair_yields_no_deadline() {
        let _g = rotation_lock();
        let _r = RotationRestore;
        crate::runner::set_session_rotation_range(0, 0);
        let r = SessionRotationDeadline::compute(Instant::now());
        assert!(!r.enabled(), "(0, 0) range disables rotation");
    }

    #[tokio::test]
    async fn range_mode_min_above_max_clamps_safely() {
        let _g = rotation_lock();
        let _r = RotationRestore;
        // Defensive: validation prevents this, но если someone calls
        // the setter directly с reversed args, we should not panic.
        crate::runner::set_session_rotation_range(7_200, 3_600);
        let r = SessionRotationDeadline::compute(Instant::now());
        assert!(r.enabled());
        // Min gets clamped к max internally; deadline ≈ 3600 s.
        let d = r.deadline().unwrap();
        let now = Instant::now();
        assert!(d <= now + Duration::from_secs(3_605));
    }
}
