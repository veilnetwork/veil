//! Consecutive write-error counter с threshold-based hot-standby
//! auto-trigger.  SessionRunner decomposition slice 29
//! (architecture backlog) — extracts the inline `u32` counter +
//! threshold-compare pattern что previously lived as а bare local
//! variable in `run()` плюс four `on_primary_write_error(count: &mut u32)`
//! arms.
//!
//! ## Wire contract
//!
//! Counter is **monotonically increasing** within а session's lifetime
//! — NOT reset on successful writes.  Rationale: а half-dead primary
//! transport may flap между OK и err states; the goal is к fire the
//! hot-standby trigger on **cumulative** failure within the session,
//! not just а burst.
//!
//! Threshold-zero (`auto_trigger_after_write_errors == 0`) disables
//! the trigger entirely (default behaviour для sessions без а
//! hot-standby configuration).  `on_error()` still increments the
//! counter (useful для observability via `count()`), но returns
//! `TriggerFire::No`.
//!
//! ## Why extract
//!
//! * **Localisation**: hot-standby threshold check лежал inline в
//!   four arms (rekey-ack, mlkem-rekey-ack, rekey-init, plus the
//!   main loop's session-ticket emission path).  Each arm replicated
//!   `*count += 1; if *count >= threshold { fire(...); }`.  Single
//!   struct centralises the invariant.
//! * **Testability**: pure compute с no async, no I/O.  Trivial
//!   unit tests verify increment + threshold-fire + zero-threshold
//!   disable semantics.
//! * **Type clarity**: the bare `&mut u32` parameter в 5 callsites
//!   becomes `&mut WriteErrorTracker` — search-greppable, dispatcher
//!   ownership change visible in signatures.

/// Outcome of [`WriteErrorTracker::on_error`].  Caller acts on
/// `TriggerFire::Yes` by invoking [`SessionRunner::fire_hot_standby_trigger`]
/// — encapsulating the wire-side call here would re-couple us к runner
/// internals, so we keep а thin pure-data signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerFire {
    /// Threshold reached — caller should fire the hot-standby trigger.
    Yes,
    /// Below threshold (or threshold disabled).
    No,
}

/// Consecutive write-error counter + threshold-compare state.
#[derive(Debug, Clone, Copy)]
pub struct WriteErrorTracker {
    count: u32,
    threshold: u32,
}

impl WriteErrorTracker {
    /// New tracker с the supplied threshold.  `threshold == 0`
    /// disables auto-trigger (counter still increments на errors —
    /// `count()` accessor exposes the value для metrics).
    pub fn new(threshold: u32) -> Self {
        Self {
            count: 0,
            threshold,
        }
    }

    /// Record а write error и check whether the threshold is reached.
    /// Returns [`TriggerFire::Yes`] iff threshold-fire conditions met:
    /// `threshold > 0 && count >= threshold` после the increment.
    ///
    /// Counter is NEVER reset by а subsequent success path — invariant
    /// of the "cumulative half-dead transport" model.  See module-doc
    /// rationale.
    pub fn on_error(&mut self) -> TriggerFire {
        self.count = self.count.saturating_add(1);
        if self.threshold == 0 {
            return TriggerFire::No;
        }
        if self.count >= self.threshold {
            TriggerFire::Yes
        } else {
            TriggerFire::No
        }
    }

    /// Current count.  Used for observability / metrics на session
    /// teardown.  Not reset на check.
    #[allow(dead_code)]
    pub fn count(&self) -> u32 {
        self.count
    }

    /// Threshold value passed к [`Self::new`].  Used by callsites
    /// that need к log the threshold alongside an event (legacy
    /// SessionRunner emits "threshold=N" в the hot-standby trigger
    /// log line).
    #[allow(dead_code)]
    pub fn threshold(&self) -> u32 {
        self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_at_zero() {
        let t = WriteErrorTracker::new(3);
        assert_eq!(t.count(), 0);
        assert_eq!(t.threshold(), 3);
    }

    #[test]
    fn on_error_increments() {
        let mut t = WriteErrorTracker::new(3);
        let _ = t.on_error();
        assert_eq!(t.count(), 1);
        let _ = t.on_error();
        assert_eq!(t.count(), 2);
    }

    #[test]
    fn on_error_below_threshold_returns_no() {
        let mut t = WriteErrorTracker::new(3);
        assert_eq!(t.on_error(), TriggerFire::No);
        assert_eq!(t.on_error(), TriggerFire::No);
    }

    #[test]
    fn on_error_at_threshold_returns_yes() {
        let mut t = WriteErrorTracker::new(3);
        let _ = t.on_error();
        let _ = t.on_error();
        assert_eq!(t.on_error(), TriggerFire::Yes);
    }

    #[test]
    fn on_error_above_threshold_continues_returning_yes() {
        let mut t = WriteErrorTracker::new(2);
        let _ = t.on_error(); // count=1, No
        assert_eq!(t.on_error(), TriggerFire::Yes); // count=2, Yes
        assert_eq!(t.on_error(), TriggerFire::Yes); // count=3, still Yes
    }

    #[test]
    fn zero_threshold_never_fires() {
        let mut t = WriteErrorTracker::new(0);
        // Counter still increments (для observability).
        assert_eq!(t.on_error(), TriggerFire::No);
        assert_eq!(t.on_error(), TriggerFire::No);
        assert_eq!(t.count(), 2);
    }

    #[test]
    fn count_saturates_does_not_overflow() {
        // Defence-in-depth: an attacker forcing u32::MAX write errors
        // shouldn't panic the session loop.  saturating_add guarantees
        // bounded behaviour even в the absurd case.
        let mut t = WriteErrorTracker::new(5);
        t.count = u32::MAX - 1;
        let _ = t.on_error(); // count = u32::MAX
        let _ = t.on_error(); // saturated; no overflow
        assert_eq!(t.count(), u32::MAX);
        // Above-threshold semantics preserved.
        assert_eq!(t.on_error(), TriggerFire::Yes);
    }
}
