//! SessionRunner decomposition slice 25-26: one-shot triggers.
//!
//! SessionRunner's hot-standby coordination uses two **one-shot
//! triggers** as inline `bool` flags inside the main `run()` loop:
//!
//! * `stall_trigger_fired` — fires when rx has been silent for 2/3 of
//!   idle_timeout (Epic 459 stage c.2 proactive rx-stall detection).
//! * `keepalive_probe_trigger_fired` — fires when our keepalives
//!   have been going unacked beyond `keepalive_probe_timeout`
//!   (Epic 459 stage c.2.2 TX-health detection).
//!
//! Both share the **fire-once-per-episode** semantic: after the trigger
//! fires the runner does NOT re-fire it on every subsequent loop
//! iteration; it stays armed until the underlying condition resolves
//! (rx-stall: peer sends а frame → cleared implicitly by note_frame_received
//! advancing last_rx; probe-timeout: KeepaliveAck arrives → explicitly
//! cleared via `clear()` here).
//!
//! Pre-slice the two flags were two raw `bool` locals в run() с the
//! `clear() on ack` site repeating itself for the probe-timeout (the
//! rx-stall flag is implicitly cleared by timer state, not explicitly).
//! This slice bundles them into [`OnceTrigger`] с а semantically-named
//! API so future refactors don't accidentally re-arm-already-fired
//! triggers or leak the wrong arm across episodes.

/// One-shot trigger that fires at most once per arming episode и
/// resets к re-armable когда `clear()` is called.
///
/// State machine:
/// ```text
///   Idle ──try_fire()──▶ Fired ──clear()──▶ Idle
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct OnceTrigger {
    fired: bool,
}

impl OnceTrigger {
    /// Construct в the Idle (unfired) state.
    pub fn new() -> Self {
        Self { fired: false }
    }

    /// Try к fire the trigger.  Returns **`true`** только если this
    /// is the FIRST fire since the last `clear()` — subsequent calls
    /// return `false` (one-shot semantic).  Caller wraps the actual
    /// side-effect (logger.warn, hot-standby kick, etc.) в
    /// `if trigger.try_fire() { ... }`.
    pub fn try_fire(&mut self) -> bool {
        if self.fired {
            false
        } else {
            self.fired = true;
            true
        }
    }

    /// Whether the trigger has fired since the last clear.  Read-only
    /// accessor для test diagnostics + а small set of consumer-side
    /// checks that want к know without firing.
    pub fn has_fired(&self) -> bool {
        self.fired
    }

    /// Reset к Idle.  Called when the underlying condition resolves
    /// (e.g. KeepaliveAck arrives → the probe-timeout trigger arms
    /// fresh on the next outstanding probe).
    pub fn clear(&mut self) {
        self.fired = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fresh trigger reports has_fired == false и try_fire returns
    /// true the first time.
    #[test]
    fn fresh_trigger_fires_once_then_blocks() {
        let mut t = OnceTrigger::new();
        assert!(!t.has_fired());
        assert!(t.try_fire(), "first fire must succeed");
        assert!(t.has_fired());
        assert!(!t.try_fire(), "subsequent fire MUST return false");
        assert!(t.has_fired(), "state stays Fired after second try");
    }

    /// `clear()` re-arms the trigger.  Subsequent `try_fire()` returns
    /// true once again.
    #[test]
    fn clear_rearms_trigger() {
        let mut t = OnceTrigger::new();
        t.try_fire();
        t.clear();
        assert!(!t.has_fired(), "clear() must put trigger back в Idle");
        assert!(t.try_fire(), "post-clear try_fire must succeed once");
        assert!(!t.try_fire(), "post-clear second fire still bounded");
    }

    /// `clear()` on an Idle trigger is а no-op (no panic, no state
    /// flip).  Cheap defensive guard for callers that clear on every
    /// KeepaliveAck regardless of probe state.
    #[test]
    fn clear_on_idle_is_noop() {
        let mut t = OnceTrigger::new();
        t.clear();
        assert!(!t.has_fired());
        assert!(t.try_fire(), "Idle stays armed after clear()");
    }

    /// Default impl matches `new()` — used by struct field init shortcuts.
    #[test]
    fn default_matches_new() {
        let a = OnceTrigger::new();
        let b = OnceTrigger::default();
        assert_eq!(a.has_fired(), b.has_fired());
    }
}
