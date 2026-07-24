//! decomposition : encapsulates the four timer
//! deadlines that gate the runner's `await_next_input` sleep
//! computation and the keepalive / cover-traffic / idle / rx-stall
//! handlers:
//!
//! * `last_rx` — last successful frame-byte read OR transport swap
//!   (idle-timeout ticker; stage (c.2) rx-stall threshold; sole input
//!   to the `now - last_rx >= idle_timeout` check at runner.rs:1416)
//! * `last_genuine_rx` — last successful frame-byte read ONLY (swaps
//!   excluded); input to the hard liveness ceiling
//!   (`liveness_ceiling_elapsed`) that reaps a session whose peer is
//!   gone but whose `last_rx` a hot-standby swap-loop keeps refreshing
//! * `next_keepalive` — scheduled time of the next outbound Keepalive
//!   (jittered to defeat per-session timing fingerprints)
//! * `next_cover` — scheduled time of the next outbound cover-Padding
//!   frame
//!
//! Plus the static enable-flags derived from config.
//!
//! Was scattered inline mutables in `run`; extracting into a typed
//! struct lets future slices touch the keepalive / cover / idle
//! handlers without each one re-touching the same three locals.
//!
//! **Critical invariant** locked in by gate Test 5
//! (`phase650b_idle_timeout_fires_during_awaiting_ack_when_peer_silent`
//! commit `7a8237f`):
//! `last_rx` must be advanced ONLY by `note_rx_activity` /
//! `note_frame_received` (peer activity) or `note_swap` (transport
//! handover); the runner's own rekey / keepalive / cover emission MUST
//! NOT advance it, else a silently-disconnecting peer would leave the
//! session hung forever. This struct's API enforces the invariant by
//! exposing `last_rx` as a read-only accessor — only those three are
//! mutators.
//!
//! **Genuine-liveness gating.** `note_rx_activity` advances `last_rx`
//! ONLY (any inbound frame, including keepalives, proves the line is not
//! idle). `note_frame_received` additionally advances `last_genuine_rx`
//! and is called ONLY for DATA-bearing frames — never for a received
//! Keepalive / KeepaliveAck / Padding. This is load-bearing: the
//! keepalive-probe teardown reaps on `last_genuine_rx` staleness, and a
//! bulk-saturated-but-healthy session can have its KeepaliveAck queued
//! behind data for minutes. If received keepalives advanced the genuine
//! ticker, that teardown could not tell "peer sends only keepalives"
//! (a real one-directional TX wedge) from "peer floods us with data but
//! our ack is queued" (a healthy loaded session) — and it reaped the
//! latter (observed live 2026-07-06: seed↔seed splice session reaped at
//! `genuine_rx age 0ms`, collapsing every circuit on it).

use std::time::Duration;
use tokio::time::Instant;

use crate::runner::{COVER_TRAFFIC_INTERVAL, jitter_cover_interval, jitter_keepalive_interval};

/// Hard liveness ceiling as a multiple of `idle_timeout`. A session that has
/// received NO genuine peer frame for this many idle-windows is torn down
/// unconditionally — the backstop for the M5 zombie where a hot-standby swap
/// keeps resetting `last_rx` (so the normal idle timeout never fires) while the
/// NAT'd peer is actually gone. 3× the idle window sits well past any legitimate
/// swap's first-frame latency (a live transport sees a keepalive every
/// `keepalive_interval` ≤ idle_timeout), so only a truly dead session trips it.
const LIVENESS_CEILING_MULTIPLE: u32 = 3;

// ── Realtime-aware liveness acceleration (P2P Stage B mobility slice) ──
//
// A direct (admitted) session that is actively carrying call media must
// notice a silently-dead path FAST: when a mobile peer hops Wi-Fi → LTE
// behind a NAT that drops without RST, our TCP writes keep "succeeding"
// into the send buffer while inbound goes totally silent. With the
// default 30 s keepalive the probe ledger arms at ~30 s and the re-eval
// reap lands at ~60-90 s — for that whole window `peer_pnet_status().
// admitted` stays true and direct media black-holes (the app-side
// repair path keeps rebuilding the same dead direct route because the
// admission gate still says "session alive").
//
// While REALTIME frames flow (media is being sent and/or received), the
// session tightens its keepalive cadence and probe deadline so a black-
// holed path is detected and reaped in ~7-10 s instead. Scope guard: a
// session with no recent realtime traffic keeps the exact pre-slice
// timeline — chat/relay/mesh sessions see zero behaviour change.
//
// Fingerprint note: during a call the wire already carries a constant
// media stream, so a 2 s keepalive adds no observable new signature;
// once the activity window decays the cadence returns to base.

/// Keepalive send interval while realtime traffic is active (upper
/// bound — an operator-configured interval SHORTER than this wins).
pub const REALTIME_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(2);

/// Keepalive-probe (unacked → TX considered broken) deadline while
/// realtime traffic is active. With the 2 s accelerated cadence this
/// yields: probe armed ≤ 2 s after silence starts, Stage A fire at
/// ~7 s, Stage B re-eval reap at ~9 s — vs ~60-90 s at the 30 s
/// default. Reap additionally requires `genuine_rx` staleness and
/// exhausted failover (see `should_reeval_teardown`), so a healthy
/// loaded session is never reaped by acceleration alone.
pub const REALTIME_KEEPALIVE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long after the last REALTIME frame (either direction) the
/// accelerated cadence stays armed. Must comfortably exceed the whole
/// accelerated detection budget (~9-10 s) so the window cannot decay
/// mid-detection after the peer's media stops arriving.
pub const REALTIME_ACTIVITY_WINDOW: Duration = Duration::from_secs(20);

pub struct SessionTimers {
    last_rx: Instant,
    /// Last GENUINE peer frame (advanced only by `note_frame_received`, never by
    /// `note_swap`). `last_rx` is reset by a transport swap too, which is correct
    /// for the normal idle window (a fresh transport deserves a fresh window) but
    /// lets a doomed swap-loop mask a dead peer forever. `last_genuine_rx` ignores
    /// swaps, so [`Self::liveness_ceiling_elapsed`] can reap that zombie.
    last_genuine_rx: Instant,
    /// Last REALTIME-priority frame seen in EITHER direction (media TX
    /// enqueue or media RX on the ordered stream). `None` until the
    /// first realtime frame — plain sessions never enter accelerated
    /// mode. See the realtime-acceleration module notes above.
    last_realtime: Option<Instant>,
    next_keepalive: Instant,
    next_cover: Instant,
    keepalive_interval: Duration,
    idle_timeout: Duration,
    keepalive_enabled: bool,
    idle_enabled: bool,
    cover_enabled: bool,
}

impl SessionTimers {
    pub fn new(keepalive_interval: Duration, idle_timeout: Duration) -> Self {
        let keepalive_enabled = !keepalive_interval.is_zero();
        let idle_enabled = idle_timeout > Duration::ZERO;
        // Cover-traffic kicks in only when keepalive is also enabled —
        // a keepalive-disabled session is short-lived and doesn't need
        // anti-DPI cover.
        let cover_enabled = keepalive_enabled;
        let now = Instant::now();
        Self {
            last_rx: now,
            last_genuine_rx: now,
            last_realtime: None,
            next_keepalive: now + jitter_keepalive_interval(keepalive_interval),
            next_cover: now + jitter_cover_interval(COVER_TRAFFIC_INTERVAL),
            keepalive_interval,
            idle_timeout,
            keepalive_enabled,
            idle_enabled,
            cover_enabled,
        }
    }

    /// Test-only accessor; production reads `last_rx` via the typed
    /// predicates `idle_timeout_elapsed` / `rx_stall_elapsed` or
    /// the `idle_deadline` / `stall_trigger_deadline` helpers.
    /// Gating with `#[cfg(test)]` blocks accidental external mutation
    /// of the ticker invariant (gate Test 5).
    #[cfg(test)]
    pub fn last_rx(&self) -> Instant {
        self.last_rx
    }

    #[cfg(test)]
    pub fn last_genuine_rx(&self) -> Instant {
        self.last_genuine_rx
    }

    pub fn keepalive_enabled(&self) -> bool {
        self.keepalive_enabled
    }

    pub fn idle_enabled(&self) -> bool {
        self.idle_enabled
    }

    pub fn cover_enabled(&self) -> bool {
        self.cover_enabled
    }

    pub fn next_keepalive(&self) -> Instant {
        self.next_keepalive
    }

    pub fn next_cover(&self) -> Instant {
        self.next_cover
    }

    /// Idle-deadline = `last_rx + idle_timeout`. Used in the
    /// `sleep_until` computation and as the upper bound for the
    /// 2/3-of-idle stall-trigger threshold.
    pub fn idle_deadline(&self) -> Instant {
        self.last_rx + self.idle_timeout
    }

    /// Stall-trigger deadline = `last_rx + 2/3·idle_timeout`.
    ///when the peer goes silent for 2/3 of
    /// idle_timeout, fire the hot-standby trigger ONE iteration
    /// before the session would naturally idle-out — gives the warm
    /// probe time to dial and attach.
    pub fn stall_trigger_deadline(&self) -> Instant {
        self.last_rx + self.idle_timeout * 2 / 3
    }

    /// Has idle_timeout elapsed since the last received frame?
    pub fn idle_timeout_elapsed(&self, now: Instant) -> bool {
        self.idle_enabled && now.duration_since(self.last_rx) >= self.idle_timeout
    }

    /// Has 2/3·idle_timeout elapsed since the last received frame?
    pub fn rx_stall_elapsed(&self, now: Instant) -> bool {
        self.idle_enabled && now.duration_since(self.last_rx) >= self.idle_timeout * 2 / 3
    }

    /// Hard liveness ceiling: has [`LIVENESS_CEILING_MULTIPLE`]×idle_timeout
    /// elapsed since the last GENUINE peer frame? Unlike [`Self::idle_timeout_elapsed`]
    /// this ignores transport swaps (`note_swap`), so a hot-standby probe-loop
    /// against a peer that is actually gone can no longer keep the session alive
    /// indefinitely. Gated on `idle_enabled` (same configuration switch as the
    /// idle timeout) so keepalive-disabled relay/test sessions are unaffected.
    pub fn liveness_ceiling_elapsed(&self, now: Instant) -> bool {
        self.idle_enabled
            && now.duration_since(self.last_genuine_rx)
                >= self.idle_timeout * LIVENESS_CEILING_MULTIPLE
    }

    /// Age of the last GENUINE peer frame (never advanced by `note_swap`).
    /// Production accessor used by the keepalive-probe re-eval teardown so a
    /// session that received genuine data inside the keepalive window is NOT
    /// reaped even if its KeepaliveAck ledger looks stale.
    pub fn genuine_rx_age(&self, now: Instant) -> Duration {
        now.duration_since(self.last_genuine_rx)
    }

    /// Mark ANY inbound-frame event (data OR keepalive/cover). Advances
    /// `last_rx` only — the line is demonstrably not idle — but deliberately
    /// NOT `last_genuine_rx`: a received keepalive is not proof the peer is
    /// doing genuine work, and letting it advance the genuine ticker would
    /// blind the keepalive-probe teardown to a one-directional TX wedge (see
    /// the module doc). Caller resets the per-stall `stall_trigger_fired`
    /// flag since "peer is responsive again".
    pub fn note_rx_activity(&mut self, now: Instant) {
        self.last_rx = now;
    }

    /// Mark a GENUINE DATA-frame event (never a keepalive / cover frame).
    /// Resets BOTH `last_rx` and `last_genuine_rx` — this is the only inbound
    /// signal that resets the liveness ceiling and the keepalive-probe
    /// teardown's staleness check.
    pub fn note_frame_received(&mut self, now: Instant) {
        self.last_rx = now;
        self.last_genuine_rx = now;
    }

    /// Mark a transport-swap event. Resets `last_rx` (the new transport deserves
    /// a fresh idle window) but DELIBERATELY NOT `last_genuine_rx`: a swap is our
    /// own recovery activity, not proof the peer is reachable. Only a real frame
    /// (`note_frame_received`) advances the genuine-RX ticker, so a doomed
    /// swap-loop still trips [`Self::liveness_ceiling_elapsed`]. Any previously-
    /// fired stall trigger is cleared (caller's responsibility).
    pub fn note_swap(&mut self, now: Instant) {
        self.last_rx = now;
    }

    /// Mark a REALTIME-priority frame event (media TX enqueue or media RX)
    /// — arms/refreshes the accelerated liveness cadence. On the rising
    /// edge (inactive → active) the next scheduled keepalive is pulled in
    /// to the accelerated interval: it may otherwise sit a full base
    /// interval (30 s) away, which would delay the whole accelerated
    /// detection pipeline by that much.
    pub fn note_realtime_activity(&mut self, now: Instant) {
        let was_active = self.realtime_active(now);
        self.last_realtime = Some(now);
        if !self.keepalive_enabled || was_active {
            return;
        }
        let accel_deadline = now + jitter_keepalive_interval(self.accel_keepalive_interval());
        if accel_deadline < self.next_keepalive {
            self.next_keepalive = accel_deadline;
        }
    }

    /// Is the accelerated (realtime) liveness cadence currently armed?
    pub fn realtime_active(&self, now: Instant) -> bool {
        self.last_realtime
            .is_some_and(|t| now.duration_since(t) < REALTIME_ACTIVITY_WINDOW)
    }

    /// Accelerated keepalive interval — an operator interval SHORTER than
    /// the realtime constant wins (never slow a fast config down).
    fn accel_keepalive_interval(&self) -> Duration {
        self.keepalive_interval.min(REALTIME_KEEPALIVE_INTERVAL)
    }

    /// Keepalive interval to use RIGHT NOW: accelerated while realtime
    /// traffic is active, the configured base otherwise.
    pub fn effective_keepalive_interval(&self, now: Instant) -> Duration {
        if self.realtime_active(now) {
            self.accel_keepalive_interval()
        } else {
            self.keepalive_interval
        }
    }

    /// Keepalive-probe timeout to use RIGHT NOW. `base` is the runner's
    /// configured probe timeout (1 × keepalive_interval); while realtime
    /// traffic is active it is capped at [`REALTIME_KEEPALIVE_PROBE_TIMEOUT`].
    /// A zero base (keepalive disabled) stays zero — acceleration never
    /// turns the probe machinery ON for sessions that opted out.
    pub fn effective_keepalive_probe_timeout(&self, base: Duration, now: Instant) -> Duration {
        if base.is_zero() || !self.realtime_active(now) {
            base
        } else {
            base.min(REALTIME_KEEPALIVE_PROBE_TIMEOUT)
        }
    }

    /// Test + reschedule for keepalive-due check. Returns `true`
    /// if caller must emit a Keepalive frame; in that case
    /// `next_keepalive` has already been advanced to the next
    /// jittered deadline so the caller doesn't have to remember
    /// to do it.
    pub fn keepalive_due_and_reschedule(&mut self, now: Instant) -> bool {
        if !self.keepalive_enabled || now < self.next_keepalive {
            return false;
        }
        // Accel-aware reschedule: while realtime traffic is active the
        // next keepalive lands on the accelerated cadence; once the
        // activity window decays this naturally returns to base.
        self.next_keepalive =
            now + jitter_keepalive_interval(self.effective_keepalive_interval(now));
        true
    }

    /// Test + reschedule for cover-traffic-due check. Returns
    /// `true` if caller must emit a Padding frame; in that case
    /// `next_cover` has already been advanced.
    pub fn cover_due_and_reschedule(&mut self, now: Instant) -> bool {
        if !self.cover_enabled || now < self.next_cover {
            return false;
        }
        self.next_cover = now + jitter_cover_interval(COVER_TRAFFIC_INTERVAL);
        true
    }

    /// Update the keepalive interval (e.g. called by
    /// `BatteryAdjustedKeepalive::maybe_recompute` with a scaled
    /// interval) and immediately reschedule `next_keepalive`.
    ///
    /// Accel-aware: a battery/background stretch applied mid-call must
    /// not push the next keepalive a full stretched interval away —
    /// realtime activity (a live call) trumps power saving for the
    /// duration of the activity window.
    pub fn update_keepalive_interval(&mut self, new_interval: Duration, now: Instant) {
        self.keepalive_interval = new_interval;
        self.next_keepalive =
            now + jitter_keepalive_interval(self.effective_keepalive_interval(now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn idle_disabled_when_timeout_zero() {
        let timers = SessionTimers::new(Duration::from_secs(10), Duration::ZERO);
        assert!(!timers.idle_enabled());
        assert!(!timers.idle_timeout_elapsed(Instant::now() + Duration::from_secs(1000)));
    }

    #[tokio::test]
    async fn keepalive_disabled_when_interval_zero() {
        let mut timers = SessionTimers::new(Duration::ZERO, Duration::from_secs(10));
        assert!(!timers.keepalive_enabled());
        assert!(
            !timers.cover_enabled(),
            "cover-traffic must follow keepalive"
        );
        // Even with `now` far in the future, keepalive-due returns false.
        assert!(!timers.keepalive_due_and_reschedule(Instant::now() + Duration::from_secs(3600)));
    }

    #[tokio::test]
    async fn note_frame_received_advances_last_rx() {
        let mut timers = SessionTimers::new(Duration::from_secs(10), Duration::from_secs(60));
        let initial = timers.last_rx();
        let later = initial + Duration::from_secs(5);
        timers.note_frame_received(later);
        assert_eq!(timers.last_rx(), later);
    }

    #[tokio::test]
    async fn idle_timeout_elapsed_uses_last_rx() {
        let mut timers = SessionTimers::new(Duration::from_secs(10), Duration::from_secs(5));
        let t0 = timers.last_rx();
        // 4 s elapsed: not idle yet (5 s threshold).
        assert!(!timers.idle_timeout_elapsed(t0 + Duration::from_secs(4)));
        // 6 s elapsed: idle.
        assert!(timers.idle_timeout_elapsed(t0 + Duration::from_secs(6)));
        // After a frame arrives, the ticker resets.
        timers.note_frame_received(t0 + Duration::from_secs(6));
        assert!(
            !timers.idle_timeout_elapsed(t0 + Duration::from_secs(7)),
            "fresh frame ⇒ idle ticker resets"
        );
    }

    #[tokio::test]
    async fn liveness_ceiling_fires_at_three_times_idle() {
        // idle=5 ⇒ ceiling=15.
        let timers = SessionTimers::new(Duration::from_secs(10), Duration::from_secs(5));
        let t0 = timers.last_genuine_rx();
        assert!(!timers.liveness_ceiling_elapsed(t0 + Duration::from_secs(14)));
        assert!(timers.liveness_ceiling_elapsed(t0 + Duration::from_secs(15)));
    }

    #[tokio::test]
    async fn note_swap_does_not_reset_liveness_ceiling() {
        // THE zombie property: a hot-standby swap-loop must NOT keep a dead peer's
        // session alive. note_swap refreshes the idle ticker but NOT the genuine-RX
        // ticker, so the ceiling still fires.
        let mut timers = SessionTimers::new(Duration::from_secs(10), Duration::from_secs(5));
        let t0 = timers.last_genuine_rx();
        // Swap every 4 s (well inside both idle=5 and ceiling=15)...
        timers.note_swap(t0 + Duration::from_secs(4));
        timers.note_swap(t0 + Duration::from_secs(8));
        timers.note_swap(t0 + Duration::from_secs(12));
        // ...idle ticker keeps getting refreshed, so idle never trips:
        assert!(!timers.idle_timeout_elapsed(t0 + Duration::from_secs(15)));
        // ...but the genuine-RX ticker never moved, so the ceiling DOES trip:
        assert!(
            timers.liveness_ceiling_elapsed(t0 + Duration::from_secs(15)),
            "swap-loop must not mask a vanished peer past the liveness ceiling"
        );
    }

    #[tokio::test]
    async fn genuine_rx_age_tracks_last_genuine_rx_and_ignores_swap() {
        let mut timers = SessionTimers::new(Duration::from_secs(10), Duration::from_secs(5));
        let t0 = timers.last_genuine_rx();
        // age at +6s == 6s.
        assert_eq!(
            timers.genuine_rx_age(t0 + Duration::from_secs(6)),
            Duration::from_secs(6)
        );
        // note_swap must NOT advance the genuine-RX ticker, so age keeps growing.
        timers.note_swap(t0 + Duration::from_secs(4));
        assert_eq!(
            timers.genuine_rx_age(t0 + Duration::from_secs(8)),
            Duration::from_secs(8)
        );
        // A genuine frame resets it.
        timers.note_frame_received(t0 + Duration::from_secs(8));
        assert_eq!(
            timers.genuine_rx_age(t0 + Duration::from_secs(9)),
            Duration::from_secs(1)
        );
    }

    #[tokio::test]
    async fn note_rx_activity_advances_last_rx_but_not_genuine() {
        // A received keepalive keeps the line non-idle (last_rx moves) but
        // must NOT refresh the genuine ticker — else a keepalive-only wedge
        // is indistinguishable from a live session.
        let mut timers = SessionTimers::new(Duration::from_secs(10), Duration::from_secs(5));
        let t0 = timers.last_genuine_rx();
        timers.note_rx_activity(t0 + Duration::from_secs(4));
        // last_rx advanced → not idle at +4s past a fresh window.
        assert_eq!(timers.last_rx(), t0 + Duration::from_secs(4));
        // genuine ticker did NOT advance → still ages from t0.
        assert_eq!(
            timers.genuine_rx_age(t0 + Duration::from_secs(6)),
            Duration::from_secs(6)
        );
        // ...so the liveness ceiling (3×idle=15s) still trips on schedule
        // even though keepalives keep arriving every 4s.
        timers.note_rx_activity(t0 + Duration::from_secs(8));
        timers.note_rx_activity(t0 + Duration::from_secs(12));
        assert!(
            timers.liveness_ceiling_elapsed(t0 + Duration::from_secs(15)),
            "keepalive-only RX must not mask a genuinely wedged peer"
        );
    }

    #[tokio::test]
    async fn note_frame_received_resets_liveness_ceiling() {
        let mut timers = SessionTimers::new(Duration::from_secs(10), Duration::from_secs(5));
        let t0 = timers.last_genuine_rx();
        // A genuine frame at 14 s resets the ceiling ticker...
        timers.note_frame_received(t0 + Duration::from_secs(14));
        // ...so at 15 s (was the ceiling) we're fine, and only 3×idle LATER trips.
        assert!(!timers.liveness_ceiling_elapsed(t0 + Duration::from_secs(15)));
        assert!(timers.liveness_ceiling_elapsed(t0 + Duration::from_secs(29)));
    }

    #[tokio::test]
    async fn liveness_ceiling_disabled_when_idle_disabled() {
        let timers = SessionTimers::new(Duration::from_secs(10), Duration::ZERO);
        assert!(!timers.idle_enabled());
        assert!(!timers.liveness_ceiling_elapsed(Instant::now() + Duration::from_secs(100_000)));
    }

    #[tokio::test]
    async fn rx_stall_elapsed_at_two_thirds_idle() {
        let timers = SessionTimers::new(Duration::from_secs(10), Duration::from_secs(9));
        let t0 = timers.last_rx();
        // 5 s < 6 s (2/3 of 9) ⇒ not stalled.
        assert!(!timers.rx_stall_elapsed(t0 + Duration::from_secs(5)));
        // 6 s == threshold ⇒ stalled.
        assert!(timers.rx_stall_elapsed(t0 + Duration::from_secs(6)));
    }

    #[tokio::test]
    async fn keepalive_due_advances_next_when_fires() {
        let mut timers = SessionTimers::new(Duration::from_secs(1), Duration::from_secs(60));
        let t = timers.next_keepalive();
        // Before the deadline ⇒ false.
        assert!(!timers.keepalive_due_and_reschedule(t - Duration::from_millis(1)));
        // At the deadline ⇒ fires AND advances next_keepalive.
        let prev_next = timers.next_keepalive();
        assert!(timers.keepalive_due_and_reschedule(t));
        assert!(
            timers.next_keepalive() > prev_next,
            "fire must advance next_keepalive"
        );
    }

    #[tokio::test]
    async fn update_keepalive_interval_reschedules() {
        let mut timers = SessionTimers::new(Duration::from_secs(1), Duration::from_secs(60));
        let prev = timers.next_keepalive();
        let now = Instant::now() + Duration::from_secs(100);
        timers.update_keepalive_interval(Duration::from_secs(60), now);
        // New next_keepalive should be ~now + 60s; in any case strictly later than prev.
        assert!(timers.next_keepalive() > prev);
    }

    #[tokio::test]
    async fn note_swap_advances_last_rx() {
        let mut timers = SessionTimers::new(Duration::from_secs(10), Duration::from_secs(30));
        let t0 = timers.last_rx();
        let swap_time = t0 + Duration::from_secs(15);
        timers.note_swap(swap_time);
        assert_eq!(timers.last_rx(), swap_time);
        // Idle threshold has effectively reset.
        assert!(
            !timers.idle_timeout_elapsed(swap_time + Duration::from_secs(20)),
            "swap counts as activity — idle ticker resets"
        );
    }

    // ── realtime-aware liveness acceleration (P2P mobility slice) ──────

    #[tokio::test]
    async fn realtime_activity_arms_and_decays() {
        let mut timers = SessionTimers::new(Duration::from_secs(30), Duration::from_secs(90));
        let t0 = timers.last_rx();
        assert!(
            !timers.realtime_active(t0),
            "no realtime frame yet — accel must be off"
        );
        timers.note_realtime_activity(t0);
        assert!(timers.realtime_active(t0 + REALTIME_ACTIVITY_WINDOW / 2));
        assert!(
            !timers.realtime_active(t0 + REALTIME_ACTIVITY_WINDOW),
            "accel must decay once the activity window elapses"
        );
    }

    #[tokio::test]
    async fn realtime_activity_accelerates_keepalive_interval_and_probe() {
        let mut timers = SessionTimers::new(Duration::from_secs(30), Duration::from_secs(90));
        let t0 = timers.last_rx();
        let base = Duration::from_secs(30);
        // Inactive: base values pass through untouched.
        assert_eq!(timers.effective_keepalive_interval(t0), base);
        assert_eq!(timers.effective_keepalive_probe_timeout(base, t0), base);
        // Active: capped at the realtime constants.
        timers.note_realtime_activity(t0);
        assert_eq!(
            timers.effective_keepalive_interval(t0),
            REALTIME_KEEPALIVE_INTERVAL
        );
        assert_eq!(
            timers.effective_keepalive_probe_timeout(base, t0),
            REALTIME_KEEPALIVE_PROBE_TIMEOUT
        );
        // Decayed: back to base.
        let later = t0 + REALTIME_ACTIVITY_WINDOW + Duration::from_secs(1);
        assert_eq!(timers.effective_keepalive_interval(later), base);
        assert_eq!(timers.effective_keepalive_probe_timeout(base, later), base);
    }

    #[tokio::test]
    async fn realtime_activity_never_slows_a_faster_config() {
        // Operator configured a 1 s keepalive — faster than the accel
        // constant. Acceleration must keep 1 s, not stretch to 2 s.
        let mut timers = SessionTimers::new(Duration::from_secs(1), Duration::from_secs(3));
        let t0 = timers.last_rx();
        timers.note_realtime_activity(t0);
        assert_eq!(
            timers.effective_keepalive_interval(t0),
            Duration::from_secs(1)
        );
        assert_eq!(
            timers.effective_keepalive_probe_timeout(Duration::from_secs(1), t0),
            Duration::from_secs(1)
        );
    }

    #[tokio::test]
    async fn realtime_activity_zero_keepalive_stays_disabled() {
        let mut timers = SessionTimers::new(Duration::ZERO, Duration::from_secs(10));
        let t0 = Instant::now();
        timers.note_realtime_activity(t0);
        assert_eq!(
            timers.effective_keepalive_probe_timeout(Duration::ZERO, t0),
            Duration::ZERO,
            "keepalive-disabled sessions must not grow a probe timeout"
        );
        assert!(!timers.keepalive_due_and_reschedule(t0 + Duration::from_secs(3600)));
    }

    #[tokio::test]
    async fn realtime_rising_edge_pulls_next_keepalive_in() {
        let mut timers = SessionTimers::new(Duration::from_secs(30), Duration::from_secs(90));
        let t0 = timers.last_rx();
        let scheduled_far = timers.next_keepalive();
        // The base schedule sits ~30 s out (jittered ±30%).
        assert!(scheduled_far > t0 + Duration::from_secs(15));
        timers.note_realtime_activity(t0);
        // Rising edge must clamp the deadline into the accelerated
        // cadence (jitter caps at +30% of 2 s).
        assert!(
            timers.next_keepalive() <= t0 + REALTIME_KEEPALIVE_INTERVAL * 2,
            "first accel keepalive must be pulled in from the base schedule"
        );
        // A second frame while already active must NOT keep re-clamping
        // (the reschedule cadence owns the deadline now).
        let after_fire = timers.next_keepalive();
        timers.note_realtime_activity(t0 + Duration::from_millis(20));
        assert_eq!(timers.next_keepalive(), after_fire);
    }
}
