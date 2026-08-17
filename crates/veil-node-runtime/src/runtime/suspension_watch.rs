//! Runtime-side OS-suspension detector — recover inbound reachability after
//! a sleep the app never told us about.
//!
//! Every deadline this runtime keeps — rendezvous-registration TTLs, republish
//! due times, keepalive probes — is measured with `std::time::Instant`, i.e.
//! CLOCK_MONOTONIC. On mobile that clock does NOT advance while the device is
//! in deep sleep (Doze, screen-off freezes, laptop lids). The relays and DHT
//! holders that hold our registrations run on the WALL clock and keep expiring
//! us while we sleep. So a node coming back from a suspension is split-brained
//! about time: its own deadlines all claim "still fresh" (they were silently
//! stretched by the sleep length), while the network expired everything long
//! ago. Measured live on Android: QUIC sessions to the seeds resume, outbound
//! works, and INBOUND stays dark for 17+ minutes — the rendezvous registration
//! expired at the relays mid-sleep, senders' introduces evaporate, and nothing
//! on this side re-registers because no local deadline has fired.
//!
//! The app-level resume hook (lifecycle event → re-join + drain nudge) covers
//! the suspensions the app SEES. This detector covers the ones it doesn't:
//! Doze with the app "foregrounded", screen-off freezes, anything where the OS
//! stopped the process without a lifecycle transition.
//!
//! The suspension signal is the divergence itself: sample `(Instant,
//! SystemTime)` as a pair on a short cadence, and compare how far each clock
//! moved since the previous pair. Awake, Δwall ≈ Δmono within NTP-slew noise.
//! Across a suspension Δwall runs AHEAD of Δmono by exactly the sleep length —
//! there is no other mechanism that moves the two clocks apart by tens of
//! seconds. Wall-clock going BACKWARD (operator set the clock, NTP step) is
//! not a suspension and is ignored; forward steps big enough to trip the
//! threshold fire a spurious recovery, which is safe — every consumer of the
//! recovery is an idempotent "run your next tick now" nudge.
//!
//! Recovery fans out to the mechanisms the runtime already owns:
//! * a synthetic `SESSIONS_CHANGED` on the event bus — the rendezvous-recipient
//!   task treats it as "re-check now" and calls its `force = true` re-register
//!   path (`rendezvous_recipient_recheck`), re-registering at the relays and
//!   republishing the ads immediately;
//! * `mlkem_republish_now` — pulls the sovereign-identity republish task's
//!   interval arm forward (document + registry + ML-KEM cert + relay key);
//! * `dht_republish_now` — drops the DHT-republish task's `Instant`-based
//!   per-key schedule so every stored key re-staggers from now;
//! * `force_reconnect_notify` — wakes every outbound-connector loop parked in
//!   a backoff sleep that the suspension stretched, so dead peers re-dial now.
//!
//! There is deliberately NO direct "probe every live session now" trigger:
//! the session runners have no external probe channel, and their reap-on-
//! stale-probe path (`should_reeval_teardown`) recovers them once their own
//! stretched deadlines fire. Adding such a channel would touch every runner
//! select loop for a path the redial wake already covers in practice.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use veil_observability::NodeLogger;

/// How often the maintenance loop samples the clock pair. Short enough that a
/// resume is noticed within one office-elevator ride; long enough to be free.
/// Independent of `cleanup_interval` on purpose — operators tune that from 1 s
/// (seeds) to minutes, and the detector's latency should not ride along.
pub(crate) const SUSPENSION_SAMPLE_INTERVAL: Duration = Duration::from_secs(15);

/// Minimum wall-ahead-of-monotonic divergence that counts as a suspension.
/// NTP slew moves the wall clock by milliseconds per sample; scheduler delay
/// on a loaded device by tens more. 30 s is orders of magnitude above both,
/// and a sleep shorter than that expires nothing the next periodic tick
/// wouldn't refresh anyway.
pub(crate) const DEFAULT_SUSPENSION_GAP_THRESHOLD: Duration = Duration::from_secs(30);

/// Pure detection core: given how far each clock moved since the previous
/// sample, was there a suspension?
///
/// `delta_wall_ms` is signed because the wall clock is allowed to move
/// backward (operator, NTP step); that is never a suspension. Returns the gap
/// — the sleep length, which is how long ago the network last heard from us —
/// when the wall clock ran ahead of the monotonic clock by at least
/// `threshold`; `None` otherwise.
pub(crate) fn detect(
    delta_mono: Duration,
    delta_wall_ms: i64,
    threshold: Duration,
) -> Option<Duration> {
    let mono_ms = delta_mono.as_millis().min(i64::MAX as u128) as i64;
    let threshold_ms = threshold.as_millis().min(i64::MAX as u128) as i64;
    let gap_ms = delta_wall_ms.saturating_sub(mono_ms);
    if gap_ms >= threshold_ms {
        Some(Duration::from_millis(gap_ms as u64))
    } else {
        None
    }
}

/// Thin stateful wrapper over [`detect`]: holds the last sampled clock pair
/// and rebaselines on EVERY sample, so one suspension fires exactly once —
/// the sample that detects it is also the baseline the next sample is judged
/// against. No I/O, no globals; the caller supplies both clocks.
pub(crate) struct SuspensionWatch {
    threshold: Duration,
    last: Option<(Instant, SystemTime)>,
}

impl SuspensionWatch {
    pub(crate) fn new(threshold: Duration) -> Self {
        Self {
            threshold,
            last: None,
        }
    }

    /// Feed one clock-pair sample. `Some(gap)` when a suspension of at least
    /// the threshold happened since the PREVIOUS sample; `None` on the first
    /// sample (no baseline yet), on ordinary passage of time, and on a
    /// backward wall step.
    pub(crate) fn sample(&mut self, now_mono: Instant, now_wall: SystemTime) -> Option<Duration> {
        let (prev_mono, prev_wall) = self.last.replace((now_mono, now_wall))?;
        let delta_mono = now_mono.saturating_duration_since(prev_mono);
        let delta_wall_ms = match now_wall.duration_since(prev_wall) {
            Ok(d) => d.as_millis().min(i64::MAX as u128) as i64,
            // Wall clock moved backward by `e.duration()`.
            Err(e) => -(e.duration().as_millis().min(i64::MAX as u128) as i64),
        };
        detect(delta_mono, delta_wall_ms, self.threshold)
    }
}

/// Fan a detected suspension out to the runtime's existing recovery levers.
///
/// Everything here is a "run your next tick now" nudge to a loop that already
/// exists, so firing spuriously (laptop sleep, a big forward NTP step) costs
/// one round of work each loop was going to do anyway:
///
/// * The synthetic `SESSIONS_CHANGED` mirrors the one `SessionGuard::drop`
///   publishes (same `u16` live-count payload) — the rendezvous-recipient
///   task's event arm re-registers at the relays with `force = true` and
///   republishes the ads; every other subscriber sees an ordinary
///   sessions-changed hint.
/// * `notify_one` (not `notify_waiters`) for the two republish nudges: it
///   stores a permit, so a consumer that is mid-turn when we fire still takes
///   the wake on its next `notified().await` — losing the wake right after a
///   resume is the exact failure this module exists to close.
/// * `notify_waiters` for the reconnect wake, matching its established
///   fan-out semantics (many connector loops parked at once; see
///   `connectivity_gain.rs`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn fire_suspension_recovery(
    gap: Duration,
    live_session_count: usize,
    event_bus: &veil_ipc::EventBus,
    mlkem_republish_now: &tokio::sync::Notify,
    dht_republish_now: &tokio::sync::Notify,
    force_reconnect_notify: &tokio::sync::Notify,
    logger: &Arc<NodeLogger>,
) {
    logger.info(
        "runtime.suspension.detected",
        format!(
            "gap={}s — wall clock ran ahead of CLOCK_MONOTONIC since the last \
             sample; the network has been expiring us the whole time. Forcing \
             rendezvous re-registration + identity/DHT republish + redial wake",
            gap.as_secs(),
        ),
    );
    // (a) Rendezvous re-registration: the recipient task's event arm calls
    // `rendezvous_recipient_recheck(..., force = true)` on this.
    let count_u16 = live_session_count.min(u16::MAX as usize) as u16;
    event_bus.publish(veil_proto::EventPayload {
        kind: veil_proto::event_kind::SESSIONS_CHANGED,
        payload: count_u16.to_be_bytes().to_vec(),
    });
    // (b) Identity records (document / registry / ML-KEM cert / relay key)
    // + the staggered DHT store re-fan.
    mlkem_republish_now.notify_one();
    dht_republish_now.notify_one();
    // (c) Wake every outbound-connector loop out of its stretched backoff.
    force_reconnect_notify.notify_waiters();
}

#[cfg(test)]
mod tests {
    use super::*;

    const THRESHOLD: Duration = DEFAULT_SUSPENSION_GAP_THRESHOLD;

    #[test]
    fn ordinary_passage_of_time_is_not_a_suspension() {
        // Both clocks moved 15 s — awake and healthy.
        assert_eq!(detect(Duration::from_secs(15), 15_000, THRESHOLD), None);
        // Half a second of NTP slew / scheduler delay stays under threshold.
        assert_eq!(detect(Duration::from_secs(15), 15_500, THRESHOLD), None);
        // Just under the threshold must not fire.
        assert_eq!(
            detect(Duration::from_secs(15), 15_000 + 29_999, THRESHOLD),
            None
        );
    }

    #[test]
    fn a_wall_clock_running_ahead_of_monotonic_is_the_suspension() {
        // The measured live shape: the post-resume tick fires within a couple
        // of monotonic seconds while the wall clock jumped 17 minutes.
        let gap = detect(Duration::from_secs(2), 17 * 60 * 1000 + 2_000, THRESHOLD)
            .expect("a 17-minute divergence IS the suspension");
        assert_eq!(gap, Duration::from_secs(17 * 60));
        // Exactly at threshold fires — the boundary belongs to detection.
        assert_eq!(
            detect(Duration::from_secs(0), 30_000, THRESHOLD),
            Some(Duration::from_secs(30)),
        );
    }

    #[test]
    fn a_backward_wall_step_is_never_a_suspension() {
        // Operator set the clock back five minutes: monotonic moved, wall
        // went negative. Suspensions only stretch wall FORWARD.
        assert_eq!(detect(Duration::from_secs(15), -300_000, THRESHOLD), None);
    }

    #[test]
    fn the_first_sample_has_no_baseline_and_detection_rebaselines() {
        let t0 = Instant::now();
        let w0 = SystemTime::now();
        let mut watch = SuspensionWatch::new(THRESHOLD);

        // First sample: nothing to compare against.
        assert_eq!(watch.sample(t0, w0), None);

        // 15 s of honest time, then a 10-minute sleep: the next sample sees
        // wall 10 min ahead of monotonic.
        let t1 = t0 + Duration::from_secs(15);
        let w1 = w0 + Duration::from_secs(15 + 600);
        assert_eq!(watch.sample(t1, w1), Some(Duration::from_secs(600)));

        // The detecting sample became the new baseline: the very next sample
        // sees only its own 15 s of honest time and must NOT re-fire.
        let t2 = t1 + Duration::from_secs(15);
        let w2 = w1 + Duration::from_secs(15);
        assert_eq!(watch.sample(t2, w2), None);
    }

    #[tokio::test]
    async fn recovery_reaches_every_wired_consumer() {
        let event_bus = veil_ipc::EventBus::new();
        let mut events = event_bus.subscribe();
        let mlkem = Arc::new(tokio::sync::Notify::new());
        let dht = Arc::new(tokio::sync::Notify::new());
        let reconnect = Arc::new(tokio::sync::Notify::new());
        let logger = Arc::new(NodeLogger::new_noop());

        // `notify_waiters` stores no permit — park the reconnect waiter first,
        // exactly as the real connector loops sit parked in their `select!`s.
        let reconnect_waiter = {
            let n = Arc::clone(&reconnect);
            tokio::spawn(async move { n.notified().await })
        };
        tokio::task::yield_now().await;

        fire_suspension_recovery(
            Duration::from_secs(120),
            3,
            &event_bus,
            &mlkem,
            &dht,
            &reconnect,
            &logger,
        );

        // (a) The rendezvous-recipient task's wake: a well-formed
        // SESSIONS_CHANGED carrying the live count.
        let ev = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("event must arrive")
            .expect("bus must stay open");
        assert_eq!(ev.kind, veil_proto::event_kind::SESSIONS_CHANGED);
        assert_eq!(ev.payload, 3u16.to_be_bytes().to_vec());

        // (b) Republish nudges use permit semantics: an await AFTER the fire
        // must still complete — the consumer being mid-turn loses nothing.
        tokio::time::timeout(Duration::from_secs(1), mlkem.notified())
            .await
            .expect("mlkem republish permit must be stored");
        tokio::time::timeout(Duration::from_secs(1), dht.notified())
            .await
            .expect("dht republish permit must be stored");

        // (c) The parked reconnect waiter was woken.
        tokio::time::timeout(Duration::from_secs(1), reconnect_waiter)
            .await
            .expect("reconnect waiter must wake")
            .expect("waiter task must not panic");
    }
}
