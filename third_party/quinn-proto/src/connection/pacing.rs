//! Pacing of packet transmissions.

use crate::{Duration, Instant};

use tracing::warn;

/// A simple token-bucket pacer
///
/// The pacer's capacity is derived on a fraction of the congestion window
/// which can be sent in regular intervals
/// Once the bucket is empty, further transmission is blocked.
/// The bucket refills at a rate slightly faster
/// than one congestion window per RTT, as recommended in
/// <https://tools.ietf.org/html/draft-ietf-quic-recovery-34#section-7.7>
pub(super) struct Pacer {
    capacity: u64,
    last_window: u64,
    last_mtu: u16,
    tokens: u64,
    prev: Instant,
}

impl Pacer {
    /// Obtains a new [`Pacer`].
    pub(super) fn new(smoothed_rtt: Duration, window: u64, mtu: u16, now: Instant) -> Self {
        let capacity = optimal_capacity(smoothed_rtt, window, mtu);
        Self {
            capacity,
            last_window: window,
            last_mtu: mtu,
            tokens: capacity,
            prev: now,
        }
    }

    /// Record that a packet has been transmitted.
    pub(super) fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into())
    }

    /// Return how long we need to wait before sending `bytes_to_send`
    ///
    /// If we can send a packet right away, this returns `None`. Otherwise, returns `Some(d)`,
    /// where `d` is the time before this function should be called again.
    ///
    /// The 5/4 ratio used here comes from the suggestion that N = 1.25 in the draft IETF RFC for
    /// QUIC.
    pub(super) fn delay(
        &mut self,
        smoothed_rtt: Duration,
        bytes_to_send: u64,
        mtu: u16,
        window: u64,
        now: Instant,
    ) -> Option<Instant> {
        debug_assert_ne!(
            window, 0,
            "zero-sized congestion control window is nonsense"
        );

        if window != self.last_window || mtu != self.last_mtu {
            self.capacity = optimal_capacity(smoothed_rtt, window, mtu);

            // Clamp the tokens
            self.tokens = self.capacity.min(self.tokens);
            self.last_window = window;
            self.last_mtu = mtu;
        }

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        // we disable pacing for extremely large windows
        if window > u64::from(u32::MAX) {
            return None;
        }

        let window = window as u32;

        let time_elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
            warn!("received a timestamp early than a previous recorded time, ignoring");
            Default::default()
        });

        if smoothed_rtt.as_nanos() == 0 {
            return None;
        }

        let elapsed_rtts = time_elapsed.as_secs_f64() / smoothed_rtt.as_secs_f64();
        let new_tokens = window as f64 * 1.25 * elapsed_rtts;
        self.tokens = self
            .tokens
            .saturating_add(new_tokens as _)
            .min(self.capacity);

        self.prev = now;

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        // The ten-MTU capacity is useful for retaining earned burst credit,
        // but it must not become a compulsory refill target. With a 4-KiB
        // congestion window and 120-ms RTT that target sleeps for 283 ms,
        // even though one MTU earns enough credit after 29 ms. Wake for one
        // packet or the normal two-ms batching interval, whichever is larger.
        // Keep the same 5/4 refill rate and debit actual transmitted bytes;
        // this neither bypasses congestion control nor reads an application role.
        let interval_credit = ((u128::from(window) * BURST_INTERVAL_NANOS)
            / smoothed_rtt.as_nanos())
        .min(u128::from(self.capacity)) as u64;
        let refill_target = bytes_to_send.max(interval_credit);
        // Round upward to the first instant with enough byte credit. Rounding
        // down can repeatedly wake one byte short and discard fractional
        // refill credit when `prev` advances, starving a small-window source.
        let delay_nanos = smoothed_rtt
            .as_nanos()
            .saturating_mul(u128::from(refill_target - self.tokens))
            .saturating_mul(4)
            .div_ceil(u128::from(window) * 5);
        let delay = Duration::new(
            (delay_nanos / 1_000_000_000).min(u128::from(u64::MAX)) as u64,
            (delay_nanos % 1_000_000_000) as u32,
        );
        Some(self.prev + delay)
    }
}

/// Calculates a pacer capacity for a certain window and RTT
///
/// The goal is to emit a burst (of size `capacity`) in timer intervals
/// which compromise between
/// - ideally distributing datagrams over time
/// - constantly waking up the connection to produce additional datagrams
///
/// Too short burst intervals means we will never meet them since the timer
/// accuracy in user-space is not high enough. If we miss the interval by more
/// than 25%, we will lose that part of the congestion window since no additional
/// tokens for the extra-elapsed time can be stored.
///
/// Too long burst intervals make pacing less effective.
fn optimal_capacity(smoothed_rtt: Duration, window: u64, mtu: u16) -> u64 {
    let rtt = smoothed_rtt.as_nanos().max(1);

    let capacity = ((window as u128 * BURST_INTERVAL_NANOS) / rtt) as u64;

    // Small bursts are less efficient (no GSO), could increase latency and don't effectively
    // use the channel's buffer capacity. Large bursts might block the connection on sending.
    capacity.clamp(MIN_BURST_SIZE * mtu as u64, MAX_BURST_SIZE * mtu as u64)
}

/// The burst interval
///
/// The capacity will we refilled in 4/5 of that time.
/// 2ms is chosen here since framework timers might have 1ms precision.
/// If kernel-level pacing is supported later a higher time here might be
/// more applicable.
const BURST_INTERVAL_NANOS: u128 = 2_000_000; // 2ms

/// Allows some usage of GSO, and doesn't slow down the handshake.
const MIN_BURST_SIZE: u64 = 10;

/// Creating 256 packets took 1ms in a benchmark, so larger bursts don't make sense.
const MAX_BURST_SIZE: u64 = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_panic_on_bad_instant() {
        let old_instant = Instant::now();
        let new_instant = old_instant + Duration::from_micros(15);
        let rtt = Duration::from_micros(400);

        assert!(Pacer::new(rtt, 30000, 1500, new_instant)
            .delay(Duration::from_micros(0), 0, 1500, 1, old_instant)
            .is_none());
        assert!(Pacer::new(rtt, 30000, 1500, new_instant)
            .delay(Duration::from_micros(0), 1600, 1500, 1, old_instant)
            .is_none());
        assert!(Pacer::new(rtt, 30000, 1500, new_instant)
            .delay(Duration::from_micros(0), 1500, 1500, 3000, old_instant)
            .is_none());
    }

    #[test]
    fn derives_initial_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let pacer = Pacer::new(rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(Duration::from_millis(0), window, mtu, now);
        assert_eq!(pacer.capacity, MAX_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(rtt, 1, mtu, now);
        assert_eq!(pacer.capacity, MIN_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    #[test]
    fn adjusts_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);
        let initial_tokens = pacer.tokens;

        pacer.delay(rtt, mtu as u64, mtu, window * 2, now);
        assert_eq!(
            pacer.capacity,
            (2 * window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens);

        pacer.delay(rtt, mtu as u64, mtu, window / 2, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 / 2 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens / 2);

        pacer.delay(rtt, mtu as u64, mtu * 2, window, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );

        pacer.delay(rtt, mtu as u64, 20_000, window, now);
        assert_eq!(pacer.capacity, 20_000_u64 * MIN_BURST_SIZE);
    }

    #[test]
    fn a_small_window_does_not_wait_for_ten_mtus_of_credit() {
        let now = Instant::now();
        let rtt = Duration::from_millis(120);
        let window = 4065;
        let mtu = 1200;
        let mut pacer = Pacer::new(rtt, window, mtu, now);
        // Exhaust previously earned credit. The connection's congestion
        // controller still separately limits outstanding bytes.
        pacer.on_transmit(pacer.capacity as u16);
        let wake = pacer.delay(rtt, mtu as u64, mtu, window, now).unwrap();
        assert!(
            wake - now <= Duration::from_millis(30),
            "one packet has enough credit in 29 ms, but wake was {:?}",
            wake - now
        );
        let sent_at = now + Duration::from_millis(30);
        assert!(pacer.delay(rtt, mtu as u64, mtu, window, sent_at).is_none());
        pacer.on_transmit(mtu);
        let next = pacer.delay(rtt, mtu as u64, mtu, window, sent_at).unwrap();
        assert!(next - sent_at <= Duration::from_millis(30));
        assert!(
            next > sent_at,
            "early wake must not grant excess byte credit"
        );
    }

    #[test]
    fn earlier_small_window_wakes_preserve_the_byte_rate() {
        let start = Instant::now();
        let rtt = Duration::from_millis(120);
        let window = 4065;
        let mtu = 1200;
        let mut pacer = Pacer::new(rtt, window, mtu, start);
        pacer.on_transmit(pacer.capacity as u16);
        let mut now = start;
        let mut sent = 0u64;
        while now - start < Duration::from_secs(1) {
            if let Some(wake) = pacer.delay(rtt, mtu as u64, mtu, window, now) {
                assert!(wake > now);
                now = wake;
            } else {
                pacer.on_transmit(mtu);
                sent += mtu as u64;
            }
        }
        let budget = window as f64 * 1.25 / rtt.as_secs_f64();
        assert!(
            sent as f64 <= budget,
            "early wake must not grant byte credit"
        );
        assert!(sent as f64 > budget - 2.0 * mtu as f64);
    }

    #[test]
    fn computes_pause_correctly() {
        let window = 2_000_000u64;
        let mtu = 1000;
        let rtt = Duration::from_millis(50);
        let old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, old_instant);
        let packet_capacity = pacer.capacity / mtu as u64;

        for _ in 0..packet_capacity {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        let pace_duration = Duration::from_nanos((BURST_INTERVAL_NANOS * 4 / 5) as u64);

        assert_eq!(
            pacer
                .delay(rtt, mtu as u64, mtu, window, old_instant)
                .expect("Send must be delayed")
                .duration_since(old_instant),
            pace_duration
        );

        // Refill half of the tokens
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                old_instant + pace_duration / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity / 2);

        for _ in 0..packet_capacity / 2 {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        // Refill all capacity by waiting more than the expected duration
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                old_instant + pace_duration * 3 / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity);
    }
}
