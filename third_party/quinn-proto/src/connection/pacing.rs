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
    last_rtt: Duration,
    explicit_rate_bps: Option<u64>,
    tokens: u64,
    // Retain sub-byte credit across unrelated driver polls.
    fraction: f64,
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
            last_rtt: smoothed_rtt,
            explicit_rate_bps: None,
            tokens: capacity,
            fraction: 0.0,
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

        self.settle(now);
        self.configure(smoothed_rtt, window, mtu, None);
        if window > u64::from(u32::MAX) || smoothed_rtt.as_nanos() == 0 {
            return None;
        }
        let window = window as u32;
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
        // Round upward using the remaining whole-byte deficit. The sub-byte
        // carry remains available on refill; conservatively ignoring it here
        // costs less than one byte of pacing time and cannot overspend credit.
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
    /// A controller-specified rate already includes its own pacing gain.
    /// It is a local transport instruction, never an application role.
    pub(super) fn delay_with_rate(
        &mut self,
        smoothed_rtt: Duration,
        bytes_to_send: u64,
        mtu: u16,
        window: u64,
        rate_bps: Option<u64>,
        now: Instant,
    ) -> Option<Instant> {
        let Some(rate) = rate_bps.filter(|rate| *rate > 0) else {
            return self.delay(smoothed_rtt, bytes_to_send, mtu, window, now);
        };
        self.settle(now);
        self.configure(smoothed_rtt, window, mtu, Some(rate));
        if self.tokens >= bytes_to_send {
            return None;
        }
        let interval_credit = ((u128::from(rate) * BURST_INTERVAL_NANOS) / 8_000_000_000)
            .min(u128::from(self.capacity)) as u64;
        let target = bytes_to_send.max(interval_credit);
        let deficit = (target - self.tokens) as f64 - self.fraction;
        let nanos = (deficit * 8_000_000_000.0 / rate as f64).ceil() as u128;
        Some(
            self.prev
                + Duration::new(
                    (nanos / 1_000_000_000).min(u128::from(u64::MAX)) as u64,
                    (nanos % 1_000_000_000) as u32,
                ),
        )
    }

    fn configure(&mut self, rtt: Duration, window: u64, mtu: u16, rate: Option<u64>) {
        if self.last_window == window
            && self.last_mtu == mtu
            && self.last_rtt == rtt
            && self.explicit_rate_bps == rate
        {
            return;
        }
        self.capacity = match rate {
            // Keep the existing two-ms timer quantum, but derive burst size
            // from the requested rate rather than an unrelated large cwnd.
            // A two-packet floor supports GSO. The BBR send-quantum discussion
            // permits a local batching choice for CPU/timer constraints:
            // https://www.ietf.org/archive/id/draft-ietf-ccwg-bbr-06.html#section-4.6.3
            Some(bits) => ((u128::from(bits) * BURST_INTERVAL_NANOS) / 8_000_000_000)
                .clamp(u128::from(mtu) * 2, (64 * 1024).max(u128::from(mtu) * 2))
                as u64,
            None => optimal_capacity(rtt, window, mtu),
        };
        if self.tokens >= self.capacity {
            self.fraction = 0.0;
        }
        self.tokens = self.tokens.min(self.capacity);
        self.last_window = window;
        self.last_mtu = mtu;
        self.last_rtt = rtt;
        self.explicit_rate_bps = rate;
    }

    fn settle(&mut self, now: Instant) {
        let elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
            warn!("received a timestamp earlier than the settled pacing clock, ignoring");
            Default::default()
        });
        self.prev = self.prev.max(now);
        // Settle the OLD rate and capacity before installing a new model.
        // Idle time and an increased rate cannot mint a larger new burst.
        let rate = match self.explicit_rate_bps {
            Some(bits) => bits as f64 / 8.0,
            None if self.last_window <= u64::from(u32::MAX) && !self.last_rtt.is_zero() => {
                self.last_window as f64 * 1.25 / self.last_rtt.as_secs_f64()
            }
            None => 0.0,
        };
        let earned = rate * elapsed.as_secs_f64() + self.fraction;
        let filled = self.tokens.saturating_add(earned as u64);
        if filled >= self.capacity {
            self.tokens = self.capacity;
            self.fraction = 0.0;
        } else {
            self.tokens = filled;
            self.fraction = earned.fract();
        }
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
    fn explicit_controller_rate_limits_a_large_window_without_extra_gain() {
        let now = Instant::now();
        let rtt = Duration::from_millis(1);
        let mut p = Pacer::new(rtt, 1_000_000, 1200, now);
        for _ in 0..2 {
            assert_eq!(
                p.delay_with_rate(rtt, 1200, 1200, 1_000_000, Some(96_000), now),
                None
            );
            p.on_transmit(1200);
        }
        assert_eq!(
            p.delay_with_rate(rtt, 1200, 1200, 1_000_000, Some(96_000), now),
            Some(now + Duration::from_millis(100))
        );
    }

    #[test]
    fn a_rate_increase_cannot_reprice_old_time_as_new_credit() {
        let now = Instant::now();
        let rtt = Duration::from_millis(1);
        let mut p = Pacer::new(rtt, 1_000_000, 1200, now);
        p.delay_with_rate(rtt, 1200, 1200, 1_000_000, Some(96_000), now);
        p.on_transmit(2400);
        let later = now + Duration::from_millis(10);
        let wake = p
            .delay_with_rate(rtt, 1200, 1200, 1_000_000, Some(80_000_000), later)
            .unwrap();
        assert_eq!(p.tokens, 120);
        assert!(wake > later && wake <= later + Duration::from_millis(2));
    }

    #[test]
    fn an_unknown_controller_rate_uses_the_normal_pacer() {
        let now = Instant::now();
        let rtt = Duration::from_millis(120);
        let mut plain = Pacer::new(rtt, 4065, 1200, now);
        let mut unknown = Pacer::new(rtt, 4065, 1200, now);
        plain.on_transmit(12000);
        unknown.on_transmit(12000);
        for at in [
            now,
            now + Duration::from_millis(10),
            now + Duration::from_millis(30),
        ] {
            assert_eq!(
                plain.delay(rtt, 1200, 1200, 4065, at),
                unknown.delay_with_rate(rtt, 1200, 1200, 4065, Some(0), at)
            );
        }
    }

    #[test]
    fn idle_time_cannot_fund_two_bursts_at_the_same_instant() {
        let start = Instant::now();
        let rtt = Duration::from_millis(120);
        let window = 4065;
        let mtu = 1200;
        for already_sent in [0, 3] {
            let mut pacer = Pacer::new(rtt, window, mtu, start);
            for _ in 0..already_sent {
                pacer.on_transmit(mtu);
            }
            let resumed = start + Duration::from_secs(10);
            let mut packets = 0;
            while pacer.delay(rtt, mtu as u64, mtu, window, resumed).is_none() {
                pacer.on_transmit(mtu);
                packets += 1;
                assert!(packets <= 10, "the same idle time funded extra packets");
            }
            assert_eq!(packets, 10);
        }
    }

    #[test]
    fn frequent_driver_polls_preserve_sub_byte_credit() {
        let start = Instant::now();
        let rtt = Duration::from_secs(1);
        let mut pacer = Pacer::new(rtt, 8, 1, start);
        pacer.on_transmit(10);
        let mut sent = 0;
        // Ten bytes/s, sampled more frequently than one byte can be earned.
        for n in 1..=1200 {
            let now = start + Duration::from_micros(n * 100);
            if pacer.delay(rtt, 1, 1, 8, now).is_none() {
                pacer.on_transmit(1);
                sent += 1;
            }
        }
        assert_eq!(sent, 1, "poll frequency cannot erase all delivery credit");
    }

    #[test]
    fn old_timestamps_cannot_replay_a_settled_refill_interval() {
        let start = Instant::now();
        let rtt = Duration::from_millis(120);
        let mut pacer = Pacer::new(rtt, 4065, 1200, start);
        pacer.on_transmit(12000);
        let later = start + Duration::from_millis(10);
        assert!(pacer.delay(rtt, 1200, 1200, 4065, later).is_some());
        let settled = pacer.tokens;
        assert!(pacer.delay(rtt, 1200, 1200, 4065, start).is_some());
        assert!(pacer.delay(rtt, 1200, 1200, 4065, later).is_some());
        assert_eq!(pacer.tokens, settled);
    }

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
