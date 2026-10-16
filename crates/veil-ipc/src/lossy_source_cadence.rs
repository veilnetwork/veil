//! Bounded origin-only cadence of opaque local work. No inter-node metadata.
use std::collections::VecDeque;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Key {
    pub destination: [u8; 32],
    pub source_app: [u8; 32],
    pub destination_app: [u8; 32],
    pub endpoint: u32,
    pub lane: u8,
}

const CAPACITY: usize = 64;
const INITIAL: Duration = Duration::from_millis(33);
const MIN_SAMPLE: Duration = Duration::from_millis(2);
const IDLE: Duration = Duration::from_secs(10);

#[derive(Default)]
pub(crate) struct SourceCadence {
    entries: VecDeque<(Key, Instant, Duration)>,
}

impl SourceCadence {
    pub(crate) fn observe(&mut self, key: Key, now: Instant) -> Duration {
        let mut span = INITIAL;
        if let Some(index) = self.entries.iter().position(|entry| entry.0 == key) {
            let (_, previous, last_span) = self.entries.remove(index).unwrap();
            let elapsed = now.saturating_duration_since(previous);
            span = if now < previous || elapsed >= IDLE {
                INITIAL
            } else if elapsed < MIN_SAMPLE {
                // Draining several already-complete frames from IPC is not
                // evidence that their original producer suddenly sped up.
                last_span
            } else {
                elapsed.min(veil_types::local_lossy_work::MAX_PACING_SPAN)
            };
        } else if self.entries.len() == CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back((key, now, span));
        span
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(destination: u8, lane: u8) -> Key {
        Key {
            destination: [destination; 32],
            source_app: [1; 32],
            destination_app: [2; 32],
            endpoint: 0,
            lane,
        }
    }
    #[test]
    fn recipient_and_plane_copies_do_not_corrupt_actual_frame_cadence() {
        let mut tracker = SourceCadence::default();
        let now = Instant::now();
        for peer in [3, 4] {
            assert_eq!(tracker.observe(key(peer, 2), now), INITIAL);
        }
        assert_eq!(
            tracker.observe(key(3, 2), now + Duration::from_secs(1)),
            Duration::from_millis(100)
        );
        assert_eq!(
            tracker.observe(key(4, 2), now + Duration::from_millis(20)),
            Duration::from_millis(20)
        );
        assert_eq!(
            tracker.observe(key(3, 3), now + Duration::from_secs(1)),
            INITIAL
        );
        assert_eq!(
            tracker.observe(key(3, 2), now + Duration::from_millis(1016)),
            Duration::from_millis(16)
        );
        assert_eq!(
            tracker.observe(key(3, 2), now + Duration::from_micros(1016500)),
            Duration::from_millis(16)
        );
    }
    #[test]
    fn history_is_bounded_and_idle_or_backward_time_starts_fresh() {
        let mut tracker = SourceCadence::default();
        let now = Instant::now();
        for peer in 0..=CAPACITY as u8 {
            tracker.observe(key(peer, 2), now);
        }
        assert_eq!(tracker.entries.len(), CAPACITY);
        assert_eq!(
            tracker.observe(key(0, 2), now + Duration::from_secs(1)),
            INITIAL
        );
        assert_eq!(
            tracker.observe(key(0, 2), now + Duration::from_millis(1020)),
            Duration::from_millis(20)
        );
        assert_eq!(tracker.observe(key(0, 2), now), INITIAL);
        assert_eq!(tracker.observe(key(0, 2), now + IDLE), INITIAL);
    }
}
