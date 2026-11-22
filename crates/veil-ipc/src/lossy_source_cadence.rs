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
const SPARSE_MIN_INTERVAL: Duration = Duration::from_millis(500);
const SPARSE_MAX_INTERVAL: Duration = Duration::from_secs(2);
const SPARSE_CAMERA_MAX_AGE: Duration = Duration::from_millis(450);

pub(crate) struct SourceSchedule {
    pub(crate) span: Duration,
    pub(crate) max_age: Duration,
}

#[derive(Default)]
pub(crate) struct SourceCadence {
    entries: VecDeque<(Key, Instant, Duration)>,
}

impl SourceCadence {
    pub(crate) fn observe(&mut self, key: Key, now: Instant) -> SourceSchedule {
        let mut interval = INITIAL;
        let mut max_age = veil_types::local_lossy_work::SOURCE_WORK_MAX_AGE;
        if let Some(index) = self.entries.iter().position(|entry| entry.0 == key) {
            let (_, previous, last_interval) = self.entries.remove(index).unwrap();
            let elapsed = now.saturating_duration_since(previous);
            interval = if now < previous || elapsed >= IDLE {
                INITIAL
            } else if elapsed < MIN_SAMPLE {
                // Draining several already-complete frames from IPC is not
                // evidence that their original producer suddenly sped up.
                last_interval
            } else {
                elapsed
            };
            // A real pair of sparse camera intervals gives a complete frame
            // time to wait for carrier ACKs. Preserve short expiry for bursts,
            // capture restarts and the independently scheduled screen lane.
            let sparse = SPARSE_MIN_INTERVAL..=SPARSE_MAX_INTERVAL;
            if key.lane == veil_proto::priority::BULK
                && sparse.contains(&elapsed)
                && sparse.contains(&last_interval)
            {
                max_age = SPARSE_CAMERA_MAX_AGE;
            }
        } else if self.entries.len() == CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back((key, now, interval));
        SourceSchedule {
            span: interval.min(veil_types::local_lossy_work::MAX_PACING_SPAN),
            max_age,
        }
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
            assert_eq!(tracker.observe(key(peer, 2), now).span, INITIAL);
        }
        assert_eq!(
            tracker
                .observe(key(3, 2), now + Duration::from_secs(1))
                .span,
            Duration::from_millis(100)
        );
        assert_eq!(
            tracker
                .observe(key(4, 2), now + Duration::from_millis(20))
                .span,
            Duration::from_millis(20)
        );
        assert_eq!(
            tracker
                .observe(key(3, 3), now + Duration::from_secs(1))
                .span,
            INITIAL
        );
        assert_eq!(
            tracker
                .observe(key(3, 2), now + Duration::from_millis(1016))
                .span,
            Duration::from_millis(16)
        );
        assert_eq!(
            tracker
                .observe(key(3, 2), now + Duration::from_micros(1016500))
                .span,
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
            tracker
                .observe(key(0, 2), now + Duration::from_secs(1))
                .span,
            INITIAL
        );
        assert_eq!(
            tracker
                .observe(key(0, 2), now + Duration::from_millis(1020))
                .span,
            Duration::from_millis(20)
        );
        assert_eq!(tracker.observe(key(0, 2), now).span, INITIAL);
        assert_eq!(tracker.observe(key(0, 2), now + IDLE).span, INITIAL);
    }

    #[test]
    fn only_regular_sparse_camera_work_gets_a_longer_queue_lifetime() {
        use veil_types::local_lossy_work::{MAX_PACING_SPAN, SOURCE_WORK_MAX_AGE};

        let mut tracker = SourceCadence::default();
        let camera = key(3, veil_proto::priority::BULK);
        let screen = key(3, veil_proto::priority::BACKGROUND);
        let now = Instant::now();
        for plane in [camera, screen] {
            for offset in [0, 1] {
                let sample = tracker.observe(plane, now + Duration::from_secs(offset));
                assert_eq!(sample.max_age, SOURCE_WORK_MAX_AGE);
            }
        }
        let at = now + Duration::from_secs(2);
        let sparse = tracker.observe(camera, at);
        assert_eq!(sparse.span, MAX_PACING_SPAN);
        assert_eq!(sparse.max_age, SPARSE_CAMERA_MAX_AGE);
        assert_eq!(tracker.observe(screen, at).max_age, SOURCE_WORK_MAX_AGE);
        assert_eq!(
            tracker
                .observe(camera, at + Duration::from_millis(1))
                .max_age,
            SOURCE_WORK_MAX_AGE,
        );
        assert_eq!(
            tracker
                .observe(camera, at + Duration::from_millis(34))
                .max_age,
            SOURCE_WORK_MAX_AGE,
        );
        assert_eq!(
            tracker.observe(camera, at + Duration::from_secs(4)).max_age,
            SOURCE_WORK_MAX_AGE,
        );
    }
}
