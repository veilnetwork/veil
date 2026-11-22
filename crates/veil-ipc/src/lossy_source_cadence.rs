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
    entries: VecDeque<(Key, Instant, Option<Duration>)>,
}

impl SourceCadence {
    pub(crate) fn observe(&mut self, key: Key, now: Instant, cells: usize) -> SourceSchedule {
        let mut interval = None;
        let mut max_age = veil_types::local_lossy_work::SOURCE_WORK_MAX_AGE;
        if let Some(index) = self.entries.iter().position(|entry| entry.0 == key) {
            let (_, previous, last_interval) = self.entries.remove(index).unwrap();
            let elapsed = now.saturating_duration_since(previous);
            interval = if now < previous || elapsed >= IDLE {
                None
            } else if elapsed < MIN_SAMPLE {
                // Draining several already-complete frames from IPC is not
                // evidence that their original producer suddenly sped up.
                last_interval
            } else {
                Some(elapsed)
            };
            // A compact frame can wait for carrier ACKs at the first observed
            // slowdown of a running camera. A larger work item still needs
            // sustained sparse cadence. Startup, bursts and screen work keep
            // the ordinary lifetime.
            let sparse = SPARSE_MIN_INTERVAL..=SPARSE_MAX_INTERVAL;
            if key.lane == veil_proto::priority::BULK
                && sparse.contains(&elapsed)
                && last_interval.is_some_and(|last| {
                    sparse.contains(&last) || (cells == 1 && last < SPARSE_MIN_INTERVAL)
                })
            {
                max_age = SPARSE_CAMERA_MAX_AGE;
            }
        } else if self.entries.len() == CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back((key, now, interval));
        SourceSchedule {
            span: interval
                .unwrap_or(INITIAL)
                .min(veil_types::local_lossy_work::MAX_PACING_SPAN),
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
            assert_eq!(tracker.observe(key(peer, 2), now, 2).span, INITIAL);
        }
        assert_eq!(
            tracker
                .observe(key(3, 2), now + Duration::from_secs(1), 2)
                .span,
            Duration::from_millis(100)
        );
        assert_eq!(
            tracker
                .observe(key(4, 2), now + Duration::from_millis(20), 2)
                .span,
            Duration::from_millis(20)
        );
        assert_eq!(
            tracker
                .observe(key(3, 3), now + Duration::from_secs(1), 2)
                .span,
            INITIAL
        );
        assert_eq!(
            tracker
                .observe(key(3, 2), now + Duration::from_millis(1016), 2)
                .span,
            Duration::from_millis(16)
        );
        assert_eq!(
            tracker
                .observe(key(3, 2), now + Duration::from_micros(1016500), 2)
                .span,
            Duration::from_millis(16)
        );
    }
    #[test]
    fn history_is_bounded_and_idle_or_backward_time_starts_fresh() {
        let mut tracker = SourceCadence::default();
        let now = Instant::now();
        for peer in 0..=CAPACITY as u8 {
            tracker.observe(key(peer, 2), now, 2);
        }
        assert_eq!(tracker.entries.len(), CAPACITY);
        assert_eq!(
            tracker
                .observe(key(0, 2), now + Duration::from_secs(1), 2)
                .span,
            INITIAL
        );
        assert_eq!(
            tracker
                .observe(key(0, 2), now + Duration::from_millis(1020), 2)
                .span,
            Duration::from_millis(20)
        );
        assert_eq!(tracker.observe(key(0, 2), now, 2).span, INITIAL);
        assert_eq!(tracker.observe(key(0, 2), now + IDLE, 2).span, INITIAL);
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
                let sample = tracker.observe(plane, now + Duration::from_secs(offset), 2);
                assert_eq!(sample.max_age, SOURCE_WORK_MAX_AGE);
            }
        }
        let at = now + Duration::from_secs(2);
        let sparse = tracker.observe(camera, at, 2);
        assert_eq!(sparse.span, MAX_PACING_SPAN);
        assert_eq!(sparse.max_age, SPARSE_CAMERA_MAX_AGE);
        assert_eq!(tracker.observe(screen, at, 2).max_age, SOURCE_WORK_MAX_AGE);
        assert_eq!(
            tracker
                .observe(camera, at + Duration::from_millis(1), 2)
                .max_age,
            SOURCE_WORK_MAX_AGE,
        );
        assert_eq!(
            tracker
                .observe(camera, at + Duration::from_millis(34), 2)
                .max_age,
            SOURCE_WORK_MAX_AGE,
        );
        assert_eq!(
            tracker
                .observe(camera, at + Duration::from_secs(4), 2)
                .max_age,
            SOURCE_WORK_MAX_AGE,
        );
    }

    #[test]
    fn compact_camera_frame_can_wait_at_the_first_measured_slowdown() {
        use veil_types::local_lossy_work::SOURCE_WORK_MAX_AGE;

        let now = Instant::now();
        let camera = key(3, veil_proto::priority::BULK);
        let screen = key(3, veil_proto::priority::BACKGROUND);
        for (plane, cells, expected) in [
            (camera, 1, SPARSE_CAMERA_MAX_AGE),
            (camera, 2, SOURCE_WORK_MAX_AGE),
            (screen, 1, SOURCE_WORK_MAX_AGE),
        ] {
            let mut tracker = SourceCadence::default();
            tracker.observe(plane, now, cells);
            tracker.observe(plane, now + Duration::from_millis(464), cells);
            let slowdown = now + Duration::from_millis(1485);
            assert_eq!(tracker.observe(plane, slowdown, cells).max_age, expected);
            assert_eq!(
                tracker
                    .observe(plane, slowdown + Duration::from_millis(33), cells)
                    .max_age,
                SOURCE_WORK_MAX_AGE,
            );
        }

        let mut startup = SourceCadence::default();
        startup.observe(camera, now, 1);
        assert_eq!(
            startup
                .observe(camera, now + Duration::from_secs(1), 1)
                .max_age,
            SOURCE_WORK_MAX_AGE,
        );
    }
}
