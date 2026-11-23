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
const SPARSE_RESUME_MAX_GAP: Duration = Duration::from_secs(20);
const SPARSE_CAMERA_MAX_AGE: Duration = Duration::from_millis(450);

pub(crate) struct SourceSchedule {
    pub(crate) span: Duration,
    pub(crate) max_age: Duration,
}

#[derive(Default)]
pub(crate) struct SourceCadence {
    entries: VecDeque<Observation>,
}

struct Observation {
    key: Key,
    at: Instant,
    interval: Option<Duration>,
    compact_resume: bool,
}

impl SourceCadence {
    pub(crate) fn observe(&mut self, key: Key, now: Instant, cells: usize) -> SourceSchedule {
        let mut interval = None;
        let mut max_age = veil_types::local_lossy_work::SOURCE_WORK_MAX_AGE;
        let mut compact_resume = false;
        if let Some(index) = self.entries.iter().position(|entry| entry.key == key) {
            let last = self.entries.remove(index).unwrap();
            let previous = last.at;
            let last_interval = last.interval;
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
            // slowdown or after a quiet gap in an established sparse camera.
            // Startup, bursts and screen work keep the ordinary lifetime.
            let sparse = SPARSE_MIN_INTERVAL..=SPARSE_MAX_INTERVAL;
            let previous_sparse = last_interval.is_some_and(|last| sparse.contains(&last));
            // The pause itself is not a frame interval. A second compact
            // frame at the expected cadence revalidates the earlier history.
            let compact_continuation = cells == 1 && last.compact_resume;
            let sparse_frame = sparse.contains(&elapsed)
                && (compact_continuation
                    || last_interval.is_some_and(|last| {
                        sparse.contains(&last) || (cells == 1 && last < SPARSE_MIN_INTERVAL)
                    }));
            let camera = key.lane == veil_proto::priority::BULK;
            compact_resume = camera
                && cells == 1
                && previous_sparse
                && elapsed > SPARSE_MAX_INTERVAL
                && elapsed <= SPARSE_RESUME_MAX_GAP;
            if camera && (sparse_frame || compact_resume) {
                max_age = SPARSE_CAMERA_MAX_AGE;
            }
        } else if self.entries.len() == CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back(Observation {
            key,
            at: now,
            interval,
            compact_resume,
        });
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

    #[test]
    fn compact_resume_retains_sparse_deadline_after_camera_pause() {
        use veil_types::local_lossy_work::SOURCE_WORK_MAX_AGE;

        let now = Instant::now();
        let camera = key(3, veil_proto::priority::BULK);
        let screen = key(3, veil_proto::priority::BACKGROUND);
        for (plane, cells, before_pause_ms, gap_ms, expected) in [
            (camera, 1, 997, 9_997, SPARSE_CAMERA_MAX_AGE),
            (camera, 1, 983, 10_004, SPARSE_CAMERA_MAX_AGE),
            (camera, 2, 983, 10_004, SOURCE_WORK_MAX_AGE),
            (screen, 1, 983, 10_004, SOURCE_WORK_MAX_AGE),
            (camera, 1, 33, 10_004, SOURCE_WORK_MAX_AGE),
            (camera, 1, 983, 20_001, SOURCE_WORK_MAX_AGE),
        ] {
            let mut tracker = SourceCadence::default();
            let previous = now + Duration::from_millis(before_pause_ms);
            tracker.observe(plane, now, 1);
            tracker.observe(plane, previous, 1);
            let resumed = previous + Duration::from_millis(gap_ms);
            assert_eq!(tracker.observe(plane, resumed, cells).max_age, expected);
            assert_eq!(
                tracker
                    .observe(plane, resumed + Duration::from_millis(33), 1)
                    .max_age,
                SOURCE_WORK_MAX_AGE,
            );
        }
    }

    #[test]
    fn second_compact_frame_confirms_sparse_cadence_after_a_pause() {
        use veil_types::local_lossy_work::SOURCE_WORK_MAX_AGE;

        let now = Instant::now();
        let camera = key(3, veil_proto::priority::BULK);
        let screen = key(3, veil_proto::priority::BACKGROUND);
        for (plane, gap_ms, first_cells, next_ms, next_cells, expected) in [
            (camera, 10_928, 1, 1_026, 1, SPARSE_CAMERA_MAX_AGE),
            (camera, 9_999, 1, 500, 1, SPARSE_CAMERA_MAX_AGE),
            (camera, 10_928, 1, 2_000, 1, SPARSE_CAMERA_MAX_AGE),
            (camera, 10_928, 1, 499, 1, SOURCE_WORK_MAX_AGE),
            (camera, 10_928, 1, 2_001, 1, SOURCE_WORK_MAX_AGE),
            (camera, 10_928, 1, 1_026, 2, SOURCE_WORK_MAX_AGE),
            (camera, 10_928, 2, 1_026, 1, SOURCE_WORK_MAX_AGE),
            (camera, 20_001, 1, 1_026, 1, SOURCE_WORK_MAX_AGE),
            (screen, 10_928, 1, 1_026, 1, SOURCE_WORK_MAX_AGE),
        ] {
            let mut tracker = SourceCadence::default();
            tracker.observe(plane, now, 1);
            let before_pause = now + Duration::from_millis(997);
            tracker.observe(plane, before_pause, 1);
            let resumed = before_pause + Duration::from_millis(gap_ms);
            tracker.observe(plane, resumed, first_cells);
            let next = resumed + Duration::from_millis(next_ms);
            assert_eq!(tracker.observe(plane, next, next_cells).max_age, expected);
        }
    }
}
