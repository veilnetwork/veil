//! Trusted local observations only. This handler never sends network frames.
use std::time::{Duration, Instant};
use veil_proto::ipc::LocalSourceFeedbackPayload;
use veil_types::FrameBroadcaster;

pub(crate) fn handle_local_source_feedback(
    body: &[u8],
    negotiated: bool,
    owns_app: impl FnOnce(&[u8; 32]) -> bool,
    registry: Option<&dyn FrameBroadcaster>,
    now_unix_ms: u64,
    now: Instant,
) -> bool {
    if !negotiated {
        return false;
    }
    let Ok(report) = LocalSourceFeedbackPayload::decode(body) else {
        return false;
    };
    if !report.is_fresh_at(now_unix_ms) || !owns_app(&report.source_app_id) {
        return false;
    }
    let Some(registry) = registry else {
        return false;
    };
    // Preserve the original sampling instant through IPC backlog. Starting a
    // new lease at receipt would let delayed/replayed-but-still-fresh reports
    // hold competing sources after their observation's lease already ended.
    // Same-host future clock tolerance must never extend a lease into the future.
    let age = Duration::from_millis(now_unix_ms.saturating_sub(report.sampled_at_unix_ms));
    let Some(sampled_at) = now.checked_sub(age) else {
        return false;
    };
    registry.note_local_source_feedback(report.pressured, sampled_at)
}

/// Explicit hold is negotiated separately so old daemons retain old semantics.
/// Current health and the original hold event are validated independently.
pub(crate) fn handle_local_source_growth_hold(
    body: &[u8],
    negotiated: bool,
    owns_app: impl FnOnce(&[u8; 32]) -> bool,
    registry: Option<&dyn FrameBroadcaster>,
    now_unix_ms: u64,
    now: Instant,
) -> bool {
    use veil_proto::ipc::LocalSourceGrowthHoldPayload;
    if !negotiated {
        return false;
    }
    let Ok(report) = LocalSourceGrowthHoldPayload::decode(body) else {
        return false;
    };
    if !report.is_fresh_at(now_unix_ms) || !owns_app(&report.source_app_id) {
        return false;
    }
    let Some(registry) = registry else {
        return false;
    };
    let Some(sampled_at) = now.checked_sub(Duration::from_millis(
        now_unix_ms.saturating_sub(report.sampled_at_unix_ms),
    )) else {
        return false;
    };
    let remaining = LocalSourceGrowthHoldPayload::HOLD_MS
        - now_unix_ms.saturating_sub(report.hold_started_at_unix_ms);
    let Some(until) = now.checked_add(Duration::from_millis(remaining)) else {
        return false;
    };
    registry.note_local_source_growth_hold(sampled_at, until, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct Observer(
        AtomicUsize,
        Mutex<Vec<Instant>>,
        Mutex<Vec<(Instant, Instant, Instant)>>,
    );
    impl FrameBroadcaster for Observer {
        fn note_local_source_feedback(&self, pressured: bool, sampled_at: Instant) -> bool {
            self.0
                .fetch_add(if pressured { 1 } else { 100 }, Ordering::Relaxed);
            self.1.lock().unwrap().push(sampled_at);
            true
        }
        fn note_local_source_growth_hold(
            &self,
            sampled_at: Instant,
            until: Instant,
            received_at: Instant,
        ) -> bool {
            self.2
                .lock()
                .unwrap()
                .push((sampled_at, until, received_at));
            true
        }
        fn send_to(&self, _: &[u8; 32], _: u8, _: Vec<u8>) -> bool {
            panic!("feedback must not forward");
        }
        fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {
            panic!("feedback must not forward");
        }
        fn active_node_ids(&self) -> Vec<[u8; 32]> {
            vec![]
        }
    }

    #[test]
    fn held_health_is_owned_fresh_negotiated_and_has_one_original_deadline() {
        use veil_proto::ipc::LocalSourceGrowthHoldPayload;
        let registry = Observer::default();
        let origin = Instant::now();
        let mut report = LocalSourceGrowthHoldPayload {
            source_app_id: [7; 32],
            sampled_at_unix_ms: 10_000,
            hold_started_at_unix_ms: 10_000,
        };
        for (sample_ms, receipt_ms) in [(0, 0), (1000, 1200), (1000, 1400), (2000, 2400)] {
            report.sampled_at_unix_ms = 10_000 + sample_ms;
            assert!(handle_local_source_growth_hold(
                &report.encode(),
                true,
                |id| *id == [7; 32],
                Some(&registry),
                10_000 + receipt_ms,
                origin + Duration::from_millis(receipt_ms)
            ));
        }
        let seen = registry.2.lock().unwrap();
        for (sampled, until, received) in seen.iter() {
            assert_eq!(*until, origin + Duration::from_secs(3));
            assert!(*sampled <= *received);
        }
        assert_eq!(
            seen[2].0,
            origin + Duration::from_secs(1),
            "replay cannot renew health freshness"
        );
        drop(seen);
        for (negotiated, owned, clock) in [
            (false, true, 12_000),
            (true, false, 12_000),
            (true, true, 13_000),
            (true, true, 14_000),
        ] {
            assert!(!handle_local_source_growth_hold(
                &report.encode(),
                negotiated,
                |_| owned,
                Some(&registry),
                clock,
                origin + Duration::from_millis(clock - 10_000)
            ));
        }
        assert!(!handle_local_source_growth_hold(
            &report.encode()[..47],
            true,
            |_| true,
            Some(&registry),
            12_000,
            origin + Duration::from_secs(2)
        ));
        assert_eq!(registry.2.lock().unwrap().len(), 4);
        assert_eq!(
            registry.0.load(Ordering::Relaxed),
            0,
            "hold is not the legacy pressure signal"
        );
    }

    #[test]
    fn ipc_delay_and_replay_do_not_renew_the_original_observation() {
        let registry = Observer::default();
        let sampled_at = Instant::now();
        let report = LocalSourceFeedbackPayload {
            source_app_id: [7; 32],
            pressured: true,
            sampled_at_unix_ms: 10_000,
        };
        for elapsed_ms in [0, 1200, LocalSourceFeedbackPayload::MAX_AGE_MS] {
            assert!(handle_local_source_feedback(
                &report.encode(),
                true,
                |id| *id == report.source_app_id,
                Some(&registry),
                10_000 + elapsed_ms,
                sampled_at + Duration::from_millis(elapsed_ms),
            ));
        }
        assert_eq!(
            *registry.1.lock().unwrap(),
            vec![sampled_at; 3],
            "IPC receipt and replay must preserve, not refresh, the source lease"
        );
        assert!(!handle_local_source_feedback(
            &report.encode(),
            true,
            |_| true,
            Some(&registry),
            11_501,
            sampled_at + Duration::from_millis(1501),
        ));
        assert_eq!(registry.0.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn tolerated_future_clock_correction_cannot_extend_the_lease() {
        let registry = Observer::default();
        let received_at = Instant::now();
        let report = LocalSourceFeedbackPayload {
            source_app_id: [7; 32],
            pressured: false,
            sampled_at_unix_ms: 10_000 + LocalSourceFeedbackPayload::MAX_FUTURE_MS,
        };
        assert!(handle_local_source_feedback(
            &report.encode(),
            true,
            |_| true,
            Some(&registry),
            10_000,
            received_at,
        ));
        assert_eq!(*registry.1.lock().unwrap(), vec![received_at]);
    }

    #[test]
    fn refuses_foreign_unnegotiated_stale_and_malformed_reports() {
        let registry = Observer::default();
        let now = Instant::now();
        let report = LocalSourceFeedbackPayload {
            source_app_id: [7; 32],
            pressured: true,
            sampled_at_unix_ms: 10_000,
        };
        let body = report.encode();
        let owns = |id: &[u8; 32]| *id == [7; 32];
        assert!(handle_local_source_feedback(
            &body,
            true,
            owns,
            Some(&registry),
            10_000,
            now
        ));
        assert!(!handle_local_source_feedback(
            &body,
            false,
            owns,
            Some(&registry),
            10_000,
            now
        ));
        assert!(!handle_local_source_feedback(
            &body,
            true,
            |_| false,
            Some(&registry),
            10_000,
            now
        ));
        assert!(!handle_local_source_feedback(
            &body,
            true,
            owns,
            Some(&registry),
            11_501,
            now
        ));
        assert!(!handle_local_source_feedback(
            &body,
            true,
            owns,
            Some(&registry),
            9_749,
            now
        ));
        assert!(!handle_local_source_feedback(
            &body[..40],
            true,
            owns,
            Some(&registry),
            10_000,
            now
        ));
        assert!(!handle_local_source_feedback(
            &body, true, owns, None, 10_000, now
        ));
        assert_eq!(
            registry.0.load(Ordering::Relaxed),
            1,
            "rejected reports did not mutate admission"
        );
    }
}
