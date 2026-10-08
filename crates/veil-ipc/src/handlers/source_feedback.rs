//! Trusted local observations only. This handler never sends network frames.
use std::time::Instant;
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
    registry.note_local_source_feedback(report.pressured, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Default)]
    struct Observer(AtomicUsize);
    impl FrameBroadcaster for Observer {
        fn note_local_source_feedback(&self, pressured: bool, _: Instant) -> bool {
            self.0
                .fetch_add(if pressured { 1 } else { 100 }, Ordering::Relaxed);
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
