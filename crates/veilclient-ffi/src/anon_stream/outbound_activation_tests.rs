use super::*;
use futures::{StreamExt, poll};
use std::sync::atomic::AtomicUsize;

#[tokio::test]
async fn ready_outbound_candidate_does_not_wait_for_a_silent_first() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let attempts = outbound_attempts(vec![0, 1], |index| {
        let gate = Arc::clone(&gate);
        async move {
            if index == 0 {
                gate.notified().await;
            }
            index
        }
    });
    futures::pin_mut!(attempts);
    // A closed gate, not a wall-clock threshold: the production scheduler
    // must expose the ready alternative before the first confirmation ends.
    assert!(matches!(
        poll!(attempts.next()),
        std::task::Poll::Ready(Some(1))
    ));
}

#[tokio::test]
async fn outbound_candidate_work_is_bounded_and_cancels_with_its_batch() {
    struct Active(Arc<AtomicUsize>);
    impl Drop for Active {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let started = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let mut attempts = Box::pin(outbound_attempts((0..20).collect(), |_| {
        let started = Arc::clone(&started);
        let active = Arc::clone(&active);
        async move {
            started.fetch_add(1, Ordering::SeqCst);
            active.fetch_add(1, Ordering::SeqCst);
            let _active = Active(active);
            std::future::pending::<()>().await;
        }
    }));
    assert!(poll!(attempts.next()).is_pending());
    let n = started.load(Ordering::SeqCst);
    assert_eq!(active.load(Ordering::SeqCst), n);
    assert!(
        n > 1 && n <= 2,
        "unbounded or serial candidate preparation: {n}"
    );
    drop(attempts);
    assert_eq!(
        active.load(Ordering::SeqCst),
        0,
        "cancelled attempts left spawned work"
    );
}
