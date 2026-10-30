//! Confirmation scheduling needs no node, network, hooks or reduced PoW.
use super::{MAX_CONCURRENT_INBOUND_CONFIRMATIONS, start_then_confirm_inbound};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

/// A confirmed later registration must publish while an earlier one is still
/// waiting, not only after that unrelated candidate's timeout. Polling once
/// against a held gate makes the old serial ordering fail without a clock.
#[tokio::test]
async fn slow_confirmation_does_not_delay_other_inbound_publications() {
    use std::{future::Future, task::Poll};
    let (release, wait) = tokio::sync::oneshot::channel();
    let mut wait = Some(wait);
    let published = Arc::new(Mutex::new(Vec::new()));
    let mut activation = Box::pin(start_then_confirm_inbound(
        vec![1, 2],
        |candidate| candidate,
        |candidate| {
            let held = (candidate == 1).then(|| wait.take().unwrap());
            let published = Arc::clone(&published);
            async move {
                if let Some(held) = held {
                    held.await.unwrap();
                }
                published.lock().unwrap().push(candidate);
                candidate
            }
        },
    ));
    std::future::poll_fn(|cx| {
        assert!(activation.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(
        *published.lock().unwrap(),
        vec![2],
        "a ready registration's publication waited for an unrelated confirmation"
    );
    release.send(()).unwrap();
    assert_eq!(
        activation.await,
        vec![1, 2],
        "keep input order in the batch result"
    );
    assert_eq!(*published.lock().unwrap(), vec![2, 1]);
}

#[tokio::test]
async fn cancelling_inbound_confirmation_batch_leaves_no_confirmation_tail() {
    use std::{future::Future, task::Poll};
    struct Pending(Arc<AtomicU64>);
    impl Drop for Pending {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::Relaxed);
        }
    }
    let active = Arc::new(AtomicU64::new(0));
    let mut activation = Box::pin(start_then_confirm_inbound(
        (0..MAX_CONCURRENT_INBOUND_CONFIRMATIONS + 3).collect(),
        |candidate| candidate,
        |_| {
            let active = Arc::clone(&active);
            async move {
                active.fetch_add(1, Ordering::Relaxed);
                let _pending = Pending(active);
                std::future::pending::<()>().await;
            }
        },
    ));
    std::future::poll_fn(|cx| {
        assert!(activation.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(
        active.load(Ordering::Relaxed),
        MAX_CONCURRENT_INBOUND_CONFIRMATIONS as u64,
        "oversized pinned sets must not create unbounded confirmation probes"
    );
    drop(activation);
    assert_eq!(active.load(Ordering::Relaxed), 0);
}
