use crate::{SessionTxRegistry, glue::SessionTxBroadcaster};
use std::{
    future::Future,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};
use veil_types::FrameBroadcaster;

#[derive(Default)]
struct WakeFlag(AtomicBool);
impl Wake for WakeFlag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn unregister_closes_the_outbox_even_while_an_external_sender_is_retained() {
    let peer = [0x45; 32];
    let mut registry = SessionTxRegistry::new();
    let mut outbox = registry.register(peer);
    let retained = registry.get_sender(&peer).unwrap().clone();
    let flag = Arc::new(WakeFlag::default());
    let waker = Waker::from(flag.clone());
    let mut cx = Context::from_waker(&waker);
    let mut receive = Box::pin(outbox.recv());
    assert!(receive.as_mut().poll(&mut cx).is_pending());
    flag.0.store(false, Ordering::SeqCst);
    registry.unregister(&peer);
    assert!(
        flag.0.load(Ordering::SeqCst),
        "unregister must schedule teardown despite a retained sender"
    );
    assert!(matches!(receive.as_mut().poll(&mut cx), Poll::Ready(None)));
    drop(receive);
    drop(outbox);
    assert!(retained.is_closed());
}

#[tokio::test]
async fn an_unpolled_real_broadcaster_send_cannot_keep_the_unregistered_session_alive() {
    let peer = [0x46; 32];
    let registry = Arc::new(RwLock::new(SessionTxRegistry::new()));
    let mut outbox = registry.write().unwrap().register(peer);
    let broadcaster = SessionTxBroadcaster::new(registry.clone());
    // The production adapter captures a FrameSender before the future is polled.
    let mut sending = broadcaster.send_reliable_to(&peer, b"pending source work".to_vec());
    registry.write().unwrap().unregister(&peer);
    let mut receive = Box::pin(outbox.recv());
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        matches!(receive.as_mut().poll(&mut cx), Poll::Ready(None)),
        "pending producer future must not extend canonical lifetime"
    );
    drop(receive);
    drop(outbox);
    assert!(matches!(sending.as_mut().poll(&mut cx), Poll::Ready(false)));
}

#[tokio::test]
async fn stale_owned_cleanup_does_not_retire_the_replacement_but_current_cleanup_does() {
    let peer = [0x47; 32];
    let old_owner = [1; 32];
    let new_owner = [2; 32];
    let mut registry = SessionTxRegistry::new();
    let old = registry.register_owned(peer, old_owner);
    let mut current = registry.register_owned(peer, new_owner);
    let retained = registry.get_sender(&peer).unwrap().clone();
    assert!(!registry.unregister_owned(&peer, &old_owner));
    let mut cx = Context::from_waker(Waker::noop());
    {
        let mut receive = Box::pin(current.recv());
        assert!(
            receive.as_mut().poll(&mut cx).is_pending(),
            "stale cleanup must not retire the replacement"
        );
    }
    drop(old);
    assert!(registry.send_to(
        &peer,
        veil_proto::priority::INTERACTIVE,
        b"new session".to_vec()
    ));
    assert_eq!(&*current.recv().await.unwrap().1, b"new session");
    assert!(registry.unregister_owned(&peer, &new_owner));
    let mut receive = Box::pin(current.recv());
    assert!(matches!(receive.as_mut().poll(&mut cx), Poll::Ready(None)));
    assert!(retained.is_closed());
}
