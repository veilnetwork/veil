use super::*;
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

#[derive(Default)]
struct WakeFlag(AtomicBool);

impl Wake for WakeFlag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn unregister_wakes_a_runner_waiting_on_a_live_silent_wire() {
    let peer = [0x35; 32];
    let mut registry = crate::SessionTxRegistry::new();
    let mut outbox = registry.register(peer);
    let (stream, _remote) = tokio::io::duplex(8192);
    let stream: BoxIoStream = Box::new(stream);
    let (mut read, _write) = tokio::io::split(stream);
    let mut reader = ordered_reader::Reader::default();
    let (wire, _writer) = mpsc::channel(1);
    let mut input = Box::pin(await_next_input(
        &mut read,
        &mut reader,
        4096,
        Some(&mut outbox),
        None,
        None,
        None,
        &wire,
        None,
        None,
        None,
        None,
        None,
    ));
    let flag = Arc::new(WakeFlag::default());
    let waker = Waker::from(flag.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(input.as_mut().poll(&mut cx).is_pending());
    flag.0.store(false, Ordering::SeqCst);
    // This is the same registry operation used by mobile NetworkChanged.
    // Neither the peer nor any timer must be needed to notice destruction.
    registry.unregister(&peer);
    assert!(
        flag.0.load(Ordering::SeqCst),
        "closing outbox must schedule its waiter"
    );
    assert!(
        matches!(
            input.as_mut().poll(&mut cx),
            Poll::Ready(NextInput::OutboxClosed)
        ),
        "closed registered outbox must wake the runner without a timer or peer input"
    );
}

#[tokio::test]
async fn a_runner_without_an_outbox_keeps_waiting_for_the_peer() {
    let (stream, _remote) = tokio::io::duplex(8192);
    let stream: BoxIoStream = Box::new(stream);
    let (mut read, _write) = tokio::io::split(stream);
    let mut reader = ordered_reader::Reader::default();
    let (wire, _writer) = mpsc::channel(1);
    let mut input = Box::pin(await_next_input(
        &mut read,
        &mut reader,
        4096,
        None,
        None,
        None,
        None,
        &wire,
        None,
        None,
        None,
        None,
        None,
    ));
    assert!(
        input
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
}

#[tokio::test]
async fn queued_frame_precedes_the_closed_outbox_event() {
    let peer = [0x36; 32];
    let mut registry = crate::SessionTxRegistry::new();
    let mut outbox = registry.register(peer);
    assert!(registry.send_to(
        &peer,
        veil_proto::priority::INTERACTIVE,
        b"last-frame".to_vec()
    ));
    registry.unregister(&peer);
    let (stream, _remote) = tokio::io::duplex(8192);
    let stream: BoxIoStream = Box::new(stream);
    let (mut read, _write) = tokio::io::split(stream);
    let mut reader = ordered_reader::Reader::default();
    let (wire, _writer) = mpsc::channel(1);
    let mut cx = Context::from_waker(Waker::noop());
    {
        let mut input = Box::pin(await_next_input(
            &mut read,
            &mut reader,
            4096,
            Some(&mut outbox),
            None,
            None,
            None,
            &wire,
            None,
            None,
            None,
            None,
            None,
        ));
        match input.as_mut().poll(&mut cx) {
            Poll::Ready(NextInput::OutboxFrame(frame)) => {
                assert_eq!(&*frame.frame.1, b"last-frame")
            }
            _ => panic!("accepted frame must drain before EOF"),
        }
    }
    let mut input = Box::pin(await_next_input(
        &mut read,
        &mut reader,
        4096,
        Some(&mut outbox),
        None,
        None,
        None,
        &wire,
        None,
        None,
        None,
        None,
        None,
    ));
    assert!(
        matches!(
            input.as_mut().poll(&mut cx),
            Poll::Ready(NextInput::OutboxClosed)
        ),
        "the final frame must not hide EOF from the next wait"
    );
}
