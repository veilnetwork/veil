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
async fn replacement_owner_end_wakes_old_runner_and_its_credit_waiter() {
    let peer = [0x35; 32];
    let local = [0x20; 32];
    let mut registry = crate::SessionTxRegistry::with_capacity(8);
    let mut outbox = registry
        .try_register_directional(peer, &local, true, false, false, [1; 32])
        .unwrap();
    let sender = registry.get_sender(&peer).unwrap().clone();
    assert!(
        sender
            .send_reliable(veil_bufpool::pooled_shared_from_vec(vec![7; 60 * 1024]))
            .await
    );
    let held = outbox.recv_envelope().await.unwrap();
    let mut credit_waiter =
        Box::pin(sender.send_reliable(veil_bufpool::pooled_shared_from_vec(vec![8])));
    let credit_flag = Arc::new(WakeFlag::default());
    let credit_waker = Waker::from(credit_flag.clone());
    assert!(
        credit_waiter
            .as_mut()
            .poll(&mut Context::from_waker(&credit_waker))
            .is_pending()
    );
    credit_flag.0.store(false, Ordering::SeqCst);

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
    assert!(
        input
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    flag.0.store(false, Ordering::SeqCst);
    // Production learned-peer eviction drops the old registration owner.
    // A borrowed producer keeps its ordinary sender alive independently.
    let mut replacement = registry
        .try_register_directional(peer, &local, true, false, true, [2; 32])
        .unwrap();
    assert!(flag.0.load(Ordering::SeqCst));
    assert!(
        matches!(
            input.as_mut().poll(&mut Context::from_waker(&waker)),
            Poll::Ready(NextInput::OutboxClosed)
        ),
        "owner end was ignored while an old producer retained the sender"
    );
    drop(input);
    assert!(credit_flag.0.load(Ordering::SeqCst));
    assert_eq!(
        credit_waiter
            .as_mut()
            .poll(&mut Context::from_waker(&credit_waker)),
        Poll::Ready(false)
    );
    // Neither pending bytes nor late cleanup may migrate into the successor.
    assert!(matches!(
        replacement.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    assert!(!registry.unregister_owned(&peer, &[1; 32]));
    assert!(registry.send_to(&peer, veil_proto::priority::INTERACTIVE, vec![9]));
    assert_eq!(&*replacement.try_recv().unwrap().1, &[9]);
    drop(held);
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
