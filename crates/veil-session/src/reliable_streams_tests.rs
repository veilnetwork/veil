use super::*;
fn state() -> ReliableStreams {
    let ctx = super::super::ordered_receiver_tests::pool_fixture_context();
    ReliableStreams::new(true, ctx.dispatcher, ctx.peer_id)
}
fn frame(msg: AppMsg, stream: u32, app: u8) -> Vec<u8> {
    let body = match msg {
        AppMsg::AppOpen => AppOpenPayload {
            app_id: [app; 32],
            endpoint_id: 17,
            flags: 0,
        }
        .encode()
        .to_vec(),
        AppMsg::AppClose => AppClosePayload {
            app_id: [app; 32],
            endpoint_id: 17,
            reason: 0,
        }
        .encode()
        .to_vec(),
        AppMsg::AppReceipt => AppReceiptPayload {
            app_id: [app; 32],
            endpoint_id: 17,
            seq: 0,
            status: 0,
        }
        .encode()
        .to_vec(),
        AppMsg::AppData => veil_proto::app::AppDataPayload {
            app_id: [app; 32],
            endpoint_id: 17,
            seq: 0,
            data: vec![5; 2048],
        }
        .encode(),
        _ => unreachable!(),
    };
    let mut h = FrameHeader::new(FrameFamily::App as u8, msg as u16);
    h.stream_id = stream;
    h.body_len = body.len() as u32;
    veil_proto::codec::encode_frame(&h, &body)
}
#[test]
fn canonical_fallback_is_sticky_when_a_child_later_becomes_ready() {
    let mut state = state();
    let open = frame(AppMsg::AppOpen, 19, 1);
    assert_eq!(state.route(&open, None), Route::Canonical);
    state.admitted(&open, Route::Canonical);
    assert_eq!(
        state.route(&frame(AppMsg::AppData, 19, 1), Some([2; 32])),
        Route::Canonical
    );
}
#[test]
fn incoming_open_pins_reply_data_and_close_to_the_same_child() {
    let mut state = state();
    let child = Route::Child([2; 32]);
    state
        .incoming(&frame(AppMsg::AppOpen, 19, 1), child)
        .unwrap();
    for msg in [AppMsg::AppReceipt, AppMsg::AppData, AppMsg::AppClose] {
        assert_eq!(state.route(&frame(msg, 19, 1), Some([3; 32])), child);
    }
    assert!(
        state
            .incoming(&frame(AppMsg::AppData, 19, 1), Route::Canonical)
            .is_err()
    );
    state
        .incoming(&frame(AppMsg::AppClose, 19, 1), child)
        .unwrap();
    assert_eq!(
        state.route(&frame(AppMsg::AppReceipt, 19, 1), Some([3; 32])),
        child
    );
}
#[test]
fn failure_or_rekey_never_replays_an_established_stream_on_another_carrier() {
    let mut state = state();
    state.admitted(&frame(AppMsg::AppOpen, 19, 1), Route::Child([2; 32]));
    state.reconcile(None);
    assert_eq!(
        state.route(&frame(AppMsg::AppData, 19, 1), None),
        Route::Failed
    );
    assert_eq!(
        state.route(&frame(AppMsg::AppData, 19, 1), Some([3; 32])),
        Route::Failed
    );
    assert_eq!(
        state.route(&frame(AppMsg::AppOpen, 20, 1), Some([3; 32])),
        Route::Child([3; 32])
    );
}
#[test]
fn a_peer_cannot_rebind_an_existing_stream_or_use_a_child_without_open() {
    let mut state = state();
    let child = Route::Child([2; 32]);
    assert!(
        state
            .incoming(&frame(AppMsg::AppData, 19, 1), child)
            .is_err()
    );
    state
        .incoming(&frame(AppMsg::AppOpen, 19, 1), child)
        .unwrap();
    assert!(
        state
            .incoming(&frame(AppMsg::AppOpen, 19, 2), child)
            .is_err()
    );
    assert_eq!(
        state.route(&frame(AppMsg::AppData, 19, 2), Some([2; 32])),
        Route::Failed
    );
}

#[test]
fn reliable_close_stays_abortable_until_dispatch_or_remote_receipt() {
    let mut state = state();
    let child = Route::Child([2; 32]);
    state.admitted(&frame(AppMsg::AppOpen, 19, 1), child);
    state.admitted(&frame(AppMsg::AppClose, 19, 1), child);
    assert!(
        state.pins[&19].active,
        "admission does not prove a close was flushed"
    );
    state
        .incoming(&frame(AppMsg::AppReceipt, 19, 1), child)
        .unwrap();
    assert!(!state.pins[&19].active);
    state
        .incoming(&frame(AppMsg::AppOpen, 20, 1), child)
        .unwrap();
    let close = frame(AppMsg::AppClose, 20, 1);
    state.incoming(&close, child).unwrap();
    assert!(
        state.pins[&20].active,
        "parsing does not prove dispatcher accepted close"
    );
    state.dispatched(&decode_header(&close).unwrap());
    assert!(!state.pins[&20].active);
}
#[test]
fn reliable_window_updates_follow_the_stored_stream_even_with_zero_header_id() {
    let mut state = state();
    let child = Route::Child([2; 32]);
    state.admitted(&frame(AppMsg::AppOpen, 19, 1), child);
    let body = AppWindowUpdatePayload {
        stream_id: 19,
        increment: 100,
    }
    .encode();
    let mut h = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppWindowUpdate as u16);
    h.body_len = body.len() as u32;
    let wire = veil_proto::codec::encode_frame(&h, &body);
    assert_eq!(state.route(&wire, Some([3; 32])), child);
    state.incoming(&wire, child).unwrap();
    assert!(state.incoming(&wire, Route::Canonical).is_err());
    h.stream_id = 20;
    let malformed = veil_proto::codec::encode_frame(&h, &body);
    assert!(state.incoming(&malformed, Route::Canonical).is_err());
    assert_eq!(state.route(&malformed, Some([3; 32])), Route::Failed);
}
#[test]
fn reliable_reply_backlog_is_fifo_bounded_and_scoped_to_one_generation() {
    let mut queue = Replies::new();
    for n in 0..512 {
        queue.push([2; 32], vec![(n % 256) as u8]).unwrap();
    }
    assert!(queue.push([2; 32], vec![5]).is_err());
    assert_eq!(queue.front().unwrap().1, &[0]);
    assert_eq!(queue.pop().unwrap(), vec![0]);
    queue.push([3; 32], vec![8]).unwrap();
    queue.reconcile(Some([3; 32]));
    assert_eq!(queue.pop().unwrap(), vec![8]);
    assert_eq!(queue.bytes, 0);
    assert!(queue.push([3; 32], vec![0; 65537]).is_err());
    assert!(queue.front().is_none());
}

#[tokio::test]
async fn reliable_reply_waits_for_credit_without_popping_or_advancing_cipher() {
    use crate::{
        parallel_binding::ParallelParent,
        reliable_frames::{FrameReservationError, ReliableFrameChannel},
    };
    let a = ParallelParent::new([1; 32], [2; 32], [3; 32]);
    let b = ParallelParent::new([1; 32], [3; 32], [2; 32]);
    let (hello, pending) = a.begin_reliable([4; 32]).unwrap();
    let (ack, keys) = b.accept_reliable(&hello, [4; 32]).unwrap();
    let (left, right) = tokio::io::duplex(64);
    let ca = ReliableFrameChannel::new(
        pending
            .finish(&ack)
            .unwrap()
            .into_reliable(Box::new(left))
            .unwrap(),
    );
    let cb = ReliableFrameChannel::new(keys.into_reliable(Box::new(right)).unwrap());
    let handle = ca.handle();
    let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppData as u16);
    header.body_len = (32750 - HEADER_SIZE) as u32;
    let filler = veil_proto::codec::encode_frame(&header, &vec![0; header.body_len as usize]);
    let first = handle.try_reserve(&filler).unwrap();
    let second = handle.try_reserve(&filler).unwrap();
    assert_eq!(handle.buffered_bytes(), 65536);
    let reply = frame(AppMsg::AppReceipt, 19, 1);
    let mut queue = Replies::new();
    queue.push([2; 32], reply.clone()).unwrap();
    assert!(matches!(
        queue.try_flush(&handle, |_| true),
        Err(FrameReservationError::Full)
    ));
    assert_eq!(queue.front().unwrap().1, reply.as_slice());
    drop(first);
    drop(second);
    // Bandwidth denial also retains plaintext and releases the reservation.
    assert!(matches!(
        queue.try_flush(&handle, |_| false),
        Err(FrameReservationError::Full)
    ));
    assert_eq!(handle.buffered_bytes(), 0);
    assert_eq!(
        queue.try_flush(&handle, |_| true).unwrap().unwrap().0,
        reply
    );
    let received = tokio::time::timeout(std::time::Duration::from_secs(1), cb.handle().recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        received.as_ref(),
        reply.as_slice(),
        "first RX nonce must match first committed reply"
    );
    assert!(queue.front().is_none());
}
