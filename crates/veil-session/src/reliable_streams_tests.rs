use super::*;
fn state() -> ReliableStreams {
    let ctx = super::super::ordered_receiver_tests::pool_fixture_context();
    ReliableStreams::new(true, ctx.dispatcher, ctx.peer_id)
}

fn delivery_record(msg: u16) -> Vec<u8> {
    let mut h = FrameHeader::new(FrameFamily::Delivery as u8, msg);
    let body = b"self-contained delivery record";
    h.body_len = body.len() as u32;
    veil_proto::codec::encode_frame(&h, body)
}

#[test]
fn reliable_delivery_requires_negotiation_and_leaves_network_control_on_parent() {
    use veil_proto::family::DeliveryMsg;
    let frame = delivery_record(DeliveryMsg::Forward as u16);
    let child = Some([7; 32]);
    let legacy = state();
    assert_eq!(
        legacy.route_with_local_class(&frame, child, 1),
        Route::Canonical
    );
    assert!(state().incoming(&frame, Route::Child([7; 32])).is_err());
    let mut modern = state().with_delivery(true);
    assert_eq!(
        modern.route_with_local_class(&frame, child, 1),
        Route::Child([7; 32])
    );
    assert!(modern.incoming(&frame, Route::Child([7; 32])).is_ok());
    assert_eq!(
        modern.route_with_local_class(&frame, None, 1),
        Route::Canonical
    );
    assert_eq!(
        modern.route_with_local_class(&frame, child, crate::LOCAL_NETWORK_CONTROL_LANE),
        Route::Canonical
    );
}

#[test]
fn reliable_delivery_permission_cannot_inject_parent_control_or_unopened_app_streams() {
    let mut modern = state().with_delivery(true);
    let child = Route::Child([7; 32]);
    let mut h = FrameHeader::new(FrameFamily::Session as u8, 0);
    h.body_len = 1;
    let control = veil_proto::codec::encode_frame(&h, &[0]);
    assert!(modern.incoming(&control, child).is_err());
    assert!(modern.incoming(&delivery_record(u16::MAX), child).is_err());
    for msg in [
        veil_proto::family::DeliveryMsg::Chunk,
        veil_proto::family::DeliveryMsg::ChunkManifest,
    ] {
        assert!(
            modern
                .incoming(&delivery_record(msg as u16), child)
                .is_err()
        );
    }
    let mut truncated = delivery_record(veil_proto::family::DeliveryMsg::Forward as u16);
    truncated.pop();
    assert!(modern.incoming(&truncated, child).is_err());
    assert_eq!(
        modern.route_with_local_class(&truncated, Some([7; 32]), 1),
        Route::Canonical
    );
    assert!(
        modern
            .incoming(&frame(AppMsg::AppData, 19, 1), child)
            .is_err()
    );
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

#[test]
fn delivery_records_have_no_stream_pin_and_survive_child_replacement() {
    use veil_proto::family::DeliveryMsg;
    let mut modern = state().with_delivery(true);
    for msg in [
        DeliveryMsg::Forward,
        DeliveryMsg::DeliveryStatus,
        DeliveryMsg::Transit,
        DeliveryMsg::RecursiveRelay,
        DeliveryMsg::RelayPath,
    ] {
        let bytes = delivery_record(msg as u16);
        let first = Route::Child([7; 32]);
        assert_eq!(
            modern.route_with_local_class(&bytes, Some([7; 32]), 1),
            first
        );
        modern.admitted(&bytes, first);
        modern.incoming(&bytes, first).unwrap();
        modern.fail_child([7; 32]);
        assert!(modern.pins.is_empty());
        assert_eq!(
            modern.route_with_local_class(&bytes, Some([8; 32]), 1),
            Route::Child([8; 32])
        );
        modern.incoming(&bytes, Route::Child([8; 32])).unwrap();
    }
}

#[test]
fn delivery_at_child_record_limit_is_routed_and_larger_records_keep_parent() {
    use veil_crypto::session_cipher::AEAD_OVERHEAD;
    use veil_transport::reliable_records::MAX_RECORD_BYTES;
    let modern = state().with_delivery(true);
    let body_limit = MAX_RECORD_BYTES - AEAD_OVERHEAD - HEADER_SIZE;
    for (length, expected) in [
        (body_limit, Route::Child([7; 32])),
        (body_limit + 1, Route::Canonical),
    ] {
        let mut h = FrameHeader::new(
            FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        );
        h.body_len = length as u32;
        let bytes = veil_proto::codec::encode_frame(&h, &vec![0; length]);
        assert_eq!(
            modern.route_with_local_class(&bytes, Some([7; 32]), 1),
            expected
        );
    }
}

#[test]
fn loss_tolerant_forward_fallback_never_enters_the_reliable_delivery_child() {
    use veil_proto::delivery::ForwardPayload;
    let seed = crate::runner::reliable_session_tests::forward_record(19);
    let mut forward = ForwardPayload::decode(&seed[HEADER_SIZE..]).unwrap();
    forward.envelope.payload.truncate(64);
    forward.envelope.ttl_secs = 1;
    forward.envelope.require_ack = false;
    forward.delivery_attempt = None;
    forward.traffic_class = Some(veil_proto::priority::INTERACTIVE);
    let body = forward.encode();
    assert!(ForwardPayload::is_realtime_datagram_eligible(&body));
    let mut h = decode_header(&seed).unwrap();
    h.body_len = body.len() as u32;
    let bytes = veil_proto::codec::encode_frame(&h, &body);
    let modern = state().with_delivery(true);
    for local_class in [0, 1, 2, 3, 4, 6] {
        assert_eq!(
            modern.route_with_local_class(&bytes, Some([7; 32]), local_class),
            Route::Canonical
        );
    }
}

fn direct_app_record(msg: AppMsg, data_len: usize) -> Vec<u8> {
    let body = if msg == AppMsg::AppSendUnopenable {
        Vec::new()
    } else {
        veil_proto::app::AppSendPayload {
            src_app_id: [1; 32],
            app_id: [2; 32],
            endpoint_id: 17,
            data: veil_bufpool::pooled_shared_from_vec(vec![0x55; data_len]),
        }
        .encode()
    };
    let mut h = FrameHeader::new(FrameFamily::App as u8, msg as u16);
    h.body_len = body.len() as u32;
    veil_proto::codec::encode_frame(&h, &body)
}

#[test]
fn direct_app_records_require_their_own_permission_and_keep_network_control_on_parent() {
    let mut modern = state().with_direct_app(true);
    let mut delivery_only = state().with_delivery(true);
    for msg in [
        AppMsg::AppSend,
        AppMsg::AppSendSealed,
        AppMsg::AppSendChunk,
        AppMsg::AppSendUnopenable,
    ] {
        let frame = direct_app_record(msg, 2048);
        let child = Route::Child([7; 32]);
        assert_eq!(
            delivery_only.route_with_local_class(&frame, Some([7; 32]), 3),
            Route::Canonical
        );
        assert!(delivery_only.incoming(&frame, child).is_err());
        assert_eq!(
            modern.route_with_local_class(&frame, Some([7; 32]), 3),
            child
        );
        modern.incoming(&frame, child).unwrap();
        modern.admitted(&frame, child);
        assert!(modern.pins.is_empty());
        assert_eq!(
            modern.route_with_local_class(&frame, None, 3),
            Route::Canonical
        );
        assert_eq!(
            modern.route_with_local_class(&frame, Some([7; 32]), crate::LOCAL_NETWORK_CONTROL_LANE),
            Route::Canonical
        );
        modern.fail_child([7; 32]);
        assert_eq!(
            modern.route_with_local_class(&frame, Some([8; 32]), 3),
            Route::Child([8; 32])
        );
    }
}

#[test]
fn direct_permission_excludes_rtp_streams_malformed_bodies_and_nonzero_stream_ids() {
    let mut modern = state().with_direct_app(true);
    let child = Route::Child([7; 32]);
    let mut variants = vec![
        direct_app_record(AppMsg::AppRtData, 10),
        frame(AppMsg::AppData, 19, 1),
    ];
    let base = direct_app_record(AppMsg::AppSendSealed, 10);
    let mut nonzero = base.clone();
    let mut h = decode_header(&nonzero).unwrap();
    h.stream_id = 19;
    nonzero[..HEADER_SIZE].copy_from_slice(&veil_proto::codec::encode_header(&h));
    variants.push(nonzero);
    let mut missing_data = base.clone();
    missing_data[HEADER_SIZE + 68..HEADER_SIZE + 72].copy_from_slice(&1000u32.to_be_bytes());
    variants.push(missing_data);
    let mut truncated = base;
    truncated.pop();
    variants.push(truncated);
    let mut nonempty_hint = direct_app_record(AppMsg::AppSendUnopenable, 0);
    let mut h = decode_header(&nonempty_hint).unwrap();
    h.body_len = 1;
    nonempty_hint[..HEADER_SIZE].copy_from_slice(&veil_proto::codec::encode_header(&h));
    nonempty_hint.push(1);
    variants.push(nonempty_hint);
    for bytes in variants {
        assert_eq!(
            modern.route_with_local_class(&bytes, Some([7; 32]), 3),
            Route::Canonical
        );
        assert!(modern.incoming(&bytes, child).is_err());
    }
    // The direct permission alone cannot accept Delivery on the child.
    assert!(
        modern
            .incoming(
                &delivery_record(veil_proto::family::DeliveryMsg::Forward as u16),
                child
            )
            .is_err()
    );
}

#[test]
fn oversized_direct_records_keep_the_legacy_parent_without_retiring_a_healthy_child() {
    use veil_crypto::session_cipher::AEAD_OVERHEAD;
    use veil_transport::reliable_records::MAX_RECORD_BYTES;
    let modern = state().with_direct_app(true);
    let data_limit = MAX_RECORD_BYTES - AEAD_OVERHEAD - HEADER_SIZE - 72;
    for (extra, expected) in [(0, Route::Child([7; 32])), (1, Route::Canonical)] {
        let bytes = direct_app_record(AppMsg::AppSend, data_limit + extra);
        assert_eq!(
            modern.route_with_local_class(&bytes, Some([7; 32]), 3),
            expected
        );
    }
}

#[test]
fn auxiliary_app_streams_reconcile_multiple_carriers_without_migration() {
    let mut streams = state();
    let open = frame(AppMsg::AppOpen, 700, 1);
    assert!(streams.unpinned_open(&open));
    assert!(stream_record(&open));
    streams.admitted(&open, Route::Child([11; 32]));
    assert!(!streams.unpinned_open(&open));
    streams.admitted(&frame(AppMsg::AppOpen, 701, 2), Route::Child([12; 32]));
    streams.reconcile_with(|id| id == [11; 32] || id == [12; 32]);
    assert_eq!(
        streams.route(&frame(AppMsg::AppData, 700, 1), Some([99; 32])),
        Route::Child([11; 32])
    );
    assert_eq!(
        streams.route(&frame(AppMsg::AppData, 701, 2), Some([99; 32])),
        Route::Child([12; 32])
    );
    streams.reconcile_with(|id| id == [12; 32]);
    assert_eq!(
        streams.route(&frame(AppMsg::AppData, 700, 1), Some([99; 32])),
        Route::Failed
    );
    assert_eq!(
        streams.route(&frame(AppMsg::AppData, 701, 2), Some([99; 32])),
        Route::Child([12; 32])
    );
    assert!(
        streams
            .incoming(&frame(AppMsg::AppData, 701, 2), Route::Child([99; 32]))
            .is_err()
    );
    assert!(
        streams
            .incoming(&frame(AppMsg::AppData, 702, 2), Route::Child([12; 32]))
            .is_err()
    );
    assert!(!stream_record(&delivery_record(0)));
    assert!(!stream_record(&frame(AppMsg::AppOpen, 700, 1)[..10]));
}
