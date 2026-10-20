//! A local stream cancellation can race bytes already admitted by the peer.
use super::*;
use veil_proto::app::{AppClosePayload, AppDataPayload, AppRtDataPayload};
use veil_proto::family::AppMsg;

const PEER: [u8; 32] = [0x55; 32];
const APP: [u8; 32] = [0xaa; 32];
const STREAM: u32 = 4242;

fn data(d: &FrameDispatcher) -> DispatchResult {
    let body = AppDataPayload {
        app_id: APP,
        endpoint_id: 9,
        seq: 0,
        data: vec![7; 32],
    }
    .encode();
    let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppData as u16);
    header.stream_id = STREAM;
    d.dispatch(&header, &body, PEER)
}

fn assert_closed(result: DispatchResult) {
    let DispatchResult::Response(frame) = result else {
        panic!("late bytes must close only their stream, got {result:?}");
    };
    let header = veil_proto::codec::decode_header(&frame).unwrap();
    assert_eq!(header.msg_type, AppMsg::AppClose as u16);
    assert_eq!(header.stream_id, STREAM);
    let close = AppClosePayload::decode(&frame[veil_proto::header::HEADER_SIZE..]).unwrap();
    assert_eq!(close.app_id, APP);
    assert_eq!(close.endpoint_id, 9);
}

#[test]
fn late_data_after_local_bridge_backpressure_does_not_accuse_the_peer() {
    let d = make_test_dispatcher(NodeRole::Core);
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
    tx.try_send(vec![1]).unwrap();
    d.veil_stream_rx.lock().unwrap().insert((PEER, STREAM), tx);

    // The first blocked delivery closes the bridge. More bytes may already
    // be in the independent reliable connection before its close is read.
    assert_closed(data(&d));
    for _ in 0..8 {
        assert_closed(data(&d));
    }
    assert_eq!(rx.try_recv().unwrap(), vec![1]);
    assert!(rx.try_recv().is_err());
    assert!(d.veil_stream_rx.lock().unwrap().is_empty());
    assert_eq!(d.stream_table.len(), 0);

    // The unrelated live datagram endpoint still receives its exact payload.
    let (_endpoint, mut inbox) = d.app_registry.register(APP, 13, 4);
    let payload = AppRtDataPayload {
        src_app_id: [0xbb; 32],
        app_id: APP,
        endpoint_id: 13,
        seq: 1,
        timestamp_us: 123,
        marker: 0,
        payload_type: 96,
        payload: vec![3, 4, 5],
    };
    let header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppRtData as u16);
    assert!(matches!(
        d.dispatch(&header, &payload.encode(), PEER),
        DispatchResult::NoResponse
    ));
    let veil_app::registry::AppMessage::RtData { payload, .. } = inbox.try_recv().unwrap() else {
        panic!("expected a datagram, not late stream data");
    };
    assert_eq!(payload.payload, vec![3, 4, 5]);
}

#[test]
fn closed_tracked_stream_and_never_opened_stream_do_not_deliver_late_bytes() {
    let d = make_test_dispatcher(NodeRole::Core);
    assert_closed(data(&d));
    d.stream_table.open(PEER, STREAM, APP, 9);
    d.stream_table.close(&PEER, STREAM);
    assert_closed(data(&d));
    assert_eq!(d.stream_table.len(), 0);
}

#[test]
fn live_stream_window_overrun_still_is_a_protocol_violation() {
    let d = make_test_dispatcher(NodeRole::Core);
    d.stream_table
        .open_with_window(PEER, STREAM, APP, 9, 256, 31);
    assert!(matches!(data(&d), DispatchResult::Violation(_)));
    assert_eq!(d.stream_table.get(&PEER, STREAM).unwrap().recv_window, 31);
}
