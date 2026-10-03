use super::*;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use veil_app::registry::AppMessage;
use veil_proto::{AppRtDataPayload, family::AppMsg};
use veil_transport::{
    TransportContext,
    quic::{PunchedQuicRole, promote_punched_quic},
};

async fn runner_channels_over_real_quic(flows: bool) {
    let a_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a_socket.local_addr().unwrap();
    let b_addr = b_socket.local_addr().unwrap();
    let context = Arc::new(TransportContext::for_debug().unwrap());
    let b_context = Arc::clone(&context);
    let b_task = tokio::spawn(async move {
        promote_punched_quic(b_socket, a_addr, b_context, PunchedQuicRole::Responder).await
    });
    let a = promote_punched_quic(a_socket, b_addr, context, PunchedQuicRole::Initiator)
        .await
        .unwrap();
    let a_datagrams = a.quic_datagrams().unwrap();
    let mut a_stream = a.into_stream().unwrap();
    // Advertise the first bidi stream before waiting for accept_bi.
    a_stream.write_all(b"test").await.unwrap();
    let b = b_task.await.unwrap().unwrap();
    let b_datagrams = b.quic_datagrams().unwrap();
    let mut b_stream = b.into_stream().unwrap();
    let mut prelude = [0u8; 4];
    b_stream.read_exact(&mut prelude).await.unwrap();

    let mut tasks = Vec::new();
    let mut receivers = Vec::new();
    let mut senders = Vec::new();
    let mut endpoints = Vec::new();
    let app_id = [0xa0; 32];
    for (stream, datagrams, tx_key, rx_key) in [
        (a_stream, a_datagrams, [1; 32], [2; 32]),
        (b_stream, b_datagrams, [2; 32], [1; 32]),
    ] {
        let (_, dummy) = tokio::io::duplex(64);
        let (mut runner, _) = make_swap_runner(dummy);
        let dispatcher = Arc::new(make_test_dispatcher(NodeRole::Core));
        let (endpoint, receiver) = dispatcher.app_registry.register(app_id, 1, 64);
        endpoints.push(endpoint);
        let (out_tx, out_rx) = mpsc::channel::<PriorityFrame>(32);
        runner.stream = stream;
        runner.quic_datagrams = Some(RealtimeLaneOffer {
            handle: datagrams,
            peer_rotates: true,
            peer_flows: flows,
        });
        runner.session_id = [3; 32];
        runner.raw_session_keys = Some((tx_key, rx_key, [3; 32]));
        runner.outbox = Some(out_rx.into());
        runner.ban_list = Arc::clone(&dispatcher.abuse.ban_list);
        runner.violation_tracker = Arc::clone(&dispatcher.abuse.violation_tracker);
        runner.logger = Arc::clone(&dispatcher.logger);
        runner.dispatcher = dispatcher;
        tasks.push(tokio::spawn(async move { runner.run().await }));
        receivers.push(receiver);
        senders.push(out_tx);
    }
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        // Exercise BOTH queue selections and both directions through actual
        // SessionRunners, QUIC DATAGRAM I/O, frame parsing and app dispatch.
        for direction in 0..2 {
            for seq in 0..16 {
                let data = vec![seq as u8; if seq % 2 == 0 { 160 } else { 1500 }];
                let payload = AppRtDataPayload {
                    src_app_id: [0xb0; 32],
                    app_id,
                    endpoint_id: 1,
                    seq,
                    timestamp_us: u64::from(seq) * 20_000,
                    marker: 0,
                    payload_type: 0,
                    payload: data.clone(),
                };
                let body = payload.encode();
                let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppRtData as u16);
                header.body_len = body.len() as u32;
                let mut frame = encode_header(&header).to_vec();
                frame.extend(body);
                let local_priority = if seq % 2 == 0 { 0 } else { 2 };
                senders[direction]
                    .send((local_priority, veil_bufpool::pooled_shared_from_vec(frame)))
                    .await
                    .unwrap();
                match receivers[1 - direction].recv().await.unwrap() {
                    AppMessage::RtData {
                        src_node_id,
                        payload,
                    } => {
                        assert_eq!(src_node_id, [1; 32]);
                        assert_eq!(payload.seq, seq);
                        assert_eq!(payload.payload, data);
                    }
                    other => panic!("unexpected dispatched message {other:?}"),
                }
            }
        }
    })
    .await;
    // Aborting a runner must also drop its receive task and transport clones.
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    assert!(
        result.is_ok(),
        "both local channels must deliver via QUIC datagrams"
    );
}

#[tokio::test]
async fn opaque_channels_run_bidirectionally_over_real_quic() {
    runner_channels_over_real_quic(true).await;
}

#[tokio::test]
async fn legacy_datagram_lane_still_runs_bidirectionally_over_real_quic() {
    runner_channels_over_real_quic(false).await;
}
