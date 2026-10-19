//! Real QUIC proof streams and the production scheduler, without a media role
//! on the wire. The ordinary parent is observed independently of child records.
use super::super::auxiliary_records;
use super::super::parallel_lanes::ParallelSession;
use super::super::{
    ParallelQuicOffer, RealtimeLaneOffer, RealtimeReceiverContext, RealtimeTransportOffer,
};
use super::*;
use veil_crypto::session_cipher::SessionCipher;
use veil_proto::{
    AppMsg, FrameFamily,
    codec::encode_frame,
    header::{FrameHeader, HEADER_SIZE},
};

fn record(family: FrameFamily, msg: u16, id: u32, body: &[u8]) -> veil_bufpool::PooledShared {
    let mut h = FrameHeader::new(family as u8, msg);
    h.request_id = id;
    h.body_len = body.len() as u32;
    veil_bufpool::pooled_shared_from_vec(encode_frame(&h, body))
}

fn data(byte: u8) -> veil_bufpool::PooledShared {
    let mut body = vec![byte; 1096];
    body[68..72].copy_from_slice(&1024u32.to_be_bytes());
    record(FrameFamily::App, AppMsg::AppSendChunk as u16, 0, &body)
}

struct Stand {
    task: JoinHandle<()>,
    sender: crate::FrameSender,
    rpc: Arc<crate::SessionOutbox>,
    remote: ParallelSession,
    remote_factory: veil_transport::QuicParallelHandle,
    remote_stream: veil_transport::BoxIoStream,
    handles: [QuicDatagramHandle; 2],
    diagnostics: Arc<super::super::parallel_lanes::ParallelDiagnostics>,
}

impl Stand {
    async fn new(records: bool) -> Self {
        let left = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let right = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let la = left.local_addr().unwrap();
        let ra = right.local_addr().unwrap();
        let ctx = Arc::new(TransportContext::for_debug().unwrap());
        let other = tokio::spawn(promote_punched_quic(
            right,
            la,
            ctx.clone(),
            PunchedQuicRole::Responder,
        ));
        let local = promote_punched_quic(left, ra, ctx, PunchedQuicRole::Initiator)
            .await
            .unwrap();
        let handle = local.quic_datagrams().unwrap();
        let mut offer = ParallelQuicOffer::new(local.parallel_quic().unwrap()).with_duplex();
        if records {
            offer = offer.with_auxiliary_records().with_reliable();
        }
        let diagnostics = offer.diagnostics();
        let mut stream = local.into_stream().unwrap();
        stream.write_all(b"main").await.unwrap();
        let other = other.await.unwrap().unwrap();
        let remote_handle = other.quic_datagrams().unwrap();
        let remote_factory = other.parallel_quic().unwrap();
        let mut remote_offer = ParallelQuicOffer::new(remote_factory.clone()).with_duplex();
        if records {
            remote_offer = remote_offer.with_auxiliary_records().with_reliable();
        }
        let mut remote_stream = other.into_stream().unwrap();
        remote_stream.read_exact(&mut [0; 4]).await.unwrap();
        let mut registry = crate::SessionTxRegistry::new();
        let outbox = registry.register([0xB1; 32]);
        let sender = registry.get_sender(&[0xB1; 32]).unwrap().clone();
        let mut runner = super::reliable_source_pressure_quic_tests::make_runner(
            stream,
            outbox,
            Some(RealtimeLaneOffer {
                transport: RealtimeTransportOffer::Quic(handle.clone()),
                peer_datagrams: true,
                peer_flows: true,
                peer_rotates: true,
                peer_circuit_datagrams: true,
                peer_neutral_forwards: true,
                parallel: Some(offer),
            }),
        );
        runner.crypto.tx_cipher = Some(SessionCipher::new(&[2; 32], true));
        runner.crypto.rx_cipher = Some(SessionCipher::new(&[3; 32], true));
        runner.raw_session_keys = Some(([2; 32], [3; 32], [1; 32]));
        let rpc = crate::SessionOutbox::new();
        runner.rpc_outbox = Some(rpc.register([0xB1; 32]));
        let context = RealtimeReceiverContext {
            peer_id: [0xA0; 32],
            dispatcher: runner.dispatcher.clone(),
            logger: runner.logger.clone(),
            metrics: None,
            ban_list: runner.ban_list.clone(),
            violation_tracker: runner.violation_tracker.clone(),
            activity: Arc::new(crate::datagram_activity::AuthenticatedDatagramActivity::new()),
        };
        let remote = ParallelSession::new(remote_offer, &[3; 32], &[2; 32], [1; 32], context, None);
        let task = tokio::spawn(async move { runner.run().await });
        Self {
            task,
            sender,
            rpc,
            remote,
            remote_factory,
            remote_stream,
            handles: [handle, remote_handle],
            diagnostics,
        }
    }

    async fn next(&self) -> auxiliary_records::Received {
        timeout(Duration::from_secs(5), self.remote.next_auxiliary())
            .await
            .expect("source record delivered")
    }

    async fn stop(mut self) {
        for handle in &self.handles {
            handle.close();
        }
        timeout(Duration::from_secs(3), &mut self.task)
            .await
            .expect("runner stopped")
            .unwrap();
    }
}

impl Drop for Stand {
    fn drop(&mut self) {
        for h in &self.handles {
            h.close();
        }
        self.task.abort();
    }
}

#[tokio::test]
async fn auxiliary_files_and_rpc_use_separate_children_while_transit_stays_canonical() {
    let mut stand = Stand::new(true).await;
    let payload = data(7);
    assert!(stand.sender.send_reliable(payload.clone()).await);
    let file = stand.next().await;
    assert_eq!(&*file.frame, &*payload);
    assert!(file.parent.is_active());
    assert!(file.received_at <= Instant::now());

    let request = record(
        FrameFamily::Discovery,
        veil_proto::DiscoveryMsg::FindValue as u16,
        71,
        b"query",
    );
    let reply = stand
        .rpc
        .send_request([0xB1; 32], 71, request.to_vec())
        .unwrap();
    let query = stand.next().await;
    assert_eq!(&*query.frame, &*request);
    // Independent child TX/RX state: a file-side failure cannot close control.
    file.handle.close();
    let response = record(
        FrameFamily::Discovery,
        veil_proto::DiscoveryMsg::FindValueResponse as u16,
        71,
        b"answer",
    );
    let receipt = query
        .handle
        .try_send((crate::LOCAL_NETWORK_CONTROL_LANE, response).into())
        .ok()
        .unwrap();
    receipt.wait().await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), reply)
            .await
            .unwrap()
            .unwrap(),
        Some(b"answer".to_vec())
    );

    // Same exact bytes without trusted own credit: no promotion from headers.
    stand
        .sender
        .try_send((veil_proto::priority::INTERACTIVE, payload.clone()))
        .unwrap();
    let mut prefix = [0; HEADER_SIZE];
    timeout(
        Duration::from_secs(3),
        stand.remote_stream.read_exact(&mut prefix),
    )
    .await
    .unwrap()
    .unwrap();
    let h = veil_proto::codec::decode_header(&prefix).unwrap();
    let mut body = vec![0; h.body_len as usize];
    stand.remote_stream.read_exact(&mut body).await.unwrap();
    let body = SessionCipher::new(&[2; 32], true)
        .open(&body, &veil_proto::codec::frame_aad(&h))
        .unwrap();
    assert_eq!(body, payload[HEADER_SIZE..]);
    assert!(stand.diagnostics.active_connections() <= 8);
    stand.stop().await;
}

#[tokio::test]
async fn auxiliary_legacy_peer_keeps_ordinary_writer_and_source_credit() {
    let mut stand = Stand::new(false).await;
    let payload = data(8);
    assert!(stand.sender.send_reliable(payload.clone()).await);
    let mut prefix = [0; HEADER_SIZE];
    timeout(
        Duration::from_secs(3),
        stand.remote_stream.read_exact(&mut prefix),
    )
    .await
    .unwrap()
    .unwrap();
    let h = veil_proto::codec::decode_header(&prefix).unwrap();
    let mut body = vec![0; h.body_len as usize];
    stand.remote_stream.read_exact(&mut body).await.unwrap();
    let body = SessionCipher::new(&[2; 32], true)
        .open(&body, &veil_proto::codec::frame_aad(&h))
        .unwrap();
    assert_eq!(body, payload[HEADER_SIZE..]);
    assert!(
        timeout(Duration::from_millis(30), stand.remote.next_auxiliary())
            .await
            .is_err()
    );
    assert_eq!(stand.diagnostics.active_connections(), 0);
    stand.stop().await;
}

#[test]
fn auxiliary_rejects_session_stream_and_realtime_payloads() {
    assert!(auxiliary_records::eligible(&data(3)));
    assert!(!auxiliary_records::eligible(&record(
        FrameFamily::Session,
        veil_proto::SessionMsg::RekeyInit as u16,
        0,
        &[]
    )));
    assert!(!auxiliary_records::eligible(&record(
        FrameFamily::App,
        AppMsg::AppData as u16,
        0,
        &[]
    )));
    assert!(!auxiliary_records::eligible(&record(
        FrameFamily::App,
        AppMsg::AppRtData as u16,
        0,
        &[1; 20]
    )));
    let mut malformed = data(4).to_vec();
    malformed.pop();
    assert!(!auxiliary_records::eligible(&malformed));
}

#[tokio::test]
async fn auxiliary_control_remains_usable_at_the_generic_connection_limit() {
    timeout(Duration::from_secs(15), async {
        let mut stand = Stand::new(true).await;
        for lane in crate::local_datagram_status::LOCAL_DATAGRAM_PRIORITIES {
            timeout(Duration::from_secs(3), async {
                while !stand.remote.prepare(lane) {
                    sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        }
        for index in [5, 6] {
            timeout(Duration::from_secs(3), async {
                while !stand.remote.prepare_without_recovery(index) {
                    sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        }
        let connection = stand.remote_factory.connect().await.unwrap();
        let raw = connection.quic_datagrams().unwrap();
        let mut stream = connection.into_stream().unwrap();
        let owner = crate::parallel_binding::ParallelParent::new([1; 32], [3; 32], [2; 32]);
        let (hello, pending) = owner.begin(raw.channel_binding().unwrap()).unwrap();
        stream.write_all(&hello).await.unwrap();
        let mut ack = [0; 32];
        stream.read_exact(&mut ack).await.unwrap();
        let _extra = pending
            .finish(&ack)
            .unwrap()
            .into_auxiliary_records(stream, raw)
            .unwrap();
        assert_eq!(stand.remote_factory.available_connection_slots(), 0);
        let source = crate::local_source_activity::LocalSourceActivity::default();
        for _ in 0..5 {
            assert!(
                stand
                    .remote
                    .auxiliary_sender(crate::LOCAL_SIGNALING_LANE, &source)
                    .is_some(),
                "control cannot be evicted at quota"
            );
            sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(stand.remote_factory.available_connection_slots(), 0);
        stand.stop().await;
    })
    .await
    .unwrap();
}
