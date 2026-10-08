use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};

fn parents() -> (ParallelParent, ParallelParent) {
    (
        ParallelParent::new([1; 32], [2; 32], [3; 32]),
        ParallelParent::new([1; 32], [3; 32], [2; 32]),
    )
}

fn keys(a: &ParallelParent, b: &ParallelParent) -> (ParallelKeys, ParallelKeys) {
    let (hello, pending) = a.begin_reliable([4; 32]).unwrap();
    let (ack, b_keys) = b.accept_reliable(&hello, [4; 32]).unwrap();
    (pending.finish(&ack).unwrap(), b_keys)
}

#[test]
fn reliable_mode_cannot_be_downgraded_replayed_reflected_or_acknowledged_as_lossy() {
    let (a, b) = parents();
    let (hello, pending) = a.begin_reliable([4; 32]).unwrap();
    assert_eq!(
        b.accept(&hello, [4; 32]).unwrap_err(),
        BindingError::InvalidProof
    );
    assert_eq!(
        b.accept_reliable(&hello, [5; 32]).unwrap_err(),
        BindingError::InvalidProof
    );
    assert_eq!(
        a.accept_reliable(&hello, [4; 32]).unwrap_err(),
        BindingError::InvalidProof
    );
    let wrong_parent = ParallelParent::new([9; 32], [3; 32], [2; 32]);
    assert_eq!(
        wrong_parent.accept_reliable(&hello, [4; 32]).unwrap_err(),
        BindingError::InvalidProof
    );
    let mut downgraded = hello;
    downgraded[..8].copy_from_slice(PREFACE);
    assert_eq!(
        b.accept(&downgraded, [4; 32]).unwrap_err(),
        BindingError::InvalidProof
    );
    let lossy_keys = a.keys(&[9; 32], &[4; 32], RecordMode::LossTolerant);
    let reliable_keys = a.keys(&[9; 32], &[4; 32], RecordMode::Reliable);
    assert_ne!(lossy_keys.session_id, reliable_keys.session_id);
    assert_ne!(lossy_keys.tx_key(), reliable_keys.tx_key());
    assert_ne!(lossy_keys.rx_key(), reliable_keys.rx_key());
    let (lossy_hello, _) = a.begin([4; 32]).unwrap();
    let mut upgraded = lossy_hello;
    upgraded[..8].copy_from_slice(RELIABLE_PREFACE);
    assert_eq!(
        b.accept_reliable(&upgraded, [4; 32]).unwrap_err(),
        BindingError::InvalidProof
    );
    let (lossy_ack, _) = b.accept(&lossy_hello, [4; 32]).unwrap();
    assert_eq!(
        pending.finish(&lossy_ack).unwrap_err(),
        BindingError::InvalidProof
    );
}

#[tokio::test]
async fn proof_keys_cannot_be_consumed_by_the_other_delivery_mode() {
    let (a, b) = parents();
    let (reliable, _) = keys(&a, &b);
    let (stream, _peer) = tokio::io::duplex(64);
    assert!(matches!(
        reliable.into_ordered(Box::new(stream)),
        Err(BindingError::InvalidProof)
    ));
    let (hello, pending) = a.begin([4; 32]).unwrap();
    let (ack, _) = b.accept(&hello, [4; 32]).unwrap();
    let (stream, _peer) = tokio::io::duplex(64);
    assert!(matches!(
        pending
            .finish(&ack)
            .unwrap()
            .into_reliable(Box::new(stream)),
        Err(BindingError::InvalidProof)
    ));
}

#[tokio::test]
async fn retired_reliable_parent_revokes_queued_data_and_blocked_io_immediately() {
    let (a, b) = parents();
    let (a_keys, b_keys) = keys(&a, &b);
    let (a_stream, b_stream) = tokio::io::duplex(64);
    let a_channel = a_keys.into_reliable(Box::new(a_stream)).unwrap();
    let b_channel = b_keys.into_reliable(Box::new(b_stream)).unwrap();
    let tx = a_channel.handle();
    let rx = b_channel.handle();
    tx.send(b"queued before retirement").await.unwrap();
    timeout(Duration::from_secs(1), async {
        while rx.progress().received_records != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    b.retire();
    // No scheduling opportunity for the asynchronous watcher is needed.
    assert_eq!(
        rx.recv().await.unwrap_err().kind(),
        std::io::ErrorKind::ConnectionAborted
    );
    assert_eq!(
        rx.send(b"late").await.unwrap_err().kind(),
        std::io::ErrorKind::ConnectionAborted
    );
    let blocked = tokio::spawn({
        let tx = tx.clone();
        async move { tx.recv().await }
    });
    drop(a);
    assert_eq!(
        timeout(Duration::from_secs(1), blocked)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::ConnectionAborted
    );
    assert!(matches!(
        a_channel.keys.parent.begin_reliable([4; 32]),
        Err(BindingError::Retired)
    ));
}

#[tokio::test]
async fn reliable_child_carries_exact_encrypted_app_frames_on_actual_obfs4() {
    use veil_crypto::session_cipher::SessionCipher;
    use veil_proto::{
        AppMsg, FrameFamily,
        app::AppDataPayload,
        header::{FrameHeader, HEADER_SIZE},
    };
    use veil_transport::{Transport, TransportUri, obfs4_tcp::Obfs4TcpTransport};
    let mut context = veil_transport::TransportContext::for_debug().unwrap();
    context.obfs4_psk = Some(Arc::new([0x42; 32]));
    let context = Arc::new(context);
    let transport = Obfs4TcpTransport;
    let listener = transport
        .bind(
            &TransportUri::Obfs4Tcp {
                host: "127.0.0.1".into(),
                port: 0,
            },
            context.clone(),
        )
        .await
        .unwrap();
    let port = listener
        .local_addr()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let dial = TransportUri::Obfs4Tcp {
        host: "127.0.0.1".into(),
        port,
    };
    let (main_a, main_b) = tokio::join!(transport.connect(&dial, context), listener.accept());
    let main_a = main_a.unwrap();
    let main_b = main_b.unwrap();
    let outgoing = main_a.parallel_stream().unwrap();
    let incoming = main_b.parallel_stream().unwrap();
    let (a_parent, b_parent) = parents();
    let (a, b) = tokio::join!(outgoing.connect(), listener.accept());
    let a = a.unwrap();
    let b = b.unwrap();
    let a_binding = a.stream_channel_binding().unwrap();
    let b_binding = b.stream_channel_binding().unwrap();
    assert_eq!(a_binding, b_binding);
    let (hello, pending) = a_parent.begin_reliable(a_binding).unwrap();
    let mut a_stream = a.into_stream().unwrap();
    let mut b_stream = b.into_stream().unwrap();
    a_stream.write_all(&hello).await.unwrap();
    a_stream.flush().await.unwrap();
    let mut received = [0; HELLO_BYTES];
    b_stream.read_exact(&mut received).await.unwrap();
    let (ack, b_keys) = b_parent.accept_reliable(&received, b_binding).unwrap();
    let mut b_stream = incoming.track_incoming(b_stream).unwrap();
    b_stream.write_all(&ack).await.unwrap();
    b_stream.flush().await.unwrap();
    let mut received_ack = [0; 32];
    a_stream.read_exact(&mut received_ack).await.unwrap();
    let a_keys = pending.finish(&received_ack).unwrap();
    assert_eq!(a_keys.tx_key(), b_keys.rx_key());
    assert_eq!(a_keys.session_id, b_keys.session_id);
    let mut tx_cipher = SessionCipher::new(a_keys.tx_key(), true);
    let mut rx_cipher = SessionCipher::new(b_keys.rx_key(), true);
    let a = a_keys.into_reliable(a_stream).unwrap();
    let b = b_keys.into_reliable(b_stream).unwrap();
    let tx = a.handle();
    let rx = b.handle();
    let sending = tokio::spawn(async move {
        for n in 0..128u64 {
            let body = AppDataPayload {
                app_id: [0x55; 32],
                endpoint_id: 17,
                seq: 0,
                data: vec![n as u8; 2048],
            }
            .encode();
            let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppData as u16);
            header.stream_id = 19;
            header.body_len = body.len() as u32;
            let plain = veil_proto::codec::encode_frame(&header, &body);
            let wire = crate::runner::apply_tx_cipher(&plain, &mut tx_cipher).unwrap();
            tx.send(&wire).await.unwrap();
        }
    });
    // Old loss-tolerant framing would evict/expire these buffered records.
    tokio::time::sleep(Duration::from_millis(500)).await;
    for n in 0..128u64 {
        let wire = timeout(Duration::from_secs(3), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let header = veil_proto::codec::decode_header(&wire).unwrap();
        assert_eq!(header.stream_id, 19);
        let body = rx_cipher
            .open(&wire[HEADER_SIZE..], &veil_proto::codec::frame_aad(&header))
            .unwrap();
        let data = AppDataPayload::decode(&body).unwrap();
        assert_eq!(data.seq, 0);
        assert_eq!(data.data, vec![n as u8; 2048]);
    }
    sending.await.unwrap();
    drop(a);
    drop(b);
    timeout(Duration::from_secs(1), async {
        while outgoing.available_connection_slots()
            != veil_transport::stream_parallel::StreamParallelHandle::CONNECTIONS_PER_DIRECTION
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn reliable_quic_owner_closes_actual_child_and_reclaims_quota_with_raw_clones() {
    use veil_transport::{PunchedQuicRole, TransportContext, promote_punched_quic};
    timeout(Duration::from_secs(10), async {
        let a_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a_socket.local_addr().unwrap();
        let b_addr = b_socket.local_addr().unwrap();
        let context = Arc::new(TransportContext::for_debug().unwrap());
        let server = tokio::spawn(promote_punched_quic(
            b_socket,
            a_addr,
            context.clone(),
            PunchedQuicRole::Responder,
        ));
        let a = promote_punched_quic(a_socket, b_addr, context, PunchedQuicRole::Initiator)
            .await
            .unwrap();
        let a_parent_datagrams = a.quic_datagrams().unwrap();
        let outgoing = a.parallel_quic().unwrap();
        let mut a_stream = a.into_stream().unwrap();
        a_stream.write_all(b"parent").await.unwrap();
        let b = server.await.unwrap().unwrap();
        let b_parent_datagrams = b.quic_datagrams().unwrap();
        let incoming = b.parallel_quic().unwrap();
        let mut b_stream = b.into_stream().unwrap();
        let mut main = [0; 6];
        b_stream.read_exact(&mut main).await.unwrap();
        let (a_parent, b_parent) = parents();
        let (wrong_transport_keys, _) = keys(&a_parent, &b_parent);
        let (wrong_stream, _peer) = tokio::io::duplex(64);
        assert!(matches!(
            wrong_transport_keys
                .into_reliable_quic(Box::new(wrong_stream), a_parent_datagrams.clone()),
            Err(BindingError::InvalidProof)
        ));
        let server = tokio::spawn({
            let parent = b_parent.handle();
            async move {
                let child = incoming.accept().await.unwrap();
                let datagrams = child.quic_datagrams().unwrap();
                let exporter = datagrams.channel_binding().unwrap();
                let mut stream = child.into_stream().unwrap();
                let mut hello = [0; HELLO_BYTES];
                stream.read_exact(&mut hello).await.unwrap();
                let (ack, keys) = parent.accept_reliable(&hello, exporter).unwrap();
                stream.write_all(&ack).await.unwrap();
                (keys, stream, datagrams)
            }
        });
        let child = outgoing.connect().await.unwrap();
        let a_datagrams = child.quic_datagrams().unwrap();
        let (hello, pending) = a_parent
            .begin_reliable(a_datagrams.channel_binding().unwrap())
            .unwrap();
        let mut stream = child.into_stream().unwrap();
        stream.write_all(&hello).await.unwrap();
        let mut ack = [0; 32];
        stream.read_exact(&mut ack).await.unwrap();
        let a_keys = pending.finish(&ack).unwrap();
        let (b_keys, b_stream, b_datagrams) = server.await.unwrap();
        let a = a_keys
            .into_reliable_quic(stream, a_datagrams.clone())
            .unwrap();
        let b = b_keys
            .into_reliable_quic(b_stream, b_datagrams.clone())
            .unwrap();
        a.handle().send(b"reliable").await.unwrap();
        assert_eq!(b.handle().recv().await.unwrap(), b"reliable");
        drop(a);
        // Raw transport clones and the quota watcher must not prolong a dead child.
        timeout(Duration::from_millis(500), a_datagrams.closed())
            .await
            .expect("child still alive after owner drop");
        timeout(Duration::from_millis(500), b_datagrams.closed())
            .await
            .unwrap();
        timeout(Duration::from_secs(1), async {
            while outgoing.available_connection_slots()
                != veil_transport::QuicParallelHandle::CONNECTIONS_PER_DIRECTION
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        b_parent_datagrams.send(b"parent survives").unwrap();
        assert_eq!(a_parent_datagrams.recv().await.unwrap(), b"parent survives");
        drop(b);
        a_parent_datagrams.close();
        b_parent_datagrams.close();
    })
    .await
    .unwrap();
}
