use super::*;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{Duration, timeout},
};
use veil_transport::{
    BoxIoStream, PunchedQuicRole, QuicParallelHandle, TransportContext, promote_punched_quic,
};

fn parents() -> (ParallelParent, ParallelParent) {
    (
        ParallelParent::new([1; 32], [2; 32], [3; 32]),
        ParallelParent::new([1; 32], [3; 32], [2; 32]),
    )
}

#[test]
fn proof_rejects_replay_reflection_tampering_and_retired_parent() {
    let (a, b) = parents();
    let (hello, pending) = a.begin([4; 32]).unwrap();
    assert_eq!(
        b.accept(&hello, [5; 32]).unwrap_err(),
        BindingError::InvalidProof
    );
    assert_eq!(
        a.accept(&hello, [4; 32]).unwrap_err(),
        BindingError::InvalidProof
    );
    let wrong_parent = ParallelParent::new([9; 32], [3; 32], [2; 32]);
    assert_eq!(
        wrong_parent.accept(&hello, [4; 32]).unwrap_err(),
        BindingError::InvalidProof
    );
    let wrong_key = ParallelParent::new([1; 32], [3; 32], [9; 32]);
    assert_eq!(
        wrong_key.accept(&hello, [4; 32]).unwrap_err(),
        BindingError::InvalidProof
    );
    let mut damaged = hello;
    damaged[40] ^= 1;
    assert_eq!(
        b.accept(&damaged, [4; 32]).unwrap_err(),
        BindingError::InvalidProof
    );
    let (ack, _) = b.accept(&hello, [4; 32]).unwrap();
    // Neither a reflected HELLO proof nor an acknowledgement from another
    // connection can finish the caller's authentication.
    let (_, reflected_pending) = a.begin([4; 32]).unwrap();
    assert_eq!(
        reflected_pending
            .finish(&hello[72..].try_into().unwrap())
            .unwrap_err(),
        BindingError::InvalidProof
    );
    let (other_hello, other_pending) = a.begin([5; 32]).unwrap();
    let (other_ack, _) = b.accept(&other_hello, [5; 32]).unwrap();
    assert_eq!(
        pending.finish(&other_ack).unwrap_err(),
        BindingError::InvalidProof
    );
    a.handle().retire();
    assert_eq!(
        other_pending.finish(&ack).unwrap_err(),
        BindingError::Retired
    );
    assert!(matches!(a.begin([4; 32]), Err(BindingError::Retired)));
    b.retire();
    assert_eq!(
        b.accept(&hello, [4; 32]).unwrap_err(),
        BindingError::Retired
    );
}

#[test]
fn canonical_owner_drop_retires_clones_and_pending_authentication() {
    let (a, b) = parents();
    let a_handle = a.handle();
    let b_handle = b.handle();
    let (hello, pending) = a_handle.begin([4; 32]).unwrap();
    let (ack, _) = b_handle.accept(&hello, [4; 32]).unwrap();
    drop(a);
    assert_eq!(pending.finish(&ack).unwrap_err(), BindingError::Retired);
    assert!(matches!(
        a_handle.begin([4; 32]),
        Err(BindingError::Retired)
    ));
    drop(b);
    assert_eq!(
        b_handle.accept(&hello, [4; 32]).unwrap_err(),
        BindingError::Retired
    );
}

#[tokio::test]
async fn ordered_child_proof_binds_the_actual_obfs4_connection() {
    use veil_transport::{Transport, TransportUri, obfs4_tcp::Obfs4TcpTransport};
    let mut context = TransportContext::for_debug().unwrap();
    context.obfs4_psk = Some(std::sync::Arc::new([0x42; 32]));
    let context = std::sync::Arc::new(context);
    let transport = Obfs4TcpTransport;
    let bind = TransportUri::Obfs4Tcp {
        host: "127.0.0.1".into(),
        port: 0,
    };
    let listener = transport.bind(&bind, context.clone()).await.unwrap();
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
    let mut saved_hello = None;
    for _ in 0..2 {
        let (a, b) = tokio::join!(outgoing.connect(), listener.accept());
        let a = a.unwrap();
        let b = b.unwrap();
        let a_binding = a.stream_channel_binding().unwrap();
        let b_binding = b.stream_channel_binding().unwrap();
        assert_eq!(a_binding, b_binding);
        if let Some(hello) = saved_hello {
            assert_eq!(
                b_parent.accept(&hello, b_binding).unwrap_err(),
                BindingError::InvalidProof
            );
        }
        let (hello, pending) = a_parent.begin(a_binding).unwrap();
        saved_hello = Some(hello);
        let mut a_stream = a.into_stream().unwrap();
        let mut b_stream = b.into_stream().unwrap();
        a_stream.write_all(&hello).await.unwrap();
        a_stream.flush().await.unwrap();
        let mut received = [0; HELLO_BYTES];
        b_stream.read_exact(&mut received).await.unwrap();
        let (ack, b_keys) = b_parent.accept(&received, b_binding).unwrap();
        // The canonical peer's bounded incoming lease is acquired only after
        // the proof verifies. No new peer/identity registration is involved.
        let mut b_stream = incoming.track_incoming(b_stream).unwrap();
        b_stream.write_all(&ack).await.unwrap();
        b_stream.flush().await.unwrap();
        let mut received_ack = [0; 32];
        a_stream.read_exact(&mut received_ack).await.unwrap();
        let a_keys = pending.finish(&received_ack).unwrap();
        assert_eq!(a_keys.session_id, b_keys.session_id);
        assert_eq!(a_keys.tx_key(), b_keys.rx_key());
        assert_eq!(a_keys.rx_key(), b_keys.tx_key());
        // Exercise the actual existing opaque-flow codec on the authenticated
        // ordered child in BOTH directions, including multi-record assembly.
        let mut a_tx = crate::datagram_flows::SessionDatagramTx::new(
            a_keys.tx_key(),
            &a_keys.session_id,
            true,
        );
        let mut b_tx = crate::datagram_flows::SessionDatagramTx::new(
            b_keys.tx_key(),
            &b_keys.session_id,
            true,
        );
        let mut a_rx = crate::datagram_flows::SessionDatagramRx::new(
            a_keys.rx_key(),
            &a_keys.session_id,
            true,
        );
        let mut b_rx = crate::datagram_flows::SessionDatagramRx::new(
            b_keys.rx_key(),
            &b_keys.session_id,
            true,
        );
        let a_channel = a_keys.into_ordered(a_stream).unwrap();
        let b_channel = b_keys.into_ordered(b_stream).unwrap();
        let a_handle = a_channel.handle();
        let b_handle = b_channel.handle();
        for frame in [vec![0x42; 64], vec![0x73; 8200]] {
            let ceiling = a_handle.max_size().unwrap();
            let packets = a_tx.encode_frame(0, &frame, ceiling).unwrap();
            let count = packets.len();
            for packet in packets {
                a_handle.send(&packet).unwrap();
            }
            let mut received = None;
            for _ in 0..count {
                let packet = timeout(Duration::from_secs(2), b_handle.recv())
                    .await
                    .unwrap()
                    .unwrap();
                received = b_rx
                    .decode_datagram(&packet, std::time::Instant::now())
                    .unwrap()
                    .or(received);
            }
            assert_eq!(received.as_deref(), Some(frame.as_slice()));
            for packet in b_tx
                .encode_frame(2, b"authenticated return", ceiling)
                .unwrap()
            {
                b_handle.send(&packet).unwrap();
            }
            let packet = timeout(Duration::from_secs(2), a_handle.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                a_rx.decode_datagram(&packet, std::time::Instant::now())
                    .unwrap()
                    .as_deref(),
                Some(b"authenticated return".as_slice())
            );
        }
    }
}

#[tokio::test]
async fn ordered_owner_retirement_revokes_admission_before_watcher_runs_and_wakes_idle_io() {
    use veil_transport::ordered_records::RecordSendError;
    let (a_parent, b_parent) = parents();
    let (hello, pending) = a_parent.begin([4; 32]).unwrap();
    let (ack, b_keys) = b_parent.accept(&hello, [4; 32]).unwrap();
    let a_keys = pending.finish(&ack).unwrap();
    let (a, b) = tokio::io::duplex(4096);
    let a_channel = a_keys.into_ordered(Box::new(a)).unwrap();
    let b_channel = b_keys.into_ordered(Box::new(b)).unwrap();
    let a_handle = a_channel.handle();
    let retained = a_handle.clone();
    let b_handle = b_channel.handle();
    b_handle.send(b"old queued frame").unwrap();
    // This task does not yield between retirement and these checks: the
    // spawned cleanup watcher cannot be responsible for synchronous rejection.
    a_parent.retire();
    assert_eq!(retained.send(b"new frame"), Err(RecordSendError::Closed));
    assert_eq!(
        retained.send_before(
            b"new frame",
            std::time::Instant::now() + Duration::from_secs(1)
        ),
        Err(RecordSendError::Closed)
    );
    assert_eq!(retained.max_size(), None);
    assert_eq!(retained.send_buffer_space(), 0);
    assert_eq!(
        retained.recv().await.unwrap_err().kind(),
        std::io::ErrorKind::ConnectionAborted
    );
    timeout(Duration::from_secs(1), retained.closed())
        .await
        .unwrap();
    // No incoming data is needed to wake cleanup and close the remote half.
    timeout(Duration::from_secs(1), b_handle.closed())
        .await
        .unwrap();
    assert!(b_handle.recv().await.is_err());
}

#[tokio::test]
async fn verified_ordered_keys_cannot_start_a_plane_after_canonical_owner_drop() {
    let (a_parent, b_parent) = parents();
    let (hello, pending) = a_parent.begin([4; 32]).unwrap();
    let (ack, _) = b_parent.accept(&hello, [4; 32]).unwrap();
    let keys = pending.finish(&ack).unwrap();
    let retained = a_parent.handle();
    drop(a_parent);
    timeout(Duration::from_secs(1), retained.retired())
        .await
        .unwrap();
    let (stream, _peer) = tokio::io::duplex(1024);
    assert!(matches!(
        keys.into_ordered(Box::new(stream)),
        Err(BindingError::Retired)
    ));
}

struct TestChild {
    keys: ParallelKeys,
    a_stream: BoxIoStream,
    b_stream: BoxIoStream,
    a_datagrams: veil_transport::QuicDatagramHandle,
    b_datagrams: veil_transport::QuicDatagramHandle,
    close: Box<dyn Fn() + Send>,
}

async fn child_roundtrip(
    a_handle: &QuicParallelHandle,
    b_handle: &QuicParallelHandle,
    a_parent: &ParallelParent,
    b_parent: &ParallelParent,
) -> TestChild {
    let b_handle = b_handle.clone();
    let b_parent = b_parent.handle();
    let server = tokio::spawn(async move {
        let connection = b_handle.accept().await.unwrap();
        let datagrams = connection.quic_datagrams().unwrap();
        let exporter = datagrams.channel_binding().unwrap();
        let mut stream = connection.into_stream().unwrap();
        let mut hello = [0; HELLO_BYTES];
        stream.read_exact(&mut hello).await.unwrap();
        let (ack, keys) = b_parent.accept(&hello, exporter).unwrap();
        stream.write_all(&ack).await.unwrap();
        (keys, stream, datagrams)
    });
    let connection = a_handle.connect().await.unwrap();
    let raw = connection.quic_connection().unwrap();
    let close = Box::new(move || raw.close(0u32.into(), b"child retired"));
    let datagrams = connection.quic_datagrams().unwrap();
    let (hello, pending) = a_parent
        .begin(datagrams.channel_binding().unwrap())
        .unwrap();
    let mut stream = connection.into_stream().unwrap();
    stream.write_all(&hello).await.unwrap();
    let mut ack = [0; 32];
    stream.read_exact(&mut ack).await.unwrap();
    let a_keys = pending.finish(&ack).unwrap();
    let (b_keys, mut b_stream, b_datagrams) = server.await.unwrap();
    assert!(a_keys.tx_key() == b_keys.rx_key());
    assert!(a_keys.rx_key() == b_keys.tx_key());
    assert_eq!(a_keys.session_id, b_keys.session_id);
    // Both child directions may start their nonce counter at zero. The same
    // plaintext is intentionally used to expose accidentally shared keys.
    let nonce = Nonce::from_slice(&[0; 12]);
    let a_cipher = ChaCha20Poly1305::new(a_keys.tx_key().into());
    let b_cipher = ChaCha20Poly1305::new(b_keys.tx_key().into());
    let a_bytes = a_cipher.encrypt(nonce, b"test".as_slice()).unwrap();
    let b_bytes = b_cipher.encrypt(nonce, b"test".as_slice()).unwrap();
    assert_ne!(a_bytes, b_bytes);
    stream.write_all(&a_bytes).await.unwrap();
    let mut received = [0; 20];
    b_stream.read_exact(&mut received).await.unwrap();
    let rx = ChaCha20Poly1305::new(b_keys.rx_key().into());
    assert_eq!(rx.decrypt(nonce, received.as_slice()).unwrap(), b"test");
    b_stream.write_all(&b_bytes).await.unwrap();
    stream.read_exact(&mut received).await.unwrap();
    let rx = ChaCha20Poly1305::new(a_keys.rx_key().into());
    assert_eq!(rx.decrypt(nonce, received.as_slice()).unwrap(), b"test");
    b_datagrams.send(b"independent-datagram").unwrap();
    assert_eq!(datagrams.recv().await.unwrap(), b"independent-datagram");
    TestChild {
        keys: a_keys,
        a_stream: stream,
        b_stream,
        a_datagrams: datagrams,
        b_datagrams,
        close,
    }
}

#[tokio::test]
async fn actual_parallel_quic_has_fresh_keys_independent_queues_and_parent_lifetime() {
    timeout(Duration::from_secs(15), async {
        let a_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a_socket.local_addr().unwrap();
        let b_addr = b_socket.local_addr().unwrap();
        let ctx = Arc::new(TransportContext::for_debug().unwrap());
        let b_ctx = Arc::clone(&ctx);
        let b_task = tokio::spawn(promote_punched_quic(
            b_socket,
            a_addr,
            b_ctx,
            PunchedQuicRole::Responder,
        ));
        let a = promote_punched_quic(
            a_socket,
            b_addr,
            Arc::clone(&ctx),
            PunchedQuicRole::Initiator,
        )
        .await
        .unwrap();
        let a_quic = a.quic_connection().unwrap();
        let a_datagrams = a.quic_datagrams().unwrap();
        let a_handle = a.parallel_quic().unwrap();
        let mut a_stream = a.into_stream().unwrap();
        a_stream.write_all(b"main").await.unwrap();
        let b = b_task.await.unwrap().unwrap();
        let b_handle = b.parallel_quic().unwrap();
        let b_datagrams = b.quic_datagrams().unwrap();
        let mut b_stream = b.into_stream().unwrap();
        let mut main = [0; 4];
        b_stream.read_exact(&mut main).await.unwrap();
        assert_eq!(&main, b"main");
        let (a_parent, b_parent) = parents();
        let mut first = child_roundtrip(&a_handle, &b_handle, &a_parent, &b_parent).await;
        let mut second = child_roundtrip(&a_handle, &b_handle, &a_parent, &b_parent).await;
        assert!(first.keys.tx_key() != second.keys.tx_key());
        assert!(first.keys.rx_key() != second.keys.rx_key());
        assert!(first.keys.tx_key() != &[2; 32]);
        assert!(first.keys.rx_key() != &[3; 32]);
        assert_ne!(first.keys.session_id, second.keys.session_id);
        assert_ne!(first.keys.session_id, [1; 32]);
        assert!(
            first.a_datagrams.channel_binding().unwrap() != a_datagrams.channel_binding().unwrap()
        );
        assert!(
            first.a_datagrams.channel_binding().unwrap()
                != second.a_datagrams.channel_binding().unwrap()
        );
        // Block a large write by admitting at most one unacknowledged byte on
        // this sibling. The other connection's reliable stream must still work.
        first.a_datagrams.set_reliable_send_window(1);
        assert!(
            timeout(
                Duration::from_millis(100),
                first.a_stream.write_all(&vec![7; 4 * 1024 * 1024])
            )
            .await
            .is_err()
        );
        timeout(Duration::from_secs(1), second.a_stream.write_all(b"fast"))
            .await
            .unwrap()
            .unwrap();
        timeout(
            Duration::from_secs(1),
            second.b_stream.read_exact(&mut main),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&main, b"fast");
        a_datagrams.send(b"parent-still-live").unwrap();
        assert_eq!(b_datagrams.recv().await.unwrap(), b"parent-still-live");
        a_stream.write_all(b"live").await.unwrap();
        b_stream.read_exact(&mut main).await.unwrap();
        assert_eq!(&main, b"live");
        // Fill one direction first. Its full incoming pool must preserve the
        // peer's independent outgoing capacity, with the aggregate still bounded.
        let mut others = Vec::new();
        for _ in 2..veil_transport::QuicParallelHandle::CONNECTIONS_PER_DIRECTION {
            others.push(child_roundtrip(&a_handle, &b_handle, &a_parent, &b_parent).await);
        }
        for _ in 0..veil_transport::QuicParallelHandle::CONNECTIONS_PER_DIRECTION {
            others.push(child_roundtrip(&b_handle, &a_handle, &b_parent, &a_parent).await);
        }
        let error = a_handle.clone().connect().await.err().unwrap();
        assert!(error.to_string().contains("budget exhausted"));
        let error = b_handle.clone().accept().await.err().unwrap();
        assert!(error.to_string().contains("budget exhausted"));
        // Explicitly retiring one child must preserve every other channel and
        // release its slot for another independently keyed connection.
        (first.close)();
        assert!(first.b_datagrams.recv().await.is_err());
        tokio::task::yield_now().await;
        let replacement = child_roundtrip(&a_handle, &b_handle, &a_parent, &b_parent).await;
        assert_ne!(replacement.keys.session_id, first.keys.session_id);
        second.a_stream.write_all(b"kept").await.unwrap();
        second.b_stream.read_exact(&mut main).await.unwrap();
        assert_eq!(&main, b"kept");
        a_quic.close(0u32.into(), b"test finished");
        assert!(first.a_datagrams.recv().await.is_err());
        assert!(second.a_datagrams.recv().await.is_err());
        assert!(a_handle.connect().await.is_err());
        assert!(b_handle.accept().await.is_err());
        for child in &others {
            assert!(child.b_datagrams.recv().await.is_err());
        }
        assert!(replacement.b_datagrams.recv().await.is_err());
        drop((first, second, others, replacement, a_stream, b_stream));
    })
    .await
    .expect("parallel QUIC stand timed out");
}
