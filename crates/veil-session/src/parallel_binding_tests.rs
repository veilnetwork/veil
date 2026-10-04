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
    ctx: &Arc<TransportContext>,
    a_parent: &ParallelParent,
    b_parent: &ParallelParent,
) -> TestChild {
    let b_handle = b_handle.clone();
    let b_ctx = Arc::clone(ctx);
    let b_parent = b_parent.handle();
    let server = tokio::spawn(async move {
        let connection = b_handle.accept(b_ctx).await.unwrap();
        let datagrams = connection.quic_datagrams().unwrap();
        let exporter = datagrams.channel_binding().unwrap();
        let mut stream = connection.into_stream().unwrap();
        let mut hello = [0; HELLO_BYTES];
        stream.read_exact(&mut hello).await.unwrap();
        let (ack, keys) = b_parent.accept(&hello, exporter).unwrap();
        stream.write_all(&ack).await.unwrap();
        (keys, stream, datagrams)
    });
    let connection = a_handle.connect(Arc::clone(ctx)).await.unwrap();
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
        let mut first = child_roundtrip(&a_handle, &b_handle, &ctx, &a_parent, &b_parent).await;
        let mut second = child_roundtrip(&a_handle, &b_handle, &ctx, &a_parent, &b_parent).await;
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
        // Budget follows live QUIC connections, shared across handle clones.
        let mut others = Vec::new();
        others.push(child_roundtrip(&b_handle, &a_handle, &ctx, &b_parent, &a_parent).await);
        for _ in 0..5 {
            others.push(child_roundtrip(&a_handle, &b_handle, &ctx, &a_parent, &b_parent).await);
        }
        let error = a_handle
            .clone()
            .connect(Arc::clone(&ctx))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("budget exhausted"));
        let error = b_handle
            .clone()
            .accept(Arc::clone(&ctx))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("budget exhausted"));
        // Explicitly retiring one child must preserve every other channel and
        // release its slot for another independently keyed connection.
        (first.close)();
        assert!(first.b_datagrams.recv().await.is_err());
        tokio::task::yield_now().await;
        let replacement = child_roundtrip(&a_handle, &b_handle, &ctx, &a_parent, &b_parent).await;
        assert_ne!(replacement.keys.session_id, first.keys.session_id);
        second.a_stream.write_all(b"kept").await.unwrap();
        second.b_stream.read_exact(&mut main).await.unwrap();
        assert_eq!(&main, b"kept");
        a_quic.close(0u32.into(), b"test finished");
        assert!(first.a_datagrams.recv().await.is_err());
        assert!(second.a_datagrams.recv().await.is_err());
        assert!(a_handle.connect(Arc::clone(&ctx)).await.is_err());
        assert!(b_handle.accept(Arc::clone(&ctx)).await.is_err());
        for child in &others {
            assert!(child.b_datagrams.recv().await.is_err());
        }
        assert!(replacement.b_datagrams.recv().await.is_err());
        drop((first, second, others, replacement, a_stream, b_stream));
    })
    .await
    .expect("parallel QUIC stand timed out");
}
