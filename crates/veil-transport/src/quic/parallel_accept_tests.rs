use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_generic_sibling_survives_idle_timeout_and_retires_with_parent() {
    let left = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let right = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (a_addr, b_addr) = (left.local_addr().unwrap(), right.local_addr().unwrap());
    let ctx = Arc::new(TransportContext::for_debug().unwrap());
    let remote = tokio::spawn(promote_punched_quic(
        right,
        a_addr,
        Arc::clone(&ctx),
        PunchedQuicRole::Responder,
    ));
    let a = promote_punched_quic(left, b_addr, ctx, PunchedQuicRole::Initiator)
        .await
        .unwrap();
    let parent = a.quic_connection().unwrap();
    let client = a.parallel_quic().unwrap();
    let mut a_stream = a.into_stream().unwrap();
    a_stream.write_all(b"main").await.unwrap();
    let b = remote.await.unwrap().unwrap();
    let server = b.parallel_quic().unwrap();
    let mut b_stream = b.into_stream().unwrap();
    b_stream.read_exact(&mut [0; 4]).await.unwrap();
    let accept = tokio::spawn(async move { server.accept().await });
    let child = client.connect().await.unwrap();
    let child_connection = child.quic_connection().unwrap();
    let id = child_connection.local_trace_id();
    let mut sender = child.into_stream().unwrap();
    sender.write_all(b"open").await.unwrap();
    let child = accept.await.unwrap().unwrap();
    let mut receiver = child.into_stream().unwrap();
    receiver.read_exact(&mut [0; 4]).await.unwrap();
    let before = child_connection.stats().frame_tx.ping;
    // Real clocks are intentional: advancing Tokio's virtual clock does not
    // advance Quinn's std::time::Instant. Keep only the canonical path busy;
    // neither application writes nor reads on this child refresh its timer.
    for _ in 0..7 {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        a_stream.write_all(b"main").await.unwrap();
        timeout(
            std::time::Duration::from_secs(1),
            b_stream.read_exact(&mut [0; 4]),
        )
        .await
        .unwrap()
        .unwrap();
    }
    let survived = child_connection.close_reason().is_none();
    let pings = child_connection
        .stats()
        .frame_tx
        .ping
        .saturating_sub(before);
    let result = async {
        sender.write_all(b"late").await?;
        let mut bytes = [0; 4];
        receiver.read_exact(&mut bytes).await?;
        receiver.write_all(&bytes).await?;
        sender.read_exact(&mut bytes).await?;
        Ok::<_, std::io::Error>(bytes)
    };
    let delivered = timeout(std::time::Duration::from_secs(1), result).await;
    parent.close(0u32.into(), b"retained sibling idle test complete");
    timeout(std::time::Duration::from_secs(1), child_connection.closed())
        .await
        .unwrap();
    assert!(
        survived,
        "retained sibling expired and would require a fresh TLS dial"
    );
    assert!(
        pings > 0,
        "idle child was not kept alive by transport PINGs"
    );
    assert_eq!(delivered.unwrap().unwrap(), *b"late");
    assert_eq!(child_connection.local_trace_id(), id);
}

#[tokio::test]
async fn a_pending_first_stream_does_not_block_another_generic_sibling() {
    let left = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let right = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (a_addr, b_addr) = (left.local_addr().unwrap(), right.local_addr().unwrap());
    let ctx = Arc::new(TransportContext::for_debug().unwrap());
    let remote = tokio::spawn(promote_punched_quic(
        right,
        a_addr,
        Arc::clone(&ctx),
        PunchedQuicRole::Responder,
    ));
    let a = promote_punched_quic(left, b_addr, ctx, PunchedQuicRole::Initiator)
        .await
        .unwrap();
    let close = a.quic_connection().unwrap();
    let client = a.parallel_quic().unwrap();
    let mut a_stream = a.into_stream().unwrap();
    a_stream.write_all(b"main").await.unwrap();
    let b = remote.await.unwrap().unwrap();
    let server = b.parallel_quic().unwrap();
    let mut b_stream = b.into_stream().unwrap();
    let mut prefix = [0; 4];
    b_stream.read_exact(&mut prefix).await.unwrap();
    let server_first = server.clone();
    let mut first_accept = tokio::spawn(async move { server_first.accept().await });
    let first = timeout(std::time::Duration::from_secs(1), client.connect())
        .await
        .unwrap()
        .unwrap();
    let mut first_stream = first.into_stream().unwrap();
    assert!(
        !first_accept.is_finished(),
        "fixture must withhold the first stream's opening bytes"
    );
    let server_second = server.clone();
    let mut second_accept = tokio::spawn(async move { server_second.accept().await });
    let mut second_sender = tokio::spawn(async move {
        let second = client.connect().await?;
        let mut stream = second.into_stream()?;
        stream.write_all(b"two").await.map_err(quic_error)?;
        Ok::<_, TransportError>(stream)
    });
    let received = match timeout(std::time::Duration::from_millis(400), &mut second_accept).await {
        Ok(Ok(Ok(connection))) => {
            let mut stream = connection.into_stream().unwrap();
            let mut bytes = [0; 3];
            timeout(
                std::time::Duration::from_millis(400),
                stream.read_exact(&mut bytes),
            )
            .await
            .unwrap()
            .unwrap();
            bytes == *b"two"
        }
        _ => false,
    };
    let first_still_pending = !first_accept.is_finished();
    // Both generic streams must remain independent in the successful case.
    let first_received = if received {
        first_stream.write_all(b"one").await.unwrap();
        let connection = timeout(std::time::Duration::from_millis(400), &mut first_accept)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let mut stream = connection.into_stream().unwrap();
        let mut bytes = [0; 3];
        timeout(
            std::time::Duration::from_millis(400),
            stream.read_exact(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        bytes == *b"one"
    } else {
        false
    };
    close.close(0u32.into(), b"generic accept independence test complete");
    // Reap even the negative case before evaluating assertions.
    if !first_accept.is_finished() {
        first_accept.abort();
        let _ = first_accept.await;
    }
    if !second_accept.is_finished() {
        second_accept.abort();
        let _ = second_accept.await;
    }
    if !second_sender.is_finished() {
        second_sender.abort();
        let _ = second_sender.await;
    } else {
        let _ = (&mut second_sender).await;
    }
    assert!(
        received,
        "one pending handshake/stream serialized every generic sibling"
    );
    assert!(
        first_still_pending && first_received,
        "second connection interfered with the independent first stream"
    );
}

#[tokio::test]
async fn idle_accept_has_no_handshake_deadline_and_parent_close_cancels_it() {
    let left = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let right = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (a_addr, b_addr) = (left.local_addr().unwrap(), right.local_addr().unwrap());
    let mut ctx = TransportContext::for_debug().unwrap();
    ctx.quic.handshake_timeout = std::time::Duration::from_millis(200);
    let ctx = Arc::new(ctx);
    let remote = tokio::spawn(promote_punched_quic(
        right,
        a_addr,
        Arc::clone(&ctx),
        PunchedQuicRole::Responder,
    ));
    let a = promote_punched_quic(left, b_addr, ctx, PunchedQuicRole::Initiator)
        .await
        .unwrap();
    let close = a.quic_connection().unwrap();
    let client = a.parallel_quic().unwrap();
    let mut a_stream = a.into_stream().unwrap();
    a_stream.write_all(b"main").await.unwrap();
    let b = remote.await.unwrap().unwrap();
    let server = b.parallel_quic().unwrap();
    let mut b_stream = b.into_stream().unwrap();
    b_stream.read_exact(&mut [0; 4]).await.unwrap();
    let idle_server = server.clone();
    let mut accept = tokio::spawn(async move { idle_server.accept().await });
    tokio::time::sleep(std::time::Duration::from_millis(450)).await;
    let idle_survived = !accept.is_finished();
    let idle_permits = server.0.slots.available_permits();
    if !idle_survived {
        close.close(0u32.into(), b"idle accept regression");
        let _ = accept.await;
        assert!(
            idle_survived,
            "idle wait consumed the incoming handshake deadline"
        );
        return;
    }
    let connection = client.connect().await.unwrap();
    let mut stream = connection.into_stream().unwrap();
    stream.write_all(b"late").await.unwrap();
    let connection = timeout(std::time::Duration::from_secs(1), &mut accept)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut received = connection.into_stream().unwrap();
    let mut bytes = [0; 4];
    received.read_exact(&mut bytes).await.unwrap();
    let idle = tokio::spawn(async move { server.accept().await });
    close.close(0u32.into(), b"idle cancellation test complete");
    let cancelled = timeout(std::time::Duration::from_secs(1), idle)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        idle_permits,
        QuicParallelHandle::CONNECTION_LIMIT,
        "idle accept reserved a child slot"
    );
    assert_eq!(&bytes, b"late");
    assert!(
        cancelled.is_err(),
        "parent close left an idle accept running"
    );
}
