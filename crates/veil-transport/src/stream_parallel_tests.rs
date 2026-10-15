use super::*;
use crate::traits::{Transport, TransportListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};

async fn pair() -> (
    Box<dyn TransportConnection>,
    Box<dyn TransportConnection>,
    Box<dyn TransportListener>,
) {
    let mut context = TransportContext::for_debug().unwrap();
    context.obfs4_psk = Some(Arc::new([0x42; 32]));
    let context = Arc::new(context);
    let transport = crate::obfs4_tcp::Obfs4TcpTransport;
    let bind = TransportUri::Obfs4Tcp {
        host: "127.0.0.1".into(),
        port: 0,
    };
    let listener = transport.bind(&bind, Arc::clone(&context)).await.unwrap();
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
    let (client, server) = tokio::join!(transport.connect(&dial, context), listener.accept());
    (client.unwrap(), server.unwrap(), listener)
}

async fn child(
    handle: &StreamParallelHandle,
    listener: &dyn TransportListener,
) -> (Box<dyn TransportConnection>, Box<dyn TransportConnection>) {
    let (client, server) = tokio::join!(handle.connect(), listener.accept());
    (client.unwrap(), server.unwrap())
}

async fn roundtrip(mut client: BoxIoStream, mut server: BoxIoStream) {
    let client_work = async {
        client.write_all(b"independent stream").await.unwrap();
        client.flush().await.unwrap();
        let mut response = [0; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
    };
    let server_work = async {
        let mut payload = [0; 18];
        server.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"independent stream");
        server.write_all(b"ok").await.unwrap();
        server.flush().await.unwrap();
    };
    timeout(Duration::from_secs(2), async {
        tokio::join!(client_work, server_work);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn child_has_fresh_binding_and_no_nested_offer() {
    let (client, server, listener) = pair().await;
    let handle = client.parallel_stream().unwrap();
    let parent_binding = client.stream_channel_binding().unwrap();
    assert_eq!(server.stream_channel_binding(), Some(parent_binding));
    let (child_client, child_server) = child(&handle, &*listener).await;
    let binding = child_client.stream_channel_binding().unwrap();
    assert_eq!(child_server.stream_channel_binding(), Some(binding));
    assert_ne!(binding, parent_binding);
    assert!(child_client.parallel_stream().is_none());
    roundtrip(
        child_client.into_stream().unwrap(),
        child_server.into_stream().unwrap(),
    )
    .await;
}

#[tokio::test]
async fn child_progresses_while_parent_tcp_write_is_blocked() {
    let (client, server, listener) = pair().await;
    let handle = client.parallel_stream().unwrap();
    let mut parent = client.into_stream().unwrap();
    let _unread_server = server.into_stream().unwrap();
    let bulk = vec![0x5a; 4 * 1024 * 1024];
    assert!(
        timeout(Duration::from_millis(150), parent.write_all(&bulk))
            .await
            .is_err(),
        "control must actually fill the parent's TCP receive/send buffers"
    );
    let (child_client, child_server) = child(&handle, &*listener).await;
    roundtrip(
        child_client.into_stream().unwrap(),
        child_server.into_stream().unwrap(),
    )
    .await;
    assert!(handle.can_connect());
}

#[tokio::test]
async fn dropping_parent_wakes_pending_child_and_revokes_held_handles() {
    let (client, _server, listener) = pair().await;
    let handle = client.parallel_stream().unwrap();
    let held = handle.clone();
    let parent = client.into_stream().unwrap();
    let (child_client, _child_server) = child(&handle, &*listener).await;
    let mut stream = child_client.into_stream().unwrap();
    let mut bytes = [0];
    let mut pending = Box::pin(stream.read_exact(&mut bytes));
    assert!(
        timeout(Duration::from_millis(20), pending.as_mut())
            .await
            .is_err()
    );
    drop(parent);
    let error = timeout(Duration::from_secs(1), pending)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert!(!held.can_connect());
    assert!(held.connect().await.is_err());
    timeout(Duration::from_secs(1), held.closed())
        .await
        .unwrap();
}

#[tokio::test]
async fn dropping_child_does_not_close_parent_or_other_child() {
    let (client, server, listener) = pair().await;
    let handle = client.parallel_stream().unwrap();
    let (first, first_remote) = child(&handle, &*listener).await;
    let (second, second_remote) = child(&handle, &*listener).await;
    drop(first);
    drop(first_remote);
    assert!(handle.can_connect());
    roundtrip(
        second.into_stream().unwrap(),
        second_remote.into_stream().unwrap(),
    )
    .await;
    roundtrip(client.into_stream().unwrap(), server.into_stream().unwrap()).await;
}

#[tokio::test]
async fn connection_budget_is_bounded_and_reclaimed_after_child_drop() {
    let (client, server, listener) = pair().await;
    let handle = client.parallel_stream().unwrap();
    let incoming = server.parallel_stream().unwrap();
    assert!(!incoming.can_connect());
    assert!(incoming.connect().await.is_err());
    let mut children = Vec::new();
    for _ in 0..StreamParallelHandle::CONNECTIONS_PER_DIRECTION {
        let (a, b) = child(&handle, &*listener).await;
        children.push((
            a.into_stream().unwrap(),
            incoming.track_incoming(b.into_stream().unwrap()).unwrap(),
        ));
    }
    assert!(handle.connect().await.is_err());
    let (extra, _other) = tokio::io::duplex(1024);
    assert!(incoming.track_incoming(Box::new(extra)).is_err());
    children.pop();
    let (a, b) = child(&handle, &*listener).await;
    let b = incoming.track_incoming(b.into_stream().unwrap()).unwrap();
    roundtrip(a.into_stream().unwrap(), b).await;
    drop(server);
    let (extra, _other) = tokio::io::duplex(1024);
    assert!(incoming.track_incoming(Box::new(extra)).is_err());
    for (_, mut receiver) in children {
        let mut bytes = [0];
        assert_eq!(
            receiver.read_exact(&mut bytes).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }
}
