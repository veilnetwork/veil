//! Exercise the production hub factory, rather than constructing fresh cores
//! in a fixture: multiple calls must survive one another's close on one hub.
use super::*;

#[tokio::test]
async fn closing_one_call_does_not_disable_other_or_future_fallbacks_on_the_same_hub() {
    let (_dir, mut runtime, services) = tests::offline_feed_fixture().await;
    let me = services.local_node_id();
    let directory = tempfile::tempdir().unwrap();
    let sock = directory.path().join("node.sock");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut server = veil_ipc::IpcServer::new(
        veil_ipc::IpcEndpoint::Unix(sock.clone()),
        shutdown_rx,
        Arc::new(veil_app::AppEndpointRegistry::new()),
        me,
    );
    let task = tokio::spawn(async move { server.run().await.unwrap() });
    tokio::time::timeout(Duration::from_secs(3), async {
        while !sock.exists() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let client = veilclient::VeilClient::connect(&sock).await.unwrap();
    let app = client
        .bind_named(STREAM_NAMESPACE, STREAM_NAME, STREAM_ENDPOINT_ID)
        .await
        .unwrap();
    let (sender, receiver) = app.into_split();
    let (messages, _streams) = receiver.into_parts();
    let hub = AnonStreamHub::new(me, sender, messages);
    let planes = [
        LocalMediaPlane::Primary,
        LocalMediaPlane::Secondary,
        LocalMediaPlane::Screen,
        LocalMediaPlane::Control,
    ];
    let mut admitted = Vec::new();
    // Same-peer repeated calls and a simultaneous call to another peer must
    // both work. No relay is available: observe real opener admission without
    // pretending queue admission proves successful network/media delivery.
    for (i, peer) in [[0x91; 32], [0x92; 32]].into_iter().enumerate() {
        let make = |channel, peer| {
            hub.private_media_routes(
                peer,
                channel,
                Arc::new(crate::media::cipher_for_test(&peer, &[1; 32], &[2; 32]).unwrap()),
            )
            .unwrap()
        };
        let first = make(10 + i as u64 * 3, [0x91; 32]);
        let concurrent = make(11 + i as u64 * 3, peer);
        first.stop();
        for plane in planes {
            concurrent.warm(plane).await;
        }
        admitted.push(concurrent.fallback_tasks_for_test().len());
        concurrent.stop();
        let subsequent = make(12 + i as u64 * 3, peer);
        for plane in planes {
            subsequent.warm(plane).await;
        }
        admitted.push(subsequent.fallback_tasks_for_test().len());
        subsequent.stop();
        assert!(first.fallback_tasks_for_test().is_empty());
    }
    let sender = Arc::clone(&hub._sender);
    drop(hub);
    Arc::try_unwrap(sender).ok().unwrap().close().await;
    drop(client);
    let _ = shutdown_tx.send(true);
    task.await.unwrap();
    runtime.stop().await.unwrap();
    assert!(!sock.exists());
    assert_eq!(
        admitted,
        vec![4, 4, 4, 4],
        "closing a call must not suppress any live/new call's fallback opener"
    );
}
