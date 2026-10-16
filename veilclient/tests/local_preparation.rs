//! Owned local preparation, wire correlation and legacy negotiation.
#![cfg(unix)]
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use veil_proto::{FrameFamily, FrameHeader, HEADER_SIZE, LocalAppMsg, codec};
use veil_types::{FrameBroadcaster, LocalDatagramChannelState as State};

fn socket_path() -> std::path::PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "veil-prepare-{}-{}.sock",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

struct Registry(Mutex<Vec<([u8; 32], u8)>>);
impl FrameBroadcaster for Registry {
    fn supports_local_datagram_preparation(&self) -> bool {
        true
    }
    fn prepare_local_datagram_channel(&self, peer: &[u8; 32], lane: u8, _: bool) -> State {
        self.0.lock().unwrap().push((*peer, lane));
        if lane == 0 {
            State::Warming
        } else {
            State::Ready
        }
    }
    fn send_to(&self, _: &[u8; 32], _: u8, _: Vec<u8>) -> bool {
        panic!("preparation must not submit user packets")
    }
    fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {
        panic!("preparation must not broadcast")
    }
    fn active_node_ids(&self) -> Vec<[u8; 32]> {
        vec![[2; 32], [3; 32]]
    }
}

#[tokio::test]
async fn preparation_requires_real_ipc_binding_and_keeps_direct_and_relay_separate() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let path = socket_path();
        let registry = Arc::new(Registry(Mutex::new(vec![])));
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        let mut server = veil_ipc::IpcServer::new(
            veil_ipc::IpcEndpoint::Unix(path.clone()),
            shutdown,
            Arc::new(veilcore::node::app::AppEndpointRegistry::new()),
            [1; 32],
        )
        .with_session_tx_registry(registry.clone());
        let server = tokio::spawn(async move {
            server.run().await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        let client = veilclient::VeilClient::connect(&path).await.unwrap();
        assert_eq!(
            client
                .prepare_local_datagram_channel([7; 32], [9; 32], veil_proto::priority::BULK, false)
                .await
                .unwrap(),
            Some(State::Unsupported)
        );
        assert!(registry.0.lock().unwrap().is_empty());
        let app = client
            .bind_named("test.preparation", "sender", 31)
            .await
            .unwrap();
        let owner = *app.app_id();
        let (audio, video) = tokio::join!(
            client.prepare_local_datagram_channel(owner, [9; 32], 0, false),
            client.prepare_local_datagram_channel(
                owner,
                [9; 32],
                veil_proto::priority::BULK,
                false
            ),
        );
        assert_eq!(audio.unwrap(), Some(State::Warming));
        assert_eq!(video.unwrap(), Some(State::Ready));
        assert!(
            registry
                .0
                .lock()
                .unwrap()
                .iter()
                .all(|(peer, _)| *peer == [9; 32])
        );
        registry.0.lock().unwrap().clear();
        assert_eq!(
            client
                .prepare_local_datagram_channel(owner, [9; 32], veil_proto::priority::BULK, true)
                .await
                .unwrap(),
            Some(State::Ready)
        );
        let mut peers = registry
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|(p, _)| *p)
            .collect::<Vec<_>>();
        peers.sort();
        assert_eq!(peers, vec![[2; 32], [3; 32]]);
        drop(app);
        drop(client);
        stop.send(true).unwrap();
        server.await.unwrap();
        let _ = tokio::fs::remove_file(&path).await;
    })
    .await
    .unwrap();
}

async fn read_frame(stream: &mut tokio::net::UnixStream) -> (FrameHeader, Vec<u8>) {
    let mut bytes = [0; HEADER_SIZE];
    stream.read_exact(&mut bytes).await.unwrap();
    let header = codec::decode_header(&bytes).unwrap();
    let mut body = vec![0; header.body_len as usize];
    stream.read_exact(&mut body).await.unwrap();
    (header, body)
}
async fn write_frame(stream: &mut tokio::net::UnixStream, mut header: FrameHeader, body: &[u8]) {
    header.body_len = body.len() as u32;
    stream
        .write_all(&codec::encode_header(&header))
        .await
        .unwrap();
    stream.write_all(body).await.unwrap();
}

#[tokio::test]
async fn preparation_replies_match_request_ids_when_the_daemon_reorders_them() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let path = socket_path();
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let daemon = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (_, body) = read_frame(&mut stream).await;
            let hello = veil_proto::ipc::AppIpcHelloPayload::decode(&body).unwrap();
            assert_ne!(
                hello.flags & veil_proto::ipc::IPC_CAP_LOCAL_DATAGRAM_PREPARATION,
                0
            );
            let mut reply =
                FrameHeader::new(FrameFamily::LocalApp as u8, LocalAppMsg::AppHelloOk as u16);
            reply.flags = veil_proto::ipc::IPC_HELLO_OK_LOCAL_DATAGRAM_PREPARATION;
            write_frame(
                &mut stream,
                reply,
                &veil_proto::ipc::AppIpcHelloOkPayload {
                    version: 1,
                    client_token: [1; 16],
                }
                .encode(),
            )
            .await;
            let a = read_frame(&mut stream).await;
            let b = read_frame(&mut stream).await;
            assert_ne!(a.0.request_id, 0);
            assert_ne!(a.0.request_id, b.0.request_id);
            for (header, body) in [b, a] {
                assert_eq!(header.msg_type, LocalAppMsg::PrepareLocalDatagram as u16);
                let request = veil_proto::ipc::PrepareLocalDatagramPayload::decode(&body).unwrap();
                assert_eq!(
                    request.refresh,
                    request.local_lane == veil_proto::priority::REALTIME
                );
                let mut reply = FrameHeader::new(
                    FrameFamily::LocalApp as u8,
                    LocalAppMsg::PrepareLocalDatagramResult as u16,
                );
                reply.request_id = header.request_id;
                write_frame(
                    &mut stream,
                    reply,
                    &[if request.local_lane == 0 { 1 } else { 2 }],
                )
                .await;
            }
        });
        let client = veilclient::VeilClient::connect(&path).await.unwrap();
        let (a, b) = tokio::join!(
            client.prepare_local_datagram_channel([7; 32], [9; 32], 0, false),
            client.local_datagram_channel_state(
                [7; 32],
                [9; 32],
                veil_proto::priority::BULK,
                false
            ),
        );
        assert_eq!(a.unwrap(), Some(State::Warming));
        assert_eq!(b.unwrap(), Some(State::Ready));
        daemon.await.unwrap();
        drop(client);
        let _ = tokio::fs::remove_file(&path).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn legacy_daemon_without_capability_receives_no_preparation_rpc() {
    tokio::time::timeout(Duration::from_secs(2), async {
        let path = socket_path();
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let daemon = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_frame(&mut stream).await;
            write_frame(
                &mut stream,
                FrameHeader::new(FrameFamily::LocalApp as u8, LocalAppMsg::AppHelloOk as u16),
                &veil_proto::ipc::AppIpcHelloOkPayload {
                    version: 1,
                    client_token: [1; 16],
                }
                .encode(),
            )
            .await;
            let mut byte = [0];
            assert!(
                tokio::time::timeout(Duration::from_millis(100), stream.read_exact(&mut byte))
                    .await
                    .is_err(),
                "an old daemon must not receive an unknown RPC"
            );
        });
        let client = veilclient::VeilClient::connect(&path).await.unwrap();
        for relayed in [false, true] {
            assert_eq!(
                client
                    .prepare_local_datagram_channel([7; 32], [9; 32], 0, relayed)
                    .await
                    .unwrap(),
                Some(State::Unsupported)
            );
        }
        daemon.await.unwrap();
        drop(client);
        let _ = tokio::fs::remove_file(&path).await;
    })
    .await
    .unwrap();
}
