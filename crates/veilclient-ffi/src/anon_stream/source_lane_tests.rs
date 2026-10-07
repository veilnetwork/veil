//! Exercise the fallback's real CellSender → SDK → Unix IPC → anonymous-send
//! boundary. The provider records arguments; cryptography remains covered by
//! the node's anonymous-send tests.

use super::*;
use std::{future::Future, pin::Pin};
use veil_types::{AnonOnionSendError, AnonOnionSender};

type SendFuture<'a> = Pin<Box<dyn Future<Output = Result<(), AnonOnionSendError>> + Send + 'a>>;

#[derive(Debug)]
struct Sent {
    lane: u8,
    target: [u8; 32],
    app: [u8; 32],
    endpoint: u32,
    bytes: Vec<u8>,
}

struct Provider(mpsc::UnboundedSender<Sent>);

impl AnonOnionSender for Provider {
    fn send_authenticated_on_local_lane<'a>(
        &'a self,
        lane: u8,
        target: [u8; 32],
        app: [u8; 32],
        endpoint: u32,
        data: &'a [u8],
    ) -> SendFuture<'a> {
        self.0
            .send(Sent {
                lane,
                target,
                app,
                endpoint,
                bytes: data.to_vec(),
            })
            .unwrap();
        Box::pin(async { Ok(()) })
    }
    fn send_authenticated<'a>(
        &'a self,
        _: [u8; 32],
        _: [u8; 32],
        _: u32,
        _: &'a [u8],
    ) -> SendFuture<'a> {
        panic!("source lane bypassed IPC dispatch")
    }
    fn send_authenticated_with_reply<'a>(
        &'a self,
        _: [u8; 32],
        _: [u8; 32],
        _: u32,
        _: &'a [u8],
        _: [u8; 32],
        _: u32,
    ) -> SendFuture<'a> {
        panic!("stream cell requested a reply circuit")
    }
    fn send_authenticated_direct_with_reply<'a>(
        &'a self,
        _: [u8; 32],
        _: [u8; 32],
        _: [u8; 32],
        _: u32,
        _: &'a [u8],
        _: Option<([u8; 32], u32)>,
    ) -> SendFuture<'a> {
        panic!("anonymous route changed")
    }
    fn send_reply<'a>(&'a self, _: u64, _: &'a [u8], _: [u8; 32]) -> SendFuture<'a> {
        panic!("unexpected reply")
    }
    fn register_onion_service<'a>(&'a self, _: usize) -> SendFuture<'a> {
        panic!("unexpected service")
    }
    fn register_rendezvous_publisher(
        &self,
        _: [u8; 32],
        _: [u8; 16],
        _: u64,
        _: u8,
        _: Vec<u8>,
        _: u64,
    ) -> bool {
        panic!("unexpected registration")
    }
    fn send_to_onion_service<'a>(
        &'a self,
        _: [u8; 32],
        _: [u8; 32],
        _: u32,
        _: &'a [u8],
        _: usize,
    ) -> SendFuture<'a> {
        panic!("wrong authentication path")
    }
    fn send_to_onion_service_anonymous<'a>(
        &'a self,
        _: [u8; 32],
        _: [u8; 32],
        _: u32,
        _: [u8; 32],
        _: &'a [u8],
        _: usize,
    ) -> SendFuture<'a> {
        panic!("lost sender authentication")
    }
    fn send_anonymous_direct<'a>(
        &'a self,
        _: [u8; 32],
        _: [u8; 32],
        _: [u8; 32],
        _: u32,
        _: [u8; 32],
        _: &'a [u8],
        _: usize,
    ) -> SendFuture<'a> {
        panic!("lost sender authentication")
    }
}

#[tokio::test]
async fn fallback_data_and_resends_keep_anonymous_routing_on_the_recoverable_source_lane() {
    use veil_onion_stream::wire::{SackVec, reset_reason};
    use veil_proto::{ipc::LOCAL_RECOVERABLE_DATA_LANE, priority::INTERACTIVE};
    let directory = tempfile::tempdir().unwrap();
    let sock = directory.path().join("node.sock");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut server = veil_ipc::IpcServer::new(
        veil_ipc::IpcEndpoint::Unix(sock.clone()),
        shutdown_rx,
        Arc::new(veil_app::AppEndpointRegistry::new()),
        [0xA1; 32],
    )
    .with_anon_onion_sender(Arc::new(Provider(tx)));
    let task = tokio::spawn(async move {
        server.run().await.unwrap();
    });
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
    let cells = AnonCells {
        sender: Arc::new(sender),
        data_pacer: Arc::new(StreamDataPacer::new(Duration::ZERO)),
    };
    let dst = Addr {
        node: [0xB2; 32],
        app: [0xAB; 32],
    };
    let payload: Vec<_> = (0..512).map(|n| (n % 251) as u8).collect();
    let frames = [
        (
            INTERACTIVE,
            Frame::Syn {
                stream_id: 7,
                isn: 10,
                win: 8192,
            },
        ),
        (
            INTERACTIVE,
            Frame::SynAck {
                stream_id: 7,
                isn: 10,
                win: 8192,
                ack: 11,
            },
        ),
        (
            LOCAL_RECOVERABLE_DATA_LANE,
            Frame::Data {
                stream_id: 7,
                seq: 11,
                win: 8192,
                payload: &payload,
            },
        ),
        // Identical retransmission also keeps its lane and exact payload.
        (
            LOCAL_RECOVERABLE_DATA_LANE,
            Frame::Data {
                stream_id: 7,
                seq: 11,
                win: 8192,
                payload: &payload,
            },
        ),
        (
            INTERACTIVE,
            Frame::Ack {
                stream_id: 7,
                ack: 523,
                win: 8192,
                sacks: SackVec::new(),
            },
        ),
        (
            INTERACTIVE,
            Frame::Fin {
                stream_id: 7,
                seq: 523,
            },
        ),
        (
            INTERACTIVE,
            Frame::Rst {
                stream_id: 7,
                reason: reset_reason::APP,
            },
        ),
    ];
    let mut expected = Vec::new();
    for (lane, frame) in frames {
        let mut bytes = Vec::new();
        frame.encode_into(&mut bytes);
        cells.send(dst, bytes.clone()).await.unwrap();
        expected.push((lane, bytes));
    }
    let malformed = vec![1, 3];
    cells.send(dst, malformed.clone()).await.unwrap();
    expected.push((INTERACTIVE, malformed));
    for (lane, bytes) in expected {
        let sent = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            sent.lane, lane,
            "fallback DATA escaped its source lane or a control was demoted"
        );
        assert_eq!(sent.target, dst.node);
        assert_eq!(sent.app, dst.app);
        assert_eq!(sent.endpoint, STREAM_ENDPOINT_ID);
        assert_eq!(
            sent.bytes, bytes,
            "source classification changed protected cell bytes"
        );
    }
    Arc::try_unwrap(cells.sender).ok().unwrap().close().await;
    drop(receiver);
    drop(client);
    let _ = shutdown_tx.send(true);
    task.await.unwrap();
    assert!(!sock.exists(), "owned IPC socket remained after shutdown");
}
