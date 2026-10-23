//! A locally queued request cannot start an application's response deadline.
use std::{io, sync::Arc, time::Duration};
use tokio::sync::{Notify, mpsc};
use veil_onion_stream::{CellDuplex, Config, End, Frame, OnionStream, wire::reset_reason};

struct Carrier {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    closed: Arc<Notify>,
}
impl CellDuplex for Carrier {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        self.tx
            .try_send(cell.to_vec())
            .map_err(|_| io::ErrorKind::WouldBlock.into())
    }
    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.rx.recv().await)
    }
    async fn on_stream_closed(&mut self, _: u32, _: End) {
        self.closed.notify_one();
    }
}

#[tokio::test]
async fn initiator_readiness_requires_the_matching_peer_answer_and_observes_reset() {
    let (out_tx, mut out_rx) = mpsc::channel(16);
    let (in_tx, in_rx) = mpsc::channel(16);
    let closed = Arc::new(Notify::new());
    let stream = OnionStream::connect(
        Carrier {
            tx: out_tx,
            rx: in_rx,
            closed: closed.clone(),
        },
        Config::default(),
        41,
        100,
    );
    let connection = stream.connection_handle();
    stream.write_all(b"queued request").await.unwrap();
    assert!(!connection.is_connected().unwrap());
    let syn = tokio::time::timeout(Duration::from_secs(1), out_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(Frame::decode(&syn), Some(Frame::Syn { .. })));
    assert!(
        !connection.is_connected().unwrap(),
        "local SYN handoff is not peer readiness"
    );
    in_tx
        .send(
            Frame::SynAck {
                stream_id: 41,
                isn: 500,
                ack: 102,
                win: 8192,
            }
            .encode(),
        )
        .await
        .unwrap();
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(
        !connection.is_connected().unwrap(),
        "an unrelated answer established the connection"
    );
    in_tx
        .send(
            Frame::SynAck {
                stream_id: 41,
                isn: 500,
                ack: 101,
                win: 8192,
            }
            .encode(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !connection.is_connected().unwrap() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    stream.reset(reset_reason::REFUSED).await;
    assert_eq!(
        connection.is_connected().unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
    tokio::time::timeout(Duration::from_secs(1), closed.notified())
        .await
        .unwrap();
}

#[tokio::test]
async fn accepted_stream_is_not_ready_until_its_peer_syn_is_processed() {
    let (out_tx, _out_rx) = mpsc::channel(16);
    let (in_tx, in_rx) = mpsc::channel(16);
    let closed = Arc::new(Notify::new());
    let stream = OnionStream::accept(
        Carrier {
            tx: out_tx,
            rx: in_rx,
            closed: closed.clone(),
        },
        Config::default(),
        42,
        700,
    );
    let connection = stream.connection_handle();
    assert!(!connection.is_connected().unwrap());
    in_tx
        .send(
            Frame::Syn {
                stream_id: 42,
                isn: 900,
                win: 8192,
            }
            .encode(),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !connection.is_connected().unwrap() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    stream.reset(reset_reason::APP).await;
    tokio::time::timeout(Duration::from_secs(1), closed.notified())
        .await
        .unwrap();
}
