//! Losing one last ACK must not strand a peer after the app saw clean EOF.
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    sync::mpsc,
    time::{Duration, Instant},
};
use veil_onion_stream::{CellDuplex, Config, Frame, OnionStream, StreamEngine};

struct Link {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    lingering: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
}
impl CellDuplex for Link {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        self.tx
            .send(cell.to_vec())
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.rx.recv().await)
    }
    async fn on_stream_linger(&mut self, _stream_id: u32) {
        self.lingering.fetch_add(1, Ordering::Relaxed);
    }
    async fn on_stream_closed(&mut self, _stream_id: u32, _end: veil_onion_stream::End) {
        self.closed.fetch_add(1, Ordering::Relaxed);
    }
}

async fn lost_final_ack(graceful_drop: bool) {
    let cfg = Config {
        ack_every: 1,
        ack_delay_ms: 1,
        init_rto_ms: 30,
        min_rto_ms: 30,
        max_rto_ms: 60,
        max_retransmits: 2,
        close_linger_ms: 120,
        ..Config::default()
    };
    let (tx, mut peer_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (peer_tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let acknowledgements = Arc::new(AtomicUsize::new(0));
    let count = acknowledgements.clone();
    let peer = tokio::spawn(async move {
        let base = Instant::now();
        let mut engine = StreamEngine::accept(7, cfg, 0, 500);
        let mut out = Vec::new();
        let mut bytes = Vec::new();
        let mut fin_end = None;
        loop {
            let now = base.elapsed().as_millis() as u64;
            while engine.poll_transmit(now, &mut out) {
                if let Some(Frame::Fin { seq, .. }) = Frame::decode(&out) {
                    fin_end = Some(seq.wrapping_add(1));
                }
                if peer_tx.send(out.clone()).is_err() {
                    return false;
                }
            }
            if engine.is_send_complete() && engine.is_eof() {
                assert_eq!(bytes, b"12345678");
                return true;
            }
            let deadline = engine.next_timeout().unwrap_or(now + 1000);
            tokio::select! {
                data = peer_rx.recv() => {
                    let Some(data) = data else { return false; };
                    if matches!(Frame::decode(&data), Some(Frame::Ack { ack, .. }) if Some(ack) == fin_end)
                        && count.fetch_add(1, Ordering::Relaxed) == 0 {
                        continue; // one genuinely lost final ACK
                    }
                    engine.on_cell(&data, base.elapsed().as_millis() as u64);
                    let mut buffer = [0; 64];
                    loop {
                        let n = engine.read(&mut buffer);
                        if n == 0 { break; }
                        bytes.extend_from_slice(&buffer[..n]);
                    }
                    if bytes.len() == 8 { engine.finish(); }
                },
                _ = tokio::time::sleep_until(base + Duration::from_millis(deadline)) => {
                    engine.on_timeout(base.elapsed().as_millis() as u64);
                }
            }
        }
    });
    let lingering = Arc::new(AtomicUsize::new(0));
    let closed = Arc::new(AtomicUsize::new(0));
    let mut stream = OnionStream::connect(
        Link {
            tx,
            rx,
            lingering: lingering.clone(),
            closed: closed.clone(),
        },
        cfg,
        7,
        100,
    );
    stream.write_all(b"12345678").await.unwrap();
    stream.finish().await.unwrap();
    let mut buf = [0; 8];
    assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
    assert_eq!(
        lingering.load(Ordering::Relaxed),
        1,
        "data admission was not released before the close lease"
    );
    assert_eq!(
        closed.load(Ordering::Relaxed),
        0,
        "the final-ACK return route closed too early"
    );
    assert!(
        !peer.is_finished(),
        "application EOF must precede the close repair"
    );
    if graceful_drop {
        drop(stream);
    }
    assert!(
        peer.await.unwrap(),
        "clean local EOF discarded the peer's final-ACK return path"
    );
    assert_eq!(acknowledgements.load(Ordering::Relaxed), 2);
}

#[tokio::test(start_paused = true)]
async fn lost_final_ack_is_repaired_after_local_eof() {
    lost_final_ack(false).await;
}

#[tokio::test(start_paused = true)]
async fn dropping_finished_handles_does_not_cancel_close_repair() {
    lost_final_ack(true).await;
}
