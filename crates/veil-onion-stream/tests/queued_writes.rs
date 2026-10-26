//! Already queued application writes should fill DATA cells together.
use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{Notify, mpsc},
    time::Instant,
};
use veil_onion_stream::{CellDuplex, Config, End, Frame, OnionStream, StreamEngine};

#[derive(Default)]
struct Observations {
    paused: Notify,
    resume: Notify,
    finished: Notify,
    closed: Notify,
    sizes: Mutex<Vec<usize>>,
    bytes: Mutex<Vec<u8>>,
}

struct Carrier {
    peer: StreamEngine,
    base: Instant,
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    observations: Arc<Observations>,
    paused: bool,
}

impl CellDuplex for Carrier {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        if let Some(Frame::Data { payload, .. }) = Frame::decode(cell) {
            if !self.paused {
                self.paused = true;
                self.observations.paused.notify_one();
                self.observations.resume.notified().await;
            }
            self.observations.sizes.lock().unwrap().push(payload.len());
        }
        let now = self.base.elapsed().as_millis() as u64;
        self.peer.on_cell(cell, now);
        let mut bytes = [0; 32768];
        loop {
            let n = self.peer.read(&mut bytes);
            if n == 0 {
                break;
            }
            self.observations
                .bytes
                .lock()
                .unwrap()
                .extend_from_slice(&bytes[..n]);
        }
        if self.peer.is_eof() {
            self.observations.finished.notify_one();
        }
        let mut response = Vec::new();
        while self.peer.poll_transmit(now, &mut response) {
            self.tx.try_send(response.clone()).unwrap();
        }
        Ok(())
    }

    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.rx.recv().await)
    }

    async fn on_stream_closed(&mut self, _: u32, _: End) {
        self.observations.closed.notify_one();
    }
}

#[tokio::test(start_paused = true)]
async fn queued_short_writes_share_cells_without_waiting_for_more_data() {
    let sizes = exercise(9).await;
    // Two cells for the already polled first write, then nine for the queued
    // 16 KiB. Repeated 66-byte tails would need eighteen padded cells.
    assert_eq!(
        sizes.len(),
        2048_usize.div_ceil(1982) + (2048_usize * 8).div_ceil(1982),
        "DATA payload sizes: {sizes:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn sustained_writes_and_fin_survive_multiple_command_batches() {
    exercise(65).await;
}

async fn exercise(chunks: usize) -> Vec<usize> {
    const MSS: usize = 1982;
    const CHUNK: usize = 2048;
    let config = Config {
        mss: MSS,
        init_cwnd: 65536,
        recv_window: 65536,
        max_pacing_batch: 32,
        ack_every: 1,
        ack_delay_ms: 1,
        ..Config::default()
    };
    let observations = Arc::new(Observations::default());
    let (tx, rx) = mpsc::channel(128);
    let carrier = Carrier {
        peer: StreamEngine::accept(41, config, 0, 500),
        base: Instant::now(),
        tx,
        rx,
        observations: observations.clone(),
        paused: false,
    };
    let stream = OnionStream::connect(carrier, config, 41, 100);
    let data: Vec<u8> = (0..CHUNK * chunks).map(|i| (i % 251) as u8).collect();
    stream.write_all(&data[..CHUNK]).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), observations.paused.notified())
        .await
        .unwrap();
    // The carrier is awaiting admission, so these eight writes are all ready
    // before its next poll. A single isolated write above must still go out.
    for chunk in data[CHUNK..CHUNK * 9].chunks(CHUNK) {
        stream.write_all(chunk).await.unwrap();
    }
    observations.resume.notify_one();
    for chunk in data[CHUNK * 9..].chunks(CHUNK) {
        stream.write_all(chunk).await.unwrap();
    }
    stream.finish().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), observations.finished.notified())
        .await
        .unwrap();
    stream
        .reset(veil_onion_stream::wire::reset_reason::APP)
        .await;
    tokio::time::timeout(Duration::from_secs(1), observations.closed.notified())
        .await
        .unwrap();
    assert_eq!(*observations.bytes.lock().unwrap(), data);
    observations.sizes.lock().unwrap().clone()
}
