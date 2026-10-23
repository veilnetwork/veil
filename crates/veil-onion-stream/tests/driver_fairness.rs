//! A paced local carrier must not keep a ready ACK behind an entire send window.
use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, mpsc},
    time::Instant,
};
use veil_onion_stream::{CellDuplex, Config, End, Frame, OnionStream, StreamEngine, seq};

const PREFIX: usize = 16;
const ADMISSION_MS: u64 = 2;
const REPLY: &[u8] = b"received";

#[derive(Default)]
struct Observations {
    admission_ms: AtomicU64,
    ack_wait_ms: AtomicU64,
    data_wait_ms: AtomicU64,
    prefix_acked: Notify,
    bulk_acked: Notify,
    closed: Notify,
    bytes: Mutex<Vec<u8>>,
}

struct PacedCarrier {
    peer: StreamEngine,
    base: Instant,
    tx: mpsc::Sender<(Instant, Vec<u8>)>,
    rx: mpsc::Receiver<(Instant, Vec<u8>)>,
    observations: Arc<Observations>,
    prefix_end: u32,
    bulk_end: u32,
    reverse_reply: bool,
    replied: bool,
}

impl CellDuplex for PacedCarrier {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        if matches!(Frame::decode(cell), Some(Frame::Data { .. })) {
            // Same shape as a shared DATA token bucket that awaits admission.
            let started = Instant::now();
            tokio::time::sleep(Duration::from_millis(ADMISSION_MS)).await;
            self.observations
                .admission_ms
                .fetch_max(started.elapsed().as_millis() as u64, Ordering::Relaxed);
        }
        let now = self.base.elapsed().as_millis() as u64;
        self.peer.on_cell(cell, now);
        let mut chunk = [0; 4096];
        loop {
            let n = self.peer.read(&mut chunk);
            if n == 0 {
                break;
            }
            self.observations
                .bytes
                .lock()
                .unwrap()
                .extend_from_slice(&chunk[..n]);
        }
        if self.reverse_reply
            && !self.replied
            && self.observations.bytes.lock().unwrap().len() > PREFIX
        {
            self.peer.write(REPLY);
            self.replied = true;
        }
        let mut response = Vec::new();
        while self.peer.poll_transmit(now, &mut response) {
            self.tx
                .try_send((Instant::now(), response.clone()))
                .unwrap();
        }
        Ok(())
    }
    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        let Some((queued, cell)) = self.rx.recv().await else {
            return Ok(None);
        };
        let age = queued.elapsed().as_millis() as u64;
        match Frame::decode(&cell) {
            Some(Frame::Ack { ack, .. }) => {
                self.observations
                    .ack_wait_ms
                    .fetch_max(age, Ordering::Relaxed);
                if seq::geq(ack, self.prefix_end) {
                    self.observations.prefix_acked.notify_one();
                }
                if seq::geq(ack, self.bulk_end) {
                    self.observations.bulk_acked.notify_one();
                }
            }
            Some(Frame::Data { .. }) => {
                self.observations
                    .data_wait_ms
                    .fetch_max(age, Ordering::Relaxed);
            }
            _ => {}
        }
        Ok(Some(cell))
    }
    async fn send_cells(&mut self, cells: &mut VecDeque<Vec<u8>>) -> io::Result<()> {
        while let Some(cell) = cells.front() {
            self.send_cell(cell).await?;
            cells.pop_front();
        }
        Ok(())
    }
    async fn on_stream_closed(&mut self, _: u32, _: End) {
        self.observations.closed.notify_one();
    }
}

async fn exercise(iss: u32, reverse_reply: bool, rack: bool) {
    let config = Config {
        mss: 64,
        init_cwnd: 4096,
        recv_window: 65536,
        max_pacing_batch: 1,
        ack_every: 1,
        ack_delay_ms: 1,
        init_rto_ms: 2000,
        min_rto_ms: 50,
        max_rto_ms: 3000,
        rack,
        ..Config::default()
    };
    let observations = Arc::new(Observations::default());
    let (tx, rx) = mpsc::channel(4096);
    let data: Vec<u8> = (0..16384).map(|i| (i % 251) as u8).collect();
    let prefix_end = iss.wrapping_add(1 + PREFIX as u32);
    let carrier = PacedCarrier {
        peer: StreamEngine::accept(41, config, 0, 500),
        base: Instant::now(),
        tx,
        rx,
        observations: observations.clone(),
        prefix_end,
        bulk_end: prefix_end.wrapping_add(data.len() as u32),
        reverse_reply,
        replied: false,
    };
    let mut stream = OnionStream::connect(carrier, config, 41, iss);
    stream.write_all(&[0; PREFIX]).await.unwrap();
    tokio::time::timeout(
        Duration::from_millis(20),
        observations.prefix_acked.notified(),
    )
    .await
    .unwrap();
    // A real acknowledged prefix warms RTT so the engine emits one paced cell
    // per tick; each successful carrier await makes the next tick due again.
    stream.write_all(&data).await.unwrap();
    let completed =
        tokio::time::timeout(Duration::from_secs(3), observations.bulk_acked.notified()).await;
    let mut reverse = vec![0; REPLY.len()];
    if reverse_reply {
        assert_eq!(stream.read(&mut reverse).await.unwrap(), REPLY.len());
    }
    stream
        .reset(veil_onion_stream::wire::reset_reason::APP)
        .await;
    tokio::time::timeout(Duration::from_millis(20), observations.closed.notified())
        .await
        .unwrap();
    assert!(completed.is_ok(), "bulk never drained its ACK clock");
    assert_eq!(
        *observations.bytes.lock().unwrap(),
        [vec![0; PREFIX], data].concat()
    );
    if reverse_reply {
        assert_eq!(reverse, REPLY);
    }
    let admission = observations.admission_ms.load(Ordering::Relaxed);
    let ack = observations.ack_wait_ms.load(Ordering::Relaxed);
    let data = observations.data_wait_ms.load(Ordering::Relaxed);
    assert!(
        ack <= admission && data <= admission,
        "ready inbound queue waited beyond one local admission: ack={ack}ms data={data}ms admission={admission}ms"
    );
}

#[tokio::test(start_paused = true)]
async fn ready_acks_are_not_held_behind_a_paced_send_window() {
    for rack in [false, true] {
        for iss in [100, u32::MAX - 127] {
            exercise(iss, false, rack).await;
        }
    }
}
#[tokio::test(start_paused = true)]
async fn reverse_data_is_not_held_behind_a_paced_send_window() {
    for rack in [false, true] {
        for iss in [100, u32::MAX - 127] {
            exercise(iss, true, rack).await;
        }
    }
}
