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
use veil_onion_stream::{
    CellDuplex, Config, End, Frame, OnionAbort, OnionStream, StreamEngine, seq, wire::reset_reason,
};

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

#[derive(Default)]
struct ReadyInputObservations {
    rtos: AtomicU64,
    data_sends: AtomicU64,
    later_write_sends: AtomicU64,
    reads: AtomicU64,
    abort: Mutex<Option<OnionAbort>>,
    closed: Notify,
}

struct ReadyInputCarrier {
    peer: StreamEngine,
    replies: VecDeque<Vec<u8>>,
    seen: Arc<ReadyInputObservations>,
    abort_at: Option<u64>,
}

impl CellDuplex for ReadyInputCarrier {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        if let Some(Frame::Data { payload, .. }) = Frame::decode(cell) {
            // Drop every DATA transmission. Duplicate ACK traffic must not
            // hide the timer needed to repair this outstanding segment.
            self.seen.data_sends.fetch_add(1, Ordering::Relaxed);
            if payload.first() == Some(&0x7b) {
                self.seen.later_write_sends.fetch_add(1, Ordering::Relaxed);
            }
            return Ok(());
        }
        self.peer.on_cell(cell, 0);
        let mut reply = Vec::new();
        while self.peer.poll_transmit(0, &mut reply) {
            self.replies.push_back(reply.clone());
        }
        Ok(())
    }

    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        if let Some(reply) = self.replies.pop_front() {
            return Ok(Some(reply));
        }
        let n = self.seen.reads.fetch_add(1, Ordering::Relaxed) + 1;
        if n > 200 {
            return Ok(None);
        }
        // Model a bounded backlog whose ready reads consume CPU/clock time
        // without an async park. A Tokio sleep would make input Pending and
        // conceal biased-select starvation. The entire fixture is < 1 second.
        std::thread::sleep(Duration::from_millis(1));
        if self.abort_at == Some(n) {
            self.seen
                .abort
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .reset(reset_reason::APP);
        }
        Ok(Some(
            Frame::Ack {
                stream_id: 41,
                ack: 101,
                win: 65536,
                sacks: Default::default(),
            }
            .encode(),
        ))
    }

    async fn on_data_rto(&mut self, _: u32, _: u32, _: u32) {
        self.seen.rtos.fetch_add(1, Ordering::Relaxed);
    }

    async fn on_stream_closed(&mut self, _: u32, _: End) {
        self.seen.closed.notify_one();
    }
}

async fn ready_input_stream(abort_at: Option<u64>) -> (OnionStream, Arc<ReadyInputObservations>) {
    let cfg = Config {
        init_rto_ms: 30,
        min_rto_ms: 30,
        max_rto_ms: 60,
        max_retransmits: 100,
        rack: true, // Repeated dup-ACKs alone must not repair the dropped DATA.
        ..Config::default()
    };
    let seen = Arc::new(ReadyInputObservations::default());
    let carrier = ReadyInputCarrier {
        peer: StreamEngine::accept(41, cfg, 0, 500),
        replies: VecDeque::new(),
        seen: seen.clone(),
        abort_at,
    };
    let stream = OnionStream::connect(carrier, cfg, 41, 100);
    *seen.abort.lock().unwrap() = Some(stream.abort_handle());
    stream.write_all(&[0x6a; 16]).await.unwrap();
    (stream, seen)
}

#[tokio::test]
async fn ready_inbound_backlog_cannot_starve_a_due_data_rto() {
    let (_stream, seen) = ready_input_stream(None).await;
    tokio::time::timeout(Duration::from_secs(2), seen.closed.notified())
        .await
        .unwrap();
    assert!(
        seen.rtos.load(Ordering::Relaxed) > 0,
        "ready input hid every due timeout"
    );
    assert!(
        seen.data_sends.load(Ordering::Relaxed) > 1,
        "the lost segment was never repaired"
    );
}

#[tokio::test]
async fn local_abort_stays_ahead_of_a_ready_inbound_backlog() {
    let (stream, seen) = ready_input_stream(Some(8)).await;
    tokio::time::timeout(Duration::from_secs(2), seen.closed.notified())
        .await
        .unwrap();
    assert_eq!(stream.end_reason(), End::Reset(reset_reason::APP));
    assert_eq!(seen.reads.load(Ordering::Relaxed), 8);
}

#[tokio::test]
async fn ready_inbound_backlog_cannot_starve_a_later_app_write() {
    let (stream, seen) = ready_input_stream(None).await;
    let (_reader, writer) = stream.into_split();
    let observed = seen.clone();
    // A separate app/FFI thread writes after inbound is already continuously
    // ready. Keeping the original Tokio executor busy must not hide this work.
    let app = std::thread::spawn(move || {
        let began = std::time::Instant::now();
        while observed.reads.load(Ordering::Relaxed) < 8 {
            assert!(began.elapsed() < Duration::from_secs(1));
            std::thread::sleep(Duration::from_millis(1));
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(writer.write_all(&[0x7b; 16]))
            .unwrap();
    });
    tokio::time::timeout(Duration::from_secs(2), seen.closed.notified())
        .await
        .unwrap();
    app.join().unwrap();
    assert!(seen.later_write_sends.load(Ordering::Relaxed) > 0);
}
