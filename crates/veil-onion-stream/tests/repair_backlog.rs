//! Network repair must not wait for an entire locally unaccepted DATA tail.
use std::{
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
    CellDuplex, Config, End, Frame, OnionStream, StreamEngine, send_backpressure,
};

#[derive(Default)]
struct Observations {
    bytes: Mutex<Vec<u8>>,
    first_byte_ms: Mutex<Option<u64>>,
    repair_ms: Mutex<Option<u64>>,
    reply_queued_ms: Mutex<Option<u64>>,
    reply_acked_ms: Mutex<Option<u64>>,
    rtos: AtomicU64,
    first_byte: Notify,
    complete: Notify,
    closed: Notify,
}

struct PacedLossCarrier {
    peer: StreamEngine,
    base: Instant,
    next_data_at: Instant,
    lose_head: bool,
    head_seen: bool,
    drop_gap_acks: bool,
    reverse_reply: bool,
    replied: bool,
    expected: usize,
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    observations: Arc<Observations>,
}

impl CellDuplex for PacedLossCarrier {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        let now = self.base.elapsed().as_millis() as u64;
        // SYN_ACK consumes no sequence number on the accepting endpoint.
        if let Some(Frame::Ack { ack: 904, .. }) = Frame::decode(cell) {
            self.observations
                .reply_acked_ms
                .lock()
                .unwrap()
                .get_or_insert(now);
        }
        if let Some(Frame::Data { seq, .. }) = Frame::decode(cell) {
            // Every DATA, repair included, pays the SAME admission budget.
            // This models a periodically available first-hop queue credit.
            if Instant::now() < self.next_data_at {
                return Err(send_backpressure(Duration::from_millis(10)));
            }
            self.next_data_at = Instant::now() + Duration::from_millis(50);
            if seq == 101 {
                if !self.head_seen {
                    self.head_seen = true;
                    if self.lose_head {
                        return Ok(());
                    }
                } else if self.lose_head {
                    self.observations
                        .repair_ms
                        .lock()
                        .unwrap()
                        .get_or_insert(now);
                }
            }
        }
        self.peer.on_cell(cell, now);
        let mut bytes = [0; 4096];
        loop {
            let count = self.peer.read(&mut bytes);
            if count == 0 {
                break;
            }
            let mut received = self.observations.bytes.lock().unwrap();
            received.extend_from_slice(&bytes[..count]);
            if self.observations.first_byte_ms.lock().unwrap().is_none() {
                *self.observations.first_byte_ms.lock().unwrap() = Some(now);
                self.observations.first_byte.notify_one();
            }
            if received.len() == self.expected {
                self.observations.complete.notify_one();
            }
        }
        let mut response = Vec::new();
        if self.reverse_reply && self.head_seen && !self.replied {
            assert_eq!(self.peer.write(b"back"), 4);
            self.replied = true;
            *self.observations.reply_queued_ms.lock().unwrap() = Some(now);
        }
        while self.peer.poll_transmit(now, &mut response) {
            if self.drop_gap_acks
                && self.head_seen
                && self.observations.bytes.lock().unwrap().is_empty()
                && matches!(Frame::decode(&response), Some(Frame::Ack { .. }))
            {
                continue;
            }
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
    async fn on_data_rto(&mut self, _: u32, _: u32, _: u32) {
        self.observations.rtos.fetch_add(1, Ordering::Relaxed);
    }
}

async fn exercise(lose_head: bool, rack: bool, drop_gap_acks: bool, reverse_reply: bool) {
    let config = Config {
        mss: 512,
        init_cwnd: 32 * 1024,
        recv_window: 128 * 1024,
        init_rto_ms: 120,
        min_rto_ms: 120,
        max_rto_ms: 1000,
        max_retransmits: 32,
        max_pacing_batch: 64,
        ack_every: 1,
        ack_delay_ms: 1,
        rack,
        rto_rewind_no_sack: drop_gap_acks,
        ..Config::default()
    };
    let observations = Arc::new(Observations::default());
    let bytes: Vec<u8> = (0..32 * 1024).map(|index| (index * 31) as u8).collect();
    let (tx, rx) = mpsc::channel(1024);
    let carrier = PacedLossCarrier {
        peer: StreamEngine::accept(19, config, 0, 900),
        base: Instant::now(),
        next_data_at: Instant::now(),
        lose_head,
        head_seen: false,
        drop_gap_acks,
        reverse_reply,
        replied: false,
        expected: bytes.len(),
        tx,
        rx,
        observations: observations.clone(),
    };
    let stream = OnionStream::connect(carrier, config, 19, 100);
    stream.write_all(&bytes).await.unwrap();
    let prefix = tokio::time::timeout(
        Duration::from_millis(500),
        observations.first_byte.notified(),
    )
    .await;
    let completed =
        tokio::time::timeout(Duration::from_secs(20), observations.complete.notified()).await;
    stream
        .reset(veil_onion_stream::wire::reset_reason::APP)
        .await;
    tokio::time::timeout(Duration::from_millis(50), observations.closed.notified())
        .await
        .unwrap();
    println!(
        "paced backlog loss={lose_head} rack={rack} first_byte_ms={:?} repair_ms={:?}",
        observations.first_byte_ms.lock().unwrap(),
        observations.repair_ms.lock().unwrap()
    );
    if drop_gap_acks {
        assert!(
            observations.rtos.load(Ordering::Relaxed) > 0,
            "fixture did not require RTO repair"
        );
    }
    if reverse_reply {
        let queued = observations.reply_queued_ms.lock().unwrap().unwrap();
        let acked = observations
            .reply_acked_ms
            .lock()
            .unwrap()
            .expect("reverse DATA never ACKed");
        assert!(
            acked - queued < 50,
            "reverse ACK waited behind the local DATA tail"
        );
    }
    assert!(completed.is_ok(), "paced stream did not complete");
    assert_eq!(
        *observations.bytes.lock().unwrap(),
        bytes,
        "lost, duplicated or reordered bytes"
    );
    assert!(
        prefix.is_ok(),
        "first-byte repair waited behind the locally blocked DATA tail"
    );
}

#[tokio::test(start_paused = true)]
async fn lost_head_repair_precedes_a_locally_backpressured_tail() {
    for rack in [false, true] {
        exercise(true, rack, false, false).await;
    }
}

#[tokio::test(start_paused = true)]
async fn no_loss_control_keeps_the_same_local_admission_budget() {
    for rack in [false, true] {
        exercise(false, rack, false, false).await;
    }
}

#[tokio::test(start_paused = true)]
async fn rto_head_repair_precedes_the_tail_without_sack_feedback() {
    for rack in [false, true] {
        exercise(true, rack, true, false).await;
    }
}

#[tokio::test(start_paused = true)]
async fn reverse_ack_precedes_locally_backpressured_data() {
    for rack in [false, true] {
        exercise(false, rack, false, true).await;
    }
}
