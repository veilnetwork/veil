//! The carrier, unlike the peer/network, may reject a cell before any handoff.
use std::io;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;
use veil_onion_stream::{
    CellDuplex, Config, End, Frame, OnionStream, StreamEngine, send_backpressure,
};

#[derive(Default)]
struct Observations {
    ready: AtomicBool,
    accepted: AtomicU64,
    rtos: AtomicU64,
    bytes: Mutex<Vec<u8>>,
    blocked: Notify,
    complete: Notify,
    closed: Notify,
}

struct Carrier {
    peer: StreamEngine,
    base: Instant,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    observations: Arc<Observations>,
    // A positive limit admits that many packets, then blocks locally. The
    // first admitted DATA can independently be lost in the network.
    initially_accepted: u64,
    lose_first: bool,
    expected_bytes: usize,
    striped: bool,
}

impl CellDuplex for Carrier {
    async fn send_cell(&mut self, bytes: &[u8]) -> io::Result<()> {
        if let Some(Frame::Data { seq, .. }) = Frame::decode(bytes) {
            let accepted = self.observations.accepted.load(Ordering::Relaxed);
            if !self.observations.ready.load(Ordering::Acquire)
                && accepted >= self.initially_accepted
                && (!self.striped || seq == 101)
            {
                self.observations.blocked.notify_one();
                return Err(send_backpressure(Duration::from_millis(10)));
            }
            self.observations.accepted.fetch_add(1, Ordering::Relaxed);
            if self.lose_first && accepted == 0 {
                return Ok(()); // actual handoff followed by network loss
            }
        }
        let now = self.base.elapsed().as_millis() as u64;
        self.peer.on_cell(bytes, now);
        let mut chunk = [0; 1024];
        loop {
            let n = self.peer.read(&mut chunk);
            if n == 0 {
                break;
            }
            let mut received = self.observations.bytes.lock().unwrap();
            received.extend_from_slice(&chunk[..n]);
            if received.len() >= self.expected_bytes {
                self.observations.complete.notify_one();
            }
        }
        let mut reply = Vec::new();
        while self.peer.poll_transmit(now, &mut reply) {
            self.inbound_tx.try_send(reply.clone()).unwrap();
        }
        Ok(())
    }
    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.inbound_rx.recv().await)
    }
    async fn send_cells(
        &mut self,
        cells: &mut std::collections::VecDeque<Vec<u8>>,
    ) -> io::Result<()> {
        if !self.striped {
            while let Some(cell) = cells.front() {
                self.send_cell(cell).await?;
                cells.pop_front();
            }
            return Ok(());
        }
        // A real striped carrier may accept later cells while one first hop
        // rejects the head. Accepted cells are not necessarily a FIFO prefix.
        let mut retained = std::collections::VecDeque::new();
        while let Some(cell) = cells.pop_front() {
            if let Err(error) = self.send_cell(&cell).await {
                assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                retained.push_back(cell);
            }
        }
        *cells = retained;
        if cells.is_empty() {
            Ok(())
        } else {
            Err(send_backpressure(Duration::from_millis(10)))
        }
    }
    async fn on_data_rto(&mut self, _: u32, _: u32, _: u32) {
        self.observations.rtos.fetch_add(1, Ordering::Relaxed);
    }
    async fn on_stream_closed(&mut self, _: u32, _: End) {
        self.observations.closed.notify_one();
    }
}

async fn exercise(rewind: bool, real_network_loss: bool, striped: bool, rack: bool) {
    let config = Config {
        mss: 64,
        init_cwnd: 256,
        recv_window: 4096,
        init_rto_ms: 50,
        min_rto_ms: 40,
        max_rto_ms: 1000,
        max_retransmits: 32,
        handshake_rto_ms: 6000,
        rto_rewind_no_sack: rewind,
        rack,
        bbr: true,
        ack_every: 1,
        ack_delay_ms: 1,
        ..Config::default()
    };
    let observations = Arc::new(Observations::default());
    let (inbound_tx, inbound_rx) = mpsc::channel(256);
    let mut state = 0x73ad_8241u32;
    let data: Vec<u8> = (0..256)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect();
    let carrier = Carrier {
        peer: StreamEngine::accept(11, config, 0, 500),
        base: Instant::now(),
        inbound_tx,
        inbound_rx,
        observations: observations.clone(),
        initially_accepted: u64::from(real_network_loss),
        lose_first: real_network_loss,
        expected_bytes: data.len(),
        striped,
    };
    let stream = OnionStream::connect(carrier, config, 11, 100);
    stream.write_all(&data).await.unwrap();
    tokio::time::timeout(Duration::from_millis(20), observations.blocked.notified())
        .await
        .unwrap();
    tokio::time::advance(Duration::from_millis(250)).await;
    // Let the driver's timeout event reach the carrier, without assuming the
    // relative scheduling of timer and channel futures at the same instant.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let accepted_before = observations.accepted.load(Ordering::Relaxed);
    let rtos_before = observations.rtos.load(Ordering::Relaxed);
    observations.ready.store(true, Ordering::Release);
    let completed =
        tokio::time::timeout(Duration::from_secs(2), observations.complete.notified()).await;
    stream
        .reset(veil_onion_stream::wire::reset_reason::APP)
        .await;
    tokio::time::timeout(Duration::from_millis(20), observations.closed.notified())
        .await
        .unwrap();
    assert_eq!(
        accepted_before,
        if striped {
            3
        } else {
            u64::from(real_network_loss)
        }
    );
    if real_network_loss {
        assert!(
            rtos_before > 0,
            "local queueing hid a genuine in-flight network loss"
        );
    } else {
        assert_eq!(
            rtos_before, 0,
            "RTO fired although no DATA left the local carrier"
        );
    }
    assert!(
        completed.is_ok(),
        "stream failed to recover after the carrier reopened"
    );
    assert_eq!(
        *observations.bytes.lock().unwrap(),
        data,
        "byte loss, duplication or reordering"
    );
}

#[tokio::test(start_paused = true)]
async fn locally_unaccepted_data_does_not_trigger_network_rto() {
    for rack in [false, true] {
        exercise(false, false, false, rack).await;
        exercise(true, false, false, rack).await;
    }
}

#[tokio::test(start_paused = true)]
async fn accepted_lost_head_still_times_out_while_local_tail_is_blocked() {
    for rack in [false, true] {
        exercise(false, true, false, rack).await;
        exercise(true, true, false, rack).await;
    }
}

#[tokio::test(start_paused = true)]
async fn striped_tail_handoff_does_not_turn_a_locally_blocked_head_into_loss() {
    for rack in [false, true] {
        exercise(false, false, true, rack).await;
        exercise(true, false, true, rack).await;
    }
}
