//! A delayed original can arrive while its repair is blocked locally.
use std::{
    io,
    sync::{Arc, Mutex},
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
    repair_attempts: Mutex<usize>,
    received: Mutex<Vec<u8>>,
    complete: Notify,
    closed: Notify,
}

struct DelayedOriginal {
    peer: StreamEngine,
    base: Instant,
    original: Option<Vec<u8>>,
    seen_head: bool,
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    obs: Arc<Observations>,
}

impl CellDuplex for DelayedOriginal {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        let now = self.base.elapsed().as_millis() as u64;
        let mut block = false;
        let delivered = if matches!(Frame::decode(cell), Some(Frame::Data { seq: 101, .. })) {
            if !self.seen_head {
                self.seen_head = true;
                self.original = Some(cell.to_vec());
                return Ok(()); // accepted by carrier, delayed in the network
            }
            *self.obs.repair_attempts.lock().unwrap() += 1;
            block = true;
            self.original.take()
        } else {
            Some(cell.to_vec())
        };
        if let Some(delivered) = delivered {
            self.peer.on_cell(&delivered, now);
        }
        let mut bytes = [0; 1024];
        loop {
            let n = self.peer.read(&mut bytes);
            if n == 0 {
                break;
            }
            let mut received = self.obs.received.lock().unwrap();
            received.extend_from_slice(&bytes[..n]);
            if received.len() == 256 {
                self.obs.complete.notify_one();
            }
        }
        let mut response = Vec::new();
        while self.peer.poll_transmit(now, &mut response) {
            self.tx.try_send(response.clone()).unwrap();
        }
        if block {
            Err(send_backpressure(Duration::from_millis(10)))
        } else {
            Ok(())
        }
    }
    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.rx.recv().await)
    }
    async fn on_stream_closed(&mut self, _: u32, _: End) {
        self.obs.closed.notify_one();
    }
}

#[tokio::test(start_paused = true)]
async fn driver_drops_blocked_repair_after_delayed_original_is_acknowledged() {
    let cfg = Config {
        mss: 64,
        init_cwnd: 256,
        recv_window: 4096,
        init_rto_ms: 100,
        min_rto_ms: 100,
        ack_every: 1,
        ack_delay_ms: 1,
        ..Config::default()
    };
    let (tx, rx) = mpsc::channel(64);
    let obs = Arc::new(Observations::default());
    let carrier = DelayedOriginal {
        peer: StreamEngine::accept(11, cfg, 0, 500),
        base: Instant::now(),
        original: None,
        seen_head: false,
        tx,
        rx,
        obs: obs.clone(),
    };
    let stream = OnionStream::connect(carrier, cfg, 11, 100);
    let expected = vec![0x39; 256];
    stream.write_all(&expected).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), obs.complete.notified())
        .await
        .unwrap();
    // Let ACK processing and several carrier retry opportunities run.
    tokio::time::sleep(Duration::from_millis(100)).await;
    stream
        .reset(veil_onion_stream::wire::reset_reason::APP)
        .await;
    tokio::time::timeout(Duration::from_secs(1), obs.closed.notified())
        .await
        .unwrap();
    assert_eq!(*obs.received.lock().unwrap(), expected);
    assert_eq!(
        *obs.repair_attempts.lock().unwrap(),
        1,
        "an ACKed repair was still offered to the carrier"
    );
}
