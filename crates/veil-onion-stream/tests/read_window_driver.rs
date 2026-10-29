//! A reader freeing a full delivery channel must wake the async driver and
//! reopen its advertised window without waiting for the sender's persist probe.
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Notify, mpsc};
use veil_onion_stream::{CellDuplex, Config, End, Frame, OnionStream};

#[derive(Default)]
struct Observations {
    acks: Vec<(u32, u32)>,
    closed: usize,
}

#[derive(Default)]
struct Witness {
    state: Mutex<Observations>,
    changed: Notify,
}

struct Carrier {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    record_ack: bool,
    witness: Arc<Witness>,
}

impl CellDuplex for Carrier {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        self.tx
            .try_send(cell.to_vec())
            .map_err(|e| io::Error::new(io::ErrorKind::WouldBlock, e))?;
        if self.record_ack
            && let Some(Frame::Ack { ack, win, .. }) = Frame::decode(cell)
        {
            self.witness.state.lock().unwrap().acks.push((ack, win));
            self.witness.changed.notify_one();
        }
        Ok(())
    }

    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.rx.recv().await)
    }

    async fn on_stream_closed(&mut self, _: u32, _: End) {
        self.witness.state.lock().unwrap().closed += 1;
        self.witness.changed.notify_one();
    }
}

async fn next_ack(witness: &Witness, cursor: &mut usize) -> (u32, u32) {
    loop {
        let changed = witness.changed.notified();
        if let Some(ack) = witness.state.lock().unwrap().acks.get(*cursor).copied() {
            *cursor += 1;
            return ack;
        }
        changed.await;
    }
}

#[tokio::test(start_paused = true)]
async fn resumed_reader_reopens_window_before_any_probe_and_both_drivers_exit() {
    // This timeout is a virtual-clock watchdog, not the latency assertion.
    tokio::time::timeout(Duration::from_secs(60), async {
        let (a_tx, b_rx) = mpsc::channel(128);
        let (b_tx, a_rx) = mpsc::channel(128);
        let witness = Arc::new(Witness::default());
        let cfg = Config {
            mss: 16,
            recv_window: 32,
            init_cwnd: 64,
            ack_every: 1,
            init_rto_ms: 10_000,
            min_rto_ms: 10_000,
            max_rto_ms: 10_000,
            ..Config::default()
        };
        let sender = OnionStream::connect(
            Carrier {
                tx: a_tx,
                rx: a_rx,
                record_ack: false,
                witness: witness.clone(),
            },
            cfg,
            7,
            100,
        );
        let mut receiver = OnionStream::accept(
            Carrier {
                tx: b_tx,
                rx: b_rx,
                record_ack: true,
                witness: witness.clone(),
            },
            cfg,
            7,
            500,
        );
        let payload: Vec<u8> = (0..4096).map(|i| (i ^ (i >> 8)) as u8).collect();
        sender.write_all(&payload).await.unwrap();
        sender.finish().await.unwrap();
        let mut cursor = 0;
        let zero_ack = loop {
            let (ack, win) = next_ack(&witness, &mut cursor).await;
            if win == 0 {
                break ack;
            }
        };
        // The receiving driver has filled its 16 app-channel slots and its
        // engine buffer. Freeing a slot must exercise reserve()->engine.read().
        let before = tokio::time::Instant::now();
        let mut first = [0];
        assert_eq!(receiver.read(&mut first).await.unwrap(), 1);
        let reopened_ack = loop {
            let (ack, win) = next_ack(&witness, &mut cursor).await;
            if win > 0 {
                break ack;
            }
        };
        eprintln!(
            "read_resume_virtual_ms={} ack_progress_before_reopen={}",
            (tokio::time::Instant::now() - before).as_millis(),
            reopened_ack.wrapping_sub(zero_ack),
        );
        assert_eq!(
            reopened_ack, zero_ack,
            "window reopened only after new DATA/probe"
        );
        assert_eq!(
            tokio::time::Instant::now(),
            before,
            "read waited for a protocol timer"
        );
        let mut received = Vec::from(first);
        let mut buf = [0; 256];
        loop {
            let n = receiver.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        assert_eq!(received, payload);
        // Retain both handles until close, proving teardown rather than
        // relying on the test runtime to cancel orphaned driver tasks.
        loop {
            let changed = witness.changed.notified();
            if witness.state.lock().unwrap().closed == 2 {
                break;
            }
            changed.await;
        }
        drop(sender);
        drop(receiver);
    })
    .await
    .expect("driver flow-control watchdog expired");
}
