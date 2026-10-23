//! A SACKed tail must not strand multiple lost retransmissions behind one RTO
//! per hole. Exercise the real driver, local handoff and receiver reassembly.
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;
use veil_onion_stream::{CellDuplex, Config, Frame, OnionStream, StreamEngine};

#[derive(Default)]
struct Observed {
    sends: Mutex<HashMap<u32, u32>>,
    bytes: Mutex<Vec<u8>>,
    lost_repairs: Notify,
    prefix_received: Notify,
    complete: Notify,
}

struct RepeatedLossPeer {
    engine: StreamEngine,
    base: Instant,
    first_data: u32,
    obs: Arc<Observed>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    staggered: bool,
}

impl CellDuplex for RepeatedLossPeer {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        if matches!(Frame::decode(cell), Some(Frame::Syn { .. })) {
            // Make the original DATA timestamps nonzero, as required by the
            // RACK frontier's unset sentinel. Later carrier admissions are
            // immediate: cells from one actual driver burst share a handoff.
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        if let Some(Frame::Data { seq, payload, .. }) = Frame::decode(cell) {
            if self.staggered {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(payload.len(), 16);
            let offset = seq.wrapping_sub(self.first_data);
            let drop = {
                let mut sends = self.obs.sends.lock().unwrap();
                let count = sends.entry(offset).or_default();
                *count += 1;
                let drop = offset < 48 && *count <= 2;
                if [0, 16, 32].iter().all(|k| sends.get(k) == Some(&2)) {
                    self.obs.lost_repairs.notify_one();
                }
                drop
            };
            if drop {
                return Ok(()); // accepted locally, lost on the network
            }
        }
        let now = self.base.elapsed().as_millis() as u64;
        self.engine.on_cell(cell, now);
        let mut buf = [0; 128];
        let n = self.engine.read(&mut buf);
        if n > 0 {
            let mut bytes = self.obs.bytes.lock().unwrap();
            bytes.extend_from_slice(&buf[..n]);
            if self.staggered && bytes.len() == 16 {
                self.obs.prefix_received.notify_one();
            }
            if bytes.len() == if self.staggered { 144 } else { 128 } {
                self.obs.complete.notify_one();
            }
        }
        let mut reply = Vec::new();
        while self.engine.poll_transmit(now, &mut reply) {
            self.tx.send(reply.clone()).unwrap();
        }
        Ok(())
    }

    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.rx.recv().await)
    }
}

async fn repair_lost_retransmissions(rack: bool, staggered: bool) {
    for iss in [100u32, u32::MAX - 32] {
        let config = Config {
            mss: 16,
            init_cwnd: 128,
            recv_window: 4096,
            init_rto_ms: 100,
            min_rto_ms: 100,
            max_rto_ms: 1000,
            max_pacing_batch: if staggered { 1 } else { 4 },
            rto_rewind_no_sack: true,
            rack,
            ack_every: 1,
            ..Config::default()
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let obs = Arc::new(Observed::default());
        let peer = RepeatedLossPeer {
            engine: StreamEngine::accept(7, config, 0, 500),
            base: Instant::now(),
            first_data: iss.wrapping_add(if staggered { 17 } else { 1 }),
            obs: obs.clone(),
            tx,
            rx,
            staggered,
        };
        let stream = OnionStream::connect(peer, config, 7, iss);
        let payload: Vec<_> = (0..128).map(|n| n as u8).collect();
        let mut expected = Vec::new();
        if staggered {
            // An acknowledged prefix warms RTT/pacing before the lossy flight,
            // so each repair is admitted in a separate one-cell pacing tick.
            stream.write_all(&[0xAA; 16]).await.unwrap();
            tokio::time::timeout(Duration::from_millis(20), obs.prefix_received.notified())
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(1)).await;
            expected.extend_from_slice(&[0xAA; 16]);
        }
        stream.write_all(&payload).await.unwrap();
        tokio::time::timeout(Duration::from_millis(80), obs.lost_repairs.notified())
            .await
            .expect("fixture did not lose all three fast/RACK repairs");
        // One 100ms RTO plus paced repairs fits here. An additional backed-off
        // 200ms RTO per lost repair does not. Virtual time keeps this instant.
        let result =
            tokio::time::timeout(Duration::from_millis(150), obs.complete.notified()).await;
        stream
            .reset(veil_onion_stream::wire::reset_reason::APP)
            .await;
        result.expect("SACK recovery waited another backed-off RTO for each lost repair");
        expected.extend_from_slice(&payload);
        assert_eq!(*obs.bytes.lock().unwrap(), expected);
        let sends = obs.sends.lock().unwrap();
        for offset in [0, 16, 32] {
            assert_eq!(
                sends.get(&offset),
                Some(&3),
                "lost repair not retried exactly once"
            );
        }
        for offset in [48, 64, 80, 96, 112] {
            assert_eq!(sends.get(&offset), Some(&1), "SACKed tail was replayed");
        }
    }
}

#[tokio::test(start_paused = true)]
async fn sack_count_recovery_repairs_multiple_lost_retransmissions_in_one_rto() {
    repair_lost_retransmissions(false, false).await;
}

#[tokio::test(start_paused = true)]
async fn rack_recovery_repairs_multiple_lost_retransmissions_in_one_rto() {
    repair_lost_retransmissions(true, false).await;
}

#[tokio::test(start_paused = true)]
async fn staggered_sack_repairs_do_not_inherit_the_oldest_holes_rto_backoff() {
    repair_lost_retransmissions(false, true).await;
}

#[tokio::test(start_paused = true)]
async fn staggered_rack_repairs_do_not_inherit_the_oldest_holes_rto_backoff() {
    repair_lost_retransmissions(true, true).await;
}
