//! Async end-to-end test: two [`OnionStream`]s over an in-memory lossy
//! [`CellDuplex`] pair, on tokio's paused (auto-advancing) virtual clock so the
//! full RTO/retransmit timeline runs instantly + deterministically.

use std::io;

use tokio::sync::mpsc;

use veil_onion_stream::driver::CellDuplex;
use veil_onion_stream::{Config, OnionStream};

/// SplitMix64 — deterministic, no external dep.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// One end of an in-memory cell pipe; drops a fraction of sent cells.
struct MemDuplex {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
    loss: f64,
    rng: Rng,
}

impl CellDuplex for MemDuplex {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        if self.rng.unit() >= self.loss {
            // Lossy but never blocks the protocol: if the buffer is full, drop
            // (the ARQ recovers) rather than apply backpressure.
            let _ = self.tx.try_send(cell.to_vec());
        }
        Ok(())
    }
    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.rx.recv().await)
    }
}

fn duplex_pair(loss: f64, seed: u64) -> (MemDuplex, MemDuplex) {
    let (a_tx, b_rx) = mpsc::channel(4096);
    let (b_tx, a_rx) = mpsc::channel(4096);
    (
        MemDuplex {
            tx: a_tx,
            rx: a_rx,
            loss,
            rng: Rng(seed),
        },
        MemDuplex {
            tx: b_tx,
            rx: b_rx,
            loss,
            rng: Rng(seed ^ 0xDEAD_BEEF),
        },
    )
}

fn payload(n: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng(seed);
    (0..n).map(|_| (r.next_u64() & 0xff) as u8).collect()
}

async fn read_to_end(s: &mut OnionStream) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 9000];
    loop {
        let n = s.read(&mut buf).await?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n]);
    }
}

async fn transfer(loss: f64, n: usize, seed: u64) -> Vec<u8> {
    let (da, db) = duplex_pair(loss, seed);
    let cfg = Config::default();
    let sender = OnionStream::connect(da, cfg, 1, 1000);
    let mut receiver = OnionStream::accept(db, cfg, 1, 7000);

    let data = payload(n, seed ^ 0x1234);
    let send_data = data.clone();
    let send = tokio::spawn(async move {
        sender.write_all(&send_data).await.unwrap();
        sender.finish().await.unwrap();
        // Drain the (empty) reverse direction so the sender closes cleanly.
        sender
    });

    let got = read_to_end(&mut receiver).await.expect("read");
    // The driver auto-closes the receiver's empty write half on EOF, so the
    // sender ends cleanly without an explicit receiver.finish() here.
    let _sender = send.await.unwrap();
    assert_eq!(got, data, "byte mismatch (loss={loss}, n={n})");
    got
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn async_clean_transfer() {
    let got = transfer(0.0, 120_000, 1).await;
    assert_eq!(got.len(), 120_000);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn async_lossy_transfer_completes_intact() {
    transfer(0.12, 80_000, 2).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn async_heavy_loss_transfer_completes_intact() {
    transfer(0.30, 40_000, 3).await;
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn async_reset_surfaces_as_read_error_not_eof() {
    let (da, db) = duplex_pair(0.0, 5);
    let cfg = Config::default();
    let sender = OnionStream::connect(da, cfg, 9, 1000);
    let mut receiver = OnionStream::accept(db, cfg, 9, 7000);

    sender.write_all(b"hello, partial transfer").await.unwrap();
    // Let it arrive.
    let mut buf = [0u8; 64];
    let n = receiver.read(&mut buf).await.unwrap();
    assert!(n > 0);

    // Abort mid-stream — the receiver must see an error, NOT a clean EOF.
    sender
        .reset(veil_onion_stream::wire::reset_reason::APP)
        .await;
    let err = read_to_end(&mut receiver).await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
}
