//! Synthetic mux/handshake fault tests.
//!
//! These are intentionally below Flutter/UI and below the real relay stack:
//! they give us a fast, deterministic regression net for the class of failure
//! seen on-device where a bulk stream dies, retries open fresh stream ids, and
//! the handshake path must recover instead of spinning in reset/SYN_SENT loops.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use veil_onion_stream::wire::reset_reason;
use veil_onion_stream::{Addr, CellSender, Config, Frame, OnionStream, StreamMux};

type Peer = [u8; 32];
type InboundTx = mpsc::Sender<(Addr, Vec<u8>)>;

#[derive(Default)]
struct Faults {
    drop_synack_b_to_a: bool,
    drop_all_b_to_a: bool,
    dropped_synacks: usize,
    dropped_b_to_a: usize,
}

struct Bus {
    a: Peer,
    b: Peer,
    routes: Mutex<HashMap<Peer, InboundTx>>,
    faults: Mutex<Faults>,
}

impl Bus {
    fn new(a: Peer, b: Peer) -> Arc<Self> {
        Arc::new(Self {
            a,
            b,
            routes: Mutex::new(HashMap::new()),
            faults: Mutex::new(Faults::default()),
        })
    }

    fn register(&self, peer: Peer, tx: InboundTx) {
        self.routes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(peer, tx);
    }

    fn set_drop_synack_b_to_a(&self, enabled: bool) {
        self.faults
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drop_synack_b_to_a = enabled;
    }

    fn set_drop_all_b_to_a(&self, enabled: bool) {
        self.faults
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drop_all_b_to_a = enabled;
    }

    fn dropped_synacks(&self) -> usize {
        self.faults
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .dropped_synacks
    }

    fn dropped_b_to_a(&self) -> usize {
        self.faults
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .dropped_b_to_a
    }
}

struct BusSender {
    bus: Arc<Bus>,
    me: Addr,
}

impl CellSender for BusSender {
    async fn send(&self, dst: Addr, cell: Vec<u8>) -> io::Result<()> {
        let b_to_a = self.me.node == self.bus.b && dst.node == self.bus.a;
        if b_to_a {
            let frame = Frame::decode(&cell);
            let mut faults = self.bus.faults.lock().unwrap_or_else(|p| p.into_inner());
            if faults.drop_all_b_to_a {
                faults.dropped_b_to_a += 1;
                if matches!(frame, Some(Frame::SynAck { .. })) {
                    faults.dropped_synacks += 1;
                }
                return Ok(());
            }
            if faults.drop_synack_b_to_a && matches!(frame, Some(Frame::SynAck { .. })) {
                faults.dropped_b_to_a += 1;
                faults.dropped_synacks += 1;
                return Ok(());
            }
        }

        let tx = self
            .bus
            .routes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&dst.node)
            .cloned();
        if let Some(tx) = tx {
            let _ = tx.try_send((self.me, cell));
        }
        Ok(())
    }
}

fn addr(byte: u8) -> Addr {
    Addr {
        node: [byte; 32],
        app: [byte ^ 0xa5; 32],
    }
}

fn fast_cfg() -> Config {
    Config {
        handshake_rto_ms: 100,
        init_rto_ms: 100,
        min_rto_ms: 50,
        max_rto_ms: 1_000,
        max_retransmits: 2,
        ..Config::default()
    }
}

fn mux_pair() -> (
    Arc<Bus>,
    StreamMux<BusSender>,
    StreamMux<BusSender>,
    Addr,
    Addr,
) {
    let a = addr(0xa1);
    let b = addr(0xb2);
    let bus = Bus::new(a.node, b.node);
    let (a_tx, a_rx) = mpsc::channel(4096);
    let (b_tx, b_rx) = mpsc::channel(4096);
    bus.register(a.node, a_tx);
    bus.register(b.node, b_tx);

    let cfg = fast_cfg();
    let mux_a = StreamMux::new(
        a.node,
        Arc::new(BusSender {
            bus: Arc::clone(&bus),
            me: a,
        }),
        a_rx,
        cfg,
    );
    let mux_b = StreamMux::new(
        b.node,
        Arc::new(BusSender {
            bus: Arc::clone(&bus),
            me: b,
        }),
        b_rx,
        cfg,
    );
    (bus, mux_a, mux_b, a, b)
}

async fn read_to_end(stream: &mut OnionStream) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buf[..n]);
    }
}

async fn read_exact(stream: &mut OnionStream, n: usize) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(n);
    let mut buf = vec![0u8; n.max(1)];
    while out.len() < n {
        let want = n - out.len();
        let got = stream.read(&mut buf[..want]).await?;
        if got == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "stream ended before enough bytes arrived",
            ));
        }
        out.extend_from_slice(&buf[..got]);
    }
    Ok(out)
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn fresh_stream_recovers_after_synack_blackhole() {
    let (bus, mux_a, mux_b, _a, b) = mux_pair();
    bus.set_drop_synack_b_to_a(true);

    let mut first = mux_a.open(b);
    let first_accept = tokio::time::timeout(Duration::from_secs(1), mux_b.accept())
        .await
        .expect("B should see the first SYN")
        .expect("accept queue open");
    drop(first_accept);

    let err = tokio::time::timeout(Duration::from_secs(2), first.read(&mut [0u8; 1]))
        .await
        .expect("the first stream should time out under SYN_ACK loss")
        .expect_err("SYN_ACK blackhole must surface as reset, not EOF");
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    assert!(
        bus.dropped_synacks() > 0,
        "fault did not actually drop any SYN_ACK frames"
    );

    bus.set_drop_synack_b_to_a(false);
    let mut second = mux_a.open(b);
    let (accepted, src) = tokio::time::timeout(Duration::from_secs(1), mux_b.accept())
        .await
        .expect("B should see the retry SYN")
        .expect("accept queue open");
    assert_eq!(src.node, addr(0xa1).node);
    tokio::spawn(async move {
        accepted.write_all(b"retry-ok").await.unwrap();
        accepted.finish().await.unwrap();
    });

    let got = tokio::time::timeout(Duration::from_secs(2), read_to_end(&mut second))
        .await
        .expect("second stream should complete")
        .expect("second stream should not reset");
    assert_eq!(got, b"retry-ok");
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn fresh_stream_recovers_after_previous_stream_reset() {
    let (_bus, mux_a, mux_b, _a, b) = mux_pair();

    let mut first = mux_a.open(b);
    let (accepted, src) = tokio::time::timeout(Duration::from_secs(1), mux_b.accept())
        .await
        .expect("B should see the first SYN")
        .expect("accept queue open");
    assert_eq!(src.node, addr(0xa1).node);

    let (reset_tx, reset_rx) = oneshot::channel();
    let server = tokio::spawn(async move {
        accepted.write_all(b"partial-before-reset").await.unwrap();
        let _ = reset_rx.await;
        accepted.reset(reset_reason::APP).await;
    });

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(1), first.read(&mut buf))
        .await
        .expect("first stream should deliver some payload before reset")
        .expect("first stream read should not reset before payload");
    assert_eq!(&buf[..n], b"partial-before-reset");

    let _ = reset_tx.send(());
    let err = tokio::time::timeout(Duration::from_secs(1), read_to_end(&mut first))
        .await
        .expect("first stream reset should surface promptly")
        .expect_err("first stream must reset, not EOF");
    assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
    server.await.unwrap();

    let mut second = mux_a.open(b);
    let (accepted, src) = tokio::time::timeout(Duration::from_secs(1), mux_b.accept())
        .await
        .expect("B should see a fresh SYN after the reset")
        .expect("accept queue open");
    assert_eq!(src.node, addr(0xa1).node);
    tokio::spawn(async move {
        accepted.write_all(b"after-reset-ok").await.unwrap();
        accepted.finish().await.unwrap();
    });

    let got = tokio::time::timeout(Duration::from_secs(2), read_to_end(&mut second))
        .await
        .expect("second stream should complete")
        .expect("second stream should not inherit the previous reset");
    assert_eq!(got, b"after-reset-ok");
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn fresh_stream_recovers_after_midstream_return_blackhole() {
    let (bus, mux_a, mux_b, _a, b) = mux_pair();

    let mut first = mux_a.open(b);
    let (accepted, _src) = tokio::time::timeout(Duration::from_secs(1), mux_b.accept())
        .await
        .expect("B should accept the first stream")
        .expect("accept queue open");

    accepted.write_all(b"prefix").await.unwrap();
    let prefix = tokio::time::timeout(Duration::from_secs(1), read_exact(&mut first, 6))
        .await
        .expect("prefix should arrive before the fault")
        .expect("first stream should be healthy before the fault");
    assert_eq!(prefix, b"prefix");

    bus.set_drop_all_b_to_a(true);
    accepted.write_all(b"-this-tail-is-blackholed").await.unwrap();
    accepted.finish().await.unwrap();
    let stalled = tokio::time::timeout(Duration::from_millis(500), first.read(&mut [0u8; 8])).await;
    assert!(
        stalled.is_err(),
        "receive-only side should stall under a return-path blackhole; app-level idle timeout resumes it"
    );
    assert!(
        bus.dropped_b_to_a() > 0,
        "fault did not actually drop return-path frames"
    );

    // The application would abandon the old stream after its payload-idle
    // timeout, then open a fresh retry stream. Once the transport path recovers,
    // the old half-open route must not poison new handshakes or stream ids.
    drop(first);
    bus.set_drop_all_b_to_a(false);

    let mut second = mux_a.open(b);
    let (accepted, _src) = tokio::time::timeout(Duration::from_secs(1), mux_b.accept())
        .await
        .expect("B should accept the retry stream")
        .expect("accept queue open");
    tokio::spawn(async move {
        accepted.write_all(b"after-blackhole").await.unwrap();
        accepted.finish().await.unwrap();
    });

    let got = tokio::time::timeout(Duration::from_secs(2), read_to_end(&mut second))
        .await
        .expect("retry stream should complete after path recovery")
        .expect("retry stream should not reset");
    assert_eq!(got, b"after-blackhole");
}
