//! Multiplex many [`OnionStream`]s over ONE anonymous cell transport.
//!
//! veil's anonymous send/recv (`send_anonymous_authenticated` + inbound app
//! datagrams) is a single addressable endpoint per node. To run several streams
//! (and to accept inbound ones) over it, cells must be demultiplexed by
//! `(peer_node, stream_id)`. [`StreamMux`] owns that: it routes each inbound
//! cell to the right stream (creating an accept-side stream on a fresh inbound
//! `SYN`), and hands each stream a [`CellDuplex`] that sends via the shared
//! [`CellSender`] and receives from its own channel.
//!
//! The crate stays transport-agnostic: [`CellSender`] is the only seam veilclient
//! implements (over `AppSender`), and inbound `(peer, cell)` pairs are fed in
//! through a channel (drained from the `AppReceiver`). Everything here is unit-
//! tested against an in-memory bus.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use crate::driver::{CellDuplex, OnionStream};
use crate::engine::Config;
use crate::wire::Frame;

/// 32-byte node id of a peer.
pub type Peer = [u8; 32];

/// Sends one cell toward a peer over the anonymous transport (best-effort: a
/// drop downstream is fine, the stream's ARQ repairs it). The receive side is
/// fed to the [`StreamMux`] separately (it owns inbound demux).
pub trait CellSender: Send + Sync + 'static {
    fn send(&self, dst: Peer, cell: Vec<u8>) -> impl Future<Output = io::Result<()>> + Send;
}

/// Per-stream inbound queue depth (cells). Bounded: a slow stream drops excess
/// (ARQ recovers) rather than back-pressuring the shared demux.
const STREAM_INBOX: usize = 256;
/// Pending not-yet-accepted inbound streams.
const ACCEPT_BACKLOG: usize = 64;

type StreamKey = (Peer, u32);
type Routes = Arc<Mutex<HashMap<StreamKey, mpsc::Sender<Vec<u8>>>>>;

/// A [`CellDuplex`] for one muxed stream: sends to a fixed peer via the shared
/// sender, receives from its demux channel. Deregisters its route on drop.
struct MuxDuplex<S: CellSender> {
    sender: Arc<S>,
    peer: Peer,
    key: StreamKey,
    routes: Routes,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
}

impl<S: CellSender> CellDuplex for MuxDuplex<S> {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        self.sender.send(self.peer, cell.to_vec()).await
    }
    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.inbound_rx.recv().await)
    }
}

impl<S: CellSender> Drop for MuxDuplex<S> {
    fn drop(&mut self) {
        self.routes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.key);
    }
}

/// Multiplexes [`OnionStream`]s over one anonymous endpoint. Construct with
/// [`new`](Self::new); [`open`](Self::open) initiates, [`accept`](Self::accept)
/// receives.
pub struct StreamMux<S: CellSender> {
    me: Peer,
    sender: Arc<S>,
    cfg: Config,
    routes: Routes,
    next_id: Arc<AtomicU32>,
    accept_rx: mpsc::Receiver<(OnionStream, Peer)>,
}

impl<S: CellSender> StreamMux<S> {
    /// `me` = this node's id (used to split the stream-id space so the two
    /// directions never collide). `inbound` carries `(src_peer, cell)` drained
    /// from the anonymous receive path. Spawns the demux task.
    pub fn new(
        me: Peer,
        sender: Arc<S>,
        inbound: mpsc::Receiver<(Peer, Vec<u8>)>,
        cfg: Config,
    ) -> Self {
        let routes: Routes = Arc::new(Mutex::new(HashMap::new()));
        let (accept_tx, accept_rx) = mpsc::channel(ACCEPT_BACKLOG);
        tokio::spawn(demux(
            sender.clone(),
            inbound,
            routes.clone(),
            accept_tx,
            cfg,
        ));
        StreamMux {
            me,
            sender,
            cfg,
            routes,
            next_id: Arc::new(AtomicU32::new(1)),
            accept_rx,
        }
    }

    /// Open a new stream to `peer`. The returned [`OnionStream`] is live
    /// immediately (its SYN goes out on first poll).
    pub fn open(&self, peer: Peer) -> OnionStream {
        // Split the id space by node order so this node's opened ids never
        // collide with the peer's opened ids on either side.
        let parity = if self.me < peer { 0 } else { 1 };
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        let sid = (n << 1) | parity;
        let (tx, rx) = mpsc::channel(STREAM_INBOX);
        let key = (peer, sid);
        self.routes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key, tx);
        let duplex = MuxDuplex {
            sender: self.sender.clone(),
            peer,
            key,
            routes: self.routes.clone(),
            inbound_rx: rx,
        };
        OnionStream::connect(duplex, self.cfg, sid, initial_seq(sid))
    }

    /// Accept the next inbound stream a peer opened to us, or `None` if the
    /// transport closed.
    pub async fn accept(&mut self) -> Option<(OnionStream, Peer)> {
        self.accept_rx.recv().await
    }
}

/// Deterministic, well-spread initial sequence from the stream id (full
/// randomness isn't needed over an authenticated channel; this just avoids
/// every stream starting at 0).
fn initial_seq(sid: u32) -> u32 {
    sid.wrapping_mul(2_654_435_761) // Knuth multiplicative hash
}

async fn demux<S: CellSender>(
    sender: Arc<S>,
    mut inbound: mpsc::Receiver<(Peer, Vec<u8>)>,
    routes: Routes,
    accept_tx: mpsc::Sender<(OnionStream, Peer)>,
    cfg: Config,
) {
    while let Some((src, cell)) = inbound.recv().await {
        let Some(frame) = Frame::decode(&cell) else {
            continue; // junk
        };
        let key = (src, frame.stream_id());
        // Existing stream?
        {
            let routes_g = routes.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(tx) = routes_g.get(&key) {
                let _ = tx.try_send(cell); // full → drop, ARQ recovers
                continue;
            }
        }
        // New inbound stream — only a SYN may create one.
        if !matches!(frame, Frame::Syn { .. }) {
            continue;
        }
        let (tx, rx) = mpsc::channel(STREAM_INBOX);
        let _ = tx.try_send(cell); // deliver the SYN itself
        routes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key, tx);
        let duplex = MuxDuplex {
            sender: sender.clone(),
            peer: src,
            key,
            routes: routes.clone(),
            inbound_rx: rx,
        };
        let stream = OnionStream::accept(duplex, cfg, key.1, initial_seq(key.1));
        if accept_tx.send((stream, src)).await.is_err() {
            break; // nobody is accepting anymore
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory bus: each node's inbound-cell sink, keyed by node id.
    type Bus = Arc<Mutex<HashMap<Peer, mpsc::Sender<(Peer, Vec<u8>)>>>>;

    fn node(b: u8) -> Peer {
        [b; 32]
    }

    /// In-memory bus: routes (dst, cell) from `me` to dst's inbound channel as
    /// `(me, cell)`, dropping a `loss` fraction.
    struct BusSender {
        me: Peer,
        bus: Bus,
        loss: u32, // out of 1000
        ctr: AtomicU32,
    }
    impl CellSender for BusSender {
        async fn send(&self, dst: Peer, cell: Vec<u8>) -> io::Result<()> {
            let n = self.ctr.fetch_add(1, Ordering::Relaxed);
            // Deterministic pseudo-loss from a counter (no real RNG in tests).
            if (n.wrapping_mul(2_654_435_761) % 1000) >= self.loss {
                let tx = {
                    let g = self.bus.lock().unwrap();
                    g.get(&dst).cloned()
                };
                if let Some(tx) = tx {
                    let _ = tx.try_send((self.me, cell));
                }
            }
            Ok(())
        }
    }

    async fn read_all(s: &mut OnionStream, n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 8192];
        while out.len() < n {
            let k = s.read(&mut buf).await.expect("read");
            if k == 0 {
                break;
            }
            out.extend_from_slice(&buf[..k]);
        }
        out
    }

    fn payload(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                (x >> 33) as u8
            })
            .collect()
    }

    async fn run(loss: u32, n: usize) {
        let a = node(1);
        let b = node(2);
        let bus: Bus = Arc::new(Mutex::new(HashMap::new()));
        let (a_in_tx, a_in_rx) = mpsc::channel(8192);
        let (b_in_tx, b_in_rx) = mpsc::channel(8192);
        bus.lock().unwrap().insert(a, a_in_tx);
        bus.lock().unwrap().insert(b, b_in_tx);

        let sa = Arc::new(BusSender { me: a, bus: bus.clone(), loss, ctr: AtomicU32::new(0) });
        let sb = Arc::new(BusSender { me: b, bus: bus.clone(), loss, ctr: AtomicU32::new(7) });
        let cfg = Config::default();
        let mux_a = StreamMux::new(a, sa, a_in_rx, cfg);
        let mut mux_b = StreamMux::new(b, sb, b_in_rx, cfg);

        let data = payload(n, 0x1234);
        let send_data = data.clone();
        let s_a = mux_a.open(b);
        let sender_task = tokio::spawn(async move {
            s_a.write_all(&send_data).await.unwrap();
            s_a.finish().await.unwrap();
            s_a
        });

        let (mut s_b, src) = mux_b.accept().await.expect("accept");
        assert_eq!(src, a, "accepted stream is from A");
        let got = read_all(&mut s_b, n).await;
        let _s_a = sender_task.await.unwrap();
        assert_eq!(got, data, "muxed transfer mismatch (loss={loss}, n={n})");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn mux_open_accept_transfer_clean() {
        run(0, 60_000).await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn mux_transfer_under_loss() {
        run(150, 40_000).await; // 15% loss
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn mux_two_streams_dont_cross() {
        // A opens two streams to B; each must accept independently + intact.
        let a = node(1);
        let b = node(2);
        let bus: Bus = Arc::new(Mutex::new(HashMap::new()));
        let (a_in_tx, a_in_rx) = mpsc::channel(8192);
        let (b_in_tx, b_in_rx) = mpsc::channel(8192);
        bus.lock().unwrap().insert(a, a_in_tx);
        bus.lock().unwrap().insert(b, b_in_tx);
        let sa = Arc::new(BusSender { me: a, bus: bus.clone(), loss: 0, ctr: AtomicU32::new(0) });
        let sb = Arc::new(BusSender { me: b, bus: bus.clone(), loss: 0, ctr: AtomicU32::new(9) });
        let cfg = Config::default();
        let mux_a = StreamMux::new(a, sa, a_in_rx, cfg);
        let mut mux_b = StreamMux::new(b, sb, b_in_rx, cfg);

        let d1 = payload(20_000, 1);
        let d2 = payload(20_000, 2);
        let (d1c, d2c) = (d1.clone(), d2.clone());
        let s1 = mux_a.open(b);
        let s2 = mux_a.open(b);
        let t1 = tokio::spawn(async move {
            s1.write_all(&d1c).await.unwrap();
            s1.finish().await.unwrap();
            s1
        });
        let t2 = tokio::spawn(async move {
            s2.write_all(&d2c).await.unwrap();
            s2.finish().await.unwrap();
            s2
        });
        // Accept both; match by length-prefix-free content compare.
        let (mut r1, _) = mux_b.accept().await.unwrap();
        let (mut r2, _) = mux_b.accept().await.unwrap();
        let g1 = read_all(&mut r1, 20_000).await;
        let g2 = read_all(&mut r2, 20_000).await;
        let _ = t1.await.unwrap();
        let _ = t2.await.unwrap();
        // Order of acceptance isn't guaranteed; match either assignment.
        let ok = (g1 == d1 && g2 == d2) || (g1 == d2 && g2 == d1);
        assert!(ok, "two muxed streams crossed or corrupted");
    }
}
