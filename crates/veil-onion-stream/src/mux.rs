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
//! Addressing: a cell is sent to an [`Addr`] = `(peer node id, peer stream-
//! endpoint app id)`. The opener supplies the peer's app id (derived from the
//! peer node + the well-known stream endpoint name); the accept side reuses the
//! SYN's authenticated sender address for its return path — no app-id derivation
//! lives in this crate.
//!
//! The crate stays transport-agnostic: [`CellSender`] is the only seam veilclient
//! implements (over `AppSender`), and inbound `(Addr, cell)` pairs are fed in
//! through a channel (drained from the `AppReceiver`). Everything here is unit-
//! tested against an in-memory bus.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::{Mutex as AsyncMutex, mpsc};

use crate::driver::{CellDuplex, End, OnionStream};
use crate::engine::Config;
use crate::wire::Frame;

/// 32-byte node id.
pub type Peer = [u8; 32];

/// A peer's stream endpoint: its node id + the app id its onion-stream endpoint
/// is bound under (anonymous sends are addressed to `(node, app, endpoint)`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Addr {
    pub node: Peer,
    pub app: [u8; 32],
}

/// Sends one cell toward a peer over the anonymous transport (best-effort: a
/// drop downstream is fine, the stream's ARQ repairs it). The receive side is
/// fed to the [`StreamMux`] separately (it owns inbound demux).
pub trait CellSender: Send + Sync + 'static {
    fn send(&self, dst: Addr, cell: Vec<u8>) -> impl Future<Output = io::Result<()>> + Send;
    /// Send an ordered burst of cells to one peer. Accepted cells are popped
    /// from the front of `cells`; on `Err` the failing cell and everything
    /// after it stay queued for the caller to retry (`WouldBlock`) or tear
    /// down. The default forwards cell-by-cell; carriers with per-cell
    /// route/pacing/lock overhead should override and amortize it.
    fn send_many(
        &self,
        dst: Addr,
        cells: &mut std::collections::VecDeque<Vec<u8>>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            while let Some(front) = cells.front() {
                self.send(dst, front.clone()).await?;
                cells.pop_front();
            }
            Ok(())
        }
    }
    fn on_stream_data_rto(
        &self,
        dst: Addr,
        stream_id: u32,
        consec_rto: u32,
        snd_una: u32,
    ) -> impl Future<Output = ()> + Send {
        let _ = (dst, stream_id, consec_rto, snd_una);
        std::future::ready(())
    }
    fn on_stream_closed(
        &self,
        dst: Addr,
        stream_id: u32,
        end: End,
    ) -> impl Future<Output = ()> + Send {
        let _ = (dst, stream_id, end);
        std::future::ready(())
    }
}

/// Per-stream inbound queue depth (cells). Bounded: a slow stream drops excess
/// (ARQ recovers) rather than back-pressuring the shared demux.
///
/// The pinned-circuit fast path can legitimately deliver a few hundred tiny
/// stream cells in one scheduler burst (session-frame batching + relay splice).
/// A 256-cell inbox turned those healthy bursts into artificial loss before the
/// stream driver got scheduled, which then cascaded into coarse RTO recovery.
/// 4096 cells is ~1.5 MiB of fixed-size circuit payload worst-case per active
/// stream and matches the session outbox/PQ burst budget.
const STREAM_INBOX: usize = 4096;
/// Pending not-yet-accepted inbound streams.
const ACCEPT_BACKLOG: usize = 64;

type StreamKey = (Peer, u32);
type Routes = Arc<Mutex<HashMap<StreamKey, mpsc::Sender<Vec<u8>>>>>;

/// A [`CellDuplex`] for one muxed stream: sends to a fixed peer via the shared
/// sender, receives from its demux channel. Deregisters its route on drop.
struct MuxDuplex<S: CellSender> {
    sender: Arc<S>,
    peer: Addr,
    key: StreamKey,
    routes: Routes,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
}

impl<S: CellSender> CellDuplex for MuxDuplex<S> {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        self.sender.send(self.peer, cell.to_vec()).await
    }
    async fn send_cells(
        &mut self,
        cells: &mut std::collections::VecDeque<Vec<u8>>,
    ) -> io::Result<()> {
        self.sender.send_many(self.peer, cells).await
    }
    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.inbound_rx.recv().await)
    }
    async fn recv_cells(&mut self, out: &mut Vec<Vec<u8>>, max: usize) -> io::Result<usize> {
        Ok(self.inbound_rx.recv_many(out, max).await)
    }
    async fn on_data_rto(&mut self, stream_id: u32, consec_rto: u32, snd_una: u32) {
        self.sender
            .on_stream_data_rto(self.peer, stream_id, consec_rto, snd_una)
            .await;
    }
    async fn on_stream_closed(&mut self, stream_id: u32, end: End) {
        self.sender
            .on_stream_closed(self.peer, stream_id, end)
            .await;
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
    accept_rx: AsyncMutex<mpsc::Receiver<(OnionStream, Addr)>>,
}

impl<S: CellSender> StreamMux<S> {
    /// `me` = this node's id (used to split the stream-id space so the two
    /// directions never collide). `inbound` carries `(src_addr, cell)` drained
    /// from the anonymous receive path. Spawns the demux task.
    pub fn new(
        me: Peer,
        sender: Arc<S>,
        inbound: mpsc::Receiver<(Addr, Vec<u8>)>,
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
            accept_rx: AsyncMutex::new(accept_rx),
        }
    }

    /// Open a new stream to `peer`. The returned [`OnionStream`] is live
    /// immediately (its SYN goes out on first poll).
    pub fn open(&self, peer: Addr) -> OnionStream {
        // Split the id space by node order so this node's opened ids never
        // collide with the peer's opened ids on either side.
        let parity = if self.me < peer.node { 0 } else { 1 };
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        let sid = (n << 1) | parity;
        let (tx, rx) = mpsc::channel(STREAM_INBOX);
        let key = (peer.node, sid);
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
    /// transport closed. `&self` so a shared mux can both open and accept.
    pub async fn accept(&self) -> Option<(OnionStream, Addr)> {
        self.accept_rx.lock().await.recv().await
    }
}

/// Deterministic, well-spread initial sequence from the stream id (full
/// randomness isn't needed over an authenticated channel; this just avoids
/// every stream starting at 0).
fn initial_seq(sid: u32) -> u32 {
    sid.wrapping_mul(2_654_435_761) // Knuth multiplicative hash
}

/// Inbound cells drained from the hub per demux turn. One routes-lock spans a
/// whole batch of routable cells; only SYNs (new streams) take the slow path.
const DEMUX_RX_BURST: usize = 256;

async fn demux<S: CellSender>(
    sender: Arc<S>,
    mut inbound: mpsc::Receiver<(Addr, Vec<u8>)>,
    routes: Routes,
    accept_tx: mpsc::Sender<(OnionStream, Addr)>,
    cfg: Config,
) {
    let mut batch: Vec<(Addr, Vec<u8>)> = Vec::new();
    let mut new_streams: Vec<(Addr, Vec<u8>)> = Vec::new();
    loop {
        batch.clear();
        if inbound.recv_many(&mut batch, DEMUX_RX_BURST).await == 0 {
            return; // hub feed closed
        }
        // Fast path: route the whole batch under ONE lock. In the handshake
        // protocol no DATA precedes the peer's SYN_ACK, so a not-yet-routed
        // non-SYN cell here is stale/junk exactly as it was per-cell.
        new_streams.clear();
        {
            let routes_g = routes.lock().unwrap_or_else(|p| p.into_inner());
            for (src, cell) in batch.drain(..) {
                let Some(frame) = Frame::decode(&cell) else {
                    continue; // junk
                };
                let key = (src.node, frame.stream_id());
                if let Some(tx) = routes_g.get(&key) {
                    let _ = tx.try_send(cell); // full → drop, ARQ recovers
                } else if matches!(frame, Frame::Syn { .. }) {
                    new_streams.push((src, cell));
                }
            }
        }
        // Slow path: new inbound streams — only a SYN may create one. Re-check
        // the route per cell so a duplicate SYN in the same batch attaches to
        // the stream its first copy created.
        for (src, cell) in new_streams.drain(..) {
            let key = (
                src.node,
                Frame::decode(&cell).expect("decoded above").stream_id(),
            );
            {
                let routes_g = routes.lock().unwrap_or_else(|p| p.into_inner());
                if let Some(tx) = routes_g.get(&key) {
                    let _ = tx.try_send(cell);
                    continue;
                }
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
                return; // nobody is accepting anymore
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory bus: each node's inbound-cell sink, keyed by node id.
    type Bus = Arc<Mutex<HashMap<Peer, mpsc::Sender<(Addr, Vec<u8>)>>>>;
    type Inbound = mpsc::Receiver<(Addr, Vec<u8>)>;

    fn addr(b: u8) -> Addr {
        Addr {
            node: [b; 32],
            app: [b ^ 0xA5; 32],
        }
    }

    /// Routes (dst, cell) from `me` to dst's inbound channel as `(me, cell)`,
    /// dropping a `loss`/1000 fraction (deterministic, counter-driven).
    struct BusSender {
        me: Addr,
        bus: Bus,
        loss: u32,
        ctr: AtomicU32,
    }
    impl CellSender for BusSender {
        async fn send(&self, dst: Addr, cell: Vec<u8>) -> io::Result<()> {
            let n = self.ctr.fetch_add(1, Ordering::Relaxed);
            if (n.wrapping_mul(2_654_435_761) % 1000) >= self.loss {
                let tx = self.bus.lock().unwrap().get(&dst.node).cloned();
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

    fn wire_bus(a: Addr, b: Addr, loss: u32) -> (Bus, Inbound, Inbound) {
        let bus: Bus = Arc::new(Mutex::new(HashMap::new()));
        let (a_tx, a_rx) = mpsc::channel(8192);
        let (b_tx, b_rx) = mpsc::channel(8192);
        bus.lock().unwrap().insert(a.node, a_tx);
        bus.lock().unwrap().insert(b.node, b_tx);
        let _ = loss;
        (bus, a_rx, b_rx)
    }

    async fn run(loss: u32, n: usize) {
        let (a, b) = (addr(1), addr(2));
        let (bus, a_rx, b_rx) = wire_bus(a, b, loss);
        let sa = Arc::new(BusSender {
            me: a,
            bus: bus.clone(),
            loss,
            ctr: AtomicU32::new(0),
        });
        let sb = Arc::new(BusSender {
            me: b,
            bus: bus.clone(),
            loss,
            ctr: AtomicU32::new(7),
        });
        let cfg = Config::default();
        let mux_a = StreamMux::new(a.node, sa, a_rx, cfg);
        let mux_b = StreamMux::new(b.node, sb, b_rx, cfg);

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
        let (a, b) = (addr(1), addr(2));
        let (bus, a_rx, b_rx) = wire_bus(a, b, 0);
        let sa = Arc::new(BusSender {
            me: a,
            bus: bus.clone(),
            loss: 0,
            ctr: AtomicU32::new(0),
        });
        let sb = Arc::new(BusSender {
            me: b,
            bus: bus.clone(),
            loss: 0,
            ctr: AtomicU32::new(9),
        });
        let cfg = Config::default();
        let mux_a = StreamMux::new(a.node, sa, a_rx, cfg);
        let mux_b = StreamMux::new(b.node, sb, b_rx, cfg);

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
        let (mut r1, _) = mux_b.accept().await.unwrap();
        let (mut r2, _) = mux_b.accept().await.unwrap();
        let g1 = read_all(&mut r1, 20_000).await;
        let g2 = read_all(&mut r2, 20_000).await;
        let _ = t1.await.unwrap();
        let _ = t2.await.unwrap();
        let ok = (g1 == d1 && g2 == d2) || (g1 == d2 && g2 == d1);
        assert!(ok, "two muxed streams crossed or corrupted");
    }
}
