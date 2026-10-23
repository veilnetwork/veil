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

use std::collections::{HashMap, hash_map::Entry};
use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
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
    /// `WouldBlock` means no local handoff occurred: retain this cell for retry.
    /// A cold route may use [`crate::send_backpressure`] to suggest a slower
    /// cadence without sleeping inside the driver's send operation.
    fn send(&self, dst: Addr, cell: Vec<u8>) -> impl Future<Output = io::Result<()>> + Send;
    /// Send a burst of cells to one peer. Remove only accepted cells; on `Err`
    /// retain every unaccepted cell for retry (`WouldBlock`) or teardown.
    /// The default accepts a FIFO prefix. A striped carrier may accept a
    /// non-prefix subset; retained cells keep their relative order. Carriers
    /// with per-cell route/pacing/lock overhead can override and amortize it.
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
    /// An unconfirmed handshake timed out after local handoff. A carrier can
    /// select another ordinary path; shared senders default to ignoring it.
    fn on_stream_handshake_rto(
        &self,
        dst: Addr,
        stream_id: u32,
        retries: u32,
    ) -> impl Future<Output = ()> + Send {
        let _ = (dst, stream_id, retries);
        std::future::ready(())
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
    /// Demand is local-only. Existing senders retain their conservative policy.
    fn on_stream_data_rto_with_demand(
        &self,
        dst: Addr,
        stream_id: u32,
        consec_rto: u32,
        snd_una: u32,
        app_limited: bool,
    ) -> impl Future<Output = ()> + Send {
        let _ = app_limited;
        self.on_stream_data_rto(dst, stream_id, consec_rto, snd_una)
    }
}

/// Per-stream inbound queue depth (cells). Bounded: a slow stream drops excess
/// (ARQ recovers) rather than back-pressuring the shared demux.
///
/// The pinned-circuit fast path can legitimately deliver a few hundred tiny
/// stream cells in one scheduler burst (session-frame batching + relay splice).
/// A 256-cell inbox turned those healthy bursts into artificial loss before the
/// stream driver got scheduled, which then cascaded into coarse RTO recovery.
/// With the 16 KiB cell (2026-07-02 second bump) 512 cells is ~8 MiB
/// worst-case per active stream — one full receive window (the advert grew
/// alongside the post-BBR-fix ~12 MB/s single-stream rate; the channel
/// allocates lazily, so the worst case is only reached when that much really
/// is in flight).
const STREAM_INBOX: usize = 512;
/// Pending not-yet-accepted inbound streams.
const ACCEPT_BACKLOG: usize = 64;

type StreamKey = (Peer, u32);
type Routes = Arc<Mutex<HashMap<StreamKey, mpsc::Sender<Vec<u8>>>>>;

/// Share the allocation sequence across hub recreations in this process. A
/// remote mux can retain a live stream after only our hub/transport restarts;
/// resetting to 1 then reuses its key and routes the fresh SYN to the old app.
/// The OS-random start also avoids deterministic reuse after a process restart.
/// Wire ids retain the existing 31-bit counter plus direction parity, so this
/// reduces restart collisions rather than creating an unlimited id namespace.
static NEXT_STREAM_ID: OnceLock<Arc<AtomicU32>> = OnceLock::new();

fn stream_id_allocator() -> Arc<AtomicU32> {
    NEXT_STREAM_ID
        .get_or_init(|| Arc::new(AtomicU32::new(OsRng.next_u32())))
        .clone()
}

/// Per-peer final delivery models `(btl_bw B/s, rtt_min ms, recorded)` from
/// closed streams, used to warm-start the next stream's BBR estimator (see
/// `Config::warm_btl_bw`). The cold estimator climb costs seconds per stream;
/// ranged bulk pulls open a fresh stream per range and paid it every time.
type BwCache = Arc<Mutex<HashMap<Peer, (u64, u32, Instant)>>>;

/// Who may answer for whom: `answering node → the node a stream was opened to`.
///
/// A stream opened to an IDENTITY is answered by one of its DEVICES, and the
/// answer names the device. Routes are keyed by the node the stream was opened
/// to, so without this every SYN_ACK from a multi-device (or deferred-boot)
/// identity missed its route and was dropped as junk: the open never
/// completed, in either direction. The transport fills this from what it
/// actually resolved (the ad a route was opened against names the device that
/// signed it); the demux consults it only for a non-SYN cell with no route of
/// its own, so a stream the device itself opens stays the device's.
pub type PeerAliases = Arc<Mutex<HashMap<Peer, Peer>>>;

/// Ignore cached delivery models older than this — path conditions drift and
/// a warm seed is a head start, not a promise (the estimator's own windowed
/// filters correct a stale seed within seconds either way).
const BW_CACHE_TTL: Duration = Duration::from_secs(600);
/// Only streams that moved real bulk update the cache: a short control stream
/// measures the pacer, not the path.
const BW_CACHE_MIN_DELIVERED: u64 = 2 * 1024 * 1024;
/// Seed at half the measured rate: cheap insurance against a degraded path,
/// while the 5/4 probe gain recovers the other half within a couple of
/// bandwidth windows.
const BW_CACHE_SEED_NUM: u64 = 1;
const BW_CACHE_SEED_DEN: u64 = 2;

/// Apply a fresh cached model (if any) to a per-stream config.
fn warm_config(cfg: Config, cache: &BwCache, peer: Peer) -> Config {
    let mut cfg = cfg;
    if !cfg.bbr {
        return cfg;
    }
    let g = cache.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(&(bw, rtt_min_ms, at)) = g.get(&peer)
        && at.elapsed() <= BW_CACHE_TTL
    {
        cfg.warm_btl_bw = bw.saturating_mul(BW_CACHE_SEED_NUM) / BW_CACHE_SEED_DEN;
        cfg.warm_rtt_min_ms = rtt_min_ms;
    }
    cfg
}

/// A [`CellDuplex`] for one muxed stream: sends to a fixed peer via the shared
/// sender, receives from its demux channel. Deregisters its route on drop.
struct MuxDuplex<S: CellSender> {
    sender: Arc<S>,
    peer: Addr,
    key: StreamKey,
    routes: Routes,
    bw_cache: BwCache,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    /// The sender half this duplex installed under [`Self::key`]. Kept only so
    /// the drop above can tell its own route from a later generation's.
    route_tx: mpsc::Sender<Vec<u8>>,
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
    async fn on_handshake_rto(&mut self, stream_id: u32, retries: u32) {
        self.sender
            .on_stream_handshake_rto(self.peer, stream_id, retries)
            .await;
    }
    async fn on_data_rto(&mut self, stream_id: u32, consec_rto: u32, snd_una: u32) {
        self.sender
            .on_stream_data_rto(self.peer, stream_id, consec_rto, snd_una)
            .await;
    }
    async fn on_data_rto_with_demand(
        &mut self,
        stream_id: u32,
        consec_rto: u32,
        snd_una: u32,
        app_limited: bool,
    ) {
        self.sender
            .on_stream_data_rto_with_demand(self.peer, stream_id, consec_rto, snd_una, app_limited)
            .await;
    }
    async fn on_stream_closed(&mut self, stream_id: u32, end: End) {
        self.sender
            .on_stream_closed(self.peer, stream_id, end)
            .await;
    }
    async fn on_stream_model(
        &mut self,
        _stream_id: u32,
        btl_bw: u64,
        rtt_min_ms: u32,
        delivered: u64,
    ) {
        if btl_bw == 0 || delivered < BW_CACHE_MIN_DELIVERED {
            return;
        }
        self.bw_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(self.peer.node, (btl_bw, rtt_min_ms, Instant::now()));
    }
}

impl<S: CellSender> Drop for MuxDuplex<S> {
    fn drop(&mut self) {
        // Only if the route under this key is still OURS.
        //
        // Stream ids repeat: `open` builds them as `(n << 1) | parity` from a
        // `u32`, so the id space is exhausted after 2^31 opens and the key
        // comes round again. A blind `remove` then let a stream that had ended
        // tear down the route of the LIVE stream that had since taken its key —
        // a stream that never collided with anything itself (report9 V-20).
        let mut routes = self.routes.lock().unwrap_or_else(|p| p.into_inner());
        if routes
            .get(&self.key)
            .is_some_and(|tx| tx.same_channel(&self.route_tx))
        {
            routes.remove(&self.key);
        }
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
    bw_cache: BwCache,
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
        Self::new_with_aliases(me, sender, inbound, cfg, PeerAliases::default())
    }

    /// Like [`new`](Self::new), with the answering-node table the transport
    /// fills (see [`PeerAliases`]).
    pub fn new_with_aliases(
        me: Peer,
        sender: Arc<S>,
        inbound: mpsc::Receiver<(Addr, Vec<u8>)>,
        cfg: Config,
        aliases: PeerAliases,
    ) -> Self {
        let routes: Routes = Arc::new(Mutex::new(HashMap::new()));
        let bw_cache: BwCache = Arc::new(Mutex::new(HashMap::new()));
        let (accept_tx, accept_rx) = mpsc::channel(ACCEPT_BACKLOG);
        tokio::spawn(demux(
            sender.clone(),
            inbound,
            routes.clone(),
            bw_cache.clone(),
            accept_tx,
            cfg,
            aliases,
        ));
        StreamMux {
            me,
            sender,
            cfg,
            routes,
            bw_cache,
            next_id: stream_id_allocator(),
            accept_rx: AsyncMutex::new(accept_rx),
        }
    }

    /// Open a new stream to `peer`. The returned [`OnionStream`] is live
    /// immediately (its SYN goes out on first poll).
    pub fn open(&self, peer: Addr) -> OnionStream {
        // Split the id space by node order so this node's opened ids never
        // collide with the peer's opened ids on either side.
        let parity = if self.me < peer.node { 0 } else { 1 };
        let (tx, rx) = mpsc::channel(STREAM_INBOX);
        // Take a key nothing is routed on. `(n << 1) | parity` from a `u32`
        // repeats after 2^31 opens, and inserting on top of a live route
        // silently steals that stream's inbound cells (report9 V-20).
        // Never displace an existing route, including when more than the old
        // 64-probe budget is occupied after counter wrap.
        let (sid, key) = {
            let mut routes = self.routes.lock().unwrap_or_else(|p| p.into_inner());
            loop {
                let n = self.next_id.fetch_add(1, Ordering::Relaxed);
                let sid = (n << 1) | parity;
                let key = (peer.node, sid);
                if let Entry::Vacant(entry) = routes.entry(key) {
                    entry.insert(tx.clone());
                    break (sid, key);
                }
            }
        };
        let duplex = MuxDuplex {
            sender: self.sender.clone(),
            peer,
            key,
            routes: self.routes.clone(),
            bw_cache: self.bw_cache.clone(),
            inbound_rx: rx,
            route_tx: tx,
        };
        let cfg = warm_config(self.cfg, &self.bw_cache, peer.node);
        OnionStream::connect(duplex, cfg, sid, initial_seq(sid))
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
    bw_cache: BwCache,
    accept_tx: mpsc::Sender<(OnionStream, Addr)>,
    cfg: Config,
    aliases: PeerAliases,
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
                } else if let Some(tx) = aliases
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .get(&src.node)
                    .and_then(|opened_to| routes_g.get(&(*opened_to, key.1)))
                {
                    // An answer from the device for a stream opened to its
                    // identity (see `PeerAliases`).
                    let _ = tx.try_send(cell);
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
                .insert(key, tx.clone());
            let duplex = MuxDuplex {
                sender: sender.clone(),
                peer: src,
                key,
                routes: routes.clone(),
                bw_cache: bw_cache.clone(),
                inbound_rx: rx,
                route_tx: tx,
            };
            // The accept side is the bulk SENDER in a ranged pull (the peer
            // opens a stream and we serve the payload), so it needs the warm
            // seed at least as much as the open side.
            let cfg = warm_config(cfg, &bw_cache, src.node);
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

    struct NoSender;

    impl CellSender for NoSender {
        async fn send(&self, _dst: Addr, _cell: Vec<u8>) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn open_skips_all_live_ids_instead_of_stealing_the_last_probe() {
        let (_tx, rx) = mpsc::channel(1);
        let mut mux = StreamMux::new(addr(1).node, Arc::new(NoSender), rx, Config::default());
        // An isolated allocator exercises occupied keys across u32 wrap, not
        // the production process-wide counter used by concurrently run tests.
        let start = u32::MAX - 32;
        mux.next_id = Arc::new(AtomicU32::new(start));
        let peer = addr(2);
        let mut live = Vec::new();
        for offset in 0..65 {
            let sid = start.wrapping_add(offset) << 1;
            let (tx, rx) = mpsc::channel(STREAM_INBOX);
            mux.routes
                .lock()
                .unwrap()
                .insert((peer.node, sid), tx.clone());
            live.push((sid, tx, rx));
        }
        let stream = mux.open(peer);
        {
            let routes = mux.routes.lock().unwrap();
            assert_eq!(
                routes.len(),
                live.len() + 1,
                "open displaced a live route after exhausting its probe budget"
            );
            for (sid, tx, _rx) in &live {
                assert!(routes.get(&(peer.node, *sid)).unwrap().same_channel(tx));
            }
        }
        stream.reset(crate::wire::reset_reason::APP).await;
    }

    /// A duplex that has ended must not take down the route of the stream that
    /// has since taken its key.
    ///
    /// Stream ids repeat — `(n << 1) | parity` from a `u32` runs out after
    /// 2^31 opens — so the key comes round while a NEW stream is using it. The
    /// old duplex's blind `remove` then killed a stream that never collided
    /// with anything itself (report9 V-20).
    #[test]
    fn a_dropped_duplex_does_not_remove_a_newer_streams_route() {
        let routes: Routes = Arc::new(Mutex::new(HashMap::new()));
        let bw_cache: BwCache = Arc::new(Mutex::new(HashMap::new()));
        let peer = Addr {
            node: [9u8; 32],
            app: [0u8; 32],
        };
        let key = (peer.node, 3u32);

        // The stream that holds the key NOW.
        let (live_tx, _live_rx) = mpsc::channel::<Vec<u8>>(1);
        routes.lock().unwrap().insert(key, live_tx.clone());

        // A duplex from an earlier generation on the same key, ending.
        let (old_tx, old_rx) = mpsc::channel::<Vec<u8>>(1);
        let stale = MuxDuplex {
            sender: Arc::new(NoSender),
            peer,
            key,
            routes: routes.clone(),
            bw_cache,
            inbound_rx: old_rx,
            route_tx: old_tx,
        };
        drop(stale);

        let held = routes.lock().unwrap();
        let still = held.get(&key).expect(
            "the live stream lost its route to a duplex from an earlier \
             generation of the same id",
        );
        assert!(
            still.same_channel(&live_tx),
            "the route under this key is no longer the live stream's"
        );
    }

    /// And a duplex still holding its own route does remove it — a guard that
    /// never removed would leak an entry per stream.
    #[test]
    fn a_dropped_duplex_removes_its_own_route() {
        let routes: Routes = Arc::new(Mutex::new(HashMap::new()));
        let peer = Addr {
            node: [4u8; 32],
            app: [0u8; 32],
        };
        let key = (peer.node, 5u32);
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1);
        routes.lock().unwrap().insert(key, tx.clone());
        drop(MuxDuplex {
            sender: Arc::new(NoSender),
            peer,
            key,
            routes: routes.clone(),
            bw_cache: Arc::new(Mutex::new(HashMap::new())),
            inbound_rx: rx,
            route_tx: tx,
        });
        assert!(
            routes.lock().unwrap().get(&key).is_none(),
            "the duplex left its own route behind"
        );
    }

    #[test]
    fn warm_config_seeds_from_fresh_cache_only() {
        let cache: BwCache = Arc::new(Mutex::new(HashMap::new()));
        let peer = [7u8; 32];
        let base = Config {
            bbr: true,
            ..Config::default()
        };
        // Empty cache → cold.
        assert_eq!(warm_config(base, &cache, peer).warm_btl_bw, 0);
        // Fresh entry → half-rate seed + rtt.
        cache
            .lock()
            .unwrap()
            .insert(peer, (8_000_000, 150, Instant::now()));
        let warmed = warm_config(base, &cache, peer);
        assert_eq!(warmed.warm_btl_bw, 4_000_000);
        assert_eq!(warmed.warm_rtt_min_ms, 150);
        // Stale entry → cold again.
        cache.lock().unwrap().insert(
            peer,
            (
                8_000_000,
                150,
                Instant::now() - (BW_CACHE_TTL + Duration::from_secs(1)),
            ),
        );
        assert_eq!(warm_config(base, &cache, peer).warm_btl_bw, 0);
        // bbr off → never seeded.
        let no_bbr = Config {
            bbr: false,
            ..Config::default()
        };
        cache
            .lock()
            .unwrap()
            .insert(peer, (8_000_000, 150, Instant::now()));
        assert_eq!(warm_config(no_bbr, &cache, peer).warm_btl_bw, 0);
    }

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

    /// A stream opened to an IDENTITY completes when a DEVICE answers it.
    ///
    /// The open is routed to whatever holds the identity's rendezvous slot,
    /// and that device answers under its own id. Routes are keyed by the node
    /// the stream was opened to, so the SYN_ACK missed and was dropped: on the
    /// stand every anonymous stream to a desktop identity stalled in the
    /// handshake, and no file above the datagram size arrived.
    async fn transfer_to_identity_answered_by_device(aliases: PeerAliases) -> bool {
        let (a, device, identity) = (addr(1), addr(2), addr(3));
        let (bus, a_rx, d_rx) = wire_bus(a, device, 0);
        // What the transport does: cells for the identity reach the device.
        let d_tx = bus.lock().unwrap().get(&device.node).cloned().unwrap();
        bus.lock().unwrap().insert(identity.node, d_tx);
        let sa = Arc::new(BusSender {
            me: a,
            bus: bus.clone(),
            loss: 0,
            ctr: AtomicU32::new(0),
        });
        let sd = Arc::new(BusSender {
            me: device,
            bus: bus.clone(),
            loss: 0,
            ctr: AtomicU32::new(5),
        });
        let cfg = Config::default();
        let mux_a = StreamMux::new_with_aliases(a.node, sa, a_rx, cfg, aliases);
        let mux_d = StreamMux::new(device.node, sd, d_rx, cfg);

        // The shape of a pull: a short request out, the file back.
        let request = payload(48, 3);
        let file = payload(20_000, 4);
        let served = file.clone();
        let server = tokio::spawn(async move {
            let (mut s_d, src) = mux_d.accept().await.expect("accept");
            assert_eq!(src, a);
            let _request = read_all(&mut s_d, 48).await;
            s_d.write_all(&served).await?;
            s_d.finish().await
        });
        let pull = async {
            let mut s_a = mux_a.open(identity);
            s_a.write_all(&request).await.ok()?;
            // Not `read_all`: a reset is this test's failure outcome, not a panic.
            let mut out = Vec::new();
            let mut buf = vec![0u8; 8192];
            while out.len() < file.len() {
                match s_a.read(&mut buf).await.ok()? {
                    0 => break,
                    k => out.extend_from_slice(&buf[..k]),
                }
            }
            Some(out)
        };
        let got = tokio::time::timeout(Duration::from_secs(120), pull).await;
        server.abort();
        matches!(got, Ok(Some(bytes)) if bytes == file)
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_stream_to_an_identity_completes_when_its_device_answers() {
        let aliases = PeerAliases::default();
        aliases.lock().unwrap().insert(addr(2).node, addr(3).node);
        assert!(
            transfer_to_identity_answered_by_device(aliases).await,
            "the device's answer must reach the stream opened to its identity"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn without_the_alias_the_devices_answer_is_lost() {
        assert!(
            !transfer_to_identity_answered_by_device(PeerAliases::default()).await,
            "control: with no alias the open must not complete — otherwise the \
             test above proves nothing about the alias"
        );
    }
}
