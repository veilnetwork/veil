//! Async driver: turns the sans-IO [`StreamEngine`] into a usable bidirectional
//! byte-stream over a [`CellDuplex`] (the cell carrier — a real onion circuit in
//! production, an in-memory pipe in tests). One tokio task owns the engine + the
//! duplex and pumps: app writes/reads ⇄ engine ⇄ circuit cells, on a real
//! monotonic clock. The app talks to it through [`OnionStream`].

use std::future::{Future, pending};
use std::io;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use tokio::sync::{Notify, mpsc, watch};
// tokio's monotonic clock (NOT std::time::Instant): it honours `start_paused`'s
// virtual time in tests, so the engine's clock and the driver's sleeps share one
// timeline. In production it is the real monotonic clock.
use tokio::time::Instant;

use crate::engine::{Config, Event, LocalTransmit, StreamEngine};
use crate::wire::reset_reason;

#[derive(Debug)]
struct SendRetryAfter(u64);

impl std::fmt::Display for SendRetryAfter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("local stream carrier is not ready")
    }
}

impl std::error::Error for SendRetryAfter {}

/// Local backpressure with a suggested retry cadence. A route being built may
/// need a slower retry than a full socket queue. The driver remains responsive
/// to reads, cancellation and protocol timers while waiting; no wire field or
/// network retransmission timer changes. Bounds prevent spinning or parking a
/// stream indefinitely. Ordinary `WouldBlock` keeps its one-millisecond retry.
pub fn send_backpressure(retry_after: Duration) -> io::Error {
    let millis = retry_after.as_millis().clamp(1, 1000) as u64;
    io::Error::new(io::ErrorKind::WouldBlock, SendRetryAfter(millis))
}

fn send_retry_delay_ms(error: &io::Error) -> u64 {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<SendRetryAfter>())
        .map_or(SEND_WOULD_BLOCK_RETRY_MS, |delay| delay.0)
}

/// The cell carrier the stream rides. Best-effort + lossy: `send_cell` may be
/// dropped downstream (ARQ repairs it); `WouldBlock` is an unsent local cell.
/// Other errors are permanent. `recv_cell` returns `None` on clean close.
pub trait CellDuplex: Send {
    fn send_cell(&mut self, cell: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
    /// Send a burst of cells. Remove only accepted cells; on `Err` retain
    /// every unaccepted cell for retry (`WouldBlock`) or teardown. The default
    /// accepts a FIFO prefix. A striped carrier may accept a non-prefix subset;
    /// retained cells keep their relative order. Carriers can override this
    /// method to amortize per-cell route/pacing/lock overhead.
    fn send_cells(
        &mut self,
        cells: &mut std::collections::VecDeque<Vec<u8>>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            while let Some(front) = cells.front() {
                let cell = front.clone();
                self.send_cell(&cell).await?;
                cells.pop_front();
            }
            Ok(())
        }
    }
    fn recv_cell(&mut self) -> impl Future<Output = io::Result<Option<Vec<u8>>>> + Send;
    /// Receive at least one cell, draining up to `max` already-buffered cells
    /// into `out` without extra wakeups. Returns the number received; `0`
    /// means the carrier is closed. Must be cancel-safe (used in `select!`).
    /// The default forwards one cell per call; channel-backed carriers should
    /// override with a batched receive so the driver processes inbound bursts
    /// in one loop turn instead of one full turn per cell.
    fn recv_cells(
        &mut self,
        out: &mut Vec<Vec<u8>>,
        max: usize,
    ) -> impl Future<Output = io::Result<usize>> + Send {
        async move {
            let _ = max;
            match self.recv_cell().await? {
                Some(cell) => {
                    out.push(cell);
                    Ok(1)
                }
                None => Ok(0),
            }
        }
    }
    /// Only an unconfirmed, locally accepted handshake can trigger this event.
    fn on_handshake_rto(
        &mut self,
        stream_id: u32,
        retries: u32,
    ) -> impl Future<Output = ()> + Send {
        let _ = (stream_id, retries);
        std::future::ready(())
    }
    fn on_data_rto(
        &mut self,
        stream_id: u32,
        consec_rto: u32,
        snd_una: u32,
    ) -> impl Future<Output = ()> + Send {
        let _ = (stream_id, consec_rto, snd_una);
        std::future::ready(())
    }
    fn on_stream_closed(&mut self, stream_id: u32, end: End) -> impl Future<Output = ()> + Send {
        let _ = (stream_id, end);
        std::future::ready(())
    }
    /// Local engine demand at the timeout. Legacy carriers keep their callback.
    fn on_data_rto_with_demand(
        &mut self,
        stream_id: u32,
        consec_rto: u32,
        snd_una: u32,
        app_limited: bool,
    ) -> impl Future<Output = ()> + Send {
        let _ = app_limited;
        self.on_data_rto(stream_id, consec_rto, snd_una)
    }
    /// The stream's final delivery model (measured bottleneck rate, min RTT,
    /// total delivered bytes), reported once just before `on_stream_closed`.
    /// Carriers may cache it per peer to warm-start follow-up streams (see
    /// `Config::warm_btl_bw`). Default: ignored.
    fn on_stream_model(
        &mut self,
        stream_id: u32,
        btl_bw: u64,
        rtt_min_ms: u32,
        delivered: u64,
    ) -> impl Future<Output = ()> + Send {
        let _ = (stream_id, btl_bw, rtt_min_ms, delivered);
        std::future::ready(())
    }
}

/// How a stream ended — the resumability signal the app keys on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Open,
    /// Clean EOF (peer FIN) — transfer complete.
    Eof,
    /// Aborted (`reason` from [`reset_reason`]) — the app should resume.
    Reset(u8),
}

enum AppCmd {
    Write(Vec<u8>),
    Finish,
}

/// App-facing handle to a reliable onion byte-stream. The sender uses
/// [`write_all`](Self::write_all) + [`finish`](Self::finish); the receiver uses
/// [`read`](Self::read) until it returns 0 (EOF) or errors (reset → resume).
pub struct OnionStream {
    cmd_tx: mpsc::Sender<AppCmd>,
    data_rx: mpsc::Receiver<Vec<u8>>,
    residual: Vec<u8>,
    end: Arc<Mutex<End>>,
    abort: OnionAbort,
    connection: OnionConnection,
}

/// Read-only local handshake state. Queueing app bytes or handing off a SYN
/// does not make a connection ready; the engine must accept the peer handshake.
#[derive(Clone)]
pub struct OnionConnection {
    connected: Arc<AtomicBool>,
    end: Arc<Mutex<End>>,
}

impl OnionConnection {
    pub fn is_connected(&self) -> io::Result<bool> {
        if let End::Reset(reason) = end_of(&self.end) {
            return reset_err(reason);
        }
        Ok(self.connected.load(Ordering::Acquire))
    }
}

impl OnionStream {
    /// A local admission failure, with no route, driver or network attempt.
    /// Keep `StreamMux::open`'s existing handle API while exposing a prompt
    /// reset to connection/read/write callers instead of probing indefinitely.
    pub(crate) fn refused() -> Self {
        let (cmd_tx, _) = mpsc::channel(1);
        let (_, data_rx) = mpsc::channel(1);
        let (reset_tx, _) = watch::channel(None);
        let end = Arc::new(Mutex::new(End::Reset(reset_reason::REFUSED)));
        let abort = OnionAbort {
            end: end.clone(),
            notify: Arc::new(Notify::new()),
            reset_tx,
        };
        Self {
            cmd_tx,
            data_rx,
            residual: Vec::new(),
            connection: OnionConnection {
                connected: Arc::new(AtomicBool::new(false)),
                end: end.clone(),
            },
            end,
            abort,
        }
    }

    /// Initiator side over `duplex`.
    pub fn connect<D>(duplex: D, cfg: Config, stream_id: u32, iss: u32) -> Self
    where
        D: CellDuplex + 'static,
    {
        Self::spawn(StreamEngine::connect(stream_id, cfg, 0, iss), duplex)
    }

    /// Responder side over `duplex`.
    pub fn accept<D>(duplex: D, cfg: Config, stream_id: u32, iss: u32) -> Self
    where
        D: CellDuplex + 'static,
    {
        Self::spawn(StreamEngine::accept(stream_id, cfg, 0, iss), duplex)
    }

    fn spawn<D>(engine: StreamEngine, duplex: D) -> Self
    where
        D: CellDuplex + 'static,
    {
        let (cmd_tx, cmd_rx) = mpsc::channel(8);
        let (reset_tx, reset_rx) = watch::channel(None);
        let (data_tx, data_rx) = mpsc::channel(16);
        let end = Arc::new(Mutex::new(End::Open));
        let connection = OnionConnection {
            connected: Arc::new(AtomicBool::new(false)),
            end: end.clone(),
        };
        let abort = OnionAbort {
            end: end.clone(),
            notify: Arc::new(Notify::new()),
            reset_tx,
        };
        tokio::spawn(drive(
            engine,
            duplex,
            cmd_rx,
            reset_rx,
            data_tx,
            end.clone(),
            connection.connected.clone(),
        ));
        OnionStream {
            cmd_tx,
            data_rx,
            residual: Vec::new(),
            end,
            abort,
            connection,
        }
    }

    /// Queue `data` for reliable delivery. Resolves once the driver has accepted
    /// it (back-pressured when the send buffer is full).
    pub async fn write_all(&self, data: &[u8]) -> io::Result<()> {
        self.cmd_tx
            .send(AppCmd::Write(data.to_vec()))
            .await
            .map_err(|_| broken())
    }

    /// Half-close the send direction: a FIN follows the last queued byte.
    pub async fn finish(&self) -> io::Result<()> {
        self.cmd_tx.send(AppCmd::Finish).await.map_err(|_| broken())
    }

    /// Abort the stream; the peer observes [`End::Reset`].
    pub async fn reset(&self, reason: u8) {
        self.abort.reset(reason);
    }

    /// Read up to `buf.len()` delivered bytes. `Ok(0)` = clean EOF; an
    /// `Err(ConnectionReset)` = the stream was aborted (the app should resume).
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        pull(
            &mut self.data_rx,
            &mut self.residual,
            &self.end,
            &self.abort,
            buf,
        )
        .await
    }

    /// Current end state (Open / Eof / Reset).
    pub fn end_reason(&self) -> End {
        end_of(&self.end)
    }

    /// Cloneable local abort handle. This lets FFI `close()` wake an in-flight
    /// blocking read immediately even if the async driver has not yet consumed
    /// the reset command.
    pub fn abort_handle(&self) -> OnionAbort {
        self.abort.clone()
    }

    pub fn connection_handle(&self) -> OnionConnection {
        self.connection.clone()
    }

    /// Split into independently-owned read + write halves so a caller can read
    /// and write concurrently (the FFI does this — one mutex over the whole
    /// stream would deadlock a blocking read against a write).
    pub fn into_split(self) -> (OnionReader, OnionWriter) {
        (
            OnionReader {
                data_rx: self.data_rx,
                residual: self.residual,
                end: self.end.clone(),
                abort: self.abort.clone(),
            },
            OnionWriter {
                cmd_tx: self.cmd_tx,
                end: self.end,
                abort: self.abort,
            },
        )
    }
}

/// Cloneable local abort signal shared by the read/write halves.
#[derive(Clone)]
pub struct OnionAbort {
    end: Arc<Mutex<End>>,
    notify: Arc<Notify>,
    reset_tx: watch::Sender<Option<u8>>,
}

impl OnionAbort {
    /// Mark the local stream as reset and wake readers currently parked in
    /// `read()`. The wire-level RST is still sent through [`OnionWriter::reset`].
    pub fn abort(&self, reason: u8) {
        set_end(&self.end, End::Reset(reason));
        self.notify.notify_waiters();
    }

    /// Wake readers and request a best-effort wire reset without waiting for
    /// the writer mutex or a backpressured application-data queue. Only the
    /// first reset is retained; repeated requests cannot grow a control queue.
    /// The driver consumes it when the current carrier operation returns.
    pub fn reset(&self, reason: u8) {
        self.abort(reason);
        self.reset_tx.send_if_modified(|pending| {
            if pending.is_some() {
                return false;
            }
            *pending = Some(reason);
            true
        });
    }
}

/// Read half of a split [`OnionStream`].
pub struct OnionReader {
    data_rx: mpsc::Receiver<Vec<u8>>,
    residual: Vec<u8>,
    end: Arc<Mutex<End>>,
    abort: OnionAbort,
}
impl OnionReader {
    /// See [`OnionStream::read`].
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        pull(
            &mut self.data_rx,
            &mut self.residual,
            &self.end,
            &self.abort,
            buf,
        )
        .await
    }
    pub fn end_reason(&self) -> End {
        end_of(&self.end)
    }
}

/// Write half of a split [`OnionStream`].
pub struct OnionWriter {
    cmd_tx: mpsc::Sender<AppCmd>,
    end: Arc<Mutex<End>>,
    abort: OnionAbort,
}
impl OnionWriter {
    /// See [`OnionStream::write_all`].
    pub async fn write_all(&self, data: &[u8]) -> io::Result<()> {
        self.cmd_tx
            .send(AppCmd::Write(data.to_vec()))
            .await
            .map_err(|_| broken())
    }
    /// See [`OnionStream::finish`].
    pub async fn finish(&self) -> io::Result<()> {
        self.cmd_tx.send(AppCmd::Finish).await.map_err(|_| broken())
    }
    /// See [`OnionStream::reset`].
    pub async fn reset(&self, reason: u8) {
        self.abort.reset(reason);
    }
    /// Locally wake readers without waiting for the async driver command queue.
    pub fn abort_local(&self, reason: u8) {
        self.abort.abort(reason);
    }
    pub fn end_reason(&self) -> End {
        end_of(&self.end)
    }
}

fn end_of(end: &Arc<Mutex<End>>) -> End {
    *end.lock().unwrap_or_else(|p| p.into_inner())
}

/// Shared read implementation for [`OnionStream`] + [`OnionReader`].
async fn pull(
    data_rx: &mut mpsc::Receiver<Vec<u8>>,
    residual: &mut Vec<u8>,
    end: &Arc<Mutex<End>>,
    abort: &OnionAbort,
    buf: &mut [u8],
) -> io::Result<usize> {
    if residual.is_empty() {
        if let End::Reset(r) = end_of(end) {
            return reset_err(r);
        }
        let recv = tokio::select! {
            biased;
            _ = abort.notify.notified() => {
                if let End::Reset(r) = end_of(end) {
                    return reset_err(r);
                }
                data_rx.recv().await
            }
            recv = data_rx.recv() => recv,
        };
        match recv {
            Some(chunk) => *residual = chunk,
            None => {
                return match end_of(end) {
                    End::Reset(r) => reset_err(r),
                    _ => Ok(0), // clean EOF
                };
            }
        }
    }
    let n = buf.len().min(residual.len());
    buf[..n].copy_from_slice(&residual[..n]);
    residual.drain(..n);
    Ok(n)
}

fn reset_err<T>(reason: u8) -> io::Result<T> {
    Err(io::Error::new(
        io::ErrorKind::ConnectionReset,
        format!("onion stream reset ({reason})"),
    ))
}

fn broken() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "onion stream driver gone")
}

/// Stop accepting new app writes once this many bytes are buffered unsent
/// (send-side back-pressure; the bounded cmd channel then stalls `write_all`).
const SEND_HIGH_WATER: usize = 4 << 20;
/// Chunk size for moving delivered bytes out of the engine to the reader.
const DELIVER_CHUNK: usize = 256 * 1024;
/// Local transport backpressure retry cadence. `WouldBlock` means the cell did
/// not enter the next bounded queue, so keep the exact encoded cell and retry it
/// instead of turning local queue pressure into end-to-end packet loss.
const SEND_WOULD_BLOCK_RETRY_MS: u64 = 1;
/// Upper bound on cells pulled out of the engine into the local outbound
/// burst before handing it to the carrier. The engine's own pacing budget
/// already bounds one poll pass (<= max_pacing_batch); this is a backstop so
/// a stuck carrier cannot accumulate unbounded committed cells locally.
const MAX_OUTBOUND_BURST: usize = 512;
/// Leave room inside the existing local bound for newly due ACKs/repairs.
/// These use the same carrier and admission budget as their ordinary peers.
const REPAIR_RESERVE: usize = 8;
/// Upper bound on inbound cells drained per loop turn. The relay splice can
/// legitimately deliver hundreds of cells in one scheduler burst; processing
/// them in one turn (one ACK/transmit pass) instead of one full loop turn per
/// cell is where the receive-side batching win comes from.
const MAX_RX_BURST: usize = 256;
const DEBUG_SUMMARY_ENV: &str = "VEIL_ONION_STREAM_DEBUG_SUMMARY_MS";

fn debug_summary_period_ms(configured: u64) -> Option<u64> {
    let from_env = std::env::var(DEBUG_SUMMARY_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0);
    let period = configured.max(from_env);
    if period > 0 { Some(period) } else { None }
}

#[cfg(target_os = "android")]
fn debug_summary_log(stream_id: u32, summary: String) {
    log::info!("onion-stream-driver[{stream_id}]: {summary}");
}

#[cfg(not(target_os = "android"))]
fn debug_summary_log(stream_id: u32, summary: String) {
    use std::io::Write as _;

    let _ = writeln!(
        std::io::stderr(),
        "onion-stream-driver[{stream_id}]: {summary}"
    );
}

async fn drive<D: CellDuplex>(
    mut engine: StreamEngine,
    mut duplex: D,
    mut cmd_rx: mpsc::Receiver<AppCmd>,
    mut reset_rx: watch::Receiver<Option<u8>>,
    data_tx: mpsc::Sender<Vec<u8>>,
    end: Arc<Mutex<End>>,
    connected: Arc<AtomicBool>,
) {
    engine.track_local_handoffs();
    let base = Instant::now();
    let now_ms = |b: &Instant| b.elapsed().as_millis() as u64;
    let debug_summary_period_ms = debug_summary_period_ms(engine.debug_summary_period_ms());
    let mut next_debug_summary_ms = debug_summary_period_ms.unwrap_or(0);
    let mut cmd_open = true;
    let mut reset_open = true;
    let mut cell = Vec::with_capacity(crate::wire::MAX_CELL);
    // Inbound burst buffer for `recv_cells` — reused across loop turns.
    let mut rx_cells: Vec<Vec<u8>> = Vec::new();
    // Bounded local reservations awaiting carrier acceptance. Unaccepted cells
    // keep their relative order, including partial striped sends. Newly due
    // control/repair can precede a retained fresh-DATA tail.
    let mut outbound: std::collections::VecDeque<Vec<u8>> = std::collections::VecDeque::new();
    let mut send_retry_at: Option<u64> = None;
    let mut close_handoff_deadline: Option<u64> = None;
    let mut blocked_since_ms: Option<u64> = None;
    let mut would_block_total: u64 = 0;
    let mut would_block_retries: u64 = 0;
    let mut would_block_recovered: u64 = 0;
    let mut local_transmits = std::collections::HashMap::<LocalTransmit, usize>::new();
    loop {
        let now = now_ms(&base);
        if let Some(period_ms) = debug_summary_period_ms
            && now >= next_debug_summary_ms
        {
            let blocked_age_ms = blocked_since_ms
                .map(|since| now.saturating_sub(since))
                .unwrap_or(0);
            debug_summary_log(
                engine.stream_id(),
                format!(
                    "now={now} blocked_cell={} blocked_age={}ms wb_total={} \
                     wb_retries={} wb_recovered={} {}",
                    outbound.len(),
                    blocked_age_ms,
                    would_block_total,
                    would_block_retries,
                    would_block_recovered,
                    engine.debug_summary()
                ),
            );
            next_debug_summary_ms = now.saturating_add(period_ms);
        }

        // 0. Once the peer has finished AND we've handed off everything we
        //    received, close our own (often empty) write half so both ends
        //    exchange FINs and settle cleanly. Done BEFORE the drain so the
        //    courtesy FIN actually goes out this iteration (not after we park).
        if engine.is_eof() {
            engine.finish();
        }

        // 1. Surface terminal events.
        while let Some(ev) = engine.poll_event() {
            match ev {
                Event::PeerFinished => set_end(&end, End::Eof),
                Event::Reset(r) => set_end(&end, End::Reset(r)),
                Event::Connected => connected.store(true, Ordering::Release),
                Event::HandshakeRto { retries } => {
                    if engine.handshake_unconfirmed() {
                        duplex.on_handshake_rto(engine.stream_id(), retries).await;
                    }
                }
                Event::DataRto {
                    consec_rto,
                    snd_una,
                    app_limited,
                } => {
                    duplex
                        .on_data_rto_with_demand(
                            engine.stream_id(),
                            consec_rto,
                            snd_una,
                            app_limited && cmd_rx.is_empty() && outbound.is_empty(),
                        )
                        .await;
                }
            }
        }

        // 2. Move delivered bytes to the reader, bounded by channel capacity so a
        //    slow reader closes the receive window (real end-to-end flow control).
        //
        // Do this BEFORE transmitting ACKs: ACK frames advertise free receive
        // window. If we ACK first and only then drain `read_buf`, a long in-order
        // transfer can repeatedly advertise a near-zero window even though the app
        // is about to consume the bytes immediately, forcing the sender into
        // zero-window/persist pulses.
        loop {
            // Dropping the entire handle is the graceful close path: queued
            // writes still finish, and late reverse-direction credits still
            // need transport ACKs. No reader remains to consume these bytes.
            // A reader-only drop with a live writer retains its abort behavior.
            if data_tx.is_closed() && cmd_rx.is_closed() {
                let mut discarded = vec![0u8; engine.readable_len().min(DELIVER_CHUNK)];
                while engine.read(&mut discarded) > 0 {}
                break;
            }
            let Ok(permit) = data_tx.try_reserve() else {
                break;
            };
            let mut tmp = vec![0u8; DELIVER_CHUNK];
            let n = engine.read(&mut tmp);
            if n == 0 {
                break;
            }
            tmp.truncate(n);
            permit.send(tmp);
        }

        // 3. Drain everything the engine wants to put on the wire and hand it
        // to the carrier as ordered bursts (the carrier amortizes route lookup,
        // pacing and per-cell locking across a run). ACKs emitted here see the
        // receive buffer after the app handoff above.
        //
        // A `WouldBlock` from the cell carrier is local backpressure (bounded
        // session TX queue full), not proof that the peer/path lost a packet.
        // The engine has reserved every polled DATA/FIN in its send window,
        // but network timing starts only when the carrier accepts that cell.
        // SYN/SYN_ACK timers use the same acceptance boundary.
        // Whatever the carrier does not accept stays queued in `outbound`.
        // Do not reserve more fresh DATA until that tail drains, but allow due
        // repairs/ACKs to precede it: otherwise a lost first response byte waits
        // for an entire locally blocked window before its repair is even polled.
        // A striped carrier can accept a non-prefix subset, so correlate cells.
        loop {
            let now = now_ms(&base);
            // An original may have reached the peer while its repair waited
            // here. Do not hand that stale repair to the carrier after SACK.
            outbound.retain(|cell| !engine.discard_received_cell(cell));
            if outbound.is_empty() && !engine.is_closed() {
                while outbound.len() < MAX_OUTBOUND_BURST - REPAIR_RESERVE
                    && engine.poll_transmit(now, &mut cell)
                {
                    outbound.push_back(cell.clone());
                }
            } else if !engine.is_closed() {
                let retained = outbound.len();
                while outbound.len() < MAX_OUTBOUND_BURST
                    && engine.poll_repair_transmit(now, &mut cell)
                {
                    outbound.push_back(cell.clone());
                }
                let urgent = outbound.len() - retained;
                outbound.rotate_right(urgent);
            }
            if outbound.is_empty() {
                break;
            }
            if send_retry_at.is_some_and(|at| now < at) {
                break;
            }
            let retrying = send_retry_at.is_some();
            local_transmits.clear();
            for cell in &outbound {
                if let Some(token) = LocalTransmit::from_cell(cell) {
                    *local_transmits.entry(token).or_default() += 1;
                }
            }
            let send_result = duplex.send_cells(&mut outbound).await;
            for cell in &outbound {
                if let Some(token) = LocalTransmit::from_cell(cell)
                    && let Some(count) = local_transmits.get_mut(&token)
                {
                    *count = count.saturating_sub(1);
                }
            }
            engine.local_handoff(&local_transmits, now_ms(&base));
            match send_result {
                Ok(()) => {
                    send_retry_at = None;
                    blocked_since_ms = None;
                    if retrying {
                        would_block_recovered = would_block_recovered.saturating_add(1);
                    }
                    if outbound.is_empty() {
                        // A paced carrier await can make the next send tick due.
                        // Poll inbound/commands/timers between accepted bursts;
                        // do not refill and drain an entire window before ACKs.
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    would_block_total = would_block_total.saturating_add(1);
                    if retrying {
                        would_block_retries = would_block_retries.saturating_add(1);
                    }
                    blocked_since_ms.get_or_insert(now);
                    // Route lookup itself may have awaited I/O. The suggested
                    // delay starts when that attempt returns, not before it.
                    send_retry_at = Some(now_ms(&base).saturating_add(send_retry_delay_ms(&e)));
                    break;
                }
                Err(_) => {
                    engine.reset(reset_reason::APP); // circuit permanently gone
                    break;
                }
            }
        }

        // 4. Both byte directions may be done while a final ACK is still
        // rejected by the local carrier. Retiring then strands the peer's FIN
        // or final credit. Keep retrying without inventing network loss, but
        // bound an unavailable carrier by the configured retry-policy ceiling.
        if engine.is_send_complete() && engine.is_eof() {
            if outbound.is_empty() {
                break;
            }
            let now = now_ms(&base);
            let deadline = close_handoff_deadline
                .get_or_insert_with(|| now.saturating_add(engine.close_handoff_timeout_ms()));
            if now >= *deadline {
                engine.reset(reset_reason::TIMED_OUT);
            }
        }
        if engine.is_closed() {
            break;
        }

        // 5. Block until the next thing happens.
        let mut timeout_at = engine.next_timeout_with_pacing(outbound.is_empty());
        if let Some(deadline) = close_handoff_deadline {
            timeout_at = Some(timeout_at.map_or(deadline, |t| t.min(deadline)));
        }
        if !outbound.is_empty()
            && let Some(retry_at) = send_retry_at
        {
            timeout_at = Some(timeout_at.map_or(retry_at, |t| t.min(retry_at)));
        }
        tokio::select! {
            biased;
            changed = reset_rx.changed(), if reset_open => {
                if changed.is_err() {
                    reset_open = false;
                } else if let Some(reason) = *reset_rx.borrow_and_update() {
                    // Never put cancellation behind DATA's high-water guard.
                    // Leave retained DATA unsent and use the final RST flush.
                    engine.reset(reason);
                    break;
                }
            }
            cmd = cmd_rx.recv(), if cmd_open && engine.send_buffer_len() < SEND_HIGH_WATER => {
                match cmd {
                    Some(AppCmd::Write(d)) => { engine.write(&d); }
                    Some(AppCmd::Finish) => { engine.finish(); }
                    None => { cmd_open = false; engine.finish(); } // handle dropped → finish send
                }
            }
            inbound = duplex.recv_cells(&mut rx_cells, MAX_RX_BURST) => {
                match inbound {
                    Ok(n) if n > 0 => {
                        let now = now_ms(&base);
                        for c in rx_cells.drain(..) { engine.on_cell(&c, now); }
                    }
                    Ok(_) | Err(_) => { engine.reset(reset_reason::TIMED_OUT); } // circuit closed
                }
            }
            () = wait_until(&base, timeout_at) => {
                let n = now_ms(&base);
                engine.on_timeout(n);
            }
            // Delivered bytes are stuck because `data_tx` was full — wake when the
            // app frees a slot so we can hand off the rest (without this, the
            // driver parks with read_buf > 0 and the close never completes).
            res = data_tx.reserve(), if engine.readable_len() > 0 => {
                match res {
                    Ok(permit) => {
                        let mut tmp = vec![0u8; DELIVER_CHUNK];
                        let n = engine.read(&mut tmp);
                        tmp.truncate(n);
                        if n > 0 {
                            permit.send(tmp);
                        }
                    }
                    Err(_) if cmd_rx.is_closed() => (), // whole handle dropped; drain above
                    Err(_) => engine.reset(reset_reason::APP), // reader-only drop
                }
            }
        }
    }

    // Final flush of anything already delivered, then settle the end state.
    let now = now_ms(&base);
    let _ = engine.poll_transmit(now, &mut cell); // best-effort: push a trailing RST/ACK
    if engine.is_closed() {
        let _ = duplex.send_cell(&cell).await;
    }
    let _ = set_end_if_open(
        &end,
        if engine.is_eof() {
            End::Eof
        } else {
            End::Reset(reset_reason::APP)
        },
    );
    let (btl_bw, rtt_min_ms, delivered) = engine.delivery_model();
    if btl_bw > 0 {
        duplex
            .on_stream_model(engine.stream_id(), btl_bw, rtt_min_ms, delivered)
            .await;
    }
    duplex
        .on_stream_closed(engine.stream_id(), end_of(&end))
        .await;
    // Dropping `data_tx` here makes the reader observe EOF/reset.
}

fn set_end(end: &Arc<Mutex<End>>, v: End) {
    let mut g = end.lock().unwrap_or_else(|p| p.into_inner());
    if *g == End::Open {
        *g = v;
    }
}
fn set_end_if_open(end: &Arc<Mutex<End>>, v: End) -> bool {
    let mut g = end.lock().unwrap_or_else(|p| p.into_inner());
    if *g == End::Open {
        *g = v;
        true
    } else {
        false
    }
}

/// Sleep until `at` (ms on `base`'s clock), or never if `None`.
async fn wait_until(base: &Instant, at: Option<u64>) {
    match at {
        Some(t) => {
            let now = base.elapsed().as_millis() as u64;
            tokio::time::sleep(Duration::from_millis(t.saturating_sub(now))).await;
        }
        None => pending::<()>().await,
    }
}
