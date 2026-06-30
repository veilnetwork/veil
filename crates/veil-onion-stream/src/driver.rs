//! Async driver: turns the sans-IO [`StreamEngine`] into a usable bidirectional
//! byte-stream over a [`CellDuplex`] (the cell carrier — a real onion circuit in
//! production, an in-memory pipe in tests). One tokio task owns the engine + the
//! duplex and pumps: app writes/reads ⇄ engine ⇄ circuit cells, on a real
//! monotonic clock. The app talks to it through [`OnionStream`].

use std::future::{Future, pending};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;
// tokio's monotonic clock (NOT std::time::Instant): it honours `start_paused`'s
// virtual time in tests, so the engine's clock and the driver's sleeps share one
// timeline. In production it is the real monotonic clock.
use tokio::time::Instant;

use crate::engine::{Config, Event, StreamEngine};
use crate::wire::reset_reason;

/// The cell carrier the stream rides. Best-effort + lossy: `send_cell` may be
/// dropped downstream (the engine's ARQ repairs it); `Err` means a PERMANENT
/// failure (circuit torn down). `recv_cell` returns `None` on clean close.
pub trait CellDuplex: Send {
    fn send_cell(&mut self, cell: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
    fn recv_cell(&mut self) -> impl Future<Output = io::Result<Option<Vec<u8>>>> + Send;
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
    Reset(u8),
}

/// App-facing handle to a reliable onion byte-stream. The sender uses
/// [`write_all`](Self::write_all) + [`finish`](Self::finish); the receiver uses
/// [`read`](Self::read) until it returns 0 (EOF) or errors (reset → resume).
pub struct OnionStream {
    cmd_tx: mpsc::Sender<AppCmd>,
    data_rx: mpsc::Receiver<Vec<u8>>,
    residual: Vec<u8>,
    end: Arc<Mutex<End>>,
}

impl OnionStream {
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
        let (data_tx, data_rx) = mpsc::channel(16);
        let end = Arc::new(Mutex::new(End::Open));
        tokio::spawn(drive(engine, duplex, cmd_rx, data_tx, end.clone()));
        OnionStream {
            cmd_tx,
            data_rx,
            residual: Vec::new(),
            end,
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
        let _ = self.cmd_tx.send(AppCmd::Reset(reason)).await;
    }

    /// Read up to `buf.len()` delivered bytes. `Ok(0)` = clean EOF; an
    /// `Err(ConnectionReset)` = the stream was aborted (the app should resume).
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        pull(&mut self.data_rx, &mut self.residual, &self.end, buf).await
    }

    /// Current end state (Open / Eof / Reset).
    pub fn end_reason(&self) -> End {
        end_of(&self.end)
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
            },
            OnionWriter {
                cmd_tx: self.cmd_tx,
                end: self.end,
            },
        )
    }
}

/// Read half of a split [`OnionStream`].
pub struct OnionReader {
    data_rx: mpsc::Receiver<Vec<u8>>,
    residual: Vec<u8>,
    end: Arc<Mutex<End>>,
}
impl OnionReader {
    /// See [`OnionStream::read`].
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        pull(&mut self.data_rx, &mut self.residual, &self.end, buf).await
    }
    pub fn end_reason(&self) -> End {
        end_of(&self.end)
    }
}

/// Write half of a split [`OnionStream`].
pub struct OnionWriter {
    cmd_tx: mpsc::Sender<AppCmd>,
    end: Arc<Mutex<End>>,
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
        let _ = self.cmd_tx.send(AppCmd::Reset(reason)).await;
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
    buf: &mut [u8],
) -> io::Result<usize> {
    if residual.is_empty() {
        match data_rx.recv().await {
            Some(chunk) => *residual = chunk,
            None => {
                return match end_of(end) {
                    End::Reset(r) => Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("onion stream reset ({r})"),
                    )),
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

fn broken() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "onion stream driver gone")
}

/// Stop accepting new app writes once this many bytes are buffered unsent
/// (send-side back-pressure; the bounded cmd channel then stalls `write_all`).
const SEND_HIGH_WATER: usize = 4 << 20;
/// Chunk size for moving delivered bytes out of the engine to the reader.
const DELIVER_CHUNK: usize = 256 * 1024;

async fn drive<D: CellDuplex>(
    mut engine: StreamEngine,
    mut duplex: D,
    mut cmd_rx: mpsc::Receiver<AppCmd>,
    data_tx: mpsc::Sender<Vec<u8>>,
    end: Arc<Mutex<End>>,
) {
    let base = Instant::now();
    let now_ms = |b: &Instant| b.elapsed().as_millis() as u64;
    let mut cmd_open = true;
    let mut cell = Vec::with_capacity(crate::wire::MAX_CELL);
    let mut last_debug_ms = 0u64;
    loop {
        let now = now_ms(&base);
        if now.saturating_sub(last_debug_ms) >= 2_000
            && (engine.send_buffer_len() > 0 || engine.readable_len() > 0)
        {
            last_debug_ms = now;
            log::warn!(
                "onion-stream-driver: send_buf={} readable={} {}",
                engine.send_buffer_len(),
                engine.readable_len(),
                engine.debug_summary()
            );
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
                Event::Connected => {}
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

        // 3. Drain everything the engine wants to put on the wire. ACKs emitted
        // here now see the receive buffer after the app handoff above.
        while engine.poll_transmit(now, &mut cell) {
            if duplex.send_cell(&cell).await.is_err() {
                engine.reset(reset_reason::APP); // circuit permanently gone
                break;
            }
        }

        // 4. Done? Terminal RST, or both directions cleanly finished.
        if engine.is_closed() || (engine.is_send_complete() && engine.is_eof()) {
            break;
        }

        // 5. Block until the next thing happens.
        let timeout_at = engine.next_timeout();
        tokio::select! {
            biased;
            cmd = cmd_rx.recv(), if cmd_open && engine.send_buffer_len() < SEND_HIGH_WATER => {
                match cmd {
                    Some(AppCmd::Write(d)) => { engine.write(&d); }
                    Some(AppCmd::Finish) => { engine.finish(); }
                    Some(AppCmd::Reset(r)) => { engine.reset(r); }
                    None => { cmd_open = false; engine.finish(); } // handle dropped → finish send
                }
            }
            inbound = duplex.recv_cell() => {
                match inbound {
                    Ok(Some(c)) => { let n = now_ms(&base); engine.on_cell(&c, n); }
                    Ok(None) | Err(_) => { engine.reset(reset_reason::TIMED_OUT); } // circuit closed
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
                    Err(_) => engine.reset(reset_reason::APP), // app stopped reading
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
    if set_end_if_open(
        &end,
        if engine.is_eof() {
            End::Eof
        } else {
            End::Reset(reset_reason::APP)
        },
    ) {}
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
