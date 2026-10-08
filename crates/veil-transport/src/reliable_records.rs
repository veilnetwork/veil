//! Lossless opaque records for a separately authenticated ordered connection.
//!
//! The session must negotiate and authenticate the SAME transport before
//! creating this plane. There is no identity admission here. The only wire
//! field is a two-byte length; producer roles and priorities are absent.
//! Unlike `ordered_records`, this plane never expires or evicts a record.
//! Byte credits and FIFO backpressure bound both directions. An I/O failure
//! aborts pending writes explicitly; completed incoming records remain readable
//! before the terminal error. Owner retirement discards them instead.

use std::io;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU64, Ordering},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::BoxIoStream;

pub const RECORD_BUFFER_BYTES: usize = 64 * 1024;
pub const MAX_RECORD_BYTES: usize = RECORD_BUFFER_BYTES - 2;
const QUEUE_DEPTH: usize = 128;
const MIN_RECORD_CHARGE: usize = 64;

fn charge(bytes: usize) -> u32 {
    (bytes + 2).max(MIN_RECORD_CHARGE) as u32
}

struct Outgoing {
    wire: Vec<u8>,
    result: oneshot::Sender<io::Result<()>>,
    // Keep the credit through flush, including buffered plaintext acceptance.
    _bytes: OwnedSemaphorePermit,
}

struct Incoming {
    payload: Vec<u8>,
    _bytes: OwnedSemaphorePermit,
}

struct Inner {
    retired: CancellationToken,
    failed: CancellationToken,
    error: OnceLock<io::ErrorKind>,
    outgoing: mpsc::Sender<Outgoing>,
    incoming: Mutex<mpsc::Receiver<Incoming>>,
    tx_bytes: Arc<Semaphore>,
    rx_bytes: Arc<Semaphore>,
    completed: AtomicU64,
    received: AtomicU64,
}

impl Inner {
    fn fail(&self, kind: io::ErrorKind) {
        let _ = self.error.set(kind);
        self.failed.cancel();
    }

    fn terminal_error(&self) -> io::Error {
        let kind = if self.retired.is_cancelled() {
            io::ErrorKind::ConnectionAborted
        } else {
            *self.error.get().unwrap_or(&io::ErrorKind::BrokenPipe)
        };
        io::Error::new(kind, "reliable record connection closed")
    }

    fn discard_incoming(rx: &mut mpsc::Receiver<Incoming>) {
        rx.close();
        while rx.try_recv().is_ok() {}
    }
}

/// Observations of this connection's local I/O, not remote acknowledgements.
#[derive(Debug, Clone, Copy)]
pub struct RecordProgress {
    pub outgoing_buffered_bytes: usize,
    pub incoming_buffered_bytes: usize,
    pub completed_records: u64,
    pub received_records: u64,
}

/// Clones cannot prolong authorization or I/O after the owning plane retires.
#[derive(Clone)]
pub struct ReliableRecordHandle(Arc<Inner>);

impl ReliableRecordHandle {
    /// Wait for bounded admission and a successful complete write + flush.
    /// Once admitted, cancelling this future does NOT retract bytes: the
    /// writer finishes its record before any following prefix. The application
    /// must close its stream rather than retry uncertain bytes on that stream.
    pub async fn send(&self, payload: &[u8]) -> io::Result<()> {
        if payload.is_empty() || payload.len() > MAX_RECORD_BYTES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let credit = tokio::select! {
            biased;
            _ = self.0.retired.cancelled() => return Err(self.0.terminal_error()),
            _ = self.0.failed.cancelled() => return Err(self.0.terminal_error()),
            permit = self.0.tx_bytes.clone().acquire_many_owned(charge(payload.len())) =>
                permit.map_err(|_| self.0.terminal_error())?,
        };
        let slot = tokio::select! {
            biased;
            _ = self.0.retired.cancelled() => return Err(self.0.terminal_error()),
            _ = self.0.failed.cancelled() => return Err(self.0.terminal_error()),
            slot = self.0.outgoing.reserve() => slot.map_err(|_| self.0.terminal_error())?,
        };
        if self.0.retired.is_cancelled() || self.0.failed.is_cancelled() {
            return Err(self.0.terminal_error());
        }
        let mut wire = Vec::with_capacity(payload.len() + 2);
        wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        wire.extend_from_slice(payload);
        let (result, completion) = oneshot::channel();
        slot.send(Outgoing {
            wire,
            result,
            _bytes: credit,
        });
        tokio::select! {
            biased;
            _ = self.0.retired.cancelled() => Err(self.0.terminal_error()),
            result = completion => result.unwrap_or_else(|_| Err(self.0.terminal_error())),
        }
    }

    /// Cancellation-safe FIFO consumption. Transport EOF/errors drain complete
    /// records; canonical-owner retirement never exposes an old queued record.
    pub async fn recv(&self) -> io::Result<Vec<u8>> {
        let mut rx = tokio::select! {
            biased;
            _ = self.0.retired.cancelled() => return Err(self.0.terminal_error()),
            rx = self.0.incoming.lock() => rx,
        };
        let record = tokio::select! {
            biased;
            _ = self.0.retired.cancelled() => {
                Inner::discard_incoming(&mut rx);
                return Err(self.0.terminal_error());
            },
            record = rx.recv() => record,
        };
        if self.0.retired.is_cancelled() {
            Inner::discard_incoming(&mut rx);
            return Err(self.0.terminal_error());
        }
        record
            .map(|record| record.payload)
            .ok_or_else(|| self.0.terminal_error())
    }

    pub fn close(&self) {
        self.0.retired.cancel();
        if let Ok(mut rx) = self.0.incoming.try_lock() {
            Inner::discard_incoming(&mut rx);
        }
    }

    pub async fn closed(&self) {
        tokio::select! {
            biased;
            _ = self.0.retired.cancelled() => {},
            _ = self.0.failed.cancelled() => {},
        }
    }

    pub fn progress(&self) -> RecordProgress {
        RecordProgress {
            outgoing_buffered_bytes: RECORD_BUFFER_BYTES - self.0.tx_bytes.available_permits(),
            incoming_buffered_bytes: RECORD_BUFFER_BYTES - self.0.rx_bytes.available_permits(),
            completed_records: self.0.completed.load(Ordering::Relaxed),
            received_records: self.0.received.load(Ordering::Relaxed),
        }
    }
}

/// Owns both halves of a separately authenticated transport. No connection,
/// key or producer classification is chosen by this framing layer.
pub struct ReliableRecordPlane {
    handle: ReliableRecordHandle,
    tasks: [tokio::task::JoinHandle<()>; 2],
}

impl ReliableRecordPlane {
    pub fn new(stream: BoxIoStream) -> Self {
        let (outgoing, out_rx) = mpsc::channel(QUEUE_DEPTH);
        let (in_tx, incoming) = mpsc::channel(QUEUE_DEPTH);
        let handle = ReliableRecordHandle(Arc::new(Inner {
            retired: CancellationToken::new(),
            failed: CancellationToken::new(),
            error: OnceLock::new(),
            outgoing,
            incoming: Mutex::new(incoming),
            tx_bytes: Arc::new(Semaphore::new(RECORD_BUFFER_BYTES)),
            rx_bytes: Arc::new(Semaphore::new(RECORD_BUFFER_BYTES)),
            completed: AtomicU64::new(0),
            received: AtomicU64::new(0),
        }));
        let (read, write) = tokio::io::split(stream);
        let tasks = [
            tokio::spawn(read_records(read, in_tx, handle.clone())),
            tokio::spawn(write_records(write, out_rx, handle.clone())),
        ];
        Self { handle, tasks }
    }

    pub fn handle(&self) -> ReliableRecordHandle {
        self.handle.clone()
    }
}

impl Drop for ReliableRecordPlane {
    fn drop(&mut self) {
        self.handle.close();
        for task in &self.tasks {
            task.abort();
        }
    }
}

// Errors, panics and cancellation cannot leave the other I/O half or queued
// completion futures alive indefinitely. Owner retirement stays a distinct
// boundary so a transport EOF can preserve already completed receive records.
struct FailOnExit(ReliableRecordHandle);
impl Drop for FailOnExit {
    fn drop(&mut self) {
        self.0.0.fail(io::ErrorKind::BrokenPipe);
    }
}

async fn read_records<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    incoming: mpsc::Sender<Incoming>,
    handle: ReliableRecordHandle,
) {
    let _exit = FailOnExit(handle.clone());
    let reading = async {
        loop {
            let len = reader.read_u16().await? as usize;
            if len == 0 || len > MAX_RECORD_BYTES {
                return Err::<(), io::Error>(io::ErrorKind::InvalidData.into());
            }
            // Reserve before allocation/read. Saturation backpressures THIS
            // connection rather than expiring or discarding reliable bytes.
            let credit = handle
                .0
                .rx_bytes
                .clone()
                .acquire_many_owned(charge(len))
                .await
                .map_err(|_| handle.0.terminal_error())?;
            let slot = incoming
                .reserve()
                .await
                .map_err(|_| handle.0.terminal_error())?;
            let mut payload = vec![0; len];
            reader.read_exact(&mut payload).await?;
            slot.send(Incoming {
                payload,
                _bytes: credit,
            });
            handle.0.received.fetch_add(1, Ordering::Relaxed);
        }
    };
    let result = tokio::select! {
        biased;
        _ = handle.0.retired.cancelled() => return,
        _ = handle.0.failed.cancelled() => return,
        result = reading => result,
    };
    if let Err(error) = result {
        handle.0.fail(error.kind());
    }
}

async fn write_records<W: tokio::io::AsyncWrite + Unpin>(
    mut writer: W,
    mut outgoing: mpsc::Receiver<Outgoing>,
    handle: ReliableRecordHandle,
) {
    let _exit = FailOnExit(handle.clone());
    let writing = async {
        while let Some(record) = outgoing.recv().await {
            writer.write_all(&record.wire).await?;
            writer.flush().await?;
            handle.0.completed.fetch_add(1, Ordering::Relaxed);
            let _ = record.result.send(Ok(()));
        }
        Ok::<(), io::Error>(())
    };
    let result = tokio::select! {
        biased;
        _ = handle.0.retired.cancelled() => return,
        _ = handle.0.failed.cancelled() => return,
        result = writing => result,
    };
    if let Err(error) = result {
        handle.0.fail(error.kind());
    }
}

#[cfg(test)]
#[path = "reliable_records_tests.rs"]
mod tests;
