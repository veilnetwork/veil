//! Bounded loss-tolerant opaque records on an independent ordered transport.
//!
//! This is framing, not identity admission or an application protocol. The
//! session must negotiate it and verify its canonical-parent proof BEFORE
//! constructing the plane. Payloads remain independently authenticated by the
//! existing session codec. The only framing field is a two-byte length inside
//! the encrypted transport: no producer role, priority or deadline is sent.
//! Every incoming record has the SAME local residence bound and oldest-first
//! eviction policy. This codec must never carry ordinary reliable messages.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use crate::BoxIoStream;

pub const MAX_RECORD_BYTES: usize = 1200;
pub const RECORD_BUFFER_BYTES: usize = crate::REALTIME_DATAGRAM_BUFFER_BYTES;
// Bound tiny-record metadata as well as payload bytes. At most 1638 admitted
// records can exist, including the record currently being written.
const MIN_RECORD_CHARGE: usize = 40;
const WRITE_COMPLETION_TIMEOUT: Duration = Duration::from_secs(30);
pub const RECORD_RECEIVE_MAX_AGE: Duration = Duration::from_millis(200);

/// Exact local queue reservation, including the framing prefix and the tiny
/// record metadata floor. Session admission must use this rather than payload
/// length alone; it is not a wire bandwidth or delivery acknowledgement.
pub fn record_queue_charge(payload_bytes: usize) -> usize {
    payload_bytes.saturating_add(2).max(MIN_RECORD_CHARGE)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecordSendError {
    #[error("record length outside negotiated bounds")]
    TooLarge,
    #[error("record queue full")]
    Full,
    #[error("record plane closed")]
    Closed,
    #[error("record expired before admission")]
    Expired,
}

struct Record {
    wire: Vec<u8>,
    expires_at: Option<Instant>,
    // Retained through the final flush, not released on queue dequeue or on
    // plaintext acceptance by a buffered transport.
    _bytes: OwnedSemaphorePermit,
}

#[derive(Default)]
struct Progress {
    active_since: Option<Instant>,
    completed: u64,
    expired: u64,
    received: u64,
    dropped_incoming: u64,
    expired_incoming: u64,
}

struct ReceivedRecord {
    bytes: Vec<u8>,
    queued_at: Instant,
    charge: usize,
}

#[derive(Default)]
struct Incoming {
    records: VecDeque<ReceivedRecord>,
    reserved_bytes: usize,
}

impl Incoming {
    fn expire(&mut self, now: Instant, max_age: Duration) -> u64 {
        let mut expired = 0;
        while self
            .records
            .front()
            .is_some_and(|r| now.saturating_duration_since(r.queued_at) >= max_age)
        {
            let record = self.records.pop_front().unwrap();
            self.reserved_bytes -= record.charge;
            expired += 1;
        }
        expired
    }
}

struct Inner {
    closed: CancellationToken,
    capacity: Arc<Semaphore>,
    outgoing: mpsc::UnboundedSender<Record>,
    incoming: Mutex<Incoming>,
    receive_ready: tokio::sync::Notify,
    receive_max_age: Duration,
    progress: Mutex<Progress>,
}

/// Local writer observations, not delivery acknowledgements or TCP RTT.
#[derive(Debug, Clone, Copy)]
pub struct RecordProgress {
    pub reserved_bytes: usize,
    pub active_record_age: Option<Duration>,
    pub completed_records: u64,
    pub expired_records: u64,
    pub incoming_buffered_bytes: usize,
    pub received_records: u64,
    pub dropped_incoming_records: u64,
    pub expired_incoming_records: u64,
}

/// Clones cannot keep a plane alive after its owning session/channel drops it.
#[derive(Clone)]
pub struct OrderedRecordHandle(Arc<Inner>);

impl OrderedRecordHandle {
    pub fn max_size(&self) -> Option<usize> {
        (!self.0.closed.is_cancelled()).then_some(MAX_RECORD_BYTES)
    }

    pub fn send_buffer_space(&self) -> usize {
        if self.0.closed.is_cancelled() {
            0
        } else {
            self.0.capacity.available_permits()
        }
    }

    /// Admission only. In-flight TCP bytes cannot be retracted or expired.
    pub fn send(&self, payload: &[u8]) -> Result<(), RecordSendError> {
        self.enqueue(payload, None)
    }

    /// A local monotonic deadline, enforced before writing any record bytes.
    pub fn send_before(&self, payload: &[u8], expires_at: Instant) -> Result<(), RecordSendError> {
        self.enqueue(payload, Some(expires_at))
    }

    fn enqueue(&self, payload: &[u8], expires_at: Option<Instant>) -> Result<(), RecordSendError> {
        if self.0.closed.is_cancelled() {
            return Err(RecordSendError::Closed);
        }
        if payload.is_empty() || payload.len() > MAX_RECORD_BYTES {
            return Err(RecordSendError::TooLarge);
        }
        if expires_at.is_some_and(|at| at <= Instant::now()) {
            return Err(RecordSendError::Expired);
        }
        let charge = record_queue_charge(payload.len()) as u32;
        let permit = Arc::clone(&self.0.capacity)
            .try_acquire_many_owned(charge)
            .map_err(|_| RecordSendError::Full)?;
        // One plaintext write avoids turning the tiny length prefix into a
        // separately padded obfs4 frame. Framing overhead stays role-neutral.
        let mut wire = Vec::with_capacity(payload.len() + 2);
        wire.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        wire.extend_from_slice(payload);
        self.0
            .outgoing
            .send(Record {
                wire,
                expires_at,
                _bytes: permit,
            })
            .map_err(|_| RecordSendError::Closed)
    }

    /// Cancel-safe: losing a select branch never consumes a queued record.
    /// A closed plane does not drain old buffered data to a retired session.
    pub async fn recv(&self) -> io::Result<Vec<u8>> {
        loop {
            let ready = self.0.receive_ready.notified();
            tokio::pin!(ready);
            // Register before inspecting the queue, including concurrent
            // readers; this prevents a lost wakeup between check and await.
            ready.as_mut().enable();
            {
                let mut q = self.0.incoming.lock().unwrap_or_else(|e| e.into_inner());
                if self.0.closed.is_cancelled() {
                    return Err(closed_error());
                }
                let expired = q.expire(Instant::now(), self.0.receive_max_age);
                if expired != 0 {
                    let mut p = self.0.progress.lock().unwrap_or_else(|e| e.into_inner());
                    p.expired_incoming = p.expired_incoming.saturating_add(expired);
                }
                if let Some(record) = q.records.pop_front() {
                    q.reserved_bytes -= record.charge;
                    return Ok(record.bytes);
                }
            }
            tokio::select! {
                biased;
                _ = self.0.closed.cancelled() => return Err(closed_error()),
                _ = &mut ready => {},
            }
        }
    }

    pub fn close(&self) {
        self.0.closed.cancel();
        let mut q = self.0.incoming.lock().unwrap_or_else(|e| e.into_inner());
        q.records.clear();
        q.reserved_bytes = 0;
    }

    pub async fn closed(&self) {
        self.0.closed.cancelled().await;
    }

    pub fn progress(&self) -> RecordProgress {
        // Keep the same incoming→progress lock order as the receive worker.
        let q = self.0.incoming.lock().unwrap_or_else(|e| e.into_inner());
        let p = self.0.progress.lock().unwrap_or_else(|e| e.into_inner());
        RecordProgress {
            reserved_bytes: RECORD_BUFFER_BYTES - self.0.capacity.available_permits(),
            active_record_age: p.active_since.map(|at| at.elapsed()),
            completed_records: p.completed,
            expired_records: p.expired,
            incoming_buffered_bytes: q.reserved_bytes,
            received_records: p.received,
            dropped_incoming_records: p.dropped_incoming,
            expired_incoming_records: p.expired_incoming,
        }
    }
}

/// Owns the stream and both I/O tasks. Dropping the owner cancels the complete
/// child, even if handles or an in-flight read are retained elsewhere.
pub struct OrderedRecordPlane {
    handle: OrderedRecordHandle,
    tasks: [tokio::task::JoinHandle<()>; 2],
}

impl OrderedRecordPlane {
    /// Use only after mutual canonical-session authentication and explicit
    /// negotiation. This constructor neither verifies nor grants identity.
    pub fn new(stream: BoxIoStream) -> Self {
        Self::with_write_timeout(stream, WRITE_COMPLETION_TIMEOUT)
    }

    fn with_write_timeout(stream: BoxIoStream, write_timeout: Duration) -> Self {
        Self::with_timeouts(stream, write_timeout, RECORD_RECEIVE_MAX_AGE)
    }

    fn with_timeouts(
        stream: BoxIoStream,
        write_timeout: Duration,
        receive_max_age: Duration,
    ) -> Self {
        let (outgoing, out_rx) = mpsc::unbounded_channel();
        let handle = OrderedRecordHandle(Arc::new(Inner {
            closed: CancellationToken::new(),
            capacity: Arc::new(Semaphore::new(RECORD_BUFFER_BYTES)),
            outgoing,
            incoming: Mutex::default(),
            receive_ready: tokio::sync::Notify::new(),
            receive_max_age,
            progress: Mutex::default(),
        }));
        let (read, write) = tokio::io::split(stream);
        let tasks = [
            tokio::spawn(read_records(read, handle.clone())),
            tokio::spawn(write_records(write, out_rx, handle.clone(), write_timeout)),
        ];
        Self { handle, tasks }
    }

    pub fn handle(&self) -> OrderedRecordHandle {
        self.handle.clone()
    }
}

impl Drop for OrderedRecordPlane {
    fn drop(&mut self) {
        self.handle.close();
        for task in &self.tasks {
            task.abort();
        }
    }
}

// Any EOF, error, task cancellation or panic closes both halves and wakes
// queued readers. A partial record is never abandoned on a still-live stream.
struct CloseOnExit(OrderedRecordHandle);
impl Drop for CloseOnExit {
    fn drop(&mut self) {
        self.0.close();
        self.0
            .0
            .progress
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active_since = None;
    }
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "record plane closed")
}

async fn read_records<R: tokio::io::AsyncRead + Unpin>(mut reader: R, handle: OrderedRecordHandle) {
    let _close = CloseOnExit(handle.clone());
    let reading = async {
        loop {
            let len = reader.read_u16().await? as usize;
            if len == 0 || len > MAX_RECORD_BYTES {
                return Err::<(), io::Error>(io::ErrorKind::InvalidData.into());
            }
            let mut bytes = vec![0; len];
            reader.read_exact(&mut bytes).await?;
            {
                let mut q = handle.0.incoming.lock().unwrap_or_else(|e| e.into_inner());
                if handle.0.closed.is_cancelled() {
                    return Err(closed_error());
                }
                let now = Instant::now();
                let expired = q.expire(now, handle.0.receive_max_age);
                let charge = record_queue_charge(bytes.len());
                let mut dropped = 0u64;
                // Loss-tolerant input must stay fresh rather than stop reading
                // TCP and retain obsolete records upstream. Every record is
                // treated identically; no role or priority is inspected.
                while q.reserved_bytes + charge > RECORD_BUFFER_BYTES {
                    let oldest = q
                        .records
                        .pop_front()
                        .expect("bounded record fits empty queue");
                    q.reserved_bytes -= oldest.charge;
                    dropped += 1;
                }
                q.reserved_bytes += charge;
                q.records.push_back(ReceivedRecord {
                    bytes,
                    queued_at: now,
                    charge,
                });
                let mut p = handle.0.progress.lock().unwrap_or_else(|e| e.into_inner());
                p.received = p.received.saturating_add(1);
                p.expired_incoming = p.expired_incoming.saturating_add(expired);
                p.dropped_incoming = p.dropped_incoming.saturating_add(dropped);
            }
            handle.0.receive_ready.notify_one();
        }
    };
    tokio::select! {
        biased;
        _ = handle.closed() => {},
        _ = reading => {},
    }
}

async fn write_records<W: tokio::io::AsyncWrite + Unpin>(
    mut writer: W,
    mut outgoing: mpsc::UnboundedReceiver<Record>,
    handle: OrderedRecordHandle,
    write_timeout: Duration,
) {
    let _close = CloseOnExit(handle.clone());
    let writing = async {
        while let Some(record) = outgoing.recv().await {
            if record.expires_at.is_some_and(|at| at <= Instant::now()) {
                let mut p = handle.0.progress.lock().unwrap_or_else(|e| e.into_inner());
                p.expired = p.expired.saturating_add(1);
                continue;
            }
            handle
                .0
                .progress
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .active_since = Some(Instant::now());
            let write = async {
                // Cancellation for expiry is safe ONLY before the first
                // successful write: Pending consumed no bytes. Once even one
                // prefix byte is accepted, finish this record or close the
                // entire child. Otherwise subsequent framing is corrupted.
                let first = match record.expires_at {
                    Some(at) => tokio::select! {
                        biased;
                        _ = tokio::time::sleep_until(at.into()) => return Ok(false),
                        result = writer.write(&record.wire) => result?,
                    },
                    None => writer.write(&record.wire).await?,
                };
                if first == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                writer.write_all(&record.wire[first..]).await?;
                writer.flush().await?;
                Ok::<_, io::Error>(true)
            };
            // Timeout/cancellation ends this entire connection; never resume
            // with another prefix after a possibly partial record write.
            let complete = match tokio::time::timeout(write_timeout, write).await {
                Ok(Ok(complete)) => complete,
                _ => return,
            };
            let mut p = handle.0.progress.lock().unwrap_or_else(|e| e.into_inner());
            p.active_since = None;
            if complete {
                p.completed = p.completed.saturating_add(1);
            } else {
                p.expired = p.expired.saturating_add(1);
            }
        }
    };
    tokio::select! {
        biased;
        _ = handle.closed() => {},
        _ = writing => {},
    }
}

#[cfg(test)]
#[path = "ordered_records_tests.rs"]
mod tests;
