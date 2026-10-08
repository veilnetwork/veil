//! Cipher ownership for a separately authenticated, lossless child.
//!
//! Producers publish plaintext into a bounded FIFO. Only its single writer
//! advances the child's implicit nonce, after admission commits. Cancelling a
//! receipt cannot retract an already admitted frame or burn a nonce without
//! sending it. Local source credit remains attached through complete flush.
//! This is carrier machinery, not a stream-routing or capability policy.

use crate::{
    frame_outbox::FrameEnvelope,
    parallel_binding::{BoundReliableChannel, BoundReliableHandle},
};
use std::{
    io,
    sync::{Arc, OnceLock},
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use veil_crypto::session_cipher::{AEAD_OVERHEAD, SessionCipher};
use veil_proto::{
    codec::{decode_header, encode_header, frame_aad},
    header::HEADER_SIZE,
};
use veil_transport::reliable_records::{MAX_RECORD_BYTES, RECORD_BUFFER_BYTES};

const QUEUE_DEPTH: usize = 64;
const MIN_CHARGE: usize = 64;

enum Owner {
    Outgoing(BoundReliableChannel),
    Incoming(crate::runner::RegisteredReliableChannel),
}

impl Owner {
    fn keys(&self) -> &crate::parallel_binding::ParallelKeys {
        match self {
            Self::Outgoing(c) => &c.keys,
            Self::Incoming(c) => c.keys(),
        }
    }
    fn handle(&self) -> BoundReliableHandle {
        match self {
            Self::Outgoing(c) => c.handle(),
            Self::Incoming(c) => c.handle(),
        }
    }
}

struct Pending {
    envelope: FrameEnvelope,
    completion: oneshot::Sender<io::Result<()>>,
    _bytes: OwnedSemaphorePermit,
}

struct Inner {
    transport: BoundReliableHandle,
    queue: mpsc::Sender<Pending>,
    bytes: Arc<Semaphore>,
    error: OnceLock<io::ErrorKind>,
    rx: Mutex<SessionCipher>,
}

impl Inner {
    fn mark_failed(&self, kind: io::ErrorKind) {
        let _ = self.error.set(kind);
        self.bytes.close();
    }
    fn fail(&self, kind: io::ErrorKind) {
        self.mark_failed(kind);
        self.transport.close();
    }
    fn error(&self) -> io::Error {
        io::Error::new(
            *self
                .error
                .get()
                .unwrap_or(&io::ErrorKind::ConnectionAborted),
            "reliable frame channel closed",
        )
    }
}

/// An admission failure returns the original plaintext and its local credits.
/// The caller can keep its FIFO position. It must never switch an established
/// stream's carrier merely because this queue is full.
pub enum FrameAdmissionError {
    Full(FrameEnvelope),
    Closed(FrameEnvelope),
    Invalid(FrameEnvelope),
}

/// Completion is the local transport's complete write and flush, not a peer
/// acknowledgement. Dropping this receipt does not cancel admitted data.
pub struct FrameReceipt(oneshot::Receiver<io::Result<()>>);

impl FrameReceipt {
    pub async fn wait(self) -> io::Result<()> {
        self.0
            .await
            .unwrap_or_else(|_| Err(io::ErrorKind::ConnectionAborted.into()))
    }
}

#[derive(Clone)]
pub struct ReliableFrameHandle(Arc<Inner>);

impl ReliableFrameHandle {
    pub fn try_send(&self, envelope: FrameEnvelope) -> Result<FrameReceipt, FrameAdmissionError> {
        // Authorization does not wait for a watcher task to observe rekey or
        // canonical-owner retirement. Retained handles cannot admit new work.
        if !self.0.transport.parent_active() {
            self.0.fail(io::ErrorKind::ConnectionAborted);
            return Err(FrameAdmissionError::Closed(envelope));
        }
        let plain = &envelope.frame.1;
        if plain.len() + AEAD_OVERHEAD > MAX_RECORD_BYTES
            || !decode_header(plain).is_ok_and(|h| h.body_len as usize + HEADER_SIZE == plain.len())
        {
            return Err(FrameAdmissionError::Invalid(envelope));
        }
        if self.0.bytes.is_closed() {
            return Err(FrameAdmissionError::Closed(envelope));
        }
        let slot = match self.0.queue.try_reserve() {
            Ok(slot) => slot,
            Err(mpsc::error::TrySendError::Full(_)) => {
                return Err(FrameAdmissionError::Full(envelope));
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(FrameAdmissionError::Closed(envelope));
            }
        };
        let charge = (plain.len() + AEAD_OVERHEAD + 2).max(MIN_CHARGE) as u32;
        let credit = match self.0.bytes.clone().try_acquire_many_owned(charge) {
            Ok(credit) => credit,
            Err(tokio::sync::TryAcquireError::Closed) => {
                return Err(FrameAdmissionError::Closed(envelope));
            }
            Err(tokio::sync::TryAcquireError::NoPermits) => {
                return Err(FrameAdmissionError::Full(envelope));
            }
        };
        let (completion, receipt) = oneshot::channel();
        slot.send(Pending {
            envelope,
            completion,
            _bytes: credit,
        });
        Ok(FrameReceipt(receipt))
    }

    /// Each receive keeps one RX cipher lock through cancellation-safe record
    /// consumption and synchronous authentication. Cancellation before a record
    /// arrives consumes neither a record nor its nonce. There is no await between
    /// consumption and cipher advancement.
    pub async fn recv(&self) -> io::Result<veil_bufpool::PooledShared> {
        let mut cipher = self.0.rx.lock().await;
        let wire = match self.0.transport.recv().await {
            Ok(wire) => wire,
            Err(e) => {
                self.0.mark_failed(e.kind());
                return Err(e);
            }
        };
        let decoded = (|| {
            let mut h = decode_header(&wire).map_err(|_| io::ErrorKind::InvalidData)?;
            if h.body_len as usize + HEADER_SIZE != wire.len() || h.body_len < AEAD_OVERHEAD as u32
            {
                return Err(io::ErrorKind::InvalidData);
            }
            let body = cipher
                .open(&wire[HEADER_SIZE..], &frame_aad(&h))
                .map_err(|_| io::ErrorKind::InvalidData)?;
            h.body_len = body.len() as u32;
            let mut plain = veil_bufpool::global().acquire(HEADER_SIZE + body.len());
            plain.as_vec_mut().extend_from_slice(&encode_header(&h));
            plain.as_vec_mut().extend_from_slice(&body);
            Ok(plain.into_shared())
        })();
        decoded.map_err(|kind| {
            self.0.fail(kind);
            io::Error::from(kind)
        })
    }

    pub fn close(&self) {
        self.0.fail(io::ErrorKind::ConnectionAborted);
    }
    pub async fn closed(&self) {
        self.0.transport.closed().await;
    }
    pub fn buffered_bytes(&self) -> usize {
        RECORD_BUFFER_BYTES - self.0.bytes.available_permits()
    }
}

/// Owns child credentials, actual transport lifetime and the sole TX cipher.
/// Retained producer handles cannot keep it authorized after owner retirement.
pub struct ReliableFrameChannel {
    handle: ReliableFrameHandle,
    _owner: Owner,
    writer: tokio::task::JoinHandle<()>,
}

impl ReliableFrameChannel {
    pub fn new(channel: BoundReliableChannel) -> Self {
        Self::from_owner(Owner::Outgoing(channel))
    }
    pub fn from_registered(channel: crate::runner::RegisteredReliableChannel) -> Self {
        Self::from_owner(Owner::Incoming(channel))
    }
    fn from_owner(owner: Owner) -> Self {
        let tx = SessionCipher::new(owner.keys().tx_key(), true);
        let rx = SessionCipher::new(owner.keys().rx_key(), true);
        let (queue, incoming) = mpsc::channel(QUEUE_DEPTH);
        let inner = Arc::new(Inner {
            transport: owner.handle(),
            queue,
            rx: Mutex::new(rx),
            bytes: Arc::new(Semaphore::new(RECORD_BUFFER_BYTES)),
            error: OnceLock::new(),
        });
        let writer = tokio::spawn(write_frames(inner.clone(), incoming, tx));
        Self {
            handle: ReliableFrameHandle(inner),
            _owner: owner,
            writer,
        }
    }
    pub fn handle(&self) -> ReliableFrameHandle {
        self.handle.clone()
    }
}

impl Drop for ReliableFrameChannel {
    fn drop(&mut self) {
        self.handle.close();
        self.writer.abort();
    }
}

struct FailOnExit {
    inner: Arc<Inner>,
    armed: bool,
}
impl Drop for FailOnExit {
    fn drop(&mut self) {
        if self.armed {
            self.inner.fail(io::ErrorKind::ConnectionAborted);
        }
    }
}

async fn write_frames(
    inner: Arc<Inner>,
    mut incoming: mpsc::Receiver<Pending>,
    mut cipher: SessionCipher,
) {
    let mut on_exit = FailOnExit {
        inner: inner.clone(),
        armed: true,
    };
    loop {
        let pending = tokio::select! {
            biased;
            _ = inner.transport.closed() => { inner.mark_failed(io::ErrorKind::ConnectionAborted); break },
            pending = incoming.recv() => match pending { Some(pending) => pending, None => break },
        };
        // No producer future can cancel this committed plaintext after sealing.
        let Some(wire) = crate::runner::apply_tx_cipher(&pending.envelope.frame.1, &mut cipher)
        else {
            inner.fail(io::ErrorKind::InvalidData);
            let _ = pending.completion.send(Err(inner.error()));
            break;
        };
        let result = inner.transport.send(&wire).await;
        let failed = result.is_err();
        if let Err(e) = &result {
            inner.mark_failed(e.kind());
        }
        // Keep both actor byte budget and endpoint source credit through flush.
        let _ = pending.completion.send(result);
        drop(pending.envelope);
        drop(pending._bytes);
        if failed {
            break;
        }
    }
    incoming.close();
    while let Ok(pending) = incoming.try_recv() {
        let _ = pending.completion.send(Err(inner.error()));
    }
    // Ordinary transport failure must preserve already completed RX records.
    // Explicit retirement and panics close the plane and discard them.
    on_exit.armed = false;
}

#[cfg(test)]
#[path = "reliable_frames_tests.rs"]
mod tests;
