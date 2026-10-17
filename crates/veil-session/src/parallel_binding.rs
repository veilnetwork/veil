//! Mutual binding of a generic auxiliary transport to a live session.
//!
//! SessionRunner authenticates exactly once per connection, bounds sibling
//! slots, and retires the owner on close/rekey/replacement. It must not install
//! a sibling in the canonical peer registry or advertise it as another node.
//! No audio/video role or scheduling request occurs in either proof.

use rand::RngCore;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) const PREFACE: &[u8; 8] = b"VPAUX001";
pub(crate) const RELIABLE_PREFACE: &[u8; 8] = b"VPAUX002";
pub const HELLO_BYTES: usize = 104;

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecordMode {
    LossTolerant,
    Reliable,
}

impl RecordMode {
    fn preface(self) -> &'static [u8; 8] {
        match self {
            Self::LossTolerant => PREFACE,
            Self::Reliable => RELIABLE_PREFACE,
        }
    }
    fn domain(self, phase: &str) -> &'static [u8] {
        match (self, phase) {
            (Self::LossTolerant, "hello") => b"veil/parallel/hello/v1",
            (Self::LossTolerant, "ack") => b"veil/parallel/ack/v1",
            (Self::LossTolerant, "key") => b"veil/parallel/key/v1",
            (Self::Reliable, "hello") => b"veil/parallel/reliable/hello/v1",
            (Self::Reliable, "ack") => b"veil/parallel/reliable/ack/v1",
            (Self::Reliable, "key") => b"veil/parallel/reliable/key/v1",
            _ => unreachable!("fixed proof phase"),
        }
    }
}

struct Parent {
    session_id: [u8; 32],
    tx: Zeroizing<[u8; 32]>,
    rx: Zeroizing<[u8; 32]>,
    active: AtomicBool,
    retired: tokio::sync::watch::Sender<bool>,
}

/// Owns credentials copied from an authenticated canonical session. Dropping
/// this owner retires all cloned handles and pending proofs automatically.
/// The canonical session must keep this owner, never an auxiliary task.
pub struct ParallelParent {
    handle: ParallelParentHandle,
}

impl std::ops::Deref for ParallelParent {
    type Target = ParallelParentHandle;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl Drop for ParallelParent {
    fn drop(&mut self) {
        self.handle.retire();
    }
}

/// A borrowed lifetime in owned form: cloning this handle keeps key storage
/// alive, but cannot prolong the canonical owner's authorization.
#[derive(Clone)]
pub struct ParallelParentHandle(Arc<Parent>);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BindingError {
    #[error("parallel channel parent retired")]
    Retired,
    #[error("invalid parallel channel proof")]
    InvalidProof,
}

/// Independently derived keys: sequence zero is safe on this child, rather
/// than reusing the parent's key/nonce space. Debug never prints key material.
pub struct ParallelKeys {
    pub session_id: [u8; 32],
    tx: Zeroizing<[u8; 32]>,
    rx: Zeroizing<[u8; 32]>,
    parent: ParallelParentHandle,
    mode: RecordMode,
    exporter: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for ParallelKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParallelKeys")
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl ParallelKeys {
    pub fn tx_key(&self) -> &[u8; 32] {
        &self.tx
    }
    pub fn rx_key(&self) -> &[u8; 32] {
        &self.rx
    }

    /// Start the explicitly negotiated ordered record codec only after this
    /// connection's mutual proof is finished. The caller transfers the SAME
    /// child stream whose fresh exporter was used for that proof.
    pub fn into_ordered(
        self,
        stream: veil_transport::BoxIoStream,
    ) -> Result<BoundOrderedChannel, BindingError> {
        self.parent.check_active()?;
        if self.mode != RecordMode::LossTolerant {
            return Err(BindingError::InvalidProof);
        }
        let plane = veil_transport::ordered_records::OrderedRecordPlane::new(stream);
        let handle = plane.handle();
        let parent = self.parent.clone();
        let lifetime = tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = parent.retired() => handle.close(),
                _ = handle.closed() => {},
            }
        });
        Ok(BoundOrderedChannel {
            keys: self,
            plane,
            lifetime,
        })
    }

    /// Lossless framing is a separately authenticated protocol mode, not a
    /// local reinterpretation of an existing expiring child. Use only after
    /// explicit peer negotiation and the reliable-mode mutual proof.
    pub fn into_reliable(
        self,
        stream: veil_transport::BoxIoStream,
    ) -> Result<BoundReliableChannel, BindingError> {
        self.into_reliable_inner(stream, ReliableTransportOwner(None))
    }

    /// A QUIC child owns the complete connection, including retained raw
    /// clones and its quota watcher. Dropping only its byte stream is not
    /// sufficient. The handle must belong to the proof's actual fresh child.
    pub fn into_reliable_quic(
        self,
        stream: veil_transport::BoxIoStream,
        transport: veil_transport::QuicDatagramHandle,
    ) -> Result<BoundReliableChannel, BindingError> {
        let exporter = transport
            .channel_binding()
            .map_err(|_| BindingError::InvalidProof)?;
        if !bool::from(exporter.ct_eq(&*self.exporter)) {
            // Do not retire an unrelated connection supplied by a bad caller.
            return Err(BindingError::InvalidProof);
        }
        self.into_reliable_inner(stream, ReliableTransportOwner(Some(transport)))
    }

    fn into_reliable_inner(
        self,
        stream: veil_transport::BoxIoStream,
        transport: ReliableTransportOwner,
    ) -> Result<BoundReliableChannel, BindingError> {
        self.parent.check_active()?;
        if self.mode != RecordMode::Reliable {
            return Err(BindingError::InvalidProof);
        }
        let plane = veil_transport::reliable_records::ReliableRecordPlane::new(stream);
        let handle = plane.handle();
        let parent = self.parent.clone();
        let quic = transport.0.clone();
        let lifetime = tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = parent.retired() => handle.close(),
                _ = handle.closed() => {},
            }
            if let Some(quic) = quic {
                quic.close();
            }
        });
        Ok(BoundReliableChannel {
            keys: self,
            plane,
            lifetime,
            transport,
        })
    }
}

/// Keeps reliable I/O, independent keys and parent authorization together.
pub struct BoundReliableChannel {
    pub keys: ParallelKeys,
    plane: veil_transport::reliable_records::ReliableRecordPlane,
    lifetime: tokio::task::JoinHandle<()>,
    transport: ReliableTransportOwner,
}

struct ReliableTransportOwner(Option<veil_transport::QuicDatagramHandle>);
impl ReliableTransportOwner {
    fn close(&self) {
        if let Some(handle) = &self.0 {
            handle.close();
        }
    }
}
impl Drop for ReliableTransportOwner {
    fn drop(&mut self) {
        self.close();
    }
}

impl BoundReliableChannel {
    /// Read the actual owned child's local counters without retaining another
    /// transport handle or changing parent authorization/lifetime.
    pub(crate) fn quic_snapshot(&self) -> Option<(u64, veil_transport::QuicDatagramPathStats)> {
        if !self.keys.parent.is_active() {
            return None;
        }
        self.transport
            .0
            .as_ref()
            .map(|handle| (handle.local_trace_id(), handle.path_stats()))
    }

    pub fn handle(&self) -> BoundReliableHandle {
        BoundReliableHandle {
            records: self.plane.handle(),
            parent: self.keys.parent.clone(),
        }
    }
}

#[derive(Clone)]
pub struct BoundReliableHandle {
    records: veil_transport::reliable_records::ReliableRecordHandle,
    parent: ParallelParentHandle,
}

impl BoundReliableHandle {
    pub(crate) fn parent_active(&self) -> bool {
        self.parent.is_active()
    }

    pub async fn send(&self, payload: &[u8]) -> std::io::Result<()> {
        if !self.parent.is_active() {
            return Err(std::io::ErrorKind::ConnectionAborted.into());
        }
        tokio::select! {
            biased;
            _ = self.parent.retired() => Err(std::io::ErrorKind::ConnectionAborted.into()),
            result = self.records.send(payload) => result,
        }
    }
    pub async fn recv(&self) -> std::io::Result<Vec<u8>> {
        let result = tokio::select! {
            biased;
            _ = self.parent.retired() => Err(std::io::ErrorKind::ConnectionAborted.into()),
            result = self.records.recv() => result,
        };
        if !self.parent.is_active() {
            return Err(std::io::ErrorKind::ConnectionAborted.into());
        }
        result
    }
    pub fn close(&self) {
        self.records.close();
    }
    pub async fn closed(&self) {
        tokio::select! { biased; _ = self.parent.retired() => {}, _ = self.records.closed() => {} }
    }
    pub fn progress(&self) -> veil_transport::reliable_records::RecordProgress {
        self.records.progress()
    }
}

impl Drop for BoundReliableChannel {
    fn drop(&mut self) {
        self.plane.handle().close();
        self.transport.close();
        self.lifetime.abort();
    }
}

/// Verified child credentials, framed stream and the canonical owner's
/// lifetime kept together. Handles retain neither admission nor task ownership.
pub struct BoundOrderedChannel {
    pub keys: ParallelKeys,
    plane: veil_transport::ordered_records::OrderedRecordPlane,
    lifetime: tokio::task::JoinHandle<()>,
}

impl BoundOrderedChannel {
    pub fn handle(&self) -> BoundOrderedHandle {
        BoundOrderedHandle {
            records: self.plane.handle(),
            parent: self.keys.parent.clone(),
        }
    }
}

/// Admission remains tied to the canonical owner even before its asynchronous
/// retirement task gets CPU time. No retained raw handle can enqueue new data
/// after retirement or drain records to a retired session.
#[derive(Clone)]
pub struct BoundOrderedHandle {
    records: veil_transport::ordered_records::OrderedRecordHandle,
    parent: ParallelParentHandle,
}

impl BoundOrderedHandle {
    pub fn is_closed(&self) -> bool {
        !self.parent.is_active() || self.records.is_closed()
    }

    pub fn max_size(&self) -> Option<usize> {
        self.parent
            .is_active()
            .then(|| self.records.max_size())
            .flatten()
    }

    pub fn send_buffer_space(&self) -> usize {
        if self.parent.is_active() {
            self.records.send_buffer_space()
        } else {
            0
        }
    }

    pub fn send(
        &self,
        payload: &[u8],
    ) -> Result<(), veil_transport::ordered_records::RecordSendError> {
        if !self.parent.is_active() {
            return Err(veil_transport::ordered_records::RecordSendError::Closed);
        }
        self.records.send(payload)
    }

    pub fn send_before(
        &self,
        payload: &[u8],
        expires_at: std::time::Instant,
    ) -> Result<(), veil_transport::ordered_records::RecordSendError> {
        if !self.parent.is_active() {
            return Err(veil_transport::ordered_records::RecordSendError::Closed);
        }
        self.records.send_before(payload, expires_at)
    }

    pub async fn recv(&self) -> std::io::Result<Vec<u8>> {
        let result = tokio::select! {
            biased;
            _ = self.parent.retired() => Err(std::io::ErrorKind::ConnectionAborted.into()),
            result = self.records.recv() => result,
        };
        if !self.parent.is_active() {
            return Err(std::io::ErrorKind::ConnectionAborted.into());
        }
        result
    }

    pub fn close(&self) {
        self.records.close();
    }

    pub async fn closed(&self) {
        tokio::select! {
            biased;
            _ = self.parent.retired() => {},
            _ = self.records.closed() => {},
        }
    }

    pub fn progress(&self) -> veil_transport::ordered_records::RecordProgress {
        self.records.progress()
    }
}

impl Drop for BoundOrderedChannel {
    fn drop(&mut self) {
        self.plane.handle().close();
        self.lifetime.abort();
    }
}

/// An outgoing proof, consumed when the remote acknowledgement is verified.
/// Retains zeroized exporter material only until that verification finishes.
pub struct PendingParallelBinding {
    parent: ParallelParentHandle,
    nonce: [u8; 32],
    exporter: Zeroizing<[u8; 32]>,
    mode: RecordMode,
}

fn proof(
    key: &[u8; 32],
    domain: &[u8],
    sid: &[u8; 32],
    nonce: &[u8; 32],
    exporter: &[u8; 32],
) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_keyed(key);
    hash.update(domain);
    hash.update(sid);
    hash.update(nonce);
    hash.update(exporter);
    *hash.finalize().as_bytes()
}

impl ParallelParent {
    /// An auxiliary task may retain this handle without owning the canonical
    /// session's lifetime. Dropping the owner still invalidates the handle.
    pub fn handle(&self) -> ParallelParentHandle {
        self.handle.clone()
    }

    /// The session owner must call `retire` before replacing these credentials.
    /// Transport security alone does not establish an OVL1 identity; do not source these keys
    /// or the session ID from an unverified peer-supplied preface.
    pub fn new(session_id: [u8; 32], tx: [u8; 32], rx: [u8; 32]) -> Self {
        Self {
            handle: ParallelParentHandle(Arc::new(Parent {
                session_id,
                tx: Zeroizing::new(tx),
                rx: Zeroizing::new(rx),
                active: AtomicBool::new(true),
                retired: tokio::sync::watch::channel(false).0,
            })),
        }
    }
}

impl ParallelParentHandle {
    /// Allocation identity for local ingress ownership. The handle keeps the
    /// allocation alive; this value carries no key, role or wire authority.
    pub(crate) fn local_generation(&self) -> usize {
        Arc::as_ptr(&self.0) as usize
    }

    pub(crate) fn is_active(&self) -> bool {
        self.0.active.load(Ordering::Acquire)
    }
    pub fn retire(&self) {
        self.0.active.store(false, Ordering::Release);
        self.0.retired.send_replace(true);
    }

    /// Wake idle auxiliary tasks on owner drop/rekey without polling timers.
    pub async fn retired(&self) {
        let mut retired = self.0.retired.subscribe();
        loop {
            if *retired.borrow_and_update() {
                return;
            }
            if retired.changed().await.is_err() {
                return;
            }
        }
    }

    fn check_active(&self) -> Result<(), BindingError> {
        if self.0.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(BindingError::Retired)
        }
    }

    /// Use the new child connection's exporter, never the parent's exporter.
    pub fn begin(
        &self,
        exporter: [u8; 32],
    ) -> Result<([u8; HELLO_BYTES], PendingParallelBinding), BindingError> {
        self.begin_mode(exporter, RecordMode::LossTolerant)
    }

    pub fn begin_reliable(
        &self,
        exporter: [u8; 32],
    ) -> Result<([u8; HELLO_BYTES], PendingParallelBinding), BindingError> {
        self.begin_mode(exporter, RecordMode::Reliable)
    }

    fn begin_mode(
        &self,
        exporter: [u8; 32],
        mode: RecordMode,
    ) -> Result<([u8; HELLO_BYTES], PendingParallelBinding), BindingError> {
        let exporter = Zeroizing::new(exporter);
        self.check_active()?;
        let mut nonce = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut hello = [0; HELLO_BYTES];
        hello[..8].copy_from_slice(mode.preface());
        hello[8..40].copy_from_slice(&self.0.session_id);
        hello[40..72].copy_from_slice(&nonce);
        hello[72..].copy_from_slice(&proof(
            &self.0.tx,
            mode.domain("hello"),
            &self.0.session_id,
            &nonce,
            &exporter,
        ));
        Ok((
            hello,
            PendingParallelBinding {
                parent: self.clone(),
                nonce,
                exporter,
                mode,
            },
        ))
    }

    /// Verify before interpreting any child frames. Call once per newly
    /// accepted connection, using its exporter. A captured preface cannot
    /// authenticate a different encrypted connection to the same endpoint.
    pub fn accept(
        &self,
        hello: &[u8; HELLO_BYTES],
        exporter: [u8; 32],
    ) -> Result<([u8; 32], ParallelKeys), BindingError> {
        self.accept_mode(hello, exporter, RecordMode::LossTolerant)
    }

    pub fn accept_reliable(
        &self,
        hello: &[u8; HELLO_BYTES],
        exporter: [u8; 32],
    ) -> Result<([u8; 32], ParallelKeys), BindingError> {
        self.accept_mode(hello, exporter, RecordMode::Reliable)
    }

    fn accept_mode(
        &self,
        hello: &[u8; HELLO_BYTES],
        exporter: [u8; 32],
        mode: RecordMode,
    ) -> Result<([u8; 32], ParallelKeys), BindingError> {
        let exporter = Zeroizing::new(exporter);
        self.check_active()?;
        if &hello[..8] != mode.preface() || hello[8..40] != self.0.session_id {
            return Err(BindingError::InvalidProof);
        }
        let nonce: [u8; 32] = hello[40..72].try_into().expect("fixed preface");
        let expected = proof(
            &self.0.rx,
            mode.domain("hello"),
            &self.0.session_id,
            &nonce,
            &exporter,
        );
        if !bool::from(expected.ct_eq(&hello[72..])) {
            return Err(BindingError::InvalidProof);
        }
        self.check_active()?;
        let ack = proof(
            &self.0.tx,
            mode.domain("ack"),
            &self.0.session_id,
            &nonce,
            &exporter,
        );
        Ok((ack, self.keys(&nonce, &exporter, mode)))
    }

    fn keys(&self, nonce: &[u8; 32], exporter: &[u8; 32], mode: RecordMode) -> ParallelKeys {
        // Child identity is opaque; it carries no traffic class or priority.
        let mut id = blake3::Hasher::new_derive_key(match mode {
            RecordMode::LossTolerant => "veil/parallel/session-id/v1",
            RecordMode::Reliable => "veil/parallel/reliable/session-id/v1",
        });
        id.update(&self.0.session_id);
        id.update(nonce);
        id.update(exporter);
        ParallelKeys {
            session_id: *id.finalize().as_bytes(),
            parent: self.clone(),
            mode,
            exporter: Zeroizing::new(*exporter),
            tx: Zeroizing::new(proof(
                &self.0.tx,
                mode.domain("key"),
                &self.0.session_id,
                nonce,
                exporter,
            )),
            rx: Zeroizing::new(proof(
                &self.0.rx,
                mode.domain("key"),
                &self.0.session_id,
                nonce,
                exporter,
            )),
        }
    }
}

impl PendingParallelBinding {
    pub fn finish(self, ack: &[u8; 32]) -> Result<ParallelKeys, BindingError> {
        self.parent.check_active()?;
        let expected = proof(
            &self.parent.0.rx,
            self.mode.domain("ack"),
            &self.parent.0.session_id,
            &self.nonce,
            &self.exporter,
        );
        if !bool::from(expected.ct_eq(ack)) {
            return Err(BindingError::InvalidProof);
        }
        self.parent.check_active()?;
        Ok(self.parent.keys(&self.nonce, &self.exporter, self.mode))
    }
}

#[cfg(test)]
#[path = "parallel_binding_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "reliable_binding_tests.rs"]
mod reliable_tests;
