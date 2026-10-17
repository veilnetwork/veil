//! One dispatcher for shared encrypted listeners. A child is never a new peer:
//! it inherits the canonical runner's identity, budgets and shutdown.
use super::*;
use crate::parallel_binding::{PREFACE, RELIABLE_PREFACE};
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::mpsc;
use veil_transport::QuicDatagramHandle;

const MAX_PARENTS: usize = 1024;

#[derive(Clone)]
struct Entry {
    parent: ParallelParentHandle,
    diagnostics: Arc<ParallelDiagnostics>,
    kind: EntryKind,
    registration: Arc<()>,
    reliable: Option<mpsc::Sender<BoundReliableChild>>,
}

enum ReliableIncomingTransport {
    Quic(Channel),
    Ordered(BoxIoStream, OrderedDiagnosticsLease),
}

/// A proof-verified lossless child waiting for its canonical owner's ACK.
pub struct BoundReliableChild {
    transport: ReliableIncomingTransport,
    keys: ParallelKeys,
    ack: [u8; 32],
    parent: ParallelParentHandle,
}

enum ReliableRetention {
    Quic { _owner: Channel },
    Ordered { _lease: OrderedDiagnosticsLease },
}

/// Retains transport accounting as well as reliable I/O and parent authority.
pub struct RegisteredReliableChannel {
    channel: crate::parallel_binding::BoundReliableChannel,
    _retention: ReliableRetention,
}

impl RegisteredReliableChannel {
    pub(crate) fn quic_snapshot(&self) -> Option<(u64, veil_transport::QuicDatagramPathStats)> {
        self.channel.quic_snapshot()
    }

    pub fn handle(&self) -> crate::parallel_binding::BoundReliableHandle {
        self.channel.handle()
    }
    pub fn keys(&self) -> &ParallelKeys {
        &self.channel.keys
    }
}

/// Own a fresh dial through proof/ACK completion. Failure or cancellation
/// drops the real transport and its accounting, including retained QUIC clones.
pub(in crate::runner) struct ReliableDialedChild {
    transport: ReliableIncomingTransport,
    exporter: [u8; 32],
}

impl ReliableDialedChild {
    pub(in crate::runner) fn new(
        connection: Box<dyn veil_transport::TransportConnection>,
        diagnostics: Arc<ParallelDiagnostics>,
    ) -> Result<Self, &'static str> {
        if connection.quic_datagrams().is_some() {
            let channel =
                Channel::new(connection, diagnostics).map_err(|_| "child transport failed")?;
            let exporter = channel
                .handle
                .channel_binding()
                .map_err(|_| "child exporter unavailable")?;
            Ok(Self {
                transport: ReliableIncomingTransport::Quic(channel),
                exporter,
            })
        } else {
            let exporter = connection
                .stream_channel_binding()
                .ok_or("child exporter unavailable")?;
            let stream = connection
                .into_stream()
                .map_err(|_| "child transport failed")?;
            diagnostics.connection_opened();
            Ok(Self {
                transport: ReliableIncomingTransport::Ordered(
                    stream,
                    OrderedDiagnosticsLease(diagnostics),
                ),
                exporter,
            })
        }
    }
    pub(in crate::runner) fn exporter(&self) -> [u8; 32] {
        self.exporter
    }
    pub(in crate::runner) fn stream(&mut self) -> &mut BoxIoStream {
        match &mut self.transport {
            ReliableIncomingTransport::Quic(c) => &mut c.stream,
            ReliableIncomingTransport::Ordered(stream, _) => stream,
        }
    }
    pub(in crate::runner) fn finish(
        self,
        keys: ParallelKeys,
    ) -> Result<RegisteredReliableChannel, &'static str> {
        finish_reliable_transport(self.transport, keys)
    }
}

fn finish_reliable_transport(
    transport: ReliableIncomingTransport,
    keys: ParallelKeys,
) -> Result<RegisteredReliableChannel, &'static str> {
    let (channel, retention) = match transport {
        ReliableIncomingTransport::Quic(mut owner) => {
            let stream = std::mem::replace(&mut owner.stream, broken_stream_sentinel());
            let channel = keys
                .into_reliable_quic(stream, owner.handle.clone())
                .map_err(|_| "parallel parent retired")?;
            (channel, ReliableRetention::Quic { _owner: owner })
        }
        ReliableIncomingTransport::Ordered(stream, lease) => {
            let channel = keys
                .into_reliable(stream)
                .map_err(|_| "parallel parent retired")?;
            (channel, ReliableRetention::Ordered { _lease: lease })
        }
    };
    Ok(RegisteredReliableChannel {
        channel,
        _retention: retention,
    })
}

impl BoundReliableChild {
    pub(super) fn exclusive_quic(
        channel: Channel,
        keys: ParallelKeys,
        ack: [u8; 32],
        parent: ParallelParentHandle,
    ) -> Self {
        Self {
            transport: ReliableIncomingTransport::Quic(channel),
            keys,
            ack,
            parent,
        }
    }
    pub async fn finish(mut self) -> Result<RegisteredReliableChannel, &'static str> {
        let stream = match &mut self.transport {
            ReliableIncomingTransport::Quic(channel) => &mut channel.stream,
            ReliableIncomingTransport::Ordered(stream, _) => stream,
        };
        let acknowledging = tokio::time::timeout(BIND_TIMEOUT, async {
            stream.write_all(&self.ack).await?;
            stream.flush().await
        });
        let result = tokio::select! {
            biased;
            _ = self.parent.retired() => return Err("parallel parent retired"),
            result = acknowledging => result,
        };
        if !matches!(result, Ok(Ok(()))) {
            return Err("parallel acknowledgement failed");
        }
        finish_reliable_transport(self.transport, self.keys)
    }
}

#[derive(Clone)]
enum EntryKind {
    Quic {
        transport: QuicParallelHandle,
        incoming: mpsc::Sender<BoundChild>,
    },
    Ordered {
        transport: veil_transport::stream_parallel::StreamParallelHandle,
        incoming: mpsc::Sender<BoundOrderedChild>,
    },
}

pub(super) struct BoundChild {
    pub(super) channel: Channel,
    pub(super) keys: ParallelKeys,
    pub(super) ack: [u8; 32],
    pub(super) parent: ParallelParentHandle,
}

struct OrderedDiagnosticsLease(Arc<ParallelDiagnostics>);

impl Drop for OrderedDiagnosticsLease {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The canonical runner receives this ONLY after the incoming proof verifies
/// and its existing incoming connection budget grants a lease. No ACK or data
/// is sent from the shared listener; the session owner completes the binding.
pub struct BoundOrderedChild {
    stream: BoxIoStream,
    keys: ParallelKeys,
    ack: [u8; 32],
    parent: ParallelParentHandle,
    diagnostics: OrderedDiagnosticsLease,
}

/// Keeps the proof, record owner and connection accounting in one lifetime.
pub struct RegisteredOrderedChannel {
    channel: crate::parallel_binding::BoundOrderedChannel,
    _diagnostics: OrderedDiagnosticsLease,
}

impl RegisteredOrderedChannel {
    pub fn handle(&self) -> crate::parallel_binding::BoundOrderedHandle {
        self.channel.handle()
    }

    pub fn keys(&self) -> &ParallelKeys {
        &self.channel.keys
    }
}

impl BoundOrderedChild {
    pub async fn finish(mut self) -> Result<RegisteredOrderedChannel, &'static str> {
        // A buffered TCP/obfs4 flight must flush before waiting for its peer.
        let acknowledging = tokio::time::timeout(BIND_TIMEOUT, async {
            self.stream.write_all(&self.ack).await?;
            self.stream.flush().await
        });
        let result = tokio::select! {
            biased;
            _ = self.parent.retired() => return Err("parallel parent retired"),
            result = acknowledging => result,
        };
        if !matches!(result, Ok(Ok(()))) {
            return Err("parallel acknowledgement failed");
        }
        let channel = self
            .keys
            .into_ordered(self.stream)
            .map_err(|_| "parallel parent retired")?;
        Ok(RegisteredOrderedChannel {
            channel,
            _diagnostics: self.diagnostics,
        })
    }
}

/// Shared only within one runtime, with registrations owned by live runners.
/// Parent keys come from an authenticated handshake, never the incoming hello.
#[derive(Default)]
pub struct ParallelRegistry {
    entries: Mutex<HashMap<[u8; 32], Entry>>,
}

// Keep cancellation safe even before enough bytes exist to classify the
// transport. Ordinary input explicitly transfers the stream to OVL1.
struct PendingStream {
    stream: Option<BoxIoStream>,
    datagrams: Option<QuicDatagramHandle>,
    stream_binding: Option<[u8; 32]>,
}

impl Drop for PendingStream {
    fn drop(&mut self) {
        if self.stream.is_some()
            && let Some(handle) = &self.datagrams
        {
            handle.close();
        }
    }
}

pub struct Registration {
    registry: Arc<ParallelRegistry>,
    sid: [u8; 32],
    token: Arc<()>,
}

impl Registration {
    /// Enable only after explicit peer capability negotiation. Registration
    /// ownership, parent lifetime and the existing transport quota are shared
    /// with other children; no second peer row or privilege is created.
    pub fn enable_reliable(&self, incoming: mpsc::Sender<BoundReliableChild>) -> bool {
        let mut entries = self
            .registry
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(entry) = entries.get_mut(&self.sid) else {
            return false;
        };
        if !Arc::ptr_eq(&entry.registration, &self.token)
            || !entry.parent.is_active()
            || entry.reliable.is_some()
        {
            return false;
        }
        entry.reliable = Some(incoming);
        true
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut entries = self
            .registry
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if entries
            .get(&self.sid)
            .is_some_and(|entry| Arc::ptr_eq(&entry.registration, &self.token))
        {
            entries.remove(&self.sid);
        }
    }
}

pub enum ParallelPeekOutcome {
    /// The canonical runner owns the child, including its authenticated ACK.
    Bound,
    /// Ordinary OVL1 input with the peeked bytes preserved.
    Handshake(BoxIoStream),
    /// Unknown parent, invalid proof, exhausted budget or incomplete preface.
    Drop(String),
}

impl ParallelRegistry {
    pub(super) fn register(
        self: &Arc<Self>,
        sid: [u8; 32],
        parent: ParallelParentHandle,
        offer: &ParallelQuicOffer,
        incoming: mpsc::Sender<BoundChild>,
    ) -> Option<Registration> {
        self.insert(
            sid,
            parent,
            Arc::clone(&offer.diagnostics),
            EntryKind::Quic {
                transport: offer.handle.clone(),
                incoming,
            },
        )
    }

    /// The live canonical owner must retain this registration and negotiate
    /// ordered-child support before offering it. Keys/SID come from its verified
    /// OVL1 handshake, never from an incoming preface or transport encryption.
    pub fn register_ordered(
        self: &Arc<Self>,
        sid: [u8; 32],
        parent: ParallelParentHandle,
        transport: veil_transport::stream_parallel::StreamParallelHandle,
        diagnostics: Arc<ParallelDiagnostics>,
        incoming: mpsc::Sender<BoundOrderedChild>,
    ) -> Option<Registration> {
        self.insert(
            sid,
            parent,
            diagnostics,
            EntryKind::Ordered {
                transport,
                incoming,
            },
        )
    }

    fn insert(
        self: &Arc<Self>,
        sid: [u8; 32],
        parent: ParallelParentHandle,
        diagnostics: Arc<ParallelDiagnostics>,
        kind: EntryKind,
    ) -> Option<Registration> {
        if !parent.is_active() {
            return None;
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= MAX_PARENTS || entries.contains_key(&sid) {
            return None;
        }
        let token = Arc::new(());
        entries.insert(
            sid,
            Entry {
                parent,
                diagnostics,
                kind,
                registration: Arc::clone(&token),
                reliable: None,
            },
        );
        Some(Registration {
            registry: Arc::clone(self),
            sid,
            token,
        })
    }

    /// Called once by the central listener before OVL1 or per-peer admission.
    /// A generic proof reveals no producer role or requested service class.
    /// The existing listener's TLS/pending-handshake limits still apply.
    pub async fn peek_and_dispatch(
        &self,
        stream: BoxIoStream,
        datagrams: Option<QuicDatagramHandle>,
    ) -> ParallelPeekOutcome {
        self.peek_and_dispatch_with_binding(stream, datagrams, None)
            .await
    }

    /// The ordered exporter is extracted from the newly accepted transport,
    /// never from a claimed parent or an incoming wire field. QUIC keeps its
    /// own TLS exporter. Ordinary OVL1 bytes are preserved on both transports.
    pub async fn peek_and_dispatch_with_binding(
        &self,
        stream: BoxIoStream,
        datagrams: Option<QuicDatagramHandle>,
        stream_binding: Option<[u8; 32]>,
    ) -> ParallelPeekOutcome {
        let mut pending = PendingStream {
            stream: Some(stream),
            datagrams,
            stream_binding,
        };
        match tokio::time::timeout(BIND_TIMEOUT, self.peek(&mut pending)).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(error)) => ParallelPeekOutcome::Drop(error.to_owned()),
            Err(_) => ParallelPeekOutcome::Drop("parallel proof timed out".to_owned()),
        }
    }

    async fn peek(&self, pending: &mut PendingStream) -> Result<ParallelPeekOutcome, &'static str> {
        let mut prefix = [0; 8];
        pending
            .stream
            .as_mut()
            .expect("unclassified stream")
            .read_exact(&mut prefix)
            .await
            .map_err(|_| "parallel prefix incomplete")?;
        if &prefix != PREFACE && &prefix != RELIABLE_PREFACE {
            return Ok(ParallelPeekOutcome::Handshake(Box::new(
                crate::handoff::PrefixedStream::new(
                    prefix.to_vec(),
                    pending.stream.take().expect("ordinary stream"),
                ),
            )));
        }
        let Some(handle) = pending.datagrams.take() else {
            let exporter = pending
                .stream_binding
                .take()
                .ok_or("parallel binding unavailable")?;
            self.bind_ordered(
                pending.stream.take().expect("child stream"),
                exporter,
                prefix,
            )
            .await?;
            return Ok(ParallelPeekOutcome::Bound);
        };
        // RAII closes a child on EVERY failure or cancellation, even if other
        // transport/DATAGRAM clones retain the raw Quinn connection.
        let channel = Channel {
            handle,
            stream: pending.stream.take().expect("child stream"),
            diagnostics: None,
        };
        self.bind(channel, prefix).await?;
        Ok(ParallelPeekOutcome::Bound)
    }

    async fn bind(&self, mut channel: Channel, prefix: [u8; 8]) -> Result<(), &'static str> {
        let mut hello = [0; HELLO_BYTES];
        hello[..8].copy_from_slice(&prefix);
        channel
            .stream
            .read_exact(&mut hello[8..])
            .await
            .map_err(|_| "parallel hello incomplete")?;
        let sid: [u8; 32] = hello[8..40].try_into().expect("fixed parent SID");
        let entry = self
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&sid)
            .cloned()
            .ok_or("parallel parent unavailable")?;
        let EntryKind::Quic {
            transport,
            incoming,
        } = entry.kind
        else {
            return Err("parallel transport mismatch");
        };
        let exporter = channel
            .handle
            .channel_binding()
            .map_err(|_| "parallel binding unavailable")?;
        let reliable = &prefix == RELIABLE_PREFACE;
        let reliable_incoming = if reliable {
            Some(
                entry
                    .reliable
                    .ok_or("parallel reliable support not negotiated")?,
            )
        } else {
            None
        };
        let (ack, keys) = if reliable {
            entry.parent.accept_reliable(&hello, exporter)
        } else {
            entry.parent.accept(&hello, exporter)
        }
        .map_err(|_| "parallel proof rejected")?;
        transport
            .track_incoming(&channel.handle)
            .map_err(|_| "parallel connection budget exhausted")?;
        entry.diagnostics.active.fetch_add(1, Ordering::AcqRel);
        channel.diagnostics = Some(entry.diagnostics);
        if let Some(incoming) = reliable_incoming {
            return incoming
                .try_send(BoundReliableChild {
                    transport: ReliableIncomingTransport::Quic(channel),
                    keys,
                    ack,
                    parent: entry.parent,
                })
                .map_err(|_| "parallel reliable owner unavailable");
        }
        incoming
            .try_send(BoundChild {
                channel,
                keys,
                ack,
                parent: entry.parent,
            })
            .map_err(|_| "parallel owner unavailable")
    }

    async fn bind_ordered(
        &self,
        mut stream: BoxIoStream,
        exporter: [u8; 32],
        prefix: [u8; 8],
    ) -> Result<(), &'static str> {
        let mut hello = [0; HELLO_BYTES];
        hello[..8].copy_from_slice(&prefix);
        stream
            .read_exact(&mut hello[8..])
            .await
            .map_err(|_| "parallel hello incomplete")?;
        let sid: [u8; 32] = hello[8..40].try_into().expect("fixed parent SID");
        let entry = self
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&sid)
            .cloned()
            .ok_or("parallel parent unavailable")?;
        let EntryKind::Ordered {
            transport,
            incoming,
        } = entry.kind
        else {
            return Err("parallel transport mismatch");
        };
        let reliable = &prefix == RELIABLE_PREFACE;
        let reliable_incoming = if reliable {
            Some(
                entry
                    .reliable
                    .ok_or("parallel reliable support not negotiated")?,
            )
        } else {
            None
        };
        let (ack, keys) = if reliable {
            entry.parent.accept_reliable(&hello, exporter)
        } else {
            entry.parent.accept(&hello, exporter)
        }
        .map_err(|_| "parallel proof rejected")?;
        // Acquiring this lease never creates an OVL1 identity or per-peer row.
        let stream = transport
            .track_incoming(stream)
            .map_err(|_| "parallel connection budget exhausted")?;
        entry.diagnostics.active.fetch_add(1, Ordering::AcqRel);
        if let Some(incoming) = reliable_incoming {
            return incoming
                .try_send(BoundReliableChild {
                    transport: ReliableIncomingTransport::Ordered(
                        stream,
                        OrderedDiagnosticsLease(entry.diagnostics),
                    ),
                    keys,
                    ack,
                    parent: entry.parent,
                })
                .map_err(|_| "parallel reliable owner unavailable");
        }
        incoming
            .try_send(BoundOrderedChild {
                stream,
                keys,
                ack,
                parent: entry.parent,
                diagnostics: OrderedDiagnosticsLease(entry.diagnostics),
            })
            .map_err(|_| "parallel owner unavailable")
    }
}

#[cfg(test)]
#[path = "parallel_registry_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "parallel_registry_ordered_tests.rs"]
mod ordered_tests;
