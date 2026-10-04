//! One dispatcher for a shared QUIC listener. A child is never a new peer:
//! it inherits the canonical runner's identity, budgets and shutdown.
use super::*;
use crate::parallel_binding::PREFACE;
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::mpsc;
use veil_transport::QuicDatagramHandle;

const MAX_PARENTS: usize = 1024;

#[derive(Clone)]
struct Entry {
    parent: ParallelParentHandle,
    transport: QuicParallelHandle,
    diagnostics: Arc<ParallelDiagnostics>,
    incoming: mpsc::Sender<BoundChild>,
}

pub(super) struct BoundChild {
    pub(super) channel: Channel,
    pub(super) keys: ParallelKeys,
    pub(super) ack: [u8; 32],
    pub(super) parent: ParallelParentHandle,
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

pub(super) struct Registration {
    registry: Arc<ParallelRegistry>,
    sid: [u8; 32],
    incoming: mpsc::Sender<BoundChild>,
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
            .is_some_and(|entry| entry.incoming.same_channel(&self.incoming))
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
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= MAX_PARENTS || entries.contains_key(&sid) {
            return None;
        }
        entries.insert(
            sid,
            Entry {
                parent,
                transport: offer.handle.clone(),
                diagnostics: Arc::clone(&offer.diagnostics),
                incoming: incoming.clone(),
            },
        );
        Some(Registration {
            registry: Arc::clone(self),
            sid,
            incoming,
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
        let mut pending = PendingStream {
            stream: Some(stream),
            datagrams,
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
        if &prefix != PREFACE {
            return Ok(ParallelPeekOutcome::Handshake(Box::new(
                crate::handoff::PrefixedStream::new(
                    prefix.to_vec(),
                    pending.stream.take().expect("ordinary stream"),
                ),
            )));
        }
        let handle = pending
            .datagrams
            .take()
            .ok_or("parallel proof requires QUIC")?;
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
        let exporter = channel
            .handle
            .channel_binding()
            .map_err(|_| "parallel binding unavailable")?;
        let (ack, keys) = entry
            .parent
            .accept(&hello, exporter)
            .map_err(|_| "parallel proof rejected")?;
        entry
            .transport
            .track_incoming(&channel.handle)
            .map_err(|_| "parallel connection budget exhausted")?;
        entry.diagnostics.active.fetch_add(1, Ordering::AcqRel);
        channel.diagnostics = Some(entry.diagnostics);
        entry
            .incoming
            .try_send(BoundChild {
                channel,
                keys,
                ack,
                parent: entry.parent,
            })
            .map_err(|_| "parallel owner unavailable")
    }
}

#[cfg(test)]
#[path = "parallel_registry_tests.rs"]
mod tests;
