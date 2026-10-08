//! Independent ordered connections for obfs4/TCP session children.
//!
//! This layer supplies transport and lifetime only, never identity admission.
//! Children require the canonical session's exporter-bound proof and must not
//! enter its peer registry as new nodes. Every parent has the same bounded
//! budget. No application role, priority, proof or new framing is sent here.
//! Session activation is deliberately gated outside this transport primitive.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

use crate::error::{Result, TransportError};
use crate::traits::{BoxIoStream, TransportConnection};
use crate::{TransportContext, TransportUri};

struct Inner {
    context: Arc<TransportContext>,
    target: Option<TransportUri>,
    parent: CancellationToken,
    outgoing: Arc<Semaphore>,
    incoming: Arc<Semaphore>,
}

/// Cloneable transport offer, not authority to create a session identity.
/// Only the TCP-dialing endpoint can open children: a TCP client's source
/// port is not a listener. Accepted children are duplex, so the session layer
/// can use a verified incoming child for return traffic without reverse dials.
#[derive(Clone)]
pub struct StreamParallelHandle(Arc<Inner>);

impl StreamParallelHandle {
    /// Match the existing generic QUIC budget: no transport gets extra slots
    /// because of payload or producer. Direction partitions prevent starvation.
    pub const CONNECTIONS_PER_DIRECTION: usize =
        crate::QuicParallelHandle::CONNECTIONS_PER_DIRECTION;
    pub const CONNECTION_LIMIT: usize = 2 * Self::CONNECTIONS_PER_DIRECTION;

    pub(crate) fn new(context: Arc<TransportContext>, target: Option<TransportUri>) -> Self {
        Self(Arc::new(Inner {
            context,
            target,
            parent: CancellationToken::new(),
            outgoing: Arc::new(Semaphore::new(Self::CONNECTIONS_PER_DIRECTION)),
            incoming: Arc::new(Semaphore::new(Self::CONNECTIONS_PER_DIRECTION)),
        }))
    }

    pub fn can_connect(&self) -> bool {
        self.0.target.is_some() && !self.0.parent.is_cancelled()
    }

    /// Local outgoing reservations, including handshakes. Incoming siblings
    /// cannot consume this partition; this snapshot does not reserve a slot.
    pub fn available_connection_slots(&self) -> usize {
        if self.0.parent.is_cancelled() {
            0
        } else {
            self.0.outgoing.available_permits()
        }
    }

    pub async fn closed(&self) {
        self.0.parent.cancelled().await;
    }

    fn reserve(&self, direction: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit> {
        if self.0.parent.is_cancelled() {
            return Err(TransportError::Io(parent_closed()));
        }
        Arc::clone(direction).try_acquire_owned().map_err(|_| {
            TransportError::Unsupported("parallel stream connection budget exhausted".into())
        })
    }

    /// Establish a fresh obfs4/TCP connection to the parent's endpoint. It
    /// has fresh framing keys and an exporter, but no OVL1 peer authorization.
    /// Cancellation/failed upgrades release the reserved slot automatically.
    pub async fn connect(&self) -> Result<Box<dyn TransportConnection>> {
        let target = self.0.target.as_ref().ok_or_else(|| {
            TransportError::Unsupported("accepted TCP endpoint cannot reverse-dial children".into())
        })?;
        let permit = self.reserve(&self.0.outgoing)?;
        let (peer, stream) = tokio::select! {
            biased;
            _ = self.0.parent.cancelled() => return Err(TransportError::Io(parent_closed())),
            result = crate::obfs4_tcp::connect_obfs4_stream(target, Arc::clone(&self.0.context)) => result?,
        };
        let binding = stream.channel_binding();
        let stream = crate::obfs4_tcp::boxed_obfs4_io(stream);
        let owned = BoundStream::child(stream, self.0.parent.clone(), permit);
        // No nested offer: an auxiliary transport is not another canonical
        // authenticated parent and cannot multiply the connection budget.
        Ok(Box::new(
            crate::tcp::StreamConnection::new(peer, owned).with_auxiliary_stream(binding, None),
        ))
    }

    /// Adopt ONLY after the canonical session verifies the child's proof.
    /// This does not grant identity admission or inspect application traffic.
    pub fn track_incoming(&self, stream: BoxIoStream) -> Result<BoxIoStream> {
        let permit = self.reserve(&self.0.incoming)?;
        Ok(Box::new(BoundStream::child(
            stream,
            self.0.parent.clone(),
            permit,
        )))
    }

    pub(crate) fn parent_stream(&self, stream: BoxIoStream) -> BoxIoStream {
        Box::new(BoundStream::parent(stream, self.0.parent.clone()))
    }
}

fn parent_closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "auxiliary stream parent closed",
    )
}

// Exactly one guard owns the canonical stream lifetime. Handles and child
// streams retain the cancellation state but cannot keep authority alive.
struct ParentOwner(CancellationToken);
impl Drop for ParentOwner {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

struct BoundStream {
    stream: BoxIoStream,
    parent: CancellationToken,
    closed: Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
    owner: Option<ParentOwner>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl BoundStream {
    fn parent(stream: BoxIoStream, token: CancellationToken) -> Self {
        Self::new(stream, token.clone(), Some(ParentOwner(token)), None)
    }

    fn child(stream: BoxIoStream, token: CancellationToken, permit: OwnedSemaphorePermit) -> Self {
        Self::new(stream, token, None, Some(permit))
    }

    fn new(
        stream: BoxIoStream,
        token: CancellationToken,
        owner: Option<ParentOwner>,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Self {
        Self {
            stream,
            closed: Box::pin(token.clone().cancelled_owned()),
            parent: token,
            owner,
            _permit: permit,
        }
    }

    fn poll_closed(&mut self, cx: &mut Context<'_>) -> bool {
        self.parent.is_cancelled() || self.closed.as_mut().poll(cx).is_ready()
    }

    fn note_failure(&self) {
        if self.owner.is_some() {
            self.parent.cancel();
        }
    }
}

impl AsyncRead for BoundStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.poll_closed(cx) {
            return Poll::Ready(Err(parent_closed()));
        }
        let had_capacity = buf.remaining() != 0;
        let before = buf.filled().len();
        let result = Pin::new(&mut *self.stream).poll_read(cx, buf);
        if matches!(&result, Poll::Ready(Err(_)))
            || (matches!(&result, Poll::Ready(Ok(())))
                && had_capacity
                && buf.filled().len() == before)
        {
            self.note_failure();
        }
        result
    }
}

impl AsyncWrite for BoundStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.poll_closed(cx) {
            return Poll::Ready(Err(parent_closed()));
        }
        let result = Pin::new(&mut *self.stream).poll_write(cx, buf);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.note_failure();
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.poll_closed(cx) {
            return Poll::Ready(Err(parent_closed()));
        }
        let result = Pin::new(&mut *self.stream).poll_flush(cx);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.note_failure();
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Closing one child never closes its parent or siblings.
        if self.owner.is_some() {
            self.parent.cancel();
        }
        Pin::new(&mut *self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "stream_parallel_tests.rs"]
mod tests;
