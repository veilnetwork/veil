//! Independent QUIC connections on one exclusively owned punched endpoint.
//!
//! This is a transport primitive, not an OVL1 authenticated session. It is
//! deliberately unavailable on shared listeners, whose central accept loop
//! must retain ownership. No producer role, priority or QoS parameter travels
//! on the wire. Application activation waits for the session binding layer.

use super::*;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

const MAX_CONNECTIONS: usize = 8;

struct Inner {
    endpoint: quinn::Endpoint,
    parent: quinn::Connection,
    peer: PeerMeta,
    accept: Mutex<()>,
    slots: Arc<Semaphore>,
}

/// Transport-only siblings with independent congestion control and reliable
/// admission. They reuse the punched UDP mapping, not the parent's TLS keys
/// or AEAD counters. Clones share one accept lock and a bounded connection
/// budget. Closing the parent closes all siblings; closing a sibling leaves
/// the parent and other siblings intact.
#[derive(Clone)]
pub struct QuicParallelHandle(Arc<Inner>);

impl QuicParallelHandle {
    pub(super) fn new(
        endpoint: quinn::Endpoint,
        parent: quinn::Connection,
        peer: PeerMeta,
    ) -> Self {
        Self(Arc::new(Inner {
            endpoint,
            parent,
            peer,
            accept: Mutex::new(()),
            slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }))
    }

    fn reserve(&self) -> Result<OwnedSemaphorePermit> {
        if self.0.parent.close_reason().is_some() {
            return Err(quic_error("parallel QUIC parent closed"));
        }
        Arc::clone(&self.0.slots)
            .try_acquire_owned()
            .map_err(|_| quic_error("parallel QUIC connection budget exhausted"))
    }

    fn bind_child(
        &self,
        connection: quinn::Connection,
        stream: BoxIoStream,
        permit: OwnedSemaphorePermit,
    ) -> Box<dyn TransportConnection> {
        let parent = self.0.parent.clone();
        let child = connection.clone();
        // The slot follows the actual QUIC lifetime, including raw connection
        // and DATAGRAM clones, rather than only the first byte stream wrapper.
        tokio::spawn(async move {
            let _permit = permit;
            tokio::select! {
                _ = parent.closed() => child.close(0u32.into(), b"parent closed"),
                _ = child.closed() => {},
            }
        });
        let mut peer = self.0.peer.clone();
        peer.remote_addr = Some(connection.remote_address());
        boxed_quic_connection(peer, self.0.endpoint.clone(), connection, stream)
    }

    /// Open a sibling to the parent's current remote UDP address without DNS
    /// discovery or a new local socket. The first stream is advertised lazily;
    /// send the authentication preface before awaiting the remote accept.
    pub async fn connect(
        &self,
        ctx: Arc<TransportContext>,
    ) -> Result<Box<dyn TransportConnection>> {
        let permit = self.reserve()?;
        let operation = async {
            let (host, _, sni, alpn) = quic_connect_parts(&self.0.peer.uri)?;
            let config = build_quic_client_config(&ctx, alpn)?;
            let connection = self
                .0
                .endpoint
                .connect_with(
                    config,
                    self.0.parent.remote_address(),
                    ctx.effective_sni(sni, host),
                )?
                .await?;
            let streams = connection.open_bi().await;
            let (send, recv) = match streams {
                Ok(streams) => streams,
                Err(error) => {
                    connection.close(0u32.into(), b"stream failed");
                    return Err(error.into());
                }
            };
            Ok(self.bind_child(connection, Box::new(QuicBidiStream { recv, send }), permit))
        };
        tokio::select! {
            _ = self.0.parent.closed() => Err(quic_error("parallel QUIC parent closed")),
            result = timeout(ctx.quic.connect_timeout, operation) => {
                result.map_err(|_| connect_timeout(ctx.quic.connect_timeout))?
            }
        }
    }

    /// Accept only a connection from the parent's current remote UDP address.
    /// This address filter is not authentication: the session must verify the
    /// exporter-bound proof before dispatching any frame or installing keys.
    /// The timeout includes lock, handshake and first-stream waits.
    pub async fn accept(&self, ctx: Arc<TransportContext>) -> Result<Box<dyn TransportConnection>> {
        let permit = self.reserve()?;
        let operation = async {
            let _accept = self.0.accept.lock().await;
            let connection = loop {
                let incoming = self
                    .0
                    .endpoint
                    .accept()
                    .await
                    .ok_or_else(|| quic_error("parallel QUIC endpoint closed"))?;
                if incoming.remote_address() != self.0.parent.remote_address() {
                    incoming.refuse();
                    continue;
                }
                break incoming.accept().map_err(quic_error)?.await?;
            };
            let (send, recv) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(error) => {
                    connection.close(0u32.into(), b"stream failed");
                    return Err(error.into());
                }
            };
            Ok(self.bind_child(connection, Box::new(QuicBidiStream { recv, send }), permit))
        };
        tokio::select! {
            _ = self.0.parent.closed() => Err(quic_error("parallel QUIC parent closed")),
            result = timeout(ctx.quic.handshake_timeout, operation) => {
                result.map_err(|_| handshake_timeout(ctx.quic.handshake_timeout))?
            }
        }
    }
}
