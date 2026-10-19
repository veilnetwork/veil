//! Independent QUIC connections sharing the parent's UDP endpoint.
//!
//! This is a transport primitive, not an OVL1 authenticated session.
//! Shared listeners retain their central accept loop; authenticated children
//! are adopted through `track_incoming`. No producer role or QoS parameter travels
//! on the wire. Application activation waits for the session binding layer.

use super::*;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

struct ChildSlot {
    _total: OwnedSemaphorePermit,
    _direction: OwnedSemaphorePermit,
}

struct Inner {
    endpoint: quinn::Endpoint,
    parent: quinn::Connection,
    context: Arc<TransportContext>,
    peer: PeerMeta,
    accept: Mutex<()>,
    slots: Arc<Semaphore>,
    outgoing_slots: Arc<Semaphore>,
    incoming_slots: Arc<Semaphore>,
    exclusive_accept: bool,
    requires_shared_dispatch: bool,
}

/// Transport-only siblings with independent congestion control and reliable
/// admission. They reuse the punched UDP mapping, not the parent's TLS keys
/// or AEAD counters. Clones share one accept lock and a bounded connection
/// budget. Closing the parent closes all siblings; closing a sibling leaves
/// the parent and other siblings intact.
#[derive(Clone)]
pub struct QuicParallelHandle(Arc<Inner>);

impl QuicParallelHandle {
    /// Seven generic connections plus one replacement per direction. All peers
    /// receive the same bound, independent of producer or payload. Partitioning
    /// directions prevents incoming siblings from consuming every local slot.
    pub const CONNECTIONS_PER_DIRECTION: usize = 8;
    pub const CONNECTION_LIMIT: usize = 2 * Self::CONNECTIONS_PER_DIRECTION;

    pub(super) fn new(
        endpoint: quinn::Endpoint,
        parent: quinn::Connection,
        peer: PeerMeta,
        context: Arc<TransportContext>,
        exclusive_accept: bool,
        requires_shared_dispatch: bool,
    ) -> Self {
        Self(Arc::new(Inner {
            endpoint,
            parent,
            peer,
            context,
            accept: Mutex::new(()),
            slots: Arc::new(Semaphore::new(Self::CONNECTION_LIMIT)),
            outgoing_slots: Arc::new(Semaphore::new(Self::CONNECTIONS_PER_DIRECTION)),
            incoming_slots: Arc::new(Semaphore::new(Self::CONNECTIONS_PER_DIRECTION)),
            exclusive_accept,
            requires_shared_dispatch,
        }))
    }

    fn reserve(&self, direction: &Arc<Semaphore>) -> Result<ChildSlot> {
        if self.0.parent.close_reason().is_some() {
            return Err(quic_error("parallel QUIC parent closed"));
        }
        let total = Arc::clone(&self.0.slots)
            .try_acquire_owned()
            .map_err(|_| quic_error("parallel QUIC connection budget exhausted"))?;
        let direction = Arc::clone(direction)
            .try_acquire_owned()
            .map_err(|_| quic_error("parallel QUIC connection budget exhausted"))?;
        Ok(ChildSlot {
            _total: total,
            _direction: direction,
        })
    }

    fn watch_child(&self, child: quinn::Connection, permit: ChildSlot) {
        let parent = self.0.parent.clone();
        tokio::spawn(async move {
            let _permit = permit;
            tokio::select! {
                _ = parent.closed() => child.close(0u32.into(), b"parent closed"),
                _ = child.closed() => {},
            }
        });
    }

    /// Whether the session owns this endpoint's accept loop. A shared listener
    /// must dispatch children centrally and never call `accept` on this handle.
    pub fn has_exclusive_accept(&self) -> bool {
        self.0.exclusive_accept
    }

    /// Ordinary QUIC peers need the newer central-dispatch capability. The
    /// original parallel capability covered exclusively owned punched pairs.
    pub fn requires_shared_dispatch(&self) -> bool {
        self.0.requires_shared_dispatch
    }

    /// Fixed canonical transport direction, not an application classification.
    /// Duplex reliable children are opened only by the original dialer. An
    /// ordinary client's ephemeral UDP endpoint need not accept reverse dials.
    pub fn is_original_dialer(&self) -> bool {
        self.0.parent.side().is_client()
    }

    pub async fn closed(&self) {
        let _ = self.0.parent.closed().await;
    }

    /// Remaining local outgoing capacity, including pending handshakes. The
    /// aggregate cap still includes incoming siblings. This is not a reservation.
    pub fn available_connection_slots(&self) -> usize {
        self.0
            .slots
            .available_permits()
            .min(self.0.outgoing_slots.available_permits())
    }

    /// Adopt an already authenticated shared-listener child into the SAME
    /// connection budget as outgoing siblings. The caller verifies the session
    /// proof first and closes rejected children; TLS alone is not identity.
    pub fn track_incoming(&self, child: &QuicDatagramHandle) -> Result<()> {
        let permit = self.reserve(&self.0.incoming_slots)?;
        self.watch_child(child.connection.clone(), permit);
        Ok(())
    }

    fn bind_child(
        &self,
        connection: quinn::Connection,
        stream: BoxIoStream,
        permit: ChildSlot,
    ) -> Box<dyn TransportConnection> {
        // The slot follows the actual QUIC lifetime, including raw connection
        // and DATAGRAM clones, rather than only the first byte stream wrapper.
        self.watch_child(connection.clone(), permit);
        let mut peer = self.0.peer.clone();
        peer.remote_addr = Some(connection.remote_address());
        boxed_quic_connection(peer, self.0.endpoint.clone(), connection, stream)
    }

    /// Open a sibling to the parent's current remote UDP address without DNS
    /// discovery or a new local socket. The first stream is advertised lazily;
    /// send the authentication preface before awaiting the remote accept.
    pub async fn connect(&self) -> Result<Box<dyn TransportConnection>> {
        self.connect_with_local_send_budget(None).await
    }

    /// A trusted local initiator can account for TLS and proof startup as well
    /// as application traffic. The peer sees the same generic QUIC connection.
    pub async fn connect_with_local_send_budget(
        &self,
        budget: Option<crate::LocalSendBudgetFactory>,
    ) -> Result<Box<dyn TransportConnection>> {
        let ctx = Arc::clone(&self.0.context);
        let permit = self.reserve(&self.0.outgoing_slots)?;
        let operation = async {
            let (host, _, sni, alpn) = quic_connect_parts(&self.0.peer.uri)?;
            let mut config = build_quic_client_config(&ctx, alpn)?;
            // Siblings use the parent's current UDP path. Its measured RTT is
            // a better initial loss-timer estimate than a cold-connect default.
            // This local rule applies to every generic sibling and changes no
            // transport parameter, role metadata or receiver admission.
            let mut transport = context_transport_config(&ctx);
            transport.initial_rtt(self.0.parent.rtt().clamp(
                std::time::Duration::from_millis(50),
                std::time::Duration::from_secs(1),
            ));
            // The live canonical owner deliberately retains these bounded
            // generic siblings. An unused reliable child otherwise expires
            // every 30 s and is immediately redialed, creating recurring TLS
            // bursts even in an audio-only call. A small transport PING keeps
            // the existing authenticated path; it carries no producer role
            // and grants no scheduling preference. Only the initiator needs
            // this timer: its peer's ACK also refreshes the idle timeout.
            // Parent retirement still closes every child through watch_child.
            transport.keep_alive_interval(Some(std::time::Duration::from_millis(
                CHROME_MAX_IDLE_TIMEOUT_MS / 3,
            )));
            config.transport_config(Arc::new(transport));
            let connection = self
                .0
                .endpoint
                .connect_with_local_send_budget_factory(
                    config,
                    self.0.parent.remote_address(),
                    ctx.effective_sni(sni, host),
                    budget,
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
    /// Idle endpoint waits remain cancellable by the parent. The timeout starts
    /// after dequeuing an incoming connection and bounds TLS/first-stream waits.
    pub async fn accept(&self) -> Result<Box<dyn TransportConnection>> {
        if !self.has_exclusive_accept() {
            return Err(TransportError::Unsupported(
                "shared QUIC listener owns acceptance".to_owned(),
            ));
        }
        if self.0.parent.close_reason().is_some() {
            return Err(quic_error("parallel QUIC parent closed"));
        }
        if self.0.slots.available_permits() == 0 || self.0.incoming_slots.available_permits() == 0 {
            return Err(quic_error("parallel QUIC connection budget exhausted"));
        }
        let ctx = Arc::clone(&self.0.context);
        let operation = async {
            // Serialize only the endpoint dequeue. TLS and the lazily opened
            // first stream must not prevent another bounded accept from making
            // progress. Empty accepts consume no connection permit.
            let incoming = loop {
                let incoming = {
                    let _accept = self.0.accept.lock().await;
                    self.0
                        .endpoint
                        .accept()
                        .await
                        .ok_or_else(|| quic_error("parallel QUIC endpoint closed"))?
                };
                if incoming.remote_address() != self.0.parent.remote_address() {
                    incoming.refuse();
                    continue;
                }
                break incoming;
            };
            let permit = self.reserve(&self.0.incoming_slots)?;
            timeout(ctx.quic.handshake_timeout, async {
                let connection = incoming.accept().map_err(quic_error)?.await?;
                let (send, recv) = match connection.accept_bi().await {
                    Ok(streams) => streams,
                    Err(error) => {
                        connection.close(0u32.into(), b"stream failed");
                        return Err(error.into());
                    }
                };
                Ok(self.bind_child(connection, Box::new(QuicBidiStream { recv, send }), permit))
            })
            .await
            .map_err(|_| handshake_timeout(ctx.quic.handshake_timeout))?
        };
        tokio::select! {
            _ = self.0.parent.closed() => Err(quic_error("parallel QUIC parent closed")),
            result = operation => result,
        }
    }
}

#[cfg(test)]
#[path = "parallel_accept_tests.rs"]
mod parallel_accept_tests;
