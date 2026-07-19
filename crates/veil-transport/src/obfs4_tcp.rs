//! Obfs4-wrapped TCP transport.  Plain TCP underneath, obfs4 handshake
//! + AEAD framing applied to the resulting stream so OVL1 is not visible
//! to passive DPI.
//!
//! Wired in Phase 3+4 of [`docs/internal/PLAN_TRANSPORT_OBFUSCATION.md`](../../docs/internal/PLAN_TRANSPORT_OBFUSCATION.md).
//!
//! ## URI scheme
//!
//! `obfs4-tcp://host:port` — same host/port form as `tcp://`.  The PSK
//! comes from [`TransportContext::obfs4_psk`] (per-runtime configuration);
//! per-peer PSK lookup is a follow-up.
//!
//! ## Anti-probing
//!
//! Server-side `bind` accepts only connections that carry a valid
//! obfs4 handshake MAC.  Bad-MAC clients are silent-dropped (the
//! `handshake.await?` Err path); active probers that don't know the
//! PSK observe only TCP RST/FIN.

use std::sync::Arc;

use futures::future::BoxFuture;
use tokio::net::TcpListener;
use veil_obfs4::{
    NodeIdMacKey, Obfs4Stream, WireFormatVariant, obfs4_client_connect_variant,
    obfs4_server_accept_multi,
};

use super::{
    TransportContext,
    error::{Result, TransportError},
    tcp::{boxed_stream_connection, configure_accepted_tcp, connect_tcp_stream, peer_meta},
    traits::{
        BoxIoStream, RawInbound, Transport, TransportCapabilities, TransportConnection,
        TransportListener,
    },
    uri::TransportUri,
};

/// SECURITY (audit 2026-05-29, HIGH listener-DoS fix): hard upper bound on
/// the inline obfs4 server handshake.  The handshake runs inside the
/// future returned by `accept()`, which the runtime accept-loop awaits
/// before accepting the next connection (services.rs).
/// `read_handshake_message` loops on `stream.read().await` with no time
/// bound and only exits on EOF or HANDSHAKE_MAX_BYTES, so a peer that
/// connects-and-goes-silent would hang the accept future forever and
/// freeze ALL new inbound connections (slowloris / HOL-blocking DoS, no
/// PSK needed).  Bounding the handshake to 10 s converts an unbounded
/// hang into a bounded per-connection cost; the loop drops the stalled
/// connection and continues.  10 s is generous for a legit crypto
/// handshake + round-trip yet tight enough to bound the attack.
const OBFS4_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Plain TCP + obfs4 wrapping.
#[derive(Debug, Default)]
pub struct Obfs4TcpTransport;

fn obfs4_parts(uri: &TransportUri) -> Result<(&str, u16)> {
    match uri {
        TransportUri::Obfs4Tcp { host, port } => Ok((host.as_str(), *port)),
        _ => Err(TransportError::Unsupported(format!(
            "obfs4-tcp transport cannot handle `{}`",
            uri.scheme()
        ))),
    }
}

fn psk_from_context(ctx: &TransportContext) -> Result<NodeIdMacKey> {
    let raw = ctx.obfs4_psk.as_ref().ok_or_else(|| {
        TransportError::Unsupported(
            "obfs4-tcp transport requires `obfs4_psk` set in TransportContext".to_owned(),
        )
    })?;
    Ok(NodeIdMacKey(**raw))
}

impl Transport for Obfs4TcpTransport {
    fn scheme(&self) -> &'static str {
        "obfs4-tcp"
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities::stream_listener()
    }

    fn connect<'a>(
        &'a self,
        uri: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            let (host, port) = obfs4_parts(uri)?;
            let psk = psk_from_context(&ctx)?;
            let tcp = connect_tcp_stream(host, port, &ctx).await?;
            let local_addr = tcp.local_addr().ok();
            let remote_addr = tcp.peer_addr().ok();

            // Phase 2 kill-switch: client variant pulled from
            // TransportContext.  Default V1 preserves pre-Phase-2
            // behavior.  Operator sets `[transport] obfs4_client_variant
            // = "v2"` only when all target servers' accept_variants
            // includes V2 (otherwise outbound dials silent-drop).
            //
            // SECURITY (cycle-7): bound the client handshake with the same
            // OBFS4_HANDSHAKE_TIMEOUT the server side uses. `connect_tcp_stream`
            // above caps the TCP connect, but a peer that completes the TCP
            // connect and then stalls the obfs4 handshake would otherwise wedge
            // this outbound dial indefinitely — across many such dials that is a
            // resource-exhaustion DoS. On timeout we drop the connection (Err).
            let wrapped = tokio::time::timeout(
                OBFS4_HANDSHAKE_TIMEOUT,
                obfs4_client_connect_variant(tcp, &psk, ctx.obfs4_client_variant),
            )
            .await
            .map_err(|_| TransportError::Tls("obfs4 client handshake timed out".to_string()))?
            .map_err(|e| TransportError::Tls(format!("obfs4 client handshake: {e}")))?;

            let peer = peer_meta("obfs4-tcp", uri.clone(), local_addr, remote_addr);
            let boxed_stream: BoxIoStream = Box::new(Obfs4IoStream(wrapped));
            Ok(boxed_stream_connection_obfs4(peer, boxed_stream))
        })
    }

    fn bind<'a>(
        &'a self,
        uri: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportListener>>> {
        Box::pin(async move {
            let (host, port) = obfs4_parts(uri)?;
            let psk = psk_from_context(&ctx)?;
            let listener = TcpListener::bind((host, port)).await?;
            Ok(Box::new(Obfs4TcpListener {
                listener,
                bind_uri: uri.clone(),
                psk,
                keepalive_idle: ctx.tcp.keepalive_idle,
                nodelay: ctx.tcp.nodelay,
                // Phase 2 kill-switch: snapshot the configured
                // accept_variants list at bind time.  Operator changes
                // (config reload) re-spawn the listener; in-flight
                // accepts keep the snapshotted list.
                accept_variants: ctx.obfs4_accept_variants.clone(),
            }) as Box<dyn TransportListener>)
        })
    }
}

struct Obfs4TcpListener {
    listener: TcpListener,
    bind_uri: TransportUri,
    psk: NodeIdMacKey,
    keepalive_idle: Option<std::time::Duration>,
    nodelay: bool,
    /// Phase 2 kill-switch: variants accepted on this listener,
    /// in priority order.  First MAC verify wins.
    accept_variants: Vec<WireFormatVariant>,
}

impl TransportListener for Obfs4TcpListener {
    fn accept<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            let (tcp, remote_addr) = self.listener.accept().await?;
            // Listening sockets do not propagate TCP_NODELAY to accepted
            // connections. Match the outbound obfs4 path before entering the
            // handshake so small realtime frames never sit behind Nagle.
            configure_accepted_tcp(&tcp, self.nodelay, self.keepalive_idle)?;
            let local_addr = tcp.local_addr().ok();

            // Run server-side handshake; silent-drop (return Err)
            // bad-PSK clients per anti-active-probe contract.  Phase 2
            // kill-switch: tries each variant in `accept_variants`
            // order; first MAC verify wins.
            //
            // SECURITY (audit 2026-05-29): bound the handshake so a
            // silent/slow client cannot wedge the accept loop forever
            // (see OBFS4_HANDSHAKE_TIMEOUT).  On timeout we drop the
            // connection (Err) and the loop proceeds to the next accept.
            let (wrapped, _matched_variant) = tokio::time::timeout(
                OBFS4_HANDSHAKE_TIMEOUT,
                obfs4_server_accept_multi(tcp, &self.psk, &self.accept_variants),
            )
            .await
            .map_err(|_| TransportError::Tls("obfs4 server handshake timed out".to_string()))?
            .map_err(|e| TransportError::Tls(format!("obfs4 server handshake: {e}")))?;

            let peer = peer_meta(
                "obfs4-tcp",
                self.bind_uri.clone(),
                local_addr,
                Some(remote_addr),
            );
            let boxed_stream: BoxIoStream = Box::new(Obfs4IoStream(wrapped));
            Ok(boxed_stream_connection_obfs4(peer, boxed_stream))
        })
    }

    /// cycle-7 H2: split the kernel accept (fast) from the obfs4 handshake
    /// (slow, attacker-driven). The runtime spawns `finish` behind the
    /// inbound-handshake semaphore so a stalled client cannot monopolise the
    /// serial accept loop for the whole `OBFS4_HANDSHAKE_TIMEOUT` window.
    fn accept_split<'a>(&'a self) -> BoxFuture<'a, Result<RawInbound>> {
        Box::pin(async move {
            let (tcp, remote_addr) = self.listener.accept().await?;
            configure_accepted_tcp(&tcp, self.nodelay, self.keepalive_idle)?;
            let local_addr = tcp.local_addr().ok();
            // Clone the config the handshake needs so `finish` is `'static`.
            let psk = self.psk.clone();
            let variants = self.accept_variants.clone();
            let bind_uri = self.bind_uri.clone();
            let finish: BoxFuture<'static, Result<Box<dyn TransportConnection>>> =
                Box::pin(async move {
                    let (wrapped, _matched_variant) = tokio::time::timeout(
                        OBFS4_HANDSHAKE_TIMEOUT,
                        obfs4_server_accept_multi(tcp, &psk, &variants),
                    )
                    .await
                    .map_err(|_| {
                        TransportError::Tls("obfs4 server handshake timed out".to_string())
                    })?
                    .map_err(|e| TransportError::Tls(format!("obfs4 server handshake: {e}")))?;
                    let peer = peer_meta("obfs4-tcp", bind_uri, local_addr, Some(remote_addr));
                    let boxed_stream: BoxIoStream = Box::new(Obfs4IoStream(wrapped));
                    Ok(boxed_stream_connection_obfs4(peer, boxed_stream))
                });
            Ok(RawInbound {
                remote_addr: Some(remote_addr),
                finish,
            })
        })
    }

    fn local_addr(&self) -> String {
        self.listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| self.bind_uri.to_string())
    }
}

/// Newtype wrapping `Obfs4Stream<TcpStream>` so we can implement the
/// crate's local `IoStream` marker trait.
struct Obfs4IoStream(Obfs4Stream<tokio::net::TcpStream>);

impl tokio::io::AsyncRead for Obfs4IoStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Obfs4IoStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

fn boxed_stream_connection_obfs4(
    peer: super::traits::PeerMeta,
    stream: BoxIoStream,
) -> Box<dyn TransportConnection> {
    // Reuse the StreamConnection wrapper from the tcp module via a
    // public constructor.  StreamConnection holds peer_meta + a
    // ready-to-be-taken BoxIoStream.
    boxed_stream_connection(peer, BoxIoStreamWrapper(stream))
}

/// Wraps a BoxIoStream so it can be passed as `impl IoStream` to
/// `boxed_stream_connection`.  `BoxIoStream` IS `Box<dyn IoStream>` but
/// `boxed_stream_connection` accepts a concrete `impl IoStream`; this
/// adapter bridges them.
struct BoxIoStreamWrapper(BoxIoStream);

impl tokio::io::AsyncRead for BoxIoStreamWrapper {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for BoxIoStreamWrapper {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn ctx_with_psk(psk: [u8; 32]) -> Arc<TransportContext> {
        let mut ctx = TransportContext::for_debug().expect("debug ctx");
        ctx.obfs4_psk = Some(Arc::new(psk));
        Arc::new(ctx)
    }

    /// End-to-end: bind, accept, connect, round-trip plaintext bytes
    /// over the obfs4-wrapped TCP transport.  Verifies that:
    /// - Both sides successfully complete the obfs4 handshake.
    /// - The session-layer sees plaintext bytes (obfs4 transparent).
    /// - Server rejects a connection with the wrong PSK.
    #[tokio::test]
    async fn obfs4_tcp_round_trip() {
        let psk = [0x42u8; 32];
        let ctx = ctx_with_psk(psk);
        let transport = Obfs4TcpTransport;

        let bind_uri = TransportUri::Obfs4Tcp {
            host: "127.0.0.1".to_owned(),
            port: 0,
        };
        let listener = transport.bind(&bind_uri, Arc::clone(&ctx)).await.unwrap();
        let local = listener.local_addr();
        let port: u16 = local.rsplit(':').next().unwrap().parse().unwrap();

        let server_task = tokio::spawn(async move {
            let conn = listener.accept().await.unwrap();
            let mut stream = conn.into_stream().unwrap();
            let mut buf = vec![0u8; 5];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            stream.write_all(b"world").await.unwrap();
            stream.flush().await.unwrap();
        });

        let connect_uri = TransportUri::Obfs4Tcp {
            host: "127.0.0.1".to_owned(),
            port,
        };
        let conn = transport
            .connect(&connect_uri, Arc::clone(&ctx))
            .await
            .unwrap();
        let mut stream = conn.into_stream().unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = vec![0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");

        let _ = server_task.await;
    }

    /// cycle-7 H2: the split accept path (`accept_split` -> `finish.await`)
    /// completes the same obfs4 handshake as `accept()` and exposes the peer
    /// address BEFORE the handshake runs (so the accept loop can ban-check the
    /// IP without paying for a handshake first).
    #[tokio::test]
    async fn obfs4_tcp_accept_split_round_trip() {
        let psk = [0x42u8; 32];
        let ctx = ctx_with_psk(psk);
        let transport = Obfs4TcpTransport;

        let bind_uri = TransportUri::Obfs4Tcp {
            host: "127.0.0.1".to_owned(),
            port: 0,
        };
        let listener = transport.bind(&bind_uri, Arc::clone(&ctx)).await.unwrap();
        let port: u16 = listener
            .local_addr()
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();

        let server_task = tokio::spawn(async move {
            let raw = listener.accept_split().await.unwrap();
            // Peer addr is known before the handshake completes.
            assert!(
                raw.remote_addr.is_some(),
                "remote_addr must be populated before the handshake runs"
            );
            let conn = raw.finish.await.unwrap();
            let mut stream = conn.into_stream().unwrap();
            let mut buf = vec![0u8; 5];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            stream.write_all(b"world").await.unwrap();
            stream.flush().await.unwrap();
        });

        let connect_uri = TransportUri::Obfs4Tcp {
            host: "127.0.0.1".to_owned(),
            port,
        };
        let conn = transport
            .connect(&connect_uri, Arc::clone(&ctx))
            .await
            .unwrap();
        let mut stream = conn.into_stream().unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = vec![0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");

        let _ = server_task.await;
    }

    #[tokio::test]
    async fn obfs4_tcp_wrong_psk_rejected() {
        let psk_server = [0x42u8; 32];
        let psk_client = [0xABu8; 32];
        let ctx_s = ctx_with_psk(psk_server);
        let ctx_c = ctx_with_psk(psk_client);
        let transport = Obfs4TcpTransport;

        let bind_uri = TransportUri::Obfs4Tcp {
            host: "127.0.0.1".to_owned(),
            port: 0,
        };
        let listener = transport.bind(&bind_uri, Arc::clone(&ctx_s)).await.unwrap();
        let port: u16 = listener
            .local_addr()
            .rsplit(':')
            .next()
            .unwrap()
            .parse()
            .unwrap();

        // Server-accept task in background; expect it to Err on bad MAC.
        let server_task = tokio::spawn(async move { listener.accept().await });

        let connect_uri = TransportUri::Obfs4Tcp {
            host: "127.0.0.1".to_owned(),
            port,
        };
        // Client connect should fail (server silent-drops bad-MAC peer).
        let result = transport.connect(&connect_uri, Arc::clone(&ctx_c)).await;
        assert!(result.is_err(), "client should fail with wrong PSK");

        let server_result = server_task.await.unwrap();
        assert!(server_result.is_err(), "server should reject bad MAC");
    }
}
