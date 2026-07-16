use std::{net::SocketAddr, sync::Arc};

use futures::future::BoxFuture;
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};

use super::{
    TransportContext,
    error::{Result, TransportError, connect_timeout},
    traits::{
        BoxIoStream, PeerMeta, Transport, TransportCapabilities, TransportConnection,
        TransportHandshakeMode, TransportListener, standard_peer_meta,
    },
    uri::TransportUri,
};

/// Upper bound we impose on the TCP Maximum Segment Size of every veil TCP
/// socket (outbound and accepted).
///
/// Device-verified 2026-07-05: a cellular carrier silently black-holed
/// seed→phone 1348-byte (full-MSS) segments — precisely the OVL1
/// KEY_AGREEMENT payload (ML-KEM + Falcon) — while filtering ICMP
/// fragmentation-needed, so path-MTU discovery went blind and the handshake
/// dead-locked at the 10 s timeout (the phone could never complete a single
/// full handshake, so it never bootstrapped a resumption ticket → every
/// redial stayed a cold handshake → permanent 0 live sessions). Capping
/// outgoing segments to 1200 bytes (comfortably under the observed
/// ~1240–1388 B effective path-MTU floor on that link) lets the handshake
/// through. 1200 mirrors the seed-side `iptables … TCPMSS --set-mss 1200`
/// mitigation but travels with the binary, so a fresh node / re-imaged seed
/// stays fixed without any firewall state.
pub(crate) const DOWNLINK_MSS_CLAMP: u32 = 1200;

/// Best-effort clamp of `TCP_MAXSEG` on an established socket so this node
/// never emits full-MSS segments that a constrained downlink black-holes
/// (see [`DOWNLINK_MSS_CLAMP`]). A failure here is a missed optimisation,
/// never a correctness problem (the option is absent on a few exotic
/// targets and the kernel bounds the value), so the `Err` is swallowed.
pub(crate) fn clamp_downlink_mss(stream: &TcpStream) {
    #[cfg(unix)]
    {
        let _ = SockRef::from(stream).set_tcp_mss(DOWNLINK_MSS_CLAMP);
    }
    #[cfg(not(unix))]
    {
        // socket2 exposes TCP_MAXSEG only on Unix. Keep the call sites
        // platform-neutral; Windows retains the kernel-selected MSS.
        let _ = (stream, DOWNLINK_MSS_CLAMP);
    }
}

/// Upper bound we impose on the kernel send buffer (`SO_SNDBUF`) of every
/// veil TCP socket (outbound and accepted); `VEIL_TCP_SNDBUF_BYTES`
/// overrides it for live experiments.
///
/// Why: the session runner drains its priority queue in WRR order, so a
/// REALTIME frame overtakes queued bulk INSIDE the process — but bytes
/// already written to the socket are beyond reordering, and the kernel
/// autotunes the send buffer into the megabytes. On a ~1 MiB/s relay leg a
/// full autotuned buffer is SECONDS of head-of-line delay for call media —
/// exactly the residual RTT-spike class the 2026-07-16 campaign kept
/// measuring after every in-process frame/queue cap (the caps moved the
/// bound to the wire channel, but the kernel buffer below it stayed
/// unbounded). Clamping the buffer moves backpressure up into the process,
/// where the priority queue can actually act on it. 256 KiB still allows
/// ~5 MiB/s on a 50 ms leg — above any single relay leg observed on this
/// overlay — and bulk swarms fan out across circuits/sessions, so file
/// throughput is not gated by one socket's clamp.
pub(crate) const UPLINK_SNDBUF_CLAMP: usize = 256 * 1024;

/// Best-effort `SO_SNDBUF` clamp (see [`UPLINK_SNDBUF_CLAMP`]). A failure is
/// a missed optimisation, never a correctness problem, so the `Err` is
/// swallowed — same stance as [`clamp_downlink_mss`].
pub(crate) fn clamp_uplink_sndbuf(stream: &TcpStream) {
    let bytes = std::env::var("VEIL_TCP_SNDBUF_BYTES")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        // Below one wire blob (64 KiB) the writer itself would stall; treat
        // smaller overrides as misconfiguration and keep the default.
        .filter(|v| *v >= 64 * 1024)
        .unwrap_or(UPLINK_SNDBUF_CLAMP);
    let _ = SockRef::from(stream).set_send_buffer_size(bytes);
}

/// Plain TCP `Transport` implementation. No encryption or framing — use a
/// TLS layer above this transport for confidentiality.
#[derive(Debug, Default)]
pub struct TcpTransport;

pub(crate) struct StreamConnection {
    capabilities: TransportCapabilities,
    peer_meta: PeerMeta,
    stream: Option<BoxIoStream>,
}

impl StreamConnection {
    pub(crate) fn new(peer_meta: PeerMeta, stream: impl super::traits::IoStream + 'static) -> Self {
        Self {
            capabilities: TransportCapabilities::stream_connection(),
            peer_meta,
            stream: Some(Box::new(stream)),
        }
    }
}

impl TransportConnection for StreamConnection {
    fn capabilities(&self) -> &TransportCapabilities {
        &self.capabilities
    }

    fn peer_meta(&self) -> &PeerMeta {
        &self.peer_meta
    }

    fn into_stream(mut self: Box<Self>) -> Result<BoxIoStream> {
        self.stream
            .take()
            .ok_or_else(|| TransportError::Unsupported("stream already taken".to_owned()))
    }

    fn close<'a>(&'a mut self) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Explicit shutdown to avoid half-open TCP sockets.
            if let Some(mut s) = self.stream.take() {
                let _ = tokio::io::AsyncWriteExt::shutdown(&mut s).await;
            }
            Ok(())
        })
    }
}

pub(crate) fn peer_meta(
    scheme: &'static str,
    uri: TransportUri,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
) -> PeerMeta {
    standard_peer_meta(
        scheme,
        uri,
        local_addr,
        remote_addr,
        TransportHandshakeMode::Stream,
    )
}

pub(crate) fn boxed_stream_connection(
    peer_meta: PeerMeta,
    stream: impl super::traits::IoStream + 'static,
) -> Box<dyn TransportConnection> {
    Box::new(StreamConnection::new(peer_meta, stream)) as Box<dyn TransportConnection>
}

pub(crate) async fn connect_tcp_stream(
    host: &str,
    port: u16,
    ctx: &TransportContext,
) -> Result<TcpStream> {
    let addrs = ctx.resolver.resolve(host, port).await?;
    let timeout_duration = ctx.tcp.connect_timeout;
    let mut last_err = None;

    for addr in addrs {
        match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                stream.set_nodelay(ctx.tcp.nodelay)?;
                if let Some(idle) = ctx.tcp.keepalive_idle {
                    let ka = TcpKeepalive::new().with_time(idle);
                    SockRef::from(&stream).set_tcp_keepalive(&ka)?;
                }
                clamp_downlink_mss(&stream);
                clamp_uplink_sndbuf(&stream);
                return Ok(stream);
            }
            Ok(Err(err)) => last_err = Some(err),
            Err(_) => return Err(connect_timeout(timeout_duration)),
        }
    }

    Err(last_err
        .map(TransportError::Io)
        .unwrap_or_else(|| TransportError::Dns(format!("no addresses resolved for {host}:{port}"))))
}

fn tcp_connect_parts(uri: &TransportUri) -> Result<(&str, u16)> {
    match uri {
        TransportUri::Tcp { host, port } => Ok((host.as_str(), *port)),
        _ => Err(TransportError::Unsupported(format!(
            "tcp transport cannot handle `{}`",
            uri.scheme()
        ))),
    }
}

fn tcp_bind_parts(uri: &TransportUri) -> Result<(&str, u16)> {
    match uri {
        TransportUri::Tcp { host, port } => Ok((host.as_str(), *port)),
        _ => Err(TransportError::Unsupported(format!(
            "tcp transport cannot bind `{}`",
            uri.scheme()
        ))),
    }
}

struct TcpTransportListener {
    listener: TcpListener,
    bind_uri: TransportUri,
    keepalive_idle: Option<std::time::Duration>,
}

fn boxed_tcp_listener(
    listener: TcpListener,
    bind_uri: TransportUri,
    keepalive_idle: Option<std::time::Duration>,
) -> Box<dyn TransportListener> {
    Box::new(TcpTransportListener {
        listener,
        bind_uri,
        keepalive_idle,
    }) as Box<dyn TransportListener>
}

impl TransportListener for TcpTransportListener {
    fn accept<'a>(&'a self) -> BoxFuture<'a, Result<Box<dyn TransportConnection>>> {
        Box::pin(async move {
            let (stream, remote_addr) = self.listener.accept().await?;
            if let Some(idle) = self.keepalive_idle {
                let ka = TcpKeepalive::new().with_time(idle);
                SockRef::from(&stream).set_tcp_keepalive(&ka)?;
            }
            clamp_downlink_mss(&stream);
            clamp_uplink_sndbuf(&stream);
            let local_addr = stream.local_addr().ok();
            let peer = peer_meta("tcp", self.bind_uri.clone(), local_addr, Some(remote_addr));
            Ok(boxed_stream_connection(peer, stream))
        })
    }

    fn local_addr(&self) -> String {
        self.listener
            .local_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|_| self.bind_uri.to_string())
    }
}

impl Transport for TcpTransport {
    fn scheme(&self) -> &'static str {
        "tcp"
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
            let (host, port) = tcp_connect_parts(uri)?;
            let stream = connect_tcp_stream(host, port, &ctx).await?;
            let local_addr = stream.local_addr().ok();
            let remote_addr = stream.peer_addr().ok();
            let peer = peer_meta("tcp", uri.clone(), local_addr, remote_addr);
            Ok(boxed_stream_connection(peer, stream))
        })
    }

    fn bind<'a>(
        &'a self,
        uri: &'a TransportUri,
        ctx: Arc<TransportContext>,
    ) -> BoxFuture<'a, Result<Box<dyn TransportListener>>> {
        Box::pin(async move {
            let (host, port) = tcp_bind_parts(uri)?;
            // SO_REUSEADDR avoids the 30-60 s
            // TIME_WAIT lockout on rapid restart (`systemctl restart` /
            // crash-loop). Without it, a node restart that re-binds the
            // same port within the kernel's TIME_WAIT window fails with
            // "address already in use" until ~60 s elapse — operationally
            // disruptive and externally observable as a downtime signal.
            //
            // SO_REUSEADDR on Linux+BSD allows binding to an address that
            // is in TIME_WAIT. It does NOT enable SO_REUSEPORT (multiple
            // processes binding the same port) — that requires a separate
            // call which we deliberately avoid (would mask config errors
            // where two veil instances accidentally share a port).
            let listener = bind_tcp_with_reuseaddr(host, port).await?;
            Ok(boxed_tcp_listener(
                listener,
                uri.clone(),
                ctx.tcp.keepalive_idle,
            ))
        })
    }
}

/// build a `tokio::net::TcpListener` with
/// `SO_REUSEADDR` enabled so a node restart doesn't get blocked by the
/// kernel's TIME_WAIT window for the previously-bound port.
///
/// Resolves `host:port` to one or more socket addresses (handles
/// hostnames + dual-stack `0.0.0.0` / `::` via `tokio::net::lookup_host`)
/// and tries each in order until one binds successfully.
async fn bind_tcp_with_reuseaddr(host: &str, port: u16) -> Result<TcpListener> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if addrs.is_empty() {
        // Fall back to tokio's bind for the empty-resolve edge case so
        // the caller still gets a meaningful "address resolution failed"
        // error from the kernel rather than a synthetic one here.
        return Ok(TcpListener::bind((host, port)).await?);
    }
    let mut last_err: Option<std::io::Error> = None;
    for addr in addrs {
        match build_reuseaddr_listener(addr) {
            Ok(l) => return Ok(l),
            Err(e) => last_err = Some(e),
        }
    }
    Err(TransportError::from(
        last_err.expect("non-empty addrs without error"),
    ))
}

fn build_reuseaddr_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    // `set_only_v6(false)` lets a bound IPv6 socket accept v4-mapped
    // connections on dual-stack hosts; explicit so we don't inherit
    // platform default (Linux defaults to true on 0.0.0.0 listeners
    // but false varies; explicit is safer).
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false); // best-effort — fails harmlessly on IPv4-only kernels
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    // 1024 backlog matches tokio's default and Linux somaxconn ceiling.
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}
