//! SOCKS5 ingress proxy.
//!
//! Listens on a local TCP address (default `127.0.0.1:1080`) and speaks the
//! SOCKS5 protocol (RFC 1928). `CONNECT` bridges TCP; `UDP ASSOCIATE` exposes
//! a loopback datagram relay and carries bounded frames over a veil stream.
//!
//! # Current limitations
//!
//! `BIND` and fragmented SOCKS5 UDP datagrams are not supported.
//! Only the `NO_AUTH` authentication method is supported.
//! The exit node is currently a fixed parameter (`exit_node_id`); future
//! versions will select it via the DHT.

use std::sync::Arc;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, watch},
};

/// cap on in-flight SOCKS5 client connections. Without a
/// semaphore, `listener.accept` + `tokio::spawn` loops unbounded — a
/// loopback attacker opens 100k+ concurrent connections and exhausts FDs.
/// Matches the order of `MAX_EXIT_STREAMS=1024` enforced on the exit side.
const MAX_SOCKS_CONCURRENT: usize = 512;

// ── SOCKS5 constants ──────────────────────────────────────────────────────────

const SOCKS_VERSION: u8 = 5;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
/// Maximum time to complete the SOCKS5 handshake (auth + CONNECT header).
/// Protects against slow-read DoS where a client trickles bytes to occupy
/// a file descriptor indefinitely.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

// ── Socks5Error ───────────────────────────────────────────────────────────────

/// Errors that can occur during a SOCKS5 proxy connection.
#[derive(Debug)]
pub enum Socks5Error {
    /// Underlying I/O error (network, socket closed, etc.).
    Io(std::io::Error),
    /// The veil connector could not open a stream to the exit node.
    ConnectFailed(String),
    /// The requested SOCKS5 command is not supported.
    UnsupportedCommand(u8),
    /// The address type (ATYP) in the CONNECT request is not supported.
    UnsupportedAtyp(u8),
}

impl std::fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::ConnectFailed(s) => write!(f, "veil connect failed: {s}"),
            Self::UnsupportedCommand(c) => write!(f, "unsupported SOCKS5 command: 0x{c:02x}"),
            Self::UnsupportedAtyp(a) => write!(f, "unsupported SOCKS5 address type: 0x{a:02x}"),
        }
    }
}

impl std::error::Error for Socks5Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Socks5Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ── ProxyDestination ──────────────────────────────────────────────────────────

/// Transport kind requested through the exit stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyTransport {
    Tcp,
    UdpAssociation,
}

/// Parsed destination plus its exit transport kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyDestination {
    pub host: String,
    pub port: u16,
    pub transport: ProxyTransport,
}

impl ProxyDestination {
    pub fn tcp(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            transport: ProxyTransport::Tcp,
        }
    }

    pub fn udp_association() -> Self {
        Self {
            host: String::new(),
            port: 0,
            transport: ProxyTransport::UdpAssociation,
        }
    }
}

// ── Socks5Proxy ───────────────────────────────────────────────────────────────

/// Runs a SOCKS5 TCP listener. Each accepted connection is handled by
/// [`handle_connection`] in a separate task.
pub struct Socks5Proxy {
    listen_addr: String,
    /// ID of the veil exit node to route through.
    exit_node_id: [u8; 32],
    /// Outbound stream opener — abstracted so tests can inject a mock.
    connector: Arc<dyn ProxyConnector>,
    /// optional metrics for throttle-counter. `None` when
    /// metrics are disabled in config — tests use the no-metrics path.
    pub metrics: Option<Arc<dyn crate::ProxyMetrics>>,
}

impl Socks5Proxy {
    pub fn new(
        listen_addr: impl Into<String>,
        exit_node_id: [u8; 32],
        connector: Arc<dyn ProxyConnector>,
    ) -> Self {
        Self {
            listen_addr: listen_addr.into(),
            exit_node_id,
            connector,
            metrics: None,
        }
    }

    /// attach metrics so the semaphore-saturation drops are
    /// countable. Chainable constructor to keep `new` signature stable.
    pub fn with_metrics(mut self, metrics: Option<Arc<dyn crate::ProxyMetrics>>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Start accepting connections. Returns when `shutdown_rx` fires.
    pub async fn run(self: Arc<Self>, mut shutdown_rx: watch::Receiver<bool>) {
        let listener = match TcpListener::bind(&self.listen_addr).await {
            Ok(l) => l,
            Err(e) => {
                log::error!("socks5 bind {} failed: {e}", self.listen_addr);
                return;
            }
        };
        // bound in-flight handler tasks so a client can't open
        // unbounded concurrent connections. `try_acquire_owned` returns
        // `None` at cap — we reject and close without spawning.
        let concurrency = Arc::new(Semaphore::new(MAX_SOCKS_CONCURRENT));

        loop {
            tokio::select! {
                // biased: shutdown beats new accepts so `node stop` doesn't
                // race one more client in.
                biased;
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, _addr)) => {
                            let Ok(permit) = Arc::clone(&concurrency).try_acquire_owned() else {
                                // At cap: drop the stream immediately. The
                                // client observes a TCP reset; no handshake
                                // is attempted on our side.
                                log::warn!(
                                    "socks5 at cap {}: rejecting new connection",
                                    MAX_SOCKS_CONCURRENT,
                                );
                                if let Some(m) = &self.metrics { m.inc_socks5_accepts_throttled(); }
                                drop(stream);
                                continue;
                            };
                            let proxy = Arc::clone(&self);
                            tokio::spawn(async move {
                                let _ = handle_connection(stream, proxy.exit_node_id, &*proxy.connector).await;
                                // Permit released on drop once handler returns.
                                drop(permit);
                            });
                        }
                        Err(e) => {
                            log::warn!("socks5 accept error: {e}");
                            // Brief pause to avoid tight-loop on persistent errors.
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
    }
}

// ── ProxyConnector trait ──────────────────────────────────────────────────────

/// Abstraction over the outbound stream to the exit node.
///
/// The real implementation calls into `SessionTxRegistry` / IPC stream API.
/// Tests can inject a mock (e.g. a connected `TcpStream` pair).
#[async_trait::async_trait]
pub trait ProxyConnector: Send + Sync {
    /// Open a bidirectional byte stream to `destination` via `exit_node_id`.
    ///
    /// Returns a boxed `(read, write)` pair on success, or a [`Socks5Error`].
    async fn connect(
        &self,
        exit_node_id: [u8; 32],
        destination: &ProxyDestination,
    ) -> Result<Box<dyn BiStream>, Socks5Error>;
}

/// A bidirectional stream suitable for proxying.
pub trait BiStream: Send + Unpin {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    );
}

enum SocksRequest {
    Connect(ProxyDestination),
    UdpAssociation,
}

// ── SOCKS5 handshake + bridge ─────────────────────────────────────────────────

/// Handle one accepted SOCKS5 client connection.
pub async fn handle_connection(
    mut client: TcpStream,
    exit_node_id: [u8; 32],
    connector: &dyn ProxyConnector,
) -> std::io::Result<()> {
    // Wrap the entire handshake in a timeout to prevent slow-read DoS attacks
    // where a client trickles bytes and holds a file descriptor open indefinitely.
    let request = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        // ── auth negotiation ─────────────────────────────────────────
        let mut hdr = [0u8; 2];
        client.read_exact(&mut hdr).await?;
        if hdr[0] != SOCKS_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not SOCKS5",
            ));
        }
        let nmethods = hdr[1] as usize;
        let mut methods = vec![0u8; nmethods];
        client.read_exact(&mut methods).await?;

        // Accept NO_AUTH only.
        if methods.contains(&METHOD_NO_AUTH) {
            client.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;
        } else {
            client
                .write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE])
                .await?;
            return Err(std::io::Error::other("no acceptable auth method"));
        }

        // ── CONNECT request ──────────────────────────────────────────
        let mut req_hdr = [0u8; 4];
        client.read_exact(&mut req_hdr).await?;
        if req_hdr[0] != SOCKS_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "not SOCKS5 request",
            ));
        }
        // req_hdr[2] is RSV, req_hdr[3] is ATYP.
        match parse_destination(&mut client, req_hdr[3]).await {
            Ok(destination) => match req_hdr[1] {
                CMD_CONNECT => Ok(SocksRequest::Connect(destination)),
                // RFC 1928 requires the client-supplied address to be parsed,
                // but xVeil learns and pins the actual loopback UDP endpoint
                // from the first datagram instead of trusting this hint.
                CMD_UDP_ASSOCIATE => Ok(SocksRequest::UdpAssociation),
                _ => {
                    send_reply(
                        &mut client,
                        REP_CMD_NOT_SUPPORTED,
                        std::net::Ipv4Addr::UNSPECIFIED,
                        0,
                    )
                    .await?;
                    Err(std::io::Error::other("unsupported command"))
                }
            },
            Err(_) => {
                send_reply(
                    &mut client,
                    REP_ATYP_NOT_SUPPORTED,
                    std::net::Ipv4Addr::UNSPECIFIED,
                    0,
                )
                .await?;
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "bad destination",
                ))
            }
        }
    })
    .await
    .map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "SOCKS5 handshake timed out")
    })??;

    let SocksRequest::Connect(dst) = request else {
        return handle_udp_association(client, exit_node_id, connector).await;
    };

    // ── open veil stream to exit node ─────────────────────────────
    let stream = match connector.connect(exit_node_id, &dst).await {
        Ok(s) => s,
        Err(_e) => {
            send_reply(
                &mut client,
                REP_GENERAL_FAILURE,
                std::net::Ipv4Addr::UNSPECIFIED,
                0,
            )
            .await?;
            return Ok(());
        }
    };

    // ── send success reply, start bridging ───────────────────────────
    send_reply(&mut client, REP_SUCCESS, std::net::Ipv4Addr::UNSPECIFIED, 0).await?;

    // Bridge the SOCKS5 client socket with the veil stream.
    // Using futures directly (not spawn) ensures the losing direction is cancelled
    // when the winning direction closes, with no orphaned background tasks.
    let (mut exit_r, mut exit_w) = stream.split();
    let (mut client_r, mut client_w) = client.into_split();

    // Bridge bidirectionally, draining BOTH directions (audit cycle-8): the old
    // `select!` cancelled the opposite copy on first EOF, truncating the
    // response when a client half-closes its request. `join!` + per-direction
    // `shutdown` mirrors the oproxy bridge.
    let up = async {
        let _ = tokio::io::copy(&mut client_r, &mut exit_w).await;
        let _ = exit_w.shutdown().await;
    };
    let down = async {
        let _ = tokio::io::copy(&mut exit_r, &mut client_w).await;
        let _ = client_w.shutdown().await;
    };
    tokio::join!(up, down);
    Ok(())
}

async fn handle_udp_association(
    mut control: TcpStream,
    exit_node_id: [u8; 32],
    connector: &dyn ProxyConnector,
) -> std::io::Result<()> {
    use crate::udp::{
        MAX_UDP_PAYLOAD, encode_datagram, encode_socks5_datagram, parse_socks5_datagram,
        read_datagram,
    };

    let peer = control.peer_addr()?;
    let local = control.local_addr()?;
    let stream = match connector
        .connect(exit_node_id, &ProxyDestination::udp_association())
        .await
    {
        Ok(stream) => stream,
        Err(_) => {
            send_reply(
                &mut control,
                REP_GENERAL_FAILURE,
                std::net::Ipv4Addr::UNSPECIFIED,
                0,
            )
            .await?;
            return Ok(());
        }
    };

    let relay = UdpSocket::bind(std::net::SocketAddr::new(local.ip(), 0)).await?;
    let relay_addr = relay.local_addr()?;
    send_reply_addr(&mut control, REP_SUCCESS, relay_addr).await?;

    let (mut exit_r, mut exit_w) = stream.split();
    let mut learned_client = None;
    let mut udp_buffer = vec![0u8; MAX_UDP_PAYLOAD + 512];
    let mut control_byte = [0u8; 1];

    loop {
        tokio::select! {
            control_read = control.read(&mut control_byte) => {
                match control_read {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
            received = relay.recv_from(&mut udp_buffer) => {
                let Ok((length, source)) = received else { break; };
                // The TCP control peer owns the association. Pin the exact UDP
                // endpoint on its first loopback datagram so another local
                // process cannot inject traffic into an established tunnel.
                if source.ip() != peer.ip() {
                    continue;
                }
                if let Some(expected) = learned_client {
                    if source != expected {
                        continue;
                    }
                } else {
                    learned_client = Some(source);
                }
                let Ok(datagram) = parse_socks5_datagram(&udp_buffer[..length]) else {
                    continue;
                };
                let Ok(frame) = encode_datagram(&datagram) else {
                    continue;
                };
                if exit_w.write_all(&frame).await.is_err() {
                    break;
                }
            }
            response = read_datagram(&mut exit_r) => {
                let Ok(datagram) = response else { break; };
                let Some(client) = learned_client else { continue; };
                let Ok(packet) = encode_socks5_datagram(&datagram) else {
                    continue;
                };
                if relay.send_to(&packet, client).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = exit_w.shutdown().await;
    Ok(())
}

/// Send a SOCKS5 reply with IPv4 bound address.
async fn send_reply(
    client: &mut TcpStream,
    rep: u8,
    bnd_addr: std::net::Ipv4Addr,
    bnd_port: u16,
) -> std::io::Result<()> {
    send_reply_addr(
        client,
        rep,
        std::net::SocketAddr::new(std::net::IpAddr::V4(bnd_addr), bnd_port),
    )
    .await
}

async fn send_reply_addr(
    client: &mut TcpStream,
    rep: u8,
    bound: std::net::SocketAddr,
) -> std::io::Result<()> {
    let mut reply = vec![SOCKS_VERSION, rep, 0x00];
    match bound.ip() {
        std::net::IpAddr::V4(address) => {
            reply.push(ATYP_IPV4);
            reply.extend_from_slice(&address.octets());
        }
        std::net::IpAddr::V6(address) => {
            reply.push(ATYP_IPV6);
            reply.extend_from_slice(&address.octets());
        }
    }
    reply.extend_from_slice(&bound.port().to_be_bytes());
    client.write_all(&reply).await
}

/// Parse destination address from SOCKS5 request body (after the 4-byte header).
async fn parse_destination(client: &mut TcpStream, atyp: u8) -> std::io::Result<ProxyDestination> {
    let host = match atyp {
        ATYP_IPV4 => {
            let mut addr = [0u8; 4];
            client.read_exact(&mut addr).await?;
            std::net::Ipv4Addr::from(addr).to_string()
        }
        ATYP_IPV6 => {
            let mut addr = [0u8; 16];
            client.read_exact(&mut addr).await?;
            std::net::Ipv6Addr::from(addr).to_string()
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            client.read_exact(&mut len_buf).await?;
            let mut domain = vec![0u8; len_buf[0] as usize];
            client.read_exact(&mut domain).await?;
            String::from_utf8(domain).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid domain")
            })?
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported atyp",
            ));
        }
    };

    let mut port_buf = [0u8; 2];
    client.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    Ok(ProxyDestination::tcp(host, port))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::net::TcpStream;

    // ── Mock connector: returns a connected socket pair ───────────────────────

    struct MockConnector {
        /// The "server" side — written by the mock, read by the bridge.
        server_tx: tokio::sync::Mutex<Option<tokio::io::DuplexStream>>,
    }

    struct DuplexBiStream(tokio::io::DuplexStream);

    impl BiStream for DuplexBiStream {
        fn split(
            self: Box<Self>,
        ) -> (
            Box<dyn tokio::io::AsyncRead + Send + Unpin>,
            Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
        ) {
            let (r, w) = tokio::io::split(self.0);
            (Box::new(r), Box::new(w))
        }
    }

    #[async_trait::async_trait]
    impl ProxyConnector for MockConnector {
        async fn connect(
            &self,
            _exit_node_id: [u8; 32],
            _destination: &ProxyDestination,
        ) -> Result<Box<dyn BiStream>, Socks5Error> {
            // Return the client-facing half; keep server half for the test.
            let (client_half, server_half) = tokio::io::duplex(4096);
            *self.server_tx.lock().await = Some(server_half);
            Ok(Box::new(DuplexBiStream(client_half)))
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Write a SOCKS5 client greeting (NO_AUTH) and return the server's method choice.
    async fn socks5_greet(stream: &mut TcpStream) -> u8 {
        stream.write_all(&[5, 1, 0]).await.unwrap(); // version=5, nmethods=1, NO_AUTH
        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp[0], 5);
        resp[1] // chosen method
    }

    /// Send a SOCKS5 CONNECT to a domain and read the reply code.
    async fn socks5_connect_domain(stream: &mut TcpStream, host: &str, port: u16) -> u8 {
        let domain = host.as_bytes();
        let mut req = vec![5, 1, 0, ATYP_DOMAIN, domain.len() as u8];
        req.extend_from_slice(domain);
        req.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&req).await.unwrap();

        let mut reply = [0u8; 10]; // ver+rep+rsv+atyp+4+2
        stream.read_exact(&mut reply).await.unwrap();
        reply[1] // REP byte
    }

    // ── 33.1: SOCKS5 server accepts connections and speaks the protocol ────────

    #[tokio::test]
    async fn socks5_no_auth_negotiation() {
        let connector = Arc::new(MockConnector {
            server_tx: tokio::sync::Mutex::new(None),
        });
        let _proxy = Arc::new(Socks5Proxy::new(
            "127.0.0.1:0",
            [0u8; 32],
            Arc::clone(&connector) as Arc<dyn ProxyConnector>,
        ));

        let (_shutdown_tx, _shutdown_rx) = watch::channel(false);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a minimal accept loop using the raw handle_connection function.
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let c = Arc::clone(&connector);
                tokio::spawn(async move {
                    let _ = handle_connection(stream, [0u8; 32], &*c).await;
                });
            }
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let method = socks5_greet(&mut client).await;
        assert_eq!(method, METHOD_NO_AUTH, "server should select NO_AUTH");
    }

    // ── 33.2: CONNECT to a domain succeeds and bridges data ───────────────────

    #[tokio::test]
    async fn socks5_connect_domain_bridges_data() {
        let connector = Arc::new(MockConnector {
            server_tx: tokio::sync::Mutex::new(None),
        });
        let connector_clone = Arc::clone(&connector);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let c = Arc::clone(&connector_clone);
                tokio::spawn(async move {
                    let _ = handle_connection(stream, [0u8; 32], &*c).await;
                });
            }
        });

        let mut client = TcpStream::connect(addr).await.unwrap();

        // Handshake.
        let method = socks5_greet(&mut client).await;
        assert_eq!(method, METHOD_NO_AUTH);

        // CONNECT to example.com:80.
        let rep = socks5_connect_domain(&mut client, "example.com", 80).await;
        assert_eq!(rep, REP_SUCCESS, "expected success reply");

        // Write through the proxy and verify the mock receives it.
        client.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();

        let mut server_side = connector.server_tx.lock().await.take().unwrap();
        let mut buf = [0u8; 18];
        use tokio::io::AsyncReadExt;
        server_side.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"GET / HTTP/1.0\r\n\r\n");
    }

    // ── 33.6: end-to-end SOCKS5 → exit proxy → TCP echo ─────────────────────
    //
    // Wires the full proxy path in-process:
    // SOCKS5 client
    // → Socks5Proxy (accepts the SOCKS5 handshake)
    // → ExitConnector (builds a duplex pair, one side goes to exit proxy)
    // → handle_proxy_connect_stream (connects to real TCP echo server)
    // → local echo TCP server
    //
    // The SOCKS5 client writes "hello" and reads back "hello" to verify the
    // complete data path.

    // ── 33.6: end-to-end SOCKS5 → TCP echo (in-process) ─────────────────────
    //
    // Wires the full SOCKS5 server path in-process. The `TcpConnector`
    // directly opens a real TCP connection to the echo server using the
    // destination parsed from the SOCKS5 CONNECT request, simulating what the
    // exit proxy would do after receiving the veil stream.

    struct TcpBiStream(tokio::net::TcpStream);

    impl BiStream for TcpBiStream {
        fn split(
            self: Box<Self>,
        ) -> (
            Box<dyn tokio::io::AsyncRead + Send + Unpin>,
            Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
        ) {
            let (r, w) = self.0.into_split();
            (Box::new(r), Box::new(w))
        }
    }

    /// A connector that opens a real TCP connection to the destination.
    struct TcpConnector;

    #[async_trait::async_trait]
    impl ProxyConnector for TcpConnector {
        async fn connect(
            &self,
            _exit_node_id: [u8; 32],
            destination: &ProxyDestination,
        ) -> Result<Box<dyn BiStream>, Socks5Error> {
            let tcp = TcpStream::connect(format!("{}:{}", destination.host, destination.port))
                .await
                .map_err(|e| Socks5Error::ConnectFailed(e.to_string()))?;
            Ok(Box::new(TcpBiStream(tcp)))
        }
    }

    #[tokio::test]
    async fn e2e_socks5_through_exit_to_tcp_echo() {
        use tokio::net::TcpListener;

        // Start a local TCP echo server.
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    tokio::io::copy(&mut r, &mut w).await.ok();
                });
            }
        });

        // Start the SOCKS5 proxy wired to the TcpConnector.
        let connector = Arc::new(TcpConnector);
        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = socks_listener.accept().await else {
                    break;
                };
                let c = Arc::clone(&connector) as Arc<dyn ProxyConnector>;
                tokio::spawn(async move {
                    let _ = handle_connection(stream, [0u8; 32], &*c).await;
                });
            }
        });

        // SOCKS5 client.
        let mut client = TcpStream::connect(socks_addr).await.unwrap();

        // negotiate NO_AUTH.
        let method = socks5_greet(&mut client).await;
        assert_eq!(method, METHOD_NO_AUTH);

        // CONNECT to echo server via the proxy.
        let rep = socks5_connect_domain(&mut client, "127.0.0.1", echo_addr.port()).await;
        assert_eq!(rep, REP_SUCCESS, "expected SOCKS5 success");

        // write data and verify echo.
        let msg = b"hello veil proxy";
        client.write_all(msg).await.unwrap();

        let mut buf = vec![0u8; msg.len()];
        use tokio::io::AsyncReadExt;
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            client.read_exact(&mut buf),
        )
        .await
        .expect("timeout waiting for echo")
        .unwrap();

        assert_eq!(&buf, msg, "echo data should match sent data");
    }

    struct UdpExitConnector;

    #[async_trait::async_trait]
    impl ProxyConnector for UdpExitConnector {
        async fn connect(
            &self,
            _exit_node_id: [u8; 32],
            destination: &ProxyDestination,
        ) -> Result<Box<dyn BiStream>, Socks5Error> {
            assert_eq!(destination.transport, ProxyTransport::UdpAssociation);
            let (mut client_half, server_half) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                crate::exit::handle_proxy_connect_stream(
                    veil_types::NodeRole::Core,
                    true,
                    true,
                    server_half,
                )
                .await
                .unwrap();
            });
            // Match VeilConnector's contract: the connector, not the SOCKS
            // client, consumes exit readiness.
            client_half
                .write_all(&crate::exit::encode_udp_associate_header())
                .await
                .unwrap();
            let mut ack = [0u8; 1];
            client_half.read_exact(&mut ack).await.unwrap();
            assert_eq!(ack, [0x00]);
            Ok(Box::new(DuplexBiStream(client_half)))
        }
    }

    #[tokio::test]
    async fn e2e_socks5_udp_associate_through_exit_to_udp_echo() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            let (length, peer) = echo.recv_from(&mut buffer).await.unwrap();
            echo.send_to(&buffer[..length], peer).await.unwrap();
        });

        let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = socks_listener.accept().await.unwrap();
            let _ = handle_connection(stream, [0u8; 32], &UdpExitConnector).await;
        });

        let mut control = TcpStream::connect(socks_addr).await.unwrap();
        assert_eq!(socks5_greet(&mut control).await, METHOD_NO_AUTH);
        control
            .write_all(&[5, CMD_UDP_ASSOCIATE, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        control.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], REP_SUCCESS);
        let relay = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                reply[4], reply[5], reply[6], reply[7],
            )),
            u16::from_be_bytes([reply[8], reply[9]]),
        );

        let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let expected = crate::udp::ProxyDatagram {
            destination: ProxyDestination::tcp(echo_addr.ip().to_string(), echo_addr.port()),
            payload: b"veil udp".to_vec(),
        };
        let packet = crate::udp::encode_socks5_datagram(&expected).unwrap();
        udp_client.send_to(&packet, relay).await.unwrap();

        let mut buffer = [0u8; 2048];
        let (length, source) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            udp_client.recv_from(&mut buffer),
        )
        .await
        .expect("timeout waiting for UDP echo")
        .unwrap();
        assert_eq!(source, relay);
        assert_eq!(
            crate::udp::parse_socks5_datagram(&buffer[..length]).unwrap(),
            expected,
        );
    }
}
