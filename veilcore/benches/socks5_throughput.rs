//! Benchmark: SOCKS5 proxy throughput.
//!
//! Measures the throughput overhead of the SOCKS5 ingress proxy by comparing:
//! 1. Direct TCP round-trip (baseline)
//! 2. SOCKS5-proxied TCP round-trip
//!
//! Target: < 2× overhead for an 8 KiB block transfer.
//!
//! The benchmark uses in-process TCP sockets only — no external processes.

use std::sync::Arc;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use veil_node_runtime::proxy::socks5::{BiStream, ProxyConnector, ProxyDestination, Socks5Error};

/// Payload size for each transfer (8 KiB).
const BLOCK_SIZE: usize = 8 * 1024;

// ── TcpConnector (same as in the socks5 tests) ────────────────────────────────

struct TcpBiStream(TcpStream);

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
            .map_err(Socks5Error::Io)?;
        Ok(Box::new(TcpBiStream(tcp)))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Spawn a local echo server and return its bound address.
async fn spawn_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                tokio::io::copy(&mut r, &mut w).await.ok();
            });
        }
    });
    addr
}

/// Spawn a SOCKS5 proxy (with TcpConnector) and return its bound address.
async fn spawn_socks5_proxy() -> std::net::SocketAddr {
    let connector = Arc::new(TcpConnector) as Arc<dyn ProxyConnector>;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let c = Arc::clone(&connector);
            tokio::spawn(async move {
                use veil_node_runtime::proxy::socks5::handle_connection;
                let _ = handle_connection(stream, [0u8; 32], &*c).await;
            });
        }
    });
    addr
}

/// Do a SOCKS5 handshake and CONNECT to `target`, returning the ready stream.
async fn socks5_connect(
    proxy_addr: std::net::SocketAddr,
    target: std::net::SocketAddr,
) -> TcpStream {
    let mut s = TcpStream::connect(proxy_addr).await.unwrap();
    // Auth negotiation.
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[1], 0); // NO_AUTH

    // CONNECT (IPv4).
    let ip = match target.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => panic!("IPv6 not supported in benchmark"),
    };
    let mut req = vec![5u8, 1, 0, 1];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0); // success
    s
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

fn bench_socks5_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let echo_addr = rt.block_on(spawn_echo_server());
    let proxy_addr = rt.block_on(spawn_socks5_proxy());
    let block = vec![0xABu8; BLOCK_SIZE];

    let mut g = c.benchmark_group("socks5_throughput");
    g.throughput(Throughput::Bytes(BLOCK_SIZE as u64));

    // Both benches reuse a single warm connection across iterations.  The
    // previous per-iteration `TcpStream::connect` / `socks5_connect` churned
    // thousands of short-lived loopback sockets, exhausting the ephemeral-port
    // range on macOS (`EADDRNOTAVAIL` during criterion's warm-up) — Linux's
    // larger range + faster TIME_WAIT recycling merely hid it.  A throughput
    // bench wants the warm-path transfer cost anyway, not per-op connection
    // setup, and the direct-vs-proxied comparison stays valid (both measure
    // steady-state 8 KiB round-trips).  The connection lives in a
    // `RefCell<Option<_>>` and each iteration takes→uses→replaces it, so no
    // `RefMut` is ever held across an await (clippy::await_holding_refcell_ref);
    // iterations are sequential, so the slot is always `Some` on entry.

    // ── Baseline: direct TCP echo ─────────────────────────────────────────────

    let direct = std::cell::RefCell::new(Some(
        rt.block_on(async { TcpStream::connect(echo_addr).await.unwrap() }),
    ));
    g.bench_function("direct_tcp_8k", |b| {
        b.to_async(&rt).iter(|| async {
            let mut s = direct.borrow_mut().take().unwrap();
            s.write_all(&block).await.unwrap();
            let mut buf = vec![0u8; BLOCK_SIZE];
            s.read_exact(&mut buf).await.unwrap();
            *direct.borrow_mut() = Some(s);
        });
    });

    // ── Proxied: SOCKS5 → echo ────────────────────────────────────────────────

    let proxied = std::cell::RefCell::new(Some(rt.block_on(socks5_connect(proxy_addr, echo_addr))));
    g.bench_function("socks5_tcp_8k", |b| {
        b.to_async(&rt).iter(|| async {
            let mut s = proxied.borrow_mut().take().unwrap();
            s.write_all(&block).await.unwrap();
            let mut buf = vec![0u8; BLOCK_SIZE];
            s.read_exact(&mut buf).await.unwrap();
            *proxied.borrow_mut() = Some(s);
        });
    });

    g.finish();
}

criterion_group!(benches, bench_socks5_throughput);
criterion_main!(benches);
