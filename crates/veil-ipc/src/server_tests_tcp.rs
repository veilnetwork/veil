//! b: end-to-end test for the TCP-loopback IPC backend.
//! Marked `#[ignore]` for the same reason as the admin TCP tests
//! (`admin_tcp_*` in `node/admin.rs`): they share the per-test current-
//! thread tokio runtime contention pattern that flakes under high
//! parallel `cargo test` load. Runs cleanly via `--ignored` and on the
//! Windows CI job that exists for exactly this signal.

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::path::{IPC_PORT_FILENAME, IPC_TOKEN_FILENAME, IpcEndpoint};
use crate::server::IpcServer;
use veil_app::AppEndpointRegistry;
use veil_proto::{
    AppIpcHelloOkPayload, AppIpcHelloPayload, FrameFamily, FrameHeader, IPC_PROTOCOL_VERSION,
    LocalAppMsg, codec,
};

fn unique_runtime_dir() -> std::path::PathBuf {
    use rand_core::{OsRng, RngCore};
    let n: u128 = ((OsRng.next_u64() as u128) << 64) | OsRng.next_u64() as u128;
    std::env::temp_dir().join(format!("ovl-ipc-tcp-{}-{:032x}", std::process::id(), n))
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "TCP IPC integration — flakes in parallel cargo test, run with `--ignored` or Windows CI"]
async fn ipc_tcp_hello_roundtrip() {
    let runtime_dir = unique_runtime_dir();
    std::fs::create_dir_all(&runtime_dir).unwrap();
    let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let registry = Arc::new(AppEndpointRegistry::new());
    let mut server = IpcServer::new(
        IpcEndpoint::Tcp {
            bind_addr,
            runtime_dir: runtime_dir.clone(),
        },
        shutdown_rx,
        Arc::clone(&registry),
        [0u8; 32],
    );
    let server_handle = tokio::spawn(async move { server.run().await });

    // Wait for both sidecars to appear.
    let port_path = runtime_dir.join(IPC_PORT_FILENAME);
    let token_path = runtime_dir.join(IPC_TOKEN_FILENAME);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if port_path.exists() && token_path.exists() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "ipc.port + ipc.token sidecars never appeared at {}",
                runtime_dir.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let port: u16 = std::fs::read_to_string(&port_path)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let token_hex = std::fs::read_to_string(&token_path)
        .unwrap()
        .trim()
        .to_owned();
    // Manual hex decode (no `hex` crate dep — keep test self-contained).
    assert_eq!(token_hex.len(), 64, "ipc.token must be 32 hex bytes");
    let mut token = [0u8; 32];
    for (i, byte) in token.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&token_hex[i * 2..i * 2 + 2], 16).unwrap();
    }

    // Connect TCP, send token, then APP_HELLO, expect APP_HELLO_OK.
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    sock.write_all(&token).await.unwrap();
    let hello = AppIpcHelloPayload {
        version: IPC_PROTOCOL_VERSION,
        flags: 0,
    };
    let mut hdr = FrameHeader::new(FrameFamily::LocalApp as u8, LocalAppMsg::AppHello as u16);
    hdr.body_len = AppIpcHelloPayload::WIRE_SIZE as u32;
    sock.write_all(&codec::encode_header(&hdr)).await.unwrap();
    sock.write_all(&hello.encode()).await.unwrap();

    let mut hdr_buf = [0u8; veil_proto::HEADER_SIZE];
    sock.read_exact(&mut hdr_buf).await.unwrap();
    let resp_hdr = codec::decode_header(&hdr_buf).unwrap();
    let mut body = vec![0u8; resp_hdr.body_len as usize];
    sock.read_exact(&mut body).await.unwrap();
    assert_eq!(resp_hdr.msg_type, LocalAppMsg::AppHelloOk as u16);
    let ok = AppIpcHelloOkPayload::decode(&body).unwrap();
    assert_eq!(ok.version, IPC_PROTOCOL_VERSION);

    drop(sock);
    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;

    // Sidecars cleaned up after shutdown.
    assert!(!port_path.exists(), "ipc.port must be removed on shutdown");
    assert!(
        !token_path.exists(),
        "ipc.token must be removed on shutdown"
    );
    let _ = std::fs::remove_dir_all(&runtime_dir);
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "TCP IPC integration — see other ignored test"]
async fn ipc_tcp_wrong_token_rejected() {
    let runtime_dir = unique_runtime_dir();
    std::fs::create_dir_all(&runtime_dir).unwrap();
    let bind_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let registry = Arc::new(AppEndpointRegistry::new());
    let mut server = IpcServer::new(
        IpcEndpoint::Tcp {
            bind_addr,
            runtime_dir: runtime_dir.clone(),
        },
        shutdown_rx,
        Arc::clone(&registry),
        [0u8; 32],
    );
    let server_handle = tokio::spawn(async move { server.run().await });

    let port_path = runtime_dir.join(IPC_PORT_FILENAME);
    for _ in 0..200 {
        if port_path.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let port: u16 = std::fs::read_to_string(&port_path)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    // Connect with wrong token — server must close the connection without
    // serving the IPC protocol.
    let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    sock.write_all(&[0xAAu8; 32]).await.unwrap();
    // Reading should yield EOF (0 bytes) within a short timeout, not data.
    let mut buf = [0u8; 8];
    let n = match tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    assert_eq!(n, 0, "server must close connection on wrong token");

    let _ = shutdown_tx.send(true);
    let _ = server_handle.await;
    let _ = std::fs::remove_dir_all(&runtime_dir);
}
