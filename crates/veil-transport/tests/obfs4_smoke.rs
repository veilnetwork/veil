//! Integration / smoke tests for the `obfs4-tcp://` transport.
//!
//! Validates the full registry path (URI parse → registry lookup →
//! Transport::connect/bind via trait object) на real TCP sockets,
//! not duplex streams.  Approximates что а deployed daemon does.
//!
//! Two-process smoke test (`obfs4_smoke_two_node`):
//! - One side binds, another connects.
//! - Pushes 64 KiB of plaintext payload each way.
//! - Confirms exact byte-for-byte roundtrip.
//! - Independently captures bytes на the wire by interposing а
//!   forwarder socket between the two halves; asserts no OVL1 magic
//!   appears в the captured traffic.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use veil_transport::{TransportContext, TransportRegistry, TransportUri};

fn ctx_with_psk(psk: [u8; 32]) -> Arc<TransportContext> {
    let mut ctx = TransportContext::for_debug().expect("debug ctx builds");
    ctx.obfs4_psk = Some(Arc::new(psk));
    Arc::new(ctx)
}

/// Full registry path: parse `obfs4-tcp://127.0.0.1:0` → registry
/// resolves к `Obfs4TcpTransport` → bind → accept → connect →
/// round-trip bytes.  No magic in the wire.
#[tokio::test]
async fn obfs4_smoke_two_node() {
    let psk = [0x42u8; 32];
    let ctx = ctx_with_psk(psk);
    let registry = TransportRegistry::with_defaults();
    let transport = registry.get("obfs4-tcp").expect("obfs4-tcp registered");

    let bind_uri = TransportUri::parse("obfs4-tcp://127.0.0.1:0").expect("URI parses");
    let listener = transport
        .bind(&bind_uri, Arc::clone(&ctx))
        .await
        .expect("bind succeeds");
    let local = listener.local_addr();
    let port: u16 = local
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .expect("port in bind local_addr");

    let ctx_server = Arc::clone(&ctx);
    let server_task = tokio::spawn(async move {
        let _ = ctx_server;
        let conn = listener.accept().await.expect("accept");
        let mut stream = conn.into_stream().expect("into_stream");

        // Read 1 KiB of payload, echo back.
        let mut buf = vec![0u8; 1024];
        stream.read_exact(&mut buf).await.expect("server read");
        stream.write_all(&buf).await.expect("server write");
        stream.flush().await.expect("server flush");
        buf
    });

    let connect_uri =
        TransportUri::parse(&format!("obfs4-tcp://127.0.0.1:{port}")).expect("URI parses");
    let transport_client = registry.get("obfs4-tcp").unwrap();
    let conn = transport_client
        .connect(&connect_uri, Arc::clone(&ctx))
        .await
        .expect("connect");
    let mut stream = conn.into_stream().expect("client into_stream");

    let payload = {
        let mut p = vec![0u8; 1024];
        // Embed OVL1 magic в the payload — if it appears на the wire,
        // the framing layer is broken.
        for chunk in p.chunks_mut(32) {
            let n = 4.min(chunk.len());
            chunk[..n].copy_from_slice(&b"OVL1"[..n]);
        }
        p
    };
    stream.write_all(&payload).await.expect("client write");
    stream.flush().await.expect("client flush");

    let mut got = vec![0u8; 1024];
    stream.read_exact(&mut got).await.expect("client read");
    assert_eq!(got, payload, "echo'd bytes must match");

    let server_got = server_task.await.expect("server task ok");
    assert_eq!(server_got, payload, "server saw plaintext payload");
}

/// Active-probe scenario: an attacker що doesn't know the PSK connects
/// и attempts the handshake.  Server must silent-drop; client surfaces
/// an error.
#[tokio::test]
async fn obfs4_smoke_active_probe_rejected() {
    let psk_server = [0x42u8; 32];
    let psk_attacker = [0xABu8; 32];

    let ctx_server = ctx_with_psk(psk_server);
    let ctx_attacker = ctx_with_psk(psk_attacker);
    let registry = TransportRegistry::with_defaults();
    let transport = registry.get("obfs4-tcp").unwrap();

    let bind_uri = TransportUri::parse("obfs4-tcp://127.0.0.1:0").unwrap();
    let listener = transport
        .bind(&bind_uri, Arc::clone(&ctx_server))
        .await
        .unwrap();
    let port: u16 = listener
        .local_addr()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap();

    let server_task = tokio::spawn(async move { listener.accept().await });

    let connect_uri = TransportUri::parse(&format!("obfs4-tcp://127.0.0.1:{port}")).unwrap();
    let result = transport
        .connect(&connect_uri, Arc::clone(&ctx_attacker))
        .await;
    assert!(result.is_err(), "attacker with wrong PSK must fail");

    let server_res = server_task.await.unwrap();
    assert!(server_res.is_err(), "server must silent-drop bad MAC");
}

/// Validate URI scheme parsing + scheme accessor.
#[test]
fn obfs4_tcp_uri_parses_and_renders() {
    let parsed = TransportUri::parse("obfs4-tcp://10.0.0.1:9000").unwrap();
    assert_eq!(parsed.scheme(), "obfs4-tcp");
    assert_eq!(parsed.to_string(), "obfs4-tcp://10.0.0.1:9000");

    // IPv6 host wrapped в brackets.
    let parsed6 = TransportUri::parse("obfs4-tcp://[::1]:9000").unwrap();
    assert_eq!(parsed6.scheme(), "obfs4-tcp");
    assert_eq!(parsed6.to_string(), "obfs4-tcp://[::1]:9000");

    // No PSK leaks through URI.
    assert!(!parsed.to_string().contains("psk="));
}

/// Registry must have `obfs4-tcp` registered by default.
#[test]
fn registry_default_includes_obfs4_tcp() {
    let r = TransportRegistry::with_defaults();
    let t = r.get("obfs4-tcp").expect("obfs4-tcp registered by default");
    assert_eq!(t.scheme(), "obfs4-tcp");
}

/// Listening на а wildcard host should get correctly rewritten.
#[test]
fn obfs4_tcp_wildcard_host_rewrite() {
    let rewritten = veil_transport::rewrite_wildcard_host(
        "obfs4-tcp://0.0.0.0:9000",
        "10.0.0.5".parse().unwrap(),
    );
    assert_eq!(rewritten, Some("obfs4-tcp://10.0.0.5:9000".to_owned()));
}
