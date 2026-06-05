//! Pluggable byte-stream transports for OVL1.
//!
//! Each submodule ships a `Transport` impl for one URI scheme (TCP, TLS
//! QUIC, Unix, SOCKS, WS/WSS). [`registry::TransportRegistry`] wires them
//! together behind a unified `connect` / `bind` façade keyed by scheme.

/// Shared per-runtime context (DNS resolver, TLS material, metrics hooks).
pub mod context;
/// HTTPS RR (RFC 9460) lookups for real TLS ECH config resolution
/// (Этап 10 slice 3).
pub mod ech_dns;
/// Ephemeral random-port binder (anti-port-clustering snowflake mode).
pub mod ephemeral;
/// Canonical `TransportError` type and `Result` alias.
pub mod error;
/// TLS ClientHello fingerprint profiles + runtime rotation policy (applied by
/// the `tls-boring` connector; the profile/policy data is always compiled).
pub mod fingerprint;
/// Local transport-success registry — per-scheme connect-outcome counters
/// surfaced via IPC `TransportHintQuery`.
pub mod hint_registry;
/// obfs4-wrapped TCP transport (anti-DPI handshake + AEAD framing).
pub mod obfs4_tcp;
/// On-demand listener controller (PoW-Gated Rendezvous epic, Slice 2).
pub mod on_demand;
/// QUIC `Transport` built on `quinn`.
pub mod quic;
/// Scheme-keyed lookup of transport implementations.
pub mod registry;
/// Ephemeral-port rotation scheduler primitives (Phase 5f).
pub mod rotation;
/// SOCKS5 proxy tunnelling (optional TLS on top).
pub mod socks;
/// Plain TCP transport.
pub mod tcp;
/// TLS transport (rustls by default).
pub mod tls;
/// BoringSSL-backed TLS transport used under `tls-boring`.
#[cfg(feature = "tls-boring")]
pub mod tls_boring;
pub mod tls_material;
/// Core traits every transport implementation must satisfy.
pub mod traits;
/// Unix-domain-socket transport (local host only).
#[cfg(unix)]
pub mod unix;
/// URI parsing and canonicalisation for transport endpoints.
pub mod uri;
/// WebSocket (`ws://`) and secure WebSocket (`wss://`) transports.
pub mod websocket;
/// Webtunnel-over-WSS transport (anti-active-probe + TLS-on-443).
pub mod webtunnel;

pub use context::{
    DnsResolver, MetricsHooks, QuicTransportSettings, SystemDnsResolver, TcpTransportSettings,
    TlsClientFingerprint, TlsContext, TracingHooks, TransportContext, WebSocketClientMode,
};
pub use error::{Result, TransportError};
pub use hint_registry::{SchemeCounters, TransportHintRegistry};
pub use registry::{TransportHintSink, TransportRegistry};
pub use traits::{
    BoxIoStream, IoStream, PeerMeta, Transport, TransportCapabilities, TransportConnection,
    TransportHandshakeMode, TransportListener, TransportMessage, TransportRuntimeInfo,
};
pub use uri::{TransportStack, TransportUri, Wrapper, rewrite_wildcard_host};

// Anti-censorship Phase 2 kill-switch: re-export the obfs4 wire-format
// variant type so veilcore's config-glue layer can parse operator
// config strings без adding а direct veil-obfs4 dep.
pub use veil_obfs4::WireFormatVariant;

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    #[cfg(unix)]
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        PeerMeta, TransportCapabilities, TransportContext, TransportHandshakeMode,
        TransportMessage, TransportRegistry, TransportRuntimeInfo, TransportUri,
    };

    fn make_test_registry_context() -> (TransportRegistry, Arc<TransportContext>) {
        (
            TransportRegistry::with_defaults(),
            Arc::new(TransportContext::for_debug().expect("debug transport context")),
        )
    }

    async fn bind_test_listener(
        registry: &TransportRegistry,
        ctx: &Arc<TransportContext>,
        bind_uri: &TransportUri,
    ) -> (Box<dyn super::TransportListener>, String) {
        let listener = registry
            .bind(bind_uri, Arc::clone(ctx))
            .await
            .expect("listener binds");
        let listen_addr = listener.local_addr();
        (listener, listen_addr)
    }

    async fn run_stream_loopback_roundtrip(
        bind_uri: TransportUri,
        connect_uri: impl Fn(String) -> String,
        assert_connection_shape: fn(&TransportCapabilities, &PeerMeta),
    ) {
        let (registry, ctx) = make_test_registry_context();
        let (listener, listen_addr) = bind_test_listener(&registry, &ctx, &bind_uri).await;

        let server = tokio::spawn(async move {
            let connection = listener.accept().await.expect("server accepts");
            assert_connection_shape(connection.capabilities(), connection.peer_meta());
            let mut stream = connection.into_stream().expect("server stream");
            let mut buf = [0_u8; 5];
            stream.read_exact(&mut buf).await.expect("server read");
            stream.write_all(&buf).await.expect("server write");
            stream.shutdown().await.expect("server shutdown");
        });

        let connect_uri =
            TransportUri::parse(&connect_uri(listen_addr)).expect("connect uri parses");
        let connection = registry
            .connect(&connect_uri, ctx)
            .await
            .expect("client connects");
        assert_connection_shape(connection.capabilities(), connection.peer_meta());
        let mut stream = connection.into_stream().expect("client stream");
        stream.write_all(b"hello").await.expect("client write");
        stream.flush().await.expect("client flush");
        let mut buf = [0_u8; 5];
        stream.read_exact(&mut buf).await.expect("client read");

        assert_eq!(&buf, b"hello");
        server.await.expect("server task joins");
    }

    fn assert_transport_runtime_metadata(
        capabilities: &TransportCapabilities,
        peer: &PeerMeta,
        handshake_mode: TransportHandshakeMode,
    ) {
        assert!(capabilities.runtime_metadata);
        let runtime = peer
            .runtime_info
            .as_ref()
            .expect("runtime metadata should be present");
        assert_eq!(runtime, &TransportRuntimeInfo { handshake_mode });
    }

    fn assert_listener_stream_capabilities(capabilities: &TransportCapabilities) {
        assert!(capabilities.listener);
        assert!(capabilities.byte_stream);
        assert!(capabilities.runtime_metadata);
    }

    fn assert_connection_stream_capabilities(capabilities: &TransportCapabilities) {
        assert!(capabilities.byte_stream);
        assert!(capabilities.runtime_metadata);
    }

    fn assert_no_messages_or_multiplexing(capabilities: &TransportCapabilities) {
        assert!(!capabilities.messages);
        assert!(!capabilities.datagrams);
        assert!(!capabilities.substreams);
    }

    fn assert_tcp_connection_shape(capabilities: &TransportCapabilities, peer: &PeerMeta) {
        assert_transport_runtime_metadata(capabilities, peer, TransportHandshakeMode::Stream);
        assert_connection_stream_capabilities(capabilities);
        assert_no_messages_or_multiplexing(capabilities);
    }

    fn assert_tls_connection_shape(capabilities: &TransportCapabilities, peer: &PeerMeta) {
        // handshake_mode depends on feature flag — `tls-boring`
        // swaps the TLS backend globally through the registry.
        #[cfg(feature = "tls-boring")]
        let expected = TransportHandshakeMode::TlsBoring;
        #[cfg(not(feature = "tls-boring"))]
        let expected = TransportHandshakeMode::TlsRustls;
        assert_transport_runtime_metadata(capabilities, peer, expected);
        assert_connection_stream_capabilities(capabilities);
        assert_no_messages_or_multiplexing(capabilities);
    }

    #[cfg(unix)]
    fn assert_unix_connection_shape(capabilities: &TransportCapabilities, peer: &PeerMeta) {
        assert_transport_runtime_metadata(capabilities, peer, TransportHandshakeMode::Stream);
        assert_connection_stream_capabilities(capabilities);
        assert_no_messages_or_multiplexing(capabilities);
        assert!(peer.local_addr.is_none());
        assert!(peer.remote_addr.is_none());
    }

    fn assert_tcp_listener_capabilities(capabilities: &TransportCapabilities) {
        assert_listener_stream_capabilities(capabilities);
        assert_no_messages_or_multiplexing(capabilities);
    }

    fn assert_ws_connection_shape(capabilities: &TransportCapabilities, peer: &PeerMeta) {
        assert_transport_runtime_metadata(
            capabilities,
            peer,
            TransportHandshakeMode::WebSocketStandard,
        );
        assert_connection_stream_capabilities(capabilities);
        assert!(capabilities.messages);
        assert!(!capabilities.datagrams);
        assert!(!capabilities.substreams);
    }

    fn assert_ws_listener_capabilities(capabilities: &TransportCapabilities) {
        assert_listener_stream_capabilities(capabilities);
        assert!(capabilities.messages);
        assert!(!capabilities.datagrams);
        assert!(!capabilities.substreams);
    }

    fn assert_quic_connection_shape(capabilities: &TransportCapabilities, peer: &PeerMeta) {
        assert_transport_runtime_metadata(capabilities, peer, TransportHandshakeMode::QuicNative);
        assert_connection_stream_capabilities(capabilities);
        assert!(capabilities.datagrams);
        assert!(capabilities.substreams);
        assert!(!capabilities.messages);
    }

    fn assert_quic_listener_capabilities(capabilities: &TransportCapabilities) {
        assert_listener_stream_capabilities(capabilities);
        assert!(capabilities.datagrams);
        assert!(capabilities.substreams);
        assert!(!capabilities.messages);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tcp_registry_loopback_byte_stream() {
        run_stream_loopback_roundtrip(
            TransportUri::parse("tcp://127.0.0.1:0").expect("tcp bind uri parses"),
            |addr| format!("tcp://{addr}"),
            assert_tcp_connection_shape,
        )
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tls_registry_loopback_byte_stream() {
        run_stream_loopback_roundtrip(
            TransportUri::parse("tls://127.0.0.1:0").expect("tls bind uri parses"),
            |addr| format!("tls://{addr}"),
            assert_tls_connection_shape,
        )
        .await;
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn unix_registry_loopback_byte_stream() {
        let socket_path = unique_unix_socket_path();
        let bind_uri = TransportUri::parse(&format!("unix://{}", socket_path.display()))
            .expect("unix bind uri parses");

        run_stream_loopback_roundtrip(bind_uri, |addr| addr, assert_unix_connection_shape).await;

        let _ = std::fs::remove_file(&socket_path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ws_registry_loopback_byte_stream() {
        run_stream_loopback_roundtrip(
            TransportUri::parse("ws://127.0.0.1:0/veil").expect("ws bind uri parses"),
            |addr| format!("ws://{addr}/veil"),
            assert_ws_connection_shape,
        )
        .await;
    }

    ///A: `wss://` end-to-end loopback. With `tls-boring`
    /// the TLS handshake beneath the WebSocket framing runs through BoringSSL
    /// with Chrome-like ClientHello; without it, rustls. Either way the ws
    /// layer sees a plain byte stream.
    #[tokio::test(flavor = "current_thread")]
    async fn wss_registry_loopback_byte_stream() {
        run_stream_loopback_roundtrip(
            TransportUri::parse("wss://127.0.0.1:0/veil").expect("wss bind uri parses"),
            |addr| format!("wss://{addr}/veil"),
            assert_ws_connection_shape,
        )
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ws_registry_loopback_message_frames() {
        let (registry, ctx) = make_test_registry_context();
        let bind_uri = TransportUri::parse("ws://127.0.0.1:0/veil").expect("ws bind uri parses");
        let (listener, listen_addr) = bind_test_listener(&registry, &ctx, &bind_uri).await;

        let server = tokio::spawn(async move {
            let connection = listener.accept().await.expect("server accepts");
            assert_ws_connection_shape(connection.capabilities(), connection.peer_meta());
            let message = connection
                .recv_message()
                .await
                .expect("server recv message");
            assert_eq!(message, TransportMessage::Binary(b"hello".to_vec()));
            connection
                .send_message(TransportMessage::Text("world".to_owned()))
                .await
                .expect("server send message");
        });

        let connect_uri =
            TransportUri::parse(&format!("ws://{listen_addr}/veil")).expect("connect uri parses");
        let connection = registry
            .connect(&connect_uri, ctx)
            .await
            .expect("client connects");
        assert_ws_connection_shape(connection.capabilities(), connection.peer_meta());
        connection
            .send_message(TransportMessage::Binary(b"hello".to_vec()))
            .await
            .expect("client send message");
        let message = connection
            .recv_message()
            .await
            .expect("client recv message");

        assert_eq!(message, TransportMessage::Text("world".to_owned()));
        server.await.expect("server task joins");
    }

    /// QUIC end-to-end loopback over the standard rustls/quinn crypto provider.
    /// Under `tls-boring` the provider swaps to `quinn-btls 0.1.0`, whose
    /// handshake state machine currently panics with self-signed ECDSA certs
    /// generated by rcgen (`failed building secrets for level Application`).
    /// The build target compiles and `build_quic_{client,server}_config` run
    /// without error — the failure is runtime-only inside `quinn-btls`. Ship
    /// the feature as experimental; validate against a real BoringSSL-backed
    /// peer before production use.
    #[cfg_attr(
        feature = "tls-boring",
        ignore = "quinn-btls 0.1.0 runtime panic with self-signed certs — upstream issue"
    )]
    #[tokio::test(flavor = "current_thread")]
    async fn quic_registry_connect_accept_metadata_and_capabilities() {
        let (registry, ctx) = make_test_registry_context();
        let bind_uri = TransportUri::parse("quic://127.0.0.1:0").expect("quic bind uri parses");
        let (listener, listen_addr) = bind_test_listener(&registry, &ctx, &bind_uri).await;

        let server = tokio::spawn(async move {
            let connection = listener.accept().await.expect("server accepts");
            assert_quic_connection_shape(connection.capabilities(), connection.peer_meta());
            let mut stream = connection.into_stream().expect("server stream");
            let mut buf = [0_u8; 5];
            stream.read_exact(&mut buf).await.expect("server read");
            assert_eq!(&buf, b"hello");
        });

        let connect_uri =
            TransportUri::parse(&format!("quic://{listen_addr}")).expect("connect uri parses");
        let connection = registry
            .connect(&connect_uri, ctx)
            .await
            .expect("client connects");
        assert_quic_connection_shape(connection.capabilities(), connection.peer_meta());
        let mut stream = connection.into_stream().expect("client stream");
        stream.write_all(b"hello").await.expect("client write");
        stream.flush().await.expect("client flush");

        server.await.expect("server task joins");
    }

    #[test]
    fn representative_transport_factory_capabilities_are_stable() {
        let registry = TransportRegistry::with_defaults();

        assert_tcp_listener_capabilities(
            &registry.get("tcp").expect("tcp transport").capabilities(),
        );
        assert_ws_listener_capabilities(&registry.get("ws").expect("ws transport").capabilities());
        assert_quic_listener_capabilities(
            &registry.get("quic").expect("quic transport").capabilities(),
        );
    }

    #[cfg(unix)]
    fn unique_unix_socket_path() -> PathBuf {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!("veil-transport-{seed}.sock"))
    }
}
