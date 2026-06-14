use std::{collections::HashMap, sync::Arc};

use super::{
    TransportContext,
    error::{Result, TransportError},
    traits::{Transport, TransportConnection, TransportListener},
    uri::TransportUri,
};

/// Sink for per-scheme connect-outcome telemetry.
///
/// Implementors record success/failure per transport scheme so that
/// applications can later query "which transports actually work from
/// this node?" via the IPC `TransportHintQuery` frame.
///
/// extraction: lifted out of the concrete
/// `node::transport_hints::TransportHintRegistry` type so the transport
/// layer (this crate) does not reverse-import the node layer. Veilcore
/// supplies the implementation; transport just calls into the trait.
pub trait TransportHintSink: Send + Sync {
    /// Record one connect attempt's outcome for `scheme`.
    fn record(&self, scheme: &str, success: bool);
}

/// Scheme-keyed lookup table for `Transport` implementations. Populated by
/// [`Self::with_defaults`] for production use; tests can construct an empty
/// registry [`Self::new`] and register only the transports they need.
#[derive(Default)]
pub struct TransportRegistry {
    transports: HashMap<&'static str, Arc<dyn Transport>>,
    /// optional success-rate sink — when attached, every
    /// `connect` outcome (success/failure) is recorded here so that
    /// applications can query `which transports have actually worked from
    /// this node?` via the IPC `TransportHintQuery` frame.
    hints: Option<Arc<dyn TransportHintSink>>,
}

impl TransportRegistry {
    /// Construct an empty registry. Use [`Self::with_defaults`] for the
    /// standard transport set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registry pre-populated with TCP, TLS (rustls or btls), QUIC, Unix
    /// (on Unix), SOCKS, SOCKS+TLS, WS, and WSS.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(super::tcp::TcpTransport));
        // prefer BoringSSL backend for `tls://` when the
        // `tls-boring` feature is enabled — Chrome-like ClientHello
        // fingerprint. Default feature set falls back to rustls.
        #[cfg(feature = "tls-boring")]
        registry.register(Arc::new(super::tls_boring::TlsBoringTransport));
        #[cfg(not(feature = "tls-boring"))]
        registry.register(Arc::new(super::tls::TlsTransport));
        registry.register(Arc::new(super::quic::QuicTransport));
        #[cfg(unix)]
        registry.register(Arc::new(super::unix::UnixTransport));
        registry.register(Arc::new(super::socks::SocksTransport));
        registry.register(Arc::new(super::socks::SocksTlsTransport));
        registry.register(Arc::new(super::websocket::WebSocketTransport));
        registry.register(Arc::new(super::websocket::WebSocketSecureTransport));
        registry.register(Arc::new(super::obfs4_tcp::Obfs4TcpTransport));
        registry.register(Arc::new(super::webtunnel::WebtunnelWssTransport));
        registry
    }

    /// Install (or replace) a `Transport` under its declared scheme.
    pub fn register(&mut self, transport: Arc<dyn Transport>) {
        self.transports.insert(transport.scheme(), transport);
    }

    /// Look up a registered transport by URI scheme; returns
    /// [`TransportError::Unsupported`] when the scheme is unknown.
    pub fn get(&self, scheme: &str) -> Result<Arc<dyn Transport>> {
        self.transports.get(scheme).cloned().ok_or_else(|| {
            TransportError::Unsupported(format!("scheme `{scheme}` is not registered"))
        })
    }

    /// Attach a [`TransportHintRegistry`] so that `connect` outcomes are
    /// recorded for IPC queries. Builder-style for chaining.
    pub fn with_hint_registry(mut self, hints: Arc<dyn TransportHintSink>) -> Self {
        self.hints = Some(hints);
        self
    }

    /// Dispatch `connect` to the transport matching `uri.scheme`. Emits a
    /// plaintext-over-WAN warning for `tcp://` / `ws://` to a non-loopback
    /// address. When a hint registry is attached, records the
    /// outcome so `TransportHintQuery` can return ranked schemes.
    pub async fn connect(
        &self,
        uri: &TransportUri,
        ctx: Arc<TransportContext>,
    ) -> Result<Box<dyn TransportConnection>> {
        warn_if_plaintext_non_localhost(uri, "connect");
        let scheme = uri.scheme();
        let result = self.get(scheme)?.connect(uri, ctx).await;
        if let Some(hints) = &self.hints {
            hints.record(scheme, result.is_ok());
        }
        result
    }

    /// Dispatch `bind` (listener creation) to the matching transport. Same
    /// plaintext warning as [`Self::connect`].
    pub async fn bind(
        &self,
        uri: &TransportUri,
        ctx: Arc<TransportContext>,
    ) -> Result<Box<dyn TransportListener>> {
        warn_if_plaintext_non_localhost(uri, "listen");
        self.get(uri.scheme())?.bind(uri, ctx).await
    }
}

/// emit a one-shot warning when the operator binds/connects a
/// plaintext transport (`tcp://`, `ws://`, `socks://`) to a non-localhost
/// address. Plaintext exposes OVL1 frames to on-path DPI, which can fingerprint
/// the protocol and block or throttle it. For production, use `tls://`
/// `quic://`, `wss://`, or `sockstls://`.
///
/// Localhost endpoints are exempt — no DPI on the loopback interface.
/// `0.0.0.0` / `[::]` are NOT localhost (bind on every interface).
fn warn_if_plaintext_non_localhost(uri: &TransportUri, op: &str) {
    let Some(host) = uri.plaintext_host() else {
        return;
    };
    if TransportUri::host_is_localhost(host) {
        return;
    }
    log::warn!(
        "transport.plaintext_non_localhost: {} scheme={} host={} — traffic is readable by on-path DPI; \
         switch to tls://, quic://, wss://, or sockstls:// for production",
        op,
        uri.scheme(),
        host,
    );
}
