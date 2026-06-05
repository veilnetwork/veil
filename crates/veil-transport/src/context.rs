use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

use futures::future::BoxFuture;
use rcgen::generate_simple_self_signed;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

use super::{
    error::{Result, TransportError},
    tls_material,
};

/// Pluggable DNS resolver used by every outbound transport.
pub trait DnsResolver: Send + Sync {
    /// Resolve `host:port` into a list of socket addresses.
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>>;

    /// **Этап 10 slice 3** — query the HTTPS RR (RFC 9460) for `host`
    /// и extract the `ech` SvcParamValue если present.  Returned bytes
    /// are the raw `EchConfigList` payload suitable for
    /// `rustls::client::EchConfig::new(EchConfigListBytes::from(...),
    /// ALL_SUPPORTED_SUITES)`.
    ///
    /// Returns `None` если no HTTPS record exists, no `ech` SvcParamKey
    /// is present, или the lookup fails for any reason.  The caller
    /// (typically [`crate::tls::connect_pki_verified_https_stream`])
    /// treats а `None` return as "fall back к ECH GREASE" — failures
    /// here ара NOT propagated as errors so transient DNS hiccups do
    /// not break bootstrap fetches.
    ///
    /// Default implementation returns `None` (the trait stays backwards-
    /// compatible с custom resolvers що don't implement HTTPS RR queries).
    fn resolve_https_ech<'a>(&'a self, _host: &'a str) -> BoxFuture<'a, Option<Vec<u8>>> {
        Box::pin(async { None })
    }
}

/// Default resolver that defers to the OS resolver via `tokio::net::lookup_host`
/// for А/AAAA queries и а static hickory resolver for HTTPS RR queries
/// (HTTPS records ара not exposed by `tokio::net::lookup_host`).
#[derive(Debug, Default)]
pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, Result<Vec<SocketAddr>>> {
        Box::pin(async move {
            tokio::net::lookup_host((host, port))
                .await
                .map(|iter| iter.collect())
                .map_err(|err| TransportError::Dns(err.to_string()))
        })
    }

    fn resolve_https_ech<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Option<Vec<u8>>> {
        Box::pin(async move { crate::ech_dns::query_https_ech(host).await })
    }
}

/// Per-process TCP tunables applied by every TCP-based transport.
#[derive(Clone, Debug)]
pub struct TcpTransportSettings {
    /// Upper bound on `connect` before aborting.
    pub connect_timeout: Duration,
    /// Whether to set `TCP_NODELAY` on new sockets.
    pub nodelay: bool,
    /// If Some, enables SO_KEEPALIVE with the given idle time before the first probe.
    pub keepalive_idle: Option<Duration>,
}

impl Default for TcpTransportSettings {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            nodelay: true,
            keepalive_idle: Some(Duration::from_secs(60)),
        }
    }
}

/// Per-process QUIC tunables for the `quinn` endpoint.
#[derive(Clone, Debug)]
pub struct QuicTransportSettings {
    /// Upper bound on the initial datagram exchange.
    pub connect_timeout: Duration,
    /// Upper bound on the TLS handshake inside the QUIC endpoint.
    pub handshake_timeout: Duration,
    /// Local socket to bind the QUIC endpoint (default: `0.0.0.0:0`).
    pub bind_addr: SocketAddr,
}

impl Default for QuicTransportSettings {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        }
    }
}

/// Reserved hook for tracing spans emitted by transport code.
#[derive(Clone, Debug, Default)]
pub struct TracingHooks;

/// Reserved hook for metrics counters emitted by transport code.
#[derive(Clone, Debug, Default)]
pub struct MetricsHooks;

/// WebSocket client behavioural mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WebSocketClientMode {
    /// Standard HTTP/1.1 upgrade handshake.
    #[default]
    Standard,
}

/// Which TLS client backend supplies the ClientHello fingerprint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsClientFingerprint {
    /// Default rustls fingerprint (stock Rust TLS stack).
    #[default]
    Rustls,
}

/// Bundle of TLS material used by every TLS-carrying transport.
///
/// Holds: root trust store, server cert chain + key, optional client cert +
/// key, and the pre-built `ClientConfig`/`ServerConfig` that transports
/// plug directly into rustls.
pub struct TlsContext {
    trusted_certificates: Vec<CertificateDer<'static>>,
    server_cert_chain: Vec<CertificateDer<'static>>,
    server_private_key: PrivateKeyDer<'static>,
    client_cert_chain: Option<Vec<CertificateDer<'static>>>,
    client_private_key: Option<PrivateKeyDer<'static>>,
    /// Pre-built rustls client config shared with every `tls://` connect.
    pub client_config: Arc<ClientConfig>,
    /// Pre-built rustls server config shared with every `tls://` listener.
    pub server_config: Arc<ServerConfig>,
    /// Local node's certificate in DER form; sent to peers and compared
    /// against the `node_id` binding.
    pub cert_der: CertificateDer<'static>,
    /// Active client fingerprint mode.
    pub client_fingerprint: TlsClientFingerprint,
    /// include Mozilla's webpki-roots in the client
    /// trust store. When the binary lacks the `tls-webpki-roots`
    /// feature, the flag has no effect. Preserved through
    /// `with_trusted_certificates` / `with_server_identity` / etc.
    /// so successive builder calls don't silently disable system
    /// roots the operator asked for.
    use_system_roots: bool,
}

impl Clone for TlsContext {
    fn clone(&self) -> Self {
        Self {
            trusted_certificates: self.trusted_certificates.clone(),
            server_cert_chain: self.server_cert_chain.clone(),
            server_private_key: self.server_private_key.clone_key(),
            client_cert_chain: self.client_cert_chain.clone(),
            client_private_key: self
                .client_private_key
                .as_ref()
                .map(PrivateKeyDer::clone_key),
            client_config: Arc::clone(&self.client_config),
            server_config: Arc::clone(&self.server_config),
            cert_der: self.cert_der.clone(),
            client_fingerprint: self.client_fingerprint,
            use_system_roots: self.use_system_roots,
        }
    }
}

/// Shared per-runtime context every transport receives on `connect`/`bind`.
#[derive(Clone)]
pub struct TransportContext {
    /// DNS resolver implementation (default: OS resolver).
    pub resolver: Arc<dyn DnsResolver>,
    /// TLS material (root trust, server/client configs, local cert).
    pub tls: TlsContext,
    /// TCP tunables.
    pub tcp: TcpTransportSettings,
    /// QUIC tunables.
    pub quic: QuicTransportSettings,
    /// WebSocket client mode (standard or browser-like).
    pub websocket_mode: WebSocketClientMode,
    /// Reserved tracing hook.
    pub tracing: TracingHooks,
    /// Reserved metrics hook.
    pub metrics: MetricsHooks,
    /// default SNI hostname to present in the TLS ClientHello
    /// when the URI did not specify `?sni=...` AND the target host is not a
    /// loopback address. `None` keeps the legacy behaviour (use the target
    /// host as SNI). Configure with `transport.default_sni` in `Config` to
    /// masquerade against an on-path DPI. Veil's cert verifier is custom
    /// (node_id binding), so SNI value does not affect cert validation.
    pub default_sni: Option<String>,
    /// Pre-shared key для obfs4-tcp transport.  When bound на а listener,
    /// server uses this к verify incoming client MACs. When dialing
    /// out, client uses it к build the handshake MAC.  None disables
    /// obfs4 transport.  Phase 3-interim: single PSK для all peers;
    /// per-peer PSK lookup via `transport_hints` is а follow-up.
    pub obfs4_psk: Option<Arc<[u8; 32]>>,
    /// Webtunnel secret path (e.g. `/_t/random-32-chars`).  When set,
    /// `webtunnel+wss://` transport's server-side matcher will activate
    /// tunnel mode only для requests с this exact path.  None disables
    /// the webtunnel transport.
    pub webtunnel_secret_path: Option<String>,
    /// Webtunnel auth-header token (sent в `X-Veil-Auth` header).
    /// Additional credential checked alongside the secret path.
    /// None = path-only mode.
    pub webtunnel_auth_token: Option<Arc<Vec<u8>>>,
    /// Webtunnel decoy directory (path on disk к static content served
    /// для non-tunnel-mode requests).  None defaults к а minimal
    /// `StaticStringDecoy` що returns "<h1>Welcome</h1>".  Operators
    /// should set к а realistic static-site snapshot.
    pub webtunnel_decoy_dir: Option<std::path::PathBuf>,

    /// SOCKS proxy URL used as outbound-dial **fallback** when direct
    /// transport fails.  Set via `[transport] outbound_socks_fallback_proxy`
    /// в config.  Default `None` keeps outbound direct-only.  Format
    /// example: `socks5://127.0.0.1:9050` (local Tor SOCKS).  Consumed
    /// by the runtime's `socks_fallback_dial` helper.
    pub outbound_socks_fallback_proxy: Option<String>,

    /// **Phase 2 kill-switch — server-side**: list of obfs4 wire-format
    /// variants the listener accepts, в priority order.  Default `&[V1]`
    /// preserves pre-Phase-2 behavior bit-for-bit.  Operators set via
    /// `[transport] obfs4_accept_variants = ["v2", "v1"]` during а
    /// V1→V2 migration; once все clients upgraded, drop к `["v2"]` к
    /// cut off V1.
    pub obfs4_accept_variants: Vec<veil_obfs4::WireFormatVariant>,

    /// **Phase 2 kill-switch — client-side**: obfs4 wire-format
    /// variant used для outbound obfs4-tcp connects.  Default `V1`.
    /// Operators set via `[transport] obfs4_client_variant = "v2"`
    /// only after **all** target servers в the cluster have accept_variants
    /// що includes V2 (otherwise outbound connects silent-drop).
    pub obfs4_client_variant: veil_obfs4::WireFormatVariant,

    /// **Этап 10 slice 2b** — wire TLS ECH GREASE into outbound public-
    /// PKI HTTPS connections (currently the bootstrap fetch path).
    /// Plumbed от `GlobalConfig.tls_ech_grease` via
    /// `transport_glue::context_from_config`.  When `true`,
    /// [`connect_pki_verified_https_stream`] builds the `ClientConfig`
    /// с `.with_ech(EchMode::Grease(...))` — adds an ECH GREASE
    /// extension к the ClientHello, defeating middlebox fingerprinting
    /// що distinguishes ECH-capable от non-ECH connections.
    ///
    /// Default `false` (slice 2b — opt-in).  Slice 2c will flip the
    /// `GlobalConfig` default к `true`.
    pub tls_ech_grease: bool,

    /// Runtime TLS ClientHello fingerprint policy for outbound `tls://` /
    /// `wss://` connects. Only consulted on the `tls-boring` BoringSSL path
    /// (the rustls path cannot morph its ClientHello, so it ignores this).
    /// Selects which browser fingerprint to present and rotates to another on
    /// handshake failure. Plumbed from `[transport.tls_fingerprint]` via
    /// `transport_glue`. Default: rotate Chrome→Firefox→Safari, sticky.
    pub tls_fingerprint: crate::fingerprint::TlsFingerprintPolicy,
}

impl std::fmt::Debug for TransportContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportContext")
            .field("tcp", &self.tcp)
            .field("quic", &self.quic)
            .field("tls_client_fingerprint", &self.tls.client_fingerprint)
            .finish_non_exhaustive()
    }
}

impl TransportContext {
    /// Construct a `TransportContext` from prepared components.
    pub fn new(
        resolver: Arc<dyn DnsResolver>,
        tls: TlsContext,
        tcp: TcpTransportSettings,
        quic: QuicTransportSettings,
    ) -> Self {
        Self {
            resolver,
            tls,
            tcp,
            quic,
            websocket_mode: WebSocketClientMode::Standard,
            tracing: TracingHooks,
            metrics: MetricsHooks,
            default_sni: None,
            obfs4_psk: None,
            webtunnel_secret_path: None,
            webtunnel_auth_token: None,
            webtunnel_decoy_dir: None,
            outbound_socks_fallback_proxy: None,
            obfs4_accept_variants: vec![veil_obfs4::WireFormatVariant::V1],
            obfs4_client_variant: veil_obfs4::WireFormatVariant::V1,
            tls_ech_grease: false,
            tls_fingerprint: crate::fingerprint::TlsFingerprintPolicy::default(),
        }
    }

    /// pick the SNI to advertise for a TLS client handshake.
    ///
    /// Precedence:
    /// 1. Explicit `?sni=...` from the URI (operator intent wins).
    /// 2. Configured `default_sni` — but only when the target host is
    ///    non-loopback, since loopback connections never leave the machine
    ///    and there is no DPI to masquerade against.
    /// 3. The target `host` itself — legacy behaviour.
    pub fn effective_sni<'a>(&'a self, uri_sni: Option<&'a str>, host: &'a str) -> &'a str {
        if let Some(s) = uri_sni {
            return s;
        }
        if let Some(ref dflt) = self.default_sni
            && !crate::uri::TransportUri::host_is_localhost(host)
        {
            return dflt.as_str();
        }
        host
    }

    /// Context pre-populated with self-signed test material — suitable for
    /// unit tests and the loopback sim, NOT for production.
    pub fn for_debug() -> Result<Self> {
        debug_transport_context()
    }

    /// Wrap a hostname string in a rustls `ServerName<'static>`, returning
    /// `InvalidUri` if the name is not a valid DNS name or IP.
    pub fn server_name(&self, name: &str) -> Result<ServerName<'static>> {
        ServerName::try_from(name.to_owned()).map_err(TransportError::from)
    }

    // `Context::from_config` (took `&veilcore::cfg::Config` and
    // populated TCP/TLS knobs from `[transport]` config) was moved to
    // `veilcore::cfg::transport_glue::context_from_config` so this crate
    // stays free of the cfg layer. The builder methods below
    // (`with_trusted_certificates_from_file`, `with_*_identity_from_files`
    // and `TlsContext::with_*`) are the primitives the glue function calls.

    /// Adjust the TCP connect timeout (was previously folded into
    /// `from_config`); kept as a primitive so the cfg-glue can still set it.
    pub fn with_tcp_connect_timeout(mut self, timeout: Duration) -> Self {
        self.tcp.connect_timeout = timeout;
        self
    }

    /// Set the default SNI hostname used by TLS-bearing transports
    ///
    pub fn with_default_sni(mut self, sni: Option<String>) -> Self {
        self.default_sni = sni;
        self
    }

    /// **Этап 10 slice 2b** — enable TLS ECH GREASE на outbound
    /// public-PKI HTTPS connections.  See the field doc на
    /// `tls_ech_grease` для the threat model и [`connect_pki_verified_https_stream`]
    /// для the call-site wiring.
    #[must_use]
    pub fn with_tls_ech_grease(mut self, enabled: bool) -> Self {
        self.tls_ech_grease = enabled;
        self
    }

    /// Set the runtime TLS ClientHello fingerprint policy (tls-boring path).
    /// See the `tls_fingerprint` field doc.
    #[must_use]
    pub fn with_tls_fingerprint(
        mut self,
        policy: crate::fingerprint::TlsFingerprintPolicy,
    ) -> Self {
        self.tls_fingerprint = policy;
        self
    }

    /// Return a new context with additional trust-anchor certificates loaded
    /// from a PEM file.
    pub fn with_trusted_certificates_from_file(&self, path: &Path) -> Result<Self> {
        let certs = TlsContext::load_certificates_from_file(path)?;
        Ok(Self {
            tls: self.tls.with_trusted_certificates(certs)?,
            ..self.clone()
        })
    }

    /// Return a new context with the server cert chain + private key loaded
    /// from disk.
    pub fn with_server_identity_from_files(
        &self,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<Self> {
        let certs = TlsContext::load_certificates_from_file(cert_path)?;
        let key = TlsContext::load_private_key_from_file(key_path)?;
        Ok(Self {
            tls: self.tls.with_server_identity(certs, key)?,
            ..self.clone()
        })
    }

    /// Return a new context with the client cert chain + private key loaded
    /// from disk (for mutual TLS).
    pub fn with_client_identity_from_files(
        &self,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<Self> {
        let certs = TlsContext::load_certificates_from_file(cert_path)?;
        let key = TlsContext::load_private_key_from_file(key_path)?;
        Ok(Self {
            tls: self.tls.with_client_identity(certs, key)?,
            ..self.clone()
        })
    }
}

impl TlsContext {
    /// accessor for the DER-encoded server cert chain. Used by
    /// the `tls-boring` backend to construct a BoringSSL `SslAcceptor` from
    /// the same material that backs the rustls `ServerConfig`.
    #[cfg(feature = "tls-boring")]
    pub fn server_cert_chain_der(&self) -> &[CertificateDer<'static>] {
        &self.server_cert_chain
    }

    /// accessor for the DER-encoded server private key.
    #[cfg(feature = "tls-boring")]
    pub fn server_private_key_der(&self) -> &PrivateKeyDer<'static> {
        &self.server_private_key
    }

    /// `TlsContext` pre-populated with a self-signed test certificate.
    pub fn for_debug() -> Result<Self> {
        let (trusted_certificates, server_cert_chain, server_private_key) = debug_tls_materials()?;
        Self::from_materials(
            trusted_certificates,
            server_cert_chain,
            server_private_key,
            None,
            TlsClientFingerprint::Rustls,
        )
    }

    /// Return a new `TlsContext` with additional trust-anchor certificates
    /// appended.
    pub fn with_trusted_certificates(&self, certs: Vec<CertificateDer<'static>>) -> Result<Self> {
        let mut trusted_certificates = self.trusted_certificates.clone();
        trusted_certificates.extend(certs);
        Self::from_materials_with_roots(
            trusted_certificates,
            self.server_cert_chain.clone(),
            self.server_private_key.clone_key(),
            self.client_identity(),
            self.client_fingerprint,
            self.use_system_roots,
        )
    }

    /// Return a new `TlsContext` with the server cert chain + key replaced.
    pub fn with_server_identity(
        &self,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self> {
        Self::from_materials_with_roots(
            self.trusted_certificates.clone(),
            certs,
            key,
            self.client_identity(),
            self.client_fingerprint,
            self.use_system_roots,
        )
    }

    /// Return a new `TlsContext` with a client cert + key attached (for mTLS).
    pub fn with_client_identity(
        &self,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self> {
        Self::from_materials_with_roots(
            self.trusted_certificates.clone(),
            self.server_cert_chain.clone(),
            self.server_private_key.clone_key(),
            Some((certs, key)),
            self.client_fingerprint,
            self.use_system_roots,
        )
    }

    /// Load a PEM-encoded certificate chain from disk.
    pub fn load_certificates_from_file(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
        tls_material::load_certificates_from_file(path)
    }

    /// Load a PEM-encoded private key from disk.
    pub fn load_private_key_from_file(path: &Path) -> Result<PrivateKeyDer<'static>> {
        tls_material::load_private_key_from_file(path)
    }

    fn from_materials(
        trusted_certificates: Vec<CertificateDer<'static>>,
        server_cert_chain: Vec<CertificateDer<'static>>,
        server_private_key: PrivateKeyDer<'static>,
        client_identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
        client_fingerprint: TlsClientFingerprint,
    ) -> Result<Self> {
        Self::from_materials_with_roots(
            trusted_certificates,
            server_cert_chain,
            server_private_key,
            client_identity,
            client_fingerprint,
            false, // preserve legacy default: no system roots
        )
    }

    fn from_materials_with_roots(
        trusted_certificates: Vec<CertificateDer<'static>>,
        server_cert_chain: Vec<CertificateDer<'static>>,
        server_private_key: PrivateKeyDer<'static>,
        client_identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
        client_fingerprint: TlsClientFingerprint,
        use_system_roots: bool,
    ) -> Result<Self> {
        let cert_der = server_cert_chain
            .first()
            .cloned()
            .ok_or_else(|| TransportError::Tls("certificate chain is empty".to_owned()))?;
        let client_config = build_client_config(
            trusted_certificates.clone(),
            client_identity
                .as_ref()
                .map(|(certs, key)| (certs.clone(), key.clone_key())),
            use_system_roots,
        )?;
        let server_config =
            build_server_config(server_cert_chain.clone(), server_private_key.clone_key())?;
        Ok(Self {
            trusted_certificates,
            server_cert_chain,
            server_private_key,
            client_cert_chain: client_identity.as_ref().map(|(certs, _)| certs.clone()),
            client_private_key: client_identity.as_ref().map(|(_, key)| key.clone_key()),
            client_config,
            server_config,
            cert_der,
            client_fingerprint,
            use_system_roots,
        })
    }

    /// return a new `TlsContext` with the system-roots
    /// flag flipped. Rebuilds the client config so the trust
    /// store reflects the new setting.
    pub fn with_system_roots(&self, enabled: bool) -> Result<Self> {
        Self::from_materials_with_roots(
            self.trusted_certificates.clone(),
            self.server_cert_chain.clone(),
            self.server_private_key.clone_key(),
            self.client_identity(),
            self.client_fingerprint,
            enabled,
        )
    }

    fn client_identity(&self) -> Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        Some((
            self.client_cert_chain.clone()?,
            self.client_private_key.as_ref()?.clone_key(),
        ))
    }
}

fn debug_transport_context() -> Result<TransportContext> {
    let (tcp, quic) = debug_transport_settings();
    Ok(TransportContext::new(
        Arc::new(SystemDnsResolver),
        TlsContext::for_debug()?,
        tcp,
        quic,
    ))
}

fn debug_transport_settings() -> (TcpTransportSettings, QuicTransportSettings) {
    (
        TcpTransportSettings::default(),
        QuicTransportSettings::default(),
    )
}

fn debug_tls_materials() -> Result<(
    Vec<CertificateDer<'static>>,
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
)> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let cert = generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
        .map_err(|err| TransportError::Tls(err.to_string()))?;
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    Ok((vec![cert_der.clone()], vec![cert_der], key_der))
}

fn build_client_config(
    certs: impl IntoIterator<Item = CertificateDer<'static>>,
    client_identity: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    include_system_roots: bool,
) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots
            .add(cert)
            .map_err(|err| TransportError::Tls(err.to_string()))?;
    }
    // bundle Mozilla's CA roots
    // when the operator opts in via config. Was originally gated on
    // the `tls-webpki-roots` feature, but `webpki-roots` is now always
    // а direct dependency of `veil-transport` (the HTTPS-bootstrap
    // and signed-update fetch paths require Web PKI verification
    // regardless of feature flags). Keeping the cfg-gate was а silent
    // config footgun — operators setting `use_system_roots = true`
    // got nothing without the build flag and only а warn log. Now
    // the config knob unconditionally controls behaviour; the
    // `tls-webpki-roots` feature is а semver-stable no-op kept for
    // existing build configs (scheduled for removal in а semver-major).
    if include_system_roots {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let client_config = match client_identity {
        Some((certs, key)) => builder
            .with_client_auth_cert(certs, key)
            .map_err(|err| TransportError::Tls(err.to_string()))?,
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(client_config))
}

fn build_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>> {
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| TransportError::Tls(err.to_string()))?;
    Ok(Arc::new(server_config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    // `from_config_*` tests moved to veilcore tests
    // (`veilcore/tests/transport_glue.rs`) because they cover the
    // cfg → transport bridge that now lives in veilcore::cfg::transport_glue.

    #[test]
    fn tls_context_keeps_custom_ca_when_server_identity_changes() {
        let tls = TlsContext::for_debug().expect("debug tls context");
        let ca_cert = generate_simple_self_signed(vec!["ca.example".to_owned()])
            .expect("ca cert")
            .cert
            .der()
            .clone();
        let (server_chain, server_key) = signed_server_identity().expect("server identity");

        let updated = tls
            .with_trusted_certificates(vec![ca_cert.clone()])
            .expect("add custom ca")
            .with_server_identity(server_chain.clone(), server_key)
            .expect("replace server identity");

        assert!(updated.trusted_certificates.contains(&ca_cert));
        assert_eq!(updated.server_cert_chain, server_chain);
    }

    #[test]
    fn tls_context_custom_ca_and_server_identity_can_coexist() {
        let tls = TlsContext::for_debug().expect("debug tls context");
        let ca_cert = generate_simple_self_signed(vec!["ca.example".to_owned()])
            .expect("ca cert")
            .cert
            .der()
            .clone();
        let (server_chain, server_key) = signed_server_identity().expect("server identity");

        let updated = tls
            .with_trusted_certificates(vec![ca_cert.clone()])
            .expect("add custom ca")
            .with_server_identity(server_chain.clone(), server_key)
            .expect("replace server identity");

        assert!(updated.trusted_certificates.contains(&ca_cert));
        assert_eq!(updated.server_cert_chain, server_chain);
        assert_eq!(updated.cert_der, updated.server_cert_chain[0]);
    }

    fn signed_server_identity() -> std::result::Result<
        (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>),
        Box<dyn std::error::Error>,
    > {
        let mut ca_params = CertificateParams::new(vec!["veil-test-ca".to_owned()])?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "veil-test-ca");
        let ca_key = KeyPair::generate()?;
        let issuer = ca_params.self_signed(&ca_key)?;

        let mut server_params = CertificateParams::new(vec!["localhost".to_owned()])?;
        server_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        let server_key = KeyPair::generate()?;
        let server_cert = server_params.signed_by(&server_key, &issuer, &ca_key)?;

        Ok((
            vec![server_cert.der().clone(), issuer.der().clone()],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        ))
    }

    // ── webpki-roots opt-in ─────────────────────────────────

    #[test]
    fn tls_context_system_roots_flag_preserved_across_builder_calls() {
        let tls = TlsContext::for_debug().expect("debug ctx");
        // Default: off
        let (chain, key) = signed_server_identity().expect("server identity");
        let step1 = tls.with_system_roots(true).expect("enable roots");
        assert!(
            step1.use_system_roots,
            "root flag sticks after explicit enable"
        );
        // Subsequent builder calls preserve the flag.
        let step2 = step1
            .with_server_identity(chain, key)
            .expect("server identity");
        assert!(
            step2.use_system_roots,
            "builder call must preserve the flag"
        );
    }

    // ── effective_sni precedence ─────────────────────────────

    fn ctx_with_default_sni(sni: Option<&str>) -> TransportContext {
        let mut ctx = TransportContext::for_debug().expect("debug ctx");
        ctx.default_sni = sni.map(str::to_owned);
        ctx
    }

    #[test]
    fn effective_sni_uri_wins() {
        let ctx = ctx_with_default_sni(Some("www.google.com"));
        assert_eq!(
            ctx.effective_sni(Some("node.example.com"), "203.0.113.5"),
            "node.example.com"
        );
    }

    #[test]
    fn effective_sni_uses_default_for_non_localhost() {
        let ctx = ctx_with_default_sni(Some("www.google.com"));
        assert_eq!(ctx.effective_sni(None, "203.0.113.5"), "www.google.com");
    }

    #[test]
    fn effective_sni_skips_default_for_localhost() {
        // Loopback never leaves the box; no DPI to masquerade against.
        let ctx = ctx_with_default_sni(Some("www.google.com"));
        assert_eq!(ctx.effective_sni(None, "127.0.0.1"), "127.0.0.1");
        assert_eq!(ctx.effective_sni(None, "localhost"), "localhost");
        assert_eq!(ctx.effective_sni(None, "::1"), "::1");
    }

    #[test]
    fn effective_sni_falls_back_to_host_when_default_unset() {
        let ctx = ctx_with_default_sni(None);
        assert_eq!(ctx.effective_sni(None, "203.0.113.5"), "203.0.113.5");
    }
}
