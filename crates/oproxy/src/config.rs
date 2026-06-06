//! TOML config schema for both client and server binaries.
//!
//! # Server example
//!
//! ```toml
//! socket_path = "/var/lib/veil/app.sock"
//! app_name    = "my-proxy"
//! # Empty / omitted = allow ALL callers.  Non-empty = strict allowlist.
//! allowed_node_ids = [
//!   "0011223344...64chars",
//!   "ffeedd...64chars",
//! ]
//! # Allow proxying to RFC1918 destinations.  Default: false (block).
//! allow_private = false
//! ```
//!
//! # Client example
//!
//! ```toml
//! socket_path  = "/var/lib/veil/app.sock"
//! # Server's node_id (hex) + app_name (must match server's app_name).
//! server_node_id = "0011223344...64chars"
//! server_app_name = "my-proxy"
//!
//! [[inbound]]
//! kind = "socks5"
//! listen = "127.0.0.1:1080"
//!
//! [[inbound]]
//! kind = "http"
//! listen = "127.0.0.1:8080"
//!
//! [[inbound]]
//! kind = "tproxy"
//! listen = "0.0.0.0:12345"   # Linux / Keenetic only (FreeBSD stubbed)
//! ```

use std::path::{Path, PathBuf};

use serde::Deserialize;
use veil_cfg::RuntimeConfig;

/// Emit a warning if the config file is readable / writable by group
/// or other.  Non-fatal.  Audit batch 2026-05-24 (M6).
#[cfg(unix)]
pub fn warn_loose_config_perms(path: &Path) {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        eprintln!(
            "oproxy: config file {} mode 0{mode:o} permits group/other access. \
             Recommended: chmod 600 (config may contain allowed_node_ids).",
            path.display()
        );
    }
}

#[cfg(not(unix))]
pub fn warn_loose_config_perms(_path: &Path) {}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Path to the local veil daemon's app socket (Unix) or named-
    /// pipe (Windows).  Default matches daemon's default.
    pub socket_path: PathBuf,
    /// App name used to derive app_id via
    /// `veil_app::address::app_id(local_node_id, "oproxy", &name)`.
    /// **Client must use the same name** to derive the matching app_id.
    pub app_name: String,
    /// Empty list ⇒ allow all callers (open proxy).  Non-empty ⇒ strict
    /// allowlist by source node_id (hex).
    #[serde(default)]
    pub allowed_node_ids: Vec<String>,
    /// Permit outbound TCP to RFC1918 / loopback / metadata addresses.
    /// Default `false` — recommended.
    #[serde(default)]
    pub allow_private: bool,

    /// Explicit acknowledgement that this server runs as an **open proxy**
    /// (no `allowed_node_ids`).  Audit batch 2026-05-24 (M11): without
    /// this flag, `allowed_node_ids = []` is rejected at startup —
    /// silent open-proxy was a footgun where operators thought "empty =
    /// nothing" but actually meant "all veil peers".
    #[serde(default)]
    pub allow_all: bool,

    /// **P-Net admission mode**.  When `true`, every incoming veil
    /// stream's source `node_id` is checked against the daemon's
    /// verified-cert cache (see `crates/veil-identity/src/network_cert.rs`)
    /// via the `LocalAppMsg::PnetStatusQuery` IPC opcode.  Streams from
    /// peers without a valid MembershipCert are dropped with `Denied`.
    ///
    /// `allowed_node_ids` remains a secondary gate when `pnet_required`
    /// is also set: peer must BOTH have a verified cert AND appear in
    /// the static list.  An empty `allowed_node_ids` + `pnet_required =
    /// true` means "trust whoever the daemon's P-Net gate admitted".
    ///
    /// Default `false` — backward-compatible with pre-P-Net deployments
    /// where admission is configured statically.
    #[serde(default)]
    pub pnet_required: bool,

    /// S2.B **app-layer cert authority**.  When all three fields are
    /// set, oproxy-server requires every incoming stream to present a
    /// signed `MembershipCert` preamble.  The cert is verified locally
    /// against `app_cert_trusted_owner_pubkey` + `app_cert_network_id`
    /// (this is the app-layer's OWN trusted authority — may differ
    /// from daemon's P-Net authority).  When unset, this gate is skipped
    /// (oproxy falls back on the existing static / pnet_required path).
    ///
    /// Use case: daemon in public mode, but oproxy specifically wants to
    /// admit only peers signed by a particular owner key.  Avoids
    /// privatising the entire daemon when per-app trust granularity
    /// is sufficient.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_cert_trusted_owner_pubkey: Option<String>,
    /// Owner signature algorithm.  Required when
    /// `app_cert_trusted_owner_pubkey` set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_cert_owner_algo: Option<veil_types::SignatureAlgorithm>,
    /// Network id (64-char hex) that incoming certs must match.
    /// Required when `app_cert_trusted_owner_pubkey` set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_cert_network_id: Option<String>,

    /// Connection-count limits (audit batch 2026-05-24, finding M8).
    /// Caps how many concurrent veil streams the server bridges.
    #[serde(default)]
    pub limits: ServerLimits,

    /// Tokio-runtime knobs (shared schema with veil-cli).  Env vars
    /// `OPROXY_RUNTIME`, `OPROXY_WORKERS`, `OPROXY_MAX_BLOCKING_THREADS`
    /// override these post-load.
    #[serde(default)]
    pub runtime: RuntimeConfig,

    /// Logging output knobs.  Env-driven `RUST_LOG` overrides config.
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Connection-count limits for `oproxy-client` (audit batch 2026-05-24,
/// finding M8).
///
/// `oproxy-client` spawns one tokio task per inbound connection.  Without
/// a cap, an `accept()` flood (DoS pivot from a compromised loopback
/// client) exhausts tasks and memory.  The semaphore-backed limit means
/// the `accept()` loop blocks (TCP backpressure to the client) when
/// already at capacity.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientLimits {
    /// Max concurrent SOCKS5 / HTTP / TProxy sessions PER LISTENER.
    /// Default 1024 — generous for legitimate workloads, fatal only
    /// for adversaries that want to exhaust the daemon.
    #[serde(default = "default_max_concurrent_per_listener")]
    pub max_concurrent_per_listener: usize,
}

impl Default for ClientLimits {
    fn default() -> Self {
        Self {
            max_concurrent_per_listener: default_max_concurrent_per_listener(),
        }
    }
}

fn default_max_concurrent_per_listener() -> usize {
    1024
}

/// Connection-count limits for `oproxy-server`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerLimits {
    /// Max concurrent inbound veil streams the server bridges.
    /// Default 1024.  When at capacity, `accept_stream()` blocks; the
    /// daemon backpressures upstream peers via the standard stream-window
    /// mechanism.
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_concurrent_streams: default_max_concurrent_streams(),
        }
    }
}

fn default_max_concurrent_streams() -> usize {
    1024
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum InboundConfig {
    /// SOCKS5 ingress (RFC 1928).
    Socks5 {
        /// `host:port` for the local listener.  Use `127.0.0.1:<port>`
        /// for loopback-only access.
        listen: String,
    },
    /// HTTP/1.1 forward proxy (CONNECT + absolute-URI rewriting).
    Http { listen: String },
    /// Transparent proxy via Linux `IP_TRANSPARENT` / `SO_ORIGINAL_DST`
    /// (Xray's "dokodemo-door" pattern).  Requires CAP_NET_ADMIN +
    /// matching iptables / nftables rules.
    ///
    /// Linux / Keenetic only (Keenetic uses standard Linux kernel).
    /// FreeBSD support was stubbed in audit batch 2026-05-23 — fail-fast
    /// at startup until pf+divert or ipfw fwd integration lands.
    /// macOS / Windows: use SOCKS5 or HTTP inbound instead.
    Tproxy { listen: String },
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub socket_path: PathBuf,
    /// 64-char hex of the upstream server's veil node_id.
    pub server_node_id: String,
    /// Same name the server published.  Both sides derive the same
    /// app_id via the canonical helper.
    pub server_app_name: String,
    /// One or more inbound listeners.  All run concurrently.
    #[serde(default)]
    pub inbound: Vec<InboundConfig>,

    /// Connection-count limits (audit batch 2026-05-24, finding M8).
    /// Caps max concurrent SOCKS5/HTTP/TProxy sessions so that `accept()`
    /// floods cannot exhaust tasks / memory.
    #[serde(default)]
    pub limits: ClientLimits,

    /// Per-target routing policy: which connects go through veil,
    /// which bypass directly, and what to do if veil is down.
    /// Omit for backward-compat (= veil-only, fail-closed).
    #[serde(default)]
    pub routing: RoutingConfig,

    /// S2.B: path to a signed `MembershipCert` blob (output of
    /// `veil-cli network sign-member`).  When set, the client
    /// prepends an app-cert preamble (see wire.rs) to every outbound
    /// stream open; the server verifies it against its own configured
    /// trusted owner pubkey before accepting the connection.  Omit
    /// when the server's `app_cert_trusted_owner_pubkey` is unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_cert_path: Option<PathBuf>,

    /// Tokio-runtime knobs (shared schema with veil-cli).  Env vars
    /// `OPROXY_RUNTIME`, `OPROXY_WORKERS`, `OPROXY_MAX_BLOCKING_THREADS`
    /// override these post-load.
    #[serde(default)]
    pub runtime: RuntimeConfig,

    /// Logging output knobs.  Env-driven `RUST_LOG` overrides config.
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Logging configuration shared between client/server binaries.
/// Mapped to `env_logger::Builder` at startup.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Minimum level: `off` | `error` | `warn` | `info` | `debug` |
    /// `trace`.  Default `info`.  Set `off` to suppress all log
    /// output.  Overridden by `RUST_LOG` env var when set.
    #[serde(default)]
    pub level: LogLevel,

    /// Optional path to a log file.  `None` (default) ⇒ logs go to
    /// stderr.  When set, logs are appended to the file (created if
    /// absent).  Parent directory must exist.  Not affected by the
    /// `level = "off"` shortcut — if you set a file and want to stop
    /// writing to it, also set `level = "off"` (or remove the
    /// `file` field).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_filter_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

// ── Routing config ─────────────────────────────────────────────────────────

/// Routing policy for outbound traffic from the client's inbound
/// listeners.
///
/// Defaults to the historical "all through veil, fail if down"
/// behaviour for backward compat.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    /// Default action when no rule matches (or when `rules` is empty).
    #[serde(default)]
    pub default: ProxyMode,

    /// What to do if `default = "veil"` or a rule yielded `veil`
    /// but the veil path fails (server unreachable, timeout, etc.).
    #[serde(default)]
    pub fallback: FallbackMode,

    /// Optional per-target rule table evaluated in order.  First match
    /// wins.  If none match, `default` applies.
    #[serde(default)]
    pub rules: Vec<RoutingRule>,

    /// audit cycle-6 (A9): permit `Direct`/`Fallback::Direct` connects to
    /// private destinations (RFC1918 / loopback / link-local / cloud-metadata
    /// `169.254.169.254` / IPv6 ULA). Default `false` (block) — without it a
    /// local process with SOCKS5/HTTP access to this client could pivot to
    /// internal services via the direct path (SSRF). Mirrors the server-side
    /// `ServerConfig::allow_private`. Set `true` only for trusted LAN use.
    #[serde(default)]
    pub allow_private: bool,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProxyMode {
    /// Tunnel the connection through veil → server (current default
    /// behaviour for backward compat).
    #[default]
    Veil,
    /// Open a direct TCP socket from the client host (acts as a plain
    /// local SOCKS5/HTTP proxy with no veil involvement).
    Direct,
    /// Refuse the connection with a SOCKS5/HTTP error.
    Block,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FallbackMode {
    /// Return CONNECT failure to the inbound client (current behaviour).
    #[default]
    Fail,
    /// Silently switch to a direct TCP connect when veil fails.
    Direct,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingRule {
    /// Match: hostname suffix (case-insensitive).  E.g. `.internal`
    /// matches `db.internal`, `app.db.internal`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_suffix: Option<String>,
    /// Match: hostname exact (case-insensitive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_exact: Option<String>,
    /// Match: destination IPv4/IPv6 CIDR.  Only applies if dst is an
    /// IP literal (or resolves to one before action — current impl
    /// matches against the *literal* host string when it's already an
    /// IP, not resolves DNS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// Match: destination port range, e.g. `"1024-65535"`, or
    /// single port `"443"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_range: Option<String>,
    /// Action when match succeeds.
    pub action: ProxyMode,
    /// Per-rule fallback override.  Applies only when `action =
    /// "veil"` and the veil path fails (phases 1-3 of the connect
    /// handshake).  `None` (default) ⇒ inherit the parent
    /// `[routing] fallback`.  Use `"fail"` to force-no-fallback for a
    /// specific rule even if global fallback is `"direct"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<FallbackMode>,
}

/// Parse a 64-char hex node_id with optional `0x` prefix.
pub fn parse_node_id_hex(s: &str) -> Result<[u8; 32], String> {
    let trimmed = s.trim().trim_start_matches("0x");
    if trimmed.len() != 64 {
        return Err(format!(
            "node_id must be 64 hex chars, got {} chars",
            trimmed.len()
        ));
    }
    let mut id = [0u8; 32];
    for (i, chunk) in trimmed.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|e| format!("utf8: {e}"))?;
        id[i] = u8::from_str_radix(s, 16).map_err(|e| format!("parse: {e}"))?;
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_server_config_minimal() {
        let toml = r#"
            socket_path = "/tmp/app.sock"
            app_name = "my-proxy"
        "#;
        let cfg: ServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.app_name, "my-proxy");
        assert!(cfg.allowed_node_ids.is_empty());
        assert!(!cfg.allow_private);
    }

    #[test]
    fn parse_server_config_with_allowlist() {
        let toml = r#"
            socket_path = "/tmp/app.sock"
            app_name = "p"
            allowed_node_ids = ["0011223344556677889900112233445566778899001122334455667788990011"]
            allow_private = true
        "#;
        let cfg: ServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.allowed_node_ids.len(), 1);
        assert!(cfg.allow_private);
    }

    #[test]
    fn parse_server_config_with_limits() {
        let toml = r#"
            socket_path = "/tmp/app.sock"
            app_name = "p"

            [limits]
            max_concurrent_streams = 64
        "#;
        let cfg: ServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.limits.max_concurrent_streams, 64);
    }

    #[test]
    fn parse_server_config_limits_default() {
        let toml = r#"
            socket_path = "/tmp/app.sock"
            app_name = "p"
        "#;
        let cfg: ServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.limits.max_concurrent_streams, 1024);
    }

    #[test]
    fn parse_client_config_with_limits() {
        let toml = r#"
            socket_path = "/tmp/app.sock"
            server_node_id = "0011223344556677889900112233445566778899001122334455667788990011"
            server_app_name = "p"

            [limits]
            max_concurrent_per_listener = 32
        "#;
        let cfg: ClientConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.limits.max_concurrent_per_listener, 32);
    }

    #[test]
    fn parse_client_config_with_multiple_inbounds() {
        let toml = r#"
            socket_path = "/tmp/app.sock"
            server_node_id = "0011223344556677889900112233445566778899001122334455667788990011"
            server_app_name = "my-proxy"

            [[inbound]]
            kind = "socks5"
            listen = "127.0.0.1:1080"

            [[inbound]]
            kind = "http"
            listen = "127.0.0.1:8080"

            [[inbound]]
            kind = "tproxy"
            listen = "0.0.0.0:12345"
        "#;
        let cfg: ClientConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.inbound.len(), 3);
        assert!(matches!(cfg.inbound[0], InboundConfig::Socks5 { .. }));
        assert!(matches!(cfg.inbound[1], InboundConfig::Http { .. }));
        assert!(matches!(cfg.inbound[2], InboundConfig::Tproxy { .. }));
    }

    /// Per-rule fallback override is parsed correctly from TOML.  Covers
    /// the user-asked RFC1918 split scenario (10/8 with fallback to direct;
    /// 172.16/12 with fallback to fail; 192.168/16 always direct).
    #[test]
    fn parse_client_config_with_per_rule_fallback() {
        let toml = r#"
            socket_path = "/tmp/app.sock"
            server_node_id = "0011223344556677889900112233445566778899001122334455667788990011"
            server_app_name = "my-proxy"

            [routing]
            default  = "veil"
            fallback = "fail"

            [[routing.rules]]
            cidr     = "10.0.0.0/8"
            action   = "veil"
            fallback = "direct"

            [[routing.rules]]
            cidr     = "172.16.0.0/12"
            action   = "veil"
            fallback = "fail"

            [[routing.rules]]
            cidr   = "192.168.0.0/16"
            action = "direct"
        "#;
        let cfg: ClientConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.routing.default, ProxyMode::Veil);
        assert_eq!(cfg.routing.fallback, FallbackMode::Fail);
        assert_eq!(cfg.routing.rules.len(), 3);
        assert_eq!(cfg.routing.rules[0].action, ProxyMode::Veil);
        assert_eq!(cfg.routing.rules[0].fallback, Some(FallbackMode::Direct));
        assert_eq!(cfg.routing.rules[1].action, ProxyMode::Veil);
        assert_eq!(cfg.routing.rules[1].fallback, Some(FallbackMode::Fail));
        assert_eq!(cfg.routing.rules[2].action, ProxyMode::Direct);
        assert_eq!(cfg.routing.rules[2].fallback, None);
    }

    #[test]
    fn parse_node_id_round_trip() {
        let hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let id = parse_node_id_hex(hex).unwrap();
        assert_eq!(id[0], 0xab);
        assert_eq!(id[31], 0x89);
    }

    #[test]
    fn parse_node_id_accepts_0x_prefix() {
        let hex = "0x".to_string() + &"a".repeat(64);
        let id = parse_node_id_hex(&hex).unwrap();
        assert_eq!(id[0], 0xaa);
    }

    #[test]
    fn parse_node_id_rejects_short() {
        assert!(parse_node_id_hex("abc").is_err());
    }
}
