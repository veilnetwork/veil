//! Ogate configuration file (TOML).
//!
//! Example:
//!
//! ```toml
//! network        = "homenet"
//! app            = "ogate"
//! mode           = "authorized"
//! socket_path    = "/run/veil/app.sock"
//! iface_name     = "ogate0"
//! mtu            = 1280
//! local_addr_v4  = "10.99.0.1"
//! prefix_v4      = 24
//! local_addr_v6  = "fd00:ogate:1::1"
//! prefix_v6      = 64
//!
//! [[peers]]
//! node_id = "deadbeef..."
//! addr_v4 = "10.99.0.2"
//! addr_v6 = "fd00:ogate:1::2"
//!
//! [[peers]]
//! node_id = "cafef00d..."
//! addr_v4 = "10.99.0.3"
//! ```

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use veil_cfg::RuntimeConfig;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OgateConfig {
    /// Network name. Two peers must share this exactly to communicate.
    /// Combined with `app` into the IPC bind namespace.
    pub network: String,

    /// Application name within the network (e.g. "ogate", "voip").
    /// Multiple apps may coexist on a single network with different IPs.
    #[serde(default = "default_app_name")]
    pub app: String,

    /// Access mode: `open` or `authorized`.
    #[serde(default)]
    pub mode: AccessMode,

    /// **P-Net admission gate**.  When `true`, ogate queries the daemon's
    /// verified-cert cache (см. [`veil_identity::network_access`])
    /// at startup и on SIGHUP, и filters out any `[[peers]]` entry whose
    /// peer hasn't presented а valid `MembershipCert`.  Combine с
    /// `mode = "authorized"` для defence-in-depth: peer must BOTH
    /// have а verified cert AND be в the configured `[[peers]]` list.
    ///
    /// Default `false` — backward-compatible с pre-P-Net deployments
    /// where the operator gates statically.
    #[serde(default)]
    pub pnet_required: bool,

    /// S2.B **app-layer cert authority** (server side).  Independent от
    /// daemon's P-Net.  When all three fields are set, ogate's ingress
    /// path drops packets от peers что haven't presented а valid
    /// `MembershipCert` signed by `app_cert_trusted_owner_pubkey`.
    /// The cert exchange happens via the cert message protocol (см.
    /// [`crate::cert_message`]) и а per-peer verified cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_cert_trusted_owner_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_cert_owner_algo: Option<veil_types::SignatureAlgorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_cert_network_id: Option<String>,
    /// S2.B (sender side): path к а signed `MembershipCert` blob.
    /// When set, ogate emits а cert message к each configured peer at
    /// startup и periodically thereafter; the peer caches the verified
    /// node_id и admits subsequent IP packets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_cert_path: Option<PathBuf>,

    /// Path to the veil daemon IPC socket.
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,

    /// Name of the TUN interface to create (OS-dependent; may be auto-assigned).
    #[serde(default = "default_iface_name")]
    pub iface_name: String,

    /// MTU for the TUN device. Default 1280 keeps room for veil headers.
    #[serde(default = "default_mtu")]
    pub mtu: u16,

    /// Local IPv4 address inside the virtual subnet.
    pub local_addr_v4: Option<Ipv4Addr>,
    /// CIDR prefix for the IPv4 subnet (default 24).
    #[serde(default = "default_prefix_v4")]
    pub prefix_v4: u8,

    /// Local IPv6 address inside the virtual prefix.
    pub local_addr_v6: Option<Ipv6Addr>,
    /// CIDR prefix for the IPv6 subnet (default 64).
    #[serde(default = "default_prefix_v6")]
    pub prefix_v6: u8,

    /// Per-peer virtual-IP table.
    #[serde(default)]
    pub peers: Vec<PeerEntry>,

    /// Endpoint id for the IPC binding (must match across all peers).
    #[serde(default = "default_endpoint_id")]
    pub endpoint_id: u32,

    /// Tokio-runtime knobs (shared schema с veil-cli). Optional —
    /// defaults work for typical deployments.  Env vars `OGATE_RUNTIME`,
    /// `OGATE_WORKERS`, `OGATE_MAX_BLOCKING_THREADS` STILL override these
    /// values после loading the file (backward-compat с existing systemd
    /// units that pass env-only tuning).
    #[serde(default)]
    pub runtime: RuntimeConfig,

    /// Egress batching config (Phase E27).  Audit batch 2026-05-24 (M13):
    /// previously batching was а compile-time const (`BATCHING_ENABLED =
    /// true`); during rolling upgrade а legacy receiver silently drops the
    /// 0xB1-prefixed batch envelope as "не IPv4 / IPv6", causing а
    /// blackhole без operator signal.  This section lets the operator
    /// flip batching off during mixed-version rollouts.
    #[serde(default)]
    pub batch: BatchConfig,

    /// Logging output knobs.  Optional — если omitted, ogate honours
    /// `RUST_LOG` env var с default `info`.
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Logging configuration for the `ogate` binary.  Translates к
/// `tracing-subscriber` filter + format + writer.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Minimum level emitted: `off` | `error` | `warn` | `info` |
    /// `debug` | `trace`.  Default `info`.  Set `off` к suppress all
    /// log output.  Overridden by `RUST_LOG` env var when set.
    #[serde(default)]
    pub level: LogLevel,

    /// Output format: `text` (default, human-readable) or `json`
    /// (machine-parseable structured logs).
    #[serde(default)]
    pub format: LogFormat,

    /// Optional path to а log file.  `None` (default) ⇒ logs go к
    /// stderr.  When set, logs are appended к the file (created if
    /// absent).  Parent directory must exist.  Useful для systemd
    /// units that pipe stderr к journald но want а separate
    /// JSON-formatted log file для shipping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
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
    pub fn as_filter_str(&self) -> &'static str {
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

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// Egress packet-batching config (audit batch 2026-05-24, M13).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchConfig {
    /// Whether к coalesce small egress IP packets into 0xB1-prefixed
    /// batch envelopes (Phase E27).  Legacy ogate peers (pre-E27) do
    /// NOT understand this format и silently drop batch envelopes —
    /// during rolling upgrades this manifests as а blackhole.
    ///
    /// **Recommended:**
    /// * Set `false` when starting а rolling upgrade until ALL peers run
    ///   an E27-or-newer build.
    /// * Set `true` (or omit) after the upgrade completes.
    ///
    /// Default: `true` (preserves shipped behaviour для homogeneous
    /// deployments).
    #[serde(default = "BatchConfig::default_enabled")]
    pub enabled: bool,
}

impl BatchConfig {
    fn default_enabled() -> bool {
        true
    }
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
        }
    }
}

/// One peer in the network: which `node_id` maps to which virtual IP.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PeerEntry {
    /// 64-char hex of the peer's veil `node_id` (= BLAKE3 of pubkey).
    pub node_id: String,
    /// Peer's virtual IPv4 address in the subnet.
    pub addr_v4: Option<Ipv4Addr>,
    /// Peer's virtual IPv6 address in the prefix.
    pub addr_v6: Option<Ipv6Addr>,
    /// Optional human label (logging only).
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AccessMode {
    /// Any peer that knows the (network, app) pair can talk in.
    /// **Use only for testing / open networks**: any peer in the network
    /// namespace can inject TUN traffic. Use [`Self::Authorized`] для
    /// production deployments.
    Open,
    /// Only peers listed in `peers[].node_id` are accepted on ingress AND
    /// allowed as egress destinations. Unauthorized sources are dropped at
    /// the app layer; egress to a non-listed peer is dropped before
    /// hitting the veil.
    ///
    /// **Default** post-audit: fail-closed. Operators that explicitly want
    /// the namespace-only gate must opt in via `mode = "open"`.
    #[default]
    Authorized,
}

impl OgateConfig {
    /// Read a config from a TOML file.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path_ref = path.as_ref();
        // Audit batch 2026-05-24 (M6): warn если config file is world/
        // group-readable.  Config may carry sensitive metadata (peer
        // node_ids, socket paths) и must not be tamper-able by
        // unprivileged users.  Logged at startup, not fatal — operators
        // may have valid reasons (e.g. read-only mount under а group).
        warn_loose_config_perms(path_ref);
        let bytes = std::fs::read_to_string(&path).map_err(|e| ConfigError::Io {
            path: path_ref.display().to_string(),
            source: e,
        })?;
        let cfg: Self = toml::from_str(&bytes).map_err(ConfigError::Parse)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Sanity-check semantic invariants after deserialization.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.network.is_empty() {
            return Err(ConfigError::Field("`network` must not be empty"));
        }
        if self.app.is_empty() {
            return Err(ConfigError::Field("`app` must not be empty"));
        }
        if self.local_addr_v4.is_none() {
            // `tun::standard::Device::new` requires `local_addr_v4` для
            // initial interface configuration (Linux TUNSETIFF, macOS utun,
            // Windows WinTun all need an IPv4 address к bring the interface
            // up). IPv6-only config previously passed validate but failed
            // at runtime с а cryptic "local_addr_v4 missing" error.
            // Fail-fast here с а clear message instead.
            return Err(ConfigError::Field(
                "`local_addr_v4` is required (IPv6-only configurations not yet supported by the TUN backend)",
            ));
        }
        if self.prefix_v4 > 32 {
            return Err(ConfigError::Field("`prefix_v4` must be in 0..=32"));
        }
        if self.prefix_v6 > 128 {
            return Err(ConfigError::Field("`prefix_v6` must be in 0..=128"));
        }
        for (i, peer) in self.peers.iter().enumerate() {
            if peer.node_id.len() != 64 {
                return Err(ConfigError::Peer {
                    index: i,
                    msg: "node_id must be exactly 64 hex chars",
                });
            }
            if hex::decode(&peer.node_id).is_err() {
                return Err(ConfigError::Peer {
                    index: i,
                    msg: "node_id is not valid hex",
                });
            }
            if peer.addr_v4.is_none() && peer.addr_v6.is_none() {
                return Err(ConfigError::Peer {
                    index: i,
                    msg: "peer needs at least one of addr_v4 / addr_v6",
                });
            }
        }
        Ok(())
    }
}

fn default_app_name() -> String {
    "ogate".to_owned()
}
fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/veil/app.sock")
}
fn default_iface_name() -> String {
    "ogate0".to_owned()
}
/// TUN MTU.  Default 16000 (= bufpool's 16 KiB bucket size — the largest
/// safe value before delivery ломается на bigger frames).  Phase E24
/// (2026-05-22) measured MTU-sweep через ogate-tunnel:
///
/// ```text
/// MTU=1500   → 166 Mbps single TCP stream
/// MTU=3000   → 296 Mbps
/// MTU=9000   → 612 Mbps
/// MTU=16000  → 786 Mbps  (sweet spot — 79 % of direct 1.07 Gbps)
/// MTU=32000+ → delivery stalls (frame fragmentation OR bufpool overflow)
/// ```
///
/// Per-packet overhead в the veil pipeline (TUN read → AppSender::send
/// → IPC frame → daemon dispatch → AEAD frame → TCP write) dominates
/// throughput; fewer larger packets = far less aggregate overhead.
/// Operators on links с MTU restrictions (PPPoE 1492, VPN nested) can
/// override через `[ogate] mtu = 1500` в config.
fn default_mtu() -> u16 {
    16000
}
fn default_prefix_v4() -> u8 {
    24
}
fn default_prefix_v6() -> u8 {
    64
}
fn default_endpoint_id() -> u32 {
    1
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("parse: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("config field: {0}")]
    Field(&'static str),
    #[error("peer[{index}]: {msg}")]
    Peer { index: usize, msg: &'static str },
}

/// Emit а warning если the config file is readable / writable by group
/// или other.  Non-fatal.  Audit batch 2026-05-24 (M6).
#[cfg(unix)]
fn warn_loose_config_perms(path: &Path) {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return; // нет файла → каллер получит понятную ошибку при read
    };
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        // Use eprintln! (не tracing) because logger may не быть init'нут
        // в момент config-load.
        eprintln!(
            "ogate: config file {} mode 0{mode:o} permits group/other access. \
             Recommended: chmod 600 (config may contain peer node_ids).",
            path.display()
        );
    }
}

#[cfg(not(unix))]
fn warn_loose_config_perms(_path: &Path) {
    // Windows ACL check is out of scope для this audit batch.
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal config parses и applies fail-closed default (`Authorized`).
    /// Audit batch 2026-05-24 (L8): name pre-dates the default flip;
    /// previously expected `Open`.  Authorized is the safer default.
    #[test]
    fn minimal_config_uses_authorized_default() {
        let toml = r#"
            network       = "homenet"
            local_addr_v4 = "10.99.0.1"
        "#;
        let cfg: OgateConfig = toml::from_str(toml).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.app, "ogate");
        assert_eq!(cfg.mode, AccessMode::Authorized);
        assert_eq!(cfg.endpoint_id, 1);
        assert_eq!(cfg.mtu, 16000);
        assert!(cfg.peers.is_empty());
        // Audit batch 2026-05-24 (M13): batching defaults к enabled.
        assert!(cfg.batch.enabled);
    }

    #[test]
    fn batch_kill_switch_parses() {
        let toml = r#"
            network       = "homenet"
            local_addr_v4 = "10.99.0.1"

            [batch]
            enabled = false
        "#;
        let cfg: OgateConfig = toml::from_str(toml).unwrap();
        assert!(!cfg.batch.enabled);
    }

    #[test]
    fn authorized_with_peers() {
        let toml = r#"
            network       = "homenet"
            mode          = "authorized"
            local_addr_v4 = "10.99.0.1"
            prefix_v4     = 16

            [[peers]]
            node_id = "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44"
            addr_v4 = "10.99.0.2"
            name    = "peer-b"
        "#;
        let cfg: OgateConfig = toml::from_str(toml).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.mode, AccessMode::Authorized);
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].name.as_deref(), Some("peer-b"));
    }

    #[test]
    fn missing_local_addr_fails() {
        let toml = r#"network = "homenet""#;
        let cfg: OgateConfig = toml::from_str(toml).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Field(_)));
    }

    #[test]
    fn invalid_hex_node_id_fails() {
        let toml = r#"
            network       = "homenet"
            local_addr_v4 = "10.99.0.1"
            [[peers]]
            node_id = "ZZ11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44"
            addr_v4 = "10.99.0.2"
        "#;
        let cfg: OgateConfig = toml::from_str(toml).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, ConfigError::Peer { .. }));
    }
}
