mod access;
pub mod adaptive;
mod error;
mod file_format;
mod format;
pub mod identity;
pub mod identity_master;
pub mod identity_master_file;
pub mod identity_master_qr;
// Pre-Phase-1 of `veilcore` extraction: identity_ops + identity_policy
// moved here from `crate::` root to break the cfg ↔ identity_ops cycle.
// `crate::lib.rs` re-exports both for backwards compat.
pub mod identity_ops;
pub mod identity_policy;
pub mod instance;
mod keys;
mod locate;
mod model;
pub mod observability_glue;
pub mod runtime;
pub mod signed_config;
pub mod sovereign_flow;
mod store;
#[cfg(test)]
mod test_support;
pub mod transport_glue;
mod validate;
mod value;

pub use access::{get, set};
pub use error::{ConfigError, Result};
pub use file_format::FileFormat;
pub use identity::{DomainIdentity, require_identity};
pub use keys::ConfigKey;
pub use locate::{default_admin_socket_uri, default_init_path, locate_config, runtime_veil_dir};
pub use model::{
    AnonymityConfig, AnycastConfig, AnycastResolvePolicyKind, BootstrapPeer, Config,
    ConnectionConfig, DhtConfig, DiscoveryMode, EphemeralConfig, ExitProxyConfig, FriendList,
    GatewayConfig, GlobalConfig, HotStandbyConfig, IdentityConfig, IpcConfig, ListenConfig,
    ListenId, LogFormat, LogLevel, LogsConfig, MEMBERSHIP_CERT_VERSION, MailboxConfig,
    MailboxPushConfig, MembershipCert, MeshConfig, MetricsConfig, MobileConfig, NatConfig,
    NetworkConfig, NetworkMode, NodeCapacityConfig, NodeId, NodeRole, OnDemandListenConfig,
    PaddingMode, PaddingPolicy, PeerConfig, PeerId, PexConfig, PinnedRelay, PowConfig,
    PriorityWeights, ProxyConfig, RoutingConfig, RuntimeFlavor, SessionConfig, SignatureAlgorithm,
    Socks5Config, TlsClientConfig, TlsFingerprintConfig, TransportConfig, TransportRotationConfig,
    UpdateConfig, Visibility, default_nonce_base64,
};
pub use runtime::{RuntimeConfig, build_tokio_runtime};
pub use store::{
    build_stub_config_with_ephemeral_identity, config_write_guard, init_config, load_config,
    load_config_str, parse_toml_str, prepare_init_path, read_raw_config, save_config,
};
pub use validate::{
    ValidationIssue, ValidationReport, validate, validate_and_fix, validate_and_fix_with_policy,
    validate_with_policy,
};
pub(crate) use value::{
    option_to_string, parse_optional_string, parse_optional_u16, parse_optional_u64,
    parse_optional_usize,
};
