use super::{ConfigError, Result};

/// Enumerates every config key that the `node config get`/`set` commands
/// can reach. Variants map one-to-one to dotted key paths (e.g.
/// `Self::IdentityAlgo` ↔ `"identity.algo"`). Use [`Self::parse`] to
/// convert from the dotted form and [`Self::as_str`] to go back.
#[allow(missing_docs)] // Variants are a direct mirror of the dotted key names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigKey {
    GlobalRuntimeFlavor,
    GlobalWorkerThreads,
    GlobalMaxBlockingThreads,
    GlobalThreadKeepAliveMs,
    GlobalThreadName,
    GlobalThreadStackSize,
    GlobalAdminSocket,
    GlobalLogs,
    GlobalLogFile,
    IpcEnabled,
    IpcSocketUri,
    IpcAppSocketDir,
    IdentityAlgo,
    IdentityRole,
    IdentityPublicKey,
    IdentityPrivateKey,
    IdentityNonce,
    IdentityNodeId,
    NatEnabled,
    NatPunchTimeoutMs,
    NatRelayEnabled,
    NatUdpReflectors,
    NatUdpReflectorBind,
    TransportTlsClientConnectTimeoutMs,
}

impl ConfigKey {
    /// Parse a dotted key string (e.g. `"global.worker_threads"`) into the
    /// matching `ConfigKey` variant.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "global.runtime_flavor" => Ok(Self::GlobalRuntimeFlavor),
            "global.worker_threads" => Ok(Self::GlobalWorkerThreads),
            "global.max_blocking_threads" => Ok(Self::GlobalMaxBlockingThreads),
            "global.thread_keep_alive_ms" => Ok(Self::GlobalThreadKeepAliveMs),
            "global.thread_name" => Ok(Self::GlobalThreadName),
            "global.thread_stack_size" => Ok(Self::GlobalThreadStackSize),
            "global.admin_socket" => Ok(Self::GlobalAdminSocket),
            "global.logs" => Ok(Self::GlobalLogs),
            "global.log_file" => Ok(Self::GlobalLogFile),
            "ipc.enabled" => Ok(Self::IpcEnabled),
            "ipc.socket_uri" => Ok(Self::IpcSocketUri),
            "ipc.app_socket_dir" => Ok(Self::IpcAppSocketDir),
            "identity.algo" => Ok(Self::IdentityAlgo),
            "identity.role" => Ok(Self::IdentityRole),
            "identity.public_key" => Ok(Self::IdentityPublicKey),
            "identity.private_key" => Ok(Self::IdentityPrivateKey),
            "identity.nonce" => Ok(Self::IdentityNonce),
            "identity.node_id" => Ok(Self::IdentityNodeId),
            "nat.enabled" => Ok(Self::NatEnabled),
            "nat.punch_timeout_ms" => Ok(Self::NatPunchTimeoutMs),
            "nat.relay_enabled" => Ok(Self::NatRelayEnabled),
            "nat.udp_reflectors" => Ok(Self::NatUdpReflectors),
            "nat.udp_reflector_bind" => Ok(Self::NatUdpReflectorBind),
            "transport.tls_client.connect_timeout_ms" => {
                Ok(Self::TransportTlsClientConnectTimeoutMs)
            }
            _ => Err(ConfigError::UnknownKey(value.to_owned())),
        }
    }

    /// Return the dotted key string corresponding to this variant.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GlobalRuntimeFlavor => "global.runtime_flavor",
            Self::GlobalWorkerThreads => "global.worker_threads",
            Self::GlobalMaxBlockingThreads => "global.max_blocking_threads",
            Self::GlobalThreadKeepAliveMs => "global.thread_keep_alive_ms",
            Self::GlobalThreadName => "global.thread_name",
            Self::GlobalThreadStackSize => "global.thread_stack_size",
            Self::GlobalAdminSocket => "global.admin_socket",
            Self::GlobalLogs => "global.logs",
            Self::GlobalLogFile => "global.log_file",
            Self::IpcEnabled => "ipc.enabled",
            Self::IpcSocketUri => "ipc.socket_uri",
            Self::IpcAppSocketDir => "ipc.app_socket_dir",
            Self::IdentityAlgo => "identity.algo",
            Self::IdentityRole => "identity.role",
            Self::IdentityPublicKey => "identity.public_key",
            Self::IdentityPrivateKey => "identity.private_key",
            Self::IdentityNonce => "identity.nonce",
            Self::IdentityNodeId => "identity.node_id",
            Self::NatEnabled => "nat.enabled",
            Self::NatPunchTimeoutMs => "nat.punch_timeout_ms",
            Self::NatRelayEnabled => "nat.relay_enabled",
            Self::NatUdpReflectors => "nat.udp_reflectors",
            Self::NatUdpReflectorBind => "nat.udp_reflector_bind",
            Self::TransportTlsClientConnectTimeoutMs => "transport.tls_client.connect_timeout_ms",
        }
    }
}
