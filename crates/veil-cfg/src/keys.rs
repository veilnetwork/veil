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
    GlobalBootstrap,
    GlobalLocalDiscovery,
    GlobalMainlineDiscovery,
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
            "global.bootstrap" => Ok(Self::GlobalBootstrap),
            "global.local_discovery" => Ok(Self::GlobalLocalDiscovery),
            "global.mainline_discovery" => Ok(Self::GlobalMainlineDiscovery),
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
            Self::GlobalBootstrap => "global.bootstrap",
            Self::GlobalLocalDiscovery => "global.local_discovery",
            Self::GlobalMainlineDiscovery => "global.mainline_discovery",
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

#[cfg(test)]
mod every_key_is_reachable {
    use super::ConfigKey;

    /// How many keys there are. Bump it when you add one, and give the new
    /// variant the next ordinal below.
    const KEY_COUNT: usize = 27;

    /// A distinct number per variant.
    ///
    /// Exhaustive on purpose: a key added to the enum without a line here does
    /// not compile, which is how the author is made to read this comment and
    /// add it to the list in the test. An identity match would say the same
    /// thing to the compiler and nothing to clippy, which is right -- the
    /// dotted spelling already has an exhaustive match in `as_str`.
    fn ordinal(key: ConfigKey) -> usize {
        match key {
            ConfigKey::GlobalRuntimeFlavor => 0,
            ConfigKey::GlobalWorkerThreads => 1,
            ConfigKey::GlobalMaxBlockingThreads => 2,
            ConfigKey::GlobalThreadKeepAliveMs => 3,
            ConfigKey::GlobalThreadName => 4,
            ConfigKey::GlobalThreadStackSize => 5,
            ConfigKey::GlobalAdminSocket => 6,
            ConfigKey::GlobalLogs => 7,
            ConfigKey::GlobalLogFile => 8,
            ConfigKey::GlobalBootstrap => 9,
            ConfigKey::GlobalLocalDiscovery => 10,
            ConfigKey::GlobalMainlineDiscovery => 11,
            ConfigKey::IpcEnabled => 12,
            ConfigKey::IpcSocketUri => 13,
            ConfigKey::IpcAppSocketDir => 14,
            ConfigKey::IdentityAlgo => 15,
            ConfigKey::IdentityRole => 16,
            ConfigKey::IdentityPublicKey => 17,
            ConfigKey::IdentityPrivateKey => 18,
            ConfigKey::IdentityNonce => 19,
            ConfigKey::IdentityNodeId => 20,
            ConfigKey::NatEnabled => 21,
            ConfigKey::NatPunchTimeoutMs => 22,
            ConfigKey::NatRelayEnabled => 23,
            ConfigKey::NatUdpReflectors => 24,
            ConfigKey::NatUdpReflectorBind => 25,
            ConfigKey::TransportTlsClientConnectTimeoutMs => 26,
        }
    }

    #[test]
    fn a_key_that_exists_can_also_be_typed() {
        // The failure this closes: `global.local_discovery` was a real field
        // with a real effect, and `config set global.local_discovery true`
        // answered "unknown config key". A flag an operator cannot type is a
        // flag that does not exist, whatever the struct says. Found by running
        // the command, not by reading the code.
        let all = [
            ConfigKey::GlobalRuntimeFlavor,
            ConfigKey::GlobalWorkerThreads,
            ConfigKey::GlobalMaxBlockingThreads,
            ConfigKey::GlobalThreadKeepAliveMs,
            ConfigKey::GlobalThreadName,
            ConfigKey::GlobalThreadStackSize,
            ConfigKey::GlobalAdminSocket,
            ConfigKey::GlobalLogs,
            ConfigKey::GlobalLogFile,
            ConfigKey::GlobalBootstrap,
            ConfigKey::GlobalLocalDiscovery,
            ConfigKey::GlobalMainlineDiscovery,
            ConfigKey::IpcEnabled,
            ConfigKey::IpcSocketUri,
            ConfigKey::IpcAppSocketDir,
            ConfigKey::IdentityAlgo,
            ConfigKey::IdentityRole,
            ConfigKey::IdentityPublicKey,
            ConfigKey::IdentityPrivateKey,
            ConfigKey::IdentityNonce,
            ConfigKey::IdentityNodeId,
            ConfigKey::NatEnabled,
            ConfigKey::NatPunchTimeoutMs,
            ConfigKey::NatRelayEnabled,
            ConfigKey::NatUdpReflectors,
            ConfigKey::NatUdpReflectorBind,
            ConfigKey::TransportTlsClientConnectTimeoutMs,
        ];
        // The list is complete, or the loop below proves nothing about the key
        // somebody forgot to add to it.
        for i in 0..KEY_COUNT {
            assert!(
                all.iter().any(|k| ordinal(*k) == i),
                "key number {i} is missing from this test's list"
            );
        }
        assert_eq!(all.len(), KEY_COUNT, "the list has a duplicate or a stray");

        for key in all {
            let dotted = key.as_str();
            assert!(dotted.contains('.'), "{dotted} is not a dotted path");
            assert_eq!(
                ConfigKey::parse(dotted).ok(),
                Some(key),
                "`{dotted}` is spelled by as_str but parse does not accept it, \
                 so nobody can set it"
            );
        }
    }

    #[test]
    fn the_two_exposure_switches_are_settable() {
        // Named on purpose, beside the general rule: these two are the ones an
        // operator MUST be able to turn on themselves, so their absence would
        // be a policy failure and not only a wiring one.
        for key in ["global.bootstrap", "global.local_discovery"] {
            assert!(
                ConfigKey::parse(key).is_ok(),
                "{key} cannot be set from the command line"
            );
        }
    }
}
