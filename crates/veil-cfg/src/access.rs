use super::{
    Config, ConfigError, ConfigKey, LogsConfig, NodeId, NodeRole, Result, RuntimeFlavor,
    SignatureAlgorithm, option_to_string, parse_optional_string, parse_optional_u16,
    parse_optional_u64, parse_optional_usize,
};

/// Read a configuration value by its dotted `ConfigKey` string and render it
/// back as a string suitable for `node config get`. Returns a
/// [`ConfigError::UnknownKey`] if `key` does not parse.
pub fn get(config: &Config, key: &str) -> Result<String> {
    match ConfigKey::parse(key)? {
        ConfigKey::GlobalRuntimeFlavor => Ok(config.global.runtime_flavor.to_string()),
        ConfigKey::GlobalWorkerThreads => Ok(option_to_string(config.global.worker_threads)),
        ConfigKey::GlobalMaxBlockingThreads => {
            Ok(option_to_string(config.global.max_blocking_threads))
        }
        ConfigKey::GlobalThreadKeepAliveMs => {
            Ok(option_to_string(config.global.thread_keep_alive_ms))
        }
        ConfigKey::GlobalThreadName => Ok(option_to_string(config.global.thread_name.as_deref())),
        ConfigKey::GlobalThreadStackSize => Ok(option_to_string(config.global.thread_stack_size)),
        ConfigKey::GlobalAdminSocket => Ok(option_to_string(config.global.admin_socket.as_deref())),
        ConfigKey::GlobalLogs => Ok(config.global.logs.to_string()),
        ConfigKey::GlobalLogFile => Ok(option_to_string(config.global.log_file.as_deref())),
        ConfigKey::IpcEnabled => Ok(config.ipc.enabled.to_string()),
        ConfigKey::IpcSocketUri => Ok(option_to_string(config.ipc.socket_uri.as_deref())),
        ConfigKey::IpcAppSocketDir => Ok(option_to_string(
            config
                .ipc
                .app_socket_dir
                .as_deref()
                .and_then(|p| p.to_str()),
        )),
        ConfigKey::IdentityAlgo => Ok(config
            .identity
            .as_ref()
            .map(|id| id.algo.to_string())
            .unwrap_or_default()),
        ConfigKey::IdentityRole => Ok(config
            .identity
            .as_ref()
            .map(|id| id.role.to_string())
            .unwrap_or_default()),
        ConfigKey::IdentityPublicKey => Ok(config
            .identity
            .as_ref()
            .map(|id| id.public_key.clone())
            .unwrap_or_default()),
        ConfigKey::IdentityPrivateKey => Ok(config
            .identity
            .as_ref()
            .map(|id| id.private_key.clone())
            .unwrap_or_default()),
        ConfigKey::IdentityNonce => Ok(config
            .identity
            .as_ref()
            .map(|id| id.nonce.clone())
            .unwrap_or_default()),
        ConfigKey::IdentityNodeId => {
            Ok(option_to_string(config.identity.as_ref().and_then(
                |identity| identity.node_id.map(|value| value.to_string()),
            )))
        }
        ConfigKey::TransportTlsClientConnectTimeoutMs => Ok(option_to_string(
            config.transport.tls_client.connect_timeout_ms,
        )),
    }
}

/// Write a configuration value by its dotted `ConfigKey` string, parsing
/// `value` into the appropriate type. Returns an error on unknown key or
/// malformed value; does not persist the change — the caller saves the
/// config file separately.
pub fn set(config: &mut Config, key: &str, value: &str) -> Result<()> {
    let key = ConfigKey::parse(key)?;

    match key {
        ConfigKey::GlobalRuntimeFlavor => {
            config.global.runtime_flavor =
                value
                    .parse::<RuntimeFlavor>()
                    .map_err(|reason| ConfigError::InvalidValue {
                        key: key.as_str().to_owned(),
                        value: value.to_owned(),
                        reason: reason.to_string(),
                    })?;
            Ok(())
        }
        ConfigKey::GlobalWorkerThreads => {
            config.global.worker_threads = parse_optional_u16(key, value)?;
            Ok(())
        }
        ConfigKey::GlobalMaxBlockingThreads => {
            config.global.max_blocking_threads = parse_optional_u16(key, value)?;
            Ok(())
        }
        ConfigKey::GlobalThreadKeepAliveMs => {
            config.global.thread_keep_alive_ms = parse_optional_u64(key, value)?;
            Ok(())
        }
        ConfigKey::GlobalThreadName => {
            config.global.thread_name = parse_optional_string(value);
            Ok(())
        }
        ConfigKey::GlobalThreadStackSize => {
            config.global.thread_stack_size = parse_optional_usize(key, value)?;
            Ok(())
        }
        ConfigKey::GlobalAdminSocket => {
            config.global.admin_socket = parse_optional_string(value);
            Ok(())
        }
        ConfigKey::GlobalLogs => {
            config.global.logs =
                value
                    .parse::<LogsConfig>()
                    .map_err(|reason| ConfigError::InvalidValue {
                        key: key.as_str().to_owned(),
                        value: value.to_owned(),
                        reason: reason.to_string(),
                    })?;
            Ok(())
        }
        ConfigKey::GlobalLogFile => {
            config.global.log_file = parse_optional_string(value);
            Ok(())
        }
        ConfigKey::IpcEnabled => {
            config.ipc.enabled = value
                .parse::<bool>()
                .map_err(|_| ConfigError::InvalidValue {
                    key: key.as_str().to_owned(),
                    value: value.to_owned(),
                    reason: "expected `true` or `false`".to_owned(),
                })?;
            Ok(())
        }
        ConfigKey::IpcSocketUri => {
            config.ipc.socket_uri = parse_optional_string(value);
            Ok(())
        }
        ConfigKey::IpcAppSocketDir => {
            config.ipc.app_socket_dir = parse_optional_string(value).map(std::path::PathBuf::from);
            Ok(())
        }
        ConfigKey::IdentityAlgo => {
            let identity = config.identity.get_or_insert_with(Default::default);
            identity.algo = value.parse::<SignatureAlgorithm>().map_err(|reason| {
                ConfigError::InvalidValue {
                    key: key.as_str().to_owned(),
                    value: value.to_owned(),
                    reason: reason.to_string(),
                }
            })?;
            Ok(())
        }
        ConfigKey::IdentityRole => {
            let identity = config.identity.get_or_insert_with(Default::default);
            identity.role =
                value
                    .parse::<NodeRole>()
                    .map_err(|reason| ConfigError::InvalidValue {
                        key: key.as_str().to_owned(),
                        value: value.to_owned(),
                        reason: reason.to_string(),
                    })?;
            Ok(())
        }
        ConfigKey::IdentityPublicKey => {
            let identity = config.identity.get_or_insert_with(Default::default);
            identity.public_key = value.to_owned();
            Ok(())
        }
        ConfigKey::IdentityPrivateKey => {
            let identity = config.identity.get_or_insert_with(Default::default);
            identity.private_key = value.to_owned();
            Ok(())
        }
        ConfigKey::IdentityNonce => {
            let identity = config.identity.get_or_insert_with(Default::default);
            identity.nonce = value.to_owned();
            Ok(())
        }
        ConfigKey::IdentityNodeId => {
            let identity = config.identity.get_or_insert_with(Default::default);
            identity.node_id = if value.trim().is_empty() {
                None
            } else {
                Some(
                    value
                        .parse::<NodeId>()
                        .map_err(|reason| ConfigError::InvalidValue {
                            key: key.as_str().to_owned(),
                            value: value.to_owned(),
                            reason: reason.to_string(),
                        })?,
                )
            };
            Ok(())
        }
        ConfigKey::TransportTlsClientConnectTimeoutMs => {
            config.transport.tls_client.connect_timeout_ms = parse_optional_u64(key, value)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updates_known_key() {
        let mut config = Config::default();
        set(&mut config, "global.worker_threads", "8").unwrap();
        assert_eq!(get(&config, "global.worker_threads").unwrap(), "8");
    }

    #[test]
    fn updates_global_admin_and_logs_keys() {
        let mut config = Config::default();
        set(&mut config, "global.admin_socket", "unix:///tmp/veil.sock").unwrap();
        set(&mut config, "global.logs", "file").unwrap();
        set(&mut config, "global.log_file", "/tmp/veil.log").unwrap();

        assert_eq!(
            get(&config, "global.admin_socket").unwrap(),
            "unix:///tmp/veil.sock"
        );
        assert_eq!(get(&config, "global.logs").unwrap(), "file");
        assert_eq!(get(&config, "global.log_file").unwrap(), "/tmp/veil.log");
    }
}
