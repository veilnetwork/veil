use crate::format::FormatBackend;
use crate::{Config, Result};

pub(crate) static BACKEND: JsonBackend = JsonBackend;

pub(crate) struct JsonBackend;

impl FormatBackend for JsonBackend {
    fn load(&self, content: &str) -> Result<Config> {
        load_config(content)
    }

    fn render(&self, config: &Config) -> Result<String> {
        render_config(config)
    }
}

fn load_config(content: &str) -> Result<Config> {
    Ok(serde_json::from_str(content)?)
}

fn render_config(config: &Config) -> Result<String> {
    Ok(serde_json::to_string_pretty(config)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        IdentityConfig, ListenConfig, ListenId, LogsConfig, MetricsConfig, PeerConfig, PeerId,
        SignatureAlgorithm,
    };

    #[test]
    fn roundtrip_preserves_identity_section() {
        let config = Config {
            identity: Some(IdentityConfig {
                algo: SignatureAlgorithm::Ed25519,
                role: Default::default(),
                public_key: "pub".to_owned(),
                private_key: "priv".to_owned(),
                nonce: "AAAAAA==".to_owned(),
                node_id: None,
                key_passphrase: None,
                key_passphrase_file: None,
                key_passphrase_prompt: false,
                lazy_mining: true,
                max_lazy_difficulty: 64,
            }),
            ..Config::default()
        };

        let rendered = render_config(&config).unwrap();
        let loaded = load_config(&rendered).unwrap();

        assert_eq!(loaded.identity, config.identity);
        assert!(rendered.contains("\"Identity\""));
    }

    #[test]
    fn roundtrip_preserves_node_sections() {
        let mut config = Config::default();
        config.global.admin_socket = Some("unix:///tmp/veil.sock".to_owned());
        config.global.logs = LogsConfig::File;
        config.global.log_file = Some("/tmp/veil.log".to_owned());
        config.peers.push(PeerConfig {
            peer_id: PeerId::new(1),
            public_key: "pub".to_owned(),
            nonce: "AAAAAA==".to_owned(),
            transport: "tcp://127.0.0.1:9000".to_owned(),
            algo: Default::default(),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            alt_uri: None,
        });
        config.listen.push(ListenConfig {
            id: ListenId::new(2),
            transport: "tcp://127.0.0.1:9001".to_owned(),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            advertise: None,
            relay: None,
            ..Default::default()
        });
        config.metrics = Some(MetricsConfig {
            listen: "tcp://127.0.0.1:9100".to_owned(),
            path: Some("/metrics".to_owned()),
            auth_token: None,
            allow_unauthenticated_remote_metrics: false,
        });

        let rendered = render_config(&config).unwrap();
        let loaded = load_config(&rendered).unwrap();

        assert_eq!(loaded.global.admin_socket, config.global.admin_socket);
        assert_eq!(loaded.global.logs, config.global.logs);
        assert_eq!(loaded.global.log_file, config.global.log_file);
        assert_eq!(loaded.peers, config.peers);
        assert_eq!(loaded.listen, config.listen);
        assert_eq!(loaded.metrics, config.metrics);
    }
}
