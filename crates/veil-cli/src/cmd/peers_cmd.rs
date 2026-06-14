use base64::{Engine as _, engine::general_purpose::STANDARD};

use tokio::runtime::Builder;

use veil_cfg::{self, NodeId, PeerConfig, PeerId, SignatureAlgorithm};
use veil_crypto::Base64Nonce;
use veil_node_runtime::admin as node;
use veil_transport::TransportUri;

use super::{
    cli::{PeersArgs, PeersCommand, TlsMaterialArgs},
    handlers::{CommandContext, ConfigMutation, ConfigOps},
    output::{CommandIo, OutputEvent},
    util::map_node_error,
};

pub fn handle_peers_command<I: CommandIo, O: ConfigOps>(
    mut context: CommandContext<'_, I, O>,
    args: PeersArgs,
) -> veil_cfg::Result<()> {
    match args.command {
        PeersCommand::List => list_peers(&mut context),
        PeersCommand::Add {
            algo,
            public_key,
            nonce,
            transport,
            alt_uri,
            tls,
        } => add_peer(
            &mut context,
            algo,
            public_key,
            nonce,
            transport,
            alt_uri,
            tls,
        ),
        PeersCommand::Del {
            peer_id,
            by_node_id,
            by_public_key,
        } => del_peer(&mut context, peer_id, by_node_id, by_public_key),
        PeersCommand::Ban { node_id } => ban_peer(&mut context, node_id, true),
        PeersCommand::Unban { node_id } => ban_peer(&mut context, node_id, false),
        PeersCommand::Banned => list_banned(&mut context),
    }
}

fn list_peers<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
) -> veil_cfg::Result<()> {
    let (path, config) = context.config().load_existing()?;
    // Merge configured peers (source=configured) + discovered peers from disk.
    let mut rows: Vec<(String, String, String, String, String, String)> = Vec::new();
    for peer in &config.peers {
        let node_id = node_id_from_public_key(&peer.public_key)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "-".to_owned());
        rows.push((
            peer.peer_id.to_string(),
            node_id,
            peer.public_key.clone(),
            peer.nonce.clone(),
            peer.transport.clone(),
            "configured".to_owned(),
        ));
    }
    // Load discovered peers.
    let disc_path = path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("peers_discovered.json");
    if let Ok(data) = std::fs::read_to_string(&disc_path) {
        #[derive(serde::Deserialize)]
        struct Snap {
            node_id: String,
            public_key: String,
            nonce: String,
            transport: String,
            source: veil_node_runtime::types::PeerSource,
        }
        if let Ok(snaps) = serde_json::from_str::<Vec<Snap>>(&data) {
            for s in snaps {
                rows.push((
                    "-".to_owned(),
                    s.node_id,
                    s.public_key,
                    s.nonce,
                    s.transport,
                    s.source.to_string(),
                ));
            }
        }
    }
    if !rows.is_empty() {
        let mut lines = vec!["peer_id\tnode_id\tpublic_key\tnonce\ttransport\tsource".to_owned()];
        for (pid, nid, pk, nonce, transport, source) in &rows {
            lines.push(format!(
                "{pid}\t{nid}\t{pk}\t{nonce}\t{transport}\t{source}"
            ));
        }
        context.io.emit(OutputEvent::message(lines.join("\n")));
    }
    Ok(())
}

fn add_peer<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    algo: SignatureAlgorithm,
    public_key: String,
    nonce: String,
    transport: String,
    alt_uri: Option<String>,
    tls: TlsMaterialArgs,
) -> veil_cfg::Result<()> {
    validate_peer_input(&public_key, &nonce, &transport, &tls)?;
    let node_id = veil_cfg::NodeId::from_public_key(algo, &public_key)?;

    let message = context.config().update_existing(|_path, config| {
        let peer_id = next_available_peer_id(&config.peers);
        config.peers.push(PeerConfig {
            peer_id,
            public_key: public_key.clone(),
            nonce: nonce.clone(),
            transport: transport.clone(),
            algo,
            tls_cert: tls.tls_cert.as_deref().map(path_string),
            tls_key: tls.tls_key.as_deref().map(path_string),
            tls_ca_cert: tls.tls_ca_cert.as_deref().map(path_string),
            alt_uri: alt_uri.clone(),
        });
        Ok(ConfigMutation::save(format!(
            "assigned peer_id: {peer_id}\ncomputed node_id: {node_id}\napply with: veil-cli node reload"
        )))
    })?;

    context.io.emit(OutputEvent::message(message));
    Ok(())
}

fn del_peer<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    peer_id: Option<PeerId>,
    by_node_id: Option<NodeId>,
    by_public_key: Option<String>,
) -> veil_cfg::Result<()> {
    let selector = PeerSelector::new(peer_id, by_node_id, by_public_key)?;
    let message = context.config().update_existing(|_path, config| {
        let matches = matching_peer_indexes(&config.peers, &selector)?;
        let index = matches[0];
        let removed = config.peers.remove(index);
        Ok(ConfigMutation::save(format!(
            "removed peer_id: {}\napply with: veil-cli node reload",
            removed.peer_id
        )))
    })?;

    context.io.emit(OutputEvent::message(message));
    Ok(())
}

fn ban_peer<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    node_id: String,
    ban: bool,
) -> veil_cfg::Result<()> {
    let (config_path, config) = context.config().load_existing()?;
    let socket = node::admin_socket_path(&config, config_path.parent()).map_err(map_node_error)?;
    if !node::admin_anchor_reachable_sync(&socket) {
        return Err(veil_cfg::ConfigError::CommandFailed(format!(
            "admin socket `{}` not found; is the node running?",
            socket.display()
        )));
    }
    let command = if ban {
        node::AdminCommand::BanNode {
            node_id: node_id.clone(),
        }
    } else {
        node::AdminCommand::UnbanNode {
            node_id: node_id.clone(),
        }
    };
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(veil_cfg::ConfigError::Io)?;
    let response = runtime
        .block_on(node::send_request(&socket, command))
        .map_err(map_node_error)?;
    if let Some(error) = response.error {
        return Err(veil_cfg::ConfigError::ValidationFailed(error));
    }
    if let Some(node::AdminResult::Ack { message }) = response.result {
        context.io.emit(OutputEvent::message(message));
    }
    Ok(())
}

pub(crate) fn list_banned<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
) -> veil_cfg::Result<()> {
    let (config_path, config) = context.config().load_existing()?;
    let socket = node::admin_socket_path(&config, config_path.parent()).map_err(map_node_error)?;
    if !node::admin_anchor_reachable_sync(&socket) {
        return Err(veil_cfg::ConfigError::CommandFailed(format!(
            "admin socket `{}` not found; is the node running?",
            socket.display()
        )));
    }
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(veil_cfg::ConfigError::Io)?;
    let response = runtime
        .block_on(node::send_request(&socket, node::AdminCommand::ListBans))
        .map_err(map_node_error)?;
    if let Some(error) = response.error {
        return Err(veil_cfg::ConfigError::ValidationFailed(error));
    }
    if let Some(node::AdminResult::BanList { bans }) = response.result {
        if bans.is_empty() {
            context
                .io
                .emit(OutputEvent::message("no active bans".to_owned()));
        } else {
            let mut lines = vec!["node_id\treason\tpersistent\tbanned_at".to_owned()];
            for b in &bans {
                // banned_at rendered as ISO-ish `YYYY-MM-DD HH:MM:SS`
                // from unix seconds. `None` (pre-468.4 persisted entries) prints `-`.
                let ts = b
                    .banned_at_unix
                    .map(format_unix_secs_iso)
                    .unwrap_or_else(|| "-".to_owned());
                lines.push(format!(
                    "{}\t{}\t{}\t{}",
                    b.node_id,
                    b.reason,
                    if b.manual { "yes" } else { "no" },
                    ts,
                ));
            }
            context.io.emit(OutputEvent::message(lines.join("\n")));
        }
    }
    Ok(())
}

pub(crate) fn kill_session<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    link_id_str: String,
) -> veil_cfg::Result<()> {
    let (config_path, config) = context.config().load_existing()?;
    let socket = node::admin_socket_path(&config, config_path.parent()).map_err(map_node_error)?;
    if !node::admin_anchor_reachable_sync(&socket) {
        return Err(veil_cfg::ConfigError::CommandFailed(format!(
            "admin socket `{}` not found; is the node running?",
            socket.display()
        )));
    }
    let link_id = u64::from_str_radix(link_id_str.trim_start_matches("0x"), 16)
        .map_err(|e| veil_cfg::ConfigError::CommandFailed(format!("invalid link_id: {e}")))?;
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(veil_cfg::ConfigError::Io)?;
    let response = runtime
        .block_on(node::send_request(
            &socket,
            node::AdminCommand::KillSession { link_id },
        ))
        .map_err(map_node_error)?;
    if let Some(error) = response.error {
        return Err(veil_cfg::ConfigError::ValidationFailed(error));
    }
    if let Some(node::AdminResult::Ack { message }) = response.result {
        context.io.emit(OutputEvent::message(message));
    }
    Ok(())
}

fn validate_peer_input(
    public_key: &str,
    nonce: &str,
    transport: &str,
    tls: &TlsMaterialArgs,
) -> veil_cfg::Result<()> {
    let _ = STANDARD
        .decode(public_key)
        .map_err(veil_cfg::ConfigError::Base64)?;
    let _ = Base64Nonce::new(nonce.to_owned())?;
    let uri =
        TransportUri::parse(transport).map_err(|err| veil_cfg::ConfigError::InvalidValue {
            key: "peers.transport".to_owned(),
            value: transport.to_owned(),
            reason: err.to_string(),
        })?;
    if tls.tls_cert.is_some() != tls.tls_key.is_some() {
        return Err(veil_cfg::ConfigError::ValidationFailed(
            "peers add requires --tls-cert and --tls-key together".to_owned(),
        ));
    }
    if (tls.tls_cert.is_some() || tls.tls_key.is_some() || tls.tls_ca_cert.is_some())
        && !matches!(
            uri,
            TransportUri::Tls { .. } | TransportUri::Wss { .. } | TransportUri::Quic { .. }
        )
    {
        return Err(veil_cfg::ConfigError::ValidationFailed(
            "peer TLS material is only supported for tls://, wss:// and quic:// transports"
                .to_owned(),
        ));
    }
    Ok(())
}

fn node_id_from_public_key(public_key: &str) -> veil_cfg::Result<NodeId> {
    let bytes = STANDARD
        .decode(public_key)
        .map_err(veil_cfg::ConfigError::Base64)?;
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(blake3::hash(&bytes).as_bytes());
    hex_string(&digest)
        .parse::<NodeId>()
        .map_err(|err| veil_cfg::ConfigError::InvalidValue {
            key: "peers.public_key".to_owned(),
            value: public_key.to_owned(),
            reason: err.to_string(),
        })
}

fn next_available_peer_id(peers: &[PeerConfig]) -> PeerId {
    let mut next = 1_u32;
    loop {
        let candidate = PeerId::new(next);
        if peers.iter().all(|peer| peer.peer_id != candidate) {
            return candidate;
        }
        next = next.saturating_add(1);
    }
}

fn matching_peer_indexes(
    peers: &[PeerConfig],
    selector: &PeerSelector,
) -> veil_cfg::Result<Vec<usize>> {
    let matches = peers
        .iter()
        .enumerate()
        .filter(|(_, peer)| selector.matches(peer))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();

    match matches.len() {
        0 => Err(veil_cfg::ConfigError::ValidationFailed(
            "peer selector did not match any configured peer".to_owned(),
        )),
        1 => Ok(matches),
        _ => Err(veil_cfg::ConfigError::ValidationFailed(
            "peer selector matched more than one configured peer".to_owned(),
        )),
    }
}

fn hex_string(bytes: &[u8]) -> String {
    veil_util::bytes_to_hex(bytes)
}

fn path_string(path: &std::path::Path) -> String {
    path.display().to_string()
}

/// Format a unix-seconds timestamp as `YYYY-MM-DD HH:MM:SS UTC`.
///
/// Avoids dragging in `chrono` just for one display helper — computes
/// calendar fields directly from seconds since the UNIX epoch. Accurate
/// for dates from 1970 through at least 2400; ignores leap seconds
/// (never emitted by SystemTime on common platforms). For ops-ergonomic
/// display only — not suitable for time arithmetic.
fn format_unix_secs_iso(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let sec_of_day = secs % 86_400;
    let hh = sec_of_day / 3600;
    let mm = (sec_of_day / 60) % 60;
    let ss = sec_of_day % 60;

    // Convert days-since-1970 (year, month, day) using the Howard
    // Hinnant civil-from-days algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{day:02} {hh:02}:{mm:02}:{ss:02} UTC")
}

struct PeerSelector {
    peer_id: Option<PeerId>,
    node_id: Option<NodeId>,
    public_key: Option<String>,
}

impl PeerSelector {
    fn new(
        peer_id: Option<PeerId>,
        node_id: Option<NodeId>,
        public_key: Option<String>,
    ) -> veil_cfg::Result<Self> {
        let selectors = usize::from(peer_id.is_some())
            + usize::from(node_id.is_some())
            + usize::from(public_key.is_some());
        if selectors != 1 {
            return Err(veil_cfg::ConfigError::ValidationFailed(
                "choose exactly one peer selector: peer_id, --by-node-id, or --by-public-key"
                    .to_owned(),
            ));
        }
        Ok(Self {
            peer_id,
            node_id,
            public_key,
        })
    }

    fn matches(&self, peer: &PeerConfig) -> bool {
        if let Some(peer_id) = self.peer_id {
            return peer.peer_id == peer_id;
        }
        if let Some(node_id) = self.node_id {
            return node_id_from_public_key(&peer.public_key)
                .map(|value| value == node_id)
                .unwrap_or(false);
        }
        if let Some(public_key) = self.public_key.as_deref() {
            return peer.public_key == public_key;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::super::handlers::CommandContext;
    use super::*;
    use crate::cmd::test_support::BufferIo;
    use crate::test_support;
    use std::{
        cell::RefCell,
        path::{Path, PathBuf},
        rc::Rc,
    };
    use veil_cfg::Config;

    #[derive(Clone, Debug)]
    struct PeersConfigOps {
        path: PathBuf,
        state: Rc<RefCell<Config>>,
    }

    impl ConfigOps for PeersConfigOps {
        fn default_init_path(&self) -> PathBuf {
            self.path.clone()
        }

        fn prepare_init_path(&self, path: &Path, _force: bool) -> veil_cfg::Result<PathBuf> {
            Ok(path.to_path_buf())
        }

        fn locate_config(&self, _config_arg: Option<&Path>) -> veil_cfg::Result<PathBuf> {
            Ok(self.path.clone())
        }

        fn read_raw_config(&self, _path: &Path) -> veil_cfg::Result<String> {
            Ok(String::new())
        }

        fn load_config(&self, _path: &Path) -> veil_cfg::Result<Config> {
            Ok(self.state.borrow().clone())
        }

        fn save_config(&self, _path: &Path, config: &Config) -> veil_cfg::Result<()> {
            *self.state.borrow_mut() = config.clone();
            Ok(())
        }

        fn write_raw_config(&self, _path: &Path, _content: &str) -> veil_cfg::Result<()> {
            // Slice 11b: test stub — fixture acks the
            // raw-write path without persisting to disk.
            Ok(())
        }
    }

    #[test]
    fn add_assigns_unique_peer_id() {
        let public_a = test_support::valid_identity().public_key;
        let public_b = test_support::ed25519_keypair().public_key;
        let config = Config {
            peers: vec![PeerConfig {
                peer_id: PeerId::new(1),
                public_key: public_a,
                nonce: "AAAAAA==".to_owned(),
                transport: "tcp://127.0.0.1:9000".to_owned(),
                algo: Default::default(),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                alt_uri: None,
            }],
            ..Config::default()
        };
        let state = Rc::new(RefCell::new(config));
        let ops = PeersConfigOps {
            path: PathBuf::from("/tmp/config.toml"),
            state: Rc::clone(&state),
        };
        let mut context = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops,
        };

        add_peer(
            &mut context,
            SignatureAlgorithm::Ed25519,
            public_b,
            "AAAAAA==".to_owned(),
            "tcp://127.0.0.1:9001".to_owned(),
            None,
            TlsMaterialArgs::default(),
        )
        .unwrap();

        assert_eq!(state.borrow().peers.len(), 2);
        assert_eq!(state.borrow().peers[1].peer_id, PeerId::new(2));
        assert!(context.io.output.contains("assigned peer_id: 0x00000002"));
    }

    #[test]
    fn del_by_peer_id_node_id_and_public_key() {
        let public_a = test_support::valid_identity().public_key;
        let public_b = test_support::ed25519_keypair().public_key;
        let public_c = test_support::ed25519_keypair().public_key;
        let peers = vec![
            PeerConfig {
                peer_id: PeerId::new(1),
                public_key: public_a.clone(),
                nonce: "AAAAAA==".to_owned(),
                transport: "tcp://127.0.0.1:9000".to_owned(),
                algo: Default::default(),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                alt_uri: None,
            },
            PeerConfig {
                peer_id: PeerId::new(2),
                public_key: public_b.clone(),
                nonce: "AAAAAA==".to_owned(),
                transport: "tcp://127.0.0.1:9001".to_owned(),
                algo: Default::default(),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                alt_uri: None,
            },
            PeerConfig {
                peer_id: PeerId::new(3),
                public_key: public_c.clone(),
                nonce: "AAAAAA==".to_owned(),
                transport: "tcp://127.0.0.1:9002".to_owned(),
                algo: Default::default(),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                alt_uri: None,
            },
        ];
        let state = Rc::new(RefCell::new(Config {
            peers,
            ..Config::default()
        }));

        for selector in [
            PeerSelector::new(Some(PeerId::new(1)), None, None).unwrap(),
            PeerSelector::new(
                None,
                Some(node_id_from_public_key(&public_b).unwrap()),
                None,
            )
            .unwrap(),
            PeerSelector::new(None, None, Some(public_c.clone())).unwrap(),
        ] {
            let mut config = state.borrow().clone();
            let indexes = matching_peer_indexes(&config.peers, &selector).unwrap();
            config.peers.remove(indexes[0]);
            assert_eq!(config.peers.len(), 2);
        }
    }

    #[test]
    fn transport_string_validated_on_add() {
        let state = Rc::new(RefCell::new(Config::default()));
        let ops = PeersConfigOps {
            path: PathBuf::from("/tmp/config.toml"),
            state,
        };
        let mut context = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops,
        };

        let err = add_peer(
            &mut context,
            SignatureAlgorithm::Ed25519,
            test_support::ed25519_keypair().public_key,
            "AAAAAA==".to_owned(),
            "://broken".to_owned(),
            None,
            TlsMaterialArgs::default(),
        )
        .expect_err("broken transport must fail");

        assert!(err.to_string().contains("peers.transport"));
    }

    #[test]
    fn list_prints_expected_columns() {
        let state = Rc::new(RefCell::new(Config {
            peers: vec![PeerConfig {
                peer_id: PeerId::new(1),
                public_key: test_support::ed25519_keypair().public_key,
                nonce: "AAAAAA==".to_owned(),
                transport: "tcp://127.0.0.1:9000".to_owned(),
                algo: Default::default(),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                alt_uri: None,
            }],
            ..Config::default()
        }));
        let ops = PeersConfigOps {
            path: PathBuf::from("/tmp/config.toml"),
            state,
        };
        let mut context = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops,
        };

        list_peers(&mut context).unwrap();

        assert!(context.io.output.contains("peer_id"));
        assert!(context.io.output.contains("node_id"));
        assert!(context.io.output.contains("public_key"));
        assert!(context.io.output.contains("nonce"));
        assert!(context.io.output.contains("transport"));
    }

    #[test]
    fn list_emits_nothing_when_no_peers_are_configured() {
        let state = Rc::new(RefCell::new(Config::default()));
        let ops = PeersConfigOps {
            path: PathBuf::from("/tmp/config.toml"),
            state,
        };
        let mut context = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops,
        };

        list_peers(&mut context).unwrap();
        assert!(context.io.output.is_empty());
    }
}
