use std::path::Path;

use veil_cfg::{self, ListenConfig, ListenId};
use veil_transport::{TransportRegistry, TransportUri};

use super::{
    cli::{ListenArgs, ListenCommand, TlsMaterialArgs},
    handlers::{CommandContext, ConfigMutation, ConfigOps},
    output::{CommandIo, OutputEvent, format_columns},
};

pub fn handle_listen_command<I: CommandIo, O: ConfigOps>(
    mut context: CommandContext<'_, I, O>,
    args: ListenArgs,
) -> veil_cfg::Result<()> {
    match args.command {
        ListenCommand::List => list_listens(&mut context),
        ListenCommand::Add {
            transport,
            advertise,
            relay,
            tls,
        } => add_listen(&mut context, transport, advertise, relay, tls),
        ListenCommand::Del { listen_id } => del_listen(&mut context, listen_id),
    }
}

fn list_listens<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
) -> veil_cfg::Result<()> {
    let (_path, config) = context.config().load_existing()?;
    let rendered = render_listens_table(&config.listen);
    if !rendered.is_empty() {
        context.io.emit(OutputEvent::message(rendered));
    }
    Ok(())
}

fn add_listen<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    transport: String,
    advertise: Option<String>,
    relay: Option<String>,
    tls: TlsMaterialArgs,
) -> veil_cfg::Result<()> {
    validate_listen_input(&transport, advertise.as_deref(), relay.as_deref(), &tls)?;

    let message = context.config().update_existing(|_path, config| {
        let listen_id = next_available_listen_id(&config.listen);
        config.listen.push(ListenConfig {
            id: listen_id,
            transport: transport.clone(),
            tls_cert: tls.tls_cert.as_deref().map(path_string),
            tls_key: tls.tls_key.as_deref().map(path_string),
            tls_ca_cert: tls.tls_ca_cert.as_deref().map(path_string),
            advertise: advertise.clone(),
            relay: relay.clone(),
            ..Default::default()
        });
        Ok(ConfigMutation::save(format!(
            "assigned listen_id: {listen_id}\napply with: veil-cli node reload"
        )))
    })?;

    context.io.emit(OutputEvent::message(message));
    Ok(())
}

fn del_listen<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    listen_id: ListenId,
) -> veil_cfg::Result<()> {
    let message = context.config().update_existing(|_path, config| {
        let Some(index) = config
            .listen
            .iter()
            .position(|listen| listen.id == listen_id)
        else {
            return Err(veil_cfg::ConfigError::ValidationFailed(format!(
                "unknown listen_id `{listen_id}`"
            )));
        };
        config.listen.remove(index);
        Ok(ConfigMutation::save(format!(
            "removed listen_id: {listen_id}\napply with: veil-cli node reload"
        )))
    })?;

    context.io.emit(OutputEvent::message(message));
    Ok(())
}

fn validate_listen_input(
    transport: &str,
    advertise: Option<&str>,
    relay: Option<&str>,
    tls: &TlsMaterialArgs,
) -> veil_cfg::Result<()> {
    let uri =
        TransportUri::parse(transport).map_err(|err| veil_cfg::ConfigError::InvalidValue {
            key: "listen.transport".to_owned(),
            value: transport.to_owned(),
            reason: err.to_string(),
        })?;

    let registry = TransportRegistry::with_defaults();
    let transport_impl = registry.get(uri.scheme()).map_err(|err| {
        veil_cfg::ConfigError::ValidationFailed(format!(
            "unsupported listen transport scheme `{}`: {}",
            uri.scheme(),
            err
        ))
    })?;
    if !transport_impl.capabilities().listener {
        return Err(veil_cfg::ConfigError::ValidationFailed(
            "listen transport must use a scheme that supports listen/bind".to_owned(),
        ));
    }

    if let Some(adv) = advertise {
        TransportUri::parse(adv).map_err(|err| veil_cfg::ConfigError::InvalidValue {
            key: "listen.advertise".to_owned(),
            value: adv.to_owned(),
            reason: err.to_string(),
        })?;
    }

    if let Some(relay_b64) = relay {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let bytes =
            STANDARD
                .decode(relay_b64)
                .map_err(|_| veil_cfg::ConfigError::InvalidValue {
                    key: "listen.relay".to_owned(),
                    value: relay_b64.to_owned(),
                    reason: "invalid base64".to_owned(),
                })?;
        if bytes.len() != 32 {
            return Err(veil_cfg::ConfigError::InvalidValue {
                key: "listen.relay".to_owned(),
                value: relay_b64.to_owned(),
                reason: format!("expected 32 bytes, got {}", bytes.len()),
            });
        }
    }

    if tls.tls_cert.is_some() != tls.tls_key.is_some() {
        return Err(veil_cfg::ConfigError::ValidationFailed(
            "listen add requires --tls-cert and --tls-key together".to_owned(),
        ));
    }
    if (tls.tls_cert.is_some() || tls.tls_key.is_some() || tls.tls_ca_cert.is_some())
        && !matches!(
            uri,
            TransportUri::Tls { .. } | TransportUri::Wss { .. } | TransportUri::Quic { .. }
        )
    {
        return Err(veil_cfg::ConfigError::ValidationFailed(
            "listen TLS material is only supported for tls://, wss:// and quic:// transports"
                .to_owned(),
        ));
    }
    Ok(())
}

fn next_available_listen_id(listens: &[ListenConfig]) -> ListenId {
    let mut next = 1_u32;
    loop {
        let candidate = ListenId::new(next);
        if listens.iter().all(|listen| listen.id != candidate) {
            return candidate;
        }
        next = next.saturating_add(1);
    }
}

fn render_listens_table(listens: &[ListenConfig]) -> String {
    if listens.is_empty() {
        return String::new();
    }
    let mut lines = vec![format_columns(
        &[
            "listen_id",
            "transport",
            "tls_cert",
            "tls_key",
            "tls_ca_cert",
        ],
        &[10, 0, 20, 20, 20],
    )];
    for listen in listens {
        lines.push(format_columns(
            &[
                &listen.id.to_string(),
                listen.transport.as_str(),
                listen.tls_cert.as_deref().unwrap_or("-"),
                listen.tls_key.as_deref().unwrap_or("-"),
                listen.tls_ca_cert.as_deref().unwrap_or("-"),
            ],
            &[10, 0, 20, 20, 20],
        ));
    }
    lines.join("\n")
}

fn path_string(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test_support::BufferIo;
    use std::{
        cell::RefCell,
        path::{Path, PathBuf},
        rc::Rc,
    };
    use veil_cfg::Config;

    #[derive(Clone, Debug)]
    struct ListenConfigOps {
        path: PathBuf,
        state: Rc<RefCell<Config>>,
    }

    impl ConfigOps for ListenConfigOps {
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
            // raw-write path without persisting к disk.
            Ok(())
        }
    }

    #[test]
    fn add_assigns_unique_listen_id() {
        let state = Rc::new(RefCell::new(Config {
            listen: vec![ListenConfig {
                id: ListenId::new(1),
                transport: "tcp://127.0.0.1:9000".to_owned(),
                advertise: None,
                relay: None,
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                ..Default::default()
            }],
            ..Config::default()
        }));
        let ops = ListenConfigOps {
            path: PathBuf::from("/tmp/config.toml"),
            state: Rc::clone(&state),
        };
        let mut context = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops,
        };

        add_listen(
            &mut context,
            "tcp://127.0.0.1:9001".to_owned(),
            None,
            None,
            TlsMaterialArgs::default(),
        )
        .unwrap();

        assert_eq!(state.borrow().listen.len(), 2);
        assert_eq!(state.borrow().listen[1].id, ListenId::new(2));
        assert!(context.io.output.contains("assigned listen_id: 0x00000002"));
    }

    #[test]
    fn del_removes_listen_by_id() {
        let state = Rc::new(RefCell::new(Config {
            listen: vec![ListenConfig {
                id: ListenId::new(1),
                transport: "tcp://127.0.0.1:9000".to_owned(),
                advertise: None,
                relay: None,
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                ..Default::default()
            }],
            ..Config::default()
        }));
        let ops = ListenConfigOps {
            path: PathBuf::from("/tmp/config.toml"),
            state: Rc::clone(&state),
        };
        let mut context = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops,
        };

        del_listen(&mut context, ListenId::new(1)).unwrap();

        assert!(state.borrow().listen.is_empty());
        assert!(context.io.output.contains("removed listen_id: 0x00000001"));
    }

    #[test]
    fn transport_string_and_listener_capability_validated_on_add() {
        let state = Rc::new(RefCell::new(Config::default()));
        let ops = ListenConfigOps {
            path: PathBuf::from("/tmp/config.toml"),
            state,
        };
        let mut context = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops,
        };

        let err = add_listen(
            &mut context,
            "socks://127.0.0.1:1080/1.1.1.1:443".to_owned(),
            None,
            None,
            TlsMaterialArgs::default(),
        )
        .expect_err("non-listener transport must fail");
        assert!(
            err.to_string()
                .contains("listen transport must use a scheme that supports listen/bind")
        );
    }

    #[test]
    fn list_prints_expected_columns() {
        let state = Rc::new(RefCell::new(Config {
            listen: vec![ListenConfig {
                id: ListenId::new(1),
                transport: "tcp://127.0.0.1:9000".to_owned(),
                advertise: None,
                relay: None,
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                ..Default::default()
            }],
            ..Config::default()
        }));
        let ops = ListenConfigOps {
            path: PathBuf::from("/tmp/config.toml"),
            state,
        };
        let mut context = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops,
        };

        list_listens(&mut context).unwrap();

        assert!(context.io.output.contains("listen_id"));
        assert!(context.io.output.contains("transport"));
        assert!(context.io.output.contains("tls_cert"));
    }

    #[test]
    fn list_emits_nothing_when_no_listens_are_configured() {
        let state = Rc::new(RefCell::new(Config::default()));
        let ops = ListenConfigOps {
            path: PathBuf::from("/tmp/config.toml"),
            state,
        };
        let mut context = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops,
        };

        list_listens(&mut context).unwrap();
        assert!(context.io.output.is_empty());
    }
}
