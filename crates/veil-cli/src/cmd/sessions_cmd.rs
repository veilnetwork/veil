use tokio::runtime::Builder;

use veil_cfg;
use veil_node_runtime::admin as node;

use super::{
    cli::{SessionsArgs, SessionsCommand},
    handlers::{CommandContext, ConfigOps},
    output::{CommandIo, OutputEvent},
    util::map_node_error,
};

pub fn handle_sessions_command<I: CommandIo, O: ConfigOps>(
    mut context: CommandContext<'_, I, O>,
    args: SessionsArgs,
) -> veil_cfg::Result<()> {
    match args.command {
        SessionsCommand::List { verbose } => list_sessions(&mut context, verbose),
        SessionsCommand::Kill { link_id } => super::peers_cmd::kill_session(&mut context, link_id),
        SessionsCommand::Ban { node_id } => super::peers_cmd::handle_peers_command(
            context,
            super::cli::PeersArgs {
                command: super::cli::PeersCommand::Ban { node_id },
            },
        ),
        SessionsCommand::Unban { node_id } => super::peers_cmd::handle_peers_command(
            context,
            super::cli::PeersArgs {
                command: super::cli::PeersCommand::Unban { node_id },
            },
        ),
        SessionsCommand::Banned => super::peers_cmd::list_banned(&mut context),
    }
}

fn list_sessions<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    verbose: bool,
) -> veil_cfg::Result<()> {
    let (config_path, config) = context.config().load_existing()?;
    if config.global.admin_socket.is_none() {
        return Err(veil_cfg::ConfigError::CommandFailed(
            "global.admin_socket must be configured".to_owned(),
        ));
    }
    let socket = node::admin_socket_path(&config, config_path.parent()).map_err(map_node_error)?;
    if !node::admin_anchor_reachable_sync(&socket) {
        return Err(veil_cfg::ConfigError::CommandFailed(format!(
            "admin socket `{}` was not found; start the node with `veil-cli node run`",
            socket.display()
        )));
    }
    let runtime = build_runtime()?;
    let response = runtime
        .block_on(node::send_request(&socket, node::AdminCommand::Sessions))
        .map_err(map_node_error)?;

    if let Some(error) = response.error {
        return Err(veil_cfg::ConfigError::ValidationFailed(error));
    }

    let Some(node::AdminResult::Sessions { sessions }) = response.result else {
        return Err(veil_cfg::ConfigError::ValidationFailed(
            "admin server returned unexpected sessions response".to_owned(),
        ));
    };

    context
        .io
        .emit(OutputEvent::message(render_sessions(&sessions, verbose)));
    Ok(())
}

/// Truncate a hex string to the first 12 chars + ellipsis, unless
/// `verbose` is true. Bare ids longer than 12 chars get an ellipsis;
/// short ids and "-" pass through unchanged.
fn maybe_short(s: &str, verbose: bool) -> String {
    if verbose || s.len() <= 12 || s == "-" {
        s.to_owned()
    } else {
        format!("{}…", &s[..12])
    }
}

fn render_sessions(sessions: &[node::AdminSessionEntry], verbose: bool) -> String {
    let mut lines =
        vec!["link_id\tnode_id\tsource\ttransport\tstate\tloss_pct\tsamples".to_owned()];
    for session in sessions {
        lines.push(format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            maybe_short(&session.link_id, verbose),
            session
                .node_id
                .as_deref()
                .map(|n| maybe_short(n, verbose))
                .unwrap_or_else(|| "-".to_owned()),
            session.source,
            session.transport,
            session.state,
            session
                .loss_rate_pct
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            session
                .loss_samples
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_owned()),
        ));
    }
    lines.join("\n")
}

fn build_runtime() -> veil_cfg::Result<tokio::runtime::Runtime> {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(veil_cfg::ConfigError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::{
        handlers::CommandContext,
        test_support::{BufferIo, MockConfigOps},
    };
    use std::path::PathBuf;
    use veil_cfg::{Config, GlobalConfig};

    #[test]
    fn renders_sessions_table() {
        let rendered = render_sessions(
            &[node::AdminSessionEntry {
                link_id: "0x0000000000000001".to_owned(),
                node_id: None,
                nonce: None,
                matched_peer_id: None,
                source: "inbound(0x00000001)".to_owned(),
                transport: "tcp://127.0.0.1:9000".to_owned(),
                state: "active".to_owned(),
                loss_rate_pct: None,
                loss_samples: None,
            }],
            false,
        );

        assert!(rendered.contains("link_id"));
        assert!(rendered.contains("source"));
        assert!(rendered.contains("state"));
        // loss columns must appear in header and as "-" placeholders.
        assert!(rendered.contains("loss_pct"));
        assert!(rendered.contains("samples"));
    }

    #[test]
    fn renders_loss_columns_when_present() {
        let rendered = render_sessions(
            &[node::AdminSessionEntry {
                link_id: "0x0000000000000002".to_owned(),
                node_id: Some("0xaabbccdd".to_owned()),
                nonce: None,
                matched_peer_id: None,
                source: "outbound(peer-1)".to_owned(),
                transport: "tcp://127.0.0.1:9001".to_owned(),
                state: "active".to_owned(),
                loss_rate_pct: Some(35),
                loss_samples: Some(120),
            }],
            true,
        ); // verbose=true to keep `0xaabbccdd` short-id intact
        assert!(rendered.contains("\t35\t120"), "rendered: {rendered}");
    }

    #[test]
    fn list_requires_admin_socket_configuration() {
        let mut context = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops: MockConfigOps {
                locate_path: PathBuf::from("/tmp/config.toml"),
                loaded_config: Config {
                    global: GlobalConfig::default(),
                    ..Config::default()
                },
                ..MockConfigOps::default()
            },
        };

        let err = list_sessions(&mut context, false).expect_err("admin socket required");
        assert_eq!(err.to_string(), "global.admin_socket must be configured");
    }

    #[test]
    fn list_reports_missing_socket_path_readably() {
        let mut context = CommandContext {
            config_arg: None,
            io: BufferIo::default(),
            ops: MockConfigOps {
                locate_path: PathBuf::from("/tmp/config.toml"),
                loaded_config: Config {
                    global: GlobalConfig {
                        admin_socket: Some("unix:///tmp/veil-missing-admin.sock".to_owned()),
                        ..GlobalConfig::default()
                    },
                    ..Config::default()
                },
                ..MockConfigOps::default()
            },
        };

        let err = list_sessions(&mut context, false).expect_err("missing socket must fail");
        assert!(
            err.to_string()
                .contains("admin socket `/tmp/veil-missing-admin.sock` was not found")
        );
    }
}
