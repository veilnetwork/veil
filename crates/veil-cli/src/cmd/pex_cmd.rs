use tokio::runtime::Builder;

use veil_cfg;
use veil_node_runtime::admin as node;

use super::{
    cli::{PexArgs, PexCommand},
    handlers::{CommandContext, ConfigOps},
    output::{CommandIo, OutputEvent},
    util::map_node_error,
};

pub fn handle_pex_command<I: CommandIo, O: ConfigOps>(
    mut context: CommandContext<'_, I, O>,
    args: PexArgs,
) -> veil_cfg::Result<()> {
    match args.command {
        PexCommand::Status => pex_status(&mut context),
    }
}

fn pex_status<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
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
    let runtime = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(veil_cfg::ConfigError::Io)?;
    let response = runtime
        .block_on(node::send_request(&socket, node::AdminCommand::PexStatus))
        .map_err(map_node_error)?;

    if let Some(error) = response.error {
        return Err(veil_cfg::ConfigError::ValidationFailed(error));
    }

    let Some(node::AdminResult::PexStatus {
        discovered_peers,
        active_walks,
        last_walk_secs_ago,
    }) = response.result
    else {
        return Err(veil_cfg::ConfigError::ValidationFailed(
            "admin server returned unexpected PEX response".to_owned(),
        ));
    };

    let last_walk_str = match last_walk_secs_ago {
        Some(secs) => format!("{}s ago", secs),
        None => "never".to_owned(),
    };

    context.io.emit(OutputEvent::message(format!(
        "discovered_peers: {discovered_peers}\nactive_walks: {active_walks}\nlast_walk: {last_walk_str}"
    )));
    Ok(())
}
