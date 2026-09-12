//! `veil-cli anycast` — advertise and resolve service tags on a running node.
//!
//! Anycast lets several nodes answer under one name, and until this existed
//! nothing could reach it: the capability is wired into the node's IPC server
//! and the only caller of those opcodes was a test module. So an operator had
//! no way to see what a node advertises, no way to ask what it resolves, and
//! no way to check either against another node — which is also why the
//! cross-node half of it went unnoticed for as long as it did.
//!
//! Every command runs against a LIVE node over the admin socket, and the node
//! builds the anycast service the same way it builds the one its IPC server
//! installs. There is no second implementation here to drift from it.

use tokio::runtime::Builder;

use veil_cfg;
use veil_node_runtime::admin as node;

use super::{
    cli::{AnycastArgs, AnycastCommand},
    handlers::{CommandContext, ConfigOps},
    output::{CommandIo, OutputEvent},
    util::map_node_error,
};

pub fn handle_anycast_command<I: CommandIo, O: ConfigOps>(
    mut context: CommandContext<'_, I, O>,
    args: AnycastArgs,
) -> veil_cfg::Result<()> {
    let command = match args.command {
        AnycastCommand::Advertise {
            tag,
            score,
            ttl_secs,
        } => node::AdminCommand::AnycastAdvertise {
            tag,
            score,
            ttl_secs,
        },
        AnycastCommand::Resolve { tag, max_results } => {
            node::AdminCommand::AnycastResolve { tag, max_results }
        }
        AnycastCommand::Withdraw { tag } => node::AdminCommand::AnycastWithdraw { tag },
    };
    let response = ask_the_node(&mut context, command)?;

    match response {
        node::AdminResult::Ack { message } => {
            context.io.emit(OutputEvent::message(message));
        }
        node::AdminResult::AnycastCandidates {
            service_tag,
            node_ids,
        } => {
            if node_ids.is_empty() {
                // Say what an empty answer MEANS. Under the default
                // `SignedBound` policy a record is dropped unless this node can
                // tie it to the address it names, so "nobody advertises it" and
                // "this node cannot check the one who does" look identical from
                // here — and the second is the common case on a node that has
                // never talked to the provider.
                context.io.emit(OutputEvent::message(format!(
                    "{service_tag}: no candidates — nobody this node can \
                     account for advertises it"
                )));
            } else {
                let mut out = format!("{service_tag}: {} candidate(s)", node_ids.len());
                for id in node_ids {
                    out.push_str("\n  ");
                    out.push_str(&id);
                }
                context.io.emit(OutputEvent::message(out));
            }
        }
        other => {
            return Err(veil_cfg::ConfigError::ValidationFailed(format!(
                "admin server returned an unexpected anycast response: {other:?}"
            )));
        }
    }
    Ok(())
}

/// Send one command to the running node, or say why there is nobody to ask.
fn ask_the_node<I: CommandIo, O: ConfigOps>(
    context: &mut CommandContext<'_, I, O>,
    command: node::AdminCommand,
) -> veil_cfg::Result<node::AdminResult> {
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
        .block_on(node::send_request(&socket, command))
        .map_err(map_node_error)?;

    if let Some(error) = response.error {
        return Err(veil_cfg::ConfigError::ValidationFailed(error));
    }
    response.result.ok_or_else(|| {
        veil_cfg::ConfigError::ValidationFailed(
            "admin server answered an anycast command with no result".to_owned(),
        )
    })
}
