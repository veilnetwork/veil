use clap::Parser;

use veil_cfg;

use super::{
    adapters::CliRuntime,
    bootstrap_cmd::handle_bootstrap_command,
    cli::{Cli, Command, ServiceCommand},
    debug::handle_debug_command,
    handlers::handle_config_command,
    identity::handle_key_command,
    invite_cmd::handle_invite_command,
    listen_cmd::handle_listen_command,
    mobile_cmd::handle_mobile_command,
    network_cmd::handle_network_command,
    node_cmd::handle_node_command,
    output::{OutputFormat, StdCommandIo},
    peers_cmd::handle_peers_command,
    pex_cmd::handle_pex_command,
    service,
    sessions_cmd::handle_sessions_command,
    sovereign_identity::handle_identity_command,
    update_cmd::handle_update_command,
};

pub fn run() -> veil_cfg::Result<()> {
    let cli = Cli::parse();
    let runtime = CliRuntime::new(cli.config.as_deref(), OutputFormat::from(cli.output_format));
    let context = runtime.context;

    match cli.command {
        Command::Config(args) => handle_config_command(context, args.command),
        Command::Key(args) => handle_key_command(context, args.command),
        Command::Node(args) => handle_node_command(context, args),
        Command::Listen(args) => handle_listen_command(context, args),
        Command::Peers(args) => handle_peers_command(context, args),
        Command::Sessions(args) => handle_sessions_command(context, args),
        Command::Debug(args) => handle_debug_command(cli.config.as_deref(), args.command),
        Command::Pex(args) => handle_pex_command(context, args),
        Command::Bootstrap(args) => handle_bootstrap_command(context, args),
        Command::Invite(args) => handle_invite_command(context, args),
        Command::Network(args) => handle_network_command(&mut { context }, args),
        Command::Update(args) => handle_update_command(context, args),
        Command::Mobile(args) => handle_mobile_command(context, args),
        Command::Identity(args) => {
            let mut io = StdCommandIo::new(OutputFormat::from(cli.output_format));
            handle_identity_command(&mut io, args.command)
        }
        Command::Service(args) => match args.command {
            ServiceCommand::Install { config } => {
                service::install(config.as_deref().or(cli.config.as_deref()))
            }
            ServiceCommand::Uninstall => service::uninstall(),
            ServiceCommand::Run => service::run(),
        },
    }
}
