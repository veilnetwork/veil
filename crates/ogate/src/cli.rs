//! CLI subcommands for the `ogate` binary.
//!
//! Subcommands:
//! * `up    --config <path>` — bring up the TUN bridge and run until SIGINT/SIGTERM.
//! * `show  --config <path>` — print resolved config (computed app_ids, peer table)
//!   without opening any device. Useful for debugging.
//! * `app-id --network <net> [--app <app>] --node-id <hex>` —
//!   compute one peer's app_id without touching the daemon
//!   (handy when bootstrapping config files).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::app_id::{derive_app_id, namespace_for};
use crate::config::OgateConfig;

#[derive(Debug, Parser)]
#[command(name = "ogate", version, about = "Veil-network TUN bridge")]
pub struct Cli {
    /// Increase verbosity (repeat for more: -v debug, -vv trace).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Bring the bridge up. Sends SIGHUP to a running instance to
    /// reload its peer table without restart.
    Up {
        /// Path to ogate.toml.
        #[arg(short, long, default_value = "/etc/ogate/ogate.toml")]
        config: PathBuf,
    },

    /// Print resolved config without opening any TUN / IPC resource.
    Show {
        #[arg(short, long, default_value = "/etc/ogate/ogate.toml")]
        config: PathBuf,
    },

    /// Trigger a hot reload of the peer table in the running ogate
    /// instance. Implemented as `kill -HUP <pid>`; you must pass the
    /// PID of the running daemon (e.g. `pidof ogate`, the value of
    /// `ogate.pid` if you maintain one, or systemd's MainPID).
    Reload {
        /// Process id of the running `ogate up` instance.
        #[arg(long)]
        pid: i32,
    },

    /// Compute an app_id for the given peer node_id + network + app.
    AppId {
        /// Network name (matches `network` in ogate.toml).
        #[arg(long)]
        network: String,
        /// App name within the network.
        #[arg(long, default_value = "ogate")]
        app: String,
        /// 64-char hex peer node_id.
        #[arg(long)]
        node_id: String,
    },

    /// Emit а commented default-config TOML template к stdout or к the
    /// file given by `-o`.  Operators fill in the placeholders (network
    /// name, peer node_ids, virtual IPs) and `ogate up --config <path>`.
    ///
    /// Examples:
    ///   ogate gen-config                                # to stdout
    ///   ogate gen-config -o /etc/ogate/ogate.toml       # to file
    GenConfig {
        /// Optional output path.  When omitted, the template is written
        /// к stdout (so you can pipe it: `ogate gen-config | less`).
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
    },
}

/// Execute the parsed CLI.
///
/// `preloaded_cfg` carries the OgateConfig already parsed by `main` for
/// commands that need one (`Up`/`Show`).  Other commands ignore it.
/// Reusing the parse avoids reading the file twice (once for tokio
/// runtime knobs in main, once here).
pub async fn run(
    cli: Cli,
    preloaded_cfg: Option<OgateConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match cli.command {
        Command::Up { config } => {
            let cfg =
                preloaded_cfg.ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
                    "internal: Up without preloaded config".into()
                })?;
            tracing::info!(network = %cfg.network, app = %cfg.app, "bringing ogate up");
            #[cfg(unix)]
            {
                crate::bridge::run(config, cfg).await?;
            }
            #[cfg(not(unix))]
            {
                let _ = (config, cfg);
                return Err("ogate up is not supported on this platform (Unix-family only)".into());
            }
        }
        Command::Show { .. } => {
            let cfg =
                preloaded_cfg.ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
                    "internal: Show without preloaded config".into()
                })?;
            show(&cfg);
        }
        Command::Reload { pid } => {
            send_sighup(pid)?;
            println!("sent SIGHUP to pid {pid}");
        }
        Command::AppId {
            network,
            app,
            node_id,
        } => {
            let nid = crate::routing::decode_node_id(&node_id)
                .ok_or_else(|| "node_id must be 64-char hex".to_owned())?;
            let app_id = derive_app_id(&nid, &network, &app);
            println!(
                "namespace = {}\nname      = {}\napp_id    = {}",
                namespace_for(&network),
                app,
                hex::encode(app_id),
            );
        }
        Command::GenConfig { output } => {
            let template = crate::config_template::OGATE_DEFAULT_CONFIG;
            match output {
                Some(path) => {
                    if path.exists() {
                        return Err(format!(
                            "refusing к overwrite existing file {} (delete it first if intentional)",
                            path.display()
                        )
                        .into());
                    }
                    if let Some(parent) = path.parent()
                        && !parent.as_os_str().is_empty()
                    {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&path, template)?;
                    eprintln!("wrote default ogate config к {}", path.display());
                    eprintln!("edit it (network, peers, local_addr_v4) then:");
                    eprintln!("    ogate up --config {}", path.display());
                }
                None => {
                    use std::io::Write;
                    let stdout = std::io::stdout();
                    stdout.lock().write_all(template.as_bytes())?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn send_sighup(pid: i32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Single libc call — no point pulling in `nix` just for this on
    // non-FreeBSD targets where it would otherwise not be a dependency.
    // SAFETY: kill is a thread-safe libc call; pid is a plain i32.
    let rc = unsafe { libc_kill(pid, SIGHUP) };
    if rc != 0 {
        return Err(format!(
            "kill({pid}, SIGHUP) failed: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    Ok(())
}

#[cfg(not(unix))]
fn send_sighup(_pid: i32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Err(
        "SIGHUP reload is not supported on this platform; restart ogate to apply config changes"
            .into(),
    )
}

#[cfg(unix)]
const SIGHUP: i32 = 1;

#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

fn show(cfg: &OgateConfig) {
    println!("network    : {}", cfg.network);
    println!("app        : {}", cfg.app);
    println!("namespace  : {}", namespace_for(&cfg.network));
    println!("mode       : {:?}", cfg.mode);
    println!("socket     : {}", cfg.socket_path.display());
    println!("iface      : {} (MTU {})", cfg.iface_name, cfg.mtu);
    if let Some(v4) = cfg.local_addr_v4 {
        println!("local v4   : {}/{}", v4, cfg.prefix_v4);
    }
    if let Some(v6) = cfg.local_addr_v6 {
        println!("local v6   : {}/{}", v6, cfg.prefix_v6);
    }
    println!("endpoint   : {}", cfg.endpoint_id);
    println!("peers      : {}", cfg.peers.len());
    for (i, p) in cfg.peers.iter().enumerate() {
        let name = p.name.as_deref().unwrap_or("");
        println!(
            "  [{i}] node_id={} v4={:?} v6={:?} {}",
            p.node_id, p.addr_v4, p.addr_v6, name
        );
        if let Some(nid) = crate::routing::decode_node_id(&p.node_id) {
            let aid = derive_app_id(&nid, &cfg.network, &cfg.app);
            println!("       app_id={}", hex::encode(aid));
        }
    }
}

// Tracing initialisation moved к `main.rs::install_tracing` so it can
// honour the config's `[logging]` section.  CLI verbosity flags
// continue к override the configured level when > 0.
