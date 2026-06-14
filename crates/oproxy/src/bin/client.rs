//! `oproxy-client` — standalone proxy client binary.
//!
//! Connects to a local veil daemon's app socket, binds an endpoint
//! under the configured `app_name`, and runs one OR more inbound listeners
//! (SOCKS5 / HTTP / TProxy) forwarding traffic through veil to a
//! configured upstream `(server_node_id, server_app_name)` pair.
//!
//! Each connection is dispatched through the `[routing]` policy (veil
//! / direct / block + optional direct-fallback on veil failure).
//!
//! Usage:
//!   oproxy-client --config /etc/oproxy/client.toml

// oproxy-client depends on `veilclient::VeilClient`, which is
// itself `#[cfg(unix)]`-gated (Unix-domain socket IPC).  Wrap the
// entire bin content in a `#[cfg(unix)] mod imp` so cross-compile to
// x86_64-pc-windows-gnu doesn't trip on the unresolved `AppSender`
// import from oproxy::connector.  Windows stub main exits with error.
#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("oproxy-client is not supported on this platform (Unix-family only).");
    std::process::ExitCode::FAILURE
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    imp::main()
}

#[cfg(unix)]
mod imp {
    use std::path::PathBuf;
    use std::sync::Arc;

    use anyhow::{Context, Result};
    use clap::Parser;

    use veilclient::VeilClient;

    use oproxy::config::{
        ClientConfig, InboundConfig, ensure_inbound_bind_allowed, parse_node_id_hex,
    };
    use oproxy::inbound;
    use veil_cfg::build_tokio_runtime;

    #[derive(Parser, Debug)]
    #[command(
        version,
        about = "Veil-network proxy client (SOCKS5 / HTTP / TProxy → veil)"
    )]
    struct Args {
        /// Path to a TOML config file (see `crates/oproxy/README.md`).
        #[arg(long, value_name = "PATH", required_unless_present = "gen_config")]
        config: Option<PathBuf>,

        /// Print a commented default-config TOML template to stdout and exit.
        /// Operators run this once, redirect to a file, edit the placeholders
        /// (`server_node_id`, `[[inbound]]` listeners), then start with
        /// `--config <path>`.
        ///
        /// Example:
        ///   oproxy-client --gen-config > /etc/oproxy/client.toml
        #[arg(long, conflicts_with = "config")]
        gen_config: bool,
    }

    pub fn main() -> std::process::ExitCode {
        let args = Args::parse();
        if args.gen_config {
            use std::io::Write;
            let stdout = std::io::stdout();
            if let Err(e) = stdout
                .lock()
                .write_all(oproxy::config_template::CLIENT_DEFAULT_CONFIG.as_bytes())
            {
                eprintln!("oproxy-client: write default config: {e}");
                return std::process::ExitCode::FAILURE;
            }
            return std::process::ExitCode::SUCCESS;
        }
        let config_path = args
            .config
            .expect("clap should have required --config when --gen-config absent");

        // Audit batch 2026-05-24 (M6): warn if config file is loose-mode.
        oproxy::config::warn_loose_config_perms(&config_path);

        // Load config first so we can derive runtime + logging knobs from
        // it before building the tokio runtime.
        let raw = match std::fs::read_to_string(&config_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("oproxy-client: read {}: {e}", config_path.display());
                return std::process::ExitCode::FAILURE;
            }
        };
        let cfg: ClientConfig = match toml::from_str(&raw) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("oproxy-client: parse {}: {e}", config_path.display());
                return std::process::ExitCode::FAILURE;
            }
        };

        // Initialise logger from config; `RUST_LOG` env var still wins (per
        // env_logger's `from_env` semantics) — operators retain debug
        // ergonomics.  When `[logging] file` is set, route output to the
        // file instead of stderr.
        if let Err(e) = oproxy::init_oproxy_logger("oproxy-client", &cfg.logging) {
            eprintln!("oproxy-client: failed to init logger: {e}");
            return std::process::ExitCode::FAILURE;
        }

        // S2.B: load app-cert blob if configured.  Fail-fast if the
        // file can't be read — better than launching and silently sending
        // no preamble.
        let app_cert_blob: Option<Vec<u8>> = match &cfg.app_cert_path {
            Some(path) => match std::fs::read(path) {
                Ok(bytes) => {
                    log::info!(
                        "oproxy-client: loaded app-cert blob ({} B) from {}",
                        bytes.len(),
                        path.display()
                    );
                    Some(bytes)
                }
                Err(e) => {
                    eprintln!(
                        "oproxy-client: failed to read app_cert_path={}: {e}",
                        path.display()
                    );
                    return std::process::ExitCode::FAILURE;
                }
            },
            None => None,
        };
        oproxy::connector::set_app_cert_blob(app_cert_blob);

        // Build the tokio runtime from `[runtime]` + env overrides.
        let mut rt_cfg = cfg.runtime.clone();
        rt_cfg.apply_env_overrides("OPROXY");
        let rt = match build_tokio_runtime(&rt_cfg) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("oproxy-client: failed to build tokio runtime: {e}");
                return std::process::ExitCode::FAILURE;
            }
        };

        rt.block_on(async move {
            match run(cfg).await {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("oproxy-client: {e}");
                    std::process::ExitCode::FAILURE
                }
            }
        })
    }

    async fn run(cfg: ClientConfig) -> Result<()> {
        let server_node_id = parse_node_id_hex(&cfg.server_node_id)
            .map_err(|e| anyhow::anyhow!("server_node_id: {e}"))?;
        let server_app_id = veil_app::address::app_id(
            &server_node_id,
            oproxy::SERVER_NAMESPACE,
            &cfg.server_app_name,
        );

        log::info!(
            "oproxy-client: connecting to daemon socket {}",
            cfg.socket_path.display()
        );
        let client = VeilClient::connect(&cfg.socket_path)
            .await
            .with_context(|| format!("connect to veil daemon at {}", cfg.socket_path.display()))?;
        log::info!(
            "oproxy-client: binding local app endpoint (namespace={}, name={})",
            oproxy::CLIENT_NAMESPACE,
            oproxy::CLIENT_BIND_NAME,
        );
        let app = client
            .bind(oproxy::CLIENT_NAMESPACE, oproxy::CLIENT_BIND_NAME, 0)
            .await
            .context("bind local app endpoint")?;
        // Audit batch 2026-05-24 (M9): use `into_split()` to get an AppSender
        // that implements `&self`-only `open_stream`.  Previously wrapped in
        // `Arc<Mutex<AppHandle>>`, but `.lock().await` was held *through* the
        // `open_stream().await` call — a single hung veil-peer blocked
        // ALL other concurrent SOCKS5/HTTP connect attempts.  oproxy-client
        // never reads inbound messages on this endpoint (only opens streams),
        // so the receiver-half is dropped immediately.
        let (sender, _rx) = app.into_split();
        let app_sender = Arc::new(sender);

        if cfg.inbound.is_empty() {
            anyhow::bail!("no [[inbound]] sections configured — nothing to do");
        }

        // Audit cycle-3 (M2): fail fast BEFORE binding if an unauthenticated
        // SOCKS5/HTTP ingress would listen on a non-loopback address without
        // the operator explicitly accepting LAN exposure. Tproxy is gated by
        // the kernel/iptables and intentionally excluded.
        for ib in &cfg.inbound {
            if let InboundConfig::Socks5 { listen } | InboundConfig::Http { listen } = ib {
                ensure_inbound_bind_allowed(listen, cfg.allow_lan_inbound)?;
            }
        }

        let routing = Arc::new(cfg.routing.clone());
        log::info!(
            "oproxy-client: routing default={:?} fallback={:?} rules={}",
            routing.default,
            routing.fallback,
            routing.rules.len()
        );

        // Audit batch 2026-05-24 (M8): per-listener semaphore caps concurrent
        // sessions.  Each listener gets its OWN semaphore (not shared) — a
        // SOCKS5 flood does not starve the HTTP path.
        let limit_per_listener = cfg.limits.max_concurrent_per_listener;
        log::info!("oproxy-client: max_concurrent_per_listener={limit_per_listener}");

        let mut tasks = Vec::with_capacity(cfg.inbound.len());
        for inbound_cfg in cfg.inbound {
            let h = Arc::clone(&app_sender);
            let r = Arc::clone(&routing);
            let sem = Arc::new(tokio::sync::Semaphore::new(limit_per_listener));
            let task = match inbound_cfg {
                InboundConfig::Socks5 { listen } => tokio::spawn(async move {
                    if let Err(e) = inbound::socks5::run(
                        listen.clone(),
                        h,
                        server_node_id,
                        server_app_id,
                        r,
                        sem,
                    )
                    .await
                    {
                        log::error!("oproxy.socks5 listener {listen} exited: {e}");
                    }
                }),
                InboundConfig::Http { listen } => tokio::spawn(async move {
                    if let Err(e) =
                        inbound::http::run(listen.clone(), h, server_node_id, server_app_id, r, sem)
                            .await
                    {
                        log::error!("oproxy.http listener {listen} exited: {e}");
                    }
                }),
                InboundConfig::Tproxy { listen } => tokio::spawn(async move {
                    if let Err(e) = inbound::tproxy::run(
                        listen.clone(),
                        h,
                        server_node_id,
                        server_app_id,
                        r,
                        sem,
                    )
                    .await
                    {
                        log::error!("oproxy.tproxy listener {listen} exited: {e}");
                    }
                }),
            };
            tasks.push(task);
        }

        // Wait for shutdown signal or task panic.
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                log::info!("oproxy-client: SIGINT received, shutting down");
            }
            _ = futures_first(tasks) => {
                log::error!("oproxy-client: an inbound task exited unexpectedly");
            }
        }
        Ok(())
    }

    /// Wait for the first task in the vector to complete.  Simple
    /// poll-based implementation — avoids a `futures` crate dependency
    /// just for this one-shot select.
    async fn futures_first(mut tasks: Vec<tokio::task::JoinHandle<()>>) {
        if tasks.is_empty() {
            std::future::pending::<()>().await;
            return;
        }
        loop {
            if let Some(idx) = tasks.iter().position(|t| t.is_finished()) {
                let _ = tasks.swap_remove(idx).await;
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }
} // end mod imp (cfg unix)
