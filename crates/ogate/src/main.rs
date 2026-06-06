use clap::Parser;
use ogate::cli::{Cli, Command, run};
use ogate::config::OgateConfig;
use veil_cfg::build_tokio_runtime;

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();

    // Load config eagerly for commands that have one so we can use
    // its [runtime] + [logging] sections.  Commands without a config
    // (`reload`, `app-id`) fall back to defaults.
    let cfg_for_runtime: Option<OgateConfig> = match &cli.command {
        Command::Up { config } | Command::Show { config } => match OgateConfig::from_path(config) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("ogate: failed to load config {}: {e}", config.display());
                return std::process::ExitCode::FAILURE;
            }
        },
        Command::Reload { .. } | Command::AppId { .. } | Command::GenConfig { .. } => None,
    };

    // Build the tokio runtime:
    //   1. Start from config's `[runtime]` section (or defaults if absent /
    //      no config command).
    //   2. Layer env-var overrides (OGATE_RUNTIME / OGATE_WORKERS /
    //      OGATE_MAX_BLOCKING_THREADS) on top for backward-compat with
    //      pre-runtime-section systemd units.
    let mut rt_cfg = cfg_for_runtime
        .as_ref()
        .map(|c| c.runtime.clone())
        .unwrap_or_default();
    rt_cfg.apply_env_overrides("OGATE");

    let rt = match build_tokio_runtime(&rt_cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ogate: failed to build tokio runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // Pull logging config out of the loaded config (or defaults).
    let log_cfg = cfg_for_runtime
        .as_ref()
        .map(|c| c.logging.clone())
        .unwrap_or_default();
    // `_log_guard` MUST live until main returns — drop flushes the
    // non-blocking writer's queued lines.
    let _log_guard = install_tracing(cli.verbose, &log_cfg);

    rt.block_on(async {
        match run(cli, cfg_for_runtime).await {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("ogate: {e}");
                std::process::ExitCode::FAILURE
            }
        }
    })
}

/// Initialise `tracing-subscriber` from config + CLI verbosity.
///
/// Precedence (high → low):
///   1. `RUST_LOG` env var (if set, always wins)
///   2. CLI `-v` / `-vv` flags (override config when > 0)
///   3. config's `[logging] level`
///   4. baked-in default "info"
///
/// Output destination:
///   * `[logging] file = "/path/to/log"` ⇒ append to the file
///   * otherwise ⇒ stderr
///
/// Returns the `_guard` from the non-blocking writer (if a file is configured),
/// which must stay alive for the duration of the process — drop flushes
/// the queued log lines.  Caller stores this in main's stack frame.
fn install_tracing(
    verbose: u8,
    log: &ogate::config::LoggingConfig,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_subscriber::EnvFilter;

    let cli_level = match verbose {
        0 => None,
        1 => Some("debug"),
        _ => Some("trace"),
    };
    let level = cli_level.unwrap_or_else(|| log.level.as_filter_str());

    // Shortcut: level=off + no env override = don't even register
    // a subscriber.  Saves the per-event filter overhead and leaves
    // stderr completely silent (operators that pipe stderr to a
    // log file expect zero lines when logging is disabled).
    if level == "off" && std::env::var("RUST_LOG").is_err() {
        return None;
    }

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

    // Choose writer: file (non-blocking, append) or stderr.
    let (writer, guard): (
        tracing_appender::non_blocking::NonBlocking,
        Option<tracing_appender::non_blocking::WorkerGuard>,
    ) = if let Some(path) = &log.file {
        // Audit batch 2026-05-24 (M5): reject `..` path traversal.  An
        // operator with writable config but without daemon-user privilege
        // could otherwise redirect logs to /etc/cron.d/... or similar.
        for c in path.components() {
            if matches!(c, std::path::Component::ParentDir) {
                eprintln!(
                    "ogate: [logging] file = {} contains `..` — refusing to open (path-traversal guard)",
                    path.display()
                );
                return None;
            }
        }
        // Open in append mode; `tracing_appender::rolling::never`
        // gives us a plain non-rolling appender.  Parent dir must
        // exist (we don't auto-create — operator's responsibility).
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        let filename = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "ogate.log".to_string());
        let appender = tracing_appender::rolling::never(parent, &filename);
        let (nb, g) = tracing_appender::non_blocking(appender);
        (nb, Some(g))
    } else {
        let (nb, g) = tracing_appender::non_blocking(std::io::stderr());
        (nb, Some(g))
    };

    match log.format {
        ogate::config::LogFormat::Json => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .with_writer(writer)
                .json()
                .try_init();
        }
        ogate::config::LogFormat::Text => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .with_writer(writer)
                .try_init();
        }
    }
    guard
}
