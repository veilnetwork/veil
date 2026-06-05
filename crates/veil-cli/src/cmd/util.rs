//! Small helpers shared across the `cmd` subcommands.
//!
//! Before consolidation each `*_cmd.rs` module carried its own copies of
//! `map_node_error`, `build_runtime`, and the `setsid` daemon-spawn
//! `pre_exec` block. Keeping them in one place avoids further drift.

use veil_cfg::{self, ConfigError};
use veil_node_runtime as node;

/// Convert a [`node::NodeError`] into a [`ConfigError`] suitable for
/// propagating up through the CLI adapters.
pub(super) fn map_node_error(err: node::NodeError) -> ConfigError {
    match err {
        node::NodeError::Io(err) => ConfigError::Io(err),
        other => ConfigError::ValidationFailed(other.to_string()),
    }
}

/// Build the default multi-thread Tokio runtime used by CLI adapters
/// that need to drive async admin / IPC calls.
pub(super) fn build_runtime() -> veil_cfg::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(ConfigError::Io)
}

/// Resolve a CLI secret (password / private key) from, in priority order:
///
/// 1. `file` — `--*-file <path>`; the sentinel path `-` reads stdin. The
///    contents are trimmed (leading + trailing whitespace) to mirror the
///    sovereign `--password-file` handling, and an empty/whitespace-only
///    source is rejected.
/// 2. `value` — the deprecated argv form (`--password` / `--private-key`).
///    Still honoured for backwards compatibility, but emits a one-line
///    deprecation warning to stderr because argv secrets leak into process
///    listings (`ps` / `/proc/<pid>/cmdline`) and shell history.
///
/// Returns `Ok(None)` when neither source is provided so callers can keep
/// their existing "fall back to config" behaviour.
pub(super) fn resolve_secret_arg(
    value: Option<String>,
    file: Option<&std::path::Path>,
    argv_flag: &str,
    file_flag: &str,
) -> veil_cfg::Result<Option<String>> {
    if let Some(path) = file {
        let raw = if path.as_os_str() == "-" {
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf).map_err(|e| {
                ConfigError::ValidationFailed(format!("read {file_flag} stdin: {e}"))
            })?;
            buf
        } else {
            std::fs::read_to_string(path).map_err(|e| {
                ConfigError::ValidationFailed(format!("read {} ({file_flag}): {e}", path.display()))
            })?
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ConfigError::ValidationFailed(format!(
                "{file_flag} source is empty or contains only whitespace"
            )));
        }
        return Ok(Some(trimmed.to_owned()));
    }
    if let Some(secret) = value {
        eprintln!(
            "warning: passing a secret via {argv_flag} exposes it in process listings \
             (ps / procfs) and shell history; prefer {file_flag} <path> (or '-' for stdin)"
        );
        return Ok(Some(secret));
    }
    Ok(None)
}
