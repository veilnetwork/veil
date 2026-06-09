//! IPC endpoint path resolution.
//!
//! Resolves the operator's `[ipc]` config to a concrete listener backend
//! (`IpcEndpoint`) and computes the anchor path that `veil-cli` /
//! `veilclient` use to find the running daemon.  All public symbols
//! here mirror the admin-endpoint contract in `node/admin.rs` so the two
//! discovery channels share parsing rules.

use std::path::{Path, PathBuf};

/// Default IPC socket path under the user's veil data directory.
pub fn default_ipc_socket_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
    PathBuf::from(home).join(".veil").join("app.sock")
}

/// Resolved IPC server backend.  Mirrors `AdminEndpoint` in `node/admin.rs` —
/// same URI parsing + sidecar pattern so app clients can discover the
/// server with one cross-platform code path.
#[derive(Debug, Clone)]
pub enum IpcEndpoint {
    /// Unix domain socket at `path`. Default on Linux/macOS.
    Unix(PathBuf),
    /// TCP-loopback at `bind_addr`; `runtime_dir` holds `ipc.port` + `ipc.token`
    /// sidecars so clients can discover the listener and authenticate.
    Tcp {
        bind_addr: std::net::SocketAddr,
        runtime_dir: PathBuf,
    },
    /// Windows NamedPipe at the given pipe name (full `\\.\pipe\xxx` form).
    /// `runtime_dir` holds `ipc.pipe` + `ipc.token`.
    NamedPipe {
        pipe_name: String,
        runtime_dir: PathBuf,
    },
}

/// Sidecar filenames written next to a TCP IPC anchor (mirrors the admin
/// `admin.port` / `admin.token` convention).
pub const IPC_PORT_FILENAME: &str = "ipc.port";
pub const IPC_TOKEN_FILENAME: &str = "ipc.token";
pub const IPC_ANCHOR_FILENAME: &str = "ipc.anchor";
/// NamedPipe sidecar filename — UTF-8 file containing the Windows pipe
/// name that clients should open.
#[cfg(windows)]
pub const IPC_PIPE_FILENAME: &str = "ipc.pipe";

/// Errors surfaced by [`resolve_ipc_endpoint`] / [`ipc_anchor_path`].
///
/// Decoupled from veilcore's error tree (`NodeError`) so this crate
/// doesn't have to depend on it.  Production runtime adapter wraps this
/// back into `NodeError::Config(ConfigError::ValidationFailed(_))`.
#[derive(Debug, thiserror::Error)]
pub enum IpcEndpointError {
    /// The configured `ipc.socket_uri` failed validation.  The contained
    /// string is the human-readable explanation.
    #[error("{0}")]
    Validation(String),
}

/// Resolve the IPC endpoint from `[ipc]` config.  Precedence:
/// 1. `socket_uri` (explicit URI form, supports both backends).
/// 2. `socket_path` (Unix-only, backward compat).
/// 3. Default Unix path under the veil home dir.
///
/// `default_runtime_dir` is the fallback used when neither the URI's
/// `?runtime_dir=` query nor `config_dir` is set.  Production runtime
/// passes the value of `cfg::runtime_veil_dir` here.
///
/// Returns an error if the URI is malformed, references a non-loopback
/// host, or specifies an unknown scheme.
pub fn resolve_ipc_endpoint(
    cfg: &veil_types::IpcConfig,
    config_dir: Option<&Path>,
    default_runtime_dir: &Path,
) -> Result<IpcEndpoint, IpcEndpointError> {
    if let Some(uri) = cfg.socket_uri.as_deref() {
        let (uri_body, query_runtime_dir) = split_ipc_uri_query(uri)?;

        // pipe:// handled here — `TransportUri` doesn't model Windows
        // NamedPipes.  Form: `pipe://LEAF[?runtime_dir=...]`.
        if let Some(rest) = uri_body.strip_prefix("pipe://") {
            let leaf = rest.split('/').next().unwrap_or("");
            if leaf.is_empty() || leaf.contains(':') || leaf.contains('\\') {
                return Err(IpcEndpointError::Validation(format!(
                    "ipc.socket_uri: pipe:// leaf must be a simple name (got: {uri})"
                )));
            }
            let pipe_name = format!(r"\\.\pipe\{leaf}");
            let runtime_dir = query_runtime_dir
                .map(PathBuf::from)
                .or_else(|| config_dir.map(|p| p.to_path_buf()))
                .unwrap_or_else(|| default_runtime_dir.to_path_buf());
            return Ok(IpcEndpoint::NamedPipe {
                pipe_name,
                runtime_dir,
            });
        }

        let parsed = veil_transport::TransportUri::parse(uri_body)
            .map_err(|e| IpcEndpointError::Validation(format!("ipc.socket_uri: {e}")))?;
        return match parsed {
            veil_transport::TransportUri::Unix { path } => Ok(IpcEndpoint::Unix(path)),
            veil_transport::TransportUri::Tcp { host, port } => {
                if host != "127.0.0.1" && host != "::1" && host != "localhost" {
                    return Err(IpcEndpointError::Validation(format!(
                        "ipc.socket_uri: TCP host must be loopback, got `{host}`"
                    )));
                }
                // `SocketAddr::parse` does not resolve hostnames and requires
                // IPv6 literals in bracket form, so normalize the accepted
                // loopback aliases (only loopback reaches here — checked above):
                // `localhost`/`127.0.0.1` → `127.0.0.1:port`, `::1` → `[::1]:port`
                // (F11: the bare `::1:port` the old code built failed to parse).
                let hostport = match host.as_str() {
                    "::1" => format!("[::1]:{port}"),
                    "localhost" | "127.0.0.1" => format!("127.0.0.1:{port}"),
                    other => format!("{other}:{port}"),
                };
                let bind_addr: std::net::SocketAddr = hostport.parse().map_err(|e| {
                    IpcEndpointError::Validation(format!(
                        "ipc.socket_uri: invalid tcp address {host}:{port} — {e}"
                    ))
                })?;
                let runtime_dir = query_runtime_dir
                    .map(PathBuf::from)
                    .or_else(|| config_dir.map(|p| p.to_path_buf()))
                    .unwrap_or_else(|| default_runtime_dir.to_path_buf());
                Ok(IpcEndpoint::Tcp {
                    bind_addr,
                    runtime_dir,
                })
            }
            _ => Err(IpcEndpointError::Validation(format!(
                "ipc.socket_uri: unsupported scheme in `{uri}` (use unix:// or tcp://)"
            ))),
        };
    }
    Ok(IpcEndpoint::Unix(default_ipc_socket_path()))
}

/// Anchor path — what `veil-cli` and `veilclient` resolve to find the
/// IPC server.  For Unix it's the socket file; for TCP / NamedPipe it's a
/// synthetic path under `runtime_dir` whose siblings (`ipc.port` /
/// `ipc.token` / `ipc.pipe`) authenticate the discovery.  See
/// [`resolve_ipc_endpoint`] for `config_dir` semantics.
pub fn ipc_anchor_path(
    cfg: &veil_types::IpcConfig,
    config_dir: Option<&Path>,
    default_runtime_dir: &Path,
) -> Result<PathBuf, IpcEndpointError> {
    Ok(
        match resolve_ipc_endpoint(cfg, config_dir, default_runtime_dir)? {
            IpcEndpoint::Unix(p) => p,
            IpcEndpoint::Tcp { runtime_dir, .. } => runtime_dir.join(IPC_ANCHOR_FILENAME),
            IpcEndpoint::NamedPipe { runtime_dir, .. } => runtime_dir.join(IPC_ANCHOR_FILENAME),
        },
    )
}

/// Split an IPC URI into `(body, runtime_dir?)`.  Extracts the
/// `?runtime_dir=` query parameter since `TransportUri::parse` doesn't
/// model query strings yet.
fn split_ipc_uri_query(uri: &str) -> Result<(&str, Option<String>), IpcEndpointError> {
    let Some(q) = uri.find('?') else {
        return Ok((uri, None));
    };
    let (body, query) = uri.split_at(q);
    let query = &query[1..];
    let mut runtime_dir = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some(rest) = pair.strip_prefix("runtime_dir=") {
            runtime_dir = Some(rest.to_owned());
        } else {
            // Reject unknown query keys so a typo (e.g. `runtime_dri=`) fails
            // loudly instead of silently using the default runtime dir.
            let key = pair.split('=').next().unwrap_or(pair);
            return Err(IpcEndpointError::Validation(format!(
                "ipc.socket_uri: unknown query parameter `{key}` (only `runtime_dir` is supported)"
            )));
        }
    }
    Ok((body, runtime_dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_ipc_uri_query_extracts_and_rejects() {
        // No query → body unchanged.
        assert_eq!(split_ipc_uri_query("tcp://[::1]:9").unwrap(), ("tcp://[::1]:9", None));
        // runtime_dir extracted.
        let (body, rd) = split_ipc_uri_query("tcp://[::1]:9?runtime_dir=/x").unwrap();
        assert_eq!(body, "tcp://[::1]:9");
        assert_eq!(rd.as_deref(), Some("/x"));
        // Unknown key (typo) is rejected, not silently dropped.
        assert!(split_ipc_uri_query("tcp://[::1]:9?runtime_dri=/x").is_err());
    }
}
