//! `APP_BIND` handler — register а new (namespace, name) → endpoint mapping.
//!
//! Handles malformed-payload protection (cap-counted decode failures),
//! per-connection endpoint quota, sovereign vs ephemeral `app_id` derivation,
//! per-app socket marker creation, и success/error reply framing.

use std::path::{Path, PathBuf};

use veil_app::registry::AppEndpointRegistry;
use veil_proto::{
    AppBindErrPayload, AppBindOkPayload, AppBindPayload, FrameFamily, LocalAppMsg, ipc_bind_err,
};

use crate::frame_io::write_frame_wh;
use crate::server::IpcClientState;
use crate::transport::IpcWriteHalf;

pub(crate) async fn handle_bind(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    client_state: &mut IpcClientState,
    app_registry: &AppEndpointRegistry,
    node_id: &[u8; 32],
    client_token: &[u8; 16],
    app_socket_dir: Option<&Path>,
) -> std::io::Result<()> {
    let bind = match AppBindPayload::decode(body) {
        Ok(b) => b,
        Err(_) => {
            // Cap bind decode-failures per IPC client — а buggy or hostile
            // local app should not be able к spam unbounded malformed
            // APP_BIND frames.
            client_state.record_bind_decode_failure();
            let err = AppBindErrPayload {
                error_code: ipc_bind_err::INVALID_REQUEST,
                detail: b"malformed APP_BIND payload".to_vec(),
            };
            write_frame_wh(
                wh,
                FrameFamily::LocalApp as u8,
                LocalAppMsg::AppBindErr as u16,
                &err.encode(),
            )
            .await?;
            if client_state.bind_decode_failures() >= veil_proto::budget::MAX_BIND_DECODE_FAILURES {
                return Err(std::io::Error::other(format!(
                    "IPC client exceeded MAX_BIND_DECODE_FAILURES ({}) — closing connection",
                    veil_proto::budget::MAX_BIND_DECODE_FAILURES,
                )));
            }
            return Ok(());
        }
    };

    if bind.namespace.is_empty() || bind.name.is_empty() {
        let err = AppBindErrPayload {
            error_code: ipc_bind_err::INVALID_REQUEST,
            detail: b"namespace and name must not be empty".to_vec(),
        };
        return write_frame_wh(
            wh,
            FrameFamily::LocalApp as u8,
            LocalAppMsg::AppBindErr as u16,
            &err.encode(),
        )
        .await;
    }

    // Cap endpoints per IPC client к prevent local resource exhaustion.
    if client_state.endpoint_count() >= veil_proto::budget::MAX_IPC_ENDPOINTS_PER_CLIENT {
        let err = AppBindErrPayload {
            error_code: ipc_bind_err::RESOURCE_LIMIT,
            detail: format!(
                "endpoint limit ({}) reached for this connection",
                veil_proto::budget::MAX_IPC_ENDPOINTS_PER_CLIENT,
            )
            .into_bytes(),
        };
        return write_frame_wh(
            wh,
            FrameFamily::LocalApp as u8,
            LocalAppMsg::AppBindErr as u16,
            &err.encode(),
        )
        .await;
    }

    let (namespace, name) = match (
        std::str::from_utf8(&bind.namespace),
        std::str::from_utf8(&bind.name),
    ) {
        (Ok(ns), Ok(n)) => (ns, n),
        _ => {
            let err = AppBindErrPayload {
                error_code: ipc_bind_err::INVALID_REQUEST,
                detail: b"namespace and name must be valid UTF-8".to_vec(),
            };
            return write_frame_wh(
                wh,
                FrameFamily::LocalApp as u8,
                LocalAppMsg::AppBindErr as u16,
                &err.encode(),
            )
            .await;
        }
    };
    let ephemeral = bind.flags & veil_proto::ipc::ipc_bind_flags::EPHEMERAL != 0;
    let app_id = if ephemeral {
        veil_app::address::ephemeral_app_id(node_id, client_token, namespace, name)
    } else {
        veil_app::address::app_id(node_id, namespace, name)
    };

    // Phase E22 (2026-05-22): bumped от 64 к 4096 для match `[session]
    // tx_queue_depth` default sized для 2 Gbps per peer baseline.  At
    // 64 the receiver-side `app_msg_channel_full_total` climbed к 9 K
    // drops/12 s under iperf load through ogate, capping throughput at
    // ~100 Mbps despite all other limits unblocked.
    match app_registry.try_register(app_id, bind.endpoint_id, 4096) {
        Ok((handle, rx)) => {
            // Create per-app socket marker в PerApp mode.
            let socket_path = if !ephemeral {
                app_socket_dir.map(|dir| build_per_app_socket(dir, &app_id))
            } else {
                None
            };
            client_state.add_endpoint(handle, rx, socket_path);
            let ok = AppBindOkPayload {
                app_id,
                endpoint_id: bind.endpoint_id,
            };
            write_frame_wh(
                wh,
                FrameFamily::LocalApp as u8,
                LocalAppMsg::AppBindOk as u16,
                &ok.encode(),
            )
            .await
        }
        Err(()) => {
            let err = AppBindErrPayload {
                error_code: ipc_bind_err::ALREADY_BOUND,
                detail: format!("endpoint {} is already bound", bind.endpoint_id).into_bytes(),
            };
            write_frame_wh(
                wh,
                FrameFamily::LocalApp as u8,
                LocalAppMsg::AppBindErr as u16,
                &err.encode(),
            )
            .await
        }
    }
}

/// Build the per-app socket node at `{dir}/{hex(app_id)}.sock` so other
/// processes can probe ownership (Unix listener bind с 0o600 perms,
/// dropped immediately as the daemon never serves on it; the node stays
/// as an ownership marker until unbind).  On non-Unix platforms an empty
/// marker file is created instead — filesystem ACLs still apply.
fn build_per_app_socket(dir: &Path, app_id: &[u8; 32]) -> PathBuf {
    let hex_id: String = app_id.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    });
    let path = dir.join(format!("{hex_id}.sock"));
    let _ = std::fs::remove_file(&path);
    #[cfg(unix)]
    {
        if let Ok(_listener) = std::os::unix::net::UnixListener::bind(&path) {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&path, perms);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = std::fs::File::create(&path);
    }
    path
}
