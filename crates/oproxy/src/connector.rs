//! Veil-side glue: open а stream к the upstream server и bridge it.
//!
//! Used by the client binary.  Wraps an [`veilclient::AppSender`] —
//! caller is expected к keep one `AppSender` alive for the daemon's
//! lifetime и dispatch every inbound connection через [`open_stream`].
//!
//! Audit batch 2026-05-24 (M9): switched от `Arc<Mutex<AppHandle>>` к
//! `Arc<AppSender>`.  `AppSender::open_stream` takes `&self`, so
//! multiple concurrent connects share the binding без serialisation —
//! а stalled veil-peer no longer blocks every other proxy attempt.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, copy};
use tokio::net::TcpStream;

use veilclient::AppSender;

use crate::wire::{ConnectStatus, encode_app_cert_preamble, encode_connect_header, read_status};

/// Initial receive-window passed к `AppSender::open_stream`.  64 KiB
/// matches typical TCP defaults и keeps the veil stream от
/// blocking under bursty payloads.
const INITIAL_WINDOW: u32 = 64 * 1024;

/// S2.B: process-wide cert blob loaded once at oproxy-client startup
/// (от `ClientConfig.app_cert_path`).  Set via [`set_app_cert_blob`].
/// When `Some(blob)`, every outbound veil stream emits an
/// app-cert preamble before the connect-header — the server verifies
/// it against its own configured trusted owner pubkey.
///
/// Using а `OnceLock` rather than threading the blob через every
/// connector function (3 inbound handlers × 2 bridge_via_routing
/// variants × 4 inner dispatch fns) keeps the diff bounded.  The
/// blob is а process-global anyway: one client identity → one cert.
static APP_CERT_BLOB: std::sync::OnceLock<Option<Vec<u8>>> = std::sync::OnceLock::new();

/// Initialise the process-wide cert blob.  Call once at main(),
/// before spawning inbound handlers.  Subsequent calls are no-ops
/// (OnceLock semantics).
pub fn set_app_cert_blob(blob: Option<Vec<u8>>) {
    let _ = APP_CERT_BLOB.set(blob);
}

/// Internal helper: produce the bytes що should precede the connect
/// header.  Returns empty slice когда no cert configured.
fn app_cert_preamble_bytes() -> Vec<u8> {
    match APP_CERT_BLOB.get() {
        Some(Some(blob)) => encode_app_cert_preamble(blob).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// Try к open an veil byte-stream к the server, send the connect
/// header, read the status reply, и bridge bytes.  Returns `Ok(())`
/// после а normal half-close или `Err((inbound, err))` если *setup*
/// failed — the caller can recover by falling back к а direct connect.
///
/// Setup failure recovery is а one-shot opportunity: the inbound
/// TcpStream is returned untouched (no bytes consumed) only while we
/// are still in phases 1-3 (open / write header / read status).  Once
/// phase 4 (bridging) starts, payload bytes are flowing on both
/// directions и fallback is impossible — failures from там drop
/// straight к `Ok(())` since both halves close cleanly.
pub async fn try_veil_setup_and_bridge(
    app_handle: Arc<AppSender>,
    server_node_id: [u8; 32],
    server_app_id: [u8; 32],
    inbound: TcpStream,
    host: String,
    port: u16,
) -> std::result::Result<(), (TcpStream, anyhow::Error)> {
    use tokio::io::AsyncWriteExt;

    // Phase 1 — open the veil stream.  Audit batch 2026-05-24 (M9):
    // bounded в `OPEN_STREAM_TIMEOUT`; previously а stalled daemon-side
    // open could hold the inbound task indefinitely.
    let stream = match tokio::time::timeout(
        crate::timeouts::OPEN_STREAM_TIMEOUT,
        app_handle.open_stream(server_node_id, server_app_id, 0, INITIAL_WINDOW),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err((
                inbound,
                anyhow!(
                    "open veil stream к {:02x}{:02x}... failed: {e}",
                    server_node_id[0],
                    server_node_id[1]
                ),
            ));
        }
        Err(_) => {
            return Err((
                inbound,
                anyhow!(
                    "open veil stream к {:02x}{:02x}... timed out ({:?})",
                    server_node_id[0],
                    server_node_id[1],
                    crate::timeouts::OPEN_STREAM_TIMEOUT
                ),
            ));
        }
    };

    // Phase 2 — write the connect header.  S2.B: precede it с the
    // app-cert preamble когда configured.  Single combined `write_all`
    // keeps the wire ordered и avoids а partial-write race где the
    // server sees the connect header without the preceding cert.
    let mut stream = stream;
    let mut header_with_preamble = app_cert_preamble_bytes();
    let header = match encode_connect_header(&host, port) {
        Some(h) => h,
        None => {
            return Err((
                inbound,
                anyhow!("host `{host}` invalid (empty or > 255 bytes)"),
            ));
        }
    };
    header_with_preamble.extend_from_slice(&header);
    if let Err(e) = stream.write_all(&header_with_preamble).await {
        return Err((inbound, anyhow!("write connect header: {e}")));
    }

    // Phase 3 — wait для status reply.  Audit batch 2026-05-24: bound
    // на а slow / unresponsive veil-server.  Without this, а stalled
    // server holds the inbound task forever.
    let status = match tokio::time::timeout(
        crate::timeouts::VEIL_STATUS_TIMEOUT,
        read_status(&mut stream),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err((inbound, anyhow!("read status reply: {e}"))),
        Err(_) => {
            return Err((
                inbound,
                anyhow!(
                    "veil status reply timeout ({:?})",
                    crate::timeouts::VEIL_STATUS_TIMEOUT
                ),
            ));
        }
    };
    if status != ConnectStatus::Ok {
        return Err((
            inbound,
            anyhow!("server rejected connect to {host}:{port}: {status:?}"),
        ));
    }

    // Phase 4 — point-of-no-return: bridge bidirectionally.
    let (mut in_r, mut in_w) = inbound.into_split();
    let (mut out_r, mut out_w) = tokio::io::split(stream);
    let up = async {
        let _ = copy(&mut in_r, &mut out_w).await;
        let _ = out_w.shutdown().await;
    };
    let down = async {
        let _ = copy(&mut out_r, &mut in_w).await;
        let _ = in_w.shutdown().await;
    };
    tokio::join!(up, down);
    Ok(())
}

/// Backward-compat shim — the original API used before routing modes
/// were added.  Pure veil path с no fallback.  Direct / fallback
/// callers should use [`bridge_via_routing`] instead.
pub async fn open_stream_and_bridge(
    app_handle: Arc<AppSender>,
    server_node_id: [u8; 32],
    server_app_id: [u8; 32],
    inbound: TcpStream,
    host: String,
    port: u16,
) -> Result<()> {
    try_veil_setup_and_bridge(
        app_handle,
        server_node_id,
        server_app_id,
        inbound,
        host,
        port,
    )
    .await
    .map_err(|(_inbound, e)| e)
}

/// Variant of [`try_veil_setup_and_bridge`] that injects а pre-built
/// prelude (rewritten HTTP request line + headers, etc.) после the
/// connect-header handshake but BEFORE bridging.  Returns the inbound
/// unconsumed on phases 1-3 failure для fallback compatibility.
#[allow(clippy::too_many_arguments)]
async fn try_veil_setup_and_bridge_with_prelude(
    app_handle: Arc<AppSender>,
    server_node_id: [u8; 32],
    server_app_id: [u8; 32],
    inbound: TcpStream,
    host: String,
    port: u16,
    prelude: Vec<u8>,
) -> std::result::Result<(), (TcpStream, anyhow::Error)> {
    use tokio::io::AsyncWriteExt;

    let stream = match tokio::time::timeout(
        crate::timeouts::OPEN_STREAM_TIMEOUT,
        app_handle.open_stream(server_node_id, server_app_id, 0, INITIAL_WINDOW),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err((inbound, anyhow!("open veil stream to {host}:{port}: {e}")));
        }
        Err(_) => {
            return Err((
                inbound,
                anyhow!(
                    "open veil stream к {host}:{port} timed out ({:?})",
                    crate::timeouts::OPEN_STREAM_TIMEOUT
                ),
            ));
        }
    };
    let mut stream = stream;
    let mut header_with_preamble = app_cert_preamble_bytes();
    let header = match encode_connect_header(&host, port) {
        Some(h) => h,
        None => {
            return Err((inbound, anyhow!("host `{host}` invalid")));
        }
    };
    header_with_preamble.extend_from_slice(&header);
    if let Err(e) = stream.write_all(&header_with_preamble).await {
        return Err((inbound, anyhow!("write connect header: {e}")));
    }
    // Audit batch 2026-05-24: same timeout-bound on the prelude path.
    let status = match tokio::time::timeout(
        crate::timeouts::VEIL_STATUS_TIMEOUT,
        read_status(&mut stream),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err((inbound, anyhow!("read status reply: {e}"))),
        Err(_) => {
            return Err((
                inbound,
                anyhow!(
                    "veil status reply timeout ({:?})",
                    crate::timeouts::VEIL_STATUS_TIMEOUT
                ),
            ));
        }
    };
    if status != ConnectStatus::Ok {
        return Err((inbound, anyhow!("server rejected: {status:?}")));
    }
    // Inject prelude — phase 4 begins.
    if let Err(e) = stream.write_all(&prelude).await {
        return Err((inbound, anyhow!("write prelude: {e}")));
    }
    let (mut in_r, mut in_w) = inbound.into_split();
    let (mut out_r, mut out_w) = tokio::io::split(stream);
    let up = async {
        let _ = copy(&mut in_r, &mut out_w).await;
        let _ = out_w.shutdown().await;
    };
    let down = async {
        let _ = copy(&mut out_r, &mut in_w).await;
        let _ = in_w.shutdown().await;
    };
    tokio::join!(up, down);
    Ok(())
}

/// Direct (non-veil) variant с prelude: write the prelude к the
/// outbound TCP socket, then bridge.  Used когда routing policy
/// resolves к `Direct` для а plain-HTTP inbound that has already
/// rewritten the request.
async fn open_direct_with_prelude_and_bridge(
    inbound: TcpStream,
    host: String,
    port: u16,
    prelude: Vec<u8>,
    allow_private: bool,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let target = format!("{host}:{port}");
    // audit cycle-6 (A9 review, BLOCKER fix): this plain-HTTP (non-CONNECT)
    // direct path previously called `TcpStream::connect(&target)` with NO SSRF
    // filter, letting `GET http://169.254.169.254/...` reach cloud-metadata /
    // RFC1918 even with `allow_private = false`. Route through the same vetted
    // connect helper as the CONNECT path.
    let mut outbound = crate::routing::connect_direct_vetted(&target, allow_private).await?;
    outbound
        .write_all(&prelude)
        .await
        .context("write prelude to direct target")?;
    log::debug!("oproxy.routing.direct.prelude: bridged {target}");
    let (mut in_r, mut in_w) = inbound.into_split();
    let (mut out_r, mut out_w) = outbound.into_split();
    let up = async {
        let _ = copy(&mut in_r, &mut out_w).await;
        let _ = out_w.shutdown().await;
    };
    let down = async {
        let _ = copy(&mut out_r, &mut in_w).await;
        let _ = in_w.shutdown().await;
    };
    tokio::join!(up, down);
    Ok(())
}

/// HTTP-plain variant of [`bridge_via_routing`] that carries а rewritten
/// HTTP prelude (request line + headers) and writes it после the connect
/// handshake (veil path) или directly после the TCP connect (direct
/// path).
#[allow(clippy::too_many_arguments)]
pub async fn bridge_via_routing_with_prelude(
    app_handle: Arc<AppSender>,
    server_node_id: [u8; 32],
    server_app_id: [u8; 32],
    routing: Arc<crate::config::RoutingConfig>,
    inbound: TcpStream,
    host: String,
    port: u16,
    prelude: Vec<u8>,
) -> Result<()> {
    use crate::config::{FallbackMode, ProxyMode};

    let decision = crate::routing::resolve(&routing, &host, port);
    log::debug!("oproxy.routing.prelude: {host}:{port} → {decision:?}");

    match decision.mode {
        ProxyMode::Block => Err(anyhow!("routing policy = Block ({host}:{port})")),
        ProxyMode::Direct => {
            open_direct_with_prelude_and_bridge(inbound, host, port, prelude, routing.allow_private)
                .await
        }
        ProxyMode::Veil => match try_veil_setup_and_bridge_with_prelude(
            app_handle,
            server_node_id,
            server_app_id,
            inbound,
            host.clone(),
            port,
            prelude.clone(),
        )
        .await
        {
            Ok(()) => Ok(()),
            Err((inbound, err)) => match decision.fallback {
                FallbackMode::Fail => Err(err),
                FallbackMode::Direct => {
                    log::warn!(
                        "oproxy.routing: veil failed для {host}:{port} (plain HTTP), falling back direct: {err}"
                    );
                    open_direct_with_prelude_and_bridge(
                        inbound,
                        host,
                        port,
                        prelude,
                        routing.allow_private,
                    )
                    .await
                }
            },
        },
    }
}

/// Dispatch each inbound connection through the configured routing
/// policy.  Replaces direct calls к `open_stream_and_bridge` от
/// inbound handlers — every inbound (SOCKS5 / HTTP / TProxy) routes its
/// `(host, port)` через this gate.
pub async fn bridge_via_routing(
    app_handle: Arc<AppSender>,
    server_node_id: [u8; 32],
    server_app_id: [u8; 32],
    routing: Arc<crate::config::RoutingConfig>,
    inbound: TcpStream,
    host: String,
    port: u16,
) -> Result<()> {
    use crate::config::{FallbackMode, ProxyMode};

    let decision = crate::routing::resolve(&routing, &host, port);
    log::debug!("oproxy.routing: {host}:{port} → {decision:?}");

    match decision.mode {
        ProxyMode::Block => Err(anyhow!("routing policy = Block ({host}:{port})")),
        ProxyMode::Direct => {
            crate::routing::open_direct_and_bridge(inbound, host, port, routing.allow_private).await
        }
        ProxyMode::Veil => match try_veil_setup_and_bridge(
            app_handle,
            server_node_id,
            server_app_id,
            inbound,
            host.clone(),
            port,
        )
        .await
        {
            Ok(()) => Ok(()),
            Err((inbound, err)) => match decision.fallback {
                FallbackMode::Fail => Err(err),
                FallbackMode::Direct => {
                    log::warn!(
                        "oproxy.routing: veil failed для {host}:{port}, falling back direct: {err}"
                    );
                    crate::routing::open_direct_and_bridge(
                        inbound,
                        host,
                        port,
                        routing.allow_private,
                    )
                    .await
                }
            },
        },
    }
}

/// Helper: read N bytes от an inbound TCP stream into а buffer
/// (used by SOCKS5 / HTTP handshake parsers).
pub async fn read_exact_n<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    n: usize,
) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}
