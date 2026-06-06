//! SOCKS5 ingress (RFC 1928).  CONNECT method only — sufficient for
//! TCP forwarding.  UDP ASSOCIATE / BIND are out of scope.
//!
//! # Handshake (client → server, all big-endian):
//!
//! 1. Method-select request:  `0x05 N_METHODS [METHODS...]`
//!    Server reply:  `0x05 0x00` (accept NO_AUTH).
//! 2. CONNECT request:  `0x05 0x01 0x00 ATYP DST_ADDR DST_PORT`
//!    Server reply: `0x05 STATUS 0x00 0x01 0.0.0.0 0` (BND fields
//!    cosmetic — clients ignore).

use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use veilclient::AppSender;

use crate::config::RoutingConfig;
use crate::connector::bridge_via_routing;
use crate::timeouts::HANDSHAKE_TIMEOUT;

const SOCKS_VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const NO_AUTH: u8 = 0x00;

/// Accept-loop driver.  Returns only on accept-error (which kills the
/// listener) — caller wraps в an outer task.
pub async fn run(
    listen_addr: String,
    app_handle: Arc<AppSender>,
    server_node_id: [u8; 32],
    server_app_id: [u8; 32],
    routing: Arc<RoutingConfig>,
    semaphore: Arc<tokio::sync::Semaphore>,
) -> Result<()> {
    let listener = TcpListener::bind(&listen_addr)
        .await
        .with_context(|| format!("bind SOCKS5 listener {listen_addr}"))?;
    log::info!("oproxy.socks5: listening on {listen_addr}");
    loop {
        // Audit batch 2026-05-24 (M8): acquire permit BEFORE accept.
        // Когда listener at capacity, accept() blocks → TCP backpressure
        // к client; daemon never spawns more than N concurrent tasks.
        let permit = match Arc::clone(&semaphore).acquire_owned().await {
            Ok(p) => p,
            Err(_closed) => return Ok(()), // Semaphore closed — graceful shutdown.
        };
        let (stream, peer) = listener.accept().await.context("accept SOCKS5")?;
        log::debug!("oproxy.socks5: accept от {peer}");
        let h = Arc::clone(&app_handle);
        let r = Arc::clone(&routing);
        tokio::spawn(async move {
            // Hold permit для the lifetime of the task; released on drop.
            let _permit = permit;
            if let Err(e) = handle_connection(stream, h, server_node_id, server_app_id, r).await {
                log::debug!("oproxy.socks5: peer {peer} dropped: {e}");
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    app_handle: Arc<AppSender>,
    server_node_id: [u8; 32],
    server_app_id: [u8; 32],
    routing: Arc<RoutingConfig>,
) -> Result<()> {
    // Audit batch 2026-05-24: wrap the entire SOCKS5 handshake phase в
    // а timeout so slow clients cannot tie up а task indefinitely.
    let (host, port) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        // Step 1 — method-select.
        let mut hdr = [0u8; 2];
        stream.read_exact(&mut hdr).await.context("read greeting")?;
        if hdr[0] != SOCKS_VERSION {
            anyhow::bail!("not SOCKS5: ver=0x{:02x}", hdr[0]);
        }
        let nmethods = hdr[1] as usize;
        if nmethods == 0 {
            anyhow::bail!("nmethods == 0");
        }
        let mut methods = vec![0u8; nmethods];
        stream
            .read_exact(&mut methods)
            .await
            .context("read methods list")?;
        if !methods.contains(&NO_AUTH) {
            // Reject — we only support NO_AUTH.
            stream.write_all(&[SOCKS_VERSION, 0xFF]).await.ok();
            anyhow::bail!("client does not offer NO_AUTH");
        }
        stream
            .write_all(&[SOCKS_VERSION, NO_AUTH])
            .await
            .context("write method-select reply")?;

        // Step 2 — read the CONNECT request.
        let mut req_hdr = [0u8; 4];
        stream
            .read_exact(&mut req_hdr)
            .await
            .context("read CONNECT header")?;
        if req_hdr[0] != SOCKS_VERSION {
            anyhow::bail!("CONNECT wrong version 0x{:02x}", req_hdr[0]);
        }
        if req_hdr[1] != CMD_CONNECT {
            // Unsupported (BIND, UDP ASSOCIATE) — reply 0x07 (command not
            // supported).
            write_reply(&mut stream, 0x07).await.ok();
            anyhow::bail!("unsupported CMD 0x{:02x}", req_hdr[1]);
        }
        // req_hdr[2] is RSV (must be 0x00 per RFC, but ignored).
        let atyp = req_hdr[3];
        let host = match atyp {
            ATYP_IPV4 => {
                let mut buf = [0u8; 4];
                stream.read_exact(&mut buf).await.context("read IPv4")?;
                Ipv4Addr::from(buf).to_string()
            }
            ATYP_IPV6 => {
                let mut buf = [0u8; 16];
                stream.read_exact(&mut buf).await.context("read IPv6")?;
                std::net::Ipv6Addr::from(buf).to_string()
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                stream
                    .read_exact(&mut len)
                    .await
                    .context("read domain len")?;
                let mut buf = vec![0u8; len[0] as usize];
                stream
                    .read_exact(&mut buf)
                    .await
                    .context("read domain bytes")?;
                String::from_utf8(buf).map_err(|e| anyhow!("domain utf8: {e}"))?
            }
            other => {
                write_reply(&mut stream, 0x08).await.ok();
                anyhow::bail!("unsupported ATYP 0x{other:02x}");
            }
        };
        let mut port_buf = [0u8; 2];
        stream
            .read_exact(&mut port_buf)
            .await
            .context("read port")?;
        let port = u16::from_be_bytes(port_buf);

        // Step 3 — confirm к the SOCKS client (return success BEFORE
        // opening the veil stream so the client может start streaming
        // immediately).  Tactic mirrors v2ray / xray behavior: best-effort
        // optimistic ack; если the veil stream открыть to NOT open,
        // the subsequent write would simply close the connection.
        write_reply(&mut stream, 0x00)
            .await
            .context("SOCKS reply")?;

        Ok::<(String, u16), anyhow::Error>((host, port))
    })
    .await
    .map_err(|_| anyhow!("SOCKS5 handshake timeout ({HANDSHAKE_TIMEOUT:?})"))??;

    // Step 4 — dispatch к the routing layer (veil / direct / block
    // + optional fallback).
    bridge_via_routing(
        app_handle,
        server_node_id,
        server_app_id,
        routing,
        stream,
        host,
        port,
    )
    .await
}

/// Build + write а SOCKS5 reply with the given status byte.  BND fields
/// are all-zero (clients ignore).
async fn write_reply(stream: &mut TcpStream, status: u8) -> std::io::Result<()> {
    // Layout: `VER REP RSV ATYP BND_ADDR BND_PORT`.  Reply atyp = IPv4
    // 0.0.0.0:0 (4 + 2 trailing zero bytes).
    let buf = [SOCKS_VERSION, status, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
    stream.write_all(&buf).await
}
