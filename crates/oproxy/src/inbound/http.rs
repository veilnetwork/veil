//! HTTP/1.1 forward proxy.  Supports the **CONNECT** method (used by
//! browsers / curl for HTTPS through-tunnels) и absolute-URI requests
//! for plain HTTP forwarding.
//!
//! # CONNECT
//!
//! Client sends: `CONNECT host:port HTTP/1.1\r\n<hdrs>\r\n\r\n`.
//! Server replies: `HTTP/1.1 200 Connection Established\r\n\r\n` и
//! then bridges bytes verbatim.
//!
//! # Plain HTTP (absolute-URI)
//!
//! Client sends: `GET http://host/path HTTP/1.1\r\n<hdrs>\r\n\r\n`.
//! We extract host:port от the URI, rewrite the request line к
//! `GET /path HTTP/1.1`, then forward the (rewritten + remainder)
//! bytes through the veil.  HTTPS upstream URIs ара treated as
//! CONNECT equivalent (not supported in this minimal mode).

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use veilclient::AppSender;

use crate::config::RoutingConfig;
use crate::connector::{bridge_via_routing, bridge_via_routing_with_prelude};
use crate::timeouts::HANDSHAKE_TIMEOUT;

const MAX_HEADERS_BYTES: usize = 8 * 1024;
const READ_CHUNK_SIZE: usize = 1024;

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
        .with_context(|| format!("bind HTTP listener {listen_addr}"))?;
    log::info!("oproxy.http: listening on {listen_addr}");
    loop {
        // Audit batch 2026-05-24 (M8): semaphore gating, см. socks5.rs.
        let permit = match Arc::clone(&semaphore).acquire_owned().await {
            Ok(p) => p,
            Err(_closed) => return Ok(()),
        };
        let (stream, peer) = listener.accept().await.context("accept HTTP")?;
        log::debug!("oproxy.http: accept от {peer}");
        let h = Arc::clone(&app_handle);
        let r = Arc::clone(&routing);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_connection(stream, h, server_node_id, server_app_id, r).await {
                log::debug!("oproxy.http: peer {peer} dropped: {e}");
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    app_handle: Arc<AppSender>,
    server_node_id: [u8; 32],
    server_app_id: [u8; 32],
    routing: Arc<RoutingConfig>,
) -> Result<()> {
    let mut stream = stream;
    // Audit batch 2026-05-24: read headers с per-chunk bounds check (NOT
    // `read_until` — that lets the read grow unbounded на а single line
    // until newline arrives, defeating MAX_HEADERS_BYTES).  Chunked
    // reads enforce the cap BEFORE each system call, и the entire phase
    // wraps в `HANDSHAKE_TIMEOUT` к defeat slow-loris clients.
    let (headers, pending_after_headers) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let mut headers: Vec<u8> = Vec::with_capacity(1024);
        let mut chunk = [0u8; READ_CHUNK_SIZE];
        // Track where к resume scanning для end-of-headers — overlap of
        // 3 bytes к catch а split "\r\n\r\n" pattern across chunks.
        let mut scan_from = 0usize;
        loop {
            // Bound check BEFORE reading, не after.  An attacker shipping
            // gigabytes на а single line cannot push us past MAX_HEADERS_BYTES.
            let remaining = MAX_HEADERS_BYTES.saturating_sub(headers.len());
            if remaining == 0 {
                anyhow::bail!("headers > {MAX_HEADERS_BYTES} bytes; refusing to continue");
            }
            let to_read = remaining.min(chunk.len());
            let n = stream
                .read(&mut chunk[..to_read])
                .await
                .context("read header bytes")?;
            if n == 0 {
                anyhow::bail!("EOF before end-of-headers");
            }
            headers.extend_from_slice(&chunk[..n]);
            // Look для end-of-headers ("\r\n\r\n" або "\n\n") в the
            // newly-added region (с а 3-byte back-scan к catch split-
            // across-chunks patterns).
            let scan_start = scan_from.saturating_sub(3);
            let eoh = find_end_of_headers(&headers[scan_start..]).map(|i| scan_start + i);
            if let Some(eoh_pos) = eoh {
                // Capture pending bytes (если client pipelined body
                // after the empty-line).  Truncate `headers` к the
                // header-only portion.
                let pending = headers.split_off(eoh_pos);
                return Ok::<(Vec<u8>, Vec<u8>), anyhow::Error>((headers, pending));
            }
            scan_from = headers.len();
        }
    })
    .await
    .map_err(|_| anyhow!("HTTP handshake timeout ({HANDSHAKE_TIMEOUT:?})"))??;

    // Parse request line.
    let first_line_end = headers
        .windows(2)
        .position(|w| w == b"\r\n")
        .or_else(|| headers.iter().position(|&b| b == b'\n'))
        .ok_or_else(|| anyhow!("no request line"))?;
    let request_line = std::str::from_utf8(&headers[..first_line_end])
        .map_err(|e| anyhow!("request line utf8: {e}"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or_else(|| anyhow!("no method"))?;
    let target = parts.next().ok_or_else(|| anyhow!("no target"))?;

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT host:port HTTP/1.1
        let (host, port) =
            parse_authority(target).ok_or_else(|| anyhow!("invalid CONNECT target `{target}`"))?;

        // Confirm tunnel established BEFORE opening veil stream
        // (optimistic — matches Xray behavior).
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .context("write CONNECT reply")?;

        // Audit batch 2026-05-24: previously pipelined post-CONNECT
        // bytes were silently dropped с а warning ("dead-code TODO").
        // Browsers don't pipeline после CONNECT, но non-standard
        // clients might.  Reject explicitly — silent drop corrupts the
        // tunnel without informing the client.
        if !pending_after_headers.is_empty() {
            return Err(anyhow!(
                "oproxy.http: client pipelined {} bytes after CONNECT request — \
                 unsupported (re-issue the request without pipelining)",
                pending_after_headers.len()
            ));
        }
        return bridge_via_routing(
            app_handle,
            server_node_id,
            server_app_id,
            routing,
            stream,
            host,
            port,
        )
        .await;
    }

    // Plain HTTP: target is absolute-URI like `http://host:port/path`.
    let (host, port, path) = parse_absolute_http_uri(target)
        .ok_or_else(|| anyhow!("non-CONNECT target `{target}` not absolute-URI HTTP"))?;
    let http_version = parts.next().unwrap_or("HTTP/1.1");

    // Rewrite the request line к origin-form (`GET /path HTTP/1.1`)
    // и forward as raw bytes.  Drop the Proxy-Connection header (per
    // RFC 7230) и add Host если missing.
    let mut rewritten: Vec<u8> = Vec::new();
    rewritten.extend_from_slice(method.as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(path.as_bytes());
    rewritten.push(b' ');
    rewritten.extend_from_slice(http_version.as_bytes());
    rewritten.extend_from_slice(b"\r\n");
    // Append remaining headers (lines после the request line) verbatim.
    // Skip Proxy-Connection.
    let mut has_host = false;
    let rest = &headers[first_line_end..];
    let rest = if rest.starts_with(b"\r\n") {
        &rest[2..]
    } else if rest.starts_with(b"\n") {
        &rest[1..]
    } else {
        rest
    };
    for line in rest.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if let Some(name_end) = line.iter().position(|&b| b == b':') {
            let name = &line[..name_end];
            if name.eq_ignore_ascii_case(b"proxy-connection") {
                continue;
            }
            if name.eq_ignore_ascii_case(b"host") {
                has_host = true;
            }
        }
        rewritten.extend_from_slice(line);
        rewritten.extend_from_slice(b"\r\n");
    }
    if !has_host {
        rewritten.extend_from_slice(b"Host: ");
        rewritten.extend_from_slice(host.as_bytes());
        if port != 80 {
            rewritten.extend_from_slice(format!(":{port}").as_bytes());
        }
        rewritten.extend_from_slice(b"\r\n");
    }
    rewritten.extend_from_slice(b"\r\n");

    // Captured during chunked read: any bytes that arrived past the
    // end-of-headers marker (request body — unlikely for GET, но
    // supported).
    let pending = pending_after_headers;

    // Open the veil stream + write rewritten request + pending
    // body bytes + then bridge.
    let initial_bytes = {
        let mut out = rewritten;
        out.extend_from_slice(&pending);
        out
    };
    bridge_via_routing_with_prelude(
        app_handle,
        server_node_id,
        server_app_id,
        routing,
        stream,
        host,
        port,
        initial_bytes,
    )
    .await
}

/// Find the first occurrence of `\r\n\r\n` or `\n\n` (end-of-headers
/// marker per RFC 7230 §3.5).  Returns the byte offset INCLUDING the
/// terminator (so `&buf[..ret]` holds the header block).
fn find_end_of_headers(buf: &[u8]) -> Option<usize> {
    // CRLF CRLF (standard)
    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some(i + 4);
    }
    // LF LF (tolerant — non-conforming clients)
    if let Some(i) = buf.windows(2).position(|w| w == b"\n\n") {
        return Some(i + 2);
    }
    None
}

/// Parse а CONNECT authority `host:port` или `[ipv6]:port`.
///
/// Audit batch 2026-05-24: explicitly reject empty hosts ("[]:443" or
/// ":443") и control chars (defence в depth against header smuggling).
pub fn parse_authority(s: &str) -> Option<(String, u16)> {
    // Reject control chars early — they have no place в an authority и
    // могут confuse downstream consumers (smuggling).
    if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }
    if let Some(stripped) = s.strip_prefix('[') {
        // IPv6 literal — `[::1]:443`.
        let end = stripped.find(']')?;
        let host = &stripped[..end];
        if host.is_empty() {
            return None;
        }
        let rest = &stripped[end + 1..];
        let port = rest.strip_prefix(':')?.parse::<u16>().ok()?;
        if port == 0 {
            return None;
        }
        Some((host.to_string(), port))
    } else {
        let colon = s.rfind(':')?;
        let host = &s[..colon];
        let port = s[colon + 1..].parse::<u16>().ok()?;
        if host.is_empty() || port == 0 {
            return None;
        }
        Some((host.to_string(), port))
    }
}

/// Parse an absolute HTTP URI like `http://host:port/path?query`.
pub fn parse_absolute_http_uri(uri: &str) -> Option<(String, u16, String)> {
    let rest = uri.strip_prefix("http://")?;
    let path_idx = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..path_idx];
    let path = if path_idx == rest.len() {
        "/".to_string()
    } else {
        rest[path_idx..].to_string()
    };
    let (host, port) = if authority.contains(':') {
        parse_authority(authority)?
    } else {
        (authority.to_string(), 80)
    };
    Some((host, port, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_parses_host_port() {
        assert_eq!(
            parse_authority("example.com:443"),
            Some(("example.com".to_string(), 443))
        );
    }

    #[test]
    fn authority_parses_ipv6() {
        assert_eq!(
            parse_authority("[::1]:8080"),
            Some(("::1".to_string(), 8080))
        );
    }

    #[test]
    fn authority_rejects_no_port() {
        assert_eq!(parse_authority("example.com"), None);
    }

    #[test]
    fn absolute_uri_default_port() {
        assert_eq!(
            parse_absolute_http_uri("http://example.com/foo"),
            Some(("example.com".to_string(), 80, "/foo".to_string()))
        );
    }

    #[test]
    fn absolute_uri_explicit_port() {
        assert_eq!(
            parse_absolute_http_uri("http://example.com:8080/"),
            Some(("example.com".to_string(), 8080, "/".to_string()))
        );
    }

    #[test]
    fn absolute_uri_no_path() {
        assert_eq!(
            parse_absolute_http_uri("http://example.com"),
            Some(("example.com".to_string(), 80, "/".to_string()))
        );
    }

    #[test]
    fn absolute_uri_rejects_https() {
        // HTTPS upstream needs CONNECT, not plain forwarding.
        assert_eq!(parse_absolute_http_uri("https://example.com/"), None);
    }
}
