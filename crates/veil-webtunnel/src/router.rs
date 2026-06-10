//! HTTP routing + WebSocket upgrade for webtunnel.
//!
//! Phase 5b of [`docs/internal/PLAN_TRANSPORT_OBFUSCATION.md`](../../docs/internal/PLAN_TRANSPORT_OBFUSCATION.md).
//!
//! Sits on top of an already-TLS-terminated stream (operator should
//! wrap raw TCP with rustls/BoringSSL via `veil-transport::tls` or
//! `tls_boring` so the TLS fingerprint is realistic).  Reads the inbound
//! HTTP request, asks the [`SecretMatcher`] whether it's a tunnel-mode
//! request, and:
//!
//! - **tunnel match** → completes the WebSocket upgrade and hands the
//!   [`WebSocketStream`] back to the caller.
//! - **decoy** → calls the [`DecoyProvider`] and sends a regular HTTPS
//!   response back over the wire.  Connection is then closed.
//!
//! ## Why tokio-tungstenite
//!
//! Already in the veil workspace ([`veil-transport`] uses it for
//! `ws://` / `wss://` transports).  `accept_hdr_async`'s Callback hook
//! lets us inspect the inbound HTTP request before deciding whether
//! to upgrade, and to reject with a custom response (the decoy) when we
//! choose not to upgrade.

#![allow(clippy::result_large_err)] // WebSocketStream Ok-arm is also large; no boxing benefit

use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::WebSocketStream;

use crate::{DecoyProvider, MatchResult, SecretMatcher};

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
#[allow(clippy::result_large_err)] // RouterError's variants carry boxed tungstenite errors; ok inline
pub enum RouterError {
    #[error("decoy provider error: {0}")]
    Decoy(#[from] crate::DecoyError),

    #[error("WebSocket handshake error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Sentinel returned when the inbound request triggered decoy mode and
    /// the decoy response was written to the wire.  Caller closes the
    /// connection; not a programmer error.
    #[error("served decoy response — connection should close")]
    ServedDecoy,
}

// ── Router ──────────────────────────────────────────────────────────────────

/// HTTP router that inspects inbound requests and either upgrades to
/// WebSocket (tunnel mode) or serves a decoy response.
///
/// Construct once and reuse across many connections — clone-cheap
/// (`Arc`-wrapped internals).
#[derive(Clone)]
pub struct WebtunnelRouter {
    matcher: Arc<SecretMatcher>,
    decoy: Arc<dyn DecoyProvider>,
    /// Optional response-timing floor (see [`Self::with_response_floor`]).
    /// `None` => respond as soon as ready (default).
    response_floor: Option<Duration>,
}

impl WebtunnelRouter {
    pub fn new(matcher: SecretMatcher, decoy: Arc<dyn DecoyProvider>) -> Self {
        Self {
            matcher: Arc::new(matcher),
            decoy,
            response_floor: None,
        }
    }

    /// Enable response-timing uniformity: hold every response — the tunnel
    /// `101 Switching Protocols` AND the decoy — until at least `floor` (plus a
    /// small random jitter) has elapsed since the request was fully read.
    ///
    /// This collapses the decoy-vs-tunnel *timing* distinguisher. Without it a
    /// tunnel match emits a near-instant 101 (just a SHA-1 + write) while a
    /// decoy response waits on a slower, variable decoy fetch (`tokio::fs::read`
    /// or an HTTP-proxy round-trip), so an active prober can tell a real tunnel
    /// endpoint from a plain site by latency alone — even though Part 1 already
    /// made the two byte-identical.
    ///
    /// Off by default: it adds up to `floor` of latency to every real tunnel
    /// handshake, so operators opt in where probe resistance outweighs handshake
    /// RTT. Choose a `floor` above the worst-case decoy-fetch time (for an
    /// HTTP-proxy decoy, above the backend's typical latency); a decoy fetch
    /// that overruns the floor still responds late and is not masked. A zero
    /// `floor` disables the feature (same as `None`).
    #[must_use]
    pub fn with_response_floor(mut self, floor: Duration) -> Self {
        self.response_floor = (!floor.is_zero()).then_some(floor);
        self
    }

    /// Handle one inbound connection.  Returns:
    /// - `Ok(WebSocketStream)` when tunnel mode upgraded successfully.
    /// - `Err(ServedDecoy)` when the request triggered decoy mode and
    ///   the response was already written to the wire.  Caller closes.
    /// - Other `Err(...)` for I/O or WebSocket errors.
    pub async fn handle<S>(&self, stream: S) -> Result<WebSocketStream<S>, RouterError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // The callback is invoked synchronously by tokio-tungstenite
        // after parsing the inbound request line + headers.  Our
        // decision: return Ok(response) to proceed with the upgrade, or
        // Err(error_response) to short-circuit and send the decoy bytes.
        let matcher = Arc::clone(&self.matcher);
        let decoy = Arc::clone(&self.decoy);

        // The decoy response, if needed, is computed inside the
        // callback (sync context) so we serialise async decoy fetches
        // synchronously here.  This means StaticDirectoryDecoy's
        // tokio::fs::read becomes a problem inside a sync callback.
        //
        // Workaround: do a preliminary HTTP-only read here to extract
        // path and auth header (see. read_http_request), then call decoy
        // async, then either invoke accept_hdr_async with a static
        // "always upgrade" callback OR write the decoy and bail.
        //
        // This means we read the HTTP request **twice** in tunnel
        // mode: once here for inspection, once by accept_hdr_async.
        // Tokio-tungstenite's API doesn't expose a "pre-parsed
        // request" entry point, so the cleaner alternative is to ship
        // a custom HTTP→WS upgrade.  For Phase 5b we take the simpler
        // route: peek the request, route, and either decoy or hand back
        // to tokio-tungstenite.
        //
        // BUT — re-reading the same stream isn't trivial since reads
        // consume bytes.  We need a peekable stream.  Two options:
        // (a) buffer bytes ourselves and replay; (b) parse the request
        // ourselves and then synthesize the upgrade response without
        // calling accept_hdr_async on the original stream.
        //
        // (b) is cleaner.  Let's do a full hand-rolled upgrade
        // including computing Sec-WebSocket-Accept.  Phase 5b ships
        // that; Phase 5c can refactor if a cleaner tungstenite API
        // surfaces.
        let (request, residual, mut stream) = read_http_request(stream).await?;
        // Anchor for the optional response-timing floor: padding is measured
        // from the moment the full request is in hand, i.e. it normalises the
        // *processing* time (where tunnel and decoy diverge), not the
        // client-paced request read. No-op unless `response_floor` is set.
        let received_at = Instant::now();

        let path = request.uri.as_str();
        let header_name = matcher.auth_header_name();
        let auth_value = header_name.and_then(|name| request.header(name));

        match matcher.check(path, auth_value) {
            MatchResult::TunnelMode => {
                // Generate the 101 Switching Protocols response.
                // A request that matched the secret path/auth but carries NO
                // Sec-WebSocket-Key is not a real WebSocket upgrade — almost
                // certainly an active probe. Serve the decoy (byte-identical to a
                // wrong-path response) rather than returning an error, so a
                // prober cannot distinguish "right path, malformed upgrade" from
                // "wrong path". This branch runs BEFORE the 101 is written, so
                // falling back to the decoy is still possible. (audit cycle-2:
                // anti-probe behavioral distinguisher. The decoy-vs-tunnel
                // *timing* distinguisher is addressed separately + opt-in by
                // `with_response_floor`, which pads this decoy and the 101 to a
                // common floor.)
                let sec_key = match request.header("Sec-WebSocket-Key") {
                    Some(k) => k,
                    None => {
                        let resp = decoy.respond(&request.method, path).await?;
                        pad_to_floor(self.response_floor, received_at).await;
                        write_http_response(&mut stream, &resp).await?;
                        stream.flush().await?;
                        let _ = stream.shutdown().await;
                        return Err(RouterError::ServedDecoy);
                    }
                };
                let accept = compute_sec_websocket_accept(sec_key);
                let response = format!(
                    "HTTP/1.1 101 Switching Protocols\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Accept: {accept}\r\n\
                     \r\n"
                );
                pad_to_floor(self.response_floor, received_at).await;
                stream.write_all(response.as_bytes()).await?;
                stream.flush().await?;

                // Hand the now-upgraded stream to tokio-tungstenite's
                // server-side framing reader.  We have to inject any
                // residual bytes that we read past the request boundary
                // (typically zero unless the client pipelined data —
                // not valid per WebSocket spec but defensive).
                if !residual.is_empty() {
                    return Err(RouterError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "client sent data before WebSocket upgrade completed",
                    )));
                }

                // Wrap the stream as a server-side WebSocket.  Since
                // we already wrote the 101 response, we use
                // `WebSocketStream::from_raw_socket` with role=Server.
                let ws = WebSocketStream::from_raw_socket(
                    stream,
                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                    Some(crate::bounded_ws_config()),
                )
                .await;
                Ok(ws)
            }
            MatchResult::Decoy => {
                let resp = decoy.respond(&request.method, path).await?;
                pad_to_floor(self.response_floor, received_at).await;
                write_http_response(&mut stream, &resp).await?;
                stream.flush().await?;
                let _ = stream.shutdown().await;
                Err(RouterError::ServedDecoy)
            }
        }
    }
}

/// Sleep until `floor` (plus up to ~25% random jitter) has elapsed since
/// `received_at`. No-op when `floor` is `None` or has already passed.
///
/// The jitter keeps the padded response time from collapsing to a tell-tale
/// constant; it is bounded above by the floor so timing stays in a tight band.
async fn pad_to_floor(floor: Option<Duration>, received_at: Instant) {
    let Some(floor) = floor else {
        return;
    };
    let jitter_max_ns = (floor / 4).as_nanos() as u64;
    let jitter = if jitter_max_ns > 0 {
        Duration::from_nanos(rand::rng().next_u64() % (jitter_max_ns + 1))
    } else {
        Duration::ZERO
    };
    if let Some(remaining) = (floor + jitter).checked_sub(received_at.elapsed()) {
        tokio::time::sleep(remaining).await;
    }
}

// ── Minimal HTTP request reader ──────────────────────────────────────────────

/// Parsed HTTP request line + headers.
struct ParsedRequest {
    method: String,
    uri: String,
    headers: Vec<(String, Vec<u8>)>,
}

impl ParsedRequest {
    fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }
}

/// Read an HTTP/1.1 request line + headers before `\r\n\r\n`.  Returns the
/// parsed request, any residual bytes read past the boundary (should
/// always be empty in well-behaved clients), and the stream (ownership
/// returned so caller can write a response back).
///
/// Caps at 16 KiB to prevent slowloris-style header floods.
async fn read_http_request<S>(mut stream: S) -> Result<(ParsedRequest, Vec<u8>, S), RouterError>
where
    S: AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    const MAX_HEADER_BYTES: usize = 16 * 1024;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let mut header_end: Option<usize> = None;
    // Bytes already scanned for the CRLF terminator. Re-scanning the whole
    // buffer from 0 after every read is O(n^2) when a slow client dribbles the
    // 16 KiB header one byte per packet; instead scan only the newly-appended
    // region, with a 3-byte overlap so a `\r\n\r\n` straddling the previous
    // read boundary is still found. Total scanning is then O(n).
    let mut scanned = 0usize;

    while buf.len() < MAX_HEADER_BYTES {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(RouterError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed before sending HTTP request",
            )));
        }
        buf.extend_from_slice(&chunk[..n]);
        let scan_from = scanned.saturating_sub(3);
        if let Some(rel) = find_double_crlf(&buf[scan_from..]) {
            header_end = Some(scan_from + rel);
            break;
        }
        scanned = buf.len();
    }
    let end = header_end.ok_or_else(|| {
        RouterError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "HTTP headers exceed 16 KiB cap",
        ))
    })?;

    let header_bytes = &buf[..end];
    let residual = buf[end + 4..].to_vec();

    let parsed = parse_request(header_bytes)?;
    Ok((parsed, residual, stream))
}

/// Find the byte position of `\r\n\r\n` in `buf`, returning the index
/// of the FIRST `\r` of the sequence.  Returns `None` if not found.
fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Parse HTTP/1.1 request from header bytes (without trailing `\r\n\r\n`).
fn parse_request(bytes: &[u8]) -> Result<ParsedRequest, RouterError> {
    let s = std::str::from_utf8(bytes).map_err(|_| {
        RouterError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "non-UTF8 HTTP headers",
        ))
    })?;
    let mut lines = s.split("\r\n");
    let request_line = lines.next().ok_or_else(|| {
        RouterError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "empty HTTP request",
        ))
    })?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| {
            RouterError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed HTTP request line",
            ))
        })?
        .to_owned();
    let uri = parts
        .next()
        .ok_or_else(|| {
            RouterError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed HTTP request line",
            ))
        })?
        .to_owned();
    // Ignore HTTP version field — caller can be HTTP/1.0 or /1.1.

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim().to_owned();
            let value = line[colon + 1..].trim().as_bytes().to_vec();
            headers.push((name, value));
        }
    }

    Ok(ParsedRequest {
        method,
        uri,
        headers,
    })
}

/// Compute the `Sec-WebSocket-Accept` header value from the client's
/// `Sec-WebSocket-Key` per RFC 6455 §1.3:  base64(SHA-1(key || GUID)).
fn compute_sec_websocket_accept(client_key: &[u8]) -> String {
    use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
    derive_accept_key(client_key)
}

/// Serialise a [`crate::DecoyResponse`] to the wire as an HTTP/1.1
/// response.
async fn write_http_response<S>(
    stream: &mut S,
    resp: &crate::DecoyResponse,
) -> Result<(), RouterError>
where
    S: AsyncWrite + Unpin,
{
    let mut headers = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        resp.status,
        status_reason(resp.status),
        resp.content_type,
        resp.body.len(),
    );
    for (k, v) in &resp.headers {
        headers.push_str(k);
        headers.push_str(": ");
        headers.push_str(v);
        headers.push_str("\r\n");
    }
    headers.push_str("\r\n");
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(&resp.body).await?;
    Ok(())
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StaticStringDecoy;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn test_router() -> WebtunnelRouter {
        let matcher = SecretMatcher::with_auth("/_t/abc", "X-Veil-Auth", b"correct-token".to_vec());
        let decoy = Arc::new(StaticStringDecoy::new("<h1>Welcome</h1>"));
        WebtunnelRouter::new(matcher, decoy)
    }

    #[tokio::test]
    async fn decoy_response_for_wrong_path() {
        let (mut client, server) = duplex(64 * 1024);
        let router = test_router();
        let router_task = tokio::spawn(async move { router.handle(server).await });

        // Client sends a regular HTTP GET to the wrong path.
        let req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();
        client.flush().await.unwrap();

        // Read response.
        let mut buf = Vec::new();
        let _ = client.read_to_end(&mut buf).await;
        let response = String::from_utf8_lossy(&buf);

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("Content-Type: text/html"));
        assert!(response.contains("<h1>Welcome</h1>"));

        let result = router_task.await.unwrap();
        assert!(matches!(result, Err(RouterError::ServedDecoy)));
    }

    #[tokio::test]
    async fn decoy_response_for_missing_auth() {
        let (mut client, server) = duplex(64 * 1024);
        let router = test_router();
        let router_task = tokio::spawn(async move { router.handle(server).await });

        // Correct path but no auth header.
        let req = "GET /_t/abc HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();
        client.flush().await.unwrap();

        let mut buf = Vec::new();
        let _ = client.read_to_end(&mut buf).await;
        let response = String::from_utf8_lossy(&buf);
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("<h1>Welcome</h1>"));

        let result = router_task.await.unwrap();
        assert!(matches!(result, Err(RouterError::ServedDecoy)));
    }

    #[tokio::test]
    async fn decoy_response_for_wrong_auth() {
        let (mut client, server) = duplex(64 * 1024);
        let router = test_router();
        let router_task = tokio::spawn(async move { router.handle(server).await });

        let req = "GET /_t/abc HTTP/1.1\r\nHost: example.com\r\nX-Veil-Auth: wrong-token\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();
        client.flush().await.unwrap();

        let mut buf = Vec::new();
        let _ = client.read_to_end(&mut buf).await;
        let response = String::from_utf8_lossy(&buf);
        assert!(response.starts_with("HTTP/1.1 200 OK"));

        let result = router_task.await.unwrap();
        assert!(matches!(result, Err(RouterError::ServedDecoy)));
    }

    #[tokio::test]
    async fn tunnel_mode_upgrades_to_websocket() {
        let (mut client, server) = duplex(64 * 1024);
        let router = test_router();
        let router_task = tokio::spawn(async move { router.handle(server).await });

        let req = "GET /_t/abc HTTP/1.1\r\nHost: example.com\r\nX-Veil-Auth: correct-token\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        client.write_all(req.as_bytes()).await.unwrap();
        client.flush().await.unwrap();

        // Read the 101 Switching Protocols response (only the header
        // part — body is the WebSocket framed stream).
        let mut buf = vec![0u8; 256];
        let n = client.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);

        assert!(
            response.starts_with("HTTP/1.1 101 Switching Protocols"),
            "expected 101 upgrade, got: {response}"
        );
        assert!(response.contains("Upgrade: websocket"));
        assert!(response.contains("Sec-WebSocket-Accept:"));

        // Server task must return Ok(WebSocketStream).
        let result = router_task.await.unwrap();
        assert!(result.is_ok(), "router should return upgraded WS stream");
    }

    #[tokio::test]
    async fn rejects_truncated_request() {
        let (mut client, server) = duplex(64 * 1024);
        let router = test_router();
        let router_task = tokio::spawn(async move { router.handle(server).await });

        // Send partial request and close.
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: ex")
            .await
            .unwrap();
        drop(client);

        let result = router_task.await.unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn response_floor_holds_decoy_until_floor() {
        let (mut client, server) = duplex(64 * 1024);
        let matcher = SecretMatcher::with_auth("/_t/abc", "X-Veil-Auth", b"correct-token".to_vec());
        let decoy = Arc::new(StaticStringDecoy::new("<h1>Welcome</h1>"));
        let floor = Duration::from_millis(80);
        let router = WebtunnelRouter::new(matcher, decoy).with_response_floor(floor);
        let router_task = tokio::spawn(async move { router.handle(server).await });

        let start = Instant::now();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        client.flush().await.unwrap();
        let mut buf = Vec::new();
        let _ = client.read_to_end(&mut buf).await;
        let elapsed = start.elapsed();

        // The (fast) static decoy would otherwise return in microseconds; the
        // floor must hold it back at least `floor`. Only the lower bound is
        // asserted — the upper bound (floor + jitter) is timing-flaky.
        assert!(
            elapsed >= floor,
            "decoy held {elapsed:?}, expected >= {floor:?}"
        );
        assert!(String::from_utf8_lossy(&buf).contains("<h1>Welcome</h1>"));
        assert!(matches!(
            router_task.await.unwrap(),
            Err(RouterError::ServedDecoy)
        ));
    }

    #[test]
    fn response_floor_zero_disables() {
        let matcher = SecretMatcher::with_auth("/_t/abc", "X-Veil-Auth", b"tok".to_vec());
        let decoy = Arc::new(StaticStringDecoy::new("x"));
        let r = WebtunnelRouter::new(matcher, decoy).with_response_floor(Duration::ZERO);
        assert!(r.response_floor.is_none(), "zero floor disables timing");
    }

    #[test]
    fn parse_request_extracts_method_uri_headers() {
        let raw = b"GET /_t/secret HTTP/1.1\r\nHost: example.com\r\nX-Auth: tok\r\nUpgrade: websocket\r\n";
        let req = parse_request(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.uri, "/_t/secret");
        assert_eq!(req.header("Host"), Some(&b"example.com"[..]));
        assert_eq!(req.header("x-auth"), Some(&b"tok"[..]));
        assert_eq!(req.header("Upgrade"), Some(&b"websocket"[..]));
        assert_eq!(req.header("Missing"), None);
    }
}
