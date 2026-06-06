//! Client-side webtunnel connector — counterpart to [`crate::WebtunnelRouter`].
//!
//! Phase 5c of [`docs/internal/PLAN_TRANSPORT_OBFUSCATION.md`](../../docs/internal/PLAN_TRANSPORT_OBFUSCATION.md).
//!
//! Given an already-TLS-terminated stream (typically `wss://` connected
//! via `veil-transport::websocket` or a plain TLS wrapper), the
//! client:
//!
//! 1. Generates a fresh random `Sec-WebSocket-Key` (16 random bytes,
//!    base64-encoded per RFC 6455).
//! 2. Sends an HTTP/1.1 GET request with the configured secret path,
//!    standard WebSocket upgrade headers, and the operator-supplied
//!    `X-Veil-Auth` (or whatever header name the matcher expects).
//! 3. Reads the server's response.  Verifies 101 Switching Protocols and
//!    that `Sec-WebSocket-Accept` matches the expected derived value.
//! 4. Returns the upgraded `WebSocketStream` ready for binary-frame I/O.
//!
//! If the server returned **anything other than 101** (typically a
//! decoy HTML page when our path/auth was wrong), the client surfaces
//! `ClientError::DecoyReceived` so the caller knows tunnel mode wasn't
//! activated.  Caller closes the connection without retrying — retry
//! with the same wrong credentials yields the same decoy.

#![allow(clippy::result_large_err)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{handshake::derive_accept_key, protocol::Role},
};

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("I/O error during webtunnel handshake: {0}")]
    Io(#[from] std::io::Error),

    #[error("server returned non-101 response (likely decoy): status={status}")]
    DecoyReceived { status: u16 },

    #[error("malformed server response: {0}")]
    BadResponse(String),

    #[error("Sec-WebSocket-Accept mismatch (possible MITM or bad server)")]
    BadAccept,

    #[error("invalid webtunnel request component (control byte / CRLF) in {0}")]
    InvalidRequestComponent(&'static str),
}

// ── Config ───────────────────────────────────────────────────────────────────

/// Per-server connection credentials.  Constructed once and reused
/// across many connect attempts.
pub struct WebtunnelClient {
    /// Path that activates tunnel mode on the server.
    secret_path: String,
    /// Host header value (real production: domain of the server).
    /// Defaults to `"example.com"`; operators should set to the actual
    /// TLS SNI host for realistic-looking requests.
    host: String,
    /// Optional auth-header credentials.  When set, both name + token
    /// must match what the server's `SecretMatcher` expects.
    auth: Option<(String, Vec<u8>)>,
    /// Additional headers to send (e.g. realistic User-Agent).  Phase
    /// 5c default: a common browser UA so we don't stick out.
    extra_headers: Vec<(String, String)>,
}

/// Reject HTTP request components that contain control bytes (CR, LF, NUL, any
/// other C0 control, or DEL). Prevents CRLF header injection / request
/// smuggling via operator-supplied `secret_path` / `host`. High bytes (≥ 0x80,
/// e.g. UTF-8) are allowed — they cannot terminate a header line.
fn is_request_component_safe(s: &str) -> bool {
    s.bytes().all(|b| b >= 0x20 && b != 0x7f)
}

impl WebtunnelClient {
    pub fn new(secret_path: impl Into<String>) -> Self {
        Self {
            secret_path: secret_path.into(),
            host: "example.com".to_owned(),
            auth: None,
            extra_headers: vec![
                (
                    "User-Agent".to_owned(),
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_owned(),
                ),
                ("Accept".to_owned(), "*/*".to_owned()),
                ("Accept-Language".to_owned(), "en-US,en;q=0.5".to_owned()),
                ("Accept-Encoding".to_owned(), "gzip, deflate, br".to_owned()),
                ("Cache-Control".to_owned(), "no-cache".to_owned()),
                ("Pragma".to_owned(), "no-cache".to_owned()),
            ],
        }
    }

    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    pub fn with_auth(mut self, header_name: impl Into<String>, token: impl Into<Vec<u8>>) -> Self {
        self.auth = Some((header_name.into(), token.into()));
        self
    }

    /// Replace the default browser-style extra headers.  Operators
    /// that want to match a specific real site's request fingerprint
    /// can supply their own list.
    pub fn with_extra_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.extra_headers = headers;
        self
    }

    /// Perform the webtunnel handshake on the supplied raw stream.
    /// Returns the upgraded `WebSocketStream` ready for binary I/O.
    pub async fn connect<S>(&self, mut stream: S) -> Result<WebSocketStream<S>, ClientError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Reject control bytes (esp. CR / LF) in operator-supplied request
        // components: a newline in `secret_path` or `host` would let CRLF
        // injection forge headers or smuggle a second request. (Auth-token
        // values are separately guarded by the base64 path below.)
        if !is_request_component_safe(&self.secret_path) {
            return Err(ClientError::InvalidRequestComponent("secret_path"));
        }
        if !is_request_component_safe(&self.host) {
            return Err(ClientError::InvalidRequestComponent("host"));
        }

        // Generate a random 16-byte Sec-WebSocket-Key per RFC 6455.
        let mut key_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut key_bytes);
        let sec_key = BASE64.encode(key_bytes);

        // Build the request.
        let mut req = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n",
            self.secret_path, self.host, sec_key,
        );
        if let Some((name, token)) = &self.auth {
            req.push_str(name);
            req.push_str(": ");
            // Auth tokens are typically printable ASCII; if not, the
            // operator's deployment is misconfigured.  We base64 non-
            // ASCII tokens to keep the header line valid.
            if token.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
                req.push_str(std::str::from_utf8(token).expect("checked ASCII"));
            } else {
                req.push_str(&BASE64.encode(token));
            }
            req.push_str("\r\n");
        }
        for (k, v) in &self.extra_headers {
            req.push_str(k);
            req.push_str(": ");
            req.push_str(v);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");

        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;

        // Read the response headers (capped at 8 KiB).
        let (status_line, headers, residual) = read_response_headers(&mut stream).await?;
        let status = parse_status_code(&status_line)?;

        if status != 101 {
            return Err(ClientError::DecoyReceived { status });
        }
        if !residual.is_empty() {
            // Server sent bytes past the 101 boundary before we asked
            // for them — odd but not protocol-correct yet (WS frames
            // start after the upgrade); reject defensively.
            return Err(ClientError::BadResponse(
                "server sent data before WebSocket upgrade completed".to_owned(),
            ));
        }

        // Verify Sec-WebSocket-Accept = base64(SHA1(sec_key || GUID)).
        let expected_accept = derive_accept_key(sec_key.as_bytes());
        let got_accept = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Sec-WebSocket-Accept"))
            .map(|(_, v)| v.as_slice());
        match got_accept {
            Some(v) if v == expected_accept.as_bytes() => {}
            _ => return Err(ClientError::BadAccept),
        }

        let ws = WebSocketStream::from_raw_socket(stream, Role::Client, None).await;
        Ok(ws)
    }
}

// ── Response-reading helpers ─────────────────────────────────────────────────

/// Read HTTP response headers until `\r\n\r\n`.  Returns the status line
/// (e.g. "HTTP/1.1 101 Switching Protocols"), a list of (name, value)
/// header pairs, and any residual bytes read past the boundary.
async fn read_response_headers<S>(
    stream: &mut S,
) -> Result<(String, Vec<(String, Vec<u8>)>, Vec<u8>), ClientError>
where
    S: AsyncRead + Unpin,
{
    const MAX_RESPONSE_HEADERS_BYTES: usize = 8 * 1024;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let end_pos = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "server closed before response completed",
            )));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p;
        }
        if buf.len() >= MAX_RESPONSE_HEADERS_BYTES {
            return Err(ClientError::BadResponse(
                "response headers exceed 8 KiB cap".to_owned(),
            ));
        }
    };

    let header_bytes = &buf[..end_pos];
    let residual = buf[end_pos + 4..].to_vec();
    let s = std::str::from_utf8(header_bytes)
        .map_err(|_| ClientError::BadResponse("non-UTF8 response headers".to_owned()))?;
    let mut lines = s.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| ClientError::BadResponse("empty response".to_owned()))?
        .to_owned();
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
    Ok((status_line, headers, residual))
}

fn parse_status_code(status_line: &str) -> Result<u16, ClientError> {
    // "HTTP/1.1 101 Switching Protocols" → 101.
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let code = parts
        .next()
        .ok_or_else(|| ClientError::BadResponse(format!("malformed status line: {status_line}")))?;
    code.parse::<u16>()
        .map_err(|_| ClientError::BadResponse(format!("non-numeric status code: {status_line}")))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DecoyProvider, MatchResult, SecretMatcher, StaticStringDecoy, WebtunnelRouter};
    use std::sync::Arc;
    use tokio::io::duplex;

    fn make_matcher() -> SecretMatcher {
        SecretMatcher::with_auth("/_t/abc", "X-Veil-Auth", b"correct-token".to_vec())
    }

    fn make_router() -> WebtunnelRouter {
        let decoy: Arc<dyn DecoyProvider> = Arc::new(StaticStringDecoy::new("<h1>Decoy</h1>"));
        WebtunnelRouter::new(make_matcher(), decoy)
    }

    #[tokio::test]
    async fn client_server_round_trip_upgrades_and_data_flows() {
        let (client_io, server_io) = duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            let router = make_router();
            router.handle(server_io).await
        });

        let client = WebtunnelClient::new("/_t/abc")
            .with_host("example.com")
            .with_auth("X-Veil-Auth", b"correct-token".to_vec());

        let mut ws_client = client
            .connect(client_io)
            .await
            .expect("upgrade should succeed");
        let server_result = server_task.await.unwrap();
        let mut ws_server = server_result.expect("server should hand back WebSocketStream");

        // Round-trip a binary frame.
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        ws_client
            .send(Message::Binary(b"hello tunnel".to_vec()))
            .await
            .unwrap();
        let msg = ws_server.next().await.unwrap().unwrap();
        assert_eq!(msg.into_data(), b"hello tunnel");

        ws_server
            .send(Message::Binary(b"reply".to_vec()))
            .await
            .unwrap();
        let msg = ws_client.next().await.unwrap().unwrap();
        assert_eq!(msg.into_data(), b"reply");
    }

    #[tokio::test]
    async fn client_sees_decoy_when_auth_wrong() {
        let (client_io, server_io) = duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            let router = make_router();
            router.handle(server_io).await
        });

        let client = WebtunnelClient::new("/_t/abc")
            .with_host("example.com")
            .with_auth("X-Veil-Auth", b"wrong-token".to_vec());

        let err = client.connect(client_io).await.unwrap_err();
        match err {
            ClientError::DecoyReceived { status } => {
                assert_eq!(status, 200, "decoy is a 200 OK with HTML body");
            }
            other => panic!("expected DecoyReceived, got {other:?}"),
        }

        // Server must return ServedDecoy.
        let server_result = server_task.await.unwrap();
        assert!(server_result.is_err());
    }

    #[tokio::test]
    async fn client_sees_decoy_when_path_wrong() {
        let (client_io, server_io) = duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            let router = make_router();
            router.handle(server_io).await
        });

        let client =
            WebtunnelClient::new("/wrong/path").with_auth("X-Veil-Auth", b"correct-token".to_vec());

        let err = client.connect(client_io).await.unwrap_err();
        assert!(matches!(err, ClientError::DecoyReceived { .. }));
        let _ = server_task.await;
    }

    #[test]
    fn parse_status_code_extracts_101() {
        assert_eq!(
            parse_status_code("HTTP/1.1 101 Switching Protocols").unwrap(),
            101
        );
        assert_eq!(parse_status_code("HTTP/1.1 200 OK").unwrap(), 200);
        assert_eq!(parse_status_code("HTTP/1.1 404 Not Found").unwrap(), 404);
    }

    #[test]
    fn parse_status_code_rejects_malformed() {
        assert!(parse_status_code("").is_err());
        assert!(parse_status_code("HTTP/1.1 NOT_A_NUMBER").is_err());
        assert!(parse_status_code("HTTP/1.1").is_err());
    }

    /// Verify the matcher contract — ensures parity between client and
    /// server expectations.
    #[test]
    fn matcher_recognizes_client_credentials() {
        let m = make_matcher();
        assert_eq!(
            m.check("/_t/abc", Some(b"correct-token")),
            MatchResult::TunnelMode
        );
    }
}
