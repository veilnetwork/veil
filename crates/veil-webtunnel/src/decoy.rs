//! Decoy-content providers що serve "looks like а regular HTTPS site"
//! responses к probes що don't carry valid tunnel-mode credentials.
//!
//! The trait is async-trait based и framework-agnostic — the request
//! comes в as а bare path + headers, response goes out as а status
//! code + headers + body.  Phase 5b's HTTP router wraps а Hyper
//! request, calls the decoy provider, и serialises the response back
//! over TLS.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper::body::Bytes;

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum DecoyError {
    #[error("decoy I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("decoy resource not found: {0}")]
    NotFound(String),

    #[error("decoy traversal attempt rejected: {0}")]
    PathTraversal(String),
}

// ── Response shape ───────────────────────────────────────────────────────────

/// Decoy-provider response.  Framework-agnostic; Phase 5b's HTTP
/// router converts this к а Hyper response.
#[derive(Debug, Clone)]
pub struct DecoyResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    /// Extra headers (e.g. `Cache-Control`, `ETag`).  Phase 5b adds
    /// reasonable defaults.
    pub headers: Vec<(String, String)>,
}

impl DecoyResponse {
    pub fn ok(content_type: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            content_type: content_type.into(),
            body: body.into(),
            headers: Vec::new(),
        }
    }

    pub fn not_found_html() -> Self {
        Self {
            status: 404,
            content_type: "text/html; charset=utf-8".into(),
            body: DEFAULT_404_HTML.as_bytes().to_vec(),
            headers: Vec::new(),
        }
    }

    pub fn bad_request_html() -> Self {
        Self {
            status: 400,
            content_type: "text/html; charset=utf-8".into(),
            body: DEFAULT_400_HTML.as_bytes().to_vec(),
            headers: Vec::new(),
        }
    }
}

const DEFAULT_404_HTML: &str = "<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head>\n<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>\n";

const DEFAULT_400_HTML: &str = "<!DOCTYPE html>\n<html><head><title>400 Bad Request</title></head>\n<body><h1>Bad Request</h1></body></html>\n";

// ── Trait ────────────────────────────────────────────────────────────────────

/// Decoy provider — produces an HTTP response для а given request path
/// when the request does NOT pass tunnel-mode authentication.
///
/// Implementations should:
/// - Return realistic-looking content (proper Content-Type, sensible
///   status codes).
/// - Avoid distinctive markers (no "Server: veil" headers, no
///   characteristic error pages).
/// - Be fast — а scanner generating thousands of probes shouldn't
///   thrash the operator's server.
#[async_trait]
pub trait DecoyProvider: Send + Sync {
    /// Generate а decoy response для the given request.
    /// `path` is the request URI path (no scheme/host); `method` is
    /// HTTP method ("GET", "POST", etc.).
    async fn respond(&self, method: &str, path: &str) -> Result<DecoyResponse, DecoyError>;
}

// ── StaticStringDecoy ───────────────────────────────────────────────────────

/// Simplest decoy: serves а single HTML string for any GET request,
/// 404 for everything else.
///
/// Low realism — а scanner що hits multiple URLs will see the same
/// page regardless of path.  Useful для tests и operator quick-starts.
pub struct StaticStringDecoy {
    body: Vec<u8>,
    content_type: String,
}

impl StaticStringDecoy {
    pub fn new(body: impl Into<String>) -> Self {
        Self {
            body: body.into().into_bytes(),
            content_type: "text/html; charset=utf-8".into(),
        }
    }

    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = content_type.into();
        self
    }
}

#[async_trait]
impl DecoyProvider for StaticStringDecoy {
    async fn respond(&self, method: &str, _path: &str) -> Result<DecoyResponse, DecoyError> {
        if !matches!(method, "GET" | "HEAD") {
            return Ok(DecoyResponse::bad_request_html());
        }
        Ok(DecoyResponse {
            status: 200,
            content_type: self.content_type.clone(),
            body: self.body.clone(),
            headers: Vec::new(),
        })
    }
}

// ── StaticDirectoryDecoy ───────────────────────────────────────────────────

/// Serves static files from а directory rooted at `root_dir`.  Maps
/// request path → file path; reads и returns the file content с а
/// sensible Content-Type guess.
///
/// Realism: medium-high.  Operator deploys а snapshot of а neutral site
/// (status dashboard, dev blog, public-data archive).  Probes see
/// realistic responses с proper Content-Type, varying file sizes, и
/// 404 для absent paths — indistinguishable от а real static-hosted site.
///
/// Security: path-traversal attempts (e.g. `..`, encoded `%2e%2e`) are
/// rejected с `DecoyError::PathTraversal`.  Caller (Phase 5b) maps это
/// к а 400 response.
pub struct StaticDirectoryDecoy {
    root_dir: PathBuf,
    index_file: String,
}

impl StaticDirectoryDecoy {
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        Self {
            root_dir: root_dir.into(),
            index_file: "index.html".to_owned(),
        }
    }

    pub fn with_index_file(mut self, name: impl Into<String>) -> Self {
        self.index_file = name.into();
        self
    }

    /// Resolve а URL path к а file path within `root_dir`, rejecting
    /// traversal attempts.  Path normalization:
    /// - `/` → `<root>/index.html`
    /// - `/foo/` → `<root>/foo/index.html`
    /// - `/foo/bar.html` → `<root>/foo/bar.html`
    /// - Rejects: `..`, `\0`, absolute paths, control bytes.
    fn resolve_path(&self, url_path: &str) -> Result<PathBuf, DecoyError> {
        if url_path.contains("\0") || url_path.bytes().any(|b| b < 0x20 && b != b'\t') {
            return Err(DecoyError::PathTraversal(url_path.to_owned()));
        }
        let trimmed = url_path.trim_start_matches('/');
        // Split into segments и reject `..` / empty-segment-as-traversal.
        let mut segments: Vec<&str> = Vec::new();
        for seg in trimmed.split('/') {
            match seg {
                "" => {}
                "." => {}
                ".." => return Err(DecoyError::PathTraversal(url_path.to_owned())),
                s => segments.push(s),
            }
        }
        let mut path = self.root_dir.clone();
        for seg in &segments {
            path.push(seg);
        }
        // Trailing-slash или empty path → use index file.
        if url_path.ends_with('/') || segments.is_empty() {
            path.push(&self.index_file);
        }
        Ok(path)
    }

    /// Best-effort Content-Type от file extension.  Returns generic
    /// `application/octet-stream` для unknown extensions.
    fn content_type_from_extension(path: &Path) -> &'static str {
        match path.extension().and_then(|e| e.to_str()) {
            Some("html" | "htm") => "text/html; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("js") => "application/javascript; charset=utf-8",
            Some("json") => "application/json; charset=utf-8",
            Some("xml") => "application/xml; charset=utf-8",
            Some("txt") => "text/plain; charset=utf-8",
            Some("png") => "image/png",
            Some("jpg" | "jpeg") => "image/jpeg",
            Some("gif") => "image/gif",
            Some("svg") => "image/svg+xml",
            Some("ico") => "image/x-icon",
            Some("webp") => "image/webp",
            Some("pdf") => "application/pdf",
            Some("woff") => "font/woff",
            Some("woff2") => "font/woff2",
            _ => "application/octet-stream",
        }
    }
}

#[async_trait]
impl DecoyProvider for StaticDirectoryDecoy {
    async fn respond(&self, method: &str, path: &str) -> Result<DecoyResponse, DecoyError> {
        if !matches!(method, "GET" | "HEAD") {
            return Ok(DecoyResponse::bad_request_html());
        }
        let resolved = match self.resolve_path(path) {
            Ok(p) => p,
            Err(DecoyError::PathTraversal(_)) => {
                return Ok(DecoyResponse::not_found_html());
            }
            Err(e) => return Err(e),
        };

        match tokio::fs::read(&resolved).await {
            Ok(body) => {
                let ct = Self::content_type_from_extension(&resolved);
                let body = if method == "HEAD" { Vec::new() } else { body };
                Ok(DecoyResponse {
                    status: 200,
                    content_type: ct.to_owned(),
                    body,
                    headers: Vec::new(),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(DecoyResponse::not_found_html())
            }
            Err(e) => Err(DecoyError::Io(e)),
        }
    }
}

// ── ReverseProxyDecoy ───────────────────────────────────────────────────────

/// Proxies decoy requests к а real HTTP backend (e.g., локальный nginx
/// serving а neutral cached site).  **Highest realism** decoy mode:
/// responses include actual server's `Server:` header, ETag, Cache-Control,
/// Content-Length matching real file sizes — DPI scrutiny of headers
/// reveals nothing distinguishing от а regular HTTPS site.
///
/// ## Setup recommendation
///
/// Operator runs local nginx serving а snapshot of а neutral website
/// (status dashboard, dev blog, open-data archive).  Configure
/// `ReverseProxyDecoy::new("http://127.0.0.1:8080")`.  Webtunnel
/// forwards all decoy-mode requests there и returns the backend's
/// response verbatim к probe clients.
///
/// ## Constraints
///
/// - Backend MUST be HTTP/1.1 (HTTP/2 not implemented здесь).
/// - Backend SHOULD bind on loopback only — exposing the backend
///   directly defeats its purpose.
/// - Default 5s connect/read timeout protects against а slow backend
///   tarpitting scanner requests.
pub struct ReverseProxyDecoy {
    backend: String,
    timeout: std::time::Duration,
}

impl ReverseProxyDecoy {
    /// `backend` like `"http://127.0.0.1:8080"`.
    pub fn new(backend: impl Into<String>) -> Self {
        Self {
            backend: backend.into(),
            timeout: std::time::Duration::from_secs(5),
        }
    }

    pub fn with_timeout(mut self, t: std::time::Duration) -> Self {
        self.timeout = t;
        self
    }

    /// Parse backend URL into (host, port, path-prefix).  Supports
    /// `http://host:port` и `http://host:port/prefix`.
    fn parse_backend(&self) -> Result<(String, u16, String), DecoyError> {
        let trimmed = self.backend.trim_start_matches("http://");
        let (host_port, prefix) = match trimmed.find('/') {
            Some(i) => (&trimmed[..i], &trimmed[i..]),
            None => (trimmed, "/"),
        };
        let (host, port_s) = match host_port.rfind(':') {
            Some(i) => (&host_port[..i], &host_port[i + 1..]),
            None => (host_port, "80"),
        };
        let port: u16 = port_s
            .parse()
            .map_err(|_| DecoyError::NotFound(format!("bad backend port in {}", self.backend)))?;
        Ok((host.to_owned(), port, prefix.to_owned()))
    }
}

#[async_trait]
impl DecoyProvider for ReverseProxyDecoy {
    async fn respond(&self, method: &str, path: &str) -> Result<DecoyResponse, DecoyError> {
        use hyper_util::client::legacy::Client;
        use hyper_util::rt::TokioExecutor;

        let (host, port, prefix) = self.parse_backend()?;
        let combined_path = if prefix == "/" {
            path.to_owned()
        } else {
            format!("{}{}", prefix.trim_end_matches('/'), path)
        };

        let connector = hyper_util::client::legacy::connect::HttpConnector::new();
        let client = Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(connector);
        let uri = format!("http://{host}:{port}{combined_path}")
            .parse::<hyper::Uri>()
            .map_err(|e| DecoyError::NotFound(format!("bad URI: {e}")))?;

        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("host", format!("{host}:{port}"))
            .body(Empty::<Bytes>::new())
            .map_err(|e| DecoyError::NotFound(format!("build request: {e}")))?;

        let fut = client.request(req);
        let resp = tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| DecoyError::NotFound("backend timeout".to_owned()))?
            .map_err(|e| DecoyError::NotFound(format!("backend error: {e}")))?;

        let status = resp.status().as_u16();
        let mut content_type = "application/octet-stream".to_owned();
        let mut extra_headers: Vec<(String, String)> = Vec::new();
        for (k, v) in resp.headers().iter() {
            let name = k.as_str().to_ascii_lowercase();
            if let Ok(value_str) = v.to_str() {
                if name == "content-type" {
                    content_type = value_str.to_owned();
                } else if !matches!(
                    name.as_str(),
                    "content-length" | "transfer-encoding" | "connection"
                ) {
                    // Copy non-hop-by-hop headers через.
                    extra_headers.push((k.as_str().to_owned(), value_str.to_owned()));
                }
            }
        }
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| DecoyError::NotFound(format!("read body: {e}")))?
            .to_bytes()
            .to_vec();
        // HEAD: drop body.
        let body = if method == "HEAD" { Vec::new() } else { body };
        Ok(DecoyResponse {
            status,
            content_type,
            body,
            headers: extra_headers,
        })
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_string_decoy_serves_body() {
        let d = StaticStringDecoy::new("<h1>Test Site</h1>");
        let r = d.respond("GET", "/").await.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.content_type, "text/html; charset=utf-8");
        assert_eq!(r.body, b"<h1>Test Site</h1>");
    }

    #[tokio::test]
    async fn static_string_decoy_serves_same_for_any_path() {
        let d = StaticStringDecoy::new("<h1>Same Body</h1>");
        let r1 = d.respond("GET", "/").await.unwrap();
        let r2 = d.respond("GET", "/foo/bar").await.unwrap();
        assert_eq!(r1.body, r2.body);
    }

    #[tokio::test]
    async fn static_string_decoy_post_returns_400() {
        let d = StaticStringDecoy::new("body");
        let r = d.respond("POST", "/").await.unwrap();
        assert_eq!(r.status, 400);
    }

    #[tokio::test]
    async fn static_directory_decoy_serves_index() {
        let tmp = tempfile_dir().await;
        tokio::fs::write(tmp.path.join("index.html"), b"<h1>Index</h1>")
            .await
            .unwrap();

        let d = StaticDirectoryDecoy::new(&tmp.path);
        let r = d.respond("GET", "/").await.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.content_type, "text/html; charset=utf-8");
        assert_eq!(r.body, b"<h1>Index</h1>");
    }

    #[tokio::test]
    async fn static_directory_decoy_serves_subfile() {
        let tmp = tempfile_dir().await;
        tokio::fs::create_dir(tmp.path.join("blog")).await.unwrap();
        tokio::fs::write(tmp.path.join("blog/post1.html"), b"<p>Post</p>")
            .await
            .unwrap();

        let d = StaticDirectoryDecoy::new(&tmp.path);
        let r = d.respond("GET", "/blog/post1.html").await.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"<p>Post</p>");
    }

    #[tokio::test]
    async fn static_directory_decoy_returns_404() {
        let tmp = tempfile_dir().await;
        let d = StaticDirectoryDecoy::new(&tmp.path);
        let r = d.respond("GET", "/missing.html").await.unwrap();
        assert_eq!(r.status, 404);
        assert_eq!(r.content_type, "text/html; charset=utf-8");
    }

    #[tokio::test]
    async fn static_directory_decoy_rejects_traversal() {
        let tmp = tempfile_dir().await;
        tokio::fs::write(tmp.path.join("safe.html"), b"<h1>Safe</h1>")
            .await
            .unwrap();
        let d = StaticDirectoryDecoy::new(&tmp.path);

        // Path traversal attempt — should return 404 (not the file outside).
        let r = d.respond("GET", "/../etc/passwd").await.unwrap();
        assert_eq!(r.status, 404);

        // Encoded traversal — naive %2e%2e not decoded by us, so just а 404.
        let r2 = d.respond("GET", "/foo/../../etc/passwd").await.unwrap();
        assert_eq!(r2.status, 404);
    }

    #[tokio::test]
    async fn static_directory_decoy_content_types() {
        let tmp = tempfile_dir().await;
        for (file, content) in [
            ("page.html", "<html/>"),
            ("style.css", "body{}"),
            ("script.js", "// js"),
            ("data.json", "{}"),
        ] {
            tokio::fs::write(tmp.path.join(file), content)
                .await
                .unwrap();
        }

        let d = StaticDirectoryDecoy::new(&tmp.path);
        assert!(
            d.respond("GET", "/page.html")
                .await
                .unwrap()
                .content_type
                .starts_with("text/html")
        );
        assert!(
            d.respond("GET", "/style.css")
                .await
                .unwrap()
                .content_type
                .starts_with("text/css")
        );
        assert!(
            d.respond("GET", "/script.js")
                .await
                .unwrap()
                .content_type
                .starts_with("application/javascript")
        );
        assert!(
            d.respond("GET", "/data.json")
                .await
                .unwrap()
                .content_type
                .starts_with("application/json")
        );
    }

    #[tokio::test]
    async fn static_directory_head_returns_empty_body() {
        let tmp = tempfile_dir().await;
        tokio::fs::write(tmp.path.join("index.html"), b"<h1>Hi</h1>")
            .await
            .unwrap();
        let d = StaticDirectoryDecoy::new(&tmp.path);
        let r = d.respond("HEAD", "/").await.unwrap();
        assert_eq!(r.status, 200);
        assert!(r.body.is_empty(), "HEAD should not return body");
    }

    #[tokio::test]
    async fn static_directory_subdir_resolves_index() {
        let tmp = tempfile_dir().await;
        tokio::fs::create_dir(tmp.path.join("blog")).await.unwrap();
        tokio::fs::write(tmp.path.join("blog/index.html"), b"<p>Blog</p>")
            .await
            .unwrap();
        let d = StaticDirectoryDecoy::new(&tmp.path);
        let r = d.respond("GET", "/blog/").await.unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"<p>Blog</p>");
    }

    // ── test helpers ─────────────────────────────────────────────────

    struct TempDir {
        path: PathBuf,
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    async fn tempfile_dir() -> TempDir {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let pid = std::process::id();
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("veil-webtunnel-test-{pid}-{n}"));
        tokio::fs::create_dir_all(&path).await.unwrap();
        TempDir { path }
    }
}
