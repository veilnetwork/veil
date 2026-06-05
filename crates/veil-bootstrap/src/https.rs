//! HTTPS bootstrap fetch.
//!
//! Fetches `Vec<BootstrapPeer>` from an operator-configured HTTPS URL.
//! The URL is just a static endpoint serving a JSON body in the same
//! format produced by [`super::seeds::encode_bootstrap_bundle`] —
//! operator can host it on any web server, CDN, S3 bucket, GitHub
//! Pages, IPFS gateway, etc.
//!
//! # Why this layer matters for censorship resistance
//!
//! The bootstrap chain layers (in order of attempt) are:
//!
//! 1. `config.bootstrap_peers` — operator-curated, static
//! 2. `node::bootstrap::builtin_seeds` — compile-time, requires rebuild
//! 3. **HTTPS bootstrap (this module)** — operator-curated, hot-rotatable
//! 4. DNS TXT `_veil._bootstrap.<domain>` — operator-curated, hot-rotatable
//! 5. `DiscoveredPeerCache` — handshake-confirmed, per-user
//!
//! HTTPS bootstrap is the easiest layer to **rotate without a binary
//! rebuild**: operator updates the JSON file, and every new node that
//! starts up will pick up the new seed list immediately. An
//! authoritarian-state censor would have to either:
//!
//! * Block the operator's HTTPS hostname (which CDN-fronting + multiple
//!   hostnames can defeat — `cdn1.example.com`, `cdn2.example.com`, etc).
//! * Block the entire CDN (high collateral damage — Cloudflare /
//!   CloudFront / Fastly host millions of legitimate sites).
//! * Compromise the cert authority (out-of-band attack, expensive).
//!
//! Compared with DNS TXT (layer 4) the HTTPS layer adds CDN
//! resilience (DNS is single-target by design) and is harder to
//! poison via on-path DNS interception (TLS verifies the server cert).
//!
//! # No new dependencies
//!
//! The fetch is a hand-rolled HTTP/1.1 GET over а PKI-verified TLS
//! handshake ([`veil_transport::tls::connect_pki_verified_https_stream`]
//! or [`veil_transport::tls_boring::connect_pki_verified_https_stream`]
//! under `--features tls-boring`). audit follow-up
//!the bootstrap path was decoupled from the veil
//! peer-transport TLS profile — the latter accepts self-signed certs
//! because trust binds к session-layer node_id, but а CDN target
//! requires real Web PKI verification (Mozilla's webpki-roots OR
//! `set_default_verify_paths`) plus hostname matching, otherwise а
//! MITM с а stale-but-veil-trusted cert could replay or DoS the
//! HTTPS fetch.
//!
//! Hand-rolled HTTP is intentionally minimal:
//! * GET only (no POST / PUT / etc).
//! * `Connection: close` — server closes after response, so we
//!   read-to-end with a hard byte cap.
//! * Status line `HTTP/1.x 200` accepted, anything else rejected.
//! * Body parsed as JSON `Vec<BootstrapPeer>` via the existing
//!   [`super::seeds::decode_bootstrap_bundle`].
//!
//! No chunked-encoding parsing, no compression, no redirects, no
//! cookies, no auth. Operators that need any of those are
//! out-of-scope; they should host a redirect-free static endpoint.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use veil_transport::TransportContext;
use veil_types::BootstrapPeer;

// bootstrap fetches MUST use the PKI-
// verified TLS path (`connect_pki_verified_https_stream`) — а CDN
// target requires real certificate-chain verification, NOT veil's
// node-id-bound trust which accepts self-signed certs. Pre-fix, both
// the rustls и tls-boring paths shared `connect_tls_client_stream`
// с veil's peer trust profile, leaving HTTPS bootstrap susceptible
// к MITM с а stale-but-still-veil-trusted cert. Bootstrap bundles
// are Ed25519-signed so payload integrity was preserved, но an MITM
// could still serve replays of older signed bundles OR break TLS
// sessions for DoS. Now bootstrap explicitly uses Mozilla's
// webpki-roots (rustls) OR boringssl `set_default_verify_paths`
// (tls-boring) с `verify_hostname(true)`.
#[cfg(not(feature = "tls-boring"))]
use veil_transport::tls::connect_pki_verified_https_stream;
#[cfg(feature = "tls-boring")]
use veil_transport::tls_boring::connect_pki_verified_https_stream;

/// Hard cap on response body size — generous enough for a few hundred
/// `BootstrapPeer` entries (~250 B each) but small enough that an
/// adversarial server can't exhaust client memory.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Header overhead allowance added to the body cap to compute the
/// total-bytes ceiling. Headers are typically < 1 KiB; this slack
/// lets even a chatty CDN return.
pub const HTTP_HEADERS_SLACK_BYTES: usize = 8 * 1024;

/// Default timeout for the entire fetch (TLS handshake + GET +
/// read-to-end). Lower than the typical TCP connect timeout because
/// HTTPS bootstrap is a "best-effort layer" — if it can't complete in
/// 10 s the caller should fall through to the next layer rather than
/// block startup.
pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// follow-up: timeout for a SINGLE `read` call
/// during the body-streaming loop. Defends against slow-loris style
/// attacks where the server stays under the global
/// [`DEFAULT_FETCH_TIMEOUT`] but dribbles bytes at < 1 B/sec to
/// occupy a client connection slot indefinitely. 10 s is generous
/// for slow real-world links (3G in poor coverage) but rejects
/// attacker pacing. The wrapping caller may pass a longer global
/// timeout [`fetch_bytes_https_with_progress_timeout`] for
/// large-binary fetches where the headline `DEFAULT_FETCH_TIMEOUT`
/// is too tight overall.
pub const DEFAULT_CHUNK_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// follow-up: longer global timeout used when
/// downloading large binaries (release artefacts). 10 MiB at 100
/// kbit/s ≈ 800 s; this ceiling tolerates very slow links while
/// still bounding worst case. The per-chunk timeout
/// ([`DEFAULT_CHUNK_READ_TIMEOUT`]) is the slow-loris defence on
/// top of this.
pub const DEFAULT_BINARY_FETCH_TIMEOUT: Duration = Duration::from_secs(900);

/// User-Agent header sent in the GET. Intentionally generic — looks
/// like a real browser to a casual log scan, but is not designed to
/// fool a determined fingerprinter (TLS handshake shape carries the
/// censorship-evasion load via `tls-boring`, not the User-Agent).
const USER_AGENT: &str = "Mozilla/5.0 (compatible; veil-bootstrap)";

#[derive(Debug, Clone, thiserror::Error)]
pub enum HttpsBootstrapError {
    #[error("malformed URL `{0}`: {1}")]
    BadUrl(String, String),
    #[error("transport: {0}")]
    Transport(String),
    #[error("write request: {0}")]
    Write(String),
    #[error("read response: {0}")]
    Read(String),
    #[error("response too large (> {limit} B); aborted at {got} B")]
    TooLarge { limit: usize, got: usize },
    /// server's `Content-Length` header
    /// declared a body bigger than `max_body_bytes` — abort BEFORE
    /// reading the body so we never allocate the oversized buffer.
    #[error(
        "Content-Length header declares {declared} B > limit {limit} B; aborted before body read"
    )]
    ContentLengthTooLarge { declared: usize, limit: usize },
    /// a single `read` call during the
    /// body-streaming loop took longer than [`DEFAULT_CHUNK_READ_TIMEOUT`]
    /// — slow-loris defence.
    #[error("body read stalled (> {0:?} between chunks); slow-loris abort")]
    ChunkTimeout(Duration),
    /// response had multiple `Content-Length`
    /// headers with conflicting values. RFC 7230 §3.3.3 requires
    /// recipients к reject such messages — they are а classic HTTP
    /// request-smuggling vector when а proxy и origin disagree on
    /// which value к honor. Even in our threat model (no proxy in
    /// front of the daemon), the strict interpretation is cheap
    /// insurance against future deployments that DO add а proxy.
    /// Previously parse_content_length silently returned None и we
    /// fell through к the streaming cap; now we abort с this error.
    #[error("conflicting Content-Length headers — rejecting per RFC 7230 §3.3.3")]
    ContentLengthConflict,
    #[error("missing `\\r\\n\\r\\n` between headers and body in response")]
    NoBodySeparator,
    #[error("bad status line `{0}`")]
    BadStatusLine(String),
    #[error("unexpected status: {0}")]
    BadStatus(u16),
    #[error("parse bundle: {0}")]
    ParseBundle(String),
    /// Fetched body is а raw JSON `Vec<BootstrapPeer>` (legacy unsigned
    /// shape), but the active [`BootstrapHttpsPolicy`] requires а
    /// signed envelope.  TLS gives channel auth ("bytes came от the
    /// CDN endpoint без on-path tampering") but not endpoint auth —
    /// если CDN, CA, hosting account или mirror endpoint is
    /// compromised, attacker swaps the JSON для own peer list.
    /// Signed bundles defend against this класса compromise.
    #[error(
        "policy requires signed bundle but endpoint returned raw JSON; \
         configure `trusted_bundle_issuer_pubkey` to enable signed bundles, \
         or set `legacy_allow_unsigned_bootstrap = true` for dev/testnet"
    )]
    SignedBundleRequired,
    /// Signed-envelope decode/verify failed (wrong issuer pubkey,
    /// tampered envelope, expired bundle, или unsupported sig algo).
    #[error("signed bundle verify: {0}")]
    SignedBundleVerify(#[from] crate::signed_bundle::SignedBundleError),
    #[error("timed out after {0:?}")]
    Timeout(Duration),
}

/// Policy governing how [`fetch_seeds_https_with_policy`] handles the
/// response body.
///
/// The default ([`BootstrapHttpsPolicy::signed_required`] when an issuer
/// pubkey pinned, [`BootstrapHttpsPolicy::signed_preferred`] without
/// pinning) protects against compromised TLS endpoints (CDN, CA,
/// hosting account, mirror endpoint).  Raw-JSON fallback is opt-in via
/// [`BootstrapHttpsPolicy::legacy_allow_unsigned`] для dev/testnet
/// builds що haven't yet provisioned а signed bundle.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BootstrapHttpsPolicy {
    /// Pinned issuer pubkey (base64).  When `Some`, signed bundles whose
    /// embedded `issuer_pk` does NOT match this value ара rejected.
    /// `None` accepts any internally-consistent signature (envelope
    /// tamper-proof но не authenticated WHO signed it — same degraded
    /// mode as `verify_signed_bundle(.., None, ..)`).
    pub trusted_issuer_pubkey: Option<String>,
    /// Если the fetched body is raw JSON (no signed-bundle magic),
    /// accept it?  Default `false`.  Set к `true` ONLY для dev/testnet
    /// configs що haven't yet provisioned а signed bundle.  Production
    /// builds should reject unsigned bodies к close the TLS-endpoint-
    /// compromise vector.
    pub legacy_allow_unsigned: bool,
}

impl BootstrapHttpsPolicy {
    /// Strict policy: require а signed envelope, pin issuer pubkey,
    /// reject raw JSON.  This is the safe default для production.
    pub fn signed_required(issuer_pubkey: impl Into<String>) -> Self {
        Self {
            trusted_issuer_pubkey: Some(issuer_pubkey.into()),
            legacy_allow_unsigned: false,
        }
    }

    /// Policy без pinning: accept signed envelopes що ара internally
    /// consistent (envelope tamper-proof) но без authenticating the
    /// issuer.  Raw JSON still rejected.  Use only когда the operator
    /// pubkey cannot be pinned out-of-band.
    pub fn signed_preferred() -> Self {
        Self {
            trusted_issuer_pubkey: None,
            legacy_allow_unsigned: false,
        }
    }

    /// LEGACY policy: accept raw JSON без any signature.  TLS gives
    /// channel auth only — compromised CDN, CA, hosting account, или
    /// mirror endpoint can substitute а malicious peer list and the
    /// fetcher will accept it.  Use ONLY для dev/testnet builds що
    /// haven't yet provisioned а signed bundle.
    pub fn legacy_unsigned() -> Self {
        Self {
            trusted_issuer_pubkey: None,
            legacy_allow_unsigned: true,
        }
    }
}

/// Fetch and parse bootstrap peers from `url`, applying `policy` к
/// govern signed-vs-unsigned handling.
///
/// `url` must be `https://host[:port]/path`; `http://` is intentionally
/// rejected.  Body is detected as signed (magic `"SB"` prefix) или raw
/// JSON; signed bundles ара verified against `policy.trusted_issuer_pubkey`
/// when set.  Raw JSON is accepted only когда `policy.legacy_allow_unsigned`
/// is `true`.
///
/// Bounded by [`DEFAULT_FETCH_TIMEOUT`] and [`MAX_RESPONSE_BYTES`].
pub async fn fetch_seeds_https_with_policy(
    url: &str,
    ctx: &TransportContext,
    policy: &BootstrapHttpsPolicy,
) -> Result<Vec<BootstrapPeer>, HttpsBootstrapError> {
    let body = fetch_bytes_https(url, ctx, MAX_RESPONSE_BYTES).await?;
    decode_with_policy(&body, policy)
}

/// Apply `policy` к а fetched body.  Public for unit-testing the
/// signed/unsigned decision matrix without spinning up an HTTPS server.
pub fn decode_with_policy(
    body: &[u8],
    policy: &BootstrapHttpsPolicy,
) -> Result<Vec<BootstrapPeer>, HttpsBootstrapError> {
    // Signed-bundle wire detection: leading 2 bytes ара the magic
    // `"SB"` (see `signed_bundle::SIGNED_BUNDLE_MAGIC`).  An unsigned
    // JSON bundle starts с `[` (array) or whitespace, neither matches.
    let looks_signed = body.len() >= 2 && &body[..2] == crate::signed_bundle::SIGNED_BUNDLE_MAGIC;
    if looks_signed {
        let envelope = crate::signed_bundle::decode_signed_bundle(body)
            .map_err(HttpsBootstrapError::SignedBundleVerify)?;
        // M-20 fail-closed: a clock before UNIX_EPOCH would let now_unix=0
        // pass the freshness check (`now > expiry` false for any positive
        // expiry), accepting arbitrarily old signed bundles. Reject instead.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| {
                HttpsBootstrapError::Transport(
                    "system clock is before UNIX_EPOCH — refusing to verify \
                     signed bootstrap bundle (cannot evaluate freshness)"
                        .to_string(),
                )
            })?;
        return crate::signed_bundle::verify_signed_bundle(
            &envelope,
            policy.trusted_issuer_pubkey.as_deref(),
            now_unix,
        )
        .map_err(HttpsBootstrapError::SignedBundleVerify);
    }
    if !policy.legacy_allow_unsigned {
        return Err(HttpsBootstrapError::SignedBundleRequired);
    }
    super::seeds::decode_bootstrap_bundle(body).map_err(HttpsBootstrapError::ParseBundle)
}

/// Fetch a JSON-bundle [`BootstrapPeer`] from `url` and return the
/// parsed peers. `url` must be `https://host[:port]/path`; `http://`
/// is intentionally rejected — bootstrap MUST verify the server cert
/// to defend against on-path tampering.
///
/// Bounded by [`DEFAULT_FETCH_TIMEOUT`] and [`MAX_RESPONSE_BYTES`].
///
/// **Legacy unsigned mode** — accepts raw JSON без а signed envelope.
/// Use [`fetch_seeds_https_with_policy`] in new code so production
/// builds can require signed bundles (closes the TLS-endpoint-
/// compromise vector — see [`BootstrapHttpsPolicy`]).  Kept для
/// existing call sites + tests; service-task wiring switches к the
/// policy-aware version once `legacy_allow_unsigned_bootstrap` config
/// is in place.
pub async fn fetch_seeds_https(
    url: &str,
    ctx: &TransportContext,
) -> Result<Vec<BootstrapPeer>, HttpsBootstrapError> {
    fetch_seeds_https_with_policy(url, ctx, &BootstrapHttpsPolicy::legacy_unsigned()).await
}

/// Fetch + verify a bootstrap seed bundle from an `http://<host>.onion/path`
/// URL **through** the Tor SOCKS5 proxy at `proxy_url` (e.g.
/// `socks5://127.0.0.1:9050`).  Deferred backlog item 481.4 — the operator's
/// censorship-resistance escape hatch when every clearnet CDN/DNS bootstrap
/// layer is blocked.
///
/// # Trust model — why this is safe over plaintext HTTP
///
/// Three independent layers stack here:
/// 1. **Tor transport**: connecting to `<key>.onion` cryptographically proves
///    (via Tor's rendezvous) that you reached the holder of that onion key,
///    and the circuit is encrypted end-to-end. No TLS / public-CA cert exists
///    or is needed — that's why the URL is `http://`, not `https://`.
/// 2. **Signed bundle**: this path **always requires a signed envelope** and
///    never accepts raw JSON, regardless of any `legacy_allow_unsigned`
///    setting elsewhere — the signature binds the seed list to the trusted
///    issuer independently of which `.onion` served it.
/// 3. **Issuer pinning**: when `trusted_issuer_pubkey` is `Some`, the bundle's
///    embedded issuer must match (`signed_required`); otherwise any
///    internally-consistent signature is accepted (`signed_preferred`).
///
/// Bounded by [`DEFAULT_FETCH_TIMEOUT`] and [`MAX_RESPONSE_BYTES`].
pub async fn fetch_seeds_via_tor(
    url: &str,
    proxy_url: &str,
    trusted_issuer_pubkey: Option<&str>,
) -> Result<Vec<BootstrapPeer>, HttpsBootstrapError> {
    // Force a signed policy for .onion — never legacy_unsigned (see the
    // trust-model note above): pin the issuer when configured, else accept any
    // valid signature.
    let policy = match trusted_issuer_pubkey {
        Some(pk) => BootstrapHttpsPolicy::signed_required(pk),
        None => BootstrapHttpsPolicy::signed_preferred(),
    };
    let body = fetch_bytes_via_tor(url, proxy_url, MAX_RESPONSE_BYTES).await?;
    decode_with_policy(&body, &policy)
}

/// Generic Tor-tunnelled GET returning raw response bytes — the `.onion`
/// counterpart of [`fetch_bytes_https`].  Opens a plaintext SOCKS5 tunnel to
/// the `.onion` host through `proxy_url` and speaks the same hand-rolled
/// HTTP/1.1 GET over it (no TLS).  `url` must be `http://<host>.onion[:port]/path`.
///
/// Bounded by [`DEFAULT_FETCH_TIMEOUT`].
pub async fn fetch_bytes_via_tor(
    url: &str,
    proxy_url: &str,
    max_body_bytes: usize,
) -> Result<Vec<u8>, HttpsBootstrapError> {
    timeout(
        DEFAULT_FETCH_TIMEOUT,
        fetch_bytes_via_tor_inner(url, proxy_url, max_body_bytes),
    )
    .await
    .map_err(|_| HttpsBootstrapError::Timeout(DEFAULT_FETCH_TIMEOUT))?
}

async fn fetch_bytes_via_tor_inner(
    url: &str,
    proxy_url: &str,
    max_body_bytes: usize,
) -> Result<Vec<u8>, HttpsBootstrapError> {
    let parsed = parse_onion_url(url)?;
    // The .onion hostname is handed to the proxy as a SOCKS5 domain address
    // (ATYP 0x03) and resolved by Tor — never resolved locally.
    let stream = veil_transport::socks::connect_socks5_stream(proxy_url, parsed.host, parsed.port)
        .await
        .map_err(|e| {
            HttpsBootstrapError::Transport(format!(
                "Tor SOCKS dial via {proxy_url} to {} failed: {e}",
                parsed.host
            ))
        })?;
    http_get_over_stream(stream, parsed.host, parsed.path, max_body_bytes).await
}

/// Outcome of a multi-URL HTTPS bootstrap fetch with failover +
/// aggregation.
#[derive(Debug, Clone, PartialEq)]
pub struct AggregatedSeeds {
    /// Concatenated seeds from every URL that returned `Ok`.
    /// Per-URL responses are appended in input order; deduplication
    /// happens at the runtime level (caller filter chain in
    /// `service_tasks::spawn_bootstrap_https_task`) since dedup
    /// criteria depend on the runtime's view of what's "already
    /// known".
    pub seeds: Vec<BootstrapPeer>,
    /// One entry per URL that returned `Err`. Tuple shape
    /// `(url, error_message)` so caller can log structured
    /// per-URL failures without re-running the fetcher.
    pub per_url_errors: Vec<(String, String)>,
    /// Per-URL success counts (`(url, peer_count)` tuples). Useful
    /// for the runtime log surface — operator wants to see "url X
    /// returned 0 seeds" (configured-but-empty) distinct from
    /// "url X failed" (configured-but-network-error).
    pub per_url_seed_counts: Vec<(String, usize)>,
}

impl AggregatedSeeds {
    pub fn is_empty(&self) -> bool {
        self.seeds.is_empty()
    }
    pub fn total_seeds(&self) -> usize {
        self.seeds.len()
    }
    pub fn url_count(&self) -> usize {
        self.per_url_seed_counts.len() + self.per_url_errors.len()
    }
    pub fn failed_url_count(&self) -> usize {
        self.per_url_errors.len()
    }
}

/// Fetch + aggregate seeds from multiple HTTPS bootstrap URLs.
///
/// **Failover semantics:** per-URL errors do NOT abort the loop —
/// every URL is tried, errors collected per-URL, successful seeds
/// concatenated. This matches contract: operators
/// configure multiple CDN URLs explicitly for redundancy under
/// censorship, so a single CDN being IP-blocked must not prevent
/// the others from contributing.
///
/// **Aggregation (not first-good-wins):** unlike the
/// `fetch_manifest_with_failover` pattern — that
/// path needs a single canonical signed manifest, so first-valid
/// wins; THIS path needs a peer pool, so multi-CDN redundancy is
/// SOURCE diversity (each operator may host different curated
/// peer subsets at different CDNs). Caller dedupes at the
/// runtime level.
///
/// Empty `urls` returns an empty `AggregatedSeeds` without
/// invoking `fetcher` — caller can short-circuit before paying
/// the spawn cost.
///
/// Generic over `F: Fn(&str) -> Fut` so unit tests can inject a
/// stub fetcher (HashMap of URL → result) without spinning up a
/// real HTTPS server. The runtime call site passes
/// `|url| fetch_seeds_https(url, &ctx)`.
pub async fn aggregate_seeds_via_failover<F, Fut>(urls: &[String], fetcher: F) -> AggregatedSeeds
where
    F: Fn(&str) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<BootstrapPeer>, HttpsBootstrapError>>,
{
    let mut seeds = Vec::new();
    let mut per_url_errors = Vec::new();
    let mut per_url_seed_counts = Vec::new();
    for url in urls {
        match fetcher(url).await {
            Ok(peers) => {
                per_url_seed_counts.push((url.clone(), peers.len()));
                seeds.extend(peers);
            }
            Err(e) => {
                per_url_errors.push((url.clone(), e.to_string()));
            }
        }
    }
    AggregatedSeeds {
        seeds,
        per_url_errors,
        per_url_seed_counts,
    }
}

/// Generic HTTPS GET that returns raw response body bytes. Same TLS
/// stack + DPI-resistant ClientHello + bounded read as
/// [`fetch_seeds_https`], but parameterised on `max_body_bytes` and
/// without JSON parsing — caller decides what to do with the bytes.
///
/// Used by the update mechanism to fetch signed
/// manifests (~600 B - 8 KiB cap) and binaries (multi-MB cap)
/// through the same TLS infrastructure.
///
/// `max_body_bytes` is the cap on response body size; the streaming
/// read limit is `max_body_bytes + HTTP_HEADERS_SLACK_BYTES` so a
/// chatty server's headers don't push us over.
///
/// Bounded by [`DEFAULT_FETCH_TIMEOUT`].
pub async fn fetch_bytes_https(
    url: &str,
    ctx: &TransportContext,
    max_body_bytes: usize,
) -> Result<Vec<u8>, HttpsBootstrapError> {
    timeout(
        DEFAULT_FETCH_TIMEOUT,
        fetch_bytes_https_inner(url, ctx, max_body_bytes),
    )
    .await
    .map_err(|_| HttpsBootstrapError::Timeout(DEFAULT_FETCH_TIMEOUT))?
}

/// same as [`fetch_bytes_https`] but uses
/// [`DEFAULT_BINARY_FETCH_TIMEOUT`] (15 min) as the global ceiling
/// — appropriate for downloading multi-MiB release artefacts over
/// slow links. Per-chunk slow-loris defence
/// ([`DEFAULT_CHUNK_READ_TIMEOUT`]) still applies inside the loop.
pub async fn fetch_binary_bytes_https(
    url: &str,
    ctx: &TransportContext,
    max_body_bytes: usize,
) -> Result<Vec<u8>, HttpsBootstrapError> {
    timeout(
        DEFAULT_BINARY_FETCH_TIMEOUT,
        fetch_bytes_https_inner(url, ctx, max_body_bytes),
    )
    .await
    .map_err(|_| HttpsBootstrapError::Timeout(DEFAULT_BINARY_FETCH_TIMEOUT))?
}

async fn fetch_bytes_https_inner(
    url: &str,
    ctx: &TransportContext,
    max_body_bytes: usize,
) -> Result<Vec<u8>, HttpsBootstrapError> {
    let parsed = parse_https_url(url)?;
    // ALPN advertises ONLY `http/1.1`. Previously
    // we listed `h2` first, claiming the server would "downgrade" — but
    // ALPN is а binding negotiation, not а suggestion. If а CDN selects
    // h2 (Cloudflare with HTTP/2-by-default-for-edge), our hand-rolled
    // HTTP/1.1 framing parser gives up reading binary HPACK frames as
    // ASCII headers. Symptom would be sporadic bootstrap/update failures
    // на specific CDN edges that prefer h2.
    //
    // DPI fingerprinting impact: minor. Modern browsers offer h2/h3
    // first, но HTTP/1.1-only is still seen widely (curl default, legacy
    // mobile, fetch libraries без h2). Anti-censorship benefit of
    // h2-in-ALPN is marginal — TLS ClientHello has many other signals
    // (cipher suites, SNI, extensions order). Until we implement а real
    // h2 client, claiming h2 capability is incorrect и harmful.
    let alpn: Vec<Vec<u8>> = vec![b"http/1.1".to_vec()];
    let stream =
        connect_pki_verified_https_stream(parsed.host, parsed.port, Some(parsed.host), &alpn, ctx)
            .await
            .map_err(|e| HttpsBootstrapError::Transport(e.to_string()))?;

    http_get_over_stream(stream, parsed.host, parsed.path, max_body_bytes).await
}

/// HTTP/1.1 GET over an already-connected stream. Pulled out so it
/// can be unit-tested against a plain TCP loopback (no TLS fixture).
///
/// `max_body_bytes` caps the response body; total streaming-read
/// limit is `max_body_bytes + HTTP_HEADERS_SLACK_BYTES`.
pub(crate) async fn http_get_over_stream<S>(
    stream: S,
    host: &str,
    path: &str,
    max_body_bytes: usize,
) -> Result<Vec<u8>, HttpsBootstrapError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    http_get_over_stream_with_timeout(
        stream,
        host,
        path,
        max_body_bytes,
        DEFAULT_CHUNK_READ_TIMEOUT,
    )
    .await
}

/// streaming HTTP GET with per-chunk timeout
/// and `Content-Length` pre-check. Same shape as
/// [`http_get_over_stream`] but exposes the per-chunk timeout for
/// callers that need a different value (binary download with very
/// slow links, etc.).
///
/// Hardening over the legacy single-pass read:
///
/// 1. **Per-chunk timeout**: each `read` is wrapped in
///    `tokio::time::timeout(chunk_timeout...)`. If a single read
///    stalls beyond the deadline, returns
///    [`HttpsBootstrapError::ChunkTimeout`]. Defends against
///    slow-loris attackers who would otherwise hold the connection
///    indefinitely under the global fetch timeout.
///
/// 2. **`Content-Length` pre-check**: as soon as the headers are
///    fully read (we see `\r\n\r\n`), parse `Content-Length`. If
///    the declared length exceeds `max_body_bytes`, abort with
///    [`HttpsBootstrapError::ContentLengthTooLarge`] BEFORE reading
///    a single byte of (potentially adversarial) body. Saves
///    bandwidth + memory on a malicious-CDN response.
///
/// 3. **Streaming cap on the body**: even with a missing or
///    understated `Content-Length`, the streaming-read loop still
///    enforces `max_body_bytes` per chunk and bails the moment the
///    total crosses the limit.
pub(crate) async fn http_get_over_stream_with_timeout<S>(
    mut stream: S,
    host: &str,
    path: &str,
    max_body_bytes: usize,
    chunk_timeout: Duration,
) -> Result<Vec<u8>, HttpsBootstrapError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let max_total_bytes = max_body_bytes.saturating_add(HTTP_HEADERS_SLACK_BYTES);
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {USER_AGENT}\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\
         \r\n",
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| HttpsBootstrapError::Write(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| HttpsBootstrapError::Write(e.to_string()))?;

    let mut buf = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 4096];
    // track whether we've already done the
    // `Content-Length` pre-check. Done once, the moment headers
    // are complete — repeated parsing per-chunk would be wasteful.
    let mut content_length_checked = false;
    loop {
        let read_fut = stream.read(&mut chunk);
        let n = match timeout(chunk_timeout, read_fut).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(HttpsBootstrapError::Read(e.to_string())),
            Err(_) => return Err(HttpsBootstrapError::ChunkTimeout(chunk_timeout)),
        };
        if n == 0 {
            break; // server closed (Connection: close honored)
        }
        if buf.len() + n > max_total_bytes {
            return Err(HttpsBootstrapError::TooLarge {
                limit: max_total_bytes,
                got: buf.len() + n,
            });
        }
        buf.extend_from_slice(&chunk[..n]);

        // as soon as the header terminator is
        // visible, parse `Content-Length` and abort if it's bigger
        // than the body cap — saves us reading (possibly
        // attacker-controlled) body in full before rejection.
        if !content_length_checked && let Some(sep) = find_subslice(&buf, b"\r\n\r\n") {
            content_length_checked = true;
            // surface conflict-rejection explicitly
            // instead of silently falling through к the streaming cap.
            match parse_content_length(&buf[..sep]) {
                Ok(Some(declared)) if declared > max_body_bytes => {
                    return Err(HttpsBootstrapError::ContentLengthTooLarge {
                        declared,
                        limit: max_body_bytes,
                    });
                }
                Ok(_) => {}
                Err(_) => return Err(HttpsBootstrapError::ContentLengthConflict),
            }
        }
    }

    let (status_code, body) = parse_http_response(&buf)?;
    if status_code != 200 {
        return Err(HttpsBootstrapError::BadStatus(status_code));
    }
    if body.len() > max_body_bytes {
        return Err(HttpsBootstrapError::TooLarge {
            limit: max_body_bytes,
            got: body.len(),
        });
    }
    Ok(body.to_vec())
}

/// parse the `Content-Length: N` header from a
/// raw header block (bytes before `\r\n\r\n`). Case-insensitive
/// header-name match per RFC 7230 §3.2.
///
/// Return semantics:
/// `Ok(Some(n))` — exactly one (or repeated-identical) header found.
/// `Ok(None)` — header absent, malformed, or non-numeric; caller
/// falls through to the streaming-cap defence (no early reject).
/// `Err` — multiple Content-Length headers with conflicting
/// values. Caller maps [`HttpsBootstrapError::ContentLengthConflict`]
/// instead of silently treating conflict as "header absent" — RFC 7230
/// §3.3.3 requires recipients to reject such messages (classic HTTP
/// request-smuggling vector when a proxy and origin disagree on which
/// value to honor).
fn parse_content_length(headers: &[u8]) -> Result<Option<usize>, ()> {
    // (HTTP request smuggling adjacency): RFC
    // 7230 §3.3.3 says a recipient MUST reject any message with
    // multiple `Content-Length` header fields with different values.
    // Even in our threat model (no proxy in front of the daemon)
    // adopting the strict interpretation is cheap insurance against
    // future deployments that DO add a proxy.
    let mut value: Option<usize> = None;
    for line in headers.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (name, raw_value) = line.split_at(colon);
        if name.eq_ignore_ascii_case(b"content-length") {
            let Ok(v_str) = std::str::from_utf8(&raw_value[1..]) else {
                continue;
            };
            let Ok(v) = v_str.trim().parse::<usize>() else {
                continue;
            };
            match value {
                None => value = Some(v),
                Some(prev) if prev == v => { /* duplicate, identical — accept */ }
                Some(_) => return Err(()), // conflict → caller maps к ContentLengthConflict
            }
        }
    }
    Ok(value)
}

/// Parse an HTTP/1.x response: returns `(status_code, body_slice)`.
/// Headers are tolerated but not parsed. Only handles
/// `Connection: close`-style responses (no chunked decoding).
fn parse_http_response(buf: &[u8]) -> Result<(u16, &[u8]), HttpsBootstrapError> {
    // Find the header/body separator.
    let sep = find_subslice(buf, b"\r\n\r\n").ok_or(HttpsBootstrapError::NoBodySeparator)?;
    let head = &buf[..sep];
    let body = &buf[sep + 4..];

    // Parse the first line: `HTTP/1.x <code> <reason>`.
    let first_line_end = find_subslice(head, b"\r\n").unwrap_or(head.len());
    let first_line = std::str::from_utf8(&head[..first_line_end])
        .map_err(|_| HttpsBootstrapError::BadStatusLine("non-utf8 status line".to_owned()))?;
    let mut it = first_line.splitn(3, ' ');
    let proto = it.next().unwrap_or("");
    let code_str = it.next().unwrap_or("");
    if !proto.starts_with("HTTP/1.") {
        return Err(HttpsBootstrapError::BadStatusLine(first_line.to_owned()));
    }
    let code: u16 = code_str
        .parse()
        .map_err(|_| HttpsBootstrapError::BadStatusLine(first_line.to_owned()))?;
    Ok((code, body))
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parsed components of an `https://host[:port]/path` URL. Path
/// defaults to `/` when omitted. Holds borrows into the original
/// URL string to avoid allocations on the bootstrap hot path.
#[derive(Debug, PartialEq)]
struct ParsedHttpsUrl<'a> {
    host: &'a str,
    port: u16,
    path: &'a str,
}

fn parse_https_url(url: &str) -> Result<ParsedHttpsUrl<'_>, HttpsBootstrapError> {
    let rest = strip_scheme_ci(url, "https").ok_or_else(|| {
        HttpsBootstrapError::BadUrl(
            url.to_owned(),
            "must start with `https://` (plain http is not allowed)".into(),
        )
    })?;
    parse_authority(url, rest, 443)
}

/// Strip a `<scheme>://` prefix **case-insensitively** (URL schemes are
/// case-insensitive per RFC 3986 §3.1).  Returns the remainder after `://`.
/// Used by both URL parsers so that the routing predicate [`is_onion_url`]
/// (which already lower-cases) and the parsers never disagree on a valid URL.
fn strip_scheme_ci<'a>(url: &'a str, scheme: &str) -> Option<&'a str> {
    let (head, rest) = url.split_once("://")?;
    head.eq_ignore_ascii_case(scheme).then_some(rest)
}

/// Parse an `http://<host>.onion[:port]/path` URL for the Tor bootstrap path.
///
/// Unlike [`parse_https_url`], plain `http://` is **required** (and
/// `https://` rejected): a `.onion` service is self-authenticating (the
/// address is the service's public key, bound by Tor's rendezvous) and the
/// Tor circuit is already encrypted, so there is no public-CA certificate to
/// verify — TLS would add nothing.  Authenticity of the seed list is enforced
/// one layer up by the **signed bundle** (see [`fetch_seeds_via_tor`]).  The
/// host MUST end with `.onion`; default port is 80.
fn parse_onion_url(url: &str) -> Result<ParsedHttpsUrl<'_>, HttpsBootstrapError> {
    let rest = strip_scheme_ci(url, "http").ok_or_else(|| {
        HttpsBootstrapError::BadUrl(
            url.to_owned(),
            "onion bootstrap URL must start with `http://` (.onion is \
             self-authenticating + Tor-encrypted; TLS is neither needed nor \
             usable on .onion)"
                .into(),
        )
    })?;
    let parsed = parse_authority(url, rest, 80)?;
    if !host_is_onion(parsed.host) {
        return Err(HttpsBootstrapError::BadUrl(
            url.to_owned(),
            "host is not a `.onion` address".into(),
        ));
    }
    Ok(parsed)
}

/// Split the post-scheme remainder `host[:port][/path]` into components,
/// applying `default_port` when no `:port` is present.  Shared by
/// [`parse_https_url`] and [`parse_onion_url`].
fn parse_authority<'a>(
    url: &str,
    rest: &'a str,
    default_port: u16,
) -> Result<ParsedHttpsUrl<'a>, HttpsBootstrapError> {
    // Reject userinfo `user@host` — credentials in the URL are a
    // common phishing/footgun pattern and we have no use for them.
    if rest.contains('@') {
        return Err(HttpsBootstrapError::BadUrl(
            url.to_owned(),
            "userinfo (`user@host`) not supported".into(),
        ));
    }
    // Authority ends at the first `/`, `?`, or `#` — matching the routing
    // predicate `is_onion_url` so the two never disagree on host extraction.
    // A `?query` / `#fragment` with NO path is treated as root `/` (origin-form
    // requires the path to start with `/`; a path-less query on a static seed
    // endpoint is degenerate, and fetching `/` beats failing outright).
    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], &rest[i..]),
        Some(i) => (&rest[..i], "/"),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(HttpsBootstrapError::BadUrl(
            url.to_owned(),
            "empty host".into(),
        ));
    }
    let (host, port) = match authority.rfind(':') {
        // No `:` → default port; or `:` inside `[ipv6]` (not handled here).
        Some(i) => {
            let port_str = &authority[i + 1..];
            let port: u16 = port_str.parse().map_err(|_| {
                HttpsBootstrapError::BadUrl(url.to_owned(), format!("invalid port `{port_str}`"))
            })?;
            (&authority[..i], port)
        }
        None => (authority, default_port),
    };
    if host.is_empty() {
        return Err(HttpsBootstrapError::BadUrl(
            url.to_owned(),
            "empty host".into(),
        ));
    }
    Ok(ParsedHttpsUrl { host, port, path })
}

/// True if `host` is a `.onion` address (case-insensitive, trailing-dot
/// tolerant).  Just a suffix check — full v3 onion validation (56 base32
/// chars) is the Tor proxy's job, not ours.
fn host_is_onion(host: &str) -> bool {
    host.trim_end_matches('.')
        .to_ascii_lowercase()
        .ends_with(".onion")
}

/// True if `url`'s host is a `.onion` address, regardless of scheme.  Used by
/// the runtime bootstrap task to route a URL through the Tor SOCKS proxy
/// instead of the direct PKI-verified HTTPS path.
pub fn is_onion_url(url: &str) -> bool {
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Drop any `userinfo@` prefix before isolating host[:port].
    let authority = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = authority
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(authority);
    host_is_onion(host)
}

/// Where a single bootstrap URL should be fetched from — the pure routing
/// decision the runtime bootstrap task makes per URL (481.4).
#[derive(Debug, PartialEq, Eq)]
pub enum BootstrapRoute<'a> {
    /// Non-`.onion` URL → the direct PKI-verified HTTPS path.
    Clearnet,
    /// `.onion` URL **and** a Tor SOCKS proxy is configured → fetch over Tor.
    Tor(&'a str),
    /// `.onion` URL but no `bootstrap_tor_socks_proxy` is set → skip
    /// (fail-soft): the caller turns this into a per-URL error so bootstrap
    /// continues with the remaining (clearnet) sources.
    OnionNoProxy,
}

/// Classify a bootstrap URL into its fetch route given the optional Tor SOCKS
/// proxy.  Pure (no I/O) so the routing decision is unit-testable independently
/// of the network: `.onion` + proxy → [`BootstrapRoute::Tor`]; `.onion` without
/// proxy → [`BootstrapRoute::OnionNoProxy`]; anything else → clearnet.
pub fn classify_bootstrap_url<'a>(url: &str, tor_proxy: Option<&'a str>) -> BootstrapRoute<'a> {
    if is_onion_url(url) {
        match tor_proxy {
            Some(proxy) => BootstrapRoute::Tor(proxy),
            None => BootstrapRoute::OnionNoProxy,
        }
    } else {
        BootstrapRoute::Clearnet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::duplex;
    use veil_types::SignatureAlgorithm;

    // ── decode_with_policy ─────────────────────────────────────────────

    fn policy_test_peer() -> Vec<BootstrapPeer> {
        vec![BootstrapPeer {
            transport: "tls://b1.example.com:9906".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned(),
            nonce: "AAAAAA==".to_owned(),
            algo: SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        }]
    }

    fn fresh_signed_bundle(peers: &[BootstrapPeer]) -> (Vec<u8>, String) {
        let kp = veil_crypto::generate_keypair(SignatureAlgorithm::Ed25519);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signed = crate::signed_bundle::sign_bundle(
            peers,
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
            now,
        )
        .unwrap();
        (signed, kp.public_key)
    }

    /// signed-required policy ACCEPTS а properly-signed bundle whose
    /// issuer matches the pinned pubkey.
    #[test]
    fn decode_signed_required_accepts_matching_pinned_issuer() {
        let peers = policy_test_peer();
        let (signed_body, issuer_pk) = fresh_signed_bundle(&peers);
        let policy = BootstrapHttpsPolicy::signed_required(issuer_pk);
        let decoded = decode_with_policy(&signed_body, &policy).unwrap();
        assert_eq!(decoded, peers);
    }

    /// signed-required policy REJECTS raw JSON (the headline B5 vector:
    /// compromised CDN serves attacker's peer list as plain JSON).
    #[test]
    fn decode_signed_required_rejects_raw_json() {
        let raw_json = crate::seeds::encode_bootstrap_bundle(&policy_test_peer()).unwrap();
        let policy = BootstrapHttpsPolicy::signed_required("anykey".to_owned());
        let err = decode_with_policy(&raw_json, &policy).unwrap_err();
        assert!(
            matches!(err, HttpsBootstrapError::SignedBundleRequired),
            "expected SignedBundleRequired, got {err:?}"
        );
    }

    /// signed-required + WRONG pinned pubkey rejects а bundle signed
    /// by а different operator (closes "sybil publishes own bundle"
    /// vector).
    #[test]
    fn decode_signed_required_rejects_wrong_issuer() {
        let peers = policy_test_peer();
        let (signed_body, _attacker_pk) = fresh_signed_bundle(&peers);
        let other_kp = veil_crypto::generate_keypair(SignatureAlgorithm::Ed25519);
        let policy = BootstrapHttpsPolicy::signed_required(other_kp.public_key);
        let err = decode_with_policy(&signed_body, &policy).unwrap_err();
        assert!(
            matches!(err, HttpsBootstrapError::SignedBundleVerify(_)),
            "expected SignedBundleVerify, got {err:?}"
        );
    }

    /// signed-preferred policy (no pinning) accepts any internally-
    /// consistent signed envelope.  Still rejects raw JSON.
    #[test]
    fn decode_signed_preferred_accepts_unpinned_signed_rejects_raw() {
        let peers = policy_test_peer();
        let (signed_body, _) = fresh_signed_bundle(&peers);
        let policy = BootstrapHttpsPolicy::signed_preferred();
        assert_eq!(decode_with_policy(&signed_body, &policy).unwrap(), peers);

        let raw_json = crate::seeds::encode_bootstrap_bundle(&peers).unwrap();
        let err = decode_with_policy(&raw_json, &policy).unwrap_err();
        assert!(matches!(err, HttpsBootstrapError::SignedBundleRequired));
    }

    /// legacy_unsigned policy (testnet/dev) accepts BOTH signed и raw.
    #[test]
    fn decode_legacy_unsigned_accepts_signed_and_raw() {
        let peers = policy_test_peer();
        let (signed_body, _) = fresh_signed_bundle(&peers);
        let policy = BootstrapHttpsPolicy::legacy_unsigned();
        assert_eq!(decode_with_policy(&signed_body, &policy).unwrap(), peers);

        let raw_json = crate::seeds::encode_bootstrap_bundle(&peers).unwrap();
        assert_eq!(decode_with_policy(&raw_json, &policy).unwrap(), peers);
    }

    // ── parse_https_url ────────────────────────────────────────────────

    #[test]
    fn epic481_4_parse_url_default_port_443() {
        let p = parse_https_url("https://example.org/").unwrap();
        assert_eq!(
            p,
            ParsedHttpsUrl {
                host: "example.org",
                port: 443,
                path: "/"
            }
        );
    }

    #[test]
    fn epic481_4_parse_url_custom_port_and_path() {
        let p = parse_https_url("https://seeds.example:8443/v1/seeds.json").unwrap();
        assert_eq!(
            p,
            ParsedHttpsUrl {
                host: "seeds.example",
                port: 8443,
                path: "/v1/seeds.json"
            },
        );
    }

    #[test]
    fn epic481_4_parse_url_no_path_defaults_to_slash() {
        let p = parse_https_url("https://example.org").unwrap();
        assert_eq!(p.path, "/");
    }

    #[test]
    fn epic481_4_parse_url_rejects_plain_http() {
        let err = parse_https_url("http://example.org/").unwrap_err();
        assert!(
            matches!(err, HttpsBootstrapError::BadUrl(..)),
            "http://… must be rejected: {err:?}"
        );
    }

    #[test]
    fn epic481_4_parse_url_rejects_userinfo() {
        let err = parse_https_url("https://user:pass@example.org/").unwrap_err();
        assert!(
            format!("{err}").contains("userinfo"),
            "userinfo must be rejected: {err}"
        );
    }

    #[test]
    fn epic481_4_parse_url_rejects_empty_host() {
        assert!(parse_https_url("https:///path").is_err());
    }

    #[test]
    fn epic481_4_parse_url_rejects_bad_port() {
        assert!(parse_https_url("https://example.org:abc/").is_err());
        assert!(parse_https_url("https://example.org:99999/").is_err());
    }

    // ── parse_http_response ────────────────────────────────────────────

    #[test]
    fn epic481_4_parse_response_extracts_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Content-Type: application/json\r\n\
                    Content-Length: 7\r\n\
                    \r\n\
                    [{\"a\":1}]";
        let (code, body) = parse_http_response(raw).unwrap();
        assert_eq!(code, 200);
        assert_eq!(body, b"[{\"a\":1}]");
    }

    #[test]
    fn epic481_4_parse_response_handles_non_200() {
        let raw = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let (code, body) = parse_http_response(raw).unwrap();
        assert_eq!(code, 404);
        assert!(body.is_empty());
    }

    #[test]
    fn epic481_4_parse_response_no_separator_errors() {
        let raw = b"HTTP/1.1 200 OK\r\nNo body separator here";
        let err = parse_http_response(raw).unwrap_err();
        assert!(
            matches!(err, HttpsBootstrapError::NoBodySeparator),
            "must surface no-separator: {err:?}"
        );
    }

    #[test]
    fn epic481_4_parse_response_rejects_non_http_proto() {
        let raw = b"GOPHER/1.0 200 OK\r\n\r\nbody";
        assert!(matches!(
            parse_http_response(raw).unwrap_err(),
            HttpsBootstrapError::BadStatusLine(_),
        ));
    }

    // ── http_get_over_stream + integration with decode_bootstrap_bundle ─

    /// Helper: produce a fake server response with the given JSON body.
    fn fake_response(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len(),
            )
            .as_bytes(),
        );
        out.extend_from_slice(body);
        out
    }

    fn sample_peers() -> Vec<BootstrapPeer> {
        vec![
            BootstrapPeer {
                transport: "tls://seed1.example:9906".to_owned(),
                public_key: "AAAAAAAA".to_owned(),
                nonce: "BBBBBBBB".to_owned(),
                algo: SignatureAlgorithm::Ed25519,
                tls_cert: None,
                tls_ca_cert: None,
            },
            BootstrapPeer {
                transport: "tls://seed2.example:9906".to_owned(),
                public_key: "CCCCCCCC".to_owned(),
                nonce: "DDDDDDDD".to_owned(),
                algo: SignatureAlgorithm::Ed25519,
                tls_cert: None,
                tls_ca_cert: None,
            },
        ]
    }

    /// Drive `http_get_over_stream` against an in-memory duplex pair —
    /// the "server" side just writes a fake HTTP response and closes.
    /// Verifies request shape AND end-to-end JSON parse.
    #[tokio::test]
    async fn epic481_4_get_over_duplex_returns_body_bytes() {
        let json = super::super::seeds::encode_bootstrap_bundle(&sample_peers()).unwrap();
        let response = fake_response(&json);

        let (client_side, mut server_side) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            // Drain the client's request before writing the response so
            // the test exercises the full request/response handshake.
            let mut req = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                let n = server_side.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&tmp[..n]);
                if find_subslice(&req, b"\r\n\r\n").is_some() {
                    break;
                }
            }
            assert!(req.starts_with(b"GET "), "expected GET request: {req:?}");
            assert!(
                find_subslice(&req, b"Host: seeds.example").is_some(),
                "Host header missing in {req:?}"
            );
            assert!(
                find_subslice(&req, b"Connection: close").is_some(),
                "Connection: close missing in {req:?}"
            );
            server_side.write_all(&response).await.unwrap();
            server_side.shutdown().await.unwrap();
        });

        let body = http_get_over_stream(
            client_side,
            "seeds.example",
            "/seeds.json",
            MAX_RESPONSE_BYTES,
        )
        .await
        .expect("http_get_over_stream");
        let peers = super::super::seeds::decode_bootstrap_bundle(&body).expect("parse");
        assert_eq!(peers, sample_peers());
        server_task.await.unwrap();
    }

    /// Server returns 503 — fetch must surface BadStatus, NOT a parse
    /// error against an empty body (the operator wants to know "the
    /// endpoint is up but unhealthy", not "JSON was bad").
    #[tokio::test]
    async fn epic481_4_get_over_duplex_propagates_non_200_status() {
        let response = b"HTTP/1.1 503 Service Unavailable\r\n\r\n";
        let (client, mut server) = duplex(8 * 1024);
        tokio::spawn(async move {
            // Drain request.
            let mut tmp = [0u8; 1024];
            while server.read(&mut tmp).await.unwrap() > 0 {
                // Read until close — duplex ends when client drops.
            }
        });
        // Push the response from a separate task so the read-loop can
        // still observe shutdown.
        let (client2, mut server2) = duplex(8 * 1024);
        let _ = client; // discard — the next call uses client2.
        tokio::spawn(async move {
            server2.write_all(response).await.unwrap();
            server2.shutdown().await.unwrap();
        });
        let err = http_get_over_stream(client2, "h", "/", MAX_RESPONSE_BYTES)
            .await
            .unwrap_err();
        assert!(
            matches!(err, HttpsBootstrapError::BadStatus(503)),
            "expected BadStatus(503), got {err:?}"
        );
    }

    /// Body of size > MAX_RESPONSE_BYTES triggers TooLarge — defends
    /// against an adversarial server returning a multi-MB blob.
    #[tokio::test]
    async fn epic481_4_oversized_response_triggers_too_large() {
        // Construct a response bigger than the streaming-read ceiling
        // (body cap + headers slack) so the overall cap fires during
        // streaming read before parse.
        let max_total = MAX_RESPONSE_BYTES + HTTP_HEADERS_SLACK_BYTES;
        let huge = vec![b'x'; max_total + 1];
        let response = fake_response(&huge);
        let (client, mut server) = duplex(max_total + 16 * 1024);
        tokio::spawn(async move {
            let mut tmp = [0u8; 1024];
            // Read request preamble once.
            loop {
                let n = server.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                if find_subslice(&tmp[..n], b"\r\n\r\n").is_some() {
                    break;
                }
            }
            server.write_all(&response).await.unwrap();
            server.shutdown().await.unwrap();
        });
        let err = http_get_over_stream(client, "h", "/", MAX_RESPONSE_BYTES)
            .await
            .unwrap_err();
        // an honest oversized server includes
        // a correct `Content-Length` in headers, so the new pre-check
        // fires first with `ContentLengthTooLarge` — strictly better
        // (rejects before reading the body). Either error variant
        // satisfies "oversized response is rejected".
        assert!(
            matches!(
                err,
                HttpsBootstrapError::TooLarge { .. }
                    | HttpsBootstrapError::ContentLengthTooLarge { .. }
            ),
            "oversized response must be rejected, got {err:?}"
        );
    }

    // ── encode_bootstrap_bundle <-> http body sanity ───────────────────

    #[test]
    fn epic481_4_bundle_format_compatible_with_layer_2_and_3() {
        // The HTTPS layer reuses the same JSON shape as the DHT
        // bootstrap bundle. Operator can serve the same
        // file from both endpoints — verify the format actually round-
        // trips through the seed bundle codec.
        let peers = sample_peers();
        let blob = super::super::seeds::encode_bootstrap_bundle(&peers).unwrap();
        let back = super::super::seeds::decode_bootstrap_bundle(&blob).unwrap();
        assert_eq!(back, peers);
    }

    /// Sanity: `find_subslice` works for both header sep and middle-of-buf.
    #[test]
    fn epic481_4_find_subslice_locates_separator() {
        assert_eq!(find_subslice(b"abc\r\n\r\nXYZ", b"\r\n\r\n"), Some(3));
        assert_eq!(find_subslice(b"no-sep-here", b"\r\n\r\n"), None);
        assert_eq!(find_subslice(b"", b"x"), None);
    }

    /// Sanity: parse_http_response gives a useful err on truncated stream.
    #[test]
    fn epic481_4_parse_truncated_stream_no_panic() {
        // Cursor is just to keep the unused Read impl happy in some
        // toolchains; this test is purely synchronous.
        let _: Cursor<&[u8]> = Cursor::new(b"");
        assert!(
            parse_http_response(b"HTTP/1.1 ").is_err(),
            "truncated status line must error, not panic"
        );
    }

    // ── multi-URL HTTPS bootstrap failover sim tests ──────────

    use std::collections::HashMap;

    /// Build a stub fetcher closure backed by a HashMap. Closures
    /// captured by `aggregate_seeds_via_failover` need to satisfy
    /// `Fn(&str) -> Fut`; we wrap the Map lookup в an immediate
    /// async block so the closure shape matches.
    type StubBootstrapFuture = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Vec<BootstrapPeer>, HttpsBootstrapError>>
                + Send,
        >,
    >;

    fn stub_fetcher(
        map: HashMap<String, Result<Vec<BootstrapPeer>, HttpsBootstrapError>>,
    ) -> impl Fn(&str) -> StubBootstrapFuture {
        move |url: &str| {
            let result = map.get(url).cloned().unwrap_or_else(|| {
                Err(HttpsBootstrapError::Transport(format!(
                    "not in stub: {url}"
                )))
            });
            Box::pin(async move { result })
        }
    }

    fn one_peer(name: &str) -> BootstrapPeer {
        BootstrapPeer {
            transport: format!("tls://{name}.example:9906"),
            public_key: format!("PK-{name}"),
            nonce: format!("NONCE-{name}"),
            algo: SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        }
    }

    #[tokio::test]
    async fn epic487_6_aggregate_empty_url_list_returns_empty_without_calling_fetcher() {
        // Caller short-circuit case: no URLs configured, no fetcher
        // calls. Verify by giving the fetcher a panic — it must
        // never run.
        let result = aggregate_seeds_via_failover(&[], |_url: &str| async {
            panic!("fetcher must not be called when urls is empty")
        })
        .await;
        assert!(result.is_empty());
        assert_eq!(result.url_count(), 0);
        assert_eq!(result.failed_url_count(), 0);
    }

    #[tokio::test]
    async fn epic487_6_aggregate_all_urls_succeed_concatenates_seeds() {
        // Three CDN URLs, each returning distinct curated peers.
        // Aggregation must concatenate ALL — operator hosts
        // different peer subsets at different CDNs for diversity.
        let mut store: HashMap<String, Result<Vec<BootstrapPeer>, HttpsBootstrapError>> =
            HashMap::new();
        store.insert(
            "https://cdn1.example/seeds".to_owned(),
            Ok(vec![one_peer("a"), one_peer("b")]),
        );
        store.insert(
            "https://cdn2.example/seeds".to_owned(),
            Ok(vec![one_peer("c")]),
        );
        store.insert(
            "https://cdn3.example/seeds".to_owned(),
            Ok(vec![one_peer("d"), one_peer("e")]),
        );

        let urls = vec![
            "https://cdn1.example/seeds".to_owned(),
            "https://cdn2.example/seeds".to_owned(),
            "https://cdn3.example/seeds".to_owned(),
        ];
        let r = aggregate_seeds_via_failover(&urls, stub_fetcher(store)).await;
        assert_eq!(r.total_seeds(), 5);
        assert_eq!(r.failed_url_count(), 0);
        assert_eq!(r.per_url_seed_counts.len(), 3);
        // Concatenation order matches input URL order.
        assert_eq!(
            r.per_url_seed_counts[0],
            ("https://cdn1.example/seeds".to_owned(), 2)
        );
        assert_eq!(
            r.per_url_seed_counts[1],
            ("https://cdn2.example/seeds".to_owned(), 1)
        );
        assert_eq!(
            r.per_url_seed_counts[2],
            ("https://cdn3.example/seeds".to_owned(), 2)
        );
    }

    #[tokio::test]
    async fn epic487_6_aggregate_per_url_failures_do_not_abort_loop() {
        // CRITICAL censorship-resistance property: if censor takes
        // down CDN1 (network error), CDN2 + CDN3 must still
        // contribute. This is the WHOLE POINT of multi-CDN config.
        let mut store: HashMap<String, Result<Vec<BootstrapPeer>, HttpsBootstrapError>> =
            HashMap::new();
        store.insert(
            "https://cdn1-blocked.example/seeds".to_owned(),
            Err(HttpsBootstrapError::Transport(
                "censor blackholed".to_owned(),
            )),
        );
        store.insert(
            "https://cdn2.example/seeds".to_owned(),
            Ok(vec![one_peer("a"), one_peer("b")]),
        );
        store.insert(
            "https://cdn3.example/seeds".to_owned(),
            Ok(vec![one_peer("c")]),
        );

        let urls = vec![
            "https://cdn1-blocked.example/seeds".to_owned(),
            "https://cdn2.example/seeds".to_owned(),
            "https://cdn3.example/seeds".to_owned(),
        ];
        let r = aggregate_seeds_via_failover(&urls, stub_fetcher(store)).await;
        assert_eq!(
            r.total_seeds(),
            3,
            "blocked CDN must NOT abort loop — other CDNs contribute"
        );
        assert_eq!(r.failed_url_count(), 1);
        assert_eq!(r.per_url_errors[0].0, "https://cdn1-blocked.example/seeds");
        assert!(
            r.per_url_errors[0].1.contains("censor blackholed"),
            "per-URL error message preserved для diagnostic logging"
        );
    }

    #[tokio::test]
    async fn epic487_6_aggregate_all_urls_fail_returns_empty_with_per_url_errors() {
        // Censor blocked all CDNs simultaneously — caller (runtime
        // bootstrap_https task) sees empty seeds + all errors so
        // it can log structured per-URL failures + signal that the
        // bootstrap layer is down.
        let mut store: HashMap<String, Result<Vec<BootstrapPeer>, HttpsBootstrapError>> =
            HashMap::new();
        store.insert(
            "https://cdn1.example/seeds".to_owned(),
            Err(HttpsBootstrapError::Timeout(
                std::time::Duration::from_secs(10),
            )),
        );
        store.insert(
            "https://cdn2.example/seeds".to_owned(),
            Err(HttpsBootstrapError::BadStatus(503)),
        );

        let urls = vec![
            "https://cdn1.example/seeds".to_owned(),
            "https://cdn2.example/seeds".to_owned(),
        ];
        let r = aggregate_seeds_via_failover(&urls, stub_fetcher(store)).await;
        assert!(r.is_empty());
        assert_eq!(r.failed_url_count(), 2);
        // Distinct error types preserved per-URL — operator
        // debugging can see "CDN1 timed out, CDN2 returned 503"
        // (different remediations needed).
        assert!(
            r.per_url_errors[0].1.contains("timed out"),
            "first URL error must surface timeout: {:?}",
            r.per_url_errors[0]
        );
        assert!(
            r.per_url_errors[1].1.contains("503"),
            "second URL error must surface 503: {:?}",
            r.per_url_errors[1]
        );
    }

    #[tokio::test]
    async fn epic487_6_aggregate_single_url_returning_empty_distinct_from_failure() {
        // CDN configured but happens to serve an empty seed bundle
        // (operator just rotated and hasn't repopulated). Must
        // distinguish from "URL failed" — operator debugging needs
        // to see "URL X is reachable + returning 0 seeds" vs "URL
        // X is unreachable".
        let mut store: HashMap<String, Result<Vec<BootstrapPeer>, HttpsBootstrapError>> =
            HashMap::new();
        store.insert("https://cdn.example/empty".to_owned(), Ok(Vec::new()));

        let urls = vec!["https://cdn.example/empty".to_owned()];
        let r = aggregate_seeds_via_failover(&urls, stub_fetcher(store)).await;
        assert!(r.is_empty(), "0 seeds total");
        assert_eq!(
            r.failed_url_count(),
            0,
            "successful-but-empty must NOT be counted as failure"
        );
        assert_eq!(
            r.per_url_seed_counts[0],
            ("https://cdn.example/empty".to_owned(), 0),
            "successful-but-empty surfaced как (url, 0) in seed counts"
        );
    }

    #[tokio::test]
    async fn epic487_6_aggregate_first_url_blocked_subsequent_succeed_classic_failover() {
        // Real-world scenario: Russia/China blocks the operator's
        // primary CDN (cdn1). Operator has CDN2 (Cloudflare) +
        // CDN3 (.onion mirror) configured. Aggregation must skip
        // cdn1 and use the others — this is THE motivating use
        // case for + 487.6.
        let mut store: HashMap<String, Result<Vec<BootstrapPeer>, HttpsBootstrapError>> =
            HashMap::new();
        store.insert(
            "https://primary.operator.example/seeds".to_owned(),
            Err(HttpsBootstrapError::Transport(
                "connection refused".to_owned(),
            )),
        );
        store.insert(
            "https://fallback.cdn.example/seeds".to_owned(),
            Ok(vec![one_peer("relay-1")]),
        );
        store.insert(
            "https://onion-mirror.example/seeds".to_owned(),
            Ok(vec![one_peer("relay-2"), one_peer("relay-3")]),
        );

        let urls = vec![
            "https://primary.operator.example/seeds".to_owned(),
            "https://fallback.cdn.example/seeds".to_owned(),
            "https://onion-mirror.example/seeds".to_owned(),
        ];
        let r = aggregate_seeds_via_failover(&urls, stub_fetcher(store)).await;
        assert_eq!(
            r.total_seeds(),
            3,
            "censor blocking primary CDN must NOT prevent fallback CDNs from contributing"
        );
        assert_eq!(r.failed_url_count(), 1);
        assert_eq!(
            r.per_url_errors[0].0,
            "https://primary.operator.example/seeds"
        );
        // Successful URLs in input order, errors collected separately.
        assert_eq!(r.per_url_seed_counts.len(), 2);
        assert_eq!(
            r.per_url_seed_counts[0].0,
            "https://fallback.cdn.example/seeds"
        );
        assert_eq!(
            r.per_url_seed_counts[1].0,
            "https://onion-mirror.example/seeds"
        );
    }

    #[tokio::test]
    async fn epic487_6_aggregate_url_count_includes_both_success_and_failure() {
        // url_count helper sums both — operator metric "I
        // configured 5 URLs, 3 succeeded, 2 failed" needs the total
        // to be 5, not just successes.
        let mut store: HashMap<String, Result<Vec<BootstrapPeer>, HttpsBootstrapError>> =
            HashMap::new();
        store.insert("https://a.example".to_owned(), Ok(vec![one_peer("x")]));
        store.insert(
            "https://b.example".to_owned(),
            Err(HttpsBootstrapError::Transport("blocked".to_owned())),
        );
        store.insert("https://c.example".to_owned(), Ok(vec![one_peer("y")]));

        let urls = vec![
            "https://a.example".to_owned(),
            "https://b.example".to_owned(),
            "https://c.example".to_owned(),
        ];
        let r = aggregate_seeds_via_failover(&urls, stub_fetcher(store)).await;
        assert_eq!(r.url_count(), 3);
    }

    // ── per-chunk timeout + Content-Length ────────

    /// A server that declares `Content-Length` larger than the body
    /// cap is rejected BEFORE reading the body — saves bandwidth +
    /// memory on a malicious-CDN response.
    #[tokio::test]
    async fn phase646_h9_content_length_oversized_rejected_before_body_read() {
        // Headers declare 10 MiB body, but the cap is 64 KiB. The
        // server doesn't even need to send the body — pre-check fires
        // as soon as headers are complete.
        let response = b"HTTP/1.1 200 OK\r\n\
                         Content-Type: application/octet-stream\r\n\
                         Content-Length: 10485760\r\n\r\n";
        let (client, mut server) = duplex(8 * 1024);
        tokio::spawn(async move {
            // Drain request.
            let mut tmp = [0u8; 1024];
            loop {
                let n = server.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                if find_subslice(&tmp[..n], b"\r\n\r\n").is_some() {
                    break;
                }
            }
            // Send only headers — DON'T send 10 MiB of body. If the
            // pre-check works, the client closes before reading body.
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });
        let err = http_get_over_stream(client, "h", "/", MAX_RESPONSE_BYTES)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                HttpsBootstrapError::ContentLengthTooLarge {
                    declared: 10_485_760,
                    limit: MAX_RESPONSE_BYTES
                }
            ),
            "expected ContentLengthTooLarge, got {err:?}"
        );
    }

    /// A server that omits `Content-Length` (or sets a sane value)
    /// must still go through the streaming-cap defence — the
    /// pre-check is best-effort, not a replacement for the inline
    /// cap. Sanity: legitimate response without Content-Length
    /// works.
    #[tokio::test]
    async fn phase646_h9_no_content_length_falls_through_to_streaming_cap() {
        // Hand-crafted response without Content-Length — server uses
        // `Connection: close` framing.
        let body = b"hello, world";
        let mut response = Vec::new();
        response.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n");
        response.extend_from_slice(body);
        let (client, mut server) = duplex(8 * 1024);
        tokio::spawn(async move {
            let mut tmp = [0u8; 1024];
            loop {
                let n = server.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                if find_subslice(&tmp[..n], b"\r\n\r\n").is_some() {
                    break;
                }
            }
            server.write_all(&response).await.unwrap();
            server.shutdown().await.unwrap();
        });
        let got = http_get_over_stream(client, "h", "/", MAX_RESPONSE_BYTES)
            .await
            .expect("no-content-length must still work");
        assert_eq!(got, body);
    }

    /// A server that dribbles bytes after a long pause triggers the
    /// per-chunk timeout — slow-loris defence. We emulate this with
    /// a duplex pair where the server task sends ONLY headers, then
    /// sleeps past the chunk timeout without sending the body.
    #[tokio::test]
    async fn phase646_h9_slow_loris_per_chunk_timeout_fires() {
        let (client, mut server) = duplex(8 * 1024);
        let stall = Duration::from_millis(800); // > the test's chunk_timeout
        let chunk_timeout = Duration::from_millis(150);
        tokio::spawn(async move {
            // Drain request.
            let mut tmp = [0u8; 1024];
            loop {
                let n = server.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                if find_subslice(&tmp[..n], b"\r\n\r\n").is_some() {
                    break;
                }
            }
            // Send only the status line + a single header — no
            // separator yet. Then sleep past the chunk timeout so
            // the next `read` on the client side stalls.
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n")
                .await
                .unwrap();
            tokio::time::sleep(stall).await;
            // Even if we eventually finish, the client should already
            // have aborted with ChunkTimeout.
            server.write_all(b"\r\nbody\r\n").await.unwrap();
            server.shutdown().await.unwrap();
        });
        let err =
            http_get_over_stream_with_timeout(client, "h", "/", MAX_RESPONSE_BYTES, chunk_timeout)
                .await
                .unwrap_err();
        assert!(
            matches!(err, HttpsBootstrapError::ChunkTimeout(_)),
            "expected ChunkTimeout, got {err:?}"
        );
    }

    /// `parse_content_length` is case-insensitive per RFC 7230 §3.2.
    #[test]
    fn phase646_h9_parse_content_length_case_insensitive() {
        let h = b"X-Other: 1\r\nContent-Length: 42\r\nFoo: bar";
        assert_eq!(parse_content_length(h), Ok(Some(42)));
        let h = b"content-length: 42";
        assert_eq!(parse_content_length(h), Ok(Some(42)));
        let h = b"CONTENT-LENGTH: 42";
        assert_eq!(parse_content_length(h), Ok(Some(42)));
        // Whitespace tolerance: leading/trailing whitespace around the value.
        let h = b"Content-Length:    42   ";
        assert_eq!(parse_content_length(h), Ok(Some(42)));
        // Absent header → Ok(None).
        let h = b"X-Other: 1\r\nFoo: bar";
        assert_eq!(parse_content_length(h), Ok(None));
        // Malformed numeric value → Ok(None) (caller falls through to
        // streaming cap, no early reject).
        let h = b"Content-Length: not-a-number";
        assert_eq!(parse_content_length(h), Ok(None));
        // duplicate identical → Ok(Some).
        let h = b"Content-Length: 42\r\nContent-Length: 42";
        assert_eq!(parse_content_length(h), Ok(Some(42)));
        // conflicting values → Err.
        let h = b"Content-Length: 42\r\nContent-Length: 17";
        assert_eq!(parse_content_length(h), Err(()));
    }

    // ── 481.4: .onion seed-source over Tor SOCKS ───────────────────────

    #[test]
    fn epic481_4_is_onion_url_detection() {
        assert!(is_onion_url("http://abc.onion/seeds.json"));
        assert!(is_onion_url("https://abc.onion"));
        assert!(is_onion_url("http://ABCdef.ONION:8080/x")); // case-insensitive
        assert!(is_onion_url(
            "http://sub.deep.expyuzz4wqqyqhjn.onion/peers.json"
        ));
        assert!(is_onion_url("abc.onion:80")); // no scheme
        assert!(is_onion_url("http://user@abc.onion/x")); // userinfo stripped
        // Negatives: `.onion` must be the actual host suffix, not a substring.
        assert!(!is_onion_url("https://cdn.example.com/seeds.json"));
        assert!(!is_onion_url("http://onion.example.com/x"));
        assert!(!is_onion_url("http://notonion/x"));
        assert!(!is_onion_url("http://abc.onion.evil.com/x"));
    }

    #[test]
    fn epic481_4_parse_onion_url_accepts_http_onion_defaults_80() {
        let p = parse_onion_url("http://abc.onion/seeds.json").unwrap();
        assert_eq!(p.host, "abc.onion");
        assert_eq!(p.port, 80);
        assert_eq!(p.path, "/seeds.json");

        let p2 = parse_onion_url("http://abc.onion:9001/p").unwrap();
        assert_eq!(p2.port, 9001);
        assert_eq!(p2.host, "abc.onion");

        // No path → defaults to "/".
        let p3 = parse_onion_url("http://abc.onion").unwrap();
        assert_eq!(p3.path, "/");
    }

    #[test]
    fn epic481_4_parse_onion_url_rejects_https_nononion_userinfo() {
        // https:// rejected — .onion has no public-CA cert; use http:// over Tor.
        assert!(matches!(
            parse_onion_url("https://abc.onion/x"),
            Err(HttpsBootstrapError::BadUrl(..))
        ));
        // non-.onion host rejected — this parser is .onion-only.
        assert!(matches!(
            parse_onion_url("http://cdn.example.com/x"),
            Err(HttpsBootstrapError::BadUrl(..))
        ));
        // userinfo rejected (shared with parse_https_url).
        assert!(matches!(
            parse_onion_url("http://user@abc.onion/x"),
            Err(HttpsBootstrapError::BadUrl(..))
        ));
    }

    /// `is_onion_url` (routing) and `parse_onion_url` (fetch) must AGREE on
    /// what is a fetchable `.onion` URL — a route-to-Tor decision followed by a
    /// parse rejection would make a legit source silently dead.  Covers the
    /// two divergences the review caught: a case-insensitive scheme and a
    /// query/fragment with no path.
    #[test]
    fn epic481_4_onion_routing_and_parsing_agree() {
        for url in [
            "http://abc.onion/seeds.json",
            "http://abc.onion",
            "HTTP://ABC.onion/seeds.json", // uppercase scheme (RFC 3986: case-insensitive)
            "http://abc.onion?v=2",        // query, NO path → treated as root
            "http://abc.onion#frag",       // fragment, NO path → treated as root
            "http://abc.onion:9001/p?x=1", // explicit port + query after path
        ] {
            assert!(is_onion_url(url), "{url} should route to Tor");
            assert!(
                parse_onion_url(url).is_ok(),
                "{url} routed to Tor but parse_onion_url rejected it (parsers disagree)"
            );
        }
        // The path-less query/fragment collapses to root `/`.
        assert_eq!(parse_onion_url("http://abc.onion?v=2").unwrap().path, "/");
        assert_eq!(
            parse_onion_url("HTTP://ABC.onion/p").unwrap().host,
            "ABC.onion"
        );
    }

    /// The pure routing decision (481.4): `.onion` + proxy → Tor; `.onion`
    /// without proxy → fail-soft skip; everything else → clearnet (proxy
    /// ignored).  This is the runtime branch, made testable without a network.
    #[test]
    fn epic481_4_classify_bootstrap_url_routes() {
        let proxy = Some("socks5://127.0.0.1:9050");
        assert_eq!(
            classify_bootstrap_url("http://abc.onion/s.json", proxy),
            BootstrapRoute::Tor("socks5://127.0.0.1:9050")
        );
        assert_eq!(
            classify_bootstrap_url("http://abc.onion/s.json", None),
            BootstrapRoute::OnionNoProxy
        );
        // Clearnet ignores the proxy entirely, both with and without it set.
        assert_eq!(
            classify_bootstrap_url("https://cdn.example.com/s.json", proxy),
            BootstrapRoute::Clearnet
        );
        assert_eq!(
            classify_bootstrap_url("https://cdn.example.com/s.json", None),
            BootstrapRoute::Clearnet
        );
    }

    /// Minimal in-process SOCKS5 server for the `.onion` fetch tests.  Does the
    /// no-auth handshake, asserts the client sent the target as a **DOMAIN**
    /// address (ATYP 0x03 — proves the `.onion` host is handed to the proxy,
    /// NOT resolved locally), then plays the role of the target HTTP server on
    /// the same socket (drains the GET, writes `response`).  Returns the
    /// `(domain, port)` the client asked the proxy to reach.
    async fn socks5_mock_serve_http(
        mut sock: tokio::net::TcpStream,
        response: Vec<u8>,
    ) -> (String, u16) {
        // 1. Greeting: VER, NMETHODS, METHODS.
        let mut head = [0u8; 2];
        sock.read_exact(&mut head).await.unwrap();
        assert_eq!(head[0], 0x05, "SOCKS version");
        let mut methods = vec![0u8; head[1] as usize];
        sock.read_exact(&mut methods).await.unwrap();
        // Method selection: no-auth.
        sock.write_all(&[0x05, 0x00]).await.unwrap();
        // 2. CONNECT request: VER, CMD, RSV, ATYP.
        let mut reqhdr = [0u8; 4];
        sock.read_exact(&mut reqhdr).await.unwrap();
        assert_eq!(reqhdr[0], 0x05);
        assert_eq!(reqhdr[1], 0x01, "expected CONNECT command");
        assert_eq!(
            reqhdr[3], 0x03,
            "target MUST be a DOMAIN (ATYP 0x03) — .onion is resolved by the \
             proxy (Tor), never locally"
        );
        let mut len = [0u8; 1];
        sock.read_exact(&mut len).await.unwrap();
        let mut domain = vec![0u8; len[0] as usize];
        sock.read_exact(&mut domain).await.unwrap();
        let mut port = [0u8; 2];
        sock.read_exact(&mut port).await.unwrap();
        let target = String::from_utf8(domain).unwrap();
        // 3. Success reply (REP=0x00), bound addr 0.0.0.0:0.
        sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        // 4. Play the target HTTP server: drain the GET, write the response.
        let mut req = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = sock.read(&mut tmp).await.unwrap();
            if n == 0 {
                break;
            }
            req.extend_from_slice(&tmp[..n]);
            if find_subslice(&req, b"\r\n\r\n").is_some() {
                break;
            }
        }
        assert!(req.starts_with(b"GET "), "expected GET over the tunnel");
        sock.write_all(&response).await.unwrap();
        sock.shutdown().await.unwrap();
        (target, u16::from_be_bytes(port))
    }

    /// End-to-end: `fetch_seeds_via_tor` does the SOCKS5 handshake through the
    /// mock proxy, hands the `.onion` host across as a domain, fetches the
    /// signed bundle over the plaintext tunnel, and verifies it against the
    /// pinned issuer.
    #[tokio::test]
    async fn epic481_4_fetch_seeds_via_tor_end_to_end() {
        let peers = policy_test_peer();
        let (signed_body, issuer_pk) = fresh_signed_bundle(&peers);
        let response = fake_response(&signed_body);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let onion_host = "expyuzz4wqqyqhjn.onion";
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            socks5_mock_serve_http(sock, response).await
        });

        let proxy_url = format!("socks5://{proxy_addr}");
        let url = format!("http://{onion_host}/seeds.json");
        let got = fetch_seeds_via_tor(&url, &proxy_url, Some(&issuer_pk))
            .await
            .expect("fetch_seeds_via_tor");
        assert_eq!(got, peers);

        let (target, port) = server.await.unwrap();
        assert_eq!(
            target, onion_host,
            "proxy must receive the .onion hostname verbatim (no local DNS)"
        );
        assert_eq!(port, 80, "default .onion port is 80");
    }

    /// The `.onion` path is **force-signed**: a raw-JSON body is rejected even
    /// when no issuer is pinned (signed_preferred), so a malicious/buggy onion
    /// endpoint can never inject an unsigned peer list.
    #[tokio::test]
    async fn epic481_4_fetch_via_tor_force_signed_rejects_raw_json() {
        let raw_json = crate::seeds::encode_bootstrap_bundle(&policy_test_peer()).unwrap();
        let response = fake_response(&raw_json);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            socks5_mock_serve_http(sock, response).await
        });

        let proxy_url = format!("socks5://{proxy_addr}");
        let err = fetch_seeds_via_tor("http://abc.onion/seeds.json", &proxy_url, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, HttpsBootstrapError::SignedBundleRequired),
            "raw JSON over .onion must be rejected, got {err:?}"
        );
        let _ = server.await;
    }

    /// A bundle signed by issuer A but fetched with issuer B **pinned** is
    /// rejected over Tor — the issuer pin is enforced on the `.onion` path just
    /// like the clearnet `decode_signed_required_rejects_wrong_issuer`.
    #[tokio::test]
    async fn epic481_4_fetch_via_tor_rejects_wrong_issuer() {
        let peers = policy_test_peer();
        let (signed_body, _issuer_a) = fresh_signed_bundle(&peers);
        let response = fake_response(&signed_body);
        let other_kp = veil_crypto::generate_keypair(SignatureAlgorithm::Ed25519);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            socks5_mock_serve_http(sock, response).await
        });

        let proxy_url = format!("socks5://{proxy_addr}");
        let err = fetch_seeds_via_tor(
            "http://abc.onion/seeds.json",
            &proxy_url,
            Some(&other_kp.public_key), // pin a DIFFERENT issuer than signed with
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, HttpsBootstrapError::SignedBundleVerify(_)),
            "wrong pinned issuer over .onion must be rejected, got {err:?}"
        );
        let _ = server.await;
    }

    /// An explicit `.onion` port is parsed and threaded all the way to the
    /// SOCKS CONNECT — the proxy receives the port the operator configured,
    /// not a hardcoded 80.
    #[tokio::test]
    async fn epic481_4_fetch_via_tor_threads_explicit_port() {
        let peers = policy_test_peer();
        let (signed_body, issuer_pk) = fresh_signed_bundle(&peers);
        let response = fake_response(&signed_body);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let onion_host = "expyuzz4wqqyqhjn.onion";
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            socks5_mock_serve_http(sock, response).await
        });

        let proxy_url = format!("socks5://{proxy_addr}");
        let url = format!("http://{onion_host}:9001/seeds.json");
        let got = fetch_seeds_via_tor(&url, &proxy_url, Some(&issuer_pk))
            .await
            .expect("fetch_seeds_via_tor");
        assert_eq!(got, peers);

        let (target, port) = server.await.unwrap();
        assert_eq!(target, onion_host);
        assert_eq!(
            port, 9001,
            "explicit .onion port must reach the proxy CONNECT"
        );
    }
}
