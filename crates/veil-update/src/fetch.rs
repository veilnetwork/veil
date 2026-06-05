//! Multi-URL fetch with failover + SHA-256 verify.
//!
//! Composes the manifest primitive with multi-endpoint
//! HTTP fetch from `node/bootstrap/https.rs`. Two helpers:
//!
//! * [`fetch_manifest_with_failover`] — try each URL until one
//!   returns a body that decodes + verifies as a signed manifest
//!   for the expected issuer + passes anti-downgrade.
//!
//! * [`fetch_binary_with_failover`] — try each URL until one
//!   returns a body whose SHA-256 matches the manifest's
//!   `binary_sha256`.
//!
//! Both helpers take an INJECTED async `fetcher` closure rather
//! than coupling to a real HTTPS stack. Three benefits:
//! * Unit tests use an in-memory HashMap stub.
//! * Different deployments wrap different transports (HTTPS
//!   IPFS gateway.onion, file) without this module having
//!   to know about all of them.
//! * The HTTPS-binding glue (TLS connect + HTTP/1.1 GET) lives
//!   in a separate slice and reuses `node/bootstrap/https.rs`
//!   when it ships.
//!
//! # Why fail-over (not first-succeed-or-fail)
//!
//! A censor that takes down one of the operator's CDN endpoints
//! must NOT halt the network's update flow. When the operator
//! signed N URLs into the manifest, the client tries them in
//! order until one returns valid content. Mid-list failures are
//! treated as transient (network blip, single-CDN outage
//! transient TLS error) and не aborts the update — only after
//! ALL URLs fail does the helper return Err.

use sha2::{Digest, Sha256};

use super::manifest::{
    BINARY_SHA256_LEN, MAX_MANIFEST_BYTES, ManifestError, UpdateManifest, decode_manifest,
    verify_manifest,
};

/// Hard cap on a single update-binary download. 100 MiB is well
/// above any reasonable single-binary size (typical Rust release
/// build < 50 MiB across all targets) but small enough that an
/// adversarial CDN cannot exhaust client memory or disk.
pub const MAX_BINARY_BYTES: usize = 100 * 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum FetchError {
    #[error("no URLs provided")]
    NoUrls,
    #[error("all {tried} URLs failed; first error: {first_error}")]
    AllUrlsFailed { tried: usize, first_error: String },
    #[error("manifest verify: {0}")]
    Manifest(ManifestError),
    #[error("binary sha256 mismatch — expected {expected_hex} got {got_hex}")]
    Sha256Mismatch {
        expected_hex: String,
        got_hex: String,
    },
}

impl From<ManifestError> for FetchError {
    fn from(e: ManifestError) -> Self {
        Self::Manifest(e)
    }
}

/// Fetch a signed manifest with URL failover.
///
/// Tries `urls` in order. For each URL: invokes `fetcher`
/// decodes + verifies the returned bytes as a manifest signed by
/// `expected_issuer_pk` and that doesn't downgrade from
/// `installed_release_unix`. First URL that produces a valid
/// manifest wins; the rest are not tried.
///
/// Returns `Err` only when ALL URLs fail. Per-URL errors are
/// swallowed (transient network failures should not stop the
/// update); the first error is included in `AllUrlsFailed` for
/// diagnostics.
///
/// # Why decode + verify per-URL (not "fetch all then pick best")
///
/// A malicious URL that returns garbage / wrong issuer / downgrade
/// must not POISON later URLs in the list — we want first-good-
/// wins semantics, not best-of-all. An attacker controlling URL
/// #2 cannot prevent client from successfully using URL #3 by
/// returning a tampered manifest at #2.
pub async fn fetch_manifest_with_failover<F, Fut>(
    urls: &[String],
    fetcher: F,
    expected_issuer_pk: &str,
    installed_release_unix: Option<u64>,
    now_unix_secs: Option<u64>,
) -> Result<UpdateManifest, FetchError>
where
    F: Fn(&str) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, String>>,
{
    if urls.is_empty() {
        return Err(FetchError::NoUrls);
    }
    let mut first_error: Option<String> = None;
    for url in urls {
        let bytes = match fetcher(url).await {
            Ok(b) => b,
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(format!("{url}: {e}"));
                }
                continue;
            }
        };
        let m = match decode_manifest(&bytes) {
            Ok(m) => m,
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(format!("{url}: decode: {e}"));
                }
                continue;
            }
        };
        if let Err(e) = verify_manifest(
            &m,
            Some(expected_issuer_pk),
            installed_release_unix,
            now_unix_secs,
        ) {
            if first_error.is_none() {
                first_error = Some(format!("{url}: verify: {e}"));
            }
            continue;
        }
        return Ok(m);
    }
    Err(FetchError::AllUrlsFailed {
        tried: urls.len(),
        first_error: first_error.unwrap_or_else(|| "no URLs reached fetcher".to_owned()),
    })
}

/// Result of an update check.
#[derive(Debug)]
pub enum UpdateAvailability {
    /// The latest signed manifest is at-or-before our installed
    /// release. Includes the latest release_unix the operator has
    /// signed (so a UI can show "you're on the latest version
    /// pushed YYYY-MM-DD").
    UpToDate { latest_release_unix: u64 },
    /// A newer signed manifest exists. Caller can pass the manifest
    /// to a binary-fetch + restart pipeline.
    Available { manifest: UpdateManifest },
}

/// Check whether a newer signed manifest exists.
///
/// Differs from a full apply-flow (which would also fetch and verify
/// and swap the binary) — this just answers the question "is there a
/// newer version published".
///
/// Internally calls [`fetch_manifest_with_failover`] with
/// `installed_release_unix = None` so we deliberately DO NOT enforce
/// anti-downgrade at fetch time. Anti-downgrade is a property of
/// the apply path; for a check, an operator who rolls back their
/// own published manifest (e.g. emergency revert) should still see
/// "up-to-date" rather than a fetch error. The distinction between
/// "older manifest published" and "newer manifest published" is
/// then made explicitly by comparing the manifest's release_unix
/// against `installed_release_unix`.
pub async fn check_for_update<F, Fut>(
    manifest_urls: &[String],
    fetcher: F,
    expected_issuer_pk: &str,
    installed_release_unix: u64,
    now_unix_secs: Option<u64>,
) -> Result<UpdateAvailability, FetchError>
where
    F: Fn(&str) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, String>>,
{
    let m = fetch_manifest_with_failover(
        manifest_urls,
        fetcher,
        expected_issuer_pk,
        None, // see doc-comment: anti-downgrade is for apply, not check.
        now_unix_secs,
    )
    .await?;
    if m.release_unix > installed_release_unix {
        Ok(UpdateAvailability::Available { manifest: m })
    } else {
        Ok(UpdateAvailability::UpToDate {
            latest_release_unix: m.release_unix,
        })
    }
}

/// Fetch a binary with URL failover + SHA-256 verify.
///
/// Tries `urls` in order. For each URL: invokes `fetcher`
/// computes SHA-256 of returned bytes, compares to
/// `expected_sha256`. First URL that produces matching bytes wins.
///
/// SHA-256 mismatch is treated SAME as fetch failure (try next URL).
/// A censor that injects a malicious binary at one URL cannot stop
/// client from fetching the legitimate binary at the next URL.
pub async fn fetch_binary_with_failover<F, Fut>(
    urls: &[String],
    fetcher: F,
    expected_sha256: &[u8; BINARY_SHA256_LEN],
) -> Result<Vec<u8>, FetchError>
where
    F: Fn(&str) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, String>>,
{
    if urls.is_empty() {
        return Err(FetchError::NoUrls);
    }
    let mut first_error: Option<String> = None;
    let mut last_hash_mismatch: Option<(String, String)> = None;
    for url in urls {
        let bytes = match fetcher(url).await {
            Ok(b) => b,
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some(format!("{url}: {e}"));
                }
                continue;
            }
        };
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash: [u8; BINARY_SHA256_LEN] = hasher.finalize().into();
        if &hash != expected_sha256 {
            // Hash mismatch — try the next URL. Stash mismatch
            // info so the final error message can name what we
            // saw (helpful when ALL URLs return the wrong hash —
            // suggests malicious-CDN attack vs misconfig).
            last_hash_mismatch = Some((
                veil_util::bytes_to_hex(expected_sha256),
                veil_util::bytes_to_hex(&hash),
            ));
            if first_error.is_none() {
                first_error = Some(format!("{url}: sha256 mismatch"));
            }
            continue;
        }
        return Ok(bytes);
    }
    // ALL URLs failed. If at least one returned a hash-mismatch
    // body, surface the explicit Sha256Mismatch error rather than
    // the generic AllUrlsFailed — operator debugging "binary
    // download keeps failing" needs to see "all your CDNs are
    // returning bytes that don't match the signed hash" loud
    // and clear.
    if let Some((expected_hex, got_hex)) = last_hash_mismatch {
        return Err(FetchError::Sha256Mismatch {
            expected_hex,
            got_hex,
        });
    }
    Err(FetchError::AllUrlsFailed {
        tried: urls.len(),
        first_error: first_error.unwrap_or_else(|| "no URLs reached fetcher".to_owned()),
    })
}

// local `bytes_hex` removed — use `veil_util::bytes_to_hex`.

// ── HTTPS bridge ──────────────────────────────────────────────────────
//
// Glue between the closure-based `fetch_*_with_failover` helpers above
// and the existing `node/bootstrap/https.rs` real-HTTPS infrastructure
// (TLS + DPI-resistant ClientHello + bounded read).
//
// Both helpers below are thin convenience wrappers — they build a
// closure that calls `fetch_bytes_https` with the appropriate byte
// cap, then delegate to `fetch_manifest_with_failover` /
// `fetch_binary_with_failover` for the failover + verify logic.

use veil_bootstrap::{HttpsBootstrapError, fetch_binary_bytes_https, fetch_bytes_https};
use veil_transport::TransportContext;

/// Fetch + verify a signed manifest from any URL in `urls` using
/// real HTTPS (TLS + DPI-resistant ClientHello). Failover semantics
/// match [`fetch_manifest_with_failover`] — censor blocking one
/// endpoint cannot stop fetch from another.
///
/// Each per-URL fetch is capped at [`MAX_MANIFEST_BYTES`] (8 KiB) to
/// bound memory amplification by an adversarial CDN.
pub async fn fetch_manifest_via_https(
    urls: &[String],
    ctx: TransportContext,
    expected_issuer_pk: &str,
    installed_release_unix: Option<u64>,
    now_unix_secs: Option<u64>,
) -> Result<UpdateManifest, FetchError> {
    let fetcher = move |url: &str| {
        let ctx = ctx.clone();
        let url = url.to_owned();
        async move {
            fetch_bytes_https(&url, &ctx, MAX_MANIFEST_BYTES)
                .await
                .map_err(stringify_https_error)
        }
    };
    fetch_manifest_with_failover(
        urls,
        fetcher,
        expected_issuer_pk,
        installed_release_unix,
        now_unix_secs,
    )
    .await
}

/// Fetch + SHA-256-verify a binary from any URL in `urls` using
/// real HTTPS. Failover semantics match
/// [`fetch_binary_with_failover`].
///
/// Each per-URL fetch is capped at [`MAX_BINARY_BYTES`] (100 MiB).
/// Sha256 mismatch on one URL falls through to the next URL — censor
/// injecting malicious binary at one CDN cannot stop fetch of the
/// legitimate binary from another.
///
/// uses [`fetch_binary_bytes_https`] (not the
/// generic [`fetch_bytes_https`]) so the per-fetch ceiling rises to
/// `DEFAULT_BINARY_FETCH_TIMEOUT = 15 min`, while the per-chunk
/// timeout (`DEFAULT_CHUNK_READ_TIMEOUT = 10 s`) still kicks in
/// against slow-loris pacing. `Content-Length` pre-check inside
/// `http_get_over_stream_with_timeout` rejects oversized headers
/// before any body bytes are read.
pub async fn fetch_binary_via_https(
    urls: &[String],
    ctx: TransportContext,
    expected_sha256: &[u8; BINARY_SHA256_LEN],
) -> Result<Vec<u8>, FetchError> {
    let fetcher = move |url: &str| {
        let ctx = ctx.clone();
        let url = url.to_owned();
        async move {
            fetch_binary_bytes_https(&url, &ctx, MAX_BINARY_BYTES)
                .await
                .map_err(stringify_https_error)
        }
    };
    fetch_binary_with_failover(urls, fetcher, expected_sha256).await
}

/// HTTPS-bound counterpart [`check_for_update`]. Operator-facing
/// "is there a newer version" probe — fetch via real HTTPS, compare
/// release_unix to installed.
pub async fn check_for_update_via_https(
    manifest_urls: &[String],
    ctx: TransportContext,
    expected_issuer_pk: &str,
    installed_release_unix: u64,
    now_unix_secs: Option<u64>,
) -> Result<UpdateAvailability, FetchError> {
    let fetcher = move |url: &str| {
        let ctx = ctx.clone();
        let url = url.to_owned();
        async move {
            fetch_bytes_https(&url, &ctx, MAX_MANIFEST_BYTES)
                .await
                .map_err(stringify_https_error)
        }
    };
    check_for_update(
        manifest_urls,
        fetcher,
        expected_issuer_pk,
        installed_release_unix,
        now_unix_secs,
    )
    .await
}

/// Convert HTTPS-layer errors to the `String` shape the closure
/// signature wants. We deliberately collapse to a string here —
/// the closure-based fetch helpers don't care about per-URL error
/// taxonomy (any failure → try next URL); only the final
/// AllUrlsFailed surface needs human-readable diagnostics.
fn stringify_https_error(e: HttpsBootstrapError) -> String {
    e.to_string()
}

#[cfg(test)]
mod tests {
    use super::super::manifest::{BINARY_SHA256_LEN, sign_manifest};
    use super::*;
    use std::collections::HashMap;
    use veil_crypto::generate_keypair;
    use veil_types::SignatureAlgorithm;

    fn fixture_manifest(release_unix: u64, sha256: [u8; BINARY_SHA256_LEN]) -> (Vec<u8>, String) {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let bytes = sign_manifest(
            release_unix,
            "1.2.3",
            "1.0.0",
            "linux-x86_64",
            sha256,
            vec!["https://cdn1.example/binary".to_owned()],
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        (bytes, kp.public_key)
    }

    /// Stub fetcher: synchronous HashMap lookup wrapped in a
    /// `Future` so the helper signature is satisfied. No I/O.
    type StubFetchFuture =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send>>;

    fn stub_fetcher(
        map: HashMap<String, Result<Vec<u8>, String>>,
    ) -> impl Fn(&str) -> StubFetchFuture {
        move |url: &str| {
            let result = map
                .get(url)
                .cloned()
                .unwrap_or_else(|| Err(format!("not in stub: {url}")));
            Box::pin(async move { result })
        }
    }

    // ── fetch_manifest_with_failover ───────────────────────────────────

    #[tokio::test]
    async fn epic484_3_manifest_no_urls_rejected() {
        let result = fetch_manifest_with_failover(
            &[],
            |_url: &str| async { Err::<Vec<u8>, String>("never called".into()) },
            "any",
            None,
            None,
        )
        .await;
        assert_eq!(result.unwrap_err(), FetchError::NoUrls);
    }

    #[tokio::test]
    async fn epic484_3_manifest_first_url_succeeds_short_circuits() {
        let (bytes, pk) = fixture_manifest(1_700_000_000, [0xAB; 32]);
        let mut store: HashMap<String, Result<Vec<u8>, String>> = HashMap::new();
        store.insert("https://cdn1.example/manifest".to_owned(), Ok(bytes));
        // cdn2 would error if called — but it shouldn't be.
        store.insert(
            "https://cdn2.example/manifest".to_owned(),
            Err("UNREACHED".into()),
        );

        let urls = vec![
            "https://cdn1.example/manifest".to_owned(),
            "https://cdn2.example/manifest".to_owned(),
        ];
        let m = fetch_manifest_with_failover(&urls, stub_fetcher(store), &pk, None, None)
            .await
            .expect("first URL should succeed");
        assert_eq!(m.version, "1.2.3");
    }

    #[tokio::test]
    async fn epic484_3_manifest_failover_to_next_url_when_first_fails() {
        let (bytes, pk) = fixture_manifest(1_700_000_000, [0xAB; 32]);
        let mut store: HashMap<String, Result<Vec<u8>, String>> = HashMap::new();
        store.insert(
            "https://cdn1.example/manifest".to_owned(),
            Err("network".into()),
        );
        store.insert("https://cdn2.example/manifest".to_owned(), Ok(bytes));

        let urls = vec![
            "https://cdn1.example/manifest".to_owned(),
            "https://cdn2.example/manifest".to_owned(),
        ];
        let m = fetch_manifest_with_failover(&urls, stub_fetcher(store), &pk, None, None)
            .await
            .expect("must failover to cdn2");
        assert_eq!(m.version, "1.2.3");
    }

    #[tokio::test]
    async fn epic484_3_manifest_failover_when_first_url_returns_wrong_issuer() {
        // Censor controls cdn1 and serves a manifest signed by THEIR
        // key — not the expected operator's. Failover to cdn2 must
        // succeed with the legitimate operator-signed manifest.
        let (legit_bytes, legit_pk) = fixture_manifest(1_700_000_000, [0xAB; 32]);
        let (bad_bytes, _) = fixture_manifest(1_700_000_000, [0xCD; 32]); // different key
        let mut store: HashMap<String, Result<Vec<u8>, String>> = HashMap::new();
        store.insert(
            "https://cdn1-bad.example/manifest".to_owned(),
            Ok(bad_bytes),
        );
        store.insert(
            "https://cdn2-good.example/manifest".to_owned(),
            Ok(legit_bytes),
        );

        let urls = vec![
            "https://cdn1-bad.example/manifest".to_owned(),
            "https://cdn2-good.example/manifest".to_owned(),
        ];
        let m = fetch_manifest_with_failover(&urls, stub_fetcher(store), &legit_pk, None, None)
            .await
            .expect("malicious cdn1 must failover to good cdn2");
        // Confirms: anti-poison is preserved. Bad-issuer manifest at
        // cdn1 didn't make us reject the WHOLE fetch — we kept trying.
        assert_eq!(m.issuer_pk, legit_pk);
    }

    #[tokio::test]
    async fn epic484_3_manifest_all_urls_fail_returns_explicit_error() {
        let (_, pk) = fixture_manifest(1_700_000_000, [0xAB; 32]);
        let mut store: HashMap<String, Result<Vec<u8>, String>> = HashMap::new();
        store.insert(
            "https://cdn1.example/manifest".to_owned(),
            Err("net1".into()),
        );
        store.insert(
            "https://cdn2.example/manifest".to_owned(),
            Err("net2".into()),
        );

        let urls = vec![
            "https://cdn1.example/manifest".to_owned(),
            "https://cdn2.example/manifest".to_owned(),
        ];
        let err = fetch_manifest_with_failover(&urls, stub_fetcher(store), &pk, None, None)
            .await
            .unwrap_err();
        match err {
            FetchError::AllUrlsFailed { tried, first_error } => {
                assert_eq!(tried, 2);
                assert!(
                    first_error.contains("cdn1.example"),
                    "must surface first error for diagnostics: {first_error}"
                );
            }
            other => panic!("expected AllUrlsFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn epic484_3_manifest_anti_downgrade_threads_through() {
        // Manifest is older than installed → must be rejected at
        // verify, failover to next URL.
        let (older, pk) = fixture_manifest(1_700_000_000, [0xAB; 32]);
        let (newer, _) = {
            let kp = generate_keypair(SignatureAlgorithm::Ed25519);
            // Sign newer with same key as older for anti-downgrade
            // test, OR new key for issuer-mismatch. Use old key
            // for cleanliness.
            let bytes = sign_manifest(
                1_800_000_000,
                "1.3.0",
                "1.0.0",
                "linux-x86_64",
                [0xAB; 32],
                vec!["https://x.example".to_owned()],
                // To use old key we'd need to thread it; rebuild
                // with new key + new pk for simplicity.
                &kp.public_key,
                &kp.private_key,
                SignatureAlgorithm::Ed25519,
            )
            .unwrap();
            (bytes, kp.public_key)
        };
        let mut store: HashMap<String, Result<Vec<u8>, String>> = HashMap::new();
        store.insert("https://cdn1.example/manifest".to_owned(), Ok(older));
        store.insert("https://cdn2.example/manifest".to_owned(), Ok(newer));

        let urls = vec![
            "https://cdn1.example/manifest".to_owned(),
            "https://cdn2.example/manifest".to_owned(),
        ];
        // Installed at release_unix = 1_700_500_000; older manifest
        // at 1_700_000_000 should be rejected as downgrade; newer
        // at 1_800_000_000 has different issuer (we used a new key)
        // so it'll also fail (but with IssuerMismatch). This test
        // verifies the FAILOVER attempts both — i.e., bad cdn1
        // didn't short-circuit the whole call.
        let err = fetch_manifest_with_failover(
            &urls,
            stub_fetcher(store),
            &pk,
            Some(1_700_500_000),
            None,
        )
        .await
        .unwrap_err();
        // Because cdn2's manifest is by a different issuer (our test
        // setup), both URLs should fail. Surface as AllUrlsFailed.
        match err {
            FetchError::AllUrlsFailed { tried, .. } => assert_eq!(tried, 2),
            other => panic!("expected AllUrlsFailed, got {other:?}"),
        }
    }

    // ── fetch_binary_with_failover ─────────────────────────────────────

    fn sha256_of(data: &[u8]) -> [u8; BINARY_SHA256_LEN] {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().into()
    }

    #[tokio::test]
    async fn epic484_3_binary_no_urls_rejected() {
        let result = fetch_binary_with_failover(
            &[],
            |_url: &str| async { Err::<Vec<u8>, String>("never".into()) },
            &[0; 32],
        )
        .await;
        assert_eq!(result.unwrap_err(), FetchError::NoUrls);
    }

    #[tokio::test]
    async fn epic484_3_binary_first_url_with_correct_sha256_wins() {
        let payload = b"the binary bytes";
        let expected_hash = sha256_of(payload);
        let mut store: HashMap<String, Result<Vec<u8>, String>> = HashMap::new();
        store.insert("https://cdn1.example/bin".to_owned(), Ok(payload.to_vec()));
        store.insert(
            "https://cdn2.example/bin".to_owned(),
            Err("UNREACHED".into()),
        );

        let urls = vec![
            "https://cdn1.example/bin".to_owned(),
            "https://cdn2.example/bin".to_owned(),
        ];
        let bytes = fetch_binary_with_failover(&urls, stub_fetcher(store), &expected_hash)
            .await
            .expect("first URL good hash → returned");
        assert_eq!(bytes, payload);
    }

    #[tokio::test]
    async fn epic484_3_binary_failover_when_first_url_returns_wrong_sha256() {
        // Censor swaps binary at cdn1 → hash mismatch → failover to
        // cdn2 which has legitimate binary.
        let payload = b"legitimate binary";
        let expected_hash = sha256_of(payload);
        let evil_payload = b"malicious binary swap";
        let mut store: HashMap<String, Result<Vec<u8>, String>> = HashMap::new();
        store.insert(
            "https://cdn1-bad.example/bin".to_owned(),
            Ok(evil_payload.to_vec()),
        );
        store.insert(
            "https://cdn2-good.example/bin".to_owned(),
            Ok(payload.to_vec()),
        );

        let urls = vec![
            "https://cdn1-bad.example/bin".to_owned(),
            "https://cdn2-good.example/bin".to_owned(),
        ];
        let bytes = fetch_binary_with_failover(&urls, stub_fetcher(store), &expected_hash)
            .await
            .expect("failover past hash-mismatch must succeed");
        assert_eq!(
            bytes, payload,
            "must return LEGITIMATE binary, not the swap"
        );
    }

    #[tokio::test]
    async fn epic484_3_binary_all_urls_with_wrong_sha256_explicit_mismatch_error() {
        // ALL CDNs return wrong hash — surface explicit
        // Sha256Mismatch (not generic AllUrlsFailed) so operator
        // debugging knows to investigate "all my CDNs are
        // serving wrong bytes" specifically.
        let expected_hash = [0xAB; 32];
        let mut store: HashMap<String, Result<Vec<u8>, String>> = HashMap::new();
        store.insert(
            "https://cdn1.example/bin".to_owned(),
            Ok(b"wrong1".to_vec()),
        );
        store.insert(
            "https://cdn2.example/bin".to_owned(),
            Ok(b"wrong2".to_vec()),
        );

        let urls = vec![
            "https://cdn1.example/bin".to_owned(),
            "https://cdn2.example/bin".to_owned(),
        ];
        let err = fetch_binary_with_failover(&urls, stub_fetcher(store), &expected_hash)
            .await
            .unwrap_err();
        match err {
            FetchError::Sha256Mismatch {
                expected_hex,
                got_hex,
            } => {
                assert!(expected_hex.starts_with("ab"));
                assert_ne!(expected_hex, got_hex);
            }
            other => panic!("expected Sha256Mismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn epic484_3_binary_all_urls_fail_with_network_error_returns_all_failed() {
        let expected_hash = sha256_of(b"never reached");
        let mut store: HashMap<String, Result<Vec<u8>, String>> = HashMap::new();
        store.insert(
            "https://cdn1.example/bin".to_owned(),
            Err("dns fail".into()),
        );
        store.insert(
            "https://cdn2.example/bin".to_owned(),
            Err("conn refused".into()),
        );

        let urls = vec![
            "https://cdn1.example/bin".to_owned(),
            "https://cdn2.example/bin".to_owned(),
        ];
        let err = fetch_binary_with_failover(&urls, stub_fetcher(store), &expected_hash)
            .await
            .unwrap_err();
        match err {
            FetchError::AllUrlsFailed { tried, first_error } => {
                assert_eq!(tried, 2);
                assert!(first_error.contains("dns fail"));
            }
            other => panic!("expected AllUrlsFailed, got {other:?}"),
        }
    }

    /// End-to-end: sign manifest A pointing at binary B; fetch
    /// manifest from URL list, then fetch binary from manifest's
    /// own URL list. Composes both helpers + manifest verify.
    #[tokio::test]
    async fn epic484_3_end_to_end_manifest_then_binary_fetch_round_trip() {
        let payload = b"the final binary blob";
        let payload_hash = sha256_of(payload);
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let manifest_bytes = sign_manifest(
            1_700_000_000,
            "1.2.3",
            "1.0.0",
            "linux-x86_64",
            payload_hash,
            vec![
                "https://bin1.example/x".to_owned(),
                "https://bin2.example/x".to_owned(),
            ],
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();

        let mut store: HashMap<String, Result<Vec<u8>, String>> = HashMap::new();
        store.insert("https://manifests.example/m".to_owned(), Ok(manifest_bytes));
        // bin1 is down; bin2 has the binary. Failover must succeed.
        store.insert("https://bin1.example/x".to_owned(), Err("down".into()));
        store.insert("https://bin2.example/x".to_owned(), Ok(payload.to_vec()));

        // Step 1: fetch + verify manifest.
        let manifest_urls = vec!["https://manifests.example/m".to_owned()];
        let m = fetch_manifest_with_failover(
            &manifest_urls,
            stub_fetcher(store.clone()),
            &kp.public_key,
            None,
            None,
        )
        .await
        .expect("manifest fetch ok");
        assert_eq!(m.version, "1.2.3");

        // Step 2: fetch binary using URLs from the verified manifest.
        let bytes =
            fetch_binary_with_failover(&m.binary_urls, stub_fetcher(store), &m.binary_sha256)
                .await
                .expect("binary fetch ok via failover");
        assert_eq!(bytes, payload);
    }

    // ── check_for_update ───────────────────────────────────────────────

    fn fixture_signed(release_unix: u64, version: &str) -> (Vec<u8>, String) {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let bytes = sign_manifest(
            release_unix,
            version,
            "1.0.0",
            "linux-x86_64",
            [0xAA; 32],
            vec!["https://bin.example/x".to_owned()],
            &kp.public_key,
            &kp.private_key,
            SignatureAlgorithm::Ed25519,
        )
        .unwrap();
        (bytes, kp.public_key)
    }

    #[tokio::test]
    async fn epic484_3_check_for_update_reports_available_when_manifest_is_newer() {
        let (bytes, pk) = fixture_signed(2_000_000_000, "1.3.0");
        let mut store: HashMap<String, Result<Vec<u8>, String>> = HashMap::new();
        store.insert("https://m.example".to_owned(), Ok(bytes));

        let urls = vec!["https://m.example".to_owned()];
        let result = check_for_update(&urls, stub_fetcher(store), &pk, 1_000_000_000, None)
            .await
            .expect("check ok");
        match result {
            UpdateAvailability::Available { manifest } => {
                assert_eq!(manifest.version, "1.3.0");
                assert_eq!(manifest.release_unix, 2_000_000_000);
            }
            other => panic!("expected Available, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn epic484_3_check_for_update_reports_up_to_date_when_manifest_equals_installed() {
        // Edge: published manifest == installed. Equality is "up to date"
        // (not "available") — operator hasn't pushed a new version.
        let (bytes, pk) = fixture_signed(1_500_000_000, "1.2.3");
        let mut store: HashMap<String, Result<Vec<u8>, String>> = HashMap::new();
        store.insert("https://m.example".to_owned(), Ok(bytes));

        let urls = vec!["https://m.example".to_owned()];
        let result = check_for_update(&urls, stub_fetcher(store), &pk, 1_500_000_000, None)
            .await
            .expect("check ok");
        match result {
            UpdateAvailability::UpToDate {
                latest_release_unix,
            } => {
                assert_eq!(latest_release_unix, 1_500_000_000);
            }
            other => panic!("expected UpToDate, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn epic484_3_check_for_update_reports_up_to_date_when_operator_rolled_back() {
        // Operator emergency-reverted to an older release (e.g. shipped
        // a buggy version, then re-published the previous build).
        // Anti-downgrade is OFF for check (it's an apply-time rule)
        // so we should still get UpToDate from the operator's POV
        // — the user already has a newer version installed.
        let (bytes, pk) = fixture_signed(1_000_000_000, "1.2.0"); // older
        let mut store: HashMap<String, Result<Vec<u8>, String>> = HashMap::new();
        store.insert("https://m.example".to_owned(), Ok(bytes));

        let urls = vec!["https://m.example".to_owned()];
        let result = check_for_update(&urls, stub_fetcher(store), &pk, 2_000_000_000, None)
            .await
            .expect("check ok even when manifest is older than installed");
        match result {
            UpdateAvailability::UpToDate {
                latest_release_unix,
            } => {
                assert_eq!(
                    latest_release_unix, 1_000_000_000,
                    "must surface the operator's currently-published release_unix"
                );
            }
            other => panic!("expected UpToDate (rollback case), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn epic484_3_check_for_update_surfaces_fetch_error_when_no_url_succeeds() {
        let (_, pk) = fixture_signed(2_000_000_000, "1.3.0");
        let mut store: HashMap<String, Result<Vec<u8>, String>> = HashMap::new();
        store.insert("https://m.example".to_owned(), Err("net".into()));

        let urls = vec!["https://m.example".to_owned()];
        let err = check_for_update(&urls, stub_fetcher(store), &pk, 1_000_000_000, None)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::AllUrlsFailed { .. }));
    }

    #[tokio::test]
    async fn epic484_3_check_for_update_rejects_wrong_issuer() {
        // Censor controls the manifest endpoint and serves a manifest
        // signed by their key. check_for_update must NOT report
        // "Available" (which would steer client into installing
        // attacker-signed binary).
        let (bytes, _attacker_pk) = fixture_signed(2_000_000_000, "1.3.0");
        let (_, expected_operator_pk) = fixture_signed(1_500_000_000, "1.2.3");
        let mut store: HashMap<String, Result<Vec<u8>, String>> = HashMap::new();
        store.insert("https://m.example".to_owned(), Ok(bytes));

        let urls = vec!["https://m.example".to_owned()];
        let err = check_for_update(
            &urls,
            stub_fetcher(store),
            &expected_operator_pk,
            1_000_000_000,
            None,
        )
        .await
        .unwrap_err();
        // Wrong-issuer manifest must NOT propagate as "Available"; it
        // shows up as AllUrlsFailed (with manifest verify error
        // surfaced in first_error).
        assert!(
            matches!(err, FetchError::AllUrlsFailed { .. }),
            "wrong-issuer must NOT produce Available"
        );
    }

    // ── HTTPS bridge smoke tests ───────────────────────────────────────
    //
    // The actual TLS path is exercised by `fetch_bytes_https` tests in
    // `node/bootstrap/https.rs` (duplex-based, no real TLS); the
    // closure-based failover logic is exercised by the stub-fetcher
    // tests above. These smoke tests verify the COMPOSITION:
    // empty URL list still routed correctly to NoUrls
    // bad URL rejected at parse time, surfaced as AllUrlsFailed
    // (NOT a panic / misroute) — protects against censor that
    // somehow injects garbage into the manifest's binary_urls list
    // between sign and use.

    fn make_test_transport_ctx() -> veil_transport::TransportContext {
        // Build a minimal TransportContext sufficient for fetch_bytes_https
        // to attempt + fail at URL-parse (we never let it actually connect).
        veil_transport::TransportContext::for_debug().expect("debug ctx")
    }

    #[tokio::test]
    async fn epic484_3_fetch_manifest_via_https_no_urls_routed_to_no_urls() {
        let ctx = make_test_transport_ctx();
        let result = fetch_manifest_via_https(&[], ctx, "any", None, None).await;
        assert_eq!(result.unwrap_err(), FetchError::NoUrls);
    }

    #[tokio::test]
    async fn epic484_3_fetch_binary_via_https_no_urls_routed_to_no_urls() {
        let ctx = make_test_transport_ctx();
        let result = fetch_binary_via_https(&[], ctx, &[0u8; 32]).await;
        assert_eq!(result.unwrap_err(), FetchError::NoUrls);
    }

    #[tokio::test]
    async fn epic484_3_fetch_manifest_via_https_bad_url_surfaced_as_all_urls_failed() {
        // Censor tampers manifest's `binary_urls` list (or operator
        // typos one). Helper must surface AllUrlsFailed with the
        // bad URL named in the diagnostic — not panic / silently drop.
        let ctx = make_test_transport_ctx();
        let urls = vec!["http://insecure.example/m".to_owned()]; // http (rejected at parse)
        let err = fetch_manifest_via_https(&urls, ctx, "any", None, None)
            .await
            .unwrap_err();
        match err {
            FetchError::AllUrlsFailed { tried, first_error } => {
                assert_eq!(tried, 1);
                assert!(
                    first_error.contains("insecure.example"),
                    "diagnostic must name the bad URL: {first_error}"
                );
            }
            other => panic!("expected AllUrlsFailed, got {other:?}"),
        }
    }
}
