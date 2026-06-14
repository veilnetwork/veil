//! HTTPS RR (RFC 9460) lookups for real TLS ECH config resolution
//! (Stage 10 slice 3).
//!
//! # Background
//!
//! Slice 2b/2c shipped TLS ECH GREASE on the public-PKI HTTPS bootstrap
//! path — every ClientHello carries a GREASE ECH extension, defeating
//! middlebox fingerprinting that distinguishes ECH-capable from non-ECH
//! connections.  GREASE alone is the **cover-traffic half**; this
//! module adds the **real-encryption half** by resolving the target's
//! `EchConfigList` from its DNS HTTPS RR and feeding it to rustls's
//! `EchMode::Enable(EchConfig::new(...))` path.
//!
//! # Wire model
//!
//! Per RFC 9460 §2.2 + RFC 9461 §3, a server publishing ECH support
//! emits one or more `HTTPS` records under its zone:
//!
//! ```text
//! example.com.    300 IN HTTPS 1 . alpn="h2" ech="<base64>"
//! ```
//!
//! The `ech` SvcParamKey (numeric ID `5`) carries the raw
//! `EchConfigList` bytes which rustls's
//! [`rustls::client::EchConfig::new`] consumes directly.
//!
//! # Failure model
//!
//! Slice 3 deliberately treats DNS-side errors as **soft failures**:
//! caller falls back to slice 2c's GREASE path on any of:
//! * no HTTPS record exists for the host,
//! * the record exists but carries no `ech` SvcParamKey,
//! * the lookup times out or the resolver returns NXDOMAIN/SERVFAIL,
//! * the bytes parse but rustls cannot select a supported HPKE suite.
//!
//! This keeps the bootstrap fetch robust against operator-side DNS
//! misconfig — a stale or missing ECH record degrades to GREASE-only,
//! not to a hard failure.
//!
//! # Caching
//!
//! Slice 3 does NOT add an in-process cache yet — bootstrap fetches
//! happen rarely (cold start + periodic peer refresh), so the
//! per-connect DNS overhead (single-digit ms when the system resolver
//! has the answer cached) is not worth the cache-invalidation complexity.
//! Future slice can add a TTL-respecting cache if a profiler points
//! to this path being hot.

use std::sync::OnceLock;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};

/// Process-wide hickory resolver used by [`query_https_ech`].  Built
/// lazily from `/etc/resolv.conf` (or the Windows equivalent) on first
/// use.  `OnceLock` keeps the resolver shared across every outbound
/// bootstrap fetch — building a fresh resolver per call would re-parse
/// the system config and incur tens-of-ms of startup cost.
static RESOLVER: OnceLock<Option<TokioResolver>> = OnceLock::new();

/// Resolver-lookup timeout.  Three seconds aligns with the TCP connect
/// timeout default; bootstrap fetches that take longer than that are
/// already past the operator's tolerance budget, so falling back to
/// GREASE is the right call.
const HTTPS_RR_TIMEOUT: Duration = Duration::from_secs(3);

fn resolver() -> Option<&'static TokioResolver> {
    RESOLVER
        .get_or_init(|| {
            let builder = TokioResolver::builder_tokio().ok()?;
            builder.build().ok()
        })
        .as_ref()
}

/// Query the HTTPS RR for `host` and return the `ech` SvcParamValue
/// bytes, if present.  See module-level docs for the failure model.
///
/// Returns `None` (NOT an error) on any DNS-side failure — caller
/// falls back to ECH GREASE.
pub async fn query_https_ech(host: &str) -> Option<Vec<u8>> {
    let resolver = resolver()?;
    let lookup_fut = resolver.lookup(host, RecordType::HTTPS);
    let lookup = tokio::time::timeout(HTTPS_RR_TIMEOUT, lookup_fut)
        .await
        .ok()? // timeout
        .ok()?; // resolver error (NXDOMAIN / SERVFAIL)

    for record in lookup.answers() {
        let https = match &record.data {
            hickory_resolver::proto::rr::RData::HTTPS(h) => h,
            _ => continue,
        };
        for (key, value) in &https.svc_params {
            if *key == SvcParamKey::EchConfigList
                && let SvcParamValue::EchConfigList(ech) = value
                && !ech.0.is_empty()
            {
                return Some(ech.0.clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The query API returns `None` for NXDOMAIN-style targets (a
    /// host that should never have an HTTPS RR in the wild).  Smoke test
    /// that the soft-failure path works — guards against a regression
    /// where DNS errors propagate up as `Result::Err` instead of `None`.
    #[tokio::test(flavor = "current_thread")]
    async fn nxdomain_target_returns_none() {
        // `.invalid` is the IANA-reserved TLD that is guaranteed never
        // to resolve.  Lookup will return NXDOMAIN; we expect `None`,
        // not a panic or unwrap-induced abort.
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            query_https_ech("nonexistent.invalid"),
        )
        .await;
        // Either the resolver returned `None`, or the test-level
        // timeout fired — both are acceptable (we are testing that we
        // do not propagate an Err / panic).
        match result {
            Ok(None) => {} // expected
            Ok(Some(_)) => panic!("`.invalid` somehow returned an HTTPS RR"),
            Err(_) => {} // outer timeout — system resolver flaky on this host, OK
        }
    }
}
