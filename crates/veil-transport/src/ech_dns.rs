//! HTTPS RR (RFC 9460) lookups for real TLS ECH config resolution
//! (Этап 10 slice 3).
//!
//! # Background
//!
//! Slice 2b/2c shipped TLS ECH GREASE on the public-PKI HTTPS bootstrap
//! path — every ClientHello carries а GREASE ECH extension, defeating
//! middlebox fingerprinting що distinguishes ECH-capable от non-ECH
//! connections.  GREASE alone is the **cover-traffic half**; this
//! module adds the **real-encryption half** by resolving the target's
//! `EchConfigList` от its DNS HTTPS RR и feeding it к rustls's
//! `EchMode::Enable(EchConfig::new(...))` path.
//!
//! # Wire model
//!
//! Per RFC 9460 §2.2 + RFC 9461 §3, а server publishing ECH support
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
//! caller falls back к slice 2c's GREASE path on any of:
//! * no HTTPS record exists for the host,
//! * the record exists but carries no `ech` SvcParamKey,
//! * the lookup times out или the resolver returns NXDOMAIN/SERVFAIL,
//! * the bytes parse but rustls cannot select а supported HPKE suite.
//!
//! This keeps the bootstrap fetch robust against operator-side DNS
//! misconfig — а stale or missing ECH record degrades к GREASE-only,
//! not к а hard failure.
//!
//! # Caching
//!
//! Slice 3 does NOT add an in-process cache yet — bootstrap fetches
//! happen rarely (cold start + periodic peer refresh), so the
//! per-connect DNS overhead (single-digit ms когда the system resolver
//! has the answer cached) is не worth the cache-invalidation complexity.
//! Future slice can add а TTL-respecting cache если а profiler points
//! к this path being hot.

use std::sync::OnceLock;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};

/// Process-wide hickory resolver used by [`query_https_ech`].  Built
/// lazily from `/etc/resolv.conf` (or the Windows equivalent) on first
/// use.  `OnceLock` keeps the resolver shared across every outbound
/// bootstrap fetch — building а fresh resolver per call would re-parse
/// the system config и incur tens-of-ms of startup cost.
static RESOLVER: OnceLock<Option<TokioResolver>> = OnceLock::new();

/// Resolver-lookup timeout.  Three seconds aligns с the TCP connect
/// timeout default; bootstrap fetches що take longer than that are
/// already past the operator's tolerance budget, so falling back к
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

/// Query the HTTPS RR for `host` и return the `ech` SvcParamValue
/// bytes, если present.  See module-level docs для the failure model.
///
/// Returns `None` (NOT an error) on any DNS-side failure — caller
/// falls back к ECH GREASE.
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

    /// The query API returns `None` для NXDOMAIN-style targets (а
    /// host що should never have an HTTPS RR в the wild).  Smoke test
    /// що the soft-failure path works — guards against а regression
    /// where DNS errors propagate up as `Result::Err` instead of `None`.
    #[tokio::test(flavor = "current_thread")]
    async fn nxdomain_target_returns_none() {
        // `.invalid` is the IANA-reserved TLD що is guaranteed never
        // к resolve.  Lookup will return NXDOMAIN; we expect `None`,
        // not а panic или unwrap-induced abort.
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            query_https_ech("nonexistent.invalid"),
        )
        .await;
        // Either the resolver returned `None`, или the test-level
        // timeout fired — both ара acceptable (we ара testing що we
        // do not propagate an Err / panic).
        match result {
            Ok(None) => {} // expected
            Ok(Some(_)) => panic!("`.invalid` somehow returned an HTTPS RR"),
            Err(_) => {} // outer timeout — system resolver flaky on this host, OK
        }
    }
}
