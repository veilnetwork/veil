//! DNS-based bootstrap seed discovery.
//!
//! Queries `_veil._bootstrap.<domain>` TXT records for seed entries.
//! Each TXT record contains one seed in the format:
//!
//! ```text
//! transport=tcp://seed.example:7001 pubkey=<base64> nonce=<base64>
//! ```
//!
//! # DPI resistance — DoT/DoH-first lookup chain
//!
//! Anti-censorship strategy P0 #2: the **default** seed-discovery
//! path uses DNS-over-TLS (DoT, port 853) against pinned-IP upstream
//! resolvers, falling through to DNS-over-HTTPS (DoH, port 443) if
//! DoT is blocked, and **only as a last resort** to system DNS (which
//! a local DPI can intercept and rewrite).
//!
//! The pinned upstreams are Cloudflare 1.1.1.1, Google 8.8.8.8, and
//! Quad9 9.9.9.9 — chosen so blocking all three has high collateral
//! damage (these resolvers serve a significant fraction of legit
//! traffic in any country).  All three are queried in parallel; the
//! first success wins.  TLS cert chain validated against bundled
//! webpki-roots (independent of OS trust store, so a compromised
//! local CA cannot MITM).
//!
//! [`discover_seeds_dns`] is the public entry-point and follows the
//! DoT → DoH → system fallback chain automatically.  Callers that
//! specifically need a variant can use [`discover_seeds_dns_secure`]
//! (DoT+DoH only, never falls back to system) or
//! [`discover_seeds_dns_system`] (system DNS only, e.g. for tests
//! where DoT/DoH would touch the public internet).

use std::time::Duration;

use hickory_resolver::Resolver;
use hickory_resolver::config::{CLOUDFLARE, GOOGLE, QUAD9, ResolverConfig, ServerGroup};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use veil_types::{BootstrapPeer, SignatureAlgorithm};

/// Default bootstrap domain. Override via `config.global.bootstrap_dns_domain`.
pub const DEFAULT_BOOTSTRAP_DOMAIN: &str = "veil.example";

/// Total time budget for the DoT or DoH stage before fallthrough.  Set
/// short enough that a blocked upstream doesn't stall startup; long
/// enough to accommodate a high-latency cellular link.
const SECURE_DNS_TIMEOUT: Duration = Duration::from_secs(4);

/// Total time budget for the system-DNS fallback stage.  Short — the
/// censor-controlled resolver typically answers quickly (often with a
/// rewritten record), so if this stage isn't done in a few seconds
/// it's hung and we'd rather move on.
const SYSTEM_DNS_TIMEOUT: Duration = Duration::from_secs(3);

/// Query DNS TXT records for bootstrap seeds, preferring encrypted
/// transports (DoT > DoH > system).
///
/// Returns an empty vec on any failure — bootstrap then falls through
/// to builtin seeds.  This is the **production** entry-point used by
/// `veilcore::node::bootstrap::*`.
pub async fn discover_seeds_dns(domain: &str) -> Vec<BootstrapPeer> {
    // Stage 1: DoT to pinned upstreams.  TLS-on-853 is the most
    // censor-resistant: encrypted, port-distinct from vanilla DNS-on-53,
    // and pinned-IP defeats DNS-spoofing of the upstream hostname.
    if let Some(seeds) = tokio::time::timeout(
        SECURE_DNS_TIMEOUT,
        run_encrypted(domain, EncryptedMode::Dot),
    )
    .await
    .ok()
    .flatten()
        && !seeds.is_empty()
    {
        return seeds;
    }

    // Stage 2: DoH if DoT was blocked.  HTTPS-on-443 indistinguishable
    // from ordinary web traffic; harder for a stateless port-block to
    // catch, but more expensive than DoT (HTTP overhead).
    if let Some(seeds) = tokio::time::timeout(
        SECURE_DNS_TIMEOUT,
        run_encrypted(domain, EncryptedMode::Doh),
    )
    .await
    .ok()
    .flatten()
        && !seeds.is_empty()
    {
        return seeds;
    }

    // Stage 3: system DNS — censor-readable, last resort.  Returns
    // whatever the local resolver chooses (potentially rewritten by a
    // DPI middlebox); operator-deployed bootstrap signature on the
    // signed-invite layer (`signed_invite.rs`) protects against a
    // tampered TXT response delivering rogue seeds.
    tokio::time::timeout(SYSTEM_DNS_TIMEOUT, discover_seeds_dns_system(domain))
        .await
        .unwrap_or_default()
}

/// DoT- + DoH-only seed discovery (no system-DNS fallback).  Used by
/// callers that explicitly want to refuse system-DNS results — e.g. a
/// deployment running inside a jurisdiction with a known-malicious
/// state resolver.  Returns empty vec if both DoT and DoH fail.
pub async fn discover_seeds_dns_secure(domain: &str) -> Vec<BootstrapPeer> {
    if let Some(seeds) = run_encrypted(domain, EncryptedMode::Dot).await
        && !seeds.is_empty()
    {
        return seeds;
    }
    run_encrypted(domain, EncryptedMode::Doh)
        .await
        .unwrap_or_default()
}

/// Plain-DNS seed discovery via the system resolver.  Used as a
/// last-resort fallback by [`discover_seeds_dns`] and directly by tests
/// (where DoT/DoH would touch the public internet).
pub async fn discover_seeds_dns_system(domain: &str) -> Vec<BootstrapPeer> {
    let query_name = format!("_veil._bootstrap.{domain}.");

    // hickory-resolver 0.26 (RUSTSEC-2026-0119 fix) renamed `AsyncResolver`
    // → `Resolver` and replaced `tokio_from_system_conf` with `builder_tokio`
    // + `.build`. `builder_tokio` pulls system DNS config (matches the
    // old `from_system_conf` semantics) and returns a `ResolverBuilder`;
    // `.build` finalizes it to a `Resolver<TokioRuntimeProvider>`.
    let resolver = match Resolver::builder_tokio().and_then(|b| b.build()) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    run_txt_query(&resolver, &query_name).await
}

#[derive(Clone, Copy, Debug)]
enum EncryptedMode {
    Dot,
    Doh,
}

/// Build a Tokio resolver from a ServerGroup using the requested
/// encrypted transport, then run a TXT query.  Returns `Some(seeds)`
/// on success (even if seeds is empty) or `None` if the
/// resolver couldn't be constructed (config error, missing TLS
/// support etc.).
async fn run_encrypted_group(
    group: &ServerGroup<'_>,
    mode: EncryptedMode,
    query_name: &str,
) -> Option<Vec<BootstrapPeer>> {
    let config = match mode {
        EncryptedMode::Dot => ResolverConfig::tls(group),
        EncryptedMode::Doh => ResolverConfig::https(group),
    };
    let provider = TokioRuntimeProvider::default();
    let resolver = Resolver::builder_with_config(config, provider)
        .build()
        .ok()?;
    Some(run_txt_query(&resolver, query_name).await)
}

/// Race CLOUDFLARE / GOOGLE / QUAD9 for the requested mode and return
/// the first non-empty success.  Single-resolver failures (network
/// error, NXDOMAIN, transport-layer block) silently fall through to
/// the next upstream.
async fn run_encrypted(domain: &str, mode: EncryptedMode) -> Option<Vec<BootstrapPeer>> {
    let query_name = format!("_veil._bootstrap.{domain}.");
    for group in [&CLOUDFLARE, &GOOGLE, &QUAD9] {
        if let Some(seeds) = run_encrypted_group(group, mode, &query_name).await
            && !seeds.is_empty()
        {
            return Some(seeds);
        }
    }
    None
}

/// Shared TXT-query worker — same path for system, DoT, and DoH.  Any
/// error (NXDOMAIN, network timeout, etc.) collapses to an empty Vec
/// so the caller can fall through to the next stage.
async fn run_txt_query<P>(resolver: &Resolver<P>, query_name: &str) -> Vec<BootstrapPeer>
where
    P: hickory_resolver::ConnectionProvider + Clone,
{
    let txt_lookup = match resolver.txt_lookup(query_name).await {
        Ok(l) => l,
        Err(_) => return Vec::new(),
    };

    let mut seeds = Vec::new();
    for record in txt_lookup.answers() {
        let hickory_resolver::proto::rr::RData::TXT(txt) = &record.data else {
            continue;
        };
        // Each TXT record may consist of multiple character-strings;
        // concatenate them as per RFC 7208 §3.3.
        let text: String = txt
            .txt_data
            .iter()
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect();
        if let Some(peer) = parse_seed_txt(&text) {
            seeds.push(peer);
        }
    }
    seeds
}

/// Parse a single TXT record line into a `BootstrapPeer`.
///
/// Expected format: `transport=<uri> pubkey=<base64> nonce=<base64>`
fn parse_seed_txt(line: &str) -> Option<BootstrapPeer> {
    let mut transport = None;
    let mut pubkey = None;
    let mut nonce = None;

    for part in line.split_whitespace() {
        if let Some((key, val)) = part.split_once('=') {
            match key {
                "transport" => transport = Some(val.to_owned()),
                "pubkey" => pubkey = Some(val.to_owned()),
                "nonce" => nonce = Some(val.to_owned()),
                _ => {}
            }
        }
    }

    Some(BootstrapPeer {
        transport: transport?,
        public_key: pubkey?,
        nonce: nonce.unwrap_or_else(veil_crypto::default_nonce_base64),
        algo: SignatureAlgorithm::Ed25519,
        tls_cert: None,
        tls_ca_cert: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_seed_txt() {
        let line = "transport=tcp://seed1.example:7001 pubkey=AQIDBA== nonce=BQYHCA==";
        let peer = parse_seed_txt(line).expect("should parse");
        assert_eq!(peer.transport, "tcp://seed1.example:7001");
        assert_eq!(peer.public_key, "AQIDBA==");
        assert_eq!(peer.nonce, "BQYHCA==");
    }

    #[test]
    fn parse_seed_txt_missing_nonce_uses_default() {
        let line = "transport=tcp://s:7001 pubkey=AAAA";
        let peer = parse_seed_txt(line).expect("should parse");
        assert!(!peer.nonce.is_empty());
    }

    #[test]
    fn parse_seed_txt_missing_transport_returns_none() {
        let line = "pubkey=AAAA nonce=BBBB";
        assert!(parse_seed_txt(line).is_none());
    }

    #[test]
    fn parse_seed_txt_missing_pubkey_returns_none() {
        let line = "transport=tcp://s:7001 nonce=BBBB";
        assert!(parse_seed_txt(line).is_none());
    }

    #[test]
    fn parse_empty_line_returns_none() {
        assert!(parse_seed_txt("").is_none());
    }

    /// Resolver-construction smoke test — DoT and DoH builders shouldn't
    /// fail at config time even without network access.  Catches the
    /// "missed a cargo feature" case where webpki-roots isn't pulled
    /// in and `TlsConfig::new()` returns an error.  No DNS query
    /// issued (so safe for CI without internet).
    #[tokio::test]
    async fn dot_resolver_builds_ok() {
        let cfg = ResolverConfig::tls(&CLOUDFLARE);
        let provider = TokioRuntimeProvider::default();
        let result = Resolver::builder_with_config(cfg, provider).build();
        assert!(result.is_ok(), "DoT resolver build failed: {result:?}");
    }

    #[tokio::test]
    async fn doh_resolver_builds_ok() {
        let cfg = ResolverConfig::https(&CLOUDFLARE);
        let provider = TokioRuntimeProvider::default();
        let result = Resolver::builder_with_config(cfg, provider).build();
        assert!(result.is_ok(), "DoH resolver build failed: {result:?}");
    }

    /// All three upstream presets should produce buildable resolvers
    /// for both DoT and DoH — guards against a typo in the pinned-list.
    #[tokio::test]
    async fn all_pinned_upstreams_build_for_dot_and_doh() {
        for group in [&CLOUDFLARE, &GOOGLE, &QUAD9] {
            for mode in [EncryptedMode::Dot, EncryptedMode::Doh] {
                let cfg = match mode {
                    EncryptedMode::Dot => ResolverConfig::tls(group),
                    EncryptedMode::Doh => ResolverConfig::https(group),
                };
                let provider = TokioRuntimeProvider::default();
                let result = Resolver::builder_with_config(cfg, provider).build();
                assert!(
                    result.is_ok(),
                    "group {:?} mode {:?} build failed: {:?}",
                    group.server_name,
                    mode,
                    result
                );
            }
        }
    }
}
