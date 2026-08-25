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

/// The encrypted upstreams, in the order they are tried.
const ENCRYPTED_UPSTREAMS: [&ServerGroup<'_>; 3] = [&CLOUDFLARE, &GOOGLE, &QUAD9];

/// What ONE encrypted upstream may spend before the next is tried.
///
/// `SECURE_DNS_TIMEOUT` divided by the number of upstreams, so every one of
/// them is reached within the stage's budget even when the earlier ones hang.
/// Kept as an expression rather than a number: adding a fourth upstream must
/// shrink the slice rather than silently overrun the stage — the arithmetic is
/// asserted in the tests below.
const PER_UPSTREAM_DNS_TIMEOUT: Duration = Duration::from_millis(
    (SECURE_DNS_TIMEOUT.as_millis() / ENCRYPTED_UPSTREAMS.len() as u128) as u64,
);

/// Query DNS TXT records for bootstrap seeds, preferring encrypted
/// transports (DoT > DoH > system).
///
/// Returns an empty vec on any failure — bootstrap then falls through
/// to builtin seeds.  This is the **production** entry-point used by
/// `veilcore::node::bootstrap::*`.
/// What an operator will accept from DNS bootstrap discovery.
///
/// A TXT record is not signed. DoT and DoH authenticate the RESOLVER, not the
/// record, and the system-DNS last resort authenticates nothing at all — so a
/// local resolver or an on-path middlebox chooses the seeds a fresh node first
/// talks to. The handshake still proves each peer is who it claims, so this is
/// not impersonation; it is eclipse, fingerprinting and denial
/// (report14 V14-M9).
///
/// What an operator can do about it is say in advance what they expect, and
/// say whether the unauthenticated stage may run at all. Both default to
/// today's behaviour: no pins, last resort allowed.
#[derive(Debug, Clone)]
pub struct DnsBootstrapPolicy {
    /// Base64 public keys the operator expects. EMPTY means no pinning; with
    /// any entry, a discovered peer whose key is not among them is dropped —
    /// from EVERY stage, because no stage authenticates the record.
    pub pinned_public_keys: Vec<String>,
    /// Whether the system-DNS stage may run. `false` means secure-only: if DoT
    /// and DoH are both blocked, discovery returns nothing rather than
    /// whatever the local resolver chooses.
    pub allow_unsigned_system_dns: bool,
}

impl Default for DnsBootstrapPolicy {
    fn default() -> Self {
        Self {
            pinned_public_keys: Vec::new(),
            allow_unsigned_system_dns: true,
        }
    }
}

impl DnsBootstrapPolicy {
    /// Drop anything the operator did not ask for. No pins ⇒ unchanged.
    fn admit(&self, seeds: Vec<BootstrapPeer>) -> Vec<BootstrapPeer> {
        if self.pinned_public_keys.is_empty() {
            return seeds;
        }
        seeds
            .into_iter()
            .filter(|p| self.pinned_public_keys.iter().any(|k| k == &p.public_key))
            .collect()
    }
}

/// [`discover_seeds_dns`] under an explicit policy.
pub async fn discover_seeds_dns_with_policy(
    domain: &str,
    policy: &DnsBootstrapPolicy,
) -> Vec<BootstrapPeer> {
    discover_seeds_dns_inner(domain, policy).await
}

pub async fn discover_seeds_dns(domain: &str) -> Vec<BootstrapPeer> {
    discover_seeds_dns_inner(domain, &DnsBootstrapPolicy::default()).await
}

async fn discover_seeds_dns_inner(domain: &str, policy: &DnsBootstrapPolicy) -> Vec<BootstrapPeer> {
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
        && !policy.admit(seeds.clone()).is_empty()
    {
        return policy.admit(seeds);
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
        && !policy.admit(seeds.clone()).is_empty()
    {
        return policy.admit(seeds);
    }

    // Stage 3: system DNS — censor-readable, last resort.  Returns
    // whatever the local resolver chooses, and NOTHING here authenticates
    // it: `parse_seed_txt` reads transport, pubkey and nonce, and there is
    // no issuer signature in the record to check.  This comment used to
    // claim the signed-invite layer covered it; it does not — that layer
    // signs invites, not TXT records, so a resolver or an on-path
    // middlebox chooses these seeds outright.
    //
    // What bounds it is where it sits rather than what it proves: the
    // caller reaches DNS discovery only when the node has no configured
    // and no builtin peers at all, so there is nothing here for rogue
    // seeds to displace, and `MAX_BOOTSTRAP_SEEDS_PER_SOURCE` caps what
    // one source can contribute.  A node with no other contact can still
    // have its first ones chosen for it, which is why stages 1 and 2 are
    // given a budget each upstream can actually use.
    if !policy.allow_unsigned_system_dns {
        // Secure-only: an operator who says so would rather have no seeds than
        // seeds a middlebox chose.
        return Vec::new();
    }
    policy.admit(
        tokio::time::timeout(SYSTEM_DNS_TIMEOUT, discover_seeds_dns_system(domain))
            .await
            .unwrap_or_default(),
    )
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
///
/// # Android
///
/// Returns an empty vec without building a resolver.  Hickory reads the
/// system nameserver list on Android by calling into the JVM, and its
/// very first statement is `ndk_context::android_context()` — an
/// `expect` on a static this workspace never initialises.  Under the
/// workspace's `panic = "abort"` that is a `SIGABRT` on whichever tokio
/// worker ran the task, not the `Err` the `match` below is written
/// against.  See [`veil_util::system_dns_config_readable`].
///
/// Skipping the stage costs Android the censor-readable last resort
/// only: the DoT and DoH stages above dial pinned upstream IPs and are
/// unaffected, so seed discovery still works.
pub async fn discover_seeds_dns_system(domain: &str) -> Vec<BootstrapPeer> {
    if !veil_util::system_dns_config_readable(std::env::consts::OS) {
        return Vec::new();
    }

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

/// Try CLOUDFLARE, then GOOGLE, then QUAD9 for the requested mode and
/// return the first non-empty success.  Single-resolver failures
/// (network error, NXDOMAIN, transport-layer block) fall through to the
/// next upstream.
///
/// In series, not raced — the doc here said "Race" and the code never
/// did, which matters because the two disclose differently: asking one
/// upstream and stopping tells only that one what this node is looking
/// for, and racing tells all three.  Kept in series for that reason;
/// what was actually broken was the budget, below.
///
/// EACH UPSTREAM GETS ITS OWN SLICE.  The stage as a whole had a single
/// 4-second timeout and nothing bounded one upstream inside it, so a
/// blocked resolver — which does not refuse, it hangs, and is exactly
/// what this staging exists for — consumed the entire budget and the
/// other two were never tried.  DoT then failed, DoH lost its own
/// budget the same way, and the node arrived at plain system DNS: the
/// censorship this ladder is built against was what collapsed it onto
/// the one rung that a censor can rewrite.
async fn run_encrypted(domain: &str, mode: EncryptedMode) -> Option<Vec<BootstrapPeer>> {
    let query_name = format!("_veil._bootstrap.{domain}.");
    for group in ENCRYPTED_UPSTREAMS {
        let Ok(Some(seeds)) = tokio::time::timeout(
            PER_UPSTREAM_DNS_TIMEOUT,
            run_encrypted_group(group, mode, &query_name),
        )
        .await
        else {
            continue;
        };
        if !seeds.is_empty() {
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

    fn peer(pk: &str) -> BootstrapPeer {
        BootstrapPeer {
            transport: "tcp://seed.example:9000".into(),
            public_key: pk.into(),
            nonce: String::new(),
            algo: veil_types::SignatureAlgorithm::Ed25519,
            tls_cert: None,
            tls_ca_cert: None,
        }
    }

    /// A TXT record is not signed, on any of the three stages: DoT and DoH
    /// authenticate the RESOLVER and the system-DNS last resort authenticates
    /// nothing. An operator who knows which seeds they expect can say so, and
    /// then a resolver's choices are refused (report14 V14-M9).
    #[test]
    fn a_pinned_operator_takes_only_the_seeds_they_named() {
        let policy = DnsBootstrapPolicy {
            pinned_public_keys: vec!["theirs".into()],
            ..Default::default()
        };
        let admitted = policy.admit(vec![peer("theirs"), peer("somebody-elses")]);
        assert_eq!(admitted.len(), 1);
        assert_eq!(admitted[0].public_key, "theirs");
    }

    /// And the default keeps today's behaviour exactly: no pins, everything
    /// through, last resort allowed. A gate that changed what every existing
    /// config does would be a different kind of failure.
    #[test]
    fn the_default_policy_changes_nothing() {
        let policy = DnsBootstrapPolicy::default();
        assert!(policy.pinned_public_keys.is_empty());
        assert!(policy.allow_unsigned_system_dns);
        let seeds = vec![peer("a"), peer("b")];
        assert_eq!(policy.admit(seeds).len(), 2);
    }
    use super::*;

    /// Every encrypted upstream must be reachable inside the stage's budget.
    ///
    /// The stage had one 4-second timeout and nothing bounded a single
    /// upstream inside it, so a blocked resolver — which hangs rather than
    /// refusing, and is exactly what this ladder exists for — spent the whole
    /// budget and the other two were never tried. DoT failed, DoH lost its own
    /// budget the same way, and the node arrived at plain system DNS: the one
    /// rung a censor can rewrite, reached BECAUSE of the censorship.
    #[test]
    fn every_upstream_fits_inside_the_stage_budget() {
        let worst_case = PER_UPSTREAM_DNS_TIMEOUT * ENCRYPTED_UPSTREAMS.len() as u32;
        assert!(
            worst_case <= SECURE_DNS_TIMEOUT,
            "all {} upstreams hanging costs {worst_case:?}, past the stage's \
             {SECURE_DNS_TIMEOUT:?} — the last ones would never be tried",
            ENCRYPTED_UPSTREAMS.len(),
        );
        assert!(
            !PER_UPSTREAM_DNS_TIMEOUT.is_zero(),
            "a slice of zero refuses every upstream instantly",
        );
    }

    /// A seed read off plain DNS carries no proof of who issued it.
    ///
    /// Pinned here because the stage-3 comment used to claim the signed-invite
    /// layer covered these records. It does not, and a reader who believes it
    /// would treat the last rung as authenticated.
    #[test]
    fn a_txt_seed_carries_no_issuer_proof() {
        let line = "transport=tcp://s:7001 pubkey=AAAA sig=anything issuer=someone";
        let peer = parse_seed_txt(line).expect("should parse");
        assert_eq!(peer.transport, "tcp://s:7001");
        assert_eq!(peer.public_key, "AAAA");
        assert!(
            peer.tls_cert.is_none() && peer.tls_ca_cert.is_none(),
            "nothing in a BootstrapPeer holds an issuer signature, so the \
             fields a record might carry one in are dropped unread",
        );
    }

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
