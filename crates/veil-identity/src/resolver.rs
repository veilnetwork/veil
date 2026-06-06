//! `@name → ValidatedIdentity` resolver pipeline.
//!
//! Takes a human-readable handle like `alice` or `alice#1234`, looks
//! up its `NameClaim` in the DHT, resolves that claim's
//! `node_id` to an `IdentityDocument`, verifies both layers, and
//! returns the fully-validated identity ready for session
//! establishment.
//!
//! ```text
//! +---------+ +----------------+
//! name -> cache? | yes-> | NameClaim | -\
//! +---------+ | + Identity Doc | |
//! | no +----------------+ |
//! v |
//! +----------------+ |
//! | NameLookup DHT | ---> NameClaim v
//! +----------------+ | ValidatedIdentity
//! v
//! +-----------------------+
//! | IdentityLookup DHT | ---> IdentityDocument
//! +-----------------------+ |
//! v
//! verifier
//!
//! ```
//!
//! ## Layered verification
//!
//! Both the `NameClaim` and the `IdentityDocument` are verified in
//! the same pass:
//!
//! `NameClaim`:
//! ASCII whitelist (enforced at decode);
//! `freshness_hour` within `±FRESHNESS_HOUR_SKEW` of now/3600;
//! PoW ≥ `required_difficulty(name)`;
//! `signing_identity_key_idx` selects an in-bounds subkey of the
//! node_id, and that subkey's signature over
//! `NAME_CLAIM_SIG_CONTEXT || canonical_signing_bytes` verifies.
//!
//! `IdentityDocument`: [`verify_identity_document`] (
//! simplified by), producing a [`ValidatedIdentity`].
//!
//! ## DI-friendly backends
//!
//! The resolver takes two [`async_trait`]-style backends — one per
//! key class — so unit tests can plug in in-memory fakes without
//! wiring up a real DHT. Production code wires the veil DHT
//! runtime as the implementor.

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ed25519_dalek::{Signature as EdSignature, Verifier as _, VerifyingKey as EdVerifyingKey};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

use veil_proto::identity_document::{ALGO_ED25519, ALGO_FALCON512, IdentityDocument};
use veil_proto::name_claim_v2::{
    NAME_CLAIM_SIG_CONTEXT, NameClaim, normalize_name, required_difficulty,
};

use super::migration::{
    MigrationCert, decode_migration_cert, migration_cert_dht_key, pubkey_bytes_to_b64,
    verify_migration_cert,
};
use super::verify::{ValidatedIdentity, VerifyError, verify_identity_document};

/// maximum migration-cert chain depth followed by the
/// resolver before giving up. `1` is the typical case (one rotation
/// from old → new identity); higher values (`MAX_MIGRATION_CHAIN_DEPTH
/// = 4`) cover successive rotations published across multiple
/// migration cycles, but still bound the worst-case lookup cost.
/// Cycle detection is layered on top via a visited-set so a malicious
/// peer can't trap the resolver in a loop even within the depth cap.
pub const MAX_MIGRATION_CHAIN_DEPTH: u32 = 4;

/// Maximum `|claim.freshness_hour - now/3600|` accepted (in hours).
///
/// Replaces the previously-shared `FRESHNESS_HOUR_SKEW` constant from
/// `verify.rs` (removed.S1b). Used only by the
/// name-claim layer; identity documents now rely on
/// `valid_until_unix` alone.
pub const NAME_CLAIM_FRESHNESS_HOUR_SKEW: u32 = 2;

// ── Policy knobs ─────────────────────────────────────────────────────────────

/// How long a successful `name → node_id` resolution is cached.
///
/// Short enough that a revocation published while we hold a cached
/// entry is picked up within one TTL window; long enough that a
/// chatty caller doesn't hammer the DHT per message.
pub const NAME_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Cap on the number of cached name resolutions — unbounded growth
/// would turn a chatty app into a memory leak.
pub const NAME_CACHE_CAPACITY: usize = 4096;

// ── Backends ─────────────────────────────────────────────────────────────────

/// DHT lookup for a name claim by its 32-byte slot key.
///
/// Returns `Ok(None)` for "name unregistered" (no value in DHT)
/// `Err(...)` for transport/timeout failures.
#[async_trait]
pub trait NameLookup: Send + Sync {
    async fn fetch_name_claim(&self, dht_key: &[u8; 32]) -> Result<Option<Vec<u8>>, LookupError>;

    /// Fetch up to `n_replicas` independent values for `dht_key` from
    /// distinct DHT replica paths.
    ///
    /// Backends without a way to distinguish replicas can keep the
    /// default implementation, which returns at most one value —
    /// the resolver then falls back to no-quorum behaviour. Backends
    /// that route queries through separate paths should override to
    /// return one result per replica actually reached.
    ///
    /// Empty `Vec` means "no replica returned a value" (not an error).
    async fn fetch_name_claim_replicated(
        &self,
        dht_key: &[u8; 32],
        n_replicas: usize,
    ) -> Result<Vec<Vec<u8>>, LookupError> {
        let _ = n_replicas;
        Ok(self.fetch_name_claim(dht_key).await?.into_iter().collect())
    }
}

/// DHT lookup for an identity document by its 32-byte slot key.
#[async_trait]
pub trait IdentityLookup: Send + Sync {
    async fn fetch_identity_document(
        &self,
        dht_key: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, LookupError>;

    /// fetch a `MigrationCert` blob (if any) published
    /// under `dht_key = migration_cert_dht_key(old_node_id)`. Returns
    /// `Ok(None)` when no migration cert exists for this old identity
    /// (the typical case — `resolve` simply proceeds with the original
    /// IdentityDocument).
    ///
    /// Default impl returns `Ok(None)` so existing in-memory test
    /// backends and historical implementations keep compiling without
    /// claiming migration support. Production DHT backends override
    /// this to route the query to the same Kademlia GET path used for
    /// identity documents.
    async fn fetch_migration_cert(
        &self,
        dht_key: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, LookupError> {
        let _ = dht_key;
        Ok(None)
    }

    /// fetch up to `n_replicas` independent `MigrationCert`
    /// blobs for `dht_key`. Used by the resolver to defend against an
    /// attacker who publishes a downgrade or unrelated cert on one
    /// replica path: when divergent values come back, the resolver
    /// picks the highest-security_tier candidate AND requires the
    /// signature to verify against the OLD master pubkey.
    ///
    /// Default impl falls back to `fetch_migration_cert` (single
    /// replica), which loses the cross-replica defence but stays
    /// safe — verification still rejects forged certs.
    async fn fetch_migration_cert_replicated(
        &self,
        dht_key: &[u8; 32],
        n_replicas: usize,
    ) -> Result<Vec<Vec<u8>>, LookupError> {
        let _ = n_replicas;
        Ok(self
            .fetch_migration_cert(dht_key)
            .await?
            .into_iter()
            .collect())
    }
}

/// Convenience bundle — implementors that do both can simply
/// implement `ResolverBackend` and pass a single value to the
/// resolver.
pub trait ResolverBackend: NameLookup + IdentityLookup {}
impl<T: NameLookup + IdentityLookup> ResolverBackend for T {}

/// Opaque backend-layer error. Kept intentionally string-typed so
/// we don't prescribe what the DHT runtime's real error type has to
/// be — the resolver only ever logs/bubbles it.
#[derive(Debug, thiserror::Error)]
#[error("dht lookup failed: {0}")]
pub struct LookupError(pub String);

impl LookupError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("invalid name: {0}")]
    InvalidName(String),
    #[error("name claim not found in DHT")]
    NameNotFound,
    #[error("identity document not found for {0:?}")]
    IdentityNotFound([u8; 32]),
    #[error("name claim malformed: {0}")]
    NameClaimMalformed(String),
    #[error("identity document malformed: {0}")]
    IdentityDocMalformed(String),
    #[error("name claim freshness_hour {doc} outside ±{skew} of now/3600 = {now}")]
    NameClaimFreshnessHourSkew { doc: u32, now: u32, skew: u32 },
    #[error("name claim PoW below required difficulty {required}")]
    NameClaimPowTooWeak { required: u32 },
    #[error("name claim signing subkey idx {idx} out of bounds ({n_keys} keys)")]
    NameClaimSigKeyOutOfBounds { idx: u16, n_keys: usize },
    #[error("name claim signature invalid")]
    NameClaimSigInvalid,
    #[error("identity document verification failed: {0}")]
    IdentityDocInvalid(VerifyError),
    #[error("dht lookup failed: {0}")]
    Lookup(#[from] LookupError),
    #[error(
        "name claim replicas disagree after {queried} queries \
         (best candidate count {best}/{required})"
    )]
    QuorumDivergence {
        queried: usize,
        best: usize,
        required: usize,
    },
    #[error("migration cert malformed: {0}")]
    MigrationCertMalformed(String),
    #[error("migration cert verify failed: {0}")]
    MigrationCertInvalid(String),
    #[error("migration cert chain depth exceeded {max_depth} hops — refusing to follow further")]
    MigrationChainTooDeep { max_depth: u32 },
    #[error("migration cert chain cycle detected at hop {hop}, node_id={node_id:?}")]
    MigrationChainCycle { hop: u32, node_id: [u8; 32] },
}

// ── Resolver ─────────────────────────────────────────────────────────────────

/// Resolves `@name` handles into [`ValidatedIdentity`] values.
///
/// The resolver owns a small positive cache (`name → node_id`).
/// Cache misses consult the DHT backend; negative results are not
/// cached so a freshly-registered name becomes visible without
/// waiting for a TTL to expire.
pub struct NameResolver<B: ResolverBackend> {
    backend: B,
    cache: RwLock<NameCache>,
    verify_config: VerifyConfig,
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyConfig {
    /// Minimum number of matching replica responses required to
    /// accept a name-claim lookup. `1` disables
    /// quorum entirely — the first successful fetch wins.
    pub resolver_quorum: usize,
    /// Upper bound on the number of replicas the resolver will
    /// query before giving up with a `QuorumDivergence` error.
    /// Must satisfy `resolver_max_replicas ≥ resolver_quorum`.
    pub resolver_max_replicas: usize,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            resolver_quorum: 2,
            resolver_max_replicas: 5,
        }
    }
}

struct NameCache {
    entries: HashMap<String, CacheEntry>,
    // Most-recent-insertion-wins eviction when we hit capacity.
    // Simple and correct: the cache exists to absorb hot repetition
    // not to model long-tail access.
    last_touch: Mutex<HashMap<String, Instant>>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    node_id: [u8; 32],
    cached_at: Instant,
}

impl<B: ResolverBackend> NameResolver<B> {
    pub fn new(backend: B) -> Self {
        Self::with_config(backend, VerifyConfig::default())
    }

    pub fn with_config(backend: B, cfg: VerifyConfig) -> Self {
        Self {
            backend,
            cache: RwLock::new(NameCache {
                entries: HashMap::new(),
                last_touch: Mutex::new(HashMap::new()),
            }),
            verify_config: cfg,
        }
    }

    /// Resolve `name` to a fully-validated identity.
    ///
    /// `now_unix_secs` is passed explicitly so callers can anchor a
    /// batch of resolutions to one consistent clock reading — this
    /// eliminates subtle discrepancies between the freshness checks
    /// applied to the name claim and the identity document.
    ///
    /// When `VerifyConfig::resolver_quorum > 1`, the name-claim
    /// lookup queries up to `resolver_max_replicas` distinct DHT
    /// paths and requires that many matching results before
    /// accepting. Divergent results (classic eclipse attack
    /// symptom) surface as [`ResolveError::QuorumDivergence`].
    pub async fn resolve(
        &self,
        name: &str,
        now_unix_secs: u64,
    ) -> Result<ValidatedIdentity, ResolveError> {
        let normalized =
            normalize_name(name).map_err(|e| ResolveError::InvalidName(e.to_string()))?;

        // Fast path: cached `name → node_id`. Even with the
        // cache we still re-fetch + re-verify the IdentityDocument
        // because rotation events invalidate identity metadata at a
        // faster cadence than the name binding.
        let cached_id = self.peek_cache(&normalized);

        // Fetch and validate (or skip on cache hit) the name claim
        // before touching the identity document.
        let claim = if cached_id.is_none() {
            Some(self.fetch_name_claim_with_policy(&normalized).await?)
        } else {
            None
        };
        let node_id = cached_id
            .or_else(|| claim.as_ref().map(|c| c.node_id))
            .expect("one of the two paths sets node_id");

        // Fetch + verify the ORIGINAL identity document — the one
        // referenced by the name claim's `node_id`. This is the
        // identity that signed the name claim, so verify_name_claim
        // MUST check against THIS doc, not whatever the chain-walk
        // ends up at.
        let original_doc_key = IdentityDocument::dht_key(&node_id);
        let original_doc_bytes = self
            .backend
            .fetch_identity_document(&original_doc_key)
            .await?
            .ok_or(ResolveError::IdentityNotFound(node_id))?;
        let original_doc = IdentityDocument::decode(&original_doc_bytes)
            .map_err(|e| ResolveError::IdentityDocMalformed(e.to_string()))?;
        // Defence-in-depth: the DHT slot is keyed by `node_id`, but a
        // peer that controls the slot could serve a self-consistent
        // document for a DIFFERENT identity (one that passes
        // `verify_identity_document`'s internal BLAKE3(master)==node_id
        // check). Bind the fetched document to the slot we asked for.
        if original_doc.node_id != node_id {
            return Err(ResolveError::IdentityDocMalformed(format!(
                "DHT returned IdentityDocument for {} but resolver asked for {}",
                veil_util::hex_short(&original_doc.node_id),
                veil_util::hex_short(&node_id),
            )));
        }
        let _original_validated = verify_identity_document(&original_doc, now_unix_secs)
            .map_err(ResolveError::IdentityDocInvalid)?;

        // Verify the name claim against the document that signed it
        // BEFORE following any migration chain — the chain hops change
        // who you talk to, not "what name does this identity claim".
        if let Some(ref claim) = claim {
            self.verify_name_claim(claim, &original_doc, now_unix_secs)?;
        }

        // walk any migration-cert chain rooted at this
        // node_id and return the most-recent migrated identity. Name
        // continuity: the claim still cryptographically binds the
        // name to the old identity, and the migration cert
        // cryptographically binds the old identity to the new one —
        // chain of trust intact end to end.
        let validated = self
            .resolve_with_migration_chain(node_id, now_unix_secs)
            .await?;

        if let Some(claim) = claim {
            // Cache against the original requested name → caller's
            // node_id (not the migrated one) so on the next call we
            // re-walk the chain (cheap, one DHT GET) and pick up
            // freshly-published rotations.
            self.insert_cache(normalized.clone(), claim.node_id);
        } else {
            self.touch(&normalized);
        }

        Ok(validated)
    }

    /// fetch the IdentityDocument at `start_node_id`
    /// then follow any chain of MigrationCerts rooted there until
    /// either:
    /// • no migration cert exists for the current node_id (steady
    /// state — return the document we just fetched)
    /// • the chain hits depth `MAX_MIGRATION_CHAIN_DEPTH` (refuse
    /// to follow further; surface `MigrationChainTooDeep`)
    /// • the chain visits a node_id we already saw (loop attack;
    /// surface `MigrationChainCycle`).
    ///
    /// Each hop's `MigrationCert.signature` is verified against the
    /// CURRENT document's `master_pubkey`, so an attacker who only
    /// controls the DHT cannot forge a migration: they'd need the
    /// old master's secret to mint a cert that binds to their new
    /// pubkey. Replica divergence is handled by
    /// `fetch_best_migration_cert`: the highest-security_tier valid
    /// candidate wins; ties broken by `issued_at_unix` (newer wins).
    async fn resolve_with_migration_chain(
        &self,
        start_node_id: [u8; 32],
        now_unix_secs: u64,
    ) -> Result<ValidatedIdentity, ResolveError> {
        let mut current_node_id = start_node_id;
        let mut visited: Vec<[u8; 32]> = vec![current_node_id];

        for hop in 0..=MAX_MIGRATION_CHAIN_DEPTH {
            let doc_key = IdentityDocument::dht_key(&current_node_id);
            let doc_bytes = self
                .backend
                .fetch_identity_document(&doc_key)
                .await?
                .ok_or(ResolveError::IdentityNotFound(current_node_id))?;
            let doc = IdentityDocument::decode(&doc_bytes)
                .map_err(|e| ResolveError::IdentityDocMalformed(e.to_string()))?;
            // Same slot/identity binding as the original-document path:
            // each migration hop fetches a document by its node_id, so
            // reject a self-consistent document served for the wrong
            // identity. The migration cert cryptographically names
            // `new_node_id`, but the document published at that slot is
            // otherwise unauthenticated against the slot key.
            if doc.node_id != current_node_id {
                return Err(ResolveError::IdentityDocMalformed(format!(
                    "DHT returned IdentityDocument for {} but resolver asked for {}",
                    veil_util::hex_short(&doc.node_id),
                    veil_util::hex_short(&current_node_id),
                )));
            }
            let validated = verify_identity_document(&doc, now_unix_secs)
                .map_err(ResolveError::IdentityDocInvalid)?;

            // Check for a migration cert published for THIS node_id.
            // No cert ⇒ steady state, return.
            let cert_key = migration_cert_dht_key(&current_node_id);
            let cert = match self
                .fetch_best_migration_cert(&cert_key, &doc, now_unix_secs)
                .await?
            {
                Some(c) => c,
                None => return Ok(validated),
            };

            if hop == MAX_MIGRATION_CHAIN_DEPTH {
                return Err(ResolveError::MigrationChainTooDeep {
                    max_depth: MAX_MIGRATION_CHAIN_DEPTH,
                });
            }

            let next = cert.new_node_id;
            if visited.iter().any(|n| n == &next) {
                return Err(ResolveError::MigrationChainCycle {
                    hop: hop + 1,
                    node_id: next,
                });
            }
            visited.push(next);
            current_node_id = next;
        }
        // Loop body always returns; the unreachable! satisfies the
        // compiler but also doubles as a runtime invariant tripwire
        // if `MAX_MIGRATION_CHAIN_DEPTH` is set to 0.
        unreachable!("migration-chain loop must return inside the body");
    }

    /// fetch up to `resolver_max_replicas` migration-cert
    /// candidates, decode each, verify against `current_doc.master_pubkey`
    /// and return the one with the highest security_tier (ties broken by
    /// `issued_at_unix` descending). Returns `Ok(None)` only when
    /// every replica returns no value (`fetch_migration_cert` ⇒ None).
    /// Malformed/invalid candidates are silently dropped — the resolver
    /// only surfaces an error when it has to (no value at all OR every
    /// replica returned a malformed blob, in which case we report the
    /// first decode failure).
    async fn fetch_best_migration_cert(
        &self,
        dht_key: &[u8; 32],
        current_doc: &IdentityDocument,
        now_unix_secs: u64,
    ) -> Result<Option<MigrationCert>, ResolveError> {
        let max_replicas = self.verify_config.resolver_max_replicas.max(1);
        let blobs = self
            .backend
            .fetch_migration_cert_replicated(dht_key, max_replicas)
            .await?;
        if blobs.is_empty() {
            return Ok(None);
        }

        let old_master_b64 = pubkey_bytes_to_b64(&current_doc.master_pubkey);
        let mut best: Option<MigrationCert> = None;
        let mut first_decode_err: Option<String> = None;
        for blob in &blobs {
            let cert = match decode_migration_cert(blob) {
                Ok(c) => c,
                Err(e) => {
                    if first_decode_err.is_none() {
                        first_decode_err = Some(e.to_string());
                    }
                    continue;
                }
            };
            // Algo + structural binding + signature verify against
            // current master. Stale-but-signed certs (window expired)
            // are dropped — the resolver wants live migrations only.
            if verify_migration_cert(&cert, &old_master_b64, now_unix_secs).is_err() {
                continue;
            }
            best = match best {
                None => Some(cert),
                Some(prev) => {
                    // Single source of truth (audit U7) — ranks Falcon-1024
                    // hybrid (tier 4) correctly, unlike the deleted local dup.
                    let prev_tier = super::migration::security_tier(prev.new_master_algo);
                    let cur_tier = super::migration::security_tier(cert.new_master_algo);
                    if cur_tier > prev_tier
                        || (cur_tier == prev_tier && cert.issued_at_unix > prev.issued_at_unix)
                    {
                        Some(cert)
                    } else {
                        Some(prev)
                    }
                }
            };
        }

        if best.is_none()
            && let Some(msg) = first_decode_err
        {
            return Err(ResolveError::MigrationCertMalformed(msg));
        }
        // All replicas decoded but none verified — treat the same
        // as "no migration cert published" (resolver continues with
        // the current doc). This matches the model: an attacker
        // who can publish junk under the cert key shouldn't be
        // able to stall name resolution by spamming invalid blobs.
        Ok(best)
    }

    /// Fetch a single `NameClaim` from the DHT, applying quorum
    /// policy when `resolver_quorum > 1`.
    async fn fetch_name_claim_with_policy(
        &self,
        normalized: &str,
    ) -> Result<NameClaim, ResolveError> {
        let key = NameClaim::dht_key(normalized);
        let quorum = self.verify_config.resolver_quorum.max(1);
        let max_replicas = self.verify_config.resolver_max_replicas.max(quorum);

        if quorum == 1 {
            let bytes = self
                .backend
                .fetch_name_claim(&key)
                .await?
                .ok_or(ResolveError::NameNotFound)?;
            return self.decode_and_check_name(&bytes, normalized);
        }

        // Quorum path: sample `max_replicas` distinct DHT paths
        // tally raw bytes, require at least `quorum` matches.
        let replies = self
            .backend
            .fetch_name_claim_replicated(&key, max_replicas)
            .await?;
        let queried = replies.len();

        let mut tally: HashMap<Vec<u8>, usize> = HashMap::new();
        for r in &replies {
            *tally.entry(r.clone()).or_insert(0) += 1;
        }

        let (best_bytes, best_count) = tally
            .iter()
            .max_by_key(|(_, c)| **c)
            .map(|(k, v)| (k.clone(), *v))
            .unwrap_or_default();

        if queried == 0 {
            return Err(ResolveError::NameNotFound);
        }
        if best_count < quorum {
            return Err(ResolveError::QuorumDivergence {
                queried,
                best: best_count,
                required: quorum,
            });
        }
        self.decode_and_check_name(&best_bytes, normalized)
    }

    fn decode_and_check_name(
        &self,
        bytes: &[u8],
        normalized: &str,
    ) -> Result<NameClaim, ResolveError> {
        let claim = NameClaim::decode(bytes)
            .map_err(|e| ResolveError::NameClaimMalformed(e.to_string()))?;
        if claim.name != normalized {
            return Err(ResolveError::NameClaimMalformed(format!(
                "DHT returned claim for different name: {}",
                claim.name
            )));
        }
        Ok(claim)
    }

    /// Verify the name claim layer in isolation. Public mainly for
    /// tests; production callers funnel through [`Self::resolve`].
    pub fn verify_name_claim(
        &self,
        claim: &NameClaim,
        doc: &IdentityDocument,
        now_unix_secs: u64,
    ) -> Result<(), ResolveError> {
        // Freshness hour skew.
        let now_hour = (now_unix_secs / 3600) as u32;
        if abs_diff_u32(claim.freshness_hour, now_hour) > NAME_CLAIM_FRESHNESS_HOUR_SKEW {
            return Err(ResolveError::NameClaimFreshnessHourSkew {
                doc: claim.freshness_hour,
                now: now_hour,
                skew: NAME_CLAIM_FRESHNESS_HOUR_SKEW,
            });
        }

        // PoW difficulty.
        let required = required_difficulty(&claim.name);
        let preimage = claim.pow_preimage();
        let hash = blake3::hash(&preimage);
        if veil_util::leading_zero_bits(hash.as_bytes()) < required {
            return Err(ResolveError::NameClaimPowTooWeak { required });
        }

        // Signing-subkey selection.
        let subkey = doc
            .identity_keys
            .get(claim.signing_identity_key_idx as usize)
            .ok_or(ResolveError::NameClaimSigKeyOutOfBounds {
                idx: claim.signing_identity_key_idx,
                n_keys: doc.identity_keys.len(),
            })?;

        // Actual signature verify.
        let mut msg = Vec::with_capacity(NAME_CLAIM_SIG_CONTEXT.len() + 256);
        msg.extend_from_slice(NAME_CLAIM_SIG_CONTEXT);
        msg.extend_from_slice(&claim.canonical_signing_bytes());
        verify_sig_raw(subkey.algo, &subkey.pubkey, &msg, &claim.sig)
            .map_err(|_| ResolveError::NameClaimSigInvalid)?;

        Ok(())
    }

    fn peek_cache(&self, name: &str) -> Option<[u8; 32]> {
        let guard = self.cache.read().unwrap_or_else(|e| e.into_inner());
        let entry = guard.entries.get(name)?;
        if entry.cached_at.elapsed() > NAME_CACHE_TTL {
            return None;
        }
        Some(entry.node_id)
    }

    fn touch(&self, name: &str) {
        let guard = self.cache.read().unwrap_or_else(|e| e.into_inner());
        if let Ok(mut lt) = guard.last_touch.lock() {
            lt.insert(name.to_string(), Instant::now());
        }
    }

    fn insert_cache(&self, name: String, node_id: [u8; 32]) {
        let mut guard = self.cache.write().unwrap_or_else(|e| e.into_inner());
        if guard.entries.len() >= NAME_CACHE_CAPACITY {
            // Evict the oldest-touched entry. Compute the eviction
            // key in its own scope so the mutex guard is dropped
            // before we reach for `guard.entries`.
            let oldest = {
                let lt = guard.last_touch.lock();
                match lt {
                    Ok(lt) => lt.iter().min_by_key(|(_, t)| **t).map(|(k, _)| k.clone()),
                    Err(_) => None,
                }
            };
            if let Some(k) = oldest {
                guard.entries.remove(&k);
                if let Ok(mut lt) = guard.last_touch.lock() {
                    lt.remove(&k);
                }
            }
        }
        if let Ok(mut lt) = guard.last_touch.lock() {
            lt.insert(name.clone(), Instant::now());
        }
        guard.entries.insert(
            name,
            CacheEntry {
                node_id,
                cached_at: Instant::now(),
            },
        );
    }

    /// Number of currently-cached entries — mostly for tests and
    /// metrics.
    pub fn cache_len(&self) -> usize {
        self.cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .len()
    }

    /// Clear the resolver's cache. Called on major events like a
    /// local revocation-cache replay or a user-initiated "forget all
    /// resolutions".
    pub fn clear_cache(&self) {
        let mut guard = self.cache.write().unwrap_or_else(|e| e.into_inner());
        guard.entries.clear();
        if let Ok(mut lt) = guard.last_touch.lock() {
            lt.clear();
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn abs_diff_u32(a: u32, b: u32) -> u32 {
    a.abs_diff(b)
}

fn verify_sig_raw(algo: u8, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), ()> {
    match algo {
        ALGO_ED25519 => {
            let pk_arr: &[u8; 32] = public_key.try_into().map_err(|_| ())?;
            let vk = EdVerifyingKey::from_bytes(pk_arr).map_err(|_| ())?;
            let sig = EdSignature::from_slice(signature).map_err(|_| ())?;
            vk.verify(message, &sig).map_err(|_| ())
        }
        ALGO_FALCON512 => {
            let pk = falcon512::PublicKey::from_bytes(public_key).map_err(|_| ())?;
            let sig = falcon512::DetachedSignature::from_bytes(signature).map_err(|_| ())?;
            falcon512::verify_detached_signature(&sig, message, &pk).map_err(|_| ())
        }
        // Hybrid name-claim signatures must verify too — otherwise a claim
        // legitimately signed by a hybrid (the recommended long-term PQ
        // identity) subkey would be rejected as invalid. Delegate to the
        // canonical hybrid verify in `veil-crypto` (both component
        // signatures required), exactly as `verify::verify_sig_raw` does.
        veil_proto::identity_document::ALGO_ED25519_FALCON512_HYBRID => {
            use base64::Engine as _;
            let pk_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);
            veil_crypto::verify_message(
                veil_types::SignatureAlgorithm::Ed25519Falcon512Hybrid,
                &pk_b64,
                message,
                signature,
            )
            .map_err(|_| ())
        }
        veil_proto::identity_document::ALGO_ED25519_FALCON1024_HYBRID => {
            use base64::Engine as _;
            let pk_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);
            veil_crypto::verify_message(
                veil_types::SignatureAlgorithm::Ed25519Falcon1024Hybrid,
                &pk_b64,
                message,
                signature,
            )
            .map_err(|_| ())
        }
        _ => Err(()),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::Arc;
    use tokio::sync::RwLock as TokioRwLock;

    use veil_crypto::identity::{certify_message as build_certify, compute_node_id};
    use veil_proto::identity_document::{ALGO_ED25519, DOC_SIG_CONTEXT, IdentityKey};

    // ── In-memory backend fake ───────────────────────────────────────────────

    #[derive(Default, Clone)]
    struct MemBackend {
        names: Arc<TokioRwLock<HashMap<[u8; 32], Vec<u8>>>>,
        docs: Arc<TokioRwLock<HashMap<[u8; 32], Vec<u8>>>>,
        // keyed by `migration_cert_dht_key(old_node_id)`.
        certs: Arc<TokioRwLock<HashMap<[u8; 32], Vec<u8>>>>,
    }

    impl MemBackend {
        async fn put_name(&self, key: [u8; 32], bytes: Vec<u8>) {
            self.names.write().await.insert(key, bytes);
        }
        async fn put_doc(&self, key: [u8; 32], bytes: Vec<u8>) {
            self.docs.write().await.insert(key, bytes);
        }
        async fn put_cert(&self, key: [u8; 32], bytes: Vec<u8>) {
            self.certs.write().await.insert(key, bytes);
        }
    }

    #[async_trait]
    impl NameLookup for MemBackend {
        async fn fetch_name_claim(
            &self,
            dht_key: &[u8; 32],
        ) -> Result<Option<Vec<u8>>, LookupError> {
            Ok(self.names.read().await.get(dht_key).cloned())
        }

        async fn fetch_name_claim_replicated(
            &self,
            dht_key: &[u8; 32],
            n_replicas: usize,
        ) -> Result<Vec<Vec<u8>>, LookupError> {
            // Simulates "all replicas in sync" — common DHT steady state.
            // Eclipse scenarios are modelled by `SplitBackend` below.
            match self.names.read().await.get(dht_key).cloned() {
                Some(bytes) => Ok(std::iter::repeat_n(bytes, n_replicas).collect()),
                None => Ok(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl IdentityLookup for MemBackend {
        async fn fetch_identity_document(
            &self,
            dht_key: &[u8; 32],
        ) -> Result<Option<Vec<u8>>, LookupError> {
            Ok(self.docs.read().await.get(dht_key).cloned())
        }

        async fn fetch_migration_cert(
            &self,
            dht_key: &[u8; 32],
        ) -> Result<Option<Vec<u8>>, LookupError> {
            Ok(self.certs.read().await.get(dht_key).cloned())
        }
    }

    // ── Fixture builder ──────────────────────────────────────────────────────

    struct Fixture {
        sub_sk: SigningKey,
        now_unix_secs: u64,
        doc: IdentityDocument,
        claim: NameClaim,
    }

    fn build_fixture(name: &str) -> Fixture {
        build_fixture_seeded(name, 0x11, 0x22)
    }

    fn build_fixture_seeded(name: &str, master_byte: u8, sub_byte: u8) -> Fixture {
        let now: u64 = 1_700_000_000;

        // Build identity document.
        let master_sk = SigningKey::from_bytes(&[master_byte; 32]);
        let master_pk = master_sk.verifying_key();
        let node_id = compute_node_id(master_pk.as_bytes());

        let sub_sk = SigningKey::from_bytes(&[sub_byte; 32]);
        let sub_pk = sub_sk.verifying_key();
        let device_id = compute_node_id(sub_pk.as_bytes());
        let valid_from = now - 60;
        let valid_until = now + 7 * 24 * 3600;

        let cert_msg = build_certify(
            &node_id,
            ALGO_ED25519,
            sub_pk.as_bytes(),
            &device_id,
            valid_from,
            valid_until,
        );
        let cert_sig = master_sk.sign(&cert_msg);

        let identity_key = IdentityKey {
            algo: ALGO_ED25519,
            pubkey: sub_pk.as_bytes().to_vec(),
            device_id,
            valid_from_unix: valid_from,
            valid_until_unix: valid_until,
            master_sig: cert_sig.to_bytes().to_vec(),
        };

        let mut doc = IdentityDocument {
            node_id,
            master_algo: ALGO_ED25519,
            master_pubkey: master_pk.as_bytes().to_vec(),
            issued_at_unix: now,
            valid_until_unix: now + 7 * 24 * 3600,
            sig_key_idx: 0,
            identity_keys: vec![identity_key],
            document_sig: Vec::new(),
        };

        let mut doc_msg = Vec::new();
        doc_msg.extend_from_slice(DOC_SIG_CONTEXT);
        doc_msg.extend_from_slice(&doc.canonical_signing_bytes());
        doc.document_sig = sub_sk.sign(&doc_msg).to_bytes().to_vec();

        // Build name claim signed by the sub key.
        let normalized = normalize_name(name).unwrap();
        let mut claim = NameClaim {
            name: normalized,
            node_id,
            claimed_at_unix: now,
            pow_nonce: [0u8; 16],
            freshness_hour: (now / 3600) as u32,
            signing_identity_key_idx: 0,
            sig: Vec::new(),
        };
        mine_claim_pow(&mut claim);

        let mut msg = Vec::new();
        msg.extend_from_slice(NAME_CLAIM_SIG_CONTEXT);
        msg.extend_from_slice(&claim.canonical_signing_bytes());
        claim.sig = sub_sk.sign(&msg).to_bytes().to_vec();

        Fixture {
            sub_sk,
            now_unix_secs: now,
            doc,
            claim,
        }
    }

    fn mine_claim_pow(claim: &mut NameClaim) {
        let required = required_difficulty(&claim.name);
        for i in 0u64..1_000_000 {
            let mut nonce = [0u8; 16];
            nonce[0..8].copy_from_slice(&i.to_be_bytes());
            claim.pow_nonce = nonce;
            let h = blake3::hash(&claim.pow_preimage());
            if veil_util::leading_zero_bits(h.as_bytes()) >= required {
                return;
            }
        }
        panic!("claim pow mining failed");
    }

    // ── Happy path ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn resolve_happy_path() {
        let f = build_fixture("alice");
        let backend = MemBackend::default();
        backend
            .put_name(NameClaim::dht_key(&f.claim.name), f.claim.encode())
            .await;
        backend
            .put_doc(IdentityDocument::dht_key(&f.doc.node_id), f.doc.encode())
            .await;

        let resolver = NameResolver::new(backend);
        let v = resolver.resolve("alice", f.now_unix_secs).await.unwrap();
        assert_eq!(v.node_id, f.doc.node_id);
        assert_eq!(v.active_key_idx, 0);
    }

    #[tokio::test]
    async fn resolve_uses_cache_on_second_call() {
        let f = build_fixture("alice");
        let backend = MemBackend::default();
        backend
            .put_name(NameClaim::dht_key(&f.claim.name), f.claim.encode())
            .await;
        backend
            .put_doc(IdentityDocument::dht_key(&f.doc.node_id), f.doc.encode())
            .await;

        let resolver = NameResolver::new(backend);
        resolver.resolve("alice", f.now_unix_secs).await.unwrap();
        assert_eq!(resolver.cache_len(), 1);

        // Drop the name claim from DHT and verify we can still resolve
        // — because the name → node_id mapping is cached.
        // (The identity document still needs to be reachable.)
        resolver.backend.names.write().await.clear();
        resolver.resolve("alice", f.now_unix_secs).await.unwrap();
    }

    #[tokio::test]
    async fn resolve_rejects_invalid_name() {
        let backend = MemBackend::default();
        let resolver = NameResolver::new(backend);
        let err = resolver.resolve("alíce", 0).await.unwrap_err();
        assert!(matches!(err, ResolveError::InvalidName(_)), "{err:?}");
    }

    #[tokio::test]
    async fn resolve_name_not_found() {
        let f = build_fixture("alice");
        let backend = MemBackend::default();
        backend
            .put_doc(IdentityDocument::dht_key(&f.doc.node_id), f.doc.encode())
            .await;
        let resolver = NameResolver::new(backend);
        let err = resolver.resolve("bob", f.now_unix_secs).await.unwrap_err();
        assert!(matches!(err, ResolveError::NameNotFound), "{err:?}");
    }

    #[tokio::test]
    async fn resolve_identity_not_found() {
        let f = build_fixture("alice");
        let backend = MemBackend::default();
        backend
            .put_name(NameClaim::dht_key(&f.claim.name), f.claim.encode())
            .await;
        // Intentionally no doc.
        let resolver = NameResolver::new(backend);
        let err = resolver
            .resolve("alice", f.now_unix_secs)
            .await
            .unwrap_err();
        assert!(matches!(err, ResolveError::IdentityNotFound(_)), "{err:?}");
    }

    #[tokio::test]
    async fn resolve_rejects_tampered_claim_sig() {
        let mut f = build_fixture("alice");
        f.claim.sig[0] ^= 0x01;
        let backend = MemBackend::default();
        backend
            .put_name(NameClaim::dht_key(&f.claim.name), f.claim.encode())
            .await;
        backend
            .put_doc(IdentityDocument::dht_key(&f.doc.node_id), f.doc.encode())
            .await;
        let resolver = NameResolver::new(backend);
        let err = resolver
            .resolve("alice", f.now_unix_secs)
            .await
            .unwrap_err();
        assert!(matches!(err, ResolveError::NameClaimSigInvalid), "{err:?}");
    }

    #[tokio::test]
    async fn resolve_rejects_mismatched_name_in_claim() {
        // Attacker publishes a claim with "bob" under the DHT slot
        // for "alice".
        let f_alice = build_fixture("alice");
        let f_bob = build_fixture("bob");
        let backend = MemBackend::default();
        // Put Bob's claim under Alice's slot.
        backend
            .put_name(NameClaim::dht_key("alice"), f_bob.claim.encode())
            .await;
        backend
            .put_doc(
                IdentityDocument::dht_key(&f_alice.doc.node_id),
                f_alice.doc.encode(),
            )
            .await;
        backend
            .put_doc(
                IdentityDocument::dht_key(&f_bob.doc.node_id),
                f_bob.doc.encode(),
            )
            .await;
        let resolver = NameResolver::new(backend);
        let err = resolver
            .resolve("alice", f_alice.now_unix_secs)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ResolveError::NameClaimMalformed(_)),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn resolve_rejects_doc_for_wrong_node_id_at_slot() {
        // Slot-substitution attack: a peer controlling Alice's
        // IdentityDocument DHT slot serves Bob's fully self-consistent
        // document there. `verify_identity_document` only checks the
        // doc's INTERNAL consistency (BLAKE3(master)==node_id), which
        // Bob's doc passes — so the resolver must independently reject
        // it because its node_id doesn't match the slot we queried.
        let f_alice = build_fixture("alice");
        let f_bob = build_fixture_seeded("bob", 0x33, 0x44);
        assert_ne!(f_alice.doc.node_id, f_bob.doc.node_id);
        let backend = MemBackend::default();
        // Alice's genuine, valid name claim under Alice's name slot.
        backend
            .put_name(NameClaim::dht_key("alice"), f_alice.claim.encode())
            .await;
        // But Bob's document under ALICE's identity-document slot.
        backend
            .put_doc(
                IdentityDocument::dht_key(&f_alice.doc.node_id),
                f_bob.doc.encode(),
            )
            .await;
        let resolver = NameResolver::new(backend);
        let err = resolver
            .resolve("alice", f_alice.now_unix_secs)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ResolveError::IdentityDocMalformed(_)),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn resolve_rejects_claim_with_wrong_freshness_hour() {
        let mut f = build_fixture("alice");
        f.claim.freshness_hour = f.claim.freshness_hour.wrapping_sub(100);
        // Re-sign after mutation (so we don't trip sig check first).
        mine_claim_pow(&mut f.claim);
        let mut msg = Vec::new();
        msg.extend_from_slice(NAME_CLAIM_SIG_CONTEXT);
        msg.extend_from_slice(&f.claim.canonical_signing_bytes());
        f.claim.sig = f.sub_sk.sign(&msg).to_bytes().to_vec();

        let backend = MemBackend::default();
        backend
            .put_name(NameClaim::dht_key(&f.claim.name), f.claim.encode())
            .await;
        backend
            .put_doc(IdentityDocument::dht_key(&f.doc.node_id), f.doc.encode())
            .await;
        let resolver = NameResolver::new(backend);
        let err = resolver
            .resolve("alice", f.now_unix_secs)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ResolveError::NameClaimFreshnessHourSkew { .. }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn resolve_rejects_subkey_out_of_bounds() {
        let mut f = build_fixture("alice");
        f.claim.signing_identity_key_idx = 7;
        // signing_identity_key_idx is part of canonical bytes, so
        // mining PoW is required to pass the difficulty step before
        // the bounds check fires. No need to re-sign — the bounds
        // check runs before signature verification.
        mine_claim_pow(&mut f.claim);
        let backend = MemBackend::default();
        backend
            .put_name(NameClaim::dht_key(&f.claim.name), f.claim.encode())
            .await;
        backend
            .put_doc(IdentityDocument::dht_key(&f.doc.node_id), f.doc.encode())
            .await;
        let resolver = NameResolver::new(backend);
        let err = resolver
            .resolve("alice", f.now_unix_secs)
            .await
            .unwrap_err();
        assert!(
            matches!(err, ResolveError::NameClaimSigKeyOutOfBounds { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn clear_cache_drops_entries() {
        // Pure synchronous test of the cache primitive.
        let backend = MemBackend::default();
        let resolver = NameResolver::new(backend);
        resolver.insert_cache("alice".into(), [0x11; 32]);
        assert_eq!(resolver.cache_len(), 1);
        resolver.clear_cache();
        assert_eq!(resolver.cache_len(), 0);
    }

    #[test]
    fn leading_zero_bits_basic() {
        assert_eq!(veil_util::leading_zero_bits(&[0xFF]), 0);
        assert_eq!(veil_util::leading_zero_bits(&[0x0F]), 4);
        assert_eq!(veil_util::leading_zero_bits(&[0x00, 0x80]), 8);
        assert_eq!(veil_util::leading_zero_bits(&[0x00, 0x00, 0x00]), 24);
    }

    #[test]
    fn order_pair_is_correct() {
        // Defensive: verify the helper crate::resolver
        // doesn't accidentally reorder bytes in a subtle way.
        let a = [0x01u8; 32];
        let b = [0x02u8; 32];
        assert!(a.as_slice() < b.as_slice());
    }

    // ── Quorum resolver tests ──────────────────────────────────

    /// Backend that returns an explicit list of replicated values per
    /// lookup — lets tests model eclipse scenarios where replicas
    /// disagree.
    type ReplicaMap = HashMap<[u8; 32], Vec<Vec<u8>>>;

    #[derive(Default, Clone)]
    struct SplitBackend {
        // key → list of replica responses (each response can differ)
        names: Arc<TokioRwLock<ReplicaMap>>,
        docs: Arc<TokioRwLock<HashMap<[u8; 32], Vec<u8>>>>,
    }

    impl SplitBackend {
        async fn put_name_replicas(&self, key: [u8; 32], replicas: Vec<Vec<u8>>) {
            self.names.write().await.insert(key, replicas);
        }
        async fn put_doc(&self, key: [u8; 32], bytes: Vec<u8>) {
            self.docs.write().await.insert(key, bytes);
        }
    }

    #[async_trait]
    impl NameLookup for SplitBackend {
        async fn fetch_name_claim(
            &self,
            dht_key: &[u8; 32],
        ) -> Result<Option<Vec<u8>>, LookupError> {
            // Single-shot path returns the first replica, if any.
            Ok(self
                .names
                .read()
                .await
                .get(dht_key)
                .and_then(|v| v.first().cloned()))
        }

        async fn fetch_name_claim_replicated(
            &self,
            dht_key: &[u8; 32],
            n_replicas: usize,
        ) -> Result<Vec<Vec<u8>>, LookupError> {
            Ok(self
                .names
                .read()
                .await
                .get(dht_key)
                .map(|v| v.iter().take(n_replicas).cloned().collect())
                .unwrap_or_default())
        }
    }

    #[async_trait]
    impl IdentityLookup for SplitBackend {
        async fn fetch_identity_document(
            &self,
            dht_key: &[u8; 32],
        ) -> Result<Option<Vec<u8>>, LookupError> {
            Ok(self.docs.read().await.get(dht_key).cloned())
        }
    }

    #[tokio::test]
    async fn quorum_accepts_unanimous_replicas() {
        let f = build_fixture("alice");
        let backend = SplitBackend::default();
        let name_key = NameClaim::dht_key(&f.claim.name);
        // Three identical replicas — quorum 2 trivially satisfied.
        backend
            .put_name_replicas(
                name_key,
                vec![f.claim.encode(), f.claim.encode(), f.claim.encode()],
            )
            .await;
        backend
            .put_doc(IdentityDocument::dht_key(&f.doc.node_id), f.doc.encode())
            .await;
        let resolver = NameResolver::new(backend);
        let v = resolver.resolve("alice", f.now_unix_secs).await.unwrap();
        assert_eq!(v.node_id, f.doc.node_id);
    }

    #[tokio::test]
    async fn quorum_accepts_bare_minimum() {
        // Two out of three replicas agree — exactly satisfies quorum.
        let f = build_fixture("alice");
        let other = build_fixture("bob"); // attacker value
        let backend = SplitBackend::default();
        let name_key = NameClaim::dht_key("alice");
        backend
            .put_name_replicas(
                name_key,
                vec![f.claim.encode(), f.claim.encode(), other.claim.encode()],
            )
            .await;
        backend
            .put_doc(IdentityDocument::dht_key(&f.doc.node_id), f.doc.encode())
            .await;
        let resolver = NameResolver::new(backend);
        let v = resolver.resolve("alice", f.now_unix_secs).await.unwrap();
        assert_eq!(v.node_id, f.doc.node_id);
    }

    #[tokio::test]
    async fn quorum_rejects_split_vote() {
        // 2 replicas say alice → honest, 2 replicas say bob → attacker
        // no majority of 3. With quorum=3 (strict majority of 5)
        // neither side wins.
        let f_a = build_fixture("alice");
        let f_b = build_fixture("bob");
        let backend = SplitBackend::default();
        let name_key = NameClaim::dht_key("alice");
        backend
            .put_name_replicas(
                name_key,
                vec![
                    f_a.claim.encode(),
                    f_a.claim.encode(),
                    f_b.claim.encode(),
                    f_b.claim.encode(),
                ],
            )
            .await;
        backend
            .put_doc(
                IdentityDocument::dht_key(&f_a.doc.node_id),
                f_a.doc.encode(),
            )
            .await;
        let resolver = NameResolver::with_config(
            backend,
            VerifyConfig {
                resolver_quorum: 3,
                resolver_max_replicas: 4,
            },
        );
        let err = resolver
            .resolve("alice", f_a.now_unix_secs)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                ResolveError::QuorumDivergence {
                    required: 3,
                    best: 2,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn quorum_name_not_found_when_no_replicas() {
        let backend = SplitBackend::default();
        let resolver = NameResolver::new(backend);
        let err = resolver.resolve("alice", 1_700_000_000).await.unwrap_err();
        assert!(matches!(err, ResolveError::NameNotFound), "{err:?}");
    }

    #[tokio::test]
    async fn quorum_one_disables_quorum_checks() {
        // With quorum=1 the resolver uses the single-shot fetch path
        // so a backend that returns only one replica still succeeds.
        let f = build_fixture("alice");
        let backend = SplitBackend::default();
        let name_key = NameClaim::dht_key("alice");
        backend
            .put_name_replicas(name_key, vec![f.claim.encode()])
            .await;
        backend
            .put_doc(IdentityDocument::dht_key(&f.doc.node_id), f.doc.encode())
            .await;
        let resolver = NameResolver::with_config(
            backend,
            VerifyConfig {
                resolver_quorum: 1,
                resolver_max_replicas: 1,
            },
        );
        let v = resolver.resolve("alice", f.now_unix_secs).await.unwrap();
        assert_eq!(v.node_id, f.doc.node_id);
    }

    #[tokio::test]
    async fn quorum_max_replicas_caps_query_fan_out() {
        // Even with many available replicas, we only ask for
        // `resolver_max_replicas` of them.
        let f = build_fixture("alice");
        let backend = SplitBackend::default();
        let name_key = NameClaim::dht_key("alice");
        let replicas = (0..10).map(|_| f.claim.encode()).collect();
        backend.put_name_replicas(name_key, replicas).await;
        backend
            .put_doc(IdentityDocument::dht_key(&f.doc.node_id), f.doc.encode())
            .await;
        let resolver = NameResolver::with_config(
            backend,
            VerifyConfig {
                resolver_quorum: 2,
                resolver_max_replicas: 3, // cap at 3 even though 10 are available
            },
        );
        resolver.resolve("alice", f.now_unix_secs).await.unwrap();
    }

    // ── migration-cert resolver chain ────────────────────────────

    /// Mints a fresh Ed25519 identity rooted at `master_sk_seed`
    /// claiming `name`. Returns (doc, master_sk_seed_bytes_b64
    /// master_pk_bytes_b64) so a follow-up migration-cert can be
    /// signed by the OLD master.
    fn build_migration_target_doc(
        name: &str,
        master_sk_seed: [u8; 32],
        sub_sk_seed: [u8; 32],
        now: u64,
    ) -> (IdentityDocument, NameClaim) {
        let master_sk = SigningKey::from_bytes(&master_sk_seed);
        let master_pk = master_sk.verifying_key();
        let node_id = compute_node_id(master_pk.as_bytes());

        let sub_sk = SigningKey::from_bytes(&sub_sk_seed);
        let sub_pk = sub_sk.verifying_key();
        let device_id = compute_node_id(sub_pk.as_bytes());
        let valid_from = now - 60;
        let valid_until = now + 7 * 24 * 3600;

        let cert_msg = build_certify(
            &node_id,
            ALGO_ED25519,
            sub_pk.as_bytes(),
            &device_id,
            valid_from,
            valid_until,
        );
        let cert_sig = master_sk.sign(&cert_msg);

        let identity_key = IdentityKey {
            algo: ALGO_ED25519,
            pubkey: sub_pk.as_bytes().to_vec(),
            device_id,
            valid_from_unix: valid_from,
            valid_until_unix: valid_until,
            master_sig: cert_sig.to_bytes().to_vec(),
        };
        let mut doc = IdentityDocument {
            node_id,
            master_algo: ALGO_ED25519,
            master_pubkey: master_pk.as_bytes().to_vec(),
            issued_at_unix: now,
            valid_until_unix: now + 7 * 24 * 3600,
            sig_key_idx: 0,
            identity_keys: vec![identity_key],
            document_sig: Vec::new(),
        };
        let mut doc_msg = Vec::new();
        doc_msg.extend_from_slice(DOC_SIG_CONTEXT);
        doc_msg.extend_from_slice(&doc.canonical_signing_bytes());
        doc.document_sig = sub_sk.sign(&doc_msg).to_bytes().to_vec();

        let normalized = normalize_name(name).unwrap();
        let mut claim = NameClaim {
            name: normalized,
            node_id,
            claimed_at_unix: now,
            pow_nonce: [0u8; 16],
            freshness_hour: (now / 3600) as u32,
            signing_identity_key_idx: 0,
            sig: Vec::new(),
        };
        mine_claim_pow(&mut claim);
        let mut msg = Vec::new();
        msg.extend_from_slice(NAME_CLAIM_SIG_CONTEXT);
        msg.extend_from_slice(&claim.canonical_signing_bytes());
        claim.sig = sub_sk.sign(&msg).to_bytes().to_vec();

        (doc, claim)
    }

    /// Builds a `MigrationCert` signed by `old_master_sk_seed`'s
    /// Ed25519 master, pointing the OLD `node_id` to the NEW one.
    fn build_ed25519_migration_cert(
        old_master_sk_seed: [u8; 32],
        old_node_id: [u8; 32],
        new_node_id: [u8; 32],
        new_master_algo: u8,
        new_master_pubkey_bytes: Vec<u8>,
        issued_at: u64,
        valid_until: u64,
    ) -> Vec<u8> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let old_master_sk = SigningKey::from_bytes(&old_master_sk_seed);
        let old_master_pk = old_master_sk.verifying_key();
        let old_pk_b64 = STANDARD.encode(old_master_pk.as_bytes());
        let old_sk_b64 = STANDARD.encode(old_master_sk.to_bytes());
        crate::migration::sign_migration_cert(
            ALGO_ED25519,
            &old_pk_b64,
            &old_sk_b64,
            old_node_id,
            new_node_id,
            new_master_algo,
            new_master_pubkey_bytes,
            issued_at,
            valid_until,
        )
        .expect("sign migration cert")
    }

    #[tokio::test]
    async fn resolve_follows_one_hop_migration_chain() {
        // Old identity = build_fixture (master_sk seed [0x11u8; 32]).
        // New identity = master_sk seed [0x33u8; 32], sub_sk seed [0x44u8; 32].
        // Both docs published; cert signed by OLD master pointing to NEW node_id.
        let f_old = build_fixture("alice");
        let now = f_old.now_unix_secs;
        let (new_doc, _new_claim) =
            build_migration_target_doc("alice", [0x33u8; 32], [0x44u8; 32], now);

        let cert_bytes = build_ed25519_migration_cert(
            [0x11u8; 32],
            f_old.doc.node_id,
            new_doc.node_id,
            new_doc.master_algo,
            new_doc.master_pubkey.clone(),
            now,
            now + 7 * 24 * 3600,
        );

        let backend = MemBackend::default();
        backend
            .put_name(NameClaim::dht_key(&f_old.claim.name), f_old.claim.encode())
            .await;
        backend
            .put_doc(
                IdentityDocument::dht_key(&f_old.doc.node_id),
                f_old.doc.encode(),
            )
            .await;
        backend
            .put_doc(
                IdentityDocument::dht_key(&new_doc.node_id),
                new_doc.encode(),
            )
            .await;
        backend
            .put_cert(
                crate::migration::migration_cert_dht_key(&f_old.doc.node_id),
                cert_bytes,
            )
            .await;

        let resolver = NameResolver::new(backend);
        let validated = resolver.resolve("alice", now).await.unwrap();
        // Resolver MUST surface the NEW node_id (chain followed).
        assert_eq!(validated.node_id, new_doc.node_id);
    }

    #[tokio::test]
    async fn resolve_skips_expired_migration_cert() {
        // Cert that's already expired must be ignored — resolver
        // returns the original identity unchanged. This is the
        // "operator forgot to refresh the cert" case.
        let f_old = build_fixture("alice");
        let now = f_old.now_unix_secs;
        let (new_doc, _new_claim) =
            build_migration_target_doc("alice", [0x33u8; 32], [0x44u8; 32], now);

        let cert_bytes = build_ed25519_migration_cert(
            [0x11u8; 32],
            f_old.doc.node_id,
            new_doc.node_id,
            new_doc.master_algo,
            new_doc.master_pubkey.clone(),
            now - 30 * 24 * 3600, // issued ~ago
            now - 1,              // expired before now
        );

        let backend = MemBackend::default();
        backend
            .put_name(NameClaim::dht_key(&f_old.claim.name), f_old.claim.encode())
            .await;
        backend
            .put_doc(
                IdentityDocument::dht_key(&f_old.doc.node_id),
                f_old.doc.encode(),
            )
            .await;
        backend
            .put_doc(
                IdentityDocument::dht_key(&new_doc.node_id),
                new_doc.encode(),
            )
            .await;
        backend
            .put_cert(
                crate::migration::migration_cert_dht_key(&f_old.doc.node_id),
                cert_bytes,
            )
            .await;

        let resolver = NameResolver::new(backend);
        let validated = resolver.resolve("alice", now).await.unwrap();
        // Cert ignored ⇒ stays on old identity.
        assert_eq!(validated.node_id, f_old.doc.node_id);
    }

    #[tokio::test]
    async fn resolve_detects_migration_chain_cycle() {
        // Two-node cycle: A migrates to B, B migrates back to A.
        // Resolver must surface MigrationChainCycle, not loop forever.
        let f_a = build_fixture("alice");
        let now = f_a.now_unix_secs;
        let (doc_b, _claim_b) =
            build_migration_target_doc("alice", [0x33u8; 32], [0x44u8; 32], now);

        // A → B (signed by A's old master = [0x11u8; 32]).
        let cert_a_to_b = build_ed25519_migration_cert(
            [0x11u8; 32],
            f_a.doc.node_id,
            doc_b.node_id,
            doc_b.master_algo,
            doc_b.master_pubkey.clone(),
            now,
            now + 7 * 24 * 3600,
        );
        // B → A (signed by B's master = [0x33u8; 32]).
        let cert_b_to_a = build_ed25519_migration_cert(
            [0x33u8; 32],
            doc_b.node_id,
            f_a.doc.node_id,
            f_a.doc.master_algo,
            f_a.doc.master_pubkey.clone(),
            now,
            now + 7 * 24 * 3600,
        );

        let backend = MemBackend::default();
        backend
            .put_name(NameClaim::dht_key(&f_a.claim.name), f_a.claim.encode())
            .await;
        backend
            .put_doc(
                IdentityDocument::dht_key(&f_a.doc.node_id),
                f_a.doc.encode(),
            )
            .await;
        backend
            .put_doc(IdentityDocument::dht_key(&doc_b.node_id), doc_b.encode())
            .await;
        backend
            .put_cert(
                crate::migration::migration_cert_dht_key(&f_a.doc.node_id),
                cert_a_to_b,
            )
            .await;
        backend
            .put_cert(
                crate::migration::migration_cert_dht_key(&doc_b.node_id),
                cert_b_to_a,
            )
            .await;

        let resolver = NameResolver::new(backend);
        let err = resolver.resolve("alice", now).await.unwrap_err();
        assert!(
            matches!(err, ResolveError::MigrationChainCycle { .. }),
            "expected MigrationChainCycle, got {err:?}"
        );
    }

    #[tokio::test]
    async fn resolve_drops_forged_migration_cert() {
        // Attacker-controlled DHT replica publishes a cert NOT signed
        // by the genuine OLD master (uses an unrelated key). Resolver
        // verify_migration_cert MUST drop it, returning original
        // identity. Defends against eclipsed-DHT-replica scenarios.
        let f_old = build_fixture("alice");
        let now = f_old.now_unix_secs;
        let (new_doc, _) = build_migration_target_doc("alice", [0x33u8; 32], [0x44u8; 32], now);

        // Sign with WRONG seed [0x99u8; 32] (not the genuine [0x11u8; 32]).
        // The cert's `old_master_algo` field still claims Ed25519 so
        // structural decode succeeds — only signature-verify rejects.
        let cert_bytes = build_ed25519_migration_cert(
            [0x99u8; 32],
            f_old.doc.node_id,
            new_doc.node_id,
            new_doc.master_algo,
            new_doc.master_pubkey.clone(),
            now,
            now + 7 * 24 * 3600,
        );

        let backend = MemBackend::default();
        backend
            .put_name(NameClaim::dht_key(&f_old.claim.name), f_old.claim.encode())
            .await;
        backend
            .put_doc(
                IdentityDocument::dht_key(&f_old.doc.node_id),
                f_old.doc.encode(),
            )
            .await;
        backend
            .put_doc(
                IdentityDocument::dht_key(&new_doc.node_id),
                new_doc.encode(),
            )
            .await;
        backend
            .put_cert(
                crate::migration::migration_cert_dht_key(&f_old.doc.node_id),
                cert_bytes,
            )
            .await;

        let resolver = NameResolver::new(backend);
        let validated = resolver.resolve("alice", now).await.unwrap();
        assert_eq!(validated.node_id, f_old.doc.node_id);
    }

    #[tokio::test]
    async fn resolve_ignores_migration_when_new_doc_missing() {
        // Cert is valid but new_doc isn't published (operator
        // forgot to publish before publishing the cert). Resolver
        // surfaces IdentityNotFound for the NEW node_id — caller can
        // distinguish from "no migration" (which silently keeps the
        // old identity).
        let f_old = build_fixture("alice");
        let now = f_old.now_unix_secs;
        let (new_doc, _) = build_migration_target_doc("alice", [0x33u8; 32], [0x44u8; 32], now);

        let cert_bytes = build_ed25519_migration_cert(
            [0x11u8; 32],
            f_old.doc.node_id,
            new_doc.node_id,
            new_doc.master_algo,
            new_doc.master_pubkey.clone(),
            now,
            now + 7 * 24 * 3600,
        );

        let backend = MemBackend::default();
        backend
            .put_name(NameClaim::dht_key(&f_old.claim.name), f_old.claim.encode())
            .await;
        backend
            .put_doc(
                IdentityDocument::dht_key(&f_old.doc.node_id),
                f_old.doc.encode(),
            )
            .await;
        // NB: new_doc.encode NOT inserted.
        backend
            .put_cert(
                crate::migration::migration_cert_dht_key(&f_old.doc.node_id),
                cert_bytes,
            )
            .await;

        let resolver = NameResolver::new(backend);
        let err = resolver.resolve("alice", now).await.unwrap_err();
        assert!(
            matches!(err, ResolveError::IdentityNotFound(id) if id == new_doc.node_id),
            "expected IdentityNotFound(new_node_id), got {err:?}"
        );
    }
}
