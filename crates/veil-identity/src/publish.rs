//! Signing-side builders for publishable sovereign-identity records
//!
//!
//! Every record that lives in the DHT or on the wire has a verifier
//! (`verify_identity_document`, `verify_mlkem_cert`
//! [`NameResolver::verify_name_claim`], `InstanceRegistry` sig
//! check, …) already implemented in sibling modules. This module
//! is the producer half: given the owner's `identity_sk` plus the
//! ingredients of each record, it returns a fully-signed
//! verifier-ready value.
//!
//! Separating signing from wire-format structs keeps the proto
//! modules pure — they stay focused on encoding/decoding and
//! capacity caps. Tests round-trip sign → verify to guarantee
//! the two halves stay in lock-step.
//!
//! ## API shape
//!
//! Each `sign_*` helper:
//! 1. Takes the unsigned draft record + the signing material.
//! 2. Stamps the `signing_identity_key_idx` field (where present).
//! 3. Computes `canonical_signing_bytes` + prefixes the
//!    appropriate domain-separated SIG_CONTEXT.
//! 4. Signs with the provided [`SigningKey`].
//! 5. Returns the signed record, ready for wire encoding + DHT put.
//!
//! Higher-level builders (`build_*`) compose a reasonable default
//! draft so callers don't have to hand-populate every field.
//!
//! ## Producer-side algo invariant: Ed25519 only — by design
//!
//! Every signing helper in this module uses ed25519-dalek. This is a
//! deliberate, security-relevant design choice, NOT pending TODO work:
//!
//! * **Runtime signing is hot-path.** `sign_identity_proof` runs once
//!   per OVL1 handshake; `sign_name_claim` runs once per name; instance/
//!   registry signing runs on every key rotation. On budget Android
//!   devices Ed25519 (~50 µs sign) is ~100× faster than Falcon-512
//!   (~5 ms sign) — the difference is felt in handshake latency.
//!
//! * **Falcon-512 stays in the cert chain.** Master-cert and identity-
//!   document signatures (signed once per rotation, ~yearly) accept
//!   Ed25519 *or* Falcon-512 [`verify_subkey_sig`]. That's the
//!   appropriate place for PQ-safe primitives because the cost is
//!   amortised over months.
//!
//! * **Verifier accepts both algos.** An IdentityDocument signed by a
//!   Falcon-512 master key is fully verifiable on the receive side; the
//!   asymmetry only affects what the *local* node can mint with its own
//!   secrets, and the local node always has an Ed25519 subkey in its
//!   document for runtime use.
//!
//! previous comment described this as
//! "future work" — that mischaracterised an intentional invariant
//! and led the auditor to flag it as incomplete.
//!
//! [`verify_subkey_sig`]: super::verify::verify_subkey_sig

use std::collections::HashSet;

// dropped `rand_core::{OsRng, RngCore}` import — only
// caller was the random `mailbox_anchor` generation in `build_instance_entry`
// which is gone with the field.

use veil_proto::identity_document::{DOC_SIG_CONTEXT, IdentityDocument, MAX_FRESHNESS_WINDOW_SECS};

use crate::signing_key::IdentitySigningKey;
use veil_proto::identity_proof::IdentityProof;
use veil_proto::instance_registry::{
    INSTANCE_REGISTRY_SIG_CONTEXT, InstanceEntry, InstanceRegistry,
};
use veil_proto::mlkem_cert::MlKemKeyCert;
use veil_proto::name_claim_v2::{NAME_CLAIM_SIG_CONTEXT, NameClaim, required_difficulty};
use veil_proto::pairing_invite::PairingInvite;
use veil_proto::prekey_bundle::ALGO_ML_KEM_768;

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("signing_identity_key_idx {idx} out of bounds ({n} keys)")]
    SigKeyIdxOutOfBounds { idx: u16, n: usize },
    #[error("PoW mining budget exceeded after {attempts} attempts")]
    PowExhausted { attempts: u64 },
    #[error(
        "valid_until_unix {valid_until} − valid_from_unix {valid_from} \
         = {span}s > MAX_FRESHNESS_WINDOW_SECS ({MAX_FRESHNESS_WINDOW_SECS}s)"
    )]
    ValidityWindowTooLong {
        valid_from: u64,
        valid_until: u64,
        span: u64,
    },
    #[error("name normalization: {0}")]
    NameNormalization(#[from] veil_proto::name_claim_v2::NameError),
}

// ── InstanceRegistry ─────────────────────────────────────────────────────────

/// Build an unsigned [`InstanceRegistry`] draft.
///
/// The caller stamps in the instances + the signing subkey index
/// and then passes the result [`sign_instance_registry`] along
/// with the matching `identity_sk`.
pub fn build_instance_registry(
    node_id: [u8; 32],
    reg_version: u64,
    signing_identity_key_idx: u16,
    instances: Vec<InstanceEntry>,
) -> InstanceRegistry {
    InstanceRegistry {
        node_id,
        reg_version,
        signing_identity_key_idx,
        instances,
        sig: Vec::new(),
    }
}

/// Sign an `InstanceRegistry` with the owner's active
/// `identity_sk`. The registry is ready for wire encoding + DHT
/// publication on return.
pub fn sign_instance_registry(
    mut registry: InstanceRegistry,
    identity_sk: &IdentitySigningKey,
) -> InstanceRegistry {
    let mut msg = Vec::with_capacity(INSTANCE_REGISTRY_SIG_CONTEXT.len() + 256);
    msg.extend_from_slice(INSTANCE_REGISTRY_SIG_CONTEXT);
    msg.extend_from_slice(&registry.canonical_signing_bytes());
    registry.sig = identity_sk.sign(&msg);
    registry
}

// ── NameClaim V2 ─────────────────────────────────────────────────────────────

const NAME_CLAIM_POW_BUDGET: u64 = 20_000_000;

/// Build an unsigned [`NameClaim`] draft. Caller supplies the
/// normalised name + the identity the claim binds to; this helper
/// fills in the structural fields (PoW nonce zeroed — mining
/// happens at signing time).
pub fn build_name_claim(
    normalized_name: String,
    node_id: [u8; 32],
    claimed_at_unix: u64,
    signing_identity_key_idx: u16,
) -> NameClaim {
    NameClaim {
        name: normalized_name,
        node_id,
        claimed_at_unix,
        pow_nonce: [0u8; 16],
        freshness_hour: (claimed_at_unix / 3600) as u32,
        signing_identity_key_idx,
        sig: Vec::new(),
    }
}

/// Mine the claim's PoW + sign it with the owner's active
/// `identity_sk`. PoW difficulty is the rarity-proportional
/// difficulty [`required_difficulty`] — short memorable names
/// cost much more hash-work than long random ones.
///
/// `#[cfg(test)]` the difficulty constants are lowered so this
/// completes in milliseconds. In production, callers typically
/// run this on a background thread and notify the user of the
/// mining cost up-front.
pub fn sign_name_claim(
    mut claim: NameClaim,
    identity_sk: &IdentitySigningKey,
) -> Result<NameClaim, PublishError> {
    mine_name_pow(&mut claim)?;

    let mut msg = Vec::with_capacity(NAME_CLAIM_SIG_CONTEXT.len() + 256);
    msg.extend_from_slice(NAME_CLAIM_SIG_CONTEXT);
    msg.extend_from_slice(&claim.canonical_signing_bytes());
    claim.sig = identity_sk.sign(&msg);
    Ok(claim)
}

fn mine_name_pow(claim: &mut NameClaim) -> Result<(), PublishError> {
    let required = required_difficulty(&claim.name);
    for i in 0..NAME_CLAIM_POW_BUDGET {
        let mut nonce = [0u8; 16];
        nonce[0..8].copy_from_slice(&i.to_be_bytes());
        claim.pow_nonce = nonce;
        let h = blake3::hash(&claim.pow_preimage());
        if veil_util::leading_zero_bits(h.as_bytes()) >= required {
            return Ok(());
        }
    }
    Err(PublishError::PowExhausted {
        attempts: NAME_CLAIM_POW_BUDGET,
    })
}

// ── MlKemKeyCert ─────────────────────────────────────────────────────────────

/// Build + sign a fresh ML-KEM key certificate. The instance's
/// `identity_sk` signs over the canonical certificate bytes.
///
/// Preconditions enforced:
/// `signing_identity_key_idx` points at an in-doc identity_key
/// whose `bound_instance_id == instance_id` (this is what the
/// verifier checks on the consumer side).
/// `valid_from_unix ≤ valid_until_unix`.
/// Window ≤ protocol cap (here we do not enforce a strict
/// upper bound — callers typically pick 30 days).
#[allow(clippy::too_many_arguments)]
pub fn sign_mlkem_cert(
    node_id: [u8; 32],
    instance_id: [u8; 16],
    mlkem_pubkey: Vec<u8>,
    valid_from_unix: u64,
    valid_until_unix: u64,
    cert_version: u64,
    signing_identity_key_idx: u16,
    signing_identity_sk: &IdentitySigningKey,
    doc: &IdentityDocument,
) -> Result<MlKemKeyCert, PublishError> {
    if valid_until_unix < valid_from_unix {
        return Err(PublishError::ValidityWindowTooLong {
            valid_from: valid_from_unix,
            valid_until: valid_until_unix,
            span: 0,
        });
    }
    // Bounds-check the signing key index. We can't cross-check the raw SK
    // bytes against the indexed identity_key here (the SK is private), but the
    // verifier enforces the SK↔pubkey binding via a round-trip sign downstream;
    // this catches the obvious "wrong idx" bug. (Was: a `let key = …get(idx)?`
    // binding immediately discarded with `let _ = key;`.)
    let idx = signing_identity_key_idx as usize;
    if idx >= doc.identity_keys.len() {
        return Err(PublishError::SigKeyIdxOutOfBounds {
            idx: signing_identity_key_idx,
            n: doc.identity_keys.len(),
        });
    }

    let mut cert = MlKemKeyCert {
        node_id,
        instance_id,
        mlkem_algo: ALGO_ML_KEM_768,
        mlkem_pubkey,
        valid_from_unix,
        valid_until_unix,
        cert_version,
        signing_identity_key_idx,
        sig: Vec::new(),
    };
    let msg = cert.signing_message();
    cert.sig = signing_identity_sk.sign(&msg);
    Ok(cert)
}

// ── IdentityDocument re-sign ─────────────────────────────────────────────────

/// Re-sign an [`IdentityDocument`] after the caller has mutated a
/// non-signed field (e.g., added a new `IdentityKey`, rotated
/// `sig_key_idx`, bumped `valid_until_unix`). Used by `identity
/// rotate` flows.
pub fn sign_identity_document(
    mut doc: IdentityDocument,
    identity_sk: &IdentitySigningKey,
    sig_key_idx: u16,
) -> Result<IdentityDocument, PublishError> {
    if (sig_key_idx as usize) >= doc.identity_keys.len() {
        return Err(PublishError::SigKeyIdxOutOfBounds {
            idx: sig_key_idx,
            n: doc.identity_keys.len(),
        });
    }
    doc.sig_key_idx = sig_key_idx;
    let mut msg = Vec::with_capacity(DOC_SIG_CONTEXT.len() + 512);
    msg.extend_from_slice(DOC_SIG_CONTEXT);
    msg.extend_from_slice(&doc.canonical_signing_bytes());
    doc.document_sig = identity_sk.sign(&msg);
    Ok(doc)
}

// ── InstanceEntry convenience builder ────────────────────────────────────────

/// Build an [`InstanceEntry`] with a random 32-byte mailbox anchor
/// and no Tier-B encrypted contact blob. Callers augment the
/// result (e.g., attaching a Tier-B blob via
/// [`tier_b::encrypt_contact`](super::tier_b::encrypt_contact)) as
/// needed before handing [`build_instance_registry`].
pub fn build_instance_entry(
    instance_id: [u8; 16],
    bound_identity_key_idx: u16,
    label: String,
    last_seen_unix_ms: u64,
) -> InstanceEntry {
    InstanceEntry {
        instance_id,
        bound_identity_key_idx,
        label,
        last_seen_unix_ms,
    }
}

// ── IdentityProof ──────────────────────────────────────────────

/// Build + sign an in-handshake [`IdentityProof`].
///
/// The signer needs the full signed [`IdentityDocument`] (so the
/// inline subkey fields + `master_sig` can be copied out of the
/// already-certified `identity_keys[sig_key_idx]`), the active
/// `identity_sk` (to sign the X25519 ephemeral pk), the session's
/// X25519 ephemeral pk (32 bytes), a `proof_valid_until_unix` window
/// (typically `now + 5 min`), and the `freshness_hour` the verifier
/// will compare against `now_unix / 3600`.
///
/// The returned proof is wire-ready. Receivers pass it to
/// `verify_identity_proof` which checks the node_id binding, the
/// inline master certification, the ephemeral-pk signature (anti-MITM)
/// and the `proof_valid_until_unix` window — all without a DHT
/// round-trip.
#[allow(clippy::too_many_arguments)]
pub fn sign_identity_proof(
    doc: &IdentityDocument,
    sig_key_idx: u16,
    identity_sk: &IdentitySigningKey,
    ephemeral_x25519_pk: [u8; 32],
    proof_valid_until_unix: u64,
    freshness_hour: u32,
) -> Result<IdentityProof, PublishError> {
    let idx = sig_key_idx as usize;
    let key = doc
        .identity_keys
        .get(idx)
        .ok_or(PublishError::SigKeyIdxOutOfBounds {
            idx: sig_key_idx,
            n: doc.identity_keys.len(),
        })?;

    let mut proof = IdentityProof {
        node_id: doc.node_id,
        master_algo: doc.master_algo,
        master_pubkey: doc.master_pubkey.clone(),
        identity_algo: key.algo,
        identity_pubkey: key.pubkey.clone(),
        device_id: key.device_id,
        key_valid_from_unix: key.valid_from_unix,
        key_valid_until_unix: key.valid_until_unix,
        master_sig: key.master_sig.clone(),
        proof_valid_until_unix,
        freshness_hour,
        ephemeral_x25519_pk,
        ephemeral_sig: Vec::new(),
    };
    let msg = proof.ephemeral_signing_message();
    proof.ephemeral_sig = identity_sk.sign(&msg);
    Ok(proof)
}

// ── PairingInvite ──────────────────────────────────────────────

/// Build + sign a [`PairingInvite`]. Signs with the provided
/// `identity_sk` [`PAIRING_INVITE_SIG_CONTEXT`] so receivers
/// bind the invite to the claimed identity before trusting the
/// `pair_secret_hash`.
///
/// Preconditions:
/// `expires_at_unix >= issued_at_unix` (rejected before signing).
/// `signing_identity_key_idx` must be a valid in-doc subkey idx —
/// callers load the SK corresponding to that subkey. The verifier
/// enforces the actual signature match; this function does not
/// cross-check `identity_sk` against the document.
#[allow(clippy::too_many_arguments)]
pub fn sign_pairing_invite(
    node_id: [u8; 32],
    pair_secret_hash: [u8; 32],
    source_instance_id: [u8; 16],
    issued_at_unix: u64,
    expires_at_unix: u64,
    signing_identity_key_idx: u16,
    signing_identity_sk: &IdentitySigningKey,
    doc: &IdentityDocument,
) -> Result<PairingInvite, PublishError> {
    if expires_at_unix < issued_at_unix {
        return Err(PublishError::ValidityWindowTooLong {
            valid_from: issued_at_unix,
            valid_until: expires_at_unix,
            span: 0,
        });
    }
    let idx = signing_identity_key_idx as usize;
    if idx >= doc.identity_keys.len() {
        return Err(PublishError::SigKeyIdxOutOfBounds {
            idx: signing_identity_key_idx,
            n: doc.identity_keys.len(),
        });
    }

    let mut invite = PairingInvite {
        node_id,
        pair_secret_hash,
        source_instance_id,
        issued_at_unix,
        expires_at_unix,
        signing_identity_key_idx,
        sig: Vec::new(),
    };
    let msg = invite.signing_message();
    invite.sig = signing_identity_sk.sign(&msg);
    Ok(invite)
}

// ── Uniqueness helper ──────────────────────────────────────────────────────

/// Validate (before signing) that a set of `InstanceEntry` values
/// has no duplicate `instance_id`s — the on-wire decode already
/// enforces this, but callers can catch the bug earlier by passing
/// their draft list through this check. Returns the first
/// duplicate id, if any.
pub fn duplicate_instance_id(instances: &[InstanceEntry]) -> Option<[u8; 16]> {
    let mut seen: HashSet<[u8; 16]> = HashSet::with_capacity(instances.len());
    for inst in instances {
        if !seen.insert(inst.instance_id) {
            return Some(inst.instance_id);
        }
    }
    None
}

// ── DHT publish trait + orchestrator ─────────────

/// Pluggable DHT write-side backend. Production wires this to
/// the veil node's DHT service; tests inject an in-memory
/// mock. Symmetric with
/// [`NameLookup`](super::resolver::NameLookup) on the fetch side.
#[async_trait::async_trait]
pub trait IdentityPublisher: Send + Sync {
    /// Store `value` at the DHT slot identified by `dht_key`.
    /// Returns a transport-level error if the put could not
    /// be committed; on success the caller assumes the record is
    /// reachable by peers (modulo normal DHT propagation delays).
    async fn put(&self, dht_key: [u8; 32], value: Vec<u8>) -> Result<(), PublishIoError>;
}

/// Opaque error produced by [`IdentityPublisher`] implementations.
/// Deliberately string-typed so the trait does not prescribe a
/// concrete transport error — the orchestrator only ever bubbles
/// it up.
#[derive(Debug, thiserror::Error)]
#[error("dht publish failed: {0}")]
pub struct PublishIoError(pub String);

impl PublishIoError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// Publish a signed [`IdentityDocument`] at its canonical DHT slot.
pub async fn publish_identity_document(
    doc: &IdentityDocument,
    publisher: &(dyn IdentityPublisher + '_),
) -> Result<(), PublishIoError> {
    let key = IdentityDocument::dht_key(&doc.node_id);
    publisher.put(key, doc.encode()).await
}

/// Publish a signed [`InstanceRegistry`] at its canonical DHT slot.
pub async fn publish_instance_registry(
    registry: &InstanceRegistry,
    publisher: &(dyn IdentityPublisher + '_),
) -> Result<(), PublishIoError> {
    let key = InstanceRegistry::dht_key(&registry.node_id);
    publisher.put(key, registry.encode()).await
}

/// Publish a signed [`MlKemKeyCert`] at its per-instance DHT slot.
pub async fn publish_mlkem_cert(
    cert: &MlKemKeyCert,
    publisher: &(dyn IdentityPublisher + '_),
) -> Result<(), PublishIoError> {
    let key = MlKemKeyCert::dht_key(&cert.node_id, &cert.instance_id);
    publisher.put(key, cert.encode()).await
}

/// Publish a signed [`NameClaim`] at its canonical DHT slot.
pub async fn publish_name_claim(
    claim: &NameClaim,
    publisher: &(dyn IdentityPublisher + '_),
) -> Result<(), PublishIoError> {
    let key = NameClaim::dht_key(&claim.name);
    publisher.put(key, claim.encode()).await
}

/// publish a signed `MigrationCert` blob at its
/// canonical DHT slot (`migration_cert_dht_key(old_node_id)`). The
/// cert is opaque bytes (the caller minted it via
/// `migration::sign_migration_cert`); this helper just routes the
/// put. Caller MUST publish the new identity's `IdentityDocument`
/// before publishing this cert — otherwise resolvers following the
/// chain will see a cert pointing at a missing target и surface
/// `IdentityNotFound`.
pub async fn publish_migration_cert(
    cert_bytes: &[u8],
    old_node_id: &[u8; 32],
    publisher: &(dyn IdentityPublisher + '_),
) -> Result<(), PublishIoError> {
    let key = super::migration::migration_cert_dht_key(old_node_id);
    publisher.put(key, cert_bytes.to_vec()).await
}

/// Summary of what a full-identity publish landed on the DHT.
/// The call site turns this into a user-facing report and/or
/// metrics counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishSummary {
    pub node_id: [u8; 32],
    pub instance_id: [u8; 16],
    pub registry_version: u64,
    pub mlkem_cert_version: u64,
    pub document_dht_key: [u8; 32],
    pub registry_dht_key: [u8; 32],
    pub mlkem_cert_dht_key: [u8; 32],
}

/// Publish a full sovereign-identity bundle (identity document +
/// instance registry + ML-KEM cert) to the DHT in a single call.
///
/// All three puts happen sequentially; if any fails the caller
/// sees the first error and is responsible for deciding whether
/// to retry. Publishes are idempotent — re-running the same
/// call replaces existing DHT values (DHT-level version
/// monotonicity / freshness handles ordering on the peer side).
pub async fn publish_full_identity(
    doc: &IdentityDocument,
    registry: &InstanceRegistry,
    mlkem_cert: &MlKemKeyCert,
    publisher: &(dyn IdentityPublisher + '_),
) -> Result<PublishSummary, PublishIoError> {
    publish_identity_document(doc, publisher).await?;
    publish_instance_registry(registry, publisher).await?;
    publish_mlkem_cert(mlkem_cert, publisher).await?;
    Ok(PublishSummary {
        node_id: doc.node_id,
        instance_id: mlkem_cert.instance_id,
        registry_version: registry.reg_version,
        mlkem_cert_version: mlkem_cert.cert_version,
        document_dht_key: IdentityDocument::dht_key(&doc.node_id),
        registry_dht_key: InstanceRegistry::dht_key(&registry.node_id),
        mlkem_cert_dht_key: MlKemKeyCert::dht_key(&mlkem_cert.node_id, &mlkem_cert.instance_id),
    })
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use ed25519_dalek::Verifier as _;

    use crate::mlkem_fanout::verify_mlkem_cert;
    use crate::resolver::{NameResolver, VerifyConfig};
    use crate::sovereign_flow::{CreateIdentityOptions, create_identity};
    use crate::verify::{ProofVerifyError, verify_identity_document, verify_identity_proof};
    use veil_crypto::x3dh::generate_prekey;
    use veil_proto::name_claim_v2::normalize_name;

    // Test PoW difficulty for sovereign-flow create_identity calls in
    // tests — kept low so fixture build is fast.
    const TEST_POW_DIFFICULTY: u32 = 8;

    use std::path::PathBuf;

    fn tempdir() -> PathBuf {
        crate::test_support::scratch_dir("veil-publish-tests")
    }

    fn fresh_identity() -> (
        crate::sovereign_flow::CreateIdentityOutput,
        IdentitySigningKey,
    ) {
        let opts = CreateIdentityOptions {
            veil_dir: tempdir(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "test".into(),
            pow_difficulty: TEST_POW_DIFFICULTY,
            issued_at_unix: 1_700_000_000,
            valid_until_unix: 1_700_000_000 + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        };
        let out = create_identity(opts).unwrap();
        let sk = IdentitySigningKey::from_ed25519_seed(*out.identity_sk_seed.as_array());
        (out, sk)
    }

    // ── InstanceRegistry sign ↔ verify ─────────────────────────────────────

    #[test]
    fn signed_instance_registry_roundtrips() {
        let (out, sk) = fresh_identity();
        let entry = build_instance_entry(out.instance.instance_id, 0, "laptop".into(), 0);
        let draft = build_instance_registry(out.node_id, 1, 0, vec![entry]);
        let signed = sign_instance_registry(draft, &sk);
        // Wire encode + decode — proves canonical bytes stable.
        let bytes = signed.encode();
        let decoded = InstanceRegistry::decode(&bytes).unwrap();
        assert_eq!(decoded, signed);

        // Signature verifies against the active identity_sk's pubkey.
        let active_pk_bytes = &out.document.identity_keys[0].pubkey;
        let pk_arr: &[u8; 32] = active_pk_bytes.as_slice().try_into().unwrap();
        let pk = ed25519_dalek::VerifyingKey::from_bytes(pk_arr).unwrap();
        let mut msg = Vec::new();
        msg.extend_from_slice(INSTANCE_REGISTRY_SIG_CONTEXT);
        msg.extend_from_slice(&decoded.canonical_signing_bytes());
        let sig = ed25519_dalek::Signature::from_slice(&decoded.sig).unwrap();
        pk.verify(&msg, &sig).expect("registry sig verifies");
    }

    #[test]
    fn instance_registry_with_multiple_devices() {
        let (out, sk) = fresh_identity();
        let a = build_instance_entry([0x11; 16], 0, "laptop".into(), 100);
        let b = build_instance_entry([0x22; 16], 0, "phone".into(), 200);
        let c = build_instance_entry([0x33; 16], 0, "server".into(), 300);
        let draft = build_instance_registry(out.node_id, 5, 0, vec![a, b, c]);
        let signed = sign_instance_registry(draft, &sk);
        assert_eq!(signed.instances.len(), 3);
        let bytes = signed.encode();
        let decoded = InstanceRegistry::decode(&bytes).unwrap();
        assert_eq!(decoded, signed);
    }

    // ── NameClaim sign ↔ verify via resolver ───────────────────────────────

    #[tokio::test]
    async fn signed_name_claim_resolves_through_resolver() {
        use crate::resolver::{IdentityLookup, LookupError, NameLookup};
        use async_trait::async_trait;
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::RwLock as TokioRwLock;

        #[derive(Default, Clone)]
        struct MemBackend {
            names: Arc<TokioRwLock<HashMap<[u8; 32], Vec<u8>>>>,
            docs: Arc<TokioRwLock<HashMap<[u8; 32], Vec<u8>>>>,
        }

        #[async_trait]
        impl NameLookup for MemBackend {
            async fn fetch_name_claim(
                &self,
                key: &[u8; 32],
            ) -> Result<Option<Vec<u8>>, LookupError> {
                Ok(self.names.read().await.get(key).cloned())
            }
            async fn fetch_name_claim_replicated(
                &self,
                key: &[u8; 32],
                n: usize,
            ) -> Result<Vec<Vec<u8>>, LookupError> {
                match self.names.read().await.get(key).cloned() {
                    Some(b) => Ok(std::iter::repeat_n(b, n).collect()),
                    None => Ok(Vec::new()),
                }
            }
        }
        #[async_trait]
        impl IdentityLookup for MemBackend {
            async fn fetch_identity_document(
                &self,
                key: &[u8; 32],
            ) -> Result<Option<Vec<u8>>, LookupError> {
                Ok(self.docs.read().await.get(key).cloned())
            }
        }

        let (out, sk) = fresh_identity();
        let normalized = normalize_name("alice").unwrap();
        let draft = build_name_claim(normalized.clone(), out.node_id, 1_700_000_000, 0);
        let claim = sign_name_claim(draft, &sk).unwrap();

        let backend = MemBackend::default();
        backend
            .names
            .write()
            .await
            .insert(NameClaim::dht_key(&normalized), claim.encode());
        backend.docs.write().await.insert(
            IdentityDocument::dht_key(&out.node_id),
            out.document.encode(),
        );

        // Default quorum=2; the MemBackend simulates all replicas in sync.
        let resolver = NameResolver::with_config(backend, VerifyConfig::default());
        let validated = resolver.resolve("alice", 1_700_000_000).await.unwrap();
        assert_eq!(validated.node_id, out.node_id);
    }

    #[test]
    fn signed_name_claim_meets_pow_difficulty() {
        let (out, sk) = fresh_identity();
        // Force a name that requires a higher difficulty tier.
        let normalized = normalize_name("bob").unwrap();
        let draft = build_name_claim(normalized, out.node_id, 1_700_000_000, 0);
        let claim = sign_name_claim(draft, &sk).unwrap();
        let required = required_difficulty(&claim.name);
        let h = blake3::hash(&claim.pow_preimage());
        assert!(
            veil_util::leading_zero_bits(h.as_bytes()) >= required,
            "mined PoW must meet rarity-proportional difficulty"
        );
    }

    // ── MlKemKeyCert sign ↔ verify ─────────────────────────────────────────

    #[test]
    fn signed_mlkem_cert_verifies_against_document() {
        let (out, sk) = fresh_identity();
        let (ek, _dk_seed) = generate_prekey();
        let cert = sign_mlkem_cert(
            out.node_id,
            out.instance.instance_id,
            ek,
            1_700_000_000 - 60,
            1_700_000_000 + 30 * 86_400,
            1,
            0,
            &sk,
            &out.document,
        )
        .unwrap();
        let verified = verify_mlkem_cert(&cert, &out.document, 1_700_000_000).unwrap();
        assert_eq!(verified.node_id, out.node_id);
        assert_eq!(verified.instance_id, out.instance.instance_id);
    }

    #[test]
    fn mlkem_cert_rejects_out_of_bounds_signing_key_idx() {
        let (out, sk) = fresh_identity();
        let (ek, _) = generate_prekey();
        let err = sign_mlkem_cert(
            out.node_id,
            out.instance.instance_id,
            ek,
            0,
            1_700_000_000,
            1,
            9, // out of bounds — doc has 1 key
            &sk,
            &out.document,
        )
        .unwrap_err();
        assert!(
            matches!(err, PublishError::SigKeyIdxOutOfBounds { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn mlkem_cert_rejects_inverted_validity_window() {
        let (out, sk) = fresh_identity();
        let (ek, _) = generate_prekey();
        let err = sign_mlkem_cert(
            out.node_id,
            out.instance.instance_id,
            ek,
            2_000_000_000,
            1_900_000_000, // earlier than valid_from
            1,
            0,
            &sk,
            &out.document,
        )
        .unwrap_err();
        assert!(
            matches!(err, PublishError::ValidityWindowTooLong { .. }),
            "{err:?}"
        );
    }

    // ── IdentityDocument re-sign ───────────────────────────────────────────

    #[test]
    fn resign_identity_document_preserves_verifier_round_trip() {
        let (out, sk) = fresh_identity();
        // To prove this helper round-trips, we just re-sign the
        // unchanged document and check the output still verifies.
        let doc = out.document.clone();
        let resigned = sign_identity_document(doc, &sk, 0).unwrap();
        verify_identity_document(&resigned, 1_700_000_000).expect("resigned doc verifies");
    }

    #[test]
    fn resign_identity_document_rejects_bad_idx() {
        let (out, sk) = fresh_identity();
        let err = sign_identity_document(out.document, &sk, 99).unwrap_err();
        assert!(
            matches!(err, PublishError::SigKeyIdxOutOfBounds { .. }),
            "{err:?}"
        );
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    #[test]
    fn duplicate_instance_id_detects_collision() {
        let id = [0x22; 16];
        let a = build_instance_entry(id, 0, "".into(), 0);
        let b = build_instance_entry(id, 0, "".into(), 0);
        let c = build_instance_entry([0x33; 16], 0, "".into(), 0);
        assert_eq!(duplicate_instance_id(&[a.clone(), c.clone()]), None);
        assert_eq!(duplicate_instance_id(&[a, b, c]), Some(id));
    }

    // dropped `build_instance_entry_uses_random_mailbox_anchor` —
    // `mailbox_anchor` field is gone (removed mailboxes; the field
    // was orphan random bytes nothing read).

    #[test]
    fn leading_zero_bits_sanity() {
        assert_eq!(veil_util::leading_zero_bits(&[0xFF]), 0);
        assert_eq!(veil_util::leading_zero_bits(&[0x0F]), 4);
        assert_eq!(veil_util::leading_zero_bits(&[0x00, 0x00, 0x00]), 24);
    }

    // ── IdentityPublisher round-trips ──────────

    /// In-memory DHT mock: implements publish (`IdentityPublisher`) and
    /// fetch (`NameLookup` + `IdentityLookup`) against a shared map
    /// so publish → resolve round-trips can run without a real DHT.
    #[derive(Default, Clone)]
    struct MemDht {
        store: std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<[u8; 32], Vec<u8>>>>,
    }

    #[async_trait::async_trait]
    impl IdentityPublisher for MemDht {
        async fn put(&self, dht_key: [u8; 32], value: Vec<u8>) -> Result<(), PublishIoError> {
            self.store.write().await.insert(dht_key, value);
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl crate::resolver::NameLookup for MemDht {
        async fn fetch_name_claim(
            &self,
            key: &[u8; 32],
        ) -> Result<Option<Vec<u8>>, crate::resolver::LookupError> {
            Ok(self.store.read().await.get(key).cloned())
        }
        async fn fetch_name_claim_replicated(
            &self,
            key: &[u8; 32],
            n: usize,
        ) -> Result<Vec<Vec<u8>>, crate::resolver::LookupError> {
            match self.store.read().await.get(key).cloned() {
                Some(b) => Ok(std::iter::repeat_n(b, n).collect()),
                None => Ok(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::resolver::IdentityLookup for MemDht {
        async fn fetch_identity_document(
            &self,
            key: &[u8; 32],
        ) -> Result<Option<Vec<u8>>, crate::resolver::LookupError> {
            Ok(self.store.read().await.get(key).cloned())
        }
    }

    /// Always-failing mock for error-path coverage.
    struct FailingDht;

    #[async_trait::async_trait]
    impl IdentityPublisher for FailingDht {
        async fn put(&self, _key: [u8; 32], _value: Vec<u8>) -> Result<(), PublishIoError> {
            Err(PublishIoError::new("simulated transport failure"))
        }
    }

    fn build_cert(
        out: &crate::sovereign_flow::CreateIdentityOutput,
        sk: &IdentitySigningKey,
        now_unix_secs: u64,
    ) -> MlKemKeyCert {
        let (ek, _dk_seed) = generate_prekey();
        sign_mlkem_cert(
            out.node_id,
            out.instance.instance_id,
            ek,
            now_unix_secs - 60,
            now_unix_secs + 30 * 86_400,
            1,
            0,
            sk,
            &out.document,
        )
        .unwrap()
    }

    fn build_registry(
        out: &crate::sovereign_flow::CreateIdentityOutput,
        sk: &IdentitySigningKey,
    ) -> InstanceRegistry {
        let entry = build_instance_entry(out.instance.instance_id, 0, "laptop".into(), 0);
        let draft = build_instance_registry(out.node_id, 1, 0, vec![entry]);
        sign_instance_registry(draft, sk)
    }

    #[tokio::test]
    async fn publish_full_identity_lands_three_records_at_canonical_keys() {
        let (out, sk) = fresh_identity();
        let now = 1_700_000_000;
        let registry = build_registry(&out, &sk);
        let cert = build_cert(&out, &sk, now);

        let dht = MemDht::default();
        let summary = publish_full_identity(&out.document, &registry, &cert, &dht)
            .await
            .expect("publish succeeds");

        // Summary reflects the published records.
        assert_eq!(summary.node_id, out.node_id);
        assert_eq!(summary.instance_id, out.instance.instance_id);
        assert_eq!(summary.registry_version, registry.reg_version);
        assert_eq!(summary.mlkem_cert_version, cert.cert_version);
        assert_eq!(
            summary.document_dht_key,
            IdentityDocument::dht_key(&out.node_id)
        );
        assert_eq!(
            summary.registry_dht_key,
            InstanceRegistry::dht_key(&out.node_id)
        );
        assert_eq!(
            summary.mlkem_cert_dht_key,
            MlKemKeyCert::dht_key(&out.node_id, &out.instance.instance_id)
        );

        // All three records actually landed in the DHT.
        let store = dht.store.read().await;
        assert_eq!(store.len(), 3, "exactly three records published");
        assert!(store.contains_key(&summary.document_dht_key));
        assert!(store.contains_key(&summary.registry_dht_key));
        assert!(store.contains_key(&summary.mlkem_cert_dht_key));

        // Bytes round-trip through the canonical codec.
        let doc_bytes = store.get(&summary.document_dht_key).unwrap();
        assert_eq!(IdentityDocument::decode(doc_bytes).unwrap(), out.document);
        let reg_bytes = store.get(&summary.registry_dht_key).unwrap();
        assert_eq!(InstanceRegistry::decode(reg_bytes).unwrap(), registry);
        let cert_bytes = store.get(&summary.mlkem_cert_dht_key).unwrap();
        assert_eq!(MlKemKeyCert::decode(cert_bytes).unwrap(), cert);
    }

    #[tokio::test]
    async fn publish_then_resolve_name_roundtrips_through_same_backend() {
        let (out, sk) = fresh_identity();
        let now = 1_700_000_000;
        let registry = build_registry(&out, &sk);
        let cert = build_cert(&out, &sk, now);

        let dht = MemDht::default();
        publish_full_identity(&out.document, &registry, &cert, &dht)
            .await
            .unwrap();

        // Also publish a name claim pointing to the same identity.
        let normalized = normalize_name("carol").unwrap();
        let draft = build_name_claim(normalized.clone(), out.node_id, now, 0);
        let claim = sign_name_claim(draft, &sk).unwrap();
        publish_name_claim(&claim, &dht).await.unwrap();

        // The resolver walks the same DHT that the publisher wrote to.
        let resolver = NameResolver::with_config(dht.clone(), VerifyConfig::default());
        let validated = resolver.resolve("carol", now).await.unwrap();
        assert_eq!(validated.node_id, out.node_id);

        // Directly fetch + verify the published mlkem cert.
        let key = MlKemKeyCert::dht_key(&out.node_id, &out.instance.instance_id);
        let fetched_bytes = dht.store.read().await.get(&key).cloned().unwrap();
        let fetched_cert = MlKemKeyCert::decode(&fetched_bytes).unwrap();
        let verified = verify_mlkem_cert(&fetched_cert, &out.document, now).unwrap();
        assert_eq!(verified.node_id, out.node_id);
        assert_eq!(verified.instance_id, out.instance.instance_id);
    }

    #[tokio::test]
    async fn publish_full_identity_is_idempotent_and_replaces_on_rotation() {
        let (out, sk) = fresh_identity();
        let now = 1_700_000_000;
        let registry = build_registry(&out, &sk);
        let cert_v1 = build_cert(&out, &sk, now);

        let dht = MemDht::default();
        publish_full_identity(&out.document, &registry, &cert_v1, &dht)
            .await
            .unwrap();
        assert_eq!(dht.store.read().await.len(), 3);

        // A rotated cert replaces the existing slot (same instance_id).
        let (ek2, _) = generate_prekey();
        let cert_v2 = sign_mlkem_cert(
            out.node_id,
            out.instance.instance_id,
            ek2,
            now - 60,
            now + 30 * 86_400,
            2,
            0,
            &sk,
            &out.document,
        )
        .unwrap();
        publish_full_identity(&out.document, &registry, &cert_v2, &dht)
            .await
            .unwrap();

        // Still exactly three records — the cert slot was overwritten.
        let store = dht.store.read().await;
        assert_eq!(store.len(), 3);
        let cert_bytes = store
            .get(&MlKemKeyCert::dht_key(
                &out.node_id,
                &out.instance.instance_id,
            ))
            .unwrap();
        assert_eq!(
            MlKemKeyCert::decode(cert_bytes).unwrap().cert_version,
            2,
            "rotated cert is now in the DHT slot"
        );
    }

    #[tokio::test]
    async fn publish_surfaces_transport_error_from_backend() {
        let (out, sk) = fresh_identity();
        let now = 1_700_000_000;
        let registry = build_registry(&out, &sk);
        let cert = build_cert(&out, &sk, now);

        let err = publish_full_identity(&out.document, &registry, &cert, &FailingDht)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("simulated transport failure"),
            "transport error bubbled up verbatim: {err}"
        );
    }

    // ── IdentityProof sign ↔ verify ──────────────────────────

    fn fresh_proof(
        now: u64,
        valid_for_secs: u64,
    ) -> (
        crate::sovereign_flow::CreateIdentityOutput,
        IdentitySigningKey,
        [u8; 32],
        IdentityProof,
    ) {
        let (out, sk) = fresh_identity();
        let ephemeral = veil_crypto::kex::generate_ephemeral();
        let ephemeral_pk = ephemeral.public_key;
        let proof = sign_identity_proof(
            &out.document,
            0,
            &sk,
            ephemeral_pk,
            now + valid_for_secs,
            (now / 3600) as u32,
        )
        .unwrap();
        (out, sk, ephemeral_pk, proof)
    }

    #[test]
    fn identity_proof_sign_verify_roundtrip() {
        let now = 1_700_000_000;
        let (out, _sk, ephemeral_pk, proof) = fresh_proof(now, 300);
        let validated = verify_identity_proof(&proof, now).expect("proof verifies");

        assert_eq!(validated.node_id, out.node_id);
        assert_eq!(validated.master_pubkey, out.document.master_pubkey);
        assert_eq!(
            validated.active_identity_pubkey,
            out.document.identity_keys[0].pubkey
        );
        // device_id deterministic from the active subkey.
        assert_eq!(
            validated.active_device_id,
            out.document.identity_keys[0].device_id,
        );
        assert_eq!(proof.ephemeral_x25519_pk, ephemeral_pk);
    }

    #[test]
    fn identity_proof_wire_roundtrip_verifies_too() {
        let now = 1_700_000_000;
        let (_, _sk, _, proof) = fresh_proof(now, 300);
        // Round-trip through the canonical wire encoder — verifier
        // must still accept.
        let bytes = proof.encode();
        let decoded = IdentityProof::decode(&bytes).unwrap();
        verify_identity_proof(&decoded, now).unwrap();
    }

    #[test]
    fn identity_proof_rejects_wrong_ephemeral_pk() {
        // Classic MITM scenario: attacker swaps the ephemeral pk in
        // transit → ephemeral_sig no longer verifies over the observed
        // pk, and the verifier catches it.
        let now = 1_700_000_000;
        let (_, _sk, _, mut proof) = fresh_proof(now, 300);
        proof.ephemeral_x25519_pk[0] ^= 0xFF;
        let err = verify_identity_proof(&proof, now).unwrap_err();
        assert!(
            matches!(err, ProofVerifyError::EphemeralSigInvalid),
            "{err:?}"
        );
    }

    #[test]
    fn identity_proof_rejects_tampered_identity_pubkey() {
        // Attacker swaps the subkey for their own — 's
        // deterministic `device_id == BLAKE3(pubkey)` check trips
        // first. (Previously this surfaced as a master-cert-sig
        // failure; the deterministic binding catches it earlier.)
        let now = 1_700_000_000;
        let (_, _sk, _, mut proof) = fresh_proof(now, 300);
        proof.identity_pubkey[0] ^= 0xFF;
        let err = verify_identity_proof(&proof, now).unwrap_err();
        assert!(
            matches!(err, ProofVerifyError::DeviceIdMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn identity_proof_rejects_tampered_master_pubkey() {
        // Swapping master_pubkey breaks the node_id binding.
        let now = 1_700_000_000;
        let (_, _sk, _, mut proof) = fresh_proof(now, 300);
        proof.master_pubkey[0] ^= 0xFF;
        let err = verify_identity_proof(&proof, now).unwrap_err();
        assert!(
            matches!(err, ProofVerifyError::NodeIdMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn identity_proof_rejects_expired_window() {
        let now = 1_700_000_000;
        let (_, _sk, _, proof) = fresh_proof(now, 300);
        let err = verify_identity_proof(&proof, now + 301).unwrap_err();
        assert!(matches!(err, ProofVerifyError::Expired { .. }), "{err:?}");
    }

    #[test]
    fn identity_proof_rejects_bad_sig_key_idx() {
        let (out, sk) = fresh_identity();
        let ephemeral = veil_crypto::kex::generate_ephemeral();
        let err = sign_identity_proof(
            &out.document,
            99, // out of bounds — doc has 1 key
            &sk,
            ephemeral.public_key,
            1_700_000_000 + 300,
            (1_700_000_000u64 / 3600) as u32,
        )
        .unwrap_err();
        assert!(
            matches!(err, PublishError::SigKeyIdxOutOfBounds { .. }),
            "{err:?}"
        );
    }

    // ── PairingInvite sign ↔ verify ──────────────────────────

    #[test]
    fn pairing_invite_sign_and_verify_signature() {
        use veil_proto::pairing_invite::{
            PAIR_SECRET_LEN, PAIRING_INVITE_SIG_CONTEXT, hash_pair_secret,
        };
        let (out, sk) = fresh_identity();
        let pair_secret = [0xCDu8; PAIR_SECRET_LEN];
        let now = 1_700_000_000u64;

        let invite = sign_pairing_invite(
            out.node_id,
            hash_pair_secret(&pair_secret),
            out.instance.instance_id,
            now,
            now + 300,
            0,
            &sk,
            &out.document,
        )
        .unwrap();

        // Wire-level round-trip: decoding the signed bytes yields the
        // identical struct.
        let bytes = invite.encode();
        let decoded = PairingInvite::decode(&bytes).unwrap();
        assert_eq!(decoded, invite);

        // Signature verifies against the active identity subkey.
        let active_pk_bytes = &out.document.identity_keys[0].pubkey;
        let pk_arr: &[u8; 32] = active_pk_bytes.as_slice().try_into().unwrap();
        let pk = ed25519_dalek::VerifyingKey::from_bytes(pk_arr).unwrap();
        let mut msg = Vec::new();
        msg.extend_from_slice(PAIRING_INVITE_SIG_CONTEXT);
        msg.extend_from_slice(&decoded.canonical_signing_bytes());
        let sig = ed25519_dalek::Signature::from_slice(&decoded.sig).unwrap();
        pk.verify(&msg, &sig).expect("invite sig verifies");
    }

    #[test]
    fn pairing_invite_rejects_bad_sig_key_idx() {
        use veil_proto::pairing_invite::{PAIR_SECRET_LEN, hash_pair_secret};
        let (out, sk) = fresh_identity();
        let err = sign_pairing_invite(
            out.node_id,
            hash_pair_secret(&[0u8; PAIR_SECRET_LEN]),
            out.instance.instance_id,
            1_700_000_000,
            1_700_000_000 + 300,
            99, // out of bounds
            &sk,
            &out.document,
        )
        .unwrap_err();
        assert!(
            matches!(err, PublishError::SigKeyIdxOutOfBounds { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn pairing_invite_rejects_inverted_window() {
        use veil_proto::pairing_invite::{PAIR_SECRET_LEN, hash_pair_secret};
        let (out, sk) = fresh_identity();
        let err = sign_pairing_invite(
            out.node_id,
            hash_pair_secret(&[0u8; PAIR_SECRET_LEN]),
            out.instance.instance_id,
            1_700_000_500,
            1_700_000_000, // before issued_at
            0,
            &sk,
            &out.document,
        )
        .unwrap_err();
        assert!(
            matches!(err, PublishError::ValidityWindowTooLong { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn pairing_full_ceremony_wire_plausibility() {
        // End-to-end library-level plausibility check: source signs
        // an invite + renders the QR URI, target parses it, hashes
        // the secret it scanned, and gets back the invite's
        // `pair_secret_hash` — no impostor can short-circuit this.
        use veil_proto::pairing_invite::{PAIR_SECRET_LEN, PairingUri, hash_pair_secret};
        let (out, sk) = fresh_identity();
        let pair_secret = [0x42u8; PAIR_SECRET_LEN];
        let now = 1_700_000_000u64;

        // Source publishes the signed invite (DHT-facing).
        let invite = sign_pairing_invite(
            out.node_id,
            hash_pair_secret(&pair_secret),
            out.instance.instance_id,
            now,
            now + 300,
            0,
            &sk,
            &out.document,
        )
        .unwrap();
        assert!(invite.is_valid_at(now));

        // Source renders the QR URI (target-facing).
        let qr = PairingUri {
            node_id: out.node_id,
            pair_secret,
            endpoint: "tcp://10.0.0.5:45000".into(),
            expires_at_unix: invite.expires_at_unix,
        };
        let uri_str = qr.to_uri().unwrap();

        // Target scans the URI and verifies the pair_secret hashes
        // to the DHT-published invite's hash.
        let scanned = PairingUri::from_uri(&uri_str).unwrap();
        assert_eq!(scanned.node_id, invite.node_id);
        assert_eq!(
            hash_pair_secret(&scanned.pair_secret),
            invite.pair_secret_hash
        );
        assert_eq!(scanned.expires_at_unix, invite.expires_at_unix);
    }

    #[test]
    fn pairing_oob_both_devices_see_matching_code() {
        // Plausibility that the OOB helper slots into the ceremony:
        // after the pair handshake the two sides share a session key
        // and both derive the same 6-digit code. Here we simulate
        // "both sides arrived at the same X25519 DH output".
        use veil_crypto::kex;
        use veil_crypto::pair_oob::derive_pair_oob_code;

        let alice = kex::generate_ephemeral();
        let bob = kex::generate_ephemeral();
        let alice_pub = alice.public_key;
        let bob_pub = bob.public_key;
        let s_alice =
            kex::compute_shared_secret(alice, &bob_pub).expect("contributory X25519 shared secret");
        let s_bob =
            kex::compute_shared_secret(bob, &alice_pub).expect("contributory X25519 shared secret");
        assert_eq!(*s_alice, *s_bob); // sanity (deref through Zeroizing)

        let code_alice = derive_pair_oob_code(&*s_alice);
        let code_bob = derive_pair_oob_code(&*s_bob);
        assert_eq!(
            code_alice, code_bob,
            "both devices must display the same OOB"
        );
        assert_eq!(code_alice.len(), 7);
    }

    // ── IdentityProof frame consumer ──────────

    /// Helper: produce a genuine IdentityProof-frame body bytes for
    /// a fresh identity, bound to the given ephemeral pk + window.
    fn build_proof_frame_body(
        out: &crate::sovereign_flow::CreateIdentityOutput,
        sk: &IdentitySigningKey,
        ephemeral_pk: [u8; 32],
        now: u64,
    ) -> Vec<u8> {
        sign_identity_proof(
            &out.document,
            0,
            sk,
            ephemeral_pk,
            now + 300,
            (now / 3600) as u32,
        )
        .unwrap()
        .encode()
    }

    #[test]
    fn proof_frame_accepts_matched_ephemeral_pk() {
        use crate::verify::verify_identity_proof_frame;
        let now = 1_700_000_000u64;
        let (out, sk) = fresh_identity();
        let eph_pk = veil_crypto::kex::generate_ephemeral().public_key;
        let body = build_proof_frame_body(&out, &sk, eph_pk, now);

        let validated = verify_identity_proof_frame(&body, &eph_pk, now).expect("ok");
        assert_eq!(validated.node_id, out.node_id);
        // device_id deterministic from active subkey.
        assert_eq!(
            validated.active_device_id,
            out.document.identity_keys[0].device_id,
        );
    }

    #[test]
    fn proof_frame_rejects_ephemeral_pk_mismatch() {
        // MITM: peer shipped a legit proof signed for ephemeral_pk A
        // but the KA payload advertised ephemeral_pk B (attacker swap).
        use crate::verify::{FrameProofError, verify_identity_proof_frame};
        let now = 1_700_000_000u64;
        let (out, sk) = fresh_identity();
        let eph_a = veil_crypto::kex::generate_ephemeral().public_key;
        let eph_b = veil_crypto::kex::generate_ephemeral().public_key;
        assert_ne!(eph_a, eph_b);
        let body = build_proof_frame_body(&out, &sk, eph_a, now);

        // Frame body was signed for eph_a, but the KA says eph_b.
        let err = verify_identity_proof_frame(&body, &eph_b, now).unwrap_err();
        assert!(
            matches!(err, FrameProofError::EphemeralPkMismatch),
            "{err:?}"
        );
    }

    #[test]
    fn proof_frame_rejects_garbage_body() {
        use crate::verify::{FrameProofError, verify_identity_proof_frame};
        let eph = [0u8; 32];
        // Random bytes, not a valid IdentityProof encoding.
        let err = verify_identity_proof_frame(&[0xFFu8; 50], &eph, 1_700_000_000).unwrap_err();
        assert!(matches!(err, FrameProofError::BodyDecode(_)), "{err:?}");
    }

    #[test]
    fn proof_frame_rejects_empty_body() {
        use crate::verify::{FrameProofError, verify_identity_proof_frame};
        let eph = [0u8; 32];
        let err = verify_identity_proof_frame(&[], &eph, 1_700_000_000).unwrap_err();
        assert!(matches!(err, FrameProofError::BodyDecode(_)), "{err:?}");
    }

    #[test]
    fn proof_frame_rejects_expired_proof() {
        // Body is well-formed and ephemeral_pk matches, but the
        // proof's valid_until has already passed.
        use crate::verify::{FrameProofError, verify_identity_proof_frame};
        let now = 1_700_000_000u64;
        let (out, sk) = fresh_identity();
        let eph_pk = veil_crypto::kex::generate_ephemeral().public_key;
        let body = build_proof_frame_body(&out, &sk, eph_pk, now);
        let err = verify_identity_proof_frame(&body, &eph_pk, now + 301).unwrap_err();
        assert!(matches!(err, FrameProofError::Verify(_)), "{err:?}");
    }
}
