//! IdentityDocument verifier (simplified by
//! re-shaped by).
//!
//! Takes a wire-decoded [`IdentityDocument`] and returns a
//! [`ValidatedIdentity`] on success. The verifier is the single
//! entry point every consumer of identity material (handshake
//! name resolver) funnels through — so the full defense ladder
//! lives here, in order:
//!
//! 1. [`IDENTITY_DOCUMENT_MAGIC`] + `version = 1`.
//! 2. `node_id == BLAKE3(master_pubkey)`.
//! 3. `now ≤ doc.valid_until` (document freshness window).
//! 4. For every [`IdentityKey`]:
//!    a. `device_id == BLAKE3(pubkey)`.
//!    b. `now ≤ key.valid_until_unix` (per-delegation expiry).
//!    c. `master_sig` verifies over [`IdentityKey::certify_message`]
//!    with `master_pubkey`.
//! 5. `sig_key_idx` in bounds.
//! 6. `document_sig` verifies over
//!    `DOC_SIG_CONTEXT || canonical_signing_bytes` with the
//!    selected identity subkey.
//!
//! Only `ALGO_ED25519` and `ALGO_FALCON512` are accepted. Unknown
//! algorithm bytes are rejected at step 4/6.

use ed25519_dalek::{Signature as EdSignature, Verifier as _, VerifyingKey as EdVerifyingKey};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

use veil_crypto::identity::compute_node_id;
use veil_proto::identity_document::{
    ALGO_ED25519, ALGO_FALCON512, CERTIFY_CONTEXT, DOC_SIG_CONTEXT, IdentityDocument, IdentityKey,
};
use veil_proto::identity_proof::IdentityProof;

// ── Types ────────────────────────────────────────────────────────────────────

/// Successful result of verifying an [`IdentityDocument`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedIdentity {
    /// Stable `node_id` = `BLAKE3(master_pubkey)`. Survives rotation
    /// because the master key is permanent.
    pub node_id: [u8; 32],
    /// Master signature algorithm byte.
    pub master_algo: u8,
    /// Master public key (verified to bind to `node_id`).
    pub master_pubkey: Vec<u8>,
    /// Active identity subkey that signed the document.
    pub active_identity_pubkey: Vec<u8>,
    /// Algorithm byte of the active subkey.
    pub active_identity_algo: u8,
    /// Index into `identity_keys` of the active subkey.
    pub active_key_idx: u16,
    /// Deterministic device address of the active subkey
    /// (`BLAKE3(active_identity_pubkey)`).
    pub active_device_id: [u8; 32],
    /// Compatibility shim: the first 16 bytes of
    /// `active_device_id`, exposed so existing dispatcher/session
    /// runtime code that keys on `[u8; 16]` instance ids keeps
    /// working without a deeper refactor. New code should prefer
    /// `active_device_id`.
    pub active_instance_id: [u8; 16],
}

/// Clock-skew tolerance applied to all `valid_from` / `issued_at`
/// lower-bound checks on identity wire formats.
///
/// **Interactive tier** — see
/// [`veil_proto::time_validity::INTERACTIVE_SKEW_SECS`].  Pinned to
/// the central policy so that future audits / refactors preserve the
/// cross-site invariant ("the user is waiting on this packet").
///
/// 60 s admits NTP drift + one human-scale retry without
/// over-tolerating future-dated abuse.
pub const TIME_VALIDITY_SKEW_SECS: u64 = veil_proto::time_validity::INTERACTIVE_SKEW_SECS;

/// audit follow-up: max declared-vs-actual hour drift
/// accepted on `IdentityProof.freshness_hour` checks. ±1 hour ⇒
/// freshness window of ~2 hours total — captures producers running
/// briefly with a wrong clock without admitting a cached proof from
/// arbitrary time in the past. Matches the existing
/// `NAME_CLAIM_FRESHNESS_HOUR_SKEW = 2` semantics (NameClaim resolver
/// uses a ±2-hour window; proofs are tighter because they are minted
/// per-handshake, not republished hourly).
pub const FRESHNESS_HOUR_SKEW: u64 = 1;

/// Errors emitted during verification. Every variant corresponds to a
/// step in the verifier ladder so log messages carry "what failed"
/// without the caller having to pattern-match further.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("identity_document: bad magic or version")]
    BadHeader,
    #[error("identity_document: node_id mismatch (computed {computed:?} vs doc {doc:?})")]
    NodeIdMismatch { computed: [u8; 32], doc: [u8; 32] },
    #[error("identity_document: expired (now {now} > valid_until {valid_until})")]
    Expired { now: u64, valid_until: u64 },
    #[error("identity_document: future-dated (now {now} < issued_at {issued_at} - skew {skew})")]
    NotYetValid { now: u64, issued_at: u64, skew: u64 },
    #[error(
        "identity_document: identity_key[{idx}] device_id mismatch \
         (computed {computed:?} vs key {key:?})"
    )]
    DeviceIdMismatch {
        idx: usize,
        computed: [u8; 32],
        key: [u8; 32],
    },
    #[error(
        "identity_document: identity_key[{idx}] expired \
         (now {now} > key.valid_until {valid_until})"
    )]
    KeyExpired {
        idx: usize,
        now: u64,
        valid_until: u64,
    },
    #[error(
        "identity_document: identity_key[{idx}] future-dated \
         (now {now} < key.valid_from {valid_from} - skew {skew})"
    )]
    KeyNotYetValid {
        idx: usize,
        now: u64,
        valid_from: u64,
        skew: u64,
    },
    #[error("identity_document: identity_key[{idx}] master certification invalid")]
    CertSigInvalid { idx: usize },
    #[error(
        "identity_document: sig_key_idx {sig_key_idx} out of bounds \
         ({n_keys} keys)"
    )]
    SigKeyIdxOutOfBounds { sig_key_idx: u16, n_keys: usize },
    #[error("identity_document: document_sig invalid")]
    DocumentSigInvalid,
    #[error("identity_document: unsupported signature algorithm byte {0}")]
    UnsupportedAlgo(u8),
    #[error("identity_document: invalid pubkey ({kind}, algo {algo}): {msg}")]
    InvalidPubkey {
        kind: &'static str,
        algo: u8,
        msg: String,
    },
    #[error("identity_document: invalid signature encoding ({kind}): {msg}")]
    InvalidSigEncoding { kind: &'static str, msg: String },
}

// ── Entry point ──────────────────────────────────────────────────────────────

/// Verify a wire-decoded [`IdentityDocument`].
///
/// `now_unix_secs` is passed in explicitly so tests can pin clock state
/// and production callers can use a single consistent "now" across a
/// batch of verifications.
pub fn verify_identity_document(
    doc: &IdentityDocument,
    now_unix_secs: u64,
) -> Result<ValidatedIdentity, VerifyError> {
    // Audit batch 2026-05-25 phase M (cross-audit closure): removed
    // tautological magic/version check.  Previous code compared
    // `IDENTITY_DOCUMENT_MAGIC != [b'I', b'D']` — both sides are the
    // same const, so the branch was unreachable.  Magic + version are
    // enforced upstream by `IdentityDocument::decode` (the single
    // source of truth); hand-constructed structs that bypass decode
    // are a callers-responsibility issue caught by tests / fuzz, not
    // by a defensive runtime check that compared a const to itself.

    // 1. node_id must bind to master_pubkey.
    let computed = compute_node_id(&doc.master_pubkey);
    if computed != doc.node_id {
        return Err(VerifyError::NodeIdMismatch {
            computed,
            doc: doc.node_id,
        });
    }

    // 3. Freshness window — both bounds. audit follow-up
    // added the lower-bound check; pre-fix a document with
    // `issued_at_unix` set to "today + 30 days" would silently
    // verify, which would let a compromised master sign a document
    // that activates AFTER a revocation window.
    if now_unix_secs > doc.valid_until_unix {
        return Err(VerifyError::Expired {
            now: now_unix_secs,
            valid_until: doc.valid_until_unix,
        });
    }
    // `issued_at_unix == 0` is the legacy / unset sentinel — never
    // reject on it (some publish-side helpers and all pre-refactor
    // identities serialize zero by default). Real producers always
    // pass `now`, so a value > now + skew can only mean intentional
    // future-dating.
    if doc.issued_at_unix > 0 && now_unix_secs + TIME_VALIDITY_SKEW_SECS < doc.issued_at_unix {
        return Err(VerifyError::NotYetValid {
            now: now_unix_secs,
            issued_at: doc.issued_at_unix,
            skew: TIME_VALIDITY_SKEW_SECS,
        });
    }

    // 4. Every identity_key's deterministic device_id binding
    // its own validity window, and its master cert.
    for (idx, key) in doc.identity_keys.iter().enumerate() {
        // 4a. device_id == BLAKE3(pubkey) — deterministic binding.
        let computed_device_id = compute_node_id(&key.pubkey);
        if computed_device_id != key.device_id {
            return Err(VerifyError::DeviceIdMismatch {
                idx,
                computed: computed_device_id,
                key: key.device_id,
            });
        }
        // 4b. Per-delegation expiry — even if doc is fresh, an
        // individual subkey may have aged out.
        if now_unix_secs > key.valid_until_unix {
            return Err(VerifyError::KeyExpired {
                idx,
                now: now_unix_secs,
                valid_until: key.valid_until_unix,
            });
        }
        // 4b'. Per-delegation lower bound.
        // Same legacy-sentinel handling as the document level.
        if key.valid_from_unix > 0 && now_unix_secs + TIME_VALIDITY_SKEW_SECS < key.valid_from_unix
        {
            return Err(VerifyError::KeyNotYetValid {
                idx,
                now: now_unix_secs,
                valid_from: key.valid_from_unix,
                skew: TIME_VALIDITY_SKEW_SECS,
            });
        }
        // 4c. Master cert.
        verify_identity_key_cert(doc, key).map_err(|_| VerifyError::CertSigInvalid { idx })?;
    }

    // 5. sig_key_idx bounds.
    let active_key = doc.identity_keys.get(doc.sig_key_idx as usize).ok_or(
        VerifyError::SigKeyIdxOutOfBounds {
            sig_key_idx: doc.sig_key_idx,
            n_keys: doc.identity_keys.len(),
        },
    )?;

    // 6. document_sig over canonical bytes (with DOC_SIG_CONTEXT prefix).
    let mut doc_msg = Vec::with_capacity(DOC_SIG_CONTEXT.len() + 512);
    doc_msg.extend_from_slice(DOC_SIG_CONTEXT);
    doc_msg.extend_from_slice(&doc.canonical_signing_bytes());
    verify_sig_raw(
        active_key.algo,
        &active_key.pubkey,
        &doc_msg,
        &doc.document_sig,
    )
    .map_err(|_| VerifyError::DocumentSigInvalid)?;

    Ok(ValidatedIdentity {
        node_id: doc.node_id,
        master_algo: doc.master_algo,
        master_pubkey: doc.master_pubkey.clone(),
        active_identity_pubkey: active_key.pubkey.clone(),
        active_identity_algo: active_key.algo,
        active_key_idx: doc.sig_key_idx,
        active_device_id: active_key.device_id,
        active_instance_id: device_id_to_instance_id(&active_key.device_id),
    })
}

/// Compatibility shim: map a 32-byte deterministic
/// `device_id` to the legacy 16-byte `instance_id` that runtime code
/// (session manager, dispatcher delivery, mlkem fanout) still keys on.
/// Truncates the high bits — collisions are not security-sensitive
/// because the routing layer cross-checks against the full
/// `node_id` + signature material elsewhere.
pub(crate) fn device_id_to_instance_id(device_id: &[u8; 32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&device_id[..16]);
    out
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn verify_identity_key_cert(doc: &IdentityDocument, key: &IdentityKey) -> Result<(), VerifyError> {
    let msg = key.certify_message(&doc.node_id);
    verify_sig_raw(doc.master_algo, &doc.master_pubkey, &msg, &key.master_sig)
}

fn verify_sig_raw(
    algo: u8,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    match algo {
        ALGO_ED25519 => {
            let pk_arr: &[u8; 32] =
                public_key
                    .try_into()
                    .map_err(|_| VerifyError::InvalidPubkey {
                        kind: "ed25519",
                        algo,
                        msg: format!("expected 32 B, got {}", public_key.len()),
                    })?;
            let vk =
                EdVerifyingKey::from_bytes(pk_arr).map_err(|e| VerifyError::InvalidPubkey {
                    kind: "ed25519",
                    algo,
                    msg: e.to_string(),
                })?;
            let sig = EdSignature::from_slice(signature).map_err(|e| {
                VerifyError::InvalidSigEncoding {
                    kind: "ed25519",
                    msg: e.to_string(),
                }
            })?;
            vk.verify(message, &sig)
                .map_err(|_| VerifyError::DocumentSigInvalid) // remapped by caller
        }
        ALGO_FALCON512 => {
            let pk = falcon512::PublicKey::from_bytes(public_key).map_err(|e| {
                VerifyError::InvalidPubkey {
                    kind: "falcon512",
                    algo,
                    msg: e.to_string(),
                }
            })?;
            let sig = falcon512::DetachedSignature::from_bytes(signature).map_err(|e| {
                VerifyError::InvalidSigEncoding {
                    kind: "falcon512",
                    msg: e.to_string(),
                }
            })?;
            falcon512::verify_detached_signature(&sig, message, &pk)
                .map_err(|_| VerifyError::DocumentSigInvalid)
        }
        veil_proto::identity_document::ALGO_ED25519_FALCON512_HYBRID => {
            // hybrid IdentityDocument verify — delegate to
            // the canonical hybrid verify in `veil-crypto` via the
            // base64-encoded path. This re-uses split_hybrid_pk +
            // split_hybrid_sig + dual verify, ensuring the IdentityDocument
            // path enforces the same security invariant as every other
            // hybrid call site (BOTH signatures must verify).
            use base64::Engine as _;
            let pk_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);
            veil_crypto::verify_message(
                veil_types::SignatureAlgorithm::Ed25519Falcon512Hybrid,
                &pk_b64,
                message,
                signature,
            )
            .map_err(|_| VerifyError::DocumentSigInvalid)
        }
        veil_proto::identity_document::ALGO_ED25519_FALCON1024_HYBRID => {
            // Phase 10 follow-up: Falcon-1024 hybrid IdentityDocument
            // verify.  Same delegation pattern as the 512-hybrid arm
            // above; both component signatures must verify under the
            // canonical `veil-crypto` hybrid-1024 path.
            use base64::Engine as _;
            let pk_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);
            veil_crypto::verify_message(
                veil_types::SignatureAlgorithm::Ed25519Falcon1024Hybrid,
                &pk_b64,
                message,
                signature,
            )
            .map_err(|_| VerifyError::DocumentSigInvalid)
        }
        _ => Err(VerifyError::UnsupportedAlgo(algo)),
    }
}

// ── IdentityProof verifier ─────────────────────────────────────

/// Errors emitted by [`verify_identity_proof`]. Kept separate from
/// [`VerifyError`] so the handshake path has a tight, auditable set of
/// reject reasons.
#[derive(Debug, thiserror::Error)]
pub enum ProofVerifyError {
    #[error("identity_proof: node_id mismatch (computed {computed:?} vs proof {proof:?})")]
    NodeIdMismatch { computed: [u8; 32], proof: [u8; 32] },
    #[error("identity_proof: expired (now {now} > valid_until {valid_until})")]
    Expired { now: u64, valid_until: u64 },
    #[error(
        "identity_proof: future-dated delegation \
         (now {now} < key.valid_from {valid_from} - skew {skew})"
    )]
    KeyNotYetValid {
        now: u64,
        valid_from: u64,
        skew: u64,
    },
    #[error(
        "identity_proof: declared freshness_hour {declared} differs from \
         actual hour {actual} by more than ±{max_skew} hours"
    )]
    FreshnessHourSkew {
        declared: u32,
        actual: u64,
        max_skew: u64,
    },
    #[error("identity_proof: device_id mismatch (computed {computed:?} vs proof {proof:?})")]
    DeviceIdMismatch { computed: [u8; 32], proof: [u8; 32] },
    #[error("identity_proof: delegation expired (now {now} > key.valid_until {valid_until})")]
    KeyExpired { now: u64, valid_until: u64 },
    #[error("identity_proof: master certification signature invalid")]
    MasterCertInvalid,
    #[error("identity_proof: ephemeral signature invalid")]
    EphemeralSigInvalid,
    #[error("identity_proof: unsupported signature algorithm byte {0}")]
    UnsupportedAlgo(u8),
    #[error("identity_proof: invalid pubkey ({kind}, algo {algo}): {msg}")]
    InvalidPubkey {
        kind: &'static str,
        algo: u8,
        msg: String,
    },
    #[error("identity_proof: invalid signature encoding ({kind}): {msg}")]
    InvalidSigEncoding { kind: &'static str, msg: String },
}

/// Verify an in-handshake [`IdentityProof`]. On success the peer is
/// authenticated:
/// `node_id == BLAKE3(master_pubkey)` — master binding check
/// inline `master_sig` covers the standard `IdentityKey`
/// certify-message shape, so the embedded subkey really is a
/// master-certified identity subkey
/// `ephemeral_sig` binds the X25519 ephemeral pk presented in this
/// handshake to the identity subkey (anti-MITM)
/// `now ≤ proof_valid_until_unix`.
///
/// Returns a [`ValidatedIdentity`] the session layer can cache to key
/// future lookups.
pub fn verify_identity_proof(
    proof: &IdentityProof,
    now_unix_secs: u64,
) -> Result<ValidatedIdentity, ProofVerifyError> {
    use veil_crypto::identity::compute_node_id;

    // 1. node_id binds to master_pubkey.
    let computed = compute_node_id(&proof.master_pubkey);
    if computed != proof.node_id {
        return Err(ProofVerifyError::NodeIdMismatch {
            computed,
            proof: proof.node_id,
        });
    }

    // 2. Validity window upper bound (proof itself).
    if now_unix_secs > proof.proof_valid_until_unix {
        return Err(ProofVerifyError::Expired {
            now: now_unix_secs,
            valid_until: proof.proof_valid_until_unix,
        });
    }

    // 3. Deterministic device_id binding.
    let computed_device_id = compute_node_id(&proof.identity_pubkey);
    if computed_device_id != proof.device_id {
        return Err(ProofVerifyError::DeviceIdMismatch {
            computed: computed_device_id,
            proof: proof.device_id,
        });
    }

    // 4. Per-delegation expiry.
    if now_unix_secs > proof.key_valid_until_unix {
        return Err(ProofVerifyError::KeyExpired {
            now: now_unix_secs,
            valid_until: proof.key_valid_until_unix,
        });
    }
    // 4'. Per-delegation lower bound.
    // Same legacy-zero handling as in `verify_identity_document`.
    if proof.key_valid_from_unix > 0
        && now_unix_secs + TIME_VALIDITY_SKEW_SECS < proof.key_valid_from_unix
    {
        return Err(ProofVerifyError::KeyNotYetValid {
            now: now_unix_secs,
            valid_from: proof.key_valid_from_unix,
            skew: TIME_VALIDITY_SKEW_SECS,
        });
    }
    // 4''. `freshness_hour` sanity check — NOT replay protection.
    // The wire field is carried through encode/decode and producers set it to
    // `floor(now / 3600)` at sign time (`publish::sign_identity_proof`).
    // IMPORTANT: `freshness_hour` is NOT covered by any signature —
    // `ephemeral_signing_message` signs context||node_id||proof_valid_until||
    // ephemeral_x25519_pk, not this field — so an attacker replaying a captured
    // proof can rewrite `freshness_hour` to the current hour and pass this check.
    // It therefore does NOT stop a deliberate replay. The load-bearing
    // anti-replay is the ephemeral-pk binding in `verify_identity_proof_frame`
    // (the proof must match the live key-agreement ephemeral of THIS session, so
    // a captured proof cannot bind to a fresh handshake). What this check DOES
    // catch is an honest producer with a badly-wrong clock or a grossly stale
    // cached proof. Skew window is FRESHNESS_HOUR_SKEW hours (±1).
    // Producers carrying `freshness_hour == 0` predate this field
    // (legacy / uninitialized) and are accepted silently — same
    // "0-as-sentinel" rule as the other lower-bound fields.
    if proof.freshness_hour > 0 {
        let actual_hour = now_unix_secs / 3600;
        let declared_hour = proof.freshness_hour as u64;
        let drift = actual_hour.abs_diff(declared_hour);
        if drift > FRESHNESS_HOUR_SKEW {
            return Err(ProofVerifyError::FreshnessHourSkew {
                declared: proof.freshness_hour,
                actual: actual_hour,
                max_skew: FRESHNESS_HOUR_SKEW,
            });
        }
    }

    // 5. Inline master certification over the subkey.
    // Rebuild the standard IdentityKey certify_message shape — the
    // inline sig must cover the same bytes the full document would.
    let cert_msg = certify_message_for(
        &proof.node_id,
        proof.identity_algo,
        &proof.identity_pubkey,
        &proof.device_id,
        proof.key_valid_from_unix,
        proof.key_valid_until_unix,
    );
    verify_proof_sig(
        proof.master_algo,
        &proof.master_pubkey,
        &cert_msg,
        &proof.master_sig,
    )
    .map_err(|e| match e {
        ProofVerifyError::EphemeralSigInvalid => ProofVerifyError::MasterCertInvalid,
        other => other,
    })?;

    // 6. Ephemeral-pk signature (anti-MITM).
    let eph_msg = proof.ephemeral_signing_message();
    verify_proof_sig(
        proof.identity_algo,
        &proof.identity_pubkey,
        &eph_msg,
        &proof.ephemeral_sig,
    )?;

    Ok(ValidatedIdentity {
        node_id: proof.node_id,
        master_algo: proof.master_algo,
        master_pubkey: proof.master_pubkey.clone(),
        active_identity_pubkey: proof.identity_pubkey.clone(),
        active_identity_algo: proof.identity_algo,
        // IdentityProof does not know the full `identity_keys` list, so
        // the index is not observable from a single proof — callers
        // that need the full document's active_key_idx must fetch it.
        active_key_idx: u16::MAX,
        active_device_id: proof.device_id,
        active_instance_id: device_id_to_instance_id(&proof.device_id),
    })
}

/// Build the `IdentityKey::certify_message` bytes without needing a
/// fully-decoded `IdentityKey` struct — used by the proof verifier.
fn certify_message_for(
    node_id: &[u8; 32],
    algo: u8,
    pubkey: &[u8],
    device_id: &[u8; 32],
    valid_from_unix: u64,
    valid_until_unix: u64,
) -> Vec<u8> {
    let mut msg =
        Vec::with_capacity(CERTIFY_CONTEXT.len() + 32 + 1 + 2 + pubkey.len() + 32 + 8 + 8);
    msg.extend_from_slice(CERTIFY_CONTEXT);
    msg.extend_from_slice(node_id);
    msg.push(algo);
    msg.extend_from_slice(&(pubkey.len() as u16).to_be_bytes());
    msg.extend_from_slice(pubkey);
    msg.extend_from_slice(device_id);
    msg.extend_from_slice(&valid_from_unix.to_be_bytes());
    msg.extend_from_slice(&valid_until_unix.to_be_bytes());
    msg
}

/// Signature verifier that returns a `ProofVerifyError` on failure.
/// Shares the algorithm dispatch with [`verify_sig_raw`] but keeps
/// error mapping local so handshake telemetry is crisp.
fn verify_proof_sig(
    algo: u8,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ProofVerifyError> {
    match algo {
        ALGO_ED25519 => {
            let pk_arr: &[u8; 32] =
                public_key
                    .try_into()
                    .map_err(|_| ProofVerifyError::InvalidPubkey {
                        kind: "ed25519",
                        algo,
                        msg: format!("expected 32 B, got {}", public_key.len()),
                    })?;
            let vk = EdVerifyingKey::from_bytes(pk_arr).map_err(|e| {
                ProofVerifyError::InvalidPubkey {
                    kind: "ed25519",
                    algo,
                    msg: e.to_string(),
                }
            })?;
            let sig = EdSignature::from_slice(signature).map_err(|e| {
                ProofVerifyError::InvalidSigEncoding {
                    kind: "ed25519",
                    msg: e.to_string(),
                }
            })?;
            vk.verify(message, &sig)
                .map_err(|_| ProofVerifyError::EphemeralSigInvalid)
        }
        ALGO_FALCON512 => {
            let pk = falcon512::PublicKey::from_bytes(public_key).map_err(|e| {
                ProofVerifyError::InvalidPubkey {
                    kind: "falcon512",
                    algo,
                    msg: e.to_string(),
                }
            })?;
            let sig = falcon512::DetachedSignature::from_bytes(signature).map_err(|e| {
                ProofVerifyError::InvalidSigEncoding {
                    kind: "falcon512",
                    msg: e.to_string(),
                }
            })?;
            falcon512::verify_detached_signature(&sig, message, &pk)
                .map_err(|_| ProofVerifyError::EphemeralSigInvalid)
        }
        veil_proto::identity_document::ALGO_ED25519_FALCON512_HYBRID => {
            // hybrid IdentityProof verify — same delegation
            // pattern as `verify_sig_raw` above; both must verify.
            use base64::Engine as _;
            let pk_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);
            veil_crypto::verify_message(
                veil_types::SignatureAlgorithm::Ed25519Falcon512Hybrid,
                &pk_b64,
                message,
                signature,
            )
            .map_err(|_| ProofVerifyError::EphemeralSigInvalid)
        }
        veil_proto::identity_document::ALGO_ED25519_FALCON1024_HYBRID => {
            // Phase 10 follow-up: Falcon-1024 hybrid IdentityProof
            // verify.  Same delegation pattern as the 512-hybrid arm.
            use base64::Engine as _;
            let pk_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);
            veil_crypto::verify_message(
                veil_types::SignatureAlgorithm::Ed25519Falcon1024Hybrid,
                &pk_b64,
                message,
                signature,
            )
            .map_err(|_| ProofVerifyError::EphemeralSigInvalid)
        }
        _ => Err(ProofVerifyError::UnsupportedAlgo(algo)),
    }
}

// ── IdentityProof-frame consumer ──────────────────────

/// Errors emitted by [`verify_identity_proof_frame`]. A superset of
/// [`ProofVerifyError`] with two extra cases specific to the
/// frame-level surface: structural decode failure of the body bytes
/// and the binding-check against the KA payload's ephemeral_pubkey.
#[derive(Debug, thiserror::Error)]
pub enum FrameProofError {
    #[error("identity_proof frame: body decode failed: {0}")]
    BodyDecode(#[from] veil_proto::ProtoError),
    #[error(
        "identity_proof frame: proof.ephemeral_x25519_pk does not match the KA payload's \
         ephemeral_pubkey — proof is for a different session (possible replay)"
    )]
    EphemeralPkMismatch,
    #[error("identity_proof frame: verifier rejected the proof: {0}")]
    Verify(#[from] ProofVerifyError),
}

/// Verify an inbound `SessionMsg::IdentityProof` frame.
///
/// The runtime session layer, after decoding the preceding
/// `KeyAgreement` payload, stashes the peer's advertised
/// `ephemeral_pubkey` and then — if the next frame is an
/// `IdentityProof` — calls this helper with the raw body bytes, the
/// ephemeral pk it observed, and the current time.
///
/// Steps (fail-closed on first error):
///
/// 1. Decode the body bytes into an [`IdentityProof`].
/// 2. Cross-check `proof.ephemeral_x25519_pk == ka_ephemeral_pubkey`
///    — this is the critical binding that stops an attacker from
///    replaying a harvested proof against a fresh session.
/// 3. Run the full cert-chain + freshness checks via
///    [`verify_identity_proof`].
pub fn verify_identity_proof_frame(
    body: &[u8],
    ka_ephemeral_pubkey: &[u8; 32],
    now_unix_secs: u64,
) -> Result<ValidatedIdentity, FrameProofError> {
    let proof = IdentityProof::decode(body)?;

    if proof.ephemeral_x25519_pk != *ka_ephemeral_pubkey {
        return Err(FrameProofError::EphemeralPkMismatch);
    }

    let validated = verify_identity_proof(&proof, now_unix_secs)?;
    Ok(validated)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    use veil_crypto::identity::certify_message as build_certify;

    // ── Fixture builder ──────────────────────────────────────────────────────

    /// Build a well-formed, signed document over ed25519 that passes
    /// every step of the verifier. Individual tests mutate the
    /// returned struct to exercise negative cases.
    struct Fixture {
        master_sk: SigningKey,
        _sub_sk: SigningKey,
        now_unix_secs: u64,
        doc: IdentityDocument,
    }

    fn build_fixture() -> Fixture {
        build_fixture_at(1_700_000_000)
    }

    fn build_fixture_at(now: u64) -> Fixture {
        // Master keypair.
        let master_sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let master_pk = master_sk.verifying_key();
        let node_id = compute_node_id(master_pk.as_bytes());

        // Identity subkey.
        let sub_sk = SigningKey::from_bytes(&[0x22u8; 32]);
        let sub_pk = sub_sk.verifying_key();
        // device_id is deterministic from the subkey pubkey.
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

        // Build the document scaffold — everything except the signature.
        let issued_at = now;

        let mut doc = IdentityDocument {
            node_id,
            master_algo: ALGO_ED25519,
            master_pubkey: master_pk.as_bytes().to_vec(),
            issued_at_unix: issued_at,
            valid_until_unix: valid_until,
            sig_key_idx: 0,
            identity_keys: vec![identity_key],
            document_sig: Vec::new(),
        };

        // Document signature.
        let mut doc_msg = Vec::new();
        doc_msg.extend_from_slice(DOC_SIG_CONTEXT);
        doc_msg.extend_from_slice(&doc.canonical_signing_bytes());
        doc.document_sig = sub_sk.sign(&doc_msg).to_bytes().to_vec();

        Fixture {
            master_sk,
            _sub_sk: sub_sk,
            now_unix_secs: now,
            doc,
        }
    }

    /// Re-sign `document_sig` after mutating other fields.
    fn resign_document(sub_sk: &SigningKey, doc: &mut IdentityDocument) {
        let mut doc_msg = Vec::new();
        doc_msg.extend_from_slice(DOC_SIG_CONTEXT);
        doc_msg.extend_from_slice(&doc.canonical_signing_bytes());
        doc.document_sig = sub_sk.sign(&doc_msg).to_bytes().to_vec();
    }

    // ── Happy path ───────────────────────────────────────────────────────────

    #[test]
    fn valid_document_verifies() {
        let f = build_fixture();
        let v = verify_identity_document(&f.doc, f.now_unix_secs).expect("valid document");
        assert_eq!(v.node_id, f.doc.node_id);
        assert_eq!(v.active_key_idx, 0);
        assert_eq!(v.master_pubkey, f.doc.master_pubkey);
        assert_eq!(
            v.active_identity_pubkey,
            f.doc.identity_keys[0].pubkey.clone()
        );
        assert_eq!(v.active_device_id, f.doc.identity_keys[0].device_id);
        // Active device_id matches BLAKE3(active_pubkey) — invariant.
        assert_eq!(
            v.active_device_id,
            compute_node_id(&v.active_identity_pubkey)
        );
        // Compatibility shim: instance_id is truncated device_id.
        assert_eq!(&v.active_instance_id[..], &v.active_device_id[..16]);
    }

    #[test]
    fn rejects_device_id_mismatch() {
        let mut f = build_fixture();
        f.doc.identity_keys[0].device_id[0] ^= 0xFF;
        let err = verify_identity_document(&f.doc, f.now_unix_secs).unwrap_err();
        assert!(
            matches!(err, VerifyError::DeviceIdMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_expired_delegation() {
        let mut f = build_fixture();
        // Make sure the doc itself is still fresh, but the per-key
        // delegation has aged out.
        f.doc.identity_keys[0].valid_until_unix = f.now_unix_secs.saturating_sub(1);
        // Have to re-sign the master cert because we changed valid_until
        // and re-sign the document since the canonical bytes changed.
        let cert_msg = build_certify(
            &f.doc.node_id,
            ALGO_ED25519,
            &f.doc.identity_keys[0].pubkey,
            &f.doc.identity_keys[0].device_id,
            f.doc.identity_keys[0].valid_from_unix,
            f.doc.identity_keys[0].valid_until_unix,
        );
        f.doc.identity_keys[0].master_sig = f.master_sk.sign(&cert_msg).to_bytes().to_vec();
        let ss = f._sub_sk.clone();
        resign_document(&ss, &mut f.doc);
        let err = verify_identity_document(&f.doc, f.now_unix_secs).unwrap_err();
        assert!(matches!(err, VerifyError::KeyExpired { .. }), "{err:?}");
    }

    // ── Negative cases ──────────────────────────────────────────────────────

    #[test]
    fn rejects_node_id_mismatch() {
        let mut f = build_fixture();
        f.doc.node_id = [0xFFu8; 32];
        let err = verify_identity_document(&f.doc, f.now_unix_secs).unwrap_err();
        assert!(matches!(err, VerifyError::NodeIdMismatch { .. }), "{err:?}");
    }

    #[test]
    fn rejects_expired_freshness_window() {
        let mut f = build_fixture();
        f.doc.valid_until_unix = f.now_unix_secs + 10;
        {
            let ss = f._sub_sk.clone();
            resign_document(&ss, &mut f.doc);
        }

        let after_expiry = f.doc.valid_until_unix + 1;
        let err = verify_identity_document(&f.doc, after_expiry).unwrap_err();
        assert!(matches!(err, VerifyError::Expired { .. }), "{err:?}");
    }

    #[test]
    fn rejects_tampered_certification_signature() {
        let mut f = build_fixture();
        f.doc.identity_keys[0].master_sig[0] ^= 0x01;
        let err = verify_identity_document(&f.doc, f.now_unix_secs).unwrap_err();
        assert!(
            matches!(err, VerifyError::CertSigInvalid { idx: 0 }),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_cert_with_wrong_node_id_binding() {
        // Attacker takes a valid cert from identity A and copies it
        // into a document claiming identity B. certify_message is
        // node_id-bound, so the sig must fail under B's master_pk
        // / cert_msg.
        let mut f = build_fixture();
        let other_master_sk = SigningKey::from_bytes(&[0xAAu8; 32]);
        let other_master_pk = other_master_sk.verifying_key();
        let other_node_id = compute_node_id(other_master_pk.as_bytes());

        // Use the OTHER node_id to build a cert message that the
        // real master signs — and then place that sig under the real
        // identity's master_pubkey.
        let bad_cert_msg = build_certify(
            &other_node_id,
            ALGO_ED25519,
            &f.doc.identity_keys[0].pubkey,
            &f.doc.identity_keys[0].device_id,
            f.doc.identity_keys[0].valid_from_unix,
            f.doc.identity_keys[0].valid_until_unix,
        );
        let bad_sig = f.master_sk.sign(&bad_cert_msg);
        f.doc.identity_keys[0].master_sig = bad_sig.to_bytes().to_vec();

        let err = verify_identity_document(&f.doc, f.now_unix_secs).unwrap_err();
        assert!(matches!(err, VerifyError::CertSigInvalid { .. }), "{err:?}");
    }

    #[test]
    fn rejects_sig_key_idx_out_of_bounds() {
        let mut f = build_fixture();
        f.doc.sig_key_idx = 7;
        let err = verify_identity_document(&f.doc, f.now_unix_secs).unwrap_err();
        assert!(
            matches!(err, VerifyError::SigKeyIdxOutOfBounds { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_tampered_document_signature() {
        let mut f = build_fixture();
        f.doc.document_sig[0] ^= 0x01;
        let err = verify_identity_document(&f.doc, f.now_unix_secs).unwrap_err();
        assert!(matches!(err, VerifyError::DocumentSigInvalid), "{err:?}");
    }

    #[test]
    fn rejects_document_signed_by_wrong_subkey() {
        let mut f = build_fixture();
        // Sign document_sig with a different ed25519 key.
        let rogue = SigningKey::from_bytes(&[0xFEu8; 32]);
        let mut doc_msg = Vec::new();
        doc_msg.extend_from_slice(DOC_SIG_CONTEXT);
        doc_msg.extend_from_slice(&f.doc.canonical_signing_bytes());
        f.doc.document_sig = rogue.sign(&doc_msg).to_bytes().to_vec();

        let err = verify_identity_document(&f.doc, f.now_unix_secs).unwrap_err();
        assert!(matches!(err, VerifyError::DocumentSigInvalid), "{err:?}");
    }

    #[test]
    fn rejects_unsupported_master_algo() {
        let mut f = build_fixture();
        f.doc.master_algo = 99;
        let err = verify_identity_document(&f.doc, f.now_unix_secs).unwrap_err();
        // master_algo is checked when verifying the master cert (step 4).
        assert!(matches!(err, VerifyError::CertSigInvalid { .. }), "{err:?}");
    }

    #[test]
    fn accepts_window_at_max() {
        use veil_proto::identity_document::MAX_FRESHNESS_WINDOW_SECS;
        let mut f = build_fixture();
        f.doc.valid_until_unix = f.doc.issued_at_unix + MAX_FRESHNESS_WINDOW_SECS;
        {
            let ss = f._sub_sk.clone();
            resign_document(&ss, &mut f.doc);
        }
        verify_identity_document(&f.doc, f.now_unix_secs).unwrap();
    }

    #[test]
    fn multiple_verifications_are_idempotent() {
        let f = build_fixture();
        for _ in 0..3 {
            verify_identity_document(&f.doc, f.now_unix_secs).unwrap();
        }
    }

    // ── audit follow-up: lower-bound time checks ──────────────

    /// `issued_at_unix` set well in the future (past skew window) ⇒ reject.
    /// Pre-fix this would silently verify since only the upper bound was
    /// checked.
    #[test]
    fn rejects_future_dated_issued_at() {
        let mut f = build_fixture();
        // Push issued_at far enough into the future that no plausible skew
        // could absorb it (skew is 60 s; 1 hour ≫ 60 s).
        f.doc.issued_at_unix = f.now_unix_secs + 3600;
        let ss = f._sub_sk.clone();
        resign_document(&ss, &mut f.doc);
        let err = verify_identity_document(&f.doc, f.now_unix_secs).unwrap_err();
        assert!(matches!(err, VerifyError::NotYetValid { .. }), "{err:?}");
    }

    /// Boundary: `issued_at_unix` within the skew window ⇒ accept.
    #[test]
    fn accepts_issued_at_within_skew_window() {
        let mut f = build_fixture();
        // Set issued_at exactly at `now + skew` — the verifier uses a strict
        // `<` on the lower-bound comparison, so equality should pass.
        f.doc.issued_at_unix = f.now_unix_secs + TIME_VALIDITY_SKEW_SECS;
        let ss = f._sub_sk.clone();
        resign_document(&ss, &mut f.doc);
        verify_identity_document(&f.doc, f.now_unix_secs)
            .expect("issued_at exactly at +skew must accept");
    }

    /// `IdentityKey.valid_from_unix` set into the future ⇒ reject with
    /// `KeyNotYetValid` (separate variant from the document-level one to
    /// surface the offending subkey index in logs).
    #[test]
    fn rejects_future_dated_identity_key() {
        let mut f = build_fixture();
        // Future-date the per-key valid_from + re-sign the master cert and
        // document_sig (canonical bytes change so all signatures must be
        // refreshed).
        let new_valid_from = f.now_unix_secs + 3600;
        f.doc.identity_keys[0].valid_from_unix = new_valid_from;
        let cert_msg = build_certify(
            &f.doc.node_id,
            ALGO_ED25519,
            &f.doc.identity_keys[0].pubkey,
            &f.doc.identity_keys[0].device_id,
            f.doc.identity_keys[0].valid_from_unix,
            f.doc.identity_keys[0].valid_until_unix,
        );
        f.doc.identity_keys[0].master_sig = f.master_sk.sign(&cert_msg).to_bytes().to_vec();
        let ss = f._sub_sk.clone();
        resign_document(&ss, &mut f.doc);
        let err = verify_identity_document(&f.doc, f.now_unix_secs).unwrap_err();
        assert!(
            matches!(err, VerifyError::KeyNotYetValid { idx: 0, .. }),
            "{err:?}"
        );
    }

    // ── verify_identity_proof — audit lower-bound + freshness ─

    /// Build a minimal IdentityProof structure with correct node_id / device_id
    /// bindings (so the verifier reaches the time-validity checks before
    /// failing on hash mismatch). Signatures are blank — sufficient for
    /// tests that intentionally trigger early-reject paths (steps 4' / 4'').
    fn build_proof_skeleton(now: u64) -> IdentityProof {
        use ed25519_dalek::SigningKey;
        let master_sk = SigningKey::from_bytes(&[0xA1u8; 32]);
        let master_pk = master_sk.verifying_key();
        let node_id = compute_node_id(master_pk.as_bytes());

        let sub_sk = SigningKey::from_bytes(&[0xB2u8; 32]);
        let sub_pk = sub_sk.verifying_key();
        let device_id = compute_node_id(sub_pk.as_bytes());

        IdentityProof {
            node_id,
            master_algo: ALGO_ED25519,
            master_pubkey: master_pk.as_bytes().to_vec(),
            identity_algo: ALGO_ED25519,
            identity_pubkey: sub_pk.as_bytes().to_vec(),
            device_id,
            key_valid_from_unix: now - 60,
            key_valid_until_unix: now + 7 * 24 * 3600,
            master_sig: vec![0u8; 64],
            proof_valid_until_unix: now + 600,
            freshness_hour: (now / 3600) as u32,
            ephemeral_x25519_pk: [0u8; 32],
            ephemeral_sig: vec![0u8; 64],
        }
    }

    /// Pre-fix a proof with `key_valid_from_unix` 1 day in the future would
    /// silently pass (since only `valid_until` was checked). Post-fix
    /// reject with `KeyNotYetValid` BEFORE the master-sig verification —
    /// proven by reaching this error variant rather than `MasterCertInvalid`
    /// (signatures are dummy bytes).
    #[test]
    fn proof_rejects_future_dated_delegation() {
        let now = 1_700_000_000u64;
        let mut proof = build_proof_skeleton(now);
        proof.key_valid_from_unix = now + 86_400; // +1 day
        let err = verify_identity_proof(&proof, now).unwrap_err();
        assert!(
            matches!(err, ProofVerifyError::KeyNotYetValid { .. }),
            "{err:?}"
        );
    }

    /// `freshness_hour` declares a value 5 hours in the past — past the
    /// ±FRESHNESS_HOUR_SKEW = 1 window — so the verifier must reject.
    /// Confirms the wire field is no longer ignored.
    #[test]
    fn proof_rejects_freshness_hour_skew() {
        let now = 1_700_000_000u64;
        let mut proof = build_proof_skeleton(now);
        // 5 hours in the past — well outside ±1.
        proof.freshness_hour = ((now / 3600) - 5) as u32;
        let err = verify_identity_proof(&proof, now).unwrap_err();
        assert!(
            matches!(err, ProofVerifyError::FreshnessHourSkew { .. }),
            "{err:?}"
        );
    }

    /// Boundary: `freshness_hour` exactly 1 hour in the past ⇒ within
    /// FRESHNESS_HOUR_SKEW → must reach signature-verification (and thus
    /// fail with `MasterCertInvalid` since dummy sigs). This proves the
    /// freshness check itself does not over-reject.
    #[test]
    fn proof_freshness_hour_within_skew_reaches_sig_check() {
        let now = 1_700_000_000u64;
        let mut proof = build_proof_skeleton(now);
        proof.freshness_hour = ((now / 3600) - 1) as u32; // exactly at the bound
        let err = verify_identity_proof(&proof, now).unwrap_err();
        // Freshness check passed → reaches master cert step → fails on dummy sig.
        assert!(
            matches!(err, ProofVerifyError::MasterCertInvalid),
            "{err:?}"
        );
    }
}
