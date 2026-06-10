//! Sovereign-identity creation flow.
//!
//! One-stop composition of every primitive needed to spin up a
//! fresh sovereign identity:
//!
//! 1. Generate a 32-byte `master_seed` (optionally mixed with
//!    caller-supplied extra entropy).
//! 2. Encode to the 24-word BIP-39 phrase — returned
//!    to the caller so the CLI / app layer displays it to the
//!    operator for paper backup.
//! 3. Derive `master_sk` (HKDF-SHA256).
//! 4. Compute the stable `node_id` (length-prefixed BLAKE3).
//! 5. Generate the first instance's Ed25519 `identity_sk`.
//! 6. Build an `IdentityKey` certified by `master_sk`.
//! 7. Build + sign a freshness certificate for the document.
//! 8. Mine the document-level PoW (rainbow-table guard via
//!    `freshness_hour`).
//! 9. Sign the document with the new `identity_sk`.
//! 10. Load-or-init a `LocalInstance` id.
//! 11. Optionally save the master seed to an Argon2id-encrypted
//!     file.
//!
//! The function does NOT publish to the DHT — that is a runtime
//! concern handled by the dispatcher once wires up
//! InstanceRegistry + IdentityDocument publish. Callers receive
//! the built `IdentityDocument` and can publish it themselves.
//!
//! ## Invariants the caller can rely on
//!
//! The returned `document` passes [`verify_identity_document`]
//! against an empty cache at `issued_at_unix`.
//! The returned phrase round-trips through
//! [`decode_master_seed_from_phrase`] and reproduces the same
//! `master_sk`.
//! `document.identity_keys[0].device_id == BLAKE3(identity_pubkey)`
//!
//!
//! [`verify_identity_document`]: crate::verify::verify_identity_document
//! [`decode_master_seed_from_phrase`]: super::master_seed::decode_master_seed_from_phrase

use std::path::{Path, PathBuf};

use bip39::Mnemonic;
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use veil_util::sensitive_bytes::SensitiveBytesN;
use zeroize::Zeroizing;

use super::instance::{LocalInstance, default_instance_path};
use super::master_file::{save_master_seed_encrypted, save_master_seed_encrypted_with};
use super::master_seed::{
    MASTER_SEED_LEN, encode_master_seed_to_phrase, generate_master_seed,
    generate_master_seed_with_extra_entropy,
};
use veil_crypto::identity::{
    certify_message as build_certify, compute_node_id, derive_master_sk_ed25519,
};
// `DELEGATION_VALIDITY_SECS` referenced only from #[cfg(test)] paths
// in this file; cfg-gating the import avoids unused-import warning in
// non-test builds while keeping it available for tests.
#[cfg(test)]
use veil_proto::identity_document::DELEGATION_VALIDITY_SECS;
use veil_proto::identity_document::{
    ALGO_ED25519, ALGO_ED25519_FALCON512_HYBRID, ALGO_ED25519_FALCON1024_HYBRID, ALGO_FALCON512,
    DOC_SIG_CONTEXT, IdentityDocument, IdentityKey, MAX_FRESHNESS_WINDOW_SECS,
};

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum CreateIdentityError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("master seed: {0}")]
    MasterSeed(#[from] super::master_seed::MasterSeedError),
    #[error("master file: {0}")]
    MasterFile(#[from] super::master_file::MasterFileError),
    #[error("instance state: {0}")]
    InstanceFile(#[from] super::instance::InstanceFileError),
    #[error(
        "valid_until_unix - issued_at_unix = {secs}s exceeds \
         MAX_FRESHNESS_WINDOW_SECS ({MAX_FRESHNESS_WINDOW_SECS}s)"
    )]
    FreshnessWindowTooLong { secs: u64 },
    #[error("internal: {0}")]
    Internal(String),
}

// ── Inputs ───────────────────────────────────────────────────────────────────

/// Options controlling a `create_identity` call.
#[derive(Debug, Clone)]
pub struct CreateIdentityOptions {
    /// Directory that holds per-identity state
    /// (`~/.config/veil` in production; a `tempfile`-style
    /// directory in tests). Created if missing.
    pub veil_dir: PathBuf,

    /// If `Some(password)`, additionally write an encrypted master
    /// file alongside the BIP-39 paper backup. The encryption
    /// params default to spec-production (64 MiB Argon2id).
    pub save_encrypted_with_password: Option<Vec<u8>>,

    /// If `Some`, override the Argon2id KDF cost — intended for
    /// tests that would otherwise spend seconds on each call.
    /// `(m_cost_kib, t_cost, p_cost)`.
    pub argon2_params_override: Option<(u32, u32, u32)>,

    /// If `Some`, mix this byte string into the RNG draw
    ///. Must be ≥ 32 bytes.
    pub extra_entropy: Option<Vec<u8>>,

    /// Human-readable label for this first instance (e.g.
    /// `"laptop"`). Persisted in the `instance_id` file.
    pub instance_label: String,

    /// Minimum leading-zero bits a future PoW component would have
    /// to satisfy. Retained for API stability and CLI plumbing —
    /// dropped the document-level PoW, so this value is
    /// currently unused by `create_identity`.
    pub pow_difficulty: u32,

    /// Unix seconds at which the document is considered issued.
    /// Typically `now`; pinning it lets tests be deterministic.
    pub issued_at_unix: u64,

    /// Unix seconds past which the document is stale and will be
    /// rejected by verifiers. Must satisfy
    /// `valid_until_unix − issued_at_unix ≤ MAX_FRESHNESS_WINDOW_SECS`.
    pub valid_until_unix: u64,

    /// master-key algorithm. `Ed25519` (default) keeps the
    /// classical-only flow; `Ed25519Falcon512Hybrid` produces a hybrid
    /// master with both classical (Ed25519, BIP-39 recoverable) and
    /// post-quantum (Falcon-512, persisted to `master_falcon.bin` because
    /// Falcon is NOT BIP-39 recoverable) components. `Falcon512`
    /// standalone is rejected here — too brittle (loss of the on-disk
    /// SK = total identity loss with no paper backup). Operators
    /// choosing PQ should use Hybrid.
    ///
    /// **Recovery semantics for Hybrid:** restore from BIP-39 alone
    /// recovers the Ed25519 component of the master. The Falcon
    /// component requires the on-disk `master_falcon.bin` file to be
    /// preserved alongside the BIP-39 paper backup — losing the file
    /// degrades the identity to Ed25519-only. Operators MUST be
    /// explicitly instructed of this trade-off at the CLI surface.
    pub algo: veil_types::SignatureAlgorithm,
}

// ── Outputs ──────────────────────────────────────────────────────────────────

/// Result of a successful `create_identity` call.
#[derive(Debug)]
pub struct CreateIdentityOutput {
    /// Stable 32-byte identity address (BLAKE3 over master_pk).
    pub node_id: [u8; 32],
    /// 24-word BIP-39 phrase. **The caller MUST display this to
    /// the operator once and then drop the value**; paper backup is
    /// the only true recovery channel.
    pub master_seed_phrase: Mnemonic,
    /// Raw 32-byte master_seed (also wrapped in Zeroizing). The
    /// caller typically discards this immediately after saving the
    /// encrypted file or collecting the BIP-39 phrase.
    pub master_seed: Zeroizing<[u8; MASTER_SEED_LEN]>,
    /// The freshly-signed, PoW-mined IdentityDocument ready for
    /// DHT publication.
    pub document: IdentityDocument,
    /// Local instance state (id + label) persisted under
    /// `veil_dir/instance_id`.
    pub instance: LocalInstance,
    /// Absolute path to the identity secret-key file (not written
    /// by this function — caller handles identity_sk storage per
    /// their policy). Populated for convenience.
    pub identity_sk_path: PathBuf,
    /// Absolute path to the encrypted master file, if one was
    /// written.
    pub encrypted_master_path: Option<PathBuf>,
    /// The raw identity signing key seed for this instance. The
    /// caller is responsible for persisting this however they
    /// choose (plain TOML, encrypted file, hardware token…).
    ///
    /// Phase 6 slice 6i — backed by `SensitiveBytesN<32>` (mlocked when
    /// `RLIMIT_MEMLOCK` permits, zeroize-on-drop fallback otherwise).
    /// Consumers that need a `[u8; 32]` for downstream APIs (e.g.
    /// `IdentitySigningKey::from_ed25519_seed`) use `.as_array()` to
    /// borrow a typed view; the value moves into the receiver via a
    /// brief stack copy.
    pub identity_sk_seed: SensitiveBytesN<32>,
    /// present only when `opts.algo ==
    /// Ed25519Falcon512Hybrid`. Path to `master_falcon.bin` (mode
    /// `0o600`) holding the post-quantum half of the master key —
    /// the BIP-39 phrase recovers ONLY the Ed25519 half; this file
    /// is the sole copy of the Falcon SK. Operators MUST back this
    /// up alongside (or as well as) the BIP-39 paper backup. `None`
    /// for the classical Ed25519 path.
    pub master_falcon_path: Option<PathBuf>,
}

// ── Main flow ────────────────────────────────────────────────────────────────

/// Create a complete, signed, PoW-mined sovereign identity.
///
/// Composable end-to-end: consumes every library primitive from
/// (master storage → crypto → proto → instance state →
/// verifier). Production callers (the CLI `identity create`
/// flow, or an app SDK's first-run setup) typically follow the
/// shape:
///
/// ```ignore
/// use veilcore::cfg::sovereign_flow::{create_identity, CreateIdentityOptions};
/// let out = create_identity(CreateIdentityOptions {
/// veil_dir: dirs::config_dir.unwrap.join("veil")
/// save_encrypted_with_password: Some(prompt_password.into_bytes)
/// argon2_params_override: None
/// extra_entropy: None
/// instance_label: "laptop".into
/// pow_difficulty: 0
/// issued_at_unix: now_unix
/// valid_until_unix: now_unix + 7 * 86_400
/// })?;
/// println!("Identity: {}", hex::encode(out.node_id));
/// println!("BIP-39 phrase:");
/// for word in out.master_seed_phrase.words {
/// println!(" {word}");
/// }
/// ```
pub fn create_identity(
    opts: CreateIdentityOptions,
) -> Result<CreateIdentityOutput, CreateIdentityError> {
    // 0. Validate inputs.
    let window = opts.valid_until_unix.saturating_sub(opts.issued_at_unix);
    if window == 0 || window > MAX_FRESHNESS_WINDOW_SECS {
        return Err(CreateIdentityError::FreshnessWindowTooLong { secs: window });
    }

    // all three algos accepted at the library boundary.
    // Standalone Falcon-512 has NO BIP-39 paper-backup path — operator
    // safety is enforced at the CLI layer (`--accept-no-recovery`
    // gate); library callers are trusted to know what they're doing.
    use veil_types::SignatureAlgorithm;

    std::fs::create_dir_all(&opts.veil_dir)?;

    // 1. Generate master_seed.
    let master_seed = match &opts.extra_entropy {
        Some(bytes) => generate_master_seed_with_extra_entropy(bytes)?,
        None => generate_master_seed(),
    };

    // 2. BIP-39 encode (for caller to display as paper backup).
    let phrase = encode_master_seed_to_phrase(&master_seed)?;

    // 3. Derive Ed25519 master_sk from the BIP-39 seed. In the hybrid
    // branch this is just the classical half — the Falcon half is
    // generated fresh from OsRng at step 3b below (Falcon is not
    // BIP-39 recoverable; the operator-side mitigation is the
    // `master_falcon.bin` file).
    let master_sk_bytes = derive_master_sk_ed25519(&master_seed);
    let master_sk = SigningKey::from_bytes(&master_sk_bytes);
    let master_ed_pk = master_sk.verifying_key();

    // 3b. Hybrid: generate Falcon-512 master keypair + compose the
    // canonical hybrid pk/sk wire encodings (see
    // veil-crypto::signature::generate_keypair for the layout
    // reference: pk = ed_pk(32) || falcon_pk(897) = 929 B; sk =
    // ed_sk(32) || u16-LE falcon_sk_len || falcon_sk). We do NOT
    // call generate_keypair here because we need the Ed25519
    // half to come from the BIP-39 seed, not OsRng.
    let (
        master_algo_byte,
        master_pubkey_bytes,
        master_pk_b64,
        master_sk_b64,
        falcon_master_sk_bytes,
    ) = match opts.algo {
        SignatureAlgorithm::Ed25519 => (
            ALGO_ED25519,
            master_ed_pk.as_bytes().to_vec(),
            String::new(),
            String::new(),
            None,
        ),
        SignatureAlgorithm::Ed25519Falcon512Hybrid => {
            use base64::Engine as _;
            use pqcrypto_falcon::falcon512;
            use pqcrypto_traits::sign::PublicKey as _;
            use pqcrypto_traits::sign::SecretKey as _;

            let (fal_pk, fal_sk) = falcon512::keypair();
            let fal_pk_bytes = fal_pk.as_bytes();
            let fal_sk_bytes = fal_sk.as_bytes();
            if fal_pk_bytes.len() != 897 {
                return Err(CreateIdentityError::Internal(format!(
                    "hybrid create: Falcon-512 pubkey size invariant \
                     changed (expected 897, got {})",
                    fal_pk_bytes.len()
                )));
            }

            let mut pk = Vec::with_capacity(32 + 897);
            pk.extend_from_slice(master_ed_pk.as_bytes());
            pk.extend_from_slice(fal_pk_bytes);

            // audit cycle-9: the assembled master SK (Ed25519 half + Falcon SK)
            // must be zeroized on drop — it does not escape this scope (only the
            // base64 `sk_b64` derived from it does).
            let mut sk = zeroize::Zeroizing::new(Vec::with_capacity(32 + 2 + fal_sk_bytes.len()));
            sk.extend_from_slice(&master_sk_bytes[..]);
            sk.extend_from_slice(&(fal_sk_bytes.len() as u16).to_le_bytes());
            sk.extend_from_slice(fal_sk_bytes);

            let pk_b64 = base64::engine::general_purpose::STANDARD.encode(&pk);
            let sk_b64 = base64::engine::general_purpose::STANDARD.encode(&sk[..]);

            (
                ALGO_ED25519_FALCON512_HYBRID,
                pk,
                pk_b64,
                sk_b64,
                Some(fal_sk_bytes.to_vec()),
            )
        }
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => {
            // Phase 10 follow-up: Falcon-1024 hybrid master.  Mirrors
            // the Falcon-512 hybrid path exactly with the larger Falcon
            // suite (1793 B pk vs 897 B, ~2305 B sk vs ~1281 B).
            // BIP-39 phrase recovers ONLY the Ed25519 half; the
            // Falcon-1024 SK lives in `master_falcon.bin` (same file
            // name as Falcon-512 hybrid — disambiguated by the
            // surrounding `master_algo` byte in the IdentityDocument).
            use base64::Engine as _;
            use pqcrypto_falcon::falcon1024;
            use pqcrypto_traits::sign::PublicKey as _;
            use pqcrypto_traits::sign::SecretKey as _;

            let (fal_pk, fal_sk) = falcon1024::keypair();
            let fal_pk_bytes = fal_pk.as_bytes();
            let fal_sk_bytes = fal_sk.as_bytes();
            // Falcon-1024 pubkey size invariant — pqcrypto-falcon 0.4
            // pins this to 1793 bytes across all backends (CLEAN /
            // AVX2 / AArch64).  Panic-on-regression matches the
            // 512-hybrid pattern: silently-misshapen pk layouts would
            // produce nodes that cannot interop with the rest of the network.
            if fal_pk_bytes.len() != 1793 {
                return Err(CreateIdentityError::Internal(format!(
                    "hybrid-1024 create: Falcon-1024 pubkey size invariant \
                     changed (expected 1793, got {})",
                    fal_pk_bytes.len()
                )));
            }

            let mut pk = Vec::with_capacity(32 + 1793);
            pk.extend_from_slice(master_ed_pk.as_bytes());
            pk.extend_from_slice(fal_pk_bytes);

            // audit cycle-9: the assembled master SK (Ed25519 half + Falcon SK)
            // must be zeroized on drop — it does not escape this scope (only the
            // base64 `sk_b64` derived from it does).
            let mut sk = zeroize::Zeroizing::new(Vec::with_capacity(32 + 2 + fal_sk_bytes.len()));
            sk.extend_from_slice(&master_sk_bytes[..]);
            sk.extend_from_slice(&(fal_sk_bytes.len() as u16).to_le_bytes());
            sk.extend_from_slice(fal_sk_bytes);

            let pk_b64 = base64::engine::general_purpose::STANDARD.encode(&pk);
            let sk_b64 = base64::engine::general_purpose::STANDARD.encode(&sk[..]);

            (
                ALGO_ED25519_FALCON1024_HYBRID,
                pk,
                pk_b64,
                sk_b64,
                Some(fal_sk_bytes.to_vec()),
            )
        }
        SignatureAlgorithm::Falcon512 => {
            // ext: standalone Falcon-512 master. No BIP-39
            // recovery — the master SK is OsRng-derived and `master_seed`
            // plus its 24-word phrase remain populated on the output
            // struct purely for API uniformity, but they DO NOT recover
            // anything. The SOLE recovery medium is `master_falcon.bin`.
            //
            // CLI gates this with `--accept-no-recovery`; library callers
            // are responsible for their own safety.
            use base64::Engine as _;
            use pqcrypto_falcon::falcon512;
            use pqcrypto_traits::sign::PublicKey as _;
            use pqcrypto_traits::sign::SecretKey as _;

            let (fal_pk, fal_sk) = falcon512::keypair();
            let fal_pk_bytes = fal_pk.as_bytes();
            let fal_sk_bytes = fal_sk.as_bytes();
            if fal_pk_bytes.len() != 897 {
                return Err(CreateIdentityError::Internal(format!(
                    "falcon512 create: pubkey size invariant changed \
                     (expected 897, got {})",
                    fal_pk_bytes.len()
                )));
            }

            let pk_bytes = fal_pk_bytes.to_vec();
            let sk_bytes = fal_sk_bytes.to_vec();
            let pk_b64 = base64::engine::general_purpose::STANDARD.encode(&pk_bytes);
            let sk_b64 = base64::engine::general_purpose::STANDARD.encode(&sk_bytes);

            (ALGO_FALCON512, pk_bytes, pk_b64, sk_b64, Some(sk_bytes))
        }
    };

    // 4. Compute node_id (stable, master-pk-derived; for hybrid this
    // is BLAKE3 over the 929 B hybrid pk so a hybrid identity has a
    // distinct node_id from any Ed25519-only identity that shared
    // the same BIP-39 phrase).
    let node_id = compute_node_id(&master_pubkey_bytes);

    // 5. Load or generate the local instance_id + label.
    let instance_path = default_instance_path(&opts.veil_dir);
    let instance = LocalInstance::load_or_init(&instance_path, &opts.instance_label)?;

    // 6. Generate the first instance's Ed25519 identity_sk. The
    // per-device subkey stays Ed25519 even in hybrid mode — fast
    // sign/verify for the hot path, hybrid PQ protection lives at
    // the master layer (cert_sig is hybrid; rotation re-issues
    // cert_sig under hybrid master).
    //
    // Phase 6 slice 6i — fill the seed bytes inside `SensitiveBytesN<32>`
    // so the entropy material lives in mlocked storage (or the zeroize-
    // only fallback) from the moment OsRng returns.
    let mut identity_sk_seed: SensitiveBytesN<32> = SensitiveBytesN::new();
    OsRng.fill_bytes(identity_sk_seed.as_mut_array());
    let identity_sk = SigningKey::from_bytes(identity_sk_seed.as_array());
    let identity_pk = identity_sk.verifying_key();

    // 7. Master certifies the identity subkey. : device_id is
    // deterministic from the subkey pubkey; the per-key delegation
    // inherits the document's `valid_until_unix` (or the 7-day
    // default, whichever is sooner) and the master re-issues at
    // half-validity via the maintenance loop.
    let device_id = compute_node_id(identity_pk.as_bytes());
    let key_valid_until = opts.valid_until_unix;
    let cert_msg = build_certify(
        &node_id,
        ALGO_ED25519,
        identity_pk.as_bytes(),
        &device_id,
        opts.issued_at_unix,
        key_valid_until,
    );
    let cert_sig_bytes: Vec<u8> = match opts.algo {
        SignatureAlgorithm::Ed25519 => master_sk.sign(&cert_msg).to_bytes().to_vec(),
        SignatureAlgorithm::Ed25519Falcon512Hybrid => veil_crypto::sign_message(
            SignatureAlgorithm::Ed25519Falcon512Hybrid,
            &master_pk_b64,
            &master_sk_b64,
            &cert_msg,
        )
        .map_err(|e| CreateIdentityError::Internal(format!("hybrid cert sign: {e}")))?,
        SignatureAlgorithm::Falcon512 => veil_crypto::sign_message(
            SignatureAlgorithm::Falcon512,
            &master_pk_b64,
            &master_sk_b64,
            &cert_msg,
        )
        .map_err(|e| CreateIdentityError::Internal(format!("falcon512 cert sign: {e}")))?,
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => veil_crypto::sign_message(
            SignatureAlgorithm::Ed25519Falcon1024Hybrid,
            &master_pk_b64,
            &master_sk_b64,
            &cert_msg,
        )
        .map_err(|e| CreateIdentityError::Internal(format!("hybrid-1024 cert sign: {e}")))?,
    };

    let identity_key = IdentityKey {
        algo: ALGO_ED25519,
        pubkey: identity_pk.as_bytes().to_vec(),
        device_id,
        valid_from_unix: opts.issued_at_unix,
        valid_until_unix: key_valid_until,
        master_sig: cert_sig_bytes,
    };

    // 8. Draft the document.
    let mut doc = IdentityDocument {
        node_id,
        master_algo: master_algo_byte,
        master_pubkey: master_pubkey_bytes.clone(),
        issued_at_unix: opts.issued_at_unix,
        valid_until_unix: opts.valid_until_unix,
        sig_key_idx: 0,
        identity_keys: vec![identity_key],
        document_sig: Vec::new(),
    };

    // 9. Sign the canonical document bytes with the active
    // identity_sk (always Ed25519, fast verify in hot path).
    let mut doc_msg = Vec::with_capacity(DOC_SIG_CONTEXT.len() + 512);
    doc_msg.extend_from_slice(DOC_SIG_CONTEXT);
    doc_msg.extend_from_slice(&doc.canonical_signing_bytes());
    doc.document_sig = identity_sk.sign(&doc_msg).to_bytes().to_vec();

    // 10. Persist the signed document + device identity_sk so
    // subsequent `rotate` / `show` / runtime-bootstrap flows
    // have a canonical on-disk source of truth. File-mode
    // 0o600 on the identity_sk file.
    let doc_path = opts.veil_dir.join(IDENTITY_DOCUMENT_FILE);
    atomic_write(&doc_path, &doc.encode())?;
    save_identity_sk(&opts.veil_dir, &identity_sk_seed)?;

    // 10b. Hybrid OR standalone Falcon: persist the master Falcon
    // keypair (SK + PK) to master_falcon.bin in framed form. For
    // hybrid this file holds the PQ half (Ed25519 half is BIP-39
    // recoverable); for standalone Falcon it's the WHOLE master
    // and the only recovery medium that exists. SK + PK are
    // bundled because pqcrypto-falcon's SecretKey doesn't expose
    //.public_key.
    let master_falcon_path: Option<PathBuf> = match falcon_master_sk_bytes {
        Some(falcon_sk) => {
            // Hybrid: master_pubkey_bytes = ed_pk(32) || falcon_pk(897);
            // standalone Falcon: master_pubkey_bytes = falcon_pk(897).
            let falcon_pk: &[u8] = match opts.algo {
                SignatureAlgorithm::Ed25519Falcon512Hybrid => &master_pubkey_bytes[32..],
                SignatureAlgorithm::Ed25519Falcon1024Hybrid => &master_pubkey_bytes[32..],
                SignatureAlgorithm::Falcon512 => &master_pubkey_bytes,
                SignatureAlgorithm::Ed25519 => {
                    unreachable!("falcon_master_sk_bytes is None for Ed25519 path")
                }
            };
            save_master_falcon_keypair(&opts.veil_dir, &falcon_sk, falcon_pk)?;
            Some(opts.veil_dir.join(MASTER_FALCON_FILE))
        }
        None => None,
    };

    // 13. Optionally persist the encrypted master file.
    let encrypted_master_path = if let Some(password) = &opts.save_encrypted_with_password {
        let path = opts.veil_dir.join("master.enc");
        match opts.argon2_params_override {
            Some((m, t, p)) => {
                save_master_seed_encrypted_with(&path, &master_seed, password, m, t, p)?;
            }
            None => save_master_seed_encrypted(&path, &master_seed, password)?,
        }
        Some(path)
    } else {
        None
    };

    let identity_sk_path = opts.veil_dir.join("identity_sk.toml");

    Ok(CreateIdentityOutput {
        node_id,
        master_seed_phrase: phrase,
        master_seed,
        document: doc,
        instance,
        identity_sk_path,
        encrypted_master_path,
        identity_sk_seed,
        master_falcon_path,
    })
}

// d removed the `revoke_identity` flow entirely. Subkey
// revocation no longer exists as a first-class operation; the
// mitigation for compromise is now a short `valid_until_unix` window
// (refresh often, revoke never). Operators that need to retire a
// device drop its `IdentityKey` on the next `rotate_identity` cycle.

// ── Restore flow ────────────────────────────────────────────────

/// Options controlling a `restore_identity` call — the device
/// already has the 32-byte master seed (recovered from BIP-39 or
/// decrypted from `master.enc`) and wants to bring up a fresh
/// per-device `identity_sk` under that seed's identity.
#[derive(Debug)]
pub struct RestoreIdentityOptions {
    /// Directory where per-identity state is persisted (created
    /// if missing).
    pub veil_dir: PathBuf,

    /// Recovered master seed — same identity layer as the original
    /// `create_identity` produced.
    pub master_seed: Zeroizing<[u8; MASTER_SEED_LEN]>,

    /// If `Some`, re-save the master seed to `master.enc` under
    /// this password (typical when the recovery medium was the
    /// BIP-39 phrase and the user wants a convenience file too).
    ///
    /// Audit L-15: `Zeroizing` so the in-flight password copy is wiped on drop
    /// — the FFI `_zeroize_with_password` path moves its owned copy in here, and
    /// a plain `Vec<u8>` would otherwise leave the plaintext in freed heap.
    pub save_encrypted_with_password: Option<Zeroizing<Vec<u8>>>,

    /// Test-only override of Argon2id parameters; production
    /// leaves this `None`.
    pub argon2_params_override: Option<(u32, u32, u32)>,

    /// Human-readable label for this device's first instance on
    /// the fresh machine.
    pub instance_label: String,

    /// Retained for API stability — `restore_identity` dropped the
    /// document-level PoW, so this value is currently unused (mirrors
    /// `CreateIdentityOptions::pow_difficulty`). (audit cycle-3: the doc was
    /// misleadingly "the new document must satisfy".)
    pub pow_difficulty: u32,

    /// Now, in Unix seconds — used as `issued_at`.
    pub now_unix: u64,

    /// New document's `valid_until_unix`. Window capped at
    /// `MAX_FRESHNESS_WINDOW_SECS` (30 days).
    pub valid_until_unix: u64,

    /// master-key algorithm. `Ed25519` (default) restores
    /// the classical-only flow; `Ed25519Falcon512Hybrid` restores a
    /// hybrid identity and REQUIRES `master_falcon_sk_bytes` to be set
    /// (this is the SOLE copy of the post-quantum master half — BIP-39
    /// alone cannot recover it). Caller is expected to have read the
    /// preserved `master_falcon.bin` from a backup medium and pass its
    /// contents through. `Falcon512` standalone is rejected (mirrors
    /// `create_identity`).
    pub algo: veil_types::SignatureAlgorithm,

    /// framed Falcon-512 master keypair bundle (SK + PK)
    /// loaded from the caller's preserved `master_falcon.bin` — see
    /// [`MASTER_FALCON_FILE`] for the wire layout. Required when
    /// `algo == Ed25519Falcon512Hybrid`; ignored otherwise. Missing
    /// on a hybrid restore surfaces as `MissingFalconMaster` — the
    /// caller MUST forward that error to the operator, since silently
    /// degrading to Ed25519-only would change the node_id and lose
    /// name-claim continuity. Tests can also pass this bundle
    /// in-memory without touching disk.
    pub master_falcon_keypair_bytes: Option<Vec<u8>>,
}

/// Successful restoration result. The returned `document` is the
/// caller's **newly-minted** replacement — the previous network
/// `IdentityDocument` (if one exists on the DHT) must be republished
/// by the caller OR superseded by version-monotonicity once the
/// restored device publishes.
#[derive(Debug)]
pub struct RestoreIdentityOutput {
    /// Stable identity address (matches what `create_identity`
    /// originally produced, because the master_seed is the same).
    pub node_id: [u8; 32],
    /// Signed, PoW-mined IdentityDocument. First-key restoration
    /// returns a single-key document — any other devices'
    /// `identity_keys` entries must be recovered separately (e.g.
    /// by fetching the latest on-DHT document, merging the old
    /// subkeys, and calling `rotate_identity` on the restored
    /// device).
    pub document: IdentityDocument,
    /// Local per-device instance state (loaded-or-initialised).
    pub instance: LocalInstance,
    /// Freshly-generated device identity_sk seed. Caller persists
    /// per their key-storage policy.  Phase 6 slice 6i — backed by
    /// `SensitiveBytesN<32>` (see `CreateIdentityOutput.identity_sk_seed`
    /// for the threat-model rationale).
    pub identity_sk_seed: SensitiveBytesN<32>,
    /// Path to the optional encrypted master file written by this
    /// call. `None` if `save_encrypted_with_password` was `None`.
    pub encrypted_master_path: Option<PathBuf>,

    /// when `algo == Ed25519Falcon512Hybrid`, path to the
    /// re-saved `master_falcon.bin` (the function persists the
    /// caller-supplied Falcon SK into the new veil_dir with mode
    /// 0o600). `None` for the classical Ed25519 path.
    pub master_falcon_path: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum RestoreIdentityError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("instance state: {0}")]
    Instance(#[from] crate::instance::InstanceFileError),
    #[error("master file: {0}")]
    MasterFile(#[from] crate::master_file::MasterFileError),
    #[error(
        "valid_until_unix − now_unix = {secs}s exceeds \
         MAX_FRESHNESS_WINDOW_SECS ({MAX_FRESHNESS_WINDOW_SECS}s)"
    )]
    FreshnessWindowTooLong { secs: u64 },
    #[error(
        "hybrid restore: master_falcon_sk_bytes missing — Ed25519 half \
         can be recovered from BIP-39 alone but the Falcon-512 half \
         requires the preserved master_falcon.bin contents"
    )]
    MissingFalconMaster,
    #[error("internal: {0}")]
    Internal(String),
}

/// Restore an existing identity on a fresh device given the
/// recovered master seed. Produces a **new** device-local
/// identity_sk — the caller's on-disk state is overwritten with
/// a fresh signed document.
///
/// Typical flow (via CLI):
///
/// 1. User runs `veil-cli identity restore --phrase-file
/// words.txt` on a blank machine.
/// 2. CLI reads BIP-39 phrase → decodes to master_seed.
/// 3. This function bootstraps the device under that seed.
/// 4. User's `node_id`, name registration, reputation all
///    survive — they're anchored to `master_pubkey`, not any
///    per-device subkey.
pub fn restore_identity(
    opts: RestoreIdentityOptions,
) -> Result<RestoreIdentityOutput, RestoreIdentityError> {
    let window = opts.valid_until_unix.saturating_sub(opts.now_unix);
    if window == 0 || window > MAX_FRESHNESS_WINDOW_SECS {
        return Err(RestoreIdentityError::FreshnessWindowTooLong { secs: window });
    }

    use veil_types::SignatureAlgorithm;

    std::fs::create_dir_all(&opts.veil_dir)?;

    // Derive the Ed25519 master half (always — present in both
    // classical and hybrid paths, recoverable from BIP-39).
    // Standalone Falcon-512 doesn't use it (master_seed is informational
    // only) but we still derive for structural simplicity.
    let master_sk_bytes = derive_master_sk_ed25519(&opts.master_seed);
    let master_sk = SigningKey::from_bytes(&master_sk_bytes);
    let master_ed_pk = master_sk.verifying_key();

    // Hybrid path: rebuild the canonical 929 B hybrid pubkey + base64
    // SK encoding from the operator-supplied Falcon SK (loaded from the
    // preserved master_falcon.bin) so cert signing goes through the
    // canonical hybrid `sign_message`. Mirrors the composition in
    // `create_identity`.
    let (
        master_algo_byte,
        master_pubkey_bytes,
        master_pk_b64,
        master_sk_b64,
        falcon_master_sk_to_persist,
    ) = match opts.algo {
        SignatureAlgorithm::Ed25519 => (
            ALGO_ED25519,
            master_ed_pk.as_bytes().to_vec(),
            String::new(),
            String::new(),
            None,
        ),
        SignatureAlgorithm::Ed25519Falcon512Hybrid => {
            use base64::Engine as _;

            let bundle_bytes = opts
                .master_falcon_keypair_bytes
                .as_deref()
                .ok_or(RestoreIdentityError::MissingFalconMaster)?;
            let (falcon_sk, falcon_pk) =
                parse_master_falcon_keypair(bundle_bytes).map_err(|e| {
                    RestoreIdentityError::Internal(format!(
                        "hybrid restore: master_falcon bundle parse failed: {e}"
                    ))
                })?;
            if falcon_pk.len() != 897 {
                return Err(RestoreIdentityError::Internal(format!(
                    "hybrid restore: Falcon-512 PK length invariant changed \
                     (expected 897, got {})",
                    falcon_pk.len()
                )));
            }

            let mut pk = Vec::with_capacity(32 + 897);
            pk.extend_from_slice(master_ed_pk.as_bytes());
            pk.extend_from_slice(&falcon_pk);

            // audit cycle-9: zeroize the assembled master SK on drop (does not
            // escape this scope; only the derived base64 `sk_b64` does).
            let mut sk = zeroize::Zeroizing::new(Vec::with_capacity(32 + 2 + falcon_sk.len()));
            sk.extend_from_slice(&master_sk_bytes[..]);
            sk.extend_from_slice(&(falcon_sk.len() as u16).to_le_bytes());
            sk.extend_from_slice(&falcon_sk);

            let pk_b64 = base64::engine::general_purpose::STANDARD.encode(&pk);
            let sk_b64 = base64::engine::general_purpose::STANDARD.encode(&sk[..]);

            (
                ALGO_ED25519_FALCON512_HYBRID,
                pk,
                pk_b64,
                sk_b64,
                Some(falcon_sk),
            )
        }
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => {
            // Phase 10 follow-up: Falcon-1024 hybrid restore.  Mirrors
            // the 512-hybrid path with the larger Falcon suite.  The
            // BIP-39 phrase reconstructs the Ed25519 half; the
            // Falcon-1024 SK + PK come from a previously-backed
            // `master_falcon.bin` bundle supplied via
            // `opts.master_falcon_keypair_bytes`.
            use base64::Engine as _;

            let bundle_bytes = opts
                .master_falcon_keypair_bytes
                .as_deref()
                .ok_or(RestoreIdentityError::MissingFalconMaster)?;
            let (falcon_sk, falcon_pk) =
                parse_master_falcon_keypair(bundle_bytes).map_err(|e| {
                    RestoreIdentityError::Internal(format!(
                        "hybrid-1024 restore: master_falcon bundle parse failed: {e}"
                    ))
                })?;
            if falcon_pk.len() != 1793 {
                return Err(RestoreIdentityError::Internal(format!(
                    "hybrid-1024 restore: Falcon-1024 PK length invariant changed \
                     (expected 1793, got {})",
                    falcon_pk.len()
                )));
            }

            let mut pk = Vec::with_capacity(32 + 1793);
            pk.extend_from_slice(master_ed_pk.as_bytes());
            pk.extend_from_slice(&falcon_pk);

            // audit cycle-9: zeroize the assembled master SK on drop (does not
            // escape this scope; only the derived base64 `sk_b64` does).
            let mut sk = zeroize::Zeroizing::new(Vec::with_capacity(32 + 2 + falcon_sk.len()));
            sk.extend_from_slice(&master_sk_bytes[..]);
            sk.extend_from_slice(&(falcon_sk.len() as u16).to_le_bytes());
            sk.extend_from_slice(&falcon_sk);

            let pk_b64 = base64::engine::general_purpose::STANDARD.encode(&pk);
            let sk_b64 = base64::engine::general_purpose::STANDARD.encode(&sk[..]);

            (
                ALGO_ED25519_FALCON1024_HYBRID,
                pk,
                pk_b64,
                sk_b64,
                Some(falcon_sk),
            )
        }
        SignatureAlgorithm::Falcon512 => {
            // Standalone Falcon-512 restore: BIP-39 phrase / master_seed
            // is irrelevant — the bundle is the SOLE recovery medium.
            // Library still requires opts.master_seed to be supplied for
            // API uniformity; callers with no preserved seed pass a dummy
            // zero-seed (CLI does this when --phrase-file is omitted).
            use base64::Engine as _;

            let bundle_bytes = opts
                .master_falcon_keypair_bytes
                .as_deref()
                .ok_or(RestoreIdentityError::MissingFalconMaster)?;
            let (falcon_sk, falcon_pk) =
                parse_master_falcon_keypair(bundle_bytes).map_err(|e| {
                    RestoreIdentityError::Internal(format!(
                        "falcon512 restore: master_falcon bundle parse failed: {e}"
                    ))
                })?;
            if falcon_pk.len() != 897 {
                return Err(RestoreIdentityError::Internal(format!(
                    "falcon512 restore: Falcon-512 PK length invariant changed \
                     (expected 897, got {})",
                    falcon_pk.len()
                )));
            }

            let pk_b64 = base64::engine::general_purpose::STANDARD.encode(&falcon_pk);
            let sk_b64 = base64::engine::general_purpose::STANDARD.encode(&falcon_sk);

            (ALGO_FALCON512, falcon_pk, pk_b64, sk_b64, Some(falcon_sk))
        }
    };

    let node_id = compute_node_id(&master_pubkey_bytes);

    // Local instance (stable per-device).
    let instance_path = default_instance_path(&opts.veil_dir);
    let instance = LocalInstance::load_or_init(&instance_path, &opts.instance_label)?;

    // Fresh per-device identity_sk (always Ed25519).
    // Phase 6 slice 6i — mlocked storage from the OsRng output forward.
    let mut identity_sk_seed: SensitiveBytesN<32> = SensitiveBytesN::new();
    OsRng.fill_bytes(identity_sk_seed.as_mut_array());
    let identity_sk = SigningKey::from_bytes(identity_sk_seed.as_array());
    let identity_pk = identity_sk.verifying_key();

    // Master certifies it (deterministic device_id +
    // explicit valid_until on the delegation).
    let device_id = compute_node_id(identity_pk.as_bytes());
    let cert_msg = build_certify(
        &node_id,
        ALGO_ED25519,
        identity_pk.as_bytes(),
        &device_id,
        opts.now_unix,
        opts.valid_until_unix,
    );
    let cert_sig_bytes: Vec<u8> = match opts.algo {
        SignatureAlgorithm::Ed25519 => master_sk.sign(&cert_msg).to_bytes().to_vec(),
        SignatureAlgorithm::Ed25519Falcon512Hybrid => veil_crypto::sign_message(
            SignatureAlgorithm::Ed25519Falcon512Hybrid,
            &master_pk_b64,
            &master_sk_b64,
            &cert_msg,
        )
        .map_err(|e| RestoreIdentityError::Internal(format!("hybrid restore cert sign: {e}")))?,
        SignatureAlgorithm::Falcon512 => veil_crypto::sign_message(
            SignatureAlgorithm::Falcon512,
            &master_pk_b64,
            &master_sk_b64,
            &cert_msg,
        )
        .map_err(|e| RestoreIdentityError::Internal(format!("falcon512 restore cert sign: {e}")))?,
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => veil_crypto::sign_message(
            SignatureAlgorithm::Ed25519Falcon1024Hybrid,
            &master_pk_b64,
            &master_sk_b64,
            &cert_msg,
        )
        .map_err(|e| {
            RestoreIdentityError::Internal(format!("hybrid-1024 restore cert sign: {e}"))
        })?,
    };

    let identity_key = IdentityKey {
        algo: ALGO_ED25519,
        pubkey: identity_pk.as_bytes().to_vec(),
        device_id,
        valid_from_unix: opts.now_unix,
        valid_until_unix: opts.valid_until_unix,
        master_sig: cert_sig_bytes,
    };

    let mut doc = IdentityDocument {
        node_id,
        master_algo: master_algo_byte,
        master_pubkey: master_pubkey_bytes.clone(),
        issued_at_unix: opts.now_unix,
        valid_until_unix: opts.valid_until_unix,
        sig_key_idx: 0,
        identity_keys: vec![identity_key],
        document_sig: Vec::new(),
    };

    let mut doc_msg = Vec::with_capacity(DOC_SIG_CONTEXT.len() + 512);
    doc_msg.extend_from_slice(DOC_SIG_CONTEXT);
    doc_msg.extend_from_slice(&doc.canonical_signing_bytes());
    doc.document_sig = identity_sk.sign(&doc_msg).to_bytes().to_vec();

    let doc_path = opts.veil_dir.join(IDENTITY_DOCUMENT_FILE);
    atomic_write(&doc_path, &doc.encode())?;
    save_identity_sk(&opts.veil_dir, &identity_sk_seed)?;

    // Hybrid OR standalone Falcon: re-persist the master Falcon
    // keypair in the new veil_dir. Hybrid: PK lives at
    // master_pubkey_bytes[32..] (after the Ed25519 prefix); standalone:
    // master_pubkey_bytes IS the falcon_pk (897 B total).
    let master_falcon_path: Option<PathBuf> = match falcon_master_sk_to_persist {
        Some(falcon_sk) => {
            let falcon_pk: &[u8] = match opts.algo {
                SignatureAlgorithm::Ed25519Falcon512Hybrid => &master_pubkey_bytes[32..],
                SignatureAlgorithm::Ed25519Falcon1024Hybrid => &master_pubkey_bytes[32..],
                SignatureAlgorithm::Falcon512 => &master_pubkey_bytes,
                SignatureAlgorithm::Ed25519 => {
                    unreachable!("falcon_master_sk_to_persist is None for Ed25519 path")
                }
            };
            save_master_falcon_keypair(&opts.veil_dir, &falcon_sk, falcon_pk)?;
            Some(opts.veil_dir.join(MASTER_FALCON_FILE))
        }
        None => None,
    };

    let encrypted_master_path = if let Some(pw) = &opts.save_encrypted_with_password {
        let path = opts.veil_dir.join("master.enc");
        match opts.argon2_params_override {
            Some((m, t, p)) => {
                save_master_seed_encrypted_with(&path, &opts.master_seed, pw, m, t, p)?;
            }
            None => save_master_seed_encrypted(&path, &opts.master_seed, pw)?,
        }
        Some(path)
    } else {
        None
    };

    Ok(RestoreIdentityOutput {
        node_id,
        document: doc,
        instance,
        identity_sk_seed,
        master_falcon_path,
        encrypted_master_path,
    })
}

// ── Rotate flow ─────────────────────────────────────────────────

/// Options controlling a `rotate_identity` call.
#[derive(Debug)]
pub struct RotateIdentityOptions {
    /// Directory containing the existing identity state.
    pub veil_dir: PathBuf,

    /// 32-byte master seed the caller has already recovered
    /// (typically via BIP-39 prompt, encrypted-file decrypt, or
    /// hardware-backed unwrap). This function derives `master_sk`
    /// from it and discards the result when the rotation completes.
    pub master_seed: Zeroizing<[u8; MASTER_SEED_LEN]>,

    /// Unix seconds at rotation time.
    pub now_unix: u64,

    /// Unix seconds the new document's freshness window ends.
    /// Capped at `now_unix + MAX_FRESHNESS_WINDOW_SECS`.
    pub valid_until_unix: u64,
}

/// Result of a successful `rotate_identity` call.
#[derive(Debug)]
pub struct RotateIdentityOutput {
    /// The newly-signed, PoW-mined IdentityDocument ready for
    /// publication.
    pub document: IdentityDocument,
    /// Index in `document.identity_keys` of the new active subkey.
    pub new_identity_key_idx: u16,
    /// Index (before the rotation) of the previously-active
    /// subkey. `0` on the first rotation.
    pub old_identity_key_idx: u16,
    /// The fresh Ed25519 secret for this device — caller persists
    /// per their key-storage policy.  Phase 6 slice 6i — backed by
    /// `SensitiveBytesN<32>`.
    pub new_identity_sk_seed: SensitiveBytesN<32>,
    /// Local time of the rotation (copied from `opts.now_unix`).
    pub rotated_at_unix: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum RotateIdentityError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(
        "master_seed does not match the existing identity: computed \
         node_id {computed:?} but document carries {doc:?}"
    )]
    MasterSeedMismatch { computed: [u8; 32], doc: [u8; 32] },
    #[error("document malformed on disk: {0}")]
    DocumentMalformed(String),
    #[error("instance state: {0}")]
    Instance(#[from] crate::instance::InstanceFileError),
    #[error(
        "valid_until_unix − now_unix = {secs}s exceeds \
         MAX_FRESHNESS_WINDOW_SECS ({MAX_FRESHNESS_WINDOW_SECS}s)"
    )]
    FreshnessWindowTooLong { secs: u64 },
    #[error(
        "cannot rotate: MAX_IDENTITY_KEYS ({cap}) would be exceeded \
         (current = {current})"
    )]
    IdentityKeysFull { current: usize, cap: usize },
    #[error(
        "master_falcon.bin missing or unreadable — required to certify a new \
         subkey under a hybrid/Falcon master"
    )]
    MissingFalconMaster,
    #[error("hybrid master cert signing failed: {0}")]
    HybridCertSign(String),
    #[error("rotation not supported for master algo byte {0}")]
    UnsupportedMasterAlgo(u8),
}

/// Rotate the device's active `identity_sk` on an existing
/// sovereign identity. See module doc for the full step list;
/// succeeds only if the supplied `master_seed` matches the
/// identity recorded in `veil_dir/identity_document.bin`.
///
/// The rotation is **additive**: a fresh subkey is appended
/// `sig_key_idx` advances to it, old subkey stays valid until its
/// natural expiry. dropped the `revoke_current` flag
/// alongside the in-band revocation flow.
///
/// This helper does NOT publish the updated document — caller is
/// responsible for the DHT put. It DOES persist the new signed
/// document to `veil_dir/identity_document.bin` atomically.
pub fn rotate_identity(
    opts: RotateIdentityOptions,
) -> Result<RotateIdentityOutput, RotateIdentityError> {
    use veil_proto::identity_document::MAX_IDENTITY_KEYS;
    use veil_types::SignatureAlgorithm;

    // 0. Validate freshness window.
    let window = opts.valid_until_unix.saturating_sub(opts.now_unix);
    if window == 0 || window > MAX_FRESHNESS_WINDOW_SECS {
        return Err(RotateIdentityError::FreshnessWindowTooLong { secs: window });
    }

    // 1. Load existing document + instance.
    let doc_path = opts.veil_dir.join(IDENTITY_DOCUMENT_FILE);
    let doc_bytes = std::fs::read(&doc_path)?;
    let mut doc = IdentityDocument::decode(&doc_bytes)
        .map_err(|e| RotateIdentityError::DocumentMalformed(e.to_string()))?;

    // The on-disk LocalInstance is still kept for backwards-compat
    // routing, but derives `device_id` deterministically
    // from the new subkey pubkey rather than reading an instance
    // tag from disk. We still need to ensure the file exists so
    // subsequent `load_from_dir` calls succeed.
    let instance_path = default_instance_path(&opts.veil_dir);
    let _instance = LocalInstance::load(&instance_path)?;

    // 2. Verify master_seed matches AND reconstruct the master key material
    //    needed to certify the new subkey.
    //
    //    The BIP-39 master_seed yields only the Ed25519 half.  For a hybrid
    //    identity the node_id binds the FULL master pubkey (ed_pk||falcon_pk)
    //    and the subkey cert must carry a HYBRID signature (mirroring
    //    create_identity).  The previous implementation derived only the
    //    Ed25519 half and signed the cert Ed25519-only, which broke hybrid
    //    rotation two ways: compute_node_id(ed_pk) never equals doc.node_id
    //    for a hybrid doc (every hybrid rotate failed MasterSeedMismatch
    //    before signing), and even past that the Ed25519-only cert would fail
    //    hybrid verification.  Reload the Falcon master half from
    //    master_falcon.bin (persisted by create/restore in veil_dir) and
    //    rebuild the exact pk/sk framing the hybrid signer expects.
    let master_ed_sk_bytes = derive_master_sk_ed25519(&opts.master_seed);
    let master_ed_sk = SigningKey::from_bytes(&master_ed_sk_bytes);
    let master_ed_pk = master_ed_sk.verifying_key();

    let (master_algo, master_pubkey_bytes, master_pk_b64, master_sk_b64) = match doc.master_algo {
        ALGO_ED25519 => (
            SignatureAlgorithm::Ed25519,
            master_ed_pk.as_bytes().to_vec(),
            String::new(),
            String::new(),
        ),
        ALGO_ED25519_FALCON512_HYBRID | ALGO_ED25519_FALCON1024_HYBRID => {
            use base64::Engine as _;
            let (algo, expected_falcon_pk_len) = if doc.master_algo == ALGO_ED25519_FALCON512_HYBRID
            {
                (SignatureAlgorithm::Ed25519Falcon512Hybrid, 897usize)
            } else {
                (SignatureAlgorithm::Ed25519Falcon1024Hybrid, 1793usize)
            };
            let (falcon_sk, falcon_pk) = load_master_falcon_keypair(&opts.veil_dir)
                .map_err(|_| RotateIdentityError::MissingFalconMaster)?;
            if falcon_pk.len() != expected_falcon_pk_len {
                return Err(RotateIdentityError::DocumentMalformed(format!(
                    "master_falcon.bin Falcon PK length {} != expected {expected_falcon_pk_len} \
                     for master algo {}",
                    falcon_pk.len(),
                    doc.master_algo
                )));
            }
            // pk = ed_pk(32) || falcon_pk; sk = ed_sk(32) || u16-LE len || falcon_sk
            // (identical framing to create_identity / restore_identity).
            let mut pk = Vec::with_capacity(32 + falcon_pk.len());
            pk.extend_from_slice(master_ed_pk.as_bytes());
            pk.extend_from_slice(&falcon_pk);
            // audit cycle-9: zeroize the assembled master SK on drop (does not
            // escape this scope; only the derived base64 `sk_b64` does).
            let mut sk = zeroize::Zeroizing::new(Vec::with_capacity(32 + 2 + falcon_sk.len()));
            sk.extend_from_slice(&master_ed_sk_bytes[..]);
            sk.extend_from_slice(&(falcon_sk.len() as u16).to_le_bytes());
            sk.extend_from_slice(&falcon_sk);
            let pk_b64 = base64::engine::general_purpose::STANDARD.encode(&pk);
            let sk_b64 = base64::engine::general_purpose::STANDARD.encode(&sk[..]);
            (algo, pk, pk_b64, sk_b64)
        }
        other => return Err(RotateIdentityError::UnsupportedMasterAlgo(other)),
    };

    let computed_id = compute_node_id(&master_pubkey_bytes);
    if computed_id != doc.node_id {
        return Err(RotateIdentityError::MasterSeedMismatch {
            computed: computed_id,
            doc: doc.node_id,
        });
    }

    // 3. Cap check.
    if doc.identity_keys.len() >= MAX_IDENTITY_KEYS {
        return Err(RotateIdentityError::IdentityKeysFull {
            current: doc.identity_keys.len(),
            cap: MAX_IDENTITY_KEYS,
        });
    }

    let old_identity_key_idx = doc.sig_key_idx;

    // 4. Generate fresh identity_sk for this device.
    // Phase 6 slice 6i — fresh entropy lands in mlocked storage.
    let mut new_sk_seed: SensitiveBytesN<32> = SensitiveBytesN::new();
    OsRng.fill_bytes(new_sk_seed.as_mut_array());
    let new_identity_sk = SigningKey::from_bytes(new_sk_seed.as_array());
    let new_identity_pk = new_identity_sk.verifying_key();

    // 5. Master certifies the new subkey. : deterministic
    // device_id from the new pubkey + per-key valid_until window.
    let new_device_id = compute_node_id(new_identity_pk.as_bytes());
    let cert_msg = build_certify(
        &doc.node_id,
        ALGO_ED25519,
        new_identity_pk.as_bytes(),
        &new_device_id,
        opts.now_unix,
        opts.valid_until_unix,
    );
    // Certify the new subkey with the master keypair.  Hybrid masters MUST
    // produce a hybrid signature (both Ed25519 and Falcon halves), matching
    // what create_identity emits and what the verifier expects given
    // doc.master_algo — an Ed25519-only cert here would fail hybrid verify.
    let cert_sig_bytes: Vec<u8> = match master_algo {
        SignatureAlgorithm::Ed25519 => master_ed_sk.sign(&cert_msg).to_bytes().to_vec(),
        SignatureAlgorithm::Ed25519Falcon512Hybrid
        | SignatureAlgorithm::Ed25519Falcon1024Hybrid => {
            veil_crypto::sign_message(master_algo, &master_pk_b64, &master_sk_b64, &cert_msg)
                .map_err(|e| RotateIdentityError::HybridCertSign(e.to_string()))?
        }
        // master_algo is constrained to the three arms above by the match on
        // doc.master_algo; standalone Falcon-512 never reaches rotation.
        SignatureAlgorithm::Falcon512 => {
            return Err(RotateIdentityError::UnsupportedMasterAlgo(doc.master_algo));
        }
    };
    doc.identity_keys.push(IdentityKey {
        algo: ALGO_ED25519,
        pubkey: new_identity_pk.as_bytes().to_vec(),
        device_id: new_device_id,
        valid_from_unix: opts.now_unix,
        valid_until_unix: opts.valid_until_unix,
        master_sig: cert_sig_bytes,
    });
    let new_identity_key_idx = (doc.identity_keys.len() - 1) as u16;

    // 6. Bump document-level fields.
    doc.issued_at_unix = opts.now_unix;
    doc.valid_until_unix = opts.valid_until_unix;
    doc.sig_key_idx = new_identity_key_idx;

    // 7. Sign document with the new identity_sk.
    let mut doc_msg = Vec::with_capacity(DOC_SIG_CONTEXT.len() + 512);
    doc_msg.extend_from_slice(DOC_SIG_CONTEXT);
    doc_msg.extend_from_slice(&doc.canonical_signing_bytes());
    doc.document_sig = new_identity_sk.sign(&doc_msg).to_bytes().to_vec();

    // 8. Persist atomically + save new device identity_sk.
    atomic_write(&doc_path, &doc.encode())?;
    save_identity_sk(&opts.veil_dir, &new_sk_seed).map_err(RotateIdentityError::Io)?;

    Ok(RotateIdentityOutput {
        document: doc,
        new_identity_key_idx,
        old_identity_key_idx,
        new_identity_sk_seed: new_sk_seed,
        rotated_at_unix: opts.now_unix,
    })
}

// ── Standalone-mode flow ────────────────────────────────────────

/// Build a degenerate ("standalone") `IdentityDocument` from a single
/// device keypair. In standalone mode the device IS the master:
/// `master_pubkey == device_pubkey`, `node_id == device_id ==
/// BLAKE3(device_pubkey)`, and the lone `IdentityKey` carries a
/// self-signed delegation.
///
/// This is the default UX for single-device users (phone-only
/// laptop-only) — no master-key ceremony, no BIP-39 phrase, no
/// `master.enc` file. The caller supplies the device signing key
/// (typically the same Ed25519 keypair the runtime uses for the
/// session-layer handshake from `[identity]` config); the helper
/// builds the cert + signs the document.
///
/// The rest of the runtime sees a normal `IdentityDocument` and does
/// not branch on standalone-ness — verifier, dispatcher, mesh, DHT
/// republish all work unchanged. Only the bootstrap path knows
/// whether to build the degenerate doc or load a real one from disk.
///
/// Wire format is unchanged. An external observer cannot tell a
/// standalone document from a multi-device document with one key;
/// the `master_pubkey == identity_keys[0].pubkey` equivalence is
/// the only structural signal, and that holds for any single-device
/// identity right after `create_identity`.
///
/// Returns the built document — caller is responsible for atomically
/// writing it to `<veil_dir>/identity_document.bin` (typically
/// [`save_standalone_identity_to_dir`]).
pub fn build_standalone_identity_document(
    device_sk_seed: &SensitiveBytesN<32>,
    issued_at_unix: u64,
    valid_until_unix: u64,
) -> Result<IdentityDocument, CreateIdentityError> {
    let window = valid_until_unix.saturating_sub(issued_at_unix);
    if window == 0 || window > MAX_FRESHNESS_WINDOW_SECS {
        return Err(CreateIdentityError::FreshnessWindowTooLong { secs: window });
    }

    let device_sk = SigningKey::from_bytes(device_sk_seed.as_array());
    let device_pk = device_sk.verifying_key();
    let node_id = compute_node_id(device_pk.as_bytes());
    let device_id = node_id; // standalone: master == device, so device_id == node_id

    // Self-signed delegation: master_sk == device_sk, so the cert is
    // produced and verified with the same key. Verifier ladder
    // doesn't care whether master_pk and identity_pk happen to be
    // the same byte sequence — step 4c just checks the cert sig
    // verifies against `master_pubkey`, which it does.
    let cert_msg = build_certify(
        &node_id,
        ALGO_ED25519,
        device_pk.as_bytes(),
        &device_id,
        issued_at_unix,
        valid_until_unix,
    );
    let cert_sig = device_sk.sign(&cert_msg);

    let identity_key = IdentityKey {
        algo: ALGO_ED25519,
        pubkey: device_pk.as_bytes().to_vec(),
        device_id,
        valid_from_unix: issued_at_unix,
        valid_until_unix,
        master_sig: cert_sig.to_bytes().to_vec(),
    };

    let mut doc = IdentityDocument {
        node_id,
        master_algo: ALGO_ED25519,
        master_pubkey: device_pk.as_bytes().to_vec(),
        issued_at_unix,
        valid_until_unix,
        sig_key_idx: 0,
        identity_keys: vec![identity_key],
        document_sig: Vec::new(),
    };

    let mut doc_msg = Vec::with_capacity(DOC_SIG_CONTEXT.len() + 512);
    doc_msg.extend_from_slice(DOC_SIG_CONTEXT);
    doc_msg.extend_from_slice(&doc.canonical_signing_bytes());
    doc.document_sig = device_sk.sign(&doc_msg).to_bytes().to_vec();

    Ok(doc)
}

/// Build + persist a degenerate ("standalone") `IdentityDocument`
/// into the given veil directory. Writes both
/// `identity_document.bin` (atomic tmp+rename) and
/// `device_identity_sk.bin` (0o600 on Unix) so a subsequent
/// [`SovereignIdentity::load_from_dir`] picks the document up.
///
/// `device_sk_seed` is the 32-byte Ed25519 seed. Standalone-mode
/// callers usually pass the same seed the runtime uses for the
/// session-layer handshake (from `[identity]` config) so the
/// sovereign `node_id` and the cfg `node_id` coincide byte-for-byte.
///
/// [`SovereignIdentity::load_from_dir`]:
/// crate::sovereign::SovereignIdentity::load_from_dir
pub fn save_standalone_identity_to_dir(
    veil_dir: &Path,
    device_sk_seed: &SensitiveBytesN<32>,
    issued_at_unix: u64,
    valid_until_unix: u64,
) -> Result<IdentityDocument, CreateIdentityError> {
    std::fs::create_dir_all(veil_dir)?;
    let doc = build_standalone_identity_document(device_sk_seed, issued_at_unix, valid_until_unix)?;
    atomic_write(&veil_dir.join(IDENTITY_DOCUMENT_FILE), &doc.encode())?;
    save_identity_sk(veil_dir, device_sk_seed)?;
    Ok(doc)
}

/// Filename where the rotate + create flows persist the signed
/// document. Kept `pub` so cmd-level / sovereign-identity loaders
/// can refer to it without a private-name dance.
pub const IDENTITY_DOCUMENT_FILE: &str = "identity_document.bin";

/// Filename where the per-device Ed25519 identity_sk seed is
/// persisted (32 bytes, file-mode `0o600` on Unix). Loaded by
/// ongoing flows like `identity revoke` and the runtime handshake.
pub const DEVICE_IDENTITY_SK_FILE: &str = "device_identity_sk.bin";

/// combined Falcon-512 keypair file.
///
/// Holds SK + PK in a single file with a small framing header so a
/// `tmp + rename` write is genuinely atomic — there is no two-file
/// partial-write window. Mutually exclusive with
/// [`DEVICE_IDENTITY_SK_FILE`] (Ed25519); the unified loader
/// [`load_identity_signing_key`] picks whichever it finds.
///
/// File mode `0o600` on Unix because the file carries SK material.
/// The PK half is "public" but it lives in the same file as the SK
/// so the strict mode applies. Operators inspecting the PK should
/// use `veil-cli identity show-pubkey` rather than `cat`.
///
/// # Wire format (binary, big-endian)
///
/// ```text
/// [0..4] magic b"OFAL" (Veil-Falcon)
/// [4] version u8 (1)
/// [5..9] sk_len u32 BE (typically 1281 for Falcon-512)
/// [9..] sk_bytes [u8; sk_len]
/// [..] pk_len u32 BE (typically 897 for Falcon-512)
/// [..] pk_bytes [u8; pk_len]
/// ```
///
/// The field-order (SK-then-PK) keeps the SK at a small fixed offset
/// for fast resumption; both halves are length-prefixed so future
/// PQ algos with different key sizes drop in without a format bump.
pub const DEVICE_IDENTITY_FALCON_FILE: &str = "device_identity_falcon.bin";

/// file-format magic. Caller-visible so an
/// operator running `file` / `xxd` can identify an Veil Falcon
/// keypair file at a glance.
pub const DEVICE_IDENTITY_FALCON_MAGIC: &[u8; 4] = b"OFAL";

/// current keypair-file version. Bumped only
/// when the binary layout changes incompatibly.
pub const DEVICE_IDENTITY_FALCON_VERSION: u8 = 1;

/// Sanity ceiling on a Falcon-512 keypair file; rejects oversized
/// files at decode time before any allocation. Real files are
/// ~1281 (SK) + 897 (PK) + 13 (header) ≈ 2.1 KiB.
const DEVICE_IDENTITY_FALCON_MAX_BYTES: usize = 8 * 1024;

/// filename where the **master-layer** Falcon-512 keypair
/// (SK + PK) is persisted when `create_identity` produces a hybrid
/// identity. Distinct from [`DEVICE_IDENTITY_FALCON_FILE`]
/// (per-device Falcon-512 keypair). Mode `0o600`.
///
/// # Wire format (binary, big-endian)
///
/// ```text
/// [0..4] magic b"OFAM" (Veil Falcon Master)
/// [4] version u8 (1)
/// [5..9] sk_len u32 BE (typically 1281)
/// [9..] sk_bytes [u8; sk_len]
/// [..] pk_len u32 BE (897 for Falcon-512)
/// [..] pk_bytes [u8; pk_len]
/// ```
///
/// SK + PK are bundled in one file because pqcrypto-falcon's
/// `SecretKey` doesn't expose `.public_key` — restore therefore
/// needs both halves preserved, and a single framed file is the only
/// atomic way to persist them.
///
/// **Recovery semantics:** the BIP-39 paper backup recovers only the
/// Ed25519 half of the hybrid master. Loss of `master_falcon.bin`
/// degrades the identity to the Ed25519 component only — the node_id
/// (which depends on the 929 B hybrid pk = ed_pk||falcon_pk) is no
/// longer reproducible. Operators choosing the hybrid algo MUST
/// preserve this file alongside the BIP-39 phrase.
pub const MASTER_FALCON_FILE: &str = "master_falcon.bin";

/// file-format magic (4 bytes) for `master_falcon.bin`.
pub const MASTER_FALCON_MAGIC: &[u8; 4] = b"OFAM";

/// current `master_falcon.bin` version.
pub const MASTER_FALCON_VERSION: u8 = 1;

/// Sanity ceiling for `master_falcon.bin`; rejects oversized files at
/// decode time before any allocation. Real files are ~1281 (SK) +
/// 897 (PK) + 13 (header) ≈ 2.2 KiB.
const MASTER_FALCON_MAX_BYTES: usize = 8 * 1024;

/// persist the **master-layer** Falcon-512 keypair (SK +
/// PK) to `<veil_dir>/master_falcon.bin` (mode `0o600`) using the
/// framed `OFAM` format (see [`MASTER_FALCON_FILE`] for wire layout).
/// Caller is responsible for emitting an operator warning that this
/// file is the SOLE copy of the Falcon master keypair — the BIP-39
/// phrase only recovers the Ed25519 half.
pub fn save_master_falcon_keypair(
    veil_dir: &std::path::Path,
    falcon_sk_bytes: &[u8],
    falcon_pk_bytes: &[u8],
) -> std::io::Result<()> {
    // audit cycle-8: the framed bundle carries the Falcon master SK — the single
    // highest-value, non-BIP-39-recoverable secret. Hold it in `Zeroizing` so it
    // is wiped from the heap on drop rather than lingering in freed memory.
    let mut framed = zeroize::Zeroizing::new(Vec::with_capacity(
        MASTER_FALCON_MAGIC.len() + 1 + 4 + falcon_sk_bytes.len() + 4 + falcon_pk_bytes.len(),
    ));
    framed.extend_from_slice(MASTER_FALCON_MAGIC);
    framed.push(MASTER_FALCON_VERSION);
    framed.extend_from_slice(&(falcon_sk_bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(falcon_sk_bytes);
    framed.extend_from_slice(&(falcon_pk_bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(falcon_pk_bytes);
    if framed.len() > MASTER_FALCON_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "master_falcon framed bundle too large: {} > {} bytes",
                framed.len(),
                MASTER_FALCON_MAX_BYTES
            ),
        ));
    }

    // cycle-7 MH3: hardened atomic write (O_EXCL + O_NOFOLLOW + 0o600 +
    // fsync + parent-dir fsync) instead of the predictable-tmp + rename dance.
    let path = veil_dir.join(MASTER_FALCON_FILE);
    veil_util::atomic_write(&path, &framed)
}

/// parse the framed `master_falcon.bin` bundle into
/// `(sk_bytes, pk_bytes)`. Caller is the one that already loaded the
/// file's contents — splitting parse from I/O makes the function
/// reusable for in-memory bundles passed via
/// `RestoreIdentityOptions::master_falcon_keypair_bytes`.
pub fn parse_master_falcon_keypair(bundle: &[u8]) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    if bundle.len() > MASTER_FALCON_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "master_falcon bundle too large: {} > {}",
                bundle.len(),
                MASTER_FALCON_MAX_BYTES
            ),
        ));
    }
    let mut p = 0usize;
    let need = |p: usize, n: usize| -> std::io::Result<()> {
        if bundle.len() - p < n {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "master_falcon bundle truncated: need {n} at {p}, have {}",
                    bundle.len() - p
                ),
            ))
        } else {
            Ok(())
        }
    };
    need(p, 4)?;
    let magic = &bundle[p..p + 4];
    if magic != MASTER_FALCON_MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("master_falcon: bad magic {magic:?}, expected {MASTER_FALCON_MAGIC:?}"),
        ));
    }
    p += 4;
    need(p, 1)?;
    let version = bundle[p];
    if version != MASTER_FALCON_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("master_falcon: unsupported version {version}"),
        ));
    }
    p += 1;
    need(p, 4)?;
    let sk_len = u32::from_be_bytes(bundle[p..p + 4].try_into().unwrap()) as usize;
    p += 4;
    need(p, sk_len)?;
    let sk = bundle[p..p + sk_len].to_vec();
    p += sk_len;
    need(p, 4)?;
    let pk_len = u32::from_be_bytes(bundle[p..p + 4].try_into().unwrap()) as usize;
    p += 4;
    need(p, pk_len)?;
    let pk = bundle[p..p + pk_len].to_vec();
    p += pk_len;
    if p != bundle.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "master_falcon: trailing bytes ({} unexpected)",
                bundle.len() - p
            ),
        ));
    }
    Ok((sk, pk))
}

/// load + parse `<veil_dir>/master_falcon.bin` into
/// `(sk_bytes, pk_bytes)`. Returns the file's `io::Error` for I/O
/// failures and `InvalidData` for structural decode errors.
pub fn load_master_falcon_keypair(
    veil_dir: &std::path::Path,
) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let path = veil_dir.join(MASTER_FALCON_FILE);
    let bytes = std::fs::read(&path)?;
    parse_master_falcon_keypair(&bytes)
}

/// Persist the device's identity_sk seed to
/// `<veil_dir>/device_identity_sk.bin` with restrictive
/// permissions. File is 32 raw bytes — no magic header because
/// an attacker with read access already has the secret material.
///
/// Phase 6 slice 6i — accepts `&SensitiveBytesN<32>` so the in-memory
/// copy that flows to disk is mlocked (or zeroize-only fallback).
pub fn save_identity_sk(
    veil_dir: &std::path::Path,
    seed: &SensitiveBytesN<32>,
) -> std::io::Result<()> {
    // cycle-7 MH3: route private-key persistence through the hardened
    // `atomic_write` (unpredictable getrandom tmp suffix + O_EXCL + O_NOFOLLOW
    // + 0o600 + fsync + parent-dir fsync) instead of a hand-rolled predictable
    // `path.with_extension("tmp")` + rename, which a local actor with write
    // access to `veil_dir` could pre-empt with a symlink to redirect the SK
    // write, and which skipped the parent-dir fsync (crash-window key loss).
    let path = veil_dir.join(DEVICE_IDENTITY_SK_FILE);
    veil_util::atomic_write(&path, seed.as_slice())
}

/// Load the device's identity_sk seed from
/// `<veil_dir>/device_identity_sk.bin`.  Returned in
/// `SensitiveBytesN<32>` (Phase 6 slice 6i) — mlocked when
/// `RLIMIT_MEMLOCK` permits, zeroize-on-drop fallback otherwise.
pub fn load_identity_sk(veil_dir: &std::path::Path) -> std::io::Result<SensitiveBytesN<32>> {
    let path = veil_dir.join(DEVICE_IDENTITY_SK_FILE);
    // audit U8: wipe the transient read buffer holding the raw Ed25519 SK on
    // every exit path (it is copied into the mlocked SensitiveBytesN below).
    // Mirrors master_file::load_master_seed_encrypted — cheap insurance against
    // a memory-disclosure / core-dump leaking the plaintext from freed heap.
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(std::fs::read(&path)?);
    if bytes.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("identity_sk file is {} bytes, expected 32", bytes.len()),
        ));
    }
    let mut out: SensitiveBytesN<32> = SensitiveBytesN::new();
    out.as_mut_slice().copy_from_slice(&bytes);
    Ok(out)
}

/// persist a Falcon-512 keypair (SK + PK) to
/// `<veil_dir>/device_identity_falcon.bin`. The two halves are
/// packed into a **single** length-prefixed file so a `tmp + rename`
/// write is genuinely atomic — there is no two-file partial-write
/// window where SK exists without PK or vice-versa.
///
/// File mode `0o600` (Unix). See [`DEVICE_IDENTITY_FALCON_FILE`] for
/// the wire format.
///
/// # Why a combined file
///
/// The previous implementation wrote two separate files
/// (SK + PK sidecar) and tried to coordinate two sequential renames.
/// On the second-rename-fails branch the rollback `remove_file(sk)`
/// destroyed the just-renamed SK — losing the user's identity on
/// any installer-retry / partial-disk-failure scenario. Combining
/// into one file makes the failure mode binary: either the rename
/// landed (file is fully present) or it didn't (file is fully
/// absent). No middle state.
pub fn save_identity_falcon_keypair(
    veil_dir: &std::path::Path,
    sk_bytes: &Zeroizing<Vec<u8>>,
    pk_bytes: &[u8],
) -> std::io::Result<()> {
    let path = veil_dir.join(DEVICE_IDENTITY_FALCON_FILE);

    // Build the file body in memory so we never write a partial header
    // to disk. The SK portion is held inside `Zeroizing<Vec<u8>>` so
    // the body buffer below is the temporary copy that crosses the I/O
    // boundary; we wipe it via `Zeroizing` too.
    let sk_len = u32::try_from(sk_bytes.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "SK exceeds u32::MAX")
    })?;
    let pk_len = u32::try_from(pk_bytes.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "PK exceeds u32::MAX")
    })?;
    let mut body: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(
        4 + 1 + 4 + sk_bytes.len() + 4 + pk_bytes.len(),
    ));
    body.extend_from_slice(DEVICE_IDENTITY_FALCON_MAGIC);
    body.push(DEVICE_IDENTITY_FALCON_VERSION);
    body.extend_from_slice(&sk_len.to_be_bytes());
    body.extend_from_slice(&sk_bytes[..]);
    body.extend_from_slice(&pk_len.to_be_bytes());
    body.extend_from_slice(pk_bytes);

    // cycle-7 MH3: hardened atomic write (O_EXCL + O_NOFOLLOW + 0o600 +
    // fsync + parent-dir fsync) — replaces the predictable-tmp + rename dance.
    // The combined SK+PK body keeps the write atomic (no SK-without-PK window).
    veil_util::atomic_write(&path, &body)
}

/// load a Falcon-512 keypair from the
/// combined-file layout written by [`save_identity_falcon_keypair`].
/// Returns `(sk_bytes, pk_bytes)`. SK is wrapped in
/// `Zeroizing<Vec<u8>>` so it gets wiped on drop.
pub fn load_identity_falcon_keypair(
    veil_dir: &std::path::Path,
) -> std::io::Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let path = veil_dir.join(DEVICE_IDENTITY_FALCON_FILE);
    // audit U8: the read buffer holds the full Falcon SK plaintext; wipe it on
    // drop (decode_falcon_keypair copies the SK half into its own Zeroizing).
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(std::fs::read(&path)?);
    if bytes.len() > DEVICE_IDENTITY_FALCON_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} oversized: {} B > {} B cap",
                DEVICE_IDENTITY_FALCON_FILE,
                bytes.len(),
                DEVICE_IDENTITY_FALCON_MAX_BYTES,
            ),
        ));
    }
    decode_falcon_keypair(&bytes)
}

/// Decode the keypair body produced by [`save_identity_falcon_keypair`].
/// Pulled out so unit tests can drive the parser without touching
/// the filesystem.
fn decode_falcon_keypair(bytes: &[u8]) -> std::io::Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    use std::io::{Error, ErrorKind};
    if bytes.len() < 4 + 1 + 4 + 4 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "{} truncated: {} B < min header",
                DEVICE_IDENTITY_FALCON_FILE,
                bytes.len(),
            ),
        ));
    }
    if &bytes[0..4] != DEVICE_IDENTITY_FALCON_MAGIC {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("{} bad magic", DEVICE_IDENTITY_FALCON_FILE),
        ));
    }
    let version = bytes[4];
    if version != DEVICE_IDENTITY_FALCON_VERSION {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "{} unsupported version {} (expected {})",
                DEVICE_IDENTITY_FALCON_FILE, version, DEVICE_IDENTITY_FALCON_VERSION,
            ),
        ));
    }
    let sk_len = u32::from_be_bytes(bytes[5..9].try_into().expect("len 4")) as usize;
    let sk_off: usize = 9;
    let sk_end = sk_off
        .checked_add(sk_len)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "sk_len overflow"))?;
    if sk_end + 4 > bytes.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("{} truncated SK", DEVICE_IDENTITY_FALCON_FILE),
        ));
    }
    let sk = Zeroizing::new(bytes[sk_off..sk_end].to_vec());
    let pk_len_off = sk_end;
    let pk_len =
        u32::from_be_bytes(bytes[pk_len_off..pk_len_off + 4].try_into().expect("len 4")) as usize;
    let pk_off = pk_len_off + 4;
    let pk_end = pk_off
        .checked_add(pk_len)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "pk_len overflow"))?;
    if pk_end > bytes.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("{} truncated PK", DEVICE_IDENTITY_FALCON_FILE),
        ));
    }
    if pk_end != bytes.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("{} trailing bytes after PK", DEVICE_IDENTITY_FALCON_FILE,),
        ));
    }
    let pk = bytes[pk_off..pk_end].to_vec();
    Ok((sk, pk))
}

/// follow-up + / : unified loader.
/// Inspects `veil_dir` and returns whichever flavour of identity
/// SK is present:
///
/// * If `device_identity_sk.bin` exists → returns Ed25519 variant.
/// * Else if `device_identity_falcon.bin` exists → returns Falcon-512
///   variant (combined SK+PK file, atomic write semantics).
/// * Else → `NotFound` error.
///
/// If BOTH are present, Ed25519 wins (legacy preference; operators
/// should remove the unused file to make the choice explicit).
pub fn load_identity_signing_key(
    veil_dir: &std::path::Path,
) -> std::io::Result<crate::signing_key::IdentitySigningKey> {
    let ed_path = veil_dir.join(DEVICE_IDENTITY_SK_FILE);
    if ed_path.exists() {
        let seed = load_identity_sk(veil_dir)?;
        return Ok(crate::signing_key::IdentitySigningKey::from_ed25519_seed(
            *seed.as_array(),
        ));
    }
    let fa_path = veil_dir.join(DEVICE_IDENTITY_FALCON_FILE);
    if fa_path.exists() {
        let (sk_bytes, pk_bytes) = load_identity_falcon_keypair(veil_dir)?;
        return crate::signing_key::IdentitySigningKey::from_falcon512_bytes(&sk_bytes, &pk_bytes)
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Falcon-512 keypair decode error: {e}"),
                )
            });
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!(
            "no identity SK file in `{}` (looked for `{}` and `{}`)",
            veil_dir.display(),
            DEVICE_IDENTITY_SK_FILE,
            DEVICE_IDENTITY_FALCON_FILE,
        ),
    ))
}

/// Filename carrying a 2-byte (u16 big-endian) per-device override
/// for which `identity_keys[..]` slot this device's `identity_sk`
/// corresponds to. Written by the target side of the pairing
/// ceremony when the device on-disk copy of the
/// `IdentityDocument` has `sig_key_idx` pointing at *another*
/// device's subkey — the target's subkey lives at a different
/// index, and `load_from_dir` honours this file over
/// `document.sig_key_idx` when present. Absent for source-side
/// devices, preserving the legacy one-device layout.
pub const DEVICE_SIG_KEY_IDX_FILE: &str = "device_sig_key_idx.bin";

/// Persist the per-device `sig_key_idx` override (2 bytes, BE).
/// Paired targets call this after `pair-accept` so subsequent
/// `SovereignIdentity::load_from_dir` picks the correct subkey.
pub fn save_device_sig_key_idx(
    veil_dir: &std::path::Path,
    sig_key_idx: u16,
) -> std::io::Result<()> {
    // cycle-7 MH3: hardened atomic write (the previous path used a bare
    // `File::create` with no 0o600 mode and a predictable tmp name).
    let path = veil_dir.join(DEVICE_SIG_KEY_IDX_FILE);
    veil_util::atomic_write(&path, &sig_key_idx.to_be_bytes())
}

/// Load the per-device `sig_key_idx` override. Returns `Ok(None)`
/// when the file is absent (i.e., source-side device — caller
/// should fall back to `document.sig_key_idx`).
pub fn load_device_sig_key_idx(veil_dir: &std::path::Path) -> std::io::Result<Option<u16>> {
    let path = veil_dir.join(DEVICE_SIG_KEY_IDX_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => {
            if bytes.len() != 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "device_sig_key_idx file is {} bytes, expected 2",
                        bytes.len()
                    ),
                ));
            }
            Ok(Some(u16::from_be_bytes([bytes[0], bytes[1]])))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Errors raised by [`save_paired_target_state`]. Distinct from
/// [`RotateIdentityError`] because the pair-accept path has its own
/// error surface (no master-seed mismatch check, no revocation, no
/// PoW mining).
#[derive(Debug, thiserror::Error)]
pub enum PairedTargetPersistError {
    #[error("paired target persist: i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("paired target persist: instance file: {0}")]
    Instance(#[from] crate::instance::InstanceFileError),
    #[error(
        "paired target persist: sig_key_idx {idx} out of bounds \
         (document has {n_keys} keys)"
    )]
    SigKeyIdxOutOfBounds { idx: u16, n_keys: usize },
}

/// Atomically persist the four files a target device needs after a
/// successful pair-accept ceremony:
///
/// `identity_document.bin` — source's updated doc carrying the
/// target's freshly master-certified `IdentityKey`.
/// `device_identity_sk.bin` — target's fresh Ed25519 SK seed.
/// `device_sig_key_idx.bin` — u16 big-endian pointing at the
/// target's subkey slot (since the doc's own `sig_key_idx`
/// points at the *source's* active subkey).
/// `instance_id` — `LocalInstance` with the target's fresh
/// `target_instance_id` + operator-chosen label.
///
/// Writes each file atomically (tmp → rename). Rolls forward on
/// partial failure — caller is expected to retry on I/O error
/// rather than running the ceremony again.
pub fn save_paired_target_state(
    veil_dir: &std::path::Path,
    document: &IdentityDocument,
    identity_sk_seed: &SensitiveBytesN<32>,
    sig_key_idx: u16,
    target_instance_id: [u8; 16],
    instance_label: impl Into<String>,
) -> Result<(), PairedTargetPersistError> {
    use crate::instance::{LocalInstance, default_instance_path};

    if (sig_key_idx as usize) >= document.identity_keys.len() {
        return Err(PairedTargetPersistError::SigKeyIdxOutOfBounds {
            idx: sig_key_idx,
            n_keys: document.identity_keys.len(),
        });
    }

    std::fs::create_dir_all(veil_dir)?;

    // 1. IdentityDocument.
    atomic_write(&veil_dir.join(IDENTITY_DOCUMENT_FILE), &document.encode())?;

    // 2. identity_sk seed (0o600 on Unix).
    save_identity_sk(veil_dir, identity_sk_seed)?;

    // 3. sig_key_idx override.
    save_device_sig_key_idx(veil_dir, sig_key_idx)?;

    // 4. instance_id file.
    let instance = LocalInstance {
        instance_id: target_instance_id,
        label: instance_label.into(),
    };
    instance.save(&default_instance_path(veil_dir))?;

    Ok(())
}

use veil_util::atomic_write;

// ── Pretty-printer ───────────────────────────────────────────────────────────

/// Format an `IdentityDocument` summary for user-facing display.
/// Used by the CLI `identity show` flow; safe to include in app
/// logs because it hides all secret material.
pub fn format_identity_summary(doc: &IdentityDocument, instance: &LocalInstance) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(&mut s, "node_id:        {}", hex_encode(&doc.node_id));
    let _ = writeln!(
        &mut s,
        "master_algo:        {}",
        match doc.master_algo {
            0 => "ed25519",
            2 => "falcon512",
            3 => "ed25519+falcon512",
            4 => "ed25519+falcon1024",
            other => {
                return format!("unknown master algo byte {other}");
            }
        }
    );
    let _ = writeln!(&mut s, "issued_at_unix:     {}", doc.issued_at_unix);
    let _ = writeln!(&mut s, "valid_until_unix:   {}", doc.valid_until_unix);
    let _ = writeln!(&mut s, "identity_keys:      {}", doc.identity_keys.len());
    for (i, key) in doc.identity_keys.iter().enumerate() {
        let _ = writeln!(
            &mut s,
            "  [{i}] device_id = {}, algo = {}, valid_until = {}",
            hex_encode(&key.device_id),
            key.algo,
            key.valid_until_unix,
        );
    }
    let _ = writeln!(
        &mut s,
        "local_instance_id:  {}  (label = {:?})",
        hex_encode(&instance.instance_id),
        instance.label,
    );
    s
}

fn hex_encode(bytes: &[u8]) -> String {
    veil_util::bytes_to_hex(bytes)
}

// ── Path helpers ─────────────────────────────────────────────────────────────

/// Default identity-state directory path. Callers that want the
/// standard veil layout use this; tests pass a `tempfile` dir.
pub fn default_identity_dir() -> std::io::Result<PathBuf> {
    use std::env;
    let dir = if let Ok(custom) = env::var("VEIL_IDENTITY_DIR") {
        PathBuf::from(custom)
    } else if let Ok(home) = env::var("HOME") {
        PathBuf::from(home).join(".config").join("veil")
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no HOME env var and no VEIL_IDENTITY_DIR",
        ));
    };
    Ok(dir)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use crate::master_file::load_master_seed_encrypted;
    use crate::master_seed::decode_master_seed_from_phrase;
    use crate::verify::verify_identity_document;

    /// PoW difficulty kept at 0 (dropped document-level
    /// PoW); retained as an inert field on `CreateIdentityOptions`.
    const TEST_POW_DIFFICULTY: u32 = 0;

    fn tempdir() -> PathBuf {
        crate::test_support::scratch_dir("veil-sovereign-flow")
    }

    fn test_opts(dir: PathBuf) -> CreateIdentityOptions {
        let issued = 1_700_000_000u64;
        CreateIdentityOptions {
            veil_dir: dir,
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "test-laptop".into(),
            pow_difficulty: TEST_POW_DIFFICULTY,
            issued_at_unix: issued,
            valid_until_unix: issued + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        }
    }

    // ── hybrid create_identity ─────────────────────────────────
    //
    // Asserts the hybrid algo path produces a document that:
    // • carries master_algo = ALGO_ED25519_FALCON512_HYBRID (3)
    // • has a 929-byte master_pubkey (32 ed + 897 falcon)
    // • has a node_id distinct from the Ed25519-only path under the
    // same BIP-39 seed (BLAKE3(929 B) ≠ BLAKE3(32 B))
    // • verifies under verify_identity_document (canonical hybrid
    // verify in verify::verify_proof_sig)
    // • persists `master_falcon.bin` (mode 0o600) inside veil_dir.
    #[test]
    fn create_identity_hybrid_produces_verifiable_document() {
        use veil_proto::identity_document::ALGO_ED25519_FALCON512_HYBRID;
        use veil_types::SignatureAlgorithm;

        let dir = tempdir();
        let issued = 1_700_000_000u64;
        let opts = CreateIdentityOptions {
            veil_dir: dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "hybrid-laptop".into(),
            pow_difficulty: TEST_POW_DIFFICULTY,
            issued_at_unix: issued,
            valid_until_unix: issued + 7 * 86_400,
            algo: SignatureAlgorithm::Ed25519Falcon512Hybrid,
        };
        let out = create_identity(opts).expect("hybrid create");

        assert_eq!(out.document.master_algo, ALGO_ED25519_FALCON512_HYBRID);
        assert_eq!(out.document.master_pubkey.len(), 32 + 897);

        // The per-device subkey (identity_sk) stays Ed25519 — fast
        // verify in hot path; PQ protection lives at the master layer.
        assert_eq!(
            out.document.identity_keys[0].algo,
            veil_proto::identity_document::ALGO_ED25519,
        );

        // Document verifies (hybrid cert_sig + Ed25519 doc_sig).
        let validated =
            verify_identity_document(&out.document, issued).expect("hybrid document must verify");
        assert_eq!(validated.node_id, out.node_id);

        // master_falcon.bin must exist and be non-empty.
        let falcon_path = out
            .master_falcon_path
            .as_ref()
            .expect("hybrid create must set master_falcon_path");
        assert!(falcon_path.exists(), "master_falcon.bin must be created");
        let falcon_bytes = std::fs::read(falcon_path).expect("read master_falcon.bin");
        assert!(
            falcon_bytes.len() > 100,
            "Falcon-512 SK is ~1281 bytes; got {}",
            falcon_bytes.len()
        );

        // node_id is BLAKE3(929 B) — distinct from any Ed25519-only
        // identity even under an identical BIP-39 seed. Sanity-check
        // by recomputing.
        let recomputed = veil_crypto::identity::compute_node_id(&out.document.master_pubkey);
        assert_eq!(recomputed, out.node_id);
    }

    // ── hybrid-1024 create_identity (Falcon-1024 follow-up) ────────────
    //
    // Mirrors the 512-hybrid acceptance test with the larger Falcon suite:
    // • master_algo = ALGO_ED25519_FALCON1024_HYBRID (4)
    // • master_pubkey is 1825 bytes (32 ed + 1793 falcon-1024)
    // • document verifies under verify_identity_document (canonical
    //   hybrid-1024 verify in verify::verify_proof_sig)
    // • master_falcon.bin persists a Falcon-1024 SK+PK bundle (~2305 B
    //   SK + ~1800 B PK + framing > the 512-hybrid 1281 B bound).
    #[test]
    fn create_identity_hybrid_1024_produces_verifiable_document() {
        use veil_proto::identity_document::ALGO_ED25519_FALCON1024_HYBRID;
        use veil_types::SignatureAlgorithm;

        let dir = tempdir();
        let issued = 1_700_000_000u64;
        let opts = CreateIdentityOptions {
            veil_dir: dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "hybrid-1024-laptop".into(),
            pow_difficulty: TEST_POW_DIFFICULTY,
            issued_at_unix: issued,
            valid_until_unix: issued + 7 * 86_400,
            algo: SignatureAlgorithm::Ed25519Falcon1024Hybrid,
        };
        let out = create_identity(opts).expect("hybrid-1024 create");

        assert_eq!(out.document.master_algo, ALGO_ED25519_FALCON1024_HYBRID);
        assert_eq!(
            out.document.master_pubkey.len(),
            32 + 1793,
            "hybrid-1024 master_pubkey = ed_pk(32) + falcon1024_pk(1793)"
        );

        // Per-device subkey stays Ed25519 — fast verify on the hot
        // path, PQ protection lives at the master layer.
        assert_eq!(
            out.document.identity_keys[0].algo,
            veil_proto::identity_document::ALGO_ED25519,
        );

        // Document verifies through the canonical hybrid-1024 path.
        let validated = verify_identity_document(&out.document, issued)
            .expect("hybrid-1024 document must verify");
        assert_eq!(validated.node_id, out.node_id);

        // master_falcon.bin must exist and hold the Falcon-1024 bundle.
        let falcon_path = out
            .master_falcon_path
            .as_ref()
            .expect("hybrid-1024 create must set master_falcon_path");
        assert!(falcon_path.exists(), "master_falcon.bin must be created");
        let falcon_bytes = std::fs::read(falcon_path).expect("read master_falcon.bin");
        // Falcon-1024 SK is ~2305 B; bundle is SK + PK (1793 B) +
        // framing overhead → well > 3000 bytes. Use 2000 as a defensive
        // lower-bound that excludes a Falcon-512 misroute.
        assert!(
            falcon_bytes.len() > 2000,
            "Falcon-1024 bundle should be > 2000 bytes; got {} \
             (Falcon-512 hybrid would be ~1281)",
            falcon_bytes.len()
        );

        let recomputed = veil_crypto::identity::compute_node_id(&out.document.master_pubkey);
        assert_eq!(recomputed, out.node_id);
    }

    /// hybrid-1024 and hybrid-512 produce **different** node_ids even
    /// under an identical BIP-39 seed — the master_pubkey layouts have
    /// different sizes (1825 vs 929 B), so BLAKE3 outputs diverge.
    /// Guards against a silent regression that would let a hybrid-1024
    /// node accidentally collide with a hybrid-512 node under matched
    /// recovery phrases.
    #[test]
    fn etap10_followup_hybrid_1024_node_id_distinct_from_hybrid_512() {
        use veil_types::SignatureAlgorithm;
        // Both paths take the seed from OsRng internally — we can't pin
        // identical phrases at the API surface, but we CAN confirm
        // structural distinctness via a side-by-side create call.
        let dir_a = tempdir();
        let dir_b = tempdir();
        let issued = 1_700_000_000u64;

        let opts_512 = CreateIdentityOptions {
            veil_dir: dir_a,
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "hybrid-512-laptop".into(),
            pow_difficulty: TEST_POW_DIFFICULTY,
            issued_at_unix: issued,
            valid_until_unix: issued + 7 * 86_400,
            algo: SignatureAlgorithm::Ed25519Falcon512Hybrid,
        };
        let opts_1024 = CreateIdentityOptions {
            veil_dir: dir_b,
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "hybrid-1024-laptop".into(),
            pow_difficulty: TEST_POW_DIFFICULTY,
            issued_at_unix: issued,
            valid_until_unix: issued + 7 * 86_400,
            algo: SignatureAlgorithm::Ed25519Falcon1024Hybrid,
        };
        let out_512 = create_identity(opts_512).expect("hybrid-512");
        let out_1024 = create_identity(opts_1024).expect("hybrid-1024");

        assert_ne!(
            out_512.document.master_pubkey.len(),
            out_1024.document.master_pubkey.len(),
            "hybrid-512 (929 B) and hybrid-1024 (1825 B) must differ structurally"
        );
        assert_ne!(out_512.node_id, out_1024.node_id);
        assert_ne!(
            out_512.document.master_algo, out_1024.document.master_algo,
            "ALGO_ED25519_FALCON512_HYBRID (3) vs ALGO_ED25519_FALCON1024_HYBRID (4)"
        );
    }

    /// ext: standalone Falcon-512 master. Library-level
    /// path now accepts it (CLI gates with --accept-no-recovery).
    /// Verify: master_pubkey is 897 B (raw Falcon pk, no Ed25519
    /// prefix), master_falcon.bin holds the SK+PK bundle, document
    /// verifies under canonical Falcon verify.
    #[test]
    fn create_identity_falcon512_standalone() {
        use veil_proto::identity_document::ALGO_FALCON512;
        use veil_types::SignatureAlgorithm;

        let dir = tempdir();
        let issued = 1_700_000_000u64;
        let opts = CreateIdentityOptions {
            veil_dir: dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "falcon-only".into(),
            pow_difficulty: TEST_POW_DIFFICULTY,
            issued_at_unix: issued,
            valid_until_unix: issued + 7 * 86_400,
            algo: SignatureAlgorithm::Falcon512,
        };
        let out = create_identity(opts).expect("falcon-only create");

        assert_eq!(out.document.master_algo, ALGO_FALCON512);
        assert_eq!(
            out.document.master_pubkey.len(),
            897,
            "standalone Falcon master_pubkey is the raw 897 B falcon_pk"
        );

        // Document verifies under the canonical hybrid-verify path
        // (Falcon-only signatures are a valid arm).
        let validated = verify_identity_document(&out.document, issued)
            .expect("falcon-only document must verify");
        assert_eq!(validated.node_id, out.node_id);
        assert_eq!(validated.master_algo, ALGO_FALCON512);

        // master_falcon.bin holds the SK+PK bundle in OFAM framing.
        let falcon_path = out
            .master_falcon_path
            .expect("standalone Falcon must persist master_falcon.bin");
        assert!(falcon_path.exists());
        let bytes = std::fs::read(&falcon_path).unwrap();
        assert_eq!(&bytes[..4], MASTER_FALCON_MAGIC);
        let (sk, pk) = parse_master_falcon_keypair(&bytes).expect("parse OFAM bundle");
        assert_eq!(pk.len(), 897);
        assert!(sk.len() > 100, "Falcon-512 SK is ~1281 B; got {}", sk.len());

        // node_id = BLAKE3(897 B falcon_pk) — distinct from any Ed25519
        // identity AND from any hybrid identity (which would hash 929 B).
        let recomputed = veil_crypto::identity::compute_node_id(&out.document.master_pubkey);
        assert_eq!(recomputed, out.node_id);
    }

    /// ext: standalone Falcon-512 restore — preserve the
    /// OFAM bundle, throw away the BIP-39 phrase (irrelevant), and
    /// reproduce the same node_id from the bundle alone. master_seed
    /// is fed as a zero-seed (mirrors what the CLI does when
    ///phrase-file is omitted on a Falcon restore).
    #[test]
    fn restore_identity_falcon512_standalone() {
        use veil_types::SignatureAlgorithm;

        let original_dir = tempdir();
        let issued = 1_700_000_000u64;
        let created = create_identity(CreateIdentityOptions {
            veil_dir: original_dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "falcon-only".into(),
            pow_difficulty: TEST_POW_DIFFICULTY,
            issued_at_unix: issued,
            valid_until_unix: issued + 7 * 86_400,
            algo: SignatureAlgorithm::Falcon512,
        })
        .expect("falcon-only create");
        let original_node_id = created.node_id;
        let bundle = std::fs::read(created.master_falcon_path.as_ref().unwrap()).unwrap();

        // Restore: zero-seed for master_seed (the standalone Falcon
        // branch ignores it), bundle is the SOLE recovery medium.
        let fresh_dir = tempdir();
        let now = 1_700_800_000u64;
        let restored = restore_identity(RestoreIdentityOptions {
            veil_dir: fresh_dir,
            master_seed: Zeroizing::new([0u8; MASTER_SEED_LEN]),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            instance_label: "falcon-only-restored".into(),
            pow_difficulty: TEST_POW_DIFFICULTY,
            now_unix: now,
            valid_until_unix: now + 7 * 86_400,
            algo: SignatureAlgorithm::Falcon512,
            master_falcon_keypair_bytes: Some(bundle.clone()),
        })
        .expect("falcon-only restore");

        assert_eq!(
            restored.node_id, original_node_id,
            "standalone Falcon restore must reproduce the original node_id from the bundle alone"
        );
        verify_identity_document(&restored.document, now)
            .expect("restored Falcon-only document must verify");
        // master_falcon.bin re-saved in the new veil_dir.
        let restored_falcon_path = restored
            .master_falcon_path
            .expect("standalone Falcon restore must re-save master_falcon.bin");
        let restored_bundle = std::fs::read(restored_falcon_path).unwrap();
        assert_eq!(restored_bundle, bundle, "round-trip preserves the bundle");
    }

    /// ext: standalone Falcon-512 restore without bundle still
    /// fails fast — the BIP-39 phrase has no Falcon recovery path
    /// so the error message must point operator at the bundle, not
    /// at any phrase-related fix.
    #[test]
    fn restore_identity_falcon512_rejects_missing_bundle() {
        use veil_types::SignatureAlgorithm;

        let dir = tempdir();
        let now = 1_700_800_000u64;
        let err = restore_identity(RestoreIdentityOptions {
            veil_dir: dir,
            master_seed: Zeroizing::new([0u8; MASTER_SEED_LEN]),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            instance_label: "falcon-fail".into(),
            pow_difficulty: TEST_POW_DIFFICULTY,
            now_unix: now,
            valid_until_unix: now + 7 * 86_400,
            algo: SignatureAlgorithm::Falcon512,
            master_falcon_keypair_bytes: None,
        })
        .expect_err("falcon-only restore must reject missing bundle");
        assert!(
            matches!(err, RestoreIdentityError::MissingFalconMaster),
            "expected MissingFalconMaster, got {err:?}"
        );
    }

    // ── End-to-end ─────────────────────────────────────────────────────────

    #[test]
    fn create_identity_produces_verifiable_document() {
        let dir = tempdir();
        let out = create_identity(test_opts(dir.clone())).expect("create");
        let validated = verify_identity_document(&out.document, 1_700_000_000)
            .expect("freshly-created document must verify");
        assert_eq!(validated.node_id, out.node_id);
        assert_eq!(validated.active_key_idx, 0);
        // active_device_id is deterministic from the active
        // subkey pubkey; the prior random-tag binding is gone.
        assert_eq!(
            validated.active_device_id, out.document.identity_keys[0].device_id,
            "verifier must report the deterministic device_id of the active subkey",
        );
    }

    #[test]
    fn bip39_phrase_roundtrips_to_same_master_seed() {
        let dir = tempdir();
        let out = create_identity(test_opts(dir)).unwrap();
        let phrase = out.master_seed_phrase.to_string();
        let restored = decode_master_seed_from_phrase(&phrase).unwrap();
        assert_eq!(
            *out.master_seed, *restored,
            "paper backup must reconstitute the same seed"
        );
    }

    #[test]
    fn instance_id_persists_across_create_calls() {
        // Per 462.11, instance_id is stable for device lifetime.
        // Calling create_identity twice against the same dir MUST
        // reuse the existing instance_id (even though node_id
        // master_seed, etc. differ — they're per-call fresh).
        let dir = tempdir();
        let first = create_identity(test_opts(dir.clone())).unwrap();
        let second = create_identity(test_opts(dir)).unwrap();
        assert_eq!(first.instance.instance_id, second.instance.instance_id);
        assert_ne!(first.node_id, second.node_id);
    }

    #[test]
    fn encrypted_master_file_roundtrips() {
        let dir = tempdir();
        let opts = CreateIdentityOptions {
            save_encrypted_with_password: Some(b"test-password".to_vec()),
            argon2_params_override: Some((16 * 1024, 1, 1)),
            ..test_opts(dir.clone())
        };
        let out = create_identity(opts).unwrap();
        let path = out.encrypted_master_path.as_ref().expect("path set");
        assert!(path.exists());
        let decoded = load_master_seed_encrypted(path, b"test-password").unwrap();
        assert_eq!(*out.master_seed, *decoded);
    }

    #[test]
    fn encrypted_master_file_rejects_wrong_password() {
        let dir = tempdir();
        let opts = CreateIdentityOptions {
            save_encrypted_with_password: Some(b"pw".to_vec()),
            argon2_params_override: Some((16 * 1024, 1, 1)),
            ..test_opts(dir)
        };
        let out = create_identity(opts).unwrap();
        let path = out.encrypted_master_path.as_ref().unwrap();
        assert!(load_master_seed_encrypted(path, b"wrong").is_err());
    }

    // ── Extra-entropy path ─────────────────────────────────────────────────

    #[test]
    fn extra_entropy_produces_different_identities_than_default() {
        let dir1 = tempdir();
        let dir2 = tempdir();
        let baseline = create_identity(test_opts(dir1)).unwrap();
        let extra = CreateIdentityOptions {
            extra_entropy: Some(vec![0xABu8; 64]),
            ..test_opts(dir2)
        };
        let mixed = create_identity(extra).unwrap();
        // They draw fresh OsRng anyway so identities differ on every
        // call — the real check is that the extra_entropy path doesn't
        // panic or produce an invalid document.
        assert_ne!(baseline.node_id, mixed.node_id);
        verify_identity_document(&mixed.document, 1_700_000_000)
            .expect("extra-entropy doc must verify");
    }

    #[test]
    fn rejects_short_extra_entropy() {
        let dir = tempdir();
        let opts = CreateIdentityOptions {
            extra_entropy: Some(vec![0u8; 16]), // < 32
            ..test_opts(dir)
        };
        let err = create_identity(opts).unwrap_err();
        assert!(matches!(err, CreateIdentityError::MasterSeed(_)), "{err:?}");
    }

    // ── Guardrails ─────────────────────────────────────────────────────────

    #[test]
    fn rejects_zero_freshness_window() {
        let dir = tempdir();
        let issued = 1_700_000_000;
        let opts = CreateIdentityOptions {
            issued_at_unix: issued,
            valid_until_unix: issued, // window = 0
            ..test_opts(dir)
        };
        let err = create_identity(opts).unwrap_err();
        assert!(matches!(
            err,
            CreateIdentityError::FreshnessWindowTooLong { .. }
        ));
    }

    #[test]
    fn rejects_oversize_freshness_window() {
        let dir = tempdir();
        let issued = 1_700_000_000;
        let opts = CreateIdentityOptions {
            issued_at_unix: issued,
            valid_until_unix: issued + MAX_FRESHNESS_WINDOW_SECS + 1,
            ..test_opts(dir)
        };
        let err = create_identity(opts).unwrap_err();
        assert!(matches!(
            err,
            CreateIdentityError::FreshnessWindowTooLong { .. }
        ));
    }

    #[test]
    fn creates_veil_dir_if_missing() {
        let parent = tempdir();
        let nested = parent.join("nested").join("dir");
        assert!(!nested.exists());
        let opts = CreateIdentityOptions {
            veil_dir: nested.clone(),
            ..test_opts(parent)
        };
        create_identity(opts).unwrap();
        assert!(nested.exists());
    }

    // ── Pretty printer ─────────────────────────────────────────────────────

    #[test]
    fn format_identity_summary_includes_required_fields() {
        let dir = tempdir();
        let out = create_identity(test_opts(dir)).unwrap();
        let summary = format_identity_summary(&out.document, &out.instance);
        assert!(summary.contains("node_id:"));
        assert!(summary.contains("master_algo:"));
        assert!(summary.contains("issued_at_unix:"));
        assert!(summary.contains("local_instance_id:"));
        // The 64-hex node_id should appear somewhere.
        assert!(summary.contains(&hex_encode(&out.node_id)));
    }

    #[test]
    fn format_identity_summary_hides_secrets() {
        // The summary must never include seed bytes, master_sk
        // identity_sk, or raw pubkeys. Only the BLAKE3 hashes /
        // node_id are safe to display.
        let dir = tempdir();
        let out = create_identity(test_opts(dir)).unwrap();
        let summary = format_identity_summary(&out.document, &out.instance);
        // master_pubkey itself shouldn't appear in full.
        let pk_hex = hex_encode(&out.document.master_pubkey);
        assert!(
            !summary.contains(&pk_hex),
            "summary must not leak master_pubkey bytes"
        );
    }

    // ── Default identity dir ──────────────────────────────────────────────

    /// env var mutations are process-global; serialise
    /// against any concurrent test that reads VEIL_IDENTITY_DIR.
    /// Process-wide Mutex deterministically orders writers (preferred
    /// over a dev-dep on `serial_test`).
    fn env_test_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::OnceLock;
        static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    #[test]
    fn default_identity_dir_respects_env_override() {
        let _g = env_test_lock();
        let key = "VEIL_IDENTITY_DIR";
        let original = std::env::var_os(key);
        // Use a unique-per-test path so racing threads don't stomp
        // on each other (race is also bounded by the lock above).
        let custom = tempdir();
        unsafe {
            std::env::set_var(key, &custom);
        }
        let resolved = default_identity_dir().unwrap();
        assert_eq!(resolved, custom);
        match original {
            Some(v) => unsafe {
                std::env::set_var(key, v);
            },
            None => unsafe {
                std::env::remove_var(key);
            },
        }
    }

    // ── leading_zero_bits helper ───────────────────────────────────────────

    #[test]
    fn leading_zero_bits_matches_byte_patterns() {
        assert_eq!(veil_util::leading_zero_bits(&[0xFF]), 0);
        assert_eq!(veil_util::leading_zero_bits(&[0x0F]), 4);
        assert_eq!(veil_util::leading_zero_bits(&[0x00, 0x80]), 8);
        assert_eq!(veil_util::leading_zero_bits(&[0x00, 0x00, 0x01]), 23);
    }

    // ── Rotate flow (462.6) ────────────────────────────────────────────────

    fn rotate_opts(
        dir: PathBuf,
        master_seed: Zeroizing<[u8; MASTER_SEED_LEN]>,
    ) -> RotateIdentityOptions {
        let now = 1_700_500_000u64; // after the create's issued_at
        RotateIdentityOptions {
            veil_dir: dir,
            master_seed,
            now_unix: now,
            valid_until_unix: now + 7 * 86_400,
        }
    }

    #[test]
    fn rotate_adds_new_subkey_and_preserves_verifier() {
        let dir = tempdir();
        let created = create_identity(test_opts(dir.clone())).unwrap();
        let master_seed = created.master_seed.clone();
        let rotated = rotate_identity(rotate_opts(dir, master_seed)).unwrap();

        assert_eq!(rotated.old_identity_key_idx, 0);
        assert_eq!(rotated.new_identity_key_idx, 1);
        assert_eq!(rotated.document.identity_keys.len(), 2);
        assert_eq!(rotated.document.sig_key_idx, 1);

        verify_identity_document(&rotated.document, 1_700_500_000)
            .expect("rotated document verifies");
    }

    /// Build CreateIdentityOptions for a given algo in a temp dir — mirrors
    /// `test_opts` but lets the hybrid-rotation tests choose the master algo.
    fn create_opts_for(
        dir: PathBuf,
        algo: veil_types::SignatureAlgorithm,
        issued: u64,
    ) -> CreateIdentityOptions {
        CreateIdentityOptions {
            veil_dir: dir,
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "hybrid-rotate".into(),
            pow_difficulty: TEST_POW_DIFFICULTY,
            issued_at_unix: issued,
            valid_until_unix: issued + 7 * 86_400,
            algo,
        }
    }

    /// Regression for Phase 10: a Falcon-1024 hybrid identity must be able to
    /// rotate. The fix reconstructs the FULL master pubkey (ed||falcon, from
    /// master_falcon.bin) so the node_id check passes, and certifies the new
    /// subkey with a HYBRID master signature. Before the fix rotate derived
    /// only the Ed25519 half: it failed MasterSeedMismatch outright, and even
    /// past that would have produced an Ed25519-only cert the hybrid verifier
    /// rejects.
    #[test]
    fn rotate_hybrid_1024_certifies_new_subkey_with_hybrid_master() {
        use veil_types::SignatureAlgorithm;
        let dir = tempdir();
        let issued = 1_700_000_000u64;
        let created = create_identity(create_opts_for(
            dir.clone(),
            SignatureAlgorithm::Ed25519Falcon1024Hybrid,
            issued,
        ))
        .expect("hybrid-1024 create");

        let rotated = rotate_identity(rotate_opts(dir.clone(), created.master_seed.clone()))
            .expect("hybrid-1024 rotation must succeed");

        assert_eq!(rotated.document.identity_keys.len(), 2);
        assert_eq!(rotated.document.sig_key_idx, 1);
        assert_eq!(
            rotated.document.node_id, created.node_id,
            "node_id stable across hybrid-1024 rotation"
        );
        assert_eq!(
            rotated.document.master_algo,
            veil_proto::identity_document::ALGO_ED25519_FALCON1024_HYBRID
        );
        // Full verify exercises the new subkey's HYBRID master cert (via
        // verify_identity_key_cert → verify_sig_raw under the hybrid
        // master_algo): an Ed25519-only cert — the pre-fix bug — fails here.
        verify_identity_document(&rotated.document, 1_700_500_000)
            .expect("rotated hybrid-1024 document (incl. new subkey cert) must verify");
        // The new subkey cert must be a hybrid signature, materially larger
        // than a 64-byte Ed25519 signature.
        assert!(
            rotated.document.identity_keys[1].master_sig.len() > 64,
            "new subkey cert must be a hybrid signature, got {} bytes",
            rotated.document.identity_keys[1].master_sig.len()
        );

        // Wire round-trip: the rotated (2-key) 1024-hybrid document — whose
        // master_pubkey (1825 B) and two hybrid certs (~1.5 KiB each) blow the
        // old 1024 B per-field caps and the old 4 KiB document cap — must
        // re-decode from disk and re-verify. This is the path a runtime
        // reboot or the next rotate takes; the create-only test never
        // exercised it, which is why the cap regressions went unnoticed.
        let reread_bytes = std::fs::read(dir.join("identity_document.bin"))
            .expect("read persisted rotated document");
        let reread = IdentityDocument::decode(&reread_bytes)
            .expect("rotated hybrid-1024 document must re-decode within wire caps");
        assert_eq!(reread, rotated.document, "disk round-trip is lossless");
        verify_identity_document(&reread, 1_700_500_000)
            .expect("re-decoded hybrid-1024 document must verify");
    }

    /// Same regression for the Falcon-512 hybrid master.
    #[test]
    fn rotate_hybrid_512_certifies_new_subkey_with_hybrid_master() {
        use veil_types::SignatureAlgorithm;
        let dir = tempdir();
        let issued = 1_700_000_000u64;
        let created = create_identity(create_opts_for(
            dir.clone(),
            SignatureAlgorithm::Ed25519Falcon512Hybrid,
            issued,
        ))
        .expect("hybrid-512 create");

        let rotated = rotate_identity(rotate_opts(dir, created.master_seed.clone()))
            .expect("hybrid-512 rotation must succeed");

        assert_eq!(rotated.document.identity_keys.len(), 2);
        assert_eq!(rotated.document.node_id, created.node_id);
        assert_eq!(
            rotated.document.master_algo,
            veil_proto::identity_document::ALGO_ED25519_FALCON512_HYBRID
        );
        verify_identity_document(&rotated.document, 1_700_500_000)
            .expect("rotated hybrid-512 document must verify");
        assert!(rotated.document.identity_keys[1].master_sig.len() > 64);
    }

    #[test]
    fn rotate_preserves_node_id() {
        let dir = tempdir();
        let created = create_identity(test_opts(dir.clone())).unwrap();
        let master_seed = created.master_seed.clone();
        let rotated = rotate_identity(rotate_opts(dir, master_seed)).unwrap();
        assert_eq!(
            rotated.document.node_id, created.node_id,
            "node_id is stable across rotation"
        );
    }

    #[test]
    fn rotate_rejects_wrong_master_seed() {
        let dir = tempdir();
        let _created = create_identity(test_opts(dir.clone())).unwrap();
        let wrong_seed = Zeroizing::new([0x99u8; MASTER_SEED_LEN]);
        let err = rotate_identity(rotate_opts(dir, wrong_seed)).unwrap_err();
        assert!(
            matches!(err, RotateIdentityError::MasterSeedMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn rotate_rejects_missing_document() {
        let dir = tempdir();
        // No prior create — document file is absent.
        let seed = Zeroizing::new([0x00u8; MASTER_SEED_LEN]);
        let err = rotate_identity(rotate_opts(dir, seed)).unwrap_err();
        assert!(matches!(err, RotateIdentityError::Io(_)), "{err:?}");
    }

    #[test]
    fn rotate_rejects_inverted_freshness_window() {
        let dir = tempdir();
        let created = create_identity(test_opts(dir.clone())).unwrap();
        let master_seed = created.master_seed.clone();
        let opts = RotateIdentityOptions {
            valid_until_unix: 1, // way before now_unix
            now_unix: 1_700_500_000,
            ..rotate_opts(dir, master_seed)
        };
        let err = rotate_identity(opts).unwrap_err();
        assert!(
            matches!(err, RotateIdentityError::FreshnessWindowTooLong { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn rotate_persists_updated_document_to_disk() {
        let dir = tempdir();
        let created = create_identity(test_opts(dir.clone())).unwrap();
        let master_seed = created.master_seed.clone();
        let rotated = rotate_identity(rotate_opts(dir.clone(), master_seed)).unwrap();

        let reread_bytes = std::fs::read(dir.join("identity_document.bin")).unwrap();
        let reread = IdentityDocument::decode(&reread_bytes).unwrap();
        assert_eq!(reread, rotated.document);
    }

    #[test]
    fn rotate_caps_at_max_identity_keys() {
        use veil_proto::identity_document::MAX_IDENTITY_KEYS;
        let dir = tempdir();
        let created = create_identity(test_opts(dir.clone())).unwrap();
        let master_seed = created.master_seed.clone();

        // Rotate enough times to saturate the keys list.
        for _ in 1..MAX_IDENTITY_KEYS {
            rotate_identity(rotate_opts(dir.clone(), master_seed.clone())).unwrap();
        }
        // One more rotation must fail with IdentityKeysFull.
        let err = rotate_identity(rotate_opts(dir, master_seed)).unwrap_err();
        assert!(
            matches!(err, RotateIdentityError::IdentityKeysFull { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn rotate_sequence_produces_distinct_device_ids() {
        // each rotation generates a fresh subkey, so the
        // deterministic `device_id = BLAKE3(pubkey)` differs from the
        // previous one. (Pre the random `bound_instance_id`
        // was preserved across rotations from the on-disk LocalInstance;
        // that field is gone.)
        let dir = tempdir();
        let created = create_identity(test_opts(dir.clone())).unwrap();
        let master_seed = created.master_seed.clone();
        let r1 = rotate_identity(rotate_opts(dir.clone(), master_seed.clone())).unwrap();
        let r2 = rotate_identity(rotate_opts(dir, master_seed)).unwrap();
        let d1 = r1.document.identity_keys[r1.new_identity_key_idx as usize].device_id;
        let d2 = r2.document.identity_keys[r2.new_identity_key_idx as usize].device_id;
        assert_ne!(d1, d2, "fresh rotation must produce a distinct device_id");
    }

    // d removed the entire `revoke_identity` test suite —
    // no in-band revocation flow remains.

    // ── Restore flow (462.8) ──────────────────────────────────────────────

    fn restore_opts(
        dir: PathBuf,
        master_seed: Zeroizing<[u8; MASTER_SEED_LEN]>,
    ) -> RestoreIdentityOptions {
        let now = 1_700_800_000u64;
        RestoreIdentityOptions {
            veil_dir: dir,
            master_seed,
            save_encrypted_with_password: None,
            argon2_params_override: None,
            instance_label: "restored-device".into(),
            pow_difficulty: TEST_POW_DIFFICULTY,
            now_unix: now,
            valid_until_unix: now + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
            master_falcon_keypair_bytes: None,
        }
    }

    #[test]
    fn restore_reproduces_same_node_id_as_original_create() {
        let original_dir = tempdir();
        let created = create_identity(test_opts(original_dir)).unwrap();
        // Simulate: user writes down the BIP-39 phrase, device
        // burns, fresh laptop.
        let phrase = created.master_seed_phrase.to_string();
        let recovered_seed = crate::master_seed::decode_master_seed_from_phrase(&phrase).unwrap();

        let fresh_dir = tempdir();
        let restored = restore_identity(restore_opts(fresh_dir, recovered_seed)).unwrap();

        assert_eq!(
            restored.node_id, created.node_id,
            "node_id must be stable across device-loss recovery"
        );
    }

    #[test]
    fn restored_document_verifies_cleanly() {
        let original = tempdir();
        let created = create_identity(test_opts(original)).unwrap();
        let phrase = created.master_seed_phrase.to_string();
        let seed = crate::master_seed::decode_master_seed_from_phrase(&phrase).unwrap();
        let fresh = tempdir();
        let restored = restore_identity(restore_opts(fresh, seed)).unwrap();
        verify_identity_document(&restored.document, 1_700_800_000)
            .expect("restored document must verify");
    }

    /// hybrid create_identity → preserve master_falcon.bin
    /// → wipe device → restore_identity using BIP-39 phrase + bundle
    /// must reproduce the SAME hybrid node_id and produce a verifying
    /// document.
    #[test]
    fn restore_hybrid_reproduces_node_id_with_falcon_bundle() {
        use veil_types::SignatureAlgorithm;

        // Step 1: create hybrid identity, capture phrase + falcon bundle.
        let original_dir = tempdir();
        let issued = 1_700_000_000u64;
        let created = create_identity(CreateIdentityOptions {
            veil_dir: original_dir.clone(),
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: "hybrid-laptop".into(),
            pow_difficulty: TEST_POW_DIFFICULTY,
            issued_at_unix: issued,
            valid_until_unix: issued + 7 * 86_400,
            algo: SignatureAlgorithm::Ed25519Falcon512Hybrid,
        })
        .expect("hybrid create");
        let original_node_id = created.node_id;
        let phrase = created.master_seed_phrase.to_string();
        let falcon_bundle = std::fs::read(
            created
                .master_falcon_path
                .as_ref()
                .expect("master_falcon_path must be set for hybrid create"),
        )
        .expect("read master_falcon.bin");

        // Step 2: simulate device loss + paper-backup-only restore.
        let recovered_seed = crate::master_seed::decode_master_seed_from_phrase(&phrase).unwrap();

        let fresh_dir = tempdir();
        let now = 1_700_800_000u64;
        let restored = restore_identity(RestoreIdentityOptions {
            veil_dir: fresh_dir.clone(),
            master_seed: recovered_seed,
            save_encrypted_with_password: None,
            argon2_params_override: None,
            instance_label: "restored-hybrid-laptop".into(),
            pow_difficulty: TEST_POW_DIFFICULTY,
            now_unix: now,
            valid_until_unix: now + 7 * 86_400,
            algo: SignatureAlgorithm::Ed25519Falcon512Hybrid,
            master_falcon_keypair_bytes: Some(falcon_bundle.clone()),
        })
        .expect("hybrid restore");

        // Same node_id ⇒ master_pubkey (929 B hybrid pk) reproduced.
        assert_eq!(
            restored.node_id, original_node_id,
            "hybrid restore must reproduce the original node_id"
        );
        // Document verifies cleanly under canonical hybrid verify.
        verify_identity_document(&restored.document, now)
            .expect("restored hybrid document must verify");
        // master_falcon.bin re-saved in the new veil_dir.
        let restored_falcon_path = restored
            .master_falcon_path
            .as_ref()
            .expect("master_falcon_path must be set on hybrid restore");
        assert!(restored_falcon_path.exists());
        let restored_bundle = std::fs::read(restored_falcon_path).unwrap();
        // Round-trip preserves the bundle bytes verbatim (same SK + PK
        // bundled in framed format).
        assert_eq!(restored_bundle, falcon_bundle);
    }

    /// hybrid restore without master_falcon_keypair_bytes
    /// surfaces `MissingFalconMaster` instead of silently producing a
    /// degraded Ed25519-only identity (which would change the
    /// node_id and lose name-claim continuity).
    #[test]
    fn restore_hybrid_rejects_missing_falcon_bundle() {
        use veil_types::SignatureAlgorithm;

        let dir = tempdir();
        let now = 1_700_800_000u64;
        let dummy_seed = Zeroizing::new([0u8; MASTER_SEED_LEN]);
        let err = restore_identity(RestoreIdentityOptions {
            veil_dir: dir,
            master_seed: dummy_seed,
            save_encrypted_with_password: None,
            argon2_params_override: None,
            instance_label: "nope".into(),
            pow_difficulty: TEST_POW_DIFFICULTY,
            now_unix: now,
            valid_until_unix: now + 7 * 86_400,
            algo: SignatureAlgorithm::Ed25519Falcon512Hybrid,
            master_falcon_keypair_bytes: None, // ← the operator forgot to back up.
        })
        .expect_err("must reject hybrid restore without master_falcon bundle");
        assert!(
            matches!(err, RestoreIdentityError::MissingFalconMaster),
            "expected MissingFalconMaster, got {err:?}"
        );
    }

    #[test]
    fn restore_uses_fresh_identity_sk_not_original() {
        // Fresh device gets a DIFFERENT identity_sk — the one the
        // original device had is still valid under the master's
        // cert, but we don't reconstruct it. Only node_id is
        // stable.
        let original = tempdir();
        let created = create_identity(test_opts(original)).unwrap();
        let phrase = created.master_seed_phrase.to_string();
        let seed = crate::master_seed::decode_master_seed_from_phrase(&phrase).unwrap();
        let fresh = tempdir();
        let restored = restore_identity(restore_opts(fresh, seed)).unwrap();
        assert_ne!(
            created.document.identity_keys[0].pubkey, restored.document.identity_keys[0].pubkey,
            "each device draws its own identity_sk"
        );
    }

    #[test]
    fn restore_rejects_inverted_freshness_window() {
        let dir = tempdir();
        let seed = Zeroizing::new([0u8; MASTER_SEED_LEN]);
        let opts = RestoreIdentityOptions {
            valid_until_unix: 1,
            now_unix: 1_700_800_000,
            ..restore_opts(dir, seed)
        };
        let err = restore_identity(opts).unwrap_err();
        assert!(
            matches!(err, RestoreIdentityError::FreshnessWindowTooLong { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn restore_creates_veil_dir_if_missing() {
        let parent = tempdir();
        let nested = parent.join("never").join("existed");
        assert!(!nested.exists());
        let seed = Zeroizing::new([0x42u8; MASTER_SEED_LEN]);
        restore_identity(restore_opts(nested.clone(), seed)).unwrap();
        assert!(nested.exists());
        assert!(nested.join(IDENTITY_DOCUMENT_FILE).exists());
    }

    #[test]
    fn restore_saves_encrypted_master_when_requested() {
        let dir = tempdir();
        let seed = Zeroizing::new([0x77u8; MASTER_SEED_LEN]);
        let opts = RestoreIdentityOptions {
            save_encrypted_with_password: Some(Zeroizing::new(b"new-pw".to_vec())),
            argon2_params_override: Some((16 * 1024, 1, 1)),
            ..restore_opts(dir.clone(), seed.clone())
        };
        let out = restore_identity(opts).unwrap();
        let path = out.encrypted_master_path.as_ref().unwrap();
        assert!(path.exists());
        let decoded = crate::master_file::load_master_seed_encrypted(path, b"new-pw").unwrap();
        assert_eq!(*seed, *decoded);
    }

    #[test]
    fn restore_persists_document_atomically() {
        let dir = tempdir();
        let seed = Zeroizing::new([0x55u8; MASTER_SEED_LEN]);
        let out = restore_identity(restore_opts(dir.clone(), seed)).unwrap();
        let reread = std::fs::read(dir.join(IDENTITY_DOCUMENT_FILE)).unwrap();
        let decoded = IdentityDocument::decode(&reread).unwrap();
        assert_eq!(decoded, out.document);
    }

    #[test]
    fn restore_has_single_identity_key_not_full_list() {
        // Recovery on a fresh device produces a single-key
        // document — the other devices' subkeys are NOT
        // reconstructed (they're lost along with their SKs).
        // The app layer is expected to re-pair other devices
        // afterward (or let them naturally fetch via DHT and
        // call rotate to append themselves).
        let dir = tempdir();
        let seed = Zeroizing::new([0x66u8; MASTER_SEED_LEN]);
        let out = restore_identity(restore_opts(dir, seed)).unwrap();
        assert_eq!(out.document.identity_keys.len(), 1);
        assert_eq!(out.document.sig_key_idx, 0);
    }

    #[test]
    fn restore_then_rotate_composes_correctly() {
        // After restore, the user should be able to do normal
        // ongoing rotations just like create.
        let dir = tempdir();
        let seed_bytes = [0x88u8; MASTER_SEED_LEN];
        let seed = Zeroizing::new(seed_bytes);
        restore_identity(restore_opts(dir.clone(), seed)).unwrap();

        let rotate_seed = Zeroizing::new(seed_bytes);
        let rotated = rotate_identity(rotate_opts(dir, rotate_seed)).unwrap();
        assert_eq!(rotated.document.identity_keys.len(), 2);
    }

    #[test]
    fn rotate_then_fresh_start_produces_different_node_id() {
        // Safety guard: a rotation keeps node_id stable, but a
        // fresh `create_identity` with new master_seed bytes (new
        // seed drawn from OsRng each call) produces a new identity.
        let dir = tempdir();
        let created = create_identity(test_opts(dir.clone())).unwrap();
        let master_seed = created.master_seed.clone();
        let rotated = rotate_identity(rotate_opts(dir.clone(), master_seed)).unwrap();
        assert_eq!(rotated.document.node_id, created.node_id);
        // Second create_identity in the SAME dir overwrites — gives
        // a new node_id (this behaviour is asserted already).
        let fresh = create_identity(test_opts(dir)).unwrap();
        assert_ne!(fresh.node_id, created.node_id);
    }

    // ── Paired-target persistence ────────────────────────────

    #[test]
    fn device_sig_key_idx_round_trip_writes_and_reads_u16_be() {
        let dir = tempdir();
        save_device_sig_key_idx(&dir, 7).unwrap();
        assert_eq!(load_device_sig_key_idx(&dir).unwrap(), Some(7));
        // Written exactly 2 bytes, big-endian.
        let raw = std::fs::read(dir.join(DEVICE_SIG_KEY_IDX_FILE)).unwrap();
        assert_eq!(raw, vec![0x00, 0x07]);
    }

    #[test]
    fn device_sig_key_idx_absent_returns_none() {
        let dir = tempdir();
        assert_eq!(load_device_sig_key_idx(&dir).unwrap(), None);
    }

    #[test]
    fn device_sig_key_idx_malformed_length_is_invalid_data() {
        let dir = tempdir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(DEVICE_SIG_KEY_IDX_FILE), [0u8; 3]).unwrap();
        let err = load_device_sig_key_idx(&dir).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn save_paired_target_state_writes_all_four_files() {
        use crate::instance::{LocalInstance, default_instance_path};
        use veil_proto::identity_document::IdentityKey;

        // Seed the target dir from a source-side `create_identity`
        // then append a fake target IdentityKey so we can exercise
        // the persistence path against a real document shape.
        let dir = tempdir();
        let created = create_identity(test_opts(dir.clone())).unwrap();
        let mut doc = created.document;
        let fake_target_pk = [0x99u8; 32];
        let fake_target_instance = [0x55u8; 16];
        doc.identity_keys.push(IdentityKey {
            algo: ALGO_ED25519,
            pubkey: fake_target_pk.to_vec(),
            device_id: veil_crypto::identity::compute_node_id(&fake_target_pk),
            valid_from_unix: 1_700_000_000,
            valid_until_unix: 1_700_000_000 + 7 * 86_400,
            master_sig: vec![0xAA; 64], // fake — persistence
                                        // doesn't verify sigs
        });
        let target_idx = (doc.identity_keys.len() - 1) as u16;

        let tgt_dir = tempdir();
        let tgt_sk_seed: SensitiveBytesN<32> = SensitiveBytesN::from_bytes([0x42u8; 32]);
        save_paired_target_state(
            &tgt_dir,
            &doc,
            &tgt_sk_seed,
            target_idx,
            fake_target_instance,
            "laptop",
        )
        .unwrap();

        assert!(tgt_dir.join(IDENTITY_DOCUMENT_FILE).exists());
        assert!(tgt_dir.join(DEVICE_IDENTITY_SK_FILE).exists());
        assert!(tgt_dir.join(DEVICE_SIG_KEY_IDX_FILE).exists());
        assert!(default_instance_path(&tgt_dir).exists());

        // Override file carries the target's idx.
        assert_eq!(load_device_sig_key_idx(&tgt_dir).unwrap(), Some(target_idx));

        // instance_id file carries the target's fresh instance.
        let inst = LocalInstance::load(&default_instance_path(&tgt_dir)).unwrap();
        assert_eq!(inst.instance_id, fake_target_instance);
        assert_eq!(inst.label, "laptop");
    }

    #[test]
    fn save_paired_target_state_round_trips_through_load_from_dir() {
        use crate::sovereign::SovereignIdentity;
        use ed25519_dalek::SigningKey as EdSk;
        use veil_proto::identity_document::IdentityKey;

        // Provision a source, then append a "target device"
        // IdentityKey whose SK seed we know; save paired target
        // state into a second dir and load it back.
        let src_dir = tempdir();
        let created = create_identity(test_opts(src_dir)).unwrap();
        let mut doc = created.document;
        let tgt_seed: SensitiveBytesN<32> = SensitiveBytesN::from_bytes([0xCDu8; 32]);
        let tgt_sk = EdSk::from_bytes(tgt_seed.as_array());
        let tgt_pk = tgt_sk.verifying_key();
        doc.identity_keys.push(IdentityKey {
            algo: ALGO_ED25519,
            pubkey: tgt_pk.as_bytes().to_vec(),
            device_id: veil_crypto::identity::compute_node_id(tgt_pk.as_bytes()),
            valid_from_unix: 1_700_000_000,
            valid_until_unix: 1_700_000_000 + 7 * 86_400,
            master_sig: vec![0u8; 64],
        });
        let tgt_idx = (doc.identity_keys.len() - 1) as u16;

        let tgt_dir = tempdir();
        save_paired_target_state(&tgt_dir, &doc, &tgt_seed, tgt_idx, [0xEE; 16], "phone").unwrap();

        let sov = SovereignIdentity::load_from_dir(&tgt_dir).expect("load");
        assert_eq!(sov.sig_key_idx, tgt_idx);
        // device_id is deterministic from the appended target
        // pubkey rather than the random `[0xEE; 16]` legacy tag.
        assert_eq!(
            sov.active_device_id(),
            veil_crypto::identity::compute_node_id(tgt_pk.as_bytes()),
        );
        assert_eq!(sov.node_id(), &created.node_id);
    }

    #[test]
    fn save_paired_target_state_rejects_out_of_bounds_idx() {
        let dir = tempdir();
        let created = create_identity(test_opts(dir)).unwrap();
        let doc = created.document;
        let n_keys = doc.identity_keys.len() as u16;

        let tgt_dir = tempdir();
        let placeholder: SensitiveBytesN<32> = SensitiveBytesN::new();
        let err = save_paired_target_state(
            &tgt_dir,
            &doc,
            &placeholder,
            n_keys, // one past the end
            [0u8; 16],
            "phone",
        )
        .unwrap_err();
        assert!(
            matches!(err, PairedTargetPersistError::SigKeyIdxOutOfBounds { .. }),
            "{err:?}"
        );
    }

    // ── Standalone-mode flow ──────────────────────────────────

    fn fixed_seed() -> SensitiveBytesN<32> {
        SensitiveBytesN::from_bytes([0x42u8; 32])
    }

    #[test]
    fn standalone_doc_collapses_master_and_device_pubkey() {
        let now = 1_700_000_000u64;
        let valid_until = now + DELEGATION_VALIDITY_SECS;
        let doc = build_standalone_identity_document(&fixed_seed(), now, valid_until)
            .expect("standalone build");
        // master_pk == device_pk == the lone subkey's pubkey.
        assert_eq!(doc.master_pubkey, doc.identity_keys[0].pubkey);
        // node_id == BLAKE3(pubkey) == identity_keys[0].device_id.
        assert_eq!(
            doc.node_id,
            veil_crypto::identity::compute_node_id(&doc.master_pubkey),
        );
        assert_eq!(doc.node_id, doc.identity_keys[0].device_id);
    }

    #[test]
    fn standalone_doc_passes_full_verifier() {
        use crate::verify::verify_identity_document;
        let now = 1_700_000_000u64;
        let valid_until = now + DELEGATION_VALIDITY_SECS;
        let doc = build_standalone_identity_document(&fixed_seed(), now, valid_until)
            .expect("standalone build");
        let validated =
            verify_identity_document(&doc, now).expect("standalone document must verify");
        // The active subkey IS the master pubkey.
        assert_eq!(validated.active_identity_pubkey, doc.master_pubkey);
        assert_eq!(validated.node_id, doc.node_id);
        assert_eq!(validated.active_device_id, doc.node_id);
    }

    #[test]
    fn standalone_doc_rejects_inverted_window() {
        let err = build_standalone_identity_document(&fixed_seed(), 100, 50).unwrap_err();
        assert!(
            matches!(err, CreateIdentityError::FreshnessWindowTooLong { .. }),
            "{err:?}",
        );
    }

    #[test]
    fn standalone_doc_rejects_oversized_window() {
        let err =
            build_standalone_identity_document(&fixed_seed(), 0, MAX_FRESHNESS_WINDOW_SECS + 1)
                .unwrap_err();
        assert!(
            matches!(err, CreateIdentityError::FreshnessWindowTooLong { .. }),
            "{err:?}",
        );
    }

    #[test]
    fn save_standalone_persists_doc_and_sk_and_loads_via_sovereign_identity() {
        use crate::sovereign::SovereignIdentity;

        let dir = tempdir();
        let now = 1_700_000_000u64;
        let valid_until = now + DELEGATION_VALIDITY_SECS;
        let written = save_standalone_identity_to_dir(&dir, &fixed_seed(), now, valid_until)
            .expect("standalone save");

        // Both files exist under veil_dir.
        assert!(dir.join(IDENTITY_DOCUMENT_FILE).exists());
        assert!(dir.join(DEVICE_IDENTITY_SK_FILE).exists());

        // SovereignIdentity::load_from_dir picks the doc up + matches
        // the SK to the active subkey (master == device, so the SK
        // produces the master_pubkey AND the active subkey pubkey).
        let sov = SovereignIdentity::load_from_dir(&dir).expect("load");
        assert_eq!(sov.node_id(), &written.node_id);
        assert_eq!(sov.active_device_id(), written.node_id);
    }

    #[test]
    fn standalone_node_id_matches_cfg_node_id() {
        // Pin the equivalence between sovereign-id derivation and the
        // cfg::NodeId derivation that the runtime keys handshakes on.
        // In standalone mode they coincide byte-for-byte against the
        // device pubkey. Both reduce to a bare BLAKE3 over the raw
        // public key bytes (part 1 dropped the legacy
        // domain-tag prefix from `compute_node_id`).
        use ed25519_dalek::SigningKey;
        let seed = fixed_seed();
        let sk = SigningKey::from_bytes(seed.as_array());
        let pk = sk.verifying_key();

        let now = 1_700_000_000u64;
        let valid_until = now + DELEGATION_VALIDITY_SECS;
        let doc = build_standalone_identity_document(&seed, now, valid_until).expect("standalone");

        let cfg_node_id = *blake3::hash(pk.as_bytes()).as_bytes();
        assert_eq!(
            doc.node_id, cfg_node_id,
            "standalone sovereign node_id MUST equal BLAKE3(device_pubkey)",
        );
    }

    // ── Falcon-512 combined-file persistence ────────

    #[test]
    fn phase647_c3_falcon_keypair_save_load_round_trip() {
        use crate::signing_key::IdentitySigningKey;
        let dir = crate::test_support::scratch_dir("veil-falcon-c3-roundtrip");
        let (sk, pk_bytes) = IdentitySigningKey::generate_falcon512();
        let sk_bytes = Zeroizing::new(sk.raw_secret_bytes());
        save_identity_falcon_keypair(&dir, &sk_bytes, &pk_bytes).expect("save");
        // ONE file (combined SK+PK).
        assert!(dir.join(DEVICE_IDENTITY_FALCON_FILE).exists());
        // Round-trip.
        let (sk2_bytes, pk2_bytes) = load_identity_falcon_keypair(&dir).expect("load");
        assert_eq!(&*sk2_bytes, &*sk_bytes);
        assert_eq!(pk2_bytes, pk_bytes);
        // Reconstructed SK signs verifiably under the original PK.
        let sk2 = IdentitySigningKey::from_falcon512_bytes(&sk2_bytes, &pk2_bytes).unwrap();
        sk2.verify_skpk_match(&pk_bytes)
            .expect("loaded SK signs valid sigs");
    }

    #[test]
    fn phase647_c3_falcon_file_has_unix_mode_0o600() {
        #[cfg(unix)]
        {
            use crate::signing_key::IdentitySigningKey;
            use std::os::unix::fs::PermissionsExt;
            let dir = crate::test_support::scratch_dir("veil-falcon-c3-mode");
            let (sk, pk_bytes) = IdentitySigningKey::generate_falcon512();
            let sk_bytes = Zeroizing::new(sk.raw_secret_bytes());
            save_identity_falcon_keypair(&dir, &sk_bytes, &pk_bytes).expect("save");
            let meta = std::fs::metadata(dir.join(DEVICE_IDENTITY_FALCON_FILE)).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "combined Falcon file must be 0o600 (contains SK material)"
            );
        }
    }

    /// regression: single-file format makes
    /// rollback **impossible to corrupt** — there is no second-rename
    /// branch. A failed save leaves either:
    /// * the previous file unchanged (rename never landed), or
    /// * the new file fully present.
    ///
    /// We exercise the "rotation succeeded" path explicitly and
    /// confirm the new content replaced the old.
    #[test]
    fn phase647_c3_falcon_save_replaces_old_atomically() {
        use crate::signing_key::IdentitySigningKey;
        let dir = crate::test_support::scratch_dir("veil-falcon-c3-rotation");
        // First save.
        let (sk1, pk1) = IdentitySigningKey::generate_falcon512();
        let sk1_bytes = Zeroizing::new(sk1.raw_secret_bytes());
        save_identity_falcon_keypair(&dir, &sk1_bytes, &pk1).expect("save 1");
        // Second save (rotation).
        let (sk2, pk2) = IdentitySigningKey::generate_falcon512();
        let sk2_bytes = Zeroizing::new(sk2.raw_secret_bytes());
        save_identity_falcon_keypair(&dir, &sk2_bytes, &pk2).expect("save 2");
        // Disk now holds the v2 keypair, NOT the v1 keypair.
        let (sk_loaded, pk_loaded) = load_identity_falcon_keypair(&dir).expect("load");
        assert_eq!(&*sk_loaded, &*sk2_bytes);
        assert_eq!(pk_loaded, pk2);
        assert_ne!(
            &*sk_loaded, &*sk1_bytes,
            "rotation must replace v1 SK on disk"
        );
    }

    /// file-format guards.
    #[test]
    fn phase647_c3_falcon_decoder_rejects_malformed() {
        use std::io::ErrorKind;
        // Truncated header.
        let err = decode_falcon_keypair(b"OFA").unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        // Bad magic.
        let bad_magic = b"XXXX\x01\x00\x00\x00\x00\x00\x00\x00\x00";
        let err = decode_falcon_keypair(bad_magic).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        // Wrong version.
        let bad_ver = b"OFAL\x99\x00\x00\x00\x00\x00\x00\x00\x00";
        let err = decode_falcon_keypair(bad_ver).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        // Truncated SK.
        let mut buf = Vec::new();
        buf.extend_from_slice(b"OFAL");
        buf.push(1);
        buf.extend_from_slice(&100u32.to_be_bytes()); // sk_len = 100
        buf.extend_from_slice(&[0u8; 50]); // only 50 SK bytes present
        let err = decode_falcon_keypair(&buf).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        // Trailing bytes after PK.
        let dir = crate::test_support::scratch_dir("veil-falcon-c3-trailing");
        use crate::signing_key::IdentitySigningKey;
        let (sk, pk) = IdentitySigningKey::generate_falcon512();
        let sk_bytes = Zeroizing::new(sk.raw_secret_bytes());
        save_identity_falcon_keypair(&dir, &sk_bytes, &pk).unwrap();
        let path = dir.join(DEVICE_IDENTITY_FALCON_FILE);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.push(0xFF); // tamper: trailing byte
        let err = decode_falcon_keypair(&bytes).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn phase647_c3_falcon_oversized_file_rejected() {
        use std::io::ErrorKind;
        let dir = crate::test_support::scratch_dir("veil-falcon-c3-oversize");
        std::fs::create_dir_all(&dir).unwrap();
        // Write a file larger than DEVICE_IDENTITY_FALCON_MAX_BYTES.
        let huge = vec![0u8; DEVICE_IDENTITY_FALCON_MAX_BYTES + 1];
        std::fs::write(dir.join(DEVICE_IDENTITY_FALCON_FILE), &huge).unwrap();
        let err = load_identity_falcon_keypair(&dir).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn phase647_c3_unified_loader_picks_ed25519_when_only_ed25519_present() {
        use crate::signing_key::IdentitySigningKey;
        use veil_proto::identity_document::ALGO_ED25519;
        let dir = crate::test_support::scratch_dir("veil-c3-ed25519-only");
        let mut seed: SensitiveBytesN<32> = SensitiveBytesN::new();
        rand_core::OsRng.fill_bytes(seed.as_mut_array());
        save_identity_sk(&dir, &seed).expect("save ed25519 sk");
        let sk = load_identity_signing_key(&dir).expect("load");
        assert_eq!(sk.algo(), ALGO_ED25519);
        sk.verify_skpk_match(&sk.public_key_bytes())
            .expect("self-verify");
        let _ = IdentitySigningKey::from_ed25519_seed(*seed.as_array());
    }

    #[test]
    fn phase647_c3_unified_loader_picks_falcon_when_only_falcon_present() {
        use crate::signing_key::IdentitySigningKey;
        use veil_proto::identity_document::ALGO_FALCON512;
        let dir = crate::test_support::scratch_dir("veil-c3-falcon-only");
        let (sk, pk_bytes) = IdentitySigningKey::generate_falcon512();
        let sk_bytes = Zeroizing::new(sk.raw_secret_bytes());
        save_identity_falcon_keypair(&dir, &sk_bytes, &pk_bytes).expect("save");
        let loaded = load_identity_signing_key(&dir).expect("load");
        assert_eq!(loaded.algo(), ALGO_FALCON512);
        loaded
            .verify_skpk_match(&pk_bytes)
            .expect("falcon sk verify");
    }

    #[test]
    fn phase647_c3_unified_loader_prefers_ed25519_when_both_present() {
        use crate::signing_key::IdentitySigningKey;
        use veil_proto::identity_document::ALGO_ED25519;
        let dir = crate::test_support::scratch_dir("veil-c3-both");
        let mut seed: SensitiveBytesN<32> = SensitiveBytesN::new();
        rand_core::OsRng.fill_bytes(seed.as_mut_array());
        save_identity_sk(&dir, &seed).expect("save ed25519 sk");
        let (falcon, falcon_pk) = IdentitySigningKey::generate_falcon512();
        let falcon_bytes = Zeroizing::new(falcon.raw_secret_bytes());
        save_identity_falcon_keypair(&dir, &falcon_bytes, &falcon_pk).expect("save");
        let sk = load_identity_signing_key(&dir).expect("load");
        assert_eq!(sk.algo(), ALGO_ED25519);
    }

    #[test]
    fn phase647_c3_unified_loader_errors_when_neither_present() {
        let dir = crate::test_support::scratch_dir("veil-c3-empty");
        let err = load_identity_signing_key(&dir).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }
}
