use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use pqcrypto_falcon::{falcon512, falcon1024};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use rand_core::OsRng;
use zeroize::Zeroizing;

use veil_error::{ConfigError, Result};
use veil_types::SignatureAlgorithm;

/// Published constant from pqcrypto-falcon — Falcon-1024 pubkey is exactly
/// 1793 bytes on every supported backend (CLEAN / AVX2 / AArch64).  Pinned
/// here as a compile-time const so the hybrid split helper can be a pure
/// slice operation without re-querying the FFI module.
const FALCON1024_PK_LEN: usize = 1793;

/// Hybrid public-key wire length for Ed25519 + Falcon-1024 (Phase 10):
/// 32 (ed25519) + 1793 (falcon-1024) = 1825 bytes.  Fixed-size layout
/// (no length prefix needed because both components have known sizes).
const HYBRID_1024_PK_LEN: usize = 32 + FALCON1024_PK_LEN;

#[derive(Clone, PartialEq, Eq)]
pub struct GeneratedKeyPair {
    pub algo: SignatureAlgorithm,
    pub public_key: String,
    pub private_key: String,
}

impl std::fmt::Debug for GeneratedKeyPair {
    /// Redacting `Debug` — a stray `debug!("{kp:?}")` must NOT leak signing
    /// material. Mirrors the redacted-Debug pattern on the sibling key-wrapper
    /// types (e.g. `types::Base64PrivateKey`). The previous `#[derive(Debug)]`
    /// printed the base64 private key in full.
    ///
    /// (Zeroize-on-drop is intentionally NOT added here: `GeneratedKeyPair` is a
    /// public, by-value-consumed type — callers move `public_key` / `private_key`
    /// out of it — so a `Drop` impl would break those moves. The redacting Debug
    /// closes the realistic leak vector; long-lived secrets are wrapped in
    /// `Zeroizing`/`SensitiveBytes` at their storage sites instead.)
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedKeyPair")
            .field("algo", &self.algo)
            .field("public_key", &self.public_key)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

pub fn generate_keypair(algo: SignatureAlgorithm) -> GeneratedKeyPair {
    match algo {
        SignatureAlgorithm::Ed25519 => {
            let signing_key = SigningKey::generate(&mut OsRng);
            GeneratedKeyPair {
                algo,
                public_key: STANDARD.encode(signing_key.verifying_key().to_bytes()),
                private_key: STANDARD.encode(signing_key.to_bytes()),
            }
        }
        SignatureAlgorithm::Falcon512 => {
            let (public_key, private_key) = falcon512::keypair();
            GeneratedKeyPair {
                algo,
                public_key: STANDARD.encode(public_key.as_bytes()),
                private_key: STANDARD.encode(private_key.as_bytes()),
            }
        }
        SignatureAlgorithm::Ed25519Falcon512Hybrid => {
            // hybrid mode generates BOTH a classical Ed25519
            // keypair AND a post-quantum Falcon-512 keypair. Hybrid
            // public_key bytes = ed_pk(32) || falcon_pk(897) — fixed
            // sizes, no length prefix needed since both are known.
            // Hybrid private_key bytes use the same concatenation
            // with a u16-LE length prefix on the Falcon SK because
            // pqcrypto-falcon's secret-key length depends on the
            // underlying implementation (some emit 1281 bytes, some
            // 1280); the length prefix makes the wire format
            // self-describing across pqcrypto-falcon version bumps.
            let ed = SigningKey::generate(&mut OsRng);
            let (fal_pk, fal_sk) = falcon512::keypair();
            let fal_pk_bytes = fal_pk.as_bytes();
            let fal_sk_bytes = fal_sk.as_bytes();
            // Audit batch 2026-05-25 phase M: convert from `assert_eq!`
            // (stripped in release with panic-on-debug-only) to
            // unconditional panic.  If pqcrypto-falcon ever regresses
            // the published Falcon-512 size constant, release builds
            // would silently generate malformed hybrid keys whose pk
            // layout no longer match `split_hybrid_pk` (32 + 897).
            // We want to fail-loudly everywhere, not only in debug.
            if fal_pk_bytes.len() != 897 {
                panic!(
                    "Falcon-512 pubkey size invariant changed: expected 897, got {} — \
                     pqcrypto-falcon dependency regression",
                    fal_pk_bytes.len()
                );
            }

            let mut pk = Vec::with_capacity(32 + 897);
            pk.extend_from_slice(&ed.verifying_key().to_bytes());
            pk.extend_from_slice(fal_pk_bytes);

            let fal_sk_len = fal_sk_bytes.len();
            let mut sk = Vec::with_capacity(32 + 2 + fal_sk_len);
            sk.extend_from_slice(&ed.to_bytes());
            sk.extend_from_slice(&(fal_sk_len as u16).to_le_bytes());
            sk.extend_from_slice(fal_sk_bytes);

            GeneratedKeyPair {
                algo,
                public_key: STANDARD.encode(&pk),
                private_key: STANDARD.encode(&sk),
            }
        }
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => {
            // hybrid mode for Falcon-1024 (Phase 10) — same construction
            // as the Falcon-512 hybrid above but swaps the PQ component
            // for Falcon-1024.  pk layout = ed_pk(32) || falcon_pk(1793)
            // (HYBRID_1024_PK_LEN = 1825); sk layout = ed_sk(32) ||
            // u16_le(falcon_sk_len) || falcon_sk (typically ~2305 bytes).
            let ed = SigningKey::generate(&mut OsRng);
            let (fal_pk, fal_sk) = falcon1024::keypair();
            let fal_pk_bytes = fal_pk.as_bytes();
            let fal_sk_bytes = fal_sk.as_bytes();
            if fal_pk_bytes.len() != FALCON1024_PK_LEN {
                panic!(
                    "Falcon-1024 pubkey size invariant changed: expected {}, got {} — \
                     pqcrypto-falcon dependency regression",
                    FALCON1024_PK_LEN,
                    fal_pk_bytes.len()
                );
            }

            let mut pk = Vec::with_capacity(HYBRID_1024_PK_LEN);
            pk.extend_from_slice(&ed.verifying_key().to_bytes());
            pk.extend_from_slice(fal_pk_bytes);

            let fal_sk_len = fal_sk_bytes.len();
            let mut sk = Vec::with_capacity(32 + 2 + fal_sk_len);
            sk.extend_from_slice(&ed.to_bytes());
            sk.extend_from_slice(&(fal_sk_len as u16).to_le_bytes());
            sk.extend_from_slice(fal_sk_bytes);

            GeneratedKeyPair {
                algo,
                public_key: STANDARD.encode(&pk),
                private_key: STANDARD.encode(&sk),
            }
        }
    }
}

pub fn sign_message(
    algo: SignatureAlgorithm,
    public_key_base64: &str,
    private_key_base64: &str,
    message: &[u8],
) -> Result<Vec<u8>> {
    match algo {
        SignatureAlgorithm::Ed25519 => {
            let _ = decode_public_key(algo, public_key_base64)?;
            let private_key = decode_private_key(algo, private_key_base64)?;
            let signing_key =
                SigningKey::from_bytes(&private_key.as_slice().try_into().map_err(|_| {
                    ConfigError::InvalidKeyLength {
                        algo: algo.to_string(),
                        key_kind: "private key",
                        expected: 32,
                        actual: private_key.len(),
                    }
                })?);
            Ok(signing_key.sign(message).to_bytes().to_vec())
        }
        SignatureAlgorithm::Falcon512 => {
            let _ = decode_public_key(algo, public_key_base64)?;
            let private_key =
                falcon512::SecretKey::from_bytes(&decode_private_key(algo, private_key_base64)?)
                    .map_err(|err| ConfigError::InvalidCryptoMaterial {
                        algo: algo.to_string(),
                        item: "private key",
                        details: err.to_string(),
                    })?;
            Ok(falcon512::detached_sign(message, &private_key)
                .as_bytes()
                .to_vec())
        }
        SignatureAlgorithm::Ed25519Falcon512Hybrid => {
            // signs with both algorithms. Hybrid signature
            // wire format: [64 B ed25519_sig][2 B u16-LE falcon_sig_len]
            // [falcon_sig_len B falcon_sig]. The length prefix lets
            // verify split the bytes deterministically without depending
            // on pqcrypto-falcon's internal variable-length encoding.
            let _ = decode_public_key(algo, public_key_base64)?;
            let sk_bytes = decode_private_key(algo, private_key_base64)?;
            let (ed_sk_bytes, fal_sk_bytes) = split_hybrid_sk(&sk_bytes)?;

            let ed_signing_key = SigningKey::from_bytes(&ed_sk_bytes.try_into().map_err(|_| {
                ConfigError::InvalidKeyLength {
                    algo: algo.to_string(),
                    key_kind: "ed25519 private key",
                    expected: 32,
                    actual: ed_sk_bytes.len(),
                }
            })?);
            let ed_sig = ed_signing_key.sign(message).to_bytes();

            let fal_sk = falcon512::SecretKey::from_bytes(fal_sk_bytes).map_err(|err| {
                ConfigError::InvalidCryptoMaterial {
                    algo: algo.to_string(),
                    item: "falcon-512 private key",
                    details: err.to_string(),
                }
            })?;
            let fal_sig = falcon512::detached_sign(message, &fal_sk);
            let fal_sig_bytes = fal_sig.as_bytes();

            // Enforce verifier-side cap (`MAX_FALCON_SIG_BYTES = 768`)
            // on the sign side too — fail fast if a future
            // `pqcrypto-falcon` regression OR a patched build produces
            // signatures que verifiers would reject anyway.  Previously
            // signer only paid the verifier cap implicitly; explicit
            // check turns a silent compat-break into a clean error.
            if fal_sig_bytes.len() > MAX_FALCON_SIG_BYTES {
                return Err(ConfigError::InvalidCryptoMaterial {
                    algo: algo.to_string(),
                    item: "falcon-512 signature",
                    details: format!(
                        "signature too long: {} > MAX_FALCON_SIG_BYTES={}",
                        fal_sig_bytes.len(),
                        MAX_FALCON_SIG_BYTES,
                    ),
                });
            }

            let mut out = Vec::with_capacity(64 + 2 + fal_sig_bytes.len());
            out.extend_from_slice(&ed_sig);
            out.extend_from_slice(&(fal_sig_bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(fal_sig_bytes);
            Ok(out)
        }
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => {
            // Etap 10: parallel hybrid sign for Falcon-1024.  Same wire
            // shape as Falcon-512 hybrid: [64 B ed_sig][2 B u16-LE
            // fal_sig_len][fal_sig_len B fal_sig].
            let _ = decode_public_key(algo, public_key_base64)?;
            let sk_bytes = decode_private_key(algo, private_key_base64)?;
            let (ed_sk_bytes, fal_sk_bytes) = split_hybrid_1024_sk(&sk_bytes)?;

            let ed_signing_key = SigningKey::from_bytes(&ed_sk_bytes.try_into().map_err(|_| {
                ConfigError::InvalidKeyLength {
                    algo: algo.to_string(),
                    key_kind: "ed25519 private key",
                    expected: 32,
                    actual: ed_sk_bytes.len(),
                }
            })?);
            let ed_sig = ed_signing_key.sign(message).to_bytes();

            let fal_sk = falcon1024::SecretKey::from_bytes(fal_sk_bytes).map_err(|err| {
                ConfigError::InvalidCryptoMaterial {
                    algo: algo.to_string(),
                    item: "falcon-1024 private key",
                    details: err.to_string(),
                }
            })?;
            let fal_sig = falcon1024::detached_sign(message, &fal_sk);
            let fal_sig_bytes = fal_sig.as_bytes();

            if fal_sig_bytes.len() > MAX_FALCON1024_SIG_BYTES {
                return Err(ConfigError::InvalidCryptoMaterial {
                    algo: algo.to_string(),
                    item: "falcon-1024 signature",
                    details: format!(
                        "signature too long: {} > MAX_FALCON1024_SIG_BYTES={}",
                        fal_sig_bytes.len(),
                        MAX_FALCON1024_SIG_BYTES,
                    ),
                });
            }

            let mut out = Vec::with_capacity(64 + 2 + fal_sig_bytes.len());
            out.extend_from_slice(&ed_sig);
            out.extend_from_slice(&(fal_sig_bytes.len() as u16).to_le_bytes());
            out.extend_from_slice(fal_sig_bytes);
            Ok(out)
        }
    }
}

/// split a hybrid private-key blob into its (ed25519_sk
/// falcon_sk) components. Wire format produced by `generate_keypair`:
/// `[32 B ed_sk][2 B u16-LE falcon_sk_len][falcon_sk_len B falcon_sk]`.
fn split_hybrid_sk(sk: &[u8]) -> Result<(&[u8], &[u8])> {
    if sk.len() < 34 {
        return Err(ConfigError::InvalidKeyLength {
            algo: SignatureAlgorithm::Ed25519Falcon512Hybrid.to_string(),
            key_kind: "private key",
            expected: 34, // minimum: 32 ed + 2 length-prefix + 0
            actual: sk.len(),
        });
    }
    let ed_sk = &sk[..32];
    let fal_len = u16::from_le_bytes([sk[32], sk[33]]) as usize;
    if sk.len() < 34 + fal_len {
        return Err(ConfigError::InvalidKeyLength {
            algo: SignatureAlgorithm::Ed25519Falcon512Hybrid.to_string(),
            key_kind: "private key (truncated falcon part)",
            expected: 34 + fal_len,
            actual: sk.len(),
        });
    }
    let fal_sk = &sk[34..34 + fal_len];
    Ok((ed_sk, fal_sk))
}

/// split a hybrid public-key blob into its (ed25519_pk
/// falcon_pk) components. Wire format produced by `generate_keypair`:
/// `[32 B ed_pk][897 B falcon_pk]`. Total = 929 bytes (no length
/// prefix because both components are fixed-size).
fn split_hybrid_pk(pk: &[u8]) -> Result<(&[u8], &[u8])> {
    const ED_PK_LEN: usize = 32;
    const FAL_PK_LEN: usize = 897;
    const HYBRID_PK_LEN: usize = ED_PK_LEN + FAL_PK_LEN;
    if pk.len() != HYBRID_PK_LEN {
        return Err(ConfigError::InvalidKeyLength {
            algo: SignatureAlgorithm::Ed25519Falcon512Hybrid.to_string(),
            key_kind: "public key",
            expected: HYBRID_PK_LEN,
            actual: pk.len(),
        });
    }
    Ok((&pk[..ED_PK_LEN], &pk[ED_PK_LEN..]))
}

/// split a hybrid signature blob into its (ed25519_sig
/// falcon_sig) components. Wire format produced by `sign_message`:
/// `[64 B ed_sig][2 B u16-LE falcon_sig_len][falcon_sig_len B falcon_sig]`.
/// tightened from 1024 → 768. Falcon-512 sigs
/// are variable-length 600-752 B per NIST spec; 768 leaves a 16-byte
/// margin for the rare upper-tail samples without the prior 272-byte gap
/// that gave attackers free CPU amplification space. Without this cap
/// an adversary-supplied hybrid sig with `fal_len = 65535` would force
/// the verifier to hand up to ~64 KiB to pqcrypto-falcon's parser per
/// verification — CPU-amplification vector against a busy DHT-store
/// endpoint. 768 B is a hard ceiling that crosses every Falcon-512
/// implementation in practice.
pub const MAX_FALCON_SIG_BYTES: usize = 768;

/// Verifier-side cap on the Falcon-1024 component of a hybrid signature
/// (Phase 10).  pqcrypto-falcon's Falcon-1024 `CRYPTO_BYTES` constant is
/// 1462 — the hard upper bound on any valid Falcon-1024 detached
/// signature.  We cap at exactly 1462 to reject malformed signatures
/// without leaving CPU-amplification headroom.  An adversary-supplied
/// hybrid sig with `fal_len = 65535` would otherwise force the verifier
/// to hand up to ~64 KiB to pqcrypto-falcon's parser per verification.
pub const MAX_FALCON1024_SIG_BYTES: usize = 1462;

/// Split a hybrid-1024 private-key blob into its (ed25519_sk, falcon_sk)
/// components.  Wire format identical to the Falcon-512 hybrid SK shape:
/// `[32 B ed_sk][2 B u16-LE falcon_sk_len][falcon_sk_len B falcon_sk]`.
fn split_hybrid_1024_sk(sk: &[u8]) -> Result<(&[u8], &[u8])> {
    if sk.len() < 34 {
        return Err(ConfigError::InvalidKeyLength {
            algo: SignatureAlgorithm::Ed25519Falcon1024Hybrid.to_string(),
            key_kind: "private key",
            expected: 34,
            actual: sk.len(),
        });
    }
    let ed_sk = &sk[..32];
    let fal_len = u16::from_le_bytes([sk[32], sk[33]]) as usize;
    if sk.len() < 34 + fal_len {
        return Err(ConfigError::InvalidKeyLength {
            algo: SignatureAlgorithm::Ed25519Falcon1024Hybrid.to_string(),
            key_kind: "private key (truncated falcon part)",
            expected: 34 + fal_len,
            actual: sk.len(),
        });
    }
    let fal_sk = &sk[34..34 + fal_len];
    Ok((ed_sk, fal_sk))
}

/// Split a hybrid-1024 public-key blob into its (ed25519_pk, falcon_pk)
/// components.  Wire format: `[32 B ed_pk][1793 B falcon_pk]` —
/// `HYBRID_1024_PK_LEN` total, fixed-size (no length prefix).
fn split_hybrid_1024_pk(pk: &[u8]) -> Result<(&[u8], &[u8])> {
    if pk.len() != HYBRID_1024_PK_LEN {
        return Err(ConfigError::InvalidKeyLength {
            algo: SignatureAlgorithm::Ed25519Falcon1024Hybrid.to_string(),
            key_kind: "public key",
            expected: HYBRID_1024_PK_LEN,
            actual: pk.len(),
        });
    }
    Ok((&pk[..32], &pk[32..]))
}

/// Split a hybrid-1024 signature blob into its (ed25519_sig, falcon_sig)
/// components.  Wire format identical to the Falcon-512 hybrid sig shape:
/// `[64 B ed_sig][2 B u16-LE fal_sig_len][fal_sig_len B fal_sig]`.
/// `fal_sig_len` is bounded by `MAX_FALCON1024_SIG_BYTES = 1462`.
fn split_hybrid_1024_sig(sig: &[u8]) -> Result<(&[u8], &[u8])> {
    if sig.len() < 66 {
        return Err(ConfigError::InvalidSignature {
            algo: SignatureAlgorithm::Ed25519Falcon1024Hybrid.to_string(),
            details: format!(
                "truncated hybrid sig: need ≥ 66 B header, got {}",
                sig.len()
            ),
        });
    }
    let ed_sig = &sig[..64];
    let fal_len = u16::from_le_bytes([sig[64], sig[65]]) as usize;
    if fal_len > MAX_FALCON1024_SIG_BYTES {
        return Err(ConfigError::InvalidSignature {
            algo: SignatureAlgorithm::Ed25519Falcon1024Hybrid.to_string(),
            details: format!(
                "falcon_len={fal_len} > MAX_FALCON1024_SIG_BYTES={MAX_FALCON1024_SIG_BYTES} cap",
            ),
        });
    }
    if sig.len() < 66 + fal_len {
        return Err(ConfigError::InvalidSignature {
            algo: SignatureAlgorithm::Ed25519Falcon1024Hybrid.to_string(),
            details: format!(
                "truncated hybrid sig: declared falcon_len={fal_len} but \
                 only {} bytes remain after header",
                sig.len() - 66
            ),
        });
    }
    let fal_sig = &sig[66..66 + fal_len];
    Ok((ed_sig, fal_sig))
}

fn split_hybrid_sig(sig: &[u8]) -> Result<(&[u8], &[u8])> {
    if sig.len() < 66 {
        return Err(ConfigError::InvalidSignature {
            algo: SignatureAlgorithm::Ed25519Falcon512Hybrid.to_string(),
            details: format!(
                "truncated hybrid sig: need ≥ 66 B header, got {}",
                sig.len()
            ),
        });
    }
    let ed_sig = &sig[..64];
    let fal_len = u16::from_le_bytes([sig[64], sig[65]]) as usize;
    // upper-bound the declared Falcon-component length.
    if fal_len > MAX_FALCON_SIG_BYTES {
        return Err(ConfigError::InvalidSignature {
            algo: SignatureAlgorithm::Ed25519Falcon512Hybrid.to_string(),
            details: format!(
                "falcon_len={fal_len} > MAX_FALCON_SIG_BYTES={MAX_FALCON_SIG_BYTES} cap",
            ),
        });
    }
    if sig.len() < 66 + fal_len {
        return Err(ConfigError::InvalidSignature {
            algo: SignatureAlgorithm::Ed25519Falcon512Hybrid.to_string(),
            details: format!(
                "truncated hybrid sig: declared falcon_len={fal_len} but \
                 only {} bytes remain after header",
                sig.len() - 66
            ),
        });
    }
    let fal_sig = &sig[66..66 + fal_len];
    Ok((ed_sig, fal_sig))
}

pub fn verify_message(
    algo: SignatureAlgorithm,
    public_key_base64: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    match algo {
        SignatureAlgorithm::Ed25519 => {
            let public_key = decode_public_key(algo, public_key_base64)?;
            let verifying_key =
                VerifyingKey::from_bytes(&public_key.as_slice().try_into().map_err(|_| {
                    ConfigError::InvalidKeyLength {
                        algo: algo.to_string(),
                        key_kind: "public key",
                        expected: 32,
                        actual: public_key.len(),
                    }
                })?)
                .map_err(|err| ConfigError::InvalidCryptoMaterial {
                    algo: algo.to_string(),
                    item: "public key",
                    details: err.to_string(),
                })?;
            let signature =
                Signature::from_slice(signature).map_err(|err| ConfigError::InvalidSignature {
                    algo: algo.to_string(),
                    details: err.to_string(),
                })?;
            verifying_key.verify(message, &signature).map_err(|err| {
                ConfigError::SignatureVerificationFailed {
                    algo: algo.to_string(),
                    details: err.to_string(),
                }
            })?;
            Ok(())
        }
        SignatureAlgorithm::Falcon512 => {
            let public_key =
                falcon512::PublicKey::from_bytes(&decode_public_key(algo, public_key_base64)?)
                    .map_err(|err| ConfigError::InvalidCryptoMaterial {
                        algo: algo.to_string(),
                        item: "public key",
                        details: err.to_string(),
                    })?;
            let signature = falcon512::DetachedSignature::from_bytes(signature).map_err(|err| {
                ConfigError::InvalidSignature {
                    algo: algo.to_string(),
                    details: err.to_string(),
                }
            })?;
            falcon512::verify_detached_signature(&signature, message, &public_key).map_err(
                |err| ConfigError::SignatureVerificationFailed {
                    algo: algo.to_string(),
                    details: err.to_string(),
                },
            )?;
            Ok(())
        }
        SignatureAlgorithm::Ed25519Falcon512Hybrid => {
            // hybrid verify — BOTH signatures must be valid.
            // Failure of either component is a hard fail; we do NOT
            // accept "one classic + one PQ" as good-enough. An attacker
            // who breaks Ed25519 (CRQC future) but doesn't have the
            // Falcon SK should not be able to forge. Conversely an
            // attacker who breaks Falcon (cryptanalytic regression)
            // but doesn't have the Ed25519 SK should also not forge.
            let pk_bytes = decode_public_key(algo, public_key_base64)?;
            let (ed_pk_bytes, fal_pk_bytes) = split_hybrid_pk(&pk_bytes)?;
            let (ed_sig_bytes, fal_sig_bytes) = split_hybrid_sig(signature)?;

            // Ed25519 verify.
            let ed_pk = VerifyingKey::from_bytes(&ed_pk_bytes.try_into().map_err(|_| {
                ConfigError::InvalidKeyLength {
                    algo: algo.to_string(),
                    key_kind: "ed25519 public key",
                    expected: 32,
                    actual: ed_pk_bytes.len(),
                }
            })?)
            .map_err(|err| ConfigError::InvalidCryptoMaterial {
                algo: algo.to_string(),
                item: "ed25519 public key",
                details: err.to_string(),
            })?;
            let ed_sig = Signature::from_slice(ed_sig_bytes).map_err(|err| {
                ConfigError::InvalidSignature {
                    algo: algo.to_string(),
                    details: format!("ed25519 component: {err}"),
                }
            })?;
            ed_pk.verify(message, &ed_sig).map_err(|err| {
                ConfigError::SignatureVerificationFailed {
                    algo: algo.to_string(),
                    details: format!("ed25519 component failed: {err}"),
                }
            })?;

            // Falcon-512 verify.
            let fal_pk = falcon512::PublicKey::from_bytes(fal_pk_bytes).map_err(|err| {
                ConfigError::InvalidCryptoMaterial {
                    algo: algo.to_string(),
                    item: "falcon-512 public key",
                    details: err.to_string(),
                }
            })?;
            let fal_sig =
                falcon512::DetachedSignature::from_bytes(fal_sig_bytes).map_err(|err| {
                    ConfigError::InvalidSignature {
                        algo: algo.to_string(),
                        details: format!("falcon-512 component: {err}"),
                    }
                })?;
            falcon512::verify_detached_signature(&fal_sig, message, &fal_pk).map_err(|err| {
                ConfigError::SignatureVerificationFailed {
                    algo: algo.to_string(),
                    details: format!("falcon-512 component failed: {err}"),
                }
            })?;
            Ok(())
        }
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => {
            // Phase 10: parallel hybrid verify for Falcon-1024.  BOTH
            // signatures must validate — failure of either component is
            // a hard fail (no fallback to classical-only acceptance).
            let pk_bytes = decode_public_key(algo, public_key_base64)?;
            let (ed_pk_bytes, fal_pk_bytes) = split_hybrid_1024_pk(&pk_bytes)?;
            let (ed_sig_bytes, fal_sig_bytes) = split_hybrid_1024_sig(signature)?;

            let ed_pk = VerifyingKey::from_bytes(&ed_pk_bytes.try_into().map_err(|_| {
                ConfigError::InvalidKeyLength {
                    algo: algo.to_string(),
                    key_kind: "ed25519 public key",
                    expected: 32,
                    actual: ed_pk_bytes.len(),
                }
            })?)
            .map_err(|err| ConfigError::InvalidCryptoMaterial {
                algo: algo.to_string(),
                item: "ed25519 public key",
                details: err.to_string(),
            })?;
            let ed_sig = Signature::from_slice(ed_sig_bytes).map_err(|err| {
                ConfigError::InvalidSignature {
                    algo: algo.to_string(),
                    details: format!("ed25519 component: {err}"),
                }
            })?;
            ed_pk.verify(message, &ed_sig).map_err(|err| {
                ConfigError::SignatureVerificationFailed {
                    algo: algo.to_string(),
                    details: format!("ed25519 component failed: {err}"),
                }
            })?;

            let fal_pk = falcon1024::PublicKey::from_bytes(fal_pk_bytes).map_err(|err| {
                ConfigError::InvalidCryptoMaterial {
                    algo: algo.to_string(),
                    item: "falcon-1024 public key",
                    details: err.to_string(),
                }
            })?;
            let fal_sig =
                falcon1024::DetachedSignature::from_bytes(fal_sig_bytes).map_err(|err| {
                    ConfigError::InvalidSignature {
                        algo: algo.to_string(),
                        details: format!("falcon-1024 component: {err}"),
                    }
                })?;
            falcon1024::verify_detached_signature(&fal_sig, message, &fal_pk).map_err(|err| {
                ConfigError::SignatureVerificationFailed {
                    algo: algo.to_string(),
                    details: format!("falcon-1024 component failed: {err}"),
                }
            })?;
            Ok(())
        }
    }
}

pub fn decode_public_key(algo: SignatureAlgorithm, value: &str) -> Result<Vec<u8>> {
    let bytes = STANDARD.decode(value)?;
    match algo {
        SignatureAlgorithm::Ed25519 => {
            if bytes.len() != 32 {
                return Err(ConfigError::InvalidKeyLength {
                    algo: algo.to_string(),
                    key_kind: "public key",
                    expected: 32,
                    actual: bytes.len(),
                });
            }
        }
        SignatureAlgorithm::Falcon512 => {
            falcon512::PublicKey::from_bytes(&bytes).map_err(|err| {
                ConfigError::InvalidCryptoMaterial {
                    algo: algo.to_string(),
                    item: "public key",
                    details: err.to_string(),
                }
            })?;
        }
        SignatureAlgorithm::Ed25519Falcon512Hybrid => {
            // validate both components parse correctly.
            let (ed_pk, fal_pk) = split_hybrid_pk(&bytes)?;
            // ed25519 length already enforced by split_hybrid_pk; do a
            // structural validate to catch malformed ed25519 points.
            //
            // Audit batch 2026-05-25 phase M: previously used
            // `.try_into().expect("split_hybrid_pk guarantees 32 B")`
            // — a runtime invariant cross-coupling between this function
            // and `split_hybrid_pk` (line ~200).  Verify locally instead:
            // if a future refactor breaks the contract, return clean
            // ConfigError rather than panic.
            let ed_pk_arr: [u8; 32] =
                ed_pk
                    .try_into()
                    .map_err(|_| ConfigError::InvalidCryptoMaterial {
                        algo: algo.to_string(),
                        item: "ed25519 public key component",
                        details: format!(
                            "expected 32 bytes from split_hybrid_pk, got {} — split_hybrid_pk \
                         invariant violated",
                            ed_pk.len()
                        ),
                    })?;
            VerifyingKey::from_bytes(&ed_pk_arr).map_err(|err| {
                ConfigError::InvalidCryptoMaterial {
                    algo: algo.to_string(),
                    item: "ed25519 public key component",
                    details: err.to_string(),
                }
            })?;
            falcon512::PublicKey::from_bytes(fal_pk).map_err(|err| {
                ConfigError::InvalidCryptoMaterial {
                    algo: algo.to_string(),
                    item: "falcon-512 public key component",
                    details: err.to_string(),
                }
            })?;
        }
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => {
            let (ed_pk, fal_pk) = split_hybrid_1024_pk(&bytes)?;
            let ed_pk_arr: [u8; 32] =
                ed_pk
                    .try_into()
                    .map_err(|_| ConfigError::InvalidCryptoMaterial {
                        algo: algo.to_string(),
                        item: "ed25519 public key component",
                        details: format!(
                            "expected 32 bytes from split_hybrid_1024_pk, got {} — split helper \
                             invariant violated",
                            ed_pk.len()
                        ),
                    })?;
            VerifyingKey::from_bytes(&ed_pk_arr).map_err(|err| {
                ConfigError::InvalidCryptoMaterial {
                    algo: algo.to_string(),
                    item: "ed25519 public key component",
                    details: err.to_string(),
                }
            })?;
            falcon1024::PublicKey::from_bytes(fal_pk).map_err(|err| {
                ConfigError::InvalidCryptoMaterial {
                    algo: algo.to_string(),
                    item: "falcon-1024 public key component",
                    details: err.to_string(),
                }
            })?;
        }
    }
    Ok(bytes)
}

pub fn decode_private_key(algo: SignatureAlgorithm, value: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = Zeroizing::new(STANDARD.decode(value)?);
    match algo {
        SignatureAlgorithm::Ed25519 => {
            if bytes.len() != 32 {
                return Err(ConfigError::InvalidKeyLength {
                    algo: algo.to_string(),
                    key_kind: "private key",
                    expected: 32,
                    actual: bytes.len(),
                });
            }
        }
        SignatureAlgorithm::Falcon512 => {
            falcon512::SecretKey::from_bytes(&bytes).map_err(|err| {
                ConfigError::InvalidCryptoMaterial {
                    algo: algo.to_string(),
                    item: "private key",
                    details: err.to_string(),
                }
            })?;
        }
        SignatureAlgorithm::Ed25519Falcon512Hybrid => {
            // validate both components parse correctly.
            let (_ed_sk, fal_sk) = split_hybrid_sk(&bytes)?;
            // ed25519 SK is 32 B and any 32-B value is a valid Ed25519
            // SK seed (bytes derive a SigningKey), so only the Falcon
            // half needs structural validation.
            falcon512::SecretKey::from_bytes(fal_sk).map_err(|err| {
                ConfigError::InvalidCryptoMaterial {
                    algo: algo.to_string(),
                    item: "falcon-512 private key component",
                    details: err.to_string(),
                }
            })?;
        }
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => {
            let (_ed_sk, fal_sk) = split_hybrid_1024_sk(&bytes)?;
            falcon1024::SecretKey::from_bytes(fal_sk).map_err(|err| {
                ConfigError::InvalidCryptoMaterial {
                    algo: algo.to_string(),
                    item: "falcon-1024 private key component",
                    details: err.to_string(),
                }
            })?;
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_ed25519_keypair() {
        let keypair = generate_keypair(SignatureAlgorithm::Ed25519);
        assert_eq!(
            decode_public_key(keypair.algo, &keypair.public_key)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(
            decode_private_key(keypair.algo, &keypair.private_key)
                .unwrap()
                .len(),
            32
        );
    }

    /// hybrid keypair generation + sign + verify round-trip.
    #[test]
    fn epic486_hybrid_keypair_sign_verify_roundtrip() {
        let keypair = generate_keypair(SignatureAlgorithm::Ed25519Falcon512Hybrid);
        assert_eq!(keypair.algo, SignatureAlgorithm::Ed25519Falcon512Hybrid);

        // Public key: 32 (ed25519) + 897 (falcon-512) = 929 bytes.
        let pk = decode_public_key(keypair.algo, &keypair.public_key).unwrap();
        assert_eq!(pk.len(), 929, "hybrid pk = ed_pk(32) + falcon_pk(897)");

        // Sign + verify a sample message.
        let msg = b"epic486 hybrid test message";
        let sig =
            sign_message(keypair.algo, &keypair.public_key, &keypair.private_key, msg).unwrap();
        // Sig: 64 (ed25519) + 2 (length prefix) + falcon_sig (variable, ~666 B).
        assert!(
            sig.len() >= 64 + 2 + 100,
            "hybrid sig too short: {}",
            sig.len()
        );
        verify_message(keypair.algo, &keypair.public_key, msg, &sig).unwrap();
    }

    /// tampered hybrid sig must fail verify. Both components
    /// independently — flipping one byte in either ed25519 or falcon
    /// component is a hard fail.
    #[test]
    fn epic486_hybrid_tampered_sig_rejected() {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519Falcon512Hybrid);
        let msg = b"verify me";
        let mut sig = sign_message(kp.algo, &kp.public_key, &kp.private_key, msg).unwrap();

        // Tamper the ed25519 component (byte 10 within the 64-B prefix).
        let original_byte = sig[10];
        sig[10] ^= 0xFF;
        assert!(
            verify_message(kp.algo, &kp.public_key, msg, &sig).is_err(),
            "tampered ed25519 component must fail hybrid verify"
        );
        sig[10] = original_byte;

        // Tamper the falcon component (somewhere past the length prefix).
        let original_byte = sig[100];
        sig[100] ^= 0xFF;
        assert!(
            verify_message(kp.algo, &kp.public_key, msg, &sig).is_err(),
            "tampered falcon-512 component must fail hybrid verify"
        );
        sig[100] = original_byte;

        // Sanity: untampered sig still verifies after restore.
        verify_message(kp.algo, &kp.public_key, msg, &sig).unwrap();
    }

    /// hybrid pubkey with wrong total length must be rejected
    /// at decode time. (Note: pqcrypto-falcon's `PublicKey::from_bytes`
    /// accepts arbitrary 897-byte blobs without semantic validation —
    /// it's the verify step that catches actually-invalid Falcon keys.
    /// So all-zeroes pk passes structural decode but fails verify.)
    #[test]
    fn epic486_hybrid_malformed_pk_rejected_at_decode() {
        // Wrong total length — hybrid pk MUST be exactly 929 bytes.
        let short = vec![0u8; 100];
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &short);
        assert!(
            decode_public_key(SignatureAlgorithm::Ed25519Falcon512Hybrid, &b64).is_err(),
            "short hybrid pk must fail decode"
        );

        let too_long = vec![0u8; 1024];
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &too_long);
        assert!(
            decode_public_key(SignatureAlgorithm::Ed25519Falcon512Hybrid, &b64).is_err(),
            "oversized hybrid pk must fail decode"
        );

        // Correct length, but ed25519 component is an INVALID curve point
        // (not a valid Edwards-curve point — most random 32-byte values
        // are valid points, but specific bit-patterns aren't. Skip this
        // sub-test: structurally most bytes pass, semantic check happens
        // at verify time.) The length-check above is the actionable test.
    }

    // ── Phase 10: Ed25519 + Falcon-1024 hybrid round-trip suite ────────

    /// Hybrid-1024 keypair generation + sign + verify round-trip.
    #[test]
    fn etap10_hybrid_1024_keypair_sign_verify_roundtrip() {
        let keypair = generate_keypair(SignatureAlgorithm::Ed25519Falcon1024Hybrid);
        assert_eq!(keypair.algo, SignatureAlgorithm::Ed25519Falcon1024Hybrid);

        // Public key: 32 (ed25519) + 1793 (falcon-1024) = 1825 bytes.
        let pk = decode_public_key(keypair.algo, &keypair.public_key).unwrap();
        assert_eq!(
            pk.len(),
            1825,
            "hybrid-1024 pk = ed_pk(32) + falcon_pk(1793)"
        );

        // Sign + verify a sample message.
        let msg = b"etap10 hybrid-1024 test message";
        let sig =
            sign_message(keypair.algo, &keypair.public_key, &keypair.private_key, msg).unwrap();
        // Sig: 64 (ed25519) + 2 (length prefix) + falcon_sig (variable,
        // up to 1462 B for falcon-1024).  Minimum sane lower bound: ~100 B.
        assert!(
            sig.len() >= 64 + 2 + 100,
            "hybrid-1024 sig too short: {}",
            sig.len()
        );
        verify_message(keypair.algo, &keypair.public_key, msg, &sig).unwrap();
    }

    /// Tampered hybrid-1024 sig must fail verify — both components
    /// independently.  Flipping one byte in either ed25519 or falcon
    /// component is a hard fail (no fallback to single-component
    /// "good enough" acceptance).
    #[test]
    fn etap10_hybrid_1024_tampered_sig_rejected() {
        let kp = generate_keypair(SignatureAlgorithm::Ed25519Falcon1024Hybrid);
        let msg = b"verify me 1024";
        let mut sig = sign_message(kp.algo, &kp.public_key, &kp.private_key, msg).unwrap();

        let original_byte = sig[10];
        sig[10] ^= 0xFF;
        assert!(
            verify_message(kp.algo, &kp.public_key, msg, &sig).is_err(),
            "tampered ed25519 component must fail hybrid-1024 verify"
        );
        sig[10] = original_byte;

        let original_byte = sig[200];
        sig[200] ^= 0xFF;
        assert!(
            verify_message(kp.algo, &kp.public_key, msg, &sig).is_err(),
            "tampered falcon-1024 component must fail hybrid-1024 verify"
        );
        sig[200] = original_byte;

        verify_message(kp.algo, &kp.public_key, msg, &sig).unwrap();
    }

    /// Hybrid-1024 pubkey with wrong total length must be rejected
    /// at decode time.
    #[test]
    fn etap10_hybrid_1024_malformed_pk_rejected_at_decode() {
        let short = vec![0u8; 100];
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &short);
        assert!(
            decode_public_key(SignatureAlgorithm::Ed25519Falcon1024Hybrid, &b64).is_err(),
            "short hybrid-1024 pk must fail decode"
        );

        let too_long = vec![0u8; 4096];
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &too_long);
        assert!(
            decode_public_key(SignatureAlgorithm::Ed25519Falcon1024Hybrid, &b64).is_err(),
            "oversized hybrid-1024 pk must fail decode"
        );
    }

    /// Wire-byte mapping: SignatureAlgorithm::wire_byte() returns 4 for
    /// the new Ed25519Falcon1024Hybrid variant, and from_wire_byte() round-
    /// trips the value correctly.
    #[test]
    fn etap10_hybrid_1024_wire_byte_roundtrip() {
        assert_eq!(SignatureAlgorithm::Ed25519Falcon1024Hybrid.wire_byte(), 4);
        assert_eq!(
            SignatureAlgorithm::from_wire_byte(4),
            Some(SignatureAlgorithm::Ed25519Falcon1024Hybrid)
        );
    }

    /// Hybrid-1024 is post-quantum AND has-classical-component —
    /// the predicates that gate `--require-pq` / legacy-verify decisions
    /// recognise the new variant correctly.
    #[test]
    fn etap10_hybrid_1024_pq_predicates() {
        assert!(SignatureAlgorithm::Ed25519Falcon1024Hybrid.is_post_quantum());
        assert!(SignatureAlgorithm::Ed25519Falcon1024Hybrid.has_classical_component());
    }

    /// A hybrid-512 signature must NOT validate under a hybrid-1024
    /// public key — algorithm pinning has to be enforced.  This guards
    /// against accidental cross-algo confusion attacks at the cap
    /// boundary.
    #[test]
    fn etap10_hybrid_512_sig_rejected_by_hybrid_1024_verify() {
        let kp_512 = generate_keypair(SignatureAlgorithm::Ed25519Falcon512Hybrid);
        let kp_1024 = generate_keypair(SignatureAlgorithm::Ed25519Falcon1024Hybrid);
        let msg = b"cross-algo guard test";
        let sig_512 = sign_message(
            SignatureAlgorithm::Ed25519Falcon512Hybrid,
            &kp_512.public_key,
            &kp_512.private_key,
            msg,
        )
        .unwrap();
        // Try to verify the 512-hybrid sig under a 1024-hybrid pk.  The
        // pk-length check fires first (1825 vs 929 bytes), but any path
        // through verify_message must end in Err.
        assert!(
            verify_message(
                SignatureAlgorithm::Ed25519Falcon1024Hybrid,
                &kp_1024.public_key,
                msg,
                &sig_512
            )
            .is_err(),
            "cross-algo (hybrid-512 sig → hybrid-1024 verify) must fail"
        );
    }
}
