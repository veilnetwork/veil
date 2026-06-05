use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer as _, SigningKey};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature as _, SecretKey as _};

use veil_error::{ConfigError, Result};
use veil_types::SignatureAlgorithm;

use super::super::sign_message;
use super::super::signature::decode_public_key;
use super::super::{Base64Nonce, Base64PrivateKey, Base64PublicKey};

const NONCE_LEN: usize = 4;

// c: POW policy defaults moved from `identity_policy::IdentityPolicy`
// to here so crypto/ no longer depends on identity_policy. identity_policy
// now imports these from crypto, which matches the natural layering
// (crypto = primitives, identity_policy = policy on top of crypto).
//
// Production: 24 leading-zero bits (~256× cost vs 16 bits). Test: 16 to
// keep simulator + unit tests under a few seconds.
//
// `cfg(test)` only fires inside veil-crypto's own test profile;
// downstream crates (notably `veilcore`) need an explicit feature
// gate to opt into the low-difficulty constant for their #[cfg(test)]
// runs. See the `test-low-difficulty` feature in Cargo.toml;
// veilcore enables it [dev-dependencies].
#[cfg(not(any(test, feature = "test-low-difficulty")))]
pub const DEFAULT_POW_DIFFICULTY: u32 = 24;
#[cfg(any(test, feature = "test-low-difficulty"))]
pub const DEFAULT_POW_DIFFICULTY: u32 = 16;
pub const DEFAULT_POW_TIMEOUT_SECS: u64 = 3600;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowScore {
    pub zero_bits: u32,
}

/// Per-thread cached key material to avoid base64 decode on every PoW iteration.
pub enum CachedSigningKey {
    Ed25519(Box<SigningKey>),
    Falcon512(Box<falcon512::SecretKey>),
}

impl CachedSigningKey {
    /// Decode and cache the private key once. Called once per worker thread.
    pub fn from_private_key(algo: SignatureAlgorithm, sk_bytes: &[u8]) -> Result<Self> {
        match algo {
            SignatureAlgorithm::Ed25519 => {
                let sk: [u8; 32] =
                    sk_bytes
                        .try_into()
                        .map_err(|_| ConfigError::InvalidKeyLength {
                            algo: algo.to_string(),
                            key_kind: "private key",
                            expected: 32,
                            actual: sk_bytes.len(),
                        })?;
                Ok(Self::Ed25519(Box::new(SigningKey::from_bytes(&sk))))
            }
            SignatureAlgorithm::Falcon512 => {
                let sk = falcon512::SecretKey::from_bytes(sk_bytes).map_err(|e| {
                    ConfigError::InvalidCryptoMaterial {
                        algo: algo.to_string(),
                        item: "private key",
                        details: e.to_string(),
                    }
                })?;
                Ok(Self::Falcon512(Box::new(sk)))
            }
            SignatureAlgorithm::Ed25519Falcon512Hybrid
            | SignatureAlgorithm::Ed25519Falcon1024Hybrid => {
                // PoW for hybrid mode signs ONLY with the
                // Ed25519 component. Falcon-512 sign is ~11.7 ms per
                // call, vs Ed25519's ~125 µs (~93× slower) — using
                // Falcon in the PoW search loop would make production
                // 24-bit difficulty (16M expected candidates) take
                // ~52 hours single-thread instead of ~21 minutes
                // pushing legitimate node-creation past any reasonable
                // boot-time budget. PoW is anti-spam (rate-limit
                // identity creation), Falcon-512/1024 is identity-binding;
                // separating the two is correct: Ed25519 PoW satisfies
                // the rate-limit goal, Falcon still binds the
                // node_id at handshake time.  Falcon-1024 hybrid shares
                // the same SK layout ([32 B ed_sk][2 B len][falcon_sk]),
                // so the Ed25519 prefix is identical.
                if sk_bytes.len() < 34 {
                    return Err(ConfigError::InvalidKeyLength {
                        algo: algo.to_string(),
                        key_kind: "private key",
                        expected: 34, // 32 ed + 2 length-prefix minimum
                        actual: sk_bytes.len(),
                    });
                }
                let ed_sk: [u8; 32] = sk_bytes[..32].try_into().expect("32 bytes");
                Ok(Self::Ed25519(Box::new(SigningKey::from_bytes(&ed_sk))))
            }
        }
    }
}

/// Reusable scratch buffers so [`pow_score_raw_into`] allocates nothing per
/// candidate nonce. Build one before the search loop (only the nonce varies;
/// `pk_bytes` + key are fixed) and reuse it each iteration. This removes the
/// dominant allocation churn the miner otherwise inflicts on the global
/// allocator — audit found `pow_score_raw` was ~33% of ALL process allocations
/// (99% temporary), fragmenting jemalloc into a multi-MB resident high-water.
#[derive(Default)]
pub struct PowScratch {
    message: Vec<u8>,
    hash_input: Vec<u8>,
}

/// Compute PoW score using pre-decoded keys, reusing caller-owned scratch
/// buffers — the allocation-free hot path called on every candidate nonce.
///
/// Byte-for-byte identical to [`pow_score_raw`]: hashes
/// `pk_bytes ‖ nonce ‖ signature(pk_bytes ‖ nonce)`. For Ed25519 (incl. hybrid,
/// which signs with its Ed25519 component) the signature is a stack `[u8; 64]`,
/// so this does ZERO heap allocations per call. Falcon-512's `detached_sign`
/// still allocates internally in pqcrypto, but that algorithm is not used in
/// the search loop (it is ~93× slower; see `CachedSigningKey::from_private_key`).
pub fn pow_score_raw_into(
    pk_bytes: &[u8],
    signing_key: &CachedSigningKey,
    nonce: &[u8; NONCE_LEN],
    scratch: &mut PowScratch,
) -> Result<PowScore> {
    // message = pk_bytes ‖ nonce  (reused buffer, no per-call alloc)
    scratch.message.clear();
    scratch.message.extend_from_slice(pk_bytes);
    scratch.message.extend_from_slice(nonce);

    // hash_input = pk_bytes ‖ nonce ‖ signature(message)  (built in place)
    scratch.hash_input.clear();
    scratch.hash_input.extend_from_slice(pk_bytes);
    scratch.hash_input.extend_from_slice(nonce);
    match signing_key {
        CachedSigningKey::Ed25519(sk) => {
            let sig = sk.sign(&scratch.message).to_bytes(); // [u8; 64], no heap
            scratch.hash_input.extend_from_slice(&sig);
        }
        CachedSigningKey::Falcon512(sk) => {
            let sig = falcon512::detached_sign(&scratch.message, sk);
            scratch.hash_input.extend_from_slice(sig.as_bytes());
        }
    }
    let hash = blake3::hash(&scratch.hash_input);
    Ok(PowScore {
        zero_bits: veil_util::leading_zero_bits(hash.as_bytes()),
    })
}

/// Compute PoW score using pre-decoded key bytes — no base64 decode overhead.
///
/// Convenience wrapper over [`pow_score_raw_into`] that allocates a fresh
/// [`PowScratch`] per call. Hot loops (the miner, the search workers) should
/// instead build one `PowScratch` before the loop and call
/// [`pow_score_raw_into`] to avoid per-candidate allocation.
pub fn pow_score_raw(
    pk_bytes: &[u8],
    signing_key: &CachedSigningKey,
    nonce: &[u8; NONCE_LEN],
) -> Result<PowScore> {
    pow_score_raw_into(pk_bytes, signing_key, nonce, &mut PowScratch::default())
}

/// Decode public key bytes from `Base64PublicKey` — call once before the
/// search loop, then pass `&[u8]` to `pow_score_raw` on each iteration.
pub fn decode_pk_bytes(algo: SignatureAlgorithm, public_key: &Base64PublicKey) -> Result<Vec<u8>> {
    decode_public_key(algo, public_key.as_str())
}

/// Decode private key bytes from `Base64PrivateKey` — call once before the
/// search loop, then build a [`CachedSigningKey`] with it.
pub fn decode_sk_bytes(
    algo: SignatureAlgorithm,
    private_key: &Base64PrivateKey,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use super::super::signature::decode_private_key;
    decode_private_key(algo, private_key.as_str())
}

pub fn pow_score(
    algo: SignatureAlgorithm,
    public_key_base64: &Base64PublicKey,
    private_key_base64: &Base64PrivateKey,
    nonce_base64: &Base64Nonce,
) -> Result<PowScore> {
    let public_key = decode_public_key(algo, public_key_base64.as_str())?;
    let nonce = decode_nonce(nonce_base64.as_str())?;
    let message = pow_message(&public_key, &nonce);
    let signature = sign_message(
        algo,
        public_key_base64.as_str(),
        private_key_base64.as_str(),
        &message,
    )?;
    let mut hash_input = Vec::with_capacity(public_key.len() + nonce.len() + signature.len());
    hash_input.extend_from_slice(&public_key);
    hash_input.extend_from_slice(&nonce);
    hash_input.extend_from_slice(&signature);
    let hash = blake3::hash(&hash_input);

    Ok(PowScore {
        zero_bits: veil_util::leading_zero_bits(hash.as_bytes()),
    })
}

pub fn available_thread_count() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}

pub fn default_nonce_base64() -> String {
    STANDARD.encode([0_u8; NONCE_LEN])
}

pub(super) fn decode_nonce(value: &str) -> Result<[u8; NONCE_LEN]> {
    STANDARD
        .decode(value)?
        .try_into()
        .map_err(|bytes: Vec<u8>| ConfigError::InvalidNonceLength {
            expected: NONCE_LEN,
            actual: bytes.len(),
        })
}

fn pow_message(public_key: &[u8], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut message = Vec::with_capacity(public_key.len() + nonce.len());
    message.extend_from_slice(public_key);
    message.extend_from_slice(nonce);
    message
}

pub(super) fn nonce_to_u32(nonce: &[u8; NONCE_LEN]) -> u32 {
    u32::from_be_bytes(*nonce)
}

pub fn u32_to_nonce(value: u32) -> [u8; NONCE_LEN] {
    value.to_be_bytes()
}
