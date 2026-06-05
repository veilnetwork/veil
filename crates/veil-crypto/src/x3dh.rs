//! X3DH-style sender / recipient crypto helpers.
//!
//! Stateless wrappers around ML-KEM-768 encapsulation/decapsulation
//! plus an HKDF-SHA256 key derivation that binds the resulting
//! session key to (sender_identity, recipient_identity, prekey_id)
//! tuple. Combined with the persistent local
//! [`PrekeySecretStore`] this implements the forward-secrecy
//! property described in [`prekey_bundle`] module.
//!
//! The key derivation context:
//!
//! ```text
//! salt = "veil.x3dh.v1.salt"
//! ikm = ml_kem_shared_secret (32 B)
//! info = "veil.x3dh.v1"
//! || sender_node_id
//! || recipient_node_id
//! || recipient_instance_id
//! || prekey_id_be
//! out = HKDF-SHA256-Expand(ikm, info, 32)
//! ```
//!
//! `prekey_id` is mixed in so two sessions established back-to-back
//! against different prekeys derive distinct keys even with
//! cosmically-improbable shared-secret collisions.
//!
//! ## Forward secrecy lifecycle
//!
//! 1. Recipient generates `(ek, dk_seed)` once per prekey, publishes
//!    `ek` in their [`PrekeyBundle`], stashes `dk_seed` in the
//!    secret store keyed by `prekey_id`.
//! 2. Sender encapsulates against `ek` → ciphertext + shared secret;
//!    derives session key, encrypts the message, transmits
//!    `(prekey_id, ciphertext, encrypted_payload)`.
//! 3. Recipient consults the secret store, decapsulates with
//!    `dk_seed`, derives the same session key, decrypts.
//! 4. Recipient calls [`PrekeySecretStore::consume`] to
//!    **permanently delete** the stored seed for that `prekey_id`.
//!    Past ciphertexts under that prekey are now undecryptable by
//!    anyone, even the original recipient.
//!
//! [`prekey_bundle`]: crate::proto::prekey_bundle

use std::collections::HashMap;
use std::sync::RwLock;

use hkdf::Hkdf;
use ml_kem::array::Array;
use ml_kem::kem::DecapsulationKey;
use ml_kem::ml_kem_768::EncapsulationKey as EK768;
use ml_kem::{Decapsulate, Encapsulate, Kem, KeyExport, MlKem768, Seed};
use sha2::Sha256;
use zeroize::Zeroizing;

type DK768 = DecapsulationKey<MlKem768>;

use veil_types::{ALGO_ML_KEM_768, ML_KEM_768_EK_LEN};

// ── Constants ────────────────────────────────────────────────────────────────

/// Length of the ML-KEM-768 decapsulation seed (private side).
pub const ML_KEM_768_DK_SEED_LEN: usize = 64;
/// Length of the derived session key.
pub const SESSION_KEY_LEN: usize = 32;

const HKDF_SALT: &[u8] = b"veil.x3dh.v1.salt";
const HKDF_INFO_PREFIX: &[u8] = b"veil.x3dh.v1";

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum X3dhError {
    #[error("unsupported prekey algo {0}")]
    UnsupportedAlgo(u8),
    #[error("invalid encapsulation key (length {0}, expected {ML_KEM_768_EK_LEN})")]
    InvalidEncapsulationKey(usize),
    #[error("invalid decapsulation seed (length {0}, expected {ML_KEM_768_DK_SEED_LEN})")]
    InvalidDecapsulationSeed(usize),
    #[error("ML-KEM encapsulate failed")]
    EncapsulateFailed,
    #[error("ML-KEM decapsulate failed (wrong ciphertext or seed)")]
    DecapsulateFailed,
    #[error("prekey {0} not found in local secret store")]
    UnknownPrekey(u32),
    #[error("prekey {0} already consumed (forward-secrecy: seed was deleted)")]
    PrekeyAlreadyConsumed(u32),
}

// ── Stateless crypto ─────────────────────────────────────────────────────────

/// Generate a fresh ML-KEM-768 keypair for use as a prekey.
///
/// Returns `(encapsulation_key, decapsulation_seed)`. The seed must
/// be persisted in a [`PrekeySecretStore`] so the recipient can
/// later decapsulate; the encapsulation key is published in the
/// recipient's [`PrekeyBundle`].
///
/// [`PrekeyBundle`]: crate::proto::prekey_bundle::PrekeyBundle
pub fn generate_prekey() -> (Vec<u8>, Zeroizing<[u8; ML_KEM_768_DK_SEED_LEN]>) {
    let (dk, ek) = MlKem768::generate_keypair();
    let ek_bytes = ek.to_bytes();
    let seed = dk.to_seed().expect("freshly generated key has seed");
    let ek_vec = ek_bytes.as_slice().to_vec();
    let mut seed_arr = Zeroizing::new([0u8; ML_KEM_768_DK_SEED_LEN]);
    seed_arr.copy_from_slice(seed.as_slice());
    (ek_vec, seed_arr)
}

/// Result of a successful sender-side encapsulation.
#[derive(Debug)]
pub struct SenderEncapsulation {
    /// ML-KEM ciphertext to send to the recipient (alongside the
    /// chosen `prekey_id`).
    pub kem_ciphertext: Vec<u8>,
    /// Per-message session key derived from the ML-KEM shared
    /// secret + (sender, recipient, prekey) context.
    pub session_key: Zeroizing<[u8; SESSION_KEY_LEN]>,
}

/// Sender side: encapsulate against the recipient's published
/// prekey and derive the per-message session key.
///
/// `prekey_algo` must match the algorithm published in the bundle
/// (currently always `ALGO_ML_KEM_768`); the function rejects
/// unknown algos so a future ML-KEM-1024 prekey doesn't get fed
/// into the 768 codepath silently.
pub fn sender_encapsulate(
    prekey_algo: u8,
    recipient_ek: &[u8],
    sender_node_id: &[u8; 32],
    recipient_node_id: &[u8; 32],
    recipient_instance_id: &[u8; 16],
    prekey_id: u32,
) -> Result<SenderEncapsulation, X3dhError> {
    if prekey_algo != ALGO_ML_KEM_768 {
        return Err(X3dhError::UnsupportedAlgo(prekey_algo));
    }
    let ek = parse_ek(recipient_ek)?;
    // ml-kem 0.3.0-rc.1 `encapsulate` is infallible — uses the
    // system RNG internally and returns (ciphertext, shared key)
    // tuple directly.
    let (kem_ct, shared_secret) = ek.encapsulate();
    let kem_ct_bytes: Vec<u8> = kem_ct.as_slice().to_vec();

    let session_key = derive_session_key(
        shared_secret.as_slice(),
        sender_node_id,
        recipient_node_id,
        recipient_instance_id,
        prekey_id,
    );

    Ok(SenderEncapsulation {
        kem_ciphertext: kem_ct_bytes,
        session_key,
    })
}

/// Recipient side: decapsulate with a stored seed and derive the
/// same per-message session key the sender computed.
///
/// Note: this function does **not** modify any state — call
/// [`PrekeySecretStore::consume`] afterwards to permanently delete
/// the seed and lock in forward secrecy.
pub fn recipient_decapsulate(
    prekey_algo: u8,
    decapsulation_seed: &[u8; ML_KEM_768_DK_SEED_LEN],
    kem_ciphertext: &[u8],
    sender_node_id: &[u8; 32],
    recipient_node_id: &[u8; 32],
    recipient_instance_id: &[u8; 16],
    prekey_id: u32,
) -> Result<Zeroizing<[u8; SESSION_KEY_LEN]>, X3dhError> {
    if prekey_algo != ALGO_ML_KEM_768 {
        return Err(X3dhError::UnsupportedAlgo(prekey_algo));
    }
    let dk = parse_dk_seed(decapsulation_seed)?;
    let shared_secret = dk
        .decapsulate_slice(kem_ciphertext)
        .map_err(|_| X3dhError::DecapsulateFailed)?;
    Ok(derive_session_key(
        shared_secret.as_slice(),
        sender_node_id,
        recipient_node_id,
        recipient_instance_id,
        prekey_id,
    ))
}

fn derive_session_key(
    shared_secret: &[u8],
    sender_node_id: &[u8; 32],
    recipient_node_id: &[u8; 32],
    recipient_instance_id: &[u8; 16],
    prekey_id: u32,
) -> Zeroizing<[u8; SESSION_KEY_LEN]> {
    // info = HKDF_INFO_PREFIX || sender_id || recipient_id || instance_id || prekey_id
    let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + 32 + 32 + 16 + 4);
    info.extend_from_slice(HKDF_INFO_PREFIX);
    info.extend_from_slice(sender_node_id);
    info.extend_from_slice(recipient_node_id);
    info.extend_from_slice(recipient_instance_id);
    info.extend_from_slice(&prekey_id.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret);
    let mut out = Zeroizing::new([0u8; SESSION_KEY_LEN]);
    hk.expand(&info, out.as_mut())
        .expect("HKDF: 32-byte output well within hash size");
    out
}

fn parse_ek(bytes: &[u8]) -> Result<EK768, X3dhError> {
    if bytes.len() != ML_KEM_768_EK_LEN {
        return Err(X3dhError::InvalidEncapsulationKey(bytes.len()));
    }
    let arr =
        Array::try_from(bytes).map_err(|_| X3dhError::InvalidEncapsulationKey(bytes.len()))?;
    EK768::new(&arr).map_err(|_| X3dhError::InvalidEncapsulationKey(bytes.len()))
}

/// raw ML-KEM-768 encapsulate. Unlike
/// [`sender_encapsulate`], does NOT mix the shared secret through
/// HKDF with X3DH's per-message info string — returns the bare
/// `(ciphertext, shared_secret)` so the session-layer hybrid kex can
/// feed both halves into `derive_hybrid_session_keys`.
///
/// Caller MUST verify `recipient_ek` is a structurally valid
/// ML-KEM-768 EK (the function enforces length + decode); the source
/// of the EK (typically a peer's `MlKemKeyCert`, signature-verified
/// upstream) is the caller's concern.
///
/// Returns `(kem_ciphertext_bytes, shared_secret_bytes)` where
/// `kem_ciphertext_bytes.len == 1088` and
/// `shared_secret_bytes.len == 32`. The shared secret is wrapped
/// in `Zeroizing` so it's wiped on drop — caller should consume it
/// promptly into HKDF and not log/copy.
pub fn mlkem_encapsulate_raw(
    recipient_ek: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), X3dhError> {
    let ek = parse_ek(recipient_ek)?;
    let (kem_ct, shared_secret) = ek.encapsulate();
    let ct_bytes: Vec<u8> = kem_ct.as_slice().to_vec();
    let ss_bytes = Zeroizing::new(shared_secret.as_slice().to_vec());
    Ok((ct_bytes, ss_bytes))
}

/// raw ML-KEM-768 decapsulate. Symmetric
/// counterpart [`mlkem_encapsulate_raw`] — returns the bare
/// shared secret without any HKDF binding so the session-layer
/// hybrid kex can mix it into `derive_hybrid_session_keys`.
///
/// The decapsulation seed is the per-instance ML-KEM-768 DK seed
/// stored in `PrekeySecretStore` / sovereign-identity material;
/// caller has already loaded it. Decapsulation failures (caller
/// tampered, key mismatch, etc.) surface as
/// [`X3dhError::DecapsulateFailed`].
pub fn mlkem_decapsulate_raw(
    decapsulation_seed: &[u8; ML_KEM_768_DK_SEED_LEN],
    kem_ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, X3dhError> {
    let dk = parse_dk_seed(decapsulation_seed)?;
    let shared_secret = dk
        .decapsulate_slice(kem_ciphertext)
        .map_err(|_| X3dhError::DecapsulateFailed)?;
    Ok(Zeroizing::new(shared_secret.as_slice().to_vec()))
}

// ── perf: prepared (pre-parsed) variants ───────────────
//
// `mlkem_encapsulate_raw` / `mlkem_decapsulate_raw` re-parse the EK / DK
// from bytes on every call. For one-shot session establishment that's
// fine (the parse cost is small absolute time). But для re-keying flows
// что hit the same peer many times in a row (mid-session forward-secrecy
// rotation, например) we can cache the parsed structure once и reuse it
// across hundreds of encap / decap operations.
//
// Measured cost breakdown (bench `veilcore/benches/hybrid_kex.rs`):
//
// Raw `mlkem_encapsulate_raw`: ~82 µs
// Raw `mlkem_decapsulate_raw`: ~171 µs
// Prepared encap (cached EK): ~88 µs (≈ same — EK parse is cheap)
// Prepared decap (cached DK): ~96 µs (≈ 1.8× faster — DK seed
// expansion is ~80 µs of
// the 171 µs raw cost)
// `PreparedEncapsulator::from_bytes`: ~8.6 µs
// `PreparedDecapsulator::from_seed`: ~80 µs (matches keygen-from-seed)
//
// **Practical guidance**:
// * One-shot kex (single handshake against a peer): `mlkem_*_raw` is
// fine. Saving 75 µs once in the lifetime of a TCP connection is
// not worth API complexity.
// * Repeated decap against the same DK (sender uses the same prekey
// bundle для many messages, OR receiver does many rekey rounds на
// a long-lived session): use `PreparedDecapsulator::from_seed` once
// при session start, then `decapsulate` за hot-path call. The
// sender side (prepared encap) saves nothing measurable; стик the
// simpler raw API there.
//
// Both prepared types hold secret material — wrap in `Arc<Mutex<…>>` if
// shared across tasks; consume / drop promptly otherwise.

/// Parsed ML-KEM-768 encapsulation key. Cheap к build once и reuse
/// для many encapsulations against the same recipient. Wraps an
/// internal `EK768` so the public API doesn't leak the underlying
/// crate's type.
pub struct PreparedEncapsulator {
    inner: EK768,
}

impl std::fmt::Debug for PreparedEncapsulator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedEncapsulator")
            .field("inner", &"<EK768>")
            .finish()
    }
}

impl PreparedEncapsulator {
    /// Parse + structurally validate an ML-KEM-768 EK once. Subsequent
    /// `encapsulate` calls skip the parse step.
    pub fn from_bytes(recipient_ek: &[u8]) -> Result<Self, X3dhError> {
        Ok(Self {
            inner: parse_ek(recipient_ek)?,
        })
    }

    /// Run an encapsulation against the cached EK. Same output shape
    /// as [`mlkem_encapsulate_raw`].
    pub fn encapsulate(&self) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
        let (kem_ct, shared_secret) = self.inner.encapsulate();
        (
            kem_ct.as_slice().to_vec(),
            Zeroizing::new(shared_secret.as_slice().to_vec()),
        )
    }
}

/// Parsed ML-KEM-768 decapsulation key. The seed → DK expansion runs
/// [`Self::from_seed`]; subsequent `decapsulate` calls skip it.
/// Holds the secret material — wrap in `Arc` if you want к share
/// across tasks; consume / drop promptly otherwise.
pub struct PreparedDecapsulator {
    inner: DK768,
}

impl PreparedDecapsulator {
    /// Run the ML-KEM key-derivation to expand the 64-byte seed into
    /// the full DK structure. This is the part of `mlkem_decapsulate_raw`
    /// что dominates its 200-µs cost — caching it here lets callers
    /// run many decap operations за фракцию того времени.
    pub fn from_seed(decapsulation_seed: &[u8; ML_KEM_768_DK_SEED_LEN]) -> Result<Self, X3dhError> {
        Ok(Self {
            inner: parse_dk_seed(decapsulation_seed)?,
        })
    }

    /// Run a decapsulation against the cached DK. Same output shape
    /// as [`mlkem_decapsulate_raw`].
    pub fn decapsulate(&self, kem_ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, X3dhError> {
        let shared_secret = self
            .inner
            .decapsulate_slice(kem_ciphertext)
            .map_err(|_| X3dhError::DecapsulateFailed)?;
        Ok(Zeroizing::new(shared_secret.as_slice().to_vec()))
    }
}

fn parse_dk_seed(seed: &[u8]) -> Result<DK768, X3dhError> {
    if seed.len() != ML_KEM_768_DK_SEED_LEN {
        return Err(X3dhError::InvalidDecapsulationSeed(seed.len()));
    }
    let arr: Seed =
        Array::try_from(seed).map_err(|_| X3dhError::InvalidDecapsulationSeed(seed.len()))?;
    Ok(DK768::from_seed(arr))
}

// ── PrekeySecretStore ────────────────────────────────────────────────────────

/// Recipient-side store of decapsulation seeds, indexed by
/// `prekey_id`.
///
/// **Invariant**: a `prekey_id` that has ever been consumed never
/// reappears in the store. This is the cornerstone of forward
/// secrecy — even if the host is later compromised and the attacker
/// recovers the on-disk file, the seeds for already-read messages
/// are already gone.
///
/// MVP storage is in-memory. A persistent variant
/// (`cfg/prekey_store.rs`) is a follow-up with the same API surface
/// and atomic-rename file persistence.
#[derive(Debug, Default)]
pub struct PrekeySecretStore {
    inner: RwLock<StoreInner>,
}

#[derive(Debug, Default)]
struct StoreInner {
    /// `prekey_id → decapsulation seed`. Seeds are wiped on remove.
    seeds: HashMap<u32, Zeroizing<[u8; ML_KEM_768_DK_SEED_LEN]>>,
    /// IDs that have been consumed — serves as a tombstone so a
    /// re-import of the same id raises an error.
    consumed: std::collections::HashSet<u32>,
}

impl PrekeySecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a fresh seed. Returns an error if the id was
    /// previously consumed (guards against accidental "unconsumption").
    pub fn insert(
        &self,
        prekey_id: u32,
        seed: Zeroizing<[u8; ML_KEM_768_DK_SEED_LEN]>,
    ) -> Result<(), X3dhError> {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if guard.consumed.contains(&prekey_id) {
            return Err(X3dhError::PrekeyAlreadyConsumed(prekey_id));
        }
        guard.seeds.insert(prekey_id, seed);
        Ok(())
    }

    /// Borrow the seed for `prekey_id` so the caller can decapsulate.
    /// Does NOT consume — call [`Self::consume`] explicitly after a
    /// successful decryption to lock in forward secrecy.
    pub fn with_seed<R, F>(&self, prekey_id: u32, f: F) -> Result<R, X3dhError>
    where
        F: FnOnce(&[u8; ML_KEM_768_DK_SEED_LEN]) -> R,
    {
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        if guard.consumed.contains(&prekey_id) {
            return Err(X3dhError::PrekeyAlreadyConsumed(prekey_id));
        }
        let seed = guard
            .seeds
            .get(&prekey_id)
            .ok_or(X3dhError::UnknownPrekey(prekey_id))?;
        Ok(f(seed))
    }

    /// Permanently consume `prekey_id` — wipes the seed and records
    /// the id as a tombstone. Subsequent `insert` or `with_seed`
    /// calls for this id error with [`X3dhError::PrekeyAlreadyConsumed`].
    pub fn consume(&self, prekey_id: u32) {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        // Remove drops the Zeroizing wrapper which wipes the seed bytes.
        guard.seeds.remove(&prekey_id);
        guard.consumed.insert(prekey_id);
    }

    /// Number of unconsumed seeds currently held. Useful for
    /// pool-refill heuristics: bundle republish kicks in when this
    /// drops below `MIN_PREKEY_POOL_REMAINING`.
    pub fn unused_count(&self) -> usize {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .seeds
            .len()
    }

    /// True iff the store has ever consumed `prekey_id`.
    pub fn was_consumed(&self, prekey_id: u32) -> bool {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .consumed
            .contains(&prekey_id)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_sender_recipient_share_session_key() {
        // Recipient generates a prekey + stashes the seed.
        let (ek, seed) = generate_prekey();
        let store = PrekeySecretStore::new();
        store.insert(7, seed).unwrap();

        let sender_id = [0xAAu8; 32];
        let recipient_id = [0xBBu8; 32];
        let recipient_instance = [0xCCu8; 16];

        let send = sender_encapsulate(
            ALGO_ML_KEM_768,
            &ek,
            &sender_id,
            &recipient_id,
            &recipient_instance,
            7,
        )
        .unwrap();

        let recv_key = store
            .with_seed(7, |seed| {
                recipient_decapsulate(
                    ALGO_ML_KEM_768,
                    seed,
                    &send.kem_ciphertext,
                    &sender_id,
                    &recipient_id,
                    &recipient_instance,
                    7,
                )
                .unwrap()
            })
            .unwrap();

        assert_eq!(*send.session_key, *recv_key);
    }

    #[test]
    fn distinct_prekey_ids_yield_distinct_session_keys() {
        let (ek, _seed1) = generate_prekey();
        let (_, seed2) = generate_prekey();

        let sender_id = [0xAAu8; 32];
        let recipient_id = [0xBBu8; 32];
        let recipient_instance = [0xCCu8; 16];

        let send_a = sender_encapsulate(
            ALGO_ML_KEM_768,
            &ek,
            &sender_id,
            &recipient_id,
            &recipient_instance,
            1,
        )
        .unwrap();
        let send_b = sender_encapsulate(
            ALGO_ML_KEM_768,
            &ek,
            &sender_id,
            &recipient_id,
            &recipient_instance,
            2,
        )
        .unwrap();
        // Same EK, same parties, but different prekey_id → different
        // session key. (The ciphertexts will also differ because of
        // ML-KEM internal randomness.)
        assert_ne!(*send_a.session_key, *send_b.session_key);

        // Sanity-check that seed2 is unused (we don't actually need
        // it for this test — present only to exercise the helper).
        let _ = seed2;
    }

    #[test]
    fn distinct_recipients_yield_distinct_session_keys() {
        let (ek, _) = generate_prekey();
        let sender_id = [0xAAu8; 32];
        let recipient_id_1 = [0xBBu8; 32];
        let recipient_id_2 = [0xCCu8; 32];
        let inst = [0xDDu8; 16];

        let s1 = sender_encapsulate(ALGO_ML_KEM_768, &ek, &sender_id, &recipient_id_1, &inst, 1)
            .unwrap();
        let s2 = sender_encapsulate(ALGO_ML_KEM_768, &ek, &sender_id, &recipient_id_2, &inst, 1)
            .unwrap();
        assert_ne!(*s1.session_key, *s2.session_key);
    }

    #[test]
    fn rejects_unsupported_algo_on_send() {
        let (ek, _) = generate_prekey();
        let err = sender_encapsulate(99, &ek, &[0; 32], &[0; 32], &[0; 16], 1).unwrap_err();
        assert!(matches!(err, X3dhError::UnsupportedAlgo(99)), "{err:?}");
    }

    #[test]
    fn rejects_unsupported_algo_on_receive() {
        let (_, seed) = generate_prekey();
        let err = recipient_decapsulate(99, &seed, &[0; 32], &[0; 32], &[0; 32], &[0; 16], 1)
            .unwrap_err();
        assert!(matches!(err, X3dhError::UnsupportedAlgo(99)), "{err:?}");
    }

    #[test]
    fn rejects_invalid_ek_length() {
        let bad_ek = vec![0u8; 100];
        let err = sender_encapsulate(ALGO_ML_KEM_768, &bad_ek, &[0; 32], &[0; 32], &[0; 16], 1)
            .unwrap_err();
        assert!(
            matches!(err, X3dhError::InvalidEncapsulationKey(100)),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_invalid_seed_length() {
        let err = recipient_decapsulate(
            ALGO_ML_KEM_768,
            &[0u8; 64], // correct length here
            &[0; 32],
            &[0; 32],
            &[0; 32],
            &[0; 16],
            1,
        );
        // Either DecapsulateFailed (because random seed) or works
        // without panicking — accept both as "no panic, structured
        // error". We're only asserting that an *invalid* shorter
        // length surfaces as InvalidDecapsulationSeed.
        let _ = err;

        let bad_seed = [0u8; 32]; // wrong length
        // Need to use a function that takes a slice; the typed array
        // version compiles only with the correct length. Re-use
        // parse_dk_seed indirectly via the public API by constructing
        // a [u8; 64] and ensuring length ok, then test parse_dk_seed
        // directly via X3dhError variant exercise:
        let parsed = parse_dk_seed(&bad_seed).unwrap_err();
        assert!(matches!(parsed, X3dhError::InvalidDecapsulationSeed(32)));
    }

    #[test]
    fn wrong_seed_fails_to_decapsulate() {
        let (ek, _seed_a) = generate_prekey();
        let (_, seed_b) = generate_prekey(); // unrelated keypair

        let send = sender_encapsulate(
            ALGO_ML_KEM_768,
            &ek,
            &[0xAA; 32],
            &[0xBB; 32],
            &[0xCC; 16],
            1,
        )
        .unwrap();

        // Decapsulate with the wrong seed. ML-KEM is designed so
        // that this produces a deterministic but *unrelated* shared
        // secret rather than an explicit error — recipients then fail
        // at the AEAD layer when the derived key doesn't unlock the
        // ciphertext. We assert that the derived session key
        // differs from the sender's.
        let wrong_key = recipient_decapsulate(
            ALGO_ML_KEM_768,
            &seed_b,
            &send.kem_ciphertext,
            &[0xAA; 32],
            &[0xBB; 32],
            &[0xCC; 16],
            1,
        )
        .unwrap();
        assert_ne!(*send.session_key, *wrong_key);
    }

    // ── Secret store ─────────────────────────────────────────────────────────

    #[test]
    fn store_insert_then_with_seed() {
        let store = PrekeySecretStore::new();
        let (_, seed) = generate_prekey();
        store.insert(42, seed).unwrap();
        store
            .with_seed(42, |s| {
                assert_eq!(s.len(), ML_KEM_768_DK_SEED_LEN);
            })
            .unwrap();
    }

    #[test]
    fn store_consume_makes_with_seed_fail() {
        let store = PrekeySecretStore::new();
        let (_, seed) = generate_prekey();
        store.insert(7, seed).unwrap();
        store.consume(7);
        let err = store.with_seed(7, |_| ()).unwrap_err();
        assert!(
            matches!(err, X3dhError::PrekeyAlreadyConsumed(7)),
            "{err:?}"
        );
    }

    #[test]
    fn store_consume_blocks_reinsertion() {
        let store = PrekeySecretStore::new();
        let (_, seed1) = generate_prekey();
        store.insert(11, seed1).unwrap();
        store.consume(11);
        // Even attempting to re-insert the same id must fail —
        // forward secrecy invariant: a consumed prekey never returns.
        let (_, seed2) = generate_prekey();
        let err = store.insert(11, seed2).unwrap_err();
        assert!(
            matches!(err, X3dhError::PrekeyAlreadyConsumed(11)),
            "{err:?}"
        );
    }

    #[test]
    fn store_unknown_id_with_seed_errors() {
        let store = PrekeySecretStore::new();
        let err = store.with_seed(99, |_| ()).unwrap_err();
        assert!(matches!(err, X3dhError::UnknownPrekey(99)), "{err:?}");
    }

    #[test]
    fn store_unused_count_tracks_inserts_and_consumes() {
        let store = PrekeySecretStore::new();
        assert_eq!(store.unused_count(), 0);
        let (_, s1) = generate_prekey();
        let (_, s2) = generate_prekey();
        store.insert(1, s1).unwrap();
        store.insert(2, s2).unwrap();
        assert_eq!(store.unused_count(), 2);
        store.consume(1);
        assert_eq!(store.unused_count(), 1);
        assert!(store.was_consumed(1));
        assert!(!store.was_consumed(2));
    }

    #[test]
    fn store_consume_of_unknown_id_is_idempotent_tombstone() {
        // Consuming an id we never inserted just records the
        // tombstone — useful for callers that want to mark gossip-
        // observed ids as off-limits even before the recipient sees
        // a corresponding seed.
        let store = PrekeySecretStore::new();
        store.consume(123);
        assert!(store.was_consumed(123));
        // Future insert of 123 must fail.
        let (_, seed) = generate_prekey();
        let err = store.insert(123, seed).unwrap_err();
        assert!(
            matches!(err, X3dhError::PrekeyAlreadyConsumed(123)),
            "{err:?}"
        );
    }

    #[test]
    fn full_forward_secrecy_round_trip() {
        // The contract: after consume, the seed bytes are gone
        // so a future attempt to re-decapsulate the same ciphertext
        // fails (UnknownPrekey via with_seed).
        let store = PrekeySecretStore::new();
        let (ek, seed) = generate_prekey();
        store.insert(5, seed).unwrap();

        let send = sender_encapsulate(
            ALGO_ML_KEM_768,
            &ek,
            &[0xAA; 32],
            &[0xBB; 32],
            &[0xCC; 16],
            5,
        )
        .unwrap();

        let key1 = store
            .with_seed(5, |s| {
                recipient_decapsulate(
                    ALGO_ML_KEM_768,
                    s,
                    &send.kem_ciphertext,
                    &[0xAA; 32],
                    &[0xBB; 32],
                    &[0xCC; 16],
                    5,
                )
                .unwrap()
            })
            .unwrap();
        assert_eq!(*send.session_key, *key1);

        store.consume(5);
        let err = store.with_seed(5, |_| ()).unwrap_err();
        assert!(
            matches!(err, X3dhError::PrekeyAlreadyConsumed(5)),
            "{err:?}"
        );
    }

    // ── raw mlkem_encapsulate_raw / decapsulate_raw ──

    #[test]
    fn mlkem_encap_decap_raw_roundtrip() {
        // Sender encapsulates под freshly-generated EK; receiver
        // decapsulates с the matching DK seed; both arrive at the
        // SAME 32-byte shared secret.
        let (ek, dk_seed) = generate_prekey();
        let (ct, ss_sender) = mlkem_encapsulate_raw(&ek).expect("encap");
        assert_eq!(ct.len(), 1088, "ML-KEM-768 CT must be 1088 B");
        assert_eq!(ss_sender.len(), 32, "ML-KEM-768 SS must be 32 B");

        let ss_receiver = mlkem_decapsulate_raw(&dk_seed, &ct).expect("decap");
        assert_eq!(*ss_sender, *ss_receiver, "shared secrets must match");
    }

    #[test]
    fn mlkem_decapsulate_raw_rejects_tampered_ct() {
        let (ek, dk_seed) = generate_prekey();
        let (mut ct, _ss) = mlkem_encapsulate_raw(&ek).expect("encap");
        ct[0] ^= 0xFF;
        // ML-KEM is IND-CCA2: a single-bit flip in the CT yields a
        // *different* shared secret with overwhelming probability
        // not an explicit decap-failure. Verify the secrets differ.
        let (clean_ct, ss_clean) = mlkem_encapsulate_raw(&ek).expect("encap");
        let ss_tampered = mlkem_decapsulate_raw(&dk_seed, &ct).expect("decap");
        let ss_clean_recv = mlkem_decapsulate_raw(&dk_seed, &clean_ct).expect("decap");
        assert_eq!(*ss_clean, *ss_clean_recv, "untampered CT roundtrip");
        assert_ne!(
            *ss_clean, *ss_tampered,
            "tampered CT must yield different SS"
        );
    }

    #[test]
    fn mlkem_encapsulate_raw_rejects_wrong_length_ek() {
        // EK with 1 extra byte is rejected при decode.
        let mut ek = vec![0u8; ML_KEM_768_EK_LEN + 1];
        ek[0] = 0x42;
        let err = mlkem_encapsulate_raw(&ek).unwrap_err();
        assert!(
            matches!(err, X3dhError::InvalidEncapsulationKey(_)),
            "{err:?}"
        );
    }

    /// perf: prepared types match raw output bit-exact —
    /// caching EK / DK doesn't change semantics, just saves parse time.
    #[test]
    fn prepared_encap_decap_roundtrip_matches_raw() {
        let (ek, dk_seed) = generate_prekey();
        let prepared_ek = PreparedEncapsulator::from_bytes(&ek).expect("prepare ek");
        let prepared_dk = PreparedDecapsulator::from_seed(&dk_seed).expect("prepare dk");

        // Three encaps in a row через the cache — each one runs ML-KEM
        // encap (different randomness) и produces a different
        // (ct, ss) pair. But each ss MUST decap correctly.
        for _ in 0..3 {
            let (ct, ss_sender) = prepared_ek.encapsulate();
            assert_eq!(ct.len(), 1088);
            assert_eq!(ss_sender.len(), 32);

            // Prepared decap matches sender's secret.
            let ss_recv_prepared = prepared_dk.decapsulate(&ct).expect("prepared decap");
            assert_eq!(*ss_sender, *ss_recv_prepared);

            // Cross-check: raw decap is bit-equal к prepared decap.
            let ss_recv_raw = mlkem_decapsulate_raw(&dk_seed, &ct).expect("raw decap");
            assert_eq!(*ss_recv_raw, *ss_recv_prepared);
        }
    }

    #[test]
    fn prepared_encapsulator_rejects_wrong_length_ek() {
        let bad = vec![0u8; ML_KEM_768_EK_LEN + 1];
        let err = PreparedEncapsulator::from_bytes(&bad).unwrap_err();
        assert!(
            matches!(err, X3dhError::InvalidEncapsulationKey(_)),
            "{err:?}"
        );
    }

    #[test]
    fn prepared_decapsulator_rejects_wrong_length_seed() {
        // Seed slice with 1 fewer byte fails parse.
        let bad: Vec<u8> = vec![0u8; ML_KEM_768_DK_SEED_LEN - 1];
        let bad_arr = bad.as_slice();
        // Need а fixed-size array to call from_seed; build it dynamically.
        // Using a 64-byte seed matches signature; fail mode tested через
        // the underlying parse helper.
        let res = parse_dk_seed(bad_arr);
        assert!(matches!(res, Err(X3dhError::InvalidDecapsulationSeed(_))));
    }
}
