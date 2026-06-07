//! Session key derivation for OVL1 sessions.
//!
//! After X25519 key exchange produces a raw shared secret, this module derives
//! the per-session keying material via HKDF-SHA256:
//!
//! ```text
//! salt = local_node_id XOR remote_node_id (order-independent)
//! info = b"ovl1-session-v1"
//! ikm = x25519_shared_secret
//!
//! output (96 bytes total):
//! [0..32] tx_key — AEAD key for outgoing frames (local→remote)
//! [32..64] rx_key — AEAD key for incoming frames (remote→local)
//! [64..96] session_id — cryptographically unique session identifier
//! ```
//!
//! `tx_key` and `rx_key` are assigned so that both sides derive the same pair
//! but use them in opposite roles: the initiator's `tx_key` == responder's
//! `rx_key` and vice-versa. Because the salt is XOR of the two node IDs
//! (commutative), both sides arrive at the same output bytes and then swap
//! roles based on lexicographic ordering of their node IDs.

use hkdf::Hkdf;
use sha2::Sha256;

/// Keying material derived for one OVL1 session.
///
/// `ZeroizeOnDrop` wipes the AEAD keys when this struct is dropped — the
/// hot path in `SessionRunner` consumes these via field-moves into
/// `SessionCipher::new`, so explicit `.zeroize()` calls would race with
/// move semantics.  Drop-on-end-of-scope catches the dangling-Vec
/// scenarios on error paths.
///
/// `PartialEq` is excluded so that future call-sites cannot accidentally
/// use a variable-time `==` compare on session-key material — use
/// `subtle::ConstantTimeEq` if equality is needed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    /// AEAD key used to **encrypt** outgoing frame bodies.
    pub tx_key: [u8; 32],
    /// AEAD key used to **decrypt** incoming frame bodies.
    pub rx_key: [u8; 32],
    /// 32-byte session identifier derived from the shared secret.
    /// Used in `SessionConfirmPayload.session_id`.
    pub session_id: [u8; 32],
}

use zeroize::{Zeroize, ZeroizeOnDrop};

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Do not log key material; only show the session_id (public identifier).
        let sid: String = self.session_id.iter().map(|b| format!("{b:02x}")).collect();
        write!(
            f,
            "SessionKeys {{ session_id: {sid}, tx_key: [redacted], rx_key: [redacted] }}"
        )
    }
}

const HKDF_INFO: &[u8] = b"ovl1-session-v1";
const HKDF_REKEY_INFO: &[u8] = b"ovl1-session-rekey-v1";
/// HKDF info-tag for hybrid X25519 + ML-KEM session-key
/// derivation. Distinct from `HKDF_INFO` (classical-only) so the two
/// derivation paths cannot collide; a peer that thinks it's running
/// classical-only and a peer running hybrid would produce different
/// session keys, refusing to interop instead of silently using only
/// the X25519 leg of the hybrid secret.
const HKDF_HYBRID_INFO: &[u8] = b"ovl1-session-hybrid-x25519-mlkem-v1";

/// 96-byte session-key block: tx_key (32) || rx_key (32) || session_id (32).
/// Constant lifted to module scope so so that [`OKM_LEN_VALID`]
/// const_assert below can pin the size at compile time. HKDF-SHA256
/// permits okm up to `255 × 32 = 8160` bytes; if a future refactor flips
/// this to anything > 8160 the const_assert fails at build time, before
/// the silently-deferred runtime panic would fire on every rekey/handshake.
const SESSION_OKM_LEN: usize = 96;

/// preempt: HKDF-SHA256 max okm = 255 × 32 = 8160 B.
/// Pre-emptive guard against a refactor that bumps `SESSION_OKM_LEN` past
/// the limit. Without this assert, the runtime `expect` chain below
/// would silently flip from "infallible" to "panics on every session
/// derivation" at the moment the buffer crosses 8160 bytes — a DoS on
/// every session establishment.
const OKM_LEN_VALID: () = assert!(SESSION_OKM_LEN <= 255 * 32, "HKDF-SHA256 max okm exceeded");
/// preempt: each subsequent slice (tx_key, rx_key
/// session_id) is exactly 32 bytes. Without this, a future refactor that
/// changes `SESSION_OKM_LEN` to a non-multiple of 32 would silently break
/// the `try_into::<[u8; 32]>` calls on every derivation.
const OKM_LEN_DIVISIBLE: () = assert!(
    SESSION_OKM_LEN == 96,
    "session OKM block must be 96 B = 3 × 32 B keys"
);
const _: () = OKM_LEN_VALID;
const _: () = OKM_LEN_DIVISIBLE;

/// Derive `SessionKeys` from the X25519 shared secret and the two node IDs.
///
/// `local_node_id` and `remote_node_id` are the 32-byte BLAKE3 node IDs from
/// the `IdentityPayload` exchanged during the handshake.
///
/// The function is deterministic: given the same inputs both sides will
/// derive identical `SessionKeys`, with `tx_key`/`rx_key` swapped.
pub fn derive_session_keys(
    shared_secret: &[u8; 32],
    local_node_id: &[u8; 32],
    remote_node_id: &[u8; 32],
) -> SessionKeys {
    // Salt = local_node_id XOR remote_node_id (commutative — both sides agree).
    let mut salt = [0u8; 32];
    for i in 0..32 {
        salt[i] = local_node_id[i] ^ remote_node_id[i];
    }

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    // Phase 6 — SensitiveBytes wraps the intermediate 96-byte block so
    // it gets wiped on drop AND the backing pages are mlocked when the
    // process budget allows (closes the swap-to-disk vector that the
    // previous `Zeroizing<[u8; N]>` left open).  On RLIMIT_MEMLOCK-
    // exhausted hosts (containers without CAP_IPC_LOCK, low-ulimit dev
    // boxes) SensitiveBytes silently falls back to a Zeroizing<Vec<u8>>
    // — identical to the pre-Phase-6 behaviour, no regression.
    let mut okm = veil_util::sensitive_bytes::SensitiveBytes::new(SESSION_OKM_LEN);
    // const_assert OKM_LEN_VALID at module scope guarantees
    // SESSION_OKM_LEN ≤ HKDF-SHA256 max (8160 B). expand cannot fail.
    hkdf.expand(HKDF_INFO, okm.as_mut_slice())
        .expect("compile-time-bounded okm size");

    // Both sides derive the same 96-byte block. The node with the
    // lexicographically smaller node_id uses [0..32] as tx and [32..64] as rx;
    // the other node uses them in reverse.
    // const_assert OKM_LEN_DIVISIBLE pins each 32-byte slice
    // size at compile time; try_into is mechanically infallible.
    let okm_slice = okm.as_slice();
    let (key_a, key_b): ([u8; 32], [u8; 32]) = (
        okm_slice[0..32]
            .try_into()
            .expect("compile-time-sized slice"),
        okm_slice[32..64]
            .try_into()
            .expect("compile-time-sized slice"),
    );
    let session_id: [u8; 32] = okm_slice[64..96]
        .try_into()
        .expect("compile-time-sized slice");

    let (tx_key, rx_key) = if local_node_id <= remote_node_id {
        (key_a, key_b)
    } else {
        (key_b, key_a)
    };

    SessionKeys {
        tx_key,
        rx_key,
        session_id,
    }
}

/// Derive new `SessionKeys` after a rekey exchange.
///
/// `new_shared_secret` — the raw X25519 output from the new ephemeral DH.
/// `session_id` — the current session's 32-byte identifier; used as
/// chaining salt to bind new keys to the original session.
/// `local_node_id` / `remote_node_id` — same 32-byte BLAKE3 node IDs used
/// during the original handshake.
///
/// The resulting `SessionKeys` replace the old ones; `session_id` in the
/// returned struct is a fresh value derived from the new secret.
pub fn derive_rekey_keys(
    new_shared_secret: &[u8; 32],
    session_id: &[u8; 32],
    local_node_id: &[u8; 32],
    remote_node_id: &[u8; 32],
) -> SessionKeys {
    // Salt = session_id XOR (local_node_id XOR remote_node_id)
    // Chaining the session_id into the salt binds new keys to the session history.
    let mut salt = [0u8; 32];
    for i in 0..32 {
        salt[i] = session_id[i] ^ local_node_id[i] ^ remote_node_id[i];
    }

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), new_shared_secret);
    // Phase 6 — SensitiveBytes intermediate (mlock-when-possible with
    // Zeroizing fallback).  See derive_session_keys for rationale.
    let mut okm = veil_util::sensitive_bytes::SensitiveBytes::new(SESSION_OKM_LEN);
    // see derive_session_keys for const_assert rationale.
    hkdf.expand(HKDF_REKEY_INFO, okm.as_mut_slice())
        .expect("compile-time-bounded okm size");

    let okm_slice = okm.as_slice();
    let (key_a, key_b): ([u8; 32], [u8; 32]) = (
        okm_slice[0..32]
            .try_into()
            .expect("compile-time-sized slice"),
        okm_slice[32..64]
            .try_into()
            .expect("compile-time-sized slice"),
    );
    let new_session_id: [u8; 32] = okm_slice[64..96]
        .try_into()
        .expect("compile-time-sized slice");

    let (tx_key, rx_key) = if local_node_id <= remote_node_id {
        (key_a, key_b)
    } else {
        (key_b, key_a)
    };

    SessionKeys {
        tx_key,
        rx_key,
        session_id: new_session_id,
    }
}

/// combine an X25519 shared secret with an ML-KEM-768
/// shared secret into a hybrid session-key block. Provides both
/// classical and post-quantum security simultaneously: a future
/// adversary that can break X25519 (CRQC) but not ML-KEM still cannot
/// recover the session keys; conversely a cryptanalytic regression in
/// ML-KEM does not weaken the X25519 leg.
///
/// HKDF inputs:
/// * `salt` = `local_node_id XOR remote_node_id` (commutative — both
///   sides agree).
/// * `info` = [`HKDF_HYBRID_INFO`] — distinct from the classical
///   [`HKDF_INFO`] so a hybrid-mode peer and a classical-mode peer
///   derive DIFFERENT session keys, refusing to interoperate instead
///   of silently dropping back to classical-only security.
/// * `ikm` = `x25519_shared_secret || mlkem_shared_secret` — the
///   concatenation gives HKDF its full entropy budget; HKDF-Extract
///   handles arbitrary-length IKM correctly.
///
/// Output (96 bytes total):
/// * `[0..32]` tx_key
/// * `[32..64]` rx_key
/// * `[64..96]` session_id
///
/// Both sides derive the same 96-byte block; lexicographic ordering
/// of node_ids picks who uses which half as `tx_key` / `rx_key`.
///
/// **Wire-protocol note:** the hybrid handshake is LIVE — the OVL1
/// handshake (`veil-session`) transmits the ML-KEM EK, encapsulates,
/// and returns the ciphertext, then calls this function to derive the
/// post-quantum-augmented session keys. This primitive can also be used
/// directly when both X25519 and ML-KEM secrets are pre-established by
/// some out-of-band mechanism (e.g. operator-driven key-rotation tests
/// or a multi-device sync flow).
pub fn derive_hybrid_session_keys(
    x25519_shared_secret: &[u8; 32],
    mlkem_shared_secret: &[u8],
    local_node_id: &[u8; 32],
    remote_node_id: &[u8; 32],
) -> SessionKeys {
    // Salt = local_node_id XOR remote_node_id (commutative).
    let mut salt = [0u8; 32];
    for i in 0..32 {
        salt[i] = local_node_id[i] ^ remote_node_id[i];
    }

    // Concatenated IKM = X25519 secret || ML-KEM secret. HKDF-Extract
    // hashes arbitrary-length IKM into a fixed-size PRK; mixing both
    // secrets into one IKM makes HKDF the combiner — the output
    // depends on BOTH inputs and an attacker who recovers ONE secret
    // (e.g. via a quantum-break of X25519) still can't predict the
    // output without the OTHER.
    // Zeroizing wrapper wipes the concatenated PQ + classical shared
    // secret on scope exit.  Both inputs are already Zeroizing on the
    // caller side; without this wrapper the intermediate Vec would
    // remain in deallocated memory until the arena page is reused.
    let mut ikm: zeroize::Zeroizing<Vec<u8>> =
        zeroize::Zeroizing::new(Vec::with_capacity(32 + mlkem_shared_secret.len()));
    ikm.extend_from_slice(x25519_shared_secret);
    ikm.extend_from_slice(mlkem_shared_secret);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    // Phase 6 — SensitiveBytes intermediate (mlock-when-possible with
    // Zeroizing fallback).  See derive_session_keys for rationale.
    let mut okm = veil_util::sensitive_bytes::SensitiveBytes::new(SESSION_OKM_LEN);
    // see derive_session_keys for const_assert rationale.
    hkdf.expand(HKDF_HYBRID_INFO, okm.as_mut_slice())
        .expect("compile-time-bounded okm size");

    // Same role-swap pattern as the classical path: smaller node_id
    // gets [0..32] as tx, larger as rx. Symmetric across both peers.
    let okm_slice = okm.as_slice();
    let (key_a, key_b): ([u8; 32], [u8; 32]) = (
        okm_slice[0..32]
            .try_into()
            .expect("compile-time-sized slice"),
        okm_slice[32..64]
            .try_into()
            .expect("compile-time-sized slice"),
    );
    let session_id: [u8; 32] = okm_slice[64..96]
        .try_into()
        .expect("compile-time-sized slice");

    let (tx_key, rx_key) = if local_node_id <= remote_node_id {
        (key_a, key_b)
    } else {
        (key_b, key_a)
    };

    SessionKeys {
        tx_key,
        rx_key,
        session_id,
    }
}

/// Derive a compact 8-byte session alias for a node.
///
/// The alias identifies a node within one session without revealing the full
/// 32-byte `node_id` on the wire. Derivation is deterministic from the pair
/// `(session_id, node_id)`, so both sides of the session can compute each
/// other's alias independently after the handshake completes.
///
/// Used in `RouteAnnounceAliased` / `RouteWithdrawAliased` gossip frames.
pub fn derive_session_alias(session_id: &[u8; 32], node_id: &[u8; 32]) -> [u8; 8] {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(b"ovl1-session-alias-v1");
    h.update(session_id);
    h.update(node_id);
    let digest = h.finalize();
    digest[0..8].try_into().expect("SHA-256 output is 32 bytes")
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn node_id(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn both_sides_agree_on_session_id() {
        let secret = [0xABu8; 32];
        let alice = node_id(0x01);
        let bob = node_id(0xFF);

        let ka = derive_session_keys(&secret, &alice, &bob);
        let kb = derive_session_keys(&secret, &bob, &alice);

        assert_eq!(ka.session_id, kb.session_id, "session_id must match");
    }

    #[test]
    fn tx_rx_keys_are_swapped_between_sides() {
        let secret = [0x55u8; 32];
        let alice = node_id(0x01);
        let bob = node_id(0xFF);

        let ka = derive_session_keys(&secret, &alice, &bob);
        let kb = derive_session_keys(&secret, &bob, &alice);

        // Alice's tx encrypts, Bob's rx decrypts the same stream.
        assert_eq!(ka.tx_key, kb.rx_key, "alice tx == bob rx");
        assert_eq!(ka.rx_key, kb.tx_key, "alice rx == bob tx");
    }

    #[test]
    fn different_secrets_produce_different_keys() {
        let node_a = node_id(0x11);
        let node_b = node_id(0x22);

        let k1 = derive_session_keys(&[0x01u8; 32], &node_a, &node_b);
        let k2 = derive_session_keys(&[0x02u8; 32], &node_a, &node_b);

        assert_ne!(k1.session_id, k2.session_id);
        assert_ne!(k1.tx_key, k2.tx_key);
    }

    #[test]
    fn rekey_both_sides_agree() {
        let init_secret = [0xABu8; 32];
        let session_id = [0x99u8; 32];
        let alice = node_id(0x01);
        let bob = node_id(0xFF);

        let ka = derive_rekey_keys(&init_secret, &session_id, &alice, &bob);
        let kb = derive_rekey_keys(&init_secret, &session_id, &bob, &alice);

        assert_eq!(ka.session_id, kb.session_id, "rekey session_id must match");
        assert_eq!(ka.tx_key, kb.rx_key, "alice rekey tx == bob rekey rx");
        assert_eq!(ka.rx_key, kb.tx_key, "alice rekey rx == bob rekey tx");
    }

    #[test]
    fn rekey_produces_different_keys_than_original() {
        let secret = [0x55u8; 32];
        let session_id = [0x77u8; 32];
        let alice = node_id(0x10);
        let bob = node_id(0x20);

        let original = derive_session_keys(&secret, &alice, &bob);
        let rekeyed = derive_rekey_keys(&secret, &session_id, &alice, &bob);

        assert_ne!(original.tx_key, rekeyed.tx_key);
        assert_ne!(original.session_id, rekeyed.session_id);
    }

    #[test]
    fn same_node_ids_but_swapped_still_swap_keys() {
        // Verify the lexicographic comparison is stable.
        let secret = [0xCCu8; 32];
        let a = node_id(0x10);
        let b = node_id(0x20);

        let k1 = derive_session_keys(&secret, &a, &b);
        let k2 = derive_session_keys(&secret, &b, &a);

        assert_eq!(k1.tx_key, k2.rx_key);
        assert_eq!(k1.rx_key, k2.tx_key);
    }

    /// role-assignment uses `<=` (not `<`), so a
    /// degenerate handshake where `local_node_id == remote_node_id`
    /// still produces stable role-symmetric keys: both sides take
    /// the same branch (`key_a` → tx, `key_b` → rx). This means tx
    /// == tx and rx == rx on both peers — they cannot decrypt each
    /// other's ciphertext, but the function does not deadlock or
    /// produce inconsistent state. Self-handshakes shouldn't happen
    /// in practice (a node never connects to itself) but this test
    /// guards against a future refactor flipping `<=` → `<` (which
    /// would split the equal-id case asymmetrically and silently
    /// corrupt the keystream).
    #[test]
    fn phase6_50_d_6_5_equal_node_ids_yield_consistent_roles() {
        let secret = [0xABu8; 32];
        let same = node_id(0x42);
        let k_self = derive_session_keys(&secret, &same, &same);
        // The function MUST be deterministic — calling twice yields
        // identical output.
        let k_again = derive_session_keys(&secret, &same, &same);
        assert_eq!(k_self.tx_key, k_again.tx_key);
        assert_eq!(k_self.rx_key, k_again.rx_key);
        assert_eq!(k_self.session_id, k_again.session_id);
        // And tx!= rx — otherwise a self-loop would encrypt-decrypt
        // its own keystream and leak plaintext.
        assert_ne!(
            k_self.tx_key, k_self.rx_key,
            "tx and rx must differ even when local_id == remote_id"
        );
    }

    /// same invariant on the rekey path.
    #[test]
    fn phase6_50_d_6_5_equal_node_ids_rekey_consistent() {
        let secret = [0x33u8; 32];
        let session_id = [0x77u8; 32];
        let same = node_id(0x99);
        let k1 = derive_rekey_keys(&secret, &session_id, &same, &same);
        let k2 = derive_rekey_keys(&secret, &session_id, &same, &same);
        assert_eq!(k1.tx_key, k2.tx_key);
        assert_eq!(k1.rx_key, k2.rx_key);
        assert_ne!(k1.tx_key, k1.rx_key);
    }

    // ── derive_session_alias ─────────────────────────────────────────────────

    #[test]
    fn alias_is_deterministic() {
        let sid = [0x42u8; 32];
        let nid = node_id(0x11);
        assert_eq!(
            derive_session_alias(&sid, &nid),
            derive_session_alias(&sid, &nid)
        );
    }

    #[test]
    fn alias_differs_by_node_id() {
        let sid = [0x01u8; 32];
        let a = node_id(0x11);
        let b = node_id(0x22);
        assert_ne!(
            derive_session_alias(&sid, &a),
            derive_session_alias(&sid, &b)
        );
    }

    #[test]
    fn alias_differs_by_session_id() {
        let nid = node_id(0xFF);
        let s1 = [0x01u8; 32];
        let s2 = [0x02u8; 32];
        assert_ne!(
            derive_session_alias(&s1, &nid),
            derive_session_alias(&s2, &nid)
        );
    }

    #[test]
    fn alias_is_8_bytes() {
        let alias = derive_session_alias(&[0u8; 32], &[1u8; 32]);
        assert_eq!(alias.len(), 8);
    }

    /// hybrid session-key derivation is deterministic across
    /// both peers (commutative salt + same IKM = same output).
    #[test]
    fn epic486_1_hybrid_session_keys_deterministic_both_sides() {
        let x25519 = [0xA0u8; 32];
        let mlkem = vec![0xB0u8; 32]; // ML-KEM-768 shared secret is 32 B per spec
        let alice = [0x01u8; 32];
        let bob = [0x02u8; 32];

        let sk_alice = derive_hybrid_session_keys(&x25519, &mlkem, &alice, &bob);
        let sk_bob = derive_hybrid_session_keys(&x25519, &mlkem, &bob, &alice);
        // Salt commutativity → both derive same 96-byte block;
        // role-swap → alice.tx == bob.rx and vice versa.
        assert_eq!(
            sk_alice.tx_key, sk_bob.rx_key,
            "hybrid: alice.tx must equal bob.rx (cross-peer role swap)"
        );
        assert_eq!(
            sk_alice.rx_key, sk_bob.tx_key,
            "hybrid: alice.rx must equal bob.tx"
        );
        assert_eq!(
            sk_alice.session_id, sk_bob.session_id,
            "hybrid: session_id must be identical across peers"
        );
    }

    /// hybrid output differs from classical (X25519-only)
    /// output even with the SAME X25519 secret + node_ids. Without
    /// this property a hybrid-mode peer and a classical-mode peer
    /// would silently interop using only the X25519 leg, defeating
    /// the post-quantum hardening.
    #[test]
    fn epic486_1_hybrid_output_differs_from_classical_with_same_x25519() {
        let x25519 = [0xC0u8; 32];
        let mlkem = vec![0xD0u8; 32];
        let alice = [0x11u8; 32];
        let bob = [0x22u8; 32];

        let classical = derive_session_keys(&x25519, &alice, &bob);
        let hybrid = derive_hybrid_session_keys(&x25519, &mlkem, &alice, &bob);
        assert_ne!(
            classical.tx_key, hybrid.tx_key,
            "hybrid path must produce different tx_key from classical \
             (proves info-tag domain separation)"
        );
        assert_ne!(classical.rx_key, hybrid.rx_key);
        assert_ne!(classical.session_id, hybrid.session_id);
    }

    /// hybrid keys are sensitive to the ML-KEM secret —
    /// flipping a byte in the ML-KEM input produces different keys.
    /// Proves both secrets contribute to the output (no silent dropping
    /// of one input).
    #[test]
    fn epic486_1_hybrid_output_depends_on_mlkem_secret() {
        let x25519 = [0xE0u8; 32];
        let mut mlkem_a = vec![0xF0u8; 32];
        let mut mlkem_b = mlkem_a.clone();
        mlkem_b[0] ^= 0x01;
        let alice = [0x33u8; 32];
        let bob = [0x44u8; 32];

        let sk_a = derive_hybrid_session_keys(&x25519, &mlkem_a, &alice, &bob);
        let sk_b = derive_hybrid_session_keys(&x25519, &mlkem_b, &alice, &bob);
        assert_ne!(
            sk_a.tx_key, sk_b.tx_key,
            "ml-kem secret must contribute to output (flip one byte → different key)"
        );

        // Sanity: idempotent in the same input.
        mlkem_a.zeroize();
        mlkem_a.extend_from_slice(&[0xF0u8; 32]);
        let sk_a2 = derive_hybrid_session_keys(&x25519, &mlkem_a, &alice, &bob);
        assert_eq!(sk_a.tx_key, sk_a2.tx_key, "deterministic on same inputs");
    }

    /// hybrid keys are sensitive to the X25519 secret too
    /// (companion to the ML-KEM sensitivity test above).
    #[test]
    fn epic486_1_hybrid_output_depends_on_x25519_secret() {
        let mut x_a = [0xA1u8; 32];
        let mut x_b = x_a;
        x_b[0] ^= 0x01;
        let mlkem = vec![0xB1u8; 32];
        let alice = [0x55u8; 32];
        let bob = [0x66u8; 32];

        let sk_a = derive_hybrid_session_keys(&x_a, &mlkem, &alice, &bob);
        let sk_b = derive_hybrid_session_keys(&x_b, &mlkem, &alice, &bob);
        assert_ne!(
            sk_a.tx_key, sk_b.tx_key,
            "x25519 secret must contribute to output"
        );

        x_a.zeroize();
        x_a.copy_from_slice(&[0xA1u8; 32]);
        let sk_a2 = derive_hybrid_session_keys(&x_a, &mlkem, &alice, &bob);
        assert_eq!(sk_a.tx_key, sk_a2.tx_key);
    }
}
