//! Single-hop AEAD onion layer.
//!
//! Wraps a payload for one hop: the sender generates a fresh X25519
//! ephemeral keypair, ECDHs with the hop's static public key, derives
//! a ChaCha20-Poly1305 key via BLAKE3, encrypts, and produces an
//! envelope of `[ephemeral_pk || nonce || ciphertext+tag]`. The
//! receiver at that hop reverses the process using its static secret
//! key.
//!
//! # Multi-hop composition
//!
//! Build an N-hop onion by wrapping in REVERSE hop order: wrap the
//! plaintext for the LAST hop first, then wrap the result for the
//! second-to-last, and so on. The first hop sees only its own
//! envelope; after unwrapping it sees the next hop's envelope as its
//! plaintext, which it forwards to that hop. See the
//! `epic482_1_layered_three_hop_composition` test for the canonical
//! pattern.
//!
//! At each hop the receiver learns:
//! * The bytes of the next layer (which it forwards as-is).
//! * Nothing about the layers PAST the next one (those bytes are
//!   still encrypted under keys it doesn't have).
//! * Nothing about the original sender (the only key visible to
//!   the hop is the ephemeral public key for THIS layer, which is
//!   fresh per layer per send).
//!
//! Combined with [`super::cell`], the on-path observer
//! sees a stream of identical-size cells whose contents look like
//! random ciphertext. The whole anonymity property collapses without
//! either piece, so they ship together in this directory.
//!
//! # Wire format (single layer)
//!
//! ```text
//! [0..32] ephemeral_pk X25519 PublicKey (32 bytes)
//! [32..44] nonce ChaCha20-Poly1305 (12 bytes, random)
//! [44..] ciphertext+tag AEAD output (N + 16 bytes)
//! ```
//!
//! Total overhead per layer: 60 bytes (32 + 12 + 16). An N-hop onion
//! that fits in a 510-byte cell can carry up to `510 - 60 * N` bytes
//! of innermost payload — for N=3, that's 330 bytes. Higher hop
//! counts trade payload budget for stronger unlinkability.
//!
//! # AEAD AAD
//!
//! The ephemeral public key + nonce are bound into the AEAD via AAD:
//!
//! ```text
//! aad = "veil-onion-v1\0" || ephemeral_pk || nonce
//! ```
//!
//! Domain prefix prevents cross-protocol reuse (an AEAD ciphertext
//! produced for some other purpose can't be replayed as an onion
//! envelope). Including the ephemeral_pk in AAD prevents an attacker
//! from substituting a different ephemeral_pk and still getting a
//! valid AEAD verify (which would otherwise fail because the derived
//! key would change, but binding it explicitly is defense in depth).
//!
//! # Why deterministic-looking but actually random nonce
//!
//! Each layer uses a fresh ephemeral key → fresh shared secret →
//! fresh derived AEAD key. We could derive the nonce from the shared
//! secret (saving 12 wire bytes), but choosing a random nonce keeps
//! the wire format aligned with conventional AEAD usage and makes
//! future "reuse a long-term key for a hop" easier to retrofit
//! without nonce-collision risk. The 12-byte cost per layer is
//! tolerable.
//!
//! # What this module does NOT do
//!
//! v1 is intentionally minimal:
//!
//! * **No multi-hop wire format.** We ship the single-layer
//!   primitive and a test that demonstrates composition. A higher
//!   layer (the circuit module, main) owns the multi-hop
//!   semantics: hop ordering, next-hop addressing, return-path
//!   handling.
//! * **No padding to fixed size.** The output of `wrap_for_hop`
//!   is `len(payload) + 60` bytes — variable. The cell layer
//!   ([`super::cell`]) provides the fixed-size envelope; callers
//!   pack the onion-wrapped bytes INTO a cell.
//! * **No replay protection.** An attacker who captures an onion
//!   envelope can re-submit it; the circuit owner is responsible
//!   for sequence numbers / freshness checks.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{
    EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret,
};

/// Bytes the hop's X25519 public key occupies at the front of the
/// envelope. Caller-visible so a higher-layer parser can compute
/// envelope-internal offsets.
pub const EPHEMERAL_PK_LEN: usize = 32;

/// AEAD nonce length — fixed by ChaCha20-Poly1305.
pub const NONCE_LEN: usize = 12;

/// AEAD tag length — fixed by ChaCha20-Poly1305.
pub const TAG_LEN: usize = 16;

/// Total per-layer envelope overhead: ephemeral_pk + nonce + AEAD tag.
pub const ONION_LAYER_OVERHEAD: usize = EPHEMERAL_PK_LEN + NONCE_LEN + TAG_LEN;

/// Domain-separation prefix bound into the AEAD AAD. Bumping `:v1`
/// would invalidate every existing onion envelope — only do this for
/// a security-relevant format change.
const AEAD_DOMAIN: &[u8] = b"veil-onion-v1\0";

/// layer-kind discriminator bound into the
/// AEAD AAD so that a single onion envelope cannot be re-interpreted
/// across different wire-format users. Without this, a future
/// protocol that piggybacks on `wrap_for_hop` could find an attacker
/// recombining its layers with circuit layers and dispatching them
/// down the wrong dispatcher path. Today only [`LAYER_KIND_CIRCUIT`]
/// is used; new kinds get a fresh constant when added.
pub const LAYER_KIND_CIRCUIT: u8 = 0;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum OnionError {
    #[error("envelope is {got} B; minimum layer size is {min} B (ephemeral_pk + nonce + tag)")]
    EnvelopeTooSmall { got: usize, min: usize },
    #[error("AEAD verification failed (wrong hop key, tampered envelope, or wrong layer)")]
    Aead,
}

/// Encrypt `payload` for a hop identified by its X25519 public key.
/// Output layout: `ephemeral_pk (32B) || nonce (12B) || ciphertext+tag`.
///
/// The ephemeral keypair is generated fresh per call and consumed
/// after one ECDH — the secret half is never stored, never returned
/// and forward-secret against future compromise of any party's keys.
pub fn wrap_for_hop(payload: &[u8], hop_pk_bytes: &[u8; EPHEMERAL_PK_LEN]) -> Vec<u8> {
    wrap_for_hop_kind(payload, hop_pk_bytes, LAYER_KIND_CIRCUIT)
}

/// kind-tagged variant [`wrap_for_hop`].
/// Binds `layer_kind` into the AEAD AAD so an envelope produced for
/// one wire format cannot be dispatched as another. All current
/// callers go through [`wrap_for_hop`] which passes
/// [`LAYER_KIND_CIRCUIT`]; expose this directly only when adding a
/// new kind.
pub fn wrap_for_hop_kind(
    payload: &[u8],
    hop_pk_bytes: &[u8; EPHEMERAL_PK_LEN],
    layer_kind: u8,
) -> Vec<u8> {
    // Fresh ephemeral keypair for this layer.
    let ephemeral_sk = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_pk = X25519PublicKey::from(&ephemeral_sk).to_bytes();
    let hop_pk = X25519PublicKey::from(*hop_pk_bytes);
    let shared = ephemeral_sk.diffie_hellman(&hop_pk);

    let aead_key = derive_aead_key(shared.as_bytes());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
    let aad = build_aad(&ephemeral_pk, &nonce_bytes, layer_kind);
    // ChaCha20-Poly1305 cannot fail at the encrypt path for valid
    // key/nonce/payload sizes (which we control here), so unwrap is
    // safe — a panic here would be a chacha20poly1305 bug.
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: payload,
                aad: &aad,
            },
        )
        .expect("chacha20poly1305 encrypt must not fail on valid inputs");

    let mut out = Vec::with_capacity(EPHEMERAL_PK_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&ephemeral_pk);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypt one onion layer using the hop's static secret key. Returns
/// the inner plaintext (which is either the next layer's bytes for a
/// non-final hop, or the original payload for the final hop — the
/// caller distinguishes via context, the onion layer doesn't carry a
/// "is_last" flag).
pub fn unwrap_at_hop(envelope: &[u8], hop_sk: &X25519StaticSecret) -> Result<Vec<u8>, OnionError> {
    unwrap_at_hop_kind(envelope, hop_sk, LAYER_KIND_CIRCUIT)
}

/// kind-tagged variant [`unwrap_at_hop`].
/// Decrypt fails with [`OnionError::Aead`] if the envelope was
/// produced for a different layer kind, surfacing dispatch-confusion
/// attempts as plain AEAD failures.
pub fn unwrap_at_hop_kind(
    envelope: &[u8],
    hop_sk: &X25519StaticSecret,
    layer_kind: u8,
) -> Result<Vec<u8>, OnionError> {
    if envelope.len() < ONION_LAYER_OVERHEAD {
        return Err(OnionError::EnvelopeTooSmall {
            got: envelope.len(),
            min: ONION_LAYER_OVERHEAD,
        });
    }
    let mut ephemeral_pk = [0u8; EPHEMERAL_PK_LEN];
    ephemeral_pk.copy_from_slice(&envelope[..EPHEMERAL_PK_LEN]);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&envelope[EPHEMERAL_PK_LEN..EPHEMERAL_PK_LEN + NONCE_LEN]);
    let ciphertext = &envelope[EPHEMERAL_PK_LEN + NONCE_LEN..];

    let shared = hop_sk.diffie_hellman(&X25519PublicKey::from(ephemeral_pk));
    let aead_key = derive_aead_key(shared.as_bytes());

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
    let aad = build_aad(&ephemeral_pk, &nonce_bytes, layer_kind);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| OnionError::Aead)
}

/// Derive a 32-byte ChaCha20-Poly1305 key from the X25519 shared
/// secret using BLAKE3 with a domain-separated salt. Domain
/// separation (vs feeding the raw shared secret to the AEAD) means
/// the same shared secret can't be repurposed as a key for some
/// other AEAD-using protocol in the codebase.
fn derive_aead_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"veil-onion-v1-aead-key\0");
    hasher.update(shared_secret);
    *hasher.finalize().as_bytes()
}

/// Construct the AEAD AAD: domain prefix || layer_kind || ephemeral_pk || nonce.
/// Binding `layer_kind`, ephemeral_pk + nonce into
/// AAD means an attacker who tries to substitute either field, OR
/// to re-dispatch a layer produced for a different wire format, will
/// fail AEAD verification — defense in depth on top of the AEAD's
/// natural integrity guarantees.
fn build_aad(
    ephemeral_pk: &[u8; EPHEMERAL_PK_LEN],
    nonce: &[u8; NONCE_LEN],
    layer_kind: u8,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AEAD_DOMAIN.len() + 1 + EPHEMERAL_PK_LEN + NONCE_LEN);
    aad.extend_from_slice(AEAD_DOMAIN);
    aad.push(layer_kind);
    aad.extend_from_slice(ephemeral_pk);
    aad.extend_from_slice(nonce);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_hop() -> (X25519StaticSecret, [u8; 32]) {
        let sk = X25519StaticSecret::random_from_rng(OsRng);
        let pk = X25519PublicKey::from(&sk).to_bytes();
        (sk, pk)
    }

    #[test]
    fn epic482_1_round_trip_recovers_payload() {
        let (hop_sk, hop_pk) = fresh_hop();
        let payload = b"meet at rendezvous@xyz";
        let envelope = wrap_for_hop(payload, &hop_pk);
        let recovered = unwrap_at_hop(&envelope, &hop_sk).expect("unwrap");
        assert_eq!(recovered, payload);
    }

    #[test]
    fn epic482_1_round_trip_empty_payload() {
        // Empty payload is valid — a 0-byte inner message is a "ping"
        // that proves the circuit terminates at the expected hop.
        let (hop_sk, hop_pk) = fresh_hop();
        let envelope = wrap_for_hop(&[], &hop_pk);
        // Wire size: just the overhead.
        assert_eq!(envelope.len(), ONION_LAYER_OVERHEAD);
        let recovered = unwrap_at_hop(&envelope, &hop_sk).expect("unwrap empty");
        assert_eq!(recovered, Vec::<u8>::new());
    }

    #[test]
    fn epic482_1_envelope_size_is_payload_plus_overhead() {
        // Sanity that the overhead is exactly what the public
        // constant claims — callers (e.g. the cell layer) compute
        // their max payload budget from this.
        let (_, hop_pk) = fresh_hop();
        let env_a = wrap_for_hop(&[0u8; 100], &hop_pk);
        let env_b = wrap_for_hop(&[0u8; 200], &hop_pk);
        assert_eq!(env_a.len(), 100 + ONION_LAYER_OVERHEAD);
        assert_eq!(env_b.len(), 200 + ONION_LAYER_OVERHEAD);
    }

    #[test]
    fn epic482_1_wrong_hop_sk_fails_aead() {
        // The intended hop has key A, but the hop trying to decrypt
        // has key B. AEAD must fail — without this, anyone
        // intercepting an envelope could decrypt it.
        let (_correct_sk, hop_pk) = fresh_hop();
        let (wrong_sk, _) = fresh_hop();
        let envelope = wrap_for_hop(b"secret", &hop_pk);
        let err = unwrap_at_hop(&envelope, &wrong_sk).unwrap_err();
        assert_eq!(err, OnionError::Aead, "wrong hop must fail AEAD");
    }

    #[test]
    fn epic482_1_tampered_ciphertext_fails_aead() {
        let (hop_sk, hop_pk) = fresh_hop();
        let mut envelope = wrap_for_hop(b"data", &hop_pk);
        // Flip a bit deep inside the ciphertext region.
        let ciphertext_start = EPHEMERAL_PK_LEN + NONCE_LEN;
        envelope[ciphertext_start] ^= 0x01;
        let err = unwrap_at_hop(&envelope, &hop_sk).unwrap_err();
        assert_eq!(err, OnionError::Aead, "tampered ciphertext must fail AEAD");
    }

    #[test]
    fn epic482_1_tampered_ephemeral_pk_fails_aead() {
        // An attacker who substitutes the ephemeral_pk thinks they can
        // re-key the AEAD path and win. But the ephemeral_pk is also
        // bound into the AAD, so AEAD verification fails regardless of
        // whether the substitute key produces a "valid" decryption
        // path.
        let (hop_sk, hop_pk) = fresh_hop();
        let mut envelope = wrap_for_hop(b"data", &hop_pk);
        envelope[0] ^= 0x01;
        let err = unwrap_at_hop(&envelope, &hop_sk).unwrap_err();
        assert_eq!(
            err,
            OnionError::Aead,
            "tampered ephemeral_pk must fail AEAD"
        );
    }

    #[test]
    fn epic482_1_tampered_nonce_fails_aead() {
        let (hop_sk, hop_pk) = fresh_hop();
        let mut envelope = wrap_for_hop(b"data", &hop_pk);
        envelope[EPHEMERAL_PK_LEN] ^= 0x01;
        let err = unwrap_at_hop(&envelope, &hop_sk).unwrap_err();
        assert_eq!(err, OnionError::Aead, "tampered nonce must fail AEAD");
    }

    #[test]
    fn epic482_1_too_small_envelope_rejected_pre_aead() {
        let (hop_sk, _) = fresh_hop();
        let too_small = vec![0u8; ONION_LAYER_OVERHEAD - 1];
        let err = unwrap_at_hop(&too_small, &hop_sk).unwrap_err();
        assert!(
            matches!(err, OnionError::EnvelopeTooSmall { .. }),
            "envelope below minimum size must be rejected pre-AEAD: {err:?}"
        );
    }

    #[test]
    fn epic482_1_two_wraps_of_same_payload_produce_distinct_envelopes() {
        // Fresh ephemeral key + random nonce per call → distinct
        // envelope bytes even for identical inputs. Without this
        // property, an observer correlating two captures could confirm
        // "same message resent" without decrypting.
        let (_, hop_pk) = fresh_hop();
        let env_a = wrap_for_hop(b"same payload", &hop_pk);
        let env_b = wrap_for_hop(b"same payload", &hop_pk);
        assert_ne!(
            env_a, env_b,
            "fresh ephemeral + random nonce per wrap must yield distinct envelopes"
        );
    }

    #[test]
    fn epic482_1_layered_three_hop_composition() {
        // Canonical multi-hop pattern. Sender wraps for hop3 first
        // (innermost), then hop2, then hop1 (outermost). Each hop
        // unwraps one layer and forwards the inner bytes to the next.
        // The final hop recovers the original payload.
        let (sk1, pk1) = fresh_hop();
        let (sk2, pk2) = fresh_hop();
        let (sk3, pk3) = fresh_hop();

        let payload = b"this only hop3 sees";

        // Sender side: wrap in REVERSE hop order.
        let inner = wrap_for_hop(payload, &pk3);
        let mid = wrap_for_hop(&inner, &pk2);
        let outer = wrap_for_hop(&mid, &pk1);

        // Hop1 unwraps outer → recovers `mid` bytes (which are
        // hop2's envelope; hop1 cannot decrypt past this layer).
        let to_hop2 = unwrap_at_hop(&outer, &sk1).expect("hop1 unwrap");
        assert_eq!(to_hop2, mid, "hop1 must produce exactly hop2's envelope");

        // Hop2 unwraps the bytes hop1 forwarded → recovers `inner`.
        let to_hop3 = unwrap_at_hop(&to_hop2, &sk2).expect("hop2 unwrap");
        assert_eq!(to_hop3, inner, "hop2 must produce exactly hop3's envelope");

        // Hop3 unwraps the bytes hop2 forwarded → recovers payload.
        let final_payload = unwrap_at_hop(&to_hop3, &sk3).expect("hop3 unwrap");
        assert_eq!(
            final_payload, payload,
            "hop3 must recover the original payload"
        );
    }

    #[test]
    fn epic482_1_layered_hop_cannot_skip_to_inner_layer() {
        // Negative test for the layered composition: hop1 receives
        // the outer envelope. hop3 cannot use its own key to
        // decrypt the OUTER envelope directly — that's what makes
        // the layering meaningful. Without this property, any hop
        // along the path could short-circuit decrypt the whole onion.
        let (_sk1, pk1) = fresh_hop();
        let (_, pk2) = fresh_hop();
        let (sk3, pk3) = fresh_hop();
        let inner = wrap_for_hop(b"secret", &pk3);
        let mid = wrap_for_hop(&inner, &pk2);
        let outer = wrap_for_hop(&mid, &pk1);

        // hop3 attempts to unwrap the outer (hop1's) envelope.
        // AEAD must fail — sk3's diffie_hellman with the OUTER
        // ephemeral_pk produces a shared secret different from
        // the one that key-encrypted the outer ciphertext.
        let err = unwrap_at_hop(&outer, &sk3).unwrap_err();
        assert_eq!(
            err,
            OnionError::Aead,
            "hops cannot skip layers — every hop sees only its own ciphertext"
        );
    }

    #[test]
    fn epic482_1_overhead_constant_matches_components() {
        // Sanity that the public constant operators rely on for
        // payload-budget calculation matches the actual structure.
        assert_eq!(ONION_LAYER_OVERHEAD, EPHEMERAL_PK_LEN + NONCE_LEN + TAG_LEN);
        assert_eq!(ONION_LAYER_OVERHEAD, 60);
    }

    /// an envelope produced for one layer kind
    /// MUST fail AEAD verification when unwrapped at a different
    /// kind. Closes the dispatch-hijack vector where a future wire
    /// format reusing `wrap_for_hop` could see its layers cross-
    /// dispatched into the circuit-peeler (or vice versa).
    #[test]
    fn phase647_h3_cross_kind_unwrap_rejected() {
        let (hop_sk, hop_pk) = fresh_hop();
        let payload = b"circuit-only-payload";
        // Wrap for kind=CIRCUIT, attempt to unwrap as kind=99 (a
        // hypothetical future wire family).
        let envelope = wrap_for_hop_kind(payload, &hop_pk, LAYER_KIND_CIRCUIT);
        let err = unwrap_at_hop_kind(&envelope, &hop_sk, 99).unwrap_err();
        assert_eq!(
            err,
            OnionError::Aead,
            "cross-kind unwrap must fail at AEAD verification"
        );
        // Sanity: same-kind unwrap still succeeds.
        let recovered =
            unwrap_at_hop_kind(&envelope, &hop_sk, LAYER_KIND_CIRCUIT).expect("same-kind unwrap");
        assert_eq!(recovered, payload);
    }
}
