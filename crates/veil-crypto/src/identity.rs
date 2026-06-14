//! Identity helpers.
//!
//! Two conceptual layers here:
//!
//! 1. **Legacy domain-identity validation** (`identity_signature_is_valid`
//!    `identity_nonce_meets_difficulty`) — the original `[identity]`-config
//!    flow bundling pubkey + privkey + PoW nonce. Kept verbatim for now.
//! 2. **Sovereign identity primitives** — `master_sk` derivation
//!    from `master_seed`, `node_id` binding, and canonical signing-message
//!    builders used by [`proto::identity_document`](crate::proto::identity_document).
//!    See [`docs/identity-model.md`](../../../docs/identity-model.md).

// Legacy domain-identity validation helpers (`identity_signature_is_valid`
// `identity_nonce_meets_difficulty`, `identity_nonce_has_leading_zero`) moved
// to `cfg::identity` in c. They orchestrate crypto primitives over
// a higher-level `DomainIdentity` (which lives in cfg), so the caller-side
// is the natural home — keeps crypto/ free of cfg/ types.

// ═══════════════════════════════════════════════════════════════════════════
// Sovereign identity primitives
// ═══════════════════════════════════════════════════════════════════════════
//
// The items below form the crypto API consumed by the verifier
//the `identity create` / `rotate` CLIs
// and the pairing ceremony. In the
// revocation-related helpers (`revoke_message`, `freshness_message`)
// were removed alongside the in-band revocation flow.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use veil_types::CERTIFY_CONTEXT;

/// Info string for master_sk derivation from master_seed. See
/// [`derive_master_sk_ed25519`].
pub const MASTER_DERIVATION_INFO: &[u8] = b"veil.master.v1";

/// Length of the master seed (32 bytes = 256 bits).
pub const MASTER_SEED_LEN: usize = 32;

/// Derive a 32-byte Ed25519 signing key from the master seed.
///
/// HKDF-SHA256:
/// ```text
/// salt = None
/// ikm = master_seed (32 B)
/// info = "veil.master.v1"
/// okm = 32 B → Ed25519SigningKey::from_bytes
/// ```
///
/// Returns the raw 32-byte secret wrapped [`Zeroizing`] so it's erased
/// from memory on drop. Callers construct the actual [`ed25519_dalek::SigningKey`]
/// from these bytes and should zeroize that too (ed25519-dalek 2.x supports
/// `.zeroize` on the signing key).
pub fn derive_master_sk_ed25519(master_seed: &[u8; MASTER_SEED_LEN]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, master_seed);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(MASTER_DERIVATION_INFO, out.as_mut())
        .expect("32 bytes < 255 * hash_len");
    out
}

/// Derive a `node_id` from a public key.
///
/// simplifies this from the previous domain-tag-prefixed shape
/// (`BLAKE3("veil.identity.v1" || len_be || pk)`) to a plain
/// `BLAKE3(pk)`. This unifies the sovereign-identity address with
/// [`cfg::NodeId::from_public_key`] (which already used the bare hash
/// for the per-device runtime address) — in standalone mode the two
/// addresses coincide because `master_pubkey == device_pubkey`.
///
/// Cross-algorithm collisions are practically impossible: BLAKE3 is
/// a 256-bit hash and the algorithm byte is part of the surrounding
/// `IdentityKey` cert that the verifier checks separately.
///
/// ```text
/// node_id = BLAKE3(master_pubkey)
/// ```
pub fn compute_node_id(master_pubkey: &[u8]) -> [u8; 32] {
    *blake3::hash(master_pubkey).as_bytes()
}

/// Build the canonical bytes that master_sk signs to certify an identity
/// subkey (a "Delegation" cert terminology).
///
/// ```text
/// CERTIFY_CONTEXT
/// || node_id
/// || algo
/// || len(subkey_pubkey) as u16 BE
/// || subkey_pubkey
/// || device_id
/// || valid_from_unix
/// || valid_until_unix
/// ```
pub fn certify_message(
    node_id: &[u8; 32],
    subkey_algo: u8,
    subkey_pubkey: &[u8],
    device_id: &[u8; 32],
    valid_from_unix: u64,
    valid_until_unix: u64,
) -> Vec<u8> {
    let mut msg =
        Vec::with_capacity(CERTIFY_CONTEXT.len() + 32 + 1 + 2 + subkey_pubkey.len() + 32 + 8 + 8);
    msg.extend_from_slice(CERTIFY_CONTEXT);
    msg.extend_from_slice(node_id);
    msg.push(subkey_algo);
    msg.extend_from_slice(&(subkey_pubkey.len() as u16).to_be_bytes());
    msg.extend_from_slice(subkey_pubkey);
    msg.extend_from_slice(device_id);
    msg.extend_from_slice(&valid_from_unix.to_be_bytes());
    msg.extend_from_slice(&valid_until_unix.to_be_bytes());
    msg
}

// dropped `pubkey_hash` — was an alias for `BLAKE3(pubkey)`
// used to derive the stable subkey id in pairing flows. After
// the same derivation is exposed as [`compute_node_id`] (master case)
// and is the default `device_id` for per-device subkeys; see also
// [`cfg::NodeId::from_public_key`]. Callers that previously held a
// `pubkey_hash(pk)` should switch to `compute_node_id(pk)`.

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_sk_derivation_is_deterministic() {
        let seed = [0x42u8; 32];
        let a = derive_master_sk_ed25519(&seed);
        let b = derive_master_sk_ed25519(&seed);
        assert_eq!(*a, *b);
    }

    #[test]
    fn master_sk_changes_with_seed() {
        let a = derive_master_sk_ed25519(&[0x42u8; 32]);
        let b = derive_master_sk_ed25519(&[0x43u8; 32]);
        assert_ne!(*a, *b);
    }

    #[test]
    fn master_sk_produces_valid_ed25519_keypair() {
        use ed25519_dalek::{Signer, SigningKey, Verifier};
        let seed = [0x11u8; 32];
        let sk_bytes = derive_master_sk_ed25519(&seed);
        let sk = SigningKey::from_bytes(&sk_bytes);
        let pk = sk.verifying_key();
        let msg = b"test message";
        let sig = sk.sign(msg);
        pk.verify(msg, &sig)
            .expect("derived master_sk must sign/verify");
    }

    #[test]
    fn node_id_is_deterministic() {
        let pk = vec![0xAAu8; 32];
        let a = compute_node_id(&pk);
        let b = compute_node_id(&pk);
        assert_eq!(a, b);
    }

    #[test]
    fn node_id_changes_with_pubkey() {
        let a = compute_node_id(&[0xAAu8; 32]);
        let b = compute_node_id(&[0xBBu8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn node_id_no_domain_tag_collision() {
        // `compute_node_id` is now a bare BLAKE3 over the pubkey
        // bytes (no length-prefix, no domain tag). Different pubkey
        // values still produce distinct hashes — including pubkeys of
        // different length whose shorter form is a prefix of the longer
        // form. This is the standard cryptographic-hash property; it
        // is just stronger than the previous length-prefix construction.
        let short = vec![0x00u8; 32];
        let mut long = vec![0x00u8; 897]; // Falcon-512 size
        long[..32].copy_from_slice(&short);
        let id_short = compute_node_id(&short);
        let id_long = compute_node_id(&long);
        assert_ne!(id_short, id_long);
    }

    // extraction: `node_id_matches_cfg_node_id` cross-validation test
    // moved to `veilcore/tests/node_id_consistency.rs` because it asserts
    // that crypto::compute_node_id and cfg::NodeId::from_public_key produce
    // identical bytes — a cross-layer assertion that doesn't fit inside
    // standalone veil-crypto.

    #[test]
    fn certify_message_format_stable() {
        let node_id = [0x12u8; 32];
        let pk = vec![0xABu8; 32];
        let device_id = [0x77u8; 32];
        let valid_from = 1_700_000_000u64;
        let valid_until = valid_from + 7 * 86_400;
        let msg = certify_message(&node_id, 0, &pk, &device_id, valid_from, valid_until);
        // Must start with context.
        assert!(msg.starts_with(CERTIFY_CONTEXT));
        let after = &msg[CERTIFY_CONTEXT.len()..];
        // node_id
        assert_eq!(&after[..32], &node_id);
        // algo byte
        assert_eq!(after[32], 0);
        // pk_len + pk
        assert_eq!(&after[33..35], &32u16.to_be_bytes());
        assert_eq!(&after[35..67], &pk[..]);
        // device_id
        assert_eq!(&after[67..99], &device_id);
        // valid_from
        assert_eq!(&after[99..107], &valid_from.to_be_bytes());
        // valid_until
        assert_eq!(&after[107..115], &valid_until.to_be_bytes());
    }

    #[test]
    fn end_to_end_sign_and_verify_cert() {
        use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
        // Genesis: derive master_sk from seed, compute node_id
        let seed = [0xAAu8; 32];
        let master_sk_bytes = derive_master_sk_ed25519(&seed);
        let master_sk = SigningKey::from_bytes(&master_sk_bytes);
        let master_pk: VerifyingKey = master_sk.verifying_key();
        let node_id = compute_node_id(master_pk.as_bytes());

        // Generate a fresh identity subkey (hot key)
        let subkey = SigningKey::from_bytes(&[0xBBu8; 32]);
        let subkey_pk = subkey.verifying_key();
        // device_id is now deterministic = BLAKE3(subkey_pk).
        let device_id = compute_node_id(subkey_pk.as_bytes());
        let valid_from = 1_700_000_000;
        let valid_until = valid_from + 7 * 86_400;

        // Master certifies the subkey
        let cert_msg = certify_message(
            &node_id,
            0,
            subkey_pk.as_bytes(),
            &device_id,
            valid_from,
            valid_until,
        );
        let master_sig = master_sk.sign(&cert_msg);

        // Verifier side: reconstruct the message, verify cert
        let verifier_msg = certify_message(
            &node_id,
            0,
            subkey_pk.as_bytes(),
            &device_id,
            valid_from,
            valid_until,
        );
        master_pk
            .verify(&verifier_msg, &master_sig)
            .expect("cert verifies");
    }
}
