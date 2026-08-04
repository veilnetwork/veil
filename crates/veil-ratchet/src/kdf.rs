//! The three key-derivation layers of the ratchet.
//!
//! All three are HKDF-SHA256 with distinct, version-tagged `info` labels, so
//! no output of one layer can ever be mistaken for an output of another. The
//! `v1` tag is a protocol version: bumping it invalidates every session in
//! flight, so it moves only when the derivation itself changes.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::KEY_LEN;

/// Root chain step. Distinct from the chain and message labels.
const INFO_ROOT: &[u8] = b"veil.ratchet.v1.root";
/// Symmetric chain step.
const INFO_CHAIN: &[u8] = b"veil.ratchet.v1.chain";
/// Message key extraction from a chain key.
const INFO_MSG: &[u8] = b"veil.ratchet.v1.msg";
/// AEAD key and nonce expansion from a message key.
const INFO_AEAD: &[u8] = b"veil.ratchet.v1.aead";

/// AEAD nonce length (ChaCha20-Poly1305).
pub(crate) const NONCE_LEN: usize = 12;

/// Root-key step: `(root, chain) = HKDF(salt = rk, ikm = dh ‖ pq)`.
///
/// The post-quantum contribution is `Some` in every asymmetric step but one —
/// the responder's very first, where the initiator has not yet seen an
/// encapsulation key to answer. That single case is safe because the root key
/// it mixes into is the PQXDH output, which already contains an ML-KEM shared
/// secret.
///
/// `None` is not encoded as 32 zero bytes. It shortens the keying material
/// from 64 bytes to 32, so "no post-quantum leg" and "a post-quantum leg that
/// happened to be all zeros" are different HKDF inputs and cannot be confused
/// for each other by anyone constructing a header.
pub(crate) fn kdf_rk(
    root_key: &[u8; KEY_LEN],
    dh_output: &[u8; KEY_LEN],
    pq_output: Option<&[u8; KEY_LEN]>,
) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let mut ikm = Zeroizing::new(Vec::with_capacity(2 * KEY_LEN));
    ikm.extend_from_slice(dh_output);
    if let Some(pq) = pq_output {
        ikm.extend_from_slice(pq);
    }

    let hk = Hkdf::<Sha256>::new(Some(root_key.as_slice()), &ikm);
    let mut out = Zeroizing::new([0u8; 2 * KEY_LEN]);
    hk.expand(INFO_ROOT, out.as_mut())
        .expect("HKDF-SHA256 with a 64-byte output is always valid");

    let mut new_root = [0u8; KEY_LEN];
    let mut new_chain = [0u8; KEY_LEN];
    new_root.copy_from_slice(&out[..KEY_LEN]);
    new_chain.copy_from_slice(&out[KEY_LEN..]);
    (new_root, new_chain)
}

/// Symmetric chain step: `(next_chain, message_key) = f(chain_key)`.
///
/// Two HKDF-Expand calls over the same pseudo-random key with different `info`
/// labels. Advancing is one-way: `next_chain` cannot be walked back to
/// `chain_key`, which is what makes a leaked current chain key useless against
/// earlier messages.
pub(crate) fn kdf_ck(chain_key: &[u8; KEY_LEN]) -> ([u8; KEY_LEN], Zeroizing<[u8; KEY_LEN]>) {
    let hk = Hkdf::<Sha256>::from_prk(chain_key.as_slice())
        .expect("a 32-byte pseudo-random key is exactly SHA-256's output length");

    let mut next_chain = [0u8; KEY_LEN];
    let mut msg_key = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(INFO_CHAIN, &mut next_chain)
        .expect("HKDF-SHA256 with a 32-byte output is always valid");
    hk.expand(INFO_MSG, msg_key.as_mut())
        .expect("HKDF-SHA256 with a 32-byte output is always valid");

    (next_chain, msg_key)
}

/// Expand a message key into the AEAD key and its nonce.
///
/// Deriving the nonce rather than transmitting it keeps 12 bytes off every
/// frame and makes nonce reuse structurally impossible: a message key is used
/// exactly once, so the nonce it expands to is used exactly once.
pub(crate) fn message_keys(msg_key: &[u8; KEY_LEN]) -> (Zeroizing<[u8; KEY_LEN]>, [u8; NONCE_LEN]) {
    let hk = Hkdf::<Sha256>::from_prk(msg_key.as_slice())
        .expect("a 32-byte pseudo-random key is exactly SHA-256's output length");
    let mut out = Zeroizing::new([0u8; KEY_LEN + NONCE_LEN]);
    hk.expand(INFO_AEAD, out.as_mut())
        .expect("HKDF-SHA256 with a 44-byte output is always valid");

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&out[..KEY_LEN]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&out[KEY_LEN..]);
    (key, nonce)
}

/// Zeroize a chain key held behind an `Option`.
pub(crate) fn zeroize_opt(k: &mut Option<[u8; KEY_LEN]>) {
    if let Some(v) = k.as_mut() {
        v.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer vectors.
    ///
    /// These are not borrowed from another implementation — this derivation is
    /// specific to veil's `info` labels, so no external vector exists. They are
    /// pinned here so that any change to the labels, the hash, or the input
    /// layout fails loudly instead of silently re-keying every deployed
    /// session. The primitives underneath (HKDF-SHA256, ML-KEM-768, X25519)
    /// carry their own vectors inside `hkdf`, `ml-kem` and `x25519-dalek`.
    #[test]
    fn kdf_rk_known_answer() {
        let (root, chain) = kdf_rk(&[0x01u8; 32], &[0x02u8; 32], Some(&[0x03u8; 32]));
        assert_eq!(
            hex(&root),
            "d1c5810eae8e48cd88f0a01c6576b8eb45331972788ef23239057b57aa4d4aaf"
        );
        assert_eq!(
            hex(&chain),
            "40fafe8c44b7ceffa5fb1a8a646fec09ab75dcb7797289465522e89ded5c935e"
        );

        // The same inputs with the post-quantum leg absent — the responder's
        // very first step, and the only case where it may be.
        let (root, chain) = kdf_rk(&[0x01u8; 32], &[0x02u8; 32], None);
        assert_eq!(
            hex(&root),
            "4c7473b56980dc5c40b57f810fbed73c56fc356b6d0477ebe40f9b346538bb6a"
        );
        assert_eq!(
            hex(&chain),
            "2baab902c90f3959e3ef071db181cf78870de4e932d986481513e69d578659a1"
        );
    }

    #[test]
    fn kdf_ck_known_answer() {
        let (next, mk) = kdf_ck(&[0x04u8; 32]);
        assert_eq!(
            hex(&next),
            "10c539cb20aaddd09ce5208e3d1f39f25252f971ed5e9389d55bb48c2b23b157"
        );
        assert_eq!(
            hex(&*mk),
            "0750dab3a27fbf19a7cdcbd81a066e29d1759f5360f04866edafb6fd56a140ab"
        );
    }

    #[test]
    fn message_keys_known_answer() {
        let (key, nonce) = message_keys(&[0x05u8; 32]);
        assert_eq!(
            hex(&*key),
            "c20b69e9f993cf1400cb076079a2a1a476162a836a7896cb4d38fec87c402ca2"
        );
        assert_eq!(hex(&nonce), "f9da1e8bd30f892316045787");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn absent_pq_leg_is_not_the_same_as_a_zero_pq_leg() {
        let rk = [0x11u8; 32];
        let dh = [0x22u8; 32];
        let zero = [0u8; 32];

        let with_zeros = kdf_rk(&rk, &dh, Some(&zero));
        let without = kdf_rk(&rk, &dh, None);

        assert_ne!(
            with_zeros, without,
            "a header omitting the post-quantum leg must not derive the same \
             keys as one carrying an all-zero secret"
        );
    }

    #[test]
    fn every_kdf_layer_is_domain_separated() {
        let k = [0x55u8; 32];
        let (root, chain) = kdf_rk(&k, &k, Some(&k));
        let (next_chain, msg) = kdf_ck(&k);
        let (aead_key, _) = message_keys(&k);

        let all = [root, chain, next_chain, *msg, *aead_key];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "layers {i} and {j} collided");
                }
            }
        }
    }

    #[test]
    fn chain_step_is_one_way_and_advances() {
        let ck0 = [0x77u8; 32];
        let (ck1, mk1) = kdf_ck(&ck0);
        let (ck2, mk2) = kdf_ck(&ck1);
        assert_ne!(ck0, ck1);
        assert_ne!(ck1, ck2);
        assert_ne!(*mk1, *mk2);
    }

    #[test]
    fn message_keys_split_key_and_nonce() {
        let (k1, n1) = message_keys(&[0x09u8; 32]);
        let (k2, n2) = message_keys(&[0x09u8; 32]);
        let (k3, n3) = message_keys(&[0x0Au8; 32]);
        assert_eq!((*k1, n1), (*k2, n2), "derivation must be deterministic");
        assert_ne!((*k1, n1), (*k3, n3));
        assert_ne!(&k1[..12], &n1[..], "key and nonce must not overlap");
    }

    #[test]
    fn root_step_binds_both_legs() {
        let rk = [0x31u8; 32];
        let dh_a = [0x32u8; 32];
        let dh_b = [0x33u8; 32];
        let pq_a = [0x34u8; 32];
        let pq_b = [0x35u8; 32];

        let base = kdf_rk(&rk, &dh_a, Some(&pq_a));
        assert_ne!(
            base,
            kdf_rk(&rk, &dh_b, Some(&pq_a)),
            "changing the DH leg must change the output"
        );
        assert_ne!(
            base,
            kdf_rk(&rk, &dh_a, Some(&pq_b)),
            "changing the ML-KEM leg must change the output"
        );
        assert_ne!(
            base,
            kdf_rk(&[0x36u8; 32], &dh_a, Some(&pq_a)),
            "changing the root must change the output"
        );
    }

    #[test]
    fn concatenation_is_unambiguous() {
        // `dh ‖ pq` is two fixed-width 32-byte fields, so no choice of one can
        // impersonate a different split of the other. Pinned because a future
        // variable-length leg would silently reintroduce the ambiguity.
        let a = kdf_rk(&[0u8; 32], &[0xAAu8; 32], Some(&[0xBBu8; 32]));
        let b = kdf_rk(&[0u8; 32], &[0xBBu8; 32], Some(&[0xAAu8; 32]));
        assert_ne!(a, b);
    }
}
