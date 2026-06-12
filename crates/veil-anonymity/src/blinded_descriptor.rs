//! Blinded service descriptor (onion-registration #3b; Tor-v3 style). See
//! `PLAN_ANON_SERVICE_ONION_REGISTRATION.md` §7.4.
//!
//! A location-anonymous service publishes its routing info (rendezvous relay R,
//! cookie, anonymity x25519) as a descriptor that is:
//!  * **keyed** in the DHT under `H(domain ‖ blinded_public(identity, period))` —
//!    a per-period, identity-unlinkable key (`key_blinding`), and
//!  * **encrypted** under a key derived from the service IDENTITY + period, and
//!  * **signed** by the per-period BLINDED key.
//!
//! A client that KNOWS the service identity derives the DHT key (to find it), the
//! decryption key (to read it), and verifies the blinded signature. A DHT
//! enumerator that does NOT know the identity sees only a rotating key + an
//! opaque ciphertext — it cannot tell which identity (if any) runs a service.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};

const ENC_KEY_DOMAIN: &[u8] = b"veil.descriptor.enc.v1\0";
const DHT_KEY_DOMAIN: &[u8] = b"veil.descriptor.dhtkey.v1\0";
const AAD_DOMAIN: &[u8] = b"veil.descriptor.aad.v1";

/// Descriptor time-period length (24 h, Tor-v3-ish). The blinded key + DHT key +
/// encryption key all rotate at this cadence; publisher and client compute the
/// same period from their (loosely-synced) clocks.
pub const PERIOD_SECS: u64 = 86_400;

/// The current descriptor period for `now_unix`.
pub fn current_period(now_unix: u64) -> u64 {
    now_unix / PERIOD_SECS
}

/// Routing the client needs to reach the service (the descriptor plaintext).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlindedDescriptorBody {
    /// Service TRANSPORT node_id. The sender signs its `AuthDeliver` over this
    /// (the service verifies by reconstructing it as its own id), so the sender
    /// must learn it — but only AFTER decrypting the descriptor, i.e. only a
    /// client that already knows the service identity. A DHT enumerator never
    /// sees it (it's inside the ciphertext), so unlinkability is preserved.
    pub receiver_node_id: [u8; 32],
    /// Rendezvous relay R that forwards introduces down the service's circuit.
    pub rendezvous_node_id: [u8; 32],
    /// One-time cookie bound to the service's return circuit at R.
    pub auth_cookie: [u8; 16],
    /// Service anonymity x25519 the client seals its introduce to.
    pub receiver_x25519_pk: [u8; 32],
}

impl BlindedDescriptorBody {
    const WIRE: usize = 32 + 32 + 16 + 32; // 112

    fn encode(&self) -> [u8; Self::WIRE] {
        let mut b = [0u8; Self::WIRE];
        b[..32].copy_from_slice(&self.receiver_node_id);
        b[32..64].copy_from_slice(&self.rendezvous_node_id);
        b[64..80].copy_from_slice(&self.auth_cookie);
        b[80..112].copy_from_slice(&self.receiver_x25519_pk);
        b
    }

    fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != Self::WIRE {
            return None;
        }
        let mut receiver_node_id = [0u8; 32];
        receiver_node_id.copy_from_slice(&b[..32]);
        let mut rendezvous_node_id = [0u8; 32];
        rendezvous_node_id.copy_from_slice(&b[32..64]);
        let mut auth_cookie = [0u8; 16];
        auth_cookie.copy_from_slice(&b[64..80]);
        let mut receiver_x25519_pk = [0u8; 32];
        receiver_x25519_pk.copy_from_slice(&b[80..112]);
        Some(Self {
            receiver_node_id,
            rendezvous_node_id,
            auth_cookie,
            receiver_x25519_pk,
        })
    }
}

/// DHT key for a service's descriptor at `period` — derived from the BLINDED
/// key, so it rotates per period and is unlinkable to the identity without it.
/// Both publisher + client compute it from the (known-to-them) service identity.
pub fn descriptor_dht_key(identity_vk: &[u8; 32], period: u64) -> Option<[u8; 32]> {
    let blinded = veil_crypto::key_blinding::blinded_public(identity_vk, period)?;
    let mut h = blake3::Hasher::new();
    h.update(DHT_KEY_DOMAIN);
    h.update(&blinded);
    Some(*h.finalize().as_bytes())
}

/// Per-(identity, period) descriptor encryption key — a client derives it from
/// the service identity it already knows.
fn enc_key(identity_vk: &[u8; 32], period: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(ENC_KEY_DOMAIN);
    h.update(identity_vk);
    h.update(&period.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Wire: `[MAGIC 2][blinded_pub 32][nonce 12][ct_len u16 BE][ciphertext][sig 64]`.
///
/// The 2-byte magic lets the DHT STORE gate (`validate_store_value_by_magic`) and
/// the periodic republish allowlist recognise a blinded descriptor (diff-audit
/// L5) so it PROPAGATES like other self-authenticating records instead of being
/// `store_local`-only. The descriptor is self-authenticating: it carries
/// `blinded_pub` + a signature under it, and its DHT key is `H(domain ‖
/// blinded_pub)` — see [`verify_descriptor_self`].
pub const DESCRIPTOR_DHT_MAGIC: &[u8; 2] = b"od";
const SIG_LEN: usize = 64;
const NONCE_LEN: usize = 12;

/// Service side: seal `body` into a publishable blinded descriptor for `period`,
/// returning `(dht_key, descriptor_bytes)`. `identity_sk` is the 32-byte Ed25519
/// identity seed.
pub fn seal_descriptor(
    identity_sk: &[u8; 32],
    identity_vk: &[u8; 32],
    period: u64,
    body: &BlindedDescriptorBody,
) -> Option<([u8; 32], Vec<u8>)> {
    let blinded_pub = veil_crypto::key_blinding::blinded_public(identity_vk, period)?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let key = enc_key(identity_vk, period);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &body.encode(),
                aad: AAD_DOMAIN,
            },
        )
        .ok()?;

    // Sign (blinded_pub ‖ nonce ‖ ciphertext) with the blinded key.
    let mut signed = Vec::with_capacity(32 + NONCE_LEN + ciphertext.len());
    signed.extend_from_slice(&blinded_pub);
    signed.extend_from_slice(&nonce);
    signed.extend_from_slice(&ciphertext);
    let sig = veil_crypto::key_blinding::sign_blinded(identity_sk, period, &signed)?;

    let mut out = Vec::with_capacity(2 + 32 + NONCE_LEN + 2 + ciphertext.len() + SIG_LEN);
    out.extend_from_slice(DESCRIPTOR_DHT_MAGIC);
    out.extend_from_slice(&blinded_pub);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&sig);

    let dht_key = descriptor_dht_key(identity_vk, period)?;
    Some((dht_key, out))
}

/// Client side: verify + decrypt a descriptor `bytes` published by a service
/// whose identity (`identity_vk`) the client already knows. Returns the routing
/// body, or `None` if the descriptor is for a different identity/period, fails
/// the blinded-signature check, or fails to decrypt.
pub fn open_descriptor(
    identity_vk: &[u8; 32],
    period: u64,
    bytes: &[u8],
) -> Option<BlindedDescriptorBody> {
    // Strip the 2-byte DHT magic prefix (L5).
    if bytes.get(..2)? != DESCRIPTOR_DHT_MAGIC {
        return None;
    }
    let bytes = &bytes[2..];
    let fixed = 32 + NONCE_LEN + 2;
    if bytes.len() < fixed + SIG_LEN {
        return None;
    }
    let blinded_pub: [u8; 32] = bytes[..32].try_into().ok()?;
    // Must match the blinded key WE derive for this identity+period.
    if veil_crypto::key_blinding::blinded_public(identity_vk, period)? != blinded_pub {
        return None;
    }
    let nonce: [u8; NONCE_LEN] = bytes[32..32 + NONCE_LEN].try_into().ok()?;
    let ct_len = u16::from_be_bytes([bytes[32 + NONCE_LEN], bytes[33 + NONCE_LEN]]) as usize;
    let ct_start = fixed;
    let ct_end = ct_start.checked_add(ct_len)?;
    if bytes.len() != ct_end + SIG_LEN {
        return None;
    }
    let ciphertext = &bytes[ct_start..ct_end];
    let sig: [u8; SIG_LEN] = bytes[ct_end..ct_end + SIG_LEN].try_into().ok()?;

    // Verify the blinded signature over (blinded_pub ‖ nonce ‖ ciphertext).
    let mut signed = Vec::with_capacity(32 + NONCE_LEN + ciphertext.len());
    signed.extend_from_slice(&blinded_pub);
    signed.extend_from_slice(&nonce);
    signed.extend_from_slice(ciphertext);
    if !veil_crypto::key_blinding::verify_blinded(identity_vk, period, &signed, &sig) {
        return None;
    }

    // Decrypt.
    let key = enc_key(identity_vk, period);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: AAD_DOMAIN,
            },
        )
        .ok()?;
    BlindedDescriptorBody::decode(&plaintext)
}

/// STORE-gate / republish verifier (diff-audit L5). A relay accepting a blinded
/// descriptor into the DHT does NOT know the service identity, so it verifies the
/// descriptor's SELF-consistency: the signature must verify under the `blinded_pub`
/// the descriptor itself carries, and the descriptor's canonical DHT key is then
/// `H(DHT_KEY_DOMAIN ‖ blinded_pub)`. Returns that key on success (the caller
/// MUST check it equals the STORE key, so a valid descriptor cannot be stored
/// under an attacker-chosen key); `None` on bad magic / length / signature.
///
/// This proves only that whoever signed holds the blinded private key (so a third
/// party cannot forge or grind a descriptor under a victim's key). It does NOT
/// reveal which identity (that needs `open_descriptor` with the identity) — the
/// unlinkability property is preserved.
pub fn verify_descriptor_self(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.get(..2)? != DESCRIPTOR_DHT_MAGIC {
        return None;
    }
    let body = &bytes[2..];
    let fixed = 32 + NONCE_LEN + 2;
    if body.len() < fixed + SIG_LEN {
        return None;
    }
    let blinded_pub: [u8; 32] = body[..32].try_into().ok()?;
    let nonce = &body[32..32 + NONCE_LEN];
    let ct_len = u16::from_be_bytes([body[32 + NONCE_LEN], body[33 + NONCE_LEN]]) as usize;
    let ct_start = fixed;
    let ct_end = ct_start.checked_add(ct_len)?;
    if body.len() != ct_end + SIG_LEN {
        return None;
    }
    let ciphertext = &body[ct_start..ct_end];
    let sig: [u8; SIG_LEN] = body[ct_end..ct_end + SIG_LEN].try_into().ok()?;

    let mut signed = Vec::with_capacity(32 + NONCE_LEN + ciphertext.len());
    signed.extend_from_slice(&blinded_pub);
    signed.extend_from_slice(nonce);
    signed.extend_from_slice(ciphertext);
    if !veil_crypto::key_blinding::verify_under_blinded_pub(&blinded_pub, &signed, &sig) {
        return None;
    }

    let mut h = blake3::Hasher::new();
    h.update(DHT_KEY_DOMAIN);
    h.update(&blinded_pub);
    Some(*h.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use veil_types::SignatureAlgorithm;

    /// Fresh Ed25519 identity → (32-byte seed, 32-byte vk).
    fn identity() -> ([u8; 32], [u8; 32]) {
        let kp = veil_crypto::generate_keypair(SignatureAlgorithm::Ed25519);
        let sk = STANDARD
            .decode(&kp.private_key)
            .unwrap()
            .try_into()
            .unwrap();
        let vk = STANDARD.decode(&kp.public_key).unwrap().try_into().unwrap();
        (sk, vk)
    }

    fn body(tag: u8) -> BlindedDescriptorBody {
        BlindedDescriptorBody {
            receiver_node_id: [tag ^ 0x33; 32],
            rendezvous_node_id: [tag; 32],
            auth_cookie: [tag ^ 0x11; 16],
            receiver_x25519_pk: [tag ^ 0x22; 32],
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let (id_sk, id_vk) = identity();
        let period = 7u64;
        let b = body(0xA5);
        let (dht_key, desc) = seal_descriptor(&id_sk, &id_vk, period, &b).unwrap();
        // DHT key matches the client-derived one (both from the identity).
        assert_eq!(dht_key, descriptor_dht_key(&id_vk, period).unwrap());
        assert_eq!(open_descriptor(&id_vk, period, &desc).unwrap(), b);
    }

    #[test]
    fn verify_descriptor_self_returns_canonical_key_and_rejects_tamper() {
        // diff-audit L5: the STORE gate verifies a descriptor WITHOUT the identity
        // (only its embedded blinded_pub + sig) and returns its canonical DHT key,
        // which the gate binds to the STORE key.
        let (id_sk, id_vk) = identity();
        let period = 9u64;
        let (dht_key, desc) = seal_descriptor(&id_sk, &id_vk, period, &body(0x5A)).unwrap();

        // Valid descriptor → its canonical key equals descriptor_dht_key.
        assert_eq!(verify_descriptor_self(&desc), Some(dht_key));

        // Wrong magic → rejected.
        let mut bad_magic = desc.clone();
        bad_magic[0] ^= 0xFF;
        assert_eq!(verify_descriptor_self(&bad_magic), None);

        // Tampered signature → rejected (proves it really verifies the sig).
        let mut tampered = desc.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 0x01;
        assert_eq!(verify_descriptor_self(&tampered), None);

        // Tampered ciphertext (sig no longer covers it) → rejected.
        let mut ct_tamper = desc.clone();
        ct_tamper[2 + 32 + NONCE_LEN + 2] ^= 0x01; // first ciphertext byte
        assert_eq!(verify_descriptor_self(&ct_tamper), None);

        // Truncated → rejected, not a panic.
        assert_eq!(verify_descriptor_self(&desc[..desc.len() - 1]), None);
        assert_eq!(verify_descriptor_self(&[]), None);
    }

    #[test]
    fn wrong_period_or_identity_or_tamper_rejected() {
        let (id_sk, id_vk) = identity();
        let (_k, desc) = seal_descriptor(&id_sk, &id_vk, 1, &body(1)).unwrap();
        assert!(open_descriptor(&id_vk, 2, &desc).is_none(), "wrong period");
        let (_, other) = identity();
        assert!(
            open_descriptor(&other, 1, &desc).is_none(),
            "wrong identity"
        );
        let mut tampered = desc.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 0xFF; // corrupt signature
        assert!(
            open_descriptor(&id_vk, 1, &tampered).is_none(),
            "tampered sig"
        );
    }

    #[test]
    fn dht_key_unlinkable_across_periods() {
        let (_, vk) = identity();
        assert_ne!(
            descriptor_dht_key(&vk, 1).unwrap(),
            descriptor_dht_key(&vk, 2).unwrap(),
            "DHT key rotates per period"
        );
    }
}
