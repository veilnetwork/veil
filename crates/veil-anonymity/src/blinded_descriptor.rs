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

/// Routing the client needs to reach the service (the descriptor plaintext).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlindedDescriptorBody {
    /// Rendezvous relay R that forwards introduces down the service's circuit.
    pub rendezvous_node_id: [u8; 32],
    /// One-time cookie bound to the service's return circuit at R.
    pub auth_cookie: [u8; 16],
    /// Service anonymity x25519 the client seals its introduce to.
    pub receiver_x25519_pk: [u8; 32],
}

impl BlindedDescriptorBody {
    const WIRE: usize = 32 + 16 + 32; // 80

    fn encode(&self) -> [u8; Self::WIRE] {
        let mut b = [0u8; Self::WIRE];
        b[..32].copy_from_slice(&self.rendezvous_node_id);
        b[32..48].copy_from_slice(&self.auth_cookie);
        b[48..80].copy_from_slice(&self.receiver_x25519_pk);
        b
    }

    fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != Self::WIRE {
            return None;
        }
        let mut rendezvous_node_id = [0u8; 32];
        rendezvous_node_id.copy_from_slice(&b[..32]);
        let mut auth_cookie = [0u8; 16];
        auth_cookie.copy_from_slice(&b[32..48]);
        let mut receiver_x25519_pk = [0u8; 32];
        receiver_x25519_pk.copy_from_slice(&b[48..80]);
        Some(Self {
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

/// Wire: `[blinded_pub 32][nonce 12][ct_len u16 BE][ciphertext][sig 64]`.
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

    let mut out = Vec::with_capacity(32 + NONCE_LEN + 2 + ciphertext.len() + SIG_LEN);
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
