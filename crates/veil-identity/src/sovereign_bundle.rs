//! Password-encrypted, portable sovereign signing material for xVeil devices.
//!
//! The BIP-39 phrase is a password and classical-key anchor, not a container
//! for the much larger Falcon key. Plaintext key bytes exist only in
//! `Zeroizing` memory; the returned bundle is safe to persist and replicate.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use veil_types::SignatureAlgorithm;

use crate::master_file::{
    DEFAULT_M_COST_KIB, DEFAULT_P_COST, DEFAULT_T_COST, MIN_M_COST_KIB, MIN_P_COST, MIN_T_COST,
};

const MAGIC: &[u8; 4] = b"XVSB";
const RECOVERY_MAGIC: &[u8; 4] = b"XVRC";
const VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const AAD: &[u8] = b"xveil.sovereign.bundle.v1";
const RECOVERY_AAD: &[u8] = b"xveil.sovereign.recovery-certificate.v1";
const MAX_BUNDLE_BYTES: usize = 16 * 1024;
const MIN_RECOVERY_CODE_BYTES: usize = 32;
const MAX_RECOVERY_CODE_BYTES: usize = 256;
const MAX_M_COST_KIB: u32 = 1_048_576;
const MAX_T_COST: u32 = 1000;
const MAX_P_COST: u8 = 64;
const MAX_KDF_PRODUCT_KIB: u64 = 256 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SovereignBundleError {
    #[error("invalid recovery phrase: {0}")]
    InvalidPhrase(String),
    #[error("sovereign bundle malformed: {0}")]
    Malformed(String),
    #[error("sovereign bundle uses unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("sovereign bundle password is wrong or bundle was modified")]
    WrongPasswordOrTampered,
    #[error("sovereign bundle crypto failed: {0}")]
    Crypto(String),
}

/// Decrypted material held only for one native signing burst.
pub struct SovereignMaterial {
    pub algorithm: SignatureAlgorithm,
    pub public_key: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
}

impl SovereignMaterial {
    pub fn node_id(&self) -> [u8; 32] {
        veil_crypto::identity::compute_node_id(&self.public_key)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SovereignBundleError> {
        // veil-crypto's decoder immediately wraps the decoded copy in
        // Zeroizing. Keep the unavoidable base64 bridge zeroizing too.
        let private_b64 = Zeroizing::new(STANDARD.encode(&self.private_key[..]));
        let public_b64 = STANDARD.encode(&self.public_key);
        veil_crypto::sign_message(self.algorithm, &public_b64, &private_b64, message)
            .map_err(|e| SovereignBundleError::Crypto(e.to_string()))
    }
}

/// Create a fresh Ed25519+Falcon512 bundle. The phrase-derived Ed25519 half
/// makes accidental cross-phrase import detectable; the random Falcon half is
/// why the encrypted blob must be present on every linked device.
pub fn create_hybrid512(phrase: &[u8]) -> Result<Vec<u8>, SovereignBundleError> {
    let phrase_str = std::str::from_utf8(phrase)
        .map_err(|_| SovereignBundleError::InvalidPhrase("not UTF-8".into()))?;
    let master_seed = crate::master_seed::decode_master_seed_from_phrase(phrase_str)
        .map_err(|e| SovereignBundleError::InvalidPhrase(e.to_string()))?;
    let ed_seed = veil_crypto::identity::derive_master_sk_ed25519(&master_seed);
    let pair = veil_crypto::signature::hybrid512_keypair_from_ed25519_seed(&ed_seed);
    encode_material(
        SignatureAlgorithm::Ed25519Falcon512Hybrid,
        &pair.public_key,
        &pair.private_key,
        phrase,
        DEFAULT_M_COST_KIB,
        DEFAULT_T_COST,
        DEFAULT_P_COST,
    )
}

pub fn open(bundle: &[u8], phrase: &[u8]) -> Result<SovereignMaterial, SovereignBundleError> {
    if bundle.len() > MAX_BUNDLE_BYTES {
        return Err(SovereignBundleError::Malformed("bundle too large".into()));
    }
    let parsed = parse_outer(bundle)?;
    validate_costs(parsed.m_cost, parsed.t_cost, parsed.p_cost)?;
    let key = derive_key(
        phrase,
        parsed.salt,
        parsed.m_cost,
        parsed.t_cost,
        parsed.p_cost,
    )?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(parsed.nonce),
                Payload {
                    msg: parsed.ciphertext,
                    aad: AAD,
                },
            )
            .map_err(|_| SovereignBundleError::WrongPasswordOrTampered)?,
    );
    let material = parse_plaintext(&plaintext)?;
    validate_material_keypair(&material)?;

    // Bind the encrypted random Falcon half to the recovery phrase's stable
    // Ed25519 half. This also rejects a validly encrypted bundle copied from a
    // different identity under an accidentally reused password.
    let phrase_str =
        std::str::from_utf8(phrase).map_err(|_| SovereignBundleError::WrongPasswordOrTampered)?;
    let master_seed = crate::master_seed::decode_master_seed_from_phrase(phrase_str)
        .map_err(|_| SovereignBundleError::WrongPasswordOrTampered)?;
    let ed_seed = veil_crypto::identity::derive_master_sk_ed25519(&master_seed);
    let ed_public = ed25519_dalek::SigningKey::from_bytes(&ed_seed)
        .verifying_key()
        .to_bytes();
    if material.public_key.get(..32) != Some(ed_public.as_slice()) {
        return Err(SovereignBundleError::WrongPasswordOrTampered);
    }
    Ok(material)
}

/// Re-wrap an existing XVSB as an offline recovery certificate. The exact
/// Ed25519+Falcon512 material is preserved, so its full public key and derived
/// node id do not rotate. Both passwords are caller-owned mutable buffers at
/// the FFI layer and are wiped there; plaintext keys stay in `Zeroizing` RAM.
pub fn export_recovery_certificate(
    credential: &[u8],
    current_secret: &[u8],
    recovery_code: &[u8],
) -> Result<Vec<u8>, SovereignBundleError> {
    validate_recovery_code(recovery_code)?;
    let material = if credential.starts_with(MAGIC) {
        open(credential, current_secret)?
    } else if credential.starts_with(RECOVERY_MAGIC) {
        open_recovery_certificate(credential, current_secret)?
    } else {
        return Err(SovereignBundleError::Malformed(
            "unsupported sovereign credential".into(),
        ));
    };
    encode_recovery_material(&material, recovery_code)
}

/// Open an XVRC recovery certificate with its independent high-entropy code.
/// Unlike XVSB, the password is not a BIP-39 phrase; continuity is proven by
/// the public node id bound into the outer AEAD header plus a private/public
/// signing self-check after decryption.
pub fn open_recovery_certificate(
    certificate: &[u8],
    recovery_code: &[u8],
) -> Result<SovereignMaterial, SovereignBundleError> {
    if certificate.len() > MAX_BUNDLE_BYTES {
        return Err(SovereignBundleError::Malformed(
            "recovery certificate too large".into(),
        ));
    }
    validate_recovery_code(recovery_code)?;
    let parsed = parse_recovery_outer(certificate)?;
    validate_costs(parsed.m_cost, parsed.t_cost, parsed.p_cost)?;
    let key = derive_key(
        recovery_code,
        parsed.salt,
        parsed.m_cost,
        parsed.t_cost,
        parsed.p_cost,
    )?;
    let aad = recovery_aad(&parsed.node_id);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(parsed.nonce),
                Payload {
                    msg: parsed.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| SovereignBundleError::WrongPasswordOrTampered)?,
    );
    let material = parse_plaintext(&plaintext)?;
    validate_material_keypair(&material)?;
    if material.node_id() != parsed.node_id {
        return Err(SovereignBundleError::WrongPasswordOrTampered);
    }
    Ok(material)
}

fn validate_recovery_code(code: &[u8]) -> Result<(), SovereignBundleError> {
    if !(MIN_RECOVERY_CODE_BYTES..=MAX_RECOVERY_CODE_BYTES).contains(&code.len()) {
        return Err(SovereignBundleError::Malformed(
            "recovery code length out of range".into(),
        ));
    }
    Ok(())
}

fn recovery_aad(node_id: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECOVERY_AAD.len() + node_id.len());
    aad.extend_from_slice(RECOVERY_AAD);
    aad.extend_from_slice(node_id);
    aad
}

fn encode_recovery_material(
    material: &SovereignMaterial,
    recovery_code: &[u8],
) -> Result<Vec<u8>, SovereignBundleError> {
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        7 + material.public_key.len() + material.private_key.len(),
    ));
    plaintext.push(material.algorithm.wire_byte());
    plaintext.extend_from_slice(&(material.public_key.len() as u16).to_be_bytes());
    plaintext.extend_from_slice(&material.public_key);
    plaintext.extend_from_slice(&(material.private_key.len() as u16).to_be_bytes());
    plaintext.extend_from_slice(&material.private_key);

    let node_id = material.node_id();
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = derive_key(
        recovery_code,
        &salt,
        DEFAULT_M_COST_KIB,
        DEFAULT_T_COST,
        DEFAULT_P_COST as u8,
    )?;
    let aad = recovery_aad(&node_id);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| SovereignBundleError::Crypto("AEAD encrypt".into()))?;

    let mut out = Vec::with_capacity(64 + ciphertext.len());
    out.extend_from_slice(RECOVERY_MAGIC);
    out.push(VERSION);
    out.push(KDF_ARGON2ID);
    out.extend_from_slice(&node_id);
    out.extend_from_slice(&DEFAULT_M_COST_KIB.to_be_bytes());
    out.extend_from_slice(&DEFAULT_T_COST.to_be_bytes());
    out.push(DEFAULT_P_COST as u8);
    out.push(SALT_LEN as u8);
    out.extend_from_slice(&salt);
    out.push(NONCE_LEN as u8);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&ciphertext);
    if out.len() > MAX_BUNDLE_BYTES {
        return Err(SovereignBundleError::Malformed(
            "encoded recovery certificate too large".into(),
        ));
    }
    Ok(out)
}

fn encode_material(
    algorithm: SignatureAlgorithm,
    public_key: &[u8],
    private_key: &[u8],
    phrase: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Vec<u8>, SovereignBundleError> {
    let mut plaintext =
        Zeroizing::new(Vec::with_capacity(7 + public_key.len() + private_key.len()));
    plaintext.push(algorithm.wire_byte());
    plaintext.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
    plaintext.extend_from_slice(public_key);
    plaintext.extend_from_slice(&(private_key.len() as u16).to_be_bytes());
    plaintext.extend_from_slice(private_key);

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = derive_key(phrase, &salt, m_cost, t_cost, p_cost as u8)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key[..]));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| SovereignBundleError::Crypto("AEAD encrypt".into()))?;

    let mut out = Vec::with_capacity(32 + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(KDF_ARGON2ID);
    out.extend_from_slice(&m_cost.to_be_bytes());
    out.extend_from_slice(&t_cost.to_be_bytes());
    out.push(p_cost as u8);
    out.push(SALT_LEN as u8);
    out.extend_from_slice(&salt);
    out.push(NONCE_LEN as u8);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&ciphertext);
    if out.len() > MAX_BUNDLE_BYTES {
        return Err(SovereignBundleError::Malformed(
            "encoded bundle too large".into(),
        ));
    }
    Ok(out)
}

struct ParsedOuter<'a> {
    m_cost: u32,
    t_cost: u32,
    p_cost: u8,
    salt: &'a [u8],
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

struct ParsedRecoveryOuter<'a> {
    node_id: [u8; 32],
    m_cost: u32,
    t_cost: u32,
    p_cost: u8,
    salt: &'a [u8],
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

fn parse_outer(bytes: &[u8]) -> Result<ParsedOuter<'_>, SovereignBundleError> {
    let mut p = 0usize;
    let take = |p: &mut usize, n: usize| -> Result<&[u8], SovereignBundleError> {
        let end = p
            .checked_add(n)
            .ok_or_else(|| SovereignBundleError::Malformed("length overflow".into()))?;
        let value = bytes
            .get(*p..end)
            .ok_or_else(|| SovereignBundleError::Malformed("truncated".into()))?;
        *p = end;
        Ok(value)
    };
    if take(&mut p, 4)? != MAGIC || take(&mut p, 1)?[0] != VERSION {
        return Err(SovereignBundleError::Malformed("bad magic/version".into()));
    }
    if take(&mut p, 1)?[0] != KDF_ARGON2ID {
        return Err(SovereignBundleError::Malformed("unsupported KDF".into()));
    }
    let m_cost = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap());
    let t_cost = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap());
    let p_cost = take(&mut p, 1)?[0];
    let salt_len = take(&mut p, 1)?[0] as usize;
    if salt_len != SALT_LEN {
        return Err(SovereignBundleError::Malformed("bad salt length".into()));
    }
    let salt = take(&mut p, salt_len)?;
    let nonce_len = take(&mut p, 1)?[0] as usize;
    if nonce_len != NONCE_LEN {
        return Err(SovereignBundleError::Malformed("bad nonce length".into()));
    }
    let nonce = take(&mut p, nonce_len)?;
    let ct_len = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
    let ciphertext = take(&mut p, ct_len)?;
    if p != bytes.len() {
        return Err(SovereignBundleError::Malformed("trailing bytes".into()));
    }
    Ok(ParsedOuter {
        m_cost,
        t_cost,
        p_cost,
        salt,
        nonce,
        ciphertext,
    })
}

fn parse_recovery_outer(bytes: &[u8]) -> Result<ParsedRecoveryOuter<'_>, SovereignBundleError> {
    let mut p = 0usize;
    let take = |p: &mut usize, n: usize| -> Result<&[u8], SovereignBundleError> {
        let end = p
            .checked_add(n)
            .ok_or_else(|| SovereignBundleError::Malformed("length overflow".into()))?;
        let value = bytes
            .get(*p..end)
            .ok_or_else(|| SovereignBundleError::Malformed("truncated".into()))?;
        *p = end;
        Ok(value)
    };
    if take(&mut p, 4)? != RECOVERY_MAGIC || take(&mut p, 1)?[0] != VERSION {
        return Err(SovereignBundleError::Malformed(
            "bad recovery magic/version".into(),
        ));
    }
    if take(&mut p, 1)?[0] != KDF_ARGON2ID {
        return Err(SovereignBundleError::Malformed("unsupported KDF".into()));
    }
    let mut node_id = [0u8; 32];
    node_id.copy_from_slice(take(&mut p, 32)?);
    let m_cost = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap());
    let t_cost = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap());
    let p_cost = take(&mut p, 1)?[0];
    let salt_len = take(&mut p, 1)?[0] as usize;
    if salt_len != SALT_LEN {
        return Err(SovereignBundleError::Malformed("bad salt length".into()));
    }
    let salt = take(&mut p, salt_len)?;
    let nonce_len = take(&mut p, 1)?[0] as usize;
    if nonce_len != NONCE_LEN {
        return Err(SovereignBundleError::Malformed("bad nonce length".into()));
    }
    let nonce = take(&mut p, nonce_len)?;
    let ct_len = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
    let ciphertext = take(&mut p, ct_len)?;
    if p != bytes.len() {
        return Err(SovereignBundleError::Malformed("trailing bytes".into()));
    }
    Ok(ParsedRecoveryOuter {
        node_id,
        m_cost,
        t_cost,
        p_cost,
        salt,
        nonce,
        ciphertext,
    })
}

fn parse_plaintext(bytes: &[u8]) -> Result<SovereignMaterial, SovereignBundleError> {
    if bytes.len() < 5 {
        return Err(SovereignBundleError::Malformed(
            "plaintext truncated".into(),
        ));
    }
    let algorithm = SignatureAlgorithm::from_wire_byte(bytes[0])
        .ok_or(SovereignBundleError::UnsupportedAlgorithm)?;
    if algorithm != SignatureAlgorithm::Ed25519Falcon512Hybrid {
        return Err(SovereignBundleError::UnsupportedAlgorithm);
    }
    let pk_len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
    let pk_end = 3usize
        .checked_add(pk_len)
        .ok_or_else(|| SovereignBundleError::Malformed("length overflow".into()))?;
    let public_key = bytes
        .get(3..pk_end)
        .ok_or_else(|| SovereignBundleError::Malformed("public key truncated".into()))?
        .to_vec();
    let sk_len_bytes = bytes
        .get(pk_end..pk_end + 2)
        .ok_or_else(|| SovereignBundleError::Malformed("private length truncated".into()))?;
    let sk_len = u16::from_be_bytes([sk_len_bytes[0], sk_len_bytes[1]]) as usize;
    let sk_start = pk_end + 2;
    let sk_end = sk_start
        .checked_add(sk_len)
        .ok_or_else(|| SovereignBundleError::Malformed("length overflow".into()))?;
    let private_key = Zeroizing::new(
        bytes
            .get(sk_start..sk_end)
            .ok_or_else(|| SovereignBundleError::Malformed("private key truncated".into()))?
            .to_vec(),
    );
    if sk_end != bytes.len() {
        return Err(SovereignBundleError::Malformed(
            "plaintext trailing bytes".into(),
        ));
    }
    // Reuse canonical parsers for exact algorithm/key-shape validation.
    let public_b64 = STANDARD.encode(&public_key);
    veil_crypto::signature::decode_public_key(algorithm, &public_b64)
        .map_err(|e| SovereignBundleError::Malformed(e.to_string()))?;
    let private_b64 = Zeroizing::new(STANDARD.encode(&private_key[..]));
    veil_crypto::signature::decode_private_key(algorithm, &private_b64)
        .map_err(|e| SovereignBundleError::Malformed(e.to_string()))?;
    Ok(SovereignMaterial {
        algorithm,
        public_key,
        private_key,
    })
}

fn validate_material_keypair(material: &SovereignMaterial) -> Result<(), SovereignBundleError> {
    const CHALLENGE: &[u8] = b"xveil.sovereign.material-keypair.v1";
    let signature = material.sign(CHALLENGE)?;
    let public_b64 = STANDARD.encode(&material.public_key);
    veil_crypto::verify_message(material.algorithm, &public_b64, CHALLENGE, &signature)
        .map_err(|_| SovereignBundleError::WrongPasswordOrTampered)
}

fn validate_costs(m: u32, t: u32, p: u8) -> Result<(), SovereignBundleError> {
    if m < MIN_M_COST_KIB || t < MIN_T_COST || p < MIN_P_COST {
        return Err(SovereignBundleError::Malformed(
            "KDF parameters below minimum".into(),
        ));
    }
    if m > MAX_M_COST_KIB
        || t > MAX_T_COST
        || p > MAX_P_COST
        || (m as u64).saturating_mul(t as u64) > MAX_KDF_PRODUCT_KIB
    {
        return Err(SovereignBundleError::Malformed(
            "KDF parameters above maximum".into(),
        ));
    }
    Ok(())
}

fn derive_key(
    password: &[u8],
    salt: &[u8],
    m: u32,
    t: u32,
    p: u8,
) -> Result<Zeroizing<[u8; 32]>, SovereignBundleError> {
    validate_costs(m, t, p)?;
    let params = Params::new(m, t, p as u32, Some(32))
        .map_err(|e| SovereignBundleError::Crypto(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(password, salt, &mut *key)
        .map_err(|e| SovereignBundleError::Crypto(e.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn phrase() -> String {
        let seed = crate::master_seed::generate_master_seed();
        crate::master_seed::encode_master_seed_to_phrase(&seed)
            .unwrap()
            .to_string()
    }

    #[test]
    fn hybrid_bundle_round_trip_signs_and_binds_full_node_id() {
        let phrase = phrase();
        let bundle = create_hybrid512(phrase.as_bytes()).unwrap();
        let material = open(&bundle, phrase.as_bytes()).unwrap();
        assert_eq!(
            material.algorithm,
            SignatureAlgorithm::Ed25519Falcon512Hybrid
        );
        assert_eq!(material.public_key.len(), 929);
        let message = b"xveil-device-manifest-v2";
        let signature = material.sign(message).unwrap();
        let public_b64 = STANDARD.encode(&material.public_key);
        veil_crypto::verify_message(material.algorithm, &public_b64, message, &signature).unwrap();
        assert_eq!(
            material.node_id(),
            veil_crypto::identity::compute_node_id(&material.public_key)
        );
    }

    #[test]
    fn wrong_phrase_and_tampering_are_rejected() {
        let recovery_phrase = phrase();
        let other = phrase();
        let mut bundle = create_hybrid512(recovery_phrase.as_bytes()).unwrap();
        assert!(matches!(
            open(&bundle, other.as_bytes()),
            Err(SovereignBundleError::WrongPasswordOrTampered)
        ));
        let last = bundle.len() - 1;
        bundle[last] ^= 1;
        assert!(matches!(
            open(&bundle, recovery_phrase.as_bytes()),
            Err(SovereignBundleError::WrongPasswordOrTampered)
        ));
    }

    #[test]
    fn recovery_certificate_preserves_full_public_key_and_node_id() {
        let phrase = phrase();
        let bundle = create_hybrid512(phrase.as_bytes()).unwrap();
        let original = open(&bundle, phrase.as_bytes()).unwrap();
        let code = b"xvrc-6DJm7JdJ55YtS5Xx1QEe9T9VyuXxJY2QpQqZ";
        let certificate = export_recovery_certificate(&bundle, phrase.as_bytes(), code).unwrap();
        assert_eq!(&certificate[..4], RECOVERY_MAGIC);
        assert_eq!(&certificate[6..38], &original.node_id());

        let restored = open_recovery_certificate(&certificate, code).unwrap();
        assert_eq!(restored.algorithm, original.algorithm);
        assert_eq!(restored.public_key, original.public_key);
        assert_eq!(restored.node_id(), original.node_id());
        let message = b"xveil-recovery-continuity";
        let signature = restored.sign(message).unwrap();
        veil_crypto::verify_message(
            restored.algorithm,
            &STANDARD.encode(&restored.public_key),
            message,
            &signature,
        )
        .unwrap();

        let next_code = b"xvrc-next-independent-code-123456789012345";
        let replacement = export_recovery_certificate(&certificate, code, next_code).unwrap();
        let reopened = open_recovery_certificate(&replacement, next_code).unwrap();
        assert_eq!(reopened.node_id(), original.node_id());
        assert_eq!(reopened.public_key, original.public_key);
    }

    #[test]
    fn recovery_certificate_wrong_code_tamper_and_weak_code_fail_closed() {
        let phrase = phrase();
        let bundle = create_hybrid512(phrase.as_bytes()).unwrap();
        let code = b"xvrc-correct-code-with-at-least-32-bytes";
        let other = b"xvrc-other-code-with-at-least-32-bytes!!";
        let certificate = export_recovery_certificate(&bundle, phrase.as_bytes(), code).unwrap();
        assert!(matches!(
            open_recovery_certificate(&certificate, other),
            Err(SovereignBundleError::WrongPasswordOrTampered)
        ));

        let mut header_tamper = certificate.clone();
        header_tamper[6] ^= 1; // public node id is AEAD-bound
        assert!(matches!(
            open_recovery_certificate(&header_tamper, code),
            Err(SovereignBundleError::WrongPasswordOrTampered)
        ));
        let mut ciphertext_tamper = certificate;
        let last = ciphertext_tamper.len() - 1;
        ciphertext_tamper[last] ^= 1;
        assert!(matches!(
            open_recovery_certificate(&ciphertext_tamper, code),
            Err(SovereignBundleError::WrongPasswordOrTampered)
        ));
        assert!(matches!(
            export_recovery_certificate(&bundle, phrase.as_bytes(), b"short"),
            Err(SovereignBundleError::Malformed(_))
        ));
    }
}
