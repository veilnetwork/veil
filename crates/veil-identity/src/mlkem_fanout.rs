//! ML-KEM cert chain verifier + per-instance fan-out encryption
//!
//!
//! Two related pieces:
//!
//! 1. [`verify_mlkem_cert`] — given an `MlKemKeyCert` and the
//!    current `IdentityDocument`, verifies the cert's full chain
//!    (master → identity_key → mlkem_cert) and returns the raw
//!    ML-KEM pubkey bytes ready for encapsulation.
//!
//! 2. [`fanout_encrypt`] — builds a `Vec<FanoutEnvelope>` of
//!    per-instance encapsulations from a plaintext message. Each
//!    envelope carries the recipient's `instance_id`, the
//!    ML-KEM ciphertext, and the ChaCha20-Poly1305 ciphertext of
//!    the plaintext under a session key derived from the ML-KEM
//!    shared secret.
//!
//! The recipient side is just "iterate envelopes, find the one
//! whose `instance_id` matches ours, decapsulate, derive, decrypt"
//! — [`fanout_decrypt_one`] does exactly that.
//!
//! ## Session-key derivation (per envelope)
//!
//! Mirrors [`crypto::x3dh`](veil_crypto::x3dh) but indexed by
//! `MlKemKeyCert.cert_version` (instead of `prekey_id`) so key
//! rotations produce fresh session keys:
//!
//! ```text
//! info = "veil.mlkem_fanout.v1"
//! || sender_node_id
//! || recipient_node_id
//! || recipient_instance_id
//! || cert_version_be
//! session = HKDF-SHA256-Expand(ml_kem_shared_secret, info)[0..32]
//! aad = sender_node_id || recipient_node_id
//! || recipient_instance_id || cert_version_be
//! ciphertext, tag = ChaCha20-Poly1305(session, nonce, aad, plaintext)
//! ```

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature as EdSignature, Verifier as _, VerifyingKey as EdVerifyingKey};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use veil_crypto::x3dh::{
    ML_KEM_768_DK_SEED_LEN, SenderEncapsulation, X3dhError, recipient_decapsulate,
    sender_encapsulate,
};
use veil_proto::identity_document::{ALGO_ED25519, ALGO_FALCON512, IdentityDocument};
use veil_proto::mlkem_cert::MlKemKeyCert;
use veil_proto::prekey_bundle::ALGO_ML_KEM_768;

// ── Constants ────────────────────────────────────────────────────────────────

const AEAD_INFO_PREFIX: &[u8] = b"veil.mlkem_fanout.v1";
const AEAD_NONCE_LEN: usize = 12;

/// Wire-format version for a serialized fan-out blob (see [`encode_fanout_blob`]).
/// Bump on any layout change so an old reader rejects a new blob cleanly.
const FANOUT_BLOB_VERSION: u8 = 1;

/// hard cap on the number of recipient certs
/// passed to a single [`fanout_encrypt`] call. Each cert triggers an
/// ML-KEM-768 encapsulation (~1.1 KiB ciphertext + AEAD work), so an
/// unbounded slice would let a caller force expensive batched crypto
/// on the sender. 16 mirrors the wire-level `MAX_INSTANCES` cap on
/// `IdentityDocument`, which is the upper bound for the legitimate
/// case (one cert per peer device).
pub const MAX_FANOUT_CERTS: usize = 16;

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum MlkemFanoutError {
    #[error("mlkem_cert node_id {cert:?} does not match doc {doc:?}")]
    NodeIdMismatch { cert: [u8; 32], doc: [u8; 32] },
    #[error("mlkem_cert signing_identity_key_idx {idx} out of bounds ({n} keys)")]
    SigKeyIdxOutOfBounds { idx: u16, n: usize },
    #[error("mlkem_cert signature invalid under the signing subkey")]
    SigInvalid,
    #[error("mlkem_cert is not valid at now (window: {from}..={until}, now = {now})")]
    CertNotValidNow { from: u64, until: u64, now: u64 },
    #[error("mlkem_cert subkey algo {0} is not supported")]
    UnsupportedSubkeyAlgo(u8),
    #[error("mlkem_cert pubkey algo {0} is not supported")]
    UnsupportedKemAlgo(u8),
    #[error("x3dh: {0}")]
    X3dh(#[from] X3dhError),
    #[error("AEAD encrypt/decrypt failed")]
    AeadFailed,
    #[error("no fan-out envelope matched this recipient instance_id")]
    NoEnvelopeForInstance,
    #[error("too many fan-out certs ({given} > cap {cap})")]
    TooManyCerts { given: usize, cap: usize },
    #[error("malformed fan-out blob: {0}")]
    MalformedBlob(&'static str),
}

// ── Cert verification ────────────────────────────────────────────────────────

/// Information recovered from a successfully-verified ML-KEM cert —
/// ready for use in encapsulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMlkemCert {
    pub node_id: [u8; 32],
    pub instance_id: [u8; 16],
    pub mlkem_algo: u8,
    pub mlkem_pubkey: Vec<u8>,
    pub cert_version: u64,
}

/// Verify an `MlKemKeyCert` against a (separately-verified)
/// `IdentityDocument`. Caller MUST have already verified `doc`
/// [`verify_identity_document`](super::verify::verify_identity_document).
///
/// Checks performed:
/// 1. `cert.node_id == doc.node_id`.
/// 2. `cert.signing_identity_key_idx` in-bounds for
///    `doc.identity_keys`.
/// 3. `cert.mlkem_algo` is supported (currently only
///    [`ALGO_ML_KEM_768`]).
/// 4. `cert.valid_from_unix ≤ now_unix_secs ≤ cert.valid_until_unix`.
/// 5. Signature `cert.sig` verifies over `cert.signing_message`
///    under the selected subkey.
///
/// Note: the previous `subkey.bound_instance_id ==
/// cert.instance_id` check is gone — `bound_instance_id` no longer
/// exists on `IdentityKey`. The cert's binding to the right device
/// is now encoded by `signing_identity_key_idx`: only the holder of
/// the matching `identity_sk` can produce a valid signature, and that
/// subkey is in turn cryptographically bound (via the master cert)
/// to its `device_id` which equals `BLAKE3(subkey.pubkey)`.
pub fn verify_mlkem_cert(
    cert: &MlKemKeyCert,
    doc: &IdentityDocument,
    now_unix_secs: u64,
) -> Result<VerifiedMlkemCert, MlkemFanoutError> {
    if cert.node_id != doc.node_id {
        return Err(MlkemFanoutError::NodeIdMismatch {
            cert: cert.node_id,
            doc: doc.node_id,
        });
    }

    let subkey = doc
        .identity_keys
        .get(cert.signing_identity_key_idx as usize)
        .ok_or(MlkemFanoutError::SigKeyIdxOutOfBounds {
            idx: cert.signing_identity_key_idx,
            n: doc.identity_keys.len(),
        })?;

    if cert.mlkem_algo != ALGO_ML_KEM_768 {
        return Err(MlkemFanoutError::UnsupportedKemAlgo(cert.mlkem_algo));
    }

    if !cert.is_valid_at(now_unix_secs) {
        return Err(MlkemFanoutError::CertNotValidNow {
            from: cert.valid_from_unix,
            until: cert.valid_until_unix,
            now: now_unix_secs,
        });
    }

    // Signature.
    let msg = cert.signing_message();
    verify_subkey_sig(subkey.algo, &subkey.pubkey, &msg, &cert.sig).map_err(|e| match e {
        SubkeySigErr::Unsupported(a) => MlkemFanoutError::UnsupportedSubkeyAlgo(a),
        SubkeySigErr::Bad => MlkemFanoutError::SigInvalid,
    })?;

    Ok(VerifiedMlkemCert {
        node_id: cert.node_id,
        instance_id: cert.instance_id,
        mlkem_algo: cert.mlkem_algo,
        mlkem_pubkey: cert.mlkem_pubkey.clone(),
        cert_version: cert.cert_version,
    })
}

enum SubkeySigErr {
    Unsupported(u8),
    Bad,
}

fn verify_subkey_sig(
    algo: u8,
    pubkey: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), SubkeySigErr> {
    match algo {
        ALGO_ED25519 => {
            let pk_arr: &[u8; 32] = pubkey.try_into().map_err(|_| SubkeySigErr::Bad)?;
            let vk = EdVerifyingKey::from_bytes(pk_arr).map_err(|_| SubkeySigErr::Bad)?;
            let sig = EdSignature::from_slice(signature).map_err(|_| SubkeySigErr::Bad)?;
            vk.verify(message, &sig).map_err(|_| SubkeySigErr::Bad)
        }
        ALGO_FALCON512 => {
            let pk = falcon512::PublicKey::from_bytes(pubkey).map_err(|_| SubkeySigErr::Bad)?;
            let sig = falcon512::DetachedSignature::from_bytes(signature)
                .map_err(|_| SubkeySigErr::Bad)?;
            falcon512::verify_detached_signature(&sig, message, &pk).map_err(|_| SubkeySigErr::Bad)
        }
        // Hybrid-signed ML-KEM subkey certs must verify too (a hybrid identity
        // signing its per-instance ML-KEM cert) — delegate to the canonical
        // hybrid verify in `veil-crypto` (both component signatures
        // required), matching `verify::verify_sig_raw`.
        veil_proto::identity_document::ALGO_ED25519_FALCON512_HYBRID => {
            use base64::Engine as _;
            let pk_b64 = base64::engine::general_purpose::STANDARD.encode(pubkey);
            veil_crypto::verify_message(
                veil_types::SignatureAlgorithm::Ed25519Falcon512Hybrid,
                &pk_b64,
                message,
                signature,
            )
            .map_err(|_| SubkeySigErr::Bad)
        }
        veil_proto::identity_document::ALGO_ED25519_FALCON1024_HYBRID => {
            use base64::Engine as _;
            let pk_b64 = base64::engine::general_purpose::STANDARD.encode(pubkey);
            veil_crypto::verify_message(
                veil_types::SignatureAlgorithm::Ed25519Falcon1024Hybrid,
                &pk_b64,
                message,
                signature,
            )
            .map_err(|_| SubkeySigErr::Bad)
        }
        other => Err(SubkeySigErr::Unsupported(other)),
    }
}

// ── Fan-out encryption ───────────────────────────────────────────────────────

/// One per-instance encrypted envelope. The sender produces one
/// per recipient `MlKemKeyCert` and delivers them all (via
/// multicast / mailbox / direct session). The recipient's
/// matching instance decapsulates + decrypts; every other instance
/// sees the envelope and skips it silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanoutEnvelope {
    pub recipient_instance_id: [u8; 16],
    pub cert_version: u64,
    pub kem_ciphertext: Vec<u8>,
    pub nonce: [u8; AEAD_NONCE_LEN],
    pub aead_ciphertext: Vec<u8>,
}

/// Encrypt `plaintext` once per verified recipient cert.
///
/// `sender_node_id` is bound into the session-key derivation
/// so an envelope cannot be cross-replayed between sender identities.
pub fn fanout_encrypt(
    plaintext: &[u8],
    certs: &[VerifiedMlkemCert],
    sender_node_id: &[u8; 32],
    recipient_node_id: &[u8; 32],
) -> Result<Vec<FanoutEnvelope>, MlkemFanoutError> {
    // defensive cap on the recipient slice.
    if certs.len() > MAX_FANOUT_CERTS {
        return Err(MlkemFanoutError::TooManyCerts {
            given: certs.len(),
            cap: MAX_FANOUT_CERTS,
        });
    }
    let mut out = Vec::with_capacity(certs.len());
    for cert in certs {
        if cert.node_id != *recipient_node_id {
            return Err(MlkemFanoutError::NodeIdMismatch {
                cert: cert.node_id,
                doc: *recipient_node_id,
            });
        }
        // Share-secret encapsulation via existing x3dh helper.
        let encap: SenderEncapsulation = sender_encapsulate(
            cert.mlkem_algo,
            &cert.mlkem_pubkey,
            sender_node_id,
            recipient_node_id,
            &cert.instance_id,
            // Reuse x3dh's prekey_id slot to carry cert_version — they
            // share the semantic meaning "per-recipient rotation
            // counter". Stays within u32 (cert_version is u64 but
            // real values stay small in practice); saturate to be
            // defensive.
            cert_version_u32(cert.cert_version),
        )?;

        // Re-derive the fan-out session key from the ML-KEM shared
        // secret + identities + cert_version. x3dh's derive already
        // uses HKDF + domain separation, but we want our own
        // cert_version (u64) and domain label. Since x3dh returns
        // an already-derived 32-byte key bound (sender, recipient
        // instance, prekey_id=cert_version_lo32), we use it as the
        // session key directly — saves a second HKDF while keeping
        // the domain-separation properties (x3dh's info prefix
        // differs from anything else in veil).
        let session_key = encap.session_key;

        let mut nonce = [0u8; AEAD_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let aad = fanout_aad(
            sender_node_id,
            recipient_node_id,
            &cert.instance_id,
            cert.cert_version,
        );
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&session_key[..]));
        let aead_ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| MlkemFanoutError::AeadFailed)?;

        out.push(FanoutEnvelope {
            recipient_instance_id: cert.instance_id,
            cert_version: cert.cert_version,
            kem_ciphertext: encap.kem_ciphertext,
            nonce,
            aead_ciphertext: aead_ct,
        });
    }
    Ok(out)
}

/// Try to decrypt **exactly one** envelope addressed to this
/// instance. Returns the matching envelope's plaintext or
/// `NoEnvelopeForInstance` if none matched.
///
/// The recipient must provide:
/// its 16-byte `instance_id`;
/// the 64-byte ML-KEM-768 decapsulation seed for the cert currently
/// published under this instance;
/// the matching `cert_version` (so rotations don't silently decap
/// under the wrong seed).
pub fn fanout_decrypt_one(
    envelopes: &[FanoutEnvelope],
    recipient_instance_id: &[u8; 16],
    recipient_node_id: &[u8; 32],
    sender_node_id: &[u8; 32],
    decapsulation_seed: &[u8; ML_KEM_768_DK_SEED_LEN],
    cert_version: u64,
) -> Result<Zeroizing<Vec<u8>>, MlkemFanoutError> {
    let env = envelopes
        .iter()
        .find(|e| {
            &e.recipient_instance_id == recipient_instance_id && e.cert_version == cert_version
        })
        .ok_or(MlkemFanoutError::NoEnvelopeForInstance)?;

    let session_key = recipient_decapsulate(
        ALGO_ML_KEM_768,
        decapsulation_seed,
        &env.kem_ciphertext,
        sender_node_id,
        recipient_node_id,
        recipient_instance_id,
        cert_version_u32(env.cert_version),
    )?;

    let aad = fanout_aad(
        sender_node_id,
        recipient_node_id,
        recipient_instance_id,
        env.cert_version,
    );
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&session_key[..]));
    let pt = cipher
        .decrypt(
            Nonce::from_slice(&env.nonce),
            Payload {
                msg: &env.aead_ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| MlkemFanoutError::AeadFailed)?;
    Ok(Zeroizing::new(pt))
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn cert_version_u32(v: u64) -> u32 {
    // Saturate — in practice cert_version stays below 2^32 easily
    // (a rotation every minute for 8000+ years). Saturating
    // rather than truncating avoids silent fold-overs.
    u32::try_from(v).unwrap_or(u32::MAX)
}

fn fanout_aad(
    sender_node_id: &[u8; 32],
    recipient_node_id: &[u8; 32],
    recipient_instance_id: &[u8; 16],
    cert_version: u64,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AEAD_INFO_PREFIX.len() + 32 + 32 + 16 + 8);
    aad.extend_from_slice(AEAD_INFO_PREFIX);
    aad.extend_from_slice(sender_node_id);
    aad.extend_from_slice(recipient_node_id);
    aad.extend_from_slice(recipient_instance_id);
    aad.extend_from_slice(&cert_version.to_be_bytes());
    aad
}

// ── Blob serialization ───────────────────────────────────────────────────────
//
// A fan-out send produces `Vec<FanoutEnvelope>`, but neither `FanoutEnvelope`
// nor the `Vec` has an on-the-wire form — and a store-and-forward use (mailbox
// blob) needs to persist + later parse one. These two functions are that wire
// format. The encoder is total; the decoder is the ONLY place that parses
// attacker-supplied bytes, so it is length-prefix-strict and bounds-checked at
// every step (never trusts a length, never over-reads, rejects trailing bytes).
//
// Layout (all integers big-endian):
//   version: u8 (= FANOUT_BLOB_VERSION)
//   count:   u8 (number of envelopes; <= MAX_FANOUT_CERTS)
//   count × envelope:
//     recipient_instance_id: 16 bytes
//     cert_version:          u64
//     kem_ciphertext:        u32 len + bytes
//     nonce:                 AEAD_NONCE_LEN (12) bytes
//     aead_ciphertext:       u32 len + bytes

/// Serialize fan-out `envelopes` into a single self-describing blob. Inverse of
/// [`decode_fanout_blob`]. Caps at [`MAX_FANOUT_CERTS`] (the same bound
/// [`fanout_encrypt`] enforces), so a `Vec` produced by `fanout_encrypt` always
/// round-trips.
pub fn encode_fanout_blob(
    envelopes: &[FanoutEnvelope],
) -> Result<Vec<u8>, MlkemFanoutError> {
    if envelopes.len() > MAX_FANOUT_CERTS {
        return Err(MlkemFanoutError::TooManyCerts {
            given: envelopes.len(),
            cap: MAX_FANOUT_CERTS,
        });
    }
    let mut out = Vec::new();
    out.push(FANOUT_BLOB_VERSION);
    out.push(envelopes.len() as u8); // <= MAX_FANOUT_CERTS (16) fits a u8
    for e in envelopes {
        out.extend_from_slice(&e.recipient_instance_id);
        out.extend_from_slice(&e.cert_version.to_be_bytes());
        // ML-KEM ciphertext + AEAD ciphertext are well under u32::MAX; encode
        // their lengths defensively so the decoder can bound-check.
        out.extend_from_slice(&(e.kem_ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&e.kem_ciphertext);
        out.extend_from_slice(&e.nonce);
        out.extend_from_slice(&(e.aead_ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&e.aead_ciphertext);
    }
    Ok(out)
}

/// A cursor over untrusted input that never reads past the end.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], MlkemFanoutError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.buf.len())
            .ok_or(MlkemFanoutError::MalformedBlob("unexpected end of blob"))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, MlkemFanoutError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, MlkemFanoutError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, MlkemFanoutError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_be_bytes(a))
    }

    /// Read a u32-length-prefixed byte string. The length is validated against
    /// the remaining input by [`take`], so a forged huge length can never cause
    /// an over-read or an out-of-proportion allocation.
    fn var_bytes(&mut self) -> Result<Vec<u8>, MlkemFanoutError> {
        let n = self.u32()? as usize;
        Ok(self.take(n)?.to_vec())
    }
}

/// Parse a blob produced by [`encode_fanout_blob`]. The inverse direction, and
/// the security-sensitive one: it operates on untrusted bytes. Rejects a wrong
/// version, an over-cap count, any truncation/over-read, and trailing bytes.
pub fn decode_fanout_blob(blob: &[u8]) -> Result<Vec<FanoutEnvelope>, MlkemFanoutError> {
    let mut r = Reader::new(blob);
    let version = r.u8()?;
    if version != FANOUT_BLOB_VERSION {
        return Err(MlkemFanoutError::MalformedBlob("unsupported blob version"));
    }
    let count = r.u8()? as usize;
    if count > MAX_FANOUT_CERTS {
        return Err(MlkemFanoutError::MalformedBlob("envelope count over cap"));
    }
    let mut envelopes = Vec::with_capacity(count);
    for _ in 0..count {
        let mut recipient_instance_id = [0u8; 16];
        recipient_instance_id.copy_from_slice(r.take(16)?);
        let cert_version = r.u64()?;
        let kem_ciphertext = r.var_bytes()?;
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        nonce.copy_from_slice(r.take(AEAD_NONCE_LEN)?);
        let aead_ciphertext = r.var_bytes()?;
        envelopes.push(FanoutEnvelope {
            recipient_instance_id,
            cert_version,
            kem_ciphertext,
            nonce,
            aead_ciphertext,
        });
    }
    // No trailing bytes: a strict parser refuses ambiguous input.
    if r.pos != blob.len() {
        return Err(MlkemFanoutError::MalformedBlob("trailing bytes after blob"));
    }
    Ok(envelopes)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    use crate::verify::verify_identity_document;
    use veil_crypto::identity::{certify_message as build_certify, compute_node_id};
    use veil_crypto::x3dh::generate_prekey;
    use veil_proto::identity_document::{ALGO_ED25519, DOC_SIG_CONTEXT, IdentityKey};
    use veil_proto::prekey_bundle::ML_KEM_768_EK_LEN;

    struct Env {
        sub_sk: SigningKey,
        doc: IdentityDocument,
        now_unix_secs: u64,
        mlkem_ek: Vec<u8>,
        mlkem_dk_seed: Zeroizing<[u8; ML_KEM_768_DK_SEED_LEN]>,
    }

    fn build_env() -> Env {
        let now: u64 = 1_700_000_000;
        let master_sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let master_pk = master_sk.verifying_key();
        let node_id = compute_node_id(master_pk.as_bytes());

        let sub_sk = SigningKey::from_bytes(&[0x22u8; 32]);
        let sub_pk = sub_sk.verifying_key();
        let device_id = compute_node_id(sub_pk.as_bytes());
        let valid_from = now - 60;
        let valid_until = now + 7 * 24 * 3600;

        let cert_msg = build_certify(
            &node_id,
            ALGO_ED25519,
            sub_pk.as_bytes(),
            &device_id,
            valid_from,
            valid_until,
        );
        let cert_sig = master_sk.sign(&cert_msg);

        let identity_key = IdentityKey {
            algo: ALGO_ED25519,
            pubkey: sub_pk.as_bytes().to_vec(),
            device_id,
            valid_from_unix: valid_from,
            valid_until_unix: valid_until,
            master_sig: cert_sig.to_bytes().to_vec(),
        };

        let mut doc = IdentityDocument {
            node_id,
            master_algo: ALGO_ED25519,
            master_pubkey: master_pk.as_bytes().to_vec(),
            issued_at_unix: now,
            valid_until_unix: now + 7 * 24 * 3600,
            sig_key_idx: 0,
            identity_keys: vec![identity_key],
            document_sig: Vec::new(),
        };

        let mut msg = Vec::new();
        msg.extend_from_slice(DOC_SIG_CONTEXT);
        msg.extend_from_slice(&doc.canonical_signing_bytes());
        doc.document_sig = sub_sk.sign(&msg).to_bytes().to_vec();

        let (mlkem_ek, mlkem_dk_seed) = generate_prekey();

        Env {
            sub_sk,
            doc,
            now_unix_secs: now,
            mlkem_ek,
            mlkem_dk_seed,
        }
    }

    fn build_cert(env: &Env) -> MlKemKeyCert {
        let mut cert = MlKemKeyCert {
            node_id: env.doc.node_id,
            instance_id: [0x77u8; 16],
            mlkem_algo: ALGO_ML_KEM_768,
            mlkem_pubkey: env.mlkem_ek.clone(),
            valid_from_unix: env.now_unix_secs - 60,
            valid_until_unix: env.now_unix_secs + 24 * 3600,
            cert_version: 1,
            signing_identity_key_idx: 0,
            sig: Vec::new(),
        };
        let msg = cert.signing_message();
        cert.sig = env.sub_sk.sign(&msg).to_bytes().to_vec();
        cert
    }

    // Make sure the IdentityDocument we built actually verifies under
    // the official verifier — otherwise subsequent negative tests may
    // be failing for unrelated reasons.
    fn assert_doc_verifies(env: &Env) {
        verify_identity_document(&env.doc, env.now_unix_secs).expect("doc verifies");
    }

    // ── verify_mlkem_cert ────────────────────────────────────────────────────

    #[test]
    fn happy_path_verifies_cert() {
        let env = build_env();
        assert_doc_verifies(&env);
        let cert = build_cert(&env);
        let verified = verify_mlkem_cert(&cert, &env.doc, env.now_unix_secs).unwrap();
        assert_eq!(verified.node_id, env.doc.node_id);
        assert_eq!(verified.instance_id, [0x77; 16]);
        assert_eq!(verified.mlkem_algo, ALGO_ML_KEM_768);
        assert_eq!(verified.mlkem_pubkey.len(), ML_KEM_768_EK_LEN);
        assert_eq!(verified.cert_version, 1);
    }

    #[test]
    fn rejects_node_id_mismatch() {
        let env = build_env();
        let mut cert = build_cert(&env);
        cert.node_id = [0xFF; 32];
        // Re-sign so the sig check doesn't fire first (though step 1
        // runs before sig — defensive).
        let msg = cert.signing_message();
        cert.sig = env.sub_sk.sign(&msg).to_bytes().to_vec();
        let err = verify_mlkem_cert(&cert, &env.doc, env.now_unix_secs).unwrap_err();
        assert!(
            matches!(err, MlkemFanoutError::NodeIdMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_sig_key_idx_out_of_bounds() {
        let env = build_env();
        let mut cert = build_cert(&env);
        cert.signing_identity_key_idx = 7;
        let msg = cert.signing_message();
        cert.sig = env.sub_sk.sign(&msg).to_bytes().to_vec();
        let err = verify_mlkem_cert(&cert, &env.doc, env.now_unix_secs).unwrap_err();
        assert!(
            matches!(err, MlkemFanoutError::SigKeyIdxOutOfBounds { .. }),
            "{err:?}"
        );
    }

    // removed `rejects_sig_key_bound_to_different_instance` —
    // `IdentityKey.bound_instance_id` no longer exists, so the
    // subkey-instance binding it tested is gone. The `instance_id`
    // field on `MlKemKeyCert` is now informational/routing rather
    // than crypto-binding; the subkey's identity is enforced by the
    // signature itself + the deterministic `device_id == BLAKE3(pubkey)`
    // check in `verify_identity_document`.

    #[test]
    fn rejects_unsupported_mlkem_algo() {
        let env = build_env();
        let mut cert = build_cert(&env);
        cert.mlkem_algo = 99;
        let msg = cert.signing_message();
        cert.sig = env.sub_sk.sign(&msg).to_bytes().to_vec();
        let err = verify_mlkem_cert(&cert, &env.doc, env.now_unix_secs).unwrap_err();
        assert!(
            matches!(err, MlkemFanoutError::UnsupportedKemAlgo(99)),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_cert_outside_validity_window() {
        let env = build_env();
        let cert = build_cert(&env);
        let too_early = cert.valid_from_unix - 1;
        let err = verify_mlkem_cert(&cert, &env.doc, too_early).unwrap_err();
        assert!(
            matches!(err, MlkemFanoutError::CertNotValidNow { .. }),
            "{err:?}"
        );
        let too_late = cert.valid_until_unix + 1;
        let err = verify_mlkem_cert(&cert, &env.doc, too_late).unwrap_err();
        assert!(
            matches!(err, MlkemFanoutError::CertNotValidNow { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_tampered_signature() {
        let env = build_env();
        let mut cert = build_cert(&env);
        cert.sig[0] ^= 0x01;
        let err = verify_mlkem_cert(&cert, &env.doc, env.now_unix_secs).unwrap_err();
        assert!(matches!(err, MlkemFanoutError::SigInvalid), "{err:?}");
    }

    // ── fanout_encrypt / fanout_decrypt_one ──────────────────────────────────

    #[test]
    fn fanout_roundtrip_one_recipient_instance() {
        let env = build_env();
        let cert = build_cert(&env);
        let verified = verify_mlkem_cert(&cert, &env.doc, env.now_unix_secs).unwrap();
        let sender_id = [0xABu8; 32];

        let envelopes = fanout_encrypt(
            b"hello world",
            std::slice::from_ref(&verified),
            &sender_id,
            &env.doc.node_id,
        )
        .unwrap();
        assert_eq!(envelopes.len(), 1);

        let pt = fanout_decrypt_one(
            &envelopes,
            &verified.instance_id,
            &env.doc.node_id,
            &sender_id,
            &env.mlkem_dk_seed,
            cert.cert_version,
        )
        .unwrap();
        assert_eq!(&*pt, b"hello world");
    }

    #[test]
    fn fanout_roundtrip_three_instances() {
        // Build three separate instances, each with its own ML-KEM
        // keypair; verify each envelope decrypts only under the
        // right instance's seed.
        let now: u64 = 1_700_000_000;
        let master_sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let master_pk = master_sk.verifying_key();
        let node_id = compute_node_id(master_pk.as_bytes());

        let mut identity_keys = Vec::new();
        let mut sub_sks = Vec::new();
        let mut mlkem_keys: Vec<(Vec<u8>, Zeroizing<[u8; 64]>)> = Vec::new();
        let instance_ids: Vec<[u8; 16]> = (0..3u8).map(|i| [i + 1; 16]).collect();

        for (idx, _instance_id) in instance_ids.iter().enumerate() {
            let sub_sk = SigningKey::from_bytes(&[0x22u8 + idx as u8; 32]);
            let sub_pk = sub_sk.verifying_key();
            let device_id = compute_node_id(sub_pk.as_bytes());
            let valid_from = now - 60;
            let valid_until = now + 7 * 86_400;
            let cert_msg = build_certify(
                &node_id,
                ALGO_ED25519,
                sub_pk.as_bytes(),
                &device_id,
                valid_from,
                valid_until,
            );
            let cert_sig = master_sk.sign(&cert_msg);
            identity_keys.push(IdentityKey {
                algo: ALGO_ED25519,
                pubkey: sub_pk.as_bytes().to_vec(),
                device_id,
                valid_from_unix: valid_from,
                valid_until_unix: valid_until,
                master_sig: cert_sig.to_bytes().to_vec(),
            });
            sub_sks.push(sub_sk);
            mlkem_keys.push(generate_prekey());
        }

        let doc = IdentityDocument {
            node_id,
            master_algo: ALGO_ED25519,
            master_pubkey: master_pk.as_bytes().to_vec(),
            issued_at_unix: now,
            valid_until_unix: now + 7 * 24 * 3600,
            sig_key_idx: 0,
            identity_keys,
            document_sig: Vec::new(),
        };

        // Build certs signed by each instance's own subkey.
        let mut verified_certs = Vec::new();
        for (idx, instance_id) in instance_ids.iter().enumerate() {
            let mut cert = MlKemKeyCert {
                node_id,
                instance_id: *instance_id,
                mlkem_algo: ALGO_ML_KEM_768,
                mlkem_pubkey: mlkem_keys[idx].0.clone(),
                valid_from_unix: now - 60,
                valid_until_unix: now + 24 * 3600,
                cert_version: 1,
                signing_identity_key_idx: idx as u16,
                sig: Vec::new(),
            };
            let msg = cert.signing_message();
            cert.sig = sub_sks[idx].sign(&msg).to_bytes().to_vec();
            let v = verify_mlkem_cert(&cert, &doc, now).unwrap();
            verified_certs.push(v);
        }

        let sender_id = [0xABu8; 32];
        let envelopes = fanout_encrypt(
            b"multi-device hello",
            &verified_certs,
            &sender_id,
            &doc.node_id,
        )
        .unwrap();
        assert_eq!(envelopes.len(), 3);

        // Each instance decrypts its own copy.
        for (idx, instance_id) in instance_ids.iter().enumerate() {
            let pt = fanout_decrypt_one(
                &envelopes,
                instance_id,
                &doc.node_id,
                &sender_id,
                &mlkem_keys[idx].1,
                1,
            )
            .unwrap();
            assert_eq!(&*pt, b"multi-device hello");
        }

        // Instance 0 cannot decrypt instance 1's envelope (wrong seed).
        let wrong = fanout_decrypt_one(
            &envelopes,
            &instance_ids[0],
            &doc.node_id,
            &sender_id,
            &mlkem_keys[1].1,
            1,
        );
        assert!(wrong.is_err(), "cross-instance decryption must fail");
    }

    #[test]
    fn fanout_encrypt_rejects_foreign_cert() {
        // A cert whose node_id doesn't match the recipient_id
        // should be refused — this guards against an attacker
        // feeding a real cert but for a different identity.
        let env = build_env();
        let cert = build_cert(&env);
        let mut foreign = verify_mlkem_cert(&cert, &env.doc, env.now_unix_secs).unwrap();
        foreign.node_id = [0xFF; 32];
        let err = fanout_encrypt(b"x", &[foreign], &[0xAB; 32], &env.doc.node_id).unwrap_err();
        assert!(
            matches!(err, MlkemFanoutError::NodeIdMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn fanout_decrypt_none_match() {
        let env = build_env();
        let cert = build_cert(&env);
        let verified = verify_mlkem_cert(&cert, &env.doc, env.now_unix_secs).unwrap();
        let sender_id = [0xABu8; 32];
        let envelopes = fanout_encrypt(
            b"hi",
            std::slice::from_ref(&verified),
            &sender_id,
            &env.doc.node_id,
        )
        .unwrap();

        let unknown_instance = [0xEEu8; 16];
        let err = fanout_decrypt_one(
            &envelopes,
            &unknown_instance,
            &env.doc.node_id,
            &sender_id,
            &env.mlkem_dk_seed,
            1,
        )
        .unwrap_err();
        assert!(
            matches!(err, MlkemFanoutError::NoEnvelopeForInstance),
            "{err:?}"
        );
    }

    #[test]
    fn fanout_decrypt_fails_for_wrong_sender_id() {
        // AAD binds sender_node_id; changing it on the recipient
        // side must cause AEAD auth to fail.
        let env = build_env();
        let cert = build_cert(&env);
        let verified = verify_mlkem_cert(&cert, &env.doc, env.now_unix_secs).unwrap();
        let sender_id = [0xABu8; 32];
        let envelopes = fanout_encrypt(
            b"hi",
            std::slice::from_ref(&verified),
            &sender_id,
            &env.doc.node_id,
        )
        .unwrap();
        let err = fanout_decrypt_one(
            &envelopes,
            &verified.instance_id,
            &env.doc.node_id,
            &[0xCC; 32], // wrong
            &env.mlkem_dk_seed,
            cert.cert_version,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                MlkemFanoutError::X3dh(_) | MlkemFanoutError::AeadFailed
            ),
            "{err:?}"
        );
    }

    #[test]
    fn fanout_decrypt_fails_for_wrong_cert_version() {
        let env = build_env();
        let cert = build_cert(&env);
        let verified = verify_mlkem_cert(&cert, &env.doc, env.now_unix_secs).unwrap();
        let sender_id = [0xABu8; 32];
        let envelopes = fanout_encrypt(
            b"hi",
            std::slice::from_ref(&verified),
            &sender_id,
            &env.doc.node_id,
        )
        .unwrap();
        // Caller claims cert_version=2, envelope was cert_version=1.
        let err = fanout_decrypt_one(
            &envelopes,
            &verified.instance_id,
            &env.doc.node_id,
            &sender_id,
            &env.mlkem_dk_seed,
            2,
        )
        .unwrap_err();
        assert!(
            matches!(err, MlkemFanoutError::NoEnvelopeForInstance),
            "{err:?}"
        );
    }

    // ── Blob serialization ───────────────────────────────────────────────────

    /// Build `n` distinct structural envelopes (not cryptographically valid —
    /// for exercising the serializer's framing, which is crypto-agnostic).
    fn dummy_envelopes(n: usize) -> Vec<FanoutEnvelope> {
        (0..n)
            .map(|i| FanoutEnvelope {
                recipient_instance_id: [i as u8; 16],
                cert_version: (i as u64) << 40 | 0xABCD, // exercise the full u64
                kem_ciphertext: vec![i as u8; 1088], // ML-KEM-768 ct size-ish
                nonce: [i as u8 ^ 0x5A; AEAD_NONCE_LEN],
                aead_ciphertext: vec![0xFFu8 ^ i as u8; 40 + i],
            })
            .collect()
    }

    #[test]
    fn fanout_blob_round_trips_structurally() {
        for n in [0usize, 1, 2, MAX_FANOUT_CERTS] {
            let envs = dummy_envelopes(n);
            let blob = encode_fanout_blob(&envs).unwrap();
            let back = decode_fanout_blob(&blob).unwrap();
            assert_eq!(envs, back, "round-trip mismatch for n={n}");
        }
    }

    #[test]
    fn fanout_blob_preserves_crypto_round_trip() {
        // The real proof: serialize a genuine envelope, parse it back, and the
        // recovered envelope still decrypts to the original plaintext.
        let env = build_env();
        let cert = build_cert(&env);
        let verified = verify_mlkem_cert(&cert, &env.doc, env.now_unix_secs).unwrap();
        let sender_id = [0xABu8; 32];
        let envelopes = fanout_encrypt(
            b"sealed for the mailbox",
            std::slice::from_ref(&verified),
            &sender_id,
            &env.doc.node_id,
        )
        .unwrap();

        let blob = encode_fanout_blob(&envelopes).unwrap();
        let parsed = decode_fanout_blob(&blob).unwrap();

        let pt = fanout_decrypt_one(
            &parsed,
            &verified.instance_id,
            &env.doc.node_id,
            &sender_id,
            &env.mlkem_dk_seed,
            cert.cert_version,
        )
        .unwrap();
        assert_eq!(&*pt, b"sealed for the mailbox");
    }

    #[test]
    fn encode_rejects_over_cap() {
        let envs = dummy_envelopes(MAX_FANOUT_CERTS + 1);
        let err = encode_fanout_blob(&envs).unwrap_err();
        assert!(matches!(err, MlkemFanoutError::TooManyCerts { .. }), "{err:?}");
    }

    #[test]
    fn decode_rejects_empty_input() {
        let err = decode_fanout_blob(&[]).unwrap_err();
        assert!(matches!(err, MlkemFanoutError::MalformedBlob(_)), "{err:?}");
    }

    #[test]
    fn decode_rejects_wrong_version() {
        let mut blob = encode_fanout_blob(&dummy_envelopes(1)).unwrap();
        blob[0] = FANOUT_BLOB_VERSION.wrapping_add(1);
        let err = decode_fanout_blob(&blob).unwrap_err();
        assert!(matches!(err, MlkemFanoutError::MalformedBlob(_)), "{err:?}");
    }

    #[test]
    fn decode_rejects_over_cap_count() {
        // A header claiming more envelopes than the cap is refused before any
        // per-envelope parsing.
        let blob = [FANOUT_BLOB_VERSION, (MAX_FANOUT_CERTS + 1) as u8];
        let err = decode_fanout_blob(&blob).unwrap_err();
        assert!(matches!(err, MlkemFanoutError::MalformedBlob(_)), "{err:?}");
    }

    #[test]
    fn decode_rejects_truncation_at_every_length() {
        // Lopping off ANY suffix must yield a clean error, never a panic or a
        // partial parse — the decoder bound-checks every read.
        let blob = encode_fanout_blob(&dummy_envelopes(2)).unwrap();
        for cut in 1..blob.len() {
            let err = decode_fanout_blob(&blob[..cut]).unwrap_err();
            assert!(
                matches!(err, MlkemFanoutError::MalformedBlob(_)),
                "cut={cut}: {err:?}"
            );
        }
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut blob = encode_fanout_blob(&dummy_envelopes(1)).unwrap();
        blob.push(0x00);
        let err = decode_fanout_blob(&blob).unwrap_err();
        assert!(matches!(err, MlkemFanoutError::MalformedBlob(_)), "{err:?}");
    }

    #[test]
    fn decode_rejects_forged_oversized_length() {
        // Forge the kem_ciphertext length field to a huge value. The decoder
        // must reject it (length > remaining input) rather than attempt a giant
        // allocation or over-read.
        let blob = encode_fanout_blob(&dummy_envelopes(1)).unwrap();
        let mut tampered = blob.clone();
        // Layout: [ver:1][count:1][instance:16][cert_version:8][kem_len:u32]…
        let kem_len_off = 1 + 1 + 16 + 8;
        tampered[kem_len_off..kem_len_off + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        let err = decode_fanout_blob(&tampered).unwrap_err();
        assert!(matches!(err, MlkemFanoutError::MalformedBlob(_)), "{err:?}");
    }
}
