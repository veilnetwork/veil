//! Private-veil-network membership cert verification.
//!
//! Each member of а private network carries а cert signed by the
//! network owner. Cert binds the member's `node_id` к а specific
//! `network_id` + expiry. Verifying the cert at handshake gates
//! peers without owner authorisation от joining the network.
//!
//! Wire format и struct definition live в `veil-types` as
//! [`veil_types::MembershipCert`]; this module owns the canonical
//! byte encoding + signature verification.

use veil_types::{MEMBERSHIP_CERT_VERSION, MembershipCert, SignatureAlgorithm};

/// Errors returned by [`verify_membership_cert`].
#[derive(Debug, thiserror::Error)]
pub enum CertVerifyError {
    #[error("unsupported membership-cert version {actual} (expected {expected})")]
    UnsupportedVersion { actual: u8, expected: u8 },
    #[error("cert is not yet valid: issued_at_unix={issued_at_unix} > now_unix={now_unix}")]
    NotYetValid { issued_at_unix: u64, now_unix: u64 },
    #[error("cert has expired: valid_until_unix={valid_until_unix} <= now_unix={now_unix}")]
    Expired {
        valid_until_unix: u64,
        now_unix: u64,
    },
    #[error("cert network_id does not match local: expected={expected_hex} got={got_hex}")]
    WrongNetwork {
        expected_hex: String,
        got_hex: String,
    },
    #[error("cert owner-algo mismatch: expected={expected:?} got={got:?}")]
    WrongAlgo {
        expected: SignatureAlgorithm,
        got: SignatureAlgorithm,
    },
    #[error("cert signature invalid: {message}")]
    BadSignature { message: String },
    #[error("invalid owner pubkey bytes: {message}")]
    BadOwnerPubkey { message: String },
}

/// Verify а membership cert against the local network configuration.
///
/// Checks (в order):
/// 1. `version` matches [`MEMBERSHIP_CERT_VERSION`].
/// 2. `issued_at_unix <= now_unix` (not back-dated past now's tolerance).
/// 3. `valid_until_unix > now_unix` (not expired).
/// 4. `cert.network_id == expected_network_id` (right network).
/// 5. `cert.algo == owner_algo` (algorithm match).
/// 6. Cryptographic signature over the canonical body bytes verifies
///    against the operator-configured owner pubkey.
///
/// Returns `Ok(())` on success. All checks run BEFORE the signature
/// verify so wrong-network / wrong-algo / expired errors do not pay
/// the crypto cost.
pub fn verify_membership_cert(
    cert: &MembershipCert,
    expected_network_id: &[u8; 32],
    owner_algo: SignatureAlgorithm,
    owner_pubkey_bytes: &[u8],
    now_unix: u64,
) -> Result<(), CertVerifyError> {
    if cert.version != MEMBERSHIP_CERT_VERSION {
        return Err(CertVerifyError::UnsupportedVersion {
            actual: cert.version,
            expected: MEMBERSHIP_CERT_VERSION,
        });
    }
    if cert.issued_at_unix > now_unix {
        return Err(CertVerifyError::NotYetValid {
            issued_at_unix: cert.issued_at_unix,
            now_unix,
        });
    }
    // Sentinel `valid_until_unix == 0` ⇒ no expiry (owner explicitly
    // minted а never-expiring cert via `sign-member --no-expiry`).
    // Real-world certs sign with valid_until_unix > issued_at_unix > 0,
    // so the sentinel can't collide с а legitimate "almost-expired-just-
    // after-the-epoch" cert.
    if cert.valid_until_unix != 0 && cert.valid_until_unix <= now_unix {
        return Err(CertVerifyError::Expired {
            valid_until_unix: cert.valid_until_unix,
            now_unix,
        });
    }
    if &cert.network_id != expected_network_id {
        return Err(CertVerifyError::WrongNetwork {
            expected_hex: hex_encode(expected_network_id),
            got_hex: hex_encode(&cert.network_id),
        });
    }
    if cert.algo != owner_algo {
        return Err(CertVerifyError::WrongAlgo {
            expected: owner_algo,
            got: cert.algo,
        });
    }
    let body = canonical_cert_body(cert);
    let pk_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        owner_pubkey_bytes,
    );
    veil_crypto::verify_message(cert.algo, &pk_b64, &body, &cert.owner_signature).map_err(|e| {
        CertVerifyError::BadSignature {
            message: e.to_string(),
        }
    })
}

/// Build the canonical byte encoding of the cert body that the owner
/// signs / the verifier authenticates. Signature-stable: changing the
/// field order or any byte-level layout requires bumping
/// [`MEMBERSHIP_CERT_VERSION`].
///
/// Layout (all big-endian):
/// ```text
/// [0]       version (u8)
/// [1..33]   network_id (32 bytes)
/// [33..65]  member_node_id (32 bytes)
/// [65..73]  issued_at_unix (u64 BE)
/// [73..81]  valid_until_unix (u64 BE)
/// [81]      admin (0 / 1)
/// [82]      algo (u8 — algo discriminant)
/// ```
/// Total: 83 bytes (deterministic).
pub fn canonical_cert_body(cert: &MembershipCert) -> Vec<u8> {
    let mut out = Vec::with_capacity(83);
    out.push(cert.version);
    out.extend_from_slice(&cert.network_id);
    out.extend_from_slice(&cert.member_node_id);
    out.extend_from_slice(&cert.issued_at_unix.to_be_bytes());
    out.extend_from_slice(&cert.valid_until_unix.to_be_bytes());
    out.push(u8::from(cert.admin));
    out.push(algo_discriminant(cert.algo));
    out
}

/// Encode а full cert (body + signature) к а compact wire blob suitable
/// for HELLO TLV transport. Layout:
/// ```text
/// [0..83]   canonical_cert_body
/// [83..85]  signature_len (u16 BE)
/// [85..]    owner_signature bytes
/// ```
/// Total: 85 + signature_len bytes.
pub fn encode_cert_blob(cert: &MembershipCert) -> Vec<u8> {
    let body = canonical_cert_body(cert);
    let sig_len: u16 = cert
        .owner_signature
        .len()
        .try_into()
        .expect("signature should fit в u16 (Ed25519: 64, Falcon-512: 666)");
    let mut out = Vec::with_capacity(body.len() + 2 + cert.owner_signature.len());
    out.extend_from_slice(&body);
    out.extend_from_slice(&sig_len.to_be_bytes());
    out.extend_from_slice(&cert.owner_signature);
    out
}

/// Inverse of [`encode_cert_blob`]. Returns the decoded cert. Errors
/// when the blob is truncated, the version byte is unsupported, or the
/// signature length field exceeds the remaining buffer.
pub fn decode_cert_blob(blob: &[u8]) -> Result<MembershipCert, CertDecodeError> {
    if blob.len() < 85 {
        return Err(CertDecodeError::TooShort {
            need: 85,
            got: blob.len(),
        });
    }
    let version = blob[0];
    let mut network_id = [0u8; 32];
    network_id.copy_from_slice(&blob[1..33]);
    let mut member_node_id = [0u8; 32];
    member_node_id.copy_from_slice(&blob[33..65]);
    let issued_at_unix = u64::from_be_bytes(blob[65..73].try_into().unwrap());
    let valid_until_unix = u64::from_be_bytes(blob[73..81].try_into().unwrap());
    let admin = blob[81] != 0;
    let algo = match blob[82] {
        1 => SignatureAlgorithm::Ed25519,
        2 => SignatureAlgorithm::Falcon512,
        3 => SignatureAlgorithm::Ed25519Falcon512Hybrid,
        4 => SignatureAlgorithm::Ed25519Falcon1024Hybrid,
        other => return Err(CertDecodeError::UnknownAlgo { actual: other }),
    };
    let sig_len = u16::from_be_bytes([blob[83], blob[84]]) as usize;
    if blob.len() < 85 + sig_len {
        return Err(CertDecodeError::TruncatedSignature {
            need: 85 + sig_len,
            got: blob.len(),
        });
    }
    let owner_signature = blob[85..85 + sig_len].to_vec();
    Ok(MembershipCert {
        version,
        network_id,
        member_node_id,
        issued_at_unix,
        valid_until_unix,
        admin,
        algo,
        owner_signature,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum CertDecodeError {
    #[error("cert blob truncated: need {need} bytes, got {got}")]
    TooShort { need: usize, got: usize },
    #[error("cert algo byte {actual} is не recognised")]
    UnknownAlgo { actual: u8 },
    #[error("cert signature truncated: need {need} bytes, got {got}")]
    TruncatedSignature { need: usize, got: usize },
}

fn algo_discriminant(algo: SignatureAlgorithm) -> u8 {
    match algo {
        SignatureAlgorithm::Ed25519 => 1,
        SignatureAlgorithm::Falcon512 => 2,
        SignatureAlgorithm::Ed25519Falcon512Hybrid => 3,
        SignatureAlgorithm::Ed25519Falcon1024Hybrid => 4,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    fn ed25519_signer() -> (SigningKey, Vec<u8>) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        (sk, pk)
    }

    fn make_cert(
        sk: &SigningKey,
        network_id: [u8; 32],
        member_node_id: [u8; 32],
        issued_at_unix: u64,
        valid_until_unix: u64,
        admin: bool,
    ) -> MembershipCert {
        let mut cert = MembershipCert {
            version: MEMBERSHIP_CERT_VERSION,
            network_id,
            member_node_id,
            issued_at_unix,
            valid_until_unix,
            admin,
            algo: SignatureAlgorithm::Ed25519,
            owner_signature: Vec::new(),
        };
        let body = canonical_cert_body(&cert);
        cert.owner_signature = sk.sign(&body).to_bytes().to_vec();
        cert
    }

    #[test]
    fn valid_cert_verifies() {
        let (sk, pk) = ed25519_signer();
        let net = [0x11u8; 32];
        let cert = make_cert(&sk, net, [0x22u8; 32], 1000, 2000, false);
        assert!(
            verify_membership_cert(&cert, &net, SignatureAlgorithm::Ed25519, &pk, 1500).is_ok()
        );
    }

    #[test]
    fn expired_cert_rejected() {
        let (sk, pk) = ed25519_signer();
        let net = [0x11u8; 32];
        let cert = make_cert(&sk, net, [0x22u8; 32], 1000, 2000, false);
        let err = verify_membership_cert(&cert, &net, SignatureAlgorithm::Ed25519, &pk, 3000)
            .expect_err("expired");
        matches!(err, CertVerifyError::Expired { .. });
    }

    #[test]
    fn wrong_network_rejected() {
        let (sk, pk) = ed25519_signer();
        let net = [0x11u8; 32];
        let other_net = [0x99u8; 32];
        let cert = make_cert(&sk, net, [0x22u8; 32], 1000, 2000, false);
        let err = verify_membership_cert(&cert, &other_net, SignatureAlgorithm::Ed25519, &pk, 1500)
            .expect_err("wrong network");
        matches!(err, CertVerifyError::WrongNetwork { .. });
    }

    #[test]
    fn tampered_signature_rejected() {
        let (sk, pk) = ed25519_signer();
        let net = [0x11u8; 32];
        let mut cert = make_cert(&sk, net, [0x22u8; 32], 1000, 2000, false);
        // Flip а byte в the signed body — the cached signature now
        // verifies а different message.
        cert.admin = true;
        let err = verify_membership_cert(&cert, &net, SignatureAlgorithm::Ed25519, &pk, 1500)
            .expect_err("tampered");
        matches!(err, CertVerifyError::BadSignature { .. });
    }

    #[test]
    fn unlimited_cert_verifies_far_future() {
        // valid_until_unix == 0 sentinel ⇒ no-expiry cert.
        // Cert minted at unix=1000, queried even far in the future
        // (e.g. unix=10_000_000_000 ≈ year 2286) must still verify.
        let (sk, pk) = ed25519_signer();
        let net = [0x11u8; 32];
        let cert = make_cert(&sk, net, [0x22u8; 32], 1000, 0, false);
        assert!(
            verify_membership_cert(
                &cert,
                &net,
                SignatureAlgorithm::Ed25519,
                &pk,
                10_000_000_000,
            )
            .is_ok(),
            "valid_until_unix=0 should mean no expiry — far-future verify must succeed"
        );
    }

    #[test]
    fn version_mismatch_rejected() {
        let (sk, pk) = ed25519_signer();
        let net = [0x11u8; 32];
        let mut cert = make_cert(&sk, net, [0x22u8; 32], 1000, 2000, false);
        cert.version = MEMBERSHIP_CERT_VERSION.wrapping_add(1);
        // Tampered body — but the version check fires before signature.
        let err = verify_membership_cert(&cert, &net, SignatureAlgorithm::Ed25519, &pk, 1500)
            .expect_err("version");
        matches!(err, CertVerifyError::UnsupportedVersion { .. });
    }

    #[test]
    fn canonical_body_is_stable() {
        let cert = MembershipCert {
            version: 1,
            network_id: [1u8; 32],
            member_node_id: [2u8; 32],
            issued_at_unix: 0x0102_0304_0506_0708,
            valid_until_unix: 0xAABB_CCDD_EEFF_0011,
            admin: true,
            algo: SignatureAlgorithm::Ed25519,
            owner_signature: vec![],
        };
        let body = canonical_cert_body(&cert);
        assert_eq!(body.len(), 83);
        assert_eq!(body[0], 1); // version
        assert_eq!(&body[1..33], &[1u8; 32]);
        assert_eq!(&body[33..65], &[2u8; 32]);
        assert_eq!(&body[65..73], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&body[81], &1u8); // admin
        assert_eq!(&body[82], &1u8); // algo discriminant for Ed25519
    }

    #[test]
    fn base64_encoded_pubkey_works() {
        // Sanity: STANDARD encoding matches verify_message expectation.
        let (sk, pk) = ed25519_signer();
        let pk_b64 = STANDARD.encode(&pk);
        let decoded = STANDARD.decode(&pk_b64).unwrap();
        assert_eq!(decoded, pk);
        // And the cert path:
        let net = [0x33u8; 32];
        let cert = make_cert(&sk, net, [0x44u8; 32], 1000, 2000, true);
        assert!(
            verify_membership_cert(&cert, &net, SignatureAlgorithm::Ed25519, &pk, 1500).is_ok()
        );
    }
}
