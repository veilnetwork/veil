//! Seal/open an authenticated app-deliver message into a self-contained blob
//! for store-and-forward (offline mailbox) delivery — the OFFLINE analogue of
//! the live onion `APP_DELIVER_AUTH` path.
//!
//! Same signed [`AuthAppDeliver`] (proves WHO sent it; the transport hides
//! WHERE), but instead of fragmenting + onion-sealing for circuit transmission,
//! the encoded auth is ML-KEM fan-out-encrypted to the recipient's verified
//! cert and serialized with [`encode_fanout_blob`](crate::mlkem_fanout::encode_fanout_blob)
//! into one blob the sender drops at a mailbox relay. The recipient fetches,
//! opens, verifies, and delivers it on reconnect.
//!
//! ## Status: DORMANT
//! Not yet wired into any runtime or FFI path. It composes only already-reviewed
//! primitives — [`SovereignIdentity::sign_auth_deliver`](crate::sovereign::SovereignIdentity::sign_auth_deliver),
//! [`fanout_encrypt`]/[`fanout_decrypt_one`], [`verify_auth_deliver`] — plus the
//! fan-out blob codec. It is landed ahead of the runtime/FFI wiring so the
//! composition can be reviewed on its own.
//!
//! ## Security boundary (for the wiring that comes later)
//! - The security-bearing BINDING — which `dst_node_id` / `app_id` /
//!   `endpoint_id` the signature covers, plus `timestamp` / `nonce` — is the
//!   CALLER's responsibility: [`seal_mailbox_blob`] seals whatever signed `auth`
//!   it is handed, and [`open_mailbox_blob`] reports the verified auth so the
//!   caller routes it. The runtime method that signs must bind correctly.
//! - `dk_seed` is the recipient instance's ML-KEM decapsulation seed. It MUST
//!   stay inside the runtime — never logged, never crossed over an FFI boundary.
//!   The recovered inner plaintext is held in a `Zeroizing` buffer by
//!   [`fanout_decrypt_one`] and dropped as soon as the auth is parsed.

use veil_crypto::x3dh::ML_KEM_768_DK_SEED_LEN;
use veil_proto::identity_document::IdentityDocument;
use veil_proto::ipc::{AuthAppDeliver, MAX_AUTH_DELIVER_MSG_BYTES};

use crate::auth_deliver::{AuthDeliverError, verify_auth_deliver};
use crate::mlkem_fanout::{
    MlkemFanoutError, VerifiedMlkemCert, decode_fanout_blob, encode_fanout_blob,
    fanout_decrypt_one, fanout_encrypt,
};

/// Errors from sealing or opening a mailbox blob.
#[derive(Debug, thiserror::Error)]
pub enum MailboxSealError {
    #[error("encoded auth-deliver too large ({got} > cap {cap})")]
    TooLarge { got: usize, cap: usize },
    #[error("fan-out: {0}")]
    Fanout(#[from] MlkemFanoutError),
    #[error("decode auth-deliver: {0}")]
    Decode(veil_proto::ProtoError),
    #[error("verify auth-deliver: {0}")]
    Verify(#[from] AuthDeliverError),
}

/// Seal a signed `auth` into a mailbox blob, E2E-encrypted to `recipient_cert`.
///
/// `auth` MUST already be signed by the sender's sovereign identity; the caller
/// owns the binding (dst / app / endpoint / timestamp / nonce). `sender_node_id`
/// and `recipient_node_id` are bound into the fan-out encryption (so an envelope
/// cannot be cross-replayed between identities). Returns the serialized blob to
/// hand to a mailbox relay.
pub fn seal_mailbox_blob(
    auth: &AuthAppDeliver,
    recipient_cert: &VerifiedMlkemCert,
    sender_node_id: &[u8; 32],
    recipient_node_id: &[u8; 32],
) -> Result<Vec<u8>, MailboxSealError> {
    let inner = auth.encode();
    // Mirror the live APP_DELIVER_AUTH path's cap on the encoded auth.
    if inner.len() > MAX_AUTH_DELIVER_MSG_BYTES {
        return Err(MailboxSealError::TooLarge {
            got: inner.len(),
            cap: MAX_AUTH_DELIVER_MSG_BYTES,
        });
    }
    let envelopes = fanout_encrypt(
        &inner,
        std::slice::from_ref(recipient_cert),
        sender_node_id,
        recipient_node_id,
    )?;
    Ok(encode_fanout_blob(&envelopes)?)
}

/// Open + verify a mailbox blob addressed to this instance.
///
/// Decrypts under our instance's `dk_seed` (keep it internal — never log, never
/// cross FFI), parses the inner [`AuthAppDeliver`], and verifies its signature +
/// freshness against the sender's `sender_doc` (resolved out of band). Returns
/// the verified auth so the caller can route `data` to `(app_id, endpoint_id)`.
///
/// Fails closed at every step: a blob not addressed to this instance, a tampered
/// ciphertext, a stale/forged signature, or a sender mismatch all yield an error
/// rather than an unverified message.
#[allow(clippy::too_many_arguments)]
pub fn open_mailbox_blob(
    blob: &[u8],
    our_instance_id: &[u8; 16],
    our_node_id: &[u8; 32],
    sender_node_id: &[u8; 32],
    dk_seed: &[u8; ML_KEM_768_DK_SEED_LEN],
    cert_version: u64,
    sender_doc: &IdentityDocument,
    now_unix: u64,
    freshness_window_secs: u64,
) -> Result<AuthAppDeliver, MailboxSealError> {
    let envelopes = decode_fanout_blob(blob)?;
    let inner = fanout_decrypt_one(
        &envelopes,
        our_instance_id,
        our_node_id,
        sender_node_id,
        dk_seed,
        cert_version,
    )?;
    let auth = AuthAppDeliver::decode(inner.as_slice()).map_err(MailboxSealError::Decode)?;
    verify_auth_deliver(&auth, sender_doc, our_node_id, now_unix, freshness_window_secs)?;
    Ok(auth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    use crate::auth_deliver::DEFAULT_AUTH_DELIVER_FRESHNESS_SECS;
    use crate::sovereign::SovereignIdentity;
    use crate::sovereign_flow::{CreateIdentityOptions, create_identity};
    use veil_crypto::x3dh::generate_prekey;
    use veil_proto::prekey_bundle::ALGO_ML_KEM_768;

    const NOW: u64 = 1_700_000_100;

    /// A freshly-minted sender identity (real document + signing key, PoW 0 so it
    /// is instant). Reused so the sealed auth verifies under `sov.document`.
    fn sender_sovereign(label: &str) -> SovereignIdentity {
        let dir = crate::test_support::scratch_dir("veil-mailbox-seal-tests");
        let out = create_identity(CreateIdentityOptions {
            veil_dir: dir,
            save_encrypted_with_password: None,
            argon2_params_override: None,
            extra_entropy: None,
            instance_label: label.into(),
            pow_difficulty: 0,
            issued_at_unix: 1_700_000_000,
            valid_until_unix: 1_700_000_000 + 7 * 86_400,
            algo: veil_types::SignatureAlgorithm::Ed25519,
        })
        .unwrap();
        SovereignIdentity::from_parts_active(out.document, &out.identity_sk_seed).unwrap()
    }

    /// A recipient: ML-KEM keypair + a directly-built VerifiedMlkemCert (cert
    /// verification itself is exercised in mlkem_fanout's own tests).
    fn recipient() -> (VerifiedMlkemCert, [u8; 32], [u8; 16], Zeroizing<[u8; 64]>) {
        let (ek, dk_seed) = generate_prekey();
        let node_id = [0xBBu8; 32];
        let instance_id = [0x77u8; 16];
        let cert = VerifiedMlkemCert {
            node_id,
            instance_id,
            mlkem_algo: ALGO_ML_KEM_768,
            mlkem_pubkey: ek,
            cert_version: 1,
        };
        (cert, node_id, instance_id, dk_seed)
    }

    #[test]
    fn seal_open_round_trips_and_verifies() {
        let sov = sender_sovereign("sender");
        let sender_id = *sov.node_id();
        let (cert, recipient_id, instance, dk_seed) = recipient();

        let auth = sov.sign_auth_deliver(
            recipient_id,
            [0xCCu8; 32],
            9,
            NOW,
            0x1234,
            b"offline hello".to_vec(),
            None,
        );
        let blob = seal_mailbox_blob(&auth, &cert, &sender_id, &recipient_id).unwrap();

        let opened = open_mailbox_blob(
            &blob,
            &instance,
            &recipient_id,
            &sender_id,
            &dk_seed,
            cert.cert_version,
            &sov.document,
            NOW,
            DEFAULT_AUTH_DELIVER_FRESHNESS_SECS,
        )
        .unwrap();
        // The recovered auth verified under the REAL verify_auth_deliver, so this
        // is end-to-end validation, not a self-consistent round-trip.
        assert_eq!(opened.data, b"offline hello");
        assert_eq!(opened.app_id, [0xCCu8; 32]);
        assert_eq!(opened.endpoint_id, 9);
        assert_eq!(opened.sender_node_id, sender_id);
    }

    #[test]
    fn open_rejects_wrong_sender_doc() {
        // Verifying against a DIFFERENT identity's document must fail: the signed
        // sender_node_id won't match, and the signature won't verify under it.
        let sov = sender_sovereign("sender");
        let other = sender_sovereign("impostor");
        let sender_id = *sov.node_id();
        let (cert, recipient_id, instance, dk_seed) = recipient();

        let auth = sov.sign_auth_deliver(recipient_id, [0xCCu8; 32], 9, NOW, 1, b"x".to_vec(), None);
        let blob = seal_mailbox_blob(&auth, &cert, &sender_id, &recipient_id).unwrap();

        let err = open_mailbox_blob(
            &blob,
            &instance,
            &recipient_id,
            &sender_id,
            &dk_seed,
            1,
            &other.document,
            NOW,
            DEFAULT_AUTH_DELIVER_FRESHNESS_SECS,
        )
        .unwrap_err();
        assert!(matches!(err, MailboxSealError::Verify(_)), "{err:?}");
    }

    #[test]
    fn open_rejects_wrong_instance() {
        // A blob sealed for instance 0x77 must not decrypt under another instance.
        let sov = sender_sovereign("sender");
        let sender_id = *sov.node_id();
        let (cert, recipient_id, _instance, dk_seed) = recipient();

        let auth = sov.sign_auth_deliver(recipient_id, [0xCCu8; 32], 9, NOW, 1, b"x".to_vec(), None);
        let blob = seal_mailbox_blob(&auth, &cert, &sender_id, &recipient_id).unwrap();

        let err = open_mailbox_blob(
            &blob,
            &[0xEEu8; 16], // wrong instance
            &recipient_id,
            &sender_id,
            &dk_seed,
            1,
            &sov.document,
            NOW,
            DEFAULT_AUTH_DELIVER_FRESHNESS_SECS,
        )
        .unwrap_err();
        assert!(matches!(err, MailboxSealError::Fanout(_)), "{err:?}");
    }

    #[test]
    fn open_rejects_tampered_blob() {
        let sov = sender_sovereign("sender");
        let sender_id = *sov.node_id();
        let (cert, recipient_id, instance, dk_seed) = recipient();

        let auth = sov.sign_auth_deliver(recipient_id, [0xCCu8; 32], 9, NOW, 1, b"x".to_vec(), None);
        let mut blob = seal_mailbox_blob(&auth, &cert, &sender_id, &recipient_id).unwrap();
        // Flip a byte at the tail (inside the AEAD ciphertext) → AEAD auth fails.
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;

        let err = open_mailbox_blob(
            &blob,
            &instance,
            &recipient_id,
            &sender_id,
            &dk_seed,
            1,
            &sov.document,
            NOW,
            DEFAULT_AUTH_DELIVER_FRESHNESS_SECS,
        )
        .unwrap_err();
        assert!(matches!(err, MailboxSealError::Fanout(_)), "{err:?}");
    }
}
