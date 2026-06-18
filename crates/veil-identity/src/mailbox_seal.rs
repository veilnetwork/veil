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
    #[error("malformed mailbox blob framing")]
    Framing,
    #[error("sender-id sidecar had the wrong length ({0} != 32)")]
    BadSidecarSender(usize),
}

/// Placeholder sender bound into the sender-id SIDECAR's fan-out derivation.
///
/// The main blob binds the REAL `sender_node_id` into its fan-out key + AAD, so
/// the recipient must already know the sender to open it — fine on the live
/// onion path (the relay supplies the authenticated source) but impossible on
/// the anonymous mailbox deposit (the wire sender is 0, for anonymity). The
/// sidecar breaks that chicken-and-egg: it is a SECOND fan-out envelope whose
/// plaintext IS the real `sender_node_id`, sealed to the recipient's same cert
/// but bound under this all-zero placeholder — a constant BOTH sides know, so
/// the recipient can decrypt the sidecar WITHOUT first knowing the sender, learn
/// the real id, then open the main blob normally. The sidecar needs no
/// authentication of its own: a tampered sidecar yields a wrong id → the main
/// blob fails to decrypt/verify → fail-closed (a malicious relay can drop the
/// blob outright anyway, so this grants no new capability). It stays anonymous
/// to the relay because the real id is encrypted under the recipient's KEM key.
const SIDECAR_PLACEHOLDER_SENDER: [u8; 32] = [0u8; 32];

/// Seal a signed `auth` into a mailbox blob, E2E-encrypted to `recipient_cert`.
///
/// `auth` MUST already be signed by the sender's sovereign identity; the caller
/// owns the binding (dst / app / endpoint / timestamp / nonce). `sender_node_id`
/// and `recipient_node_id` are bound into the fan-out encryption (so an envelope
/// cannot be cross-replayed between identities). Returns the serialized blob to
/// hand to a mailbox relay.
///
/// Wire layout (v2 — carries the sender-id sidecar, see
/// [`SIDECAR_PLACEHOLDER_SENDER`]):
///   `[ sidecar_len(u32 BE) | sidecar_fanout_blob | main_fanout_blob ]`
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
    // Main blob: REAL sender bound into the fan-out (unchanged anti-redirect
    // binding) — the recipient needs the recovered sender_node_id to open it.
    let main = fanout_encrypt(
        &inner,
        std::slice::from_ref(recipient_cert),
        sender_node_id,
        recipient_node_id,
    )?;
    let main_blob = encode_fanout_blob(&main)?;
    // Sidecar: the real sender_node_id, sealed to the same cert under the
    // all-zero placeholder so the recipient can recover it BEFORE knowing it.
    let sidecar = fanout_encrypt(
        sender_node_id,
        std::slice::from_ref(recipient_cert),
        &SIDECAR_PLACEHOLDER_SENDER,
        recipient_node_id,
    )?;
    let sidecar_blob = encode_fanout_blob(&sidecar)?;

    let mut out = Vec::with_capacity(4 + sidecar_blob.len() + main_blob.len());
    out.extend_from_slice(&(sidecar_blob.len() as u32).to_be_bytes());
    out.extend_from_slice(&sidecar_blob);
    out.extend_from_slice(&main_blob);
    Ok(out)
}

/// Split a v2 mailbox blob into `(sidecar_fanout_blob, main_fanout_blob)`.
fn split_mailbox_blob(blob: &[u8]) -> Result<(&[u8], &[u8]), MailboxSealError> {
    let len_bytes = blob.get(..4).ok_or(MailboxSealError::Framing)?;
    let sidecar_len = u32::from_be_bytes(len_bytes.try_into().unwrap()) as usize;
    let rest = &blob[4..];
    if sidecar_len > rest.len() {
        return Err(MailboxSealError::Framing);
    }
    Ok(rest.split_at(sidecar_len))
}

/// Recover the sealed `sender_node_id` from a mailbox blob's sidecar, decrypting
/// under this instance's `dk_seed`. The caller resolves that sender's document
/// out of band, then passes the SAME id to [`open_mailbox_blob`] to open + verify
/// the main blob. No signature on the sidecar itself — a forged id simply makes
/// the subsequent open fail closed (see [`SIDECAR_PLACEHOLDER_SENDER`]).
pub fn recover_sender_node_id(
    blob: &[u8],
    our_instance_id: &[u8; 16],
    our_node_id: &[u8; 32],
    dk_seed: &[u8; ML_KEM_768_DK_SEED_LEN],
    cert_version: u64,
) -> Result<[u8; 32], MailboxSealError> {
    let (sidecar_blob, _main) = split_mailbox_blob(blob)?;
    let envelopes = decode_fanout_blob(sidecar_blob)?;
    let recovered = fanout_decrypt_one(
        &envelopes,
        our_instance_id,
        our_node_id,
        &SIDECAR_PLACEHOLDER_SENDER,
        dk_seed,
        cert_version,
    )?;
    let bytes: &[u8] = recovered.as_slice();
    if bytes.len() != 32 {
        return Err(MailboxSealError::BadSidecarSender(bytes.len()));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(bytes);
    Ok(id)
}

/// Open + verify a mailbox blob's MAIN portion addressed to this instance.
///
/// `sender_node_id` is the id recovered from the sidecar via
/// [`recover_sender_node_id`] (on the anonymous path the caller cannot know it a
/// priori). Splits off the sidecar, decrypts the main blob under our instance's
/// `dk_seed` (keep it internal — never log, never cross FFI), parses the inner
/// [`AuthAppDeliver`], and verifies its signature + freshness against the
/// sender's `sender_doc` (resolved from the recovered id). Returns the verified
/// auth so the caller can route `data` to `(app_id, endpoint_id)`.
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
    let (_sidecar, main_blob) = split_mailbox_blob(blob)?;
    let envelopes = decode_fanout_blob(main_blob)?;
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
    fn sidecar_recovers_sender_then_opens() {
        // The anonymous-path flow: the recipient does NOT know the sender a
        // priori — it recovers it from the sidecar, then opens the main blob.
        let sov = sender_sovereign("sender");
        let sender_id = *sov.node_id();
        let (cert, recipient_id, instance, dk_seed) = recipient();

        let auth = sov.sign_auth_deliver(
            recipient_id,
            [0xCCu8; 32],
            9,
            NOW,
            0x1234,
            b"sealed-sender hello".to_vec(),
            None,
        );
        let blob = seal_mailbox_blob(&auth, &cert, &sender_id, &recipient_id).unwrap();

        // 1) recover the sender from the sidecar with NO prior knowledge of it.
        let recovered =
            recover_sender_node_id(&blob, &instance, &recipient_id, &dk_seed, cert.cert_version)
                .unwrap();
        assert_eq!(recovered, sender_id, "sidecar must yield the real sender id");

        // 2) open the main blob using the recovered id; verifies under the doc.
        let opened = open_mailbox_blob(
            &blob,
            &instance,
            &recipient_id,
            &recovered,
            &dk_seed,
            cert.cert_version,
            &sov.document,
            NOW,
            DEFAULT_AUTH_DELIVER_FRESHNESS_SECS,
        )
        .unwrap();
        assert_eq!(opened.data, b"sealed-sender hello");
        assert_eq!(opened.sender_node_id, sender_id);
    }

    #[test]
    fn recover_sender_rejects_tampered_sidecar() {
        // A tampered sidecar must fail closed (wrong/undecryptable id), never
        // silently yield a bogus sender. Flip a byte INSIDE the sidecar region.
        let sov = sender_sovereign("sender");
        let sender_id = *sov.node_id();
        let (cert, recipient_id, instance, dk_seed) = recipient();

        let auth = sov.sign_auth_deliver(recipient_id, [0xCCu8; 32], 9, NOW, 7, b"x".to_vec(), None);
        let mut blob = seal_mailbox_blob(&auth, &cert, &sender_id, &recipient_id).unwrap();
        // Flip a byte well inside the sidecar fan-out blob's interior.
        let tamper_at = blob.len() / 4;
        blob[tamper_at] ^= 0xFF;

        let err =
            recover_sender_node_id(&blob, &instance, &recipient_id, &dk_seed, cert.cert_version)
                .unwrap_err();
        assert!(matches!(err, MailboxSealError::Fanout(_)), "{err:?}");
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
