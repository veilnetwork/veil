//! Announcement signing helpers.
//!
//! Moved here from `proto::discovery` to break the
//! `proto → crypto` dependency direction (cycle blocker for
//! crate extraction): proto remains pure-data wire-format
//! definitions; orchestration of sign/verify lives at the
//! caller layer (`node/`).
//!
//! See `docs/CRATE_ARCHITECTURE.md` status discussion.

use veil_types::SignatureAlgorithm;

use veil_crypto::{sign_message, verify_message};
use veil_proto::discovery::AnnounceAttachmentPayload;

/// Sign an `AnnounceAttachmentPayload` with the node's signing key.
///
/// Sets `payload.signature` to the signature over
/// `payload.signable_body`. The caller must set `payload.seq_no`
/// before calling this function.
pub fn sign_announcement(
    payload: &mut AnnounceAttachmentPayload,
    algo: SignatureAlgorithm,
    public_key_b64: &str,
    private_key_b64: &str,
) -> Result<(), veil_error::ConfigError> {
    let body = payload.signable_body();
    payload.signature = sign_message(algo, public_key_b64, private_key_b64, &body)?;
    Ok(())
}

/// Verify the signature on an `AnnounceAttachmentPayload`.
///
/// `public_key_bytes` must be the raw (non-base64) bytes of the
/// signing key, i.e. `BLAKE3(public_key_bytes) == payload.node_id`.
///
/// Returns `true` if the signature is valid, `false` if absent or
/// invalid.
pub fn verify_announcement_signature(
    payload: &AnnounceAttachmentPayload,
    algo: SignatureAlgorithm,
    public_key_bytes: &[u8],
) -> bool {
    if payload.signature.is_empty() {
        return false;
    }
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let public_key_b64 = STANDARD.encode(public_key_bytes);
    let body = payload.signable_body();
    verify_message(algo, &public_key_b64, &body, &payload.signature).is_ok()
}
