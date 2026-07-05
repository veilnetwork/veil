//! Opt-in message-authorship signature (deniable-by-default attestation).
//!
//! xVeil is a DENIABLE messenger: authorship is deliberately non-provable to a
//! third party by default. This module implements the *opt-in* exception — a
//! recipient may ASK the author to sign a specific message, and the author may
//! (per policy / per prompt) VOLUNTARILY produce a portable signature over
//! `author ‖ recipient ‖ msgId ‖ body`. That binds the attestation to exactly
//! one message sent to exactly one recipient, so it cannot be transplanted.
//! Deniability is preserved because it is the author's conscious choice each
//! time — nothing is signed unless the author opts in.
//!
//! Both entry points are STATELESS pure crypto (no node handle, no IPC): sign
//! takes the caller's own identity config TOML (already held in the app's
//! deniable container, the same bytes it boots the node from); verify takes the
//! author's public key + node_id. Identities are Ed25519 (`node_id =
//! BLAKE3(public_key)`), so verify also re-derives the node_id from the key to
//! prove the key really belongs to the claimed author.

use std::ffi::{CString, c_char, c_int};

use libc::size_t;

/// `veil_identity_verify` verdicts.
const VERIFY_VALID: c_int = 0;
const VERIFY_INVALID: c_int = 1;
const SIGN_ERR: c_int = -1;

/// Write an owned error string into `*err_out` (freed by `veil_free_string`).
unsafe fn set_err(err_out: *mut *mut c_char, msg: &str) {
    if err_out.is_null() {
        return;
    }
    let c = CString::new(msg).unwrap_or_else(|_| CString::new("error").unwrap());
    unsafe { *err_out = c.into_raw() };
}

/// Sign `message` with the Ed25519 identity in `identity_toml` (the config the
/// host stores in its deniable container). Writes the 64-byte signature to
/// `out_sig_64` and the 32-byte public key to `out_pubkey_32` (so the verifier
/// can bind it to the author's node_id). Returns 0 on success, -1 on error with
/// `*err_out` set (free with `veil_free_string`).
///
/// # Safety
/// `identity_toml_ptr`/`msg_ptr` must point to their respective readable byte
/// lengths; `out_sig_64` must be writable for 64 bytes and `out_pubkey_32` for
/// 32; `err_out` (if non-null) must be a writable `*mut c_char` slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_identity_sign(
    identity_toml_ptr: *const u8,
    identity_toml_len: size_t,
    msg_ptr: *const u8,
    msg_len: size_t,
    out_sig_64: *mut u8,
    out_pubkey_32: *mut u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if identity_toml_ptr.is_null()
        || msg_ptr.is_null()
        || out_sig_64.is_null()
        || out_pubkey_32.is_null()
    {
        unsafe { set_err(err_out, "veil_identity_sign: null argument") };
        return SIGN_ERR;
    }
    let toml_bytes = unsafe { std::slice::from_raw_parts(identity_toml_ptr, identity_toml_len) };
    let toml = match std::str::from_utf8(toml_bytes) {
        Ok(s) => s,
        Err(_) => {
            unsafe { set_err(err_out, "identity_toml is not valid UTF-8") };
            return SIGN_ERR;
        }
    };
    // `msg_len == 0` is legal (empty message) — from_raw_parts requires a
    // non-null ptr even for len 0, which the null check above guarantees.
    let message = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };

    let config = match veil_cfg::parse_toml_str(toml) {
        Ok(c) => c,
        Err(e) => {
            unsafe { set_err(err_out, &format!("identity_toml parse failed: {e}")) };
            return SIGN_ERR;
        }
    };
    let identity = match config.identity {
        Some(id) => id,
        None => {
            unsafe { set_err(err_out, "identity_toml carries no [Identity]") };
            return SIGN_ERR;
        }
    };
    if identity.algo != veil_types::SignatureAlgorithm::Ed25519 {
        unsafe {
            set_err(
                err_out,
                "message signing is only supported for Ed25519 identities",
            )
        };
        return SIGN_ERR;
    }

    let sig = match veil_crypto::sign_message(
        identity.algo,
        identity.public_key.as_str(),
        identity.private_key.as_str(),
        message,
    ) {
        Ok(s) => s,
        Err(e) => {
            unsafe { set_err(err_out, &format!("sign failed: {e}")) };
            return SIGN_ERR;
        }
    };
    let pubkey =
        match veil_crypto::signature::decode_public_key(identity.algo, identity.public_key.as_str())
        {
            Ok(p) => p,
            Err(e) => {
                unsafe { set_err(err_out, &format!("public-key decode failed: {e}")) };
                return SIGN_ERR;
            }
        };
    if sig.len() != 64 || pubkey.len() != 32 {
        unsafe {
            set_err(
                err_out,
                &format!(
                    "unexpected Ed25519 sizes (sig={} pk={})",
                    sig.len(),
                    pubkey.len()
                ),
            )
        };
        return SIGN_ERR;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(sig.as_ptr(), out_sig_64, 64);
        std::ptr::copy_nonoverlapping(pubkey.as_ptr(), out_pubkey_32, 32);
    }
    0
}

/// Verify a message-authorship signature. Checks BOTH that `pubkey_32` really
/// belongs to `node_id_32` (`node_id = BLAKE3(pubkey)` — so a forged pubkey for
/// a claimed author is rejected) AND that `sig_64` is a valid Ed25519 signature
/// over `message` by that key.
///
/// Returns 0 (`VERIFY_VALID`) if authentic, 1 (`VERIFY_INVALID`) if the node_id
/// binding or the signature fails, -1 on a bad argument (null pointer).
///
/// # Safety
/// `node_id_32`/`pubkey_32` must be readable for 32 bytes, `sig_64` for 64, and
/// `msg_ptr` for `msg_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_identity_verify(
    node_id_32: *const u8,
    pubkey_32: *const u8,
    msg_ptr: *const u8,
    msg_len: size_t,
    sig_64: *const u8,
) -> c_int {
    if node_id_32.is_null() || pubkey_32.is_null() || msg_ptr.is_null() || sig_64.is_null() {
        return SIGN_ERR;
    }
    let node_id = unsafe { std::slice::from_raw_parts(node_id_32, 32) };
    let pubkey = unsafe { std::slice::from_raw_parts(pubkey_32, 32) };
    let message = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };
    let sig = unsafe { std::slice::from_raw_parts(sig_64, 64) };

    // Bind the key to the claimed author: node_id MUST be BLAKE3(pubkey), else a
    // third party could present someone else's signature under this author's id.
    if veil_crypto::identity::compute_node_id(pubkey) != *node_id {
        return VERIFY_INVALID;
    }
    // Re-encode the raw key to base64 for the audited verify path.
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let pubkey_b64 = STANDARD.encode(pubkey);
    match veil_crypto::verify_message(
        veil_types::SignatureAlgorithm::Ed25519,
        &pubkey_b64,
        message,
        sig,
    ) {
        Ok(()) => VERIFY_VALID,
        Err(_) => VERIFY_INVALID,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    // Mine a low-difficulty Ed25519 identity and return its config TOML.
    fn identity_toml() -> String {
        let mut err: *mut c_char = std::ptr::null_mut();
        let out = unsafe { crate::node::veil_config_init(8, &mut err) };
        assert!(!out.is_null(), "config_init failed");
        let toml = unsafe { CStr::from_ptr(out) }.to_string_lossy().into_owned();
        unsafe { crate::veil_free_string(out) };
        toml
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let toml = identity_toml();
        let msg = b"veil-msg-attest-v1\x1fauthor\x1frecipient\x1fmid\x1fhello";
        let mut sig = [0u8; 64];
        let mut pk = [0u8; 32];
        let mut err: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            veil_identity_sign(
                toml.as_ptr(),
                toml.len(),
                msg.as_ptr(),
                msg.len(),
                sig.as_mut_ptr(),
                pk.as_mut_ptr(),
                &mut err,
            )
        };
        assert_eq!(rc, 0, "sign failed");
        // node_id = BLAKE3(pubkey).
        let node_id = veil_crypto::identity::compute_node_id(&pk);
        let v = unsafe {
            veil_identity_verify(
                node_id.as_ptr(),
                pk.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
            )
        };
        assert_eq!(v, VERIFY_VALID, "valid signature must verify");
    }

    #[test]
    fn tampered_message_or_key_fails() {
        let toml = identity_toml();
        let msg = b"original body";
        let mut sig = [0u8; 64];
        let mut pk = [0u8; 32];
        let mut err: *mut c_char = std::ptr::null_mut();
        unsafe {
            veil_identity_sign(
                toml.as_ptr(),
                toml.len(),
                msg.as_ptr(),
                msg.len(),
                sig.as_mut_ptr(),
                pk.as_mut_ptr(),
                &mut err,
            )
        };
        let node_id = veil_crypto::identity::compute_node_id(&pk);
        // A different message under the same (node_id, pubkey, sig) is rejected.
        let tampered = b"tampered body";
        let v = unsafe {
            veil_identity_verify(
                node_id.as_ptr(),
                pk.as_ptr(),
                tampered.as_ptr(),
                tampered.len(),
                sig.as_ptr(),
            )
        };
        assert_eq!(v, VERIFY_INVALID, "tampered message must fail");

        // A mismatched node_id (not BLAKE3 of this key) is rejected before the
        // signature is even checked.
        let wrong_node_id = [0x11u8; 32];
        let v2 = unsafe {
            veil_identity_verify(
                wrong_node_id.as_ptr(),
                pk.as_ptr(),
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
            )
        };
        assert_eq!(v2, VERIFY_INVALID, "wrong node_id binding must fail");
    }

    #[test]
    fn sign_rejects_null_and_bad_toml() {
        let mut sig = [0u8; 64];
        let mut pk = [0u8; 32];
        let mut err: *mut c_char = std::ptr::null_mut();
        let rc = unsafe {
            veil_identity_sign(
                std::ptr::null(),
                0,
                b"m".as_ptr(),
                1,
                sig.as_mut_ptr(),
                pk.as_mut_ptr(),
                &mut err,
            )
        };
        assert_eq!(rc, SIGN_ERR);
        unsafe {
            if !err.is_null() {
                crate::veil_free_string(err);
            }
        }
        // Non-identity TOML → clean error, not a panic.
        let bad = CString::new("[global]\n").unwrap();
        let bad_bytes = bad.as_bytes();
        let mut err2: *mut c_char = std::ptr::null_mut();
        let rc2 = unsafe {
            veil_identity_sign(
                bad_bytes.as_ptr(),
                bad_bytes.len(),
                b"m".as_ptr(),
                1,
                sig.as_mut_ptr(),
                pk.as_mut_ptr(),
                &mut err2,
            )
        };
        assert_eq!(rc2, SIGN_ERR);
        unsafe {
            if !err2.is_null() {
                crate::veil_free_string(err2);
            }
        }
    }
}
