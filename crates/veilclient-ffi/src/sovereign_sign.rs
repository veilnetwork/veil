//! One-burst sovereign signing.
//!
//! The sovereign key signs, and then the material is gone: these entry points
//! exist so a caller can hand in a secret, get a signature, and never hold the
//! key. The zeroizing variants are not an alternative spelling — they are the
//! contract, and the plain ones are what a caller may use when the material
//! was never theirs to begin with.
//!
//! Moved verbatim out of `lib.rs` (report24 RUNTIME-3), declared `pub mod`
//! so cbindgen still exports every declaration: a PRIVATE module makes it
//! skip `pub` items it finds there, which silently dropped the `VEIL_JOIN_*`
//! constants from the header the first time this was tried.
//!
//! The generated header is reordered by the move and its SHA-256 — the ABI
//! contract hash — changes with it. Nothing is added or removed: the header
//! before and after hold the same multiset of lines.

use super::*;

// ── One-burst sovereign signing FFI ────────────────────────────

/// Open a short-lived sovereign signer from a recovery phrase.
///
/// The writable phrase buffer is wiped on every path. Only an opaque handle,
/// the public key, and its node id cross back to the caller; the decoded master
/// seed and derived signing seed remain in native memory and zeroize on drop.
/// Call [`veil_sovereign_signer_close`] immediately after the membership-signing
/// burst.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_signer_open_from_phrase_zeroize(
    phrase: *mut u8,
    phrase_len: size_t,
    out_signer: *mut *mut VeilSovereignSigner,
    out_node_id: *mut u8,
    out_node_id_cap: size_t,
    out_public_key: *mut u8,
    out_public_key_cap: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe { clear_err(err_out) };
    if !out_signer.is_null() {
        unsafe { *out_signer = ptr::null_mut() };
    }
    if phrase.is_null()
        || out_signer.is_null()
        || out_node_id.is_null()
        || out_public_key.is_null()
        || out_node_id_cap < 32
        || out_public_key_cap < 32
        || phrase_len > MAX_FFI_CSTR_LEN
    {
        unsafe { write_err(err_out, "invalid sovereign signer open arguments") };
        if !phrase.is_null() && phrase_len <= MAX_FFI_CSTR_LEN {
            unsafe { volatile_wipe(phrase, phrase_len) };
        }
        return VEIL_ERR_INVALID_ARG;
    }
    let owned = zeroize::Zeroizing::new(
        unsafe { std::slice::from_raw_parts(phrase as *const u8, phrase_len) }.to_vec(),
    );
    unsafe { volatile_wipe(phrase, phrase_len) };
    let phrase_str = match std::str::from_utf8(&owned) {
        Ok(s) => s,
        Err(_) => {
            unsafe { write_err(err_out, "phrase is not valid UTF-8") };
            return VEIL_ERR_INVALID_ARG;
        }
    };
    let master_seed = match veil_identity::master_seed::decode_master_seed_from_phrase(phrase_str) {
        Ok(seed) => seed,
        Err(e) => {
            unsafe { write_err(err_out, format!("invalid phrase: {e}")) };
            return VEIL_ERR;
        }
    };
    let sk_seed = veil_crypto::identity::derive_master_sk_ed25519(&master_seed);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&sk_seed);
    let public_key = signing_key.verifying_key().to_bytes();
    let node_id = veil_crypto::identity::compute_node_id(&public_key);
    let token = HandleTable::insert(
        sovereign_signer_table(),
        VeilSovereignSigner {
            key: SovereignSignerKey::RecoveryEd25519(sk_seed),
        },
    );
    unsafe {
        ptr::copy_nonoverlapping(node_id.as_ptr(), out_node_id, 32);
        ptr::copy_nonoverlapping(public_key.as_ptr(), out_public_key, 32);
        *out_signer = token as *mut VeilSovereignSigner;
    }
    VEIL_OK
}

/// Sign one message during an open sovereign burst. The output is a raw
/// 64-byte Ed25519 signature.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_signer_sign(
    signer: *mut VeilSovereignSigner,
    message: *const u8,
    message_len: size_t,
    out_signature: *mut u8,
    out_signature_cap: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe { clear_err(err_out) };
    if signer.is_null()
        || message.is_null()
        || message_len > VEIL_MAX_DATA_LEN
        || out_signature.is_null()
        || out_signature_cap < 64
    {
        unsafe { write_err(err_out, "invalid sovereign signer sign arguments") };
        return VEIL_ERR_INVALID_ARG;
    }
    let Some(live) = HandleTable::get(sovereign_signer_table(), signer as usize) else {
        unsafe { write_err(err_out, "sovereign signer is closed or invalid") };
        return VEIL_ERR_CLOSED;
    };
    let message = unsafe { std::slice::from_raw_parts(message, message_len) };
    let SovereignSignerKey::RecoveryEd25519(sk_seed) = &live.key else {
        unsafe { write_err(err_out, "use variable-length signer API for bundle signer") };
        return VEIL_ERR_INVALID_ARG;
    };
    use ed25519_dalek::Signer as _;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(sk_seed);
    let signature = signing_key.sign(message).to_bytes();
    unsafe { ptr::copy_nonoverlapping(signature.as_ptr(), out_signature, 64) };
    VEIL_OK
}

/// Create a portable Ed25519+Falcon512 sovereign bundle encrypted with the
/// recovery phrase. The mutable phrase is wiped on every path. The returned
/// ciphertext buffer is freed with [`veil_free_buf`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_bundle_create_hybrid512_zeroize(
    phrase: *mut u8,
    phrase_len: size_t,
    out_bundle: *mut *mut u8,
    out_bundle_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe { clear_err(err_out) };
    if !out_bundle.is_null() {
        unsafe { *out_bundle = ptr::null_mut() }
    }
    if !out_bundle_len.is_null() {
        unsafe { *out_bundle_len = 0 }
    }
    if phrase.is_null()
        || phrase_len > MAX_FFI_CSTR_LEN
        || out_bundle.is_null()
        || out_bundle_len.is_null()
    {
        if !phrase.is_null() && phrase_len <= MAX_FFI_CSTR_LEN {
            unsafe { volatile_wipe(phrase, phrase_len) };
        }
        unsafe { write_err(err_out, "invalid sovereign bundle create arguments") };
        return VEIL_ERR_INVALID_ARG;
    }
    let owned = Zeroizing::new(
        unsafe { std::slice::from_raw_parts(phrase.cast_const(), phrase_len) }.to_vec(),
    );
    unsafe { volatile_wipe(phrase, phrase_len) };
    match veil_identity::sovereign_bundle::create_hybrid512(&owned) {
        Ok(bundle) => {
            let boxed = bundle.into_boxed_slice();
            let len = boxed.len();
            unsafe {
                *out_bundle = Box::into_raw(boxed).cast();
                *out_bundle_len = len;
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe { write_err(err_out, e.to_string()) };
            VEIL_ERR
        }
    }
}

/// Re-wrap an existing XVSB or XVRC credential into a fresh XVRC recovery
/// certificate while preserving the exact full public key and derived node id.
/// Current-secret and new-code buffers are wiped on every path; only encrypted
/// certificate bytes return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_recovery_certificate_export_zeroize(
    bundle: *const u8,
    bundle_len: size_t,
    phrase: *mut u8,
    phrase_len: size_t,
    recovery_code: *mut u8,
    recovery_code_len: size_t,
    out_certificate: *mut *mut u8,
    out_certificate_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe { clear_err(err_out) };
    if !out_certificate.is_null() {
        unsafe { *out_certificate = ptr::null_mut() }
    }
    if !out_certificate_len.is_null() {
        unsafe { *out_certificate_len = 0 }
    }
    let valid_phrase = !phrase.is_null() && phrase_len <= MAX_FFI_CSTR_LEN;
    let valid_code = !recovery_code.is_null() && recovery_code_len <= MAX_FFI_CSTR_LEN;
    if bundle.is_null()
        || bundle_len == 0
        || bundle_len > 16 * 1024
        || !valid_phrase
        || !valid_code
        || out_certificate.is_null()
        || out_certificate_len.is_null()
    {
        if valid_phrase {
            unsafe { volatile_wipe(phrase, phrase_len) };
        }
        if valid_code {
            unsafe { volatile_wipe(recovery_code, recovery_code_len) };
        }
        unsafe { write_err(err_out, "invalid recovery certificate export arguments") };
        return VEIL_ERR_INVALID_ARG;
    }
    let owned_phrase = Zeroizing::new(
        unsafe { std::slice::from_raw_parts(phrase.cast_const(), phrase_len) }.to_vec(),
    );
    let owned_code = Zeroizing::new(
        unsafe { std::slice::from_raw_parts(recovery_code.cast_const(), recovery_code_len) }
            .to_vec(),
    );
    unsafe {
        volatile_wipe(phrase, phrase_len);
        volatile_wipe(recovery_code, recovery_code_len);
    }
    let encrypted = unsafe { std::slice::from_raw_parts(bundle, bundle_len) };
    match veil_identity::sovereign_bundle::export_recovery_certificate(
        encrypted,
        &owned_phrase,
        &owned_code,
    ) {
        Ok(certificate) => {
            let boxed = certificate.into_boxed_slice();
            let len = boxed.len();
            unsafe {
                *out_certificate = Box::into_raw(boxed).cast();
                *out_certificate_len = len;
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe { write_err(err_out, e.to_string()) };
            VEIL_ERR
        }
    }
}

/// Open an XVRC with its independent recovery code as a short-lived hybrid
/// signer. The code is wiped before return and plaintext material stays native.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_signer_open_recovery_certificate_zeroize(
    certificate: *const u8,
    certificate_len: size_t,
    recovery_code: *mut u8,
    recovery_code_len: size_t,
    out_signer: *mut *mut VeilSovereignSigner,
    out_algorithm: *mut u8,
    out_node_id: *mut u8,
    out_node_id_cap: size_t,
    out_public_key: *mut u8,
    out_public_key_cap: size_t,
    out_public_key_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe { clear_err(err_out) };
    if !out_signer.is_null() {
        unsafe { *out_signer = ptr::null_mut() }
    }
    if !out_public_key_len.is_null() {
        unsafe { *out_public_key_len = 0 }
    }
    let valid_code = !recovery_code.is_null() && recovery_code_len <= MAX_FFI_CSTR_LEN;
    if certificate.is_null()
        || certificate_len == 0
        || certificate_len > 16 * 1024
        || !valid_code
        || out_signer.is_null()
        || out_algorithm.is_null()
        || out_node_id.is_null()
        || out_node_id_cap < 32
        || out_public_key.is_null()
        || out_public_key_len.is_null()
    {
        if valid_code {
            unsafe { volatile_wipe(recovery_code, recovery_code_len) };
        }
        unsafe { write_err(err_out, "invalid recovery certificate open arguments") };
        return VEIL_ERR_INVALID_ARG;
    }
    let owned_code = Zeroizing::new(
        unsafe { std::slice::from_raw_parts(recovery_code.cast_const(), recovery_code_len) }
            .to_vec(),
    );
    unsafe { volatile_wipe(recovery_code, recovery_code_len) };
    let encrypted = unsafe { std::slice::from_raw_parts(certificate, certificate_len) };
    let material =
        match veil_identity::sovereign_bundle::open_recovery_certificate(encrypted, &owned_code) {
            Ok(value) => value,
            Err(e) => {
                unsafe { write_err(err_out, e.to_string()) };
                return VEIL_ERR;
            }
        };
    if material.public_key.len() > out_public_key_cap {
        unsafe { write_err(err_out, "sovereign public-key output buffer too small") };
        return VEIL_ERR_INVALID_ARG;
    }
    let node_id = material.node_id();
    let algorithm = material.algorithm.wire_byte();
    let public_key_len = material.public_key.len();
    unsafe {
        ptr::copy_nonoverlapping(node_id.as_ptr(), out_node_id, 32);
        ptr::copy_nonoverlapping(material.public_key.as_ptr(), out_public_key, public_key_len);
        *out_algorithm = algorithm;
        *out_public_key_len = public_key_len;
    }
    let token = HandleTable::insert(
        sovereign_signer_table(),
        VeilSovereignSigner {
            key: SovereignSignerKey::Bundle(material),
        },
    );
    unsafe { *out_signer = token as *mut VeilSovereignSigner };
    VEIL_OK
}

/// Decrypt a local sovereign bundle and open a short-lived variable-algorithm
/// signer. Neither phrase nor plaintext key material crosses back to the host.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_signer_open_bundle_zeroize(
    bundle: *const u8,
    bundle_len: size_t,
    phrase: *mut u8,
    phrase_len: size_t,
    out_signer: *mut *mut VeilSovereignSigner,
    out_algorithm: *mut u8,
    out_node_id: *mut u8,
    out_node_id_cap: size_t,
    out_public_key: *mut u8,
    out_public_key_cap: size_t,
    out_public_key_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe { clear_err(err_out) };
    if !out_signer.is_null() {
        unsafe { *out_signer = ptr::null_mut() }
    }
    if !out_public_key_len.is_null() {
        unsafe { *out_public_key_len = 0 }
    }
    if bundle.is_null()
        || bundle_len == 0
        || bundle_len > 16 * 1024
        || phrase.is_null()
        || phrase_len > MAX_FFI_CSTR_LEN
        || out_signer.is_null()
        || out_algorithm.is_null()
        || out_node_id.is_null()
        || out_node_id_cap < 32
        || out_public_key.is_null()
        || out_public_key_len.is_null()
    {
        if !phrase.is_null() && phrase_len <= MAX_FFI_CSTR_LEN {
            unsafe { volatile_wipe(phrase, phrase_len) };
        }
        unsafe { write_err(err_out, "invalid sovereign bundle open arguments") };
        return VEIL_ERR_INVALID_ARG;
    }
    let owned_phrase = Zeroizing::new(
        unsafe { std::slice::from_raw_parts(phrase.cast_const(), phrase_len) }.to_vec(),
    );
    unsafe { volatile_wipe(phrase, phrase_len) };
    let encrypted = unsafe { std::slice::from_raw_parts(bundle, bundle_len) };
    let material = match veil_identity::sovereign_bundle::open(encrypted, &owned_phrase) {
        Ok(value) => value,
        Err(e) => {
            unsafe { write_err(err_out, e.to_string()) };
            return VEIL_ERR;
        }
    };
    if material.public_key.len() > out_public_key_cap {
        unsafe { write_err(err_out, "sovereign public-key output buffer too small") };
        return VEIL_ERR_INVALID_ARG;
    }
    let node_id = material.node_id();
    let algorithm = material.algorithm.wire_byte();
    let public_key_len = material.public_key.len();
    unsafe {
        ptr::copy_nonoverlapping(node_id.as_ptr(), out_node_id, 32);
        ptr::copy_nonoverlapping(material.public_key.as_ptr(), out_public_key, public_key_len);
        *out_algorithm = algorithm;
        *out_public_key_len = public_key_len;
    }
    let token = HandleTable::insert(
        sovereign_signer_table(),
        VeilSovereignSigner {
            key: SovereignSignerKey::Bundle(material),
        },
    );
    unsafe { *out_signer = token as *mut VeilSovereignSigner };
    VEIL_OK
}

/// Variable-length sovereign signature API. `out_signature_len` receives the
/// exact number of bytes written (64 for Ed25519, ~700-830 for hybrid-512).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_signer_sign_into(
    signer: *mut VeilSovereignSigner,
    message: *const u8,
    message_len: size_t,
    out_signature: *mut u8,
    out_signature_cap: size_t,
    out_signature_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe { clear_err(err_out) };
    if !out_signature_len.is_null() {
        unsafe { *out_signature_len = 0 }
    }
    if signer.is_null()
        || message.is_null()
        || message_len > VEIL_MAX_DATA_LEN
        || out_signature.is_null()
        || out_signature_len.is_null()
    {
        unsafe { write_err(err_out, "invalid sovereign signer sign-into arguments") };
        return VEIL_ERR_INVALID_ARG;
    }
    let Some(live) = HandleTable::get(sovereign_signer_table(), signer as usize) else {
        unsafe { write_err(err_out, "sovereign signer is closed or invalid") };
        return VEIL_ERR_CLOSED;
    };
    let message = unsafe { std::slice::from_raw_parts(message, message_len) };
    let signature = match &live.key {
        SovereignSignerKey::RecoveryEd25519(seed) => {
            use ed25519_dalek::Signer as _;
            ed25519_dalek::SigningKey::from_bytes(seed)
                .sign(message)
                .to_bytes()
                .to_vec()
        }
        SovereignSignerKey::Bundle(material) => match material.sign(message) {
            Ok(value) => value,
            Err(e) => {
                unsafe { write_err(err_out, e.to_string()) };
                return VEIL_ERR;
            }
        },
    };
    if signature.len() > out_signature_cap {
        unsafe { write_err(err_out, "sovereign signature output buffer too small") };
        return VEIL_ERR_INVALID_ARG;
    }
    unsafe {
        ptr::copy_nonoverlapping(signature.as_ptr(), out_signature, signature.len());
        *out_signature_len = signature.len();
    }
    VEIL_OK
}

/// Verify an algorithm-tagged sovereign signature and bind the supplied node
/// id to the full public key. Invalid signatures return VEIL_OK + false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_verify(
    algorithm: u8,
    node_id: *const u8,
    public_key: *const u8,
    public_key_len: size_t,
    message: *const u8,
    message_len: size_t,
    signature: *const u8,
    signature_len: size_t,
    out_valid: *mut bool,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe { clear_err(err_out) };
    if !out_valid.is_null() {
        unsafe { *out_valid = false }
    }
    if node_id.is_null()
        || public_key.is_null()
        || public_key_len > 4096
        || message.is_null()
        || message_len > VEIL_MAX_DATA_LEN
        || signature.is_null()
        || signature_len > 4096
        || out_valid.is_null()
    {
        unsafe { write_err(err_out, "invalid sovereign verify arguments") };
        return VEIL_ERR_INVALID_ARG;
    }
    let Some(algorithm) = veil_types::SignatureAlgorithm::from_wire_byte(algorithm) else {
        return VEIL_OK;
    };
    let expected_node = unsafe { std::slice::from_raw_parts(node_id, 32) };
    let public_key = unsafe { std::slice::from_raw_parts(public_key, public_key_len) };
    if veil_crypto::identity::compute_node_id(public_key).as_slice() != expected_node {
        return VEIL_OK;
    }
    let message = unsafe { std::slice::from_raw_parts(message, message_len) };
    let signature = unsafe { std::slice::from_raw_parts(signature, signature_len) };
    use base64::Engine as _;
    let public_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);
    unsafe {
        *out_valid =
            veil_crypto::verify_message(algorithm, &public_b64, message, signature).is_ok();
    }
    VEIL_OK
}

/// Close a sovereign signing burst. Double-close and stale handles are safe
/// no-ops; the generational table prevents ABA reuse.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_sovereign_signer_close(signer: *mut VeilSovereignSigner) {
    if signer.is_null() {
        return;
    }
    drop(HandleTable::remove(
        sovereign_signer_table(),
        signer as usize,
    ));
}
