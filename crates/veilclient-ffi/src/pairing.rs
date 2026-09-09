//! Multi-device pairing (Epic 489.8): admitting a second device.
//!
//! Both ends of one exchange live here on purpose. The initiator mints an
//! offer, the target answers it, and each step is only meaningful against the
//! matching step on the other side — a change to one that is not made to the
//! other produces two builds that cannot pair and no compiler error saying
//! so.
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

// ── Multi-device pairing FFI (Epic 489.8) ──────────────────────

/// Wire-byte status codes for Source-side pairing ops.  Mirror
/// `veil_proto::pair_source_status`.
pub const VEIL_PAIR_SOURCE_OK: u8 = 0;
pub const VEIL_PAIR_SOURCE_NOT_CONFIGURED: u8 = 1;
pub const VEIL_PAIR_SOURCE_ALREADY_IN_PROGRESS: u8 = 2;
pub const VEIL_PAIR_SOURCE_INTERNAL_ERROR: u8 = 3;
pub const VEIL_PAIR_SOURCE_WRONG_STATE: u8 = 4;
pub const VEIL_PAIR_SOURCE_BAD_HELLO: u8 = 5;
pub const VEIL_PAIR_SOURCE_USER_ABORTED: u8 = 6;
pub const VEIL_PAIR_SOURCE_BAD_CONFIRM: u8 = 7;

/// Wire-byte status codes for Target-side pairing ops.  Mirror
/// `veil_proto::pair_target_status`.
pub const VEIL_PAIR_TARGET_OK: u8 = 0;
pub const VEIL_PAIR_TARGET_BAD_URI: u8 = 1;
pub const VEIL_PAIR_TARGET_EXPIRED: u8 = 2;
pub const VEIL_PAIR_TARGET_ALREADY_IN_PROGRESS: u8 = 3;
pub const VEIL_PAIR_TARGET_BAD_CERT: u8 = 4;
pub const VEIL_PAIR_TARGET_WRONG_STATE: u8 = 5;
pub const VEIL_PAIR_TARGET_INTERNAL_ERROR: u8 = 6;

/// Hard cap on ceremony frame size (mirrors
/// `veil_proto::MAX_PAIR_CEREMONY_BYTES`).  Callers can pre-
/// allocate a buffer of this size to safely receive Hello / Cert /
/// Confirm bytes without two-call sizing.
pub const VEIL_MAX_PAIR_CEREMONY_BYTES: size_t = 64 * 1024;

/// OOB code length (always 6 ASCII digits).
pub const VEIL_PAIR_OOB_CODE_LEN: size_t = 6;

/// Helper: write SDK reply detail to err_out if non-empty (treats
/// detail as advisory metadata, not a fatal-error string).  Used by
/// every pairing FFI fn so consumers get a stable surface.
unsafe fn write_pair_detail(err_out: *mut *mut c_char, detail: &str) {
    if !detail.is_empty() && !err_out.is_null() {
        unsafe {
            write_err(err_out, detail);
        }
    }
}

/// Source-side: generate a pair-invite URI + initialize ceremony.
/// On success, `*out_uri` receives a malloc'd NUL-terminated UTF-8
/// string — caller frees with [`veil_free_string`].  `password` is the
/// master_sk decryption passphrase as `(ptr, len)` UTF-8; pass a NULL pointer
/// (length ignored) for a standalone identity with no encrypted master.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_pair_source_create_invite(
    handle: *mut VeilHandle,
    password: *const u8,
    password_len: usize,
    out_status: *mut u8,
    out_uri: *mut *mut c_char,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_pair_source_create_invite") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_status" => out_status,
        "out_uri" => out_uri,
    );
    unsafe {
        *out_uri = ptr::null_mut();
    }
    // M26: reject a non-NULL but non-UTF-8 master password rather than silently
    // dropping it to None (pairing transfers master-identity material — a
    // silently-unprotected invite is even worse than the bootstrap case).
    let pw = match unsafe { opt_slice_to_str(password, password_len) } {
        Ok(p) => p,
        Err(()) => {
            unsafe {
                write_err(
                    err_out,
                    "master password is not valid UTF-8 — refusing to proceed".to_owned(),
                );
            }
            return VEIL_ERR_INVALID_ARG;
        }
    };
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.pair_source_create_invite(pw).await
    });
    match res {
        Ok(reply) => {
            unsafe {
                *out_status = reply.status;
            }
            if reply.status == VEIL_PAIR_SOURCE_OK && !reply.uri.is_empty() {
                match std::ffi::CString::new(reply.uri.as_bytes()) {
                    Ok(c) => unsafe {
                        *out_uri = c.into_raw();
                    },
                    Err(e) => unsafe {
                        *out_status = VEIL_PAIR_SOURCE_INTERNAL_ERROR;
                        write_err(err_out, format!("URI contains NUL byte: {e}"));
                    },
                }
            }
            unsafe {
                write_pair_detail(err_out, &reply.detail);
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("pair_source_create_invite failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Source-side: process Hello bytes from Target.  Returns Cert bytes
/// (via caller buffer) + 6-digit OOB code.  `out_cert_buf` must be
/// writable for ≥ `out_cert_buf_cap` bytes (recommend
/// `VEIL_MAX_PAIR_CEREMONY_BYTES` = 64 KiB so a fixed-size buffer
/// always fits the Cert).  `out_oob_6` MUST point to a 6-byte buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_pair_source_handle_hello(
    handle: *mut VeilHandle,
    hello_bytes: *const u8,
    hello_len: size_t,
    out_status: *mut u8,
    out_oob_6: *mut u8,
    out_cert_buf: *mut u8,
    out_cert_buf_cap: size_t,
    out_cert_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_pair_source_handle_hello") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_status" => out_status,
        "out_oob_6" => out_oob_6,
        "out_cert_buf" => out_cert_buf,
        "out_cert_len" => out_cert_len,
    );
    if hello_bytes.is_null() && hello_len > 0 {
        unsafe {
            write_err(err_out, "hello_bytes is NULL but hello_len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    // Audit L-16: bound the caller-supplied length BEFORE `from_raw_parts(...)
    // .to_vec()`, matching every other byte-input FFI fn. An unbounded `len`
    // (mis-bound / hostile caller) would OOM-kill the host before any downstream
    // pairing-frame limit fires. 64 KiB is the documented ceremony-frame cap.
    if hello_len > VEIL_MAX_PAIR_CEREMONY_BYTES {
        unsafe {
            write_err(err_out, "hello_len exceeds VEIL_MAX_PAIR_CEREMONY_BYTES");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    unsafe {
        ptr::write_bytes(out_oob_6, 0, 6);
        *out_cert_len = 0;
    }
    let hello = if hello_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(hello_bytes, hello_len) }.to_vec()
    };
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.pair_source_handle_hello(hello).await
    });
    match res {
        Ok(reply) => {
            unsafe {
                *out_status = reply.status;
            }
            if reply.status == VEIL_PAIR_SOURCE_OK {
                if reply.response_bytes.len() > out_cert_buf_cap {
                    unsafe {
                        write_err(
                            err_out,
                            format!(
                                "cert bytes {} > out_cert_buf_cap {}",
                                reply.response_bytes.len(),
                                out_cert_buf_cap,
                            ),
                        );
                        *out_status = VEIL_PAIR_SOURCE_INTERNAL_ERROR;
                    }
                } else {
                    unsafe {
                        if !reply.response_bytes.is_empty() {
                            ptr::copy_nonoverlapping(
                                reply.response_bytes.as_ptr(),
                                out_cert_buf,
                                reply.response_bytes.len(),
                            );
                        }
                        *out_cert_len = reply.response_bytes.len();
                        ptr::copy_nonoverlapping(reply.oob_code.as_ptr(), out_oob_6, 6);
                    }
                }
            }
            unsafe {
                write_pair_detail(err_out, &reply.detail);
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("pair_source_handle_hello failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Source-side: process Confirm bytes — finalizes the ceremony.
///
/// Phase 6.49 exemplar: uses [`guard::ffi_prelude`] + [`null_check!`]
/// for the boundary checks so that the consistent error messages
/// land on every FFI fn after incremental migration.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_pair_source_handle_confirm(
    handle: *mut VeilHandle,
    confirm_bytes: *const u8,
    confirm_len: size_t,
    out_status: *mut u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_pair_source_handle_confirm") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_status" => out_status,
    );
    // Conditional null check doesn't fit the uniform macro shape —
    // keep inline.  Pattern stays consistent across all FFI fns.
    if confirm_bytes.is_null() && confirm_len > 0 {
        unsafe {
            write_err(err_out, "confirm_bytes is NULL but confirm_len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    // Audit L-16: bound the length before `from_raw_parts(...).to_vec()`.
    if confirm_len > VEIL_MAX_PAIR_CEREMONY_BYTES {
        unsafe {
            write_err(err_out, "confirm_len exceeds VEIL_MAX_PAIR_CEREMONY_BYTES");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    let confirm = if confirm_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(confirm_bytes, confirm_len) }.to_vec()
    };
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.pair_source_handle_confirm(confirm).await
    });
    match res {
        Ok(reply) => {
            unsafe {
                *out_status = reply.status;
                write_pair_detail(err_out, &reply.detail);
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("pair_source_handle_confirm failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Target-side: consume scanned URI, build Hello bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_pair_target_consume_uri(
    handle: *mut VeilHandle,
    uri: *const u8,
    uri_len: usize,
    out_status: *mut u8,
    out_hello_buf: *mut u8,
    out_hello_buf_cap: size_t,
    out_hello_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_pair_target_consume_uri") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_status" => out_status,
        "out_hello_buf" => out_hello_buf,
        "out_hello_len" => out_hello_len,
    );
    let Some(uri_str) = (unsafe { slice_to_str(uri, uri_len) }) else {
        unsafe {
            write_err(err_out, "uri is NULL or invalid UTF-8");
        }
        return VEIL_ERR_INVALID_ARG;
    };
    unsafe {
        *out_hello_len = 0;
    }
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.pair_target_consume_uri(uri_str).await
    });
    match res {
        Ok(reply) => {
            unsafe {
                *out_status = reply.status;
            }
            if reply.status == VEIL_PAIR_TARGET_OK {
                if reply.bytes.len() > out_hello_buf_cap {
                    unsafe {
                        write_err(
                            err_out,
                            format!(
                                "hello bytes {} > out_hello_buf_cap {}",
                                reply.bytes.len(),
                                out_hello_buf_cap,
                            ),
                        );
                        *out_status = VEIL_PAIR_TARGET_INTERNAL_ERROR;
                    }
                } else {
                    unsafe {
                        if !reply.bytes.is_empty() {
                            ptr::copy_nonoverlapping(
                                reply.bytes.as_ptr(),
                                out_hello_buf,
                                reply.bytes.len(),
                            );
                        }
                        *out_hello_len = reply.bytes.len();
                    }
                }
            }
            unsafe {
                write_pair_detail(err_out, &reply.detail);
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("pair_target_consume_uri failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Target-side: process Cert bytes, return OOB code.
///
/// Phase 6.49 exemplar (second after `veil_pair_source_handle_confirm`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_pair_target_handle_cert(
    handle: *mut VeilHandle,
    cert_bytes: *const u8,
    cert_len: size_t,
    out_status: *mut u8,
    out_oob_6: *mut u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_pair_target_handle_cert") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_status" => out_status,
        "out_oob_6" => out_oob_6,
    );
    if cert_bytes.is_null() && cert_len > 0 {
        unsafe {
            write_err(err_out, "cert_bytes is NULL but cert_len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    // Audit L-16: bound the length before `from_raw_parts(...).to_vec()`.
    if cert_len > VEIL_MAX_PAIR_CEREMONY_BYTES {
        unsafe {
            write_err(err_out, "cert_len exceeds VEIL_MAX_PAIR_CEREMONY_BYTES");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    unsafe {
        ptr::write_bytes(out_oob_6, 0, 6);
    }
    let cert = if cert_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(cert_bytes, cert_len) }.to_vec()
    };
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.pair_target_handle_cert(cert).await
    });
    match res {
        Ok(reply) => {
            unsafe {
                *out_status = reply.status;
                if reply.status == VEIL_PAIR_TARGET_OK {
                    ptr::copy_nonoverlapping(reply.oob_code.as_ptr(), out_oob_6, 6);
                }
                write_pair_detail(err_out, &reply.detail);
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("pair_target_handle_cert failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Target-side: emit Confirm bytes based on user's OOB-compare
/// decision.  `confirmed = 1` triggers identity persistence.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_pair_target_build_confirm(
    handle: *mut VeilHandle,
    confirmed: u8,
    out_status: *mut u8,
    out_confirm_buf: *mut u8,
    out_confirm_buf_cap: size_t,
    out_confirm_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_pair_target_build_confirm") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_status" => out_status,
        "out_confirm_buf" => out_confirm_buf,
        "out_confirm_len" => out_confirm_len,
    );
    unsafe {
        *out_confirm_len = 0;
    }
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client.pair_target_build_confirm(confirmed != 0).await
    });
    match res {
        Ok(reply) => {
            unsafe {
                *out_status = reply.status;
            }
            if reply.status == VEIL_PAIR_TARGET_OK {
                if reply.bytes.len() > out_confirm_buf_cap {
                    unsafe {
                        write_err(
                            err_out,
                            format!(
                                "confirm bytes {} > out_confirm_buf_cap {}",
                                reply.bytes.len(),
                                out_confirm_buf_cap,
                            ),
                        );
                        *out_status = VEIL_PAIR_TARGET_INTERNAL_ERROR;
                    }
                } else {
                    unsafe {
                        if !reply.bytes.is_empty() {
                            ptr::copy_nonoverlapping(
                                reply.bytes.as_ptr(),
                                out_confirm_buf,
                                reply.bytes.len(),
                            );
                        }
                        *out_confirm_len = reply.bytes.len();
                    }
                }
            }
            unsafe {
                write_pair_detail(err_out, &reply.detail);
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("pair_target_build_confirm failed: {e}"));
            }
            VEIL_ERR
        }
    }
}
