//! Host-owned durability for peer revocation/rollback evidence. No disk I/O.
#![cfg(feature = "node-embedded")]

use crate::{
    VEIL_ERR, VEIL_ERR_INVALID_ARG, VEIL_OK, VeilHandle, embedded_services_for_bundle, guard,
    handle_table, null_check, write_err,
};
use libc::{c_char, c_int, size_t};

/// Host buffer ceiling for signed peer authorization documents. The data
/// contains peer identifiers: retain it only in the host's encrypted space.
pub const VEIL_PEER_AUTHORIZATION_MAX_STATE_LEN: size_t = 12 * 1024 * 1024;
/// Export wrote no payload. Retry with `*out_length` bytes of capacity.
pub const VEIL_ERR_PEER_AUTHORIZATION_BUFFER_TOO_SMALL: c_int = -40;

/// Revalidate a host's previously authenticated device/identity binding against
/// retained verified authorization. This is not proof of an anonymous caller.
/// Unknown, expired, revoked or not-yet-durable delegation returns false.
///
/// # Safety
/// The two ids must each be readable for 32 bytes. `out_allowed` and `err_out`
/// must be writable; `handle` must identify a live client connection.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_peer_device_proof_allowed(
    handle: *mut VeilHandle,
    peer_id: *const u8,
    device_id: *const u8,
    out_allowed: *mut u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_peer_device_proof_allowed") } {
        return rc;
    }
    null_check!(err_out, "handle" => handle, "peer_id" => peer_id,
        "device_id" => device_id, "out_allowed" => out_allowed);
    unsafe { *out_allowed = 0 };
    get_or_return!(
        live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let services = match embedded_services_for_bundle(&live.bundle) {
        Ok(services) => services,
        Err(error) => {
            unsafe { write_err(err_out, error) };
            return VEIL_ERR;
        }
    };
    let peer: &[u8; 32] = unsafe { &*peer_id.cast::<[u8; 32]>() };
    let device: &[u8; 32] = unsafe { &*device_id.cast::<[u8; 32]>() };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    unsafe {
        *out_allowed = u8::from(services.peer_device_proof_allowed(peer, device, now));
    }
    VEIL_OK
}

/// Acknowledge exactly the exported revision after durable encrypted storage.
/// Documents learned since that export remain unusable until their own commit.
///
/// # Safety
/// `handle` must be live and `err_out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_peer_authorization_ack(
    handle: *mut VeilHandle,
    revision: u64,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_peer_authorization_ack") } {
        return rc;
    }
    null_check!(err_out, "handle" => handle);
    get_or_return!(
        live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let result = embedded_services_for_bundle(&live.bundle).and_then(|services| {
        services
            .identity
            .peer_mlkem_cert_store
            .acknowledge_peer_authorization(revision)
    });
    match result {
        Ok(()) => VEIL_OK,
        Err(error) => {
            unsafe { write_err(err_out, error) };
            VEIL_ERR
        }
    }
}

/// Current process-local peer authorization revision. Cache reads do not move
/// it; accepted document changes and initial host restore do.
///
/// # Safety
/// `handle` must be live; `out_revision` and `err_out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_peer_authorization_version(
    handle: *mut VeilHandle,
    out_revision: *mut u64,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_peer_authorization_version") } {
        return rc;
    }
    null_check!(err_out, "handle" => handle, "out_revision" => out_revision);
    get_or_return!(
        live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let services = match embedded_services_for_bundle(&live.bundle) {
        Ok(services) => services,
        Err(error) => {
            unsafe { write_err(err_out, error) };
            return VEIL_ERR;
        }
    };
    unsafe {
        *out_revision = services
            .identity
            .peer_mlkem_cert_store
            .peer_authorization_version()
    };
    VEIL_OK
}

/// Snapshot all retained peer floors and their exact revision under one lock.
/// A snapshot consumes no dirty state. The host advances its saved revision
/// only after its encrypted publication is durable. JSON v1 contains `entries`
/// of `{peer: lowercase node-id hex, document: base64 signed document}`.
///
/// # Safety
/// `handle` must be live. `out_length`, `out_revision` and `err_out` writable.
/// `out_buf` must be writable for `capacity` bytes; NULL is allowed at capacity
/// zero for a size query. Insufficient capacity writes no payload bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_peer_authorization_export(
    handle: *mut VeilHandle,
    out_buf: *mut u8,
    capacity: size_t,
    out_length: *mut size_t,
    out_revision: *mut u64,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_peer_authorization_export") } {
        return rc;
    }
    null_check!(err_out, "handle" => handle, "out_length" => out_length, "out_revision" => out_revision);
    unsafe {
        *out_length = 0;
        *out_revision = 0;
    }
    if capacity > VEIL_PEER_AUTHORIZATION_MAX_STATE_LEN || (capacity > 0 && out_buf.is_null()) {
        unsafe { write_err(err_out, "invalid peer authorization output buffer") };
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let result = embedded_services_for_bundle(&live.bundle).and_then(|services| {
        services
            .identity
            .peer_mlkem_cert_store
            .export_peer_authorization()
    });
    let (revision, bytes) = match result {
        Ok(snapshot) => snapshot,
        Err(error) => {
            unsafe { write_err(err_out, error) };
            return VEIL_ERR;
        }
    };
    if bytes.len() > VEIL_PEER_AUTHORIZATION_MAX_STATE_LEN {
        unsafe { write_err(err_out, "peer authorization state exceeds budget") };
        return VEIL_ERR;
    }
    unsafe {
        *out_length = bytes.len();
        *out_revision = revision;
    }
    if capacity < bytes.len() {
        return VEIL_ERR_PEER_AUTHORIZATION_BUFFER_TOO_SMALL;
    }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len()) };
    VEIL_OK
}

/// Restore the host's durable negative evidence once, before binding the app's
/// endpoints or sending application traffic. Signed historical documents are
/// rechecked; they never grant current delegation rights. Transient native-boot
/// observations are replayed against this durable baseline. Clears warm sender
/// key caches so pre-restore authorization cannot survive restoration.
///
/// # Safety
/// `handle` must be live; `bytes` readable for `length`; `err_out` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_peer_authorization_restore(
    handle: *mut VeilHandle,
    bytes: *const u8,
    length: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_peer_authorization_restore") } {
        return rc;
    }
    null_check!(err_out, "handle" => handle, "bytes" => bytes);
    if length == 0 || length > VEIL_PEER_AUTHORIZATION_MAX_STATE_LEN {
        unsafe { write_err(err_out, "invalid peer authorization input length") };
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let services = match embedded_services_for_bundle(&live.bundle) {
        Ok(services) => services,
        Err(error) => {
            unsafe { write_err(err_out, error) };
            return VEIL_ERR;
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let input = unsafe { std::slice::from_raw_parts(bytes, length) };
    if let Err(error) = services
        .identity
        .peer_mlkem_cert_store
        .restore_peer_authorization(input, now)
    {
        unsafe { write_err(err_out, error) };
        return VEIL_ERR;
    }
    veil_util::wlock!(services.identity.peer_mlkem_keys).clear();
    veil_util::wlock!(services.identity.peer_mlkem_certs).clear();
    veil_util::wlock!(services.identity.peer_ratchet_keys).clear();
    VEIL_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn rejects_bad_lengths_and_handles_without_reading_or_writing_payloads() {
        let mut error = ptr::null_mut();
        let stale = ptr::dangling_mut::<VeilHandle>();
        let mut revision = 9;
        let mut length = 9;
        let mut guard = [0xab; 8];
        let ids = [0u8; 32];
        let mut allowed = 1;
        unsafe {
            assert_eq!(
                veil_peer_device_proof_allowed(
                    stale,
                    ids.as_ptr(),
                    ids.as_ptr(),
                    &mut allowed,
                    &mut error
                ),
                VEIL_ERR_INVALID_ARG
            );
            assert_eq!(allowed, 0);
            crate::veil_free_string(error);
            assert_eq!(
                veil_peer_authorization_version(stale, &mut revision, &mut error),
                VEIL_ERR_INVALID_ARG
            );
            crate::veil_free_string(error);
            assert_eq!(
                veil_peer_authorization_ack(stale, 0, &mut error),
                VEIL_ERR_INVALID_ARG
            );
            crate::veil_free_string(error);
            assert_eq!(
                veil_peer_authorization_export(
                    stale,
                    guard.as_mut_ptr(),
                    8,
                    &mut length,
                    &mut revision,
                    &mut error
                ),
                VEIL_ERR_INVALID_ARG
            );
            crate::veil_free_string(error);
            assert_eq!(guard, [0xab; 8]);
            assert_eq!((length, revision), (0, 0));
            for input_len in [0, VEIL_PEER_AUTHORIZATION_MAX_STATE_LEN + 1] {
                assert_eq!(
                    veil_peer_authorization_restore(stale, ptr::dangling(), input_len, &mut error),
                    VEIL_ERR_INVALID_ARG
                );
                crate::veil_free_string(error);
            }
            assert_eq!(
                veil_peer_authorization_export(
                    stale,
                    ptr::null_mut(),
                    1,
                    &mut length,
                    &mut revision,
                    &mut error
                ),
                VEIL_ERR_INVALID_ARG
            );
            crate::veil_free_string(error);
        }
    }
}
