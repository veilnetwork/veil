//! Trusted host publication floors; never accepts commands from a peer.
use super::{VEIL_RATCHET_MAX_SEND_POSITIONS, ratchet_for_bundle, ratchet_key_from};
use crate::{
    VEIL_ERR, VEIL_ERR_INVALID_ARG, VEIL_OK, VeilHandle, guard, handle_table, null_check, write_err,
};
use libc::{c_char, c_int, size_t};
use std::ptr;

/// The queried attachment is retired or has been superseded.
pub const VEIL_RATCHET_HOST_RETIRED: c_int = 0;
/// The queried attachment is active and no chain currently needs a floor.
pub const VEIL_RATCHET_HOST_IDLE: c_int = 1;
/// At least one encryption is waiting for a committed reservation.
pub const VEIL_RATCHET_HOST_NEEDS_RESERVATION: c_int = 2;
/// Another owner has replaced this attachment; its state must not be saved
/// into the retired owner's container.
pub const VEIL_RATCHET_HOST_SUPERSEDED: c_int = 3;

fn with_store(
    handle: *mut VeilHandle,
    err_out: *mut *mut c_char,
    op: impl FnOnce(&veil_e2e::RatchetStore) -> c_int,
) -> c_int {
    get_or_return!(
        live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    match ratchet_for_bundle(&live.bundle) {
        Ok(runtime) => op(&runtime.store),
        Err(error) => {
            unsafe { write_err(err_out, error) };
            VEIL_ERR
        }
    }
}

/// Begin a journaled publication attachment. Must precede application sends.
/// Memory-only stores remain unchanged until this API is explicitly called.
///
/// # Safety
/// `handle` is live; `out_epoch` is writable. Standard error-pointer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_ratchet_host_begin(
    handle: *mut VeilHandle,
    out_epoch: *mut u64,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_ratchet_host_begin") } {
        return rc;
    }
    null_check!(err_out, "handle" => handle, "out_epoch" => out_epoch);
    unsafe {
        *out_epoch = 0;
    }
    with_store(handle, err_out, |store| {
        unsafe {
            *out_epoch = store.begin_host_publication();
        }
        VEIL_OK
    })
}

/// Read this attachment's bounded reservation demand without changing keys.
///
/// # Safety
/// `handle` is live; `out_state` is writable. Standard error-pointer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_ratchet_host_state(
    handle: *mut VeilHandle,
    epoch: u64,
    out_state: *mut c_int,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_ratchet_host_state") } {
        return rc;
    }
    null_check!(err_out, "handle" => handle, "out_state" => out_state);
    unsafe {
        *out_state = VEIL_RATCHET_HOST_RETIRED;
    }
    with_store(handle, err_out, |store| {
        let state = store.host_publication_state();
        unsafe {
            *out_state = if state.epoch != epoch {
                VEIL_RATCHET_HOST_SUPERSEDED
            } else if !state.active {
                VEIL_RATCHET_HOST_RETIRED
            } else if state.required == 0 {
                VEIL_RATCHET_HOST_IDLE
            } else {
                VEIL_RATCHET_HOST_NEEDS_RESERVATION
            };
        }
        VEIL_OK
    })
}

/// Install public chain/index floors only AFTER the host committed them.
/// Records are 32 chain bytes followed by a big-endian u32 exclusive end.
/// An absent/retired chain cannot acquire authority from another chain's mark.
///
/// # Safety
/// `handle` is live; `key_64` names 64 readable bytes; `marks` names
/// `count * 36` readable bytes (may be null only for count zero). Error contract
/// matches the other ratchet entry points. Count is bounded before any read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_ratchet_host_allow(
    handle: *mut VeilHandle,
    epoch: u64,
    key_64: *const u8,
    marks: *const u8,
    count: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_ratchet_host_allow") } {
        return rc;
    }
    null_check!(err_out, "handle" => handle, "key_64" => key_64);
    if count > VEIL_RATCHET_MAX_SEND_POSITIONS || (count != 0 && marks.is_null()) {
        unsafe {
            write_err(err_out, "invalid host publication mark count/buffer");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    with_store(handle, err_out, |store| {
        let key = unsafe { ratchet_key_from(key_64) };
        let mut positions = Vec::with_capacity(count);
        for i in 0..count {
            let mut chain = [0u8; 32];
            let mut next = [0u8; 4];
            unsafe {
                ptr::copy_nonoverlapping(marks.add(i * 36), chain.as_mut_ptr(), 32);
                ptr::copy_nonoverlapping(marks.add(i * 36 + 32), next.as_mut_ptr(), 4);
            }
            positions.push(veil_e2e::ratchet::SendPosition {
                chain,
                next: u32::from_be_bytes(next),
            });
        }
        match store.allow_host_publication(epoch, &key, &positions) {
            Ok(()) => VEIL_OK,
            Err(error) => {
                unsafe {
                    write_err(err_out, error.to_string());
                }
                VEIL_ERR_INVALID_ARG
            }
        }
    })
}

/// Close only this attachment. Blocked requests fail closed, never downgrade.
/// Closing a superseded epoch is an idempotent no-op for the current owner.
///
/// # Safety
/// `handle` is live. Standard error-pointer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_ratchet_host_end(
    handle: *mut VeilHandle,
    epoch: u64,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_ratchet_host_end") } {
        return rc;
    }
    null_check!(err_out,"handle"=>handle);
    with_store(handle, err_out, |store| {
        store.end_host_publication(epoch);
        VEIL_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_handles_and_counts_are_rejected_before_reading_mark_buffers() {
        // Deliberately unreadable key/mark pointers must never be followed
        // when the capability handle or count is invalid.
        let unknown = std::ptr::without_provenance_mut::<VeilHandle>(1);
        let unreadable = std::ptr::without_provenance::<u8>(1);
        let mut error = ptr::null_mut();
        let mut epoch = 99;
        assert_eq!(
            unsafe { veil_ratchet_host_begin(unknown, &mut epoch, &mut error) },
            VEIL_ERR_INVALID_ARG
        );
        assert_eq!(epoch, 0);
        unsafe { crate::veil_free_string(error) };
        error = ptr::null_mut();
        let mut status = 99;
        assert_eq!(
            unsafe { veil_ratchet_host_state(unknown, 1, &mut status, &mut error) },
            VEIL_ERR_INVALID_ARG
        );
        assert_eq!(status, VEIL_RATCHET_HOST_RETIRED);
        unsafe { crate::veil_free_string(error) };
        for count in [0, 1, VEIL_RATCHET_MAX_SEND_POSITIONS + 1, usize::MAX] {
            error = ptr::null_mut();
            assert_eq!(
                unsafe {
                    veil_ratchet_host_allow(unknown, 1, unreadable, unreadable, count, &mut error)
                },
                VEIL_ERR_INVALID_ARG
            );
            unsafe { crate::veil_free_string(error) };
        }
        error = ptr::null_mut();
        assert_eq!(
            unsafe { veil_ratchet_host_end(unknown, 1, &mut error) },
            VEIL_ERR_INVALID_ARG
        );
        unsafe { crate::veil_free_string(error) };
    }
}
