//! Shared boundary helpers для FFI entry points (Phase 6.49 audit
//! recommendation).
//!
//! Every `veil_*` FFI fn historically repeats the same prelude:
//!
//! ```ignore
//! unsafe { clear_err(err_out); }
//! if in_tokio_runtime() {
//!     unsafe { write_err(err_out, "<op_name> called from inside a Tokio runtime — would deadlock"); }
//!     return VEIL_ERR_REENTRANT;
//! }
//! if handle.is_null() {
//!     unsafe { write_err(err_out, "handle is NULL"); }
//!     return VEIL_ERR_INVALID_ARG;
//! }
//! // ... more null checks ...
//! ```
//!
//! This module consolidates that boilerplate into а single function +
//! pair of macros so every FFI fn surfaces the same diagnostic
//! strings, the same return codes, и the same reentrancy guard.
//!
//! # Migration plan
//!
//! Rollout is incremental — а complete one-shot migration would touch
//! ~40 fns с large per-fn diffs.  Instead:
//!
//! * **New FFI fns** (including any future Epic 489 / 462 work) use
//!   the helpers from day one.  See `veil_pair_*` (Epic 489.8) and
//!   `veil_create_bootstrap_invite` (Epic 489.7 generator) for
//!   reference applications.
//! * **Existing fns** get migrated opportunistically когда touched
//!   для another reason — the rule "any FFI fn you edit gets ported
//!   к [`ffi_prelude`]" caps the rollout cost к fns we already
//!   touch.
//! * Pure renames / additions of FFI fns are NOT а trigger by
//!   themselves — only behavioral edits.
//!
//! Hard pre-merge gate is intentionally light: enforcing the migration
//! through CI lint would require either а custom rustc lint pass or а
//! fragile grep, и the audit findings explicitly note the original
//! pattern is "mostly cosmetic" — а forcing function makes the
//! tradeoff worse, not better.
//!
//! # Intentionally not migrated (status: closed)
//!
//! Phase 6.51 migration sweep brought the count к **26/40 fns
//! ported**.  Phase 6.50.b-followup batch added 3 new FFI fns
//! (multi-device pairing + bootstrap-invite generator + push-envelope
//! seal) which slot into the existing categorisation без changing the
//! "intentionally-not-migrated" subset.  Current count as of
//! 2026-05-21: **29/41 fns ported**.  The remaining 12 fns ара
//! INTENTIONALLY NOT MIGRATED because they fall into one of four
//! categories с different semantics than the ffi_prelude pattern was
//! designed для.  Listed here so future audits don't re-open the row:
//!
//! ## Category 1 — destructors / cleanup fns (silent on null)
//!
//! These fns DO accept `NULL` as а valid value (idempotent close +
//! double-free guard) and have NO `err_out` parameter.  Adding the
//! ffi_prelude pattern would change their semantics — they ара
//! expected к silently no-op on already-freed / NULL handles, NOT
//! к write а diagnostic string.
//!
//! * `veil_free_string(s: *mut c_char)` — frees а Box-allocated
//!   error string.  No err_out; silent on null.
//! * `veil_close(handle)` — drops the connection; uses the external
//!   live-handle registry double-free guard.  No err_out.
//! * `veil_app_close(app)` — same pattern, app-handle-scoped.
//! * `veil_stream_close(stream)` — same pattern, stream-scoped.
//!
//! ## Category 2 — getters without err_out
//!
//! These fns return either а sentinel value (0, NULL) или а
//! cheap-to-compute value directly; they don't have an err_out
//! parameter to populate с а diagnostic.  Adding the ffi_prelude
//! pattern would require а signature change что breaks ABI.
//!
//! * `veil_app_get_app_id(app, out) -> c_int` — copies 32 bytes;
//!   returns `VEIL_ERR_INVALID_ARG` direct on null.
//! * `veil_app_get_endpoint_id(app) -> u32` — returns 0 sentinel
//!   on null.
//!
//! ## Category 3 — trampolines к internal helpers
//!
//! These fns immediately delegate к an internal `*_inner` function
//! that DOES use ffi_prelude.  Adding the prelude к the trampoline
//! too would just run the check twice.
//!
//! * `veil_bind` → `bind_internal` (which calls ffi_prelude).
//! * `veil_bind_named` → `bind_internal`.
//! * `veil_mailbox_put` → `mailbox_put_inner`.
//!
//! ## Category 4 — pure-sync fns (no `block_on`, no daemon IPC)
//!
//! The reentrancy guard inside `ffi_prelude` exists к catch callers
//! что invoke а `block_on`-using FFI fn от inside an existing tokio
//! runtime (causes deadlock).  Pure-sync fns что do no async work
//! ара not deadlock-vulnerable, so the reentrancy check is dead
//! weight.  They still call `clear_err(err_out)` + manual null checks
//! since the boilerplate that motivated the prelude (multi-line
//! diagnostic + reentrancy guard) doesn't apply.
//!
//! * `veil_seal_push_envelope` — calls
//!   `veil-anonymity::push_envelope::seal_push_envelope`
//!   (synchronous X25519 + ChaCha20-Poly1305).
//! * `veil_set_event_handler` — just stashes а callback pointer
//!   в the handle's mutex.
//! * `veil_validate_bip39_phrase` + `_zeroize` variant — invokes
//!   `veil-identity::master_seed::decode_master_seed_from_phrase`
//!   (pure BIP-39 dictionary + checksum check).
//! * `veil_restore_identity_from_phrase` + `_zeroize` +
//!   `_zeroize_with_password` variants — synchronous identity
//!   derivation + atomic disk writes.  No daemon IPC.
//! * `veil_mailbox_fetch_into` — reads cached state from а
//!   `Mutex<Option<Vec<MailboxBlob>>>` populated by the prior
//!   `veil_mailbox_fetch_count` call.  Pure-sync state pop.
//!
//! ## Re-evaluation criteria
//!
//! Open this row если any of:
//! 1. А new category-4 fn gains а `block_on` call (now needs
//!    reentrancy check).
//! 2. CI gains а custom-lint pass capable of enforcing the migration
//!    cheaply (so the "forcing function trade-off" calculation
//!    flips).
//! 3. А category-2 fn signature changes к add an err_out parameter
//!    (then prelude makes sense).

use std::ffi::c_char;
use std::os::raw::c_int;

use crate::{VEIL_ERR_INVALID_ARG, VEIL_ERR_REENTRANT, clear_err, in_tokio_runtime, write_err};

/// Outcome of [`ffi_prelude`] — either а return code the caller must
/// surface immediately, or `Ok(())` indicating safe к proceed.
pub(crate) type FfiPreludeOutcome = Result<(), c_int>;

/// Combined boundary prelude:
///
/// 1. Clears any pre-existing error string in `err_out`.
/// 2. Checks the calling thread is NOT inside а tokio runtime context
///    (those would deadlock on `block_on`).
///
/// Returns `Err(VEIL_ERR_REENTRANT)` if the reentrancy check
/// trips; the caller propagates that immediately.  Returns `Ok(())`
/// otherwise.
///
/// `op_name` is embedded в the error message ("<op_name> called from
/// inside a Tokio runtime — would deadlock") so consumers can identify
/// which FFI fn tripped.  Keep this а static literal matching the fn
/// name; doc-comment lint катches mismatches at review time.
///
/// # Safety
///
/// `err_out` may be NULL OR must point к а writable `*mut c_char`
/// slot.  Same contract as [`write_err`].
pub(crate) unsafe fn ffi_prelude(
    err_out: *mut *mut c_char,
    op_name: &'static str,
) -> FfiPreludeOutcome {
    unsafe {
        clear_err(err_out);
    }
    if in_tokio_runtime() {
        unsafe {
            write_err(
                err_out,
                format!("{op_name} called from inside a Tokio runtime — would deadlock"),
            );
        }
        return Err(VEIL_ERR_REENTRANT);
    }
    Ok(())
}

/// Convenience: chain а null-pointer check for а single argument.
///
/// On null, writes а consistent error message `"<arg_name> is NULL"`
/// и returns `Err(VEIL_ERR_INVALID_ARG)`.  Usage:
///
/// ```ignore
/// match unsafe { check_not_null(err_out, "handle", handle as *const _) } {
///     Ok(()) => {}
///     Err(rc) => return rc,
/// }
/// ```
///
/// Or via the helper macro [`null_check!`] for shorter call sites.
pub(crate) unsafe fn check_not_null(
    err_out: *mut *mut c_char,
    arg_name: &'static str,
    ptr: *const std::ffi::c_void,
) -> Result<(), c_int> {
    if ptr.is_null() {
        unsafe {
            write_err(err_out, format!("{arg_name} is NULL"));
        }
        Err(VEIL_ERR_INVALID_ARG)
    } else {
        Ok(())
    }
}

/// Macro form of [`check_not_null`] that fans out across an arbitrary
/// list of `(arg_name, ptr)` pairs и `return`s early on first miss.
///
/// ```ignore
/// null_check!(err_out,
///     "handle" => handle,
///     "out_status" => out_status,
///     "out_uri" => out_uri,
/// );
/// ```
///
/// Each entry produces the equivalent of:
///
/// ```ignore
/// if let Err(rc) = unsafe { check_not_null(err_out, $name, $ptr as *const _) } {
///     return rc;
///     // — or, для fns returning а non-c_int, the macro variant
///     // null_check_with_default!(...) lets caller specify а default.
/// }
/// ```
///
/// Designed для use в `unsafe extern "C" fn` bodies where the
/// surrounding fn's return type is `c_int`.  For fns returning а
/// pointer (e.g. `veil_connect` returning `*mut VeilHandle`),
/// use [`null_check_with_default!`] instead.
#[macro_export]
macro_rules! null_check {
    ($err_out:expr, $($name:literal => $ptr:expr),+ $(,)?) => {{
        // Expand metavariables в а safe scope before reaching the
        // unsafe block — required by clippy::macro_metavars_in_unsafe
        // (would otherwise let macro users smuggle unsafe expressions
        // через the unsafe block inside the macro body).
        let err_out_ref = $err_out;
        $(
            let ptr_typed: *const _ = $ptr as *const _;
            let name_lit: &'static str = $name;
            if let Err(rc) = unsafe {
                $crate::guard::check_not_null(err_out_ref, name_lit, ptr_typed)
            } {
                return rc;
            }
        )+
    }};
}

/// Variant of [`null_check!`] для FFI fns that return а pointer
/// instead of `c_int`.  Caller supplies the default-on-null value
/// (typically `std::ptr::null_mut()`).
///
/// ```ignore
/// null_check_with_default!(err_out, std::ptr::null_mut(),
///     "socket_path" => socket_path,
/// );
/// ```
#[macro_export]
macro_rules! null_check_with_default {
    ($err_out:expr, $default:expr, $($name:literal => $ptr:expr),+ $(,)?) => {{
        // Expand metavariables в а safe scope (see [`null_check!`]).
        let err_out_ref = $err_out;
        $(
            let ptr_typed: *const _ = $ptr as *const _;
            let name_lit: &'static str = $name;
            if unsafe {
                $crate::guard::check_not_null(err_out_ref, name_lit, ptr_typed)
            }.is_err() {
                return $default;
            }
        )+
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use std::ptr;

    /// `ffi_prelude` on the main thread (not in tokio) succeeds
    /// и clears any pre-existing err_out.
    #[test]
    fn prelude_succeeds_outside_tokio() {
        let mut err: *mut c_char = std::ffi::CString::new("stale").unwrap().into_raw();
        let err_ptr: *mut *mut c_char = &mut err;
        let outcome = unsafe { ffi_prelude(err_ptr, "test_op") };
        assert!(outcome.is_ok());
        // err_out should be cleared.
        assert!(unsafe { *err_ptr }.is_null());
    }

    /// `check_not_null` on а valid pointer succeeds; on NULL it
    /// returns `INVALID_ARG` и writes а consistent message.
    #[test]
    fn null_check_writes_consistent_message() {
        let mut err: *mut c_char = ptr::null_mut();
        let err_ptr: *mut *mut c_char = &mut err;

        let valid: *const std::ffi::c_void = 0xDEAD_BEEF_usize as *const _;
        assert!(unsafe { check_not_null(err_ptr, "valid", valid) }.is_ok());

        let outcome = unsafe { check_not_null(err_ptr, "missing_arg", ptr::null()) };
        assert_eq!(outcome, Err(VEIL_ERR_INVALID_ARG));
        let msg = unsafe { CStr::from_ptr(*err_ptr) }.to_str().unwrap();
        assert_eq!(msg, "missing_arg is NULL");
        // Free the written error.
        unsafe {
            crate::veil_free_string(*err_ptr);
        }
    }
}
