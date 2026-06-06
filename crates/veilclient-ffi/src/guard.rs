//! Shared boundary helpers for FFI entry points (Phase 6.49 audit
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
//! This module consolidates that boilerplate into a single function +
//! pair of macros so every FFI fn surfaces the same diagnostic
//! strings, the same return codes, and the same reentrancy guard.
//!
//! # Migration plan
//!
//! Rollout is incremental — a complete one-shot migration would touch
//! ~40 fns with large per-fn diffs.  Instead:
//!
//! * **New FFI fns** (including any future Epic 489 / 462 work) use
//!   the helpers from day one.  See `veil_pair_*` (Epic 489.8) and
//!   `veil_create_bootstrap_invite` (Epic 489.7 generator) for
//!   reference applications.
//! * **Existing fns** get migrated opportunistically when touched
//!   for another reason — the rule "any FFI fn you edit gets ported
//!   to [`ffi_prelude`]" caps the rollout cost to fns we already
//!   touch.
//! * Pure renames / additions of FFI fns are NOT a trigger by
//!   themselves — only behavioral edits.
//!
//! Hard pre-merge gate is intentionally light: enforcing the migration
//! through CI lint would require either a custom rustc lint pass or a
//! fragile grep, and the audit findings explicitly note the original
//! pattern is "mostly cosmetic" — a forcing function makes the
//! tradeoff worse, not better.
//!
//! # Intentionally not migrated (status: closed)
//!
//! Phase 6.51 migration sweep brought the count to **26/40 fns
//! ported**.  Phase 6.50.b-followup batch added 3 new FFI fns
//! (multi-device pairing + bootstrap-invite generator + push-envelope
//! seal) which slot into the existing categorisation without changing the
//! "intentionally-not-migrated" subset.  Current count as of
//! 2026-05-21: **29/41 fns ported**.  The remaining 12 fns are
//! INTENTIONALLY NOT MIGRATED because they fall into one of four
//! categories with different semantics than the ffi_prelude pattern was
//! designed for.  Listed here so future audits don't re-open the row:
//!
//! ## Category 1 — destructors / cleanup fns (silent on null)
//!
//! These fns DO accept `NULL` as a valid value (idempotent close +
//! double-free guard) and have NO `err_out` parameter.  Adding the
//! ffi_prelude pattern would change their semantics — they are
//! expected to silently no-op on already-freed / NULL handles, NOT
//! to write a diagnostic string.
//!
//! * `veil_free_string(s: *mut c_char)` — frees a Box-allocated
//!   error string.  No err_out; silent on null.
//! * `veil_close(handle)` — drops the connection; uses the external
//!   live-handle registry double-free guard.  No err_out.
//! * `veil_app_close(app)` — same pattern, app-handle-scoped.
//! * `veil_stream_close(stream)` — same pattern, stream-scoped.
//!
//! ## Category 2 — getters without err_out
//!
//! These fns return either a sentinel value (0, NULL) or a
//! cheap-to-compute value directly; they don't have an err_out
//! parameter to populate with a diagnostic.  Adding the ffi_prelude
//! pattern would require a signature change that breaks ABI.
//!
//! * `veil_app_get_app_id(app, out) -> c_int` — copies 32 bytes;
//!   returns `VEIL_ERR_INVALID_ARG` direct on null.
//! * `veil_app_get_endpoint_id(app) -> u32` — returns 0 sentinel
//!   on null.
//!
//! ## Category 3 — trampolines to internal helpers
//!
//! These fns immediately delegate to an internal `*_inner` function
//! that DOES use ffi_prelude.  Adding the prelude to the trampoline
//! too would just run the check twice.
//!
//! * `veil_bind` → `bind_internal` (which calls ffi_prelude).
//! * `veil_bind_named` → `bind_internal`.
//! * `veil_mailbox_put` → `mailbox_put_inner`.
//!
//! ## Category 4 — pure-sync fns (no `block_on`, no daemon IPC)
//!
//! The reentrancy guard inside `ffi_prelude` exists to catch callers
//! that invoke a `block_on`-using FFI fn from inside an existing tokio
//! runtime (causes deadlock).  Pure-sync fns that do no async work
//! are not deadlock-vulnerable, so the reentrancy check is dead
//! weight.  They still call `clear_err(err_out)` + manual null checks
//! since the boilerplate that motivated the prelude (multi-line
//! diagnostic + reentrancy guard) doesn't apply.
//!
//! * `veil_seal_push_envelope` — calls
//!   `veil-anonymity::push_envelope::seal_push_envelope`
//!   (synchronous X25519 + ChaCha20-Poly1305).
//! * `veil_set_event_handler` — just stashes a callback pointer
//!   in the handle's mutex.
//! * `veil_validate_bip39_phrase` + `_zeroize` variant — invokes
//!   `veil-identity::master_seed::decode_master_seed_from_phrase`
//!   (pure BIP-39 dictionary + checksum check).
//! * `veil_restore_identity_from_phrase` + `_zeroize` +
//!   `_zeroize_with_password` variants — synchronous identity
//!   derivation + atomic disk writes.  No daemon IPC.
//! * `veil_mailbox_fetch_into` — reads cached state from a
//!   `Mutex<Option<Vec<MailboxBlob>>>` populated by the prior
//!   `veil_mailbox_fetch_count` call.  Pure-sync state pop.
//!
//! ## Re-evaluation criteria
//!
//! Open this row if any of:
//! 1. A new category-4 fn gains a `block_on` call (now needs
//!    reentrancy check).
//! 2. CI gains a custom-lint pass capable of enforcing the migration
//!    cheaply (so the "forcing function trade-off" calculation
//!    flips).
//! 3. A category-2 fn signature changes to add an err_out parameter
//!    (then prelude makes sense).

use std::ffi::c_char;
use std::os::raw::c_int;

use crate::{VEIL_ERR_INVALID_ARG, VEIL_ERR_REENTRANT, clear_err, in_tokio_runtime, write_err};

/// Outcome of [`ffi_prelude`] — either a return code the caller must
/// surface immediately, or `Ok(())` indicating safe to proceed.
pub(crate) type FfiPreludeOutcome = Result<(), c_int>;

/// Combined boundary prelude:
///
/// 1. Clears any pre-existing error string in `err_out`.
/// 2. Checks the calling thread is NOT inside a tokio runtime context
///    (those would deadlock on `block_on`).
///
/// Returns `Err(VEIL_ERR_REENTRANT)` if the reentrancy check
/// trips; the caller propagates that immediately.  Returns `Ok(())`
/// otherwise.
///
/// `op_name` is embedded in the error message ("<op_name> called from
/// inside a Tokio runtime — would deadlock") so consumers can identify
/// which FFI fn tripped.  Keep this a static literal matching the fn
/// name; doc-comment lint catches mismatches at review time.
///
/// # Safety
///
/// `err_out` may be NULL OR must point to a writable `*mut c_char`
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

/// Convenience: chain a null-pointer check for a single argument.
///
/// On null, writes a consistent error message `"<arg_name> is NULL"`
/// and returns `Err(VEIL_ERR_INVALID_ARG)`.  Usage:
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
/// list of `(arg_name, ptr)` pairs and `return`s early on first miss.
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
///     // — or, for fns returning a non-c_int, the macro variant
///     // null_check_with_default!(...) lets caller specify a default.
/// }
/// ```
///
/// Designed for use in `unsafe extern "C" fn` bodies where the
/// surrounding fn's return type is `c_int`.  For fns returning a
/// pointer (e.g. `veil_connect` returning `*mut VeilHandle`),
/// use [`null_check_with_default!`] instead.
#[macro_export]
macro_rules! null_check {
    ($err_out:expr, $($name:literal => $ptr:expr),+ $(,)?) => {{
        // Expand metavariables in a safe scope before reaching the
        // unsafe block — required by clippy::macro_metavars_in_unsafe
        // (would otherwise let macro users smuggle unsafe expressions
        // through the unsafe block inside the macro body).
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

/// Variant of [`null_check!`] for FFI fns that return a pointer
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
        // Expand metavariables in a safe scope (see [`null_check!`]).
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
    /// and clears any pre-existing err_out.
    #[test]
    fn prelude_succeeds_outside_tokio() {
        let mut err: *mut c_char = std::ffi::CString::new("stale").unwrap().into_raw();
        let err_ptr: *mut *mut c_char = &mut err;
        let outcome = unsafe { ffi_prelude(err_ptr, "test_op") };
        assert!(outcome.is_ok());
        // err_out should be cleared.
        assert!(unsafe { *err_ptr }.is_null());
    }

    /// `check_not_null` on a valid pointer succeeds; on NULL it
    /// returns `INVALID_ARG` and writes a consistent message.
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
