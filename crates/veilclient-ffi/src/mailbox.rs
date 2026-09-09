//! The mailbox: leaving something for a device that is not listening.
//!
//! Deposit, seal, open, count, fetch, ack — the whole offline path, plus the
//! status codes a caller has to branch on. They belong together because the
//! codes are the contract: a PUT can be refused for a quota, a rate limit, a
//! missing capability token or an invalid one, and a caller that collapses
//! those into "failed" cannot tell a full mailbox from a rejected credential.
//!
//! Moved verbatim out of `lib.rs` (report24 RUNTIME-3), declared `pub mod`
//! so cbindgen still exports every declaration; the generated header is
//! reordered by the move and its SHA-256 — the ABI contract hash — moves
//! with it. Nothing is added or removed.

use super::*;

// ── Mailbox put/fetch/ack ────────────────

/// Status return codes [`veil_mailbox_put`]. Mirrors
/// `MailboxPutStatus` on the wire (0..8 byte).
pub const VEIL_MAILBOX_PUT_STORED: c_int = 0;
pub const VEIL_MAILBOX_PUT_DUPLICATE: c_int = 1;
pub const VEIL_MAILBOX_PUT_QUOTA_PER_RECEIVER: c_int = 2;
pub const VEIL_MAILBOX_PUT_QUOTA_GLOBAL: c_int = 3;
pub const VEIL_MAILBOX_PUT_RATE_LIMITED: c_int = 4;
pub const VEIL_MAILBOX_PUT_NOT_RELAY: c_int = 5;
/// relay configured with
/// `require_capability_token = true` rejected a PUT that arrived
/// without a capability token.
pub const VEIL_MAILBOX_PUT_CAPABILITY_REQUIRED: c_int = 6;
/// capability token decode or verify
/// failed (expired, wrong receiver, or bad signature).
pub const VEIL_MAILBOX_PUT_CAPABILITY_INVALID: c_int = 7;
/// per-sender byte cap exceeded.
pub const VEIL_MAILBOX_PUT_QUOTA_PER_SENDER: c_int = 8;

/// Deposit `blob` for an offline `receiver_id` at the daemon's mailbox
///. No `auth_cookie` required.
///
/// `push_envelope` / `push_envelope_len` are optional (pass NULL / 0
/// to skip). When supplied and storage succeeds, the relay fires a
/// wake-push to the receiver after this call returns.
///
/// Returns one of `VEIL_MAILBOX_PUT_*` (≥0) on a structured outcome
/// or a negative `VEIL_ERR_*` on transport / argument errors.
/// `out_evicted` (may be NULL) receives the count of older blobs the
/// relay had to evict to fit (only nonzero on `VEIL_MAILBOX_PUT_STORED`).
///
/// # Safety
/// `handle` must be a live `VeilHandle*` from `veil_connect`.
/// `receiver_id`, `content_id`, `sender_id` must each point to ≥32
/// readable bytes. `blob` must point to ≥`blob_len` readable bytes
/// (or NULL if `blob_len == 0`). `push_envelope` must point to
/// ≥`push_envelope_len` readable bytes (or NULL if 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_mailbox_put(
    handle: *mut VeilHandle,
    receiver_id: *const u8,
    content_id: *const u8,
    sender_id: *const u8,
    blob: *const u8,
    blob_len: size_t,
    push_envelope: *const u8,
    push_envelope_len: size_t,
    out_evicted: *mut u32,
    err_out: *mut *mut c_char,
) -> c_int {
    // Forwards to the shared body with `capability_token = None` and
    // `wake_hmac_envelope = None`. For relays running with
    // `require_capability_token = true` the daemon will reply
    // `CAPABILITY_REQUIRED` (status 6); callers that have a token should
    // use [`veil_mailbox_put_with_capability`].  Callers that forward
    // the receiver's sealed wake-HMAC envelope should use
    // [`veil_mailbox_put_with_wake_hmac`].
    unsafe {
        mailbox_put_inner(
            handle,
            receiver_id,
            content_id,
            sender_id,
            blob,
            blob_len,
            push_envelope,
            push_envelope_len,
            ptr::null(),
            0,
            ptr::null(),
            0,
            out_evicted,
            err_out,
        )
    }
}

/// `veil_mailbox_put` variant that forwards
/// a receiver-signed capability token. Required when targeting a
/// relay running with `MailboxConfig::require_capability_token = true`.
///
/// `capability_token` / `capability_token_len` are the bytes obtained
/// from the receiver's `RendezvousAd` (surfaced on the SDK side as
/// `RendezvousReplicaInfo::capability_token`). Pass `NULL` / `0` to
/// fall back to the no-token path (equivalent to calling the original
/// `veil_mailbox_put`). Maximum length is
/// [`veilclient::MAX_MAILBOX_CAPABILITY_TOKEN_BYTES`].
///
/// All other parameters and safety contracts are identical to
/// [`veil_mailbox_put`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_mailbox_put_with_capability(
    handle: *mut VeilHandle,
    receiver_id: *const u8,
    content_id: *const u8,
    sender_id: *const u8,
    blob: *const u8,
    blob_len: size_t,
    push_envelope: *const u8,
    push_envelope_len: size_t,
    capability_token: *const u8,
    capability_token_len: size_t,
    out_evicted: *mut u32,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe {
        mailbox_put_inner(
            handle,
            receiver_id,
            content_id,
            sender_id,
            blob,
            blob_len,
            push_envelope,
            push_envelope_len,
            capability_token,
            capability_token_len,
            ptr::null(),
            0,
            out_evicted,
            err_out,
        )
    }
}

/// `veil_mailbox_put` variant that forwards BOTH a receiver-signed
/// capability token AND the receiver's sealed wake-HMAC envelope (Epic
/// 489.10 slice 4.3.4).  This is the export a mobile sender uses to
/// forward the wake-HMAC envelope so the relay can mint a receiver-
/// verifiable wake-HMAC tag on the push.
///
/// `capability_token` / `capability_token_len` are as in
/// [`veil_mailbox_put_with_capability`] (pass `NULL` / `0` to skip).
///
/// `wake_hmac_envelope` / `wake_hmac_envelope_len` are the bytes the
/// receiver published in its `RendezvousAd` (surfaced SDK-side as
/// `RendezvousReplicaInfo::wake_hmac_envelope` and returned over the C
/// ABI by [`veil_lookup_rendezvous_replicas`]).  Pass `NULL` / `0`
/// to fall back to an unauthenticated wake (equivalent to
/// [`veil_mailbox_put_with_capability`]).  Maximum length is
/// [`veilclient::MAX_WAKE_HMAC_ENVELOPE_BYTES`]; overflow returns
/// `VEIL_ERR_INVALID_ARG`.
///
/// All other parameters and safety contracts are identical to
/// [`veil_mailbox_put`].  `wake_hmac_envelope` MUST point to
/// ≥`wake_hmac_envelope_len` readable bytes (or NULL if 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_mailbox_put_with_wake_hmac(
    handle: *mut VeilHandle,
    receiver_id: *const u8,
    content_id: *const u8,
    sender_id: *const u8,
    blob: *const u8,
    blob_len: size_t,
    push_envelope: *const u8,
    push_envelope_len: size_t,
    capability_token: *const u8,
    capability_token_len: size_t,
    wake_hmac_envelope: *const u8,
    wake_hmac_envelope_len: size_t,
    out_evicted: *mut u32,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe {
        mailbox_put_inner(
            handle,
            receiver_id,
            content_id,
            sender_id,
            blob,
            blob_len,
            push_envelope,
            push_envelope_len,
            capability_token,
            capability_token_len,
            wake_hmac_envelope,
            wake_hmac_envelope_len,
            out_evicted,
            err_out,
        )
    }
}

/// Shared implementation for `veil_mailbox_put`,
/// `veil_mailbox_put_with_capability` and
/// `veil_mailbox_put_with_wake_hmac`.
///
/// # Safety
/// All pointer / length contracts from the public wrappers apply. This
/// helper is `unsafe` because it dereferences caller pointers; the
/// public wrappers re-document the safety surface explicitly.
#[allow(clippy::too_many_arguments)]
unsafe fn mailbox_put_inner(
    handle: *mut VeilHandle,
    receiver_id: *const u8,
    content_id: *const u8,
    sender_id: *const u8,
    blob: *const u8,
    blob_len: size_t,
    push_envelope: *const u8,
    push_envelope_len: size_t,
    capability_token: *const u8,
    capability_token_len: size_t,
    wake_hmac_envelope: *const u8,
    wake_hmac_envelope_len: size_t,
    out_evicted: *mut u32,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_mailbox_put_with_capability") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "receiver_id" => receiver_id,
        "content_id" => content_id,
        "sender_id" => sender_id,
    );
    if blob.is_null() && blob_len > 0 {
        unsafe {
            write_err(err_out, "blob is null but blob_len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if push_envelope.is_null() && push_envelope_len > 0 {
        unsafe {
            write_err(err_out, "push_envelope is null but push_envelope_len > 0");
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if capability_token.is_null() && capability_token_len > 0 {
        unsafe {
            write_err(
                err_out,
                "capability_token is null but capability_token_len > 0",
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if wake_hmac_envelope.is_null() && wake_hmac_envelope_len > 0 {
        unsafe {
            write_err(
                err_out,
                "wake_hmac_envelope is null but wake_hmac_envelope_len > 0",
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    // cap pre-allocation so that
    // a huge caller-supplied len cannot OOM the process before the
    // mailbox-layer quota check fires. Backend caps exist
    // (MAX_MAILBOX_BLOB_BYTES = 1 MiB, MAX_PUSH_ENVELOPE_BYTES =
    // 512 B), but they're enforced AFTER the slice→Vec copy here.
    // Reject up-front to avoid the copy.
    if blob_len > veilclient::MAX_MAILBOX_BLOB_BYTES {
        unsafe {
            write_err(
                err_out,
                format!(
                    "mailbox_put blob_len {blob_len} exceeds MAX_MAILBOX_BLOB_BYTES ({})",
                    veilclient::MAX_MAILBOX_BLOB_BYTES,
                ),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if push_envelope_len > veilclient::MAX_PUSH_ENVELOPE_BYTES {
        unsafe {
            write_err(
                err_out,
                format!(
                    "mailbox_put push_envelope_len {push_envelope_len} exceeds MAX_PUSH_ENVELOPE_BYTES ({})",
                    veilclient::MAX_PUSH_ENVELOPE_BYTES,
                ),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if capability_token_len > veilclient::MAX_MAILBOX_CAPABILITY_TOKEN_BYTES {
        unsafe {
            write_err(
                err_out,
                format!(
                    "mailbox_put capability_token_len {capability_token_len} exceeds MAX_MAILBOX_CAPABILITY_TOKEN_BYTES ({})",
                    veilclient::MAX_MAILBOX_CAPABILITY_TOKEN_BYTES,
                ),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    if wake_hmac_envelope_len > veilclient::MAX_WAKE_HMAC_ENVELOPE_BYTES {
        unsafe {
            write_err(
                err_out,
                format!(
                    "mailbox_put wake_hmac_envelope_len {wake_hmac_envelope_len} exceeds MAX_WAKE_HMAC_ENVELOPE_BYTES ({})",
                    veilclient::MAX_WAKE_HMAC_ENVELOPE_BYTES,
                ),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    let mut recv_arr = [0u8; 32];
    let mut content_arr = [0u8; 32];
    let mut sender_arr = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(receiver_id, recv_arr.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(content_id, content_arr.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(sender_id, sender_arr.as_mut_ptr(), 32);
    }
    let blob_vec: Vec<u8> = if blob_len == 0 {
        Vec::new()
    } else {
        let slice = unsafe { std::slice::from_raw_parts(blob, blob_len) };
        slice.to_vec()
    };
    let envelope_opt: Option<Vec<u8>> = if push_envelope_len == 0 {
        None
    } else {
        let slice = unsafe { std::slice::from_raw_parts(push_envelope, push_envelope_len) };
        Some(slice.to_vec())
    };
    let capability_opt: Option<Vec<u8>> = if capability_token_len == 0 {
        None
    } else {
        let slice = unsafe { std::slice::from_raw_parts(capability_token, capability_token_len) };
        Some(slice.to_vec())
    };
    let wake_hmac_opt: Option<Vec<u8>> = if wake_hmac_envelope_len == 0 {
        None
    } else {
        let slice =
            unsafe { std::slice::from_raw_parts(wake_hmac_envelope, wake_hmac_envelope_len) };
        Some(slice.to_vec())
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
        client
            .mailbox_put(
                recv_arr,
                content_arr,
                sender_arr,
                blob_vec,
                envelope_opt,
                capability_opt,
                // .10 slice 4.3.4: forward the receiver's sealed wake-HMAC
                // envelope (surfaced SDK-side as
                // `RendezvousReplicaInfo::wake_hmac_envelope`) so the relay can
                // mint a receiver-verifiable wake-HMAC tag.  `None` when the
                // caller passed NULL / 0 — relay falls back to an
                // unauthenticated wake.  Reachable with the wake bytes only via
                // [`veil_mailbox_put_with_wake_hmac`]; the two legacy
                // exports forward `(NULL, 0)` here for ABI back-compat.
                wake_hmac_opt,
            )
            .await
    });
    match res {
        Ok(reply) => {
            if !out_evicted.is_null() {
                unsafe {
                    *out_evicted = reply.evicted;
                }
            }
            reply.status as u8 as c_int
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("mailbox_put failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Seal `data` for `recipient`'s `(app_id, endpoint_id)` into an offline-mailbox
/// blob (node-side E2E crypto: sign + DHT-resolve the recipient cert +
/// fan-out-encrypt). On success returns [`VEIL_OK`] and writes a heap-allocated
/// buffer to `*out_buf` (its length to `*out_len`); free it with
/// [`veil_free_buf`]. On error returns a negative `VEIL_ERR_*`, sets `*err_out`,
/// and leaves `*out_buf = NULL` / `*out_len = 0`.
///
/// `recipient` and `app_id` MUST point to ≥32 readable bytes; `data` to
/// ≥`data_len` (may be NULL iff `data_len == 0`). `out_buf` / `out_len` MUST be
/// valid writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_mailbox_seal(
    handle: *mut VeilHandle,
    recipient: *const u8,
    app_id: *const u8,
    endpoint_id: u32,
    data: *const u8,
    data_len: size_t,
    out_buf: *mut *mut u8,
    out_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_mailbox_seal") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "recipient" => recipient,
        "app_id" => app_id,
        "out_buf" => out_buf,
        "out_len" => out_len,
    );
    unsafe {
        *out_buf = ptr::null_mut();
        *out_len = 0;
    }
    let mut recipient_arr = [0u8; 32];
    let mut app_id_arr = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(recipient, recipient_arr.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(app_id, app_id_arr.as_mut_ptr(), 32);
    }
    let payload: Vec<u8> = if data_len == 0 {
        Vec::new()
    } else {
        null_check!(err_out, "data" => data);
        unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec()
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
        client
            .mailbox_seal(recipient_arr, app_id_arr, endpoint_id, payload)
            .await
    });
    match res {
        Ok(blob) => {
            let boxed: Box<[u8]> = blob.into_boxed_slice();
            let len = boxed.len();
            let p = Box::into_raw(boxed) as *mut u8;
            unsafe {
                *out_buf = p;
                *out_len = len;
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("mailbox_seal failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Open + verify a fetched offline-mailbox `blob`, decrypting under our current
/// cert version `our_cert_version`. The sender is RECOVERED from the blob's
/// sidecar (the anonymous mailbox deposit carries no usable wire sender) and,
/// once crypto-verified, written to `out_sender` (32 bytes). On success returns
/// [`VEIL_OK`], writes the verified destination app id to `out_app_id` (32 bytes)
/// and the endpoint id to `*out_endpoint_id`. A heap-allocated data buffer is written
/// to `*out_data` (length to `*out_data_len`); free with [`veil_free_buf`].
///
/// `blob` MUST point to ≥`blob_len`. `out_sender` / `out_app_id` MUST each point
/// to ≥32 writable bytes; the other out-pointers MUST be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_mailbox_open(
    handle: *mut VeilHandle,
    our_cert_version: u64,
    blob: *const u8,
    blob_len: size_t,
    out_sender: *mut u8,
    out_app_id: *mut u8,
    out_endpoint_id: *mut u32,
    out_data: *mut *mut u8,
    out_data_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_mailbox_open") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_sender" => out_sender,
        "out_app_id" => out_app_id,
        "out_endpoint_id" => out_endpoint_id,
        "out_data" => out_data,
        "out_data_len" => out_data_len,
    );
    unsafe {
        *out_data = ptr::null_mut();
        *out_data_len = 0;
        *out_endpoint_id = 0;
    }
    let blob_vec: Vec<u8> = if blob_len == 0 {
        Vec::new()
    } else {
        null_check!(err_out, "blob" => blob);
        unsafe { std::slice::from_raw_parts(blob, blob_len) }.to_vec()
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
        client.mailbox_open(blob_vec, our_cert_version).await
    });
    match res {
        Ok((sender_id, app_id, endpoint_id, data)) => {
            let boxed: Box<[u8]> = data.into_boxed_slice();
            let len = boxed.len();
            let p = Box::into_raw(boxed) as *mut u8;
            unsafe {
                ptr::copy_nonoverlapping(sender_id.as_ptr(), out_sender, 32);
                ptr::copy_nonoverlapping(app_id.as_ptr(), out_app_id, 32);
                *out_endpoint_id = endpoint_id;
                *out_data = p;
                *out_data_len = len;
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("mailbox_open failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Fetch all blobs currently stored for `receiver_id`. `auth_cookie`
/// must match a previously-registered rendezvous-publisher entry.
///
/// On success returns ≥0 (the count of blobs returned) and populates
/// `out_blobs` (allocated via `veil_mailbox_blobs_alloc`-style
/// caller-managed buffer). Apps fetch blobs into a length-aware
/// container by calling [`veil_mailbox_fetch_count`] first to size
/// their array, then [`veil_mailbox_fetch_into`] to copy.
///
/// Two-call API avoids hidden allocations through the FFI boundary —
/// callers control all memory lifetimes.
///
/// # Safety
/// `handle`, `receiver_id` (32 B), `auth_cookie` (16 B), `out_count`
/// must all be valid pointers. `out_count` receives the count.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_mailbox_fetch_count(
    handle: *mut VeilHandle,
    receiver_id: *const u8,
    auth_cookie: *const u8,
    out_count: *mut u32,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_mailbox_fetch_count") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "receiver_id" => receiver_id,
        "auth_cookie" => auth_cookie,
        "out_count" => out_count,
    );
    let mut recv_arr = [0u8; 32];
    let mut cookie_arr = [0u8; 16];
    unsafe {
        ptr::copy_nonoverlapping(receiver_id, recv_arr.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(auth_cookie, cookie_arr.as_mut_ptr(), 16);
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
        client.mailbox_fetch(recv_arr, cookie_arr).await
    });
    match res {
        Ok(blobs) => {
            // Stash the result on the handle for the next _into call.
            // Single-shot: the handle holds at most one pending fetch
            // result. A second fetch_count overwrites it.
            //
            // Mutex poison recovery: this is a FFI boundary — a panic
            // here would unwind across the `extern "C"` ABI and trigger
            // UB on the C-side caller (mobile SDK / chat_node). If
            // the mutex is poisoned (a previous holder panicked), we
            // adopt the inner state and continue; the stored value is
            // about to be overwritten anyway so that poison is harmless.
            let count = blobs.len();
            let mut pending = match bundle.pending_mailbox_fetch.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            *pending = Some(blobs);
            unsafe {
                *out_count = count as u32;
            }
            VEIL_OK
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("mailbox_fetch_count failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Mailbox blob descriptor returned by [`veil_mailbox_fetch_into`].
/// `blob` is a borrow into a buffer the caller provided to the fetch
/// call; valid until the caller frees that buffer.
#[repr(C)]
pub struct VeilMailboxBlob {
    pub sender_id: [u8; 32],
    pub content_id: [u8; 32],
    pub deposited_at: u64,
    /// Pointer into caller-provided `blob_buf` (NOT separately allocated).
    pub blob: *const u8,
    pub blob_len: u32,
    pub _reserved: u32,
}

/// Copy the most-recently-fetched blob list (cached by
/// [`veil_mailbox_fetch_count`]) into caller-provided buffers.
///
/// `descriptors_out` must point to ≥`max_descriptors` `VeilMailboxBlob`
/// slots. `blob_buf` is a contiguous byte buffer where blob payloads
/// are concatenated; descriptors' `blob` pointers index into it.
/// `blob_buf_len` must be ≥ sum of all blob_len; if too small, returns
/// `VEIL_ERR_INVALID_ARG` and the cached fetch list is kept (caller
/// can re-call with a larger buffer without re-fetching).
///
/// On success returns the count of descriptors written and clears the
/// cache.
///
/// # Safety
/// All output pointers must be writable for at least the documented
/// extents. After this call, the descriptor `blob` pointers are valid
/// only as long as `blob_buf` is alive and unmodified.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_mailbox_fetch_into(
    handle: *mut VeilHandle,
    descriptors_out: *mut VeilMailboxBlob,
    max_descriptors: u32,
    blob_buf: *mut u8,
    blob_buf_len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    unsafe {
        clear_err(err_out);
    }
    if handle.is_null() || descriptors_out.is_null() || blob_buf.is_null() {
        unsafe {
            write_err(err_out, "null pointer argument");
        }
        return VEIL_ERR_INVALID_ARG;
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
    // Mutex poison recovery: see fetch_count for rationale — FFI panic
    // = UB on C-side. Adopt poisoned inner state and continue.
    let mut pending = match bundle.pending_mailbox_fetch.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let Some(blobs) = pending.take() else {
        unsafe {
            write_err(
                err_out,
                "no fetch result cached — call veil_mailbox_fetch_count first",
            );
        }
        return VEIL_ERR;
    };
    // Audit cycle-5 (FFI): fail (and restore the cache) when the caller supplies
    // fewer descriptor slots than the cached result holds, instead of silently
    // writing a prefix and discarding the rest. The required count came from a
    // prior veil_mailbox_fetch_count, so an undersized max_descriptors is a
    // caller error — mirror the blob_buf-too-small path below so the result is
    // not lost. The Dart wrapper always passes the queried count; this guards
    // direct C callers.
    if (max_descriptors as usize) < blobs.len() {
        let need = blobs.len();
        *pending = Some(blobs);
        unsafe {
            write_err(
                err_out,
                format!("max_descriptors too small: need {need}, got {max_descriptors}"),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    let total_bytes: usize = blobs.iter().map(|b| b.blob.len()).sum();
    let count = blobs.len();
    if total_bytes > blob_buf_len {
        // Restore cache so caller can retry with larger buffer.
        *pending = Some(blobs);
        unsafe {
            write_err(
                err_out,
                format!("blob_buf too small: need {total_bytes}, got {blob_buf_len}",),
            );
        }
        return VEIL_ERR_INVALID_ARG;
    }
    let mut offset = 0usize;
    for (i, b) in blobs.iter().take(count).enumerate() {
        let dst_ptr = unsafe { blob_buf.add(offset) };
        if !b.blob.is_empty() {
            unsafe {
                ptr::copy_nonoverlapping(b.blob.as_ptr(), dst_ptr, b.blob.len());
            }
        }
        let descriptor = VeilMailboxBlob {
            sender_id: b.sender_id,
            content_id: b.content_id,
            deposited_at: b.deposited_at,
            blob: dst_ptr as *const u8,
            blob_len: b.blob.len() as u32,
            _reserved: 0,
        };
        unsafe {
            ptr::write(descriptors_out.add(i), descriptor);
        }
        offset += b.blob.len();
    }
    count as c_int
}

/// Acknowledge end-to-end receipt of a mailbox blob. Daemon deletes
/// the blob and frees its quota slice. Idempotent.
///
/// Returns 1 if the blob was removed, 0 if no-op (already acked /
/// not present / wrong cookie), or negative on transport error.
///
/// # Safety
/// `handle` must be a live `VeilHandle*`; `receiver_id` (32 B)
/// `content_id` (32 B), `auth_cookie` (16 B) must point to readable
/// storage of at least the documented length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_mailbox_ack(
    handle: *mut VeilHandle,
    receiver_id: *const u8,
    content_id: *const u8,
    auth_cookie: *const u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_mailbox_ack") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "receiver_id" => receiver_id,
        "content_id" => content_id,
        "auth_cookie" => auth_cookie,
    );
    let mut recv_arr = [0u8; 32];
    let mut content_arr = [0u8; 32];
    let mut cookie_arr = [0u8; 16];
    unsafe {
        ptr::copy_nonoverlapping(receiver_id, recv_arr.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(content_id, content_arr.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(auth_cookie, cookie_arr.as_mut_ptr(), 16);
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
        client.mailbox_ack(recv_arr, content_arr, cookie_arr).await
    });
    match res {
        Ok(removed) => {
            if removed {
                1
            } else {
                0
            }
        }
        Err(e) => {
            unsafe {
                write_err(err_out, format!("mailbox_ack failed: {e}"));
            }
            VEIL_ERR
        }
    }
}
