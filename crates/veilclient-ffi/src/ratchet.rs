//! The half of a conversation veil does not keep.
//!
//! A one-to-one conversation is a Double Ratchet, and a Double Ratchet is
//! state: chain keys that advance one way, message keys banked for frames
//! that arrived out of order, an outstanding encapsulation. None of it can be
//! rebuilt from anything public — that is what forward secrecy means — and
//! none of it can be kept by veil, whose only database belongs to the mailbox.
//! So the host keeps it, and these are the calls it keeps it through.
//!
//! Moved verbatim out of `lib.rs` (report24 RUNTIME-3), declared `pub mod`
//! so cbindgen still exports every declaration: a PRIVATE module makes it
//! skip `pub` items it finds there, which silently dropped the `VEIL_JOIN_*`
//! constants from the header the first time this was tried.
//!
//! The generated header is reordered by the move and its SHA-256 — the ABI
//! contract hash — changes with it. Nothing is added or removed: the header
//! before and after hold the same multiset of lines.

// Named one by one rather than through `use super::*`. The glob worked, but
// the only thing it was still providing was the `#[macro_export]`ed
// `null_check!` — which the unused-import lint cannot see through a glob, so
// the whole import read as dead and `-D warnings` refused the build. Naming
// them says what this module actually depends on.
// Every item in this module is `node-embedded`-only, so every import is too.
//
// `use super::*` hid that: a glob names whatever happens to be there, so the
// default-feature build never had to agree with the all-features one. Naming
// them turned the disagreement into a compile error the moment it appeared,
// which is how `embedded_services_for_bundle` — a helper that exists only
// with the in-process node compiled in — was caught here rather than in CI.
#[cfg(feature = "node-embedded")]
use std::ptr;
#[cfg(feature = "node-embedded")]
use std::sync::Arc;

#[cfg(feature = "node-embedded")]
use libc::{c_char, c_int, size_t};

#[cfg(feature = "node-embedded")]
use crate::null_check;
#[cfg(feature = "node-embedded")]
use crate::{
    RuntimeBundle, VEIL_ERR, VEIL_ERR_INVALID_ARG, VEIL_OK, VeilHandle,
    embedded_services_for_bundle, guard, handle_table, write_err,
};

// ── Ratchet state: the half of the conversation veil does not keep ──────────
//
// A one-to-one conversation is a Double Ratchet, and a Double Ratchet is
// state: chain keys that advance one way, message keys banked for frames that
// arrived out of order, an outstanding key encapsulation. None of it can be
// rebuilt from anything public — that is the point of forward secrecy — and
// none of it can be kept by veil, whose only database belongs to the mailbox
// and is reachable from neither the send path nor the frame dispatcher.
//
// So the host keeps it, and in this project the host is xVeil and the store is
// the hidden volume. That makes durability a contract with a silent failure
// mode: a write the host skips is a message key nobody has, and the message
// that needed it never opens and never says why. Hence the shape of this API —
// a version that advances on every committed operation, and a list that names
// exactly which conversations changed. The host writes what the list names
// before it treats a send or a receive as done.
//
// The addressing is [`VEIL_RATCHET_KEY_LEN`] bytes:
// `local_instance_id(16) ‖ peer_node_id(32) ‖ peer_instance_id(16)`. Flat and
// reversible on purpose: a host removing a device or forgetting a contact
// decides what to drop by reading the key, with no side table mapping opaque
// digests back to peers. Nothing in it is secret — all three identifiers
// already travel on the wire.

/// Byte length of a conversation key.
#[cfg(feature = "node-embedded")]
pub const VEIL_RATCHET_KEY_LEN: size_t = 64;

/// Upper bound on one conversation's exported state.
///
/// An established session is about 1.4 kB; the rest is the skipped-message-key
/// cache, at 68 bytes per key banked for a frame that has not arrived yet, and
/// the ratchet caps that. A host sizing a buffer to this never sees a short
/// write.
#[cfg(feature = "node-embedded")]
pub const VEIL_RATCHET_MAX_STATE_LEN: size_t = 256 * 1024;

/// Returned when a conversation key names nothing this node holds.
#[cfg(feature = "node-embedded")]
pub const VEIL_ERR_RATCHET_NO_CONVERSATION: c_int = -20;

/// Returned when the caller's buffer is too small for the conversation's state.
/// Nothing was written and nothing was consumed; retry with a larger buffer.
#[cfg(feature = "node-embedded")]
pub const VEIL_ERR_RATCHET_BUFFER_TOO_SMALL: c_int = -21;

/// Returned when the store is at [`VEIL_RATCHET_MAX_CONVERSATIONS`] and every
/// conversation held is one this device has spoken on, so none can be dropped
/// without permanently stranding it and its peer.
///
/// Distinct from a malformed argument because the remedy is different and
/// belongs to the host: forget conversations the user no longer wants. It is
/// not reachable by a peer — everything a stranger can plant is unproven, and
/// unproven conversations are exactly what the quota evicts on its own.
#[cfg(feature = "node-embedded")]
pub const VEIL_ERR_RATCHET_STORE_FULL: c_int = -22;

/// Most conversations one device holds at once, and so the most
/// [`veil_ratchet_list_page`] can ever walk.
///
/// Spelled as a literal because cbindgen emits `#define`s only for literals: a
/// `= veil_e2e::MAX_CONVERSATIONS` here compiles perfectly well and then simply
/// does not appear in the header, which is the same "header drifts from
/// lib.rs" failure the regeneration gate exists to stop — except that a
/// MISSING constant produces no diff for the gate to catch. The assertion
/// below is what keeps the literal honest: move the store's ceiling without
/// moving this and the build stops here rather than shipping two numbers.
#[cfg(feature = "node-embedded")]
pub const VEIL_RATCHET_MAX_CONVERSATIONS: size_t = 1024;

#[cfg(feature = "node-embedded")]
const _: () = assert!(
    VEIL_RATCHET_MAX_CONVERSATIONS == veil_e2e::MAX_CONVERSATIONS,
    "VEIL_RATCHET_MAX_CONVERSATIONS drifted from veil_e2e::MAX_CONVERSATIONS"
);

/// Most conversation keys one [`veil_ratchet_ack_dirty`] call may name.
///
/// A host acknowledges what it peeked, so this is far above any real batch. It
/// exists because the count decides how many bytes are read from the caller's
/// buffer, and a bogus one must be refused rather than followed.
#[cfg(feature = "node-embedded")]
pub const VEIL_RATCHET_MAX_ACK_KEYS: size_t = 4096;

#[cfg(feature = "node-embedded")]
fn ratchet_for_bundle(bundle: &Arc<RuntimeBundle>) -> Result<veil_e2e::RatchetRuntime, String> {
    let services = embedded_services_for_bundle(bundle)?;
    services
        .dispatcher
        .crypto
        .ratchet
        .clone()
        .ok_or_else(|| "this node runs no ratchet".to_string())
}

/// Read a caller-supplied conversation key.
#[cfg(feature = "node-embedded")]
unsafe fn ratchet_key_from(key_64: *const u8) -> veil_e2e::ConversationKey {
    let mut raw = [0u8; 64];
    unsafe { ptr::copy_nonoverlapping(key_64, raw.as_mut_ptr(), 64) };
    veil_e2e::ConversationKey::from_storage_key(&raw)
}

/// Write conversation keys into `out_buf`, returning how many were written.
#[cfg(feature = "node-embedded")]
unsafe fn write_conversation_keys(
    keys: &[veil_e2e::ConversationKey],
    out_buf: *mut u8,
    out_buf_cap: size_t,
) -> size_t {
    let room = out_buf_cap / VEIL_RATCHET_KEY_LEN;
    let n = room.min(keys.len());
    for (i, key) in keys.iter().take(n).enumerate() {
        let bytes = key.storage_key();
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf.add(i * VEIL_RATCHET_KEY_LEN), 64);
        }
    }
    n
}

/// Read `count` conversation keys out of a caller-supplied buffer.
///
/// # Safety
///
/// `keys` MUST point to `count * VEIL_RATCHET_KEY_LEN` readable bytes.
#[cfg(feature = "node-embedded")]
unsafe fn read_conversation_keys(keys: *const u8, count: size_t) -> Vec<veil_e2e::ConversationKey> {
    (0..count)
        .map(|i| unsafe { ratchet_key_from(keys.add(i * VEIL_RATCHET_KEY_LEN)) })
        .collect()
}

/// How many ratchet operations this node has committed since it started.
///
/// Monotonic, never reset, and moved only by work that actually completed — a
/// forged frame that failed its tag moves nothing. A host that samples this
/// can tell "no conversation changed" from "one changed and I read it twice",
/// which a dirty list alone cannot say.
///
/// # Safety
///
/// `handle` must be a live handle. `out_version` MUST be writable.
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_ratchet_state_version(
    handle: *mut VeilHandle,
    out_version: *mut u64,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_ratchet_state_version") } {
        return rc;
    }
    null_check!(err_out, "handle" => handle, "out_version" => out_version);
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    match ratchet_for_bundle(&handle_live.bundle) {
        Ok(ratchet) => {
            unsafe { *out_version = ratchet.store.version() };
            VEIL_OK
        }
        Err(e) => {
            unsafe { write_err(err_out, e) };
            VEIL_ERR
        }
    }
}

/// Name up to `out_buf_cap / VEIL_RATCHET_KEY_LEN` conversations waiting to be
/// persisted, WITHOUT clearing anything.
///
/// `*out_written` receives how many keys were written — a COUNT OF KEYS, not a
/// byte length. `*out_remaining` receives how many are still waiting beyond
/// them, so a host with a small buffer loops until it reads zero.
/// `*out_generation` receives the store's version at the moment of the read,
/// and is what the host hands to [`veil_ratchet_ack_dirty`].
///
/// The host's contract is peek, persist, THEN acknowledge, and it must persist
/// before it treats the send or receive that produced the change as complete.
/// Reading the list is deliberately not what discharges the obligation: between
/// here and a durable write there is an export, a worker hop and a commit, and
/// a failure at any of them would otherwise lose the only notice these
/// conversations get until they change again.
///
/// # Safety
///
/// `handle` must be live. `out_buf` MUST be writable for `out_buf_cap` bytes.
/// `out_written`, `out_remaining` and `out_generation` MUST be writable.
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_ratchet_peek_dirty(
    handle: *mut VeilHandle,
    out_buf: *mut u8,
    out_buf_cap: size_t,
    out_written: *mut size_t,
    out_remaining: *mut size_t,
    out_generation: *mut u64,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_ratchet_peek_dirty") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_buf" => out_buf,
        "out_written" => out_written,
        "out_remaining" => out_remaining,
        "out_generation" => out_generation,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let ratchet = match ratchet_for_bundle(&handle_live.bundle) {
        Ok(r) => r,
        Err(e) => {
            unsafe { write_err(err_out, e) };
            return VEIL_ERR;
        }
    };
    let room = out_buf_cap / VEIL_RATCHET_KEY_LEN;
    let (named, generation) = ratchet.store.peek_dirty(room);
    let written = unsafe { write_conversation_keys(&named, out_buf, out_buf_cap) };
    unsafe {
        *out_written = written;
        *out_remaining = ratchet.store.dirty_len().saturating_sub(written);
        *out_generation = generation;
    }
    VEIL_OK
}

/// Clear the marks of `key_count` conversations whose state is now durable.
///
/// `generation` is the value [`veil_ratchet_peek_dirty`] reported for the read
/// these keys came from. A conversation that has changed since was re-marked at
/// a later generation and KEEPS its mark: the bytes the host just wrote do not
/// contain that change, and clearing it would discard the only notice it gets.
/// `*out_cleared` receives how many marks were actually cleared, which is how a
/// host sees that a conversation moved under it.
///
/// Acknowledging a conversation nobody marked is not an error.
///
/// Returns [`VEIL_ERR_INVALID_ARG`] when `key_count` exceeds
/// [`VEIL_RATCHET_MAX_ACK_KEYS`], in which case nothing was read or cleared.
///
/// # Safety
///
/// `handle` must be live. `keys` MUST point to
/// `key_count * VEIL_RATCHET_KEY_LEN` readable bytes. `out_cleared` MUST be
/// writable.
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_ratchet_ack_dirty(
    handle: *mut VeilHandle,
    keys: *const u8,
    key_count: size_t,
    generation: u64,
    out_cleared: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_ratchet_ack_dirty") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "keys" => keys,
        "out_cleared" => out_cleared,
    );
    if key_count > VEIL_RATCHET_MAX_ACK_KEYS {
        unsafe { write_err(err_out, format!("implausible key count {key_count}")) };
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
    let ratchet = match ratchet_for_bundle(&handle_live.bundle) {
        Ok(r) => r,
        Err(e) => {
            unsafe { write_err(err_out, e) };
            return VEIL_ERR;
        }
    };
    let named = unsafe { read_conversation_keys(keys, key_count) };
    let cleared = ratchet.store.ack_dirty(&named, generation);
    unsafe { *out_cleared = cleared };
    VEIL_OK
}

/// List the conversations this node holds, for a full save at shutdown.
///
/// `*out_total` receives the TOTAL number held, which may exceed what fit in
/// `out_buf`; nothing is consumed, so a host may call this as often as it
/// likes.
///
/// # Safety
///
/// `handle` must be live. `out_buf` MUST be writable for `out_buf_cap` bytes.
/// `out_total` MUST be writable.
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_ratchet_list(
    handle: *mut VeilHandle,
    out_buf: *mut u8,
    out_buf_cap: size_t,
    out_total: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_ratchet_list") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_buf" => out_buf,
        "out_total" => out_total,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let ratchet = match ratchet_for_bundle(&handle_live.bundle) {
        Ok(r) => r,
        Err(e) => {
            unsafe { write_err(err_out, e) };
            return VEIL_ERR;
        }
    };
    let keys = ratchet.store.keys();
    let _ = unsafe { write_conversation_keys(&keys, out_buf, out_buf_cap) };
    unsafe { *out_total = keys.len() };
    VEIL_OK
}

/// One page of the conversations this node holds, in key order, resuming
/// strictly after `after_key_64`.
///
/// Pass `NULL` for `after_key_64` to start the walk, then pass the LAST key of
/// the page just returned to continue it. A page shorter than
/// `out_buf_cap / VEIL_RATCHET_KEY_LEN` is the end; a page of zero keys is the
/// end with nothing in it. `*out_written` receives the count of keys written.
///
/// This is what [`veil_ratchet_list`] cannot do. That call writes as many keys
/// as fit and reports the total, so a host whose buffer is smaller than the
/// store can never reach the tail — it can only allocate for the whole set and
/// try again. Here the cost of a page is the page: the walk seeks in
/// logarithmic time and holds the store's lock for the length of the page
/// rather than the length of the store, so a full save streams instead of
/// stopping every other send and receive while it copies.
///
/// The cursor is a key rather than an offset because the store moves between
/// pages — a conversation opens, another is evicted by the quota — and an
/// offset would then skip or repeat whatever crossed it. Resuming at a key is
/// well-defined whether or not that key is still held.
///
/// # Safety
///
/// `handle` must be live. `after_key_64`, when not NULL, MUST point to exactly
/// [`VEIL_RATCHET_KEY_LEN`] readable bytes. `out_buf` MUST be writable for
/// `out_buf_cap` bytes. `out_written` MUST be writable.
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_ratchet_list_page(
    handle: *mut VeilHandle,
    after_key_64: *const u8,
    out_buf: *mut u8,
    out_buf_cap: size_t,
    out_written: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_ratchet_list_page") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "out_buf" => out_buf,
        "out_written" => out_written,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let ratchet = match ratchet_for_bundle(&handle_live.bundle) {
        Ok(r) => r,
        Err(e) => {
            unsafe { write_err(err_out, e) };
            return VEIL_ERR;
        }
    };
    let after = if after_key_64.is_null() {
        None
    } else {
        Some(unsafe { ratchet_key_from(after_key_64) })
    };
    let room = out_buf_cap / VEIL_RATCHET_KEY_LEN;
    let page = ratchet.store.keys_after(after.as_ref(), room);
    let written = unsafe { write_conversation_keys(&page, out_buf, out_buf_cap) };
    unsafe { *out_written = written };
    VEIL_OK
}

/// Drop every unproven conversation that has gone unused for longer than the
/// ratchet's time-to-live, and mark each so the host deletes its stored blob.
/// `*out_dropped` receives how many went.
///
/// For a host to call on a timer, or when it comes back to the foreground.
/// Without it the sweep only runs when the store is full, so a device that has
/// been flooded once keeps carrying the wreckage until something else needs
/// the room.
///
/// "Unproven" means a conversation this device has never sent a message on:
/// somebody opened it, and nothing has confirmed they are who they named. Only
/// those are aged out. A conversation that has carried traffic is never
/// dropped by time, at any age — the peer's copy of it cannot be restarted by
/// anything on the wire, so aging one out would wedge both ends for good. The
/// host decides those with [`veil_ratchet_forget`].
///
/// The clock is this device's own, read here. There is no parameter for it,
/// because there must be no way for a value that came off the network to
/// decide which conversations are old enough to disappear.
///
/// # Safety
///
/// `handle` must be live. `out_dropped` MUST be writable.
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_ratchet_expire(
    handle: *mut VeilHandle,
    out_dropped: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_ratchet_expire") } {
        return rc;
    }
    null_check!(err_out, "handle" => handle, "out_dropped" => out_dropped);
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let ratchet = match ratchet_for_bundle(&handle_live.bundle) {
        Ok(r) => r,
        Err(e) => {
            unsafe { write_err(err_out, e) };
            return VEIL_ERR;
        }
    };
    unsafe { *out_dropped = ratchet.store.expire(veil_util::unix_secs_now_u64()) };
    VEIL_OK
}

/// Export one conversation's whole state.
///
/// EVERY BYTE IS KEY MATERIAL. The host must store it encrypted and must not
/// log, copy to temporary files, or transmit it. In this project that store is
/// the hidden volume.
///
/// Returns [`VEIL_ERR_RATCHET_NO_CONVERSATION`] when the key names nothing
/// held, and [`VEIL_ERR_RATCHET_BUFFER_TOO_SMALL`] when the buffer cannot take
/// the state — in which case `*out_len` receives the length required and
/// nothing was written or consumed.
///
/// # Safety
///
/// `handle` must be live. `key_64` MUST point to exactly
/// [`VEIL_RATCHET_KEY_LEN`] readable bytes. `out_buf` MUST be writable for
/// `out_buf_cap` bytes. `out_len` MUST be writable.
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_ratchet_export(
    handle: *mut VeilHandle,
    key_64: *const u8,
    out_buf: *mut u8,
    out_buf_cap: size_t,
    out_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_ratchet_export") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "key_64" => key_64,
        "out_buf" => out_buf,
        "out_len" => out_len,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let ratchet = match ratchet_for_bundle(&handle_live.bundle) {
        Ok(r) => r,
        Err(e) => {
            unsafe { write_err(err_out, e) };
            return VEIL_ERR;
        }
    };
    let key = unsafe { ratchet_key_from(key_64) };
    let Some(blob) = ratchet.store.export(&key) else {
        unsafe { write_err(err_out, "no conversation under that key") };
        return VEIL_ERR_RATCHET_NO_CONVERSATION;
    };
    unsafe { *out_len = blob.len() };
    if out_buf_cap < blob.len() {
        unsafe {
            write_err(
                err_out,
                format!("out_buf_cap {out_buf_cap} < required {}", blob.len()),
            );
        }
        return VEIL_ERR_RATCHET_BUFFER_TOO_SMALL;
    }
    unsafe { ptr::copy_nonoverlapping(blob.as_ptr(), out_buf, blob.len()) };
    VEIL_OK
}

/// Where a conversation's sending chain stands: the chain it is on, and the
/// index the next sealed message will carry.
///
/// A host records this durably BEFORE it publishes a ciphertext, so that a
/// state write which never lands cannot let a restart re-derive a key this
/// session already spent on the wire (report12 X-H5). It is 36 bytes against
/// the state's kilobytes, which is what makes it affordable on the send path —
/// and a host reserving a small run of indices at a time pays it once per run
/// rather than once per message.
///
/// Returns [`VEIL_ERR_RATCHET_NO_CONVERSATION`] when the key names nothing
/// held, or names a conversation with no sending chain yet — there is then no
/// position to reserve, and nothing has been published either.
///
/// # Safety
///
/// `handle` must be live. `key_64` MUST point to exactly
/// [`VEIL_RATCHET_KEY_LEN`] readable bytes. `out_chain_32` MUST be writable
/// for 32 bytes. `out_next` MUST be writable.
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_ratchet_send_position(
    handle: *mut VeilHandle,
    key_64: *const u8,
    out_chain_32: *mut u8,
    out_next: *mut u32,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_ratchet_send_position") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "key_64" => key_64,
        "out_chain_32" => out_chain_32,
        "out_next" => out_next,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let ratchet = match ratchet_for_bundle(&handle_live.bundle) {
        Ok(r) => r,
        Err(e) => {
            unsafe { write_err(err_out, e) };
            return VEIL_ERR;
        }
    };
    let key = unsafe { ratchet_key_from(key_64) };
    let Some(at) = ratchet.store.send_position(&key) else {
        unsafe {
            write_err(
                err_out,
                "no conversation with a sending chain under that key",
            )
        };
        return VEIL_ERR_RATCHET_NO_CONVERSATION;
    };
    unsafe {
        ptr::copy_nonoverlapping(at.chain.as_ptr(), out_chain_32, 32);
        *out_next = at.next;
    }
    VEIL_OK
}

/// Step a conversation's sending chain past every index that might already
/// have been spent, and report how many keys were burned.
///
/// The recovery half of [`veil_ratchet_send_position`]: on start, a state
/// restored from before an unwritten send is fast-forwarded to the last
/// position the host recorded. Keys burned this way were never emitted, so the
/// peer sees a gap its skipped-key window absorbs.
///
/// A position naming a chain this conversation is no longer on, or an index it
/// has already passed, burns nothing and is not an error — keys from a chain
/// we no longer hold cannot collide with keys from the one we do.
///
/// Returns [`VEIL_ERR_RATCHET_NO_CONVERSATION`] when the key names nothing
/// held, and [`VEIL_ERR_INVALID_ARG`] when the position asks for a jump past
/// what a host reserving indices could legitimately have got ahead — a
/// corrupted or hostile mark. Nothing is burned in either case.
///
/// # Safety
///
/// `handle` must be live. `key_64` MUST point to exactly
/// [`VEIL_RATCHET_KEY_LEN`] readable bytes. `chain_32` MUST point to 32
/// readable bytes. `out_burned` MUST be writable.
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_ratchet_skip_send_to(
    handle: *mut VeilHandle,
    key_64: *const u8,
    chain_32: *const u8,
    next: u32,
    out_burned: *mut u32,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_ratchet_skip_send_to") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "key_64" => key_64,
        "chain_32" => chain_32,
        "out_burned" => out_burned,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let ratchet = match ratchet_for_bundle(&handle_live.bundle) {
        Ok(r) => r,
        Err(e) => {
            unsafe { write_err(err_out, e) };
            return VEIL_ERR;
        }
    };
    let key = unsafe { ratchet_key_from(key_64) };
    let mut chain = [0u8; 32];
    unsafe { ptr::copy_nonoverlapping(chain_32, chain.as_mut_ptr(), 32) };
    match ratchet
        .store
        .skip_send_to(&key, veil_e2e::ratchet::SendPosition { chain, next })
    {
        Ok(burned) => {
            unsafe { *out_burned = burned };
            VEIL_OK
        }
        Err(veil_e2e::ratchet::RatchetSkipError::NoConversation) => {
            unsafe { write_err(err_out, "no conversation under that key") };
            VEIL_ERR_RATCHET_NO_CONVERSATION
        }
        Err(e) => {
            unsafe { write_err(err_out, e.to_string()) };
            VEIL_ERR_INVALID_ARG
        }
    }
}

/// Restore one conversation from bytes [`veil_ratchet_export`] produced.
///
/// Called for every stored conversation at startup, BEFORE traffic flows: a
/// frame that arrives for a conversation not yet restored cannot be opened,
/// and — unlike a lost network packet — the sender has already advanced its
/// chain, so nothing will re-send it in a form this node can read.
///
/// Replaces whatever is held under that key. Rejects a blob it does not fully
/// understand rather than salvaging part of one: a partially-understood
/// session is a session with the wrong keys.
///
/// # Safety
///
/// `handle` must be live. `key_64` MUST point to exactly
/// [`VEIL_RATCHET_KEY_LEN`] readable bytes. `blob` MUST point to `blob_len`
/// readable bytes.
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_ratchet_import(
    handle: *mut VeilHandle,
    key_64: *const u8,
    blob: *const u8,
    blob_len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_ratchet_import") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "key_64" => key_64,
        "blob" => blob,
    );
    if blob_len == 0 || blob_len > VEIL_RATCHET_MAX_STATE_LEN {
        unsafe { write_err(err_out, format!("implausible state length {blob_len}")) };
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
    let ratchet = match ratchet_for_bundle(&handle_live.bundle) {
        Ok(r) => r,
        Err(e) => {
            unsafe { write_err(err_out, e) };
            return VEIL_ERR;
        }
    };
    let key = unsafe { ratchet_key_from(key_64) };
    let bytes = unsafe { std::slice::from_raw_parts(blob, blob_len) };
    match ratchet
        .store
        .import(&key, bytes, veil_util::unix_secs_now_u64())
    {
        Ok(()) => VEIL_OK,
        Err(veil_e2e::RatchetSpliceError::StoreFull) => {
            unsafe {
                write_err(
                    err_out,
                    "ratchet store is full and holds nothing that can be dropped",
                );
            }
            VEIL_ERR_RATCHET_STORE_FULL
        }
        Err(e) => {
            unsafe { write_err(err_out, format!("ratchet state rejected: {e}")) };
            VEIL_ERR_INVALID_ARG
        }
    }
}

/// Drop one conversation.
///
/// Irreversible: nothing public can rebuild the chain, so every message the
/// peer has already sealed to it is unreadable from here on. For when the host
/// deletes a chat or removes a device — not for eviction, which would cost
/// every message that peer sends afterwards.
///
/// Returns [`VEIL_ERR_RATCHET_NO_CONVERSATION`] if nothing was held.
///
/// # Safety
///
/// `handle` must be live. `key_64` MUST point to exactly
/// [`VEIL_RATCHET_KEY_LEN`] readable bytes.
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_ratchet_forget(
    handle: *mut VeilHandle,
    key_64: *const u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_ratchet_forget") } {
        return rc;
    }
    null_check!(err_out, "handle" => handle, "key_64" => key_64);
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let ratchet = match ratchet_for_bundle(&handle_live.bundle) {
        Ok(r) => r,
        Err(e) => {
            unsafe { write_err(err_out, e) };
            return VEIL_ERR;
        }
    };
    let key = unsafe { ratchet_key_from(key_64) };
    if ratchet.store.forget(&key) {
        VEIL_OK
    } else {
        unsafe { write_err(err_out, "no conversation under that key") };
        VEIL_ERR_RATCHET_NO_CONVERSATION
    }
}
