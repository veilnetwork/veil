//! Nicknames: a human-readable name over veil, and the four jobs it takes.
//!
//! Mining, verifying, normalizing and asking the floor are one story, and what
//! holds them together is WHERE each runs. The host mines PoW seeds off the UI
//! isolate — a bounded, chunked, cancellable loop, because an unbounded one on
//! the UI thread is a frozen app — and then hands the seed set to the node to
//! sign with the sovereign key and publish. Verify, normalize and floor stay
//! pure helpers the UI may call on any thread.
//!
//! Moved verbatim out of `lib.rs` (report24 RUNTIME-3), declared `pub mod`
//! so cbindgen still exports every declaration; the generated header is
//! reordered by the move and its SHA-256 — the ABI contract hash — moves
//! with it. Nothing is added or removed.

use super::*;

// ── Nicknames ───────────────────────────────────────────────────────────────
// Human-readable names over veil (see veil-crypto::nickname). The host mines
// PoW seeds OFF the UI isolate (a bounded, chunked, cancellable loop), then
// hands the seed set to the node to sign with the sovereign key and publish
// (brick 3). Verify + normalize + floor are pure helpers for the UI.

/// Normalize a candidate nickname. On VEIL_OK, `*out_buf`/`*out_len` hold the
/// normalized ASCII bytes (free with `veil_free_buf`); returns
/// VEIL_ERR_INVALID_ARG if the name cannot be normalized (bad charset/length).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_nickname_normalize(
    name: *const u8,
    name_len: size_t,
    out_buf: *mut *mut u8,
    out_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if unsafe { guard::ffi_prelude(err_out, "veil_nickname_normalize") }.is_err() {
        return VEIL_ERR_REENTRANT;
    }
    if name.is_null() || out_buf.is_null() || out_len.is_null() {
        unsafe { write_err(err_out, "null argument") };
        return VEIL_ERR_INVALID_ARG;
    }
    let bytes = unsafe { std::slice::from_raw_parts(name, name_len) };
    let Some(s) = std::str::from_utf8(bytes).ok() else {
        unsafe { write_err(err_out, "name is not valid UTF-8") };
        return VEIL_ERR_INVALID_ARG;
    };
    match veil_crypto::nickname::normalize_name(s) {
        Some(norm) => {
            let boxed: Box<[u8]> = norm.into_bytes().into_boxed_slice();
            let len = boxed.len();
            unsafe {
                *out_buf = Box::into_raw(boxed) as *mut u8;
                *out_len = len;
            }
            VEIL_OK
        }
        None => {
            unsafe { write_err(err_out, "name is not a valid nickname") };
            VEIL_ERR_INVALID_ARG
        }
    }
}

/// The cumulative PoW weight a name of this length must carry (the anti-squat
/// floor) — the host mines until it reaches this. 0 on a bad name.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_nickname_length_floor(name: *const u8, name_len: size_t) -> u64 {
    if name.is_null() {
        return 0;
    }
    let bytes = unsafe { std::slice::from_raw_parts(name, name_len) };
    match std::str::from_utf8(bytes)
        .ok()
        .and_then(veil_crypto::nickname::normalize_name)
    {
        Some(n) => veil_crypto::nickname::length_weight_floor(n.chars().count()),
        None => 0,
    }
}

/// Mine PoW seeds for `name` under `owner_node_id`, continuing from
/// `prior_seeds` (a concatenation of 32-byte seeds; may be NULL/0), until the
/// cumulative weight reaches `target_weight` or `max_hashes` is spent. The
/// call is bounded by `max_hashes` — the host loops (fresh call = fresh random
/// salt) and cancels by simply not calling again, threading the returned seed
/// set back in as `prior_seeds`.
///
/// On VEIL_OK, `*out_buf`/`*out_len` hold a serialized outcome (free with
/// `veil_free_buf`): `hit_target:u8 | weight:u64 LE | hashes:u64 LE |
/// seed_count:u32 LE | seeds (count*32)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_nickname_mine(
    name: *const u8,
    name_len: size_t,
    owner_node_id: *const u8,
    prior_seeds: *const u8,
    prior_seeds_len: size_t,
    target_weight: u64,
    max_hashes: u64,
    out_buf: *mut *mut u8,
    out_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if unsafe { guard::ffi_prelude(err_out, "veil_nickname_mine") }.is_err() {
        return VEIL_ERR_REENTRANT;
    }
    if name.is_null() || owner_node_id.is_null() || out_buf.is_null() || out_len.is_null() {
        unsafe { write_err(err_out, "null argument") };
        return VEIL_ERR_INVALID_ARG;
    }
    if !prior_seeds_len.is_multiple_of(32) {
        unsafe { write_err(err_out, "prior_seeds length must be a multiple of 32") };
        return VEIL_ERR_INVALID_ARG;
    }
    let name_bytes = unsafe { std::slice::from_raw_parts(name, name_len) };
    let Some(name_str) = std::str::from_utf8(name_bytes).ok() else {
        unsafe { write_err(err_out, "name is not valid UTF-8") };
        return VEIL_ERR_INVALID_ARG;
    };
    let mut owner = [0u8; 32];
    unsafe { ptr::copy_nonoverlapping(owner_node_id, owner.as_mut_ptr(), 32) };
    let prior: Vec<[u8; 32]> = if prior_seeds.is_null() || prior_seeds_len == 0 {
        Vec::new()
    } else {
        let raw = unsafe { std::slice::from_raw_parts(prior_seeds, prior_seeds_len) };
        raw.chunks_exact(32)
            .map(|c| {
                let mut a = [0u8; 32];
                a.copy_from_slice(c);
                a
            })
            .collect()
    };
    // A fresh random salt per call so repeated host calls explore new nonces.
    let salt = {
        use rand_core::RngCore;
        rand_core::OsRng.next_u64()
    };
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let Some(outcome) = veil_crypto::nickname::mine_seeds_continue(
        name_str,
        &owner,
        &prior,
        target_weight,
        max_hashes,
        salt,
        &cancel,
    ) else {
        unsafe { write_err(err_out, "name is not a valid nickname") };
        return VEIL_ERR_INVALID_ARG;
    };
    let mut buf = Vec::with_capacity(1 + 8 + 8 + 4 + outcome.seeds.len() * 32);
    buf.push(outcome.hit_target as u8);
    buf.extend_from_slice(&outcome.weight.to_le_bytes());
    buf.extend_from_slice(&outcome.hashes_done.to_le_bytes());
    buf.extend_from_slice(&(outcome.seeds.len() as u32).to_le_bytes());
    for s in &outcome.seeds {
        buf.extend_from_slice(s);
    }
    let boxed: Box<[u8]> = buf.into_boxed_slice();
    let len = boxed.len();
    unsafe {
        *out_buf = Box::into_raw(boxed) as *mut u8;
        *out_len = len;
    }
    VEIL_OK
}

/// Verify a serialized nickname record (from `NicknameRecord::to_bytes`).
/// Returns VEIL_OK if valid; VEIL_ERR with a reason in `err_out` otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_nickname_verify(
    record: *const u8,
    record_len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if unsafe { guard::ffi_prelude(err_out, "veil_nickname_verify") }.is_err() {
        return VEIL_ERR_REENTRANT;
    }
    if record.is_null() {
        unsafe { write_err(err_out, "null record") };
        return VEIL_ERR_INVALID_ARG;
    }
    let bytes = unsafe { std::slice::from_raw_parts(record, record_len) };
    let Some(rec) = veil_crypto::nickname::NicknameRecord::from_bytes(bytes) else {
        unsafe { write_err(err_out, "record failed to parse") };
        return VEIL_ERR;
    };
    match rec.verify() {
        Ok(()) => VEIL_OK,
        Err(e) => {
            unsafe { write_err(err_out, format!("record invalid: {e:?}")) };
            VEIL_ERR
        }
    }
}
