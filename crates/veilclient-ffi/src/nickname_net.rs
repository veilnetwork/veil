//! Networked nickname FFI — claim (sign + publish) and resolve, brick 3b.
//!
//! The pure helpers (`veil_nickname_normalize` / `_length_floor` / `_mine` /
//! `_verify`, in lib.rs) never touch the network; these two do, so they need
//! the IN-PROCESS embedded node (`node-embedded` feature): they look up the
//! live [`veil_node_runtime::NodeServices`] published by the embedded node of
//! the given identity and call its `nickname_claim` / `nickname_resolve`.
//!
//! Only the SOVEREIGN identity may claim (owner binding `blake3(owner_pk) ==
//! node_id` — enforced node-side); the app must never call these for
//! anonymous identities (a public name is a linkability signal — same policy
//! as the P2P gate).

use std::ffi::{CString, c_char, c_int};

use libc::size_t;

use crate::{VEIL_ERR, VEIL_ERR_INVALID_ARG, VEIL_OK, guard};

/// `veil_nickname_resolve`: positive verdict for "the name is free" (no valid
/// owner record found) — not an error.
pub const NICKNAME_FREE: c_int = 1;

/// Write an owned error string into `*err_out` (freed by `veil_free_string`).
unsafe fn set_err(err_out: *mut *mut c_char, msg: &str) {
    if err_out.is_null() {
        return;
    }
    let c = CString::new(msg).unwrap_or_else(|_| CString::new("error").unwrap());
    unsafe { *err_out = c.into_raw() };
}

/// Live services for the embedded node running as identity `me` — keyed slot
/// first, then the single-node `latest` fallback (same pattern as
/// anon_stream's `try_open_circuit`).
fn services_for(me: &[u8; 32]) -> Option<veil_node_runtime::NodeServices> {
    veil_node_runtime::embedded_services_for(me).or_else(|| {
        let latest = veil_node_runtime::embedded_services()?;
        (latest.local_node_id() == *me).then_some(latest)
    })
}

/// Turn an open sovereign signer handle into the master key the claim needs.
///
/// The handle keeps the secret; what leaves here is the master PUBLIC key and
/// a closure that asks the handle for one signature. The `Arc` is captured so
/// the material outlives this function without being copied out of it.
fn master_key_from_signer(
    signer: *mut crate::VeilSovereignSigner,
) -> Result<veil_node_runtime::NicknameMasterKey, &'static str> {
    use veil_node_runtime::NicknameMasterKey;
    use veil_types::SignatureAlgorithm;

    let live = crate::HandleTable::get(crate::sovereign_signer_table(), signer as usize)
        .ok_or("sovereign signer is closed or invalid")?;
    match &live.key {
        crate::SovereignSignerKey::RecoveryEd25519(seed) => {
            let sk = ed25519_dalek::SigningKey::from_bytes(seed);
            let public_key = sk.verifying_key().to_bytes().to_vec();
            Ok(NicknameMasterKey {
                algo: SignatureAlgorithm::Ed25519,
                public_key,
                sign: Box::new(move |msg| {
                    use ed25519_dalek::Signer as _;
                    Some(sk.sign(msg).to_bytes().to_vec())
                }),
            })
        }
        crate::SovereignSignerKey::Bundle(material) => {
            let algo = material.algorithm;
            let public_key = material.public_key.clone();
            // The Arc, not the key: `SovereignMaterial` keeps its secret
            // private to its own module, and signing through the handle is
            // what keeps it that way.
            let held = std::sync::Arc::clone(&live);
            Ok(NicknameMasterKey {
                algo,
                public_key,
                sign: Box::new(move |msg| match &held.key {
                    crate::SovereignSignerKey::Bundle(m) => m.sign(msg).ok(),
                    crate::SovereignSignerKey::RecoveryEd25519(_) => None,
                }),
            })
        }
    }
}

fn timeout_from_ms(timeout_ms: u64) -> std::time::Duration {
    // 0 = "use the default"; clamp so a bad caller can't hang a worker isolate.
    let ms = if timeout_ms == 0 { 8_000 } else { timeout_ms };
    std::time::Duration::from_millis(ms.min(60_000))
}

/// The node id a nickname must be mined and claimed under: the IDENTITY's,
/// not this device's.
///
/// The proof-of-work is bound to the owner id (`blake3(name ‖ owner ‖ seed)`),
/// so mining under the wrong one produces seeds that prove nothing for the
/// record that gets published. On a device whose own key is the identity's
/// master the two ids are equal and this is a no-op; on every other device
/// they differ, and that difference is the whole reason a name outlives a
/// device.
///
/// `node_node_id` is the running node's own id (what the host already knows);
/// the identity's id is written to `out_owner_node_id`.
///
/// # Safety
/// `node_node_id` must point to 32 readable bytes, `out_owner_node_id` to 32
/// writable bytes; `err_out` (if non-null) a writable `*mut c_char` slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_nickname_owner_node_id(
    node_node_id: *const u8,
    out_owner_node_id: *mut u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if unsafe { guard::ffi_prelude(err_out, "veil_nickname_owner_node_id") }.is_err() {
        return crate::VEIL_ERR_REENTRANT;
    }
    if node_node_id.is_null() || out_owner_node_id.is_null() {
        unsafe { set_err(err_out, "null argument") };
        return VEIL_ERR_INVALID_ARG;
    }
    let mut me = [0u8; 32];
    unsafe { std::ptr::copy_nonoverlapping(node_node_id, me.as_mut_ptr(), 32) };
    let Some(services) = services_for(&me) else {
        unsafe { set_err(err_out, "no embedded node running for this identity") };
        return VEIL_ERR;
    };
    let Some(owner) = services.sovereign_node_id() else {
        unsafe {
            set_err(
                err_out,
                "node has no sovereign identity — nicknames require one",
            )
        };
        return VEIL_ERR;
    };
    unsafe { std::ptr::copy_nonoverlapping(owner.as_ptr(), out_owner_node_id, 32) };
    VEIL_OK
}

/// Sign an already-mined seed set with the IDENTITY's master key and publish
/// the nickname record to the DHT (store-local + K-closest fan-out;
/// auto-renewal rides the periodic republish). `seeds` is a concatenation of
/// 32-byte seeds from `veil_nickname_mine`. On VEIL_OK writes the published
/// record's cumulative weight to `*out_weight`.
///
/// `signer` is an open sovereign signer (see
/// `veil_sovereign_signer_open_bundle_zeroize` and friends) holding the
/// identity's MASTER key. The name belongs to the identity, so the master is
/// what signs; a device subkey cannot, on any device. Pass NULL only for an
/// identity whose master IS this node's own key — the node then signs with
/// it, and says so plainly if it turns out not to hold one.
///
/// No secret crosses this call: the signer stays a handle, and the claim asks
/// it for one signature.
///
/// Errors (VEIL_ERR, reason in `*err_out` — free with `veil_free_string`):
/// invalid name/seed set, weight under the per-length floor, no embedded node
/// for this identity, a signer that is closed or belongs to a DIFFERENT
/// identity, no signer on a device that does not hold the master, or the name
/// is owned by a heavier foreign record (the message carries the weight to
/// beat).
///
/// # Safety
/// `owner_node_id` must point to 32 readable bytes; `name` to `name_len`
/// readable bytes; `seeds` to `seeds_len` readable bytes (multiple of 32, may
/// be NULL iff `seeds_len == 0` — though an empty set never clears the
/// floor); `signer` must be a live handle from one of the
/// `veil_sovereign_signer_open_*` calls or NULL; `out_weight` must be a
/// writable `u64` slot; `err_out` (if non-null) a writable `*mut c_char` slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_nickname_claim(
    owner_node_id: *const u8,
    name: *const u8,
    name_len: size_t,
    seeds: *const u8,
    seeds_len: size_t,
    timeout_ms: u64,
    signer: *mut crate::VeilSovereignSigner,
    out_weight: *mut u64,
    err_out: *mut *mut c_char,
) -> c_int {
    if unsafe { guard::ffi_prelude(err_out, "veil_nickname_claim") }.is_err() {
        return crate::VEIL_ERR_REENTRANT;
    }
    if owner_node_id.is_null() || name.is_null() || out_weight.is_null() {
        unsafe { set_err(err_out, "null argument") };
        return VEIL_ERR_INVALID_ARG;
    }
    if !seeds_len.is_multiple_of(32) {
        unsafe { set_err(err_out, "seeds length must be a multiple of 32") };
        return VEIL_ERR_INVALID_ARG;
    }
    let name_bytes = unsafe { std::slice::from_raw_parts(name, name_len) };
    let Ok(name_str) = std::str::from_utf8(name_bytes) else {
        unsafe { set_err(err_out, "name is not valid UTF-8") };
        return VEIL_ERR_INVALID_ARG;
    };
    let mut me = [0u8; 32];
    unsafe { std::ptr::copy_nonoverlapping(owner_node_id, me.as_mut_ptr(), 32) };
    let seed_vec: Vec<[u8; 32]> = if seeds.is_null() || seeds_len == 0 {
        Vec::new()
    } else {
        let raw = unsafe { std::slice::from_raw_parts(seeds, seeds_len) };
        raw.chunks_exact(32)
            .map(|c| {
                let mut a = [0u8; 32];
                a.copy_from_slice(c);
                a
            })
            .collect()
    };
    let Some(services) = services_for(&me) else {
        unsafe { set_err(err_out, "no embedded node running for this identity") };
        return VEIL_ERR;
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            unsafe { set_err(err_out, format!("runtime: {e}").as_str()) };
            return VEIL_ERR;
        }
    };
    let master = if signer.is_null() {
        None
    } else {
        match master_key_from_signer(signer) {
            Ok(m) => Some(m),
            Err(e) => {
                unsafe { set_err(err_out, e) };
                return VEIL_ERR;
            }
        }
    };
    let timeout = timeout_from_ms(timeout_ms);
    match rt.block_on(services.nickname_claim(name_str, seed_vec, timeout, master)) {
        Ok(rec) => {
            unsafe { *out_weight = rec.weight };
            VEIL_OK
        }
        Err(e) => {
            unsafe { set_err(err_out, &e) };
            VEIL_ERR
        }
    }
}

/// Resolve the current owner of a nickname via the embedded node running as
/// `self_node_id`. Verifies every replica (owner binding + signature +
/// recomputed cumulative PoW + length floor) and picks the record that
/// displaces all others.
///
/// Returns VEIL_OK with `*out_owner` (32 bytes), `*out_weight` and
/// `*out_issued_at` filled when an owner exists; [`NICKNAME_FREE`] (=1) when
/// the name has no valid owner record (available); negative on error
/// (`*err_out` set — free with `veil_free_string`).
///
/// # Safety
/// `self_node_id` must point to 32 readable bytes; `name` to `name_len`
/// readable bytes; `out_owner` must be writable for 32 bytes; `out_weight` /
/// `out_issued_at` writable `u64` slots; `err_out` (if non-null) a writable
/// `*mut c_char` slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_nickname_resolve(
    self_node_id: *const u8,
    name: *const u8,
    name_len: size_t,
    timeout_ms: u64,
    out_owner: *mut u8,
    out_weight: *mut u64,
    out_issued_at: *mut u64,
    err_out: *mut *mut c_char,
) -> c_int {
    if unsafe { guard::ffi_prelude(err_out, "veil_nickname_resolve") }.is_err() {
        return crate::VEIL_ERR_REENTRANT;
    }
    if self_node_id.is_null()
        || name.is_null()
        || out_owner.is_null()
        || out_weight.is_null()
        || out_issued_at.is_null()
    {
        unsafe { set_err(err_out, "null argument") };
        return VEIL_ERR_INVALID_ARG;
    }
    let name_bytes = unsafe { std::slice::from_raw_parts(name, name_len) };
    let Ok(name_str) = std::str::from_utf8(name_bytes) else {
        unsafe { set_err(err_out, "name is not valid UTF-8") };
        return VEIL_ERR_INVALID_ARG;
    };
    let mut me = [0u8; 32];
    unsafe { std::ptr::copy_nonoverlapping(self_node_id, me.as_mut_ptr(), 32) };
    let Some(services) = services_for(&me) else {
        unsafe { set_err(err_out, "no embedded node running for this identity") };
        return VEIL_ERR;
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            unsafe { set_err(err_out, format!("runtime: {e}").as_str()) };
            return VEIL_ERR;
        }
    };
    let timeout = timeout_from_ms(timeout_ms);
    match rt.block_on(services.nickname_resolve(name_str, timeout)) {
        Ok(Some(rec)) => {
            unsafe {
                std::ptr::copy_nonoverlapping(rec.owner_node_id.as_ptr(), out_owner, 32);
                *out_weight = rec.weight;
                *out_issued_at = rec.issued_at_unix;
            }
            VEIL_OK
        }
        Ok(None) => NICKNAME_FREE,
        Err(e) => {
            unsafe { set_err(err_out, &e) };
            VEIL_ERR
        }
    }
}
