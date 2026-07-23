//! Networked public-Space discovery carrier FFI.
//!
//! The caller builds and signs the strict `XS` record with its deniable
//! identity. These functions only publish it through the embedded node or
//! return the bounded contested replica set for application-level descriptor
//! and holder-quorum verification.

use std::ffi::{CString, c_char, c_int};
use std::ptr;

use libc::size_t;
use veil_crypto::space_discovery::{SpaceDiscoveryRecord, SpaceDiscoveryRoute};

use crate::{VEIL_ERR, VEIL_ERR_INVALID_ARG, VEIL_OK, guard};

unsafe fn set_err(err_out: *mut *mut c_char, message: &str) {
    if err_out.is_null() {
        return;
    }
    let value = CString::new(message).unwrap_or_else(|_| CString::new("error").unwrap());
    unsafe { *err_out = value.into_raw() };
}

fn services_for(me: &[u8; 32]) -> Option<veil_node_runtime::NodeServices> {
    veil_node_runtime::embedded_services_for(me).or_else(|| {
        let latest = veil_node_runtime::embedded_services()?;
        (latest.local_node_id() == *me).then_some(latest)
    })
}

fn timeout_from_ms(timeout_ms: u64) -> std::time::Duration {
    let milliseconds = if timeout_ms == 0 { 8_000 } else { timeout_ms };
    std::time::Duration::from_millis(milliseconds.min(60_000))
}

/// Publish one already-signed `XS` public-Space discovery carrier through the
/// embedded node. The record is verified, must name `self_node_id` as holder,
/// is stored under its canonical direct/search route key and replicated to the
/// K closest DHT peers.
///
/// # Safety
/// `self_node_id` must point to exactly 32 readable bytes; `record` must point
/// to `record_len` readable bytes. `err_out`, when non-null, must be a writable
/// pointer slot and its returned string must be freed with `veil_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_space_discovery_publish(
    self_node_id: *const u8,
    record: *const u8,
    record_len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if unsafe { guard::ffi_prelude(err_out, "veil_space_discovery_publish") }.is_err() {
        return crate::VEIL_ERR_REENTRANT;
    }
    if self_node_id.is_null() || record.is_null() || record_len == 0 {
        unsafe { set_err(err_out, "null or empty argument") };
        return VEIL_ERR_INVALID_ARG;
    }
    let bytes = unsafe { std::slice::from_raw_parts(record, record_len) };
    if SpaceDiscoveryRecord::from_bytes(bytes).is_none() {
        unsafe { set_err(err_out, "malformed SpaceDiscoveryRecord") };
        return VEIL_ERR_INVALID_ARG;
    }
    let mut me = [0; 32];
    unsafe { ptr::copy_nonoverlapping(self_node_id, me.as_mut_ptr(), 32) };
    let Some(services) = services_for(&me) else {
        unsafe { set_err(err_out, "no embedded node running for this identity") };
        return VEIL_ERR;
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            unsafe { set_err(err_out, &format!("runtime: {error}")) };
            return VEIL_ERR;
        }
    };
    match runtime.block_on(services.space_discovery_publish(bytes.to_vec())) {
        Ok(()) => VEIL_OK,
        Err(error) => {
            unsafe { set_err(err_out, &error) };
            VEIL_ERR
        }
    }
}

/// Resolve an exact-Space (`route_kind=0`) or search-token (`route_kind=1`)
/// route. On success returns a boxed length-prefixed buffer:
///
/// `count:u32 LE`, followed by `count × (record_len:u32 LE | record bytes)`.
///
/// Free the exact `out_buf/out_len` pair with `veil_free_buf`.
///
/// # Safety
/// `self_node_id` and `route_body` must each point to exactly 32 readable
/// bytes. `out_buf` and `out_len` must be writable pointer slots. `err_out`,
/// when non-null, must be writable and its returned string must be freed with
/// `veil_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_space_discovery_resolve(
    self_node_id: *const u8,
    route_kind: u8,
    route_body: *const u8,
    timeout_ms: u64,
    out_buf: *mut *mut u8,
    out_len: *mut size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if unsafe { guard::ffi_prelude(err_out, "veil_space_discovery_resolve") }.is_err() {
        return crate::VEIL_ERR_REENTRANT;
    }
    if self_node_id.is_null() || route_body.is_null() || out_buf.is_null() || out_len.is_null() {
        unsafe { set_err(err_out, "null argument") };
        return VEIL_ERR_INVALID_ARG;
    }
    unsafe {
        *out_buf = ptr::null_mut();
        *out_len = 0;
    }
    let mut me = [0; 32];
    let mut body = [0; 32];
    unsafe {
        ptr::copy_nonoverlapping(self_node_id, me.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(route_body, body.as_mut_ptr(), 32);
    }
    let route = match route_kind {
        0 => SpaceDiscoveryRoute::Direct(body),
        1 => SpaceDiscoveryRoute::Search(body),
        _ => {
            unsafe { set_err(err_out, "route_kind must be 0 or 1") };
            return VEIL_ERR_INVALID_ARG;
        }
    };
    let Some(services) = services_for(&me) else {
        unsafe { set_err(err_out, "no embedded node running for this identity") };
        return VEIL_ERR;
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            unsafe { set_err(err_out, &format!("runtime: {error}")) };
            return VEIL_ERR;
        }
    };
    let records =
        runtime.block_on(services.space_discovery_resolve(route, timeout_from_ms(timeout_ms)));
    let mut encoded =
        Vec::with_capacity(4 + records.iter().map(|record| 4 + record.len()).sum::<usize>());
    encoded.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for record in records {
        encoded.extend_from_slice(&(record.len() as u32).to_le_bytes());
        encoded.extend_from_slice(&record);
    }
    let boxed = encoded.into_boxed_slice();
    let length = boxed.len();
    let data = Box::into_raw(boxed) as *mut u8;
    unsafe {
        *out_buf = data;
        *out_len = length;
    }
    VEIL_OK
}
