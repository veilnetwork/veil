//! Onion services: publishing a location-anonymous address, and withdrawing it.
//!
//! Registering under the sovereign key, registering under a caller-owned
//! ephemeral seed, the provider-slot variant, the withdraw, and the two
//! rendezvous-publisher registrations. One family because they are one
//! decision taken five ways: WHICH identity the service is published under,
//! and therefore what a watcher can link it to.
//!
//! `embedded_services_for_bundle` sat in the middle of this run and stayed
//! behind: it is the shared "give me the node's services" helper that
//! `ratchet.rs` also calls, and the only thing it had in common with these was
//! its position in the file.
//!
//! Moved verbatim (report24 RUNTIME-3), `pub mod` so cbindgen keeps every
//! declaration.

use super::*;

/// Register this node as a LOCATION-anonymous (onion) service: the daemon picks
/// relays, builds an onion circuit to a rendezvous relay (which never learns
/// this node's location), and publishes the ad so clients can reach this node by
/// its identity. `hop_count` is clamped to ≥ 2 by the daemon (2 = node→mid→relay).
///
/// `VEIL_OK` once the daemon accepts; `VEIL_ERR` with a detail otherwise (e.g.
/// no relays available yet — retry after a short back-off). Connection-level:
/// hosts the whole node as a service; any bound endpoint can then receive.
///
/// # Safety
/// `handle` must be a live `VeilHandle*` from `veil_connect`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_register_onion_service(
    handle: *mut VeilHandle,
    hop_count: u32,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_register_onion_service") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
    );
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
        client.register_onion_service(hop_count).await
    });
    match res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            unsafe {
                write_err(err_out, format!("register_onion_service failed: {e}"));
            }
            VEIL_ERR
        }
    }
}

/// Register a location-anonymous service under a caller-owned random Ed25519
/// seed rather than the node's sovereign key. The seed buffer is writable and
/// is ZEROED immediately on every post-validation path. On success writes the
/// corresponding 32-byte public service identity to `out_identity_vk`; this is
/// the only address that belongs in a public capability link. The blinded DHT
/// descriptor and rendezvous advert contain no sovereign public key/node id.
///
/// Embedded-node only: the service circuit lives in this process's node
/// runtime. Re-register the same seed after restart; registration is idempotent
/// within a descriptor period. At most the runtime's bounded hosted-service cap
/// may be active.
///
/// # Safety
/// `identity_seed_32` must point to 32 WRITABLE bytes; they are zeroized.
/// `out_identity_vk_32` must point to 32 writable bytes.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_register_ephemeral_onion_service_zeroize(
    handle: *mut VeilHandle,
    identity_seed_32: *mut u8,
    hop_count: u32,
    out_identity_vk_32: *mut u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) =
        unsafe { guard::ffi_prelude(err_out, "veil_register_ephemeral_onion_service_zeroize") }
    {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "identity_seed_32" => identity_seed_32,
        "out_identity_vk_32" => out_identity_vk_32,
    );
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    unsafe {
        ptr::copy_nonoverlapping(identity_seed_32, seed.as_mut_ptr(), 32);
        ptr::write_bytes(identity_seed_32, 0, 32);
    }
    if seed.iter().all(|byte| *byte == 0) {
        unsafe { write_err(err_out, "ephemeral service seed must not be all-zero") };
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
    let services = match embedded_services_for_bundle(&handle_live.bundle) {
        Ok(services) => services,
        Err(error) => {
            unsafe { write_err(err_out, error) };
            return VEIL_ERR;
        }
    };
    let public_key = match services.register_ephemeral_onion_service(seed, hop_count as usize) {
        Ok(public_key) => public_key,
        Err(error) => {
            unsafe {
                write_err(
                    err_out,
                    format!("register_ephemeral_onion_service failed: {error:?}"),
                )
            };
            return VEIL_ERR;
        }
    };
    unsafe { ptr::copy_nonoverlapping(public_key.as_ptr(), out_identity_vk_32, 32) };
    VEIL_OK
}

/// Provider-slotted form of
/// [`veil_register_ephemeral_onion_service_zeroize`]. Linked devices hosting
/// the same capability seed must use distinct slots in `0..8`; the runtime
/// publishes a collision-free descriptor for that slot while retaining the
/// legacy descriptor for old resolvers.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_register_ephemeral_onion_service_zeroize_v2(
    handle: *mut VeilHandle,
    identity_seed_32: *mut u8,
    hop_count: u32,
    provider_slot: u8,
    out_identity_vk_32: *mut u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) =
        unsafe { guard::ffi_prelude(err_out, "veil_register_ephemeral_onion_service_zeroize_v2") }
    {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "identity_seed_32" => identity_seed_32,
        "out_identity_vk_32" => out_identity_vk_32,
    );
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    unsafe {
        ptr::copy_nonoverlapping(identity_seed_32, seed.as_mut_ptr(), 32);
        ptr::write_bytes(identity_seed_32, 0, 32);
    }
    if seed.iter().all(|byte| *byte == 0) {
        unsafe { write_err(err_out, "ephemeral service seed must not be all-zero") };
        return VEIL_ERR_INVALID_ARG;
    }
    if provider_slot >= veil_anonymity::blinded_descriptor::MAX_PROVIDER_SLOTS {
        unsafe { write_err(err_out, "provider_slot must be in 0..8") };
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
    let services = match embedded_services_for_bundle(&handle_live.bundle) {
        Ok(services) => services,
        Err(error) => {
            unsafe { write_err(err_out, error) };
            return VEIL_ERR;
        }
    };
    let public_key = match services.register_ephemeral_onion_service_with_provider_slot(
        seed,
        hop_count as usize,
        provider_slot,
    ) {
        Ok(public_key) => public_key,
        Err(error) => {
            unsafe {
                write_err(
                    err_out,
                    format!("register_ephemeral_onion_service failed: {error:?}"),
                )
            };
            return VEIL_ERR;
        }
    };
    unsafe { ptr::copy_nonoverlapping(public_key.as_ptr(), out_identity_vk_32, 32) };
    VEIL_OK
}

/// Stop maintaining one caller-owned ephemeral onion service. Idempotent:
/// unknown/already-withdrawn public keys return `VEIL_OK` too, so this local
/// lifecycle API never becomes a remote existence oracle. DHT ciphertext and
/// the circuit age out naturally; the host must reject capability requests as
/// soon as its encrypted registry marks the share revoked.
#[cfg(feature = "node-embedded")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_withdraw_ephemeral_onion_service(
    handle: *mut VeilHandle,
    identity_vk_32: *const u8,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_withdraw_ephemeral_onion_service") }
    {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "identity_vk_32" => identity_vk_32,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilHandle"
    );
    let mut public_key = [0u8; 32];
    unsafe { ptr::copy_nonoverlapping(identity_vk_32, public_key.as_mut_ptr(), 32) };
    let services = match embedded_services_for_bundle(&handle_live.bundle) {
        Ok(services) => services,
        Err(error) => {
            unsafe { write_err(err_out, error) };
            return VEIL_ERR;
        }
    };
    services.withdraw_ephemeral_onion_service(public_key);
    VEIL_OK
}

/// Register a PLAIN rendezvous-publisher entry (mailbox-by-discovery): the
/// daemon's maintenance tick signs + publishes a v5 `RendezvousAd` under THIS
/// node's real id at `rendezvous_node_id`'s rendezvous slot, advertising the
/// relay's KEM key so a sender resolving the ad (`veil_lookup_rendezvous_replicas`)
/// can anonymously deposit a mailbox PUT at the relay. Replaces any existing
/// entry with the same `(rendezvous_node_id, auth_cookie)`.
///
/// `relay_kem_algo` is the KEM tag (`0` = X25519); `relay_kem_pk` / `kem_len`
/// the relay's KEM pubkey (32-byte X25519 for algo 0; obtain a self-relay key
/// via `veil_get_relay_x25519_pubkey`). Pass `kem_len = 0` to advertise no key.
///
/// `VEIL_OK` once the daemon records the entry; `VEIL_ERR` otherwise.
///
/// # Safety
/// `handle` must be a live `VeilHandle*`. `rendezvous_node_id` must be readable
/// for 32 bytes, `auth_cookie` for 16. `relay_kem_pk` must be readable for
/// `kem_len` bytes (or NULL iff `kem_len == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_register_rendezvous_publisher(
    handle: *mut VeilHandle,
    rendezvous_node_id: *const u8,
    auth_cookie: *const u8,
    validity_window_secs: u64,
    relay_kem_algo: u8,
    relay_kem_pk: *const u8,
    kem_len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_register_rendezvous_publisher") } {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "rendezvous_node_id" => rendezvous_node_id,
        "auth_cookie" => auth_cookie,
    );
    if relay_kem_pk.is_null() && kem_len > 0 {
        unsafe {
            write_err(err_out, "relay_kem_pk is NULL but kem_len > 0");
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
    let mut node_id = [0u8; 32];
    let mut cookie = [0u8; 16];
    // SAFETY: both pointers NULL-checked; caller guarantees the documented byte
    // counts.
    unsafe {
        ptr::copy_nonoverlapping(rendezvous_node_id, node_id.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(auth_cookie, cookie.as_mut_ptr(), 16);
    }
    let kem_pk: Vec<u8> = if kem_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(relay_kem_pk, kem_len) }.to_vec()
    };
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client
            .register_rendezvous_publisher(
                node_id,
                cookie,
                validity_window_secs,
                relay_kem_algo,
                kem_pk,
                // Not known through this export — the ad runs on its own
                // window, as it always did. See the `_with_expiry` twin.
                0,
            )
            .await
    });
    match res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            unsafe {
                write_err(
                    err_out,
                    format!("register_rendezvous_publisher failed: {e}"),
                );
            }
            VEIL_ERR
        }
    }
}

/// [`veil_register_rendezvous_publisher`], plus the relay key's expiry.
///
/// The daemon clips the published ad's `valid_until` to
/// `relay_kem_valid_until_unix`, so an ad cannot go on advertising a relay key
/// past the point that key stopped being the relay's — thirty days of deposits
/// to a key nobody holds, or to whoever holds the old private half (report17
/// V17-M1). Take the value from
/// [`veil_lookup_relay_x25519_with_expiry`]; `0` means "not known" and leaves
/// the ad on its own window.
///
/// A separate export rather than a wider one, for the same reason as its
/// lookup twin: the shorter form is already compiled into shipped callers.
///
/// # Safety
/// As [`veil_register_rendezvous_publisher`].
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn veil_register_rendezvous_publisher_with_expiry(
    handle: *mut VeilHandle,
    rendezvous_node_id: *const u8,
    auth_cookie: *const u8,
    validity_window_secs: u64,
    relay_kem_algo: u8,
    relay_kem_pk: *const u8,
    kem_len: size_t,
    relay_kem_valid_until_unix: u64,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) =
        unsafe { guard::ffi_prelude(err_out, "veil_register_rendezvous_publisher_with_expiry") }
    {
        return rc;
    }
    null_check!(err_out,
        "handle" => handle,
        "rendezvous_node_id" => rendezvous_node_id,
        "auth_cookie" => auth_cookie,
    );
    if relay_kem_pk.is_null() && kem_len > 0 {
        unsafe {
            write_err(err_out, "relay_kem_pk is NULL but kem_len > 0");
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
    let mut node_id = [0u8; 32];
    let mut cookie = [0u8; 16];
    // SAFETY: both pointers NULL-checked; caller guarantees the documented byte
    // counts.
    unsafe {
        ptr::copy_nonoverlapping(rendezvous_node_id, node_id.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(auth_cookie, cookie.as_mut_ptr(), 16);
    }
    let kem_pk: Vec<u8> = if kem_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(relay_kem_pk, kem_len) }.to_vec()
    };
    let bundle = Arc::clone(&handle_live.bundle);
    let res = bundle.runtime.block_on(async {
        let client = bundle.client.lock().await;
        client
            .register_rendezvous_publisher(
                node_id,
                cookie,
                validity_window_secs,
                relay_kem_algo,
                kem_pk,
                relay_kem_valid_until_unix,
            )
            .await
    });
    match res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            unsafe {
                write_err(
                    err_out,
                    format!("register_rendezvous_publisher failed: {e}"),
                );
            }
            VEIL_ERR
        }
    }
}
