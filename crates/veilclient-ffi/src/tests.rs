//! The crate's main test suite: the handle table, the ABI contract, and the entry points.
//!
//! Moved verbatim out of `lib.rs`, which was fourteen thousand lines with four
//! thousand of them test code interleaved with the production surface
//! (report24 RUNTIME-3). Nothing here is compiled into the library — the
//! module keeps the same `cfg`, the same name and the same `use super::*`, so
//! every test still runs under the path it ran under before.
//!
//! The production code was deliberately NOT moved. cbindgen emits this crate's
//! header in parse order and skips `pub` items it finds in a private module,
//! so moving a section of `lib.rs` into a submodule rewrote the header and
//! DROPPED declarations from it — measured, then reverted. Tests are the part
//! that can move without the header noticing, and this checks that it did not.

use super::*;
// The families that moved to files of their own; the tests came with
// neither, because they reach across several of them.
use crate::sovereign_sign::*;
use std::ffi::CStr;

/// The compiled-in contract hash must be the hash of the header actually
/// committed next to it.
///
/// This is the "forgot to regenerate the derived files" half of the gate.
/// The other half — "forgot to regenerate the header itself" — is the
/// cbindgen diff CI already runs; neither catches the other's case, and
/// together nothing gets through. Note the direction this one covers is
/// the one a local run can prove: `include_bytes!` reads the same file the
/// generator hashed, so a stale header hashes consistently and passes here
/// while the cbindgen diff fails.
#[test]
fn abi_contract_hash_is_the_hash_of_the_committed_header() {
    use sha2::{Digest, Sha256};
    let header = include_bytes!("../include/veil_ffi.h");
    let want = format!("{:x}", Sha256::digest(header));
    assert_eq!(
        abi_contract::VEIL_ABI_CONTRACT_HASH.to_str().unwrap(),
        want,
        "abi_contract.rs is stale — run ./scripts/regen-ffi-header.sh"
    );
    assert_eq!(
        abi_contract::VEIL_ABI_CONTRACT_HASH.count_bytes(),
        VEIL_ABI_CONTRACT_HASH_LEN,
        "the advertised hash length must match the hash"
    );
}

/// The accessor hands out exactly that hash, NUL-terminated, and the
/// pointer is static (a caller must never free it).
#[test]
fn abi_contract_accessor_returns_the_compiled_in_hash() {
    let a = veil_abi_contract_hash();
    assert!(!a.is_null());
    let s = unsafe { CStr::from_ptr(a) };
    assert_eq!(s, abi_contract::VEIL_ABI_CONTRACT_HASH);
    // Static storage: two calls yield the SAME pointer, so there is
    // nothing to free and nothing to race.
    assert_eq!(a, veil_abi_contract_hash());
}

/// The `VEIL_MAILBOX_*` constants are what a C or Dart caller sizes its
/// fetch buffers from; the daemon's are what actually bound a batch. Held
/// equal HERE, mechanically, because the alternative — a doc comment saying
/// they mirror — is what let the Dart data ceiling sit 256 bytes above this
/// crate's for however long it did (report7 V-07). A drift is a failing
/// test in the standard gate, not a `blob_buf too small` on a phone.
#[test]
fn mailbox_abi_constants_track_the_daemon() {
    assert_eq!(
        VEIL_MAILBOX_MAX_FETCH_BYTES as u64,
        veil_mailbox::MAX_FETCH_BYTES,
        "exported fetch-byte ceiling drifted from veil_mailbox::MAX_FETCH_BYTES"
    );
    assert_eq!(
        VEIL_MAILBOX_MAX_FETCH_COUNT as usize,
        veil_mailbox::MAX_FETCH_COUNT,
        "exported fetch-count ceiling drifted from veil_mailbox::MAX_FETCH_COUNT"
    );
    assert_eq!(
        VEIL_MAILBOX_MAX_BLOB_BYTES as u64,
        veil_mailbox::MAX_BLOB_BYTES,
        "exported blob ceiling drifted from veil_mailbox::MAX_BLOB_BYTES"
    );
}

/// A batch has to fit the transport that carries it, or the ceiling moved
/// the wedge instead of removing it; and a batch has to hold at least one
/// worst-case record, or an oversized head is served alone forever. Both
/// are relations between compile-time constants, so they are checked at
/// compile time.
const _: () = assert!(VEIL_MAILBOX_MAX_FETCH_BYTES <= VEIL_MAX_DATA_LEN);
const _: () = assert!(VEIL_MAILBOX_MAX_BLOB_BYTES <= VEIL_MAILBOX_MAX_FETCH_BYTES);

#[cfg(feature = "node-embedded")]
#[test]
fn direct_media_receiver_binds_named_app_to_authenticated_node() {
    let peer = [0x42; 32];
    let expected = direct_media_source_app(&peer, "xveil", "media");

    assert_eq!(expected, veil_app::app_id(&peer, "xveil", "media"));
    assert_ne!(
        expected,
        direct_media_source_app(&[0x43; 32], "xveil", "media")
    );
    assert_ne!(
        expected,
        direct_media_source_app(&peer, "xveil", "messages")
    );
}

/// diff-audit M26 (explicit-length ABI): a non-NULL but non-UTF-8 password
/// must NOT collapse to `None` (which silently emits a plaintext invite) —
/// `opt_slice_to_str` must reject it.
#[test]
fn opt_slice_to_str_distinguishes_null_utf8_and_invalid_m26() {
    // NULL ptr → no value (length ignored), intended plain output.
    assert!(matches!(
        unsafe { opt_slice_to_str(ptr::null(), 7) },
        Ok(None)
    ));
    // Valid UTF-8 → Some.
    let ok = b"hunter2";
    assert!(matches!(
        unsafe { opt_slice_to_str(ok.as_ptr(), ok.len()) },
        Ok(Some("hunter2"))
    ));
    // Non-NULL but non-UTF-8 (0xFF) → Err — caller rejects, never coerces to
    // a plaintext-emitting None.
    let bad = [0xFFu8, 0xFE];
    assert!(matches!(
        unsafe { opt_slice_to_str(bad.as_ptr(), bad.len()) },
        Err(())
    ));
    // Over-cap length → Err (not silently dropped).
    let big = vec![b'x'; MAX_FFI_CSTR_LEN + 1];
    assert!(matches!(
        unsafe { opt_slice_to_str(big.as_ptr(), big.len()) },
        Err(())
    ));
}

/// `slice_to_str`: NULL, over-cap, and invalid-UTF-8 all reject; a valid
/// non-terminated buffer of exactly `len` bytes decodes (no NUL needed).
#[test]
fn slice_to_str_rejects_null_overcap_and_invalid() {
    assert!(unsafe { slice_to_str(ptr::null(), 4) }.is_none());
    let good = b"obfs4-tcp://host:1"; // no NUL terminator
    assert_eq!(
        unsafe { slice_to_str(good.as_ptr(), good.len()) },
        Some("obfs4-tcp://host:1")
    );
    let bad = [0xFFu8, 0x00, 0x01];
    assert!(unsafe { slice_to_str(bad.as_ptr(), bad.len()) }.is_none());
    let big = vec![b'x'; MAX_FFI_CSTR_LEN + 1];
    assert!(unsafe { slice_to_str(big.as_ptr(), big.len()) }.is_none());
    // Exactly at cap is accepted.
    let at_cap = vec![b'a'; MAX_FFI_CSTR_LEN];
    assert!(unsafe { slice_to_str(at_cap.as_ptr(), at_cap.len()) }.is_some());
}

#[test]
fn null_handle_close_is_noop() {
    unsafe {
        veil_close(ptr::null_mut());
    }
}

#[test]
fn max_data_len_leaves_frame_headroom() {
    // The daemon frames an FFI send as body_len = <payload FIXED_SIZE> +
    // data_len and rejects body_len > MAX_FRAME_BODY (16 MiB), tearing down
    // the WHOLE IPC connection on overflow (diff-audit defect M25). So
    // VEIL_MAX_DATA_LEN must leave headroom for the LARGEST send-payload
    // fixed prefix. Literals mirror veil_proto::codec::MAX_FRAME_BODY and
    // SendAnonymousDirectPayload::FIXED_SIZE (the largest cap-using sender);
    // veilclient-ffi does not depend on veil-proto directly, hence the
    // documented constants here.
    const MAX_FRAME_BODY: usize = 16 * 1024 * 1024;
    const LARGEST_SEND_PREFIX: usize = 136; // SendAnonymousDirectPayload::FIXED_SIZE
    // Asserting a compile-time-constant invariant is the whole point here —
    // this test pins that VEIL_MAX_DATA_LEN can never grow past the headroom.
    #[allow(clippy::assertions_on_constants)]
    {
        assert!(
            VEIL_MAX_DATA_LEN + LARGEST_SEND_PREFIX <= MAX_FRAME_BODY,
            "VEIL_MAX_DATA_LEN ({VEIL_MAX_DATA_LEN}) + prefix ({LARGEST_SEND_PREFIX}) \
             must stay <= MAX_FRAME_BODY ({MAX_FRAME_BODY})"
        );
    }
}

#[test]
fn validate_bip39_zeroize_wipes_invalid_utf8_input() {
    // audit cycle-3: even a non-UTF-8 (so rejected) but NUL-terminated
    // writable buffer must be scrubbed — the RAII guard runs on every path.
    let mut buf: Vec<u8> = vec![0xFF, 0xFE, 0xAA]; // invalid UTF-8
    let n = buf.len();
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe { veil_validate_bip39_phrase_zeroize(buf.as_mut_ptr(), n, &mut err) };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    assert_eq!(&buf[..3], &[0, 0, 0], "content bytes must be zeroed");
    if !err.is_null() {
        unsafe { veil_free_string(err) };
    }
}

#[test]
fn validate_bip39_zeroize_wipes_rejected_phrase() {
    // A valid-UTF-8 but not-a-mnemonic phrase is also wiped (was already the
    // case; guards against regression).
    let mut buf: Vec<u8> = b"not a real mnemonic".to_vec();
    let n = buf.len();
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe { veil_validate_bip39_phrase_zeroize(buf.as_mut_ptr(), n, &mut err) };
    assert_ne!(rc, VEIL_OK);
    assert!(
        buf.iter().all(|&b| b == 0),
        "phrase buffer must be fully zeroed"
    );
    if !err.is_null() {
        unsafe { veil_free_string(err) };
    }
}

/// The generational table makes a double-close a safe no-op and a stale
/// token (slot reused by a DIFFERENT handle) fail validation, WITHOUT
/// dereferencing the opaque token. Exercised on a local table with a cheap
/// value type — no real handle / allocation / deref required.
#[test]
fn handle_table_insert_get_remove_roundtrip() {
    let table = StdMutex::new(HandleTable::<u64>::new());
    let tok = HandleTable::insert(&table, 0xABCD);
    assert_ne!(tok, 0, "a live token must never be NULL");
    assert_eq!(
        HandleTable::get(&table, tok).as_deref().copied(),
        Some(0xABCD),
        "get must return the live value"
    );
    assert_eq!(
        HandleTable::remove(&table, tok).as_deref().copied(),
        Some(0xABCD),
        "first close must claim the live entry"
    );
    assert!(
        HandleTable::get(&table, tok).is_none(),
        "use-after-close must report not-live"
    );
    assert!(
        HandleTable::remove(&table, tok).is_none(),
        "double-close must be a safe no-op"
    );
}

/// ABA: closing a handle and creating a new one that REUSES the freed slot
/// must NOT let the old (stale) token address the new handle. The bumped
/// per-slot generation makes the two tokens distinct and the stale one
/// invalid — the property the prior address-keyed registry could not give.
/// A bumped generation must always still fit the token that carries it.
///
/// This host is 64-bit, where the token splits 32/32 and the counter and
/// the field are the same width — so the end-to-end path CANNOT be
/// exercised here. The 32-bit split (16/16) is the broken one: bumping the
/// `u32` counter at full width walked it past the 16-bit field, and from
/// then on every token that slot handed out carried `generation & 0xFFFF`
/// while validation compared the whole counter, so the slot's handles
/// failed permanently. The rule is checked at BOTH splits.
#[test]
fn a_bumped_generation_always_fits_the_token_field() {
    for &mask in &[0xFFFFu32, u32::MAX] {
        let mut generation = 1u32;
        for _ in 0..4 {
            generation = bump_generation(generation, mask);
            assert!(
                generation <= mask,
                "generation {generation} left field {mask:#x}"
            );
            assert_ne!(generation, 0, "an all-zero token would look like NULL");
        }
        // At the top of the field it must wrap back INSIDE the field.
        let wrapped = bump_generation(mask, mask);
        assert!(
            wrapped <= mask,
            "wrap left the field: {wrapped:#x} > {mask:#x}"
        );
        assert_ne!(wrapped, 0);
    }
    // On this target the mask must leave the index bits alone.
    assert_eq!(
        HANDLE_GENERATION_MASK as usize & HANDLE_INDEX_MASK,
        HANDLE_INDEX_MASK.min(HANDLE_GENERATION_MASK as usize),
        "generation field and index field must not be mis-sized"
    );
}

#[test]
fn handle_table_generation_defeats_aba() {
    let table = StdMutex::new(HandleTable::<u64>::new());
    let t1 = HandleTable::insert(&table, 1);
    assert!(HandleTable::remove(&table, t1).is_some());
    // New handle reuses slot 0 with a bumped generation.
    let t2 = HandleTable::insert(&table, 2);
    assert_ne!(
        t1, t2,
        "slot reuse must yield a distinct token (new generation)"
    );
    assert!(
        HandleTable::get(&table, t1).is_none(),
        "stale token must NOT address the reused slot (ABA closed)"
    );
    assert_eq!(
        HandleTable::get(&table, t2).as_deref().copied(),
        Some(2),
        "the live token still resolves"
    );
    assert!(
        HandleTable::remove(&table, t1).is_none(),
        "stale double-close must not free the reused slot"
    );
    assert!(
        HandleTable::get(&table, t2).is_some(),
        "live handle survives a stale close of its predecessor"
    );
}

/// Per-type isolation: a token minted by one table must not resolve in
/// another, so the use path rejects a cross-type token before any deref.
#[test]
fn handle_table_tokens_are_per_table() {
    let a = StdMutex::new(HandleTable::<u64>::new());
    let b = StdMutex::new(HandleTable::<u64>::new());
    let tok = HandleTable::insert(&a, 7);
    assert!(
        HandleTable::get(&b, tok).is_none(),
        "a token from table A must not resolve in table B"
    );
}

/// Audit M-2 (use path): a real USE entry point handed a token that is not
/// live in its table — never-created, already-closed, ABA-stale, or the
/// wrong type — must return INVALID_ARG via the liveness guard and NEVER
/// dereference the opaque (non-pointer) token. In a unit test the global
/// handle/app/stream tables are empty (no daemon connection), so any
/// synthetic non-NULL token is "not live" and exercises exactly that guard.
#[test]
fn use_with_unknown_handle_token_returns_error_not_uaf() {
    let bogus = 0x0AF5_0001_usize as *mut VeilHandle;
    let mut out_node = [0u8; 32];
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe { veil_get_node_id(bogus, out_node.as_mut_ptr(), &mut err) };
    assert_eq!(
        rc, VEIL_ERR_INVALID_ARG,
        "unknown handle must return INVALID_ARG, not crash"
    );
    let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap();
    assert_eq!(msg, "VeilHandle: use-after-close or unknown handle");
    unsafe {
        veil_free_string(err);
    }
}

#[test]
fn use_with_unknown_app_token_returns_error_not_uaf() {
    let bogus = 0x0AF5_0003_usize as *mut VeilApp;
    let dst_node = [0u8; 32];
    let dst_app = [0u8; 32];
    let mut err: *mut c_char = ptr::null_mut();
    // len == 0 with valid stack dst buffers carries control past the cheap
    // arg checks straight to the liveness guard.
    let rc = unsafe {
        veil_send(
            bogus,
            dst_node.as_ptr(),
            dst_app.as_ptr(),
            0,
            ptr::null(),
            0,
            &mut err,
        )
    };
    assert_eq!(
        rc, VEIL_ERR_INVALID_ARG,
        "unknown app must return INVALID_ARG, not crash"
    );
    let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap();
    assert_eq!(msg, "VeilApp: use-after-close or unknown handle");
    unsafe {
        veil_free_string(err);
    }
}

#[test]
fn use_with_unknown_stream_token_returns_error_not_uaf() {
    let bogus = 0x0AF5_0004_usize as *mut VeilStreamFfi;
    let mut err: *mut c_char = ptr::null_mut();
    // len == 0 → no payload deref; control reaches the liveness guard.
    let rc = unsafe { veil_stream_write(bogus, ptr::null(), 0, &mut err) };
    assert_eq!(
        rc, VEIL_ERR_INVALID_ARG,
        "unknown stream must return INVALID_ARG, not crash"
    );
    let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap();
    assert_eq!(msg, "VeilStreamFfi: use-after-close or unknown handle");
    unsafe {
        veil_free_string(err);
    }
}

#[test]
fn null_string_free_is_noop() {
    unsafe {
        veil_free_string(ptr::null_mut());
    }
}

/// Onboarding phrase epic: a freshly generated master phrase is 24 words
/// and round-trips through the production decoder (checksum valid) — the
/// same phrase later drives the deterministic restore.
#[test]
fn generate_master_phrase_roundtrips() {
    let mut phrase: *mut c_char = ptr::null_mut();
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe { veil_generate_master_phrase(&mut phrase, &mut err) };
    assert_eq!(rc, VEIL_OK);
    assert!(!phrase.is_null());
    let s = unsafe { CStr::from_ptr(phrase) }
        .to_str()
        .expect("utf-8 phrase")
        .to_string();
    assert_eq!(s.split(' ').count(), 24);
    assert!(
        veil_identity::master_seed::decode_master_seed_from_phrase(&s).is_ok(),
        "generated phrase must satisfy the master-phrase checksum"
    );
    // Two calls must not collide (fresh entropy each time).
    let mut phrase2: *mut c_char = ptr::null_mut();
    let rc2 = unsafe { veil_generate_master_phrase(&mut phrase2, &mut err) };
    assert_eq!(rc2, VEIL_OK);
    let s2 = unsafe { CStr::from_ptr(phrase2) }.to_str().unwrap();
    assert_ne!(s, s2);
    unsafe {
        veil_free_string(phrase);
        veil_free_string(phrase2);
    }
}

#[test]
fn generate_master_phrase_null_out_is_invalid_arg() {
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe { veil_generate_master_phrase(ptr::null_mut(), &mut err) };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    unsafe { veil_free_string(err) };
}

#[test]
fn connect_to_invalid_path_returns_null() {
    let path = CString::new("/nonexistent/path/that/does/not/exist.sock").unwrap();
    let mut err: *mut c_char = ptr::null_mut();
    let h = unsafe { veil_connect(path.as_bytes().as_ptr(), path.as_bytes().len(), &mut err) };
    assert!(h.is_null());
    assert!(!err.is_null());
    unsafe {
        veil_free_string(err);
    }
}

#[test]
fn connect_with_null_path_returns_null() {
    let mut err: *mut c_char = ptr::null_mut();
    let h = unsafe { veil_connect(ptr::null(), 0, &mut err) };
    assert!(h.is_null());
    assert!(!err.is_null());
    unsafe {
        veil_free_string(err);
    }
}

#[test]
fn null_app_get_id_returns_invalid_arg() {
    let mut buf = [0u8; 32];
    let rc = unsafe { veil_app_get_app_id(ptr::null(), buf.as_mut_ptr()) };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
}

#[test]
fn null_app_get_endpoint_id_returns_zero() {
    let rc = unsafe { veil_app_get_endpoint_id(ptr::null()) };
    assert_eq!(rc, 0);
}

#[test]
fn null_app_close_is_noop() {
    unsafe {
        veil_app_close(ptr::null_mut());
    }
}

#[test]
fn null_stream_close_is_noop() {
    unsafe {
        veil_stream_close(ptr::null_mut());
    }
}

#[test]
fn null_app_send_returns_invalid_arg() {
    let dst_node = [0u8; 32];
    let dst_app = [0u8; 32];
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_send(
            ptr::null_mut(),
            dst_node.as_ptr(),
            dst_app.as_ptr(),
            0,
            ptr::null(),
            0,
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    assert!(!err.is_null());
    unsafe {
        veil_free_string(err);
    }
}

#[test]
fn null_app_realtime_send_returns_invalid_arg() {
    let dst_node = [0u8; 32];
    let dst_app = [0u8; 32];
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_send_realtime(
            ptr::null_mut(),
            dst_node.as_ptr(),
            dst_app.as_ptr(),
            0,
            ptr::null(),
            0,
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    assert!(!err.is_null());
    unsafe {
        veil_free_string(err);
    }
}

#[test]
fn null_app_relay_realtime_send_returns_invalid_arg() {
    let dst_node = [0u8; 32];
    let dst_app = [0u8; 32];
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_send_relay_realtime(
            ptr::null_mut(),
            dst_node.as_ptr(),
            dst_app.as_ptr(),
            0,
            ptr::null(),
            0,
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    assert!(!err.is_null());
    unsafe {
        veil_free_string(err);
    }
}

/// every block_on / blocking_lock FFI entry
/// point must refuse to run when called from inside a Tokio
/// runtime worker (e.g. recv-handler callback) — a re-entrant
/// `block_on` would park the only worker forever. We verify the
/// guard fires by calling `veil_connect` from a tokio task; the
/// runtime context check should trip and surface
/// [`VEIL_ERR_REENTRANT`] / a NULL handle without ever
/// reaching `runtime.block_on`.
#[test]
fn phase647_h6_connect_from_tokio_runtime_returns_reentrant() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let r = rt.block_on(async {
        let path = CString::new("/tmp/veil-h6.sock").unwrap();
        let mut err: *mut c_char = ptr::null_mut();
        let h = unsafe { veil_connect(path.as_bytes().as_ptr(), path.as_bytes().len(), &mut err) };
        let err_string = if err.is_null() {
            String::new()
        } else {
            let s = unsafe { CStr::from_ptr(err) }
                .to_string_lossy()
                .into_owned();
            unsafe {
                veil_free_string(err);
            }
            s
        };
        (h.is_null(), err_string)
    });
    assert!(
        r.0,
        "handle must be NULL when called from inside tokio runtime"
    );
    assert!(
        r.1.contains("would deadlock"),
        "err message should mention deadlock; got: {}",
        r.1
    );
}

/// sanity: the same call from a non-tokio thread must NOT trip
/// the guard (otherwise the guard is broken). We can't actually
/// connect (path is invalid), but the failure mode must be the
/// connect-error path, not the re-entrancy path.
#[test]
fn phase647_h6_connect_from_plain_thread_does_not_trip_guard() {
    let path = CString::new("/nonexistent/h6.sock").unwrap();
    let mut err: *mut c_char = ptr::null_mut();
    let h = unsafe { veil_connect(path.as_bytes().as_ptr(), path.as_bytes().len(), &mut err) };
    assert!(h.is_null());
    assert!(!err.is_null());
    let s = unsafe { CStr::from_ptr(err) }
        .to_string_lossy()
        .into_owned();
    unsafe {
        veil_free_string(err);
    }
    // Real failure is "connect failed:..." — guard would say "would deadlock".
    assert!(
        !s.contains("would deadlock"),
        "guard must NOT fire on a fresh thread; got: {s}"
    );
}

/// zeroize-on-consume variant overwrites
/// the caller's phrase buffer in place. After return, every byte
/// of the original phrase must be `0` — including on the error
/// path (invalid checksum), so a UI bug that retries with the
/// same buffer doesn't keep the secret resident in heap.
#[test]
fn phase647_h8_validate_zeroize_clears_phrase_buffer_on_success() {
    let phrase = fresh_phrase();
    // Explicit-length ABI: pass the content bytes (no NUL terminator).
    let mut buf: Vec<u8> = phrase.as_bytes().to_vec();
    let n = buf.len();
    let buf_ptr = buf.as_mut_ptr();
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe { veil_validate_bip39_phrase_zeroize(buf_ptr, n, &mut err) };
    assert_eq!(rc, VEIL_OK);
    assert!(err.is_null());
    // Every byte must now be 0.
    assert!(
        buf.iter().all(|&b| b == 0),
        "buffer must be fully zeroed; got: {:?}",
        buf
    );
}

#[test]
fn phase647_h8_validate_zeroize_clears_phrase_buffer_on_error() {
    // Crafted invalid phrase (random words but not a real BIP-39).
    let bad = std::ffi::CString::new(
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon zoo",
    )
    .unwrap();
    let mut buf: Vec<u8> = bad.as_bytes().to_vec();
    let n = buf.len();
    let buf_ptr = buf.as_mut_ptr();
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe { veil_validate_bip39_phrase_zeroize(buf_ptr, n, &mut err) };
    assert_eq!(rc, VEIL_ERR); // bad checksum
    if !err.is_null() {
        unsafe {
            veil_free_string(err);
        }
    }
    // Even on the error path the buffer must be zeroed.
    assert!(
        buf.iter().all(|&b| b == 0),
        "buffer must be zeroed on error path; got: {:?}",
        buf
    );
}

/// A `_zeroize` entry point that refuses the call because of a SECONDARY
/// argument must still have wiped the secret.
///
/// The guard used to be armed after those checks, so a NULL device id, a
/// NULL document or a TOML that would not parse returned the documented
/// error with the caller's phrase exactly where they had put it. xVeil
/// wipes its own buffer in a `finally` and never saw it; a C caller
/// following the header has no such second line of defence
/// (report14 V14-M14).
// Two of the three entry points below live behind `node-embedded`, and
// the whole point is the ORDER inside them, so the test follows the gate.
#[cfg(feature = "node-embedded")]
#[test]
fn a_refusal_over_another_argument_still_wipes_the_secret() {
    let dir = tempfile::tempdir().expect("tempdir");
    let dir_s = dir.path().to_str().unwrap();

    // 1. Revoke: valid phrase, NULL device id.
    let phrase = fresh_phrase();
    let mut buf: Vec<u8> = phrase.as_bytes().to_vec();
    let n = buf.len();
    let mut changed: u8 = 0;
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_revoke_identity_device_from_phrase_zeroize(
            buf.as_mut_ptr(),
            n,
            dir_s.as_ptr(),
            dir_s.len(),
            ptr::null(),
            &mut changed,
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    if !err.is_null() {
        unsafe { veil_free_string(err) };
    }
    assert!(
        buf.iter().all(|&b| b == 0),
        "a NULL device_id must not cost the caller their phrase: {buf:?}"
    );

    // 2. Master signing key: valid phrase, NULL output pointer.
    let phrase = fresh_phrase();
    let mut buf: Vec<u8> = phrase.as_bytes().to_vec();
    let n = buf.len();
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_master_signing_key_from_phrase_zeroize(buf.as_mut_ptr(), n, ptr::null_mut(), &mut err)
    };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    if !err.is_null() {
        unsafe { veil_free_string(err) };
    }
    assert!(
        buf.iter().all(|&b| b == 0),
        "a NULL out_master_sk must not cost the caller their phrase: {buf:?}"
    );

    // 3. Restore with a node key: valid phrase, TOML that will not parse.
    let phrase = fresh_phrase();
    let mut buf: Vec<u8> = phrase.as_bytes().to_vec();
    let n = buf.len();
    let junk = b"this is not toml at all {{{";
    let label = "test-device";
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_restore_identity_from_phrase_zeroize_with_node_key(
            buf.as_mut_ptr(),
            n,
            dir_s.as_ptr(),
            dir_s.len(),
            label.as_ptr(),
            label.len(),
            junk.as_ptr(),
            junk.len(),
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    if !err.is_null() {
        unsafe { veil_free_string(err) };
    }
    assert!(
        buf.iter().all(|&b| b == 0),
        "a TOML that would not parse must not cost the caller their \
         phrase: {buf:?}"
    );
}

#[test]
fn phase647_h8_validate_zeroize_rejects_null() {
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe { veil_validate_bip39_phrase_zeroize(ptr::null_mut(), 0, &mut err) };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    assert!(!err.is_null());
    unsafe {
        veil_free_string(err);
    }
}

unsafe extern "C" fn noop_event_cb(
    _user: *mut std::ffi::c_void,
    _kind: u8,
    _payload: *const u8,
    _payload_len: size_t,
) {
}

#[test]
fn null_handle_set_event_handler_returns_invalid_arg() {
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_set_event_handler(
            ptr::null_mut(),
            Some(noop_event_cb),
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    assert!(!err.is_null());
    unsafe {
        veil_free_string(err);
    }
}

/// NULL callback (i.e. `None` after
/// the `Option<fn>` retype) must be rejected with `VEIL_ERR_INVALID_ARG`
/// rather than dereferenced — pre-fix this would have segfaulted.
#[test]
fn null_callback_set_event_handler_returns_invalid_arg() {
    // Note: passing `None` requires a live handle to exercise the
    // post-handle-check path. We use a null handle here to confirm
    // that handle check fires first; a separate test would need a
    // real VeilHandle to hit the cb-check after.
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe { veil_set_event_handler(ptr::null_mut(), None, ptr::null_mut(), &mut err) };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    assert!(!err.is_null());
    unsafe {
        veil_free_string(err);
    }
}

#[test]
fn event_kind_constants_match_proto() {
    assert_eq!(
        VEIL_EVENT_SESSIONS_CHANGED,
        veil_proto::event_kind::SESSIONS_CHANGED
    );
    assert_eq!(
        VEIL_EVENT_MOBILE_TIER_CHANGED,
        veil_proto::event_kind::MOBILE_TIER_CHANGED
    );
    assert_eq!(
        VEIL_EVENT_IDENTITY_ROTATED,
        veil_proto::event_kind::IDENTITY_ROTATED
    );
    assert_eq!(
        VEIL_EVENT_MAILBOX_DRAINED,
        veil_proto::event_kind::MAILBOX_DRAINED
    );
}

// ── Wake-HMAC FFI (Epic 489.10 slice 4.3.3) ──────────────────────

#[test]
fn wake_hmac_constants_match_crypto() {
    assert_eq!(
        VEIL_WAKE_HMAC_KEY_LEN,
        veil_crypto::wake_hmac::WAKE_HMAC_KEY_LEN,
    );
    assert_eq!(
        VEIL_WAKE_PAYLOAD_LEN,
        veil_crypto::wake_hmac::WAKE_PAYLOAD_LEN,
    );
    // Verdict codes are not exposed on the crypto side as integers
    // (they're a Rust enum), but this test pins the FFI mapping
    // contract: 0 = Valid, 1 = Tampered, 2 = Expired, 3 = Malformed.
    assert_eq!(VEIL_WAKE_VERDICT_VALID, 0);
    assert_eq!(VEIL_WAKE_VERDICT_TAMPERED, 1);
    assert_eq!(VEIL_WAKE_VERDICT_EXPIRED, 2);
    assert_eq!(VEIL_WAKE_VERDICT_MALFORMED, 3);
}

#[test]
fn generate_wake_hmac_key_writes_32_bytes() {
    let mut buf = [0u8; 32];
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe { veil_generate_wake_hmac_key(buf.as_mut_ptr(), &mut err) };
    assert_eq!(rc, VEIL_OK);
    assert!(err.is_null());
    // OsRng-generated key is extremely unlikely to be all zeros.
    assert!(buf.iter().any(|&b| b != 0));
}

#[test]
fn generate_wake_hmac_key_rejects_null_out() {
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe { veil_generate_wake_hmac_key(ptr::null_mut(), &mut err) };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    assert!(!err.is_null());
    unsafe { veil_free_string(err) };
}

#[test]
fn verify_wake_hmac_accepts_well_formed_payload() {
    let key = veil_crypto::wake_hmac::WakeHmacKey::from_bytes([1u8; 32]);
    let cid = [2u8; 32];
    let rid = [3u8; 32];
    let ts = 1_700_000_000u64;
    let tag = veil_crypto::wake_hmac::compute_wake_hmac(&key, ts, &cid, &rid);
    let payload = veil_crypto::wake_hmac::encode_wake_payload(ts, &cid, &tag);
    let mut verdict: c_int = -1;
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_verify_wake_hmac(
            key.as_bytes().as_ptr(),
            payload.as_ptr(),
            payload.len(),
            rid.as_ptr(),
            ts + 10,
            &mut verdict,
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_OK);
    assert_eq!(verdict, VEIL_WAKE_VERDICT_VALID);
    assert!(err.is_null());
}

#[test]
fn verify_wake_hmac_rejects_forged_payload_silently() {
    let key = veil_crypto::wake_hmac::WakeHmacKey::from_bytes([1u8; 32]);
    let wrong_key = veil_crypto::wake_hmac::WakeHmacKey::from_bytes([2u8; 32]);
    let cid = [2u8; 32];
    let rid = [3u8; 32];
    let ts = 1_700_000_000u64;
    let forged_tag = veil_crypto::wake_hmac::compute_wake_hmac(&wrong_key, ts, &cid, &rid);
    let payload = veil_crypto::wake_hmac::encode_wake_payload(ts, &cid, &forged_tag);
    let mut verdict: c_int = -1;
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_verify_wake_hmac(
            key.as_bytes().as_ptr(),
            payload.as_ptr(),
            payload.len(),
            rid.as_ptr(),
            ts + 10,
            &mut verdict,
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_OK);
    assert_eq!(verdict, VEIL_WAKE_VERDICT_TAMPERED);
}

#[test]
fn verify_wake_hmac_surfaces_expired_distinct_from_tampered() {
    let key = veil_crypto::wake_hmac::WakeHmacKey::from_bytes([1u8; 32]);
    let cid = [2u8; 32];
    let rid = [3u8; 32];
    let ts = 1_700_000_000u64;
    let tag = veil_crypto::wake_hmac::compute_wake_hmac(&key, ts, &cid, &rid);
    let payload = veil_crypto::wake_hmac::encode_wake_payload(ts, &cid, &tag);
    let now_far_future = ts + veil_crypto::wake_hmac::WAKE_FRESHNESS_SECS + 1;
    let mut verdict: c_int = -1;
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_verify_wake_hmac(
            key.as_bytes().as_ptr(),
            payload.as_ptr(),
            payload.len(),
            rid.as_ptr(),
            now_far_future,
            &mut verdict,
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_OK);
    assert_eq!(verdict, VEIL_WAKE_VERDICT_EXPIRED);
}

#[test]
fn verify_wake_hmac_rejects_malformed_length() {
    let key = [0u8; 32];
    let rid = [0u8; 32];
    let short = [0u8; VEIL_WAKE_PAYLOAD_LEN - 1];
    let mut verdict: c_int = -1;
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_verify_wake_hmac(
            key.as_ptr(),
            short.as_ptr(),
            short.len(),
            rid.as_ptr(),
            1_700_000_000,
            &mut verdict,
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_OK);
    assert_eq!(verdict, VEIL_WAKE_VERDICT_MALFORMED);
}

#[test]
fn verify_wake_hmac_rejects_null_args() {
    let key = [0u8; 32];
    let mut verdict: c_int = -1;
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_verify_wake_hmac(
            ptr::null(),
            ptr::null(),
            0,
            key.as_ptr(),
            0,
            &mut verdict,
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    assert!(!err.is_null());
    unsafe { veil_free_string(err) };
}

// ── BIP-39 restore FFI ───────────────────────────────────────

fn fresh_phrase() -> std::ffi::CString {
    // Generate a fresh master_seed and convert to its BIP-39 phrase.
    // This guarantees the phrase is well-formed (24 words, valid
    // checksum) without hardcoding a secret in the test.
    let seed = veil_identity::master_seed::generate_master_seed();
    let mnemonic =
        veil_identity::master_seed::encode_master_seed_to_phrase(&seed).expect("seed → phrase");
    std::ffi::CString::new(mnemonic.to_string()).unwrap()
}

#[test]
fn sovereign_signer_is_one_burst_phrase_bound_and_zeroizing() {
    let phrase = fresh_phrase();
    let mut phrase_buf = phrase.as_bytes().to_vec();
    let phrase_len = phrase_buf.len();
    let mut signer: *mut VeilSovereignSigner = ptr::null_mut();
    let mut node_id = [0u8; 32];
    let mut public_key = [0u8; 32];
    let mut err: *mut c_char = ptr::null_mut();

    let rc = unsafe {
        veil_sovereign_signer_open_from_phrase_zeroize(
            phrase_buf.as_mut_ptr(),
            phrase_len,
            &mut signer,
            node_id.as_mut_ptr(),
            node_id.len(),
            public_key.as_mut_ptr(),
            public_key.len(),
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_OK);
    assert!(err.is_null());
    assert!(!signer.is_null());
    assert!(phrase_buf.iter().all(|byte| *byte == 0));
    assert_eq!(node_id, veil_crypto::identity::compute_node_id(&public_key));

    let message = b"xveil-device-membership-v2";
    let mut signature = [0u8; 64];
    let rc = unsafe {
        veil_sovereign_signer_sign(
            signer,
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
            signature.len(),
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_OK);
    assert!(err.is_null());
    ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .expect("valid sovereign public key")
        .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
        .expect("signature verifies against exported public key");

    unsafe { veil_sovereign_signer_close(signer) };
    let rc = unsafe {
        veil_sovereign_signer_sign(
            signer,
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
            signature.len(),
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_ERR_CLOSED);
    assert!(!err.is_null());
    unsafe {
        veil_free_string(err);
        veil_sovereign_signer_close(signer);
    }
}

#[test]
fn sovereign_signer_rejects_invalid_phrase_after_wiping_it() {
    let mut phrase_buf = b"not a recovery phrase".to_vec();
    let phrase_len = phrase_buf.len();
    let mut signer: *mut VeilSovereignSigner = ptr::null_mut();
    let mut node_id = [0u8; 32];
    let mut public_key = [0u8; 32];
    let mut err: *mut c_char = ptr::null_mut();

    let rc = unsafe {
        veil_sovereign_signer_open_from_phrase_zeroize(
            phrase_buf.as_mut_ptr(),
            phrase_len,
            &mut signer,
            node_id.as_mut_ptr(),
            node_id.len(),
            public_key.as_mut_ptr(),
            public_key.len(),
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_ERR);
    assert!(signer.is_null());
    assert!(phrase_buf.iter().all(|byte| *byte == 0));
    assert!(!err.is_null());
    unsafe { veil_free_string(err) };
}

#[test]
fn sovereign_hybrid_bundle_ffi_round_trip_is_variable_length_and_zeroizing() {
    let phrase = fresh_phrase();
    let mut create_phrase = phrase.as_bytes().to_vec();
    let create_len = create_phrase.len();
    let mut bundle_ptr: *mut u8 = ptr::null_mut();
    let mut bundle_len = 0usize;
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_sovereign_bundle_create_hybrid512_zeroize(
            create_phrase.as_mut_ptr(),
            create_len,
            &mut bundle_ptr,
            &mut bundle_len,
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_OK);
    assert!(err.is_null());
    assert!(create_phrase.iter().all(|byte| *byte == 0));
    assert!(!bundle_ptr.is_null());
    let bundle = unsafe { std::slice::from_raw_parts(bundle_ptr, bundle_len) };

    let mut open_phrase = phrase.as_bytes().to_vec();
    let open_len = open_phrase.len();
    let mut signer: *mut VeilSovereignSigner = ptr::null_mut();
    let mut algorithm = 0u8;
    let mut node_id = [0u8; 32];
    let mut public_key = [0u8; 1024];
    let mut public_key_len = 0usize;
    let rc = unsafe {
        veil_sovereign_signer_open_bundle_zeroize(
            bundle.as_ptr(),
            bundle.len(),
            open_phrase.as_mut_ptr(),
            open_len,
            &mut signer,
            &mut algorithm,
            node_id.as_mut_ptr(),
            node_id.len(),
            public_key.as_mut_ptr(),
            public_key.len(),
            &mut public_key_len,
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_OK);
    assert!(err.is_null());
    assert!(open_phrase.iter().all(|byte| *byte == 0));
    assert_eq!(
        algorithm,
        veil_types::SignatureAlgorithm::Ed25519Falcon512Hybrid.wire_byte()
    );
    assert_eq!(public_key_len, 929);
    assert_eq!(
        node_id,
        veil_crypto::identity::compute_node_id(&public_key[..public_key_len])
    );

    let message = b"xveil-sovereign-hybrid-probe";
    let mut signature = [0u8; 1024];
    let mut signature_len = 0usize;
    let rc = unsafe {
        veil_sovereign_signer_sign_into(
            signer,
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
            signature.len(),
            &mut signature_len,
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_OK);
    assert!(signature_len > 64);
    let mut valid = false;
    let rc = unsafe {
        veil_sovereign_verify(
            algorithm,
            node_id.as_ptr(),
            public_key.as_ptr(),
            public_key_len,
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
            signature_len,
            &mut valid,
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_OK);
    assert!(valid);

    unsafe {
        veil_sovereign_signer_close(signer);
        veil_free_buf(bundle_ptr, bundle_len);
    }
}

#[test]
fn sovereign_recovery_certificate_ffi_preserves_node_id_and_wipes_codes() {
    let phrase = fresh_phrase();
    let mut create_phrase = phrase.as_bytes().to_vec();
    let create_len = create_phrase.len();
    let mut bundle_ptr: *mut u8 = ptr::null_mut();
    let mut bundle_len = 0usize;
    let mut err: *mut c_char = ptr::null_mut();
    assert_eq!(
        unsafe {
            veil_sovereign_bundle_create_hybrid512_zeroize(
                create_phrase.as_mut_ptr(),
                create_len,
                &mut bundle_ptr,
                &mut bundle_len,
                &mut err,
            )
        },
        VEIL_OK
    );

    let mut export_phrase = phrase.as_bytes().to_vec();
    let export_phrase_len = export_phrase.len();
    let mut export_code = b"xvrc-ffi-code-with-more-than-thirty-two-randomish-bytes".to_vec();
    let export_code_len = export_code.len();
    let mut certificate_ptr: *mut u8 = ptr::null_mut();
    let mut certificate_len = 0usize;
    assert_eq!(
        unsafe {
            veil_sovereign_recovery_certificate_export_zeroize(
                bundle_ptr,
                bundle_len,
                export_phrase.as_mut_ptr(),
                export_phrase_len,
                export_code.as_mut_ptr(),
                export_code_len,
                &mut certificate_ptr,
                &mut certificate_len,
                &mut err,
            )
        },
        VEIL_OK
    );
    assert!(err.is_null());
    assert!(export_phrase.iter().all(|byte| *byte == 0));
    assert!(export_code.iter().all(|byte| *byte == 0));
    let certificate =
        unsafe { std::slice::from_raw_parts(certificate_ptr.cast_const(), certificate_len) };
    assert_eq!(&certificate[..4], b"XVRC");

    let mut open_code = b"xvrc-ffi-code-with-more-than-thirty-two-randomish-bytes".to_vec();
    let open_code_len = open_code.len();
    let mut signer: *mut VeilSovereignSigner = ptr::null_mut();
    let mut algorithm = 0u8;
    let mut node_id = [0u8; 32];
    let mut public_key = [0u8; 1024];
    let mut public_key_len = 0usize;
    assert_eq!(
        unsafe {
            veil_sovereign_signer_open_recovery_certificate_zeroize(
                certificate.as_ptr(),
                certificate.len(),
                open_code.as_mut_ptr(),
                open_code_len,
                &mut signer,
                &mut algorithm,
                node_id.as_mut_ptr(),
                node_id.len(),
                public_key.as_mut_ptr(),
                public_key.len(),
                &mut public_key_len,
                &mut err,
            )
        },
        VEIL_OK
    );
    assert!(err.is_null());
    assert!(open_code.iter().all(|byte| *byte == 0));
    assert_eq!(public_key_len, 929);
    assert_eq!(
        node_id,
        veil_crypto::identity::compute_node_id(&public_key[..public_key_len])
    );
    assert_eq!(&certificate[6..38], &node_id);

    unsafe {
        veil_sovereign_signer_close(signer);
        veil_free_buf(certificate_ptr, certificate_len);
        veil_free_buf(bundle_ptr, bundle_len);
    }
}

// (validate accept/garbage/null are covered by the `phase647_h8_*` zeroize
// tests above; the non-zeroize `veil_validate_bip39_phrase` was removed in
// the explicit-length ABI migration.)

#[test]
fn epic489_8_restore_writes_identity_files() {
    // End-to-end: valid phrase + tempdir → produces signed identity
    // document + instance file + identity_sk on disk. Uses the zeroize
    // restore variant (explicit-length ABI; the phrase buffer is wiped).
    let dir = tempfile::tempdir().expect("tempdir");
    let phrase = fresh_phrase();
    let mut pbuf = phrase.as_bytes().to_vec();
    let pbuf_len = pbuf.len();
    let dir_s = dir.path().to_str().unwrap();
    let label = "test-device";
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_restore_identity_from_phrase_zeroize(
            pbuf.as_mut_ptr(),
            pbuf_len,
            dir_s.as_ptr(),
            dir_s.len(),
            label.as_ptr(),
            label.len(),
            &mut err,
        )
    };
    if rc != VEIL_OK {
        let detail = unsafe { CStr::from_ptr(err).to_string_lossy().into_owned() };
        unsafe {
            veil_free_string(err);
        }
        panic!("restore failed: {detail}");
    }
    assert!(
        dir.path().join("identity_document.bin").exists(),
        "identity_document.bin must be written"
    );
}

#[test]
fn epic489_8_restore_same_phrase_yields_same_node_id() {
    // Critical: BIP-39 → master_seed → master_pk → node_id is
    // DETERMINISTIC. Restoring on Device A and Device B from the
    // same phrase MUST give the same node_id (that's the whole
    // point of identity recovery). Each zeroize call wipes its buffer,
    // so we materialize a fresh phrase buffer per device.
    let phrase = fresh_phrase();
    let label = "dev";

    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let dir_a_s = dir_a.path().to_str().unwrap();
    let dir_b_s = dir_b.path().to_str().unwrap();
    let mut err: *mut c_char = ptr::null_mut();

    let mut pbuf_a = phrase.as_bytes().to_vec();
    let pbuf_a_len = pbuf_a.len();
    let rc_a = unsafe {
        veil_restore_identity_from_phrase_zeroize(
            pbuf_a.as_mut_ptr(),
            pbuf_a_len,
            dir_a_s.as_ptr(),
            dir_a_s.len(),
            label.as_ptr(),
            label.len(),
            &mut err,
        )
    };
    assert_eq!(rc_a, VEIL_OK);
    let mut pbuf_b = phrase.as_bytes().to_vec();
    let pbuf_b_len = pbuf_b.len();
    let rc_b = unsafe {
        veil_restore_identity_from_phrase_zeroize(
            pbuf_b.as_mut_ptr(),
            pbuf_b_len,
            dir_b_s.as_ptr(),
            dir_b_s.len(),
            label.as_ptr(),
            label.len(),
            &mut err,
        )
    };
    assert_eq!(rc_b, VEIL_OK);

    // Both files start with the same node_id field (first 32 bytes
    // after magic "ID" + version + master_algo). We just
    // byte-compare the node_id range, not decode the full document.
    let bytes_a = std::fs::read(dir_a.path().join("identity_document.bin")).unwrap();
    let bytes_b = std::fs::read(dir_b.path().join("identity_document.bin")).unwrap();
    // Magic "ID" (2) + version (1) + master_algo (1) = 4 byte prefix
    // before node_id.
    assert_eq!(
        &bytes_a[4..36],
        &bytes_b[4..36],
        "same phrase MUST produce same node_id (BIP-39 deterministic)"
    );
}

// ── Wake-HMAC put + replica-lookup FFI (Epic 489.10 slice 4.3.4) ──

/// `veil_mailbox_put_with_wake_hmac` must exist with the full arg
/// set (incl. the wake bytes) and reject a NULL handle up-front with
/// `VEIL_ERR_INVALID_ARG` — i.e. the wake-arg slot is wired through
/// without needing a live daemon. Compile-time presence of the symbol
/// with this exact signature is itself part of what we're asserting.
#[test]
fn mailbox_put_with_wake_hmac_rejects_null_handle() {
    let id = [7u8; 32];
    let wake = [0xABu8; 16];
    let mut err: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_mailbox_put_with_wake_hmac(
            ptr::null_mut(), // handle
            id.as_ptr(),     // receiver_id
            id.as_ptr(),     // content_id
            id.as_ptr(),     // sender_id
            ptr::null(),     // blob
            0,
            ptr::null(), // push_envelope
            0,
            ptr::null(), // capability_token
            0,
            wake.as_ptr(), // wake_hmac_envelope
            wake.len(),
            ptr::null_mut(), // out_evicted
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    assert!(!err.is_null());
    unsafe { veil_free_string(err) };
}

/// The legacy `veil_mailbox_put` / `_with_capability` exports must
/// keep their original ABI — same arg arity, same NULL-handle
/// rejection. (A signature drift would fail to compile here.)
#[test]
fn legacy_mailbox_put_exports_keep_abi() {
    let id = [5u8; 32];
    let mut err: *mut c_char = ptr::null_mut();
    let rc1 = unsafe {
        veil_mailbox_put(
            ptr::null_mut(),
            id.as_ptr(),
            id.as_ptr(),
            id.as_ptr(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc1, VEIL_ERR_INVALID_ARG);
    unsafe { veil_free_string(err) };
    err = ptr::null_mut();
    let rc2 = unsafe {
        veil_mailbox_put_with_capability(
            ptr::null_mut(),
            id.as_ptr(),
            id.as_ptr(),
            id.as_ptr(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc2, VEIL_ERR_INVALID_ARG);
    unsafe { veil_free_string(err) };
}

/// `veil_lookup_rendezvous_replicas` must reject NULL out-params
/// up-front and leave them in the documented empty/failure state.
#[test]
fn lookup_rendezvous_replicas_rejects_null_out_params() {
    let id = [9u8; 32];
    let mut err: *mut c_char = ptr::null_mut();
    // NULL handle → INVALID_ARG (null_check! fires before any deref).
    let rc = unsafe {
        veil_lookup_rendezvous_replicas(
            ptr::null_mut(),
            id.as_ptr(),
            0,
            ptr::null_mut(), // out_buf
            ptr::null_mut(), // out_len
            &mut err,
        )
    };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    assert!(!err.is_null());
    unsafe { veil_free_string(err) };
}

/// `veil_free_replica_buf(NULL, _)` is a documented no-op.
#[test]
fn free_replica_buf_null_is_noop() {
    unsafe {
        veil_free_replica_buf(ptr::null_mut(), 0);
        veil_free_replica_buf(ptr::null_mut(), 9999);
    }
}

/// Independent parser for the replica wire layout documented on
/// `veil_lookup_rendezvous_replicas` — decodes back to
/// `(relay_node_id, valid_until, push, cap, wake)` tuples WITHOUT
/// reusing the serializer, so a layout change in either direction
/// fails the round-trip.
#[allow(clippy::type_complexity)]
fn parse_replica_buf(buf: &[u8]) -> Vec<([u8; 32], u64, Vec<u8>, Vec<u8>, Vec<u8>, u8, Vec<u8>)> {
    let mut off = 0usize;
    let take = |buf: &[u8], off: &mut usize, n: usize| -> Vec<u8> {
        let out = buf[*off..*off + n].to_vec();
        *off += n;
        out
    };
    let count = u32::from_le_bytes(take(buf, &mut off, 4).try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let mut rid = [0u8; 32];
        rid.copy_from_slice(&take(buf, &mut off, 32));
        let valid = u64::from_le_bytes(take(buf, &mut off, 8).try_into().unwrap());
        let mut blobs: Vec<Vec<u8>> = Vec::with_capacity(3);
        for _ in 0..3 {
            let len = u16::from_le_bytes(take(buf, &mut off, 2).try_into().unwrap()) as usize;
            blobs.push(take(buf, &mut off, len));
        }
        let wake = blobs.pop().unwrap();
        let cap = blobs.pop().unwrap();
        let push = blobs.pop().unwrap();
        // v5 KEM trailer: algo byte + u16-len-prefixed pubkey.
        let kem_algo = take(buf, &mut off, 1)[0];
        let kem_len = u16::from_le_bytes(take(buf, &mut off, 2).try_into().unwrap()) as usize;
        let kem_pk = take(buf, &mut off, kem_len);
        out.push((rid, valid, push, cap, wake, kem_algo, kem_pk));
    }
    assert_eq!(off, buf.len(), "no trailing bytes in replica buffer");
    out
}

#[test]
fn serialize_replica_buf_roundtrips_layout() {
    let replicas = vec![
        veilclient::RendezvousReplicaInfo {
            relay_node_id: [0x11; 32],
            valid_until_unix: 1_700_000_000,
            push_envelope: vec![1, 2, 3, 4, 5],
            capability_token: vec![9, 8, 7],
            wake_hmac_envelope: vec![0xAA, 0xBB],
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: vec![0xCC, 0xDD, 0xEE],
        },
        // Second entry exercises empty blobs (all len-prefixes 0, incl. KEM).
        veilclient::RendezvousReplicaInfo {
            relay_node_id: [0x22; 32],
            valid_until_unix: 0,
            push_envelope: vec![],
            capability_token: vec![],
            wake_hmac_envelope: vec![],
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: vec![],
        },
    ];
    let buf = serialize_replica_buf(&replicas);
    // count(4) + entry0 (32+8 + (2+5)+(2+3)+(2+2) + 1+(2+3))
    //          + entry1 (32+8 + 2+2+2 + 1+2)
    let expected_len = 4 + (32 + 8 + 7 + 5 + 4 + 1 + 5) + (32 + 8 + 2 + 2 + 2 + 1 + 2);
    assert_eq!(buf.len(), expected_len, "exact serialized length");

    let parsed = parse_replica_buf(&buf);
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].0, [0x11; 32]);
    assert_eq!(parsed[0].1, 1_700_000_000);
    assert_eq!(parsed[0].2, vec![1, 2, 3, 4, 5]);
    assert_eq!(parsed[0].3, vec![9, 8, 7]);
    assert_eq!(parsed[0].4, vec![0xAA, 0xBB]);
    assert_eq!(parsed[0].5, 0);
    assert_eq!(parsed[0].6, vec![0xCC, 0xDD, 0xEE]);
    assert_eq!(parsed[1].0, [0x22; 32]);
    assert_eq!(parsed[1].1, 0);
    assert!(parsed[1].2.is_empty());
    assert!(parsed[1].3.is_empty());
    assert!(parsed[1].4.is_empty());
    assert_eq!(parsed[1].5, 0);
    assert!(parsed[1].6.is_empty());
}

#[test]
fn serialize_replica_buf_empty_is_count_header_only() {
    let buf = serialize_replica_buf(&[]);
    assert_eq!(
        buf,
        vec![0, 0, 0, 0],
        "empty list = u32 count 0, nothing else"
    );
    // And it round-trips back to an empty parse.
    assert!(parse_replica_buf(&buf).is_empty());
}

/// The (ptr, len) the C entry-point leaks must be reconstructable by
/// `veil_free_replica_buf` with no leak/double-free. Mirror the
/// shrink_to_fit + forget + from_raw_parts dance the export performs.
#[test]
fn replica_buf_leak_then_free_roundtrips() {
    let replicas = vec![veilclient::RendezvousReplicaInfo {
        relay_node_id: [0x33; 32],
        valid_until_unix: 42,
        push_envelope: vec![0; 10],
        capability_token: vec![1; 4],
        wake_hmac_envelope: vec![2; 6],
        rendezvous_kem_algo: 0,
        rendezvous_kem_pk: vec![3; 8],
    }];
    let mut buf = serialize_replica_buf(&replicas);
    buf.shrink_to_fit();
    let len = buf.len();
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    // Caller would parse here; we just confirm the free path is sound
    // (run under `cargo test` / Miri this proves no double-free / leak).
    unsafe { veil_free_replica_buf(ptr, len) };
}

#[cfg(feature = "node-embedded")]
#[test]
fn ephemeral_service_registration_zeroizes_seed_before_dead_handle_error() {
    let mut seed = [0xA5u8; 32];
    let mut public_key = [0u8; 32];
    let mut error: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_register_ephemeral_onion_service_zeroize(
            ptr::dangling_mut::<VeilHandle>(),
            seed.as_mut_ptr(),
            3,
            public_key.as_mut_ptr(),
            &mut error,
        )
    };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    assert_eq!(seed, [0u8; 32], "writable caller seed is always scrubbed");
    assert!(!error.is_null());
    unsafe { veil_free_string(error) };
}

#[cfg(feature = "node-embedded")]
#[test]
fn ephemeral_service_registration_rejects_zero_seed_after_scrub() {
    let mut seed = [0u8; 32];
    let mut public_key = [0u8; 32];
    let mut error: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_register_ephemeral_onion_service_zeroize(
            ptr::dangling_mut::<VeilHandle>(),
            seed.as_mut_ptr(),
            3,
            public_key.as_mut_ptr(),
            &mut error,
        )
    };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    assert_eq!(seed, [0u8; 32]);
    assert!(!error.is_null());
    unsafe { veil_free_string(error) };
}

#[cfg(feature = "node-embedded")]
#[test]
fn provider_slot_registration_rejects_range_after_seed_scrub() {
    let mut seed = [0x5Au8; 32];
    let mut public_key = [0u8; 32];
    let mut error: *mut c_char = ptr::null_mut();
    let rc = unsafe {
        veil_register_ephemeral_onion_service_zeroize_v2(
            ptr::dangling_mut::<VeilHandle>(),
            seed.as_mut_ptr(),
            3,
            veil_anonymity::blinded_descriptor::MAX_PROVIDER_SLOTS,
            public_key.as_mut_ptr(),
            &mut error,
        )
    };
    assert_eq!(rc, VEIL_ERR_INVALID_ARG);
    assert_eq!(seed, [0u8; 32], "invalid slot still scrubs caller seed");
    assert!(!error.is_null());
    unsafe { veil_free_string(error) };
}
