//! Fuzz target for `SessionCipher::open`.
//!
//! Verifies that decrypting arbitrary ciphertext never panics, regardless of
//! the input. Authentication failures must return `Err`, not panic.
//!
//! ## The AAD is the whole header now
//!
//! This target used to call `session_cipher::frame_aad(0, 0)` with a comment
//! calling that "a fixed known-good value (family=0, msg_type=0)". Audit V-01
//! moved the function to `veil_proto::codec`, gave it a `&FrameHeader`, and
//! widened what it covers from those three bytes to the ENTIRE 24-byte wire
//! header — because on `tcp://`, `ws://` and `socks://` an on-path attacker
//! could otherwise rewrite `stream_id`, `flags` and the lengths of an
//! authentic frame.
//!
//! The target did not follow, so it stopped compiling — and a fuzz target that
//! does not build is coverage nobody is getting. Nothing noticed: the CI steps
//! that touch this crate read its lockfile and never build its targets.
//!
//! Since the AAD is now 24 bytes rather than 3, the header is DERIVED from the
//! input instead of pinned. `open` must not panic for any associated data, and
//! pinning one value would leave the twenty-one bytes the audit added
//! unexercised.
#![no_main]
use libfuzzer_sys::fuzz_target;
use veilcore::proto::{FrameHeader, HEADER_SIZE, VERSION};

/// Big-endian read of `n` bytes at `at`, zero where the input runs out.
///
/// Total by construction: a fuzz target that can panic while BUILDING its own
/// input reports its own bug as the library's.
fn take(data: &[u8], at: usize, n: usize) -> u64 {
    let mut v = 0u64;
    for i in 0..n {
        v = (v << 8) | u64::from(data.get(at + i).copied().unwrap_or(0));
    }
    v
}

fuzz_target!(|data: &[u8]| {
    // Use first 32 bytes as key (pad with zeros if shorter), rest as ciphertext.
    let mut key = [0u8; 32];
    let ciphertext = if data.len() >= 32 {
        key.copy_from_slice(&data[..32]);
        &data[32..]
    } else {
        key[..data.len()].copy_from_slice(data);
        &[][..]
    };

    // The AAD's own bytes come from the ciphertext side, so the key stays
    // whatever the first 32 bytes said and the two inputs do not shadow each
    // other.
    let header = FrameHeader {
        version: VERSION,
        family: take(ciphertext, 0, 1) as u8,
        msg_type: take(ciphertext, 1, 2) as u16,
        flags: take(ciphertext, 3, 2) as u16,
        header_len: HEADER_SIZE as u16,
        body_len: take(ciphertext, 5, 4) as u32,
        stream_id: take(ciphertext, 9, 4) as u32,
        request_id: take(ciphertext, 13, 4) as u32,
    };
    let aad = veilcore::proto::codec::frame_aad(&header);

    // Try both directions (is_tx = true and false).
    for is_tx in [true, false] {
        let mut cipher = veilcore::crypto::session_cipher::SessionCipher::new(&key, is_tx);
        let _ = cipher.open(ciphertext, &aad); // must not panic
    }
});
