//! Fuzz target for `SessionCipher::open`.
//!
//! Verifies that decrypting arbitrary ciphertext never panics, regardless of
//! the input. Authentication failures must return `Err`, not panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

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

    // Try both directions (is_tx = true and false).
    for is_tx in [true, false] {
        let mut cipher = veilcore::crypto::session_cipher::SessionCipher::new(&key, is_tx);
        // AAD: use a fixed known-good value (family=0, msg_type=0).
        let aad = veilcore::crypto::session_cipher::frame_aad(0, 0);
        let _ = cipher.open(ciphertext, &aad); // must not panic
    }
});
