//! Veil network cryptographic primitives.
//!
//! extraction from `veilcore`. Pure crypto with no
//! cfg-layer or proto-layer dependencies — depends only on
//! veil-types, veil-util, veil-error.

pub mod identity;
pub mod identity_fingerprint;
pub mod kex;
pub mod key_blinding;
pub mod pair_oob;
pub mod pow;
pub mod session_cipher;
pub mod session_kdf;
pub mod signature;
pub mod types;
pub mod wake_hmac;
pub mod x3dh;

pub use pow::{
    DEFAULT_POW_DIFFICULTY, DEFAULT_POW_TIMEOUT_SECS, PowParams, PowProgress, PowResult, PowScore,
    PowStopReason, available_thread_count, default_nonce_base64, pow_score, reset_interrupt_flag,
    search_nonce,
};
pub use signature::{GeneratedKeyPair, generate_keypair, sign_message, verify_message};
pub use types::{Base64Nonce, Base64PrivateKey, Base64PublicKey};
