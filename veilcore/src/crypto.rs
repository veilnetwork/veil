//! Re-export shim for the extracted [`veil-crypto`](veil_crypto) crate.
//!
//! the crate split moved all cryptographic primitives —
//! Ed25519/Falcon-512 signatures, X25519 + ML-KEM-768 X3DH key exchange
//! ChaCha20-Poly1305 AEAD session cipher, BLAKE3, PoW score — out to a
//! standalone Tier-1 crate. This module preserves the existing
//! `crate::crypto::X` import paths so the rest of veilcore (cfg, node
//! cmd, sim, …) does not need a mass find/replace.
//!
//! New code should prefer importing from `veil_crypto` directly.

pub use veil_crypto::*;
