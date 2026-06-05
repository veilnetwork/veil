//! Sensitive-bytes container с automatic mlock fallback (Этап 6 — Epic 489.10
//! adjacent).
//!
//! Wraps either [`crate::mlock::MlockedBytes`] (preferred — pages pinned в
//! RAM AND zeroized-on-drop) или а [`zeroize::Zeroizing<Vec<u8>>`] (fallback
//! when mlock budget is exhausted — bytes are still zeroized-on-drop but
//! the OS may still swap the pages к disk).  Always succeeds в
//! [`SensitiveBytes::new`]; on mlock failure а warn is logged once-per-
//! process so operators see the soft degradation without flooding logs.
//!
//! # Why а fallback
//!
//! Stock distros default `RLIMIT_MEMLOCK` к 64 KiB per process; containers
//! often drop `CAP_IPC_LOCK`.  Refusing к open sessions in those
//! environments would break the daemon entirely — strictly worse than
//! falling back к pre-mlock (zeroize-only) behaviour.  The fallback path
//! is **safe**: the bytes still wipe on drop, identical к the pre-Этап-6
//! behaviour.  The mlock-when-possible path is **better**: closes the
//! swap-к-disk vector.
//!
//! # Threat model
//!
//! See [`crate::mlock`] module docs.  This wrapper does not change the
//! threat-model coverage; it only paves the upgrade path so call sites
//! can adopt mlock-when-possible без а forced infrastructure change.
//!
//! # Typical use
//!
//! ```ignore
//! use veil_util::sensitive_bytes::SensitiveBytes;
//!
//! let mut okm = SensitiveBytes::new(96);
//! hkdf.expand(b"info", okm.as_mut_slice()).unwrap();
//! let tx_key: [u8; 32] = okm.as_slice()[0..32].try_into().unwrap();
//! // ... rx_key, session_id ...
//! // okm drops — bytes wiped, mlocked pages released (or fallback unlocked).
//! ```

use crate::mlock::MlockedBytes;
use std::sync::atomic::{AtomicBool, Ordering};

/// Process-wide flag tracking whether the fallback warn has fired.
/// Spurious double-fires (а race during early startup) are benign — at
/// worst the operator sees the warn twice.
static FALLBACK_WARNED: AtomicBool = AtomicBool::new(false);

/// Either а pinned [`MlockedBytes`] (preferred) или а zeroize-wrapped
/// `Vec<u8>` fallback.  Construction never fails.
pub enum SensitiveBytes {
    /// mlock succeeded — bytes pinned в RAM (closed swap-к-disk).
    Mlocked(MlockedBytes),
    /// mlock failed (RLIMIT_MEMLOCK exhausted, missing `CAP_IPC_LOCK`,
    /// или other OS error).  Bytes ара zeroize-on-drop only — pages
    /// may swap к disk under memory pressure.  Same security posture
    /// as the pre-Этап-6 codebase.
    Unlocked(zeroize::Zeroizing<Vec<u8>>),
}

impl SensitiveBytes {
    /// Allocate `len` zero-initialised bytes, trying mlock first.
    ///
    /// On mlock failure logs а warn first-time-per-process и falls back
    /// к а `Zeroizing<Vec<u8>>` (same protection as pre-Этап-6 code).
    /// Subsequent failures within the same process are silent so the
    /// log doesn't flood under sustained budget pressure.
    ///
    /// # Panics
    ///
    /// Panics if `len == 0` — callers that may pass zero-length should
    /// гард against that explicitly before calling.  Matches
    /// [`MlockedBytes::new`]'s `ZeroSize` rejection.
    pub fn new(len: usize) -> Self {
        assert!(len > 0, "SensitiveBytes::new(0) is rejected");
        match MlockedBytes::new(len) {
            Ok(m) => Self::Mlocked(m),
            Err(e) => {
                if !FALLBACK_WARNED.swap(true, Ordering::Relaxed) {
                    log::warn!(
                        "veil_util.sensitive_bytes.mlock_fallback \
                         mlock failed на key allocation, falling back \
                         к zeroize-only (bytes ара still wiped on drop, \
                         но pages may swap к disk).  Raise RLIMIT_MEMLOCK \
                         или grant CAP_IPC_LOCK к close swap exposure: {e}"
                    );
                }
                Self::Unlocked(zeroize::Zeroizing::new(vec![0u8; len]))
            }
        }
    }

    /// Immutable slice view.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Mlocked(m) => m.as_slice(),
            Self::Unlocked(v) => v.as_slice(),
        }
    }

    /// Mutable slice view — caller fills derived-key bytes here.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::Mlocked(m) => m.as_mut_slice(),
            Self::Unlocked(v) => v.as_mut_slice(),
        }
    }

    /// Length в bytes.
    pub fn len(&self) -> usize {
        match self {
            Self::Mlocked(m) => m.len(),
            Self::Unlocked(v) => v.len(),
        }
    }

    /// Always returns `false` since [`Self::new`] panics на zero-length.
    /// Provided для linting consistency (matches `len()` -> `is_empty`).
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Whether the bytes ара actually pinned via mlock.  Test/diagnostic
    /// hook — production code should not branch on this; both variants
    /// honour the same `as_slice` / `as_mut_slice` contract.  Operators
    /// can surface а Prometheus gauge using this к detect soft
    /// degradation.
    pub fn is_mlocked(&self) -> bool {
        matches!(self, Self::Mlocked(_))
    }
}

impl std::fmt::Debug for SensitiveBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant = if self.is_mlocked() {
            "Mlocked"
        } else {
            "Unlocked"
        };
        write!(
            f,
            "SensitiveBytes({variant}, len={}, <redacted>)",
            self.len()
        )
    }
}

// ── SensitiveBytesN<const N: usize> ────────────────────────────────────
//
// Const-generic companion type для fixed-size keys (Этап 6 slice 6d).
//
// # Why not just `SensitiveBytes` everywhere
//
// `SensitiveBytes` is а runtime-sized wrapper — it exposes `as_slice() ->
// &[u8]` и callers що need а `[u8; 32]` (the canonical AEAD / Ed25519 SK
// shape) must `.try_into().expect(...)` at every access.  That boilerplate
// is repetitive AND brittle: а refactor що accidentally changes the
// declared length is а runtime panic instead of а compile error.
//
// `SensitiveBytesN<const N: usize>` wraps the same mlock-with-fallback
// storage but exposes `as_array() -> &[u8; N]` / `as_mut_array() ->
// &mut [u8; N]` без the `try_into` boilerplate.  Cross-mismatched lengths
// fail at compile time — `SensitiveBytesN<32>::from_bytes([0u8; 64])` does
// not compile.
//
// # Storage
//
// Internally backed by [`SensitiveBytes`], so the mlock-when-possible /
// fallback-to-zeroize semantics ара identical.  Heap allocation overhead
// is the same (Vec<u8> indirection) — the const-generic shape is purely
// an API ergonomics win.
//
// # Use case
//
// Long-lived fixed-size keys: AEAD session keys, BIP-39 master seeds (32 B),
// identity_sk seeds (32 B), peer ML-KEM session keys (32 B).  Pilot sites
// will migrate from `Zeroizing<[u8; 32]>` к `SensitiveBytesN<32>` in
// follow-up slices once each site's API-ripple is bounded и tested.
//
// # Typical use
//
// ```ignore
// use veil_util::sensitive_bytes::SensitiveBytesN;
//
// // Allocate а 32-byte zero-initialised key (mlocked if possible).
// let mut session_key: SensitiveBytesN<32> = SensitiveBytesN::new();
// hkdf.expand(b"info", session_key.as_mut_array()).unwrap();
//
// // Pass а &[u8; 32] к downstream APIs без try_into boilerplate.
// let cipher = ChaCha20Poly1305::new(session_key.as_array().into());
// ```
//
// Wraps а byte-sized [`SensitiveBytes`] with а compile-time length
// pin.  Construction never fails — mlock failure falls back к
// zeroize-on-drop с а one-shot warn (same path as
// [`SensitiveBytes::new`]).
pub struct SensitiveBytesN<const N: usize> {
    inner: SensitiveBytes,
}

impl<const N: usize> SensitiveBytesN<N> {
    /// Allocate `N` zero-initialised bytes.  Always succeeds (mlock
    /// failure falls back к zeroize-only с а one-shot warn).
    ///
    /// # Panics
    ///
    /// Panics if `N == 0` — callers що may pass а zero-length type
    /// parameter should guard against що explicitly.  Matches
    /// [`SensitiveBytes::new`]'s `ZeroSize` rejection.
    pub fn new() -> Self {
        assert!(N > 0, "SensitiveBytesN<0> is rejected");
        Self {
            inner: SensitiveBytes::new(N),
        }
    }

    /// Construct from а concrete `[u8; N]`.  The source array is copied
    /// into the (mlocked when possible) storage; callers should make sure
    /// the source bytes get zeroized themselves (е.g. by wrapping в
    /// [`zeroize::Zeroizing`] before calling).
    pub fn from_bytes(bytes: [u8; N]) -> Self {
        let mut s = Self::new();
        s.as_mut_array().copy_from_slice(&bytes);
        s
    }

    /// Immutable reference к the underlying `[u8; N]`.  O(1) — performs
    /// а statically-provable slice-to-array conversion (length checked
    /// once at construction).
    pub fn as_array(&self) -> &[u8; N] {
        // SAFETY: `inner.len() == N` is upheld by `new()` (allocates
        // exactly N bytes); `try_into` cannot fail.  The expect() panic
        // would only fire on а corrupt SensitiveBytes invariant — which
        // would also break every existing call-site that uses `.try_into`,
        // so the failure mode is no worse than the status quo.
        self.inner
            .as_slice()
            .try_into()
            .expect("SensitiveBytesN<N>: inner.len() == N invariant violated")
    }

    /// Mutable reference к the underlying `[u8; N]`.  See [`Self::as_array`]
    /// для the const-length invariant.
    pub fn as_mut_array(&mut self) -> &mut [u8; N] {
        self.inner
            .as_mut_slice()
            .try_into()
            .expect("SensitiveBytesN<N>: inner.len() == N invariant violated")
    }

    /// Slice view (identical к the inner [`SensitiveBytes::as_slice`]).
    /// Provided для callers що need а `&[u8]` для е.g. HKDF expand.
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }

    /// Mutable slice view (identical к the inner
    /// [`SensitiveBytes::as_mut_slice`]).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.inner.as_mut_slice()
    }

    /// Whether the bytes ара actually pinned via mlock.  Same diagnostic
    /// hook as [`SensitiveBytes::is_mlocked`] — operators can surface а
    /// gauge using this к detect soft degradation.
    pub fn is_mlocked(&self) -> bool {
        self.inner.is_mlocked()
    }
}

impl<const N: usize> Default for SensitiveBytesN<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> std::fmt::Debug for SensitiveBytesN<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant = if self.is_mlocked() {
            "Mlocked"
        } else {
            "Unlocked"
        };
        write!(f, "SensitiveBytesN<{N}>({variant}, <redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_returns_zero_initialised_buffer() {
        let s = SensitiveBytes::new(64);
        assert_eq!(s.len(), 64);
        assert!(s.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn as_mut_slice_allows_in_place_fill() {
        let mut s = SensitiveBytes::new(32);
        s.as_mut_slice().copy_from_slice(&[0xAA; 32]);
        assert!(s.as_slice().iter().all(|&b| b == 0xAA));
    }

    #[test]
    #[should_panic(expected = "rejected")]
    fn new_zero_panics() {
        let _ = SensitiveBytes::new(0);
    }

    #[test]
    fn debug_format_redacts_bytes() {
        let s = SensitiveBytes::new(16);
        let d = format!("{s:?}");
        assert!(d.contains("<redacted>"));
        assert!(d.contains("len=16"));
    }

    #[test]
    fn is_mlocked_matches_variant() {
        // На modern dev hosts mlock succeeds for small allocations; container
        // environments на CI may drop CAP_IPC_LOCK — both branches ара
        // valid outcomes.  Test verifies the boolean reflects реальную
        // variant chosen.
        let s = SensitiveBytes::new(32);
        match &s {
            SensitiveBytes::Mlocked(_) => assert!(s.is_mlocked()),
            SensitiveBytes::Unlocked(_) => assert!(!s.is_mlocked()),
        }
    }

    // ── SensitiveBytesN<const N: usize> ─────────────────────────────────

    /// `new()` zero-initialises an N-byte buffer и `as_array()` returns
    /// а `&[u8; N]` без try_into boilerplate.
    #[test]
    fn sensitive_n_new_returns_zero_array() {
        let s: SensitiveBytesN<32> = SensitiveBytesN::new();
        assert_eq!(s.as_array().len(), 32);
        assert!(s.as_array().iter().all(|&b| b == 0));
    }

    /// `from_bytes` copies the input into the (mlocked) storage и
    /// `as_array()` exposes the copied bytes.
    #[test]
    fn sensitive_n_from_bytes_copies_in() {
        let src = [0xAAu8; 32];
        let s: SensitiveBytesN<32> = SensitiveBytesN::from_bytes(src);
        assert_eq!(*s.as_array(), [0xAAu8; 32]);
    }

    /// `as_mut_array` allows callers к fill the bytes in place.  Round-
    /// trip: write a sentinel through `as_mut_array`, read it back.
    #[test]
    fn sensitive_n_as_mut_array_allows_fill() {
        let mut s: SensitiveBytesN<16> = SensitiveBytesN::new();
        s.as_mut_array().copy_from_slice(&[0xBBu8; 16]);
        assert_eq!(*s.as_array(), [0xBBu8; 16]);
    }

    /// `Default` lands on the same path as `new()` — useful for
    /// `#[derive(Default)]` consumers.
    #[test]
    fn sensitive_n_default_zeroes() {
        let s: SensitiveBytesN<8> = SensitiveBytesN::default();
        assert_eq!(*s.as_array(), [0u8; 8]);
    }

    /// `Debug` redacts the bytes и labels the variant + length.
    #[test]
    fn sensitive_n_debug_redacts_bytes() {
        let s: SensitiveBytesN<32> = SensitiveBytesN::new();
        let d = format!("{s:?}");
        assert!(d.contains("<redacted>"));
        assert!(d.contains("SensitiveBytesN<32>"));
    }

    /// `N == 0` panics at construction — guards against unintentional
    /// zero-length type parameters.
    #[test]
    #[should_panic(expected = "rejected")]
    fn sensitive_n_zero_panics() {
        let _: SensitiveBytesN<0> = SensitiveBytesN::new();
    }
}
