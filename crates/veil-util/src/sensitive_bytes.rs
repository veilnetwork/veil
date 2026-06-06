//! Sensitive-bytes container with automatic mlock fallback (Phase 6 — Epic 489.10
//! adjacent).
//!
//! Wraps either [`crate::mlock::MlockedBytes`] (preferred — pages pinned in
//! RAM AND zeroized-on-drop) or a [`zeroize::Zeroizing<Vec<u8>>`] (fallback
//! when mlock budget is exhausted — bytes are still zeroized-on-drop but
//! the OS may still swap the pages to disk).  Always succeeds in
//! [`SensitiveBytes::new`]; on mlock failure a warn is logged once-per-
//! process so operators see the soft degradation without flooding logs.
//!
//! # Why a fallback
//!
//! Stock distros default `RLIMIT_MEMLOCK` to 64 KiB per process; containers
//! often drop `CAP_IPC_LOCK`.  Refusing to open sessions in those
//! environments would break the daemon entirely — strictly worse than
//! falling back to pre-mlock (zeroize-only) behaviour.  The fallback path
//! is **safe**: the bytes still wipe on drop, identical to the pre-Phase-6
//! behaviour.  The mlock-when-possible path is **better**: closes the
//! swap-to-disk vector.
//!
//! # Threat model
//!
//! See [`crate::mlock`] module docs.  This wrapper does not change the
//! threat-model coverage; it only paves the upgrade path so call sites
//! can adopt mlock-when-possible without a forced infrastructure change.
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
/// Spurious double-fires (a race during early startup) are benign — at
/// worst the operator sees the warn twice.
static FALLBACK_WARNED: AtomicBool = AtomicBool::new(false);

/// Either a pinned [`MlockedBytes`] (preferred) or a zeroize-wrapped
/// `Vec<u8>` fallback.  Construction never fails.
pub enum SensitiveBytes {
    /// mlock succeeded — bytes pinned in RAM (closed swap-to-disk).
    Mlocked(MlockedBytes),
    /// mlock failed (RLIMIT_MEMLOCK exhausted, missing `CAP_IPC_LOCK`,
    /// or other OS error).  Bytes are zeroize-on-drop only — pages
    /// may swap to disk under memory pressure.  Same security posture
    /// as the pre-Phase-6 codebase.
    Unlocked(zeroize::Zeroizing<Vec<u8>>),
}

impl SensitiveBytes {
    /// Allocate `len` zero-initialised bytes, trying mlock first.
    ///
    /// On mlock failure logs a warn first-time-per-process and falls back
    /// to a `Zeroizing<Vec<u8>>` (same protection as pre-Phase-6 code).
    /// Subsequent failures within the same process are silent so the
    /// log doesn't flood under sustained budget pressure.
    ///
    /// # Panics
    ///
    /// Panics if `len == 0` — callers that may pass zero-length should
    /// guard against that explicitly before calling.  Matches
    /// [`MlockedBytes::new`]'s `ZeroSize` rejection.
    pub fn new(len: usize) -> Self {
        assert!(len > 0, "SensitiveBytes::new(0) is rejected");
        match MlockedBytes::new(len) {
            Ok(m) => Self::Mlocked(m),
            Err(e) => {
                if !FALLBACK_WARNED.swap(true, Ordering::Relaxed) {
                    log::warn!(
                        "veil_util.sensitive_bytes.mlock_fallback \
                         mlock failed on key allocation, falling back \
                         to zeroize-only (bytes are still wiped on drop, \
                         but pages may swap to disk).  Raise RLIMIT_MEMLOCK \
                         or grant CAP_IPC_LOCK to close swap exposure: {e}"
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

    /// Length in bytes.
    pub fn len(&self) -> usize {
        match self {
            Self::Mlocked(m) => m.len(),
            Self::Unlocked(v) => v.len(),
        }
    }

    /// Always returns `false` since [`Self::new`] panics on zero-length.
    /// Provided for linting consistency (matches `len()` -> `is_empty`).
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Whether the bytes are actually pinned via mlock.  Test/diagnostic
    /// hook — production code should not branch on this; both variants
    /// honour the same `as_slice` / `as_mut_slice` contract.  Operators
    /// can surface a Prometheus gauge using this to detect soft
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
// Const-generic companion type for fixed-size keys (Phase 6 slice 6d).
//
// # Why not just `SensitiveBytes` everywhere
//
// `SensitiveBytes` is a runtime-sized wrapper — it exposes `as_slice() ->
// &[u8]` and callers that need a `[u8; 32]` (the canonical AEAD / Ed25519 SK
// shape) must `.try_into().expect(...)` at every access.  That boilerplate
// is repetitive AND brittle: a refactor that accidentally changes the
// declared length is a runtime panic instead of a compile error.
//
// `SensitiveBytesN<const N: usize>` wraps the same mlock-with-fallback
// storage but exposes `as_array() -> &[u8; N]` / `as_mut_array() ->
// &mut [u8; N]` without the `try_into` boilerplate.  Cross-mismatched lengths
// fail at compile time — `SensitiveBytesN<32>::from_bytes([0u8; 64])` does
// not compile.
//
// # Storage
//
// Internally backed by [`SensitiveBytes`], so the mlock-when-possible /
// fallback-to-zeroize semantics are identical.  Heap allocation overhead
// is the same (Vec<u8> indirection) — the const-generic shape is purely
// an API ergonomics win.
//
// # Use case
//
// Long-lived fixed-size keys: AEAD session keys, BIP-39 master seeds (32 B),
// identity_sk seeds (32 B), peer ML-KEM session keys (32 B).  Pilot sites
// will migrate from `Zeroizing<[u8; 32]>` to `SensitiveBytesN<32>` in
// follow-up slices once each site's API-ripple is bounded and tested.
//
// # Typical use
//
// ```ignore
// use veil_util::sensitive_bytes::SensitiveBytesN;
//
// // Allocate a 32-byte zero-initialised key (mlocked if possible).
// let mut session_key: SensitiveBytesN<32> = SensitiveBytesN::new();
// hkdf.expand(b"info", session_key.as_mut_array()).unwrap();
//
// // Pass a &[u8; 32] to downstream APIs without try_into boilerplate.
// let cipher = ChaCha20Poly1305::new(session_key.as_array().into());
// ```
//
// Wraps a byte-sized [`SensitiveBytes`] with a compile-time length
// pin.  Construction never fails — mlock failure falls back to
// zeroize-on-drop with a one-shot warn (same path as
// [`SensitiveBytes::new`]).
pub struct SensitiveBytesN<const N: usize> {
    inner: SensitiveBytes,
}

impl<const N: usize> SensitiveBytesN<N> {
    /// Allocate `N` zero-initialised bytes.  Always succeeds (mlock
    /// failure falls back to zeroize-only with a one-shot warn).
    ///
    /// # Panics
    ///
    /// Panics if `N == 0` — callers that may pass a zero-length type
    /// parameter should guard against that explicitly.  Matches
    /// [`SensitiveBytes::new`]'s `ZeroSize` rejection.
    pub fn new() -> Self {
        assert!(N > 0, "SensitiveBytesN<0> is rejected");
        Self {
            inner: SensitiveBytes::new(N),
        }
    }

    /// Construct from a concrete `[u8; N]`.  The source array is copied
    /// into the (mlocked when possible) storage; callers should make sure
    /// the source bytes get zeroized themselves (e.g. by wrapping in
    /// [`zeroize::Zeroizing`] before calling).
    pub fn from_bytes(bytes: [u8; N]) -> Self {
        let mut s = Self::new();
        s.as_mut_array().copy_from_slice(&bytes);
        s
    }

    /// Immutable reference to the underlying `[u8; N]`.  O(1) — performs
    /// a statically-provable slice-to-array conversion (length checked
    /// once at construction).
    pub fn as_array(&self) -> &[u8; N] {
        // SAFETY: `inner.len() == N` is upheld by `new()` (allocates
        // exactly N bytes); `try_into` cannot fail.  The expect() panic
        // would only fire on a corrupt SensitiveBytes invariant — which
        // would also break every existing call-site that uses `.try_into`,
        // so the failure mode is no worse than the status quo.
        self.inner
            .as_slice()
            .try_into()
            .expect("SensitiveBytesN<N>: inner.len() == N invariant violated")
    }

    /// Mutable reference to the underlying `[u8; N]`.  See [`Self::as_array`]
    /// for the const-length invariant.
    pub fn as_mut_array(&mut self) -> &mut [u8; N] {
        self.inner
            .as_mut_slice()
            .try_into()
            .expect("SensitiveBytesN<N>: inner.len() == N invariant violated")
    }

    /// Slice view (identical to the inner [`SensitiveBytes::as_slice`]).
    /// Provided for callers that need a `&[u8]` for e.g. HKDF expand.
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }

    /// Mutable slice view (identical to the inner
    /// [`SensitiveBytes::as_mut_slice`]).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.inner.as_mut_slice()
    }

    /// Whether the bytes are actually pinned via mlock.  Same diagnostic
    /// hook as [`SensitiveBytes::is_mlocked`] — operators can surface a
    /// gauge using this to detect soft degradation.
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
        // On modern dev hosts mlock succeeds for small allocations; container
        // environments on CI may drop CAP_IPC_LOCK — both branches are
        // valid outcomes.  Test verifies the boolean reflects the actual
        // variant chosen.
        let s = SensitiveBytes::new(32);
        match &s {
            SensitiveBytes::Mlocked(_) => assert!(s.is_mlocked()),
            SensitiveBytes::Unlocked(_) => assert!(!s.is_mlocked()),
        }
    }

    // ── SensitiveBytesN<const N: usize> ─────────────────────────────────

    /// `new()` zero-initialises an N-byte buffer and `as_array()` returns
    /// a `&[u8; N]` without try_into boilerplate.
    #[test]
    fn sensitive_n_new_returns_zero_array() {
        let s: SensitiveBytesN<32> = SensitiveBytesN::new();
        assert_eq!(s.as_array().len(), 32);
        assert!(s.as_array().iter().all(|&b| b == 0));
    }

    /// `from_bytes` copies the input into the (mlocked) storage and
    /// `as_array()` exposes the copied bytes.
    #[test]
    fn sensitive_n_from_bytes_copies_in() {
        let src = [0xAAu8; 32];
        let s: SensitiveBytesN<32> = SensitiveBytesN::from_bytes(src);
        assert_eq!(*s.as_array(), [0xAAu8; 32]);
    }

    /// `as_mut_array` allows callers to fill the bytes in place.  Round-
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

    /// `Debug` redacts the bytes and labels the variant + length.
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
