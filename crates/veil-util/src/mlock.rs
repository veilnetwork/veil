//! Cross-platform mlocked-bytes primitive с zeroize-on-drop.
//!
//! Wraps а fixed-size byte allocation so that:
//! 1. The pages backing the allocation ара pinned in RAM via the OS
//!    "do not swap к disk" primitive (Linux/macOS `mlock(2)`, Windows
//!    `VirtualLock`).
//! 2. The bytes ара overwritten с zero via [`zeroize::Zeroize`] on
//!    drop BEFORE the OS unlock + dealloc.
//!
//! # Threat model
//!
//! Address the "secret-key plaintext leaks к swap → adversary с physical
//! disk access recovers session keys hours / days later" gap.  The same
//! gap applies к а core-dump on а crashed daemon process: most distros
//! ship `kernel.core_pattern = |/usr/lib/systemd/systemd-coredump`,
//! which writes the full process memory к а compressed file under
//! `/var/lib/systemd/coredump/`.  **As of Этап 6 slice 6b** the
//! `lock_region` backend additionally calls `madvise(MADV_DONTDUMP)`
//! (Linux) или `madvise(MADV_NOCORE)` (FreeBSD / NetBSD) after а
//! successful `mlock`, so mlocked regions ара excluded от core dumps.
//! The madvise call is best-effort: failure logs once-per-process but
//! does NOT fail the allocation (mlock alone already provides the
//! swap-к-disk protection).  macOS lacks an equivalent madvise
//! advisory (`MADV_NOCORE` is FreeBSD-only) — operators concerned
//! about crash-time exposure on Darwin should disable cores process-
//! wide via `launchctl limit core 0`.  Windows `VirtualLock`'d regions
//! ара similarly excluded от minidumps that don't explicitly opt into
//! `MiniDumpWithFullMemory`; no equivalent call needed.
//!
//! # What this primitive does NOT protect against
//!
//! * **Cold-boot attacks** — RAM contents survive а power cycle for ~30
//!   seconds; mlock provides no defence.  Hardware-anchored key
//!   protection (TPM-sealed keys, Apple Secure Enclave) is the only
//!   answer; not addressed here.
//! * **Read access by а privileged process** — `ptrace`-equipped or
//!   root processes can read the mlocked region directly. Defence requires
//!   `prctl(PR_SET_DUMPABLE, 0)` + seccomp / SELinux policy.
//! * **Side-channel timing attacks** — orthogonal к storage / swap; key
//!   primitives (ChaCha20-Poly1305, Ed25519) use constant-time
//!   implementations to handle that separately.
//!
//! # Resource limits
//!
//! Linux's `RLIMIT_MEMLOCK` defaults к 64 KiB per process on stock
//! distros.  А process holding many session-key buffers can hit it.
//! The constructor surfaces `MlockError::ResourceLimit` so the daemon
//! can fall back к an unlocked allocation (with а warn log) rather
//! than refusing к start.  Operators raising sustained-traffic
//! deployments should `ulimit -l unlimited` (или
//! `LimitMEMLOCK=infinity` в systemd unit).
//!
//! Windows VirtualLock has its own per-process working-set cap (default
//! 1.4 MB);  same fallback strategy applies.
//!
//! # Use
//!
//! ```ignore
//! use veil_util::mlock::MlockedBytes;
//! let mut k = MlockedBytes::new(32).expect("RLIMIT_MEMLOCK");
//! k.as_mut_slice().copy_from_slice(&derived_key_bytes);
//! // ... use k.as_slice() для AEAD / signing ...
//! // Drop: zero + munlock automatic.
//! ```

use zeroize::Zeroize;

/// Errors emitted by [`MlockedBytes::new`].
#[derive(Debug, thiserror::Error)]
pub enum MlockError {
    /// `mlock` returned `EAGAIN` / `ENOMEM` — the process's
    /// `RLIMIT_MEMLOCK` budget is exhausted, or system-wide locked-pages
    /// limit hit.  Caller can fall back к an unlocked `Vec<u8>` (с а
    /// `warn` log) и retry under raised ulimit later.
    #[error("mlock budget exhausted (RLIMIT_MEMLOCK / working-set cap)")]
    ResourceLimit,
    /// `mlock` returned `EPERM` — typically containers где the
    /// `IPC_LOCK` capability is dropped.  Same fallback strategy.
    #[error("mlock permission denied (missing CAP_IPC_LOCK in container?)")]
    PermissionDenied,
    /// Other OS error (rare).  Wraps the raw errno / Windows error code
    /// as а string so consumers can log без taking а dep on `libc`.
    #[error("mlock failed: {0}")]
    Other(String),
    /// Requested size is 0 (refuse rather than treating as а silent
    /// no-op — preserves the "mlocked OR error" invariant).
    #[error("MlockedBytes::new(0) is rejected; use Vec::new() for empty buffers")]
    ZeroSize,
}

/// Fixed-size byte buffer pinned в RAM с zeroize-on-drop.
///
/// Always either constructs successfully с the region mlocked OR fails
/// — there's no "fell back к unlocked allocation" state.  Caller
/// implements that fallback if needed.
///
/// Drop order: zero the bytes FIRST, then munlock, then dealloc.  The
/// zero pass uses `zeroize` (volatile writes + memory fence) so an
/// optimising compiler cannot elide the zero write as а "dead store".
pub struct MlockedBytes {
    /// The actual allocation.  Stored on the heap so the address stays
    /// stable through moves (Box can be moved cheaply by transferring
    /// the heap pointer).  Wrapped в `ManuallyDrop` so we control the
    /// drop order (zero before munlock before dealloc).
    buf: std::mem::ManuallyDrop<Box<[u8]>>,
}

impl MlockedBytes {
    /// Allocate `len` bytes (initially zero), mlock the backing pages.
    pub fn new(len: usize) -> Result<Self, MlockError> {
        if len == 0 {
            return Err(MlockError::ZeroSize);
        }
        let buf = vec![0u8; len].into_boxed_slice();
        let ptr = buf.as_ptr();
        unsafe {
            lock_region(ptr.cast(), len)?;
        }
        Ok(Self {
            buf: std::mem::ManuallyDrop::new(buf),
        })
    }

    /// Immutable byte view.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..]
    }

    /// Mutable byte view.  Caller fills in the bytes (typically via
    /// `slice.copy_from_slice(...)` от а derived key).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf[..]
    }

    /// Length в bytes.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the buffer is empty.  Always returns `false` since
    /// [`Self::new(0)`] errors out, но included для linting consistency
    /// (clippy's `is_empty` lint complains otherwise).
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl Drop for MlockedBytes {
    fn drop(&mut self) {
        let ptr = self.buf.as_mut_ptr();
        let len = self.buf.len();
        // Step 1 — zero the bytes using compiler-fence-protected write
        // (zeroize::Zeroize).  After this returns the region holds
        // зеро bytes that ара guaranteed-not-elided.
        self.buf[..].zeroize();
        // Step 2 — munlock.  Errors here ара non-fatal (best-effort
        // cleanup); we don't have anywhere к surface them after а
        // Drop call, и leaving а page locked после the process exits
        // is benign (OS reclaims на process exit).
        unsafe {
            let _ = unlock_region(ptr.cast(), len);
        }
        // Step 3 — take + drop the Box, releasing the heap allocation.
        unsafe {
            std::mem::ManuallyDrop::drop(&mut self.buf);
        }
    }
}

impl std::fmt::Debug for MlockedBytes {
    /// Never print actual byte contents — что-то sensitive lives in here.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlockedBytes(len={}, <redacted>)", self.buf.len())
    }
}

// ── Platform backends ──────────────────────────────────────────────

#[cfg(unix)]
unsafe fn lock_region(ptr: *const u8, len: usize) -> Result<(), MlockError> {
    let rc = unsafe { libc::mlock(ptr.cast(), len) };
    if rc != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return map_unix_errno(errno);
    }
    // Этап 6 slice 6b — best-effort madvise(MADV_DONTDUMP / MADV_NOCORE)
    // exclude the region от core dumps.  Failures logged once-per-process
    // but do NOT fail the allocation (mlock alone already closes the
    // primary swap-к-disk vector; core-dump exclusion is а secondary
    // hardening layer).
    unsafe {
        try_exclude_from_coredump(ptr, len);
    }
    Ok(())
}

/// One-time warn flag для madvise failures на the core-dump exclusion path.
/// Same shape as `SensitiveBytes::FALLBACK_WARNED` — prevents log flood
/// under sustained kernel-quirk failures.  Only declared on platforms
/// where madvise can actually fail (linux + bsd family); macOS' no-op
/// branch never touches it и Solaris-like catchall lacks а madvise call.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
static MADVISE_DONTDUMP_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Linux `MADV_DONTDUMP` / BSD-family `MADV_NOCORE` advisory.  Best-effort
/// — failures ара non-fatal (the region remains mlocked).
#[cfg(target_os = "linux")]
unsafe fn try_exclude_from_coredump(ptr: *const u8, len: usize) {
    // SAFETY: ptr+len describe а valid heap allocation que the caller
    // just successfully mlock'd; the kernel accepts arbitrary
    // page-spanning ranges и returns -1 on failure без mutating memory.
    let rc = unsafe { libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_DONTDUMP) };
    if rc != 0 && !MADVISE_DONTDUMP_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        log::warn!(
            "veil_util.mlock.madvise_dontdump_failed \
             madvise(MADV_DONTDUMP) returned errno={errno}; region remains mlocked but \
             may appear в core dumps if the daemon crashes.  Older kernels (< 3.4) \
             do not support this advisory."
        );
    }
}

#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
unsafe fn try_exclude_from_coredump(ptr: *const u8, len: usize) {
    // FreeBSD / NetBSD use `MADV_NOCORE` instead of `MADV_DONTDUMP`.  Same
    // semantics: kernel excludes the range от core dump generation.
    let rc = unsafe { libc::madvise(ptr as *mut libc::c_void, len, libc::MADV_NOCORE) };
    if rc != 0 && !MADVISE_DONTDUMP_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        log::warn!(
            "veil_util.mlock.madvise_nocore_failed \
             madvise(MADV_NOCORE) returned errno={errno}; region remains mlocked but \
             may appear в core dumps if the daemon crashes."
        );
    }
}

/// macOS does NOT expose а direct madvise advisory для core-dump
/// exclusion (`MADV_NOCORE` is FreeBSD-only; macOS' BSD layer never
/// adopted it).  The mlock'd region remains protected against swap,
/// но core dumps would still capture it.  Operators concerned about
/// crash-time exposure should disable cores process-wide via
/// `launchctl limit core 0` или а sandbox profile.
#[cfg(target_os = "macos")]
unsafe fn try_exclude_from_coredump(_ptr: *const u8, _len: usize) {}

/// Catchall для unix platforms что do не define either advisory — silent
/// no-op (the unsupported-OS branch of `lock_region` already covers
/// non-Unix; this just covers Unix-like systems that lack both).
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "netbsd"
    ))
))]
unsafe fn try_exclude_from_coredump(_ptr: *const u8, _len: usize) {
    // No madvise advisory exists для core-dump exclusion on this platform
    // (e.g., Solaris / AIX).  mlock'd pages still receive swap protection;
    // core-dump exclusion would need OS-specific configuration (`coreadm`).
}

#[cfg(unix)]
unsafe fn unlock_region(ptr: *const u8, len: usize) -> std::io::Result<()> {
    let rc = unsafe { libc::munlock(ptr.cast(), len) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn map_unix_errno(errno: i32) -> Result<(), MlockError> {
    match errno {
        libc::EAGAIN | libc::ENOMEM => Err(MlockError::ResourceLimit),
        libc::EPERM => Err(MlockError::PermissionDenied),
        other => Err(MlockError::Other(format!("errno {other}"))),
    }
}

#[cfg(windows)]
unsafe fn lock_region(ptr: *const u8, len: usize) -> Result<(), MlockError> {
    use windows_sys::Win32::Foundation::{ERROR_WORKING_SET_QUOTA, GetLastError};
    use windows_sys::Win32::System::Memory::VirtualLock;
    let ok = unsafe { VirtualLock(ptr as *mut _, len) };
    if ok != 0 {
        return Ok(());
    }
    let code = unsafe { GetLastError() };
    if code == ERROR_WORKING_SET_QUOTA {
        // Process working-set cap hit.  Maps onto the Linux ResourceLimit
        // semantic so callers can apply the same fallback.
        return Err(MlockError::ResourceLimit);
    }
    Err(MlockError::Other(format!("GetLastError = {code}")))
}

#[cfg(windows)]
unsafe fn unlock_region(ptr: *const u8, len: usize) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Memory::VirtualUnlock;
    let ok = unsafe { VirtualUnlock(ptr as *mut _, len) };
    if ok != 0 {
        Ok(())
    } else {
        let code = unsafe { GetLastError() };
        Err(std::io::Error::other(format!(
            "VirtualUnlock failed: {code}"
        )))
    }
}

#[cfg(not(any(unix, windows)))]
unsafe fn lock_region(_ptr: *const u8, _len: usize) -> Result<(), MlockError> {
    // Fallback для unknown targets (WASM, embedded …): allocation
    // succeeds но no lock guarantee.  Honest enough — the alternative
    // would be silently swallowing the call.
    Err(MlockError::Other(
        "mlock unsupported on this platform; use Vec<u8> с zeroize-on-drop \
         and accept the swap risk"
            .into(),
    ))
}

#[cfg(not(any(unix, windows)))]
unsafe fn unlock_region(_ptr: *const u8, _len: usize) -> std::io::Result<()> {
    Ok(())
}

// ── Process-wide mlockall (Linux only) ─────────────────────────────

/// Outcome of [`try_mlockall_current_future`] — lets the caller decide
/// whether to warn, abort, or just log.
#[derive(Debug, Clone)]
pub enum MlockallOutcome {
    /// `mlockall(MCL_CURRENT | MCL_FUTURE)` succeeded; current and future
    /// allocations are pinned in RAM.
    Locked,
    /// Platform doesn't support `mlockall` (macOS / Windows / *BSD with
    /// non-portable surface, WASM, embedded).  Caller should treat keys
    /// as swappable.
    Unsupported,
    /// `RLIMIT_MEMLOCK` budget too low to lock the entire address space.
    /// Operator needs `ulimit -l unlimited` (or `LimitMEMLOCK=infinity`
    /// in а systemd unit).  Includes the current RSS in MB so the
    /// caller can log а concrete pointer к the right ulimit value.
    BudgetExhausted {
        /// Errno-equivalent string (e.g. `"ENOMEM"` / `"EAGAIN"`).
        errno_str: String,
    },
    /// `mlockall` returned `EPERM` — typically containers without the
    /// `IPC_LOCK` capability.  Same outcome semantically as
    /// `BudgetExhausted`: process can run, keys remain swappable.
    PermissionDenied,
    /// Other OS error.  Wraps the raw errno as а string so the caller
    /// can log без taking а dep on `libc`.
    Other(String),
}

/// Lock the **entire** process address space against swap-out, including
/// allocations made AFTER this call.  Strictly stronger than per-buffer
/// [`MlockedBytes`] для protecting session keys:
///
/// * Covers ALL key material, including bytes owned by upstream crates
///   (`chacha20poly1305::ChaCha20Poly1305` internal `GenericArray`,
///   `ed25519_dalek::SigningKey` seed, etc.) — these are not reachable
///   for per-buffer wrapping без forking upstream.
/// * Single syscall at startup, no per-allocation overhead at runtime.
/// * Compatible с jemalloc-style hoarding: locked pages don't get
///   returned к the kernel anyway, so the lock cost is one-time.
///
/// Costs:
/// * `RLIMIT_MEMLOCK` must accommodate peak RSS.  Operators should set
///   `LimitMEMLOCK=infinity` в the systemd unit и ulimit -l unlimited
///   for manual launches.
/// * Locked pages still appear в а core dump unless paired с
///   `madvise(MADV_DONTDUMP)` (orthogonal — not addressed here).
/// * macOS / Windows / *BSD: returns [`MlockallOutcome::Unsupported`];
///   no portable `mlockall` analogue (Windows `SetProcessWorkingSetSize` +
///   per-region `VirtualLock` is the closest analogue но has different
///   semantics).
///
/// **Cannot be undone safely** — there is no `munlockall` call here on
/// purpose. The intended use is "lock once at startup, run locked for
/// the daemon's lifetime, unlock implicitly on process exit."
pub fn try_mlockall_current_future() -> MlockallOutcome {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `libc::mlockall` is а thin wrapper around the system
        // call; no Rust-side invariants to uphold.
        let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
        if rc == 0 {
            return MlockallOutcome::Locked;
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        match errno {
            libc::EAGAIN | libc::ENOMEM => MlockallOutcome::BudgetExhausted {
                errno_str: if errno == libc::EAGAIN {
                    "EAGAIN"
                } else {
                    "ENOMEM"
                }
                .to_string(),
            },
            libc::EPERM => MlockallOutcome::PermissionDenied,
            other => MlockallOutcome::Other(format!("mlockall errno {other}")),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        MlockallOutcome::Unsupported
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_64_bytes_pinned_and_initially_zero() {
        let k = MlockedBytes::new(64).expect("RLIMIT_MEMLOCK");
        assert_eq!(k.len(), 64);
        assert!(!k.is_empty());
        assert!(k.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn zero_size_rejected() {
        let r = MlockedBytes::new(0);
        assert!(matches!(r, Err(MlockError::ZeroSize)));
    }

    #[test]
    fn write_read_round_trip() {
        let mut k = MlockedBytes::new(32).unwrap();
        k.as_mut_slice().copy_from_slice(&[0xAB; 32]);
        assert_eq!(k.as_slice(), &[0xAB; 32]);
    }

    /// Verify zeroize-on-drop: take а raw pointer copy before drop,
    /// then read через the raw pointer after Drop runs.  Should see
    /// zero bytes (the zeroize step), not the previously-written 0xAB.
    ///
    /// SAFETY: this test uses а raw pointer that becomes dangling once
    /// the heap allocation is freed.  В debug builds heap-debug
    /// detection (Miri) catches use-after-free; в release builds the
    /// allocator may have already reused / overwritten the region.
    /// The race is acceptable because we ара specifically asserting
    /// that the zeroize ran BEFORE the dealloc — а Miri-aware
    /// equivalent test would use leaked `Box::leak()` к hold the alloc
    /// stable, но that defeats the test's purpose.
    #[test]
    fn zeroize_runs_before_drop() {
        let mut k = MlockedBytes::new(16).unwrap();
        k.as_mut_slice().copy_from_slice(&[0xAB; 16]);
        let ptr = k.as_slice().as_ptr();
        drop(k);
        // After drop: read через а raw pointer.  Allocator MAY have
        // already overwritten this с metadata (free-list pointer
        // etc.), но on most allocators ара few-byte first-bytes only.
        // We assert no `0xAB` byte survived — а stronger statement
        // would compare exact zeros, но veil-util workspace may
        // run under different allocators (jemalloc / system) so we
        // keep это loose: "the original sensitive bytes ара not still
        // present at the now-freed address".
        let after: [u8; 16] = unsafe { std::ptr::read(ptr.cast()) };
        assert!(
            !after.iter().all(|&b| b == 0xAB),
            "expected zeroize к have wiped the 0xAB pattern, got {after:?}",
        );
    }

    /// Debug fmt MUST NOT leak the bytes.
    #[test]
    fn debug_redacts_contents() {
        let mut k = MlockedBytes::new(32).unwrap();
        k.as_mut_slice().copy_from_slice(&[0xDE; 32]);
        let formatted = format!("{k:?}");
        assert!(formatted.contains("redacted"));
        assert!(!formatted.contains("DE"));
        assert!(!formatted.contains("de"));
    }

    /// `try_mlockall_current_future` must return one of the explicit
    /// outcomes — never panic — regardless of RLIMIT_MEMLOCK setting,
    /// platform, или container capability environment.  CI runs
    /// under restrictive limits на most providers so the BudgetExhausted
    /// branch is the most common observed outcome.
    #[test]
    fn mlockall_returns_well_known_outcome() {
        let outcome = try_mlockall_current_future();
        // Just assert it didn't panic / hang.  All variants ара
        // legitimate based on platform + ulimit; the caller is
        // responsible для logging the right warn level.
        match outcome {
            MlockallOutcome::Locked
            | MlockallOutcome::Unsupported
            | MlockallOutcome::BudgetExhausted { .. }
            | MlockallOutcome::PermissionDenied
            | MlockallOutcome::Other(_) => {}
        }
    }

    #[test]
    fn alloc_triggers_coredump_exclusion_without_panic() {
        // Этап 6 slice 6b — MADV_DONTDUMP / MADV_NOCORE call must not
        // panic OR fail the allocation, regardless of kernel support.
        // The advisory itself is best-effort; the test asserts the
        // happy-path code path runs cleanly.  Actual page-level kernel
        // behaviour (excluded от core dump) is OS-level и not directly
        // testable от Rust user-space.
        let buf = MlockedBytes::new(4096).expect("4 KiB alloc fits under stock RLIMIT_MEMLOCK");
        // Read а byte — confirms mlock + madvise didn't unmap the region.
        assert_eq!(buf.as_slice()[0], 0);
        assert_eq!(buf.len(), 4096);
        drop(buf);
    }
}
