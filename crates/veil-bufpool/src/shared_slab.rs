//! m: slab-allocated shared cells for `PooledShared`.
//!
//! ## Problem
//!
//! Each `Pooled::into_shared` or `pooled_shared_from_vec` previously
//! ran `Arc::new(PooledSharedInner{…})`, allocating ~64 bytes from jemalloc
//! every time. At sustained ~14k frames/sec on a forwarder bootstrap
//! that's ~900 KB/sec of small-bin allocator churn outside the bufpool —
//! enough to keep jemalloc's small-bin arena dirty faster than
//! `dirty_decay_ms=1000` could release pages. Result: linear RSS growth
//! ~5 MiB/min on high-throughput hosts despite ALL upstream buffers
//! capped, queue gauges flat, and pool serving 99.99 % cache-hits.
//!
//! ## Design
//!
//! Replace `Arc<PooledSharedInner>` with a custom refcounted handle that
//! points into a pre-allocated slab of fixed-size cells.
//!
//! ```text
//! static SHARED_SLAB: SharedSlab = SharedSlab {
//! cells: [SharedCell; 4096] / ~280 KiB at startup
//! free: Mutex<Vec<u32>> / FIFO of available cell indices
//! };
//! ```
//!
//! Each `SharedCell` carries:
//! * `refcount: AtomicUsize` — Arc-style strong count (no weak refs).
//! * `inner: UnsafeCell<MaybeUninit<PooledSharedInner>>` — payload.
//!
//! When the slab is full, callers fall back to heap-allocated
//! `Box<SharedCell>` (counter: `fallback_alloc_total`). This keeps
//! correctness under burst load while making the steady state allocation-
//! free.
//!
//! ## Safety
//!
//! Standard Arc patterns with manual control:
//! Release ordering on `fetch_sub`, Acquire fence on last-decrement.
//! `MaybeUninit` prevents Drop running on uninitialised cells.
//! Cells in the freelist are logically uninitialised; their `inner`
//! field is NOT dropped until the next `acquire` initialises and
//! uses it.

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::ptr::NonNull;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering, fence};

use crate::PooledSharedInner;

/// Default slab size — sized to cover steady-state inflight count
/// (~8 sessions × 64-frame queues × 4 stages ≈ 2k) with headroom.
/// At ~80 bytes per cell that's ~320 KiB pre-allocated at process
/// startup, released only at process exit.
pub const DEFAULT_SLAB_CELLS: usize = 4096;

/// Single slab cell — Arc-style refcount + payload. Layout is
/// load-bearing: `refcount` MUST be `AtomicUsize` for cross-thread
/// release/acquire semantics; the payload is `MaybeUninit` so we
/// can leave cells logically uninitialised while on the freelist
/// without double-dropping.
#[repr(C)]
pub(crate) struct SharedCell {
    pub(crate) refcount: AtomicUsize,
    pub(crate) inner: UnsafeCell<MaybeUninit<PooledSharedInner>>,
    /// Slab index for return-to-freelist on last drop. `u32::MAX`
    /// flags a heap-fallback cell (Box::leak, freed normally).
    pub(crate) slot: u32,
}

// SAFETY: SharedCell is heap-allocated and refcount uses atomic
// operations; the UnsafeCell content is read only while refcount > 0
// and read-only (PooledSharedInner has Deref<Target=[u8]> but no
// interior mutation), so multi-thread access via shared reference is
// sound when refcount > 1.
unsafe impl Send for SharedCell {}
unsafe impl Sync for SharedCell {}

pub(crate) struct SharedSlab {
    cells: Box<[SharedCell]>,
    free: Mutex<Vec<u32>>,
    /// Slab-exhaustion fallback counter — exported via
    /// `BufferPool::stats.shared_fallback_alloc_total`.
    fallback_alloc_total: AtomicU64,
    /// Currently held cells (high-water for diagnostics).
    inflight_peak: AtomicU64,
}

impl SharedSlab {
    fn new(cap: usize) -> Self {
        let mut cells = Vec::with_capacity(cap);
        let mut free = Vec::with_capacity(cap);
        for i in 0..cap {
            cells.push(SharedCell {
                refcount: AtomicUsize::new(0),
                inner: UnsafeCell::new(MaybeUninit::uninit()),
                slot: i as u32,
            });
            // Pre-populate freelist in reverse so pop returns 0, 1, 2…
            // first, simplifying determinism in tests.
            free.push((cap - 1 - i) as u32);
        }
        Self {
            cells: cells.into_boxed_slice(),
            free: Mutex::new(free),
            fallback_alloc_total: AtomicU64::new(0),
            inflight_peak: AtomicU64::new(0),
        }
    }

    /// Acquire a cell from the slab. When the slab is empty, allocates
    /// a heap fallback cell (Box::leak) and increments
    /// `fallback_alloc_total`. The returned pointer is non-null and
    /// remains valid until the last `PooledSharedRef` referencing it
    /// drops.
    pub(crate) fn acquire(&'static self, init: PooledSharedInner) -> NonNull<SharedCell> {
        let cell_ptr = if let Some(idx) = self.free.lock().unwrap_or_else(|p| p.into_inner()).pop()
        {
            let cell = &self.cells[idx as usize];
            // Write the payload into the cell's MaybeUninit slot.
            unsafe {
                (*cell.inner.get()).write(init);
            }
            // Refcount: 0 → 1. No fence needed; this thread is the only
            // owner of the cell until the returned NonNull leaks.
            cell.refcount.store(1, Ordering::Relaxed);
            NonNull::from(cell)
        } else {
            // Slab exhausted — leak a heap-allocated cell. `slot=u32::MAX`
            // tells `release` to free it via Box rather than return to
            // the slab.
            self.fallback_alloc_total.fetch_add(1, Ordering::Relaxed);
            let boxed = Box::new(SharedCell {
                refcount: AtomicUsize::new(1),
                inner: UnsafeCell::new(MaybeUninit::new(init)),
                slot: u32::MAX,
            });
            // SAFETY: Box::leak returns a valid &'static reference;
            // we control the de-allocation in `release`.
            let r: &'static SharedCell = Box::leak(boxed);
            NonNull::from(r)
        };
        // Update inflight peak (best-effort, relaxed).
        let inflight = self.cells.len()
            - self
                .free
                .lock()
                .map(|g| g.len())
                .unwrap_or(self.cells.len());
        let inflight = inflight as u64;
        let prev = self.inflight_peak.load(Ordering::Relaxed);
        if inflight > prev {
            let _ = self.inflight_peak.compare_exchange(
                prev,
                inflight,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
        cell_ptr
    }

    /// Called from `PooledSharedRef::drop` on the last decrement (rc→0).
    /// Drops the payload in place and returns the cell to the freelist
    /// (or frees the Box if it was a fallback cell).
    ///
    /// # Safety
    /// Caller MUST guarantee this is the LAST reference (rc dropped 1→0)
    /// and that no other thread holds a pointer to the cell. An Acquire
    /// fence at the call site is required to synchronise with the prior
    /// Release stores from other references.
    pub(crate) unsafe fn release(&'static self, ptr: NonNull<SharedCell>) {
        let cell: &SharedCell = unsafe { ptr.as_ref() };
        // Drop the payload in place. After this `inner` is logically
        // uninitialised again.
        unsafe { (*cell.inner.get()).assume_init_drop() };

        if cell.slot == u32::MAX {
            // Heap-fallback cell — reconstruct the Box and let it drop.
            // SAFETY: we created this via `Box::leak`, so `Box::from_raw`
            // is sound. The cell's `inner` was just dropped above;
            // dropping the Box now will free the SharedCell allocation.
            unsafe {
                let _ = Box::from_raw(ptr.as_ptr());
            }
            return;
        }
        // Real slab cell — return slot to freelist. Order:
        // inner already dropped, so future acquire can safely
        // initialise it.
        // refcount remains at 0 until next acquire bumps it to 1.
        self.free
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(cell.slot);
    }

    pub(crate) fn stats(&self) -> SlabStats {
        let free_len = self.free.lock().map(|g| g.len()).unwrap_or(0);
        SlabStats {
            cells_total: self.cells.len() as u64,
            cells_inflight: (self.cells.len() - free_len) as u64,
            inflight_peak: self.inflight_peak.load(Ordering::Relaxed),
            fallback_alloc_total: self.fallback_alloc_total.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of slab usage for metrics.
#[derive(Debug, Clone, Copy)]
pub struct SlabStats {
    pub cells_total: u64,
    pub cells_inflight: u64,
    pub inflight_peak: u64,
    pub fallback_alloc_total: u64,
}

/// Hard upper bound on `VEIL_SHARED_SLAB_CELLS`. The slab preallocates a
/// `Vec<SharedCell>` of the configured size at first use, so an absurd env
/// value (typo / hostile env) would otherwise drive a multi-GB allocation /
/// OOM at startup. 1 Mi cells is far above any real workload and caps the
/// preallocation. Values are clamped into `[1, MAX_SLAB_CELLS]`.
pub const MAX_SLAB_CELLS: usize = 1 << 20;

/// Lazy global slab — allocated on first use, persists for process
/// lifetime. Sized via `VEIL_SHARED_SLAB_CELLS` env (default
/// [`DEFAULT_SLAB_CELLS`]), clamped to `[1, MAX_SLAB_CELLS]`.
pub(crate) fn global() -> &'static SharedSlab {
    static GLOBAL: OnceLock<SharedSlab> = OnceLock::new();
    GLOBAL.get_or_init(|| {
        let cap = std::env::var("VEIL_SHARED_SLAB_CELLS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_SLAB_CELLS)
            .clamp(1, MAX_SLAB_CELLS);
        SharedSlab::new(cap)
    })
}

/// Acquire a refcounted slab cell, writing `inner` into the slot.
/// Returns a raw pointer that the caller wraps in `PooledShared`.
pub(crate) fn acquire(inner: PooledSharedInner) -> NonNull<SharedCell> {
    global().acquire(inner)
}

/// Snapshot global slab usage for metrics export.
pub fn stats() -> SlabStats {
    global().stats()
}

/// Increment refcount on `cell`. Used by `PooledShared::clone`.
///
/// # Safety
/// `cell` must point to a live SharedCell with refcount > 0.
pub(crate) unsafe fn clone_cell(cell: NonNull<SharedCell>) {
    let c = unsafe { cell.as_ref() };
    // Relaxed is sufficient for clone: the new ref doesn't observe
    // anything beyond what the cloning thread already saw.
    let prev = c.refcount.fetch_add(1, Ordering::Relaxed);
    debug_assert!(prev > 0, "clone of dropped SharedCell");
    // diff-audit M10: abort on refcount overflow in RELEASE too, like
    // `std::sync::Arc`. `refcount` is an `AtomicUsize` — only 32-bit wide on
    // 32-bit targets (mobile FFI / armv7), where a runaway clone could wrap
    // `usize::MAX → 0` and let a still-referenced cell be freed (use-after-free).
    // A `debug_assert` alone compiles out in release. Unreachable in practice
    // (needs ~2^31 live clones of one cell), so the branch is free on the hot
    // path; the abort just forecloses the UAF.
    if prev > usize::MAX / 2 {
        std::process::abort();
    }
}

/// Decrement refcount on `cell`; if it hits zero, return the cell to
/// the slab freelist (or free the heap fallback).
///
/// # Safety
/// `cell` must point to a live SharedCell with refcount > 0. After
/// this call, the caller MUST NOT use `cell` (the storage may be
/// reused by another thread immediately).
pub(crate) unsafe fn drop_cell(cell: NonNull<SharedCell>) {
    let c = unsafe { cell.as_ref() };
    // Release on decrement to synchronise our writes to the payload with
    // other threads' Acquire on the last decrement. Matches Arc.
    let prev = c.refcount.fetch_sub(1, Ordering::Release);
    if prev != 1 {
        return;
    }
    // We just observed the 1→0 transition. Issue an Acquire fence so
    // we synchronise with all prior Release decrements from other threads.
    fence(Ordering::Acquire);
    // SAFETY: refcount was 1 before our decrement, so no other thread
    // holds a pointer to the cell. Release to the slab.
    unsafe { global().release(cell) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_inner() -> PooledSharedInner {
        // Minimal inner with an orphan pool — drop is a no-op for bucket_idx=None.
        PooledSharedInner {
            buf: Vec::new(),
            bucket_idx: None,
            pool: crate::orphan_pool(),
        }
    }

    #[test]
    fn slab_acquire_returns_distinct_cells() {
        let p1 = acquire(dummy_inner());
        let p2 = acquire(dummy_inner());
        assert_ne!(p1.as_ptr(), p2.as_ptr());
        unsafe {
            drop_cell(p1);
            drop_cell(p2);
        }
    }

    #[test]
    fn refcount_clone_drop_returns_to_slab() {
        let stats_before = stats();
        let p = acquire(dummy_inner());
        unsafe {
            clone_cell(p);
            clone_cell(p);
            drop_cell(p);
            drop_cell(p);
            drop_cell(p);
        }
        let stats_after = stats();
        // Cell returned to slab — inflight should be back to whatever it
        // was before. (Not strictly equal in parallel tests, but
        // inflight should not have grown beyond the snapshot's peak.)
        assert!(stats_after.cells_inflight <= stats_before.cells_inflight.max(1));
    }

    #[test]
    fn slab_exhaustion_falls_back_to_heap() {
        // Build a private mini-slab so other parallel tests don't
        // race with us on the global one.
        let local: &'static SharedSlab = Box::leak(Box::new(SharedSlab::new(2)));
        let a = local.acquire(dummy_inner());
        let b = local.acquire(dummy_inner());
        let c = local.acquire(dummy_inner()); // fallback
        assert_eq!(local.stats().fallback_alloc_total, 1);
        unsafe {
            // Release in mixed order to exercise both paths.
            //
            // SAFETY: each pointer is a valid SharedCell with rc=1.
            let cell_a = a.as_ref();
            let cell_b = b.as_ref();
            let cell_c = c.as_ref();
            // Force the slab pointer indirection to use `local` (not
            // global) by calling.release directly. Mimics
            // drop_cell's flow without routing to the wrong slab.
            cell_a.refcount.fetch_sub(1, Ordering::Release);
            fence(Ordering::Acquire);
            local.release(a);
            cell_b.refcount.fetch_sub(1, Ordering::Release);
            fence(Ordering::Acquire);
            local.release(b);
            cell_c.refcount.fetch_sub(1, Ordering::Release);
            fence(Ordering::Acquire);
            local.release(c);
        }
    }

    #[test]
    fn threaded_clone_drop_sound() {
        // Use the high-level `PooledShared` API which implements Send.
        // (Bare `NonNull<SharedCell>` is!Send by default; intentional —
        // callers must go through the wrapper that owns refcount semantics.)
        let p = crate::pooled_shared_from_vec(b"thread-safe".to_vec());
        let p2 = p.clone();
        let p3 = p.clone();
        let handle1 = std::thread::spawn(move || {
            assert_eq!(p2.as_ref(), b"thread-safe");
            drop(p2);
        });
        let handle2 = std::thread::spawn(move || {
            assert_eq!(p3.as_ref(), b"thread-safe");
            drop(p3);
        });
        handle1.join().unwrap();
        handle2.join().unwrap();
        assert_eq!(p.as_ref(), b"thread-safe");
    }
}
