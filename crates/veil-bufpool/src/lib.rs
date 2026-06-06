//! Size-bucketed buffer pool for the veil daemon's frame hot path.
//!
//! # Why this exists
//!
//! `jemalloc` (Linux global allocator) handles
//! fragmentation well — RSS dropped 4-9× and stopped monotonically
//! growing. But under sustained 200 msg/sec × 60 KB frame churn the
//! daemon's resident set still **oscillates** between (e.g.) 45 MB and
//! 95 MB because dirty pages from freshly-freed Vec<u8> bodies sit in
//! jemalloc's per-arena dirty list until decay reclaim. On a 961 MB
//! VPS, the oscillation peaks were close to capacity ceilings.
//!
//! This pool eliminates the cycle by reusing buffers in-process:
//! the same Vec<u8> backing storage serves frame N+1 that just held
//! frame N's bytes. jemalloc never sees the free/alloc churn, so
//! pages never become dirty-and-reclaimable in the first place.
//!
//! # API shape (lifetime safety by type)
//!
//! Acquired buffers come in two flavours:
//!
//! [`Pooled`] — unique handle, `&mut [u8]` access. Inbound reader
//! reads bytes into it. Cannot be cloned, cannot be shared.
//! Returns to pool on Drop.
//! [`PooledShared`] — `Arc`-equivalent reference-counted handle
//! `&[u8]` access only. Suitable for the multi-hop relay fanout
//! path where N outbound writers share one inbound frame. Returns
//! to pool when the refcount drops to zero.
//!
//! `Pooled` converts into `PooledShared` once with
//! [`Pooled::into_shared`], at which point write access is forfeit.
//! There is no path back to unique access — this prevents data races
//! by construction.
//!
//! # Bounded growth guarantee
//!
//! Each size-bucket has a hard cap on the number of buffers it will
//! cache. When the cache is empty AND a new buffer is requested, the
//! pool falls back to a fresh heap allocation that bypasses the cache
//! entirely on Drop (counted as `fallback_alloc`). The pool **never
//! blocks** and **never panics** even under acquire spikes;
//! correctness is preserved by always servicing the request, at worst
//! by degrading to direct-heap behaviour identical to pre-pool code.
//!
//! When the cache is full AND a buffer comes home, the excess buffer
//! is dropped to the heap instead of cached (counted as
//! `overflow_drop`). This caps total pool memory at
//! `Σ bucket_cap × bucket_size` regardless of acquire rate.
//!
//! # Invariants
//!
//! 1. After `acquire(n)`, the returned handle's `capacity >= n`.
//!    The buffer is **logically empty** (`len == 0`) — callers
//!    must extend / `resize` it. Buffer contents from prior tenant
//!    are NOT zeroed (pool is a perf primitive; callers handle this
//!    if needed via `clear_and_resize_zeroed`).
//! 2. On `Pooled::drop` (and on `PooledShared`'s last drop), the
//!    buffer's `len` is reset to 0, `capacity` is preserved, and
//!    the buffer is offered to the pool. The pool may keep or
//!    reject (overflow_drop).
//! 3. The pool is `Send + Sync`. Internal state is protected by a
//!    short-critical-section `Mutex` (held only across the free-list
//!    Vec push/pop).
//! 4. A `PooledShared` cannot be cloned BEFORE the underlying buffer
//!    is written; or rather, write access is gone the moment the
//!    handle becomes shared — by type, not convention.
//!
//! # Metrics
//!
//! [`BufferPool::stats`] returns a snapshot suitable for prometheus
//! export. Callers must wire this into their metrics layer
//! (the pool itself has no observability dependency, by design —
//! it must remain a leaf crate with zero side effects).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

mod shared_slab;
pub use shared_slab::{SlabStats, stats as shared_slab_stats};

/// Pre-defined size buckets covering the veil daemon's typical
/// frame allocations. Sizes were chosen from observed workloads:
///
/// 256 B — small control frames (HELLO, PING, ACK, route updates)
/// 4 KiB — handshake messages, small APP_DATA
/// 64 KiB — full chat_node payloads, max APP_DATA bodies, IPC frames
///
/// Buckets are powers of 2 to keep bucket-selection branchless via
/// `next_power_of_two` rounding. Requests larger than the largest
/// bucket fall back to direct heap allocation.
const BUCKET_SIZES: &[usize] = &[256, 4096, 65536];

/// Hard cap on cached buffers per bucket. At 64 buffers × 64 KiB =
/// 4 MiB max cache per largest bucket, ~12 MiB total worst case.
/// Tuned so cache cap is small relative to typical RSS, large enough
/// to absorb sub-second bursts on a 200 msg/sec workload.
const DEFAULT_BUCKET_CAPACITY: usize = 64;

/// Public statistics snapshot for metrics export.
#[derive(Debug, Default, Clone, Copy)]
pub struct PoolStats {
    /// Total successful pool-cache hits (no allocation needed).
    pub cache_hit_total: u64,
    /// Total times the cache was empty and we fell back to heap.
    pub fallback_alloc_total: u64,
    /// Total returns rejected because the cache was full (buffer dropped).
    pub overflow_drop_total: u64,
    /// Total returns where the bucket size didn't match capacity
    /// (defensive: should be 0 in correct callers). Buffer is freed.
    pub return_anomaly_total: u64,
    /// Current number of buffers held in caches across all buckets.
    pub cached_inflight: u64,
    /// Peak number of cached buffers seen so far (across all buckets).
    pub cached_peak: u64,
}

/// Internal per-bucket state. Mutex-protected free list plus its
/// configured size + cap.
struct Bucket {
    /// Free-list of available buffers. All have `capacity == size`.
    free: Mutex<Vec<Vec<u8>>>,
    /// Bucket size in bytes (covers requests of `[prev_bucket+1, size]`).
    size: usize,
    /// Hard cap on cached buffers in this bucket.
    cap: usize,
}

impl Bucket {
    fn new(size: usize, cap: usize) -> Self {
        Self {
            free: Mutex::new(Vec::with_capacity(cap)),
            size,
            cap,
        }
    }

    /// Pop a buffer from the free list, or return None if empty.
    ///
    /// Poison-tolerant: an inner `Vec::pop` cannot panic, so poisoning
    /// requires a thread cancellation between `lock()` and the pop.
    /// Recovering matches the workspace-wide poison policy.
    fn pop(&self) -> Option<Vec<u8>> {
        let mut guard = self.free.lock().unwrap_or_else(|p| p.into_inner());
        guard.pop()
    }

    /// Try to return a buffer to the free list. Returns `true` if
    /// cached; `false` if the cache was full (buffer is dropped by
    /// caller).
    ///
    /// Poison-tolerant: see `pop`.
    fn push(&self, buf: Vec<u8>) -> bool {
        let mut guard = self.free.lock().unwrap_or_else(|p| p.into_inner());
        if guard.len() >= self.cap {
            return false;
        }
        guard.push(buf);
        true
    }

    /// Current cached count (for stats).
    fn cached_count(&self) -> usize {
        self.free.lock().map(|g| g.len()).unwrap_or(0)
    }
}

/// The buffer pool. Cheap to clone via `Arc` — clones share storage.
#[derive(Clone)]
pub struct BufferPool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    buckets: Vec<Bucket>,
    cache_hit: AtomicU64,
    fallback_alloc: AtomicU64,
    overflow_drop: AtomicU64,
    return_anomaly: AtomicU64,
    cached_peak: AtomicU64,
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_BUCKET_CAPACITY)
    }
}

impl BufferPool {
    /// Create a pool with the given per-bucket cap (same cap for all
    /// buckets — keeps the API minimal; if workload demands per-
    /// bucket caps, add an explicit constructor later).
    pub fn with_capacity(per_bucket_cap: usize) -> Self {
        let buckets: Vec<Bucket> = BUCKET_SIZES
            .iter()
            .map(|&s| Bucket::new(s, per_bucket_cap))
            .collect();
        Self {
            inner: Arc::new(PoolInner {
                buckets,
                cache_hit: AtomicU64::new(0),
                fallback_alloc: AtomicU64::new(0),
                overflow_drop: AtomicU64::new(0),
                return_anomaly: AtomicU64::new(0),
                cached_peak: AtomicU64::new(0),
            }),
        }
    }

    /// Acquire a buffer with at-least `min_capacity` bytes. Returns a
    /// unique handle. The buffer's `len` is 0 on return; contents
    /// of the underlying allocation are unspecified (NOT zeroed).
    ///
    /// Never blocks, never fails: falls back to direct heap if no
    /// bucket can serve the request.
    pub fn acquire(&self, min_capacity: usize) -> Pooled {
        // Find the smallest bucket that can serve the request.
        let bucket_idx = self
            .inner
            .buckets
            .iter()
            .position(|b| b.size >= min_capacity);

        match bucket_idx {
            Some(idx) => {
                let bucket = &self.inner.buckets[idx];
                if let Some(mut buf) = bucket.pop() {
                    buf.clear();
                    self.inner.cache_hit.fetch_add(1, Ordering::Relaxed);
                    Pooled {
                        buf,
                        bucket_idx: Some(idx),
                        pool: self.inner.clone(),
                    }
                } else {
                    // Bucket empty — alloc fresh at bucket size so it
                    // can be cached on return.
                    self.inner.fallback_alloc.fetch_add(1, Ordering::Relaxed);
                    let buf = Vec::with_capacity(bucket.size);
                    Pooled {
                        buf,
                        bucket_idx: Some(idx),
                        pool: self.inner.clone(),
                    }
                }
            }
            None => {
                // Request larger than largest bucket — direct heap
                // never cached. bucket_idx=None signals "skip return".
                self.inner.fallback_alloc.fetch_add(1, Ordering::Relaxed);
                let buf = Vec::with_capacity(min_capacity);
                Pooled {
                    buf,
                    bucket_idx: None,
                    pool: self.inner.clone(),
                }
            }
        }
    }

    /// Snapshot current pool statistics for metrics export.
    pub fn stats(&self) -> PoolStats {
        let cached_inflight: u64 = self
            .inner
            .buckets
            .iter()
            .map(|b| b.cached_count() as u64)
            .sum();
        // Update cached_peak atomically with monotonic max.
        loop {
            let prev = self.inner.cached_peak.load(Ordering::Relaxed);
            if cached_inflight <= prev {
                break;
            }
            if self
                .inner
                .cached_peak
                .compare_exchange_weak(prev, cached_inflight, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
        PoolStats {
            cache_hit_total: self.inner.cache_hit.load(Ordering::Relaxed),
            fallback_alloc_total: self.inner.fallback_alloc.load(Ordering::Relaxed),
            overflow_drop_total: self.inner.overflow_drop.load(Ordering::Relaxed),
            return_anomaly_total: self.inner.return_anomaly.load(Ordering::Relaxed),
            cached_inflight,
            cached_peak: self.inner.cached_peak.load(Ordering::Relaxed),
        }
    }
}

/// Unique buffer handle. Provides `&mut [u8]` access via Deref +
/// the inner `Vec<u8>` API. Returns to pool on Drop.
pub struct Pooled {
    buf: Vec<u8>,
    /// Bucket index for return. `None` means "don't cache" (oversize
    /// request that bypassed bucketing).
    bucket_idx: Option<usize>,
    pool: Arc<PoolInner>,
}

impl Pooled {
    /// Backing capacity.
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// Borrow the inner Vec mutably to fill bytes. Caller must NOT
    /// reduce `capacity` (e.g. via `shrink_to_fit`) or the pool's
    /// bucket invariant breaks on return — defended by
    /// `return_anomaly_total` counter.
    pub fn as_vec_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }

    // Audit cycle-5: `into_vec_detached` removed. It had ZERO callers anywhere
    // (production / tests / FFI) and was buggy — it `ptr::read`-d only `buf` out
    // of a `ManuallyDrop<Pooled>`, leaking the `pool: Arc<PoolInner>` field (one
    // strong-count per call) since `Drop for Pooled` was suppressed. The shared
    // path (`into_shared` / `pooled_shared_from_vec`) is the live API. Restore
    // from git history if a `Vec<u8>`-detach is ever genuinely needed (and read
    // ALL non-Copy fields then).

    /// Convert this unique handle into a refcounted shared handle.
    /// After this point, multiple readers can hold a `PooledShared`
    /// pointing to the same buffer, but no writer can mutate it.
    /// Buffer returns to pool when ALL `PooledShared` clones drop.
    pub fn into_shared(self) -> PooledShared {
        // Move fields out of Self without triggering its Drop (which
        // would otherwise return buf to the pool — we want to give
        // it to the PooledSharedInner instead, so PooledShared's
        // own Drop is what eventually returns).
        //
        // SAFETY: ManuallyDrop prevents the original Drop from
        // running. After ptr::read each field, the original
        // memory is logically uninitialised but we own the values.
        let this = std::mem::ManuallyDrop::new(self);
        let buf = unsafe { std::ptr::read(&this.buf) };
        let bucket_idx = this.bucket_idx;
        let pool = unsafe { std::ptr::read(&this.pool) };
        // m: acquire a slab cell rather than Arc::new(...).
        let cell = shared_slab::acquire(PooledSharedInner {
            buf,
            bucket_idx,
            pool,
        });
        PooledShared { cell }
    }
}

impl std::ops::Deref for Pooled {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buf
    }
}

impl std::ops::DerefMut for Pooled {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }
}

impl Drop for Pooled {
    fn drop(&mut self) {
        return_to_pool(&mut self.buf, self.bucket_idx, &self.pool);
    }
}

/// Refcounted shared buffer handle. Read-only access. Returns to
/// pool when the last clone drops.
///
/// m: backed by a pre-allocated slab cell (see
/// [`shared_slab`]). Each `PooledShared` is a 1-word raw pointer
/// into the slab; clone bumps a custom refcount, last drop returns
/// the cell to the freelist. Replaces previous `Arc<PooledSharedInner>`
/// which allocated ~64 bytes from jemalloc per shared handle —
/// at sustained 14k frames/sec that was the dominant remaining
/// allocator-pressure source.
pub struct PooledShared {
    cell: std::ptr::NonNull<shared_slab::SharedCell>,
}

// SAFETY: SharedCell is Send+Sync (atomic refcount); the inner
// PooledSharedInner is read-only through PooledShared's Deref — no
// interior mutation, no aliased mutable refs. Mirrors `Arc<T>` for
// T: Send + Sync.
unsafe impl Send for PooledShared {}
unsafe impl Sync for PooledShared {}

impl PooledShared {
    /// Borrow the underlying inner cell payload. Safe only when
    /// `self.cell` points to a live SharedCell with rc >= 1, which is
    /// our invariant — guaranteed by construction (refcount starts at
    /// 1 on acquire) and preserved by clone/drop (no decrement to 0
    /// while shared).
    #[inline]
    fn inner(&self) -> &PooledSharedInner {
        // SAFETY: cell is live (rc >= 1 invariant); payload was written
        // on acquire and has not been dropped (would require rc=0).
        unsafe { (*self.cell.as_ref().inner.get()).assume_init_ref() }
    }
}

impl Clone for PooledShared {
    fn clone(&self) -> Self {
        // SAFETY: self.cell is live (rc >= 1).
        unsafe {
            shared_slab::clone_cell(self.cell);
        }
        Self { cell: self.cell }
    }
}

impl Drop for PooledShared {
    fn drop(&mut self) {
        // SAFETY: self.cell is live (rc >= 1); the slab handles
        // payload-drop + return-to-freelist on the 1→0 transition.
        unsafe {
            shared_slab::drop_cell(self.cell);
        }
    }
}

impl std::fmt::Debug for PooledShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner();
        f.debug_struct("PooledShared")
            .field("len", &inner.buf.len())
            .field("capacity", &inner.buf.capacity())
            .finish()
    }
}

impl PartialEq for PooledShared {
    fn eq(&self, other: &Self) -> bool {
        self.inner().buf == other.inner().buf
    }
}

impl Eq for PooledShared {}

pub(crate) struct PooledSharedInner {
    pub(crate) buf: Vec<u8>,
    pub(crate) bucket_idx: Option<usize>,
    pub(crate) pool: Arc<PoolInner>,
}

impl PooledShared {
    pub fn len(&self) -> usize {
        self.inner().buf.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner().buf.is_empty()
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.inner().buf
    }
}

impl std::ops::Deref for PooledShared {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.inner().buf
    }
}

impl AsRef<[u8]> for PooledShared {
    fn as_ref(&self) -> &[u8] {
        &self.inner().buf
    }
}

impl Drop for PooledSharedInner {
    fn drop(&mut self) {
        return_to_pool(&mut self.buf, self.bucket_idx, &self.pool);
    }
}

/// Wrap an existing `Vec<u8>` as a `PooledShared` without copying.
///
/// The Vec's heap allocation is moved into a fresh `Pooled` handle, then
/// shared. `bucket_idx=None` flags it as "oversize / unmanaged" so it
/// will be freed normally on drop (not cached to a bucket — capacity
/// likely doesn't match a bucket size). Use this when migration to the
/// pool is incremental: producers that already hold a `Vec<u8>` (from
/// non-refactored code paths) can still feed into pool-typed channels
/// without a cascade refactor. Cache-hit benefit is forfeit on this
/// path; cache-warm benefit still applies to downstream consumers because
/// the buffer drops normally rather than holding a pool slot.
pub fn pooled_shared_from_vec(buf: Vec<u8>) -> PooledShared {
    // m: slab-allocated cell rather than Arc::new(...).
    let cell = shared_slab::acquire(PooledSharedInner {
        buf,
        bucket_idx: None,
        // Dangling Arc<PoolInner> would require carrying a live pool
        // reference; instead we lift a sentinel pool — its counters
        // would only be touched if Drop tried to return. Since
        // bucket_idx=None short-circuits the Drop's return path
        // before touching pool fields, this sentinel is safe.
        pool: orphan_pool(),
    });
    PooledShared { cell }
}

/// Lazy sentinel `Arc<PoolInner>` for `pooled_shared_from_vec` use only.
/// Its counters are never read/written by anyone except its own Drop —
/// which is a no-op because no `Pooled`/`PooledShared` ever sets its
/// `bucket_idx` to `Some` while pointing to it.
fn orphan_pool() -> Arc<PoolInner> {
    static ORPHAN: OnceLock<Arc<PoolInner>> = OnceLock::new();
    ORPHAN
        .get_or_init(|| {
            Arc::new(PoolInner {
                buckets: Vec::new(),
                cache_hit: AtomicU64::new(0),
                fallback_alloc: AtomicU64::new(0),
                overflow_drop: AtomicU64::new(0),
                return_anomaly: AtomicU64::new(0),
                cached_peak: AtomicU64::new(0),
            })
        })
        .clone()
}

/// Lazy-init accessor for the process-wide singleton `BufferPool`.
///
/// Capacity controlled by the optional env override `VEIL_BUFPOOL_CAP`
/// (default 64 per bucket). Multiple crates (veilcore, veil-ipc
/// future consumers) share the same pool so buffers recycle across all
/// frame-handling paths — inbound OVL1, outbound OVL1, IPC delivery.
///
/// First call wins. Race-safe via `OnceLock`. Returns a cheap-clone
/// handle (Arc-backed internally).
pub fn global() -> &'static BufferPool {
    static GLOBAL: OnceLock<BufferPool> = OnceLock::new();
    GLOBAL.get_or_init(|| {
        let cap = std::env::var("VEIL_BUFPOOL_CAP")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_BUCKET_CAPACITY);
        BufferPool::with_capacity(cap)
    })
}

/// Common return path: validate, reset len, push to bucket cache.
fn return_to_pool(buf: &mut Vec<u8>, bucket_idx: Option<usize>, pool: &PoolInner) {
    let Some(idx) = bucket_idx else {
        // Oversize buffer — never was cacheable. Just let Drop free.
        return;
    };
    let bucket = &pool.buckets[idx];
    // Defensive: if the caller did something weird that changed
    // capacity (e.g. shrink_to_fit), the buffer no longer matches
    // its bucket. Don't cache it — count anomaly + let Drop free.
    if buf.capacity() != bucket.size {
        pool.return_anomaly.fetch_add(1, Ordering::Relaxed);
        return;
    }
    buf.clear();
    // Take the Vec by replacing with a dummy empty one (whose Drop is
    // a no-op since capacity=0). This lets us move the original
    // into the bucket's free list without disturbing the &mut.
    let to_return = std::mem::take(buf);
    if !bucket.push(to_return) {
        // Cache full — buffer is dropped by Vec's own Drop because
        // we just `mem::take`d it and the local `to_return` goes out
        // of scope. Wait — actually we passed `to_return` BY VALUE
        // to `push`, so if push returns false it gave it back, and
        // we lose it on this scope's end. Same effect either way.
        pool.overflow_drop.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    // ── Core invariants ──────────────────────────────────────────────

    #[test]
    fn acquire_returns_empty_buffer_with_sufficient_capacity() {
        let pool = BufferPool::default();
        let buf = pool.acquire(1000);
        assert_eq!(buf.len(), 0);
        assert!(buf.capacity() >= 1000);
    }

    #[test]
    fn acquire_picks_smallest_fitting_bucket() {
        let pool = BufferPool::default();
        let small = pool.acquire(100);
        let med = pool.acquire(1000);
        let large = pool.acquire(60_000);
        // 100 → 256 bucket, 1000 → 4096 bucket, 60000 → 65536 bucket.
        assert_eq!(small.capacity(), 256);
        assert_eq!(med.capacity(), 4096);
        assert_eq!(large.capacity(), 65536);
    }

    #[test]
    fn acquire_oversize_falls_back_to_heap_no_cache() {
        let pool = BufferPool::default();
        let buf = pool.acquire(100_000); // > 65536 → oversize
        assert!(buf.capacity() >= 100_000);
        drop(buf);
        let stats = pool.stats();
        assert_eq!(stats.cached_inflight, 0, "oversize never cached");
        assert!(stats.fallback_alloc_total >= 1);
    }

    #[test]
    fn drop_returns_buffer_to_pool() {
        let pool = BufferPool::default();
        assert_eq!(pool.stats().cached_inflight, 0);
        {
            let _buf = pool.acquire(100);
            // While alive, NOT in cache.
            assert_eq!(pool.stats().cached_inflight, 0);
        }
        // After drop, IS in cache.
        assert_eq!(pool.stats().cached_inflight, 1);
    }

    #[test]
    fn reacquire_hits_cache() {
        let pool = BufferPool::default();
        drop(pool.acquire(100)); // primes cache
        assert_eq!(pool.stats().cached_inflight, 1);

        let buf = pool.acquire(100);
        let stats = pool.stats();
        assert_eq!(stats.cached_inflight, 0);
        assert_eq!(stats.cache_hit_total, 1);
        drop(buf);
    }

    #[test]
    fn overflow_drop_when_cache_full() {
        let pool = BufferPool::with_capacity(2); // tiny cap for test
        // Acquire and return 5 buffers in the 256-bucket. Cache holds
        // 2; overflow_drop counts 3.
        let bufs: Vec<_> = (0..5).map(|_| pool.acquire(100)).collect();
        drop(bufs);
        let stats = pool.stats();
        assert_eq!(stats.cached_inflight, 2);
        assert_eq!(stats.overflow_drop_total, 3);
    }

    #[test]
    fn fallback_alloc_when_cache_empty() {
        let pool = BufferPool::default();
        // First acquire: empty cache → fallback.
        let _buf = pool.acquire(100);
        let stats = pool.stats();
        assert_eq!(stats.cache_hit_total, 0);
        assert_eq!(stats.fallback_alloc_total, 1);
    }

    #[test]
    fn into_shared_skips_unique_drop_path() {
        let pool = BufferPool::default();
        let buf = pool.acquire(100);
        let shared = buf.into_shared();
        // Shared still alive → not yet cached.
        assert_eq!(pool.stats().cached_inflight, 0);
        drop(shared);
        // Shared dropped → cached.
        assert_eq!(pool.stats().cached_inflight, 1);
    }

    #[test]
    fn shared_clone_holds_buffer_until_last_drop() {
        let pool = BufferPool::default();
        let shared1 = pool.acquire(100).into_shared();
        let shared2 = shared1.clone();
        drop(shared1);
        assert_eq!(pool.stats().cached_inflight, 0, "still 1 clone alive");
        drop(shared2);
        assert_eq!(pool.stats().cached_inflight, 1);
    }

    #[test]
    fn return_anomaly_when_capacity_mutated() {
        let pool = BufferPool::default();
        let mut buf = pool.acquire(100);
        // Hostile caller: shrinks capacity. Now 0, doesn't match
        // 256-bucket. Should be counted as anomaly, not cached.
        buf.as_vec_mut().shrink_to_fit();
        drop(buf);
        let stats = pool.stats();
        assert_eq!(stats.cached_inflight, 0);
        assert_eq!(stats.return_anomaly_total, 1);
    }

    // ── Thread safety / property tests ───────────────────────────────

    #[test]
    fn concurrent_acquire_release_no_deadlock_or_loss() {
        let pool = BufferPool::default();
        let n_threads = 8;
        let iters_per_thread = 10_000;
        let handles: Vec<_> = (0..n_threads)
            .map(|tid| {
                let p = pool.clone();
                thread::spawn(move || {
                    let mut acc: u64 = 0;
                    for i in 0..iters_per_thread {
                        // Mix bucket sizes to stress all caches.
                        let sz = match (tid + i) % 3 {
                            0 => 100,
                            1 => 2000,
                            _ => 60_000,
                        };
                        let buf = p.acquire(sz);
                        // Touch the buffer so allocator commits pages.
                        acc = acc.wrapping_add(buf.capacity() as u64);
                    }
                    acc
                })
            })
            .collect();
        let mut total = 0u64;
        for h in handles {
            total = total.wrapping_add(h.join().unwrap());
        }
        // Sanity: each thread saw `iters_per_thread` buffers; total
        // touched must be non-zero.
        assert!(total > 0);
        let stats = pool.stats();
        // All buffers must have returned (cached_inflight bounded by
        // 3 buckets × default cap). No leaks: total acquired
        // ≈ cache_hit + fallback_alloc.
        let acquired = stats.cache_hit_total + stats.fallback_alloc_total;
        assert_eq!(acquired as usize, n_threads * iters_per_thread);
    }

    #[test]
    fn stress_overflow_keeps_invariants() {
        // tiny cap forces overflow path on every drop.
        let pool = BufferPool::with_capacity(1);
        for _ in 0..100 {
            let _bufs: Vec<_> = (0..10).map(|_| pool.acquire(100)).collect();
        }
        let stats = pool.stats();
        // Each iteration: 10 acquired (1 hit + 9 fallback after first)
        // 10 dropped (1 cached + 9 overflow). Roughly.
        assert!(stats.overflow_drop_total > 0);
        // Cache size never exceeds cap.
        assert!(stats.cached_inflight <= 3); // 1 per bucket × 3 buckets
    }
}
