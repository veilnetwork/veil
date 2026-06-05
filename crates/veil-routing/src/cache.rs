//! Route cache — short-lived multi-path next-hop hints.
//!
//! `RouteCache` maps each destination `node_id` to up to `MAX_ROUTES_PER_DST`
//! candidate next-hops, ordered by score (lower = better). Callers pick the
//! best live entry [`RouteCache::lookup`] and fall back to secondary hops
//! with [`RouteCache::lookup_all`] when the primary fails.
//!
//! Entries expire after a configurable TTL so the cache never becomes
//! permanently stale. A specific hop can be removed (e.g. after a send
//! failure) [`RouteCache::invalidate_hop`].
//!
//! **Persistence**: call [`RouteCache::snapshot`] to serialise the
//! current live entries to a `Vec<CacheEntrySnapshot>` and
//! [`RouteCache::restore`] to repopulate from a previously-saved snapshot.
//! Restored entries are tagged `is_stale = true` and sorted after fresh entries
//! in all lookup methods; they become fresh again when confirmed via `insert`.

use std::{
    collections::{HashMap, HashSet},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

use veil_proto::budget::{MAX_ROUTE_CACHE_SIZE, MAX_ROUTES_PER_DST, MAX_ROUTES_PER_VIA};

// monotonic counter used as a logical "last-accessed" timestamp
// on `RouteCacheEntry`. Replaces the previous `Instant` field so that
// `RouteCache::lookup*` can update LRU rank through `&self` — essential for a
// future `RwLock<RouteCache>` migration (read-heavy dispatch path). Relative
// ordering is all we need; wall-clock precision is not. u64 will not wrap in
// any realistic deployment (≈585 years at 1 ns granularity, and we step once
// per route lookup).
//
// (process-global counter — accepted): a
// per-`RouteCache` counter would require either `&mut self` on
// every lookup (incompatible with the future RwLock migration) or
// adding `AtomicU64` as an instance field, which forces a custom
// Clone impl (atomics aren't Clone). Cross-cache interleaving of
// the counter is harmless: the counter is only consulted within
// one cache's eviction-ordering decisions; values from a different
// cache never leak in. Test determinism is preserved because each
// cargo test process gets its own counter range.
static ROUTE_ACCESS_COUNTER: AtomicU64 = AtomicU64::new(1);

#[inline]
fn next_access_token() -> u64 {
    ROUTE_ACCESS_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ── CacheEntrySnapshot ────────────────────────────────────────────────────────

/// Serialisable snapshot of one route cache entry, used for persistence.
///
/// `Instant` fields are not preserved; they are reconstructed at restore time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntrySnapshot {
    pub dst_node_id: [u8; 32],
    pub next_hop: [u8; 32],
    pub score: u32,
    pub hop_count: u8,
    /// Historical contact count for `next_hop`.
    ///
    /// Defaults to `0` when reading snapshots written before this field was
    /// added so that old files remain valid.
    #[serde(default)]
    pub contact_count: u32,
}

// ── RouteCacheEntry ───────────────────────────────────────────────────────────

/// One cached route entry.
#[derive(Debug)]
pub struct RouteCacheEntry {
    /// The preferred next-hop toward `dst_node_id`.
    pub next_hop: [u8; 32],
    /// Score at insertion time (lower = better), stored as **integer milliunits**
    /// of the logical float score (e.g. logical `1.5` → stored `1500`).
    ///
    /// Using `u32` instead of `f32` guarantees total ordering (`u32::cmp` is
    /// infallible) and eliminates NaN/±Inf edge cases that would make
    /// `partial_cmp` unreliable.
    ///
    /// Typical range: `hop_count * 10_000` (direct peer = 10 000) up to
    /// `~250_000_000` for a high-latency, low-reachability multi-hop path.
    pub score: u32,
    /// Number of hops from this node to `dst` via `next_hop`.
    /// `1` for directly connected peers.
    pub hop_count: u8,
    /// Absolute expiry.
    pub expires_at: Instant,
    /// logical LRU token (monotonic counter). Updated on
    /// `lookup*` through `&self` via atomic `store` — allows lookup to be
    /// non-mutating and unlocks future `RwLock<RouteCache>` migration. Zero
    /// means "never accessed since insert"; larger = more recently used.
    pub last_used: AtomicU64,
    /// `true` for entries restored from a persisted snapshot.
    ///
    /// Stale entries are never evicted by TTL — they persist until a fresh
    /// `insert` overwrites them. They are sorted *after* all fresh entries
    /// (higher effective sort-key) so lookups prefer live routes but still fall
    /// back to stale routes when no fresh information is available.
    pub is_stale: bool,
    /// capability labels claimed by the destination (target)
    /// signed and propagated via `RouteResponsePayload.target_labels`.
    /// Lets requesters filter routes by attribute (e.g. "exit-capable").
    /// Empty when the target advertised no labels or for entries inserted
    /// before label propagation existed.
    pub labels: Vec<[u8; veil_proto::budget::LABEL_WIDTH]>,
}

impl Clone for RouteCacheEntry {
    fn clone(&self) -> Self {
        Self {
            next_hop: self.next_hop,
            score: self.score,
            hop_count: self.hop_count,
            expires_at: self.expires_at,
            last_used: AtomicU64::new(self.last_used.load(Ordering::Relaxed)),
            is_stale: self.is_stale,
            labels: self.labels.clone(),
        }
    }
}

impl RouteCacheEntry {
    /// Returns `true` if this entry has passed its TTL.
    ///
    /// Stale (snapshot-restored) entries never expire by time — only by being
    /// overwritten with a fresh `insert` or explicitly invalidated.
    pub fn is_expired(&self, now: Instant) -> bool {
        !self.is_stale && now >= self.expires_at
    }

    /// Sort key: stale entries sort after all fresh entries.
    ///
    /// Uses the upper 32 bits to carry the stale flag so that all fresh routes
    /// (stale=0) sort before all stale routes (stale=1) regardless of score.
    #[inline]
    fn sort_key(&self) -> u64 {
        ((self.is_stale as u64) << 32) | self.score as u64
    }
}

// ── RouteCache ────────────────────────────────────────────────────────────────

/// Short-lived multi-path next-hop hints indexed by destination node_id.
///
/// Each destination can have up to `MAX_ROUTES_PER_DST` candidates sorted by
/// score ascending (best first).
///
/// A per-via rate limit (`MAX_ROUTES_PER_VIA`) bounds how many distinct
/// destinations any single `next_hop` peer may appear in. This prevents a
/// misbehaving relay from flooding the cache with fake destinations and
/// starving legitimate routes via LRU eviction.
#[derive(Debug, Clone)]
pub struct RouteCache {
    /// dst_node_id → sorted Vec<RouteCacheEntry> (score asc, max MAX_ROUTES_PER_DST)
    entries: HashMap<[u8; 32], Vec<RouteCacheEntry>>,
    /// next_hop → number of distinct dst_node_ids where it appears.
    /// Entries are removed when count drops to zero.
    via_counts: HashMap<[u8; 32], usize>,
    /// Reverse index: next_hop → set of dst_node_ids that route through it.
    ///
    /// Maintained alongside `via_counts` so that `rescore_via` can target only
    /// the affected destination buckets instead of scanning all entries (O(1)
    /// per-via lookup vs O(n×m) scan). May contain stale entries after TTL
    /// expiry (which only happens during lookup, not explicitly here), but
    /// those are harmlessly skipped during `rescore_via`.
    via_to_dsts: HashMap<[u8; 32], HashSet<[u8; 32]>>,
    ttl: Duration,
    /// Per-origin version counter for event-driven sync.
    /// Tracks the latest version seen for each origin to produce version vectors.
    route_versions: HashMap<[u8; 32], u64>,
    /// Maximum number of destination entries (0 = unlimited).
    /// configurable capacity; insert evicts LRU when full.
    max_destinations: usize,
}

impl RouteCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            via_counts: HashMap::new(),
            via_to_dsts: HashMap::new(),
            ttl,
            route_versions: HashMap::new(),
            max_destinations: 0, // unlimited
        }
    }

    /// Resize the cache capacity online.
    ///
    /// When `new_cap < current entries`, the least-recently-used destinations
    /// are evicted. Hot (recently used) entries are preserved.
    pub fn resize(&mut self, new_cap: usize) {
        self.max_destinations = new_cap;
        if new_cap == 0 {
            return;
        } // unlimited
        // M5: was O(N²) — full-table scan inside `while
        // entries.len > new_cap` loop. At N=10K and 10% shrink that's
        // ~10M comparisons during a single memory-pressure event. Replace
        // with a single sort: collect (dst, oldest_in_bucket), sort
        // ascending, drain the front until size <= new_cap. O(N log N)
        // total, ~7K comparisons at N=10K — three orders of magnitude
        // faster.
        if self.entries.len() > new_cap {
            let to_remove = self.entries.len() - new_cap;
            let mut by_age: Vec<([u8; 32], u64)> = self
                .entries
                .iter()
                .map(|(dst, routes)| {
                    let oldest = routes
                        .iter()
                        .map(|r| r.last_used.load(Ordering::Relaxed))
                        .min()
                        .unwrap_or(u64::MAX);
                    (*dst, oldest)
                })
                .collect();
            // Partial-sort would be faster but for the rare resize event
            // and N ≤ ~10K, full sort is plenty. Smallest oldest = oldest
            // overall = first to evict.
            by_age.sort_by_key(|(_, t)| *t);
            for (dst, _) in by_age.into_iter().take(to_remove) {
                if let Some(routes) = self.entries.remove(&dst) {
                    for r in &routes {
                        Self::via_dec(&mut self.via_counts, r.next_hop);
                        Self::idx_remove(&mut self.via_to_dsts, &r.next_hop, &dst);
                    }
                }
                self.route_versions.remove(&dst);
            }
        }
        // Defensive idempotent-tail block (kept for symmetry with old code
        // path). No-op when the bulk-evict above was sufficient.
        while self.entries.len() > new_cap {
            let coldest = self.entries.keys().next().copied();
            if let Some(dst) = coldest {
                if let Some(routes) = self.entries.remove(&dst) {
                    for r in &routes {
                        Self::via_dec(&mut self.via_counts, r.next_hop);
                        Self::idx_remove(&mut self.via_to_dsts, &r.next_hop, &dst);
                    }
                }
                self.route_versions.remove(&dst);
            } else {
                break;
            }
        }
    }

    /// Update the version for an origin.
    pub fn update_version(&mut self, origin: [u8; 32], version: u64) {
        // Audit M-C: bound `route_versions` so it cannot grow without limit on
        // origin churn (previously it was pruned ONLY inside `resize()`, never
        // on the LRU-evict / invalidate / expire paths). On the direct route
        // plane the immediate peer self-signs the RouteUpdate, so it controls
        // `origin_node_id` freely — a stream of distinct origins would add a
        // permanent entry each, leaking memory AND, past 10_000 entries, making
        // this node's periodic `version_summary()` broadcast undecodable by
        // every receiver (`VersionVectorSyncPayload::decode` rejects
        // count > 10_000). Cap at `MAX_ROUTE_CACHE_SIZE` (same bound as
        // `entries`), evicting the lowest-version (most stale) origin when full
        // before inserting a new one — the same policy as `route_origin_seq`.
        if !self.route_versions.contains_key(&origin)
            && self.route_versions.len() >= MAX_ROUTE_CACHE_SIZE
            && let Some(evict) = self
                .route_versions
                .iter()
                .min_by_key(|(_, v)| **v)
                .map(|(k, _)| *k)
        {
            self.route_versions.remove(&evict);
        }
        let entry = self.route_versions.entry(origin).or_insert(0);
        if version > *entry {
            *entry = version;
        }
    }

    /// Return a summary of all known origin→version pairs for version-vector exchange.
    pub fn version_summary(&self) -> Vec<([u8; 32], u64)> {
        self.route_versions.iter().map(|(k, v)| (*k, *v)).collect()
    }

    // ── insert ────────────────────────────────────────────────────────────

    /// Insert or update a route.
    ///
    /// * If `next_hop` already exists for `dst_node_id`, its score and expiry
    ///   are updated in place and the list re-sorted (no via_count change).
    /// * If `next_hop` is new and the per-via limit (`MAX_ROUTES_PER_VIA`) is
    ///   reached for this `next_hop`, the insertion is silently dropped.
    /// * If `next_hop` is new and the bucket is at `MAX_ROUTES_PER_DST`, the
    ///   worst-scoring (last) entry is evicted first.
    /// * When the number of tracked *destinations* would exceed
    ///   `MAX_ROUTE_CACHE_SIZE`, the least-recently-used destination bucket is
    ///   evicted entirely and its via_counts decremented.
    pub fn insert(&mut self, dst_node_id: [u8; 32], next_hop: [u8; 32], score: u32, hop_count: u8) {
        self.insert_labelled(dst_node_id, next_hop, score, hop_count, Vec::new());
    }

    /// variant [`Self::insert`] that
    /// records the destination's capability labels alongside the route
    /// entry.
    ///
    /// **Contract (load-bearing):** the caller MUST have just
    /// verified that `labels` come from a payload whose digital
    /// signature was produced by the target identified by
    /// `dst_node_id`. Concretely, `RouteResponsePayload::signable_bytes`
    /// already includes `target_labels`, so the production caller in
    /// `dispatcher/routing.rs` can only reach the `wlock!(route_cache)
    ///.insert_labelled(...)` line after the `sig_valid` check has
    /// passed. Any future caller that adopts this method MUST
    /// preserve the same invariant — otherwise a peer can plant
    /// label-of-their-choice (e.g. `"exit"`) into the cache and bias
    /// traffic egress through itself.
    ///
    /// Existing call sites use [`Self::insert`] which delegates with
    /// empty labels — only the `RouteResponse` ingestion path needs to
    /// call this with real labels.
    pub fn insert_labelled(
        &mut self,
        dst_node_id: [u8; 32],
        next_hop: [u8; 32],
        score: u32,
        hop_count: u8,
        labels: Vec<[u8; veil_proto::budget::LABEL_WIDTH]>,
    ) {
        let now = Instant::now();
        let new_entry = RouteCacheEntry {
            next_hop,
            score,
            hop_count,
            expires_at: now + self.ttl,
            // fresh insert gets the latest access token so LRU
            // sees it as the most recently used.
            last_used: AtomicU64::new(next_access_token()),
            is_stale: false,
            labels,
        };

        if self.entries.contains_key(&dst_node_id) {
            // ── existing destination bucket ────────────────────────────────
            // Determine if this is an update to an existing hop or a new one
            // and collect any via_count changes needed — all BEFORE the bucket
            // borrow so that self.via_counts can be mutated freely afterward.
            let is_existing_hop = self.entries[&dst_node_id]
                .iter()
                .any(|e| e.next_hop == next_hop);

            if !is_existing_hop {
                // New next_hop: check per-via limit.
                if self.via_counts.get(&next_hop).copied().unwrap_or(0) >= MAX_ROUTES_PER_VIA {
                    return;
                }
            }

            // Now mutate the bucket; collect the evicted hop (if any) as a
            // plain Copy value so the borrow on self.entries ends before we
            // touch self.via_counts.
            let evicted_hop: Option<[u8; 32]> = {
                let Some(bucket) = self.entries.get_mut(&dst_node_id) else {
                    return;
                };
                if let Some(pos) = bucket.iter().position(|e| e.next_hop == next_hop) {
                    bucket[pos] = new_entry; // update — no via_count change
                    bucket.sort_by_key(|e| e.sort_key());
                    None
                } else {
                    let evicted = if bucket.len() >= MAX_ROUTES_PER_DST {
                        if new_entry.score >= bucket.last().map_or(u32::MAX, |e| e.score) {
                            return; // new entry is worse — discard it
                        }
                        Some(bucket.pop().expect("bucket is non-empty: len >= MAX_ROUTES_PER_DST was just checked").next_hop)
                    } else {
                        None
                    };
                    bucket.push(new_entry);
                    bucket.sort_by_key(|e| e.sort_key());
                    evicted
                }
                // bucket borrow dropped here when the block ends
            };

            // Apply via_count + reverse-index changes — no entries borrow held.
            if !is_existing_hop {
                *self.via_counts.entry(next_hop).or_insert(0) += 1;
                Self::idx_add(&mut self.via_to_dsts, next_hop, dst_node_id);
            }
            if let Some(hop) = evicted_hop {
                Self::via_dec(&mut self.via_counts, hop);
                Self::idx_remove(&mut self.via_to_dsts, &hop, &dst_node_id);
            }
        } else {
            // ── new destination ────────────────────────────────────────────
            if self.via_counts.get(&next_hop).copied().unwrap_or(0) >= MAX_ROUTES_PER_VIA {
                return;
            }
            // Evict LRU bucket if at capacity; collect (dst, hops) before
            // mutating via_counts / via_to_dsts.
            let lru_evicted: Option<([u8; 32], Vec<[u8; 32]>)> =
                if self.entries.len() >= MAX_ROUTE_CACHE_SIZE {
                    // True LRU: find the bucket whose most-recent access is oldest.
                    // `last_used` is a u64 access-counter; higher
                    // value = more recently used. Find the bucket whose
                    // maximum (newest) access token is the lowest.
                    let lru_key = self
                        .entries
                        .iter()
                        .filter_map(|(k, v)| {
                            v.iter()
                                .map(|e| e.last_used.load(Ordering::Relaxed))
                                .max()
                                .map(|t| (*k, t))
                        })
                        .min_by_key(|(_, t)| *t)
                        .map(|(k, _)| k);
                    lru_key.and_then(|k| {
                        self.entries.remove(&k).map(|b| {
                            let hops = b.into_iter().map(|e| e.next_hop).collect();
                            (k, hops)
                        })
                    })
                } else {
                    None
                };
            self.entries.insert(dst_node_id, vec![new_entry]);
            *self.via_counts.entry(next_hop).or_insert(0) += 1;
            Self::idx_add(&mut self.via_to_dsts, next_hop, dst_node_id);
            if let Some((lru_dst, hops)) = lru_evicted {
                for hop in hops {
                    Self::via_dec(&mut self.via_counts, hop);
                    Self::idx_remove(&mut self.via_to_dsts, &hop, &lru_dst);
                }
            }
        }
    }

    /// Decrement the via_count for `hop`, removing the entry when it reaches zero.
    ///
    /// Takes `via_counts` directly (not `&mut self`) so it can be called while
    /// other fields of `RouteCache` are borrowed.
    fn via_dec(via_counts: &mut HashMap<[u8; 32], usize>, hop: [u8; 32]) {
        if let Some(c) = via_counts.get_mut(&hop) {
            if *c <= 1 {
                via_counts.remove(&hop);
            } else {
                *c -= 1;
            }
        }
    }

    /// Record that `dst` routes through `via` in the reverse index.
    fn idx_add(
        via_to_dsts: &mut HashMap<[u8; 32], HashSet<[u8; 32]>>,
        via: [u8; 32],
        dst: [u8; 32],
    ) {
        via_to_dsts.entry(via).or_default().insert(dst);
    }

    /// Remove `dst` from `via`'s reverse-index set; drop the set when empty.
    fn idx_remove(
        via_to_dsts: &mut HashMap<[u8; 32], HashSet<[u8; 32]>>,
        via: &[u8; 32],
        dst: &[u8; 32],
    ) {
        if let Some(set) = via_to_dsts.get_mut(via) {
            set.remove(dst);
            if set.is_empty() {
                via_to_dsts.remove(via);
            }
        }
    }

    // ── lookup ────────────────────────────────────────────────────────────

    /// return the best non-expired next-hop for `dst_node_id`
    /// **only if** the cached entry advertises *all* `required_labels`.
    /// Returns `None` when no labelled match exists — callers can fall back
    /// [`Self::lookup`] for an any-route route. An empty
    /// `required_labels` slice degenerates [`Self::lookup`] semantics
    /// (filter is satisfied trivially). Updates LRU on the winning entry.
    pub fn lookup_with_labels(
        &self,
        dst_node_id: &[u8; 32],
        required_labels: &[[u8; veil_proto::budget::LABEL_WIDTH]],
    ) -> Option<[u8; 32]> {
        let now = Instant::now();
        let bucket = self.entries.get(dst_node_id)?;
        let entry = bucket.iter().find(|e| {
            !e.is_expired(now) && required_labels.iter().all(|req| e.labels.contains(req))
        })?;
        entry
            .last_used
            .store(next_access_token(), Ordering::Relaxed);
        Some(entry.next_hop)
    }

    /// Return the best (lowest-score) non-expired next-hop for `dst_node_id`.
    ///
    /// Updates the winning entry's LRU token through `&self` (atomic store).
    /// Expired entries are not pruned inline — that happens in the periodic
    /// `evict_expired` tick; lookup just skips over them.
    pub fn lookup(&self, dst_node_id: &[u8; 32]) -> Option<[u8; 32]> {
        let now = Instant::now();
        let bucket = self.entries.get(dst_node_id)?;
        let entry = bucket.iter().find(|e| !e.is_expired(now))?;
        entry
            .last_used
            .store(next_access_token(), Ordering::Relaxed);
        Some(entry.next_hop)
    }

    /// Return **all** non-expired next-hops for `dst_node_id`, best-first.
    ///
    /// Useful when the primary hop fails and a fallback is needed.
    pub fn lookup_all(&self, dst_node_id: &[u8; 32]) -> Vec<[u8; 32]> {
        self.lookup_all_with_scores_and_hops(dst_node_id)
            .into_iter()
            .map(|(hop, _, _)| hop)
            .collect()
    }

    /// Combined lookup returning `(next_hop, score, hop_count)` triples in a
    /// single call — avoids acquiring the route-cache lock twice when both
    /// the raw score (for ECMP grouping) and the hop count (for penalty) are
    /// needed at the same time.
    ///
    /// takes `&self` so lookups can be done under `RwLock::read`
    /// in a future migration. Expired entries are skipped (not pruned
    /// inline); the periodic `evict_expired` tick handles cleanup.
    pub fn lookup_all_with_scores_and_hops(
        &self,
        dst_node_id: &[u8; 32],
    ) -> Vec<([u8; 32], u32, u8)> {
        let now = Instant::now();
        let Some(bucket) = self.entries.get(dst_node_id) else {
            return vec![];
        };
        // Atomic LRU refresh on every live entry in the bucket. We keep the
        // whole-bucket refresh (not just the winner) because callers of this
        // method use the full set for fan-out ECMP; any hit in the set
        // constitutes "active use".
        let token = next_access_token();
        let mut out = Vec::with_capacity(bucket.len());
        for e in bucket.iter() {
            if e.is_expired(now) {
                continue;
            }
            e.last_used.store(token, Ordering::Relaxed);
            out.push((e.next_hop, e.score, e.hop_count));
        }
        out
    }

    // ── invalidate ────────────────────────────────────────────────────────

    /// Remove a **specific** next-hop for `dst_node_id` (e.g. after a send
    /// failure). Other hops for the same destination remain intact.
    pub fn invalidate_hop(&mut self, dst_node_id: &[u8; 32], next_hop: &[u8; 32]) {
        // Mutate the bucket first; then decrement via_count after the borrow drops.
        let (hop_removed, bucket_empty) = {
            if let Some(bucket) = self.entries.get_mut(dst_node_id) {
                let before = bucket.len();
                bucket.retain(|e| &e.next_hop != next_hop);
                (bucket.len() < before, bucket.is_empty())
            } else {
                (false, false)
            }
        };
        if hop_removed {
            Self::via_dec(&mut self.via_counts, *next_hop);
            Self::idx_remove(&mut self.via_to_dsts, next_hop, dst_node_id);
        }
        if bucket_empty {
            self.entries.remove(dst_node_id);
        }
    }

    /// Remove **all** routes whose next-hop is `via` (e.g. after the session
    /// to `via` is closed).
    ///
    /// Uses the `via_to_dsts` reverse index for an O(|affected_dsts|) walk
    /// instead of a full O(n×m) scan. After this call no cached entry will
    /// route through `via`.
    pub fn invalidate_all_via(&mut self, via: &[u8; 32]) {
        // Snapshot affected destinations from the reverse index — we need to
        // release the borrow on via_to_dsts before mutating entries.
        let affected: Vec<[u8; 32]> = self
            .via_to_dsts
            .get(via)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();

        for dst in &affected {
            if let Some(bucket) = self.entries.get_mut(dst) {
                bucket.retain(|e| &e.next_hop != via);
                if bucket.is_empty() {
                    self.entries.remove(dst);
                }
            }
        }

        // Remove the via's count entry and reverse-index in one shot —
        // all affected (dst) pairs have been removed above.
        self.via_counts.remove(via);
        self.via_to_dsts.remove(via);
    }

    /// Rescore all entries that use `via` as their next-hop.
    ///
    /// `score_fn(hop_count) -> score` is called for each matching entry and
    /// should use the same formula as `RouteCache::insert` so that relative
    /// ordering within buckets stays consistent. Each affected bucket is
    /// re-sorted after the update.
    ///
    /// Called on `ROUTE_REPLY` receipt to refresh cache scores when a fresh
    /// RTT measurement changes the effective reachability of a peer (137.6).
    ///
    /// Uses the `via_to_dsts` reverse index to avoid an O(n×m) scan — only
    /// the destination buckets that actually route through `via` are visited.
    /// multiply the score of every route through `via` by
    /// `factor` (≥ 1.0). Used as a fast degradation signal when the
    /// session to `via` closes abnormally — it doesn't *remove* the routes
    /// (the peer might come back, the cache TTL handles real eviction)
    /// but pushes them out of the ECMP / multi-path band so alternative
    /// paths win immediately. No-op when `via` has no cached routes.
    ///
    /// Multiplication saturates at `u32::MAX`; lookup still returns these
    /// routes when they're the only option (as last-resort fallback).
    pub fn demote_via(&mut self, via: &[u8; 32], factor: f64) {
        if factor <= 1.0 {
            return;
        }
        // Reverse-index lookup so we only touch buckets that route through
        // `via` — same approach as `rescore_via` but with multiplicative
        // semantics (we want to scale the existing score, not derive a new
        // one from `hop_count`).
        let affected: Vec<[u8; 32]> = self
            .via_to_dsts
            .get(via)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        for dst in affected {
            if let Some(bucket) = self.entries.get_mut(&dst) {
                for entry in bucket.iter_mut() {
                    if &entry.next_hop == via {
                        let bumped = (entry.score as f64 * factor).round();
                        entry.score = if bumped >= u32::MAX as f64 {
                            u32::MAX
                        } else {
                            bumped as u32
                        };
                    }
                }
                bucket.sort_by_key(|e| e.sort_key());
            }
        }
    }

    pub fn rescore_via(&mut self, via: &[u8; 32], score_fn: impl Fn(u8) -> u32) {
        // Collect the affected destinations from the reverse index without
        // holding a borrow on `via_to_dsts` during the mutating loop.
        let affected: Vec<[u8; 32]> = self
            .via_to_dsts
            .get(via)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();

        for dst in affected {
            if let Some(bucket) = self.entries.get_mut(&dst) {
                let mut changed = false;
                for entry in bucket.iter_mut() {
                    if &entry.next_hop == via {
                        entry.score = score_fn(entry.hop_count);
                        changed = true;
                    }
                }
                if changed {
                    bucket.sort_by_key(|e| e.sort_key());
                }
            }
        }
    }

    // ── persistence ───────────────────────────────────────────────────────

    /// Serialise all **fresh** (non-stale), non-expired routes to a snapshot.
    ///
    /// Only fresh entries are snapshotted; writing previously-restored stale
    /// entries back to disk would perpetuate possibly-outdated topology data.
    ///
    /// Pass `contact_counts` (a map of `next_hop → contact_count` from the
    /// RTT table) to embed historical contact frequencies in the snapshot so
    /// they survive a node restart.
    pub fn snapshot(
        &self,
        contact_counts: &std::collections::HashMap<[u8; 32], u32>,
    ) -> Vec<CacheEntrySnapshot> {
        let now = Instant::now();
        let mut out = Vec::new();
        for (dst, bucket) in &self.entries {
            for e in bucket {
                if !e.is_stale && !e.is_expired(now) {
                    out.push(CacheEntrySnapshot {
                        dst_node_id: *dst,
                        next_hop: e.next_hop,
                        score: e.score,
                        hop_count: e.hop_count,
                        contact_count: contact_counts.get(&e.next_hop).copied().unwrap_or(0),
                    });
                }
            }
        }
        out
    }

    /// Repopulate the cache from a previously-saved snapshot.
    ///
    /// All inserted entries are tagged `is_stale = true` so that they sort
    /// after fresh entries in every lookup. Existing entries (e.g., already
    /// acquired by startup peers) are not overwritten.
    ///
    /// Capacity limits (`MAX_ROUTES_PER_DST`, `MAX_ROUTES_PER_VIA`
    /// `MAX_ROUTE_CACHE_SIZE`) are respected; entries that would exceed them are
    /// silently dropped rather than evicting live routes.
    pub fn restore(&mut self, entries: Vec<CacheEntrySnapshot>) {
        let now = Instant::now();
        for snap in entries {
            // Honour per-via limit.
            if self.via_counts.get(&snap.next_hop).copied().unwrap_or(0) >= MAX_ROUTES_PER_VIA {
                continue;
            }
            // Don't evict live entries to make room for stale ones.
            if !self.entries.contains_key(&snap.dst_node_id)
                && self.entries.len() >= MAX_ROUTE_CACHE_SIZE
            {
                continue;
            }
            let entry = RouteCacheEntry {
                next_hop: snap.next_hop,
                score: snap.score,
                hop_count: snap.hop_count,
                expires_at: now + self.ttl,
                // restored stale entries get a fresh access
                // token so they compete in LRU on equal footing with live
                // inserts (if an operator restores and immediately inserts
                // both count as "just-used").
                last_used: AtomicU64::new(next_access_token()),
                is_stale: true,
                // snapshot format does not yet carry labels —
                // restored entries get an empty list and will only have
                // labels populated when the next live RouteResponse arrives.
                labels: Vec::new(),
            };
            let bucket = self.entries.entry(snap.dst_node_id).or_default();
            if bucket.len() < MAX_ROUTES_PER_DST
                && !bucket.iter().any(|e| e.next_hop == snap.next_hop)
            {
                bucket.push(entry);
                bucket.sort_by_key(|e| e.sort_key());
                *self.via_counts.entry(snap.next_hop).or_insert(0) += 1;
                Self::idx_add(&mut self.via_to_dsts, snap.next_hop, snap.dst_node_id);
            }
        }
    }

    /// Remove **all** routes for `dst_node_id`.
    pub fn invalidate(&mut self, dst_node_id: &[u8; 32]) {
        if let Some(bucket) = self.entries.remove(dst_node_id) {
            // entries.remove gives us ownership, so via_counts/via_to_dsts are free to mutate.
            for e in &bucket {
                Self::via_dec(&mut self.via_counts, e.next_hop);
                Self::idx_remove(&mut self.via_to_dsts, &e.next_hop, dst_node_id);
            }
        }
    }

    // ── snapshot ──────────────────────────────────────────────────────────

    /// Return `(dst_node_id, best_next_hop, hop_count)` for every non-expired
    /// destination. Used by `on_session_opened` to bootstrap a new peer's
    /// routing knowledge with the full local routing table.
    pub fn all_routes(&mut self) -> Vec<([u8; 32], [u8; 32], u8)> {
        let now = Instant::now();
        let mut out = Vec::with_capacity(self.entries.len());
        for (dst, bucket) in &mut self.entries {
            bucket.retain(|e| !e.is_expired(now));
            if let Some(best) = bucket.first() {
                out.push((*dst, best.next_hop, best.hop_count));
            }
        }
        // Remove now-empty buckets.
        self.entries.retain(|_, b| !b.is_empty());
        out
    }

    /// Number of distinct destinations cached. Cheap O(1) accessor for
    /// metrics; each destination may hold up to `MAX_ROUTES_PER_DST`
    /// candidate routes (see [`total_routes`](Self::total_routes)).
    pub fn destination_count(&self) -> usize {
        self.entries.len()
    }

    /// Total number (destination, route) pairs across all buckets.
    /// Operator-visible upper bound on cache memory footprint —
    /// roughly `total_routes * 96` bytes for the entry struct itself.
    pub fn total_routes(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    /// Return `(dst, next_hop, score, hop_count)` for every non-expired route.
    ///
    /// Used by the admin introspection path (`node routes`).
    pub fn all_routes_with_score(&self) -> Vec<([u8; 32], [u8; 32], u32, u8)> {
        let now = Instant::now();
        let mut out = Vec::with_capacity(self.entries.len());
        for (dst, bucket) in &self.entries {
            for e in bucket {
                if !e.is_expired(now) {
                    out.push((*dst, e.next_hop, e.score, e.hop_count));
                }
            }
        }
        out
    }

    // ── maintenance ───────────────────────────────────────────────────────

    /// Evict all expired entries across all destinations.
    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        // Collect expired (next_hop, dst) pairs first, then update indexes
        // after the entries borrow is dropped.
        let mut expired: Vec<([u8; 32], [u8; 32])> = Vec::new();
        for (dst, bucket) in self.entries.iter() {
            for e in bucket.iter() {
                if e.is_expired(now) {
                    expired.push((e.next_hop, *dst));
                }
            }
        }
        for bucket in self.entries.values_mut() {
            bucket.retain(|e| !e.is_expired(now));
        }
        self.entries.retain(|_, b| !b.is_empty());
        // entries borrow fully released; safe to mutate via_counts + via_to_dsts.
        for (hop, dst) in &expired {
            Self::via_dec(&mut self.via_counts, *hop);
            Self::idx_remove(&mut self.via_to_dsts, hop, dst);
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_lookup_single() {
        let mut cache = RouteCache::new(Duration::from_secs(60));
        cache.insert([1u8; 32], [2u8; 32], 5_000, 1);
        assert_eq!(cache.lookup(&[1u8; 32]), Some([2u8; 32]));
    }

    /// Audit M-C: `route_versions` must stay bounded at `MAX_ROUTE_CACHE_SIZE`
    /// under origin churn (a peer streaming distinct self-signed origins), so it
    /// neither leaks memory nor grows the version_summary() broadcast past the
    /// 10_000-entry VV-sync decode limit.
    #[test]
    fn update_version_is_bounded_m_c() {
        let mut cache = RouteCache::new(Duration::from_secs(60));
        for i in 0..(MAX_ROUTE_CACHE_SIZE + 500) {
            let mut origin = [0u8; 32];
            origin[..8].copy_from_slice(&(i as u64).to_be_bytes());
            cache.update_version(origin, i as u64 + 1);
        }
        assert!(
            cache.version_summary().len() <= MAX_ROUTE_CACHE_SIZE,
            "route_versions must be bounded at MAX_ROUTE_CACHE_SIZE ({}), got {}",
            MAX_ROUTE_CACHE_SIZE,
            cache.version_summary().len()
        );
    }

    #[test]
    fn unknown_dst_returns_none() {
        // lookup now takes `&self`; no need for mut binding.
        let cache = RouteCache::new(Duration::from_secs(60));
        assert!(cache.lookup(&[9u8; 32]).is_none());
    }

    #[test]
    fn expired_entry_returns_none() {
        let mut cache = RouteCache::new(Duration::ZERO);
        cache.insert([1u8; 32], [2u8; 32], 1_000, 1);
        // TTL=0 → immediately expired
        assert!(cache.lookup(&[1u8; 32]).is_none());
    }

    #[test]
    fn multipath_best_first() {
        let mut cache = RouteCache::new(Duration::from_secs(60));
        cache.insert([1u8; 32], [10u8; 32], 30_000, 3); // worse
        cache.insert([1u8; 32], [20u8; 32], 10_000, 1); // best
        cache.insert([1u8; 32], [30u8; 32], 20_000, 2); // mid
        // Primary lookup returns best score.
        assert_eq!(cache.lookup(&[1u8; 32]), Some([20u8; 32]));
        // lookup_all returns all, best-first.
        let all = cache.lookup_all(&[1u8; 32]);
        assert_eq!(all, vec![[20u8; 32], [30u8; 32], [10u8; 32]]);
    }

    #[test]
    fn invalidate_hop_falls_back_to_secondary() {
        let mut cache = RouteCache::new(Duration::from_secs(60));
        cache.insert([1u8; 32], [10u8; 32], 10_000, 1); // primary
        cache.insert([1u8; 32], [20u8; 32], 20_000, 2); // secondary
        cache.invalidate_hop(&[1u8; 32], &[10u8; 32]);
        // After primary removed, secondary becomes best.
        assert_eq!(cache.lookup(&[1u8; 32]), Some([20u8; 32]));
    }

    #[test]
    fn demote_via_pushes_alt_path_to_winner() {
        // when primary route through `via=10` is demoted, the
        // secondary route through `via=20` (originally lower-scored) wins.
        let mut cache = RouteCache::new(Duration::from_secs(60));
        let dst = [1u8; 32];
        cache.insert(dst, [10u8; 32], 10_000, 1); // primary, score 10k
        cache.insert(dst, [20u8; 32], 20_000, 2); // alt, score 20k
        assert_eq!(cache.lookup(&dst), Some([10u8; 32]));

        cache.demote_via(&[10u8; 32], 4.0); // primary score → 40k
        // Now alt (20k) beats demoted primary (40k).
        assert_eq!(cache.lookup(&dst), Some([20u8; 32]));
    }

    #[test]
    fn demote_via_keeps_route_as_fallback() {
        // Demotion never removes — if the demoted route is the only one
        // it's still returned (fallback).
        let mut cache = RouteCache::new(Duration::from_secs(60));
        let dst = [1u8; 32];
        cache.insert(dst, [10u8; 32], 10_000, 1);
        cache.demote_via(&[10u8; 32], 100.0);
        // Still the only route → still returned.
        assert_eq!(cache.lookup(&dst), Some([10u8; 32]));
    }

    #[test]
    fn demote_via_no_op_for_factor_le_1() {
        // factor ≤ 1 must not change scores (defensive: don't accidentally
        // boost a route on bad input).
        let mut cache = RouteCache::new(Duration::from_secs(60));
        let dst = [1u8; 32];
        cache.insert(dst, [10u8; 32], 10_000, 1);
        cache.demote_via(&[10u8; 32], 0.5);
        cache.demote_via(&[10u8; 32], 1.0);
        let score = cache.entries.get(&dst).unwrap()[0].score;
        assert_eq!(score, 10_000, "score must not change on factor ≤ 1");
    }

    #[test]
    fn demote_via_saturates_at_u32_max() {
        let mut cache = RouteCache::new(Duration::from_secs(60));
        let dst = [1u8; 32];
        cache.insert(dst, [10u8; 32], 1_000_000_000, 1);
        // factor 10 × 1e9 = 1e10, far above u32::MAX (~) — must clamp.
        cache.demote_via(&[10u8; 32], 10.0);
        assert_eq!(cache.entries.get(&dst).unwrap()[0].score, u32::MAX);
    }

    #[test]
    fn demote_via_only_touches_matching_via() {
        // Routes through OTHER `via`s must not be affected.
        let mut cache = RouteCache::new(Duration::from_secs(60));
        cache.insert([1u8; 32], [10u8; 32], 10_000, 1); // via 10
        cache.insert([2u8; 32], [20u8; 32], 15_000, 1); // via 20
        cache.demote_via(&[10u8; 32], 4.0);
        assert_eq!(cache.entries.get(&[1u8; 32]).unwrap()[0].score, 40_000);
        assert_eq!(cache.entries.get(&[2u8; 32]).unwrap()[0].score, 15_000);
    }

    #[test]
    fn invalidate_hop_last_removes_dst() {
        let mut cache = RouteCache::new(Duration::from_secs(60));
        cache.insert([1u8; 32], [10u8; 32], 10_000, 1);
        cache.invalidate_hop(&[1u8; 32], &[10u8; 32]);
        assert!(cache.lookup(&[1u8; 32]).is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn invalidate_removes_all_hops() {
        let mut cache = RouteCache::new(Duration::from_secs(60));
        cache.insert([1u8; 32], [10u8; 32], 10_000, 1);
        cache.insert([1u8; 32], [20u8; 32], 20_000, 2);
        cache.invalidate(&[1u8; 32]);
        assert!(cache.lookup(&[1u8; 32]).is_none());
    }

    #[test]
    fn update_existing_hop_score() {
        let mut cache = RouteCache::new(Duration::from_secs(60));
        cache.insert([1u8; 32], [2u8; 32], 10_000, 1);
        cache.insert([1u8; 32], [3u8; 32], 20_000, 2);
        // Re-insert hop 3 with better score — should become primary.
        cache.insert([1u8; 32], [3u8; 32], 5_000, 1);
        assert_eq!(cache.lookup(&[1u8; 32]), Some([3u8; 32]));
    }

    #[test]
    fn evict_removes_expired() {
        let mut cache = RouteCache::new(Duration::ZERO);
        cache.insert([1u8; 32], [2u8; 32], 1_000, 1);
        cache.insert([3u8; 32], [4u8; 32], 2_000, 1);
        cache.evict_expired();
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn max_routes_per_dst_evicts_worst() {
        let mut cache = RouteCache::new(Duration::from_secs(60));
        // Fill bucket to MAX_ROUTES_PER_DST with distinct hops.
        for i in 0..MAX_ROUTES_PER_DST {
            let mut hop = [0u8; 32];
            hop[0] = i as u8;
            cache.insert([1u8; 32], hop, (i as u32) * 10_000, i as u8 + 1);
        }
        // One more — worst (highest score) gets evicted.
        let mut overflow = [0xFFu8; 32];
        overflow[0] = 0xEE;
        cache.insert([1u8; 32], overflow, 999_000, 99);
        let all = cache.lookup_all(&[1u8; 32]);
        assert_eq!(
            all.len(),
            MAX_ROUTES_PER_DST,
            "bucket must not grow beyond cap"
        );
        assert!(
            !all.contains(&overflow),
            "worst hop (score=999) must have been evicted"
        );
    }

    #[test]
    fn per_via_limit_blocks_excess_dsts() {
        // A single next_hop should not be insertable for more than
        // MAX_ROUTES_PER_VIA distinct destinations.
        let mut cache = RouteCache::new(Duration::from_secs(60));
        let hop = [0xAAu8; 32];
        for i in 0..MAX_ROUTES_PER_VIA {
            let mut dst = [0u8; 32];
            dst[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            cache.insert(dst, hop, 1_000, 1);
        }
        // Via count should be exactly MAX_ROUTES_PER_VIA now.
        assert_eq!(
            *cache.via_counts.get(&hop).unwrap_or(&0),
            MAX_ROUTES_PER_VIA
        );
        // One more destination via the same hop must be silently dropped.
        let overflow_dst = [0xFFu8; 32];
        cache.insert(overflow_dst, hop, 1_000, 1);
        assert!(
            cache.lookup(&overflow_dst).is_none(),
            "insertion over per-via limit must be rejected"
        );
    }

    #[test]
    fn per_via_count_decremented_on_invalidate() {
        let mut cache = RouteCache::new(Duration::from_secs(60));
        let hop = [0xBBu8; 32];
        let dst = [0x01u8; 32];
        cache.insert(dst, hop, 1_000, 1);
        assert_eq!(*cache.via_counts.get(&hop).unwrap_or(&0), 1);
        cache.invalidate(&dst);
        assert_eq!(cache.via_counts.get(&hop).copied().unwrap_or(0), 0);
    }

    #[test]
    fn per_via_count_decremented_on_invalidate_hop() {
        let mut cache = RouteCache::new(Duration::from_secs(60));
        let hop = [0xCCu8; 32];
        let dst = [0x02u8; 32];
        cache.insert(dst, hop, 1_000, 1);
        assert_eq!(*cache.via_counts.get(&hop).unwrap_or(&0), 1);
        cache.invalidate_hop(&dst, &hop);
        assert_eq!(cache.via_counts.get(&hop).copied().unwrap_or(0), 0);
    }

    #[test]
    fn via_count_freed_after_lru_eviction() {
        // When the LRU bucket is evicted to make room for a new destination
        // its via_counts must be decremented so the slot becomes available again.
        //
        // Setup: fill cache to exactly MAX_ROUTE_CACHE_SIZE, using a unique hop
        // per destination except for the very first entry which uses hop_a.
        // Then insert one more entry (triggering LRU eviction of the first entry).
        // After eviction, hop_a's via_count must drop to 0.
        let mut cache = RouteCache::new(Duration::from_secs(60));
        let hop_a = [0xAAu8; 32];

        // Insert 1 entry via hop_a (dst=0).
        let dst_a = [0u8; 32];
        cache.insert(dst_a, hop_a, 1_000, 1);
        assert_eq!(*cache.via_counts.get(&hop_a).unwrap_or(&0), 1);

        // Fill the remaining MAX_ROUTE_CACHE_SIZE - 1 slots with distinct hops.
        for i in 1..MAX_ROUTE_CACHE_SIZE {
            let mut dst = [0u8; 32];
            dst[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            let mut hop = [0u8; 32];
            hop[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            hop[8] = 0xFF; // distinct from dst
            cache.insert(dst, hop, 1_000, 1);
        }
        assert_eq!(cache.len(), MAX_ROUTE_CACHE_SIZE);

        // Insert one more entry — LRU eviction removes dst_a (oldest, via hop_a).
        let overflow_dst = [0xFFu8; 32];
        let overflow_hop = [0xFEu8; 32];
        cache.insert(overflow_dst, overflow_hop, 1_000, 1);

        // hop_a's via_count must be 0 after LRU eviction of dst_a.
        assert_eq!(
            cache.via_counts.get(&hop_a).copied().unwrap_or(0),
            0,
            "LRU eviction must decrement via_count for evicted hop"
        );
    }

    #[test]
    fn lru_dst_eviction_at_max_cache_size() {
        let mut cache = RouteCache::new(Duration::from_secs(60));
        // Use a unique next_hop per destination so we don't hit MAX_ROUTES_PER_VIA.
        for i in 0..MAX_ROUTE_CACHE_SIZE {
            let mut dst = [0u8; 32];
            dst[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            let mut hop = [0xABu8; 32];
            hop[0..8].copy_from_slice(&(i as u64).to_be_bytes()); // unique hop
            cache.insert(dst, hop, 1_000, 1);
        }
        assert_eq!(cache.len(), MAX_ROUTE_CACHE_SIZE);
        let overflow = [0xFFu8; 32];
        cache.insert(overflow, [0xCDu8; 32], 2_000, 2);
        assert_eq!(
            cache.len(),
            MAX_ROUTE_CACHE_SIZE,
            "must not grow beyond cap"
        );
        assert!(
            cache.lookup(&overflow).is_some(),
            "newly inserted dst must be reachable"
        );
    }
}

// ── property-based tests (103.3) ─────────────────────────────────────────────

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use std::time::Duration;

    proptest! {
        /// Bucket size never exceeds MAX_ROUTES_PER_DST regardless of how many
        /// distinct next-hops are inserted for the same destination.
        #[test]
        fn bucket_never_exceeds_max(
            hops in proptest::collection::vec(proptest::array::uniform32(0u8..), 1..=MAX_ROUTES_PER_DST * 3),
            scores in proptest::collection::vec(0u32..=u32::MAX, 1..=MAX_ROUTES_PER_DST * 3),
        ) {
            let dst = [0x42u8; 32];
            let mut cache = RouteCache::new(Duration::from_secs(60));
            let n = hops.len().min(scores.len());
            for i in 0..n {
                cache.insert(dst, hops[i], scores[i], 1);
            }
            let bucket = cache.all_routes().iter().filter(|(d, _, _)| *d == dst).count();
            prop_assert!(bucket <= MAX_ROUTES_PER_DST, "bucket size exceeded MAX_ROUTES_PER_DST");
            // Direct check: the number of returned routes for this dst must be <= cap
            let routes = cache.lookup_all(&dst);
            prop_assert!(
                routes.len() <= MAX_ROUTES_PER_DST,
                "lookup_all returned {} routes, expected <= {}",
                routes.len(), MAX_ROUTES_PER_DST
            );
        }

        /// `lookup` always returns the best-scoring (lowest score) known next-hop.
        #[test]
        fn lookup_returns_best_hop(
            hops in proptest::collection::vec(proptest::array::uniform32(0u8..), 2..=MAX_ROUTES_PER_DST),
            scores in proptest::collection::vec(1u32..=1_000_000, 2..=MAX_ROUTES_PER_DST),
        ) {
            let dst = [0x77u8; 32];
            let mut cache = RouteCache::new(Duration::from_secs(60));
            let n = hops.len().min(scores.len());
            // Insert all hops — ensure they are all distinct (zip pairs by index).
            let mut inserted: Vec<([u8; 32], u32)> = Vec::new();
            for i in 0..n {
                let mut hop = hops[i];
                hop[0] = i as u8; // ensure uniqueness
                cache.insert(dst, hop, scores[i], 1);
                inserted.push((hop, scores[i]));
            }
            if let Some(best_hop) = cache.lookup(&dst) {
                // The returned hop must be the one with the lowest score among inserted.
                let best_score = inserted.iter()
                    .find(|(h, _)| *h == best_hop)
                    .map(|(_, s)| *s)
                    .unwrap_or(u32::MAX);
                let min_score = inserted.iter().map(|(_, s)| *s).min().unwrap_or(0);
                prop_assert!(
                    best_score <= min_score * 2 + 1,
                    "lookup returned a hop with score {best_score}, min inserted score was {min_score}"
                );
            }
        }

        /// Total cache size never exceeds MAX_ROUTE_CACHE_SIZE regardless of how
        /// many distinct destinations are inserted.
        #[test]
        fn total_size_never_exceeds_cap(
            dsts in proptest::collection::vec(proptest::array::uniform32(0u8..), 1..=MAX_ROUTE_CACHE_SIZE + 10),
        ) {
            let mut cache = RouteCache::new(Duration::from_secs(60));
            for dst in &dsts {
                cache.insert(*dst, [0xABu8; 32], 100, 1);
            }
            prop_assert!(
                cache.len() <= MAX_ROUTE_CACHE_SIZE,
                "cache.len()={} exceeded MAX_ROUTE_CACHE_SIZE={}",
                cache.len(), MAX_ROUTE_CACHE_SIZE
            );
        }
    }

    // ── label filtering ─────────────────────────────────────────
    mod label_filter {
        use super::super::*;
        use std::time::Duration;

        #[test]
        fn lookup_with_labels_returns_route_when_all_labels_match() {
            let mut cache = RouteCache::new(Duration::from_secs(60));
            let dst = [0x42u8; 32];
            let hop = [0x10u8; 32];
            cache.insert_labelled(dst, hop, 100, 1, vec![*b"exit", *b"low\0"]);
            assert_eq!(cache.lookup_with_labels(&dst, &[*b"exit"]), Some(hop));
            assert_eq!(
                cache.lookup_with_labels(&dst, &[*b"exit", *b"low\0"]),
                Some(hop),
            );
        }

        #[test]
        fn lookup_with_labels_returns_none_when_label_missing() {
            let mut cache = RouteCache::new(Duration::from_secs(60));
            let dst = [0x42u8; 32];
            cache.insert_labelled(dst, [0x10u8; 32], 100, 1, vec![*b"exit"]);
            // Required label `qiwi` is not on the entry.
            assert_eq!(cache.lookup_with_labels(&dst, &[*b"qiwi"]), None);
        }

        #[test]
        fn lookup_with_labels_empty_required_matches_anything() {
            let mut cache = RouteCache::new(Duration::from_secs(60));
            let dst = [0x42u8; 32];
            // Entry has no labels; empty required slice still matches.
            cache.insert(dst, [0x10u8; 32], 100, 1);
            assert_eq!(cache.lookup_with_labels(&dst, &[]), Some([0x10u8; 32]));
        }

        #[test]
        fn lookup_with_labels_skips_unlabelled_entries() {
            let mut cache = RouteCache::new(Duration::from_secs(60));
            let dst = [0x42u8; 32];
            // Two routes to same dst: best-scoring one has no labels, second has them.
            cache.insert(dst, [0x10u8; 32], 100, 1);
            cache.insert_labelled(dst, [0x20u8; 32], 200, 2, vec![*b"exit"]);
            // Plain lookup gets best (unlabelled).
            assert_eq!(cache.lookup(&dst), Some([0x10u8; 32]));
            // Labelled lookup skips it and returns the second-best.
            assert_eq!(
                cache.lookup_with_labels(&dst, &[*b"exit"]),
                Some([0x20u8; 32])
            );
        }

        #[test]
        fn insert_falls_back_to_empty_labels() {
            // Plain insert still works — labels default to empty.
            let mut cache = RouteCache::new(Duration::from_secs(60));
            let dst = [0x42u8; 32];
            cache.insert(dst, [0x10u8; 32], 100, 1);
            // Any label requirement filters this entry out.
            assert!(cache.lookup_with_labels(&dst, &[*b"any "]).is_none());
        }
    }
}
