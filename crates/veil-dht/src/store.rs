//! Tiered DHT value store.
//!
//! # Architecture
//!
//! **Hot tier**: in-memory `HashMap` for recently accessed entries (bounded).
//! **Cold tier**: pluggable via `ColdBackend` trait (default: in-memory HashMap;
//! production: RocksDB).
//!
//! # Promotion / demotion
//!
//! On `get` — if found in cold, promote to hot (LRU caching).
//! On `put` — insert into hot. When hot is full, demote oldest to cold.
//! On cold full — evict oldest entry entirely.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

// ── ColdBackend trait ───────────────────────────────────────────

/// A value-based freshness predicate: `true` ⇒ the value is expired and should
/// be dropped. Borrowed for the duration of a single `retain_fresh` call.
/// Aliased to keep `retain_fresh_inner`'s signature within clippy's
/// type-complexity budget (audit cycle-8).
type ValuePredicate<'a> = dyn Fn(&[u8]) -> bool + 'a;

/// What happened to a value handed to the cold tier.
///
/// The trait used to return `Option<evicted>`, which cannot say "I did not
/// store it". `RocksDbCold` handles a disk-full write by logging and returning
/// `None` — indistinguishable from "stored, nothing evicted" — so the caller
/// believed the value was safe. Worse, demotion removed the entry from the hot
/// tier BEFORE the cold write, so a failure lost the value from both tiers and
/// left `total_bytes` counting something that no longer existed (audit V-08).
#[derive(Debug)]
pub enum ColdPut {
    /// Stored. Carries whatever the backend evicted to make room, if any, so
    /// the caller can keep its byte and per-origin counters in step.
    Stored(Option<([u8; 32], Vec<u8>)>),
    /// NOT stored. The value is handed back rather than dropped, so a caller
    /// that had already taken it out of the hot tier can put it back.
    Failed(Vec<u8>),
}

/// One persisted row's publisher: `(key, origin, value_len)`.
///
/// A named type because the tuple is three arrays deep and clippy is right
/// that nobody reads that at a glance.
pub type PersistedOrigin = ([u8; 32], [u8; 32], u64);

/// Trait for the cold storage tier.
///
/// Default: `InMemoryCold` (HashMap).
/// Production: `RocksDbCold` (wraps `rocksdb::DB`).
pub trait ColdBackend: Send + Sync + std::fmt::Debug {
    fn get(&self, key: &[u8; 32]) -> Option<Vec<u8>>;
    /// Insert `(key, value)` into cold storage.  Returns the entry that
    /// was evicted by an internal capacity check, if any, so the
    /// caller (typically [`TieredStore`]) can keep byte/metric counters
    /// in sync.  Returns `None` when no eviction occurred (room was
    /// available, OR the backend evicts asynchronously /
    /// compaction-driven — RocksDB).  Audit batch 2026-05-23: signature
    /// expanded to return the evicted entry for byte-cap bookkeeping.
    fn put(&mut self, key: [u8; 32], value: Vec<u8>) -> ColdPut;
    fn remove(&mut self, key: &[u8; 32]);
    fn contains(&self, key: &[u8; 32]) -> bool;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Iterate all entries (for snapshot/migration).
    fn iter_entries(&self) -> Vec<([u8; 32], Vec<u8>)>;
    /// Like [`Self::iter_entries`] but also reports when each entry was
    /// inserted, so a snapshot can preserve remaining lifetime instead of
    /// handing every restored entry a fresh full TTL.
    ///
    /// The default answers `now` for every entry, i.e. "age unknown". Only
    /// backends that are VOLATILE need to override it — a durable backend is
    /// never part of the JSON value snapshot (it survives restart by itself,
    /// see [`TieredStore::cold_is_durable`]), so the default is never the
    /// answer anyone acts on.
    fn iter_entries_with_ts(&self, now: Instant) -> Vec<([u8; 32], Vec<u8>, Instant)> {
        self.iter_entries()
            .into_iter()
            .map(|(k, v)| (k, v, now))
            .collect()
    }
    /// Iterate all KEYS without materializing values. Backends that can
    /// enumerate keys without copying values out of RAM/disk pages MUST
    /// override this — the default falls back to `iter_entries`, which
    /// defeats a disk tier. Audit cycle-7 M4: the republish driver needs the
    /// full key set each tick but values only for the few keys actually due,
    /// so it must never pull the whole cold value set into process memory.
    fn iter_keys(&self) -> Vec<[u8; 32]> {
        self.iter_entries().into_iter().map(|(k, _)| k).collect()
    }
    /// Remove entries that do NOT match the predicate (TTL cleanup). Returns
    /// the removed `(key, byte_len)` pairs so [`TieredStore`] can adjust its
    /// byte/per-origin counters from the delta WITHOUT re-walking the tier
    /// (audit U2: the old before/after `iter_entries` diff materialized the
    /// entire cold set into RAM twice per cleanup tick — for RocksDB that
    /// loaded the full on-disk value set into process memory, defeating the
    /// disk tier).
    fn retain(&mut self, f: &dyn Fn(&[u8; 32], &[u8]) -> bool) -> Vec<([u8; 32], u64)>;
    /// drop entries whose insertion `Instant` is older than
    /// `cutoff`. Complements `retain` which only sees `(key, value)` — the
    /// cutoff variant is the only way to evict cold-tier entries by age for
    /// values that do not embed their own expires_at. Returns removed
    /// `(key, byte_len)` pairs (see [`Self::retain`]).
    ///
    /// Default implementation is a no-op for backends that do not track
    /// per-entry insert timestamps (e.g., RocksDB with its own compaction).
    fn retain_newer_than(&mut self, _cutoff: Instant) -> Vec<([u8; 32], u64)> {
        Vec::new()
    }
    /// Remove and return the OLDEST entry, if any.  Used by
    /// [`TieredStore`] for byte-cap eviction when the global
    /// `max_bytes` budget is exceeded.  Default implementation
    /// returns `None` (backends without age-ordering opt out — their
    /// own internal compaction handles eviction).
    fn evict_oldest(&mut self) -> Option<([u8; 32], Vec<u8>)> {
        None
    }

    /// Total bytes currently held by an already-persisted cold tier, if the
    /// backend can report it cheaply at construction time.
    ///
    /// Audit cycle-8: a disk-backed backend (RocksDB) survives process restart
    /// with data on disk, but [`TieredStore::total_bytes`] starts at 0, so the
    /// global byte-cap and per-origin caps don't account for what's already
    /// there — repeated restarts let the caps drift. A backend that maintains
    /// a per-key byte-length index returns `Some(sum)` here so the store can
    /// seed `total_bytes` on open. In-memory backends start empty and return
    /// `None` (nothing to seed).
    fn cold_total_bytes(&self) -> Option<u64> {
        None
    }

    /// Record WHO published the value now stored at `key`.
    ///
    /// Per-origin bytes lived only in memory, so a restart handed every
    /// publisher a fresh allowance while its rows were still on disk — the
    /// global cap bounded the damage, but the per-origin one stopped meaning
    /// anything across restarts (report14 V14-L3).
    ///
    /// Optional: an in-memory backend does not survive a restart, so it has
    /// nothing to remember. The default does nothing.
    fn set_origin(&mut self, _key: &[u8; 32], _origin: &[u8; 32]) {}

    /// Store `value` at `key` together with everything known about it, so a
    /// crash cannot leave one without the others.
    ///
    /// The value and its two side rows describe the SAME record: the origin is
    /// what the per-origin quota charges, the first-seen stamp is what the TTL
    /// ages from. Written as three separate calls, a crash between them left a
    /// value nobody is charged for and that ages from the moment it is read
    /// back — and an overwrite left the previous publisher's row behind
    /// (report16 V16-M4).
    ///
    /// The default is the three calls, which is what every backend that cannot
    /// batch has always done and what an in-memory one loses nothing by. A
    /// backend that CAN write them atomically overrides this.
    fn put_with_side(
        &mut self,
        key: [u8; 32],
        value: Vec<u8>,
        origin: Option<[u8; 32]>,
        first_seen_unix: Option<u64>,
    ) -> ColdPut {
        let put = self.put(key, value);
        if matches!(put, ColdPut::Stored(_)) {
            match origin {
                Some(origin) => self.set_origin(&key, &origin),
                // An overwrite by a publisher this node cannot name must not
                // leave the PREVIOUS one charged for it.
                None => self.forget_origin(&key),
            }
            match first_seen_unix {
                Some(secs) => self.set_first_seen(&key, secs),
                // SYMMETRIC with the origin above, and for the same reason: an
                // overwrite with no stamp must not leave the value aged from
                // whenever the PREVIOUS one at this key was first seen. The
                // asymmetry was here only in the default — the RocksDB
                // override already cleared both — so it was a trap for the
                // next durable backend rather than a live defect (report17
                // V17-L1).
                None => self.forget_first_seen(&key),
            }
        }
        put
    }

    /// Forget `key`'s origin, when the value it described is gone.
    fn forget_origin(&mut self, _key: &[u8; 32]) {}

    /// Every persisted row whose publisher this backend remembers, so the
    /// per-origin counters can be rebuilt on open.
    ///
    /// `None` means "this backend does not remember"; rows it has no origin
    /// for are simply unattributed — legacy rows written before this existed
    /// are exactly that, and they stay counted by the global total.
    fn origins(&self) -> Option<Vec<PersistedOrigin>> {
        None
    }

    /// Record WHEN this node first saw the record now stored at `key`, as a
    /// wall-clock unix second.
    ///
    /// `first_seen` is an `Instant`, which is process-local by construction —
    /// so a restart forgot every cold entry's age and the sweep aged them from
    /// zero, handing a record another full lifetime for the price of a restart
    /// (report14 V14-L2). The backend's own stamp cannot stand in for it: that
    /// one says when the entry was DEMOTED.
    ///
    /// Wall-clock and not the monotonic clock, because it has to survive the
    /// process. The reader clamps a stamp from the future, which is what a
    /// clock moved backwards looks like.
    fn set_first_seen(&mut self, _key: &[u8; 32], _unix_secs: u64) {}

    /// Forget `key`'s first-seen stamp.
    fn forget_first_seen(&mut self, _key: &[u8; 32]) {}

    /// `(key, first_seen_unix)` for every persisted row this backend stamped.
    ///
    /// `None` means "this backend does not remember"; a row it has no stamp
    /// for is aged from the moment it was read back, which is the behaviour
    /// every row had before this existed.
    fn first_seen_all(&self) -> Option<Vec<([u8; 32], u64)>> {
        None
    }

    /// Whether this backend persists across a process restart (disk-backed).
    /// In-memory backends return `false`; a RocksDB backend returns `true`.
    /// Distinct from [`Self::cold_total_bytes`], which concerns restart
    /// byte-seeding and is `None`/0 for an *empty* durable backend — so it must
    /// NOT be used as a durability signal.
    fn is_durable(&self) -> bool {
        false
    }
}

/// In-memory cold backend (default).
#[derive(Debug, Default)]
pub struct InMemoryCold {
    entries: HashMap<[u8; 32], (Vec<u8>, Instant)>,
    order: BTreeMap<(Instant, [u8; 32]), ()>,
    capacity: usize,
}

impl InMemoryCold {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: BTreeMap::new(),
            capacity,
        }
    }
}

impl ColdBackend for InMemoryCold {
    fn get(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.entries.get(key).map(|(v, _)| v.clone())
    }

    fn put(&mut self, key: [u8; 32], value: Vec<u8>) -> ColdPut {
        // An in-memory insert has nothing to fail at, so this is always
        // `Stored` — the outcome type exists for the backends that do.
        let ts = Instant::now();
        // Evict if at capacity (return evicted entry for byte-cap bookkeeping).
        let mut evicted: Option<([u8; 32], Vec<u8>)> = None;
        if self.entries.len() >= self.capacity
            && !self.entries.contains_key(&key)
            && let Some(&(old_ts, old_key)) = self.order.keys().next()
        {
            if let Some((old_val, _)) = self.entries.remove(&old_key) {
                evicted = Some((old_key, old_val));
            }
            self.order.remove(&(old_ts, old_key));
        }
        if let Some((_, old_ts)) = self.entries.remove(&key) {
            self.order.remove(&(old_ts, key));
        }
        self.entries.insert(key, (value, ts));
        self.order.insert((ts, key), ());
        ColdPut::Stored(evicted)
    }

    fn remove(&mut self, key: &[u8; 32]) {
        if let Some((_, ts)) = self.entries.remove(key) {
            self.order.remove(&(ts, *key));
        }
    }

    fn contains(&self, key: &[u8; 32]) -> bool {
        self.entries.contains_key(key)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn iter_entries(&self) -> Vec<([u8; 32], Vec<u8>)> {
        self.entries
            .iter()
            .map(|(k, (v, _))| (*k, v.clone()))
            .collect()
    }

    fn iter_entries_with_ts(&self, _now: Instant) -> Vec<([u8; 32], Vec<u8>, Instant)> {
        self.entries
            .iter()
            .map(|(k, (v, ts))| (*k, v.clone(), *ts))
            .collect()
    }

    fn iter_keys(&self) -> Vec<[u8; 32]> {
        self.entries.keys().copied().collect()
    }

    fn retain(&mut self, f: &dyn Fn(&[u8; 32], &[u8]) -> bool) -> Vec<([u8; 32], u64)> {
        let mut removed: Vec<([u8; 32], u64)> = Vec::new();
        self.entries.retain(|k, (v, ts)| {
            let keep = f(k, v);
            if !keep {
                self.order.remove(&(*ts, *k));
                removed.push((*k, v.len() as u64));
            }
            keep
        });
        removed
    }

    fn retain_newer_than(&mut self, cutoff: Instant) -> Vec<([u8; 32], u64)> {
        // `order` is sorted by (ts, key); walk from the front and pop all
        // entries whose ts < cutoff in O(k log n) where k is the number of
        // expired entries.
        let mut expired_keys: Vec<[u8; 32]> = Vec::new();
        for &(ts, key) in self.order.keys() {
            if ts < cutoff {
                expired_keys.push(key);
            } else {
                break;
            }
        }
        let mut removed: Vec<([u8; 32], u64)> = Vec::new();
        for key in expired_keys {
            if let Some((v, ts)) = self.entries.remove(&key) {
                self.order.remove(&(ts, key));
                removed.push((key, v.len() as u64));
            }
        }
        removed
    }

    fn evict_oldest(&mut self) -> Option<([u8; 32], Vec<u8>)> {
        let &(ts, key) = self.order.keys().next()?;
        self.order.remove(&(ts, key));
        let (val, _) = self.entries.remove(&key)?;
        Some((key, val))
    }
}

// ── RocksDB cold backend ────────────────────────────────────────

/// RocksDB-backed cold storage tier.
///
/// Enabled with `--features rocksdb-cold`. Stores DHT values on disk with
/// O(1) point lookups. For production deployments with > 1M DHT entries.
#[cfg(feature = "rocksdb-cold")]
pub mod rocks {
    use super::{ColdBackend, ColdPut};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    /// Side column-family: `ts_be(8) ‖ key(32)` → `[]`. Ordered by insert
    /// wall-clock (big-endian, so byte-order == numeric order), giving O(1)
    /// oldest-first iteration for `evict_oldest` / `retain_newer_than`
    /// (audit cycle-6 T5-B). RocksDB raw values carry no timestamp, so this
    /// index is what makes TTL/byte/entry eviction possible on the disk tier.
    const CF_TS_INDEX: &str = "ts_index_v1";
    /// Side column-family: `key(32)` → `ts_be(8) ‖ len_be(8)`. Reverse map so an
    /// overwrite/remove can delete the stale `ts_index` entry, AND (audit
    /// cycle-8) the per-key value byte-length so a restart can re-sum the disk
    /// tier's total bytes to seed `TieredStore::total_bytes`. Legacy `v1`
    /// entries (8-byte, ts-only) are read back compatibly: missing len ⇒ 0.
    const CF_KEY_TS: &str = "key_ts_v1";
    /// `key -> publisher node id`, so the per-origin quota survives a restart
    /// (report14 V14-L3). A separate family and not a value prefix: the value
    /// format is what every existing node already has on disk, and
    /// `create_missing_column_families` means an old database opens with this
    /// one simply empty — its rows are then unattributed, which is the honest
    /// answer for values written before anybody wrote the origin down.
    const CF_KEY_ORIGIN: &str = "key_origin_v1";
    /// `key -> first-seen unix seconds`, so a record cannot buy another full
    /// lifetime by surviving a restart (report14 V14-L2). Separate from
    /// `CF_KEY_TS`, whose stamp is when the entry was DEMOTED and therefore
    /// says nothing about how old the record is.
    const CF_KEY_FIRST_SEEN: &str = "key_first_seen_v1";

    /// The entry `evict_oldest` settled on: its ts-index row (kept so the row
    /// can be deleted by its own key), the 32-byte store key, and the value.
    /// Aliased to keep the local inside clippy's type-complexity budget.
    type Victim = (Box<[u8]>, [u8; 32], Vec<u8>);

    #[derive(Debug)]
    pub struct RocksDbCold {
        db: rocksdb::DB,
        /// Entry cap (0 = unlimited). When a new key would exceed it, the
        /// oldest entry is evicted on `put` (amortised, like `InMemoryCold`).
        capacity: usize,
        /// Exact in-process entry count (the indexed entries), seeded by a
        /// one-time scan of `CF_KEY_TS` on open. RocksDB's `estimate-num-keys`
        /// is unreliable (reads 0 before memtable flush), so a maintained count
        /// is what lets the entry cap actually fire.
        count: usize,
        /// Sum of value byte-lengths on disk at `open` (audit cycle-8), used
        /// once to seed `TieredStore::total_bytes` so the byte/origin caps
        /// account for an already-populated disk tier across restarts. Summed
        /// from the ACTUAL values by [`Self::reconcile`], not from the lengths
        /// recorded in the reverse map — a recorded length that has drifted
        /// away from its value is one of the states reconciliation repairs.
        seed_bytes: u64,
        /// Test-only: how many `WriteBatch`es this store has pushed to disk.
        ///
        /// The instrument for atomicity. "The eviction and the entry it makes
        /// room for travel together" is a statement about the NUMBER of
        /// durable writes, and nothing else observes it: with two batches the
        /// end state after a SUCCESSFUL put is identical, and the divergence
        /// only appears at a crash or a failure between them — neither of
        /// which a test can stand in the middle of (report20 V18-M1).
        #[cfg(test)]
        writes: std::sync::atomic::AtomicUsize,
    }

    impl RocksDbCold {
        /// How many rows the two side column families hold, counting the ones
        /// whose value is gone.
        ///
        /// Every ordinary reader hides those on purpose — an origin row for a
        /// key with no value describes nothing and must not charge anybody —
        /// which is precisely why rows outliving their value were invisible to
        /// all of them while the files grew (report15 V15-M4). Nothing but a
        /// direct count can see that, so a test needs this.
        #[doc(hidden)]
        pub fn side_row_count(&self) -> (usize, usize) {
            let count = |cf| {
                self.db
                    .iterator_cf(cf, rocksdb::IteratorMode::Start)
                    .filter(|item| item.is_ok())
                    .count()
            };
            (count(self.cf_origin()), count(self.cf_first_seen()))
        }

        pub fn open(
            path: impl AsRef<std::path::Path>,
            capacity: usize,
        ) -> Result<Self, rocksdb::Error> {
            let path = path.as_ref();
            // ASK BEFORE OPENING whether the side CFs already exist. This is
            // the one signal that separates a grandfathered legacy value from
            // a ghost, and opening destroys it — `create_missing_column_families`
            // makes the CFs exist either way. See [`Self::reconcile`].
            let side_cfs_existed = rocksdb::DB::list_cf(&rocksdb::Options::default(), path)
                .map(|cfs| cfs.iter().any(|name| name == CF_KEY_TS))
                .unwrap_or(false);
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            // Legacy DBs (pre-T5-B) have only the default CF; create the new
            // side CFs on open. Their values stay in the default CF and remain
            // readable; `reconcile` adopts them into the index on this same
            // open, which is what ends the old grandfathering (they used to be
            // unreachable by TTL and by every cap until overwritten).
            opts.create_missing_column_families(true);
            opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
            // Memory-footprint caps (audit: RSS reduction on the small nodes).
            // RocksDB defaults target throughput on big hosts: a 64 MiB memtable
            // ×2 per CF, a private block cache per CF, and unbounded open files
            // (each SST pins its index/filter blocks in RAM). The veil DHT
            // store is a few MB on disk, so size for footprint instead:
            //   * one SHARED 8 MiB LRU block cache across all 3 CFs (not 1 each)
            //   * 8 MiB memtable ×2 (down from 64) — the memtable arena is the
            //     single largest heap consumer, and the cap bounds it under load
            //   * bound open files so SST index/filter blocks can't accumulate
            // All are open-time runtime options — no on-disk format change, so
            // existing DBs reopen unchanged.
            let block_cache = rocksdb::Cache::new_lru_cache(8 * 1024 * 1024);
            let mut block_opts = rocksdb::BlockBasedOptions::default();
            block_opts.set_block_cache(&block_cache);
            opts.set_block_based_table_factory(&block_opts);
            opts.set_write_buffer_size(8 * 1024 * 1024);
            opts.set_max_write_buffer_number(2);
            opts.set_max_open_files(256);
            // Side CFs (CF_TS_INDEX, CF_KEY_TS) hold keys + tiny fixed values;
            // share the same cache and use even smaller memtables.
            let mut cf_opts = rocksdb::Options::default();
            cf_opts.set_block_based_table_factory(&block_opts);
            cf_opts.set_write_buffer_size(4 * 1024 * 1024);
            cf_opts.set_max_write_buffer_number(2);
            let cfs = vec![
                rocksdb::ColumnFamilyDescriptor::new(CF_TS_INDEX, cf_opts.clone()),
                rocksdb::ColumnFamilyDescriptor::new(CF_KEY_TS, cf_opts.clone()),
                rocksdb::ColumnFamilyDescriptor::new(CF_KEY_ORIGIN, cf_opts.clone()),
                rocksdb::ColumnFamilyDescriptor::new(CF_KEY_FIRST_SEEN, cf_opts),
            ];
            let db = rocksdb::DB::open_cf_descriptors(&opts, path, cfs)?;
            let (count, seed_bytes) = Self::reconcile(&db, side_cfs_existed);
            Ok(Self {
                db,
                capacity,
                count,
                seed_bytes,
                #[cfg(test)]
                writes: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        /// Test-only: reopen an existing store READ-ONLY. Every write against
        /// the returned handle fails at the RocksDB level, which is the only
        /// honest way to observe what a failed write leaves behind.
        #[cfg(test)]
        pub fn open_read_only(
            path: impl AsRef<std::path::Path>,
            capacity: usize,
        ) -> Result<Self, rocksdb::Error> {
            let opts = rocksdb::Options::default();
            let cf_opts = rocksdb::Options::default();
            let cfs = vec![
                rocksdb::ColumnFamilyDescriptor::new(CF_TS_INDEX, cf_opts.clone()),
                rocksdb::ColumnFamilyDescriptor::new(CF_KEY_TS, cf_opts.clone()),
                rocksdb::ColumnFamilyDescriptor::new(CF_KEY_ORIGIN, cf_opts.clone()),
                rocksdb::ColumnFamilyDescriptor::new(CF_KEY_FIRST_SEEN, cf_opts),
            ];
            let db = rocksdb::DB::open_cf_descriptors_read_only(&opts, path, cfs, false)?;
            let (count, seed_bytes) = Self::reconcile(&db, true);
            Ok(Self {
                db,
                capacity,
                count,
                seed_bytes,
                #[cfg(test)]
                writes: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        /// One-time open-time reconciliation across the three column families,
        /// returning the exact `(entry count, total value bytes)` of the tier.
        ///
        /// A stored entry is three rows: the value in the default CF, a reverse
        /// map `key → ts‖len` in `CF_KEY_TS`, and a ts-index row in
        /// `CF_TS_INDEX`. The scan this replaces walked `CF_KEY_TS` ONLY and
        /// never enumerated the default CF, so it could not see a single one of
        /// the states a torn write leaves — it summed the lengths the index
        /// claimed and trusted them. It already paid for a full pass; checking
        /// the other two families against it is a bounded addition, and it is
        /// what turns the pass from bookkeeping into repair:
        ///
        /// * reverse map row whose value is gone — ORPHAN; both index rows go.
        /// * recorded length that disagrees with the value — rewritten, so the
        ///   next open's byte seed matches what is really on disk.
        /// * value with no reverse map row — ADOPTED (see below).
        /// * ts-index row with no matching reverse map row (or a drifted ts) —
        ///   dangling; it goes. Such a row is what used to freeze eviction for
        ///   the entire cold tier.
        ///
        /// # Telling a ghost from a grandfathered legacy value
        ///
        /// A value with no index rows has two possible histories, and the bytes
        /// on disk do not distinguish them:
        ///
        /// * it was written by a pre-T5-B binary, which had only the default CF
        ///   — the class `open`'s header calls grandfathered; or
        /// * a post-T5-B write was torn between the value and its index rows —
        ///   a GHOST: `get` serves it, `iter_entries` publishes it, no eviction
        ///   path can reach it and no byte counter knows about it.
        ///
        /// What separates them is not the row, it is WHEN we look. A pre-T5-B
        /// database has no `CF_KEY_TS` at all until this very open creates it,
        /// so `side_cfs_existed == false` proves every unindexed value is
        /// legacy, and `true` proves every unindexed value is a ghost. That
        /// signal exists exactly once per database, which is why `open`
        /// captures it BEFORE opening.
        ///
        /// Both are then treated identically, and neither is deleted: the value
        /// is live data that `get` is already serving, and deleting it would
        /// lose a DHT record to repair a bookkeeping fault. They are ADOPTED —
        /// indexed at the current wall clock — which counts their bytes and
        /// brings them under the ordinary TTL/cap lifecycle. For a ghost that
        /// is the repair.
        ///
        /// ⚠️ For a legacy value adoption ENDS the grandfathering, deliberately.
        /// An unbounded class of values that no cap and no TTL can ever reach
        /// is itself the leak this audit is closing; the values are kept, they
        /// merely stop being exempt. It is also what makes the signal above
        /// one-shot: after this pass no unindexed value exists, so any that
        /// appears later is unambiguously a ghost.
        fn reconcile(db: &rocksdb::DB, side_cfs_existed: bool) -> (usize, u64) {
            let cf_kt = db.cf_handle(CF_KEY_TS).expect("CF_KEY_TS just created");
            let cf_ix = db.cf_handle(CF_TS_INDEX).expect("CF_TS_INDEX just created");

            let mut batch = rocksdb::WriteBatch::default();
            let mut count = 0usize;
            let mut summed = 0u64;
            let (mut orphans, mut adopted, mut dangling, mut relengths) = (0usize, 0, 0, 0);
            // EVERY repair below is a DELETE decided by a read. A read that
            // failed is not an answer, and folding one into "the value is not
            // there" takes the index away from a value that is perfectly alive
            // — after which nothing counts it, nothing evicts it, and only the
            // next successful open notices (report21 V21-L3). One unreadable
            // row therefore abandons the whole repair: nothing is written, the
            // tier stays as it was, and the next open tries again. The seed
            // numbers are still returned so the tier opens.
            let mut readable = true;

            // Pass 1 — reverse map against the values.
            for item in db.iterator_cf(cf_kt, rocksdb::IteratorMode::Start) {
                let Ok((k, kt)) = item else {
                    readable = false;
                    break;
                };
                let Ok(key) = <[u8; 32]>::try_from(k.as_ref()) else {
                    batch.delete_cf(cf_kt, &k);
                    continue;
                };
                let ts = kt
                    .get(..8)
                    .and_then(|s| <[u8; 8]>::try_from(s).ok())
                    .map(u64::from_be_bytes);
                match db.get_pinned(key) {
                    Err(_) => {
                        readable = false;
                        break;
                    }
                    Ok(Some(value)) => {
                        let actual = value.len() as u64;
                        count += 1;
                        summed = summed.saturating_add(actual);
                        let recorded = kt
                            .get(8..16)
                            .and_then(|s| <[u8; 8]>::try_from(s).ok())
                            .map(u64::from_be_bytes);
                        // Also upgrades a legacy v1 row (`ts(8)`, no length).
                        if recorded != Some(actual)
                            && let Some(ts) = ts
                        {
                            batch.put_cf(cf_kt, key, Self::kt_value(ts, actual));
                            relengths += 1;
                        }
                    }
                    Ok(None) => {
                        if let Some(ts) = ts {
                            batch.delete_cf(cf_ix, Self::ix_key(ts, &key));
                        }
                        batch.delete_cf(cf_kt, key);
                        orphans += 1;
                    }
                }
            }

            // Pass 2 — values with no reverse map row: ghost or legacy, adopted
            // either way. Staged deletes from pass 1 are not visible here, but
            // they cannot collide: an orphan is by definition a key whose value
            // this iteration does not produce.
            let now = Self::now_secs();
            for item in db.iterator(rocksdb::IteratorMode::Start) {
                if !readable {
                    break;
                }
                let Ok((k, value)) = item else {
                    readable = false;
                    break;
                };
                let Ok(key) = <[u8; 32]>::try_from(k.as_ref()) else {
                    continue;
                };
                match db.get_pinned_cf(cf_kt, key) {
                    // Already accounted for in pass 1.
                    Ok(Some(_)) => continue,
                    Ok(None) => {}
                    Err(_) => {
                        readable = false;
                        break;
                    }
                }
                let len = value.len() as u64;
                batch.put_cf(cf_kt, key, Self::kt_value(now, len));
                batch.put_cf(cf_ix, Self::ix_key(now, &key), []);
                count += 1;
                summed = summed.saturating_add(len);
                adopted += 1;
            }

            // Pass 3 — ts-index rows the reverse map does not vouch for. Rows
            // adopted in pass 2 are still only in the batch, so they are not
            // seen here and cannot be mistaken for dangling.
            for item in db.iterator_cf(cf_ix, rocksdb::IteratorMode::Start) {
                if !readable {
                    break;
                }
                let Ok((ix, _)) = item else {
                    readable = false;
                    break;
                };
                let vouched = match <[u8; 32]>::try_from(ix.get(8..40).unwrap_or_default()) {
                    // A row too short to name a key vouches for nothing and is
                    // a leftover by its shape alone.
                    Err(_) => false,
                    Ok(key) => match db.get_pinned_cf(cf_kt, key) {
                        // The ts prefix must agree, or this row is a leftover
                        // from an overwrite whose delete never landed.
                        Ok(Some(kt)) => kt.get(..8) == ix.get(..8),
                        Ok(None) => false,
                        Err(_) => {
                            readable = false;
                            break;
                        }
                    },
                };
                if !vouched {
                    batch.delete_cf(cf_ix, &ix);
                    dangling += 1;
                }
            }

            let repairs = orphans + adopted + dangling + relengths;
            if !readable {
                log::error!(
                    "dht.cold.rocksdb: the cold tier could not be read to the end on open;                      {repairs} staged repair(s) DISCARDED rather than applied on a partial                      picture, and the next open will try again"
                );
                return (count, summed);
            }
            if repairs > 0 {
                if let Err(e) = db.write(batch) {
                    log::error!(
                        "dht.cold.rocksdb: open-time reconciliation could not be written ({e}); \
                         the tier stays inconsistent and the next open will retry"
                    );
                } else if side_cfs_existed {
                    log::warn!(
                        "dht.cold.rocksdb: repaired a torn cold tier on open — {orphans} orphaned \
                         index entries dropped, {dangling} dangling ts-index rows dropped, \
                         {adopted} ghost values (written without their index) adopted into the \
                         index, {relengths} byte-length records corrected"
                    );
                } else {
                    log::info!(
                        "dht.cold.rocksdb: upgraded a pre-index database — {adopted} legacy \
                         values adopted into the index; they are no longer exempt from TTL and \
                         cap eviction"
                    );
                }
            }
            (count, summed)
        }

        /// Build the `CF_KEY_TS` value (`ts_be(8) ‖ len_be(8)`).
        fn kt_value(ts: u64, byte_len: u64) -> [u8; 16] {
            let mut v = [0u8; 16];
            v[..8].copy_from_slice(&ts.to_be_bytes());
            v[8..].copy_from_slice(&byte_len.to_be_bytes());
            v
        }

        fn now_secs() -> u64 {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        }

        fn cf_ix(&self) -> &rocksdb::ColumnFamily {
            self.db.cf_handle(CF_TS_INDEX).expect("CF_TS_INDEX present")
        }
        fn cf_first_seen(&self) -> &rocksdb::ColumnFamily {
            self.db
                .cf_handle(CF_KEY_FIRST_SEEN)
                .expect("CF_KEY_FIRST_SEEN present")
        }

        fn cf_origin(&self) -> &rocksdb::ColumnFamily {
            self.db
                .cf_handle(CF_KEY_ORIGIN)
                .expect("CF_KEY_ORIGIN present")
        }

        fn cf_kt(&self) -> &rocksdb::ColumnFamily {
            self.db.cf_handle(CF_KEY_TS).expect("CF_KEY_TS present")
        }

        fn ix_key(ts: u64, key: &[u8; 32]) -> [u8; 40] {
            let mut k = [0u8; 40];
            k[..8].copy_from_slice(&ts.to_be_bytes());
            k[8..].copy_from_slice(key);
            k
        }

        /// STAGE the removal of `key`'s index rows (reverse map + ts-index)
        /// into `batch`, returning `true` if an index entry existed.
        ///
        /// Staging rather than writing is the point: this used to issue two
        /// independent `delete_cf` calls whose failures were reported by
        /// nothing but a `log::warn!`, so a caller could believe the entry was
        /// unindexed while one row survived. Its four callers now fold it into
        /// the same `WriteBatch` as the value write/delete, which is what makes
        /// a logical operation all-or-nothing.
        fn stage_unindex(
            &self,
            batch: &mut rocksdb::WriteBatch,
            key: &[u8; 32],
        ) -> Result<bool, rocksdb::Error> {
            // `Err` IS NOT `None`. A read that failed says nothing about
            // whether this key is indexed, and folding it into "it is not"
            // told the caller to count a fresh entry over an existing one and
            // left the stale ts-index row behind (report21 V21-L3).
            if let Some(old_kt) = self.db.get_cf(self.cf_kt(), key)? {
                // Value is `ts(8)` (legacy v1) or `ts(8)‖len(8)` (v2); the ts
                // prefix is what locates the stale ts-index entry.
                if old_kt.len() >= 8 {
                    let mut ts_arr = [0u8; 8];
                    ts_arr.copy_from_slice(&old_kt[..8]);
                    let old_ts = u64::from_be_bytes(ts_arr);
                    batch.delete_cf(self.cf_ix(), Self::ix_key(old_ts, key));
                }
                batch.delete_cf(self.cf_kt(), key);
                Ok(true)
            } else {
                Ok(false)
            }
        }

        /// The ONE place a batch reaches the disk, so the count of durable
        /// writes per operation is a thing a test can assert.
        fn write_batch(&self, batch: rocksdb::WriteBatch) -> Result<(), rocksdb::Error> {
            #[cfg(test)]
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.db.write(batch)
        }

        /// Test-only: durable writes since `open`.
        #[cfg(test)]
        pub fn durable_write_count(&self) -> usize {
            self.writes.load(std::sync::atomic::Ordering::Relaxed)
        }

        /// Stage EVERY row an entry owns: the value, both index rows, and the
        /// two side columns. Returns whether the entry was indexed, so a
        /// caller can move the maintained count only when its write lands.
        ///
        /// One function because there is more than one way an entry leaves,
        /// and each of them has to take the whole entry with it. The side
        /// columns were not deleted at all until report15 V15-M4, and the fix
        /// then went into ordinary deletion only — so cap EVICTION still left
        /// an origin and a first-seen stamp behind for every value it dropped.
        /// Unique-key churn holds the logical entry count at N while two
        /// column families nothing counts and nothing sweeps grow without
        /// bound (report17 V17-M2).
        fn stage_full_delete(
            &self,
            batch: &mut rocksdb::WriteBatch,
            key: &[u8; 32],
        ) -> Result<bool, rocksdb::Error> {
            let was_indexed = self.stage_unindex(batch, key)?;
            batch.delete(key);
            batch.delete_cf(self.cf_origin(), key);
            batch.delete_cf(self.cf_first_seen(), key);
            Ok(was_indexed)
        }

        /// Pick the oldest live entry and stage its removal into `batch`,
        /// WITHOUT writing anything. Returns the victim and whether it was
        /// indexed (so the caller moves the count only once its batch lands).
        ///
        /// Separate from the write so that an eviction made to admit a new
        /// entry travels in the SAME batch as that entry (report20 V18-M1).
        /// Two batches meant the victim could leave and the newcomer never
        /// arrive: on a failed put the caller returned `Failed` and dropped
        /// the victim on the floor, so the tier's byte accounting kept
        /// charging for a value that was already gone, and a crash in the
        /// window lost the old value to make room for nothing.
        fn stage_evict_oldest(
            &mut self,
            batch: &mut rocksdb::WriteBatch,
        ) -> Option<([u8; 32], Vec<u8>, bool)> {
            // Walk the ts-index oldest-first. A row whose value is already
            // gone — a torn write, or a value delete whose index delete failed
            // — must be DROPPED AND SKIPPED, never read as "there is nothing
            // to evict". Such a row is by construction the SMALLEST index key,
            // so bailing out on it (the old `?` on the value lookup) stopped
            // eviction for the whole cold tier permanently: the entry cap and
            // the cold half of `TieredStore`'s byte-cap loop stayed frozen
            // while the loop chewed through the hot tier on every put, until
            // the node degenerated to an almost-empty hot tier in front of a
            // frozen, over-full cold one — with no recovery short of deleting
            // the database (audit report5).
            let mut victim: Option<Victim> = None;
            let mut dangling: Vec<Box<[u8]>> = Vec::new();
            for item in self
                .db
                .iterator_cf(self.cf_ix(), rocksdb::IteratorMode::Start)
            {
                // A READ THAT FAILED IS NOT AN ANSWER. Every branch below acts
                // on "the value is not there" by DELETING this row, and a
                // transient I/O error folded into that verdict took the index
                // away from a value that was perfectly alive — after which
                // nothing counts it, nothing evicts it, and only the next
                // successful reconciliation notices (report21 V21-L3). On any
                // error the scan stops and repairs nothing: eviction is
                // best-effort and the next call retries.
                let Ok((ix_key, _)) = item else {
                    log::warn!(
                        "dht.cold.rocksdb: the ts-index could not be read to the end;                          evicting nothing this pass"
                    );
                    return None;
                };
                // Row layout is `ts_be(8) ‖ key(32)`; a short row is corrupt
                // and is treated exactly like a dangling one.
                let Ok(key) = <[u8; 32]>::try_from(ix_key.get(8..40).unwrap_or_default()) else {
                    dangling.push(ix_key);
                    continue;
                };
                match self.db.get(key) {
                    Ok(Some(value)) => {
                        victim = Some((ix_key, key, value));
                        break;
                    }
                    Ok(None) => dangling.push(ix_key),
                    Err(e) => {
                        log::warn!(
                            "dht.cold.rocksdb: a value could not be read while choosing an                              eviction ({e}); evicting nothing this pass"
                        );
                        return None;
                    }
                }
            }
            // Drop every dangling row walked past, so the next call does not
            // pay for them again. `unindex` cannot do this: it locates the
            // ts-index row THROUGH the reverse map, which is precisely what a
            // dangling row is missing.
            if !dangling.is_empty() {
                let mut repair = rocksdb::WriteBatch::default();
                for ix_key in &dangling {
                    repair.delete_cf(self.cf_ix(), ix_key);
                }
                if let Err(e) = self.write_batch(repair) {
                    log::warn!("dht.cold.rocksdb: dangling ts-index cleanup failed: {e}");
                }
            }
            let (ix_key, key, value) = victim?;
            // The SAME staging as an ordinary delete, which is the point: an
            // eviction that dropped the value and kept the entry's origin and
            // first-seen stamp is how two uncounted column families grew
            // without bound under churn (report17 V17-M2).
            let was_indexed = match self.stage_full_delete(batch, &key) {
                Ok(indexed) => indexed,
                Err(e) => {
                    log::warn!(
                        "dht.cold.rocksdb: an eviction could not be staged ({e});                          evicting nothing this pass"
                    );
                    return None;
                }
            };
            // Delete THIS row directly as well: `stage_unindex` reaches the
            // ts-index through the reverse map's ts, so a missing or drifted
            // reverse map would otherwise leave the row behind as a fresh
            // dangler.
            batch.delete_cf(self.cf_ix(), &ix_key);
            Some((key, value, was_indexed))
        }

        /// Delete an entry — value, both index rows and both side rows — in
        /// ONE batch, and move the maintained count only if the write landed.
        /// Returns whether it did: a caller that credits bytes back for a
        /// delete that failed drifts its byte counter DOWN against a value
        /// that is still on disk.
        fn delete_entry(&mut self, key: &[u8; 32]) -> bool {
            let mut batch = rocksdb::WriteBatch::default();
            let was_indexed = match self.stage_full_delete(&mut batch, key) {
                Ok(indexed) => indexed,
                Err(e) => {
                    // The delete is not staged completely, so it is not made
                    // at all: a half-delete is the torn state reconciliation
                    // exists to repair.
                    log::warn!("dht.cold.rocksdb: entry delete could not be staged: {e}");
                    return false;
                }
            };
            if let Err(e) = self.write_batch(batch) {
                log::warn!("dht.cold.rocksdb: entry delete failed: {e}");
                return false;
            }
            if was_indexed {
                self.count = self.count.saturating_sub(1);
            }
            true
        }

        /// Test-only fixture: plant a ts-index row pointing at `key` while
        /// leaving no value and no reverse-map row — the exact state left
        /// behind when a value delete lands but its index delete does not.
        /// A small `ts` makes it the OLDEST row, which is the case that used
        /// to stop `evict_oldest` dead.
        #[cfg(test)]
        pub fn plant_dangling_index_row(&self, ts: u64, key: &[u8; 32]) {
            self.db
                .put_cf(self.cf_ix(), Self::ix_key(ts, key), [])
                .expect("test fixture: ts-index write");
        }

        /// Test-only fixture: write a value into the default CF and NOTHING
        /// else — the state a torn put leaves when the value lands and its two
        /// index rows do not. Indistinguishable on disk from a grandfathered
        /// pre-T5-B value, which is the whole point of `reconcile`'s
        /// `side_cfs_existed` signal.
        #[cfg(test)]
        pub fn plant_unindexed_value(&self, key: &[u8; 32], value: &[u8]) {
            self.db.put(key, value).expect("test fixture: value write");
        }

        /// Test-only fixture: write the two index rows for `key` with a
        /// recorded length of `recorded_len`. With no value present this is an
        /// ORPHAN (a torn delete, or a torn put whose value never landed);
        /// with a value present and a wrong length it is the recorded-length
        /// drift that made the restart byte seed lie.
        #[cfg(test)]
        pub fn plant_index_rows(&self, ts: u64, key: &[u8; 32], recorded_len: u64) {
            self.db
                .put_cf(self.cf_kt(), key, Self::kt_value(ts, recorded_len))
                .expect("test fixture: reverse-map write");
            self.db
                .put_cf(self.cf_ix(), Self::ix_key(ts, key), [])
                .expect("test fixture: ts-index write");
        }

        /// Test-only observation: number of rows in the reverse-map CF.
        #[cfg(test)]
        pub fn reverse_map_row_count(&self) -> usize {
            self.db
                .iterator_cf(self.cf_kt(), rocksdb::IteratorMode::Start)
                .count()
        }

        /// Test-only observation: number of rows in the ts-index CF. Lets a
        /// test assert positively that a dangling row was actually removed,
        /// rather than merely stepped over.
        #[cfg(test)]
        pub fn ts_index_row_count(&self) -> usize {
            self.db
                .iterator_cf(self.cf_ix(), rocksdb::IteratorMode::Start)
                .count()
        }
    }

    impl ColdBackend for RocksDbCold {
        fn get(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
            self.db.get(key).ok().flatten()
        }

        fn put(&mut self, key: [u8; 32], value: Vec<u8>) -> ColdPut {
            self.put_with_side(key, value, None, None)
        }

        /// The value and BOTH side rows in the one batch.
        ///
        /// The three value rows were already atomic together; the origin and
        /// the first-seen stamp went afterwards as two independent writes, so a
        /// crash between them left a value charged to nobody and aged from the
        /// moment it is read back — and an overwrite by an unnamed publisher
        /// left the PREVIOUS one's row behind to be charged for a value that is
        /// no longer theirs (report16 V16-M4).
        fn put_with_side(
            &mut self,
            key: [u8; 32],
            value: Vec<u8>,
            origin: Option<[u8; 32]>,
            first_seen_unix: Option<u64>,
        ) -> ColdPut {
            let byte_len = value.len() as u64;
            let ts = Self::now_secs();
            // Make room BEFORE inserting, the way `InMemoryCold::put` already
            // does.
            //
            // The ts-index key is `ts_secs(8) ‖ key(32)`, so entries written
            // in the SAME second are ordered by key — and "the oldest" is then
            // whichever key sorts first, not whichever arrived first. Insert a
            // low key into a full tier inside one second and the entry the cap
            // evicts is the one just written. The old code evicted after
            // inserting and then said `Stored(None)` when the victim was the
            // new key, on the stated reasoning that this "can't happen"; what
            // the caller got was "stored, nothing evicted" for a value already
            // off the disk, and its bytes and its first-seen stamp stayed on
            // the books (report17 V17-M3).
            //
            // Evicting first makes that impossible by construction rather than
            // by argument: the new key is not in the index yet, so it cannot
            // be chosen.
            //
            // And it travels in the SAME batch as the entry it makes room for
            // (report20 V18-M1). Two batches had two bad ends: the write in
            // between could crash, losing the victim to admit nothing, and a
            // failed put returned `Failed` while the victim — already gone
            // from disk — was dropped from the return value, so the tier went
            // on charging bytes for a value it no longer had.
            let mut batch = rocksdb::WriteBatch::default();
            let mut evicted: Option<([u8; 32], Vec<u8>)> = None;
            let mut evicted_was_indexed = false;
            // `Ok(None)` alone means "this key is new". An `Err` says nothing,
            // and reading it as "new" makes room by evicting somebody for an
            // entry that may be a plain overwrite.
            let key_is_new = matches!(self.db.get_cf(self.cf_kt(), key), Ok(None));
            if self.capacity > 0 && self.count >= self.capacity && key_is_new {
                // The `victim != key` arm: staged deletes for the very key
                // being written would be overwritten by the puts below — the
                // entry would still be there, so reporting it evicted would
                // credit its bytes back twice. It cannot normally be chosen
                // (it has no reverse-map row, checked just above), but a torn
                // legacy row could put it in the index, and the caller's
                // accounting must not depend on that not happening.
                if let Some((victim, value, was_indexed)) = self.stage_evict_oldest(&mut batch)
                    && victim != key
                {
                    evicted_was_indexed = was_indexed;
                    evicted = Some((victim, value));
                }
            }
            // ONE batch per logical put. A stored entry is three rows — the
            // value, the reverse map, the ts-index — and they used to go to
            // disk as three independent writes of which only the FIRST was
            // checked; the other two reported failure with a `log::warn!` and
            // the count was then bumped regardless. Every durable state that
            // leaves is reachable that way and none of them is recoverable at
            // runtime: a value with no index rows is a GHOST (served by `get`,
            // published by `iter_entries`, reachable by no eviction path and
            // uncounted after restart), and index rows with no value are what
            // used to freeze eviction for the whole tier (audit report5).
            // RocksDB applies a WriteBatch atomically across column families,
            // so the only two outcomes now are all three rows or none.
            //
            // Drop any stale (old_ts, key) row first. Same batch, applied in
            // insertion order, so an overwrite within the same wall-clock
            // second still ends with the fresh rows rather than deleting them.
            let was_indexed = match self.stage_unindex(&mut batch, &key) {
                Ok(indexed) => indexed,
                Err(e) => {
                    // Whether this key is already indexed decides both the
                    // stale rows to drop and the direction the count moves.
                    // Guessing "it is not" writes a fresh entry over an
                    // existing one and leaves its old ts-index row behind, so
                    // the value goes BACK to the caller instead (report21
                    // V21-L3).
                    log::warn!("dht.cold.rocksdb: put failed ({e}); not stored");
                    return ColdPut::Failed(value);
                }
            };
            batch.put(key, &value);
            batch.put_cf(self.cf_kt(), key, Self::kt_value(ts, byte_len));
            batch.put_cf(self.cf_ix(), Self::ix_key(ts, &key), []);
            match origin {
                Some(origin) => batch.put_cf(self.cf_origin(), key, origin),
                // An overwrite by a publisher this node cannot name must not
                // leave the previous one charged for it.
                None => batch.delete_cf(self.cf_origin(), key),
            }
            match first_seen_unix {
                Some(secs) => {
                    batch.put_cf(self.cf_first_seen(), key, secs.to_be_bytes());
                }
                // No stamp offered: drop a stale one rather than let the new
                // value inherit the age of whatever was here before.
                None => batch.delete_cf(self.cf_first_seen(), key),
            }
            if let Err(e) = self.write_batch(batch) {
                // Hand the value BACK rather than dropping it. Returning
                // `None` here was indistinguishable from "stored, nothing
                // evicted", so a disk-full write silently lost a DHT value
                // that demotion had already taken out of the hot tier
                // (audit V-08).
                log::warn!("dht.cold.rocksdb: put failed ({e}); not stored");
                return ColdPut::Failed(value);
            }
            // The entry is real only now, so only now does it count — and
            // the eviction landed in the very same write, so its count moves
            // here too or not at all.
            if evicted_was_indexed {
                self.count = self.count.saturating_sub(1);
            }
            if !was_indexed {
                self.count += 1;
            }
            // Room was made above, so anything reported here is a different
            // entry by construction.
            ColdPut::Stored(evicted)
        }

        fn set_origin(&mut self, key: &[u8; 32], origin: &[u8; 32]) {
            if let Err(e) = self.db.put_cf(self.cf_origin(), key, origin) {
                // Best effort: an origin nobody wrote down is an unattributed
                // row, which is the same state every legacy row is in. The
                // VALUE is what must not be lost, and that write already
                // happened.
                log::warn!("dht.cold.rocksdb: origin write failed: {e}");
            }
        }

        fn forget_origin(&mut self, key: &[u8; 32]) {
            let _ = self.db.delete_cf(self.cf_origin(), key);
        }

        fn set_first_seen(&mut self, key: &[u8; 32], unix_secs: u64) {
            if let Err(e) = self
                .db
                .put_cf(self.cf_first_seen(), key, unix_secs.to_be_bytes())
            {
                // Best effort: a row with no stamp is aged from the moment it
                // is read back, which is where every row was before this.
                log::warn!("dht.cold.rocksdb: first-seen write failed: {e}");
            }
        }

        fn forget_first_seen(&mut self, key: &[u8; 32]) {
            let _ = self.db.delete_cf(self.cf_first_seen(), key);
        }

        fn first_seen_all(&self) -> Option<Vec<([u8; 32], u64)>> {
            let mut out = Vec::new();
            for item in self
                .db
                .iterator_cf(self.cf_first_seen(), rocksdb::IteratorMode::Start)
            {
                let Ok((k, v)) = item else { continue };
                if k.len() != 32 || v.len() != 8 {
                    continue;
                }
                // A stamp for a key whose value is gone describes nothing.
                if !matches!(self.db.get(&k[..]), Ok(Some(_))) {
                    continue;
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&k);
                let mut ts = [0u8; 8];
                ts.copy_from_slice(&v);
                out.push((key, u64::from_be_bytes(ts)));
            }
            Some(out)
        }

        fn origins(&self) -> Option<Vec<super::PersistedOrigin>> {
            let mut out = Vec::new();
            for item in self
                .db
                .iterator_cf(self.cf_origin(), rocksdb::IteratorMode::Start)
            {
                let Ok((k, v)) = item else { continue };
                if k.len() != 32 || v.len() != 32 {
                    continue;
                }
                // The VALUE's length, read from the main family: an origin row
                // for a key whose value is gone describes nothing and must not
                // charge anybody.
                let Ok(Some(value)) = self.db.get(&k[..]) else {
                    continue;
                };
                let mut key = [0u8; 32];
                let mut origin = [0u8; 32];
                key.copy_from_slice(&k);
                origin.copy_from_slice(&v);
                out.push((key, origin, value.len() as u64));
            }
            Some(out)
        }

        fn remove(&mut self, key: &[u8; 32]) {
            let _ = self.delete_entry(key);
        }

        fn contains(&self, key: &[u8; 32]) -> bool {
            self.db.get(key).ok().flatten().is_some()
        }

        fn len(&self) -> usize {
            self.count
        }

        fn cold_total_bytes(&self) -> Option<u64> {
            Some(self.seed_bytes)
        }

        fn is_durable(&self) -> bool {
            true
        }

        fn iter_entries(&self) -> Vec<([u8; 32], Vec<u8>)> {
            let iter = self.db.iterator(rocksdb::IteratorMode::Start);
            iter.filter_map(|item| {
                let (k, v) = item.ok()?;
                let key: [u8; 32] = k.as_ref().try_into().ok()?;
                Some((key, v.to_vec()))
            })
            .collect()
        }

        /// Collect only the 32-byte keys — read from the ts-index, so no value
        /// is ever touched.
        ///
        /// Dropping `_v` from an iterator over the VALUE column family (what
        /// this used to do) keeps the result small but does not stop the read:
        /// RocksDB materializes each value into the iterator before the closure
        /// can discard it. The republish driver calls this once a second while
        /// holding the DHT mutex, so the whole cold tier was being pulled off
        /// disk every second — the disk tier paying a full scan to hand back
        /// 32 bytes per entry.
        ///
        /// The ts-index CF is an exact mirror of the value set: `put` and
        /// `delete_entry` write value + reverse map + ts-index in ONE RocksDB
        /// WriteBatch (all three rows or none), and `reconcile` repairs any
        /// pre-batch database at open. Its rows are `ts(8) ‖ key(32)` with an
        /// empty value, so iterating it reads index blocks only. Same key set,
        /// no value I/O.
        fn iter_keys(&self) -> Vec<[u8; 32]> {
            self.db
                .iterator_cf(self.cf_ix(), rocksdb::IteratorMode::Start)
                .filter_map(|item| {
                    let (ix_key, _) = item.ok()?;
                    <[u8; 32]>::try_from(ix_key.get(8..40)?).ok()
                })
                .collect()
        }

        fn retain(&mut self, f: &dyn Fn(&[u8; 32], &[u8]) -> bool) -> Vec<([u8; 32], u64)> {
            let condemned: Vec<([u8; 32], u64)> = self
                .iter_entries()
                .into_iter()
                .filter(|(k, v)| !f(k, v))
                .map(|(k, v)| (k, v.len() as u64))
                .collect();
            // Report only what actually left. The removed list is the caller's
            // byte-counter delta, so a delete that failed must not appear in
            // it — those bytes are still on disk.
            let mut removed = Vec::with_capacity(condemned.len());
            for (key, bytes) in condemned {
                if self.delete_entry(&key) {
                    removed.push((key, bytes));
                }
            }
            removed
        }

        fn retain_newer_than(&mut self, cutoff: Instant) -> Vec<([u8; 32], u64)> {
            // The trait cutoff is a monotonic `Instant`; the index stores
            // wall-clock seconds. Convert: age = how far in the past `cutoff`
            // is, then wall_cutoff = now_wall − age. Entries with stored
            // ts < wall_cutoff are older than the cutoff and get evicted.
            let age = Instant::now().saturating_duration_since(cutoff);
            let wall_cutoff = Self::now_secs().saturating_sub(age.as_secs());
            // Scan the ts-index from oldest; stop at the first entry >= cutoff
            // (the index is ordered by ts, so the rest are all newer).
            let mut victims: Vec<[u8; 32]> = Vec::new();
            for item in self
                .db
                .iterator_cf(self.cf_ix(), rocksdb::IteratorMode::Start)
            {
                let Ok((ix_key, _)) = item else { break };
                if ix_key.len() < 40 {
                    continue;
                }
                let mut ts_arr = [0u8; 8];
                ts_arr.copy_from_slice(&ix_key[..8]);
                if u64::from_be_bytes(ts_arr) >= wall_cutoff {
                    break; // ordered: everything from here on is newer
                }
                if let Ok(k) = <[u8; 32]>::try_from(&ix_key[8..40]) {
                    victims.push(k);
                }
            }
            let mut removed = Vec::with_capacity(victims.len());
            for key in victims {
                let byte_len = self
                    .db
                    .get(key)
                    .ok()
                    .flatten()
                    .map(|v| v.len())
                    .unwrap_or(0) as u64;
                // Same rule as `retain`: only what really left is reported.
                if self.delete_entry(&key) {
                    removed.push((key, byte_len));
                }
            }
            removed
        }

        /// Evict on its own — the maintenance path, where there is no
        /// newcomer to travel with. Everything the entry owns leaves in one
        /// batch or the eviction did not happen and must not be reported.
        fn evict_oldest(&mut self) -> Option<([u8; 32], Vec<u8>)> {
            let mut batch = rocksdb::WriteBatch::default();
            let (key, value, was_indexed) = self.stage_evict_oldest(&mut batch)?;
            if let Err(e) = self.write_batch(batch) {
                log::warn!("dht.cold.rocksdb: eviction of the oldest entry failed: {e}");
                return None;
            }
            if was_indexed {
                self.count = self.count.saturating_sub(1);
            }
            Some((key, value))
        }
    }
}

// ── Cold-tier selection ─────────────────────────────────────────

/// Construct a [`TieredStore`], choosing the cold-tier backend from the
/// optional `cold_store_path`.
///
/// * `cold_store_path == None` → cold tier is the bounded in-memory map
///   ([`InMemoryCold`], capacity `cold_capacity`). Identical to
///   [`TieredStore::new`] — the historical, all-in-memory behaviour.
/// * `cold_store_path == Some(path)` **and** the binary is built with the
///   `rocksdb-cold` feature → cold tier is a disk-backed RocksDB store at
///   `path` (durable across restarts; sized for > 1M entries — disk space
///   and the optional `max_store_bytes` cap bound it, not RAM).
/// * `cold_store_path == Some(path)` **without** the feature, or when the
///   RocksDB open fails → logs and falls back to the in-memory cold tier so
///   the node keeps serving. This mirrors the daemon's best-effort
///   snapshot-persistence convention (a persistence-layer error never takes
///   the node down); the operator sees a loud log line instead.
pub fn build_tiered_store(
    hot_capacity: usize,
    cold_capacity: usize,
    cold_store_path: Option<&str>,
) -> TieredStore {
    match cold_store_path {
        None => TieredStore::new(hot_capacity, cold_capacity),
        Some(path) => build_cold_tier(hot_capacity, cold_capacity, path),
    }
}

#[cfg(feature = "rocksdb-cold")]
fn build_cold_tier(hot_capacity: usize, cold_capacity: usize, path: &str) -> TieredStore {
    // audit cycle-6 (T5-B): thread `cold_capacity` (max_store_entries for the
    // cold tier) into RocksDbCold so the entry cap is actually enforced via the
    // side timestamp index (previously the RocksDB path ignored the cap).
    match rocks::RocksDbCold::open(path, cold_capacity) {
        Ok(backend) => {
            log::info!(
                "DHT cold tier: disk-backed RocksDB at {path} (entry cap {cold_capacity}, \
                 TTL/oldest eviction via side timestamp index)"
            );
            TieredStore::with_cold(hot_capacity, Box::new(backend))
        }
        Err(e) => {
            log::error!(
                "DHT cold tier: failed to open RocksDB at {path}: {e}; \
                 falling back to the in-memory cold tier — cold entries will \
                 NOT persist across restarts and capacity is RAM-bound"
            );
            TieredStore::new(hot_capacity, cold_capacity)
        }
    }
}

#[cfg(not(feature = "rocksdb-cold"))]
fn build_cold_tier(hot_capacity: usize, cold_capacity: usize, path: &str) -> TieredStore {
    log::warn!(
        "DHT cold_store_path is set ({path}) but this binary was built without \
         the `rocksdb-cold` feature; using the in-memory cold tier instead. \
         Rebuild with `--features rocksdb-cold` to enable the disk cold tier."
    );
    TieredStore::new(hot_capacity, cold_capacity)
}

/// Synthetic origin id used by `put` / `store_local` / republish / mailbox
/// — internal writes that bypass per-origin accounting.  All-zero is safe
/// because no real Ed25519 pubkey hashes to it (1-in-2^256 collision).
pub const ORIGIN_INTERNAL: [u8; 32] = [0u8; 32];

/// Synthetic origin id used by legacy unsigned STOREs (accepted only when
/// [`crate::DhtRuntimeConfig::allow_unsigned_store`] is `true`).  All
/// unsigned records on a node share this single bucket, so the per-origin
/// cap functions as a collective ceiling for the inner-sig deployment
/// pattern.
pub const ORIGIN_UNSIGNED: [u8; 32] = [0xFFu8; 32];

/// Synthetic origin id used by recursive-plane STOREs of signed operator
/// bootstrap bundles, which carry no per-identity owner to attribute bytes to
/// (audit N1).  All such bundles share this single bucket so the per-origin
/// byte cap still bounds bundle spam on the recursive store path. Records that
/// DO carry an owner node_id (app-endpoint / attachment / name-claim /
/// identity-document / instance-registry / mlkem-cert) are attributed to that
/// owner instead, matching the direct STORE path's per-signer accounting.
pub const ORIGIN_RECURSIVE_BUNDLE: [u8; 32] = [0xEEu8; 32];

/// One stored entry together with the two facts a `(key, value)` pair drops on
/// the floor: the origin that authorised the write, and how long the entry has
/// already lived.
///
/// Both matter on restore. Without the origin every restored entry re-enters as
/// [`ORIGIN_INTERNAL`], which is exempt from the per-origin byte cap, so a
/// restart launders a capped origin's bytes into the uncapped bucket. Without
/// the age every restored entry gets a fresh full TTL, so a value that should
/// have expired can be kept alive indefinitely by restarting.
#[derive(Debug, Clone)]
pub struct StoredEntry {
    pub key: [u8; 32],
    pub value: Vec<u8>,
    pub origin: [u8; 32],
    pub age: Duration,
}

/// Tiered key-value store for DHT entries.
#[derive(Debug)]
pub struct TieredStore {
    /// Hot tier: recently accessed entries (always in-memory).
    ///
    /// `(value, order_ts, first_seen)`. The two stamps used to be one, and one
    /// stamp cannot do both jobs: `hot_order` wants the entry RE-DATED on
    /// promotion (or a record read up from cold is the next thing demoted, so
    /// promotion buys nothing), while the TTL wants the stamp NEVER re-dated
    /// (or a tier move hands the record a fresh full lifetime). Merged, the
    /// re-dating won and age reset on every promotion — report12 V-M7.
    hot: HashMap<[u8; 32], (Vec<u8>, Instant, Instant)>,
    /// Keyed by `order_ts`: demotion order, and nothing to do with expiry.
    hot_order: BTreeMap<(Instant, [u8; 32]), ()>,
    /// `first_seen` for entries that are currently COLD, so a promotion can
    /// give the record its own age back rather than today's date.
    ///
    /// Kept here rather than in the backends: neither would have to change on
    /// disk for this, and a durable tier restored from disk has no meaningful
    /// `Instant` anyway. Every path that takes a key out of cold drops it from
    /// here too, so this cannot outgrow the tier it describes.
    cold_first_seen: HashMap<[u8; 32], Instant>,
    hot_capacity: usize,

    /// Cold tier: pluggable backend.
    cold: Box<dyn ColdBackend>,

    /// Running sum of bytes stored across both tiers (audit batch
    /// 2026-05-23 — DHT byte-cap).  Maintained incrementally on
    /// every put/remove/eviction.  Use [`Self::total_bytes`] for
    /// access — the field is private so the invariant cannot be
    /// trampled by a sibling crate.
    total_bytes: u64,

    /// Optional global byte budget.  When `Some(N)`, a put that would
    /// push `total_bytes` past `N` triggers eviction of the oldest
    /// entries (cold first, then hot demoted-and-evicted) until the
    /// new value fits.  If the new value alone exceeds the cap, the
    /// put is refused (value silently dropped — sender sees the
    /// daemon-side rejection as a regular DHT-store failure).
    /// Default `None` (no cap, backward-compat).
    max_bytes: Option<u64>,

    /// Per-origin byte tracking (Phase 11e).  Maps signer-origin id to the
    /// number of bytes that origin currently occupies across both tiers.
    /// [`ORIGIN_INTERNAL`] entries are tracked but exempt from the cap
    /// check; everything else is capped at [`Self::per_origin_max_bytes`].
    origin_bytes: HashMap<[u8; 32], u64>,

    /// Reverse map: DHT key → origin that wrote it.  Maintained alongside
    /// the value tiers so `remove` / eviction paths can decrement
    /// [`Self::origin_bytes`] without re-scanning.  Entries inserted via
    /// [`Self::put`] (no origin) inherit `ORIGIN_INTERNAL` automatically.
    entry_origin: HashMap<[u8; 32], [u8; 32]>,

    /// Optional per-origin byte cap.  When `Some(N)`, a
    /// [`Self::put_with_origin`] whose origin is non-internal AND whose
    /// `origin_bytes[origin] - existing_for_this_key + new_bytes`
    /// exceeds `N` is refused outright (the put returns `false`).
    /// `None` disables the cap; internal-origin puts are never capped.
    per_origin_max_bytes: Option<u64>,
}

impl TieredStore {
    /// Create a tiered store with given hot and cold capacities (in-memory cold).
    pub fn new(hot_capacity: usize, cold_capacity: usize) -> Self {
        Self {
            hot: HashMap::new(),
            hot_order: BTreeMap::new(),
            cold_first_seen: HashMap::new(),
            hot_capacity,
            cold: Box::new(InMemoryCold::new(cold_capacity)),
            total_bytes: 0,
            max_bytes: None,
            origin_bytes: HashMap::new(),
            entry_origin: HashMap::new(),
            per_origin_max_bytes: None,
        }
    }

    /// Create with a custom cold backend (e.g., RocksDB).
    ///
    /// Audit cycle-8: seed `total_bytes` from the backend's already-persisted
    /// data (`cold_total_bytes`) so a disk tier that survived a restart is
    /// accounted for by the global byte-cap from the first put — previously
    /// `total_bytes` started at 0 regardless of what was on disk, letting the
    /// cap drift across restarts. Per-origin bytes are NOT seeded (the origin
    /// of a persisted value isn't recorded on disk); the global cap is the
    /// meaningful restart-safety bound. In-memory backends return `None` here.
    pub fn with_cold(hot_capacity: usize, cold: Box<dyn ColdBackend>) -> Self {
        let total_bytes = cold.cold_total_bytes().unwrap_or(0);
        if total_bytes > 0 {
            log::info!(
                "DHT cold tier: seeded total_bytes={total_bytes} from persisted disk tier on open"
            );
        }
        // Per-origin bytes are seeded too, from what the backend remembers.
        // They used to start empty however much was on disk, so a restart
        // handed every publisher a fresh allowance while its rows were still
        // there — the per-origin cap simply stopped applying across restarts
        // (report14 V14-L3).
        //
        // A row the backend has no origin for stays UNATTRIBUTED rather than
        // being guessed at. That is every row written before this existed, and
        // it is the honest state: the global total still counts them.
        let mut origin_bytes: HashMap<[u8; 32], u64> = HashMap::new();
        let mut entry_origin: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
        // How old each persisted row is, so the expiry sweep does not start
        // it over. A stamp from the FUTURE is what a clock moved backwards
        // looks like, and it is clamped to "now" rather than believed
        // (report14 V14-L2).
        let mut cold_first_seen: HashMap<[u8; 32], Instant> = HashMap::new();
        if let Some(rows) = cold.first_seen_all() {
            let now = Instant::now();
            let unix_now = veil_util::unix_secs_now_u64();
            for (key, stamped) in rows {
                let age = unix_now.saturating_sub(stamped);
                cold_first_seen.insert(
                    key,
                    now.checked_sub(std::time::Duration::from_secs(age))
                        .unwrap_or(now),
                );
            }
            if !cold_first_seen.is_empty() {
                log::info!(
                    "DHT cold tier: seeded {} first-seen stamp(s) from disk",
                    cold_first_seen.len()
                );
            }
        }
        if let Some(rows) = cold.origins() {
            for (key, origin, bytes) in rows {
                entry_origin.insert(key, origin);
                *origin_bytes.entry(origin).or_insert(0) += bytes;
            }
            if !entry_origin.is_empty() {
                log::info!(
                    "DHT cold tier: seeded {} per-origin row(s) across {} publisher(s)",
                    entry_origin.len(),
                    origin_bytes.len()
                );
            }
        }
        Self {
            hot: HashMap::new(),
            hot_order: BTreeMap::new(),
            cold_first_seen,
            hot_capacity,
            cold,
            total_bytes,
            max_bytes: None,
            origin_bytes,
            entry_origin,
            per_origin_max_bytes: None,
        }
    }

    /// Builder-style: enable a global byte-cap.  Returns `Self` so
    /// callers can chain after `new` / `with_cold`.  Operators set this
    /// from `[dht] max_store_bytes` in the daemon config.
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = Some(max_bytes);
        self
    }

    /// Builder-style: enable the per-origin byte cap (Phase 11e).  Returns
    /// `Self` so callers can chain after `new` / `with_cold` / `with_max_bytes`.
    /// Operators set this from `[dht] per_origin_max_bytes` in the daemon
    /// config — a conservative ceiling (e.g. 64 KiB) bounds how much a
    /// single misbehaving signer can write before its puts start being
    /// refused at the local node.
    #[must_use]
    pub fn with_per_origin_max_bytes(mut self, per_origin_max_bytes: u64) -> Self {
        self.per_origin_max_bytes = Some(per_origin_max_bytes);
        self
    }

    /// Running byte total across both tiers.  O(1) — maintained
    /// incrementally.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Configured byte cap (if any).
    pub fn max_bytes(&self) -> Option<u64> {
        self.max_bytes
    }

    /// Bytes currently held by a specific origin.  O(1) — backed by the
    /// `origin_bytes` map. Returns `0` for unknown origins.
    pub fn origin_bytes(&self, origin: &[u8; 32]) -> u64 {
        self.origin_bytes.get(origin).copied().unwrap_or(0)
    }

    /// Configured per-origin byte cap (if any).
    pub fn per_origin_max_bytes(&self) -> Option<u64> {
        self.per_origin_max_bytes
    }

    /// Get a value by key. Promotes from cold to hot on access.
    pub fn get(&mut self, key: &[u8; 32]) -> Option<&Vec<u8>> {
        // Check hot first.
        if self.hot.contains_key(key) {
            return self.hot.get(key).map(|(v, _, _)| v);
        }
        // Check cold — promote if found.
        if let Some(value) = self.cold.get(key) {
            // Promotion must be byte-neutral: `cold.remove` does NOT adjust
            // `total_bytes`, but `insert_hot` re-adds `value.len()`. The bytes
            // were already counted while the entry sat in cold, so cancel
            // insert_hot's re-add here — otherwise `total_bytes` drifts upward
            // on every cold→hot promotion and spuriously trips the byte-cap
            // eviction loop (audit U1).
            let now = Instant::now();
            // Byte-neutral ONLY when the cold copy really went away. If the
            // delete failed the node now holds two copies, and both are
            // counted — see `release_cold`.
            // Re-dated for ORDER, its own age kept for EXPIRY.
            let (_, first_seen) = self.release_cold(key, value.len() as u64, now);
            self.insert_hot(*key, value, now, first_seen);
            return self.hot.get(key).map(|(v, _, _)| v);
        }
        None
    }

    /// Read without moving the entry between tiers or re-dating it.
    ///
    /// [`Self::get`] promotes a cold hit to hot and stamps it `Instant::now()`.
    /// That is right for OUR OWN lookups: a key this node keeps asking for
    /// belongs in the hot tier. It is wrong for the answer to a remote
    /// FIND_VALUE, where reading is something anyone may ask for and each ask
    /// re-dates the record. Alternating eviction and reads, a peer keeps a
    /// record alive past the retention its publisher asked for and pays
    /// nothing for it (report12 V-M7).
    ///
    /// This is only the half that stops a REMOTE reader from extending a
    /// record. The absolute expiry is still not carried across a tier move, so
    /// a promotion driven by our own lookups still re-dates — that needs the
    /// original insertion stamp stored in the cold tier, which changes what
    /// both cold backends keep on disk.
    ///
    /// Returns an owned value because the cold tier hands back owned bytes.
    /// Taking `&self` is the point: this path cannot mutate the store.
    pub fn get_no_promote(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some((value, _, _)) = self.hot.get(key) {
            return Some(value.clone());
        }
        self.cold.get(key)
    }

    /// Get a value AND its hot-tier `inserted_at` timestamp.  Used by
    /// layers that need per-entry freshness independent of the store-
    /// wide TTL (audit batch 2026-05-25 phase N — anycast resolve uses
    /// this to drop records whose record-level `ttl` has elapsed even
    /// though the store-wide TTL hasn't yet evicted them).
    ///
    /// Returns `(value, inserted_at)` if present, `None` otherwise.
    /// Like [`Self::get`], promotes cold-tier hits to hot (the promotion
    /// stamps a fresh `Instant::now()`; callers that need the original
    /// publish-time should not rely on this for records that have just
    /// surfaced from cold tier).
    pub fn get_with_meta(&mut self, key: &[u8; 32]) -> Option<(&Vec<u8>, Instant)> {
        if self.hot.contains_key(key) {
            return self.hot.get(key).map(|(v, _, first)| (v, *first));
        }
        if let Some(value) = self.cold.get(key) {
            // Byte-neutral promotion — see `get` (audit U1), and only when
            // the cold copy really went (report14 V14-M4).
            let now = Instant::now();
            let (_, first_seen) = self.release_cold(key, value.len() as u64, now);
            self.insert_hot(*key, value, now, first_seen);
            return self.hot.get(key).map(|(v, _, first)| (v, *first));
        }
        None
    }

    /// Insert or update a key-value pair. Goes into hot tier.
    ///
    /// When [`Self::max_bytes`] is set and the new value would push the
    /// total past the cap, evicts the oldest entries (cold first, then
    /// hot demoted-and-evicted) until the value fits.  If the value
    /// alone is larger than the cap, the put is refused (returns
    /// silently — callers that need a success/refusal signal should
    /// pre-check `value.len() as u64 <= max_bytes`).
    pub fn put(&mut self, key: [u8; 32], value: Vec<u8>) {
        let _ = self.put_with_origin_at(key, value, ORIGIN_INTERNAL, Instant::now());
    }

    /// Insert with a specific timestamp (used by tests and snapshot restore).
    pub fn put_at(&mut self, key: [u8; 32], value: Vec<u8>, ts: Instant) {
        let _ = self.put_with_origin_at(key, value, ORIGIN_INTERNAL, ts);
    }

    /// Insert or update a key-value pair carrying an explicit origin
    /// (Phase 11e).  Returns `true` on accept, `false` if refused by either
    /// the global byte cap (oversized value) or the per-origin cap.
    ///
    /// `origin` must be the 32-byte signer id of the entity that
    /// authorised the STORE — typically the Ed25519 / Falcon-512 pubkey
    /// or a derived 32-byte identifier.  Use [`ORIGIN_INTERNAL`] for
    /// trusted internal writes (mailbox replication, republish, raw
    /// `store_local`) — those bypass the per-origin cap.  Use
    /// [`ORIGIN_UNSIGNED`] when accepting legacy unsigned STOREs (the
    /// shared bucket pattern — see the field docs on
    /// [`crate::DhtRuntimeConfig::allow_unsigned_store`]).
    pub fn put_with_origin(&mut self, key: [u8; 32], value: Vec<u8>, origin: [u8; 32]) -> bool {
        self.put_with_origin_at(key, value, origin, Instant::now())
    }

    /// Like [`Self::put_with_origin`] but with a caller-supplied timestamp.
    /// Useful for snapshot-restore paths and unit tests that need a
    /// deterministic clock.
    pub fn put_with_origin_at(
        &mut self,
        key: [u8; 32],
        value: Vec<u8>,
        origin: [u8; 32],
        ts: Instant,
    ) -> bool {
        let new_bytes = value.len() as u64;

        // 0. Per-origin cap check (non-internal origins only).  Computed
        //    over the projected delta: existing same-origin same-key
        //    bytes are refunded before checking the cap.
        if origin != ORIGIN_INTERNAL
            && let Some(cap) = self.per_origin_max_bytes
        {
            let existing_for_origin_this_key = match self.entry_origin.get(&key) {
                Some(prev_origin) if *prev_origin == origin => self.value_bytes(&key),
                _ => 0,
            };
            let projected = self
                .origin_bytes
                .get(&origin)
                .copied()
                .unwrap_or(0)
                .saturating_sub(existing_for_origin_this_key)
                .saturating_add(new_bytes);
            if projected > cap {
                return false;
            }
        }

        // 1. Byte-cap check: refuse single values that exceed the cap.
        //    BEFORE the removal below, not after.  This depends only on the
        //    value being offered, so running it second made a refused put
        //    destructive: replacing a key with an oversized value dropped the
        //    incumbent and then declined to store anything, and the caller was
        //    told `false` — which reads as "nothing happened" (report16
        //    V16-L2).  Every check that can be made without touching the store
        //    is made before the store is touched.
        if let Some(cap) = self.max_bytes
            && new_bytes > cap
        {
            // Value alone exceeds the budget — drop silently.  Caller
            // can pre-check via `total_bytes()` / `max_bytes()` to
            // distinguish "won't fit" from "succeeded but evicted others".
            return false;
        }

        // 2. Drop the previous value's bytes for this key (if any) — done
        //    by calling remove(), which adjusts total_bytes and origin_bytes
        //    appropriately.
        self.remove(&key);

        // 3. Evict oldest entries until the new value fits.  Cold first
        //    (cheapest data — already demoted), then hot (demote-and-
        //    evict).  Each eviction strictly decreases total_bytes.
        if let Some(cap) = self.max_bytes {
            while self.total_bytes.saturating_add(new_bytes) > cap {
                if let Some((evicted_key, evicted_val)) = self.cold.evict_oldest() {
                    self.account_eviction(&evicted_key, evicted_val.len() as u64);
                    continue;
                }
                // Cold drained — fall back to demoting hot's oldest and
                // immediately dropping it (instead of into cold) so the
                // bytes actually free.
                if let Some(&(old_ts, old_key)) = self.hot_order.keys().next() {
                    self.hot_order.remove(&(old_ts, old_key));
                    if let Some((old_val, _, _)) = self.hot.remove(&old_key) {
                        self.account_eviction(&old_key, old_val.len() as u64);
                    }
                    continue;
                }
                // Both tiers empty but the cap is still exceeded — the
                // cap is smaller than `new_bytes`.  Already handled by
                // the explicit `new_bytes > cap` check above, but defence
                // in depth: bail out of the loop.
                break;
            }
        }

        // 4. Insert into hot.  insert_hot maintains total_bytes for the
        //    hot side and handles hot-overflow demotion.
        self.entry_origin.insert(key, origin);
        *self.origin_bytes.entry(origin).or_insert(0) += new_bytes;
        self.insert_hot(key, value, ts, ts);
        true
    }

    /// Also drops the entry's `first_seen`: every path that takes a key out
    /// of cold comes through here or names the key itself, which is what keeps
    /// [`Self::cold_first_seen`] from outgrowing the tier it describes.
    ///
    /// Decrement [`Self::total_bytes`] and per-origin tracking when an
    /// entry is evicted out-of-band (cold backend's own LRU cache or
    /// hot-overflow demote-and-drop).  Internal helper — call sites must
    /// have already removed the entry from its tier.
    fn account_eviction(&mut self, key: &[u8; 32], bytes: u64) {
        self.total_bytes = self.total_bytes.saturating_sub(bytes);
        self.cold_first_seen.remove(key);
        if let Some(origin) = self.entry_origin.remove(key)
            && let Some(slot) = self.origin_bytes.get_mut(&origin)
        {
            *slot = slot.saturating_sub(bytes);
            if *slot == 0 {
                self.origin_bytes.remove(&origin);
            }
        }
    }

    /// Drop `key`'s cold copy and stop counting its bytes — but only if the
    /// backend really deleted it.
    ///
    /// [`ColdBackend::remove`] reports nothing: the trait returns `()`, and a
    /// RocksDB write error is logged and swallowed. Subtracting bytes for a
    /// value that is still on disk drifts `total_bytes` DOWN, and the record
    /// comes back at the next restart to be counted again — expiry and the
    /// global cap both stop meaning what they say (report14 V14-M4).
    /// `TieredStore::remove` already asked this question (audit report5); the
    /// promotion and sweep paths did not.
    ///
    /// Returns whether the value is gone, and the `first_seen` to carry
    /// forward. A failed delete KEEPS the stamp, so the next sweep tries
    /// again instead of losing track of an entry it can no longer age.
    fn release_cold(&mut self, key: &[u8; 32], bytes: u64, now: Instant) -> (bool, Instant) {
        self.cold.remove(key);
        if self.cold.contains(key) {
            // Still there, so its origin row still describes something.
            let first_seen = self.cold_first_seen.get(key).copied().unwrap_or(now);
            return (false, first_seen);
        }
        // Gone for real: its side rows describe nothing now.
        self.cold.forget_origin(key);
        self.cold.forget_first_seen(key);
        self.total_bytes = self.total_bytes.saturating_sub(bytes);
        (true, self.cold_first_seen.remove(key).unwrap_or(now))
    }

    /// Look up the byte size of a stored value, irrespective of tier.
    /// Used by the per-origin cap delta check.  Returns `0` if absent.
    fn value_bytes(&self, key: &[u8; 32]) -> u64 {
        if let Some((v, _, _)) = self.hot.get(key) {
            return v.len() as u64;
        }
        self.cold.get(key).map(|v| v.len() as u64).unwrap_or(0)
    }

    /// Remove a key from both tiers.
    pub fn remove(&mut self, key: &[u8; 32]) {
        let mut removed_bytes: u64 = 0;
        if let Some((val, ts, _)) = self.hot.remove(key) {
            self.hot_order.remove(&(ts, *key));
            removed_bytes = removed_bytes.saturating_add(val.len() as u64);
        }
        // Cold doesn't return the removed value from its `remove` API.
        // Get the value first so we can subtract its bytes from the total.
        let cold_bytes = self.cold.get(key).map(|v| v.len() as u64).unwrap_or(0);
        self.cold.remove(key);
        // The in-memory stamp goes only once the value really has.
        //
        // It used to be dropped BEFORE the delete was attempted, so a delete
        // the backend could not perform — reported by the trait as nothing at
        // all — left the value on disk with its age forgotten. `retain_fresh`
        // then ages it from now, which hands a record that should have expired
        // another full lifetime; `release_cold` already got this right and
        // this path did not (report17 V17-L2).
        if !self.cold.contains(key) {
            self.cold_first_seen.remove(key);
        }
        // Credit the cold bytes back ONLY once the value is really gone. A
        // backend delete can fail (a disk error is reported by the trait as
        // nothing at all), and subtracting bytes for a value still on disk
        // drifts `total_bytes` DOWN — then the next put of the same key
        // reaches this same line and subtracts them a second time. Two failed
        // deletes of a large value buy unlimited room under the global cap
        // (audit report5).
        if cold_bytes > 0 && !self.cold.contains(key) {
            removed_bytes = removed_bytes.saturating_add(cold_bytes);
        }
        if removed_bytes > 0 {
            self.total_bytes = self.total_bytes.saturating_sub(removed_bytes);
            if let Some(origin) = self.entry_origin.remove(key)
                && let Some(slot) = self.origin_bytes.get_mut(&origin)
            {
                *slot = slot.saturating_sub(removed_bytes);
                if *slot == 0 {
                    self.origin_bytes.remove(&origin);
                }
            }
        }
    }

    /// Check if key exists in either tier (without promoting).
    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.hot.contains_key(key) || self.cold.contains(key)
    }

    /// Total entries across both tiers.
    pub fn len(&self) -> usize {
        self.hot.len() + self.cold.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hot.is_empty() && self.cold.is_empty()
    }

    /// Hot tier size.
    pub fn hot_len(&self) -> usize {
        self.hot.len()
    }

    /// Cold tier size.
    /// `true` if `key` currently sits in the hot tier.
    ///
    /// Tier PLACEMENT, not tier size: a promotion is byte- and count-neutral
    /// because it demotes something else to make room, so `cold_len` alone
    /// cannot see one happen. A test that watched the counts watched the one
    /// number a promotion is guaranteed not to move.
    pub fn is_hot(&self, key: &[u8; 32]) -> bool {
        self.hot.contains_key(key)
    }

    pub fn cold_len(&self) -> usize {
        self.cold.len()
    }

    /// Whether the cold tier persists across process restarts on its own
    /// (e.g. a disk-backed RocksDB). True for durable backends, false for the
    /// volatile in-memory cold tier. Used by the values-snapshot path: when the
    /// cold tier is durable it need not be re-serialised to the JSON snapshot
    /// every tick (it survives restart by itself).
    pub fn cold_is_durable(&self) -> bool {
        self.cold.is_durable()
    }

    /// Iterate all entries across both tiers (hot first, then cold).
    /// Returns owned `(key, value)` pairs — no promotion side-effects.
    pub fn iter(&self) -> Vec<([u8; 32], Vec<u8>)> {
        let mut result: Vec<([u8; 32], Vec<u8>)> = self
            .hot
            .iter()
            .map(|(k, (v, _, _))| (*k, v.clone()))
            .collect();
        result.extend(self.cold.iter_entries());
        result
    }

    /// One stored entry plus the metadata a persisted snapshot must carry.
    ///
    /// A snapshot of `(key, value)` alone loses two things the store knows and
    /// cannot re-derive on restore: WHO put the entry there, and HOW LONG it
    /// has already lived. See [`StoredEntry`].
    fn entry_meta(
        &self,
        key: &[u8; 32],
        inserted_at: Instant,
        now: Instant,
    ) -> ([u8; 32], Duration) {
        let origin = self
            .entry_origin
            .get(key)
            .copied()
            .unwrap_or(ORIGIN_INTERNAL);
        (origin, now.saturating_duration_since(inserted_at))
    }

    /// [`Self::iter_hot`] with provenance and age attached.
    pub fn iter_hot_with_meta(&self, now: Instant) -> Vec<StoredEntry> {
        self.hot
            .iter()
            .map(|(k, (v, _order_ts, first_seen))| {
                let (origin, age) = self.entry_meta(k, *first_seen, now);
                StoredEntry {
                    key: *k,
                    value: v.clone(),
                    origin,
                    age,
                }
            })
            .collect()
    }

    /// [`Self::iter`] with provenance and age attached.
    pub fn iter_with_meta(&self, now: Instant) -> Vec<StoredEntry> {
        let mut out = self.iter_hot_with_meta(now);
        out.extend(
            self.cold
                .iter_entries_with_ts(now)
                .into_iter()
                .map(|(k, v, inserted_at)| {
                    let (origin, age) = self.entry_meta(&k, inserted_at, now);
                    StoredEntry {
                        key: k,
                        value: v,
                        origin,
                        age,
                    }
                }),
        );
        out
    }

    /// Insert an entry that has ALREADY lived for `age`, attributed to
    /// `origin`. The restore-from-snapshot counterpart of
    /// [`Self::put_with_origin`]: a value that was 59 minutes into its hour
    /// must come back with one minute left, not with a fresh hour.
    pub fn put_restored(
        &mut self,
        key: [u8; 32],
        value: Vec<u8>,
        origin: [u8; 32],
        age: Duration,
        now: Instant,
    ) -> bool {
        let inserted_at = now.checked_sub(age).unwrap_or(now);
        self.put_with_origin_at(key, value, origin, inserted_at)
    }

    /// Iterate **only the volatile HOT tier** `(key, value)` pairs (no cold
    /// tier). Used by the values snapshot when the cold tier is durable
    /// (`cold_is_durable()`): the cold set persists via its own backend, so
    /// re-serialising it every interval would defeat the disk tier and risk an
    /// OOM on large stores. No promotion side-effects.
    pub fn iter_hot(&self) -> Vec<([u8; 32], Vec<u8>)> {
        self.hot
            .iter()
            .map(|(k, (v, _, _))| (*k, v.clone()))
            .collect()
    }

    /// Iterate all KEYS across both tiers WITHOUT materializing cold-tier
    /// values (audit cycle-7 M4). The republish driver calls this every tick
    /// and fetches values only for the keys actually due via [`Self::peek`],
    /// so the full cold value set never enters RAM — unlike [`Self::iter`],
    /// which clones every value (defeating a RocksDB disk tier).
    pub fn iter_keys(&self) -> Vec<[u8; 32]> {
        let mut keys: Vec<[u8; 32]> = self.hot.keys().copied().collect();
        keys.extend(self.cold.iter_keys());
        keys
    }

    /// Read a value by key WITHOUT promoting a cold-tier hit to hot (unlike
    /// [`Self::get`]). The republish driver touches every due key each
    /// interval; promoting them would churn the hot/cold boundary and defeat
    /// the tiering. Returns an owned clone; `&self`, no side-effects.
    pub fn peek(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        if let Some((v, _, _)) = self.hot.get(key) {
            return Some(v.clone());
        }
        self.cold.get(key)
    }

    /// Age-only cleanup: remove entries older than `ttl` from both tiers,
    /// WITHOUT inspecting any value (audit cycle-8). This is the DHT default
    /// path — the production caller passes a value-predicate of `|_| false`,
    /// so the value-based `cold.retain` was a guaranteed no-op that still
    /// materialized the entire RocksDB value set into RAM each cleanup tick.
    /// Skipping it leaves the (cheap, ts-index-driven) `retain_newer_than` as
    /// the only cold-tier work.
    pub fn retain_fresh_age_only(&mut self, now: Instant, ttl: std::time::Duration) {
        self.retain_fresh_inner(now, ttl, None);
    }

    /// Remove entries older than `ttl` from hot tier.
    /// Also removes entries where `expired(value)` returns true from both tiers.
    pub fn retain_fresh(
        &mut self,
        now: Instant,
        ttl: std::time::Duration,
        expired: impl Fn(&[u8]) -> bool,
    ) {
        self.retain_fresh_inner(now, ttl, Some(&expired));
    }

    /// Shared body. `expired = None` → age-only (skip the cold value-scan);
    /// `Some(f)` → also drop entries whose value satisfies `f` (full scan).
    fn retain_fresh_inner(
        &mut self,
        now: Instant,
        ttl: std::time::Duration,
        expired: Option<&ValuePredicate<'_>>,
    ) {
        // Hot tier retain — accumulate per-key freed bytes so we can
        // adjust per-origin counters once the iteration finishes.
        let mut freed_hot_keys: Vec<([u8; 32], u64)> = Vec::new();
        self.hot.retain(|key, (value, order_ts, first_seen)| {
            let value_expired = expired.map(|f| f(value)).unwrap_or(false);
            // Age from `first_seen`: the whole point of splitting the stamps is
            // that a tier move must not buy a record another full lifetime.
            let keep = now.duration_since(*first_seen) < ttl && !value_expired;
            if !keep {
                self.hot_order.remove(&(*order_ts, *key));
                freed_hot_keys.push((*key, value.len() as u64));
            }
            keep
        });
        let mut freed_hot: u64 = 0;
        for (key, bytes) in &freed_hot_keys {
            freed_hot = freed_hot.saturating_add(*bytes);
            if let Some(origin) = self.entry_origin.remove(key)
                && let Some(slot) = self.origin_bytes.get_mut(&origin)
            {
                *slot = slot.saturating_sub(*bytes);
                if *slot == 0 {
                    self.origin_bytes.remove(&origin);
                }
            }
        }
        self.total_bytes = self.total_bytes.saturating_sub(freed_hot);
        // Apply both filters to the cold tier.  Both `retain` methods return
        // the removed `(key, byte_len)` pairs, so we attribute freed bytes to
        // the global + per-origin counters from the delta directly — NO
        // before/after `iter_entries` materialization (audit U2: that loaded
        // the entire RocksDB on-disk value set into process RAM twice per
        // cleanup tick, under the inner lock, negating the disk tier's purpose).
        // The two removed-lists are disjoint: `retain` runs first (by value),
        // then `retain_newer_than` removes by age from what survives.
        // Value-based cold-tier scan ONLY when a value-predicate is supplied.
        // For the age-only path (`expired == None`) we skip it entirely —
        // otherwise `cold.retain` materializes the whole disk value set into
        // RAM for a scan that would keep everything (audit cycle-8).
        let mut removed_cold: Vec<([u8; 32], u64)> = match expired {
            Some(f) => self.cold.retain(&|_k, v| !f(v)),
            None => Vec::new(),
        };
        if let Some(cutoff) = now.checked_sub(ttl) {
            removed_cold.extend(self.cold.retain_newer_than(cutoff));
            // A backend's own stamp is when the entry was DEMOTED — it has no
            // idea when the record was first seen, and a durable one keeps no
            // stamp at all. So age the cold tier by what we kept for it: an
            // entry demoted a moment ago can still be long past its lifetime,
            // and before this it simply outlived the sweep (report12 V-M7).
            let stale: Vec<[u8; 32]> = self
                .cold_first_seen
                .iter()
                .filter(|(_, first)| **first < cutoff)
                .map(|(k, _)| *k)
                .collect();
            for key in stale {
                // Only the stale keys' sizes are read, never the whole tier —
                // the materialization audit U2 warns about is a full scan.
                let bytes = self.value_bytes(&key);
                // Counted as freed only if it really went. A delete that
                // failed leaves the record on disk AND its stamp in place, so
                // the next sweep tries again rather than forgetting an entry
                // it can no longer age (report14 V14-M4).
                // Zero bytes on purpose: the subtraction for this tier happens
                // once below, from `removed_cold`, and doing it here as well
                // would take the value off the total twice.
                if self.release_cold(&key, 0, now).0 {
                    removed_cold.push((key, bytes));
                }
            }
        }
        let mut freed_cold: u64 = 0;
        for (key, bytes) in &removed_cold {
            self.cold_first_seen.remove(key);
            freed_cold = freed_cold.saturating_add(*bytes);
            if let Some(origin) = self.entry_origin.remove(key)
                && let Some(slot) = self.origin_bytes.get_mut(&origin)
            {
                *slot = slot.saturating_sub(*bytes);
                if *slot == 0 {
                    self.origin_bytes.remove(&origin);
                }
            }
        }
        self.total_bytes = self.total_bytes.saturating_sub(freed_cold);
    }

    /// Insert into hot, demoting oldest to cold if full.
    ///
    /// Demotion is attempted ONCE. If the cold tier refuses (a failing disk),
    /// the demoted value goes back to hot and this insert takes the tier one
    /// entry over its soft capacity — which is the right way round: an
    /// over-full hot tier is a bounded overshoot that the next successful
    /// demotion corrects, and a dropped DHT value is not recoverable at all
    /// (audit V-08).
    fn insert_hot(&mut self, key: [u8; 32], value: Vec<u8>, ts: Instant, first_seen: Instant) {
        if self.hot.len() >= self.hot_capacity {
            self.demote_oldest_hot();
        }
        // Account for the new bytes (total_bytes invariant: sum of all
        // values across both tiers).  Caller must NOT have already
        // inserted into hot when calling this — invariant enforced by
        // private visibility and call-sites that come through put_at.
        self.total_bytes = self.total_bytes.saturating_add(value.len() as u64);
        self.hot.insert(key, (value, ts, first_seen));
        self.hot_order.insert((ts, key), ());
    }

    /// Demote the oldest hot entry to cold.  total_bytes is unchanged
    /// (bytes move from hot to cold) UNLESS cold's internal eviction
    /// kicks in, in which case the returned evicted entry's bytes are
    /// subtracted from the running total and its per-origin slot is
    /// decremented.
    fn demote_oldest_hot(&mut self) {
        if let Some(&(ts, key)) = self.hot_order.keys().next()
            && let Some(entry) = self.hot.remove(&key)
        {
            self.hot_order.remove(&(ts, key));
            let first_seen = entry.2;
            // WHO published it and HOW OLD it is go down WITH the value, in one
            // operation. Both were separate writes after the value's: the
            // per-origin counters live in memory, so a restart handed every
            // publisher a fresh allowance while its rows were still on disk
            // (report14 V14-L3); `first_seen` is an `Instant` that dies with
            // the process, so a restart aged every cold entry from zero and
            // handed it another full lifetime (report14 V14-L2). Three writes
            // meant a crash between them could leave the value with neither —
            // charged to nobody, aged from the moment it is read back
            // (report16 V16-M4).
            let origin = self.entry_origin.get(&key).copied();
            let age = Instant::now().saturating_duration_since(first_seen);
            let unix_now = veil_util::unix_secs_now_u64();
            let first_seen_unix = unix_now.saturating_sub(age.as_secs());
            match self
                .cold
                .put_with_side(key, entry.0, origin, Some(first_seen_unix))
            {
                ColdPut::Stored(evicted) => {
                    // The cold tier only knows when it was DEMOTED, so without
                    // this a promotion hands the record a fresh lifetime and a
                    // tier move became a way to outlive the retention its
                    // publisher asked for.
                    self.cold_first_seen.insert(key, first_seen);
                    if let Some((evicted_key, evicted_val)) = evicted {
                        self.account_eviction(&evicted_key, evicted_val.len() as u64);
                    }
                }
                ColdPut::Failed(value) => {
                    // The cold tier did not take it, so it goes back where it
                    // came from. Removing from hot BEFORE the cold write meant
                    // a failed write lost the value from both tiers, while
                    // `total_bytes` went on counting it (audit V-08).
                    //
                    // Restored under its ORIGINAL timestamp: it is not a new
                    // entry, and re-dating it would make it the last thing
                    // demotion tries again rather than the first.
                    log::warn!("dht.demote: cold tier refused the value; keeping it hot");
                    self.hot.insert(key, (value, ts, first_seen));
                    self.hot_order.insert((ts, key), ());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_get() {
        let mut store = TieredStore::new(2, 2);
        store.put([1u8; 32], b"hello".to_vec());
        assert_eq!(store.get(&[1u8; 32]).unwrap(), b"hello");
        assert_eq!(store.hot_len(), 1);
    }

    #[test]
    fn hot_overflow_demotes_to_cold() {
        let mut store = TieredStore::new(2, 10);
        store.put([1u8; 32], b"a".to_vec());
        store.put([2u8; 32], b"b".to_vec());
        store.put([3u8; 32], b"c".to_vec()); // demotes [1] to cold
        assert_eq!(store.hot_len(), 2);
        assert_eq!(store.cold_len(), 1);
        // [1] is still accessible (promoted back to hot on access).
        assert_eq!(store.get(&[1u8; 32]).unwrap(), b"a");
    }

    #[test]
    fn cold_overflow_evicts() {
        let mut store = TieredStore::new(1, 1);
        store.put([1u8; 32], b"a".to_vec());
        store.put([2u8; 32], b"b".to_vec()); // [1] → cold
        store.put([3u8; 32], b"c".to_vec()); // [2] → cold, [1] evicted from cold
        assert_eq!(store.len(), 2);
        assert!(store.get(&[1u8; 32]).is_none()); // fully evicted
    }

    #[test]
    fn remove_from_both_tiers() {
        let mut store = TieredStore::new(1, 10);
        store.put([1u8; 32], b"a".to_vec());
        store.put([2u8; 32], b"b".to_vec()); // [1] → cold
        store.remove(&[1u8; 32]);
        assert_eq!(store.len(), 1);
        assert!(store.get(&[1u8; 32]).is_none());
    }

    #[test]
    fn promotion_on_access() {
        let mut store = TieredStore::new(1, 10);
        store.put([1u8; 32], b"a".to_vec());
        store.put([2u8; 32], b"b".to_vec()); // [1] → cold
        assert_eq!(store.cold_len(), 1);
        store.get(&[1u8; 32]); // promote [1] back to hot, demote [2]
        assert_eq!(store.hot_len(), 1);
        assert!(store.hot.contains_key(&[1u8; 32]));
    }

    /// report12 V-M7, the other half: a tier move must not hand the record
    /// another full lifetime.
    ///
    /// The stamp `hot_order` sorts by is re-dated on promotion — it has to be,
    /// or a record read up from cold is the very next thing demoted and
    /// promotion buys nothing. When that was also the stamp the TTL measured,
    /// every promotion reset the record's age, and a node that keeps looking a
    /// key up keeps it alive past whatever its publisher asked for.
    #[test]
    fn a_promotion_does_not_buy_the_record_another_lifetime() {
        use std::time::Duration;

        let now = Instant::now();
        // Stored in the PAST, because the promotion stamps the real clock: an
        // entry put at `now` and promoted a microsecond later is the same age
        // either way, and the test cannot tell the two apart. An earlier
        // version did exactly that and passed against the defect.
        let Some(long_ago) = now.checked_sub(Duration::from_secs(600)) else {
            eprintln!("skipped: the clock has no past to place the entry in");
            return;
        };

        let mut store = TieredStore::new(1, 10);
        store.put_at([1u8; 32], b"a".to_vec(), long_ago);
        store.put_at([2u8; 32], b"b".to_vec(), long_ago); // [1] → cold
        assert_eq!(store.cold_len(), 1);

        // Read it back up. The promotion re-dates it for ORDER, which is what
        // used to re-date it for age as well.
        assert!(store.get(&[1u8; 32]).is_some());
        assert!(store.is_hot(&[1u8; 32]), "the fixture failed to promote it");

        // Sweeping everything older than a minute. Both entries are ten
        // minutes old; only a reset age would save one.
        store.retain_fresh_age_only(now, Duration::from_secs(60));
        assert!(
            store.get_no_promote(&[2u8; 32]).is_none(),
            "the never-moved entry of the same age survived, so the sweep is \
             not doing what the rest of this test assumes"
        );
        assert!(
            store.get_no_promote(&[1u8; 32]).is_none(),
            "the record outlived its ttl by being read: the promotion reset its age"
        );
    }

    /// report12 V-M7: the read that answers a REMOTE FIND_VALUE must leave the
    /// entry where it is. `promotion_on_access` above pins the opposite for our
    /// own lookups, and both are wanted — the difference is who asked.
    #[test]
    fn a_non_promoting_read_leaves_both_tiers_alone() {
        let mut store = TieredStore::new(1, 10);
        store.put([1u8; 32], b"a".to_vec());
        store.put([2u8; 32], b"b".to_vec()); // [1] → cold
        assert_eq!(store.cold_len(), 1);

        assert_eq!(
            store.get_no_promote(&[1u8; 32]),
            Some(b"a".to_vec()),
            "a cold entry must still be answerable"
        );
        assert_eq!(store.cold_len(), 1, "reading it must not promote it");
        assert!(
            store.hot.contains_key(&[2u8; 32]),
            "and must not demote whatever was hot to make room"
        );
        assert_eq!(
            store.get_no_promote(&[2u8; 32]),
            Some(b"b".to_vec()),
            "a hot entry reads the same way"
        );
        assert_eq!(store.hot_len(), 1);
    }

    /// report6 V-M1: a snapshot must carry provenance and remaining lifetime
    /// across both tiers, and a restore must honour both.
    ///
    /// `(key, value)` alone loses two facts the store knows and cannot
    /// re-derive. Everything used to come back as `ORIGIN_INTERNAL` — which is
    /// exempt from the per-origin byte cap — with a full fresh TTL, so a
    /// restart laundered a capped origin's bytes into the uncapped bucket and
    /// reset the clock on values that were one minute from expiring.
    #[test]
    fn snapshot_meta_carries_origin_and_age_and_restore_honours_them() {
        let origin_a = [0xA1u8; 32];
        let origin_b = [0xB2u8; 32];
        // hot_capacity 1 so the first entry is demoted into the cold tier —
        // the snapshot must describe BOTH tiers, not just the hot one.
        let mut store = TieredStore::new(1, 8);
        let t0 = Instant::now();
        assert!(store.put_with_origin_at([1u8; 32], vec![1u8; 40], origin_a, t0));
        assert!(store.put_with_origin_at([2u8; 32], vec![2u8; 40], origin_b, t0));
        assert_eq!(store.cold_len(), 1, "fixture: one entry demoted to cold");

        // Snapshot taken two hours later. Ages come out at ~7200 s: the cold
        // entry's clock starts at DEMOTION rather than at the original put, so
        // it lags by the microseconds between the two — which is exactly the
        // age the store itself uses to evict it, and therefore the age the
        // snapshot must report.
        let snap_at = t0 + Duration::from_secs(7200);
        let snap = store.iter_with_meta(snap_at);
        assert_eq!(snap.len(), 2, "both tiers must appear in the snapshot");
        for e in &snap {
            let expected = if e.key == [1u8; 32] {
                origin_a
            } else {
                origin_b
            };
            assert_eq!(e.origin, expected, "provenance lost for {:?}", e.key);
            assert!(
                (7199..=7200).contains(&e.age.as_secs()),
                "age lost for {:?} ({:?}) — a restore would hand it a fresh TTL",
                e.key,
                e.age,
            );
        }

        // Restore into a fresh store at the moment the snapshot was taken.
        let mut restored = TieredStore::new(1, 8);
        let restore_at = snap_at;
        for e in &snap {
            assert!(restored.put_restored(e.key, e.value.clone(), e.origin, e.age, restore_at));
        }

        // Provenance: the bytes land under the recorded origins, not in the
        // uncapped internal bucket.
        assert_eq!(restored.origin_bytes.get(&origin_a).copied(), Some(40));
        assert_eq!(restored.origin_bytes.get(&origin_b).copied(), Some(40));
        assert!(
            !restored.origin_bytes.contains_key(&ORIGIN_INTERNAL),
            "restored entries were laundered into the uncapped internal origin",
        );

        // Lifetime: with a one-hour TTL both entries are already two hours old
        // at `restore_at`, so the very next cleanup must drop them. Under the
        // old behaviour they would have come back with a full hour left.
        restored.retain_fresh_age_only(restore_at, Duration::from_secs(3600));
        assert_eq!(
            restored.len(),
            0,
            "restored entries kept a fresh TTL — restarting resets the clock",
        );
    }

    /// audit cycle-7 M4: `iter_keys` returns every key from both tiers without
    /// materializing values, and `peek` reads a cold-tier value WITHOUT
    /// promoting it (so the republish driver, which touches every due key each
    /// interval, never churns the hot/cold boundary).
    #[test]
    fn iter_keys_and_peek_are_non_promoting_m4() {
        let mut store = TieredStore::new(1, 10);
        store.put([1u8; 32], b"hot-then-cold".to_vec());
        store.put([2u8; 32], b"hot".to_vec()); // [1] → cold, [2] stays hot
        assert_eq!(store.hot_len(), 1);
        assert_eq!(store.cold_len(), 1);

        // iter_keys sees both tiers.
        let mut keys = store.iter_keys();
        keys.sort_unstable();
        assert_eq!(keys, vec![[1u8; 32], [2u8; 32]]);

        // peek of the COLD key returns the value but does NOT promote it.
        assert_eq!(
            store.peek(&[1u8; 32]).as_deref(),
            Some(&b"hot-then-cold"[..])
        );
        assert_eq!(store.hot_len(), 1, "peek must not promote cold → hot");
        assert_eq!(store.cold_len(), 1, "cold entry stays cold after peek");
        assert!(
            !store.hot.contains_key(&[1u8; 32]),
            "[1] must remain in cold tier"
        );

        // missing key → None; hot key still readable.
        assert_eq!(store.peek(&[9u8; 32]), None);
        assert_eq!(store.peek(&[2u8; 32]).as_deref(), Some(&b"hot"[..]));
    }

    /// audit U1: a cold→hot promotion MUST be byte-neutral. Before the fix,
    /// `get` did `cold.remove` (no decrement) + `insert_hot` (+len), so
    /// `total_bytes` drifted upward on every promotion and spuriously tripped
    /// the byte-cap eviction loop.
    #[test]
    fn promotion_is_byte_neutral_u1() {
        let mut store = TieredStore::new(1, 10);
        store.put([1u8; 32], vec![0u8; 100]);
        store.put([2u8; 32], vec![0u8; 100]); // [1] demoted to cold
        let baseline = store.total_bytes();
        assert_eq!(baseline, 200, "two 100-byte values");
        // Repeated promote→re-demote cycles must not change the total.
        for _ in 0..5 {
            store.get(&[1u8; 32]); // promote [1] (demotes [2])
            store.get(&[2u8; 32]); // promote [2] (demotes [1])
            assert_eq!(
                store.total_bytes(),
                baseline,
                "total_bytes must be invariant across cold→hot promotions"
            );
        }
    }

    // ── Byte-cap (audit batch 2026-05-23) ─────────────────────────────

    /// Sanity check: `total_bytes` tracks puts and removes incrementally.
    #[test]
    fn total_bytes_tracks_put_and_remove() {
        let mut store = TieredStore::new(2, 10);
        assert_eq!(store.total_bytes(), 0);
        store.put([1u8; 32], vec![0u8; 100]);
        assert_eq!(store.total_bytes(), 100);
        store.put([2u8; 32], vec![0u8; 250]);
        assert_eq!(store.total_bytes(), 350);
        // Overwrite [1] with a smaller value — counter must reflect the delta.
        store.put([1u8; 32], vec![0u8; 30]);
        assert_eq!(store.total_bytes(), 280);
        store.remove(&[1u8; 32]);
        assert_eq!(store.total_bytes(), 250);
        store.remove(&[2u8; 32]);
        assert_eq!(store.total_bytes(), 0);
    }

    /// `with_max_bytes` evicts oldest entries until a new value fits.
    #[test]
    fn byte_cap_evicts_oldest_until_new_value_fits() {
        // Hot/cold capacities generous — only the byte cap should bite.
        let mut store = TieredStore::new(8, 8).with_max_bytes(300);
        store.put([1u8; 32], vec![0u8; 100]); // total 100
        store.put([2u8; 32], vec![0u8; 100]); // total 200
        store.put([3u8; 32], vec![0u8; 100]); // total 300 (at cap)
        assert_eq!(store.total_bytes(), 300);
        // Inserting another 100-byte entry must evict [1] (oldest).
        store.put([4u8; 32], vec![0u8; 100]);
        assert!(
            store.total_bytes() <= 300,
            "byte total must stay at or under cap; got {}",
            store.total_bytes()
        );
        assert!(
            store.get(&[1u8; 32]).is_none(),
            "oldest entry must be evicted"
        );
        assert!(
            store.get(&[4u8; 32]).is_some(),
            "newest entry must be present"
        );
    }

    /// New value that alone exceeds the cap is refused outright — store
    /// state preserved.
    #[test]
    fn byte_cap_refuses_oversized_value() {
        let mut store = TieredStore::new(8, 8).with_max_bytes(100);
        store.put([1u8; 32], vec![0u8; 50]);
        assert_eq!(store.total_bytes(), 50);
        // Trying to insert a 200-byte value when cap is 100 must fail.
        store.put([2u8; 32], vec![0u8; 200]);
        assert!(
            store.get(&[2u8; 32]).is_none(),
            "oversized put must be refused"
        );
        assert_eq!(
            store.total_bytes(),
            50,
            "store state must be unchanged on refused put"
        );
        assert!(store.get(&[1u8; 32]).is_some(), "existing entry preserved");
    }

    /// A refused put must not be destructive — including when it REPLACES an
    /// existing key.
    ///
    /// The test above uses a fresh key, so it never reached the case that
    /// mattered: the removal of the incumbent ran BEFORE the cap check, so
    /// offering an oversized replacement deleted what was there and then
    /// returned `false`.  A caller reading that answer as "the store is
    /// unchanged" had already lost the value (report16 V16-L2).
    #[test]
    fn refused_oversized_replacement_keeps_the_incumbent() {
        let mut store = TieredStore::new(8, 8).with_max_bytes(100);
        store.put([1u8; 32], vec![7u8; 50]);

        let accepted = store.put_with_origin([1u8; 32], vec![9u8; 200], ORIGIN_INTERNAL);

        assert!(!accepted, "premise: the oversized value must be refused");
        assert_eq!(
            store.get(&[1u8; 32]).map(|v| v.to_vec()),
            Some(vec![7u8; 50]),
            "a refused put deleted the value it failed to replace"
        );
        assert_eq!(store.total_bytes(), 50, "accounting followed the deletion");
    }

    /// The same rule for the other refusal: a per-origin cap that rejects a
    /// replacement must leave the incumbent alone too.
    #[test]
    fn refused_over_origin_cap_replacement_keeps_the_incumbent() {
        let mut store = TieredStore::new(8, 8).with_per_origin_max_bytes(100);
        let origin = [3u8; 32];
        assert!(
            store.put_with_origin([1u8; 32], vec![7u8; 50], origin),
            "premise: the first put fits"
        );

        let accepted = store.put_with_origin([1u8; 32], vec![9u8; 200], origin);

        assert!(!accepted, "premise: the replacement must be refused");
        assert_eq!(
            store.get(&[1u8; 32]).map(|v| v.to_vec()),
            Some(vec![7u8; 50]),
            "a refused put deleted the value it failed to replace"
        );
    }

    /// Vacuity guard: an oversized value must still be REFUSED, and an
    /// ordinary replacement must still go through.  Refusing to mutate is only
    /// correct for the puts that are actually refused.
    #[test]
    fn an_accepted_replacement_still_replaces() {
        let mut store = TieredStore::new(8, 8).with_max_bytes(100);
        store.put([1u8; 32], vec![7u8; 50]);

        assert!(store.put_with_origin([1u8; 32], vec![9u8; 60], ORIGIN_INTERNAL));

        assert_eq!(
            store.get(&[1u8; 32]).map(|v| v.to_vec()),
            Some(vec![9u8; 60]),
            "the new value never landed"
        );
        assert_eq!(store.total_bytes(), 60, "the old bytes were never released");
    }

    /// Updating an existing key uses the delta semantics — already-counted
    /// bytes are released before the cap check.
    #[test]
    fn byte_cap_overwrite_respects_delta() {
        let mut store = TieredStore::new(8, 8).with_max_bytes(200);
        store.put([1u8; 32], vec![0u8; 150]);
        // Overwriting [1] with a 200-byte value should succeed (releases the
        // 150 already counted, then inserts 200 — fits in cap).
        store.put([1u8; 32], vec![0u8; 200]);
        assert_eq!(store.total_bytes(), 200);
        assert_eq!(store.get(&[1u8; 32]).map(|v| v.len()), Some(200));
    }

    /// `retain_fresh` must subtract evicted bytes from `total_bytes`.
    #[test]
    fn retain_fresh_updates_total_bytes() {
        let mut store = TieredStore::new(2, 10);
        store.put([1u8; 32], vec![0u8; 100]);
        store.put([2u8; 32], vec![0u8; 100]); // [1] → cold
        assert_eq!(store.total_bytes(), 200);
        // Force-evict everything via a TTL of 1 ns.
        store.retain_fresh(Instant::now(), std::time::Duration::from_nanos(1), |_| {
            false
        });
        assert_eq!(
            store.total_bytes(),
            0,
            "all bytes accounted for after retain_fresh"
        );
        assert_eq!(store.hot_len(), 0);
        assert_eq!(store.cold_len(), 0);
    }

    // ── Per-origin byte cap (Phase 11e) ────────────────────────────────

    /// Per-origin tracking accumulates bytes by signer id.
    #[test]
    fn origin_bytes_tracks_puts_by_signer() {
        let mut store = TieredStore::new(8, 8);
        let alice = [0x11u8; 32];
        let bob = [0x22u8; 32];
        assert_eq!(store.origin_bytes(&alice), 0);
        store.put_with_origin([1u8; 32], vec![0u8; 100], alice);
        store.put_with_origin([2u8; 32], vec![0u8; 200], alice);
        store.put_with_origin([3u8; 32], vec![0u8; 50], bob);
        assert_eq!(store.origin_bytes(&alice), 300);
        assert_eq!(store.origin_bytes(&bob), 50);
        assert_eq!(store.total_bytes(), 350);
    }

    /// Per-origin cap refuses a put that would push the signer past the
    /// budget — other signers stay unaffected.
    #[test]
    fn per_origin_cap_refuses_noisy_signer() {
        let mut store = TieredStore::new(8, 8).with_per_origin_max_bytes(250);
        let noisy = [0x11u8; 32];
        let polite = [0x22u8; 32];
        assert!(store.put_with_origin([1u8; 32], vec![0u8; 100], noisy));
        assert!(store.put_with_origin([2u8; 32], vec![0u8; 100], noisy));
        // [3] @ 100 bytes would put noisy at 300 > cap 250 — refused.
        assert!(!store.put_with_origin([3u8; 32], vec![0u8; 100], noisy));
        assert_eq!(store.origin_bytes(&noisy), 200, "noisy state preserved");
        // Polite signer with a full 250-byte put still succeeds — caps
        // are per-origin not shared.
        assert!(store.put_with_origin([4u8; 32], vec![0u8; 250], polite));
        assert_eq!(store.origin_bytes(&polite), 250);
    }

    /// Overwriting an existing key by the SAME origin refunds the
    /// previous bytes before the cap check.
    #[test]
    fn per_origin_cap_overwrite_refunds_prior_bytes() {
        let mut store = TieredStore::new(8, 8).with_per_origin_max_bytes(200);
        let alice = [0x11u8; 32];
        assert!(store.put_with_origin([1u8; 32], vec![0u8; 150], alice));
        // Overwriting [1] with 200 bytes: refunds 150, projects 200 → fits.
        assert!(store.put_with_origin([1u8; 32], vec![0u8; 200], alice));
        assert_eq!(store.origin_bytes(&alice), 200);
        assert_eq!(store.get(&[1u8; 32]).map(|v| v.len()), Some(200));
    }

    /// Removing entries decrements the per-origin counter.
    #[test]
    fn per_origin_bytes_decrement_on_remove() {
        let mut store = TieredStore::new(8, 8);
        let alice = [0x11u8; 32];
        store.put_with_origin([1u8; 32], vec![0u8; 100], alice);
        store.put_with_origin([2u8; 32], vec![0u8; 50], alice);
        assert_eq!(store.origin_bytes(&alice), 150);
        store.remove(&[1u8; 32]);
        assert_eq!(store.origin_bytes(&alice), 50);
        store.remove(&[2u8; 32]);
        assert_eq!(store.origin_bytes(&alice), 0);
    }

    /// `ORIGIN_INTERNAL` puts (e.g. `put` /  mailbox replication /
    /// republish) bypass the per-origin cap entirely.
    #[test]
    fn internal_origin_bypasses_cap() {
        let mut store = TieredStore::new(8, 8).with_per_origin_max_bytes(50);
        // Internal path — should accept 200 bytes despite a 50-byte cap.
        store.put([1u8; 32], vec![0u8; 200]);
        assert_eq!(store.total_bytes(), 200);
        assert!(store.get(&[1u8; 32]).is_some());
    }

    /// retain_fresh evictions update per-origin counters.
    #[test]
    fn retain_fresh_updates_origin_bytes() {
        let mut store = TieredStore::new(8, 8);
        let alice = [0x11u8; 32];
        store.put_with_origin([1u8; 32], vec![0u8; 100], alice);
        store.put_with_origin([2u8; 32], vec![0u8; 100], alice);
        assert_eq!(store.origin_bytes(&alice), 200);
        // Evict everything with a TTL of 1 ns.
        store.retain_fresh(Instant::now(), std::time::Duration::from_nanos(1), |_| {
            false
        });
        assert_eq!(store.origin_bytes(&alice), 0);
        assert_eq!(store.total_bytes(), 0);
    }

    /// Unsigned-origin (legacy STOREs) shares a single bucket — fills
    /// collectively und hits the cap as a group.
    #[test]
    fn unsigned_origin_shares_single_bucket() {
        let mut store = TieredStore::new(8, 8).with_per_origin_max_bytes(150);
        // Three "different" anonymous STOREs all share ORIGIN_UNSIGNED.
        assert!(store.put_with_origin([1u8; 32], vec![0u8; 50], ORIGIN_UNSIGNED));
        assert!(store.put_with_origin([2u8; 32], vec![0u8; 50], ORIGIN_UNSIGNED));
        assert!(store.put_with_origin([3u8; 32], vec![0u8; 50], ORIGIN_UNSIGNED));
        // 4th 50-byte unsigned put: 150 + 50 = 200 > 150 → refused.
        assert!(!store.put_with_origin([4u8; 32], vec![0u8; 50], ORIGIN_UNSIGNED));
        assert_eq!(store.origin_bytes(&ORIGIN_UNSIGNED), 150);
    }

    /// cold tier entries must be evicted by age in `retain_fresh`
    /// not only by the `expired(value)` predicate.
    #[test]
    fn retain_fresh_evicts_old_cold_entries() {
        let mut store = TieredStore::new(1, 10);
        // Insert a value; it goes to hot.
        store.put([1u8; 32], b"old".to_vec());
        // Push it down to cold by inserting another.
        store.put([2u8; 32], b"new".to_vec());
        assert_eq!(store.cold_len(), 1);
        assert_eq!(store.hot_len(), 1);

        // Backdate the cold entry's insertion timestamp so it appears old.
        // We cheat by downcasting via the order map since we own the struct.
        // Replace the cold backend contents directly through its public API:
        // re-insert with the same key but shift the internal timestamp.
        // Simpler: verify behaviour with a TTL=0 eviction.
        store.retain_fresh(Instant::now(), std::time::Duration::from_nanos(1), |_| {
            false
        });
        // Hot and cold entries both older than 1ns → both evicted.
        assert_eq!(store.hot_len(), 0);
        assert_eq!(
            store.cold_len(),
            0,
            "cold entry older than TTL must be evicted"
        );
    }

    // ── build_tiered_store / cold-tier selection ────────────────────

    /// `build_tiered_store(.., None)` is exactly the historical in-memory
    /// tiered store: hot overflow demotes to the in-memory cold map.
    #[test]
    fn build_tiered_store_none_is_in_memory_tiered() {
        let mut store = build_tiered_store(1, 10, None);
        store.put([1u8; 32], b"a".to_vec());
        store.put([2u8; 32], b"b".to_vec()); // demotes [1] to in-memory cold
        assert_eq!(store.hot_len(), 1);
        assert_eq!(store.cold_len(), 1);
        assert_eq!(
            store.get(&[1u8; 32]).map(|v| v.as_slice()),
            Some(b"a".as_slice())
        );
    }

    /// U2: `cold_is_durable()` + `iter_hot()` drive the values-snapshot
    /// hot-only optimisation. The in-memory cold tier is volatile (NOT
    /// durable), so a snapshot must span both tiers; `iter_hot()` returns only
    /// the hot entry while `iter()` returns both.
    #[test]
    fn in_memory_cold_not_durable_and_iter_hot_excludes_cold() {
        let mut store = build_tiered_store(1, 10, None);
        store.put([1u8; 32], b"a".to_vec());
        store.put([2u8; 32], b"b".to_vec()); // demotes [1] to in-memory cold
        assert!(
            !store.cold_is_durable(),
            "in-memory cold tier must report not-durable"
        );
        assert_eq!(store.iter().len(), 2, "iter() spans both tiers");
        let hot = store.iter_hot();
        assert_eq!(hot.len(), 1, "iter_hot() returns only the hot tier");
        assert_eq!(hot[0].0, [2u8; 32], "the newest entry is the hot one");
    }

    /// U2: the RocksDB cold tier reports durable, so the values snapshot can
    /// safely skip it — it persists across restart by itself (see
    /// `rocksdb_cold_tier_persists_across_reopen`), and re-serialising it every
    /// 120 s would defeat the disk tier.
    /// report15 V15-M4: an entry's origin and its first-seen stamp outlived
    /// the value.
    ///
    /// No delete path touched the side column families — not ordinary removal,
    /// not entry-cap eviction, not expiry. `forget_origin` and
    /// `forget_first_seen` exist and were called from one promotion path only.
    /// So unique-key churn grew two column families that no cap counts and no
    /// sweep visits, and after a restart those rows are what the quota and the
    /// TTL are computed from.
    /// report16 V16-M4: the value and its two side rows go down together.
    ///
    /// The three VALUE rows were already atomic; the origin and the first-seen
    /// stamp went afterwards as two independent writes. A crash between them
    /// left a value charged to nobody and aged from the moment it is read
    /// back — the quota and the TTL both computed from what is on disk after a
    /// restart.
    ///
    /// Atomicity across a crash cannot be shown from inside the process. What
    /// CAN be, and is the property the fix is: one operation carries all
    /// three, so there is no window between them for anything to observe.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn a_value_and_its_side_rows_are_one_operation() {
        use super::rocks::RocksDbCold;

        let dir = tempfile::tempdir().unwrap();
        let mut cold =
            RocksDbCold::open(dir.path().join("cold").to_str().unwrap(), 0).expect("open");

        let key = [7u8; 32];
        let put = cold.put_with_side(key, b"value".to_vec(), Some([3u8; 32]), Some(1_700_000_000));

        assert!(matches!(put, ColdPut::Stored(_)));
        assert_eq!(
            cold.side_row_count(),
            (1, 1),
            "the side rows did not travel with the value"
        );
        assert_eq!(
            cold.origins().unwrap().first().map(|o| o.1),
            Some([3u8; 32])
        );
        assert_eq!(
            cold.first_seen_all().unwrap().first().map(|(_, s)| *s),
            Some(1_700_000_000)
        );
    }

    /// And an overwrite by a publisher this node cannot name does not leave
    /// the previous one charged for it.
    ///
    /// The side write was skipped when there was no origin to write, so the
    /// row from the value that USED to be at that key stayed — and the quota
    /// went on charging somebody for bytes that are not theirs.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn an_unattributed_overwrite_does_not_inherit_the_previous_publisher() {
        use super::rocks::RocksDbCold;

        let dir = tempfile::tempdir().unwrap();
        let mut cold =
            RocksDbCold::open(dir.path().join("cold").to_str().unwrap(), 0).expect("open");

        let key = [7u8; 32];
        cold.put_with_side(key, b"first".to_vec(), Some([3u8; 32]), Some(1_700_000_000));
        assert_eq!(cold.side_row_count(), (1, 1), "premise");

        // The same key, written by nobody this node can name.
        cold.put_with_side(key, b"second".to_vec(), None, None);

        assert_eq!(
            cold.side_row_count(),
            (0, 0),
            "the previous publisher is still charged for a value that is no \
             longer theirs, and the new value inherited the old age"
        );
        assert_eq!(cold.get(&key).as_deref(), Some(b"second".as_slice()));
    }

    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn deleting_an_entry_takes_its_origin_and_age_with_it() {
        use super::rocks::RocksDbCold;

        let dir = tempfile::tempdir().unwrap();
        let mut cold =
            RocksDbCold::open(dir.path().join("cold").to_str().unwrap(), 0).expect("open");

        let key = [9u8; 32];
        cold.put(key, b"value".to_vec());
        cold.set_origin(&key, &[1u8; 32]);
        cold.set_first_seen(&key, 1_700_000_000);

        // Counted DIRECTLY. `origins()` and every other reader skip a row
        // whose value is gone — deliberately, because such a row describes
        // nothing and must not charge anybody — so the leak was invisible to
        // all of them while the files grew. A first version of this test
        // asserted through `origins()` and passed against the defect.
        assert_eq!(
            cold.side_row_count(),
            (1, 1),
            "the side rows were never written, so what follows proves nothing"
        );

        // Through the trait, which is what every caller uses.
        cold.remove(&key);
        assert!(!cold.contains(&key), "the value is still there");

        assert_eq!(
            cold.side_row_count(),
            (0, 0),
            "an origin or first-seen row outlived the value it describes; \
             nothing counts them and no sweep visits them"
        );
    }

    /// report17 V17-L2: a delete the backend could not perform forgot the
    /// entry's age, and the value on disk then became invisible to the sweep.
    ///
    /// The in-memory stamp was dropped BEFORE the delete was attempted. The
    /// trait reports a failed delete as nothing at all, so the value stayed —
    /// and the cold half of the age sweep walks `cold_first_seen`, which no
    /// longer had it. Nothing ages it, nothing evicts it, and it comes back at
    /// every restart. `release_cold` already kept the stamp on a failed
    /// delete; `remove` did not.
    #[test]
    fn a_delete_that_failed_keeps_the_age_it_will_be_swept_by() {
        #[derive(Debug, Default)]
        struct Inner {
            entries: HashMap<[u8; 32], Vec<u8>>,
            fail_deletes: bool,
        }
        #[derive(Debug, Clone, Default)]
        struct FlakyCold(std::sync::Arc<std::sync::Mutex<Inner>>);
        impl FlakyCold {
            fn disk(&self) -> std::sync::MutexGuard<'_, Inner> {
                self.0.lock().unwrap_or_else(|p| p.into_inner())
            }
        }
        impl ColdBackend for FlakyCold {
            fn get(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
                self.disk().entries.get(key).cloned()
            }
            fn put(&mut self, key: [u8; 32], value: Vec<u8>) -> ColdPut {
                self.disk().entries.insert(key, value);
                ColdPut::Stored(None)
            }
            fn remove(&mut self, key: &[u8; 32]) {
                let mut d = self.disk();
                if !d.fail_deletes {
                    d.entries.remove(key);
                }
            }
            fn contains(&self, key: &[u8; 32]) -> bool {
                self.disk().entries.contains_key(key)
            }
            fn len(&self) -> usize {
                self.disk().entries.len()
            }
            fn iter_entries(&self) -> Vec<([u8; 32], Vec<u8>)> {
                self.disk()
                    .entries
                    .iter()
                    .map(|(k, v)| (*k, v.clone()))
                    .collect()
            }
            fn retain(&mut self, _f: &dyn Fn(&[u8; 32], &[u8]) -> bool) -> Vec<([u8; 32], u64)> {
                Vec::new()
            }
        }

        let disk = FlakyCold::default();
        // Hot capacity 1: the second put demotes the first into cold, which is
        // where the stamp is written.
        let mut store = TieredStore::with_cold(1, Box::new(disk.clone()));
        let doomed = [1u8; 32];
        store.put(doomed, b"value".to_vec());
        store.put([2u8; 32], b"other".to_vec());
        assert!(store.contains(&doomed), "premise: the value is in cold");

        // The disk refuses the delete, exactly as a RocksDB error looks from
        // above.
        disk.disk().fail_deletes = true;
        store.remove(&doomed);
        assert!(
            store.contains(&doomed),
            "the fixture stopped modelling a failed delete, so this test is \
             about nothing"
        );

        // The disk recovers, and the sweep runs well past the lifetime.
        disk.disk().fail_deletes = false;
        let ttl = std::time::Duration::from_secs(1);
        store.retain_fresh_age_only(Instant::now() + ttl * 10, ttl);

        assert!(
            !store.contains(&doomed),
            "the value outlived its lifetime on disk because the sweep had no \
             age for it: the stamp was dropped when the delete failed, and \
             nothing ages an entry it cannot see"
        );
    }

    /// report17 V17-L1: the DEFAULT `put_with_side` forgot an origin nobody
    /// named and kept a first-seen stamp nobody offered.
    ///
    /// The RocksDB override already cleared both, so this was a trap for the
    /// next durable backend rather than a live defect — and a trap of the
    /// worst kind, because what it produces is a value that ages from
    /// whenever the PREVIOUS value at that key was first seen. Under a
    /// ten-minute lifetime that is a record swept while it is new.
    ///
    /// Driven through the default implementation on purpose: a backend that
    /// stores the two side facts and does NOT override the batched write is
    /// exactly the shape the trait is meant to serve.
    #[test]
    fn the_default_side_write_clears_both_facts_when_neither_is_offered() {
        #[derive(Debug, Default)]
        struct PlainCold {
            entries: std::collections::HashMap<[u8; 32], Vec<u8>>,
            origin: std::collections::HashMap<[u8; 32], [u8; 32]>,
            first_seen: std::collections::HashMap<[u8; 32], u64>,
        }
        impl ColdBackend for PlainCold {
            fn put(&mut self, key: [u8; 32], value: Vec<u8>) -> ColdPut {
                self.entries.insert(key, value);
                ColdPut::Stored(None)
            }
            fn get(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
                self.entries.get(key).cloned()
            }
            fn remove(&mut self, key: &[u8; 32]) {
                self.entries.remove(key);
            }
            fn contains(&self, key: &[u8; 32]) -> bool {
                self.entries.contains_key(key)
            }
            fn len(&self) -> usize {
                self.entries.len()
            }
            fn iter_entries(&self) -> Vec<([u8; 32], Vec<u8>)> {
                self.entries.iter().map(|(k, v)| (*k, v.clone())).collect()
            }
            fn retain(&mut self, _f: &dyn Fn(&[u8; 32], &[u8]) -> bool) -> Vec<([u8; 32], u64)> {
                Vec::new()
            }
            fn set_origin(&mut self, key: &[u8; 32], origin: &[u8; 32]) {
                self.origin.insert(*key, *origin);
            }
            fn forget_origin(&mut self, key: &[u8; 32]) {
                self.origin.remove(key);
            }
            fn set_first_seen(&mut self, key: &[u8; 32], unix_secs: u64) {
                self.first_seen.insert(*key, unix_secs);
            }
            fn forget_first_seen(&mut self, key: &[u8; 32]) {
                self.first_seen.remove(key);
            }
        }

        let mut cold = PlainCold::default();
        let key = [7u8; 32];
        cold.put_with_side(
            key,
            b"first".to_vec(),
            Some([0xAA; 32]),
            Some(1_700_000_000),
        );
        assert_eq!(cold.origin.len(), 1, "premise: both facts were written");
        assert_eq!(cold.first_seen.len(), 1, "premise: both facts were written");

        // The same key again, by a publisher this node cannot name and with no
        // stamp to offer.
        cold.put_with_side(key, b"second".to_vec(), None, None);

        assert!(
            cold.origin.is_empty(),
            "the previous publisher is still charged for a value that is no \
             longer theirs"
        );
        assert!(
            cold.first_seen.is_empty(),
            "the new value inherited the age of whatever was here before it, \
             so a fresh record is swept as though it were old"
        );
    }

    /// report17 V17-M3: a put could evict the value it had just written, and
    /// report it as "stored, nothing evicted".
    ///
    /// The ts-index key is `ts_secs(8) ‖ key(32)`, so entries written in the
    /// same second are ordered BY KEY. A low key arriving at a full tier is
    /// therefore "the oldest" the moment it lands — the cap evicts it, the
    /// guard `ev_key != key` swallowed the event on the stated reasoning that
    /// it cannot happen, and the caller went on believing it holds a value
    /// that is no longer on disk: its bytes stay on the global and per-origin
    /// counters and its first-seen stamp stays in the sweep's map.
    ///
    /// One wall-clock second is all the collision needs, and a DHT node under
    /// load writes many entries a second.
    /// Overwriting a key already on disk is not a reason to drop somebody
    /// else's entry.
    ///
    /// The cap is a count of ENTRIES, and an overwrite adds none: the pre-insert
    /// eviction is guarded by "is this key already here" for that reason. That
    /// guard was carrying no test — removing it left all 207 of them green —
    /// while what it prevents is a plain overwrite at capacity silently
    /// deleting an unrelated value and leaving the tier one entry short.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn overwriting_a_key_already_here_evicts_nobody() {
        use super::rocks::RocksDbCold;

        let dir = tempfile::tempdir().unwrap();
        let cap = 3usize;
        let mut cold =
            RocksDbCold::open(dir.path().join("cold").to_str().unwrap(), cap).expect("open");

        let keys: Vec<[u8; 32]> = [0x11u8, 0x22, 0x33]
            .iter()
            .map(|lead| {
                let mut k = [0u8; 32];
                k[0] = *lead;
                cold.put(k, vec![*lead; 32]);
                k
            })
            .collect();
        assert_eq!(cold.len(), cap, "premise: the tier is full");

        let put = cold.put(keys[0], b"second thoughts".to_vec());

        assert!(
            matches!(put, ColdPut::Stored(None)),
            "an overwrite reported an eviction: {put:?}"
        );
        assert_eq!(cold.len(), cap, "the tier lost an entry to an overwrite");
        for k in &keys {
            assert!(
                cold.contains(k),
                "an overwrite of one key dropped another: {k:02x?}"
            );
        }
        assert_eq!(
            cold.get(&keys[0]).as_deref(),
            Some(b"second thoughts".as_slice()),
            "the overwrite itself did not land"
        );
    }

    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn a_put_never_evicts_the_value_it_just_wrote() {
        use super::rocks::RocksDbCold;

        let dir = tempfile::tempdir().unwrap();
        let cap = 3usize;
        let mut cold =
            RocksDbCold::open(dir.path().join("cold").to_str().unwrap(), cap).expect("open");

        // Three high keys first, then a low one — the shape from the report.
        for lead in [0x03u8, 0x04, 0x05] {
            let mut key = [0u8; 32];
            key[0] = lead;
            cold.put(key, vec![lead; 32]);
        }
        let mut newcomer = [0u8; 32];
        newcomer[0] = 0x01;
        let put = cold.put(newcomer, b"the newcomer".to_vec());

        // It is THERE. Whatever the cap did, it did not do it to this value.
        assert!(
            cold.contains(&newcomer),
            "the put evicted the value it had just written"
        );
        assert_eq!(
            cold.get(&newcomer).as_deref(),
            Some(b"the newcomer".as_slice()),
        );

        // And what came back names the entry that actually left, so the
        // caller's byte counters follow the disk.
        match put {
            ColdPut::Stored(Some((ev_key, _))) => assert_ne!(
                ev_key, newcomer,
                "the eviction reported was of the value just stored"
            ),
            ColdPut::Stored(None) => panic!(
                "a full tier took a new entry and reported no eviction: \
                 something left the disk that nobody was told about"
            ),
            ColdPut::Failed(_) => panic!("the put failed"),
        }
        assert_eq!(cold.len(), cap, "the cap was not held");
    }

    /// report17 V17-M2: EVICTION dropped the value and kept the entry's
    /// origin and first-seen stamp.
    ///
    /// The delete path was fixed for V15-M4 and the eviction path was not, so
    /// under unique-key churn the logical entry count sits at the cap forever
    /// while two column families nothing counts and nothing sweeps grow
    /// without bound. Nothing reads those rows — every reader skips a row
    /// whose value is gone — so the only symptom is a database that keeps
    /// growing on a node whose entry count never moves.
    ///
    /// Counted DIRECTLY for that reason: a version of this asserted through
    /// `origins()` would pass against the defect.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn evicting_an_entry_takes_its_origin_and_age_with_it() {
        use super::rocks::RocksDbCold;

        let dir = tempfile::tempdir().unwrap();
        // Capacity one, so the second put evicts the first.
        let mut cold =
            RocksDbCold::open(dir.path().join("cold").to_str().unwrap(), 1).expect("open");

        let first = [1u8; 32];
        cold.put_with_side(
            first,
            b"first".to_vec(),
            Some([0xAA; 32]),
            Some(1_700_000_000),
        );
        assert_eq!(
            cold.side_row_count(),
            (1, 1),
            "the side rows were never written, so what follows proves nothing"
        );

        // Through `evict_oldest`, which is what the entry cap and the byte cap
        // both call.
        let evicted = cold.evict_oldest().expect("something to evict");
        assert_eq!(evicted.0, first, "the wrong entry was evicted");
        assert!(!cold.contains(&first), "the value survived its eviction");

        assert_eq!(
            cold.side_row_count(),
            (0, 0),
            "an evicted entry left its origin and first-seen stamp behind: \
             unique-key churn then grows two uncounted column families while \
             the entry count stays at the cap"
        );
    }

    /// And the same over the CAP, not the primitive: a node taking unique keys
    /// forever holds its entry count at N with nothing accumulating beside it.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn churn_at_the_entry_cap_leaves_nothing_behind() {
        use super::rocks::RocksDbCold;

        let dir = tempfile::tempdir().unwrap();
        let cap = 4usize;
        let mut cold =
            RocksDbCold::open(dir.path().join("cold").to_str().unwrap(), cap).expect("open");

        for i in 0..64u8 {
            let mut key = [0u8; 32];
            key[0] = i;
            cold.put_with_side(
                key,
                vec![i; 64],
                Some([i; 32]),
                Some(1_700_000_000 + u64::from(i)),
            );
        }

        let (origins, first_seen) = cold.side_row_count();
        assert!(
            origins <= cap && first_seen <= cap,
            "sixty-four unique keys through a cap of {cap} left {origins} \
             origin rows and {first_seen} first-seen rows on disk"
        );
    }

    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn rocksdb_cold_reports_durable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cold-durable");
        let store = build_tiered_store(4, 16, Some(path.to_str().unwrap()));
        assert!(
            store.cold_is_durable(),
            "RocksDB cold tier must report durable"
        );
    }

    /// `build_tiered_store(.., Some(path))` returns a working store whether
    /// or not the `rocksdb-cold` feature is compiled in. With the feature it
    /// opens a real RocksDB; without it the helper logs and falls back to the
    /// in-memory cold tier. Either way put/get must round-trip — the daemon
    /// never goes down because a cold path was configured.
    #[test]
    fn build_tiered_store_some_path_round_trips_regardless_of_feature() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cold");
        let mut store = build_tiered_store(4, 16, Some(path.to_str().unwrap()));
        store.put([7u8; 32], b"v".to_vec());
        assert_eq!(
            store.get(&[7u8; 32]).map(|v| v.as_slice()),
            Some(b"v".as_slice())
        );
    }

    /// The defining property of the disk cold tier: an entry demoted to the
    /// RocksDB cold store survives dropping and reopening the store at the
    /// same path. The hot tier is RAM-only, so it does NOT persist — which is
    /// exactly why a node that wants warm hot-tier state on restart also sets
    /// `values_persist_path`.
    ///
    /// We do not assert on `cold_len()` here: RocksDB reports an *estimate*
    /// derived from SST properties that reads 0 for a freshly-written memtable
    /// before flush. Persistence is proven behaviorally via the reopen `get`.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn rocksdb_cold_tier_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dht-cold");
        let path_str = path.to_str().unwrap();

        let k_cold = [1u8; 32]; // demoted to the RocksDB cold tier
        let k_hot = [2u8; 32]; // stays in the RAM-only hot tier

        // hot_capacity = 1 → the second put demotes the first entry to cold.
        {
            let mut store = build_tiered_store(1, 1000, Some(path_str));
            store.put(k_cold, b"persist-me".to_vec());
            store.put(k_hot, b"ram-only".to_vec()); // demotes k_cold → RocksDB
            assert_eq!(store.hot_len(), 1, "only the newest entry stays hot");
            // Do NOT `get(k_cold)` — that would promote it back out of cold.
            // store drops here → rocksdb::DB closes and flushes its WAL.
        }

        // Reopen at the same path.
        {
            let mut store = build_tiered_store(1, 1000, Some(path_str));
            assert_eq!(
                store.get(&k_cold).map(|v| v.as_slice()),
                Some(b"persist-me".as_slice()),
                "cold-tier entry must survive a store reopen (disk persistence)"
            );
            assert_eq!(
                store.get(&k_hot),
                None,
                "hot-tier entry was RAM-only and must not persist"
            );
        }
    }

    /// Audit cycle-8: `retain_fresh_age_only` must evict purely by age across
    /// both tiers and leave value-fresh entries intact — identical end-state to
    /// `retain_fresh(.., |_| false)` but without the cold-tier value scan.
    #[test]
    fn retain_fresh_age_only_evicts_by_age_both_tiers() {
        let mut store = TieredStore::new(1, 100); // hot_cap 1 → demotion to cold
        store.put([1u8; 32], b"aaaa".to_vec()); // → cold on next put
        store.put([2u8; 32], b"bbbb".to_vec()); // demotes [1]; [2] hot
        assert_eq!(store.total_bytes(), 8);
        // TTL of 1ns → both entries (hot + cold) are older → all evicted.
        store.retain_fresh_age_only(Instant::now(), std::time::Duration::from_nanos(1));
        assert_eq!(store.hot_len(), 0, "hot entry evicted by age");
        assert_eq!(store.cold_len(), 0, "cold entry evicted by age");
        assert_eq!(store.total_bytes(), 0, "byte counter reconciled");
        // Fresh entries (large TTL) survive.
        store.put([3u8; 32], b"cccc".to_vec());
        store.retain_fresh_age_only(Instant::now(), std::time::Duration::from_secs(3600));
        assert_eq!(store.total_bytes(), 4, "fresh entry retained");
    }

    /// Audit cycle-8: `total_bytes` must be re-seeded from the persisted disk
    /// tier on reopen, so the global byte-cap accounts for already-stored data
    /// instead of starting at 0 and drifting across restarts.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn rocksdb_cold_seeds_total_bytes_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dht-cold-bytes");
        let path_str = path.to_str().unwrap();
        let val = b"twelve-bytes".to_vec(); // 12 bytes
        let n = val.len() as u64;

        // hot_capacity 1 so each put demotes the previous entry to the cold
        // (disk) tier; only the LAST entry stays in the RAM-only hot tier.
        {
            let mut store = build_tiered_store(1, 1000, Some(path_str));
            store.put([1u8; 32], val.clone()); // hot
            store.put([2u8; 32], val.clone()); // [1] → cold(disk), [2] hot
            store.put([3u8; 32], val.clone()); // [2] → cold(disk), [3] hot
            assert_eq!(store.total_bytes(), 3 * n, "all three counted live");
        } // drop → flush; only [1] and [2] are on disk ([3] was hot/RAM-only).

        // Reopen: hot tier is empty; the 2 demoted values live on disk.
        // total_bytes must reflect exactly those persisted bytes (pre-cycle-8
        // it would be 0 here — the drift bug).
        {
            let store = build_tiered_store(1, 1000, Some(path_str));
            assert_eq!(
                store.total_bytes(),
                2 * n,
                "total_bytes must be seeded from the 2 persisted disk entries on reopen"
            );
        }
    }

    /// audit cycle-6 (T5-B): the RocksDB cold tier now enforces the entry cap
    /// via the side timestamp index — `put` evicts the oldest when over
    /// capacity, and the exact count stays bounded (previously the cap was a
    /// no-op on this path).
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn rocksdb_cold_entry_cap_evicts_oldest() {
        use super::ColdBackend;
        let dir = tempfile::tempdir().unwrap();
        let mut cold = super::rocks::RocksDbCold::open(dir.path().join("c"), 3).unwrap();
        for i in 1u8..=5 {
            cold.put([i; 32], vec![i; 8]);
        }
        assert_eq!(cold.len(), 3, "entry count must stay at the cap (3)");
        // The newest key is never the first evicted.
        assert!(cold.contains(&[5u8; 32]), "newest entry must survive");
        // Total present == cap.
        let present = (1u8..=5).filter(|i| cold.contains(&[*i; 32])).count();
        assert_eq!(present, 3);
    }

    /// audit cycle-6 (T5-B): `evict_oldest` returns entries oldest-first and
    /// keeps the maintained count in sync; empty store → None.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn rocksdb_cold_evict_oldest_drains_and_counts() {
        use super::ColdBackend;
        let dir = tempfile::tempdir().unwrap();
        let mut cold = super::rocks::RocksDbCold::open(dir.path().join("c"), 0).unwrap();
        cold.put([1u8; 32], b"a".to_vec());
        cold.put([2u8; 32], b"b".to_vec());
        assert_eq!(cold.len(), 2);
        assert!(cold.evict_oldest().is_some());
        assert_eq!(cold.len(), 1);
        assert!(cold.evict_oldest().is_some());
        assert_eq!(cold.len(), 0);
        assert!(cold.evict_oldest().is_none(), "empty store evicts nothing");
    }

    /// audit report5: a SINGLE dangling ts-index row — index row present, its
    /// value gone — used to switch eviction off for the whole cold tier. The
    /// dangling row sorts oldest, and `evict_oldest` answered `None` on it
    /// (the `?` on the value lookup) instead of stepping over it, so every
    /// later call re-read the same row and gave up again.
    ///
    /// Asserted positively: eviction must PROCEED and hand back exactly the
    /// entries it owes, oldest-first — "no error" would pass on the bug,
    /// whose whole signature is doing nothing quietly.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn rocksdb_cold_evict_oldest_steps_over_a_dangling_index_row() {
        use super::ColdBackend;
        let dir = tempfile::tempdir().unwrap();
        let mut cold = super::rocks::RocksDbCold::open(dir.path().join("c"), 0).unwrap();
        cold.put([1u8; 32], b"one".to_vec());
        cold.put([2u8; 32], b"two".to_vec());
        cold.put([3u8; 32], b"three".to_vec());
        // ts = 1 (1970) sorts strictly ahead of every real row's wall clock.
        cold.plant_dangling_index_row(1, &[9u8; 32]);
        assert_eq!(
            cold.ts_index_row_count(),
            4,
            "fixture: 3 live rows + 1 dangling"
        );

        assert_eq!(
            cold.evict_oldest(),
            Some(([1u8; 32], b"one".to_vec())),
            "eviction must step over the dangling row and return the real oldest"
        );
        assert_eq!(cold.len(), 2, "the maintained count follows the eviction");
        assert!(!cold.contains(&[1u8; 32]), "the evicted value is gone");
        // Deleted, not merely walked past: 4 − 1 dangling − 1 evicted = 2.
        assert_eq!(
            cold.ts_index_row_count(),
            2,
            "the dangling row must be removed, not re-walked on every call"
        );

        // The rest of the tier still drains, in order, to empty.
        assert_eq!(cold.evict_oldest(), Some(([2u8; 32], b"two".to_vec())));
        assert_eq!(cold.evict_oldest(), Some(([3u8; 32], b"three".to_vec())));
        assert_eq!(cold.evict_oldest(), None, "drained tier evicts nothing");
        assert_eq!(cold.len(), 0);
        assert_eq!(cold.ts_index_row_count(), 0, "index drained with the tier");
    }

    /// audit report5, the same defect seen where it hurts: with cold eviction
    /// frozen by one dangling index row, `TieredStore`'s byte-cap loop falls
    /// straight through to the hot tier and drops a hot entry on every put,
    /// while the over-full cold tier sits untouched. The node degenerates into
    /// an almost-empty hot tier in front of a frozen cold one.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn dangling_index_row_does_not_make_the_byte_cap_eat_the_hot_tier() {
        use super::ColdBackend;
        let dir = tempfile::tempdir().unwrap();
        let mut cold = super::rocks::RocksDbCold::open(dir.path().join("c"), 0).unwrap();
        for i in 1u8..=4 {
            cold.put([i; 32], vec![i; 10]);
        }
        cold.plant_dangling_index_row(1, &[9u8; 32]);

        // hot_capacity 8 → no demotion; cap 25 → the third 10-byte put must
        // free room, and the cold tier is where it has to come from.
        let mut store = TieredStore::with_cold(8, Box::new(cold)).with_max_bytes(25);
        store.put([100u8; 32], vec![0u8; 10]);
        store.put([101u8; 32], vec![0u8; 10]);
        store.put([102u8; 32], vec![0u8; 10]);

        assert_eq!(
            store.hot_len(),
            3,
            "all three hot entries survive — the bytes come out of cold"
        );
        assert_eq!(store.cold_len(), 3, "exactly one cold entry was evicted");
        assert!(
            !store.contains(&[1u8; 32]),
            "and it is the OLDEST cold entry, not an arbitrary one"
        );
        for i in 2u8..=4 {
            assert!(store.contains(&[i; 32]), "younger cold entries stay");
        }
    }

    /// audit cycle-6 (T5-B): overwriting a key re-indexes it (drops the stale
    /// ts-index entry) and must NOT double-count.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn rocksdb_cold_overwrite_does_not_double_count() {
        use super::ColdBackend;
        let dir = tempfile::tempdir().unwrap();
        let mut cold = super::rocks::RocksDbCold::open(dir.path().join("c"), 0).unwrap();
        cold.put([1u8; 32], b"v1".to_vec());
        cold.put([1u8; 32], b"v2".to_vec());
        assert_eq!(cold.len(), 1, "overwrite must not double-count");
        assert_eq!(cold.get(&[1u8; 32]).as_deref(), Some(b"v2".as_slice()));
        // remove decrements; the count survives a reopen (seeded from CF_KEY_TS).
        cold.remove(&[1u8; 32]);
        assert_eq!(cold.len(), 0);
    }

    /// report6 V-M2: `iter_keys` must read the ts-index, never the value CF.
    ///
    /// The republish driver calls it once a second while holding the DHT mutex.
    /// Iterating the value CF and dropping each value looks free but is not —
    /// RocksDB materializes every value into the iterator first, so the whole
    /// cold tier was read off disk every second to hand back 32 bytes an entry.
    ///
    /// A value planted with no index rows is the observable difference between
    /// the two implementations: the value CF has it, the ts-index does not. It
    /// is unreachable in production (put and delete write all three rows in one
    /// WriteBatch, and `reconcile` adopts any pre-batch leftovers at open), so
    /// it serves purely as a probe for WHICH family the scan walks.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn rocksdb_cold_iter_keys_reads_the_index_not_the_values() {
        use super::ColdBackend;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c");
        let mut cold = super::rocks::RocksDbCold::open(&path, 0).unwrap();

        cold.put([1u8; 32], b"indexed-a".to_vec());
        cold.put([2u8; 32], b"indexed-b".to_vec());
        // Value CF only — no reverse-map row, no ts-index row.
        cold.plant_unindexed_value(&[3u8; 32], b"value-cf-only");

        let keys = cold.iter_keys();
        assert_eq!(
            keys.len(),
            2,
            "iter_keys must report the indexed set: {keys:?}"
        );
        assert!(keys.contains(&[1u8; 32]) && keys.contains(&[2u8; 32]));
        assert!(
            !keys.contains(&[3u8; 32]),
            "iter_keys walked the value column family — that scan reads every \
             value off disk before discarding it",
        );

        // And it stays in step with the tier: a delete drops the key, an
        // overwrite does not duplicate it.
        cold.put([1u8; 32], b"indexed-a-v2".to_vec());
        cold.remove(&[2u8; 32]);
        let keys = cold.iter_keys();
        assert_eq!(keys, vec![[1u8; 32]], "after overwrite + delete: {keys:?}");
    }

    /// audit report5: a torn put leaves a GHOST — the value landed, its two
    /// index rows did not. `get` serves it and `iter_entries` publishes it,
    /// but no eviction path can reach it and no byte counter knows about it,
    /// because the open scan only ever walked the reverse map and never
    /// enumerated the values. Reconciliation adopts it.
    ///
    /// The side CFs exist before this value is planted, which is exactly what
    /// makes it a ghost rather than a grandfathered pre-index value.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn rocksdb_cold_open_adopts_a_ghost_value() {
        use super::ColdBackend;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c");
        {
            let mut cold = super::rocks::RocksDbCold::open(&path, 0).unwrap();
            cold.put([1u8; 32], b"indexed".to_vec()); // 7 bytes
            cold.plant_unindexed_value(&[2u8; 32], b"ghost-value"); // 11 bytes
            assert_eq!(
                cold.len(),
                1,
                "fixture: the ghost is invisible to the count"
            );
        }

        let mut cold = super::rocks::RocksDbCold::open(&path, 0).unwrap();
        assert_eq!(cold.len(), 2, "the ghost must be adopted into the index");
        assert_eq!(
            cold.cold_total_bytes(),
            Some(18),
            "and its bytes must reach the restart byte seed"
        );
        assert_eq!(cold.reverse_map_row_count(), 2);
        assert_eq!(cold.ts_index_row_count(), 2);

        // The point of adoption: the value becomes reachable by eviction at
        // all. Drain the tier and require the ghost among the evicted.
        let mut evicted: Vec<[u8; 32]> = Vec::new();
        while let Some((key, _)) = cold.evict_oldest() {
            evicted.push(key);
        }
        assert_eq!(evicted.len(), 2, "the whole tier drains");
        assert!(
            evicted.contains(&[2u8; 32]),
            "the adopted ghost is evictable now"
        );
        assert_eq!(cold.len(), 0);
    }

    /// report21 V21-L3: a read that FAILED is not a read that said "absent".
    ///
    /// Every repair in this tier is a DELETE decided by a read — an orphan, a
    /// dangling row, a victim to evict — and each of them folded an I/O error
    /// into "the value is not there". One transient failure therefore took the
    /// index away from a value that was perfectly alive: nothing counts it,
    /// nothing evicts it, the byte and entry caps stop seeing it, and only the
    /// next successful open notices.
    ///
    /// The absence side is covered by the tests around this one, which plant
    /// real orphans and real danglers and require them repaired. What cannot
    /// be reached from a test is the ERROR side: RocksDB has no supported way
    /// to make a read fail on demand, and a fixture that corrupted an SST
    /// would fail the open rather than the read. So this asserts the shape
    /// that keeps the two apart.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn a_read_that_failed_is_not_a_value_that_is_gone() {
        let src = include_str!("store.rs");
        let rocks = src
            .split("pub mod rocks {")
            .nth(1)
            .and_then(|t| t.split("\n#[cfg(test)]").next())
            .expect("the rocksdb backend");

        // The staging helpers hand the error back rather than answering with
        // a bool that cannot tell the two apart.
        assert!(
            rocks.contains("        ) -> Result<bool, rocksdb::Error> {"),
            "a staging helper answers a failed read with a bool again, so the \
             caller cannot tell 'not indexed' from 'could not look'"
        );

        // Reconciliation keeps a verdict on whether it saw the whole tier, and
        // discards its repairs when it did not.
        assert!(
            rocks.contains("let mut readable = true;"),
            "reconciliation no longer tracks whether it could read the tier"
        );
        assert!(
            rocks.contains("if !readable {") && rocks.contains("return (count, summed);"),
            "reconciliation applies its repairs on a partial picture: a value \
             it could not read is deleted from the index as an orphan"
        );

        // And nothing in the repair paths turns an error into absence by
        // catch-all. `Ok(None)` is written out where a decision to delete is
        // taken, so an `Err` cannot arrive there by falling through.
        for banned in [
            "self.db.get(key).ok().flatten().map(|v| (key, v))",
            "match db.get_pinned(key) {\n                    Ok(Some(value)) => {",
        ] {
            assert!(
                !rocks.contains(banned),
                "a repair path folds a failed read into absence again: {banned}"
            );
        }
        // The eviction scan abstains instead of repairing on an error.
        let evict = rocks
            .split("fn stage_evict_oldest")
            .nth(1)
            .and_then(|t| t.split("\n        /// ").next())
            .expect("the eviction scan");
        assert!(
            evict.contains("Ok(None) => dangling.push(ix_key),"),
            "the eviction scan no longer separates a value that is gone from \
             one it could not read"
        );
        assert_eq!(
            evict.matches("return None;").count(),
            3,
            "the eviction scan has stopped abstaining on one of its three \
             read failures, and abstaining is what stops it deleting the index \
             of a live value"
        );
    }

    /// audit report5: the mirror state — index rows for a value that is not
    /// there. A reverse-map row whose value is gone made the open scan count a
    /// non-existent entry and add its CLAIMED byte length to the restart seed;
    /// a bare ts-index row is what used to freeze eviction for the whole tier.
    /// Reconciliation drops both.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn rocksdb_cold_open_drops_orphaned_and_dangling_index_rows() {
        use super::ColdBackend;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c");
        {
            let mut cold = super::rocks::RocksDbCold::open(&path, 0).unwrap();
            cold.put([1u8; 32], b"real".to_vec()); // 4 bytes
            // A torn delete: the value went, both index rows stayed, and the
            // reverse map claims 999 bytes for it.
            cold.plant_index_rows(1, &[2u8; 32], 999);
            // A half-torn delete: only the ts-index row survived.
            cold.plant_dangling_index_row(2, &[3u8; 32]);
            assert_eq!(cold.reverse_map_row_count(), 2);
            assert_eq!(cold.ts_index_row_count(), 3);
        }

        let cold = super::rocks::RocksDbCold::open(&path, 0).unwrap();
        assert_eq!(
            cold.len(),
            1,
            "an orphan is not an entry and must not count"
        );
        assert_eq!(
            cold.cold_total_bytes(),
            Some(4),
            "and its claimed 999 bytes must not reach the byte seed"
        );
        assert_eq!(
            cold.reverse_map_row_count(),
            1,
            "the orphaned reverse-map row is deleted"
        );
        assert_eq!(
            cold.ts_index_row_count(),
            1,
            "and so are both leftover ts-index rows"
        );
    }

    /// audit report5: the open scan summed the byte lengths the reverse map
    /// CLAIMED, so a recorded length that had drifted away from its value —
    /// or a legacy v1 row, which records no length at all — seeded the global
    /// byte cap with a number that was simply wrong. Reconciliation sums the
    /// actual values and rewrites the record, and drops the ts-index row the
    /// superseded reverse-map row used to point at.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn rocksdb_cold_open_repairs_a_drifted_length_and_its_stale_index_row() {
        use super::ColdBackend;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c");
        {
            let mut cold = super::rocks::RocksDbCold::open(&path, 0).unwrap();
            cold.put([1u8; 32], b"four".to_vec()); // really 4 bytes
            // Re-point the reverse map at ts 7 and claim 4096 bytes. The
            // original ts-index row is left behind, superseded.
            cold.plant_index_rows(7, &[1u8; 32], 4096);
            assert_eq!(cold.ts_index_row_count(), 2, "fixture: one row superseded");
        }

        for pass in 1..=2 {
            let cold = super::rocks::RocksDbCold::open(&path, 0).unwrap();
            assert_eq!(cold.len(), 1, "pass {pass}");
            assert_eq!(
                cold.cold_total_bytes(),
                Some(4),
                "pass {pass}: the seed comes from the value, not from the claim"
            );
            assert_eq!(
                cold.ts_index_row_count(),
                1,
                "pass {pass}: the superseded ts-index row is dropped"
            );
        }
    }

    /// audit report5: a logical put is three rows in three column families,
    /// and they used to be three independent writes of which only the first
    /// was checked — the other two warned to the log and the count was bumped
    /// regardless. They are one `WriteBatch` now, so "one of the three failed"
    /// is not a reachable state and what has to be proven is the remaining
    /// one: a failed write leaves NOTHING — no value, no index row, no count.
    ///
    /// The failure is real, not simulated: a read-only handle makes RocksDB
    /// itself refuse the write.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn rocksdb_cold_a_failed_write_leaves_no_ghost_and_no_count_drift() {
        use super::ColdBackend;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c");
        {
            let mut cold = super::rocks::RocksDbCold::open(&path, 0).unwrap();
            cold.put([1u8; 32], b"stored".to_vec()); // 6 bytes
        }
        {
            let mut cold = super::rocks::RocksDbCold::open_read_only(&path, 0).unwrap();
            assert_eq!(cold.len(), 1);
            let outcome = cold.put([2u8; 32], b"never".to_vec());
            assert!(
                matches!(&outcome, ColdPut::Failed(v) if v.as_slice() == b"never"),
                "a failed write must hand the value back, not report success: {outcome:?}"
            );
            assert_eq!(cold.len(), 1, "and must not bump the count");
            // The delete path is the same batch and the same rule.
            cold.remove(&[1u8; 32]);
            assert_eq!(cold.len(), 1, "a failed delete must not move the count");
        }

        let cold = super::rocks::RocksDbCold::open(&path, 0).unwrap();
        assert_eq!(
            cold.len(),
            1,
            "nothing was adopted on reopen, so the failed put left no ghost"
        );
        assert!(!cold.contains(&[2u8; 32]), "and no value");
        assert!(
            cold.contains(&[1u8; 32]),
            "the failed delete kept its value"
        );
        assert_eq!(cold.reverse_map_row_count(), 1);
        assert_eq!(cold.ts_index_row_count(), 1);
        assert_eq!(cold.cold_total_bytes(), Some(6));
    }

    /// report20 V18-M1: the eviction that makes room and the entry it makes
    /// room FOR are one durable write.
    ///
    /// They used to be two. Between them the victim was already off the disk
    /// while the newcomer was not yet on it, and the window has two ends: a
    /// crash there loses the old value to admit nothing, and a failed put
    /// returns `Failed` — dropping the victim from the return value — so the
    /// tier goes on charging bytes for a value it no longer holds and the
    /// byte cap evicts against a number that only grows.
    ///
    /// A successful put ends in the same state either way, so the end state
    /// proves nothing; the number of writes is the property.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn rocksdb_cold_an_eviction_travels_in_the_batch_of_the_entry_it_admits() {
        use super::ColdBackend;
        let dir = tempfile::tempdir().unwrap();
        let mut cold = super::rocks::RocksDbCold::open(dir.path().join("c"), 2).unwrap();
        cold.put([1u8; 32], b"one".to_vec());
        cold.put([2u8; 32], b"two".to_vec());
        assert_eq!(cold.len(), 2, "premise: the tier is at its cap");

        let before = cold.durable_write_count();
        let outcome = cold.put([3u8; 32], b"three".to_vec());
        let writes = cold.durable_write_count() - before;

        assert!(
            matches!(&outcome, super::ColdPut::Stored(Some(_))),
            "premise: this put had to evict to fit: {outcome:?}"
        );
        assert_eq!(
            writes, 1,
            "the eviction and the insertion reached the disk as {writes} \
             separate writes: everything between them is a state where the \
             victim is gone and the newcomer never arrived"
        );

        // And the tier is consistent afterwards, on disk as well as in memory.
        assert_eq!(cold.len(), 2);
        assert!(cold.contains(&[3u8; 32]), "the newcomer is stored");
        assert_eq!(cold.reverse_map_row_count(), 2);
        assert_eq!(cold.ts_index_row_count(), 2);
    }

    /// The return contract at the cap: a put that fails reports no eviction
    /// and leaves every victim in place.
    ///
    /// This one does NOT prove the atomicity — a read-only handle refuses
    /// both writes, so the two-batch code reaches the same end state. It pins
    /// the contract; the write count above is what pins them together.
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn rocksdb_cold_a_failed_put_evicts_nobody() {
        use super::ColdBackend;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c");
        {
            let mut cold = super::rocks::RocksDbCold::open(&path, 2).unwrap();
            cold.put([1u8; 32], b"one".to_vec());
            cold.put([2u8; 32], b"two".to_vec());
        }
        {
            let mut cold = super::rocks::RocksDbCold::open_read_only(&path, 2).unwrap();
            assert_eq!(cold.len(), 2, "premise: at the cap, so a put must evict");
            let outcome = cold.put([3u8; 32], b"three".to_vec());
            assert!(
                matches!(&outcome, super::ColdPut::Failed(v) if v.as_slice() == b"three"),
                "a refused disk must hand the value back: {outcome:?}"
            );
            assert_eq!(cold.len(), 2, "and must not move the count");
        }
        let cold = super::rocks::RocksDbCold::open(&path, 2).unwrap();
        assert!(
            cold.contains(&[1u8; 32]) && cold.contains(&[2u8; 32]),
            "the put failed, so nothing was evicted to make room for it"
        );
        assert!(!cold.contains(&[3u8; 32]));
        assert_eq!(cold.cold_total_bytes(), Some(6));
    }

    /// audit cycle-6 (T5-B): TTL eviction works end-to-end on the disk tier —
    /// `retain_newer_than` drops entries older than the cutoff. Uses a real
    /// wait of ~1.1s because the index stores wall-clock SECONDS (the only
    /// slow test; correctness of the second-granularity age path).
    #[cfg(feature = "rocksdb-cold")]
    #[test]
    fn rocksdb_cold_retain_newer_than_evicts_old() {
        use super::ColdBackend;
        let dir = tempfile::tempdir().unwrap();
        let mut cold = super::rocks::RocksDbCold::open(dir.path().join("c"), 0).unwrap();
        cold.put([1u8; 32], b"old".to_vec());
        // Cross a wall-clock second boundary so the entry's stored ts is < now.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let removed = cold.retain_newer_than(std::time::Instant::now());
        assert_eq!(removed.len(), 1, "the >1s-old entry must be evicted");
        assert_eq!(removed[0].0, [1u8; 32]);
        assert_eq!(cold.len(), 0);
        assert!(!cold.contains(&[1u8; 32]));
    }
}

#[cfg(test)]
mod v08_tests {
    use super::*;

    /// A cold tier that refuses everything, the way a full disk does.
    #[derive(Debug, Default)]
    struct RefusingCold {
        refusals: usize,
    }

    impl ColdBackend for RefusingCold {
        fn get(&self, _key: &[u8; 32]) -> Option<Vec<u8>> {
            None
        }
        fn put(&mut self, _key: [u8; 32], value: Vec<u8>) -> ColdPut {
            self.refusals += 1;
            ColdPut::Failed(value)
        }
        fn remove(&mut self, _key: &[u8; 32]) {}
        fn contains(&self, _key: &[u8; 32]) -> bool {
            false
        }
        fn len(&self) -> usize {
            0
        }
        fn iter_keys(&self) -> Vec<[u8; 32]> {
            Vec::new()
        }
        fn iter_entries(&self) -> Vec<([u8; 32], Vec<u8>)> {
            Vec::new()
        }
        fn retain(&mut self, _f: &dyn Fn(&[u8; 32], &[u8]) -> bool) -> Vec<([u8; 32], u64)> {
            Vec::new()
        }
    }

    /// A cold tier whose deletes fail: `remove` does nothing and `contains`
    /// goes on saying yes — which is exactly what a RocksDB whose `delete`
    /// returned an error looks like from above, because the trait has no way
    /// to report it.
    #[derive(Debug, Default)]
    struct UndeletableCold {
        entries: HashMap<[u8; 32], Vec<u8>>,
    }

    impl ColdBackend for UndeletableCold {
        fn get(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
            self.entries.get(key).cloned()
        }
        fn put(&mut self, key: [u8; 32], value: Vec<u8>) -> ColdPut {
            self.entries.insert(key, value);
            ColdPut::Stored(None)
        }
        fn remove(&mut self, _key: &[u8; 32]) {}
        fn contains(&self, key: &[u8; 32]) -> bool {
            self.entries.contains_key(key)
        }
        fn len(&self) -> usize {
            self.entries.len()
        }
        fn iter_entries(&self) -> Vec<([u8; 32], Vec<u8>)> {
            self.entries.iter().map(|(k, v)| (*k, v.clone())).collect()
        }
        fn retain(&mut self, _f: &dyn Fn(&[u8; 32], &[u8]) -> bool) -> Vec<([u8; 32], u64)> {
            Vec::new()
        }
    }

    /// A promotion whose cold delete failed leaves TWO copies, and both are
    /// counted.
    ///
    /// The subtraction here exists to cancel `insert_hot`'s re-add, so the
    /// promotion is byte-neutral — which is true only while the cold copy
    /// actually goes away. When it does not, the node holds the value in hot
    /// AND on disk while the counter believes it holds one: the disk copy is
    /// free, and it comes back at the next restart to be counted again
    /// (report14 V14-M4).
    #[test]
    fn a_promotion_whose_cold_delete_failed_counts_both_copies() {
        let mut store = TieredStore::with_cold(1, Box::new(UndeletableCold::default()));
        store.put([1u8; 32], vec![0u8; 100]);
        store.put([2u8; 32], vec![0u8; 10]); // demotes [1] into cold
        assert_eq!(store.total_bytes(), 110);

        // Promote it back. The cold backend says yes and does nothing.
        assert_eq!(store.get(&[1u8; 32]).map(|v| v.len()), Some(100));

        assert_eq!(
            store.total_bytes(),
            210,
            "the value is in hot and still on disk; counting one of them makes \
             the other free"
        );
        assert!(
            store.contains(&[1u8; 32]),
            "the fixture stopped modelling a failed delete, so this test is \
             about nothing"
        );
    }

    /// The same for the age sweep: an entry it could not delete must keep its
    /// stamp, or the next sweep has nothing left to age it by.
    #[test]
    fn an_expiry_sweep_that_could_not_delete_keeps_the_entry_accounted() {
        let mut store = TieredStore::with_cold(1, Box::new(UndeletableCold::default()));
        store.put([1u8; 32], vec![0u8; 100]);
        store.put([2u8; 32], vec![0u8; 10]); // demotes [1] into cold
        assert_eq!(store.total_bytes(), 110);

        // Everything is long past its lifetime.
        store.retain_fresh_age_only(Instant::now(), std::time::Duration::from_secs(0));

        assert!(
            store.contains(&[1u8; 32]),
            "the delete failed, so the value is still on disk"
        );
        assert_eq!(
            store.total_bytes(),
            100,
            "the hot entry went and the cold one did not; crediting bytes that \
             are still stored is what lets a failing disk open unlimited room \
             under the cap"
        );

        // And the sweep can still find it: a stamp dropped for an entry that
        // did not go is an entry nothing will ever age again.
        store.retain_fresh_age_only(Instant::now(), std::time::Duration::from_secs(0));
        assert_eq!(store.total_bytes(), 100);
    }

    /// A restart does not buy a record another lifetime.
    ///
    /// `first_seen` is an `Instant`, which dies with the process — so every
    /// cold entry came back aged zero and the expiry sweep started it over.
    /// The backend's own stamp cannot stand in for it: that one says when the
    /// entry was DEMOTED (report14 V14-L2).
    #[test]
    fn a_restart_does_not_reset_a_cold_entry_age() {
        #[derive(Debug, Default)]
        struct Disk {
            entries: HashMap<[u8; 32], Vec<u8>>,
            first_seen: HashMap<[u8; 32], u64>,
        }

        #[derive(Debug, Clone, Default)]
        struct StampingCold(std::sync::Arc<std::sync::Mutex<Disk>>);

        impl StampingCold {
            fn disk(&self) -> std::sync::MutexGuard<'_, Disk> {
                self.0.lock().unwrap_or_else(|p| p.into_inner())
            }
        }

        impl ColdBackend for StampingCold {
            fn get(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
                self.disk().entries.get(key).cloned()
            }
            fn put(&mut self, key: [u8; 32], value: Vec<u8>) -> ColdPut {
                self.disk().entries.insert(key, value);
                ColdPut::Stored(None)
            }
            fn remove(&mut self, key: &[u8; 32]) {
                self.disk().entries.remove(key);
            }
            fn contains(&self, key: &[u8; 32]) -> bool {
                self.disk().entries.contains_key(key)
            }
            fn len(&self) -> usize {
                self.disk().entries.len()
            }
            fn iter_entries(&self) -> Vec<([u8; 32], Vec<u8>)> {
                self.disk()
                    .entries
                    .iter()
                    .map(|(k, v)| (*k, v.clone()))
                    .collect()
            }
            fn retain(&mut self, _f: &dyn Fn(&[u8; 32], &[u8]) -> bool) -> Vec<([u8; 32], u64)> {
                Vec::new()
            }
            fn set_first_seen(&mut self, key: &[u8; 32], unix_secs: u64) {
                self.disk().first_seen.insert(*key, unix_secs);
            }
            fn forget_first_seen(&mut self, key: &[u8; 32]) {
                self.disk().first_seen.remove(key);
            }
            fn first_seen_all(&self) -> Option<Vec<([u8; 32], u64)>> {
                let disk = self.disk();
                Some(
                    disk.first_seen
                        .iter()
                        .filter(|(k, _)| disk.entries.contains_key(*k))
                        .map(|(k, t)| (*k, *t))
                        .collect(),
                )
            }
        }

        let disk = StampingCold::default();
        {
            // Hot capacity 1: the first value is demoted into cold by the
            // second, and demotion is where the stamp is written.
            let mut store = TieredStore::with_cold(1, Box::new(disk.clone()));
            store.put([1u8; 32], vec![0u8; 10]);
            store.put([2u8; 32], vec![0u8; 10]);
            assert!(store.contains(&[1u8; 32]));
        }

        // The record was first seen an hour ago. Backdate the stamp the way
        // the passage of time would.
        {
            let mut d = disk.disk();
            let stamped = veil_util::unix_secs_now_u64().saturating_sub(3600);
            for v in d.first_seen.values_mut() {
                *v = stamped;
            }
        }

        // Reopened: everything this session learned in memory is gone.
        let mut reopened = TieredStore::with_cold(1, Box::new(disk.clone()));
        reopened.retain_fresh_age_only(Instant::now(), std::time::Duration::from_secs(600));
        assert!(
            !reopened.contains(&[1u8; 32]),
            "a record an hour old under a ten-minute lifetime survived a \
             restart: the age was aged from zero, which is another full \
             lifetime for the price of restarting"
        );

        // And a record inside its lifetime is NOT swept, or the assertion
        // above would pass by deleting everything.
        let fresh = StampingCold::default();
        let mut store = TieredStore::with_cold(1, Box::new(fresh.clone()));
        store.put([3u8; 32], vec![0u8; 10]);
        store.put([4u8; 32], vec![0u8; 10]);
        drop(store);
        let mut reopened = TieredStore::with_cold(1, Box::new(fresh));
        reopened.retain_fresh_age_only(Instant::now(), std::time::Duration::from_secs(600));
        assert!(
            reopened.contains(&[3u8; 32]),
            "a record well inside its lifetime must survive"
        );
    }

    /// A backend that remembers publishers seeds the per-origin counters.
    ///
    /// They used to start empty however much was on disk, so a restart handed
    /// every publisher a fresh allowance while its rows were still there — the
    /// per-origin cap stopped applying across restarts, and only the global one
    /// stood (report14 V14-L3).
    #[test]
    fn a_restart_does_not_hand_a_publisher_a_fresh_allowance() {
        /// Shared so the test can open the SAME disk twice — which is what a
        /// restart is, and the only thing that exercises the seeding.
        #[derive(Debug, Default)]
        struct Disk {
            entries: HashMap<[u8; 32], Vec<u8>>,
            origins: HashMap<[u8; 32], [u8; 32]>,
        }

        #[derive(Debug, Clone, Default)]
        struct RememberingCold(std::sync::Arc<std::sync::Mutex<Disk>>);

        impl RememberingCold {
            fn disk(&self) -> std::sync::MutexGuard<'_, Disk> {
                self.0.lock().unwrap_or_else(|p| p.into_inner())
            }
        }

        impl ColdBackend for RememberingCold {
            fn get(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
                self.disk().entries.get(key).cloned()
            }
            fn put(&mut self, key: [u8; 32], value: Vec<u8>) -> ColdPut {
                self.disk().entries.insert(key, value);
                ColdPut::Stored(None)
            }
            fn remove(&mut self, key: &[u8; 32]) {
                self.disk().entries.remove(key);
            }
            fn contains(&self, key: &[u8; 32]) -> bool {
                self.disk().entries.contains_key(key)
            }
            fn len(&self) -> usize {
                self.disk().entries.len()
            }
            fn iter_entries(&self) -> Vec<([u8; 32], Vec<u8>)> {
                self.disk()
                    .entries
                    .iter()
                    .map(|(k, v)| (*k, v.clone()))
                    .collect()
            }
            fn retain(&mut self, _f: &dyn Fn(&[u8; 32], &[u8]) -> bool) -> Vec<([u8; 32], u64)> {
                Vec::new()
            }
            fn set_origin(&mut self, key: &[u8; 32], origin: &[u8; 32]) {
                self.disk().origins.insert(*key, *origin);
            }
            fn forget_origin(&mut self, key: &[u8; 32]) {
                self.disk().origins.remove(key);
            }
            fn origins(&self) -> Option<Vec<super::PersistedOrigin>> {
                let disk = self.disk();
                Some(
                    disk.origins
                        .iter()
                        .filter_map(|(k, o)| disk.entries.get(k).map(|v| (*k, *o, v.len() as u64)))
                        .collect(),
                )
            }
        }

        let publisher = [0xAAu8; 32];
        // Hot capacity 1, so the first value is demoted into cold by the
        // second — which is the path that writes the origin down.
        let disk = RememberingCold::default();
        let mut store =
            TieredStore::with_cold(1, Box::new(disk.clone())).with_per_origin_max_bytes(150);
        assert!(store.put_with_origin([1u8; 32], vec![0u8; 100], publisher));
        assert!(store.put_with_origin([2u8; 32], vec![0u8; 10], publisher));
        assert!(
            !store.put_with_origin([3u8; 32], vec![0u8; 100], publisher),
            "the publisher is at its quota, or this test is about nothing"
        );

        // The same disk, opened again. Everything this session learned in
        // memory is gone; what the backend remembers is all there is.
        drop(store);
        let mut reopened = TieredStore::with_cold(1, Box::new(disk)).with_per_origin_max_bytes(150);
        assert!(
            !reopened.put_with_origin([4u8; 32], vec![0u8; 100], publisher),
            "a restart must not hand a publisher a second allowance while its \
             rows are still on disk"
        );
    }

    /// audit report5: `TieredStore::remove` measured the cold value, told the
    /// backend to delete it, and subtracted the bytes — without ever asking
    /// whether the delete happened. It can fail, and the trait reports that
    /// with nothing at all, so the bytes came off `total_bytes` while the
    /// value stayed on disk. The next put of the same key reaches the same
    /// line and subtracts them AGAIN: repeat, and arbitrary room opens up
    /// under a global byte cap whose whole job is to bound the node's disk.
    #[test]
    fn a_cold_delete_that_failed_must_not_credit_its_bytes_back() {
        let mut store = TieredStore::with_cold(1, Box::new(UndeletableCold::default()));
        store.put([1u8; 32], vec![0u8; 100]);
        store.put([2u8; 32], vec![0u8; 10]); // demotes [1] into the cold tier
        assert_eq!(store.total_bytes(), 110);

        store.remove(&[1u8; 32]);
        assert!(
            store.contains(&[1u8; 32]),
            "the delete failed — the value is still there"
        );
        assert_eq!(
            store.total_bytes(),
            110,
            "bytes still on disk must still be counted"
        );

        // The compounding half: each further attempt used to shave off another
        // 100 until the counter hit zero with 110 bytes still stored.
        store.remove(&[1u8; 32]);
        store.remove(&[1u8; 32]);
        assert_eq!(
            store.total_bytes(),
            110,
            "and repeated attempts must not compound the total downward"
        );
    }

    /// A cold tier that cannot take the value must not cost us the value.
    ///
    /// Demotion removed the entry from hot and THEN wrote to cold. The trait
    /// could not report a failure — `RocksDbCold` logged a disk-full write and
    /// returned `None`, which reads as "stored, nothing evicted" — so the
    /// value was gone from both tiers while `total_bytes` went on counting it
    /// (audit V-08).
    #[test]
    fn a_cold_tier_that_refuses_does_not_lose_the_value() {
        let mut store = TieredStore::with_cold(1, Box::new(RefusingCold::default()));

        store.insert_hot([1u8; 32], b"first".to_vec(), Instant::now(), Instant::now());
        // Forces a demotion attempt, which the cold tier refuses.
        store.insert_hot(
            [2u8; 32],
            b"second".to_vec(),
            Instant::now(),
            Instant::now(),
        );

        assert_eq!(
            store.hot.get(&[1u8; 32]).map(|(v, _, _)| v.as_slice()),
            Some(&b"first"[..]),
            "the refused value must stay hot, not vanish"
        );
        assert_eq!(
            store.hot.get(&[2u8; 32]).map(|(v, _, _)| v.as_slice()),
            Some(&b"second"[..]),
            "and the new one still lands"
        );
        assert_eq!(
            store.hot_order.len(),
            store.hot.len(),
            "the ordering index must not drift from the map"
        );
    }
}
