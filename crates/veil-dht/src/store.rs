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
use std::time::Instant;

// ── ColdBackend trait ───────────────────────────────────────────

/// A value-based freshness predicate: `true` ⇒ the value is expired and should
/// be dropped. Borrowed for the duration of a single `retain_fresh` call.
/// Aliased to keep `retain_fresh_inner`'s signature within clippy's
/// type-complexity budget (audit cycle-8).
type ValuePredicate<'a> = dyn Fn(&[u8]) -> bool + 'a;

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
    fn put(&mut self, key: [u8; 32], value: Vec<u8>) -> Option<([u8; 32], Vec<u8>)>;
    fn remove(&mut self, key: &[u8; 32]);
    fn contains(&self, key: &[u8; 32]) -> bool;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Iterate all entries (for snapshot/migration).
    fn iter_entries(&self) -> Vec<([u8; 32], Vec<u8>)>;
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

    fn put(&mut self, key: [u8; 32], value: Vec<u8>) -> Option<([u8; 32], Vec<u8>)> {
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
        evicted
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
        for (&(ts, key), _) in self.order.iter() {
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
    use super::ColdBackend;
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
        /// Sum of indexed value byte-lengths seen at `open` (audit cycle-8),
        /// used once to seed `TieredStore::total_bytes` so the byte/origin caps
        /// account for an already-populated disk tier across restarts. `None`
        /// if the index carried no length info (all-legacy-v1 DB).
        seed_bytes: Option<u64>,
    }

    impl RocksDbCold {
        pub fn open(
            path: impl AsRef<std::path::Path>,
            capacity: usize,
        ) -> Result<Self, rocksdb::Error> {
            let mut opts = rocksdb::Options::default();
            opts.create_if_missing(true);
            // Legacy DBs (pre-T5-B) have only the default CF; create the new
            // side CFs on open. Legacy values stay in the default CF and remain
            // readable; they carry no index entry, so they are grandfathered
            // (never age/cap-evicted) until overwritten or owner-DELETE'd.
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
                rocksdb::ColumnFamilyDescriptor::new(CF_KEY_TS, cf_opts),
            ];
            let db = rocksdb::DB::open_cf_descriptors(&opts, path, cfs)?;
            // One-time O(n) startup scan of the reverse-map CF (keys + small
            // fixed values — cheap relative to the value set): seed both the
            // exact entry count AND (audit cycle-8) the sum of per-key value
            // byte-lengths so the store can re-seed `total_bytes` for the
            // already-persisted disk tier. A v2 value is `ts(8)‖len(8)`; a
            // legacy v1 value is `ts(8)` only (len treated as 0, so a fully
            // legacy DB yields `seed_bytes = None`).
            let (count, summed_bytes, any_len) = {
                let cf = db.cf_handle(CF_KEY_TS).expect("CF_KEY_TS just created");
                let mut count = 0usize;
                let mut summed: u64 = 0;
                let mut any_len = false;
                for item in db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
                    let Ok((_k, v)) = item else { continue };
                    count += 1;
                    if v.len() >= 16 {
                        let mut len_arr = [0u8; 8];
                        len_arr.copy_from_slice(&v[8..16]);
                        summed = summed.saturating_add(u64::from_be_bytes(len_arr));
                        any_len = true;
                    }
                }
                (count, summed, any_len)
            };
            Ok(Self {
                db,
                capacity,
                count,
                seed_bytes: if any_len { Some(summed_bytes) } else { None },
            })
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
        fn cf_kt(&self) -> &rocksdb::ColumnFamily {
            self.db.cf_handle(CF_KEY_TS).expect("CF_KEY_TS present")
        }

        fn ix_key(ts: u64, key: &[u8; 32]) -> [u8; 40] {
            let mut k = [0u8; 40];
            k[..8].copy_from_slice(&ts.to_be_bytes());
            k[8..].copy_from_slice(key);
            k
        }

        /// Drop the index entries for `key` (reverse-map + ts-index), returning
        /// `true` if an index entry existed (i.e. the key was an indexed entry,
        /// not a grandfathered legacy value).
        fn unindex(&mut self, key: &[u8; 32]) -> bool {
            if let Ok(Some(old_kt)) = self.db.get_cf(self.cf_kt(), key) {
                // Value is `ts(8)` (legacy v1) or `ts(8)‖len(8)` (v2); the ts
                // prefix is what locates the stale ts-index entry.
                if old_kt.len() >= 8 {
                    let mut ts_arr = [0u8; 8];
                    ts_arr.copy_from_slice(&old_kt[..8]);
                    let old_ts = u64::from_be_bytes(ts_arr);
                    if let Err(e) = self.db.delete_cf(self.cf_ix(), Self::ix_key(old_ts, key)) {
                        log::warn!("dht.cold.rocksdb: delete ts-index failed: {e}");
                    }
                }
                if let Err(e) = self.db.delete_cf(self.cf_kt(), key) {
                    log::warn!("dht.cold.rocksdb: delete key-ts failed: {e}");
                }
                true
            } else {
                false
            }
        }
    }

    impl ColdBackend for RocksDbCold {
        fn get(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
            self.db.get(key).ok().flatten()
        }

        fn put(&mut self, key: [u8; 32], value: Vec<u8>) -> Option<([u8; 32], Vec<u8>)> {
            let byte_len = value.len() as u64;
            // Write the value FIRST and bail on failure WITHOUT touching the
            // index or count (audit cycle-8: previously `let _ = db.put(...)`
            // ignored disk-full/IO errors, then bumped `count` and wrote index
            // entries for a value that never landed — drifting count vs data).
            if let Err(e) = self.db.put(key, &value) {
                log::warn!(
                    "dht.cold.rocksdb: value write failed ({e}); entry dropped, counters unchanged"
                );
                return None;
            }
            // Value is durable; now (re)index. Drop any stale (old_ts, key)
            // index entry on overwrite, then write the fresh ts‖len + ts-index.
            let was_indexed = self.unindex(&key);
            let ts = Self::now_secs();
            if let Err(e) = self
                .db
                .put_cf(self.cf_kt(), key, Self::kt_value(ts, byte_len))
            {
                log::warn!("dht.cold.rocksdb: key-ts index write failed: {e}");
            }
            if let Err(e) = self.db.put_cf(self.cf_ix(), Self::ix_key(ts, &key), []) {
                log::warn!("dht.cold.rocksdb: ts-index write failed: {e}");
            }
            if !was_indexed {
                self.count += 1;
            }
            // Entry-cap: evict the single oldest entry if over capacity
            // (amortised one-per-put, matching InMemoryCold). Returns the
            // evicted entry for the caller's byte-counter bookkeeping.
            if self.capacity > 0
                && self.count > self.capacity
                && let Some((ev_key, ev_val)) = self.evict_oldest()
                // Don't report self-eviction (can't happen — we just inserted
                // `key`, and the oldest is strictly older).
                && ev_key != key
            {
                return Some((ev_key, ev_val));
            }
            None
        }

        fn remove(&mut self, key: &[u8; 32]) {
            if self.unindex(key) {
                self.count = self.count.saturating_sub(1);
            }
            if let Err(e) = self.db.delete(key) {
                log::warn!("dht.cold.rocksdb: value delete failed: {e}");
            }
        }

        fn contains(&self, key: &[u8; 32]) -> bool {
            self.db.get(key).ok().flatten().is_some()
        }

        fn len(&self) -> usize {
            self.count
        }

        fn cold_total_bytes(&self) -> Option<u64> {
            self.seed_bytes
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

        /// Audit cycle-7 M4: collect only the 32-byte keys, dropping each
        /// value without cloning it into the result. The whole on-disk value
        /// set therefore never lands in process RAM at once (cf.
        /// `iter_entries`, which materializes every value).
        fn iter_keys(&self) -> Vec<[u8; 32]> {
            let iter = self.db.iterator(rocksdb::IteratorMode::Start);
            iter.filter_map(|item| {
                let (k, _v) = item.ok()?;
                k.as_ref().try_into().ok()
            })
            .collect()
        }

        fn retain(&mut self, f: &dyn Fn(&[u8; 32], &[u8]) -> bool) -> Vec<([u8; 32], u64)> {
            let to_delete: Vec<([u8; 32], u64)> = self
                .iter_entries()
                .into_iter()
                .filter(|(k, v)| !f(k, v))
                .map(|(k, v)| (k, v.len() as u64))
                .collect();
            for (key, _) in &to_delete {
                if self.unindex(key) {
                    self.count = self.count.saturating_sub(1);
                }
                let _ = self.db.delete(key);
            }
            to_delete
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
                if self.unindex(&key) {
                    self.count = self.count.saturating_sub(1);
                }
                let _ = self.db.delete(key);
                removed.push((key, byte_len));
            }
            removed
        }

        fn evict_oldest(&mut self) -> Option<([u8; 32], Vec<u8>)> {
            // Smallest ts_index key = oldest entry.
            let oldest = self
                .db
                .iterator_cf(self.cf_ix(), rocksdb::IteratorMode::Start)
                .next()?
                .ok()?;
            let (ix_key, _) = oldest;
            if ix_key.len() < 40 {
                return None;
            }
            let key: [u8; 32] = <[u8; 32]>::try_from(&ix_key[8..40]).ok()?;
            let value = self.db.get(key).ok().flatten()?;
            if self.unindex(&key) {
                self.count = self.count.saturating_sub(1);
            }
            let _ = self.db.delete(key);
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

/// Tiered key-value store for DHT entries.
#[derive(Debug)]
pub struct TieredStore {
    /// Hot tier: recently accessed entries (always in-memory).
    hot: HashMap<[u8; 32], (Vec<u8>, Instant)>,
    hot_order: BTreeMap<(Instant, [u8; 32]), ()>,
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
        Self {
            hot: HashMap::new(),
            hot_order: BTreeMap::new(),
            hot_capacity,
            cold,
            total_bytes,
            max_bytes: None,
            origin_bytes: HashMap::new(),
            entry_origin: HashMap::new(),
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
            return self.hot.get(key).map(|(v, _)| v);
        }
        // Check cold — promote if found.
        if let Some(value) = self.cold.get(key) {
            // Promotion must be byte-neutral: `cold.remove` does NOT adjust
            // `total_bytes`, but `insert_hot` re-adds `value.len()`. The bytes
            // were already counted while the entry sat in cold, so cancel
            // insert_hot's re-add here — otherwise `total_bytes` drifts upward
            // on every cold→hot promotion and spuriously trips the byte-cap
            // eviction loop (audit U1).
            self.cold.remove(key);
            self.total_bytes = self.total_bytes.saturating_sub(value.len() as u64);
            self.insert_hot(*key, value, Instant::now());
            return self.hot.get(key).map(|(v, _)| v);
        }
        None
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
            return self.hot.get(key).map(|(v, ts)| (v, *ts));
        }
        if let Some(value) = self.cold.get(key) {
            // Byte-neutral promotion — see `get` (audit U1).
            self.cold.remove(key);
            self.total_bytes = self.total_bytes.saturating_sub(value.len() as u64);
            let now = Instant::now();
            self.insert_hot(*key, value, now);
            return self.hot.get(key).map(|(v, ts)| (v, *ts));
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

        // 1. Drop the previous value's bytes for this key (if any) — done
        //    by calling remove(), which adjusts total_bytes and origin_bytes
        //    appropriately.
        self.remove(&key);

        // 2. Byte-cap check: refuse single values that exceed the cap.
        if let Some(cap) = self.max_bytes
            && new_bytes > cap
        {
            // Value alone exceeds the budget — drop silently.  Caller
            // can pre-check via `total_bytes()` / `max_bytes()` to
            // distinguish "won't fit" from "succeeded but evicted others".
            return false;
        }

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
                    if let Some((old_val, _)) = self.hot.remove(&old_key) {
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
        self.insert_hot(key, value, ts);
        true
    }

    /// Decrement [`Self::total_bytes`] and per-origin tracking when an
    /// entry is evicted out-of-band (cold backend's own LRU cache or
    /// hot-overflow demote-and-drop).  Internal helper — call sites must
    /// have already removed the entry from its tier.
    fn account_eviction(&mut self, key: &[u8; 32], bytes: u64) {
        self.total_bytes = self.total_bytes.saturating_sub(bytes);
        if let Some(origin) = self.entry_origin.remove(key)
            && let Some(slot) = self.origin_bytes.get_mut(&origin)
        {
            *slot = slot.saturating_sub(bytes);
            if *slot == 0 {
                self.origin_bytes.remove(&origin);
            }
        }
    }

    /// Look up the byte size of a stored value, irrespective of tier.
    /// Used by the per-origin cap delta check.  Returns `0` if absent.
    fn value_bytes(&self, key: &[u8; 32]) -> u64 {
        if let Some((v, _)) = self.hot.get(key) {
            return v.len() as u64;
        }
        self.cold.get(key).map(|v| v.len() as u64).unwrap_or(0)
    }

    /// Remove a key from both tiers.
    pub fn remove(&mut self, key: &[u8; 32]) {
        let mut removed_bytes: u64 = 0;
        if let Some((val, ts)) = self.hot.remove(key) {
            self.hot_order.remove(&(ts, *key));
            removed_bytes = removed_bytes.saturating_add(val.len() as u64);
        }
        // Cold doesn't return the removed value from its `remove` API.
        // Get the value first so we can subtract its bytes from the total.
        if let Some(val) = self.cold.get(key) {
            removed_bytes = removed_bytes.saturating_add(val.len() as u64);
        }
        self.cold.remove(key);
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
        let mut result: Vec<([u8; 32], Vec<u8>)> =
            self.hot.iter().map(|(k, (v, _))| (*k, v.clone())).collect();
        result.extend(self.cold.iter_entries());
        result
    }

    /// Iterate **only the volatile HOT tier** `(key, value)` pairs (no cold
    /// tier). Used by the values snapshot when the cold tier is durable
    /// (`cold_is_durable()`): the cold set persists via its own backend, so
    /// re-serialising it every interval would defeat the disk tier and risk an
    /// OOM on large stores. No promotion side-effects.
    pub fn iter_hot(&self) -> Vec<([u8; 32], Vec<u8>)> {
        self.hot.iter().map(|(k, (v, _))| (*k, v.clone())).collect()
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
        if let Some((v, _)) = self.hot.get(key) {
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
        self.hot.retain(|key, (value, inserted_at)| {
            let value_expired = expired.map(|f| f(value)).unwrap_or(false);
            let keep = now.duration_since(*inserted_at) < ttl && !value_expired;
            if !keep {
                self.hot_order.remove(&(*inserted_at, *key));
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
        }
        let mut freed_cold: u64 = 0;
        for (key, bytes) in &removed_cold {
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
    fn insert_hot(&mut self, key: [u8; 32], value: Vec<u8>, ts: Instant) {
        if self.hot.len() >= self.hot_capacity {
            self.demote_oldest_hot();
        }
        // Account for the new bytes (total_bytes invariant: sum of all
        // values across both tiers).  Caller must NOT have already
        // inserted into hot when calling this — invariant enforced by
        // private visibility and call-sites that come through put_at.
        self.total_bytes = self.total_bytes.saturating_add(value.len() as u64);
        self.hot.insert(key, (value, ts));
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
            let evicted = self.cold.put(key, entry.0);
            if let Some((evicted_key, evicted_val)) = evicted {
                self.account_eviction(&evicted_key, evicted_val.len() as u64);
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
