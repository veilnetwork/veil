//! Sender-side outbox for peer-sync.
//!
//! When sender A delivers (or attempts to deliver) a message to
//! receiver B, A also stores a reference in its outbox keyed by
//! `(B, content_id)`. The outbox lets A re-send any message B
//! claims it didn't get when the two peers next sync.
//!
//! ## Why a separate store from mailbox
//!
//! **Lifecycle is different.** Mailbox blobs live until the
//! recipient acks (or TTL expires); outbox entries live until the
//! recipient *peer-syncs* and acks individually (or 30-day hard
//! cap).
//! **Placement is different.** Mailbox runs on the relay; outbox
//! runs on every sender's node. Mailbox-relay operators don't
//! want a 100 MiB-per-receiver outbox cluttering disk on top of
//! already-stored blobs.
//! **Authentication is different.** Mailbox has cookie-auth on
//! fetch/ack (it's a third-party store). Outbox is local to the
//! sender — no auth needed; the sender's own runtime is the only
//! caller.
//!
//! ## API shape
//!
//! [`Outbox::put`] — record a freshly-sent message
//! [`Outbox::find_missing`] — given a peer's Bloom filter, return
//! the entries B is likely missing. This is the heart of
//! peer-sync.
//! [`Outbox::ack`] — drop an entry after B confirmed receipt end-
//! to-end (NOT after mailbox-relay confirmed storage)
//! [`Outbox::prune_expired`] — TTL eviction (default 30 days)
//!
//! ## Storage
//!
//! Same redb backend as the mailbox (`<veil_dir>/mailbox/outbox.db`)
//! but a different file so the two databases evolve independently.
//! Two tables:
//!
//! `entries[(receiver[32] || content_id[32])] → encoded_record`
//! `eviction_index[(deposited_at[8] || receiver[32] || content_id[32])] → `
//!
//! No global byte counter or quota — outbox sizing is bounded by the
//! TTL and the user's actual send rate, not by an explicit cap.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use veil_bloom::BloomFilter;

use crate::MailboxError;

const OUTBOX_TABLE_ENTRIES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("outbox_entries_v1");
const OUTBOX_TABLE_EVICT: TableDefinition<&[u8], ()> = TableDefinition::new("outbox_eviction_v1");
/// single-row metadata table holding the running
/// total-blob-bytes counter. Kept in a separate redb table to avoid
/// ABI churn on the entries table.
const OUTBOX_TABLE_META: TableDefinition<&str, u64> = TableDefinition::new("outbox_meta_v1");
const META_KEY_TOTAL_BYTES: &str = "total_bytes";

const KEY_LEN: usize = 32 + 32;

/// Default outbox TTL for individual entries (30 days).
pub const DEFAULT_OUTBOX_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Maximum entries returned in a single [`Outbox::find_missing`] call.
/// Bounds memory + IPC frame size when a peer's Bloom filter accepts
/// thousands of outbox entries (typical: dozens).
pub const MAX_FIND_MISSING_RESULTS: usize = 256;

/// per-blob hard cap. Voice messages + small
/// attachments fit comfortably under 4 MiB; anything bigger from a local
/// IPC client smells like a bug or a flood attempt. Bound is independent
/// of the protocol's `MAX_FRAME_BODY` so the daemon never persists
/// adversarially-large blobs even if a compromised app sends them.
pub const MAX_OUTBOX_BLOB_BYTES: usize = 4 * 1024 * 1024;

/// default cap on aggregate blob bytes across the
/// outbox. 50 MiB ~ 12 voice messages or hundreds of text messages;
/// keeps the per-device disk footprint bounded under a sender's local
/// IPC-flood attack. Hit either expands ack/prune cadence or surfaces
/// the failure to the app as a fast-failed send.
pub const DEFAULT_OUTBOX_QUOTA_BYTES: u64 = 50 * 1024 * 1024;

/// Configuration for an [`Outbox`].
#[derive(Debug, Clone)]
pub struct OutboxConfig {
    /// Time-to-live for individual entries (seconds). After this
    /// `prune_expired` removes them.
    pub ttl_secs: u64,
    /// cap on total blob payload bytes. Sum of
    /// all blob bodies (excluding redb framing); enforced by
    /// [`Outbox::put`] before any DB write.
    pub quota_total_bytes: u64,
}

impl Default for OutboxConfig {
    fn default() -> Self {
        Self {
            ttl_secs: DEFAULT_OUTBOX_TTL_SECS,
            quota_total_bytes: DEFAULT_OUTBOX_QUOTA_BYTES,
        }
    }
}

/// One outbox entry returned by [`Outbox::find_missing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntry {
    /// Receiver this entry is for.
    pub receiver_id: [u8; 32],
    /// Content id (caller-chosen, e.g. BLAKE3 of plaintext).
    pub content_id: [u8; 32],
    /// Unix-seconds when the message was sent.
    pub deposited_at: u64,
    /// Encrypted blob the sender wants to retransmit. Same shape
    /// as `MailboxBlob.blob` — caller is responsible for encryption.
    pub blob: Vec<u8>,
}

/// Sender-side persistent outbox for peer-sync. Cheap to clone via Arc.
pub struct Outbox {
    db: Arc<Database>,
    config: OutboxConfig,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl std::fmt::Debug for Outbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outbox")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Outbox {
    /// Open (or create) an outbox at `<veil_dir>/mailbox/outbox.db`.
    pub fn open(veil_dir: &Path, config: OutboxConfig) -> Result<Self, MailboxError> {
        let dir = veil_dir.join("mailbox");
        std::fs::create_dir_all(&dir)?;
        let db_path = dir.join("outbox.db");
        let db = Database::create(&db_path)?;
        // ensure the metadata table exists and
        // initialize the total-bytes counter on first open or upgrade
        // (existing DBs from before #8 won't have the table OR the key).
        // If the key is missing AND entries already exist, walk the
        // entries table once to compute the true initial total — avoids
        // a stale counter forever underreporting on legacy DBs.
        let txn = db.begin_write()?;
        {
            let _ = txn.open_table(OUTBOX_TABLE_ENTRIES)?;
            let _ = txn.open_table(OUTBOX_TABLE_EVICT)?;
            let mut meta = txn.open_table(OUTBOX_TABLE_META)?;
            if meta.get(META_KEY_TOTAL_BYTES)?.is_none() {
                let entries = txn.open_table(OUTBOX_TABLE_ENTRIES)?;
                let mut total: u64 = 0;
                for entry in entries.iter()? {
                    let (_, v) = entry?;
                    let (_, blob) = decode_record(v.value())?;
                    total = total.saturating_add(blob.len() as u64);
                }
                meta.insert(META_KEY_TOTAL_BYTES, total)?;
            }
        }
        txn.commit()?;
        Ok(Self {
            db: Arc::new(db),
            config,
            clock: Arc::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
                    .as_secs()
            }),
        })
    }

    #[doc(hidden)]
    /// Test helper — open with an injected clock.
    pub fn open_with_clock<F: Fn() -> u64 + Send + Sync + 'static>(
        veil_dir: &Path,
        config: OutboxConfig,
        clock: F,
    ) -> Result<Self, MailboxError> {
        let mut o = Self::open(veil_dir, config)?;
        o.clock = Arc::new(clock);
        Ok(o)
    }

    /// Record a freshly-sent message. Idempotent on `(receiver
    /// content_id)` — a repeat put refreshes `deposited_at` (so a
    /// re-send extends the TTL window).
    ///
    /// rejects blobs above [`MAX_OUTBOX_BLOB_BYTES`]
    /// with [`MailboxError::BlobTooLarge`], and rejects puts that would
    /// push aggregate bytes above `config.quota_total_bytes` with
    /// [`MailboxError::OutboxQuotaExceeded`]. Both checks fire before
    /// any DB write so a flooding caller cannot grow the database.
    pub fn put(
        &self,
        receiver_id: [u8; 32],
        content_id: [u8; 32],
        blob: Vec<u8>,
    ) -> Result<(), MailboxError> {
        // per-blob cap. Cheap fast-fail before
        // any DB work.
        if blob.len() > MAX_OUTBOX_BLOB_BYTES {
            return Err(MailboxError::BlobTooLarge {
                actual: blob.len() as u64,
                max: MAX_OUTBOX_BLOB_BYTES as u64,
            });
        }
        let now = (self.clock)();
        let txn = self.db.begin_write()?;
        {
            let mut entries = txn.open_table(OUTBOX_TABLE_ENTRIES)?;
            let mut evict = txn.open_table(OUTBOX_TABLE_EVICT)?;
            let mut meta = txn.open_table(OUTBOX_TABLE_META)?;
            let key = make_key(&receiver_id, &content_id);
            // If a stale entry exists, remove its eviction-index row
            // so we don't leak a never-pruned timestamp. Also remember
            // its blob.len so the quota check below treats a replace
            // as a delta, not a pure add.
            let stale_record = entries.get(key.as_slice())?.map(|g| g.value().to_vec());
            let mut old_blob_len: u64 = 0;
            if let Some(record) = stale_record {
                let (old_ts, old_blob) = decode_record(&record)?;
                old_blob_len = old_blob.len() as u64;
                let old_evict = make_evict_key(old_ts, &receiver_id, &content_id);
                evict.remove(old_evict.as_slice())?;
            }
            // aggregate quota check.
            let current_total = meta
                .get(META_KEY_TOTAL_BYTES)?
                .map(|v| v.value())
                .unwrap_or(0);
            let new_total = current_total
                .saturating_sub(old_blob_len)
                .saturating_add(blob.len() as u64);
            if new_total > self.config.quota_total_bytes {
                // Abort the txn implicitly by returning before commit.
                return Err(MailboxError::OutboxQuotaExceeded {
                    current_bytes: current_total,
                    blob_size: blob.len() as u64,
                    cap_bytes: self.config.quota_total_bytes,
                });
            }
            let record = encode_record(now, &blob);
            entries.insert(key.as_slice(), record.as_slice())?;
            let evict_key = make_evict_key(now, &receiver_id, &content_id);
            evict.insert(evict_key.as_slice(), ())?;
            meta.insert(META_KEY_TOTAL_BYTES, new_total)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Find entries for `receiver_id` deposited at-or-after `since` that
    /// are NOT in `bloom`. Capped at [`MAX_FIND_MISSING_RESULTS`].
    /// Returned oldest-first so a peer-sync round-trip ships the
    /// oldest-still-missing first (most likely to age out otherwise).
    pub fn find_missing(
        &self,
        receiver_id: [u8; 32],
        since: u64,
        bloom: &BloomFilter,
    ) -> Result<Vec<OutboxEntry>, MailboxError> {
        let txn = self.db.begin_read()?;
        let entries = txn.open_table(OUTBOX_TABLE_ENTRIES)?;
        let mut start = [0u8; KEY_LEN];
        start[..32].copy_from_slice(&receiver_id);
        let mut end = [0xFFu8; KEY_LEN];
        end[..32].copy_from_slice(&receiver_id);

        // Pass 1: select the MAX_FIND_MISSING_RESULTS OLDEST missing entries
        // WITHOUT materializing every blob. The record is `ts(8) || blob_len(4)
        // || blob`, so the timestamp is read from the header alone. A bounded
        // max-heap on `deposited_at` keeps only the oldest `cap` (deposited_at,
        // content_id) pairs (each ~40 B) — peak memory is the result cap, not
        // the whole outbox (which previously pushed every full blob, then
        // truncated). Mirrors the bounded `Mailbox::fetch` (audit U10).
        let mut heap: std::collections::BinaryHeap<(u64, [u8; 32])> =
            std::collections::BinaryHeap::new();
        for entry in entries.range::<&[u8]>(start.as_slice()..=end.as_slice())? {
            let (k, v) = entry?;
            let key_bytes = k.value();
            if key_bytes.len() != KEY_LEN || key_bytes[..32] != receiver_id {
                continue;
            }
            let val = v.value();
            if val.len() < 12 {
                continue; // corrupt/short header — skip (decode would error later)
            }
            let deposited_at = u64::from_be_bytes(val[..8].try_into().unwrap());
            if deposited_at < since {
                continue;
            }
            let mut content_id = [0u8; 32];
            content_id.copy_from_slice(&key_bytes[32..]);
            if bloom.contains(&content_id) {
                // Receiver claims to have it. Skip.
                continue;
            }
            heap.push((deposited_at, content_id));
            if heap.len() > MAX_FIND_MISSING_RESULTS {
                heap.pop(); // evicts the NEWEST (largest ts) → keep the oldest cap
            }
        }

        // Pass 2: load blobs for exactly the selected survivors, oldest-first.
        let mut selected: Vec<(u64, [u8; 32])> = heap.into_vec();
        selected.sort_by_key(|(ts, _)| *ts);
        let mut out: Vec<OutboxEntry> = Vec::with_capacity(selected.len());
        for (_, content_id) in selected {
            let mut key = [0u8; KEY_LEN];
            key[..32].copy_from_slice(&receiver_id);
            key[32..].copy_from_slice(&content_id);
            if let Some(v) = entries.get(key.as_slice())? {
                let (deposited_at, blob) = decode_record(v.value())?;
                out.push(OutboxEntry {
                    receiver_id,
                    content_id,
                    deposited_at,
                    blob,
                });
            }
        }
        Ok(out)
    }

    /// Drop an entry after the receiver confirmed end-to-end receipt.
    /// Idempotent — acking a non-existent entry returns `false`
    /// without error.
    pub fn ack(&self, receiver_id: [u8; 32], content_id: [u8; 32]) -> Result<bool, MailboxError> {
        let txn = self.db.begin_write()?;
        let mut should_commit = false;
        let removed = {
            let mut entries = txn.open_table(OUTBOX_TABLE_ENTRIES)?;
            let mut evict = txn.open_table(OUTBOX_TABLE_EVICT)?;
            let mut meta = txn.open_table(OUTBOX_TABLE_META)?;
            let key = make_key(&receiver_id, &content_id);
            let record_opt = entries.get(key.as_slice())?.map(|g| g.value().to_vec());
            match record_opt {
                None => false,
                Some(record) => {
                    let (deposited_at, blob) = decode_record(&record)?;
                    entries.remove(key.as_slice())?;
                    let evict_key = make_evict_key(deposited_at, &receiver_id, &content_id);
                    evict.remove(evict_key.as_slice())?;
                    // decrement total-bytes counter.
                    let current = meta
                        .get(META_KEY_TOTAL_BYTES)?
                        .map(|v| v.value())
                        .unwrap_or(0);
                    let new_total = current.saturating_sub(blob.len() as u64);
                    meta.insert(META_KEY_TOTAL_BYTES, new_total)?;
                    should_commit = true;
                    true
                }
            }
        };
        if should_commit {
            txn.commit()?;
        }
        Ok(removed)
    }

    /// Remove entries older than `now - ttl_secs`. Returns the count
    /// pruned. Designed for periodic background invocation.
    pub fn prune_expired(&self) -> Result<u64, MailboxError> {
        let now = (self.clock)();
        let cutoff = now.saturating_sub(self.config.ttl_secs);
        let txn = self.db.begin_write()?;
        let pruned = {
            let mut entries = txn.open_table(OUTBOX_TABLE_ENTRIES)?;
            let mut evict = txn.open_table(OUTBOX_TABLE_EVICT)?;
            let mut meta = txn.open_table(OUTBOX_TABLE_META)?;
            let cutoff_be = cutoff.to_be_bytes();
            let mut upper = [0u8; 8 + 32 + 32];
            upper[..8].copy_from_slice(&cutoff_be);
            let lower = [0u8; 8 + 32 + 32];
            let mut victims: Vec<Vec<u8>> = Vec::new();
            for e in evict.range::<&[u8]>(lower.as_slice()..upper.as_slice())? {
                let (k, _) = e?;
                victims.push(k.value().to_vec());
            }
            let mut count = 0u64;
            // accumulate bytes freed by pruned
            // blobs to decrement the counter once at the end (cheaper
            // than one redb write per victim).
            let mut bytes_freed: u64 = 0;
            for v in victims {
                if v.len() != 8 + 32 + 32 {
                    continue;
                }
                let mut recv = [0u8; 32];
                let mut cid = [0u8; 32];
                recv.copy_from_slice(&v[8..40]);
                cid.copy_from_slice(&v[40..72]);
                let key = make_key(&recv, &cid);
                if let Some(record_guard) = entries.get(key.as_slice())? {
                    let (_, blob) = decode_record(record_guard.value())?;
                    bytes_freed = bytes_freed.saturating_add(blob.len() as u64);
                }
                if entries.remove(key.as_slice())?.is_some() {
                    count += 1;
                }
                evict.remove(v.as_slice())?;
            }
            if bytes_freed > 0 {
                let current = meta
                    .get(META_KEY_TOTAL_BYTES)?
                    .map(|v| v.value())
                    .unwrap_or(0);
                let new_total = current.saturating_sub(bytes_freed);
                meta.insert(META_KEY_TOTAL_BYTES, new_total)?;
            }
            count
        };
        txn.commit()?;
        Ok(pruned)
    }

    /// Total entry count across all receivers. Cheap.
    pub fn len(&self) -> Result<u64, MailboxError> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(OUTBOX_TABLE_ENTRIES)?;
        Ok(t.len()?)
    }

    /// aggregate blob bytes currently stored.
    /// Cheap (single-key read). Useful for operators tracking how
    /// close the outbox is to its `quota_total_bytes` cap.
    pub fn total_blob_bytes(&self) -> Result<u64, MailboxError> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(OUTBOX_TABLE_META)?;
        Ok(meta
            .get(META_KEY_TOTAL_BYTES)?
            .map(|v| v.value())
            .unwrap_or(0))
    }

    /// True if the outbox has zero entries. Mirror of `len == 0` —
    /// added per clippy `len_without_is_empty`.
    pub fn is_empty(&self) -> Result<bool, MailboxError> {
        Ok(self.len()? == 0)
    }
}

/// Storage record format: `[ts_u64_be (8) | blob_len_u32_be (4) | blob_bytes]`.
fn encode_record(deposited_at: u64, blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 4 + blob.len());
    out.extend_from_slice(&deposited_at.to_be_bytes());
    out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
    out.extend_from_slice(blob);
    out
}

fn decode_record(bytes: &[u8]) -> Result<(u64, Vec<u8>), MailboxError> {
    if bytes.len() < 12 {
        return Err(MailboxError::Corrupt("outbox record too short for header"));
    }
    let ts = u64::from_be_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| MailboxError::Corrupt("outbox record ts slice"))?,
    );
    let blob_len = u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| MailboxError::Corrupt("outbox record blob_len slice"))?,
    ) as usize;
    if bytes.len() != 12 + blob_len {
        return Err(MailboxError::Corrupt("outbox record blob_len mismatch"));
    }
    Ok((ts, bytes[12..].to_vec()))
}

fn make_key(receiver: &[u8; 32], content_id: &[u8; 32]) -> [u8; KEY_LEN] {
    let mut k = [0u8; KEY_LEN];
    k[..32].copy_from_slice(receiver);
    k[32..].copy_from_slice(content_id);
    k
}

fn make_evict_key(deposited_at: u64, receiver: &[u8; 32], content_id: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(8 + 32 + 32);
    k.extend_from_slice(&deposited_at.to_be_bytes());
    k.extend_from_slice(receiver);
    k.extend_from_slice(content_id);
    k
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn fresh(cfg: OutboxConfig) -> (Outbox, tempfile::TempDir, Arc<AtomicU64>) {
        let tmp = tempfile::tempdir().unwrap();
        let clock = Arc::new(AtomicU64::new(1_700_000_000));
        let clk = Arc::clone(&clock);
        let o =
            Outbox::open_with_clock(tmp.path(), cfg, move || clk.load(Ordering::SeqCst)).unwrap();
        (o, tmp, clock)
    }

    #[test]
    fn t1_4_p4_outbox_put_then_find_missing_with_empty_bloom() {
        let (o, _tmp, _clk) = fresh(OutboxConfig::default());
        let recv = [1u8; 32];
        o.put(recv, [b'A'; 32], b"msg-a".to_vec()).unwrap();
        o.put(recv, [b'B'; 32], b"msg-b".to_vec()).unwrap();
        // Empty bloom → both entries missing.
        let bf = BloomFilter::for_capacity(100, 0.01);
        let missing = o.find_missing(recv, 0, &bf).unwrap();
        assert_eq!(missing.len(), 2);
    }

    #[test]
    fn t1_4_p4_outbox_find_missing_caps_results_oldest_first() {
        let (o, _tmp, _clk) = fresh(OutboxConfig::default());
        let recv = [1u8; 32];
        let n = MAX_FIND_MISSING_RESULTS + 7;
        for i in 0..n {
            let mut cid = [0u8; 32];
            cid[..8].copy_from_slice(&(i as u64).to_be_bytes());
            o.put(recv, cid, vec![0u8; 16]).unwrap();
        }
        let bf = BloomFilter::for_capacity(1000, 0.01);
        let missing = o.find_missing(recv, 0, &bf).unwrap();
        assert_eq!(
            missing.len(),
            MAX_FIND_MISSING_RESULTS,
            "result set must be capped regardless of how many match"
        );
        for w in missing.windows(2) {
            assert!(
                w[0].deposited_at <= w[1].deposited_at,
                "results must be oldest-first"
            );
        }
    }

    #[test]
    fn t1_4_p4_outbox_find_missing_filters_by_bloom() {
        let (o, _tmp, _clk) = fresh(OutboxConfig::default());
        let recv = [1u8; 32];
        let cid_a = [b'A'; 32];
        let cid_b = [b'B'; 32];
        o.put(recv, cid_a, b"msg-a".to_vec()).unwrap();
        o.put(recv, cid_b, b"msg-b".to_vec()).unwrap();
        // Bloom contains cid_a → only cid_b returned.
        let mut bf = BloomFilter::for_capacity(100, 0.01);
        bf.insert(&cid_a);
        let missing = o.find_missing(recv, 0, &bf).unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].content_id, cid_b);
    }

    #[test]
    fn t1_4_p4_outbox_find_missing_filters_by_since() {
        let (o, _tmp, clk) = fresh(OutboxConfig::default());
        let recv = [1u8; 32];
        clk.store(100, Ordering::SeqCst);
        o.put(recv, [b'A'; 32], b"old".to_vec()).unwrap();
        clk.store(200, Ordering::SeqCst);
        o.put(recv, [b'B'; 32], b"new".to_vec()).unwrap();
        let bf = BloomFilter::for_capacity(100, 0.01);
        // since=150 → only 'new'.
        let missing = o.find_missing(recv, 150, &bf).unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].content_id, [b'B'; 32]);
    }

    #[test]
    fn t1_4_p4_outbox_find_missing_returns_oldest_first() {
        let (o, _tmp, clk) = fresh(OutboxConfig::default());
        let recv = [1u8; 32];
        clk.store(300, Ordering::SeqCst);
        o.put(recv, [b'C'; 32], vec![]).unwrap();
        clk.store(100, Ordering::SeqCst);
        o.put(recv, [b'A'; 32], vec![]).unwrap();
        clk.store(200, Ordering::SeqCst);
        o.put(recv, [b'B'; 32], vec![]).unwrap();
        let bf = BloomFilter::for_capacity(100, 0.01);
        let missing = o.find_missing(recv, 0, &bf).unwrap();
        assert_eq!(missing.len(), 3);
        assert_eq!(missing[0].deposited_at, 100);
        assert_eq!(missing[1].deposited_at, 200);
        assert_eq!(missing[2].deposited_at, 300);
    }

    #[test]
    fn t1_4_p4_outbox_ack_removes_entry() {
        let (o, _tmp, _clk) = fresh(OutboxConfig::default());
        let recv = [1u8; 32];
        let cid = [b'X'; 32];
        o.put(recv, cid, b"x".to_vec()).unwrap();
        assert_eq!(o.len().unwrap(), 1);
        let removed = o.ack(recv, cid).unwrap();
        assert!(removed);
        assert_eq!(o.len().unwrap(), 0);
        // Idempotent.
        let again = o.ack(recv, cid).unwrap();
        assert!(!again);
    }

    #[test]
    fn t1_4_p4_outbox_repeat_put_refreshes_timestamp() {
        let (o, _tmp, clk) = fresh(OutboxConfig::default());
        let recv = [1u8; 32];
        let cid = [b'X'; 32];
        clk.store(100, Ordering::SeqCst);
        o.put(recv, cid, b"first".to_vec()).unwrap();
        clk.store(200, Ordering::SeqCst);
        o.put(recv, cid, b"second".to_vec()).unwrap();
        let bf = BloomFilter::for_capacity(100, 0.01);
        let missing = o.find_missing(recv, 0, &bf).unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].deposited_at, 200);
        assert_eq!(missing[0].blob, b"second");
    }

    #[test]
    fn t1_4_p4_outbox_prune_expired_drops_old_entries() {
        let (o, _tmp, clk) = fresh(OutboxConfig {
            ttl_secs: 100,
            ..OutboxConfig::default()
        });
        let recv = [1u8; 32];
        clk.store(0, Ordering::SeqCst);
        o.put(recv, [b'A'; 32], vec![]).unwrap();
        clk.store(50, Ordering::SeqCst);
        o.put(recv, [b'B'; 32], vec![]).unwrap();
        clk.store(200, Ordering::SeqCst);
        let pruned = o.prune_expired().unwrap();
        // Cutoff = 200-100 = 100. A (ts=0) and B (ts=50) both pruned.
        assert_eq!(pruned, 2);
        assert_eq!(o.len().unwrap(), 0);
    }

    #[test]
    fn t1_4_p4_outbox_persistence_across_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let recv = [7u8; 32];
        let cid = [8u8; 32];
        {
            let o = Outbox::open(tmp.path(), OutboxConfig::default()).unwrap();
            o.put(recv, cid, b"persisted".to_vec()).unwrap();
        }
        let o2 = Outbox::open(tmp.path(), OutboxConfig::default()).unwrap();
        let bf = BloomFilter::for_capacity(100, 0.01);
        let missing = o2.find_missing(recv, 0, &bf).unwrap();
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].blob, b"persisted");
    }

    #[test]
    fn t1_4_p4_outbox_filters_by_receiver() {
        let (o, _tmp, _clk) = fresh(OutboxConfig::default());
        o.put([1u8; 32], [b'A'; 32], vec![1]).unwrap();
        o.put([2u8; 32], [b'B'; 32], vec![2]).unwrap();
        o.put([1u8; 32], [b'C'; 32], vec![3]).unwrap();
        let bf = BloomFilter::for_capacity(100, 0.01);
        let r1 = o.find_missing([1u8; 32], 0, &bf).unwrap();
        assert_eq!(r1.len(), 2);
        let r2 = o.find_missing([2u8; 32], 0, &bf).unwrap();
        assert_eq!(r2.len(), 1);
    }

    /// per-blob cap fires before any DB write.
    #[test]
    fn phase6_50_d_6_3_outbox_rejects_oversized_blob() {
        let (o, _tmp, _clk) = fresh(OutboxConfig::default());
        let huge = vec![0xAB; MAX_OUTBOX_BLOB_BYTES + 1];
        let err = o.put([1u8; 32], [b'A'; 32], huge).unwrap_err();
        match err {
            MailboxError::BlobTooLarge { actual, max } => {
                assert_eq!(actual, (MAX_OUTBOX_BLOB_BYTES + 1) as u64);
                assert_eq!(max, MAX_OUTBOX_BLOB_BYTES as u64);
            }
            other => panic!("expected BlobTooLarge, got {other:?}"),
        }
        // No bytes leaked into the counter.
        assert_eq!(o.total_blob_bytes().unwrap(), 0);
    }

    /// aggregate quota fires before DB write.
    #[test]
    fn phase6_50_d_6_3_outbox_rejects_over_quota_total() {
        let cfg = OutboxConfig {
            ttl_secs: DEFAULT_OUTBOX_TTL_SECS,
            quota_total_bytes: 100,
        };
        let (o, _tmp, _clk) = fresh(cfg);
        let recv = [1u8; 32];
        // 60 + 60 = 120 > 100; second put rejected.
        o.put(recv, [b'A'; 32], vec![0; 60]).unwrap();
        let err = o.put(recv, [b'B'; 32], vec![0; 60]).unwrap_err();
        match err {
            MailboxError::OutboxQuotaExceeded {
                current_bytes,
                blob_size,
                cap_bytes,
            } => {
                assert_eq!(current_bytes, 60);
                assert_eq!(blob_size, 60);
                assert_eq!(cap_bytes, 100);
            }
            other => panic!("expected OutboxQuotaExceeded, got {other:?}"),
        }
        // Counter still reflects only the first successful put.
        assert_eq!(o.total_blob_bytes().unwrap(), 60);
    }

    /// replace-put adjusts the counter by delta.
    #[test]
    fn phase6_50_d_6_3_outbox_replace_adjusts_counter() {
        let (o, _tmp, _clk) = fresh(OutboxConfig::default());
        let recv = [1u8; 32];
        let cid = [b'A'; 32];
        o.put(recv, cid, vec![0; 100]).unwrap();
        assert_eq!(o.total_blob_bytes().unwrap(), 100);
        // Re-put same key with larger blob → counter goes to new size, not sum.
        o.put(recv, cid, vec![0; 300]).unwrap();
        assert_eq!(o.total_blob_bytes().unwrap(), 300);
        // Re-put same key with smaller blob → counter shrinks.
        o.put(recv, cid, vec![0; 50]).unwrap();
        assert_eq!(o.total_blob_bytes().unwrap(), 50);
    }

    /// ack decrements the counter.
    #[test]
    fn phase6_50_d_6_3_outbox_ack_decrements_counter() {
        let (o, _tmp, _clk) = fresh(OutboxConfig::default());
        let recv = [1u8; 32];
        o.put(recv, [b'A'; 32], vec![0; 100]).unwrap();
        o.put(recv, [b'B'; 32], vec![0; 200]).unwrap();
        assert_eq!(o.total_blob_bytes().unwrap(), 300);
        assert!(o.ack(recv, [b'A'; 32]).unwrap());
        assert_eq!(o.total_blob_bytes().unwrap(), 200);
        assert!(o.ack(recv, [b'B'; 32]).unwrap());
        assert_eq!(o.total_blob_bytes().unwrap(), 0);
    }

    /// prune_expired decrements the counter.
    #[test]
    fn phase6_50_d_6_3_outbox_prune_decrements_counter() {
        let cfg = OutboxConfig {
            ttl_secs: 100,
            ..OutboxConfig::default()
        };
        let (o, _tmp, clk) = fresh(cfg);
        let recv = [1u8; 32];
        clk.store(0, Ordering::SeqCst);
        o.put(recv, [b'A'; 32], vec![0; 100]).unwrap();
        clk.store(200, Ordering::SeqCst);
        o.put(recv, [b'B'; 32], vec![0; 50]).unwrap();
        assert_eq!(o.total_blob_bytes().unwrap(), 150);
        clk.store(300, Ordering::SeqCst);
        let pruned = o.prune_expired().unwrap();
        // Cutoff = 300-100 = 200. A (ts=0) pruned; B (ts=200, NOT <
        // cutoff in `range::<&[u8]>(.. upper)` — exclusive upper) kept.
        assert_eq!(pruned, 1);
        assert_eq!(o.total_blob_bytes().unwrap(), 50);
    }
}
