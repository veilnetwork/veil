//! Persistence for verified P-Net bans received over the network.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use veil_dht::NetworkAuthGate as _;
use veil_dht::kademlia::{DEFAULT_TTL, DhtValueSnapshot, KademliaService};
use veil_identity::network_access::NetworkAccessGate;
use veil_identity::network_ban::{MAX_BAN_BLOB_SIZE, decode_ban_blob};
use veil_observability::NodeLogger;
use veil_proto::budget::MAX_BAN_LIST_SIZE;
use veil_util::{lock, unix_secs_now_u64};

use super::issued_bans::{
    directory_exists, ensure_directory, entry_key, open_record, read_record_bytes,
};

const QUEUE_CAPACITY: usize = 256;
const BATCH_SIZE: usize = 32;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(120);
const FIRST_RETRY: Duration = Duration::from_secs(1);
const MAX_RETRY: Duration = Duration::from_secs(30);
const RECEIVED_MAGIC: &[u8; 4] = b"PBR1";
const TIMESTAMP_LEN: usize = 8;
const FILE_LIMIT: usize = RECEIVED_MAGIC.len() + TIMESTAMP_LEN + MAX_BAN_BLOB_SIZE;
static STORAGE: Mutex<()> = Mutex::new(());

pub(super) fn storage_dir(config: &veil_cfg::Config) -> Option<PathBuf> {
    super::issued_bans::sibling_storage_dir(config, ".pnet-received-bans")
}

struct Receipt {
    key: [u8; 32],
    value: Vec<u8>,
    stamp: ReceiptStamp,
    next_backoff: Duration,
}

struct RetryRequest {
    key: [u8; 32],
    stamp: ReceiptStamp,
    next_backoff: Duration,
}

enum WriteBatch {
    Incoming(Vec<Receipt>),
    Retry(Vec<RetryRequest>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ReceiptStamp {
    received_at: u64,
    fingerprint: blake3::Hash,
}

impl ReceiptStamp {
    fn is_live(self, now: u64) -> bool {
        now.saturating_sub(self.received_at) < DEFAULT_TTL.as_secs()
    }
}

#[derive(Clone, Copy)]
enum StorageStatus {
    Queued,
    Deferred { due: Instant, backoff: Duration },
    Saved,
}

struct TrackedReceipt {
    stamp: ReceiptStamp,
    status: StorageStatus,
}

#[derive(Default)]
struct QueueState {
    known: HashMap<[u8; 32], TrackedReceipt>,
    scheduled: BTreeSet<(Instant, [u8; 32])>,
    deferred: u64,
    full: u64,
}

impl QueueState {
    fn track(&mut self, key: [u8; 32], stamp: ReceiptStamp, status: StorageStatus) {
        if let Some(previous) = self.known.insert(key, TrackedReceipt { stamp, status })
            && let StorageStatus::Deferred { due, .. } = previous.status
        {
            self.scheduled.remove(&(due, key));
        }
        if let StorageStatus::Deferred { due, .. } = status {
            self.scheduled.insert((due, key));
        }
    }

    fn for_receipt(&mut self, receipt: &Receipt) -> Option<&mut TrackedReceipt> {
        self.known
            .get_mut(&receipt.key)
            .filter(|tracked| tracked.stamp == receipt.stamp)
    }

    fn expire(&mut self, unix_now: u64) {
        self.known
            .retain(|_, tracked| tracked.stamp.is_live(unix_now));
        self.scheduled
            .retain(|(_, key)| self.known.contains_key(key));
    }

    fn take_retries(&mut self, now: Instant, unix_now: u64) -> Vec<RetryRequest> {
        let mut ready = Vec::new();
        while ready.len() < BATCH_SIZE
            && let Some(&(due, key)) = self.scheduled.first()
            && due <= now
        {
            self.scheduled.pop_first();
            let Some(tracked) = self.known.get_mut(&key) else {
                continue;
            };
            if !tracked.stamp.is_live(unix_now) {
                self.known.remove(&key);
                continue;
            }
            let StorageStatus::Deferred { backoff, .. } = tracked.status else {
                continue;
            };
            tracked.status = StorageStatus::Queued;
            ready.push(RetryRequest {
                key,
                stamp: tracked.stamp,
                next_backoff: (backoff * 2).min(MAX_RETRY),
            });
        }
        ready
    }
}

pub(super) struct ReceivedBanSender {
    tx: mpsc::Sender<Receipt>,
    state: Arc<Mutex<QueueState>>,
    logger: Arc<NodeLogger>,
}

impl ReceivedBanSender {
    /// Called from the session dispatcher. No filesystem work runs here.
    pub(super) fn record(&self, key: [u8; 32], value: &[u8]) {
        let stamp = ReceiptStamp {
            received_at: unix_secs_now_u64(),
            fingerprint: blake3::hash(value),
        };
        let mut state = lock!(self.state);
        if state.known.get(&key).is_some_and(|known| {
            known.stamp.fingerprint == stamp.fingerprint && known.stamp.is_live(stamp.received_at)
        }) {
            return;
        }
        if state.known.len() == MAX_BAN_LIST_SIZE && !state.known.contains_key(&key) {
            state.full = state.full.saturating_add(1);
            let full = state.full;
            drop(state);
            if full.is_power_of_two() {
                self.logger.warn(
                    "network.ban.received_storage.backlog_full",
                    format!("dropped={full}"),
                );
            }
            return;
        }
        let permit = match self.tx.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Closed(())) => return,
            Err(mpsc::error::TrySendError::Full(())) => {
                state.track(
                    key,
                    stamp,
                    StorageStatus::Deferred {
                        due: Instant::now() + FIRST_RETRY,
                        backoff: FIRST_RETRY,
                    },
                );
                state.deferred = state.deferred.saturating_add(1);
                let deferred = state.deferred;
                drop(state);
                if deferred.is_power_of_two() {
                    self.logger.warn(
                        "network.ban.received_storage.deferred",
                        format!("queued_for_retry={deferred}"),
                    );
                }
                return;
            }
        };
        state.track(key, stamp, StorageStatus::Queued);
        permit.send(Receipt {
            key,
            value: value.to_vec(),
            stamp,
            next_backoff: FIRST_RETRY,
        });
    }
}

pub(super) struct ReceivedBanWriter {
    rx: mpsc::Receiver<Receipt>,
    dir: PathBuf,
    state: Arc<Mutex<QueueState>>,
    gate: Arc<NetworkAccessGate>,
    logger: Arc<NodeLogger>,
}

impl ReceivedBanWriter {
    pub(super) fn channel(
        dir: PathBuf,
        gate: &Arc<NetworkAccessGate>,
        logger: &Arc<NodeLogger>,
    ) -> (ReceivedBanSender, Self) {
        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        let state = Arc::new(Mutex::new(QueueState::default()));
        let sender = ReceivedBanSender {
            tx,
            state: Arc::clone(&state),
            logger: Arc::clone(logger),
        };
        (
            sender,
            Self {
                rx,
                dir,
                state,
                gate: Arc::clone(gate),
                logger: Arc::clone(logger),
            },
        )
    }

    pub(super) async fn run(
        mut self,
        dht: Arc<KademliaService>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut cleanup = tokio::time::interval_at(
            tokio::time::Instant::now() + CLEANUP_INTERVAL,
            CLEANUP_INTERVAL,
        );
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut retry = tokio::time::interval_at(Instant::now() + FIRST_RETRY, FIRST_RETRY);
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let has_retries = !lock!(self.state).scheduled.is_empty();
            let batch = tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                _ = cleanup.tick() => {
                    lock!(self.state).expire(unix_secs_now_u64());
                    let dir = self.dir.clone();
                    match tokio::task::spawn_blocking(move || prune_expired(&dir, unix_secs_now_u64())).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => self.logger.warn("network.ban.received_storage.cleanup_failed", error.to_string()),
                        Err(error) => self.logger.warn("network.ban.received_storage.cleanup_failed", error.to_string()),
                    }
                    continue;
                }
                _ = retry.tick(), if has_retries => {
                    let ready = lock!(self.state).take_retries(Instant::now(), unix_secs_now_u64());
                    if ready.is_empty() { continue; }
                    WriteBatch::Retry(ready)
                }
                first = self.rx.recv() => {
                    let Some(first) = first else { break };
                    let mut batch = Vec::with_capacity(BATCH_SIZE);
                    batch.push(first);
                    while batch.len() < BATCH_SIZE {
                        let Ok(receipt) = self.rx.try_recv() else { break };
                        batch.push(receipt);
                    }
                    WriteBatch::Incoming(batch)
                }
            };
            let dir = self.dir.clone();
            let gate = Arc::clone(&self.gate);
            let state = Arc::clone(&self.state);
            let logger = Arc::clone(&self.logger);
            let dht = Arc::clone(&dht);
            let saved = tokio::task::spawn_blocking(move || {
                let batch = match batch {
                    WriteBatch::Incoming(batch) => batch,
                    WriteBatch::Retry(ready) => {
                        load_retry_batch(&dht, &gate, &state, &logger, ready)
                    }
                };
                if batch.is_empty() {
                    return 0;
                }
                let mut saved = 0;
                let mut failed = 0;
                let mut first_error = None;
                let results = save_batch(&dir, &gate, &batch);
                let mut state = lock!(state);
                for (receipt, result) in batch.iter().zip(results) {
                    match result {
                        Ok(written) => {
                            saved += usize::from(written);
                            if let Some(tracked) = state.for_receipt(receipt) {
                                tracked.status = StorageStatus::Saved;
                            }
                        }
                        Err(error) => {
                            failed += 1;
                            if first_error.is_none() {
                                first_error = Some(error);
                            }
                            if state.for_receipt(receipt).is_some() {
                                state.track(
                                    receipt.key,
                                    receipt.stamp,
                                    StorageStatus::Deferred {
                                        due: Instant::now() + receipt.next_backoff,
                                        backoff: receipt.next_backoff,
                                    },
                                );
                            }
                        }
                    }
                }
                drop(state);
                if let Some(error) = first_error {
                    logger.warn(
                        "network.ban.received_storage.failed",
                        format!("records={failed} error={error}"),
                    );
                }
                saved
            })
            .await;
            match saved {
                Ok(saved) if saved > 0 => self.logger.info(
                    "network.ban.received_storage.saved",
                    format!("records={saved}"),
                ),
                Err(error) => self
                    .logger
                    .warn("network.ban.received_storage.failed", error.to_string()),
                _ => {}
            }
        }
    }
}

fn load_retry_batch(
    dht: &KademliaService,
    gate: &NetworkAccessGate,
    state: &Mutex<QueueState>,
    logger: &NodeLogger,
    ready: Vec<RetryRequest>,
) -> Vec<Receipt> {
    let mut batch = Vec::with_capacity(ready.len());
    let mut missing = 0;
    for RetryRequest {
        key,
        stamp,
        next_backoff,
    } in ready
    {
        if let Some(value) = dht.peek_value(&key)
            && blake3::hash(&value) == stamp.fingerprint
            && gate.verify_ban_record(&key, &value)
        {
            batch.push(Receipt {
                key,
                value,
                stamp,
                next_backoff,
            });
            continue;
        }
        let mut state = lock!(state);
        if state
            .known
            .get(&key)
            .is_some_and(|tracked| tracked.stamp == stamp)
        {
            state.known.remove(&key);
            missing += 1;
        }
    }
    if missing > 0 {
        logger.warn(
            "network.ban.received_storage.retry_source_unavailable",
            format!("records={missing}"),
        );
    }
    batch
}

fn receipt_parts(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (timestamp, value) = bytes
        .strip_prefix(RECEIVED_MAGIC)?
        .split_at_checked(TIMESTAMP_LEN)?;
    Some((u64::from_be_bytes(timestamp.try_into().ok()?), value))
}

fn prune_expired(dir: &Path, now: u64) -> io::Result<()> {
    let _storage = lock!(STORAGE);
    if !directory_exists(dir)? {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if entry_key(&path).is_none() {
            continue;
        }
        let Some(mut file) = open_record(&path)? else {
            continue;
        };
        let mut header = [0; RECEIVED_MAGIC.len() + TIMESTAMP_LEN];
        let read = file.read_exact(&mut header);
        drop(file);
        if read.is_ok()
            && let Some((received_at, _)) = receipt_parts(&header)
            && now.saturating_sub(received_at) >= DEFAULT_TTL.as_secs()
        {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn read_record(
    path: &Path,
    key: [u8; 32],
    gate: &NetworkAccessGate,
    now: u64,
) -> io::Result<Option<DhtValueSnapshot>> {
    let bytes = match read_record_bytes(path, FILE_LIMIT) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(None),
        Err(error) => return Err(error),
    };
    let record = receipt_parts(&bytes).and_then(|(received_at, value)| {
        let age_secs = now.checked_sub(received_at)?;
        (age_secs < DEFAULT_TTL.as_secs() && gate.verify_ban_record(&key, value)).then(|| {
            DhtValueSnapshot {
                key,
                value: value.to_vec(),
                origin: veil_dht::store::ORIGIN_INTERNAL,
                age_secs,
            }
        })
    });
    Ok(record)
}

fn save_batch(dir: &Path, gate: &NetworkAccessGate, batch: &[Receipt]) -> Vec<io::Result<bool>> {
    let _storage = lock!(STORAGE);
    let prepared = ensure_directory(dir);
    let now = unix_secs_now_u64();
    let mut file_count = None;
    batch
        .iter()
        .map(|receipt| {
            if !receipt.stamp.is_live(now) {
                return Ok(false);
            }
            match &prepared {
                Ok(()) => save_record(dir, gate, now, receipt, &mut file_count),
                Err(error) => Err(io::Error::other(error.to_string())),
            }
        })
        .collect()
}

fn save_record(
    dir: &Path,
    gate: &NetworkAccessGate,
    now: u64,
    receipt: &Receipt,
    file_count: &mut Option<usize>,
) -> io::Result<bool> {
    let path = dir.join(format!("{}.pban", veil_util::bytes_to_hex(&receipt.key)));
    let new_file = match read_record(&path, receipt.key, gate, now) {
        Ok(Some(current)) => {
            if current.value == receipt.value {
                return Ok(false);
            }
            let current = decode_ban_blob(&current.value).map_err(io::Error::other)?;
            let incoming = decode_ban_blob(&receipt.value).map_err(io::Error::other)?;
            if current.issued_at_unix > incoming.issued_at_unix {
                return Ok(false);
            }
            false
        }
        Ok(None) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => return Err(error),
    };
    if new_file {
        if file_count.is_none() {
            let mut count = 0;
            for entry in fs::read_dir(dir)? {
                count += usize::from(entry_key(&entry?.path()).is_some());
            }
            *file_count = Some(count);
        }
        if *file_count == Some(MAX_BAN_LIST_SIZE) {
            // Space is reclaimed only from unusable records. An active
            // signed revocation can continue blocking a peer after restart.
            let victim = fs::read_dir(dir)?.find_map(|entry| {
                let path = entry.ok()?.path();
                let key = entry_key(&path)?;
                matches!(read_record(&path, key, gate, now), Ok(None)).then_some(path)
            });
            if let Some(victim) = victim {
                fs::remove_file(victim)?;
                *file_count = Some(MAX_BAN_LIST_SIZE - 1);
            }
        }
        if file_count.is_some_and(|count| count >= MAX_BAN_LIST_SIZE) {
            return Err(io::Error::other("received P-Net ban storage is full"));
        }
    }
    let mut bytes = Vec::with_capacity(RECEIVED_MAGIC.len() + TIMESTAMP_LEN + receipt.value.len());
    bytes.extend_from_slice(RECEIVED_MAGIC);
    bytes.extend_from_slice(&receipt.stamp.received_at.to_be_bytes());
    bytes.extend_from_slice(&receipt.value);
    veil_util::atomic_write_owner_only(&path, &bytes)?;
    if new_file && let Some(count) = file_count {
        *count += 1;
    }
    Ok(true)
}

pub(super) fn load(
    dir: &Path,
    gate: &NetworkAccessGate,
    logger: &NodeLogger,
) -> io::Result<Vec<DhtValueSnapshot>> {
    let _storage = lock!(STORAGE);
    if !directory_exists(dir)? {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    let mut failed = 0;
    let now = unix_secs_now_u64();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let Some(key) = entry_key(&path) else {
            continue;
        };
        if records.len() == MAX_BAN_LIST_SIZE {
            logger.warn(
                "network.ban.received_storage.limit",
                "restored the maximum number of records",
            );
            break;
        }
        match read_record(&path, key, gate, now) {
            Ok(Some(record)) => records.push(record),
            Ok(None) => {}
            Err(_) => failed += 1,
        }
    }
    if failed > 0 {
        logger.warn(
            "network.ban.received_storage.load_failed",
            format!("records={failed}"),
        );
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_write_queue_keeps_a_retry_without_another_network_copy() {
        let gate = Arc::new(NetworkAccessGate {
            local_cert_blob: Vec::new(),
            expected_network_id: [1; 32],
            owner_algo: veil_types::SignatureAlgorithm::Ed25519,
            owner_pubkey_bytes: Vec::new(),
            admin_node_ids: Default::default(),
        });
        let logger = Arc::new(NodeLogger::new_noop());
        let (sender, writer) = ReceivedBanWriter::channel(PathBuf::new(), &gate, &logger);
        for i in 0..QUEUE_CAPACITY {
            let mut key = [0; 32];
            key[..2].copy_from_slice(&(i as u16).to_be_bytes());
            sender.record(key, b"payload");
        }
        sender.record([0; 32], b"payload");
        assert_eq!(writer.rx.len(), QUEUE_CAPACITY);
        assert_eq!(lock!(sender.state).deferred, 0);

        let deferred_key = [255; 32];
        sender.record(deferred_key, b"new payload");
        assert_eq!(writer.rx.len(), QUEUE_CAPACITY);
        let mut state = lock!(sender.state);
        assert_eq!(state.deferred, 1);
        let &(due, key) = state.scheduled.first().unwrap();
        assert_eq!(key, deferred_key);
        let received_at = state.known[&key].stamp.received_at;
        assert!(
            state
                .take_retries(due - Duration::from_millis(1), received_at)
                .is_empty()
        );
        let retry = state.take_retries(due, received_at).pop().unwrap();
        assert_eq!(retry.key, deferred_key);
        assert_eq!(retry.stamp.fingerprint, blake3::hash(b"new payload"));
        assert_eq!(retry.stamp.received_at, received_at);
        assert!(state.scheduled.is_empty());
    }

    #[test]
    fn cleanup_removes_only_expired_receipts() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("received");
        ensure_directory(&dir).unwrap();
        let now = 10_000;
        let expired = dir.join(format!("{}.pban", "01".repeat(32)));
        let current = dir.join(format!("{}.pban", "02".repeat(32)));
        let unrelated = dir.join("operator-file");
        for (path, timestamp) in [
            (&expired, now - DEFAULT_TTL.as_secs()),
            (&current, now),
            (&unrelated, 0),
        ] {
            let mut bytes = RECEIVED_MAGIC.to_vec();
            bytes.extend_from_slice(&timestamp.to_be_bytes());
            fs::write(path, bytes).unwrap();
        }
        prune_expired(&dir, now).unwrap();
        assert!(!expired.exists());
        assert!(current.exists());
        assert!(unrelated.exists());
    }
}
