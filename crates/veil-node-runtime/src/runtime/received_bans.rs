//! Persistence for verified P-Net bans received over the network.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use veil_dht::NetworkAuthGate as _;
use veil_dht::kademlia::{DEFAULT_TTL, DhtValueSnapshot};
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
    received_at: u64,
    fingerprint: blake3::Hash,
}

#[derive(Default)]
struct QueueState {
    known: HashMap<[u8; 32], (blake3::Hash, u64)>,
    dropped: u64,
}

pub(super) struct ReceivedBanSender {
    tx: mpsc::Sender<Receipt>,
    state: Arc<Mutex<QueueState>>,
    logger: Arc<NodeLogger>,
}

impl ReceivedBanSender {
    /// Called from the session dispatcher. No filesystem work runs here.
    pub(super) fn record(&self, key: [u8; 32], value: &[u8]) {
        let now = unix_secs_now_u64();
        let fingerprint = blake3::hash(value);
        let mut state = lock!(self.state);
        if state.known.get(&key).is_some_and(|(known, stored_at)| {
            *known == fingerprint && now.saturating_sub(*stored_at) < DEFAULT_TTL.as_secs()
        }) {
            return;
        }
        let permit = match self.tx.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Closed(())) => return,
            Err(mpsc::error::TrySendError::Full(())) => {
                state.dropped = state.dropped.saturating_add(1);
                let dropped = state.dropped;
                drop(state);
                if dropped.is_power_of_two() {
                    self.logger.warn(
                        "network.ban.received_storage.queue_full",
                        format!("dropped={dropped}"),
                    );
                }
                return;
            }
        };
        if state.known.len() == MAX_BAN_LIST_SIZE && !state.known.contains_key(&key) {
            state
                .known
                .retain(|_, (_, seen)| now.saturating_sub(*seen) < DEFAULT_TTL.as_secs());
        }
        if state.known.len() < MAX_BAN_LIST_SIZE || state.known.contains_key(&key) {
            state.known.insert(key, (fingerprint, now));
        }
        permit.send(Receipt {
            key,
            value: value.to_vec(),
            received_at: now,
            fingerprint,
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

    pub(super) async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        let mut cleanup = tokio::time::interval_at(
            tokio::time::Instant::now() + CLEANUP_INTERVAL,
            CLEANUP_INTERVAL,
        );
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let first = tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                _ = cleanup.tick() => {
                    let dir = self.dir.clone();
                    match tokio::task::spawn_blocking(move || prune_expired(&dir, unix_secs_now_u64())).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => self.logger.warn("network.ban.received_storage.cleanup_failed", error.to_string()),
                        Err(error) => self.logger.warn("network.ban.received_storage.cleanup_failed", error.to_string()),
                    }
                    continue;
                }
                first = self.rx.recv() => first,
            };
            let Some(first) = first else { break };
            let mut batch = Vec::with_capacity(BATCH_SIZE);
            batch.push(first);
            while batch.len() < BATCH_SIZE {
                let Ok(receipt) = self.rx.try_recv() else {
                    break;
                };
                batch.push(receipt);
            }
            let dir = self.dir.clone();
            let gate = Arc::clone(&self.gate);
            let state = Arc::clone(&self.state);
            let logger = Arc::clone(&self.logger);
            let saved = tokio::task::spawn_blocking(move || {
                let (saved, failed) = save_batch(&dir, &gate, batch);
                for (receipt, error) in failed {
                    let mut state = lock!(state);
                    if state.known.get(&receipt.key)
                        == Some(&(receipt.fingerprint, receipt.received_at))
                    {
                        state.known.remove(&receipt.key);
                    }
                    drop(state);
                    logger.warn("network.ban.received_storage.failed", error.to_string());
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

fn save_batch(
    dir: &Path,
    gate: &NetworkAccessGate,
    batch: Vec<Receipt>,
) -> (usize, Vec<(Receipt, io::Error)>) {
    let _storage = lock!(STORAGE);
    let prepared = ensure_directory(dir);
    let now = unix_secs_now_u64();
    let mut file_count = None;
    let mut saved = 0;
    let mut failed = Vec::new();
    for receipt in batch {
        let result = match &prepared {
            Ok(()) => save_record(dir, gate, now, &receipt, &mut file_count),
            Err(error) => Err(io::Error::other(error.to_string())),
        };
        match result {
            Ok(true) => saved += 1,
            Ok(false) => {}
            Err(error) => failed.push((receipt, error)),
        }
    }
    (saved, failed)
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
    bytes.extend_from_slice(&receipt.received_at.to_be_bytes());
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
    fn a_full_write_queue_accepts_replays_of_dropped_records_after_draining() {
        let gate = Arc::new(NetworkAccessGate {
            local_cert_blob: Vec::new(),
            expected_network_id: [1; 32],
            owner_algo: veil_types::SignatureAlgorithm::Ed25519,
            owner_pubkey_bytes: Vec::new(),
            admin_node_ids: Default::default(),
        });
        let logger = Arc::new(NodeLogger::new_noop());
        let (sender, mut writer) = ReceivedBanWriter::channel(PathBuf::new(), &gate, &logger);
        for i in 0..QUEUE_CAPACITY {
            let mut key = [0; 32];
            key[..2].copy_from_slice(&(i as u16).to_be_bytes());
            sender.record(key, b"payload");
        }
        sender.record([0; 32], b"payload");
        assert_eq!(writer.rx.len(), QUEUE_CAPACITY);
        assert_eq!(lock!(sender.state).dropped, 0);

        let previously_dropped = [255; 32];
        sender.record(previously_dropped, b"new payload");
        assert_eq!(lock!(sender.state).dropped, 1);
        assert!(!lock!(sender.state).known.contains_key(&previously_dropped));
        writer.rx.try_recv().unwrap();
        sender.record(previously_dropped, b"new payload");
        assert_eq!(writer.rx.len(), QUEUE_CAPACITY);
        assert!(lock!(sender.state).known.contains_key(&previously_dropped));
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
