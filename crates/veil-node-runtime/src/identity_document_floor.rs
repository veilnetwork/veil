//! Persistent negative authorization evidence. Stored documents never grant
//! rights: incoming material still needs a fresh, fully verified document.
use std::{
    collections::HashMap,
    io::Read,
    path::{Path, PathBuf},
    sync::Mutex,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use veil_identity::verify::{verify_identity_document, verify_identity_document_bindings};
use veil_proto::{
    budget::MAX_PEER_MLKEM_CACHE,
    identity_document::{IdentityDocument, MAX_IDENTITY_DOCUMENT_BYTES},
};
use veil_util::lock;

use crate::runtime::persistence::{next_snapshot_seq, write_snapshot_ordered};

struct Floor {
    document: IdentityDocument,
    digest: [u8; 32],
    touched: u64,
    changed_revision: u64,
}

#[derive(Default)]
struct State {
    rows: HashMap<[u8; 32], Floor>,
    clock: u64,
    dirty: bool,
    unreadable: bool,
    revision: u64,
    host_restored: bool,
    durable_revision: u64,
}

pub(crate) const MAX_HOST_SNAPSHOT_BYTES: usize =
    MAX_PEER_MLKEM_CACHE * (MAX_IDENTITY_DOCUMENT_BYTES.div_ceil(3) * 4 + 160) + 128;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostSnapshot {
    version: u8,
    entries: Vec<HostEntry>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostEntry {
    peer: String,
    document: String,
}

pub(crate) struct IdentityDocumentFloor {
    path: Option<PathBuf>,
    state: Mutex<State>,
    checkpointed: tokio::sync::Notify,
}

impl IdentityDocumentFloor {
    pub(crate) fn is_pending(&self, peer: &[u8; 32]) -> bool {
        let state = lock!(self.state);
        !state.unreadable
            && state.host_restored
            && state
                .rows
                .get(peer)
                .is_some_and(|floor| floor.changed_revision > state.durable_revision)
    }

    pub(crate) fn is_durable(&self, peer: &[u8; 32]) -> bool {
        let state = lock!(self.state);
        !state.unreadable
            && (!state.host_restored
                || state
                    .rows
                    .get(peer)
                    .is_some_and(|floor| floor.changed_revision <= state.durable_revision))
    }

    pub(crate) fn acknowledge_host(&self, revision: u64) -> Result<(), String> {
        let mut state = lock!(self.state);
        if !state.host_restored || revision > state.revision {
            return Err("invalid peer authorization checkpoint revision".into());
        }
        state.durable_revision = state.durable_revision.max(revision);
        drop(state);
        self.checkpointed.notify_waiters();
        Ok(())
    }

    pub(crate) async fn wait_durable(&self, peer: &[u8; 32], timeout: std::time::Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.checkpointed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_durable(peer) {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return false;
            }
        }
    }
    pub(crate) fn revision(&self) -> u64 {
        lock!(self.state).revision
    }

    pub(crate) fn export_host(&self) -> Result<(u64, Vec<u8>), String> {
        let state = lock!(self.state);
        if state.unreadable {
            return Err("peer authorization state is unreadable".into());
        }
        let mut entries: Vec<_> = state
            .rows
            .values()
            .map(|floor| HostEntry {
                peer: veil_util::bytes_to_hex(&floor.document.node_id),
                document: STANDARD.encode(floor.document.encode()),
            })
            .collect();
        entries.sort_by(|a, b| a.peer.cmp(&b.peer));
        let bytes = serde_json::to_vec(&HostSnapshot {
            version: 1,
            entries,
        })
        .map_err(|_| "peer authorization state serialization failed")?;
        Ok((state.revision, bytes))
    }

    /// Install the host's durable negative evidence before application traffic.
    /// Any documents learned during native boot are replayed *against* that
    /// baseline, so a stale replica seen before restore cannot veto a known
    /// revocation with a larger attacker-chosen issued_at timestamp.
    pub(crate) fn import_host(&self, bytes: &[u8], now: u64) -> Result<(), String> {
        if self.path.is_some() {
            return Err("host restore requires a memory-only runtime".into());
        }
        if bytes.len() > MAX_HOST_SNAPSHOT_BYTES {
            return Err("peer authorization snapshot exceeds budget".into());
        }
        let snapshot: HostSnapshot =
            serde_json::from_slice(bytes).map_err(|_| "malformed peer authorization snapshot")?;
        if snapshot.version != 1 || snapshot.entries.len() > MAX_PEER_MLKEM_CACHE {
            return Err("unsupported peer authorization snapshot".into());
        }
        let mut restored = State::default();
        for entry in snapshot.entries {
            if entry.document.len() > MAX_IDENTITY_DOCUMENT_BYTES.div_ceil(3) * 4 {
                return Err("oversized peer authorization record".into());
            }
            let bytes = STANDARD
                .decode(entry.document)
                .map_err(|_| "malformed peer authorization record")?;
            let document = IdentityDocument::decode(&bytes)
                .map_err(|_| "malformed peer authorization document")?;
            if entry.peer != veil_util::bytes_to_hex(&document.node_id)
                || verify_identity_document_bindings(&document).is_err()
            {
                return Err("unverified peer authorization document".into());
            }
            let peer = document.node_id;
            if restored.rows.contains_key(&peer) {
                return Err("duplicate peer authorization document".into());
            }
            restored.clock += 1;
            restored.rows.insert(
                peer,
                Floor {
                    document,
                    digest: *blake3::hash(&bytes).as_bytes(),
                    touched: restored.clock,
                    changed_revision: 0,
                },
            );
        }
        let mut state = lock!(self.state);
        // Restore is a one-time boot operation. Calling it after a checkpoint
        // could otherwise undo a revocation learned during this process.
        if state.host_restored {
            return Err("peer authorization host state was already restored".into());
        }
        let transient: Vec<_> = state.rows.values().map(|r| r.document.clone()).collect();
        restored.revision = state.revision.saturating_add(1);
        restored.host_restored = true;
        *state = restored;
        for doc in transient {
            self.observe_locked(&mut state, &doc, now);
        }
        Ok(())
    }
    pub(crate) fn current(&self, peer: &[u8; 32]) -> Option<IdentityDocument> {
        lock!(self.state)
            .rows
            .get(peer)
            .map(|floor| floor.document.clone())
    }

    pub(crate) fn allows_cert(
        &self,
        peer: &[u8; 32],
        cert: &veil_identity::mlkem_fanout::VerifiedMlkemCert,
        now: u64,
    ) -> bool {
        let state = lock!(self.state);
        if state.unreadable {
            return false;
        }
        let Some(floor) = state.rows.get(peer) else {
            return true;
        };
        let doc = &floor.document;
        (!state.host_restored || floor.changed_revision <= state.durable_revision)
            && doc.valid_until_unix >= now
            && cert.device_id.is_some_and(|device| {
                !doc.revoked_devices.iter().any(|r| r.device_id == device)
                    && doc.identity_keys.iter().any(|key| {
                        key.device_id == device
                            && key.valid_from_unix <= now
                            && now <= key.valid_until_unix
                    })
            })
    }

    pub(crate) fn ephemeral() -> Self {
        Self {
            path: None,
            state: Mutex::new(State::default()),
            checkpointed: tokio::sync::Notify::new(),
        }
    }

    pub(crate) fn load(config: &Path) -> Self {
        let path = config
            .parent()
            .unwrap_or(Path::new("."))
            .join("peer_identity_floors.json");
        let mut state = State::default();
        // Bound even malformed local snapshots before allocating/deserializing.
        let cap = MAX_PEER_MLKEM_CACHE * (MAX_IDENTITY_DOCUMENT_BYTES * 4 / 3 + 32);
        let load = || -> Result<Option<Vec<String>>, Box<dyn std::error::Error>> {
            let file = match std::fs::File::open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error.into()),
            };
            let mut bytes = Vec::new();
            file.take(cap as u64 + 1).read_to_end(&mut bytes)?;
            if bytes.len() > cap {
                return Err("identity floor snapshot exceeds budget".into());
            }
            Ok(Some(serde_json::from_slice(&bytes)?))
        };
        let result = load().and_then(|rows| {
            let Some(rows) = rows else {
                return Ok(());
            };
            if rows.len() > MAX_PEER_MLKEM_CACHE {
                return Err("too many identity floors".into());
            }
            for encoded in rows {
                if encoded.len() > MAX_IDENTITY_DOCUMENT_BYTES.div_ceil(3) * 4 {
                    return Err("oversized identity floor".into());
                }
                let bytes = STANDARD.decode(encoded)?;
                let document = IdentityDocument::decode(&bytes)?;
                // Historical evidence can be expired. Check all signatures and
                // bindings, never use it as a current delegation or certificate.
                verify_identity_document_bindings(&document)?;
                let node = document.node_id;
                if state.rows.contains_key(&node) {
                    return Err("duplicate identity floor".into());
                }
                state.clock += 1;
                state.rows.insert(
                    node,
                    Floor {
                        digest: *blake3::hash(&bytes).as_bytes(),
                        document,
                        touched: state.clock,
                        changed_revision: 0,
                    },
                );
            }
            Ok(())
        });
        if let Err(error) = result {
            // This is security state, unlike a disposable cert cache. Do not
            // silently turn corruption into permission to accept old keys.
            log::warn!(
                "identity floor snapshot unavailable; peer document authorization refused: {error}"
            );
            state.unreadable = true;
        }
        state.revision = u64::from(!state.rows.is_empty());
        Self {
            path: Some(path),
            state: Mutex::new(state),
            checkpointed: tokio::sync::Notify::new(),
        }
    }

    pub(crate) fn observe(&self, doc: &IdentityDocument, now: u64) -> bool {
        let mut state = lock!(self.state);
        self.observe_locked(&mut state, doc, now)
    }

    fn observe_locked(&self, state: &mut State, doc: &IdentityDocument, now: u64) -> bool {
        if state.unreadable || doc.valid_until_unix < now {
            return false;
        }
        let bytes = doc.encode();
        let digest = *blake3::hash(&bytes).as_bytes();
        if let Some(previous) = state.rows.get(&doc.node_id) {
            if doc.issued_at_unix < previous.document.issued_at_unix
                || previous.document.revoked_devices.iter().any(|revoked| {
                    !doc.revoked_devices
                        .iter()
                        .any(|r| r.device_id == revoked.device_id)
                })
            {
                return false;
            }
            if previous.digest == digest {
                state.clock = state.clock.saturating_add(1);
                let touched = state.clock;
                state.rows.get_mut(&doc.node_id).unwrap().touched = touched;
                self.flush(state);
                return true;
            }
        }
        if verify_identity_document(doc, now).is_err() {
            return false;
        }
        if !state.rows.contains_key(&doc.node_id) && state.rows.len() >= MAX_PEER_MLKEM_CACHE {
            // Never forget a revocation to accommodate unrelated traffic.
            // If every slot carries tombstones, refuse new identities instead.
            let victim = state
                .rows
                .iter()
                .filter(|(_, floor)| floor.document.revoked_devices.is_empty())
                .min_by_key(|(_, floor)| floor.touched)
                .map(|(node, _)| *node);
            let Some(victim) = victim else {
                return false;
            };
            state.rows.remove(&victim);
        }
        state.clock = state.clock.saturating_add(1);
        let touched = state.clock;
        let revision = state.revision.saturating_add(1);
        state.rows.insert(
            doc.node_id,
            Floor {
                document: doc.clone(),
                digest,
                touched,
                changed_revision: revision,
            },
        );
        state.dirty = true;
        state.revision = revision;
        self.flush(state);
        true
    }

    fn flush(&self, state: &mut State) {
        let Some(path) = &self.path else {
            return;
        };
        if !state.dirty {
            return;
        }
        let snapshot: Vec<_> = state
            .rows
            .values()
            .map(|floor| STANDARD.encode(floor.document.encode()))
            .collect();
        // Hold the state lock across the ordered atomic publication. A failed
        // write retains the floor in RAM and retries on the next observation.
        state.dirty =
            !write_snapshot_ordered(path, &snapshot, "peer identity floors", next_snapshot_seq())
                .is_durable();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use veil_crypto::identity::{certify_message, compute_node_id};
    use veil_proto::identity_document::{
        ALGO_ED25519, DOC_SIG_CONTEXT, IdentityKey, RevokedDevice,
    };

    fn document(index: u64, issued: u64, revoked: bool) -> IdentityDocument {
        let master = SigningKey::from_bytes(&blake3::derive_key(
            "floor test master",
            &index.to_le_bytes(),
        ));
        let sub = SigningKey::from_bytes(&blake3::derive_key(
            "floor test device",
            &index.to_le_bytes(),
        ));
        let node_id = compute_node_id(master.verifying_key().as_bytes());
        let pubkey = sub.verifying_key().to_bytes();
        let device_id = compute_node_id(&pubkey);
        let expires = issued + 1_000_000;
        let mut doc = IdentityDocument {
            node_id,
            master_algo: ALGO_ED25519,
            master_pubkey: master.verifying_key().to_bytes().to_vec(),
            issued_at_unix: issued,
            valid_until_unix: expires,
            sig_key_idx: 0,
            identity_keys: vec![IdentityKey {
                algo: ALGO_ED25519,
                pubkey: pubkey.to_vec(),
                device_id,
                valid_from_unix: 1,
                valid_until_unix: expires,
                master_sig: master
                    .sign(&certify_message(
                        &node_id,
                        ALGO_ED25519,
                        &pubkey,
                        &device_id,
                        1,
                        expires,
                    ))
                    .to_bytes()
                    .to_vec(),
            }],
            revoked_devices: if revoked {
                vec![RevokedDevice {
                    device_id: [0xf0; 32],
                    master_sig: master
                        .sign(&RevokedDevice::signing_message(&node_id, &[0xf0; 32]))
                        .to_bytes()
                        .to_vec(),
                }]
            } else {
                vec![]
            },
            document_sig: vec![],
        };
        let mut message = DOC_SIG_CONTEXT.to_vec();
        message.extend_from_slice(&doc.canonical_signing_bytes());
        doc.document_sig = sub.sign(&message).to_bytes().to_vec();
        doc
    }

    #[test]
    fn host_restore_precedes_transient_boot_replica_even_with_a_larger_timestamp() {
        let durable = IdentityDocumentFloor::ephemeral();
        let known = document(7, 1000, true);
        assert!(durable.observe(&known, 1000));
        let (_, bytes) = durable.export_host().unwrap();
        let boot = IdentityDocumentFloor::ephemeral();
        let stale = document(7, 1001, false);
        assert!(boot.observe(&stale, 1001));
        boot.import_host(&bytes, 1001).unwrap();
        assert!(!boot.observe(&stale, 1001));
        assert_eq!(
            boot.current(&known.node_id).unwrap().revoked_devices.len(),
            1
        );
        assert!(boot.observe(&document(7, 1002, true), 1002));
        assert!(
            boot.import_host(&bytes, 1002).is_err(),
            "restore must not roll back a running node twice"
        );
    }

    #[test]
    fn host_restore_replays_newer_compatible_boot_observations() {
        let durable = IdentityDocumentFloor::ephemeral();
        assert!(durable.observe(&document(7, 1000, true), 1000));
        let (_, bytes) = durable.export_host().unwrap();
        let boot = IdentityDocumentFloor::ephemeral();
        let newer = document(7, 1010, true);
        assert!(boot.observe(&newer, 1010));
        boot.import_host(&bytes, 1010).unwrap();
        assert_eq!(boot.current(&newer.node_id).unwrap().issued_at_unix, 1010);
    }

    #[test]
    fn expired_host_document_remains_negative_evidence_without_granting_rights() {
        let durable = IdentityDocumentFloor::ephemeral();
        let old = document(7, 1000, true);
        assert!(durable.observe(&old, 1000));
        let (_, bytes) = durable.export_host().unwrap();
        let boot = IdentityDocumentFloor::ephemeral();
        let now = old.valid_until_unix + 1;
        boot.import_host(&bytes, now).unwrap();
        assert!(!boot.observe(&document(7, now, false), now));
        assert!(boot.observe(&document(7, now, true), now));
    }

    #[test]
    fn failed_host_import_is_transactional_and_does_not_consume_the_restore() {
        let durable = IdentityDocumentFloor::ephemeral();
        let doc = document(7, 1000, true);
        assert!(durable.observe(&doc, 1000));
        let (_, good) = durable.export_host().unwrap();
        let mut mismatched: serde_json::Value = serde_json::from_slice(&good).unwrap();
        mismatched["entries"][0]["peer"] = serde_json::Value::String("00".repeat(32));
        let bad = serde_json::to_vec(&mismatched).unwrap();
        let boot = IdentityDocumentFloor::ephemeral();
        assert!(boot.observe(&document(8, 1000, false), 1000));
        let before = boot.export_host().unwrap();
        for input in [b"not JSON".as_slice(), bad.as_slice()] {
            assert!(boot.import_host(input, 1000).is_err());
            assert_eq!(boot.export_host().unwrap(), before);
        }
        boot.import_host(&good, 1000).unwrap();
        assert!(!boot.observe(&document(7, 1001, false), 1001));
    }

    #[test]
    fn host_revision_moves_only_when_authorization_changes() {
        let store = IdentityDocumentFloor::ephemeral();
        assert_eq!(store.revision(), 0);
        let doc = document(7, 1000, false);
        assert!(store.observe(&doc, 1000));
        let first = store.revision();
        for _ in 0..100 {
            assert!(store.observe(&doc, 1000));
        }
        assert_eq!(store.revision(), first);
        assert!(store.observe(&document(7, 1001, true), 1001));
        assert!(store.revision() > first);
    }

    #[test]
    fn cache_pressure_never_forgets_a_revocation() {
        let store = IdentityDocumentFloor::ephemeral();
        let revoked = document(0, 1000, true);
        assert!(store.observe(&revoked, 1000));
        for index in 1..=MAX_PEER_MLKEM_CACHE as u64 + 16 {
            assert!(store.observe(&document(index, 1000, false), 1000));
        }
        assert_eq!(lock!(store.state).rows.len(), MAX_PEER_MLKEM_CACHE);
        assert!(!store.observe(&document(0, 999, false), 1000));
        assert!(!store.observe(&document(0, 1001, false), 1001));
        assert!(store.observe(&document(0, 1001, true), 1001));
    }

    #[tokio::test]
    async fn host_commit_gates_new_authorization_and_wakes_waiters() {
        let store = std::sync::Arc::new(IdentityDocumentFloor::ephemeral());
        assert!(store.acknowledge_host(0).is_err());
        store
            .import_host(br#"{"version":1,"entries":[]}"#, 1000)
            .unwrap();
        let doc = document(17, 1000, false);
        assert!(!store.is_pending(&doc.node_id));
        assert!(store.observe(&doc, 1000));
        let revision = store.export_host().unwrap().0;
        assert!(store.is_pending(&doc.node_id));
        assert!(!store.is_durable(&doc.node_id));
        let cert = veil_identity::mlkem_fanout::VerifiedMlkemCert {
            node_id: doc.node_id,
            device_id: Some(doc.identity_keys[0].device_id),
            instance_id: [1; 16],
            mlkem_algo: 1,
            mlkem_pubkey: vec![1; 32],
            ratchet_x25519_pubkey: [2; 32],
            cert_version: 1,
            valid_until_unix: doc.valid_until_unix,
        };
        assert!(!store.allows_cert(&doc.node_id, &cert, 1000));
        let waiting = {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .wait_durable(&doc.node_id, std::time::Duration::from_secs(1))
                    .await
            })
        };
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        assert!(store.acknowledge_host(revision + 1).is_err());
        store.acknowledge_host(revision).unwrap();
        assert!(waiting.await.unwrap());
        assert!(store.is_durable(&doc.node_id));
        assert!(store.allows_cert(&doc.node_id, &cert, 1000));
        assert!(!store.is_pending(&doc.node_id));
        let newer = document(17, 1001, true);
        assert!(store.observe(&newer, 1001));
        store.acknowledge_host(revision).unwrap();
        assert!(
            !store.is_durable(&doc.node_id),
            "old ACK must not unlock a newer floor"
        );
        assert!(
            !store
                .wait_durable(&doc.node_id, std::time::Duration::from_millis(1))
                .await
        );
        store.acknowledge_host(store.revision()).unwrap();
        assert!(store.is_durable(&doc.node_id));
        assert!(!store.observe(&doc, 1001));
    }

    #[test]
    fn host_baseline_is_durable_but_transient_boot_updates_are_not() {
        let baseline = IdentityDocumentFloor::ephemeral();
        let older = document(19, 1000, true);
        assert!(baseline.observe(&older, 1000));
        let bytes = baseline.export_host().unwrap().1;
        let next = IdentityDocumentFloor::ephemeral();
        next.import_host(&bytes, 1000).unwrap();
        assert!(next.is_durable(&older.node_id));
        let boot = IdentityDocumentFloor::ephemeral();
        assert!(boot.observe(&document(19, 1001, true), 1001));
        boot.import_host(&bytes, 1001).unwrap();
        assert!(boot.is_pending(&older.node_id));
        assert!(!boot.is_durable(&older.node_id));
        boot.acknowledge_host(boot.revision()).unwrap();
        assert!(boot.is_durable(&older.node_id));
        assert!(!boot.observe(&older, 1001));
    }

    #[test]
    fn a_full_tombstone_store_refuses_new_peers_without_growing() {
        let store = IdentityDocumentFloor::ephemeral();
        for index in 0..MAX_PEER_MLKEM_CACHE as u64 {
            assert!(store.observe(&document(index, 1000, true), 1000));
        }
        assert!(!store.observe(&document(10000, 1000, false), 1000));
        assert!(store.observe(&document(0, 1001, true), 1001));
        assert_eq!(lock!(store.state).rows.len(), MAX_PEER_MLKEM_CACHE);
    }

    #[test]
    fn restart_retains_both_timestamp_floor_and_grow_only_revocations() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let store = IdentityDocumentFloor::load(&config);
        assert!(store.observe(&document(1, 1000, false), 1000));
        assert!(store.observe(&document(1, 1010, true), 1010));
        drop(store);
        let store = IdentityDocumentFloor::load(&config);
        assert!(!store.observe(&document(1, 1000, false), 1010));
        assert!(!store.observe(&document(1, 1011, false), 1011));
        assert!(store.observe(&document(1, 1011, true), 1011));
    }

    #[test]
    fn malformed_or_unsigned_snapshot_does_not_silently_clear_security_state() {
        for contents in [b"invalid JSON".as_slice(), b"[\"AAAA\"]".as_slice()] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("peer_identity_floors.json"), contents).unwrap();
            let store = IdentityDocumentFloor::load(&dir.path().join("config.toml"));
            assert!(!store.observe(&document(1, 1000, false), 1000));
        }
    }

    #[test]
    fn failed_disk_write_retains_ram_floor_and_retries_identical_document() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let store = IdentityDocumentFloor::load(&config);
        let obstructed = dir.path().join("peer_identity_floors.json");
        std::fs::create_dir(&obstructed).unwrap();
        let current = document(1, 1000, true);
        assert!(store.observe(&current, 1000));
        assert!(lock!(store.state).dirty);
        assert!(!store.observe(&document(1, 999, false), 1000));
        std::fs::remove_dir(&obstructed).unwrap();
        assert!(store.observe(&current, 1000));
        assert!(!lock!(store.state).dirty);
        let restarted = IdentityDocumentFloor::load(&config);
        assert!(!restarted.observe(&document(1, 999, false), 1000));
    }
}
