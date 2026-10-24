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
}

#[derive(Default)]
struct State {
    rows: HashMap<[u8; 32], Floor>,
    clock: u64,
    dirty: bool,
    unreadable: bool,
}

pub(crate) struct IdentityDocumentFloor {
    path: Option<PathBuf>,
    state: Mutex<State>,
}

impl IdentityDocumentFloor {
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
        doc.valid_until_unix >= now
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
        Self {
            path: Some(path),
            state: Mutex::new(state),
        }
    }

    pub(crate) fn observe(&self, doc: &IdentityDocument, now: u64) -> bool {
        let mut state = lock!(self.state);
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
                self.flush(&mut state);
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
        state.rows.insert(
            doc.node_id,
            Floor {
                document: doc.clone(),
                digest,
                touched,
            },
        );
        state.dirty = true;
        self.flush(&mut state);
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
        let mut doc = IdentityDocument {
            node_id,
            master_algo: ALGO_ED25519,
            master_pubkey: master.verifying_key().to_bytes().to_vec(),
            issued_at_unix: issued,
            valid_until_unix: 1_000_000,
            sig_key_idx: 0,
            identity_keys: vec![IdentityKey {
                algo: ALGO_ED25519,
                pubkey: pubkey.to_vec(),
                device_id,
                valid_from_unix: 1,
                valid_until_unix: 1_000_000,
                master_sig: master
                    .sign(&certify_message(
                        &node_id,
                        ALGO_ED25519,
                        &pubkey,
                        &device_id,
                        1,
                        1_000_000,
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
