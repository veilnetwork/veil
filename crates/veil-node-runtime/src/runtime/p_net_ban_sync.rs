//! P-Net DHT-replicated ban sync.
//!
//! In a private veil network (`[network].mode = "private"`) admin
//! nodes publish signed `BanEntry` records to the DHT at ban time.
//! Each upgraded recipient applies verified STOREs to its in-memory
//! `BanList` as they arrive. Startup and periodic scans also check the
//! local DHT store for revocations.
//!
//! Public-mode nodes never construct this task (gate is `None`), so
//! their bans stay node-local — preserving the user's explicit
//! "publish-only-as-owner" constraint in open networks.

use std::sync::{Arc, Mutex, RwLock};

use veil_abuse::BanList;
use veil_dht::{KademliaService, NetworkAuthGate};
use veil_identity::network_access::NetworkAccessGate;
use veil_identity::network_ban::{
    BAN_BLOB_MAGIC, ban_dht_key, decode_ban_blob, encode_ban_blob, verify_ban_entry,
};
use veil_observability::NodeLogger;
use veil_session::SessionTxRegistry;
use veil_types::{BAN_ENTRY_VERSION, BanEntry};
use veil_util::{lock, wlock};

use super::{NodeRuntime, lock_tasks, supervised_spawn};

/// Cap on the in-flight reason string before signing. The receiver
/// re-checks via `MAX_BAN_REASON_LEN`; clamping at publish time keeps
/// our wire encoder happy.
pub const MAX_PUBLISH_REASON_LEN: usize = veil_types::MAX_BAN_REASON_LEN;

/// Periodic interval at which every member walks its DHT store for
/// PBAN entries and refreshes its local `BanList`. Inexpensive: scan is
/// O(|stored entries|) + small fixed verifies. 60 s strikes a balance
/// between propagation lag and CPU spend on idle clusters.
pub const APPLY_INTERVAL_SECS: u64 = 60;

struct BanStoreGate {
    gate: Arc<NetworkAccessGate>,
    ban_list: Arc<Mutex<BanList>>,
    sessions: Arc<RwLock<SessionTxRegistry>>,
    logger: Arc<NodeLogger>,
}

impl NetworkAuthGate for BanStoreGate {
    fn verify_ban_record(&self, key: &[u8; 32], value: &[u8]) -> bool {
        self.gate.verify_ban_record(key, value)
    }

    fn ban_stored(&self, value: &[u8]) {
        if apply_verified_ban(value, &self.ban_list, &self.sessions) {
            self.logger
                .info("network.ban.applied", "applied=1 source=store");
        }
    }
}

pub(super) fn configure_p_net_bans(
    dht: &mut KademliaService,
    gate: &Arc<NetworkAccessGate>,
    ban_list: &Arc<Mutex<BanList>>,
    sessions: &Arc<RwLock<SessionTxRegistry>>,
    logger: &Arc<NodeLogger>,
) {
    dht.set_network_auth_gate(Arc::new(BanStoreGate {
        gate: Arc::clone(gate),
        ban_list: Arc::clone(ban_list),
        sessions: Arc::clone(sessions),
        logger: Arc::clone(logger),
    }));
}

/// Errors returned by [`NodeRuntime::publish_p_net_ban`].
#[derive(Debug, thiserror::Error)]
pub enum PublishBanError {
    #[error("[network] not configured — this is a public-mode node")]
    NoGate,
    #[error("local cert decode failed: {0}")]
    BadLocalCert(String),
    #[error("local node is not an admin — cert.admin = false")]
    NotAdmin,
    #[error("local identity signing key not available (Ed25519 falcon mode?)")]
    NoSigningKey,
    #[error("ban reason exceeds {0} bytes")]
    ReasonTooLong(usize),
    #[error("DHT replication failed: {0}")]
    Replication(String),
    #[error("local verify failed (impossible — sign bug): {0}")]
    LocalVerifyFailed(String),
}

/// audit cycle-6 (T7): the prepared-but-not-yet-replicated ban. Carries the
/// Arc-cloned handles needed for the async DHT fan-out so the caller can drop
/// the `NodeRuntime` lock BEFORE awaiting `replicate()` (the network step).
#[derive(Clone)]
pub struct PreparedBan {
    dht: Arc<veil_dht::KademliaService>,
    session_outbox: Arc<veil_session::SessionOutbox>,
    logger: Arc<veil_observability::NodeLogger>,
    key: [u8; 32],
    blob: Vec<u8>,
    banned_node_id: [u8; 32],
}

impl PreparedBan {
    /// Fan the prepared ban out to the network via DHT replication. No lock is
    /// held here (the caller dropped the `NodeRuntime` mutex after `prepare`),
    /// so the multi-second iterative DHT walk does not serialise the runtime.
    pub async fn replicate(self) -> Result<usize, PublishBanError> {
        let replicas_sent = self
            .dht
            .store_replicated(
                self.key,
                self.blob,
                self.session_outbox as Arc<dyn veil_dht::FrameRouter>,
            )
            .await
            .map_err(|e| PublishBanError::Replication(format!("{e:?}")))?;
        self.logger.info(
            "network.ban.published",
            format!(
                "banned={} replicas_sent={}",
                veil_util::hex_short(&self.banned_node_id),
                replicas_sent
            ),
        );
        Ok(replicas_sent)
    }
}

impl NodeRuntime {
    /// Author a signed `BanEntry`, store it locally, and apply it to the local
    /// `BanList` — the synchronous half. Returns a [`PreparedBan`] whose
    /// [`PreparedBan::replicate`] performs the async DHT fan-out. Split out
    /// (audit cycle-6 T7) so the admin handler can drop the `NodeRuntime` lock
    /// before the network await. `publish_p_net_ban` chains both for callers
    /// that don't hold the lock.
    ///
    /// Requires `[network].mode = "private"`, a local membership cert
    /// flagged `admin: true`, and a live identity Ed25519 signing key
    /// (the cert's `admin_pubkey` derives of it). All three pre-
    /// conditions are static at startup, so failures here generally
    /// indicate a misconfiguration rather than transient state.
    pub fn prepare_p_net_ban(
        &self,
        banned_node_id: [u8; 32],
        reason: impl Into<String>,
    ) -> Result<PreparedBan, PublishBanError> {
        let gate = self.network_gate.as_ref().ok_or(PublishBanError::NoGate)?;
        let local_cert = veil_identity::network_cert::decode_cert_blob(&gate.local_cert_blob)
            .map_err(|e| PublishBanError::BadLocalCert(e.to_string()))?;
        if !local_cert.admin {
            return Err(PublishBanError::NotAdmin);
        }
        let sk = self
            .dispatcher
            .crypto
            .local_signing_key
            .as_ref()
            .ok_or(PublishBanError::NoSigningKey)?;
        let admin_pubkey = sk.verifying_key().to_bytes().to_vec();
        let admin_node_id = *blake3::hash(&admin_pubkey).as_bytes();

        let reason = reason.into();
        if reason.len() > MAX_PUBLISH_REASON_LEN {
            return Err(PublishBanError::ReasonTooLong(MAX_PUBLISH_REASON_LEN));
        }
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut entry = BanEntry {
            version: BAN_ENTRY_VERSION,
            network_id: gate.expected_network_id,
            banned_node_id,
            reason: reason.clone(),
            issued_at_unix: now_unix,
            admin_node_id,
            admin_cert_blob: gate.local_cert_blob.clone(),
            admin_pubkey,
            admin_signature: Vec::new(),
        };
        let body = veil_identity::network_ban::canonical_ban_body(&entry);
        use ed25519_dalek::Signer;
        entry.admin_signature = sk.sign(&body).to_bytes().to_vec();

        // Defence-in-depth: re-verify what we just signed before
        // shipping. Catches any silent invariant violation (e.g.
        // mismatched algos) at the publish boundary instead of letting
        // the receiver reject and log a cryptic error.
        verify_ban_entry(
            &entry,
            &gate.expected_network_id,
            gate.owner_algo,
            &gate.owner_pubkey_bytes,
            now_unix,
        )
        .map_err(|e| PublishBanError::LocalVerifyFailed(e.to_string()))?;

        let blob = encode_ban_blob(&entry);
        let key = ban_dht_key(&gate.expected_network_id, &banned_node_id);

        // Apply at the publisher before any network replication.
        {
            let mut bl = lock!(self.ban_list);
            bl.ban_manual(banned_node_id, reason.clone());
        }
        wlock!(self.session_tx_registry).unregister(&banned_node_id);

        // The async fan-out lives in `PreparedBan::replicate` so the caller can
        // drop the NodeRuntime lock first.
        Ok(PreparedBan {
            dht: Arc::clone(&self.dht),
            session_outbox: Arc::clone(&self.session_outbox),
            logger: Arc::clone(&self.logger),
            key,
            blob,
            banned_node_id,
        })
    }

    /// Convenience wrapper: prepare + replicate. For callers that are NOT
    /// holding the `NodeRuntime` lock across the await (the admin handler
    /// instead calls `prepare_p_net_ban` under the lock, drops it, then
    /// `PreparedBan::replicate` — see audit cycle-6 T7).
    pub async fn publish_p_net_ban(
        &self,
        banned_node_id: [u8; 32],
        reason: impl Into<String>,
    ) -> Result<usize, PublishBanError> {
        self.prepare_p_net_ban(banned_node_id, reason)?
            .replicate()
            .await
    }

    /// Periodic background task: every `APPLY_INTERVAL_SECS` seconds
    /// scan the local DHT store for PBAN-prefixed values, verify each,
    /// and apply to `BanList`. Idempotent — re-running on already-banned
    /// node IDs is a cheap `is_banned` check.
    ///
    pub(super) fn apply_stored_p_net_bans(&self) {
        if let Some(gate) = &self.network_gate {
            apply_stored_bans(
                &self.dht,
                gate,
                &self.ban_list,
                &self.session_tx_registry,
                &self.logger,
            );
        }
    }

    /// Spawned only when the network gate is wired (private mode);
    /// public-mode nodes don't have ban records to sync.
    pub fn spawn_p_net_ban_sync_task(&mut self) {
        let Some(gate) = self.network_gate.as_ref().map(Arc::clone) else {
            return; // public mode — no sync needed
        };
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let dht = Arc::clone(&self.dht);
        let ban_list = Arc::clone(&self.ban_list);
        let sessions = Arc::clone(&self.session_tx_registry);
        let logger = Arc::clone(&self.logger);
        let handle = supervised_spawn(Arc::clone(&self.logger), "p_net_ban_sync", async move {
            let mut tick =
                tokio::time::interval(std::time::Duration::from_secs(APPLY_INTERVAL_SECS));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    Ok(_) = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { break; }
                    }
                    _ = tick.tick() => {
                        apply_stored_bans(&dht, &gate, &ban_list, &sessions, &logger);
                    }
                }
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }
}

fn apply_stored_bans(
    dht: &KademliaService,
    gate: &NetworkAccessGate,
    ban_list: &Mutex<BanList>,
    sessions: &RwLock<SessionTxRegistry>,
    logger: &NodeLogger,
) {
    let mut applied = 0;
    // Fetch values individually without promoting cold entries into memory.
    for key in dht.stored_key_ids() {
        let Some(value) = dht.peek_value(&key) else {
            continue;
        };
        if !value.starts_with(BAN_BLOB_MAGIC) || !gate.verify_ban_record(&key, &value) {
            continue;
        }
        applied += usize::from(apply_verified_ban(&value, ban_list, sessions));
    }
    if applied > 0 {
        logger.info("network.ban.applied", format!("applied={applied}"));
    }
}

fn apply_verified_ban(
    value: &[u8],
    ban_list: &Mutex<BanList>,
    sessions: &RwLock<SessionTxRegistry>,
) -> bool {
    let Ok(entry) = decode_ban_blob(value) else {
        return false;
    };
    let mut bans = lock!(ban_list);
    if bans
        .get(&entry.banned_node_id)
        .is_some_and(|ban| ban.manual && ban.banned_until.is_none())
    {
        return false;
    }
    bans.ban_manual(entry.banned_node_id, entry.reason);
    // Registration checks the ban while holding the session registry lock.
    // Release the ban list lock before attempting to retire the sender.
    drop(bans);
    wlock!(sessions).unregister(&entry.banned_node_id);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use veil_identity::network_cert::{canonical_cert_body, encode_cert_blob};
    use veil_proto::discovery::StorePayload;
    use veil_types::{MEMBERSHIP_CERT_VERSION, MembershipCert, SignatureAlgorithm};

    #[test]
    fn incoming_ban_retires_the_sender_only_after_verification_and_storage() {
        let owner = SigningKey::from_bytes(&[1; 32]);
        let admin = SigningKey::from_bytes(&[2; 32]);
        let admin_pubkey = admin.verifying_key().to_bytes().to_vec();
        let admin_node_id = *blake3::hash(&admin_pubkey).as_bytes();
        let network_id = [3; 32];
        let target = [4; 32];
        let now = veil_util::unix_secs_now_u64();
        let mut cert = MembershipCert {
            version: MEMBERSHIP_CERT_VERSION,
            network_id,
            member_node_id: admin_node_id,
            issued_at_unix: now.saturating_sub(1),
            valid_until_unix: now + 3600,
            admin: true,
            algo: SignatureAlgorithm::Ed25519,
            owner_signature: Vec::new(),
        };
        cert.owner_signature = owner.sign(&canonical_cert_body(&cert)).to_bytes().to_vec();
        let mut entry = BanEntry {
            version: BAN_ENTRY_VERSION,
            network_id,
            banned_node_id: target,
            reason: "admin revocation".into(),
            issued_at_unix: now,
            admin_node_id,
            admin_cert_blob: encode_cert_blob(&cert),
            admin_pubkey,
            admin_signature: Vec::new(),
        };
        let key = ban_dht_key(&network_id, &target);
        let gate = Arc::new(NetworkAccessGate {
            local_cert_blob: Vec::new(),
            expected_network_id: network_id,
            owner_algo: SignatureAlgorithm::Ed25519,
            owner_pubkey_bytes: owner.verifying_key().to_bytes().to_vec(),
            admin_node_ids: [admin_node_id].into(),
        });
        let logger = Arc::new(NodeLogger::new_noop());
        let bans = Arc::new(Mutex::new(BanList::new()));
        lock!(bans).ban(
            target,
            "temporary",
            Some(std::time::Duration::from_secs(90)),
        );
        let sessions = Arc::new(RwLock::new(SessionTxRegistry::new()));
        let _outbox = wlock!(sessions).register(target);
        let mut dht = KademliaService::new([5; 32]);
        configure_p_net_bans(&mut dht, &gate, &bans, &sessions, &logger);
        entry.admin_signature = admin
            .sign(&veil_identity::network_ban::canonical_ban_body(&entry))
            .to_bytes()
            .to_vec();
        let value = encode_ban_blob(&entry);

        entry.admin_signature[0] ^= 1;
        assert!(
            dht.handle_store(StorePayload::unsigned(key, encode_ban_blob(&entry)))
                .is_err()
        );
        assert!(dht.peek_value(&key).is_none());
        assert!(!lock!(bans).get(&target).unwrap().manual);

        let mut small = KademliaService::with_config(
            [5; 32],
            veil_dht::DhtRuntimeConfig {
                max_store_bytes: Some(1),
                ..Default::default()
            },
        );
        configure_p_net_bans(&mut small, &gate, &bans, &sessions, &logger);
        small
            .handle_store(StorePayload::unsigned(key, value.clone()))
            .unwrap();
        assert!(small.peek_value(&key).is_none());
        assert!(!lock!(bans).get(&target).unwrap().manual);
        assert!(veil_util::rlock!(sessions).has_session(&target));

        dht.handle_store(StorePayload::unsigned(key, value.clone()))
            .unwrap();
        assert_eq!(dht.peek_value(&key), Some(value));
        assert!(!veil_util::rlock!(sessions).has_session(&target));
        let mut bans = lock!(bans);
        bans.ban(
            target,
            "late temporary ban",
            Some(std::time::Duration::from_secs(30)),
        );
        let ban = bans.get(&target).unwrap();
        assert!(ban.manual && ban.banned_until.is_none());
        assert_eq!(ban.reason, "admin revocation");
    }
}
