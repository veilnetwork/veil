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

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use veil_abuse::BanList;
use veil_app::AppEndpointRegistry;
use veil_dht::{KademliaService, NetworkAuthGate};
use veil_identity::network_access::NetworkAccessGate;
use veil_identity::network_ban::{
    BAN_BLOB_MAGIC, ban_dht_key, decode_ban_blob, encode_ban_blob, verify_ban_entry,
};
use veil_observability::NodeLogger;
use veil_session::SessionTxRegistry;
use veil_types::{BAN_ENTRY_VERSION, BanEntry};
use veil_util::{lock, wlock};

use super::received_bans::{ReceivedBanSender, ReceivedBanStorage};
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
    received: Option<ReceivedBanSender>,
}

impl NetworkAuthGate for BanStoreGate {
    fn verify_ban_record(&self, key: &[u8; 32], value: &[u8]) -> bool {
        self.gate.verify_ban_record(key, value)
    }

    fn ban_stored(&self, value: &[u8]) {
        let Ok(entry) = decode_ban_blob(value) else {
            return;
        };
        let key = ban_dht_key(&entry.network_id, &entry.banned_node_id);
        if apply_ban_entry(entry, &self.ban_list, &self.sessions) {
            self.logger
                .info("network.ban.applied", "applied=1 source=store");
        }
        if let Some(received) = &self.received {
            received.record(key, value);
        }
    }
}

pub(super) fn configure_p_net_bans(
    dht: &mut KademliaService,
    gate: &Arc<NetworkAccessGate>,
    ban_list: &Arc<Mutex<BanList>>,
    sessions: &Arc<RwLock<SessionTxRegistry>>,
    logger: &Arc<NodeLogger>,
    received_dir: Option<PathBuf>,
) -> Option<ReceivedBanStorage> {
    let (received, storage) = if let Some(dir) = received_dir {
        let (sender, storage) = ReceivedBanStorage::channel(dir, logger);
        (Some(sender), Some(storage))
    } else {
        (None, None)
    };
    dht.set_network_auth_gate(Arc::new(BanStoreGate {
        gate: Arc::clone(gate),
        ban_list: Arc::clone(ban_list),
        sessions: Arc::clone(sessions),
        logger: Arc::clone(logger),
        received,
    }));
    storage
}

pub(super) fn guard_private_app_datagrams(
    registry: AppEndpointRegistry,
    ban_list: &Arc<Mutex<BanList>>,
) -> AppEndpointRegistry {
    let bans = Arc::clone(ban_list);
    registry.with_peer_revocation_check(move |peer| lock!(bans).is_banned(peer))
}

pub(super) fn enforced_ban_keys(
    bans: &Mutex<BanList>,
    network_id: [u8; 32],
) -> impl Iterator<Item = [u8; 32]> {
    let targets: Vec<_> = lock!(bans)
        .manual_bans()
        .into_iter()
        .filter(|ban| ban.banned_until.is_none())
        .map(|ban| ban.peer_id)
        .collect();
    targets
        .into_iter()
        .map(move |peer| ban_dht_key(&network_id, &peer))
}

/// Errors returned by [`NodeRuntime::publish_p_net_ban`].
#[derive(Debug, thiserror::Error)]
pub enum PublishBanError {
    #[error("[network] not configured — this is a public-mode node")]
    NoGate,
    #[error("local cert decode failed: {0}")]
    BadLocalCert(String),
    #[error(
        "local P-Net administrator requires cert.admin = true and inclusion in any nonempty [network].admin_node_ids list"
    )]
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
    issuer: [u8; 32],
    issued_at: u64,
    gate: Arc<NetworkAccessGate>,
    storage_dir: Option<PathBuf>,
}

pub(crate) enum IssuerStorage {
    Disabled,
    Saved,
    Volatile(String),
}

impl std::fmt::Display for IssuerStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str("disabled"),
            Self::Saved => f.write_str("saved"),
            Self::Volatile(reason) => write!(f, "volatile ({reason})"),
        }
    }
}

impl PreparedBan {
    /// Fan the prepared ban out to the network via DHT replication. No lock is
    /// held here (the caller dropped the `NodeRuntime` mutex after `prepare`),
    /// so the multi-second iterative DHT walk does not serialise the runtime.
    pub async fn replicate(self) -> Result<usize, PublishBanError> {
        self.replicate_with_storage()
            .await
            .map(|(replicas, _)| replicas)
    }

    pub(crate) async fn replicate_with_storage(
        self,
    ) -> Result<(usize, IssuerStorage), PublishBanError> {
        let save = self.storage_dir.map(|dir| {
            let key = self.key;
            let bytes = self.blob.clone();
            let gate = self.gate;
            let issuer = self.issuer;
            let issued_at = self.issued_at;
            tokio::task::spawn_blocking(move || {
                super::issued_bans::save(&dir, key, &bytes, issued_at, &gate, &issuer)
            })
        });
        let replicas = self
            .dht
            .store_replicated(
                self.key,
                self.blob,
                self.session_outbox as Arc<dyn veil_dht::FrameRouter>,
            )
            .await;
        let storage = match save {
            None => IssuerStorage::Disabled,
            Some(save) => match save.await {
                Ok(Ok(())) => IssuerStorage::Saved,
                Ok(Err(error)) => IssuerStorage::Volatile(error.to_string()),
                Err(error) => IssuerStorage::Volatile(format!("storage task failed: {error}")),
            },
        };
        if matches!(storage, IssuerStorage::Volatile(_)) {
            self.logger
                .warn("network.ban.storage.failed", storage.to_string());
        }
        let replicas_sent = replicas.map_err(|e| PublishBanError::Replication(format!("{e:?}")))?;
        self.logger.info(
            "network.ban.published",
            format!(
                "banned={} replicas_sent={} issuer_storage={}",
                veil_util::hex_short(&self.banned_node_id),
                replicas_sent,
                storage
            ),
        );
        Ok((replicas_sent, storage))
    }
}

impl NodeRuntime {
    /// Author a signed `BanEntry` and apply it to the local `BanList`.
    /// Returns a [`PreparedBan`] whose [`PreparedBan::replicate`] performs
    /// the async DHT fan-out. Split out
    /// (audit cycle-6 T7) so the admin handler can drop the `NodeRuntime` lock
    /// before the network await. `publish_p_net_ban` chains both for callers
    /// that don't hold the lock.
    ///
    /// Requires a private network, a local membership cert flagged
    /// `admin: true`, inclusion in any configured admin allowlist, and a
    /// live identity Ed25519 signing key.
    pub fn prepare_p_net_ban(
        &self,
        banned_node_id: [u8; 32],
        reason: impl Into<String>,
    ) -> Result<PreparedBan, PublishBanError> {
        let gate = self.network_gate.as_ref().ok_or(PublishBanError::NoGate)?;
        let local_cert = veil_identity::network_cert::decode_cert_blob(&gate.local_cert_blob)
            .map_err(|e| PublishBanError::BadLocalCert(e.to_string()))?;
        if !gate.is_admin(&local_cert) {
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
            issuer: admin_node_id,
            issued_at: now_unix,
            gate: Arc::clone(gate),
            storage_dir: self.issued_bans_dir.clone(),
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

    /// Restore locally authorized actions before listeners or connectors can
    /// admit peers. The DHT cache and the disk record have different roles:
    /// ordinary DHT entries age out, while the issuer can resume a ban that
    /// its active authority still permits it to publish.
    pub(super) async fn restore_issued_p_net_bans(&self) {
        let (Some(dir), Some(gate)) = (self.issued_bans_dir.clone(), self.network_gate.clone())
        else {
            return;
        };
        let issuer = *self.identity.local_identity.node_id.as_bytes();
        let logger = Arc::clone(&self.logger);
        let verify = Arc::clone(&gate);
        let loaded = tokio::task::spawn_blocking(move || {
            super::issued_bans::load(&dir, &verify, &issuer, &logger)
        })
        .await;
        let records = match loaded {
            Ok(Ok(records)) => records,
            Ok(Err(error)) => {
                self.logger
                    .warn("network.ban.storage.load_failed", error.to_string());
                return;
            }
            Err(error) => {
                self.logger
                    .warn("network.ban.storage.load_failed", error.to_string());
                return;
            }
        };
        let total = records.len();
        for (key, bytes) in records {
            apply_verified_ban(&bytes, &self.ban_list, &self.session_tx_registry);
            if self
                .dht
                .peek_value(&key)
                .is_none_or(|value| !gate.verify_ban_record(&key, &value))
            {
                self.dht.store_local(key, bytes);
            }
        }
        if total > 0 {
            self.logger
                .info("network.ban.storage.restored", format!("records={total}"));
        }
    }

    pub(super) async fn restore_received_p_net_bans(&self, config: &veil_cfg::Config) {
        let (Some(dir), Some(gate)) = (
            super::received_bans::storage_dir(config),
            self.network_gate.clone(),
        ) else {
            return;
        };
        let logger = Arc::clone(&self.logger);
        let records =
            tokio::task::spawn_blocking(move || super::received_bans::load(&dir, &gate, &logger))
                .await;
        match records {
            Ok(Ok(records)) => {
                let count = records.len();
                for record in &records {
                    apply_verified_ban(&record.value, &self.ban_list, &self.session_tx_registry);
                }
                self.dht.restore_values(records);
                if count > 0 {
                    self.logger.info(
                        "network.ban.received_storage.restored",
                        format!("records={count}"),
                    );
                }
            }
            Ok(Err(error)) => self.logger.warn(
                "network.ban.received_storage.load_failed",
                error.to_string(),
            ),
            Err(error) => self.logger.warn(
                "network.ban.received_storage.load_failed",
                error.to_string(),
            ),
        }
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
        if let Some(writer) = self
            .received_ban_storage
            .as_mut()
            .and_then(|storage| storage.take_writer(&gate, &self.logger))
        {
            let handle = supervised_spawn(
                Arc::clone(&self.logger),
                "p_net_received_ban_storage",
                writer.run(Arc::clone(&self.dht), shutdown_tx.subscribe()),
            );
            lock_tasks(&self.tasks).sessions.push(handle);
        }
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
        self.spawn_p_net_ban_forwarding();
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
    apply_ban_entry(entry, ban_list, sessions)
}

fn apply_ban_entry(
    entry: BanEntry,
    ban_list: &Mutex<BanList>,
    sessions: &RwLock<SessionTxRegistry>,
) -> bool {
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

    const TEST_NETWORK_ID: [u8; 32] = [3; 32];

    fn admin_fixture(mode: veil_cfg::NetworkMode) -> (tempfile::TempDir, veil_cfg::Config) {
        use super::super::tests::runtime_config_with_listen;
        use base64::{Engine, engine::general_purpose::STANDARD};
        use veil_cfg::{BuiltinSeedPolicy, NetworkConfig, NodeRole};

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("network.cert");
        let owner = SigningKey::from_bytes(&[1; 32]);
        let mut config = runtime_config_with_listen();
        config.peers.clear();
        config.global.builtin_seed_policy = BuiltinSeedPolicy::Never;
        let identity = config.identity.as_mut().unwrap();
        identity.role = NodeRole::Leaf;
        let local_id = *identity.node_id.unwrap().as_bytes();
        let now = veil_util::unix_secs_now_u64();
        let mut cert = MembershipCert {
            version: MEMBERSHIP_CERT_VERSION,
            network_id: TEST_NETWORK_ID,
            member_node_id: local_id,
            issued_at_unix: now.saturating_sub(1),
            valid_until_unix: now + 3600,
            admin: true,
            algo: SignatureAlgorithm::Ed25519,
            owner_signature: Vec::new(),
        };
        cert.owner_signature = owner.sign(&canonical_cert_body(&cert)).to_bytes().to_vec();
        std::fs::write(&cert_path, encode_cert_blob(&cert)).unwrap();
        config.network = Some(NetworkConfig {
            mode,
            network_id: Some(veil_util::bytes_to_hex(&TEST_NETWORK_ID)),
            owner_pubkey: Some(STANDARD.encode(owner.verifying_key().to_bytes())),
            owner_algo: Some(SignatureAlgorithm::Ed25519),
            membership_cert: Some(cert_path.to_str().unwrap().to_owned()),
            admin_node_ids: Vec::new(),
        });
        (dir, config)
    }

    #[tokio::test]
    async fn publishing_a_ban_checks_the_admin_allowlist_before_effects() {
        let (dir, mut config) = admin_fixture(veil_cfg::NetworkMode::PrivateConfigured);
        let config_path = dir.path().join("node.toml");
        let local_id = *config
            .identity
            .as_ref()
            .unwrap()
            .node_id
            .unwrap()
            .as_bytes();
        for (target, allowlist, permitted) in [
            ([4; 32], vec![[9; 32]], false),
            ([5; 32], vec![local_id], true),
            ([6; 32], vec![], true),
        ] {
            config.network.as_mut().unwrap().admin_node_ids = allowlist
                .iter()
                .map(|id| veil_util::bytes_to_hex(id))
                .collect();
            std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
            let mut runtime = NodeRuntime::start(&config_path, true).await.unwrap();
            let _outbox = wlock!(runtime.session_tx_registry).register(target);

            let result = runtime.publish_p_net_ban(target, "test ban").await;
            if permitted {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(PublishBanError::NotAdmin)));
            }
            assert_eq!(lock!(runtime.ban_list).is_banned(&target), permitted);
            assert_eq!(
                runtime
                    .dht
                    .peek_value(&ban_dht_key(&TEST_NETWORK_ID, &target))
                    .is_some(),
                permitted
            );
            assert_eq!(
                veil_util::rlock!(runtime.session_tx_registry).has_session(&target),
                !permitted
            );
            runtime.stop().await.unwrap();
        }
    }

    #[tokio::test]
    async fn an_offline_ban_survives_reload_and_reaches_a_new_session_without_disk_state() {
        use std::time::Duration;
        use veil_proto::family::{DiscoveryMsg, FrameFamily};

        for mode in [
            veil_cfg::NetworkMode::Private,
            veil_cfg::NetworkMode::PrivateConfigured,
        ] {
            let (dir, mut config) = admin_fixture(mode);
            let config_path = dir.path().join("node.toml");
            config.persist_enabled = false;
            config.dht.values_persist_path = None;
            std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
            let mut runtime = NodeRuntime::start(&config_path, true).await.unwrap();
            let target = [4; 32];
            let key = ban_dht_key(&TEST_NETWORK_ID, &target);
            assert_eq!(
                runtime
                    .publish_p_net_ban(target, "offline ban")
                    .await
                    .unwrap(),
                0
            );
            let signed = runtime.dht.peek_value(&key).unwrap();
            let unrelated = [19; 32];
            runtime.dht.store_local(unrelated, vec![17]);

            runtime.reload().await.unwrap();
            assert!(lock!(runtime.ban_list).is_banned(&target));
            assert_eq!(
                runtime.dht.peek_value(&key).as_deref(),
                Some(signed.as_slice())
            );
            assert!(runtime.dht.peek_value(&unrelated).is_none());

            let peer = [5; 32];
            let owner = [6; 32];
            let mut rx = wlock!(runtime.session_tx_registry).register_owned(peer, owner);
            let _request_rx = runtime.session_outbox.register_owned(peer, owner);
            let store = tokio::time::timeout(Duration::from_secs(5), async {
                while let Some((_, frame)) = rx.recv().await {
                    let header = veil_proto::codec::decode_header(&frame).unwrap();
                    if header.family == FrameFamily::Discovery as u8
                        && header.msg_type == DiscoveryMsg::Store as u16
                    {
                        let store =
                            StorePayload::decode(&frame[usize::from(header.header_len)..]).unwrap();
                        if store.key == key {
                            return store;
                        }
                    }
                }
                panic!("registered session closed before receiving the signed ban");
            })
            .await
            .expect("new session should receive the signed ban after reloading");
            assert_eq!(store.value, signed);
            runtime.stop().await.unwrap();
        }
    }

    #[tokio::test]
    async fn confirmed_issuer_storage_restores_only_locally_authorized_bans() {
        let (dir, mut config) = admin_fixture(veil_cfg::NetworkMode::PrivateConfigured);
        let config_path = dir.path().join("node.toml");
        let snapshot = dir.path().join("dht-values.json");
        config.persist_enabled = true;
        config.dht.values_persist_path = Some(snapshot.to_string_lossy().into_owned());
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let storage_dir = super::super::issued_bans::storage_dir(&config).unwrap();
        let mut runtime = NodeRuntime::start(&config_path, true).await.unwrap();
        let target = [7; 32];
        let key = ban_dht_key(&TEST_NETWORK_ID, &target);

        std::fs::write(&storage_dir, b"storage collision").unwrap();
        let (replicas, storage) = runtime
            .prepare_p_net_ban(target, "blocked storage")
            .unwrap()
            .replicate_with_storage()
            .await
            .unwrap();
        assert_eq!(replicas, 0);
        assert!(matches!(storage, IssuerStorage::Volatile(_)));
        assert!(lock!(runtime.ban_list).is_banned(&target));
        assert!(runtime.dht.peek_value(&key).is_some());

        std::fs::remove_file(&storage_dir).unwrap();
        let (replicas, storage) = runtime
            .prepare_p_net_ban(target, "saved before reply")
            .unwrap()
            .replicate_with_storage()
            .await
            .unwrap();
        assert_eq!(replicas, 0);
        assert!(matches!(storage, IssuerStorage::Saved));
        let signed = runtime.dht.peek_value(&key).unwrap();
        let file = storage_dir.join(format!("{}.pban", veil_util::bytes_to_hex(&key)));
        assert_eq!(std::fs::read(&file).unwrap(), signed);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        runtime.stop().await.unwrap();
        let _ = std::fs::remove_file(&snapshot);

        let mut runtime = NodeRuntime::start(&config_path, true).await.unwrap();
        assert!(lock!(runtime.ban_list).is_banned(&target));
        assert_eq!(runtime.dht.peek_value(&key), Some(signed));
        runtime.stop().await.unwrap();
        let _ = std::fs::remove_file(&snapshot);

        config.network.as_mut().unwrap().admin_node_ids = vec![veil_util::bytes_to_hex(&[9; 32])];
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let mut runtime = NodeRuntime::start(&config_path, true).await.unwrap();
        assert!(!lock!(runtime.ban_list).is_banned(&target));
        assert!(runtime.dht.peek_value(&key).is_none());
        runtime.stop().await.unwrap();
    }

    fn signed_ban_fixture(target: [u8; 32]) -> (BanEntry, Arc<NetworkAccessGate>) {
        let owner = SigningKey::from_bytes(&[1; 32]);
        let admin = SigningKey::from_bytes(&[2; 32]);
        let admin_pubkey = admin.verifying_key().to_bytes().to_vec();
        let admin_node_id = *blake3::hash(&admin_pubkey).as_bytes();
        let network_id = [3; 32];
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
        let gate = Arc::new(NetworkAccessGate {
            local_cert_blob: Vec::new(),
            expected_network_id: network_id,
            owner_algo: SignatureAlgorithm::Ed25519,
            owner_pubkey_bytes: owner.verifying_key().to_bytes().to_vec(),
            admin_node_ids: [admin_node_id].into(),
        });
        entry.admin_signature = admin
            .sign(&veil_identity::network_ban::canonical_ban_body(&entry))
            .to_bytes()
            .to_vec();
        (entry, gate)
    }

    #[tokio::test]
    async fn received_records_restore_without_a_snapshot_and_keep_their_age() {
        use std::time::Duration;
        use veil_dht::kademlia::DEFAULT_TTL;

        let (dir, mut config) = admin_fixture(veil_cfg::NetworkMode::PrivateConfigured);
        let config_path = dir.path().join("node.toml");
        let snapshot = dir.path().join("dht-values.json");
        let log_file = dir.path().join("daemon.log");
        config.global.logs = veil_cfg::LogsConfig::File;
        config.global.log_file = Some(log_file.to_string_lossy().into_owned());
        config.persist_enabled = true;
        config.dht.values_persist_path = Some(snapshot.to_string_lossy().into_owned());
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let receiver_store = super::super::received_bans::storage_dir(&config).unwrap();
        let target = [10; 32];
        let (entry, _) = signed_ban_fixture(target);
        let key = ban_dht_key(&TEST_NETWORK_ID, &target);
        let record = encode_ban_blob(&entry);
        let file = receiver_store.join(format!("{}.pban", veil_util::bytes_to_hex(&key)));

        let mut runtime = NodeRuntime::start(&config_path, true).await.unwrap();
        std::fs::write(&receiver_store, b"temporary storage collision").unwrap();
        let _receiver = wlock!(runtime.session_tx_registry).register(target);
        runtime
            .dht
            .handle_store(StorePayload::unsigned(key, record.clone()))
            .unwrap();
        assert!(lock!(runtime.ban_list).is_banned(&target));
        assert!(!veil_util::rlock!(runtime.session_tx_registry).has_session(&target));
        tokio::time::timeout(Duration::from_secs(5), async {
            while !std::fs::read_to_string(&log_file)
                .unwrap()
                .contains("network.ban.received_storage.failed")
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the first disk write should fail");
        std::fs::remove_file(&receiver_store).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !file.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the writer should retry without another network STORE");
        let mut bytes = std::fs::read(&file).unwrap();
        assert_eq!(&bytes[12..], &record);
        runtime.stop().await.unwrap();

        let aged = veil_util::unix_secs_now_u64() - 120;
        bytes[4..12].copy_from_slice(&aged.to_be_bytes());
        // Give each restart an empty DHT-snapshot path and copy just the
        // receipt. A graceful flush from the prior process cannot race it.
        config.dht.values_persist_path =
            Some(dir.path().join("aged.json").to_string_lossy().into_owned());
        let aged_store = super::super::received_bans::storage_dir(&config).unwrap();
        veil_util::create_dir_owner_only(&aged_store).unwrap();
        veil_util::atomic_write_owner_only(&aged_store.join(file.file_name().unwrap()), &bytes)
            .unwrap();
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let mut runtime = NodeRuntime::start(&config_path, true).await.unwrap();
        assert!(lock!(runtime.ban_list).is_banned(&target));
        assert_eq!(
            runtime.dht.peek_value(&key).as_deref(),
            Some(record.as_slice())
        );
        let saved = runtime
            .dht
            .snapshot_values()
            .into_iter()
            .find(|entry| entry.key == key)
            .unwrap();
        assert!(
            saved.age_secs >= 120,
            "restored DHT age was {} seconds",
            saved.age_secs
        );
        runtime.stop().await.unwrap();

        let expired = veil_util::unix_secs_now_u64() - DEFAULT_TTL.as_secs();
        bytes[4..12].copy_from_slice(&expired.to_be_bytes());
        config.dht.values_persist_path = Some(
            dir.path()
                .join("expired.json")
                .to_string_lossy()
                .into_owned(),
        );
        let expired_store = super::super::received_bans::storage_dir(&config).unwrap();
        veil_util::create_dir_owner_only(&expired_store).unwrap();
        veil_util::atomic_write_owner_only(&expired_store.join(file.file_name().unwrap()), &bytes)
            .unwrap();
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let mut runtime = NodeRuntime::start(&config_path, true).await.unwrap();
        assert!(!lock!(runtime.ban_list).is_banned(&target));
        assert!(runtime.dht.peek_value(&key).is_none());
        runtime.stop().await.unwrap();
    }

    #[tokio::test]
    async fn pending_received_ban_survives_reload_without_refreshing_its_age() {
        use std::time::Duration;

        let (dir, mut config) = admin_fixture(veil_cfg::NetworkMode::PrivateConfigured);
        let config_path = dir.path().join("node.toml");
        let log_file = dir.path().join("daemon.log");
        config.global.logs = veil_cfg::LogsConfig::File;
        config.global.log_file = Some(log_file.to_string_lossy().into_owned());
        config.persist_enabled = true;
        config.dht.values_persist_path = Some(
            dir.path()
                .join("dht-values.json")
                .to_string_lossy()
                .into_owned(),
        );
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let store = super::super::received_bans::storage_dir(&config).unwrap();
        let target = [18; 32];
        let (entry, _) = signed_ban_fixture(target);
        let key = ban_dht_key(&TEST_NETWORK_ID, &target);
        let record = encode_ban_blob(&entry);
        let receipt = store.join(format!("{}.pban", veil_util::bytes_to_hex(&key)));
        let mut runtime = NodeRuntime::start(&config_path, true).await.unwrap();
        std::fs::write(&store, b"temporary storage collision").unwrap();

        let earliest = veil_util::unix_secs_now_u64();
        runtime
            .dht
            .handle_store(StorePayload::unsigned(key, record.clone()))
            .unwrap();
        let latest = veil_util::unix_secs_now_u64();
        tokio::time::timeout(Duration::from_secs(5), async {
            while veil_util::unix_secs_now_u64() <= latest
                || !std::fs::read_to_string(&log_file)
                    .unwrap()
                    .contains("network.ban.received_storage.failed")
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the old writer should have a failed write before reload");

        runtime.reload().await.unwrap();
        assert!(lock!(runtime.ban_list).is_banned(&target));
        assert_eq!(
            runtime.dht.peek_value(&key).as_deref(),
            Some(record.as_slice())
        );
        std::fs::remove_file(&store).unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(6), async {
            while !receipt.exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        runtime.stop().await.unwrap();
        outcome.expect("reload should hand the pending write to the new writer");

        let bytes = std::fs::read(receipt).unwrap();
        let received_at = u64::from_be_bytes(bytes[4..12].try_into().unwrap());
        assert!((earliest..=latest).contains(&received_at));
        assert_eq!(&bytes[12..], record.as_slice());
    }

    #[test]
    fn incoming_ban_retires_the_sender_only_after_verification_and_storage() {
        let target = [4; 32];
        let (mut entry, gate) = signed_ban_fixture(target);
        let key = ban_dht_key(&TEST_NETWORK_ID, &target);
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
        assert!(configure_p_net_bans(&mut dht, &gate, &bans, &sessions, &logger, None).is_none());
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
        assert!(configure_p_net_bans(&mut small, &gate, &bans, &sessions, &logger, None).is_none());
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
