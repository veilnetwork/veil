//! P-Net DHT-replicated ban sync.
//!
//! In а private veil network (`[network].mode = "private"`) admin
//! nodes publish signed `BanEntry` records to the DHT при ban time.
//! Every member periodically polls its local DHT store for ban entries
//! и applies them к the in-memory `BanList`, so an admin's decision
//! propagates network-wide вне зависимости от which node typed the
//! command.
//!
//! Public-mode nodes never construct this task (gate is `None`), so
//! their bans stay node-local — preserving the user's explicit
//! "publish-only-as-owner" constraint в open networks.

use std::sync::Arc;

use veil_identity::network_ban::{
    BAN_BLOB_MAGIC, ban_dht_key, decode_ban_blob, encode_ban_blob, verify_ban_entry,
};
use veil_types::{BAN_ENTRY_VERSION, BanEntry};
use veil_util::lock;

use super::{NodeRuntime, lock_tasks, supervised_spawn};

/// Cap on the in-flight reason string before signing. The receiver
/// re-checks via `MAX_BAN_REASON_LEN`; clamping at publish time keeps
/// our wire encoder happy.
pub const MAX_PUBLISH_REASON_LEN: usize = veil_types::MAX_BAN_REASON_LEN;

/// Periodic interval at which every member walks its DHT store for
/// PBAN entries и refreshes its local `BanList`. Inexpensive: scan is
/// O(|stored entries|) + small fixed verifies. 60 s strikes а balance
/// between propagation lag и CPU spend on idle clusters.
pub const APPLY_INTERVAL_SECS: u64 = 60;

/// Errors returned by [`NodeRuntime::publish_p_net_ban`].
#[derive(Debug, thiserror::Error)]
pub enum PublishBanError {
    #[error("[network] not configured — this is а public-mode node")]
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
    /// Author а signed `BanEntry`, store it locally, и apply it к the local
    /// `BanList` — the synchronous half. Returns a [`PreparedBan`] whose
    /// [`PreparedBan::replicate`] performs the async DHT fan-out. Split out
    /// (audit cycle-6 T7) so the admin handler can drop the `NodeRuntime` lock
    /// before the network await. `publish_p_net_ban` chains both for callers
    /// that don't hold the lock.
    ///
    /// Requires `[network].mode = "private"`, а local membership cert
    /// flagged `admin: true`, и а live identity Ed25519 signing key
    /// (the cert's `admin_pubkey` derives of it). All three pre-
    /// conditions are static at startup, so failures here generally
    /// indicate а misconfiguration rather than transient state.
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
        // the receiver reject и log а cryptic error.
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

        // Apply locally immediately. Don't wait for the DHT scanner —
        // the admin's own session set should reflect the ban в the next
        // dispatch step.
        {
            let mut bl = lock!(self.ban_list);
            bl.ban_manual(banned_node_id, reason.clone());
        }

        // The async fan-out lives in `PreparedBan::replicate` so the caller can
        // drop the NodeRuntime lock first. Our gate accepts the PBAN value at
        // `handle_store` time on every receiver, so remote nodes ingest и (on
        // their next apply tick) push к their own `BanList`.
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
    /// и apply к `BanList`. Idempotent — re-running on already-banned
    /// node IDs is а cheap `is_banned` check.
    ///
    /// Spawned only when the network gate is wired (private mode);
    /// public-mode nodes don't have ban records к sync.
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
                        // Stream keys and fetch each value on demand (`peek` =
                        // no cold-tier promotion) instead of materializing the
                        // ENTIRE store — including a RocksDB cold tier — into
                        // RAM every tick. At most one value is resident at a
                        // time; non-ban records are skipped after a 4-byte
                        // magic check. (Was: `dht.stored_entries()`, an O(store)
                        // RAM spike on large private-mode deployments.)
                        let keys = dht.stored_key_ids();
                        let now_unix = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let mut applied = 0usize;
                        for key in keys {
                            let Some(value) = dht.peek_value(&key) else {
                                continue;
                            };
                            if value.len() < 4 || &value[..4] != BAN_BLOB_MAGIC {
                                continue;
                            }
                            let Ok(entry) = decode_ban_blob(&value) else {
                                continue;
                            };
                            // Wrong-network records can't legitimately
                            // exist on this node (gate verified at ingest),
                            // but defence-in-depth: re-check before applying.
                            let derived = ban_dht_key(&gate.expected_network_id, &entry.banned_node_id);
                            if derived != key {
                                continue;
                            }
                            if verify_ban_entry(
                                &entry,
                                &gate.expected_network_id,
                                gate.owner_algo,
                                &gate.owner_pubkey_bytes,
                                now_unix,
                            ).is_err() {
                                continue;
                            }
                            // Skip if the admin cert isn't trusted by our
                            // allowlist (defence-in-depth — gate already
                            // applied this at ingest, but the admin set
                            // may have changed at config reload).
                            let Ok(admin_cert) = veil_identity::network_cert::decode_cert_blob(
                                &entry.admin_cert_blob,
                            ) else { continue };
                            if !gate.is_admin(&admin_cert) {
                                continue;
                            }
                            let mut bl = lock!(ban_list);
                            if !bl.is_banned(&entry.banned_node_id) {
                                bl.ban_manual(entry.banned_node_id, entry.reason.clone());
                                applied += 1;
                            }
                        }
                        if applied > 0 {
                            logger.info(
                                "network.ban.applied",
                                format!("applied={applied}"),
                            );
                        }
                    }
                }
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }
}
