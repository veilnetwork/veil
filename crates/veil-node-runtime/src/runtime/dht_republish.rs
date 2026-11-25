//! Periodic republish of locally-stored DHT entries to K-closest peers
//! (Kademlia spec: republish at TTL/2).
//!
//! Extracted from `runtime/mod.rs` during refactor.

use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use tokio::time::Instant;
use veil_abuse::BanList;
use veil_dht::KademliaService;
use veil_identity::network_access::NetworkAccessGate;
use veil_identity::network_ban::BAN_BLOB_MAGIC;
use veil_session::{SendToError, SessionOutbox, SessionTxRegistry};
use veil_util::{lock, rlock};

use super::p_net_ban_sync::enforced_ban_keys;
use super::{NodeRuntime, lock_tasks, supervised_spawn};

const BAN_CATCH_UP_COOLDOWN: Duration = Duration::from_secs(15);
const BAN_CATCH_UP_MAX_CHECKS: usize = 32;
const BAN_CATCH_UP_MAX_RECIPIENTS: usize = 8;
const BAN_RETRY_PER_TICK: usize = BAN_CATCH_UP_MAX_RECIPIENTS / 2;
const BAN_RETRY_CAPACITY: usize = 256;
const BAN_RETRY_INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const BAN_RETRY_MAX_BACKOFF: Duration = Duration::from_secs(15);

type SessionRegistration = ([u8; 32], [u8; 32]);

struct BanReplicaBatch<'a> {
    key: [u8; 32],
    frame: Vec<u8>,
    recipients: &'a [SessionRegistration],
}

struct BanRetry {
    key: [u8; 32],
    registration: SessionRegistration,
    next_due: Instant,
    backoff: Duration,
}

#[derive(Default)]
struct BanReplicaQueue {
    keys: VecDeque<[u8; 32]>,
    recipients: Vec<SessionRegistration>,
    next_recipient: usize,
}

#[derive(Default)]
struct BanCatchUp {
    sessions: Vec<SessionRegistration>,
    pending: BTreeSet<SessionRegistration>,
    next_scan: Option<Instant>,
    reconnect: BanReplicaQueue,
    fresh: BanReplicaQueue,
    pending_fresh: BTreeSet<[u8; 32]>,
    prefer_reconnect: bool,
    retries: VecDeque<BanRetry>,
}

impl BanCatchUp {
    fn observe_sessions(
        &mut self,
        dht: &KademliaService,
        outbox: &SessionOutbox,
        bans: &Mutex<BanList>,
        network_id: &[u8; 32],
        now: Instant,
    ) {
        let current = outbox.live_owned_registrations();
        let added_bans = dht.take_new_network_bans();
        if current.is_empty() {
            self.pending.clear();
            self.pending_fresh.clear();
            self.reconnect = BanReplicaQueue::default();
            self.fresh = BanReplicaQueue::default();
            self.retries.clear();
        } else if self.sessions != current {
            self.pending
                .retain(|registration| current.binary_search(registration).is_ok());
            self.retries
                .retain(|retry| current.binary_search(&retry.registration).is_ok());
            self.pending.extend(
                current
                    .iter()
                    .copied()
                    .filter(|registration| self.sessions.binary_search(registration).is_err()),
            );
        }
        self.sessions = current;
        if !self.sessions.is_empty() {
            for key in added_bans {
                if self.pending_fresh.len() >= veil_proto::budget::MAX_BAN_LIST_SIZE {
                    break;
                }
                self.pending_fresh.insert(key);
            }
        }
        if self.fresh.keys.is_empty() && !self.pending_fresh.is_empty() {
            self.fresh = BanReplicaQueue {
                keys: std::mem::take(&mut self.pending_fresh)
                    .into_iter()
                    .collect(),
                recipients: self.sessions.clone(),
                next_recipient: 0,
            };
        }
        if self.pending.is_empty()
            || !self.reconnect.keys.is_empty()
            || self.next_scan.is_some_and(|due| now < due)
        {
            return;
        }
        self.next_scan = Some(now + BAN_CATCH_UP_COOLDOWN);
        let recipients = std::mem::take(&mut self.pending).into_iter().collect();
        // Each accepted signed record creates a permanent local ban. Use
        // those IDs to address records without scanning unrelated DHT values.
        self.reconnect = BanReplicaQueue {
            keys: enforced_ban_keys(bans, *network_id).collect(),
            recipients,
            next_recipient: 0,
        };
    }

    fn next_batch(
        &mut self,
        dht: &KademliaService,
        limit: usize,
    ) -> Option<(&'static str, BanReplicaBatch<'_>)> {
        let reconnect = (&mut self.reconnect, "network.ban.catch_up");
        let fresh = (&mut self.fresh, "network.ban.forwarded");
        let (first, second) = if self.prefer_reconnect {
            (reconnect, fresh)
        } else {
            (fresh, reconnect)
        };
        self.prefer_reconnect = !self.prefer_reconnect;
        first
            .0
            .next_batch(dht, limit)
            .map(|batch| (first.1, batch))
            .or_else(|| {
                second
                    .0
                    .next_batch(dht, limit)
                    .map(|batch| (second.1, batch))
            })
    }

    fn defer_full_queue(&mut self, key: [u8; 32], registration: SessionRegistration, now: Instant) {
        if self
            .retries
            .iter()
            .any(|retry| retry.key == key && retry.registration == registration)
        {
            return;
        }
        if self.retries.len() == BAN_RETRY_CAPACITY {
            // Persistent congestion must leave room for new failures. The
            // evicted record is still eligible for ordinary DHT republishing.
            let (index, _) = self
                .retries
                .iter()
                .enumerate()
                .max_by_key(|(_, retry)| (retry.backoff, retry.next_due))
                .expect("retry queue at capacity");
            self.retries.remove(index);
        }
        self.retries.push_back(BanRetry {
            key,
            registration,
            next_due: now + BAN_RETRY_INITIAL_BACKOFF,
            backoff: BAN_RETRY_INITIAL_BACKOFF,
        });
    }

    fn send_next_batch(
        &mut self,
        dht: &KademliaService,
        bans: &Mutex<BanList>,
        senders: &RwLock<SessionTxRegistry>,
        limit: usize,
        now: Instant,
    ) -> Option<(&'static str, u64)> {
        let (event, batch) = self.next_batch(dht, limit)?;
        let mut sent = 0;
        let mut full = Vec::new();
        for registration in batch.recipients {
            match send_ban_replica(dht, bans, senders, registration, batch.frame.clone()) {
                Ok(()) => sent += 1,
                Err(SendToError::Full) => full.push(*registration),
                Err(_) => {}
            }
        }
        let key = batch.key;
        for registration in full {
            self.defer_full_queue(key, registration, now);
        }
        Some((event, sent))
    }

    fn retry_full_queues(
        &mut self,
        dht: &KademliaService,
        bans: &Mutex<BanList>,
        senders: &RwLock<SessionTxRegistry>,
        now: Instant,
    ) -> (usize, u64) {
        let mut attempts = 0;
        let mut sent = 0;
        // A backed-off peer must not block work for other sessions. Due
        // entries rotate to the tail, and new publications use spare slots.
        for _ in 0..BAN_RETRY_PER_TICK {
            let Some(index) = self.retries.iter().position(|retry| retry.next_due <= now) else {
                break;
            };
            let mut retry = self.retries.remove(index).expect("retry index exists");
            attempts += 1;
            let Some(value) = dht.peek_value(&retry.key) else {
                continue;
            };
            let Ok(frame) = dht.build_private_ban_replica(retry.key, value) else {
                continue;
            };
            match send_ban_replica(dht, bans, senders, &retry.registration, frame) {
                Ok(()) => sent += 1,
                Err(SendToError::Full) => {
                    retry.backoff = (2 * retry.backoff).min(BAN_RETRY_MAX_BACKOFF);
                    retry.next_due = now + retry.backoff;
                    self.retries.push_back(retry);
                }
                Err(_) => {}
            }
        }
        (attempts, sent)
    }
}

impl BanReplicaQueue {
    fn next_batch(&mut self, dht: &KademliaService, limit: usize) -> Option<BanReplicaBatch<'_>> {
        for _ in 0..BAN_CATCH_UP_MAX_CHECKS {
            let key = *self.keys.front()?;
            if let Some(value) = dht.peek_value(&key)
                && let Ok(frame) = dht.build_private_ban_replica(key, value)
            {
                let start = self.next_recipient;
                let end = (start + limit).min(self.recipients.len());
                self.next_recipient = end;
                if end == self.recipients.len() {
                    self.keys.pop_front();
                    self.next_recipient = 0;
                }
                return Some(BanReplicaBatch {
                    key,
                    frame,
                    recipients: &self.recipients[start..end],
                });
            }
            self.keys.pop_front();
            self.next_recipient = 0;
        }
        None
    }
}

fn send_ban_replica(
    dht: &KademliaService,
    bans: &Mutex<BanList>,
    senders: &RwLock<SessionTxRegistry>,
    (peer, owner): &SessionRegistration,
    frame: Vec<u8>,
) -> Result<(), SendToError> {
    if !dht.peer_serves_dht(peer) {
        return Err(SendToError::Missing);
    }
    // Registration checks the ban list while holding the sender registry.
    let senders = rlock!(senders);
    let bans = lock!(bans);
    if bans.is_banned(peer) {
        return Err(SendToError::Missing);
    }
    senders.send_to_owned_result(peer, owner, veil_proto::priority::BACKGROUND, frame)
}

fn republishable_record_at(
    network_gate: Option<&NetworkAccessGate>,
    key: &[u8; 32],
    value: &[u8],
    now_unix_ms: u64,
) -> bool {
    if value.starts_with(BAN_BLOB_MAGIC) {
        return network_gate
            .is_some_and(|gate| gate.verify_ban_record_at(key, value, now_unix_ms / 1_000));
    }
    NodeRuntime::is_republishable_dht_value_at(value, now_unix_ms)
}

impl NodeRuntime {
    /// Periodically republish locally-stored DHT entries to the K closest peers.
    ///
    /// The Kademlia spec recommends republishing at half the TTL interval so that
    /// records do not expire on remote nodes before the owner refreshes them.
    /// Interval: `DEFAULT_TTL / 2` = 30 minutes.
    ///
    /// uses `RepublishScheduler` to stagger per-key publication times
    /// so that all keys are NOT republished in a single burst every `interval`.
    /// The task wakes every 1 s and only publishes keys whose individual due
    /// time has elapsed.
    /// is this DHT value a self-authenticating record type that
    /// can be safely re-published via unsigned STORE?
    ///
    /// Returns `true` only for records whose wire format carries an internal
    /// signature that the recipient's dispatcher knows how to verify. Other
    /// values would trip `session.violation: Store: unsigned STORE for
    /// non-self key` on the receiver.
    pub fn is_self_authenticating_dht_value(value: &[u8]) -> bool {
        if value.len() < 2 {
            return false;
        }
        let magic = &value[..2];
        // P-Net ban records use a 4-byte `PBAN` magic; the receiver's
        // `KademliaService::handle_store` routes those through
        // `NetworkAuthGate` regardless of signed-STORE flags, so
        // republishing them propagates legitimate bans to peers that
        // joined after the original publish.
        if value.starts_with(BAN_BLOB_MAGIC) {
            return true;
        }
        magic == veil_discovery::directory::APP_ENDPOINT_DHT_MAGIC
            || magic == veil_discovery::directory::ATTACHMENT_DHT_MAGIC
            // sovereign-identity records — each carries
            // its own signature (identity_sk) + PoW / master-cert
            // chain, verifiable at resolve time by the lookup
            // caller. Included here so periodic republish actually
            // propagates them to K-closest peers.
            || magic == veil_proto::name_claim_v2::NAME_CLAIM_MAGIC
            || magic == veil_proto::identity_document::IDENTITY_DOCUMENT_MAGIC
            || magic == veil_proto::instance_registry::INSTANCE_REGISTRY_MAGIC
            || magic == veil_proto::mlkem_cert::MLKEM_CERT_MAGIC
            // audit cycle-6 (P1 review): SignedBootstrapBundle ("SB") is also
            // self-authenticating (accepted by the dispatcher's
            // `validate_store_value_by_magic` on both STORE arms), but was
            // missing here — so a forwarding node that stored an SB record never
            // republished it, letting bootstrap bundles decay after one TTL.
            || magic == veil_bootstrap::SIGNED_BUNDLE_MAGIC
            // Blinded onion-service descriptor (diff-audit L5): self-authenticating
            // (signed under the embedded blinded_pub; DHT key = H(domain ‖
            // blinded_pub) — `verify_descriptor_self`). Without this the descriptor
            // was store_local-only and by-identity send never resolved cross-node.
            || magic == veil_anonymity::blinded_descriptor::DESCRIPTOR_DHT_MAGIC
            || magic == veil_anonymity::blinded_descriptor::PROVIDER_DESCRIPTOR_DHT_MAGIC
            // Relay-directory entry ("RD"): the relay's anonymity x25519 pk,
            // resolvable by node_id, that a sender needs for the outer onion
            // layer to the rendezvous relay. Without this it was store_local-only
            // at the relay (never replicated to its K-closest), so a COLD sender
            // — which hasn't organically cached the relay's entry — could not
            // resolve an arbitrary advertised rendezvous relay → introduce
            // silent-drop → `NoRendezvous`. Re-verified on the resolver read path
            // (`verify_entry`); accepted at the STORE gate by the `RD` arm in
            // `validate_store_value_by_magic`.
            || magic == &veil_anonymity::directory::RELAY_DIRECTORY_DHT_MAGIC[..]
            // RelayKeyRecord ("RK"): the relay's signed X25519 KEM pubkey,
            // resolvable by node_id, that a sender needs to seal an anonymous
            // mailbox deposit to an always-on relay. Same gap class as "RD"
            // above: accepted at the STORE gate (`validate_store_value_by_magic`)
            // and self-authenticating (signed under the publisher's identity
            // subkey; verified by `verify_relay_key` on the read path), but
            // missing here — so a forwarding node that cached an RK never
            // republished it, leaving it store_local-only at the publisher and
            // un-discoverable to any node that hadn't organically cached it.
            || magic == &veil_proto::relay_key::RELAY_KEY_MAGIC[..]
            // NicknameRecord ("NK"): fully self-authenticating (owner binding
            // node_id == blake3(pk) + ed25519 sig + cumulative PoW), accepted
            // at the STORE gate via `nickname_store_gate` which additionally
            // applies the replace-on-heavier conflict rule — so republishing
            // an incumbent can never clobber a heavier record at the
            // receiver. Without this arm a nickname decays after one DHT TTL
            // and the name silently un-resolves (this IS the auto-renewal
            // path: holders and the owner alike keep re-fanning the record).
            || magic == &veil_crypto::nickname::NICKNAME_DHT_MAGIC[..]
            // Public Space discovery carrier ("XS"): short-lived,
            // holder-signed and canonical-key-bound at the dispatcher. The
            // application still verifies the strict descriptor/holder payload.
            || magic == &veil_crypto::space_discovery::SPACE_DISCOVERY_DHT_MAGIC[..]
            // Anycast service list ("AC"/"AD"/"AE"): every record in it carries
            // its own owner signature, re-verified at the STORE gate
            // (`anycast_store_gate`, which also merges rather than replaces so
            // a republish cannot erase other providers) and again at resolve
            // under the reader's own policy. Without this arm an advertisement
            // was `store_local`-only at the advertiser and reached no other
            // node at all: the republish driver skipped it, the receiving gate
            // had no arm for it, and a resolver anywhere else therefore
            // returned nothing, always. Anycast had never distributed anything
            // across the network.
            || veil_proto::anycast::is_anycast_blob(value)
    }

    /// Check whether a DHT record is eligible for republication at this time.
    /// P-Net bans require the network trust context in `republishable_record_at`.
    ///
    /// Most self-authenticating DHT types carry their own longer-lived
    /// lifecycle checks on resolve. `XS` is deliberately short-lived: sending
    /// an expired cached sample would make a correct peer classify a benign
    /// stale cache entry as an invalid STORE.
    ///
    /// DO NOT SEND WHAT YOU WOULD REFUSE, and this is not a tidiness rule.
    /// Measured on the production seeds the day 0.11.30 rolled out: ONE stale
    /// v1 `NicknameRecord` left in every holder's store — a name claimed
    /// before v2 existed — was re-fanned by each of them every republish
    /// interval, refused by every recipient as `Store: invalid NicknameRecord`,
    /// counted as a session VIOLATION, and after enough of them one seed
    /// auto-banned another. Four honest nodes made each other look like
    /// attackers over a record none of them would have accepted.
    ///
    /// A format change turns every holder into a violator unless the sender
    /// applies the receiver's rule first. `nickname_store_decision` is that
    /// rule, and it is the same call the STORE gate makes.
    pub fn is_republishable_dht_value_at(value: &[u8], now_unix_ms: u64) -> bool {
        if value.starts_with(BAN_BLOB_MAGIC) {
            return false;
        }
        if value.get(..2) == Some(&veil_crypto::space_discovery::SPACE_DISCOVERY_SAMPLES_MAGIC[..])
        {
            return veil_crypto::space_discovery::decode_space_discovery_samples(value)
                .and_then(|records| records.first().map(|record| record.route.dht_key()))
                .and_then(|key| {
                    veil_crypto::space_discovery::live_space_discovery_samples(
                        value,
                        &key,
                        now_unix_ms,
                    )
                })
                .is_some_and(|records| !records.is_empty());
        }
        if !Self::is_self_authenticating_dht_value(value) {
            return false;
        }
        if value.get(..2) == Some(&veil_crypto::space_discovery::SPACE_DISCOVERY_DHT_MAGIC[..]) {
            return veil_crypto::space_discovery::SpaceDiscoveryRecord::from_bytes(value)
                .is_some_and(|record| record.verify_at(now_unix_ms).is_ok());
        }
        if value.get(..2) == Some(&veil_crypto::nickname::NICKNAME_DHT_MAGIC[..]) {
            // `None` for the incumbent: this asks only "would a peer holding
            // nothing accept this record", which is the weakest form of the
            // question and the one a sender can answer. A peer that holds a
            // heavier incumbent still refuses, and that refusal is benign —
            // `RejectKeepExisting` is not a violation.
            return matches!(
                veil_crypto::nickname::nickname_store_decision(None, value),
                veil_crypto::nickname::StoreDecision::Accept
            );
        }
        true
    }

    pub(super) fn spawn_p_net_ban_forwarding(&mut self) {
        let (Some(shutdown_tx), Some(gate)) = (&self.shutdown_tx, &self.network_gate) else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let network_id = gate.expected_network_id;
        let dht = Arc::clone(&self.dht);
        let bans = Arc::clone(&self.ban_list);
        let session_outbox = Arc::clone(&self.session_outbox);
        let session_senders = Arc::clone(&self.session_tx_registry);
        let metrics = self.metrics.clone();
        let logger = Arc::clone(&self.logger);
        // Forwarding over live private sessions must keep ticking while the
        // general DHT republisher awaits iterative network lookups.
        let handle = supervised_spawn(
            Arc::clone(&self.logger),
            "p_net_ban_forwarding",
            async move {
                let mut catch_up = BanCatchUp::default();
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                let record_sent = |event, sent| {
                    if sent > 0 {
                        if let Some(m) = &metrics {
                            m.add_replicas_published(sent);
                        }
                        logger.info(event, format!("replicas_sent={sent}"));
                    }
                };

                loop {
                    tokio::select! {
                        biased;
                        result = shutdown_rx.changed() => {
                            if result.is_err() || *shutdown_rx.borrow() { break; }
                        }
                        _ = tick.tick() => {
                            let now = Instant::now();
                            catch_up.observe_sessions(&dht, &session_outbox, &bans, &network_id, now);
                            let (attempts, retried) = catch_up.retry_full_queues(&dht, &bans, &session_senders, now);
                            record_sent("network.ban.retry", retried);
                            if let Some((event, sent)) = catch_up.send_next_batch(
                                &dht, &bans, &session_senders, BAN_CATCH_UP_MAX_RECIPIENTS - attempts, now,
                            ) {
                                record_sent(event, sent);
                            }
                        }
                    }
                }
            },
        );
        lock_tasks(&self.tasks).sessions.push(handle);
    }

    pub fn spawn_dht_republish_task(&mut self, republish_interval: std::time::Duration) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let dht = Arc::clone(&self.dht);
        let network_gate = self.network_gate.clone();
        let session_outbox = Arc::clone(&self.session_outbox);
        let metrics = self.metrics.clone();
        let logger = Arc::clone(&self.logger);
        // Poked by the suspension detector — see the select arm below.
        let republish_now = Arc::clone(&self.dht_republish_now);
        let handle = supervised_spawn(Arc::clone(&self.logger), "dht_republish", async move {
            let interval = republish_interval;
            let mut scheduler = veil_dht::republish::RepublishScheduler::new();
            let mut tick_interval = tokio::time::interval(std::time::Duration::from_secs(1));
            tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    Ok(_) = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { break; }
                    }
                    // Suspension detected (`runtime/suspension_watch.rs`): the
                    // per-key due times in `RepublishScheduler` are `Instant`s,
                    // which froze with CLOCK_MONOTONIC while the device slept —
                    // so every key is now due LATE by the sleep length, while
                    // the remote holders of our replicas kept expiring them on
                    // the wall clock. Drop the schedule: every stored key
                    // re-staggers over `interval / 4` from now, the same
                    // bounded fan a fresh boot does, instead of trusting
                    // deadlines the suspension silently stretched.
                    _ = republish_now.notified() => {
                        scheduler = veil_dht::republish::RepublishScheduler::new();
                    }
                    _ = tick_interval.tick() => {
                        // audit cycle-7 M4: enumerate KEYS only (32 B each) and
                        // fetch values lazily for the few keys actually due
                        // this tick. The previous `stored_entries()` pulled
                        // every (key, value) pair — including the ENTIRE RocksDB
                        // cold tier — into RAM every second, defeating the disk
                        // tier (same bug class as the U2 cleanup-path fix).
                        // Republish semantics are unchanged: cold-tier records
                        // are still republished when their staggered due time
                        // arrives.
                        let keys = dht.stored_key_ids();
                        // Prune scheduler entries for keys no longer in the
                        // store, so the `RepublishScheduler` HashMap stays
                        // O(live_keys) rather than O(keys_seen_lifetime).
                        let live_keys: std::collections::HashSet<[u8; 32]> =
                            keys.iter().copied().collect();
                        scheduler.retain_keys(&live_keys);
                        for key in keys {
                            if !scheduler.next_due(key, interval) {
                                continue;
                            }
                            // Due — fetch the value now (non-promoting, so we
                            // don't churn the hot/cold boundary). The key may
                            // have been evicted between the key-scan and here;
                            // skip if so.
                            let Some(value) = dht.peek_value(&key) else {
                                continue;
                            };
                            // skip records without a recognized
                            // self-authenticating magic prefix. Unsigned
                            // STOREs for non-self keys are violations on the
                            // receiver (`Store: unsigned STORE for non-self
                            // key — ed25519 authenticator required`), so
                            // propagating them accumulates peer violations →
                            // `abuse.auto_ban` → peer-flapping. Accepted magics
                            // cover record types that carry their own signature
                            // (AppEndpoint, Attachment, sovereign-identity
                            // records). Anything else (legacy unsigned `encode_for_dht`
                            // intermediate local state, future record types
                            // without signed wire format) is not propagated.
                            let now_unix_ms = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
                                .unwrap_or(0);
                            if !republishable_record_at(network_gate.as_deref(), &key, &value, now_unix_ms) {
                                continue;
                            }
                            // audit follow-up: capture the fan-out count for
                            // observability. Fire-and-forget remains — we never
                            // wait for STORE acknowledgements (would serialise
                            // re-publish at RTT × K) — but we DO know how many
                            // peers the outbox accepted a frame for.
                            match dht.store_replicated(
                                key,
                                value,
                                Arc::clone(&session_outbox) as Arc<dyn veil_dht::FrameRouter>,
                            ).await {
                                Ok(replicas_sent) => {
                                    if let Some(m) = &metrics {
                                        if replicas_sent > 0 {
                                            m.add_replicas_published(replicas_sent as u64);
                                        } else {
                                            m.inc_replicas_under_count();
                                            logger.warn(
                                                "dht.republish.under_count",
                                                format!("key={} fan-out reached zero remote peers — partition or empty routing table",
                                                    veil_util::hex_short(&key)),
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    logger.warn(
                                        "dht.republish.failed",
                                        format!("key={} err={:?}", veil_util::hex_short(&key), e),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use veil_crypto::space_discovery::{SpaceDiscoveryRecord, SpaceDiscoveryRoute};
    use veil_dht::NetworkAuthGate;
    use veil_identity::network_ban::{ban_dht_key, canonical_ban_body, encode_ban_blob};
    use veil_identity::network_cert::{canonical_cert_body, encode_cert_blob};
    use veil_proto::priority;
    use veil_types::{
        BAN_ENTRY_VERSION, BanEntry, MEMBERSHIP_CERT_VERSION, MembershipCert, SignatureAlgorithm,
    };

    use super::{
        BAN_CATCH_UP_COOLDOWN, BAN_CATCH_UP_MAX_RECIPIENTS, BAN_RETRY_CAPACITY, BAN_RETRY_PER_TICK,
        BanCatchUp, BanList, Duration, Instant, KademliaService, Mutex, NetworkAccessGate,
        NodeRuntime, RwLock, SessionOutbox, SessionTxRegistry, republishable_record_at,
    };

    struct TestGate;

    impl NetworkAuthGate for TestGate {
        fn verify_ban_record(&self, _key: &[u8; 32], value: &[u8]) -> bool {
            value == b"PBAN-verified"
        }
    }

    #[test]
    fn ban_catch_up_uses_new_authenticated_registrations_and_coalesces_flaps() {
        let network = [1; 32];
        let target = [2; 32];
        let key = ban_dht_key(&network, &target);
        let mut bans = BanList::new();
        bans.ban_manual(target, "signed record candidate");
        bans.ban([3; 32], "temporary", Some(Duration::from_secs(600)));
        let bans = Mutex::new(bans);
        let outbox = SessionOutbox::new();
        let dht = KademliaService::new([100; 32]);
        let _unowned = outbox.register([4; 32]);
        let mut catch_up = BanCatchUp::default();
        let start = Instant::now();

        catch_up.observe_sessions(&dht, &outbox, &bans, &network, start);
        assert!(catch_up.reconnect.keys.is_empty());
        let _first = outbox.register_owned([5; 32], [6; 32]);
        catch_up.observe_sessions(&dht, &outbox, &bans, &network, start);
        assert_eq!(catch_up.reconnect.keys.pop_front(), Some(key));
        assert!(catch_up.reconnect.keys.is_empty());
        catch_up.observe_sessions(
            &dht,
            &outbox,
            &bans,
            &network,
            start + Duration::from_secs(1),
        );
        assert!(catch_up.pending.is_empty());

        let second = outbox.register_owned([5; 32], [7; 32]);
        catch_up.observe_sessions(
            &dht,
            &outbox,
            &bans,
            &network,
            start + Duration::from_secs(2),
        );
        assert!(!catch_up.pending.is_empty() && catch_up.reconnect.keys.is_empty());
        catch_up.observe_sessions(
            &dht,
            &outbox,
            &bans,
            &network,
            start + BAN_CATCH_UP_COOLDOWN,
        );
        assert!(catch_up.pending.is_empty());
        assert_eq!(catch_up.reconnect.keys.pop_front(), Some(key));
        assert_eq!(catch_up.reconnect.recipients, vec![([5; 32], [7; 32])]);

        drop(second);
        catch_up.observe_sessions(
            &dht,
            &outbox,
            &bans,
            &network,
            start + 2 * BAN_CATCH_UP_COOLDOWN,
        );
        assert!(catch_up.sessions.is_empty() && catch_up.reconnect.keys.is_empty());
    }

    #[test]
    fn ban_catch_up_batches_all_new_peers_with_a_fixed_send_budget() {
        let network = [1; 32];
        let target = [2; 32];
        let key = ban_dht_key(&network, &target);
        let mut dht = KademliaService::new([100; 32]);
        dht.set_network_auth_gate(std::sync::Arc::new(TestGate));
        dht.store_local(key, b"PBAN-verified".to_vec());
        let mut bans = BanList::new();
        bans.ban_manual(target, "signed record candidate");
        let outbox = SessionOutbox::new();
        let receivers: Vec<_> = (10..29)
            .map(|peer| outbox.register_owned([peer; 32], [peer + 1; 32]))
            .collect();
        let mut catch_up = BanCatchUp::default();
        catch_up.observe_sessions(&dht, &outbox, &Mutex::new(bans), &network, Instant::now());
        let mut delivered = Vec::new();
        let reduced_budget = BAN_CATCH_UP_MAX_RECIPIENTS - BAN_RETRY_PER_TICK;
        for (limit, expected) in [(reduced_budget, 4), (8, 8), (8, 7)] {
            let (event, batch) = catch_up.next_batch(&dht, limit).unwrap();
            assert_eq!(event, "network.ban.catch_up");
            assert_eq!(batch.recipients.len(), expected);
            let header = veil_proto::codec::decode_header(&batch.frame).unwrap();
            assert_eq!(header.priority(), veil_proto::priority::BACKGROUND);
            assert_eq!(
                header.msg_type,
                veil_proto::family::DiscoveryMsg::Store as u16
            );
            delivered.extend(batch.recipients.iter().map(|(peer, _)| peer[0]));
        }
        assert_eq!(delivered, (10..29).collect::<Vec<_>>());
        assert!(
            catch_up
                .next_batch(&dht, BAN_CATCH_UP_MAX_RECIPIENTS)
                .is_none()
        );
        drop(receivers);
    }

    #[test]
    fn a_session_queue_that_stays_full_sends_the_ban_once_it_drains() {
        let key = [7; 32];
        let peer = [8; 32];
        let owner = [9; 32];
        let ready_peer = ([10; 32], [11; 32]);
        let mut dht = KademliaService::new([100; 32]);
        dht.set_network_auth_gate(std::sync::Arc::new(TestGate));
        dht.store_local(key, b"PBAN-verified".to_vec());
        let bans = Mutex::new(BanList::new());
        let mut senders = SessionTxRegistry::with_capacity(1);
        let mut rx = senders.register_owned(peer, owner);
        let mut ready_rx = senders.register_owned(ready_peer.0, ready_peer.1);
        senders
            .send_to_owned_result(&peer, &owner, priority::INTERACTIVE, b"busy".to_vec())
            .unwrap();
        let senders = RwLock::new(senders);
        let mut catch_up = BanCatchUp::default();
        catch_up.fresh.keys.push_back(key);
        catch_up.fresh.recipients.push((peer, owner));
        let now = Instant::now();

        assert_eq!(
            catch_up.send_next_batch(&dht, &bans, &senders, BAN_CATCH_UP_MAX_RECIPIENTS, now),
            Some(("network.ban.forwarded", 0)),
        );
        assert_eq!(catch_up.retries.len(), 1);
        catch_up.defer_full_queue(key, (peer, owner), now);
        let tick = Duration::from_secs(1);
        for second in 1..29 {
            let due = matches!(second, 1 | 3 | 7 | 15);
            assert_eq!(
                catch_up.retry_full_queues(&dht, &bans, &senders, now + second * tick),
                (usize::from(due), 0),
            );
        }
        // A backed-off entry at the front does not delay a due entry behind it.
        catch_up.defer_full_queue(key, ready_peer, now + 28 * tick);
        assert_eq!(
            catch_up.retry_full_queues(&dht, &bans, &senders, now + 29 * tick),
            (1, 1)
        );
        assert_eq!(ready_rx.try_recv().unwrap().0, priority::BACKGROUND);
        assert_eq!(rx.try_recv().unwrap().1.as_ref(), b"busy");

        assert_eq!(
            catch_up.retry_full_queues(&dht, &bans, &senders, now + 30 * tick),
            (1, 1)
        );
        let (prio, frame) = rx.try_recv().unwrap();
        assert_eq!(prio, priority::BACKGROUND);
        let body = &frame.as_ref()[veil_proto::header::HEADER_SIZE..];
        let store = veil_proto::discovery::StorePayload::decode(body).unwrap();
        assert_eq!(store.key, key);
        assert_eq!(store.value, b"PBAN-verified");
        assert!(catch_up.retries.is_empty());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn retries_are_bounded_and_check_the_current_record_and_registration() {
        let key = [7; 32];
        let peer = [8; 32];
        let stale_owner = [9; 32];
        let owner = [10; 32];
        let mut dht = KademliaService::new([100; 32]);
        dht.set_network_auth_gate(std::sync::Arc::new(TestGate));
        dht.store_local(key, b"PBAN-verified".to_vec());
        let bans = Mutex::new(BanList::new());
        let mut senders = SessionTxRegistry::with_capacity(1);
        let mut rx = senders.register_owned(peer, owner);
        let senders = RwLock::new(senders);
        let mut catch_up = BanCatchUp::default();
        let now = Instant::now();
        let tick = Duration::from_secs(1);

        catch_up.defer_full_queue(key, (peer, stale_owner), now);
        assert_eq!(
            catch_up.retry_full_queues(&dht, &bans, &senders, now + tick),
            (1, 0)
        );
        assert!(catch_up.retries.is_empty());
        assert!(rx.try_recv().is_err());

        catch_up.defer_full_queue(key, (peer, owner), now);
        dht.store_local(key, b"PBAN-invalid".to_vec());
        assert_eq!(
            catch_up.retry_full_queues(&dht, &bans, &senders, now + tick),
            (1, 0)
        );
        assert!(catch_up.retries.is_empty());
        assert!(rx.try_recv().is_err());

        for i in 0..BAN_RETRY_CAPACITY {
            let mut distinct_key = key;
            distinct_key[..2].copy_from_slice(&(i as u16).to_le_bytes());
            catch_up.defer_full_queue(distinct_key, (peer, owner), now);
        }
        assert_eq!(catch_up.retries.len(), BAN_RETRY_CAPACITY);
        // A newer ban remains eligible even when a stalled session has
        // already filled every slot. Its retry is independent of the old work.
        let new_key = [42; 32];
        catch_up.retries[0].backoff *= 2;
        let evicted = catch_up.retries[0].key;
        catch_up.defer_full_queue(new_key, (peer, owner), now);
        assert_eq!(catch_up.retries.len(), BAN_RETRY_CAPACITY);
        assert!(catch_up.retries.iter().all(|retry| retry.key != evicted));
        assert_eq!(catch_up.retries.back().unwrap().key, new_key);
        assert_eq!(
            catch_up.retry_full_queues(&dht, &bans, &senders, now + tick),
            (BAN_RETRY_PER_TICK, 0)
        );
        assert_eq!(
            catch_up.retries.len(),
            BAN_RETRY_CAPACITY - BAN_RETRY_PER_TICK
        );
    }

    #[test]
    fn p_net_ban_republish_rechecks_the_network_authority() {
        let owner = SigningKey::from_bytes(&[1; 32]);
        let admin = SigningKey::from_bytes(&[2; 32]);
        let admin_pubkey = admin.verifying_key().to_bytes().to_vec();
        let admin_node_id = *blake3::hash(&admin_pubkey).as_bytes();
        let network_id = [3; 32];
        let target = [4; 32];
        let mut cert = MembershipCert {
            version: MEMBERSHIP_CERT_VERSION,
            network_id,
            member_node_id: admin_node_id,
            issued_at_unix: 10,
            valid_until_unix: 30,
            admin: true,
            algo: SignatureAlgorithm::Ed25519,
            owner_signature: Vec::new(),
        };
        cert.owner_signature = owner.sign(&canonical_cert_body(&cert)).to_bytes().to_vec();
        let mut entry = BanEntry {
            version: BAN_ENTRY_VERSION,
            network_id,
            banned_node_id: target,
            reason: "test ban".into(),
            issued_at_unix: 15,
            admin_node_id,
            admin_cert_blob: encode_cert_blob(&cert),
            admin_pubkey,
            admin_signature: Vec::new(),
        };
        entry.admin_signature = admin.sign(&canonical_ban_body(&entry)).to_bytes().to_vec();
        let blob = encode_ban_blob(&entry);
        let key = ban_dht_key(&network_id, &target);
        let mut gate = NetworkAccessGate {
            local_cert_blob: Vec::new(),
            expected_network_id: network_id,
            owner_algo: SignatureAlgorithm::Ed25519,
            owner_pubkey_bytes: owner.verifying_key().to_bytes().to_vec(),
            admin_node_ids: [admin_node_id].into(),
        };

        assert!(republishable_record_at(Some(&gate), &key, &blob, 29_999));
        assert!(!republishable_record_at(Some(&gate), &key, &blob, 30_000));
        assert!(!republishable_record_at(
            Some(&gate),
            &[5; 32],
            &blob,
            29_999
        ));
        assert!(!republishable_record_at(None, &key, &blob, 29_999));
        assert!(!NodeRuntime::is_republishable_dht_value_at(&blob, 29_999));
        gate.admin_node_ids = [[6; 32]].into();
        assert!(!republishable_record_at(Some(&gate), &key, &blob, 29_999));
    }

    #[test]
    fn expired_space_discovery_records_are_not_republished() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let valid = SpaceDiscoveryRecord::sign(
            SpaceDiscoveryRoute::Direct([3; 32]),
            [3; 32],
            &key,
            1_000,
            2_000,
            vec![1],
        )
        .to_bytes();
        assert!(NodeRuntime::is_republishable_dht_value_at(&valid, 1_500));
        assert!(!NodeRuntime::is_republishable_dht_value_at(&valid, 2_000));
    }

    #[test]
    fn space_discovery_bucket_republish_keeps_live_holders_after_another_expires() {
        use veil_crypto::space_discovery::merge_space_discovery_sample;
        let first = SpaceDiscoveryRecord::sign(
            SpaceDiscoveryRoute::Search([3; 32]),
            [4; 32],
            &SigningKey::from_bytes(&[9; 32]),
            1_000,
            2_000,
            vec![1],
        )
        .to_bytes();
        let second = SpaceDiscoveryRecord::sign(
            SpaceDiscoveryRoute::Search([3; 32]),
            [4; 32],
            &SigningKey::from_bytes(&[8; 32]),
            1_000,
            3_000,
            vec![2],
        )
        .to_bytes();
        let bucket = merge_space_discovery_sample(Some(&first), &second, 1_500, &[7; 32]).unwrap();
        assert!(NodeRuntime::is_republishable_dht_value_at(&bucket, 2_000));
        assert!(!NodeRuntime::is_republishable_dht_value_at(&bucket, 3_000));
        let mut forged = bucket;
        let end = forged.len() - 1;
        forged[end] ^= 1;
        assert!(!NodeRuntime::is_republishable_dht_value_at(&forged, 1_500));
    }
}
