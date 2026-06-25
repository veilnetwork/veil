//! Periodic republish of locally-stored DHT entries to K-closest peers
//! (Kademlia spec: republish at TTL/2).
//!
//! Extracted from `runtime/mod.rs` during refactor.

use std::sync::Arc;

use super::{NodeRuntime, lock_tasks, supervised_spawn};

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
        if value.len() >= 4 && &value[..4] == veil_identity::network_ban::BAN_BLOB_MAGIC {
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
    }

    pub fn spawn_dht_republish_task(&mut self, republish_interval: std::time::Duration) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let mut shutdown_rx = shutdown_tx.subscribe();
        let dht = Arc::clone(&self.dht);
        let session_outbox = Arc::clone(&self.session_outbox);
        let metrics = self.metrics.clone();
        let logger = Arc::clone(&self.logger);
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
                            if !Self::is_self_authenticating_dht_value(&value) {
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
