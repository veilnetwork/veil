//! Test/sim-only debug accessors on `NodeRuntime`. Extracted from
//! `runtime/mod.rs` during refactor so the core runtime
//! module doesn't carry ~200 LOC of sim-harness wiring.
//!
//! Everything here is `pub fn` (callable from the sim crate and
//! integration tests); nothing is load-bearing in the production path.

use std::sync::Arc;
use veil_util::lock;

use super::{NodeRuntime, Result};

impl NodeRuntime {
    /// Test/simulation bridge for the production token-bearing signaling
    /// path. Unlike `attempt_nat_traversal_via`, this supplies the one-time
    /// token that makes the target hand the request to its asynchronous UDP
    /// punch responder. Real callers enter through
    /// `nat_fallback_dial`/`udp_hole_punch_dial` and generate the token there.
    pub async fn debug_attempt_nat_traversal_via_with_punch_token(
        &self,
        target_node_id: [u8; 32],
        coordinator_node_id: [u8; 32],
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        timeout: std::time::Duration,
        punch_token: [u8; 16],
    ) -> Option<veil_proto::control::NatProbeReplyPayload> {
        self.access()
            .attempt_nat_traversal_via_with_punch_token(
                target_node_id,
                coordinator_node_id,
                local_candidates,
                timeout,
                Some(punch_token),
            )
            .await
    }

    /// (test-only): force immediate publish of this node's
    /// signed relay-directory entry to the local DHT, bypassing the
    /// 60-second maintenance-tick scheduler. Returns `Ok(true)` when
    /// the node is `relay_capable` AND publish actually wrote an entry;
    /// `Ok(false)` when the node is not `relay_capable` (no-op); never
    /// returns Err in current implementation but the signature reserves
    /// space for sign-failure surfacing.
    pub async fn debug_force_publish_relay_directory_entry(&self) -> Result<bool> {
        Ok(NodeRuntime::tick_publish_relay_directory_entry(
            self.anonymity.relay_capable,
            self.anonymity.advertised_bps,
            self.anonymity.x25519_sk.as_ref(),
            &self.identity.local_identity,
            &self.dht,
            &self.logger,
        ))
    }

    /// (test-only): force immediate publish of any registered
    /// rendezvous-ads to the local DHT, bypassing the maintenance-tick
    /// scheduler. Returns the number of ads published this call (0 if no
    /// `RendezvousPublisherEntry` is registered, otherwise typically 1
    /// since one ad covers the receiver's slot).
    pub async fn debug_force_publish_rendezvous_ads(&self) -> usize {
        NodeRuntime::tick_publish_rendezvous_ads(
            &self.anonymity.rendezvous_publisher_entries,
            self.anonymity.x25519_sk.as_ref(),
            &self.identity.local_identity,
            &self.dht,
            &self.logger,
            None, // documented as local-only force-publish
        )
    }

    /// test-only helper — force immediate DHT replication of
    /// every key in the local DHT store, bypassing the 1-second `DhtRepublish`
    /// scheduler. Used by integration tests that want a deterministic signal
    /// without racing the scheduler jitter.
    pub async fn debug_force_dht_republish(&self) {
        let entries = self.dht.stored_entries();
        for (key, value) in entries {
            let _ = self
                .dht
                .store_replicated(
                    key,
                    value,
                    Arc::clone(&self.session_outbox) as Arc<dyn veil_dht::FrameRouter>,
                )
                .await;
        }
    }

    /// (test-only): resolve a sovereign
    /// `Recipient` to the live peer_ids that own a session for it
    /// on this node. Used by sim scenarios to assert that
    /// `InstanceTag::All` actually fans out to every live
    /// instance after multi-instance setup, that
    /// `InstanceTag::Specific(inst)` hits one peer, and that
    /// `InstanceTag::Any` returns one of the live instances.
    pub fn debug_resolve_recipient(
        &self,
        recipient: &veil_proto::recipient::Recipient,
    ) -> Vec<[u8; 32]> {
        self.session_registry
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .resolve_recipient(recipient)
    }

    /// (test-only): raw snapshot of the session
    /// registry's `(node_id, instance_id)` composite keys.
    /// Used by diagnostics for multi-instance fan-out tests.
    pub fn debug_session_identity_instances(&self) -> Vec<([u8; 32], [u8; 16])> {
        self.session_registry
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .debug_identity_instance_keys()
    }

    /// (test-only): score-based
    /// `InstanceTag::Any` pick — accept a per-instance scorer
    /// closure, return the live peer_id with the highest score.
    /// In production the dispatcher would compose reputation +
    /// RTT + battery into the scorer; sim scenarios pass a
    /// fixture closure.
    pub fn debug_resolve_recipient_any_scored<F>(
        &self,
        node_id: &[u8; 32],
        scorer: F,
    ) -> Option<[u8; 32]>
    where
        F: Fn([u8; 32], [u8; 16]) -> f64,
    {
        self.session_registry
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .peer_id_for_identity_scored(&veil_cfg::NodeId::from(*node_id), scorer)
    }

    /// (test-only): re-publish the sovereign identity
    /// into the local DHT (document + instance registry + ML-KEM
    /// cert + persisted name claims), equivalent to the initial-
    /// startup publish path. Used by sim scenarios after a
    /// config reload (`wire_full_mesh` etc.) swaps out the
    /// `KademliaService` and wipes the pre-reload store.
    ///
    /// The sovereign handle is re-loaded from `<veil_dir>/…`
    /// on every call so mid-scenario `rotate_identity` / `revoke`
    /// updates to the on-disk document propagate without waiting
    /// for the production 60 s mtime-poll on the republish task.
    /// No-op when no sovereign identity is on disk.
    pub async fn debug_republish_sovereign_identity(&self) -> Result<()> {
        let veil_dir = self
            .config_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .to_path_buf();
        let Ok(sov) = veil_identity::sovereign::SovereignIdentity::load_from_dir(&veil_dir) else {
            return Ok(());
        };
        let sov = Arc::new(sov);
        let publisher =
            crate::identity_local::publisher_dht::DhtBackedPublisher::new(Arc::clone(&self.dht));
        let _ = veil_identity::publish::publish_identity_document(&sov.document, &publisher).await;
        let instance_entry = veil_identity::publish::build_instance_entry(
            sov.active_instance_id(),
            sov.sig_key_idx,
            String::new(),
            0,
        );
        let registry = sov.build_and_sign_registry(1, vec![instance_entry]);
        let _ = veil_identity::publish::publish_instance_registry(&registry, &publisher).await;
        let cert_valid_from = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Ok(cert) = sov.sign_mlkem_cert(
            self.identity.mlkem_ek.as_slice().to_vec(),
            cert_valid_from,
            cert_valid_from + 30 * 86_400,
            1,
        ) {
            let _ = veil_identity::publish::publish_mlkem_cert(&cert, &publisher).await;
        }
        let veil_dir = self
            .config_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .to_path_buf();
        if let Ok(claims) = veil_identity::sovereign::load_persisted_name_claims(&veil_dir) {
            for claim in &claims {
                let _ = veil_identity::publish::publish_name_claim(claim, &publisher).await;
            }
        }
        Ok(())
    }

    /// test-only — whether this node has an ed25519 signing key
    /// wired into its `DiscoveryService`. Used by sim tests to assert that
    /// signed DHT records can be produced at all.
    pub fn debug_has_ed25519_signing_key(&self) -> bool {
        self.dispatcher.crypto.local_signing_key.is_some()
    }

    /// test-only — inspect raw DHT value bytes by key.
    /// Returns `None` if the key is not stored locally.
    pub fn debug_dht_raw_value(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.dht.get_local(key)
    }

    /// test-only — remove a key from the local DHT shard
    /// so a subsequent resolve has to go to the network. Used by
    /// sim tests that exercise the multi-replica quorum path
    /// (without this, the local fast-path in `dht_get_replicated`
    /// short-circuits and never fans out).
    pub fn debug_dht_delete_local(&self, key: &[u8; 32]) {
        self.dht.delete_local(key);
    }

    /// test-only — check whether this node has cached a
    /// `SESSION_TICKET` for `peer_node_id`. Used by sim tests that
    /// verify ticket-based session-resume survives a transport
    /// disconnect (the ticket cache must NOT be flushed on session
    /// close, otherwise every WiFi → cellular network change forces
    /// a full re-handshake). Read-only; does not mutate state.
    pub fn debug_peer_tickets_contains(&self, peer_node_id: &[u8; 32]) -> bool {
        lock!(self.resumption.peer_tickets).contains_key(peer_node_id)
    }

    /// test-only — total number of cached client tickets.
    pub fn debug_peer_tickets_count(&self) -> usize {
        lock!(self.resumption.peer_tickets).len()
    }

    /// hygiene (test-only): inspect the size of the
    /// dispatcher's `nat_probe_waiters` map. Used by sim tests that
    /// verify the `MAX_NAT_PROBE_WAITERS` cap actually rejects new
    /// inserts when the map is full. Read-only.
    pub fn debug_nat_probe_waiters_count(&self) -> usize {
        lock!(self.dispatcher.nat_probe_waiters).len()
    }

    /// hygiene (test-only): pre-fill the dispatcher's
    /// `nat_probe_waiters` map with `count` dummy oneshot senders.
    /// Returns the receivers so the caller can keep them alive
    /// (drop = sender closed = `retain` cleanup at next insert
    /// would remove them, defeating the test scenario). Used to
    /// simulate "many concurrent in-flight probes" so we can
    /// exercise the cap-rejection path without spinning up a
    /// realistic flood of network traversals.
    pub fn debug_fill_nat_probe_waiters(
        &self,
        count: usize,
    ) -> Vec<tokio::sync::oneshot::Receiver<veil_proto::control::NatProbeReplyPayload>> {
        let mut receivers = Vec::with_capacity(count);
        let mut waiters = lock!(self.dispatcher.nat_probe_waiters);
        for token in 0..count {
            let (tx, rx) =
                tokio::sync::oneshot::channel::<veil_proto::control::NatProbeReplyPayload>();
            waiters.insert(token as u32, tx);
            receivers.push(rx);
        }
        receivers
    }

    /// (test-only): inject a `PeerConfigEntry`
    /// directly into `state.peers` with caller-supplied
    /// `transport`/`node_id`/`public_key`/`nonce`. Returns the
    /// freshly-allocated `PeerId`.
    ///
    /// The motivating sim-test scenario is "stale-bootstrap recovery":
    /// A holds a peer entry for B with a deliberately-wrong transport
    /// URI (e.g., `tcp://127.0.0.1:9` — RFC 1340 "discard"), then
    /// `connect_peer_active` should fail the primary dial and
    /// auto-trigger NAT-traversal fallback. Without this
    /// debug hook the test would have to either (a) round-trip
    /// through `SimNetwork::connect` which establishes a real session
    /// (defeating the test precondition), or (b) re-implement the
    /// peer-insertion plumbing inline in every fixture.
    ///
    /// `peer_id` is generated as `i32::MAX - peers.len` to avoid
    /// colliding with the production allocator (which counts up
    /// from low values via `peer_id_counter` in
    /// `mesh_gateway.rs`). The high-end allocation is purely a sim
    /// hygiene measure — production never gets close to `i32::MAX`.
    pub fn debug_insert_peer_with_transport(
        &self,
        node_id: [u8; 32],
        public_key: String,
        nonce: String,
        transport: String,
        algo: veil_cfg::SignatureAlgorithm,
    ) -> crate::types::PeerId {
        use crate::types::{PeerConfigEntry, PeerId, PeerSource};
        use std::str::FromStr;
        // Round-trip through hex because `NodeId` is intentionally
        // opaque outside the cfg module — no public `from_bytes`
        // constructor. hex_round_trip is infallible for any 32-byte
        // input, so unwrap is safe.
        let node_id_hex = veil_util::bytes_to_hex(&node_id);
        let node_id = veil_cfg::NodeId::from_str(&node_id_hex)
            .expect("32-byte → hex → NodeId round-trip is infallible");
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let peer_id = PeerId::new(i32::MAX as u32 - state.peers.len() as u32);
        let entry = PeerConfigEntry {
            peer_id,
            node_id,
            public_key,
            nonce,
            transport,
            algo,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            bootstrap_only: false,
            source: PeerSource::Configured,
        };
        state.peers.insert(peer_id, entry);
        peer_id
    }
}
