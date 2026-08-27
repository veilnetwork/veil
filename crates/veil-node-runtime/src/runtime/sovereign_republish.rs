//! Periodic re-publish of the local sovereign `IdentityDocument` +
//! `InstanceRegistry` + `MlKemKeyCert` + `PrekeyBundle` + `NameClaim`
//! records to the DHT.
//!
//! Extracted from `runtime/mod.rs` during refactor.
//! No-op when the node is running in legacy (node_id-keyed) mode.

use std::sync::Arc;
use std::time::Duration;

use super::{NodeRuntime, lock_tasks, supervised_spawn};

/// adaptive republish-interval scaling. At trillion
/// scale, network-wide republish load = `O(N × frequency)`. A node
/// with a dense routing-table (many peers know about it) doesn't
/// need to refresh as often — its identity record sits in the DHT
/// stores of many neighbours which themselves republish on their
/// own schedules. A sparsely-connected node (just joined / on a
/// flaky cellular link / behind a CGN-NAT with high churn) must
/// republish more often to maintain visibility.
///
/// On budget cellular phones this also cuts metered-bandwidth +
/// battery: each republish ≈ 1-3 KB DHT STORE × ~k peers; cutting
/// from 6h to 24h cadence saves 75 % of identity-republish bytes
/// (the typical leaf-on-WiFi case where routing table is dense).
///
/// `target_density` is the reference point — a node whose routing
/// table holds exactly `target_density` contacts uses the base
/// interval. Above target → multiplied (less frequent). Below →
/// divided (more frequent). Multiplier clamped to `[0.5, 4.0]`
/// so neither extreme drifts off the safe plateau.
///
/// Pure function — caller passes the current routing-table size.
pub fn adaptive_republish_interval(
    base: Duration,
    current_routing_table_size: usize,
    target_density: usize,
) -> Duration {
    if target_density == 0 {
        return base;
    }
    let raw = (current_routing_table_size.max(1) as f64) / (target_density as f64);
    let multiplier = raw.clamp(0.5, 4.0);
    let scaled_secs = (base.as_secs_f64() * multiplier).round() as u64;
    Duration::from_secs(scaled_secs)
}

impl NodeRuntime {
    /// runtime: periodic re-publish of the node's sovereign
    /// `IdentityDocument` to the DHT. Keeps the record fresh against
    /// its freshness-window / TTL so late-arriving peers can still
    /// resolve this identity after hours of uptime.
    ///
    /// No-op when no sovereign identity is loaded (legacy nodes).
    /// Cadence: hard-coded 6h default (matches the `IdentityDocument
    /// freshness` figure in `docs/identity-model.md`). A dedicated
    /// config knob can ship with a later polish pass — this task's
    /// whole behavior is idempotent, so the exact interval is a
    /// knob on a safe plateau.
    pub fn spawn_sovereign_identity_republish_task(&mut self) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let Some(sov) = self.identity.sovereign_identity.get() else {
            // Legacy node — nothing to republish.
            return;
        };
        // The CELL, so a document this task re-reads from disk becomes the
        // document the rest of the node uses. Re-reading into the task's own
        // handle and stopping there is what made a merged second device visible
        // to the DHT and invisible to everything local: sealing, handshakes and
        // the delegation re-issue all read the cell.
        let sovereign_cell = self.identity.sovereign_identity.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();
        let dht = Arc::clone(&self.dht);
        let dht_for_density = Arc::clone(&self.dht);
        // republish ticks fan publishes out to K-closest
        // replicas via this session_tx_registry — without it
        // `IdentityDocument` / `NameClaim` are local-only and vanish
        // when the publisher goes offline.
        let session_tx_registry = Arc::clone(&self.session_tx_registry);
        let local_node_id_for_replication = *self.identity.local_identity.node_id.as_bytes();
        // subscribe to routing-table-change notifications so
        // a freshly-joined closer-in-keyspace peer picks up replicas
        // immediately instead of waiting for the next 6h republish.
        // Critical under churn (mobile peers walking around with WiFi
        // handoffs every few minutes). Debounced — see the
        // `DEBOUNCE_AFTER_PUBLISH` window below — to keep cellular
        // bandwidth + battery cost bounded on cheap Android.
        let route_updated = Arc::clone(&self.dispatcher.route_updated);
        let logger = Arc::clone(&self.logger);
        // MlKemCert republish needs the node's own ML-KEM ek to re-sign
        // with a fresh validity window each tick.
        let mlkem_keys = Arc::clone(&self.identity.mlkem_keys);
        // Poked by `spawn_mlkem_rotation_task`; see the select arm below.
        let mlkem_republish_now = Arc::clone(&self.mlkem_republish_now);
        // RelayKeyRecord republish: only relay-capable nodes have an anonymity
        // X25519 keypair to advertise (`None` for non-relays — we skip the
        // record entirely so we never publish a key the dispatcher can't
        // actually decrypt onions for).
        let relay_x25519_pk = self.anonymity_x25519_pk();
        // Veil dir for re-scanning persisted name claims on each tick
        // (so a claim added mid-session starts publishing at the next
        // republish without requiring a node restart).
        let veil_dir = self.identity_dir.clone();

        /// Default republish cadence — matches the 6-hour TTL/freshness
        /// figure cited in `docs/identity-model.md`.
        const SOVEREIGN_REPUBLISH_INTERVAL: std::time::Duration =
            std::time::Duration::from_secs(6 * 3600);

        /// on-change republish — poll the identity
        /// document's disk mtime at this cadence so rotate/revoke
        /// edits made by the CLI propagate to peers within a minute
        /// rather than waiting the full 6 hours. 60 s is a
        /// reasonable balance between tail-latency on key-compromise
        /// revocation and filesystem-stat cost at scale.
        ///
        /// `test-low-difficulty` feature shrinks this to 2 s so
        /// devnet smoke tests can validate the on-change republish
        /// path without a 60-second
        /// wall clock wait. Production builds keep the 60 s cadence.
        #[cfg(any(test, feature = "test-low-difficulty"))]
        const SOVEREIGN_ON_CHANGE_POLL_INTERVAL: std::time::Duration =
            std::time::Duration::from_secs(2);
        #[cfg(not(any(test, feature = "test-low-difficulty")))]
        const SOVEREIGN_ON_CHANGE_POLL_INTERVAL: std::time::Duration =
            std::time::Duration::from_secs(60);

        // What the NETWORK will hand a peer for us, asked of the network the
        // same way a peer asks. A node can be perfectly self-consistent —
        // advertising exactly the keys it holds — and still be unreachable
        // because what is actually stored under its key is something else.
        // Nothing compared those two, so that gap was invisible.
        // Frames that never reached the wire, counted where they are shed.
        // Without this a lost frame is indistinguishable from one the network
        // ate, and the search goes to the network every time.
        let drop_metrics = self.metrics.clone();
        let selfcheck_resolver = self.proxy_mlkem_ek_resolver();
        let selfcheck_node_id = *self.identity.local_identity.node_id.as_bytes();
        let selfcheck_ring = Arc::clone(&self.identity.mlkem_keys);

        let handle = supervised_spawn(
            Arc::clone(&self.logger),
            "sovereign_identity_republish",
            async move {
                let publisher =
                    crate::identity_local::publisher_dht::DhtBackedPublisher::with_replication(
                        dht,
                        session_tx_registry,
                        local_node_id_for_replication,
                    );
                // One-shot, once the routing table has had a chance to fill:
                // ask the network for OUR OWN certificate exactly as a peer
                // would, and print it beside the keys we actually hold. Equal
                // means a peer can seal something we can open. Different means
                // every peer is sealing to keys we cannot answer, and no amount
                // of looking at our own publish path would ever show it.
                let _selfcheck = {
                    let resolver = Arc::clone(&selfcheck_resolver);
                    let ring = Arc::clone(&selfcheck_ring);
                    let lg = Arc::clone(&logger);
                    // OWNED, not detached (report17 V17-L8). Aborting this
                    // republish task does not touch what it spawned, so a
                    // 45-second sleeper outlived every reload: a node that
                    // reloaded its identity a few times in a minute ended up
                    // with several of them, each waking to make a network
                    // resolve and warn on behalf of a service that was gone.
                    // The guard lives to the end of the task body, so the
                    // child goes when the task does — by return, by panic or
                    // by abort.
                    crate::runtime::AbortOnDrop(tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(45)).await;
                        let held_pk = veil_util::bytes_to_hex(&ring.current_ratchet_pk()[..4]);
                        let held_ek = veil_util::bytes_to_hex(&ring.current_ek()[..4]);
                        match resolver.resolve_cert(selfcheck_node_id).await {
                            Some(c) => {
                                let net_pk = veil_util::bytes_to_hex(&c.ratchet_x25519_pk[..4]);
                                let net_ek =
                                    veil_util::bytes_to_hex(&c.mlkem_ek[..4.min(c.mlkem_ek.len())]);
                                let agree = net_pk == held_pk && net_ek == held_ek;
                                lg.warn(
                                    "node.identity.selfcheck",
                                    format!(
                                        "network returns ratchet_pk={net_pk} ek={net_ek}; \
                                         we hold ratchet_pk={held_pk} ek={held_ek} — {}",
                                        if agree { "AGREE" } else { "DISAGREE" }
                                    ),
                                );
                            }
                            None => lg.warn(
                                "node.identity.selfcheck",
                                format!(
                                    "network returned NO certificate for us; we hold \
                                     ratchet_pk={held_pk} ek={held_ek} — no peer can seal \
                                     anything this node could open"
                                ),
                            ),
                        }
                    }))
                };
                // target routing-table density at which we
                // use the base republish cadence. Above target → less
                // frequent (save bandwidth); below → more frequent
                // (maintain visibility under churn). 100 is a sensible
                // default for "well-connected leaf" — operator can tune
                // via config if specific deployment needs differ.
                const TARGET_ROUTING_TABLE_DENSITY: usize = 100;

                let initial_interval = adaptive_republish_interval(
                    SOVEREIGN_REPUBLISH_INTERVAL,
                    dht_for_density.routing_table_contacts().len(),
                    TARGET_ROUTING_TABLE_DENSITY,
                );
                // First REPLICATED republish fires ~2 min after startup (once
                // the routing table has peers), NOT a full interval (up to 6h)
                // later. The startup one-shots publish LOCAL-ONLY (no peers
                // exist yet — see DhtBackedPublisher::new), so a freshly-minted
                // record (e.g. a new RelayKeyRecord on a just-restarted node)
                // is not cross-node discoverable until the first with_replication
                // republish. Firing it early closes that cold-start window from
                // up to 6h down to ~minutes; steady-state cadence (recomputed
                // adaptively after each tick) is unchanged. Shrunk under
                // `test-low-difficulty` so devnet smoke tests don't wait 2 min.
                #[cfg(any(test, feature = "test-low-difficulty"))]
                const REPUBLISH_WARMUP: std::time::Duration = std::time::Duration::from_secs(3);
                #[cfg(not(any(test, feature = "test-low-difficulty")))]
                const REPUBLISH_WARMUP: std::time::Duration = std::time::Duration::from_secs(120);
                let mut next_republish_at = tokio::time::Instant::now() + REPUBLISH_WARMUP;
                let mut interval = tokio::time::interval_at(next_republish_at, initial_interval);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

                // Cold-start warmup phase. The adaptive interval floors at 0.5×
                // base (≈3h), so a republish that fires while the routing table
                // is still sparse (just-restarted node, or a fleet-wide restart
                // where ALL peers are cold) replicates to an INACCURATE K-closest
                // set — `find_closest` can't see the true closest peers yet — and
                // a freshly-minted record (e.g. a RelayKeyRecord with no prior
                // replicas) then stays cross-node-unresolvable for ~3h. To
                // recover, republish FREQUENTLY (every WARMUP_REPUBLISH_PERIOD)
                // until the routing table is healthy (≥ WARMUP_HEALTHY_CONTACTS)
                // or a bound is hit, so a republish lands once `find_closest` is
                // accurate. Bounded so a genuinely tiny private network doesn't
                // republish forever.
                #[cfg(any(test, feature = "test-low-difficulty"))]
                const WARMUP_REPUBLISH_PERIOD: std::time::Duration =
                    std::time::Duration::from_secs(2);
                #[cfg(not(any(test, feature = "test-low-difficulty")))]
                const WARMUP_REPUBLISH_PERIOD: std::time::Duration =
                    std::time::Duration::from_secs(90);
                const WARMUP_HEALTHY_CONTACTS: usize = 16;
                const MAX_WARMUP_REPUBLISHES: u32 = 12;
                let mut warmup_republishes_left = MAX_WARMUP_REPUBLISHES;

                // Fast on-change poll ticks at 60 s regardless of the
                // main republish cadence.
                let mut on_change_tick = tokio::time::interval(SOVEREIGN_ON_CHANGE_POLL_INTERVAL);
                // Skip the immediate first tick — nothing could have
                // changed in the 0 s since startup.
                on_change_tick.tick().await;
                on_change_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

                // `sov` is mutable: on-change reload replaces it in
                // place when the document file's mtime advances.
                let mut sov = sov;
                let doc_path = veil_dir.join(veil_identity::sovereign::IDENTITY_DOCUMENT_FILE);
                let mut last_seen_mtime: Option<std::time::SystemTime> =
                    std::fs::metadata(&doc_path)
                        .ok()
                        .and_then(|m| m.modified().ok());

                // Built once before the loop so we don't reallocate it on every
                // tick — from the DOCUMENT, exactly as the startup publish
                // builds it.
                //
                // It used to be a set of one (this device) under a constant
                // `reg_version = 1`, which is the shape the startup path was
                // fixed away from and this one was not. Left alone it undid that
                // fix on a schedule: every device publishes under the same
                // node_id, so each republish tick overwrote the registry naming
                // both devices with one naming only the publisher, and the equal
                // version gave the network no way to prefer the fuller record.
                // A second device linked successfully and then dropped off the
                // map within a tick.
                let mut registry = super::identity_publish::full_registry(&sov);

                // debounce window for topology-driven republish.
                // Without it, every PEX walk / route announce / handshake
                // ack would fire `route_updated.notified` and trigger
                // a re-fan of K-closest STORE messages. At 60 s minimum
                // between topology-driven republishes we get O(1)
                // republishes per minute even on heavy churn — bandwidth
                // cap is K × value_size × 1/min ≈ 100-500 B/min for a
                // single identity record. Production-safe on cellular.
                #[cfg(any(test, feature = "test-low-difficulty"))]
                const TOPOLOGY_REPUBLISH_DEBOUNCE: std::time::Duration =
                    std::time::Duration::from_secs(2);
                #[cfg(not(any(test, feature = "test-low-difficulty")))]
                const TOPOLOGY_REPUBLISH_DEBOUNCE: std::time::Duration =
                    std::time::Duration::from_secs(60);
                let mut last_topology_publish_at = tokio::time::Instant::now();

                loop {
                    tokio::select! {
                        Ok(_) = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() { break; }
                        }
                        // The ML-KEM mailbox key just rotated. Every branch that
                        // republishes the `MlKemCert` lives in the interval arm
                        // below, so rather than duplicate it, pull that arm
                        // forward — the next loop turn takes it immediately and
                        // re-signs the cert around whatever `mlkem_keys` now
                        // holds. Until it does, the node is advertising an EK it
                        // has already replaced.
                        _ = mlkem_republish_now.notified() => {
                            interval.reset_immediately();
                        }
                        // topology-driven republish. When a new
                        // peer joins / leaves, the K-closest set for our
                        // identity dht_key may have shifted — re-fan the
                        // identity document to the current K-closest so the
                        // freshly-joined peer picks up a replica without
                        // waiting for the next 6 h tick.
                        _ = route_updated.notified() => {
                            let now = tokio::time::Instant::now();
                            if now.duration_since(last_topology_publish_at)
                                < TOPOLOGY_REPUBLISH_DEBOUNCE
                            {
                                continue;
                            }
                            last_topology_publish_at = now;
                            if let Err(e) = veil_identity::publish::publish_identity_document(
                                &sov.document, &publisher,
                            ).await {
                                logger.debug(
                                    "node.sovereign_identity.topology_republish_failed",
                                    format!("node_id={} — topology-driven publish failed: {e}",
                                        veil_util::bytes_to_hex(sov.node_id())),
                                );
                            } else {
                                logger.debug(
                                    "node.sovereign_identity.topology_republished",
                                    format!("node_id={} — re-fanned IdentityDocument to K-closest after route_updated",
                                        veil_util::bytes_to_hex(sov.node_id())),
                                );
                            }
                        }
                        _ = on_change_tick.tick() => {
                            if let Some(m) = &drop_metrics {
                                let snap = m.snapshot();
                                logger.info(
                                    "node.session.shed_totals",
                                    format!(
                                        "tx_queue={} outbox={}",
                                        snap.session_tx_drops_total,
                                        snap.session_outbox_drops_total,
                                    ),
                                );
                            }
                            // On-change republish (462.12): detect CLI-driven
                            // rotate / revoke by comparing the document
                            // file's mtime against the previous tick.
                            let current_mtime =
                                std::fs::metadata(&doc_path).ok().and_then(|m| m.modified().ok());
                            if current_mtime != last_seen_mtime && current_mtime.is_some() {
                                match veil_identity::sovereign::SovereignIdentity::load_from_dir(&veil_dir) {
                                    Ok(new_sov) => {
                                        // skip the K-closest STORE
                                        // re-fan when the on-disk document is
                                        // byte-identical to what we already
                                        // have in memory. mtime changes for
                                        // many reasons that don't change the
                                        // protocol bytes — `touch`, atomic
                                        // editor saves, `chmod`, OS-level
                                        // filesystem ops. Without this guard
                                        // every such no-op triggers a full
                                        // K-closest STORE fan-out (≈ K × doc
                                        // size = 8 × 1 KB = 8 KB outbound on
                                        // cellular), wasting bandwidth on a
                                        // device that can least afford it.
                                        // Equality includes the master sig +
                                        // every identity_key + valid_until
                                        // so any meaningful rotation/revoke
                                        // still goes through the publish path.
                                        if new_sov.document == sov.document {
                                            logger.debug(
                                                "node.sovereign_identity.on_change_no_op",
                                                format!(
                                                    "node_id={} mtime advanced but document bytes unchanged — skip republish",
                                                    veil_util::bytes_to_hex(new_sov.node_id()),
                                                ),
                                            );
                                            last_seen_mtime = current_mtime;
                                            continue;
                                        }
                                        logger.info(
                                            "node.sovereign_identity.reloaded_on_change",
                                            format!(
                                                "node_id={} new_valid_until={} prev_valid_until={}",
                                                veil_util::bytes_to_hex(new_sov.node_id()),
                                                new_sov.document.valid_until_unix,
                                                sov.document.valid_until_unix,
                                            ),
                                        );
                                        sov = std::sync::Arc::new(new_sov);
                                        // Everything else reads the cell, so a
                                        // re-read that stops at this task's own
                                        // handle changes what the DHT is told
                                        // and nothing about what this node does.
                                        sovereign_cell.set(std::sync::Arc::clone(&sov));
                                        // Rebuild registry with the fresh sovereign handle.
                                        registry =
                                            super::identity_publish::full_registry(&sov);
                                        // Immediate re-publish of document + registry.
                                        if let Err(e) = veil_identity::publish::publish_identity_document(
                                            &sov.document, &publisher,
                                        ).await {
                                            logger.warn(
                                                "node.sovereign_identity.on_change_publish_failed",
                                                format!("document republish after reload failed: {e}"),
                                            );
                                        }
                                        if let Err(e) = veil_identity::publish::publish_instance_registry(
                                            &registry, &publisher,
                                        ).await {
                                            logger.warn(
                                                "node.sovereign_identity.on_change_registry_failed",
                                                format!("registry republish after reload failed: {e}"),
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        logger.warn(
                                            "node.sovereign_identity.reload_on_change_failed",
                                            format!(
                                                "reload after mtime change failed: {e} — keeping previous identity in-memory"
                                            ),
                                        );
                                    }
                                }
                                last_seen_mtime = current_mtime;
                            }
                        }
                        _ = interval.tick() => {
                            // Document.
                            match veil_identity::publish::publish_identity_document(
                                &sov.document, &publisher,
                            ).await {
                                Ok(()) => logger.debug(
                                    "node.sovereign_identity.republished",
                                    format!(
                                        "node_id={} valid_until_unix={}",
                                        veil_util::bytes_to_hex(sov.node_id()),
                                        sov.document.valid_until_unix,
                                    ),
                                ),
                                Err(e) => logger.warn(
                                    "node.sovereign_identity.republish_failed",
                                    format!(
                                        "node_id={} — republish failed: {e}",
                                        veil_util::bytes_to_hex(sov.node_id()),
                                    ),
                                ),
                            }
                            // Registry.
                            match veil_identity::publish::publish_instance_registry(
                                &registry, &publisher,
                            ).await {
                                Ok(()) => logger.debug(
                                    "node.sovereign_identity.registry_republished",
                                    format!(
                                        "node_id={} reg_version={}",
                                        veil_util::bytes_to_hex(sov.node_id()),
                                        registry.reg_version,
                                    ),
                                ),
                                Err(e) => logger.warn(
                                    "node.sovereign_identity.registry_republish_failed",
                                    format!(
                                        "node_id={} — registry republish failed: {e}",
                                        veil_util::bytes_to_hex(sov.node_id()),
                                    ),
                                ),
                            }
                            // MlKemCert — rebuild with fresh validity
                            // window on each tick so the cert's
                            // `valid_until` rolls forward (30 days from
                            // now). Same `cert_version = 1` for MVP.
                            let cert_valid_from = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            match sov.sign_mlkem_cert(
                                mlkem_keys.current_ek().to_vec(),
                                mlkem_keys.current_ratchet_pk(),
                                cert_valid_from,
                                cert_valid_from + 30 * 86_400,
                                1,
                            ) {
                                Ok(cert) => {
                                    if let Err(e) =
                                        veil_identity::publish::publish_mlkem_cert(
                                            &cert, &publisher,
                                        ).await
                                    {
                                        logger.warn(
                                            "node.sovereign_identity.mlkem_cert_republish_failed",
                                            format!(
                                                "node_id={} — ML-KEM cert republish failed: {e}",
                                                veil_util::bytes_to_hex(sov.node_id()),
                                            ),
                                        );
                                    } else {
                                        logger.debug(
                                            "node.sovereign_identity.mlkem_cert_republished",
                                            format!(
                                                "node_id={} cert_version={}",
                                                veil_util::bytes_to_hex(sov.node_id()),
                                                cert.cert_version,
                                            ),
                                        );
                                    }
                                }
                                Err(e) => logger.warn(
                                    "node.sovereign_identity.mlkem_cert_sign_failed",
                                    format!(
                                        "node_id={} — ML-KEM cert sign failed: {e}",
                                        veil_util::bytes_to_hex(sov.node_id()),
                                    ),
                                ),
                            }

                            // RelayKeyRecord — only relay-capable nodes have an
                            // anonymity X25519 key to advertise. Rebuilt each
                            // tick with a fresh 30-day validity window so a
                            // resolver always sees an unexpired record; keyed by
                            // node_id, so the put replaces the prior slot.
                            if let Some(relay_pk) = relay_x25519_pk {
                                match sov.sign_relay_key(
                                    relay_pk.to_vec(),
                                    cert_valid_from,
                                    cert_valid_from + 30 * 86_400,
                                    1,
                                ) {
                                    Ok(record) => {
                                        if let Err(e) =
                                            veil_identity::publish::publish_relay_key(
                                                &record, &publisher,
                                            ).await
                                        {
                                            logger.warn(
                                                "node.sovereign_identity.relay_key_republish_failed",
                                                format!(
                                                    "node_id={} — relay-key republish failed: {e}",
                                                    veil_util::bytes_to_hex(sov.node_id()),
                                                ),
                                            );
                                        } else {
                                            logger.debug(
                                                "node.sovereign_identity.relay_key_republished",
                                                format!(
                                                    "node_id={} relay_x25519 advertised",
                                                    veil_util::bytes_to_hex(sov.node_id()),
                                                ),
                                            );
                                        }
                                    }
                                    Err(e) => logger.warn(
                                        "node.sovereign_identity.relay_key_sign_failed",
                                        format!(
                                            "node_id={} — relay-key sign failed: {e}",
                                            veil_util::bytes_to_hex(sov.node_id()),
                                        ),
                                    ),
                                }
                            }

                            // Persisted NameClaims — re-scan every tick
                            // so newly-claimed names published via CLI
                            // mid-session also get republished.
                            match veil_identity::sovereign::load_persisted_name_claims(
                                &veil_dir,
                            ) {
                                Ok(claims) => {
                                    for claim in &claims {
                                        if let Err(e) =
                                            veil_identity::publish::publish_name_claim(
                                                claim, &publisher,
                                            ).await
                                        {
                                            logger.warn(
                                                "node.sovereign_identity.name_claim_republish_failed",
                                                format!(
                                                    "node_id={} name=\"{}\" — {e}",
                                                    veil_util::bytes_to_hex(sov.node_id()),
                                                    claim.name,
                                                ),
                                            );
                                        } else {
                                            logger.debug(
                                                "node.sovereign_identity.name_claim_republished",
                                                format!(
                                                    "node_id={} name=\"{}\"",
                                                    veil_util::bytes_to_hex(sov.node_id()),
                                                    claim.name,
                                                ),
                                            );
                                        }
                                    }
                                }
                                Err(e) => logger.warn(
                                    "node.sovereign_identity.name_claims_scan_failed",
                                    format!(
                                        "node_id={} — name_claims scan failed: {e}",
                                        veil_util::bytes_to_hex(sov.node_id()),
                                    ),
                                ),
                            }
                            // recompute the adaptive interval
                            // for the NEXT tick based on current routing-
                            // table density. A node that's grown its
                            // routing table since the last tick (just
                            // joined a busy LAN, finished initial PEX
                            // walk) gets a longer next-cadence; a node
                            // that lost contacts (cell handover, gateway
                            // churn) gets a shorter one. Recreate the
                            // interval so subsequent `interval.tick`
                            // uses the new period.
                            let contacts = dht_for_density.routing_table_contacts().len();
                            // Stay in the frequent warmup cadence while the
                            // routing table is still sparse (and the bound isn't
                            // exhausted); otherwise use the adaptive steady-state.
                            let next_period = if warmup_republishes_left > 0
                                && contacts < WARMUP_HEALTHY_CONTACTS
                            {
                                warmup_republishes_left -= 1;
                                WARMUP_REPUBLISH_PERIOD
                            } else {
                                adaptive_republish_interval(
                                    SOVEREIGN_REPUBLISH_INTERVAL,
                                    contacts,
                                    TARGET_ROUTING_TABLE_DENSITY,
                                )
                            };
                            next_republish_at = tokio::time::Instant::now() + next_period;
                            interval = tokio::time::interval_at(
                                next_republish_at,
                                next_period,
                            );
                            interval.set_missed_tick_behavior(
                                tokio::time::MissedTickBehavior::Delay,
                            );
                        }
                    }
                }
            },
        );
        lock_tasks(&self.tasks).sessions.push(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::adaptive_republish_interval;
    use std::time::Duration;

    const BASE: Duration = Duration::from_secs(6 * 3600); // 6 hours

    #[test]
    fn epic487_5_at_target_density_returns_base_interval() {
        let result = adaptive_republish_interval(BASE, 100, 100);
        assert_eq!(
            result, BASE,
            "actual = target → multiplier 1.0 → base interval unchanged"
        );
    }

    #[test]
    fn epic487_5_dense_routing_table_lengthens_interval() {
        // Node has 4× the target density → multiplier 4.0 → 4× base.
        let result = adaptive_republish_interval(BASE, 400, 100);
        assert_eq!(
            result,
            Duration::from_secs(24 * 3600),
            "4× density → 24h interval (saves 75% bandwidth on dense node)"
        );
    }

    #[test]
    fn epic487_5_sparse_routing_table_shortens_interval() {
        // Node has 1/2 target density → multiplier 0.5 → half base.
        let result = adaptive_republish_interval(BASE, 50, 100);
        assert_eq!(
            result,
            Duration::from_secs(3 * 3600),
            "half density → 3h interval (more frequent, maintain visibility)"
        );
    }

    #[test]
    fn epic487_5_extreme_dense_clamped_at_4x() {
        // 100× the target density would give 600h; clamp at 4× = 24h.
        let result = adaptive_republish_interval(BASE, 10_000, 100);
        assert_eq!(
            result,
            Duration::from_secs(24 * 3600),
            "extreme density must clamp at 4× base, never longer"
        );
    }

    #[test]
    fn epic487_5_extreme_sparse_clamped_at_half() {
        // Empty routing table would give 0; clamp at 0.5× = 3h.
        // (We pass 0 → max(1) → 1/100 = 0.01 → clamp 0.5).
        let result = adaptive_republish_interval(BASE, 0, 100);
        assert_eq!(
            result,
            Duration::from_secs(3 * 3600),
            "extreme sparse must clamp at 0.5× base, never shorter (avoids \
             republish-storm during catastrophic disconnect)"
        );
    }

    #[test]
    fn epic487_5_zero_target_density_returns_base() {
        // Operator misconfigured target_density = 0. Don't divide by 0;
        // fall back to base interval (no adaptation).
        let result = adaptive_republish_interval(BASE, 100, 0);
        assert_eq!(
            result, BASE,
            "target = 0 (misconfig) must fall back to base, not panic"
        );
    }

    #[test]
    fn epic487_5_monotonic_in_density_within_clamp_range() {
        // Sanity: between the clamp bounds, denser routing table → longer
        // interval. This is the load-bearing property of the adapter.
        let dense = adaptive_republish_interval(BASE, 200, 100); // 2.0×
        let medium = adaptive_republish_interval(BASE, 100, 100); // 1.0×
        let sparse = adaptive_republish_interval(BASE, 75, 100); // 0.75×
        assert!(dense > medium, "denser must be longer interval");
        assert!(medium > sparse, "sparser must be shorter interval");
    }

    /// Bandwidth-savings sanity at trillion scale. Even modest density
    /// (200 contacts vs 100 target) cuts republish bytes in half over
    /// any time window. At 10⁹ nodes × 1.5 KB STORE × 6h vs 12h:
    /// Without adapter: 10⁹ × 1.5 KB / 6h ≈ 70 KB/s aggregate
    /// With adapter (dense nodes at 12h): ≈ 35 KB/s aggregate
    /// 50 % reduction in DHT-storage traffic for the median node — and
    /// way more dramatic on sparsely-connected nodes that climb to 24h.
    #[test]
    fn epic487_5_dense_nodes_save_at_least_50_percent_bandwidth() {
        let dense = adaptive_republish_interval(BASE, 200, 100);
        // (12h vs 6h) → 0.5× the publish frequency → 0.5× bandwidth.
        let savings_factor = BASE.as_secs_f64() / dense.as_secs_f64();
        assert!(
            savings_factor <= 0.5 + 1e-9,
            "dense nodes (2× density) must publish ≤ 50% as often \
             as base; savings_factor = {savings_factor}"
        );
    }
}
