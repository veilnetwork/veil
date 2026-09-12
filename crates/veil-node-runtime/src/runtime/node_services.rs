//! Everything the app is allowed to ask the node, in one place.
//!
//! [`NodeServices`] is the facade the IPC layer and the in-process app hold:
//! send, resolve, register a meeting point, open and maintain an onion
//! circuit, withdraw a service. `NodeRuntime` owns the machinery; this is the
//! surface across which somebody else asks for it.
//!
//! It lived in `runtime/mod.rs` as two `impl` blocks totalling six thousand
//! lines, four thousand of them below a test module — which is to say that the
//! single most consequential question about this crate, "what can a caller
//! actually do", was answered in the last place anybody would look. Moving it
//! does not change the answer; it puts the answer where the question is asked
//! (report24 RUNTIME-3).
//!
//! The split runs along the type, not along a line count: `mod.rs` keeps
//! `NodeRuntime` and the shapes both share, and this file holds every method
//! reachable from outside. Nothing else moved, and nothing changed but the
//! visibility of the few items `mod.rs` still owns and this file still calls.

use std::sync::Arc;

use super::*;

impl NodeServices {
    /// Does this node still hold a peer row for `node_id`?
    ///
    /// An outbound connector task retries for the life of the process, so
    /// until this existed there was no way to stop one: dropping the peer row
    /// left the task dialling an address nothing wanted any more. That is what
    /// made the exchanged-peer table unboundable — a cap can only evict if
    /// eviction actually retires the work the row was paying for.
    pub(crate) fn holds_peer_row(&self, node_id: &[u8; 32]) -> bool {
        self.current_peer_slot(node_id).is_some()
    }

    /// WHICH row currently represents `node_id`, if any.
    ///
    /// A `PeerId` is a local slot, not an identity: a node rediscovered at a
    /// new address gets a NEW slot, and the old one is gone. An outbound
    /// connector captured its slot when it spawned and dialled that number for
    /// the life of the task, while the per-node-id claim stopped a second task
    /// from being spawned for the replacement — so a peer that came back under
    /// a new row was dialled by nobody until the process restarted (report16
    /// V16-M6). The connector asks this every pass instead.
    pub(crate) fn current_peer_slot(&self, node_id: &[u8; 32]) -> Option<veil_cfg::PeerId> {
        crate::runtime::persistence::existing_slot_for(&lock_state(&self.state).peers, node_id)
    }

    /// The WHOLE row that currently stands for `node_id`, not just its slot.
    ///
    /// A connector task is spawned with a snapshot of the row it was born
    /// with, and that row can be replaced while the task lives — a peer that
    /// comes back at a new address gets a new slot, and the per-node-id claim
    /// stops a second connector being spawned for it. Dialling already
    /// followed the replacement (report16 V16-M6); everything the task did
    /// AFTER a successful handshake still described the row it started with,
    /// so the trusted routing contact, the cold-start bootstrap cache and the
    /// rotation's primary URI were all written from an address and keys that
    /// are no longer the peer's (report17 V17-M4).
    pub(crate) fn current_peer_entry(
        &self,
        node_id: &[u8; 32],
    ) -> Option<crate::types::PeerConfigEntry> {
        crate::runtime::persistence::existing_entry_for(&lock_state(&self.state).peers, node_id)
            .cloned()
    }

    pub async fn dht_get_replicated(
        &self,
        key: [u8; 32],
        n_replicas: usize,
        timeout: std::time::Duration,
        // F1 (DHT cache-poisoning): a local cache value is an OPTIMIZATION, not a
        // trust boundary. The identity-family STORE path stores NM/ID/IR/MC
        // bytes after STRUCTURAL decode only (verification is deferred to read),
        // so a peer can park a structurally-valid but cryptographically-invalid
        // value under a target key. The single-replica local fast path then
        // short-circuits remote quorum and the resolver fails verification with
        // no fallback — a targeted resolve DoS (and, for names, a quorum bypass).
        // The fast path is now taken ONLY when `validate` accepts the local
        // bytes; otherwise we fall through to remote quorum (the resolver's
        // post-quorum `store_local` then repairs the poisoned shard). Pass
        // `|_| true` to preserve the old unconditional fast path.
        validate: impl Fn(&[u8]) -> bool,
    ) -> Vec<Vec<u8>> {
        self.dht_get_replicated_inner(key, n_replicas, timeout, validate, true)
            .await
    }

    /// Contested-record variant (nicknames): ownership is displaceable by
    /// cumulative PoW weight, so a VALID local copy is necessary but NOT
    /// sufficient — a stale lighter record still verifies, and letting it
    /// short-circuit the remote quorum would blind the holder to a heavier
    /// displacement forever (the owner-changed re-verify would never fire on
    /// exactly the nodes that mirrored the old owner). The validated local
    /// value joins the replica set instead of ending the fetch; the caller's
    /// displacement pick decides the winner.
    pub async fn dht_get_replicated_contested(
        &self,
        key: [u8; 32],
        n_replicas: usize,
        timeout: std::time::Duration,
        validate: impl Fn(&[u8]) -> bool,
    ) -> Vec<Vec<u8>> {
        self.dht_get_replicated_inner(key, n_replicas, timeout, validate, false)
            .await
    }

    async fn dht_get_replicated_inner(
        &self,
        key: [u8; 32],
        n_replicas: usize,
        timeout: std::time::Duration,
        validate: impl Fn(&[u8]) -> bool,
        local_fast_path: bool,
    ) -> Vec<Vec<u8>> {
        // Validated local value. A local value that fails `validate`
        // (poisoned / unverifiable) never short-circuits and never joins the
        // replica set — the resolver's post-quorum `store_local` repairs it.
        let mut local = self.dht.get_local(&key).filter(|value| validate(value));
        if local_fast_path && let Some(value) = local.take() {
            return vec![value];
        }
        let n = n_replicas.clamp(1, veil_proto::budget::DHT_REPLICATION_K);

        let mut peers: Vec<[u8; 32]> = rlock!(self.session_tx_registry).peer_ids();
        if peers.is_empty() {
            return local.into_iter().collect();
        }
        peers.sort_by_key(|pid| {
            let mut xor = [0u8; 32];
            for i in 0..32 {
                xor[i] = pid[i] ^ key[i];
            }
            xor
        });
        let targets: Vec<[u8; 32]> = peers.into_iter().take(n).collect();
        if targets.is_empty() {
            return local.into_iter().collect();
        }

        let local_node_id = *self.identity.local_identity.node_id.as_bytes();

        // Per-target: fresh query_id, oneshot, encoded frame. We
        // build them all up-front so the registration / send batch
        // is mostly lock-free at the call site.
        struct PerTarget {
            rx: tokio::sync::oneshot::Receiver<Vec<u8>>,
            frame: Vec<u8>,
            peer: [u8; 32],
        }
        let mut work: Vec<PerTarget> = Vec::with_capacity(targets.len());
        for peer in &targets {
            let query_id: [u8; 16] = {
                use rand_core::RngCore;
                let mut id = [0u8; 16];
                rand_core::OsRng.fill_bytes(&mut id);
                id
            };
            let q = veil_proto::routing::RecursiveQueryPayload {
                query_id,
                target_key: key,
                reply_to: local_node_id,
                ttl: 40,
                query_type: veil_proto::routing::recursive_query_type::FIND_VALUE,
                reply_port: 0,
                payload: vec![],
            };
            let q_bytes = q.encode();
            let mut hdr = veil_proto::header::FrameHeader::new(
                veil_proto::family::FrameFamily::Routing as u8,
                veil_proto::family::RoutingMsg::RecursiveQuery as u16,
            );
            hdr.body_len = q_bytes.len() as u32;
            let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
            frame.extend_from_slice(&q_bytes);

            // oncurrency-register the pending
            // entry FIRST, then push to `work`. The previous order
            // pushed `(tx, rx, frame)` into `work`, then on cap-hit
            // BROKE without registering the tx — leaving the rx
            // waiting for a response that the dispatcher could never
            // route back (no matching entry in `pending_recursive`).
            // Originator silently timed out instead of failing fast.
            // Now: if cap is hit before registering, drop the just-
            // created tx/rx pair and break without polluting `work`.
            use veil_proto::budget::MAX_PENDING_RECURSIVE;
            let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
            {
                let mut m = lock!(self.dispatcher.pending_recursive);
                m.retain(|_, p| !p.tx.is_closed());
                if m.len() >= MAX_PENDING_RECURSIVE {
                    // Out of pending slots — drop tx/rx, do not push
                    // to `work`, work with whatever was registered
                    // before this iteration.
                    break;
                }
                m.insert(
                    query_id,
                    veil_dispatcher::PendingRecursive {
                        target_key: key,
                        query_type: veil_proto::routing::recursive_query_type::FIND_VALUE,
                        tx,
                    },
                );
            }
            work.push(PerTarget {
                rx,
                frame,
                peer: *peer,
            });
        }

        // Fan-out: send each peer their own query_id'd frame.
        {
            let guard = rlock!(self.session_tx_registry);
            for w in &work {
                guard.send_to(
                    &w.peer,
                    veil_proto::header::priority::INTERACTIVE,
                    w.frame.clone(),
                );
            }
        }

        // Collect: race every oneshot against the shared deadline.
        // Use `tokio::select!` over a `FuturesUnordered` so peers that
        // respond fast contribute to the tally even if a sybil sits
        // at the top of the closest list and never replies.
        let deadline = tokio::time::Instant::now() + timeout;
        let mut futs: futures::stream::FuturesUnordered<_> = work
            .into_iter()
            .map(|w| async move { tokio::time::timeout_at(deadline, w.rx).await })
            .collect();

        let mut out: Vec<Vec<u8>> = Vec::new();
        use futures::StreamExt;
        while let Some(res) = futs.next().await {
            if let Ok(Ok(payload)) = res
                && !payload.is_empty()
            {
                out.push(payload);
            }
        }
        // Contested mode: the validated local copy is one replica among the
        // remote ones, never the whole answer.
        if let Some(value) = local {
            out.push(value);
        }
        out
    }

    // ── audit cycle-6 (T7): admin network ops relocated here from
    // `impl NodeRuntime` so the admin handlers can run them on an
    // Arc-cloned `access()` bundle WITHOUT holding the NodeRuntime mutex
    // across the multi-second network await (DHT walk / identity+name
    // resolution). `self.{dht,dispatcher,identity,session_tx_registry}`
    // resolve identically on NodeServices. ──────────────────────────────
    pub async fn dht_recursive_get(
        &self,
        key: [u8; 32],
        timeout: std::time::Duration,
    ) -> Option<Vec<u8>> {
        // Local fast path.
        if let Some(value) = self.dht.get_local(&key) {
            return Some(value);
        }

        // Pick K closest active session peers; bail if we have no
        // peers to forward (can't do a recursive walk solo).
        let mut peers: Vec<[u8; 32]> = rlock!(self.session_tx_registry).peer_ids();
        if peers.is_empty() {
            return None;
        }
        peers.sort_by_key(|pid| {
            let mut xor = [0u8; 32];
            for i in 0..32 {
                xor[i] = pid[i] ^ key[i];
            }
            xor
        });

        // Build the RecursiveQuery frame with a fresh 16-byte query_id.
        let local_node_id = *self.identity.local_identity.node_id.as_bytes();
        let query_id: [u8; 16] = {
            use rand_core::RngCore;
            let mut id = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut id);
            id
        };
        let q = veil_proto::routing::RecursiveQueryPayload {
            query_id,
            target_key: key,
            reply_to: local_node_id,
            ttl: 40,
            query_type: veil_proto::routing::recursive_query_type::FIND_VALUE,
            reply_port: 0,
            payload: vec![],
        };
        let q_bytes = q.encode();
        let mut hdr = veil_proto::header::FrameHeader::new(
            veil_proto::family::FrameFamily::Routing as u8,
            veil_proto::family::RoutingMsg::RecursiveQuery as u16,
        );
        hdr.body_len = q_bytes.len() as u32;
        let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
        frame.extend_from_slice(&q_bytes);

        // Register a oneshot so the dispatcher's response handler can
        // wake us when the matching RecursiveResponse arrives.
        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        {
            use veil_proto::budget::MAX_PENDING_RECURSIVE;
            let mut m = lock!(self.dispatcher.pending_recursive);
            m.retain(|_, p| !p.tx.is_closed());
            if m.len() >= MAX_PENDING_RECURSIVE {
                return None;
            }
            m.insert(
                query_id,
                veil_dispatcher::PendingRecursive {
                    target_key: key,
                    query_type: veil_proto::routing::recursive_query_type::FIND_VALUE,
                    tx,
                },
            );
        }

        // Forward to top-2 closest peers.
        {
            let guard = rlock!(self.session_tx_registry);
            for pid in peers.iter().take(2) {
                guard.send_to(
                    pid,
                    veil_proto::header::priority::INTERACTIVE,
                    frame.clone(),
                );
            }
        }

        // Await the response or timeout.
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(payload)) if !payload.is_empty() => Some(payload),
            _ => None,
        }
    }

    /// Actively FETCH + locally cache the relay-directory (RD) entries of a set
    /// of KNOWN relay node_ids, regardless of whether we hold a live session to
    /// each. Sibling of [`service_tasks::warm_connected_relay_directory`], which
    /// only warms the SESSION-connected set.
    ///
    /// Why this exists (reverse-leg fix): the reply / introduce circuit builders
    /// (`select_onion_relay_path_to`, `send_sealed_introduce`) require several
    /// DISTINCT relays whose RD is fresh in the local store. A desktop holding a
    /// session to every seed warms all of them via `warm_connected_relay_directory`.
    /// A mobile node on cellular/Doze sustains ~one relay session, so the connected-
    /// only warm caches at most ONE RD — the multi-hop reply/introduce then fails
    /// `middles_insufficient` / `InsufficientRelayCandidates { have: 0 }` and the
    /// live-ACK is lost. `dht_recursive_get` walks the DHT over WHATEVER session
    /// exists, so the single live relay is enough to pull the other seeds' RDs.
    ///
    /// Bounded fan-out (`max_fetch`) + freshness-skip: an entry already fresh
    /// locally costs zero RPC, so in steady state this is a no-op. Only the same
    /// signature-bound, node-id-bound entries the connected warm accepts are cached.
    ///
    /// Uses `find_value_iterative_network` (the client-driven iterative Kademlia
    /// lookup the proven `warm_connected_relay_directory` uses), NOT
    /// `dht_recursive_get` (server-side recursion) — on the sparse pinned-seed
    /// network the iterative walk is the one that reliably resolves relay-directory
    /// keys.
    pub(crate) async fn warm_known_relay_directory(
        &self,
        relays: &[[u8; 32]],
        max_fetch: usize,
        _timeout: std::time::Duration,
    ) -> usize {
        use veil_anonymity::directory::{
            DEFAULT_FRESHNESS_WINDOW_SECS, decode_entry, discover_relay_hops,
            relay_directory_dht_key, verify_entry,
        };
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let outbox: Arc<dyn veil_dht::FrameRouter> =
            Arc::clone(&self.session_outbox) as Arc<dyn veil_dht::FrameRouter>;
        // Peers we hold a live session with: for these we can ask the relay
        // DIRECTLY for its own RD entry (one deterministic hop) instead of the
        // XOR-converging iterative walk, which on the sparse pinned-seed net
        // never queries the far-from-key holder → have:0 under live sessions.
        let session_peers: std::collections::HashSet<[u8; 32]> =
            outbox.peer_ids().into_iter().collect();
        let mut fetched = 0usize;
        let mut cached = 0usize;
        let mut direct_ok = 0usize;
        let mut walk_ok = 0usize;
        let mut failed = 0usize;
        for relay in relays {
            if fetched >= max_fetch {
                break;
            }
            // Skip when the local entry is present AND fresh by the SAME predicate
            // the circuit-building consumers apply — a stale-but-present entry is
            // filtered out downstream, so it must be re-fetched (not treated as a hit).
            let fresh = !discover_relay_hops(
                std::slice::from_ref(relay),
                |n| self.dht.get_local(&relay_directory_dht_key(n)),
                now_unix,
                DEFAULT_FRESHNESS_WINDOW_SECS,
            )
            .is_empty();
            if fresh {
                continue;
            }
            fetched += 1;
            let key = relay_directory_dht_key(relay);
            // DIRECT-FIRST for connected relays (deterministic single hop to the
            // node that store_local's its OWN entry), then fall back to the
            // iterative walk (routing-table-only relays, or a direct miss).
            let mut from_direct = false;
            let bytes = if session_peers.contains(relay) {
                match self
                    .dht
                    .find_value_from_peer(*relay, key, Arc::clone(&outbox))
                    .await
                {
                    Some(b) => {
                        from_direct = true;
                        Some(b)
                    }
                    None => {
                        self.dht
                            .find_value_iterative_network(key, Arc::clone(&outbox))
                            .await
                    }
                }
            } else {
                self.dht
                    .find_value_iterative_network(key, Arc::clone(&outbox))
                    .await
            };
            let Some(bytes) = bytes else {
                failed += 1;
                continue;
            };
            // SECURITY: attacker-supplied until checked — the RD key is well-known,
            // so only cache an entry that decodes, verifies its OWN signature, AND
            // is bound to THIS relay's node_id (else a peer could steer our relay
            // choice by serving another node's entry under this key). Same gate as
            // `warm_connected_relay_directory`.
            match decode_entry(&bytes) {
                Ok(entry) if entry.node_id == *relay && verify_entry(&entry).is_ok() => {
                    self.dht.store_local(key, bytes);
                    cached += 1;
                    if from_direct {
                        direct_ok += 1;
                    } else {
                        walk_ok += 1;
                    }
                }
                _ => failed += 1,
            }
        }
        if fetched > 0 {
            log::info!(
                "anonymity.relay_directory.warm_known fetched={fetched} cached={cached} direct={direct_ok} walk={walk_ok} failed={failed} session_peers={} relays={}",
                session_peers.len(),
                relays.len(),
            );
        }
        cached
    }

    pub async fn resolve_identity_verified(
        &self,
        node_id: [u8; 32],
        now_unix_secs: u64,
        timeout: std::time::Duration,
    ) -> std::result::Result<
        veil_identity::verify::ValidatedIdentity,
        veil_identity::resolver::ResolveError,
    > {
        use veil_identity::resolver::{MAX_MIGRATION_CHAIN_DEPTH, ResolveError};

        // walk any MigrationCert chain rooted at the
        // requested `node_id` until either a steady-state document is
        // reached or the depth/cycle bounds are hit. Each hop's cert
        // signature is verified against the CURRENT document's master
        // pubkey, so a sybil who only controls the DHT cannot forge a
        // migration — they'd need the old master's secret to mint a
        // cert binding their own pubkey.
        let mut current_node_id = node_id;
        let mut visited: Vec<[u8; 32]> = vec![current_node_id];

        for hop in 0..=MAX_MIGRATION_CHAIN_DEPTH {
            let (validated, _doc) = self
                .resolve_one_identity_doc(current_node_id, now_unix_secs, timeout)
                .await?;

            // Look for a migration cert published under this node_id.
            // No cert ⇒ steady state, return.
            let cert = match self
                .fetch_best_migration_cert_for(current_node_id, now_unix_secs, timeout)
                .await?
            {
                Some(c) => c,
                None => return Ok(validated),
            };

            if hop == MAX_MIGRATION_CHAIN_DEPTH {
                return Err(ResolveError::MigrationChainTooDeep {
                    max_depth: MAX_MIGRATION_CHAIN_DEPTH,
                });
            }

            let next = cert.new_node_id;
            if visited.iter().any(|n| n == &next) {
                return Err(ResolveError::MigrationChainCycle {
                    hop: hop + 1,
                    node_id: next,
                });
            }
            visited.push(next);
            current_node_id = next;
        }
        unreachable!("migration-chain loop must return inside the body");
    }

    pub(crate) async fn resolve_one_identity_doc(
        &self,
        node_id: [u8; 32],
        now_unix_secs: u64,
        timeout: std::time::Duration,
    ) -> std::result::Result<
        (
            veil_identity::verify::ValidatedIdentity,
            veil_proto::identity_document::IdentityDocument,
        ),
        veil_identity::resolver::ResolveError,
    > {
        use veil_identity::resolver::ResolveError;
        use veil_identity::verify::verify_identity_document;
        use veil_proto::identity_document::IdentityDocument;

        let key = IdentityDocument::dht_key(&node_id);

        // quorum policy preserved verbatim — N replicas
        // queried, ≥QUORUM matches required, anti-sybil at resolve.
        let replicas = self
            .dht_get_replicated(key, RESOLVE_MAX_REPLICAS, timeout, |bytes| {
                // Self-validating: a forged document cannot have
                // node_id == BLAKE3(its master), so a local doc that decodes for
                // `node_id` AND verifies is authoritative — trust the fast path.
                matches!(IdentityDocument::decode(bytes), Ok(d)
                    if d.node_id == node_id
                        && verify_identity_document(&d, now_unix_secs).is_ok())
            })
            .await;
        // Identity documents are self-certifying: each replica was already
        // filtered through `verify_identity_document` + `node_id == BLAKE3`
        // above, so a single verified replica is independently trustworthy →
        // allow_single_replica = true. (audit cycle-9.)
        let bytes =
            pick_quorum_match(&replicas, RESOLVE_QUORUM_THRESHOLD, true).ok_or_else(|| {
                if replicas.is_empty() {
                    ResolveError::IdentityNotFound(node_id)
                } else {
                    ResolveError::QuorumDivergence {
                        queried: replicas.len(),
                        best: replicas.iter().filter(|r| **r == replicas[0]).count(),
                        required: RESOLVE_QUORUM_THRESHOLD,
                    }
                }
            })?;
        // Cache-poison fix: overwrite the local DHT shard
        // with the quorum-winning bytes.
        self.dht.store_local(key, bytes.clone());
        let doc = IdentityDocument::decode(&bytes)
            .map_err(|e| ResolveError::IdentityDocMalformed(e.to_string()))?;
        if doc.node_id != node_id {
            return Err(ResolveError::IdentityDocMalformed(format!(
                "DHT returned IdentityDocument for {} but resolver \
                 asked for {}",
                veil_util::hex_short(&doc.node_id),
                veil_util::hex_short(&node_id),
            )));
        }
        let validated = verify_identity_document(&doc, now_unix_secs)
            .map_err(ResolveError::IdentityDocInvalid)?;
        Ok((validated, doc))
    }

    async fn fetch_best_migration_cert_for(
        &self,
        old_node_id: [u8; 32],
        now_unix_secs: u64,
        timeout: std::time::Duration,
    ) -> std::result::Result<
        Option<veil_identity::migration::MigrationCert>,
        veil_identity::resolver::ResolveError,
    > {
        use veil_identity::migration::{
            MigrationCert, decode_migration_cert, migration_cert_dht_key, pubkey_bytes_to_b64,
            verify_migration_cert,
        };
        use veil_identity::resolver::ResolveError;
        use veil_proto::identity_document::{
            ALGO_ED25519, ALGO_ED25519_FALCON512_HYBRID, ALGO_FALCON512, IdentityDocument,
        };

        // Tier-ranking helper duplicated locally (it lives privately in
        // both migration.rs and resolver.rs; keeping a 5-line copy beats
        // making the function pub).
        fn tier_rank(algo: u8) -> u8 {
            match algo {
                ALGO_ED25519 => 1,
                ALGO_FALCON512 => 2,
                ALGO_ED25519_FALCON512_HYBRID => 3,
                _ => 0,
            }
        }

        let cert_key = migration_cert_dht_key(&old_node_id);

        // Need the OLD master pubkey to verify cert signatures. The
        // previous hop's resolve_one_identity_doc just mirrored the
        // current document into the local store; pull it back for
        // free (no second quorum round-trip). Fetched BEFORE the replica
        // query so the fast-path validator (F1) can verify a local cert.
        let doc_key = IdentityDocument::dht_key(&old_node_id);
        let old_master_b64 = match self.dht.get_local(&doc_key) {
            Some(bytes) => match IdentityDocument::decode(&bytes) {
                Ok(doc) => pubkey_bytes_to_b64(&doc.master_pubkey),
                Err(_) => return Ok(None), // local cache corrupt; treat as no cert
            },
            None => return Ok(None), // no current doc → can't verify cert
        };

        let replicas = self
            .dht_get_replicated(cert_key, RESOLVE_MAX_REPLICAS, timeout, |bytes| {
                // Verify the local cert against the old master before trusting the
                // fast path (F1); a poisoned/unverifiable local cert falls through
                // to remote quorum instead of hiding a real published migration.
                matches!(decode_migration_cert(bytes), Ok(c)
                    if verify_migration_cert(&c, &old_master_b64, now_unix_secs).is_ok())
            })
            .await;
        if replicas.is_empty() {
            return Ok(None);
        }

        let mut best: Option<MigrationCert> = None;
        let mut first_decode_err: Option<String> = None;
        for blob in &replicas {
            let cert = match decode_migration_cert(blob) {
                Ok(c) => c,
                Err(e) => {
                    if first_decode_err.is_none() {
                        first_decode_err = Some(e.to_string());
                    }
                    continue;
                }
            };
            if verify_migration_cert(&cert, &old_master_b64, now_unix_secs).is_err() {
                continue;
            }
            best = match best {
                None => Some(cert),
                Some(prev) => {
                    let prev_tier = tier_rank(prev.new_master_algo);
                    let cur_tier = tier_rank(cert.new_master_algo);
                    if cur_tier > prev_tier
                        || (cur_tier == prev_tier && cert.issued_at_unix > prev.issued_at_unix)
                    {
                        Some(cert)
                    } else {
                        Some(prev)
                    }
                }
            };
        }

        if best.is_none()
            && let Some(msg) = first_decode_err
        {
            return Err(ResolveError::MigrationCertMalformed(msg));
        }
        // All replicas signed but none verified — treat as "no
        // migration published" (defence against a sybil spamming
        // junk under the cert key to stall name resolution).
        Ok(best)
    }

    pub async fn resolve_name_verified(
        &self,
        name: &str,
        now_unix_secs: u64,
        timeout: std::time::Duration,
    ) -> std::result::Result<
        veil_identity::verify::ValidatedIdentity,
        veil_identity::resolver::ResolveError,
    > {
        use veil_identity::resolver::{
            IdentityLookup, LookupError, NameLookup, NameResolver, ResolveError,
        };
        use veil_proto::name_claim_v2::{NameClaim, normalize_name};

        // Allow callers to pass either `"alice"` or `"@alice"` — the
        // user-facing handle convention (`@alice`) and the wire-level
        // claim name (`alice`) are the same string with the leading
        // sigil stripped. `normalize_name` does NOT strip it because
        // the `@` is invalid in a wire claim — handle it at the
        // resolver boundary so production callers don't need to know.
        let stripped = name.trim().strip_prefix('@').unwrap_or(name.trim());
        let normalized =
            normalize_name(stripped).map_err(|e| ResolveError::InvalidName(e.to_string()))?;
        let claim_key = NameClaim::dht_key(&normalized);
        // A NameClaim binds a name to the SOVEREIGN node_id of the signer
        // (`sign_name_claim` lives on `SovereignIdentity`), NOT the handshake /
        // PoW `local_identity`. A legacy (node_id-keyed) node has no sovereign
        // identity and never publishes a name, so it always falls through to
        // remote quorum.
        let our_sovereign_id = self.identity.sovereign_identity.get().map(|s| *s.node_id());
        // A name WE published is locally authoritative and needs NO remote
        // corroboration: quorum exists to stop a sybil forging a claim for
        // SOMEONE ELSE's name, but a NameClaim can only bind a name to the
        // sovereign node_id whose key signed it (re-verified by
        // `verify_name_claim` below), so a self-published claim (node_id ==
        // our sovereign id) is self-evidently ours. Resolve it straight from
        // the local store so an isolated / offline / sparse-network node can
        // always resolve its own @name.
        //
        // (cycle-10: the cycle-9 anti-sybil quorum gate over-corrected — the
        // `dht_get_replicated` local fast path returned the self-published value
        // as a single-element set, which then flowed into the ≥2 quorum check
        // below and was rejected as a "single remote response". The cycle-9
        // local-fast-path validator ALSO compared against `local_identity`, the
        // wrong identity for a sovereign-signed claim, so the fast path never
        // even fired for sovereign nodes. The fix distinguishes replica ORIGIN —
        // local-self vs remote — and compares against the SOVEREIGN id. A
        // poisoned local entry forging `@bob → our_sovereign_id` would resolve
        // to OUR identity, not the attacker's, and `verify_name_claim` below
        // rejects it unless the claim is signed by our key — which only we hold.)
        let self_published = our_sovereign_id.and_then(|our_id| {
            self.dht.get_local(&claim_key).filter(|bytes| {
                matches!(NameClaim::decode(bytes), Ok(c)
                    if c.name == normalized && c.node_id == our_id)
            })
        });
        let claim_bytes = if let Some(bytes) = self_published {
            bytes
        } else {
            // Remote name: NameClaim is NON-self-certifying (a self-consistent
            // forged claim @name -> attacker, signed by attacker, passes any
            // crypto self-check), so remote quorum is the only defense and a
            // single remote response must NOT be accepted → allow_single_replica
            // = false. (audit cycle-9 — closes the single-remote-responder name
            // hijack.) The local fast path inside `dht_get_replicated` is gated to
            // our sovereign id, which is false (or absent) for a remote name, so
            // it correctly falls through to the remote fan-out.
            let claim_replicas = self
                .dht_get_replicated(claim_key, RESOLVE_MAX_REPLICAS, timeout, |bytes| {
                    matches!((our_sovereign_id, NameClaim::decode(bytes)),
                        (Some(our_id), Ok(c))
                            if c.name == normalized && c.node_id == our_id)
                })
                .await;
            pick_quorum_match(&claim_replicas, RESOLVE_QUORUM_THRESHOLD, false).ok_or_else(
                || {
                    if claim_replicas.is_empty() {
                        ResolveError::NameNotFound
                    } else {
                        ResolveError::QuorumDivergence {
                            queried: claim_replicas.len(),
                            best: claim_replicas
                                .iter()
                                .filter(|r| **r == claim_replicas[0])
                                .count(),
                            required: RESOLVE_QUORUM_THRESHOLD,
                        }
                    }
                },
            )?
        };
        // same cache-poisoning fix as identity resolve —
        // overwrite local with the quorum-winning bytes so a sybil's
        // first-arriving forgery doesn't linger in the local store.
        self.dht.store_local(claim_key, claim_bytes.clone());
        let claim = NameClaim::decode(&claim_bytes)
            .map_err(|e| ResolveError::NameClaimMalformed(e.to_string()))?;
        if claim.name != normalized {
            return Err(ResolveError::NameClaimMalformed(format!(
                "DHT returned claim for {} but resolver asked for {}",
                claim.name, normalized,
            )));
        }
        let validated = self
            .resolve_identity_verified(claim.node_id, now_unix_secs, timeout)
            .await?;

        // Reuse the crypto path in `NameResolver::verify_name_claim`
        // via a stub backend (the verify method is pure — no fetch
        // no cache write).
        struct StubBackend;
        #[async_trait::async_trait]
        impl NameLookup for StubBackend {
            async fn fetch_name_claim(
                &self,
                _: &[u8; 32],
            ) -> std::result::Result<Option<Vec<u8>>, LookupError> {
                Err(LookupError::new("stub backend"))
            }
        }
        #[async_trait::async_trait]
        impl IdentityLookup for StubBackend {
            async fn fetch_identity_document(
                &self,
                _: &[u8; 32],
            ) -> std::result::Result<Option<Vec<u8>>, LookupError> {
                Err(LookupError::new("stub backend"))
            }
        }
        let resolver = NameResolver::new(StubBackend);
        // Re-decode the document from its canonical bytes so
        // `verify_name_claim` has the same `IdentityDocument` shape
        // it expects (the validated wrapper exposes node_id but not
        // the full doc). Cheap on a single resolve.
        let doc_key = veil_proto::identity_document::IdentityDocument::dht_key(&validated.node_id);
        // The doc bytes were already quorum-validated by
        // `resolve_identity_verified` above — but `verify_name_claim`
        // needs the full `IdentityDocument` shape. Trust the local
        // store: when `resolve_identity_verified` succeeded, the
        // dispatcher mirrored the response into our local DHT shard
        // (see routing.rs FIND_VALUE response handler), so a local
        // get is enough and avoids a second quorum round-trip.
        let doc_bytes = self
            .dht
            .get_local(&doc_key)
            .ok_or(ResolveError::IdentityNotFound(validated.node_id))?;
        let doc = veil_proto::identity_document::IdentityDocument::decode(&doc_bytes)
            .map_err(|e| ResolveError::IdentityDocMalformed(e.to_string()))?;
        resolver.verify_name_claim(&claim, &doc, now_unix_secs)?;
        Ok(validated)
    }

    pub async fn connect_peer(&self, peer_id: PeerId) -> Result<AttachedDebugSession> {
        self.connect_peer_with_state(peer_id, SessionState::DebugAttached)
            .await
    }

    pub async fn connect_peer_active(&self, peer_id: PeerId) -> Result<AttachedDebugSession> {
        self.connect_peer_with_state(peer_id, SessionState::Active)
            .await
    }

    pub(crate) fn make_session_context(&self) -> SessionRuntimeContext {
        SessionRuntimeContext {
            identity: Arc::clone(&self.identity),
            state: Arc::clone(&self.state),
            live_sessions: Arc::clone(&self.live_sessions),
            session_close_generations: Arc::clone(&self.session_close_generations),
            event_bus: Arc::clone(&self.event_bus),
            next_link_id: Arc::clone(&self.next_link_id),
            logger: Arc::clone(&self.logger),
            metrics: self.metrics.clone(),
            dispatcher: Arc::clone(&self.dispatcher),
            session_registry: Arc::clone(&self.session_registry),
            session_tx_registry: Arc::clone(&self.session_tx_registry),
            session_outbox: Arc::clone(&self.session_outbox),
            anonymity: Arc::clone(&self.anonymity),
            sessions_per_ip: Arc::clone(&self.sessions_per_ip),
            scanner_shield: Arc::clone(&self.scanner_shield),
            defaults: Arc::clone(&self.defaults),
            // NodeServices carries its own rtt_table clone (not via the
            // RoutingState bundle, which lives on NodeRuntime only).
            rtt_table: Arc::clone(&self.rtt_table),
            config_path: self.config_path.clone(),
            mobile: Arc::clone(&self.mobile),
            resumption: Arc::clone(&self.resumption),
            handoff: Arc::clone(&self.handoff),
            allowed_peer_algos: self.allowed_peer_algos.clone(),
            network_gate: self.network_gate.as_ref().map(Arc::clone),
            verified_peer_certs: Arc::clone(&self.verified_peer_certs),
            outbound_connector_refresh: Arc::clone(&self.outbound_connector_refresh),
        }
    }

    pub(crate) fn spawn_punched_inbound(
        &self,
        connection: Box<dyn veil_transport::TransportConnection>,
    ) {
        let handle = spawn_inbound_session(
            InboundSessionContext {
                runtime: self.make_session_context(),
                // Synthetic source labels: punched QUIC does not originate
                // from a configured listener, and listener_handle=0 matches no
                // allowlist entry. Identity/P-Net gates still run normally.
                listen_id: ListenId::new(0),
                listener_handle: ListenerHandle::new(0),
            },
            connection,
        );
        push_session_handle(&self.tasks, handle);
    }

    async fn connect_peer_with_state(
        &self,
        peer_id: PeerId,
        session_state: SessionState,
    ) -> Result<AttachedDebugSession> {
        let peer = lock_state(&self.state)
            .peers
            .get(&peer_id)
            .cloned()
            .ok_or_else(|| NodeError::AdminProtocol(format!("unknown peer_id `{peer_id}`")))?;
        self.logger.info(
            "peer.connect.attempt",
            format!(
                "peer_id={} transport={}",
                peer_id,
                veil_util::redact_addr_for_log(&peer.transport),
            ),
        );
        let session_ctx = self.make_session_context();
        if let Some(metrics) = &session_ctx.metrics {
            metrics.inc_outbound_connect_attempts();
        }
        let uri = TransportUri::parse(&peer.transport)?;
        let peer_ctx = Arc::new(peer_transport_context(&self.transport_ctx, &peer)?);
        // E20: a connection recovered via NAT-traversal / SOCKS fallback is a
        // one-sided, no-glare recovery dial — the primary URI was unreachable
        // and the peer is not reciprocally dialing — so it must bypass
        // directional dedup or the larger-node_id side is stranded ~50% of the
        // time. The primary (direct-dial) path keeps normal dedup.
        let mut used_fallback = false;
        let connection = match self.registry.connect(&uri, Arc::clone(&peer_ctx)).await {
            Ok(connection) => connection,
            Err(primary_err) => {
                // NAT-traversal auto-trigger on
                // outbound-dial failure. Only fires for production
                // (`SessionState::Active`) outbound dials — admin
                // `connect_peer` (DebugAttached) is operator-driven
                // diagnostic, not a path that should silently fall back
                // through signaling. Also skipped if no peer is
                // currently connected (no coordinator candidate, so
                // signaling has nowhere to go) or if the primary URI
                // is a variant that `with_host_port` can't promote
                // (Unix/Socks/Ws — there's nothing meaningful to
                // substitute the peer's IP candidate into).
                let primary_err_str = primary_err.to_string();
                if matches!(session_state, SessionState::Active) {
                    if let Some(connection) = self
                        .nat_fallback_dial(&peer, &uri, Arc::clone(&peer_ctx))
                        .await
                    {
                        self.logger.info(
                            "peer.connect.nat_fallback_success",
                            format!("peer_id={peer_id} primary_err={primary_err_str}",),
                        );
                        if let Some(metrics) = &session_ctx.metrics {
                            metrics.inc_outbound_connect_attempts();
                        }
                        used_fallback = true;
                        connection
                    } else if let Some(connection) = self.socks_fallback_dial(&uri, peer_ctx).await
                    {
                        // Anti-censorship: operator-configured SOCKS
                        // fallback (typically local Tor) succeeded
                        // when both direct and NAT-traversal failed.
                        self.logger.info(
                            "peer.connect.socks_fallback_success",
                            format!("peer_id={peer_id} primary_err={primary_err_str}"),
                        );
                        if let Some(metrics) = &session_ctx.metrics {
                            metrics.inc_outbound_connect_attempts();
                        }
                        used_fallback = true;
                        connection
                    } else {
                        if let Some(metrics) = &session_ctx.metrics {
                            metrics.inc_outbound_connect_failures();
                        }
                        self.logger.warn(
                            "peer.connect.failure",
                            format!("peer_id={peer_id} error={primary_err_str}"),
                        );
                        return Err(NodeError::Transport(primary_err));
                    }
                } else {
                    if let Some(metrics) = &session_ctx.metrics {
                        metrics.inc_outbound_connect_failures();
                    }
                    self.logger.warn(
                        "peer.connect.failure",
                        format!("peer_id={peer_id} error={primary_err_str}"),
                    );
                    return Err(NodeError::Transport(primary_err));
                }
            }
        };
        self.logger
            .info("peer.connect.success", format!("peer_id={peer_id}"));
        // Outbound sessions never hit the handoff-bound path (that branch
        // is inbound-only), so `Ok(None)` here is a defensive impossibility.
        // An expectation only when the row HAS one.
        //
        // Every other way this node learns of a peer comes with a claimed
        // identity, and checking the handshake against it is what catches an
        // address takeover. A peer found on a public index comes with an
        // address and nothing else -- there is no claim to check, so demanding
        // one would mean either inventing a claim (which would then always
        // "mismatch") or never dialling at all.
        //
        // What is NOT weakened: the handshake still proves who answered, and
        // the caller writes its record from that proof. An adversary at the
        // announced address gets to be a peer of ours, exactly as one at a
        // seed address does -- and being an entry point is all either of them
        // becomes.
        let expected = if peer_handshake::outbound_expects_an_identity(&peer) {
            Some(ExpectedPeerIdentity {
                peer_id,
                public_key: peer.public_key,
                node_id: peer.node_id,
                nonce: peer.nonce,
                row_transport_at_dial: peer.transport,
            })
        } else {
            None
        };
        register_connection_session(
            session_ctx,
            SessionSource::Outbound(peer_id),
            expected,
            None,
            session_state,
            connection,
            used_fallback,
        )
        .await?
        .ok_or_else(|| {
            NodeError::AdminProtocol(
                "register_connection_session returned None on an outbound path — impossible".into(),
            )
        })
    }

    pub async fn accept_listen(&self, listen_id: ListenId) -> Result<AttachedDebugSession> {
        {
            let state = lock_state(&self.state);
            let listen = state.listens.get(&listen_id).ok_or_else(|| {
                NodeError::AdminProtocol(format!("unknown listen_id `{listen_id}`"))
            })?;
            if !listen.active {
                return Err(NodeError::AdminProtocol(format!(
                    "listen `{listen_id}` is not active"
                )));
            }
        }

        let (tx, rx) = oneshot::channel();
        lock_waiters(&self.pending_accepts)
            .entry(listen_id)
            .or_default()
            .push_back(tx);
        let (listener_handle, connection) = rx.await.map_err(|_| {
            NodeError::AdminProtocol(format!(
                "listen `{listen_id}` stopped before a debug session was attached"
            ))
        })?;
        // DebugAttached inbound — operator explicitly attached via admin;
        // a handoff-bound outcome on this path means the debug attach got
        // hijacked by a live session's warm standby, which is surprising
        // but not fatal. Surface it as an admin-protocol error so the
        // operator sees what happened.
        register_connection_session(
            self.make_session_context(),
            SessionSource::Inbound(listen_id),
            None,
            Some(listener_handle),
            SessionState::DebugAttached,
            connection,
            false,
        )
        .await?
        .ok_or_else(|| {
            NodeError::AdminProtocol(
                "inbound connection was bound to an existing session via hot-standby handoff; \
             no debug session produced"
                    .into(),
            )
        })
    }

    // ── Diagnostic helpers ─────────────────────────────────────────

    /// The local node's 32-byte ID.
    pub fn local_node_id(&self) -> [u8; 32] {
        *self.identity.local_identity.node_id.as_bytes()
    }

    /// Monotonic generation incremented whenever the session runner for `peer`
    /// exits. Long-lived circuit handles can sample this at open time and later
    /// detect that their first-hop relay session churned underneath them.
    pub fn session_close_generation(&self, peer: &[u8; 32]) -> u64 {
        lock!(self.session_close_generations)
            .get(peer)
            .copied()
            .unwrap_or(0)
    }

    /// Whether the session TX registry currently has a live sender for `peer`.
    /// Long-lived circuit handles use this as a cheap pre-flight guard: a route
    /// can become unusable before its close-generation observer has noticed the
    /// runner exit, and otherwise the next `CircuitData` enqueue fails as
    /// `NoRelays`.
    pub fn has_live_session(&self, peer: &[u8; 32]) -> bool {
        rlock!(self.session_tx_registry).has_session(peer)
    }

    /// Register a channel that will receive the next Pong/TraceHop for `seq`.
    ///
    /// Closed-receiver entries are evicted before inserting. If the map is
    /// still at `MAX_PENDING_DIAG` after eviction, the new entry is silently
    /// dropped to prevent unbounded growth from admin command abuse.
    pub fn register_diag_seq(
        &self,
        seq: u32,
        tx: tokio::sync::mpsc::Sender<veil_dispatcher::DiagEvent>,
    ) {
        use veil_proto::budget::MAX_PENDING_DIAG;
        let mut map = lock!(self.dispatcher.pending_diag);
        // Evict entries whose receiver has already been dropped.
        map.retain(
            |_, sender: &mut tokio::sync::mpsc::Sender<veil_dispatcher::DiagEvent>| {
                !sender.is_closed()
            },
        );
        if map.len() < MAX_PENDING_DIAG {
            map.insert(seq, tx);
        }
    }

    /// Remove the pending channel for `seq` (cleanup after timeout or receipt).
    pub fn remove_diag_seq(&self, seq: u32) {
        lock!(self.dispatcher.pending_diag).remove(&seq);
    }

    /// Send a pre-encoded Diag frame to a target node via session registry.
    pub fn send_diag_frame(&self, target_id: &[u8; 32], frame: Vec<u8>) {
        // Snapshot the route-cache fallback hop BEFORE taking the registry, to
        // preserve the canonical lock order (route_cache → session_tx_registry;
        // documented in veil-dispatcher lib.rs). The lookup returns an owned
        // value and the route_cache guard is dropped immediately, so the two
        // guards never coexist (the previous order held the registry across the
        // route_cache read — the inversion the workspace was audited to avoid).
        let fallback_hop = rlock!(self.dispatcher.route_cache).lookup(target_id);
        let reg = rlock!(self.session_tx_registry);
        if !reg.send_to(
            target_id,
            veil_proto::header::priority::INTERACTIVE,
            frame.clone(),
        ) {
            // No direct session — use the pre-computed route-cache hop.
            if let Some(hop) = fallback_hop {
                reg.send_to(&hop, veil_proto::header::priority::INTERACTIVE, frame);
            }
        }
    }
}

impl NodeServices {
    /// Derive the onion-stream circuit-registration key from this node's stable
    /// identity secret. The rendezvous registry is first-registration-wins for
    /// a cookie, so generating this key randomly in each stream hub made a hub
    /// recreation look like a cookie hijack and R rejected every new circuit
    /// until the old 600-second subscription expired.
    ///
    /// Use a domain-separated one-way derivation instead of the identity key
    /// itself: the relay sees only this registration public key, not the node's
    /// published handshake public key. A stable stream cookie requires an
    /// equally stable anti-squat key across runtime and process restarts.
    pub fn onion_stream_registration_keypair(&self) -> veil_crypto::GeneratedKeyPair {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let seed = blake3::derive_key(
            "veil/onion-stream-registration/ed25519/v1",
            self.identity.local_identity.private_key.as_bytes(),
        );
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        veil_crypto::GeneratedKeyPair {
            algo: veil_types::SignatureAlgorithm::Ed25519,
            public_key: STANDARD.encode(signing_key.verifying_key().to_bytes()),
            private_key: STANDARD.encode(signing_key.to_bytes()),
        }
    }

    /// This node's onion-stream rendezvous cookie — the value a peer must put in
    /// front of every `[cookie][bytes]` circuit cell for R to splice it down our
    /// pinned receive circuit.
    ///
    /// It is the cookie our registration key MAY claim, and nothing else: R
    /// recomputes it from `reg_pk` and refuses any other pairing (see
    /// [`veil_anonymity::circuit_register::cookie_for_reg_pk`]). A cookie derived
    /// from the node_id instead — the shape the plain mailbox rendezvous uses,
    /// where the registry is namespaced by the registrant's authenticated
    /// session peer and needs no such binding — is refused at every relay, which
    /// leaves the receive circuit unACKed and the whole live path dark.
    ///
    /// Consequently this value is NOT derivable by a peer from our node_id. A
    /// sender learns it from the stream ad we publish once a receive circuit is
    /// confirmed (`publish_stream_rendezvous_ad`).
    pub fn onion_stream_local_cookie(&self) -> [u8; veil_anonymity::circuit_register::COOKIE_LEN] {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        let kp = self.onion_stream_registration_keypair();
        // The key above is minted here as a raw 32-byte Ed25519 verifying key, so
        // the decode cannot fail; fall back to an all-zero cookie rather than
        // panicking on the hot receive path if that ever stops holding (an
        // all-zero cookie fails the pairing check at R exactly like any other
        // mismatch — it degrades to "no live path", never to a wrong binding).
        STANDARD
            .decode(&kp.public_key)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .map(|pk| veil_anonymity::circuit_register::cookie_for_reg_pk(&pk))
            .unwrap_or([0u8; veil_anonymity::circuit_register::COOKIE_LEN])
    }

    /// The MAILBOX rendezvous cookie a node publishes in its plain ads.
    ///
    /// A receiver's plain (sovereign-signed) ad space holds two classes of ad:
    /// the mailbox ads the rendezvous-recipient task publishes under this
    /// node_id-derived cookie, and the onion-stream ads published under
    /// [`Self::onion_stream_local_cookie`]. A sender cannot compute the latter,
    /// so it identifies stream ads by ELIMINATION — every ad whose cookie is not
    /// this one. Exposed for that check.
    pub fn mailbox_rendezvous_cookie(
        node_id: &[u8; 32],
    ) -> [u8; veil_anonymity::circuit_register::COOKIE_LEN] {
        service_tasks::rendezvous_cookie_from_node_id(node_id)
    }

    /// Register a LOCATION-anonymous service (onion-registration b5b-runtime):
    /// build an onion circuit whose terminus is the rendezvous relay R
    /// (`relay_path.last()`), and register `cookie` AT R over that circuit —
    /// piggy-backed as the circuit-setup terminus payload — so R binds the cookie
    /// to the return circuit WITHOUT learning this node's location. Introduces a
    /// client sends to (R, cookie) are then forwarded back DOWN the circuit and
    /// opened here.
    ///
    /// `relay_path` is the full hop list first→terminus; each hop's X25519 key is
    /// resolved from the LOCAL relay-directory shard (publish/mirror it first).
    /// The caller separately publishes a `RendezvousAd` pointing at (R, cookie,
    /// our x25519) so clients can find the service — this method does NOT
    /// session-register (that is the leak it avoids).
    ///
    /// NOTE (§3.B): the ad does not yet COMMIT to the registration key, so the
    /// anti-squat guarantee is first-wins only; binding `reg_pk` into the ad is a
    /// follow-up. (Periodic rebuild-on-TTL maintenance IS now wired — see the
    /// `REFRESH_SECS` tick in the onion-service maintenance path, which rebuilds
    /// each due service on a fresh or proven-live path and re-publishes its
    /// descriptor.)
    pub(crate) fn build_onion_circuit_once(
        &self,
        relay_path: &[[u8; 32]],
        cookie: [u8; 16],
        reg_kp: &veil_crypto::GeneratedKeyPair,
        // B2: per-service strictly-monotonic registration epoch counter. See
        // `OnionServiceEntry::registration_epoch`. For one-shot circuits (reply
        // paths) pass a fresh counter — a unique (cookie, reg_pk) never collides
        // at R, so the epoch is just `unix_now`.
        last_epoch: &std::sync::atomic::AtomicU64,
        // True for an EPHEMERAL REPLY circuit: an introduce arriving back down
        // it proves OUR live introduce reached the peer (see
        // `OriginCircuit::is_reply` / the sender stall detector).
        is_reply: bool,
    ) -> std::result::Result<
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        veil_types::AnonOnionSendError,
    > {
        use base64::Engine;
        use veil_anonymity::circuit_origin::{OriginHop, build_origin_circuit};
        use veil_anonymity::circuit_register::CircuitRegisterPayload;
        use veil_anonymity::directory::{decode_entry, relay_directory_dht_key};
        use veil_types::AnonOnionSendError;

        if relay_path.is_empty() {
            return Err(AnonOnionSendError::NoRelays);
        }
        // Receive-capable only: we must own the origin table (to open returns).
        let Some(origin_table) = &self.dispatcher.circuit_origin else {
            return Err(AnonOnionSendError::NoIdentity);
        };

        // Resolve each hop's anonymity X25519 key from the local directory.
        let mut hops = Vec::with_capacity(relay_path.len());
        for nid in relay_path {
            let Some(bytes) = self.dht.get_local(&relay_directory_dht_key(nid)) else {
                log::warn!(
                    "build_onion_circuit_once NoRelays: hop {} RD missing in get_local",
                    veil_util::hex_short(nid),
                );
                return Err(AnonOnionSendError::NoRelays);
            };
            let entry = decode_entry(&bytes).map_err(|_| AnonOnionSendError::NoRelays)?;
            hops.push(OriginHop {
                node_id: *nid,
                pubkey: entry.x25519_pk,
            });
        }

        // STABLE Ed25519 registration key (diff-audit L1): the caller persists it
        // in the OnionServiceEntry and passes the SAME key on every rebuild, so R
        // sees a same-reg_pk refresh instead of CookieClaimed (first-wins
        // anti-squat against our own prior registration).
        let reg_pk: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&reg_kp.public_key)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(AnonOnionSendError::NoIdentity)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // diff-audit M2 + B2: bind the registration to a STRICTLY-monotonic
        // freshness epoch. R rejects a re-registration whose epoch is not
        // strictly greater than the recorded one (replay-hijack defense of the
        // cookie→circuit map). Wall-clock seconds alone collided when two
        // rebuilds landed in the same second (or the clock didn't advance),
        // dropping the rebuild as StaleEpoch and stranding the service on a
        // stale circuit. `next_monotonic_epoch` advances the per-service counter
        // to `max(now, prev + 1)` so the epoch is monotonic AND tracks wall-clock.
        let epoch = next_monotonic_epoch(last_epoch, now);
        let msg = CircuitRegisterPayload::signing_bytes(&cookie, &reg_pk, epoch);
        let sig = veil_crypto::sign_message(
            veil_types::SignatureAlgorithm::Ed25519,
            &reg_kp.public_key,
            &reg_kp.private_key,
            &msg,
        )
        .map_err(|_| AnonOnionSendError::NoIdentity)?;
        let reg = CircuitRegisterPayload {
            cookie,
            reg_pk,
            epoch,
            signature: sig,
        };

        // Build the origin circuit with the registration as terminus payload.
        let (setup, mut origin) = match build_origin_circuit(
            &hops,
            veil_anonymity::circuit_origin::choose_cell_bytes(),
            &reg.encode(),
            now,
        ) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("build_onion_circuit_once NoRelays: build_origin_circuit failed: {e:?}");
                return Err(AnonOnionSendError::NoRelays);
            }
        };
        origin.is_reply = is_reply;
        let first_hop = origin.first_hop;
        // Δ2-d: share the circuit's confirmation flag with the caller so the
        // maintenance tick can tell whether the terminus ACK'd this path (and
        // re-select a fresh path if it never did).
        let confirmed = std::sync::Arc::clone(&origin.confirmed);
        if !origin_table.insert(std::sync::Arc::new(origin)) {
            log::warn!(
                "build_onion_circuit_once NoRelays: origin_table FULL (cap {}, len {})",
                origin_table.cap(),
                origin_table.len(),
            );
            return Err(AnonOnionSendError::NoRelays); // origin table full
        }

        // Send the CircuitBuild envelope to the first hop over its session.
        if self
            .send_relay_chain_frame(
                &first_hop,
                veil_proto::family::RelayChainMsg::CircuitBuild,
                &setup,
            )
            .is_err()
        {
            log::debug!(
                "build_onion_circuit_once NoRelays: CircuitBuild send to first hop {} failed (no live session)",
                veil_util::hex_short(&first_hop),
            );
            return Err(AnonOnionSendError::NoRelays);
        }
        Ok(confirmed)
    }

    /// Open a pinned [`DataCircuit`] through `relay_path` (`relay_path[0]` first
    /// hop, `relay_path.last()` the terminus), carrying `terminus_payload` to the
    /// terminus (e.g. a signed registration so it can route returns back). The
    /// originating `OriginCircuit` is inserted into the dispatcher origin table so
    /// its RETURN cells dispatch here; the `CircuitBuild` envelope goes to the
    /// first hop. Returns a handle for [`Self::send_circuit_cell`]. ADDITIVE — the
    /// onion-stream CellDuplex (Phase 1d) will use it; no existing path changes.
    pub fn open_data_circuit(
        &self,
        relay_path: &[[u8; 32]],
        terminus_payload: &[u8],
    ) -> std::result::Result<
        (DataCircuit, tokio::sync::mpsc::Receiver<Vec<u8>>),
        veil_types::AnonOnionSendError,
    > {
        use veil_anonymity::circuit_origin::{OriginHop, build_origin_circuit};
        use veil_anonymity::directory::{decode_entry, relay_directory_dht_key};
        use veil_types::AnonOnionSendError;

        if relay_path.is_empty() {
            return Err(AnonOnionSendError::NoRelays);
        }
        // Receive-capable only: we must own the origin table to open returns.
        let Some(origin_table) = &self.dispatcher.circuit_origin else {
            return Err(AnonOnionSendError::NoIdentity);
        };
        // Resolve each hop's anonymity X25519 key from the local relay directory.
        let mut hops = Vec::with_capacity(relay_path.len());
        for nid in relay_path {
            let Some(bytes) = self.dht.get_local(&relay_directory_dht_key(nid)) else {
                log::warn!(
                    "open_data_circuit NoRelays: hop {} RD missing in get_local",
                    veil_util::hex_short(nid),
                );
                return Err(AnonOnionSendError::NoRelays);
            };
            let entry = decode_entry(&bytes).map_err(|_| AnonOnionSendError::NoRelays)?;
            hops.push(OriginHop {
                node_id: *nid,
                pubkey: entry.x25519_pk,
            });
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (setup, origin) = build_origin_circuit(
            &hops,
            veil_anonymity::circuit_origin::choose_cell_bytes(),
            terminus_payload,
            now,
        )
        .map_err(|_| AnonOnionSendError::NoRelays)?;
        // Snapshot what the handle needs BEFORE the origin moves into the table.
        let circ = DataCircuit {
            first_hop: origin.first_hop,
            relay_path: relay_path.to_vec(),
            origin_circuit_id: origin.origin_circuit_id,
            keys: origin.circuit_keys.clone(),
            next_seq: std::sync::atomic::AtomicU32::new(0),
            confirmed: std::sync::Arc::clone(&origin.confirmed),
            cell_bytes: origin.cell_bytes,
        };
        // Register the stream return-cell sink keyed by origin_circuit_id BEFORE
        // sending the build, so no early return cell is dropped once it comes up.
        // The dispatcher's CircuitData origin branch routes matching ids here.
        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        if let Ok(mut map) = self.dispatcher.stream_recv.lock() {
            map.insert(circ.origin_circuit_id, tx);
        }
        if !origin_table.insert(std::sync::Arc::new(origin)) {
            if let Ok(mut map) = self.dispatcher.stream_recv.lock() {
                map.remove(&circ.origin_circuit_id); // roll back on table-full
            }
            return Err(AnonOnionSendError::NoRelays);
        }
        if self
            .send_relay_chain_frame(
                &circ.first_hop,
                veil_proto::family::RelayChainMsg::CircuitBuild,
                &setup,
            )
            .is_err()
        {
            if let Ok(mut map) = self.dispatcher.stream_recv.lock() {
                map.remove(&circ.origin_circuit_id); // roll back on no live first-hop session
            }
            self.close_data_circuit(circ.origin_circuit_id);
            return Err(AnonOnionSendError::NoRelays);
        }
        Ok((circ, rx))
    }

    /// Remove a pinned circuit's stream return-cell sink (call on stream close).
    /// The `OriginCircuitTable` reaps the circuit itself by idle TTL.
    pub fn close_data_circuit(&self, origin_circuit_id: u32) {
        if let Ok(mut map) = self.dispatcher.stream_recv.lock() {
            map.remove(&origin_circuit_id);
        }
    }

    /// Open a pinned stream circuit to a rendezvous relay R (`relay_path.last()`)
    /// and REGISTER this node's stream cookie at R, so the R-splice
    /// (`splice_stream_cell`) can forward a peer's `[cookie][bytes]` cells down
    /// THIS circuit (Phase 1c++). `reg_kp` signs the registration; `last_epoch`
    /// is the per-cookie monotonic freshness counter. Returns the [`DataCircuit`]
    /// send handle + the inbound return-cell channel. A bidirectional stream uses
    /// one of these per endpoint; the CellDuplex sends `[peer_cookie][bytes]`
    /// forward cells and reads returns off the channel. Mirrors
    /// `build_onion_circuit_once`'s registration, but keeps the data-plane handle
    /// instead of just the ACK flag.
    ///
    /// The cookie is NOT a parameter: R refuses any pairing other than
    /// [`veil_anonymity::circuit_register::cookie_for_reg_pk`], so a caller that
    /// minted its cookie independently of `reg_kp` would build a circuit whose
    /// registration is silently refused — no ACK, no cookie→circuit binding, and
    /// therefore no live path at all. Deriving it here from the key makes that
    /// pairing unrepresentable. Callers that need the value use
    /// [`Self::onion_stream_local_cookie`], which derives it the same way.
    pub fn open_stream_circuit(
        &self,
        relay_path: &[[u8; 32]],
        reg_kp: &veil_crypto::GeneratedKeyPair,
        last_epoch: &std::sync::atomic::AtomicU64,
    ) -> std::result::Result<
        (DataCircuit, tokio::sync::mpsc::Receiver<Vec<u8>>),
        veil_types::AnonOnionSendError,
    > {
        use base64::Engine;
        use veil_anonymity::circuit_register::CircuitRegisterPayload;
        use veil_types::AnonOnionSendError;

        let reg_pk: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&reg_kp.public_key)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(AnonOnionSendError::NoIdentity)?;
        let cookie = veil_anonymity::circuit_register::cookie_for_reg_pk(&reg_pk);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let epoch = next_monotonic_epoch(last_epoch, now);
        let msg = CircuitRegisterPayload::signing_bytes(&cookie, &reg_pk, epoch);
        let sig = veil_crypto::sign_message(
            veil_types::SignatureAlgorithm::Ed25519,
            &reg_kp.public_key,
            &reg_kp.private_key,
            &msg,
        )
        .map_err(|_| AnonOnionSendError::NoIdentity)?;
        let reg = CircuitRegisterPayload {
            cookie,
            reg_pk,
            epoch,
            signature: sig,
        };
        self.open_data_circuit(relay_path, &reg.encode())
    }

    /// Relays advertised by this process's plain rendezvous publisher entries.
    ///
    /// The mobile/desktop app registers mailbox rendezvous publishers on several
    /// relays. The onion-stream receive side must register its stream cookie at
    /// those same relays; otherwise a sender that resolves any valid published ad
    /// other than our one chosen stream relay black-holes at R.
    pub fn local_published_rendezvous_relays(&self) -> Vec<[u8; 32]> {
        let mut relays: Vec<[u8; 32]> = lock!(self.anonymity.rendezvous_publisher_entries)
            .iter()
            // Ephemeral onion-service ads are separate blinded-descriptor
            // services; the plain identity ads are the peer-visible mailbox
            // rendezvous slots that stream senders resolve by node id.
            .filter(|e| e.ephemeral_ad_identity.is_none())
            .map(|e| e.rendezvous_node_id)
            .collect();
        relays.sort_unstable();
        relays.dedup();
        relays
    }

    /// Operator-pinned rendezvous relays configured for this receiver.
    ///
    /// Stream receivers use this as a cold-start source before the node-level
    /// rendezvous-recipient task has published its ordinary mailbox ad. The stream
    /// path still builds an onion circuit to the relay and publishes its own
    /// stream-cookie ad after confirmation.
    pub fn pinned_rendezvous_relays(&self) -> Vec<[u8; 32]> {
        self.anonymity.pinned_rendezvous_relays.clone()
    }

    /// Publish a plain rendezvous ad for a just-confirmed stream circuit.
    ///
    /// The stream backend uses a domain-separated `stream-cookie-v2`, distinct
    /// from the mailbox receiver cookie. Therefore it cannot rely on the
    /// node-level mailbox publisher entry: senders resolve the receiver's ad to
    /// learn `R` and the receiver X25519 key, then address circuit cells to the
    /// deterministic stream cookie.
    pub fn publish_stream_rendezvous_ad(&self, relay: [u8; 32], cookie: [u8; 16]) {
        if !service_tasks::rendezvous_register_publisher(
            &self.anonymity,
            &relay,
            cookie,
            service_tasks::RENDEZVOUS_AD_VALIDITY_SECS,
            None,
        ) {
            // Said out loud rather than swallowed: this receiver's stream ad
            // will not be published, and every sender resolving it finds
            // nothing (report17 V17-M6).
            self.logger.warn(
                "anonymity.rendezvous_ad.slots_full",
                "no publisher slot left for the stream rendezvous ad — it will \
                 not be published",
            );
        }
        let published = NodeRuntime::tick_publish_rendezvous_ads(
            &self.anonymity.rendezvous_publisher_entries,
            self.anonymity.x25519_sk.as_ref(),
            self.identity.local_identity.as_ref(),
            &self.identity.sovereign_identity,
            &self.dht,
            &self.logger,
            Some(&self.session_tx_registry),
        );
        if published > 0 {
            self.logger.info(
                "anonymity.stream_rendezvous_ad.published",
                format!(
                    "relay={} cookie={}",
                    veil_util::hex_short(&relay),
                    cookie
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                ),
            );
        }
    }

    /// Decrypt a small onion-stream peer-introduction payload sealed to this
    /// node's advertised rendezvous X25519 key. Used by the pinned stream
    /// circuit to hide the sender node id from the rendezvous relay while still
    /// letting the receiver demux stream cells by the real peer id.
    pub fn decrypt_stream_peer_intro(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let sk = self.dispatcher.anonymity_x25519_sk.as_ref()?;
        veil_anonymity::rendezvous::decrypt_introduce(ciphertext, sk.as_ref()).ok()
    }

    /// Resolve the receiver's currently valid published rendezvous ads in the
    /// same deterministic order every caller sees: newest ads first, then relay
    /// id. The full ad is needed by the pinned stream path so handshake cells can
    /// seal a peer-introduction payload to the receiver's X25519 key without
    /// exposing the sender node id to the rendezvous relay.
    pub async fn resolve_stream_rendezvous_ads(
        &self,
        receiver_node_id: [u8; 32],
    ) -> std::result::Result<
        Vec<veil_anonymity::rendezvous::RendezvousAd>,
        veil_types::AnonOnionSendError,
    > {
        use veil_types::AnonOnionSendError;

        const AD_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(3500);

        let ads = rendezvous_resolver::resolve_fresh_rendezvous_ads(
            &self.dht,
            &self.session_tx_registry,
            &self.dispatcher.pending_recursive,
            *self.identity.local_identity.node_id.as_bytes(),
            &self.anonymity.rendezvous_resolve_cache,
            &self.logger,
            receiver_node_id,
            AD_RESOLVE_TIMEOUT,
            false,
        )
        .await;

        if ads.is_empty() {
            return Err(AnonOnionSendError::NoRendezvous);
        }
        Ok(ads)
    }

    /// Resolve the receiver's currently valid published rendezvous relays in the
    /// same deterministic order every caller sees: newest ads first, then relay
    /// id. Returned relays are de-duplicated while preserving that order.
    pub async fn resolve_stream_rendezvous_relays(
        &self,
        receiver_node_id: [u8; 32],
    ) -> std::result::Result<Vec<[u8; 32]>, veil_types::AnonOnionSendError> {
        use veil_types::AnonOnionSendError;

        let ads = self.resolve_stream_rendezvous_ads(receiver_node_id).await?;

        let mut relays = Vec::new();
        for ad in ads {
            if !relays.contains(&ad.rendezvous_node_id) {
                relays.push(ad.rendezvous_node_id);
            }
        }
        if relays.is_empty() {
            return Err(AnonOnionSendError::NoRendezvous);
        }
        Ok(relays)
    }

    fn valid_stream_relay_directory_entry(relay: [u8; 32], bytes: &[u8]) -> bool {
        use veil_anonymity::directory::{decode_entry, verify_entry};

        matches!(
            decode_entry(bytes),
            Ok(entry) if entry.node_id == relay && verify_entry(&entry).is_ok()
        )
    }

    async fn cache_stream_relay_directory(&self, relay: [u8; 32]) -> bool {
        use veil_anonymity::directory::relay_directory_dht_key;

        const RELAY_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(3500);

        let relay_key = relay_directory_dht_key(&relay);
        if self
            .dht
            .get_local(&relay_key)
            .is_some_and(|bytes| Self::valid_stream_relay_directory_entry(relay, &bytes))
        {
            return true;
        }

        // A stream circuit to an exact rendezvous R needs R's relay-directory
        // entry (its onion X25519 key). In the sparse pinned/mobile topology, R
        // is often a directly-connected relay while the local DHT shard is still
        // cold. Ask that exact connected peer first; it answers authoritatively
        // from its own store_local, and the signature/node-id binding below keeps
        // a malicious peer from poisoning the cache.
        if let Some(bytes) = crate::mlkem_resolver::recursive_dht_get(
            &self.dht,
            &self.session_tx_registry,
            &self.dispatcher.pending_recursive,
            *self.identity.local_identity.node_id.as_bytes(),
            relay_key,
            RELAY_RESOLVE_TIMEOUT,
            Some(relay),
            move |bytes| Self::valid_stream_relay_directory_entry(relay, bytes),
        )
        .await
            && Self::valid_stream_relay_directory_entry(relay, &bytes)
        {
            self.dht.store_local(relay_key, bytes);
            return true;
        }

        false
    }

    async fn cache_stream_relay_directories_for_path(
        &self,
        rendezvous_node_id: [u8; 32],
        hop_count: usize,
    ) -> usize {
        const MAX_STREAM_RELAY_PREWARM: usize = 8;

        let mut relays = Vec::with_capacity(MAX_STREAM_RELAY_PREWARM);
        relays.push(rendezvous_node_id);

        for relay in &self.anonymity.pinned_rendezvous_relays {
            if !relays.contains(relay) {
                relays.push(*relay);
            }
        }
        for entry in lock!(self.anonymity.rendezvous_publisher_entries).iter() {
            if entry.ephemeral_ad_identity.is_none() && !relays.contains(&entry.rendezvous_node_id)
            {
                relays.push(entry.rendezvous_node_id);
            }
        }

        // Add a small bounded set of currently-connected peers that explicitly
        // advertised ANONYMITY_RELAY. For published-mode CIRCUIT_HOPS=2 we need
        // at least one middle relay distinct from R; relying on the periodic
        // maintenance prewarm leaves a cold embedded/mobile endpoint in NoRelays
        // until the next tick.
        let active_anon_relays = {
            let flags = self
                .dispatcher
                .crypto
                .peer_cap_flags
                .read()
                .unwrap_or_else(|p| p.into_inner());
            let sessions = lock!(self.live_sessions);
            sessions
                .values()
                .filter(|i| i.state == crate::types::SessionState::Active)
                .filter_map(|i| i.node_id.as_ref().map(|n| *n.as_bytes()))
                .filter(|node_id| {
                    flags
                        .get(node_id)
                        .copied()
                        .is_some_and(|f| f & veil_proto::session::cap_flags::ANONYMITY_RELAY != 0)
                })
                .collect::<Vec<_>>()
        };
        for relay in active_anon_relays {
            if relays.len() >= MAX_STREAM_RELAY_PREWARM.max(hop_count + 1) {
                break;
            }
            if !relays.contains(&relay) {
                relays.push(relay);
            }
        }

        let mut cached = 0usize;
        for relay in relays {
            if self.cache_stream_relay_directory(relay).await {
                cached += 1;
            }
        }

        // Mirror the MIDDLE-selector's candidate set so every relay
        // `select_onion_relay_path_to` might pick as a middle has its RD warmed
        // — not just R / pinned / cap-flag-advertised sessions. On a mobile
        // node the per-relay `cache_stream_relay_directory` above (server-side
        // `recursive_dht_get` with a direct-peer hint) is unreliable for a seed
        // that is a middle-candidate but not yet a settled session, so
        // `discover_relay_hops` kept finding < hop_count-1 fresh middles and
        // the whole onion stream failed `middles_insufficient` / NoRelays even
        // with all three seed sessions live (device-observed 2026-07-06). Warm
        // the selector's exact candidate set (routing_table ∪ live_sessions)
        // over WHATEVER session exists using the iterative Kademlia walk — the
        // one that reliably resolves RD keys on the sparse pinned-seed net.
        // Freshness-gated + capped ⇒ zero RPC once fresh (no extra radio
        // wakeups). This is the same fix the mailbox FETCH reply-leg already
        // applies (service_tasks.rs `warm_known_relay_directory`).
        let selector_candidates: Vec<[u8; 32]> = {
            let mut c: Vec<[u8; 32]> = self
                .dht
                .routing_table_contacts()
                .into_iter()
                .map(|contact| contact.node_id)
                .collect();
            {
                let sessions = lock!(self.live_sessions);
                c.extend(
                    sessions
                        .values()
                        .filter(|i| i.state == crate::types::SessionState::Active)
                        .filter_map(|i| i.node_id.as_ref().map(|n| *n.as_bytes())),
                );
            }
            c.sort_unstable();
            c.dedup();
            // Never warm our own RD key (self can appear via routing/sessions).
            let me = self.dht.local_node_id();
            c.retain(|n| *n != me);
            // The routing table also contains ordinary app endpoints and
            // transport-only relays. Their relay-directory keys can never
            // exist; probing them on every circuit retry turns one miss into a
            // self-sustaining DHT/circuit storm. The authenticated handshake
            // capability is the authoritative anonymity-relay signal.
            c.retain(|n| {
                service_tasks::peer_advertised_anonymity_relay(
                    &self.dispatcher.crypto.peer_cap_flags,
                    n,
                )
            });
            c
        };
        cached += self
            .warm_known_relay_directory(
                &selector_candidates,
                MAX_STREAM_RELAY_PREWARM,
                std::time::Duration::from_secs(5),
            )
            .await;
        cached
    }

    /// Open a pinned stream circuit ending at an exact published rendezvous relay.
    ///
    /// Used by the receive side to register the same stream cookie at every live
    /// published R, and by the send side after it has chosen one of the receiver's
    /// fresh ads.
    pub async fn open_stream_circuit_to_rendezvous_relay(
        &self,
        rendezvous_node_id: [u8; 32],
        reg_kp: &veil_crypto::GeneratedKeyPair,
        last_epoch: &std::sync::atomic::AtomicU64,
        hop_count: usize,
    ) -> std::result::Result<
        (DataCircuit, tokio::sync::mpsc::Receiver<Vec<u8>>),
        veil_types::AnonOnionSendError,
    > {
        let relay_path = match self.select_onion_relay_path_to(rendezvous_node_id, hop_count) {
            Ok(path) => path,
            Err(_) => {
                let _warm_guard = self.anonymity.stream_relay_directory_warm_lock.lock().await;

                // Another parallel stream worker may have completed the
                // cold-start warm while we waited for the single-flight
                // guard. Re-check before doing any network DHT work.
                match self.select_onion_relay_path_to(rendezvous_node_id, hop_count) {
                    Ok(path) => path,
                    Err(_) => {
                        let cached = self
                            .cache_stream_relay_directories_for_path(rendezvous_node_id, hop_count)
                            .await;

                        let outbox: Arc<dyn veil_dht::FrameRouter> =
                            Arc::clone(&self.session_outbox) as Arc<dyn veil_dht::FrameRouter>;
                        service_tasks::warm_connected_relay_directory(
                            &self.live_sessions,
                            &self.dht,
                            &outbox,
                            &self.logger,
                            Some(&self.dispatcher.crypto.peer_cap_flags),
                        )
                        .await;

                        let path =
                            self.select_onion_relay_path_to(rendezvous_node_id, hop_count)?;
                        if cached > 0 {
                            log::debug!(
                                "onion-stream.relay-directory.prewarmed cached={} R={}",
                                cached,
                                veil_util::hex_short(&rendezvous_node_id),
                            );
                        }
                        path
                    }
                }
            }
        };
        self.open_stream_circuit(&relay_path, reg_kp, last_epoch)
    }

    /// Open a pinned stream circuit to the receiver's PUBLISHED rendezvous relay.
    ///
    /// This is the production-safe stream counterpart of
    /// [`Self::send_anonymous_authenticated_to`]: resolve the receiver's freshest
    /// signed `RendezvousAd`s, then try their relays in deterministic freshness
    /// order until one stateful circuit opens. The circuit registers THIS origin's
    /// stream cookie at the receiver's R, so return cells (ACKs / reverse stream
    /// data) splice back over this same circuit.
    pub async fn open_stream_circuit_to_receiver_ad(
        &self,
        receiver_node_id: [u8; 32],
        reg_kp: &veil_crypto::GeneratedKeyPair,
        last_epoch: &std::sync::atomic::AtomicU64,
        hop_count: usize,
    ) -> std::result::Result<
        (DataCircuit, tokio::sync::mpsc::Receiver<Vec<u8>>),
        veil_types::AnonOnionSendError,
    > {
        use veil_types::AnonOnionSendError;

        let relays = self
            .resolve_stream_rendezvous_relays(receiver_node_id)
            .await?;
        let mut last_err = AnonOnionSendError::NoRelays;
        for relay in relays {
            match self
                .open_stream_circuit_to_rendezvous_relay(relay, reg_kp, last_epoch, hop_count)
                .await
            {
                Ok(opened) => return Ok(opened),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    /// Like [`Self::open_stream_circuit`] but PICKS the rendezvous relay R itself:
    /// the relay-directory-resolvable routing-table contact with the smallest
    /// node_id (DETERMINISTIC, so both endpoints on the same network agree on R
    /// without a handshake — the onion-stream validation shortcut). 1-hop circuit
    /// (R is first hop AND terminus): R sees the sender directly, acceptable on a
    /// trusted test net; production uses a multi-hop path to a resolved rendezvous
    /// ad. `None`-relays error if no resolvable relay is known yet.
    pub async fn open_stream_circuit_auto(
        &self,
        reg_kp: &veil_crypto::GeneratedKeyPair,
        last_epoch: &std::sync::atomic::AtomicU64,
    ) -> std::result::Result<
        (DataCircuit, tokio::sync::mpsc::Receiver<Vec<u8>>),
        veil_types::AnonOnionSendError,
    > {
        use veil_anonymity::directory::relay_directory_dht_key;
        use veil_types::AnonOnionSendError;
        // R candidates = CONNECTED (session) peers whose relay-directory entry
        // (their anonymity x25519, needed to onion-wrap to them) is cached
        // locally — the rendezvous relays we actually have a session to, NOT the
        // DHT routing table (which rarely holds them). Deterministic (smallest
        // node_id) so both ends agree on R with no handshake.
        // FETCH + cache the CONNECTED relays' relay-directory entries (their
        // anonymity x25519, needed to onion-wrap to R) — the proven cold-start warm
        // the datagram path runs; the pinned-seed setup never caches them
        // organically (the documented DHT-completeness wall).
        let outbox: Arc<dyn veil_dht::FrameRouter> =
            Arc::clone(&self.session_outbox) as Arc<dyn veil_dht::FrameRouter>;
        let warmed = service_tasks::warm_connected_relay_directory(
            &self.live_sessions,
            &self.dht,
            &outbox,
            &self.logger,
            Some(&self.dispatcher.crypto.peer_cap_flags),
        )
        .await;
        // DETERMINISTIC terminus: the lowest-node_id contact in the routing
        // table. Both ends seed routing from the SAME bootstrap relays, so its
        // minimum (a seed-relay — this deployment's seeds sort below the clients)
        // is IDENTICAL on both ends, and the splice only rendezvous if BOTH
        // register at one R. Picking the lowest currently-RESOLVABLE relay
        // diverged on-device: the desktop had warmed only 2 of 3 relay-dirs and
        // chose c6ace22e while the phone (3 of 3) chose 3d3575c9 → the splice
        // never met → the pull stream RESET. So fix R = min(routing) and WAIT —
        // via the caller's retry loop — until THAT specific R's relay-dir is
        // cached (the warm above fetches connected relays'); never silently fall
        // back to a different R. (Validation shortcut: assumes the lowest routing
        // contact is a relay; prod wants the receiver's published rendezvous R.)
        let mut routing: Vec<[u8; 32]> = self
            .dht
            .routing_table_contacts()
            .into_iter()
            .map(|c| c.node_id)
            .collect();
        routing.sort_unstable();
        routing.dedup();
        let connected = {
            let g = lock!(self.live_sessions);
            g.values()
                .filter(|i| i.state == crate::types::SessionState::Active)
                .count()
        };
        let r = match routing.first() {
            Some(r) => *r,
            None => {
                log::warn!("onion-stream.relay-pick routing=0 connected={connected} (no contacts)");
                return Err(AnonOnionSendError::NoRelays);
            }
        };
        let r_resolvable = self.dht.get_local(&relay_directory_dht_key(&r)).is_some();
        // log::warn so it reaches Android logcat (the node's tracing logger doesn't).
        log::warn!(
            "onion-stream.relay-pick warmed={warmed} connected={connected} routing={} R={:02x}{:02x}{:02x}{:02x} r_resolvable={r_resolvable}",
            routing.len(),
            r[0],
            r[1],
            r[2],
            r[3],
        );
        if !r_resolvable {
            // The deterministic R isn't cached yet — retry (NOT a different R).
            return Err(AnonOnionSendError::NoRelays);
        }
        self.open_stream_circuit(&[r], reg_kp, last_epoch)
    }

    /// Send one FORWARD data cell over a pinned [`DataCircuit`]: `wrap_payload`
    /// (fixed 384 B) → XOR every hop layer → `CircuitData` to the first hop. No
    /// per-cell ECDH, no per-cell signature. `payload` ≤ `MAX_CIRCUIT_INNER`
    /// (382 B). ADDITIVE helper.
    pub fn send_circuit_cell(
        &self,
        circ: &DataCircuit,
        payload: &[u8],
    ) -> std::result::Result<(), veil_types::AnonOnionSendError> {
        self.send_circuit_cell_detailed(circ, payload)
            .map_err(Into::into)
    }

    /// Detailed sibling of [`Self::send_circuit_cell`] for stream transports.
    /// `QueueFull` means the cell has NOT entered the next local queue and should
    /// be retried as local backpressure, not treated as an end-to-end loss.
    pub fn send_circuit_cell_detailed(
        &self,
        circ: &DataCircuit,
        payload: &[u8],
    ) -> std::result::Result<(), DataCircuitSendError> {
        use veil_anonymity::circuit_data::{Direction, apply_layers, wrap_payload};
        use veil_anonymity::circuit_wire::CircuitDataPayload;

        let seq = circ.alloc_seq().ok_or(DataCircuitSendError::NoRelays)?; // exhausted → rotate
        let mut buf = wrap_payload(payload, circ.cell_bytes)
            .map_err(|_| DataCircuitSendError::PayloadTooLarge)?;
        apply_layers(&circ.keys, Direction::Forward, seq, &mut buf)
            .map_err(|_| DataCircuitSendError::NoRelays)?;
        let cell = CircuitDataPayload {
            circuit_id: circ.origin_circuit_id,
            seq,
            ciphertext: buf,
        };
        let enc = cell
            .encode(circ.cell_bytes)
            .map_err(|_| DataCircuitSendError::NoRelays)?;
        self.send_relay_chain_frame(
            &circ.first_hop,
            veil_proto::family::RelayChainMsg::CircuitData,
            &enc,
        )
        .map_err(|err| match err {
            veil_session::SendToError::Full => DataCircuitSendError::QueueFull,
            veil_session::SendToError::Missing | veil_session::SendToError::Closed => {
                DataCircuitSendError::NoRelays
            }
        })?;
        Ok(())
    }

    /// Register this node as a LOCATION-anonymous service (the prod entry point):
    /// pick a rendezvous relay R + `hop_count - 1` intermediate hops from the
    /// local relay directory, build an onion circuit to R (registering a fresh
    /// cookie over it — R never learns our location), and publish a
    /// `RendezvousAd` at (R, cookie, our x25519). The maintenance tick keeps the
    /// circuit alive. `hop_count` is clamped to ≥ 2 so R itself can't see us.
    /// Returns the published cookie.
    /// Pick an onion relay path first→terminus: a connected+published rendezvous
    /// relay R (the terminus = `relay_path.last()`) + `hop_count - 1` intermediate
    /// published relays from the local directory, distinct from R. `hop_count` is
    /// clamped to ≥ 2 so R itself can't see us. Errors `NoRelays` when there
    /// aren't enough published relays.
    pub(crate) fn select_onion_relay_path(
        &self,
        hop_count: usize,
    ) -> std::result::Result<Vec<[u8; 32]>, veil_types::AnonOnionSendError> {
        use veil_types::AnonOnionSendError;

        let hop_count = hop_count.max(2);
        // Δ2-h: honour the operator's pinned rendezvous relays (was `&[]`, which
        // silently ignored the `[anonymity].rendezvous_relays` pin on this path).
        let r = service_tasks::pick_rendezvous_relay(
            &self.live_sessions,
            &self.dht,
            &self.anonymity.pinned_rendezvous_relays,
        )
        .ok_or_else(|| {
            // Which of the NoRelays conditions actually fired — needed to
            // diagnose the bursty reply-path failures (all concurrent sends
            // share this state, so one lapse fails a whole drain pass).
            log::debug!(
                "anonymity.reply_path.no_rendezvous_relay live_active={} pinned={}",
                lock!(self.live_sessions)
                    .values()
                    .filter(|i| i.state == crate::types::SessionState::Active)
                    .count(),
                self.anonymity.pinned_rendezvous_relays.len(),
            );
            AnonOnionSendError::NoRelays
        })?;
        self.select_onion_relay_path_to(r, hop_count)
    }

    /// Pick a multi-hop relay path ending at a specific published rendezvous relay.
    ///
    /// Used when the receiver has already told us (via its signed rendezvous ad)
    /// which R owns its cookie. Unlike the validation shortcut, this keeps at least
    /// one middle hop before R so the rendezvous relay cannot directly observe the
    /// origin transport session.
    pub(crate) fn select_onion_relay_path_to(
        &self,
        r: [u8; 32],
        hop_count: usize,
    ) -> std::result::Result<Vec<[u8; 32]>, veil_types::AnonOnionSendError> {
        use veil_anonymity::directory::{
            DEFAULT_FRESHNESS_WINDOW_SECS, discover_relay_hops_cached, relay_directory_dht_key,
        };
        use veil_types::AnonOnionSendError;

        let hop_count = hop_count.max(2);
        if self.dht.get_local(&relay_directory_dht_key(&r)).is_none() {
            log::debug!(
                "anonymity.reply_path.r_directory_missing r={}",
                veil_util::hex_short(&r),
            );
            return Err(AnonOnionSendError::NoRelays);
        }
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut candidates: Vec<[u8; 32]> = self
            .dht
            .routing_table_contacts()
            .into_iter()
            .map(|c| c.node_id)
            .collect();
        {
            let sessions = lock!(self.live_sessions);
            candidates.extend(
                sessions
                    .values()
                    .filter(|i| i.state == crate::types::SessionState::Active)
                    .filter_map(|i| i.node_id.as_ref().map(|n| *n.as_bytes())),
            );
        }
        candidates.sort_unstable();
        candidates.dedup();
        // Exclude R (the terminus, must differ from middles) and ourselves (our
        // own node id can appear via routing table / a self session entry; we
        // must never pick ourselves as a middle hop, and our RD key never
        // resolves locally anyway).
        let me = self.dht.local_node_id();
        candidates.retain(|n| *n != r && *n != me);
        let dht = std::sync::Arc::clone(&self.dht);
        let mut discovered: Vec<[u8; 32]> = discover_relay_hops_cached(
            &candidates,
            |n| dht.get_local(&relay_directory_dht_key(n)),
            now_unix,
            DEFAULT_FRESHNESS_WINDOW_SECS,
            &self.anonymity.relay_entry_verify_cache,
        )
        .into_iter()
        .map(|d| d.hop.node_id)
        .collect();
        if discovered.len() < hop_count - 1 {
            // not enough relays to hide from R
            log::warn!(
                "anonymity.reply_path.middles_insufficient r={} candidates={} \
                 discovered_fresh={} need={}",
                veil_util::hex_short(&r),
                candidates.len(),
                discovered.len(),
                hop_count - 1,
            );
            return Err(AnonOnionSendError::NoRelays);
        }
        // M-1: randomise which middle relays we pick. `discover_relay_hops`
        // returns hops in a deterministic (freshness/candidate) order, so a bare
        // `.take(hop_count - 1)` always selected the SAME middles for a given
        // directory snapshot — predictable paths concentrate traffic on a few
        // relays and let an observer pre-compute likely hop sets. Fisher–Yates
        // over OsRng so each registration draws an independent middle subset.
        {
            use rand_core::{OsRng, RngCore};
            let n = discovered.len();
            for i in (1..n).rev() {
                // i+1 distinct outcomes; modulo bias is negligible for
                // routing-table-sized n and not security-relevant to the draw.
                let j = (OsRng.next_u64() % (i as u64 + 1)) as usize;
                discovered.swap(i, j);
            }
        }
        // The FIRST hop must be reachable over a LIVE session: we send its
        // CircuitBuild frame directly to it (every later hop is reached via
        // relay-chain forwarding, so those need no session of ours). A middle is
        // admitted purely on RD freshness above, so the shuffle can put an
        // RD-fresh-but-session-less relay at index 0 — the circuit then builds a
        // valid path whose CircuitBuild send fails NoRelays at build time. This
        // is the reply/reverse-leg's dominant failure (bursty
        // reply_circuit_failed on the mailbox drain: RD present, no session to
        // the picked first middle). The stream path masked it with a post-build
        // has_live_session retire+retry; the reply path has none. Promote a
        // session-backed discovered relay to index 0 (keeps the shuffle's
        // randomness among the session-backed set). Selecting the first hop
        // through a relay we already transport to is not an anonymity loss — the
        // first hop always observes our origin session regardless.
        {
            let session_peers: std::collections::HashSet<[u8; 32]> = {
                let sessions = lock!(self.live_sessions);
                sessions
                    .values()
                    .filter(|i| i.state == crate::types::SessionState::Active)
                    .filter_map(|i| i.node_id.as_ref().map(|n| *n.as_bytes()))
                    .collect()
            };
            if !discovered.is_empty()
                && !session_peers.contains(&discovered[0])
                && let Some(pos) = discovered.iter().position(|n| session_peers.contains(n))
            {
                discovered.swap(0, pos);
                // else: no discovered middle is session-backed — the build's
                // CircuitBuild send will fail NoRelays, the honest outcome (we
                // hold no session to reach any usable first hop right now).
            }
        }
        let mids: Vec<[u8; 32]> = discovered.into_iter().take(hop_count - 1).collect();
        let mut relay_path = mids;
        relay_path.push(r);
        Ok(relay_path)
    }

    pub fn register_onion_service(
        &self,
        hop_count: usize,
    ) -> std::result::Result<[u8; 16], veil_types::AnonOnionSendError> {
        let seed = self.sovereign_onion_identity_seed();
        self.register_onion_service_with_identity(hop_count, seed, false, None)
            .map(|(cookie, _)| cookie)
    }

    pub fn register_ephemeral_onion_service(
        &self,
        identity_seed: zeroize::Zeroizing<[u8; 32]>,
        hop_count: usize,
    ) -> std::result::Result<[u8; 32], veil_types::AnonOnionSendError> {
        self.register_ephemeral_onion_service_with_provider_slot(identity_seed, hop_count, 0)
    }

    pub fn register_ephemeral_onion_service_with_provider_slot(
        &self,
        identity_seed: zeroize::Zeroizing<[u8; 32]>,
        hop_count: usize,
        provider_slot: u8,
    ) -> std::result::Result<[u8; 32], veil_types::AnonOnionSendError> {
        if provider_slot >= veil_anonymity::blinded_descriptor::MAX_PROVIDER_SLOTS {
            return Err(veil_types::AnonOnionSendError::NoRelays);
        }
        let seed = std::sync::Arc::new(identity_seed);
        self.register_onion_service_with_identity(hop_count, Some(seed), true, Some(provider_slot))
            .map(|(_, vk)| vk.expect("ephemeral identity seed always has a public key"))
    }

    pub fn withdraw_ephemeral_onion_service(&self, identity_vk: [u8; 32]) -> bool {
        withdraw_ephemeral_service(
            &self.anonymity.onion_services,
            &self.anonymity.rendezvous_publisher_entries,
            identity_vk,
        )
    }

    fn sovereign_onion_identity_seed(
        &self,
    ) -> Option<std::sync::Arc<zeroize::Zeroizing<[u8; 32]>>> {
        let sovereign_current = self.identity.sovereign_identity.get();
        sovereign_current
            .as_ref()
            .and_then(|sov| sov.ed25519_signing_key())
            .map(|ed| std::sync::Arc::new(zeroize::Zeroizing::new(ed.to_bytes())))
    }

    fn register_onion_service_with_identity(
        &self,
        hop_count: usize,
        identity_seed: Option<std::sync::Arc<zeroize::Zeroizing<[u8; 32]>>>,
        ephemeral: bool,
        descriptor_provider_slot: Option<u8>,
    ) -> std::result::Result<([u8; 16], Option<[u8; 32]>), veil_types::AnonOnionSendError> {
        // Keep the existing hard work cap, but NEVER evict an older live
        // capability silently: that would turn an apparently-valid public link
        // into a black hole. Re-registering the same identity is allowed.
        const MAX_ONION_SERVICES: usize = 8;
        // Always reserve one slot for the config-driven sovereign service.
        // Otherwise seven live links plus one more capability could prevent
        // the node's ordinary anonymous endpoint from starting after restart.
        const MAX_EPHEMERAL_ONION_SERVICES: usize = MAX_ONION_SERVICES - 1;
        let requested_vk = identity_seed
            .as_deref()
            .map(|seed| veil_crypto::key_blinding::ed25519_public_from_seed(seed));
        {
            let services = lock!(self.anonymity.onion_services);
            let already_registered = requested_vk.and_then(|vk| {
                services.iter().find_map(|entry| {
                    entry
                        .descriptor_identity_seed
                        .as_deref()
                        .filter(|seed| {
                            veil_crypto::key_blinding::ed25519_public_from_seed(seed) == vk
                        })
                        .filter(|_| entry.descriptor_provider_slot == descriptor_provider_slot)
                        .map(|_| (entry.cookie, Some(vk)))
                })
            });
            if let Some(existing) = already_registered {
                return Ok(existing);
            }
            let identity_registered = requested_vk.is_some_and(|vk| {
                services.iter().any(|entry| {
                    entry
                        .descriptor_identity_seed
                        .as_deref()
                        .is_some_and(|seed| {
                            veil_crypto::key_blinding::ed25519_public_from_seed(seed) == vk
                        })
                })
            });
            if identity_registered {
                self.logger.warn(
                    "onion.service.provider_slot_change",
                    "withdraw the existing capability identity before changing its provider slot",
                );
                return Err(veil_types::AnonOnionSendError::NoRelays);
            }
            let cap = if ephemeral {
                MAX_EPHEMERAL_ONION_SERVICES
            } else {
                MAX_ONION_SERVICES
            };
            if services.len() >= cap {
                self.logger.warn(
                    "onion.service.capacity",
                    format!("onion-service slot cap ({cap}) reached — refusing registration"),
                );
                return Err(veil_types::AnonOnionSendError::NoRelays);
            }
        }

        let relay_path = self.select_onion_relay_path(hop_count)?;
        let r = *relay_path.last().expect("non-empty relay path");
        // Derive a per-identity, per-period rendezvous cookie (HKDF of the
        // sovereign Ed25519 seed) instead of a fresh OsRng value. A random cookie
        // rotated on every process restart: the relay re-registered under a NEW
        // cookie while a sender resolved an ad (<=24h valid) carrying the OLD one
        // -> lookup(cookie) missed -> cookie_unknown black-hole on a node that
        // restarts every few minutes. The derivation is STABLE across restarts
        // within the 24h blinded-descriptor period and rotates per period in
        // lockstep with the descriptor (so a relay cannot link the receiver's
        // rendezvous across the boundary). Seed-derived (NOT node_id) keeps it
        // opaque to the relay, preserving the descriptor's unlinkability. No
        // sovereign identity -> cannot publish a descriptor anyway -> keep random.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let period = veil_anonymity::blinded_descriptor::current_period(now_unix);
        let identity_vk = identity_seed
            .as_deref()
            .map(|seed| veil_crypto::key_blinding::ed25519_public_from_seed(seed));
        // The cookie is whatever this service's registration key may claim —
        // the relay checks the pairing, so the two can no longer be minted
        // apart. `register_onion_circuit_with_identity` re-derives the same
        // key from the same inputs, and for the seedless case mints its own
        // random one; either way the cookie below is the one that key claims.
        let (reg_keypair, cookie) = Self::onion_reg_pair(
            identity_seed.as_deref().map(|s| &**s),
            period,
            descriptor_provider_slot,
        );

        // Δ2-c: sign + DHT-key the ad under a per-service EPHEMERAL pseudo
        // identity (derived from this service's registration keypair), NOT our
        // sovereign node_id — otherwise the ad would publicly link our identity
        // to our live rendezvous point, defeating the blinded descriptor's
        // unlinkability. Taken from the keypair in hand, not looked up by
        // cookie afterwards: the cookie does not name a registration.
        let ephemeral_ad_identity = ephemeral_ad_identity_for(&reg_keypair);
        // Build + register the circuit (no session register — that is the leak),
        // then publish the ad so clients can find us.
        let OnionRegistration {
            id: registration,
            confirmed,
        } = self.register_onion_circuit_with_identity(
            &relay_path,
            reg_keypair,
            cookie,
            identity_seed.clone(),
            ephemeral,
            descriptor_provider_slot,
        )?;
        // COOKIE-DIAG: the cookie THIS node registers at the relay + publishes in
        // its ad. A sender's `rendezvous.cookie.introduce` line for this node must
        // carry the SAME cookie, else the relay drops the introduce (cookie_unknown).
        log::info!(
            "rendezvous.cookie.register: relay={} cookie={} period={} me={}",
            veil_util::hex_short(&r),
            cookie
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            period,
            veil_util::hex_short(self.identity.local_identity.node_id.as_bytes()),
        );
        // ORDERING BARRIER (publish-before-register race): the descriptor/ad
        // must not become resolvable before the relay has BOUND the cookie —
        // `register_onion_circuit` fires the build and returns immediately,
        // while the terminus registration only takes effect when the
        // `CircuitBuilt` ACK lands. Publishing right here let a stall-watching
        // sender resolve the fresh descriptor and fire its whole queued
        // introduce burst ~40 ms BEFORE the registration (relay-trace measured:
        // 60 introduces silently dropped as cookie_unknown, recovery deferred
        // to the sender's next stall window — the churn minute-outliers).
        // Defer both publishes until the entry's `confirmed` flag flips.
        let relay = r;
        let publish_seed = identity_seed.clone();
        let publish_slot = descriptor_provider_slot;
        // The publisher row is written UNDER the services lock, in one step
        // with the check that this registration is still on the books (see
        // `publish_row_if_registered`).
        let publish_row = move |this: &NodeServices| {
            let registered = service_tasks::rendezvous_register_publisher(
                &this.anonymity,
                &relay,
                cookie,
                // Short rendezvous-ad TTL (NOT the 24h directory default): a stale ad
                // a sender cached before this receiver rotated relay/cookie must
                // self-expire fast, else its introduces black-hole as cookie_unknown.
                // The ~15s refresh tick keeps the live ad alive.
                service_tasks::RENDEZVOUS_AD_VALIDITY_SECS,
                ephemeral_ad_identity,
            );
            if !registered {
                // Nothing will sign this service's ad, so it is undiscoverable
                // by the rendezvous path however well the rest of the
                // registration went (report17 V17-M6).
                this.logger.warn(
                    "anonymity.rendezvous_ad.slots_full",
                    "no publisher slot left for this service's rendezvous ad",
                );
            }
        };
        // The BLINDED descriptor (3c) goes to the DHT after the lock is let
        // go: identity-unlinkable, and a DHT write holds no registry of ours.
        // Capability services use their random per-share identity here, never
        // the host's sovereign key.
        let publish_descriptor = move |this: &NodeServices| {
            if let Some(seed) = publish_seed.as_deref() {
                this.publish_blinded_descriptor_for(seed, relay, cookie, publish_slot);
            }
        };
        self.publish_after_circuit_confirmed(
            registration,
            confirmed,
            publish_row,
            publish_descriptor,
        );

        Ok((cookie, identity_vk))
    }

    /// Run `publish` once `confirmed` flips true — i.e. once the rendezvous
    /// relay ACK'd this circuit's registration (`CircuitBuilt`) — so a cookie
    /// is never RESOLVABLE before it is LIVE at the relay (the
    /// publish-before-register race; see `register_onion_service`). Bounded:
    /// after ~3 s without an ACK it publishes anyway — discoverability must
    /// not hard-fail on a lost ACK; the maintenance tick already re-selects a
    /// fresh path for unconfirmed circuits (Δ2-d). A short-lived thread (not a
    /// blocking poll in the caller): registrations are rare (startup + period
    /// rotation, ≤ MAX_ONION_SERVICES entries) and the callers sit on the
    /// async maintenance tick / IPC path where blocking would stall the
    /// executor — the typical wait is one relay round-trip (~40-100 ms).
    /// Bounded wait for a just-built EPHEMERAL REPLY circuit's `CircuitBuilt`
    /// ACK before the caller fires the introduce that hands out its cookie.
    /// The receiver's delivery-ACK comes back FAST (one introduce-forward +
    /// processing, often <100 ms) and can otherwise reach our reply relay
    /// BEFORE our own registration ACK — relay-trace measured exactly that
    /// residual after the publish barrier: 3× `cookie_unknown` on the reply
    /// cookie ~100 ms before its `circuit.registered`. The lost delivery-ACK
    /// then feeds the stall tracker a FALSE miss and slows churn recovery.
    /// Blocking is acceptable here: reply-expecting sends are user-message
    /// rate, the surrounding send path already blocks on crypto + session
    /// enqueue, and the typical wait is one relay round-trip (~40–100 ms).
    /// After 1 s proceed anyway (old behavior): the ACK may still land before
    /// the receiver answers, and a dead relay path shouldn't stall the send.
    pub(crate) async fn wait_reply_circuit_confirmed(
        &self,
        confirmed: &std::sync::atomic::AtomicBool,
    ) {
        const TIMEOUT_MS: u64 = 1_000;
        const POLL_MS: u64 = 10;

        // This wait runs ON a tokio worker: the async send path (IPC handler
        // task) reaches it inline. It used to be a blocking `thread::sleep`,
        // which PARKS that worker together with its task queue — and the
        // inbound dispatch that would process the very `CircuitBuilt` ACK we
        // are waiting for sits in that queue. Device-log evidence: only
        // 15/1148 confirmations landed inside a wait window, while 791/938
        // landed within 200 ms AFTER the timeout expired. The wait essentially
        // never succeeded, every reply-expecting send (chat message, mailbox
        // FETCH) paid the full 1000 ms, and the introduce still fired with an
        // unregistered reply cookie — the exact race this wait exists to
        // close.
        //
        // `block_in_place` fixed that on multi-thread runtimes by handing the
        // worker's queue to another thread, but it PANICS on a current-thread
        // runtime, so that flavour was left skipping the wait entirely and
        // keeping the race open. Awaiting instead of blocking works on every
        // flavour: each poll yields, the dispatch task runs, the ACK lands and
        // the loop returns early — typically one relay round-trip (~40-100 ms).
        //
        // Polling rather than a `Notify`: the confirmation flag lives on
        // `OriginCircuit` in `veil-anonymity`, where tokio is only a
        // dev-dependency. An event-driven wake would promote tokio to a
        // library dependency of a crate deliberately kept to crypto + codec
        // deps, to save ~5 ms and ≤100 timer wakeups on a user-message-rate
        // path. The polling loop keeps that crate lean; revisit if the flag
        // ever moves somewhere that already has tokio.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(TIMEOUT_MS);
        while !confirmed.load(std::sync::atomic::Ordering::Relaxed) {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            let step = std::time::Duration::from_millis(POLL_MS).min(deadline - now);
            tokio::time::sleep(step).await;
        }
        if !confirmed.load(std::sync::atomic::Ordering::Relaxed) {
            self.logger.info(
                "anonymity.reply_circuit.unconfirmed",
                format!(
                    "no CircuitBuilt ACK for the reply circuit within {TIMEOUT_MS}ms — \
                     sending anyway (delivery-ACK may race the registration)"
                ),
            );
        }
    }

    fn publish_after_circuit_confirmed(
        &self,
        registration: u64,
        confirmed: std::sync::Arc<std::sync::atomic::AtomicBool>,
        publish_row: impl FnOnce(&NodeServices) + Send + 'static,
        publish_descriptor: impl FnOnce(&NodeServices) + Send + 'static,
    ) {
        const CONFIRM_TIMEOUT_MS: u64 = 3_000;
        const POLL_MS: u64 = 20;
        /// The most publishes that may be waiting on an ACK at once.
        ///
        /// Generous against the honest case — every service may be registering
        /// at the same moment, twice over — and finite, which the old code was
        /// not: `withdraw` frees the service slot at once and leaves the
        /// waiter behind, so register-then-withdraw in a loop grew threads
        /// without any cap applying (report17 V17-M7).
        const MAX_PENDING: usize = 16;

        let this = self.clone();
        let pending = std::sync::Arc::clone(&self.anonymity.pending_confirm_publishes);
        if !claim_confirm_waiter(&pending, MAX_PENDING) {
            self.logger.warn(
                "anonymity.publish.confirm_waiters_full",
                format!(
                    "{MAX_PENDING} publishes are already waiting for an ACK — \
                     publishing this one immediately"
                ),
            );
            // Immediately rather than never: the barrier is an optimisation
            // against a narrow race, and dropping the publish would cost this
            // service its discoverability outright.
            if publish_row_if_registered(&self.anonymity.onion_services, registration, || {
                publish_row(self)
            }) {
                publish_descriptor(self);
            }
            return;
        }
        std::thread::spawn(move || {
            // Decremented on EVERY exit path below.
            struct Waiting(std::sync::Arc<std::sync::atomic::AtomicUsize>);
            impl Drop for Waiting {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                }
            }
            let _waiting = Waiting(pending);
            let mut waited_ms = 0u64;
            while !confirmed.load(std::sync::atomic::Ordering::Relaxed)
                && waited_ms < CONFIRM_TIMEOUT_MS
            {
                std::thread::sleep(std::time::Duration::from_millis(POLL_MS));
                waited_ms += POLL_MS;
            }
            if confirmed.load(std::sync::atomic::Ordering::Relaxed) {
                this.logger.info(
                    "anonymity.publish.after_confirm",
                    format!("circuit registration ACK'd after ~{waited_ms}ms — publishing ad"),
                );
            } else {
                this.logger.warn(
                    "anonymity.publish.unconfirmed",
                    format!(
                        "no CircuitBuilt ACK within {CONFIRM_TIMEOUT_MS}ms — publishing \
                         anyway (ad may briefly black-hole until the rebuild tick)"
                    ),
                );
            }
            // The service may have been WITHDRAWN while this waited.
            //
            // `withdraw_ephemeral_onion_service` drops the entry and its
            // publisher row and returns; this thread carried neither a
            // cancellation nor any notion of which registration it belonged
            // to, so it went on to re-add the publisher and put a fresh
            // blinded descriptor into the DHT — new ciphertext for a service
            // the owner had revoked, discoverable until it ages out, with the
            // ephemeral signing key kept alive beside it (report17 V17-M7).
            //
            // Two things it then still got wrong (report20 V18-M5). It asked
            // by COOKIE, and a re-registration inside the same period has the
            // same cookie, so a stale waiter was satisfied by a service it
            // did not belong to and wrote a row for the OLD relay. And it
            // asked, let go of the lock, and only then wrote the row, so a
            // withdraw fitting between the two left a row behind that every
            // tick re-signed. The registration number answers the first; the
            // row going in under the same lock as the question answers the
            // second.
            if !publish_row_if_registered(&this.anonymity.onion_services, registration, || {
                publish_row(&this)
            }) {
                this.logger.info(
                    "anonymity.publish.withdrawn_before_publish",
                    "the service was withdrawn while its publish waited for the \
                     circuit ACK — not publishing",
                );
                return;
            }
            publish_descriptor(&this);
        });
    }

    /// Seal + store a blinded service descriptor for one explicit service
    /// identity. The seed may be the normal sovereign Ed25519 seed OR a random
    /// per-capability seed; the descriptor wire/DHT layer cannot distinguish
    /// them and therefore cannot link the latter to this node's identity.
    fn publish_blinded_descriptor_for(
        &self,
        identity_seed: &[u8; 32],
        rendezvous: [u8; 32],
        cookie: [u8; 16],
        provider_slot: Option<u8>,
    ) {
        let Some(x25519_pk) = self
            .dispatcher
            .anonymity_x25519_sk
            .as_ref()
            .map(|sk| x25519_dalek::PublicKey::from(sk.as_ref()).to_bytes())
        else {
            return;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let period = veil_anonymity::blinded_descriptor::current_period(now);
        let body = veil_anonymity::blinded_descriptor::BlindedDescriptorBody {
            receiver_node_id: *self.identity.local_identity.node_id.as_bytes(),
            rendezvous_node_id: rendezvous,
            auth_cookie: cookie,
            receiver_x25519_pk: x25519_pk,
        };
        if let Some((dht_key, bytes)) =
            veil_anonymity::blinded_descriptor::seal_descriptor(identity_seed, period, &body)
        {
            // diff-audit L5: replicate to the K-closest peers immediately (not
            // store_local-only). A by-identity sender resolves the descriptor at
            // H(domain ‖ blinded_pub), which is unlikely to be in OUR keyspace —
            // so a local-only store would never be found cross-node until the
            // 30-min republish tick happened to fan it out. The recursive STORE
            // is accepted by remote dispatchers now that the "od" magic is
            // self-authenticating (validate_store_value_by_magic +
            // mirror_cache_key_ok bind it to its canonical key); the periodic
            // republish tick keeps it alive thereafter.
            dht_publish_replicated_via(
                &self.dht,
                &self.session_tx_registry,
                *self.identity.local_identity.node_id.as_bytes(),
                dht_key,
                bytes,
            );
        }
        if let Some(provider_slot) = provider_slot
            && let Some((dht_key, bytes)) =
                veil_anonymity::blinded_descriptor::seal_provider_descriptor(
                    identity_seed,
                    period,
                    provider_slot,
                    &body,
                )
        {
            dht_publish_replicated_via(
                &self.dht,
                &self.session_tx_registry,
                *self.identity.local_identity.node_id.as_bytes(),
                dht_key,
                bytes,
            );
        }
    }

    /// The onion service's rendezvous registration keypair for `period`,
    /// derived from that SERVICE identity seed (see
    /// `veil_crypto::identity::derive_onion_reg_seed` for why and for the
    /// anonymity argument). `None` without a descriptor identity — the caller
    /// falls back to a random keypair, matching the cookie's own fallback.
    fn onion_reg_keypair_for_seed(
        identity_seed: Option<&[u8; 32]>,
        period: u64,
        provider_slot: Option<u8>,
    ) -> Option<veil_crypto::GeneratedKeyPair> {
        identity_seed.map(|seed| {
            let reg_seed = match provider_slot {
                Some(slot) => {
                    veil_crypto::identity::derive_onion_provider_reg_seed(seed, period, slot)
                }
                None => veil_crypto::identity::derive_onion_reg_seed(seed, period),
            };
            veil_crypto::ed25519_keypair_from_seed(&reg_seed)
        })
    }

    /// The cookie a registration keypair may claim at the rendezvous.
    ///
    /// The cookie is no longer derived from the identity seed directly: the
    /// rendezvous relay has to be able to *check* the pairing, and the only
    /// thing it holds is the registration payload — it never learns who we are
    /// and never sees our ad. Deriving from `reg_pk` moves the answer into its
    /// reach without telling it anything more. See
    /// [`veil_anonymity::circuit_register::cookie_for_reg_pk`].
    ///
    /// The rotation cadence is unchanged: `reg_pk` was already derived from
    /// `(identity_seed, period, slot)`, so the cookie still rotates per period
    /// and per provider slot, and is still stable across process restarts
    /// inside a period.
    fn onion_auth_cookie_for_keypair(
        reg_keypair: &veil_crypto::GeneratedKeyPair,
    ) -> Option<[u8; 16]> {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&reg_keypair.public_key)
            .ok()?;
        let pk: [u8; 32] = raw.try_into().ok()?;
        Some(veil_anonymity::circuit_register::cookie_for_reg_pk(&pk))
    }

    /// The `(registration keypair, cookie)` pair for a service.
    ///
    /// Minted together and only together: the relay now rejects a registration
    /// whose cookie is not the one its key may claim, so any path that mints
    /// the two independently would produce a service that cannot register.
    /// Seed-derived when a sovereign identity exists (stable across restarts
    /// within a period), random otherwise — random still pairs, because the
    /// cookie comes from whichever key was minted.
    pub(crate) fn onion_reg_pair(
        identity_seed: Option<&[u8; 32]>,
        period: u64,
        provider_slot: Option<u8>,
    ) -> (veil_crypto::GeneratedKeyPair, [u8; 16]) {
        loop {
            let kp = Self::onion_reg_keypair_for_seed(identity_seed, period, provider_slot)
                .unwrap_or_else(|| {
                    veil_crypto::generate_keypair(veil_types::SignatureAlgorithm::Ed25519)
                });
            if let Some(cookie) = Self::onion_auth_cookie_for_keypair(&kp) {
                return (kp, cookie);
            }
            // A key whose public half does not decode to 32 bytes cannot be
            // used. Deterministic derivation never produces one, so this can
            // only be a malformed random mint; retrying costs nothing and
            // beats handing back a service that can never register.
            debug_assert!(
                identity_seed.is_none(),
                "seed-derived registration key must always decode",
            );
        }
    }

    /// Register a location-anonymous service: build its onion circuit + record it
    /// so the maintenance tick keeps it alive ([`Self::maintain_onion_circuits`]).
    /// `relay_path` is first→terminus (terminus = rendezvous relay R); each hop's
    /// X25519 key is resolved from the local relay-directory shard. The caller
    /// separately publishes a `RendezvousAd` at (R, cookie, our x25519) — this
    /// does NOT session-register (the location leak it avoids). See the
    /// onion-registration design doc.
    /// Returns the cookie the service registered under — derived from its
    /// registration key, so the caller must publish THIS cookie in the ad.
    pub fn register_onion_circuit(
        &self,
        relay_path: &[[u8; 32]],
    ) -> std::result::Result<[u8; 16], veil_types::AnonOnionSendError> {
        let seed = self.sovereign_onion_identity_seed();
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let period = veil_anonymity::blinded_descriptor::current_period(now_unix);
        let (reg_keypair, cookie) =
            Self::onion_reg_pair(seed.as_deref().map(|s| &**s), period, None);
        self.register_onion_circuit_with_identity(
            relay_path,
            reg_keypair,
            cookie,
            seed,
            false,
            None,
        )?;
        Ok(cookie)
    }

    /// `reg_keypair` and `cookie` MUST be a pair minted by
    /// [`Self::onion_reg_pair`]: the relay rejects a registration whose cookie
    /// is not the one its key may claim, so the two cannot be chosen
    /// independently any more. Taking the keypair rather than deriving it here
    /// is what makes the seedless (random) case pair at all — a second random
    /// mint would not match the caller's cookie.
    fn register_onion_circuit_with_identity(
        &self,
        relay_path: &[[u8; 32]],
        reg_keypair: veil_crypto::GeneratedKeyPair,
        cookie: [u8; 16],
        descriptor_identity_seed: Option<std::sync::Arc<zeroize::Zeroizing<[u8; 32]>>>,
        ephemeral: bool,
        descriptor_provider_slot: Option<u8>,
    ) -> std::result::Result<OnionRegistration, veil_types::AnonOnionSendError> {
        // Registration keypair: seed-derived per blinded-descriptor period, and
        // the cookie is derived from it (L1 kept the key stable across REBUILDS;
        // deriving it from the seed makes it stable across PROCESS RESTARTS
        // too). R's registry is first-wins anti-squat, so a random per-process
        // key meant an abrupt restart within one period came back with the same
        // derived cookie but a foreign reg_pk and was rejected (CookieClaimed)
        // until the dead subscription aged out (600 s GC) — a live-path black
        // hole on a small-relay topology. With the derived key the restart is a
        // same-key refresh; `next_monotonic_epoch` tracks wall-clock, so the
        // fresh registration's epoch is already above the relay's stored one.
        // No sovereign identity → a random key, and the cookie follows it.
        debug_assert_eq!(
            Some(cookie),
            Self::onion_auth_cookie_for_keypair(&reg_keypair),
            "cookie must be the one this registration key claims",
        );
        // B2: per-service monotonic registration-epoch counter, reused on every
        // rebuild so re-registrations strictly increase even within one second.
        let registration_epoch = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let confirmed = self.build_onion_circuit_once(
            relay_path,
            cookie,
            &reg_keypair,
            &registration_epoch,
            false, // hosted service, not a reply circuit
        )?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let registration = next_onion_registration();
        let mut svcs = lock!(self.anonymity.onion_services);
        // Replace any prior entry for the same cookie (re-register), else push.
        // The entry it displaces takes its publisher row with it: the new
        // registration may sit at another relay, and a row nobody owns is
        // re-signed every tick for as long as the process lives.
        let displaced: Vec<([u8; 32], [u8; 16])> = svcs
            .iter()
            .filter(|e| e.cookie == cookie)
            .filter_map(|e| e.relay_path.last().map(|r| (*r, e.cookie)))
            .collect();
        svcs.retain(|e| e.cookie != cookie);
        if !displaced.is_empty() {
            remove_publisher_rows(&self.anonymity.rendezvous_publisher_entries, &displaced);
        }
        // diff-audit S3: bound the live-service set. Each `register_onion_service`
        // mints a FRESH cookie, so an IPC client looping the call would otherwise
        // grow this Vec without limit — and every maintenance tick rebuilds AND
        // re-publishes a descriptor for EACH entry, turning the leak into traffic
        // amplification. Evict the oldest (FIFO) once at capacity so the work per
        // tick stays bounded; the rate-limiter on the IPC arm bounds call rate.
        const MAX_ONION_SERVICES: usize = 8;
        if svcs.len() >= MAX_ONION_SERVICES {
            self.logger.warn(
                "onion.service.capacity_race",
                "onion-service cap filled concurrently after circuit build",
            );
            return Err(veil_types::AnonOnionSendError::NoRelays);
        }
        svcs.push(anonymity_state::OnionServiceEntry {
            relay_path: relay_path.to_vec(),
            cookie,
            registration,
            built_unix: now,
            reg_keypair,
            confirmed: std::sync::Arc::clone(&confirmed),
            registration_epoch,
            descriptor_identity_seed,
            descriptor_provider_slot,
            ephemeral,
        });
        Ok(OnionRegistration {
            id: registration,
            confirmed,
        })
    }

    /// Maintenance: rebuild any hosted onion-service circuit that is older than
    /// half the relay circuit TTL, so it never lapses. Called from the
    /// maintenance tick. Best-effort — a rebuild that fails (e.g. a hop's
    /// directory entry not currently cached) is retried next tick.
    pub fn maintain_onion_circuits(&self, now_unix: u64) {
        // Config-driven auto-start: if `[anonymity].onion_service` is on and we
        // haven't registered yet, do so now (once relays are available). Builds
        // once; the rebuild loop below keeps it alive.
        //
        // diff-audit S2: scope the `onion_services` lock so its guard is dropped
        // BEFORE `register_onion_service` re-locks the same mutex. Folding the
        // `is_empty()` check into the let-chain condition only avoids a
        // self-deadlock thanks to the edition-2024 if-let temporary-drop rule —
        // a latent footgun that an edition downgrade or refactor would re-arm.
        if let Some(hops) = self.anonymity.onion_service_hops {
            // Ephemeral capability services share this registry; their presence
            // must not suppress the config-driven NORMAL sovereign service.
            let none_registered = {
                !lock!(self.anonymity.onion_services)
                    .iter()
                    .any(|entry| !entry.ephemeral)
            };
            if none_registered {
                let _ = self.register_onion_service(hops);
            }
        }

        // Evict expired circuit state (diff-audit L2): these GCs had ZERO prod
        // callers, so the relay table, rendezvous registry and origin table grew
        // unbounded — the origin table (cap 256) filled in ~10 h as each 150 s
        // rebuild leaked an entry, after which builds failed and the service went
        // dark. Run them here so idle/expired entries are reclaimed.
        let gc_relay = self
            .dispatcher
            .circuit_table
            .as_ref()
            .map_or(0, |t| t.gc(now_unix));
        let gc_rendezvous = self
            .dispatcher
            .circuit_rendezvous
            .as_ref()
            .map_or(0, |r| r.gc(now_unix));
        let gc_origin = self
            .dispatcher
            .circuit_origin
            .as_ref()
            .map_or(0, |o| o.gc(now_unix));
        // Not a GC result: bindings the per-link ceiling dropped at register
        // time, drained here so they ride the same line. A neighbour holding
        // registry state past its table quota shows up as a non-zero count
        // here and nowhere else.
        let over_link_cap = self
            .dispatcher
            .circuit_rendezvous
            .as_ref()
            .map_or(0, |r| r.take_over_link_cap_evictions());
        if gc_relay + gc_rendezvous + gc_origin > 0 || over_link_cap > 0 {
            // OBSERVABILITY (log-only): an evicted rendezvous binding is the
            // event that later surfaces as introduce.cookie_unknown at this
            // relay; an evicted relay circuit is what turns the NEXT forwarded
            // introduce into a data_unknown_circuit drop on this hop. Name the
            // evictions when they happen instead of leaving them silent.
            log::info!(
                "anonymity.circuit.gc evicted relay_circuits={gc_relay} \
                 rendezvous_bindings={gc_rendezvous} origin_circuits={gc_origin} \
                 over_link_cap={over_link_cap}"
            );
        }

        // Refresh at half the relay-side circuit idle TTL (300 s) → 150 s.
        const REFRESH_SECS: u64 = veil_anonymity::circuit_table::DEFAULT_CIRCUIT_TTL_SECS / 2;
        type DueEntry = (
            u64,
            [u8; 16],
            Vec<[u8; 32]>,
            veil_crypto::GeneratedKeyPair,
            std::sync::Arc<std::sync::atomic::AtomicBool>,
            std::sync::Arc<std::sync::atomic::AtomicU64>,
            Option<std::sync::Arc<zeroize::Zeroizing<[u8; 32]>>>,
            Option<u8>,
        );
        let due: Vec<DueEntry> = {
            let svcs = lock!(self.anonymity.onion_services);
            svcs.iter()
                .filter(|e| now_unix.saturating_sub(e.built_unix) >= REFRESH_SECS)
                .map(|e| {
                    (
                        e.registration,
                        e.cookie,
                        e.relay_path.clone(),
                        e.reg_keypair.clone(),
                        std::sync::Arc::clone(&e.confirmed),
                        std::sync::Arc::clone(&e.registration_epoch),
                        e.descriptor_identity_seed.clone(),
                        e.descriptor_provider_slot,
                    )
                })
                .collect()
        };
        for (
            registration,
            cookie,
            relay_path,
            reg_keypair,
            prev_confirmed,
            registration_epoch,
            descriptor_identity_seed,
            descriptor_provider_slot,
        ) in due
        {
            // Rotate the rendezvous cookie WITH the blinded-descriptor period. The
            // entry was minted under its build-time period, but a long-running node
            // crosses 24h boundaries; keeping one cookie across periods would
            // re-introduce the cross-period relay link that per-period rotation is
            // built to deny. Re-derive for the CURRENT period each tick (seed-derived,
            // STABLE within a period so restarts still match); a random-fallback entry
            // (no sovereign identity) keeps its cookie. Used for BOTH the relay
            // re-registration AND the descriptor re-publish so they cannot diverge;
            // the in-memory entry is re-keyed to the new cookie on a successful build.
            let period_now = veil_anonymity::blinded_descriptor::current_period(now_unix);
            // The registration keypair rotates WITH the cookie's period (they
            // are one derivation now: the cookie IS a function of the key), so
            // re-deriving here keeps the pair the relay holds equal to what a
            // crash-restarted process would derive, and a restart right after a
            // period boundary still lands on the same-key refresh path instead
            // of CookieClaimed. Random-fallback entries (no sovereign identity)
            // keep the keypair and cookie they were minted with — theirs never
            // rotates, and re-minting would be a fresh unrelated service.
            let (reg_keypair, cookie_now) = match descriptor_identity_seed.as_deref() {
                Some(seed) => {
                    Self::onion_reg_pair(Some(seed), period_now, descriptor_provider_slot)
                }
                None => (reg_keypair, cookie),
            };
            // diff-audit Δ2-d: if the terminus never ACK'd the current circuit
            // (CircuitBuilt), its path is suspect — a hop is likely dead. Pick a
            // FRESH path rather than rebuilding the same frozen one. A confirmed
            // circuit keeps its proven-live path. (Build stays optimistic, so a
            // pre-Δ2-d terminus that never ACKs just causes path rotation, never
            // a broken service.)
            let reselect = !prev_confirmed.load(std::sync::atomic::Ordering::Relaxed);
            let path = if reselect {
                match self.select_onion_relay_path(relay_path.len()) {
                    Ok(p) => {
                        self.logger.info(
                            "onion.circuit.reselect",
                            "unconfirmed circuit — re-selecting a fresh relay path",
                        );
                        p
                    }
                    Err(_) => relay_path.clone(), // no fresh path available — retry same
                }
            } else {
                relay_path.clone()
            };
            let built = self.build_onion_circuit_once(
                &path,
                cookie_now,
                &reg_keypair,
                &registration_epoch,
                false, // hosted service rebuild, not a reply circuit
            );
            if let Ok(new_confirmed) = &built {
                // COOKIE-DIAG (periodic re-register): the cookie this node now
                // holds at its relay. Must equal what senders put in introduces.
                log::info!(
                    "rendezvous.cookie.register(periodic): cookie={} period={} me={}",
                    cookie_now
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>(),
                    period_now,
                    veil_util::hex_short(self.identity.local_identity.node_id.as_bytes()),
                );
                let mut svcs = lock!(self.anonymity.onion_services);
                // Locate by registration (a withdrawn-and-re-registered
                // service has the same cookie and is not this entry), then
                // re-key the entry to cookie_now so subsequent ticks track the
                // current period.
                if let Some(e) = svcs.iter_mut().find(|e| e.registration == registration) {
                    let was = e.relay_path.last().map(|r| (*r, e.cookie));
                    e.built_unix = now_unix;
                    e.relay_path = path.clone();
                    e.confirmed = std::sync::Arc::clone(new_confirmed);
                    e.cookie = cookie_now;
                    e.reg_keypair = reg_keypair.clone();
                    // The publisher row follows the entry, in the same step.
                    // A path re-selection or a period boundary changes what
                    // the row is keyed by, and a row left under the old
                    // (relay, cookie) is one `withdraw` can no longer find —
                    // re-signed every tick for a service that is gone
                    // (report20 V18-M5). Same lock order as everywhere else:
                    // services, then publishers.
                    if let (Some(was), Some(&relay_now)) = (was, path.last()) {
                        rekey_publisher_row(
                            &mut lock!(self.anonymity.rendezvous_publisher_entries),
                            was,
                            (relay_now, cookie_now),
                            ephemeral_ad_identity_for(&reg_keypair),
                        );
                    }
                }
            }
            let relay_path = path;
            // Re-publish the blinded descriptor under the CURRENT period so the
            // by-identity send path keeps resolving across period boundaries.
            // register_onion_service seals it only once; the descriptor's DHT key
            // rotates every PERIOD_SECS (24 h), so without this refresh a sender
            // computing the current-period key stops finding it after ~1–2 periods
            // (it only tolerates ±1). REFRESH_SECS (150 s) ≪ the period, so a fresh
            // descriptor is always present under the live key.
            if let Some(&rendezvous) = relay_path.last() {
                let publish_seed = descriptor_identity_seed.clone();
                let publish_slot = descriptor_provider_slot;
                match built {
                    // Same publish-before-register barrier as the initial
                    // registration: at a period boundary `cookie_now` is a
                    // cookie the relay has never seen — publishing it before
                    // the rebuild's CircuitBuilt ACK reopens the race there.
                    Ok(new_confirmed) => {
                        // A service withdrawn while the rebuild's ACK is
                        // outstanding must not be republished. The row was
                        // re-keyed above; only the descriptor is deferred.
                        self.publish_after_circuit_confirmed(
                            registration,
                            new_confirmed,
                            |_: &NodeServices| {},
                            move |this: &NodeServices| {
                                if let Some(seed) = publish_seed.as_deref() {
                                    this.publish_blinded_descriptor_for(
                                        seed,
                                        rendezvous,
                                        cookie_now,
                                        publish_slot,
                                    );
                                }
                            },
                        );
                    }
                    // Build failed: publish immediately, matching the old
                    // "decoupled from the rebuild result" behavior —
                    // discoverability shouldn't hinge on one tick's rebuild
                    // succeeding (the next tick retries in REFRESH_SECS).
                    Err(_) => {
                        if let Some(seed) = publish_seed.as_deref() {
                            self.publish_blinded_descriptor_for(
                                seed,
                                rendezvous,
                                cookie_now,
                                publish_slot,
                            );
                        }
                    }
                }
            }
        }
    }
}
