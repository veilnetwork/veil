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

    /// try NAT traversal toward `target_node_id`
    /// using ANY currently-connected peer as the signaling coordinator.
    /// See `NodeRuntime::try_nat_traversal` for the full doc-comment;
    /// the actual logic lives here on `NodeServices` so the
    /// auto-trigger path (`nat_fallback_dial`) can call it directly
    /// without going through a public-API forwarder.
    pub async fn try_nat_traversal(
        &self,
        target_node_id: [u8; 32],
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        per_coordinator_timeout: std::time::Duration,
    ) -> Option<veil_proto::control::NatProbeReplyPayload> {
        self.try_nat_traversal_with_punch_token(
            target_node_id,
            local_candidates,
            per_coordinator_timeout,
            None,
        )
        .await
    }

    pub(crate) async fn try_nat_traversal_with_punch_token(
        &self,
        target_node_id: [u8; 32],
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        per_coordinator_timeout: std::time::Duration,
        punch_token: Option<[u8; 16]>,
    ) -> Option<veil_proto::control::NatProbeReplyPayload> {
        let local_node_id = *self.identity.local_identity.node_id.as_bytes();
        let mut candidates: Vec<[u8; 32]> = rlock!(self.session_tx_registry)
            .peer_ids()
            .into_iter()
            .filter(|p| *p != local_node_id && *p != target_node_id)
            .collect();
        if candidates.is_empty() {
            return None;
        }
        candidates.sort_by_key(|pid| {
            let mut xor = [0u8; 32];
            for i in 0..32 {
                xor[i] = pid[i] ^ target_node_id[i];
            }
            xor
        });
        const MAX_COORDINATOR_ATTEMPTS: usize = 4;
        // Give up on a target that will not answer. See `nat_probe_backoff`
        // for what this cost in production before it existed.
        if !lock!(self.nat_probe_backoff).allow(target_node_id) {
            self.logger.debug(
                "nat.probe.backoff",
                format!(
                    "target {} is in probe back-off — not asking any coordinator",
                    veil_util::hex_short(&target_node_id),
                ),
            );
            return None;
        }

        for coordinator in candidates.into_iter().take(MAX_COORDINATOR_ATTEMPTS) {
            if let Some(reply) = self
                .attempt_nat_traversal_via_with_punch_token(
                    target_node_id,
                    coordinator,
                    local_candidates.clone(),
                    per_coordinator_timeout,
                    punch_token,
                )
                .await
            {
                // Mixed-version resilience: a coordinator built before the
                // punch-token wire extension decodes-then-re-encodes the
                // frames and strips the token in flight, so the reply comes
                // back without it. Such a reply cannot authenticate a punch —
                // it must not poison the whole attempt while a newer
                // coordinator later in the ladder would preserve the token.
                if punch_token.is_some() && reply.punch_token != punch_token {
                    self.logger.debug(
                        "nat.udp_punch.signaling_no_token",
                        format!(
                            "reply via coordinator {} lacks our punch token \
                             (coordinator or peer build too old?) — trying next",
                            veil_util::hex_short(&coordinator),
                        ),
                    );
                    continue;
                }
                return Some(reply);
            }
        }
        None
    }

    /// signaling driver — see `NodeRuntime::attempt_nat_traversal_via`.
    pub async fn attempt_nat_traversal_via(
        &self,
        target_node_id: [u8; 32],
        coordinator_node_id: [u8; 32],
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        timeout: std::time::Duration,
    ) -> Option<veil_proto::control::NatProbeReplyPayload> {
        self.attempt_nat_traversal_via_with_punch_token(
            target_node_id,
            coordinator_node_id,
            local_candidates,
            timeout,
            None,
        )
        .await
    }

    pub(crate) async fn attempt_nat_traversal_via_with_punch_token(
        &self,
        target_node_id: [u8; 32],
        coordinator_node_id: [u8; 32],
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        timeout: std::time::Duration,
        punch_token: Option<[u8; 16]>,
    ) -> Option<veil_proto::control::NatProbeReplyPayload> {
        use veil_proto::codec::encode_header;
        use veil_proto::control::NatProbeRequestPayload;
        use veil_proto::family::{ControlMsg, FrameFamily};
        use veil_proto::header::{FrameHeader, HEADER_SIZE};

        let local_node_id = *self.identity.local_identity.node_id.as_bytes();

        let (tx, rx) = tokio::sync::oneshot::channel::<veil_proto::control::NatProbeReplyPayload>();
        // oncurrency-allocate a session_token
        // that does not collide with any in-flight waiter. Without
        // this, two concurrent NAT-probe requests landing on the same
        // u32 random value silently overwrite each other in
        // `nat_probe_waiters` — the prior requester's `tx` is dropped
        // and they time out without diagnostic. Birthday-bound at
        // u32 means ~65K concurrent waiters before 50% collision risk;
        // production-class relays can hit that under sustained load.
        // The retry loop is bounded — at MAX_NAT_PROBE_WAITERS we
        // refuse the request rather than spin forever.
        let session_token: u32 = {
            use rand_core::RngCore;
            use veil_proto::budget::MAX_NAT_PROBE_WAITERS;
            let mut waiters = lock!(self.dispatcher.nat_probe_waiters);
            waiters.retain(|_, sender| !sender.is_closed());
            if waiters.len() >= MAX_NAT_PROBE_WAITERS {
                return None;
            }
            // Try a random value; on the off chance of a collision
            // re-roll up to MAX_NAT_PROBE_WAITERS times (the cap above
            // means at least one slot is free, so we WILL find one).
            let mut tok = rand_core::OsRng.next_u32();
            for _ in 0..MAX_NAT_PROBE_WAITERS {
                if !waiters.contains_key(&tok) {
                    break;
                }
                tok = rand_core::OsRng.next_u32();
            }
            waiters.insert(tok, tx);
            tok
        };

        let request = NatProbeRequestPayload {
            initiator_node_id: local_node_id,
            target_node_id,
            session_token,
            punch_token,
            candidates: local_candidates,
        };
        let body = request.encode();
        let mut hdr = FrameHeader::new(
            FrameFamily::Control as u8,
            ControlMsg::NatProbeRequest as u16,
        );
        hdr.body_len = body.len() as u32;
        let mut frame = Vec::with_capacity(HEADER_SIZE + body.len());
        frame.extend_from_slice(&encode_header(&hdr));
        frame.extend_from_slice(&body);

        {
            let guard = rlock!(self.session_tx_registry);
            if !guard.send_to(
                &coordinator_node_id,
                veil_proto::header::priority::INTERACTIVE,
                frame,
            ) {
                lock!(self.dispatcher.nat_probe_waiters).remove(&session_token);
                return None;
            }
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(reply)) => Some(reply),
            _ => {
                lock!(self.dispatcher.nat_probe_waiters).remove(&session_token);
                None
            }
        }
    }

    /// Collect live reflector announcements from authenticated direct peers,
    /// nearest to the intended destination first. Static config entries are
    /// appended only as a backward-compatible fallback. A peer's own endpoint
    /// is bound to its transport IP; transitively shared endpoints are numeric,
    /// public-only and bounded before they enter this map.
    pub(crate) fn available_udp_reflectors(
        &self,
        target_node_id: [u8; 32],
        configured: &[String],
    ) -> Vec<std::net::SocketAddr> {
        let mut announced = rlock!(self.dispatcher.peer_udp_reflectors)
            .iter()
            .map(|(node_id, endpoints)| (*node_id, endpoints.clone()))
            .collect::<Vec<_>>();
        announced.sort_by_key(|(node_id, _)| {
            let mut distance = [0u8; 32];
            for i in 0..32 {
                distance[i] = node_id[i] ^ target_node_id[i];
            }
            distance
        });

        let mut out = Vec::with_capacity(8);
        // Round-robin across independent announcers before accepting a second
        // endpoint from one peer, so one connected peer cannot eclipse every
        // other live reflector by filling the eight-entry fan-out.
        for index in 0..4 {
            for (_, endpoints) in &announced {
                let Some(endpoint) = endpoints.get(index).copied() else {
                    continue;
                };
                if !out.contains(&endpoint) {
                    out.push(endpoint);
                }
                if out.len() == 8 {
                    return out;
                }
            }
        }
        for endpoint in configured
            .iter()
            .filter_map(|value| value.parse::<std::net::SocketAddr>().ok())
        {
            if !out.contains(&endpoint) {
                out.push(endpoint);
            }
            if out.len() == 8 {
                break;
            }
        }
        out
    }

    /// signaling + URI promotion — see
    /// `NodeRuntime::try_nat_traversal_promote_uris`.
    pub async fn try_nat_traversal_promote_uris(
        &self,
        target_node_id: [u8; 32],
        template_uri: &veil_transport::TransportUri,
        local_candidates: Vec<veil_proto::control::NatCandidate>,
        per_coordinator_timeout: std::time::Duration,
    ) -> Vec<veil_transport::TransportUri> {
        let Some(reply) = self
            .try_nat_traversal(target_node_id, local_candidates, per_coordinator_timeout)
            .await
        else {
            return Vec::new();
        };
        let mut sorted = reply.candidates;
        sorted.sort_by_key(|c| std::cmp::Reverse(c.priority));
        sorted
            .iter()
            .filter_map(|c| nat_candidate_to_transport_uri(c, template_uri))
            .collect()
    }

    /// drive NAT-traversal signaling on the
    /// initiator side and try each promoted candidate URI as a real
    /// transport dial. Returns `Some(connection)` on the first
    /// success, `None` if signaling fails or every candidate fails to
    /// dial. Cheap-bail conditions (no connected peers / unsupported
    /// URI variant) are checked before signaling so we don't waste a
    /// 5-second round-trip on a doomed attempt.
    ///
    /// Why this lives in `NodeServices` and not inline in
    /// `connect_peer_with_state`:
    /// * Encapsulates the policy (timeout, candidate cap
    ///   coordinator-availability check) in one place so it's
    ///   reviewable + tunable independently of the dial state
    ///   machine.
    /// * Lets future tests stub it out via the runtime's existing
    ///   debug accessors if needed.
    ///
    /// Per-attempt timeout: signaling is bounded at 3s (
    /// auto-coordinator default); each candidate dial is bounded
    /// implicitly by the registry's own connect timeout — we don't
    /// add a second layer. Total worst-case latency for the
    /// fallback path is ~3s + (N candidates × per-dial timeout)
    /// which sits inside the outbound-connector's exponential-
    /// backoff loop without blowing past its `backoff_max`.
    ///
    /// Candidate cap: at most 4 promoted URIs are attempted, in RFC
    /// 8445 priority order (host → srflx → relay). Without a cap a
    /// peer that advertises 50 host candidates (e.g., a server with
    /// many interfaces) would burn the full backoff window on
    /// fallback attempts and starve the next real backoff cycle.
    async fn udp_hole_punch_dial(
        &self,
        target_node_id: [u8; 32],
        peer_ctx: Arc<veil_transport::TransportContext>,
    ) -> Option<Box<dyn TransportConnection>> {
        let config = veil_cfg::load_config(&self.config_path).ok()?;
        let budget = std::time::Duration::from_millis(config.nat.punch_timeout_ms);
        if budget.is_zero() {
            return None;
        }
        self.udp_hole_punch_dial_stages(target_node_id, peer_ctx, &config, budget)
            .await
            .ok()
    }

    /// Staged core of the initiator-side UDP hole punch. Same orchestration
    /// as the historical `udp_hole_punch_dial`, but every early exit names
    /// the stage that ended the attempt so the explicit call-path API
    /// (`attempt_p2p_hole_punch`) can surface a structured outcome instead
    /// of a bare miss. Strict stage order: reflector selection → mapping
    /// discovery → coordinator signaling (candidate + one-time punch token)
    /// → simultaneous punch → same-socket QUIC promotion.
    async fn udp_hole_punch_dial_stages(
        &self,
        target_node_id: [u8; 32],
        peer_ctx: Arc<veil_transport::TransportContext>,
        config: &veil_cfg::Config,
        budget: std::time::Duration,
    ) -> std::result::Result<Box<dyn TransportConnection>, HolePunchDialFailure> {
        if !config.nat.enabled {
            return Err(HolePunchDialFailure::NoReflector);
        }
        let mut reflectors =
            self.available_udp_reflectors(target_node_id, &config.nat.udp_reflectors);
        let Some(first_reflector) = reflectors.first().copied() else {
            return Err(HolePunchDialFailure::NoReflector);
        };
        reflectors.retain(|value| value.is_ipv4() == first_reflector.is_ipv4());
        if budget.is_zero() {
            return Err(HolePunchDialFailure::PunchTimeout);
        }
        let deadline = tokio::time::Instant::now() + budget;
        let bind_addr = match first_reflector {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };
        let socket = tokio::net::UdpSocket::bind(bind_addr)
            .await
            .map_err(|_| HolePunchDialFailure::MappingUnusable)?;
        veil_util::outbound_interface::configure_outbound_socket(
            &socket,
            if first_reflector.is_ipv4() {
                veil_util::outbound_interface::SocketFamilies::V4
            } else {
                veil_util::outbound_interface::SocketFamilies::V6
            },
        )
        .map_err(|_| HolePunchDialFailure::MappingUnusable)?;
        let (discovery_token, punch_token) = {
            use rand_core::RngCore;
            let mut discovery = [0u8; 16];
            let mut punch = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut discovery);
            rand_core::OsRng.fill_bytes(&mut punch);
            (discovery, punch)
        };
        let discovery_timeout = budget.min(std::time::Duration::from_millis(500));
        let mapping = veil_nat::discover_udp_mapping_any_for_punch(
            &socket,
            &reflectors,
            discovery_token,
            discovery_timeout,
        )
        .await
        // An I/O error here means no reflector was even sendable — a
        // reflector-availability failure, not a mapping verdict.
        .map_err(|_| HolePunchDialFailure::NoReflector)?;
        let Some((mapping, _)) = mapping else {
            self.logger.debug(
                "nat.udp_punch.discovery_unusable",
                "no non-hairpin UDP mapping from peer-announced reflectors",
            );
            return Err(HolePunchDialFailure::MappingUnusable);
        };
        let mut candidate = veil_nat::socket_addr_to_candidate(mapping);
        candidate.candidate_type = veil_proto::control::candidate_type::SRFLX;
        candidate.priority = 1_694_498_815;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(HolePunchDialFailure::SignalingTimeout);
        }
        let signaling_timeout = remaining.min(std::time::Duration::from_millis(1_500));
        let reply = self
            .try_nat_traversal_with_punch_token(
                target_node_id,
                vec![candidate],
                signaling_timeout,
                Some(punch_token),
            )
            .await
            .ok_or(HolePunchDialFailure::SignalingTimeout)?;
        if reply.punch_token != Some(punch_token) {
            // Reply came back without our one-time token — an older peer
            // build that cannot run the punch responder. Signaling-stage
            // failure; the log carries the precise cause.
            self.logger.debug(
                "nat.udp_punch.signaling_no_token",
                "NAT probe reply lacks our punch token (peer build too old?)",
            );
            return Err(HolePunchDialFailure::SignalingTimeout);
        }
        let candidates = reply
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.candidate_type == veil_proto::control::candidate_type::SRFLX
            })
            .filter_map(veil_nat::candidate_to_socket_addr)
            .filter(|candidate| veil_nat::is_public_punch_addr(*candidate))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            // The peer answered but could not offer any public
            // server-reflexive candidate — its mapping is unusable, so a
            // punch can never converge. Distinct from our own mapping
            // failure only in the log line.
            self.logger.debug(
                "nat.udp_punch.peer_mapping_unusable",
                "peer reply carried no public srflx candidate",
            );
            return Err(HolePunchDialFailure::MappingUnusable);
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        // Reserve up to 750 ms (and at least half this remaining slice) for
        // QUIC so a doomed punch cannot consume the entire direct-path budget.
        let quic_reserve = (remaining / 2).min(std::time::Duration::from_millis(750));
        let punch_timeout = remaining.saturating_sub(quic_reserve);
        if punch_timeout.is_zero() {
            return Err(HolePunchDialFailure::PunchTimeout);
        }
        // The punch is bound to this node's veil, so a peer on a different
        // deployment cannot converge with us and be promoted into a session.
        let network_tag = veil_nat::network_tag(self.transport_ctx.obfs4_psk.as_deref());
        let punched = veil_nat::punch_udp(
            &socket,
            &candidates,
            punch_token,
            &network_tag,
            punch_timeout,
        )
        .await
        .unwrap_or_default();
        if punched.peer.is_none() && punched.foreign_tokens > 0 {
            // A cross-veil punch fails by timing out, exactly like a NAT that
            // never opened. Say which one it was.
            self.logger.debug(
                "nat.udp_punch.foreign_network",
                format!(
                    "{} punch packet(s) carried a token from another veil",
                    punched.foreign_tokens
                ),
            );
        }
        let peer = punched.peer.ok_or(HolePunchDialFailure::PunchTimeout)?;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(HolePunchDialFailure::PunchTimeout);
        }
        let promoted = tokio::time::timeout(
            remaining,
            veil_transport::promote_punched_quic(
                socket,
                peer,
                peer_ctx,
                veil_transport::PunchedQuicRole::Initiator,
            ),
        )
        .await;
        match promoted {
            Ok(Ok(connection)) => {
                self.logger.info(
                    "nat.udp_punch.connected",
                    format!(
                        "peer={} role=initiator",
                        veil_util::hex_short(&target_node_id)
                    ),
                );
                Ok(connection)
            }
            Ok(Err(error)) => {
                self.logger
                    .warn("nat.udp_punch.quic_failed", error.to_string());
                Err(HolePunchDialFailure::QuicFailed)
            }
            Err(_) => {
                self.logger.warn(
                    "nat.udp_punch.quic_failed",
                    "overall NAT traversal deadline elapsed",
                );
                Err(HolePunchDialFailure::QuicFailed)
            }
        }
    }

    /// Explicit, bounded call-path hole-punch attempt toward a registered
    /// peer (real-P2P epic, Stage B; exposed over IPC as
    /// `LocalAppMsg::AttemptHolePunch`).
    ///
    /// Contract (mirrors [`veil_ipc::HolePunchDriver`]):
    /// * **Anonymity posture never enters this path** — a node booted with
    ///   `[anonymity].onion_service` refuses immediately
    ///   ([`veil_ipc::HolePunchOutcome::RefusedAnonymous`]) before any
    ///   socket, reflector, or signaling side effect.
    /// * **Idempotent** — an existing live direct session short-circuits to
    ///   `Connected` without network work; a repeat call after a successful
    ///   punch takes the same short-circuit.
    /// * **Single-flight per peer** — a call that finds an attempt already
    ///   in flight subscribes to its outcome instead of racing a second
    ///   socket/punch toward the same peer.
    /// * **One shared budget** ([`veil_proto::budget::
    ///   HOLE_PUNCH_ATTEMPT_BUDGET_MS`], 5 s) covers every stage including
    ///   the session handshake on the punched QUIC connection.
    ///
    /// On `Connected` the punched session is registered through the normal
    /// outbound path (`register_connection_session` + session runner), so
    /// `peer_pnet_status().admitted` flips the standard way and REALTIME
    /// media rides the session's QUIC DATAGRAM lane exactly like any other
    /// admitted direct QUIC session.
    pub async fn attempt_p2p_hole_punch(
        &self,
        peer_node_id: [u8; 32],
    ) -> veil_ipc::HolePunchOutcome {
        use veil_ipc::HolePunchOutcome as Outcome;
        // Anonymity gate FIRST: `onion_service_hops` is `Some` iff the node
        // was booted with `[anonymity].onion_service = true` (pinned at
        // boot; reloads cannot flip it), which is exactly the posture whose
        // real external address must never be disclosed by a punch.
        if self.anonymity.onion_service_hops.is_some() {
            self.logger.debug(
                "nat.udp_punch.refused_anonymous",
                format!(
                    "explicit punch refused under onion-service posture peer={}",
                    veil_util::hex_short(&peer_node_id)
                ),
            );
            return Outcome::RefusedAnonymous;
        }
        // Idempotent short-circuit: a live direct session already exists
        // (same registry signal `PnetStatusProvider` derives `admitted`
        // from — sessions appear there only after a completed handshake).
        if self.has_live_session(&peer_node_id) {
            return Outcome::Connected;
        }
        // Single-flight: either claim the peer's slot (initiator) or join
        // the attempt already in flight. The map lock is confined to this
        // block — never held across an await.
        enum Flight {
            Join(tokio::sync::broadcast::Receiver<veil_ipc::HolePunchOutcome>),
            Run(HolePunchInflightGuard),
        }
        let flight = {
            let mut inflight = lock!(self.hole_punch_inflight);
            match inflight.get(&peer_node_id) {
                Some(tx) => Flight::Join(tx.subscribe()),
                None => {
                    let (tx, _rx) = tokio::sync::broadcast::channel(1);
                    inflight.insert(peer_node_id, tx.clone());
                    Flight::Run(HolePunchInflightGuard {
                        map: Arc::clone(&self.hole_punch_inflight),
                        peer_node_id,
                        tx,
                        outcome: None,
                    })
                }
            }
        };
        match flight {
            Flight::Join(mut rx) => match rx.recv().await {
                Ok(outcome) => outcome,
                // Initiator dropped without broadcasting: the drop-guard
                // normally sends PunchTimeout, so this arm is
                // belt-and-braces for a torn-down runtime.
                Err(_) => Outcome::PunchTimeout,
            },
            Flight::Run(mut guard) => {
                let outcome = self.attempt_p2p_hole_punch_run(peer_node_id).await;
                guard.outcome = Some(outcome);
                drop(guard); // releases the slot + broadcasts to joiners
                outcome
            }
        }
    }

    /// Number of exclusive punch attempts started through this
    /// `NodeServices` (single-flight joiners do not count). Test hook for
    /// asserting that a concurrent second call joined instead of starting
    /// a second punch.
    pub fn hole_punch_run_count(&self) -> u64 {
        self.hole_punch_run_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The staged body of one exclusive (slot-holding) punch attempt.
    async fn attempt_p2p_hole_punch_run(
        &self,
        peer_node_id: [u8; 32],
    ) -> veil_ipc::HolePunchOutcome {
        use veil_ipc::HolePunchOutcome as Outcome;
        self.hole_punch_run_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let budget =
            std::time::Duration::from_millis(veil_proto::budget::HOLE_PUNCH_ATTEMPT_BUDGET_MS);
        let deadline = tokio::time::Instant::now() + budget;
        // The target must be a registered peer: endpoint exchange
        // (bootstrap join) both authenticates the pubkey/nonce we hand to
        // the QUIC context below and bounds who can make this node punch.
        let Some(peer) = lock_state(&self.state)
            .peers
            .values()
            .find(|entry| entry.node_id.as_bytes() == &peer_node_id)
            .cloned()
        else {
            return Outcome::UnknownPeer;
        };
        let config = match veil_cfg::load_config(&self.config_path) {
            Ok(config) => config,
            Err(error) => {
                self.logger.warn(
                    "nat.udp_punch.config_unavailable",
                    format!("explicit punch cannot load config: {error}"),
                );
                return Outcome::ConfigUnavailable;
            }
        };
        let peer_ctx = match peer_transport_context(&self.transport_ctx, &peer) {
            Ok(ctx) => Arc::new(ctx),
            Err(error) => {
                self.logger.warn(
                    "nat.udp_punch.peer_ctx_failed",
                    format!("peer={} error={error}", peer.peer_id),
                );
                return Outcome::QuicFailed;
            }
        };
        // Reserve a slice of the shared budget for the OVL1 handshake on
        // the punched connection so a slow punch cannot leave registration
        // with a zero deadline.
        const HANDSHAKE_RESERVE: std::time::Duration = std::time::Duration::from_millis(1_000);
        let dial_budget = budget.saturating_sub(HANDSHAKE_RESERVE);
        let connection = match self
            .udp_hole_punch_dial_stages(peer_node_id, peer_ctx, &config, dial_budget)
            .await
        {
            Ok(connection) => connection,
            Err(failure) => return failure.into(),
        };
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let session_ctx = self.make_session_context();
        if let Some(metrics) = &session_ctx.metrics {
            metrics.inc_outbound_connect_attempts();
        }
        // E20: a punched dial is a one-sided no-glare recovery dial — the
        // primary URI was undialable and the peer is not reciprocally
        // dialing this exact socket — so bypass directional dedup like the
        // other NAT-traversal recovery paths.
        let registered = tokio::time::timeout(
            remaining,
            register_connection_session(
                session_ctx,
                SessionSource::Outbound(peer.peer_id),
                Some(ExpectedPeerIdentity {
                    peer_id: peer.peer_id,
                    public_key: peer.public_key.clone(),
                    node_id: peer.node_id,
                    nonce: peer.nonce.clone(),
                    row_transport_at_dial: peer.transport.clone(),
                }),
                None,
                SessionState::Active,
                connection,
                true,
            ),
        )
        .await;
        match registered {
            Ok(Ok(Some(session))) => {
                self.logger.info(
                    "nat.udp_punch.session_registered",
                    format!("peer={} via=explicit_call_path", peer.peer_id),
                );
                self.spawn_punched_outbound(session, &peer);
                Outcome::Connected
            }
            Ok(Ok(None)) => {
                // Handoff-binding is an inbound-only branch; reaching it on
                // an outbound register would be a runtime bug. Surface as
                // the QUIC/session stage failing rather than lying about
                // success.
                self.logger.warn(
                    "nat.udp_punch.session_register_anomaly",
                    "outbound punched register returned handoff-bound (impossible)",
                );
                Outcome::QuicFailed
            }
            Ok(Err(error)) => {
                self.logger.warn(
                    "nat.udp_punch.session_register_failed",
                    format!("peer={} error={error}", peer.peer_id),
                );
                Outcome::QuicFailed
            }
            Err(_) => {
                self.logger.warn(
                    "nat.udp_punch.session_register_failed",
                    "punched session handshake exceeded the attempt budget",
                );
                Outcome::QuicFailed
            }
        }
    }

    /// Spawn the session runner for an initiator-side punched session —
    /// the outbound analog of [`Self::spawn_punched_inbound`]. Mirrors the
    /// outbound-connector runner wiring minus the connector-loop concerns
    /// (no gateway ATTACH/keepalive, no bootstrap FIND_NODE burst) and
    /// with `primary_uri: None`: the punched mapping is ephemeral, so
    /// rotation/handoff must not try to re-dial it — recovery of a dead
    /// punched session belongs to the standard outbound connector via the
    /// SessionGuard refresh bump (mobility slice).
    fn spawn_punched_outbound(
        &self,
        session: AttachedDebugSession,
        peer: &crate::types::PeerConfigEntry,
    ) {
        let access = self.clone();
        let peer = peer.clone();
        let handle = tokio::spawn(async move {
            let dispatcher = Arc::clone(&access.dispatcher);
            let ban_list = Arc::clone(&dispatcher.abuse.ban_list);
            let violation_tracker = Arc::clone(&dispatcher.abuse.violation_tracker);
            let (tx_cipher, rx_cipher, session_id, raw_tx_key, raw_rx_key) = {
                let keys = session.session_keys;
                let tx = keys.tx_key;
                let rx = keys.rx_key;
                (
                    Some(veil_crypto::session_cipher::SessionCipher::new(&tx, true)),
                    Some(veil_crypto::session_cipher::SessionCipher::new(&rx, true)),
                    keys.session_id,
                    tx,
                    rx,
                )
            };
            let peer_id = session.peer_id;
            let outbox_rx = session.reserved_outbox_rx;
            let rpc_rx = access.session_outbox.register_owned(peer_id, session_id);
            let mut runner = veil_session::runner::SessionRunner {
                stream: session.stream,
                quic_datagrams: session.quic_datagrams,
                peer_id: *peer_id.as_bytes(),
                dispatcher,
                logger: Arc::clone(&access.logger),
                metrics: access.metrics.clone(),
                ban_list,
                violation_tracker,
                crypto: veil_session::runner::CryptoState {
                    tx_cipher,
                    rx_cipher,
                    peer_mlkem_keys: Some(Arc::clone(&access.identity.peer_mlkem_keys)),
                    per_session_mlkem_dk: Some(Arc::clone(&access.identity.per_session_mlkem_dk)),
                },
                outbox: Some(outbox_rx),
                rpc_outbox: Some(rpc_rx),
                keepalive_interval: access.defaults.keepalive_interval,
                idle_timeout: access.defaults.idle_timeout,
                max_pending_responses: access.defaults.max_pending_responses,
                pending_response_ttl: access.defaults.pending_response_ttl,
                max_frame_body: access.defaults.max_frame_body,
                rekey: veil_session::runner::RekeyConfig {
                    bytes_threshold: access.defaults.rekey_bytes_threshold,
                    time_threshold_secs: access.defaults.rekey_time_threshold_secs,
                },
                qos_weights: access.defaults.qos_weights,
                session_id,
                local_node_id: access.local_node_id,
                mobile: veil_session::runner::MobileConfig {
                    base_keepalive_interval: access.defaults.keepalive_interval,
                    battery_keepalive_scale_low: access.mobile.battery_keepalive_scale_low,
                    battery_keepalive_scale_medium: access.mobile.battery_keepalive_scale_medium,
                    battery_threshold_low: access.mobile.battery_threshold_low,
                    battery_threshold_medium: access.mobile.battery_threshold_medium,
                },
                // Client role — the responder issues the ticket; we store it.
                ticket_to_send: None,
                peer_tickets: Some(Arc::clone(&access.resumption.peer_tickets)),
                raw_session_keys: Some((raw_tx_key, raw_rx_key, session_id)),
                peer_public_key: Some(session.public_key.clone()),
                peer_nonce: Some(session.nonce.clone()),
                hot_standby: veil_session::runner::HotStandbyState {
                    swap_registry: None,
                    swap_rx: None,
                    handoff_registry: Some(Arc::clone(&access.handoff.registry)),
                    handoff_ack_waiters: Some(Arc::clone(&access.handoff.ack_waiters)),
                    controller: Some(Arc::clone(&access.handoff.controller)),
                    auto_trigger_after_write_errors: access.handoff.auto_trigger_after_write_errors,
                },
                primary_uri: None,
            };
            // Same post-handshake bookkeeping as the outbound connector: the
            // peer joins the DHT routing table (proved key ownership), the
            // dispatcher learns the session + reflector advertisements, and
            // the mobility-slice connectivity-gain hook fires (an outbound
            // handshake completing is fresh evidence of working egress).
            access
                .dht
                .add_contact_trusted(veil_dht::routing::Contact::from_handshake(
                    *peer.node_id.as_bytes(),
                    &peer.transport,
                    session
                        .remote_caps_stated
                        .then_some((session.remote_discovery_mode, session.remote_dht_service)),
                ));
            let _ = access
                .dht
                .promote_contact_if_pending(peer.node_id.as_bytes());
            access.dispatcher.on_session_opened(
                *peer_id.as_bytes(),
                session.observed_addr,
                session.udp_reflector_port,
                &session.shared_udp_reflectors,
            );
            access.connectivity_gain.on_outbound_session_established();
            crate::runtime::send_local_announcement(
                &access.dht,
                &access.session_outbox,
                *peer_id.as_bytes(),
            );
            access
                .session_tx_registry
                .write()
                .unwrap_or_else(|p| p.into_inner())
                .send_to(
                    peer_id.as_bytes(),
                    veil_proto::priority::INTERACTIVE,
                    crate::outbound_connector::build_startup_route_probe_frame(),
                );
            let _swap_guard = runner.register_swap_channel(&access.handoff.swap_registry);
            runner.run().await;
            drop(_swap_guard);
            // Owner-aware teardown — same contract as the inbound path:
            // never tear down peer-wide state a reconnect now owns. This
            // path also used to notify the dispatcher BEFORE unregistering
            // the tx channel, the ordering the inbound path fixed long ago.
            session_guard::release_session(
                session_guard::SessionRelease {
                    session_tx_registry: &access.session_tx_registry,
                    session_outbox: &access.session_outbox,
                    session_close_generations: &access.session_close_generations,
                    identity: &access.identity,
                    dispatcher: &access.dispatcher,
                    logger: &access.logger,
                },
                peer_id,
                &session_id,
                // Outbound sessions are never capacity-referral.
                false,
            );
            let _ = runner.stream.shutdown().await;
        });
        push_session_handle(&self.tasks, handle);
    }

    async fn nat_fallback_dial(
        &self,
        peer: &crate::types::PeerConfigEntry,
        primary_uri: &TransportUri,
        peer_ctx: Arc<veil_transport::TransportContext>,
    ) -> Option<Box<dyn TransportConnection>> {
        // Cheap-bail #1: primary URI scheme must be promotable. No
        // point running signaling to learn the peer's IP if we can't
        // build a connectable URI from it (`with_host_port` returns
        // None for Unix/Socks/Ws*).
        primary_uri.with_host_port("0.0.0.0".into(), 0)?;

        // Cheap-bail #2: signaling needs at least one connected peer
        // to act as a coordinator. `try_nat_traversal` would also
        // return None in this case, but going through the full path
        // for an inevitable miss wastes log lines.
        let connected_peer_count = rlock!(self.session_tx_registry).peer_ids().len();
        if connected_peer_count == 0 {
            return None;
        }

        if let Some(connection) = self
            .udp_hole_punch_dial(*peer.node_id.as_bytes(), Arc::clone(&peer_ctx))
            .await
        {
            return Some(connection);
        }

        // Build our own host candidates from the dispatcher's known
        // listen transports (same source-of-truth used by the
        // dispatcher's echo-bugfix path so the wire is
        // symmetric).
        let local_candidates = veil_dispatcher::build_own_host_candidates(
            &self
                .dispatcher
                .listen_transports
                .read()
                .unwrap_or_else(|p| p.into_inner()),
        );

        let promoted = self
            .try_nat_traversal_promote_uris(
                *peer.node_id.as_bytes(),
                primary_uri,
                local_candidates,
                std::time::Duration::from_secs(3),
            )
            .await;
        if promoted.is_empty() {
            return None;
        }

        const MAX_FALLBACK_DIAL_ATTEMPTS: usize = 4;
        for candidate_uri in promoted.into_iter().take(MAX_FALLBACK_DIAL_ATTEMPTS) {
            match self
                .registry
                .connect(&candidate_uri, Arc::clone(&peer_ctx))
                .await
            {
                Ok(connection) => return Some(connection),
                Err(_) => continue, // try next candidate
            }
        }
        None
    }

    /// Anti-censorship: wrap a failed-direct dial through an operator-
    /// configured SOCKS proxy (typically local Tor on
    /// `socks5://127.0.0.1:9050`).  Closes #22/#23/#27 partially —
    /// Tor's exit nodes are in diverse ASes by design, so an AS-level
    /// block on the operator's host is bypassed via the proxy hop.
    ///
    /// Returns `None` if:
    /// * `transport.outbound_socks_fallback_proxy` is unset (default —
    ///   feature opt-in)
    /// * the primary URI's scheme cannot be wrapped in SOCKS
    ///   (`Self::Quic`, `Self::Unix`, etc. — SOCKS5 is a TCP-only
    ///   transport)
    /// * the proxy URL is unparseable as a SOCKS URI
    /// * the proxy itself fails to connect (logged, returns None)
    async fn socks_fallback_dial(
        &self,
        primary_uri: &TransportUri,
        peer_ctx: Arc<veil_transport::TransportContext>,
    ) -> Option<Box<dyn TransportConnection>> {
        let proxy_str = peer_ctx.outbound_socks_fallback_proxy.as_ref()?;
        let (proxy_host, proxy_port, target_host, target_port) =
            crate::socks_fallback::compose_socks_fallback(proxy_str, primary_uri)?;

        // Construct a `socks://<proxy>/<target_host>:<target_port>`
        // URI and dial via the existing SOCKS transport.
        let socks_uri_str = format!(
            "socks://{}:{}/{}:{}",
            proxy_host, proxy_port, target_host, target_port,
        );
        let socks_uri = TransportUri::parse(&socks_uri_str).ok()?;

        self.logger.info(
            "peer.connect.socks_fallback_dial",
            format!(
                "primary={} proxy={proxy_host}:{proxy_port}",
                veil_util::redact_addr_for_log(&primary_uri.to_string()),
            ),
        );

        match self.registry.connect(&socks_uri, peer_ctx).await {
            Ok(connection) => Some(connection),
            Err(e) => {
                self.logger.warn(
                    "peer.connect.socks_fallback_failed",
                    format!("proxy={proxy_host}:{proxy_port} error={e}"),
                );
                None
            }
        }
    }

    fn make_session_context(&self) -> SessionRuntimeContext {
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
    fn build_onion_circuit_once(
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

        let ads = service_tasks::resolve_fresh_rendezvous_ads(
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
    fn onion_reg_pair(
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

    /// Build + enqueue one `RelayChain::<msg>` control frame to `peer`'s session.
    fn send_relay_chain_frame(
        &self,
        peer: &[u8; 32],
        msg: veil_proto::family::RelayChainMsg,
        body: &[u8],
    ) -> std::result::Result<(), veil_session::SendToError> {
        use veil_proto::{codec::encode_header, family::FrameFamily, header::FrameHeader};
        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, msg as u16);
        hdr.body_len = body.len() as u32;
        hdr.set_priority(veil_proto::priority::INTERACTIVE);
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(body);
        let guard = wlock!(self.session_tx_registry);
        guard.send_to_result(peer, veil_proto::priority::INTERACTIVE, frame)
    }

    /// Authenticated rendezvous send (Epic 482 v1, "any recipient"): like
    /// [`send_via_rendezvous`] but the sealed payload is a per-message Ed25519/
    /// Falcon-signed [`veil_proto::AuthAppDeliver`], so the recipient
    /// cryptographically verifies WHO sent it. A signed message rarely fits one
    /// onion cell, so it is sign-whole-then-fragmented across multiple
    /// introduces (`AuthDeliverFragment`); the recipient reassembles + verifies
    /// once. Requires a loaded sovereign identity. One-way (sender → recipient).
    #[allow(clippy::too_many_arguments)]
    pub async fn send_via_rendezvous_authenticated(
        &self,
        ad: &veil_anonymity::rendezvous::RendezvousAd,
        // Additional DISTINCT-relay ads for the SAME recipient (it registered on
        // several rendezvous relays). When non-empty, fragments are ROUND-ROBINED
        // across `[ad] + these` — independent endpoint relays carry different
        // fragments, so the recipient's aggregate receive throughput scales with
        // the relay count instead of funneling `redundancy` copies of every
        // fragment through ONE relay. Empty → the classic single-relay path with
        // `redundancy` retransmit. No new exposure: the recipient already
        // registered the SAME cookie at each of these relays.
        extra_relays: &[veil_anonymity::rendezvous::RendezvousAd],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        data: &[u8],
        hop_count: usize,
        // When `Some((reply_app_id, reply_endpoint_id))`, attach a one-time
        // reply block so the recipient can reply WITHOUT us publishing a public
        // ad (presence-leak mitigation): we register R-locally with a rendezvous
        // relay under a fresh cookie and embed the sealed reply path.
        reply: Option<([u8; 32], u32)>,
        // Send each fragment this many times over independent circuits (bounded
        // retransmit). The recipient's fragment reassembler de-dups by
        // `(msg_id, frag_idx)`, so duplicates collapse → exactly-once delivery at
        // higher odds. 1 = no redundancy (forward sends); >1 for fire-and-forget
        // replies that have no end-to-end ack.
        redundancy: usize,
        // True for a circuit-backed / location-anonymous recipient: the introduce
        // cleartext receiver_node_id is replaced by a cookie-derived pseudo-id so
        // R cannot learn the recipient's transport node_id (L3). The AuthDeliver
        // signature below still binds the REAL `ad.receiver_node_id`.
        circuit_backed: bool,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        use rand_core::RngCore;
        use veil_anonymity::rendezvous::final_hop_kind;

        let sovereign = self
            .identity
            .sovereign_identity
            .get()
            .ok_or(veil_anonymity::sender::SenderError::MissingSenderIdentity)?;

        const REPLY_CIRCUIT_HOPS: usize = 2;
        // Optionally set up an ephemeral reply path (no public ad). diff-audit
        // S4: we PREPARE the reply block (select the relay path + cookie) here so
        // its bytes are included in the size validation below, but DEFER actually
        // building the onion circuit (which registers a cookie at R_a) until
        // AFTER all the PayloadTooLarge / fragment-budget checks pass — otherwise
        // a late size failure would strand the ephemeral circuit + its R_a
        // registration to expire on idle-GC.
        let (reply_block, pending_reply_circuit) = match reply {
            Some((reply_app_id, reply_endpoint_id)) => {
                // We must own the anonymity key to unseal the eventual reply —
                // i.e. be receive-capable (`receive_anonymous`/`relay_capable`).
                let x25519_pk = match self.dispatcher.anonymity_x25519_sk.as_ref() {
                    Some(sk) => x25519_dalek::PublicKey::from(sk.as_ref()).to_bytes(),
                    None => {
                        return Err(veil_anonymity::sender::SenderError::MissingReplyCapability);
                    }
                };
                // The reply cookie will be registered over an ONION CIRCUIT to
                // R_a (not a direct session), so R_a never learns OUR location
                // either (1c). No ad is published: the signed reply block IS the
                // private descriptor sent to the replier. Ephemeral (build-once,
                // no maintenance entry) — the reply happens within the block TTL.
                let relay_path =
                    self.select_onion_relay_path(REPLY_CIRCUIT_HOPS)
                        .map_err(|_| {
                            veil_anonymity::sender::SenderError::InsufficientRelayCandidates {
                                need: REPLY_CIRCUIT_HOPS,
                                have: 0,
                            }
                        })?;
                let relay = *relay_path.last().expect("non-empty relay path");
                // Ephemeral one-shot reply circuit (build-once, no maintenance
                // rebuild), so a fresh registration key is fine — no CookieClaimed
                // concern (L1 only matters for the rebuilt hosted-service circuits).
                // The cookie is derived from that key rather than drawn
                // independently: the relay checks the pairing, so an unpaired
                // cookie would simply be refused.
                let (reply_reg_kp, cookie) = Self::onion_reg_pair(None, 0, None);
                let block = veil_proto::ReplyBlock {
                    rendezvous_node_id: relay,
                    auth_cookie: cookie,
                    x25519_pk,
                    reply_app_id,
                    reply_endpoint_id,
                    // Circuit-backed: R_a forwards the reply DOWN our circuit by
                    // COOKIE alone, so this transport id is now unused on the
                    // circuit path (kept for wire compatibility / the legacy
                    // session path).
                    receiver_node_id: *self.identity.local_identity.node_id.as_bytes(),
                };
                (Some(block), Some((relay_path, cookie, reply_reg_kp)))
            }
            None => (None, None),
        };

        // Build + sign the whole message. dst = the ad's receiver_node_id (bound
        // by the signature; the verifier reconstructs it as its own node_id).
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let nonce = rand_core::OsRng.next_u64();
        let auth = sovereign.sign_auth_deliver(
            ad.receiver_node_id,
            target_app_id,
            target_endpoint_id,
            now_unix,
            nonce,
            data.to_vec(),
            reply_block.into_iter().collect(),
        );
        let auth_bytes = auth.encode();
        if auth_bytes.len() > veil_proto::MAX_AUTH_DELIVER_MSG_BYTES {
            return Err(veil_anonymity::sender::SenderError::PayloadTooLarge {
                hop_count,
                got: data.len(),
                max: veil_proto::MAX_AUTH_DELIVER_MSG_BYTES,
            });
        }

        // Largest signed-blob chunk that fits one fragment at this hop_count:
        //   Final-hop budget − [1 onion tag] − IntroducePayload fixed − introduce
        //   overhead − [1 inner tag] − fragment header.
        let chunk_size = introduce_fragment_chunk_size(hop_count).ok_or(
            veil_anonymity::sender::SenderError::HopCountExceedsCellBudget {
                hop_count,
                max: veil_anonymity::packet::MAX_HOPS_PER_CELL,
            },
        )?;
        if chunk_size == 0 {
            return Err(veil_anonymity::sender::SenderError::PayloadTooLarge {
                hop_count,
                got: data.len(),
                max: 0,
            });
        }
        let frag_count = auth_bytes.len().div_ceil(chunk_size).max(1);
        if frag_count > veil_proto::MAX_AUTH_DELIVER_FRAGMENTS as usize {
            return Err(veil_anonymity::sender::SenderError::PayloadTooLarge {
                hop_count,
                got: data.len(),
                max: chunk_size * veil_proto::MAX_AUTH_DELIVER_FRAGMENTS as usize,
            });
        }

        // Reassembly is ALL-OR-NOTHING across the fragments: the recipient
        // verifies the signed whole only once every fragment of `msg_id` lands.
        // Each fragment is one tiny onion cell (~100-200 B), independently lost,
        // so at F fragments the delivery odds collapse as (1-p)^F — a 27-fragment
        // bulk chunk at p≈0.27 / redundancy 1 delivers ~0.01%. Single-fragment
        // chat text is fine at redundancy 1, but any MULTI-fragment message
        // (bulk file content) needs redundancy to survive: each fragment is then
        // sent over `redundancy` independent circuits and de-duped by
        // (msg_id, frag_idx), lifting per-fragment delivery to 1-p^redundancy.
        // Auto-bump here so small messages stay cheap and only bulk pays the cost
        // — no API/FFI plumbing, and the reply path's explicit 3 is preserved.
        // The rendezvous relays to spread across: the primary `ad` plus any
        // distinct extra relays the recipient registered on (dedup by relay id).
        let mut relays: Vec<&veil_anonymity::rendezvous::RendezvousAd> = vec![ad];
        for e in extra_relays {
            if !relays
                .iter()
                .any(|r| r.rendezvous_node_id == e.rendezvous_node_id)
            {
                relays.push(e);
            }
        }
        // Spreading pays ONLY for a message that actually fragments. A
        // single-fragment message round-robins to exactly ONE relay at
        // redundancy 1 (see the send loop), which is strictly fewer copies than
        // the caller's redundant retransmit down one relay. On the reply path —
        // fire-and-forget, no end-to-end ack — that would trade reliability for
        // a throughput win that a one-fragment message cannot even collect.
        // `frag_count` is known here, so gate on it rather than on relay count
        // alone.
        let parallel = relays.len() > 1 && frag_count >= BULK_FRAGMENT_THRESHOLD;

        let redundancy = onion_send_redundancy(redundancy, frag_count, parallel, relays.len());

        // S4: all size/fragment validation passed — NOW build the ephemeral reply
        // circuit (registers the cookie at R_a). Doing it here means a size
        // failure above returns without ever creating a circuit to strand.
        if let Some((relay_path, cookie, reply_reg_kp)) = pending_reply_circuit {
            // Reply circuits are one-shot with a fresh (cookie, reg_pk), so a
            // throwaway epoch counter is fine — the registration is unique at R
            // and never collides; the epoch is just `unix_now`.
            let reply_epoch = std::sync::atomic::AtomicU64::new(0);
            let confirmed = self
                .build_onion_circuit_once(&relay_path, cookie, &reply_reg_kp, &reply_epoch, true)
                .map_err(
                    |_| veil_anonymity::sender::SenderError::InsufficientRelayCandidates {
                        need: REPLY_CIRCUIT_HOPS,
                        have: 0,
                    },
                )?;
            self.wait_reply_circuit_confirmed(&confirmed).await;
        }

        let mut msg_id = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut msg_id);

        // Each fragment: [APP_DELIVER_AUTH tag][AuthDeliverFragment] → sealed +
        // onion-routed to the rendezvous independently.
        for (idx, chunk) in auth_bytes.chunks(chunk_size).enumerate() {
            let frag = veil_proto::AuthDeliverFragment {
                msg_id,
                frag_count: frag_count as u16,
                frag_idx: idx as u16,
                chunk: chunk.to_vec(),
            };
            let frag_bytes = frag.encode();
            let mut sealed_plaintext = Vec::with_capacity(1 + frag_bytes.len());
            sealed_plaintext.push(final_hop_kind::APP_DELIVER_AUTH);
            sealed_plaintext.extend_from_slice(&frag_bytes);
            if parallel {
                // Round-robin fragments across relays for throughput, ONE copy
                // per fragment. A ⌈relays/frags⌉ per-fragment spread briefly
                // lived here to mask single-fragment chat losses, but those were
                // introduces landing on relays without a live registration
                // (`cookie_unknown`): the spread is now generation-gated to the
                // receiver's CURRENT registration set, so a single chain lands
                // and the extra copies were pure traffic (device-verified
                // 2026-07-05: 15/15 delivered at redundancy=1). A genuine
                // R→recipient cell loss falls back to the mailbox-drain hot
                // window, same as bulk fragments.
                let relay = relays[idx % relays.len()];
                self.send_sealed_introduce(relay, &sealed_plaintext, hop_count, circuit_backed)?;
            } else {
                // Bounded retransmit: send the fragment `redundancy` times over
                // independent circuits; the recipient de-dups by (msg_id, frag_idx).
                for _ in 0..redundancy.max(1) {
                    self.send_sealed_introduce(ad, &sealed_plaintext, hop_count, circuit_backed)?;
                }
            }
        }
        Ok(())
    }

    /// Authenticated anonymous send to a KNOWN relay (KEM key given) with an
    /// optional one-time reply block — the mailbox FETCH primitive.
    ///
    /// This is the proven key-given direct-onion send (reaches the target as the
    /// final onion hop with NO rendezvous-ad resolve, exactly like the mailbox
    /// DEPOSIT) plus the one-time reply-block construction from
    /// [`Self::send_via_rendezvous_authenticated`]. It exists because the mailbox
    /// drain must reach the RELAY directly: a relay publishes no `RendezvousAd`
    /// for itself, so the ad-resolving [`Self::send_anonymous_authenticated_to`]
    /// always returns `NoRendezvous` for a relay node_id. Here the caller hands us
    /// the relay's KEM key (cached at registration), so the sealed `AuthAppDeliver`
    /// is onion-routed straight to the relay — zero DHT ad lookup, no
    /// `NoRendezvous`.
    ///
    /// Anonymity: the forward send is a source-routed onion (the relay learns
    /// nothing of our location); the relay sees our sovereign node_id ONLY because
    /// the mailbox is, by design, keyed on the verified receiver identity
    /// (identical exposure to the ad-resolving path this replaces). The reply
    /// rides a one-time onion reply circuit to a relay WE pick, forwarded by
    /// cookie alone, so the mailbox relay cannot correlate our identity to a
    /// network location or to the reply path. No plain/direct-session fallback —
    /// on `InsufficientRelayCandidates` this errors rather than degrading.
    ///
    /// FETCH `data` is empty, so the signed `AuthAppDeliver` is a single onion
    /// cell — no fragmentation loop (unlike the rendezvous path).
    #[allow(clippy::too_many_arguments)]
    pub async fn send_anonymous_authenticated_direct_with_reply(
        &self,
        target_node_id: [u8; 32],
        target_x25519_pk: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        data: &[u8],
        hop_count: usize,
        // `Some((reply_app_id, reply_endpoint_id))` attaches a one-time reply
        // block so the relay can answer our mailbox over an onion reply circuit
        // WITHOUT either side publishing a public ad.
        reply: Option<([u8; 32], u32)>,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        use rand_core::RngCore;

        const REPLY_CIRCUIT_HOPS: usize = 2;

        let sovereign = self
            .identity
            .sovereign_identity
            .get()
            .ok_or(veil_anonymity::sender::SenderError::MissingSenderIdentity)?;

        // PREPARE the reply block (select relay path + cookie) so its bytes are
        // counted in the size check below, but DEFER building the onion circuit
        // (which registers a cookie at R_a) until AFTER the size check passes —
        // otherwise a late size failure would strand the ephemeral circuit + its
        // R_a registration (presence leak + idle-GC churn). Mirrors
        // `send_via_rendezvous_authenticated` exactly.
        let (reply_block, pending_reply_circuit) = match reply {
            Some((reply_app_id, reply_endpoint_id)) => {
                // We must own the anonymity key to unseal the eventual reply
                // (receive-capable: `receive_anonymous`/`relay_capable`).
                let x25519_pk = match self.dispatcher.anonymity_x25519_sk.as_ref() {
                    Some(sk) => x25519_dalek::PublicKey::from(sk.as_ref()).to_bytes(),
                    None => {
                        return Err(veil_anonymity::sender::SenderError::MissingReplyCapability);
                    }
                };
                let relay_path = self
                    .select_onion_relay_path(REPLY_CIRCUIT_HOPS)
                    .map_err(|e| {
                        // Surface the REAL reason before collapsing to the
                        // coarse IPC-visible error — this used to vanish into
                        // "status 2/NO_ROUTE" and made the mailbox-FETCH
                        // failure bursts undiagnosable from logs.
                        log::warn!(
                            "mailbox.fetch.reply_path_failed hops={REPLY_CIRCUIT_HOPS} err={e:?}"
                        );
                        veil_anonymity::sender::SenderError::InsufficientRelayCandidates {
                            need: REPLY_CIRCUIT_HOPS,
                            have: 0,
                        }
                    })?;
                let relay = *relay_path.last().expect("non-empty relay path");
                // Cookie derived from the one-shot reply key — see the sibling
                // reply path; the relay refuses an unpaired cookie.
                let (reply_reg_kp, cookie) = Self::onion_reg_pair(None, 0, None);
                let block = veil_proto::ReplyBlock {
                    rendezvous_node_id: relay,
                    auth_cookie: cookie,
                    x25519_pk,
                    reply_app_id,
                    reply_endpoint_id,
                    receiver_node_id: *self.identity.local_identity.node_id.as_bytes(),
                };
                (Some(block), Some((relay_path, cookie, reply_reg_kp)))
            }
            None => (None, None),
        };

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let nonce = rand_core::OsRng.next_u64();

        let auth = sovereign.sign_auth_deliver(
            target_node_id,
            target_app_id,
            target_endpoint_id,
            now_unix,
            nonce,
            data.to_vec(),
            reply_block.into_iter().collect(),
        );
        let auth_bytes = auth.encode();
        if auth_bytes.len() > veil_proto::MAX_AUTH_DELIVER_MSG_BYTES {
            return Err(veil_anonymity::sender::SenderError::PayloadTooLarge {
                hop_count,
                got: data.len(),
                max: veil_proto::MAX_AUTH_DELIVER_MSG_BYTES,
            });
        }

        // Size OK — NOW build the ephemeral reply circuit (registers the cookie at
        // R_a). A size failure above returns without ever creating one.
        if let Some((relay_path, cookie, reply_reg_kp)) = pending_reply_circuit {
            let reply_epoch = std::sync::atomic::AtomicU64::new(0);
            let confirmed = self
                .build_onion_circuit_once(&relay_path, cookie, &reply_reg_kp, &reply_epoch, true)
                .map_err(|e| {
                    // See reply_path_failed above — keep the real circuit-build
                    // error visible instead of the generic NO_ROUTE it becomes
                    // at the IPC boundary.
                    if e == veil_types::AnonOnionSendError::NoRelays {
                        log::debug!(
                            "mailbox.fetch.reply_circuit_unavailable relay={} err={e:?}",
                            veil_util::hex_short(relay_path.last().unwrap_or(&[0u8; 32])),
                        );
                    } else {
                        log::warn!(
                            "mailbox.fetch.reply_circuit_failed relay={} err={e:?}",
                            veil_util::hex_short(relay_path.last().unwrap_or(&[0u8; 32])),
                        );
                    }
                    veil_anonymity::sender::SenderError::InsufficientRelayCandidates {
                        need: REPLY_CIRCUIT_HOPS,
                        have: 0,
                    }
                })?;
            self.wait_reply_circuit_confirmed(&confirmed).await;
        }

        let mut payload_bytes = Vec::with_capacity(1 + auth_bytes.len());
        payload_bytes.push(veil_anonymity::rendezvous::final_hop_kind::APP_DELIVER_AUTH);
        payload_bytes.extend_from_slice(&auth_bytes);

        self.send_anonymous_onion(&payload_bytes, target_node_id, target_x25519_pk, hop_count)
    }

    /// Resolve the recipient's `RendezvousAd` and send an authenticated
    /// anonymous message to it (Epic 482 v1, "any recipient"). This is the
    /// production entry point behind the IPC `anonymous_authenticated` flag.
    /// Fetches + verifies the ad from the DHT (recursive, across replica slots),
    /// pre-resolves the rendezvous relay's directory entry into the local shard
    /// (so the onion build can reach it instead of silent-dropping), then
    /// signs/fragments/sends via [`Self::send_via_rendezvous_authenticated`].
    /// Errors are local/pre-transmit; once the cell is on the wire it is
    /// fire-and-forget (no end-to-end ACK).
    pub async fn send_anonymous_authenticated_to(
        &self,
        receiver_node_id: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        data: &[u8],
        hop_count: usize,
        // `Some((reply_app_id, reply_endpoint_id))` attaches a one-time reply
        // block (see `send_via_rendezvous_authenticated`).
        reply: Option<([u8; 32], u32)>,
    ) -> std::result::Result<(), veil_types::AnonOnionSendError> {
        use veil_types::AnonOnionSendError;

        const AD_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(3500);
        const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        if self.identity.sovereign_identity.is_none() {
            return Err(AnonOnionSendError::NoIdentity);
        }
        // Sender-side stall self-heal. The introduce is fire-and-forget and a
        // relay drops a cookie-less introduce SILENTLY (`cookie_unknown` must
        // not answer probes), so the only sender-observable failure is "my
        // sends to R pile up and nothing verified ever comes back from R"
        // (their delivery-ACKs / replies all arrive as verified AuthDeliver —
        // see the note_answer hook in process_auth_deliver). When that trips:
        //  * drop R's resolve-cache entry (once per window) so THIS send
        //    re-compares fresh replicas instead of re-firing into the hole;
        //  * widen the introduce fan-out below with connected relay candidates
        //    ordered by XOR distance to R — approximating R's OWN deterministic
        //    relay pick, so if R is live-registered at a relay whose fresh ad
        //    simply hasn't propagated to us, the introduce still lands there.
        let stall_now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Only reply-expecting sends DRIVE the stall accounting: their
        // delivery-ACK comes back over OUR ephemeral reply circuit, so its
        // absence is a true me→R signal. Beacons / acks / content chunks carry
        // no reply block and are legitimately unanswered — counting them made
        // a quiet-but-healthy pair re-trip the verdict every widen window.
        // They still ride an ACTIVE widen (peek) so a stalled route widens
        // every outgoing frame, not just the messages.
        let stall = if reply.is_some() {
            self.anonymity
                .send_stall
                .note_send(receiver_node_id, stall_now_unix)
        } else {
            self.anonymity
                .send_stall
                .peek(&receiver_node_id, stall_now_unix)
        };
        if stall.invalidate_cache {
            self.anonymity
                .rendezvous_resolve_cache
                .remove(&receiver_node_id);
            self.logger.info(
                "anonymity.sender.stall",
                format!(
                    "no verified inbound from {} across repeated sends — forcing \
                     fresh ad resolve + widened introduce fan-out",
                    veil_util::hex_short(&receiver_node_id),
                ),
            );
        }
        // A merely-valid local ad is not sufficient here. The receiver may
        // have reconnected and moved to a different relay while the old signed
        // ad remains unexpired; using it produces a valid-looking introduce at
        // a relay that no longer owns the cookie (`cookie_unknown`). Compare
        // independently-served candidates on a short cadence and repair the
        // local mirror with the newest publication.
        let mut ads = service_tasks::resolve_fresh_rendezvous_ads(
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
        // Pick the most-recently-PUBLISHED ad (highest valid_from_unix, set to
        // now at publish), NOT the highest valid_until. The auth_cookie is
        // per-period (derive_onion_auth_cookie(seed, now/86400)), so the
        // freshest-published ad carries the cookie that matches the receiver's
        // CURRENT registration. Ranking by valid_until preferred a stale ad from
        // a previous period that merely has a LONGER validity window (e.g. an old
        // 24h ad over today's 1h ad) — its old-period cookie then mismatched at
        // the relay and EVERY introduce was dropped as `cookie_unknown` (the
        // onion content path's residual ~30% loss after the replica-resolver fix;
        // this `send_anonymous_authenticated_to` selection is the one the content
        // send actually uses).
        ads.sort_by_key(|ad| std::cmp::Reverse(ad.valid_from_unix));
        if ads.is_empty() {
            return Err(AnonOnionSendError::NoRendezvous);
        }
        // The receiver's CHAT cookie is deterministic + public
        // (`rendezvous_cookie_from_node_id`, the same XOR-fold the recipient
        // task and the app's mailbox publisher register under). Filter to it
        // UP FRONT: the resolved union can also contain other same-receiver
        // publications (e.g. the onion-stream cookie published for a
        // just-opened stream circuit) whose valid_from can outrank the chat
        // ads — taking ads[0].auth_cookie blindly then aimed every chat
        // introduce at the stream registration. Fall back to the freshest
        // ad's cookie only if no ad carries the expected chat cookie
        // (unexpected publisher — behave like the legacy selection).
        let expected_cookie = service_tasks::rendezvous_cookie_from_node_id(&receiver_node_id);
        let primary_cookie = if ads.iter().any(|a| a.auth_cookie == expected_cookie) {
            expected_cookie
        } else {
            ads[0].auth_cookie
        };
        // Keep up to MAX distinct-relay ads (freshest-first). The recipient
        // registered on several rendezvous relays; bulk content is round-robined
        // across them for parallel-endpoint throughput instead of funnelling
        // redundant copies through one. A recipient on a single relay yields one
        // ad → classic path.
        const MAX_PARALLEL_RELAYS: usize = 3;
        // GENERATION gate: the receiver re-signs ALL its plain ads together with
        // one shared valid_from stamp (see `tick_publish_rendezvous_ads`), so
        // "the receiver's current relay set" is exactly the same-cookie ads
        // carrying the NEWEST stamp. The chat cookie itself never rotates, so
        // cookie equality cannot tell a live relay from one the receiver left
        // minutes ago whose unexpired ad still floats around DHT replicas — the
        // relay dropped that registration the moment the receiver's session
        // closed, and an introduce there is silently dropped as cookie_unknown.
        // Spreading strictly within the newest generation keeps every parallel
        // introduce on a relay of the receiver's current registration set.
        let primary_generation = ads
            .iter()
            .find(|a| a.auth_cookie == primary_cookie)
            .map(|a| a.valid_from_unix)
            .unwrap_or(ads[0].valid_from_unix);
        let mut chosen: Vec<veil_anonymity::rendezvous::RendezvousAd> = Vec::new();
        let mut seen_relays = std::collections::HashSet::new();
        for a in ads {
            if a.auth_cookie != primary_cookie {
                continue; // different publication (e.g. stream cookie)
            }
            if a.valid_from_unix != primary_generation {
                continue; // stale generation → receiver likely left this relay
            }
            if seen_relays.insert(a.rendezvous_node_id) {
                chosen.push(a);
                if chosen.len() >= MAX_PARALLEL_RELAYS {
                    break;
                }
            }
        }
        // Stalled route: additionally introduce at connected relay candidates
        // the resolvable ads did NOT name, XOR-ordered by R's node_id (the same
        // metric R's own recipient task uses to pick its relays, so the overlap
        // is high). The chat cookie is deterministic per identity — identical at
        // every relay R registers with — so the primary cookie is the right one
        // at a widened relay too; where R is NOT registered the introduce drops
        // exactly like today (silent, bounded). The receiver's E2E key comes
        // from the freshest ad; only the rendezvous target differs.
        if stall.widen {
            const WIDEN_EXTRA_RELAYS: usize = 2;
            let widened = service_tasks::pick_rendezvous_relays_deterministic(
                &self.live_sessions,
                &self.dht,
                &self.dispatcher.crypto.peer_cap_flags,
                &[],
                &receiver_node_id,
            );
            let template = chosen[0].clone();
            let mut added = 0usize;
            for relay in widened {
                if added >= WIDEN_EXTRA_RELAYS {
                    break;
                }
                if seen_relays.insert(relay) {
                    let mut ad = template.clone();
                    ad.rendezvous_node_id = relay;
                    chosen.push(ad);
                    added += 1;
                }
            }
            if added > 0 {
                self.logger.info(
                    "anonymity.sender.stall_widen",
                    format!(
                        "stalled route to {} — introducing at {added} extra \
                         connected relay(s) beyond the resolved ads",
                        veil_util::hex_short(&receiver_node_id),
                    ),
                );
            }
        }

        // Pre-resolve EACH chosen relay's directory entry into our local DHT shard
        // so `send_via_rendezvous_authenticated`'s `get_local` lookup finds it for
        // every relay we round-robin across (otherwise that path silent-drops when
        // the entry isn't organically cached — review fix).
        for a in &chosen {
            let relay_key =
                veil_anonymity::directory::relay_directory_dht_key(&a.rendezvous_node_id);
            if self.dht.get_local(&relay_key).is_none()
                && let Some(bytes) = self.dht_recursive_get(relay_key, RESOLVE_TIMEOUT).await
            {
                self.dht.store_local(relay_key, bytes);
            }
        }

        // The rendezvous relay alone is not enough: `select_onion_relay_path`
        // needs >= hop_count-1 MIDDLE relays drawn from our connected peers and
        // filtered by `get_local(relay_directory_dht_key(peer))`. A cold sender
        // holds none of those entries (passive Kademlia replication hasn't run),
        // so the circuit can't be built and the introduce silently fails with
        // `InsufficientRelayCandidates { have: 0 }`. Actively FIND_VALUE + verify
        // + cache the connected relays' directory entries first — the exact
        // sender-side analogue of the recipient cold-start warm. (review fix)
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

        self.send_via_rendezvous_authenticated(
            &chosen[0],
            &chosen[1..], // extra distinct-relay endpoints → round-robin parallelism
            target_app_id,
            target_endpoint_id,
            data,
            hop_count,
            reply,
            1,     // forward sends: no redundancy (the recipient is reachable via its ad)
            false, // by-node_id: recipient may be session-backed → keep real id (L3)
        )
        .await
        .map_err(|e| match e {
            veil_anonymity::sender::SenderError::MissingSenderIdentity => {
                AnonOnionSendError::NoIdentity
            }
            veil_anonymity::sender::SenderError::InsufficientRelayCandidates { .. } => {
                AnonOnionSendError::NoRelays
            }
            veil_anonymity::sender::SenderError::PayloadTooLarge { .. } => {
                AnonOnionSendError::PayloadTooLarge
            }
            _ => AnonOnionSendError::NoRelays,
        })
    }

    /// Send an authenticated anonymous message to a LOCATION-anonymous (onion)
    /// service addressed by its Ed25519 IDENTITY key — the unlinkable analogue of
    /// [`Self::send_anonymous_authenticated_to`] (which addresses by node_id and
    /// resolves a node_id-keyed `RendezvousAd`). Here we resolve the service's
    /// per-period BLINDED descriptor: `descriptor_dht_key(identity, period)` is
    /// derived from the blinded key, so a DHT enumerator who doesn't know the
    /// identity cannot find or read it. We decrypt it (we know the identity),
    /// reconstruct a synthetic ad from the body, and route over the onion exactly
    /// as the node_id path does.
    ///
    /// We try the current period plus ±1 to tolerate clock skew across a period
    /// boundary and a service that registered in the previous period and hasn't
    /// rotated yet (the descriptor's blinded key + enc key + signature all bind
    /// the period, so a wrong-period attempt simply fails to open).
    pub async fn send_to_onion_service(
        &self,
        service_identity_vk: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        data: &[u8],
        hop_count: usize,
        reply: Option<([u8; 32], u32)>,
    ) -> std::result::Result<(), veil_types::AnonOnionSendError> {
        use veil_types::AnonOnionSendError;

        // The authenticated path signs with our sovereign identity.
        if self.identity.sovereign_identity.is_none() {
            return Err(AnonOnionSendError::NoIdentity);
        }
        let ads = self.resolve_onion_service_ads(&service_identity_vk).await?;
        let ad = Self::select_rendezvous_candidates(&ads, data, 1)
            .into_iter()
            .next()
            .ok_or(AnonOnionSendError::NoRendezvous)?;

        // Other provider slots published by the SAME node are additional
        // introduction points to one service instance, so a FRAGMENTED message
        // can be round-robined across them instead of funnelling redundant
        // copies of every fragment through one relay — which is what caps bulk
        // throughput here, since reassembly is all-or-nothing. (A single-
        // fragment message is unaffected: the spread is gated on frag_count.)
        //
        // Ads from OTHER providers are DIFFERENT NODES holding the same
        // content. They must never be mixed in: each fragment would go to
        // whichever node the round-robin landed on, and no node would ever
        // hold the whole message.
        let extra_ads = Self::same_node_extra_ads(&ads, ad);

        self.send_via_rendezvous_authenticated(
            ad,
            &extra_ads,
            target_app_id,
            target_endpoint_id,
            data,
            hop_count,
            reply,
            1,
            true, // by-identity → circuit-backed: pseudo cleartext receiver id (L3)
        )
        .await
        .map_err(map_sender_err)
    }

    /// Like [`Self::send_to_onion_service`] but UNAUTHENTICATED: the service
    /// receives the message with `src_node_id = [0; 32]`, so it never learns who
    /// sent it. Combined with the unlinkable descriptor resolution, this is the
    /// fully-anonymous "anonymous user → anonymous service" quadrant — neither the
    /// relays, R, nor the service itself learn the sender's location or identity.
    /// `src_app_id` rides inside the sealed payload for the service's app-level
    /// routing only (no node identity). No sovereign identity is required.
    pub async fn send_to_onion_service_anonymous(
        &self,
        service_identity_vk: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        src_app_id: [u8; 32],
        data: &[u8],
        hop_count: usize,
    ) -> std::result::Result<(), veil_types::AnonOnionSendError> {
        let ads = self.resolve_onion_service_ads(&service_identity_vk).await?;

        // Unauthenticated final-hop payload: src_node_id zero (anonymity).
        let app_deliver = veil_proto::AppDeliverPayload {
            src_node_id: [0u8; 32],
            src_app_id,
            app_id: target_app_id,
            endpoint_id: target_endpoint_id,
            data: veil_bufpool::pooled_shared_from_vec(data.to_vec()),
            reply_id: 0,
            // Sender-written; the receiver decides provenance itself.
            provenance: veil_proto::SenderProvenance::Claimed,
        };
        let app_deliver_bytes = app_deliver.encode();

        // by-identity anonymous send → circuit-backed: pseudo cleartext id (L3).
        // AppDeliver framing alone is 112 B and introduce HPKE adds another
        // 60 B, leaving far less than one public-cloud chunk in the 320 B
        // ciphertext budget. Fragment the opaque AppDeliver bytes without
        // adding a sovereign signature (the receiver must still see node_id=0).
        // A send enqueue cannot prove end-to-end delivery, so a sequential
        // fallback would be illusory. Fan out to at most three independently
        // hosted providers. Cloud requests carry a fresh nonce; hashing the
        // opaque request rotates the starting provider across retries while a
        // fixed cap bounds traffic and duplicate responses.
        let mut first_error = None;
        let mut enqueued = 0usize;
        let candidates = Self::select_rendezvous_candidates(&ads, data, 3);
        for ad in &candidates {
            match self.send_via_rendezvous_anonymous_payload(
                ad,
                &app_deliver_bytes,
                hop_count,
                true,
            ) {
                Ok(()) => enqueued += 1,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if candidates.is_empty() {
            return Err(veil_types::AnonOnionSendError::NoRendezvous);
        }
        if enqueued == 0 {
            // Nothing got out over any candidate, so the cached route set is
            // the prime suspect — drop it rather than re-firing into it for the
            // rest of the TTL. (A route that accepts sends but silently eats
            // them is a different problem: the receiver-addressed path detects
            // that with a stall counter, which this path does not yet have.)
            self.anonymity
                .onion_resolve_cache
                .remove(&service_identity_vk);
        }
        match (enqueued, first_error) {
            (0, Some(error)) => Err(map_sender_err(error)),
            (0, None) => Err(veil_types::AnonOnionSendError::NoRendezvous),
            _ => Ok(()),
        }
    }

    fn send_via_rendezvous_anonymous_payload(
        &self,
        ad: &veil_anonymity::rendezvous::RendezvousAd,
        app_deliver_bytes: &[u8],
        hop_count: usize,
        circuit_backed: bool,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        use rand_core::RngCore;
        use veil_anonymity::rendezvous::final_hop_kind;

        let hops_fit = || veil_anonymity::sender::SenderError::HopCountExceedsCellBudget {
            hop_count,
            max: veil_anonymity::packet::MAX_HOPS_PER_CELL,
        };
        let plaintext_budget = introduce_plaintext_budget(hop_count).ok_or_else(hops_fit)?;
        if app_deliver_bytes.len() < plaintext_budget {
            let mut plaintext = Vec::with_capacity(1 + app_deliver_bytes.len());
            plaintext.push(final_hop_kind::APP_DELIVER);
            plaintext.extend_from_slice(app_deliver_bytes);
            return self.send_sealed_introduce(ad, &plaintext, hop_count, circuit_backed);
        }

        let chunk_size = introduce_fragment_chunk_size(hop_count).ok_or_else(hops_fit)?;
        if chunk_size == 0 {
            return Err(veil_anonymity::sender::SenderError::PayloadTooLarge {
                hop_count,
                got: app_deliver_bytes.len(),
                max: 0,
            });
        }
        let frag_count = app_deliver_bytes.len().div_ceil(chunk_size);
        if frag_count == 0 || frag_count > veil_proto::MAX_AUTH_DELIVER_FRAGMENTS as usize {
            return Err(veil_anonymity::sender::SenderError::PayloadTooLarge {
                hop_count,
                got: app_deliver_bytes.len(),
                max: chunk_size * veil_proto::MAX_AUTH_DELIVER_FRAGMENTS as usize,
            });
        }
        let mut msg_id = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut msg_id);
        // Multi-fragment delivery is all-or-nothing. Match the authenticated
        // bulk path's bounded redundancy; app-level chunk retry handles the
        // remaining loss without unbounded transport amplification.
        let redundancy = if frag_count >= 3 { 3 } else { 1 };
        for (index, chunk) in app_deliver_bytes.chunks(chunk_size).enumerate() {
            let fragment = veil_proto::AuthDeliverFragment {
                msg_id,
                frag_count: frag_count as u16,
                frag_idx: index as u16,
                chunk: chunk.to_vec(),
            };
            let encoded = fragment.encode();
            let mut plaintext = Vec::with_capacity(1 + encoded.len());
            plaintext.push(final_hop_kind::APP_DELIVER_FRAGMENT);
            plaintext.extend_from_slice(&encoded);
            for _ in 0..redundancy {
                self.send_sealed_introduce(ad, &plaintext, hop_count, circuit_backed)?;
            }
        }
        Ok(())
    }

    /// Send `data` to a KNOWN peer `(target_node_id, target_x25519_pk)` as an
    /// UNAUTHENTICATED anonymous onion message — the direct (non-rendezvous)
    /// sender-anonymous path. The source-routed onion hides our network location
    /// from every relay, and the receiver sees `src_node_id = [0; 32]` (it does
    /// NOT learn who sent it; replies need the separate rendezvous flow).
    /// Fire-and-forget: `Ok` means handed to the first hop, not delivered.
    // 8-arg signature — destination+payload+anonymity shape is one tuple;
    // a struct adds boilerplate without ergonomic gain.
    #[allow(clippy::too_many_arguments)]
    pub fn send_anonymous(
        &self,
        target_node_id: [u8; 32],
        target_x25519_pk: [u8; 32],
        target_app_id: [u8; 32],
        target_endpoint_id: u32,
        src_app_id: [u8; 32],
        data: &[u8],
        hop_count: usize,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        // Wrap data in `AppDeliverPayload` so the receiver's Final-hop dispatcher
        // can route to the addressed endpoint. src_node_id stays zero — the
        // anonymity guarantee: the receiver does NOT learn the sender's node id.
        let deliver_payload = veil_proto::AppDeliverPayload {
            src_node_id: [0u8; 32],
            src_app_id,
            app_id: target_app_id,
            endpoint_id: target_endpoint_id,
            data: veil_bufpool::pooled_shared_from_vec(data.to_vec()),
            reply_id: 0,
            // Sender-written; the receiver decides provenance itself.
            provenance: veil_proto::SenderProvenance::Claimed,
        };
        let deliver_bytes = deliver_payload.encode();
        let mut payload_bytes = Vec::with_capacity(1 + deliver_bytes.len());
        payload_bytes.push(veil_anonymity::rendezvous::final_hop_kind::APP_DELIVER);
        payload_bytes.extend_from_slice(&deliver_bytes);

        self.send_anonymous_onion(&payload_bytes, target_node_id, target_x25519_pk, hop_count)
    }

    /// Common onion-send path shared by [`Self::send_anonymous`] (un-authenticated)
    /// and the Runtime's `send_anonymous_authenticated`. `payload` is the
    /// already-assembled final-hop blob: a `final_hop_kind` tag byte followed by
    /// the kind-specific body. This helper owns candidate selection, relay
    /// discovery/verify, AS-diversity + reputation-weighted circuit picking, the
    /// onion wrap, and the fire-and-forget first-hop send.
    pub(crate) fn send_anonymous_onion(
        &self,
        payload: &[u8],
        target_node_id: [u8; 32],
        target_x25519_pk: [u8; 32],
        hop_count: usize,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        use veil_anonymity::{
            directory::{
                DEFAULT_FRESHNESS_WINDOW_SECS, discover_relay_hops_cached, relay_directory_dht_key,
            },
            sender::{DiversityOutcome, build_outbound_anonymous_cell_guarded},
        };

        // W0 measurement (anonymity-preserving plan): time the SELECTION phase
        // (candidate snapshot + relay discovery/verify + diversity map) vs the
        // BUILD phase (pick + onion wrap) to decide whether selection dominates
        // the per-send overhead (gates W2 selection-input caching). Local timing
        // of our OWN send — nothing is transmitted, no peer correlation; emitted
        // at debug level (off by default).
        let t_select = std::time::Instant::now();

        // Step 1: snapshot candidates from local DHT routing table.
        // We could also pull from PEX-discovered peers or the live-
        // sessions registry, but routing table is the canonical
        // "peers we already know about" set + matches the security
        // story (anonymity layer must not consult sources that an
        // attacker can poison faster than DHT).
        let candidate_node_ids: Vec<[u8; 32]> = self
            .dht
            .routing_table_contacts()
            .into_iter()
            .map(|c| c.node_id)
            .collect();

        // Step 2 + 3: fetch + verify + filter via discovery helper.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let dht = Arc::clone(&self.dht);
        let usable_relays = discover_relay_hops_cached(
            &candidate_node_ids,
            |node_id| dht.get_local(&relay_directory_dht_key(node_id)),
            now_unix,
            DEFAULT_FRESHNESS_WINDOW_SECS,
            &self.anonymity.relay_entry_verify_cache,
        );

        // Step 4: build the cell. RTT estimator pulls from Vivaldi
        // when local coords have converged; falls back to None
        // (which the picker handles by sorting unknown-RTT to last).
        let local_vivaldi = self.dispatcher.local_vivaldi.clone();
        let peer_vivaldi = Arc::clone(&self.dispatcher.peer_vivaldi);
        let rtt_estimator = move |node_id: &[u8; 32]| -> Option<u32> {
            // Vivaldi distance estimate: Euclidean distance between
            // local + peer coords, scaled. When either coord is
            // unknown, return None (picker treats as worst-priority).
            let local = local_vivaldi.as_ref()?;
            let peer_map = rlock!(peer_vivaldi);
            let (peer_coord, _) = peer_map.get(node_id)?;
            let local_guard = lock!(local);
            let estimated_ms = local_guard.distance_estimate(peer_coord) * 1000.0;
            // Sanity: clamp to u32 range. Vivaldi can return
            // negative or NaN values during convergence — treat as
            // unknown (None) so picker doesn't sort by garbage.
            if !estimated_ms.is_finite() || estimated_ms < 0.0 {
                return None;
            }
            Some(estimated_ms.min(u32::MAX as f64) as u32)
        };

        // Anti-censorship AS-diversity extractor — snapshots already-
        // dialed peers' IPs from discovered_peers_cache + builds a
        // node_id → /16 (IPv4) / /32 (IPv6) prefix map.  Used by the
        // circuit picker to enforce "no two hops in the same /16" even
        // when relay-directory wire format doesn't carry IP/ASN.
        // Unknown relays get `None` (graceful degradation —
        // picker accepts them without a diversity gate).
        let diversity_map = build_as_diversity_map(&self.discovered_peers_cache);
        let diversity_key_of =
            move |node_id: &[u8; 32]| -> Option<String> { diversity_map.get(node_id).cloned() };

        // Downweight relays with recorded failures (Epic 482.3/482.4 Phase A):
        // a misbehaving relay's effective RTT is bumped by its penalty so it
        // sorts behind viable alternatives.
        let relay_reputation = Arc::clone(&self.anonymity.relay_reputation);
        let reputation_penalty_ms =
            move |node_id: &[u8; 32]| -> u32 { relay_reputation.rtt_penalty_ms(*node_id) };
        // First-hop liveness guard: the finished cell is handed to hops[0]
        // over a DIRECT session (no dial-on-demand below), so a sessionless
        // first hop means the cell silently evaporates — the dominant
        // first-attempt-loss source. Snapshot the live-session set and let
        // the picker prefer it for the guard slot. Tor-guard semantics: the
        // first hop learns our IP from the direct session anyway, so
        // preferring already-connected relays reveals nothing new.
        let live_first_hops: std::collections::HashSet<[u8; 32]> = self
            .dispatcher
            .session_tx_registry
            .as_ref()
            .map(|reg| rlock!(reg).active_node_ids())
            .unwrap_or_default();
        let first_hop_live = |node_id: &[u8; 32]| live_first_hops.contains(node_id);
        let select_us = t_select.elapsed().as_micros();
        let t_build = std::time::Instant::now();
        let ((first_hop_node_id, cell), diversity) = build_outbound_anonymous_cell_guarded(
            payload,
            &usable_relays,
            rtt_estimator,
            diversity_key_of,
            reputation_penalty_ms,
            first_hop_live,
            target_node_id,
            target_x25519_pk,
            hop_count,
        )?;
        if !live_first_hops.contains(&first_hop_node_id) {
            // Guard fallback: no live-session candidate was available in the
            // relay pool (or the target itself is the first hop) — this send
            // rides the old sessionless-first-hop odds and may be lost until
            // an app-layer retry.
            log::debug!(
                "anonymity.first_hop.guard_fallback path=onion first_hop={} \
                 live_sessions={} usable={}",
                veil_util::hex_short(&first_hop_node_id),
                live_first_hops.len(),
                usable_relays.len(),
            );
        }
        // W0 measurement: selection (candidate prep + discovery + diversity map)
        // vs build (pick + onion wrap). The anonymity-preserving plan expects
        // selection to dominate → justifies W2 selection-input caching.
        log::debug!(
            "anonymity.send.timing select_us={select_us} build_us={} \
             payload={} hops={hop_count} candidates={} usable={}",
            t_build.elapsed().as_micros(),
            payload.len(),
            candidate_node_ids.len(),
            usable_relays.len(),
        );
        if diversity == DiversityOutcome::DegradedToLatency {
            // AS-correlation protection was silently lost — surface it so an
            // operator can see when circuits aren't netblock-diverse. (cycle-8 F4.)
            log::warn!(
                "anonymity.circuit.diversity_degraded hop_count={hop_count} \
                 candidates={} — no AS-diverse relay set; fell back to latency-only",
                usable_relays.len()
            );
        }

        // Step 5: hit the wire. RelayChain::Hop frame to first hop's
        // session. If first_hop has no live session, the send is a
        // silent drop — caller learns from app-layer timeout, NOT
        // from a synchronous error (which would leak whether the
        // first hop is reachable to a sender-side observer).
        use veil_proto::{
            codec::encode_header,
            family::{FrameFamily, RelayChainMsg},
            header::FrameHeader,
        };
        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
        hdr.body_len = cell.len() as u32;
        hdr.set_priority(veil_proto::priority::INTERACTIVE);
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(&cell[..]);
        if let Some(ref reg) = self.dispatcher.session_tx_registry {
            let guard = wlock!(reg);
            let sent =
                guard.send_to_result(&first_hop_node_id, veil_proto::priority::INTERACTIVE, frame);
            drop(guard);
            if let Err(e) = sent {
                // The cell is lost. With the first-hop liveness guard above
                // this should be rare (session died between snapshot and
                // send, or TX queue Full ≠ no session). Log the reason —
                // Full vs Missing/Closed need different remedies — and
                // record the failure so the picker downweights this relay.
                // Still fire-and-forget (return Ok): a synchronous error
                // would leak first-hop reachability to a sender-side observer.
                match e {
                    veil_session::SendToError::Missing => log::debug!(
                        "anonymity.first_hop.session_missing path=onion first_hop={}",
                        veil_util::hex_short(&first_hop_node_id),
                    ),
                    _ => log::warn!(
                        "anonymity.first_hop.send_failed path=onion reason={e:?} first_hop={}",
                        veil_util::hex_short(&first_hop_node_id),
                    ),
                }
                self.anonymity
                    .relay_reputation
                    .record_failure(first_hop_node_id);
            }
        }
        Ok(())
    }

    /// Resolve a location-anonymous service's BLINDED descriptor (by its Ed25519
    /// identity) into a synthetic `RendezvousAd` ready for the send path. Tries
    /// the current period plus ±1 to tolerate clock skew across a period boundary
    /// and a service that registered in the previous period and hasn't rotated yet
    /// (the descriptor's blinded key + enc key + signature all bind the period, so
    /// a wrong-period attempt simply fails to open). Also pre-resolves the
    /// rendezvous relay's directory entry into our local shard so the onion build
    /// finds it. `NoRendezvous` if no descriptor resolves/decrypts.
    /// The other introduction points of the SAME service instance as
    /// `primary`: ads that name the same receiver node at a different
    /// rendezvous relay, deduplicated by relay.
    ///
    /// A service may publish into several provider slots, and ads from OTHER
    /// providers are DIFFERENT NODES holding the same content. Those must never
    /// be mixed in: round-robin would send each fragment to whichever node it
    /// landed on, and no node would ever hold the whole message.
    pub(crate) fn same_node_extra_ads(
        ads: &[veil_anonymity::rendezvous::RendezvousAd],
        primary: &veil_anonymity::rendezvous::RendezvousAd,
    ) -> Vec<veil_anonymity::rendezvous::RendezvousAd> {
        let mut extras: Vec<veil_anonymity::rendezvous::RendezvousAd> = Vec::new();
        for candidate in ads {
            if candidate.receiver_node_id != primary.receiver_node_id
                || candidate.rendezvous_node_id == primary.rendezvous_node_id
                || extras
                    .iter()
                    .any(|e| e.rendezvous_node_id == candidate.rendezvous_node_id)
            {
                continue;
            }
            extras.push(candidate.clone());
        }
        extras
    }

    pub(crate) fn select_rendezvous_candidates<'a>(
        ads: &'a [veil_anonymity::rendezvous::RendezvousAd],
        request_bytes: &[u8],
        limit: usize,
    ) -> Vec<&'a veil_anonymity::rendezvous::RendezvousAd> {
        if ads.is_empty() || limit == 0 {
            return Vec::new();
        }
        let mut hash = blake3::Hasher::new();
        hash.update(b"veil.provider.candidate-order.v1\0");
        hash.update(request_bytes);
        let digest = hash.finalize();
        let mut start_bytes = [0u8; 8];
        start_bytes.copy_from_slice(&digest.as_bytes()[..8]);
        let start = (u64::from_le_bytes(start_bytes) as usize) % ads.len();
        (0..ads.len().min(limit))
            .map(|offset| &ads[(start + offset) % ads.len()])
            .collect()
    }

    /// How long the remaining slot lookups may still join after the first one
    /// has answered. Long enough for a peer that is merely a little slower to be
    /// counted — the fan-out picks up to three providers and wants the choice —
    /// short enough that a service publishing one slot no longer pays the full
    /// timeout for the eight it left empty.
    const SLOT_GRACE: std::time::Duration = std::time::Duration::from_millis(400);

    async fn resolve_onion_service_period_bodies(
        &self,
        service_identity_vk: &[u8; 32],
        period: u64,
        timeout: std::time::Duration,
    ) -> Vec<veil_anonymity::blinded_descriptor::BlindedDescriptorBody> {
        use veil_anonymity::blinded_descriptor as bd;

        let provider_lookups = (0..bd::MAX_PROVIDER_SLOTS).filter_map(|slot| {
            bd::provider_descriptor_dht_key(service_identity_vk, period, slot)
                .map(|key| (slot, key))
        });
        let lookups = provider_lookups
            .map(|(slot, key)| (Some(slot), key))
            .chain(bd::descriptor_dht_key(service_identity_vk, period).map(|key| (None, key)));
        // Every key is still QUERIED — the lookup shape must not reveal how many
        // provider slots are occupied, and that invariant is about what goes out
        // on the wire. It is not about how long we sit here: a service normally
        // fills one slot, so the other eight have nothing to find and each runs
        // its full timeout. Waiting for all of them made every resolve cost
        // exactly `timeout`, measured at 5003/5003/5002/5002/5003/5002/5003/5004
        // ms across one 8 KiB pull while the answer itself was already in hand.
        //
        // So: collect as they land, and once something HAS landed, give the rest
        // a short grace to join before returning. A resolve that finds nothing
        // still waits the whole budget, because there the wait is the search.
        use futures::stream::StreamExt;
        let mut pending: futures::stream::FuturesUnordered<_> = lookups
            .map(|(slot, key)| async move {
                let bytes = self.dht_recursive_get(key, timeout).await?;
                let body = match slot {
                    Some(slot) => {
                        bd::open_provider_descriptor(service_identity_vk, period, slot, &bytes)
                    }
                    None => bd::open_descriptor(service_identity_vk, period, &bytes),
                }?;
                Some(body)
            })
            .collect();

        let mut bodies: Vec<bd::BlindedDescriptorBody> = Vec::new();
        let mut grace_deadline: Option<tokio::time::Instant> = None;
        loop {
            let next = match grace_deadline {
                None => pending.next().await,
                Some(deadline) => match tokio::time::timeout_at(deadline, pending.next()).await {
                    Ok(item) => item,
                    // The stragglers are still in flight and their answers still
                    // reach the local store through the dispatcher, so the next
                    // resolve benefits from them even though this one moved on.
                    Err(_) => break,
                },
            };
            let Some(found) = next else { break };
            if let Some(body) = found {
                if !bodies.contains(&body) {
                    bodies.push(body);
                }
                grace_deadline
                    .get_or_insert_with(|| tokio::time::Instant::now() + Self::SLOT_GRACE);
            }
        }
        bodies
    }

    async fn resolve_onion_service_ads(
        &self,
        service_identity_vk: &[u8; 32],
    ) -> std::result::Result<
        Vec<veil_anonymity::rendezvous::RendezvousAd>,
        veil_types::AnonOnionSendError,
    > {
        use veil_anonymity::blinded_descriptor as bd;
        use veil_types::AnonOnionSendError;

        const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // A resolve ran on EVERY send. A member content pull issues one send
        // per 256-byte chunk, so a single file paid a whole DHT fan-out — nine
        // slot lookups against a multi-second budget — for every chunk of it.
        // The receiver-addressed path was given this cache long ago; the
        // identity-addressed one was simply never wired to it.
        if let Some(ads) = self
            .anonymity
            .onion_resolve_cache
            .get(service_identity_vk, now)
        {
            return Ok(ads);
        }
        // Coalesce the burst. Without this a window of chunk requests all miss
        // the cold cache together and each launches its own fan-out before the
        // first one has anything to share.
        let _refresh = self
            .anonymity
            .onion_resolve_cache
            .lock_refresh(*service_identity_vk)
            .await;
        // Whoever held the lock has published by now.
        if let Some(ads) = self
            .anonymity
            .onion_resolve_cache
            .get(service_identity_vk, now)
        {
            return Ok(ads);
        }
        let cur = bd::current_period(now);
        let resolve_started = std::time::Instant::now();

        // Query every fixed slot, not "until missing": the lookup shape must
        // not reveal the provider count. Legacy `od` participates as a ninth
        // compatibility candidate. Adjacent periods are queried only when the
        // current period has no valid descriptor at all.
        let mut bodies = self
            .resolve_onion_service_period_bodies(service_identity_vk, cur, RESOLVE_TIMEOUT)
            .await;
        if bodies.is_empty() {
            let adjacent = futures::future::join_all([
                self.resolve_onion_service_period_bodies(
                    service_identity_vk,
                    cur.saturating_sub(1),
                    RESOLVE_TIMEOUT,
                ),
                self.resolve_onion_service_period_bodies(
                    service_identity_vk,
                    cur.saturating_add(1),
                    RESOLVE_TIMEOUT,
                ),
            ])
            .await;
            for body in adjacent.into_iter().flatten() {
                if !bodies.contains(&body) {
                    bodies.push(body);
                }
            }
        }
        if bodies.is_empty() {
            return Err(AnonOnionSendError::NoRendezvous);
        }

        let ads: Vec<_> = bodies
            .into_iter()
            .map(|body| veil_anonymity::rendezvous::RendezvousAd {
                receiver_node_id: body.receiver_node_id,
                rendezvous_node_id: body.rendezvous_node_id,
                auth_cookie: body.auth_cookie,
                receiver_x25519_pk: body.receiver_x25519_pk,
                valid_from_unix: 0,
                valid_until_unix: u64::MAX,
                issuer_pk: String::new(),
                issuer_algo: veil_types::SignatureAlgorithm::Ed25519,
                signature: Vec::new(),
                push_envelope: Vec::new(),
                capability_token: Vec::new(),
                wake_hmac_envelope: Vec::new(),
                rendezvous_kem_algo: 0,
                rendezvous_kem_pk: Vec::new(),
                wire_version: 0,
            })
            .collect();

        // Drop our OWN registrations for this service. A node can be both a
        // provider and a client of the same service — member content is exactly
        // that: adopting bytes makes a member a servable replica, and every
        // member derives the same service identity. Our own ad is then one of
        // the candidates, an anonymous send can pick it, and we answer our own
        // request holding nothing it asked for. Denials there are silent by
        // design, so the fetch could only ever time out.
        //
        // Matched on (rendezvous relay, cookie) like `withdraw_ephemeral_onion_
        // service` does, and scoped to THIS service identity so a legitimate
        // send to some other locally hosted service is untouched.
        let ads: Vec<_> = {
            let mine: Vec<([u8; 32], [u8; 16])> = {
                let services = lock!(self.anonymity.onion_services);
                services
                    .iter()
                    .filter(|entry| {
                        entry
                            .descriptor_identity_seed
                            .as_deref()
                            .map(|seed| {
                                veil_crypto::key_blinding::ed25519_public_from_seed(seed)
                                    == *service_identity_vk
                            })
                            .unwrap_or(false)
                    })
                    .filter_map(|entry| entry.relay_path.last().map(|r| (*r, entry.cookie)))
                    .collect()
            };
            ads.into_iter()
                .filter(|ad| {
                    !mine.iter().any(|(relay, cookie)| {
                        *relay == ad.rendezvous_node_id && *cookie == ad.auth_cookie
                    })
                })
                .collect()
        };
        // Being the only provider is not "no service" — but there is nobody
        // else to ask, and saying so at once beats a silent self-timeout.
        if ads.is_empty() {
            return Err(AnonOnionSendError::NoRendezvous);
        }

        let relay_keys: Vec<_> = ads
            .iter()
            .map(|ad| veil_anonymity::directory::relay_directory_dht_key(&ad.rendezvous_node_id))
            .collect();
        let resolved = futures::future::join_all(relay_keys.iter().map(|relay_key| async move {
            if self.dht.get_local(relay_key).is_some() {
                return None;
            }
            self.dht_recursive_get(*relay_key, RESOLVE_TIMEOUT)
                .await
                .map(|bytes| (*relay_key, bytes))
        }))
        .await;
        for (relay_key, bytes) in resolved.into_iter().flatten() {
            self.dht.store_local(relay_key, bytes);
        }
        // Short-lived on purpose, and the TTL is the whole safety argument: a
        // descriptor stays cryptographically valid after the service reconnects
        // onto a different rendezvous relay, and the old relay no longer holds
        // the cookie, so every introduce sent to it disappears without a word.
        self.anonymity
            .onion_resolve_cache
            .put(*service_identity_vk, ads.clone());
        // What a cache miss actually costs, so the value of caching it is a
        // measurement rather than an inference from the timeout constant.
        self.logger.info(
            "anonymity.onion_resolve.cold",
            format!(
                "service={} took_ms={} ads={}",
                veil_util::hex_short(service_identity_vk),
                resolve_started.elapsed().as_millis(),
                ads.len(),
            ),
        );
        Ok(ads)
    }

    /// Reply to a previously-received authenticated message via its one-time
    /// reply block. `reply_id` is the opaque handle the recipient app got
    /// alongside the inbound message; we look the daemon-side block up,
    /// reconstruct the original sender's rendezvous path from it, and send an
    /// authenticated anonymous message back — WITHOUT either side publishing a
    /// public ad (the whole point of the reply channel: no presence leak).
    ///
    /// The reply itself carries no further reply block (`reply = None`): a v1
    /// reply is terminal. The block is NON-consuming and valid until its TTL (1b),
    /// so a reply whose cell the network drops can be RETRIED with the same
    /// `reply_id`; delivery is at-least-once (the recipient de-dups). An unknown
    /// or TTL-expired id fails with `NoRendezvous`.
    pub async fn send_reply(
        &self,
        reply_id: u64,
        data: &[u8],
        hop_count: usize,
        src_app_id: [u8; 32],
    ) -> std::result::Result<(), veil_types::AnonOnionSendError> {
        use veil_types::AnonOnionSendError;
        // Per-fragment redundancy for the fire-and-forget reply (2).
        const REPLY_SEND_REDUNDANCY: usize = 3;

        const RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

        if self.identity.sovereign_identity.is_none() {
            return Err(AnonOnionSendError::NoIdentity);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Look up the reply block (NON-consuming — stays valid until TTL so the
        // app can retry if this reply's cell is dropped; 1b). gone/expired → no
        // reply path.
        // D3: only the app that received the original message (and was handed
        // this reply_id) may reply through it — peek enforces the owner binding.
        let Some(blocks) = self
            .anonymity
            .reply_block_store
            .peek(reply_id, src_app_id, now)
        else {
            return Err(AnonOnionSendError::NoRendezvous);
        };
        // `peek` never yields an empty list, so `blocks[0]` is sound below.
        let primary = &blocks[0];

        // Reconstruct the original sender's rendezvous path as a synthetic ad.
        // Only the four routing fields are read downstream
        // (`send_via_rendezvous_authenticated` → `send_sealed_introduce`); the
        // signed-ad fields are irrelevant here because the path came from a
        // signature-bound reply block, not a DHT lookup, so it needs no
        // re-verification. Validity bounds are set wide-open for the same reason.
        let synthetic = |block: &veil_proto::ReplyBlock| veil_anonymity::rendezvous::RendezvousAd {
            receiver_node_id: block.receiver_node_id,
            rendezvous_node_id: block.rendezvous_node_id,
            auth_cookie: block.auth_cookie,
            receiver_x25519_pk: block.x25519_pk,
            valid_from_unix: 0,
            valid_until_unix: u64::MAX,
            issuer_pk: String::new(),
            issuer_algo: veil_types::SignatureAlgorithm::Ed25519,
            signature: Vec::new(),
            push_envelope: Vec::new(),
            capability_token: Vec::new(),
            wake_hmac_envelope: Vec::new(),
            rendezvous_kem_algo: 0,
            rendezvous_kem_pk: Vec::new(),
            // Inert: the synthetic ad is never re-encoded or verified.
            wire_version: 0,
        };
        // One ad per DISTINCT rendezvous relay the original sender registered
        // under. `send_via_rendezvous_authenticated` round-robins a fragmented
        // reply across them, so the reply's aggregate throughput stops being one
        // relay's — duplicates would just funnel it back onto one endpoint.
        let mut ads: Vec<veil_anonymity::rendezvous::RendezvousAd> = Vec::new();
        for block in &blocks {
            if !ads
                .iter()
                .any(|a| a.rendezvous_node_id == block.rendezvous_node_id)
            {
                ads.push(synthetic(block));
            }
        }

        // Pre-resolve EVERY reply relay's directory entry into our local shard
        // so the onion build can reach it (same fix as `send_anonymous_*_to`).
        // A relay whose entry cannot be resolved is dropped rather than left to
        // fail the build: the remaining relays still carry the reply, and
        // keeping it would hand round-robin a hop it cannot route.
        let mut resolved: Vec<veil_anonymity::rendezvous::RendezvousAd> = Vec::new();
        for ad in ads {
            let relay_key =
                veil_anonymity::directory::relay_directory_dht_key(&ad.rendezvous_node_id);
            if self.dht.get_local(&relay_key).is_none()
                && let Some(bytes) = self.dht_recursive_get(relay_key, RESOLVE_TIMEOUT).await
            {
                self.dht.store_local(relay_key, bytes);
            }
            if self.dht.get_local(&relay_key).is_some() || resolved.is_empty() {
                // The first relay is kept even unresolved: it is the one the
                // pre-multi-block path always used, so dropping it would turn a
                // previously-working single-relay reply into `NoRendezvous`.
                resolved.push(ad);
            }
        }
        let ads = resolved;

        // Reverse-leg RD-staleness fix: the introduce cell `send_via_rendezvous_
        // authenticated` builds needs several DISTINCT relays whose RD is fresh
        // locally (`usable_relays` in `send_sealed_introduce`). On mobile we hold
        // ~one relay session, so `warm_connected_relay_directory` (session-only)
        // caches at most one RD → the guard falls back to a sessionless first hop
        // and the live-ACK evaporates (`guard_fallback` / `send_failed Missing`).
        // Actively pull the KNOWN relay set's RDs over whatever session exists so
        // the freshest-first pick has real candidates. Bounded + freshness-gated
        // (a no-op when already warm). The connected relay stays the guard's
        // preferred first hop; this just makes it — and the middles — RD-fresh.
        {
            let mut relays: Vec<[u8; 32]> = self
                .dht
                .routing_table_contacts()
                .into_iter()
                .map(|c| c.node_id)
                .collect();
            // Union in ACTIVE live-session relays too — the introduce/reply middle
            // selection draws from routing_table ∪ live_sessions, but this warm only
            // sourced the routing table, which thins to near-empty across Doze on
            // mobile while the seed sessions stay live. Mirror the selector's set so
            // the session-backed relays' RD is warmed for the middle pick. Freshness-
            // gated + capped ⇒ no-op (zero RPC) when already fresh.
            {
                let g = lock!(self.live_sessions);
                relays.extend(
                    g.values()
                        .filter(|i| i.state == crate::types::SessionState::Active)
                        .filter_map(|i| i.node_id.as_ref().map(|n| *n.as_bytes())),
                );
            }
            relays.sort_unstable();
            relays.dedup();
            relays.retain(|n| {
                service_tasks::peer_advertised_anonymity_relay(
                    &self.dispatcher.crypto.peer_cap_flags,
                    n,
                )
            });
            self.warm_known_relay_directory(&relays, 6, RESOLVE_TIMEOUT)
                .await;
        }

        self.send_via_rendezvous_authenticated(
            &ads[0],
            // Every extra relay the sender registered under. Empty on a
            // single-block reply, which is then byte-for-byte the old path.
            &ads[1..],
            primary.reply_app_id,
            primary.reply_endpoint_id,
            data,
            hop_count,
            None,
            // Replies are fire-and-forget with no end-to-end ack and a lossy
            // onion+circuit return path — send each fragment a few times; the
            // recipient de-dups (1b/2). Bounded so the amplification is small.
            REPLY_SEND_REDUNDANCY,
            true, // reply goes over the original sender's circuit-backed cookie (L3)
        )
        .await
        .map_err(|e| match e {
            veil_anonymity::sender::SenderError::MissingSenderIdentity => {
                AnonOnionSendError::NoIdentity
            }
            veil_anonymity::sender::SenderError::InsufficientRelayCandidates { .. } => {
                AnonOnionSendError::NoRelays
            }
            veil_anonymity::sender::SenderError::PayloadTooLarge { .. } => {
                AnonOnionSendError::PayloadTooLarge
            }
            _ => AnonOnionSendError::NoRelays,
        })
    }

    /// Seal `sealed_plaintext` (which already carries its `final_hop_kind` tag)
    /// to the ad's recipient, wrap it as an `IntroducePayload`, and onion-route
    /// it to the rendezvous relay as the Final hop. Shared by the plain
    /// ([`send_via_rendezvous`]) and authenticated
    /// ([`send_via_rendezvous_authenticated`]) rendezvous paths.
    pub(crate) fn send_sealed_introduce(
        &self,
        ad: &veil_anonymity::rendezvous::RendezvousAd,
        sealed_plaintext: &[u8],
        hop_count: usize,
        // When true (circuit-backed / location-anonymous service), the cleartext
        // `receiver_node_id` R reads is replaced by a cookie-derived pseudo-id so
        // R never learns the service's transport node_id (L3). The AuthDeliver
        // signature still binds the real id inside the seal.
        circuit_backed: bool,
    ) -> std::result::Result<(), veil_anonymity::sender::SenderError> {
        use veil_anonymity::rendezvous::{IntroducePayload, encrypt_introduce, final_hop_kind};

        // Step 2: seal to receiver_x25519_pk. Rendezvous cannot read
        // this — only the receiver after their `decrypt_introduce`.
        // encrypt_introduce only fails on AEAD library error (vanishingly
        // rare); treat as PayloadTooLarge for surface-level error
        // reporting (caller's recourse is the same: shrink payload or
        // retry).
        let ciphertext =
            encrypt_introduce(sealed_plaintext, &ad.receiver_x25519_pk).map_err(|_| {
                veil_anonymity::sender::SenderError::PayloadTooLarge {
                    hop_count,
                    got: sealed_plaintext.len(),
                    max: 0,
                }
            })?;

        // Step 3: wrap as IntroducePayload. For a circuit-backed service the
        // cleartext receiver_node_id is a cookie-derived pseudo-id (L3) — R
        // routes by cookie and never forwards this field to the service.
        let intro = IntroducePayload {
            receiver_node_id: if circuit_backed {
                circuit_backed_cleartext_id(&ad.auth_cookie)
            } else {
                ad.receiver_node_id
            },
            auth_cookie: ad.auth_cookie,
            ciphertext,
        };
        let intro_bytes =
            intro
                .encode()
                .map_err(|_| veil_anonymity::sender::SenderError::PayloadTooLarge {
                    hop_count,
                    got: sealed_plaintext.len(),
                    max: 0,
                })?;

        // Step 4: prepend final-hop kind tag.
        let mut payload_bytes = Vec::with_capacity(1 + intro_bytes.len());
        payload_bytes.push(final_hop_kind::INTRODUCE);
        payload_bytes.extend_from_slice(&intro_bytes);

        // Step 5: build + dispatch the onion cell with rendezvous_node_id
        // as the Final-hop target. Rendezvous's anonymity_x25519_pk
        // is needed for the outermost onion layer; we look it up from
        // its directory entry (shipped in).
        use veil_anonymity::{
            directory::{
                DEFAULT_FRESHNESS_WINDOW_SECS, discover_relay_hops_cached, relay_directory_dht_key,
            },
            sender::{DiversityOutcome, build_outbound_anonymous_cell_guarded},
        };
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Resolve rendezvous's directory entry to fetch its x25519_pk.
        let dht = Arc::clone(&self.dht);
        let candidates = vec![ad.rendezvous_node_id];
        let resolved = discover_relay_hops_cached(
            &candidates,
            |node_id| dht.get_local(&relay_directory_dht_key(node_id)),
            now_unix,
            DEFAULT_FRESHNESS_WINDOW_SECS,
            &self.anonymity.relay_entry_verify_cache,
        );
        let rendezvous_relay = match resolved.into_iter().next() {
            Some(r) => r,
            None => {
                // Rendezvous not in our DHT cache — same silent-drop
                // semantics as `send_anonymous` first-hop unreachable.
                return Ok(());
            }
        };

        // Snapshot relay candidates (excluding rendezvous itself —
        // rendezvous is the Final-hop, not a middle-hop).
        // W0 measurement: time selection vs build (see send_anonymous).
        let t_select = std::time::Instant::now();
        let mut candidate_node_ids: Vec<[u8; 32]> = self
            .dht
            .routing_table_contacts()
            .into_iter()
            .map(|c| c.node_id)
            .collect();
        // Union the live-session relays into the candidate pool (mirrors
        // `select_onion_relay_path_to`). A relay we hold a session to is the
        // guard's preferred first hop, but it only becomes a valid candidate here
        // if it appears in the pool AND its RD is fresh — the pre-warm at the
        // async call sites (`send_reply` / mailbox FETCH) makes the RD fresh; this
        // guarantees the relay is present even if it briefly dropped out of the
        // routing table between handshake and send.
        {
            let sessions = lock!(self.live_sessions);
            candidate_node_ids.extend(
                sessions
                    .values()
                    .filter(|i| i.state == crate::types::SessionState::Active)
                    .filter_map(|i| i.node_id.as_ref().map(|n| *n.as_bytes())),
            );
        }
        candidate_node_ids.sort_unstable();
        candidate_node_ids.dedup();
        candidate_node_ids.retain(|nid| *nid != ad.rendezvous_node_id);
        let usable_relays = discover_relay_hops_cached(
            &candidate_node_ids,
            |node_id| dht.get_local(&relay_directory_dht_key(node_id)),
            now_unix,
            DEFAULT_FRESHNESS_WINDOW_SECS,
            &self.anonymity.relay_entry_verify_cache,
        );

        // Vivaldi-based RTT estimator (same shape as send_anonymous).
        let local_vivaldi = self.dispatcher.local_vivaldi.clone();
        let peer_vivaldi = Arc::clone(&self.dispatcher.peer_vivaldi);
        let rtt_estimator = move |node_id: &[u8; 32]| -> Option<u32> {
            let local = local_vivaldi.as_ref()?;
            let peer_map = rlock!(peer_vivaldi);
            let (peer_coord, _) = peer_map.get(node_id)?;
            let local_guard = lock!(local);
            let estimated_ms = local_guard.distance_estimate(peer_coord) * 1000.0;
            if !estimated_ms.is_finite() || estimated_ms < 0.0 {
                return None;
            }
            Some(estimated_ms.min(u32::MAX as f64) as u32)
        };

        // Anti-censorship AS-diversity extractor (same shape as
        // send_anonymous) — see the helper comments in that function.
        let diversity_map = build_as_diversity_map(&self.discovered_peers_cache);
        let diversity_key_of =
            move |node_id: &[u8; 32]| -> Option<String> { diversity_map.get(node_id).cloned() };

        // Downweight relays with recorded failures (Epic 482.3/482.4 Phase A) —
        // see send_anonymous for rationale.
        let relay_reputation = Arc::clone(&self.anonymity.relay_reputation);
        let reputation_penalty_ms =
            move |node_id: &[u8; 32]| -> u32 { relay_reputation.rtt_penalty_ms(*node_id) };
        // First-hop liveness guard — same rationale as `send_anonymous_onion`:
        // the introduce cell dies silently if hops[0] has no live session, so
        // the guard slot prefers the live-session set (Tor-guard semantics).
        let live_first_hops: std::collections::HashSet<[u8; 32]> = self
            .dispatcher
            .session_tx_registry
            .as_ref()
            .map(|reg| rlock!(reg).active_node_ids())
            .unwrap_or_default();
        let first_hop_live = |node_id: &[u8; 32]| live_first_hops.contains(node_id);
        let select_us = t_select.elapsed().as_micros();
        let t_build = std::time::Instant::now();
        let ((first_hop_node_id, cell), diversity) = build_outbound_anonymous_cell_guarded(
            &payload_bytes,
            &usable_relays,
            rtt_estimator,
            diversity_key_of,
            reputation_penalty_ms,
            first_hop_live,
            ad.rendezvous_node_id,
            rendezvous_relay.hop.pubkey,
            hop_count,
        )?;
        if !live_first_hops.contains(&first_hop_node_id) {
            // Guard fallback: no live-session candidate in the pool — this
            // introduce rides the old sessionless-first-hop odds.
            log::debug!(
                "anonymity.first_hop.guard_fallback path=introduce first_hop={} \
                 live_sessions={} usable={}",
                veil_util::hex_short(&first_hop_node_id),
                live_first_hops.len(),
                usable_relays.len(),
            );
        }
        // W0 measurement (see send_anonymous).
        log::debug!(
            "anonymity.rendezvous.timing select_us={select_us} build_us={} \
             payload={} hops={hop_count} candidates={} usable={}",
            t_build.elapsed().as_micros(),
            payload_bytes.len(),
            candidate_node_ids.len(),
            usable_relays.len(),
        );
        if diversity == DiversityOutcome::DegradedToLatency {
            log::warn!(
                "anonymity.rendezvous.diversity_degraded hop_count={hop_count} \
                 candidates={} — no AS-diverse relay set; fell back to latency-only",
                usable_relays.len()
            );
        }

        use veil_proto::{
            codec::encode_header,
            family::{FrameFamily, RelayChainMsg},
            header::FrameHeader,
        };
        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
        hdr.body_len = cell.len() as u32;
        hdr.set_priority(veil_proto::priority::INTERACTIVE);
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(&cell[..]);
        if let Some(ref reg) = self.dispatcher.session_tx_registry {
            let guard = wlock!(reg);
            let sent =
                guard.send_to_result(&first_hop_node_id, veil_proto::priority::INTERACTIVE, frame);
            drop(guard);
            if let Err(e) = sent {
                // Introduce lost. Rare with the liveness guard above (session
                // died between snapshot and send, or TX queue Full). Log the
                // reason + record the failure; still fire-and-forget (see
                // send_anonymous — a synchronous error would leak first-hop
                // reachability).
                match e {
                    veil_session::SendToError::Missing => log::debug!(
                        "anonymity.first_hop.session_missing path=introduce first_hop={}",
                        veil_util::hex_short(&first_hop_node_id),
                    ),
                    _ => log::warn!(
                        "anonymity.first_hop.send_failed path=introduce reason={e:?} first_hop={}",
                        veil_util::hex_short(&first_hop_node_id),
                    ),
                }
                self.anonymity
                    .relay_reputation
                    .record_failure(first_hop_node_id);
            }
        }
        Ok(())
    }
}
