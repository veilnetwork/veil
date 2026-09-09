//! Joining the network, and noticing when you have fallen out of it.
//!
//! Two tasks that are one story told twice:
//!
//!  * [`NodeRuntime::spawn_bootstrap_task`] is the join — derive each seed's
//!    node id, dial it, ask FIND_NODE for our own id, keep what comes back,
//!    and hang up on anything the operator did not ask to stay connected to.
//!  * [`NodeRuntime::spawn_bootstrap_watchdog_task`] is the same walk again,
//!    later, when the peer count says the node has been partitioned off.
//!
//! Keeping them together is what stops the second from drifting from the
//! first. They must agree about which peers are candidates — a watchdog that
//! read `config.bootstrap_peers` directly had NOTHING to re-dial on a stock
//! install, because the seeds live in a list it never saw, and every such node
//! got no partition recovery at all. Both now go through
//! `resolve_bootstrap_candidates`, and that agreement is easier to keep when
//! the two are a file rather than nine hundred lines apart.
//!
//! Moved verbatim out of `service_tasks.rs` (report24 RUNTIME-3). Behaviour
//! is unchanged; the same inherent methods on the same type.

use std::sync::Arc;

use veil_util::lock;

use crate::types::{PeerConfigEntry, PeerId};

use super::service_tasks::{
    BOOTSTRAP_WATCHDOG_CHECK_INTERVAL, BOOTSTRAP_WATCHDOG_COOLDOWN,
    BOOTSTRAP_WATCHDOG_ZERO_STREAK_THRESHOLD, MAX_BOOTSTRAP_SEEDS_PER_SOURCE, WatchdogDecision,
    dns_seed_discovery_domain, evaluate_watchdog_tick, filter_already_known, filter_self_seeds,
    resolve_bootstrap_candidates,
};
use super::{
    NodeRuntime, derive_node_id_from_bootstrap_peer, lock_state, lock_tasks, supervised_spawn,
};

impl NodeRuntime {
    /// Spawn the bootstrap task.
    ///
    /// For each `BootstrapPeer` in config:
    /// 1. Derives the peer's node_id and adds it to the local DHT routing table.
    /// 2. Opens an outbound session to the bootstrap peer.
    /// 3. Sends FIND_NODE(local_node_id) via the DHT NetworkPeerQuerier.
    /// 4. Adds the returned contacts to the local DHT routing table.
    /// 5. Closes the session if the bootstrap peer is not in `config.peers`.
    pub fn spawn_bootstrap_task(&mut self, config: &veil_cfg::Config) {
        // A bootstrap node listed in `builtin_seeds` would otherwise try to
        // connect to itself when its config has no `bootstrap_peers` (the
        // normal state for seed deployments). Compare base64 pubkeys — same
        // encoding used in IdentityConfig and BootstrapPeer.
        let my_pubkey = self.identity.local_identity.public_key.clone();

        // 4th bootstrap fallback — peers we've personally
        // handshaken in a prior run. Loaded from disk into
        // `self.discovered_peers_cache`; here we splice them into the
        // `bootstrap_peers` list (deduplicated by pubkey) BEFORE the
        // builtin-seeds / DNS fallbacks run. Censor that takes down
        // (1) operator config + (2) builtin seeds + (3) DNS still
        // can't invalidate (4) without per-user blocking.
        let cached = filter_self_seeds(lock!(self.discovered_peers_cache).snapshot(), &my_pubkey);
        if !cached.is_empty() {
            let mut patched = config.clone();
            // Dedup against the operator-curated list using the same
            // helper the HTTPS layer uses so all
            // bootstrap layers share one dedup contract.
            let existing: std::collections::HashSet<String> = patched
                .bootstrap_peers
                .iter()
                .map(|p| p.public_key.clone())
                .collect();
            let added = filter_already_known(cached, &existing);
            if !added.is_empty() {
                self.logger.info(
                    "bootstrap.cache.augment",
                    format!(
                        "added {} discovered-peer(s) to bootstrap candidates (config has {})",
                        added.len(),
                        patched.bootstrap_peers.len(),
                    ),
                );
                patched.bootstrap_peers.extend(added);
                return self.spawn_bootstrap_task(&patched);
            }
        }

        // HTTPS bootstrap fetch. Runs UNCONDITIONALLY when
        // any URL is configured — operator may have stale
        // `bootstrap_peers` (censored IPs) AND a fresh HTTPS endpoint
        // returning rotated seeds. Each URL is fetched concurrently;
        // discovered peers are registered + dialed via the same
        // outbound-connector path the DNS layer uses.
        // Fail-closed gate (audit cycle-9 BOOT-UNPIN): without an issuer pin,
        // signed_preferred accepts ANY internally-valid bundle — an attacker
        // who controls the HTTPS origin (CDN/CA/hosting/mirror compromise)
        // can serve their own validly-signed seed list and the fetcher merges
        // it. A pin is the only author authentication. Refuse to fetch
        // unpinned bootstrap unless an operator explicitly opts in
        // (production → trusted_bundle_issuer_pubkey; dev/testnet →
        // allow_unpinned_signed_bootstrap). A signed envelope is always
        // required; the knob that accepted raw JSON is gone.
        let https_urls_present = !config.global.bootstrap_https_urls.is_empty();
        let https_pinned_or_opted_in = config.global.trusted_bundle_issuer_pubkey.is_some()
            || config.global.allow_unpinned_signed_bootstrap;
        if https_urls_present && !https_pinned_or_opted_in {
            self.logger.error(
                "bootstrap.https.fail_closed",
                format!(
                    "{} HTTPS bootstrap URL(s) configured without \
                     trusted_bundle_issuer_pubkey — refusing to fetch unpinned bootstrap \
                     (an HTTPS-origin compromise could serve a validly-signed attacker \
                     bundle). Set trusted_bundle_issuer_pubkey for production, or \
                     allow_unpinned_signed_bootstrap = true for dev/testnet.",
                    config.global.bootstrap_https_urls.len(),
                ),
            );
        }
        // BOOT-UNPIN scope fix (diff-audit 2026-06-12): gate ONLY the HTTPS
        // fetch. The prior `return` here exited the WHOLE task, so a node with
        // valid bootstrap_peers + one unpinned HTTPS URL lost ALL startup
        // bootstrap (configured peers / DNS / builtin seeds below). Those must
        // still run when the HTTPS branch is refused.
        if https_urls_present && https_pinned_or_opted_in {
            let logger = self.logger.clone();
            let urls = config.global.bootstrap_https_urls.clone();
            let transport_ctx = self.transport_ctx.clone();
            // Policy (the unpinned-without-opt-in case already failed closed
            // above): pinned issuer → signed-required + pin, which authenticates
            // the bundle author; otherwise signed_preferred, which verifies the
            // envelope's self-embedded key only (NO author authentication —
            // dev/testnet opt-in, gated above).
            let bootstrap_policy = match config.global.trusted_bundle_issuer_pubkey.as_deref() {
                Some(pk) => veil_bootstrap::https::BootstrapHttpsPolicy::signed_required(pk),
                None => veil_bootstrap::https::BootstrapHttpsPolicy::signed_preferred(),
            };
            // 481.4: `.onion` URLs in the list are routed through this Tor
            // SOCKS proxy (plaintext HTTP over the Tor circuit); clearnet URLs
            // ignore it.  The issuer pin (if any) is reused for `.onion`
            // signature verification, which is always required.
            let bootstrap_tor_proxy = config.global.bootstrap_tor_socks_proxy.clone();
            let bootstrap_issuer_pk = config.global.trusted_bundle_issuer_pubkey.clone();
            let state = Arc::clone(&self.state);
            let dht = Arc::clone(&self.dht);
            let access = self.access();
            let shutdown_tx = self.shutdown_tx.clone();
            let tasks = Arc::clone(&self.tasks);
            let my_pubkey_async = my_pubkey.clone();
            // Snapshot every pubkey we already know about (operator-curated
            // bootstrap_peers + configured peers + cache). Captured here
            // SYNCHRONOUSLY so we don't race against concurrent reloads /
            // cache upserts inside the spawned task. Snapshot is one-shot
            // — peers added AFTER the HTTPS fetch task starts won't be
            // deduped, but that race is benign (worst case: one extra dial).
            let mut known_pubkeys: std::collections::HashSet<String> = config
                .bootstrap_peers
                .iter()
                .map(|p| p.public_key.clone())
                .collect();
            for p in &config.peers {
                known_pubkeys.insert(p.public_key.clone());
            }
            for cached in lock!(self.discovered_peers_cache).snapshot() {
                known_pubkeys.insert(cached.public_key);
            }
            let handle = supervised_spawn(
                Arc::clone(&self.logger),
                "bootstrap_https",
                async move {
                    // Multi-URL fetch with failover. The pure
                    // function lives in `node/bootstrap/https.rs` so it can
                    // be unit-tested with a stub fetcher; here we just
                    // close over `transport_ctx` to bind it to real HTTPS.
                    let aggregated =
                        {
                            let ctx_ref = &transport_ctx;
                            let policy_ref = &bootstrap_policy;
                            let tor_proxy_ref = bootstrap_tor_proxy.as_deref();
                            let issuer_pk_ref = bootstrap_issuer_pk.as_deref();
                            veil_bootstrap::https::aggregate_seeds_via_failover(
                                &urls,
                                move |url: &str| {
                                    let url = url.to_owned();
                                    async move {
                                        use veil_bootstrap::https::BootstrapRoute;
                                        // 481.4: route `.onion` URLs through the Tor
                                        // SOCKS proxy (plaintext HTTP over Tor +
                                        // mandatory signed bundle); clearnet URLs use
                                        // the PKI-verified HTTPS path as before. The
                                        // decision is the pure `classify_bootstrap_url`.
                                        match veil_bootstrap::https::classify_bootstrap_url(
                                        &url,
                                        tor_proxy_ref,
                                    ) {
                                        BootstrapRoute::Tor(proxy) => {
                                            veil_bootstrap::https::fetch_seeds_via_tor(
                                                &url, proxy, issuer_pk_ref,
                                            )
                                            .await
                                        }
                                        BootstrapRoute::OnionNoProxy => Err(
                                            veil_bootstrap::https::HttpsBootstrapError::Transport(
                                                format!(
                                                    "skipping .onion bootstrap URL `{url}`: set \
                                                     [global] bootstrap_tor_socks_proxy (e.g. \
                                                     socks5://127.0.0.1:9050) to enable Tor"
                                                ),
                                            ),
                                        ),
                                        BootstrapRoute::Clearnet => {
                                            veil_bootstrap::https::fetch_seeds_https_with_policy(
                                                &url, ctx_ref, policy_ref,
                                            )
                                            .await
                                        }
                                    }
                                    }
                                },
                            )
                            .await
                        };
                    for (url, count) in &aggregated.per_url_seed_counts {
                        logger.info(
                            "bootstrap.https.found",
                            format!("{count} seed(s) from {url}"),
                        );
                    }
                    for (url, err) in &aggregated.per_url_errors {
                        logger.warn(
                            "bootstrap.https.fetch_failed",
                            format!("url={url} err={err}"),
                        );
                    }
                    let all_seeds = aggregated.seeds;
                    // Filter chain: drop self, drop pubkeys already known to
                    // the runtime (operator config, configured peers, cache)
                    // then dedupe within the HTTPS results themselves
                    // (operator may host the same peer at multiple CDN
                    // endpoints for redundancy).
                    let pre_filter_count = all_seeds.len();
                    let after_self = filter_self_seeds(all_seeds, &my_pubkey_async);
                    let after_known = filter_already_known(after_self, &known_pubkeys);
                    let mut seen: std::collections::HashSet<String> =
                        std::collections::HashSet::new();
                    let seeds: Vec<_> = after_known
                        .into_iter()
                        .filter(|p| seen.insert(p.public_key.clone()))
                        .collect();
                    if seeds.len() < pre_filter_count {
                        logger.info(
                        "bootstrap.https.dedup",
                        format!(
                            "dropped {} duplicate / self / already-known peer(s) from HTTPS bundle",
                            pre_filter_count - seeds.len(),
                        ),
                    );
                    }
                    if seeds.is_empty() {
                        return;
                    }
                    if seeds.len() > MAX_BOOTSTRAP_SEEDS_PER_SOURCE {
                        logger.warn(
                            "bootstrap.https.capped",
                            format!(
                                "dialing {} of {} HTTPS-discovered seeds (per-source cap, anti-eclipse)",
                                MAX_BOOTSTRAP_SEEDS_PER_SOURCE,
                                seeds.len(),
                            ),
                        );
                    }
                    // HTTPS_SEEDS_BASE namespace — sits between DNS and the
                    // synthetic/gateway range (>= GATEWAY_SYNTHETIC) so the
                    // discovered-peer cache skips these too. Distinct from
                    // APP_ADDED_BASE (cycle-7 M3: the two used to collide on
                    // 0x8800_0000); see `types::synthetic_peer_id`.
                    for (i, bp) in seeds
                        .iter()
                        .take(MAX_BOOTSTRAP_SEEDS_PER_SOURCE)
                        .enumerate()
                    {
                        let Some(node_id_bytes) = derive_node_id_from_bootstrap_peer(bp) else {
                            continue;
                        };
                        let hex = veil_util::hex_str(&node_id_bytes);
                        let Ok(node_id) = <veil_cfg::NodeId as std::str::FromStr>::from_str(&hex)
                        else {
                            continue;
                        };

                        dht.add_contact(veil_dht::routing::Contact::new(
                            node_id_bytes,
                            &bp.transport,
                        ));

                        let peer_id = PeerId::new(
                            crate::types::synthetic_peer_id::HTTPS_SEEDS_BASE
                                .wrapping_add(i as u32),
                        );
                        let entry = PeerConfigEntry {
                            peer_id,
                            node_id,
                            public_key: bp.public_key.clone(),
                            nonce: bp.nonce.clone(),
                            transport: bp.transport.clone(),
                            algo: bp.algo,
                            tls_cert: bp.tls_cert.clone(),
                            tls_key: None,
                            tls_ca_cert: bp.tls_ca_cert.clone(),
                            bootstrap_only: true,
                            source: crate::types::PeerSource::Bootstrap,
                        };
                        lock_state(&state).peers.insert(peer_id, entry.clone());
                        if let Some(ref stx) = shutdown_tx {
                            let handles = crate::outbound_connector::spawn_outbound_peers(
                                vec![entry],
                                &access,
                                stx,
                            );
                            lock_tasks(&tasks).sessions.extend(handles);
                        }
                    }
                },
            );
            lock_tasks(&self.tasks).sessions.push(handle);
        }

        // Splice in whatever the builtin-seed policy contributes. Under `Auto`
        // this reproduces the historical either/or (seeds only when nothing is
        // configured); under `Always` the seeds ride ALONGSIDE the operator's
        // own entry points instead of being switched off by them, which is the
        // only way a node can hold both a seed set and an alternative to it.
        //
        // Terminates because `resolve_bootstrap_candidates` is a fixed point:
        // on the recursive call its output already IS `bootstrap_peers`, so
        // the length stops growing and we fall through. Pinned by
        // `resolving_twice_is_a_fixed_point`.
        let resolved = resolve_bootstrap_candidates(config, &my_pubkey);
        if resolved.len() > config.bootstrap_peers.len() {
            self.logger.info(
                "bootstrap.builtin",
                format!(
                    "dialing {} entry point(s): {} configured + {} builtin seed(s) \
                     (policy={})",
                    resolved.len(),
                    config.bootstrap_peers.len(),
                    resolved.len() - config.bootstrap_peers.len(),
                    config.global.builtin_seed_policy,
                ),
            );
            let mut patched = config.clone();
            // Assignment is safe ONLY because `resolved` already carries the
            // configured entries; the previous code assigned the builtin list
            // alone, which is what dropped them.
            patched.bootstrap_peers = resolved;
            return self.spawn_bootstrap_task(&patched);
        }

        // if both peers and bootstrap_peers are empty, try DNS discovery as
        // the last fallback — but only against a domain the operator actually
        // named. See `dns_seed_discovery_domain`.
        if let Some(domain) = dns_seed_discovery_domain(config) {
            // No builtin seeds — try DNS discovery asynchronously.
            let logger = self.logger.clone();
            let state = Arc::clone(&self.state);
            let dht = Arc::clone(&self.dht);
            let access = self.access();
            let shutdown_tx = self.shutdown_tx.clone();
            let tasks = Arc::clone(&self.tasks);
            let my_pubkey_async = my_pubkey.clone();
            // What this operator will accept from an unsigned TXT record. No
            // pins and the last resort allowed is the default, which is what
            // every existing config says (report14 V14-M9).
            let dns_policy = veil_bootstrap::DnsBootstrapPolicy {
                pinned_public_keys: config.global.bootstrap_dns_pinned_keys.clone(),
                allow_unsigned_system_dns: config.global.bootstrap_dns_allow_system,
            };
            let handle = supervised_spawn(Arc::clone(&self.logger), "bootstrap_dns", async move {
                let seeds = filter_self_seeds(
                    veil_bootstrap::discover_seeds_dns_with_policy(&domain, &dns_policy).await,
                    &my_pubkey_async,
                );
                if seeds.is_empty() {
                    logger.info(
                        "bootstrap.dns.empty",
                        format!("no seeds from DNS domain={domain}"),
                    );
                    return;
                }
                logger.info(
                    "bootstrap.dns.found",
                    format!("{} seed(s) from DNS domain={domain}", seeds.len()),
                );
                if seeds.len() > MAX_BOOTSTRAP_SEEDS_PER_SOURCE {
                    logger.warn(
                        "bootstrap.dns.capped",
                        format!(
                            "dialing {} of {} DNS-discovered seeds (per-source cap, anti-eclipse)",
                            MAX_BOOTSTRAP_SEEDS_PER_SOURCE,
                            seeds.len(),
                        ),
                    );
                }
                // Register and connect to each discovered seed.
                for (i, bp) in seeds
                    .iter()
                    .take(MAX_BOOTSTRAP_SEEDS_PER_SOURCE)
                    .enumerate()
                {
                    let Some(node_id_bytes) = derive_node_id_from_bootstrap_peer(bp) else {
                        continue;
                    };
                    let hex = veil_util::hex_str(&node_id_bytes);
                    let Ok(node_id) = <veil_cfg::NodeId as std::str::FromStr>::from_str(&hex)
                    else {
                        continue;
                    };

                    dht.add_contact(veil_dht::routing::Contact::new(
                        node_id_bytes,
                        &bp.transport,
                    ));

                    let peer_id = PeerId::new(0x8000_0000u32.wrapping_add(i as u32));
                    let entry = PeerConfigEntry {
                        peer_id,
                        node_id,
                        public_key: bp.public_key.clone(),
                        nonce: bp.nonce.clone(),
                        transport: bp.transport.clone(),
                        algo: bp.algo,
                        tls_cert: bp.tls_cert.clone(),
                        tls_key: None,
                        tls_ca_cert: bp.tls_ca_cert.clone(),
                        bootstrap_only: true,
                        source: crate::types::PeerSource::Bootstrap,
                    };
                    lock_state(&state).peers.insert(peer_id, entry.clone());
                    if let Some(ref stx) = shutdown_tx {
                        let handles = crate::outbound_connector::spawn_outbound_peers(
                            vec![entry],
                            &access,
                            stx,
                        );
                        lock_tasks(&tasks).sessions.extend(handles);
                    }
                }
            });
            lock_tasks(&self.tasks).sessions.push(handle);
            return;
        }
        if config.bootstrap_peers.is_empty() {
            // Nothing to dial and nothing to discover. This is a legitimate
            // resting state — a node whose owner declined the builtin seeds
            // and named no entry points of its own is meant to come up
            // OFFLINE AND ALIVE, not to abort and not to be quietly re-seeded.
            // Say so once, so "no network" reads as a decision in the log
            // rather than as a silent failure.
            if config.peers.is_empty() {
                self.logger.info(
                    "bootstrap.none",
                    format!(
                        "no entry points: 0 configured, builtin seeds {} \
                         (policy={}), DNS discovery {}; node stays offline \
                         until a peer is added",
                        if matches!(
                            config.global.builtin_seed_policy,
                            veil_cfg::BuiltinSeedPolicy::Never
                        ) {
                            "refused"
                        } else {
                            "unavailable"
                        },
                        config.global.builtin_seed_policy,
                        match config.global.bootstrap_dns_domain {
                            Some(ref d) => format!("found nothing at {d}"),
                            None => "not configured".to_owned(),
                        },
                    ),
                );
            }
            return;
        }

        // Collect node_id bytes for all peers in config.peers so we can
        // distinguish bootstrap-only peers from regular configured peers.
        let bootstrap_node_ids: std::collections::HashSet<[u8; 32]> = config
            .peers
            .iter()
            .filter_map(|p| veil_cfg::NodeId::from_public_key(p.algo, &p.public_key).ok())
            .map(|id| *id.as_bytes())
            .collect();

        for (i, bp) in config.bootstrap_peers.iter().enumerate() {
            if bp.public_key == my_pubkey {
                self.logger.info(
                    "bootstrap.skip_self",
                    format!(
                        "skipping bootstrap_peer with our own public_key (transport={})",
                        veil_util::redact_addr_for_log(&bp.transport)
                    ),
                );
                continue;
            }
            let Some(node_id_bytes) = derive_node_id_from_bootstrap_peer(bp) else {
                self.logger.warn(
                    "bootstrap.bad_peer",
                    format!("cannot derive node_id from public_key={}", bp.public_key),
                );
                continue;
            };

            let hex = veil_util::hex_str(&node_id_bytes);
            let Ok(node_id) = <veil_cfg::NodeId as std::str::FromStr>::from_str(&hex) else {
                continue;
            };

            // Add to DHT routing table so iterative lookups can reach it.
            self.dht.add_contact(veil_dht::routing::Contact::new(
                node_id_bytes,
                &bp.transport,
            ));

            self.logger.info(
                "bootstrap.contact_added",
                format!(
                    "transport={} node_id={}",
                    veil_util::redact_addr_for_log(&bp.transport),
                    veil_util::hex_short(&node_id_bytes)
                ),
            );

            let is_bootstrap_only = !bootstrap_node_ids.contains(&node_id_bytes);
            if !is_bootstrap_only {
                // Already a regular configured peer — outbound connector handles it.
                continue;
            }

            // Synthetic peer_id for bootstrap-only peers: high bit set to avoid
            // conflicts with configured peer IDs (which are typically small integers).
            let peer_id = PeerId::new(0x8000_0000u32.wrapping_add(i as u32));

            let entry = PeerConfigEntry {
                peer_id,
                node_id,
                public_key: bp.public_key.clone(),
                nonce: bp.nonce.clone(),
                transport: bp.transport.clone(),
                algo: bp.algo,
                tls_cert: bp.tls_cert.clone(),
                tls_key: None,
                tls_ca_cert: bp.tls_ca_cert.clone(),
                bootstrap_only: true,
                source: crate::types::PeerSource::Bootstrap,
            };

            self.logger.info(
                "bootstrap.connecting",
                format!(
                    "transport={} node_id={}",
                    veil_util::redact_addr_for_log(&bp.transport),
                    veil_util::hex_short(&node_id_bytes)
                ),
            );

            // Register in state so connect_peer_active can find the peer config.
            lock_state(&self.state).peers.insert(peer_id, entry.clone());

            if let Some(ref shutdown_tx) = self.shutdown_tx {
                let handles = crate::outbound_connector::spawn_outbound_peers(
                    vec![entry],
                    &self.access(),
                    shutdown_tx,
                );
                lock_tasks(&self.tasks).sessions.extend(handles);
            }
        }
    }

    /// Spawn the bootstrap watchdog — partition-recovery loop.
    ///
    /// `spawn_bootstrap_task` runs once at startup and the outbound
    /// connectors it creates are `bootstrap_only=true`, meaning the
    /// connector task terminates when the first session ends. If the
    /// cluster later fragments (every direct session torn down through
    /// some combination of bans, network split, or peer crashes), the
    /// daemon is stuck "online but isolated": `dht.republish` emits
    /// `under_count fan-out=0` indefinitely, but nothing re-dials the
    /// operator-curated `bootstrap_peers` list to recover.
    ///
    /// This watchdog samples `live_sessions.len` every
    /// `CHECK_INTERVAL`. After `ZERO_STREAK_THRESHOLD` consecutive
    /// zero-session ticks (≈ 90 s by default — long enough that a brief
    /// network blip doesn't trip a needless re-dial), it respawns the
    /// outbound connectors for the operator-configured bootstrap peers.
    /// A `COOLDOWN` between retries prevents a thundering herd if the
    /// bootstrap hosts themselves are temporarily unreachable.
    ///
    /// Only the *statically known* entry points are re-dialed: the
    /// operator-curated `bootstrap_peers` plus whatever the builtin-seed
    /// policy contributes ([`resolve_bootstrap_candidates`]). DNS / HTTPS /
    /// cache fallbacks are deliberately skipped here because they're
    /// discovery mechanisms for *initial* bootstrap; they belong in startup,
    /// not in steady-state partition recovery.
    /// Bootstrap layer 7: find peers through BitTorrent's Mainline DHT.
    ///
    /// Three states, because the right answer differs by what the node is —
    /// see `global.mainline_discovery`. `Fallback` runs only when nothing else
    /// offers a way in, which is the state an app should be in; `Always` runs
    /// regardless, which is what an operator sets on a node they run.
    ///
    /// Announcing is a separate decision and stays with `global.bootstrap`:
    /// looking costs a little exposure to the DHT nodes asked, being listed
    /// costs exposure to everyone.
    pub fn spawn_bootstrap_watchdog_task(&mut self, config: &veil_cfg::Config) {
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        // Resolve the same candidate set `spawn_bootstrap_task` dials rather
        // than reading `config.bootstrap_peers` directly. A node running on
        // builtin seeds has that field EMPTY — the seeds are spliced into a
        // local clone that never reaches here — so the old early-return
        // disabled partition recovery for exactly the nodes that had no other
        // way back: every stock install with no operator-curated list.
        let bootstrap_peers =
            resolve_bootstrap_candidates(config, &self.identity.local_identity.public_key);
        if bootstrap_peers.is_empty() {
            // Nothing to retry — no operator list and no builtin contribution.
            return;
        }

        let mut shutdown_rx = shutdown_tx.subscribe();
        let shutdown_tx_clone = shutdown_tx.clone();
        let logger = Arc::clone(&self.logger);
        let live_sessions = Arc::clone(&self.live_sessions);
        let state = Arc::clone(&self.state);
        let dht = Arc::clone(&self.dht);
        let access = self.access();
        let tasks = Arc::clone(&self.tasks);
        let metrics = self.metrics.clone();
        let my_pubkey = self.identity.local_identity.public_key.clone();

        let handle = supervised_spawn(Arc::clone(&self.logger), "bootstrap_watchdog", async move {
            let mut interval = tokio::time::interval(BOOTSTRAP_WATCHDOG_CHECK_INTERVAL);
            interval.tick().await; // skip immediate first tick
            let mut zero_streak: u32 = 0;
            let mut last_retry: Option<tokio::time::Instant> = None;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let session_count = veil_util::lock!(live_sessions).len();
                        let prev_streak = zero_streak;
                        zero_streak = if session_count == 0 {
                            zero_streak.saturating_add(1)
                        } else {
                            0
                        };
                        let decision = evaluate_watchdog_tick(
                            session_count,
                            zero_streak,
                            BOOTSTRAP_WATCHDOG_ZERO_STREAK_THRESHOLD,
                            last_retry.map(|t| t.elapsed()),
                            BOOTSTRAP_WATCHDOG_COOLDOWN,
                        );
                        match decision {
                            WatchdogDecision::Idle => {
                                if prev_streak > 0 {
                                    logger.info(
                                        "bootstrap.watchdog.recovered",
                                        format!(
                                            "session count back to {} after {} zero-tick(s)",
                                            session_count, prev_streak,
                                        ),
                                    );
                                }
                                continue;
                            }
                            WatchdogDecision::Wait => continue,
                            WatchdogDecision::Retry => {}
                        }

                        logger.warn(
                            "bootstrap.watchdog.retry",
                            format!(
                                "zero sessions for {}s — re-dialing {} bootstrap peer(s)",
                                zero_streak.saturating_mul(
                                    BOOTSTRAP_WATCHDOG_CHECK_INTERVAL.as_secs() as u32,
                                ),
                                bootstrap_peers.len(),
                            ),
                        );
                        if let Some(m) = metrics.as_ref() {
                            m.inc_bootstrap_watchdog_retries();
                        }
                        last_retry = Some(tokio::time::Instant::now());

                        for (i, bp) in bootstrap_peers.iter().enumerate() {
                            if bp.public_key == my_pubkey {
                                continue;
                            }
                            let Some(node_id_bytes) = derive_node_id_from_bootstrap_peer(bp)
                            else {
                                continue;
                            };
                            let hex = veil_util::hex_str(&node_id_bytes);
                            let Ok(node_id) =
                                <veil_cfg::NodeId as std::str::FromStr>::from_str(&hex)
                            else {
                                continue;
                            };

                            dht.add_contact(veil_dht::routing::Contact::new(
                                node_id_bytes,
                                &bp.transport,
                            ));

                            let peer_id =
                                PeerId::new(0x8000_0000u32.wrapping_add(i as u32));
                            let entry = PeerConfigEntry {
                                peer_id,
                                node_id,
                                public_key: bp.public_key.clone(),
                                nonce: bp.nonce.clone(),
                                transport: bp.transport.clone(),
                                algo: bp.algo,
                                tls_cert: bp.tls_cert.clone(),
                                tls_key: None,
                                tls_ca_cert: bp.tls_ca_cert.clone(),
                                bootstrap_only: true,
                                source: crate::types::PeerSource::Bootstrap,
                            };
                            lock_state(&state).peers.insert(peer_id, entry.clone());

                            let handles =
                                crate::outbound_connector::spawn_outbound_peers(
                                    vec![entry],
                                    &access,
                                    &shutdown_tx_clone,
                                );
                            // Funnel through push_session_handle so the
                            // 256-entry prune-on-overflow logic catches
                            // the stale JoinHandles from prior retry
                            // waves; raw `extend` bypasses pruning and
                            // grows the Vec linearly with retry count.
                            {
                                let mut t = lock_tasks(&tasks);
                                if t.sessions.len() + handles.len() >= 256 {
                                    t.sessions.retain(|h| !h.is_finished());
                                }
                                t.sessions.extend(handles);
                            }
                        }
                    }
                    Ok(_) = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }
}
