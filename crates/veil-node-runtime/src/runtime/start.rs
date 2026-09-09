//! Bringing a node up: one method, and the order everything happens in.
//!
//! [`NodeRuntime::start`] is fifteen hundred lines because starting a node is
//! fifteen hundred lines of ordering, and the ordering is the content. The
//! identity has to exist before anything can be signed with it; the listeners
//! have to be bound before their ports can be announced; the dispatcher has to
//! be running before a session can hand it a frame; the discovery layers must
//! not publish before the operator's opt-in has been read. Nearly every line
//! here is a step that has to come after the one above it and before the one
//! below, which is why it is a sequence rather than a set of helpers.
//!
//! Splitting it into stages was NOT done. A stage boundary in the middle of a
//! sequence like this is a promise that the two halves are independent, and
//! they are not — the second half reads a dozen bindings the first half made.
//! Faking that independence by threading a context struct through would move
//! the ordering into a type without making it any easier to check.
//!
//! So the file is the honest unit: `mod.rs` no longer carries the boot
//! sequence in the middle of the type's other three hundred methods, and the
//! sequence is readable end to end on its own (report24 RUNTIME-3). Moved
//! verbatim; behaviour unchanged.

use super::*;

impl NodeRuntime {
    pub async fn start(config_path: impl AsRef<Path>, foreground_mode: bool) -> Result<Self> {
        let config_path = config_path.as_ref().to_path_buf();
        let config = veil_cfg::load_config(&config_path)?;

        // Fail fast if the config has structural or identity issues. Under the
        // production-hardening profile (`[global].strict_config_validation`),
        // also treat the risky-but-permitted advisories (push wake-HMAC, mailbox
        // capability tokens, unsigned DHT store, …) as fatal so the daemon
        // refuses to start on an unsafe production posture.
        let validation = if config.global.strict_config_validation {
            veil_cfg::validate_strict(&config)
        } else {
            veil_cfg::validate(&config)
        };
        if !validation.is_valid() {
            return Err(NodeError::Config(veil_cfg::ConfigError::ValidationFailed(
                validation.format_issues(),
            )));
        }

        let logger = Arc::new(veil_cfg::observability_glue::logger_from_config(&config)?);

        #[cfg(windows)]
        if let Err(error) = veil_util::outbound_interface::pin_current_default_interfaces() {
            logger.warn(
                "network.outbound_interface_pin_failed",
                format!("error={error}"),
            );
        }

        // Pin the process address space in RAM against swap-out before
        // loading any key material. `mlockall(MCL_CURRENT | MCL_FUTURE)`
        // covers ALL future allocations, including key bytes inside
        // upstream crates (chacha20poly1305 internal GenericArray,
        // ed25519_dalek SigningKey seed) that cannot be reached with
        // per-buffer wrappers. Linux only; macOS / Windows / *BSD log
        // as "unsupported" and continue with swap risk accepted.
        //
        // Failure path: log a warn but DO NOT refuse to start. Cheap
        // VPS deployments may run without `LimitMEMLOCK=infinity`; refusing
        // to boot would break those deployments. Operators raising
        // sustained-load servers should set `ulimit -l unlimited` (or
        // `LimitMEMLOCK=infinity` in systemd unit) and check the log line
        // confirms `Locked`.
        match veil_util::mlock::try_mlockall_current_future() {
            veil_util::mlock::MlockallOutcome::Locked => {
                logger.info(
                    "node.mlock.success",
                    "process address space pinned in RAM (swap protection active)",
                );
            }
            veil_util::mlock::MlockallOutcome::Unsupported => {
                logger.info(
                    "node.mlock.unsupported",
                    "mlockall not supported on this platform; key material may swap to disk",
                );
            }
            veil_util::mlock::MlockallOutcome::BudgetExhausted { errno_str } => {
                logger.warn(
                    "node.mlock.budget_exhausted",
                    format!(
                        "mlockall failed ({errno_str}): RLIMIT_MEMLOCK too low. \
                         Set `LimitMEMLOCK=infinity` in systemd unit OR `ulimit -l unlimited`. \
                         Key material remains swappable until raised."
                    ),
                );
            }
            veil_util::mlock::MlockallOutcome::PermissionDenied => {
                logger.warn(
                    "node.mlock.permission_denied",
                    "mlockall denied (missing CAP_IPC_LOCK in container?). \
                     Key material remains swappable.",
                );
            }
            veil_util::mlock::MlockallOutcome::Other(msg) => {
                logger.warn(
                    "node.mlock.unexpected_error",
                    format!("mlockall failed: {msg}. Key material remains swappable."),
                );
            }
        }

        let transport_ctx = Arc::new(veil_cfg::transport_glue::context_from_config(&config)?);
        let local_identity = Arc::new(HandshakeIdentity::from_config(&config)?);

        // veil_dir is home to the identity files (`device_identity_sk.bin`,
        // `mlkem.key`) read by the sovereign load and the ML-KEM key resolution.
        // The ML-KEM keypair is resolved AFTER the sovereign auto-load below
        // (not here), because its identity-derived path needs
        // `device_identity_sk.bin`, which the standalone-identity build writes
        // during that auto-load.
        //
        // Normally the config file's own directory. `[global] identity_dir`
        // overrides it, and an EMBEDDED host has to use that: deferred init
        // stages the config in a per-boot temp directory this crate creates and
        // scrubs, so a host that provisions an identity of its own has nowhere
        // to put it and would silently get the degenerate document instead.
        let veil_dir_path = config.identity_dir_for(&config_path);

        // sovereign-identity auto-load. Three paths:
        //
        // 1. `identity_document.bin` exists on disk → load it. Multi-device
        // identity provisioned via `identity create` / `pair-accept` /
        // `restore` lives here.
        //
        // 2. No `identity_document.bin` but the `[identity]` config block
        // has an Ed25519 keypair AND no master keypair has been
        // provisioned → build a degenerate "standalone" document
        // where master_pk == device_pk, persist it to disk, then
        // treat it like any other `IdentityDocument`. This is the
        // default UX for single-device users; the rest of the runtime
        // sees a normal document and doesn't branch on standalone-ness.
        //
        // 3. Falcon-512 nodes (or anything else without an Ed25519
        // `local_signing_key`) fall through to legacy `None` mode —
        // same behaviour as before this commit.
        let sovereign_identity: Option<Arc<veil_identity::sovereign::SovereignIdentity>> = {
            let doc_path = veil_dir_path.join(veil_identity::sovereign::IDENTITY_DOCUMENT_FILE);
            if doc_path.exists() {
                match veil_identity::sovereign::SovereignIdentity::load_from_dir(&veil_dir_path) {
                    Ok(sov) => {
                        logger.info(
                            "node.sovereign_identity.loaded",
                            format!(
                                "node_id={} instance_id={}",
                                veil_util::bytes_to_hex(sov.node_id()),
                                veil_util::bytes_to_hex(&sov.active_instance_id()),
                            ),
                        );
                        Some(Arc::new(sov))
                    }
                    Err(e) if config.global.allow_identity_fallback => {
                        // Explicitly permitted: the operator asked for a node
                        // that comes up even with a broken document, e.g. to
                        // reach `veil-cli identity restore` on a host they
                        // cannot otherwise log into.
                        logger.warn(
                            "node.sovereign_identity.load_failed",
                            format!(
                                "{e} — running as legacy node_id-keyed \
                                 (allow_identity_fallback = true)"
                            ),
                        );
                        None
                    }
                    Err(e) => {
                        // Fail closed. A MISSING document is ordinary and still
                        // starts the node as legacy — that path is untouched.
                        // A document that exists and does not load is a
                        // different thing: the operator provisioned an
                        // identity, it is on disk, and it is broken.
                        //
                        // Continuing ran the node under a DIFFERENT identity
                        // binding than the one its operator installed — peers
                        // see an unrelated legacy node, multi-device pairing
                        // does not apply, and one warning line was the only
                        // trace of the downgrade (audit V-07).
                        logger.error(
                            "node.sovereign_identity.load_failed",
                            format!("{e} — refusing to start as a legacy node"),
                        );
                        return Err(NodeError::Config(veil_cfg::ConfigError::ValidationFailed(
                            format!(
                                "sovereign identity at {} exists but cannot be \
                             loaded: {e}. Re-provision with `veil-cli identity \
                             create`/`restore`, or set \
                             [global].allow_identity_fallback = true to start \
                             as an unrelated legacy node on purpose.",
                                doc_path.display()
                            ),
                        )));
                    }
                }
            } else if config.ephemeral_identity {
                // The deferred boot's `[identity]` is a compiled-in constant.
                // Building a standalone sovereign out of it would write that
                // constant to `device_identity_sk.bin` — and the ML-KEM and
                // X25519 resolves immediately below read exactly that file, so
                // the node's receive keys would be a pure function of a value
                // published in the source tree. Worse, the onion auth-cookie
                // and registration key derive from the same seed, so EVERY
                // deferred node would register at a relay under one shared,
                // world-known cookie.
                //
                // So: no sovereign here. Both key resolves below fall through
                // to their in-memory random branch, and the real identity — the
                // one that arrives with `apply_config` — is what
                // `apply_reload_after_stop` derives from.
                logger.info(
                    "node.sovereign_identity.deferred_skipped",
                    "deferred boot: no sovereign identity built from the placeholder \
                     [identity] — real keys are derived when the identity is applied",
                );
                None
            } else {
                // no document on disk — try the standalone
                // branch. We need an Ed25519 device SK; the config's
                // `[identity]` block carries one for normal nodes.
                build_standalone_sovereign_identity(&veil_dir_path, &config, &logger)
            }
        };

        // ML-KEM-768 mailbox keypair — resolved HERE, after the sovereign
        // auto-load, because the IDENTITY-DERIVED path (the stable-key fix) reads
        // `device_identity_sk.bin`, which the standalone-identity build writes
        // during that auto-load. Resolving it before the load silently fell back
        // to a random per-launch key (the reverse store-and-forward black-hole:
        // a peer's blob sealed to last launch's published EK could not be opened
        // after a restart). An existing persisted `mlkem.key` still wins
        // (operator/seed nodes never rotate); a node with no identity seed
        // (Falcon, or sovereign load failed) falls back to random+persist.
        let mlkem_key_path = veil_dir_path.join("mlkem.key");
        // Passphrase cascade: prompt > env > file > inline. Zeroizing<String>
        // wipes the heap contents when it drops just below.
        let key_passphrase = crate::key_passphrase::resolve_key_passphrase(&config, &logger)?;
        let mlkem_epoch = crate::identity_local::mlkem_dk::rotation_epoch(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            config.global.mlkem_rotation_secs,
        );
        let mlkem_key = crate::identity_local::mlkem_dk::load_or_derive(
            &mlkem_key_path,
            &veil_dir_path,
            key_passphrase.as_deref().map(|p| p.as_str()),
            mlkem_epoch,
            config.ephemeral_identity,
        )?;
        let (mlkem_ek_arr, mlkem_dk_arr) = (mlkem_key.ek, mlkem_key.dk_seed);
        logger.info(
            "node.mlkem_dk.source",
            format!("mlkem dk_seed source={}", mlkem_key.source.as_str()),
        );
        // The key is usable either way, so this is a warning and not a refusal
        // to start — a node down because its config directory is read-only is
        // worse than a node up with a posture problem it has just named. What
        // it must not be is silent: the loader used to discard this error
        // entirely, so an operator who had just turned on a passphrase got a
        // node that started, worked, and kept the seed in plaintext with
        // nothing anywhere saying so (audit report7 V-02).
        if let veil_e2e::MlKemKeyAtRest::PlaintextUpgradeFailed { reason } = &mlkem_key.at_rest {
            logger.warn(
                "node.mlkem_dk.at_rest",
                format!(
                    "a passphrase is configured but {} could NOT be re-encrypted \
                     ({reason}) — the ML-KEM decapsulation seed is still stored in \
                     PLAINTEXT. The node is running on the correct key; fix the \
                     path and restart to complete the upgrade.",
                    mlkem_key_path.display(),
                ),
            );
        }
        let mlkem_key_at_rest = mlkem_key.at_rest.clone();
        drop(key_passphrase);
        // One holder for the keypair, from here down. The seed inside is
        // mlock-pinned (or zeroize-on-drop); the source arrays drop at the end
        // of this statement. The ring starts at the epoch currently in force,
        // not at 0, so a restart resumes the key this node was already
        // publishing; `spawn_mlkem_rotation_task` moves it on from there.
        let mlkem_keys = Arc::new(veil_e2e::MlKemSeedRing::new(
            mlkem_epoch,
            mlkem_dk_arr,
            mlkem_ek_arr,
        ));

        // d removed the persistent RevocationCache; document
        // freshness now relies on `valid_until_unix` alone.

        // shared transport-hint registry — IPC clients query it
        // via `TransportHintQuery` to find which schemes work from this node.
        let hint_registry = Arc::new(veil_transport::hint_registry::TransportHintRegistry::new());
        let registry = Arc::new(
            TransportRegistry::with_defaults().with_hint_registry(
                Arc::clone(&hint_registry) as Arc<dyn veil_transport::TransportHintSink>
            ),
        );
        let started_at = Instant::now();
        let metrics = veil_cfg::observability_glue::metrics_from_config(&config)
            .map(|(metrics, _)| Arc::new(metrics));
        if let Some(metrics) = &metrics {
            metrics.set_configured_peers(config.peers.len());
        }
        let role = config
            .identity
            .as_ref()
            .map(|id| id.role)
            .unwrap_or_default();
        let state = Arc::new(Mutex::new(build_state(
            &config,
            config_path.clone(),
            foreground_mode,
            started_at,
            config.metrics.is_some(),
            None,
        )?));
        // Recorded, not merely logged: whether the key is actually encrypted at
        // rest is a standing property of this node, and a warning scrolled past
        // at startup leaves an operator no way to ask about it later.
        lock_state(&state).mlkem_key_at_rest = mlkem_key_at_rest;

        let local_node_id = *local_identity.node_id.as_bytes();
        let mesh_realm = Self::init_mesh_realm(&config).await;
        // load signing key early so discovery records can be
        // self-authenticating (signed) for cross-DHT replication.
        let local_signing_key = load_signing_key(&config);
        // Falcon-512 identity material for signed V2 records on
        // post-quantum nodes. `None` on Ed25519 nodes — only one algo active
        // at a time.
        let local_falcon_signer = load_falcon_signer(&config);
        let gateway = Arc::new(GatewayService::new_with_lease_ttl(
            role,
            std::time::Duration::from_secs(config.gateway.attachment_lease_ttl_secs),
        ));
        let shared_rtt_table = Arc::new(Mutex::new(RttTable::new(std::time::Duration::from_secs(
            300,
        ))));
        // create Vivaldi arcs here so they can be shared with both DHT and dispatcher.
        let shared_vivaldi = Arc::new(Mutex::new(VivaldiCoord::new()));
        #[allow(clippy::type_complexity)]
        // p: pre-size to MAX_PEER_VIVALDI_CACHE (avoids rehash).
        let shared_peer_vivaldi: Arc<
            std::sync::RwLock<
                std::collections::HashMap<NodeIdBytes, (VivaldiCoord, std::time::Instant)>,
            >,
        > = Arc::new(std::sync::RwLock::new(
            std::collections::HashMap::with_capacity(veil_proto::budget::MAX_PEER_VIVALDI_CACHE),
        ));
        // P-Net Phase 3b: build the auth gate BEFORE the DHT so that
        // STOREs carrying the `PBAN` magic prefix can be verified at
        // ingest time. Public-mode nodes (or nodes with no `[network]`
        // block) leave `network_gate_arc` = None; the DHT path treats
        // that as "reject all PBAN STOREs".
        let network_gate_arc: Option<Arc<veil_identity::network_access::NetworkAccessGate>> =
            if let Some(ref net_cfg) = config.network {
                match veil_identity::network_access::NetworkAccessGate::from_config(net_cfg) {
                    Ok(Some(gate)) => {
                        logger.info(
                            "network.private_mode",
                            format!(
                                "loaded membership cert for network_id={}",
                                net_cfg.network_id.as_deref().unwrap_or("<unset>"),
                            ),
                        );
                        Some(Arc::new(gate))
                    }
                    Ok(None) => None,
                    Err(e) => {
                        return Err(crate::error::NodeError::Config(
                            veil_cfg::ConfigError::ValidationFailed(format!(
                                "[network] gate load failed: {e}"
                            )),
                        ));
                    }
                }
            } else {
                None
            };
        let dht = {
            let mut dht_cfg = config.dht.clone();
            if role == veil_cfg::NodeRole::Core && dht_cfg.k == veil_cfg::DhtConfig::default().k {
                dht_cfg.k = 40;
            }
            let mut svc = KademliaService::with_config(
                local_node_id,
                crate::dht_glue::runtime_config_from(&dht_cfg),
            );
            if role == veil_cfg::NodeRole::Core {
                svc.set_sketch_threshold(128);
            }
            svc.set_rtt_table(Arc::new(crate::dht_glue::RttHintAdapter::new(Arc::clone(
                &shared_rtt_table,
            ))));
            svc.set_coord_oracle(Arc::new(crate::dht_glue::VivaldiOracle::new(
                Arc::clone(&shared_vivaldi),
                Arc::clone(&shared_peer_vivaldi),
            )));
            if let Some(m) = &metrics {
                svc.set_metrics(Arc::clone(m) as Arc<dyn veil_dht::DhtMetrics>);
            }
            if let Some(ref gate) = network_gate_arc {
                svc.set_network_auth_gate(Arc::clone(gate) as Arc<dyn veil_dht::NetworkAuthGate>);
            }
            Arc::new(svc)
        };
        // + backlog re-mint: configure our
        // self-signed transport announcement source. Pre-condition:
        // we have an Ed25519 signing key AND at least one advertised
        // transport. Pure outbound nodes (no listen entries) skip
        // this step — they'll still verify peers' announcements but
        // cannot be `ResolveTransport`'d.
        //
        // Storing (signing_key, transport) pair lets the
        // maintenance tick re-mint the bundle at half-validity, so
        // long-running peers don't go silent ~30 days after startup.
        if let Some(ref sk) = local_signing_key {
            let advertised = build_advertised_transports(&config);
            if let Some(transport) = advertised.into_iter().next() {
                dht.configure_local_announcement_source(Arc::clone(sk), transport);
            }
        }
        // DiscoveryService is created AFTER the DHT so it can
        // publish signed records into it; AppEndpointRegistry's auto_publish
        // then flows through the same DHT-wired DiscoveryService.
        let discovery = {
            let mut svc = DiscoveryService::new(role).with_dht(Arc::clone(&dht));
            if let Some(ref sk) = local_signing_key {
                svc = svc.with_signing_key(Arc::clone(sk));
            }
            if let Some(ref fs) = local_falcon_signer {
                svc = svc.with_falcon_signer(Arc::clone(fs));
            }
            Arc::new(svc)
        };
        let app_registry = Arc::new({
            let r = AppEndpointRegistry::new().with_auto_publish(
                local_node_id,
                Arc::clone(&discovery),
                300,
            );
            if let Some(m) = &metrics {
                r.with_metrics(Arc::clone(m) as Arc<dyn veil_app::AppMetrics>)
            } else {
                r
            }
        });
        let mesh_forwarder = Arc::new(MeshForwarder::new(
            local_node_id,
            role,
            Arc::new(NeighborTable::new()),
        ));
        let control_plane = Arc::new(
            veil_routing::control_plane::ControlPlaneService::with_rtt_table(Arc::clone(
                &shared_rtt_table,
            )),
        );
        let route_cache = Arc::new(RwLock::new(RouteCache::new(
            std::time::Duration::from_secs(config.routing.route_cache_ttl_secs),
        )));
        // b: per-peer byte-rate enforcement. Chained
        // ONLY when operator opted in via `abuse.per_peer_bytes_per_sec`
        // — preserves backwards-compat "no enforcement" default.
        let rate_limiter = {
            let mut limiter = PerPeerLimiter::new(
                config.abuse.rate_limit_fps,
                config.abuse.rate_limit_burst,
                std::time::Duration::from_secs(300),
            );
            if let Some(rate) = config.abuse.per_peer_bytes_per_sec
                && let Some(burst) = config.abuse.resolved_per_peer_byte_burst()
            {
                limiter = limiter.with_byte_rate(rate as f64, burst as f64);
            }
            Arc::new(Mutex::new(limiter))
        };
        let ban_list = Arc::new(Mutex::new(BanList::new()));
        persistence::load_bans(&ban_list, &config_path);
        let violation_tracker = Arc::new(Mutex::new(
            // `.max(1)` makes the threshold provably ≥ 1, which is the
            // only failure precondition of `ViolationTracker::new`
            // (`Err("ban_threshold must be > 0")`). `.expect` is
            // therefore unreachable; keep it as a tripwire so a future
            // refactor that removes the clamp surfaces here, not at
            // runtime.
            ViolationTracker::new(
                config.abuse.ban_threshold.max(1),
                std::time::Duration::from_secs(config.abuse.ban_initial_secs),
                std::time::Duration::from_secs(config.abuse.ban_step_secs),
                std::time::Duration::from_secs(config.abuse.ban_max_secs),
                std::time::Duration::from_secs(600),
            )
            .expect("ban_threshold clamped to >= 1 — invariant in this call site"),
        ));
        // p: pre-size all peer-cache HashMaps to their caps
        // so that inserts up to the cap do not trigger `reserve_rehash`
        // transient allocations. jeprof callgraph showed
        // ~49 MiB of jemalloc dirty pages pinned by these rehash events
        // on bootstrap'e under chaos-ban peer churn. Pre-allocation costs
        // ~80 KiB total upfront in exchange for a flat allocator footprint.
        let peer_pubkeys: veil_types::PeerPubkeysCache = Arc::new(Mutex::new(
            veil_types::PeerLruCache::with_capacity(veil_proto::budget::MAX_PEER_PUBKEYS_CACHE),
        ));
        // persistent peer → sovereign identity binding
        // cache. Lives on the runtime so it survives `reload_with`
        // (the session_registry is wiped on reload but this map
        // is kept). Lets the resumption fast path restore the
        // peer's `ValidatedIdentity` even though the handshake
        // skipped the `IdentityProof` exchange.
        let peer_sovereign_identities: crate::runtime::identity_state::PeerSovereignBindings =
            Arc::new(Mutex::new(std::collections::HashMap::with_capacity(
                veil_proto::budget::MAX_PEER_SOVEREIGN_IDENTITIES,
            )));
        let peer_roles: Arc<Mutex<veil_types::PeerLruCache<u8>>> = Arc::new(Mutex::new(
            veil_types::PeerLruCache::with_capacity(veil_proto::budget::MAX_PEER_PUBKEYS_CACHE),
        ));
        // maps peer_id → flags bitmask from CapabilitiesPayload (CAN_RELAY etc.)
        let peer_cap_flags: Arc<std::sync::RwLock<std::collections::HashMap<NodeIdBytes, u8>>> =
            Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::with_capacity(
                    veil_proto::budget::MAX_PEER_PUBKEYS_CACHE,
                ),
            ));
        let shared_peer_mlkem_keys: Arc<std::sync::RwLock<veil_e2e::PeerMlKemCache>> =
            Arc::new(std::sync::RwLock::new(
                veil_e2e::PeerMlKemCache::with_capacity(veil_proto::budget::MAX_PEER_MLKEM_CACHE),
            ));
        // Verified-cert fast-path cache, shared by the live-E2E + offline-seal
        // ML-KEM resolvers so one DHT walk serves both (kills per-seal walks).
        let shared_peer_mlkem_certs: Arc<
            std::sync::RwLock<crate::mlkem_resolver::PeerMlKemCertCache>,
        > = Arc::new(std::sync::RwLock::new(
            crate::mlkem_resolver::PeerMlKemCertCache::with_capacity(
                veil_proto::budget::MAX_PEER_MLKEM_CACHE,
            ),
        ));
        // The same certificates on disk. Built here beside the RAM cache it
        // backs, and from `config_path` because that is where every other
        // learned-state snapshot this runtime keeps already lives
        // (`peers_discovered.json`, `bans.json`).
        let shared_peer_mlkem_cert_store = Arc::new(crate::mlkem_cert_store::MlKemCertStore::load(
            &config_path,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        ));
        // The device Diffie-Hellman half of the same certificates, kept apart
        // so the frame dispatcher can read it: the dispatcher decides sender
        // provenance synchronously and cannot reach this crate's cert type.
        let shared_peer_ratchet_keys: Arc<std::sync::RwLock<veil_e2e::PeerRatchetKeyCache>> =
            Arc::new(std::sync::RwLock::new(
                veil_e2e::PeerRatchetKeyCache::with_capacity(
                    veil_proto::budget::MAX_PEER_MLKEM_CACHE,
                ),
            ));
        // Built here rather than beside `IdentityState` below, because the
        // frame dispatcher is constructed first and needs the same cell: the
        // ratchet's two ends are a send path in veil-ipc and a receive path in
        // veil-dispatcher, and a conversation only works if both agree which
        // of our devices they are speaking as.
        let sovereign_cell = identity_state::SovereignIdentityCell::new(sovereign_identity.clone());
        // One-to-one ratchet conversations. Empty at start: the state is the
        // host's, and xVeil restores it over the FFI before traffic flows.
        let ratchet_runtime = veil_e2e::RatchetRuntime {
            store: Arc::new(veil_e2e::RatchetStore::new()),
            seed_ring: Arc::new(RwLock::new(Arc::clone(&mlkem_keys))),
            local_node_id: Arc::new(RwLock::new(local_node_id)),
            local_instance_id: sovereign_cell.active_instance_handle(),
            peer_ratchet_keys: Arc::clone(&shared_peer_ratchet_keys),
        };
        // per-session ephemeral ML-KEM DK seeds (key = peer_id, value =
        // SensitiveBytesN<64>-wrapped dk_seed).  Phase 6 slice 6h —
        // values are mlocked while the session is open.
        let shared_per_session_mlkem_dk: Arc<
            Mutex<
                std::collections::HashMap<
                    NodeIdBytes,
                    veil_util::sensitive_bytes::SensitiveBytesN<{ veil_e2e::DK_SEED_BYTES }>,
                >,
            >,
        > = Arc::new(Mutex::new(std::collections::HashMap::with_capacity(
            veil_proto::budget::MAX_PER_SESSION_MLKEM_DK,
        )));
        let shared_pending_diag: Arc<
            Mutex<
                std::collections::HashMap<
                    u32,
                    tokio::sync::mpsc::Sender<veil_dispatcher::DiagEvent>,
                >,
            >,
        > = Arc::new(Mutex::new(std::collections::HashMap::new()));
        // PEX event channel (dispatcher → initiator).
        let (pex_event_tx, pex_event_rx) = tokio::sync::mpsc::channel::<veil_pex::PexEvent>(64);
        // PEX connect channel (initiator → runtime outbound connector).
        let (pex_connect_tx, pex_connect_rx) =
            tokio::sync::mpsc::channel::<Vec<veil_proto::pex::PexPeer>>(16);
        // shared PEX state (dispatcher + initiator + runtime).
        let shared_pex_state: Arc<Mutex<veil_pex::PexState>> =
            Arc::new(Mutex::new(veil_pex::PexState::new()));
        // shared session registry for sovereign routing.
        // Built here so both `FrameDispatcher` (read side) and the
        // `NodeRuntime` struct literal (write side, populated by the
        // handshake) hold the same `Arc` — no double init.
        let shared_session_registry = Arc::new(Mutex::new(veil_session::SessionRegistry::new()));

        // one-shot sovereign-identity publish at startup.
        // When this node was provisioned with an IdentityDocument
        // publish it — plus its single-entry `InstanceRegistry` —
        // to the local DHT shard so peers walking the DHT keyspace
        // can retrieve the signed records without going through the
        // legacy node_id-keyed path. Scheduled periodic republish
        // (every 6h) + on-change republish (rotate/revoke) are the
        // remaining plumbing steps — this one-shot covers the common
        // case of a freshly-started node being immediately queryable.
        // Runs before any outbound session so the first handshake
        // that triggers a resolver query finds the document.
        if let Some(ref sov) = sovereign_identity {
            // Also re-run whenever the identity in force CHANGES — see
            // [`identity_publish`] for the promotion that used to leave the
            // DHT holding a placeholder's records.
            crate::runtime::identity_publish::publish_sovereign_identity(
                sov,
                &dht,
                &mlkem_keys,
                &veil_dir_path,
                // No peers yet at boot — this one is local-only by design.
                None,
                &logger,
            )
            .await;
        }
        let shared_session_tx_registry = Arc::new(RwLock::new(if let Some(m) = &metrics {
            veil_session::SessionTxRegistry::with_capacity_and_drop_counter(
                config.session.tx_queue_depth,
                m.session_tx_drops_counter(),
            )
        } else {
            veil_session::SessionTxRegistry::with_capacity(config.session.tx_queue_depth)
        }));
        // create congestion monitor once; shared with dispatcher and runtime.
        let shared_congestion_monitor = Arc::new(veil_congestion::CongestionMonitor::new(
            config.capacity.clone(),
            config.session.tx_queue_depth,
        ));
        // shared reputation tracker for transit gate.
        let shared_reputation: Arc<Mutex<veil_reputation::ReputationTracker>> =
            Arc::new(Mutex::new(veil_reputation::ReputationTracker::new()));
        let session_outbox = if let Some(m) = &metrics {
            veil_session::SessionOutbox::with_capacity_and_drop_counter(
                config.session.outbox_depth,
                m.session_outbox_drops_counter(),
            )
        } else {
            veil_session::SessionOutbox::with_capacity(config.session.outbox_depth)
        };
        // `local_signing_key` already computed earlier (above `discovery`).
        let listen_transports =
            Arc::new(std::sync::RwLock::new(build_advertised_transports(&config)));
        let shared_route_seen_set = Arc::new(Mutex::new(veil_dispatcher::RouteSeenSet::new(
            std::time::Duration::from_secs(config.routing.route_seen_window_secs),
            config.routing.route_seen_capacity,
        )));
        let shared_announce_seq = Arc::new(AtomicU32::new(0));
        let shared_route_updated = Arc::new(tokio::sync::Notify::new());
        let shared_neighbor_scorer = Arc::new(Mutex::new(NeighborScorer::with_alphas(0.5, 0.1)));
        // shared gateway list (same Arc used by runtime and dispatcher).
        let shared_gateway_list: Arc<Mutex<veil_gateway::GatewayList>> = Arc::new(Mutex::new(
            veil_gateway::GatewayList::new(config.connection.prefer_internet_gateway),
        ));
        // veil proxy stream routing tables (shared with VeilConnector).
        use veil_proxy::veil_connector::{PendingReceiptMap, VeilStreamRxMap};
        let shared_pending_stream_receipts: PendingReceiptMap =
            Arc::new(Mutex::new(std::collections::HashMap::new()));
        let shared_veil_stream_rx: VeilStreamRxMap =
            Arc::new(Mutex::new(std::collections::HashMap::new()));
        // 482.7: anonymity X25519 SK shared between
        // NodeRuntime (which the relay-directory publish task reads
        // via `anonymity_x25519_sk` field) and the dispatcher's
        // RelayChain handler (which peels inbound onion cells).
        // Constructed once, ARC-cloned to both consumers. Only
        // populated when the operator opted in to being a relay —
        // None signals "anonymity disabled, drop RelayChain frames".
        //
        //.4 P0: persisted to disk under
        // `<veil_dir>/device_anonymity_x25519_sk.bin` so push-
        // envelopes sealed by apps survive relay restart. Before T1.4
        // the key was `random_from_rng` on every startup, silently
        // invalidating every sealed envelope already registered with
        // this relay's rendezvous publisher.
        // Generated when the node either RELAYS others' circuits
        // (`relay_capable`) or RECEIVES authenticated anonymous messages
        // (`receive_anonymous`) — both need the key (relaying peels cells;
        // receiving unseals forwarded introduces). The two roles are gated
        // separately downstream: the dispatcher's onion Forward arm + the
        // rendezvous registry stay on `relay_capable`, so a receive-only node
        // never carries others' circuits.
        let anonymity_x25519_sk_for_dispatcher: Option<Arc<x25519_dalek::StaticSecret>> =
            if config.anonymity.relay_capable
                || config.anonymity.receive_anonymous
                || config.anonymity.onion_service
            {
                // Prefer an existing persisted key (long-lived nodes never
                // rotate); else DERIVE deterministically from the identity seed
                // so ephemeral-runtime-dir nodes (xVeil clients recreate
                // veil_dir every session) stop minting a fresh random key each
                // launch — the churned pubkey silently black-holed delivery to
                // peers holding an older ad (anonymity.relay_chain.forward
                // .decrypt_failed). See anonymity_x25519::load_or_derive.
                let (sk, src) = crate::identity_local::anonymity_x25519::load_or_derive(
                    &veil_dir_path,
                    sovereign_identity.is_some(),
                    config.ephemeral_identity,
                )?;
                logger.info(
                    "node.anonymity_x25519.source",
                    format!("anonymity x25519 key source={}", src.as_str()),
                );
                Some(Arc::new(sk))
            } else {
                None
            };

        // One-shot relay-key publish at startup. If this node has an anonymity
        // X25519 key (relay_capable / receive_anonymous / onion_service), publish
        // a signed `RelayKeyRecord` so peers can resolve its relay X25519 by
        // node_id alone (e.g. to advertise it as an always-on mailbox host). The
        // 6h republish task refreshes it; this one-shot makes it resolvable
        // immediately, mirroring the identity/registry/mlkem one-shots above.
        if let (Some(sov), Some(relay_sk)) =
            (&sovereign_identity, &anonymity_x25519_sk_for_dispatcher)
        {
            let relay_pk = x25519_dalek::PublicKey::from(relay_sk.as_ref()).to_bytes();
            let publisher =
                crate::identity_local::publisher_dht::DhtBackedPublisher::new(Arc::clone(&dht));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            match sov.sign_relay_key(relay_pk.to_vec(), now, now + 30 * 86_400, 1) {
                Ok(rec) => {
                    match veil_identity::publish::publish_relay_key(&rec, &publisher).await {
                        Ok(()) => logger.info(
                            "node.sovereign_identity.relay_key_published",
                            format!(
                                "node_id={} relay_x25519 advertised",
                                veil_util::bytes_to_hex(sov.node_id()),
                            ),
                        ),
                        Err(e) => logger.warn(
                            "node.sovereign_identity.relay_key_publish_failed",
                            format!(
                                "node_id={} — relay-key DHT publish failed: {e}",
                                veil_util::bytes_to_hex(sov.node_id()),
                            ),
                        ),
                    }
                }
                Err(e) => logger.warn(
                    "node.sovereign_identity.relay_key_sign_failed",
                    format!(
                        "node_id={} — relay-key signing failed: {e}",
                        veil_util::bytes_to_hex(sov.node_id()),
                    ),
                ),
            }
        }
        //.4 P2: open mailbox if operator
        // opted in. Storage lives at `<veil_dir>/mailbox/blobs.db`
        // (redb). Zero-valued config fields fall through to crate
        // defaults.
        //.4 P4: always-on sender-side outbox
        // for peer-sync. Cheap (idle DB until first put) and decoupled
        // from `mailbox.enabled` — every node sends, so every node
        // benefits from peer-sync retransmits when contacts come back
        // online. Failure to open is non-fatal: outbox stays None and
        // the peer-sync IPC handlers respond with graceful "feature off".
        let outbox_handle: Option<Arc<veil_mailbox::Outbox>> =
            match veil_mailbox::Outbox::open(&veil_dir_path, veil_mailbox::OutboxConfig::default())
            {
                Ok(o) => Some(Arc::new(o)),
                Err(e) => {
                    log::warn!("veil-mailbox: outbox open failed (peer-sync disabled): {e}");
                    None
                }
            };

        let mailbox_handle: Option<Arc<veil_mailbox::Mailbox>> = if config.mailbox.enabled {
            let mb_cfg =
                build_mailbox_runtime_config(&config.mailbox, *local_identity.node_id.as_bytes());
            let mb = veil_mailbox::Mailbox::open(&veil_dir_path, mb_cfg).map_err(|e| {
                crate::error::NodeError::Io(std::io::Error::other(format!(
                    "mailbox open failed: {e}"
                )))
            })?;
            Some(Arc::new(mb))
        } else {
            None
        };
        let dispatcher = Arc::new(FrameDispatcher {
            role,
            gateway: Arc::clone(&gateway),
            discovery: Arc::clone(&discovery),
            dht: Arc::clone(&dht),
            app_registry: Arc::clone(&app_registry),
            stream_table: Arc::new(veil_app::AppStreamTable::new()),
            mesh_forwarder: Arc::clone(&mesh_forwarder),
            chunk_reassembler: Arc::new(Mutex::new(
                veil_dispatcher::envelope_chunks::EnvelopeChunkReassembler::new(),
            )),
            discovery_forwarder: Arc::new(Mutex::new(
                veil_routing::discovery_forwarder::DiscoveryForwarder::with_default_difficulty(
                    local_node_id,
                    role,
                ),
            )),
            control_plane: Arc::clone(&control_plane),
            route_cache: Arc::clone(&route_cache),
            metrics: metrics.clone(),
            logger: Arc::clone(&logger),
            crypto: Arc::new(veil_dispatcher::CryptoContext {
                local_signing_key: local_signing_key.clone(),
                mlkem_keys: Arc::clone(&mlkem_keys),
                peer_mlkem_keys: Arc::clone(&shared_peer_mlkem_keys),
                peer_pubkeys: Arc::clone(&peer_pubkeys),
                peer_roles: Arc::clone(&peer_roles),
                peer_cap_flags: Arc::clone(&peer_cap_flags),
                per_session_mlkem_dk: Arc::clone(&shared_per_session_mlkem_dk),
                ratchet: Some(ratchet_runtime.clone()),
            }),
            abuse: Arc::new(veil_dispatcher::AbuseContext {
                // Role-aware on purpose: a seed is Core and serving others IS
                // its job, so metering it would meter the backbone. Only a
                // leaf — every xVeil client — gets a bill.
                service_budget: Arc::new(veil_dispatcher::service_budget::ServiceBudget::for_role(
                    role,
                    config.dht.service_budget_bytes_per_hour,
                )),
                rate_limiter: Arc::clone(&rate_limiter),
                ban_list: Arc::clone(&ban_list),
                violation_tracker: Arc::clone(&violation_tracker),
                dht_quota: Arc::new(Mutex::new(veil_abuse::DhtQuota::new(
                    veil_proto::budget::MAX_DHT_OPS_PER_PEER_PER_WINDOW,
                    std::time::Duration::from_secs(veil_proto::budget::DHT_QUOTA_WINDOW_SECS),
                ))),
                // per-identity DHT write quota.
                identity_write_quota: Arc::new(
                    veil_abuse::identity_quota::IdentityWriteQuota::default_policy(),
                ),
                pow_challenge_limiter: Arc::new(Mutex::new(veil_abuse::PerPeerLimiter::new(
                    config.pow.challenge_rate,
                    config.pow.challenge_burst,
                    std::time::Duration::from_secs(config.pow.challenge_window_secs),
                ))),
                unsigned_route_request_budget: Arc::new(Mutex::new(
                    veil_abuse::rate_limiter::TokenBucket::new(
                        veil_proto::budget::UNSIGNED_ROUTE_REQUEST_BURST as f64,
                        1.0 / veil_proto::budget::UNSIGNED_ROUTE_REQUEST_REFILL_SECS as f64,
                    ),
                )),
                route_request_forward_budget: Arc::new(Mutex::new(
                    veil_abuse::rate_limiter::TokenBucket::new(
                        veil_proto::budget::ROUTE_REQUEST_FORWARD_BURST as f64,
                        veil_proto::budget::ROUTE_REQUEST_FORWARD_BURST as f64
                            / veil_proto::budget::ROUTE_REQUEST_FORWARD_REFILL_SECS as f64,
                    ),
                )),
                unproven_ratchet_open_budget: Arc::new(Mutex::new(
                    veil_abuse::rate_limiter::TokenBucket::new(
                        veil_proto::budget::UNPROVEN_RATCHET_OPEN_BURST as f64,
                        veil_proto::budget::UNPROVEN_RATCHET_OPEN_BURST as f64
                            / veil_proto::budget::UNPROVEN_RATCHET_OPEN_REFILL_SECS as f64,
                    ),
                )),
                // per-peer quota on new route insertions from RouteResponse.
                dht_contact_quota: Arc::new(Mutex::new(veil_abuse::DhtQuota::new(
                    veil_proto::budget::MAX_NEW_ROUTES_PER_PEER_PER_WINDOW,
                    std::time::Duration::from_secs(veil_proto::budget::DHT_QUOTA_WINDOW_SECS),
                ))),
                // rate-limit AnnounceAttachment to prevent signature-verify DoS.
                announce_attachment_limiter: Arc::new(Mutex::new(veil_abuse::PerPeerLimiter::new(
                    1.0 / 60.0, // 1 per minute steady-state
                    3.0,        // burst: 3 (handles reconnect storms)
                    std::time::Duration::from_secs(600),
                ))),
                //round 7 / : per-peer cap on relay-mode
                // NAT-probe forwards. Closes the amplification surface
                // opened: a peer firing unique `query_id`s
                // fast through us as coordinator would have us forward
                // each one outbound (≈2× bandwidth amplification).
                nat_probe_forward_quota: Arc::new(Mutex::new(veil_abuse::DhtQuota::new(
                    veil_proto::budget::MAX_NAT_PROBE_FORWARDS_PER_PEER_PER_WINDOW,
                    std::time::Duration::from_secs(veil_proto::budget::DHT_QUOTA_WINDOW_SECS),
                ))),
                // RecursiveQuery rate-limit (5/sec sustained, burst 20). Stops a
                // peer flooding distinct query_ids that the existing dedup misses.
                recursive_query_limiter: Arc::new(Mutex::new(veil_abuse::PerPeerLimiter::new(
                    5.0,
                    20.0,
                    std::time::Duration::from_secs(300),
                ))),
                inbound_bandwidth: Arc::new(Mutex::new(veil_abuse::BandwidthGate::new(
                    veil_cfg::NodeCapacityConfig::bandwidth_kbps_to_gate(
                        config.capacity.max_inbound_bandwidth_kbps,
                    ),
                ))),
                outbound_bandwidth: Arc::new(Mutex::new(veil_abuse::BandwidthGate::new(
                    veil_cfg::NodeCapacityConfig::bandwidth_kbps_to_gate(
                        config.capacity.max_outbound_bandwidth_kbps,
                    ),
                ))),
            }),
            local_node_id,
            session_tx_registry: Some(Arc::clone(&shared_session_tx_registry)),
            rendezvous_weak: Arc::new(std::sync::Mutex::new(None)),
            session_registry: Some(Arc::clone(&shared_session_registry)),
            // Filled in-place by the IPC wiring in `service_tasks` once the
            // runtime resolver exists (defect №35 sender-side feedback).
            peer_cert_invalidate: Arc::new(Mutex::new(None)),
            route_seen_set: Arc::clone(&shared_route_seen_set),
            announce_seq: Arc::clone(&shared_announce_seq),
            listen_transports: Arc::clone(&listen_transports),
            own_external_addrs: Arc::new(std::sync::RwLock::new(vec![])),
            relay_node_ids: build_relay_node_ids(&config),
            target_labels: build_target_labels(&config.routing),
            route_updated: Arc::clone(&shared_route_updated),
            pow_difficulty: config.abuse.pow_min_difficulty as u8,
            pow_pending: Arc::new(Mutex::new(veil_dispatcher::PowPendingTable::new())),
            discovery_mode: config.routing.discovery_mode,
            dht_service: config.dht.participate,
            pending_diag: Arc::clone(&shared_pending_diag),
            capture_tx: Arc::new(Mutex::new(None)),
            capture_active: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            capture_rate_limit: Arc::new(veil_dispatcher_state::CaptureRateLimiter::new()),
            route_miss_tx: Arc::new(Mutex::new(None)),
            // Wired post-construction by `spawn_auth_deliver_handler`.
            auth_deliver_tx: Arc::new(Mutex::new(None)),
            neighbor_scorer: Arc::clone(&shared_neighbor_scorer),
            local_vivaldi: Some(Arc::clone(&shared_vivaldi)),
            peer_vivaldi: Arc::clone(&shared_peer_vivaldi),
            // DELIVERY_FORWARD dedup set.
            // Sized to 100 000 entries with a 60-second TTL so that burst
            // traffic cannot exhaust the cache and reopen a replay window.
            forward_seen_set: Arc::new(Mutex::new(veil_dispatcher::ForwardSeenSet::new(
                std::time::Duration::from_secs(veil_proto::budget::FORWARD_SEEN_SET_TTL_SECS),
                veil_proto::budget::MAX_FORWARD_SEEN_SET_SIZE,
            ))),
            forward_seen_content: Arc::new(Mutex::new(veil_dispatcher::ForwardSeenSet::new(
                std::time::Duration::from_secs(veil_proto::budget::FORWARD_SEEN_SET_TTL_SECS),
                veil_proto::budget::MAX_FORWARD_SEEN_SET_SIZE,
            ))),
            terminal_ack_replay: Arc::new(Mutex::new(veil_dispatcher::ExpiryMap::new(
                std::time::Duration::from_secs(veil_proto::budget::FORWARD_SEEN_SET_TTL_SECS),
                veil_proto::budget::MAX_FORWARD_SEEN_SET_SIZE,
            ))),
            recursive_query_seen: Arc::new(Mutex::new(veil_dispatcher::ExpiryCache::new(
                std::time::Duration::from_secs(30),
                65536,
            ))),
            pending_recursive: Arc::new(Mutex::new(std::collections::HashMap::new())),
            recursive_reverse_path: Arc::new(Mutex::new(std::collections::HashMap::new())),
            // session alias registry (empty; populated by SessionRunner).
            alias_registry: Arc::new(Mutex::new(std::collections::HashMap::new())),
            // NAT traversal — observed peer addresses (empty; populated by on_session_opened).
            // p: pre-size to MAX_PEER_OBSERVED_ADDRS (avoids rehash spikes).
            peer_observed_addrs: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::with_capacity(
                    veil_proto::budget::MAX_PEER_OBSERVED_ADDRS,
                ),
            )),
            local_udp_reflector_port: Arc::new(std::sync::atomic::AtomicU16::new(0)),
            peer_udp_reflectors: Arc::new(std::sync::RwLock::new(
                std::collections::HashMap::with_capacity(
                    veil_proto::budget::MAX_PEER_OBSERVED_ADDRS,
                ),
            )),
            // NAT relay tunnel table (empty; populated by NatRelayRequest dispatch).
            relay_tunnels: Arc::new(Mutex::new(std::collections::HashMap::new())),
            // pending NAT-probe waiters (empty; populated by attempt_nat_traversal).
            nat_probe_waiters: Arc::new(Mutex::new(std::collections::HashMap::new())),
            nat_punch_offer_tx: Arc::new(Mutex::new(None)),
            // scale-aware adaptive params. Init from
            // `from_network_size(100)` — the hard floor in
            // `estimate_network_size`. Reload tick refreshes this from
            // the live routing table once peers connect.
            adaptive_params: Arc::new(std::sync::RwLock::new(
                veil_cfg::adaptive::AdaptiveParams::default(),
            )),
            // configurable routing limits.
            max_gossip_hops: config.routing.max_gossip_hops,
            // congestion monitor.
            congestion_monitor: Some(Arc::clone(&shared_congestion_monitor)),
            reputation: Some(Arc::clone(&shared_reputation)),
            // gateway list — provisional initial value; the live list is
            // wired in via the rebuild below.
            gateway_list: Some(Arc::clone(&shared_gateway_list)),
            prefer_internet_gateway: config.connection.prefer_internet_gateway,
            exit_diversification: config.connection.exit_diversification,
            exit_diversification_top_k: config.connection.exit_diversification_top_k,
            // ECMP multipath.
            ecmp_score_band: config.routing.ecmp_score_band,
            redundant_send: config.routing.redundant_send,
            // epidemic broadcast.
            epidemic_seen: Arc::new(Mutex::new(veil_dispatcher::EpidemicSeenSet::new(
                std::time::Duration::from_secs(120),
                4096,
            ))),
            epidemic_fanout: config.routing.epidemic_fanout,
            epidemic_max_payload: config.routing.epidemic_max_payload,
            battery_threshold_low: config.routing.battery_threshold_low,
            battery_threshold_medium: config.routing.battery_threshold_medium,
            battery_penalty_low: config.routing.battery_penalty_low,
            battery_penalty_medium: config.routing.battery_penalty_medium,
            last_sleep_advertisement_ts: Arc::new(AtomicU64::new(0)),
            multi_path_enabled: config.routing.multi_path_enabled,
            max_parallel_paths: config.routing.max_parallel_paths,
            multi_path_min_priority: config.routing.multi_path_min_priority,
            relay_reputation_min_attempts: config.routing.relay_reputation_min_attempts,
            relay_reputation_threshold: config.routing.relay_reputation_threshold,
            relay_reputation_penalty: config.routing.relay_reputation_penalty,
            jitter_penalty_weight: config.routing.jitter_penalty_weight,
            jitter_threshold_ms: config.routing.jitter_threshold_ms,
            narrow_bandwidth_bulk_penalty: config.routing.narrow_bandwidth_bulk_penalty,
            trace_buffer: Arc::new(Mutex::new(veil_dispatcher::TraceBuffer::new(
                config.routing.trace_buffer_size,
            ))),
            pending_ack: Arc::new(Mutex::new(
                veil_dispatcher::pending_ack::PendingAckTracker::new(),
            )),
            // in-line packet loss tracker.
            loss_tracker: Arc::new(veil_routing::loss_tracker::LossTracker::new()),
            // per-origin sequence monotonicity cache.
            route_origin_seq: Arc::new(Mutex::new(std::collections::HashMap::new())),
            route_forward_last: Arc::new(Mutex::new(std::collections::HashMap::new())),
            owned_push_last: Arc::new(Mutex::new(std::collections::HashMap::new())),
            // PoW solver resource limits.
            pow_solver_semaphore: Arc::new(tokio::sync::Semaphore::new(
                veil_proto::budget::MAX_CONCURRENT_POW_SOLVERS,
            )),
            pow_active_difficulty: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            pow_challenge_seen: Arc::new(Mutex::new(veil_dispatcher::ExpiryCache::new(
                std::time::Duration::from_secs(veil_proto::budget::POW_CHALLENGE_TTL_SECS),
                veil_proto::budget::MAX_POW_CHALLENGE_SEEN_SIZE,
            ))),
            pending_stream_receipts: Arc::clone(&shared_pending_stream_receipts),
            veil_stream_rx: Arc::clone(&shared_veil_stream_rx),
            // Audit M2: shared with the reload path (`build_reload_dispatcher`)
            // so the dispatcher is wired to the live PEX event channel the same
            // way on cold start and on every reload.
            pex_dispatcher: pex_runtime::build_pex_dispatcher(
                &config,
                local_node_id,
                logger.clone(),
                pex_event_tx.clone(),
            ),
            pex_state: Some(Arc::clone(&shared_pex_state)),
            anonymity_x25519_sk: anonymity_x25519_sk_for_dispatcher.clone(),
            anonymity_relay_capable: config.anonymity.relay_capable,
            // per-node Introduce-frame replay
            // cache. Cheap struct (Mutex<HashMap>); always allocated
            // even on non-anonymity nodes since the cost is one
            // pointer + one Mutex of an empty HashMap.
            introduce_replay_cache: Arc::new(
                veil_anonymity::rendezvous::IntroduceReplayCache::new(),
            ),
            // Δ2-g1: relay-side introduce-forward dedup (TTL 300s, cap 4096).
            circuit_introduce_seen: Arc::new(std::sync::Mutex::new(
                veil_dispatcher::ExpiryCache::new(std::time::Duration::from_secs(300), 4096),
            )),
            // bundle rendezvous-relay capability
            // with general anonymity-relay capability for v1. Both
            // are opt-in [anonymity].relay_capable; operators
            // wanting separation will get a dedicated knob if the
            // memory cost justifies it (default cap is 800 KiB).
            // The rendezvous-relay SERVER role (accept RegisterRendezvous +
            // forward introduces for others) is gated on `relay_capable`, NOT on
            // SK presence — a `receive_anonymous`-only node owns the SK (to
            // unseal its OWN forwarded introduces) but must NOT serve as a
            // rendezvous relay for strangers.
            rendezvous_registry: config
                .anonymity
                .relay_capable
                .then(|| Arc::new(veil_anonymity::rendezvous::RendezvousRegistry::default())),
            // Mailbox relays hold the SEPARATE private fetch-cookie registry
            // (gated on mailbox.enabled, not relay_capable) used to authorize
            // mailbox fetch/ack — never the published rendezvous cookie.
            mailbox_cookie_registry: config.mailbox.enabled.then(|| {
                Arc::new(std::sync::RwLock::new(
                    veil_anonymity::mailbox_cookie_registry::MailboxCookieRegistry::new(
                        veil_anonymity::mailbox_cookie_registry::DEFAULT_MAX_RECEIVERS,
                    ),
                ))
            }),
            // Same relay-capable gate: only relays hold per-hop circuit state.
            circuit_table: config
                .anonymity
                .relay_capable
                .then(|| Arc::new(veil_anonymity::circuit_table::CircuitTable::new())),
            circuit_rendezvous: config.anonymity.relay_capable.then(|| {
                Arc::new(veil_anonymity::circuit_register::CircuitRendezvousRegistry::new())
            }),
            // Origin-side: any receive-capable node (owns the anonymity key) may
            // ORIGINATE circuits to host a location-anonymous service.
            circuit_origin: anonymity_x25519_sk_for_dispatcher
                .is_some()
                .then(|| Arc::new(veil_anonymity::circuit_origin::OriginCircuitTable::new())),
            // onion-stream Phase 1c: per-origin-circuit sinks for byte-stream
            // return cells (empty until `open_data_circuit` registers one).
            stream_recv: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
        });
        // cleanup: pre-build the hot-standby controller and
        // its prerequisite Arcs (handoff_ack_waiters, swap_registry)
        // before the runtime literal so the literal can hold a direct
        // Arc clone instead of a throwaway placeholder that gets
        // replaced post-construction. All inputs are already bound at
        // this point: `registry` (line 1027), `transport_ctx` (line 948)
        // `shared_session_tx_registry` (line 1355), `logger` (line 947).
        let handoff_ack_waiters_arc = Arc::new(crate::runtime::handoff::HandoffAckWaiters::new());
        let swap_registry_arc = Arc::new(crate::runtime::handoff::SessionSwapRegistry::new());
        let hot_standby_controller_arc =
            Arc::new(crate::runtime::hot_standby::HotStandbyController::new(
                Arc::clone(&registry),
                Arc::clone(&transport_ctx),
                Arc::clone(&shared_session_tx_registry),
                Arc::clone(&handoff_ack_waiters_arc),
                Arc::clone(&swap_registry_arc),
                config.hot_standby.clone(),
                Arc::clone(&logger),
            ));
        // Apply per-peer alt_uri from config to the pre-built controller.
        // Pre-cleanup, this loop ran AFTER the runtime literal's
        // placeholder was replaced; running here lets the runtime
        // literal hold an already-populated Arc.
        for peer in &config.peers {
            if let Some(ref uri) = peer.alt_uri
                && let Ok(node_id) = veil_cfg::NodeId::from_public_key(peer.algo, &peer.public_key)
            {
                hot_standby_controller_arc.set_alt_uri(node_id, uri.clone());
            }
        }
        // Built before the literal because the connectivity-gain hook
        // (mobility slice) shares the same Notify with the
        // `force_reconnect_notify` field below.
        let force_reconnect_notify_arc = Arc::new(tokio::sync::Notify::new());
        let mut runtime = Self {
            config_path,
            identity_dir: veil_dir_path.clone(),
            foreground_mode,
            registry,
            transport_ctx,
            // identity bundle built below after the
            // builder so the local closures that need `local_identity`
            // / `mlkem_ek` / etc. above can still reference the local
            // var bindings. See `identity:` field assignment below.
            logger: Arc::clone(&logger),
            metrics: metrics.clone(),
            hint_registry,
            state,
            live_sessions: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            session_close_generations: Arc::new(Mutex::new(std::collections::HashMap::new())),
            session_registry: shared_session_registry,
            app_registry,
            gateway,
            discovery,
            dht,
            control_plane,
            mesh_forwarder,
            // metrics is moved into the field below, so clone here first.
            mesh_bridge: Arc::new(
                GatewayBridge::new(local_node_id, role)
                    .with_metrics(
                        metrics
                            .as_ref()
                            .map(|m| Arc::clone(m) as Arc<dyn veil_mesh::MeshMetrics>),
                    )
                    // The leaf byte quota was built end to end — guard, adapter,
                    // builder — and then never attached here, so a greedy leaf
                    // was only ever counted, never throttled. Share the runtime's
                    // per-peer limiter: it enforces bytes ONLY when the operator
                    // sets `abuse.per_peer_bytes_per_sec`, so an unconfigured node
                    // keeps today's no-enforcement posture and a configured one
                    // finally gets the quota it asked for. `reload` swaps the
                    // limiter's contents behind this same Arc, so the guard picks
                    // up a new config without rebuilding.
                    .with_leaf_bandwidth_quota(Arc::new(
                        crate::mesh_glue::LeafBandwidthGuard::from_limiter(Arc::clone(
                            &rate_limiter,
                        )),
                    )),
            ),
            mesh_realm,
            autodiscovered_peers: Arc::new(veil_mesh::AutoDiscoveredPeers::new()),
            // trips when a synthetic-range gateway session
            // closes, so `spawn_gateway_autodiscover_loop` can wake
            // immediately and back-fill instead of waiting for its
            // periodic poll. Drives the < 1 s failover acceptance bar.
            gateway_failover_notify: Arc::new(tokio::sync::Notify::new()),
            // see field doc comment.
            force_reconnect_notify: Arc::clone(&force_reconnect_notify_arc),
            // mobility slice: outbound-session-established fan-out
            // (srflx re-probe + debounced force_reconnect wake).
            connectivity_gain: Arc::new(crate::connectivity_gain::ConnectivityGain::new(
                force_reconnect_notify_arc,
            )),
            // shared push-event bus. Default capacity (256)
            // — fast subscribers consume events in microseconds; only
            // pathologically slow consumers (Flutter UI mid-paint) ever
            // hit the lag boundary, and they get a one-frame skip
            // rather than a stalled publisher.
            event_bus: Arc::new(veil_ipc::EventBus::new()),
            // empty registry of node_ids with active
            // outbound-connector tasks; populated atomically inside
            // `spawn_outbound_peers`.
            outbound_connector_refresh: Arc::new(Mutex::new(std::collections::HashMap::new())),
            // load cached discovered peers from disk if
            // configured. Missing/corrupt file → empty cache (no
            // panic — first-run case) so node still boots.
            //
            // HMAC the cache against a
            // per-device key stored next to the daemon's veil_dir
            // so a local attacker that rewrites the JSON cannot
            // make us dial peers of their choosing. The key file
            // is auto-generated on first start.
            discovered_peers_cache: Arc::new(Mutex::new({
                let cache_path: Option<std::path::PathBuf> = config
                    .global
                    .discovered_peers_cache_path
                    .as_ref()
                    .map(std::path::PathBuf::from);
                let key_dir = cache_path
                    .as_ref()
                    .and_then(|p| p.parent())
                    .map(|p| p.to_path_buf());
                let hmac_key = key_dir
                    .as_ref()
                    .and_then(|d| veil_bootstrap::load_or_generate_cache_hmac_key(d).ok());
                match (cache_path, hmac_key) {
                    (Some(p), Some(k)) => {
                        veil_bootstrap::DiscoveredPeerCache::load_with_hmac_key(p, k)
                    }
                    (Some(p), None) => veil_bootstrap::DiscoveredPeerCache::load(p),
                    (None, _) => veil_bootstrap::DiscoveredPeerCache::in_memory(),
                }
            })),
            // decomposition PR1: bundle the four
            // anonymity-related fields into a dedicated AnonymityState.
            // Reuses the SAME x25519 Arc that was passed into the
            // dispatcher above, so the publish task (which reads the
            // field on NodeRuntime) and the inbound RelayChain handler
            // (which reads the dispatcher's field) operate on the same
            // key. When relay is disabled, both are None — but we
            // still need *some* SK for `tick_publish_relay_directory_entry`
            // to be a no-op, so fall back to a fresh ephemeral so the
            // type signature stays `Arc<StaticSecret>`. The publish
            // helper's `relay_capable = false` early-return guards
            // against this fallback ever being used.
            anonymity: Arc::new(anonymity_state::AnonymityState::new(
                config.anonymity.relay_capable,
                config.anonymity.advertised_bps,
                anonymity_x25519_sk_for_dispatcher
                    .clone()
                    .unwrap_or_else(|| {
                        Arc::new(x25519_dalek::StaticSecret::random_from_rng(
                            rand_core::OsRng,
                        ))
                    }),
                config.anonymity.onion_service.then(|| {
                    config
                        .anonymity
                        .onion_service_hops
                        .map_or(3, |h| h as usize)
                }),
                // Δ2-h: operator-pinned rendezvous relays, parsed once so
                // select_onion_relay_path can honour them.
                config
                    .anonymity
                    .rendezvous_relays
                    .iter()
                    .filter_map(|s| {
                        <veil_cfg::NodeId as std::str::FromStr>::from_str(s)
                            .ok()
                            .map(|n| *n.as_bytes())
                    })
                    .collect(),
            )),
            mailbox_state: Arc::new(mailbox_state::MailboxState::new(
                mailbox_handle,
                outbox_handle,
            )),
            builtin_app_host: Some(crate::builtin::BuiltinAppHost::new()),
            routing: Arc::new(routing_state::RoutingState::new(
                shared_rtt_table,
                route_cache,
                Arc::clone(&shared_neighbor_scorer),
                Arc::clone(&shared_vivaldi),
            )),
            rate_limiter,
            nat_probe_backoff: Arc::new(Mutex::new(PerPeerLimiter::new(
                NAT_PROBE_SUSTAINED_PER_SEC,
                NAT_PROBE_BURST,
                NAT_PROBE_IDLE_FORGET,
            ))),
            ban_list,
            violation_tracker,
            runtime_summary: Arc::new(Mutex::new(RuntimeSummary {
                role: role.to_string(),
                ..Default::default()
            })),
            dispatcher,
            next_link_id: Arc::new(AtomicU64::new(1)),
            next_listener_handle: Arc::new(AtomicU64::new(1)),
            pending_accepts: Arc::new(Mutex::new(BTreeMap::new())),
            metrics_path: resolve_metrics_path(&config),
            metrics_endpoint: None,
            shutdown_tx: None,
            ephemeral_rotator_shutdowns: Mutex::new(Vec::new()),
            rendezvous_controller: Mutex::new(None),
            tasks: Arc::new(Mutex::new(RuntimeTasks::default())),
            health_tick: Arc::new(AtomicU64::new(0)),
            session_tx_registry: shared_session_tx_registry,
            session_outbox,
            wire_stream_counter: Arc::new(AtomicU32::new(1)),
            // bundle identity-domain fields into one Arc.
            identity: Arc::new(identity_state::IdentityState::new(
                Arc::clone(&local_identity),
                sovereign_cell,
                Arc::clone(&peer_pubkeys),
                Arc::clone(&peer_sovereign_identities),
                Arc::clone(&peer_roles),
                Arc::clone(&mlkem_keys),
                Arc::clone(&shared_peer_mlkem_keys),
                Arc::clone(&shared_peer_mlkem_certs),
                Arc::clone(&shared_peer_mlkem_cert_store),
                Arc::clone(&shared_peer_ratchet_keys),
                Arc::clone(&shared_per_session_mlkem_dk),
            )),
            sessions_per_ip: Arc::new(ip_slot::IpSlotTable::new()),
            scanner_shield: Arc::new(veil_abuse::scanner_shield::ScannerShield::new()),
            // pre-spawn inbound handshake cap. See struct field doc.
            // Derive cap from session defaults `max_concurrent`: 4× the
            // post-handshake session cap, floor 1024.  At default
            // `max_concurrent=512` → 2048 permits; at relay-class
            // `max_concurrent=65_536` → 262144 permits.
            inbound_handshake_sem: Arc::new(tokio::sync::Semaphore::new(
                config.session.max_concurrent.saturating_mul(4).max(1024),
            )),
            inbound_handshake_sem_target: config.session.max_concurrent.saturating_mul(4).max(1024),
            mlkem_republish_now: Arc::new(tokio::sync::Notify::new()),
            dht_republish_now: Arc::new(tokio::sync::Notify::new()),
            pending_diag: Arc::clone(&shared_pending_diag),
            // H10 stage-B (4/N): 16 session-config knobs collapsed
            // into one `Arc<SessionDefaults>`. Same Arc is cloned into
            // NodeServices and SessionRuntimeContext at boundary builds.
            defaults: session_defaults::SessionDefaults::new(
                std::time::Duration::from_secs(config.session.keepalive_interval_secs),
                std::time::Duration::from_secs(config.session.idle_timeout_secs),
                config.session.max_pending_responses,
                std::time::Duration::from_millis(config.session.pending_response_ttl_ms),
                config.session.max_frame_body_bytes,
                config.session.rekey_bytes_threshold,
                config.session.rekey_time_threshold_secs,
                config.session.qos_weights.map(|w| w as u32),
                config.session.max_concurrent,
                config.session.referral_headroom,
                config.session.max_per_ip,
                config.session.max_per_subnet,
                std::time::Duration::from_secs(config.gateway.keepalive_interval_secs),
                std::time::Duration::from_millis(config.connection.reconnect_backoff_min_ms),
                std::time::Duration::from_millis(config.connection.reconnect_backoff_max_ms),
                config.connection.reconnect_quiet_after_failures,
            ),
            // bundled mobile / battery-tier state.
            mobile: Arc::new(mobile_state::MobileState::new(
                Arc::new(std::sync::atomic::AtomicBool::new(false)),
                config.session.battery_keepalive_scale_low,
                config.session.battery_keepalive_scale_medium,
                config.session.battery_threshold_low,
                config.session.battery_threshold_medium,
            )),
            // congestion monitor.
            congestion_monitor: shared_congestion_monitor,
            memory_budget: Arc::new(crate::memory::MemoryBudget::default_budget()),
            // route-cache persistence path (None = disabled).
            cache_persist_path: config.routing.cache_persist_path.clone(),
            // RTT table persistence path (None = disabled).
            rtt_persist_path: config.routing.rtt_persist_path.clone(),
            // Master switch for all persistence.
            persist_enabled: config.persist_enabled,
            // gateway list — same Arc shared with the dispatcher.
            gateway_list: Arc::clone(&shared_gateway_list),
            // record when the ML-KEM key was loaded so the admin
            // metrics endpoint can report key age.
            mlkem_key_loaded_at: Instant::now(),
            mlkem_key_path: mlkem_key_path.clone(),
            // discovery initiator channel — populated by spawn_discovery_initiator_task.
            discovery_trigger_tx: Arc::new(Mutex::new(None)),
            // H10 stage-B: session-resumption bundle —
            // ticket_issuer (fresh host ticket key) + peer_tickets (per-peer
            // cache populated at handshake-complete) wrapped together so the
            // 3 propagation structs (NodeRuntime / NodeServices /
            // SessionRuntimeContext) carry one `Arc<ResumptionState>` instead
            // of two siblings.
            resumption: Arc::new(resumption_state::ResumptionState::new(
                Arc::new(Mutex::new(
                    veil_session::ticket::TicketIssuer::new(
                        veil_session::ticket::TicketKey::generate(),
                    )
                    // The issuer refuses to resume an instance-less ticket from
                    // a peer we already know as a multi-device identity; the
                    // binding cache is what knows that, and it lives here.
                    .with_instance_oracle({
                        let bindings = Arc::clone(&peer_sovereign_identities);
                        Arc::new(move |peer: &[u8; 32]| {
                            lock!(bindings).keys().any(|(id, _)| id == peer)
                        })
                    }),
                )),
                Arc::new(Mutex::new(std::collections::HashMap::new())),
            )),
            // H10 stage-B: PEX bundle — 4 PEX fields collapsed
            // (state + 3 channels) into one owned `PexRuntime`. Receivers
            // remain `Option<...>` inside the bundle so the initiator/
            // connector tasks can `.take()` them at spawn time.
            pex: pex_runtime::PexRuntime::new(
                Arc::clone(&shared_pex_state),
                pex_event_rx,
                pex_connect_tx,
                pex_connect_rx,
            ),
            // sovereign_identity now lives inside the
            // `identity: Arc<IdentityState>` bundle initialised earlier
            // in this literal. Local var consumed by the IdentityState
            // ctor; nothing else to assign here.
            // H10 stage-B: 5 handoff fields collapsed into
            // one `Arc<HandoffRuntime>` bundle. hot_standby_controller_arc
            // is built once before the runtime literal from pre-extracted
            // Arcs (registry / transport_ctx / shared_session_tx_registry
            // / handoff_ack_waiters_arc / swap_registry_arc / logger);
            // pre-cleanup, a throwaway "placeholder" was constructed
            // here and immediately replaced after the literal closed
            // because the real Arcs weren't addressable yet through
            // `runtime.x`.
            handoff: Arc::new(handoff_runtime::HandoffRuntime::new(
                Arc::new(crate::runtime::handoff::HandoffRegistry::new()),
                Arc::clone(&swap_registry_arc),
                Arc::clone(&handoff_ack_waiters_arc),
                Arc::clone(&hot_standby_controller_arc),
                config.hot_standby.auto_trigger_after_write_errors,
            )),
            allowed_peer_algos: config.session.allowed_peer_algos.clone(),
            // P-Net Phase 3b: gate was constructed early so the DHT
            // ingest path could be wired before `Arc::new(svc)`. Stash
            // the same Arc here so the rest of the runtime (handshake,
            // ban-sync) sees the same gate instance.
            network_gate: network_gate_arc.clone(),
            // S2.A part 3: per-peer verified-cert cache. Filled by
            // handshake on successful verify_peer; read by PnetStatusProvider
            // when an IPC consumer (ogate/oproxy) queries a peer's
            // admission state.
            verified_peer_certs: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            // real-P2P Stage B: single-flight registry for explicit
            // call-path hole-punch attempts (peer → in-flight outcome).
            hole_punch_inflight: Arc::new(Mutex::new(std::collections::HashMap::new())),
            // open the admin audit log next to the config
            // file (typically <veil-dir>/admin-audit.log). A
            // failure to open is logged and the runtime continues
            // without auditing — denying node startup because audit
            // disk-space is full would be worse than missing audit
            // entries until disk-space is reclaimed.
            admin_audit: {
                // `config_path` is already moved into one of the
                // earlier fields by name; recover the parent dir
                // from the `veil_dir_path` (computed at line ~738
                // for exactly this kind of derived setup).
                let dir = veil_dir_path.clone();
                match crate::admin_audit::AdminAuditLog::open(&dir) {
                    Ok(a) => Some(Arc::new(a)),
                    Err(e) => {
                        logger.warn(
                            "admin.audit.open_failed",
                            format!("dir={} err={e} — audit disabled", dir.display()),
                        );
                        None
                    }
                }
            },
        };
        // prime the global mobile background-mode
        // multiplier from config so session runners see it on
        // their first keepalive recomputation tick. The flag
        // itself stays false until SetMobileBackgroundMode flips
        // it; this just sets the SCALE that flip applies.
        veil_session::runner::set_mobile_background_keepalive_multiplier(
            config.mobile.background_keepalive_multiplier,
        );
        // deferred : prime the outbound-batch
        // signals. Default config: threshold = None → disabled
        // sentinel; window = None → 0. Both must be configured
        // for coalescing to engage (gated in `current_outbound_batch_window`).
        veil_session::runner::set_mobile_low_battery_threshold_pct(
            config.mobile.low_battery_threshold_pct,
        );
        veil_session::runner::set_mobile_outbound_batch_window_ms(
            config.mobile.outbound_batch_window_ms.unwrap_or(0),
        );
        // The battery-independent opt-in. Without priming it the config field
        // would parse and then do nothing, which is the failure mode the
        // window itself already had.
        veil_session::runner::set_mobile_outbound_batch_always(config.mobile.outbound_batch_always);
        // prime the global session-rotation interval
        // (0 = disabled). Runtime-side clamp ensures any value
        // < 60 gets pushed up to the floor, defending against
        // misconfig OR validation bypass.
        //
        // `[transport.rotation]` is the only knob; `-1`/`-1` disables.
        match config.transport.rotation.resolved_range() {
            Some((min, max)) => veil_session::runner::set_session_rotation_range(min, max),
            None => veil_session::runner::set_session_rotation_range(0, 0),
        }
        // cleanup: hot_standby_controller + per-peer
        // alt_uri now built before the runtime literal (see. above).
        // Pre-cleanup, this block replaced a throwaway placeholder
        // controller; the placeholder is gone, this block with it.
        // –164: restore snapshots only when persistence is globally enabled.
        if config.persist_enabled {
            // restore route cache from snapshot before accepting connections.
            runtime.restore_route_cache_snapshot(&config);
            // restore RTT table from snapshot.
            runtime.restore_rtt_snapshot(&config);
            // restore Vivaldi coordinate.
            runtime.restore_vivaldi_snapshot(&config);
            // restore DHT routing table contacts.
            runtime.restore_dht_routing_snapshot(&config);
            // restore DHT stored values.
            runtime.restore_dht_values_snapshot(&config);
            // restore autodiscovered peers.
            runtime.restore_autodiscover_snapshot(&config);
            // restore gateway list; then rebuild from config (config entries take precedence).
            runtime.restore_gateway_list_snapshot(&config);
            // restore peer pubkeys cache.
            runtime.restore_peer_pubkeys_snapshot(&config);
            //restore peer transport announcements.
            runtime.restore_transport_announcements_snapshot(&config);
        } // end if config.persist_enabled
        // populate gateway list from configured peers (always, regardless of persist).
        runtime.rebuild_gateway_list_from_state();
        runtime.logger.info(
            "node.start",
            format!("config={}", runtime.config_path.display()),
        );
        // every background task the runtime keeps alive lives in
        // `RuntimeService::ALL`; both start and reload walk that list so they
        // cannot drift out of sync. The dispatch table lives in
        // `spawn_service`.
        runtime.spawn_all_services(&config).await?;
        // onion-stream Phase 1d: publish a services view for the embedded FFI to
        // drive pinned stream circuits in-process (the IPC surface has none).
        crate::runtime::services::publish_embedded_services(runtime.access());
        Ok(runtime)
    }
}
