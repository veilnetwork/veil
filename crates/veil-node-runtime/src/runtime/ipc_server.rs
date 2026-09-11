//! The local IPC server: the one socket an app on this machine talks through.
//!
//! One method, six hundred lines, and every one of them is wiring: the server
//! is where each app-facing capability is handed the piece of runtime state it
//! answers from — the mailbox, the outbox, the rendezvous resolver, the
//! anonymous onion sender, the push-envelope sink. Nothing here decides
//! anything; the backends it installs live in `ipc_bridges.rs` and the
//! anonymity modules, and this is the assembly that connects them to a socket.
//!
//! That is exactly why it wants its own file. It is the single largest
//! statement of what the app can reach, and reading it in the middle of a
//! module about background tasks meant reading past it every time.
//!
//! Moved verbatim out of `service_tasks.rs` (report24 RUNTIME-3). Behaviour
//! is unchanged; the same inherent method on the same type.

use std::sync::Arc;

use veil_util::wlock;

use crate::builtin::PushTrigger;
use veil_ipc::{IpcServer, path::default_ipc_socket_path};

use super::ipc_bridges::{MailboxIpcBridge, OutboxIpcBridge, RendezvousPushEnvelopeForwarder};
use super::push_tasks::{
    HotReloadDispatcher, build_push_dispatcher, push_creds_watch_task, push_dispatch_task,
};
use super::rendezvous_resolver::{RendezvousResolverImpl, RuntimeAnonOnionSender};
use super::{NodeRuntime, lock_tasks};

impl NodeRuntime {
    pub fn spawn_ipc_server(&mut self, config: &veil_cfg::Config) {
        // b: IPC server now supports both Unix-domain socket and
        // TCP-loopback backends, so spawning it works on every platform.
        if !config.ipc.enabled {
            return;
        }
        let Some(shutdown_tx) = &self.shutdown_tx else {
            return;
        };
        let shutdown_rx = shutdown_tx.subscribe();
        // b: dispatch on `ipc.socket_uri` (Unix or TCP-loopback).
        // `socket_path` remains the legacy fallback for Unix-only deployments.
        // Pass config-file dir so TCP-endpoint sidecars land NEXT TO the
        // config (multi-node-friendly default; multi nodes on the same host
        // each have their own config dir → no clobbering).
        let config_dir = self.config_path.parent();
        let default_runtime_dir = veil_cfg::runtime_veil_dir();
        let endpoint = match veil_ipc::path::resolve_ipc_endpoint(
            &config.ipc,
            config_dir,
            &default_runtime_dir,
        ) {
            Ok(ep) => ep,
            Err(e) => {
                self.logger.warn(
                    "ipc.config.invalid",
                    format!("could not resolve [ipc] endpoint, ipc disabled: {e}"),
                );
                return;
            }
        };
        let anchor_for_log =
            match veil_ipc::path::ipc_anchor_path(&config.ipc, config_dir, &default_runtime_dir) {
                Ok(p) => p,
                Err(_) => default_ipc_socket_path(),
            };
        self.logger
            .info("ipc.start", format!("anchor={}", anchor_for_log.display()));
        let node_id = *self.identity.local_identity.node_id.as_bytes();
        let app_registry = Arc::clone(&self.app_registry);
        // veil-ipc's IpcServer takes Arc<dyn FrameBroadcaster>.
        // Wrap our concrete Arc<RwLock<SessionTxRegistry>> in the production
        // SessionTxBroadcaster adapter so the trait dispatch matches.
        let session_tx_broadcaster: Arc<dyn veil_types::FrameBroadcaster> = Arc::new(
            veil_session::glue::SessionTxBroadcaster::new(Arc::clone(&self.session_tx_registry)),
        );
        let route_cache = Arc::clone(&self.routing.route_cache);
        let route_updated = Arc::clone(&self.dispatcher.route_updated);
        // Epic 486.1 slice 3 (audit batch 2026-05-23): construct cold-start
        // ML-KEM EK resolver and attach it to the IPC server.  When the IPC
        // sender's local `peer_mlkem_keys` cache misses for a target node_id,
        // the resolver fetches + verifies the recipient's EK from DHT (instance
        // registry walk + cert chain) and populates the cache.
        // One concrete resolver instance serves BOTH the ML-KEM EK lookup AND
        // the relay-X25519-by-node_id lookup (`RelayKeyResolver`) — they share
        // the same DHT walk + document fetch, so we coerce the single Arc into
        // both trait objects rather than building two.
        let dht_key_resolver = Arc::new(crate::mlkem_resolver::DhtMlKemEkResolver::new(
            Arc::clone(&self.dht),
            Arc::clone(&self.session_tx_registry),
            Arc::clone(&self.dispatcher.pending_recursive),
            *self.identity.local_identity.node_id.as_bytes(),
            Arc::clone(&self.identity.peer_mlkem_keys),
            Arc::clone(&self.identity.peer_ratchet_keys),
            Arc::clone(&self.identity.peer_mlkem_certs),
            Arc::clone(&self.identity.peer_mlkem_cert_store),
            Arc::clone(&self.logger),
        ));
        let mlkem_ek_resolver: Arc<dyn veil_types::MlKemEkResolver> =
            Arc::clone(&dht_key_resolver) as Arc<dyn veil_types::MlKemEkResolver>;
        // The dispatcher already holds this; the send path needs the same one.
        let Some(ratchet_runtime) = self.dispatcher.crypto.ratchet.clone() else {
            unreachable!("the dispatcher is always built with a ratchet runtime")
        };
        // Defect №35, sender-side feedback: a peer answering AppSendUnopenable
        // has just refused something we sealed — a wedged conversation, or a
        // frame keyed to a sibling device of its family. The dispatcher
        // forgets the conversation; THIS closure is what keeps the re-key from
        // re-sealing to the identical wrong row the resolver still holds
        // cached (30-minute TTL). Set in-place on the shared slot because the
        // dispatcher (and its session clones) were built before this resolver
        // existed.
        {
            let resolver = Arc::clone(&dht_key_resolver);
            *self
                .dispatcher
                .peer_cert_invalidate
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(move |peer: &[u8; 32]| {
                resolver.invalidate_peer(peer)
            }));
        }
        let relay_key_resolver: Arc<dyn veil_types::RelayKeyResolver> =
            dht_key_resolver as Arc<dyn veil_types::RelayKeyResolver>;
        // Authenticated anonymous (onion/rendezvous) sender for the IPC
        // `anonymous_authenticated` flag. Holds the access bundle + the
        // configured circuit length.
        let anon_onion_sender: Arc<dyn veil_types::AnonOnionSender> =
            Arc::new(RuntimeAnonOnionSender::new(
                self.access(),
                config.anonymity.default_hop_count.unwrap_or(2).max(1) as usize,
            ));
        let mut server = IpcServer::new(endpoint, shutdown_rx, app_registry, node_id)
            .with_session_tx_registry(session_tx_broadcaster)
            // Cross-node IPC STREAM_OPEN forwarding: share the dispatcher's
            // inbound routing tables + the runtime-wide wire stream-id counter
            // (also used by VeilConnector) so remote streams bridge cleanly.
            .with_stream_bridge(veil_ipc::bridge::IpcStreamBridge {
                veil_stream_rx: Arc::clone(&self.dispatcher.veil_stream_rx),
                pending_receipts: Arc::clone(&self.dispatcher.pending_stream_receipts),
                wire_stream_counter: Arc::clone(&self.wire_stream_counter),
            })
            .with_route_cache(route_cache)
            .with_route_updated(route_updated)
            .with_e2e_keys(Arc::clone(&self.identity.peer_mlkem_keys))
            .with_mlkem_ek_resolver(mlkem_ek_resolver)
            // Defect №35, the pairing rule: the ratchet seal must resolve the
            // cert for the DEVICE the live session terminates at, not for
            // whichever registry row the resolver's zero-valued freshness tie
            // happened to hand back. The session registry's validated
            // identities are the one place that knows the far device.
            .with_session_instance_lookup(Arc::new(
                veil_session::glue::SessionInstanceDirectory::new(Arc::clone(
                    &self.session_registry,
                )),
            ))
            .with_relay_key_resolver(relay_key_resolver)
            // The SAME conversations the frame dispatcher opens with. Two
            // stores would mean a session advanced on send and not on receive:
            // the peer's reply would arrive for a chain that never moved.
            .with_ratchet(ratchet_runtime)
            .with_anon_onion_sender(anon_onion_sender)
            // Offline-mailbox seal/open (node-side E2E crypto). DORMANT — no app
            // sends MailboxSeal/Open yet; wired so the path is live once an app
            // does.
            .with_mailbox_crypto_sink(std::sync::Arc::new(self.mailbox_crypto()))
            .with_trace_sample_rate(config.routing.trace_sample_rate)
            .with_pending_ack(Arc::clone(&self.dispatcher.pending_ack))
            .with_pending_recursive(Arc::clone(&self.dispatcher.pending_recursive));
        if let Some(ref m) = self.metrics {
            server = server.with_metrics(Arc::clone(m) as Arc<dyn veil_ipc::IpcMetrics>);
        }
        let anycast_policy = match config.anycast.resolve_policy {
            veil_cfg::AnycastResolvePolicyKind::BestEffort => {
                veil_anycast::AnycastResolvePolicy::BestEffort
            }
            veil_cfg::AnycastResolvePolicyKind::SignedOnly => {
                veil_anycast::AnycastResolvePolicy::SignedOnly
            }
            veil_cfg::AnycastResolvePolicyKind::SignedBound => {
                veil_anycast::AnycastResolvePolicy::SignedBound
            }
        };
        // Audit batch 2026-05-25 phase O (cross-audit #3 closure):
        // if sovereign identity wired AND uses Ed25519, configure
        // anycast to auto-sign all advertise calls (including those
        // initiated through IPC `AnycastAdvertise`).  Resolvers running
        // `SignedOnly` / `SignedBound` will admit our records.  PQ-only
        // sovereign identities (Falcon-512) fall through to unsigned
        // v1 advertise — caller-side opt-in to sign would require Falcon
        // anycast support, which is a separate wire-compat exercise.
        let mut anycast_svc_builder = veil_anycast::AnycastService::new(
            Arc::clone(&self.dht),
            *self.identity.local_identity.node_id.as_bytes(),
        )
        .with_policy(anycast_policy);
        if let Some(sov) = self.identity.sovereign_identity.get() {
            // Algo-generic owner-signer: signs v2 (Ed25519) OR v3 (Falcon-512 /
            // hybrid) records, so a PQ-only sovereign signs too instead of
            // falling back to unsigned advertise. The index comes WITH the key:
            // 0 on a device whose own key is the master (self-signed binding),
            // its own index on every other device (the document proves the
            // binding). Several nodes answering on one identity address is what
            // anycast is for, and pinning this to 0 disabled exactly that.
            if let Some((algo_byte, owner_pubkey, sig_key_idx, sign)) = sov.anycast_owner_signer() {
                match veil_types::SignatureAlgorithm::from_wire_byte(algo_byte) {
                    Some(algo) => {
                        anycast_svc_builder = anycast_svc_builder.with_signer(
                            veil_anycast::AnycastSigner::new(algo, owner_pubkey, sig_key_idx, sign),
                        );
                    }
                    None => {
                        // Unreachable in practice: `identity_sk.algo()` only ever
                        // yields a known wire byte. Guard rather than panic.
                        self.logger.warn(
                            "anycast.signing.unknown_algo",
                            "sovereign identity reports an unrecognized signature \
                             algorithm byte: anycast records will be published \
                             UNSIGNED",
                        );
                    }
                }
            } else {
                // A device of an identity signs with its own key at its own
                // index, so this is no longer the multi-device case — that one
                // advertises. What is left is an identity whose active key sits
                // past index 255, which the record's `sig_key_idx` field cannot
                // name. Nothing can be signed for it; say so rather than let
                // unsigned records go out and be dropped in silence.
                self.logger.warn(
                    "anycast.signing.index_out_of_range",
                    "sovereign identity's active device key is past index 255, \
                     which an anycast record cannot name: records are published \
                     UNSIGNED and dropped by peers running the default \
                     SignedBound resolve policy",
                );
            }
        }
        // Admit records signed by a DEVICE of an identity, not only by its
        // master. Every device of one identity answers on the same address, so
        // without this the strict resolve policy drops every multi-device
        // identity — which is the arrangement anycast exists to serve.
        //
        // The local shard only, on purpose: the filter it feeds is
        // synchronous, and a resolve must not block on a DHT walk. A node that
        // does not hold the document answers `None` and drops the record, the
        // same conservative outcome as before delegation existed. The K-closest
        // to an identity DO hold it, and so does a node that has talked to that
        // identity.
        {
            let dht = Arc::clone(&self.dht);
            anycast_svc_builder = anycast_svc_builder.with_delegation_lookup(std::sync::Arc::new(
                move |node_id: &[u8; 32], idx: u8| {
                    let key = veil_proto::identity_document::IdentityDocument::dht_key(node_id);
                    let bytes = dht.get_local(&key)?;
                    let doc =
                        veil_proto::identity_document::IdentityDocument::decode(&bytes).ok()?;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    // The FULL ladder, clock included. This document came
                    // off the network: it is exactly the case the
                    // time-checked verifier is for, and an expired
                    // delegation must not keep advertising.
                    veil_identity::verify::verify_identity_document(&doc, now).ok()?;
                    // The verifier has established node_id == BLAKE3(master)
                    // and that every key here is master-certified, so the
                    // key at this index is authorised to speak for the
                    // address.
                    doc.identity_keys
                        .get(idx as usize)
                        .map(|k| k.pubkey.clone())
                },
            ));
        }
        let anycast_svc = Arc::new(anycast_svc_builder);
        server = server.with_anycast_service(anycast_svc);
        // share the hint registry so IPC clients can query it.
        server = server.with_hint_registry(Arc::clone(&self.hint_registry));
        // reuse the runtime-wide push-event bus. IpcServer
        // subscribes one receiver per connected client; runtime
        // publishers (session insert/remove sites + MobileEventForwarder)
        // share the same Arc so every event reaches every connected app.
        let event_bus: Arc<veil_ipc::EventBus> = Arc::clone(&self.event_bus);
        server = server.with_event_bus(Arc::clone(&event_bus));
        // 489.5: install mobile-event sink so apps can
        // toggle background mode and notify network-state changes via IPC.
        // The forwarder also publishes MOBILE_TIER_CHANGED events on
        // every tier transition.
        let mobile_sink: Arc<dyn veil_ipc::MobileEventSink> = Arc::new(
            crate::mobile_sink::MobileEventForwarder::new(
                Arc::clone(&self.logger),
                Arc::clone(&self.gateway_failover_notify),
                Arc::clone(&self.force_reconnect_notify),
                Arc::clone(&self.session_tx_registry),
            )
            .with_event_bus(Arc::clone(&event_bus)),
        );
        server = server.with_mobile_event_sink(mobile_sink);
        // surface daemon's signing-pubkey + algo to IPC clients
        // so Flutter / Swift / Kotlin UIs can display "you are: …" without
        // scraping VEIL_LOCAL_NODE_ID env or admin-socket round-trip.
        // Decode the base64 pubkey once at IPC-server construction; if
        // decoding fails fall back to empty bytes (clients still get node_id).
        let identity_pubkey_bytes = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD
                .decode(self.identity.local_identity.public_key.as_bytes())
                .unwrap_or_default()
        };
        server = server.with_local_identity(
            self.identity.local_identity.algo.wire_byte(),
            identity_pubkey_bytes,
        );
        // peer-list provider — answers `LocalAppMsg::GetPeers`
        // by snapshotting `live_sessions` (cheap mutex-and-clone, no
        // network I/O). Without it Flutter UI has to poll mobile_status
        // through admin socket, which requires admin-token (operator-only).
        let peer_list: Arc<dyn veil_ipc::PeerListProvider> = Arc::new(
            crate::peer_list_provider::LiveSessionsPeerList::new(Arc::clone(&self.live_sessions)),
        );
        server = server.with_peer_list_provider(peer_list);
        // S2.A: P-Net status provider — surfaces verified cert state
        // to IPC consumers (ogate / oproxy) for app-layer admission
        // decisions.  Empty cache (public-mode daemon) ⇒ all queries
        // reply has_cert=false; strict-p_net apps reject downstream.
        let pnet_status: Arc<dyn veil_ipc::PnetStatusProvider> =
            Arc::new(crate::pnet_status_provider::DaemonPnetStatus::new(
                Arc::clone(&self.verified_peer_certs),
                Arc::clone(&self.live_sessions),
            ));
        server = server.with_pnet_status_provider(pnet_status);
        // Listen-transports provider — surfaces the dispatcher's listener
        // snapshot (wildcard hosts rewritten to the observed external IP
        // after a server-reflexive NAT probe) so apps can mine their own
        // external ip:port candidates for direct-endpoint exchange
        // (real-P2P epic, Stage B). Cheap read-lock + clone.
        struct DispatcherListenTransports(Arc<veil_dispatcher::FrameDispatcher>);
        impl veil_ipc::ListenTransportsProvider for DispatcherListenTransports {
            fn listen_transports(&self) -> Vec<String> {
                // Advertisable listeners first, then the raw srflx
                // observations as `srflx://ip:port` pseudo-URIs (the
                // observed PORT is the probe session's mapping, not a
                // listener port — consumers substitute their own).
                let mut out = self.0.listen_transports_snapshot();
                out.extend(
                    self.0
                        .own_external_addrs_snapshot()
                        .into_iter()
                        .map(|a| format!("srflx://{a}")),
                );
                out
            }
        }
        let listen_transports: Arc<dyn veil_ipc::ListenTransportsProvider> =
            Arc::new(DispatcherListenTransports(Arc::clone(&self.dispatcher)));
        server = server.with_listen_transports_provider(listen_transports);
        // Explicit call-path hole-punch driver (real-P2P Stage B). The IPC
        // `AttemptHolePunch` request runs one bounded punch attempt on the
        // runtime's NAT orchestration; contract (budget / single-flight /
        // idempotency / anonymity refusal) lives in
        // `NodeServices::attempt_p2p_hole_punch`.
        struct RuntimeHolePunchDriver(crate::runtime::NodeServices);
        impl veil_ipc::HolePunchDriver for RuntimeHolePunchDriver {
            fn attempt_hole_punch<'a>(
                &'a self,
                peer_node_id: [u8; 32],
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = veil_ipc::HolePunchOutcome> + Send + 'a>,
            > {
                Box::pin(self.0.attempt_p2p_hole_punch(peer_node_id))
            }
        }
        let hole_punch: Arc<dyn veil_ipc::HolePunchDriver> =
            Arc::new(RuntimeHolePunchDriver(self.access()));
        server = server.with_hole_punch_driver(hole_punch);
        // bootstrap-URI join sink — handles `JoinBootstrapUri`
        // requests by decoding the URI and registering the resulting
        // peer for outbound dial. Critical for Flutter onboarding —
        // without it, an app receiving an `veil:` deep-link would
        // have to either re-implement the decode (Argon2id + Ed25519)
        // in Dart or shell out to veil-cli (impossible on Android).
        // Runtime-owned dial drain for app-added bootstrap peers. The IPC sink
        // can't spawn an outbound connector (needs &NodeServices + the shutdown
        // watch::Sender); it hands each registered peer over this channel and
        // this task — which holds both — spawns the reconnect loop. (audit
        // cycle-10: app-added peers were previously never dialed; the old
        // gateway_failover_notify kick woke a loop that only dials gateways.)
        let bootstrap_join: Arc<dyn veil_ipc::BootstrapJoinSink> = {
            // Rep-B-2: bound the app-added-peer dial queue so an IPC client
            // looping BootstrapJoin can't grow it without limit. A full queue
            // drops the dial (peer stays registered; dialed later) rather than
            // accumulating unboundedly.
            const BOOTSTRAP_JOIN_DIAL_QUEUE: usize = 128;
            let (dial_tx, mut dial_rx) = tokio::sync::mpsc::channel::<crate::types::PeerConfigEntry>(
                BOOTSTRAP_JOIN_DIAL_QUEUE,
            );
            if let Some(shutdown_tx) = &self.shutdown_tx {
                let dial_access = self.access();
                let dial_shutdown_tx = shutdown_tx.clone();
                let mut dial_shutdown_rx = shutdown_tx.subscribe();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = dial_shutdown_rx.changed() => break,
                            recv = dial_rx.recv() => match recv {
                                Some(entry) => {
                                    let _ = crate::outbound_connector::spawn_outbound_peers(
                                        vec![entry],
                                        &dial_access,
                                        &dial_shutdown_tx,
                                    );
                                    // A repeat join for an already-claimed peer
                                    // no-ops in spawn_outbound_peers (per-node-id
                                    // slot), but the live reconnect loop may be
                                    // mid 30-s sleep while the entry's transport
                                    // was just refreshed (P2P endpoint exchange /
                                    // network change). Kick it awake so the new
                                    // address is dialed now, not up to 30 s later.
                                    dial_access.force_reconnect_notify.notify_waiters();
                                }
                                None => break, // forwarder dropped → no more joins
                            },
                        }
                    }
                });
            }
            Arc::new(crate::bootstrap_join::BootstrapJoinForwarder::new(
                Arc::clone(&self.logger),
                Arc::clone(&self.state),
                Arc::clone(&self.dht),
                dial_tx,
            ))
        };
        server = server.with_bootstrap_join_sink(bootstrap_join);
        // bootstrap-invite-create sink (Epic 489.7 generator side).
        // Snapshot the daemon's `[identity]` keypair + first advertise URI
        // at register time — used by `CreateBootstrapInvite` IPC to
        // assemble a canonical `veil:bootstrap?…` URI (plain) or
        // `veil:pair?…` (when caller supplies a passphrase).
        let invite_create_sink: Arc<dyn veil_ipc::BootstrapInviteCreateSink> = {
            let identity_snap = Some((
                self.identity.local_identity.algo,
                self.identity.local_identity.public_key.clone(),
                self.identity.local_identity.nonce.clone(),
            ));
            let transport_snap = self.listens().into_iter().find_map(|l| {
                // Prefer explicit `advertise` (public hostname behind
                // nginx) over bind transport (e.g. tcp://0.0.0.0:443);
                // matches the CLI `bootstrap invite` address-picking
                // logic and what a live peer can actually dial.
                l.advertise.clone().or(Some(l.transport.clone()))
            });
            Arc::new(crate::bootstrap_invite_create::BootstrapInviteCreator::new(
                Arc::clone(&self.logger),
                identity_snap,
                transport_snap,
            ))
        };
        server = server.with_bootstrap_invite_create_sink(invite_create_sink);
        // multi-device pairing sinks (Epic 489.8).  One forwarder
        // instance handles both Source + Target sides — wire surface
        // shipped; ceremony plumbing fills in a follow-up slice.
        let veil_dir = self.identity_dir.clone();
        let pairing_fwd = Arc::new(crate::pairing_forwarder::PairingForwarder::new(
            Arc::clone(&self.logger),
            veil_dir,
            self.identity.sovereign_identity.get(),
        ));
        let pair_src: Arc<dyn veil_ipc::PairSourceSink> = pairing_fwd.clone();
        let pair_tgt: Arc<dyn veil_ipc::PairTargetSink> = pairing_fwd;
        server = server
            .with_pair_source_sink(pair_src)
            .with_pair_target_sink(pair_tgt);
        // mobile-status provider — answers `GetMobileStatus`
        // queries with current tier + battery + factors snapshot.
        let mobile_status: Arc<dyn veil_ipc::MobileStatusProvider> = Arc::new(
            crate::mobile_status_provider::RuntimeMobileStatus::new(self.config_path.clone()),
        );
        server = server.with_mobile_status_provider(mobile_status);
        //.2: push-envelope sink — handles `LocalAppMsg::SetPushEnvelope`
        // by routing to `NodeRuntime::set_rendezvous_push_envelope`. Without it
        // IPC handler responds with `NoMatchingRendezvous` for every client request
        // (graceful degradation on nodes without active rendezvous publications).
        let push_envelope_sink: Arc<dyn veil_ipc::PushEnvelopeSink> =
            Arc::new(RendezvousPushEnvelopeForwarder::new(Arc::clone(
                &self.anonymity.rendezvous_publisher_entries,
            )));
        server = server.with_push_envelope_sink(push_envelope_sink);
        // In-network deposit-wake LISTENER: every node may be a mailbox
        // RECEIVER (not just relays), so bind the wake endpoint unconditionally
        // — an inbound wake datagram from a relay becomes a MAILBOX_WAKE event
        // the client SDK turns into an immediate drain. Nodes older than this
        // endpoint simply have nothing bound and drop the wake silently.
        //
        // Because the binding is unconditional the SENDER is any session peer,
        // not necessarily a relay holding a deposit for us, and the per-receiver
        // `WAKE_DEBOUNCE` below is on the wrong side of the wire to help. The
        // listener therefore keeps its own per-sender debounce
        // (`builtin::mailbox::WAKE_RECV_DEBOUNCE`).
        if let Some(host) = self.builtin_app_host.as_mut() {
            let wake_ctx = host.make_context(
                *self.identity.local_identity.node_id.as_bytes(),
                Arc::clone(&self.app_registry),
            );
            crate::builtin::spawn_mailbox_wake_listener(
                host,
                wake_ctx,
                Arc::clone(&self.event_bus),
            );
        }
        //.4 P2/P3: wire mailbox IPC bridge
        // + push-dispatch task. Only present when operator opted in
        // (`mailbox.enabled`). Without it, `MailboxPut/Fetch/Ack`
        // reply with graceful "not a mailbox relay" / empty list / no-op.
        if let Some(mailbox) = self.mailbox_state.mailbox.as_ref() {
            // bounded channel. See
            // `crate::builtin::mailbox::PUSH_TRIGGER_QUEUE_CAP`
            // doc-comment for buffer-size rationale.
            let (push_tx, push_rx) = tokio::sync::mpsc::channel::<PushTrigger>(
                crate::builtin::mailbox::PUSH_TRIGGER_QUEUE_CAP,
            );
            // Clone the sender BEFORE moving into IPC bridge so the
            // built-in app service (spawned below) gets the same
            // channel — both put paths trigger pushes uniformly.
            let push_tx_for_app = push_tx.clone();
            let bridge: Arc<dyn veil_ipc::MailboxBackend> = Arc::new(MailboxIpcBridge::new(
                Arc::clone(mailbox),
                self.dispatcher.mailbox_cookie_registry.clone(),
                push_tx,
                Some(Arc::clone(&self.event_bus)),
            ));
            server = server.with_mailbox_backend(bridge);
            //.4 P6: build push dispatcher from operator
            // config. Falls back to LogOnly when no FCM/APNs creds
            // are configured (default — daemon doesn't contact any
            // third party). See `build_push_dispatcher` for
            // per-provider error handling.
            //
            //.4 followup: wrap in HotReloadDispatcher so
            // operators can rotate FCM/APNs credentials without
            // restarting the daemon. The mtime-watch task spawned
            // below polls credential paths every 60 s and swaps the
            // inner dispatcher in-place when either file changes.
            let initial_dispatcher = build_push_dispatcher(&config.mailbox.push);
            let hot_reload = Arc::new(HotReloadDispatcher::new(initial_dispatcher));
            let dispatcher: Arc<dyn veil_push::PushDispatcher> =
                Arc::clone(&hot_reload) as Arc<dyn veil_push::PushDispatcher>;
            // Spawn the cred-watch task — only when at least one
            // provider is configured (otherwise mtime polling on
            // empty paths is pointless and noisy).
            if config.mailbox.push.fcm_enabled() || config.mailbox.push.apns_enabled() {
                let watch_cfg = config.mailbox.push.clone();
                let watch_shutdown = shutdown_tx.subscribe();
                let watch_handle = tokio::spawn(push_creds_watch_task(
                    watch_cfg,
                    Arc::clone(&hot_reload),
                    watch_shutdown,
                ));
                lock_tasks(&self.tasks).sessions.push(watch_handle);
            }
            // Push task only runs if the relay has an X25519 secret
            // (otherwise unseal is impossible). Already guaranteed
            // by `mailbox.enabled` requiring `anonymity.relay_capable`
            // for sealing semantics — but we check defensively.
            if let Some(sk) = self.dispatcher.anonymity_x25519_sk.as_ref() {
                let sk_clone = Arc::clone(sk);
                let require_wake_hmac = config.mailbox.push.require_wake_hmac;
                if !require_wake_hmac {
                    // Startup advisory (audit cycle-2): with the gate off, the
                    // relay falls back to an UNauthenticated wake-only push for
                    // any receiver that hasn't uploaded a wake-HMAC envelope —
                    // forgeable by anyone who learns the push token. Operators
                    // who control their client fleet should enable the gate.
                    log::warn!(
                        "veil-push: [mailbox.push] require_wake_hmac is OFF — unauthenticated \
                         wake-only pushes are permitted (forgeable battery-drain/nuisance \
                         vector); set require_wake_hmac = true once clients opt into wake-HMAC"
                    );
                }
                let push_handle = tokio::spawn(push_dispatch_task(
                    push_rx,
                    sk_clone,
                    dispatcher,
                    require_wake_hmac,
                ));
                lock_tasks(&self.tasks).sessions.push(push_handle);
            }
            //.4 P5b: spawn the mailbox built-in app
            // service. Receives `MailboxPutPayload` from senders over
            // the veil app-message channel (cross-node fanout path)
            // and calls the same `Mailbox::put` the IPC bridge uses.
            // Both paths share the push_trigger channel — the dispatch
            // task drains regardless of source.
            //
            // Reuses `push_tx` cloned above so app-route puts trigger
            // pushes the same way IPC-route puts do.
            // Anonymous-reply egress for network FETCH (built BEFORE the mutable
            // `builtin_app_host` borrow so `self.access()` is free to borrow).
            // Gated on the relay X25519 secret like push: without it the node
            // can't run the onion send the reply needs. hop_count is nominal —
            // a reply routes over the requester's one-time reply path.
            let mailbox_reply_sender: Option<Arc<dyn veil_types::AnonOnionSender>> =
                self.dispatcher.anonymity_x25519_sk.is_some().then(|| {
                    Arc::new(RuntimeAnonOnionSender::new(self.access(), 2))
                        as Arc<dyn veil_types::AnonOnionSender>
                });
            if let Some(host) = self.builtin_app_host.as_mut() {
                let app_ctx = host.make_context(
                    *self.identity.local_identity.node_id.as_bytes(),
                    Arc::clone(&self.app_registry),
                );
                let push_tx_opt = if self.dispatcher.anonymity_x25519_sk.is_some() {
                    Some(push_tx_for_app)
                } else {
                    // No relay X25519 secret = can't unseal envelopes
                    // anyway. Drop the cloned sender so push triggers
                    // from the app service silently no-op.
                    drop(push_tx_for_app);
                    None
                };
                // In-network deposit WAKE sender: on a stored deposit, send a
                // tiny empty datagram to the receiver's wake endpoint over its
                // LIVE direct session with this relay (SessionTxRegistry is the
                // liveness test — no session, no frame). Debounced per receiver
                // so a backlog flush can't storm a client; a dropped wake only
                // costs latency (the poll schedule still drains). No new
                // linkage: the relay already stores deposits addressed to R's
                // public node_id AND authenticates R's session; the timing
                // profile equals the live-introduce forward it performs anyway.
                let wake_sender: crate::builtin::MailboxWakeSender = {
                    const WAKE_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(2);
                    const MAX_WAKE_DEBOUNCE_ENTRIES: usize = 1024;
                    let tx_registry = Arc::clone(&self.session_tx_registry);
                    let last_wake: std::sync::Mutex<
                        std::collections::HashMap<[u8; 32], std::time::Instant>,
                    > = std::sync::Mutex::new(std::collections::HashMap::new());
                    Arc::new(move |receiver: &[u8; 32]| -> bool {
                        {
                            let mut m = last_wake.lock().unwrap_or_else(|p| p.into_inner());
                            let now = std::time::Instant::now();
                            if m.get(receiver)
                                .is_some_and(|t| now.duration_since(*t) < WAKE_DEBOUNCE)
                            {
                                return false;
                            }
                            if m.len() >= MAX_WAKE_DEBOUNCE_ENTRIES {
                                m.retain(|_, t| now.duration_since(*t) < WAKE_DEBOUNCE);
                            }
                            m.insert(*receiver, now);
                        }
                        let payload = veil_proto::AppSendPayload {
                            src_app_id: veil_mailbox::MAILBOX_APP_ID,
                            app_id: veil_mailbox::MAILBOX_APP_ID,
                            endpoint_id: veil_mailbox::MAILBOX_WAKE_ENDPOINT_ID,
                            data: veil_bufpool::pooled_shared_from_vec(Vec::new()),
                        };
                        let body = payload.encode();
                        let mut hdr = veil_proto::header::FrameHeader::new(
                            veil_proto::family::FrameFamily::App as u8,
                            veil_proto::family::AppMsg::AppSend as u16,
                        );
                        hdr.body_len = body.len() as u32;
                        hdr.set_priority(veil_proto::priority::INTERACTIVE);
                        let mut frame = veil_proto::codec::encode_header(&hdr).to_vec();
                        frame.extend_from_slice(&body);
                        let guard = wlock!(tx_registry);
                        guard.send_to(receiver, veil_proto::priority::INTERACTIVE, frame)
                    })
                };
                crate::builtin::spawn_mailbox_app_service(
                    host,
                    app_ctx,
                    Arc::clone(mailbox),
                    push_tx_opt,
                    mailbox_reply_sender,
                    Some(wake_sender),
                );
            }
        }
        //.4 P4: wire sender-side outbox
        // bridge. Always wired when outbox opened successfully —
        // every node sends, so peer-sync is universally beneficial.
        if let Some(outbox) = self.mailbox_state.outbox.as_ref() {
            let bridge: Arc<dyn veil_ipc::OutboxBackend> =
                Arc::new(OutboxIpcBridge::new(Arc::clone(outbox)));
            server = server.with_outbox_backend(bridge);
        }
        //.4 P0: publish the relay-side
        // X25519 public key to apps via `NodeIdentityPayload`. Apps
        // need this exact key to seal push-envelopes that this relay
        // can later decrypt. `None` when the operator did not opt
        // into `anonymity.relay_capable` — apps see the field as
        // absent and must pick a different relay for sealing.
        if let Some(relay_pk) = self.anonymity_x25519_pk() {
            server = server.with_relay_x25519_pubkey(relay_pk);
        }
        //.4 P5c: wire the rendezvous-replica resolver
        // so apps can lookup K candidate mailbox-relays for a
        // receiver via IPC. Always wired — even on nodes without
        // `mailbox.enabled`, because senders need lookup to find
        // OTHER nodes' replicas (asymmetric: lookup-side vs
        // serve-side roles).
        let resolver: Arc<dyn veil_ipc::RendezvousReplicaResolver> =
            Arc::new(RendezvousResolverImpl::new(
                Arc::clone(&self.dht),
                Arc::clone(&self.session_tx_registry),
                Arc::clone(&self.dispatcher.pending_recursive),
                *self.identity.local_identity.node_id.as_bytes(),
                Arc::clone(&self.anonymity.rendezvous_resolve_cache),
                Arc::clone(&self.logger),
            ));
        server = server.with_rendezvous_resolver(resolver);
        // log IpcServer::run failure instead of swallowing.
        // Previously `let _ = server.run.await` made bind failures, rename
        // collisions on stale sockets, and any future `Err`-path in the run
        // loop completely invisible — operators would see `ipc.start` in the
        // log followed by silence, with no listener actually attached to the
        // socket file. Surfacing the error cost is one log line, gain is
        // every silent IPC failure becomes diagnosable on the spot.
        let logger = Arc::clone(&self.logger);
        let handle = tokio::spawn(async move {
            if let Err(e) = server.run().await {
                logger.error(
                    "ipc.run.exit_err",
                    format!("IPC server run loop exited with error: {e}"),
                );
            }
        });
        lock_tasks(&self.tasks).sessions.push(handle);
    }
}
