# files_to_check.md — security/code audit tracker

**Started:** 2026-06-02 · **HEAD:** bec329f9 · **Method:** read-only file-by-file via parallel audit agents.
**Scope:** 537 .rs files / 51 crates / ~277k LOC. Findings → AUDIT_REPORT (this session's response).

Legend: `[ ]` not yet · `[~]` wave in progress · `[x]` audited.

## Wave 1 (security-critical core) — IN PROGRESS
### crates/veil-crypto
- [x] crates/veil-crypto/src/identity.rs
- [x] crates/veil-crypto/src/identity_fingerprint.rs
- [x] crates/veil-crypto/src/kex.rs
- [x] crates/veil-crypto/src/lib.rs
- [x] crates/veil-crypto/src/pair_oob.rs
- [x] crates/veil-crypto/src/pow/interrupt.rs
- [x] crates/veil-crypto/src/pow/mod.rs
- [x] crates/veil-crypto/src/pow/score.rs
- [x] crates/veil-crypto/src/pow/search.rs
- [x] crates/veil-crypto/src/pow/state.rs
- [x] crates/veil-crypto/src/session_cipher.rs
- [x] crates/veil-crypto/src/session_kdf.rs
- [x] crates/veil-crypto/src/signature.rs
- [x] crates/veil-crypto/src/types.rs
- [x] crates/veil-crypto/src/wake_hmac.rs
- [x] crates/veil-crypto/src/x3dh.rs
### crates/veil-e2e
- [x] crates/veil-e2e/src/lib.rs
### crates/veil-identity
- [x] crates/veil-identity/src/error.rs
- [x] crates/veil-identity/src/freshness.rs
- [x] crates/veil-identity/src/identity_policy.rs
- [x] crates/veil-identity/src/instance.rs
- [x] crates/veil-identity/src/integration_tests.rs
- [x] crates/veil-identity/src/lib.rs
- [x] crates/veil-identity/src/master_file.rs
- [x] crates/veil-identity/src/master_qr.rs
- [x] crates/veil-identity/src/master_seed.rs
- [x] crates/veil-identity/src/migration.rs
- [x] crates/veil-identity/src/mlkem_fanout.rs
- [x] crates/veil-identity/src/network_access.rs
- [x] crates/veil-identity/src/network_ban.rs
- [x] crates/veil-identity/src/network_cert.rs
- [x] crates/veil-identity/src/pair_runtime.rs
- [x] crates/veil-identity/src/pair_transport.rs
- [x] crates/veil-identity/src/publish.rs
- [x] crates/veil-identity/src/resolver.rs
- [x] crates/veil-identity/src/signing_key.rs
- [x] crates/veil-identity/src/sovereign.rs
- [x] crates/veil-identity/src/sovereign_flow.rs
- [x] crates/veil-identity/src/verify.rs
### crates/veil-session
- [x] crates/veil-session/src/backpressure_signal.rs
- [x] crates/veil-session/src/battery_adjusted_keepalive.rs
- [x] crates/veil-session/src/cover_traffic.rs
- [x] crates/veil-session/src/dispatcher_sink.rs
- [x] crates/veil-session/src/fsm.rs
- [x] crates/veil-session/src/glue.rs
- [x] crates/veil-session/src/handoff.rs
- [x] crates/veil-session/src/handshake.rs
- [x] crates/veil-session/src/hot_standby.rs
- [x] crates/veil-session/src/keepalive_emit.rs
- [x] crates/veil-session/src/lib.rs
- [x] crates/veil-session/src/manager.rs
- [x] crates/veil-session/src/mlkem_rekey_context.rs
- [x] crates/veil-session/src/once_trigger.rs
- [x] crates/veil-session/src/outbound_batch_coalescer.rs
- [x] crates/veil-session/src/outbox.rs
- [x] crates/veil-session/src/pending_response_table.rs
- [x] crates/veil-session/src/priority_queue.rs
- [x] crates/veil-session/src/rekey_context.rs
- [x] crates/veil-session/src/rekey_rx_grace_buffer.rs
- [x] crates/veil-session/src/rendezvous.rs
- [x] crates/veil-session/src/rotation_deadline.rs
- [x] crates/veil-session/src/runner.rs
- [x] crates/veil-session/src/session_alias_guard.rs
- [x] crates/veil-session/src/ticket.rs
- [x] crates/veil-session/src/timers.rs
- [x] crates/veil-session/src/tx_registry.rs
- [x] crates/veil-session/src/warm_probe.rs
- [x] crates/veil-session/src/write_error_tracker.rs
### crates/veil-dht
- [x] crates/veil-dht/src/bucket_pollution_sim.rs
- [x] crates/veil-dht/src/churn_sim.rs
- [x] crates/veil-dht/src/iterative.rs
- [x] crates/veil-dht/src/kademlia.rs
- [x] crates/veil-dht/src/lib.rs
- [x] crates/veil-dht/src/lookup_cache.rs
- [x] crates/veil-dht/src/network_querier.rs
- [x] crates/veil-dht/src/republish.rs
- [x] crates/veil-dht/src/routing.rs
- [x] crates/veil-dht/src/shard.rs
- [x] crates/veil-dht/src/store.rs
- [x] crates/veil-dht/src/traits.rs
- [x] crates/veil-dht/src/transport_cache.rs
### crates/veil-dispatcher
- [x] crates/veil-dispatcher/src/anonymity.rs
- [x] crates/veil-dispatcher/src/app.rs
- [x] crates/veil-dispatcher/src/control.rs
- [x] crates/veil-dispatcher/src/delivery.rs
- [x] crates/veil-dispatcher/src/diag.rs
- [x] crates/veil-dispatcher/src/discovery.rs
- [x] crates/veil-dispatcher/src/lib.rs
- [x] crates/veil-dispatcher/src/pending_ack.rs
- [x] crates/veil-dispatcher/src/routing.rs
- [x] crates/veil-dispatcher/src/session.rs
- [x] crates/veil-dispatcher/src/sink_impl.rs
### crates/veil-dispatcher-state
- [x] crates/veil-dispatcher-state/src/lib.rs
### crates/veil-proto
- [x] crates/veil-proto/src/anycast.rs
- [x] crates/veil-proto/src/app.rs
- [x] crates/veil-proto/src/budget.rs
- [x] crates/veil-proto/src/codec.rs
- [x] crates/veil-proto/src/control.rs
- [x] crates/veil-proto/src/cursor.rs
- [x] crates/veil-proto/src/delivery.rs
- [x] crates/veil-proto/src/diag.rs
- [x] crates/veil-proto/src/discovery.rs
- [x] crates/veil-proto/src/e2e.rs
- [x] crates/veil-proto/src/epidemic.rs
- [x] crates/veil-proto/src/family.rs
- [x] crates/veil-proto/src/golden_tests.rs
- [x] crates/veil-proto/src/header.rs
- [x] crates/veil-proto/src/identity_contact.rs
- [x] crates/veil-proto/src/identity_document.rs
- [x] crates/veil-proto/src/identity_proof.rs
- [x] crates/veil-proto/src/instance_registry.rs
- [x] crates/veil-proto/src/introducer.rs
- [x] crates/veil-proto/src/ipc.rs
- [x] crates/veil-proto/src/lib.rs
- [x] crates/veil-proto/src/mesh.rs
- [x] crates/veil-proto/src/mlkem_cert.rs
- [x] crates/veil-proto/src/name_claim_v2.rs
- [x] crates/veil-proto/src/pair_session.rs
- [x] crates/veil-proto/src/pairing_invite.rs
- [x] crates/veil-proto/src/pex.rs
- [x] crates/veil-proto/src/prekey_bundle.rs
- [x] crates/veil-proto/src/recipient.rs
- [x] crates/veil-proto/src/relay_chain.rs
- [x] crates/veil-proto/src/rendezvous.rs
- [x] crates/veil-proto/src/routing.rs
- [x] crates/veil-proto/src/serde_base64.rs
- [x] crates/veil-proto/src/session.rs
- [x] crates/veil-proto/src/time_validity.rs
- [x] crates/veil-proto/src/transport_hints.rs
- [x] crates/veil-proto/tests/decode_panic_resistance.rs
### crates/veil-node-runtime
- [x] crates/veil-node-runtime/src/admin.rs
- [x] crates/veil-node-runtime/src/admin_audit.rs
- [x] crates/veil-node-runtime/src/admin_transport.rs
- [x] crates/veil-node-runtime/src/bootstrap_invite_create.rs
- [x] crates/veil-node-runtime/src/bootstrap_join.rs
- [x] crates/veil-node-runtime/src/builtin/host.rs
- [x] crates/veil-node-runtime/src/builtin/mailbox.rs
- [x] crates/veil-node-runtime/src/builtin/mod.rs
- [x] crates/veil-node-runtime/src/dht_fallback.rs
- [x] crates/veil-node-runtime/src/dht_glue.rs
- [x] crates/veil-node-runtime/src/error.rs
- [x] crates/veil-node-runtime/src/identity_local/anonymity_x25519.rs
- [x] crates/veil-node-runtime/src/identity_local/mod.rs
- [x] crates/veil-node-runtime/src/identity_local/publisher_dht.rs
- [x] crates/veil-node-runtime/src/key_passphrase.rs
- [x] crates/veil-node-runtime/src/lazy_miner.rs
- [x] crates/veil-node-runtime/src/lib.rs
- [x] crates/veil-node-runtime/src/listener_supervisor.rs
- [x] crates/veil-node-runtime/src/local_identity.rs
- [x] crates/veil-node-runtime/src/memory.rs
- [x] crates/veil-node-runtime/src/mesh_glue.rs
- [x] crates/veil-node-runtime/src/metrics_http.rs
- [x] crates/veil-node-runtime/src/mlkem_resolver.rs
- [x] crates/veil-node-runtime/src/mobile_sink.rs
- [x] crates/veil-node-runtime/src/mobile_status_provider.rs
- [x] crates/veil-node-runtime/src/outbound_connector.rs
- [x] crates/veil-node-runtime/src/pairing_forwarder.rs
- [x] crates/veil-node-runtime/src/peer_list_provider.rs
- [x] crates/veil-node-runtime/src/pnet_status_provider.rs
- [x] crates/veil-node-runtime/src/proxy/mod.rs
- [x] crates/veil-node-runtime/src/proxy/tasks.rs
- [x] crates/veil-node-runtime/src/runtime/anonymity_state.rs
- [x] crates/veil-node-runtime/src/runtime/debug.rs
- [x] crates/veil-node-runtime/src/runtime/dht_republish.rs
- [x] crates/veil-node-runtime/src/runtime/ephemeral_rotator.rs
- [x] crates/veil-node-runtime/src/runtime/handoff_runtime.rs
- [x] crates/veil-node-runtime/src/runtime/identity_loaders.rs
- [x] crates/veil-node-runtime/src/runtime/identity_state.rs
- [x] crates/veil-node-runtime/src/runtime/inspect.rs
- [x] crates/veil-node-runtime/src/runtime/ip_slot.rs
- [x] crates/veil-node-runtime/src/runtime/lifecycle.rs
- [x] crates/veil-node-runtime/src/runtime/mailbox_state.rs
- [x] crates/veil-node-runtime/src/runtime/maintenance.rs
- [x] crates/veil-node-runtime/src/runtime/mesh_gateway.rs
- [x] crates/veil-node-runtime/src/runtime/mobile_state.rs
- [x] crates/veil-node-runtime/src/runtime/mod.rs
- [x] crates/veil-node-runtime/src/runtime/p_net_ban_sync.rs
- [x] crates/veil-node-runtime/src/runtime/peer_handshake.rs
- [x] crates/veil-node-runtime/src/runtime/persist_tasks.rs
- [x] crates/veil-node-runtime/src/runtime/persistence.rs
- [x] crates/veil-node-runtime/src/runtime/pex_runtime.rs
- [x] crates/veil-node-runtime/src/runtime/rendezvous_binder.rs
- [x] crates/veil-node-runtime/src/runtime/resumption_state.rs
- [x] crates/veil-node-runtime/src/runtime/routing_health.rs
- [x] crates/veil-node-runtime/src/runtime/routing_state.rs
- [x] crates/veil-node-runtime/src/runtime/service_tasks.rs
- [x] crates/veil-node-runtime/src/runtime/services.rs
- [x] crates/veil-node-runtime/src/runtime/session_defaults.rs
- [x] crates/veil-node-runtime/src/runtime/session_guard.rs
- [x] crates/veil-node-runtime/src/runtime/sovereign_republish.rs
- [x] crates/veil-node-runtime/src/runtime/tests.rs
- [x] crates/veil-node-runtime/src/runtime/update_check.rs
- [x] crates/veil-node-runtime/src/runtime/uri_helpers.rs
- [x] crates/veil-node-runtime/src/socks_fallback.rs
- [x] crates/veil-node-runtime/src/state.rs
- [x] crates/veil-node-runtime/src/task_registry.rs
- [x] crates/veil-node-runtime/src/test_support.rs
- [x] crates/veil-node-runtime/src/types.rs
### crates/veil-ipc
- [x] crates/veil-ipc/src/frame_io.rs
- [x] crates/veil-ipc/src/handlers/anycast.rs
- [x] crates/veil-ipc/src/handlers/bind.rs
- [x] crates/veil-ipc/src/handlers/mailbox.rs
- [x] crates/veil-ipc/src/handlers/mobile.rs
- [x] crates/veil-ipc/src/handlers/mod.rs
- [x] crates/veil-ipc/src/handlers/outbox.rs
- [x] crates/veil-ipc/src/handlers/queries.rs
- [x] crates/veil-ipc/src/handlers/send.rs
- [x] crates/veil-ipc/src/handlers/stream.rs
- [x] crates/veil-ipc/src/lib.rs
- [x] crates/veil-ipc/src/path.rs
- [x] crates/veil-ipc/src/server.rs
- [x] crates/veil-ipc/src/server_tests_tcp.rs
- [x] crates/veil-ipc/src/server_tests_unix.rs
- [x] crates/veil-ipc/src/streams.rs
- [x] crates/veil-ipc/src/transport.rs
### crates/veilclient-ffi
- [x] crates/veilclient-ffi/src/guard.rs
- [x] crates/veilclient-ffi/src/lib.rs
### crates/veil-transport
- [x] crates/veil-transport/src/context.rs
- [x] crates/veil-transport/src/ech_dns.rs
- [x] crates/veil-transport/src/ephemeral.rs
- [x] crates/veil-transport/src/error.rs
- [x] crates/veil-transport/src/fingerprint.rs
- [x] crates/veil-transport/src/hint_registry.rs
- [x] crates/veil-transport/src/lib.rs
- [x] crates/veil-transport/src/obfs4_tcp.rs
- [x] crates/veil-transport/src/on_demand.rs
- [x] crates/veil-transport/src/quic.rs
- [x] crates/veil-transport/src/registry.rs
- [x] crates/veil-transport/src/rotation.rs
- [x] crates/veil-transport/src/socks.rs
- [x] crates/veil-transport/src/tcp.rs
- [x] crates/veil-transport/src/tls.rs
- [x] crates/veil-transport/src/tls_boring.rs
- [x] crates/veil-transport/src/tls_material.rs
- [x] crates/veil-transport/src/traits.rs
- [x] crates/veil-transport/src/unix.rs
- [x] crates/veil-transport/src/uri.rs
- [x] crates/veil-transport/src/websocket.rs
- [x] crates/veil-transport/src/webtunnel.rs
- [x] crates/veil-transport/tests/obfs4_smoke.rs
### crates/veil-obfs4
- [x] crates/veil-obfs4/src/elligator2.rs
- [x] crates/veil-obfs4/src/lib.rs
- [x] crates/veil-obfs4/src/ntor.rs
- [x] crates/veil-obfs4/src/stream.rs
- [x] crates/veil-obfs4/src/tls_prefix.rs
- [x] crates/veil-obfs4/src/wire_variant.rs
### crates/veil-webtunnel
- [x] crates/veil-webtunnel/src/client.rs
- [x] crates/veil-webtunnel/src/decoy.rs
- [x] crates/veil-webtunnel/src/lib.rs
- [x] crates/veil-webtunnel/src/matcher.rs
- [x] crates/veil-webtunnel/src/router.rs
### crates/veil-udp-obfs
- [x] crates/veil-udp-obfs/src/lib.rs
### crates/veil-fingerprint
- [x] crates/veil-fingerprint/src/bin/fp-compare.rs
- [x] crates/veil-fingerprint/src/lib.rs
- [x] crates/veil-fingerprint/src/pcap.rs
### veilclient
- [x] veilclient/examples/chat_client.rs
- [x] veilclient/examples/chat_node.rs
- [x] veilclient/examples/chat_server.rs
- [x] veilclient/examples/echo_server.rs
- [x] veilclient/examples/ping_client.rs
- [x] veilclient/examples/throughput_bench.rs
- [x] veilclient/src/client.rs
- [x] veilclient/src/error.rs
- [x] veilclient/src/handle.rs
- [x] veilclient/src/lib.rs
- [x] veilclient/src/rendezvous.rs
- [x] veilclient/src/stream.rs
- [x] veilclient/tests/integration.rs

## Wave 2 (remaining) — PENDING
### crates/veil-routing
- [x] crates/veil-routing/src/cache.rs
- [x] crates/veil-routing/src/control_plane.rs
- [x] crates/veil-routing/src/discovery_forwarder.rs
- [x] crates/veil-routing/src/discovery_initiator.rs
- [x] crates/veil-routing/src/lib.rs
- [x] crates/veil-routing/src/loss_tracker.rs
- [x] crates/veil-routing/src/miss_handler.rs
- [x] crates/veil-routing/src/pow.rs
- [x] crates/veil-routing/src/probe.rs
- [x] crates/veil-routing/src/score.rs
- [x] crates/veil-routing/src/vivaldi.rs
### crates/veil-anonymity
- [x] crates/veil-anonymity/src/cell.rs
- [x] crates/veil-anonymity/src/circuit.rs
- [x] crates/veil-anonymity/src/circuit_builder.rs
- [x] crates/veil-anonymity/src/directory.rs
- [x] crates/veil-anonymity/src/lib.rs
- [x] crates/veil-anonymity/src/onion.rs
- [x] crates/veil-anonymity/src/packet.rs
- [x] crates/veil-anonymity/src/push_envelope.rs
- [x] crates/veil-anonymity/src/relay_reputation.rs
- [x] crates/veil-anonymity/src/rendezvous.rs
- [x] crates/veil-anonymity/src/sender.rs
### crates/veil-mesh
- [x] crates/veil-mesh/src/auth.rs
- [x] crates/veil-mesh/src/beacon.rs
- [x] crates/veil-mesh/src/bridge.rs
- [x] crates/veil-mesh/src/forwarder.rs
- [x] crates/veil-mesh/src/lib.rs
- [x] crates/veil-mesh/src/link.rs
- [x] crates/veil-mesh/src/neighbor.rs
- [x] crates/veil-mesh/src/realm.rs
- [x] crates/veil-mesh/src/transport.rs
- [x] crates/veil-mesh/src/udp.rs
### crates/veil-nat
- [x] crates/veil-nat/src/coordinator.rs
- [x] crates/veil-nat/src/discovery.rs
- [x] crates/veil-nat/src/lib.rs
- [x] crates/veil-nat/src/puncher.rs
- [x] crates/veil-nat/src/relay.rs
### crates/veil-gateway
- [x] crates/veil-gateway/src/attachment.rs
- [x] crates/veil-gateway/src/endpoint.rs
- [x] crates/veil-gateway/src/lease.rs
- [x] crates/veil-gateway/src/lib.rs
- [x] crates/veil-gateway/src/service.rs
### crates/veil-discovery
- [x] crates/veil-discovery/src/announcement_sig.rs
- [x] crates/veil-discovery/src/directory.rs
- [x] crates/veil-discovery/src/lib.rs
- [x] crates/veil-discovery/src/service.rs
### crates/veil-pex
- [x] crates/veil-pex/src/dispatcher.rs
- [x] crates/veil-pex/src/initiator.rs
- [x] crates/veil-pex/src/lib.rs
### crates/veil-bootstrap
- [x] crates/veil-bootstrap/src/cache.rs
- [x] crates/veil-bootstrap/src/dns.rs
- [x] crates/veil-bootstrap/src/encrypted_invite.rs
- [x] crates/veil-bootstrap/src/https.rs
- [x] crates/veil-bootstrap/src/invite.rs
- [x] crates/veil-bootstrap/src/lib.rs
- [x] crates/veil-bootstrap/src/seeds.rs
- [x] crates/veil-bootstrap/src/signed_bundle.rs
- [x] crates/veil-bootstrap/src/signed_invite.rs
### crates/veil-abuse
- [x] crates/veil-abuse/src/backpressure.rs
- [x] crates/veil-abuse/src/ban_list.rs
- [x] crates/veil-abuse/src/bandwidth_gate.rs
- [x] crates/veil-abuse/src/dht_quota.rs
- [x] crates/veil-abuse/src/identity_quota.rs
- [x] crates/veil-abuse/src/lib.rs
- [x] crates/veil-abuse/src/per_peer_limiter.rs
- [x] crates/veil-abuse/src/pow_verifier.rs
- [x] crates/veil-abuse/src/rate_limiter.rs
- [x] crates/veil-abuse/src/replay_window.rs
- [x] crates/veil-abuse/src/scanner_shield.rs
- [x] crates/veil-abuse/src/violation_tracker.rs
### crates/veil-mailbox
- [x] crates/veil-mailbox/src/capability.rs
- [x] crates/veil-mailbox/src/lib.rs
- [x] crates/veil-mailbox/src/outbox.rs
- [x] crates/veil-mailbox/src/rate_limit.rs
- [x] crates/veil-mailbox/src/service.rs
- [x] crates/veil-mailbox/src/tests.rs
### crates/veil-app
- [x] crates/veil-app/src/address.rs
- [x] crates/veil-app/src/lib.rs
- [x] crates/veil-app/src/registry.rs
- [x] crates/veil-app/src/streams.rs
### crates/veil-update
- [x] crates/veil-update/src/apply.rs
- [x] crates/veil-update/src/check_task.rs
- [x] crates/veil-update/src/checker.rs
- [x] crates/veil-update/src/fetch.rs
- [x] crates/veil-update/src/installed_version.rs
- [x] crates/veil-update/src/lib.rs
- [x] crates/veil-update/src/manifest.rs
### crates/veil-push
- [x] crates/veil-push/src/apns.rs
- [x] crates/veil-push/src/fcm.rs
- [x] crates/veil-push/src/lib.rs
- [x] crates/veil-push/src/router.rs
- [x] crates/veil-push/src/token.rs
### crates/veil-anycast
- [x] crates/veil-anycast/src/lib.rs
- [x] crates/veil-anycast/src/reputation.rs
### crates/veil-invite
- [x] crates/veil-invite/src/lib.rs
### crates/veil-cli
- [x] crates/veil-cli/src/bin/cli.rs
- [x] crates/veil-cli/src/cmd/adapters.rs
- [x] crates/veil-cli/src/cmd/background.rs
- [x] crates/veil-cli/src/cmd/bootstrap_cmd.rs
- [x] crates/veil-cli/src/cmd/cli.rs
- [x] crates/veil-cli/src/cmd/debug.rs
- [x] crates/veil-cli/src/cmd/debug_transport.rs
- [x] crates/veil-cli/src/cmd/handlers.rs
- [x] crates/veil-cli/src/cmd/identity/input.rs
- [x] crates/veil-cli/src/cmd/identity/mod.rs
- [x] crates/veil-cli/src/cmd/identity/output.rs
- [x] crates/veil-cli/src/cmd/identity/persistence.rs
- [x] crates/veil-cli/src/cmd/identity/progress.rs
- [x] crates/veil-cli/src/cmd/identity/types.rs
- [x] crates/veil-cli/src/cmd/invite_cmd.rs
- [x] crates/veil-cli/src/cmd/listen_cmd.rs
- [x] crates/veil-cli/src/cmd/mobile_cmd.rs
- [x] crates/veil-cli/src/cmd/mod.rs
- [x] crates/veil-cli/src/cmd/network_cmd.rs
- [x] crates/veil-cli/src/cmd/node_cmd.rs
- [x] crates/veil-cli/src/cmd/output.rs
- [x] crates/veil-cli/src/cmd/peers_cmd.rs
- [x] crates/veil-cli/src/cmd/pex_cmd.rs
- [x] crates/veil-cli/src/cmd/run.rs
- [x] crates/veil-cli/src/cmd/service.rs
- [x] crates/veil-cli/src/cmd/sessions_cmd.rs
- [x] crates/veil-cli/src/cmd/sovereign_identity.rs
- [x] crates/veil-cli/src/cmd/test_support.rs
- [x] crates/veil-cli/src/cmd/update_cmd.rs
- [x] crates/veil-cli/src/cmd/util.rs
- [x] crates/veil-cli/src/lib.rs
- [x] crates/veil-cli/src/test_support.rs
### crates/ogate
- [x] crates/ogate/src/app_cert_gate.rs
- [x] crates/ogate/src/app_id.rs
- [x] crates/ogate/src/batch.rs
- [x] crates/ogate/src/bridge.rs
- [x] crates/ogate/src/cert_message.rs
- [x] crates/ogate/src/cli.rs
- [x] crates/ogate/src/config.rs
- [x] crates/ogate/src/config_template.rs
- [x] crates/ogate/src/lib.rs
- [x] crates/ogate/src/main.rs
- [x] crates/ogate/src/routing.rs
- [x] crates/ogate/src/tun/freebsd.rs
- [x] crates/ogate/src/tun/mod.rs
- [x] crates/ogate/src/tun/standard.rs
### crates/oproxy
- [x] crates/oproxy/src/app_cert_gate.rs
- [x] crates/oproxy/src/authz.rs
- [x] crates/oproxy/src/bin/client.rs
- [x] crates/oproxy/src/bin/server.rs
- [x] crates/oproxy/src/config.rs
- [x] crates/oproxy/src/config_template.rs
- [x] crates/oproxy/src/connector.rs
- [x] crates/oproxy/src/inbound/http.rs
- [x] crates/oproxy/src/inbound/mod.rs
- [x] crates/oproxy/src/inbound/socks5.rs
- [x] crates/oproxy/src/inbound/tproxy.rs
- [x] crates/oproxy/src/inbound/tproxy_unix.rs
- [x] crates/oproxy/src/lib.rs
- [x] crates/oproxy/src/logging.rs
- [x] crates/oproxy/src/routing.rs
- [x] crates/oproxy/src/timeouts.rs
- [x] crates/oproxy/src/wire.rs
### crates/veil-proxy
- [x] crates/veil-proxy/src/exit.rs
- [x] crates/veil-proxy/src/lib.rs
- [x] crates/veil-proxy/src/veil_connector.rs
- [x] crates/veil-proxy/src/socks5.rs
### crates/veil-cfg
- [x] crates/veil-cfg/src/access.rs
- [x] crates/veil-cfg/src/adaptive.rs
- [x] crates/veil-cfg/src/error.rs
- [x] crates/veil-cfg/src/file_format.rs
- [x] crates/veil-cfg/src/format/json.rs
- [x] crates/veil-cfg/src/format/mod.rs
- [x] crates/veil-cfg/src/format/toml.rs
- [x] crates/veil-cfg/src/identity.rs
- [x] crates/veil-cfg/src/identity_master.rs
- [x] crates/veil-cfg/src/identity_master_file.rs
- [x] crates/veil-cfg/src/identity_master_qr.rs
- [x] crates/veil-cfg/src/identity_ops.rs
- [x] crates/veil-cfg/src/identity_policy.rs
- [x] crates/veil-cfg/src/instance.rs
- [x] crates/veil-cfg/src/keys.rs
- [x] crates/veil-cfg/src/lib.rs
- [x] crates/veil-cfg/src/locate.rs
- [x] crates/veil-cfg/src/model.rs
- [x] crates/veil-cfg/src/observability_glue.rs
- [x] crates/veil-cfg/src/runtime.rs
- [x] crates/veil-cfg/src/signed_config.rs
- [x] crates/veil-cfg/src/sovereign_flow.rs
- [x] crates/veil-cfg/src/store.rs
- [x] crates/veil-cfg/src/test_support.rs
- [x] crates/veil-cfg/src/transport_glue.rs
- [x] crates/veil-cfg/src/validate/identity.rs
- [x] crates/veil-cfg/src/validate/mod.rs
- [x] crates/veil-cfg/src/validate/report.rs
- [x] crates/veil-cfg/src/validate/structural.rs
- [x] crates/veil-cfg/src/value.rs
### crates/veil-util
- [x] crates/veil-util/src/lib.rs
- [x] crates/veil-util/src/mlock.rs
- [x] crates/veil-util/src/sensitive_bytes.rs
### crates/veil-types
- [x] crates/veil-types/src/lib.rs
### crates/veil-bufpool
- [x] crates/veil-bufpool/benches/pool_vs_malloc.rs
- [x] crates/veil-bufpool/src/lib.rs
- [x] crates/veil-bufpool/src/shared_slab.rs
### crates/veil-memory
- [x] crates/veil-memory/src/lib.rs
### crates/veil-bloom
- [x] crates/veil-bloom/src/lib.rs
### crates/veil-congestion
- [x] crates/veil-congestion/src/lib.rs
### crates/veil-adaptive
- [x] crates/veil-adaptive/src/lib.rs
### crates/veil-pending-ack
- [x] crates/veil-pending-ack/src/lib.rs
### crates/veil-reputation
- [x] crates/veil-reputation/src/lib.rs
### crates/veil-observability
- [x] crates/veil-observability/src/lib.rs
### crates/veil-transfer
- [x] crates/veil-transfer/src/lib.rs
### crates/veil-local-transport
- [x] crates/veil-local-transport/src/lib.rs
### crates/veil-error
- [x] crates/veil-error/src/lib.rs
### crates/veil-session-integration-tests
- [x] crates/veil-session-integration-tests/src/lib.rs
- [x] crates/veil-session-integration-tests/tests/runner_tests.rs
### crates/veil-obfs4-smoke
- [x] crates/veil-obfs4-smoke/src/bin/obfs4-dial.rs
### veilcore
- [x] veilcore/benches/adversary_validation.rs
- [x] veilcore/benches/dht_lookup.rs
- [x] veilcore/benches/dht_store_throughput.rs
- [x] veilcore/benches/hybrid_kex.rs
- [x] veilcore/benches/recursive_relay_chain.rs
- [x] veilcore/benches/session_scale.rs
- [x] veilcore/benches/socks5_throughput.rs
- [x] veilcore/benches/voice_stream.rs
- [x] veilcore/src/crypto.rs
- [x] veilcore/src/lib.rs
- [x] veilcore/src/node/abuse.rs
- [x] veilcore/src/node/anonymity.rs
- [x] veilcore/src/node/anycast.rs
- [x] veilcore/src/node/app.rs
- [x] veilcore/src/node/battery.rs
- [x] veilcore/src/node/bootstrap.rs
- [x] veilcore/src/node/control.rs
- [x] veilcore/src/node/dht.rs
- [x] veilcore/src/node/discovery.rs
- [x] veilcore/src/node/e2e.rs
- [x] veilcore/src/node/gateway/mod.rs
- [x] veilcore/src/node/gateway_list.rs
- [x] veilcore/src/node/mesh.rs
- [x] veilcore/src/node/mod.rs
- [x] veilcore/src/node/nat.rs
- [x] veilcore/src/node/observability.rs
- [x] veilcore/src/node/routing/mod.rs
- [x] veilcore/src/node/session/chaos_sim.rs
- [x] veilcore/src/node/session/mod.rs
- [x] veilcore/src/node/session_glue.rs
- [x] veilcore/src/node/transfer.rs
- [x] veilcore/src/node/transport_hints.rs
- [x] veilcore/src/node/update.rs
- [x] veilcore/src/node/util.rs
- [x] veilcore/src/proto.rs
- [x] veilcore/src/sim/events.rs
- [x] veilcore/src/sim/loss.rs
- [x] veilcore/src/sim/mod.rs
- [x] veilcore/src/sim/network.rs
- [x] veilcore/src/sim/node.rs
- [x] veilcore/src/sim/scenarios.rs
- [x] veilcore/src/test_support.rs
- [x] veilcore/src/transport.rs
- [x] veilcore/src/util.rs
- [x] veilcore/tests/dht_key_domain_separation.rs
- [x] veilcore/tests/discovery_auto_publish.rs
- [x] veilcore/tests/frame_broadcaster_adapter.rs
- [x] veilcore/tests/identity_contact_roundtrip.rs
- [x] veilcore/tests/mesh_bridge_integration.rs
- [x] veilcore/tests/node_id_consistency.rs
### fuzz
- [x] fuzz/fuzz_targets/fuzz_app_decode.rs
- [x] fuzz/fuzz_targets/fuzz_cipher_open.rs
- [x] fuzz/fuzz_targets/fuzz_delivery_decode.rs
- [x] fuzz/fuzz_targets/fuzz_ipc_decode.rs
- [x] fuzz/fuzz_targets/fuzz_proto_decode.rs
- [x] fuzz/fuzz_targets/fuzz_routing_decode.rs
- [x] fuzz/fuzz_targets/fuzz_session_decode.rs
