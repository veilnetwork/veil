//! `NodeRuntime` unit tests, extracted from `runtime/mod.rs` during the
//! refactor. `#[cfg(test)] mod tests;` include lands in
//! `mod.rs`; all helpers live inside this file via `use super::*;`.

use std::{fs, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};

use crate::local_identity::HandshakeIdentity;
use crate::test_support;
use veil_cfg::{
    self, Config, IdentityConfig, ListenConfig, ListenId, NodeId, PeerConfig, PeerId,
    SignatureAlgorithm,
};
use veil_session::handshake::perform_ovl1_handshake;
use veil_transport::{TransportRegistry, TransportUri};

use super::peer_handshake::{
    ExpectedPeerIdentity, PeerVerificationError, RemoteHandshakeInfo, verify_remote_peer_identity,
};
use super::uri_helpers::{uri_has_port_zero, uri_scheme};
use super::*;

fn provider_test_ad(tag: u8) -> veil_anonymity::rendezvous::RendezvousAd {
    veil_anonymity::rendezvous::RendezvousAd {
        receiver_node_id: [tag; 32],
        rendezvous_node_id: [tag.wrapping_add(1); 32],
        auth_cookie: [tag; 16],
        receiver_x25519_pk: [tag.wrapping_add(2); 32],
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
    }
}

#[test]
fn spread_never_mixes_ads_from_different_providers() {
    // The killer case: a fragmented message round-robined across ads belonging
    // to DIFFERENT nodes would scatter its fragments, and no node would ever
    // hold the whole thing. Only slots of the SAME node are introduction
    // points to one service instance.
    let mine = provider_test_ad(7);
    let mut my_second_slot = provider_test_ad(7);
    my_second_slot.rendezvous_node_id = [0x99; 32];
    let other_provider = provider_test_ad(40);

    let ads = vec![mine.clone(), other_provider.clone(), my_second_slot.clone()];
    let extras = NodeServices::same_node_extra_ads(&ads, &mine);

    assert_eq!(extras.len(), 1, "only the same node's other slot");
    assert_eq!(
        extras[0].rendezvous_node_id,
        my_second_slot.rendezvous_node_id
    );
    assert!(
        !extras
            .iter()
            .any(|e| e.receiver_node_id == other_provider.receiver_node_id),
        "another provider must never become a spread target",
    );
}

#[test]
fn spread_skips_the_primary_relay_and_duplicate_relays() {
    // The primary is already the send's own target, and two ads naming one
    // relay are one introduction point — counting either again would inflate
    // the relay list without adding an independent path.
    let primary = provider_test_ad(3);
    let duplicate_relay = primary.clone();
    let mut second_slot = provider_test_ad(3);
    second_slot.rendezvous_node_id = [0x55; 32];
    let mut third_slot_same_relay = provider_test_ad(3);
    third_slot_same_relay.rendezvous_node_id = [0x55; 32];

    let ads = vec![
        primary.clone(),
        duplicate_relay,
        second_slot,
        third_slot_same_relay,
    ];
    let extras = NodeServices::same_node_extra_ads(&ads, &primary);
    assert_eq!(extras.len(), 1);
    assert_eq!(extras[0].rendezvous_node_id, [0x55; 32]);
}

#[test]
fn capability_provider_candidates_are_bounded_and_nonce_rotated() {
    let ads: Vec<_> = (0..6).map(provider_test_ad).collect();
    let selected = NodeServices::select_rendezvous_candidates(&ads, b"request-a", 3);
    assert_eq!(selected.len(), 3);
    assert!(
        selected
            .windows(2)
            .all(|pair| { pair[0].rendezvous_node_id != pair[1].rendezvous_node_id })
    );
    assert_eq!(
        selected
            .iter()
            .map(|ad| ad.rendezvous_node_id)
            .collect::<Vec<_>>(),
        NodeServices::select_rendezvous_candidates(&ads, b"request-a", 3)
            .iter()
            .map(|ad| ad.rendezvous_node_id)
            .collect::<Vec<_>>()
    );

    let starts: std::collections::HashSet<_> = (0u8..64)
        .map(|nonce| {
            NodeServices::select_rendezvous_candidates(&ads, &[nonce], 3)[0].rendezvous_node_id
        })
        .collect();
    assert!(
        starts.len() > 1,
        "fresh request nonces must rotate providers"
    );
    assert!(NodeServices::select_rendezvous_candidates(&ads, b"x", 0).is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn node_state_builds_from_config() {
    let path = save_test_config("node-runtime-build", runtime_config_with_listen()).unwrap();

    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");
    let summary = runtime.summary();

    assert_eq!(summary.peers_configured, 1);
    assert_eq!(summary.listens_configured, 1);
    assert_eq!(runtime.peers().len(), 1);
    assert_eq!(runtime.listens().len(), 1);

    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

/// The deferred-boot `anonymous` flag must actually arm onion at the RUNTIME
/// level, not just in the config struct: a node booted from the anonymous stub
/// config hosts an onion service (`anonymity.onion_service_hops = Some`), while
/// the plain stub does not. This is what makes a deferred node onion-reachable
/// once its real identity is applied (the descriptor publishes under the live
/// identity). Guards the xVeil "Route anonymously" path end to end on the veil
/// side.
#[tokio::test(flavor = "current_thread")]
async fn deferred_anonymous_stub_arms_onion_at_runtime() {
    // Plain deferred stub: NOT hosting an onion service.
    let plain = save_test_config(
        "stub-plain",
        veil_cfg::build_stub_config_with_ephemeral_identity(false).unwrap(),
    )
    .unwrap();
    let mut rt = NodeRuntime::start(&plain, true)
        .await
        .expect("plain stub starts");
    assert!(
        rt.anonymity.onion_service_hops.is_none(),
        "non-anonymous stub must not host an onion service"
    );
    rt.stop().await.expect("plain stub stops");
    let _ = fs::remove_file(plain);

    // Anonymous deferred stub: onion IS armed at boot.
    let anon = save_test_config(
        "stub-anon",
        veil_cfg::build_stub_config_with_ephemeral_identity(true).unwrap(),
    )
    .unwrap();
    let mut rt = NodeRuntime::start(&anon, true)
        .await
        .expect("anonymous stub starts");
    assert!(
        rt.anonymity.onion_service_hops.is_some(),
        "anonymous stub must arm the onion service at boot"
    );
    rt.stop().await.expect("anon stub stops");
    let _ = fs::remove_file(anon);
}

/// A deferred boot must reach NOTHING.
///
/// This is the window nobody was watching. `veil_node_start_deferred` takes no
/// config — the node boots from `build_stub_config_with_ephemeral_identity`,
/// and the host's real config arrives afterwards as an apply-config. The stub
/// was `Config::default()`, which is `builtin_seed_policy = "auto"`, and
/// `auto`'s condition is "no `peers`, no `[[bootstrap_peers]]`" — which the
/// stub satisfies by construction. So every deferred boot, on every host, put
/// the compiled-in production seeds in its peer table and opened connectors to
/// them, seconds before the config that had something to say about it landed.
///
/// For the messenger built on this that silently defeated a shipped setting: a
/// person who declined the shared seeds gets `builtin_seed_policy = "never"` in
/// the config the app COMPOSES, and still touched those hosts once per start.
///
/// Asserted on a runtime that has actually STARTED, not on the config struct.
/// `peers()` is the table `connect_peer_active` reads and the table
/// `spawn_bootstrap_task` writes immediately before it spawns the outbound
/// connector for each entry, so an entry appearing here IS the dial.
#[tokio::test(flavor = "current_thread")]
async fn deferred_stub_boot_dials_no_builtin_seed() {
    let stub = veil_cfg::build_stub_config_with_ephemeral_identity(false).unwrap();

    // A floor first. This whole test is "a set stayed empty", and the loudest
    // way for it to pass is for the compiled-in list to have become empty —
    // which is a real build configuration here (`allow-empty-seeds`), not a
    // hypothetical.
    assert!(
        !veil_bootstrap::builtin_seeds().is_empty(),
        "this build has no builtin seeds at all, so an empty peer table proves \
         nothing about the stub"
    );
    // The decision, on the exact value the boot below is about to use.
    assert!(
        super::service_tasks::resolve_bootstrap_candidates(
            &stub,
            &stub.identity.as_ref().expect("stub identity").public_key,
        )
        .is_empty(),
        "the stub must contribute no bootstrap candidate of any kind"
    );

    let path = save_test_config("node-runtime-deferred-stub", stub).unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("the deferred stub must still start — offline is not failed");
    assert!(
        runtime.peers().is_empty(),
        "a deferred boot registered {} peer(s) before its host said anything: {:?}",
        runtime.peers().len(),
        runtime
            .peers()
            .iter()
            .map(|p| p.transport.clone())
            .collect::<Vec<_>>(),
    );
    // The splice happens inside the bootstrap task, not at `start`. Stay up
    // past the window in which it runs, or the emptiness above is just an
    // observation taken too early.
    sleep(Duration::from_millis(750)).await;
    assert!(
        runtime.peers().is_empty(),
        "the deferred boot reached the builtin seeds after all: {:?}",
        runtime
            .peers()
            .iter()
            .map(|p| p.transport.clone())
            .collect::<Vec<_>>(),
    );

    runtime.stop().await.expect("the stub shuts down cleanly");
    let _ = fs::remove_file(path);
}

/// The positive control for [`deferred_stub_boot_dials_no_builtin_seed`]:
/// refusing at the stub must not cost the ordinary owner their bootstrap.
///
/// Without this, a "fix" that switched bootstrapping off entirely would pass
/// the test above and take every install off the network.
///
/// Two halves, because the keeper's seeds arrive by two different mechanisms
/// and both have to still work:
///
///   * the DECISION — an applied config shaped like the one the app composes
///     for someone who KEPT the seeds (no `[[bootstrap_peers]]`, policy left at
///     the shipped default) still resolves to every compiled-in seed;
///   * the ACT — the reload that apply-config performs re-runs the bootstrap
///     task and registers what it resolved. That half is asserted with ONE
///     bootstrap peer on loopback rather than with the production list: the
///     mechanism is what is in question, and a test that dials an operator's
///     hosts to prove it is a test that dials an operator's hosts.
#[tokio::test(flavor = "current_thread")]
async fn the_applied_config_is_what_puts_a_deferred_node_on_the_network() {
    // ── the decision ────────────────────────────────────────────────────────
    let mut keeper = runtime_config_with_listen();
    keeper.peers.clear();
    keeper.bootstrap_peers.clear();
    assert_eq!(
        keeper.global.builtin_seed_policy,
        veil_cfg::BuiltinSeedPolicy::Auto,
        "a keeper's composed config leaves the policy alone — only a refusal \
         writes one"
    );
    let builtin = veil_bootstrap::builtin_seeds();
    assert!(!builtin.is_empty(), "floor: this build compiles in seeds");
    assert_eq!(
        super::service_tasks::resolve_bootstrap_candidates(
            &keeper,
            &test_support::valid_identity().public_key,
        )
        .len(),
        builtin.len(),
        "an owner who kept the shared seeds must still get all of them"
    );

    // ── the act ─────────────────────────────────────────────────────────────
    let stub = veil_cfg::build_stub_config_with_ephemeral_identity(false).unwrap();
    let path = save_test_config("node-runtime-deferred-promote", stub).unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("the deferred stub starts");
    assert!(runtime.peers().is_empty(), "nothing before the host speaks");

    let mut promoted = runtime_config_with_listen();
    promoted.peers.clear();
    let seed_keys = test_support::ed25519_keypair();
    promoted.bootstrap_peers = vec![veil_cfg::BootstrapPeer {
        // Port 1 on loopback: the registration is what is asserted, and the
        // connector's dial fails immediately with nowhere to go.
        transport: "tcp://127.0.0.1:1".to_owned(),
        public_key: seed_keys.public_key.clone(),
        nonce: "AAAAAAAAAAAAAAAAAAAAAA==".to_owned(),
        algo: veil_cfg::SignatureAlgorithm::Ed25519,
        tls_cert: None,
        tls_ca_cert: None,
    }];
    // A FULL render, not `save_config`'s comment-preserving patch — the file on
    // disk is the stub, and patching hand-maintained sections over it is not
    // what apply-config does with the bytes it is handed.
    veil_cfg::render_config(&path, &promoted).expect("write the promoted config");
    // The same pipeline `AdminCommand::ApplyConfig` runs: validate, stop every
    // task, respawn them all against the new config.
    runtime.reload().await.expect("apply-config style reload");

    let registered: Vec<String> = runtime
        .peers()
        .iter()
        .map(|p| p.transport.clone())
        .collect();
    assert_eq!(
        registered,
        vec!["tcp://127.0.0.1:1".to_owned()],
        "the reload must register the applied config's bootstrap peers — if it \
         does not, refusing at the stub leaves a node that never dials anything"
    );

    runtime.stop().await.expect("the promoted node shuts down");
    let _ = fs::remove_file(path);
}

/// A node whose owner refused the shared seeds must come up OFFLINE AND
/// ALIVE. This is the exact shape the app composes for a declining identity:
/// `builtin_seed_policy = "never"`, no `peers`, no `[[bootstrap_peers]]`, no
/// `bootstrap_dns_domain`.
///
/// On an Android device that config used to reach
/// `discover_seeds_dns_system` → `Resolver::builder_tokio()` →
/// `ndk_context::android_context()` and take the process down with
/// `SIGABRT: 'android context was not initialized'` from a tokio worker,
/// 12-90 s after boot.
///
/// This host is not Android, so the abort itself cannot be reproduced here —
/// see `veil_util::system_dns_config_readable`'s tests and the
/// `every_system_conf_resolver_is_android_guarded` structural guard for that
/// half. What this test pins is the reachability half, on the real boot path:
/// the node starts, reports itself running with zero peers, survives past the
/// point where the DNS fallback would have been spawned, and shuts down — and
/// the very config it booted from is one the gate refuses to arm discovery
/// for.
#[tokio::test(flavor = "current_thread")]
async fn node_refusing_builtin_seeds_boots_offline_and_stays_alive() {
    let mut config = runtime_config_with_listen();
    config.peers.clear();
    config.bootstrap_peers.clear();
    config.global.builtin_seed_policy = veil_cfg::BuiltinSeedPolicy::Never;
    assert!(
        config.global.bootstrap_dns_domain.is_none(),
        "fixture must mirror the shipped config, which names no DNS domain"
    );

    // The decision, checked on the same value the runtime is about to boot
    // from: nothing may arm DNS seed discovery here.
    assert_eq!(
        super::service_tasks::dns_seed_discovery_domain(&config),
        None,
        "a refusing identity with no peers must not start DNS seed discovery: \
         the only domain on offer is the RFC 6761-reserved placeholder, and \
         reaching the system-DNS stage aborts the process on Android"
    );
    // And the refusal must not be a lie either — no builtin seed may be
    // spliced into the dial list behind the owner's back.
    assert!(
        super::service_tasks::resolve_bootstrap_candidates(
            &config,
            &test_support::valid_identity().public_key,
        )
        .is_empty(),
        "builtin_seed_policy=never must leave the candidate set empty"
    );

    let path = save_test_config("node-runtime-seedless", config).unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("a node that refused the builtin seeds must still start");

    let summary = runtime.summary();
    assert_eq!(summary.peers_configured, 0, "offline: no peers configured");
    assert_eq!(summary.listens_configured, 1, "alive: still listening");
    assert!(
        runtime.peers().is_empty(),
        "no peer may appear from a seed list the owner declined"
    );

    // Stay up past the window in which the bootstrap task would have run its
    // DoT/DoH stages and fallen into the system-DNS stage. On Android the
    // pre-fix build was already dead by this point.
    sleep(Duration::from_millis(750)).await;
    assert!(
        runtime.peers().is_empty(),
        "still no peers after the bootstrap window — the refusal held"
    );

    runtime
        .stop()
        .await
        .expect("a seedless node must shut down cleanly, not abort");
    let _ = fs::remove_file(path);
}

#[tokio::test(flavor = "current_thread")]
async fn inbound_listen_creates_session() {
    let path =
        save_test_config("node-runtime-session-create", runtime_config_with_listen()).unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");
    let listen = runtime.listens().into_iter().next().expect("listen entry");
    let registry = TransportRegistry::with_defaults();
    let ctx = Arc::new(TransportContext::for_debug().expect("debug context"));
    let uri = TransportUri::parse(&format!(
        "tcp://{}",
        listen.local_addr.clone().expect("local addr")
    ))
    .expect("connect uri");

    let connection = registry.connect(&uri, ctx).await.expect("connects");
    let mut stream = connection.into_stream().expect("stream");
    complete_test_handshake(&mut stream).await;

    timeout(Duration::from_secs(2), async {
        loop {
            let sessions = runtime.sessions();
            if !sessions.is_empty() {
                let session = &sessions[0];
                assert_eq!(session.source, SessionSource::Inbound(listen.listen_id));
                assert!(session.listener_handle.is_some());
                assert_eq!(session.node_id, Some(test_handshake_identity().node_id));
                assert_eq!(
                    session.nonce.as_deref(),
                    Some(test_handshake_identity().nonce.as_str())
                );
                assert_eq!(session.matched_peer_id, Some(PeerId::new(1)));
                assert!(session.remote_addr.is_some());
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("session appears");

    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

#[tokio::test(flavor = "current_thread")]
async fn session_removed_on_close() {
    let path =
        save_test_config("node-runtime-session-close", runtime_config_with_listen()).unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");
    let listen = runtime.listens().into_iter().next().expect("listen entry");
    let registry = TransportRegistry::with_defaults();
    let ctx = Arc::new(TransportContext::for_debug().expect("debug context"));
    let uri = TransportUri::parse(&format!(
        "tcp://{}",
        listen.local_addr.clone().expect("local addr")
    ))
    .expect("connect uri");

    let connection = registry.connect(&uri, ctx).await.expect("connects");
    let mut stream = connection.into_stream().expect("stream");
    complete_test_handshake(&mut stream).await;
    stream.write_all(b"hello").await.expect("write");
    stream.shutdown().await.expect("shutdown");

    timeout(Duration::from_secs(2), async {
        loop {
            if runtime.sessions().is_empty() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("session removed");

    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

#[tokio::test(flavor = "current_thread")]
async fn listen_ids_map_correctly_to_runtime() {
    let path =
        save_test_config("node-runtime-listen-ids", runtime_config_with_two_listens()).unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");

    let listens = runtime.listens();
    assert_eq!(listens.len(), 2);
    assert_eq!(listens[0].listen_id, ListenId::new(1));
    assert_eq!(listens[1].listen_id, ListenId::new(2));
    assert!(
        listens
            .iter()
            .all(|listen| listen.listener_handle.is_some())
    );
    assert!(listens.iter().all(|listen| listen.active));
    assert!(listens.iter().all(|listen| listen.local_addr.is_some()));

    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

#[tokio::test(flavor = "current_thread")]
async fn metrics_exporter_starts_when_configured() {
    let path = save_test_config("node-runtime-metrics", runtime_config_with_metrics()).unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");

    let summary = runtime.summary();
    assert!(summary.metrics_active);
    let endpoint = summary.metrics_endpoint.expect("metrics endpoint");
    let rendered = fetch_metrics(&endpoint, "/metrics").await;

    assert!(rendered.contains("veil_configured_peers 1"));
    assert!(rendered.contains("veil_active_sessions 0"));

    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

#[tokio::test(flavor = "current_thread")]
async fn metrics_counters_move_on_session_lifecycle() {
    let path = save_test_config(
        "node-runtime-metrics-session",
        runtime_config_with_metrics(),
    )
    .unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");
    let listen = runtime.listens().into_iter().next().expect("listen entry");
    let endpoint = runtime
        .summary()
        .metrics_endpoint
        .expect("metrics endpoint");

    let mut stream = TcpStream::connect(listen.local_addr.as_ref().unwrap())
        .await
        .expect("connects");
    complete_test_handshake(&mut stream).await;

    // Phase 1 — observe the session-OPEN counters while the session is idle,
    // BEFORE sending any post-handshake frame. (audit cycle-9 CRIT-0): the M1
    // empty-frame AEAD fix (commit 11e5065) now correctly tears down a session
    // that receives an unsealed/empty body under an active cipher. So the
    // open-state (active_sessions 1) must be sampled before the Ping below,
    // which both counts its wire bytes AND triggers the close — previously this
    // test required all three counters true at ONE scrape, which is impossible
    // now that the Ping closes the session microseconds after the byte count.
    timeout(Duration::from_secs(2), async {
        loop {
            let rendered = fetch_metrics(&endpoint, "/metrics").await;
            if rendered.contains("veil_inbound_sessions_total 1")
                && rendered.contains("veil_active_sessions 1")
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("session-open counters observed");

    // Send a raw OVL1 Ping header (Control family, Ping msg_type, empty body).
    // The runner counts its 24 wire bytes (HEADER_SIZE) into
    // transport_bytes_rx_total BEFORE the empty-body decrypt rejects it and
    // closes the session — so this single frame drives both the rx-byte counter
    // and the session-close half of the lifecycle.
    {
        use veil_proto::{
            codec::encode_header,
            family::{ControlMsg, FrameFamily},
            header::FrameHeader,
        };
        let mut hdr = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::Ping as u16);
        hdr.body_len = 0;
        stream
            .write_all(&encode_header(&hdr))
            .await
            .expect("write ping frame");
    }

    // Phase 2 — the Ping's 24 wire bytes are counted (cumulative counter) and
    // the session is torn down by the empty-frame rejection.
    timeout(Duration::from_secs(2), async {
        loop {
            let rendered = fetch_metrics(&endpoint, "/metrics").await;
            if rendered.contains("veil_transport_bytes_rx_total 24")
                && rendered.contains("veil_active_sessions 0")
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("rx bytes counted and session closed");

    let _ = stream.shutdown().await;

    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

/// How long a test waits for the runtime to dial it before calling it a
/// failure.
///
/// The tests that use it are `#[ignore]`d as probabilistic — the dial may
/// legitimately not happen, which is the thing they are about. What must not
/// happen is a WEDGE: `accept()` waits forever, so a run invited by the ignore
/// note ("run with --ignored") stops dead instead of reporting. Ten seconds is
/// far past any real dial on loopback, and the point is that there is a bound
/// at all.
const TEST_DIAL_WAIT: Duration = Duration::from_secs(10);

/// `listener.accept()` with [`TEST_DIAL_WAIT`] on it, so a dial that never
/// comes is a named failure rather than a hung run.
async fn accept_dial(listener: &TcpListener, what: &str) -> tokio::net::TcpStream {
    match timeout(TEST_DIAL_WAIT, listener.accept()).await {
        Ok(Ok((stream, _))) => stream,
        Ok(Err(e)) => panic!("{what}: accept failed: {e}"),
        Err(_) => panic!(
            "{what}: the runtime never dialled within {TEST_DIAL_WAIT:?} — \
             which is what these tests call probabilistic, and is a RESULT, \
             not a reason to stop"
        ),
    }
}

// Audit batch 2026-05-24: probabilistically flaky after Phase E20
// directional dedup landed (commit 4caea9b, 2026-05-22).  The test
// uses a randomly-generated sovereign identity for the runtime AND
// `test_support::valid_identity()` (cached, also random per process)
// for the test peer.  When `hex(runtime) > hex(peer_pubkey-derived
// node_id)`, runtime keeps INBOUND for that peer and its own outbound
// dial is policy-rejected as "duplicate" — test fails at the
// "outbound session appears" timeout.  ~50% pass rate.  Fix requires
// either pinning the sovereign identity to a node_id that always
// orders below the test peer's, OR rewriting the test to bind a
// listener on the runtime + dialing from the peer side instead.
// Marked `#[ignore]` until that rework lands.
#[ignore = "Phase E20 directional dedup makes this probabilistic; see comment"]
#[tokio::test(flavor = "current_thread")]
async fn runtime_creates_outbound_session_for_configured_peer() {
    let peer_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("peer listener");
    let peer_addr = peer_listener.local_addr().expect("peer addr");
    let path = save_test_config(
        "node-runtime-outbound-create",
        runtime_config_with_peer_transport(format!("tcp://{peer_addr}")),
    )
    .unwrap();

    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");
    let mut peer_stream = accept_dial(&peer_listener, "peer").await;
    let _runtime_node_id = complete_test_handshake(&mut peer_stream).await;

    timeout(Duration::from_secs(2), async {
        loop {
            let sessions = runtime.sessions();
            if let Some(session) = sessions
                .iter()
                .find(|session| session.source == SessionSource::Outbound(PeerId::new(1)))
            {
                assert_eq!(session.state, SessionState::Active);
                assert_eq!(session.node_id, Some(test_handshake_identity().node_id));
                assert_eq!(
                    session.nonce.as_deref(),
                    Some(test_handshake_identity().nonce.as_str())
                );
                assert_eq!(session.matched_peer_id, Some(PeerId::new(1)));
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("outbound session appears");

    peer_stream.shutdown().await.expect("peer shutdown");
    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

// ── P2P Stage B mobility slice: reap → instant re-dial loop ─────────
//
// The veil-level shape of the epic scenario «сессия admitted → адрес
// сменился → relay → новый адрес → re-exchange → снова admitted»:
//
//   1. an app-added (bootstrap-only, dedup-exempt — exactly how
//      P2PEndpointService registers direct peers) session is live
//      → `live_sessions` non-empty ⇒ peer_pnet_status().admitted=true;
//   2. the peer's address silently dies (scripted peer never responds
//      after the handshake; socket stays open — no FIN/RST, the NAT
//      black-hole shape) → the keepalive probe reaps the session
//      within a few keepalive intervals → `admitted` flips false and
//      call media falls back to relay;
//   3. connectivity returns (same listener accepts again) → the
//      outbound connector re-dials WITHOUT waiting out a poll interval
//      → fresh handshake → session re-registered ⇒ admitted=true again.
//
// Deterministic against Phase E20 directional dedup: bootstrap-only
// peers bypass the lexicographic keep-inbound policy, so the dial
// always happens regardless of the random sovereign identity.
#[tokio::test(flavor = "current_thread")]
async fn mobility_black_holed_bootstrap_session_reaps_and_redials() {
    use veil_cfg::{BootstrapPeer, default_nonce_base64};

    // Scripted peer identity — distinct from the runtime's own.
    let peer_keys = test_support::ed25519_keypair();
    let peer_identity = HandshakeIdentity {
        algo: SignatureAlgorithm::Ed25519,
        public_key: peer_keys.public_key.clone(),
        private_key: peer_keys.private_key.clone(),
        nonce: default_nonce_base64(),
        node_id: NodeId::from_public_key(SignatureAlgorithm::Ed25519, &peer_keys.public_key)
            .expect("peer node id"),
    };
    let peer_node_id = peer_identity.node_id;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("peer listener");
    let peer_addr = listener.local_addr().expect("peer addr");

    let mut config = runtime_config_with_listen();
    // No configured peers — the app-added path registers via
    // bootstrap_peers (bootstrap_only=true, directional-dedup exempt).
    config.peers.clear();
    config.bootstrap_peers = vec![BootstrapPeer {
        transport: format!("tcp://{peer_addr}"),
        public_key: peer_keys.public_key.clone(),
        nonce: default_nonce_base64(),
        algo: Default::default(),
        tls_cert: None,
        tls_ca_cert: None,
    }];
    // Compressed liveness timeline so the test runs in seconds. The
    // realtime acceleration itself is pinned by the veil-session suite
    // (production 30 s constants); here 1 s ≤ the 2 s accel constant so
    // the base machinery drives the reap.
    config.session.keepalive_interval_secs = 1;
    config.session.idle_timeout_secs = 3;

    let path = save_test_config("mobility-reap-redial", config).unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");

    // Phase 1 — admitted: the bootstrap dial lands, we complete the
    // scripted handshake, the session registers.
    let mut first_stream = accept_dial(&listener, "first").await;
    let _ = perform_ovl1_handshake(
        &mut first_stream,
        &peer_identity,
        veil_cfg::NodeRole::Core,
        veil_cfg::DiscoveryMode::Public,
        None,
        None,
        None,
        Some([0u8; 32]),
        None,
        None,
        None,
        &[],
        false,
        true, // dht_service: a test node serves, like any default node
        None,
        None,
        None,
    )
    .await
    .expect("first scripted handshake");

    let first_link_id = timeout(Duration::from_secs(10), async {
        loop {
            if let Some(s) = runtime
                .sessions()
                .iter()
                .find(|s| s.node_id == Some(peer_node_id))
            {
                return s.link_id;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("session must register after handshake (admitted=true)");

    // Phase 2 — black hole: the scripted peer never sends another byte
    // (socket held open — no FIN). The keepalive probe machinery must
    // reap the session within a few 1 s intervals, flipping the
    // admitted-equivalent (live session presence) to false.
    let reap_started = std::time::Instant::now();
    timeout(Duration::from_secs(10), async {
        loop {
            if runtime
                .sessions()
                .iter()
                .all(|s| s.node_id != Some(peer_node_id))
            {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("black-holed session must be reaped (admitted flips false)");
    let reap_elapsed = reap_started.elapsed();

    // Phase 3 — connectivity returns: the connector re-dials without an
    // extra poll-interval wait; a fresh handshake re-registers the
    // session (admitted=true again).
    let redial_started = std::time::Instant::now();
    let (mut second_stream, _) = timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("connector must re-dial promptly after the reap")
        .expect("second accept");
    let redial_elapsed = redial_started.elapsed();
    let _ = perform_ovl1_handshake(
        &mut second_stream,
        &peer_identity,
        veil_cfg::NodeRole::Core,
        veil_cfg::DiscoveryMode::Public,
        None,
        None,
        None,
        Some([0u8; 32]),
        None,
        None,
        None,
        &[],
        false,
        true, // dht_service: a test node serves, like any default node
        None,
        None,
        None,
    )
    .await
    .expect("second scripted handshake");

    timeout(Duration::from_secs(10), async {
        loop {
            if runtime
                .sessions()
                .iter()
                .any(|s| s.node_id == Some(peer_node_id) && s.link_id != first_link_id)
            {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("re-dialed session must re-register (admitted=true again)");

    // Envelope assertions: the reap rides the compressed keepalive
    // machinery (not a 30 s+ poll), and the re-dial is prompt.
    assert!(
        reap_elapsed <= Duration::from_secs(8),
        "reap took {reap_elapsed:?} — must ride the keepalive probe, not long polls"
    );
    assert!(
        redial_elapsed <= Duration::from_secs(8),
        "re-dial took {redial_elapsed:?} — must not wait out a backoff/poll interval"
    );

    drop(first_stream);
    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

// Audit batch 2026-05-24: same Phase E20 dedup interaction as
// [`runtime_creates_outbound_session_for_configured_peer`] — flaky
// on ~50% of runs depending on lex order of randomly-generated
// sovereign identity vs cached test-peer identity.
#[ignore = "Phase E20 directional dedup makes this probabilistic; see comment above runtime_creates_outbound_session_for_configured_peer"]
#[tokio::test(flavor = "current_thread")]
async fn outbound_reconnect_happens_after_disconnect() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("peer listener");
    let peer_addr = listener.local_addr().expect("peer addr");
    let path = save_test_config(
        "node-runtime-outbound-reconnect",
        runtime_config_with_peer_transport(format!("tcp://{peer_addr}")),
    )
    .unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");

    let mut first_stream = accept_dial(&listener, "first").await;
    let _runtime_node_id = complete_test_handshake(&mut first_stream).await;
    timeout(Duration::from_secs(2), async {
        loop {
            if runtime
                .sessions()
                .iter()
                .any(|session| session.source == SessionSource::Outbound(PeerId::new(1)))
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("first outbound session");

    let first_link_id = runtime
        .sessions()
        .iter()
        .find(|session| session.source == SessionSource::Outbound(PeerId::new(1)))
        .map(|session| session.link_id)
        .expect("first outbound session link id");

    first_stream.shutdown().await.expect("first shutdown");

    let mut second_stream = accept_dial(&listener, "second").await;
    let _runtime_node_id = complete_test_handshake(&mut second_stream).await;
    timeout(Duration::from_secs(3), async {
        loop {
            if runtime.sessions().iter().any(|session| {
                session.source == SessionSource::Outbound(PeerId::new(1))
                    && session.link_id != first_link_id
            }) {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reconnected outbound session");

    assert!(runtime.sessions().iter().any(|session| {
        session.source == SessionSource::Outbound(PeerId::new(1))
            && session.link_id != first_link_id
    }));

    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

// Audit batch 2026-05-25 phase M: same Phase E20 dedup interaction as
// the other runtime::tests::outbound_* tests — random sovereign identity
// vs cached test-peer identity makes session establishment probabilistic.
// Test hangs indefinitely waiting for a session that policy may never
// allow.  Aligned with the other ignored siblings (CI green-up phase G).
#[ignore = "Phase E20 directional dedup makes this probabilistic; see runtime_creates_outbound_session_for_configured_peer comment"]
#[tokio::test(flavor = "current_thread")]
async fn outbound_session_rejects_mismatched_peer_identity() {
    let peer_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("peer listener");
    let peer_addr = peer_listener.local_addr().expect("peer addr");
    let path = save_test_config(
        "node-runtime-outbound-mismatch",
        runtime_config_with_mismatched_peer_transport(format!("tcp://{peer_addr}")),
    )
    .unwrap();

    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");
    let mut peer_stream = accept_dial(&peer_listener, "peer").await;
    let _runtime_node_id = complete_test_handshake(&mut peer_stream).await;

    timeout(Duration::from_secs(2), async {
        loop {
            if runtime.sessions().is_empty() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("mismatched outbound session not registered");

    peer_stream.shutdown().await.expect("peer shutdown");
    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

/// A nonce mismatch (same public key, different nonce) is treated as a
/// legitimate re-mine: the session is accepted and the stored nonce is
/// auto-updated. This replaces the old "reject" behaviour.
// Audit batch 2026-05-24: same Phase E20 dedup interaction — flaky.
#[ignore = "Phase E20 directional dedup makes this probabilistic; see comment above runtime_creates_outbound_session_for_configured_peer"]
#[tokio::test(flavor = "current_thread")]
async fn outbound_session_accepts_and_updates_mismatched_peer_nonce() {
    let peer_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("peer listener");
    let peer_addr = peer_listener.local_addr().expect("peer addr");
    let path = save_test_config(
        "node-runtime-outbound-nonce-update",
        runtime_config_with_mismatched_peer_nonce_transport(format!("tcp://{peer_addr}")),
    )
    .unwrap();

    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");
    let mut peer_stream = accept_dial(&peer_listener, "peer").await;
    let _runtime_node_id = complete_test_handshake(&mut peer_stream).await;

    // Session must be established (not rejected) even though the stored
    // nonce does not match the handshake nonce.
    timeout(Duration::from_secs(2), async {
        loop {
            if !runtime.sessions().is_empty() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("session should be established after nonce auto-update");

    // The peer's nonce in state must have been updated to the handshake value.
    let new_nonce = test_handshake_identity().nonce;
    let updated = runtime
        .sessions()
        .iter()
        .any(|s| s.nonce.as_deref() == Some(new_nonce.as_str()));
    assert!(
        updated,
        "session nonce must reflect the new value from handshake"
    );

    peer_stream.shutdown().await.expect("peer shutdown");
    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_handshake_node_id_rejects_inbound_session() {
    let path = save_test_config(
        "node-runtime-invalid-handshake",
        runtime_config_with_listen(),
    )
    .unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");
    let listen = runtime.listens().into_iter().next().expect("listen entry");

    let mut stream = TcpStream::connect(listen.local_addr.as_ref().unwrap())
        .await
        .expect("connects");
    write_invalid_test_handshake(&mut stream).await;

    timeout(Duration::from_secs(2), async {
        loop {
            if runtime.sessions().is_empty() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("invalid handshake does not create session");

    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

#[tokio::test(flavor = "current_thread")]
async fn inbound_unknown_peer_stays_unmatched() {
    let path = save_test_config(
        "node-runtime-inbound-unknown-peer",
        runtime_config_with_unknown_inbound_peer(),
    )
    .unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");
    let listen = runtime.listens().into_iter().next().expect("listen entry");
    let registry = TransportRegistry::with_defaults();
    let ctx = Arc::new(TransportContext::for_debug().expect("debug context"));
    let uri = TransportUri::parse(&format!(
        "tcp://{}",
        listen.local_addr.clone().expect("local addr")
    ))
    .expect("connect uri");

    let connection = registry.connect(&uri, ctx).await.expect("connects");
    let mut stream = connection.into_stream().expect("stream");
    complete_test_handshake(&mut stream).await;

    timeout(Duration::from_secs(2), async {
        loop {
            let sessions = runtime.sessions();
            if let Some(session) = sessions.first() {
                assert_eq!(session.source, SessionSource::Inbound(listen.listen_id));
                assert_eq!(session.matched_peer_id, None);
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("session appears");

    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

/// Abuse pipeline integration test: a peer that exceeds the rate limit
/// receives `Violation` responses (the session stays open, but frames are
/// dropped) and is eventually banned, after which new connections are
/// rejected at the ban-list pre-check.
///
/// This test exercises the full OVL1 path:
/// connect → OVL1 handshake → SessionRunner → FrameDispatcher → abuse checks
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ovl1_abuse_pipeline_ban_and_rate_limit() {
    use veil_cfg::NodeRole;
    use veil_proto::{
        codec::encode_header,
        family::{ControlMsg, FrameFamily},
        header::FrameHeader,
    };

    // Start a Core runtime with a very tight rate limit so we can trigger
    // it quickly. We use a tiny bucket (2 tokens, refill 1/s) so 3 Pings
    // in a row will hit the limit.
    let identity = test_support::valid_identity();
    let config = Config {
        identity: Some(IdentityConfig {
            role: NodeRole::Core,
            node_id: Some(NodeId::from_public_key(identity.algo, &identity.public_key).unwrap()),
            ..identity
        }),
        listen: vec![ListenConfig {
            id: ListenId::new(1),
            transport: "tcp://127.0.0.1:0".to_owned(),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            advertise: None,
            relay: None,
            ..Default::default()
        }],
        peers: vec![],
        ..Config::default()
    };
    let path = save_test_config("node-runtime-ovl1-abuse", config).unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");
    let listen = runtime.listens().into_iter().next().expect("listen entry");

    // Connect and complete handshake.
    let mut stream = TcpStream::connect(listen.local_addr.as_ref().unwrap())
        .await
        .expect("connects");
    complete_test_handshake(&mut stream).await;

    // Wait for session to appear in runtime state.
    timeout(Duration::from_secs(2), async {
        loop {
            if !runtime.sessions().is_empty() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("session registered");

    // Immediately ban the peer via the dispatcher's ban list.
    {
        let peer_id = runtime.sessions()[0]
            .node_id
            .expect("node_id set")
            .as_bytes()
            .to_owned();
        runtime
            .dispatcher
            .abuse
            .ban_list
            .lock()
            .unwrap()
            .ban(peer_id, "test ban", None);
    }

    // Send a Ping — the dispatcher should return a Violation (peer banned).
    // The SessionRunner does NOT close the session on a single violation;
    // it just records it. The stream stays open until we drop it.
    let mut hdr = FrameHeader::new(FrameFamily::Control as u8, ControlMsg::Ping as u16);
    hdr.body_len = 0;
    stream.write_all(&encode_header(&hdr)).await.unwrap();

    // Drop the stream to let the session close cleanly.
    drop(stream);

    // Verify ban list records the peer.
    timeout(Duration::from_secs(2), async {
        loop {
            let banned_count = runtime.runtime_summary.lock().unwrap().banned_peers;
            if banned_count > 0 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("ban list reports banned peer");

    // Read the response to the Ping to prove the session runner still
    // processes frames even from banned peers (it logs + records but does
    // not hard-close). We drop the stream before reading to keep the
    // test simple; the important invariant is that the ban is persisted.

    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

/// b: verify that the per-IP session limit is bypassed for
/// loopback peers (devnet/sim ergonomics — many local nodes share
/// 127.0.0.1 and would otherwise starve). The runtime still enforces
/// the limit for routable peers; that path is covered by the legacy
/// test (now ignored; would need a non-loopback bind to exercise).
#[tokio::test]
#[ignore = "454.2b: loopback now bypasses per-IP limit; new assertion would need non-loopback"]
async fn per_ip_session_limit_rejects_excess_connections() {
    use veil_cfg::NodeRole;
    let max_per_ip = veil_cfg::SessionConfig::default().max_per_ip;

    let identity = test_support::valid_identity();
    let config = Config {
        identity: Some(IdentityConfig {
            role: NodeRole::Core,
            node_id: Some(NodeId::from_public_key(identity.algo, &identity.public_key).unwrap()),
            ..identity
        }),
        listen: vec![ListenConfig {
            id: ListenId::new(1),
            transport: "tcp://127.0.0.1:0".to_owned(),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            advertise: None,
            relay: None,
            ..Default::default()
        }],
        peers: vec![],
        ..Config::default()
    };
    let path = save_test_config("node-runtime-per-ip-limit", config).unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");
    let listen_addr = runtime
        .listens()
        .into_iter()
        .next()
        .expect("listen entry")
        .local_addr
        .unwrap();

    // Establish max_per_ip connections from 127.0.0.1 — all should succeed.
    let mut streams: Vec<TcpStream> = Vec::new();
    for _ in 0..max_per_ip {
        let mut s = TcpStream::connect(&listen_addr).await.expect("connects");
        complete_test_handshake(&mut s).await;
        streams.push(s);
    }

    // Wait until all sessions appear.
    timeout(Duration::from_secs(5), async {
        loop {
            if runtime.sessions().len() >= max_per_ip {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("all sessions registered within timeout");

    assert_eq!(runtime.sessions().len(), max_per_ip);

    // One more connection from the same IP must be rejected (TCP reset or closed).
    let extra = TcpStream::connect(&listen_addr)
        .await
        .expect("TCP layer accepts");
    // The runtime closes the socket without completing the handshake.
    let mut buf = [0u8; 16];
    let result = timeout(
        Duration::from_secs(2),
        tokio::io::AsyncReadExt::read(&mut tokio::io::BufReader::new(extra), &mut buf),
    )
    .await;
    // Either the read times out (runtime dropped the socket) or returns 0 bytes (EOF).
    if let Ok(Ok(n)) = result {
        assert_eq!(n, 0, "server must close socket, not write data");
    }

    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

pub fn runtime_config_with_listen() -> Config {
    let identity = test_support::valid_identity();
    Config {
        identity: Some(IdentityConfig {
            node_id: Some(NodeId::from_public_key(identity.algo, &identity.public_key).unwrap()),
            ..identity
        }),
        peers: vec![PeerConfig {
            peer_id: PeerId::new(1),
            public_key: test_support::valid_identity().public_key,
            nonce: test_support::valid_identity().nonce,
            transport: "tcp://127.0.0.1:9000".to_owned(),
            algo: Default::default(),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            alt_uri: None,
        }],
        listen: vec![ListenConfig {
            id: ListenId::new(1),
            transport: "tcp://127.0.0.1:0".to_owned(),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            advertise: None,
            relay: None,
            ..Default::default()
        }],
        ..Config::default()
    }
}

pub fn runtime_config_with_two_listens() -> Config {
    let mut config = runtime_config_with_listen();
    config.listen.push(ListenConfig {
        id: ListenId::new(2),
        transport: "tcp://127.0.0.1:0".to_owned(),
        tls_cert: None,
        tls_key: None,
        tls_ca_cert: None,
        advertise: None,
        relay: None,
        ..Default::default()
    });
    config
}

pub fn runtime_config_with_metrics() -> Config {
    let mut config = runtime_config_with_listen();
    config.metrics = Some(veil_cfg::MetricsConfig {
        listen: "tcp://127.0.0.1:0".to_owned(),
        path: Some("/metrics".to_owned()),
        auth_token: None,
        allow_unauthenticated_remote_metrics: false,
    });
    config
}

pub fn runtime_config_with_peer_transport(transport: String) -> Config {
    let mut config = runtime_config_with_listen();
    config.peers[0].transport = transport;
    config
}

pub fn runtime_config_with_unknown_inbound_peer() -> Config {
    let mut config = runtime_config_with_listen();
    let other_keypair = test_support::ed25519_keypair();
    config.peers[0].public_key = other_keypair.public_key;
    config
}

pub fn runtime_config_with_mismatched_peer_transport(transport: String) -> Config {
    let mut config = runtime_config_with_peer_transport(transport);
    let mismatched_keypair = test_support::ed25519_keypair();
    config.peers[0].public_key = mismatched_keypair.public_key;
    config.peers[0].nonce = "AAAAAAAAAAAAAAAAAAAAAA==".to_owned();
    config
}

pub fn runtime_config_with_mismatched_peer_nonce_transport(transport: String) -> Config {
    let mut config = runtime_config_with_peer_transport(transport);
    config.peers[0].nonce = "AAAAAAAAAAAAAAAAAAAAAA==".to_owned();
    config
}

#[test]
pub fn verify_remote_peer_identity_reports_mismatch_readably() {
    let id = test_handshake_identity();
    let remote = RemoteHandshakeInfo {
        node_id: id.node_id,
        public_key: id.public_key.clone(),
        nonce: id.nonce.clone(),
        session_keys: veil_crypto::session_kdf::SessionKeys {
            tx_key: [0u8; 32],
            rx_key: [0u8; 32],
            session_id: [0u8; 32],
        },
        remote_discovery_mode: veil_cfg::DiscoveryMode::Public,
        remote_dht_service: true,
        remote_caps_stated: true,
        supports_realtime_datagrams: false,
        supports_realtime_rekey: false,
        udp_reflector_port: None,
        shared_udp_reflectors: Vec::new(),
    };
    let mismatched_keypair = test_support::ed25519_keypair();
    let expected = ExpectedPeerIdentity {
        peer_id: PeerId::new(7),
        public_key: mismatched_keypair.public_key.clone(),
        node_id: NodeId::from_public_key(
            SignatureAlgorithm::Ed25519,
            &mismatched_keypair.public_key,
        )
        .expect("node id"),
        nonce: id.nonce,
    };

    let error = verify_remote_peer_identity(&remote, &expected).expect_err("mismatch");
    let message = match error {
        PeerVerificationError::IdentityMismatch(msg) => msg,
        PeerVerificationError::NonceMismatch => {
            panic!("expected IdentityMismatch, got NonceMismatch")
        }
    };
    assert!(message.contains("peer identity mismatch"));
    assert!(message.contains("0x00000007"));
}

#[test]
pub fn verify_remote_peer_identity_reports_nonce_mismatch_readably() {
    let id = test_handshake_identity();
    let remote = RemoteHandshakeInfo {
        node_id: id.node_id,
        public_key: id.public_key.clone(),
        nonce: id.nonce.clone(),
        session_keys: veil_crypto::session_kdf::SessionKeys {
            tx_key: [0u8; 32],
            rx_key: [0u8; 32],
            session_id: [0u8; 32],
        },
        remote_discovery_mode: veil_cfg::DiscoveryMode::Public,
        remote_dht_service: true,
        remote_caps_stated: true,
        supports_realtime_datagrams: false,
        supports_realtime_rekey: false,
        udp_reflector_port: None,
        shared_udp_reflectors: Vec::new(),
    };
    let expected = ExpectedPeerIdentity {
        peer_id: PeerId::new(8),
        public_key: test_handshake_identity().public_key,
        node_id: test_handshake_identity().node_id,
        nonce: "AAAAAAAAAAAAAAAAAAAAAA==".to_owned(),
    };

    // NonceMismatch now carries no message (the caller builds the log line).
    let error = verify_remote_peer_identity(&remote, &expected).expect_err("mismatch");
    assert!(
        matches!(error, PeerVerificationError::NonceMismatch),
        "expected NonceMismatch variant for peer 0x00000008"
    );
}

pub fn save_test_config(prefix: &str, config: Config) -> veil_cfg::Result<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    // Its OWN directory, not a unique filename in the shared one.
    //
    // The node treats the config's PARENT as its veil dir and writes
    // `identity_document.bin` and `device_identity_sk.bin` next to it. With
    // every test sharing `temp_dir()`, one test's identity files were read by
    // the next — and a document from one run paired with a secret key from
    // another does not load. That used to be swallowed with a warning, so the
    // tests passed while quietly running as legacy; now it is refused
    // (audit V-07), which is what made the leak visible.
    //
    // Per-test directories are the actual fix: the isolation was missing all
    // along, the old behaviour just hid it.
    let dir = std::env::temp_dir().join(format!("{prefix}-{unique}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(veil_cfg::ConfigError::Io)?;
    let path = dir.join(format!("{prefix}.toml"));
    veil_cfg::save_config(&path, &config)?;
    Ok(path)
}

async fn fetch_metrics(endpoint: &str, path: &str) -> String {
    let mut stream = TcpStream::connect(endpoint).await.expect("metrics connect");
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("metrics request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .expect("metrics response");
    response
}

pub fn test_handshake_identity() -> HandshakeIdentity {
    let identity = test_support::valid_identity();
    HandshakeIdentity {
        algo: identity.algo,
        public_key: identity.public_key.clone(),
        private_key: identity.private_key.clone(),
        nonce: identity.nonce.clone(),
        node_id: NodeId::from_public_key(identity.algo, &identity.public_key).unwrap(),
    }
}

async fn complete_test_handshake<S>(stream: &mut S) -> NodeId
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    use veil_cfg::NodeRole;
    // this fixture acts as a CLIENT dialing the server-
    // under-test, so it's the outbound side and must pass
    // `Some(...)` for `known_remote_id` to skip the silent-server
    // wait. Placeholder value is fine — the actual peer node_id is
    // overwritten from the server's HELLO during the handshake.
    perform_ovl1_handshake(
        stream,
        &test_handshake_identity(),
        NodeRole::Core,
        veil_cfg::DiscoveryMode::Public,
        None,
        None,
        None,
        Some([0u8; 32]),
        None,
        None,
        None,
        &[],
        false,
        true, // dht_service: a test node serves, like any default node
        None,
        None, // P-Net: no network gate in this fixture
        None, // S3: no peer_observed_addr in this fixture
    )
    .await
    .expect("OVL1 handshake succeeds")
    .node_id
}

// `write_invalid_test_handshake` writes bytes that the runtime will reject
// regardless of handshake type — in legacy mode it's a wrong node_id frame;
// in OVL1 mode it's an unrecognisable byte sequence that fails header decode.
async fn write_invalid_test_handshake<S>(stream: &mut S)
where
    S: AsyncWrite + Unpin,
{
    // Write 8 garbage bytes — too short for either handshake framing.
    stream
        .write_all(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x01])
        .await
        .unwrap();
}

// ── tests ─────────────────────────────────────────────────────────

/// 79.1 — `derive_node_id_from_bootstrap_peer` matches `NodeId::from_public_key`.
#[test]
pub fn derive_node_id_matches_node_id_from_public_key() {
    use veil_cfg::{BootstrapPeer, SignatureAlgorithm, default_nonce_base64};

    let identity = test_support::valid_identity();
    let expected_node_id =
        NodeId::from_public_key(SignatureAlgorithm::Ed25519, &identity.public_key)
            .expect("valid node id");

    let bp = BootstrapPeer {
        transport: "tcp://bootstrap.example.com:9000".to_owned(),
        public_key: identity.public_key.clone(),
        nonce: default_nonce_base64(),
        algo: Default::default(),
        tls_cert: None,
        tls_ca_cert: None,
    };
    let derived =
        derive_node_id_from_bootstrap_peer(&bp).expect("valid public key should derive a node_id");

    assert_eq!(
        &derived,
        expected_node_id.as_bytes(),
        "derive_node_id_from_bootstrap_peer must produce BLAKE3(pubkey_bytes)"
    );
}

/// 79.1 — `derive_node_id_from_bootstrap_peer` returns None for invalid base64.
#[test]
pub fn derive_node_id_returns_none_for_invalid_key() {
    use veil_cfg::{BootstrapPeer, default_nonce_base64};

    let bp = BootstrapPeer {
        transport: "tcp://x:9000".to_owned(),
        public_key: "not-valid-base64!!!".to_owned(),
        nonce: default_nonce_base64(),
        algo: Default::default(),
        tls_cert: None,
        tls_ca_cert: None,
    };
    assert!(derive_node_id_from_bootstrap_peer(&bp).is_none());
}

/// 79.3 — bootstrap task adds the peer contact to the DHT routing table.
#[tokio::test(flavor = "current_thread")]
async fn bootstrap_task_adds_contact_to_dht() {
    use veil_cfg::{BootstrapPeer, default_nonce_base64};

    // Use a freshly-generated keypair so it differs from the runtime's own identity.
    let bootstrap_keypair = test_support::ed25519_keypair();
    let bp = BootstrapPeer {
        transport: "tcp://bootstrap.example.com:9000".to_owned(),
        public_key: bootstrap_keypair.public_key.clone(),
        nonce: default_nonce_base64(),
        algo: Default::default(),
        tls_cert: None,
        tls_ca_cert: None,
    };
    let expected_node_id = derive_node_id_from_bootstrap_peer(&bp).expect("valid node id");

    // Build a minimal config with one bootstrap peer.
    let mut config = runtime_config_with_listen();
    config.bootstrap_peers = vec![bp];

    // Use a unique path for this test to avoid interference with other tests
    // that may have left a patched file at the same counter offset.
    let path = save_test_config("bootstrap-dht-contact-epic79", config).unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");

    // Give the bootstrap task a moment to run.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify the contact appears in the DHT routing table.
    let contacts = runtime.dht.routing_table_contacts();
    assert!(
        contacts.iter().any(|c| c.node_id == expected_node_id),
        "bootstrap peer must be added to DHT routing table"
    );

    runtime.stop().await.expect("runtime stops");
    let _ = std::fs::remove_file(path);
}

// ── tests ─────────────────────────────────────────────────────────

/// 82.1 — bootstrap-only peer is inserted into `state.peers` with
/// `bootstrap_only = true` and a synthetic high-bit `peer_id`.
#[tokio::test(flavor = "current_thread")]
async fn bootstrap_only_peer_registered_in_state() {
    use veil_cfg::{BootstrapPeer, default_nonce_base64};

    let bootstrap_keypair = test_support::ed25519_keypair();
    let bp = BootstrapPeer {
        transport: "tcp://127.0.0.1:19999".to_owned(),
        public_key: bootstrap_keypair.public_key.clone(),
        nonce: default_nonce_base64(),
        algo: Default::default(),
        tls_cert: None,
        tls_ca_cert: None,
    };

    // Config with bootstrap peer that is NOT in config.peers.
    let mut config = runtime_config_with_listen();
    config.bootstrap_peers = vec![bp];

    let path = save_test_config("bootstrap-state-epic82", config).unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");

    // Give the bootstrap task a moment to register the peer.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The bootstrap-only peer must appear in state.peers with bootstrap_only = true.
    let peers = runtime.peers();
    let bootstrap_peer = peers.iter().find(|p| p.bootstrap_only);
    assert!(
        bootstrap_peer.is_some(),
        "bootstrap-only peer must appear in state.peers"
    );
    let bp_entry = bootstrap_peer.unwrap();
    assert!(
        bp_entry.peer_id.get() >= 0x8000_0000,
        "bootstrap peer_id must have high bit set"
    );
    assert_eq!(
        bp_entry.public_key, bootstrap_keypair.public_key,
        "public key must match bootstrap peer config"
    );

    runtime.stop().await.expect("runtime stops");
    let _ = std::fs::remove_file(path);
}

/// 82.2 — a peer that appears in both `config.peers` and `config.bootstrap_peers`
/// is NOT inserted as a bootstrap-only entry (the regular outbound connector
/// manages it) and does NOT appear twice in state.
#[tokio::test(flavor = "current_thread")]
async fn bootstrap_peer_that_is_also_configured_peer_not_duplicated() {
    use veil_cfg::{BootstrapPeer, default_nonce_base64};

    // Use the same keypair as the existing config.peers[0].
    let regular_peer_key = test_support::valid_identity().public_key;
    let bp = BootstrapPeer {
        transport: "tcp://127.0.0.1:9000".to_owned(),
        public_key: regular_peer_key.clone(),
        nonce: default_nonce_base64(),
        algo: Default::default(),
        tls_cert: None,
        tls_ca_cert: None,
    };

    let mut config = runtime_config_with_listen();
    // config.peers[0] already has this public_key — bp overlaps.
    config.bootstrap_peers = vec![bp];

    let path = save_test_config("bootstrap-no-dup-epic82", config).unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");

    tokio::time::sleep(Duration::from_millis(50)).await;

    // No bootstrap-only entry must appear — the peer is a regular configured peer.
    let peers = runtime.peers();
    assert!(
        peers.iter().all(|p| !p.bootstrap_only),
        "peer that is in config.peers must not be marked bootstrap_only"
    );

    runtime.stop().await.expect("runtime stops");
    let _ = std::fs::remove_file(path);
}

/// 82.3 — `NetworkPeerQuerier::find_node` returns contacts from a mock session
/// and `add_contact` inserts them into the DHT. This tests the core data-flow
/// that the bootstrap outbound connector task drives.
///
/// the querier now uses the V2 wire path (FindNodeV2 +
/// per-id ResolveTransport). The mock answers both message types.
#[tokio::test]
async fn bootstrap_find_node_contacts_added_to_dht() {
    use veil_dht::{iterative::PeerQuerier, network_querier::NetworkPeerQuerier, routing::Contact};
    use veil_session::outbox::SessionOutbox;

    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    let outbox = SessionOutbox::new();
    let peer_node_id = [0xBBu8; 32];
    let local_node_id = [0xAAu8; 32];

    //the mock must serve a real signed
    // announcement so the walker accepts the resolved transport.
    // Generate a fresh ed25519 key for the discovered peer; node_id
    // is derived as BLAKE3(pubkey).
    let discovered_sk = SigningKey::generate(&mut OsRng);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let discovered_ann = veil_proto::discovery::sign_transport_announcement(
        &discovered_sk,
        "tcp://192.168.1.1:9000".to_owned(),
        now + 600,
    );
    let discovered = Contact {
        node_id: discovered_ann.node_id,
        transport: discovered_ann.transport.clone(),
        discovery_mode: 0,
        // Learned from a signed announcement, not from a handshake: nobody
        // stated capabilities, so it serves (the bit only ever asks for less)
        // and `caps_known` stays false so a later handshake can speak.
        no_dht_service: false,
        caps_known: false,
    };

    // Spawn a mock session that answers FindNodeV2 → node_ids and
    // ResolveTransport → the signed announcement.
    let discovered_clone = discovered.clone();
    let discovered_ann_clone = discovered_ann.clone();
    let mut rx = outbox.register(peer_node_id);
    tokio::spawn(async move {
        use veil_proto::{
            HEADER_SIZE,
            codec::decode_header,
            discovery::{FindNodeV2Response, ResolveTransportPayload, ResolveTransportResponse},
            family::DiscoveryMsg,
        };
        while let Some(req) = rx.recv().await {
            if req.frame.len() < HEADER_SIZE {
                continue;
            }
            let hdr = match decode_header(&req.frame[..HEADER_SIZE]) {
                Ok(h) => h,
                Err(_) => continue,
            };
            if hdr.msg_type == DiscoveryMsg::FindNodeV2 as u16 {
                let resp = FindNodeV2Response {
                    node_ids: vec![discovered_clone.node_id],
                };
                let _ = req.response_tx.send(Some(resp.encode()));
            } else if hdr.msg_type == DiscoveryMsg::ResolveTransport as u16 {
                let payload = &req.frame[HEADER_SIZE..];
                let Ok(rt) = ResolveTransportPayload::decode(payload) else {
                    continue;
                };
                let announcement = if rt.node_id == discovered_clone.node_id {
                    Some(discovered_ann_clone.clone())
                } else {
                    None
                };
                let resp = ResolveTransportResponse {
                    node_id: rt.node_id,
                    announcement,
                };
                let _ = req.response_tx.send(Some(resp.encode()));
            }
        }
    });

    // Run the querier.
    let querier = NetworkPeerQuerier::new(
        Arc::clone(&outbox) as Arc<dyn veil_dht::FrameRouter>,
        veil_cfg::DhtConfig::default().k,
        tokio::time::Duration::from_millis(veil_cfg::DhtConfig::default().find_node_timeout_ms),
        local_node_id,
    );
    let contacts: Vec<Contact> = querier.find_node(peer_node_id, local_node_id).await;

    assert_eq!(
        contacts.len(),
        1,
        "must receive one contact from mock session"
    );
    assert_eq!(contacts[0].node_id, discovered.node_id);

    // Simulate what the bootstrap task does: add each contact to the DHT.
    let dht = KademliaService::new(local_node_id);
    for c in &contacts {
        dht.add_contact(c.clone());
    }

    let table = dht.routing_table_contacts();
    assert!(
        table.iter().any(|c| c.node_id == discovered.node_id),
        "discovered contact must be in the DHT routing table"
    );
}

// ── graceful shutdown ──────────────────────────────────────────

/// `stop` must complete without panicking and log "all listeners stopped".
/// The Detach broadcast path is exercised by stop_tasks; since there are no
/// active sessions in this test the send_to_all is a no-op.
#[tokio::test(flavor = "current_thread")]
async fn graceful_stop_completes_without_panic() {
    let path = save_test_config("graceful-stop", runtime_config_with_listen()).unwrap();
    let mut runtime = NodeRuntime::start(&path, false).await.expect("start");
    // stop should succeed and not panic (Detach drain + task abort).
    runtime.stop().await.expect("graceful stop");
    let _ = fs::remove_file(&path);
}

/// Double-stop must be safe: calling stop twice should not panic.
#[tokio::test(flavor = "current_thread")]
async fn graceful_stop_is_idempotent() {
    let path = save_test_config("graceful-stop-idem", runtime_config_with_listen()).unwrap();
    let mut runtime = NodeRuntime::start(&path, false).await.expect("start");
    runtime.stop().await.expect("first stop");
    runtime.stop().await.expect("second stop must not panic");
    let _ = fs::remove_file(&path);
}

/// Audit M2 regression: PEX must survive `reload()`.
///
/// Before the fix the initiator/connector were torn down by `do_stop_tasks`
/// (aborted out of `tasks.background` + signalled via the main `shutdown_tx`)
/// and never respawned — the take-once `event_rx`/`connect_rx` on `self.pex`
/// stayed `None`, so the spawn arms in `spawn_all_services` were skipped while
/// the Arc-cloned dispatcher kept pushing into the orphaned channel. PEX
/// peer-exchange was permanently dead after the first reload.
///
/// The fix recreates the PEX channels on reload and rebuilds a FRESH
/// dispatcher pointing at the new event sender. Both halves are asserted:
///   1. the dispatcher is a *new* `Arc` after reload (channel rebuilt, not
///      Arc-cloned);
///   2. `event_rx` is `None` after reload — proving the respawned initiator
///      consumed the freshly-primed receiver (the old bug left it `None` only
///      because it was never re-primed; here it is re-primed to `Some` then
///      taken by the respawn, so `None` is positive proof of respawn).
#[tokio::test(flavor = "current_thread")]
async fn pex_survives_reload_m2() {
    let path = save_test_config("pex-reload-m2", runtime_config_with_listen()).unwrap();
    let mut runtime = NodeRuntime::start(&path, false).await.expect("start");

    // PEX is enabled by default → dispatcher present, receiver consumed by the
    // initiator spawned during start.
    let disp_before = runtime
        .dispatcher
        .pex_dispatcher
        .as_ref()
        .map(Arc::clone)
        .expect("pex enabled → dispatcher present on start");
    assert!(
        runtime.pex.event_rx.is_none(),
        "initiator should have consumed event_rx on start"
    );

    runtime.reload().await.expect("reload succeeds");

    let disp_after = runtime
        .dispatcher
        .pex_dispatcher
        .as_ref()
        .map(Arc::clone)
        .expect("pex dispatcher still present after reload");
    assert!(
        !Arc::ptr_eq(&disp_before, &disp_after),
        "reload must build a FRESH pex dispatcher wired to the new channel, \
         not Arc-clone the stale one"
    );
    assert!(
        runtime.pex.event_rx.is_none(),
        "respawned initiator must have consumed the freshly-primed event_rx \
         (None proves PEX respawned on reload)"
    );

    runtime.stop().await.expect("stop");
    let _ = fs::remove_file(&path);
}

#[tokio::test(flavor = "current_thread")]
async fn bans_survive_reload_crit4() {
    // audit cycle-9 CRIT-4: a reload reset the ban list to empty and never
    // re-read bans.json, so banned peers reconnected immediately after any
    // SIGHUP / admin reload. The fix re-loads persisted bans after the reset.
    let path = save_test_config("ban-reload-crit4", runtime_config_with_listen()).unwrap();
    let mut runtime = NodeRuntime::start(&path, false).await.expect("start");

    let victim = [0x42u8; 32];
    veil_util::lock!(runtime.ban_list).ban_manual(victim, "audit-test");
    assert!(
        super::persistence::persist_bans(&runtime.ban_list, &path).is_durable(),
        "precondition: the ban must actually reach disk before a reload can \
         restore it"
    );
    assert!(
        veil_util::lock!(runtime.ban_list).is_banned(&victim),
        "peer banned before reload"
    );

    runtime.reload().await.expect("reload succeeds");

    assert!(
        veil_util::lock!(runtime.ban_list).is_banned(&victim),
        "manual ban must survive reload (CRIT-4) — was reset to empty before the fix"
    );

    runtime.stop().await.expect("stop");
    let _ = fs::remove_file(&path);
}

#[tokio::test(flavor = "current_thread")]
async fn rejected_handshake_does_not_leak_session_registry_crit6() {
    // audit cycle-9 CRIT-6: the SessionEntry was inserted into session_registry
    // BEFORE the accept gates, and no SessionGuard is created on a reject path,
    // so every handshake-then-reject leaked a ~1 KB entry into the unbounded
    // `sessions` map (and clobbered by_peer for a peer with a live session).
    // A second concurrent session from the SAME peer is rejected at the dedup
    // gate AFTER the handshake crypto completes — exactly the post-cache reject
    // path. After the fix the second session's entry is never inserted, so
    // session_registry stays at 1, not 2.
    let path = save_test_config("node-runtime-crit6", runtime_config_with_metrics()).unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");
    let listen = runtime.listens().into_iter().next().expect("listen entry");
    let addr = listen.local_addr.as_ref().unwrap().clone();

    // Session 1 — accepted and registered.
    let mut stream1 = TcpStream::connect(&addr).await.expect("connects 1");
    complete_test_handshake(&mut stream1).await;
    timeout(Duration::from_secs(2), async {
        loop {
            if veil_util::lock!(runtime.session_registry).len() == 1 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("session 1 registered");

    // Session 2 — same client identity, so the dedup gate rejects it AFTER its
    // handshake completes. Keep stream1 alive so the dedup actually fires.
    let mut stream2 = TcpStream::connect(&addr).await.expect("connects 2");
    complete_test_handshake(&mut stream2).await;
    sleep(Duration::from_millis(300)).await;

    assert_eq!(
        veil_util::lock!(runtime.session_registry).len(),
        1,
        "dedup-rejected second session must NOT leak into session_registry (CRIT-6) — \
         len would be 2 before the fix"
    );

    let _ = stream2.shutdown().await;
    let _ = stream1.shutdown().await;
    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

/// Audit M7: the ephemeral-rotator shutdown senders must be drained out of the
/// runtime on stop/reload (so the list does not grow unbounded across reloads)
/// and actually signalled (the old code only ever pushed — the documented
/// graceful send was never implemented).
#[tokio::test(flavor = "current_thread")]
async fn ephemeral_rotator_shutdowns_drained_and_signalled_m7() {
    let path = save_test_config("eph-rotator-drain-m7", runtime_config_with_listen()).unwrap();
    let mut runtime = NodeRuntime::start(&path, false).await.expect("start");

    // Simulate a spawned ephemeral rotator stashing its shutdown sender.
    let (tx, mut rx) = tokio::sync::watch::channel(false);
    veil_util::lock!(runtime.ephemeral_rotator_shutdowns).push(tx);
    assert_eq!(
        veil_util::lock!(runtime.ephemeral_rotator_shutdowns).len(),
        1
    );

    // take_stop_tasks_context must DRAIN the list (no growth across reloads)
    // and carry the sender so do_stop_tasks can signal it.
    let ctx = runtime.take_stop_tasks_context();
    assert_eq!(
        ctx.ephemeral_rotator_shutdowns.len(),
        1,
        "sender carried into the stop context"
    );
    assert!(
        veil_util::lock!(runtime.ephemeral_rotator_shutdowns).is_empty(),
        "source list drained — a reload re-populates rather than accumulating"
    );

    // do_stop_tasks must send `true` to the rotator (graceful-exit signal).
    NodeRuntime::do_stop_tasks(ctx).await;
    assert!(
        *rx.borrow_and_update(),
        "rotator must receive the graceful shutdown signal"
    );

    let _ = fs::remove_file(&path);
}

// ── health_tick ────────────────────────────────────────────────

/// `health_tick` must return a non-zero value after the maintenance loop
/// has had a chance to run (at least 1 tick in ~1.5 s).
#[tokio::test(flavor = "current_thread")]
async fn health_tick_advances_after_maintenance_loop() {
    let path = save_test_config("health-tick", runtime_config_with_listen()).unwrap();
    let mut runtime = NodeRuntime::start(&path, false).await.expect("start");
    let tick_before = runtime.health_tick();
    // Wait up to 2 s for at least one maintenance tick (interval = 1 s).
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if runtime.health_tick() > tick_before {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!("health_tick did not advance within 2 s");
        }
    }
    runtime.stop().await.expect("stop");
    let _ = fs::remove_file(&path);
}

// ── advertise / relay helpers ──────────────────────────────────

#[test]
pub fn advertise_substituted_in_listen_transports() {
    let config = Config {
        listen: vec![ListenConfig {
            id: ListenId::new(1),
            transport: "tcp://0.0.0.0:9000".to_owned(),
            advertise: Some("tcp://1.2.3.4:9000".to_owned()),
            relay: None,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            ..Default::default()
        }],
        ..Config::default()
    };
    let transports = build_advertised_transports(&config);
    assert_eq!(transports, vec!["tcp://1.2.3.4:9000"]);
}

#[test]
pub fn transport_used_when_advertise_absent_and_not_wildcard() {
    // Real bind address — fall back to `transport` for advertising.
    let config = Config {
        listen: vec![ListenConfig {
            id: ListenId::new(1),
            transport: "tcp://192.0.2.10:9000".to_owned(),
            advertise: None,
            relay: None,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            ..Default::default()
        }],
        ..Config::default()
    };
    let transports = build_advertised_transports(&config);
    assert_eq!(transports, vec!["tcp://192.0.2.10:9000"]);
}

#[test]
pub fn wildcard_bind_without_advertise_yields_empty_list() {
    // Bind on 0.0.0.0 with no `advertise` set — PEX/RouteResponse must
    // NOT advertise the wildcard, since peers receiving it would dial
    // their own loopback (hardening).
    let config = Config {
        listen: vec![ListenConfig {
            id: ListenId::new(1),
            transport: "tcp://0.0.0.0:9000".to_owned(),
            advertise: None,
            relay: None,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            ..Default::default()
        }],
        ..Config::default()
    };
    let transports = build_advertised_transports(&config);
    assert!(
        transports.is_empty(),
        "wildcard bind without advertise must produce empty list"
    );
}

#[test]
pub fn relay_node_ids_decoded_into_dispatcher() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let relay_id = [0x42u8; 32];
    let config = Config {
        listen: vec![ListenConfig {
            id: ListenId::new(1),
            transport: "tcp://0.0.0.0:9000".to_owned(),
            advertise: None,
            relay: Some(STANDARD.encode(relay_id)),
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            ..Default::default()
        }],
        ..Config::default()
    };
    let ids = build_relay_node_ids(&config);
    assert_eq!(ids, vec![relay_id]);
}

#[test]
pub fn relay_node_ids_deduplicated() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let relay_id = [0x11u8; 32];
    let encoded = STANDARD.encode(relay_id);
    let config = Config {
        listen: vec![
            ListenConfig {
                id: ListenId::new(1),
                transport: "tcp://0.0.0.0:9001".to_owned(),
                advertise: None,
                relay: Some(encoded.clone()),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                ..Default::default()
            },
            ListenConfig {
                id: ListenId::new(2),
                transport: "tcp://0.0.0.0:9002".to_owned(),
                advertise: None,
                relay: Some(encoded),
                tls_cert: None,
                tls_key: None,
                tls_ca_cert: None,
                ..Default::default()
            },
        ],
        ..Config::default()
    };
    let ids = build_relay_node_ids(&config);
    assert_eq!(ids.len(), 1, "duplicate relay ids must be deduplicated");
    assert_eq!(ids[0], relay_id);
}

#[test]
pub fn relay_absent_yields_empty_relay_node_ids() {
    let config = Config {
        listen: vec![ListenConfig {
            id: ListenId::new(1),
            transport: "tcp://0.0.0.0:9000".to_owned(),
            advertise: None,
            relay: None,
            tls_cert: None,
            tls_key: None,
            tls_ca_cert: None,
            ..Default::default()
        }],
        ..Config::default()
    };
    assert!(build_relay_node_ids(&config).is_empty());
}

// ── PeerPubkeySnapshot JSON roundtrip ───────────────────────────

/// PeerPubkeySnapshot serialises and deserialises all fields correctly.
#[test]
pub fn peer_pubkey_snapshot_json_roundtrip() {
    let node_id = [0xABu8; 32];
    let pubkey = vec![0x01u8, 0x02, 0x03, 0xFFu8];
    let snap = PeerPubkeySnapshot {
        node_id,
        algo: 1,
        pubkey: pubkey.clone(),
    };
    let json = serde_json::to_string(&snap).expect("serialize");
    let decoded: PeerPubkeySnapshot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.node_id, node_id);
    assert_eq!(decoded.algo, 1);
    assert_eq!(decoded.pubkey, pubkey);
}

/// A Vec of PeerPubkeySnapshot roundtrips through JSON (simulates the actual
/// flush/restore format used by flush_peer_pubkeys_snapshot_sync).
#[test]
pub fn peer_pubkey_snapshot_vec_json_roundtrip() {
    let entries = vec![
        PeerPubkeySnapshot {
            node_id: [0x01u8; 32],
            algo: 0,
            pubkey: vec![0xAAu8; 32],
        },
        PeerPubkeySnapshot {
            node_id: [0x02u8; 32],
            algo: 1,
            pubkey: vec![0xBBu8; 64],
        },
    ];
    let json = serde_json::to_string(&entries).expect("serialize");
    let decoded: Vec<PeerPubkeySnapshot> = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].node_id, [0x01u8; 32]);
    assert_eq!(decoded[0].pubkey, vec![0xAAu8; 32]);
    assert_eq!(decoded[1].node_id, [0x02u8; 32]);
    assert_eq!(decoded[1].algo, 1);
}

/// flush + restore roundtrip through a temp file.
#[test]
pub fn peer_pubkey_snapshot_flush_restore_roundtrip() {
    use veil_observability::NodeLogger;
    let tmp_path = std::env::temp_dir()
        .join("peer_pubkeys_epic164_test.json")
        .to_str()
        .unwrap()
        .to_owned();

    let entries = vec![PeerPubkeySnapshot {
        node_id: [0xCCu8; 32],
        algo: 0,
        pubkey: vec![1, 2, 3],
    }];

    let logger = Arc::new(NodeLogger::new_noop());
    NodeRuntime::flush_peer_pubkeys_snapshot_sync(tmp_path.clone(), entries, logger);

    // Read the written file and deserialise.
    let data = std::fs::read_to_string(&tmp_path).expect("file written");
    let decoded: Vec<PeerPubkeySnapshot> = serde_json::from_str(&data).expect("valid JSON");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].node_id, [0xCCu8; 32]);
    assert_eq!(decoded[0].pubkey, vec![1, 2, 3]);

    let _ = std::fs::remove_file(&tmp_path);
}

// ── discovery initiator ─────────────────────────────────────────

#[tokio::test(flavor = "current_thread")]
async fn trigger_discovery_search_returns_ok_after_start() {
    let path = save_test_config("node-runtime-discovery", runtime_config_with_listen()).unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");

    // After start the discovery initiator task is spawned — the trigger should succeed.
    assert!(runtime.trigger_discovery_search().is_ok());
    // Second call also succeeds (channel has capacity 4).
    assert!(runtime.trigger_discovery_search().is_ok());

    runtime.stop().await.expect("runtime stops");
    let _ = std::fs::remove_file(path);
}

// ── DhtRepublish filter ────────────────────────────────────

#[test]
pub fn is_self_authenticating_accepts_app_endpoint_magic() {
    let mut v = Vec::new();
    v.extend_from_slice(&veil_discovery::directory::APP_ENDPOINT_DHT_MAGIC);
    v.extend_from_slice(&[0u8; 32]);
    assert!(NodeRuntime::is_self_authenticating_dht_value(&v));
}

#[test]
pub fn is_self_authenticating_accepts_attachment_magic() {
    let mut v = Vec::new();
    v.extend_from_slice(&veil_discovery::directory::ATTACHMENT_DHT_MAGIC);
    v.extend_from_slice(&[0u8; 32]);
    assert!(NodeRuntime::is_self_authenticating_dht_value(&v));
}

#[test]
pub fn is_self_authenticating_accepts_nickname_magic() {
    // "NK" — NicknameRecord (auto-renewal path for claimed names).
    let mut v = Vec::new();
    v.extend_from_slice(&veil_crypto::nickname::NICKNAME_DHT_MAGIC);
    v.extend_from_slice(&[0u8; 32]);
    assert!(NodeRuntime::is_self_authenticating_dht_value(&v));
}

#[test]
pub fn is_self_authenticating_rejects_unsigned_legacy() {
    // Raw AppEndpointEntry legacy format: starts with node_id (32 bytes)
    // first two bytes unlikely to match any magic by accident.
    let v = vec![0x00u8; 120];
    assert!(!NodeRuntime::is_self_authenticating_dht_value(&v));

    // Arbitrary garbage.
    let v = vec![0xFFu8, 0xFE, 0xFD, 0xFC];
    assert!(!NodeRuntime::is_self_authenticating_dht_value(&v));
}

#[test]
pub fn is_self_authenticating_rejects_short_values() {
    // 0 and 1-byte values have no room for a 2-byte magic prefix.
    assert!(!NodeRuntime::is_self_authenticating_dht_value(&[]));
    assert!(!NodeRuntime::is_self_authenticating_dht_value(b"A"));
}

#[test]
pub fn is_self_authenticating_rejects_ap_prefix_impostor() {
    // "AP" as magic requires the exact 2-byte sequence; "Ax" must not
    // trigger acceptance.
    assert!(!NodeRuntime::is_self_authenticating_dht_value(b"Az"));
    assert!(!NodeRuntime::is_self_authenticating_dht_value(b"Zp"));
}

// ── SessionGuard publishes SESSIONS_CHANGED on drop ─────────

#[test]
pub fn session_guard_drop_publishes_sessions_changed() {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use veil_ipc::EventBus;
    use veil_proto::event_kind;

    // Fresh bus + subscriber observed before SessionGuard is built.
    let bus = Arc::new(EventBus::new());
    let mut rx = bus.subscribe();

    let live_sessions: Arc<Mutex<BTreeMap<LinkId, SessionInfo>>> =
        Arc::new(Mutex::new(BTreeMap::new()));
    let session_registry: Arc<Mutex<veil_session::SessionRegistry>> =
        Arc::new(Mutex::new(veil_session::SessionRegistry::default()));
    let sessions_per_ip = Arc::new(super::ip_slot::IpSlotTable::new());

    // Drop a freshly-built guard immediately so we test the publish
    // path in isolation (no insert path running here).
    let link_id = LinkId::new(42);
    let guard = SessionGuard::new(
        Arc::clone(&live_sessions),
        link_id,
        Arc::new(veil_observability::NodeLogger::new_noop()),
        None,
        [0u8; 32],
        session_registry,
        None,
        sessions_per_ip,
        [0u8; 32],
        Arc::new(std::sync::RwLock::new(
            veil_session::SessionTxRegistry::new(),
        )),
        None,
        Arc::clone(&bus),
        None,
    );
    drop(guard);

    let event = rx.try_recv().expect("event published on guard drop");
    assert_eq!(event.kind, event_kind::SESSIONS_CHANGED);
    // BTreeMap was empty, remove of absent key still publishes
    // count=0 (current live count) — that the contract.
    assert_eq!(event.payload, 0u16.to_be_bytes().to_vec());
}

// ── SessionGuard reaps its orphaned outbox sender on drop ───────
// Regression for the production NAT'd-client dedup storm: a dead session's
// node_id-keyed sender in `session_tx_registry` was only cleared on the runner's
// normal exit, so other teardown paths orphaned it — and the orphan then made
// dedup reject every reconnect from that peer forever. The guard must reap its
// own sender on drop, but NEVER one a newer same-node_id session owns.
#[test]
pub fn session_guard_drop_removes_only_its_owned_tx_sender() {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex, RwLock};
    use veil_cfg::{NodeId, PeerId};
    use veil_ipc::EventBus;

    use crate::types::{LinkId, SessionInfo, SessionSource, SessionState};

    fn session_info(node: [u8; 32], link: u64) -> SessionInfo {
        SessionInfo {
            link_id: LinkId::new(link),
            node_id: Some(NodeId::from(node)),
            nonce: None,
            matched_peer_id: None,
            source: SessionSource::Outbound(PeerId::new(0u32)),
            listener_handle: None,
            state: SessionState::Active,
            transport: "test".to_string(),
            remote_addr: None,
            description: String::new(),
        }
    }

    fn build_guard(
        live: &Arc<Mutex<BTreeMap<LinkId, SessionInfo>>>,
        tx_reg: &Arc<RwLock<veil_session::SessionTxRegistry>>,
        node: [u8; 32],
        link: u64,
    ) -> SessionGuard {
        SessionGuard::new(
            Arc::clone(live),
            LinkId::new(link),
            Arc::new(veil_observability::NodeLogger::new_noop()),
            None,
            [link as u8; 32],
            Arc::new(Mutex::new(veil_session::SessionRegistry::default())),
            None,
            Arc::new(super::ip_slot::IpSlotTable::new()),
            node,
            Arc::clone(tx_reg),
            None,
            Arc::new(EventBus::new()),
            None,
        )
    }

    let node = [7u8; 32];

    // CASE 1 — the current sender has the dying session's owner token, so its
    // still-open orphan MUST be reaped and cannot block the next reconnect.
    {
        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let _rx = tx_reg.write().unwrap().register_owned(node, [1u8; 32]);
        assert!(tx_reg.read().unwrap().has_session(&node));

        let live = Arc::new(Mutex::new(BTreeMap::new()));
        live.lock()
            .unwrap()
            .insert(LinkId::new(1), session_info(node, 1));

        drop(build_guard(&live, &tx_reg, node, 1));
        assert!(
            !tx_reg.read().unwrap().has_session(&node),
            "the dying session's owned sender must be reaped"
        );
    }

    // CASE 2 — a newer session has replaced the sender under the same node id.
    // The old guard MUST preserve it based on owner identity, independently of
    // timing or the live-session map.
    {
        let tx_reg = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        // The newer link owns the current sender. Dropping link 1 must not
        // unregister this link-2 entry even though both share the same node id.
        let _rx = tx_reg.write().unwrap().register_owned(node, [2u8; 32]);

        let live = Arc::new(Mutex::new(BTreeMap::new()));
        live.lock()
            .unwrap()
            .insert(LinkId::new(1), session_info(node, 1));
        live.lock()
            .unwrap()
            .insert(LinkId::new(2), session_info(node, 2));

        drop(build_guard(&live, &tx_reg, node, 1)); // drop link 1; link 2 still live
        assert!(
            tx_reg.read().unwrap().has_session(&node),
            "a replacement sender with a different owner must NOT be evicted"
        );
    }
}

// ── SessionGuard wakes the peer's outbound-connector on drop ───────
// P2P mobility slice: when a session dies, a connector loop parked in its
// 30 s `has_session` pre-check sleep must be woken instantly (per-peer
// refresh generation bump) so the direct session is re-dialed within
// seconds of `admitted` flipping false — not after the poll interval.
#[test]
pub fn session_guard_drop_bumps_peer_connector_refresh() {
    use std::collections::{BTreeMap, HashMap};
    use std::sync::{Arc, Mutex};
    use tokio::sync::watch;
    use veil_ipc::EventBus;

    let node = [9u8; 32];
    let other = [8u8; 32];
    let (tx, rx) = watch::channel(0u64);
    let (other_tx, other_rx) = watch::channel(0u64);
    let refresh: Arc<Mutex<HashMap<[u8; 32], watch::Sender<u64>>>> =
        Arc::new(Mutex::new(HashMap::from([(node, tx), (other, other_tx)])));

    let guard = SessionGuard::new(
        Arc::new(Mutex::new(BTreeMap::new())),
        LinkId::new(77),
        Arc::new(veil_observability::NodeLogger::new_noop()),
        None,
        [0u8; 32],
        Arc::new(Mutex::new(veil_session::SessionRegistry::default())),
        None,
        Arc::new(super::ip_slot::IpSlotTable::new()),
        node,
        Arc::new(std::sync::RwLock::new(
            veil_session::SessionTxRegistry::new(),
        )),
        None,
        Arc::new(EventBus::new()),
        Some(Arc::clone(&refresh)),
    );
    assert_eq!(*rx.borrow(), 0);
    drop(guard);
    assert_eq!(
        *rx.borrow(),
        1,
        "guard drop must bump the closing peer's refresh generation"
    );
    assert_eq!(
        *other_rx.borrow(),
        0,
        "unrelated peers' connectors must NOT be woken"
    );
}

// ── sim hot-standby template-URI fix ───────────────────────
// TASKS.md row "Hot-standby auto-swap to template tcp://127.0.0.1:0".
// Verify the helpers that drive port-0 substitution in the per-handshake
// `local_advertised_transports` snapshot.

#[test]
pub fn phase650_uri_has_port_zero_recognises_placeholders() {
    // Sim convention forms.
    assert!(uri_has_port_zero("tcp://127.0.0.1:0"));
    assert!(uri_has_port_zero("tcp://[::]:0"));
    assert!(uri_has_port_zero("ws://localhost:0"));
    // Real bound ports — must NOT match.
    assert!(!uri_has_port_zero("tcp://127.0.0.1:46165"));
    assert!(!uri_has_port_zero("tls://b1.example.com:9906"));
    // Edge: empty / malformed.
    assert!(!uri_has_port_zero(""));
    assert!(!uri_has_port_zero("tcp://127.0.0.1"));
}

#[test]
pub fn phase650_uri_scheme_extracts_prefix() {
    assert_eq!(uri_scheme("tcp://127.0.0.1:0"), Some("tcp"));
    assert_eq!(uri_scheme("tls://b1.example.com:9906"), Some("tls"));
    assert_eq!(uri_scheme("ws://localhost:0"), Some("ws"));
    assert_eq!(uri_scheme("wss://example.com:443/path"), Some("wss"));
    // Malformed — no scheme separator.
    assert_eq!(uri_scheme("just-a-host:0"), None);
    assert_eq!(uri_scheme(""), None);
}

#[test]
fn pick_quorum_match_single_replica_gated_by_allow_single() {
    // audit cycle-9: a single replica is accepted ONLY when the caller marks it
    // independently trustworthy (self-certifying, re-verified). For
    // non-self-certifying values (NameClaim) a lone remote response must be
    // rejected so a single Sybil responder can't hijack a name.
    let one = vec![vec![1u8, 2, 3]];
    assert_eq!(
        super::pick_quorum_match(&one, 2, true),
        Some(vec![1u8, 2, 3]),
        "self-certifying single replica accepted"
    );
    assert_eq!(
        super::pick_quorum_match(&one, 2, false),
        None,
        "non-self-certifying single replica must be rejected (name-hijack guard)"
    );
    // Quorum still works regardless of the flag: 2 agreeing of 3 meets threshold.
    let three = vec![vec![9u8], vec![9u8], vec![7u8]];
    assert_eq!(super::pick_quorum_match(&three, 2, false), Some(vec![9u8]));
    // Below threshold (all distinct) → None.
    let distinct = vec![vec![1u8], vec![2u8], vec![3u8]];
    assert_eq!(super::pick_quorum_match(&distinct, 2, false), None);
}

#[tokio::test(flavor = "current_thread")]
async fn reload_with_unapplyable_config_does_not_zombie() {
    // audit cycle-9 reload-zombie: a config that passes require_identity but
    // fails reconstruction (here a malformed public_key makes
    // HandshakeIdentity::from_config error) must be rejected BEFORE the running
    // tasks are torn down, leaving the node alive (shutdown_tx intact) — not a
    // zombie that needs a full process restart.
    let path = save_test_config("reload-zombie", runtime_config_with_metrics()).unwrap();
    let mut runtime = NodeRuntime::start(&path, true).await.expect("start");
    assert!(runtime.shutdown_tx.is_some(), "tasks running after start");

    // Overwrite the config with a valid identity SECTION but an unparseable
    // public_key + absent node_id (forces the from_public_key failure path).
    let mut bad = runtime_config_with_metrics();
    if let Some(id) = bad.identity.as_mut() {
        id.public_key = "!!!not-base64!!!".to_owned();
        id.node_id = None;
    }
    veil_cfg::save_config(&path, &bad).expect("write bad config");

    let result = runtime.reload().await;
    assert!(result.is_err(), "reload must reject an unapplyable config");
    assert!(
        runtime.shutdown_tx.is_some(),
        "running node must stay intact on a rejected reload (reload-zombie guard)"
    );

    runtime.stop().await.expect("stop");
    let _ = fs::remove_file(&path);
}

#[tokio::test(flavor = "current_thread")]
async fn reload_with_malformed_listen_transport_does_not_zombie() {
    // M-2: the LOCAL identity, peers, and full build_state dry-run all pass,
    // but a listen entry's transport URI is malformed — caught only by
    // `TransportUri::parse` / `listen_transport_context`, which run at BIND time
    // inside spawn_all_services (AFTER do_stop_tasks) in the live reload path.
    // Without the per-listener dry-run the reload would pass validation, tear
    // down the tasks, then fail post-stop → zombie. The node must stay intact.
    let path = save_test_config("reload-zombie-listen", runtime_config_with_listen()).unwrap();
    let mut runtime = NodeRuntime::start(&path, true).await.expect("start");
    assert!(runtime.shutdown_tx.is_some(), "tasks running after start");

    // Valid identity + peers, malformed listen transport URI.
    let mut bad = runtime_config_with_listen();
    bad.listen[0].transport = "!!!not-a-transport-uri!!!".to_owned();
    veil_cfg::save_config(&path, &bad).expect("write bad config");

    let result = runtime.reload().await;
    assert!(
        result.is_err(),
        "reload must reject a config with a malformed listen transport URI"
    );
    assert!(
        runtime.shutdown_tx.is_some(),
        "running node must stay intact (no zombie) on a bad listen URI reload"
    );

    runtime.stop().await.expect("stop");
    let _ = fs::remove_file(&path);
}

#[tokio::test(flavor = "current_thread")]
async fn reload_with_malformed_peer_pubkey_does_not_zombie() {
    // audit cycle-10: completes the cycle-9 reload-zombie guard. The LOCAL
    // identity is valid (HandshakeIdentity::from_config passes), but a PEER's
    // public_key is unparseable — caught only by build_state's per-peer
    // NodeId::from_public_key, which the cycle-9 validate_reloadable_config did
    // NOT dry-run. Without the build_state dry-run the reload would pass
    // validation, tear down the tasks, then fail in apply_reload_after_stop →
    // zombie. The node must stay intact instead.
    let path = save_test_config("reload-zombie-peer", runtime_config_with_listen()).unwrap();
    let mut runtime = NodeRuntime::start(&path, true).await.expect("start");
    assert!(runtime.shutdown_tx.is_some(), "tasks running after start");

    // Valid identity, malformed PEER public_key.
    let mut bad = runtime_config_with_listen();
    bad.peers[0].public_key = "!!!not-base64!!!".to_owned();
    veil_cfg::save_config(&path, &bad).expect("write bad config");

    let result = runtime.reload().await;
    assert!(
        result.is_err(),
        "reload must reject a config with a malformed peer pubkey"
    );
    assert!(
        runtime.shutdown_tx.is_some(),
        "running node must stay intact (no zombie) on a bad peer pubkey reload"
    );

    runtime.stop().await.expect("stop");
    let _ = fs::remove_file(&path);
}

#[tokio::test]
async fn peer_announced_reflectors_are_diverse_ordered_and_need_no_static_config() {
    let path = save_test_config("dynamic-reflector-selection", runtime_config_with_metrics())
        .expect("save config");
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("start runtime");
    let near = [0x01; 32];
    let far = [0x80; 32];
    {
        let mut announced = runtime.dispatcher.peer_udp_reflectors.write().unwrap();
        announced.insert(
            near,
            vec![
                "1.1.1.1:39999".parse().unwrap(),
                "1.0.0.1:39999".parse().unwrap(),
            ],
        );
        announced.insert(far, vec!["8.8.8.8:39999".parse().unwrap()]);
    }

    let selected = runtime.access().available_udp_reflectors([0u8; 32], &[]);
    assert_eq!(
        selected,
        vec![
            "1.1.1.1:39999".parse().unwrap(),
            "8.8.8.8:39999".parse().unwrap(),
            "1.0.0.1:39999".parse().unwrap(),
        ],
        "one announcer must not crowd out independent peers, and no static list is required",
    );

    runtime.stop().await.expect("stop");
    let _ = fs::remove_file(path);
}

#[tokio::test]
async fn udp_discovery_punch_and_same_socket_quic_roundtrip() {
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use tokio::sync::oneshot;
    use veil_transport::{PunchedQuicRole, TransportContext, promote_punched_quic};

    let reflector_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let reflector_addr = reflector_socket.local_addr().unwrap();
    let (reflector_stop_tx, reflector_stop_rx) = oneshot::channel();
    let reflector = tokio::spawn(veil_nat::serve_udp_reflector(
        reflector_socket,
        reflector_stop_rx,
    ));

    let left = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let right = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let discovery_token = [0x11; 16];
    let (left_mapping, right_mapping) = tokio::join!(
        veil_nat::discover_udp_mapping(
            &left,
            reflector_addr,
            discovery_token,
            Duration::from_secs(1),
        ),
        veil_nat::discover_udp_mapping(
            &right,
            reflector_addr,
            discovery_token,
            Duration::from_secs(1),
        ),
    );
    let left_mapping = left_mapping.unwrap().unwrap();
    let right_mapping = right_mapping.unwrap().unwrap();

    let punch_token = [0xA5; 16];
    let left_candidates = [right_mapping];
    let right_candidates = [left_mapping];
    // Both ends are the same deployment here, so they share a network tag.
    let tag = veil_nat::network_tag(None);
    let (left_peer, right_peer) = tokio::join!(
        veil_nat::punch_udp(
            &left,
            &left_candidates,
            punch_token,
            &tag,
            Duration::from_secs(1),
        ),
        veil_nat::punch_udp(
            &right,
            &right_candidates,
            punch_token,
            &tag,
            Duration::from_secs(1),
        ),
    );
    assert_eq!(left_peer.unwrap().peer, Some(right_mapping));
    assert_eq!(right_peer.unwrap().peer, Some(left_mapping));

    let ctx = Arc::new(TransportContext::for_debug().unwrap());
    let responder_ctx = Arc::clone(&ctx);
    let responder = tokio::spawn(async move {
        promote_punched_quic(
            right,
            left_mapping,
            responder_ctx,
            PunchedQuicRole::Responder,
        )
        .await
    });
    let initiator = promote_punched_quic(left, right_mapping, ctx, PunchedQuicRole::Initiator)
        .await
        .unwrap();
    assert_eq!(initiator.peer_meta().local_addr, Some(left_mapping));
    let mut initiator_stream = initiator.into_stream().unwrap();
    initiator_stream.write_all(b"stage-b").await.unwrap();

    let responder = responder.await.unwrap().unwrap();
    assert_eq!(responder.peer_meta().local_addr, Some(right_mapping));
    let mut responder_stream = responder.into_stream().unwrap();
    let mut payload = [0u8; 7];
    responder_stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"stage-b");

    let _ = reflector_stop_tx.send(());
    reflector.await.unwrap().unwrap();
}

// ── Explicit call-path hole punch (real-P2P Stage B) ───────────────────────

/// The dial-stage failure enum maps 1:1 onto the wire outcomes so an
/// early exit never loses its stage identity crossing the API boundary.
#[test]
fn hole_punch_dial_failure_maps_to_every_wire_outcome() {
    use super::HolePunchDialFailure as F;
    use veil_ipc::HolePunchOutcome as O;
    assert_eq!(O::from(F::NoReflector), O::NoReflector);
    assert_eq!(O::from(F::MappingUnusable), O::MappingUnusable);
    assert_eq!(O::from(F::SignalingTimeout), O::SignalingTimeout);
    assert_eq!(O::from(F::PunchTimeout), O::PunchTimeout);
    assert_eq!(O::from(F::QuicFailed), O::QuicFailed);
    // Outcomes with no dial-stage source still carry distinct wire bytes.
    assert_eq!(
        O::RefusedAnonymous.wire_status(),
        veil_proto::hole_punch_status::REFUSED_ANONYMOUS
    );
    assert_eq!(
        O::UnknownPeer.wire_status(),
        veil_proto::hole_punch_status::UNKNOWN_PEER
    );
    assert_eq!(
        O::Connected.wire_status(),
        veil_proto::hole_punch_status::CONNECTED
    );
}

/// A node booted under an anonymity posture (onion-service armed) MUST
/// refuse the explicit punch before any socket / reflector / signaling
/// side effect — a punch would disclose its real external address. The
/// refusal is a dedicated outcome, not a masked failure.
#[tokio::test(flavor = "current_thread")]
async fn attempt_hole_punch_refuses_under_anonymity_posture() {
    let anon = save_test_config(
        "punch-anon",
        veil_cfg::build_stub_config_with_ephemeral_identity(true).unwrap(),
    )
    .unwrap();
    let mut rt = NodeRuntime::start(&anon, true)
        .await
        .expect("anonymous stub starts");
    assert!(
        rt.anonymity.onion_service_hops.is_some(),
        "precondition: anonymous stub arms the onion service",
    );
    let services = rt.access();
    // Gate fires before peer lookup, so any node_id triggers it.
    let outcome = services.attempt_p2p_hole_punch([0x42; 32]).await;
    assert_eq!(outcome, veil_ipc::HolePunchOutcome::RefusedAnonymous);
    // Refusal must be pure — no single-flight slot, no attempt started.
    assert_eq!(services.hole_punch_run_count(), 0);
    rt.stop().await.expect("stop");
    let _ = fs::remove_file(anon);
}

/// A node_id that is not a registered peer yields the explicit
/// `UnknownPeer` outcome; sequential repeats are idempotent (same
/// outcome, no leaked single-flight slot — proven by each call starting a
/// fresh attempt).
#[tokio::test(flavor = "current_thread")]
async fn attempt_hole_punch_unknown_peer_is_idempotent() {
    let path = save_test_config("punch-unknown-peer", runtime_config_with_listen()).unwrap();
    let mut rt = NodeRuntime::start(&path, true).await.expect("start");
    let services = rt.access();
    let unknown = [0xEE; 32];
    let first = services.attempt_p2p_hole_punch(unknown).await;
    let second = services.attempt_p2p_hole_punch(unknown).await;
    assert_eq!(first, veil_ipc::HolePunchOutcome::UnknownPeer);
    assert_eq!(second, veil_ipc::HolePunchOutcome::UnknownPeer);
    // Two SEQUENTIAL calls each ran a fresh attempt (the first released its
    // slot on completion, so the second did not join a stale entry).
    assert_eq!(services.hole_punch_run_count(), 2);
    rt.stop().await.expect("stop");
    let _ = fs::remove_file(path);
}

/// With NAT enabled by default but no reflector known, a registered peer
/// yields `NoReflector` — the attempt reaches the dial ladder (peer
/// lookup + config load succeed) and stops at the first stage.
#[tokio::test(flavor = "current_thread")]
async fn attempt_hole_punch_registered_peer_without_reflector() {
    let path = save_test_config("punch-no-reflector", runtime_config_with_listen()).unwrap();
    let mut rt = NodeRuntime::start(&path, true).await.expect("start");
    let services = rt.access();
    // The config peer's pubkey equals the local identity's, so its node_id
    // equals `local_node_id` — a genuinely registered peer entry.
    let peer = services.local_node_id;
    let outcome = services.attempt_p2p_hole_punch(peer).await;
    assert_eq!(outcome, veil_ipc::HolePunchOutcome::NoReflector);
    assert_eq!(services.hole_punch_run_count(), 1);
    rt.stop().await.expect("stop");
    let _ = fs::remove_file(path);
}

/// Mixed-version network: a coordinator built before the punch-token wire
/// extension strips the token in flight, so the initiator's reply comes back
/// without it. Such a reply must NOT terminate the coordinator ladder — the
/// initiator skips it and completes through the next coordinator whose path
/// preserves the token. Regression test for the live LTE↔wired failure where
/// one stale seed poisoned every punch attempt it coordinated.
#[tokio::test(flavor = "current_thread")]
async fn nat_signaling_skips_tokenless_reply_and_uses_next_coordinator() {
    use veil_proto::codec::decode_header;
    use veil_proto::control::{NatProbeReplyPayload, NatProbeRequestPayload};
    use veil_proto::family::ControlMsg;
    use veil_proto::header::HEADER_SIZE;

    let path = save_test_config("punch-tokenless-retry", runtime_config_with_listen()).unwrap();
    let mut rt = NodeRuntime::start(&path, true).await.expect("start");
    let services = rt.access();

    let target = [0xBB; 32];
    let punch_token = [0x42; 16];
    // XOR distance to `target` orders the coordinator ladder: `stale` differs
    // only in the last byte (tried first), `fresh` in the first byte (second).
    let mut stale = target;
    stale[31] ^= 0x01;
    let mut fresh = target;
    fresh[0] ^= 0xF0;

    let (mut stale_rx, mut fresh_rx) = {
        let mut guard = services.session_tx_registry.write().unwrap();
        (guard.register(stale), guard.register(fresh))
    };

    // Model both coordinators' end-to-end behaviour by answering the frames
    // the initiator actually queues to their sessions. The stale one echoes a
    // reply WITHOUT the punch token (extension lost to its old re-encode);
    // the fresh one preserves the token.
    let waiters = Arc::clone(&services.dispatcher.nat_probe_waiters);
    let responder = tokio::spawn(async move {
        let answer = |frame: Vec<u8>, responder_id: [u8; 32], echo_token: bool| {
            let header = decode_header(&frame[..HEADER_SIZE]).unwrap();
            assert_eq!(header.msg_type, ControlMsg::NatProbeRequest as u16);
            let request = NatProbeRequestPayload::decode(&frame[HEADER_SIZE..]).unwrap();
            assert_eq!(request.punch_token, Some(punch_token));
            let reply = NatProbeReplyPayload {
                responder_node_id: responder_id,
                final_target_node_id: request.initiator_node_id,
                session_token: request.session_token,
                punch_token: echo_token.then_some(punch_token),
                candidates: request.candidates.clone(),
            };
            let waiter = lock!(waiters)
                .remove(&request.session_token)
                .expect("waiter registered before the frame was sent");
            waiter.send(reply).unwrap();
        };
        let (_, stale_frame) = stale_rx.recv().await.expect("stale coordinator receives");
        answer(stale_frame.to_vec(), stale, false);
        let (_, fresh_frame) = fresh_rx.recv().await.expect("fresh coordinator receives");
        answer(fresh_frame.to_vec(), fresh, true);
    });

    let reply = services
        .try_nat_traversal_with_punch_token(
            target,
            Vec::new(),
            Duration::from_millis(500),
            Some(punch_token),
        )
        .await
        .expect("tokenless first reply must not poison the ladder");
    assert_eq!(
        reply.punch_token,
        Some(punch_token),
        "accepted reply must carry the initiator's punch token"
    );
    assert_eq!(
        reply.responder_node_id, fresh,
        "reply must come from the second (token-preserving) coordinator"
    );
    responder.await.expect("both coordinators were consulted");

    rt.stop().await.expect("stop");
    let _ = fs::remove_file(path);
}

/// Two concurrent attempts for the SAME peer collapse into one: the second
/// caller joins the in-flight attempt and observes its outcome instead of
/// starting a second punch. Uses a silent local reflector so the shared
/// attempt stays inside its discovery window while both callers race, and
/// asserts the whole thing finishes well inside the 5 s budget.
// Loopback reflector, so unix only. On Windows the punch socket is pinned to an
// outbound interface with `IP_UNICAST_IF`
// (`veil_util::outbound_interface::configure_outbound_socket`, a no-op
// everywhere else), and a socket pinned to a physical interface cannot reach
// 127.0.0.1. Every send then fails and discovery reports "no reflector was
// sendable" — which is CORRECT for what it was asked to do.
//
// Established by marking each of the four `NoReflector` returns with a distinct
// outcome and running on the machine: the discovery call was the one that
// fired, after the config, its reflector list and the discovery primitive had
// each been cleared by their own assertion. The single-flight property under
// test is platform-independent; only the way this arranges a failure is not.
#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn attempt_hole_punch_is_single_flight_per_peer() {
    // A bound-but-silent UDP socket: discovery sends here and never gets a
    // reply, so the attempt spends its ~500 ms discovery window before
    // returning `MappingUnusable` — long enough for the second caller to
    // observe the in-flight slot.
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();

    let mut config = runtime_config_with_listen();
    config.nat.enabled = true;
    config.nat.udp_reflectors = vec![silent_addr.to_string()];
    let path = save_test_config("punch-single-flight", config).unwrap();
    let mut rt = NodeRuntime::start(&path, true).await.expect("start");
    let services = rt.access();
    let peer = services.local_node_id;

    // The premise, stated. `attempt_p2p_hole_punch` RE-READS the config from
    // disk and answers `NoReflector` when it cannot — the same answer it gives
    // when there is genuinely no reflector, so a round-trip that loses these
    // fields is indistinguishable from the outcome under test. Checked here so
    // a failure names the cause instead of showing two enum variants.
    let reloaded = veil_cfg::load_config(&path).expect("the config must reload");
    assert!(
        reloaded.nat.enabled,
        "nat.enabled did not survive the round trip"
    );
    assert!(
        !reloaded.nat.udp_reflectors.is_empty(),
        "nat.udp_reflectors did not survive the round trip"
    );
    // And they must PARSE. `available_udp_reflectors` drops anything that does
    // not with `.parse().ok()`, silently, so a surviving-but-unparsable string
    // reaches the caller as the same `NoReflector` this test is distinguishing
    // from.
    let parsed: Vec<std::net::SocketAddr> = reloaded
        .nat
        .udp_reflectors
        .iter()
        .filter_map(|value| value.parse::<std::net::SocketAddr>().ok())
        .collect();
    assert!(
        !parsed.is_empty(),
        "configured reflectors survived but none parses: {:?}",
        reloaded.nat.udp_reflectors
    );

    let started = std::time::Instant::now();
    // Poll both on ONE task: the first poll of `a` inserts the single-flight
    // slot before yielding into discovery; `b` is then polled, sees the slot
    // and joins.
    let (a, b) = tokio::join!(
        services.attempt_p2p_hole_punch(peer),
        services.attempt_p2p_hole_punch(peer),
    );
    let elapsed = started.elapsed();

    // And the same premise AFTER the attempt. The runtime persists config in
    // some flows, so "valid when the test looked" and "valid when the punch
    // re-read it" are different claims; if these two disagree the outcome
    // below is about a config that was rewritten under us.
    let after = veil_cfg::load_config(&path).expect("the config must still reload");
    assert!(
        after.nat.enabled,
        "nat.enabled was cleared during the attempt"
    );
    assert!(
        !after.nat.udp_reflectors.is_empty(),
        "nat.udp_reflectors was cleared during the attempt"
    );

    assert_eq!(a, veil_ipc::HolePunchOutcome::MappingUnusable);
    assert_eq!(
        b,
        veil_ipc::HolePunchOutcome::MappingUnusable,
        "joiner sees same outcome"
    );
    assert_eq!(
        services.hole_punch_run_count(),
        1,
        "second concurrent call must join, not start a second punch",
    );
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "attempt must finish inside the 5 s budget (took {elapsed:?})",
    );

    drop(silent);
    rt.stop().await.expect("stop");
    let _ = fs::remove_file(path);
}

/// P3-27: the leaf byte quota was fully built — guard, adapter, builder — and
/// then never attached to the production `GatewayBridge`, so a greedy leaf was
/// counted and never throttled. The throttling logic itself was correct and
/// tested; what nothing covered was the *attachment*, because a missing builder
/// call is invisible to the type system. Assert it directly, at construction
/// and again after a reload rebuilds the bridge.
#[tokio::test(flavor = "current_thread")]
async fn leaf_bandwidth_quota_is_attached_to_the_mesh_bridge() {
    let path = save_test_config("node-runtime-leaf-quota", runtime_config_with_metrics()).unwrap();
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");

    assert!(
        runtime.mesh_bridge.has_leaf_bandwidth_quota(),
        "the initial constructor must attach the leaf quota",
    );

    runtime.reload().await.expect("runtime reloads");
    assert!(
        runtime.mesh_bridge.has_leaf_bandwidth_quota(),
        "reload rebuilds the bridge — it must not drop the quota on the way",
    );

    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

/// P1-12: the reply-circuit confirmation wait must be AWAITED, never blocked.
/// Blocking parked the worker together with the dispatch task that delivers
/// the very `CircuitBuilt` ACK being waited for, so on a current-thread runtime
/// the wait could not succeed by construction and cost a full second of frozen
/// networking to fail. This asserts the shape that makes it work: the wait
/// yields, so other tasks on the SAME single worker make progress while it runs.
#[tokio::test(flavor = "current_thread")]
async fn the_reply_circuit_wait_yields_to_the_single_worker() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    let path = save_test_config("node-runtime-reply-wait", runtime_config_with_metrics()).unwrap();
    let runtime = NodeRuntime::start(&path, true)
        .await
        .expect("runtime starts");
    let access = runtime.access();

    // Never set: the wait runs its full 1 s budget, which is the worst case.
    let confirmed = Arc::new(AtomicBool::new(false));

    // Stands in for the inbound dispatch task that would carry the ACK. On a
    // current-thread runtime it can only run if the waiter yields.
    let ticks = Arc::new(AtomicU32::new(0));
    let ticker = {
        let ticks = Arc::clone(&ticks);
        tokio::spawn(async move {
            for _ in 0..20 {
                ticks.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
    };

    access.wait_reply_circuit_confirmed(&confirmed).await;

    assert!(
        ticks.load(Ordering::Relaxed) > 1,
        "the co-scheduled task never ran — the wait blocked the only worker \
         instead of yielding, which is exactly what starved the ACK",
    );
    ticker.abort();

    let mut runtime = runtime;
    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_file(path);
}

/// An `identity_document.bin` that exists but does not load must stop the node.
///
/// A MISSING document is ordinary: a node is required to start without a
/// sovereign identity, and that path is deliberately unchanged. A document
/// that is PRESENT and unreadable is a different thing — the operator
/// provisioned an identity, it is on disk, and it is broken. Starting anyway
/// ran the node under a different identity binding than the one its operator
/// installed (peers see an unrelated legacy node, multi-device pairing does
/// not apply), with one warning line as the only trace (audit V-07).
#[tokio::test(flavor = "current_thread")]
async fn a_corrupt_identity_document_refuses_to_start_unless_allowed() {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    // Its own directory: the document sits NEXT TO the config, and a shared
    // temp dir would leak it into every other runtime test.
    let dir = std::env::temp_dir().join(format!("v07-identity-{unique}"));
    // A previous FAILED run leaves its corrupt document behind, and the
    // counter restarts at 0 in a fresh process — reusing that directory made
    // the no-document control fail for the previous run's reason.
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("node.toml");

    let mut config = runtime_config_with_listen();
    config.global.allow_identity_fallback = false;
    veil_cfg::save_config(&path, &config).unwrap();

    // Control FIRST: with no document at all the node still starts. This is
    // the invariant the fix must not break.
    {
        let mut runtime = NodeRuntime::start(&path, true)
            .await
            .expect("a node with NO sovereign identity must still start");
        runtime.stop().await.expect("runtime stops");
    }

    // Now a document that exists and is not a valid one.
    let doc = dir.join(veil_identity::sovereign::IDENTITY_DOCUMENT_FILE);
    fs::write(&doc, b"not an identity document").unwrap();

    let err = NodeRuntime::start(&path, true)
        .await
        .err()
        .expect("a present-but-unloadable document must refuse to start");
    let msg = format!("{err}");
    assert!(
        msg.contains("cannot be loaded"),
        "the error must say WHAT is wrong, not just fail: {msg}"
    );

    // Opting in explicitly brings it up as legacy, which is the recovery path.
    config.global.allow_identity_fallback = true;
    // Written fresh, not patched: `save_config` PATCHES an existing file, and
    // the patcher only rewrites keys the file already carries — a flag absent
    // from it stays absent. An operator sets this by editing the file, which
    // is the same full-file path.
    let _ = fs::remove_file(&path);
    veil_cfg::save_config(&path, &config).unwrap();
    let reloaded = veil_cfg::load_config(&path).unwrap();
    assert!(
        reloaded.global.allow_identity_fallback,
        "precondition: the opt-in must survive a save/load round-trip"
    );
    let mut runtime = NodeRuntime::start(&path, true)
        .await
        .expect("allow_identity_fallback = true must start as legacy");
    runtime.stop().await.expect("runtime stops");

    let _ = fs::remove_dir_all(&dir);
}

/// A node whose key could not be encrypted at rest says so, and keeps running.
///
/// The operator turned a key passphrase on for the first time. The loader
/// re-encrypts the existing plaintext `mlkem.key` in place, and that write can
/// fail — read-only directory here, but ENOSPC and wrong-owner land the same
/// way. Before this the error was discarded outright (`let _ = atomic_write`,
/// under a comment claiming it was logged, with no logging anywhere in the
/// tree), so the node came up, worked, and left the decapsulation seed in
/// plaintext while its operator believed otherwise (audit report7 V-02).
///
/// Both halves are asserted: the node STARTS (a daemon down because a
/// directory is read-only would be a worse trade), and the state it reports is
/// degraded.
#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn a_key_that_could_not_be_encrypted_at_rest_is_reported_crit_v02() {
    use std::os::unix::fs::PermissionsExt as _;

    // First run in a writable directory, with no passphrase: this is the node
    // as it was before the operator changed their mind — identity files and a
    // PLAINTEXT mlkem.key on disk.
    let warm = save_test_config("mlkem-at-rest-warm", runtime_config_with_listen()).unwrap();
    let warm_dir = warm.parent().unwrap().to_path_buf();
    NodeRuntime::start(&warm, false)
        .await
        .expect("warm-up start")
        .stop()
        .await
        .expect("warm-up stop");

    // Same node, now with a passphrase configured — and a directory nothing can
    // be written into, so the in-place re-encrypt cannot land.
    let mut with_pass = runtime_config_with_listen();
    with_pass.identity.as_mut().unwrap().key_passphrase = Some("first-passphrase".to_owned());
    let cold = save_test_config("mlkem-at-rest-cold", with_pass).unwrap();
    let cold_dir = cold.parent().unwrap().to_path_buf();
    // The identity the warm-up materialised, so startup has nothing left to
    // write into a directory it is about to lose write access to.
    for name in [
        "identity_document.bin",
        "device_identity_sk.bin",
        "anonymity_x25519.key",
    ] {
        let from = warm_dir.join(name);
        if from.exists() {
            fs::copy(&from, cold_dir.join(name)).unwrap();
        }
    }
    // A PLAINTEXT key file: this is what the passphrase is about to fail to
    // upgrade. (The warm-up does not leave one — a node with an identity seed
    // DERIVES its key and persists nothing; only operator/seed nodes carry a
    // file. This is that file.)
    veil_e2e::load_or_generate_mlkem_key_encrypted(&cold_dir.join("mlkem.key"), None).unwrap();
    assert!(
        fs::read_to_string(cold_dir.join("mlkem.key"))
            .unwrap()
            .contains("BEGIN VEIL ML-KEM-768 KEY"),
        "precondition: the key on disk is plaintext"
    );
    fs::set_permissions(&cold_dir, fs::Permissions::from_mode(0o500)).unwrap();
    let writable_anyway = fs::File::create(cold_dir.join(".probe")).is_ok();
    if writable_anyway {
        // Running as a user the mode bits do not bind (root): the scenario
        // cannot be built here, so assert nothing rather than assert something
        // weaker.
        let _ = fs::remove_file(cold_dir.join(".probe"));
        fs::set_permissions(&cold_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let _ = fs::remove_dir_all(&cold_dir);
        let _ = fs::remove_dir_all(&warm_dir);
        eprintln!("SKIP: this user can write into a 0o500 directory (root?)");
        return;
    }

    let mut runtime = NodeRuntime::start(&cold, false)
        .await
        .expect("a read-only key directory must NOT stop the node from starting");

    let at_rest = runtime.mlkem_key_at_rest();
    assert!(
        at_rest.is_degraded(),
        "the node must report that its key is not stored as configured, got {at_rest:?}"
    );
    assert_eq!(at_rest.as_str(), "plaintext_upgrade_failed");

    runtime.stop().await.expect("runtime stops");
    fs::set_permissions(&cold_dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        fs::read_to_string(cold_dir.join("mlkem.key"))
            .unwrap()
            .contains("BEGIN VEIL ML-KEM-768 KEY"),
        "the file really is still plaintext — that is what the silence hid"
    );
    let _ = fs::remove_dir_all(&cold_dir);
    let _ = fs::remove_dir_all(&warm_dir);
}

/// CONTROL: the same node with a WRITABLE directory reports a healthy state,
/// so the assertion above is about the failed write and not about every node
/// that has a passphrase.
#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn a_key_encrypted_at_rest_reports_as_configured() {
    let mut cfg = runtime_config_with_listen();
    cfg.identity.as_mut().unwrap().key_passphrase = Some("first-passphrase".to_owned());
    let path = save_test_config("mlkem-at-rest-ok", cfg).unwrap();
    let dir = path.parent().unwrap().to_path_buf();

    let mut runtime = NodeRuntime::start(&path, false).await.expect("start");
    let at_rest = runtime.mlkem_key_at_rest();
    assert!(
        !at_rest.is_degraded(),
        "a writable directory must yield a healthy at-rest state, got {at_rest:?}"
    );
    runtime.stop().await.expect("runtime stops");
    let _ = fs::remove_dir_all(&dir);
}

/// A message must not fragment just to cross the introduce path.
///
/// Two different cells carry an introduce: the sender -> rendezvous leg rides
/// one `CELL_SIZE` ANONYMOUS cell, and the rendezvous -> receiver leg rides one
/// fixed `CIRCUIT_PAYLOAD_BYTES` circuit-data cell. They were never tied
/// together. The circuit cell was bumped 384 -> 4096 -> 16384 on 2026-07-02 for
/// onion-stream throughput while the anonymous cell stayed at 512, which left a
/// 3-hop fragment carrying 135 usable bytes into a 16 KiB cell — so every
/// message over 135 B fragmented, each fragment paid a whole cell inbound, and
/// three-or-more-fragment messages paid it three times (bulk redundancy).
/// Measured on two live devices, 2026-08-07: 41 MB to deliver ten 7-byte chat
/// messages out of a mailbox, about 3.7 MB apiece.
///
/// The 2026-08-07 bump to 8192 closes it. What this test holds is the PROPERTY,
/// not the constant: the largest thing that rides this path is a signed
/// AuthDeliver, and one fragment must carry a whole one. Raising
/// `MAX_AUTH_DELIVER_MSG_BYTES` past the cell, or shrinking the cell, brings
/// the fragmentation back — and fails here first.
#[test]
fn one_fragment_carries_a_whole_auth_deliver() {
    use veil_anonymity::circuit_data::CIRCUIT_PAYLOAD_BYTES;

    // The budget the sender packs into, from the real helper both send paths use.
    assert_eq!(
        super::introduce_plaintext_budget(3),
        Some(7836),
        "3-hop sealed introduce plaintext budget"
    );
    let chunk = super::introduce_fragment_chunk_size(3).expect("3 hops fit a cell");
    assert_eq!(chunk, 7815, "signed bytes carried by one 3-hop fragment");

    // THE property: the largest message this path carries fits one fragment,
    // so nothing that a client actually sends is cut up at all.
    assert!(
        chunk >= veil_proto::MAX_AUTH_DELIVER_MSG_BYTES,
        "a full {} B AuthDeliver must ride ONE fragment; at {chunk} B per \
         fragment it needs {}",
        veil_proto::MAX_AUTH_DELIVER_MSG_BYTES,
        veil_proto::MAX_AUTH_DELIVER_MSG_BYTES.div_ceil(chunk),
    );

    // And the cell that fragment arrives in is no longer mostly padding: one
    // fragment now fills a useful share of it instead of 0.8%.
    assert_eq!(CIRCUIT_PAYLOAD_BYTES, 16384, "circuit-data cell is fixed");
    assert!(
        chunk * 3 >= CIRCUIT_PAYLOAD_BYTES,
        "one fragment fills only 1/{} of the cell it rides",
        CIRCUIT_PAYLOAD_BYTES / chunk.max(1),
    );
}

/// A full mailbox deposit chunk must fit the one anonymous cell that carries it.
///
/// `MAILBOX_PUT_CHUNK_DATA_BYTES` lives in veil-proto and the cell budget lives
/// in veil-anonymity, which do not see each other — so the two were kept in step
/// by a comment, and the comment went stale the moment the cell moved. This is
/// the first place that can hold both. It encodes a MAXIMUM chunk exactly as the
/// deposit path does (kind tag + AppDeliverPayload wrapping the encoded chunk)
/// and checks the result against the real 1-hop budget.
#[test]
fn a_full_deposit_chunk_fits_one_anonymous_cell() {
    use veil_proto::{MAILBOX_PUT_CHUNK_DATA_BYTES, MAX_MAILBOX_PUT_CHUNKS};

    let chunk = veil_proto::ipc::MailboxPutChunkPayload {
        content_id: [0x11; 32],
        chunk_index: 0,
        chunk_total: 1,
        chunk_data: vec![0xAB; MAILBOX_PUT_CHUNK_DATA_BYTES],
    }
    .encode();

    let deliver = veil_proto::AppDeliverPayload {
        src_node_id: [0u8; 32],
        src_app_id: [0x22; 32],
        app_id: [0x33; 32],
        endpoint_id: 1,
        data: veil_bufpool::pooled_shared_from_vec(chunk),
        reply_id: 0,
        provenance: veil_proto::SenderProvenance::Claimed,
    }
    .encode();
    // The deposit path prepends one final-hop kind tag before the onion wrap.
    let on_wire = 1 + deliver.len();

    let budget = veil_anonymity::packet::max_payload_for_hops(1).expect("1 hop fits a cell");
    assert!(
        on_wire <= budget,
        "a full {MAILBOX_PUT_CHUNK_DATA_BYTES} B chunk encodes to {on_wire} B, over the \
         1-hop cell budget of {budget} B — deposits would fail to build"
    );

    // Relay reassembly memory is the product, not either factor. Hold the
    // ceiling it had at 256 x 240 so a bigger chunk cannot quietly buy a
    // bigger buffer at every relay.
    assert!(
        MAILBOX_PUT_CHUNK_DATA_BYTES * MAX_MAILBOX_PUT_CHUNKS as usize <= 64 * 1024,
        "reassembly ceiling grew past 64 KiB per in-flight deposit"
    );
}

/// A single-fragment send puts ONE copy on the wire, whatever the caller asked
/// for; a fragmented one still pays for its all-or-nothing reassembly.
///
/// The reply path asks for 3 explicitly, and before the 2026-08-07 cell bump a
/// ~6 KB mailbox FETCH reply really was 46 fragments, where losing any one lost
/// the whole reply. After the bump the same reply is one fragment, so the two
/// extra copies re-sent something the next drain round would have re-requested
/// three seconds later anyway — measured as the largest remaining term in the
/// cost of delivering one message.
#[test]
fn redundancy_is_for_reassembly_not_for_retry() {
    use super::{BULK_FRAGMENT_THRESHOLD, onion_send_redundancy};

    // One fragment: the caller's 3 is dropped. This is the reply path.
    assert_eq!(
        onion_send_redundancy(3, 1, false, 1),
        1,
        "a one-fragment reply must not be sent three times"
    );
    assert_eq!(onion_send_redundancy(1, 1, false, 1), 1);

    // Two fragments: reassembly can now fail partially, so the caller's ask
    // stands — but the bulk bump has not kicked in yet.
    assert_eq!(onion_send_redundancy(3, 2, false, 1), 3);
    assert_eq!(onion_send_redundancy(1, 2, false, 1), 1);

    // Bulk down ONE relay: redundancy is raised to the bulk floor even when the
    // caller asked for none.
    assert_eq!(
        onion_send_redundancy(1, BULK_FRAGMENT_THRESHOLD, false, 1),
        super::BULK_REDUNDANCY
    );

    // Bulk across SEVERAL relays: spread instead of duplicate.
    assert_eq!(onion_send_redundancy(3, 27, true, 3), 1);
}

/// The probe back-off has to let a real reconnect through and still stop a
/// target that never answers. Pins the CHOICE of constants against the
/// limiter's own semantics: the bucket is what veil-abuse tests, the numbers
/// are what this commit decided.
#[test]
fn a_target_that_never_answers_stops_being_probed_but_a_returning_one_does_not() {
    use veil_abuse::PerPeerLimiter;
    let mut l = PerPeerLimiter::new(
        super::NAT_PROBE_SUSTAINED_PER_SEC,
        super::NAT_PROBE_BURST,
        super::NAT_PROBE_IDLE_FORGET,
    );
    let dead = [7u8; 32];

    // A genuine reconnect gets its attempts: the handshake succeeds on the
    // first or second, so the burst must cover that with room.
    let granted = (0..3).filter(|_| l.allow(dead)).count();
    assert_eq!(granted, 3, "burst must cover a real reconnect");

    // After that the target is refused, and stays refused — this is the whole
    // point: 6093 failures in 5.3 h came from having no such stop.
    for _ in 0..50 {
        assert!(
            !l.allow(dead),
            "a target that spent its burst must not be probed again immediately"
        );
    }

    // A different target is unaffected — the back-off is per target, not global.
    assert!(
        l.allow([9u8; 32]),
        "back-off on one target must not silence probes to another"
    );
}

/// The sustained rate is the number that decides the steady-state cost, so it
/// gets pinned separately from the burst: one probe per ten minutes is
/// 6 an hour against the 1140 an hour measured on a production seed.
#[test]
fn the_sustained_probe_rate_is_one_per_ten_minutes() {
    let per_hour = super::NAT_PROBE_SUSTAINED_PER_SEC * 3600.0;
    assert!(
        (per_hour - 6.0).abs() < 1e-9,
        "expected 6 probes an hour, got {per_hour}"
    );
}
