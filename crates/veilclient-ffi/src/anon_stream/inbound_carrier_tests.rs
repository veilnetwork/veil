//! Cold inbound setup without an eligible onion first hop.
use super::*;
use veil_anonymity::rendezvous::rendezvous_ad_dht_key_at;

/// A cold receive hub has nothing to register through when every connected
/// peer explicitly declines onion transit. Do not spend eight self-ad walks
/// on a path that cannot be built. Unknown/newly eligible peers must still
/// enter ordinary discovery, without an inherited negative cache.
#[tokio::test(flavor = "current_thread")]
async fn inbound_skips_self_lookup_when_all_connected_peers_decline_circuits() {
    const CHILD: &str = "VEIL_TEST_INBOUND_CARRIER_CAPS_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "anon_stream::inbound_carrier_tests::inbound_skips_self_lookup_when_all_connected_peers_decline_circuits", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    // Isolated child: a compiled-in test identity cannot collide with another
    // fixture in the embedded-services registry. No network peers/discovery.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.toml");
    let mut config = veil_cfg::build_stub_config_with_ephemeral_identity(false).unwrap();
    config.peers.clear();
    config.global.builtin_seed_policy = veil_cfg::BuiltinSeedPolicy::Never;
    config.global.meeting_points = veil_cfg::MeetingPoints::Only(Vec::new());
    veil_cfg::save_config(&path, &config).unwrap();
    let mut runtime = veil_node_runtime::NodeRuntime::start(&path, true)
        .await
        .unwrap();
    let services = runtime.access();
    let peer = [0x93; 32];
    let mut outbox = services.session_tx_registry.write().unwrap().register(peer);
    let me = services.local_node_id();
    let key = services.onion_stream_registration_keypair();
    let epoch = AtomicU64::new(0);
    let group = veil_node_runtime::LocalCircuitPathGroup::default();
    let self_slots: Vec<_> = (0..8).map(|i| rendezvous_ad_dht_key_at(&me, i)).collect();
    let mut observations = Vec::new();
    for flags in [
        Some(0),
        Some(veil_proto::session::cap_flags::ANONYMITY_RELAY),
        None,
    ] {
        {
            let mut caps = services.dispatcher.crypto.peer_cap_flags.write().unwrap();
            match flags {
                Some(flags) => {
                    caps.insert(peer, flags);
                }
                None => {
                    caps.remove(&peer);
                }
            }
        }
        let mut open = Box::pin(open_inbound_circuits(
            &services,
            me,
            &key,
            &epoch,
            CircuitMode::PublishedRendezvous,
            &group,
            None,
        ));
        let status = futures::poll!(open.as_mut());
        let declined_without_wait = matches!(
            status,
            std::task::Poll::Ready(Err(veil_types::AnonOnionSendError::NoRelays))
        );
        let pending = status.is_pending();
        drop(open);
        let mut queries = 0;
        while let Ok((_, frame)) = outbox.try_recv() {
            if let Some(body) = frame.get(veil_proto::HEADER_SIZE..)
                && let Ok(q) = veil_proto::routing::RecursiveQueryPayload::decode(body)
                && q.query_type == veil_proto::routing::recursive_query_type::FIND_VALUE
                && self_slots.contains(&q.target_key)
            {
                queries += 1;
            }
        }
        observations.push((flags, declined_without_wait, pending, queries));
        assert!(
            services
                .dispatcher
                .pending_recursive
                .lock()
                .unwrap()
                .is_empty()
        );
    }
    runtime.stop().await.unwrap();
    let (_, declined, pending, queries) = observations[0];
    assert!(
        declined && !pending && queries == 0,
        "explicitly incapable peers must not trigger a self-ad lookup: {observations:?}"
    );
    for (_, declined, pending, queries) in observations.into_iter().skip(1) {
        assert!(
            !declined && pending && queries > 0,
            "newly capable or unknown peer must re-enter discovery immediately"
        );
    }
}
