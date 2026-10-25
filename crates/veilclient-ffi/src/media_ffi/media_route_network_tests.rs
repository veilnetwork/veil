//! Real node runtimes, builders, relay dispatchers and native media pumps.
//! Most fixtures join session outboxes in memory. The real-obfs4 variant uses
//! actual authenticated sessions, independent children and encrypted splicing.
//! The optional codecs module adds synthetic PCM/decoded-video observations;
//! none of these fixtures establishes physical acoustic quality.
use super::*;
use crate::anon_stream::MediaRoutes;
use crate::media::{LocalMediaPlane, cipher_for_test};
use base64::Engine;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use veil_node_runtime::{NodeRuntime, NodeServices};
use veil_proto::{HEADER_SIZE, family::FrameFamily};

const STAND_SERVICE_ALLOWANCE: u64 = 1 << 40;

#[cfg(unix)]
mod codecs {
    use super::*;
    include!("media_route_codec_tests.rs");
}

struct Stand {
    _dirs: Vec<tempfile::TempDir>,
    nodes: Vec<NodeRuntime>,
    services: Vec<NodeServices>,
    pipes: Vec<tokio::task::JoinHandle<()>>,
    delivered_cells: Arc<Mutex<HashMap<(usize, u32), usize>>>,
    file_loss_budget: Arc<std::sync::atomic::AtomicUsize>,
    file_dropped: Arc<std::sync::atomic::AtomicUsize>,
    file_cells: Arc<std::sync::atomic::AtomicUsize>,
    reliable_route_probes: Arc<std::sync::atomic::AtomicUsize>,
    hold_reliable_route_probes: Arc<std::sync::atomic::AtomicBool>,
    held_route_probes: Arc<std::sync::atomic::AtomicUsize>,
    hold_primary_datagrams: Arc<std::sync::atomic::AtomicBool>,
    cut_link: Arc<Mutex<Option<(usize, usize)>>>,
    cut_link_frames: Arc<std::sync::atomic::AtomicUsize>,
}
impl Drop for Stand {
    fn drop(&mut self) {
        for pipe in &self.pipes {
            pipe.abort();
        }
    }
}
impl Stand {
    async fn new() -> Self {
        Self::with_middle_count(1).await
    }
    async fn with_middle_count(middle_count: usize) -> Self {
        Self::with_links(middle_count, false).await
    }
    async fn with_links(middle_count: usize, real_obfs4: bool) -> Self {
        assert!(middle_count >= 1);
        let mut s = Self {
            _dirs: Vec::new(),
            nodes: Vec::new(),
            services: Vec::new(),
            pipes: Vec::new(),
            delivered_cells: Arc::new(Mutex::new(HashMap::new())),
            file_loss_budget: Arc::default(),
            file_dropped: Arc::default(),
            file_cells: Arc::default(),
            reliable_route_probes: Arc::default(),
            hold_reliable_route_probes: Arc::default(),
            held_route_probes: Arc::default(),
            hold_primary_datagrams: Arc::default(),
            cut_link: Arc::default(),
            cut_link_frames: Arc::default(),
        };
        let mut configs = Vec::new();
        for _ in 0..middle_count + 3 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("config.toml");
            let mut cfg = veil_cfg::build_stub_config_with_ephemeral_identity(false).unwrap();
            let (key, pow) = tokio::task::spawn_blocking(|| {
                let algo = veil_types::SignatureAlgorithm::Ed25519;
                let key = veil_crypto::generate_keypair(algo);
                let pow = veil_crypto::search_nonce(veil_crypto::PowParams {
                    algo,
                    public_key: veil_crypto::Base64PublicKey::new(algo, key.public_key.clone())
                        .unwrap(),
                    private_key: veil_crypto::Base64PrivateKey::new(algo, key.private_key.clone())
                        .unwrap(),
                    target_zero_bits: veil_crypto::DEFAULT_POW_DIFFICULTY,
                    timeout: Duration::from_secs(60),
                    start_from: veil_crypto::Base64Nonce::zero(),
                    threads: veil_crypto::available_thread_count(),
                    progress: None,
                })
                .unwrap();
                assert_eq!(pow.stop_reason, veil_crypto::PowStopReason::Found);
                (key, pow)
            })
            .await
            .unwrap();
            let identity = cfg.identity.as_mut().unwrap();
            // The stub helper caches an identity for fast unit tests. A stand
            // needs distinct origins, otherwise keyed services replace each other.
            let public_bytes = base64::engine::general_purpose::STANDARD
                .decode(&key.public_key)
                .unwrap();
            identity.node_id = Some(veil_cfg::NodeId::from(
                *blake3::hash(&public_bytes).as_bytes(),
            ));
            identity.nonce = pow.best_nonce.as_str().to_owned();
            identity.public_key = key.public_key;
            identity.private_key = key.private_key;
            identity.role = veil_cfg::NodeRole::Leaf;
            cfg.global.meeting_points = veil_cfg::MeetingPoints::Only(Vec::new());
            cfg.anonymity.receive_anonymous = true;
            cfg.anonymity.relay_capable = true;
            // Equal relay allowance, above the burst on every node. This
            // test stalls an endpoint sink, not the shared service quota.
            cfg.dht.service_budget_bytes_per_hour = Some(STAND_SERVICE_ALLOWANCE);
            configs.push((path, cfg));
            s._dirs.push(dir);
        }
        // A(0) and C(1) -> middle(2) -> rendezvous(3). Relays use ordinary
        // priority for every cell; producer lanes are endpoint-local.
        let middles: Vec<_> = std::iter::once(2).chain(4..middle_count + 3).collect();
        let mut uris = Vec::new();
        let mut reserved_ports = Vec::new();
        if real_obfs4 {
            let psk = s._dirs[0].path().join("fixture-obfs4.psk");
            std::fs::write(
                &psk,
                base64::engine::general_purpose::STANDARD.encode([0x42; 32]),
            )
            .unwrap();
            let rendezvous = configs[3]
                .1
                .identity
                .as_ref()
                .unwrap()
                .node_id
                .unwrap()
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            for (index, (_, cfg)) in configs.iter_mut().enumerate() {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let uri = format!("obfs4-tcp://{}", listener.local_addr().unwrap());
                cfg.listen = vec![veil_cfg::ListenConfig {
                    id: "0x00000001".parse().unwrap(),
                    transport: uri.clone(),
                    ..Default::default()
                }];
                cfg.transport.obfs4_psk_file = Some(psk.clone());
                cfg.global.builtin_seed_policy = veil_cfg::BuiltinSeedPolicy::Never;
                if std::env::var("VEIL_MEDIA_CODEC_TRACE").as_deref() == Ok("1") {
                    cfg.global.log_level = veil_cfg::LogLevel::Debug;
                }
                cfg.pex.enabled = false;
                cfg.anonymity.receive_anonymous = index < 2;
                cfg.anonymity.relay_capable = index >= 2;
                cfg.anonymity.rendezvous_relays = vec![rendezvous.clone()];
                cfg.peers.clear();
                uris.push(uri);
                reserved_ports.push(listener);
            }
            for &middle in &middles {
                for (a, b) in [(0, middle), (1, middle), (middle, 3)] {
                    for (from, to) in [(a, b), (b, a)] {
                        let identity = configs[to].1.identity.as_ref().unwrap().clone();
                        configs[from].1.peers.push(veil_cfg::PeerConfig {
                            peer_id: format!("0x{:08x}", to + 1).parse().unwrap(),
                            public_key: identity.public_key,
                            nonce: identity.nonce,
                            algo: identity.algo,
                            transport: uris[to].clone(),
                            ..Default::default()
                        });
                    }
                }
            }
        }
        drop(reserved_ports);
        for (path, cfg) in configs {
            veil_cfg::save_config(&path, &cfg).unwrap();
            let node = NodeRuntime::start(&path, true).await.unwrap();
            assert_eq!(
                node.access()
                    .dispatcher
                    .abuse
                    .service_budget
                    .bytes_per_hour(),
                STAND_SERVICE_ALLOWANCE,
                "fixture relay allowance must survive config serialization and runtime startup"
            );
            s.services.push(node.access());
            s.nodes.push(node);
        }
        if real_obfs4 {
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    let ready = middles.iter().all(|&middle| {
                        [(0, middle), (1, middle), (middle, 3)]
                            .iter()
                            .all(|&(a, b)| {
                                s.services[a].has_live_session(&s.services[b].local_node_id())
                                    && s.services[b]
                                        .has_live_session(&s.services[a].local_node_id())
                            })
                    });
                    if ready {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .expect("real loopback obfs4 topology must become active");
            assert!(
                s.pipes.is_empty(),
                "real sessions must not use in-memory delivery"
            );
        } else {
            for &middle in &middles {
                for (a, b) in [(0, middle), (1, middle), (middle, 3)] {
                    s.connect(a, b);
                    s.connect(b, a);
                }
            }
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        for index in middles.iter().copied().chain(std::iter::once(3)) {
            let relay = &s.services[index];
            let id = relay.local_node_id();
            let identity = &relay.identity.local_identity;
            let entry = veil_anonymity::directory::sign_entry(
                id,
                relay.stream_peer_intro_public_key().unwrap(),
                1_000_000,
                now,
                &identity.public_key,
                &identity.private_key,
                identity.algo,
            )
            .unwrap();
            for svc in &s.services {
                svc.dht.store_local(
                    veil_anonymity::directory::relay_directory_dht_key(&id),
                    entry.clone(),
                );
            }
        }
        for index in [0, 1] {
            let svc = &s.services[index];
            for &middle in &middles {
                svc.dht.add_contact(veil_dht::routing::Contact::new(
                    s.services[middle].local_node_id(),
                    if real_obfs4 {
                        uris[middle].as_str()
                    } else {
                        "tcp://127.0.0.1:1"
                    },
                ));
            }
            svc.publish_stream_rendezvous_ad(
                s.services[3].local_node_id(),
                svc.onion_stream_local_cookie(),
            );
        }
        s.copy_ads(0, 1);
        s.copy_ads(1, 0);
        s
    }
    fn connect(&mut self, from: usize, to: usize) {
        let src = self.services[from].local_node_id();
        let dest = self.services[to].clone();
        let delivered = Arc::clone(&self.delivered_cells);
        let file_loss_budget = Arc::clone(&self.file_loss_budget);
        let file_dropped = Arc::clone(&self.file_dropped);
        let file_cells = Arc::clone(&self.file_cells);
        let reliable_route_probes = Arc::clone(&self.reliable_route_probes);
        let hold_reliable_route_probes = Arc::clone(&self.hold_reliable_route_probes);
        let held_route_probes = Arc::clone(&self.held_route_probes);
        let hold_primary_datagrams = Arc::clone(&self.hold_primary_datagrams);
        let cut_link = Arc::clone(&self.cut_link);
        let cut_link_frames = Arc::clone(&self.cut_link_frames);
        let mut rx = self.services[from]
            .session_tx_registry
            .write()
            .unwrap()
            .register(dest.local_node_id());
        self.pipes.push(tokio::spawn(async move {
            while let Some((priority, bytes)) = rx.recv().await {
                let header =
                    veil_proto::codec::decode_header_with_limit(&bytes[..HEADER_SIZE], 65536)
                        .unwrap();
                if header.family != FrameFamily::RelayChain as u8 {
                    continue;
                }
                if *cut_link.lock().unwrap() == Some((from, to)) {
                    cut_link_frames.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    continue;
                }
                assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
                if from >= 2 {
                    assert_eq!(priority, veil_proto::priority::INTERACTIVE);
                }
                if from < 2
                    && priority == veil_session::LOCAL_NETWORK_CONTROL_LANE
                    && header.msg_type == veil_proto::family::RelayChainMsg::CircuitData as u16
                {
                    reliable_route_probes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if hold_reliable_route_probes.load(std::sync::atomic::Ordering::Acquire) {
                        held_route_probes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        continue;
                    }
                }
                if from < 2
                    && priority == veil_proto::priority::REALTIME
                    && header.msg_type == veil_proto::family::RelayChainMsg::CircuitDatagram as u16
                    && hold_primary_datagrams.load(std::sync::atomic::Ordering::Acquire)
                {
                    continue;
                }
                if from < 2 && priority == veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE {
                    use std::sync::atomic::Ordering;
                    assert_eq!(
                        header.msg_type,
                        veil_proto::family::RelayChainMsg::CircuitDatagram as u16
                    );
                    file_cells.fetch_add(1, Ordering::Relaxed);
                    if file_loss_budget
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |budget| {
                            budget.checked_sub(1)
                        })
                        .is_ok()
                    {
                        file_dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }
                dest.dispatcher.dispatch_relay_chain(
                    &header,
                    &bytes[HEADER_SIZE..],
                    veil_cfg::NodeId::from(src),
                );
                if to < 2
                    && header.msg_type == veil_proto::family::RelayChainMsg::CircuitDatagram as u16
                {
                    let body = &bytes[HEADER_SIZE..];
                    veil_anonymity::circuit_wire::CircuitDataPayload::validate(body).unwrap();
                    let cid = u32::from_be_bytes(body[..4].try_into().unwrap());
                    *delivered.lock().unwrap().entry((to, cid)).or_default() += 1;
                }
            }
        }));
    }
    fn delivered(&self, to: usize, cid: u32) -> usize {
        self.delivered_cells
            .lock()
            .unwrap()
            .get(&(to, cid))
            .copied()
            .unwrap_or(0)
    }
    fn copy_ads(&self, from: usize, to: usize) {
        for slot in 0..veil_anonymity::rendezvous::MAX_RENDEZVOUS_AD_SLOTS {
            let key = veil_anonymity::rendezvous::rendezvous_ad_dht_key_at(
                &self.services[from].local_node_id(),
                slot,
            );
            if let Some(bytes) = self.services[from].dht.get_local(&key) {
                self.services[to].dht.store_local(key, bytes);
            }
        }
    }
    async fn stop(mut self) {
        for pipe in self.pipes.drain(..) {
            pipe.abort();
            let _ = pipe.await;
        }
        for node in &mut self.nodes {
            node.stop().await.unwrap();
        }
    }
}
struct Received {
    packet: Vec<u8>,
    at: Instant,
}
struct Channel {
    id: u64,
    routes: Arc<MediaRoutes>,
    _callback: Box<mpsc::Sender<Received>>,
    rx: mpsc::Receiver<Received>,
    files: Arc<crate::anon_stream::CircuitStreamMuxForTest>,
}
impl Drop for Channel {
    fn drop(&mut self) {
        unsafe { veil_media_close_channel(self.id) };
    }
}
extern "C" fn receive(ctx: *mut c_void, ptr: *const u8, len: usize) {
    let tx = unsafe { &*(ctx as *const mpsc::Sender<Received>) };
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let _ = tx.try_send(Received {
        packet: bytes.to_vec(),
        at: Instant::now(),
    });
}
fn channel(me: [u8; 32], peer: [u8; 32], tx_key: [u8; 32], rx_key: [u8; 32]) -> Channel {
    let id = MEDIA_NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let cipher = Arc::new(cipher_for_test(&peer, &tx_key, &rx_key).unwrap());
    let (routes, files) = MediaRoutes::on_node_for_test(me, peer, id, Arc::clone(&cipher));
    let (tx_hi, rx_hi) = mpsc::channel(MEDIA_TX_HI_QUEUE);
    let (tx_video, rx_video) = mpsc::channel(MEDIA_TX_VIDEO_QUEUE);
    let (tx_screen, rx_screen) = mpsc::channel(MEDIA_TX_VIDEO_QUEUE);
    let (tx_feedback, rx_feedback) = mpsc::channel(16);
    let (repair_feedback, repair_feedback_rx) = mpsc::channel(1);
    let (repair_screen, repair_screen_rx) = mpsc::channel(1);
    let (repair_hi, repair_hi_rx) = mpsc::channel(1);
    let (repair_video, repair_video_rx) = mpsc::channel(1);
    let spawn = |rx, repairs, plane| {
        let send = Arc::clone(&routes);
        let warm = Arc::clone(&routes);
        tokio::spawn(drain_anonymous_media(
            rx,
            repairs,
            Arc::clone(&cipher),
            plane,
            move |sealed| {
                let routes = Arc::clone(&send);
                async move { routes.send(plane, &sealed).await }
            },
            move || {
                let routes = Arc::clone(&warm);
                async move { routes.warm(plane).await }
            },
        ))
    };
    let task = spawn(rx_hi, repair_hi_rx, LocalMediaPlane::Primary);
    let video_task = spawn(rx_video, repair_video_rx, LocalMediaPlane::Secondary);
    let screen_task = spawn(rx_screen, repair_screen_rx, LocalMediaPlane::Screen);
    let feedback_task = spawn(rx_feedback, repair_feedback_rx, LocalMediaPlane::Control);
    let ingress = MediaIngress::with_screen(
        tx_hi,
        MediaVideoIngress::Packets(tx_video),
        MediaVideoIngress::Packets(tx_screen),
    );
    *ingress.feedback_tx.write().unwrap() = Some(tx_feedback);
    MEDIA_CHANNELS.write().unwrap().insert(
        id,
        MediaChannel {
            cost_context: None,
            path_probe: None,
            source_preflight: None,
            ingress,
            repair_tx: Some([repair_hi, repair_video, repair_screen, repair_feedback]),
            peer,
            task,
            video_task: Some(video_task),
            screen_task: Some(screen_task),
            feedback_task: Some(feedback_task),
            direct_seq: None,
            video_sender: None,
            screen_sender: None,
            sender_app_id: None,
            control_destination: None,
            batching: None,
            cipher,
            relay_stats: None,
            routes: Some(Arc::clone(&routes)),
        },
    );
    let (tx, rx) = mpsc::channel(2048);
    let mut context = Box::new(tx);
    assert_eq!(
        unsafe {
            veil_media_set_recv_callback(
                id,
                Some(receive),
                (&mut *context as *mut mpsc::Sender<Received>).cast(),
            )
        },
        0
    );
    Channel {
        id,
        routes,
        _callback: context,
        rx,
        files: Arc::new(files),
    }
}
fn packet(pt: u8, seq: u16) -> Vec<u8> {
    let mut p = vec![0x7d; if pt == 96 { 500 } else { 80 }];
    p[0] = 0x80;
    p[1] = pt;
    p[2..4].copy_from_slice(&seq.to_be_bytes());
    p
}
fn send(id: u64, p: &[u8]) -> c_int {
    unsafe { veil_media_send_datagram(id, p.as_ptr(), p.len()) }
}
async fn wait_until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
async fn expect_packet(rx: &mut mpsc::Receiver<Received>, wanted: &[u8]) -> Instant {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let r = rx.recv().await.unwrap();
            if r.packet == wanted {
                return r.at;
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "media packet did not arrive: type={} seq={}",
            wanted.get(1).copied().unwrap_or(0),
            wanted
                .get(2..4)
                .map(|bytes| u16::from_be_bytes(bytes.try_into().unwrap()))
                .unwrap_or(0)
        )
    })
}
async fn expect_packets(rx: &mut mpsc::Receiver<Received>, wanted: &[Vec<u8>]) {
    let mut received = vec![false; wanted.len()];
    tokio::time::timeout(Duration::from_secs(2), async {
        while received.iter().any(|seen| !seen) {
            let packet = rx.recv().await.unwrap().packet;
            if let Some(index) = wanted.iter().position(|expected| *expected == packet) {
                assert!(!received[index], "duplicate media packet");
                received[index] = true;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fallback_uses_the_call_receive_address_instead_of_an_obsolete_public_cookie() {
    let stand = Stand::new().await;
    let a = &stand.services[0];
    let c = &stand.services[1];
    let mut cc = channel(c.local_node_id(), a.local_node_id(), [0xc1; 32], [0xa1; 32]);
    cc.routes.start(&tokio::runtime::Handle::current());
    wait_until(|| cc.routes.receive_addresses_for_test().len() == 4).await;
    // A family's public ad may refer to a different, unavailable device. The
    // selected call endpoint still has its own authenticated receive address.
    let obsolete_cookie = [0xb7; 16];
    let registry = stand.services[3]
        .dispatcher
        .circuit_rendezvous
        .as_ref()
        .unwrap();
    assert!(registry.lookup(&obsolete_cookie).is_none());
    wait_until(|| registry.lookup(&c.onion_stream_local_cookie()).is_some()).await;
    let identity = &c.identity.local_identity;
    let obsolete_key = stand.services[2].stream_peer_intro_public_key().unwrap();
    assert_ne!(obsolete_key, c.stream_peer_intro_public_key().unwrap());
    let now = veil_util::unix_secs_now_u64();
    let obsolete_ad = veil_anonymity::rendezvous::sign_rendezvous_ad_v5(
        c.local_node_id(),
        stand.services[3].local_node_id(),
        obsolete_cookie,
        obsolete_key,
        now,
        now + 1800,
        &[],
        &[],
        &[],
        0,
        &[],
        &identity.public_key,
        &identity.private_key,
        identity.algo,
    )
    .unwrap();
    // Give A only the stale sibling record. Its signature is valid, but its
    // cookie and introduction key both differ from the selected call endpoint.
    for slot in 0..veil_anonymity::rendezvous::MAX_RENDEZVOUS_AD_SLOTS {
        let key = veil_anonymity::rendezvous::rendezvous_ad_dht_key_at(&c.local_node_id(), slot);
        a.dht.store_local(key, obsolete_ad.clone());
    }
    let resolved = a
        .resolve_stream_rendezvous_ads(c.local_node_id())
        .await
        .unwrap();
    assert!(!resolved.is_empty());
    assert!(
        resolved
            .iter()
            .all(|ad| ad.auth_cookie == obsolete_cookie && ad.receiver_x25519_pk == obsolete_key)
    );
    let ca = channel(a.local_node_id(), c.local_node_id(), [0xa1; 32], [0xc1; 32]);
    // Deliberately do not start A's private route workers: only its normal
    // fallback pool can transmit. C's encrypted offer must still reach A.
    wait_until(|| ca.routes.received_offer_for_test().is_some()).await;
    let cipher = Arc::clone(&MEDIA_CHANNELS.read().unwrap().get(&ca.id).unwrap().cipher);
    let wanted = packet(111, 71);
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let sealed = cipher
                .seal_on_plane(LocalMediaPlane::Primary, &wanted)
                .unwrap();
            if ca
                .routes
                .send_fallback_for_test(LocalMediaPlane::Primary, &sealed)
                .await
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("negative control: a real fallback circuit must accept the packet");
    let public_cookies = ca
        .routes
        .fallback_cookies_for_test(LocalMediaPlane::Primary)
        .await;
    let received = tokio::time::timeout(Duration::from_secs(2), cc.rx.recv()).await;
    let private_received = cc.routes.received_media_cells_for_test()[0];
    // A cookie registered at R cannot be reused at an unrelated relay, even
    // if the healthy public pool would otherwise accept this new packet.
    let mut other_relay = ca.routes.received_offer_for_test().unwrap();
    let revision = u64::from_be_bytes(other_relay[12..20].try_into().unwrap());
    other_relay[12..20].copy_from_slice(&(revision + 1000).to_be_bytes());
    assert_eq!(other_relay[21], 0);
    other_relay[22..54].copy_from_slice(&stand.services[2].local_node_id());
    ca.routes.accept_control(&other_relay);
    let rejected = cipher
        .seal_on_plane(LocalMediaPlane::Primary, &packet(111, 72))
        .unwrap();
    let wrong_relay_accepted = ca
        .routes
        .send_fallback_for_test(LocalMediaPlane::Primary, &rejected)
        .await;
    assert!(ca.routes.outgoing_for_test().await.is_empty());
    drop((ca, cc));
    stand.stop().await;
    assert_eq!(
        public_cookies,
        [obsolete_cookie],
        "fixture must use the obsolete public ad"
    );
    let packet = received
        .expect("fallback sent to the obsolete public cookie")
        .unwrap()
        .packet;
    assert_eq!(packet, wanted);
    assert!(
        private_received > 0,
        "packet must arrive at the selected private receive address"
    );
    assert!(
        !wrong_relay_accepted,
        "must not retarget a circuit to another relay"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audio_only_call_receives_video_without_reserving_an_outgoing_video_route() {
    let stand = Stand::new().await;
    let a = &stand.services[0];
    let c = &stand.services[1];
    let ca = channel(a.local_node_id(), c.local_node_id(), [0xa1; 32], [0xc1; 32]);
    let mut cc = channel(c.local_node_id(), a.local_node_id(), [0xc1; 32], [0xa1; 32]);
    let registry = stand.services[3]
        .dispatcher
        .circuit_rendezvous
        .as_ref()
        .unwrap();
    wait_until(|| {
        registry.lookup(&a.onion_stream_local_cookie()).is_some()
            && registry.lookup(&c.onion_stream_local_cookie()).is_some()
    })
    .await;
    stand.copy_ads(0, 1);
    stand.copy_ads(1, 0);
    ca.routes.start(&tokio::runtime::Handle::current());
    cc.routes.start(&tokio::runtime::Handle::current());
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if ca.routes.receive_addresses_for_test().len() == 4
                && cc.routes.receive_addresses_for_test().len() == 4
                && ca.routes.outgoing_for_test().await.len() >= 2
                && cc.routes.outgoing_for_test().await.len() >= 2
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // Allow another maintenance tick: a dormant camera must not allocate a
    // circuit in the background, while every incoming plane remains ready.
    tokio::time::sleep(Duration::from_secs(2)).await;
    for routes in [&ca.routes, &cc.routes] {
        let planes: Vec<_> = routes
            .outgoing_for_test()
            .await
            .iter()
            .map(|r| r.plane)
            .collect();
        assert_eq!(
            planes,
            [0, 3],
            "audio-only call allocated an unused producer"
        );
    }
    let video = packet(96, 1);
    assert_eq!(send(ca.id, &video), 0);
    tokio::time::timeout(Duration::from_secs(20), async {
        while !ca
            .routes
            .outgoing_for_test()
            .await
            .iter()
            .any(|r| r.plane == 1)
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // The first loss-tolerant frame can expire during circuit construction.
    // A fresh packet must traverse the route activated by that first frame.
    let video = packet(96, 2);
    assert_eq!(send(ca.id, &video), 0);
    expect_packet(&mut cc.rx, &video).await;
    assert!(
        !cc.routes
            .outgoing_for_test()
            .await
            .iter()
            .any(|r| r.plane == 1),
        "receiving video must not activate the receiver's own camera route"
    );
    stand.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_outgoing_construction_cannot_delay_our_receive_address() {
    let mut stand = Stand::with_middle_count(2).await;
    // A can receive through R(3). The peer's advertised address uses the
    // other relay(2), reached through middle(4); that last link blackholes.
    stand.connect(4, 2);
    stand.connect(2, 4);
    *stand.cut_link.lock().unwrap() = Some((4, 2));
    let a = &stand.services[0];
    let c = &stand.services[1];
    let ca = channel(a.local_node_id(), c.local_node_id(), [0xa1; 32], [0xc1; 32]);
    let registry = stand.services[3]
        .dispatcher
        .circuit_rendezvous
        .as_ref()
        .unwrap();
    wait_until(|| registry.lookup(&a.onion_stream_local_cookie()).is_some()).await;
    let mut offer = b"VMR1".to_vec();
    offer.extend_from_slice(&1u64.to_be_bytes());
    offer.extend_from_slice(&1u64.to_be_bytes());
    offer.extend_from_slice(&[1, 0]); // one primary address
    offer.extend_from_slice(&stand.services[2].local_node_id());
    offer.extend_from_slice(&[0xa7; 16]);
    offer.extend_from_slice(&c.stream_peer_intro_public_key().unwrap());
    ca.routes.accept_control(&offer);
    ca.routes.start(&tokio::runtime::Handle::current());
    let published = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if ca
                .routes
                .receive_addresses_for_test()
                .iter()
                .any(|(p, _)| *p == 0)
                && stand
                    .cut_link_frames
                    .load(std::sync::atomic::Ordering::Relaxed)
                    > 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let outgoing = ca.routes.outgoing_for_test().await;
    let blocked = stand
        .cut_link_frames
        .load(std::sync::atomic::Ordering::Relaxed);
    drop(ca);
    stand.stop().await;
    assert!(
        blocked > 0,
        "negative control: the test must exercise the broken link"
    );
    assert!(
        published.is_ok(),
        "our receive address waited behind the peer's stalled route"
    );
    assert!(
        !outgoing.iter().any(|r| r.plane == 0),
        "negative control: the peer's circuit must remain unconfirmed"
    );
}

// Separate endpoint carriers deliberately have independent progress. Delaying
// reliable recovery traffic must not retire a working datagram circuit; losing
// that circuit's own datagrams MUST still expire it at the original 12-s gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_route_liveness_follows_its_datagram_carrier_not_reliable_maintenance() {
    use std::sync::atomic::Ordering;
    let stand = Stand::new().await;
    let a = &stand.services[0];
    let c = &stand.services[1];
    let mut ca = channel(a.local_node_id(), c.local_node_id(), [0xa1; 32], [0xc1; 32]);
    let mut cc = channel(c.local_node_id(), a.local_node_id(), [0xc1; 32], [0xa1; 32]);
    let registry = stand.services[3]
        .dispatcher
        .circuit_rendezvous
        .as_ref()
        .unwrap();
    wait_until(|| {
        registry.lookup(&a.onion_stream_local_cookie()).is_some()
            && registry.lookup(&c.onion_stream_local_cookie()).is_some()
    })
    .await;
    stand.copy_ads(0, 1);
    stand.copy_ads(1, 0);
    ca.routes.start(&tokio::runtime::Handle::current());
    cc.routes.start(&tokio::runtime::Handle::current());
    ca.routes.warm(LocalMediaPlane::Secondary).await;
    cc.routes.warm(LocalMediaPlane::Secondary).await;
    tokio::time::timeout(Duration::from_secs(20), async {
        while ca.routes.outgoing_for_test().await.len() < 3
            || cc.routes.outgoing_for_test().await.len() < 3
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let initial_a = ca.routes.outgoing_for_test().await;
    let initial_c = cc.routes.outgoing_for_test().await;

    let before_a = ca.routes.send_paths_for_test().1[0];
    let before_c = cc.routes.send_paths_for_test().1[0];
    stand
        .hold_reliable_route_probes
        .store(true, Ordering::Release);
    let started = Instant::now();
    let mut seq = 0;
    let mut received = [0usize; 2];
    while started.elapsed() < Duration::from_secs(16) {
        assert_eq!(send(ca.id, &packet(111, seq)), 0);
        assert_eq!(send(cc.id, &packet(111, seq)), 0);
        for (i, rx) in [&mut ca.rx, &mut cc.rx].into_iter().enumerate() {
            while let Ok(r) = rx.try_recv() {
                if r.packet.get(1) == Some(&111) {
                    received[i] += 1;
                }
            }
        }
        seq += 1;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let healthy_a = ca.routes.outgoing_for_test().await;
    let healthy_c = cc.routes.outgoing_for_test().await;
    let fallback_a = ca.routes.send_paths_for_test().1[0] - before_a;
    let fallback_c = cc.routes.send_paths_for_test().1[0] - before_c;
    let held = stand.held_route_probes.load(Ordering::Acquire);
    // Negative control: same carrier now really fails. Do not mask that with
    // reliable-path echoes, a longer timeout or an application receive stamp.
    stand
        .hold_reliable_route_probes
        .store(false, Ordering::Release);
    stand.hold_primary_datagrams.store(true, Ordering::Release);
    // Keep exercising the production send path under loss. A silent call may
    // retain a stale route object while replacement construction retries;
    // its presence in a raw snapshot does not mean it can still carry media.
    let failed_started = Instant::now();
    while failed_started.elapsed() < Duration::from_secs(16) {
        let _ = send(ca.id, &packet(111, seq));
        let _ = send(cc.id, &packet(111, seq));
        for rx in [&mut ca.rx, &mut cc.rx] {
            while rx.try_recv().is_ok() {}
        }
        seq += 1;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let failed_a = ca.routes.outgoing_for_test().await;
    let failed_c = cc.routes.outgoing_for_test().await;
    let stable = healthy_a.iter().find(|r| r.plane == 0).map(|r| r.origin)
        == initial_a.iter().find(|r| r.plane == 0).map(|r| r.origin)
        && healthy_c.iter().find(|r| r.plane == 0).map(|r| r.origin)
            == initial_c.iter().find(|r| r.plane == 0).map(|r| r.origin);
    let expired = failed_a.iter().find(|r| r.plane == 0).map(|r| r.origin)
        != healthy_a.iter().find(|r| r.plane == 0).map(|r| r.origin)
        && failed_c.iter().find(|r| r.plane == 0).map(|r| r.origin)
            != healthy_c.iter().find(|r| r.plane == 0).map(|r| r.origin);
    drop((ca, cc));
    stand.stop().await;
    eprintln!(
        "independent liveness: stable={stable} expired={expired} received={received:?} fallback={fallback_a}/{fallback_c} held_reliable={held}"
    );
    assert!(
        received.into_iter().all(|n| n > 500),
        "actual authenticated media must flow"
    );
    assert!(
        stable,
        "working datagram routes expired because reliable maintenance stalled"
    );
    assert_eq!(
        (fallback_a, fallback_c),
        (0, 0),
        "no fallback while the actual carrier works"
    );
    assert!(
        expired,
        "failed datagram routes must expire despite a working reliable carrier"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_routes_negotiate_splice_and_repair_while_video_ingress_is_stalled() {
    let stand = Stand::new().await;
    let a = &stand.services[0];
    let c = &stand.services[1];
    let middle = &stand.services[2];
    let rendezvous = &stand.services[3];
    let mut ca = channel(a.local_node_id(), c.local_node_id(), [0xa1; 32], [0xc1; 32]);
    let mut cc = channel(c.local_node_id(), a.local_node_id(), [0xc1; 32], [0xa1; 32]);
    let registry = rendezvous.dispatcher.circuit_rendezvous.as_ref().unwrap();
    wait_until(|| {
        registry.lookup(&a.onion_stream_local_cookie()).is_some()
            && registry.lookup(&c.onion_stream_local_cookie()).is_some()
    })
    .await;
    stand.copy_ads(0, 1);
    stand.copy_ads(1, 0);
    ca.routes.start(&tokio::runtime::Handle::current());
    cc.routes.start(&tokio::runtime::Handle::current());
    ca.routes.warm(LocalMediaPlane::Secondary).await;
    cc.routes.warm(LocalMediaPlane::Secondary).await;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if ca.routes.outgoing_for_test().await.len() == 3
                && cc.routes.outgoing_for_test().await.len() == 3
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let incoming = cc.routes.receive_addresses_for_test();
    let outgoing = ca.routes.outgoing_for_test().await;
    assert_eq!(
        incoming.len(),
        4,
        "all four producers need independent receive circuits"
    );
    for route in &outgoing {
        assert_eq!(route.destination_cookie, incoming[route.plane as usize].1);
    }
    assert_eq!(
        incoming
            .iter()
            .map(|(_, cookie)| *cookie)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        4
    );
    assert!(
        incoming
            .iter()
            .all(|(_, cookie)| *cookie != c.onion_stream_local_cookie())
    );
    let control = outgoing.iter().find(|r| r.plane == 3).unwrap();
    let audio_route = outgoing.iter().find(|r| r.plane == 0).unwrap();
    assert_ne!(control.origin, audio_route.origin);
    assert_ne!(control.return_cookie, audio_route.return_cookie);
    let feedback = vec![0x80, 201, 0, 1, 0, 0, 0, 7];
    assert_eq!(send(ca.id, &feedback), 0);
    expect_packet(&mut cc.rx, &feedback).await;
    // Holding the control receive sink must not hold the primary receive sink.
    let control_r = registry.lookup(&incoming[3].1).unwrap();
    let control_m = middle
        .dispatcher
        .circuit_table
        .as_ref()
        .unwrap()
        .lookup_backward(&rendezvous.local_node_id(), control_r.circuit_id_in)
        .unwrap();
    assert_ne!(
        control_r.circuit_id_in,
        registry.lookup(&incoming[0].1).unwrap().circuit_id_in
    );
    let (held_control, mut control_buffer) = mpsc::channel(1);
    held_control.try_send(vec![0xff]).unwrap();
    let original_control = c
        .dispatcher
        .stream_recv
        .lock()
        .unwrap()
        .insert(control_m.circuit_id_in, held_control)
        .unwrap();
    let control_before = stand.delivered(1, control_m.circuit_id_in);
    for _ in 0..20 {
        let _ = send(ca.id, &feedback);
    }
    wait_until(|| stand.delivered(1, control_m.circuit_id_in) > control_before).await;
    let audio_while_control_blocked = packet(111, 0x70);
    assert_eq!(send(ca.id, &audio_while_control_blocked), 0);
    expect_packet(&mut cc.rx, &audio_while_control_blocked).await;
    assert_eq!(control_buffer.try_recv().unwrap(), vec![0xff]);
    c.dispatcher
        .stream_recv
        .lock()
        .unwrap()
        .insert(control_m.circuit_id_in, original_control);
    let video_r = registry.lookup(&incoming[1].1).unwrap();
    let primary_r = registry.lookup(&incoming[0].1).unwrap();
    assert_ne!(video_r.circuit_id_in, primary_r.circuit_id_in);
    let table = middle.dispatcher.circuit_table.as_ref().unwrap();
    let video_m = table
        .lookup_backward(&rendezvous.local_node_id(), video_r.circuit_id_in)
        .unwrap();
    let primary_m = table
        .lookup_backward(&rendezvous.local_node_id(), primary_r.circuit_id_in)
        .unwrap();
    assert_ne!(video_m.circuit_id_in, primary_m.circuit_id_in);
    // Stall the endpoint sink after onion decryption, not relay scheduling.
    let (blocked_tx, mut blocked_rx) = mpsc::channel(1);
    blocked_tx.try_send(vec![0xff]).unwrap();
    let original = c
        .dispatcher
        .stream_recv
        .lock()
        .unwrap()
        .insert(video_m.circuit_id_in, blocked_tx)
        .unwrap();
    let video_before = stand.delivered(1, video_m.circuit_id_in);
    for seq in 0..1000 {
        let _ = send(ca.id, &packet(96, seq));
    }
    // The burst actually reaches the stalled sink; silence from a broken
    // secondary route must not make the audio-isolation assertion pass.
    wait_until(|| stand.delivered(1, video_m.circuit_id_in) >= video_before + 10).await;
    let audio = packet(111, 0x71);
    let started = Instant::now();
    assert_eq!(send(ca.id, &audio), 0);
    assert!(
        expect_packet(&mut cc.rx, &audio)
            .await
            .duration_since(started)
            < Duration::from_secs(2)
    );
    assert_eq!(blocked_rx.try_recv().unwrap(), vec![0xff]);
    assert!(blocked_rx.try_recv().is_err());
    c.dispatcher
        .stream_recv
        .lock()
        .unwrap()
        .insert(video_m.circuit_id_in, original);
    wait_until(|| {
        let channels = MEDIA_CHANNELS.read().unwrap();
        let MediaVideoIngress::Packets(tx) = &channels.get(&ca.id).unwrap().ingress.video else {
            panic!("anonymous channel must have a packet ingress")
        };
        tx.capacity() == MEDIA_TX_VIDEO_QUEUE
    })
    .await;
    let video = packet(96, 0x72);
    assert_eq!(send(ca.id, &video), 0);
    expect_packet(&mut cc.rx, &video).await;
    let reverse = packet(111, 0x73);
    assert_eq!(send(cc.id, &reverse), 0);
    expect_packet(&mut ca.rx, &reverse).await;
    assert_eq!(unsafe { veil_media_repair_channel(ca.id) }, 0);
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let new = ca.routes.outgoing_for_test().await;
            if new.len() == 3
                && new.iter().all(|r| {
                    r.origin
                        != outgoing
                            .iter()
                            .find(|old| old.plane == r.plane)
                            .unwrap()
                            .origin
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        registry.lookup(&incoming[0].1).unwrap().circuit_id_in,
        primary_r.circuit_id_in
    );
    assert_eq!(
        registry.lookup(&incoming[1].1).unwrap().circuit_id_in,
        video_r.circuit_id_in
    );
    let after = packet(111, 0x74);
    assert_eq!(send(ca.id, &after), 0);
    expect_packet(&mut cc.rx, &after).await;
    // Screen has its own receive circuit as well as its own outgoing circuit.
    assert_eq!(super::veil_media_channel_set_screen_sharing(ca.id, 1), 0);
    let screen = packet(96, 0x75);
    assert_eq!(send(ca.id, &screen), 0);
    tokio::time::timeout(Duration::from_secs(15), async {
        while ca.routes.outgoing_for_test().await.len() != 4 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let outgoing_all = ca.routes.outgoing_for_test().await;
    assert_eq!(
        stand
            .reliable_route_probes
            .load(std::sync::atomic::Ordering::Acquire),
        0,
        "route checks must follow their actual datagram carriers"
    );
    assert_eq!(cc.routes.receive_addresses_for_test().len(), 4);
    assert_eq!(outgoing_all[2].destination_cookie, incoming[2].1);
    for other in outgoing_all.iter().filter(|r| r.plane != 2) {
        assert_ne!(outgoing_all[2].origin, other.origin);
        assert_ne!(outgoing_all[2].return_cookie, other.return_cookie);
    }
    // The first cell may expire during route construction. Fresh cells must
    // decrypt while the camera's distinct receive sink is blocked.
    let (held_camera, mut camera_buffer) = mpsc::channel(1);
    held_camera.try_send(vec![0xff]).unwrap();
    let original_camera = c
        .dispatcher
        .stream_recv
        .lock()
        .unwrap()
        .insert(video_m.circuit_id_in, held_camera)
        .unwrap();
    let camera_before = stand.delivered(1, video_m.circuit_id_in);
    assert_eq!(super::veil_media_channel_set_screen_sharing(ca.id, 0), 0);
    assert_eq!(send(ca.id, &packet(96, 0x77)), 0);
    wait_until(|| stand.delivered(1, video_m.circuit_id_in) > camera_before).await;
    assert_eq!(super::veil_media_channel_set_screen_sharing(ca.id, 1), 0);
    assert_eq!(send(ca.id, &screen), 0);
    expect_packet(&mut cc.rx, &screen).await;
    assert_eq!(camera_buffer.try_recv().unwrap(), vec![0xff]);
    c.dispatcher
        .stream_recv
        .lock()
        .unwrap()
        .insert(video_m.circuit_id_in, original_camera);
    assert_eq!(super::veil_media_channel_set_screen_sharing(ca.id, 0), 0);
    let camera_after_screen = packet(96, 0x76);
    assert_eq!(send(ca.id, &camera_after_screen), 0);
    expect_packet(&mut cc.rx, &camera_after_screen).await;
    let mut cookies = ca.routes.receive_addresses_for_test();
    cookies.extend(cc.routes.receive_addresses_for_test());
    let mut returns = ca.routes.outgoing_for_test().await;
    returns.extend(cc.routes.outgoing_for_test().await);
    cookies.extend(returns.iter().map(|r| (r.plane, r.return_cookie)));
    cookies.extend(outgoing.iter().map(|r| (r.plane, r.return_cookie)));
    drop(ca);
    drop(cc);
    wait_until(|| {
        cookies
            .iter()
            .all(|(_, cookie)| registry.lookup(cookie).is_none())
    })
    .await;
    for pipe in &stand.pipes {
        assert!(
            !pipe.is_finished(),
            "ordinary relay forwarding must stay live"
        );
    }
    stand.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_media_routes_deliver_over_real_multihop_obfs4_sessions() {
    let stand = Stand::with_links(1, true).await;
    let a = &stand.services[0];
    let c = &stand.services[1];
    let mut ca = channel(a.local_node_id(), c.local_node_id(), [0xa1; 32], [0xc1; 32]);
    let mut cc = channel(c.local_node_id(), a.local_node_id(), [0xc1; 32], [0xa1; 32]);
    let registry = stand.services[3]
        .dispatcher
        .circuit_rendezvous
        .as_ref()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if registry.lookup(&a.onion_stream_local_cookie()).is_some()
                && registry.lookup(&c.onion_stream_local_cookie()).is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("both real receive registrations must reach rendezvous");
    stand.copy_ads(0, 1);
    stand.copy_ads(1, 0);
    ca.routes.start(&tokio::runtime::Handle::current());
    cc.routes.start(&tokio::runtime::Handle::current());
    ca.routes.warm(LocalMediaPlane::Secondary).await;
    cc.routes.warm(LocalMediaPlane::Secondary).await;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if ca.routes.outgoing_for_test().await.len() == 3
                && cc.routes.outgoing_for_test().await.len() == 3
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("audio, camera and control must negotiate real private routes");
    ca.routes.warm(LocalMediaPlane::Screen).await;
    cc.routes.warm(LocalMediaPlane::Screen).await;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if ca.routes.outgoing_for_test().await.len() == 4
                && cc.routes.outgoing_for_test().await.len() == 4
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("all four producers must negotiate independent receive addresses");
    for routes in [&ca.routes, &cc.routes] {
        let peer_incoming = if Arc::ptr_eq(routes, &ca.routes) {
            cc.routes.receive_addresses_for_test()
        } else {
            ca.routes.receive_addresses_for_test()
        };
        assert_eq!(peer_incoming.len(), 4);
        for route in routes.outgoing_for_test().await {
            assert_eq!(
                route.destination_cookie,
                peer_incoming[route.plane as usize].1
            );
            assert_eq!(route.first_hop, stand.services[2].local_node_id());
            let source = if Arc::ptr_eq(routes, &ca.routes) {
                a
            } else {
                c
            };
            let middle = stand.services[2]
                .dispatcher
                .circuit_table
                .as_ref()
                .unwrap()
                .lookup_forward(&source.local_node_id(), route.origin)
                .unwrap();
            assert_eq!(middle.next_link, Some(stand.services[3].local_node_id()));
            let terminus = stand.services[3]
                .dispatcher
                .circuit_table
                .as_ref()
                .unwrap()
                .lookup_forward(&stand.services[2].local_node_id(), middle.circuit_id_out)
                .unwrap();
            assert!(terminus.next_link.is_none());
        }
    }
    for seq in 1..=20 {
        for payload_type in [111, 96] {
            let forward = packet(payload_type, seq);
            let reverse = packet(payload_type, seq + 100);
            assert_eq!(send(ca.id, &forward), 0);
            assert_eq!(send(cc.id, &reverse), 0);
            expect_packet(&mut cc.rx, &forward).await;
            expect_packet(&mut ca.rx, &reverse).await;
        }
    }
    let feedback = vec![0x80, 201, 0, 1, 0, 0, 0, 7];
    assert_eq!(send(ca.id, &feedback), 0);
    expect_packet(&mut cc.rx, &feedback).await;

    // Actual recoverable file traffic shares these node sessions. Wait for its
    // first bytes before measuring media; circuit construction alone is not load.
    let mux_a = Arc::clone(&ca.files);
    let mux_c = Arc::clone(&cc.files);
    let destination = c.local_node_id();
    let (first_bytes, file_started) = tokio::sync::oneshot::channel();
    let file_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done = Arc::clone(&file_done);
    let file = tokio::spawn(async move {
        let expected: Vec<_> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let outgoing = mux_a.open(veil_onion_stream::Addr {
            node: destination,
            app: [0; 32],
        });
        let send = async {
            outgoing.write_all(&expected).await.unwrap();
            outgoing.finish().await.unwrap();
        };
        let receive = async {
            let (mut incoming, _) = mux_c.accept().await.unwrap();
            let mut first_bytes = Some(first_bytes);
            let mut bytes = Vec::new();
            let mut buffer = [0; 4096];
            loop {
                let count = incoming.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                bytes.extend_from_slice(&buffer[..count]);
                if let Some(first_bytes) = first_bytes.take() {
                    let _ = first_bytes.send(());
                }
            }
            assert_eq!(
                bytes, expected,
                "real multihop file must preserve every byte"
            );
        };
        tokio::join!(send, receive);
        done.store(true, std::sync::atomic::Ordering::Release);
    });
    tokio::time::timeout(Duration::from_secs(30), file_started)
        .await
        .unwrap()
        .unwrap();
    let id = ca.id;
    let video = tokio::spawn(async move {
        for seq in 2000..2256 {
            assert_eq!(super::veil_media_channel_set_screen_sharing(id, 0), 0);
            let _ = send(id, &packet(96, seq));
            assert_eq!(super::veil_media_channel_set_screen_sharing(id, 1), 0);
            let _ = send(id, &packet(96, seq + 1000));
            if seq % 4 == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        assert_eq!(super::veil_media_channel_set_screen_sharing(id, 0), 0);
    });
    let mut worst = Duration::ZERO;
    let mut overlap = 0;
    let mut video_received = 0;
    let mut screen_received = 0;
    for seq in 1000..1050 {
        let forward = packet(111, seq);
        let started = Instant::now();
        if !file_done.load(std::sync::atomic::Ordering::Acquire) {
            overlap += 1;
        }
        assert_eq!(send(ca.id, &forward), 0);
        let arrival = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let received = cc.rx.recv().await.unwrap();
                if received.packet.get(1).is_some_and(|pt| pt & 0x7f == 96) {
                    let seq = u16::from_be_bytes(received.packet[2..4].try_into().unwrap());
                    if (3000..3256).contains(&seq) {
                        screen_received += 1;
                    } else if (2000..2256).contains(&seq) {
                        video_received += 1;
                    }
                }
                if received.packet == forward {
                    break received.at;
                }
            }
        })
        .await
        .expect("audio must keep arriving during file/video load");
        worst = worst.max(arrival.duration_since(started));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    video.await.unwrap();
    tokio::time::timeout(Duration::from_secs(60), file)
        .await
        .unwrap()
        .unwrap();
    drop((ca, cc));
    stand.stop().await;
    assert!(overlap > 0, "media must overlap actual file delivery");
    assert!(
        video_received > 0,
        "competing video must actually reach the endpoint"
    );
    assert!(
        screen_received > 0,
        "competing screen packets must actually reach their independent receive circuit"
    );
    eprintln!(
        "real_multihop_media: audio_packets=50 file_overlap={overlap} video_packets={video_received} screen_packets={screen_received} packet_delay_peak_ms={:.3}",
        worst.as_secs_f64() * 1000.0
    );
    assert!(
        worst < Duration::from_millis(200),
        "network packet delay exceeded 200 ms under local video/file load: {worst:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn extended_receive_routes_interoperate_with_legacy_peer_over_real_obfs4() {
    let stand = Stand::with_links(1, true).await;
    let a = &stand.services[0];
    let c = &stand.services[1];
    let mut ca = channel(a.local_node_id(), c.local_node_id(), [0xa1; 32], [0xc1; 32]);
    let mut cc = channel(c.local_node_id(), a.local_node_id(), [0xc1; 32], [0xa1; 32]);
    cc.routes.emulate_legacy_peer_for_test();
    let registry = stand.services[3]
        .dispatcher
        .circuit_rendezvous
        .as_ref()
        .unwrap();
    wait_until(|| {
        registry.lookup(&a.onion_stream_local_cookie()).is_some()
            && registry.lookup(&c.onion_stream_local_cookie()).is_some()
    })
    .await;
    stand.copy_ads(0, 1);
    stand.copy_ads(1, 0);
    ca.routes.start(&tokio::runtime::Handle::current());
    cc.routes.start(&tokio::runtime::Handle::current());
    ca.routes.warm(LocalMediaPlane::Secondary).await;
    cc.routes.warm(LocalMediaPlane::Secondary).await;
    ca.routes.warm(LocalMediaPlane::Screen).await;
    cc.routes.warm(LocalMediaPlane::Screen).await;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if ca.routes.outgoing_for_test().await.len() == 4
                && cc.routes.outgoing_for_test().await.len() == 4
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("both versions must negotiate usable routes");
    let incoming_a = ca.routes.receive_addresses_for_test();
    let incoming_c = cc.routes.receive_addresses_for_test();
    assert_eq!(incoming_a.len(), 4);
    assert_eq!(incoming_c.len(), 2);
    // The old decoder sees only the unchanged two-address companion. Neither
    // direction claims that legacy screen/control paths are independent.
    assert_eq!(ca.routes.received_offer_for_test().unwrap()[20], 2);
    assert_eq!(cc.routes.received_offer_for_test().unwrap()[20], 2);
    for (routes, incoming) in [(&ca.routes, &incoming_c), (&cc.routes, &incoming_a)] {
        for route in routes.outgoing_for_test().await {
            assert_eq!(
                route.destination_cookie,
                incoming[[0, 1, 1, 0][route.plane as usize]].1
            );
        }
    }
    for pt in [111, 96] {
        let forward = packet(pt, 500);
        let reverse = packet(pt, 501);
        assert_eq!(send(ca.id, &forward), 0);
        assert_eq!(send(cc.id, &reverse), 0);
        expect_packet(&mut cc.rx, &forward).await;
        expect_packet(&mut ca.rx, &reverse).await;
    }
    let feedback = vec![0x80, 201, 0, 1, 0, 0, 0, 7];
    assert_eq!(send(ca.id, &feedback), 0);
    expect_packet(&mut cc.rx, &feedback).await;
    assert_eq!(send(cc.id, &feedback), 0);
    expect_packet(&mut ca.rx, &feedback).await;
    assert_eq!(super::veil_media_channel_set_screen_sharing(ca.id, 1), 0);
    assert_eq!(super::veil_media_channel_set_screen_sharing(cc.id, 1), 0);
    let forward = packet(96, 502);
    let reverse = packet(96, 503);
    assert_eq!(send(ca.id, &forward), 0);
    assert_eq!(send(cc.id, &reverse), 0);
    expect_packet(&mut cc.rx, &forward).await;
    expect_packet(&mut ca.rx, &reverse).await;
    drop((ca, cc));
    stand.stop().await;
}

/// Distinct local producers select different real first-hop sessions when
/// three middles exist. The same relay-header/queue assertions as the scarce
/// four-node stand apply to every forwarded build, probe and media cell.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_media_paths_use_distinct_first_hops_when_alternatives_exist() {
    let stand = Stand::with_middle_count(3).await;
    let a = &stand.services[0];
    let c = &stand.services[1];
    let rendezvous = &stand.services[3];
    let mut ca = channel(a.local_node_id(), c.local_node_id(), [0xa1; 32], [0xc1; 32]);
    let mut cc = channel(c.local_node_id(), a.local_node_id(), [0xc1; 32], [0xa1; 32]);
    let registry = rendezvous.dispatcher.circuit_rendezvous.as_ref().unwrap();
    wait_until(|| {
        registry.lookup(&a.onion_stream_local_cookie()).is_some()
            && registry.lookup(&c.onion_stream_local_cookie()).is_some()
    })
    .await;
    stand.copy_ads(0, 1);
    stand.copy_ads(1, 0);
    ca.routes.start(&tokio::runtime::Handle::current());
    cc.routes.start(&tokio::runtime::Handle::current());
    ca.routes.warm(LocalMediaPlane::Secondary).await;
    cc.routes.warm(LocalMediaPlane::Secondary).await;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if ca.routes.outgoing_for_test().await.len() == 3
                && cc.routes.outgoing_for_test().await.len() == 3
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    for (routes, endpoint) in [(&ca.routes, a), (&cc.routes, c)] {
        let outgoing = routes.outgoing_for_test().await;
        let file_first_hop = registry
            .lookup(&endpoint.onion_stream_local_cookie())
            .unwrap()
            .prev_link;
        assert_ne!(outgoing[0].first_hop, outgoing[1].first_hop);
        assert_ne!(outgoing[0].first_hop, file_first_hop);
        assert_ne!(outgoing[1].first_hop, file_first_hop);
    }
    for seq in 0..12 {
        let audio = packet(111, seq);
        let video = packet(96, seq);
        assert_eq!(send(ca.id, &audio), 0);
        assert_eq!(send(ca.id, &video), 0);
        expect_packets(&mut cc.rx, &[audio.clone(), video.clone()]).await;
        assert_eq!(send(cc.id, &audio), 0);
        assert_eq!(send(cc.id, &video), 0);
        expect_packets(&mut ca.rx, &[audio, video]).await;
    }
    // Rebuilding retains first-hop isolation while circuit ids change.
    let before = ca.routes.outgoing_for_test().await;
    unsafe {
        veil_media_repair_channel(ca.id);
    }
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let after = ca.routes.outgoing_for_test().await;
            if after.len() == 3
                && after.iter().all(|r| {
                    r.origin
                        != before
                            .iter()
                            .find(|old| old.plane == r.plane)
                            .unwrap()
                            .origin
                })
            {
                assert_ne!(after[0].first_hop, after[1].first_hop);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let after = packet(111, 0x79);
    assert_eq!(send(ca.id, &after), 0);
    expect_packet(&mut cc.rx, &after).await;
    drop(ca);
    drop(cc);
    for pipe in &stand.pipes {
        assert!(!pipe.is_finished(), "neutral forwarding must remain live");
    }
    stand.stop().await;
}

#[tokio::test]
async fn recoverable_file_data_uses_its_own_local_lane_through_neutral_relays() {
    verify_recoverable_file(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recoverable_file_crosses_real_obfs4_without_media_load() {
    verify_recoverable_file(true).await;
}

async fn verify_recoverable_file(real_obfs4: bool) {
    use std::sync::atomic::Ordering;
    let stand = Stand::with_links(1, real_obfs4).await;
    let a = stand.services[0].local_node_id();
    let c = stand.services[1].local_node_id();
    let mux_a = crate::anon_stream::circuit_stream_mux_for_test(a);
    let mux_c = crate::anon_stream::circuit_stream_mux_for_test(c);
    let loss = if real_obfs4 { 0 } else { 4 };
    stand.file_loss_budget.store(loss, Ordering::Release);
    let size = if real_obfs4 {
        4 * 1024 * 1024
    } else {
        64 * 1024
    };
    let expected: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let outgoing = mux_a.open(veil_onion_stream::Addr {
            node: c,
            app: [0; 32],
        });
        let send = async {
            outgoing.write_all(&expected).await.unwrap();
            outgoing.finish().await.unwrap();
        };
        let receive = async {
            let (mut incoming, _) = mux_c.accept().await.unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let count = incoming.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            assert_eq!(
                bytes, expected,
                "ARQ must restore the complete file after datagram loss"
            );
        };
        tokio::join!(send, receive);
    })
    .await;
    let dropped = stand.file_dropped.load(Ordering::Acquire);
    let cells = stand.file_cells.load(Ordering::Acquire);
    drop((mux_a, mux_c));
    stand.stop().await;
    result.expect("recoverable file must complete through both neutral relays");
    assert_eq!(dropped, loss);
    if !real_obfs4 {
        assert!(cells > 4);
    }
}
