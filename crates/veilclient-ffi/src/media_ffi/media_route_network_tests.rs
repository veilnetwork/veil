//! Real node runtimes, builders, relay dispatchers and native media pumps.
//! Session outboxes are joined in memory, exercising encrypted onion splicing
//! and call negotiation. This does not measure QUIC congestion or acoustics.
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

struct Stand {
    _dirs: Vec<tempfile::TempDir>,
    nodes: Vec<NodeRuntime>,
    services: Vec<NodeServices>,
    pipes: Vec<tokio::task::JoinHandle<()>>,
    delivered_cells: Arc<Mutex<HashMap<(usize, u32), usize>>>,
    file_loss_budget: Arc<std::sync::atomic::AtomicUsize>,
    file_dropped: Arc<std::sync::atomic::AtomicUsize>,
    file_cells: Arc<std::sync::atomic::AtomicUsize>,
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
        };
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
            cfg.dht.service_budget_bytes_per_hour = Some(u64::MAX);
            veil_cfg::save_config(&path, &cfg).unwrap();
            let node = NodeRuntime::start(&path, true).await.unwrap();
            s.services.push(node.access());
            s.nodes.push(node);
            s._dirs.push(dir);
        }
        // A(0) and C(1) -> middle(2) -> rendezvous(3). Relays use ordinary
        // priority for every cell; producer lanes are endpoint-local.
        let middles: Vec<_> = std::iter::once(2).chain(4..middle_count + 3).collect();
        for &middle in &middles {
            for (a, b) in [(0, middle), (1, middle), (middle, 3)] {
                s.connect(a, b);
                s.connect(b, a);
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
                    "tcp://127.0.0.1:1",
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
                assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
                if from >= 2 {
                    assert_eq!(priority, veil_proto::priority::INTERACTIVE);
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
    _files: mpsc::Receiver<(veil_onion_stream::Addr, Vec<u8>)>,
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
    MEDIA_CHANNELS.lock().unwrap().insert(
        id,
        MediaChannel {
            path_probe: None,
            ingress: MediaIngress::with_screen(
                tx_hi,
                MediaVideoIngress::Packets(tx_video),
                MediaVideoIngress::Packets(tx_screen),
            ),
            repair_tx: Some([repair_hi, repair_video, repair_screen]),
            peer,
            task,
            video_task: Some(video_task),
            screen_task: Some(screen_task),
            video_sender: None,
            screen_sender: None,
            sender_app_id: None,
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
        _files: files,
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
    .unwrap()
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
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if ca.routes.outgoing_for_test().await.len() == 2
                && cc.routes.outgoing_for_test().await.len() == 2
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
    assert_eq!(incoming.len(), 2);
    for route in &outgoing {
        assert_eq!(route.destination_cookie, incoming[route.plane as usize].1);
    }
    assert_ne!(incoming[0].1, incoming[1].1);
    assert!(
        incoming
            .iter()
            .all(|(_, cookie)| *cookie != c.onion_stream_local_cookie())
    );
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
        let channels = MEDIA_CHANNELS.lock().unwrap();
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
            if new.len() == 2
                && new
                    .iter()
                    .all(|r| r.origin != outgoing[r.plane as usize].origin)
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
    // Keep the two-address VMR1 offer for old peers; the third producer
    // opens its own circuit and return registration to the secondary address.
    assert_eq!(super::veil_media_channel_set_screen_sharing(ca.id, 1), 0);
    let screen = packet(96, 0x75);
    assert_eq!(send(ca.id, &screen), 0);
    tokio::time::timeout(Duration::from_secs(15), async {
        while ca.routes.outgoing_for_test().await.len() != 3 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let outgoing_three = ca.routes.outgoing_for_test().await;
    assert_eq!(cc.routes.receive_addresses_for_test().len(), 2);
    assert_eq!(outgoing_three[2].destination_cookie, incoming[1].1);
    for other in &outgoing_three[..2] {
        assert_ne!(outgoing_three[2].origin, other.origin);
        assert_ne!(outgoing_three[2].return_cookie, other.return_cookie);
    }
    // The first cell may expire during route construction. Fresh cells must
    // decrypt at the other endpoint, not merely enter a source queue.
    assert_eq!(send(ca.id, &screen), 0);
    expect_packet(&mut cc.rx, &screen).await;
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
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if ca.routes.outgoing_for_test().await.len() == 2
                && cc.routes.outgoing_for_test().await.len() == 2
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
            if after.len() == 2
                && after
                    .iter()
                    .all(|r| r.origin != before[r.plane as usize].origin)
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
    use std::sync::atomic::Ordering;
    let stand = Stand::new().await;
    let a = stand.services[0].local_node_id();
    let c = stand.services[1].local_node_id();
    let mux_a = crate::anon_stream::circuit_stream_mux_for_test(a);
    let mux_c = crate::anon_stream::circuit_stream_mux_for_test(c);
    stand.file_loss_budget.store(4, Ordering::Release);
    let expected: Vec<u8> = (0..64 * 1024).map(|index| (index % 251) as u8).collect();
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
    assert_eq!(dropped, 4);
    assert!(cells > 4);
}
