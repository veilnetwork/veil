//! Drive the real sealed dispatcher and echo's SDK -> Unix IPC -> source
//! envelope boundary. The last session sink is captured, so these tests prove
//! route selection/crypto/ownership, not physical Internet latency.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use veil_proto::{
    AppRtDataPayload, HEADER_SIZE, codec,
    family::{AppMsg, FrameFamily},
};
use veil_types::FrameBroadcaster;

const IDENTITY: [u8; 32] = [0xa3; 32];
const DEVICE: [u8; 32] = [0xa4; 32];
const PEER: [u8; 32] = [0xb3; 32];
const PEER_DEVICE: [u8; 32] = [0xb4; 32];
const RELAY: [u8; 32] = [0xe3; 32];
const TX: [u8; 32] = [0x63; 32];
const RX: [u8; 32] = [0x64; 32];
static FIXTURE_LOCK: StdMutex<()> = StdMutex::new(());
type Captured = ([u8; 32], u8, Vec<u8>);

struct Capture(std::sync::mpsc::Sender<Captured>);
impl FrameBroadcaster for Capture {
    fn send_to(&self, peer: &[u8; 32], lane: u8, bytes: Vec<u8>) -> bool {
        self.0.send((*peer, lane, bytes)).is_ok()
    }
    fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {
        panic!("probe broadcast");
    }
    fn active_node_ids(&self) -> Vec<[u8; 32]> {
        vec![PEER, RELAY]
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    runtime: tokio::runtime::Runtime,
    stop: tokio::sync::watch::Sender<bool>,
    server: Option<tokio::task::JoinHandle<()>>,
    handle: *mut VeilHandle,
    relay_handle: *mut VeilHandle,
    direct: *mut VeilApp,
    relay: *mut VeilApp,
    captured: std::sync::mpsc::Receiver<Captured>,
    channels: Vec<u64>,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("probe.sock");
        let runtime = build_runtime().unwrap();
        let (stop, stop_rx) = tokio::sync::watch::channel(false);
        let (tx, captured) = std::sync::mpsc::channel();
        let mut server = veil_ipc::IpcServer::new(
            veil_ipc::IpcEndpoint::Unix(socket.clone()),
            stop_rx,
            Arc::new(veil_app::AppEndpointRegistry::new()),
            DEVICE,
        )
        .with_bind_node_id(IDENTITY)
        .with_session_tx_registry(Arc::new(Capture(tx)));
        let server = runtime.spawn(async move {
            server.run().await.unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        while !socket.exists() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let path = std::ffi::CString::new(socket.to_str().unwrap()).unwrap();
        let handle = unsafe {
            veil_connect(
                path.as_bytes().as_ptr(),
                path.as_bytes().len(),
                ptr::null_mut(),
            )
        };
        assert!(!handle.is_null());
        let relay_handle = unsafe {
            veil_connect(
                path.as_bytes().as_ptr(),
                path.as_bytes().len(),
                ptr::null_mut(),
            )
        };
        assert!(!relay_handle.is_null());
        let ns = c"xveil";
        let name = c"probe-test";
        let direct = unsafe {
            veil_bind_named(
                handle,
                ns.to_bytes().as_ptr(),
                ns.to_bytes().len(),
                name.to_bytes().as_ptr(),
                name.to_bytes().len(),
                13,
                ptr::null_mut(),
            )
        };
        let relay = unsafe {
            veil_bind_device_scoped(
                relay_handle,
                ns.to_bytes().as_ptr(),
                ns.to_bytes().len(),
                name.to_bytes().as_ptr(),
                name.to_bytes().len(),
                13,
                ptr::null_mut(),
            )
        };
        assert!(!direct.is_null() && !relay.is_null());
        Self {
            _dir: dir,
            runtime,
            stop,
            server: Some(server),
            handle,
            relay_handle,
            direct,
            relay,
            captured,
            channels: vec![],
        }
    }

    fn paths(&self) -> [VeilMediaProbePath; 2] {
        [
            VeilMediaProbePath {
                app: self.direct,
                peer_node_id: PEER,
                peer_app_id: direct_media_source_app(&PEER, "xveil", "probe-test"),
                peer_endpoint_id: 13,
            },
            VeilMediaProbePath {
                app: self.relay,
                peer_node_id: PEER_DEVICE,
                peer_app_id: direct_media_source_app(&PEER_DEVICE, "xveil", "probe-test"),
                peer_endpoint_id: 13,
            },
        ]
    }

    fn channel(&mut self, route: ProbeRoute) -> (u64, mpsc::Receiver<QueuedMediaPacket>) {
        let paths = self.paths();
        let app = HandleTable::get(app_table(), paths[route.index()].app as usize).unwrap();
        let peer = paths[route.index()].peer_node_id;
        let cipher = Arc::new(media::cipher_for_test(&peer, &TX, &RX).unwrap());
        let (tx, rx) = mpsc::channel(4);
        let (video, _) = mpsc::channel(4);
        let id = MEDIA_NEXT_ID.fetch_add(1, Ordering::Relaxed);
        MEDIA_CHANNELS.write().unwrap().insert(
            id,
            MediaChannel {
                path_probe: None,
                ingress: MediaIngress::new(tx, MediaVideoIngress::Packets(video)),
                repair_tx: None,
                peer,
                task: self.runtime.spawn(std::future::pending()),
                video_task: None,
                screen_task: None,
                feedback_task: None,
                video_sender: None,
                screen_sender: None,
                sender_app_id: Some(app.app_id),
                control_destination: None,
                direct_seq: None,
                batching: None,
                cipher,
                relay_stats: (route == ProbeRoute::Relay)
                    .then(|| Arc::new(RelayMediaStats::default())),
                routes: None,
            },
        );
        self.channels.push(id);
        assert_eq!(
            unsafe { veil_media_channel_configure_path_probes(id, &paths[0], &paths[1]) },
            0
        );
        // A reused native channel does not reset a pending ledger.
        assert_eq!(
            unsafe { veil_media_channel_configure_path_probes(id, &paths[0], &paths[1]) },
            0
        );
        (id, rx)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for channel in &self.channels {
            unsafe { veil_media_close_channel(*channel) };
        }
        unsafe {
            veil_app_close(self.direct);
            veil_app_close(self.relay);
            veil_close(self.handle);
            veil_close(self.relay_handle);
        }
        self.stop.send(true).unwrap();
        if let Some(server) = self.server.take() {
            self.runtime.block_on(server).unwrap();
        }
    }
}

extern "C" fn count_media(ctx: *mut c_void, _: *const u8, _: usize) {
    unsafe { &*(ctx as *const AtomicUsize) }.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn a_relay_receiver_accepts_authenticated_media_from_both_pinned_paths() {
    let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut fixture = Fixture::new();
    let (relay, _) = fixture.channel(ProbeRoute::Relay);
    let deliveries = AtomicUsize::new(0);
    assert_eq!(
        unsafe {
            veil_media_set_recv_callback(
                relay,
                Some(count_media),
                (&deliveries as *const AtomicUsize).cast_mut().cast(),
            )
        },
        0
    );
    // No callback was committed to the candidate; closing it must not steal
    // either live receive address from the still-active relay engine.
    let (candidate, _) = fixture.channel(ProbeRoute::Direct);
    unsafe { veil_media_close_channel(candidate) };
    let peer = media::cipher_for_test(&DEVICE, &RX, &TX).unwrap();
    let direct_audio = peer.seal(&[0x80, 111, 1, 2]).unwrap().into_vec();
    media::dispatch_inbound_auto(PEER, &direct_audio);
    assert_eq!(
        deliveries.load(Ordering::Relaxed),
        1,
        "peer can switch its sender before our outgoing candidate qualifies"
    );
    media::dispatch_inbound_auto(PEER_DEVICE, &direct_audio);
    assert_eq!(
        deliveries.load(Ordering::Relaxed),
        1,
        "aliases share replay protection"
    );
    let relay_audio = peer.seal(&[0x80, 111, 3, 4]).unwrap().into_vec();
    media::dispatch_inbound_auto(PEER_DEVICE, &relay_audio);
    assert_eq!(deliveries.load(Ordering::Relaxed), 2);
    let stranger_audio = peer.seal(&[0x80, 111, 5, 6]).unwrap().into_vec();
    media::dispatch_inbound_auto([0xc5; 32], &stranger_audio);
    let mut corrupt = stranger_audio.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    media::dispatch_inbound_auto(PEER, &corrupt);
    assert_eq!(
        deliveries.load(Ordering::Relaxed),
        2,
        "pin and seal still gate RTP"
    );
    unsafe { veil_media_set_recv_callback(relay, None, ptr::null_mut()) };
    for address in [PEER, PEER_DEVICE] {
        media::dispatch_inbound_auto(address, &stranger_audio);
    }
    assert_eq!(
        deliveries.load(Ordering::Relaxed),
        2,
        "unregister clears both aliases"
    );
}

#[test]
fn closing_replaced_alias_owner_cannot_clear_the_new_receiver() {
    let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut fixture = Fixture::new();
    let (old, _) = fixture.channel(ProbeRoute::Relay);
    let (new, _) = fixture.channel(ProbeRoute::Direct);
    let old_deliveries = AtomicUsize::new(0);
    let new_deliveries = AtomicUsize::new(0);
    for (channel, counter) in [(old, &old_deliveries), (new, &new_deliveries)] {
        assert_eq!(
            unsafe {
                veil_media_set_recv_callback(
                    channel,
                    Some(count_media),
                    (counter as *const AtomicUsize).cast_mut().cast(),
                )
            },
            0
        );
    }
    unsafe { veil_media_close_channel(old) };
    let peer = media::cipher_for_test(&DEVICE, &RX, &TX).unwrap();
    for address in [PEER, PEER_DEVICE] {
        let audio = peer.seal(&[0x80, 111, 7, 8]).unwrap().into_vec();
        media::dispatch_inbound_auto(address, &audio);
    }
    assert_eq!(old_deliveries.load(Ordering::Relaxed), 0);
    assert_eq!(new_deliveries.load(Ordering::Relaxed), 2);
    unsafe { veil_media_close_channel(new) };
    for address in [PEER, PEER_DEVICE] {
        let audio = peer.seal(&[0x80, 111, 9, 10]).unwrap().into_vec();
        media::dispatch_inbound_auto(address, &audio);
    }
    assert_eq!(
        new_deliveries.load(Ordering::Relaxed),
        2,
        "close clears every owned alias"
    );
}

#[test]
fn candidate_alias_requires_its_sealed_reply_and_never_counts_as_audio() {
    let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut fixture = Fixture::new();
    let (old, _) = fixture.channel(ProbeRoute::Direct);
    let (candidate, mut rx) = fixture.channel(ProbeRoute::Relay);
    let deliveries = AtomicUsize::new(0);
    assert_eq!(
        unsafe {
            veil_media_set_recv_callback(
                old,
                Some(count_media),
                (&deliveries as *const AtomicUsize).cast_mut().cast(),
            )
        },
        0
    );
    assert_eq!(veil_media_channel_begin_path_probe(candidate, 600), 0);
    assert_eq!(
        veil_media_channel_begin_path_probe(candidate, 600),
        1,
        "pending attempt is not replaced"
    );
    assert_eq!(
        veil_media_channel_poll_path_probe(candidate),
        0,
        "local enqueue is no proof"
    );
    let request = ProbeControl::decode(&rx.blocking_recv().unwrap().payload).unwrap();
    assert!(rx.try_recv().is_err());
    let peer = media::cipher_for_test(&DEVICE, &RX, &TX).unwrap();
    let reply = peer
        .seal(&request.reply().unwrap().encode())
        .unwrap()
        .into_vec();
    let mut corrupt = reply.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    media::dispatch_inbound_auto(PEER_DEVICE, &corrupt);
    assert_eq!(veil_media_channel_poll_path_probe(candidate), 0);
    media::dispatch_inbound_auto(PEER_DEVICE, &reply);
    assert_eq!(veil_media_channel_poll_path_probe(candidate), 1);
    assert_eq!(deliveries.load(Ordering::Relaxed), 0);
    media::dispatch_inbound_auto(PEER_DEVICE, &reply); // duplicate cannot add activity
    assert_eq!(deliveries.load(Ordering::Relaxed), 0);
    let audio = peer.seal(&[0x80, 111, 1, 2]).unwrap().into_vec();
    media::dispatch_inbound_auto(PEER, &audio);
    assert_eq!(
        deliveries.load(Ordering::Relaxed),
        1,
        "old receiver still owns RTP"
    );
    unsafe { veil_media_close_channel(candidate) };
    media::dispatch_inbound_auto(PEER_DEVICE, &reply);
    assert_eq!(veil_media_channel_poll_path_probe(candidate), -1);
    unsafe { veil_media_set_recv_callback(old, None, ptr::null_mut()) };
}

#[test]
fn a_short_observation_also_bounds_the_queued_challenge() {
    let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut fixture = Fixture::new();
    let (candidate, mut rx) = fixture.channel(ProbeRoute::Relay);
    let before = tokio::time::Instant::now();
    assert_eq!(veil_media_channel_begin_path_probe(candidate, 100), 0);
    let queued = rx.blocking_recv().unwrap();
    assert!(queued.deadline <= before + Duration::from_millis(125));
    assert!(ProbeControl::decode(&queued.payload).is_some());
    unsafe { veil_media_close_channel(candidate) };
    assert_eq!(veil_media_channel_poll_path_probe(candidate), -1);
    assert!(rx.try_recv().is_err());
}

#[test]
fn a_lost_first_challenge_retries_without_stealing_the_live_audio_receiver() {
    let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut fixture = Fixture::new();
    let (old, _) = fixture.channel(ProbeRoute::Direct);
    let (candidate, mut rx) = fixture.channel(ProbeRoute::Relay);
    let deliveries = AtomicUsize::new(0);
    assert_eq!(
        unsafe {
            veil_media_set_recv_callback(
                old,
                Some(count_media),
                (&deliveries as *const AtomicUsize).cast_mut().cast(),
            )
        },
        0
    );
    let peer = media::cipher_for_test(&DEVICE, &RX, &TX).unwrap();
    let audio = peer.seal(&[0x80, 111, 1, 2]).unwrap().into_vec();
    media::dispatch_inbound_auto(PEER, &audio);
    assert_eq!(deliveries.load(Ordering::Relaxed), 1);

    assert_eq!(veil_media_channel_begin_path_probe(candidate, 600), 0);
    // Model the lossy independent sender's first warm-up packet being lost.
    let first = rx.blocking_recv().unwrap().payload;
    assert_eq!(veil_media_channel_poll_path_probe(candidate), 0);
    assert!(rx.try_recv().is_err());
    std::thread::sleep(Duration::from_millis(260));
    assert_eq!(veil_media_channel_poll_path_probe(candidate), 0);
    let retry = rx
        .try_recv()
        .expect("fresh challenge after the warm-up loss");
    assert_eq!(retry.payload, first);
    let request = ProbeControl::decode(&retry.payload).unwrap();
    let reply = peer
        .seal(&request.reply().unwrap().encode())
        .unwrap()
        .into_vec();
    media::dispatch_inbound_auto(PEER_DEVICE, &reply);
    assert_eq!(veil_media_channel_poll_path_probe(candidate), 1);
    assert_eq!(
        deliveries.load(Ordering::Relaxed),
        1,
        "control is never audio activity"
    );
    assert!(rx.try_recv().is_err());
    media::dispatch_inbound_auto(PEER_DEVICE, &reply);
    let audio = peer.seal(&[0x80, 111, 3, 4]).unwrap().into_vec();
    media::dispatch_inbound_auto(PEER, &audio);
    assert_eq!(
        deliveries.load(Ordering::Relaxed),
        2,
        "old audio still owns its receiver"
    );
    unsafe { veil_media_close_channel(candidate) };
    assert_eq!(veil_media_channel_poll_path_probe(candidate), -1);
    unsafe { veil_media_set_recv_callback(old, None, ptr::null_mut()) };
}

#[test]
fn a_relay_request_uses_a_neutral_relay_echo_even_while_direct_is_active() {
    let _lock = FIXTURE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut fixture = Fixture::new();
    let (old, _) = fixture.channel(ProbeRoute::Direct);
    let deliveries = AtomicUsize::new(0);
    assert_eq!(
        unsafe {
            veil_media_set_recv_callback(
                old,
                Some(count_media),
                (&deliveries as *const AtomicUsize).cast_mut().cast(),
            )
        },
        0
    );
    let peer = media::cipher_for_test(&DEVICE, &RX, &TX).unwrap();
    for route in [ProbeRoute::Relay, ProbeRoute::Direct] {
        let probe = RouteProbe::begin(route, Instant::now(), Duration::from_millis(600));
        let request = peer.seal(&probe.request_payload()).unwrap().into_vec();
        // The advertised/claimed source is NOT a reply destination.
        media::dispatch_inbound_auto([0xff; 32], &request);
        let (target, lane, bytes) = fixture
            .captured
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        assert_eq!(lane, veil_proto::priority::REALTIME);
        let header = codec::decode_header(&bytes).unwrap();
        let payload = if route == ProbeRoute::Relay {
            assert_eq!(header.family, FrameFamily::Delivery as u8);
            assert_eq!(
                header.priority(),
                veil_proto::priority::INTERACTIVE,
                "relay wire stays neutral"
            );
            let forward =
                veil_proto::delivery::ForwardPayload::decode(&bytes[HEADER_SIZE..]).unwrap();
            assert_eq!(forward.envelope.sender_node_id, DEVICE);
            assert_eq!(
                forward.envelope.src_app_id,
                fixture.paths()[1].app_id_for_test()
            );
            assert_eq!(forward.envelope.recipient.node_id, PEER_DEVICE);
            assert_ne!(target, [0xff; 32]);
            forward.envelope.payload
        } else {
            assert_eq!(target, PEER);
            assert_eq!(header.family, FrameFamily::App as u8);
            assert_eq!(header.msg_type, AppMsg::AppRtData as u16);
            let rt = AppRtDataPayload::decode(&bytes[HEADER_SIZE..]).unwrap();
            assert_eq!(rt.src_app_id, fixture.paths()[0].app_id_for_test());
            rt.payload
        };
        let reply = ProbeControl::decode(&peer.open(&payload).unwrap()).unwrap();
        assert!(reply.reply().is_none());
        let mut probe = probe;
        assert!(matches!(
            probe.observe(reply, Instant::now()),
            ProbeStatus::Qualified(_)
        ));
        assert_eq!(deliveries.load(Ordering::Relaxed), 0);
        // Echo limiter is per call, not a source-side classification at a relay.
        std::thread::sleep(Duration::from_millis(210));
        while fixture.captured.try_recv().is_ok() {}
    }
    unsafe { veil_media_set_recv_callback(old, None, ptr::null_mut()) };
}

impl VeilMediaProbePath {
    fn app_id_for_test(&self) -> [u8; 32] {
        HandleTable::get(app_table(), self.app as usize)
            .unwrap()
            .app_id
    }
}
