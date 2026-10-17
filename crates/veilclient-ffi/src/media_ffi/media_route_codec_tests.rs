// Optional real-codec extension of the owned multihop fixture. These tests
// require a separately built media library with synthetic ADM test hooks;
// they never create a microphone, speaker, camera or installed application.
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;

struct CodecLibrary(*mut c_void);

impl CodecLibrary {
    fn open() -> Self {
        Self::from_env("VEIL_MEDIA_CODEC_TEST_DYLIB")
    }

    fn from_env(name: &str) -> Self {
        let path = std::env::var_os(name)
            .unwrap_or_else(|| panic!("set {name} to the owned test library"));
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // RTLD_NOW must resolve the actual exported SDK functions in this
        // executable. Loading another SDK would create a second channel table.
        let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        assert!(
            !handle.is_null(),
            "native codec load failed: {}",
            Self::error()
        );
        Self(handle)
    }

    fn error() -> String {
        let error = unsafe { libc::dlerror() };
        if error.is_null() {
            "unknown dynamic-loader error".into()
        } else {
            unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned()
        }
    }

    unsafe fn symbol<T: Copy>(&self, name: &CStr) -> T {
        assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<*mut c_void>());
        let symbol = unsafe { libc::dlsym(self.0, name.as_ptr()) };
        assert!(!symbol.is_null(), "missing {name:?}: {}", Self::error());
        unsafe { std::mem::transmute_copy(&symbol) }
    }
}

impl Drop for CodecLibrary {
    fn drop(&mut self) {
        unsafe { libc::dlclose(self.0) };
    }
}

#[test]
#[ignore = "requires the owned test-hooks media dylib; no production SDK is loaded"]
fn native_codec_library_resolves_this_test_executable_sdk() {
    let library = CodecLibrary::open();
    // Requiring the test-only synthetic constructor prevents this path from
    // silently becoming an ordinary device-backed media test.
    let _: unsafe extern "C" fn(u64, *const u8, *const u8) -> *mut c_void =
        unsafe { library.symbol(c"veil_media_test_codec_create_unstarted") };
    let _: unsafe extern "C" fn(*mut c_void, c_int) -> c_int =
        unsafe { library.symbol(c"veil_media_test_audio_capture_tone") };
    let _: unsafe extern "C" fn(*mut c_void, *mut i16, usize) -> c_int =
        unsafe { library.symbol(c"veil_media_test_audio_playout_pcm") };
}

type Capture = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type Playout = unsafe extern "C" fn(*mut c_void, *mut i16, usize) -> c_int;
struct NativeApi {
    _library: CodecLibrary,
    create: unsafe extern "C" fn(u64, *const u8, *const u8) -> *mut c_void,
    feedback: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
    audio: unsafe extern "C" fn(*mut c_void, c_int, c_int) -> c_int,
    video: unsafe extern "C" fn(*mut c_void, c_int, c_int, c_int, c_int) -> c_int,
    anchor: unsafe extern "C" fn(*mut c_void, c_int) -> c_int,
    stats: unsafe extern "C" fn(*mut c_void) -> *mut c_char,
    free: unsafe extern "C" fn(*mut c_char),
    destroy: unsafe extern "C" fn(*mut c_void),
    frame: unsafe extern "C" fn(*mut c_void, *mut u8, c_int, *mut c_int, *mut c_int) -> c_int,
    capture: Capture,
    playout: Playout,
}
impl NativeApi {
    fn open() -> Self {
        let library = CodecLibrary::open();
        unsafe {
            Self {
                create: library.symbol(c"veil_media_test_codec_create_unstarted"),
                feedback: library.symbol(c"veil_media_engine_set_independent_transport_feedback"),
                audio: library.symbol(c"veil_media_engine_start_audio"),
                video: library.symbol(c"veil_media_engine_start_video"),
                anchor: library.symbol(c"veil_media_test_audio_timing_anchor"),
                stats: library.symbol(c"veil_media_engine_get_stats"),
                free: library.symbol(c"veil_media_free_string"),
                destroy: library.symbol(c"veil_media_engine_destroy"),
                frame: library.symbol(c"veil_media_engine_get_video_frame"),
                capture: library.symbol(c"veil_media_test_audio_capture_tone"),
                playout: library.symbol(c"veil_media_test_audio_playout_pcm"),
                _library: library,
            }
        }
    }
}
struct NativePair<'a> {
    api: &'a NativeApi,
    engines: [*mut c_void; 2],
}
impl<'a> NativePair<'a> {
    fn new(api: &'a NativeApi, channels: &[&Channel; 2], nodes: [[u8; 32]; 2]) -> Self {
        let mut pair = Self {
            api,
            engines: [std::ptr::null_mut(); 2],
        };
        for i in 0..2 {
            let engine =
                unsafe { (api.create)(channels[i].id, nodes[i].as_ptr(), nodes[1 - i].as_ptr()) };
            pair.engines[i] = engine;
            assert!(!engine.is_null(), "synthetic codec construction failed");
            // Match anonymous pre-start controls: no non-onion packet-overhead
            // hint or 1000-byte RTP override. The ADM alone is synthetic.
            assert_eq!(unsafe { (api.feedback)(engine, 1) }, 0);
            assert_eq!(unsafe { (api.audio)(engine, 1, 1) }, 0);
            assert_eq!(unsafe { (api.anchor)(engine, i as c_int) }, 0);
        }
        pair
    }
    fn stats(&self, i: usize) -> serde_json::Value {
        let raw = unsafe { (self.api.stats)(self.engines[i]) };
        assert!(!raw.is_null());
        let bytes = unsafe { CStr::from_ptr(raw) }.to_bytes().to_vec();
        unsafe { (self.api.free)(raw) };
        serde_json::from_slice(&bytes).unwrap()
    }
}
impl Drop for NativePair<'_> {
    fn drop(&mut self) {
        for engine in self.engines.iter().rev().copied().filter(|e| !e.is_null()) {
            unsafe { (self.api.destroy)(engine) };
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PcmRow {
    t: f64,
    source_at: f64,
    rms: f64,
    freq: f64,
    interval_ms: f64,
    source_tick: u64,
    side: u32,
    source_freq: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PcmStats {
    max_interval_ms: f64,
    late_intervals: u64,
    dropped_rows: u64,
    failures: [u64; 2],
    ticks: u64,
    max_wake_lateness_ms: f64,
    max_callback_ms: f64,
    max_publication_ms: f64,
    qos_supported: i32,
    qos_result: i32,
    qos_requested: i32,
    qos_actual: i32,
    timer_error: i32,
}
struct PcmCapture {
    origin: f64,
    rows: Vec<PcmRow>,
    stats: PcmStats,
}
struct AudioClock<'a, 'media> {
    _library: &'a CodecLibrary,
    _engines: &'a NativePair<'media>,
    handle: *mut c_void,
    now: unsafe extern "C" fn() -> f64,
    poll: unsafe extern "C" fn(*mut c_void, *mut PcmRow, usize, *mut PcmStats) -> usize,
    request_stop: unsafe extern "C" fn(*mut c_void),
    finished: unsafe extern "C" fn(*mut c_void) -> c_int,
    destroy: unsafe extern "C" fn(*mut c_void),
    origin: f64,
    rows: Vec<PcmRow>,
    stats: PcmStats,
}
impl<'a, 'media> AudioClock<'a, 'media> {
    fn start(library: &'a CodecLibrary, engines: &'a NativePair<'media>) -> Self {
        let size: unsafe extern "C" fn() -> usize =
            unsafe { library.symbol(c"stand_pcm_row_size") };
        assert_eq!(
            unsafe { size() },
            std::mem::size_of::<PcmRow>(),
            "PCM row ABI mismatch"
        );
        let size: unsafe extern "C" fn() -> usize =
            unsafe { library.symbol(c"stand_pcm_stats_size") };
        assert_eq!(
            unsafe { size() },
            std::mem::size_of::<PcmStats>(),
            "PCM stats ABI mismatch"
        );
        let now: unsafe extern "C" fn() -> f64 = unsafe { library.symbol(c"stand_pcm_now") };
        let start: unsafe extern "C" fn(
            Capture,
            Playout,
            *mut c_void,
            *mut c_void,
            f64,
            c_int,
            c_int,
        ) -> *mut c_void = unsafe { library.symbol(c"stand_pcm_start") };
        // Resolve every operation before starting a thread that borrows the
        // engines. A missing export must fail before any callback can run.
        let poll = unsafe { library.symbol(c"stand_pcm_poll") };
        let request_stop = unsafe { library.symbol(c"stand_pcm_request_stop") };
        let finished = unsafe { library.symbol(c"stand_pcm_finished") };
        let destroy = unsafe { library.symbol(c"stand_pcm_destroy") };
        let origin = unsafe { now() };
        let handle = unsafe {
            start(
                engines.api.capture,
                engines.api.playout,
                engines.engines[0],
                engines.engines[1],
                origin,
                1010,
                1,
            )
        };
        assert!(!handle.is_null());
        Self {
            _library: library,
            _engines: engines,
            handle,
            now,
            poll,
            request_stop,
            finished,
            destroy,
            origin,
            rows: Vec::with_capacity(12_500),
            stats: PcmStats::default(),
        }
    }
    fn elapsed(&self) -> f64 {
        (unsafe { (self.now)() }) - self.origin
    }
    fn drain(&mut self) {
        let mut rows = [PcmRow::default(); 1024];
        loop {
            let count =
                unsafe { (self.poll)(self.handle, rows.as_mut_ptr(), rows.len(), &mut self.stats) };
            self.rows.extend_from_slice(&rows[..count]);
            assert!(
                self.rows.len() <= 13_000,
                "bounded sixty-second capture overflow"
            );
            if count < rows.len() {
                break;
            }
        }
    }
    fn stop(&mut self) {
        unsafe { (self.request_stop)(self.handle) };
        let deadline = Instant::now() + Duration::from_secs(5);
        while unsafe { (self.finished)(self.handle) } == 0 {
            assert!(Instant::now() < deadline, "native audio clock did not stop");
            std::thread::sleep(Duration::from_millis(2));
        }
        self.drain();
        unsafe { (self.destroy)(self.handle) };
        self.handle = std::ptr::null_mut();
    }
    fn finish(mut self) -> PcmCapture {
        self.stop();
        PcmCapture {
            origin: self.origin,
            rows: std::mem::take(&mut self.rows),
            stats: self.stats,
        }
    }
}
impl Drop for AudioClock<'_, '_> {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { (self.destroy)(self.handle) };
        }
    }
}

async fn codec_routes_ready(stand: &Stand, channels: &[&Channel; 2]) {
    let registry = stand.services[3]
        .dispatcher
        .circuit_rendezvous
        .as_ref()
        .unwrap();
    wait_until(|| {
        channels.iter().enumerate().all(|(i, _)| {
            registry
                .lookup(&stand.services[i].onion_stream_local_cookie())
                .is_some()
        })
    })
    .await;
    stand.copy_ads(0, 1);
    stand.copy_ads(1, 0);
    for channel in channels {
        channel.routes.start(&tokio::runtime::Handle::current());
    }
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            if channels[0].routes.outgoing_for_test().await.len() >= 3
                && channels[1].routes.outgoing_for_test().await.len() >= 3
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        for channel in channels {
            channel.routes.warm(LocalMediaPlane::Screen).await;
        }
        loop {
            if channels[0].routes.outgoing_for_test().await.len() == 4
                && channels[1].routes.outgoing_for_test().await.len() == 4
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("four real media routes must negotiate before codec capture");
    for (side, channel) in channels.iter().enumerate() {
        let peer = channels[1 - side].routes.receive_addresses_for_test();
        assert_eq!(peer.len(), 4);
        for route in channel.routes.outgoing_for_test().await {
            assert_eq!(route.destination_cookie, peer[route.plane as usize].1);
            assert_eq!(route.first_hop, stand.services[2].local_node_id());
            let middle = stand.services[2]
                .dispatcher
                .circuit_table
                .as_ref()
                .unwrap()
                .lookup_forward(&stand.services[side].local_node_id(), route.origin)
                .unwrap();
            assert_eq!(middle.next_link, Some(stand.services[3].local_node_id()));
            let end = stand.services[3]
                .dispatcher
                .circuit_table
                .as_ref()
                .unwrap()
                .lookup_forward(&stand.services[2].local_node_id(), middle.circuit_id_out)
                .unwrap();
            assert!(end.next_link.is_none());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real obfs4 route keepalive stand"]
async fn private_codec_routes_survive_idle_keepalive() {
    check_private_route_keepalive(false, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real obfs4 route keepalive stand"]
async fn private_codec_routes_survive_active_primary_keepalive() {
    check_private_route_keepalive(true, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real obfs4 route keepalive stand"]
async fn private_codec_routes_survive_primary_and_feedback_keepalive() {
    check_private_route_keepalive(true, true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real obfs4 route liveness under sustained endpoint pressure"]
async fn private_codec_routes_survive_sustained_source_pressure() {
    check_private_route_keepalive(true, true, true).await;
}

async fn check_private_route_keepalive(primary: bool, feedback: bool, pressure: bool) {
    if veil_session::rt_trace::rt_trace_enabled() {
        struct RouteTrace;
        impl log::Log for RouteTrace {
            fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
                metadata.target() == "veilclient_ffi::anon_stream::media_routes"
            }
            fn log(&self, record: &log::Record<'_>) {
                if self.enabled(record.metadata()) {
                    eprintln!("{}", record.args());
                }
            }
            fn flush(&self) {}
        }
        static TRACE: RouteTrace = RouteTrace;
        if log::set_logger(&TRACE).is_ok() {
            log::set_max_level(log::LevelFilter::Info);
        }
    }
    let stand = Stand::with_links(1, true).await;
    let a = stand.services[0].local_node_id();
    let c = stand.services[1].local_node_id();
    let mut ca = channel(a, c, [0xa1; 32], [0xc1; 32]);
    let mut cc = channel(c, a, [0xc1; 32], [0xa1; 32]);
    codec_routes_ready(&stand, &[&ca, &cc]).await;
    let before = [
        ca.routes.outgoing_for_test().await,
        cc.routes.outgoing_for_test().await,
    ];
    if primary {
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let packets = if pressure { 3600 } else { 900 };
        for seq in 1..=packets {
            tick.tick().await;
            if pressure && seq % 50 == 1 {
                for service in &stand.services[..2] {
                    service
                        .session_tx_registry
                        .read()
                        .unwrap()
                        .note_local_source_feedback(true, Instant::now());
                }
            }
            let forward = packet(111, seq);
            let reverse = packet(111, seq + 1000);
            assert_eq!(send(ca.id, &forward), 0);
            assert_eq!(send(cc.id, &reverse), 0);
            expect_packet(&mut cc.rx, &forward).await;
            expect_packet(&mut ca.rx, &reverse).await;
            if feedback && seq % 5 == 0 {
                let rtcp = [0x80, 201, 0, 1, 1, 2, 3, 4];
                assert_eq!(send(ca.id, &rtcp), 0);
                assert_eq!(send(cc.id, &rtcp), 0);
            }
        }
    } else {
        tokio::time::sleep(Duration::from_secs(18)).await;
    }
    let after = [
        ca.routes.outgoing_for_test().await,
        cc.routes.outgoing_for_test().await,
    ];
    for (side, (old, new)) in before.iter().zip(&after).enumerate() {
        for previous in old {
            let current = new.iter().find(|route| route.plane == previous.plane);
            eprintln!(
                "private route identity side={side} plane={} origin={}/{} destination_same={}",
                previous.plane,
                previous.origin,
                current.map_or(0, |r| r.origin),
                current.is_some_and(|r| r.destination_cookie == previous.destination_cookie),
            );
        }
    }
    let unchanged = before.iter().zip(&after).all(|(old, new)| {
        old.len() == 4
            && new.len() == 4
            && old
                .iter()
                .zip(new)
                .all(|(a, b)| a.origin == b.origin && a.destination_cookie == b.destination_cookie)
    });
    let paths = [
        ca.routes.send_paths_for_test(),
        cc.routes.send_paths_for_test(),
    ];
    eprintln!(
        "private routes primary={primary} feedback={feedback} pressure={pressure} unchanged={unchanged} paths={paths:?}"
    );
    drop((ca, cc));
    stand.stop().await;
    assert!(
        unchanged,
        "healthy private circuits must retain their identities past the probe timeout"
    );
}

fn codec_file(
    from: Arc<crate::anon_stream::CircuitStreamMuxForTest>,
    to: Arc<crate::anon_stream::CircuitStreamMuxForTest>,
    destination: [u8; 32],
    pattern: usize,
    received: Arc<std::sync::atomic::AtomicUsize>,
    timeout: Duration,
) -> tokio::task::JoinHandle<Result<usize, String>> {
    tokio::spawn(async move {
        tokio::time::timeout(timeout, async {
            let expected: Vec<_> = (0..512 * 1024)
                .map(|i| ((i + pattern) % 251) as u8)
                .collect();
            let outgoing = from.open(veil_onion_stream::Addr {
                node: destination,
                app: [0; 32],
            });
            let send = async {
                outgoing
                    .write_all(&expected)
                    .await
                    .map_err(|e| e.to_string())?;
                outgoing.finish().await.map_err(|e| e.to_string())
            };
            let receive = async {
                let (mut incoming, _) = to
                    .accept()
                    .await
                    .ok_or_else(|| "file accept closed".to_owned())?;
                let mut bytes = Vec::new();
                let mut buffer = [0u8; 4096];
                loop {
                    let count = incoming
                        .read(&mut buffer)
                        .await
                        .map_err(|e| e.to_string())?;
                    if count == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                    received.store(bytes.len(), std::sync::atomic::Ordering::Relaxed);
                    if bytes.len() > expected.len() {
                        return Err("file length overflow".to_owned());
                    }
                }
                if bytes != expected {
                    return Err("file bytes differ".to_owned());
                }
                Ok(bytes.len())
            };
            let (sent, received) = tokio::join!(send, receive);
            sent?;
            received
        })
        .await
        .map_err(|_| "file timed out".to_owned())?
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real obfs4 delayed bidirectional file diagnostic"]
async fn private_routes_allow_bidirectional_files_after_idle() {
    check_bidirectional_files(false, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real obfs4 file opens while primary and feedback are active"]
async fn private_routes_allow_bidirectional_files_during_primary() {
    check_bidirectional_files(true, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "in-memory control for active-primary file regression"]
async fn private_routes_allow_bidirectional_files_during_primary_in_memory() {
    check_bidirectional_files(true, false).await;
}

async fn check_bidirectional_files(primary: bool, real_obfs4: bool) {
    let stand = Stand::with_links(1, real_obfs4).await;
    let a = stand.services[0].local_node_id();
    let c = stand.services[1].local_node_id();
    let ca = channel(a, c, [0xa1; 32], [0xc1; 32]);
    let cc = channel(c, a, [0xc1; 32], [0xa1; 32]);
    codec_routes_ready(&stand, &[&ca, &cc]).await;
    let media = if primary {
        let ids = [ca.id, cc.id];
        Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(20));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            for seq in 1..=1500 {
                tick.tick().await;
                for id in ids {
                    assert_eq!(send(id, &packet(111, seq)), 0);
                    if seq % 5 == 0 {
                        assert_eq!(send(id, &[0x80, 201, 0, 1, 1, 2, 3, 4]), 0);
                    }
                }
            }
        }))
    } else {
        None
    };
    tokio::time::sleep(Duration::from_secs(20)).await;
    let bytes: [Arc<std::sync::atomic::AtomicUsize>; 2] = std::array::from_fn(|_| Arc::default());
    let forward = codec_file(
        Arc::clone(&ca.files),
        Arc::clone(&cc.files),
        c,
        7,
        Arc::clone(&bytes[0]),
        Duration::from_secs(30),
    );
    let reverse = codec_file(
        Arc::clone(&cc.files),
        Arc::clone(&ca.files),
        a,
        19,
        Arc::clone(&bytes[1]),
        Duration::from_secs(30),
    );
    let results = tokio::join!(forward, reverse);
    if let Some(media) = media {
        media.await.unwrap();
    }
    eprintln!(
        "bidirectional files primary={primary}: results={results:?} received={:?}",
        bytes
            .each_ref()
            .map(|n| n.load(std::sync::atomic::Ordering::Relaxed))
    );
    drop((ca, cc));
    stand.stop().await;
    assert_eq!(results.0.unwrap(), Ok(512 * 1024));
    assert_eq!(results.1.unwrap(), Ok(512 * 1024));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned synthetic media/PCM libraries and a private output directory"]
async fn real_anonymous_codecs_share_obfs4_with_files_on_four_private_planes() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    assert_eq!(
        std::env::var("VEIL_MEDIA_TEST_VIDEO").as_deref(),
        Ok("1"),
        "synthetic video must be selected before the native library loads"
    );
    let directory = std::path::PathBuf::from(std::env::var_os("VEIL_MEDIA_CODEC_OUTPUT").unwrap());
    let meta = std::fs::symlink_metadata(&directory).unwrap();
    assert!(meta.is_dir() && !meta.file_type().is_symlink());
    assert_eq!(meta.uid(), unsafe { libc::geteuid() });
    assert_eq!(meta.permissions().mode() & 0o077, 0);
    for file in [
        "summary.json",
        "pcm-samples.json",
        "codec-samples.json",
        "decoded-video-samples.json",
    ] {
        assert!(
            !directory.join(file).exists(),
            "never overwrite captured evidence"
        );
    }
    let media = NativeApi::open();
    let driver = CodecLibrary::from_env("VEIL_MEDIA_PCM_DRIVER_DYLIB");
    let stand = Stand::with_links(1, true).await;
    assert!(
        stand.pipes.is_empty(),
        "all hops must use real obfs4 sockets"
    );
    let nodes = [
        stand.services[0].local_node_id(),
        stand.services[1].local_node_id(),
    ];
    let a = channel(nodes[0], nodes[1], [0xa1; 32], [0xc1; 32]);
    let c = channel(nodes[1], nodes[0], [0xc1; 32], [0xa1; 32]);
    let channels = [&a, &c];
    codec_routes_ready(&stand, &channels).await;
    let engines = NativePair::new(&media, &channels, nodes);
    let fallback_before = channels.map(|ch| ch.routes.send_paths_for_test().1);
    let file_bytes: [Arc<std::sync::atomic::AtomicUsize>; 2] =
        std::array::from_fn(|_| Arc::default());
    let mut clock = AudioClock::start(&driver, &engines);
    let mut codec_rows = Vec::new();
    let mut video_rows = Vec::new();
    let mut buffers = [vec![0u8; 320 * 240 * 4], vec![0u8; 320 * 240 * 4]];
    let mut last_hash = [None, None];
    let mut files = Vec::new();
    let mut files_done_at_end = false;
    let mut before_camera = None;
    let mut before_screen = None;
    let mut video_started = false;
    let mut screen_started = false;
    let mut sample = 0u64;
    while clock.elapsed() < 60.0 {
        clock.drain();
        let at = clock.elapsed();
        if at >= 20.0 && !video_started {
            before_camera = Some([
                a.routes.received_media_cells_for_test(),
                c.routes.received_media_cells_for_test(),
            ]);
            for engine in engines.engines {
                assert_eq!(unsafe { (media.video)(engine, 1, 1, 150, 15) }, 0);
            }
            files.push(codec_file(
                Arc::clone(&a.files),
                Arc::clone(&c.files),
                nodes[1],
                7,
                Arc::clone(&file_bytes[0]),
                Duration::from_secs(90),
            ));
            files.push(codec_file(
                Arc::clone(&c.files),
                Arc::clone(&a.files),
                nodes[0],
                19,
                Arc::clone(&file_bytes[1]),
                Duration::from_secs(90),
            ));
            video_started = true;
        }
        if at >= 40.0 && !screen_started {
            before_screen = Some([
                a.routes.received_media_cells_for_test(),
                c.routes.received_media_cells_for_test(),
            ]);
            for channel in channels {
                assert_eq!(
                    super::super::veil_media_channel_set_screen_sharing(channel.id, 1),
                    0
                );
            }
            screen_started = true;
        }
        if at >= sample as f64 {
            for side in 0..2 {
                let stats = engines.stats(side);
                codec_rows.push(serde_json::json!({"t": at, "side":side, "stats":stats,
                    "file_bytes_received": file_bytes[side].load(std::sync::atomic::Ordering::Relaxed),
                    "send_paths_private_fallback": channels[side].routes.send_paths_for_test(),
                    "private_media_cells_before_aead":channels[side].routes.received_media_cells_for_test()}));
                if sample % 10 == 0 {
                    eprintln!(
                        "codec_phase t={at:.1} side={side} private_fallback={:?} received={:?} audio_rx={}",
                        channels[side].routes.send_paths_for_test(),
                        channels[side].routes.received_media_cells_for_test(),
                        stats["audio_rx_pkts"]
                    );
                }
                if video_started {
                    let mut width = 0;
                    let mut height = 0;
                    let seq = unsafe {
                        (media.frame)(
                            engines.engines[side],
                            buffers[side].as_mut_ptr(),
                            buffers[side].len() as c_int,
                            &mut width,
                            &mut height,
                        )
                    };
                    assert!(seq >= 0, "decoded-frame retrieval failed");
                    let mut changed = false;
                    if seq > 0 {
                        assert!(width > 0 && height > 0 && width <= 320 && height <= 240);
                        let hash =
                            *blake3::hash(&buffers[side][..width as usize * height as usize * 4])
                                .as_bytes();
                        changed = last_hash[side].is_some_and(|old| old != hash);
                        last_hash[side] = Some(hash);
                    }
                    video_rows
                        .push(serde_json::json!({"t":at,"side":side,"seq":seq,"changed":changed}));
                }
            }
            sample += 1;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if files.len() == 2 {
        files_done_at_end = files.iter().all(|f| f.is_finished());
    }
    let clock = clock.finish(); // Ends the engine/library borrow only after join.
    let private_counts = [
        a.routes.received_media_cells_for_test(),
        c.routes.received_media_cells_for_test(),
    ];
    let fallback_after = channels.map(|ch| ch.routes.send_paths_for_test().1);
    let file_bytes_during_media = file_bytes
        .each_ref()
        .map(|n| n.load(std::sync::atomic::Ordering::Relaxed));
    drop(engines); // Joins native queues and flushes bounded RTP/encoder evidence.
    // Require actual competing traffic during media. Byte-exact completion may
    // extend beyond that phase when endpoint pressure constrains reliable DATA;
    // allow the native producers to release the uplink before the final wait.
    let mut file_results = Vec::new();
    for file in files {
        file_results.push(file.await.map_err(|e| e.to_string()).and_then(|r| r));
    }
    drop((a, c));
    stand.stop().await;
    let observation_count_verified = clock.rows.len() as u64 == clock.stats.ticks * 2;
    let clock_ok = clock.stats.max_interval_ms < 40.0
        && clock.stats.dropped_rows == 0
        && clock.stats.failures == [0, 0]
        && clock.stats.timer_error == 0
        && observation_count_verified
        && (clock.stats.qos_supported == 0
            || (clock.stats.qos_result == 0
                && clock.stats.qos_actual == clock.stats.qos_requested));
    let video_ok = (0..2).all(|side| {
        [(22.0, 39.0), (43.0, 60.0)].iter().all(|&(lo, hi)| {
            video_rows
                .iter()
                .filter(|r| {
                    r["side"] == side
                        && r["t"].as_f64().unwrap() >= lo
                        && r["t"].as_f64().unwrap() < hi
                        && r["changed"] == true
                })
                .count()
                >= 2
        })
    });
    let camera_counts = before_camera.unwrap();
    let screen_counts = before_screen.unwrap();
    let paths_ok = (0..2).all(|side| {
        fallback_after[side][..3] == fallback_before[side][..3]
            && screen_counts[side][0] > camera_counts[side][0]
            && private_counts[side][0] > screen_counts[side][0]
            && screen_counts[side][1] > camera_counts[side][1]
            && private_counts[side][2] > screen_counts[side][2]
            && private_counts[side][3] > camera_counts[side][3]
    });
    let feedback_ok = (0..2).all(|side| {
        codec_rows
            .iter()
            .rev()
            .find(|r| r["side"] == side)
            .is_some_and(|r| {
                r["stats"]["audio_feedback_reports"].as_u64().unwrap_or(0) > 0
                    && r["stats"]["worker_stalled"] == 0
            })
    });
    let files_ok = file_results.len() == 2 && file_results.iter().all(|r| *r == Ok(512 * 1024));
    let file_contention_verified = file_bytes_during_media.iter().all(|n| *n > 0);
    let rows: Vec<_> = clock
        .rows
        .iter()
        .map(|r| {
            serde_json::json!({"t":r.t,"source_at":r.source_at,
        "rms":r.rms,"freq":r.freq,"interval_ms":r.interval_ms,"source_tick":r.source_tick,
        "side":r.side,"source_freq":r.source_freq})
        })
        .collect();
    let summary = serde_json::json!({"loopback_only":true,"duration_seconds":60,
        "stand_start_monotonic_us":(clock.origin*1e6).round() as u64,"real_opus":true,"real_vp8":true,
        "video_requested":true,"competing_file_bytes":512*1024,"anonymous_routes":true,
        "two_relays_verified":true,"four_receive_planes_verified":true,"session_transport":"obfs4-tcp",
        "shaped":false,"application_adapter":false,"synthetic_camera":[320,240],
        "fixed_video_budget":{"kbps":150,"fps":15},"camera_seconds":[20,40],"screen_seconds":[40,60],
        "node_shutdown_verified":true,"native_engines_destroyed":true,
        "clock_ok":clock_ok,"max_driver_interval_ms":clock.stats.max_interval_ms,
        "observations":rows.len(),"observation_count_verified":observation_count_verified,
        "dropped_rows":clock.stats.dropped_rows,"timer_error":clock.stats.timer_error,
        "native_failures":clock.stats.failures,"private_media_cells_before_aead":private_counts,
        "private_cells_before_camera":camera_counts,"private_cells_before_screen":screen_counts,
        "files_complete_during_media":files_done_at_end,"files_ok":files_ok,
        "file_bytes_received_during_media":file_bytes_during_media,
        "file_contention_verified":file_contention_verified,
        "private_fallback_before":fallback_before,"private_fallback_after":fallback_after,
        "file_results":file_results.iter().map(|r|format!("{r:?}")).collect::<Vec<_>>(),
        "video_decoding_verified":video_ok,"paths_verified":paths_ok,
        "native_audio_rtcp_verified":feedback_ok,
        "codec_isolation_ok":clock_ok && video_ok && paths_ok && files_ok && feedback_ok && file_contention_verified});
    for (name, value) in [
        ("pcm-samples.json", serde_json::json!(rows)),
        ("codec-samples.json", serde_json::json!(codec_rows)),
        ("decoded-video-samples.json", serde_json::json!(video_rows)),
        ("summary.json", summary.clone()),
    ] {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(name))
            .unwrap();
        serde_json::to_writer(&mut file, &value).unwrap();
    }
    eprintln!("anonymous real codecs: {summary}");
    assert!(
        summary["codec_isolation_ok"] == true,
        "codec isolation gates failed; PCM latency still requires exact offline attribution"
    );
}
