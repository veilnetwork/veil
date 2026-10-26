//! Small, ephemeral call state on an independent endpoint IPC sender.
//! Peers must negotiate support before use. Relays see only sealed cells.
use super::*;
use std::collections::{HashMap, VecDeque};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

const MAGIC: &[u8; 4] = b"XVH1";
/// Maximum opaque payload of an ephemeral call-state update, before sealing.
pub const VEIL_CALL_CONTROL_MAX_BYTES: size_t = 768;
const MAX_PAYLOAD: usize = VEIL_CALL_CONTROL_MAX_BYTES;
const QUEUE_DEPTH: usize = 8;
const MAX_AGE: Duration = Duration::from_secs(5);

struct ControlPacket {
    bytes: Vec<u8>,
    deadline: tokio::time::Instant,
}

struct ControlChannel {
    cipher: Arc<media::MediaCipher>,
    tx: mpsc::Sender<ControlPacket>,
    inbox: VecDeque<ControlPacket>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ControlChannel {
    fn drop(&mut self) {
        self.task.abort();
    }
}

static CONTROLS: LazyLock<Mutex<HashMap<u64, ControlChannel>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

async fn drain_control<F, Fut>(
    mut rx: mpsc::Receiver<ControlPacket>,
    cipher: Arc<media::MediaCipher>,
    mut send: F,
) where
    F: FnMut(media::SealedMediaCell) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    while let Some(packet) = rx.recv().await {
        if packet.deadline <= tokio::time::Instant::now() {
            continue;
        }
        let mut body = Vec::with_capacity(MAGIC.len() + packet.bytes.len());
        body.extend_from_slice(MAGIC);
        body.extend_from_slice(&packet.bytes);
        let Some(sealed) = cipher.seal_call_control(&body) else {
            continue;
        };
        let sealed = sealed.with_local_deadline(packet.deadline);
        if !send(sealed).await {
            break;
        }
    }
}

/// Install a separate control IPC sender on an existing direct/relay channel.
/// Bind the same app identity on a separate connection, and negotiate peer
/// support first. Anonymous channels retain their existing signaling path.
/// A second configuration is rejected; close/reopen for a new sender.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_channel_set_control_sender(
    chan: u64,
    app: *mut VeilApp,
    err_out: *mut *mut c_char,
) -> c_int {
    if unsafe { guard::ffi_prelude(err_out, "veil_media_channel_set_control_sender") }.is_err() {
        return -1;
    }
    null_check_with_default!(err_out, -1, "app" => app);
    get_or_return!(app_ref, app_table(), app, err_out, -1, "VeilApp");
    // Holding membership until registration finishes serializes with close.
    let channels = MEDIA_CHANNELS.read().unwrap_or_else(|p| p.into_inner());
    let Some(channel) = channels.get(&chan) else {
        unsafe { write_err(err_out, "unknown media channel") };
        return -1;
    };
    if channel.sender_app_id != Some(app_ref.app_id) || channel.routes.is_some() {
        unsafe {
            write_err(
                err_out,
                "control sender requires the same direct/relay app identity",
            )
        };
        return -1;
    }
    let mut controls = CONTROLS.lock().unwrap_or_else(|p| p.into_inner());
    if controls.contains_key(&chan) {
        unsafe { write_err(err_out, "control sender already configured") };
        return -1;
    }
    let (tx, rx) = mpsc::channel(QUEUE_DEPTH);
    let sender = Arc::clone(&app_ref.sender);
    let cipher = Arc::clone(&channel.cipher);
    let peer = channel.peer;
    let Some((peer_app, peer_endpoint)) = channel.control_destination else {
        unsafe { write_err(err_out, "media channel has no control destination") };
        return -1;
    };
    let relay = channel.relay_stats.is_some();
    let seq = channel
        .direct_seq
        .clone()
        .unwrap_or_else(|| Arc::new(std::sync::atomic::AtomicU32::new(0)));
    let task =
        app_ref
            .bundle
            .runtime
            .spawn(drain_control(rx, Arc::clone(&cipher), move |sealed| {
                let sender = Arc::clone(&sender);
                let seq = Arc::clone(&seq);
                async move {
                    let Some(guard) = sealed.lock_while_fresh(&sender).await else {
                        return true;
                    };
                    let Some(sender) = guard.as_ref() else {
                        return false;
                    };
                    let deadline = sealed
                        .local_deadline()
                        .expect("control retains admission deadline");
                    if relay {
                        let _ = sender
                            .send_call_control_sealed_before_owned(
                                peer,
                                peer_app,
                                peer_endpoint,
                                sealed.into_vec(),
                                deadline,
                            )
                            .await;
                    } else {
                        let _ = sender
                            .send_rt_data_on_local_lane_before(
                                veil_proto::priority::INTERACTIVE,
                                peer,
                                peer_app,
                                peer_endpoint,
                                seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                                0,
                                0,
                                0,
                                sealed.as_bytes(),
                                deadline,
                            )
                            .await;
                    }
                    true
                }
            }));
    controls.insert(
        chan,
        ControlChannel {
            cipher,
            tx,
            inbox: VecDeque::new(),
            task,
        },
    );
    0
}

/// Queue one ephemeral state update, up to 768 bytes. Returns 0 queued,
/// 1 full/busy, -1 invalid/closed. This is not a reliable command channel;
/// repeat state periodically and keep setup/end commands on signaling.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_send_call_control(
    chan: u64,
    ptr: *const u8,
    len: size_t,
) -> c_int {
    if ptr.is_null() || len == 0 || len > MAX_PAYLOAD {
        return -1;
    }
    let controls = match CONTROLS.try_lock() {
        Ok(controls) => controls,
        Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return 1,
    };
    let Some(control) = controls.get(&chan) else {
        return -1;
    };
    let packet = ControlPacket {
        bytes: unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec(),
        deadline: tokio::time::Instant::now() + MAX_AGE,
    };
    match control.tx.try_send(packet) {
        Ok(()) => 0,
        Err(mpsc::error::TrySendError::Full(_)) => 1,
        Err(mpsc::error::TrySendError::Closed(_)) => -1,
    }
}

/// Poll authenticated peer state into caller memory. Positive = bytes copied,
/// 0 = no fresh update, -1 = invalid/closed, -2 = output too small (not consumed).
/// Receipt is bound to this channel's cipher. No native callback enters Dart.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veil_media_poll_call_control(
    chan: u64,
    ptr: *mut u8,
    capacity: size_t,
) -> c_int {
    if ptr.is_null() || capacity == 0 {
        return -1;
    }
    let mut controls = CONTROLS.lock().unwrap_or_else(|p| p.into_inner());
    let Some(control) = controls.get_mut(&chan) else {
        return -1;
    };
    while control
        .inbox
        .front()
        .is_some_and(|packet| packet.deadline <= tokio::time::Instant::now())
    {
        control.inbox.pop_front();
    }
    let Some(packet) = control.inbox.front() else {
        return 0;
    };
    if packet.bytes.len() > capacity {
        return -2;
    }
    let packet = control.inbox.pop_front().expect("front is present");
    unsafe {
        ptr::copy_nonoverlapping(packet.bytes.as_ptr(), ptr, packet.bytes.len());
    }
    packet.bytes.len() as c_int
}

pub(crate) fn dispatch_control(
    chan: u64,
    cipher: &Arc<media::MediaCipher>,
    plaintext: &[u8],
) -> bool {
    let Some(body) = plaintext.strip_prefix(MAGIC) else {
        return false;
    };
    // Reserved control never reaches the RTP engine, even if malformed or
    // received before the local host finished negotiating/configuring it.
    if body.is_empty() || body.len() > MAX_PAYLOAD {
        return true;
    }
    let channels = MEDIA_CHANNELS.read().unwrap_or_else(|p| p.into_inner());
    if !channels
        .get(&chan)
        .is_some_and(|channel| Arc::ptr_eq(&channel.cipher, cipher))
    {
        return true;
    }
    let mut controls = CONTROLS.lock().unwrap_or_else(|p| p.into_inner());
    let Some(control) = controls.get_mut(&chan) else {
        return true;
    };
    if !Arc::ptr_eq(&control.cipher, cipher) {
        return true;
    }
    if control.inbox.len() == QUEUE_DEPTH {
        control.inbox.pop_front();
    }
    control.inbox.push_back(ControlPacket {
        bytes: body.to_vec(),
        deadline: tokio::time::Instant::now() + MAX_AGE,
    });
    true
}

pub(crate) fn close(chan: u64) {
    CONTROLS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&chan);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Sending intentionally returns BUSY rather than waiting for CONTROLS.
    // These exact queue/close assertions require an uncontended fixture;
    // another test's registry operation must not turn -1/0 into valid BUSY.
    static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

    struct Fixture {
        _serial: std::sync::MutexGuard<'static, ()>,
        id: u64,
        peer: [u8; 32],
        cipher: Arc<media::MediaCipher>,
        remote: media::MediaCipher,
        engine_calls: Arc<AtomicUsize>,
        _rx: mpsc::Receiver<ControlPacket>,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            unsafe {
                veil_media_close_channel(self.id);
            }
        }
    }

    extern "C" fn record_engine(ctx: *mut c_void, _: *const u8, _: usize) {
        unsafe { &*(ctx as *const AtomicUsize) }.fetch_add(1, Ordering::Relaxed);
    }

    fn fixture() -> Fixture {
        let serial = FIXTURE_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let id = MEDIA_NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let mut peer = [0xcd; 32];
        peer[24..].copy_from_slice(&id.to_be_bytes());
        let cipher = Arc::new(media::cipher_for_test(&peer, &[1; 32], &[2; 32]).unwrap());
        let remote = media::cipher_for_test(&peer, &[2; 32], &[1; 32]).unwrap();
        let engine_calls = Arc::new(AtomicUsize::new(0));
        let (audio_tx, _audio_rx) = mpsc::channel(1);
        let (video_tx, _video_rx) = mpsc::channel(1);
        MEDIA_CHANNELS.write().unwrap().insert(
            id,
            MediaChannel {
                cost_context: None,
                path_probe: None,
                source_preflight: None,
                ingress: MediaIngress::new(audio_tx, MediaVideoIngress::Packets(video_tx)),
                repair_tx: None,
                peer,
                task: tokio::spawn(std::future::pending()),
                video_task: None,
                screen_task: None,
                feedback_task: None,
                video_sender: None,
                screen_sender: None,
                sender_app_id: None,
                control_destination: None,
                direct_seq: None,
                batching: None,
                cipher: Arc::clone(&cipher),
                relay_stats: None,
                routes: None,
            },
        );
        let (tx, rx) = mpsc::channel(QUEUE_DEPTH);
        CONTROLS.lock().unwrap().insert(
            id,
            ControlChannel {
                cipher: Arc::clone(&cipher),
                tx,
                inbox: VecDeque::new(),
                task: tokio::spawn(std::future::pending()),
            },
        );
        media::set_recv_callback(
            peer,
            id,
            record_engine,
            Arc::as_ptr(&engine_calls) as *mut c_void,
            Arc::clone(&cipher),
        );
        Fixture {
            _serial: serial,
            id,
            peer,
            cipher,
            remote,
            engine_calls,
            _rx: rx,
        }
    }

    fn incoming(f: &Fixture, bytes: &[u8]) -> Vec<u8> {
        let body = [MAGIC.as_slice(), bytes].concat();
        let sealed = f.remote.seal_call_control(&body).unwrap();
        media::dispatch_inbound_auto(f.peer, sealed.as_bytes());
        sealed.into_vec()
    }

    #[tokio::test]
    async fn authenticated_control_is_polled_once_and_never_enters_the_engine() {
        let f = fixture();
        let wire = incoming(&f, b"current state");
        let mut out = [0u8; MAX_PAYLOAD];
        assert_eq!(
            unsafe { veil_media_poll_call_control(f.id, out.as_mut_ptr(), 2) },
            -2
        );
        assert_eq!(
            unsafe { veil_media_poll_call_control(f.id, out.as_mut_ptr(), out.len()) },
            13
        );
        assert_eq!(&out[..13], b"current state");
        media::dispatch_inbound_auto(f.peer, &wire);
        assert_eq!(
            unsafe { veil_media_poll_call_control(f.id, out.as_mut_ptr(), out.len()) },
            0
        );
        assert_eq!(f.engine_calls.load(Ordering::Relaxed), 0);
        let rtp = f
            .remote
            .seal_on_plane(media::LocalMediaPlane::Primary, &[0x80, 111, 0, 1])
            .unwrap();
        media::dispatch_inbound_auto(f.peer, rtp.as_bytes());
        assert_eq!(f.engine_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn malformed_foreign_and_superseded_control_do_not_reach_the_host() {
        let f = fixture();
        incoming(&f, &[]);
        incoming(&f, &vec![0; MAX_PAYLOAD + 1]);
        let other = Arc::new(media::cipher_for_test(&f.peer, &[1; 32], &[2; 32]).unwrap());
        assert!(dispatch_control(
            f.id,
            &other,
            &[MAGIC.as_slice(), b"superseded"].concat()
        ));
        let foreign = media::cipher_for_test(&f.peer, &[3; 32], &[4; 32]).unwrap();
        let wire = foreign
            .seal_call_control(&[MAGIC.as_slice(), b"foreign"].concat())
            .unwrap();
        media::dispatch_inbound_auto(f.peer, wire.as_bytes());
        let mut out = [0u8; MAX_PAYLOAD];
        assert_eq!(
            unsafe { veil_media_poll_call_control(f.id, out.as_mut_ptr(), out.len()) },
            0
        );
        assert_eq!(f.engine_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn control_queues_are_bounded_and_close_releases_the_owner() {
        let f = fixture();
        for i in 0..QUEUE_DEPTH {
            assert_eq!(
                unsafe { veil_media_send_call_control(f.id, [i as u8].as_ptr(), 1) },
                0
            );
        }
        assert_eq!(
            unsafe { veil_media_send_call_control(f.id, [0u8].as_ptr(), 1) },
            1
        );
        assert_eq!(
            unsafe { veil_media_send_call_control(f.id, [0u8].as_ptr(), MAX_PAYLOAD + 1) },
            -1
        );
        for i in 0..QUEUE_DEPTH + 3 {
            incoming(&f, &[i as u8]);
        }
        let mut out = [0u8; MAX_PAYLOAD];
        for i in 3..QUEUE_DEPTH + 3 {
            assert_eq!(
                unsafe { veil_media_poll_call_control(f.id, out.as_mut_ptr(), out.len()) },
                1
            );
            assert_eq!(out[0], i as u8);
        }
        let before = Arc::strong_count(&f.cipher);
        unsafe {
            veil_media_close_channel(f.id);
        }
        assert!(Arc::strong_count(&f.cipher) < before);
        assert_eq!(
            unsafe { veil_media_send_call_control(f.id, [0u8].as_ptr(), 1) },
            -1
        );
        assert_eq!(
            unsafe { veil_media_poll_call_control(f.id, out.as_mut_ptr(), out.len()) },
            -1
        );
    }

    #[tokio::test]
    async fn expired_receive_work_is_not_renewed_by_polling() {
        let f = fixture();
        incoming(&f, b"old");
        CONTROLS.lock().unwrap().get_mut(&f.id).unwrap().inbox[0].deadline =
            tokio::time::Instant::now() - Duration::from_millis(1);
        let mut out = [0u8; MAX_PAYLOAD];
        assert_eq!(
            unsafe { veil_media_poll_call_control(f.id, out.as_mut_ptr(), out.len()) },
            0
        );
    }

    #[tokio::test]
    async fn expired_send_work_does_not_precede_current_state() {
        let f = fixture();
        let (tx, rx) = mpsc::channel(2);
        let now = tokio::time::Instant::now();
        tx.send(ControlPacket {
            bytes: b"old".to_vec(),
            deadline: now - Duration::from_millis(1),
        })
        .await
        .unwrap();
        tx.send(ControlPacket {
            bytes: b"new".to_vec(),
            deadline: now + MAX_AGE,
        })
        .await
        .unwrap();
        drop(tx);
        let cells = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&cells);
        drain_control(rx, Arc::clone(&f.cipher), move |cell| {
            captured.lock().unwrap().push(cell);
            std::future::ready(true)
        })
        .await;
        let cells = cells.lock().unwrap();
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0].local_deadline(), Some(now + MAX_AGE));
        assert_eq!(
            f.remote.open(cells[0].as_bytes()),
            Some([MAGIC.as_slice(), b"new"].concat())
        );
    }

    #[test]
    fn four_producers_keep_replay_windows_across_two_generations() {
        let peer = [0xc9; 32];
        // Replay history is intentionally scoped to the key, not peer id.
        // Other parallel fixtures use [1;32]/[2;32] and would add their own
        // epochs to this exact eight-epoch boundary test. Keep the same key
        // across both generations here, with a scope unique to this test.
        let forward = blake3::derive_key("xveil/test/call-control/two-generations", b"forward");
        let reverse = blake3::derive_key("xveil/test/call-control/two-generations", b"reverse");
        let first = media::cipher_for_test(&peer, &forward, &reverse).unwrap();
        let second = media::cipher_for_test(&peer, &forward, &reverse).unwrap();
        let receiver = media::cipher_for_test(&peer, &reverse, &forward).unwrap();
        let seal = |cipher: &media::MediaCipher, producer, bytes: &[u8]| match producer {
            0 => cipher.seal_on_plane(media::LocalMediaPlane::Primary, bytes),
            1 => cipher.seal_on_plane(media::LocalMediaPlane::Secondary, bytes),
            2 => cipher.seal_on_plane(media::LocalMediaPlane::Screen, bytes),
            3 => cipher.seal_call_control(bytes),
            _ => unreachable!(),
        };
        let mut wires = Vec::new();
        for cipher in [&first, &second] {
            for producer in 0..4 {
                let sealed = seal(cipher, producer, b"first").unwrap();
                assert_eq!(receiver.open(sealed.as_bytes()), Some(b"first".to_vec()));
                wires.push(sealed);
            }
        }
        for wire in wires {
            assert!(receiver.open(wire.as_bytes()).is_none());
        }
        for producer in 0..4 {
            let sealed = seal(&first, producer, b"overlap").unwrap();
            assert_eq!(receiver.open(sealed.as_bytes()), Some(b"overlap".to_vec()));
        }
    }
}
