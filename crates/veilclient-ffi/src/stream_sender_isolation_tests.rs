//! The real C entry points, SDK, Unix IPC server and stream receipt wait.
//! A shared app sender locks chat behind an open; a separate binding/connection
//! must deliver chat before that same outstanding receipt is released.
use super::*;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, atomic::AtomicU32},
    time::Duration,
};
use veil_ipc::{IpcEndpoint, IpcServer, bridge::IpcStreamBridge};
use veil_proto::{family::AppMsg, header::HEADER_SIZE};

const PEER: [u8; 32] = [0xb7; 32];
struct Capture(std::sync::mpsc::Sender<(u8, Vec<u8>)>);
impl veil_types::FrameBroadcaster for Capture {
    fn send_to(&self, peer: &[u8; 32], lane: u8, frame: Vec<u8>) -> bool {
        *peer == PEER && self.0.send((lane, frame)).is_ok()
    }
    fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {}
    fn active_node_ids(&self) -> Vec<[u8; 32]> {
        vec![PEER]
    }
}
unsafe fn connect_and_bind(path: &str, endpoint: u32) -> (usize, usize) {
    let mut err = ptr::null_mut();
    let client = unsafe { veil_connect(path.as_ptr(), path.len(), &mut err) };
    assert!(
        !client.is_null() && err.is_null(),
        "fixture client could not connect"
    );
    let app = unsafe {
        veil_bind_named(
            client,
            b"xveil".as_ptr(),
            5,
            b"inbox".as_ptr(),
            5,
            endpoint,
            &mut err,
        )
    };
    assert!(!app.is_null() && err.is_null(), "fixture binding failed");
    (client as usize, app as usize)
}

#[test]
fn close_cancels_blocked_ffi_stream_halves_and_releases_peer_state() {
    struct Source {
        frames: std::sync::mpsc::Sender<(u8, Vec<u8>)>,
        entered: std::sync::mpsc::Sender<()>,
        permits: tokio::sync::Semaphore,
    }
    impl veil_types::FrameBroadcaster for Source {
        fn send_to(&self, peer: &[u8; 32], lane: u8, frame: Vec<u8>) -> bool {
            *peer == PEER && self.frames.send((lane, frame)).is_ok()
        }
        fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {}
        fn active_node_ids(&self) -> Vec<[u8; 32]> {
            vec![PEER]
        }
        fn send_reliable_to<'a>(
            &'a self,
            _: &'a [u8; 32],
            frame: Vec<u8>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
            Box::pin(async move {
                if veil_proto::codec::decode_header(&frame).unwrap().msg_type
                    == AppMsg::AppOpen as u16
                {
                    return self
                        .frames
                        .send((veil_proto::priority::BACKGROUND, frame))
                        .is_ok();
                }
                self.entered.send(()).unwrap();
                self.permits.acquire().await.unwrap().forget();
                self.frames
                    .send((veil_proto::priority::BACKGROUND, frame))
                    .is_ok()
            })
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("ipc.sock");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let bridge = IpcStreamBridge {
        veil_stream_rx: Arc::new(Mutex::new(HashMap::new())),
        pending_receipts: Arc::new(Mutex::new(HashMap::new())),
        wire_stream_counter: Arc::new(AtomicU32::new(1)),
    };
    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    let (frames, received) = std::sync::mpsc::channel();
    let (entered, waiting) = std::sync::mpsc::channel();
    let source = Arc::new(Source {
        frames,
        entered,
        permits: tokio::sync::Semaphore::new(0),
    });
    let mut server = IpcServer::new(
        IpcEndpoint::Unix(socket.clone()),
        shutdown_rx,
        Arc::new(veil_app::registry::AppEndpointRegistry::new()),
        [0x42; 32],
    )
    .with_session_tx_registry(source.clone())
    .with_stream_bridge(bridge.clone());
    let task = rt.spawn(async move { server.run().await.unwrap() });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let bound = unsafe { connect_and_bind(socket.to_str().unwrap(), 16) };
    let open_stream = || {
        let open = std::thread::spawn(move || {
            let mut err = ptr::null_mut();
            let stream = unsafe {
                veil_stream_open(
                    bound.1 as *mut VeilApp,
                    PEER.as_ptr(),
                    [0xaa; 32].as_ptr(),
                    0,
                    256 * 1024,
                    &mut err,
                )
            };
            assert!(err.is_null() && !stream.is_null());
            stream as usize
        });
        let (_, opening) = received.recv_timeout(Duration::from_secs(2)).unwrap();
        let header = veil_proto::codec::decode_header(&opening).unwrap();
        assert_eq!(header.msg_type, AppMsg::AppOpen as u16);
        bridge
            .pending_receipts
            .lock()
            .unwrap()
            .remove(&(PEER, header.stream_id))
            .unwrap()
            .send(veil_proto::app::receipt_status::ACCEPTED)
            .unwrap();
        (open.join().unwrap(), header.stream_id)
    };
    let (stream, wire_id) = open_stream();
    let (other, other_wire) = open_stream();
    let state = HandleTable::get(stream_table(), other).unwrap();
    let other_weak = Arc::downgrade(&state);
    drop(state);
    let other_read = std::thread::spawn(move || {
        let mut err = ptr::null_mut();
        let mut byte = 0;
        let rc = unsafe { veil_stream_read(other as *mut VeilStreamFfi, &mut byte, 1, &mut err) };
        if !err.is_null() {
            unsafe {
                veil_free_string(err);
            }
        }
        (rc, byte)
    });
    let state = HandleTable::get(stream_table(), stream).unwrap();
    let weak = Arc::downgrade(&state);
    drop(state);
    let (done, results) = std::sync::mpsc::channel();
    let mut workers = Vec::new();
    // First writer exhausts IPC credit while the source waits for capacity.
    // Second writer waits for its mutex; two readers wait for data and mutex.
    for (label, reading) in [(0, false), (1, false), (2, true), (3, true)] {
        let done = done.clone();
        workers.push(std::thread::spawn(move || {
            let mut err = ptr::null_mut();
            let rc = if reading {
                let mut byte = 0;
                unsafe {
                    veil_stream_read(stream as *mut VeilStreamFfi, &mut byte, 1, &mut err) as i32
                }
            } else {
                let bytes = vec![label + 5; 25001];
                unsafe {
                    veil_stream_write(
                        stream as *mut VeilStreamFfi,
                        bytes.as_ptr(),
                        bytes.len(),
                        &mut err,
                    )
                }
            };
            if !err.is_null() {
                unsafe {
                    veil_free_string(err);
                }
            }
            done.send((label, rc)).unwrap();
        }));
        if label == 0 {
            waiting.recv_timeout(Duration::from_secs(2)).unwrap();
        }
    }
    drop(done);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while weak.strong_count() < 5 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    let all_inflight = weak.strong_count() == 5;
    // Foreign-thread close must interrupt I/O without waiting for peer data,
    // source permits, or the read/write mutexes held by the first operations.
    unsafe {
        veil_stream_close(stream as *mut VeilStreamFfi);
    }
    let mut early = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_millis(250);
    while early.len() < 4 {
        let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
            break;
        };
        match results.recv_timeout(remaining) {
            Ok(result) => early.push(result),
            Err(_) => break,
        }
    }
    let released_before_network = weak.strong_count() == 0;
    // Release the negative control too, so a failed regression strands no
    // native thread, runtime, source permit or temporary IPC server.
    source.permits.add_permits(100);
    if let Some(tx) = bridge
        .veil_stream_rx
        .lock()
        .unwrap()
        .get(&(PEER, wire_id))
        .cloned()
    {
        let _ = tx.try_send(vec![55, 66]);
    }
    while early.len() < 4 {
        early.push(results.recv_timeout(Duration::from_secs(2)).unwrap());
    }
    for worker in workers {
        worker.join().unwrap();
    }
    let other_untouched = !other_read.is_finished() && other_weak.strong_count() == 2;
    bridge
        .veil_stream_rx
        .lock()
        .unwrap()
        .get(&(PEER, other_wire))
        .unwrap()
        .try_send(vec![77])
        .unwrap();
    let other_result = other_read.join().unwrap();
    let mut closed = false;
    let deadline = std::time::Instant::now() + Duration::from_millis(250);
    while let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) {
        let Ok((lane, frame)) = received.recv_timeout(remaining) else {
            break;
        };
        let h = veil_proto::codec::decode_header(&frame).unwrap();
        assert_eq!(h.priority(), veil_proto::priority::INTERACTIVE);
        if h.msg_type == AppMsg::AppClose as u16 && h.stream_id == wire_id {
            assert_eq!(lane, veil_proto::priority::BACKGROUND);
            closed = true;
            break;
        }
    }
    let cleaned_peer = !bridge
        .veil_stream_rx
        .lock()
        .unwrap()
        .contains_key(&(PEER, wire_id));
    unsafe {
        veil_stream_close(other as *mut VeilStreamFfi);
    }
    unsafe {
        veil_app_close(bound.1 as *mut VeilApp);
        veil_close(bound.0 as *mut VeilHandle);
    }
    shutdown.send(true).unwrap();
    rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    });
    assert!(
        all_inflight,
        "fixture must have both I/O halves and mutex waiters in flight"
    );
    assert!(
        released_before_network,
        "close left FFI stream operations waiting for the network"
    );
    assert!(early.iter().all(|(_, rc)| *rc == VEIL_ERR_CLOSED));
    assert!(
        other_untouched && other_result == (1, 77),
        "closing one stream interrupted another on the same client"
    );
    assert!(
        closed && cleaned_peer,
        "foreign-thread close left peer stream state behind"
    );
}

#[test]
fn dedicated_p2p_file_sender_keeps_chat_live_during_remote_open_wait() {
    let mut previous_open = None;
    for isolated in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("ipc.sock");
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let bridge = IpcStreamBridge {
            veil_stream_rx: Arc::new(Mutex::new(HashMap::new())),
            pending_receipts: Arc::new(Mutex::new(HashMap::new())),
            wire_stream_counter: Arc::new(AtomicU32::new(1)),
        };
        let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
        let (frames, received) = std::sync::mpsc::channel();
        let mut server = IpcServer::new(
            IpcEndpoint::Unix(socket.clone()),
            shutdown_rx,
            Arc::new(veil_app::registry::AppEndpointRegistry::new()),
            [0x42; 32],
        )
        .with_session_tx_registry(Arc::new(Capture(frames)))
        .with_stream_bridge(bridge.clone());
        let task = rt.spawn(async move { server.run().await.unwrap() });
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let main = unsafe { connect_and_bind(socket.to_str().unwrap(), 0) };
        let file = if isolated {
            unsafe { connect_and_bind(socket.to_str().unwrap(), 16) }
        } else {
            main
        };
        let mut main_id = [0; 32];
        let mut file_id = [0; 32];
        assert_eq!(
            unsafe { veil_app_get_app_id(main.1 as *const VeilApp, main_id.as_mut_ptr()) },
            0
        );
        assert_eq!(
            unsafe { veil_app_get_app_id(file.1 as *const VeilApp, file_id.as_mut_ptr()) },
            0
        );
        assert_eq!(
            main_id, file_id,
            "separation must retain the same source app identity"
        );
        let open = std::thread::spawn(move || {
            let mut err = ptr::null_mut();
            let stream = unsafe {
                veil_stream_open(
                    file.1 as *mut VeilApp,
                    PEER.as_ptr(),
                    [0xaa; 32].as_ptr(),
                    0,
                    256 * 1024,
                    &mut err,
                )
            };
            let failed = !err.is_null();
            if failed {
                unsafe { veil_free_string(err) };
            }
            (stream as usize, failed)
        });
        let (lane, opening) = received.recv_timeout(Duration::from_secs(2)).unwrap();
        let header = veil_proto::codec::decode_header(&opening).unwrap();
        assert_eq!(header.msg_type, AppMsg::AppOpen as u16);
        assert_eq!(lane, veil_proto::priority::BACKGROUND);
        assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
        let send = std::thread::spawn(move || {
            let mut err = ptr::null_mut();
            let data = b"chat while file open is waiting";
            let rc = unsafe {
                veil_send(
                    main.1 as *mut VeilApp,
                    PEER.as_ptr(),
                    [0xaa; 32].as_ptr(),
                    0,
                    data.as_ptr(),
                    data.len(),
                    &mut err,
                )
            };
            if !err.is_null() {
                unsafe { veil_free_string(err) };
            }
            rc
        });
        let early_chat = received.recv_timeout(Duration::from_millis(250));
        let open_still_waiting = !open.is_finished();
        // Release the receipt before assertions/cleanup, including the
        // negative control, so neither FFI operation can be stranded.
        bridge
            .pending_receipts
            .lock()
            .unwrap()
            .remove(&(PEER, header.stream_id))
            .unwrap()
            .send(veil_proto::app::receipt_status::ACCEPTED)
            .unwrap();
        let (stream, failed) = open.join().unwrap();
        let send_rc = send.join().unwrap();
        let chat = if let Ok(frame) = &early_chat {
            frame.clone()
        } else {
            received.recv_timeout(Duration::from_secs(2)).unwrap()
        };
        unsafe {
            if stream != 0 {
                veil_stream_close(stream as *mut VeilStreamFfi);
            }
            if isolated {
                veil_app_close(file.1 as *mut VeilApp);
                veil_close(file.0 as *mut VeilHandle);
            }
            veil_app_close(main.1 as *mut VeilApp);
            veil_close(main.0 as *mut VeilHandle);
        }
        shutdown.send(true).unwrap();
        rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
        });
        assert!(stream != 0 && !failed);
        assert_eq!(send_rc, 0);
        assert!(
            open_still_waiting,
            "chat timing must be checked with the receipt outstanding"
        );
        assert_eq!(
            early_chat.is_ok(),
            isolated,
            "shared sender must block; dedicated sender must progress"
        );
        assert_eq!(chat.0, veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE);
        let chat_header = veil_proto::codec::decode_header(&chat.1).unwrap();
        assert_eq!(chat_header.msg_type, AppMsg::AppSend as u16);
        let chat_body = veil_proto::AppSendPayload::decode(&chat.1[HEADER_SIZE..]).unwrap();
        assert_eq!(chat_body.data.as_ref(), b"chat while file open is waiting");
        if let Some(previous) = previous_open {
            assert_eq!(
                opening, previous,
                "local sender endpoint must not change stream wire bytes"
            );
        }
        previous_open = Some(opening);
        assert!(bridge.pending_receipts.lock().unwrap().is_empty());
        assert!(bridge.veil_stream_rx.lock().unwrap().is_empty());
    }
}

#[test]
fn ffi_signalling_datagrams_use_a_separate_source_lane_without_wire_hints() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("ipc.sock");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    let (frames, received) = std::sync::mpsc::channel();
    let mut server = IpcServer::new(
        IpcEndpoint::Unix(socket.clone()),
        shutdown_rx,
        Arc::new(veil_app::registry::AppEndpointRegistry::new()),
        [0x42; 32],
    )
    .with_session_tx_registry(Arc::new(Capture(frames)));
    let task = rt.spawn(async move { server.run().await.unwrap() });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let bound = unsafe { connect_and_bind(socket.to_str().unwrap(), 0) };
    let mut error = ptr::null_mut();
    let bytes = b"opaque application control";
    let result = unsafe {
        veil_send_realtime(
            bound.1 as *mut VeilApp,
            PEER.as_ptr(),
            [0xa1; 32].as_ptr(),
            7,
            bytes.as_ptr(),
            bytes.len(),
            &mut error,
        )
    };
    let error_text = if error.is_null() {
        None
    } else {
        let text = unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned();
        unsafe { veil_free_string(error) };
        Some(text)
    };
    let capture = received.recv_timeout(Duration::from_secs(2));
    unsafe {
        veil_app_close(bound.1 as *mut VeilApp);
        veil_close(bound.0 as *mut VeilHandle);
    }
    shutdown.send(true).unwrap();
    rt.block_on(task).unwrap();
    assert_eq!(result, VEIL_OK, "{error_text:?}");
    let (local_lane, frame) = capture.unwrap();
    assert_eq!(local_lane, veil_proto::priority::BACKGROUND);
    let header = veil_proto::codec::decode_header(&frame).unwrap();
    assert_eq!(header.msg_type, AppMsg::AppRtData as u16);
    assert_eq!(header.priority(), veil_proto::priority::REALTIME);
    assert_eq!(
        header.flags, 0,
        "endpoint lane must not appear on the network"
    );
    let payload = veil_proto::app::AppRtDataPayload::decode(&frame[HEADER_SIZE..]).unwrap();
    assert_eq!(payload.payload, bytes);
    assert_eq!(payload.app_id, [0xa1; 32]);
    assert_eq!(payload.endpoint_id, 7);
}
