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
        assert_eq!(chat.0, veil_proto::priority::INTERACTIVE);
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
