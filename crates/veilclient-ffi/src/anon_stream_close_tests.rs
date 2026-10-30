//! Real C read/close calls over an in-memory stream driver and a local IPC
//! client runtime. No peer payload/EOF is released until our FIN arrives.
use super::*;
use std::{io, sync::mpsc as sync_mpsc, time::Duration};
use tokio::sync::mpsc;
use veil_onion_stream::{CellDuplex, Config, End, Frame, OnionStream};

struct Peer {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    bytes: Arc<StdMutex<Vec<u8>>>,
    finished: sync_mpsc::Sender<()>,
    closed: sync_mpsc::Sender<End>,
}

impl Peer {
    fn emit(&self, frame: Frame<'_>) {
        let _ = self.tx.send(frame.encode());
    }
}

impl CellDuplex for Peer {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        match Frame::decode(cell).unwrap() {
            Frame::Syn { stream_id, isn, .. } => self.emit(Frame::SynAck {
                stream_id,
                isn: 500,
                ack: isn.wrapping_add(1),
                win: 4096,
            }),
            Frame::Data {
                stream_id,
                seq,
                payload,
                ..
            } => {
                self.bytes.lock().unwrap().extend_from_slice(payload);
                self.emit(Frame::Ack {
                    stream_id,
                    ack: seq.wrapping_add(payload.len() as u32),
                    win: 4096,
                    sacks: Default::default(),
                });
            }
            Frame::Fin { stream_id, seq } => {
                let _ = self.finished.send(());
                self.emit(Frame::Ack {
                    stream_id,
                    ack: seq.wrapping_add(1),
                    win: 4096,
                    sacks: Default::default(),
                });
                self.emit(Frame::Fin {
                    stream_id,
                    seq: 500,
                });
            }
            _ => (),
        }
        Ok(())
    }

    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.rx.recv().await)
    }

    async fn on_stream_closed(&mut self, _: u32, end: End) {
        let _ = self.closed.send(end);
    }
}

fn close_with_pending_read(busy_writer: bool) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("ipc.sock");
    let server_runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (shutdown, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut server = veil_ipc::IpcServer::new(
        veil_ipc::IpcEndpoint::Unix(socket.clone()),
        shutdown_rx,
        Arc::new(veil_app::registry::AppEndpointRegistry::new()),
        [0x42; 32],
    );
    let serving = server_runtime.spawn(async move { server.run().await.unwrap() });
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !socket.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(socket.exists(), "local IPC fixture did not bind");
    let path = socket.to_str().unwrap();
    let mut error = ptr::null_mut();
    let client = unsafe { veil_connect(path.as_ptr(), path.len(), &mut error) };
    assert!(!client.is_null() && error.is_null());
    let bundle = HandleTable::get(handle_table(), client as usize)
        .unwrap()
        .bundle
        .clone();
    let bytes = Arc::new(StdMutex::new(Vec::new()));
    let (finished, fin) = sync_mpsc::channel();
    let (closed, end) = sync_mpsc::channel();
    let stream = bundle.runtime.block_on(async {
        let (tx, rx) = mpsc::unbounded_channel();
        OnionStream::connect(
            Peer {
                tx,
                rx,
                bytes: bytes.clone(),
                finished,
                closed,
            },
            Config {
                mss: 64,
                init_cwnd: 256,
                recv_window: 4096,
                ..Config::default()
            },
            17,
            100,
        )
    });
    let abort = stream.abort_handle();
    let connection = stream.connection_handle();
    let (reader, writer) = stream.into_split();
    let token = HandleTable::insert(
        anon_stream_table(),
        VeilAnonStreamFfi {
            bundle: bundle.clone(),
            abort: abort.clone(),
            connection,
            reader: TokioMutex::new(Some(reader)),
            writer: TokioMutex::new(Some(writer)),
        },
    );
    let payload = vec![0x6d; 73];
    let wrote = unsafe {
        veil_anon_stream_write(
            token as *mut VeilAnonStreamFfi,
            payload.as_ptr(),
            payload.len(),
            &mut error,
        )
    };
    assert_eq!(wrote, VEIL_OK);
    assert!(error.is_null());
    let current = HandleTable::get(anon_stream_table(), token).unwrap();
    let mut writer_guard = busy_writer.then(|| bundle.runtime.block_on(current.writer.lock()));
    let weak = Arc::downgrade(&current);
    let read = std::thread::spawn(move || {
        let mut out = [0u8; 32];
        let mut error = ptr::null_mut();
        let result = unsafe {
            veil_anon_stream_read(
                token as *mut VeilAnonStreamFfi,
                out.as_mut_ptr(),
                out.len(),
                &mut error,
            )
        };
        if !error.is_null() {
            unsafe { veil_free_string(error) };
        }
        result
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let reading = loop {
        if current.reader.try_lock().is_err() {
            break true;
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    // The read now owns the actual FFI Arc and cannot finish until our FIN.
    let (closing, closed) = sync_mpsc::channel();
    let closer = std::thread::spawn(move || {
        unsafe {
            veil_anon_stream_close(token as *mut VeilAnonStreamFfi);
            veil_anon_stream_close(token as *mut VeilAnonStreamFfi);
        }
        closing.send(()).unwrap();
    });
    let close_returned = closed.recv_timeout(Duration::from_secs(2)).is_ok();
    let tail = b"in-flight writer tail";
    if let Some(writer) = writer_guard.as_mut() {
        // Model the already-entered writer critical section: close must not
        // wait on it synchronously or discard its remaining queued bytes.
        bundle
            .runtime
            .block_on(writer.as_ref().unwrap().write_all(tail))
            .unwrap();
    }
    drop(writer_guard);
    drop(current);
    if !close_returned {
        abort.reset(veil_onion_stream::wire::reset_reason::APP);
    }
    closer.join().unwrap();
    let fin_arrived = fin.recv_timeout(Duration::from_secs(2)).is_ok();
    if !fin_arrived || !reading {
        // Always release the blocked C worker before asserting the regression.
        abort.reset(veil_onion_stream::wire::reset_reason::APP);
    }
    let read_result = read.join().unwrap();
    let stream_end = end.recv_timeout(Duration::from_secs(2)).ok();
    let released = weak.upgrade().is_none();
    unsafe { veil_close(client) };
    shutdown.send(true).unwrap();
    server_runtime.block_on(serving).unwrap();
    let mut expected = payload;
    if busy_writer {
        expected.extend_from_slice(tail);
    }
    assert!(reading, "fixture did not park the real C read");
    assert!(close_returned, "close blocked on an in-flight operation");
    assert!(
        fin_arrived,
        "close waited for its own blocked read before FIN"
    );
    assert_eq!(read_result, 0, "the pending read must see clean EOF");
    assert_eq!(stream_end, Some(End::Eof));
    assert_eq!(*bytes.lock().unwrap(), expected);
    assert!(released, "closed FFI stream Arc remained owned");
}

#[test]
fn close_finishes_while_a_ffi_read_keeps_the_stream_alive() {
    close_with_pending_read(false);
}

#[test]
fn close_finishes_after_a_busy_writer_without_waiting_on_it_inline() {
    close_with_pending_read(true);
}
