//! Edges where the FFI meets the operating system.
//!
//! Moved verbatim out of `lib.rs`, which was fourteen thousand lines with four
//! thousand of them test code interleaved with the production surface
//! (report24 RUNTIME-3). Nothing here is compiled into the library — the
//! module keeps the same `cfg`, the same name and the same `use super::*`, so
//! every test still runs under the path it ran under before.
//!
//! The production code was deliberately NOT moved. cbindgen emits this crate's
//! header in parse order and skips `pub` items it finds in a private module,
//! so moving a section of `lib.rs` into a submodule rewrote the header and
//! DROPPED declarations from it — measured, then reverted. Tests are the part
//! that can move without the header noticing, and this checks that it did not.

//! X/V-01, second half: the trust level must SURVIVE to the FFI edge.
//!
//! `2e5471cc` made the node decide what it knows about a delivery's
//! `src_node_id` and carried that decision as far as the IPC wire. It stopped
//! there: `VeilRecvCb` had no parameter for it, so every host — the app that
//! actually shows the message — saw the same untyped 32 bytes it always had and
//! had no choice but to treat a contact's message and a stranger's frame naming
//! that contact identically. A `grep provenance` over this crate returned
//! nothing; the byte was parsed in Rust and lost one frame later.
//!
//! So the assertion below is made on the BYTE THE C CALLBACK RECEIVES, and the
//! delivery that produces it is stamped at the other end of the real chain:
//!
//! ```text
//! AppEndpointRegistry::route_ipc_deliver   ← where the delivery layer decides
//!   → veil-ipc forward_endpoint → AppDeliverPayload → a real Unix socket
//!   → veilclient reader_task → IncomingMessage
//!   → run_recv_dispatch_loop → cb(.., provenance, ..)   ← asserted here
//! ```
//!
//! Every leg is production code: a real `IpcServer`, a real `VeilClient`, the
//! real dispatch loop. Nothing in this module re-encodes or re-decodes a frame
//! itself, because a test that did would have passed against the broken build —
//! the break was not in any one leg, it was the hand-off between them.

use super::*;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use veilclient::SenderProvenance;

/// The daemon's node id — also the namespace input for the derived app id.
const NODE_ID: [u8; 32] = [0x42u8; 32];
/// A contact this device has accepted. Both deliveries below NAME it; only
/// one of them was authenticated as it.
const CONTACT: [u8; 32] = [0xAAu8; 32];
const NS: &str = "test.xv01";
const NAME: &str = "edge";
const ENDPOINT: u32 = 77;

fn temp_socket() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("veil-xv01-edge-{}-{}.sock", std::process::id(), n))
}

/// One callback invocation as the HOST saw it: the raw provenance byte,
/// the sender's 32 bytes, and the payload.
type Seen = (u8, [u8; 32], Vec<u8>);

/// What the host actually saw, per invocation.
#[derive(Default)]
struct EdgeProbe {
    seen: StdMutex<Vec<Seen>>,
}

/// A host trampoline that records the provenance byte verbatim — it does
/// NOT interpret it, so a wrong value cannot be normalised away here.
unsafe extern "C" fn edge_cb(
    user: *mut std::ffi::c_void,
    node_id: *const u8,
    _app_id: *const u8,
    provenance: u8,
    _reply_id: u64,
    data: *const u8,
    data_len: size_t,
) {
    let probe = unsafe { &*(user as *const EdgeProbe) };
    let src: [u8; 32] = unsafe { std::slice::from_raw_parts(node_id, 32) }
        .try_into()
        .expect("32-byte node id");
    let payload = if data_len > 0 {
        unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec()
    } else {
        Vec::new()
    };
    probe
        .seen
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((provenance, src, payload));
    // Callee owns the `[node_id(32)|app_id(32)|data]` buffer.
    unsafe { veil_free_buf(node_id as *mut u8, 64 + data_len) };
}

/// A delivery the node authenticated must reach the edge as
/// `VEIL_PROVENANCE_SESSION_PEER`; one it merely had a claim for must reach
/// the edge as `VEIL_PROVENANCE_CLAIMED` — with the SAME `src_node_id` in
/// both, which is the whole point: the 32 bytes cannot tell them apart, and
/// until now that was all the host got.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stamped_provenance_survives_from_the_delivery_layer_to_the_ffi_edge() {
    let sock = temp_socket();
    let registry = Arc::new(veil_app::AppEndpointRegistry::new());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut server = veil_ipc::IpcServer::new(
        veil_ipc::IpcEndpoint::Unix(sock.clone()),
        shutdown_rx,
        Arc::clone(&registry),
        NODE_ID,
    );
    let server_task = tokio::spawn(async move {
        let _ = server.run().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = veilclient::VeilClient::connect(&sock)
        .await
        .expect("connect to the test daemon");
    let app_handle = client
        .bind_named(NS, NAME, ENDPOINT)
        .await
        .expect("bind endpoint");
    // Keep the send half alive: dropping it unbinds the endpoint.
    let (_sender, receiver) = app_handle.into_split();
    let (msg_rx, _streams) = receiver.into_parts();

    let probe = Box::new(EdgeProbe::default());
    let cb_cell = Arc::new(StdMutex::new(Some(RecvCbSlot {
        cb: edge_cb,
        user_addr: (&*probe as *const EdgeProbe) as usize,
    })));
    let dispatch_task = tokio::spawn(run_recv_dispatch_loop(msg_rx, Arc::clone(&cb_cell)));

    let app = veil_app::address::app_id(&NODE_ID, NS, NAME);
    // The two calls the delivery plane makes: `terminal_sender_provenance`
    // returns SessionPeer when the claim IS the authenticated session peer,
    // and Claimed for everything relayed or anonymous.
    assert!(
        registry.route_ipc_deliver(
            CONTACT,
            SenderProvenance::SessionPeer,
            [0xA1u8; 32],
            app,
            ENDPOINT,
            veil_bufpool::pooled_shared_from_vec(b"from the contact".to_vec()),
        ),
        "authenticated delivery must be routed to the bound endpoint",
    );
    assert!(
        registry.route_ipc_deliver(
            CONTACT,
            SenderProvenance::Claimed,
            [0xA1u8; 32],
            app,
            ENDPOINT,
            veil_bufpool::pooled_shared_from_vec(b"a stranger naming the contact".to_vec()),
        ),
        "claimed delivery must still be routed — it is labelled, not dropped",
    );

    // Wait for both to land at the edge.
    let t0 = Instant::now();
    loop {
        if probe.seen.lock().unwrap_or_else(|e| e.into_inner()).len() >= 2 {
            break;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "deliveries never reached the FFI callback",
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let seen = probe.seen.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(seen.len(), 2, "expected exactly two deliveries: {seen:?}");

    let (auth_prov, auth_src, auth_data) = &seen[0];
    assert_eq!(
        *auth_src, CONTACT,
        "the sender's 32 bytes must arrive unchanged",
    );
    assert_eq!(auth_data.as_slice(), b"from the contact");
    assert_eq!(
        *auth_prov, VEIL_PROVENANCE_SESSION_PEER,
        "a delivery the node AUTHENTICATED must reach the FFI edge still \
         authenticated — the level is decided in the delivery layer and \
         this byte is the only place a host can read it",
    );

    let (claim_prov, claim_src, claim_data) = &seen[1];
    assert_eq!(
        *claim_src, CONTACT,
        "the spoof carries the very same 32 bytes — that is why the \
         provenance byte has to exist",
    );
    assert_eq!(claim_data.as_slice(), b"a stranger naming the contact");
    assert_eq!(
        *claim_prov, VEIL_PROVENANCE_CLAIMED,
        "a merely CLAIMED sender must reach the FFI edge as a claim",
    );

    // The two are distinguishable at the edge. Without this the pair of
    // assertions above would also pass on a build that hard-coded one
    // constant for every delivery.
    assert_ne!(
        auth_prov, claim_prov,
        "identical `src_node_id`, different evidence — the edge MUST be \
         able to tell them apart",
    );

    drop(_sender);
    drop(client);
    dispatch_task.abort();
    let _ = shutdown_tx.send(true);
    let _ = server_task.await;
    let _ = std::fs::remove_file(&sock);
}

/// The OTHER way a sender reaches the app: a byte-stream initiator.
///
/// `veil_stream_accept` handed out 32 raw bytes with no trust level for the
/// same reason `VeilRecvCb` did — nobody had asked what stood behind them.
/// This drives the whole thing through the PUBLIC C entry points
/// (`veil_connect` → `veil_bind_named` → `veil_stream_open` →
/// `veil_stream_accept`) against a real daemon, and asserts the out-param
/// byte an actual host would read.
///
/// Not a `#[tokio::test]`: `veil_stream_open` / `veil_stream_accept` block
/// on their handle's OWN runtime, which panics if called from inside
/// another one — exactly as they would from a host thread.
#[test]
fn stream_initiator_provenance_reaches_the_ffi_edge() {
    let sock = temp_socket();
    let daemon_rt = build_runtime().expect("daemon runtime");
    let registry = Arc::new(veil_app::AppEndpointRegistry::new());
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut server = veil_ipc::IpcServer::new(
        veil_ipc::IpcEndpoint::Unix(sock.clone()),
        shutdown_rx,
        registry,
        NODE_ID,
    );
    daemon_rt.spawn(async move {
        let _ = server.run().await;
    });
    let t0 = Instant::now();
    while !sock.exists() {
        assert!(t0.elapsed() < Duration::from_secs(10), "daemon never bound");
        std::thread::sleep(Duration::from_millis(10));
    }

    /// `veil_connect` + `veil_bind_named`, through the real C surface.
    fn connect_and_bind(
        sock: &std::path::Path,
        name: &str,
        endpoint: u32,
    ) -> (*mut VeilHandle, *mut VeilApp) {
        let path = sock.to_str().expect("utf-8 socket path");
        let mut err: *mut c_char = ptr::null_mut();
        let handle = unsafe { veil_connect(path.as_ptr(), path.len(), &mut err) };
        assert!(!handle.is_null(), "veil_connect failed");
        let app = unsafe {
            veil_bind_named(
                handle,
                NS.as_ptr(),
                NS.len(),
                name.as_ptr(),
                name.len(),
                endpoint,
                &mut err,
            )
        };
        assert!(!app.is_null(), "veil_bind_named failed");
        (handle, app)
    }

    const ACCEPTOR_NAME: &str = "stream-acceptor";
    const ACCEPTOR_ENDPOINT: u32 = 78;
    let (acceptor_handle, acceptor_app) = connect_and_bind(&sock, ACCEPTOR_NAME, 78);
    let (opener_handle, opener_app) = connect_and_bind(&sock, "stream-opener", 79);

    // Accept on a separate thread: `veil_stream_accept` blocks, and the
    // open below cannot complete until something is there to accept it.
    let acceptor_addr = acceptor_app as usize;
    let accept_thread = std::thread::spawn(move || {
        let app = acceptor_addr as *mut VeilApp;
        let mut out_node = [0u8; 32];
        // Seeded with a value that is NOT the expected answer, so a native
        // side that forgot to write it cannot accidentally pass.
        let mut out_provenance: u8 = 0xFF;
        let mut err: *mut c_char = ptr::null_mut();
        let stream = unsafe {
            veil_stream_accept(
                app,
                5_000,
                out_node.as_mut_ptr(),
                &mut out_provenance,
                &mut err,
            )
        };
        (stream as usize, out_node, out_provenance)
    });
    std::thread::sleep(Duration::from_millis(100));

    let acceptor_app_id = veil_app::address::app_id(&NODE_ID, NS, ACCEPTOR_NAME);
    let mut err: *mut c_char = ptr::null_mut();
    let opened = unsafe {
        veil_stream_open(
            opener_app,
            NODE_ID.as_ptr(),
            acceptor_app_id.as_ptr(),
            ACCEPTOR_ENDPOINT,
            65536,
            &mut err,
        )
    };
    assert!(!opened.is_null(), "veil_stream_open failed");

    let (accepted, src_node, provenance) = accept_thread.join().expect("accept thread");
    assert!(accepted != 0, "veil_stream_accept returned NULL");
    assert_eq!(
        src_node, NODE_ID,
        "a same-node opener is identified by this node's own id",
    );
    assert_eq!(
        provenance, VEIL_PROVENANCE_LOCAL_IPC,
        "the initiator came in over the local IPC socket, and the FFI edge \
         must SAY so — before this, the host got 32 bytes and no evidence \
         at all, which is the same hole X/V-01 was about on the datagram \
         path",
    );

    unsafe {
        veil_stream_close(accepted as *mut VeilStreamFfi);
        veil_stream_close(opened);
        veil_app_close(acceptor_app);
        veil_app_close(opener_app);
        veil_close(acceptor_handle);
        veil_close(opener_handle);
    }
    let _ = shutdown_tx.send(true);
    let _ = std::fs::remove_file(&sock);
}

/// The wire byte and the Rust enum are two spellings of one value; a host
/// reads only the former. If they ever drift, every gate written against
/// the constants silently starts asking a different question.
#[test]
fn provenance_byte_matches_core_enum() {
    assert_eq!(SenderProvenance::Claimed.as_u8(), VEIL_PROVENANCE_CLAIMED);
    assert_eq!(
        SenderProvenance::LocalIpc.as_u8(),
        VEIL_PROVENANCE_LOCAL_IPC
    );
    assert_eq!(
        SenderProvenance::SessionPeer.as_u8(),
        VEIL_PROVENANCE_SESSION_PEER
    );
    assert_eq!(SenderProvenance::Signed.as_u8(), VEIL_PROVENANCE_SIGNED);
    // Fail-closed direction, restated at the boundary that consumes it: a
    // byte no one recognises is a claim, never a promotion.
    for unknown in [4u8, 7, 42, 255] {
        assert_eq!(
            SenderProvenance::from_wire(unknown).as_u8(),
            VEIL_PROVENANCE_CLAIMED,
            "unknown level {unknown} must read as CLAIMED",
        );
    }
}
