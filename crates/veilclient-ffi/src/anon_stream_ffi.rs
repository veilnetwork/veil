//! The anonymous stream: open, accept, read, write, finish, close, abort.
//!
//! Seven calls and a warm-up, and the machinery they drive is
//! [`crate::anon_stream`] — the circuit, the window, the reset protocol. Same
//! division as the media plane: the surface is small and the machinery is not,
//! and they were in different files already except that the surface was not in
//! a file of its own.
//!
//! The eight sat in TWO runs in `lib.rs` with three hundred lines of media
//! queue internals wedged between them. Nothing about that was a boundary; it
//! was where the media work happened to be typed.
//!
//! Moved verbatim (report24 RUNTIME-3), `pub mod` so cbindgen keeps every
//! declaration. The header is reordered and the ABI contract hash moves with
//! it; nothing is added or removed.

// `node-embedded`-only, like everything in it — the third time this file
// shape has come up, and the reason the glob cannot just be left alone: the
// unused-import lint sees it as dead under default features.
#[cfg(feature = "node-embedded")]
use super::*;

/// Open an anonymous reliable byte-stream to a peer. `dst_app_id` is the peer's
/// onion-stream endpoint app id (`deriveAppId(peer_node, "xveil",
/// "onion-stream")` — the Dart caller derives it, mirroring `veil_stream_open`).
/// Returns NULL on error.
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_anon_stream_open(
    handle: *mut VeilHandle,
    dst_node_id: *const u8,
    dst_app_id: *const u8,
    err_out: *mut *mut c_char,
) -> *mut VeilAnonStreamFfi {
    if unsafe { guard::ffi_prelude(err_out, "veil_anon_stream_open") }.is_err() {
        return ptr::null_mut();
    }
    null_check_with_default!(err_out, ptr::null_mut(),
        "handle" => handle,
        "dst_node_id" => dst_node_id,
        "dst_app_id" => dst_app_id,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        ptr::null_mut(),
        "VeilHandle"
    );
    let mut node = [0u8; 32];
    let mut app = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(dst_node_id, node.as_mut_ptr(), 32);
        ptr::copy_nonoverlapping(dst_app_id, app.as_mut_ptr(), 32);
    }
    let hub = match ensure_anon_hub(&handle_live.bundle, &handle_live.anon_hub) {
        Ok(h) => h,
        Err(e) => {
            unsafe { write_err(err_out, format!("anon stream open: {e}")) };
            return ptr::null_mut();
        }
    };
    let bundle = Arc::clone(&handle_live.bundle);
    // open() spawns the stream driver, so it must run inside the runtime.
    let stream = bundle
        .runtime
        .block_on(async { hub.open(veil_onion_stream::Addr { node, app }) });
    let abort = stream.abort_handle();
    let (rd, wr) = stream.into_split();
    let ffi = VeilAnonStreamFfi {
        bundle,
        abort,
        reader: TokioMutex::new(Some(rd)),
        writer: TokioMutex::new(Some(wr)),
    };
    HandleTable::insert(anon_stream_table(), ffi) as *mut VeilAnonStreamFfi
}

/// Accept the next inbound anonymous stream, or NULL on timeout (no error) /
/// error. On success writes the initiator's 32-byte node id + onion-stream app
/// id into the out params (caller-allocated, 32 B each).
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_anon_stream_accept(
    handle: *mut VeilHandle,
    timeout_ms: u64,
    out_src_node_id: *mut u8,
    out_src_app_id: *mut u8,
    err_out: *mut *mut c_char,
) -> *mut VeilAnonStreamFfi {
    if unsafe { guard::ffi_prelude(err_out, "veil_anon_stream_accept") }.is_err() {
        return ptr::null_mut();
    }
    null_check_with_default!(err_out, ptr::null_mut(),
        "handle" => handle,
        "out_src_node_id" => out_src_node_id,
        "out_src_app_id" => out_src_app_id,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        ptr::null_mut(),
        "VeilHandle"
    );
    let hub = match ensure_anon_hub(&handle_live.bundle, &handle_live.anon_hub) {
        Ok(h) => h,
        Err(e) => {
            unsafe { write_err(err_out, format!("anon stream accept: {e}")) };
            return ptr::null_mut();
        }
    };
    let bundle = Arc::clone(&handle_live.bundle);
    let accepted = bundle.runtime.block_on(async {
        tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), hub.accept()).await
    });
    match accepted {
        Ok(Some((stream, src))) => {
            unsafe {
                ptr::copy_nonoverlapping(src.node.as_ptr(), out_src_node_id, 32);
                ptr::copy_nonoverlapping(src.app.as_ptr(), out_src_app_id, 32);
            }
            let abort = stream.abort_handle();
            let (rd, wr) = stream.into_split();
            let ffi = VeilAnonStreamFfi {
                bundle,
                abort,
                reader: TokioMutex::new(Some(rd)),
                writer: TokioMutex::new(Some(wr)),
            };
            HandleTable::insert(anon_stream_table(), ffi) as *mut VeilAnonStreamFfi
        }
        Ok(None) => ptr::null_mut(),      // hub closed
        Err(_elapsed) => ptr::null_mut(), // timeout — caller polls again
    }
}

/// Pre-warm the anonymous-stream outbound circuit pool toward a peer.
/// Fire-and-forget: kicks the background pool open (resolve ads + open +
/// confirm) and returns immediately, so a freshly-restarted node's first
/// serve/pull does not pay the cold-pool price inside the peer's manifest
/// window. Idempotent; cheap when the pool is already up. Returns 0 on
/// dispatch, -1 on error (NULL args / dead handle / hub bind failure).
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_anon_stream_warm_peer(
    handle: *mut VeilHandle,
    dst_node_id: *const u8,
    err_out: *mut *mut c_char,
) -> i32 {
    if unsafe { guard::ffi_prelude(err_out, "veil_anon_stream_warm_peer") }.is_err() {
        return -1;
    }
    null_check_with_default!(err_out, -1,
        "handle" => handle,
        "dst_node_id" => dst_node_id,
    );
    get_or_return!(
        handle_live,
        handle_table(),
        handle,
        err_out,
        -1,
        "VeilHandle"
    );
    let mut node = [0u8; 32];
    unsafe {
        ptr::copy_nonoverlapping(dst_node_id, node.as_mut_ptr(), 32);
    }
    let hub = match ensure_anon_hub(&handle_live.bundle, &handle_live.anon_hub) {
        Ok(h) => h,
        Err(e) => {
            unsafe { write_err(err_out, format!("anon stream warm: {e}")) };
            return -1;
        }
    };
    handle_live.bundle.runtime.spawn(async move {
        hub.warm_outbound(node).await;
    });
    0
}

/// Read up to `cap` bytes. Returns the count (0 = clean EOF), or a negative
/// error code (the stream was reset → the app should resume).
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_anon_stream_read(
    stream: *mut VeilAnonStreamFfi,
    buf: *mut u8,
    cap: size_t,
    err_out: *mut *mut c_char,
) -> ssize_t {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_anon_stream_read") } {
        return rc as ssize_t;
    }
    if stream.is_null() || buf.is_null() {
        unsafe { write_err(err_out, "stream or buf is NULL") };
        return VEIL_ERR_INVALID_ARG as ssize_t;
    }
    if cap == 0 {
        return 0;
    }
    if cap > VEIL_MAX_DATA_LEN {
        unsafe { write_err(err_out, format!("cap {cap} exceeds VEIL_MAX_DATA_LEN")) };
        return VEIL_ERR_INVALID_ARG as ssize_t;
    }
    get_or_return!(
        stream_ref,
        anon_stream_table(),
        stream,
        err_out,
        VEIL_ERR_INVALID_ARG as ssize_t,
        "VeilAnonStreamFfi"
    );
    let res: Result<usize, String> = stream_ref.bundle.runtime.block_on(async {
        let mut guard = stream_ref.reader.lock().await;
        let Some(rd) = guard.as_mut() else {
            return Err("stream closed".to_string());
        };
        let mut tmp = vec![0u8; cap];
        let n = rd.read(&mut tmp).await.map_err(|e| e.to_string())?;
        unsafe { ptr::copy_nonoverlapping(tmp.as_ptr(), buf, n) };
        Ok(n)
    });
    match res {
        Ok(n) => n as ssize_t,
        Err(e) => {
            unsafe { write_err(err_out, e) };
            VEIL_ERR as ssize_t
        }
    }
}

/// Queue `len` bytes for reliable delivery. Returns `VEIL_OK` / a negative code.
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_anon_stream_write(
    stream: *mut VeilAnonStreamFfi,
    data: *const u8,
    len: size_t,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_anon_stream_write") } {
        return rc;
    }
    null_check!(err_out, "stream" => stream);
    if data.is_null() && len > 0 {
        unsafe { write_err(err_out, "data is NULL but len > 0") };
        return VEIL_ERR_INVALID_ARG;
    }
    if len > VEIL_MAX_DATA_LEN {
        unsafe { write_err(err_out, format!("data len {len} exceeds VEIL_MAX_DATA_LEN")) };
        return VEIL_ERR_INVALID_ARG;
    }
    get_or_return!(
        stream_ref,
        anon_stream_table(),
        stream,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilAnonStreamFfi"
    );
    let payload = if len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(data, len) }.to_vec()
    };
    let res: Result<(), String> = stream_ref.bundle.runtime.block_on(async {
        let guard = stream_ref.writer.lock().await;
        let Some(wr) = guard.as_ref() else {
            return Err("stream closed".to_string());
        };
        wr.write_all(&payload).await.map_err(|e| e.to_string())
    });
    match res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            unsafe { write_err(err_out, e) };
            VEIL_ERR_CLOSED
        }
    }
}

/// Half-close the send direction (a FIN follows the last queued byte). The peer
/// reads EOF. Returns `VEIL_OK` / a negative code.
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_anon_stream_finish(
    stream: *mut VeilAnonStreamFfi,
    err_out: *mut *mut c_char,
) -> c_int {
    if let Err(rc) = unsafe { guard::ffi_prelude(err_out, "veil_anon_stream_finish") } {
        return rc;
    }
    null_check!(err_out, "stream" => stream);
    get_or_return!(
        stream_ref,
        anon_stream_table(),
        stream,
        err_out,
        VEIL_ERR_INVALID_ARG,
        "VeilAnonStreamFfi"
    );
    let res: Result<(), String> = stream_ref.bundle.runtime.block_on(async {
        let guard = stream_ref.writer.lock().await;
        let Some(wr) = guard.as_ref() else {
            return Err("stream closed".to_string());
        };
        wr.finish().await.map_err(|e| e.to_string())
    });
    match res {
        Ok(()) => VEIL_OK,
        Err(e) => {
            unsafe { write_err(err_out, e) };
            VEIL_ERR_CLOSED
        }
    }
}

/// Close + free the stream handle (idempotent, NULL-safe). This is the graceful
/// resource-release path: dropping the write half closes the command channel, so
/// the driver finishes the send direction rather than resetting normal EOF.
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_anon_stream_close(stream: *mut VeilAnonStreamFfi) {
    if stream.is_null() {
        return;
    }
    let _ = HandleTable::remove(anon_stream_table(), stream as usize);
}

/// Abort + free the stream handle (idempotent, NULL-safe). Use for timeout /
/// retry cancellation. A Dart timeout may call this while another FFI worker is
/// blocked inside `read()`, and removing the generational handle alone does not
/// wake that already-cloned Arc. First signal the local read half, then send a
/// best-effort RST through the driver so the peer/route settle too.
#[unsafe(no_mangle)]
#[cfg(feature = "node-embedded")]
pub unsafe extern "C" fn veil_anon_stream_abort(stream: *mut VeilAnonStreamFfi) {
    if stream.is_null() {
        return;
    }
    let Some(stream_ref) = HandleTable::remove(anon_stream_table(), stream as usize) else {
        return;
    };
    stream_ref
        .abort
        .abort(veil_onion_stream::wire::reset_reason::APP);
    let bundle = Arc::clone(&stream_ref.bundle);
    let _task = bundle.runtime.spawn(async move {
        let guard = stream_ref.writer.lock().await;
        if let Some(wr) = guard.as_ref() {
            wr.abort_local(veil_onion_stream::wire::reset_reason::APP);
            wr.reset(veil_onion_stream::wire::reset_reason::APP).await;
        }
    });
}
