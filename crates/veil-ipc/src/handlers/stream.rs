//! `STREAM_OPEN` handler — open a new reliable bidirectional byte stream
//! to a local app endpoint.
//!
//! Stages: per-client open-quota gate → decode `StreamOpenPayload` →
//! resolve target `(app_id, endpoint_id)` to the receiving endpoint's
//! sender → reserve a `stream_id` in the global `IpcStreamTable` → claim
//! ownership on this connection (so cross-client hijack via a guessed
//! `stream_id` is impossible) → reply `STREAM_OPEN_OK` with initial window.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use veil_app::registry::AppEndpointRegistry;
use veil_proto::{
    FrameFamily, LocalAppMsg, STREAM_INITIAL_WINDOW, StreamOpenErrPayload, StreamOpenOkPayload,
    StreamOpenPayload,
    app::{AppClosePayload, AppDataPayload, AppOpenPayload, close_reason, receipt_status},
    codec::encode_header,
    family::AppMsg,
    header::{FrameHeader, priority},
    stream_open_err,
};
use veil_types::FrameBroadcaster;

use crate::bridge::{IpcStreamBridge, VeilStreamRxMap};
use crate::server::IpcClientState;
use crate::streams::{IpcStreamTable, encode_stream_close, encode_stream_data};
use crate::transport::IpcWriteHalf;

/// How long `handle_stream_open_remote` waits for the remote node's
/// `AppReceipt` after sending `AppOpen` before giving up. Mirrors
/// `VeilConnector`'s `OPEN_RECEIPT_TIMEOUT`.
const OPEN_RECEIPT_TIMEOUT: Duration = Duration::from_secs(5);

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_stream_open(
    wh: &mut IpcWriteHalf,
    body: &[u8],
    req_id: u32,
    client_state: &mut IpcClientState,
    app_registry: &AppEndpointRegistry,
    stream_table: &IpcStreamTable,
    src_node_id: &[u8; 32],
    session_tx_registry: Option<Arc<dyn FrameBroadcaster>>,
    stream_bridge: Option<&IpcStreamBridge>,
    spawn_sem: &Arc<tokio::sync::Semaphore>,
    reply_tx: &mpsc::Sender<crate::server::LoopReply>,
) -> std::io::Result<()> {
    // `req_id` echo discipline: StreamOpenOk/Err replies for one connection
    // may come from BOTH the inline path (local opens) and spawned tasks
    // (remote opens). The id-stamping client matches replies by id, so when
    // `req_id != 0` EVERY reply — inline or spawned, ok or err — must echo
    // it; a single id-less reply would fall back to positional FIFO and could
    // be matched to the wrong waiter. Legacy clients stamp 0 and everything
    // stays inline + in-order.

    // Per-client stream-open quota: refuse new opens once the cumulative
    // count for this IPC session reaches the cap, even if the global
    // `MAX_TOTAL_STREAMS` still has room.  Without this check a single
    // misbehaving local app can exhaust the global pool and starve every
    // other client on the same node.
    if client_state.stream_quota_exhausted() {
        return reply_stream_open_err(wh, req_id, stream_open_err::CAPACITY_REACHED).await;
    }

    let p = match StreamOpenPayload::decode(body) {
        Ok(p) => p,
        Err(_) => {
            return reply_stream_open_err(wh, req_id, stream_open_err::NOT_FOUND).await;
        }
    };

    // Cross-node STREAM_OPEN: `dst_node_id` is a remote peer. Implemented via
    // the wire AppOpen/AppData/AppClose machinery + a per-stream bridge task —
    // see `open_remote_stream` (the path mirrors
    // `veil_proxy::VeilConnector`, which has used the same building blocks
    // for the proxy surfaces since Epic 33). Plan + history:
    // `docs/en/PLAN_IPC_STREAM_FORWARDING.md` (Phases 2-4, 2026-06-03).
    if p.dst_node_id != *src_node_id {
        // Cross-node STREAM_OPEN. When the daemon has wired the stream bridge
        // (the shared veil_stream_rx / pending_receipts tables + the wire
        // stream-id counter) AND a session-tx broadcaster is available, forward
        // the open onto the wire `AppOpen`/`AppData`/`AppClose` machinery.
        // Otherwise (tests / setups without a full NodeRuntime) surface the
        // documented `REMOTE_NOT_IMPLEMENTED` so callers get a clean error
        // rather than a hang.
        return match (session_tx_registry, stream_bridge) {
            (Some(broadcaster), Some(bridge)) => {
                // Remote opens await the peer's AppReceipt (up to 5 s) — the
                // seconds-class arc of audit V. With a non-zero req_id and a
                // free spawn slot, run it off-loop so it can't freeze the
                // connection; ownership claiming (which needs `&mut
                // client_state`) is carried back to the loop via
                // `LoopReply::RemoteStreamOpened`.
                if req_id != 0
                    && let Ok(permit) = Arc::clone(spawn_sem).try_acquire_owned()
                {
                    // Reserve the per-session quota at REQUEST time: N spawned
                    // opens in flight may not overshoot the cap. Failed
                    // attempts consume quota (conservative; the cap only
                    // guards pool exhaustion).
                    client_state.record_stream_opened();
                    let delivery_tx = client_state.delivery_tx_clone();
                    let stream_table = stream_table.clone();
                    let bridge = bridge.clone();
                    let reply_tx = reply_tx.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        let msg = match open_remote_stream(
                            &p,
                            delivery_tx,
                            &stream_table,
                            broadcaster,
                            &bridge,
                        )
                        .await
                        {
                            Ok(ipc_stream_id) => {
                                let ok = StreamOpenOkPayload {
                                    stream_id: ipc_stream_id,
                                    initial_window: STREAM_INITIAL_WINDOW,
                                };
                                crate::server::LoopReply::RemoteStreamOpened {
                                    ipc_stream_id,
                                    frame: crate::frame_io::encode_reply_frame_id(
                                        LocalAppMsg::StreamOpenOk as u16,
                                        req_id,
                                        &ok.encode(),
                                    ),
                                }
                            }
                            Err(code) => crate::server::LoopReply::Frame(
                                crate::frame_io::encode_reply_frame_id(
                                    LocalAppMsg::StreamOpenErr as u16,
                                    req_id,
                                    &StreamOpenErrPayload { error_code: code }.encode(),
                                ),
                            ),
                        };
                        let _ = reply_tx.send(msg).await;
                    });
                    Ok(())
                } else {
                    handle_stream_open_remote(
                        wh,
                        req_id,
                        &p,
                        client_state,
                        stream_table,
                        broadcaster,
                        bridge,
                    )
                    .await
                }
            }
            _ => reply_stream_open_err(wh, req_id, stream_open_err::REMOTE_NOT_IMPLEMENTED).await,
        };
    }

    let b_tx = match app_registry.get_sender(p.app_id, p.endpoint_id) {
        Some(tx) => tx,
        None => {
            return reply_stream_open_err(wh, req_id, stream_open_err::NOT_FOUND).await;
        }
    };

    let Some(stream_id) = stream_table.open_local(
        client_state.delivery_tx_clone(),
        b_tx,
        *src_node_id,
        p.initial_window,
    ) else {
        return reply_stream_open_err(wh, req_id, stream_open_err::CAPACITY_REACHED).await;
    };
    client_state.record_stream_opened();
    // Claim opener-side ownership so cross-client hijack via a known /
    // guessed `stream_id` is prevented downstream.  The acceptor side
    // claims its own ownership separately inside the per-endpoint
    // forwarder when it translates `AppMessage::StreamOpen` into a
    // `STREAM_OPEN_INBOUND` IPC frame.
    client_state.claim_stream_opener(stream_id);

    let ok = StreamOpenOkPayload {
        stream_id,
        initial_window: STREAM_INITIAL_WINDOW,
    };
    crate::frame_io::write_frame_wh_id(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::StreamOpenOk as u16,
        req_id,
        &ok.encode(),
    )
    .await
}

// ── Cross-node (remote) STREAM_OPEN ───────────────────────────────────────────

/// Open a stream to an endpoint on a **remote** node by bridging the IPC
/// `STREAM_OPEN` onto the wire `AppOpen`/`AppData`/`AppClose` machinery — the
/// same path `veil_proxy::VeilConnector` uses for the proxy surfaces.
///
/// Flow: allocate a wire stream-id from the shared counter → register the
/// inbound-data channel + receipt waiter → send `AppOpen` → await `AppReceipt`
/// (5 s) → on ACCEPTED, reserve the IPC stream-id, spawn the inbound bridge
/// task, and reply `STREAM_OPEN_OK`. Every failure path deregisters the bridge
/// tables and replies a distinct `STREAM_OPEN_ERR` code (never a silent hang).
async fn handle_stream_open_remote(
    wh: &mut IpcWriteHalf,
    req_id: u32,
    p: &StreamOpenPayload,
    client_state: &mut IpcClientState,
    stream_table: &IpcStreamTable,
    broadcaster: Arc<dyn FrameBroadcaster>,
    bridge: &IpcStreamBridge,
) -> std::io::Result<()> {
    let delivery_tx = client_state.delivery_tx_clone();
    match open_remote_stream(p, delivery_tx, stream_table, broadcaster, bridge).await {
        Ok(ipc_stream_id) => {
            client_state.record_stream_opened();
            client_state.claim_stream_opener(ipc_stream_id);
            let ok = StreamOpenOkPayload {
                stream_id: ipc_stream_id,
                initial_window: STREAM_INITIAL_WINDOW,
            };
            crate::frame_io::write_frame_wh_id(
                wh,
                FrameFamily::LocalApp as u8,
                LocalAppMsg::StreamOpenOk as u16,
                req_id,
                &ok.encode(),
            )
            .await
        }
        Err(code) => reply_stream_open_err(wh, req_id, code).await,
    }
}

/// Core of the cross-node open — everything except the per-connection pieces
/// (ownership claim + reply write), so it can run either inline on the
/// connection loop or in a spawned task (request-id concurrency). On success
/// the inbound bridge task is already running and the IPC stream-id is
/// reserved; the CALLER must claim opener ownership before the client learns
/// the id. On failure every registration is rolled back and the
/// `stream_open_err` code is returned.
async fn open_remote_stream(
    p: &StreamOpenPayload,
    delivery_tx: crate::server::DeliveryQueueTx,
    stream_table: &IpcStreamTable,
    broadcaster: Arc<dyn FrameBroadcaster>,
    bridge: &IpcStreamBridge,
) -> Result<u32, u16> {
    use std::sync::atomic::Ordering;

    let dst = p.dst_node_id;
    let wire_stream_id = bridge.wire_stream_counter.fetch_add(1, Ordering::Relaxed);

    // Register the receipt waiter + inbound data channel BEFORE sending AppOpen
    // so a fast remote cannot reply before we are listening.
    let (receipt_tx, receipt_rx) = oneshot::channel::<u8>();
    bridge
        .pending_receipts
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert((dst, wire_stream_id), receipt_tx);
    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(veil_proto::budget::PROXY_STREAM_CHANNEL_CAP);
    bridge
        .veil_stream_rx
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert((dst, wire_stream_id), data_tx);

    // Send AppOpen to the remote node.
    if !send_app_open(
        broadcaster.as_ref(),
        &dst,
        wire_stream_id,
        p.app_id,
        p.endpoint_id,
    ) {
        deregister_wire_stream(bridge, &dst, wire_stream_id);
        return Err(stream_open_err::NO_SESSION);
    }

    // Await the open receipt.
    let status = match tokio::time::timeout(OPEN_RECEIPT_TIMEOUT, receipt_rx).await {
        Ok(Ok(status)) => status,
        // Timeout, or the dispatcher dropped the waiter without a status.
        Ok(Err(_)) | Err(_) => {
            deregister_wire_stream(bridge, &dst, wire_stream_id);
            return Err(stream_open_err::REMOTE_TIMEOUT);
        }
    };
    if status != receipt_status::ACCEPTED {
        deregister_wire_stream(bridge, &dst, wire_stream_id);
        return Err(stream_open_err::REFUSED);
    }

    // Accepted — reserve the IPC-facing stream-id + outbound route.
    let Some(ipc_stream_id) =
        stream_table.open_remote(dst, wire_stream_id, p.app_id, p.endpoint_id)
    else {
        // The remote already ACCEPTED (it holds wire-side stream state), but we
        // cannot reserve a local IPC stream-id (table at capacity). Tell the
        // remote to release its half before tearing down our registrations,
        // otherwise it leaks the accepted stream until its own idle reaper.
        send_app_close(
            broadcaster.as_ref(),
            &dst,
            wire_stream_id,
            p.app_id,
            p.endpoint_id,
        );
        deregister_wire_stream(bridge, &dst, wire_stream_id);
        return Err(stream_open_err::CAPACITY_REACHED);
    };

    // Spawn the inbound bridge: remote AppData (routed by the dispatcher into
    // `data_rx`) → IPC STREAM_DATA frames pushed to this client's delivery
    // channel; tears down + emits STREAM_CLOSE when the remote side closes.
    tokio::spawn(run_remote_stream_bridge(
        data_rx,
        delivery_tx,
        ipc_stream_id,
        dst,
        wire_stream_id,
        p.app_id,
        p.endpoint_id,
        Arc::clone(&bridge.veil_stream_rx),
        stream_table.clone(),
        Arc::clone(&broadcaster),
    ));

    Ok(ipc_stream_id)
}

/// Inbound pump for a remote-bound stream: forwards bytes the dispatcher routes
/// into `data_rx` to the IPC client as `STREAM_DATA` frames. Exits when the
/// remote closes (the dispatcher drops the sender) or the client's delivery
/// channel is gone, cleaning up the bridge tables and — if it was the first to
/// close the stream — notifying the client with a `STREAM_CLOSE`.
// Threads the per-stream identity (dst/wire/app/endpoint) plus the broadcaster
// needed to emit a wire AppClose on local-backpressure teardown; splitting into
// a struct would obscure the plain spawn call site for no real benefit.
#[allow(clippy::too_many_arguments)]
async fn run_remote_stream_bridge(
    mut data_rx: mpsc::Receiver<Vec<u8>>,
    delivery_tx: impl Into<crate::server::DeliveryQueueTx>,
    ipc_stream_id: u32,
    dst_node_id: [u8; 32],
    wire_stream_id: u32,
    app_id: [u8; 32],
    endpoint_id: u32,
    veil_stream_rx: VeilStreamRxMap,
    stream_table: IpcStreamTable,
    broadcaster: Arc<dyn FrameBroadcaster>,
) {
    let delivery_tx = delivery_tx.into();
    let mut local_backpressure = false;
    while let Some(data) = data_rx.recv().await {
        let frame = encode_stream_data(ipc_stream_id, &data);
        if delivery_tx.try_send(frame).is_err() {
            // Client's delivery channel is full or gone — tear the stream down.
            local_backpressure = true;
            break;
        }
    }
    // `data_rx` closed: the dispatcher dropped the sender on inbound AppClose
    // (remote-initiated close) or we broke out on local backpressure. Remove our
    // registration and, if WE are the side that closes the table entry first
    // (i.e. the local STREAM_CLOSE arm has not already removed it), notify the
    // client.
    veil_stream_rx
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&(dst_node_id, wire_stream_id));
    if stream_table.close_remote(ipc_stream_id).is_some() {
        let _ = delivery_tx.try_send(encode_stream_close(ipc_stream_id));
    }
    // If we tore the stream down because the LOCAL client stopped reading
    // (backpressure), the remote peer's wire-side stream is still OPEN — it never
    // saw an AppClose. Send one now so the peer releases its half immediately
    // instead of leaking the wire stream until its own idle reaper fires.
    // (When `data_rx` simply closed, the remote already initiated the close, so
    // no AppClose is owed — mirrors the capacity-reached path above.)
    if local_backpressure {
        send_app_close(
            broadcaster.as_ref(),
            &dst_node_id,
            wire_stream_id,
            app_id,
            endpoint_id,
        );
    }
}

/// Reply a `STREAM_OPEN_ERR` with `code`.
async fn reply_stream_open_err(
    wh: &mut IpcWriteHalf,
    req_id: u32,
    code: u16,
) -> std::io::Result<()> {
    let err = StreamOpenErrPayload { error_code: code };
    crate::frame_io::write_frame_wh_id(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::StreamOpenErr as u16,
        req_id,
        &err.encode(),
    )
    .await
}

/// Drop the receipt waiter + inbound-data registration for a wire stream that
/// failed to open (so a rejected/timed-out open leaks nothing).
fn deregister_wire_stream(bridge: &IpcStreamBridge, dst: &[u8; 32], wire_stream_id: u32) {
    bridge
        .pending_receipts
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&(*dst, wire_stream_id));
    bridge
        .veil_stream_rx
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&(*dst, wire_stream_id));
}

// ── Wire-frame encoders (shared with the server dispatch loop) ─────────────────

/// Encode + send an `AppOpen` frame on `wire_stream_id`. Returns `false` if
/// there is no session to `dst` (the send was dropped).
pub(crate) fn send_app_open(
    broadcaster: &dyn FrameBroadcaster,
    dst: &[u8; 32],
    wire_stream_id: u32,
    app_id: [u8; 32],
    endpoint_id: u32,
) -> bool {
    let body = AppOpenPayload {
        app_id,
        endpoint_id,
        flags: 0,
    }
    .encode();
    send_app_frame(broadcaster, dst, wire_stream_id, AppMsg::AppOpen, &body)
}

/// Encode + send an `AppData` frame carrying `data` on `wire_stream_id`.
pub(crate) fn send_app_data(
    broadcaster: &dyn FrameBroadcaster,
    dst: &[u8; 32],
    wire_stream_id: u32,
    app_id: [u8; 32],
    endpoint_id: u32,
    data: Vec<u8>,
) -> bool {
    let body = AppDataPayload {
        app_id,
        endpoint_id,
        seq: 0, // ordering is maintained by the underlying session transport
        data,
    }
    .encode();
    send_app_frame(broadcaster, dst, wire_stream_id, AppMsg::AppData, &body)
}

/// Encode + send an `AppClose` frame on `wire_stream_id`.
pub(crate) fn send_app_close(
    broadcaster: &dyn FrameBroadcaster,
    dst: &[u8; 32],
    wire_stream_id: u32,
    app_id: [u8; 32],
    endpoint_id: u32,
) -> bool {
    let body = AppClosePayload {
        app_id,
        endpoint_id,
        reason: close_reason::NORMAL,
    }
    .encode();
    send_app_frame(broadcaster, dst, wire_stream_id, AppMsg::AppClose, &body)
}

/// Build the `[header || body]` wire frame for an App-family message on
/// `wire_stream_id` and hand it to the broadcaster at INTERACTIVE priority.
fn send_app_frame(
    broadcaster: &dyn FrameBroadcaster,
    dst: &[u8; 32],
    wire_stream_id: u32,
    msg: AppMsg,
    body: &[u8],
) -> bool {
    let mut hdr = FrameHeader::new(FrameFamily::App as u8, msg as u16);
    hdr.body_len = body.len() as u32;
    hdr.stream_id = wire_stream_id;
    hdr.set_priority(priority::INTERACTIVE);
    let mut frame = encode_header(&hdr).to_vec();
    frame.extend_from_slice(body);
    broadcaster.send_to(dst, priority::INTERACTIVE, frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::{StreamClosePayload, StreamDataPayload, header::HEADER_SIZE};

    /// Test `FrameBroadcaster` that captures every `(peer, frame)` sent so a
    /// test can assert e.g. that a wire `AppClose` went out on teardown.
    #[derive(Default)]
    struct CapturingBroadcaster {
        sent: std::sync::Mutex<Vec<([u8; 32], Vec<u8>)>>,
    }
    impl FrameBroadcaster for CapturingBroadcaster {
        fn send_to(&self, peer_id: &[u8; 32], _priority: u8, bytes: Vec<u8>) -> bool {
            self.sent.lock().unwrap().push((*peer_id, bytes));
            true
        }
        fn send_to_all_with_priority(&self, _priority: u8, _bytes: std::sync::Arc<[u8]>) {}
        fn active_node_ids(&self) -> Vec<[u8; 32]> {
            Vec::new()
        }
    }

    /// Decode a LocalApp IPC frame into `(msg_type, body)`.
    fn parse_local_frame(frame: &[u8]) -> (u16, Vec<u8>) {
        let hdr = veil_proto::codec::decode_header(frame).expect("decode header");
        (hdr.msg_type, frame[HEADER_SIZE..].to_vec())
    }

    /// The inbound bridge forwards remote `AppData` as IPC `STREAM_DATA` frames
    /// and, when the remote closes (the dispatcher drops the sender so `data_rx`
    /// ends), emits a final `STREAM_CLOSE` and removes the remote-stream entry.
    #[tokio::test]
    async fn remote_bridge_pumps_inbound_then_closes_and_cleans_up() {
        let table = IpcStreamTable::new();
        let dst = [3u8; 32];
        let wire_id = 77u32;
        let ipc_id = table.open_remote(dst, wire_id, [1u8; 32], 9).unwrap();

        // Bridge tables, registered the way `handle_stream_open_remote` does.
        let osr: VeilStreamRxMap =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(8);
        osr.lock().unwrap().insert((dst, wire_id), data_tx.clone());
        let (delivery_tx, mut delivery_rx) = mpsc::channel::<veil_bufpool::PooledShared>(8);

        let handle = tokio::spawn(run_remote_stream_bridge(
            data_rx,
            delivery_tx,
            ipc_id,
            dst,
            wire_id,
            [1u8; 32],
            9,
            Arc::clone(&osr),
            table.clone(),
            Arc::new(CapturingBroadcaster::default()) as Arc<dyn FrameBroadcaster>,
        ));

        // Inbound remote bytes → a STREAM_DATA frame addressed to `ipc_id`.
        data_tx.send(b"hello".to_vec()).await.unwrap();
        let frame = delivery_rx.recv().await.expect("stream data frame");
        let (msg, body) = parse_local_frame(frame.as_ref());
        assert_eq!(msg, LocalAppMsg::StreamData as u16);
        let data = StreamDataPayload::decode(&body).unwrap();
        assert_eq!(data.stream_id, ipc_id);
        assert_eq!(data.data, b"hello");

        // Remote close: drop BOTH senders (the original + the map's clone) so
        // `data_rx` ends and the bridge tears the stream down.
        drop(data_tx);
        osr.lock().unwrap().remove(&(dst, wire_id));
        let frame = delivery_rx.recv().await.expect("stream close frame");
        let (msg, body) = parse_local_frame(frame.as_ref());
        assert_eq!(msg, LocalAppMsg::StreamClose as u16);
        assert_eq!(StreamClosePayload::decode(&body).unwrap().stream_id, ipc_id);

        handle.await.unwrap();
        assert!(
            table.remote_route(ipc_id).is_none(),
            "remote entry must be cleaned up after close"
        );
    }

    /// M-2 (audit): when the LOCAL client stops reading and its delivery channel
    /// fills, the bridge must send a wire `AppClose` to the remote peer so it
    /// releases its half immediately — not just close the local side and leak
    /// the remote wire-stream until its idle reaper.
    #[tokio::test]
    async fn remote_bridge_backpressure_sends_wire_app_close() {
        let table = IpcStreamTable::new();
        let dst = [4u8; 32];
        let wire_id = 88u32;
        let app_id = [7u8; 32];
        let endpoint_id = 5u32;
        let ipc_id = table
            .open_remote(dst, wire_id, app_id, endpoint_id)
            .unwrap();
        let osr: VeilStreamRxMap =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(8);
        osr.lock().unwrap().insert((dst, wire_id), data_tx.clone());
        // Delivery channel cap 1 that we never drain (rx held so it's FULL, not
        // closed): the 2nd inbound frame can't be delivered → backpressure.
        let (delivery_tx, _delivery_rx) = mpsc::channel::<veil_bufpool::PooledShared>(1);
        let bc = Arc::new(CapturingBroadcaster::default());
        let handle = tokio::spawn(run_remote_stream_bridge(
            data_rx,
            delivery_tx,
            ipc_id,
            dst,
            wire_id,
            app_id,
            endpoint_id,
            Arc::clone(&osr),
            table.clone(),
            Arc::clone(&bc) as Arc<dyn FrameBroadcaster>,
        ));
        data_tx.send(b"a".to_vec()).await.unwrap(); // fills the cap-1 delivery
        data_tx.send(b"b".to_vec()).await.unwrap(); // can't be delivered
        drop(data_tx);
        handle.await.unwrap();

        let sent = bc.sent.lock().unwrap();
        assert_eq!(
            sent.len(),
            1,
            "exactly one wire frame (the AppClose) on backpressure teardown"
        );
        let (peer, frame) = &sent[0];
        assert_eq!(peer, &dst, "AppClose must target the remote peer");
        let hdr = veil_proto::codec::decode_header(frame).expect("decode wire header");
        assert_eq!(
            hdr.msg_type,
            AppMsg::AppClose as u16,
            "teardown frame must be an AppClose"
        );
    }
}
