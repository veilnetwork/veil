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
use crate::frame_io::write_frame_wh;
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
    client_state: &mut IpcClientState,
    app_registry: &AppEndpointRegistry,
    stream_table: &IpcStreamTable,
    src_node_id: &[u8; 32],
    session_tx_registry: Option<&dyn FrameBroadcaster>,
    stream_bridge: Option<&IpcStreamBridge>,
) -> std::io::Result<()> {
    // Per-client stream-open quota: refuse new opens once the cumulative
    // count for this IPC session reaches the cap, even if the global
    // `MAX_TOTAL_STREAMS` still has room.  Without this check a single
    // misbehaving local app can exhaust the global pool and starve every
    // other client on the same node.
    if client_state.stream_quota_exhausted() {
        let err = StreamOpenErrPayload {
            error_code: stream_open_err::CAPACITY_REACHED,
        };
        return write_frame_wh(
            wh,
            FrameFamily::LocalApp as u8,
            LocalAppMsg::StreamOpenErr as u16,
            &err.encode(),
        )
        .await;
    }

    let p = match StreamOpenPayload::decode(body) {
        Ok(p) => p,
        Err(_) => {
            let err = StreamOpenErrPayload {
                error_code: stream_open_err::NOT_FOUND,
            };
            return write_frame_wh(
                wh,
                FrameFamily::LocalApp as u8,
                LocalAppMsg::StreamOpenErr as u16,
                &err.encode(),
            )
            .await;
        }
    };

    // Cross-node STREAM_OPEN: `dst_node_id` is a remote peer. Implemented via
    // the wire AppOpen/AppData/AppClose machinery + a per-stream bridge task —
    // see `handle_stream_open_remote` (the path mirrors
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
                handle_stream_open_remote(wh, &p, client_state, stream_table, broadcaster, bridge)
                    .await
            }
            _ => reply_stream_open_err(wh, stream_open_err::REMOTE_NOT_IMPLEMENTED).await,
        };
    }

    let b_tx = match app_registry.get_sender(p.app_id, p.endpoint_id) {
        Some(tx) => tx,
        None => {
            let err = StreamOpenErrPayload {
                error_code: stream_open_err::NOT_FOUND,
            };
            return write_frame_wh(
                wh,
                FrameFamily::LocalApp as u8,
                LocalAppMsg::StreamOpenErr as u16,
                &err.encode(),
            )
            .await;
        }
    };

    let Some(stream_id) = stream_table.open_local(
        client_state.delivery_tx_clone(),
        b_tx,
        *src_node_id,
        p.initial_window,
    ) else {
        let err = StreamOpenErrPayload {
            error_code: stream_open_err::CAPACITY_REACHED,
        };
        return write_frame_wh(
            wh,
            FrameFamily::LocalApp as u8,
            LocalAppMsg::StreamOpenErr as u16,
            &err.encode(),
        )
        .await;
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
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::StreamOpenOk as u16,
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
    p: &StreamOpenPayload,
    client_state: &mut IpcClientState,
    stream_table: &IpcStreamTable,
    broadcaster: &dyn FrameBroadcaster,
    bridge: &IpcStreamBridge,
) -> std::io::Result<()> {
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
        .insert(wire_stream_id, receipt_tx);
    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(veil_proto::budget::PROXY_STREAM_CHANNEL_CAP);
    bridge
        .veil_stream_rx
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert((dst, wire_stream_id), data_tx);

    // Send AppOpen to the remote node.
    if !send_app_open(broadcaster, &dst, wire_stream_id, p.app_id, p.endpoint_id) {
        deregister_wire_stream(bridge, &dst, wire_stream_id);
        return reply_stream_open_err(wh, stream_open_err::NO_SESSION).await;
    }

    // Await the open receipt.
    let status = match tokio::time::timeout(OPEN_RECEIPT_TIMEOUT, receipt_rx).await {
        Ok(Ok(status)) => status,
        // Timeout, or the dispatcher dropped the waiter without a status.
        Ok(Err(_)) | Err(_) => {
            deregister_wire_stream(bridge, &dst, wire_stream_id);
            return reply_stream_open_err(wh, stream_open_err::REMOTE_TIMEOUT).await;
        }
    };
    if status != receipt_status::ACCEPTED {
        deregister_wire_stream(bridge, &dst, wire_stream_id);
        return reply_stream_open_err(wh, stream_open_err::REFUSED).await;
    }

    // Accepted — reserve the IPC-facing stream-id + outbound route.
    let Some(ipc_stream_id) =
        stream_table.open_remote(dst, wire_stream_id, p.app_id, p.endpoint_id)
    else {
        // The remote already ACCEPTED (it holds wire-side stream state), but we
        // cannot reserve a local IPC stream-id (table at capacity). Tell the
        // remote to release its half before tearing down our registrations,
        // otherwise it leaks the accepted stream until its own idle reaper.
        send_app_close(broadcaster, &dst, wire_stream_id, p.app_id, p.endpoint_id);
        deregister_wire_stream(bridge, &dst, wire_stream_id);
        return reply_stream_open_err(wh, stream_open_err::CAPACITY_REACHED).await;
    };
    client_state.record_stream_opened();
    client_state.claim_stream_opener(ipc_stream_id);

    // Spawn the inbound bridge: remote AppData (routed by the dispatcher into
    // `data_rx`) → IPC STREAM_DATA frames pushed to this client's delivery
    // channel; tears down + emits STREAM_CLOSE when the remote side closes.
    tokio::spawn(run_remote_stream_bridge(
        data_rx,
        client_state.delivery_tx_clone(),
        ipc_stream_id,
        dst,
        wire_stream_id,
        Arc::clone(&bridge.veil_stream_rx),
        stream_table.clone(),
    ));

    let ok = StreamOpenOkPayload {
        stream_id: ipc_stream_id,
        initial_window: STREAM_INITIAL_WINDOW,
    };
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::StreamOpenOk as u16,
        &ok.encode(),
    )
    .await
}

/// Inbound pump for a remote-bound stream: forwards bytes the dispatcher routes
/// into `data_rx` to the IPC client as `STREAM_DATA` frames. Exits when the
/// remote closes (the dispatcher drops the sender) or the client's delivery
/// channel is gone, cleaning up the bridge tables and — if it was the first to
/// close the stream — notifying the client with a `STREAM_CLOSE`.
async fn run_remote_stream_bridge(
    mut data_rx: mpsc::Receiver<Vec<u8>>,
    delivery_tx: mpsc::Sender<veil_bufpool::PooledShared>,
    ipc_stream_id: u32,
    dst_node_id: [u8; 32],
    wire_stream_id: u32,
    veil_stream_rx: VeilStreamRxMap,
    stream_table: IpcStreamTable,
) {
    while let Some(data) = data_rx.recv().await {
        let frame = encode_stream_data(ipc_stream_id, &data);
        if delivery_tx.try_send(frame).is_err() {
            // Client's delivery channel is full or gone — tear the stream down.
            break;
        }
    }
    // `data_rx` closed: the dispatcher dropped the sender on inbound AppClose
    // (remote-initiated close) or on backpressure. Remove our registration and,
    // if WE are the side that closes the table entry first (i.e. the local
    // STREAM_CLOSE arm has not already removed it), notify the client.
    veil_stream_rx
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&(dst_node_id, wire_stream_id));
    if stream_table.close_remote(ipc_stream_id).is_some() {
        let _ = delivery_tx.try_send(encode_stream_close(ipc_stream_id));
    }
}

/// Reply a `STREAM_OPEN_ERR` with `code`.
async fn reply_stream_open_err(wh: &mut IpcWriteHalf, code: u16) -> std::io::Result<()> {
    let err = StreamOpenErrPayload { error_code: code };
    write_frame_wh(
        wh,
        FrameFamily::LocalApp as u8,
        LocalAppMsg::StreamOpenErr as u16,
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
        .remove(&wire_stream_id);
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
            Arc::clone(&osr),
            table.clone(),
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
}
