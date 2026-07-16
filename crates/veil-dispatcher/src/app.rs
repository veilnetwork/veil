use super::{DispatchResult, FrameDispatcher, encode_response};
use tokio::sync::mpsc;
use veil_cfg::NodeId;
use veil_proto::{
    app::{
        AppClosePayload, AppDataPayload, AppOpenPayload, AppReceiptPayload, AppRtDataPayload,
        AppSendPayload, AppWindowUpdatePayload, receipt_status,
    },
    family::{AppMsg, FrameFamily},
    header::FrameHeader,
};

impl FrameDispatcher {
    pub fn dispatch_app(
        &self,
        header: &FrameHeader,
        body: &[u8],
        node_id: NodeId,
    ) -> DispatchResult {
        // All node roles can receive App frames for local endpoint delivery.
        // Role restrictions apply to relay/DHT participation, not to receiving
        // messages addressed to this node's own registered app endpoints.
        let msg = match AppMsg::try_from(header.msg_type) {
            Ok(m) => m,
            Err(_) => {
                return DispatchResult::Violation(format!(
                    "unknown app msg_type {}",
                    header.msg_type
                ));
            }
        };

        match msg {
            AppMsg::AppData => {
                let payload = match AppDataPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad AppData: {e}")),
                };
                // Locally-initiated veil streams (SOCKS `VeilConnector` or
                // the IPC remote-stream bridge) register their inbound channel
                // ONLY in `veil_stream_rx` and deliberately hold no
                // `AppStreamTable` entry — their flow control is the channel's own
                // backpressure. Route to that channel FIRST, *before* the
                // receive-window check below: that check governs only
                // APP_OPEN-tracked streams and (returning `false` for an unknown
                // stream) would otherwise reject this legitimate inbound data as a
                // window violation, silently breaking the stream's return path.
                {
                    let mut map = self
                        .veil_stream_rx
                        .lock()
                        .unwrap_or_else(|p| p.into_inner());
                    let map_key = (*node_id.as_bytes(), header.stream_id);
                    if let Some(tx) = map.get(&map_key) {
                        match tx.try_send(payload.data) {
                            Ok(()) => return DispatchResult::NoResponse,
                            // Channel full (local SOCKS5/IPC client too slow) or
                            // receiver gone: stop routing AND tell the remote peer
                            // — the data source — to close its half, so it does not
                            // hold the stream open until its own idle reaper fires.
                            // Everything the wire AppClose needs is in hand: dst =
                            // `node_id` (this frame's source), `header.stream_id`,
                            // and `app_id`/`endpoint_id` from the payload. (Pre-fix
                            // we only dropped the local entry, leaving the remote
                            // half-open until timeout — audit M-3.)
                            Err(mpsc::error::TrySendError::Full(_))
                            | Err(mpsc::error::TrySendError::Closed(_)) => {
                                map.remove(&map_key);
                                drop(map);
                                let close = AppClosePayload {
                                    app_id: payload.app_id,
                                    endpoint_id: payload.endpoint_id,
                                    reason: veil_proto::app::close_reason::NORMAL,
                                };
                                return DispatchResult::Response(encode_response(
                                    header,
                                    FrameFamily::App as u8,
                                    AppMsg::AppClose as u16,
                                    &close.encode(),
                                ));
                            }
                        }
                    }
                }
                // Remotely-opened (APP_OPEN-tracked) stream: enforce the receive
                // window before delivering to the local endpoint.
                let byte_count = payload.data.len() as u32;
                if !self.stream_table.record_data_received(
                    node_id.as_bytes(),
                    header.stream_id,
                    byte_count,
                ) {
                    return DispatchResult::Violation("APP_DATA exceeds receive window".to_owned());
                }
                // If this stream_id is tracked in the stream_table (opened via APP_OPEN)
                // route as StreamData so the endpoint can correlate data to the correct stream.
                if self
                    .stream_table
                    .get(node_id.as_bytes(), header.stream_id)
                    .is_some()
                {
                    self.app_registry.route_stream_data(
                        payload.app_id,
                        payload.endpoint_id,
                        header.stream_id,
                        payload.data,
                    );
                } else {
                    self.app_registry.route_data(payload);
                }
                DispatchResult::NoResponse
            }
            AppMsg::AppSend => {
                let payload = match AppSendPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad AppSend: {e}")),
                };
                // Use the session node_id as src_node_id so the recipient can reply correctly.
                self.app_registry.route_ipc_deliver(
                    *node_id.as_bytes(),
                    payload.src_app_id,
                    payload.app_id,
                    payload.endpoint_id,
                    payload.data,
                );
                DispatchResult::NoResponse
            }

            AppMsg::AppOpen => {
                let payload = match AppOpenPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad AppOpen: {e}")),
                };
                let stream_id = header.stream_id;
                let status = match self.stream_table.open(
                    *node_id.as_bytes(),
                    stream_id,
                    payload.app_id,
                    payload.endpoint_id,
                ) {
                    veil_app::OpenResult::Opened => receipt_status::ACCEPTED,
                    veil_app::OpenResult::AlreadyOpen | veil_app::OpenResult::CapacityReached => {
                        // Stream already exists or global/per-peer capacity reached — reject.
                        let receipt = AppReceiptPayload {
                            app_id: payload.app_id,
                            endpoint_id: payload.endpoint_id,
                            seq: 0,
                            status: receipt_status::REJECTED,
                        };
                        return DispatchResult::Response(encode_response(
                            header,
                            FrameFamily::App as u8,
                            veil_proto::family::AppMsg::AppReceipt as u16,
                            &receipt.encode(),
                        ));
                    }
                };
                // Notify the registered endpoint that a new stream was opened.
                self.app_registry.route_stream_open(
                    payload.app_id,
                    payload.endpoint_id,
                    stream_id,
                    *node_id.as_bytes(),
                    veil_app::APP_STREAM_INITIAL_WINDOW,
                );
                let receipt = AppReceiptPayload {
                    app_id: payload.app_id,
                    endpoint_id: payload.endpoint_id,
                    seq: 0,
                    status,
                };
                DispatchResult::Response(encode_response(
                    header,
                    FrameFamily::App as u8,
                    veil_proto::family::AppMsg::AppReceipt as u16,
                    &receipt.encode(),
                ))
            }

            AppMsg::AppClose => {
                let payload = match AppClosePayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad AppClose: {e}")),
                };
                // Notify the endpoint that the remote side closed the stream.
                self.app_registry.route_stream_close(
                    payload.app_id,
                    payload.endpoint_id,
                    header.stream_id,
                );
                self.stream_table
                    .close(node_id.as_bytes(), header.stream_id);
                // A locally-initiated veil/IPC stream (VeilConnector or the
                // IPC remote-stream bridge) registers its inbound channel in
                // `veil_stream_rx`. Drop it on remote close so the bridge
                // task's `data_rx` ends and it can tear down + notify its client;
                // otherwise the inbound channel leaks until the session drops.
                self.veil_stream_rx
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&(*node_id.as_bytes(), header.stream_id));
                // Send ACCEPTED receipt to acknowledge the close.
                let receipt = AppReceiptPayload {
                    app_id: payload.app_id,
                    endpoint_id: payload.endpoint_id,
                    seq: 0,
                    status: receipt_status::ACCEPTED,
                };
                DispatchResult::Response(encode_response(
                    header,
                    FrameFamily::App as u8,
                    veil_proto::family::AppMsg::AppReceipt as u16,
                    &receipt.encode(),
                ))
            }

            AppMsg::AppReceipt => {
                // Receipts from the remote side: route to a pending VeilConnector
                // waiter if one is registered for this stream_id; otherwise drop.
                match AppReceiptPayload::decode(body) {
                    Ok(receipt) => {
                        // Key by (source peer, stream_id): the receipt's sender
                        // is the peer we opened the stream to, matching the
                        // (node_id, wire_stream_id) key the opener registered.
                        // Prevents a receipt from resolving a different peer's
                        // waiter that shares a wire_stream_id (possible only if
                        // the shared u32 counter wrapped — now excluded).
                        if let Some(tx) = self
                            .pending_stream_receipts
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .remove(&(*node_id.as_bytes(), header.stream_id))
                        {
                            let _ = tx.send(receipt.status);
                        }
                        DispatchResult::NoResponse
                    }
                    Err(e) => DispatchResult::Violation(format!("bad AppReceipt: {e}")),
                }
            }

            AppMsg::AppWindowUpdate => {
                let payload = match AppWindowUpdatePayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => {
                        return DispatchResult::Violation(format!("bad AppWindowUpdate: {e}"));
                    }
                };
                self.stream_table.apply_window_update(
                    node_id.as_bytes(),
                    payload.stream_id,
                    payload.increment,
                );
                DispatchResult::NoResponse
            }

            AppMsg::AppRtData => {
                let payload = match AppRtDataPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad AppRtData: {e}")),
                };
                // No window check — real-time frames are loss-tolerant.
                if let Some(m) = &self.metrics {
                    m.inc_rt_frames_rx();
                    m.check_and_count_rt_seq_gap(&payload.app_id, payload.endpoint_id, payload.seq);
                }
                self.app_registry
                    .route_rt_data(*node_id.as_bytes(), payload);
                DispatchResult::NoResponse
            }
        }
    }
}
