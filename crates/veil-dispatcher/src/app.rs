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
                // Use the session node_id as src_node_id so the recipient can
                // reply correctly. That id came from the authenticated OVL1
                // session this frame arrived on, not from the frame body, so
                // it is a real identity — the one case that earns
                // `SessionPeer` outright.
                self.app_registry.route_ipc_deliver(
                    *node_id.as_bytes(),
                    veil_app::registry::SenderProvenance::SessionPeer,
                    payload.src_app_id,
                    payload.app_id,
                    payload.endpoint_id,
                    payload.data,
                );
                DispatchResult::NoResponse
            }

            // The same datagram, with the ratchet under it.
            //
            // This is the branch that matters for anyone actually online. An
            // ordinary `AppSend` over a direct session carries NO end-to-end
            // sealing at all: the session's own hop cipher is the only thing
            // protecting it, so the payload is in the clear the moment it
            // leaves that one link, and the sender is only as good as the
            // session peer id. Most one-to-one traffic goes this way, so
            // ratcheting only the relay path would have ratcheted the minority.
            AppMsg::AppSendSealed => {
                let payload = match AppSendPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad AppSendSealed: {e}")),
                };
                let Some(ratchet) = &self.crypto.ratchet else {
                    // No device identity: nothing could have been keyed to us.
                    return DispatchResult::NoResponse;
                };
                let now_unix = veil_util::unix_secs_now_u64();
                match ratchet.open_payload(node_id.as_bytes(), &payload.data, now_unix) {
                    Ok(opened) => {
                        // `SessionPeer` is the floor, not the answer: the frame
                        // did arrive on an authenticated session with this
                        // peer, so even an unmatched device key leaves us
                        // knowing that much. Opening under a session keyed to
                        // the key that peer published is strictly more.
                        let provenance = if opened.authenticated {
                            veil_app::registry::SenderProvenance::Signed
                        } else {
                            veil_app::registry::SenderProvenance::SessionPeer
                        };
                        self.app_registry.route_ipc_deliver(
                            *node_id.as_bytes(),
                            provenance,
                            payload.src_app_id,
                            payload.app_id,
                            payload.endpoint_id,
                            veil_bufpool::pooled_shared_from_vec(opened.plaintext),
                        );
                    }
                    Err(e) => {
                        // Not a violation: a conversation the host has not
                        // restored yet looks exactly like this, and so does a
                        // frame for another of our devices.
                        self.logger.debug("app.ratchet.open_failed", format!("{e}"));
                    }
                }
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
                    // The opener is the authenticated OVL1 session peer this
                    // APP_OPEN arrived on — read from the session, never from
                    // the frame body, so it is an identity and not a claim.
                    *node_id.as_bytes(),
                    veil_app::registry::SenderProvenance::SessionPeer,
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
                let is_xveil_signal = payload.payload_type == u32::from_be_bytes(*b"XVSG");
                let endpoint_id = payload.endpoint_id;
                let app_prefix = veil_util::bytes_to_hex(&payload.app_id[..4]);
                let payload_len = payload.payload.len();
                let routed = self
                    .app_registry
                    .route_rt_data(*node_id.as_bytes(), payload);
                if is_xveil_signal {
                    log::info!(
                        "app.rt_control.route peer={} app={} endpoint_id={} bytes={} routed={}",
                        veil_util::bytes_to_hex(&node_id.as_bytes()[..4]),
                        app_prefix,
                        endpoint_id,
                        payload_len,
                        routed,
                    );
                }
                DispatchResult::NoResponse
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use veil_app::registry::{AppMessage, SenderProvenance};
    use veil_proto::app::AppOpenPayload;
    use veil_proto::family::{AppMsg, FrameFamily};
    use veil_proto::header::FrameHeader;

    /// X/V-01, the stream half. A byte-stream initiator reaches the app as the
    /// same raw 32 bytes a datagram sender did, so it carries a trust level
    /// too — and this is the one path that can legitimately claim
    /// `SessionPeer`, because the id comes from the authenticated OVL1 session
    /// the `APP_OPEN` arrived on rather than from anything in the frame body.
    ///
    /// Asserted on the message the ENDPOINT receives, not on the argument
    /// passed to `route_stream_open`: what matters is what the app is told.
    #[test]
    fn app_open_labels_the_initiator_as_the_authenticated_session_peer() {
        let opener = [0xAAu8; 32];
        let app_id = [0xCCu8; 32];
        let endpoint_id = 0xC0DE;

        let disp = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let (_handle, mut rx) = disp.app_registry.register(app_id, endpoint_id, 16);

        let body = AppOpenPayload {
            app_id,
            endpoint_id,
            flags: 0,
        }
        .encode();
        let mut hdr = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppOpen as u16);
        hdr.body_len = body.len() as u32;
        hdr.stream_id = 9;
        disp.dispatch(&hdr, &body, opener);

        match rx.try_recv() {
            Ok(AppMessage::StreamOpen {
                src_node_id,
                provenance,
                ..
            }) => {
                assert_eq!(src_node_id, opener);
                assert_eq!(
                    provenance,
                    SenderProvenance::SessionPeer,
                    "the opener IS the authenticated session peer — the app \
                     must be told that, not left to assume it",
                );
                assert!(provenance.is_authenticated());
            }
            other => panic!("expected a StreamOpen, got {other:?}"),
        }
    }
}
