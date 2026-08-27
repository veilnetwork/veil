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
                    //
                    // This returned in silence, and silence here is indistinguishable
                    // from delivery: the sender's `veil_send` had already returned OK
                    // (the IPC write to ITS node succeeded), so a node in this state
                    // drops every direct frame ever addressed to it while both ends
                    // report success. Measured 0 of 86 delivered across every payload
                    // size before this line said anything at all.
                    self.logger.warn(
                        "app.ratchet.absent",
                        format!(
                            "sealed app frame from {} DROPPED — this node has no ratchet, \
                             so no direct-session frame can ever be opened",
                            veil_util::bytes_to_hex(&node_id.as_bytes()[..4])
                        ),
                    );
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
                        //
                        // Not a violation, but not nothing either — at debug level
                        // this was invisible on any normally-configured node, and a
                        // peer whose every direct frame fails to open looks exactly
                        // like a peer sending nothing. Warn: the sender believes it
                        // delivered, and only this side knows otherwise.
                        // Whether we hold the peer's PUBLISHED device key decides
                        // whether an inbound prologue may displace a stale entry
                        // (`proves_authorship` in veil-e2e's `open`). That map is
                        // filled as a side effect of resolving a peer's certificate
                        // to SEND to them, so a node that has only ever received
                        // from this peer holds nothing — and then no prologue can
                        // ever replace the entry that keeps refusing. Log it beside
                        // the error: the two together say which of those it is.
                        self.logger.warn(
                            "app.ratchet.open_failed",
                            format!(
                                "sealed app frame from {} DROPPED — {e} \
                                 (published peer key known: {}, stored conversation \
                                 authenticated: {:?})",
                                veil_util::bytes_to_hex(&node_id.as_bytes()[..4]),
                                ratchet.published_ik(node_id.as_bytes()).is_some(),
                                ratchet.peer_entry_authenticated(node_id.as_bytes()),
                            ) + &format!(
                                " kind={} we-hold ratchet_pk={} ek={}",
                                payload.data.get(2).copied().unwrap_or(255),
                                // Compare against the `advertises ratchet_pk=`
                                // in this node's own publish line: a peer seals
                                // to what was PUBLISHED, and can only be
                                // answered with what is still HELD.
                                veil_util::bytes_to_hex(
                                    &self.crypto.mlkem_keys.current_ratchet_pk()[..4]
                                ),
                                veil_util::bytes_to_hex(&self.crypto.mlkem_keys.current_ek()[..4]),
                            ) + &format!(
                                " ratchet-ring pk={} ek={}",
                                // The ring the RATCHET actually opens with, as
                                // opposed to the one the node publishes from.
                                // They are the same Arc at startup and nothing
                                // re-points the ratchet's when the identity is
                                // promoted, so a difference here means peers
                                // seal to a key this node cannot decapsulate.
                                veil_util::bytes_to_hex(
                                    &ratchet
                                        .identity()
                                        .map(|i| i.seed_ring.current_ratchet_pk())
                                        .unwrap_or([0u8; 32])[..4]
                                ),
                                veil_util::bytes_to_hex(
                                    &ratchet
                                        .identity()
                                        .map(|i| i.seed_ring.current_ek())
                                        .unwrap_or([0u8; veil_e2e::EK_BYTES])[..4]
                                ),
                            ),
                        );
                        // The conversation was given up, and the peer does not
                        // know: nothing on a send path reports that a frame did
                        // not open, so without this it keeps sending on a
                        // session no longer at this end and the pair never
                        // recovers. Tell it to start over.
                        //
                        // `NotForThisDevice` earns the same reply (defect №35):
                        // the frame was keyed to a SIBLING device of ours,
                        // because the sender's cert row and its session named
                        // "which device of the family" independently — the row
                        // by an all-zero last_seen tie (whichever the iterator
                        // ended on, cached 30 min), the session by whichever
                        // device rendezvous resolved. Four times out of five in
                        // a five-device family those disagree, and a frame on a
                        // direct session terminates HERE, so it is always the
                        // mismatch and never a sibling's legitimate mail. In
                        // silence the sender re-sends its prologue every ~9 s
                        // forever; this reply makes it drop the conversation
                        // AND the cached row, and the re-key resolves for the
                        // device its session actually ends at.
                        if matches!(
                            e,
                            veil_e2e::RatchetSpliceError::WedgedConversationDropped
                                | veil_e2e::RatchetSpliceError::NotForThisDevice
                        ) {
                            return DispatchResult::Response(crate::encode_response(
                                header,
                                veil_proto::family::FrameFamily::App as u8,
                                AppMsg::AppSendUnopenable as u16,
                                &[],
                            ));
                        }
                    }
                }
                DispatchResult::NoResponse
            }

            // The peer could not open what we sealed for it. Drop our side of
            // the conversation so the next thing we seal starts a fresh key
            // agreement; the peer has already dropped its own.
            //
            // Unauthenticated by construction, and it does not need to be: a
            // false one costs one extra prologue, a true one ignored costs the
            // conversation for good.
            AppMsg::AppSendUnopenable => {
                if let Some(ratchet) = &self.crypto.ratchet {
                    let dropped = ratchet.forget_peer(node_id.as_bytes());
                    self.logger.warn(
                        "app.ratchet.peer_cannot_open",
                        format!(
                            "{} cannot open our sealed frames — dropped {dropped} \
                             conversation(s); the next send re-keys",
                            veil_util::bytes_to_hex(&node_id.as_bytes()[..4])
                        ),
                    );
                }
                // The conversation is not the only thing keyed to the wrong
                // place: the verified-cert cache that keyed it still holds the
                // same row for up to 30 minutes, and a re-key that re-reads it
                // re-seals to the same device the peer just refused (defect
                // №35). Drop the peer's cached rows so the re-key re-resolves
                // — and, when its session names an instance, resolves for THAT
                // device.
                let invalidate = self
                    .peer_cert_invalidate
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone();
                if let Some(invalidate) = invalidate {
                    invalidate(node_id.as_bytes());
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
    use std::sync::Arc;

    use veil_app::registry::{AppMessage, SenderProvenance};
    use veil_proto::app::AppOpenPayload;
    use veil_proto::family::{AppMsg, FrameFamily};
    use veil_proto::header::FrameHeader;

    fn ratchet_runtime(node_id: [u8; 32], instance: [u8; 16]) -> veil_e2e::RatchetRuntime {
        let (ek, dk) = veil_e2e::generate_keypair();
        veil_e2e::RatchetRuntime {
            store: Arc::new(veil_e2e::RatchetStore::new()),
            seed_ring: Arc::new(std::sync::RwLock::new(Arc::new(
                veil_e2e::MlKemSeedRing::new(0, dk, ek),
            ))),
            local_node_id: Arc::new(std::sync::RwLock::new(node_id)),
            local_instance_id: Arc::new(std::sync::RwLock::new(Some(instance))),
            peer_ratchet_keys: Arc::new(std::sync::RwLock::new(
                veil_e2e::PeerRatchetKeyCache::new(),
            )),
        }
    }

    /// Defect №35, the recipient's half. A direct-session frame keyed to a
    /// SIBLING device of ours is always the sender's cert-row/session
    /// mismatch — the session terminates here, so no sibling's legitimate
    /// mail can arrive on it — and in silence the sender re-sends its
    /// prologue every ~9 s forever. It must earn the same `AppSendUnopenable`
    /// reply a dropped wedged conversation earns.
    #[test]
    fn a_frame_keyed_to_a_sibling_device_earns_the_unopenable_reply() {
        let us = [0xBBu8; 32];
        let sender_id = [0xAAu8; 32];

        let mut disp = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let our_rt = ratchet_runtime(us, [0x0B; 16]);
        let our_ring = Arc::clone(&our_rt.seed_ring.read().expect("ring"));
        disp.crypto = Arc::new(crate::CryptoContext {
            ratchet: Some(our_rt),
            ..(*disp.crypto).clone()
        });

        // The sender seals to our identity's published keys but names our
        // sibling — the two independent answers to "which device of the
        // family" (its cached cert row's tie accident vs. the device its
        // session actually reached) disagreeing, as they do 4/5 of the time
        // in a five-device family.
        let sender_rt = ratchet_runtime(sender_id, [0x0A; 16]);
        let ek = our_ring.current_ek();
        let ratchet_pk = our_ring.current_ratchet_pk();
        let (sealed, _ack_key) = sender_rt
            .seal_for(
                veil_e2e::PeerRatchetKeys {
                    node_id: &us,
                    instance_id: &[0x0C; 16], // a sibling, not our [0x0B; 16]
                    mlkem_ek: &ek,
                    ratchet_pk: &ratchet_pk,
                    authorized_until_unix: u64::MAX,
                },
                b"keyed to the wrong device",
                veil_util::unix_secs_now_u64(),
            )
            .expect("seal");

        let body = veil_proto::app::AppSendPayload {
            src_app_id: [0x11; 32],
            app_id: [0x22; 32],
            endpoint_id: 7,
            data: veil_bufpool::pooled_shared_from_vec(sealed),
        }
        .encode();
        let mut hdr = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppSendSealed as u16);
        hdr.body_len = body.len() as u32;

        let crate::DispatchResult::Response(reply) = disp.dispatch(&hdr, &body, sender_id) else {
            panic!("a sibling-keyed frame must answer the sender, not drop in silence");
        };
        let reply_hdr = veil_proto::codec::decode_header(&reply).expect("reply header");
        assert_eq!(
            reply_hdr.msg_type,
            AppMsg::AppSendUnopenable as u16,
            "the reply that makes the sender re-key instead of retrying forever"
        );
    }

    /// The sender-side half of the same feedback: an inbound
    /// `AppSendUnopenable` must invalidate the peer's cached certificate rows
    /// (via the runtime-wired hook), or the re-key it triggers re-reads the
    /// 30-minute cache and re-seals to the very row the peer just refused.
    #[test]
    fn an_unopenable_reply_drops_the_peers_cached_certs() {
        let disp = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let hits: Arc<std::sync::Mutex<Vec<[u8; 32]>>> = Arc::default();
        {
            let hits = Arc::clone(&hits);
            *disp
                .peer_cert_invalidate
                .lock()
                .unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(move |peer: &[u8; 32]| {
                hits.lock().unwrap_or_else(|p| p.into_inner()).push(*peer);
            }));
        }

        let peer = [0xAAu8; 32];
        let hdr = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppSendUnopenable as u16);
        disp.dispatch(&hdr, &[], peer);

        assert_eq!(
            hits.lock().unwrap_or_else(|p| p.into_inner()).as_slice(),
            &[peer],
            "exactly the refusing peer's rows, nobody else's"
        );
    }

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
