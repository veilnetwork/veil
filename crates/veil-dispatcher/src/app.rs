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
use veil_util::lock;

/// The least time between two `AppSendUnopenable` replies to one peer.
pub(crate) const UNOPENABLE_REPLY_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(10);

impl FrameDispatcher {
    /// Whether `peer` may be told `AppSendUnopenable` now, recording it if so.
    pub(crate) fn unopenable_reply_due(&self, peer: [u8; 32]) -> bool {
        let now = std::time::Instant::now();
        let mut replied = self
            .unopenable_replied
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(at) = replied.get(&peer)
            && now.duration_since(*at) < UNOPENABLE_REPLY_INTERVAL
        {
            return false;
        }
        // Bounded: entries past the interval carry no information.
        if replied.len() >= 1024 {
            replied.retain(|_, at| now.duration_since(*at) < UNOPENABLE_REPLY_INTERVAL);
        }
        replied.insert(peer, now);
        true
    }

    pub fn dispatch_app(
        &self,
        header: &FrameHeader,
        body: &[u8],
        node_id: NodeId,
    ) -> DispatchResult {
        // WHO THIS FRAME IS FROM, as the application knows them.
        //
        // `node_id` is the SESSION peer, and on a sovereign install that is the
        // DEVICE key the handshake proved. Everything above this line addresses
        // a CONTACT, and a contact is an identity: the ratchet keys its
        // conversations by `(my device, peer IDENTITY)` and carries the peer's
        // device in the payload header instead, and the app was told an address
        // its user has never seen.
        //
        // Passing the device meant `peer_devices()` found no published keys and
        // the conversation lookup found no conversation, so every sealed frame
        // that arrived over a DIRECT session was dropped — measured on the
        // stand 2026-09-19 as `app.ratchet.open_failed … published peer key
        // known: false, stored conversation authenticated: None`, while the
        // same messages arrived fine through the relay path that had the
        // identity all along.
        //
        // Falls back to the session peer exactly as `node_id_for_peer`
        // documents: a legacy peer proves no identity and IS its own address.
        let sender = sovereign_sender_of(self.session_registry.as_deref(), &node_id);
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
                // And the session peer is the DEVICE, which is who waits for
                // the answer (see `origin_device`).
                self.app_registry.route_ipc_deliver_from_device(
                    sender,
                    veil_app::registry::SenderProvenance::SessionPeer,
                    *node_id.as_bytes(),
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
                match ratchet.open_payload(&sender, &payload.data, now_unix) {
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
                        // The session peer is the device that sealed it and
                        // is waiting for the answer (see `origin_device`).
                        self.app_registry.route_ipc_deliver_from_device(
                            sender,
                            provenance,
                            *node_id.as_bytes(),
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
                                veil_util::bytes_to_hex(&sender[..4]),
                                ratchet.published_ik(&sender).is_some(),
                                ratchet.peer_entry_authenticated(&sender),
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
                        //
                        // `NoSession` earns it too. It is what every frame of
                        // the OLD conversation gets once this side has given
                        // it up — the common case after an outage — and in
                        // silence the sender keeps sealing into a chain nobody
                        // holds, never starting over (owner's decision 1a,
                        // 2026-09-23). Rate-limited per peer, see
                        // `unopenable_replied`.
                        if matches!(
                            e,
                            veil_e2e::RatchetSpliceError::WedgedConversationDropped
                                | veil_e2e::RatchetSpliceError::NotForThisDevice
                                | veil_e2e::RatchetSpliceError::NoSession
                        ) && self.unopenable_reply_due(sender)
                        {
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
                    let dropped = ratchet.forget_peer(&sender);
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
                // THE SENDER, same as both branches above — and this is the
                // one that carries call signalling.
                //
                // The app registers its realtime endpoint under the CONTACT,
                // and a contact is an identity. Routing by the session peer
                // handed the registry a DEVICE id it had never seen, so every
                // `XVSG` frame was received, counted, and dropped: measured on
                // the stand 2026-09-19 as `app.rt_control.route peer=8313f2f7
                // … routed=false` while the callee sat in `active tr=p2p` and
                // the caller stayed in `dialing` until it gave up. The offer
                // survived only because it also travels the message path.
                let routed = self.app_registry.route_rt_data(sender, payload);
                if is_xveil_signal {
                    log::info!(
                        "app.rt_control.route peer={} app={} endpoint_id={} bytes={} routed={}",
                        veil_util::bytes_to_hex(&sender[..4]),
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

    /// A frame over a direct session reaches the app naming the DEVICE it
    /// came from — the session peer, which the handshake proved — beside the
    /// sender. That is who waits for the acknowledgement: answering the
    /// identity instead let routing pick a sibling, and the device that sent
    /// kept re-sending into a flood of misrouted acks.
    #[test]
    fn a_direct_frame_names_the_device_it_came_from() {
        let device = [0xD7u8; 32];
        let disp = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let (_handle, mut rx) = disp.app_registry.register([0x22; 32], 7, 4);
        let body = veil_proto::app::AppSendPayload {
            src_app_id: [0x11; 32],
            app_id: [0x22; 32],
            endpoint_id: 7,
            data: veil_bufpool::pooled_shared_from_vec(b"hi".to_vec()),
        }
        .encode();
        let mut hdr = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppSend as u16);
        hdr.body_len = body.len() as u32;
        disp.dispatch(&hdr, &body, device);
        match rx.try_recv() {
            Ok(veil_app::registry::AppMessage::Deliver { origin_device, .. }) => {
                assert_eq!(origin_device, Some(device));
            }
            other => panic!("expected a Deliver, got {other:?}"),
        }
    }

    /// A frame of a conversation we no longer hold — what every frame of the
    /// old conversation gets once this side has given it up — earns the same
    /// reply, so the sender starts over instead of sealing into a chain nobody
    /// holds. Once per interval per peer: the frames it had in flight keep
    /// coming, and answering each would kill the conversation it just began.
    #[test]
    fn a_frame_for_a_conversation_we_do_not_hold_earns_one_unopenable_reply() {
        let us = [0xBBu8; 32];
        let sender_id = [0xAAu8; 32];
        let mut disp = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        disp.crypto = Arc::new(crate::CryptoContext {
            ratchet: Some(ratchet_runtime(us, [0x0B; 16])),
            ..(*disp.crypto).clone()
        });

        // marker ‖ version ‖ kind=FRAME ‖ sender_instance ‖ OUR instance ‖ body
        let mut sealed = vec![veil_proto::RATCHET_E2E_MARKER, 1, 1];
        sealed.extend_from_slice(&[0x0A; 16]);
        sealed.extend_from_slice(&[0x0B; 16]);
        sealed.extend_from_slice(&[0x5A; 64]);
        let frame = |data: Vec<u8>| {
            let body = veil_proto::app::AppSendPayload {
                src_app_id: [0x11; 32],
                app_id: [0x22; 32],
                endpoint_id: 7,
                data: veil_bufpool::pooled_shared_from_vec(data),
            }
            .encode();
            let mut hdr = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppSendSealed as u16);
            hdr.body_len = body.len() as u32;
            (hdr, body)
        };

        let (hdr, body) = frame(sealed.clone());
        let crate::DispatchResult::Response(reply) = disp.dispatch(&hdr, &body, sender_id) else {
            panic!("a frame for a dropped conversation must tell the sender to start over");
        };
        assert_eq!(
            veil_proto::codec::decode_header(&reply)
                .expect("hdr")
                .msg_type,
            AppMsg::AppSendUnopenable as u16,
        );
        let (hdr, body) = frame(sealed.clone());
        assert!(
            matches!(
                disp.dispatch(&hdr, &body, sender_id),
                crate::DispatchResult::NoResponse
            ),
            "the second in-flight frame must not be answered again at once",
        );
        let (hdr, body) = frame(sealed);
        assert!(
            matches!(
                disp.dispatch(&hdr, &body, [0xCCu8; 32]),
                crate::DispatchResult::Response(_)
            ),
            "the limit is per peer, not global",
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

/// The address an APPLICATION knows this session's peer by.
///
/// Split out of `dispatch_app` so the choice can be exercised without standing
/// up a dispatcher, a ratchet and a live session: it is one decision — which of
/// a peer's TWO names to hand upward — and it is the decision that was wrong.
///
/// Returns the peer's sovereign identity when the OVL1 handshake proved one,
/// and the session peer itself otherwise. The fallback is the contract
/// `SessionRegistry::node_id_for_peer` states: a legacy peer proves no identity
/// and IS its own address.
pub(crate) fn sovereign_sender_of(
    session_registry: Option<&std::sync::Mutex<veil_session::SessionRegistry>>,
    peer: &NodeId,
) -> [u8; 32] {
    session_registry
        .and_then(|reg| lock!(reg).node_id_for_peer(peer))
        .unwrap_or(*peer.as_bytes())
}

#[cfg(test)]
mod sender_identity_tests {
    use super::*;
    use std::sync::Mutex;
    use veil_proto::session::{
        AttachPayload, CapabilitiesPayload, IdentityPayload, cap_flags, role_bits,
    };

    const DEVICE: [u8; 32] = [0x01u8; 32];
    const IDENTITY: [u8; 32] = [0x56u8; 32];

    /// The defect: the app was handed the DEVICE, so the ratchet looked its
    /// conversation up under an address the user has never seen.
    #[test]
    fn a_proved_peer_is_named_by_its_identity() {
        let reg = Mutex::new(registry_with(Some(IDENTITY)));
        assert_eq!(
            sovereign_sender_of(Some(&reg), &NodeId::from(DEVICE)),
            IDENTITY,
            "a peer that PROVED an identity must be named by it",
        );
    }

    /// A legacy peer proves nothing and IS its own address — the fallback
    /// `node_id_for_peer` documents. Silently renaming it would break every
    /// pre-sovereign conversation.
    #[test]
    fn an_unproved_peer_stays_its_own_address() {
        let reg = Mutex::new(registry_with(None));
        assert_eq!(
            sovereign_sender_of(Some(&reg), &NodeId::from(DEVICE)),
            DEVICE,
            "without a proof the peer is its own name",
        );
    }

    /// A dispatcher built without a session registry (test wiring, sovereign
    /// routing bypassed) must keep the behaviour it had, not lose the sender.
    #[test]
    fn without_a_registry_the_peer_is_its_own_address() {
        assert_eq!(
            sovereign_sender_of(None, &NodeId::from(DEVICE)),
            DEVICE,
            "no registry must not mean no sender",
        );
    }

    fn registry_with(sovereign: Option<[u8; 32]>) -> veil_session::SessionRegistry {
        let mut reg = veil_session::SessionRegistry::new();
        reg.insert(veil_session::SessionEntry {
            session_id: [0x77; 32],
            remote_node_id: DEVICE,
            remote_identity: IdentityPayload {
                algo: 1,
                public_key: DEVICE.to_vec(),
                nonce: b"nonce".to_vec(),
                node_id: DEVICE,
                mlkem_pubkey: None,
            },
            remote_capabilities: CapabilitiesPayload {
                roles_supported: role_bits::CORE,
                flags: cap_flags::CAN_RELAY,
                discovery_mode: 0,
            },
            remote_attach: AttachPayload {
                role: 3,
                realm_id: 0,
                attach_epoch: 1,
                mailbox_preference_count: 0,
                gateway_preference_count: 0,
                flags: 0,
            },
            remote_role: veil_session::RemoteRole::Core,
            validated_sovereign_identity: sovereign.map(|node_id| {
                veil_identity::verify::ValidatedIdentity {
                    node_id,
                    master_algo: 0,
                    master_pubkey: vec![0xEE; 32],
                    active_identity_pubkey: vec![0xFF; 32],
                    active_identity_algo: 0,
                    active_key_idx: 0,
                    active_device_id: DEVICE,
                    active_instance_id: [0xCC; 16],
                }
            }),
        });
        reg
    }
}
