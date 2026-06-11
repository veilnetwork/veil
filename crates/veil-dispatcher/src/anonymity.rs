//! Anonymity-cell relay handler.
//!
//! Wires [`crate::node::anonymity`] primitives into the
//! dispatcher's `FrameFamily::RelayChain` slot. Replaces the
//! stub that was returning `Violation` for all
//! RelayChain frames pending an ECDH-based rewrite — 's
//! `cell` + `onion` + `circuit` + `packet` modules ARE that rewrite.
//!
//! # Per-frame flow
//!
//! 1. Decode the frame body as a 512-byte
//!    [`veil_anonymity::cell::CELL_SIZE`] cell — anything
//!    else is a wire-format violation (operator misconfiguration or
//!    deliberate poisoning) and the handler returns `Violation`.
//!
//! 2. Peel one layer using the local node's
//!    `anonymity_x25519_sk` via
//!    [`veil_anonymity::packet::peel_anonymous_cell`].
//!    AEAD failure → `Violation` (likely tampered envelope or
//!    a frame intended for a different relay).
//!
//! 3. On [`CellPeelResult::Forward`]: locate the next-hop session
//!    in `session_tx_registry`, send the inner cell as a fresh
//!    `RelayChain::Hop` frame. If no session exists for the next
//!    hop the cell is dropped — anonymity layer doesn't surface
//!    "next hop offline" to the sender (which would leak path
//!    structure).
//!
//! 4. On [`CellPeelResult::Final`]: this node is the final
//!    destination. v1 simply logs the receipt + records a metric;
//!    a separate slice will wire delivery into a per-app inbox.
//!
//! # Why "drop on next-hop-down" is the right choice
//!
//! Tor handles relay-down by tearing down the circuit and surfacing
//! to the sender so it can rebuild. We don't have circuit state
//! yet, so
//! the alternative is "send an error back through the inbound
//! path". But that error message would leak the position of the
//! failing hop to the sender's previous-hop observer, which is the
//! exact correlation attack the cell+onion+packet machinery is
//! designed to prevent. Silent drop is the safer v1 default; the
//! sender will retry with a fresh circuit when it notices the
//! lack of response at the application layer.

use veil_cfg::NodeId;
#[cfg(test)]
use veil_types::NodeIdBytes;
use veil_util::{lock, wlock};
// `Arc` referenced only from #[cfg(test)] paths in this file;
// cfg-gating the import avoids unused-import warning in non-test builds.
#[cfg(test)]
use std::sync::Arc;

use super::{DispatchResult, FrameDispatcher};
use veil_anonymity::{
    cell::CELL_SIZE,
    packet::{CellPeelResult, peel_anonymous_cell},
    rendezvous::{
        ForwardIntroducePayload, IntroducePayload, RegisterRendezvousPayload, RendezvousSubscriber,
        UnregisterRendezvousPayload, final_hop_kind,
    },
};
use veil_proto::{
    AppDeliverPayload,
    family::{FrameFamily, RelayChainMsg},
    header::FrameHeader,
};

impl FrameDispatcher {
    /// Handle one inbound `FrameFamily::RelayChain` frame. See
    /// module docs for the per-frame flow.
    pub fn dispatch_relay_chain(
        &self,
        header: &FrameHeader,
        body: &[u8],
        node_id: NodeId,
    ) -> DispatchResult {
        // Format checks first (cheap, leak-free). Crypto-key check
        // last (its outcome is the one that could leak relay-capability
        // to a sender probe).
        let msg = match RelayChainMsg::try_from(header.msg_type) {
            Ok(m) => m,
            Err(_) => {
                return DispatchResult::Violation(format!(
                    "RelayChain: unknown msg_type {}",
                    header.msg_type,
                ));
            }
        };

        // Branch on msg_type before the cell-size check: only Hop
        // frames carry 512 B onion cells; Register / Unregister /
        // ForwardIntroduce are plain control frames over an
        // established OVL1 session.
        match msg {
            RelayChainMsg::Hop => {} // fall-through to cell processing below
            RelayChainMsg::RegisterRendezvous => {
                return self.handle_register_rendezvous(body, node_id);
            }
            RelayChainMsg::UnregisterRendezvous => {
                return self.handle_unregister_rendezvous(body, node_id);
            }
            RelayChainMsg::ForwardIntroduce => return self.handle_forward_introduce(body, node_id),
        }

        if body.len() != CELL_SIZE {
            return DispatchResult::Violation(format!(
                "RelayChain::Hop body must be exactly {CELL_SIZE} B; got {}",
                body.len(),
            ));
        }
        // peel_anonymous_cell takes &[u8; CELL_SIZE] — promote.
        let cell: &[u8; CELL_SIZE] = body
            .try_into()
            .expect("body length verified to equal CELL_SIZE");

        // The handler runs only when the operator opted in to being
        // an anonymity relay (`[anonymity].relay_capable = true`)
        // AND the runtime threaded the SK into the dispatcher. When
        // the SK is missing we have no key to peel cells with — drop
        // silently, as if we'd never received the frame, since
        // returning Violation would leak "this node is not a relay"
        // to a sender probing for relay-capable peers.
        let Some(ref sk) = self.anonymity_x25519_sk else {
            // D5: counter for "operator forgot relay_capable=true"
            // vs "active probing for relay-capable peers" — surfacing via
            // metric is what makes this actionable; the log line alone gets
            // lost in volume on a busy bootstrap node.
            if let Some(m) = &self.metrics {
                m.inc_dropped_relay_frames();
            }
            self.logger.info(
                "anonymity.relay_chain.dropped",
                format!(
                    "received RelayChain frame from peer_id={peer_hex} but \
                     local node has no anonymity_x25519_sk (relay_capable=false?)",
                    peer_hex = veil_util::hex_str(node_id.as_bytes())
                ),
            );
            return DispatchResult::NoResponse;
        };

        match peel_anonymous_cell(cell, sk) {
            Ok(CellPeelResult::Forward {
                next_hop,
                outbound_cell,
            }) => {
                // Forward to next_hop's session, if we have one.
                self.forward_anonymous_cell(&next_hop, &outbound_cell);
                DispatchResult::NoResponse
            }
            Ok(CellPeelResult::Final { payload }) => {
                // tag-byte routing. Payload starts with a
                // 1-byte kind selector that tells us whether to
                // deliver locally (APP_DELIVER) or to forward
                // through the rendezvous-relay flow (INTRODUCE).
                if payload.is_empty() {
                    self.logger.info(
                        "anonymity.relay_chain.final.empty",
                        "Final-hop payload is empty (no kind tag); dropped",
                    );
                    return DispatchResult::NoResponse;
                }
                let kind = payload[0];
                let body = &payload[1..];
                match kind {
                    final_hop_kind::APP_DELIVER => self.handle_final_app_deliver(body),
                    final_hop_kind::APP_DELIVER_AUTH => self.handle_final_auth_deliver(body),
                    final_hop_kind::INTRODUCE => self.handle_final_introduce(body),
                    other => {
                        self.logger.info(
                            "anonymity.relay_chain.final.unknown_kind",
                            format!(
                                "Final-hop payload kind=0x{other:02x} not recognised; \
                                 {} B dropped",
                                body.len(),
                            ),
                        );
                        DispatchResult::NoResponse
                    }
                }
            }
            Err(e) => {
                // AEAD verification failed. Most likely: cell wasn't
                // intended for us (we're the wrong relay), or the
                // envelope was tampered with. Either way, silent drop.
                self.logger.info(
                    "anonymity.relay_chain.peel_failed",
                    format!(
                        "from peer_id={}: {e}",
                        veil_util::hex_str(node_id.as_bytes()),
                    ),
                );
                DispatchResult::NoResponse
            }
        }
    }

    /// Final-hop kind=APP_DELIVER: decode AppDeliverPayload and route
    /// to the addressed local endpoint via app_registry.
    /// behaviour, now triggered by explicit kind tag.
    fn handle_final_app_deliver(&self, body: &[u8]) -> DispatchResult {
        let p = match AppDeliverPayload::decode(body) {
            Ok(p) => p,
            Err(e) => {
                self.logger.info(
                    "anonymity.relay_chain.final.decode_failed",
                    format!("AppDeliverPayload decode failed ({} B): {e}", body.len(),),
                );
                return DispatchResult::NoResponse;
            }
        };
        let data_len = p.data.len();
        let endpoint_id = p.endpoint_id;
        let delivered = self.app_registry.route_ipc_deliver(
            p.src_node_id,
            p.src_app_id,
            p.app_id,
            endpoint_id,
            p.data,
        );
        if delivered {
            self.logger.info(
                "anonymity.relay_chain.final.delivered",
                format!(
                    "delivered {data_len} B to local app endpoint \
                     (endpoint_id={endpoint_id})",
                ),
            );
        } else {
            self.logger.info(
                "anonymity.relay_chain.final.unbound",
                format!("no app bound to endpoint_id={endpoint_id}; {data_len} B dropped",),
            );
        }
        DispatchResult::NoResponse
    }

    /// Final-hop kind=APP_DELIVER_AUTH: an authenticated anonymous delivery
    /// (Epic 482 v1). Decode the `AuthAppDeliver` and hand it to the
    /// runtime-owned async verify+deliver task via `auth_deliver_tx`. This
    /// dispatcher is SYNC and has no identity resolver, while verification
    /// needs an async DHT resolve of the sender's identity document — so the
    /// crypto + replay check + final delivery all happen off-thread in the
    /// runtime task. Here we only decode (cheap, leak-free) and enqueue.
    ///
    /// `auth_deliver_tx` is `None` on dispatchers the runtime never wired
    /// (test harnesses) → the cell is dropped, same silent-drop policy as an
    /// unbound endpoint. A full channel also drops (best-effort; the sender
    /// learns from an app-layer timeout, never a synchronous error — which
    /// would leak first-hop reachability).
    fn handle_final_auth_deliver(&self, body: &[u8]) -> DispatchResult {
        let auth = match veil_proto::AuthAppDeliver::decode(body) {
            Ok(a) => a,
            Err(e) => {
                self.logger.info(
                    "anonymity.relay_chain.auth.decode_failed",
                    format!("AuthAppDeliver decode failed ({} B): {e}", body.len()),
                );
                return DispatchResult::NoResponse;
            }
        };
        let tx = match lock!(self.auth_deliver_tx).as_ref().cloned() {
            Some(tx) => tx,
            None => {
                self.logger.info(
                    "anonymity.relay_chain.auth.unwired",
                    "authenticated delivery received but no verify task wired; dropped",
                );
                return DispatchResult::NoResponse;
            }
        };
        if let Err(e) = tx.try_send(auth) {
            // Channel full or closed — best-effort drop. Don't block the
            // session read loop on a slow verifier.
            self.logger.info(
                "anonymity.relay_chain.auth.enqueue_dropped",
                format!("auth-deliver verify queue unavailable; dropped: {e}"),
            );
        }
        DispatchResult::NoResponse
    }

    /// Final-hop kind=INTRODUCE: this node is a rendezvous; look up
    /// the cookie's subscriber and forward the ciphertext over their
    /// established OVL1 session.
    fn handle_final_introduce(&self, body: &[u8]) -> DispatchResult {
        let intro = match IntroducePayload::decode(body) {
            Ok(p) => p,
            Err(e) => {
                self.logger.info(
                    "anonymity.relay_chain.introduce.decode_failed",
                    format!("IntroducePayload decode ({} B): {e}", body.len()),
                );
                return DispatchResult::NoResponse;
            }
        };
        let Some(reg) = &self.rendezvous_registry else {
            self.logger.info(
                "anonymity.relay_chain.introduce.no_registry",
                "no rendezvous registry — node is not acting as a rendezvous",
            );
            return DispatchResult::NoResponse;
        };
        // Look up by (receiver_node_id, cookie). The registry is
        // namespaced by the registrant's authenticated peer_node_id, so
        // this resolves only the genuine receiver's entry — a squatter
        // who registered the same (public) cookie under a different
        // identity is keyed elsewhere and never matched here. This also
        // makes the old explicit `receiver_node_id == peer_node_id`
        // check structurally guaranteed: the resolved subscriber's
        // peer_node_id IS `intro.receiver_node_id`.
        let subscriber = match reg.lookup(&intro.receiver_node_id, &intro.auth_cookie) {
            Some(s) => s,
            None => {
                // No entry for this (receiver, cookie). Silent drop:
                // surfacing this would leak "this rendezvous serves
                // cookie X / Y" to sender probes — exactly what the
                // auth_cookie cipher-shape is designed to hide.
                self.logger.info(
                    "anonymity.relay_chain.introduce.cookie_unknown",
                    "no subscriber registered for this (receiver, auth_cookie); dropped",
                );
                return DispatchResult::NoResponse;
            }
        };
        // Forward the ciphertext over the subscriber's OVL1 session.
        let forward = ForwardIntroducePayload {
            ciphertext: intro.ciphertext,
        };
        let body_bytes = match forward.encode() {
            Ok(b) => b,
            Err(_) => return DispatchResult::NoResponse, // oversize (cap'd anyway)
        };
        // subscriber.peer_node_id is the raw [u8; 32] from the
        // veil-anonymity crate — convert to NodeId at the boundary.
        let target = NodeId::from(subscriber.peer_node_id);
        self.send_relay_chain_msg(&target, RelayChainMsg::ForwardIntroduce, &body_bytes);
        DispatchResult::NoResponse
    }

    /// Receiver → rendezvous: register a cookie. Idempotent on
    /// same-subscriber repeat. Rejects on cookie collision (different
    /// peer holds it) and on registry-full.
    fn handle_register_rendezvous(&self, body: &[u8], node_id: NodeId) -> DispatchResult {
        let req = match RegisterRendezvousPayload::decode(body) {
            Ok(p) => p,
            Err(e) => {
                return DispatchResult::Violation(format!("Register decode: {e}"));
            }
        };
        let Some(reg) = &self.rendezvous_registry else {
            // Node not configured as rendezvous — anti-leak silent drop
            // (returning Violation would identify "this node will not
            // serve as rendezvous" to anyone probing).
            return DispatchResult::NoResponse;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let subscriber = RendezvousSubscriber {
            // veil-anonymity stores peer_node_id as raw [u8; 32]
            // (it's an external crate that doesn't know about
            // `cfg::NodeId`). Convert at the crate boundary.
            peer_node_id: *node_id.as_bytes(),
            receiver_x25519_pk: req.receiver_x25519_pk,
            registered_at_unix: now,
        };
        match reg.register(req.auth_cookie, subscriber) {
            Ok(()) => {
                self.logger.info(
                    "anonymity.relay_chain.register.ok",
                    format!(
                        "registered cookie from peer={}; total registrations={}",
                        veil_util::hex_short(node_id.as_bytes()),
                        reg.len(),
                    ),
                );
            }
            Err(e) => {
                self.logger.warn(
                    "anonymity.relay_chain.register.rejected",
                    format!(
                        "from peer={}: {e}",
                        veil_util::hex_short(node_id.as_bytes()),
                    ),
                );
            }
        }
        DispatchResult::NoResponse
    }

    /// Receiver → rendezvous: drop a previously-registered cookie.
    fn handle_unregister_rendezvous(&self, body: &[u8], node_id: NodeId) -> DispatchResult {
        let req = match UnregisterRendezvousPayload::decode(body) {
            Ok(p) => p,
            Err(e) => {
                return DispatchResult::Violation(format!("Unregister decode: {e}"));
            }
        };
        let Some(reg) = &self.rendezvous_registry else {
            return DispatchResult::NoResponse;
        };
        let removed = reg.unregister(&req.auth_cookie, node_id.as_bytes());
        self.logger.info(
            "anonymity.relay_chain.unregister",
            format!(
                "peer={} requested unregister; removed={removed}",
                veil_util::hex_short(node_id.as_bytes()),
            ),
        );
        DispatchResult::NoResponse
    }

    /// Rendezvous → receiver: forwarded Introduce ciphertext arrived;
    /// decrypt with our anonymity_x25519_sk and route the inner
    /// AppDeliverPayload via app_registry.
    fn handle_forward_introduce(&self, body: &[u8], node_id: NodeId) -> DispatchResult {
        let p = match ForwardIntroducePayload::decode(body) {
            Ok(p) => p,
            Err(e) => {
                return DispatchResult::Violation(format!("ForwardIntroduce decode: {e}"));
            }
        };
        let Some(ref sk) = self.anonymity_x25519_sk else {
            // Not configured for anonymity — silent drop (anti-leak).
            self.logger.info(
                "anonymity.relay_chain.forward.no_sk",
                "received forwarded introduce but no anonymity_x25519_sk wired",
            );
            return DispatchResult::NoResponse;
        };
        // replay-protected decrypt. A captured
        // ciphertext re-submitted to this dispatcher is rejected at
        // the cache lookup BEFORE the AEAD verify, so a replay flood
        // costs only a HashMap lookup per packet.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let plaintext = match veil_anonymity::rendezvous::decrypt_introduce_checked(
            &p.ciphertext,
            sk,
            &self.introduce_replay_cache,
            now_unix,
        ) {
            Ok(pt) => pt,
            Err(veil_anonymity::rendezvous::RendezvousError::Replay) => {
                // Captured-and-replayed Introduce. Silent drop —
                // logging would be a timing oracle confirming "this
                // node decrypted that ciphertext successfully once".
                // Replay-detection counter would land here if a
                // future SOC dashboard requires it; current rate-
                // limit + abuse tracker covers operator visibility.
                return DispatchResult::NoResponse;
            }
            Err(_) => {
                // AEAD failed — most likely sender encrypted to a
                // different x25519 key (stale ad) or random poison.
                // Silent drop.
                self.logger.info(
                    "anonymity.relay_chain.forward.decrypt_failed",
                    format!(
                        "decrypt failed for forward from peer={}",
                        veil_util::hex_short(node_id.as_bytes()),
                    ),
                );
                return DispatchResult::NoResponse;
            }
        };
        // Decrypted plaintext IS an AppDeliverPayload (no tag byte —
        // it's already inside the rendezvous-shielded layer and delivery
        // path is unambiguous).
        let app_deliver = match AppDeliverPayload::decode(&plaintext) {
            Ok(p) => p,
            Err(e) => {
                self.logger.info(
                    "anonymity.relay_chain.forward.payload_decode_failed",
                    format!("AppDeliverPayload decode: {e}"),
                );
                return DispatchResult::NoResponse;
            }
        };
        let data_len = app_deliver.data.len();
        let endpoint_id = app_deliver.endpoint_id;
        let delivered = self.app_registry.route_ipc_deliver(
            app_deliver.src_node_id,
            app_deliver.src_app_id,
            app_deliver.app_id,
            endpoint_id,
            app_deliver.data,
        );
        if delivered {
            self.logger.info(
                "anonymity.relay_chain.forward.delivered",
                format!("delivered {data_len} B via rendezvous to endpoint_id={endpoint_id}",),
            );
        } else {
            self.logger.info(
                "anonymity.relay_chain.forward.unbound",
                format!("no app bound to endpoint_id={endpoint_id}; {data_len} B dropped",),
            );
        }
        DispatchResult::NoResponse
    }

    /// Send a `RelayChain::<msg>` frame with the given body bytes to
    /// the named peer's session. Used by the rendezvous-relay
    /// state machine for receiver↔rendezvous control frames AND
    /// for forwarding cells / introduces.
    fn send_relay_chain_msg(&self, node_id: &NodeId, msg: RelayChainMsg, body: &[u8]) {
        use veil_proto::codec::encode_header;
        let Some(ref reg) = self.session_tx_registry else {
            self.logger.info(
                "anonymity.relay_chain.send.no_registry",
                "session_tx_registry not wired; cannot send",
            );
            return;
        };
        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, msg as u16);
        hdr.body_len = body.len() as u32;
        hdr.set_priority(veil_proto::priority::INTERACTIVE);
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(body);
        let guard = wlock!(reg);
        if !guard.send_to(node_id.as_bytes(), veil_proto::priority::INTERACTIVE, frame) {
            self.logger.info(
                "anonymity.relay_chain.send.peer_unreachable",
                format!(
                    "peer={} has no live session; dropped",
                    veil_util::hex_short(node_id.as_bytes()),
                ),
            );
        }
    }

    /// Forward `outbound_cell` to `next_hop` as a fresh
    /// `RelayChain::Hop` frame. Drops silently when no session
    /// exists for the next hop — see module docs for why.
    fn forward_anonymous_cell(&self, next_hop: &[u8; 32], outbound_cell: &[u8]) {
        use veil_proto::codec::encode_header;
        let Some(ref reg) = self.session_tx_registry else {
            self.logger.info(
                "anonymity.relay_chain.no_registry",
                "session_tx_registry not wired; cannot forward",
            );
            return;
        };
        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
        hdr.body_len = outbound_cell.len() as u32;
        hdr.set_priority(veil_proto::priority::INTERACTIVE);
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(outbound_cell);
        let guard = wlock!(reg);
        if !guard.send_to(next_hop, veil_proto::priority::INTERACTIVE, frame) {
            // Next hop has no live session. Don't retry, don't
            // surface to caller, don't log the next_hop bytes
            // (which would leak the path structure to a verbose-
            // log-watcher).
            self.logger.info(
                "anonymity.relay_chain.next_hop_unreachable",
                "no live session for next hop; cell dropped silently",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use veil_anonymity::{cell::pack, circuit::Hop, packet::build_anonymous_cell};
    use x25519_dalek::{PublicKey, StaticSecret};

    fn fresh_hop(id_byte: u8) -> (StaticSecret, Hop) {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk).to_bytes();
        let mut node_id = [0u8; 32];
        node_id[0] = id_byte;
        (
            sk,
            Hop {
                node_id,
                pubkey: pk,
            },
        )
    }

    /// Sanity wrap: builds a 1-hop cell, peels with the matching key.
    /// Verifies our test fixtures + the underlying crypto agree.
    #[tokio::test]
    async fn epic482_7_test_fixture_sanity_check() {
        let (sk1, hop1) = fresh_hop(0xAA);
        let payload = b"check fixture";
        let cell = build_anonymous_cell(payload, &[hop1]).unwrap();
        match peel_anonymous_cell(&cell, &sk1).unwrap() {
            CellPeelResult::Final { payload: p } => assert_eq!(p.as_slice(), payload),
            _ => panic!("1-hop must yield Final"),
        }
    }

    /// Wrong-size body (not 512 B) must be rejected as Violation.
    #[test]
    fn epic482_7_dispatch_rejects_non_cell_size_body() {
        let dispatcher = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
        hdr.body_len = 100;
        let body = vec![0u8; 100]; // wrong size
        let result = dispatcher.dispatch_relay_chain(&hdr, &body, NodeId::from([0x11u8; 32]));
        match result {
            DispatchResult::Violation(msg) => {
                assert!(
                    msg.contains("CELL_SIZE") || msg.contains("512"),
                    "violation must mention size: {msg}"
                );
            }
            other => panic!("expected Violation, got {other:?}"),
        }
    }

    /// Unknown msg_type must be rejected as Violation.
    #[test]
    fn epic482_7_dispatch_rejects_unknown_msg_type() {
        let dispatcher = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, 99); // unknown msg type
        hdr.body_len = CELL_SIZE as u32;
        let body = vec![0u8; CELL_SIZE];
        let result = dispatcher.dispatch_relay_chain(&hdr, &body, NodeId::from([0x11u8; 32]));
        match result {
            DispatchResult::Violation(msg) => {
                assert!(msg.contains("unknown msg_type"));
            }
            other => panic!("expected Violation, got {other:?}"),
        }
    }

    /// When `anonymity_x25519_sk = None` (relay not enabled), the
    /// handler drops silently with NoResponse. Critical: must NOT
    /// return Violation, which would leak "this node is not a
    /// relay" to a sender probing for relay-capable peers.
    #[test]
    fn epic482_7_dispatch_drops_silently_when_sk_missing() {
        let dispatcher = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        // for_test sets anonymity_x25519_sk = None.
        assert!(dispatcher.anonymity_x25519_sk.is_none());

        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
        hdr.body_len = CELL_SIZE as u32;
        let cell = pack(b"x").unwrap();
        let result = dispatcher.dispatch_relay_chain(&hdr, &cell, NodeId::from([0x11u8; 32]));
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "missing sk must yield silent NoResponse, NOT Violation \
             (would leak relay-capability status to a sender probe)"
        );
    }

    /// Cell peel failure (e.g. cell intended for a different relay)
    /// must drop silently — same argument as above: returning Violation
    /// would leak whether this node is the intended hop.
    #[test]
    fn epic482_7_dispatch_drops_silently_on_peel_aead_failure() {
        let mut dispatcher = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        // Wire an SK so the handler doesn't take the no-SK fast path.
        let local_sk = StaticSecret::random_from_rng(OsRng);
        dispatcher.anonymity_x25519_sk = Some(Arc::new(local_sk));

        // Build a cell intended for SOMEONE ELSE. Our local SK can't
        // decrypt it.
        let (_other_sk, other_hop) = fresh_hop(0xBB);
        let cell = build_anonymous_cell(b"data", &[other_hop]).unwrap();

        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
        hdr.body_len = CELL_SIZE as u32;
        let result = dispatcher.dispatch_relay_chain(&hdr, &cell, NodeId::from([0x11u8; 32]));
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "AEAD failure must yield silent NoResponse, NOT Violation \
             (would leak 'wrong recipient' to a sender probe)"
        );
    }

    /// When this node IS the final hop for a 1-hop circuit AND the
    /// payload decodes as an AppDeliverPayload addressed to a bound
    /// endpoint, the handler delivers through `AppEndpointRegistry` —
    /// closes (now with tag-byte routing).
    #[tokio::test]
    async fn epic482_7_dispatch_delivers_final_hop_payload_to_app() {
        use veil_anonymity::rendezvous::final_hop_kind;
        use veil_proto::AppDeliverPayload;
        let mut dispatcher = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let local_sk = StaticSecret::random_from_rng(OsRng);
        let local_pk = PublicKey::from(&local_sk).to_bytes();
        dispatcher.anonymity_x25519_sk = Some(Arc::new(local_sk));

        // Bind a local endpoint so route_ipc_deliver finds a target.
        let app_id = [0xAB; 32];
        let endpoint_id = 7u32;
        let (_handle, mut rx) = dispatcher.app_registry.register(app_id, endpoint_id, 16);

        // Sender wraps payload as AppDeliverPayload before onion-encrypting.
        let inner_data = b"hello-anon".to_vec();
        let deliver = AppDeliverPayload {
            src_node_id: [0u8; 32], // anonymity: never reveals sender's node_id
            src_app_id: [0xCD; 32],
            app_id,
            endpoint_id,
            data: veil_bufpool::pooled_shared_from_vec(inner_data.clone()),
        };
        // Final-hop payload now starts with a kind tag.
        let mut onion_payload = vec![final_hop_kind::APP_DELIVER];
        onion_payload.extend_from_slice(&deliver.encode());

        // Build a cell where local node IS the destination.
        let mut node_id = [0u8; 32];
        node_id[0] = 0xCC;
        let me_as_hop = Hop {
            node_id,
            pubkey: local_pk,
        };
        let cell = build_anonymous_cell(&onion_payload, &[me_as_hop]).unwrap();

        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
        hdr.body_len = CELL_SIZE as u32;
        let result = dispatcher.dispatch_relay_chain(&hdr, &cell, NodeId::from([0x11u8; 32]));
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "Final hop accept must yield NoResponse: got {result:?}"
        );

        // App should now have received the message on its registered channel.
        let msg = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .expect("recv timed out — message not delivered to app")
            .expect("channel closed");
        match msg {
            veil_app::registry::AppMessage::Deliver {
                src_node_id,
                src_app_id,
                data,
                ..
            } => {
                assert_eq!(
                    src_node_id, [0u8; 32],
                    "anonymity: src_node_id must be zeros"
                );
                assert_eq!(src_app_id, [0xCD; 32]);
                assert_eq!(data.as_ref(), inner_data.as_slice());
            }
            other => panic!("expected AppMessage::Deliver, got {other:?}"),
        }
    }

    /// Final-hop payload that IS tagged APP_DELIVER but carries
    /// malformed AppDeliverPayload bytes must silently drop — same
    /// anti-leak logic as on AEAD failure.
    #[test]
    fn epic482_7_dispatch_drops_silently_on_malformed_app_deliver() {
        use veil_anonymity::rendezvous::final_hop_kind;
        let mut dispatcher = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let local_sk = StaticSecret::random_from_rng(OsRng);
        let local_pk = PublicKey::from(&local_sk).to_bytes();
        dispatcher.anonymity_x25519_sk = Some(Arc::new(local_sk));

        // Tag = APP_DELIVER but body is too short for a real
        // AppDeliverPayload — should silent-drop on decode error.
        let mut onion_payload = vec![final_hop_kind::APP_DELIVER];
        onion_payload.extend_from_slice(b"garbage");
        let mut node_id = [0u8; 32];
        node_id[0] = 0xCC;
        let me_as_hop = Hop {
            node_id,
            pubkey: local_pk,
        };
        let cell = build_anonymous_cell(&onion_payload, &[me_as_hop]).unwrap();

        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
        hdr.body_len = CELL_SIZE as u32;
        let result = dispatcher.dispatch_relay_chain(&hdr, &cell, NodeId::from([0x11u8; 32]));
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "malformed AppDeliverPayload must silent-drop: got {result:?}"
        );
    }

    /// An `APP_DELIVER_AUTH` final-hop cell decodes the `AuthAppDeliver` and
    /// hands it to the runtime verify task over `auth_deliver_tx`. The crypto
    /// verification + replay check are async (need a DHT identity resolve) and
    /// live in the runtime task; here we assert the sync dispatcher's hand-off.
    #[tokio::test]
    async fn auth_deliver_final_hop_enqueues_to_verify_task() {
        use veil_anonymity::rendezvous::final_hop_kind;
        let mut dispatcher = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let local_sk = StaticSecret::random_from_rng(OsRng);
        let local_pk = PublicKey::from(&local_sk).to_bytes();
        dispatcher.anonymity_x25519_sk = Some(Arc::new(local_sk));

        // Wire a verify-task channel in place of the real runtime task.
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        *veil_util::lock!(dispatcher.auth_deliver_tx) = Some(tx);

        let auth = veil_proto::AuthAppDeliver {
            version: veil_proto::AuthAppDeliver::VERSION,
            sender_node_id: [0x5A; 32],
            sig_key_idx: 0,
            timestamp: 1_700_000_000,
            nonce: 42,
            dst_node_id: [0xCC; 32],
            app_id: [0xAB; 32],
            endpoint_id: 7,
            data: b"authed-hello".to_vec(),
            signature: vec![0u8; 64],
        };
        let mut onion_payload = vec![final_hop_kind::APP_DELIVER_AUTH];
        onion_payload.extend_from_slice(&auth.encode());

        let me_as_hop = Hop {
            node_id: [0xCC; 32],
            pubkey: local_pk,
        };
        let cell = build_anonymous_cell(&onion_payload, &[me_as_hop]).unwrap();
        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
        hdr.body_len = CELL_SIZE as u32;
        let result = dispatcher.dispatch_relay_chain(&hdr, &cell, NodeId::from([0x11u8; 32]));
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "auth final-hop accept must yield NoResponse: got {result:?}"
        );

        let got = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .expect("auth deliver was not enqueued to the verify task")
            .expect("verify-task channel closed");
        assert_eq!(got.sender_node_id, [0x5A; 32]);
        assert_eq!(got.nonce, 42);
        assert_eq!(got.endpoint_id, 7);
        assert_eq!(got.data, b"authed-hello");
    }

    /// With no verify task wired (`auth_deliver_tx = None`, the default on test
    /// dispatchers), an `APP_DELIVER_AUTH` cell is silently dropped — same
    /// anti-leak policy as an unbound endpoint, and crucially it must not panic
    /// on the unset channel.
    #[tokio::test]
    async fn auth_deliver_final_hop_drops_when_verify_task_unwired() {
        use veil_anonymity::rendezvous::final_hop_kind;
        let mut dispatcher = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let local_sk = StaticSecret::random_from_rng(OsRng);
        let local_pk = PublicKey::from(&local_sk).to_bytes();
        dispatcher.anonymity_x25519_sk = Some(Arc::new(local_sk));

        let auth = veil_proto::AuthAppDeliver {
            version: veil_proto::AuthAppDeliver::VERSION,
            sender_node_id: [0x5A; 32],
            sig_key_idx: 0,
            timestamp: 1_700_000_000,
            nonce: 1,
            dst_node_id: [0xCC; 32],
            app_id: [0xAB; 32],
            endpoint_id: 7,
            data: b"x".to_vec(),
            signature: vec![0u8; 64],
        };
        let mut onion_payload = vec![final_hop_kind::APP_DELIVER_AUTH];
        onion_payload.extend_from_slice(&auth.encode());
        let me_as_hop = Hop {
            node_id: [0xCC; 32],
            pubkey: local_pk,
        };
        let cell = build_anonymous_cell(&onion_payload, &[me_as_hop]).unwrap();
        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
        hdr.body_len = CELL_SIZE as u32;
        let result = dispatcher.dispatch_relay_chain(&hdr, &cell, NodeId::from([0x11u8; 32]));
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "unwired auth final-hop must silent-drop: got {result:?}"
        );
    }

    // ── Slices 2-4: rendezvous-relay dispatcher coverage ─────────────────────

    /// Register frame with valid payload + active registry inserts an
    /// entry; subsequent lookup returns the subscriber.
    #[test]
    fn epic482_5_dispatch_register_inserts_into_registry() {
        use veil_anonymity::rendezvous::{RegisterRendezvousPayload, RendezvousRegistry};
        let mut dispatcher = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let registry = Arc::new(RendezvousRegistry::default());
        dispatcher.rendezvous_registry = Some(Arc::clone(&registry));

        let req = RegisterRendezvousPayload {
            receiver_x25519_pk: [0xAB; 32],
            auth_cookie: [0xCD; 16],
        };
        let body = req.encode();
        let mut hdr = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::RegisterRendezvous as u16,
        );
        hdr.body_len = body.len() as u32;

        let node_id_bytes: NodeIdBytes = [0xEE; 32];
        let node_id: NodeId = node_id_bytes.into();
        let result = dispatcher.dispatch_relay_chain(&hdr, &body, node_id);
        assert!(matches!(result, DispatchResult::NoResponse));
        // Registry is namespaced by the authenticated session
        // peer_node_id — look up under it.
        let sub = registry
            .lookup(&node_id_bytes, &req.auth_cookie)
            .expect("registered");
        assert_eq!(sub.peer_node_id, node_id_bytes);
        assert_eq!(sub.receiver_x25519_pk, req.receiver_x25519_pk);
    }

    /// Register to node without registry (not configured as rendezvous)
    /// silently drops — anti-leak.
    #[test]
    fn epic482_5_dispatch_register_no_registry_silent_drop() {
        use veil_anonymity::rendezvous::RegisterRendezvousPayload;
        let dispatcher = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        assert!(dispatcher.rendezvous_registry.is_none());

        let req = RegisterRendezvousPayload {
            receiver_x25519_pk: [0xAB; 32],
            auth_cookie: [0xCD; 16],
        };
        let body = req.encode();
        let mut hdr = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::RegisterRendezvous as u16,
        );
        hdr.body_len = body.len() as u32;
        let result = dispatcher.dispatch_relay_chain(&hdr, &body, NodeId::from([0xEE; 32]));
        assert!(matches!(result, DispatchResult::NoResponse));
    }

    /// Forward frame with no anonymity SK silent-drops (anti-leak).
    #[test]
    fn epic482_5_dispatch_forward_no_sk_silent_drop() {
        use veil_anonymity::rendezvous::ForwardIntroducePayload;
        let dispatcher = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        assert!(dispatcher.anonymity_x25519_sk.is_none());

        let p = ForwardIntroducePayload {
            ciphertext: vec![0u8; 60],
        };
        let body = p.encode().unwrap();
        let mut hdr = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::ForwardIntroduce as u16,
        );
        hdr.body_len = body.len() as u32;
        let result = dispatcher.dispatch_relay_chain(&hdr, &body, NodeId::from([0xEE; 32]));
        assert!(matches!(result, DispatchResult::NoResponse));
    }

    /// End-to-end through-the-rendezvous: sender encrypts a payload
    /// to receiver_x25519_pk wrapped as IntroducePayload, dispatcher
    /// (rendezvous role) receives it, decodes IntroducePayload, looks
    /// up cookie → forwarder, and attempts to forward. Forward will
    /// silent-drop here because no live session to the subscriber, but
    /// the lookup path itself runs.
    #[test]
    fn epic482_5_dispatch_introduce_routes_via_cookie() {
        use veil_anonymity::rendezvous::{
            IntroducePayload, RendezvousRegistry, RendezvousSubscriber, encrypt_introduce,
            final_hop_kind,
        };
        let mut dispatcher = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let local_sk = StaticSecret::random_from_rng(OsRng);
        let local_pk = PublicKey::from(&local_sk).to_bytes();
        dispatcher.anonymity_x25519_sk = Some(Arc::new(local_sk));

        // Register a subscriber under a known cookie. The subscriber
        // session is fictional here (no real OVL1 session in test
        // dispatcher), so the eventual forward is a silent drop, but
        // the cookie lookup must succeed.
        let registry = Arc::new(RendezvousRegistry::default());
        let auth_cookie = [0xCC; 16];
        let receiver_node_id = [0x11; 32];
        let receiver_x25519_pk = [0x22; 32]; // dummy (sender encrypts to THIS)
        registry
            .register(
                auth_cookie,
                RendezvousSubscriber {
                    peer_node_id: receiver_node_id,
                    receiver_x25519_pk,
                    registered_at_unix: 1_700_000_000,
                },
            )
            .unwrap();
        dispatcher.rendezvous_registry = Some(Arc::clone(&registry));

        // Sender encrypts the inner payload to receiver_x25519_pk and
        // wraps in IntroducePayload + final-hop tag.
        let inner = b"e2e-payload";
        let ciphertext = encrypt_introduce(inner, &receiver_x25519_pk).unwrap();
        let intro = IntroducePayload {
            receiver_node_id,
            auth_cookie,
            ciphertext,
        };
        let mut payload_with_tag = vec![final_hop_kind::INTRODUCE];
        payload_with_tag.extend_from_slice(&intro.encode().unwrap());

        // Build a 1-hop circuit where local node IS the rendezvous.
        let mut node_id = [0u8; 32];
        node_id[0] = 0xCC;
        let me_as_hop = Hop {
            node_id,
            pubkey: local_pk,
        };
        let cell = build_anonymous_cell(&payload_with_tag, &[me_as_hop]).unwrap();

        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
        hdr.body_len = CELL_SIZE as u32;
        let result = dispatcher.dispatch_relay_chain(&hdr, &cell, NodeId::from([0xEE; 32]));
        assert!(matches!(result, DispatchResult::NoResponse));
        // Registry still has the entry (forwarding doesn't unregister).
        assert_eq!(registry.len(), 1);
    }

    /// Final-hop with valid AppDeliverPayload but no bound app endpoint
    /// silently drops too — matches direct-delivery unbound semantics.
    #[test]
    fn epic482_7_dispatch_drops_silently_on_unbound_endpoint() {
        use veil_anonymity::rendezvous::final_hop_kind;
        use veil_proto::AppDeliverPayload;
        let mut dispatcher = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let local_sk = StaticSecret::random_from_rng(OsRng);
        let local_pk = PublicKey::from(&local_sk).to_bytes();
        dispatcher.anonymity_x25519_sk = Some(Arc::new(local_sk));

        // No endpoint bound — route_ipc_deliver will return false.
        let deliver = AppDeliverPayload {
            src_node_id: [0u8; 32],
            src_app_id: [0xCD; 32],
            app_id: [0xAB; 32],
            endpoint_id: 7,
            data: veil_bufpool::pooled_shared_from_vec(b"never-arrives".to_vec()),
        };
        let mut onion_payload = vec![final_hop_kind::APP_DELIVER];
        onion_payload.extend_from_slice(&deliver.encode());
        let mut node_id = [0u8; 32];
        node_id[0] = 0xCC;
        let me_as_hop = Hop {
            node_id,
            pubkey: local_pk,
        };
        let cell = build_anonymous_cell(&onion_payload, &[me_as_hop]).unwrap();

        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
        hdr.body_len = CELL_SIZE as u32;
        let result = dispatcher.dispatch_relay_chain(&hdr, &cell, NodeId::from([0x11u8; 32]));
        assert!(
            matches!(result, DispatchResult::NoResponse),
            "unbound endpoint must silent-drop: got {result:?}"
        );
    }
}
