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
//!    destination. The payload's 1-byte kind tag routes it:
//!    `APP_DELIVER` is delivered to the local per-app inbox, and
//!    `INTRODUCE` is forwarded through the rendezvous-relay flow.
//!    (Earlier revisions only logged + metered the receipt; delivery
//!    is now wired — see the `CellPeelResult::Final` arm below.)
//!
//! # Why "drop on next-hop-down" is the right choice
//!
//! Tor handles relay-down by tearing down the circuit and surfacing
//! to the sender so it can rebuild. This cell-relay path has no
//! per-circuit teardown signal of its own (the separate
//! CircuitBuild/CircuitData state machine does; this older onion-cell
//! path does not), so the alternative is "send an error back through
//! the inbound path". But that error message would leak the position of the
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
use std::sync::{Mutex as StdMutex, OnceLock};

use super::{AuthDeliverInbound, DispatchResult, FrameDispatcher};
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

/// Unix seconds for circuit install/touch/GC timestamps (best-effort clock).
fn circuit_now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Default)]
struct CircuitDataDiag {
    rx: u64,
    fwd_relay_ok: u64,
    fwd_relay_fail: u64,
    fwd_terminus: u64,
    splice_hit: u64,
    splice_miss: u64,
    splice_ok: u64,
    splice_fail: u64,
    ret_relay_ok: u64,
    ret_relay_fail: u64,
    send_missing: u64,
    send_full: u64,
    send_closed: u64,
    origin_open_ok: u64,
    origin_open_err: u64,
    origin_stream_ok: u64,
    origin_stream_full: u64,
    origin_stream_missing: u64,
    unknown: u64,
    last_logged_rx: u64,
    last_log: Option<std::time::Instant>,
}

static CIRCUIT_DATA_DIAG: OnceLock<StdMutex<CircuitDataDiag>> = OnceLock::new();

fn circuit_data_diag(update: impl FnOnce(&mut CircuitDataDiag)) {
    let mut diag = CIRCUIT_DATA_DIAG
        .get_or_init(|| StdMutex::new(CircuitDataDiag::default()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    update(&mut diag);
    if diag.rx == diag.last_logged_rx {
        return;
    }
    let now = std::time::Instant::now();
    if diag
        .last_log
        .is_some_and(|last| now.duration_since(last) < std::time::Duration::from_secs(2))
    {
        return;
    }
    diag.last_log = Some(now);
    diag.last_logged_rx = diag.rx;
    log::info!(
        "onion-stream.circuit-data rx={} fwd_relay={}/{} fwd_terminus={} \
         splice_hit={} splice_miss={} splice_send={}/{} ret_relay={}/{} \
         send_err=missing:{} full:{} closed:{} \
         origin_open={}/{} origin_stream=ok:{} full:{} missing:{} unknown={}",
        diag.rx,
        diag.fwd_relay_ok,
        diag.fwd_relay_fail,
        diag.fwd_terminus,
        diag.splice_hit,
        diag.splice_miss,
        diag.splice_ok,
        diag.splice_fail,
        diag.ret_relay_ok,
        diag.ret_relay_fail,
        diag.send_missing,
        diag.send_full,
        diag.send_closed,
        diag.origin_open_ok,
        diag.origin_open_err,
        diag.origin_stream_ok,
        diag.origin_stream_full,
        diag.origin_stream_missing,
        diag.unknown,
    );
}

/// Outcome of attempting to forward an introduce down a return circuit.
/// Lets the caller tell a genuinely-unknown cookie apart from a known cookie
/// whose cell was simply not (re)sent.
enum CircuitIntroduceForward {
    /// A fresh introduce cell was framed and sent down the circuit.
    Forwarded,
    /// The cookie maps to a known circuit subscription, but no cell was sent —
    /// a replay we already forwarded, or a transient drop (cell oversize /
    /// return-seq exhausted / encode failure). The cookie WAS known.
    KnownButDropped,
    /// No circuit-backed subscription exists for this cookie.
    NotCircuit,
}

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
            RelayChainMsg::RegisterMailboxCookie => {
                return self.handle_register_mailbox_cookie(body, node_id);
            }
            RelayChainMsg::ForwardIntroduce => return self.handle_forward_introduce(body, node_id),
            // Stateful return circuits (onion-registration epic). Control frames
            // over an established session (NOT fixed CELL_SIZE), so return before
            // the Hop cell-size check below.
            RelayChainMsg::CircuitBuild => return self.handle_circuit_build(body, node_id),
            RelayChainMsg::CircuitData => return self.handle_circuit_data(body, node_id),
            RelayChainMsg::CircuitTeardown => return self.handle_circuit_teardown(body, node_id),
            RelayChainMsg::CircuitBuilt => return self.handle_circuit_built(body, node_id),
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
                // Forward to next_hop's session, if we have one — but ONLY if
                // this node opted in to carrying others' circuits. A
                // `receive_anonymous`-only node owns the SK (to unseal its own
                // forwarded introduces + accept Final cells) yet must never
                // relay for strangers; it silently drops Forward cells (same
                // anti-leak policy — surfacing "I won't relay" would reveal the
                // node's capability to a probe).
                if self.anonymity_relay_capable {
                    self.forward_anonymous_cell(&next_hop, &outbound_cell);
                }
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
        match veil_proto::AuthAppDeliver::decode(body) {
            Ok(auth) => self.enqueue_auth_deliver(AuthDeliverInbound::Full(Box::new(auth))),
            Err(e) => self.logger.info(
                "anonymity.relay_chain.auth.decode_failed",
                format!("AuthAppDeliver decode failed ({} B): {e}", body.len()),
            ),
        }
        DispatchResult::NoResponse
    }

    /// Hand one inbound authenticated delivery (whole message or fragment) to
    /// the runtime-owned async verify+deliver task via `auth_deliver_tx`. The
    /// dispatcher is SYNC and has no identity resolver, while verification needs
    /// an async DHT resolve — so resolve + verify + replay + (reassembly +)
    /// delivery all happen off-thread. `auth_deliver_tx` is `None` on
    /// dispatchers the runtime never wired (test harnesses) → silent drop, same
    /// policy as an unbound endpoint. A full channel also drops (best-effort;
    /// the sender learns from an app-layer timeout, never a synchronous error —
    /// which would leak reachability).
    fn enqueue_auth_deliver(&self, inbound: AuthDeliverInbound) {
        let Some(tx) = lock!(self.auth_deliver_tx).as_ref().cloned() else {
            self.logger.info(
                "anonymity.relay_chain.auth.unwired",
                "authenticated delivery received but no verify task wired; dropped",
            );
            return;
        };
        if let Err(e) = tx.try_send(inbound) {
            self.logger.info(
                "anonymity.relay_chain.auth.enqueue_dropped",
                format!("auth-deliver verify queue unavailable; dropped: {e}"),
            );
        }
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
                // No session-backed subscriber. Try a circuit-backed
                // (onion-registered) subscription, keyed by cookie ALONE — for a
                // LOCATION-anonymous service R forwards the introduce DOWN the
                // receiver's return circuit instead of over a direct session.
                match self.try_forward_introduce_via_circuit(&intro) {
                    #[allow(unused_variables)]
                    disposition @ (CircuitIntroduceForward::Forwarded
                    | CircuitIntroduceForward::KnownButDropped) => {
                        // Cookie was a known circuit subscription — either
                        // forwarded, or deliberately dropped (replay / cell
                        // budget / seq-exhausted). NOT an unknown cookie, so
                        // don't emit the cookie_unknown signal.
                        // INSTRUMENT (`relay-trace` feature, OFF in prod): both
                        // outcomes are otherwise silent, so a trace diff can't
                        // tell "delivered down the circuit" from "known cookie
                        // but cell dropped". Log the disposition + cookie.
                        #[cfg(feature = "relay-trace")]
                        {
                            let cf_cookie: String = intro
                                .auth_cookie
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect();
                            let (sig, msg) = match disposition {
                                CircuitIntroduceForward::Forwarded => (
                                    "anonymity.relay_chain.introduce.circuit_forwarded",
                                    "forwarded down the return circuit",
                                ),
                                _ => (
                                    "anonymity.relay_chain.introduce.known_but_dropped",
                                    "known circuit cookie; cell dropped (replay/budget/seq)",
                                ),
                            };
                            self.logger.info(
                                sig,
                                format!(
                                    "{msg}: receiver={} cookie={}",
                                    veil_util::hex_short(&intro.receiver_node_id),
                                    cf_cookie,
                                ),
                            );
                        }
                        return DispatchResult::NoResponse;
                    }
                    CircuitIntroduceForward::NotCircuit => {
                        // No entry for this (receiver, cookie) in either the
                        // session OR the circuit registry. Silent drop:
                        // surfacing this would leak "this rendezvous serves
                        // cookie X / Y" to sender probes — exactly what the
                        // auth_cookie cipher-shape is designed to hide.
                        // INSTRUMENT (`relay-trace` feature, OFF in prod): log the
                        // introduce's (receiver, cookie) so it can be diffed
                        // against the register.ok keys. The default build keeps the
                        // opaque message (surfacing the cookie would leak "this
                        // rendezvous serves cookie X" to sender probes).
                        #[cfg(feature = "relay-trace")]
                        {
                            let cu_cookie: String = intro
                                .auth_cookie
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect();
                            self.logger.info(
                                "anonymity.relay_chain.introduce.cookie_unknown",
                                format!(
                                    "no subscriber for receiver={} cookie={}; dropped",
                                    veil_util::hex_short(&intro.receiver_node_id),
                                    cu_cookie,
                                ),
                            );
                        }
                        #[cfg(not(feature = "relay-trace"))]
                        self.logger.info(
                            "anonymity.relay_chain.introduce.cookie_unknown",
                            "no subscriber registered for this (receiver, auth_cookie); dropped",
                        );
                        return DispatchResult::NoResponse;
                    }
                }
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
        // INSTRUMENT (`relay-trace` feature, OFF in prod): the session-forward
        // path is otherwise SILENT, so a live plain/session introduce delivery
        // left no log (only the circuit path logged introduce.forwarded) — making
        // "forwarded=0" misleading.
        #[cfg(feature = "relay-trace")]
        {
            let sf_cookie: String = intro
                .auth_cookie
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            self.logger.info(
                "anonymity.relay_chain.introduce.session_forwarded",
                format!(
                    "forwarded to receiver={} cookie={}",
                    veil_util::hex_short(&subscriber.peer_node_id),
                    sf_cookie,
                ),
            );
        }
        self.send_relay_chain_msg(&target, RelayChainMsg::ForwardIntroduce, &body_bytes);
        DispatchResult::NoResponse
    }

    /// Receiver → relay: register a PRIVATE mailbox fetch cookie, keyed by the
    /// authenticated session source (`node_id`) — so a node can only register
    /// its own. Stored in the mailbox-specific registry (NOT the rendezvous one),
    /// which the mailbox bridge consults to authorize fetch/ack. Fire-and-forget
    /// (no reply); the receiver re-registers each epoch.
    fn handle_register_mailbox_cookie(&self, body: &[u8], node_id: NodeId) -> DispatchResult {
        use veil_anonymity::mailbox_cookie_registry::RegisterMailboxCookiePayload;
        let req = match RegisterMailboxCookiePayload::decode(body) {
            Ok(p) => p,
            Err(e) => {
                return DispatchResult::Violation(format!("RegisterMailboxCookie decode: {e}"));
            }
        };
        let Some(reg) = &self.mailbox_cookie_registry else {
            // Node is not a mailbox relay — anti-leak silent drop (a Violation
            // would identify "this node won't serve as a mailbox" to a prober).
            return DispatchResult::NoResponse;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if let Ok(mut w) = reg.write() {
            w.register(*node_id.as_bytes(), req.cookie, now);
            self.logger.info(
                "mailbox.cookie.register.ok",
                format!(
                    "registered mailbox fetch-cookie from peer={}",
                    veil_util::hex_short(node_id.as_bytes())
                ),
            );
        }
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
                // INSTRUMENT (`relay-trace` feature, OFF in prod): include the
                // cookie so a register.ok can be diffed against an introduce's
                // cookie_unknown. Default build omits it (a registered cookie is a
                // subscriber-linkable value).
                #[cfg(feature = "relay-trace")]
                {
                    let reg_cookie: String =
                        req.auth_cookie.iter().map(|b| format!("{b:02x}")).collect();
                    self.logger.info(
                        "anonymity.relay_chain.register.ok",
                        format!(
                            "registered cookie={} from peer={}; total registrations={}",
                            reg_cookie,
                            veil_util::hex_short(node_id.as_bytes()),
                            reg.len(),
                        ),
                    );
                }
                #[cfg(not(feature = "relay-trace"))]
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
        // Session-forwarded: arrived via our RENDEZVOUS registration, not one
        // of our reply circuits.
        self.process_introduce_ciphertext(&p.ciphertext, node_id.as_bytes(), false)
    }

    /// Decrypt a sealed introduce ciphertext (replay-protected) with our
    /// anonymity key and dispatch the inner final-hop payload (APP_DELIVER /
    /// APP_DELIVER_AUTH). Shared by the SESSION forward path
    /// ([`Self::handle_forward_introduce`]) and the CIRCUIT origin-receive path
    /// (a return cell the originator opened — b5b). `via_reply_circuit` is true
    /// only on the latter when the opened circuit is one of OUR ephemeral reply
    /// circuits (see [`AuthDeliverInbound::Fragment`]).
    fn process_introduce_ciphertext(
        &self,
        ciphertext: &[u8],
        peer: &[u8; 32],
        via_reply_circuit: bool,
    ) -> DispatchResult {
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
            ciphertext,
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
                        veil_util::hex_short(peer),
                    ),
                );
                return DispatchResult::NoResponse;
            }
        };
        // The decrypted plaintext is tagged with a `final_hop_kind` so the
        // receiver can tell a plain delivery from an authenticated one. Plain
        // rendezvous sends `APP_DELIVER`; the authenticated path sends
        // `APP_DELIVER_AUTH` fragments (reassembled + verified by the runtime
        // task — the recipient learns the VERIFIED sender).
        let Some((&kind, inner)) = plaintext.split_first() else {
            self.logger.info(
                "anonymity.relay_chain.forward.empty",
                "decrypted rendezvous plaintext is empty; dropped",
            );
            return DispatchResult::NoResponse;
        };
        match kind {
            final_hop_kind::APP_DELIVER => {
                let app_deliver = match AppDeliverPayload::decode(inner) {
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
                        format!(
                            "delivered {data_len} B via rendezvous to endpoint_id={endpoint_id}"
                        ),
                    );
                } else {
                    self.logger.info(
                        "anonymity.relay_chain.forward.unbound",
                        format!("no app bound to endpoint_id={endpoint_id}; {data_len} B dropped"),
                    );
                }
            }
            final_hop_kind::APP_DELIVER_AUTH => {
                // A fragment of a signed AuthAppDeliver — hand to the runtime
                // task to reassemble + verify + deliver with the VERIFIED sender.
                match veil_proto::AuthDeliverFragment::decode(inner) {
                    Ok(frag) => self.enqueue_auth_deliver(AuthDeliverInbound::Fragment {
                        frag,
                        via_reply_circuit,
                    }),
                    Err(e) => self.logger.info(
                        "anonymity.relay_chain.forward.auth_decode_failed",
                        format!("AuthDeliverFragment decode: {e}"),
                    ),
                }
            }
            other => self.logger.info(
                "anonymity.relay_chain.forward.unknown_kind",
                format!("rendezvous plaintext kind=0x{other:02x} not recognised; dropped"),
            ),
        }
        DispatchResult::NoResponse
    }

    // ── Stateful return circuits (onion-registration epic) ─────────────
    //
    // NOTE: circuit data cells are currently variable-size (each hop's AEAD tag
    // grows/shrinks the layered ciphertext), which leaks hop position to a
    // passive observer. Fixed-size cell padding (482.7 §4 — the cell layer
    // provides the fixed envelope) is a follow-up; tracked as a b6 refinement.

    /// `RelayChainMsg::CircuitBuild`: peel one setup layer, install the per-hop
    /// state, then forward the inner setup to the next hop (or, at the terminus,
    /// surface the piggy-backed payload). `node_id` is the authenticated sender
    /// = this hop's `prev_link`.
    fn handle_circuit_build(&self, body: &[u8], node_id: NodeId) -> DispatchResult {
        let (Some(sk), Some(table)) = (&self.anonymity_x25519_sk, &self.circuit_table) else {
            // Not circuit-capable — anti-leak silent drop (a Violation would
            // confirm relay-capability to a prober).
            return DispatchResult::NoResponse;
        };
        let peeled = match veil_anonymity::circuit_setup::peel_circuit_setup(body, sk) {
            Ok(p) => p,
            Err(_) => return DispatchResult::NoResponse, // bad/foreign setup — drop
        };
        let now = circuit_now_unix();
        let prev_link = *node_id.as_bytes();
        match peeled {
            veil_anonymity::circuit_setup::SetupPeelResult::Forward {
                install,
                next_hop,
                inner,
            } => {
                if table
                    .install(&install, prev_link, Some(next_hop), now)
                    .is_err()
                {
                    return DispatchResult::NoResponse; // cap/duplicate — drop
                }
                self.send_relay_chain_msg(
                    &NodeId::from(next_hop),
                    RelayChainMsg::CircuitBuild,
                    &inner,
                );
            }
            veil_anonymity::circuit_setup::SetupPeelResult::Terminus { install, payload } => {
                let circuit = match table.install(&install, prev_link, None, now) {
                    Ok(c) => c,
                    Err(_) => return DispatchResult::NoResponse,
                };
                let circuit_id_in = circuit.circuit_id_in;

                // diff-audit B1: the `CircuitBuilt` ACK must mean "this circuit is
                // USABLE for its role", not merely "transport reached the
                // terminus". The originator marks the circuit CONFIRMED on this
                // ACK and FREEZES that path; if the piggy-backed cookie
                // registration was rejected (squat / stale-epoch / malformed /
                // registry full), the onion service is dark even though the path
                // is up. So for a circuit that carries a rendezvous registration,
                // emit the ACK ONLY AFTER the cookie→circuit binding succeeds — a
                // failed registration leaves the originator UNconfirmed, so its
                // maintenance tick re-selects a fresh path instead of freezing a
                // service that can't be reached. A circuit with no registration
                // payload (or arriving where no registry is configured) is a pure
                // transport circuit and is ACK'd immediately, as before.
                //
                // R never learns the receiver's node_id (cookie-keyed,
                // first-wins). A failed registration leaves the bare circuit
                // installed (idle-GC'd) — anti-leak silent.
                let usable = match (
                    self.circuit_rendezvous.as_ref(),
                    veil_anonymity::circuit_register::CircuitRegisterPayload::decode(&payload),
                ) {
                    (Some(reg), Some(p)) => match reg.register(&p, circuit, now) {
                        Ok(()) => {
                            // INSTRUMENT (`relay-trace` feature, OFF in prod): the
                            // circuit path is the anonymous receiver's registration,
                            // so a cookie_unknown diff needs its cookie too. Default
                            // build keeps the cookie out of the log (linkable value).
                            #[cfg(feature = "relay-trace")]
                            {
                                let cr_cookie: String =
                                    p.cookie.iter().map(|b| format!("{b:02x}")).collect();
                                self.logger.info(
                                    "anonymity.circuit.registered",
                                    format!(
                                        "circuit-rendezvous registration bound cookie={cr_cookie} epoch={} to a return circuit",
                                        p.epoch,
                                    ),
                                );
                            }
                            #[cfg(not(feature = "relay-trace"))]
                            self.logger.info(
                                "anonymity.circuit.registered",
                                "circuit-rendezvous registration bound a cookie to a return circuit",
                            );
                            true
                        }
                        Err(e) => {
                            #[cfg(feature = "relay-trace")]
                            {
                                let cr_cookie: String =
                                    p.cookie.iter().map(|b| format!("{b:02x}")).collect();
                                self.logger.info(
                                    "anonymity.circuit.register_rejected",
                                    format!(
                                        "circuit registration rejected: {e:?} cookie={cr_cookie} epoch={} — not ACKing",
                                        p.epoch,
                                    ),
                                );
                            }
                            #[cfg(not(feature = "relay-trace"))]
                            self.logger.info(
                                "anonymity.circuit.register_rejected",
                                format!("circuit registration rejected: {e:?} — not ACKing"),
                            );
                            false
                        }
                    },
                    // No registry here, or the payload is not a registration:
                    // pure transport circuit — confirm transport reachability.
                    _ => true,
                };

                if usable {
                    let ack = veil_anonymity::circuit_wire::CircuitBuiltPayload {
                        circuit_id: circuit_id_in,
                    };
                    self.send_relay_chain_msg(
                        &NodeId::from(prev_link),
                        RelayChainMsg::CircuitBuilt,
                        &ack.encode(),
                    );
                }
            }
        }
        DispatchResult::NoResponse
    }

    /// `RelayChainMsg::CircuitData`: re-tag + relay a data cell. A cell matching
    /// the FORWARD index (arrived from `prev_link`) is unwrapped one layer and
    /// passed toward the terminus; a cell matching the BACKWARD index (arrived
    /// from `next_link`) gets ANOTHER layer and is passed toward the originator.
    fn handle_circuit_data(&self, body: &[u8], node_id: NodeId) -> DispatchResult {
        use veil_anonymity::circuit_data::{Direction, apply_layer, read_payload};
        use veil_anonymity::circuit_register::COOKIE_LEN;
        use veil_anonymity::circuit_wire::CircuitDataPayload;
        let cell = match CircuitDataPayload::decode(body) {
            Ok(c) => c,
            Err(_) => return DispatchResult::NoResponse,
        };
        circuit_data_diag(|d| d.rx = d.rx.saturating_add(1));
        let link = *node_id.as_bytes();
        let now = circuit_now_unix();

        // Relay paths — only if this node carries others' circuits (a receive-
        // only service has no relay table but still ORIGINATES below). Layers are
        // length-preserving XOR (2a) — cells are FIXED-SIZE on every link; the
        // relay can't authenticate (no per-layer tag), so the replay window is
        // seq-only and end-to-end integrity is the inner introduce's own AEAD.
        if let Some(table) = &self.circuit_table {
            // FORWARD cell: arrived from prev_link tagged circuit_id_in.
            if let Some(state) = table.lookup_forward(&link, cell.circuit_id) {
                if !state
                    .replay_fwd
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .accept(cell.seq)
                {
                    return DispatchResult::NoResponse; // replay / too-old
                }
                state.touch(now);
                let mut buf = cell.ciphertext.clone();
                apply_layer(&state.circuit_key, Direction::Forward, cell.seq, &mut buf);
                match state.next_link {
                    Some(nl) => {
                        let out = CircuitDataPayload {
                            circuit_id: state.circuit_id_out,
                            seq: cell.seq,
                            ciphertext: buf,
                        };
                        if let Ok(b) = out.encode() {
                            let sent = self.send_relay_chain_msg(
                                &NodeId::from(nl),
                                RelayChainMsg::CircuitData,
                                &b,
                            );
                            circuit_data_diag(|d| {
                                if sent {
                                    d.fwd_relay_ok = d.fwd_relay_ok.saturating_add(1);
                                } else {
                                    d.fwd_relay_fail = d.fwd_relay_fail.saturating_add(1);
                                }
                            });
                        }
                    }
                    None => {
                        // Terminus. onion-stream R-SPLICE: a framed payload of
                        // `[target_cookie 16][stream bytes]` whose cookie is a
                        // circuit-registered rendezvous cookie is forwarded down
                        // THAT receiver's circuit as a RETURN cell — the bulk
                        // bidirectional splice (like try_forward_introduce_via_circuit
                        // but no signature/dedup; the byte-stream layer above gives
                        // reliability + ordering). Anything else is a plain terminus
                        // delivery (logged). Forward-terminus CircuitData carries no
                        // other traffic today, so this overload is safe.
                        circuit_data_diag(|d| d.fwd_terminus = d.fwd_terminus.saturating_add(1));
                        let payload = read_payload(&buf);
                        let mut spliced = false;
                        if let Some(p) = &payload
                            && p.len() >= COOKIE_LEN
                            && let Some(reg) = &self.circuit_rendezvous
                        {
                            let mut cookie = [0u8; COOKIE_LEN];
                            cookie.copy_from_slice(&p[..COOKIE_LEN]);
                            if let Some(circuit) = reg.lookup(&cookie) {
                                circuit_data_diag(|d| {
                                    d.splice_hit = d.splice_hit.saturating_add(1)
                                });
                                spliced = self.splice_stream_cell(&circuit, &p[COOKIE_LEN..]);
                            } else {
                                circuit_data_diag(|d| {
                                    d.splice_miss = d.splice_miss.saturating_add(1);
                                });
                            }
                        }
                        if !spliced && let Some(p) = &payload {
                            self.logger.info(
                                "anonymity.circuit.terminus_data",
                                format!("circuit terminus rx {} B", p.len()),
                            );
                        }
                    }
                }
                return DispatchResult::NoResponse;
            }

            // RETURN cell: arrived from next_link tagged circuit_id_out. This relay
            // applies its layer and passes toward the originator (prev_link).
            if let Some(state) = table.lookup_backward(&link, cell.circuit_id) {
                if !state
                    .replay_ret
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .accept(cell.seq)
                {
                    return DispatchResult::NoResponse;
                }
                state.touch(now);
                let mut buf = cell.ciphertext.clone();
                apply_layer(&state.circuit_key, Direction::Return, cell.seq, &mut buf);
                let out = CircuitDataPayload {
                    circuit_id: state.circuit_id_in,
                    seq: cell.seq,
                    ciphertext: buf,
                };
                if let Ok(b) = out.encode() {
                    let sent = self.send_relay_chain_msg(
                        &NodeId::from(state.prev_link),
                        RelayChainMsg::CircuitData,
                        &b,
                    );
                    circuit_data_diag(|d| {
                        if sent {
                            d.ret_relay_ok = d.ret_relay_ok.saturating_add(1);
                        } else {
                            d.ret_relay_fail = d.ret_relay_fail.saturating_add(1);
                        }
                    });
                }
                return DispatchResult::NoResponse;
            }
        } // end relay-table paths

        // ORIGIN cell: this node BUILT the circuit (it is the receiver). The
        // return cell arrives from the first hop tagged our origin circuit_id;
        // open ALL accreted layers to recover the introduce R forwarded down the
        // circuit, then decrypt + deliver it (the same path as a session-
        // forwarded introduce). R never learned our location.
        if let Some(origin) = self
            .circuit_origin
            .as_ref()
            .and_then(|t| t.lookup(&link, cell.circuit_id))
        {
            return match origin.open_return(cell.seq, &cell.ciphertext) {
                Ok(opened) => {
                    circuit_data_diag(|d| d.origin_open_ok = d.origin_open_ok.saturating_add(1));
                    // onion-stream Phase 1c: a return cell on a REGISTERED stream
                    // circuit is delivered to its channel; any other id is a sealed
                    // introduce R forwarded down the circuit (path unchanged — no
                    // circuit is registered in `stream_recv` for introduce traffic).
                    if let Ok(map) = self.stream_recv.lock()
                        && let Some(tx) = map.get(&cell.circuit_id)
                    {
                        match tx.try_send(opened) {
                            Ok(()) => circuit_data_diag(|d| {
                                d.origin_stream_ok = d.origin_stream_ok.saturating_add(1);
                            }),
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                circuit_data_diag(|d| {
                                    d.origin_stream_full = d.origin_stream_full.saturating_add(1);
                                });
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                circuit_data_diag(|d| {
                                    d.origin_stream_missing =
                                        d.origin_stream_missing.saturating_add(1);
                                });
                            }
                        }
                        return DispatchResult::NoResponse;
                    }
                    circuit_data_diag(|d| {
                        d.origin_stream_missing = d.origin_stream_missing.saturating_add(1);
                    });
                    // A return cell on OUR circuit: if this circuit is one of
                    // our ephemeral REPLY circuits, the payload is the peer
                    // answering something we sent live (me→R proof).
                    self.process_introduce_ciphertext(&opened, &link, origin.is_reply)
                }
                Err(_) => {
                    circuit_data_diag(|d| {
                        d.origin_open_err = d.origin_open_err.saturating_add(1);
                    });
                    DispatchResult::NoResponse // a layer failed AEAD — drop
                }
            };
        }

        // Unknown circuit — anti-leak silent drop.
        circuit_data_diag(|d| d.unknown = d.unknown.saturating_add(1));
        DispatchResult::NoResponse
    }

    /// `RelayChainMsg::CircuitBuilt` (diff-audit Δ2-d): the terminus's
    /// establishment ACK, travelling RETURN-ward toward the originator. An
    /// intermediate hop re-tags + forwards it (mirroring the return data path);
    /// the originator marks its origin circuit CONFIRMED.
    fn handle_circuit_built(&self, body: &[u8], node_id: NodeId) -> DispatchResult {
        use veil_anonymity::circuit_wire::CircuitBuiltPayload;
        let p = match CircuitBuiltPayload::decode(body) {
            Ok(p) => p,
            Err(_) => return DispatchResult::NoResponse,
        };
        let link = *node_id.as_bytes();

        // Intermediate hop: the ACK arrived from next_link tagged circuit_id_out
        // → forward toward the originator (prev_link), re-tagged circuit_id_in.
        if let Some(table) = &self.circuit_table
            && let Some(state) = table.lookup_backward(&link, p.circuit_id)
        {
            let out = CircuitBuiltPayload {
                circuit_id: state.circuit_id_in,
            };
            self.send_relay_chain_msg(
                &NodeId::from(state.prev_link),
                RelayChainMsg::CircuitBuilt,
                &out.encode(),
            );
            return DispatchResult::NoResponse;
        }

        // Originator: this node BUILT the circuit (return cells arrive from the
        // first hop tagged our origin circuit_id) → mark it CONFIRMED so the
        // maintenance tick keeps this (proven-live) path instead of re-selecting.
        if let Some(origin) = self
            .circuit_origin
            .as_ref()
            .and_then(|t| t.lookup(&link, p.circuit_id))
        {
            origin.mark_confirmed();
            self.logger.info(
                "anonymity.circuit.confirmed",
                "origin circuit confirmed by terminus CircuitBuilt ACK",
            );
        }
        DispatchResult::NoResponse
    }

    /// `RelayChainMsg::CircuitTeardown`: drop the matched circuit state and
    /// propagate the teardown to the OTHER neighbour so the whole path is freed.
    fn handle_circuit_teardown(&self, body: &[u8], node_id: NodeId) -> DispatchResult {
        use veil_anonymity::circuit_wire::CircuitTeardownPayload;
        let Some(table) = &self.circuit_table else {
            return DispatchResult::NoResponse;
        };
        let p = match CircuitTeardownPayload::decode(body) {
            Ok(p) => p,
            Err(_) => return DispatchResult::NoResponse,
        };
        let link = *node_id.as_bytes();

        // Teardown from prev_link → propagate forward to next_link.
        if let Some(state) = table.lookup_forward(&link, p.circuit_id) {
            let next = state.next_link;
            let cid_out = state.circuit_id_out;
            // Terminus circuit backing a circuit-rendezvous sub → evict it now
            // (don't wait for the registry TTL).
            if next.is_none()
                && let (Some(reg), Some(cookie)) =
                    (&self.circuit_rendezvous, state.registered_cookie())
            {
                reg.remove(&cookie);
            }
            table.remove(&link, p.circuit_id);
            if let Some(nl) = next {
                let tp = CircuitTeardownPayload {
                    circuit_id: cid_out,
                };
                self.send_relay_chain_msg(
                    &NodeId::from(nl),
                    RelayChainMsg::CircuitTeardown,
                    &tp.encode(),
                );
            }
            return DispatchResult::NoResponse;
        }

        // Teardown from next_link → propagate back to prev_link.
        if let Some(state) = table.lookup_backward(&link, p.circuit_id) {
            let prev = state.prev_link;
            let cid_in = state.circuit_id_in;
            table.remove(&state.prev_link, state.circuit_id_in);
            let tp = CircuitTeardownPayload { circuit_id: cid_in };
            self.send_relay_chain_msg(
                &NodeId::from(prev),
                RelayChainMsg::CircuitTeardown,
                &tp.encode(),
            );
            return DispatchResult::NoResponse;
        }

        DispatchResult::NoResponse
    }

    /// If `intro.auth_cookie` is bound to a circuit-backed (onion-registered)
    /// subscription, seal the introduce ciphertext as the FIRST return layer and
    /// send it down that circuit toward the receiver. Returns `true` if handled.
    /// R is the circuit terminus, so it originates the return seq + seals one
    /// layer; intermediate hops add their layers, the receiver opens all N.
    /// Attempt to forward an introduce down a receiver's return circuit.
    /// Result distinguishes "cookie unknown to the circuit registry" from
    /// "cookie known but cell not (re)sent", so the caller logs an unknown
    /// cookie only when the cookie really is unrecognised — a duplicate or a
    /// transient send-drop is NOT an unknown cookie.
    fn try_forward_introduce_via_circuit(
        &self,
        intro: &veil_anonymity::rendezvous::IntroducePayload,
    ) -> CircuitIntroduceForward {
        use veil_anonymity::circuit_data::{Direction, apply_layer, wrap_payload};
        use veil_anonymity::circuit_wire::CircuitDataPayload;
        let Some(reg) = &self.circuit_rendezvous else {
            return CircuitIntroduceForward::NotCircuit;
        };
        let Some(circuit) = reg.lookup(&intro.auth_cookie) else {
            return CircuitIntroduceForward::NotCircuit;
        };
        // Δ2-g1: drop a byte-identical replayed introduce before it consumes
        // circuit bandwidth. Fingerprint the (public cookie ‖ sealed ciphertext);
        // the ciphertext is AEAD so an on-path attacker can't mutate it to dodge
        // the fingerprint. (Duplicate DELIVERY is already blocked downstream by
        // the receiver's introduce replay cache; this closes the amplification.)
        let fp: [u8; 32] = {
            let mut h = blake3::Hasher::new();
            h.update(&intro.auth_cookie);
            h.update(&intro.ciphertext);
            *h.finalize().as_bytes()
        };
        if lock!(self.circuit_introduce_seen).check_and_insert(fp) {
            // Already forwarded this exact introduce recently. The cookie WAS
            // known — caller must not mislabel it as an unknown cookie.
            return CircuitIntroduceForward::KnownButDropped;
        }
        // Frame the introduce into a FIXED-SIZE cell, then apply R's (terminus)
        // return layer; intermediate hops add theirs, the originator peels all.
        let mut buf = match wrap_payload(&intro.ciphertext) {
            Ok(b) => b,
            // introduce larger than one cell — drop, but the cookie was known.
            Err(_) => return CircuitIntroduceForward::KnownButDropped,
        };
        // D5: refuse to send if the return-seq space is exhausted (would reuse
        // keystream). Drop the cell; the circuit idle-GCs and is rebuilt fresh.
        let Some(seq) = circuit.alloc_return_seq() else {
            return CircuitIntroduceForward::KnownButDropped;
        };
        apply_layer(&circuit.circuit_key, Direction::Return, seq, &mut buf);
        let cell = CircuitDataPayload {
            circuit_id: circuit.circuit_id_in,
            seq,
            ciphertext: buf,
        };
        match cell.encode() {
            Ok(body) => {
                self.send_relay_chain_msg(
                    &NodeId::from(circuit.prev_link),
                    RelayChainMsg::CircuitData,
                    &body,
                );
                CircuitIntroduceForward::Forwarded
            }
            // Oversize (too many return hops for the cell cap) — drop; the cell
            // budget is a known b6 refinement. Cookie was known.
            Err(_) => CircuitIntroduceForward::KnownButDropped,
        }
    }

    /// onion-stream R-SPLICE: forward `bytes` down an already-registered receiver
    /// circuit as a RETURN cell — the bulk-data analogue of
    /// `try_forward_introduce_via_circuit` (no signature, no dedup; the byte-stream
    /// engine above provides reliability + ordering). The receiver opens it via
    /// `OriginCircuit::open_return` → its `stream_recv` channel (Phase 1c).
    fn splice_stream_cell(
        &self,
        circuit: &veil_anonymity::circuit_table::CircuitState,
        bytes: &[u8],
    ) -> bool {
        use veil_anonymity::circuit_data::{Direction, apply_layer, wrap_payload};
        use veil_anonymity::circuit_wire::CircuitDataPayload;
        let mut buf = match wrap_payload(bytes) {
            Ok(b) => b,
            Err(_) => {
                circuit_data_diag(|d| d.splice_fail = d.splice_fail.saturating_add(1));
                return false; // larger than one cell — drop (stream MSS keeps small)
            }
        };
        let Some(seq) = circuit.alloc_return_seq() else {
            circuit_data_diag(|d| d.splice_fail = d.splice_fail.saturating_add(1));
            return false; // return-seq exhausted — drop; the circuit idle-GCs + rebuilds
        };
        apply_layer(&circuit.circuit_key, Direction::Return, seq, &mut buf);
        let cell = CircuitDataPayload {
            circuit_id: circuit.circuit_id_in,
            seq,
            ciphertext: buf,
        };
        if let Ok(body) = cell.encode() {
            let sent = self.send_relay_chain_msg(
                &NodeId::from(circuit.prev_link),
                RelayChainMsg::CircuitData,
                &body,
            );
            circuit_data_diag(|d| {
                if sent {
                    d.splice_ok = d.splice_ok.saturating_add(1);
                } else {
                    d.splice_fail = d.splice_fail.saturating_add(1);
                }
            });
            return sent;
        }
        circuit_data_diag(|d| d.splice_fail = d.splice_fail.saturating_add(1));
        false
    }

    /// Send a `RelayChain::<msg>` frame with the given body bytes to
    /// the named peer's session. Used by the rendezvous-relay
    /// state machine for receiver↔rendezvous control frames AND
    /// for forwarding cells / introduces.
    fn send_relay_chain_msg(&self, node_id: &NodeId, msg: RelayChainMsg, body: &[u8]) -> bool {
        use veil_proto::codec::encode_header;
        let Some(ref reg) = self.session_tx_registry else {
            self.logger.info(
                "anonymity.relay_chain.send.no_registry",
                "session_tx_registry not wired; cannot send",
            );
            return false;
        };
        let mut hdr = FrameHeader::new(FrameFamily::RelayChain as u8, msg as u16);
        hdr.body_len = body.len() as u32;
        hdr.set_priority(veil_proto::priority::INTERACTIVE);
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(body);
        let guard = wlock!(reg);
        if let Err(err) =
            guard.send_to_result(node_id.as_bytes(), veil_proto::priority::INTERACTIVE, frame)
        {
            circuit_data_diag(|d| match err {
                veil_session::SendToError::Missing => {
                    d.send_missing = d.send_missing.saturating_add(1);
                }
                veil_session::SendToError::Full => {
                    d.send_full = d.send_full.saturating_add(1);
                }
                veil_session::SendToError::Closed => {
                    d.send_closed = d.send_closed.saturating_add(1);
                }
            });
            self.logger.info(
                "anonymity.relay_chain.send.peer_unreachable",
                format!(
                    "peer={} send failed ({err:?}); dropped",
                    veil_util::hex_short(node_id.as_bytes()),
                ),
            );
            return false;
        }
        true
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
            reply_id: 0,
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
            reply_block: None,
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
        // The direct onion final-hop enqueues a whole message.
        let auth = match got {
            crate::AuthDeliverInbound::Full(a) => a,
            crate::AuthDeliverInbound::Fragment { .. } => panic!("expected Full, got Fragment"),
        };
        assert_eq!(auth.sender_node_id, [0x5A; 32]);
        assert_eq!(auth.nonce, 42);
        assert_eq!(auth.endpoint_id, 7);
        assert_eq!(auth.data, b"authed-hello");
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
            reply_block: None,
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

    /// CircuitBuild at the terminus installs circuit state keyed by
    /// (prev_link, circuit_id_in); a CircuitTeardown frees it.
    #[test]
    fn circuit_build_installs_terminus_then_teardown_frees() {
        use veil_anonymity::circuit_setup::{CircuitSetupHop, build_circuit_setup};
        use veil_anonymity::circuit_table::CircuitTable;
        use veil_anonymity::circuit_wire::CircuitTeardownPayload;

        let mut d = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk).to_bytes();
        d.anonymity_x25519_sk = Some(std::sync::Arc::new(sk));
        d.circuit_table = Some(std::sync::Arc::new(CircuitTable::new()));

        // 1-hop circuit → this node is the terminus (next_hop sentinel).
        let hop = CircuitSetupHop {
            node_id: [0u8; 32],
            pubkey: pk,
            circuit_id_in: 42,
            circuit_id_out: 0,
            circuit_key: [7u8; 32],
        };
        let env = build_circuit_setup(&[hop], b"reg-payload").unwrap();
        let mut hdr = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::CircuitBuild as u16,
        );
        hdr.body_len = env.len() as u32;
        let prev = NodeId::from([0xEE; 32]);
        assert!(matches!(
            d.dispatch_relay_chain(&hdr, &env, prev),
            DispatchResult::NoResponse
        ));

        let table = d.circuit_table.as_ref().unwrap();
        assert_eq!(table.len(), 1, "terminus circuit installed");
        assert!(table.lookup_forward(&[0xEE; 32], 42).is_some());

        // Teardown from the same prev_link frees it.
        let tp = CircuitTeardownPayload { circuit_id: 42 };
        let tbody = tp.encode();
        let mut thdr = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::CircuitTeardown as u16,
        );
        thdr.body_len = tbody.len() as u32;
        d.dispatch_relay_chain(&thdr, &tbody, prev);
        assert!(
            d.circuit_table.as_ref().unwrap().is_empty(),
            "teardown freed the circuit"
        );
    }

    /// A terminus CircuitBuild whose setup payload is a signed circuit
    /// registration binds the cookie → circuit in the circuit-rendezvous
    /// registry (R never sees the receiver's node_id).
    #[test]
    fn circuit_build_terminus_registers_cookie() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        use veil_anonymity::circuit_register::{CircuitRegisterPayload, CircuitRendezvousRegistry};
        use veil_anonymity::circuit_setup::{CircuitSetupHop, build_circuit_setup};
        use veil_anonymity::circuit_table::CircuitTable;
        use veil_crypto::{generate_keypair, sign_message};
        use veil_types::SignatureAlgorithm;

        let mut d = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk).to_bytes();
        d.anonymity_x25519_sk = Some(std::sync::Arc::new(sk));
        d.circuit_table = Some(std::sync::Arc::new(CircuitTable::new()));
        d.circuit_rendezvous = Some(std::sync::Arc::new(CircuitRendezvousRegistry::new()));

        // Signed registration for a cookie.
        let cookie = [0x5A; 16];
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let reg_pk: [u8; 32] = STANDARD.decode(&kp.public_key).unwrap().try_into().unwrap();
        let epoch = 1u64;
        let msg = CircuitRegisterPayload::signing_bytes(&cookie, &reg_pk, epoch);
        let sig = sign_message(
            SignatureAlgorithm::Ed25519,
            &kp.public_key,
            &kp.private_key,
            &msg,
        )
        .unwrap();
        let reg = CircuitRegisterPayload {
            cookie,
            reg_pk,
            epoch,
            signature: sig,
        };

        // 1-hop circuit (this node is terminus); registration as terminus payload.
        let hop = CircuitSetupHop {
            node_id: [0u8; 32],
            pubkey: pk,
            circuit_id_in: 77,
            circuit_id_out: 0,
            circuit_key: [3u8; 32],
        };
        let env = build_circuit_setup(&[hop], &reg.encode()).unwrap();
        let mut hdr = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::CircuitBuild as u16,
        );
        hdr.body_len = env.len() as u32;
        d.dispatch_relay_chain(&hdr, &env, NodeId::from([0xEE; 32]));

        // Cookie is now bound to the installed circuit.
        assert!(
            d.circuit_rendezvous
                .as_ref()
                .unwrap()
                .lookup(&cookie)
                .is_some(),
            "terminus registration bound the cookie to its return circuit"
        );

        // Tearing the circuit down evicts the subscription eagerly (b2d) — no
        // waiting for the registry TTL.
        use veil_anonymity::circuit_wire::CircuitTeardownPayload;
        let tp = CircuitTeardownPayload { circuit_id: 77 };
        let tbody = tp.encode();
        let mut thdr = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::CircuitTeardown as u16,
        );
        thdr.body_len = tbody.len() as u32;
        d.dispatch_relay_chain(&thdr, &tbody, NodeId::from([0xEE; 32]));
        assert!(
            d.circuit_rendezvous
                .as_ref()
                .unwrap()
                .lookup(&cookie)
                .is_none(),
            "teardown evicted the circuit-rendezvous subscription"
        );
    }

    /// diff-audit B1: the terminus emits a `CircuitBuilt` ACK only when the
    /// circuit is USABLE for its role. For a registration-carrying circuit that
    /// means the cookie→circuit binding must SUCCEED first; a rejected
    /// registration (here: a corrupted signature → `BadSignature`) must NOT
    /// produce an ACK, so the originator stays unconfirmed and re-selects a
    /// fresh path instead of freezing a service that R cannot route to.
    #[test]
    fn circuit_build_failed_registration_does_not_ack_b1() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        use veil_anonymity::circuit_register::{CircuitRegisterPayload, CircuitRendezvousRegistry};
        use veil_anonymity::circuit_setup::{CircuitSetupHop, build_circuit_setup};
        use veil_anonymity::circuit_table::CircuitTable;
        use veil_crypto::{generate_keypair, sign_message};
        use veil_session::tx_registry::SessionTxRegistry;
        use veil_types::SignatureAlgorithm;

        // Returns (cookie_bound, ack_sent) for a build whose terminus payload is
        // a registration with an optionally-corrupted signature.
        let run = |corrupt_sig: bool| -> (bool, bool) {
            let mut d = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
            let sk = StaticSecret::random_from_rng(OsRng);
            let pk = PublicKey::from(&sk).to_bytes();
            d.anonymity_x25519_sk = Some(std::sync::Arc::new(sk));
            d.circuit_table = Some(std::sync::Arc::new(CircuitTable::new()));
            d.circuit_rendezvous = Some(std::sync::Arc::new(CircuitRendezvousRegistry::new()));

            // The ACK target is `prev_link` = the node the build arrived from.
            let prev = [0xEE; 32];
            let mut reg_tx = SessionTxRegistry::new();
            let mut rx = reg_tx.register(NodeId::from(prev));
            d.session_tx_registry = Some(std::sync::Arc::new(std::sync::RwLock::new(reg_tx)));

            let cookie = [0x5B; 16];
            let kp = generate_keypair(SignatureAlgorithm::Ed25519);
            let reg_pk: [u8; 32] = STANDARD.decode(&kp.public_key).unwrap().try_into().unwrap();
            let epoch = 1u64;
            let msg = CircuitRegisterPayload::signing_bytes(&cookie, &reg_pk, epoch);
            let mut sig = sign_message(
                SignatureAlgorithm::Ed25519,
                &kp.public_key,
                &kp.private_key,
                &msg,
            )
            .unwrap();
            if corrupt_sig {
                sig[0] ^= 0xFF; // break the registration self-signature
            }
            let regp = CircuitRegisterPayload {
                cookie,
                reg_pk,
                epoch,
                signature: sig,
            };

            let hop = CircuitSetupHop {
                node_id: [0u8; 32],
                pubkey: pk,
                circuit_id_in: 78,
                circuit_id_out: 0,
                circuit_key: [3u8; 32],
            };
            let env = build_circuit_setup(&[hop], &regp.encode()).unwrap();
            let mut hdr = FrameHeader::new(
                FrameFamily::RelayChain as u8,
                RelayChainMsg::CircuitBuild as u16,
            );
            hdr.body_len = env.len() as u32;
            d.dispatch_relay_chain(&hdr, &env, NodeId::from(prev));

            let bound = d
                .circuit_rendezvous
                .as_ref()
                .unwrap()
                .lookup(&cookie)
                .is_some();
            let acked = rx.try_recv().is_ok();
            (bound, acked)
        };

        // Positive control: a valid registration binds the cookie AND ACKs.
        let (bound_ok, acked_ok) = run(false);
        assert!(bound_ok, "valid registration must bind the cookie");
        assert!(acked_ok, "a usable (registered) circuit must be ACK'd");

        // Regression: a rejected registration binds NOTHING and emits NO ACK.
        let (bound_bad, acked_bad) = run(true);
        assert!(!bound_bad, "rejected registration must not bind the cookie");
        assert!(
            !acked_bad,
            "B1: a rejected registration must NOT emit a CircuitBuilt ACK",
        );
    }

    /// Origin-receive: a return CircuitData that matches a circuit THIS node
    /// built is opened across all layers, decrypted, and delivered to the bound
    /// app — the full receiver side of an onion-registered service.
    #[tokio::test]
    async fn circuit_origin_return_opens_decrypts_and_delivers() {
        use veil_anonymity::circuit_data::{Direction, apply_layer, wrap_payload};
        use veil_anonymity::circuit_origin::{OriginCircuit, OriginCircuitTable};
        use veil_anonymity::circuit_wire::CircuitDataPayload;
        use veil_anonymity::rendezvous::{encrypt_introduce, final_hop_kind};
        use veil_proto::AppDeliverPayload;

        let mut d = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let local_sk = StaticSecret::random_from_rng(OsRng);
        let local_pk = PublicKey::from(&local_sk).to_bytes();
        d.anonymity_x25519_sk = Some(std::sync::Arc::new(local_sk));
        d.circuit_origin = Some(std::sync::Arc::new(OriginCircuitTable::new()));

        // Bind the receiving endpoint.
        let app_id = [0xAB; 32];
        let endpoint_id = 7u32;
        let (_h, mut rx) = d.app_registry.register(app_id, endpoint_id, 16);

        // 1-hop origin circuit: terminus R is the first (and only) hop. We craft
        // the return cell R would produce, so a placeholder R id + key suffice.
        let r_id = [0x9C; 32];
        let r_key = [0x33u8; 32];
        let origin_cid = 555u32;
        d.circuit_origin
            .as_ref()
            .unwrap()
            .insert(std::sync::Arc::new(OriginCircuit {
                circuit_keys: vec![r_key],
                first_hop: r_id,
                origin_circuit_id: origin_cid,
                created_unix: 0,
                confirmed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                is_reply: false,
            }));

        // The sealed introduce the sender produced (sealed to OUR anonymity key).
        let payload = b"anon-service-hello".to_vec();
        let deliver = AppDeliverPayload {
            src_node_id: [0u8; 32],
            src_app_id: [0xCD; 32],
            app_id,
            endpoint_id,
            data: veil_bufpool::pooled_shared_from_vec(payload.clone()),
            reply_id: 0,
        };
        let mut introduce_plain = vec![final_hop_kind::APP_DELIVER];
        introduce_plain.extend_from_slice(&deliver.encode());
        let introduce_ct = encrypt_introduce(&introduce_plain, &local_pk).unwrap();

        // R frames it into a fixed-size cell + applies its return layer.
        let seq = 1u32;
        let mut buf = wrap_payload(&introduce_ct).unwrap();
        apply_layer(&r_key, Direction::Return, seq, &mut buf);
        let cell = CircuitDataPayload {
            circuit_id: origin_cid,
            seq,
            ciphertext: buf,
        };
        let body = cell.encode().unwrap();
        let mut hdr = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::CircuitData as u16,
        );
        hdr.body_len = body.len() as u32;
        d.dispatch_relay_chain(&hdr, &body, NodeId::from(r_id));

        // The introduce was opened across the circuit, decrypted, and delivered.
        let msg = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .expect("origin-receive did not deliver in 500ms")
            .expect("channel closed");
        match msg {
            veil_app::registry::AppMessage::Deliver {
                src_node_id, data, ..
            } => {
                assert_eq!(src_node_id, [0u8; 32], "anonymity: src_node_id zeros");
                assert_eq!(data.as_ref(), payload.as_slice());
            }
            other => panic!("expected Deliver, got {other:?}"),
        }
    }

    /// onion-stream Phase 1c: a return `CircuitData` on a circuit registered in
    /// `stream_recv` is delivered to its BYTE-STREAM channel (not the introduce
    /// path). Proves the recv-hook end of the stateful-circuit data plane.
    #[tokio::test]
    async fn circuit_return_routes_to_stream_recv() {
        use veil_anonymity::circuit_data::{Direction, apply_layer, wrap_payload};
        use veil_anonymity::circuit_origin::{OriginCircuit, OriginCircuitTable};
        use veil_anonymity::circuit_wire::CircuitDataPayload;

        let mut d = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        d.circuit_origin = Some(std::sync::Arc::new(OriginCircuitTable::new()));

        // A circuit THIS node originated, R the 1-hop terminus (placeholder key —
        // we craft the exact return cell R would emit).
        let r_id = [0x9C; 32];
        let r_key = [0x44u8; 32];
        let origin_cid = 4242u32;
        d.circuit_origin
            .as_ref()
            .unwrap()
            .insert(std::sync::Arc::new(OriginCircuit {
                circuit_keys: vec![r_key],
                first_hop: r_id,
                origin_circuit_id: origin_cid,
                created_unix: 0,
                confirmed: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                is_reply: false,
            }));

        // Register a byte-stream sink for this circuit (what open_data_circuit does).
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
        d.stream_recv.lock().unwrap().insert(origin_cid, tx);

        // R frames the stream bytes into a fixed cell + applies its return layer.
        let stream_bytes = b"onion-stream cell payload".to_vec();
        let seq = 1u32;
        let mut buf = wrap_payload(&stream_bytes).unwrap();
        apply_layer(&r_key, Direction::Return, seq, &mut buf);
        let cell = CircuitDataPayload {
            circuit_id: origin_cid,
            seq,
            ciphertext: buf,
        };
        let body = cell.encode().unwrap();
        let mut hdr = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::CircuitData as u16,
        );
        hdr.body_len = body.len() as u32;
        d.dispatch_relay_chain(&hdr, &body, NodeId::from(r_id));

        // Delivered to the STREAM channel (opened across the circuit), NOT the
        // introduce path.
        let got = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .expect("stream cell not delivered in 500ms")
            .expect("channel closed");
        assert_eq!(
            got, stream_bytes,
            "stream_recv must receive the opened return-cell bytes"
        );
    }

    /// R-SPLICE end-to-end (the core of the pinned-circuit stream): a FORWARD
    /// CircuitData arriving at a terminus, framed `[target_cookie 16][bytes]`
    /// whose cookie is circuit-registered, is forwarded down THAT receiver's
    /// circuit as a RETURN cell carrying EXACTLY those bytes — no sign/verify, no
    /// dedup. This is the splice the throughput path depends on (sender→R→receiver),
    /// distinct from the signed-introduce flow. Keys are READ from the installed
    /// circuits (not assumed) so the test is robust to key derivation.
    #[tokio::test]
    async fn circuit_forward_splices_to_registered_cookie_return() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        use veil_anonymity::circuit_data::{Direction, apply_layer, read_payload, wrap_payload};
        use veil_anonymity::circuit_register::{CircuitRegisterPayload, CircuitRendezvousRegistry};
        use veil_anonymity::circuit_setup::{CircuitSetupHop, build_circuit_setup};
        use veil_anonymity::circuit_table::CircuitTable;
        use veil_anonymity::circuit_wire::CircuitDataPayload;
        use veil_crypto::{generate_keypair, sign_message};
        use veil_session::tx_registry::SessionTxRegistry;
        use veil_types::SignatureAlgorithm;

        let mut d = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let sk = StaticSecret::random_from_rng(OsRng);
        let pk = PublicKey::from(&sk).to_bytes();
        d.anonymity_x25519_sk = Some(std::sync::Arc::new(sk));
        d.circuit_table = Some(std::sync::Arc::new(CircuitTable::new()));
        d.circuit_rendezvous = Some(std::sync::Arc::new(CircuitRendezvousRegistry::new()));

        // Capture frames R emits toward the RECEIVER's hop (the spliced return).
        let recv_hop = [0xEE; 32];
        let send_hop = [0xDD; 32];
        let mut reg_tx = SessionTxRegistry::new();
        let mut recv_rx = reg_tx.register(NodeId::from(recv_hop));
        let _send_rx = reg_tx.register(NodeId::from(send_hop)); // drain any sender-side ACK
        d.session_tx_registry = Some(std::sync::Arc::new(std::sync::RwLock::new(reg_tx)));

        // (1) RECEIVER's circuit at R: a terminus build whose payload registers a
        //     cookie, arriving from recv_hop → binds cookie → this return circuit.
        let cookie = [0x5A; 16];
        let recv_cid = 77u32;
        let kp = generate_keypair(SignatureAlgorithm::Ed25519);
        let reg_pk: [u8; 32] = STANDARD.decode(&kp.public_key).unwrap().try_into().unwrap();
        let epoch = 1u64;
        let msg = CircuitRegisterPayload::signing_bytes(&cookie, &reg_pk, epoch);
        let sig = sign_message(
            SignatureAlgorithm::Ed25519,
            &kp.public_key,
            &kp.private_key,
            &msg,
        )
        .unwrap();
        let regp = CircuitRegisterPayload {
            cookie,
            reg_pk,
            epoch,
            signature: sig,
        };
        let rhop = CircuitSetupHop {
            node_id: [0u8; 32],
            pubkey: pk,
            circuit_id_in: recv_cid,
            circuit_id_out: 0,
            circuit_key: [3u8; 32],
        };
        let renv = build_circuit_setup(&[rhop], &regp.encode()).unwrap();
        let mut rhdr = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::CircuitBuild as u16,
        );
        rhdr.body_len = renv.len() as u32;
        d.dispatch_relay_chain(&rhdr, &renv, NodeId::from(recv_hop));
        assert!(
            d.circuit_rendezvous
                .as_ref()
                .unwrap()
                .lookup(&cookie)
                .is_some(),
            "receiver cookie bound to its return circuit"
        );
        let _ = recv_rx.try_recv(); // drain the CircuitBuilt ACK toward recv_hop

        // (2) SENDER's circuit at R: a plain terminus build arriving from send_hop.
        let send_cid = 42u32;
        let shop = CircuitSetupHop {
            node_id: [0u8; 32],
            pubkey: pk,
            circuit_id_in: send_cid,
            circuit_id_out: 0,
            circuit_key: [7u8; 32],
        };
        let senv = build_circuit_setup(&[shop], b"no-reg").unwrap();
        let mut shdr = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::CircuitBuild as u16,
        );
        shdr.body_len = senv.len() as u32;
        d.dispatch_relay_chain(&shdr, &senv, NodeId::from(send_hop));

        // Read the INSTALLED keys (build may derive, so don't assume the setup key).
        let table = d.circuit_table.as_ref().unwrap();
        let send_key = table
            .lookup_forward(&send_hop, send_cid)
            .unwrap()
            .circuit_key;
        let recv_key = table
            .lookup_forward(&recv_hop, recv_cid)
            .unwrap()
            .circuit_key;

        // (3) FORWARD CircuitData on the sender's circuit, framed `[cookie][bytes]`
        //     and encrypted with the sender circuit's forward layer (R XORs back).
        let post_cookie = b"[sender-node-32B..]+stream cell".to_vec();
        let mut framed = Vec::with_capacity(16 + post_cookie.len());
        framed.extend_from_slice(&cookie);
        framed.extend_from_slice(&post_cookie);
        let fseq = 1u32;
        let mut fbuf = wrap_payload(&framed).unwrap();
        apply_layer(&send_key, Direction::Forward, fseq, &mut fbuf);
        let fwd = CircuitDataPayload {
            circuit_id: send_cid,
            seq: fseq,
            ciphertext: fbuf,
        };
        let fbody = fwd.encode().unwrap();
        let mut fhdr = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::CircuitData as u16,
        );
        fhdr.body_len = fbody.len() as u32;
        d.dispatch_relay_chain(&fhdr, &fbody, NodeId::from(send_hop));

        // (4) R spliced a RETURN cell toward the receiver hop on recv_cid. Decode,
        //     peel the receiver circuit's return layer, unwrap → exactly the bytes.
        let (_prio, frame) = recv_rx
            .try_recv()
            .expect("splice must emit a return cell toward the receiver hop");
        let ret = CircuitDataPayload::decode(&frame[veil_proto::header::HEADER_SIZE..])
            .expect("decode spliced return CircuitData");
        assert_eq!(
            ret.circuit_id, recv_cid,
            "return cell rides the receiver's circuit_id_in"
        );
        let mut rbuf = ret.ciphertext.clone();
        apply_layer(&recv_key, Direction::Return, ret.seq, &mut rbuf);
        let got = read_payload(&rbuf).expect("unwrap the spliced payload");
        assert_eq!(
            got, post_cookie,
            "splice forwarded EXACTLY the post-cookie bytes"
        );
    }

    /// diff-audit Δ2-d: a `CircuitBuilt` ACK arriving from the first hop, tagged
    /// with our origin circuit id, marks that origin circuit CONFIRMED.
    #[test]
    fn circuit_built_ack_confirms_origin_circuit_delta2d() {
        use veil_anonymity::circuit_origin::{OriginCircuit, OriginCircuitTable};
        use veil_anonymity::circuit_wire::CircuitBuiltPayload;

        let mut d = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        d.circuit_origin = Some(std::sync::Arc::new(OriginCircuitTable::new()));

        let r_id = [0x9C; 32];
        let origin_cid = 555u32;
        let confirmed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        d.circuit_origin
            .as_ref()
            .unwrap()
            .insert(std::sync::Arc::new(OriginCircuit {
                circuit_keys: vec![[0x33u8; 32]],
                first_hop: r_id,
                origin_circuit_id: origin_cid,
                created_unix: 0,
                confirmed: std::sync::Arc::clone(&confirmed),
                is_reply: false,
            }));
        assert!(!confirmed.load(std::sync::atomic::Ordering::Relaxed));

        // The terminus ACK arrives from the first hop tagged our origin id.
        let body = CircuitBuiltPayload {
            circuit_id: origin_cid,
        }
        .encode();
        let mut hdr = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::CircuitBuilt as u16,
        );
        hdr.body_len = body.len() as u32;
        d.dispatch_relay_chain(&hdr, &body, NodeId::from(r_id));

        assert!(
            confirmed.load(std::sync::atomic::Ordering::Relaxed),
            "CircuitBuilt ACK must confirm the origin circuit",
        );
    }

    /// A non-circuit-capable node (no SK / table) silently drops CircuitBuild.
    #[test]
    fn circuit_build_no_capability_silent_drop() {
        let d = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        assert!(d.circuit_table.is_none());
        let mut hdr = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::CircuitBuild as u16,
        );
        hdr.body_len = 8;
        assert!(matches!(
            d.dispatch_relay_chain(&hdr, &[0u8; 8], NodeId::from([0xEE; 32])),
            DispatchResult::NoResponse
        ));
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

    /// MUST-FIX-1: a `receive_anonymous`-only node owns an anonymity SK (to
    /// unseal its own forwarded introduces) but `anonymity_relay_capable =
    /// false`, so it must NOT forward OTHERS' onion cells. The Forward arm is
    /// gated on the relay flag, not SK presence. With the flag set it forwards.
    #[test]
    fn forward_arm_gated_on_relay_capable() {
        use veil_session::tx_registry::SessionTxRegistry;
        let (me_sk, me_hop) = fresh_hop(0xAA);
        let (_next_sk, next_hop) = fresh_hop(0xBB);
        let next_node_id = next_hop.node_id;
        // 2-hop cell: this node (hop0) forwards to next_hop (hop1).
        let cell = build_anonymous_cell(b"inner onion payload", &[me_hop, next_hop]).unwrap();
        let me_sk_bytes = me_sk.to_bytes();

        let run = |relay_capable: bool| -> bool {
            let mut dispatcher = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
            dispatcher.anonymity_x25519_sk = Some(Arc::new(StaticSecret::from(me_sk_bytes)));
            dispatcher.anonymity_relay_capable = relay_capable;
            let mut reg = SessionTxRegistry::new();
            let mut rx = reg.register(NodeId::from(next_node_id));
            dispatcher.session_tx_registry = Some(Arc::new(std::sync::RwLock::new(reg)));

            let mut hdr =
                FrameHeader::new(FrameFamily::RelayChain as u8, RelayChainMsg::Hop as u16);
            hdr.body_len = CELL_SIZE as u32;
            let result = dispatcher.dispatch_relay_chain(&hdr, &cell, NodeId::from([0xEE; 32]));
            assert!(matches!(result, DispatchResult::NoResponse));
            rx.try_recv().is_ok()
        };

        assert!(run(true), "relay_capable node must forward the cell");
        assert!(
            !run(false),
            "receive-only node must NOT forward others' circuits",
        );
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
            reply_id: 0,
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
