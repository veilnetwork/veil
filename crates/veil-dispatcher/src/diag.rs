use super::{DiagEvent, DispatchResult, FrameDispatcher};
use veil_cfg::NodeId;
use veil_proto::{
    codec::encode_header,
    diag::{
        DIAG_DEFAULT_HOP_LIMIT, DiagPingPayload, DiagPongPayload, DiagTraceHopPayload,
        DiagTraceProbePayload,
    },
    family::{DiagMsg, FrameFamily},
    header::{FrameHeader, HEADER_SIZE},
};
use veil_util::{lock, rlock, wlock};

impl FrameDispatcher {
    /// should we answer a `DiagPing` / `TraceProbe` whose
    /// expiring-hop is us, given the originating `sender`?
    ///
    /// * `Public` — yes, anyone may probe (the originally-published
    ///   diagnostic semantics).
    /// * `ContactsOnly` — only if `sender` is in our `peer_pubkeys` cache
    ///   i.e. we have actually handshaked with them at least once. An
    ///   attacker scanning random `node_id`s gets nothing back.
    /// * `IntroductionOnly` — never; introduction-only nodes refuse to
    ///   publish their own existence over diagnostics, period.
    fn diag_disclosure_allowed(&self, sender: &[u8; 32]) -> bool {
        match self.discovery_mode {
            veil_cfg::DiscoveryMode::Public => true,
            veil_cfg::DiscoveryMode::ContactsOnly => {
                lock!(self.crypto.peer_pubkeys).contains_key(sender)
            }
            veil_cfg::DiscoveryMode::IntroductionOnly => false,
        }
    }

    pub fn dispatch_diag(
        &self,
        header: &FrameHeader,
        body: &[u8],
        _node_id: NodeId,
    ) -> DispatchResult {
        let msg = match DiagMsg::try_from(header.msg_type) {
            Ok(m) => m,
            Err(_) => {
                return DispatchResult::Violation(format!(
                    "unknown diag msg_type {}",
                    header.msg_type
                ));
            }
        };

        match msg {
            // ── Ping: forward to target or reply if we are the target ─────────
            DiagMsg::Ping => {
                let mut p = match DiagPingPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad DiagPing: {e}")),
                };
                if p.target == self.local_node_id {
                    // discovery_mode gate — silently drop when we
                    // are not willing to disclose our existence to `p.sender`.
                    // Per-peer rate-limit is already applied at the
                    // dispatch level (`FrameDispatcher::dispatch` →
                    // `abuse.rate_limiter.allow(peer_id)`), so DiagPing
                    // floods from a single session are bounded by the same
                    // bucket as every other frame family.
                    if !self.diag_disclosure_allowed(&p.sender) {
                        return DispatchResult::NoResponse;
                    }
                    // We are the target: reply with Pong routed back to sender.
                    let pong = DiagPongPayload {
                        seq: p.seq,
                        responder: self.local_node_id,
                        echo_ts_us: p.ts_us,
                        dest: p.sender,
                        hop_limit: DIAG_DEFAULT_HOP_LIMIT,
                    };
                    let mut hdr = FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::Pong as u16);
                    let body_bytes = pong.encode();
                    hdr.body_len = body_bytes.len() as u32;
                    let mut out = Vec::with_capacity(HEADER_SIZE + body_bytes.len());
                    out.extend_from_slice(&encode_header(&hdr));
                    out.extend_from_slice(&body_bytes);
                    // Route Pong back to sender (may require relay).
                    self.forward_toward(&p.sender, out);
                    return DispatchResult::NoResponse;
                }
                // Not the target: decrement the forwarding hop budget and
                // forward toward p.target. Dropping at zero bounds route-cache
                // loops — without this a Ping can bounce forever between two
                // relays whose route caches disagree about the next hop
                // (Ping carries no other loop guard, unlike TraceProbe's TTL).
                p.hop_limit = p.hop_limit.saturating_sub(1);
                if p.hop_limit == 0 {
                    return DispatchResult::NoResponse;
                }
                let forwarded_body = p.encode();
                let mut fwd_hdr = FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::Ping as u16);
                fwd_hdr.body_len = forwarded_body.len() as u32;
                let mut out = Vec::with_capacity(HEADER_SIZE + forwarded_body.len());
                out.extend_from_slice(&encode_header(&fwd_hdr));
                out.extend_from_slice(&forwarded_body);
                self.forward_toward(&p.target, out);
                DispatchResult::NoResponse
            }

            // ── Pong: forward to dest or deliver to waiting admin handler ─────
            DiagMsg::Pong => {
                let mut p = match DiagPongPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad DiagPong: {e}")),
                };
                // If not addressed to us, decrement the forwarding hop budget
                // and forward toward dest. Dropping at zero bounds route-cache
                // loops on the return path the same way the Ping path does.
                if p.dest != self.local_node_id {
                    p.hop_limit = p.hop_limit.saturating_sub(1);
                    if p.hop_limit == 0 {
                        return DispatchResult::NoResponse;
                    }
                    let forwarded_body = p.encode();
                    let mut hdr = FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::Pong as u16);
                    hdr.body_len = forwarded_body.len() as u32;
                    let mut out = Vec::with_capacity(HEADER_SIZE + forwarded_body.len());
                    out.extend_from_slice(&encode_header(&hdr));
                    out.extend_from_slice(&forwarded_body);
                    self.forward_toward(&p.dest, out);
                    return DispatchResult::NoResponse;
                }
                // Addressed to us: deliver to the waiting ping handler.
                let event = DiagEvent::Pong {
                    responder: p.responder,
                    echo_ts_us: p.echo_ts_us,
                };
                if let Some(tx) = lock!(self.pending_diag).get(&p.seq) {
                    let _ = tx.try_send(event);
                }
                DispatchResult::NoResponse
            }

            // ── TraceProbe: decrement TTL; forward or send TraceHop back ─────
            DiagMsg::TraceProbe => {
                let mut p = match DiagTraceProbePayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad DiagTraceProbe: {e}")),
                };
                // Classic traceroute semantics: decrement first, then check.
                // A relay that decrements TTL to 0 is the expiring hop — it sends
                // TraceHop back. This means a probe with TTL=1 expires at the
                // first relay, TTL=2 at the second, and so on.
                // Also stop immediately when the probe reaches its final target
                // (p.target == local_node_id) regardless of remaining TTL — this
                // prevents the probe from looping back into the network.
                p.ttl = p.ttl.saturating_sub(1);
                if p.ttl == 0 || p.target == self.local_node_id {
                    // refuse to disclose our `local_node_id` via
                    // TraceHop unless `discovery_mode` permits it for this
                    // sender. We still forward TraceProbe transit (above)
                    // so that legitimate traceroute through multi-hop paths
                    // continues to work — only the *final* hop reveal is
                    // gated. In `IntroductionOnly` mode no node ever sends
                    // TraceHop, which is the whole point. Per-peer rate
                    // limit is enforced at the dispatch level.
                    if !self.diag_disclosure_allowed(&p.sender) {
                        return DispatchResult::NoResponse;
                    }
                    // TTL expired at this hop: send TraceHop back to the original sender.
                    // hop_idx = orig_ttl = which hop number this probe was probing.
                    let hop = DiagTraceHopPayload {
                        seq: p.seq,
                        hop_node_id: self.local_node_id,
                        hop_idx: p.orig_ttl,
                        echo_ts_us: p.ts_us,
                        dest: p.sender,
                        hop_limit: DIAG_DEFAULT_HOP_LIMIT,
                    };
                    let mut hdr =
                        FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::TraceHop as u16);
                    let body_bytes = hop.encode();
                    hdr.body_len = body_bytes.len() as u32;
                    let mut out = Vec::with_capacity(HEADER_SIZE + body_bytes.len());
                    out.extend_from_slice(&encode_header(&hdr));
                    out.extend_from_slice(&body_bytes);
                    // Route the TraceHop back to the original sender.
                    self.forward_toward(&p.sender, out);
                    return DispatchResult::NoResponse;
                }
                // TTL still > 0: forward toward the probe's target.
                let forwarded_body = p.encode();
                let mut hdr = FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::TraceProbe as u16);
                hdr.body_len = forwarded_body.len() as u32;
                let mut out = Vec::with_capacity(HEADER_SIZE + forwarded_body.len());
                out.extend_from_slice(&encode_header(&hdr));
                out.extend_from_slice(&forwarded_body);
                // Route toward p.target: prefer direct session, then route cache.
                self.forward_toward(&p.target, out);
                DispatchResult::NoResponse
            }

            // ── TraceHop: forward to dest or deliver to waiting admin handler ─
            DiagMsg::TraceHop => {
                let mut p = match DiagTraceHopPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad DiagTraceHop: {e}")),
                };
                // If this hop report is not addressed to us, decrement the
                // forwarding hop budget and forward it toward dest. Dropping at
                // zero bounds route-cache loops on the hop-report return path.
                if p.dest != self.local_node_id {
                    p.hop_limit = p.hop_limit.saturating_sub(1);
                    if p.hop_limit == 0 {
                        return DispatchResult::NoResponse;
                    }
                    let forwarded_body = p.encode();
                    let mut hdr =
                        FrameHeader::new(FrameFamily::Diag as u8, DiagMsg::TraceHop as u16);
                    hdr.body_len = forwarded_body.len() as u32;
                    let mut out = Vec::with_capacity(HEADER_SIZE + forwarded_body.len());
                    out.extend_from_slice(&encode_header(&hdr));
                    out.extend_from_slice(&forwarded_body);
                    self.forward_toward(&p.dest, out);
                    return DispatchResult::NoResponse;
                }
                // Addressed to us: deliver to the waiting trace handler.
                let event = DiagEvent::TraceHop {
                    hop_idx: p.hop_idx,
                    node_id: p.hop_node_id,
                    echo_ts_us: p.echo_ts_us,
                };
                if let Some(tx) = lock!(self.pending_diag).get(&p.seq) {
                    let _ = tx.try_send(event);
                }
                DispatchResult::NoResponse
            }
        }
    }

    /// Route a frame toward `dest`: try direct session first, then fall back
    /// to the route cache if no direct session exists.
    pub fn forward_toward(&self, dest: &[u8; 32], frame: Vec<u8>) {
        if let Some(ref reg) = self.session_tx_registry {
            // DEADLOCK FIX (audit 2026-05-29): snapshot the route-cache
            // fallback hop BEFORE taking the session_tx_registry write
            // lock.  The previous order (registry-write held while
            // acquiring route_cache-read) inverted the canonical
            // route_cache→registry order used throughout routing.rs — а
            // second thread taking the locks in canonical order could
            // deadlock against this one.  The extra route_cache lookup в
            // the direct-hit case is а cheap LRU read.
            let fallback_hop = rlock!(self.route_cache).lookup(dest);
            let guard = wlock!(reg);
            if !guard.send_to(
                dest,
                veil_proto::header::priority::INTERACTIVE,
                frame.clone(),
            ) && let Some(hop_id) = fallback_hop
            {
                guard.send_to(&hop_id, veil_proto::header::priority::INTERACTIVE, frame);
            }
        }
    }
}
