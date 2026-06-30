use super::{DispatchResult, FrameDispatcher};
use veil_cfg::NodeId;
use veil_proto::{
    codec::encode_header,
    delivery::{DeliveryEnvelope, ForwardPayload},
    family::{DeliveryMsg, FrameFamily},
    header::{FrameHeader, TrafficClass},
};
use veil_types::NodeIdBytes;
use veil_util::{lock, rlock, wlock};

/// produce a u64 randomness seed for `pick_weighted` from a
/// `trace_id` (already random per-frame) folded with the current monotonic
/// nanosecond tick. Concatenating an already-random per-frame id with a
/// fast-changing local clock avoids two failure modes: (a) deterministic
/// repetition when the same frame is re-dispatched (would always pick the
/// same gateway) (b) adversarial trace_id selection biasing the choice.
pub fn rand_seed_for_pick(trace_id: u64) -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // Mix with xorshift64 step so low-order bits propagate.
    let mut x = trace_id ^ nanos.rotate_left(17);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    x
}

/// Per-candidate routing attributes captured once at relay-forward
/// time so the scoring loop doesn't re-acquire `rtt_table` / `peer_
/// vivaldi` locks for every candidate.  Stored parallel to the
/// `candidates: Vec<[u8; 32]>` array (`hop_attrs[i]` describes
/// `candidates[i]`).
///
/// Lifted from a local-scope struct inside `relay_forward` so helper
/// methods (`gather_relay_candidates`, future scoring extraction) can
/// take and return it without inheriting the function's local type.
/// Tuple returned by [`FrameDispatcher::gather_relay_candidates`]:
/// `(candidates, hop_attrs, hops_with_scores)` — three parallel vectors
/// indexed by relay-hop position.
pub type RelayCandidates = (Vec<[u8; 32]>, Vec<HopAttrs>, Vec<([u8; 32], u32)>);

#[derive(Copy, Clone)]
pub struct HopAttrs {
    /// Hop-count from the route_cache entry (1 = direct peer, 2+ = relay chain).
    pub hop_count: u8,
    /// EWMA-smoothed round-trip time in ms; `u32::MAX` if no probe data.
    pub rtt_ms: u32,
    /// Congestion byte (0-255) reported by the peer in keepalive frames.
    pub congestion: u8,
    /// RTT-probe confidence (0.0 - 1.0).  Stale probes decay to 0 and
    /// fall back to Vivaldi distance.
    pub confidence: f64,
    /// Battery percentage (0 = AC / unknown / not reported).
    pub battery: u8,
    /// MAD-based jitter (ms).  High jitter penalises real-time traffic.
    pub jitter_ms: f64,
    /// `BandwidthClass` discriminant.  Narrow class penalises BULK traffic.
    pub bandwidth_class: u8,
    /// Relay success EMA (0.0 - 1.0).  Used to penalise unreliable relays
    /// once `relay_attempts >= relay_reputation_min_attempts`.
    pub relay_success_ema: f32,
    /// Cumulative relay attempt count (gates reputation penalty).
    pub relay_attempts: u32,
}

impl FrameDispatcher {
    /// resolve a sovereign [`Recipient`](veil_proto::recipient::Recipient)
    /// (`node_id` + `InstanceTag`) into the transport-level
    /// peer_ids the dispatcher should forward to, via the wired
    /// `SessionRegistry`.
    ///
    /// Return-value semantics:
    /// `None` — no `SessionRegistry` is wired (test dispatcher or
    /// pre-462 build). Caller falls back to legacy `node_id`
    /// routing via the `route_cache`.
    /// `Some(vec![])` — `SessionRegistry` is wired but reports no
    /// live session for this `node_id` + `InstanceTag`
    /// combination. Caller falls back to `route_cache` / mailbox.
    /// `Some(vec![peer_id...])` — live sessions exist; the
    /// dispatcher fans out to each `peer_id` via the existing
    /// `session_tx_registry` send paths.
    ///
    /// Currently exercised only by unit tests; the `relay_forward`
    /// integration that calls this at frame-forward time is the
    /// remaining runtime plumbing step.
    pub fn resolve_sovereign_delivery_targets(
        &self,
        recipient: &veil_proto::recipient::Recipient,
    ) -> Option<Vec<[u8; 32]>> {
        let reg = self.session_registry.as_ref()?;
        Some(lock!(reg).resolve_recipient(recipient))
    }

    /// attempt to forward `payload` directly over a live
    /// sovereign session, bypassing `route_cache` scoring. Called
    /// from `relay_forward` before the legacy multi-hop path.
    ///
    /// Returns `true` iff the envelope was successfully handed off to
    /// at least one live sovereign session (after split-horizon +
    /// self-loop filtering). Returns `false` on:
    /// No `session_registry` wired (test dispatcher / legacy build).
    /// No `session_tx_registry` wired (no outbound send path).
    /// `resolve_recipient` returned empty (identity offline, legacy
    /// peer, or recipient not sovereign).
    /// All resolved peers were filtered out (sent to us by
    /// ourselves or by the sender — split-horizon).
    /// Every attempted `send_to` failed (session queue full).
    ///
    /// In any `false` case the caller (`relay_forward`) falls through
    /// to the scored `route_cache` relay path unchanged — so this
    /// helper is purely additive. It never changes the outcome of
    /// a frame that the legacy path would have handled; it only
    /// shortens delivery when a direct authenticated session exists.
    fn try_sovereign_direct_forward(
        &self,
        payload: &ForwardPayload,
        sender_peer_id: NodeId,
        traffic_class: u8,
        relay_hops_out: u8,
    ) -> bool {
        let Some(targets) = self.resolve_sovereign_delivery_targets(&payload.envelope.recipient)
        else {
            return false;
        };
        if targets.is_empty() {
            return false;
        }
        let Some(reg) = &self.session_tx_registry else {
            return false;
        };

        // Build the forward body once — identical structure to
        // `relay_forward`'s `make_fwd_frame` closure (
        // single-allocation pattern). The only per-target difference
        // is the 32-byte `next_hop_node_id` prefix.
        let envelope_bytes = payload.envelope.encode();
        let mut suffix = Vec::with_capacity(9);
        suffix.extend_from_slice(&payload.envelope.trace_id.to_be_bytes());
        suffix.push(relay_hops_out);
        let body_len = 32 + envelope_bytes.len() + suffix.len();
        let total_wire_len = veil_proto::header::HEADER_SIZE + body_len;

        let reg_guard = rlock!(reg);
        for target in targets {
            // Split-horizon + self-loop filtering (mirrors the same
            // predicate relay_forward applies to route_cache hops).
            if &target == sender_peer_id.as_bytes() || target == self.local_node_id {
                continue;
            }

            let mut fwd_hdr =
                FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
            fwd_hdr.body_len = body_len as u32;
            let mut frame = Vec::with_capacity(total_wire_len);
            frame.extend_from_slice(&encode_header(&fwd_hdr));
            frame.extend_from_slice(&target);
            frame.extend_from_slice(&envelope_bytes);
            frame.extend_from_slice(&suffix);

            if reg_guard.send_to(&target, traffic_class, frame) {
                // Direct-forward counter would land here on a future
                // operator-dashboard milestone (was closed
                // without the metric; not critical to session correctness).
                return true;
            }
        }
        false
    }

    pub fn dispatch_delivery(
        &self,
        header: &FrameHeader,
        body: &[u8],
        peer_id: NodeId,
    ) -> DispatchResult {
        let msg = match DeliveryMsg::try_from(header.msg_type) {
            Ok(m) => m,
            Err(_) => {
                return DispatchResult::Violation(format!(
                    "unknown delivery msg_type {}",
                    header.msg_type
                ));
            }
        };

        match msg {
            DeliveryMsg::Forward => self.handle_delivery_forward(header, body, peer_id),
            DeliveryMsg::DeliveryStatus => self.handle_delivery_status(body),
            DeliveryMsg::ChunkManifest => self.handle_chunk_manifest(body),
            DeliveryMsg::Chunk => self.handle_chunk(body, peer_id),
            DeliveryMsg::Transit => self.handle_transit(body, peer_id),

            // ── DHT-routed recursive relay ─────────────────────────
            DeliveryMsg::RecursiveRelay => self.handle_recursive_relay(body, peer_id),

            // ── Source-routed relay (audit batch 2026-05-23) ───────
            DeliveryMsg::RelayPath => self.handle_relay_path(body, peer_id),
        }
    }

    /// Handle a source-routed relay frame.  Either forward to the next
    /// node listed in `path` OR deliver the inner payload locally if
    /// we are the terminal hop.  Drops on:
    /// - malformed wire bytes,
    /// - `path[next_hop] != local_node_id` (mis-routed),
    /// - no session to the next-recipient (chain broken).
    ///
    /// The inner payload, at the terminal hop, is dispatched as a
    /// regular `AppDeliver` frame (sender-side wraps an `AppDeliverPayload`
    /// inside `inner`) so the existing app-registry routing path
    /// delivers to the bound endpoint.
    fn handle_relay_path(&self, body: &[u8], peer_id: NodeId) -> DispatchResult {
        use veil_proto::app::AppSendPayload;
        use veil_proto::codec::encode_header;
        use veil_proto::delivery::RelayPathPayload;
        use veil_proto::family::FrameFamily;
        use veil_proto::header::{FrameHeader, priority};

        let mut payload = match RelayPathPayload::decode(body) {
            Ok(p) => p,
            Err(e) => return DispatchResult::Violation(format!("bad RelayPath: {e}")),
        };

        // Defence-in-depth: verify the recipient slot really points at us.
        let current = match payload.current_recipient() {
            Some(id) => *id,
            None => {
                return DispatchResult::Violation(
                    "RelayPath: next_hop out of range (decode-time guard failed)".into(),
                );
            }
        };
        if current != self.local_node_id {
            return DispatchResult::Violation(format!(
                "RelayPath: path[next_hop] != local_node_id (next_hop slot {:?} != self {:?})",
                &current[..4],
                &self.local_node_id[..4],
            ));
        }

        // Terminal hop: decode the inner as `AppSendPayload` and hand off
        // to the app registry just like an incoming `AppSend` from a direct
        // session.  `src_node_id` becomes the last-hop peer (best effort;
        // proper originator preservation needs a wire-format extension
        // that carries the originator separately).
        if payload.is_terminal() {
            match AppSendPayload::decode(&payload.inner) {
                Ok(send) => {
                    self.logger.info(
                        "relay_path.terminal",
                        format!(
                            "from={} hops={} endpoint_id={} data_len={}",
                            veil_util::hex_short(peer_id.as_bytes()),
                            payload.path.len(),
                            send.endpoint_id,
                            send.data.len(),
                        ),
                    );
                    // Terminal replay guard (M-1): RelayPath's AppSendPayload
                    // carries no content_id, so dedup on a hash of the inner
                    // (distinct 0xFD key-domain vs Forward/Transit/Recursive).
                    // A replayed source-routed frame is dropped; legitimate
                    // single delivery (incl. the 64-node chain) still passes.
                    let mut dedup_key: [u8; 32] = *blake3::hash(&payload.inner).as_bytes();
                    dedup_key[0] = 0xFD;
                    if lock!(self.forward_seen_set).check_and_insert(dedup_key) {
                        return DispatchResult::NoResponse;
                    }
                    self.app_registry.route_ipc_deliver(
                        *peer_id.as_bytes(),
                        send.src_app_id,
                        send.app_id,
                        send.endpoint_id,
                        send.data,
                    );
                    return DispatchResult::NoResponse;
                }
                Err(e) => {
                    return DispatchResult::Violation(format!(
                        "RelayPath terminal: inner is not a valid AppSend: {e}"
                    ));
                }
            }
        }

        // Forward to the next node in the path.  Increment next_hop, re-encode,
        // send through whatever session exists to next_recipient.  If no
        // session — drop (the sender's path is broken; no point flooding).
        let next_id = match payload.next_recipient() {
            Some(id) => *id,
            None => {
                return DispatchResult::Violation(
                    "RelayPath: terminal-check + next_recipient disagree".into(),
                );
            }
        };
        let new_hop_index = payload.next_hop.saturating_add(1);
        let total_hops = payload.path.len();
        payload.next_hop = new_hop_index;
        let body_out = payload.encode();
        let mut hdr = FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::RelayPath as u16);
        hdr.body_len = body_out.len() as u32;
        hdr.set_priority(priority::INTERACTIVE);
        let mut frame = encode_header(&hdr).to_vec();
        frame.extend_from_slice(&body_out);

        let sent = match &self.session_tx_registry {
            Some(reg) => veil_util::rlock!(reg).send_to(&next_id, priority::INTERACTIVE, frame),
            None => false,
        };
        if sent {
            self.logger.info(
                "relay_path.forward",
                format!(
                    "from={} next={} hop={}/{}",
                    veil_util::hex_short(peer_id.as_bytes()),
                    veil_util::hex_short(&next_id),
                    new_hop_index,
                    total_hops,
                ),
            );
        } else {
            self.logger.warn(
                "relay_path.chain_broken",
                format!(
                    "from={} next={} hop={}/{} (no session to next hop)",
                    veil_util::hex_short(peer_id.as_bytes()),
                    veil_util::hex_short(&next_id),
                    new_hop_index,
                    total_hops,
                ),
            );
            // Chain broken at this hop.  We have no way to signal the
            // sender (RelayPath is unidirectional by design).
            if let Some(m) = &self.metrics {
                m.inc_route_miss();
            }
        }
        DispatchResult::NoResponse
    }

    // ── Relay-forward path ───────────────────────────────────────────────────

    /// Relay a `DELIVERY_FORWARD` frame that is **not** addressed to this node.
    ///
    /// Performs TTL expiry check, content_id dedup, RTT-sorted next-hop
    /// selection, and mailbox fallback — in that order.
    /// gate a FORWARD frame against all pre-routing invariants.
    ///
    /// Extracted from `relay_forward`. Runs (in order): congestion
    /// backpressure, sender-identity spoof check (
    /// with a meta-E2E exception), hop-limit
    /// TTL + clock-skew sanity (overflow-safe via `saturating_add`), and
    /// content-id dedup (zero-id rejected outright).
    ///
    /// Returns `Ok(relay_hops_out)` — the incremented hop counter the
    /// caller should stamp on its outgoing frame — or `Err(result)` with
    /// the exact `DispatchResult` variant to return to the dispatch
    /// loop (Violation / RateLimited / NoResponse).
    #[allow(clippy::result_large_err)]
    fn check_relay_preconditions(
        &self,
        payload: &ForwardPayload,
        peer_id: NodeId,
    ) -> std::result::Result<u8, DispatchResult> {
        // backpressure — drop FORWARD when local congestion exceeds threshold.
        // score_u8 > 200 ≈ 78% load → reject transit traffic to protect local node.
        if let Some(ref cm) = self.congestion_monitor
            && cm.score_u8() > 200
        {
            log::warn!(
                "LIMIT rate_limited(congestion_shed): relay load {}/255 (>200 ≈ 78%) \
                 — dropping FORWARD from peer {}",
                cm.score_u8(),
                veil_util::hex_short(peer_id.as_bytes()),
            );
            if let Some(m) = &self.metrics {
                m.inc_rate_limit_drops();
            }
            return Err(DispatchResult::RateLimited);
        }

        // SEC: verify the envelope's sender_node_id matches the authenticated peer
        // when this peer is the originator. Meta-E2E envelopes
        // intentionally carry zero outer sender_node_id.
        let is_meta_e2e = payload.envelope.payload.first() == Some(&veil_proto::META_E2E_MARKER);
        if payload.relay_hops == 0 {
            if is_meta_e2e {
                // Meta-E2E: outer sender must be zeroed — the real identity is
                // inside the ciphertext. A non-zero sender_node_id here is a
                // spoofing attempt to bypass sender verification.
                if payload.envelope.sender_node_id != [0u8; 32] {
                    return Err(DispatchResult::Violation(format!(
                        "DELIVERY_FORWARD: meta-E2E at hop=0 with non-zero sender_node_id {} from peer {}",
                        veil_util::hex_short(&payload.envelope.sender_node_id),
                        veil_util::hex_short(peer_id.as_bytes()),
                    )));
                }
            } else if &payload.envelope.sender_node_id != peer_id.as_bytes() {
                return Err(DispatchResult::Violation(format!(
                    "DELIVERY_FORWARD: sender_node_id {} does not match authenticated peer {} (relay_hops=0)",
                    veil_util::hex_short(&payload.envelope.sender_node_id),
                    veil_util::hex_short(peer_id.as_bytes()),
                )));
            }
        }

        // hop-limit check — drop frames that have already traversed
        // MAX_RELAY_HOPS relay nodes (terminates multi-node routing loops
        // that slip past content_id dedup or split-horizon).
        if payload.relay_hops >= veil_proto::budget::MAX_RELAY_HOPS {
            return Err(DispatchResult::Violation(format!(
                "DELIVERY_FORWARD: relay_hops {} >= MAX_RELAY_HOPS ({})",
                payload.relay_hops,
                veil_proto::budget::MAX_RELAY_HOPS,
            )));
        }
        let relay_hops_out = payload.relay_hops.saturating_add(1);

        // TTL check: drop envelope if it has expired or has an implausible timestamp.
        {
            use veil_proto::budget::MAX_CLOCK_SKEW_SECS;
            let now_secs = veil_util::unix_secs_now_u64();
            if payload.envelope.created_at > now_secs.saturating_add(MAX_CLOCK_SKEW_SECS) {
                return Err(DispatchResult::Violation(
                    "DELIVERY_FORWARD: created_at too far in the future".to_owned(),
                ));
            }
            let expires_at = payload
                .envelope
                .created_at
                .saturating_add(payload.envelope.ttl_secs as u64);
            if now_secs > expires_at {
                return Err(DispatchResult::NoResponse);
            }
        }

        // Forward dedup: enforce unique content_id on every relayed frame.
        // Zero content_id would allow unlimited replay — reject outright.
        {
            let content_id = payload.envelope.content_id;
            if content_id == [0u8; 32] {
                return Err(DispatchResult::Violation(
                    "DELIVERY_FORWARD: zero content_id not allowed on relay path".to_owned(),
                ));
            }
            if lock!(self.forward_seen_content).check_and_insert(content_id) {
                return Err(DispatchResult::NoResponse);
            }
        }

        Ok(relay_hops_out)
    }

    /// Collect and rank relay-hop candidates for `dst`, excluding `peer_id`
    /// (split-horizon) and `local_node_id` (self-loop guard), and filtering out
    /// peers that did not advertise `CAN_RELAY`.
    ///
    /// Returns three parallel vectors:
    /// - `candidates[i]` — hop `node_id`
    /// - `hop_attrs[i]` — routing attributes captured from RTT table
    /// - `hops_with_scores` — `(hop, score)` pairs from route_cache (used
    ///   downstream for ECMP flow-pinning hash input)
    ///
    /// All read locks are acquired and released inside the helper; no guards
    /// are held across the return.
    pub fn gather_relay_candidates(&self, dst: NodeIdBytes, peer_id: NodeId) -> RelayCandidates {
        // Acquire route_cache (Mutex), collect candidates with scores + hop counts.
        // Split-horizon: drop the sending peer and self.
        let mut raw: Vec<([u8; 32], u32, u8)> = rlock!(self.route_cache)
            .lookup_all_with_scores_and_hops(&dst)
            .into_iter()
            .filter(|(h, _, _)| h != peer_id.as_bytes() && *h != self.local_node_id)
            .collect();
        // Apply CAN_RELAY cap-flag filter under a separate RwLock read guard.
        // Peers with no entry (unknown caps) are allowed through conservatively.
        {
            let cap = self
                .crypto
                .peer_cap_flags
                .read()
                .unwrap_or_else(|p| p.into_inner());
            raw.retain(|(h, _, _)| {
                cap.get(h)
                    .map(|f| f & veil_proto::session::cap_flags::CAN_RELAY != 0)
                    .unwrap_or(true)
            });
        }
        let hops_with_scores: Vec<([u8; 32], u32)> = raw.iter().map(|(h, s, _)| (*h, *s)).collect();
        // Parallel vec: hop_count for each candidate (same order as raw).
        let raw_hop_counts: Vec<u8> = raw.iter().map(|(_, _, c)| *c).collect();
        let candidates: Vec<[u8; 32]> = raw.into_iter().map(|(h, _, _)| h).collect();
        if !candidates.is_empty()
            && let Some(m) = &self.metrics
        {
            m.inc_route_cache_hits();
        }
        // Per-hop routing attributes — one Vec instead of 5 HashMaps.
        // Index-based lookup avoids HashMap overhead for the typical
        // 1-5 candidate case. rtt_lock is acquired and released here so
        // the caller can then take peer_vivaldi without lock-order risk.
        let hop_attrs: Vec<HopAttrs> = {
            let rtt_lock = self.control_plane.rtt_table();
            let rtt = lock!(rtt_lock);
            // Use rtt_smoothed (EWMA-filtered) for routing decisions;
            // raw rtt_ms is retained in RttProbe for diagnostics.
            // Confidence decays linearly as the probe ages — fresh probes
            // get weight 1.0; stale probes get 0.0 (treated as unknown).
            candidates
                .iter()
                .enumerate()
                .map(|(i, hop)| {
                    let (
                        rtt_ms,
                        congestion,
                        confidence,
                        battery,
                        jitter_ms,
                        bandwidth_class,
                        relay_success_ema,
                        relay_attempts,
                    ) = rtt
                        .get_with_confidence(hop)
                        .map(|(p, conf)| {
                            (
                                p.rtt_smoothed,
                                p.congestion,
                                conf,
                                p.battery_level,
                                p.jitter_ms(),
                                p.bandwidth_class,
                                p.relay_success_ema,
                                p.relay_attempts,
                            )
                        })
                        .unwrap_or((u32::MAX, 0, 0.0, 0, 0.0, 0, 1.0, 0));
                    HopAttrs {
                        hop_count: raw_hop_counts[i],
                        rtt_ms,
                        congestion,
                        confidence,
                        battery,
                        jitter_ms,
                        bandwidth_class,
                        relay_success_ema,
                        relay_attempts,
                    }
                })
                .collect()
        }; // rtt_lock released here — before peer_vivaldi is acquired

        (candidates, hop_attrs, hops_with_scores)
    }

    /// Apply ECMP flow-pinning: identify the equal-cost group inside
    /// `candidates` (using raw cache scores from `hops_with_scores` and the
    /// dispatcher's `ecmp_score_band`), order it so the per-flow pinned hop is
    /// first, the rest of the group follows, and worse-cost candidates trail.
    /// Returns the group size; `0` means no pinning (no scores or singleton).
    ///
    /// Does **not** assume any incoming order: the ECMP members are gathered by
    /// identity and ordered DETERMINISTICALLY (by node_id) before the per-flow
    /// hash picks one, so the same `(sender, dst)` flow pins the same hop every
    /// time regardless of the upstream weighted-random shuffle — that is the
    /// point of flow-pinning (no per-frame path flapping / reordering). Worse-
    /// cost candidates keep their incoming (shuffled) order as fallback.
    ///
    /// `candidates` and `hop_attrs` are permuted **together** so callers that
    /// index them in parallel (e.g. RTT metrics on the chosen hop) stay
    /// consistent.
    pub fn apply_ecmp_pinning(
        &self,
        candidates: &mut [[u8; 32]],
        hop_attrs: &mut [HopAttrs],
        hops_with_scores: &[([u8; 32], u32)],
        sender_node_id: NodeIdBytes,
        dst: NodeIdBytes,
    ) -> usize {
        if hops_with_scores.is_empty() {
            return 0;
        }
        let best_score = hops_with_scores
            .iter()
            .map(|(_, s)| *s)
            .min()
            .unwrap_or(u32::MAX);
        let threshold = best_score as f64 * (1.0 + self.ecmp_score_band);
        let ecmp_set: std::collections::HashSet<[u8; 32]> = hops_with_scores
            .iter()
            .filter(|(_, s)| *s as f64 <= threshold)
            .map(|(h, _)| *h)
            .collect();

        // ECMP-member candidate indices, ordered DETERMINISTICALLY by node_id
        // (independent of the per-frame weighted shuffle) so flow-pinning is
        // stable across frames.
        let mut member_idx: Vec<usize> = (0..candidates.len())
            .filter(|&i| ecmp_set.contains(&candidates[i]))
            .collect();
        let group_len = member_idx.len();
        if group_len < 2 {
            return 0;
        }
        member_idx.sort_unstable_by(|&a, &b| candidates[a].cmp(&candidates[b]));

        // Flow-pinning hash: XOR sender and destination node-ids, mix with
        // FNV-1a → a stable per-flow index into the deterministic group order.
        let mut xored = [0u8; 32];
        for i in 0..32 {
            xored[i] = sender_node_id[i] ^ dst[i];
        }
        const FNV_OFFSET: u64 = 14695981039346656037;
        const FNV_PRIME: u64 = 1099511628211;
        let hash = xored.iter().fold(FNV_OFFSET, |acc, &b| {
            acc.wrapping_mul(FNV_PRIME) ^ (b as u64)
        });
        let pin_idx = (hash as usize) % group_len;
        member_idx.rotate_left(pin_idx);

        // Final order: pinned ECMP group first (deterministic), then the
        // remaining worse-cost candidates in their incoming order. Permute both
        // parallel arrays the same way.
        let order: Vec<usize> = member_idx
            .iter()
            .copied()
            .chain((0..candidates.len()).filter(|&i| !ecmp_set.contains(&candidates[i])))
            .collect();
        let new_candidates: Vec<[u8; 32]> = order.iter().map(|&i| candidates[i]).collect();
        let new_attrs: Vec<HopAttrs> = order.iter().map(|&i| hop_attrs[i]).collect();
        candidates.copy_from_slice(&new_candidates);
        hop_attrs.copy_from_slice(&new_attrs);
        group_len
    }

    /// Score candidates via the weighted-random Efraimidis-Spirakis
    /// reservoir-sampling shuffle so multiple senders don't synchronise on
    /// the same "best" hop under load.
    ///
    /// `effective_score = (rtt_ms + 1 + jitter_penalty) × (1 + 2×cong/255)
    ///                    × (1 + 0.1×hop_count) × (1 + battery_penalty)
    ///                    × (1 + bw_penalty) × relay_reputation_penalty`
    /// `weight = confidence / effective_score`
    ///
    /// Stale probes (confidence → 0) sort last; otherwise candidates are
    /// permuted with probability proportional to their weight.  The mutation
    /// is in-place — `candidates` and `hop_attrs` are reshuffled together
    /// preserving their parallel indexing.
    pub fn score_and_shuffle_candidates(
        &self,
        candidates: &mut Vec<[u8; 32]>,
        hop_attrs: &mut Vec<HopAttrs>,
        traffic_class: u8,
    ) {
        let local_viv = self.local_vivaldi.as_ref().map(|v| lock!(v).clone());
        let peer_viv = rlock!(self.peer_vivaldi);

        // Capture config snapshots so the inner closures don't borrow `self`.
        let bat_thresh_low = self.battery_threshold_low;
        let bat_thresh_medium = self.battery_threshold_medium;
        let bat_penalty_low = self.battery_penalty_low;
        let bat_penalty_medium = self.battery_penalty_medium;
        let jitter_weight_base = self.jitter_penalty_weight;
        let jitter_thresh = self.jitter_threshold_ms as f64;
        let narrow_bw_penalty = self.narrow_bandwidth_bulk_penalty;
        let is_realtime = traffic_class == veil_proto::header::TrafficClass::RealTime as u8;
        let is_bulk_or_bg = traffic_class == veil_proto::header::TrafficClass::Bulk as u8
            || traffic_class == veil_proto::header::TrafficClass::Background as u8;
        let narrow_class = veil_routing::probe::BandwidthClass::Narrow as u8;
        let relay_rep_min_attempts = self.relay_reputation_min_attempts;
        let relay_rep_threshold = self.relay_reputation_threshold;
        let relay_rep_penalty = self.relay_reputation_penalty;

        let effective_score = |i: usize, hop_attrs: &[HopAttrs], candidates: &[[u8; 32]]| -> f64 {
            let a = &hop_attrs[i];
            let hop = &candidates[i];
            let rtt = if a.rtt_ms != u32::MAX {
                a.rtt_ms as f64
            } else if let (Some(lv), Some((rv, _))) = (&local_viv, peer_viv.get(hop)) {
                lv.distance_estimate(rv)
            } else {
                u32::MAX as f64
            };
            let cong_norm = a.congestion as f64 / 255.0;
            let hops = a.hop_count as f64;
            let bat_penalty = if a.battery == 0 {
                0.0 // AC power or unknown — no penalty
            } else if a.battery <= bat_thresh_low {
                bat_penalty_low
            } else if a.battery <= bat_thresh_medium {
                bat_penalty_medium
            } else {
                0.0
            };
            let jitter_weight = if is_realtime {
                jitter_weight_base * 2.0
            } else {
                jitter_weight_base
            };
            let jitter_penalty = jitter_weight * (a.jitter_ms - jitter_thresh).max(0.0);
            let bw_penalty = if is_bulk_or_bg && a.bandwidth_class == narrow_class {
                narrow_bw_penalty
            } else {
                0.0
            };
            let rep_penalty = if a.relay_attempts >= relay_rep_min_attempts
                && a.relay_success_ema < relay_rep_threshold
            {
                relay_rep_penalty
            } else {
                1.0
            };
            (rtt + 1.0 + jitter_penalty)
                * (1.0 + 2.0 * cong_norm)
                * (1.0 + 0.1 * hops)
                * (1.0 + bat_penalty)
                * (1.0 + bw_penalty)
                * rep_penalty
        };

        if candidates.len() > 1 {
            // Efraimidis-Spirakis weighted reservoir sample: each candidate
            // gets key k = u^(1/w), sort descending → bias to high-weight
            // entries without deterministically picking the best one.
            use rand_core::{OsRng, RngCore};
            let mut keyed: Vec<(f64, usize)> = (0..candidates.len())
                .map(|i| {
                    let conf = hop_attrs[i].confidence;
                    let weight = if conf <= 0.0 {
                        0.0
                    } else {
                        conf / effective_score(i, hop_attrs, candidates)
                    };
                    let key = if weight <= 0.0 {
                        0.0 // stale / unknown → always sort last
                    } else {
                        let u = (OsRng.next_u64() as f64 + 1.0) / (u64::MAX as f64 + 1.0);
                        u.powf(1.0 / weight)
                    };
                    (key, i)
                })
                .collect();
            keyed.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
            *hop_attrs = keyed.iter().map(|(_, src)| hop_attrs[*src]).collect();
            *candidates = keyed.iter().map(|(_, src)| candidates[*src]).collect();
        }
        // Single candidate: nothing to shuffle.
    }

    /// Gateway fallback: route a forward through an internet-capable gateway
    /// peer when the direct/route_cache path failed. Returns `true` if the
    /// frame was successfully queued on a gateway session.
    ///
    /// Selection precedence (matches the inline policy that used to live in
    /// `relay_forward`):
    ///   1. `prefer_internet_gateway` → always pick best internet GW.
    ///   2. `exit_diversification` → weighted-random over top-K.
    ///   3. default → deterministic best.
    ///
    /// split-horizon: drops the gateway candidate if it equals the recipient
    /// (`fwd_dst`) or the upstream peer (`peer_id`).
    pub fn try_forward_via_gateway(
        &self,
        payload: &ForwardPayload,
        peer_id: NodeId,
        fwd_dst: NodeIdBytes,
        relay_hops_out: u8,
    ) -> bool {
        let (Some(gl), Some(reg)) = (&self.gateway_list, &self.session_tx_registry) else {
            return false;
        };
        let gw_node_id: Option<[u8; 32]> = {
            let active: std::collections::HashSet<[u8; 32]> = {
                let r = rlock!(reg);
                r.active_node_ids()
            };
            let gl_guard = lock!(gl);
            if self.prefer_internet_gateway {
                gl_guard
                    .preferred_internet_gateway(&active)
                    .map(|e| e.node_id)
            } else if self.exit_diversification {
                let rand_u64 = rand_seed_for_pick(payload.envelope.trace_id);
                gl_guard
                    .pick_weighted(&active, self.exit_diversification_top_k as usize, rand_u64)
                    .map(|e| e.node_id)
            } else {
                gl_guard.preferred(&active).map(|e| e.node_id)
            }
        };
        let Some(gw) = gw_node_id else {
            return false;
        };
        if gw == fwd_dst || &gw == peer_id.as_bytes() {
            return false;
        }
        let envelope_bytes = payload.envelope.encode();
        let gw_suffix: Vec<u8> = {
            let mut s = Vec::with_capacity(9);
            s.extend_from_slice(&payload.envelope.trace_id.to_be_bytes());
            s.push(relay_hops_out);
            s
        };
        let body_len = 32 + envelope_bytes.len() + gw_suffix.len();
        let mut fwd_hdr = veil_proto::header::FrameHeader::new(
            veil_proto::family::FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        );
        fwd_hdr.body_len = body_len as u32;
        let mut frame = Vec::with_capacity(veil_proto::header::HEADER_SIZE + body_len);
        frame.extend_from_slice(&veil_proto::codec::encode_header(&fwd_hdr));
        frame.extend_from_slice(&gw);
        frame.extend_from_slice(&envelope_bytes);
        frame.extend_from_slice(&gw_suffix);
        rlock!(reg).send_to(&gw, TrafficClass::Interactive as u8, frame)
    }

    /// DHT recursive-relay fallback: when neither route_cache nor a gateway
    /// can reach the recipient, find the DHT-closest nodes to `fwd_dst` and
    /// wrap the forward in a `RecursiveRelayPayload` toward the first one
    /// that has a live session. Returns `true` if a recursive-relay frame
    /// was emitted (regardless of whether the underlying `send_to` succeeded
    /// — failure is observed via the `send_to_failed` metric).
    pub fn try_recursive_relay_via_dht(
        &self,
        payload: &ForwardPayload,
        peer_id: NodeId,
        fwd_dst: NodeIdBytes,
    ) -> bool {
        use veil_proto::delivery::RecursiveRelayPayload;
        let closest = self.dht.find_closest_nodes(&fwd_dst, 3);
        let Some(reg) = &self.session_tx_registry else {
            return false;
        };
        let reg_guard = rlock!(reg);
        for next in &closest {
            if next == peer_id.as_bytes() || *next == self.local_node_id {
                continue;
            }
            if reg_guard.get_sender(next).is_some() {
                let qid = self
                    .announce_seq
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let rr = RecursiveRelayPayload {
                    dst_node_id: fwd_dst,
                    originator_pseudonym: RecursiveRelayPayload::make_pseudonym(
                        &self.local_node_id,
                        qid,
                    ),
                    query_id: qid,
                    hop_count: veil_proto::budget::MAX_RECURSIVE_RELAY_HOPS,
                    payload: payload.encode(),
                };
                let rr_bytes = rr.encode();
                let mut rr_hdr = veil_proto::header::FrameHeader::new(
                    veil_proto::family::FrameFamily::Delivery as u8,
                    veil_proto::family::DeliveryMsg::RecursiveRelay as u16,
                );
                rr_hdr.body_len = rr_bytes.len() as u32;
                let frame = veil_proto::codec::encode_frame(&rr_hdr, &rr_bytes);
                drop(reg_guard);
                let sent =
                    rlock!(reg).send_to(next, veil_proto::header::priority::INTERACTIVE, frame);
                if let Some(m) = &self.metrics {
                    if !sent {
                        m.inc_send_to_failed();
                    }
                    m.inc_recursive_relay_initiated();
                }
                return true;
            }
        }
        false
    }

    pub fn relay_forward(
        &self,
        payload: ForwardPayload,
        peer_id: NodeId,
        traffic_class: u8,
    ) -> DispatchResult {
        let relay_hops_out = match self.check_relay_preconditions(&payload, peer_id) {
            Ok(hops) => hops,
            Err(result) => return result,
        };

        // sovereign fast-path. If a live, authenticated
        // session exists to the recipient's identity, forward directly
        // via that session — a 1-hop authenticated session is always
        // preferable to a multi-hop route_cache relay. Falls through
        // to the scored route_cache path when no sovereign session is
        // available (legacy peer, identity offline, or no registry
        // wired in this build).
        if self.try_sovereign_direct_forward(&payload, peer_id, traffic_class, relay_hops_out) {
            return DispatchResult::NoResponse;
        }

        // Intermediate relay — forward the envelope intact so that
        // sender_node_id is preserved through the full relay chain.
        let fwd_dst = payload.envelope.recipient_node_id();
        let sender_node_id = payload.envelope.sender_node_id();
        if let Some(reg) = &self.session_tx_registry {
            let dst = fwd_dst;

            // Collect and rank candidates BEFORE acquiring reg_guard.
            // All read-only lookups (route_cache, rtt) happen inside the helper
            // so reg_guard is held only for the minimal `send_to` window,
            // avoiding nested lock-ordering hazards. peer_vivaldi is acquired
            // separately inside `score_and_shuffle_candidates` for scoring.
            let (mut candidates, mut hop_attrs, hops_with_scores) =
                self.gather_relay_candidates(dst, peer_id);
            self.score_and_shuffle_candidates(&mut candidates, &mut hop_attrs, traffic_class);

            // ECMP flow pinning — identify the equal-cost group and rotate the
            // candidate prefix so the flow-pinned path comes first. Provides
            // deterministic per-flow path selection while leaving the order
            // outside the group unchanged.
            let ecmp_group_len = self.apply_ecmp_pinning(
                &mut candidates,
                &mut hop_attrs,
                &hops_with_scores,
                sender_node_id,
                dst,
            );

            // Pre-encode the envelope once; each hop attempt only differs in the
            // 32-byte `next_hop_node_id` prefix, so we avoid re-serialising the
            // (potentially large) envelope body for every candidate.
            //
            // 191/415.7: build the trailing suffix (trace_id + relay_hops)
            // once. tightened `ForwardPayload::decode` to require the
            // fixed 9-byte suffix unconditionally, so we must always emit both
            // fields — including `trace_id == 0` — or the receiver will reject
            // the frame with "bad Forward: buffer too short".
            let envelope_bytes = payload.envelope.encode();
            let suffix: Vec<u8> = {
                let mut s = Vec::with_capacity(9);
                s.extend_from_slice(&payload.envelope.trace_id.to_be_bytes());
                s.push(relay_hops_out);
                s
            };
            let body_len = 32 + envelope_bytes.len() + suffix.len();
            let total_wire_len = veil_proto::header::HEADER_SIZE + body_len;
            let make_fwd_frame = |hop: NodeIdBytes| -> Vec<u8> {
                let mut fwd_hdr =
                    FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
                fwd_hdr.body_len = body_len as u32;
                // single allocation sized for the whole wire frame.
                // The previous `encode_header(...).to_vec` pattern allocated
                // HEADER_SIZE bytes, then extend_from_slice would reallocate
                // once `body_len` exceeded the initial capacity — up to 2-3
                // allocations per frame. With_capacity + extend runs in one.
                let mut frame = Vec::with_capacity(total_wire_len);
                frame.extend_from_slice(&encode_header(&fwd_hdr));
                frame.extend_from_slice(&hop);
                frame.extend_from_slice(&envelope_bytes);
                frame.extend_from_slice(&suffix);
                frame
            };

            // ── Acquire reg_guard only for the send window ────────────────────
            let reg_guard = rlock!(reg);

            // Try direct session to recipient.
            let fwd_frame = make_fwd_frame(dst);
            if reg_guard.send_to(&dst, TrafficClass::Interactive as u8, fwd_frame) {
                return DispatchResult::NoResponse;
            }

            // Collect failed hops to invalidate in RouteCache after releasing reg_guard.
            // We must not hold reg_guard while locking route_cache (lock ordering).
            let mut failed_hops: Vec<[u8; 32]> = Vec::new();

            // ── multi-path delivery ──────────────────────────────────
            // When enabled and the frame priority is latency-sensitive (≤ min_priority)
            // send on the top-N candidates simultaneously. The receiver deduplicates
            // via `ForwardSeenSet` (content_id check) so duplicates are harmless.
            if self.multi_path_enabled
                && traffic_class <= self.multi_path_min_priority
                && candidates.len() >= 2
            {
                let n = (self.max_parallel_paths as usize).min(candidates.len());
                let mut any_sent = false;
                let mut mp_sent: u64 = 0;
                for &hop in candidates.iter().take(n) {
                    let fwd_frame = make_fwd_frame(hop);
                    if reg_guard.send_to(&hop, traffic_class, fwd_frame) {
                        any_sent = true;
                        mp_sent += 1;
                    } else {
                        failed_hops.push(hop);
                    }
                }
                if any_sent {
                    drop(reg_guard);
                    if let Some(m) = &self.metrics {
                        m.inc_multi_path_sends(mp_sent);
                    }
                    // Record relay attempt for each hop we successfully sent to.
                    {
                        let rtt_lock = self.control_plane.rtt_table();
                        let mut rtt = lock!(rtt_lock);
                        for &hop in candidates.iter().take(n) {
                            if !failed_hops.contains(&hop) {
                                rtt.record_relay_attempt(hop);
                            }
                        }
                    }
                    if !failed_hops.is_empty() {
                        let mut rc = wlock!(self.route_cache);
                        for hop in &failed_hops {
                            rc.invalidate_hop(&dst, hop);
                        }
                    }
                    return DispatchResult::NoResponse;
                }
                // All multi-path sends failed — fall through to single-hop logic.
            }

            // ── redundant send ────────────────────────────────────
            // When `redundant_send` is enabled and the ECMP group has ≥2 members
            // send the frame on ALL ECMP paths simultaneously. This trades
            // bandwidth for improved delivery reliability.
            if self.redundant_send && ecmp_group_len >= 2 {
                let mut any_sent = false;
                for &hop in candidates.iter().take(ecmp_group_len) {
                    let fwd_frame = make_fwd_frame(hop);
                    match reg_guard.send_to(&hop, TrafficClass::Interactive as u8, fwd_frame) {
                        true => {
                            any_sent = true;
                        }
                        false => {
                            failed_hops.push(hop);
                        }
                    }
                }
                if any_sent {
                    drop(reg_guard);
                    if !failed_hops.is_empty() {
                        let mut rc = wlock!(self.route_cache);
                        for hop in &failed_hops {
                            rc.invalidate_hop(&dst, hop);
                        }
                    }
                    return DispatchResult::NoResponse;
                }
                // All ECMP paths failed — fall through to the linear scan below
                // which will also attempt any non-ECMP candidates.
            }

            // Save the successfully chosen hop so we can record the relay attempt
            // AFTER releasing reg_guard (lock ordering: rtt_table must not be
            // acquired while session_tx_registry is held).
            let mut sent_hop: Option<[u8; 32]> = None;
            for (idx, hop) in candidates.iter().enumerate() {
                let hop = *hop;
                let fwd_frame = make_fwd_frame(hop);
                if reg_guard.send_to(&hop, traffic_class, fwd_frame) {
                    // record RTT of the selected route (pre-snapshotted above).
                    let rtt_ms = hop_attrs[idx].rtt_ms;
                    if let Some(m) = &self.metrics
                        && rtt_ms != u32::MAX
                    {
                        m.record_route_selection_rtt(rtt_ms);
                    }
                    // log trace info for sampled frames.
                    let trace_id = payload.envelope.trace_id;
                    if trace_id != 0 {
                        let rtt = if rtt_ms != u32::MAX { rtt_ms } else { 0 };
                        let ts_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        log::debug!(
                            "delivery.trace trace_id={:#018x} from_peer={} to_peer={} hop_rtt_ms={} timestamp_ms={}",
                            trace_id,
                            veil_util::hex_str(peer_id.as_bytes()),
                            veil_util::hex_str(&hop),
                            rtt,
                            ts_ms,
                        );
                        lock!(self.trace_buffer).push(crate::TraceHopRecord {
                            trace_id,
                            from_peer: *peer_id.as_bytes(),
                            to_peer: hop,
                            hop_rtt_ms: rtt,
                            timestamp_ms: ts_ms,
                        });
                    }
                    sent_hop = Some(hop);
                    break;
                } else {
                    // channel full or closed — mark for immediate invalidation.
                    failed_hops.push(hop);
                }
            }
            drop(reg_guard);

            if let Some(relay_hop) = sent_hop {
                // record relay attempt for reputation scoring.
                // Acquired after reg_guard is released to respect lock ordering.
                lock!(self.control_plane.rtt_table()).record_relay_attempt(relay_hop);
                // Invalidate any candidates that failed before we found a working hop.
                if !failed_hops.is_empty() {
                    let mut rc = wlock!(self.route_cache);
                    for hop in &failed_hops {
                        rc.invalidate_hop(&dst, hop);
                    }
                }
                return DispatchResult::NoResponse;
            }

            // invalidate unreachable hops immediately so subsequent
            // packets don't keep trying a dead path until RouteCache TTL expires.
            if !failed_hops.is_empty() {
                let mut rc = wlock!(self.route_cache);
                for hop in &failed_hops {
                    rc.invalidate_hop(&dst, hop);
                }
            }
        }

        // Before declaring a route-miss, try forwarding via a
        // Gateway that has internet access. This handles the case where the
        // destination is a global-veil node that is not in the local route
        // cache but reachable through any connected gateway.
        if self.try_forward_via_gateway(&payload, peer_id, fwd_dst, relay_hops_out) {
            return DispatchResult::NoResponse;
        }

        // Route miss — trigger on-demand discovery so the message can
        // be re-forwarded once a route is learned.

        {
            // Clone the sender while holding the lock, then release the lock
            // before calling try_send so we don't hold a Mutex across a channel
            // operation. mpsc::Sender::clone is O(1) (Arc increment).
            let tx_opt = lock!(self.route_miss_tx).as_ref().cloned();
            if let Some(tx) = tx_opt {
                // try_send — route-miss signals are best-effort;
                // drop silently when the channel is full (consumer is busy).
                // pair `fwd_dst` with `traffic_class`
                // so the fallback's per-priority timeout multiplier picks
                // the right budget (INTERACTIVE = fast-fail
                // BACKGROUND = tolerant).
                let _ = tx.try_send((fwd_dst, traffic_class));
            }
        }
        if let Some(m) = &self.metrics {
            m.inc_route_miss();
        }

        // attempt DHT-routed recursive relay before mailbox fallback.
        if self.try_recursive_relay_via_dht(&payload, peer_id, fwd_dst) {
            return DispatchResult::NoResponse;
        }

        // mailbox subsystem removed. When no relay path exists
        // and DHT recursive relay also fails, the frame is silently dropped.
        // Reliable async delivery is now an application-layer concern (e.g.
        // a future `veil-mailbox` crate built on top of this transport).
        DispatchResult::NoResponse
    }

    /// Build and fire a `DeliveryStatus(DELIVERED)` frame toward `sender`.
    ///
    /// Best-effort: if we cannot route to the sender right now, the sender
    /// will time out and retransmit; the terminal-delivery `content_id` dedup
    /// in `deliver_forward_locally` (forward_seen_set) drops the duplicate at
    /// the recipient, so a retransmit re-delivers at most once per TTL window.
    fn send_delivery_ack(&self, sender: [u8; 32], content_id: [u8; 32], ack_key: [u8; 32]) {
        use veil_proto::{
            delivery::{DeliveryStatusPayload, delivery_status},
            family::{DeliveryMsg, FrameFamily},
            header::FrameHeader,
        };

        // C-09: MAC content_id with the per-message ACK key so the originator
        // can confirm this DELIVERED came from the actual recipient, not an
        // on-path relay (only the recipient + originator can derive the key).
        // A zero ack_key (meta-E2E / non-E2E) yields a MAC a relay could
        // reproduce, so the originator credits no reputation for those.
        let mac = *blake3::keyed_hash(&ack_key, &content_id).as_bytes();
        let status_payload = DeliveryStatusPayload {
            content_id,
            status: delivery_status::DELIVERED,
            mac,
        };
        let body = status_payload.encode();

        let mut hdr = FrameHeader::new(
            FrameFamily::Delivery as u8,
            DeliveryMsg::DeliveryStatus as u16,
        );
        hdr.body_len = body.len() as u32;
        // single-allocation frame assembly.
        let frame = veil_proto::codec::encode_frame(&hdr, &body);

        if let Some(reg) = &self.session_tx_registry {
            let guard = rlock!(reg);
            guard.send_to(&sender, veil_proto::header::priority::INTERACTIVE, frame);
        }
    }

    /// 178/190/200.A path: DELIVERY_FORWARD — either terminally
    /// deliver the envelope to the local app registry (after optional E2E
    /// decryption) or relay toward the recipient via `relay_forward`.
    fn handle_delivery_forward(
        &self,
        header: &FrameHeader,
        body: &[u8],
        peer_id: NodeId,
    ) -> DispatchResult {
        // cheap TTL pre-check before full decode — drops stale
        // envelopes without the 1 MiB envelope-payload clone that `decode`
        // would perform.
        if self.forward_ttl_already_expired(body) {
            return DispatchResult::NoResponse;
        }

        let payload = match ForwardPayload::decode(body) {
            Ok(p) => p,
            Err(e) => return DispatchResult::Violation(format!("bad Forward: {e}")),
        };

        // Reject envelopes with unset node ids (meta-E2E and chunk-envelope
        // wrappers are the exceptions — an anonymous chunked send carries a
        // zero sender on each chunk and a meta-E2E payload only after reassembly).
        if payload.envelope.sender_node_id == [0u8; 32]
            && payload.envelope.payload.first() != Some(&veil_proto::META_E2E_MARKER)
            && payload.envelope.payload.first()
                != Some(&veil_proto::delivery::CHUNKED_ENVELOPE_MARKER)
        {
            return DispatchResult::Violation("Forward: zero sender_node_id".into());
        }
        if payload.envelope.recipient_node_id() == [0u8; 32] {
            return DispatchResult::Violation("Forward: zero recipient_node_id".into());
        }

        if payload.envelope.recipient_node_id() == self.local_node_id {
            self.deliver_forward_locally(payload, peer_id);
            return DispatchResult::NoResponse;
        }

        self.relay_forward(payload, peer_id, header.priority())
    }

    /// Peek the envelope's fixed-offset `created_at`+`ttl_secs` without
    /// allocating and return `true` iff it is already expired. Saves a full
    /// envelope-payload memcpy when a flood of stale frames arrives.
    fn forward_ttl_already_expired(&self, body: &[u8]) -> bool {
        use veil_proto::delivery::{DELIVERY_FLAG_REQUIRE_ACK, OFFSET_CREATED_AT, OFFSET_TTL_SECS};
        // ForwardPayload = next_hop_node_id(32) || envelope, so the envelope's
        // fixed fields live at body[32 + OFFSET_*].
        const HDR: usize = 32;
        if body.len() < HDR + OFFSET_TTL_SECS + 4 {
            return false;
        }
        let Ok(created) =
            <[u8; 8]>::try_from(&body[HDR + OFFSET_CREATED_AT..HDR + OFFSET_CREATED_AT + 8])
        else {
            return false;
        };
        let Ok(ttl_wire) =
            <[u8; 4]>::try_from(&body[HDR + OFFSET_TTL_SECS..HDR + OFFSET_TTL_SECS + 4])
        else {
            return false;
        };
        let created_at = u64::from_be_bytes(created);
        let ttl_secs = u32::from_be_bytes(ttl_wire) & !DELIVERY_FLAG_REQUIRE_ACK;
        let now = veil_util::unix_secs_now_u64();
        now > created_at.saturating_add(ttl_secs as u64)
    }

    /// Terminal delivery: decrypt E2E/meta-E2E payload (if marked), cache the
    /// reverse route, dispatch to the local app registry, and emit an ACK
    /// back to the original sender when `require_ack` is set.
    fn deliver_forward_locally(&self, payload: ForwardPayload, peer_id: NodeId) {
        self.terminal_deliver(payload.envelope, peer_id);
    }

    /// Terminal delivery of a `DeliveryEnvelope` addressed to this node. Handles
    /// (a) relay-chunked envelopes — accumulated in the reassembler until the
    /// whole message arrives, then re-entered here as the reconstructed original
    /// envelope — and (b) ordinary envelopes — deduped, E2E-decrypted, delivered
    /// to the addressed app, and ACKed. Called both from `deliver_forward_locally`
    /// (a Forward addressed to us) and from chunk reassembly on completion.
    fn terminal_deliver(&self, envelope: DeliveryEnvelope, peer_id: NodeId) {
        // Relay-chunked piece? Divert to reassembly. Only the reassembled
        // ORIGINAL envelope (payload no longer chunk-marked) proceeds below, so
        // app_id/endpoint_id/E2E/ACK semantics are preserved instead of being
        // flattened into an epidemic broadcast.
        if envelope.payload.first() == Some(&veil_proto::delivery::CHUNKED_ENVELOPE_MARKER) {
            self.handle_chunk_envelope(envelope, peer_id);
            return;
        }

        // Terminal replay guard: the same envelope can arrive here twice (a
        // captured-frame replay, or a multi-path delivery race). The relay
        // path already dedups on `content_id` (see `check_relay_preconditions`);
        // mirror it on the terminal path so the app sees each `content_id` at
        // most once within the TTL window. A zero `content_id` is an unset
        // sentinel — never dedup it (that would collapse every zero-id frame
        // into one); just deliver.
        let content_id = envelope.content_id;
        if content_id != [0u8; 32] && lock!(self.forward_seen_content).check_and_insert(content_id)
        {
            // Duplicate terminal arrival (audit cycle-8 H8): a retransmit because
            // our original DELIVERED ACK was lost (the retransmit window 15 s is
            // inside the 60 s dedup window), or a replay. The app already saw
            // this content_id, so do NOT re-deliver — but if the original
            // required an ACK, re-emit it from the replay cache so the
            // originator can recover a lost ACK (no re-decrypt; cheap +
            // replay-safe). Without this the originator burns all retransmits and
            // reports AppSendFailed for a message that WAS delivered, and the
            // loss_tracker is poisoned against a healthy hop.
            if let Some((sender, ack_key)) =
                lock!(self.terminal_ack_replay).get(&content_id).copied()
            {
                self.send_delivery_ack(sender, content_id, ack_key);
            }
            return;
        }
        let first_byte = envelope.payload.first().copied();

        // Resolve the decapsulation-key seed once (used by both E2E branches).
        // prefer per-session ephemeral DK seed over long-term seed.
        let dk_seed: [u8; veil_e2e::DK_SEED_BYTES] = {
            // Phase 6 slice 6h: per-session DK seeds are
            // SensitiveBytesN<64> not Copy, so dereference the `.as_array()`
            // view to get a `[u8; 64]` value off the mlocked storage.  The
            // resulting stack copy lives only through the ml-kem decap call
            // below — short enough that swap exposure is bounded to single-
            // digit microseconds under normal load.
            let map = lock!(self.crypto.per_session_mlkem_dk);
            map.get(&envelope.sender_node_id)
                .map(|s| *s.as_array())
                .unwrap_or_else(|| *self.crypto.mlkem_dk_seed.as_array())
        };

        // Fields that may be overridden by meta-E2E decryption.
        let mut deliver_sender_node_id = envelope.sender_node_id;
        let mut deliver_src_app_id = envelope.src_app_id;
        let mut deliver_app_id = envelope.app_id;
        let mut deliver_endpoint_id = envelope.endpoint_id;

        let Some((app_payload, ack_key)) = self.decrypt_forward_payload(
            first_byte,
            &dk_seed,
            &envelope,
            &mut deliver_sender_node_id,
            &mut deliver_src_app_id,
            &mut deliver_app_id,
            &mut deliver_endpoint_id,
        ) else {
            return; // decrypt failed — metric already incremented.
        };

        // Cache reverse route: sender → peer_id (direct hop). ONLY for an
        // AUTHENTICATED sender. The meta-E2E (anonymous) path carries an inner
        // sender_node_id that is encrypted but NOT authenticated (ML-KEM gives
        // confidentiality, not origin proof — anyone who knows our published EK
        // can claim any sender). Caching it would let such a peer poison the
        // route cache with a bogus node_id→peer mapping, redirecting our later
        // traffic for that node_id. (audit cycle-4 M2.)
        let is_meta_e2e = first_byte == Some(veil_proto::META_E2E_MARKER);
        if !is_meta_e2e
            && deliver_sender_node_id != self.local_node_id
            && &deliver_sender_node_id != peer_id.as_bytes()
            && deliver_sender_node_id != [0u8; 32]
        {
            wlock!(self.route_cache).insert(deliver_sender_node_id, *peer_id.as_bytes(), 1_000, 1);
        }

        self.app_registry.route_ipc_deliver(
            deliver_sender_node_id,
            deliver_src_app_id,
            deliver_app_id,
            deliver_endpoint_id,
            veil_bufpool::pooled_shared_from_vec(app_payload),
        );

        // send E2E delivery ACK back to the original sender, MAC'd with the
        // per-message ACK key (C-09) so a relay cannot forge it.
        if envelope.require_ack {
            self.send_delivery_ack(deliver_sender_node_id, envelope.content_id, ack_key);
            // audit cycle-8 H8: cache (sender, ack_key) keyed by content_id so a
            // retransmit (sent when this ACK is lost) can be re-ACK'd from the
            // duplicate path above without re-decrypting the payload.
            if envelope.content_id != [0u8; 32] {
                lock!(self.terminal_ack_replay)
                    .insert(envelope.content_id, (deliver_sender_node_id, ack_key));
            }
        }
    }

    /// Accumulate one relay-chunked envelope. Each chunk is an ordinary Forward
    /// envelope whose payload is a [`ChunkedEnvelopePayload`]; the bounded
    /// reassembler joins them by `transfer_id`, and on completion we re-enter
    /// [`Self::terminal_deliver`] with the reconstructed ORIGINAL envelope so the
    /// standard E2E-decrypt + addressed-delivery + ACK path runs unchanged.
    fn handle_chunk_envelope(&self, envelope: DeliveryEnvelope, peer_id: NodeId) {
        use crate::envelope_chunks::AddChunkResult;
        use veil_proto::delivery::ChunkedEnvelopePayload;
        let chunk = match ChunkedEnvelopePayload::decode(&envelope.payload) {
            Ok(c) => c,
            Err(e) => {
                self.logger
                    .warn("chunk.bad_envelope", format!("decode failed: {e}"));
                return;
            }
        };
        let now = veil_util::unix_secs_now_u64();
        let result = lock!(self.chunk_reassembler).add(&envelope, chunk, now);
        match result {
            AddChunkResult::Complete(reassembled) => {
                if let Some(m) = &self.metrics {
                    m.inc_chunks_reassembled();
                }
                self.logger.info(
                    "chunk.reassembly_complete",
                    format!(
                        "content_id={} size={}",
                        veil_util::hex_short(&reassembled.content_id),
                        reassembled.payload.len(),
                    ),
                );
                // Re-enter terminal delivery; the reassembled payload is no
                // longer chunk-marked, so it takes the normal decrypt+deliver path.
                self.terminal_deliver(*reassembled, peer_id);
            }
            AddChunkResult::Pending => {}
            AddChunkResult::Rejected(reason) => {
                // LIMIT-prefixed so any quota/limit drop is greppable in debug
                // (per-sender / global reassembly quotas, metadata mismatch, …).
                self.logger.warn(
                    "chunk.rejected",
                    &format!("LIMIT chunk_reassembly: {reason}"),
                );
            }
        }
    }

    /// Decrypt the forward payload based on its leading marker byte. Returns
    /// `None` on decrypt failure (metric is incremented internally). For
    /// meta-E2E, updates the sender/app/endpoint out-params with the values
    /// recovered from the ciphertext.
    #[allow(clippy::too_many_arguments)]
    fn decrypt_forward_payload(
        &self,
        first_byte: Option<u8>,
        dk_seed: &[u8; veil_e2e::DK_SEED_BYTES],
        envelope: &DeliveryEnvelope,
        deliver_sender_node_id: &mut [u8; 32],
        deliver_src_app_id: &mut [u8; 32],
        deliver_app_id: &mut [u8; 32],
        deliver_endpoint_id: &mut u32,
    ) -> Option<(Vec<u8>, [u8; 32])> {
        // META_E2E_MARKER (0xE3): onion — sender identity is inside ciphertext.
        if first_byte == Some(veil_proto::META_E2E_MARKER) {
            match veil_e2e::meta_decrypt(dk_seed, &self.local_node_id, &envelope.payload) {
                Ok((snd, src_app, app, eid, plain)) => {
                    *deliver_sender_node_id = snd;
                    *deliver_src_app_id = src_app;
                    *deliver_app_id = app;
                    *deliver_endpoint_id = eid;
                    // meta-E2E: no ACK key wired on this path yet — DELIVERED
                    // for an anonymous message clears the pending entry but
                    // earns no reputation (C-09 scoping; full meta-E2E ACK auth
                    // is a follow-up).
                    return Some((plain, [0u8; 32]));
                }
                Err(_) => {
                    if let Some(m) = &self.metrics {
                        m.inc_decrypt_failures();
                    }
                    return None;
                }
            }
        }
        // E2E_MARKER (0xE2): standard E2E — sender in outer envelope.
        if first_byte == Some(veil_proto::E2E_MARKER) {
            let envelope_bytes = &envelope.payload[1..];
            let e2e_env = match veil_proto::E2eEnvelope::decode(envelope_bytes) {
                Ok(e) => e,
                Err(_) => {
                    if let Some(m) = &self.metrics {
                        m.inc_decrypt_failures();
                    }
                    return None;
                }
            };
            return match veil_e2e::decrypt_with_ack(
                dk_seed,
                &envelope.sender_node_id,
                &self.local_node_id,
                &e2e_env,
            ) {
                // C-09: the per-message ACK key flows out so the recipient can
                // MAC `content_id` in the DELIVERED frame.
                Ok((plain, ack_key)) => Some((plain, ack_key)),
                Err(_) => {
                    // Drop — decrypt failure is not a peer protocol violation
                    // (e.g. key-rotation race), but count it so operators can
                    // detect misconfiguration or active key-mismatch attacks.
                    if let Some(m) = &self.metrics {
                        m.inc_decrypt_failures();
                    }
                    None
                }
            };
        }
        // No E2E marker — plaintext envelope (legitimate inter-app traffic).
        // No ACK key (non-E2E): DELIVERED clears the entry but earns no reputation.
        Some((envelope.payload.clone(), [0u8; 32]))
    }

    /// originating IPC app of the delivery-stage transition.
    fn handle_delivery_status(&self, body: &[u8]) -> DispatchResult {
        let Ok(status) = veil_proto::delivery::DeliveryStatusPayload::decode(body) else {
            return DispatchResult::NoResponse;
        };
        // Match-shape (rather than `if status == DELIVERED`) is intentional —
        // future /221 work will add additional status arms (LOST
        // QUEUED, RETRYING etc); the match's `_ => {}` arm is the natural
        // place to add them. Switching to `if`-form would require a bigger
        // refactor when the next status code arrives.
        #[allow(clippy::single_match)]
        match status.status {
            // DELIVERED ACK clears the pending entry and (only when
            // authenticated) credits the relay.
            veil_proto::delivery::delivery_status::DELIVERED => {
                // C-09: PEEK the stored ACK key without clearing the entry, so a
                // forged DELIVERED whose MAC we cannot reproduce leaves the
                // pending entry intact (retransmit continues) and earns nothing.
                if let Some((_, _, ack_key)) =
                    lock!(self.pending_ack).peek_ack_info(&status.content_id)
                {
                    // A non-zero ACK key means this was an E2E send: require a
                    // valid recipient MAC over content_id. Only the recipient
                    // and the originator can derive the key (from the ML-KEM
                    // shared secret); an on-path relay cannot, so it cannot forge
                    // this. `blake3::Hash` equality is constant-time.
                    let expected = blake3::keyed_hash(&ack_key, &status.content_id);
                    let is_e2e = ack_key != [0u8; 32];
                    let authenticated = is_e2e && expected == blake3::Hash::from(status.mac);

                    if is_e2e && !authenticated {
                        // E2E message with a bad/forged MAC: ignore it — keep the
                        // pending entry so the legitimate ACK (or a retransmit)
                        // still resolves delivery, and credit nothing.
                    } else if let Some((hop, src_app_id)) =
                        // Authenticated E2E ACK, OR an unauthenticated zero-key
                        // path (meta-E2E / non-E2E): atomically remove the entry.
                        // Using ack_and_get_info (not ack) means only the thread
                        // that actually removes the entry proceeds — preventing a
                        // double-credit if a relay replays the valid ACK.
                        lock!(self.pending_ack).ack_and_get_info(&status.content_id)
                    {
                        // Credit relay reputation ONLY for an authenticated ACK.
                        // A zero-key (unauthenticated) DELIVERED — which a relay
                        // could forge — clears the entry but earns no reputation,
                        // closing the "forge DELIVERED for free reputation" path
                        // (462.18 ACK-gating is now MAC-gated, C-09).
                        if authenticated {
                            lock!(self.control_plane.rtt_table()).record_relay_success(hop);
                            self.loss_tracker.record_success(hop);
                            if let Some(ref rep) = self.reputation {
                                let identity_for_rep = self
                                    .session_registry
                                    .as_ref()
                                    .and_then(|sr| lock!(sr).node_id_for_peer(&hop.into()))
                                    .unwrap_or(hop);
                                lock!(rep).record_relay_success(identity_for_rep.into());
                            }
                        }
                        self.app_registry.route_delivery_stage(
                            src_app_id,
                            status.content_id,
                            veil_proto::delivery::delivery_status::DELIVERED,
                        );
                    }
                }
            }
            _ => {}
        }
        DispatchResult::NoResponse
    }

    /// 289: register the reassembly manifest for an upcoming chunk set.
    // Legacy direct-chunk frames (`DeliveryMsg::ChunkManifest` / `Chunk`) are
    // obsolete. Large payloads now ride the relay-preserving chunk-envelope path
    // (`handle_chunk_envelope`), where each chunk is an ordinary relayable
    // Forward envelope reassembled into the original addressed envelope. These
    // frame types are no longer emitted by this codebase. Drop them (no peer
    // penalty, for version-skew tolerance) rather than the old
    // reassemble-then-`broadcast_epidemic` behaviour, which flattened an
    // addressed message into an unauthenticated epidemic broadcast to every
    // local app endpoint (that vector is closed here).
    fn handle_chunk_manifest(&self, _body: &[u8]) -> DispatchResult {
        self.logger.warn(
            "chunk.obsolete_frame",
            "dropped obsolete ChunkManifest frame",
        );
        DispatchResult::NoResponse
    }

    fn handle_chunk(&self, _body: &[u8], _peer_id: NodeId) -> DispatchResult {
        self.logger
            .warn("chunk.obsolete_frame", "dropped obsolete Chunk frame");
        DispatchResult::NoResponse
    }

    /// stateless transit relay — deliver locally if addressed to us
    /// otherwise forward along the route_cache next-hop with split-horizon
    /// and self-loop guards plus content-hash dedup.
    fn handle_transit(&self, body: &[u8], peer_id: NodeId) -> DispatchResult {
        use veil_proto::delivery::TransitFramePayload;
        let tf = match TransitFramePayload::decode(body) {
            Ok(f) => f,
            Err(e) => return DispatchResult::Violation(format!("bad Transit: {e}")),
        };

        // Destination: unwrap the E2E-encrypted envelope and deliver locally.
        if tf.dst_node_id == self.local_node_id {
            // Terminal replay guard: dedup before delivering, using the same
            // 8-byte content_hash → 32-byte key (0xFF marker at byte 8) as the
            // forward path below, so a replayed/duplicated terminal frame is
            // dropped. An all-zero content_hash is treated as unset (no dedup).
            if tf.content_hash != [0u8; 8] {
                let mut dedup_key = [0u8; 32];
                dedup_key[..8].copy_from_slice(&tf.content_hash);
                dedup_key[8] = 0xFF;
                if lock!(self.forward_seen_set).check_and_insert(dedup_key) {
                    return DispatchResult::NoResponse;
                }
            }
            if let Ok((envelope, _)) = veil_proto::delivery::DeliveryEnvelope::decode(&tf.payload)
                && envelope.recipient_node_id() == self.local_node_id
            {
                self.app_registry.route_ipc_deliver(
                    envelope.sender_node_id,
                    envelope.src_app_id,
                    envelope.app_id,
                    envelope.endpoint_id,
                    veil_bufpool::pooled_shared_from_vec(envelope.payload),
                );
            }
            return DispatchResult::NoResponse;
        }
        if tf.ttl == 0 {
            return DispatchResult::NoResponse;
        }

        // Dedup by content_hash (8-byte → 32-byte key with 0xFF marker byte
        // to avoid collision with real content_ids in the shared ExpiryCache).
        let mut dedup_key = [0u8; 32];
        dedup_key[..8].copy_from_slice(&tf.content_hash);
        dedup_key[8] = 0xFF;
        if lock!(self.forward_seen_set).check_and_insert(dedup_key) {
            return DispatchResult::NoResponse;
        }

        // Split-horizon + self-loop guard before forwarding.
        //
        // Audit batch 2026-05-24 (M3): bind the looked-up hop to a local
        // immediately so the rlock guard is dropped BEFORE we acquire
        // the session_tx_registry wlock.  Rust temporary semantics
        // already drop it at end of statement, but binding makes the
        // intent explicit and survives refactors (e.g. if `lookup()`
        // were to return `&NodeId` instead of `NodeId`).  Lock-asymmetry
        // concern: route_cache is read hot-path frequently; holding a
        // reader across an unrelated wlock would let many writers
        // pile up on the registry — sequential locking avoids the
        // hazard entirely.
        let hop = {
            let cache = rlock!(self.route_cache);
            match cache.lookup(&tf.dst_node_id) {
                Some(h) => h,
                None => return DispatchResult::NoResponse,
            }
            // `cache` (rlock guard) dropped here.
        };
        if &hop == peer_id.as_bytes() || hop == self.local_node_id {
            return DispatchResult::NoResponse;
        }
        let Some(reg) = &self.session_tx_registry else {
            return DispatchResult::NoResponse;
        };

        let fwd = TransitFramePayload {
            ttl: tf.ttl - 1,
            ..tf
        };
        let fwd_bytes = fwd.encode();
        let mut fwd_hdr = veil_proto::header::FrameHeader::new(
            veil_proto::family::FrameFamily::Delivery as u8,
            DeliveryMsg::Transit as u16,
        );
        fwd_hdr.body_len = fwd_bytes.len() as u32;
        // single-allocation frame assembly.
        let frame = veil_proto::codec::encode_frame(&fwd_hdr, &fwd_bytes);
        // count transit-frame forward failures — previously
        // silently dropped, hiding link degradation.
        let sent = rlock!(reg).send_to(&hop, veil_proto::header::priority::INTERACTIVE, frame);
        if !sent && let Some(m) = &self.metrics {
            m.inc_send_to_failed();
        }
        DispatchResult::NoResponse
    }

    /// DHT-routed recursive relay — four-way decision:
    /// (a) terminal delivery if we're the destination; (b) direct forward
    /// if we have a session to the destination; (c) hop-limit exhausted
    /// → mailbox fallback; (d) greedy forward to Kademlia closest.
    fn handle_recursive_relay(&self, body: &[u8], peer_id: NodeId) -> DispatchResult {
        use veil_proto::delivery::RecursiveRelayPayload;
        let rr = match RecursiveRelayPayload::decode(body) {
            Ok(f) => f,
            Err(e) => return DispatchResult::Violation(format!("bad RecursiveRelay: {e}")),
        };

        // 439.2 / 461.8: dedup by (query_id, dst_node_id
        // originator_pseudonym) to prevent amplification loops. Including
        // the pseudonym blocks the "dedup poisoning" attack where an
        // attacker replays a victim's `(query_id, dst)` pair to suppress
        // the victim's legitimate queries inside the TTL window. Uses
        // BLAKE3 hash XORed with marker 0xFE in byte 0 to stay disjoint
        // from content_id and TransitFrame dedup keys in the shared
        // ExpiryCache.
        {
            let mut hash_input = [0u8; 68]; // 4 (qid) + 32 (dst) + 32 (pseudonym)
            hash_input[..4].copy_from_slice(&rr.query_id.to_be_bytes());
            hash_input[4..36].copy_from_slice(&rr.dst_node_id);
            hash_input[36..68].copy_from_slice(&rr.originator_pseudonym);
            let mut dedup_key: [u8; 32] = *blake3::hash(&hash_input).as_bytes();
            dedup_key[0] ^= 0xFE; // marker to avoid collision with other dedup domains
            if lock!(self.forward_seen_set).check_and_insert(dedup_key) {
                return DispatchResult::NoResponse;
            }
        }

        // (a) Destination reached — unwrap inner ForwardPayload and deliver.
        if rr.dst_node_id == self.local_node_id {
            if let Ok(fwd) = veil_proto::delivery::ForwardPayload::decode(&rr.payload) {
                self.app_registry.route_ipc_deliver(
                    fwd.envelope.sender_node_id,
                    fwd.envelope.src_app_id,
                    fwd.envelope.app_id,
                    fwd.envelope.endpoint_id,
                    veil_bufpool::pooled_shared_from_vec(fwd.envelope.payload),
                );
            }
            // Reverse path: originator → peer we received from.
            wlock!(self.route_cache).insert(
                rr.originator_pseudonym,
                *peer_id.as_bytes(),
                1_000,
                rr.hop_count,
            );
            if let Some(m) = &self.metrics {
                m.inc_recursive_relay_delivered();
            }
            return DispatchResult::NoResponse;
        }

        // (b) Direct-session forward: we already have a session to the dst.
        if let Some(reg) = &self.session_tx_registry
            && rlock!(reg).get_sender(&rr.dst_node_id).is_some()
        {
            let mut fwd_hdr = veil_proto::header::FrameHeader::new(
                veil_proto::family::FrameFamily::Delivery as u8,
                DeliveryMsg::Forward as u16,
            );
            fwd_hdr.body_len = rr.payload.len() as u32;
            // single-allocation frame assembly.
            let frame = veil_proto::codec::encode_frame(&fwd_hdr, &rr.payload);
            rlock!(reg).send_to(
                &rr.dst_node_id,
                veil_proto::header::priority::INTERACTIVE,
                frame,
            );
            wlock!(self.route_cache).insert(
                rr.originator_pseudonym,
                *peer_id.as_bytes(),
                1_000,
                rr.hop_count,
            );
            if let Some(m) = &self.metrics {
                m.inc_recursive_relay_delivered();
            }
            return DispatchResult::NoResponse;
        }

        // (c) Hop limit exhausted — : mailbox fallback removed
        // frame is silently dropped. Async-delivery semantics belong to
        // the application layer now.
        if rr.hop_count == 0 {
            return DispatchResult::NoResponse;
        }

        // (d) Greedy forward to closest reachable Kademlia contact.
        if self.forward_rr_to_closest(&rr, peer_id) {
            return DispatchResult::NoResponse;
        }

        // (e) No reachable closer node — : drop (was mailbox fallback).
        DispatchResult::NoResponse
    }

    /// Attempt a greedy single-hop forward of a `RecursiveRelayPayload` to
    /// the closest Kademlia contact (i) has a live session (ii) is not
    /// the peer we received (split-horizon), and (iii) has earned transit
    /// reputation. Returns `true` when a forward was sent.
    fn forward_rr_to_closest(
        &self,
        rr: &veil_proto::delivery::RecursiveRelayPayload,
        peer_id: NodeId,
    ) -> bool {
        let reg = match &self.session_tx_registry {
            Some(r) => r,
            None => return false,
        };
        let closest = self.dht.find_closest_nodes(&rr.dst_node_id, 3);
        let reg_guard = rlock!(reg);
        for next in &closest {
            // Split-horizon + self-loop guard.
            if next == peer_id.as_bytes() || *next == self.local_node_id {
                continue;
            }
            // skip peers without transit reputation.
            if let Some(ref rep) = self.reputation
                && !lock!(rep).can_transit(&(*next).into())
            {
                continue;
            }
            if reg_guard.get_sender(next).is_none() {
                continue;
            }

            let fwd_rr = veil_proto::delivery::RecursiveRelayPayload {
                hop_count: rr.hop_count - 1,
                ..rr.clone()
            };
            let fwd_bytes = fwd_rr.encode();
            let mut fwd_hdr = veil_proto::header::FrameHeader::new(
                veil_proto::family::FrameFamily::Delivery as u8,
                DeliveryMsg::RecursiveRelay as u16,
            );
            fwd_hdr.body_len = fwd_bytes.len() as u32;
            // single-allocation frame assembly.
            let frame = veil_proto::codec::encode_frame(&fwd_hdr, &fwd_bytes);
            drop(reg_guard);
            rlock!(reg).send_to(next, veil_proto::header::priority::INTERACTIVE, frame);
            if let Some(m) = &self.metrics {
                m.inc_recursive_relay_forwarded();
            }
            // the reputation credit was previously fired here
            // right after `send_to` placed the frame in the session buffer —
            // that means a peer with a stuck TCP could farm reputation
            // without ever actually delivering. For DELIVERY_FORWARD the
            // credit is now ACK-gated in the DELIVERED handler; recursive
            // relay has no per-hop ACK, so we drop the signal here entirely
            // rather than leave an unverified credit path.
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::HopAttrs;
    use veil_cfg::NodeId;
    use veil_util::rlock;

    /// audit cycle-3 (M1): ECMP flow-pinning must be deterministic per flow
    /// regardless of the upstream weighted shuffle, keep the equal-cost group at
    /// the front, and permute `hop_attrs` in lockstep with `candidates`.
    #[test]
    fn ecmp_pinning_deterministic_group_front_attrs_parallel() {
        let disp = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let mk = |rtt: u32| HopAttrs {
            hop_count: 1,
            rtt_ms: rtt,
            congestion: 0,
            confidence: 1.0,
            battery: 0,
            jitter_ms: 0.0,
            bandwidth_class: 0,
            relay_success_ema: 1.0,
            relay_attempts: 0,
        };
        let (h1, h2, h3, h4) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
        // h1/h2/h3 equal-cost (ECMP group); h4 far worse-cost (excluded).
        let scores = vec![(h1, 100u32), (h2, 100), (h3, 100), (h4, 1_000_000)];
        let (sender, dst) = ([9u8; 32], [8u8; 32]);
        // rtt encodes hop identity so we can check the parallel permutation.
        let rtt_of = |h: [u8; 32]| -> u32 {
            if h == h1 {
                11
            } else if h == h2 {
                22
            } else if h == h3 {
                33
            } else {
                44
            }
        };

        // Run A — one input order.
        let mut ca = vec![h1, h2, h3, h4];
        let mut aa = vec![mk(11), mk(22), mk(33), mk(44)];
        let g = disp.apply_ecmp_pinning(&mut ca, &mut aa, &scores, sender, dst);
        assert_eq!(g, 3, "three equal-cost members form the group");
        assert_eq!(ca[3], h4, "worse-cost hop trails the group");
        assert!(ca[..3].contains(&h1) && ca[..3].contains(&h2) && ca[..3].contains(&h3));
        assert_ne!(ca[0], h4, "primary hop is an ECMP member");
        for i in 0..ca.len() {
            assert_eq!(aa[i].rtt_ms, rtt_of(ca[i]), "attrs parallel at {i}");
        }

        // Run B — DIFFERENT input order (simulating the weighted shuffle), same flow.
        let mut cb = vec![h4, h3, h1, h2];
        let mut ab = vec![mk(44), mk(33), mk(11), mk(22)];
        disp.apply_ecmp_pinning(&mut cb, &mut ab, &scores, sender, dst);
        assert_eq!(
            ca[0], cb[0],
            "flow-pinned primary hop is identical across input orders (determinism)"
        );
        for i in 0..cb.len() {
            assert_eq!(ab[i].rtt_ms, rtt_of(cb[i]), "attrs parallel (B) at {i}");
        }
    }

    /// Standalone implementation of the effective_score formula so that tests
    /// can exercise jitter/bandwidth/reputation scoring without going through relay_forward.
    #[allow(clippy::too_many_arguments)]
    fn effective_score(
        rtt_ms: u32,
        jitter_ms: f64,
        congestion: u8,
        hop_count: u8,
        battery: u8,
        bandwidth_class: u8,
        traffic_class: u8,
        relay_success_ema: f32,
        relay_attempts: u32,
        jitter_penalty_weight: f64,
        jitter_threshold_ms: f64,
        narrow_bw_penalty: f64,
        bat_thresh_low: u8,
        bat_thresh_medium: u8,
        bat_penalty_low: f64,
        bat_penalty_medium: f64,
        relay_rep_min_attempts: u32,
        relay_rep_threshold: f32,
        relay_rep_penalty: f64,
    ) -> f64 {
        use veil_proto::header::TrafficClass;
        use veil_routing::probe::BandwidthClass;
        let rtt = rtt_ms as f64;
        let cong_norm = congestion as f64 / 255.0;
        let hops = hop_count as f64;
        let bat_penalty = if battery == 0 {
            0.0
        } else if battery <= bat_thresh_low {
            bat_penalty_low
        } else if battery <= bat_thresh_medium {
            bat_penalty_medium
        } else {
            0.0
        };
        let is_realtime = traffic_class == TrafficClass::RealTime as u8;
        let is_bulk_or_bg = traffic_class == TrafficClass::Bulk as u8
            || traffic_class == TrafficClass::Background as u8;
        let jitter_weight = if is_realtime {
            jitter_penalty_weight * 2.0
        } else {
            jitter_penalty_weight
        };
        let jitter_penalty = jitter_weight * (jitter_ms - jitter_threshold_ms).max(0.0);
        let bw_penalty = if is_bulk_or_bg && bandwidth_class == BandwidthClass::Narrow as u8 {
            narrow_bw_penalty
        } else {
            0.0
        };
        let rep_penalty = if relay_attempts >= relay_rep_min_attempts
            && relay_success_ema < relay_rep_threshold
        {
            relay_rep_penalty
        } else {
            1.0
        };
        (rtt + 1.0 + jitter_penalty)
            * (1.0 + 2.0 * cong_norm)
            * (1.0 + 0.1 * hops)
            * (1.0 + bat_penalty)
            * (1.0 + bw_penalty)
            * rep_penalty
    }

    /// Convenience wrapper using all-defaults for relay reputation params.
    fn score_with_defaults(
        rtt_ms: u32,
        jitter_ms: f64,
        bandwidth_class: u8,
        traffic_class: u8,
        relay_success_ema: f32,
        relay_attempts: u32,
    ) -> f64 {
        let d = veil_cfg::RoutingConfig::default();
        effective_score(
            rtt_ms,
            jitter_ms,
            0,
            0,
            0,
            bandwidth_class,
            traffic_class,
            relay_success_ema,
            relay_attempts,
            d.jitter_penalty_weight,
            d.jitter_threshold_ms as f64,
            d.narrow_bandwidth_bulk_penalty,
            d.battery_threshold_low,
            d.battery_threshold_medium,
            d.battery_penalty_low,
            d.battery_penalty_medium,
            d.relay_reputation_min_attempts,
            d.relay_reputation_threshold,
            d.relay_reputation_penalty,
        )
    }

    /// 216.5: High-jitter low-RTT path loses to low-jitter higher-RTT path at REALTIME priority.
    #[test]
    fn jitter_penalty_realtime_prefers_low_jitter() {
        let tc_rt = veil_proto::header::TrafficClass::RealTime as u8;
        let score_a = score_with_defaults(20, 30.0, 0, tc_rt, 1.0, 0); // RTT=20, jitter=30
        let score_b = score_with_defaults(25, 5.0, 0, tc_rt, 1.0, 0); // RTT=25, jitter=5
        assert!(
            score_b < score_a,
            "REALTIME: low-jitter RTT=25ms (score={score_b:.1}) must beat high-jitter RTT=20ms (score={score_a:.1})"
        );
    }

    /// 216.10: BULK traffic prefers WIDE bandwidth path over NARROW even when NARROW has lower RTT.
    #[test]
    fn narrow_bandwidth_penalty_bulk_prefers_wide() {
        use veil_routing::probe::BandwidthClass;
        let tc_bulk = veil_proto::header::TrafficClass::Bulk as u8;
        let score_wide = score_with_defaults(30, 0.0, BandwidthClass::Wide as u8, tc_bulk, 1.0, 0);
        let score_narrow =
            score_with_defaults(20, 0.0, BandwidthClass::Narrow as u8, tc_bulk, 1.0, 0);
        assert!(
            score_wide < score_narrow,
            "BULK: WIDE RTT=30ms (score={score_wide:.1}) must beat NARROW RTT=20ms (score={score_narrow:.1})"
        );
    }

    /// 219.4: ForwardSeenSet deduplicates a second arrival of the same content_id.
    ///
    /// Simulates what happens when two parallel paths both deliver the same frame
    /// to the same relay node: the second should be silently dropped.
    #[test]
    fn forward_seen_set_deduplicates_second_arrival() {
        use crate::ForwardSeenSet;
        use std::time::Duration;
        let mut seen = ForwardSeenSet::new(Duration::from_secs(60), 1024);
        let content_id = [0xAAu8; 32];
        // First arrival: not yet seen → should be inserted (returns false = new).
        assert!(
            !seen.check_and_insert(content_id),
            "first arrival must not be a duplicate"
        );
        // Second arrival: already seen → duplicate (returns true).
        assert!(
            seen.check_and_insert(content_id),
            "second arrival must be detected as duplicate"
        );
    }

    /// Terminal DELIVERY_FORWARD replay guard: two identical terminal Forward
    /// frames (same non-zero `content_id`) addressed to the local node must
    /// result in exactly ONE app delivery — the second is silently dropped by
    /// the content_id dedup added at the top of `deliver_forward_locally`.
    #[test]
    fn terminal_forward_deduplicates_replayed_frame() {
        use crate::DispatchResult;
        use crate::make_test_dispatcher;
        use veil_app::registry::AppMessage;
        use veil_proto::delivery::{DeliveryEnvelope, ForwardPayload};
        use veil_proto::family::{DeliveryMsg, FrameFamily};
        use veil_proto::header::FrameHeader;

        let sender_id = [0xAAu8; 32];
        let recipient_id = [0xBBu8; 32];
        let dst_app_id = [0xCCu8; 32];
        let dst_endpoint_id = 0xC0DEu32;

        let mut disp = make_test_dispatcher(veil_cfg::NodeRole::Core);
        disp.local_node_id = recipient_id;

        // Register the destination endpoint so a terminal delivery lands in a
        // receiver we can drain. `_handle` must stay in scope (drop unregisters).
        let (_handle, mut endpoint_rx) =
            disp.app_registry.register(dst_app_id, dst_endpoint_id, 16);

        // Plaintext envelope (first payload byte must NOT be an E2E marker) with
        // a fresh timestamp (so the cheap TTL pre-check passes) and a non-zero
        // content_id (zero is the unset sentinel that bypasses dedup).
        let envelope = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(recipient_id),
            sender_node_id: sender_id,
            src_app_id: [0xA1u8; 32],
            app_id: dst_app_id,
            endpoint_id: dst_endpoint_id,
            content_id: [0x77u8; 32],
            created_at: veil_util::unix_secs_now_u64(),
            ttl_secs: 3600,
            payload: vec![0x01, 0x02, 0x03],
            trace_id: 0,
            require_ack: false,
        };
        let fwd = ForwardPayload {
            next_hop_node_id: recipient_id,
            envelope,
            relay_hops: 0,
        };
        let body = fwd.encode();
        let mut hdr = FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
        hdr.body_len = body.len() as u32;

        // First arrival: delivered.
        let r1 = disp.dispatch(&hdr, &body, sender_id);
        assert!(
            matches!(r1, DispatchResult::NoResponse),
            "first terminal Forward must deliver (NoResponse), got {r1:?}",
        );
        // Replay (byte-identical): dropped by content_id dedup.
        let r2 = disp.dispatch(&hdr, &body, sender_id);
        assert!(
            matches!(r2, DispatchResult::NoResponse),
            "replayed terminal Forward must be silently dropped, got {r2:?}",
        );

        // Exactly one Deliver reached the endpoint.
        match endpoint_rx.try_recv() {
            Ok(AppMessage::Deliver {
                app_id,
                endpoint_id,
                data,
                ..
            }) => {
                assert_eq!(app_id, dst_app_id);
                assert_eq!(endpoint_id, dst_endpoint_id);
                assert_eq!(data.as_ref(), &[0x01, 0x02, 0x03]);
            }
            other => panic!("first arrival must enqueue exactly one Deliver, got {other:?}"),
        }
        assert!(
            endpoint_rx.try_recv().is_err(),
            "replayed terminal Forward must NOT produce a second delivery",
        );
    }

    /// audit cycle-8 F9 — the replay-critical content_id dedup
    /// (`forward_seen_content`) must be isolated from the floodable relay
    /// domains (`forward_seen_set`): a flood that overflows the relay cache by
    /// far more than its capacity must NOT evict a recorded content_id and
    /// re-open the payload-replay window within the TTL.
    #[test]
    fn content_dedup_survives_relay_seen_set_flood() {
        use crate::make_test_dispatcher;
        use veil_util::lock;

        let disp = make_test_dispatcher(veil_cfg::NodeRole::Core);
        let content_id = [0x77u8; 32];
        // Record a content_id in the isolated terminal cache (new → false).
        assert!(!lock!(disp.forward_seen_content).check_and_insert(content_id));

        // Flood the relay/loop-suppression cache well past its 10_000 test cap.
        for i in 0..20_000u32 {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_le_bytes());
            k[31] = 0xFD; // floodable relay-path domain tag
            lock!(disp.forward_seen_set).check_and_insert(k);
        }

        // The content_id is still present → replayed payload would be dropped.
        assert!(
            lock!(disp.forward_seen_content).check_and_insert(content_id),
            "content_id must survive a relay-domain flood (F9 isolation)"
        );
    }

    /// H-B end-to-end: a payload larger than `MAX_ENVELOPE_PAYLOAD`, split into
    /// relay-chunked envelopes (as the IPC sender does), is reassembled at the
    /// destination and delivered ONCE to the addressed app endpoint with the
    /// full original bytes — i.e. `app_id`/`endpoint_id` and message integrity
    /// are preserved (the old path flattened this into a lossy epidemic broadcast).
    #[test]
    fn relay_chunked_envelope_reassembles_and_delivers_once() {
        use crate::make_test_dispatcher;
        use veil_app::registry::AppMessage;
        use veil_proto::budget::MAX_CHUNK_PAYLOAD;
        use veil_proto::delivery::{
            ChunkedEnvelopePayload, DeliveryEnvelope, ForwardPayload, MAX_ENVELOPE_PAYLOAD,
        };
        use veil_proto::family::{DeliveryMsg, FrameFamily};
        use veil_proto::header::FrameHeader;

        let sender_id = [0xAAu8; 32];
        let recipient_id = [0xBBu8; 32];
        let dst_app_id = [0xCCu8; 32];
        let dst_endpoint_id = 0xC0DEu32;

        let mut disp = make_test_dispatcher(veil_cfg::NodeRole::Core);
        disp.local_node_id = recipient_id;
        let (_handle, mut endpoint_rx) =
            disp.app_registry.register(dst_app_id, dst_endpoint_id, 16);

        // Original plaintext message just over the single-envelope limit so it
        // genuinely requires chunking. First byte must not be an E2E/chunk marker.
        let total = MAX_ENVELOPE_PAYLOAD + 50_000;
        let original: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        assert!(original[0] < 0xE2);

        let pieces: Vec<&[u8]> = original.chunks(MAX_CHUNK_PAYLOAD).collect();
        let chunk_count = pieces.len() as u32;
        assert!(chunk_count > 1, "test must span multiple chunks");
        let transfer_id = [0x5Au8; 16];
        let orig_content_id = [0x77u8; 32];

        // Deliver every chunk-envelope as an ordinary terminal Forward (out of
        // order, to exercise index-based reassembly).
        let mut order: Vec<usize> = (0..pieces.len()).collect();
        order.rotate_left(1); // 1,2,...,0 — last chunk arrives last but not first

        for &i in &order {
            let wrapper = ChunkedEnvelopePayload {
                transfer_id,
                chunk_index: i as u32,
                chunk_count,
                total_size: total as u32,
                orig_content_id,
                require_ack: false,
                data: pieces[i].to_vec(),
            }
            .encode();
            let mut cid = [0u8; 32];
            cid[..8].copy_from_slice(&(i as u64).to_be_bytes());
            cid[8] = 1; // ensure non-zero, distinct per chunk
            let envelope = DeliveryEnvelope {
                recipient: veil_proto::recipient::Recipient::any(recipient_id),
                sender_node_id: sender_id,
                src_app_id: [0xA1u8; 32],
                app_id: dst_app_id,
                endpoint_id: dst_endpoint_id,
                content_id: cid,
                created_at: veil_util::unix_secs_now_u64(),
                ttl_secs: 3600,
                payload: wrapper,
                trace_id: 0,
                require_ack: false,
            };
            let body = ForwardPayload {
                next_hop_node_id: recipient_id,
                envelope,
                relay_hops: 0,
            }
            .encode();
            let mut hdr =
                FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
            hdr.body_len = body.len() as u32;
            disp.dispatch(&hdr, &body, sender_id);
        }

        // Exactly one Deliver, carrying the full reassembled payload.
        match endpoint_rx.try_recv() {
            Ok(AppMessage::Deliver {
                app_id,
                endpoint_id,
                data,
                ..
            }) => {
                assert_eq!(app_id, dst_app_id);
                assert_eq!(endpoint_id, dst_endpoint_id);
                assert_eq!(data.as_ref().len(), total, "reassembled length mismatch");
                assert_eq!(
                    data.as_ref(),
                    original.as_slice(),
                    "reassembled bytes mismatch"
                );
            }
            other => panic!("expected one reassembled Deliver, got {other:?}"),
        }
        assert!(
            endpoint_rx.try_recv().is_err(),
            "chunked transfer must deliver exactly once",
        );
    }

    /// 221.8: Relay with low success rate (0.3) loses to a higher-RTT relay with high success rate (0.9).
    ///
    /// Candidate A: RTT=20ms, relay_success=0.3 (unreliable) → penalty applied → score ≈ 42.
    /// Candidate B: RTT=30ms, relay_success=0.9 (reliable) → no penalty → score ≈ 31.
    /// Expected: B is preferred (lower score).
    #[test]
    fn relay_reputation_penalty_prefers_reliable_relay() {
        let d = veil_cfg::RoutingConfig::default();
        let tc = veil_proto::header::TrafficClass::Interactive as u8;
        let min_a = d.relay_reputation_min_attempts;
        let score_a = score_with_defaults(20, 0.0, 0, tc, 0.3, min_a); // unreliable
        let score_b = score_with_defaults(30, 0.0, 0, tc, 0.9, min_a); // reliable
        assert!(
            score_b < score_a,
            "relay_success=0.9 RTT=30ms (score={score_b:.1}) must beat relay_success=0.3 RTT=20ms (score={score_a:.1})"
        );
    }

    // ── 272: Transit handler tests ──────────────────────────────────────────

    #[test]
    fn transit_frame_local_delivery() {
        use veil_proto::family::{DeliveryMsg, FrameFamily};
        use veil_proto::header::FrameHeader;
        let disp = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let local_node_id = disp.local_node_id;

        let payload = b"E2E encrypted envelope data".to_vec();
        let tf = veil_proto::delivery::TransitFramePayload {
            dst_node_id: local_node_id,
            src_node_id: [0xAAu8; 32],
            ttl: 10,
            content_hash: veil_proto::delivery::TransitFramePayload::compute_content_hash(&payload),
            payload,
        };
        let body = tf.encode();
        let hdr = FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Transit as u16);
        let result = disp.dispatch(&hdr, &body, [0xBBu8; 32]);
        assert!(
            matches!(result, super::DispatchResult::NoResponse),
            "Transit to local node should deliver locally: {result:?}",
        );
    }

    #[test]
    fn transit_frame_ttl_zero_dropped() {
        use veil_proto::family::{DeliveryMsg, FrameFamily};
        use veil_proto::header::FrameHeader;
        let disp = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);

        let tf = veil_proto::delivery::TransitFramePayload {
            dst_node_id: [0xCCu8; 32], // not local
            src_node_id: [0xAAu8; 32],
            ttl: 0, // expired
            content_hash: [0u8; 8],
            payload: vec![],
        };
        let body = tf.encode();
        let hdr = FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Transit as u16);
        let result = disp.dispatch(&hdr, &body, [0xBBu8; 32]);
        assert!(
            matches!(result, super::DispatchResult::NoResponse),
            "Transit with TTL=0 should be dropped: {result:?}",
        );
    }

    // ── RecursiveRelay dispatch test ─────────────────────────────

    /// Validate that a RecursiveRelay frame addressed to the local node is
    /// delivered (payload decoded, reverse route inserted).
    #[test]
    fn recursive_relay_local_delivery() {
        use veil_proto::{
            delivery::{DeliveryEnvelope, ForwardPayload, RecursiveRelayPayload},
            family::{DeliveryMsg, FrameFamily},
            header::FrameHeader,
        };

        let local_id = [0xAAu8; 32];
        let originator = [0xBBu8; 32];
        let peer = [0xCCu8; 32];

        let mut disp = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        disp.local_node_id = local_id;

        // Build a RecursiveRelay frame addressed to local_id.
        let envelope = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(local_id),
            sender_node_id: originator,
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id: [0x42u8; 32],
            created_at: 0,
            ttl_secs: 3600,
            payload: b"hello via DHT".to_vec(),
            trace_id: 0,
            require_ack: false,
        };
        let fwd = ForwardPayload {
            next_hop_node_id: local_id,
            envelope,
            relay_hops: 0,
        };
        let rr = RecursiveRelayPayload {
            dst_node_id: local_id,
            originator_pseudonym: RecursiveRelayPayload::make_pseudonym(&originator, 1),
            query_id: 1,
            hop_count: 5,
            payload: fwd.encode(),
        };
        let body = rr.encode();
        let hdr = FrameHeader::new(
            FrameFamily::Delivery as u8,
            DeliveryMsg::RecursiveRelay as u16,
        );
        let result = disp.dispatch(&hdr, &body, peer);
        assert!(
            matches!(result, super::DispatchResult::NoResponse),
            "local RecursiveRelay delivery should succeed: {result:?}",
        );
        // Reverse route: originator pseudonym should be reachable via peer.
        let pseudo = RecursiveRelayPayload::make_pseudonym(&originator, 1);
        let hop = rlock!(disp.route_cache).lookup(&pseudo);
        assert_eq!(
            hop,
            Some(peer),
            "reverse route pseudonym→peer should be cached"
        );
    }

    /// with mailbox removed, a RecursiveRelay frame with hop_count=0
    /// is silently dropped (was: spilled to mailbox for later delivery).
    #[test]
    fn recursive_relay_hop_exhausted_dropped() {
        use veil_proto::{
            delivery::{DeliveryEnvelope, ForwardPayload, RecursiveRelayPayload},
            family::{DeliveryMsg, FrameFamily},
            header::FrameHeader,
        };

        let dst = [0xDDu8; 32]; // not local
        let peer = [0xCCu8; 32];

        let disp = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);

        let envelope = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(dst),
            sender_node_id: [0xBBu8; 32],
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id: [0x43u8; 32],
            created_at: 0,
            ttl_secs: 3600,
            payload: b"exhausted".to_vec(),
            trace_id: 0,
            require_ack: false,
        };
        let fwd = ForwardPayload {
            next_hop_node_id: dst,
            envelope,
            relay_hops: 0,
        };
        let rr = RecursiveRelayPayload {
            dst_node_id: dst,
            originator_pseudonym: RecursiveRelayPayload::make_pseudonym(&[0xBBu8; 32], 2),
            query_id: 2,
            hop_count: 0, // exhausted
            payload: fwd.encode(),
        };
        let body = rr.encode();
        let hdr = FrameHeader::new(
            FrameFamily::Delivery as u8,
            DeliveryMsg::RecursiveRelay as u16,
        );
        let result = disp.dispatch(&hdr, &body, peer);
        assert!(
            matches!(result, super::DispatchResult::NoResponse),
            "hop-exhausted RecursiveRelay should be silently dropped: {result:?}",
        );
    }

    // ── rand_seed_for_pick non-determinism ──────────────────────

    #[test]
    fn rand_seed_for_pick_changes_across_calls_with_same_trace_id() {
        // Same trace_id called twice in quick succession should still produce
        // distinct seeds — the wall-clock nanos component dominates. This
        // matters because a re-dispatched frame with identical trace_id must
        // not always pick the same gateway (would defeat diversification).
        //
        // Use sleep instead of a tight CPU loop: on modern fast CPUs (M2/M3)
        // 1 000 black-box multiplies retire in well under a microsecond, which
        // is shorter than the macOS `clock_gettime` resolution for some
        // CLOCK_REALTIME backends.  100 µs sleep guarantees the OS wall clock
        // advances past the SystemTime granularity bound on every supported
        // platform.
        let trace = 0xDEAD_BEEF_CAFE_BABEu64;
        let s1 = super::rand_seed_for_pick(trace);
        std::thread::sleep(std::time::Duration::from_micros(100));
        let s2 = super::rand_seed_for_pick(trace);
        assert_ne!(s1, s2, "seed must change across calls (got {s1} == {s2})");
    }

    #[test]
    fn rand_seed_for_pick_differs_per_trace_id() {
        // Two simultaneous calls with different trace_ids should differ —
        // even if they happen in the same nanosecond, the trace_id XOR'd
        // into the seed propagates through the xorshift mixing.
        let s1 = super::rand_seed_for_pick(0x1111_1111_1111_1111);
        let s2 = super::rand_seed_for_pick(0x2222_2222_2222_2222);
        assert_ne!(s1, s2);
    }

    // ── — resolve_sovereign_delivery_targets ──────────────────

    #[test]
    fn resolve_sovereign_targets_returns_none_without_registry() {
        // Test dispatcher has `session_registry: None` — sovereign
        // routing is not wired, helper reports `None` so callers
        // know to fall back to the legacy `route_cache` path.
        let disp = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let got = disp
            .resolve_sovereign_delivery_targets(&veil_proto::recipient::Recipient::any([0xAA; 32]));
        assert!(got.is_none());
    }

    #[test]
    fn resolve_sovereign_targets_hits_live_session() {
        // Wire a SessionRegistry containing a live sovereign session
        // then verify resolve_sovereign_delivery_targets finds it
        // for Any / Specific / All.
        use veil_identity::verify::ValidatedIdentity;
        use veil_proto::recipient::{InstanceTag, Recipient};
        use veil_proto::session::{cap_flags, role_bits};
        use veil_session::{SessionEntry, SessionRegistry};

        let mut disp = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let reg = std::sync::Arc::new(std::sync::Mutex::new(SessionRegistry::new()));
        disp.session_registry = Some(std::sync::Arc::clone(&reg));

        let node_id = [0x42u8; 32];
        let instance_id = [0x07u8; 16];
        let peer_id = [0xEEu8; 32];
        reg.lock().unwrap().insert(SessionEntry {
            session_id: [0x01; 32],
            remote_node_id: peer_id,
            remote_identity: veil_proto::session::IdentityPayload {
                algo: 0,
                public_key: vec![0u8; 32],
                nonce: b"n".to_vec(),
                node_id: peer_id,
                mlkem_pubkey: None,
            },
            remote_capabilities: veil_proto::session::CapabilitiesPayload {
                roles_supported: role_bits::CORE,
                flags: cap_flags::SUPPORTS_SOVEREIGN_IDENTITY,
                discovery_mode: 0,
            },
            remote_attach: veil_proto::session::AttachPayload {
                role: 1,
                realm_id: 0,
                attach_epoch: 0,
                mailbox_preference_count: 0,
                gateway_preference_count: 0,
                flags: 0,
            },
            remote_role: veil_session::RemoteRole::Core,
            validated_sovereign_identity: Some(ValidatedIdentity {
                node_id,
                master_algo: 0,
                master_pubkey: vec![0u8; 32],
                active_identity_pubkey: vec![0u8; 32],
                active_identity_algo: 0,
                active_key_idx: 0,
                active_device_id: {
                    let mut d = [0u8; 32];
                    d[..16].copy_from_slice(&instance_id);
                    d
                },
                active_instance_id: instance_id,
            }),
        });

        // Any — picks the one live instance.
        assert_eq!(
            disp.resolve_sovereign_delivery_targets(&Recipient::any(node_id)),
            Some(vec![peer_id])
        );
        // Specific — hits on exact match.
        assert_eq!(
            disp.resolve_sovereign_delivery_targets(&Recipient {
                node_id,
                instance_tag: InstanceTag::Specific(instance_id),
            }),
            Some(vec![peer_id])
        );
        // Specific — misses on wrong instance.
        assert_eq!(
            disp.resolve_sovereign_delivery_targets(&Recipient {
                node_id,
                instance_tag: InstanceTag::Specific([0xFF; 16]),
            }),
            Some(vec![])
        );
        // All — one entry.
        assert_eq!(
            disp.resolve_sovereign_delivery_targets(&Recipient::all(node_id)),
            Some(vec![peer_id])
        );
    }

    #[test]
    fn try_sovereign_direct_forward_uses_live_session() {
        // Wire both session_registry + session_tx_registry, seed one
        // sovereign session for identity Alice. A forward addressed to
        // Alice must be delivered directly via the live peer_id
        // bypassing (empty) route_cache. Returns `true`.
        use veil_identity::verify::ValidatedIdentity;
        use veil_proto::delivery::{DeliveryEnvelope, ForwardPayload};
        use veil_proto::recipient::Recipient;
        use veil_proto::session::{cap_flags, role_bits};
        use veil_session::SessionTxRegistry;
        use veil_session::{SessionEntry, SessionRegistry};

        let alice_id = [0xAAu8; 32];
        let alice_instance = [0x01u8; 16];
        let alice_peer = [0xEEu8; 32];
        let sender_peer = [0xBBu8; 32]; // who handed us this envelope

        let mut disp = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        // Real session_tx_registry so send_to has a queue to hit.
        let tx = std::sync::Arc::new(std::sync::RwLock::new(SessionTxRegistry::new()));
        disp.session_tx_registry = Some(std::sync::Arc::clone(&tx));
        let reg = std::sync::Arc::new(std::sync::Mutex::new(SessionRegistry::new()));
        disp.session_registry = Some(std::sync::Arc::clone(&reg));

        // Register a session outbox so send_to can actually place the frame.
        // `SessionTxRegistry::register` creates the channel internally and
        // returns the receiver.
        let mut frame_rx = tx.write().unwrap().register(alice_peer);

        // Seed the sovereign registry.
        reg.lock().unwrap().insert(SessionEntry {
            session_id: [0xAB; 32],
            remote_node_id: alice_peer,
            remote_identity: veil_proto::session::IdentityPayload {
                algo: 0,
                public_key: vec![0u8; 32],
                nonce: b"n".to_vec(),
                node_id: alice_peer,
                mlkem_pubkey: None,
            },
            remote_capabilities: veil_proto::session::CapabilitiesPayload {
                roles_supported: role_bits::CORE,
                flags: cap_flags::SUPPORTS_SOVEREIGN_IDENTITY,
                discovery_mode: 0,
            },
            remote_attach: veil_proto::session::AttachPayload {
                role: 1,
                realm_id: 0,
                attach_epoch: 0,
                mailbox_preference_count: 0,
                gateway_preference_count: 0,
                flags: 0,
            },
            remote_role: veil_session::RemoteRole::Core,
            validated_sovereign_identity: Some(ValidatedIdentity {
                node_id: alice_id,
                master_algo: 0,
                master_pubkey: vec![0u8; 32],
                active_identity_pubkey: vec![0u8; 32],
                active_identity_algo: 0,
                active_key_idx: 0,
                active_device_id: {
                    let mut d = [0u8; 32];
                    d[..16].copy_from_slice(&alice_instance);
                    d
                },
                active_instance_id: alice_instance,
            }),
        });

        // Build a forward addressed to Alice (Any instance).
        let envelope = DeliveryEnvelope {
            recipient: Recipient::any(alice_id),
            sender_node_id: sender_peer,
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id: [0x42; 32],
            created_at: 0,
            ttl_secs: 3600,
            payload: b"hi alice".to_vec(),
            trace_id: 0,
            require_ack: false,
        };
        let fwd = ForwardPayload {
            next_hop_node_id: alice_id, // not meaningful for sovereign path
            envelope,
            relay_hops: 0,
        };

        // Fire the fast-path directly.
        let sent = disp.try_sovereign_direct_forward(
            &fwd,
            NodeId::from(sender_peer),
            veil_proto::header::priority::INTERACTIVE,
            1,
        );
        assert!(sent, "sovereign fast-path should deliver directly");

        // A frame landed in Alice's outbox. PriorityFrame = (priority, bytes).
        let (priority, bytes) = frame_rx
            .try_recv()
            .expect("sovereign fast-path must have placed a frame in alice's outbox");
        assert_eq!(priority, veil_proto::header::priority::INTERACTIVE);
        assert!(!bytes.is_empty());
        // Frame is `header(24) || next_hop_node_id(32=alice_peer) || envelope || suffix(9)`.
        let hs = veil_proto::header::HEADER_SIZE;
        assert_eq!(
            &bytes[hs..hs + 32],
            &alice_peer[..],
            "frame's next_hop_node_id prefix must be alice_peer",
        );
    }

    #[test]
    fn try_sovereign_direct_forward_returns_false_without_registry() {
        // No session_registry wired → helper reports false without
        // touching session_tx_registry. Caller falls through to
        // legacy relay_forward.
        use veil_proto::delivery::{DeliveryEnvelope, ForwardPayload};
        use veil_proto::recipient::Recipient;

        let disp = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let envelope = DeliveryEnvelope {
            recipient: Recipient::any([0xAA; 32]),
            sender_node_id: [0xBB; 32],
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id: [0x42; 32],
            created_at: 0,
            ttl_secs: 3600,
            payload: b"x".to_vec(),
            trace_id: 0,
            require_ack: false,
        };
        let fwd = ForwardPayload {
            next_hop_node_id: [0xCC; 32],
            envelope,
            relay_hops: 0,
        };
        assert!(!disp.try_sovereign_direct_forward(
            &fwd,
            NodeId::from([0xBB; 32]),
            veil_proto::header::priority::INTERACTIVE,
            1,
        ));
    }

    #[test]
    fn try_sovereign_direct_forward_skips_self_and_sender() {
        // Split-horizon + self-loop: a resolved peer that equals the
        // sender_peer_id (split-horizon) or the local_node_id
        // (self-loop) MUST be skipped. When the only resolved peer
        // is filtered out, helper returns false.
        use veil_identity::verify::ValidatedIdentity;
        use veil_proto::delivery::{DeliveryEnvelope, ForwardPayload};
        use veil_proto::recipient::Recipient;
        use veil_proto::session::{cap_flags, role_bits};
        use veil_session::{SessionEntry, SessionRegistry};

        let sender_peer = [0xBBu8; 32];
        let mut disp = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        disp.local_node_id = [0xAAu8; 32];
        let reg = std::sync::Arc::new(std::sync::Mutex::new(SessionRegistry::new()));
        disp.session_registry = Some(std::sync::Arc::clone(&reg));

        // The only live session for `node_id` is via `sender_peer`
        // itself (split-horizon case). Helper must skip it.
        reg.lock().unwrap().insert(SessionEntry {
            session_id: [0x01; 32],
            remote_node_id: sender_peer,
            remote_identity: veil_proto::session::IdentityPayload {
                algo: 0,
                public_key: vec![0u8; 32],
                nonce: b"n".to_vec(),
                node_id: sender_peer,
                mlkem_pubkey: None,
            },
            remote_capabilities: veil_proto::session::CapabilitiesPayload {
                roles_supported: role_bits::CORE,
                flags: cap_flags::SUPPORTS_SOVEREIGN_IDENTITY,
                discovery_mode: 0,
            },
            remote_attach: veil_proto::session::AttachPayload {
                role: 1,
                realm_id: 0,
                attach_epoch: 0,
                mailbox_preference_count: 0,
                gateway_preference_count: 0,
                flags: 0,
            },
            remote_role: veil_session::RemoteRole::Core,
            validated_sovereign_identity: Some(ValidatedIdentity {
                node_id: [0x77; 32],
                master_algo: 0,
                master_pubkey: vec![0u8; 32],
                active_identity_pubkey: vec![0u8; 32],
                active_identity_algo: 0,
                active_key_idx: 0,
                active_device_id: [0x01; 32],
                active_instance_id: [0x01; 16],
            }),
        });

        let envelope = DeliveryEnvelope {
            recipient: Recipient::any([0x77; 32]),
            sender_node_id: sender_peer,
            src_app_id: [0u8; 32],
            app_id: [0u8; 32],
            endpoint_id: 0,
            content_id: [0x42; 32],
            created_at: 0,
            ttl_secs: 3600,
            payload: b"x".to_vec(),
            trace_id: 0,
            require_ack: false,
        };
        let fwd = ForwardPayload {
            next_hop_node_id: [0xCC; 32],
            envelope,
            relay_hops: 0,
        };
        assert!(!disp.try_sovereign_direct_forward(
            &fwd,
            NodeId::from(sender_peer),
            veil_proto::header::priority::INTERACTIVE,
            1,
        ));
    }

    #[test]
    fn resolve_sovereign_targets_empty_when_identity_offline() {
        use veil_proto::recipient::Recipient;
        use veil_session::SessionRegistry;

        let mut disp = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        let reg = std::sync::Arc::new(std::sync::Mutex::new(SessionRegistry::new()));
        disp.session_registry = Some(std::sync::Arc::clone(&reg));

        // No entries → registry is wired but reports empty for every
        // tag variant. Caller falls back to mailbox / DHT paths.
        assert_eq!(
            disp.resolve_sovereign_delivery_targets(&Recipient::any([0xAA; 32])),
            Some(vec![])
        );
        assert_eq!(
            disp.resolve_sovereign_delivery_targets(&Recipient::all([0xAA; 32])),
            Some(vec![])
        );
    }

    /// Regression test for audit batch 2026-05-23: source-routed relay
    /// must walk a 63-hop path end-to-end (worst-case diameter of the
    /// 64-node testnet linear topology, where node-0 → node-63).
    ///
    /// Verifies:
    /// * every intermediate hop increments `next_hop` by exactly 1
    /// * `path` is never mutated in transit
    /// * `inner` survives 63 wire roundtrips byte-for-byte
    /// * terminal hop calls `route_ipc_deliver` and the registered
    ///   endpoint receives the original payload
    /// * neither `Violation` nor `chain_broken` occurs along the chain
    ///
    /// Uses a single dispatcher instance per hop (cheap) by rewriting
    /// `local_node_id` between iterations and feeding the forwarded
    /// frame back in as the next hop's input.
    #[test]
    fn relay_path_63_hops_end_to_end() {
        use crate::DispatchResult;
        use crate::make_test_dispatcher;
        use std::sync::{Arc, RwLock};
        use veil_app::registry::AppMessage;
        use veil_proto::app::AppSendPayload;
        use veil_proto::codec::decode_header;
        use veil_proto::delivery::{MAX_RELAY_PATH_HOPS, RelayPathPayload};
        use veil_proto::family::{DeliveryMsg, FrameFamily};
        use veil_proto::header::{FrameHeader, HEADER_SIZE, priority};
        use veil_session::SessionTxRegistry;

        let sender_id = [0u8; 32];

        // path[i] = byte-distinct id with i+1 in byte 0 (matches node-1..node-63).
        let mut path: Vec<[u8; 32]> = Vec::with_capacity(63);
        for i in 1u8..=63 {
            let mut id = [0u8; 32];
            id[0] = i;
            path.push(id);
        }
        assert_eq!(path.len(), 63);
        assert!(
            path.len() <= MAX_RELAY_PATH_HOPS,
            "test assumes path fits in MAX_RELAY_PATH_HOPS={MAX_RELAY_PATH_HOPS}"
        );

        // Original inner payload (identifiable byte pattern).
        let inner_data: Vec<u8> = b"node-0 to node-63".to_vec();
        let dst_app_id = [0xBBu8; 32];
        let dst_endpoint_id = 0xC0DEu32;
        let inner_send = AppSendPayload {
            src_app_id: [0xAAu8; 32],
            app_id: dst_app_id,
            endpoint_id: dst_endpoint_id,
            data: veil_bufpool::pooled_shared_from_vec(inner_data.clone()),
        };
        let inner_bytes = inner_send.encode();

        // Initial relay frame body — next_hop=0 (node-0 hands off to path[0]).
        let initial_relay = RelayPathPayload {
            path: path.clone(),
            next_hop: 0,
            inner: inner_bytes.clone(),
        };
        let mut current_body: Vec<u8> = initial_relay.encode();

        // Single dispatcher instance reused across hops.  Each hop mutates
        // `local_node_id` so handle_relay_path's path-matching check passes.
        let mut disp = make_test_dispatcher(veil_cfg::NodeRole::Core);
        let tx_reg = Arc::new(RwLock::new(SessionTxRegistry::new()));

        // Register all 63 path entries upfront so forward sends never miss.
        let mut rxs: Vec<tokio::sync::mpsc::Receiver<(u8, veil_bufpool::PooledShared)>> =
            Vec::with_capacity(63);
        {
            let mut reg = tx_reg.write().unwrap();
            for id in &path {
                rxs.push(reg.register(*id));
            }
        }
        disp.session_tx_registry = Some(Arc::clone(&tx_reg));

        // Register an endpoint on the dispatcher's app_registry so the
        // terminal hop's `route_ipc_deliver` call lands in a receiver we
        // can drain. `_endpoint_handle` MUST stay in scope (drop unregisters).
        let (_endpoint_handle, mut endpoint_rx) =
            disp.app_registry.register(dst_app_id, dst_endpoint_id, 16);

        for i in 0..63usize {
            disp.local_node_id = path[i];

            let mut hdr =
                FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::RelayPath as u16);
            hdr.body_len = current_body.len() as u32;

            let result = disp.dispatch(&hdr, &current_body, sender_id);
            assert!(
                matches!(result, DispatchResult::NoResponse),
                "hop {i}: expected NoResponse, got {result:?}",
            );

            if i == 62 {
                // Terminal hop — endpoint must have received Deliver with
                // original byte-pattern intact.
                let msg = endpoint_rx
                    .try_recv()
                    .expect("terminal hop must enqueue Deliver");
                match msg {
                    AppMessage::Deliver {
                        app_id,
                        endpoint_id,
                        data,
                        ..
                    } => {
                        assert_eq!(app_id, dst_app_id);
                        assert_eq!(endpoint_id, dst_endpoint_id);
                        assert_eq!(
                            data.as_ref(),
                            inner_data.as_slice(),
                            "inner payload corrupted across 63 hops",
                        );
                    }
                    other => panic!("expected AppMessage::Deliver, got {other:?}"),
                }

                // Non-terminal receiver must NOT have received anything
                // (terminal calls route_ipc_deliver, not session_tx).
                assert!(
                    rxs[i].try_recv().is_err(),
                    "terminal hop must not forward via session_tx",
                );
            } else {
                // Intermediate hop — receiver for path[i+1] gets the
                // forwarded frame.
                let (prio, frame) = rxs[i + 1].try_recv().unwrap_or_else(|e| {
                    panic!("hop {i}: expected forward to rxs[{}], got {e:?}", i + 1)
                });
                assert_eq!(
                    prio,
                    priority::INTERACTIVE,
                    "hop {i}: forwarded frame must use INTERACTIVE priority"
                );

                // Strip 24-byte header; decode body as RelayPathPayload.
                assert!(
                    frame.len() > HEADER_SIZE,
                    "hop {i}: forwarded frame too short",
                );
                let new_hdr = decode_header(&frame[..HEADER_SIZE])
                    .expect("forwarded frame must carry a valid header");
                assert_eq!(new_hdr.family, FrameFamily::Delivery as u8);
                assert_eq!(new_hdr.msg_type, DeliveryMsg::RelayPath as u16);

                let body_slice = &frame[HEADER_SIZE..];
                let forwarded = RelayPathPayload::decode(body_slice)
                    .expect("forwarded body must decode as RelayPathPayload");
                assert_eq!(
                    forwarded.next_hop as usize,
                    i + 1,
                    "hop {i}: forwarded next_hop must equal i+1",
                );
                assert_eq!(
                    forwarded.path, path,
                    "hop {i}: path must not be mutated in transit",
                );
                assert_eq!(
                    forwarded.inner, inner_bytes,
                    "hop {i}: inner must be preserved byte-for-byte",
                );

                // Feed forwarded body back in as next hop's input.
                current_body = body_slice.to_vec();
            }
        }
    }
}
