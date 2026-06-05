use super::{DispatchResult, FrameDispatcher, encode_response};
use veil_cfg::NodeId;
use veil_proto::{
    family::{FrameFamily, SessionMsg},
    header::FrameHeader,
    session::{AttachPayload, DetachPayload, KeepalivePayload, SleepAdvertisementPayload},
};
use veil_util::hex_short;
use veil_util::lock;

impl FrameDispatcher {
    pub fn dispatch_session_post_handshake(
        &self,
        header: &FrameHeader,
        body: &[u8],
        node_id: NodeId,
    ) -> DispatchResult {
        let msg = match SessionMsg::try_from(header.msg_type) {
            Ok(m) => m,
            Err(_) => return DispatchResult::NotHandled,
        };

        match msg {
            SessionMsg::Attach => {
                let payload = match AttachPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad Attach: {e}")),
                };
                if let Err(e) = self.gateway.handle_attach(*node_id.as_bytes(), &payload) {
                    return DispatchResult::Violation(format!("Attach rejected: {e}"));
                }
                DispatchResult::NoResponse
            }

            SessionMsg::Detach => {
                let payload = match DetachPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad Detach: {e}")),
                };
                let _ = self.gateway.handle_detach(node_id.as_bytes(), &payload);
                DispatchResult::NoResponse
            }

            SessionMsg::Keepalive => {
                let payload = match KeepalivePayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => return DispatchResult::Violation(format!("bad Keepalive: {e}")),
                };
                if let Err(e) = self.gateway.handle_keepalive(node_id.as_bytes(), &payload) {
                    self.logger.warn(
                        "dispatcher.keepalive",
                        format!(
                            "peer_id={} keepalive rejected: {e}",
                            hex_short(node_id.as_bytes())
                        ),
                    );
                }
                // Echo keepalive back
                DispatchResult::Response(encode_response(
                    header,
                    FrameFamily::Session as u8,
                    SessionMsg::Keepalive as u16,
                    &payload.encode(),
                ))
            }

            SessionMsg::SleepAdvertisement => {
                // a peer tells us it is about to go offline and
                // expects to wake up at `expected_wake_ts`. Mailbox hosts
                // (Gateway/Core) extend per-recipient retention so queued
                // messages survive the sleep window.
                let payload = match SleepAdvertisementPayload::decode(body) {
                    Ok(p) => p,
                    Err(e) => {
                        return DispatchResult::Violation(format!("bad SleepAdvertisement: {e}"));
                    }
                };

                // The announced `node_id` must match the authenticated peer —
                // no third-party sleep spoofing.
                if &payload.node_id != node_id.as_bytes() {
                    return DispatchResult::Violation(format!(
                        "SleepAdvertisement: node_id {} does not match peer_id {}",
                        hex_short(&payload.node_id),
                        hex_short(node_id.as_bytes()),
                    ));
                }

                // Verify the signature against the cached peer public key.
                // The cache is populated by the OVL1 handshake, so the key
                // is always available here.
                {
                    let cache = lock!(self.crypto.peer_pubkeys);
                    let (algo_byte, pubkey_bytes) = match cache.get(node_id.as_bytes()) {
                        Some(entry) => entry,
                        None => {
                            return DispatchResult::Violation(format!(
                                "SleepAdvertisement: no pubkey cached for peer_id={}",
                                hex_short(node_id.as_bytes()),
                            ));
                        }
                    };
                    let algo = if *algo_byte == 2 {
                        veil_cfg::SignatureAlgorithm::Falcon512
                    } else {
                        veil_cfg::SignatureAlgorithm::Ed25519
                    };
                    use base64::{Engine as _, engine::general_purpose::STANDARD};
                    let pk_b64 = STANDARD.encode(pubkey_bytes);
                    let body_bytes = payload.signable_bytes();
                    if veil_crypto::verify_message(algo, &pk_b64, &body_bytes, &payload.signature)
                        .is_err()
                    {
                        return DispatchResult::Violation(format!(
                            "SleepAdvertisement: invalid signature from peer_id={}",
                            hex_short(node_id.as_bytes()),
                        ));
                    }
                }

                // Reject stale announcements: `issued_at_ts` must not be in
                // the distant past (replay) or the distant future (clock attack).
                // `expected_wake_ts` must not be in the past.
                use std::time::{SystemTime, UNIX_EPOCH};
                let now_unix = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                // **Sleep tier** — mobile/sleeping device may have been
                // offline (airplane mode) just before issuing this ad,
                // so we tolerate а 10-min stale clock.  Pinned к central
                // policy
                // [`veil_proto::time_validity::SLEEP_SKEW_SECS`].
                const MAX_ISSUED_SKEW_SECS: u64 = veil_proto::time_validity::SLEEP_SKEW_SECS;
                // saturating_add so attacker-controlled issued_at_ts near u64::MAX
                // can't overflow past the check; now_unix + MAX_ISSUED_SKEW_SECS
                // only matters past year 2584 but guarded for the same reason.
                if payload.issued_at_ts.saturating_add(MAX_ISSUED_SKEW_SECS) < now_unix
                    || payload.issued_at_ts > now_unix.saturating_add(MAX_ISSUED_SKEW_SECS)
                {
                    return DispatchResult::Violation(format!(
                        "SleepAdvertisement: issued_at_ts {} out of acceptable window (now={})",
                        payload.issued_at_ts, now_unix,
                    ));
                }
                if payload.expected_wake_ts <= now_unix {
                    return DispatchResult::Violation(format!(
                        "SleepAdvertisement: expected_wake_ts {} must be in the future (now={})",
                        payload.expected_wake_ts, now_unix,
                    ));
                }

                // SleepAdvertisement no longer extends mailbox
                // retention (mailbox subsystem removed). We still accept
                // the frame for back-compat and bump the metric so observability
                // reflects the peer's intent.
                let _ = (node_id, payload.expected_wake_ts);
                if let Some(metrics) = &self.metrics {
                    metrics.inc_sleep_advertisements_accepted();
                }
                DispatchResult::NoResponse
            }

            // Handshake messages (HELLO..SESSION_CONFIRM) are not handled here.
            _ => DispatchResult::NotHandled,
        }
    }
}
