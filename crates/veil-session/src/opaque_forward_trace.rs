//! Opt-in, role-blind correlation of bounded opaque Forward payloads.
//! No payload bytes, keys, RTP metadata or application classes are retained.
//! These local observations never select admission, priority or a transport.

use sha2::{Digest, Sha256};
use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};
use veil_proto::{delivery::ForwardPayload, header::FrameHeader};

const MAX_BODY: usize = 8192;
const ROW_LIMIT: u64 = 524_288;
static ENABLED: OnceLock<bool> = OnceLock::new();
static ROWS: AtomicU64 = AtomicU64::new(0);

pub fn enabled() -> bool {
    *ENABLED.get_or_init(|| std::env::var("VEIL_DIAG_OPAQUE_FORWARD").is_ok_and(|v| v == "1"))
}

fn digest(payload: &[u8]) -> Option<String> {
    if payload.is_empty() || payload.len() > MAX_BODY {
        return None;
    }
    Some(veil_util::hex_str(&Sha256::digest(payload)))
}

/// Join an endpoint's already authenticated opaque bytes to generic forwarding
/// observations. Does not interpret or require a ciphertext format/marker.
pub fn payload_digest(payload: &[u8]) -> Option<String> {
    enabled().then(|| digest(payload)).flatten()
}

struct Sample {
    digest: String,
    bytes: usize,
}

fn sample(header: &FrameHeader, body: &[u8]) -> Option<Sample> {
    if header.family != veil_proto::family::FrameFamily::Delivery as u8
        || header.msg_type != veil_proto::family::DeliveryMsg::Forward as u16
        || body.len() > MAX_BODY
    {
        return None;
    }
    // Use the normal bounded Forward decoder, including its extension policy.
    // Payload contents and sender traffic hints never select these records.
    let forward = ForwardPayload::decode(body).ok()?;
    Some(Sample {
        digest: digest(&forward.envelope.payload)?,
        bytes: forward.envelope.payload.len(),
    })
}

fn record(stage: &str, node: &[u8; 32], peer: &[u8; 32], sample: &Sample) {
    let row = ROWS.fetch_add(1, Ordering::Relaxed);
    if row == ROW_LIMIT {
        log::info!("delivery.opaque_trace_limit rows={ROW_LIMIT}");
    }
    if row >= ROW_LIMIT {
        return;
    }
    let monotonic_us = veil_util::diagnostic_clock::monotonic_us().map_or(-1, i128::from);
    log::info!(
        "delivery.opaque_trace stage={stage} monotonic_us={monotonic_us} node={} peer={} opaque_bytes={} opaque_sha256={}",
        veil_util::hex_str(&node[..4]),
        veil_util::hex_str(&peer[..4]),
        sample.bytes,
        sample.digest,
    );
}

/// Bracket synchronous dispatch, including early returns. A return observation
/// can follow downstream work already admitted by dispatch; it is not a send.
pub struct Receive {
    node: [u8; 32],
    peer: [u8; 32],
    sample: Sample,
}

impl Drop for Receive {
    fn drop(&mut self) {
        record("dispatch_return", &self.node, &self.peer, &self.sample);
    }
}

pub fn receive(
    node: &[u8; 32],
    peer: &[u8; 32],
    header: &FrameHeader,
    body: &[u8],
) -> Option<Receive> {
    if !enabled() || ROWS.load(Ordering::Relaxed) > ROW_LIMIT {
        return None;
    }
    let sample = sample(header, body)?;
    record("dispatch_enter", node, peer, &sample);
    Some(Receive {
        node: *node,
        peer: *peer,
        sample,
    })
}

/// Called at existing transport capture sites after ordinary queue selection.
/// Does not promise DATAGRAM acceptance or wire send.
pub fn selected(node: &[u8; 32], peer: &[u8; 32], frame: &[u8]) {
    if !enabled() || ROWS.load(Ordering::Relaxed) > ROW_LIMIT {
        return;
    }
    let Ok(header) = veil_proto::codec::decode_header(frame) else {
        return;
    };
    let Some(body) = frame.get(veil_proto::header::HEADER_SIZE..) else {
        return;
    };
    if usize::from(header.header_len) != veil_proto::header::HEADER_SIZE
        || header.body_len as usize != body.len()
    {
        return;
    }
    if let Some(sample) = sample(&header, body) {
        record("transport_selected", node, peer, &sample);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::delivery::DeliveryEnvelope;

    fn forward(payload: Vec<u8>) -> ForwardPayload {
        ForwardPayload {
            next_hop_node_id: [1; 32],
            relay_hops: 1,
            delivery_attempt: None,
            traffic_class: None,
            envelope: DeliveryEnvelope {
                recipient: veil_proto::recipient::Recipient::any([2; 32]),
                sender_node_id: [3; 32],
                src_app_id: [4; 32],
                app_id: [5; 32],
                endpoint_id: 6,
                content_id: [7; 32],
                created_at: 8,
                ttl_secs: 30,
                payload,
                trace_id: 9,
                require_ack: false,
            },
        }
    }

    fn header() -> FrameHeader {
        FrameHeader::new(
            veil_proto::family::FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        )
    }

    #[test]
    fn payload_identity_survives_outer_routing_and_hint_changes() {
        let mut f = forward(vec![0x51; 235]);
        let first = sample(&header(), &f.encode()).unwrap();
        f.next_hop_node_id = [11; 32];
        f.relay_hops = 0;
        f.traffic_class = Some(veil_proto::priority::REALTIME);
        f.delivery_attempt = Some(1);
        let later = sample(&header(), &f.encode()).unwrap();
        assert_eq!(first.digest, later.digest);
        assert_eq!(first.bytes, 235);
        f.envelope.payload[100] ^= 1;
        assert_ne!(first.digest, sample(&header(), &f.encode()).unwrap().digest);
    }

    #[test]
    fn arbitrary_payload_formats_are_not_media_classifiers() {
        for bytes in [vec![0x17; 100], vec![0; 300], b"VME1".repeat(100)] {
            let f = forward(bytes.clone());
            assert_eq!(
                sample(&header(), &f.encode()).unwrap().digest,
                digest(&bytes).unwrap()
            );
        }
    }

    #[test]
    fn malformed_and_unbounded_envelopes_have_no_observation() {
        let body = forward(vec![0x51; 235]).encode();
        for end in 0..body.len() {
            assert!(sample(&header(), &body[..end]).is_none());
        }
        let expected = sample(&header(), &body).unwrap().digest;
        let mut extra = body;
        extra.push(0xff);
        // The protocol decoder tolerates unknown future outer trailers.
        assert_eq!(sample(&header(), &extra).unwrap().digest, expected);
        assert!(sample(&header(), &forward(vec![1; MAX_BODY]).encode()).is_none());
        assert!(sample(&header(), &forward(vec![]).encode()).is_none());
        assert!(digest(&vec![0; MAX_BODY + 1]).is_none());
        let wrong = FrameHeader::new(veil_proto::family::FrameFamily::App as u8, 1);
        assert!(sample(&wrong, &forward(vec![1; 100]).encode()).is_none());
    }
}
