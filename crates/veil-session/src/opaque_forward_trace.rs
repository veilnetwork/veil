//! Opt-in, role-blind correlation of bounded opaque forwarding payloads.
//! No payload bytes, keys, RTP metadata or application classes are retained.
//! These local observations never select admission, priority or a transport.

use sha2::{Digest, Sha256};
use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};
use veil_proto::{
    delivery::{ForwardPayload, RecursiveRelayPayload},
    header::FrameHeader,
};

const MAX_BODY: usize = 8192;
const ROW_LIMIT: u64 = 524_288;
static ENABLED: OnceLock<bool> = OnceLock::new();
static ROWS: AtomicU64 = AtomicU64::new(0);

pub fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        veil_util::operator_trace::enabled(
            "VEIL_DIAG_OPAQUE_FORWARD",
            c"debug.xveil.opaque_forward",
        )
    })
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
    wrapper: &'static str,
}

fn sample(header: &FrameHeader, body: &[u8]) -> Option<Sample> {
    if header.family != veil_proto::family::FrameFamily::Delivery as u8 || body.len() > MAX_BODY {
        return None;
    }
    // One bounded routing wrapper only. RecursiveRelay carries an ordinary
    // ForwardPayload, not another frame: do not recursively follow untrusted
    // wrappers or interpret application/cryptographic payload formats.
    let (forward, wrapper) = match header.msg_type {
        n if n == veil_proto::family::DeliveryMsg::Forward as u16 => {
            (ForwardPayload::decode(body).ok()?, "forward")
        }
        n if n == veil_proto::family::DeliveryMsg::RecursiveRelay as u16 => {
            let recursive = RecursiveRelayPayload::decode(body).ok()?;
            (
                ForwardPayload::decode(&recursive.payload).ok()?,
                "recursive",
            )
        }
        _ => return None,
    };
    Some(Sample {
        digest: digest(&forward.envelope.payload)?,
        bytes: forward.envelope.payload.len(),
        wrapper,
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
        "delivery.opaque_trace stage={stage} monotonic_us={monotonic_us} node={} peer={} opaque_bytes={} opaque_sha256={} wrapper={}",
        veil_util::hex_str(&node[..4]),
        veil_util::hex_str(&peer[..4]),
        sample.bytes,
        sample.digest,
        sample.wrapper,
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

pub(crate) enum OrderedStage {
    SendAttempt,
    AuthenticatedFrame,
}

/// Link an opaque Forward to an encrypted ordered fragment. A send attempt is
/// not admission or delivery. On receive, this is the final fragment of an
/// authenticated, eligible frame, not proof of application delivery.
/// Both independent operator gates are required; nothing travels on the wire.
pub(crate) fn ordered_fragment(
    stage: OrderedStage,
    node: Option<&[u8; 32]>,
    peer: &[u8; 32],
    frame: &[u8],
    child: u64,
    fragment: &[u8],
) {
    if !enabled() || ROWS.load(Ordering::Relaxed) > ROW_LIMIT {
        return;
    }
    let Some(record_digest) = veil_transport::ordered_record_trace::fingerprint(fragment) else {
        return;
    };
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
    let Some(sample) = sample(&header, body) else {
        return;
    };
    let row = ROWS.fetch_add(1, Ordering::Relaxed);
    if row == ROW_LIMIT {
        log::info!("delivery.opaque_trace_limit rows={ROW_LIMIT}");
    }
    if row >= ROW_LIMIT {
        return;
    }
    let monotonic_us = veil_util::diagnostic_clock::monotonic_us().map_or(-1, i128::from);
    let stage = match stage {
        OrderedStage::SendAttempt => "send_attempt",
        OrderedStage::AuthenticatedFrame => "authenticated_frame",
    };
    log::info!(
        "delivery.opaque_record stage={stage} monotonic_us={monotonic_us} node={} peer={} opaque_sha256={} child_local={child} record_bytes={} record_sha256={record_digest}",
        node.map_or_else(|| "-".to_owned(), |node| veil_util::hex_str(&node[..4])),
        veil_util::hex_str(&peer[..4]),
        sample.digest,
        fragment.len(),
    );
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
    fn ordered_fragment_link_requires_both_operator_gates() {
        const CHILD: &str = "VEIL_TEST_OPAQUE_RECORD_LINK";
        if let Ok(expected) = std::env::var(CHILD) {
            static EVENTS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
            struct Sink;
            impl log::Log for Sink {
                fn enabled(&self, _: &log::Metadata<'_>) -> bool {
                    true
                }
                fn log(&self, r: &log::Record<'_>) {
                    if r.target().ends_with("opaque_forward_trace") {
                        EVENTS.lock().unwrap().push(r.args().to_string());
                    }
                }
                fn flush(&self) {}
            }
            static SINK: Sink = Sink;
            log::set_logger(&SINK).unwrap();
            log::set_max_level(log::LevelFilter::Info);
            let secret = b"PRIVATE_OPAQUE_PAYLOAD";
            let wire = b"PRIVATE_ENCRYPTED_RECORD";
            let body = forward(secret.to_vec()).encode();
            let mut h = header();
            h.body_len = body.len() as u32;
            let mut frame = veil_proto::codec::encode_header(&h).to_vec();
            frame.extend_from_slice(&body);
            ordered_fragment(
                OrderedStage::SendAttempt,
                Some(&[1; 32]),
                &[2; 32],
                &frame,
                7,
                wire,
            );
            let rows = EVENTS.lock().unwrap().clone();
            if expected == "1" {
                assert_eq!(rows.len(), 1);
                assert!(rows[0].contains(&format!("opaque_sha256={}", digest(secret).unwrap())));
                assert!(rows[0].contains(&format!(
                    "record_sha256={}",
                    veil_transport::ordered_record_trace::fingerprint(wire).unwrap()
                )));
                assert!(rows[0].contains("child_local=7 "));
                assert!(rows[0].contains("stage=send_attempt "));
                assert!(!rows[0].contains("PRIVATE_"));
                ordered_fragment(
                    OrderedStage::AuthenticatedFrame,
                    None,
                    &[2; 32],
                    &frame,
                    8,
                    wire,
                );
                assert!(EVENTS.lock().unwrap()[1].contains("stage=authenticated_frame "));
                assert!(EVENTS.lock().unwrap()[1].contains("node=- "));
                // Unknown/truncated frames and unbounded records cannot
                // create links from arbitrary bytes in an enabled capture.
                ordered_fragment(
                    OrderedStage::SendAttempt,
                    Some(&[1; 32]),
                    &[2; 32],
                    &frame[..frame.len() - 1],
                    7,
                    wire,
                );
                ordered_fragment(
                    OrderedStage::SendAttempt,
                    Some(&[1; 32]),
                    &[2; 32],
                    &frame,
                    7,
                    &vec![0; 1201],
                );
                assert_eq!(EVENTS.lock().unwrap().len(), 2);
            } else {
                assert!(rows.is_empty());
            }
            return;
        }
        for (opaque, records, expected) in [
            ("0", "0", "0"),
            ("1", "0", "0"),
            ("0", "1", "0"),
            ("1", "1", "1"),
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "opaque_forward_trace::tests::ordered_fragment_link_requires_both_operator_gates", "--nocapture"])
                .env(CHILD, expected)
                .env("VEIL_DIAG_OPAQUE_FORWARD", opaque)
                .env("VEIL_DIAG_ORDERED_RECORDS", records)
                .output().unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
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

    fn recursive_header() -> FrameHeader {
        FrameHeader::new(
            veil_proto::family::FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::RecursiveRelay as u16,
        )
    }

    fn recursive_body(inner: Vec<u8>) -> Vec<u8> {
        veil_proto::delivery::RecursiveRelayPayload {
            dst_node_id: [9; 32],
            originator_pseudonym: [8; 32],
            query_id: 7,
            hop_count: 6,
            payload: inner,
        }
        .encode()
    }

    #[test]
    fn payload_identity_survives_recursive_relay_wrapping() {
        let mut f = forward(vec![0x51; 235]);
        let first = sample(&header(), &f.encode()).unwrap();
        let wrapped = recursive_body(f.encode());
        let next = sample(&recursive_header(), &wrapped)
            .expect("recursive transport must retain the opaque correlation witness");
        assert_eq!(first.digest, next.digest);
        assert_eq!(first.bytes, next.bytes);
        assert_eq!(first.wrapper, "forward");
        assert_eq!(next.wrapper, "recursive");
        f.envelope.payload[100] ^= 1;
        assert_ne!(
            first.digest,
            sample(&recursive_header(), &recursive_body(f.encode()))
                .unwrap()
                .digest,
        );
    }

    #[test]
    fn recursive_observation_is_bounded_and_decodes_one_wrapper_only() {
        let wrapped = recursive_body(forward(vec![0x51; 235]).encode());
        for end in 0..wrapped.len() {
            assert!(sample(&recursive_header(), &wrapped[..end]).is_none());
        }
        assert!(sample(&recursive_header(), &recursive_body(vec![0; MAX_BODY])).is_none());
        assert!(sample(&recursive_header(), &recursive_body(vec![])).is_none());
        assert!(sample(&recursive_header(), &recursive_body(wrapped)).is_none());
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
