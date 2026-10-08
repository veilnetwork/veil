//! Packetization of endpoint-owned envelopes. Never used by relay forwarding.

use rand_core::RngCore;
use veil_proto::delivery::{ChunkedEnvelopePayload, DeliveryEnvelope, ForwardPayload};
use veil_proto::family::{DeliveryMsg, FrameFamily};
use veil_proto::{FrameHeader, codec};

/// Advice comes only from the origin's local registry. Preserve canonical
/// fallback for old adapters and large payloads: smaller pieces must never
/// make an otherwise valid transfer exceed the receiver's chunk limit.
pub(super) fn source_segment_bytes(reg: &dyn veil_types::FrameBroadcaster, bytes: usize) -> usize {
    let canonical = veil_proto::budget::LOCAL_ENVELOPE_SEGMENT_DATA_BYTES;
    match reg
        .local_source_segment_data_bytes()
        .filter(|hint| *hint > 0)
    {
        None => canonical,
        Some(hint) => hint
            .max(bytes.div_ceil(veil_proto::budget::MAX_TRANSFER_CHUNKS as usize))
            .min(canonical),
    }
}

pub(super) struct EnvelopeChunks<'a> {
    envelope: &'a DeliveryEnvelope,
    transfer_id: [u8; 16],
    require_ack: bool,
    segment_size: usize,
    chunk_count: u32,
}

impl<'a> EnvelopeChunks<'a> {
    pub(super) fn new(
        envelope: &'a DeliveryEnvelope,
        require_ack: bool,
        segment_size: usize,
    ) -> Option<Self> {
        use veil_proto::budget::{MAX_REASSEMBLY_BYTES, MAX_TRANSFER_CHUNKS};
        if segment_size == 0 || envelope.payload.is_empty() {
            return None;
        }
        let count = envelope.payload.len().div_ceil(segment_size);
        if envelope.payload.len() > MAX_REASSEMBLY_BYTES || count > MAX_TRANSFER_CHUNKS as usize {
            return None;
        }
        let mut transfer_id = [0; 16];
        rand_core::OsRng.fill_bytes(&mut transfer_id);
        Some(Self {
            envelope,
            transfer_id,
            require_ack,
            segment_size,
            chunk_count: count as u32,
        })
    }

    pub(super) fn direct_app_frames(&self) -> impl Iterator<Item = Vec<u8>> + '_ {
        self.envelope
            .payload
            .chunks(self.segment_size)
            .enumerate()
            .map(move |(index, data)| {
                let body = veil_proto::app::AppSendPayload {
                    src_app_id: self.envelope.src_app_id,
                    app_id: self.envelope.app_id,
                    endpoint_id: self.envelope.endpoint_id,
                    data: veil_bufpool::pooled_shared_from_vec(self.chunk_payload(index, data)),
                }
                .encode();
                let mut header = FrameHeader::new(
                    FrameFamily::App as u8,
                    veil_proto::family::AppMsg::AppSendChunk as u16,
                );
                header.set_priority(veil_proto::priority::INTERACTIVE);
                header.body_len = body.len() as u32;
                let mut frame = codec::encode_header(&header).to_vec();
                frame.extend(body);
                frame
            })
    }

    fn chunk_payload(&self, index: usize, data: &[u8]) -> Vec<u8> {
        ChunkedEnvelopePayload {
            transfer_id: self.transfer_id,
            chunk_index: index as u32,
            chunk_count: self.chunk_count,
            total_size: self.envelope.payload.len() as u32,
            orig_content_id: self.envelope.content_id,
            require_ack: self.require_ack,
            data: data.to_vec(),
        }
        .encode()
    }

    pub(super) fn frames_for(&self, next_hop: [u8; 32]) -> impl Iterator<Item = Vec<u8>> + '_ {
        self.envelope
            .payload
            .chunks(self.segment_size)
            .enumerate()
            .map(move |(index, data)| {
                let mut content_id = [0; 32];
                rand_core::OsRng.fill_bytes(&mut content_id);
                let envelope = DeliveryEnvelope {
                    recipient: self.envelope.recipient,
                    sender_node_id: self.envelope.sender_node_id,
                    src_app_id: self.envelope.src_app_id,
                    app_id: self.envelope.app_id,
                    endpoint_id: self.envelope.endpoint_id,
                    content_id,
                    created_at: self.envelope.created_at,
                    ttl_secs: self.envelope.ttl_secs,
                    payload: self.chunk_payload(index, data),
                    trace_id: self.envelope.trace_id,
                    require_ack: false,
                };
                let body = ForwardPayload {
                    next_hop_node_id: next_hop,
                    envelope,
                    relay_hops: 0,
                    delivery_attempt: None,
                    traffic_class: None,
                }
                .encode();
                let mut header =
                    FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
                header.set_priority(veil_proto::priority::INTERACTIVE);
                header.body_len = body.len() as u32;
                let mut frame = codec::encode_header(&header).to_vec();
                frame.extend(body);
                frame
            })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum DirectAdmission {
    Accepted,
    Missing,
    TimedOut,
    Rejected,
}

/// The caller has already verified which device the ciphertext is keyed to.
/// Use existing Forward/chunk framing on that very session, not a third party.
/// Direct sends retain their existing source-admission reply semantics; they
/// do not acquire a new E2E ACK/retry protocol as a side effect of packetization.
pub(super) async fn admit_direct_sealed(
    ctx: &super::IpcSendContext,
    send: &veil_proto::AppIpcSendPayload,
    device: [u8; 32],
    sealed: &[u8],
    deadline: tokio::time::Instant,
) -> DirectAdmission {
    let Some(reg) = ctx.session_tx_registry.as_deref() else {
        return DirectAdmission::Missing;
    };
    let Some((_, instance)) = veil_e2e::payload_instances(sealed) else {
        return DirectAdmission::Rejected;
    };
    let pairing = ctx
        .session_instance_lookup
        .as_deref()
        .and_then(|lookup| lookup.session_pairing(&device));
    if device != send.dst_node_id
        && pairing.is_some_and(|pairing| pairing.identity != send.dst_node_id)
    {
        return DirectAdmission::Rejected;
    }
    let recipient = match pairing {
        Some(pairing) if pairing.instance == instance => {
            veil_proto::recipient::Recipient::specific(pairing.identity, instance)
        }
        Some(_) => return DirectAdmission::Missing,
        None => veil_proto::recipient::Recipient::any(device),
    };
    let mut content_id = [0; 32];
    rand_core::OsRng.fill_bytes(&mut content_id);
    let envelope = DeliveryEnvelope {
        recipient,
        sender_node_id: ctx.local_node_id,
        src_app_id: send.src_app_id,
        app_id: send.app_id,
        endpoint_id: send.endpoint_id,
        content_id,
        created_at: veil_util::unix_secs_now_u64(),
        ttl_secs: 30,
        payload: sealed.to_vec(),
        trace_id: 0,
        require_ack: false,
    };
    let Some(chunks) = EnvelopeChunks::new(
        &envelope,
        false,
        source_segment_bytes(reg, envelope.payload.len()),
    ) else {
        return DirectAdmission::Rejected;
    };
    match tokio::time::timeout_at(deadline, async {
        for frame in chunks.frames_for(device) {
            if !reg.send_reliable_to(&device, frame).await {
                return false;
            }
        }
        true
    })
    .await
    {
        Ok(true) => DirectAdmission::Accepted,
        Ok(false) => DirectAdmission::Missing,
        Err(_) => DirectAdmission::TimedOut,
    }
}

/// Arbitrary application bytes use an explicit App family type. This path is
/// direct only; it never acquires encrypted-envelope semantics or relay authority.
pub(super) async fn admit_direct_plain(
    ctx: &super::IpcSendContext,
    send: &veil_proto::AppIpcSendPayload,
    device: [u8; 32],
    deadline: tokio::time::Instant,
) -> DirectAdmission {
    let Some(reg) = ctx.session_tx_registry.as_deref() else {
        return DirectAdmission::Missing;
    };
    let supports = || {
        ctx.session_instance_lookup
            .as_deref()
            .is_some_and(|lookup| lookup.supports_direct_app_chunks(&device))
    };
    if !supports() {
        return DirectAdmission::Missing;
    }
    let mut content_id = [0; 32];
    rand_core::OsRng.fill_bytes(&mut content_id);
    let envelope = DeliveryEnvelope {
        recipient: veil_proto::recipient::Recipient::any(send.dst_node_id),
        sender_node_id: ctx.local_node_id,
        src_app_id: send.src_app_id,
        app_id: send.app_id,
        endpoint_id: send.endpoint_id,
        content_id,
        created_at: 0,
        ttl_secs: 0,
        payload: send.data.to_vec(),
        trace_id: 0,
        require_ack: false,
    };
    let Some(chunks) = EnvelopeChunks::new(
        &envelope,
        false,
        source_segment_bytes(reg, envelope.payload.len()),
    ) else {
        return DirectAdmission::Rejected;
    };
    match tokio::time::timeout_at(deadline, async {
        for frame in chunks.direct_app_frames() {
            if device != send.dst_node_id
                && !super::device_matches_identity(ctx, &device, &send.dst_node_id)
            {
                return DirectAdmission::Rejected;
            }
            if !supports() || !reg.send_direct_app_chunk_to(&device, frame).await {
                return DirectAdmission::Missing;
            }
        }
        DirectAdmission::Accepted
    })
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => DirectAdmission::TimedOut,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, RwLock};

    #[test]
    fn smaller_origin_chunks_preserve_wire_budget_and_large_transfer_bounds() {
        let registry = Arc::new(RwLock::new(veil_session::SessionTxRegistry::new()));
        let source = veil_session::glue::SessionTxBroadcaster::new(registry.clone());
        assert_eq!(source_segment_bytes(&source, 12000), 3600);
        registry
            .read()
            .unwrap()
            .note_local_source_feedback(false, std::time::Instant::now());
        let bytes = vec![0xa5; 12000];
        let envelope = DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any([1; 32]),
            sender_node_id: [2; 32],
            src_app_id: [3; 32],
            app_id: [4; 32],
            endpoint_id: 7,
            content_id: [5; 32],
            created_at: 123,
            ttl_secs: 30,
            payload: bytes.clone(),
            trace_id: 0,
            require_ack: false,
        };
        let chunks =
            EnvelopeChunks::new(&envelope, false, source_segment_bytes(&source, bytes.len()))
                .unwrap();
        let mut reassembled = Vec::new();
        for (index, frame) in chunks.frames_for([6; 32]).enumerate() {
            // Reserve the 16-byte hop AEAD tag: each new piece stays below a typical
            // datagram payload rather than sending a multi-packet burst.
            assert!(frame.len() + 16 <= 1200);
            let header = codec::decode_header(&frame).unwrap();
            assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
            let forward =
                ForwardPayload::decode(&frame[veil_proto::header::HEADER_SIZE..]).unwrap();
            assert_eq!(forward.traffic_class, None);
            let chunk = ChunkedEnvelopePayload::decode(&forward.envelope.payload).unwrap();
            assert_eq!(chunk.chunk_index, index as u32);
            reassembled.extend_from_slice(&chunk.data);
        }
        assert_eq!(reassembled, bytes);
        let largest = veil_proto::budget::LOCAL_ENVELOPE_SEGMENT_DATA_BYTES
            * veil_proto::budget::MAX_TRANSFER_CHUNKS as usize;
        let segment = source_segment_bytes(&source, largest);
        assert!(largest.div_ceil(segment) <= veil_proto::budget::MAX_TRANSFER_CHUNKS as usize);
        assert_eq!(segment, 3600);
    }
}
