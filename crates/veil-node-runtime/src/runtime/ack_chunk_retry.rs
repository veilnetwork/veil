//! Endpoint-owned acknowledged retries. Relay forwarding never uses this.

use std::sync::{Arc, Mutex};
use std::time::Duration;
use veil_dispatcher::pending_ack::PendingAckTracker;
use veil_types::FrameBroadcaster;
use veil_util::lock;

pub(super) struct ChunkRetry {
    pub content_id: [u8; 32],
    pub next_hop: [u8; 32],
    pub alternative_hop: Option<[u8; 32]>,
    pub frames: Arc<[Arc<[u8]>]>,
    pub attempt: u32,
}

/// A single-frame retry is still this endpoint's authored data. Preserve its
/// source queue through scheduling without putting that classification on the
/// wire. Keep the existing nonblocking admission and next-attempt semantics.
pub(super) fn try_admit_single_retry(
    registry: &veil_session::SessionTxRegistry,
    hop: [u8; 32],
    frame: &[u8],
    attempt: u32,
) -> bool {
    let Some(prepared) = super::prepare_ack_retransmit_frame(frame, hop, attempt) else {
        return false;
    };
    registry.send_to(&hop, veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE, prepared)
}

/// Wait for source credits with one admission deadline. A closed original hop
/// can retry the complete indexed batch on a different hop; a full queue waits
/// and an admission timeout never sprays a second copy. An authenticated ACK
/// cancels remaining pieces, including a currently blocked source admission.
pub(super) async fn admit_chunk_retry(
    sender: &dyn FrameBroadcaster,
    tracker: &Mutex<PendingAckTracker>,
    retry: ChunkRetry,
) -> Option<[u8; 32]> {
    let first = retry.frames.first()?.get(veil_proto::HEADER_SIZE..)?;
    let envelope = veil_proto::delivery::ForwardPayload::decode(first)
        .ok()?
        .envelope;
    let remaining = envelope
        .created_at
        .saturating_add(envelope.ttl_secs as u64)
        .saturating_sub(veil_util::unix_secs_now_u64())
        .min(30);
    if remaining == 0 {
        return None;
    }
    tokio::time::timeout(Duration::from_secs(remaining), async {
        let alternative = retry.alternative_hop.filter(|hop| *hop != retry.next_hop);
        for hop in std::iter::once(retry.next_hop).chain(alternative) {
            let mut complete = true;
            for frame in retry.frames.iter() {
                if !lock!(tracker).retry_is_current(&retry.content_id, retry.attempt) {
                    return None;
                }
                let prepared = super::prepare_ack_retransmit_frame(frame, hop, retry.attempt)?;
                let mut admission = sender.send_reliable_to(&hop, prepared);
                let accepted = loop {
                    tokio::select! {
                        accepted = &mut admission => { break accepted; }
                        _ = tokio::time::sleep(Duration::from_millis(100)) => {
                            if !lock!(tracker).retry_is_current(&retry.content_id, retry.attempt) {
                                return None;
                            }
                        }
                    }
                };
                if !accepted {
                    complete = false;
                    break;
                }
            }
            if complete {
                return Some(hop);
            }
        }
        None
    })
    .await
    .unwrap_or(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;
    use veil_dispatcher::envelope_chunks::{AddChunkResult, EnvelopeChunkReassembler};
    use veil_proto::delivery::{ChunkedEnvelopePayload, DeliveryEnvelope, ForwardPayload};
    use veil_proto::family::{DeliveryMsg, FrameFamily};
    use veil_proto::{FrameHeader, HEADER_SIZE};

    #[tokio::test]
    async fn bounded_retry_burst_leaves_primary_and_transit_ahead_without_changing_e2e_bytes() {
        let data = b"acknowledged source message";
        let (ek, dk) = veil_e2e::generate_keypair();
        let mut payload = vec![veil_proto::E2E_MARKER];
        payload.extend(
            veil_e2e::encrypt(&ek, &[1; 32], &[2; 32], data)
                .unwrap()
                .encode(),
        );
        let hop = [9; 32];
        let mut registry = veil_session::SessionTxRegistry::with_capacity(64);
        let mut outbox = registry.register(hop);
        let mut originals = Vec::new();
        let mut queue = veil_session::priority_queue::PriorityQueue::with_default_weights();
        let mut saw_backpressure = false;
        for n in 0..32u8 {
            let body = ForwardPayload {
                next_hop_node_id: [8; 32],
                envelope: DeliveryEnvelope {
                    recipient: veil_proto::recipient::Recipient::any([2; 32]),
                    sender_node_id: [1; 32],
                    src_app_id: [3; 32],
                    app_id: [4; 32],
                    endpoint_id: 5,
                    content_id: [n; 32],
                    created_at: veil_util::unix_secs_now_u64(),
                    ttl_secs: 30,
                    payload: payload.clone(),
                    trace_id: 0,
                    require_ack: true,
                },
                relay_hops: 0,
                delivery_attempt: Some(1),
                traffic_class: None,
            }
            .encode();
            let mut header =
                FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
            header.set_priority(veil_proto::priority::INTERACTIVE);
            header.body_len = body.len() as u32;
            let mut frame = veil_proto::codec::encode_header(&header).to_vec();
            frame.extend(body);
            if !try_admit_single_retry(&registry, hop, &frame, 2) {
                saw_backpressure = true;
                // Consume ingress before offering the retry again. This
                // fixture checks scheduling markers and E2E bytes; the real
                // scheduler's retained credit is covered in veil-session.
                let (lane, admitted) = outbox.try_recv().unwrap();
                queue.push(lane, admitted);
                assert!(try_admit_single_retry(&registry, hop, &frame, 2));
            }
            originals.push(frame);
        }
        assert!(
            saw_backpressure,
            "authored retries must retain bounded ingress"
        );
        // The runner's WRR queue sees the real retry producer's local marker.
        // A burst of authored retries must not acquire the neutral FIFO's turn.
        while let Ok((lane, frame)) = outbox.try_recv() {
            queue.push(lane, frame);
        }
        assert!(registry.send_to(&hop, veil_proto::priority::INTERACTIVE, b"transit".to_vec()));
        assert!(registry.send_to(&hop, veil_proto::priority::REALTIME, b"primary".to_vec()));
        while let Ok((lane, frame)) = outbox.try_recv() {
            queue.push(lane, frame);
        }
        assert_eq!(&*queue.pop().unwrap(), b"primary");
        assert_eq!(&*queue.pop().unwrap(), b"transit");
        for original in &originals {
            let frame = queue.pop().unwrap();
            assert_eq!(&frame[..HEADER_SIZE], &original[..HEADER_SIZE]);
            let forwarded = ForwardPayload::decode(&frame[HEADER_SIZE..]).unwrap();
            let old = ForwardPayload::decode(&original[HEADER_SIZE..]).unwrap();
            assert_eq!(forwarded.next_hop_node_id, hop);
            assert_eq!(forwarded.delivery_attempt, Some(2));
            assert_eq!(forwarded.envelope.encode(), old.envelope.encode());
            assert_eq!(forwarded.traffic_class, None);
            let encrypted =
                veil_proto::E2eEnvelope::decode(&forwarded.envelope.payload[1..]).unwrap();
            assert_eq!(
                veil_e2e::decrypt(&dk, &[1; 32], &[2; 32], &encrypted).unwrap(),
                data
            );
        }
        assert!(queue.is_empty(), "one frame per retry, with no duplicate");
        assert!(!try_admit_single_retry(
            &registry,
            [10; 32],
            &originals[0],
            2
        ));
        assert!(!try_admit_single_retry(&registry, hop, &[], 2));
        assert!(!try_admit_single_retry(&registry, hop, &originals[0], 256));
        assert!(outbox.try_recv().is_err());
    }

    fn sealed_batch() -> (ChunkRetry, Vec<u8>, Vec<u8>) {
        let data: Vec<_> = (0..20_000).map(|i| (i % 251) as u8).collect();
        let (ek, dk) = veil_e2e::generate_keypair();
        let mut payload = vec![veil_proto::E2E_MARKER];
        payload.extend(
            veil_e2e::encrypt(&ek, &[1; 32], &[2; 32], &data)
                .unwrap()
                .encode(),
        );
        let parts: Vec<_> = payload
            .chunks(veil_proto::budget::LOCAL_ENVELOPE_SEGMENT_DATA_BYTES)
            .collect();
        let frames = parts
            .iter()
            .enumerate()
            .map(|(i, part)| {
                let env = DeliveryEnvelope {
                    recipient: veil_proto::recipient::Recipient::any([2; 32]),
                    sender_node_id: [1; 32],
                    src_app_id: [3; 32],
                    app_id: [4; 32],
                    endpoint_id: 5,
                    content_id: [i as u8 + 10; 32],
                    created_at: veil_util::unix_secs_now_u64(),
                    ttl_secs: 30,
                    payload: ChunkedEnvelopePayload {
                        transfer_id: [6; 16],
                        chunk_index: i as u32,
                        chunk_count: parts.len() as u32,
                        total_size: payload.len() as u32,
                        orig_content_id: [7; 32],
                        require_ack: true,
                        data: part.to_vec(),
                    }
                    .encode(),
                    trace_id: 0,
                    require_ack: false,
                };
                let body = ForwardPayload {
                    next_hop_node_id: [8; 32],
                    envelope: env,
                    relay_hops: 0,
                    delivery_attempt: None,
                    traffic_class: None,
                }
                .encode();
                let mut header =
                    FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
                header.set_priority(veil_proto::priority::INTERACTIVE);
                header.body_len = body.len() as u32;
                let mut frame = veil_proto::codec::encode_header(&header).to_vec();
                frame.extend(body);
                Arc::<[u8]>::from(frame)
            })
            .collect::<Vec<_>>();
        (
            ChunkRetry {
                content_id: [7; 32],
                next_hop: [8; 32],
                alternative_hop: Some([9; 32]),
                frames: frames.into(),
                attempt: 1,
            },
            data,
            dk.to_vec(),
        )
    }

    fn tracked(retry: &ChunkRetry) -> Mutex<PendingAckTracker> {
        let mut tracker = PendingAckTracker::new();
        assert!(tracker.register_batch(
            retry.content_id,
            retry.next_hop,
            [2; 32],
            [3; 32],
            [4; 32],
            retry.frames.iter().map(|f| f.to_vec()).collect()
        ));
        Mutex::new(tracker)
    }

    #[tokio::test]
    async fn chunk_retry_waits_for_credit_keeps_primary_live_and_reassembles_partial_retry_once() {
        for original_live in [true, false] {
            let (retry, data, dk) = sealed_batch();
            let original = retry.frames.clone();
            let tracker = tracked(&retry);
            let hop = if original_live { [8; 32] } else { [9; 32] };
            let registry = Arc::new(RwLock::new(veil_session::SessionTxRegistry::with_capacity(
                1,
            )));
            let mut outbox = registry.write().unwrap().register(hop);
            let sender = veil_session::glue::SessionTxBroadcaster::new(registry.clone());
            assert!(registry.read().unwrap().send_to(
                &hop,
                veil_proto::priority::BACKGROUND,
                vec![0]
            ));
            let mut admission = Box::pin(admit_chunk_retry(&sender, &tracker, retry));
            assert!(
                tokio::time::timeout(Duration::from_millis(20), &mut admission)
                    .await
                    .is_err(),
                "chunk retry must await source queue"
            );
            assert!(registry.try_write().is_ok());
            assert!(registry.read().unwrap().send_to(
                &hop,
                veil_proto::priority::REALTIME,
                vec![1]
            ));
            assert_eq!(&*outbox.recv().await.unwrap().1, [1]);
            assert_eq!(&*outbox.recv().await.unwrap().1, [0]);
            let mut received = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    tokio::select! {
                        result=&mut admission => {assert_eq!(result,Some(hop));break;}
                        frame=outbox.recv()=>{received.push(frame.unwrap());}
                    }
                }
            })
            .await
            .unwrap();
            while let Ok(frame) = outbox.try_recv() {
                received.push(frame);
            }
            assert_eq!(received.len(), original.len());
            let mut reassembler = EnvelopeChunkReassembler::new();
            // The receiver retained the prefix of the original failed attempt.
            let first = ForwardPayload::decode(&original[0][HEADER_SIZE..]).unwrap();
            let part = ChunkedEnvelopePayload::decode(&first.envelope.payload).unwrap();
            assert!(matches!(
                reassembler.add(&first.envelope, hop, part, veil_util::unix_secs_now_u64()),
                AddChunkResult::Pending
            ));
            let mut complete = None;
            for ((lane, frame), old) in received.iter().zip(original.iter()) {
                assert_eq!(*lane, veil_proto::priority::BACKGROUND);
                assert!(frame.len() + 16 + 40 <= 4096);
                assert_eq!(
                    veil_proto::codec::decode_header(frame).unwrap().priority(),
                    veil_proto::priority::INTERACTIVE
                );
                let f = ForwardPayload::decode(&frame[HEADER_SIZE..]).unwrap();
                let old = ForwardPayload::decode(&old[HEADER_SIZE..]).unwrap();
                assert_eq!(f.next_hop_node_id, hop);
                assert_ne!(f.envelope.content_id, old.envelope.content_id);
                assert_eq!(f.envelope.payload, old.envelope.payload);
                let chunk = ChunkedEnvelopePayload::decode(&f.envelope.payload).unwrap();
                match reassembler.add(
                    &f.envelope,
                    hop,
                    chunk.clone(),
                    veil_util::unix_secs_now_u64(),
                ) {
                    AddChunkResult::Pending => {}
                    AddChunkResult::Rejected("duplicate chunk") => {}
                    AddChunkResult::Complete(envelope) => {
                        assert!(complete.is_none());
                        complete = Some(envelope);
                    }
                    other => panic!("unexpected reassembly: {other:?}"),
                }
                let duplicate =
                    reassembler.add(&f.envelope, hop, chunk, veil_util::unix_secs_now_u64());
                assert!(
                    matches!(
                        duplicate,
                        AddChunkResult::Rejected("duplicate chunk")
                            | AddChunkResult::CompletedReplay(_)
                    ),
                    "duplicate must not redeliver: {duplicate:?}"
                );
            }
            let result = complete.unwrap();
            assert!(result.require_ack);
            assert_eq!(result.content_id, [7; 32]);
            let encrypted = veil_proto::E2eEnvelope::decode(&result.payload[1..]).unwrap();
            assert_eq!(
                veil_e2e::decrypt(&dk, &[1; 32], &[2; 32], &encrypted).unwrap(),
                data
            );
        }
    }

    #[tokio::test]
    async fn expired_chunk_retry_does_not_spend_source_capacity() {
        struct MustNotSend;
        impl FrameBroadcaster for MustNotSend {
            fn send_to(&self, _: &[u8; 32], _: u8, _: Vec<u8>) -> bool {
                panic!("expired chunk must not send");
            }
            fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {}
            fn active_node_ids(&self) -> Vec<[u8; 32]> {
                vec![]
            }
        }
        let (mut retry, _, _) = sealed_batch();
        let frames = retry
            .frames
            .iter()
            .map(|frame| {
                let mut f = ForwardPayload::decode(&frame[HEADER_SIZE..]).unwrap();
                f.envelope.created_at = veil_util::unix_secs_now_u64() - 31;
                let mut updated = frame[..HEADER_SIZE].to_vec();
                updated.extend(f.encode());
                Arc::<[u8]>::from(updated)
            })
            .collect::<Vec<_>>();
        retry.frames = frames.into();
        let tracker = tracked(&retry);
        assert_eq!(admit_chunk_retry(&MustNotSend, &tracker, retry).await, None);
        assert_eq!(lock!(tracker).len(), 1, "expiry does not forge an ACK");
    }

    #[tokio::test]
    async fn authenticated_ack_cancels_blocked_chunk_admission_without_a_suffix_or_credit_leak() {
        let (retry, _, _) = sealed_batch();
        let tracker = tracked(&retry);
        let registry = Arc::new(RwLock::new(veil_session::SessionTxRegistry::with_capacity(
            1,
        )));
        let mut outbox = registry.write().unwrap().register([8; 32]);
        let sender = veil_session::glue::SessionTxBroadcaster::new(registry.clone());
        assert!(registry.read().unwrap().send_to(
            &[8; 32],
            veil_proto::priority::BACKGROUND,
            vec![0]
        ));
        let mut admission = Box::pin(admit_chunk_retry(&sender, &tracker, retry));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut admission)
                .await
                .is_err()
        );
        lock!(tracker).ack(&[7; 32]);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), admission)
                .await
                .unwrap(),
            None
        );
        assert_eq!(&*outbox.recv().await.unwrap().1, [0]);
        assert!(outbox.try_recv().is_err());
        assert!(sender.send_reliable_to(&[8; 32], vec![2]).await);
        assert_eq!(&*outbox.recv().await.unwrap().1, [2]);
    }
}
