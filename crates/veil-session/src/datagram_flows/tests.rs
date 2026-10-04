use super::*;
use crate::realtime_datagram::{ASSEMBLY_TTL, MAX_FRAGMENTS};
use std::time::Duration;

const KEY: [u8; 32] = [1; 32];
const SESSION: [u8; 32] = [2; 32];

#[test]
fn delayed_channel_survives_another_channels_replay_and_fragment_flood() {
    let now = Instant::now();
    let mut tx = FlowDatagramTx::new(&KEY, &SESSION);
    let mut rx = FlowDatagramRx::new(&KEY, &SESSION);
    let delayed = vec![7u8; 1500];
    let packets = tx.encode_frame(0, &delayed, 1200).unwrap();
    assert_eq!(packets.len(), 2);
    assert_eq!(rx.decode_datagram(&packets[0], now).unwrap(), None);
    // Well past the old shared replay window, then past its assembly quota.
    for index in 0..4096 {
        let packet = tx.encode_frame(2, &[index as u8], 1200).unwrap();
        assert_eq!(
            rx.decode_datagram(&packet[0], now).unwrap(),
            Some(vec![index as u8])
        );
    }
    for _ in 0..MAX_ASSEMBLIES * 2 {
        let partial = tx.encode_frame(2, &[5; 1500], 1200).unwrap();
        assert!(rx.decode_datagram(&partial[0], now).unwrap().is_none());
    }
    assert_eq!(rx.decode_datagram(&packets[1], now).unwrap(), Some(delayed));
    assert_eq!(
        rx.decode_datagram(&packets[0], now),
        Err(RealtimeDatagramError::Replay)
    );
}

#[test]
fn opaque_ids_are_authenticated_without_carrying_local_channel_numbers() {
    let now = Instant::now();
    let mut tx = FlowDatagramTx::new(&KEY, &SESSION);
    let mut rx = FlowDatagramRx::new(&KEY, &SESSION);
    let a = tx.encode_frame(0, &[9; 50], 1200).unwrap().remove(0);
    let b = tx.encode_frame(u64::MAX, &[8; 50], 1200).unwrap().remove(0);
    assert_eq!(&a[..4], &b[..4]);
    assert_ne!(&a[4..20], &b[4..20]);
    assert_eq!(
        &a[20..44],
        &b[20..44],
        "each channel begins with its own message/nonce counters"
    );
    assert_ne!(&a[44..], &b[44..]);
    let mut changed = a.clone();
    changed[4..20].copy_from_slice(&b[4..20]);
    assert_eq!(
        rx.decode_datagram(&changed, now),
        Err(RealtimeDatagramError::Authentication)
    );
    assert!(rx.flows.is_empty());
    assert_eq!(rx.decode_datagram(&a, now).unwrap(), Some(vec![9; 50]));
    assert_eq!(rx.decode_datagram(&b, now).unwrap(), Some(vec![8; 50]));
    // Equal key/session material in another TX instance still produces new ids.
    let mut another = FlowDatagramTx::new(&KEY, &SESSION);
    let other = another.encode_frame(0, &[9; 50], 1200).unwrap().remove(0);
    assert_ne!(&a[4..20], &other[4..20]);
    assert_eq!(rx.decode_datagram(&other, now).unwrap(), Some(vec![9; 50]));
}

#[test]
fn channel_ids_and_ciphertexts_are_bound_to_direction_and_session() {
    let mut tx = FlowDatagramTx::new(&KEY, &SESSION);
    let packet = tx.encode_frame(0, &[3], 1200).unwrap().remove(0);
    for (key, session) in [([4; 32], SESSION), (KEY, [4; 32])] {
        let mut wrong = FlowDatagramRx::new(&key, &session);
        assert_eq!(
            wrong.decode_datagram(&packet, Instant::now()),
            Err(RealtimeDatagramError::Authentication)
        );
        assert!(wrong.flows.is_empty());
    }
}

#[test]
fn unauthenticated_flow_flood_cannot_consume_slots_or_displace_an_active_channel() {
    let now = Instant::now();
    let mut tx = FlowDatagramTx::new(&KEY, &SESSION);
    let mut rx = FlowDatagramRx::new(&KEY, &SESSION);
    let packet = tx.encode_frame(0, &[3], 1200).unwrap().remove(0);
    assert_eq!(rx.decode_datagram(&packet, now).unwrap(), Some(vec![3]));
    for id in 1u64..=1024 {
        let mut forged = packet.clone();
        forged[4..12].copy_from_slice(&id.to_be_bytes());
        assert_eq!(
            rx.decode_datagram(&forged, now),
            Err(RealtimeDatagramError::Authentication)
        );
    }
    assert_eq!(rx.flows.len(), 1);
    let next = tx.encode_frame(0, &[4], 1200).unwrap().remove(0);
    assert_eq!(rx.decode_datagram(&next, now).unwrap(), Some(vec![4]));
}

#[test]
fn total_assembly_budget_does_not_multiply_by_channel_count() {
    let now = Instant::now();
    let mut tx = FlowDatagramTx::new(&KEY, &SESSION);
    let mut rx = FlowDatagramRx::new(&KEY, &SESSION);
    for id in 0..MAX_FLOWS as u64 {
        for _ in 0..MAX_ASSEMBLIES {
            let packets = tx.encode_frame(id, &[6; MAX_REALTIME_FRAME], 1200).unwrap();
            for packet in &packets[..packets.len() - 1] {
                assert!(rx.decode_datagram(packet, now).unwrap().is_none());
            }
        }
    }
    let (count, bytes) = rx
        .flows
        .values()
        .map(RealtimeDatagramRx::retained)
        .fold((0, 0), |(count, bytes), next| {
            (count + next.0, bytes + next.1)
        });
    assert_eq!(rx.flows.len(), MAX_FLOWS);
    assert!(count <= MAX_ASSEMBLIES);
    assert!(bytes <= MAX_ASSEMBLY_BYTES);
    assert!(bytes > 0);
    // A new local handle reuses an existing wire slot without expanding quotas.
    let reused = tx
        .encode_frame(MAX_FLOWS as u64, &[1], 1200)
        .unwrap()
        .remove(0);
    assert_eq!(rx.decode_datagram(&reused, now).unwrap(), Some(vec![1]));
    assert_eq!(tx.flows.len(), MAX_FLOWS);
    assert_eq!(rx.flows.len(), MAX_FLOWS);
    // A genuinely new authenticated wire id still cannot expand RX quotas.
    let mut other = FlowDatagramTx::new(&KEY, &SESSION);
    let excess = other.encode_frame(0, &[1], 1200).unwrap().remove(0);
    assert_eq!(
        rx.decode_datagram(&excess, now),
        Err(RealtimeDatagramError::FlowCapacity)
    );
    // Activity on one channel also expires fragments in inactive channels.
    let packet = tx.encode_frame(0, &[1], 1200).unwrap().remove(0);
    assert_eq!(
        rx.decode_datagram(&packet, now + ASSEMBLY_TTL).unwrap(),
        Some(vec![1])
    );
    assert!(rx.flows.values().all(|rx| rx.retained() == (0, 0)));
}

#[test]
fn rekey_preserves_each_channels_ids_sequences_replay_and_inflight_fragments() {
    let now = Instant::now();
    let mut tx = FlowDatagramTx::new(&KEY, &SESSION);
    let mut rx = FlowDatagramRx::new(&KEY, &SESSION);
    let mut queued = Vec::new();
    for id in [0, 2] {
        let frame = vec![id as u8; 1500];
        let packets = tx.encode_frame(id, &frame, 1200).unwrap();
        assert_eq!(rx.decode_datagram(&packets[0], now).unwrap(), None);
        queued.push((id, frame, packets));
    }
    tx.rekey(&[8; 32], &[9; 32]);
    rx.rekey(&[8; 32], &[9; 32], now);
    for (id, frame, old) in queued {
        assert_eq!(rx.decode_datagram(&old[1], now).unwrap(), Some(frame));
        assert_eq!(
            rx.decode_datagram(&old[0], now),
            Err(RealtimeDatagramError::Replay)
        );
        let fresh = tx.encode_frame(id, &[4], 1200).unwrap().remove(0);
        assert_eq!(&old[0][4..20], &fresh[4..20]);
        assert_ne!(&old[0][36..44], &fresh[36..44]);
        assert_eq!(rx.decode_datagram(&fresh, now).unwrap(), Some(vec![4]));
    }
}

#[test]
fn late_first_channel_packet_uses_exact_rekey_grace_without_extending_it() {
    let now = Instant::now();
    let mut tx = FlowDatagramTx::new(&KEY, &SESSION);
    let mut rx = FlowDatagramRx::new(&KEY, &SESSION);
    let old = tx.encode_frame(0, &[3], 1200).unwrap().remove(0);
    let expired = tx.encode_frame(0, &[4], 1200).unwrap().remove(0);
    let unknown = tx.encode_frame(2, &[5], 1200).unwrap().remove(0);
    rx.rekey(&[8; 32], &[9; 32], now);
    assert_eq!(
        rx.decode_datagram(&old, now + Duration::from_secs(4))
            .unwrap(),
        Some(vec![3])
    );
    let deadline = now + REALTIME_REKEY_GRACE;
    assert_eq!(
        rx.decode_datagram(&expired, deadline),
        Err(RealtimeDatagramError::Authentication)
    );
    assert_eq!(
        rx.decode_datagram(&unknown, deadline),
        Err(RealtimeDatagramError::Authentication)
    );
    assert_eq!(rx.flows.len(), 1);
    assert!(rx.previous.is_none());
    tx.rekey(&[8; 32], &[9; 32]);
    let fresh = tx.encode_frame(2, &[6], 1200).unwrap().remove(0);
    assert_eq!(rx.decode_datagram(&fresh, deadline).unwrap(), Some(vec![6]));
}

#[test]
fn legacy_negotiation_keeps_exact_vrt1_bytes_and_rejects_new_wire_format() {
    let frame = [3; 32];
    let mut legacy = RealtimeDatagramTx::new(&KEY, &SESSION);
    let mut session = SessionDatagramTx::new(&KEY, &SESSION, false);
    let old = session.encode_frame(999, &frame, 1200).unwrap();
    assert_eq!(old, legacy.encode_frame(&frame, 1200).unwrap());
    let mut receiver = SessionDatagramRx::new(&KEY, &SESSION, false);
    assert_eq!(
        receiver.decode_datagram(&old[0], Instant::now()).unwrap(),
        Some(frame.to_vec())
    );
    let mut modern = SessionDatagramTx::new(&KEY, &SESSION, true);
    let new = modern.encode_frame(999, &frame, 1200).unwrap();
    assert_eq!(
        receiver.decode_datagram(&new[0], Instant::now()),
        Err(RealtimeDatagramError::Malformed)
    );
    let mut modern_rx = SessionDatagramRx::new(&KEY, &SESSION, true);
    assert_eq!(
        modern_rx.decode_datagram(&old[0], Instant::now()),
        Err(RealtimeDatagramError::Malformed)
    );
    assert_eq!(
        modern_rx.decode_datagram(&new[0], Instant::now()).unwrap(),
        Some(frame.to_vec())
    );
}

#[test]
fn opaque_prefix_is_included_in_mtu_budget_and_bad_frames_do_not_allocate_channels() {
    let mut tx = FlowDatagramTx::new(&KEY, &SESSION);
    assert_eq!(
        tx.encode_frame(0, &[], 1200),
        Err(RealtimeDatagramError::FrameSize(0))
    );
    assert_eq!(
        tx.encode_frame(0, &[1], MIN_FLOW_DATAGRAM_SIZE - 1),
        Err(RealtimeDatagramError::DatagramTooSmall(
            MIN_FLOW_DATAGRAM_SIZE - 1
        ))
    );
    assert!(tx.flows.is_empty());
    let frame = [9; MAX_REALTIME_FRAME];
    let packets = tx.encode_frame(0, &frame, 1200).unwrap();
    assert!(packets.len() <= MAX_FRAGMENTS);
    assert!(packets.iter().all(|packet| packet.len() <= 1200));
    let mut rx = FlowDatagramRx::new(&KEY, &SESSION);
    let mut complete = None;
    for packet in packets.into_iter().rev() {
        complete = rx
            .decode_datagram(&packet, Instant::now())
            .unwrap()
            .or(complete);
    }
    assert_eq!(complete, Some(frame.to_vec()));
}

#[test]
fn complete_frame_wire_bound_covers_legacy_and_opaque_fragmentation() {
    for flows in [false, true] {
        for ceiling in [
            MAX_REALTIME_FRAME.div_ceil(MAX_FRAGMENTS)
                + PREFIX_LEN
                + crate::realtime_datagram::FRAGMENT_OVERHEAD,
            1200,
            MAX_REALTIME_FRAME + PREFIX_LEN + crate::realtime_datagram::FRAGMENT_OVERHEAD,
        ] {
            let mut tx = SessionDatagramTx::new(&KEY, &SESSION, flows);
            let datagrams = tx
                .encode_frame(0, &vec![7; MAX_REALTIME_FRAME], ceiling)
                .unwrap();
            let wire_bytes: usize = datagrams.iter().map(Vec::len).sum();
            assert!(wire_bytes <= MAX_FRAME_WIRE_BYTES);
            if flows && datagrams.len() == MAX_FRAGMENTS {
                assert_eq!(wire_bytes, MAX_FRAME_WIRE_BYTES);
            }
        }
    }
}

#[test]
fn circuit_churn_reuses_bounded_slots_without_resetting_nonces_or_local_lanes() {
    let now = Instant::now();
    let mut tx = FlowDatagramTx::new(&KEY, &SESSION);
    let mut rx = FlowDatagramRx::new(&KEY, &SESSION);
    let pending = tx.encode_frame(0, &[7; 1500], 1200).unwrap();
    assert_eq!(rx.decode_datagram(&pending[0], now).unwrap(), None);
    let mut sequences = HashMap::new();
    for circuit in 0..2048u64 {
        let packets = tx
            .encode_frame((1u64 << 32) | circuit, &[5; 1500], 1200)
            .unwrap();
        for (index, packet) in packets.iter().enumerate() {
            let id: FlowId = packet[4..PREFIX_LEN].try_into().unwrap();
            let sequence = u64::from_be_bytes(packet[36..44].try_into().unwrap());
            if let Some(previous) = sequences.insert(id, sequence) {
                assert!(
                    sequence > previous,
                    "slot reuse must never reset an AEAD nonce"
                );
            }
            let frame = rx.decode_datagram(packet, now).unwrap();
            if index + 1 == packets.len() {
                assert_eq!(frame, Some(vec![5; 1500]));
            } else {
                assert_eq!(frame, None);
            }
        }
        assert!(tx.flows.len() <= MAX_FLOWS);
        assert!(rx.flows.len() <= MAX_FLOWS);
        assert!(tx.reusable.len() <= MAX_FLOWS - LOCAL_LANES.len());
    }
    assert_eq!(sequences.len(), MAX_FLOWS - LOCAL_LANES.len());
    // The second endpoint lane was not present during churn; its slot remains
    // available without allocating a new wire id past the receiver's cap.
    let secondary = tx.encode_frame(2, &[9], 1200).unwrap().remove(0);
    assert_eq!(rx.decode_datagram(&secondary, now).unwrap(), Some(vec![9]));
    assert_eq!(tx.flows.len(), MAX_FLOWS);
    assert_eq!(rx.flows.len(), MAX_FLOWS);
    assert_eq!(
        rx.decode_datagram(&pending[1], now).unwrap(),
        Some(vec![7; 1500])
    );
    assert_eq!(
        rx.decode_datagram(&pending[0], now),
        Err(RealtimeDatagramError::Replay)
    );
    let primary = tx.encode_frame(0, &[8], 1200).unwrap().remove(0);
    assert_eq!(&pending[0][4..PREFIX_LEN], &primary[4..PREFIX_LEN]);
    assert_eq!(rx.decode_datagram(&primary, now).unwrap(), Some(vec![8]));
}

#[test]
fn rebound_slot_keeps_inflight_messages_separate_and_rekeys_without_nonce_reset() {
    let now = Instant::now();
    let mut tx = FlowDatagramTx::new(&KEY, &SESSION);
    let mut rx = FlowDatagramRx::new(&KEY, &SESSION);
    let old = tx.encode_frame(1u64 << 32, &[7; 1500], 1200).unwrap();
    assert_eq!(rx.decode_datagram(&old[0], now).unwrap(), None);
    for circuit in 1..(MAX_FLOWS - LOCAL_LANES.len()) as u64 {
        let p = tx
            .encode_frame((1u64 << 32) | circuit, &[3], 1200)
            .unwrap()
            .remove(0);
        assert_eq!(rx.decode_datagram(&p, now).unwrap(), Some(vec![3]));
    }
    let reused = tx
        .encode_frame((1u64 << 32) | 999, &[8; 1500], 1200)
        .unwrap();
    assert_eq!(&old[0][4..PREFIX_LEN], &reused[0][4..PREFIX_LEN]);
    assert_ne!(&old[0][24..28], &reused[0][24..28]);
    assert_eq!(rx.decode_datagram(&reused[0], now).unwrap(), None);
    assert_eq!(
        rx.decode_datagram(&old[1], now).unwrap(),
        Some(vec![7; 1500])
    );
    tx.rekey(&[8; 32], &[9; 32]);
    rx.rekey(&[8; 32], &[9; 32], now);
    assert_eq!(
        rx.decode_datagram(&reused[1], now).unwrap(),
        Some(vec![8; 1500])
    );
    let fresh = tx
        .encode_frame((1u64 << 32) | 999, &[9], 1200)
        .unwrap()
        .remove(0);
    assert_eq!(&reused[0][4..PREFIX_LEN], &fresh[4..PREFIX_LEN]);
    let seq = |packet: &[u8]| u64::from_be_bytes(packet[36..44].try_into().unwrap());
    assert!(seq(&fresh) > seq(&reused[1]));
    assert_eq!(rx.decode_datagram(&fresh, now).unwrap(), Some(vec![9]));
    assert_eq!(
        rx.decode_datagram(&old[0], now),
        Err(RealtimeDatagramError::Replay)
    );
}

#[test]
fn rejected_fragment_count_never_rebinds_a_slot_or_changes_reuse_order() {
    let mut tx = FlowDatagramTx::new(&KEY, &SESSION);
    for id in 0..32u64 {
        tx.encode_frame((1u64 << 32) | id, &[1], 1200).unwrap();
    }
    let order = tx.reusable.clone();
    let ids: HashMap<_, _> = tx.flows.iter().map(|(key, flow)| (*key, flow.id)).collect();
    assert_eq!(
        tx.encode_frame((1u64 << 32) | 999, &[1; 64], MIN_FLOW_DATAGRAM_SIZE),
        Err(RealtimeDatagramError::TooManyFragments(64))
    );
    assert_eq!(tx.reusable, order);
    assert_eq!(
        tx.flows
            .iter()
            .map(|(key, flow)| (*key, flow.id))
            .collect::<HashMap<_, _>>(),
        ids
    );
}
