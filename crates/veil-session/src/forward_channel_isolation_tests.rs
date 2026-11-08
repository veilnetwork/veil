//! Production selection and authenticated record I/O, with one deliberately
//! unread pipe. The same sender/recipient must not collapse distinct ingress
//! connections onto that pipe. These are generic opaque Forward cells.
use super::*;
use crate::parallel_binding::{ParallelKeys, ParallelParent};
use tokio::time::{Duration, timeout};
use veil_anonymity::circuit_carrier::{Carrier, DatagramCarrier};

pub(super) fn raw_pair(
    left: &ParallelParent,
    right: &ParallelParent,
    capacity: usize,
) -> (BoundOrderedChannel, ParallelKeys, tokio::io::DuplexStream) {
    let (hello, pending) = left.handle().begin([4; 32]).unwrap();
    let (ack, remote_keys) = right.handle().accept(&hello, [4; 32]).unwrap();
    let local_keys = pending.finish(&ack).unwrap();
    let (a, b) = tokio::io::duplex(capacity);
    (
        local_keys.into_ordered(Box::new(a)).unwrap(),
        remote_keys,
        b,
    )
}

fn opaque_forward(fill: u8) -> Vec<u8> {
    let body = veil_proto::delivery::ForwardPayload {
        next_hop_node_id: [9; 32],
        envelope: veil_proto::delivery::DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any([8; 32]),
            sender_node_id: [7; 32],
            src_app_id: [6; 32],
            app_id: [5; 32],
            endpoint_id: 1,
            content_id: [fill; 32],
            created_at: veil_util::unix_secs_now_u64(),
            ttl_secs: veil_proto::delivery::FORWARD_REALTIME_TTL_SECS,
            payload: vec![fill; 256],
            trace_id: 0,
            require_ack: false,
        },
        relay_hops: 0,
        delivery_attempt: None,
        traffic_class: Some(veil_proto::priority::INTERACTIVE),
    }
    .encode();
    let mut header = FrameHeader::new(
        FrameFamily::Delivery as u8,
        veil_proto::family::DeliveryMsg::Forward as u16,
    );
    header.set_priority(veil_proto::priority::INTERACTIVE);
    header.body_len = body.len() as u32;
    veil_proto::codec::encode_frame(&header, &body)
}

#[tokio::test]
async fn failed_cold_selections_do_not_block_a_ready_source_or_neutral_transit() {
    for transit_first in [false, true] {
        let parent = ParallelParent::new([1; 32], [2; 32], [3; 32]);
        let remote = ParallelParent::new([1; 32], [3; 32], [2; 32]);
        let diagnostics = Arc::new(ParallelDiagnostics::default());
        let salt = blake3::derive_key("veil/transit-shard/v1", &[7; 32]);
        let direct = super::super::ordered_receiver_tests::app_frame(501, 64);
        let forwarded = opaque_forward(81);
        let direct_body = &direct[veil_proto::header::HEADER_SIZE..];
        let forwarded_body = &forwarded[veil_proto::header::HEADER_SIZE..];
        let source = (
            veil_proto::priority::REALTIME,
            direct_body,
            RealtimeLaneFrameKind::DirectApp,
        );
        let transit = (
            veil_proto::priority::INTERACTIVE,
            forwarded_body,
            RealtimeLaneFrameKind::RelayForward,
        );
        let (first, second, expected) = if transit_first {
            (transit, source, &direct)
        } else {
            (source, transit, &forwarded)
        };
        let mut pool = Pool::default();
        assert!(
            pool.selected_sender(first.0, first.1, first.2, None, &salt, &diagnostics)
                .is_none()
        );
        // Complete precisely the channel a failed old-style selection would
        // have reserved. There was no authenticated child to own at that time.
        let mut reservations = channel_assignments::ChannelAssignments::<TOTAL_SLOTS>::default();
        let physical = if transit_first {
            let bucket = parallel_lanes::neutral_transit_index(
                &salt,
                forwarded_body,
                RealtimeLaneFrameKind::RelayForward,
            )
            .unwrap();
            reservations.transit(None, bucket).unwrap().physical
        } else {
            reservations.source(0).unwrap().physical
        };
        let (channel, keys, raw) = raw_pair(&parent, &remote, 65536);
        let receiver = keys.into_ordered(Box::new(raw)).unwrap();
        let mut decoder = crate::datagram_flows::SessionDatagramRx::new(
            receiver.keys.rx_key(),
            &receiver.keys.session_id,
            true,
        );
        pool.slots[physical] = Some(Ready::new(
            Owner::Outgoing(channel),
            parent.handle(),
            super::super::ordered_receiver_tests::pool_fixture_context(),
            diagnostics.clone(),
        ));
        let selected = pool
            .selected_sender(second.0, second.1, second.2, None, &salt, &diagnostics)
            .expect("a failed cold probe pinned the only ready channel");
        let packets = lock!(selected).tx.encode_frame(10, expected, 1200).unwrap();
        assert_eq!(packets.len(), 1);
        lock!(selected).handle.send(&packets[0]).unwrap();
        let received = timeout(Duration::from_secs(1), receiver.handle().recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            decoder
                .decode_datagram(&received, std::time::Instant::now())
                .unwrap()
                .unwrap(),
            *expected
        );
        // Ownership starts with successful selection, and is protected after
        // that: the original cold requester cannot steal the healthy child.
        assert!(
            pool.selected_sender(first.0, first.1, first.2, None, &salt, &diagnostics)
                .is_none()
        );
        let again = pool
            .selected_sender(second.0, second.1, second.2, None, &salt, &diagnostics)
            .unwrap();
        assert!(Arc::ptr_eq(&selected, &again));
    }
}

#[tokio::test]
async fn own_keepalive_does_not_hold_neutral_forward_behind_a_full_canonical_writer() {
    use crate::keepalive_emit::{PendingKeepaliveProbe, enqueue_probe};
    use crate::priority_queue::{HeadAdmission, PriorityQueue};

    // The real writer owns a partially written first blob and a full channel.
    // Its reader stays alive and unread; no timeout/EOF can free this capacity.
    let (canonical, mut peer) = tokio::io::duplex(1);
    let canonical: veil_transport::BoxIoStream = Box::new(canonical);
    let (_read, write) = tokio::io::split(canonical);
    let (wire_tx, wire_rx) = mpsc::channel::<super::super::WireBlob>(1);
    let _writer = super::super::OwnedWriter(tokio::spawn(super::super::writer_task(
        write,
        wire_rx,
        None,
        None,
        None,
        Arc::new(veil_observability::NodeLogger::new_noop()),
        "fixture".into(),
    )));
    let first = veil_bufpool::pooled_shared_from_vec(vec![0x31; 64]);
    let second = veil_bufpool::pooled_shared_from_vec(vec![0x72; 64]);
    wire_tx.send(first.clone().into()).await.unwrap();
    wire_tx.send(second.clone().into()).await.unwrap();
    assert_eq!(wire_tx.capacity(), 0);

    let mut queue = PriorityQueue::with_default_weights();
    let mut pending = PendingKeepaliveProbe::new();
    let now = tokio::time::Instant::now();
    assert!(!enqueue_probe(&mut queue, &mut pending, now));
    assert!(enqueue_probe(
        &mut queue,
        &mut pending,
        now + Duration::from_secs(1)
    ));
    assert_eq!(pending.oldest(), Some(now));
    let frames = [opaque_forward(21), opaque_forward(22)];
    for frame in &frames {
        queue.push_lossy(
            veil_proto::priority::INTERACTIVE,
            veil_bufpool::pooled_shared_from_vec(frame.clone()),
        );
    }

    // The independent ordered child has real parent/exporter proof, session
    // encryption, framing and receive decoding. It grants no source class.
    let parent = ParallelParent::new([1; 32], [2; 32], [3; 32]);
    let remote = ParallelParent::new([1; 32], [3; 32], [2; 32]);
    let (channel, keys, raw) = raw_pair(&parent, &remote, 65536);
    let sender = Arc::new(Mutex::new(RealtimeSender::new(
        channel.handle(),
        crate::datagram_flows::SessionDatagramTx::new(
            channel.keys.tx_key(),
            &channel.keys.session_id,
            true,
        ),
    )));
    let mut decoder =
        crate::datagram_flows::SessionDatagramRx::new(keys.rx_key(), &keys.session_id, true);
    let receiver = keys.into_ordered(Box::new(raw)).unwrap();
    for expected in &frames {
        let selected = queue
            .pop_admitted_envelope(|_, frame, _, _| {
                if super::super::datagram_lane_supports_frame(frame, true, true) {
                    HeadAdmission::Allow
                } else {
                    HeadAdmission::FlushBatch
                }
            })
            .expect("own keepalive blocked an independent neutral Forward");
        assert_eq!(selected.frame.0, veil_proto::priority::INTERACTIVE);
        assert_eq!(&*selected.frame.1, expected);
        assert_eq!(wire_tx.capacity(), 0);
        publish(&sender, &selected.frame.1);
        let packet = timeout(Duration::from_secs(1), receiver.handle().recv())
            .await
            .unwrap()
            .unwrap();
        let decoded = decoder
            .decode_datagram(&packet, std::time::Instant::now())
            .unwrap()
            .unwrap();
        assert_eq!(&decoded, expected);
        assert_eq!(wire_tx.capacity(), 0);
    }
    assert_eq!(queue.drops_total(), 0);
    assert_eq!(
        queue.len(),
        2,
        "both unacked parent probes must remain queued"
    );
    for _ in 0..2 {
        let probe = queue
            .pop_admitted_envelope(|_, _, _, _| HeadAdmission::Allow)
            .unwrap();
        assert_eq!(probe.frame.0, crate::LOCAL_NETWORK_CONTROL_LANE);
        let header = decode_header(&probe.frame.1).unwrap();
        assert_eq!(header.family, FrameFamily::Control as u8);
        assert_eq!(header.msg_type, veil_proto::ControlMsg::Keepalive as u16);
        assert!(
            !super::super::auxiliary_records::outgoing_eligible(&probe.frame.1),
            "a healthy child must not turn the parent TX probe into child health"
        );
    }
    assert_eq!(pending.oldest(), Some(now));
    let mut bytes = [0; 128];
    peer.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes[..64], &*first);
    assert_eq!(&bytes[64..], &*second);
}

pub(super) fn publish(sender: &Arc<Mutex<RealtimeSender>>, frame: &[u8]) {
    let (_, body, kind) = decode_realtime_lane_frame(frame).unwrap();
    let mut sender = lock!(sender);
    let size = sender.handle.max_size().unwrap();
    let packets = sender
        .tx
        .encode_frame(
            local_datagram_flow(veil_proto::priority::INTERACTIVE, body, kind),
            frame,
            size,
        )
        .unwrap();
    for packet in packets {
        sender.handle.send(&packet).unwrap();
    }
}

#[tokio::test]
async fn retained_closed_ordered_carrier_releases_ingress_and_refuses_before_admission() {
    let parent = ParallelParent::new([1; 32], [2; 32], [3; 32]);
    let remote = ParallelParent::new([1; 32], [3; 32], [2; 32]);
    let diagnostics = Arc::new(ParallelDiagnostics::default());
    let mut assignments = super::super::channel_assignments::ChannelAssignments::<1>::default();
    let (old, _, _old_pipe) = raw_pair(&parent, &remote, 1024);
    let make = |channel: &BoundOrderedChannel| {
        parallel_lanes::make_carrier(
            &diagnostics,
            Arc::new(Mutex::new(RealtimeSender::new(
                channel.handle(),
                crate::datagram_flows::SessionDatagramTx::new(
                    channel.keys.tx_key(),
                    &channel.keys.session_id,
                    true,
                ),
            ))),
            parent.handle(),
            [4; 32],
        )
    };
    let retained = make(&old);
    let old_flow = retained.local_ingress_flow().unwrap();
    let witness = Arc::downgrade(&retained);
    assert_eq!(assignments.transit(Some(&witness), 0).unwrap().physical, 0);
    old.handle().close();
    assert!(parent.handle().is_active());
    assert!(retained.local_ingress_flow().is_none());
    let mut admitted = false;
    assert!(matches!(
        retained.try_send(&[4; 32], &opaque_forward(21), &mut |_| {
            admitted = true;
            true
        }),
        veil_anonymity::circuit_carrier::CarrierSend::Unavailable,
    ));
    assert!(
        !admitted,
        "a closed child must not spend fallback admission"
    );
    let (new, _, _new_pipe) = raw_pair(&parent, &remote, 1024);
    let replacement = make(&new);
    let new_flow = replacement.local_ingress_flow().unwrap();
    assert_eq!(old_flow.parent, new_flow.parent);
    assert_ne!(old_flow.connection, new_flow.connection);
    let replacement_witness = Arc::downgrade(&replacement);
    assert_eq!(
        assignments
            .transit(Some(&replacement_witness), 0)
            .unwrap()
            .physical,
        0
    );
}

#[tokio::test]
async fn distinct_forward_ingress_progresses_while_the_same_routes_other_pipe_is_blocked() {
    forward_ingress_progress_with_blocked_pipe(2).await;
}

#[tokio::test]
async fn four_same_route_ingress_connections_remain_independent_without_remote_roles() {
    forward_ingress_progress_with_blocked_pipe(4).await;
}

#[tokio::test]
async fn full_neutral_connection_pool_preserves_progress_and_refuses_aliasing_another_ingress() {
    forward_ingress_progress_with_blocked_pipe(TOTAL_SLOTS).await;
}

async fn forward_ingress_progress_with_blocked_pipe(flow_count: usize) {
    let parent = ParallelParent::new([1; 32], [2; 32], [3; 32]);
    let remote = ParallelParent::new([1; 32], [3; 32], [2; 32]);
    let diagnostics = Arc::new(ParallelDiagnostics::default());
    let context = super::super::ordered_receiver_tests::pool_fixture_context();
    let mut pool = Pool::default();
    let mut destinations = Vec::new();
    for physical in 0..TOTAL_SLOTS {
        let (channel, keys, raw) = raw_pair(&parent, &remote, 32);
        pool.slots[physical] = Some(Ready::new(
            Owner::Outgoing(channel),
            parent.handle(),
            context.clone(),
            diagnostics.clone(),
        ));
        destinations.push(Some((keys, raw)));
    }

    // Independent authenticated incoming connections of one canonical parent.
    // No role, application endpoint or traffic hint chooses their outgoing pipe.
    let ingress_parent = ParallelParent::new([11; 32], [12; 32], [13; 32]);
    let ingress_remote = ParallelParent::new([11; 32], [13; 32], [12; 32]);
    let mut owners = Vec::new();
    let mut carriers: Vec<Arc<dyn DatagramCarrier>> = Vec::new();
    for _ in 0..flow_count {
        let (channel, keys, raw) = raw_pair(&ingress_parent, &ingress_remote, 32);
        let sender = Arc::new(Mutex::new(RealtimeSender::new(
            channel.handle(),
            crate::datagram_flows::SessionDatagramTx::new(
                channel.keys.tx_key(),
                &channel.keys.session_id,
                true,
            ),
        )));
        carriers.push(parallel_lanes::make_carrier(
            &diagnostics,
            sender,
            ingress_parent.handle(),
            [4; 32],
        ));
        owners.push((channel, keys, raw));
    }
    let witnesses: Vec<Carrier> = carriers.iter().map(Arc::downgrade).collect();
    let salt = [17; 32];
    let frames: Vec<_> = (0..flow_count)
        .map(|i| opaque_forward(21 + i as u8))
        .collect();
    let (_, body, kind) = decode_realtime_lane_frame(&frames[0]).unwrap();
    let senders: Vec<_> = witnesses
        .iter()
        .map(|witness| {
            pool.selected_sender(
                veil_proto::priority::INTERACTIVE,
                body,
                kind,
                Some(witness),
                &salt,
                &diagnostics,
            )
            .unwrap()
        })
        .collect();
    for (i, sender) in senders.iter().enumerate() {
        for other in &senders[..i] {
            assert!(
                !Arc::ptr_eq(sender, other),
                "same-route Forward connections were merged"
            );
        }
        let guard = lock!(sender);
        let (_, counter) = guard.sent_counter.as_ref().unwrap();
        assert!(*counter >= crate::local_datagram_status::LOCAL_DATAGRAM_PRIORITIES.len());
    }
    let physical: Vec<_> = senders
        .iter()
        .map(|sender| {
            pool.slots
                .iter()
                .position(|ready| {
                    ready
                        .as_ref()
                        .is_some_and(|r| Arc::ptr_eq(&r.sender, sender))
                })
                .unwrap()
        })
        .collect();
    if flow_count == TOTAL_SLOTS {
        let (channel, keys, raw) = raw_pair(&ingress_parent, &ingress_remote, 32);
        let extra = parallel_lanes::make_carrier(
            &diagnostics,
            Arc::new(Mutex::new(RealtimeSender::new(
                channel.handle(),
                crate::datagram_flows::SessionDatagramTx::new(
                    channel.keys.tx_key(),
                    &channel.keys.session_id,
                    true,
                ),
            ))),
            ingress_parent.handle(),
            [4; 32],
        );
        assert!(
            pool.selected_sender(
                veil_proto::priority::INTERACTIVE,
                body,
                kind,
                Some(&Arc::downgrade(&extra)),
                &salt,
                &diagnostics
            )
            .is_none(),
            "saturation must not alias an existing live connection"
        );
        owners.push((channel, keys, raw));
        carriers.push(extra);
        for (i, witness) in witnesses.iter().enumerate() {
            let retained = pool
                .selected_sender(
                    veil_proto::priority::INTERACTIVE,
                    body,
                    kind,
                    Some(witness),
                    &salt,
                    &diagnostics,
                )
                .unwrap();
            assert!(Arc::ptr_eq(&retained, &senders[i]));
        }
    }
    let first = senders[0].clone();
    publish(&first, &frames[0]);
    timeout(Duration::from_secs(1), async {
        loop {
            let blocked = match &lock!(first).handle {
                LossyTransportHandle::Ordered(handle) => handle
                    .progress()
                    .active_record_age
                    .is_some_and(|age| age >= Duration::from_millis(2)),
                _ => false,
            };
            if blocked {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Every other receiver progresses without consuming the unread pipe.
    for i in 1..flow_count {
        let (keys, raw) = destinations[physical[i]].take().unwrap();
        let mut decoder =
            crate::datagram_flows::SessionDatagramRx::new(keys.rx_key(), &keys.session_id, true);
        let channel = keys.into_ordered(Box::new(raw)).unwrap();
        publish(&senders[i], &frames[i]);
        let packet = timeout(Duration::from_millis(250), channel.handle().recv())
            .await
            .unwrap()
            .unwrap();
        let decoded = decoder
            .decode_datagram(&packet, std::time::Instant::now())
            .unwrap()
            .unwrap();
        assert_eq!(decoded, frames[i]);
        assert_eq!(
            decode_realtime_lane_frame(&decoded).unwrap().0.priority(),
            veil_proto::priority::INTERACTIVE
        );
        assert!(destinations[physical[0]].is_some());
    }
    ingress_parent.handle().retire();
    assert!(
        carriers
            .iter()
            .all(|carrier| carrier.local_ingress_flow().is_none())
    );
    drop(owners);
}
