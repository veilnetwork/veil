//! Production selection and authenticated record I/O, with one deliberately
//! unread pipe. The same sender/recipient must not collapse distinct ingress
//! connections onto that pipe. These are generic opaque Forward cells.
use super::*;
use crate::parallel_binding::{ParallelKeys, ParallelParent};
use tokio::time::{Duration, timeout};
use veil_anonymity::circuit_carrier::{Carrier, DatagramCarrier};

fn raw_pair(
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

fn publish(sender: &Arc<Mutex<RealtimeSender>>, frame: &[u8]) {
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
async fn distinct_forward_ingress_progresses_while_the_same_routes_other_pipe_is_blocked() {
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
    for _ in 0..2 {
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
    let frames = [opaque_forward(21), opaque_forward(22)];
    let (_, body, kind) = decode_realtime_lane_frame(&frames[0]).unwrap();
    let first = pool
        .selected_sender(
            veil_proto::priority::INTERACTIVE,
            body,
            kind,
            Some(&witnesses[0]),
            &salt,
            &diagnostics,
        )
        .unwrap();
    let second = pool
        .selected_sender(
            veil_proto::priority::INTERACTIVE,
            body,
            kind,
            Some(&witnesses[1]),
            &salt,
            &diagnostics,
        )
        .unwrap();
    assert!(
        !Arc::ptr_eq(&first, &second),
        "same-route Forward connections were merged"
    );
    for sender in [&first, &second] {
        let guard = lock!(sender);
        let (_, counter) = guard.sent_counter.as_ref().unwrap();
        assert!(*counter >= crate::local_datagram_status::LOCAL_DATAGRAM_PRIORITIES.len());
    }
    let first_physical = pool
        .slots
        .iter()
        .position(|ready| {
            ready
                .as_ref()
                .is_some_and(|ready| Arc::ptr_eq(&ready.sender, &first))
        })
        .unwrap();
    let second_physical = pool
        .slots
        .iter()
        .position(|ready| {
            ready
                .as_ref()
                .is_some_and(|ready| Arc::ptr_eq(&ready.sender, &second))
        })
        .unwrap();

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
    // Starting the second receiver cannot consume the first unread raw pipe.
    let (keys, raw) = destinations[second_physical].take().unwrap();
    let mut decoder =
        crate::datagram_flows::SessionDatagramRx::new(keys.rx_key(), &keys.session_id, true);
    let channel = keys.into_ordered(Box::new(raw)).unwrap();
    publish(&second, &frames[1]);
    let packet = timeout(Duration::from_millis(250), channel.handle().recv())
        .await
        .unwrap()
        .unwrap();
    let decoded = decoder
        .decode_datagram(&packet, std::time::Instant::now())
        .unwrap()
        .unwrap();
    assert_eq!(decoded, frames[1]);
    assert!(destinations[first_physical].is_some());
    // A selection cannot spend another flow's admission or change wire class.
    assert_eq!(
        decode_realtime_lane_frame(&decoded).unwrap().0.priority(),
        veil_proto::priority::INTERACTIVE
    );
    ingress_parent.handle().retire();
    assert!(
        carriers
            .iter()
            .all(|carrier| carrier.local_ingress_flow().is_none())
    );
    drop(owners);
}
