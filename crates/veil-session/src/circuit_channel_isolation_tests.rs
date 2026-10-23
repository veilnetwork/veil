//! Circuit-id bucket collisions must not share an ordered congestion budget.
use super::forward_channel_isolation_tests::{publish, raw_pair};
use super::*;
use tokio::time::{Duration, timeout};
use veil_anonymity::{
    circuit_data::CircuitCellBytes, circuit_setup::CircuitInstall, circuit_table::CircuitTable,
    circuit_wire::CircuitDataPayload,
};

fn circuit_frame(cid: u32) -> Vec<u8> {
    let body = CircuitDataPayload {
        circuit_id: cid,
        seq: 1,
        ciphertext: vec![42; 1024],
    }
    .encode(CircuitCellBytes::new(1024).unwrap())
    .unwrap();
    let mut header = FrameHeader::new(
        FrameFamily::RelayChain as u8,
        veil_proto::family::RelayChainMsg::CircuitDatagram as u16,
    );
    header.set_priority(veil_proto::priority::INTERACTIVE);
    header.body_len = body.len() as u32;
    veil_proto::codec::encode_frame(&header, &body)
}

#[tokio::test]
async fn unavailable_ordered_source_uses_an_unowned_authenticated_spare() {
    for (source, &priority) in ORDERED_PRIORITIES.iter().enumerate() {
        for occupied in [false, true] {
            let parent = ParallelParent::new([1; 32], [2; 32], [3; 32]);
            let remote = ParallelParent::new([1; 32], [3; 32], [2; 32]);
            let diagnostics = Arc::new(ParallelDiagnostics::default());
            let context = super::super::ordered_receiver_tests::pool_fixture_context();
            let mut pool = Pool::default();
            let assigned = pool.assignments.source(source).unwrap().physical;
            let spare = if occupied {
                pool.assignments.transit(None, 0).unwrap().physical
            } else {
                (assigned + 1) % TOTAL_SLOTS
            };
            let (channel, keys, raw) = raw_pair(&parent, &remote, 65536);
            let mut decoder = crate::datagram_flows::SessionDatagramRx::new(
                keys.rx_key(),
                &keys.session_id,
                true,
            );
            let receiver = keys.into_ordered(Box::new(raw)).unwrap();
            pool.slots[spare] = Some(Ready::new(
                Owner::Outgoing(channel),
                parent.handle(),
                context,
                diagnostics.clone(),
            ));
            let status = Arc::new(LocalDatagramStatus::default());
            let lease = Arc::new(status.activate_without_signaling());
            assert_eq!(
                status.request(priority),
                crate::LocalDatagramChannelState::Warming
            );
            mark(&mut pool, &Arc::downgrade(&lease));
            let frame = circuit_frame(1);
            let (_, body, kind) = decode_realtime_lane_frame(&frame).unwrap();
            let selected =
                pool.selected_sender(priority, body, kind, None, &[17; 32], &diagnostics);
            if occupied {
                assert!(
                    selected.is_none(),
                    "another owner's ready channel was stolen"
                );
                assert_eq!(
                    status.state(priority),
                    crate::LocalDatagramChannelState::Warming
                );
                assert_eq!(pool.assignments.source_physical(source), Some(assigned));
                continue;
            }
            assert!(
                selected.is_some(),
                "ready spare ignored while assigned child is unavailable"
            );
            assert_eq!(
                status.state(priority),
                crate::LocalDatagramChannelState::Ready
            );
            assert_eq!(pool.assignments.source_physical(source), Some(spare));
            assert!(pool.slots[assigned].is_none());
            publish(&selected.unwrap(), &frame);
            let packet = timeout(Duration::from_secs(1), receiver.handle().recv())
                .await
                .unwrap()
                .unwrap();
            let decoded = decoder
                .decode_datagram(&packet, std::time::Instant::now())
                .unwrap()
                .unwrap();
            assert_eq!(decoded, frame, "recovery changed the neutral frame");
        }
    }
}

#[tokio::test]
async fn unavailable_ordered_transit_uses_an_unowned_authenticated_spare() {
    let parent = ParallelParent::new([1; 32], [2; 32], [3; 32]);
    let remote = ParallelParent::new([1; 32], [3; 32], [2; 32]);
    let diagnostics = Arc::new(ParallelDiagnostics::default());
    let context = super::super::ordered_receiver_tests::pool_fixture_context();
    let mut pool = Pool::default();
    let frame = circuit_frame(1);
    let (_, body, kind) = decode_realtime_lane_frame(&frame).unwrap();
    let table = CircuitTable::new();
    let state = table
        .install(
            &CircuitInstall {
                circuit_id_in: 1,
                circuit_id_out: 1,
                circuit_key: [5; 32],
                cell_bytes: CircuitCellBytes::new(1024).unwrap(),
            },
            [7; 32],
            Some([8; 32]),
            1000,
        )
        .unwrap();
    let witness = state.outbound_carrier(true);
    let salt = [17; 32];
    let bucket = parallel_lanes::neutral_transit_index(&salt, body, kind).unwrap();
    let assigned = pool
        .assignments
        .transit(Some(&witness), bucket)
        .unwrap()
        .physical;
    let spare = (assigned + 1) % TOTAL_SLOTS;
    let (channel, keys, raw) = raw_pair(&parent, &remote, 65536);
    let mut decoder =
        crate::datagram_flows::SessionDatagramRx::new(keys.rx_key(), &keys.session_id, true);
    let receiver = keys.into_ordered(Box::new(raw)).unwrap();
    pool.slots[spare] = Some(Ready::new(
        Owner::Outgoing(channel),
        parent.handle(),
        context,
        diagnostics.clone(),
    ));
    let selected = pool
        .selected_sender(
            veil_proto::priority::INTERACTIVE,
            body,
            kind,
            Some(&witness),
            &salt,
            &diagnostics,
        )
        .expect("neutral transit ignored its ready spare");
    assert!(Arc::ptr_eq(
        &selected,
        &pool.slots[spare].as_ref().unwrap().sender
    ));
    assert_eq!(
        pool.assignments
            .transit(Some(&witness), bucket)
            .unwrap()
            .physical,
        spare
    );
    publish(&selected, &frame);
    let packet = timeout(Duration::from_secs(1), receiver.handle().recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        decoder
            .decode_datagram(&packet, std::time::Instant::now())
            .unwrap()
            .unwrap(),
        frame
    );
}

#[tokio::test]
async fn colliding_cold_circuits_progress_on_independent_authenticated_pipes() {
    verify_colliding_circuits(2, false).await;
}

#[tokio::test]
async fn full_circuit_pool_preserves_independence_and_refuses_a_seventh_flow() {
    verify_colliding_circuits(TOTAL_SLOTS, false).await;
}

#[tokio::test]
async fn shared_legacy_return_pipe_does_not_merge_ready_circuit_assignments() {
    verify_colliding_circuits(TOTAL_SLOTS, true).await;
}

async fn verify_colliding_circuits(count: usize, shared_return: bool) {
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
    let salt = [17; 32];
    let bucket = |frame: &[u8]| {
        let (_, body, kind) = decode_realtime_lane_frame(frame).unwrap();
        parallel_lanes::neutral_transit_index(&salt, body, kind).unwrap()
    };
    let first_frame = circuit_frame(1);
    let frames: Vec<_> = (1..100)
        .map(circuit_frame)
        .filter(|frame| bucket(frame) == bucket(&first_frame))
        .take(count + 1)
        .collect();
    assert_eq!(frames.len(), count + 1);
    let table = CircuitTable::new();
    let states: Vec<_> = frames
        .iter()
        .map(|frame| {
            let (_, body, _) = decode_realtime_lane_frame(frame).unwrap();
            let cid = u32::from_be_bytes(body[..4].try_into().unwrap());
            table
                .install(
                    &CircuitInstall {
                        circuit_id_in: cid,
                        circuit_id_out: cid,
                        circuit_key: [5; 32],
                        cell_bytes: CircuitCellBytes::new(1024).unwrap(),
                    },
                    [7; 32],
                    Some([8; 32]),
                    1000,
                )
                .unwrap()
        })
        .collect();
    let common_return = parallel_lanes::make_carrier(
        &diagnostics,
        pool.slots[0].as_ref().unwrap().sender.clone(),
        parent.handle(),
        [8; 32],
    );
    if shared_return {
        for state in &states {
            state.observe_carrier(false, 1, Some(&Arc::downgrade(&common_return)));
        }
    }
    let senders: Vec<_> = states
        .iter()
        .zip(&frames)
        .take(count)
        .map(|(state, frame)| {
            let (_, body, kind) = decode_realtime_lane_frame(frame).unwrap();
            pool.selected_sender(
                veil_proto::priority::INTERACTIVE,
                body,
                kind,
                Some(&state.outbound_carrier(true)),
                &salt,
                &diagnostics,
            )
            .unwrap()
        })
        .collect();
    for (i, sender) in senders.iter().enumerate() {
        assert!(
            senders[..i].iter().all(|other| !Arc::ptr_eq(sender, other)),
            "distinct live circuits with colliding legacy buckets were merged"
        );
    }
    if count == TOTAL_SLOTS {
        let (_, body, kind) = decode_realtime_lane_frame(&frames[count]).unwrap();
        assert!(
            pool.selected_sender(
                veil_proto::priority::INTERACTIVE,
                body,
                kind,
                Some(&states[count].outbound_carrier(true)),
                &salt,
                &diagnostics
            )
            .is_none()
        );
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
    publish(&senders[0], &frames[0]);
    timeout(Duration::from_secs(1), async {
        loop {
            let blocked = {
                let sender = lock!(senders[0]);
                let LossyTransportHandle::Ordered(handle) = &sender.handle else {
                    panic!("ordered pipe")
                };
                handle
                    .progress()
                    .active_record_age
                    .is_some_and(|age| age >= Duration::from_millis(2))
            };
            if blocked {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for i in 1..count {
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
        assert!(destinations[physical[0]].is_some());
    }
    // Detachment retires ownership even while this test retains the old state.
    // A new circuit can reclaim that slot without displacing another live flow.
    let cid = states[0].circuit_id_in;
    table.remove(&[7; 32], cid);
    let (_, body, kind) = decode_realtime_lane_frame(&frames[count]).unwrap();
    let selected = pool
        .selected_sender(
            veil_proto::priority::INTERACTIVE,
            body,
            kind,
            Some(&states[count].outbound_carrier(true)),
            &salt,
            &diagnostics,
        )
        .unwrap();
    assert!(Arc::ptr_eq(&selected, &senders[0]));
}
