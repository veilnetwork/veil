//! Packet-driven cold-chain regression: real dispatchers and bounded session
//! outboxes, no network clocks, pre-seeded data routes, or transit credits.
use std::sync::{Arc, Mutex, RwLock};

use ed25519_dalek::{Signer, SigningKey};
use veil_proto::{
    codec::decode_header,
    family::RoutingMsg,
    priority::INTERACTIVE,
    routing::{PowResponsePayload, RouteRequestPayload},
};
use veil_session::{FrameOutbox, SessionTxRegistry};

use crate::{DispatchResult, FrameDispatcher, encode_routing_frame, make_test_dispatcher};

fn cold_chain(pow: u8, known_key: bool) {
    // The requested physical graph has two clients plus six transit nodes.
    let keys: Vec<_> = (1..=8).map(|i| SigningKey::from_bytes(&[i; 32])).collect();
    let ids: Vec<[u8; 32]> = keys
        .iter()
        .map(|k| *blake3::hash(k.verifying_key().as_bytes()).as_bytes())
        .collect();
    let registries: Vec<_> = (0..8)
        .map(|_| Arc::new(RwLock::new(SessionTxRegistry::new())))
        .collect();
    let mut nodes: Vec<FrameDispatcher> = (0..8)
        .map(|i| {
            let mut node = make_test_dispatcher(if i == 0 || i == 7 {
                veil_cfg::NodeRole::Leaf
            } else {
                veil_cfg::NodeRole::Core
            });
            node.local_node_id = ids[i];
            Arc::get_mut(&mut node.crypto).unwrap().local_signing_key =
                Some(Arc::new(keys[i].clone()));
            node.session_tx_registry = Some(Arc::clone(&registries[i]));
            node.reputation = Some(Arc::new(Mutex::new(
                veil_reputation::ReputationTracker::new(),
            )));
            node
        })
        .collect();
    nodes[7].pow_difficulty = pow;
    // Isolate reverse-path mechanics first. Unknown-key bootstrap is covered
    // separately: even a requester that already knows the issuer fails here.
    if known_key {
        nodes[0].crypto.peer_pubkeys.lock().unwrap().insert_lru(
            ids[7],
            (0, keys[7].verifying_key().to_bytes().to_vec()),
            veil_proto::budget::MAX_PEER_PUBKEYS_CACHE,
        );
    }
    let mut links: Vec<(usize, usize, FrameOutbox)> = Vec::new();
    for from in 0usize..8 {
        for to in [from.checked_sub(1), (from + 1 < 8).then_some(from + 1)]
            .into_iter()
            .flatten()
        {
            let rx = registries[from].write().unwrap().register(ids[to]);
            links.push((from, to, rx));
            nodes[from]
                .dht
                .add_contact_trusted(veil_dht::routing::Contact::new(
                    ids[to],
                    "quic://192.0.2.1:18443",
                ));
        }
    }
    let mut request = RouteRequestPayload {
        target_node_id: ids[7],
        requester_node_id: ids[0],
        request_id: 41,
        ttl: 7,
        signature: [0; 64],
    };
    request.signature = keys[0].sign(&request.signable_bytes()).to_bytes();
    assert!(nodes[0].discovery_paths.lock().unwrap().remember_request(
        veil_routing::discovery_paths::RequestKey {
            requester: ids[0],
            target: ids[7],
            id: request.request_id
        },
        veil_routing::discovery_paths::ReplyTo::Local,
        std::time::Instant::now(),
    ));
    assert!(registries[0].read().unwrap().send_to(
        &ids[1],
        INTERACTIVE,
        encode_routing_frame(RoutingMsg::RouteRequest, &request.encode())
    ));
    let mut deliveries = 0;
    let mut target_saw_solution = pow == 0;
    let mut solved = 0;
    loop {
        let mut changed = false;
        for (from, to, rx) in &mut links {
            let Ok((_, frame)) = rx.try_recv() else {
                continue;
            };
            changed = true;
            deliveries += 1;
            assert!(deliveries <= 256, "discovery packet loop");
            let header = decode_header(&frame).unwrap();
            if *to == 7 && header.msg_type == RoutingMsg::PowResponse as u16 {
                target_saw_solution = true;
            }
            if header.msg_type == RoutingMsg::RouteResponse as u16
                || header.msg_type == RoutingMsg::PowAccept as u16
            {
                assert!(
                    target_saw_solution,
                    "disclosure before the target received its PoW solution"
                );
            }
            let action =
                nodes[*to].dispatch(&header, &frame[veil_proto::HEADER_SIZE..], ids[*from]);
            match action {
                DispatchResult::Response(reply) => {
                    assert!(registries[*to].read().unwrap().send_to(
                        &ids[*from],
                        INTERACTIVE,
                        reply
                    ));
                }
                DispatchResult::SolvePow(challenge) => {
                    assert_eq!(*to, 0);
                    solved += 1;
                    let solution = veil_routing::pow::solve_pow(
                        &ids[0],
                        &challenge.challenge_nonce,
                        challenge.difficulty,
                    );
                    let response = PowResponsePayload {
                        requester_node_id: ids[0],
                        acceptor_node_id: ids[7],
                        challenge_nonce: challenge.challenge_nonce,
                        solution_nonce: solution,
                    };
                    assert!(registries[0].read().unwrap().send_to(
                        &ids[*from],
                        INTERACTIVE,
                        encode_routing_frame(RoutingMsg::PowResponse, &response.encode())
                    ));
                }
                DispatchResult::NoResponse => {}
                other => panic!("unexpected discovery action at node {to}: {other:?}"),
            }
        }
        if !changed {
            break;
        }
    }
    assert_eq!(
        solved,
        usize::from(pow > 0),
        "requester must receive and solve the challenge exactly once"
    );
    for i in 0..7 {
        assert_eq!(
            nodes[i].route_cache.read().unwrap().lookup(&ids[7]),
            Some(ids[i + 1]),
            "verified route must traverse the next physical neighbor at node {i}"
        );
    }
    // Data must use the verified chain with every reputation ledger still cold.
    // This checks transit arrival, independently of application E2E decoding.
    use veil_proto::{
        delivery::{DeliveryEnvelope, ForwardPayload},
        family::{DeliveryMsg, FrameFamily},
    };
    let payload = b"ordinary forwarding after verified discovery".to_vec();
    let forward = ForwardPayload {
        next_hop_node_id: ids[1],
        envelope: DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any(ids[7]),
            sender_node_id: ids[0],
            src_app_id: [1; 32],
            app_id: [2; 32],
            endpoint_id: 3,
            content_id: [0xE7; 32],
            created_at: veil_util::unix_secs_now_u64(),
            ttl_secs: 30,
            payload: payload.clone(),
            trace_id: 0,
            require_ack: false,
        },
        relay_hops: 0,
        delivery_attempt: None,
        traffic_class: None,
    };
    let mut header = veil_proto::header::FrameHeader::new(
        FrameFamily::Delivery as u8,
        DeliveryMsg::Forward as u16,
    );
    let body = forward.encode();
    header.body_len = body.len() as u32;
    assert!(registries[0].read().unwrap().send_to(
        &ids[1],
        INTERACTIVE,
        veil_proto::codec::encode_frame(&header, &body)
    ));
    for to in 1..8 {
        let (_, _, rx) = links
            .iter_mut()
            .find(|(from, dest, _)| *from == to - 1 && *dest == to)
            .unwrap();
        let (_, frame) = rx.try_recv().expect("data reaches the next physical hop");
        let header = decode_header(&frame).unwrap();
        assert_eq!(header.family, FrameFamily::Delivery as u8);
        assert_eq!(
            header.msg_type,
            DeliveryMsg::Forward as u16,
            "must not fall back to reputation-gated RecursiveRelay"
        );
        let body = &frame[veil_proto::HEADER_SIZE..];
        let actual = ForwardPayload::decode(body).unwrap();
        assert_eq!(actual.envelope.payload, payload);
        if to < 7 {
            assert!(matches!(
                nodes[to].dispatch(&header, body, ids[to - 1]),
                DispatchResult::NoResponse
            ));
        }
    }
}

#[test]
fn cold_six_core_chain_returns_verified_route_without_pow() {
    cold_chain(0, true);
}

#[test]
fn cold_six_core_chain_returns_verified_route_with_pow() {
    cold_chain(4, true);
}

#[test]
fn cold_six_core_chain_bootstraps_an_unknown_pow_issuer() {
    cold_chain(4, false);
}

fn context_challenge() -> (
    FrameDispatcher,
    veil_proto::routing::PowChallengePayload,
    SigningKey,
) {
    use veil_proto::routing::{PowChallengeContext, PowChallengePayload};
    let mut node = make_test_dispatcher(veil_cfg::NodeRole::Core);
    node.local_node_id = [0xA1; 32];
    let key = SigningKey::from_bytes(&[91; 32]);
    let mut challenge = PowChallengePayload {
        requester_node_id: node.local_node_id,
        acceptor_node_id: *blake3::hash(key.verifying_key().as_bytes()).as_bytes(),
        challenge_nonce: [92; 32],
        difficulty: 4,
        signature: [0; 64],
        context: Some(PowChallengeContext {
            request_id: 93,
            ed25519_pubkey: key.verifying_key().to_bytes(),
        }),
    };
    challenge.signature = key.sign(&challenge.signable_bytes()).to_bytes();
    node.discovery_paths.lock().unwrap().remember_request(
        veil_routing::discovery_paths::RequestKey {
            requester: challenge.requester_node_id,
            target: challenge.acceptor_node_id,
            id: 93,
        },
        veil_routing::discovery_paths::ReplyTo::Local,
        std::time::Instant::now(),
    );
    (node, challenge, key)
}
fn challenge_action(
    node: &FrameDispatcher,
    challenge: &veil_proto::routing::PowChallengePayload,
) -> DispatchResult {
    let frame = encode_routing_frame(RoutingMsg::PowChallenge, &challenge.encode());
    node.dispatch(
        &decode_header(&frame).unwrap(),
        &frame[veil_proto::HEADER_SIZE..],
        [94; 32],
    )
}
#[test]
fn unknown_challenge_proves_key_without_mutating_key_or_authorization_cache() {
    let (node, challenge, _) = context_challenge();
    assert!(matches!(
        challenge_action(&node, &challenge),
        DispatchResult::SolvePow(_)
    ));
    assert_eq!(node.crypto.peer_pubkeys.lock().unwrap().map_len(), 0);
}
#[test]
fn unsolicited_or_expired_unknown_challenges_never_start_solver() {
    for expired in [false, true] {
        let (node, challenge, _) = context_challenge();
        *node.discovery_paths.lock().unwrap() = Default::default();
        if expired {
            node.discovery_paths.lock().unwrap().remember_request(
                veil_routing::discovery_paths::RequestKey {
                    requester: challenge.requester_node_id,
                    target: challenge.acceptor_node_id,
                    id: 93,
                },
                veil_routing::discovery_paths::ReplyTo::Local,
                std::time::Instant::now()
                    - std::time::Duration::from_secs(
                        veil_proto::budget::POW_CHALLENGE_TTL_SECS + 1,
                    ),
            );
        }
        assert!(matches!(
            challenge_action(&node, &challenge),
            DispatchResult::NoResponse
        ));
    }
}
#[test]
fn changed_signed_context_key_signature_and_stripped_context_are_rejected() {
    for variant in 0..5 {
        let (node, mut challenge, key) = context_challenge();
        match variant {
            0 => challenge.context.as_mut().unwrap().request_id ^= 1,
            1 => challenge.context.as_mut().unwrap().ed25519_pubkey[0] ^= 1,
            2 => challenge.signature[0] ^= 1,
            3 => {
                challenge.context = None;
            }
            _ => {
                challenge.acceptor_node_id[0] ^= 1;
                challenge.signature = key.sign(&challenge.signable_bytes()).to_bytes();
            }
        }
        assert!(
            matches!(
                challenge_action(&node, &challenge),
                DispatchResult::NoResponse
            ),
            "variant {variant}"
        );
        assert_eq!(node.crypto.peer_pubkeys.lock().unwrap().map_len(), 0);
    }
}

#[test]
fn forged_transit_response_does_not_learn_a_route_or_destroy_its_request() {
    use veil_proto::routing::RouteResponsePayload;
    let mut relay = make_test_dispatcher(veil_cfg::NodeRole::Core);
    relay.local_node_id = [0xB1; 32];
    let key = SigningKey::from_bytes(&[0xD1; 32]);
    let target = *blake3::hash(key.verifying_key().as_bytes()).as_bytes();
    let back = [0xA1; 32];
    let incoming = [0xC1; 32];
    let registry = Arc::new(RwLock::new(SessionTxRegistry::new()));
    let mut back_rx = registry.write().unwrap().register(back);
    let mut next_rx = registry.write().unwrap().register(incoming);
    relay.session_tx_registry = Some(Arc::clone(&registry));
    let request = RouteRequestPayload {
        requester_node_id: back,
        target_node_id: target,
        request_id: 41,
        ttl: 7,
        signature: [0; 64],
    };
    let bytes = encode_routing_frame(RoutingMsg::RouteRequest, &request.encode());
    relay.dispatch(
        &decode_header(&bytes).unwrap(),
        &bytes[veil_proto::HEADER_SIZE..],
        back,
    );
    assert!(next_rx.try_recv().is_ok());
    let mut response = RouteResponsePayload {
        requester_node_id: back,
        target_node_id: target,
        request_id: 41,
        transports: vec![],
        relay_ids: vec![],
        mlkem_pubkey: None,
        signature: [0; 64],
        ed25519_pubkey: Some(key.verifying_key().to_bytes().to_vec()),
        target_labels: vec![],
    };
    response.signature = key.sign(&response.signable_bytes()).to_bytes();
    let mut bad = response.clone();
    bad.signature[0] ^= 1;
    let frame = encode_routing_frame(RoutingMsg::RouteResponse, &bad.encode());
    assert!(matches!(
        relay.dispatch(
            &decode_header(&frame).unwrap(),
            &frame[veil_proto::HEADER_SIZE..],
            incoming
        ),
        DispatchResult::NoResponse
    ));
    assert!(relay.route_cache.read().unwrap().lookup(&target).is_none());
    assert!(back_rx.try_recv().is_err());
    let frame = encode_routing_frame(RoutingMsg::RouteResponse, &response.encode());
    relay.dispatch(
        &decode_header(&frame).unwrap(),
        &frame[veil_proto::HEADER_SIZE..],
        incoming,
    );
    assert_eq!(
        relay.route_cache.read().unwrap().lookup(&target),
        Some(incoming)
    );
    assert!(back_rx.try_recv().is_ok());
}

#[test]
fn stripping_context_cannot_downgrade_a_known_issuer_signature() {
    let (node, mut challenge, key) = context_challenge();
    node.crypto.peer_pubkeys.lock().unwrap().insert_lru(
        challenge.acceptor_node_id,
        (0, key.verifying_key().to_bytes().to_vec()),
        veil_proto::budget::MAX_PEER_PUBKEYS_CACHE,
    );
    challenge.context = None;
    assert!(matches!(
        challenge_action(&node, &challenge),
        DispatchResult::NoResponse
    ));
}
