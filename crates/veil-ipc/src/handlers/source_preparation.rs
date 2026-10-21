//! Prepare owned local producers without forwarding an application frame.
use std::sync::RwLock;
use veil_proto::ipc::PrepareLocalDatagramPayload;
use veil_types::{FrameBroadcaster, LocalDatagramChannelState as State};

pub(crate) fn prepare(
    body: &[u8],
    negotiated: bool,
    owns_app: impl FnOnce(&[u8; 32]) -> bool,
    registry: Option<&dyn FrameBroadcaster>,
    route_cache: Option<&RwLock<veil_routing::RouteCache>>,
) -> State {
    if !negotiated {
        return State::Unsupported;
    }
    let Ok(request) = PrepareLocalDatagramPayload::decode(body) else {
        return State::Unsupported;
    };
    if !owns_app(&request.source_app_id) {
        return State::Unsupported;
    }
    let Some(registry) = registry.filter(|reg| reg.supports_local_datagram_preparation()) else {
        return State::Unsupported;
    };
    let peers = if request.relayed {
        // Same existing candidates as relay sends. No discovery, mailbox,
        // direct-path promotion or invented application packet is involved.
        crate::source_paths::sealed_relay_hops_for_source(
            &request.peer_node_id,
            route_cache,
            registry,
            request.local_lane,
        )
        .into_iter()
        .take(2)
        .collect::<Vec<_>>()
    } else {
        let devices = registry.devices_of(&request.peer_node_id);
        if devices.is_empty() {
            vec![request.peer_node_id]
        } else {
            devices
        }
    };
    if peers.is_empty() {
        return State::Unsupported;
    }
    let mut result = State::Ready;
    for peer in peers {
        let state =
            registry.prepare_local_datagram_channel(&peer, request.local_lane, request.refresh);
        // Request every candidate, even if an earlier one cannot prepare.
        result = match (result, state) {
            (State::Unsupported, _) | (_, State::Unsupported) => State::Unsupported,
            (State::Warming, _) | (_, State::Warming) => State::Warming,
            _ => State::Ready,
        };
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct Registry {
        calls: Mutex<Vec<([u8; 32], u8)>>,
        state: State,
        datagram_hop: Option<[u8; 32]>,
    }
    impl FrameBroadcaster for Registry {
        fn has_neutral_forward_datagram_transport(&self, peer: &[u8; 32]) -> bool {
            self.datagram_hop.as_ref() == Some(peer)
        }
        fn supports_local_datagram_preparation(&self) -> bool {
            true
        }
        fn prepare_local_datagram_channel(&self, peer: &[u8; 32], lane: u8, _: bool) -> State {
            self.calls.lock().unwrap().push((*peer, lane));
            self.state
        }
        fn send_to(&self, _: &[u8; 32], _: u8, _: Vec<u8>) -> bool {
            panic!("preparation must not forward a packet")
        }
        fn send_to_all_with_priority(&self, _: u8, _: Arc<[u8]>) {
            panic!("preparation must not broadcast a packet")
        }
        fn active_node_ids(&self) -> Vec<[u8; 32]> {
            vec![[2; 32], [3; 32], [4; 32]]
        }
        fn devices_of(&self, id: &[u8; 32]) -> Vec<[u8; 32]> {
            if *id == [8; 32] {
                vec![[2; 32], [3; 32]]
            } else {
                vec![]
            }
        }
    }
    fn request(relayed: bool) -> PrepareLocalDatagramPayload {
        PrepareLocalDatagramPayload {
            source_app_id: [1; 32],
            peer_node_id: [8; 32],
            local_lane: veil_proto::priority::BULK,
            relayed,
            refresh: true,
        }
    }
    fn registry(state: State) -> Registry {
        Registry {
            calls: Mutex::new(vec![]),
            state,
            datagram_hop: None,
        }
    }

    #[test]
    fn relay_preparation_uses_the_senders_preferred_datagram_hops() {
        let mut r = registry(State::Ready);
        r.datagram_hop = Some([4; 32]);
        assert_eq!(
            prepare(&request(true).encode(), true, |_| true, Some(&r), None),
            State::Ready
        );
        assert_eq!(
            *r.calls.lock().unwrap(),
            vec![
                ([4; 32], veil_proto::priority::BULK),
                ([2; 32], veil_proto::priority::BULK),
            ]
        );
    }

    #[test]
    fn requires_negotiation_owned_source_and_valid_payload() {
        let r = registry(State::Ready);
        let body = request(false).encode();
        assert_eq!(
            prepare(&body, false, |_| true, Some(&r), None),
            State::Unsupported
        );
        assert_eq!(
            prepare(&body, true, |_| false, Some(&r), None),
            State::Unsupported
        );
        for size in 0..body.len() {
            assert_eq!(
                prepare(&body[..size], true, |_| true, Some(&r), None),
                State::Unsupported
            );
        }
        assert!(r.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn direct_alias_prepares_each_verified_device_without_relay_fallback() {
        let r = registry(State::Warming);
        assert_eq!(
            prepare(
                &request(false).encode(),
                true,
                |id| *id == [1; 32],
                Some(&r),
                None
            ),
            State::Warming
        );
        assert_eq!(
            *r.calls.lock().unwrap(),
            vec![
                ([2; 32], veil_proto::priority::BULK),
                ([3; 32], veil_proto::priority::BULK)
            ]
        );
        let r = registry(State::Ready);
        let mut req = request(false);
        req.peer_node_id = [9; 32];
        assert_eq!(
            prepare(&req.encode(), true, |_| true, Some(&r), None),
            State::Ready
        );
        assert_eq!(
            *r.calls.lock().unwrap(),
            vec![([9; 32], veil_proto::priority::BULK)]
        );
    }

    #[test]
    fn relay_preparation_uses_bounded_existing_candidates_even_if_unsupported() {
        let r = registry(State::Unsupported);
        assert_eq!(
            prepare(&request(true).encode(), true, |_| true, Some(&r), None),
            State::Unsupported
        );
        let calls = r.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(
            calls
                .iter()
                .all(|(peer, lane)| *peer != [8; 32] && *lane == veil_proto::priority::BULK)
        );
    }
}
