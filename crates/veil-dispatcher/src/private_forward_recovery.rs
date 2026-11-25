use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::sync::{Notify, watch};
use veil_cfg::NodeId;
use veil_proto::{
    codec::encode_frame,
    delivery::ForwardPayload,
    family::{DeliveryMsg, FrameFamily},
    header::{FrameHeader, priority},
};
use veil_types::NodeIdBytes;
use veil_util::{lock, rlock};

use crate::{FrameDispatcher, RouteMissTx};

pub(crate) const PRIVATE_FORWARD_WAIT: Duration = Duration::from_secs(1);
const MAX_PENDING_FORWARDS: usize = 32;
const MAX_PENDING_PER_PEER: usize = 2;
const MAX_PENDING_PAYLOAD: usize = 8192;

struct HeldForward {
    until: Instant,
    ingress: NodeId,
    ingress_registration: u64,
    outgoing_hops: u8,
    payload: ForwardPayload,
}

impl HeldForward {
    fn destination(&self) -> NodeIdBytes {
        self.payload.envelope.recipient_node_id()
    }

    fn still_authorized(&self, dispatcher: &FrameDispatcher) -> bool {
        let now = veil_util::unix_secs_now_u64();
        self.payload
            .envelope
            .created_at
            .saturating_add(u64::from(self.payload.envelope.ttl_secs))
            >= now
            && !dispatcher
                .app_registry
                .is_peer_revoked(self.ingress.as_bytes())
            && !dispatcher.app_registry.is_peer_revoked(&self.destination())
            && !dispatcher
                .app_registry
                .is_peer_revoked(&self.payload.envelope.sender_node_id())
            && !dispatcher
                .congestion_monitor
                .as_ref()
                .is_some_and(|monitor| monitor.score_u8() > 200)
    }
}

/// One short in-memory hold for a private application datagram while the
/// existing route-miss service obtains a signed response.
#[derive(Default)]
pub struct PrivateForwardRecovery {
    held: Mutex<Vec<HeldForward>>,
    pending_changed: Notify,
}

impl FrameDispatcher {
    pub(crate) fn hold_private_forward(
        &self,
        payload: &ForwardPayload,
        ingress: NodeId,
        outgoing_hops: u8,
        traffic_class: u8,
        route_miss: &RouteMissTx,
    ) -> bool {
        let dst = payload.envelope.recipient_node_id();
        if dst == self.local_node_id
            || payload.envelope.require_ack
            || payload.traffic_class == Some(priority::REALTIME)
            || payload.envelope.payload.len() > MAX_PENDING_PAYLOAD
            || !matches!(
                payload.envelope.payload.first().copied(),
                Some(veil_proto::E2E_MARKER | veil_proto::RATCHET_E2E_MARKER)
            )
        {
            return false;
        }
        let Some(registration) = self
            .session_tx_registry
            .as_ref()
            .and_then(|reg| rlock!(reg).live_registration(ingress.as_bytes()))
        else {
            return false;
        };
        let recovery = &self.private_forward_recovery;
        let mut held = lock!(recovery.held);
        if held.len() >= MAX_PENDING_FORWARDS
            || held.iter().filter(|item| item.ingress == ingress).count() >= MAX_PENDING_PER_PEER
            || held.iter().any(|item| item.destination() == dst)
        {
            return false;
        }
        // Publish under the same lock used by the response path. Even an
        // immediate reply cannot overtake insertion once the job is queued.
        if route_miss.try_send((dst, traffic_class)).is_err() {
            return false;
        }
        held.push(HeldForward {
            until: Instant::now() + PRIVATE_FORWARD_WAIT,
            ingress,
            ingress_registration: registration,
            outgoing_hops,
            payload: payload.clone(),
        });
        drop(held);
        recovery.pending_changed.notify_one();
        true
    }

    /// Called only after validating the signed reply to our own discovery.
    pub(crate) fn resume_private_forward(&self, dst: NodeIdBytes, next: NodeId) {
        let next = *next.as_bytes();
        if next == self.local_node_id || self.app_registry.is_peer_revoked(&next) {
            return;
        }
        if next != dst
            && rlock!(self.crypto.peer_cap_flags)
                .get(&next)
                .is_some_and(|flags| flags & veil_proto::session::cap_flags::CAN_RELAY == 0)
        {
            return;
        }
        let Some(registry) = &self.session_tx_registry else {
            return;
        };
        let registry = rlock!(registry);
        let mut queue = lock!(self.private_forward_recovery.held);
        let now = Instant::now();
        let Some(index) = queue.iter().position(|item| {
            item.destination() == dst && item.ingress.as_bytes() != &next && now < item.until
        }) else {
            return;
        };
        let item = &queue[index];
        if !item.still_authorized(self)
            || registry.live_registration(item.ingress.as_bytes())
                != Some(item.ingress_registration)
        {
            queue.remove(index);
            return;
        }
        let mut payload = item.payload.clone();
        payload.next_hop_node_id = next;
        payload.relay_hops = item.outgoing_hops;
        payload.traffic_class = payload
            .traffic_class
            .filter(|class| *class == priority::INTERACTIVE);
        let body = payload.encode();
        let mut header = FrameHeader::new(FrameFamily::Delivery as u8, DeliveryMsg::Forward as u16);
        header.set_priority(priority::INTERACTIVE);
        header.body_len = body.len() as u32;
        let admitted = registry.send_to(&next, priority::INTERACTIVE, encode_frame(&header, &body));
        if admitted {
            queue.remove(index);
        } else if let Some(metrics) = &self.metrics {
            metrics.inc_send_to_failed();
        }
    }

    /// Runtime-owned expiry loop. An idle relay waits without polling.
    pub async fn expire_private_forwards(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let recovery = &self.private_forward_recovery;
        while !*shutdown.borrow() {
            let pending = recovery.pending_changed.notified();
            let deadline = lock!(recovery.held).iter().map(|item| item.until).min();
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { break; }
                }
                _ = pending => {}
                _ = async {
                    if let Some(deadline) = deadline {
                        tokio::time::sleep_until(deadline.into()).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    let now = Instant::now();
                    let expired: Vec<_> = lock!(recovery.held)
                        .extract_if(.., |item| item.until <= now)
                        .collect();
                    for item in expired {
                        if item.still_authorized(&self) {
                            self.try_recursive_relay_with_ingress(
                                &item.payload,
                                item.ingress,
                                item.destination(),
                                Some(item.ingress_registration),
                            );
                        }
                    }
                }
            }
        }
        lock!(recovery.held).clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use veil_proto::{
        codec::decode_header, delivery::DeliveryEnvelope, family::RoutingMsg, header::HEADER_SIZE,
        recipient::Recipient, routing::RouteResponsePayload,
    };
    use veil_routing::discovery_paths::{ReplyTo, RequestKey};
    use veil_session::SessionTxRegistry;
    use veil_util::wlock;

    #[test]
    fn a_held_forward_requires_a_recent_signed_answer_and_the_original_ingress() {
        use crate::DispatchResult;

        let mut relay = crate::make_test_dispatcher(veil_cfg::NodeRole::Core);
        relay.app_registry =
            Arc::new(veil_app::AppEndpointRegistry::new().with_peer_revocation_check(|_| false));
        let ingress = [71; 32];
        let next = [72; 32];
        let key = SigningKey::from_bytes(&[73; 32]);
        let dst = *blake3::hash(key.verifying_key().as_bytes()).as_bytes();
        let mut registry = SessionTxRegistry::new();
        let mut upstream = registry.register(ingress);
        let mut downstream = registry.register(next);
        let registry = Arc::new(std::sync::RwLock::new(registry));
        relay.session_tx_registry = Some(Arc::clone(&registry));
        let (miss, mut requests) = tokio::sync::mpsc::channel(8);
        let payload = ForwardPayload {
            next_hop_node_id: relay.local_node_id,
            envelope: DeliveryEnvelope {
                recipient: Recipient::any(dst),
                sender_node_id: ingress,
                src_app_id: [74; 32],
                app_id: [75; 32],
                endpoint_id: 1,
                content_id: [76; 32],
                created_at: veil_util::unix_secs_now_u64(),
                ttl_secs: 30,
                payload: vec![veil_proto::RATCHET_E2E_MARKER, 5, 6],
                trace_id: 7,
                require_ack: false,
            },
            relay_hops: 2,
            delivery_attempt: None,
            traffic_class: None,
        };
        let response = |id, via, signed| {
            let mut reply = RouteResponsePayload {
                target_node_id: dst,
                requester_node_id: relay.local_node_id,
                request_id: id,
                transports: Vec::new(),
                relay_ids: Vec::new(),
                mlkem_pubkey: None,
                signature: [0; 64],
                ed25519_pubkey: Some(key.verifying_key().to_bytes().to_vec()),
                target_labels: Vec::new(),
            };
            if signed {
                reply.signature = key.sign(&reply.signable_bytes()).to_bytes();
            }
            let header =
                FrameHeader::new(FrameFamily::Routing as u8, RoutingMsg::RouteResponse as u16);
            relay.dispatch_routing(&header, &reply.encode(), via)
        };
        let witness = |id, at| {
            let request = RequestKey {
                requester: relay.local_node_id,
                target: dst,
                id,
            };
            assert!(lock!(relay.discovery_paths).remember_request(request, ReplyTo::Local, at));
        };
        let hold = || {
            relay.hold_private_forward(&payload, ingress.into(), 3, priority::INTERACTIVE, &miss)
        };

        assert!(hold());
        assert!(!hold(), "one held frame per destination");
        assert_eq!(requests.try_recv().unwrap(), (dst, priority::INTERACTIVE));
        response(1, next.into(), true);
        assert!(
            downstream.try_recv().is_err(),
            "a signature alone cannot release a frame"
        );
        witness(2, Instant::now() - PRIVATE_FORWARD_WAIT * 2);
        response(2, next.into(), true);
        assert!(
            downstream.try_recv().is_err(),
            "previous discovery is too old"
        );
        witness(3, Instant::now());
        assert!(matches!(
            response(3, next.into(), false),
            DispatchResult::Violation(_)
        ));
        assert!(downstream.try_recv().is_err());
        response(3, ingress.into(), true);
        assert!(
            upstream.try_recv().is_err(),
            "cannot route a held frame back through ingress"
        );
        response(3, next.into(), true);

        let (_, frame) = downstream
            .try_recv()
            .expect("recent verified route releases first frame");
        let hdr = decode_header(&frame).unwrap();
        assert_eq!(hdr.msg_type, DeliveryMsg::Forward as u16);
        let forwarded = ForwardPayload::decode(&frame[HEADER_SIZE..]).unwrap();
        assert_eq!(forwarded.next_hop_node_id, next);
        assert_eq!(forwarded.relay_hops, 3);
        assert_eq!(forwarded.envelope, payload.envelope);
        response(3, next.into(), true);
        assert!(
            downstream.try_recv().is_err(),
            "one dispatch per held frame"
        );

        assert!(hold());
        let _replacement = wlock!(registry).register(ingress);
        witness(4, Instant::now());
        response(4, next.into(), true);
        assert!(
            downstream.try_recv().is_err(),
            "replacement ingress cannot inherit the frame"
        );
        assert!(lock!(relay.private_forward_recovery.held).is_empty());
    }
}
