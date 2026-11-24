//! Private-network ACK return on the authenticated path used by Forward.

use std::time::Duration;

use veil_proto::delivery::{CHUNKED_ENVELOPE_MARKER, ChunkedEnvelopePayload, ForwardPayload};
use veil_types::NodeIdBytes;

use crate::ExpiryMap;

pub(crate) fn receipt_mac(key: &[u8; 32], content_id: &[u8; 32], relayed: bool) -> blake3::Hash {
    if relayed {
        let mut mac = blake3::Hasher::new_keyed(key);
        mac.update(b"veil/pnet/relayed-delivered/v1");
        mac.update(content_id);
        mac.finalize()
    } else {
        blake3::keyed_hash(key, content_id)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MessageBinding {
    Sealed(blake3::Hash),
    Chunked([u8; 16]),
}

#[derive(Clone, Copy)]
pub(crate) struct ForwardAck {
    pub(crate) content_id: [u8; 32],
    pub(crate) previous: NodeIdBytes,
    sender: NodeIdBytes,
    recipient: veil_proto::recipient::Recipient,
    binding: MessageBinding,
    attempt: Option<u8>,
    expires_at: u64,
}

impl ForwardAck {
    pub(crate) fn from_forward(forward: &ForwardPayload, previous: NodeIdBytes) -> Option<Self> {
        let envelope = &forward.envelope;
        let sender = envelope.sender_node_id();
        if sender == [0; 32] {
            return None;
        }
        let (content_id, binding) = match envelope.payload.first().copied()? {
            veil_proto::E2E_MARKER | veil_proto::RATCHET_E2E_MARKER if envelope.require_ack => (
                envelope.content_id,
                MessageBinding::Sealed(blake3::hash(&envelope.payload)),
            ),
            CHUNKED_ENVELOPE_MARKER => {
                let (id, transfer) =
                    ChunkedEnvelopePayload::acknowledged_transfer(&envelope.payload)?;
                (id, MessageBinding::Chunked(transfer))
            }
            _ => return None,
        };
        (content_id != [0; 32]).then_some(Self {
            content_id,
            previous,
            sender,
            recipient: envelope.recipient,
            binding,
            attempt: forward.delivery_attempt,
            expires_at: envelope
                .created_at
                .saturating_add(u64::from(envelope.ttl_secs)),
        })
    }

    pub(crate) fn is_revoked(&self, registry: &veil_app::registry::AppEndpointRegistry) -> bool {
        [&self.previous, &self.sender, &self.recipient.node_id]
            .into_iter()
            .any(|id| registry.is_peer_revoked(id))
    }

    fn same_message(&self, other: &Self) -> bool {
        self.sender == other.sender
            && self.recipient == other.recipient
            && self.binding == other.binding
            && self.expires_at == other.expires_at
    }
}

type RouteKey = ([u8; 32], NodeIdBytes);

struct Route {
    forward: ForwardAck,
    returned: bool,
}

/// Bounded per-node state owned by the dispatcher. Keys include the exact
/// authenticated session peer used on the way out. ACKs cannot create routes.
pub struct RelayDeliveryAcks(ExpiryMap<RouteKey, Route>);

impl Default for RelayDeliveryAcks {
    fn default() -> Self {
        // The three 5-second delivery windows fit inside this bound. A shorter
        // envelope lifetime is still enforced when using the route.
        Self(ExpiryMap::new(Duration::from_secs(30), 4096))
    }
}

impl RelayDeliveryAcks {
    pub(crate) fn record_admission(&mut self, downstream: NodeIdBytes, forward: ForwardAck) {
        let key = (forward.content_id, downstream);
        if let Some(route) = self.0.get_mut(&key) {
            if route.forward.same_message(&forward)
                && (forward.attempt > route.forward.attempt
                    || (matches!(forward.binding, MessageBinding::Chunked(_)) && route.returned))
            {
                route.forward = forward;
                route.returned = false;
            }
        } else {
            self.0.insert(
                key,
                Route {
                    forward,
                    returned: false,
                },
            );
        }
    }

    pub(crate) fn return_ack(
        &mut self,
        content_id: [u8; 32],
        downstream: NodeIdBytes,
        now: u64,
        enqueue: impl FnOnce(&ForwardAck) -> bool,
    ) {
        if let Some(route) = self.0.get_mut(&(content_id, downstream))
            && !route.returned
            && now <= route.forward.expires_at
            && enqueue(&route.forward)
        {
            route.returned = true;
        }
    }
}
