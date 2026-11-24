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
    Chunked {
        transfer_id: [u8; 16],
        count: u32,
        size: u32,
        addressing: blake3::Hash,
    },
}

#[derive(Clone, Copy)]
struct ChunkAdmission {
    index: u32,
    hash: blake3::Hash,
}

#[derive(Clone, Copy)]
pub(crate) struct ForwardAck {
    pub(crate) content_id: [u8; 32],
    pub(crate) previous: NodeIdBytes,
    sender: NodeIdBytes,
    recipient: veil_proto::recipient::Recipient,
    binding: MessageBinding,
    chunk: Option<ChunkAdmission>,
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
        let (content_id, binding, chunk) = match envelope.payload.first().copied()? {
            veil_proto::E2E_MARKER | veil_proto::RATCHET_E2E_MARKER if envelope.require_ack => (
                envelope.content_id,
                MessageBinding::Sealed(blake3::hash(&envelope.payload)),
                None,
            ),
            CHUNKED_ENVELOPE_MARKER => {
                let header = ChunkedEnvelopePayload::acknowledged_chunk_header(&envelope.payload)?;
                (
                    header.orig_content_id,
                    MessageBinding::Chunked {
                        transfer_id: header.transfer_id,
                        count: header.chunk_count,
                        size: header.total_size,
                        addressing: crate::chunk_receipt::addressing(envelope),
                    },
                    Some(ChunkAdmission {
                        index: header.chunk_index,
                        // The outer carrier ID changes on retry. The indexed
                        // chunk header and ciphertext it encloses do not.
                        hash: blake3::hash(&envelope.payload),
                    }),
                )
            }
            _ => return None,
        };
        (content_id != [0; 32]).then_some(Self {
            content_id,
            previous,
            sender,
            recipient: envelope.recipient,
            binding,
            chunk,
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
    chunks: Option<Box<ChunkRoute>>,
}

const MAX_REORDERED_CHUNKS: usize = 8;
const MAX_ALTERNATE_PASSES: usize = 2;

struct ChunkPass {
    previous: NodeIdBytes,
    next_index: u32,
    digest: blake3::Hash,
    reordered: Vec<ChunkAdmission>,
}

impl ChunkPass {
    fn new(previous: NodeIdBytes) -> Self {
        Self {
            previous,
            next_index: 0,
            digest: blake3::hash(b"veil/pnet/relay-chunk-pass/v1"),
            reordered: Vec::new(),
        }
    }

    fn observe(&mut self, chunk: ChunkAdmission, count: u32) -> Option<blake3::Hash> {
        if chunk.index > self.next_index {
            if self.reordered.len() < MAX_REORDERED_CHUNKS
                && !self.reordered.iter().any(|seen| seen.index == chunk.index)
            {
                self.reordered.push(chunk);
            }
            return None;
        }
        if chunk.index < self.next_index {
            return None;
        }
        self.append(chunk.hash);
        while let Some(position) = self
            .reordered
            .iter()
            .position(|seen| seen.index == self.next_index)
        {
            let next = self.reordered.swap_remove(position);
            self.append(next.hash);
        }
        (self.next_index == count).then_some(self.digest)
    }

    fn append(&mut self, hash: blake3::Hash) {
        // Hash a fixed-size node with the prefix for internal nodes. A leaf
        // starts with the chunk wire marker and includes its index.
        let mut node = [1; 65];
        node[1..33].copy_from_slice(self.digest.as_bytes());
        node[33..].copy_from_slice(hash.as_bytes());
        self.digest = blake3::hash(&node);
        self.next_index += 1;
    }
}

struct ChunkRoute {
    original: ChunkPass,
    commitment: Option<blake3::Hash>,
    alternates: Vec<ChunkPass>,
    fallback: Option<NodeIdBytes>,
    last_receipt: Option<[u8; 32]>,
}

impl ChunkRoute {
    fn new(previous: NodeIdBytes) -> Self {
        Self {
            original: ChunkPass::new(previous),
            commitment: None,
            alternates: Vec::new(),
            fallback: None,
            last_receipt: None,
        }
    }

    fn matches_replay(&mut self, previous: NodeIdBytes, chunk: ChunkAdmission, count: u32) -> bool {
        let Some(commitment) = self.commitment else {
            return false;
        };

        let position = match self
            .alternates
            .iter()
            .position(|pass| pass.previous == previous)
        {
            Some(position) => position,
            // A candidate starts near the beginning of a batch and must
            // eventually provide the whole batch from this same peer.
            None if chunk.index < MAX_REORDERED_CHUNKS as u32
                && self.alternates.len() < MAX_ALTERNATE_PASSES =>
            {
                self.alternates.push(ChunkPass::new(previous));
                self.alternates.len() - 1
            }
            None => return false,
        };
        let Some(observed) = self.alternates[position].observe(chunk, count) else {
            return false;
        };
        self.alternates.remove(position);
        observed == commitment
    }
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
    /// A proven new chunk path can return one receipt already received from
    /// the same downstream, including when the old queue accepted it locally.
    pub(crate) fn record_admission(
        &mut self,
        downstream: NodeIdBytes,
        forward: ForwardAck,
    ) -> Option<[u8; 32]> {
        let key = (forward.content_id, downstream);
        let Some(route) = self.0.get_mut(&key) else {
            let chunks = if let (MessageBinding::Chunked { count, .. }, Some(chunk)) =
                (forward.binding, forward.chunk)
            {
                let mut state = ChunkRoute::new(forward.previous);
                state.commitment = state.original.observe(chunk, count);
                Some(Box::new(state))
            } else {
                None
            };
            self.0.insert(
                key,
                Route {
                    forward,
                    returned: false,
                    chunks,
                },
            );
            return None;
        };
        if !route.forward.same_message(&forward) {
            return None;
        }
        if let (MessageBinding::Chunked { count, .. }, Some(chunk), Some(chunks)) =
            (forward.binding, forward.chunk, &mut route.chunks)
        {
            if forward.previous == route.forward.previous {
                if chunks.commitment.is_none() {
                    chunks.commitment = chunks.original.observe(chunk, count);
                }
                route.returned = false;
            } else if chunks.matches_replay(forward.previous, chunk, count) {
                chunks.fallback = Some(route.forward.previous);
                route.forward = forward;
                route.returned = false;
                return chunks.last_receipt.take();
            }
        } else if forward.attempt > route.forward.attempt {
            route.forward = forward;
            route.returned = false;
        }
        None
    }

    pub(crate) fn return_ack(
        &mut self,
        content_id: [u8; 32],
        downstream: NodeIdBytes,
        mac: [u8; 32],
        now: u64,
        mut enqueue: impl FnMut(&ForwardAck) -> bool,
    ) {
        if let Some(route) = self.0.get_mut(&(content_id, downstream))
            && !route.returned
            && now <= route.forward.expires_at
        {
            route.returned = enqueue(&route.forward)
                || route
                    .chunks
                    .as_ref()
                    .and_then(|chunks| chunks.fallback)
                    .is_some_and(|previous| {
                        enqueue(&ForwardAck {
                            previous,
                            ..route.forward
                        })
                    });
            if let Some(chunks) = &mut route.chunks {
                // A local enqueue cannot tell whether the rest of the old
                // return path is live. Retain one receipt for a proven retry.
                chunks.last_receipt = Some(mac);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::delivery::DeliveryEnvelope;
    use veil_proto::recipient::Recipient;

    const ORIGINAL: NodeIdBytes = [1; 32];
    const BACKUP: NodeIdBytes = [2; 32];
    const OTHER: NodeIdBytes = [3; 32];
    const DOWNSTREAM: NodeIdBytes = [4; 32];
    const CONTENT: [u8; 32] = [5; 32];
    const MAC: [u8; 32] = [6; 32];

    fn chunk(previous: NodeIdBytes, index: u32, data: u8) -> ForwardAck {
        let payload = ChunkedEnvelopePayload {
            transfer_id: [8; 16],
            chunk_index: index,
            chunk_count: 3,
            total_size: 96,
            orig_content_id: CONTENT,
            require_ack: true,
            data: vec![data; 32],
        };
        let forward = ForwardPayload {
            next_hop_node_id: DOWNSTREAM,
            envelope: DeliveryEnvelope {
                recipient: Recipient::any(DOWNSTREAM),
                sender_node_id: [9; 32],
                src_app_id: [10; 32],
                app_id: [11; 32],
                endpoint_id: 1,
                content_id: [data; 32],
                created_at: 10,
                ttl_secs: 30,
                payload: payload.encode(),
                trace_id: 0,
                require_ack: false,
            },
            relay_hops: 1,
            delivery_attempt: None,
            traffic_class: None,
        };
        ForwardAck::from_forward(&forward, previous).unwrap()
    }

    #[test]
    fn shared_downstream_moves_only_after_one_peer_admits_the_matching_batch() {
        let mut routes = RelayDeliveryAcks::default();
        for index in [0, 2, 1] {
            assert_eq!(
                routes.record_admission(DOWNSTREAM, chunk(ORIGINAL, index, index as u8)),
                None
            );
        }
        for (index, value) in [(0, 0), (1, 99), (2, 2)] {
            assert_eq!(
                routes.record_admission(DOWNSTREAM, chunk(BACKUP, index, value)),
                None
            );
        }
        routes.return_ack(CONTENT, DOWNSTREAM, MAC, 15, |route| {
            assert_eq!(route.previous, ORIGINAL);
            false
        });

        assert_eq!(
            routes.record_admission(DOWNSTREAM, chunk(BACKUP, 1, 1)),
            None
        );
        assert_eq!(
            routes.record_admission(DOWNSTREAM, chunk(OTHER, 0, 0)),
            None
        );
        assert_eq!(
            routes.record_admission(DOWNSTREAM, chunk(BACKUP, 2, 2)),
            None
        );
        routes.return_ack(CONTENT, DOWNSTREAM, MAC, 16, |route| {
            assert_eq!(route.previous, ORIGINAL);
            false
        });

        assert_eq!(
            routes.record_admission(DOWNSTREAM, chunk(BACKUP, 0, 0)),
            Some(MAC)
        );
        routes.return_ack(CONTENT, DOWNSTREAM, MAC, 16, |route| {
            assert_eq!(route.previous, BACKUP);
            true
        });
        routes.return_ack(CONTENT, DOWNSTREAM, MAC, 16, |_| {
            panic!("duplicate receipt")
        });

        assert_eq!(
            routes.record_admission(DOWNSTREAM, chunk(BACKUP, 0, 0)),
            None
        );
        let mut attempted = Vec::new();
        routes.return_ack(CONTENT, DOWNSTREAM, MAC, 17, |route| {
            attempted.push(route.previous);
            route.previous == ORIGINAL
        });
        assert_eq!(attempted, [BACKUP, ORIGINAL]);
        for index in 0..2 {
            assert_eq!(
                routes.record_admission(DOWNSTREAM, chunk(ORIGINAL, index, index as u8)),
                None
            );
        }
        // The accepted enqueue above could have failed beyond this relay.
        assert_eq!(
            routes.record_admission(DOWNSTREAM, chunk(ORIGINAL, 2, 2)),
            Some(MAC)
        );
        assert_eq!(
            routes.record_admission(DOWNSTREAM, chunk(ORIGINAL, 1, 1)),
            None
        );
        routes.return_ack(CONTENT, DOWNSTREAM, MAC, 41, |_| panic!("expired receipt"));
    }
}
