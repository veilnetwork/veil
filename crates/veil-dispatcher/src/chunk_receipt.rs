//! Proof that a retrying hop carried bytes from a previously opened transfer.

use std::sync::Arc;

use veil_proto::delivery::{ChunkedEnvelopePayload, DeliveryEnvelope};
use veil_types::NodeIdBytes;

const TAG_BYTES: usize = 16;
const MAX_REPLAY_PEERS: usize = 4;

/// Ties a completed transfer to the ACK state created after its envelope opens.
#[derive(Clone, Debug)]
pub struct ChunkReceiptBinding(Arc<()>);

impl ChunkReceiptBinding {
    pub(crate) fn matches(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

struct TagPart {
    index: u32,
    chunk_len: usize,
    start: usize,
    len: usize,
    tag_offset: usize,
}

struct ReplayCandidate {
    peer: NodeIdBytes,
    received: u16,
    tag: [u8; TAG_BYTES],
}

pub(crate) struct ChunkReceiptReplay {
    pub(crate) binding: ChunkReceiptBinding,
    addressing: blake3::Hash,
    chunk_count: u32,
    total_size: u32,
    expires_at: u64,
    parts: Vec<TagPart>,
    tag_hash: blake3::Hash,
    candidates: Vec<ReplayCandidate>,
}

impl ChunkReceiptReplay {
    pub(crate) fn new(
        envelope: &DeliveryEnvelope,
        chunk_lengths: &[usize],
        expires_at: u64,
    ) -> Option<Self> {
        let tag_end = tag_end(&envelope.payload)?;
        let tag_start = tag_end.checked_sub(TAG_BYTES)?;
        let tag = envelope.payload.get(tag_start..tag_end)?;

        // Map the 16 bytes onto the original chunk boundaries. Empty chunks
        // consume no slots and even one-byte chunks require at most 16 parts.
        let mut parts = Vec::new();
        let mut end = envelope.payload.len();
        for (index, &len) in chunk_lengths.iter().enumerate().rev() {
            let start = end - len;
            let overlap_start = start.max(tag_start);
            let overlap_end = end.min(tag_end);
            if overlap_start < overlap_end {
                parts.push(TagPart {
                    index: index as u32,
                    chunk_len: len,
                    start: overlap_start - start,
                    len: overlap_end - overlap_start,
                    tag_offset: overlap_start - tag_start,
                });
            }
            if start <= tag_start {
                break;
            }
            end = start;
        }
        debug_assert_eq!(parts.iter().map(|part| part.len).sum::<usize>(), TAG_BYTES);
        Some(Self {
            binding: ChunkReceiptBinding(Arc::new(())),
            addressing: addressing(envelope),
            chunk_count: chunk_lengths.len() as u32,
            total_size: envelope.payload.len() as u32,
            expires_at,
            parts,
            tag_hash: blake3::hash(tag),
            candidates: Vec::new(),
        })
    }

    pub(crate) fn observe(
        &mut self,
        envelope: &DeliveryEnvelope,
        chunk: &ChunkedEnvelopePayload,
        peer: NodeIdBytes,
        now: u64,
    ) -> Option<ChunkReceiptBinding> {
        if now > self.expires_at
            || !chunk.require_ack
            || chunk.chunk_count != self.chunk_count
            || chunk.total_size != self.total_size
        {
            return None;
        }
        let part = self
            .parts
            .iter()
            .find(|part| part.index == chunk.chunk_index)?;
        if chunk.data.len() != part.chunk_len || addressing(envelope) != self.addressing {
            return None;
        }
        let bytes = &chunk.data[part.start..part.start + part.len];
        if self.parts.len() == 1 {
            return (blake3::hash(bytes) == self.tag_hash).then(|| self.binding.clone());
        }

        let index = if let Some(index) = self.candidates.iter().position(|entry| entry.peer == peer)
        {
            index
        } else {
            if self.candidates.len() == MAX_REPLAY_PEERS {
                self.candidates.remove(0);
            }
            let index = self.candidates.len();
            self.candidates.push(ReplayCandidate {
                peer,
                received: 0,
                tag: [0; TAG_BYTES],
            });
            index
        };
        let candidate = &mut self.candidates[index];
        candidate.tag[part.tag_offset..part.tag_offset + part.len].copy_from_slice(bytes);
        let mask = ((1u32 << part.len) - 1) << part.tag_offset;
        candidate.received |= mask as u16;
        if candidate.received != u16::MAX {
            return None;
        }

        // Check only a complete tag. Partial matches would let a peer learn
        // whether it guessed one of the short pieces correctly.
        let candidate = self.candidates.remove(index);
        (blake3::hash(&candidate.tag) == self.tag_hash).then(|| self.binding.clone())
    }
}

fn addressing(envelope: &DeliveryEnvelope) -> blake3::Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&envelope.recipient.node_id);
    hasher.update(&[envelope.recipient.instance_tag.byte()]);
    if let veil_proto::recipient::InstanceTag::Specific(instance) = envelope.recipient.instance_tag
    {
        hasher.update(&instance);
    }
    hasher.update(&envelope.sender_node_id);
    hasher.update(&envelope.src_app_id);
    hasher.update(&envelope.app_id);
    hasher.update(&envelope.endpoint_id.to_be_bytes());
    hasher.finalize()
}

fn tag_end(payload: &[u8]) -> Option<usize> {
    match *payload.first()? {
        veil_proto::RATCHET_E2E_MARKER => Some(payload.len()),
        veil_proto::E2E_MARKER => {
            // Legacy E2E decoding permits trailing bytes after its declared
            // ciphertext. Only the actual Poly1305 tag can prove the replay.
            let kem_len = u16::from_be_bytes(payload.get(2..4)?.try_into().ok()?) as usize;
            let ct_start = 1 + veil_proto::E2eEnvelope::HEADER_SIZE + kem_len;
            let length_offset = ct_start - 4;
            let ct_len =
                u32::from_be_bytes(payload.get(length_offset..ct_start)?.try_into().ok()?) as usize;
            let end = ct_start.checked_add(ct_len)?;
            (ct_len >= TAG_BYTES && end <= payload.len()).then_some(end)
        }
        _ => None,
    }
}
