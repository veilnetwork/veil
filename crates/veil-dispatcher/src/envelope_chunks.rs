//! Reassembly of relay-chunked `DeliveryEnvelope`s.
//!
//! The sender splits an oversized envelope payload into N pieces, wraps each in
//! a [`ChunkedEnvelopePayload`] header, and ships each piece as an ordinary
//! relayable `DeliveryMsg::Forward` envelope (see `veil-ipc`'s `handle_ipc_send`
//! relay path). This reassembler runs on the destination: it collects the
//! pieces for a `transfer_id`, and once all chunks arrive it reconstructs the
//! ORIGINAL `DeliveryEnvelope` (the per-chunk envelopes all carry identical
//! addressing metadata) with the reassembled payload, so the standard terminal
//! delivery path (E2E-decrypt → addressed `route_ipc_deliver` → ACK) can run
//! unchanged.
//!
//! Bounded against memory-exhaustion: a global byte budget
//! ([`MAX_REASSEMBLY_BYTES`]), a cap on concurrent transfers
//! ([`MAX_CONCURRENT_TRANSFERS`]), per-transfer chunk/size validation, and a
//! TTL ([`CHUNK_REASSEMBLY_TTL_SECS`]) after which a partial transfer is evicted.

use std::collections::HashMap;

use veil_proto::budget::{CHUNK_REASSEMBLY_TTL_SECS, MAX_REASSEMBLY_BYTES};
use veil_proto::delivery::{ChunkedEnvelopePayload, DeliveryEnvelope, TransferId};

/// Cap on simultaneously-tracked chunked transfers. Bounds the reassembler's
/// HashMap so a flood of distinct `transfer_id`s with a single chunk each cannot
/// grow memory without bound. New transfers beyond this are dropped until an
/// existing one completes or ages out.
pub const MAX_CONCURRENT_TRANSFERS: usize = 64;

/// Outcome of feeding one chunk into the reassembler.
#[derive(Debug)]
pub enum AddChunkResult {
    /// Transfer is still missing chunks.
    Pending,
    /// All chunks received — the reconstructed original envelope is ready for
    /// terminal delivery.
    Complete(Box<DeliveryEnvelope>),
    /// Chunk ignored (duplicate index, inconsistent metadata, or caps hit). The
    /// `&'static str` is a short reason for logging.
    Rejected(&'static str),
}

/// Per-transfer accumulation state.
struct TransferState {
    chunk_count: u32,
    total_size: u32,
    orig_content_id: [u8; 32],
    require_ack: bool,
    // Addressing metadata snapshot from the first chunk's envelope — identical
    // across all chunks of one transfer; used to rebuild the original envelope.
    recipient: veil_proto::recipient::Recipient,
    sender_node_id: [u8; 32],
    src_app_id: [u8; 32],
    app_id: [u8; 32],
    endpoint_id: u32,
    // Received chunk bodies indexed by chunk_index (None = not yet seen).
    received: Vec<Option<Vec<u8>>>,
    received_count: u32,
    received_bytes: usize,
    /// Unix-secs deadline after which this partial transfer is evicted.
    deadline: u64,
}

/// Bounded reassembler for relay-chunked envelopes.
#[derive(Default)]
pub struct EnvelopeChunkReassembler {
    transfers: HashMap<TransferId, TransferState>,
    total_buffered: usize,
}

impl EnvelopeChunkReassembler {
    /// Construct an empty reassembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of in-flight transfers (test/metrics helper).
    pub fn transfer_count(&self) -> usize {
        self.transfers.len()
    }

    /// Total buffered chunk bytes across all in-flight transfers.
    pub fn buffered_bytes(&self) -> usize {
        self.total_buffered
    }

    /// Feed one chunk (already decoded from the chunk-envelope's payload). The
    /// `envelope` is the carrier chunk-envelope — its addressing fields are
    /// snapshotted on first sight and used to rebuild the original message.
    ///
    /// `now` is the current Unix time in seconds (injected for testability).
    pub fn add(
        &mut self,
        envelope: &DeliveryEnvelope,
        chunk: ChunkedEnvelopePayload,
        now: u64,
    ) -> AddChunkResult {
        // Opportunistic eviction of timed-out partials on each add.
        self.evict_expired(now);

        let entry = self.transfers.get_mut(&chunk.transfer_id);
        if entry.is_none() {
            // New transfer — enforce concurrency + global byte caps before
            // allocating the per-chunk vector.
            if self.transfers.len() >= MAX_CONCURRENT_TRANSFERS {
                return AddChunkResult::Rejected("too many concurrent transfers");
            }
            // `decode` already validated chunk_count (1..=MAX_TRANSFER_CHUNKS),
            // chunk_index < chunk_count, total_size <= MAX_REASSEMBLY_BYTES, and
            // data.len() <= MAX_CHUNK_PAYLOAD.
            if self.total_buffered.saturating_add(chunk.data.len()) > MAX_REASSEMBLY_BYTES {
                return AddChunkResult::Rejected("global reassembly budget exceeded");
            }
            let mut received = vec![None; chunk.chunk_count as usize];
            let data_len = chunk.data.len();
            received[chunk.chunk_index as usize] = Some(chunk.data);
            self.total_buffered += data_len;
            self.transfers.insert(
                chunk.transfer_id,
                TransferState {
                    chunk_count: chunk.chunk_count,
                    total_size: chunk.total_size,
                    orig_content_id: chunk.orig_content_id,
                    require_ack: chunk.require_ack,
                    recipient: envelope.recipient,
                    sender_node_id: envelope.sender_node_id,
                    src_app_id: envelope.src_app_id,
                    app_id: envelope.app_id,
                    endpoint_id: envelope.endpoint_id,
                    received,
                    received_count: 1,
                    received_bytes: data_len,
                    deadline: now.saturating_add(CHUNK_REASSEMBLY_TTL_SECS),
                },
            );
            // A 1-chunk transfer completes immediately.
            return self.try_complete(&chunk.transfer_id);
        }

        let state = entry.expect("checked Some above");
        // Reject chunks whose framing disagrees with the established transfer —
        // a confused or malicious relay must not be able to corrupt reassembly.
        if chunk.chunk_count != state.chunk_count
            || chunk.total_size != state.total_size
            || chunk.orig_content_id != state.orig_content_id
        {
            return AddChunkResult::Rejected("inconsistent chunk metadata");
        }
        let idx = chunk.chunk_index as usize;
        if idx >= state.received.len() {
            return AddChunkResult::Rejected("chunk_index out of range");
        }
        if state.received[idx].is_some() {
            return AddChunkResult::Rejected("duplicate chunk");
        }
        if self.total_buffered.saturating_add(chunk.data.len()) > MAX_REASSEMBLY_BYTES {
            return AddChunkResult::Rejected("global reassembly budget exceeded");
        }
        let data_len = chunk.data.len();
        state.received[idx] = Some(chunk.data);
        state.received_count += 1;
        state.received_bytes += data_len;
        self.total_buffered += data_len;
        self.try_complete(&chunk.transfer_id)
    }

    /// If `transfer_id` has all chunks, concatenate them, validate the total
    /// size, remove the state, and return the reconstructed original envelope.
    fn try_complete(&mut self, transfer_id: &TransferId) -> AddChunkResult {
        let Some(state) = self.transfers.get(transfer_id) else {
            return AddChunkResult::Pending;
        };
        if state.received_count != state.chunk_count {
            return AddChunkResult::Pending;
        }
        if state.received_bytes != state.total_size as usize {
            // Reassembled size disagrees with the advertised total — drop it.
            let removed = self.transfers.remove(transfer_id).expect("present");
            self.total_buffered = self.total_buffered.saturating_sub(removed.received_bytes);
            return AddChunkResult::Rejected("reassembled size != total_size");
        }
        let state = self.transfers.remove(transfer_id).expect("present");
        self.total_buffered = self.total_buffered.saturating_sub(state.received_bytes);

        let mut payload = Vec::with_capacity(state.total_size as usize);
        for piece in state.received.into_iter() {
            // All Some: received_count == chunk_count == received.len().
            payload.extend_from_slice(&piece.expect("all chunks present"));
        }

        let envelope = DeliveryEnvelope {
            recipient: state.recipient,
            sender_node_id: state.sender_node_id,
            src_app_id: state.src_app_id,
            app_id: state.app_id,
            endpoint_id: state.endpoint_id,
            content_id: state.orig_content_id,
            created_at: veil_util::unix_secs_now_u64(),
            ttl_secs: 0,
            payload,
            trace_id: 0,
            require_ack: state.require_ack,
        };
        AddChunkResult::Complete(Box::new(envelope))
    }

    /// Drop-in eviction sweep using the current wall clock — called from the
    /// runtime maintenance tick. Returns the number of partial transfers dropped.
    pub fn evict_stale(&mut self) -> usize {
        self.evict_expired(veil_util::unix_secs_now_u64())
    }

    /// Evict partial transfers whose TTL has elapsed. Returns the count evicted.
    pub fn evict_expired(&mut self, now: u64) -> usize {
        let before = self.transfers.len();
        let mut freed = 0usize;
        self.transfers.retain(|_, s| {
            let keep = now <= s.deadline;
            if !keep {
                freed += s.received_bytes;
            }
            keep
        });
        self.total_buffered = self.total_buffered.saturating_sub(freed);
        before - self.transfers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn carrier(content_id: [u8; 32]) -> DeliveryEnvelope {
        DeliveryEnvelope {
            recipient: veil_proto::recipient::Recipient::any([1u8; 32]),
            sender_node_id: [9u8; 32],
            src_app_id: [5u8; 32],
            app_id: [2u8; 32],
            endpoint_id: 42,
            content_id, // per-chunk unique id (unused by reassembly)
            created_at: 0,
            ttl_secs: 30,
            payload: vec![],
            trace_id: 0,
            require_ack: false,
        }
    }

    fn chunk(
        tid: [u8; 16],
        idx: u32,
        count: u32,
        total: u32,
        data: Vec<u8>,
    ) -> ChunkedEnvelopePayload {
        ChunkedEnvelopePayload {
            transfer_id: tid,
            chunk_index: idx,
            chunk_count: count,
            total_size: total,
            orig_content_id: [0xAAu8; 32],
            require_ack: true,
            data,
        }
    }

    #[test]
    fn reassembles_in_order() {
        let mut r = EnvelopeChunkReassembler::new();
        let tid = [1u8; 16];
        let total = 6;
        assert!(matches!(
            r.add(&carrier([0; 32]), chunk(tid, 0, 3, total, vec![1, 2]), 100),
            AddChunkResult::Pending
        ));
        assert!(matches!(
            r.add(&carrier([1; 32]), chunk(tid, 1, 3, total, vec![3, 4]), 100),
            AddChunkResult::Pending
        ));
        match r.add(&carrier([2; 32]), chunk(tid, 2, 3, total, vec![5, 6]), 100) {
            AddChunkResult::Complete(env) => {
                assert_eq!(env.payload, vec![1, 2, 3, 4, 5, 6]);
                assert_eq!(env.content_id, [0xAAu8; 32]); // orig_content_id
                assert!(env.require_ack);
                assert_eq!(env.app_id, [2u8; 32]);
                assert_eq!(env.endpoint_id, 42);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
        assert_eq!(r.transfer_count(), 0);
        assert_eq!(r.buffered_bytes(), 0);
    }

    #[test]
    fn out_of_order_completes() {
        let mut r = EnvelopeChunkReassembler::new();
        let tid = [2u8; 16];
        assert!(matches!(
            r.add(&carrier([0; 32]), chunk(tid, 2, 3, 6, vec![5, 6]), 0),
            AddChunkResult::Pending
        ));
        assert!(matches!(
            r.add(&carrier([0; 32]), chunk(tid, 0, 3, 6, vec![1, 2]), 0),
            AddChunkResult::Pending
        ));
        match r.add(&carrier([0; 32]), chunk(tid, 1, 3, 6, vec![3, 4]), 0) {
            AddChunkResult::Complete(env) => assert_eq!(env.payload, vec![1, 2, 3, 4, 5, 6]),
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_chunk_rejected() {
        let mut r = EnvelopeChunkReassembler::new();
        let tid = [3u8; 16];
        r.add(&carrier([0; 32]), chunk(tid, 0, 2, 4, vec![1, 2]), 0);
        assert!(matches!(
            r.add(&carrier([0; 32]), chunk(tid, 0, 2, 4, vec![9, 9]), 0),
            AddChunkResult::Rejected(_)
        ));
    }

    #[test]
    fn inconsistent_metadata_rejected() {
        let mut r = EnvelopeChunkReassembler::new();
        let tid = [4u8; 16];
        r.add(&carrier([0; 32]), chunk(tid, 0, 3, 6, vec![1, 2]), 0);
        // Same transfer_id but different chunk_count → reject.
        assert!(matches!(
            r.add(&carrier([0; 32]), chunk(tid, 1, 4, 6, vec![3, 4]), 0),
            AddChunkResult::Rejected(_)
        ));
    }

    #[test]
    fn size_mismatch_rejected() {
        let mut r = EnvelopeChunkReassembler::new();
        let tid = [5u8; 16];
        // total advertised 6 but pieces sum to 5 → reject on completion.
        r.add(&carrier([0; 32]), chunk(tid, 0, 2, 6, vec![1, 2]), 0);
        assert!(matches!(
            r.add(&carrier([0; 32]), chunk(tid, 1, 2, 6, vec![3, 4, 5]), 0),
            AddChunkResult::Rejected("reassembled size != total_size")
        ));
        assert_eq!(r.transfer_count(), 0);
    }

    #[test]
    fn ttl_eviction() {
        let mut r = EnvelopeChunkReassembler::new();
        let tid = [6u8; 16];
        r.add(&carrier([0; 32]), chunk(tid, 0, 2, 4, vec![1, 2]), 1000);
        assert_eq!(r.transfer_count(), 1);
        // Advance past TTL on the next add of a different transfer.
        let tid2 = [7u8; 16];
        r.add(
            &carrier([0; 32]),
            chunk(tid2, 0, 2, 4, vec![1, 2]),
            1000 + CHUNK_REASSEMBLY_TTL_SECS + 1,
        );
        // tid evicted, only tid2 remains.
        assert_eq!(r.transfer_count(), 1);
        assert_eq!(r.buffered_bytes(), 2);
    }

    #[test]
    fn single_chunk_completes_immediately() {
        let mut r = EnvelopeChunkReassembler::new();
        let tid = [8u8; 16];
        match r.add(&carrier([0; 32]), chunk(tid, 0, 1, 3, vec![1, 2, 3]), 0) {
            AddChunkResult::Complete(env) => assert_eq!(env.payload, vec![1, 2, 3]),
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn concurrency_cap_enforced() {
        let mut r = EnvelopeChunkReassembler::new();
        for i in 0..MAX_CONCURRENT_TRANSFERS {
            let mut tid = [0u8; 16];
            tid[0] = (i & 0xff) as u8;
            tid[1] = (i >> 8) as u8;
            // multi-chunk so each stays pending and occupies a slot
            assert!(matches!(
                r.add(&carrier([0; 32]), chunk(tid, 0, 2, 4, vec![1, 2]), 0),
                AddChunkResult::Pending
            ));
        }
        // One more distinct transfer must be rejected.
        let tid = [0xFFu8; 16];
        assert!(matches!(
            r.add(&carrier([0; 32]), chunk(tid, 0, 2, 4, vec![1, 2]), 0),
            AddChunkResult::Rejected("too many concurrent transfers")
        ));
    }
}
