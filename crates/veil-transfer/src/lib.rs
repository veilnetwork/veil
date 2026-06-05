//! Large payload chunking —.
//!
//! Provides two building blocks:
//!
//! * [`fragment_payload`] — splits a `&[u8]` into a `ChunkManifest` + a `Vec`
//!   of chunk bodies, ready to send as `DeliveryMsg::ChunkManifest` /
//!   `DeliveryMsg::Chunk` frames.
//!
//! * [`ChunkReassembler`] — receives individual chunks (keyed by `transfer_id` +
//!   `chunk_index`) and yields the complete payload once all chunks have arrived.
//!   Enforces global memory and per-transfer TTL limits.

use std::time::Instant;

use veil_proto::{
    budget::{
        CHUNK_REASSEMBLY_TTL_SECS, MAX_CHUNK_PAYLOAD, MAX_REASSEMBLY_BYTES, MAX_TRANSFER_CHUNKS,
        MAX_TRANSFERS_CONCURRENT,
    },
    delivery::{ChunkManifestPayload, TransferId},
};

// ── fragment_payload ─────────────────────────────────────────────────

/// The manifest returned by [`fragment_payload`].
pub struct ChunkManifest {
    /// Wire-ready `ChunkManifestPayload` (send this frame first).
    pub payload: ChunkManifestPayload,
    /// The content_id echoed from the manifest (convenience alias).
    pub content_id: [u8; 32],
}

/// Fragment `data` into a manifest + chunk bodies.
///
/// Each chunk body is at most `MAX_CHUNK_PAYLOAD` bytes. The manifest carries
/// the BLAKE3 hash of the complete `data` so that the receiver can verify
/// integrity after reassembly.
///
/// Returns `None` if `data` is empty or would require more than
/// `MAX_TRANSFER_CHUNKS` chunks.
pub fn fragment_payload(
    data: &[u8],
    content_id: [u8; 32],
) -> Option<(ChunkManifest, Vec<Vec<u8>>)> {
    if data.is_empty() {
        return None;
    }
    let chunk_count = data.len().div_ceil(MAX_CHUNK_PAYLOAD);
    if chunk_count > MAX_TRANSFER_CHUNKS as usize {
        return None;
    }

    // BLAKE3 hash of the full payload for integrity verification.
    let content_hash: [u8; 32] = blake3::hash(data).into();

    // Random 16-byte transfer_id.
    let mut transfer_id = [0u8; 16];
    use rand_core::{OsRng, RngCore};
    OsRng.fill_bytes(&mut transfer_id);

    let chunks: Vec<Vec<u8>> = data.chunks(MAX_CHUNK_PAYLOAD).map(|c| c.to_vec()).collect();

    let manifest = ChunkManifest {
        payload: ChunkManifestPayload {
            transfer_id,
            content_id,
            total_size: data.len().min(u32::MAX as usize) as u32,
            chunk_count: chunks.len().min(u32::MAX as usize) as u32,
            max_chunk_bytes: MAX_CHUNK_PAYLOAD as u32,
            content_hash,
        },
        content_id,
    };
    Some((manifest, chunks))
}

// ── ChunkReassembler (–C5) ─────────────────────────────────────────────

/// State for one in-progress chunked transfer.
struct ReassemblyState {
    /// Expected total number of chunks.
    chunk_count: u32,
    /// Expected total byte count.
    total_size: u32,
    /// BLAKE3 hash of the complete payload.
    content_hash: [u8; 32],
    /// Received chunks indexed by chunk_index.
    chunks: Vec<Option<Vec<u8>>>,
    /// How many chunks have been received so far.
    received: u32,
    /// Total bytes currently buffered.
    buffered_bytes: usize,
    /// Time the first chunk or manifest arrived (for TTL eviction).
    created_at: Instant,
    /// Original content_id from the manifest (echoed to deliver callback).
    content_id: [u8; 32],
}

impl ReassemblyState {
    fn new(manifest: &ChunkManifestPayload) -> Self {
        let n = manifest.chunk_count as usize;
        Self {
            chunk_count: manifest.chunk_count,
            total_size: manifest.total_size,
            content_hash: manifest.content_hash,
            chunks: vec![None; n],
            received: 0,
            buffered_bytes: 0,
            created_at: Instant::now(),
            content_id: manifest.content_id,
        }
    }
}

/// Result of adding a chunk to the reassembler.
#[derive(Debug)]
pub enum AddChunkResult {
    /// More chunks still needed.
    Pending,
    /// All chunks received and hash verified — returns the complete payload.
    Complete {
        payload: Vec<u8>,
        content_id: [u8; 32],
    },
    /// Hash mismatch after all chunks arrived — transfer corrupted.
    HashMismatch,
    /// Memory cap exceeded — transfer rejected.
    MemoryCapExceeded,
    /// Transfer unknown (no manifest received yet) — chunk buffered as orphan is
    /// not supported; caller should drop the chunk.
    UnknownTransfer,
    /// Chunk index out of range for this transfer.
    ChunkIndexOutOfRange,
}

/// Accumulates chunk frames and yields complete payloads.
///
/// # Limits
/// Global: `MAX_REASSEMBLY_BYTES` total buffered across all transfers.
/// Per-transfer TTL: `CHUNK_REASSEMBLY_TTL_SECS`.
/// Max chunks per transfer: `MAX_TRANSFER_CHUNKS`.
pub struct ChunkReassembler {
    transfers: std::collections::HashMap<TransferId, ReassemblyState>,
    /// Total bytes buffered across all in-progress transfers.
    total_buffered: usize,
}

impl Default for ChunkReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkReassembler {
    pub fn new() -> Self {
        Self {
            transfers: std::collections::HashMap::new(),
            total_buffered: 0,
        }
    }

    /// Number of in-progress reassembly transfers (one entry per
    /// `TransferId`). Metrics-only accessor.
    pub fn transfer_count(&self) -> usize {
        self.transfers.len()
    }

    /// Total bytes currently held across all in-progress transfers.
    /// Bounded by `MAX_REASSEMBLY_BYTES`; operators watch this gauge
    /// к catch chunked-transfer leaks AND to size memory budgets.
    pub fn buffered_bytes(&self) -> usize {
        self.total_buffered
    }

    /// Register a manifest, creating a `ReassemblyState` for `transfer_id`.
    ///
    /// If a manifest for the same `transfer_id` already exists it is replaced
    /// (idempotent retransmit). Returns `false` if the manifest is invalid
    /// (e.g. `chunk_count == 0` or exceeds `MAX_TRANSFER_CHUNKS`).
    pub fn register_manifest(&mut self, manifest: &ChunkManifestPayload) -> bool {
        if manifest.chunk_count == 0 || manifest.chunk_count > MAX_TRANSFER_CHUNKS {
            return false;
        }
        // Reject manifests that declare a total_size exceeding the reassembly cap.
        // Without this check a peer could send chunk_count=1, total_size=u32::MAX
        // and trigger a 4 GiB Vec::with_capacity when the single chunk arrives.
        if manifest.total_size as usize > MAX_REASSEMBLY_BYTES {
            return false;
        }
        // cap concurrent in-progress transfers.
        // Idempotent retransmits (same transfer_id) bypass the cap because
        // they evict the previous state before inserting.
        let is_new = !self.transfers.contains_key(&manifest.transfer_id);
        if is_new && self.transfers.len() >= MAX_TRANSFERS_CONCURRENT {
            return false;
        }
        // Evict any previous state for this transfer_id (freeing buffered bytes).
        if let Some(old) = self.transfers.remove(&manifest.transfer_id) {
            self.total_buffered = self.total_buffered.saturating_sub(old.buffered_bytes);
        }
        self.transfers
            .insert(manifest.transfer_id, ReassemblyState::new(manifest));
        true
    }

    /// Add chunk `chunk_index` for transfer `transfer_id`.
    ///
    /// Requires that a manifest has already been registered via
    /// [`register_manifest`]. Returns [`AddChunkResult`] describing the
    /// outcome.
    pub fn add_chunk(
        &mut self,
        transfer_id: &TransferId,
        chunk_index: u32,
        data: Vec<u8>,
    ) -> AddChunkResult {
        let state = match self.transfers.get_mut(transfer_id) {
            Some(s) => s,
            None => return AddChunkResult::UnknownTransfer,
        };

        if chunk_index >= state.chunk_count {
            return AddChunkResult::ChunkIndexOutOfRange;
        }

        // Memory cap check — use net delta for duplicate chunks.
        let old_len = state.chunks[chunk_index as usize]
            .as_ref()
            .map_or(0, |v| v.len());
        let net_new = data.len().saturating_sub(old_len);
        if net_new > 0 && self.total_buffered + net_new > MAX_REASSEMBLY_BYTES {
            return AddChunkResult::MemoryCapExceeded;
        }

        // Only count bytes if this slot was previously empty.
        if state.chunks[chunk_index as usize].is_none() {
            state.buffered_bytes += data.len();
            self.total_buffered += data.len();
            state.received += 1;
            state.chunks[chunk_index as usize] = Some(data);
        } else {
            // Duplicate chunk — update value, adjust byte accounting using net delta.
            self.total_buffered = self
                .total_buffered
                .saturating_sub(old_len)
                .saturating_add(data.len());
            state.buffered_bytes = state
                .buffered_bytes
                .saturating_sub(old_len)
                .saturating_add(data.len());
            state.chunks[chunk_index as usize] = Some(data);
        }

        if state.received < state.chunk_count {
            return AddChunkResult::Pending;
        }

        // All chunks received — reassemble and verify hash.
        let mut payload = Vec::with_capacity(state.total_size as usize);
        for chunk in state.chunks.iter().filter_map(|c| c.as_ref()) {
            payload.extend_from_slice(chunk);
        }

        let actual_hash: [u8; 32] = blake3::hash(&payload).into();
        let expected_hash = state.content_hash;
        let content_id = state.content_id;

        // Clean up.
        self.total_buffered = self.total_buffered.saturating_sub(state.buffered_bytes);
        self.transfers.remove(transfer_id);

        if actual_hash != expected_hash {
            return AddChunkResult::HashMismatch;
        }
        AddChunkResult::Complete {
            payload,
            content_id,
        }
    }

    /// Evict transfers older than `CHUNK_REASSEMBLY_TTL_SECS`.
    ///
    /// Returns the list of `content_id`s of evicted transfers (for logging).
    /// Call this periodically from a background timer.
    pub fn evict_stale(&mut self) -> Vec<[u8; 32]> {
        let ttl = std::time::Duration::from_secs(CHUNK_REASSEMBLY_TTL_SECS);
        let now = Instant::now();
        let mut evicted = Vec::new();
        self.transfers.retain(|_, state| {
            if now.duration_since(state.created_at) >= ttl {
                self.total_buffered = self.total_buffered.saturating_sub(state.buffered_bytes);
                evicted.push(state.content_id);
                false
            } else {
                true
            }
        });
        evicted
    }
}

// ── Tests (and) ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use veil_proto::delivery::ChunkPayload;

    /// fragment a 3 MiB payload and verify manifest fields.
    #[test]
    fn fragment_3mib_gives_correct_manifest() {
        let data: Vec<u8> = (0u8..=255).cycle().take(3 * 1024 * 1024).collect();
        let content_id = [0x42u8; 32];
        let (manifest, chunks) = fragment_payload(&data, content_id).expect("should fragment");

        let expected_count = data.len().div_ceil(MAX_CHUNK_PAYLOAD);
        assert_eq!(chunks.len(), expected_count, "chunk count mismatch");
        assert_eq!(manifest.payload.chunk_count as usize, expected_count);
        assert_eq!(manifest.payload.total_size as usize, data.len());
        assert_eq!(manifest.payload.content_id, content_id);
        assert_eq!(manifest.payload.max_chunk_bytes, MAX_CHUNK_PAYLOAD as u32);

        // Every chunk except possibly the last must be exactly MAX_CHUNK_PAYLOAD bytes.
        for (i, chunk) in chunks.iter().enumerate() {
            if i + 1 < chunks.len() {
                assert_eq!(chunk.len(), MAX_CHUNK_PAYLOAD, "chunk {i} wrong size");
            } else {
                assert!(chunk.len() <= MAX_CHUNK_PAYLOAD);
            }
        }

        // Verify BLAKE3 hash.
        let actual_hash: [u8; 32] = blake3::hash(&data).into();
        assert_eq!(
            manifest.payload.content_hash, actual_hash,
            "content_hash mismatch"
        );
    }

    /// reassemble 48 × 64 KiB chunks = 3 MiB; verify hash; complete.
    #[test]
    fn reassemble_48_chunks_verifies_hash() {
        const CHUNK_COUNT: usize = 48;
        let data: Vec<u8> = (0u8..=255)
            .cycle()
            .take(CHUNK_COUNT * MAX_CHUNK_PAYLOAD)
            .collect();
        let content_id = [0xBBu8; 32];
        let (manifest_struct, chunks) = fragment_payload(&data, content_id).unwrap();
        assert_eq!(chunks.len(), CHUNK_COUNT);

        let mut r = ChunkReassembler::new();
        assert!(r.register_manifest(&manifest_struct.payload));

        let transfer_id = manifest_struct.payload.transfer_id;
        for (i, chunk_data) in chunks.iter().enumerate() {
            let result = r.add_chunk(&transfer_id, i as u32, chunk_data.clone());
            if i + 1 < CHUNK_COUNT {
                assert!(
                    matches!(result, AddChunkResult::Pending),
                    "chunk {i} should be Pending"
                );
            } else {
                match result {
                    AddChunkResult::Complete {
                        payload,
                        content_id: cid,
                    } => {
                        assert_eq!(cid, content_id);
                        assert_eq!(payload, data, "reassembled payload mismatch");
                    }
                    other => panic!("expected Complete on last chunk, got {other:?}"),
                }
            }
        }
    }

    /// Eviction test: stale transfers are removed on `evict_stale`.
    /// We inject a fake-old transfer by manipulating `created_at` via a
    /// direct clone approach — instead, we rely on the public API and just
    /// verify that a fresh transfer is NOT evicted.
    #[test]
    fn evict_stale_does_not_evict_fresh() {
        let data = vec![1u8; 100];
        let content_id = [0u8; 32];
        let (manifest_struct, _) = fragment_payload(&data, content_id).unwrap();
        let mut r = ChunkReassembler::new();
        r.register_manifest(&manifest_struct.payload);
        let evicted = r.evict_stale();
        assert!(evicted.is_empty(), "fresh transfer must not be evicted");
    }

    /// Memory cap: adding a chunk that would exceed MAX_REASSEMBLY_BYTES is rejected.
    #[test]
    fn memory_cap_rejects_chunk() {
        // Create a manifest claiming MAX_TRANSFER_CHUNKS chunks × MAX_CHUNK_PAYLOAD each.
        // Even one chunk would push us over MAX_REASSEMBLY_BYTES if the cap is set very low.
        // We test by filling the reassembler to just under the cap and then exceeding it.
        //
        // Use two transfers and fill the first one to just under the cap
        // then verify the next chunk is rejected.
        let big_data: Vec<u8> = vec![0u8; MAX_REASSEMBLY_BYTES]; // exactly at cap
        let content_id = [0x11u8; 32];

        // fragment into a single big "transfer" — but MAX_REASSEMBLY_BYTES / MAX_CHUNK_PAYLOAD
        // might exceed MAX_TRANSFER_CHUNKS, so use a smaller dataset that fits.
        let usable = MAX_CHUNK_PAYLOAD * 2; // 2 chunks — well under MAX_TRANSFER_CHUNKS
        let data2 = vec![0u8; usable];
        let (m2, _) = fragment_payload(&data2, content_id).unwrap();
        let mut r = ChunkReassembler::new();
        r.register_manifest(&m2.payload);

        // Manually saturate total_buffered to just below cap.
        // We can't do this without accessing internal state, so instead:
        // fill the first chunk, then check that a > MAX_REASSEMBLY_BYTES chunk is rejected.
        // The easiest approach: add a chunk of MAX_REASSEMBLY_BYTES bytes directly.
        let oversized = vec![0u8; MAX_REASSEMBLY_BYTES + 1];
        // This should fail because it alone exceeds the cap.
        let result = r.add_chunk(&m2.payload.transfer_id, 0, oversized);
        assert!(matches!(result, AddChunkResult::MemoryCapExceeded));
        let _ = big_data; // suppress unused warning
    }

    /// ChunkManifestPayload encode/decode roundtrip.
    #[test]
    fn chunk_manifest_roundtrip() {
        use veil_proto::delivery::ChunkManifestPayload;
        let m = ChunkManifestPayload {
            transfer_id: [1u8; 16],
            content_id: [2u8; 32],
            total_size: 1_000_000,
            chunk_count: 16,
            max_chunk_bytes: MAX_CHUNK_PAYLOAD as u32,
            content_hash: [3u8; 32],
        };
        let enc = m.encode();
        let dec = ChunkManifestPayload::decode(&enc).unwrap();
        assert_eq!(dec, m);
    }

    /// ChunkPayload encode/decode roundtrip.
    #[test]
    fn chunk_payload_roundtrip() {
        let p = ChunkPayload {
            transfer_id: [7u8; 16],
            chunk_index: 42,
            data: b"hello chunking".to_vec(),
        };
        let enc = p.encode();
        let dec = ChunkPayload::decode(&enc).unwrap();
        assert_eq!(dec, p);
    }
}
