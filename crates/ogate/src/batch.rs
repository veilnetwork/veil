//! Egress packet-batching wire format (Phase E27).
//!
//! A single IPC frame normally carries one IP packet.  At high pps that puts
//! the IPC / session / TCP pipeline at the bottleneck (4-6 await-points per
//! packet).  Batching coalesces up to 255 IP packets into one envelope:
//!
//! ```text
//! [0]:    magic = 0xB1  (distinct from IPv4 0x4N / IPv6 0x6N first byte)
//! [1]:    count = N     (u8, 1..=255)
//! [2..]:  N records of [u16-BE len][len bytes of IP packet]
//! ```
//!
//! The magic byte is chosen so legacy ogate peers — which feed received
//! bytes straight into `parse_ip_endpoints` — silently drop the envelope as
//! "not IPv4 or IPv6" instead of crashing.  No explicit version negotiation
//! is required: a node that has been upgraded sends batches by default; an
//! un-upgraded receiver drops them; an upgraded receiver decodes them.

use std::time::Instant;

use crate::routing::NodeId;

/// Magic first byte of a batched envelope.
pub const BATCH_MAGIC: u8 = 0xB1;

/// Maximum sub-packets per batch (one byte count).
pub const BATCH_MAX_COUNT: usize = 255;

/// Returns `true` if `data` starts with the batch magic.
#[inline]
pub fn is_batch_envelope(data: &[u8]) -> bool {
    data.first() == Some(&BATCH_MAGIC)
}

/// Per-peer outgoing batch buffer.
///
/// `bridge::run` keeps one of these per active peer so packets for different
/// destinations don't head-of-line block each other.
#[derive(Debug)]
pub struct PeerBatch {
    buf: Vec<u8>,
    count: u8,
    /// Cached at first-push time.  Flush task uses this to find the oldest
    /// pending batch when its deadline expires.
    first_push: Option<Instant>,
    /// Cached peer app_id at first-push time so flush doesn't have to
    /// re-resolve it against (possibly hot-swapped) routing state.
    app_id: [u8; 32],
}

impl PeerBatch {
    pub fn new(app_id: [u8; 32]) -> Self {
        let mut buf = Vec::with_capacity(65_536);
        buf.push(BATCH_MAGIC);
        buf.push(0); // count placeholder
        Self {
            buf,
            count: 0,
            first_push: None,
            app_id,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn count(&self) -> u8 {
        self.count
    }

    pub fn first_push(&self) -> Option<Instant> {
        self.first_push
    }

    pub fn app_id(&self) -> &[u8; 32] {
        &self.app_id
    }

    /// Append `pkt` (single IP packet) to the batch.
    ///
    /// Caller is expected to flush via `take` when [`PeerBatch::should_flush`]
    /// returns true OR when the deadline (from `first_push + flush_after`)
    /// expires.
    pub fn push(&mut self, pkt: &[u8]) {
        debug_assert!(
            pkt.len() <= u16::MAX as usize,
            "ip pkt > 64 KiB cannot fit a batch slot"
        );
        debug_assert!(
            self.count < BATCH_MAX_COUNT as u8,
            "BatchBuilder::push past 255"
        );
        if self.count == 0 {
            self.first_push = Some(Instant::now());
        }
        self.buf
            .extend_from_slice(&(pkt.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(pkt);
        self.count = self.count.saturating_add(1);
        self.buf[1] = self.count;
    }

    /// Should the batch be flushed на size/count grounds RIGHT NOW
    /// (timer-independent)?
    pub fn should_flush(&self, byte_threshold: usize) -> bool {
        self.count as usize >= BATCH_MAX_COUNT || self.buf.len() >= byte_threshold
    }

    /// Drain the batch into а Vec<u8>, ready to hand off to `AppSender::send_owned`.
    /// Leaves an empty (header-only) batch behind so the slot can be reused.
    pub fn take(&mut self) -> Vec<u8> {
        // Take the full envelope by swap; reinitialize header in place.
        let mut out = Vec::with_capacity(self.buf.capacity());
        out.push(BATCH_MAGIC);
        out.push(0);
        std::mem::swap(&mut self.buf, &mut out);
        self.count = 0;
        self.first_push = None;
        out
    }
}

/// Zero-copy iterator over а received batch envelope.
///
/// Skips truncated trailing records — а malformed batch yields the valid
/// prefix and stops.  Caller must run `is_batch_envelope` first.
pub struct BatchIter<'a> {
    data: &'a [u8],
    pos: usize,
    remaining: u8,
}

impl<'a> BatchIter<'a> {
    /// Construct over а buffer that starts с `BATCH_MAGIC`.
    pub fn new(data: &'a [u8]) -> Self {
        let (count, pos) = if data.len() >= 2 && data[0] == BATCH_MAGIC {
            (data[1], 2)
        } else {
            (0, data.len())
        };
        Self {
            data,
            pos,
            remaining: count,
        }
    }
}

impl<'a> Iterator for BatchIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.remaining == 0 {
            return None;
        }
        if self.pos + 2 > self.data.len() {
            self.remaining = 0;
            return None;
        }
        let len = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]) as usize;
        self.pos += 2;
        if self.pos + len > self.data.len() {
            self.remaining = 0;
            return None;
        }
        let pkt = &self.data[self.pos..self.pos + len];
        self.pos += len;
        self.remaining -= 1;
        Some(pkt)
    }
}

/// Egress-side state: per-peer batches keyed by destination `NodeId`.
///
/// Methods here are sync — the egress loop owns this struct exclusively.
#[derive(Default)]
pub struct EgressBatches {
    by_peer: std::collections::HashMap<NodeId, PeerBatch>,
}

impl EgressBatches {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns а `&mut PeerBatch` for `peer`, creating it lazily.  Caller
    /// supplies the precomputed `app_id` so the batch envelope carries it.
    pub fn get_or_create(&mut self, peer: NodeId, app_id: [u8; 32]) -> &mut PeerBatch {
        self.by_peer
            .entry(peer)
            .or_insert_with(|| PeerBatch::new(app_id))
    }

    /// Mutable access к the per-peer batch без implicit creation. Caller uses
    /// this к flush а pending batch immediately before shipping а solo packet
    /// (out-of-band order preservation).
    pub fn peek_mut(&mut self, peer: &NodeId) -> Option<&mut PeerBatch> {
        self.by_peer.get_mut(peer)
    }

    /// Find the earliest `first_push` across non-empty batches.
    pub fn earliest_deadline(&self) -> Option<Instant> {
        self.by_peer.values().filter_map(|b| b.first_push()).min()
    }

    /// For each non-empty batch whose `first_push <= cutoff`, yield (peer, drained_buf, app_id).
    pub fn drain_expired(&mut self, cutoff: Instant) -> Vec<(NodeId, Vec<u8>, [u8; 32])> {
        let mut out = Vec::new();
        for (peer, b) in self.by_peer.iter_mut() {
            if let Some(first) = b.first_push()
                && first <= cutoff
                && !b.is_empty()
            {
                let app_id = *b.app_id();
                out.push((*peer, b.take(), app_id));
            }
        }
        out
    }

    /// Drain every non-empty batch (used on shutdown).
    pub fn drain_all(&mut self) -> Vec<(NodeId, Vec<u8>, [u8; 32])> {
        let mut out = Vec::new();
        for (peer, b) in self.by_peer.iter_mut() {
            if !b.is_empty() {
                let app_id = *b.app_id();
                out.push((*peer, b.take(), app_id));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_byte_disjoint_from_ip_versions() {
        // First byte of IPv4 = 0x4N, of IPv6 = 0x6N.  Our magic must be neither.
        assert_ne!(BATCH_MAGIC & 0xF0, 0x40);
        assert_ne!(BATCH_MAGIC & 0xF0, 0x60);
    }

    #[test]
    fn roundtrip_two_packets() {
        let mut b = PeerBatch::new([0u8; 32]);
        b.push(&[0x45, 0x00, 0x00, 0x14, 0xde, 0xad, 0xbe, 0xef]); // 8 B IPv4 stub
        b.push(&[0x60, 0x00, 0x00, 0x00, 0xca, 0xfe]); // 6 B IPv6 stub
        assert_eq!(b.count(), 2);
        let env = b.take();
        assert!(is_batch_envelope(&env));
        let pkts: Vec<&[u8]> = BatchIter::new(&env).collect();
        assert_eq!(pkts.len(), 2);
        assert_eq!(pkts[0].len(), 8);
        assert_eq!(pkts[1].len(), 6);
        assert_eq!(pkts[0][0], 0x45);
        assert_eq!(pkts[1][0], 0x60);
    }

    #[test]
    fn batch_iter_handles_truncated_trailing_record() {
        // Hand-crafted envelope: magic + count=2 + len=4 + 4 bytes + len=10 + only 3 bytes.
        let env = vec![BATCH_MAGIC, 2, 0, 4, 1, 2, 3, 4, 0, 10, 9, 9, 9];
        let pkts: Vec<&[u8]> = BatchIter::new(&env).collect();
        assert_eq!(
            pkts.len(),
            1,
            "truncated trailing record dropped, prefix preserved"
        );
        assert_eq!(pkts[0], &[1u8, 2, 3, 4]);
    }

    #[test]
    fn batch_iter_zero_count_yields_nothing() {
        let env = vec![BATCH_MAGIC, 0];
        let pkts: Vec<&[u8]> = BatchIter::new(&env).collect();
        assert!(pkts.is_empty());
    }

    #[test]
    fn non_magic_envelope_yields_nothing() {
        // BatchIter::new on а non-batch payload yields zero items.
        let ip = vec![0x45u8, 0x00, 0x00, 0x14];
        let pkts: Vec<&[u8]> = BatchIter::new(&ip).collect();
        assert!(pkts.is_empty());
    }

    #[test]
    fn should_flush_threshold() {
        let mut b = PeerBatch::new([0u8; 32]);
        b.push(&vec![0u8; 1000]);
        assert!(!b.should_flush(60_000));
        // Push enough к cross threshold.
        for _ in 0..70 {
            b.push(&vec![0u8; 1000]);
        }
        assert!(b.should_flush(60_000));
    }

    #[test]
    fn take_resets_state() {
        let mut b = PeerBatch::new([0u8; 32]);
        b.push(&[0x45, 0, 0, 0]);
        let _ = b.take();
        assert!(b.is_empty());
        assert_eq!(b.count(), 0);
        assert!(b.first_push().is_none());
    }

    #[test]
    fn egress_batches_drain_expired_filters_by_cutoff() {
        let mut batches = EgressBatches::new();
        let nid_a = [1u8; 32];
        let nid_b = [2u8; 32];
        let app = [0u8; 32];
        batches.get_or_create(nid_a, app).push(&[0x45, 0, 0, 0]);
        std::thread::sleep(std::time::Duration::from_millis(2));
        let mid = Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(2));
        batches.get_or_create(nid_b, app).push(&[0x60, 0, 0, 0]);

        // Only A should drain (pushed before `mid`); B is younger.
        let expired = batches.drain_expired(mid);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, nid_a);
    }
}
