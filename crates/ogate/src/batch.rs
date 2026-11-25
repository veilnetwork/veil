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

use std::sync::OnceLock;
use std::time::{Duration, Instant};

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
/// `bridge::run` keeps one of these per pending destination so packets for different
/// destinations don't head-of-line block each other.
#[derive(Debug)]
pub struct PeerBatch {
    buf: Vec<u8>,
    prefix: usize,
    count: u8,
    timing: Option<BatchTiming>,
    /// Cached peer app_id at first-push time so flush doesn't have to
    /// re-resolve it against (possibly hot-swapped) routing state.
    app_id: [u8; 32],
}

#[derive(Debug)]
struct BatchTiming {
    first_push: Instant,
    flush_at: Instant,
}

impl PeerBatch {
    pub fn new(app_id: [u8; 32]) -> Self {
        Self::with_prefix(app_id, 0)
    }

    fn with_prefix(app_id: [u8; 32], prefix: usize) -> Self {
        Self {
            buf: Vec::new(),
            prefix,
            count: 0,
            timing: None,
            app_id,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn len(&self) -> usize {
        if self.is_empty() {
            2
        } else {
            self.buf.len() - self.prefix
        }
    }

    pub fn count(&self) -> u8 {
        self.count
    }

    pub fn first_push(&self) -> Option<Instant> {
        self.timing.as_ref().map(|timing| timing.first_push)
    }

    fn flush_at(&self) -> Option<Instant> {
        self.timing.as_ref().map(|timing| timing.flush_at)
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
        self.push_with_window(pkt, Duration::ZERO);
    }

    /// Pin the window when this batch receives its first packet.
    pub(crate) fn push_with_window(&mut self, pkt: &[u8], window: Duration) {
        debug_assert!(
            pkt.len() <= u16::MAX as usize,
            "ip pkt > 64 KiB cannot fit a batch slot"
        );
        debug_assert!(
            self.count < BATCH_MAX_COUNT as u8,
            "BatchBuilder::push past 255"
        );
        if self.count == 0 {
            self.buf.reserve(self.prefix + 2 + 2 + pkt.len());
            self.buf.resize(self.prefix, 0);
            self.buf.extend_from_slice(&[BATCH_MAGIC, 0]);
            let first_push = Instant::now();
            self.timing = Some(BatchTiming {
                first_push,
                flush_at: first_push + window,
            });
        }
        self.buf
            .extend_from_slice(&(pkt.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(pkt);
        self.count = self.count.saturating_add(1);
        self.buf[self.prefix + 1] = self.count;
    }

    /// Should the batch be flushed on size/count grounds RIGHT NOW
    /// (timer-independent)?
    pub fn should_flush(&self, byte_threshold: usize) -> bool {
        self.count as usize >= BATCH_MAX_COUNT || self.len() >= byte_threshold
    }

    /// Move the envelope out, leaving an empty batch.
    pub fn take(&mut self) -> Vec<u8> {
        if self.is_empty() {
            let mut header = vec![0; self.prefix];
            header.extend_from_slice(&[BATCH_MAGIC, 0]);
            return header;
        }
        self.count = 0;
        self.timing = None;
        std::mem::take(&mut self.buf)
    }
}

/// Zero-copy iterator over a received batch envelope.
///
/// Skips truncated trailing records — a malformed batch yields the valid
/// prefix and stops.  Caller must run `is_batch_envelope` first.
pub struct BatchIter<'a> {
    data: &'a [u8],
    pos: usize,
    remaining: u8,
}

impl<'a> BatchIter<'a> {
    /// Construct over a buffer that starts with `BATCH_MAGIC`.
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
    // Empty caches require rebuilding. An initialized None means no batch is open.
    next_flush: OnceLock<Option<Instant>>,
    prefix: usize,
}

impl EgressBatches {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(unix)]
    pub(crate) fn with_ipc_prefix() -> Self {
        Self {
            prefix: veilclient::APP_IPC_SEND_PREFIX_BYTES,
            ..Self::default()
        }
    }

    /// Returns a `&mut PeerBatch` for `peer`, creating it lazily.  Caller
    /// supplies the precomputed `app_id` so the batch envelope carries it.
    pub fn get_or_create(&mut self, peer: NodeId, app_id: [u8; 32]) -> &mut PeerBatch {
        self.next_flush.take();
        self.by_peer
            .entry(peer)
            .or_insert_with(|| PeerBatch::with_prefix(app_id, self.prefix))
    }

    /// Mutable access to the per-peer batch without implicit creation. Caller uses
    /// this to flush a pending batch immediately before shipping a solo packet
    /// (out-of-band order preservation).
    pub fn peek_mut(&mut self, peer: &NodeId) -> Option<&mut PeerBatch> {
        let batch = self.by_peer.get_mut(peer)?;
        self.next_flush.take();
        Some(batch)
    }

    #[cfg(unix)]
    pub(crate) fn peek(&self, peer: &NodeId) -> Option<&PeerBatch> {
        self.by_peer.get(peer)
    }

    #[cfg(unix)]
    pub(crate) fn pending_packet_count(&self) -> u64 {
        self.by_peer
            .values()
            .map(|batch| u64::from(batch.count()))
            .sum()
    }

    #[cfg(unix)]
    pub(crate) fn push_packet(
        &mut self,
        peer: NodeId,
        app_id: [u8; 32],
        packet: &[u8],
        window: impl FnOnce() -> Duration,
    ) -> &PeerBatch {
        let batch = self
            .by_peer
            .entry(peer)
            .or_insert_with(|| PeerBatch::with_prefix(app_id, self.prefix));
        let opens_batch = batch.is_empty();
        let window = if opens_batch {
            window()
        } else {
            Duration::ZERO
        };
        batch.push_with_window(packet, window);
        if opens_batch
            && let Some(next) = self.next_flush.get_mut()
            && let Some(deadline) = batch.flush_at()
            && next.is_none_or(|current| deadline < current)
        {
            *next = Some(deadline);
        }
        batch
    }

    #[cfg(unix)]
    pub(crate) fn take_peer(&mut self, peer: &NodeId) -> Option<Vec<u8>> {
        let mut batch = self.by_peer.remove(peer)?;
        if self
            .next_flush
            .get()
            .is_some_and(|next| *next == batch.flush_at())
        {
            self.next_flush.take();
        }
        (!batch.is_empty()).then(|| batch.take())
    }

    /// Find the earliest flush time across non-empty batches.
    pub fn earliest_deadline(&self) -> Option<Instant> {
        *self
            .next_flush
            .get_or_init(|| self.by_peer.values().filter_map(PeerBatch::flush_at).min())
    }

    /// Yield (peer, drained_buf, app_id) for batches due by `cutoff`.
    pub fn drain_expired(&mut self, cutoff: Instant) -> Vec<(NodeId, Vec<u8>, [u8; 32])> {
        let mut next: Option<Instant> = None;
        let expired = self
            .by_peer
            .extract_if(|_, batch| {
                let Some(deadline) = batch.flush_at() else {
                    return false;
                };
                if deadline <= cutoff {
                    return true;
                }
                next = Some(next.map_or(deadline, |current| current.min(deadline)));
                false
            })
            .map(|(peer, mut batch)| (peer, batch.take(), *batch.app_id()))
            .collect();
        self.next_flush = OnceLock::from(next);
        expired
    }

    /// Drain every non-empty batch (used on shutdown).
    pub fn drain_all(&mut self) -> Vec<(NodeId, Vec<u8>, [u8; 32])> {
        self.next_flush = OnceLock::from(None);
        self.by_peer
            .drain()
            .filter(|(_, batch)| !batch.is_empty())
            .map(|(peer, mut batch)| (peer, batch.take(), *batch.app_id()))
            .collect()
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
        // BatchIter::new on a non-batch payload yields zero items.
        let ip = vec![0x45u8, 0x00, 0x00, 0x14];
        let pkts: Vec<&[u8]> = BatchIter::new(&ip).collect();
        assert!(pkts.is_empty());
    }

    #[test]
    fn should_flush_threshold() {
        let mut b = PeerBatch::new([0u8; 32]);
        b.push(&vec![0u8; 1000]);
        assert!(!b.should_flush(60_000));
        // Push enough to cross threshold.
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
        assert!(batches.peek_mut(&nid_a).is_none());
        assert!(batches.peek_mut(&nid_b).is_some());
    }

    #[test]
    fn a_window_change_applies_only_to_new_batches() {
        let mut batches = EgressBatches::new();
        let first = [1; 32];
        let second = [2; 32];
        let packet = [0x45, 0, 0, 0];
        let old_window = Duration::from_secs(60);
        batches
            .get_or_create(first, first)
            .push_with_window(&packet, old_window);
        let original_deadline = batches.earliest_deadline().unwrap();

        batches
            .get_or_create(first, first)
            .push_with_window(&packet, Duration::ZERO);
        assert_eq!(batches.earliest_deadline(), Some(original_deadline));
        batches
            .get_or_create(second, second)
            .push_with_window(&packet, Duration::ZERO);
        let next = batches.earliest_deadline().unwrap();
        assert!(next < original_deadline);
        let drained = batches.drain_expired(next);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, second);

        let drained = batches.drain_expired(original_deadline);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, first);
        assert_eq!(BatchIter::new(&drained[0].1).count(), 2);
        assert!(batches.earliest_deadline().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn cached_deadline_follows_new_batches_drains_and_direct_mutation() {
        let mut batches = EgressBatches::new();
        let first = [1; 32];
        let second = [2; 32];
        let third = [3; 32];
        let packet = [0x45, 0, 0, 0];
        assert!(batches.earliest_deadline().is_none());

        batches.push_packet(first, first, &packet, || Duration::from_secs(60));
        let later = batches.earliest_deadline().unwrap();
        batches.push_packet(first, first, &packet, || panic!("batch already open"));
        assert_eq!(batches.earliest_deadline(), Some(later));
        batches.push_packet(second, second, &packet, || Duration::ZERO);
        let sooner = batches.earliest_deadline().unwrap();
        assert!(sooner < later);

        batches.push_packet(third, third, &packet, || Duration::from_secs(120));
        batches.take_peer(&third).unwrap();
        assert_eq!(batches.earliest_deadline(), Some(sooner));
        batches.take_peer(&second).unwrap();
        assert_eq!(batches.earliest_deadline(), Some(later));

        batches.get_or_create(third, third).push(&packet);
        let direct = batches.earliest_deadline().unwrap();
        assert!(direct < later);
        let expired = batches.drain_expired(direct);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, third);
        assert_eq!(batches.earliest_deadline(), Some(later));

        batches.peek_mut(&first).unwrap().take();
        assert!(batches.earliest_deadline().is_none());
        batches.push_packet(first, first, &packet, || Duration::ZERO);
        assert!(batches.earliest_deadline().is_some());
        assert_eq!(batches.drain_all().len(), 1);
        assert!(batches.earliest_deadline().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn ipc_prefix_is_reserved_without_changing_envelope_size_or_bytes() {
        let mut batches = EgressBatches::with_ipc_prefix();
        let peer = [1; 32];
        let batch = batches.get_or_create(peer, [2; 32]);
        let packet = [0x45, 1, 2, 3];
        batch.push(&packet);
        assert_eq!(batch.len(), packet.len() + 4);
        assert!(!batch.should_flush(packet.len() + 5));
        let buf = batches.take_peer(&peer).unwrap();
        let (prefix, envelope) = buf.split_at(veilclient::APP_IPC_SEND_PREFIX_BYTES);
        assert!(prefix.iter().all(|byte| *byte == 0));
        assert!(BatchIter::new(envelope).eq([packet.as_slice()]));
        assert!(batches.earliest_deadline().is_none());
    }
}
