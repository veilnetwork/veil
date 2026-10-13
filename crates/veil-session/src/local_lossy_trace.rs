//! Opt-in endpoint diagnostics for complete source work items and their cells.
//! These observations never travel on IPC or the network and never classify
//! forwarded traffic. No plaintext, keys, node ids or peer ids are recorded.
use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};

const SEQUENCE_LIMIT: u64 = 4096;
const ROW_LIMIT: u64 = 65_536;
static ENABLED: OnceLock<bool> = OnceLock::new();
static ROWS: AtomicU64 = AtomicU64::new(0);

fn enabled() -> bool {
    *ENABLED.get_or_init(|| std::env::var("VEIL_DIAG_SOURCE_CELLS").is_ok_and(|v| v == "1"))
}

fn owned_secondary(priority: u8) -> bool {
    matches!(
        priority,
        veil_proto::priority::BULK | veil_proto::priority::BACKGROUND
    )
}

fn header(data: &[u8]) -> Option<(u64, u64)> {
    if data.len() < 36 || !data.starts_with(&veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC) {
        return None;
    }
    let epoch = u64::from_be_bytes(data[4..12].try_into().ok()?);
    let sequence = u64::from_be_bytes(data[12..20].try_into().ok()?);
    (sequence > 0).then_some((epoch, sequence))
}

fn row_available() -> bool {
    let n = ROWS.fetch_add(1, Ordering::Relaxed);
    if n == ROW_LIMIT {
        log::info!("media.source_trace_limit rows={ROW_LIMIT}");
    }
    n < ROW_LIMIT
}

fn unix_us() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
}

fn owned_cell(priority: u8, frame: &[u8]) -> Option<(u64, u64)> {
    // A wire traffic-class hint never selects this diagnostic. The private
    // local queue must already establish that this is our own producer.
    if !owned_secondary(priority)
        || frame.len() > 8192
        || crate::frame_diag::family_and_type(frame)
            != Some((
                veil_proto::family::FrameFamily::Delivery as u8,
                veil_proto::family::DeliveryMsg::Forward as u16,
            ))
    {
        return None;
    }
    let forward =
        veil_proto::delivery::ForwardPayload::decode(&frame[veil_proto::header::HEADER_SIZE..])
            .ok()?;
    header(&forward.envelope.payload).filter(|(_, seq)| *seq <= SEQUENCE_LIMIT)
}

pub(crate) fn cell(stage: &'static str, priority: u8, frame: &[u8]) {
    if !enabled() {
        return;
    }
    let Some((epoch, sequence)) = owned_cell(priority, frame) else {
        return;
    };
    if row_available() {
        log::info!(
            "media.source_cell_trace at_unix_us={} stage={stage} local_slot={priority} epoch={epoch:016x} seq={sequence} wire_bytes={}",
            unix_us(),
            frame
                .len()
                .saturating_add(veil_crypto::session_cipher::AEAD_OVERHEAD)
        );
    }
}

/// The native sender supplies the boundary of a complete plaintext work item.
/// The opaque seal's existing nonce identifies its cells in local queues.
pub struct SourceFrameTrace {
    priority: u8,
    packets: usize,
    raw_bytes: usize,
    planned_cells: usize,
    expired_cells: usize,
    epoch: Option<u64>,
    first: u64,
    last: u64,
    cells: usize,
    sealed_bytes: usize,
    contiguous: bool,
}

impl SourceFrameTrace {
    pub fn new(
        priority: u8,
        packets: usize,
        raw_bytes: usize,
        planned_cells: usize,
    ) -> Option<Self> {
        (enabled() && owned_secondary(priority)).then_some(Self {
            priority,
            packets,
            raw_bytes,
            planned_cells,
            expired_cells: 0,
            epoch: None,
            first: 0,
            last: 0,
            cells: 0,
            sealed_bytes: 0,
            contiguous: true,
        })
    }

    pub fn observe(&mut self, sealed: &[u8]) {
        let Some((epoch, sequence)) = header(sealed) else {
            self.contiguous = false;
            return;
        };
        if let Some(first_epoch) = self.epoch {
            self.contiguous &= first_epoch == epoch && self.last.checked_add(1) == Some(sequence);
        } else {
            self.epoch = Some(epoch);
            self.first = sequence;
        }
        self.last = sequence;
        self.cells += 1;
        self.sealed_bytes += sealed.len();
    }

    pub fn expired(&mut self) {
        self.expired_cells += 1;
    }
}

impl Drop for SourceFrameTrace {
    fn drop(&mut self) {
        let Some(epoch) = self.epoch else {
            return;
        };
        if self.first <= SEQUENCE_LIMIT && row_available() {
            log::info!(
                "media.source_frame_trace at_unix_us={} local_slot={} epoch={epoch:016x} first_seq={} last_seq={} cells={} planned_cells={} expired_cells={} packets={} raw_bytes={} sealed_bytes={} contiguous={} sequence_limit={SEQUENCE_LIMIT}",
                unix_us(),
                self.priority,
                self.first,
                self.last,
                self.cells,
                self.planned_cells,
                self.expired_cells,
                self.packets,
                self.raw_bytes,
                self.sealed_bytes,
                self.contiguous
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal(sequence: u64) -> Vec<u8> {
        let mut data = vec![0; 36];
        data[..4].copy_from_slice(&veil_proto::ipc::RELAY_MEDIA_SEALED_MAGIC);
        data[4..12].copy_from_slice(&7u64.to_be_bytes());
        data[12..20].copy_from_slice(&sequence.to_be_bytes());
        data
    }

    fn forward(sequence: u64) -> Vec<u8> {
        use veil_proto::{
            delivery::{DeliveryEnvelope, ForwardPayload},
            header::FrameHeader,
        };
        let body = ForwardPayload {
            next_hop_node_id: [0; 32],
            relay_hops: 0,
            delivery_attempt: None,
            traffic_class: Some(veil_proto::priority::REALTIME),
            envelope: DeliveryEnvelope {
                recipient: veil_proto::recipient::Recipient::any([0; 32]),
                sender_node_id: [0; 32],
                src_app_id: [0; 32],
                app_id: [0; 32],
                endpoint_id: 0,
                content_id: [0; 32],
                created_at: 0,
                ttl_secs: 30,
                payload: seal(sequence),
                trace_id: 0,
                require_ack: false,
            },
        }
        .encode();
        let mut header = FrameHeader::new(
            veil_proto::family::FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        );
        header.body_len = body.len() as u32;
        let mut frame = veil_proto::codec::encode_header(&header).to_vec();
        frame.extend(body);
        frame
    }

    #[test]
    fn header_requires_complete_versioned_nonzero_sequence() {
        assert_eq!(header(&seal(1)), Some((7, 1)));
        assert_eq!(header(&seal(0)), None);
        assert_eq!(header(&seal(1)[..35]), None);
        let mut wrong = seal(1);
        wrong[0] = 0;
        assert_eq!(header(&wrong), None);
    }

    #[test]
    fn remote_and_primary_slots_cannot_select_source_cell_diagnostics() {
        let frame = forward(1);
        assert_eq!(owned_cell(veil_proto::priority::BULK, &frame), Some((7, 1)));
        assert_eq!(
            owned_cell(veil_proto::priority::BACKGROUND, &frame),
            Some((7, 1))
        );
        for priority in [
            veil_proto::priority::INTERACTIVE,
            veil_proto::priority::REALTIME,
            veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
        ] {
            assert!(!owned_secondary(priority));
            assert_eq!(owned_cell(priority, &frame), None);
        }
    }

    #[test]
    fn sampled_cells_enforce_both_size_and_sequence_bounds() {
        assert_eq!(
            owned_cell(veil_proto::priority::BULK, &forward(SEQUENCE_LIMIT)),
            Some((7, SEQUENCE_LIMIT))
        );
        assert_eq!(
            owned_cell(veil_proto::priority::BULK, &forward(SEQUENCE_LIMIT + 1)),
            None
        );
        let mut oversized = forward(1);
        oversized.resize(8193, 0);
        assert_eq!(owned_cell(veil_proto::priority::BULK, &oversized), None);
    }

    #[test]
    fn mixed_epochs_or_nonce_gaps_do_not_claim_a_contiguous_frame() {
        let mut trace = SourceFrameTrace {
            priority: veil_proto::priority::BULK,
            packets: 3,
            raw_bytes: 300,
            planned_cells: 3,
            expired_cells: 0,
            epoch: None,
            first: 0,
            last: 0,
            cells: 0,
            sealed_bytes: 0,
            contiguous: true,
        };
        trace.observe(&seal(1));
        trace.observe(&seal(2));
        assert!(trace.contiguous);
        trace.observe(&seal(4));
        assert!(!trace.contiguous);
        trace.contiguous = true;
        let mut other_epoch = seal(5);
        other_epoch[4..12].copy_from_slice(&8u64.to_be_bytes());
        trace.observe(&other_epoch);
        assert!(!trace.contiguous);
        // Avoid emitting test observations through the process-wide logger.
        trace.epoch = None;
    }
}
