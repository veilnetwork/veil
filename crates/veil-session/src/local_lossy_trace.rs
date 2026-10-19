//! Opt-in endpoint diagnostics for complete source work items and their cells.
//! These observations never travel on IPC or the network and never classify
//! forwarded traffic. No plaintext, keys, node ids or peer ids are recorded.
use sha2::{Digest, Sha256};
use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};

const SEQUENCE_LIMIT: u64 = 4096;
const ROW_LIMIT: u64 = 65_536;
static ENABLED: OnceLock<bool> = OnceLock::new();
static ROWS: AtomicU64 = AtomicU64::new(0);
// Extra transport observations must not consume the pre-existing budget/work
// rows. Both independently bounded streams cover a full owned stress capture.
static ACCEPTED_ROWS: AtomicU64 = AtomicU64::new(0);
const WORK_ROW_LIMIT: u64 = 16_384;
static WORK_ROWS: AtomicU64 = AtomicU64::new(0);
static ADMISSION_ROWS: AtomicU64 = AtomicU64::new(0);

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

fn cell_row_available(stage: &str) -> bool {
    if stage != "datagram_accepted" {
        return row_available();
    }
    let n = ACCEPTED_ROWS.fetch_add(1, Ordering::Relaxed);
    if n == ROW_LIMIT {
        log::info!("media.source_accepted_trace_limit rows={ROW_LIMIT}");
    }
    n < ROW_LIMIT
}

fn unix_us() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros()
}

fn owned_secondary_header(priority: u8, frame: &[u8]) -> Option<(u64, u64)> {
    // A wire traffic-class hint never selects this diagnostic. The private
    // local queue must already establish that this is our own producer.
    if !owned_secondary(priority) {
        return None;
    }
    owned_frame_header(frame)
}

/// Preserve the actual admission result before the caller cancels a denied
/// DATAGRAM work item. Wait (credit unavailable) and Rejected (including a
/// release span that no longer fits) must not collapse into one guessed cause.
pub(crate) fn work_admission(
    work: &veil_types::local_lossy_work::LocalLossyCell,
    priority: u8,
    frame: &[u8],
    decision: &veil_types::local_lossy_work::WorkAdmission,
    attempted_at: std::time::Instant,
) {
    use veil_types::local_lossy_work::WorkAdmission;
    if matches!(decision, WorkAdmission::Admitted) || !enabled() {
        return;
    }
    let Some((epoch, sequence)) = owned_secondary_header(priority, frame) else {
        return;
    };
    let row = ADMISSION_ROWS.fetch_add(1, Ordering::Relaxed);
    if row == ROW_LIMIT {
        log::info!("media.source_admission_trace_limit rows={ROW_LIMIT}");
    }
    if row >= ROW_LIMIT {
        return;
    }
    let (result, retry_us) = match decision {
        WorkAdmission::Admitted => unreachable!(),
        WorkAdmission::Wait(until) => (
            "wait",
            until.saturating_duration_since(attempted_at).as_micros() as i128,
        ),
        WorkAdmission::Rejected => ("rejected", -1),
    };
    let span_us = work.pacing_span().map_or(-1, |d| d.as_micros() as i128);
    let remaining_us = work.expires_at().map_or(-1, |until| {
        until.saturating_duration_since(attempted_at).as_micros() as i128
    });
    log::info!(
        "media.source_admission_trace at_unix_us={} monotonic_us={} local_slot={priority} epoch={epoch:016x} seq={sequence} result={result} retry_us={retry_us} span_us={span_us} remaining_us={remaining_us} attempt_elapsed_us={}",
        unix_us(),
        veil_util::diagnostic_clock::monotonic_us().map_or(-1, i128::from),
        attempted_at.elapsed().as_micros(),
    );
}

/// First/last owned members accepted by the local DATAGRAM transport. This is
/// not a NIC-send timestamp: the existing opaque UDP trace observes that later.
/// A separate bounded budget keeps late work visible without changing the
/// existing per-cell trace budget. Remote transit has no LocalLossyCell handle.
pub(crate) fn work_release(
    work: &veil_types::local_lossy_work::LocalLossyCell,
    priority: u8,
    frame: &[u8],
    datagram_bytes: usize,
    connection_trace_id: u64,
) {
    if !crate::rt_trace::rt_trace_enabled() {
        return;
    }
    let Some(snapshot) = work.boundary_snapshot_at(std::time::Instant::now()) else {
        return;
    };
    let Some((epoch, seq)) = owned_secondary_header(priority, frame) else {
        return;
    };
    let row = WORK_ROWS.fetch_add(1, Ordering::Relaxed);
    if row == WORK_ROW_LIMIT {
        log::info!("media.source_work_trace_limit rows={WORK_ROW_LIMIT}");
    }
    if row >= WORK_ROW_LIMIT {
        return;
    }
    log::info!(target: "veil::source_work_release",
        "at_unix_us={} monotonic_us={} connection_trace_id={connection_trace_id} local_slot={priority} epoch={epoch:016x} seq={seq} cell={} cells={} sealed_bytes={} envelope_work_bytes={} envelope_cell_bytes={} span_us={} admission_age_us={} remaining_us={} datagram_cell_bytes={datagram_bytes} admitted_work_bytes={}",
        unix_us(), veil_util::diagnostic_clock::monotonic_us().map_or(-1, i128::from), snapshot.index, snapshot.cells, snapshot.sealed_bytes,
        snapshot.envelope_wire_bytes,
        frame.len().saturating_add(veil_crypto::session_cipher::AEAD_OVERHEAD),
        snapshot.span.as_micros(),
        snapshot.since_admission.as_micros(), snapshot.until_expiry.as_micros(), snapshot.admission_wire_bytes);
}

fn owned_primary_cell(priority: u8, frame: &[u8]) -> Option<(u64, u64)> {
    // Selection comes from our private source slot, never a remote wire hint.
    if priority != veil_proto::priority::REALTIME {
        return None;
    }
    owned_frame_header(frame)
}

fn owned_frame_header(frame: &[u8]) -> Option<(u64, u64)> {
    if frame.len() > 8192 {
        return None;
    }
    let wire_header = veil_proto::codec::decode_header(frame).ok()?;
    if usize::from(wire_header.header_len) != veil_proto::header::HEADER_SIZE
        || veil_proto::header::HEADER_SIZE.checked_add(wire_header.body_len as usize)
            != Some(frame.len())
    {
        return None;
    }
    let body = frame.get(veil_proto::header::HEADER_SIZE..)?;
    match crate::frame_diag::family_and_type(frame)? {
        (family, kind)
            if family == veil_proto::family::FrameFamily::App as u8
                && kind == veil_proto::family::AppMsg::AppRtData as u16 =>
        {
            header(
                &veil_proto::app::AppRtDataPayload::decode(body)
                    .ok()?
                    .payload,
            )
        }
        (family, kind)
            if family == veil_proto::family::FrameFamily::Delivery as u8
                && kind == veil_proto::family::DeliveryMsg::Forward as u16 =>
        {
            header(
                &veil_proto::delivery::ForwardPayload::decode(body)
                    .ok()?
                    .envelope
                    .payload,
            )
        }
        _ => None,
    }
}

pub(crate) fn cell(stage: &'static str, priority: u8, frame: &[u8]) {
    record_cell(stage, priority, frame, 0);
}

/// A complete owned primary/secondary frame reached the local DATAGRAM handle.
/// This remains a queue observation, not a NIC-send or peer-delivery promise.
/// Ordinary sparse RT tracing does not enable this additional observation.
pub(crate) fn datagram_accepted(
    priority: u8,
    frame: &[u8],
    connection_trace_id: impl FnOnce() -> u64,
) {
    if let Some(connection_trace_id) =
        accepted_connection(enabled(), priority, frame, connection_trace_id)
    {
        record_cell("datagram_accepted", priority, frame, connection_trace_id);
    }
}

fn accepted_connection(
    detailed: bool,
    priority: u8,
    frame: &[u8],
    connection_trace_id: impl FnOnce() -> u64,
) -> Option<u64> {
    if !detailed
        || owned_primary_cell(priority, frame)
            .or_else(|| owned_secondary_header(priority, frame))
            .is_none()
    {
        return None;
    }
    // Looking up an ordinal locks the transport connection. Keep that work
    // behind both opt-in and ownership checks, including at the caller.
    Some(connection_trace_id())
}

fn record_cell(stage: &'static str, priority: u8, frame: &[u8], connection_trace_id: u64) {
    let primary = priority == veil_proto::priority::REALTIME
        && (crate::rt_trace::rt_trace_enabled() || enabled());
    let sample = if primary {
        owned_primary_cell(priority, frame)
    } else if enabled() {
        // Detailed secondary capture uses the same explicit row bound as
        // primary capture; a high nonce must not silently hide a late fault.
        owned_secondary_header(priority, frame)
    } else {
        None
    };
    let Some((epoch, sequence)) = sample else {
        return;
    };
    // Explicit, bounded fixture tracing covers late primary cells too. The
    // ordinary RT trace retains its original sparse/short observation budget.
    if primary
        && !enabled()
        && (sequence > SEQUENCE_LIMIT || (sequence != 1 && !sequence.is_multiple_of(50)))
    {
        return;
    }
    if cell_row_available(stage) {
        let Some((family, kind)) = crate::frame_diag::family_and_type(frame) else {
            return;
        };
        let body = &frame[veil_proto::header::HEADER_SIZE..];
        // Same bounded encrypted preview as the admin observer. It lets the
        // owned endpoint establish the source; no role is inferred at a relay.
        let digest = veil_util::hex_str(&Sha256::digest(&body[..body.len().min(256)]));
        log::info!(
            "media.source_cell_trace at_unix_us={} monotonic_us={} stage={stage} connection_trace_id={connection_trace_id} local_slot={priority} epoch={epoch:016x} seq={sequence} wire_bytes={} family={family} msg_type={kind} body_len={} body_preview_sha256={digest}",
            unix_us(),
            veil_util::diagnostic_clock::monotonic_us().map_or(-1, i128::from),
            frame
                .len()
                .saturating_add(veil_crypto::session_cipher::AEAD_OVERHEAD),
            body.len(),
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
        // Explicit full-call capture already has a finite shared row bound.
        // A fresh video seal can have a high nonce; hiding that boundary would
        // make late RTP-to-work attribution impossible despite complete cells.
        if row_available() {
            log::info!(
                "media.source_frame_trace at_unix_us={} local_slot={} epoch={epoch:016x} first_seq={} last_seq={} cells={} planned_cells={} expired_cells={} packets={} raw_bytes={} sealed_bytes={} contiguous={}",
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

    #[test]
    fn late_secondary_cells_are_visible_and_reject_transit() {
        let bytes = forward(SEQUENCE_LIMIT + 1);
        assert_eq!(
            owned_secondary_header(veil_proto::priority::BULK, &bytes),
            Some((7, SEQUENCE_LIMIT + 1))
        );
        assert!(owned_secondary_header(veil_proto::priority::INTERACTIVE, &bytes).is_none());
        assert!(owned_secondary_header(veil_proto::priority::REALTIME, &bytes).is_none());
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
    fn primary_samples_require_a_local_slot_and_complete_sealed_direct_body() {
        let payload = veil_proto::app::AppRtDataPayload {
            src_app_id: [1; 32],
            app_id: [2; 32],
            endpoint_id: 3,
            seq: 4,
            timestamp_us: 5,
            marker: 0,
            payload_type: 0,
            payload: seal(50),
        };
        let body = payload.encode();
        let mut header = veil_proto::header::FrameHeader::new(
            veil_proto::family::FrameFamily::App as u8,
            veil_proto::family::AppMsg::AppRtData as u16,
        );
        header.body_len = body.len() as u32;
        header.set_priority(veil_proto::priority::REALTIME);
        let mut frame = veil_proto::codec::encode_header(&header).to_vec();
        frame.extend(body);
        assert_eq!(
            owned_primary_cell(veil_proto::priority::REALTIME, &frame),
            Some((7, 50))
        );
        // A remote wire REALTIME hint cannot opt neutral relay traffic in.
        assert_eq!(
            owned_primary_cell(veil_proto::priority::INTERACTIVE, &frame),
            None
        );
        assert_eq!(owned_primary_cell(veil_proto::priority::BULK, &frame), None);
        for priority in [veil_proto::priority::BULK, veil_proto::priority::BACKGROUND] {
            assert_eq!(owned_secondary_header(priority, &frame), Some((7, 50)));
            assert_eq!(accepted_connection(true, priority, &frame, || 31), Some(31));
        }
        assert_eq!(
            owned_secondary_header(veil_proto::priority::INTERACTIVE, &frame),
            None
        );
        for size in 0..frame.len() {
            assert_eq!(
                owned_primary_cell(veil_proto::priority::REALTIME, &frame[..size]),
                None
            );
            assert_eq!(
                owned_secondary_header(veil_proto::priority::BULK, &frame[..size]),
                None
            );
        }
        let mut unsealed = payload;
        unsealed.payload[0] = 0;
        let mut malformed = veil_proto::codec::encode_header(&header).to_vec();
        malformed.extend(unsealed.encode());
        assert_eq!(
            owned_primary_cell(veil_proto::priority::REALTIME, &malformed),
            None
        );
        assert_eq!(
            owned_secondary_header(veil_proto::priority::BULK, &malformed),
            None
        );
        assert_eq!(
            accepted_connection(true, veil_proto::priority::BULK, &malformed, || {
                panic!("invalid direct secondary must not lock QUIC")
            }),
            None
        );
    }

    #[test]
    fn relayed_primary_ownership_ignores_wire_hints_and_covers_late_cells() {
        let frame = forward(SEQUENCE_LIMIT + 1);
        assert_eq!(
            owned_primary_cell(veil_proto::priority::REALTIME, &frame),
            Some((7, SEQUENCE_LIMIT + 1))
        );
        for priority in [
            veil_proto::priority::INTERACTIVE,
            veil_proto::priority::BULK,
            veil_proto::priority::BACKGROUND,
        ] {
            assert_eq!(owned_primary_cell(priority, &frame), None);
        }
        for end in 0..frame.len() {
            assert_eq!(
                owned_primary_cell(veil_proto::priority::REALTIME, &frame[..end]),
                None
            );
        }
        let mut extra = frame;
        extra.push(0);
        assert_eq!(
            owned_primary_cell(veil_proto::priority::REALTIME, &extra),
            None
        );
    }

    #[test]
    fn transport_acceptance_requires_explicit_trace_and_local_ownership() {
        let frame = forward(SEQUENCE_LIMIT + 50);
        assert_eq!(
            accepted_connection(false, veil_proto::priority::REALTIME, &frame, || {
                panic!("disabled diagnostics must not lock QUIC")
            }),
            None
        );
        assert_eq!(
            accepted_connection(true, veil_proto::priority::REALTIME, &frame, || 17),
            Some(17)
        );
        for priority in [veil_proto::priority::BULK, veil_proto::priority::BACKGROUND] {
            assert_eq!(accepted_connection(true, priority, &frame, || 23), Some(23));
            assert_eq!(
                accepted_connection(false, priority, &frame, || {
                    panic!("disabled diagnostics must not lock QUIC")
                }),
                None
            );
        }
        for priority in [
            veil_proto::priority::INTERACTIVE,
            veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
        ] {
            assert_eq!(
                accepted_connection(true, priority, &frame, || {
                    panic!("transit diagnostics must not lock QUIC")
                }),
                None
            );
        }
        assert_eq!(
            accepted_connection(true, veil_proto::priority::REALTIME, &frame[..35], || {
                panic!("invalid frames must not lock QUIC")
            }),
            None
        );
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
        assert_eq!(
            owned_secondary_header(veil_proto::priority::BULK, &frame),
            Some((7, 1))
        );
        assert_eq!(
            owned_secondary_header(veil_proto::priority::BACKGROUND, &frame),
            Some((7, 1))
        );
        for priority in [
            veil_proto::priority::INTERACTIVE,
            veil_proto::priority::REALTIME,
            veil_proto::ipc::LOCAL_RECOVERABLE_DATA_LANE,
        ] {
            assert!(!owned_secondary(priority));
            assert_eq!(owned_secondary_header(priority, &frame), None);
        }
    }

    #[test]
    fn detailed_secondary_cells_retain_size_bound_without_a_silent_nonce_cutoff() {
        assert_eq!(
            owned_secondary_header(veil_proto::priority::BULK, &forward(SEQUENCE_LIMIT)),
            Some((7, SEQUENCE_LIMIT))
        );
        assert_eq!(
            owned_secondary_header(veil_proto::priority::BULK, &forward(SEQUENCE_LIMIT + 1)),
            Some((7, SEQUENCE_LIMIT + 1))
        );
        let mut oversized = forward(1);
        oversized.resize(8193, 0);
        assert_eq!(
            owned_secondary_header(veil_proto::priority::BULK, &oversized),
            None
        );
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
