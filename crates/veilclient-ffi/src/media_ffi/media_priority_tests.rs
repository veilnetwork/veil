//! Priority handling for media frames, behind the embedded-node feature.
//!
//! Moved verbatim out of `lib.rs`, which was fourteen thousand lines with four
//! thousand of them test code interleaved with the production surface
//! (report24 RUNTIME-3). Nothing here is compiled into the library — the
//! module keeps the same `cfg`, the same name and the same `use super::*`, so
//! every test still runs under the path it ran under before.
//!
//! The production code was deliberately NOT moved. cbindgen emits this crate's
//! header in parse order and skips `pub` items it finds in a private module,
//! so moving a section of `lib.rs` into a submodule rewrote the header and
//! DROPPED declarations from it — measured, then reverted. Tests are the part
//! that can move without the header noticing, and this checks that it did not.

use super::{
    RELAY_VIDEO_FRAME_MAX_BYTES, RelayMediaStats, RelayVideoFrameAssembler, RelayVideoFramePush,
    media_is_vp8_rtp, media_wire_cells, veil_media_repair_channel,
};

fn video_packet(timestamp: u32, marker: bool, fill: u8) -> Vec<u8> {
    let mut packet = vec![0u8; 120];
    packet[0] = 0x80;
    packet[1] = 96 | if marker { 0x80 } else { 0 };
    packet[4..8].copy_from_slice(&timestamp.to_be_bytes());
    packet[8..].fill(fill);
    packet
}

#[test]
fn media_priority_classifies_only_vp8_rtp_as_video() {
    assert!(media_is_vp8_rtp(&[0x80, 96, 0, 1]));
    assert!(media_is_vp8_rtp(&[0x80, 0x80 | 96, 0, 1]));
    assert!(!media_is_vp8_rtp(&[0x80, 111, 0, 1])); // Opus RTP.
    assert!(!media_is_vp8_rtp(&[0x80, 72, 0, 1])); // RTCP mux range.
    assert!(!media_is_vp8_rtp(&[0x40, 96, 0, 1])); // Not RTP v2.
    assert!(!media_is_vp8_rtp(&[0x80]));
}

#[test]
fn media_repair_rejects_zero_and_unknown_channels() {
    assert_eq!(unsafe { veil_media_repair_channel(0) }, -1);
    assert_eq!(unsafe { veil_media_repair_channel(u64::MAX) }, -1);
}

#[test]
fn relay_video_assembler_admits_a_complete_frame_atomically() {
    let mut assembler = RelayVideoFrameAssembler::default();
    assert!(matches!(
        assembler.push(video_packet(7, false, 1)),
        RelayVideoFramePush::Pending
    ));
    assert!(matches!(
        assembler.push(video_packet(7, false, 2)),
        RelayVideoFramePush::Pending
    ));
    let RelayVideoFramePush::Complete(frame) = assembler.push(video_packet(7, true, 3)) else {
        panic!("marker must complete the frame");
    };
    assert_eq!(frame.len(), 3);
    assert_eq!(frame[0][8], 1);
    assert_eq!(frame[2][8], 3);
}

#[test]
fn relay_video_assembler_discards_an_unterminated_old_frame() {
    let mut assembler = RelayVideoFrameAssembler::default();
    assert!(matches!(
        assembler.push(video_packet(7, false, 1)),
        RelayVideoFramePush::Pending
    ));
    let RelayVideoFramePush::Complete(frame) = assembler.push(video_packet(8, true, 2)) else {
        panic!("new timestamp marker must complete only the new frame");
    };
    assert_eq!(frame.len(), 1);
    assert_eq!(frame[0][8], 2);
}

#[test]
fn relay_video_assembler_bounds_pathological_frames_and_recovers() {
    let mut assembler = RelayVideoFrameAssembler::default();
    let mut first = video_packet(7, false, 1);
    first.resize(RELAY_VIDEO_FRAME_MAX_BYTES / 2 + 1, 1);
    assert!(matches!(
        assembler.push(first.clone()),
        RelayVideoFramePush::Pending
    ));
    assert!(matches!(
        assembler.push(first),
        RelayVideoFramePush::Dropped
    ));
    let RelayVideoFramePush::Complete(frame) = assembler.push(video_packet(8, true, 2)) else {
        panic!("assembler must recover immediately after a bounded drop");
    };
    assert_eq!(frame.len(), 1);
}

fn expand_wire_cells(cells: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    for cell in cells {
        if cell.first() != Some(&crate::media::MEDIA_BATCH_MAGIC) {
            packets.push(cell.clone());
            continue;
        }
        let body = &cell[1..];
        let count = u16::from_be_bytes([body[0], body[1]]) as usize;
        let mut offset = 2;
        for _ in 0..count {
            let len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
            offset += 2;
            packets.push(body[offset..offset + len].to_vec());
            offset += len;
        }
        assert_eq!(offset, body.len());
    }
    packets
}

#[test]
fn relay_video_batching_emits_immediately_in_order_bounded_groups() {
    let frame: Vec<Vec<u8>> = (0..9)
        .map(|index| video_packet(7, index == 8, index as u8))
        .collect();
    let cells = media_wire_cells(frame.clone(), true);
    assert_eq!(cells.len(), 3, "four + four + one RTP packets");
    assert_eq!(cells[0][0], crate::media::MEDIA_BATCH_MAGIC);
    assert_eq!(cells[1][0], crate::media::MEDIA_BATCH_MAGIC);
    assert_ne!(cells[2][0], crate::media::MEDIA_BATCH_MAGIC);
    assert_eq!(expand_wire_cells(&cells), frame);
}

#[test]
fn relay_video_batching_stays_legacy_when_not_negotiated() {
    let frame = vec![video_packet(7, false, 1), video_packet(7, true, 2)];
    assert_eq!(media_wire_cells(frame.clone(), false), frame);
}

#[test]
fn relay_stats_separate_queue_lock_and_ipc_holds() {
    let stats = RelayMediaStats::default();
    stats.enqueue_frame();
    stats.enqueue_frame();
    stats.start_frame(std::time::Duration::from_millis(81));
    stats.observe_sender_lock(std::time::Duration::from_millis(17));
    stats.observe_ipc_cell(std::time::Duration::from_millis(18), true);
    stats.observe_frame_ipc(std::time::Duration::from_millis(40));

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.video_frames_enqueued, 2);
    assert_eq!(snapshot.video_frames_started, 1);
    assert_eq!(snapshot.video_queue_depth, 1);
    assert_eq!(snapshot.video_queue_max_depth, 2);
    assert_eq!(snapshot.video_queue_age_max_ms, 81);
    assert_eq!(snapshot.video_queue_holds_75ms, 1);
    assert_eq!(snapshot.sender_lock_holds_16ms, 1);
    assert_eq!(snapshot.video_frame_ipc_holds_33ms, 1);
    assert_eq!(snapshot.ipc_cell_holds_16ms, 1);
    assert_eq!(snapshot.ipc_send_failures, 1);
}
