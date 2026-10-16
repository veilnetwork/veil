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
    COMPACT_RELAY_MEDIA_CELL_MAX, MEDIA_BATCHING_COMPACT_RELAY, MEDIA_BATCHING_LEGACY,
    MEDIA_BATCHING_OFF, MEDIA_CHANNELS, MEDIA_LOCAL_QUEUE_AGE, MEDIA_NEXT_ID, MediaChannel,
    MediaIngress, MediaSenderSlot, MediaVideoIngress, QueuedMediaPacket, RelayVideoFrame,
    drain_anonymous_media, drain_media_packets, drain_media_packets_on_plane, drain_relay_video,
    drain_relay_video_batches_on_plane, drain_relay_video_on_plane, media_batched_cells,
    media_is_rtcp, media_ready_batch, timed_media_cells, veil_media_channel_set_screen_sharing,
    veil_media_close_channel, veil_media_send_datagram, veil_media_send_video_control_datagram,
};
use super::{
    RELAY_VIDEO_FRAME_MAX_BYTES, RelayMediaStats, RelayVideoFrameAssembler, RelayVideoFramePush,
    media_cell_is_video, media_is_vp8_rtp, media_wire_cells, veil_media_repair_channel,
};
use crate::media::{LocalMediaPlane, cipher_for_test};
use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify, mpsc};

fn video_packet(timestamp: u32, marker: bool, fill: u8) -> Vec<u8> {
    let mut packet = vec![0u8; 120];
    packet[0] = 0x80;
    packet[1] = 96 | if marker { 0x80 } else { 0 };
    packet[4..8].copy_from_slice(&timestamp.to_be_bytes());
    packet[8..].fill(fill);
    packet
}

#[test]
fn sealed_relay_media_size_accounts_for_ordered_record_framing() {
    use veil_proto::delivery::{DeliveryEnvelope, ForwardPayload};
    use veil_proto::{FrameHeader, codec};
    use veil_session::realtime_datagram::RealtimeDatagramTx;

    // The channel's opaque prefix consumes 20 bytes of the negotiated
    // 1200-byte record. Exercise the real seal, Forward and fragment codecs;
    // checking the RTP size alone missed the extra record on ordered routes.
    let cipher = cipher_for_test(&[0xd7; 32], &[1; 32], &[2; 32]).unwrap();
    let mut tx = RealtimeDatagramTx::new(&[3; 32], &[4; 32]);
    for (size, fragments) in [(840, 1), (841, 2), (1000, 2)] {
        let mut packet = video_packet(7, true, 3);
        packet.resize(size, 3);
        let sealed = cipher.seal(&packet).unwrap();
        let forward = ForwardPayload {
            next_hop_node_id: [5; 32],
            envelope: DeliveryEnvelope {
                recipient: veil_proto::recipient::Recipient::any([6; 32]),
                sender_node_id: [7; 32],
                src_app_id: [8; 32],
                app_id: [9; 32],
                endpoint_id: 0,
                content_id: [10; 32],
                created_at: 0,
                ttl_secs: veil_proto::delivery::FORWARD_REALTIME_TTL_SECS,
                payload: sealed.as_bytes().to_vec(),
                trace_id: 0,
                require_ack: false,
            },
            relay_hops: 0,
            delivery_attempt: None,
            traffic_class: Some(veil_proto::priority::INTERACTIVE),
        };
        let body = forward.encode();
        let mut header = FrameHeader::new(
            veil_proto::family::FrameFamily::Delivery as u8,
            veil_proto::family::DeliveryMsg::Forward as u16,
        );
        header.flags = u16::from(veil_proto::priority::INTERACTIVE);
        header.body_len = body.len() as u32;
        let mut frame = codec::encode_header(&header).to_vec();
        frame.extend_from_slice(&body);
        let encoded = tx.encode_frame(&frame, 1200 - 20).unwrap();
        assert_eq!(encoded.len(), fragments, "RTP size {size}");
        assert!(encoded.iter().all(|packet| packet.len() + 20 <= 1200));
    }
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
fn batching_never_puts_video_into_an_audio_cell() {
    let audio = vec![0x80, 111, 1, 2, 3, 4];
    let packets = vec![
        audio.clone(),
        audio.clone(),
        video_packet(7, false, 1),
        video_packet(7, true, 2),
        audio,
    ];
    let cells = media_wire_cells(packets.clone(), true);
    assert_eq!(cells.len(), 3);
    assert_eq!(
        cells
            .iter()
            .map(|cell| media_cell_is_video(cell))
            .collect::<Vec<_>>(),
        vec![false, true, false]
    );
    assert_eq!(expand_wire_cells(&cells), packets);
    assert!(!media_cell_is_video(&[crate::media::MEDIA_BATCH_MAGIC]));
}

#[tokio::test]
async fn compact_video_batches_ready_frames_without_crossing_cell_or_frame_boundaries() {
    for plane in [LocalMediaPlane::Secondary, LocalMediaPlane::Screen] {
        for (mode, expected_cells) in [
            (MEDIA_BATCHING_OFF, 9),
            (MEDIA_BATCHING_LEGACY, 5),
            (MEDIA_BATCHING_COMPACT_RELAY, 6),
        ] {
            let sized = |timestamp, marker, size| {
                let mut packet = video_packet(timestamp, marker, 3);
                packet.resize(size, 3);
                packet
            };
            let frames = vec![
                vec![sized(7, false, 120), sized(7, true, 120)],
                vec![sized(8, false, 120), sized(8, true, 120)],
                // Including batch marker/count/lengths, exactly 1000 bytes.
                vec![sized(9, false, 480), sized(9, true, 513)],
                // One additional byte must force separate compact cells.
                vec![sized(10, false, 480), sized(10, true, 514)],
                vec![sized(11, true, 1000)],
            ];
            let expected: Vec<_> = frames.iter().flatten().cloned().collect();
            let enqueued_at = Instant::now();
            let deadline = tokio::time::Instant::from_std(enqueued_at) + MEDIA_LOCAL_QUEUE_AGE;
            let (tx, rx) = mpsc::channel(frames.len());
            for packets in frames {
                tx.try_send(RelayVideoFrame {
                    packets,
                    enqueued_at,
                })
                .unwrap();
            }
            drop(tx);
            let peer = [0xd6; 32];
            let cipher = Arc::new(cipher_for_test(&peer, &[1; 32], &[2; 32]).unwrap());
            let receiver = cipher_for_test(&peer, &[2; 32], &[1; 32]).unwrap();
            let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
            tokio::time::timeout(
                Duration::from_secs(1),
                drain_relay_video_on_plane(
                    rx,
                    Arc::new(AtomicU8::new(mode)),
                    cipher,
                    Arc::new(RelayMediaStats::default()),
                    plane,
                    move |cell| {
                        sent_tx.send(cell).unwrap();
                        async { true }
                    },
                ),
            )
            .await
            .unwrap();
            let mut cells = Vec::new();
            while let Ok(sealed) = sent_rx.try_recv() {
                assert_eq!(sealed.local_deadline(), Some(deadline));
                let cell = receiver
                    .open(sealed.as_bytes())
                    .expect("authenticated video cell");
                if mode == MEDIA_BATCHING_COMPACT_RELAY {
                    assert!(cell.len() <= COMPACT_RELAY_MEDIA_CELL_MAX);
                }
                let packets = expand_wire_cells(std::slice::from_ref(&cell));
                let timestamp = &packets[0][4..8];
                assert!(packets.iter().all(|p| &p[4..8] == timestamp));
                cells.push(cell);
            }
            assert_eq!(cells.len(), expected_cells);
            assert_eq!(expand_wire_cells(&cells), expected);
        }
    }
}

#[test]
fn anonymous_batch_preserves_other_producer_and_overflow() {
    let (audio_tx, mut audio_rx) = mpsc::channel::<QueuedMediaPacket>(4);
    let (video_tx, mut video_rx) = mpsc::channel(4);
    let audio = vec![0x80, 111, 1, 2, 3, 4];
    let video = video_packet(7, false, 1);
    audio_tx.try_send(audio.clone().into()).unwrap();
    video_tx.try_send(video.clone().into()).unwrap();
    video_tx.try_send(video.clone().into()).unwrap();
    let max_body = 4 + 2 * (2 + video.len());
    let (cell, overflow) = media_ready_batch(video.clone().into(), &mut video_rx, max_body);
    let cell = cell.unwrap().payload;
    assert!(media_cell_is_video(&cell));
    assert_eq!(
        expand_wire_cells(&[cell]),
        vec![video.clone(), video.clone()]
    );
    assert_eq!(overflow.map(|packet| packet.payload), Some(video));
    assert_eq!(audio_rx.try_recv().unwrap().payload, audio);
    let (cell, overflow) = media_ready_batch(audio.clone().into(), &mut audio_rx, max_body);
    assert_eq!(cell.map(|packet| packet.payload), Some(audio));
    assert!(overflow.is_none());
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

#[tokio::test]
async fn relay_frame_repair_and_control_cannot_renew_original_fragment_age() {
    let (audio, _audio_rx) = mpsc::channel(1);
    let (video, mut video_rx) = mpsc::channel(3);
    let ingress = MediaIngress::new(
        audio,
        MediaVideoIngress::relay_frames(video, Arc::default()),
    );
    let now = tokio::time::Instant::now();
    let original_deadline = now + Duration::from_millis(50);
    let repair_deadline = now + Duration::from_millis(180);
    let control_deadline = now + Duration::from_millis(190);
    let prefix = video_packet(8, false, 1);
    let repair = video_packet(7, false, 2);
    let tail = video_packet(8, true, 3);
    let control = vec![0x80, 201, 0, 1, 1, 2, 3, 4];
    assert_eq!(
        ingress.enqueue(QueuedMediaPacket {
            payload: prefix.clone(),
            deadline: original_deadline,
        }),
        0
    );
    assert_eq!(
        ingress.enqueue(QueuedMediaPacket {
            payload: repair.clone(),
            deadline: repair_deadline,
        }),
        0
    );
    assert_eq!(
        ingress.enqueue_video_control(QueuedMediaPacket {
            payload: control.clone(),
            deadline: control_deadline,
        }),
        0
    );
    assert_eq!(
        ingress.enqueue(QueuedMediaPacket {
            payload: tail.clone(),
            deadline: now + MEDIA_LOCAL_QUEUE_AGE,
        }),
        0
    );
    for (expected, deadline) in [
        (vec![repair], repair_deadline),
        (vec![control], control_deadline),
        (vec![prefix, tail], original_deadline),
    ] {
        let frame = video_rx.try_recv().unwrap();
        assert_eq!(frame.packets, expected);
        assert_eq!(
            tokio::time::Instant::from_std(frame.enqueued_at + MEDIA_LOCAL_QUEUE_AGE),
            deadline
        );
    }
}

#[tokio::test]
async fn relay_marker_with_older_admission_must_set_the_whole_frame_deadline() {
    let (audio, _audio_rx) = mpsc::channel(1);
    let (video, mut video_rx) = mpsc::channel(1);
    let ingress = MediaIngress::new(
        audio,
        MediaVideoIngress::relay_frames(video, Arc::default()),
    );
    let now = tokio::time::Instant::now();
    let deadline = now + Duration::from_millis(30);
    assert_eq!(
        ingress.enqueue(QueuedMediaPacket {
            payload: video_packet(7, false, 1),
            deadline: now + Duration::from_millis(150),
        }),
        0
    );
    assert_eq!(
        ingress.enqueue(QueuedMediaPacket {
            payload: video_packet(7, true, 2),
            deadline,
        }),
        0
    );
    let frame = video_rx.try_recv().unwrap();
    assert_eq!(frame.packets.len(), 2);
    assert_eq!(
        tokio::time::Instant::from_std(frame.enqueued_at + MEDIA_LOCAL_QUEUE_AGE),
        deadline
    );
}

#[tokio::test]
async fn stale_assembled_video_never_seals_or_precedes_a_fresh_frame() {
    let (audio, _audio_rx) = mpsc::channel(1);
    let (video, video_rx) = mpsc::channel(2);
    let stats = Arc::new(RelayMediaStats::default());
    let ingress = MediaIngress::new(
        audio,
        MediaVideoIngress::relay_frames(video, Arc::clone(&stats)),
    );
    assert_eq!(
        ingress.enqueue(QueuedMediaPacket {
            payload: video_packet(7, false, 1),
            deadline: tokio::time::Instant::now() - Duration::from_millis(1),
        }),
        0
    );
    assert_eq!(ingress.enqueue(video_packet(7, true, 2).into()), 0);
    let fresh = video_packet(8, true, 3);
    assert_eq!(ingress.enqueue(fresh.clone().into()), 0);
    drop(ingress);
    let peer = [0xd5; 32];
    let cipher = Arc::new(cipher_for_test(&peer, &[1; 32], &[2; 32]).unwrap());
    let receiver = cipher_for_test(&peer, &[2; 32], &[1; 32]).unwrap();
    let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
    tokio::time::timeout(
        Duration::from_secs(1),
        drain_relay_video(
            video_rx,
            Arc::new(AtomicU8::new(MEDIA_BATCHING_OFF)),
            cipher,
            stats,
            move |cell| {
                sent_tx.send(cell).unwrap();
                async { true }
            },
        ),
    )
    .await
    .unwrap();
    let cell = sent_rx.try_recv().expect("fresh frame is sent");
    assert_eq!(receiver.open(cell.as_bytes()), Some(fresh));
    assert_eq!(
        u64::from_be_bytes(cell.as_bytes()[12..20].try_into().unwrap()),
        1,
        "stale frame must not consume media nonces"
    );
    assert!(
        sent_rx.try_recv().is_err(),
        "stale frame must not reach transport"
    );
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
fn relay_video_repair_is_immediate_and_preserves_the_next_frame_prefix() {
    let mut assembler = RelayVideoFrameAssembler::default();
    let original = video_packet(7, true, 1);
    assert!(matches!(
        assembler.push(original),
        RelayVideoFramePush::Complete(_)
    ));
    let prefix = video_packet(8, false, 2);
    assert!(matches!(
        assembler.push(prefix.clone()),
        RelayVideoFramePush::Pending
    ));

    let mut oversized_repair = video_packet(7, false, 9);
    oversized_repair.resize(RELAY_VIDEO_FRAME_MAX_BYTES + 1, 9);
    assert!(matches!(
        assembler.push(oversized_repair),
        RelayVideoFramePush::Dropped
    ));

    // A NACK asks for a single old fragment, not its whole encoded frame.
    // Neither its timestamp nor its missing marker may replace frame 8.
    for marker in [false, true] {
        let repair = video_packet(7, marker, 3);
        let RelayVideoFramePush::Complete(packets) = assembler.push(repair.clone()) else {
            panic!("a repair must not wait for the old frame's other packets");
        };
        assert_eq!(packets, vec![repair]);
    }
    let tail = video_packet(8, true, 4);
    let RelayVideoFramePush::Complete(packets) = assembler.push(tail.clone()) else {
        panic!("the next frame must still complete");
    };
    assert_eq!(packets, vec![prefix, tail]);
}

#[test]
fn relay_video_repairs_remain_separate_after_completion_and_timestamp_wrap() {
    let mut assembler = RelayVideoFrameAssembler::default();
    let old = video_packet(u32::MAX - 3, true, 1);
    assert!(matches!(
        assembler.push(old.clone()),
        RelayVideoFramePush::Complete(_)
    ));
    let duplicate = video_packet(u32::MAX - 3, false, 2);
    let RelayVideoFramePush::Complete(packets) = assembler.push(duplicate.clone()) else {
        panic!("a completed timestamp's repair must be sent immediately");
    };
    assert_eq!(packets, vec![duplicate]);
    let prefix = video_packet(2, false, 3);
    assert!(matches!(
        assembler.push(prefix.clone()),
        RelayVideoFramePush::Pending
    ));
    let RelayVideoFramePush::Complete(packets) = assembler.push(old.clone()) else {
        panic!("a pre-wrap repair must not replace the post-wrap frame");
    };
    assert_eq!(packets, vec![old]);
    let tail = video_packet(2, true, 4);
    let RelayVideoFramePush::Complete(packets) = assembler.push(tail.clone()) else {
        panic!("post-wrap frame must complete normally");
    };
    assert_eq!(packets, vec![prefix, tail]);
}

#[test]
fn relay_video_repair_marker_cannot_clear_a_contended_frame_discard() {
    let mut assembler = RelayVideoFrameAssembler::default();
    assert!(matches!(
        assembler.push(video_packet(7, true, 1)),
        RelayVideoFramePush::Complete(_)
    ));
    assert!(matches!(
        assembler.push(video_packet(8, false, 2)),
        RelayVideoFramePush::Pending
    ));
    assembler.discard_after_contention();
    assert!(matches!(
        assembler.push(video_packet(7, true, 3)),
        RelayVideoFramePush::Complete(_)
    ));
    assert!(matches!(
        assembler.push(video_packet(8, false, 4)),
        RelayVideoFramePush::Dropped
    ));
    assert!(matches!(
        assembler.push(video_packet(8, true, 5)),
        RelayVideoFramePush::Dropped
    ));
    let next = video_packet(9, true, 6);
    let RelayVideoFramePush::Complete(packets) = assembler.push(next.clone()) else {
        panic!("a new frame must recover after the discarded frame's marker");
    };
    assert_eq!(packets, vec![next]);
}

#[tokio::test]
async fn relay_video_repairs_use_bounded_video_capacity_and_leave_audio_and_prefix_intact() {
    let (audio, mut audio_rx) = mpsc::channel(1);
    let (video, mut video_rx) = mpsc::channel(1);
    let stats = Arc::new(RelayMediaStats::default());
    let ingress = MediaIngress::new(audio, MediaVideoIngress::relay_frames(video, stats));
    let voice = vec![0x80, 111, 1, 2];
    assert_eq!(ingress.enqueue(voice.clone().into()), 0);
    assert_eq!(ingress.enqueue(video_packet(7, true, 1).into()), 0);
    video_rx.try_recv().unwrap();
    let prefix = video_packet(8, false, 2);
    assert_eq!(ingress.enqueue(prefix.clone().into()), 0);
    let repair = video_packet(7, false, 3);
    assert_eq!(ingress.enqueue(repair.clone().into()), 0);
    // Full video capacity reports loss without spending the reserved audio
    // capacity or discarding the next frame's already assembled prefix.
    assert_eq!(ingress.enqueue(video_packet(7, true, 4).into()), 1);
    assert_eq!(video_rx.try_recv().unwrap().packets, vec![repair]);
    let tail = video_packet(8, true, 5);
    assert_eq!(ingress.enqueue(tail.clone().into()), 0);
    assert_eq!(video_rx.try_recv().unwrap().packets, vec![prefix, tail]);
    assert_eq!(audio_rx.try_recv().unwrap().payload, voice);
    assert!(video_rx.try_recv().is_err());
    ingress.closed.store(true, Ordering::Release);
    assert_eq!(ingress.enqueue(video_packet(7, false, 6).into()), -1);
    assert!(video_rx.try_recv().is_err());
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

// These are the production drain helpers and sender indirection, with only
// their IPC sink replaced. Hold the secondary writer lock throughout audio
// delivery to exercise the exact stall that a common sender used to cause.
async fn audio_continues_while_video_writer_is_blocked(relay: bool) {
    let peer = if relay { [0xf1; 32] } else { [0xf2; 32] };
    let cipher = Arc::new(cipher_for_test(&peer, &[1; 32], &[2; 32]).unwrap());
    let receiver = cipher_for_test(&peer, &[2; 32], &[1; 32]).unwrap();
    let mode = Arc::new(AtomicU8::new(if relay {
        MEDIA_BATCHING_COMPACT_RELAY
    } else {
        MEDIA_BATCHING_OFF
    }));
    let primary = Arc::new(Mutex::new(Some(())));
    let secondary = Arc::new(Mutex::new(Some(())));
    let slot = Arc::new(MediaSenderSlot::new(Arc::clone(&primary)));
    slot.replace(Arc::clone(&secondary));
    let held_writer = secondary.lock().await;
    let entered = Arc::new(Notify::new());
    let video_entered = Arc::clone(&entered);
    let (sent_audio, mut received_audio) = mpsc::unbounded_channel();
    let (sent_video, mut received_video) = mpsc::unbounded_channel();
    let (audio_tx, audio_rx) = mpsc::channel(8);
    let audio_task = tokio::spawn(drain_media_packets(
        audio_rx,
        Arc::clone(&mode),
        Arc::clone(&cipher),
        relay,
        move |cell| {
            let primary = Arc::clone(&primary);
            let sent = sent_audio.clone();
            async move {
                let _guard = primary.lock().await;
                sent.send(cell.sealed.into_vec()).unwrap();
                true
            }
        },
    ));
    let sink = move |sealed: crate::media::SealedMediaCell| {
        let writer = slot.current();
        let entered = Arc::clone(&video_entered);
        let sent = sent_video.clone();
        async move {
            entered.notify_one();
            let _guard = writer.lock().await;
            sent.send(sealed.into_vec()).unwrap();
            true
        }
    };
    let video = video_packet(7, true, 3);
    let video_task = if relay {
        let (tx, rx) = mpsc::channel(1);
        tx.send(RelayVideoFrame {
            packets: vec![video.clone()],
            enqueued_at: Instant::now(),
        })
        .await
        .unwrap();
        drop(tx);
        tokio::spawn(drain_relay_video(
            rx,
            Arc::clone(&mode),
            Arc::clone(&cipher),
            Arc::new(RelayMediaStats::default()),
            sink,
        ))
    } else {
        let (tx, rx) = mpsc::channel(1);
        tx.send(video.clone().into()).await.unwrap();
        drop(tx);
        tokio::spawn(drain_media_packets(
            rx,
            Arc::clone(&mode),
            Arc::clone(&cipher),
            false,
            move |cell| sink(cell.sealed),
        ))
    };
    // Wait for video sealing to complete and
    // for that task to reach the blocked writer before sending the audio.
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    let audio = vec![0x80, 111, 1, 2, 3, 4];
    audio_tx.send(audio.clone().into()).await.unwrap();
    let sealed_audio = tokio::time::timeout(Duration::from_millis(100), received_audio.recv())
        .await
        .expect("audio must not wait for the video IPC writer")
        .unwrap();
    assert!(
        received_video.try_recv().is_err(),
        "video writer is still held"
    );
    drop(held_writer);
    let sealed_video = tokio::time::timeout(Duration::from_secs(1), received_video.recv())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        &sealed_audio[4..12],
        &sealed_video[4..12],
        "each producer must have an independent epoch key and replay window"
    );
    assert_eq!(receiver.open(&sealed_audio), Some(audio));
    assert_eq!(receiver.open(&sealed_video), Some(video));
    assert!(
        receiver.open(&sealed_audio).is_none(),
        "replay remains rejected"
    );
    drop(audio_tx);
    tokio::time::timeout(Duration::from_secs(1), audio_task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), video_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn anonymous_audio_continues_during_blocked_video_or_control_send_and_warm() {
    for (blocked_plane, block_warm) in [
        (LocalMediaPlane::Secondary, false),
        (LocalMediaPlane::Secondary, true),
        (LocalMediaPlane::Control, false),
        (LocalMediaPlane::Control, true),
    ] {
        let cipher = Arc::new(cipher_for_test(&[0x87; 32], &[1; 32], &[2; 32]).unwrap());
        let receiver = cipher_for_test(&[0x88; 32], &[2; 32], &[1; 32]).unwrap();
        let (audio_tx, audio_rx) = mpsc::channel(2);
        let (video_tx, video_rx) = mpsc::channel(2);
        let (audio_repair_tx, audio_repair_rx) = mpsc::channel(1);
        let (video_repair_tx, video_repair_rx) = mpsc::channel(1);
        let (received_tx, mut received_rx) = mpsc::channel(4);
        let audio_received = received_tx.clone();
        let audio_task = tokio::spawn(drain_anonymous_media(
            audio_rx,
            audio_repair_rx,
            Arc::clone(&cipher),
            LocalMediaPlane::Primary,
            move |cell| {
                let tx = audio_received.clone();
                async move { tx.send(cell.into_vec()).await.is_ok() }
            },
            || async {},
        ));
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let send_entered = Arc::clone(&entered);
        let send_release = Arc::clone(&release);
        let video_task = tokio::spawn(drain_anonymous_media(
            video_rx,
            video_repair_rx,
            cipher,
            blocked_plane,
            move |cell| {
                let tx = received_tx.clone();
                let entered = Arc::clone(&send_entered);
                let release = Arc::clone(&send_release);
                async move {
                    if !block_warm {
                        entered.notify_one();
                        release.notified().await;
                    }
                    tx.send(cell.into_vec()).await.is_ok()
                }
            },
            {
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                move || {
                    let entered = Arc::clone(&entered);
                    let release = Arc::clone(&release);
                    async move {
                        if block_warm {
                            entered.notify_one();
                            release.notified().await;
                        }
                    }
                }
            },
        ));
        let video = if matches!(blocked_plane, LocalMediaPlane::Control) {
            vec![0x80, 201, 0, 1, 0, 0, 0, 7]
        } else {
            video_packet(7, true, 1)
        };
        let ingress = MediaIngress::new(
            audio_tx.clone(),
            MediaVideoIngress::Packets(video_tx.clone()),
        );
        *ingress.feedback_tx.write().unwrap() = Some(video_tx.clone());
        assert_eq!(ingress.enqueue(video.clone().into()), 0);
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .unwrap();
        let audio = vec![0x80, 111, 1, 2, 3, 4];
        assert_eq!(ingress.enqueue(audio.clone().into()), 0);
        let cell = tokio::time::timeout(Duration::from_millis(100), received_rx.recv())
            .await
            .expect("anonymous audio must not wait for another source")
            .unwrap();
        assert_eq!(receiver.open(&cell), Some(audio));
        release.notify_one();
        let cell = tokio::time::timeout(Duration::from_secs(1), received_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receiver.open(&cell), Some(video));
        drop((
            ingress,
            audio_tx,
            video_tx,
            audio_repair_tx,
            video_repair_tx,
        ));
        for task in [audio_task, video_task] {
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
        }
    }
}

#[tokio::test]
async fn anonymous_active_producers_rewarm_on_repair_and_stop_with_closed_ingress() {
    for plane in [
        LocalMediaPlane::Primary,
        LocalMediaPlane::Secondary,
        LocalMediaPlane::Screen,
        LocalMediaPlane::Control,
    ] {
        let cipher = Arc::new(cipher_for_test(&[0x8e; 32], &[1; 32], &[2; 32]).unwrap());
        let receiver = cipher_for_test(&[0x8f; 32], &[2; 32], &[1; 32]).unwrap();
        let (tx, rx) = mpsc::channel(1);
        let (repair_tx, repair_rx) = mpsc::channel(1);
        let (warm_tx, mut warm_rx) = mpsc::channel(4);
        let (sent_tx, mut sent_rx) = mpsc::channel(1);
        let task = tokio::spawn(drain_anonymous_media(
            rx,
            repair_rx,
            cipher,
            plane,
            move |cell| {
                let tx = sent_tx.clone();
                async move { tx.send(cell.into_vec()).await.is_ok() }
            },
            move || {
                let tx = warm_tx.clone();
                async move {
                    tx.send(()).await.unwrap();
                }
            },
        ));
        let packet = vec![0x80, 111, 1, 2];
        tx.send(packet.clone().into()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), warm_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let cell = tokio::time::timeout(Duration::from_secs(1), sent_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receiver.open(&cell), Some(packet));
        repair_tx.send(()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), warm_rx.recv())
            .await
            .unwrap()
            .unwrap();
        drop(tx);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(warm_rx.try_recv().is_err(), "one warm per accepted repair");
    }
}

#[tokio::test]
async fn anonymous_video_does_not_construct_unused_routes() {
    let cipher = Arc::new(cipher_for_test(&[0x89; 32], &[1; 32], &[2; 32]).unwrap());
    let (tx, rx) = mpsc::channel(1);
    let (repair_tx, repair_rx) = mpsc::channel(1);
    let warms = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(drain_anonymous_media(
        rx,
        repair_rx,
        cipher,
        LocalMediaPlane::Secondary,
        |_| async { true },
        {
            let warms = Arc::clone(&warms);
            move || {
                let warms = Arc::clone(&warms);
                async move {
                    warms.fetch_add(1, Ordering::SeqCst);
                }
            }
        },
    ));
    repair_tx.send(()).await.unwrap();
    // Closing ingress ends the task even if repair ingress is still alive.
    drop(tx);
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(warms.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn anonymous_repair_fans_out_with_independent_backpressure() {
    let (tx_hi, _hi_rx) = mpsc::channel(1);
    let (tx_video, _video_rx) = mpsc::channel(1);
    let (repair_hi, mut repair_hi_rx) = mpsc::channel(1);
    let (repair_video, mut repair_video_rx) = mpsc::channel(1);
    let (repair_screen, mut repair_screen_rx) = mpsc::channel(1);
    let (repair_feedback, mut repair_feedback_rx) = mpsc::channel(1);
    let id = MEDIA_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    MEDIA_CHANNELS
        .write()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            id,
            MediaChannel {
                path_probe: None,
                source_preflight: None,
                ingress: MediaIngress::new(tx_hi, MediaVideoIngress::Packets(tx_video)),
                repair_tx: Some([repair_hi, repair_video, repair_screen, repair_feedback]),
                peer: [0x8a; 32],
                task: tokio::spawn(std::future::pending()),
                video_task: Some(tokio::spawn(std::future::pending())),
                screen_task: None,
                feedback_task: None,
                video_sender: None,
                screen_sender: None,
                sender_app_id: None,
                control_destination: None,
                direct_seq: None,
                batching: None,
                cipher: Arc::new(cipher_for_test(&[0x8a; 32], &[1; 32], &[2; 32]).unwrap()),
                relay_stats: None,
                routes: None,
            },
        );
    assert_eq!(unsafe { veil_media_repair_channel(id) }, 0);
    assert_eq!(unsafe { veil_media_repair_channel(id) }, 1);
    repair_hi_rx.try_recv().unwrap();
    assert_eq!(unsafe { veil_media_repair_channel(id) }, 0);
    repair_hi_rx.try_recv().unwrap();
    repair_video_rx.try_recv().unwrap();
    assert!(repair_video_rx.try_recv().is_err());
    repair_screen_rx.try_recv().unwrap();
    assert!(repair_screen_rx.try_recv().is_err());
    repair_feedback_rx.try_recv().unwrap();
    assert!(repair_feedback_rx.try_recv().is_err());
    unsafe { veil_media_close_channel(id) };
}

#[tokio::test]
async fn direct_audio_does_not_wait_for_video_writer() {
    audio_continues_while_video_writer_is_blocked(false).await;
}

#[tokio::test]
async fn relay_audio_does_not_wait_for_video_writer() {
    audio_continues_while_video_writer_is_blocked(true).await;
}

#[test]
fn relay_audio_batches_respect_compact_size_and_packet_limits() {
    let packets = vec![vec![0x80, 111, 1, 2, 3, 4]; 15];
    let cells = media_batched_cells(packets.clone(), 22, 6);
    assert!(cells.iter().all(|cell| cell.len() <= 23));
    assert_eq!(expand_wire_cells(&cells), packets);
    let cells = media_batched_cells(packets.clone(), 1000, 6);
    assert_eq!(cells.len(), 3, "six + six + three");
    assert_eq!(expand_wire_cells(&cells), packets);
}

#[tokio::test]
async fn closing_channel_cancels_both_blocked_pumps() {
    let task = tokio::spawn(std::future::pending::<()>());
    let video_task = tokio::spawn(std::future::pending::<()>());
    let screen_task = tokio::spawn(std::future::pending::<()>());
    let feedback_task = tokio::spawn(std::future::pending::<()>());
    let abort_feedback = feedback_task.abort_handle();
    let abort_screen = screen_task.abort_handle();
    let abort_audio = task.abort_handle();
    let abort_video = video_task.abort_handle();
    let (tx_hi, _hi_rx) = mpsc::channel(1);
    let (tx_video, _video_rx) = mpsc::channel(1);
    let id = MEDIA_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    MEDIA_CHANNELS
        .write()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            id,
            MediaChannel {
                path_probe: None,
                source_preflight: None,
                ingress: MediaIngress::new(tx_hi, MediaVideoIngress::Packets(tx_video)),
                repair_tx: None,
                peer: [0xf3; 32],
                task,
                video_task: Some(video_task),
                screen_task: Some(screen_task),
                feedback_task: Some(feedback_task),
                video_sender: None,
                screen_sender: None,
                sender_app_id: None,
                control_destination: None,
                direct_seq: None,
                batching: None,
                cipher: Arc::new(cipher_for_test(&[0xf3; 32], &[1; 32], &[2; 32]).unwrap()),
                relay_stats: None,
                routes: None,
            },
        );
    unsafe { veil_media_close_channel(id) };
    tokio::time::timeout(Duration::from_secs(1), async {
        while !abort_audio.is_finished()
            || !abort_video.is_finished()
            || !abort_screen.is_finished()
            || !abort_feedback.is_finished()
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("close must cancel all media and feedback tasks");
    let packet = [0x80, 111, 1, 2];
    // Other parallel fixtures deliberately hold the registry. Busy ingress
    // returns 1 before lookup; once available, this closed handle must be gone.
    assert_eq!(send_when_registry_available(id, &packet), -1);
    unsafe { veil_media_close_channel(id) }; // Idempotent.
}

#[tokio::test]
async fn private_address_control_requires_call_aead_and_never_reaches_the_engine() {
    extern "C" fn count(ctx: *mut std::ffi::c_void, _ptr: *const u8, _len: usize) {
        unsafe { &*(ctx as *const AtomicUsize) }.fetch_add(1, Ordering::SeqCst);
    }
    let peer = [0xe9; 32];
    let id = MEDIA_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let cipher = Arc::new(cipher_for_test(&peer, &[0x61; 32], &[0x62; 32]).unwrap());
    let sender = cipher_for_test(&peer, &[0x62; 32], &[0x61; 32]).unwrap();
    let (_dir, mut node, routes) =
        crate::anon_stream::media_routes::fixture(peer, id, Arc::clone(&cipher)).await;
    struct CloseChannel(u64);
    impl Drop for CloseChannel {
        fn drop(&mut self) {
            unsafe { veil_media_close_channel(self.0) };
        }
    }
    let mut count_context = Box::new(AtomicUsize::new(0));
    let before = crate::media::recv_count(peer);
    let (tx_hi, _rx) = mpsc::channel(1);
    let (tx_video, _video_rx) = mpsc::channel(1);
    MEDIA_CHANNELS.write().unwrap().insert(
        id,
        MediaChannel {
            path_probe: None,
            source_preflight: None,
            ingress: MediaIngress::new(tx_hi, MediaVideoIngress::Packets(tx_video)),
            repair_tx: None,
            peer,
            task: tokio::spawn(std::future::pending()),
            video_task: None,
            screen_task: None,
            feedback_task: None,
            video_sender: None,
            screen_sender: None,
            sender_app_id: None,
            control_destination: None,
            direct_seq: None,
            batching: None,
            cipher: Arc::clone(&cipher),
            relay_stats: None,
            routes: Some(Arc::clone(&routes)),
        },
    );
    crate::media::set_recv_callback(
        peer,
        id,
        count,
        (&mut *count_context as *mut AtomicUsize).cast(),
        Arc::clone(&cipher),
    );
    let cleanup = CloseChannel(id);
    let mut body = crate::anon_stream::MEDIA_ROUTE_CONTROL_MAGIC.to_vec();
    body.extend_from_slice(&1u64.to_be_bytes());
    body.extend_from_slice(&1u64.to_be_bytes());
    body.extend_from_slice(&[1, 0]); // One primary address.
    body.extend_from_slice(&[0x73; 32]);
    body.extend_from_slice(&[0x74; 16]);
    body.extend_from_slice(&[0x75; 32]);
    let sealed = sender.seal(&body).unwrap().into_vec();
    let mut forged = sealed.clone();
    *forged.last_mut().unwrap() ^= 1;
    crate::media::dispatch_inbound_auto(peer, &body);
    crate::media::dispatch_inbound_auto(peer, &forged);
    assert!(routes.received_offer_for_test().is_none());
    crate::media::dispatch_inbound_auto(peer, &sealed);
    assert_eq!(routes.received_offer_for_test(), Some(body));
    // Extending the receive map never makes its capability/addresses public
    // control input: the complete four-address offer still needs this call AEAD.
    let mut extended = crate::anon_stream::MEDIA_ROUTE_CONTROL_MAGIC.to_vec();
    extended.extend_from_slice(&1u64.to_be_bytes());
    extended.extend_from_slice(&2u64.to_be_bytes());
    extended.push(4);
    for plane in 0..4u8 {
        extended.push(plane);
        extended.extend_from_slice(&[0x73; 32]);
        extended.extend_from_slice(&[0x74 + plane; 16]);
        extended.extend_from_slice(&[0x75; 32]);
    }
    let extended_sealed = sender.seal(&extended).unwrap().into_vec();
    let mut extended_forged = extended_sealed.clone();
    *extended_forged.last_mut().unwrap() ^= 1;
    let previous = routes.received_offer_for_test();
    crate::media::dispatch_inbound_auto(peer, &extended);
    crate::media::dispatch_inbound_auto(peer, &extended_forged);
    assert_eq!(routes.received_offer_for_test(), previous);
    crate::media::dispatch_inbound_auto(peer, &extended_sealed);
    assert_eq!(routes.received_offer_for_test(), Some(extended));
    assert_eq!(count_context.load(Ordering::SeqCst), 0);
    assert_eq!(
        crate::media::recv_count(peer),
        before,
        "control is not media liveness"
    );
    let rtp = sender.seal(&[0x80, 111, 1, 2]).unwrap();
    crate::media::dispatch_inbound_auto(peer, rtp.as_bytes());
    assert_eq!(count_context.load(Ordering::SeqCst), 1);
    drop(cleanup);
    node.stop().await.unwrap();
}

#[tokio::test]
async fn route_warm_stall_drops_old_audio_and_keeps_current_audio_and_control() {
    let peer = [0xc1; 32];
    let cipher = Arc::new(cipher_for_test(&peer, &[1; 32], &[2; 32]).unwrap());
    let receiver = cipher_for_test(&peer, &[2; 32], &[1; 32]).unwrap();
    let (tx, rx) = mpsc::channel(8);
    let (repair_tx, repair_rx) = mpsc::channel(1);
    let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    tx.send(vec![0x80, 111, 1, 9].into()).await.unwrap();
    let warm_entered = Arc::clone(&entered);
    let warm_release = Arc::clone(&release);
    let task = tokio::spawn(drain_anonymous_media(
        rx,
        repair_rx,
        cipher,
        LocalMediaPlane::Primary,
        move |cell| {
            let tx = sent_tx.clone();
            async move { tx.send(cell.into_vec()).is_ok() }
        },
        move || {
            let entered = Arc::clone(&warm_entered);
            let release = Arc::clone(&warm_release);
            async move {
                entered.notify_one();
                release.notified().await;
            }
        },
    ));
    entered.notified().await;
    tokio::time::sleep(MEDIA_LOCAL_QUEUE_AGE + Duration::from_millis(20)).await;
    let current = vec![0x80, 111, 2, 9];
    let control = vec![0x80, 200, 0, 1];
    tx.send(current.clone().into()).await.unwrap();
    tx.send(control.clone().into()).await.unwrap();
    drop(tx);
    drop(repair_tx);
    release.notify_one();
    task.await.unwrap();
    let mut actual = Vec::new();
    while let Some(cell) = sent_rx.recv().await {
        actual.extend(expand_wire_cells(&[receiver.open(&cell).unwrap()]));
    }
    assert_eq!(actual, vec![current, control]);
}

#[tokio::test]
async fn a_dequeued_burst_expires_while_its_first_ipc_request_finishes_normally() {
    for (relay, mode) in [
        (false, MEDIA_BATCHING_OFF),
        (false, super::MEDIA_BATCHING_LEGACY),
        (true, MEDIA_BATCHING_COMPACT_RELAY),
    ] {
        let peer = [0xc2; 32];
        let cipher = Arc::new(cipher_for_test(&peer, &[1; 32], &[2; 32]).unwrap());
        let receiver = cipher_for_test(&peer, &[2; 32], &[1; 32]).unwrap();
        let (tx, rx) = mpsc::channel(16);
        let (sent_tx, mut sent_rx) = mpsc::unbounded_channel();
        let ack = Arc::new(Notify::new());
        let pending_ack = Arc::clone(&ack);
        let calls = Arc::new(AtomicUsize::new(0));
        let sink_calls = Arc::clone(&calls);
        let packets: Vec<_> = (0..8).map(|seq| vec![0x80, 111, seq, 9]).collect();
        for packet in &packets {
            tx.send(packet.clone().into()).await.unwrap();
        }
        let task = tokio::spawn(drain_media_packets(
            rx,
            Arc::new(AtomicU8::new(mode)),
            cipher,
            relay,
            move |cell| {
                let tx = sent_tx.clone();
                let ack = Arc::clone(&pending_ack);
                let calls = Arc::clone(&sink_calls);
                async move {
                    let first = calls.fetch_add(1, Ordering::SeqCst) == 0;
                    // Bytes have been written. Expiry must not cancel an ACK
                    // wait or truncate the already-started IPC request.
                    tx.send(cell.sealed.into_vec()).unwrap();
                    if first {
                        ack.notified().await;
                    }
                    true
                }
            },
        ));
        let first = sent_rx.recv().await.unwrap();
        tokio::time::sleep(MEDIA_LOCAL_QUEUE_AGE + Duration::from_millis(20)).await;
        assert!(
            !task.is_finished(),
            "expiry must not cancel in-progress IPC"
        );
        let current = vec![0x80, 111, 99, 9];
        tx.send(current.clone().into()).await.unwrap();
        drop(tx);
        ack.notify_one();
        task.await.unwrap();
        let mut actual = expand_wire_cells(&[receiver.open(&first).unwrap()]);
        while let Some(cell) = sent_rx.recv().await {
            actual.extend(expand_wire_cells(&[receiver.open(&cell).unwrap()]));
        }
        let first_count = if mode == MEDIA_BATCHING_OFF {
            1
        } else if relay {
            6
        } else {
            4
        };
        let mut expected = packets[..first_count].to_vec();
        expected.push(current);
        assert_eq!(actual, expected, "mode={mode} relay={relay}");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn sealed_cell_expires_while_waiting_for_a_writer_without_changing_wire_bytes() {
    let peer = [0xc3; 32];
    let cipher = cipher_for_test(&peer, &[1; 32], &[2; 32]).unwrap();
    let receiver = cipher_for_test(&peer, &[2; 32], &[1; 32]).unwrap();
    let packet = [0x80, 111, 9, 1];
    let cell = cipher.seal(&packet).unwrap();
    let wire = cell.as_bytes().to_vec();
    let cell = cell.with_local_deadline(tokio::time::Instant::now() + Duration::from_millis(20));
    let writer = Mutex::new(());
    let held = writer.lock().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), cell.lock_while_fresh(&writer))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        writer.try_lock().is_err(),
        "the existing writer still owns the lock"
    );
    assert_eq!(cell.as_bytes(), wire);
    assert_eq!(receiver.open(&wire), Some(packet.to_vec()));
    drop(held);
    assert!(
        cell.lock_while_fresh(&writer).await.is_none(),
        "an expired cell must not start a write after release"
    );
}

#[tokio::test]
async fn anonymous_overflow_preserves_the_original_deadline() {
    let (tx, mut rx) = mpsc::channel(1);
    let first: QueuedMediaPacket = vec![0x80, 111, 1, 9].into();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
    tx.send(QueuedMediaPacket {
        payload: vec![0x80, 111, 2, 9],
        deadline,
    })
    .await
    .unwrap();
    let (cell, overflow) = media_ready_batch(first, &mut rx, 4);
    assert!(cell.is_some());
    let pending = overflow.unwrap();
    assert_eq!(pending.deadline, deadline);
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(media_ready_batch(pending, &mut rx, 4).0.is_none());
}

#[test]
fn timed_cell_deadlines_follow_actual_batches_and_raw_fallback_packets() {
    let now = tokio::time::Instant::now();
    let packets = vec![
        QueuedMediaPacket {
            payload: vec![0x80; 700],
            deadline: now + Duration::from_millis(10),
        },
        QueuedMediaPacket {
            payload: vec![0x80, 111, 1, 9],
            deadline: now + Duration::from_millis(20),
        },
        QueuedMediaPacket {
            payload: vec![0x80, 111, 2, 9],
            deadline: now + Duration::from_millis(30),
        },
        QueuedMediaPacket {
            payload: vec![0x80; 700],
            deadline: now + Duration::from_millis(40),
        },
    ];
    let cells = timed_media_cells(packets, true, 500, 6);
    assert_eq!(cells.len(), 3);
    assert_eq!(
        cells.iter().map(|cell| cell.deadline).collect::<Vec<_>>(),
        vec![
            now + Duration::from_millis(10),
            now + Duration::from_millis(20),
            now + Duration::from_millis(40)
        ]
    );
    assert_eq!(
        expand_wire_cells(
            &cells
                .into_iter()
                .map(|cell| cell.payload)
                .collect::<Vec<_>>()
        )
        .len(),
        4
    );
}

fn register_test_ingress(
    ingress: Arc<MediaIngress>,
    peer: [u8; 32],
) -> (u64, std::sync::Weak<crate::media::MediaCipher>) {
    let id = MEDIA_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let cipher = Arc::new(cipher_for_test(&peer, &[1; 32], &[2; 32]).unwrap());
    let weak = Arc::downgrade(&cipher);
    MEDIA_CHANNELS.write().unwrap().insert(
        id,
        MediaChannel {
            path_probe: None,
            source_preflight: None,
            ingress,
            repair_tx: None,
            peer,
            task: tokio::spawn(std::future::pending()),
            video_task: Some(tokio::spawn(std::future::pending())),
            screen_task: None,
            feedback_task: None,
            video_sender: None,
            screen_sender: None,
            sender_app_id: None,
            control_destination: None,
            direct_seq: None,
            batching: None,
            cipher,
            relay_stats: None,
            routes: None,
        },
    );
    (id, weak)
}

fn send_when_registry_available(id: u64, packet: &[u8]) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let result = unsafe { veil_media_send_datagram(id, packet.as_ptr(), packet.len()) };
        if result != 1 || Instant::now() >= deadline {
            return result;
        }
        std::thread::yield_now();
    }
}

#[cfg(debug_assertions)]
#[test]
fn native_ingress_diagnostics_attribute_queue_failures_without_changing_admission() {
    use super::ingress_diagnostics::{Reason, snapshot};
    let (tx_hi, mut rx_hi) = mpsc::channel(1);
    let (tx_video, rx_video) = mpsc::channel(1);
    let ingress = MediaIngress::new(tx_hi, MediaVideoIngress::Packets(tx_video));
    let before = snapshot();
    assert_eq!(ingress.enqueue(video_packet(1, true, 1).into()), 0);
    assert_eq!(ingress.enqueue(video_packet(2, true, 2).into()), 1);
    // Saturated video still cannot occupy the audio source.
    assert_eq!(ingress.enqueue(vec![0x80, 111, 1, 2].into()), 0);
    assert_eq!(ingress.enqueue(vec![0x80, 111, 3, 4].into()), 1);
    let full = snapshot();
    assert!(
        full[Reason::PacketQueueFull as usize * 2] > before[Reason::PacketQueueFull as usize * 2]
    );
    assert!(
        full[Reason::PacketQueueFull as usize * 2 + 1]
            > before[Reason::PacketQueueFull as usize * 2 + 1]
    );
    assert_eq!(rx_hi.try_recv().unwrap().payload, [0x80, 111, 1, 2]);
    drop(rx_video);
    assert_eq!(ingress.enqueue(video_packet(3, true, 3).into()), -1);
    let closed = snapshot();
    assert!(
        closed[Reason::PacketQueueClosed as usize * 2 + 1]
            > full[Reason::PacketQueueClosed as usize * 2 + 1]
    );
}

#[tokio::test]
async fn native_ingress_audio_control_and_other_channels_pass_held_video_assembly() {
    let (tx_hi, mut hi_rx) = mpsc::channel(4);
    let (tx_video, mut video_rx) = mpsc::channel(4);
    let ingress = MediaIngress::new(
        tx_hi,
        MediaVideoIngress::relay_frames(tx_video, Arc::default()),
    );
    let (id, _) = register_test_ingress(Arc::clone(&ingress), [0xd1; 32]);
    let (other_hi, _other_hi_rx) = mpsc::channel(4);
    let (other_video, mut other_video_rx) = mpsc::channel(4);
    let (other_id, _) = register_test_ingress(
        MediaIngress::new(other_hi, MediaVideoIngress::Packets(other_video)),
        [0xd2; 32],
    );
    let MediaVideoIngress::RelayFrames { assembler, .. } = &ingress.video else {
        unreachable!()
    };
    let guard = assembler.lock().unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let audio = [0x80, 111, 1, 2];
        let control = [0x80, 201, 0, 1];
        let video = video_packet(1, true, 0x22);
        let result = (
            send_when_registry_available(id, &audio),
            send_when_registry_available(id, &control),
            send_when_registry_available(other_id, &video),
        );
        done_tx.send(result).unwrap();
    });
    let passed_while_held = done_rx.recv_timeout(Duration::from_secs(1));
    drop(guard); // Release before asserting, including on a regression.
    worker.join().unwrap();
    unsafe {
        veil_media_close_channel(id);
        veil_media_close_channel(other_id);
    }
    assert_eq!(passed_while_held.unwrap(), (0, 0, 0));
    assert_eq!(hi_rx.try_recv().unwrap().payload, [0x80, 111, 1, 2]);
    assert_eq!(hi_rx.try_recv().unwrap().payload, [0x80, 201, 0, 1]);
    assert_eq!(
        other_video_rx.try_recv().unwrap().payload,
        video_packet(1, true, 0x22)
    );
    assert!(video_rx.try_recv().is_err());
}

#[tokio::test]
async fn native_ingress_registry_readers_do_not_discard_audio_or_video() {
    // Other tests deliberately hold the global registry's write lock. A
    // queued writer may make try_read refuse admission, so exercise this
    // read-only regression in a child running this exact test alone.
    const CHILD: &str = "VEIL_MEDIA_REGISTRY_READER_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "media_ffi::media_priority_tests::native_ingress_registry_readers_do_not_discard_audio_or_video",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let (tx_hi, mut rx_hi) = mpsc::channel(4);
    let (video, mut rx_video) = mpsc::channel(4);
    let (id, _) = register_test_ingress(
        MediaIngress::new(tx_hi, MediaVideoIngress::Packets(video)),
        [0xd5; 32],
    );
    let reader = MEDIA_CHANNELS.read().unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let audio = [0x80, 111, 1, 2];
        let video = video_packet(1, true, 3);
        let feedback = [0x80, 201, 0, 1, 0, 0, 0, 1];
        done_tx
            .send(unsafe {
                (
                    veil_media_send_datagram(id, audio.as_ptr(), audio.len()),
                    veil_media_send_datagram(id, video.as_ptr(), video.len()),
                    veil_media_send_video_control_datagram(id, feedback.as_ptr(), feedback.len()),
                )
            })
            .unwrap();
    });
    let result = done_rx.recv_timeout(Duration::from_secs(1));
    drop(reader); // Release before any assertion, including a regression.
    worker.join().unwrap();
    unsafe { veil_media_close_channel(id) };
    assert_eq!(result.unwrap(), (0, 0, 0));
    assert_eq!(rx_hi.try_recv().unwrap().payload, [0x80, 111, 1, 2]);
    assert_eq!(
        rx_video.try_recv().unwrap().payload,
        video_packet(1, true, 3)
    );
    assert_eq!(
        rx_video.try_recv().unwrap().payload,
        [0x80, 201, 0, 1, 0, 0, 0, 1]
    );
}

#[tokio::test]
async fn native_ingress_registry_mutation_drops_without_waiting() {
    let (tx_hi, mut rx_hi) = mpsc::channel(4);
    let (video, _rx_video) = mpsc::channel(4);
    let (id, _) = register_test_ingress(
        MediaIngress::new(tx_hi, MediaVideoIngress::Packets(video)),
        [0xd3; 32],
    );
    let registry_guard = MEDIA_CHANNELS.write().unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let packet = [0x80, 111, 1, 2];
        done_tx
            .send(unsafe { veil_media_send_datagram(id, packet.as_ptr(), packet.len()) })
            .unwrap();
    });
    let dropped_while_held = done_rx.recv_timeout(Duration::from_secs(1));
    drop(registry_guard);
    worker.join().unwrap();
    assert_eq!(dropped_while_held.unwrap(), 1);
    assert!(rx_hi.try_recv().is_err());
    assert_eq!(send_when_registry_available(id, &[0x80, 111, 1, 2]), 0);
    unsafe {
        veil_media_close_channel(id);
    }
}

#[tokio::test]
async fn native_video_contention_discards_tail_and_close_retires_surviving_ingress() {
    let (tx_hi, mut rx_hi) = mpsc::channel(4);
    let (tx_video, mut rx_video) = mpsc::channel(4);
    let ingress = MediaIngress::new(
        tx_hi,
        MediaVideoIngress::relay_frames(tx_video, Arc::default()),
    );
    let (id, cipher) = register_test_ingress(Arc::clone(&ingress), [0xd4; 32]);
    let MediaVideoIngress::RelayFrames { assembler, .. } = &ingress.video else {
        unreachable!()
    };
    assert_eq!(ingress.enqueue(video_packet(10, false, 1).into()), 0);
    let guard = assembler.lock().unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let clone = Arc::clone(&ingress);
    let worker = std::thread::spawn(move || {
        done_tx
            .send(clone.enqueue(video_packet(10, false, 3).into()))
            .unwrap();
    });
    let result = done_rx.recv_timeout(Duration::from_secs(1));
    // Release before joining/asserting so a blocking regression terminates.
    drop(guard);
    worker.join().unwrap();
    assert_eq!(result.unwrap(), 1);
    assert_eq!(ingress.enqueue(video_packet(10, true, 4).into()), 1);
    assert!(
        rx_video.try_recv().is_err(),
        "discard the incomplete frame rather than forwarding its tail"
    );
    assert_eq!(ingress.enqueue(video_packet(11, true, 5).into()), 0);
    assert_eq!(
        rx_video.try_recv().unwrap().packets,
        vec![video_packet(11, true, 5)]
    );
    let guard = assembler.lock().unwrap();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        unsafe {
            veil_media_close_channel(id);
        }
        done_tx.send(()).unwrap();
    });
    let closed_while_held = done_rx.recv_timeout(Duration::from_secs(1));
    drop(guard);
    worker.join().unwrap();
    closed_while_held.unwrap();
    assert!(
        cipher.upgrade().is_none(),
        "ingress must not keep the channel's keys alive"
    );
    assert_eq!(ingress.enqueue(vec![0x80, 111, 1, 2].into()), -1);
    assert_eq!(ingress.enqueue(video_packet(12, true, 6).into()), -1);
    assert!(rx_hi.try_recv().is_err());
    assert!(rx_video.try_recv().is_err());
}

#[tokio::test]
async fn screen_switch_routes_at_ingress_and_backpressure_stays_local() {
    let (audio_tx, mut audio_rx) = mpsc::channel(2);
    let (camera_tx, mut camera_rx) = mpsc::channel(2);
    let (screen_tx, mut screen_rx) = mpsc::channel(1);
    let ingress = MediaIngress::with_screen(
        audio_tx,
        MediaVideoIngress::Packets(camera_tx),
        MediaVideoIngress::Packets(screen_tx),
    );
    let (id, _) = register_test_ingress(Arc::clone(&ingress), [0xd3; 32]);
    let old_camera = video_packet(1, true, 1);
    let screen = video_packet(2, true, 2);
    let new_camera = video_packet(3, true, 3);
    assert_eq!(ingress.enqueue(old_camera.clone().into()), 0);
    assert_eq!(veil_media_channel_set_screen_sharing(id, 1), 0);
    assert_eq!(ingress.enqueue(screen.clone().into()), 0);
    assert_eq!(
        ingress.enqueue(screen.clone().into()),
        1,
        "screen queue is full"
    );
    assert_eq!(ingress.enqueue(vec![0x80, 111, 1, 2].into()), 0);
    assert_eq!(ingress.enqueue(vec![0x80, 72, 1, 2].into()), 0);
    assert_eq!(veil_media_channel_set_screen_sharing(id, 0), 0);
    assert_eq!(ingress.enqueue(new_camera.clone().into()), 0);
    assert_eq!(camera_rx.try_recv().unwrap().payload, old_camera);
    assert_eq!(camera_rx.try_recv().unwrap().payload, new_camera);
    assert_eq!(screen_rx.try_recv().unwrap().payload, screen);
    assert_eq!(audio_rx.try_recv().unwrap().payload, [0x80, 111, 1, 2]);
    assert_eq!(audio_rx.try_recv().unwrap().payload, [0x80, 72, 1, 2]);
    assert_eq!(veil_media_channel_set_screen_sharing(id, 2), -1);
    unsafe { veil_media_close_channel(id) };
    assert_eq!(veil_media_channel_set_screen_sharing(id, 1), -1);
    assert_eq!(ingress.enqueue(screen.clone().into()), -1);
}

#[tokio::test]
async fn camera_and_screen_relay_assemblers_cannot_merge_equal_timestamps() {
    let (audio_tx, _audio_rx) = mpsc::channel(2);
    let (camera_tx, mut camera_rx) = mpsc::channel(2);
    let (screen_tx, mut screen_rx) = mpsc::channel(2);
    let ingress = MediaIngress::with_screen(
        audio_tx,
        MediaVideoIngress::relay_frames(camera_tx, Arc::default()),
        MediaVideoIngress::relay_frames(screen_tx, Arc::default()),
    );
    assert_eq!(ingress.enqueue(video_packet(7, false, 1).into()), 0);
    ingress.screen_sharing.store(true, Ordering::Release);
    assert_eq!(ingress.enqueue(video_packet(7, true, 2).into()), 0);
    ingress.screen_sharing.store(false, Ordering::Release);
    assert_eq!(ingress.enqueue(video_packet(7, true, 3).into()), 0);
    assert_eq!(
        screen_rx.try_recv().unwrap().packets,
        vec![video_packet(7, true, 2)]
    );
    assert_eq!(
        camera_rx.try_recv().unwrap().packets,
        vec![video_packet(7, false, 1), video_packet(7, true, 3)]
    );
}

#[tokio::test]
async fn blocked_screen_writer_does_not_hold_audio_or_camera() {
    let peer = [0xd4; 32];
    let cipher = Arc::new(cipher_for_test(&peer, &[1; 32], &[2; 32]).unwrap());
    let receiver = cipher_for_test(&peer, &[2; 32], &[1; 32]).unwrap();
    let (audio_tx, audio_rx) = mpsc::channel(2);
    let (camera_tx, camera_rx) = mpsc::channel(2);
    let (screen_tx, screen_rx) = mpsc::channel(2);
    let (sent_tx, mut sent_rx) = mpsc::channel(2);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let mut entered = Some(entered_tx);
    let batching = Arc::new(AtomicU8::new(MEDIA_BATCHING_OFF));
    let screen_task = tokio::spawn(drain_media_packets_on_plane(
        screen_rx,
        Arc::clone(&batching),
        Arc::clone(&cipher),
        false,
        Some(LocalMediaPlane::Screen),
        move |_| {
            entered.take().unwrap().send(()).unwrap();
            std::future::pending::<bool>()
        },
    ));
    let spawn = |rx, plane| {
        let sent_tx = sent_tx.clone();
        tokio::spawn(drain_media_packets_on_plane(
            rx,
            Arc::clone(&batching),
            Arc::clone(&cipher),
            false,
            Some(plane),
            move |cell| {
                let tx = sent_tx.clone();
                async move {
                    tx.send(cell.sealed.into_vec()).await.unwrap();
                    true
                }
            },
        ))
    };
    let audio_task = spawn(audio_rx, LocalMediaPlane::Primary);
    let camera_task = spawn(camera_rx, LocalMediaPlane::Secondary);
    screen_tx
        .send(video_packet(1, true, 1).into())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), entered_rx)
        .await
        .unwrap()
        .unwrap();
    let audio = vec![0x80, 111, 1, 2];
    let camera = video_packet(2, true, 2);
    audio_tx.send(audio.clone().into()).await.unwrap();
    camera_tx.send(camera.clone().into()).await.unwrap();
    let mut received = Vec::new();
    for _ in 0..2 {
        let cell = tokio::time::timeout(Duration::from_secs(1), sent_rx.recv())
            .await
            .unwrap()
            .unwrap();
        received.push(receiver.open(&cell).unwrap());
    }
    screen_task.abort();
    assert!(screen_task.await.unwrap_err().is_cancelled());
    drop((audio_tx, camera_tx, screen_tx));
    audio_task.await.unwrap();
    camera_task.await.unwrap();
    assert!(received.contains(&audio) && received.contains(&camera));
}

fn send_video_control_when_available(id: u64, packet: &[u8]) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let rc =
            unsafe { veil_media_send_video_control_datagram(id, packet.as_ptr(), packet.len()) };
        if rc != 1 || Instant::now() >= deadline {
            return rc;
        }
        std::thread::yield_now();
    }
}

#[test]
fn video_control_accepts_only_complete_rtcp_compounds() {
    let rr = [0x80, 201, 0, 1, 1, 2, 3, 4];
    assert!(media_is_rtcp(&rr));
    assert!(media_is_rtcp(&[rr, rr].concat()));
    for packet in [
        vec![],
        vec![0x80, 201],
        vec![0x80, 201, 0, 2, 1, 2, 3, 4],
        vec![0x80, 111, 0, 1, 1, 2, 3, 4],
        vec![0x80, 224, 0, 1, 1, 2, 3, 4],
        vec![0xa0, 201, 0, 1, 1, 2, 3, 0],
        vec![0xa0, 201, 0, 1, 1, 2, 3, 5],
        [vec![0xa0, 201, 0, 1, 1, 2, 3, 4], rr.to_vec()].concat(),
    ] {
        assert!(!media_is_rtcp(&packet), "malformed control: {packet:?}");
    }
}

#[tokio::test]
async fn video_control_backpressure_never_falls_into_audio() {
    let (audio, mut audio_rx) = mpsc::channel(2);
    let (camera, mut camera_rx) = mpsc::channel(1);
    let (screen, mut screen_rx) = mpsc::channel(1);
    let ingress = MediaIngress::with_screen(
        audio,
        MediaVideoIngress::Packets(camera),
        MediaVideoIngress::Packets(screen),
    );
    let (id, _) = register_test_ingress(Arc::clone(&ingress), [0xe6; 32]);
    let rr = [0x80, 201, 0, 1, 1, 2, 3, 4];
    assert_eq!(send_video_control_when_available(id, &rr), 0);
    assert_eq!(
        unsafe { veil_media_send_video_control_datagram(id, rr.as_ptr(), rr.len()) },
        1
    );
    assert_eq!(veil_media_channel_set_screen_sharing(id, 1), 0);
    assert_eq!(send_video_control_when_available(id, &rr), 0);
    assert_eq!(
        unsafe { veil_media_send_video_control_datagram(id, rr.as_ptr(), rr.len()) },
        1
    );
    assert_eq!(send_when_registry_available(id, &[0x80, 111, 1, 2]), 0);
    assert_eq!(send_when_registry_available(id, &rr), 0);
    assert_eq!(audio_rx.try_recv().unwrap().payload, [0x80, 111, 1, 2]);
    assert_eq!(audio_rx.try_recv().unwrap().payload, rr);
    assert!(audio_rx.try_recv().is_err());
    assert_eq!(camera_rx.try_recv().unwrap().payload, rr);
    assert_eq!(screen_rx.try_recv().unwrap().payload, rr);
    assert_eq!(
        unsafe { veil_media_send_video_control_datagram(id, rr.as_ptr(), 3) },
        -1
    );
    unsafe { veil_media_close_channel(id) };
    assert_eq!(send_video_control_when_available(id, &rr), -1);
    assert_eq!(ingress.enqueue_video_control(rr.to_vec().into()), -1);
}

#[tokio::test]
async fn relay_video_control_cannot_consume_partial_frame_or_audio_capacity() {
    let (audio, mut audio_rx) = mpsc::channel(1);
    let (video, mut video_rx) = mpsc::channel(3);
    let stats = Arc::new(RelayMediaStats::default());
    let ingress = MediaIngress::new(
        audio,
        MediaVideoIngress::relay_frames(video, Arc::clone(&stats)),
    );
    assert_eq!(ingress.enqueue(vec![0x80, 111, 1, 2].into()), 0);
    assert_eq!(ingress.enqueue(video_packet(7, false, 1).into()), 0);
    let rr = vec![0x80, 201, 0, 1, 1, 2, 3, 4];
    assert_eq!(ingress.enqueue_video_control(rr.clone().into()), 0);
    assert_eq!(ingress.enqueue(video_packet(7, true, 2).into()), 0);
    assert_eq!(video_rx.try_recv().unwrap().packets, vec![rr]);
    assert_eq!(
        video_rx.try_recv().unwrap().packets,
        vec![video_packet(7, false, 1), video_packet(7, true, 2)]
    );
    assert_eq!(audio_rx.try_recv().unwrap().payload, [0x80, 111, 1, 2]);
    assert!(audio_rx.try_recv().is_err());
    assert_eq!(stats.snapshot().video_frames_enqueued, 2);
}

#[tokio::test]
async fn complete_relay_frames_reach_the_batch_sink_as_independent_work_items() {
    let peer = [0x71; 32];
    let cipher = Arc::new(cipher_for_test(&peer, &[1; 32], &[2; 32]).unwrap());
    let receiver = cipher_for_test(&peer, &[2; 32], &[1; 32]).unwrap();
    let enqueued_at = Instant::now();
    let (tx, rx) = mpsc::channel(2);
    let first = vec![
        video_packet(7, false, 1),
        video_packet(7, false, 2),
        video_packet(7, true, 3),
    ];
    let second = vec![video_packet(8, true, 4)];
    for packets in [&first, &second] {
        tx.try_send(RelayVideoFrame {
            packets: packets.clone(),
            enqueued_at,
        })
        .unwrap();
    }
    drop(tx);
    let (sink, mut groups) = mpsc::unbounded_channel();
    drain_relay_video_batches_on_plane(
        rx,
        Arc::new(AtomicU8::new(MEDIA_BATCHING_OFF)),
        cipher,
        Arc::new(RelayMediaStats::default()),
        LocalMediaPlane::Secondary,
        move |cells| {
            sink.send(cells).unwrap();
            async { true }
        },
    )
    .await;
    for expected in [first, second] {
        let actual = groups.try_recv().unwrap();
        assert_eq!(actual.len(), expected.len());
        for (sealed, packet) in actual.into_iter().zip(expected) {
            assert_eq!(
                sealed.local_deadline(),
                Some(tokio::time::Instant::from_std(enqueued_at) + MEDIA_LOCAL_QUEUE_AGE)
            );
            assert_eq!(receiver.open(sealed.as_bytes()), Some(packet));
        }
    }
    assert!(groups.try_recv().is_err());
}

#[tokio::test]
async fn audio_feedback_overflow_and_writer_stall_never_enter_audio_or_video() {
    let (audio_tx, mut audio_rx) = mpsc::channel(1);
    let (video_tx, mut video_rx) = mpsc::channel(1);
    let (feedback_tx, mut feedback_rx) = mpsc::channel(1);
    let ingress = MediaIngress::new(audio_tx, MediaVideoIngress::Packets(video_tx));
    *ingress.feedback_tx.write().unwrap() = Some(feedback_tx);
    let feedback = vec![0x80, 201, 0, 1, 0, 0, 0, 7];
    assert_eq!(ingress.enqueue(feedback.clone().into()), 0);
    assert_eq!(ingress.enqueue(feedback.clone().into()), 1);
    assert!(audio_rx.try_recv().is_err());
    assert!(video_rx.try_recv().is_err());
    let audio = vec![0x80, 111, 0, 1];
    assert_eq!(ingress.enqueue(audio.clone().into()), 0);
    assert_eq!(audio_rx.recv().await.unwrap().payload, audio);
    assert_eq!(feedback_rx.recv().await.unwrap().payload, feedback);
    let guard = ingress.feedback_tx.write().unwrap();
    assert_eq!(ingress.enqueue(vec![0x80, 201, 0, 1, 0, 0, 0, 7].into()), 1);
    assert_eq!(ingress.enqueue(vec![0x80, 111, 0, 2].into()), 0);
    drop(guard);
    ingress.closed.store(true, Ordering::Release);
    assert_eq!(
        ingress.enqueue(vec![0x80, 201, 0, 1, 0, 0, 0, 7].into()),
        -1
    );
}

#[tokio::test(start_paused = true)]
async fn feedback_pump_preserves_rtcp_and_original_deadline_without_audio_wait() {
    let peer = [0xe7; 32];
    let cipher = Arc::new(cipher_for_test(&peer, &[0x41; 32], &[0x42; 32]).unwrap());
    let remote = cipher_for_test(&peer, &[0x42; 32], &[0x41; 32]).unwrap();
    let (tx, rx) = mpsc::channel(2);
    let (sent_tx, mut sent_rx) = mpsc::channel(2);
    let deadline = tokio::time::Instant::now() + MEDIA_LOCAL_QUEUE_AGE;
    let packet = vec![0x80, 201, 0, 1, 0, 0, 0, 7];
    tx.send(QueuedMediaPacket {
        payload: packet.clone(),
        deadline,
    })
    .await
    .unwrap();
    let task = tokio::spawn(drain_media_packets_on_plane(
        rx,
        Arc::new(AtomicU8::new(MEDIA_BATCHING_OFF)),
        cipher,
        false,
        Some(LocalMediaPlane::Primary),
        move |cell| {
            let sent_tx = sent_tx.clone();
            async move {
                sent_tx.send(cell).await.unwrap();
                true
            }
        },
    ));
    let sealed = sent_rx.recv().await.unwrap().sealed;
    assert_eq!(sealed.local_deadline(), Some(deadline));
    assert_eq!(remote.open(sealed.as_bytes()).unwrap(), packet);
    tokio::time::advance(Duration::from_millis(201)).await;
    tx.send(QueuedMediaPacket {
        payload: vec![0x80, 201, 0, 1, 0, 0, 0, 8],
        deadline,
    })
    .await
    .unwrap();
    drop(tx);
    task.await.unwrap();
    assert!(sent_rx.try_recv().is_err());
}
