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
    MEDIA_BATCHING_COMPACT_RELAY, MEDIA_BATCHING_OFF, MEDIA_CHANNELS, MEDIA_NEXT_ID, MediaChannel,
    MediaSenderSlot, MediaVideoIngress, RelayVideoFrame, drain_anonymous_media,
    drain_media_packets, drain_relay_video, media_batched_cells, media_ready_batch,
    veil_media_close_channel, veil_media_send_datagram,
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

#[test]
fn anonymous_batch_preserves_other_producer_and_overflow() {
    let (audio_tx, mut audio_rx) = mpsc::channel(4);
    let (video_tx, mut video_rx) = mpsc::channel(4);
    let audio = vec![0x80, 111, 1, 2, 3, 4];
    let video = video_packet(7, false, 1);
    audio_tx.try_send(audio.clone()).unwrap();
    video_tx.try_send(video.clone()).unwrap();
    video_tx.try_send(video.clone()).unwrap();
    let max_body = 4 + 2 * (2 + video.len());
    let (cell, overflow) = media_ready_batch(video.clone(), &mut video_rx, max_body);
    let cell = cell.unwrap();
    assert!(media_cell_is_video(&cell));
    assert_eq!(
        expand_wire_cells(&[cell]),
        vec![video.clone(), video.clone()]
    );
    assert_eq!(overflow, Some(video));
    assert_eq!(audio_rx.try_recv().unwrap(), audio);
    let (cell, overflow) = media_ready_batch(audio.clone(), &mut audio_rx, max_body);
    assert_eq!(cell, Some(audio));
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
        tx.send(video.clone()).await.unwrap();
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
    audio_tx.send(audio.clone()).await.unwrap();
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
async fn anonymous_audio_continues_during_blocked_video_send_or_warm() {
    for block_warm in [false, true] {
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
            LocalMediaPlane::Secondary,
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
        let video = video_packet(7, true, 1);
        video_tx.send(video.clone()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .unwrap();
        let audio = vec![0x80, 111, 1, 2, 3, 4];
        audio_tx.send(audio.clone()).await.unwrap();
        let cell = tokio::time::timeout(Duration::from_millis(100), received_rx.recv())
            .await
            .expect("anonymous audio must not wait for video")
            .unwrap();
        assert_eq!(receiver.open(&cell), Some(audio));
        release.notify_one();
        let cell = tokio::time::timeout(Duration::from_secs(1), received_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receiver.open(&cell), Some(video));
        drop((audio_tx, video_tx, audio_repair_tx, video_repair_tx));
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
    for plane in [LocalMediaPlane::Primary, LocalMediaPlane::Secondary] {
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
        tx.send(packet.clone()).await.unwrap();
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
    let id = MEDIA_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    MEDIA_CHANNELS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            id,
            MediaChannel {
                tx_hi,
                video: MediaVideoIngress::Packets(tx_video),
                repair_tx: Some([repair_hi, repair_video]),
                peer: [0x8a; 32],
                task: tokio::spawn(std::future::pending()),
                video_task: Some(tokio::spawn(std::future::pending())),
                video_sender: None,
                sender_app_id: None,
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
    let abort_audio = task.abort_handle();
    let abort_video = video_task.abort_handle();
    let (tx_hi, _hi_rx) = mpsc::channel(1);
    let (tx_video, _video_rx) = mpsc::channel(1);
    let id = MEDIA_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    MEDIA_CHANNELS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(
            id,
            MediaChannel {
                tx_hi,
                video: MediaVideoIngress::Packets(tx_video),
                repair_tx: None,
                peer: [0xf3; 32],
                task,
                video_task: Some(video_task),
                video_sender: None,
                sender_app_id: None,
                batching: None,
                cipher: Arc::new(cipher_for_test(&[0xf3; 32], &[1; 32], &[2; 32]).unwrap()),
                relay_stats: None,
                routes: None,
            },
        );
    unsafe { veil_media_close_channel(id) };
    tokio::time::timeout(Duration::from_secs(1), async {
        while !abort_audio.is_finished() || !abort_video.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("close must cancel both pending tasks");
    let packet = [0x80, 111, 1, 2];
    assert_eq!(
        unsafe { veil_media_send_datagram(id, packet.as_ptr(), packet.len()) },
        -1
    );
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
    MEDIA_CHANNELS.lock().unwrap().insert(
        id,
        MediaChannel {
            tx_hi,
            video: MediaVideoIngress::Packets(tx_video),
            repair_tx: None,
            peer,
            task: tokio::spawn(std::future::pending()),
            video_task: None,
            video_sender: None,
            sender_app_id: None,
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
