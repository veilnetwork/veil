use super::*;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use veil_crypto::session_cipher::SessionCipher;
use veil_proto::{codec::decode_header, family::AppMsg, header::HEADER_SIZE};

/// Freshness includes the real producer outbox, not just the runner's WRR
/// queue. On recovery, stale source and neutral datagrams must not be replayed
/// on an encrypted stream; reliable data and freshly admitted datagrams remain.
#[tokio::test]
async fn encrypted_stream_recovery_discards_media_aged_in_the_producer_outbox() {
    use veil_anonymity::{circuit_data::CircuitCellBytes, circuit_wire::CircuitDataPayload};
    use veil_proto::{AppRtDataPayload, family::RelayChainMsg};
    use veil_session::priority_queue::LOSSY_REALTIME_MAX_AGE;

    let cell = CircuitCellBytes::new(1024).unwrap();
    let packet = |p: u8, seq: u32| {
        let (family, kind, body) = if p == 1 {
            (
                FrameFamily::RelayChain,
                RelayChainMsg::CircuitDatagram as u16,
                CircuitDataPayload {
                    circuit_id: 4242,
                    seq,
                    ciphertext: vec![seq as u8; cell.get()],
                }
                .encode(cell)
                .unwrap(),
            )
        } else {
            (
                FrameFamily::App,
                AppMsg::AppRtData as u16,
                AppRtDataPayload {
                    src_app_id: [0xa1; 32],
                    app_id: [0xb2; 32],
                    endpoint_id: 13,
                    seq,
                    timestamp_us: 0,
                    marker: 0,
                    payload_type: 0,
                    payload: vec![seq as u8; 128],
                }
                .encode(),
            )
        };
        let mut header = FrameHeader::new(family as u8, kind);
        if p == 1 {
            header.set_priority(veil_proto::priority::INTERACTIVE);
        }
        header.body_len = body.len() as u32;
        let mut frame = encode_header(&header).to_vec();
        frame.extend(body);
        (p, veil_bufpool::pooled_shared_from_vec(frame))
    };
    let (tx, outbox) = veil_session::frame_outbox::frame_channel(16);
    for p in 0..4 {
        tx.try_send(packet(p, p.into())).unwrap();
    }
    let reliable_body = b"reliable before stall";
    let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppData as u16);
    header.body_len = reliable_body.len() as u32;
    let mut reliable = encode_header(&header).to_vec();
    reliable.extend(reliable_body);
    tx.try_send((3, veil_bufpool::pooled_shared_from_vec(reliable)))
        .unwrap();
    tokio::time::sleep(LOSSY_REALTIME_MAX_AGE + Duration::from_millis(60)).await;
    for p in 0..4 {
        tx.try_send(packet(p, 100 + u32::from(p))).unwrap();
    }
    let (_, legacy_rx) = mpsc::channel(1);
    let (stream, mut receiver) = tokio::io::duplex(4096);
    let key = [0x44; 32];
    let mut runner = make_mobility_blackhole_runner(legacy_rx);
    runner.outbox = Some(outbox);
    runner.stream = Box::new(stream);
    runner.crypto.tx_cipher = Some(SessionCipher::new(&key, true));
    let task = tokio::spawn(async move { runner.run().await });
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        let mut cipher = SessionCipher::new(&key, true);
        let mut media = Vec::new();
        let mut reliable = false;
        while media.len() < 4 || !reliable {
            let mut header_bytes = [0; HEADER_SIZE];
            receiver.read_exact(&mut header_bytes).await.unwrap();
            let header = decode_header(&header_bytes).unwrap();
            let mut encrypted = vec![0; header.body_len as usize];
            receiver.read_exact(&mut encrypted).await.unwrap();
            let body = cipher
                .open(&encrypted, &veil_proto::codec::frame_aad(&header))
                .unwrap();
            if header.family == FrameFamily::Session as u8 {
                assert_eq!(header.msg_type, SessionMsg::Padding as u16);
                continue;
            }
            if header.family == FrameFamily::Control as u8 {
                assert_eq!(header.msg_type, ControlMsg::Keepalive as u16);
                continue;
            }
            if header.family == FrameFamily::App as u8 && header.msg_type == AppMsg::AppData as u16
            {
                assert!(!reliable, "reliable frame duplicated");
                assert_eq!(body, reliable_body);
                reliable = true;
                continue;
            }
            let seq = if header.family == FrameFamily::RelayChain as u8 {
                assert_eq!(header.msg_type, RelayChainMsg::CircuitData as u16);
                assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
                let data = CircuitDataPayload::decode(&body).unwrap();
                assert_eq!(data.ciphertext, vec![data.seq as u8; cell.get()]);
                data.seq
            } else {
                assert_eq!(header.family, FrameFamily::App as u8);
                assert_eq!(header.msg_type, AppMsg::AppRtData as u16);
                let data = AppRtDataPayload::decode(&body).unwrap();
                assert_eq!(data.payload, vec![data.seq as u8; 128]);
                data.seq
            };
            media.push(seq);
        }
        media.sort_unstable();
        media
    })
    .await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        result.unwrap(),
        [100, 101, 102, 103],
        "stale outbox media replayed"
    );
}

/// Exercise the real encrypted SessionRunner and its writer channel on a
/// stream-only hop. The receiving endpoint adds uniform pacing to all bytes;
/// it has no application labels or differentiated transport service.
#[tokio::test]
async fn local_source_stream_budget_limits_committed_bulk_and_resumes_without_input() {
    let (tx, rx) = mpsc::channel::<PriorityFrame>(128);
    let primary = || {
        (
            0,
            veil_bufpool::pooled_shared_from_vec(realtime_media_frame()),
        )
    };
    tx.try_send(primary()).unwrap();
    const COUNT: u32 = 64;
    for seq in 0..COUNT {
        let mut data = vec![seq as u8; veil_proto::budget::LOCAL_STREAM_SEGMENT_DATA_BYTES];
        data[..4].copy_from_slice(&seq.to_le_bytes());
        let body = veil_proto::AppDataPayload {
            app_id: [0x71; 32],
            endpoint_id: 9,
            seq: 0,
            data,
        }
        .encode();
        let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppData as u16);
        header.body_len = body.len() as u32;
        header.set_priority(veil_proto::priority::INTERACTIVE);
        let mut frame = encode_header(&header).to_vec();
        frame.extend(body);
        tx.try_send((3, veil_bufpool::pooled_shared_from_vec(frame)))
            .unwrap();
    }
    let (stream, mut receiver) = tokio::io::duplex(4096);
    let key = [0x32; 32];
    let mut runner = make_mobility_blackhole_runner(rx);
    runner.stream = Box::new(stream);
    runner.crypto.tx_cipher = Some(SessionCipher::new(&key, true));
    let task = tokio::spawn(async move { runner.run().await });
    // Leave the reader stopped so the runner can fill its downstream FIFO.
    tokio::time::sleep(Duration::from_millis(40)).await;
    tx.send(primary()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut cipher = SessionCipher::new(&key, true);
        let mut bytes = 0;
        let mut primary_count = 0;
        let mut second_primary_at = None;
        let mut bulk = Vec::new();
        while bulk.len() < COUNT as usize || primary_count < 2 {
            let mut header_bytes = [0u8; HEADER_SIZE];
            receiver.read_exact(&mut header_bytes).await.unwrap();
            let header = decode_header(&header_bytes).unwrap();
            let mut encrypted = vec![0; header.body_len as usize];
            receiver.read_exact(&mut encrypted).await.unwrap();
            bytes += HEADER_SIZE + encrypted.len();
            let body = cipher
                .open(&encrypted, &veil_proto::codec::frame_aad(&header))
                .unwrap();
            if header.family == FrameFamily::App as u8 {
                if header.msg_type == AppMsg::AppRtData as u16 {
                    primary_count += 1;
                    assert_eq!(body, [0xEEu8; 48]);
                    if primary_count == 2 {
                        second_primary_at = Some(bytes);
                    }
                } else {
                    assert_eq!(header.msg_type, AppMsg::AppData as u16);
                    assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
                    assert!(
                        HEADER_SIZE + encrypted.len() <= 4096,
                        "oversized source wire frame"
                    );
                    let segment = veil_proto::AppDataPayload::decode(&body).unwrap();
                    let seq = u32::from_le_bytes(segment.data[..4].try_into().unwrap());
                    assert_eq!(
                        &segment.data[4..],
                        vec![seq as u8; veil_proto::budget::LOCAL_STREAM_SEGMENT_DATA_BYTES - 4]
                    );
                    bulk.push(seq);
                }
            } else {
                assert_eq!(header.family, FrameFamily::Session as u8);
                assert_eq!(header.msg_type, SessionMsg::Padding as u16);
            }
            // Uniform rate limit; no further outbox or inbound traffic arrives.
            tokio::time::sleep(Duration::from_millis(4)).await;
        }
        assert_eq!(
            bulk,
            (0..COUNT).collect::<Vec<_>>(),
            "file order, completeness, no duplicates"
        );
        assert!(
            second_primary_at.unwrap() < 16 * 1024,
            "endpoint committed too much bulk ahead of new primary: {second_primary_at:?}"
        );
    })
    .await;
    task.abort();
    let _ = task.await;
    assert!(
        result.is_ok(),
        "writer capacity did not resume the pending file without external input"
    );
}

/// Real queue admission, encrypted writer and stream fallback. Each local
/// source fits its own lossy budget; a shared 64-frame pool used to discard
/// older primary frames when the second primary burst arrived. The neutral
/// circuit source must also retain its ordinary FIFO and wire priority.
#[tokio::test]
async fn local_lossy_sources_keep_complete_bursts_on_an_encrypted_stream_hop() {
    use veil_anonymity::{circuit_data::CircuitCellBytes, circuit_wire::CircuitDataPayload};
    use veil_proto::{AppRtDataPayload, family::RelayChainMsg};
    use veil_session::priority_queue::LOSSY_REALTIME_MAX_DEPTH;

    const COUNT: u32 = LOSSY_REALTIME_MAX_DEPTH as u32;
    let (tx, rx) = mpsc::channel::<PriorityFrame>(4 * COUNT as usize + 1);
    let app_frame = |seq| {
        let payload = AppRtDataPayload {
            src_app_id: [0xa1; 32],
            app_id: [0xb2; 32],
            endpoint_id: 13,
            seq,
            timestamp_us: 0,
            marker: 0,
            payload_type: 0,
            payload: vec![seq as u8; 128],
        }
        .encode();
        let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppRtData as u16);
        header.body_len = payload.len() as u32;
        let mut frame = encode_header(&header).to_vec();
        frame.extend(payload);
        veil_bufpool::pooled_shared_from_vec(frame)
    };
    // All four sources are queued before the runner's drain pass. No producer
    // needs further input for the writer to finish the admitted bursts.
    for seq in 0..COUNT / 2 {
        tx.try_send((0, app_frame(seq))).unwrap();
    }
    for seq in COUNT / 2..COUNT / 2 + COUNT {
        tx.try_send((2, app_frame(seq))).unwrap();
    }
    for seq in COUNT / 2 + COUNT..COUNT / 2 + 2 * COUNT {
        tx.try_send((3, app_frame(seq))).unwrap();
    }
    let cell = CircuitCellBytes::new(1024).unwrap();
    for seq in 0..COUNT {
        let body = CircuitDataPayload {
            circuit_id: 4242,
            seq,
            ciphertext: vec![seq as u8; cell.get()],
        }
        .encode(cell)
        .unwrap();
        let mut header = FrameHeader::new(
            FrameFamily::RelayChain as u8,
            RelayChainMsg::CircuitDatagram as u16,
        );
        header.set_priority(veil_proto::priority::INTERACTIVE);
        header.body_len = body.len() as u32;
        let mut frame = encode_header(&header).to_vec();
        frame.extend(body);
        tx.try_send((1, veil_bufpool::pooled_shared_from_vec(frame)))
            .unwrap();
    }
    for seq in COUNT / 2 + 2 * COUNT..3 * COUNT {
        tx.try_send((0, app_frame(seq))).unwrap();
    }
    let (stream, mut receiver) = tokio::io::duplex(4096);
    let key = [0x43; 32];
    let mut runner = make_mobility_blackhole_runner(rx);
    runner.stream = Box::new(stream);
    runner.crypto.tx_cipher = Some(SessionCipher::new(&key, true));
    let task = tokio::spawn(async move { runner.run().await });
    let mut sources: [Vec<u32>; 4] = Default::default();
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        let mut cipher = SessionCipher::new(&key, true);
        while sources.iter().map(Vec::len).sum::<usize>() < 4 * COUNT as usize {
            let mut header_bytes = [0u8; HEADER_SIZE];
            receiver.read_exact(&mut header_bytes).await.unwrap();
            let header = decode_header(&header_bytes).unwrap();
            let mut encrypted = vec![0; header.body_len as usize];
            receiver.read_exact(&mut encrypted).await.unwrap();
            let body = cipher
                .open(&encrypted, &veil_proto::codec::frame_aad(&header))
                .unwrap();
            if header.family == FrameFamily::Session as u8 {
                assert_eq!(header.msg_type, SessionMsg::Padding as u16);
                continue;
            }
            if header.family == FrameFamily::Control as u8 {
                assert_eq!(header.msg_type, ControlMsg::Keepalive as u16);
                continue;
            }
            if header.family == FrameFamily::RelayChain as u8 {
                assert_eq!(header.msg_type, RelayChainMsg::CircuitData as u16);
                assert_eq!(header.priority(), veil_proto::priority::INTERACTIVE);
                let circuit = CircuitDataPayload::decode(&body).unwrap();
                assert_eq!(circuit.circuit_id, 4242);
                assert_eq!(circuit.ciphertext, vec![circuit.seq as u8; cell.get()]);
                sources[1].push(circuit.seq);
            } else {
                assert_eq!(header.family, FrameFamily::App as u8);
                assert_eq!(header.msg_type, AppMsg::AppRtData as u16);
                // No local source class is copied into this direct wire frame.
                assert_eq!(header.priority(), veil_proto::priority::REALTIME);
                let data = AppRtDataPayload::decode(&body).unwrap();
                assert_eq!(data.marker, 0);
                assert_eq!(data.payload_type, 0);
                assert_eq!(data.payload, vec![data.seq as u8; 128]);
                let source = if (COUNT / 2..COUNT / 2 + COUNT).contains(&data.seq) {
                    2
                } else if (COUNT / 2 + COUNT..COUNT / 2 + 2 * COUNT).contains(&data.seq) {
                    3
                } else {
                    0
                };
                sources[source].push(data.seq);
            }
        }
        assert_eq!(
            sources[0],
            (0..COUNT / 2)
                .chain(COUNT / 2 + 2 * COUNT..3 * COUNT)
                .collect::<Vec<_>>()
        );
        assert_eq!(sources[1], (0..COUNT).collect::<Vec<_>>());
        assert_eq!(
            sources[2],
            (COUNT / 2..COUNT / 2 + COUNT).collect::<Vec<_>>()
        );
        assert_eq!(
            sources[3],
            (COUNT / 2 + COUNT..COUNT / 2 + 2 * COUNT).collect::<Vec<_>>()
        );
    })
    .await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(
        result.is_ok(),
        "shared lossy admission lost a complete source burst: {result:?}; counts={:?}, primary={:?}",
        sources.each_ref().map(Vec::len),
        sources[0]
    );
}
