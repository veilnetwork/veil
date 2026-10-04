use super::*;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use veil_crypto::session_cipher::SessionCipher;
use veil_proto::{codec::decode_header, family::AppMsg, header::HEADER_SIZE};

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
        let mut body = vec![seq as u8; 2048];
        body[..4].copy_from_slice(&seq.to_le_bytes());
        let mut header = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppData as u16);
        header.body_len = body.len() as u32;
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
                    let seq = u32::from_le_bytes(body[..4].try_into().unwrap());
                    assert_eq!(&body[4..], vec![seq as u8; 2044]);
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
