use super::write_with_progress_timeout;
use std::time::Duration;
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn partial_progress_preserves_blob_beyond_one_idle_timeout() {
    let (mut writer, mut reader) = tokio::io::duplex(1);
    let started = tokio::time::Instant::now();
    let send = tokio::spawn(async move {
        write_with_progress_timeout(&mut writer, b"abcdef", Duration::from_secs(2))
            .await
            .unwrap()
            .unwrap();
        // Retain the transport until the final byte is received.
        writer
    });
    let mut received = Vec::new();
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut byte = [0];
        reader.read_exact(&mut byte).await.unwrap();
        received.extend_from_slice(&byte);
    }
    let _writer = send.await.unwrap();
    assert_eq!(received, b"abcdef");
    assert!(started.elapsed() > Duration::from_secs(2));
}

#[tokio::test]
async fn blocked_partial_write_still_expires_without_progress() {
    let (mut writer, _reader) = tokio::io::duplex(1);
    assert!(
        write_with_progress_timeout(&mut writer, b"ab", Duration::from_millis(50))
            .await
            .is_err()
    );
}

#[test]
fn remote_priority_cannot_select_local_control_admission() {
    use veil_proto::{
        family::{AppMsg, FrameFamily},
        header::FrameHeader,
        priority::{BACKGROUND, BULK, INTERACTIVE, REALTIME},
    };
    let mut h = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppData as u16);
    h.set_priority(REALTIME);
    let frame = veil_proto::encode_header(&h);
    assert!(super::local_control_write(REALTIME, &frame));
    for local in [INTERACTIVE, BULK, BACKGROUND] {
        assert!(!super::local_control_write(local, &frame));
    }
    let raw = veil_bufpool::pooled_shared_from_vec(frame.to_vec());
    let blob = super::WireBlob::from(raw);
    assert!(!blob.control);
    assert!(blob.primary_feedback.is_none());
}

#[tokio::test]
async fn stalled_stream_primary_holds_other_producers_without_losing_bytes() {
    use super::{WireBlob, writer_task};
    use crate::local_source_activity::{LocalSourceActivity, RELIABLE_SECONDARY_BYTES};
    use std::sync::Arc;
    use tokio::io::{AsyncWriteExt, split};
    let activity = Arc::new(LocalSourceActivity::default());
    activity.note(std::time::Instant::now());
    let (stream, mut peer) = tokio::io::duplex(1);
    let stream: veil_transport::BoxIoStream = Box::new(stream);
    let (_read, write) = split(stream);
    let (tx, rx) = tokio::sync::mpsc::channel::<WireBlob>(2);
    let writer = tokio::spawn(writer_task(
        write,
        rx,
        None,
        None,
        Arc::new(veil_observability::NodeLogger::new_noop()),
        "fixture".into(),
    ));
    tx.send(WireBlob {
        bytes: veil_bufpool::pooled_shared_from_vec(b"primary".to_vec()),
        control: false,
        primary_feedback: Some(Arc::clone(&activity)),
    })
    .await
    .unwrap();
    // No QUIC stats, incoming packets or producer events are available. A
    // pinned blocked partial write itself must publish endpoint pressure.
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let now = std::time::Instant::now();
            assert!(
                activity
                    .admit_reliable_secondary(RELIABLE_SECONDARY_BYTES, now)
                    .is_ok()
            );
            if activity
                .admit_reliable_secondary(RELIABLE_SECONDARY_BYTES, now)
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("stalled primary never held a different producer");
    let mut received = [0; 7];
    peer.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"primary");
    // Another frame after the hold proves no writer reset or byte reordering.
    tx.send(WireBlob::from(veil_bufpool::pooled_shared_from_vec(
        b"after".to_vec(),
    )))
    .await
    .unwrap();
    let mut after = [0; 5];
    peer.read_exact(&mut after).await.unwrap();
    assert_eq!(&after, b"after");
    drop(tx);
    writer.await.unwrap();
    peer.shutdown().await.unwrap();
    tokio::time::sleep(crate::local_source_activity::PRESSURE_GRACE).await;
    let now = std::time::Instant::now();
    assert!(
        activity
            .admit_reliable_secondary(RELIABLE_SECONDARY_BYTES, now)
            .is_ok()
    );
    assert!(
        activity
            .admit_reliable_secondary(RELIABLE_SECONDARY_BYTES, now)
            .is_ok()
    );
}

#[tokio::test]
async fn stalled_neutral_writer_does_not_claim_primary_pressure() {
    use super::{WireBlob, writer_task};
    use crate::local_source_activity::{LocalSourceActivity, RELIABLE_SECONDARY_BYTES};
    use std::sync::Arc;
    let activity = Arc::new(LocalSourceActivity::default());
    // Another local primary is active. Neutral wire bytes still cannot publish.
    activity.note(std::time::Instant::now());
    let (stream, mut peer) = tokio::io::duplex(1);
    let stream: veil_transport::BoxIoStream = Box::new(stream);
    let (_read, write) = tokio::io::split(stream);
    let (tx, rx) = tokio::sync::mpsc::channel::<WireBlob>(2);
    let writer = tokio::spawn(writer_task(
        write,
        rx,
        None,
        None,
        Arc::new(veil_observability::NodeLogger::new_noop()),
        "fixture".into(),
    ));
    tx.send(WireBlob::from(veil_bufpool::pooled_shared_from_vec(
        b"neutral".to_vec(),
    )))
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(350)).await;
    let now = std::time::Instant::now();
    assert!(
        activity
            .admit_reliable_secondary(RELIABLE_SECONDARY_BYTES, now)
            .is_ok()
    );
    assert!(
        activity
            .admit_reliable_secondary(RELIABLE_SECONDARY_BYTES, now)
            .is_ok()
    );
    let mut received = [0; 7];
    peer.read_exact(&mut received).await.unwrap();
    assert_eq!(&received, b"neutral");
    drop(tx);
    writer.await.unwrap();
}

#[tokio::test]
async fn pressure_ticks_preserve_the_idle_deadline_for_a_blocked_primary() {
    let activity = crate::local_source_activity::LocalSourceActivity::default();
    activity.note(std::time::Instant::now());
    let (mut writer, _reader) = tokio::io::duplex(1);
    let started = tokio::time::Instant::now();
    assert!(
        super::write_with_source_feedback(
            &mut writer,
            b"blocked",
            Duration::from_millis(500),
            Some(&activity)
        )
        .await
        .is_err()
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "feedback renewed the stalled-write deadline"
    );
}
