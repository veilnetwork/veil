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
    let timeout = write_with_progress_timeout(&mut writer, b"ab", Duration::from_millis(50))
        .await
        .expect_err("the undrained peer must exhaust the write window");
    assert_eq!(timeout.phase, "write");
    assert_eq!(timeout.written, 1);
}

#[tokio::test]
async fn blocked_buffer_flush_reports_accepted_bytes_without_claiming_delivery() {
    let (stream, _peer) = tokio::io::duplex(1);
    let mut writer = tokio::io::BufWriter::with_capacity(1024, stream);
    let timeout = write_with_progress_timeout(&mut writer, b"buffered", Duration::from_millis(50))
        .await
        .expect_err("flush cannot finish while the peer stops draining");
    assert_eq!(timeout.phase, "flush");
    assert_eq!(timeout.written, b"buffered".len());
}

#[tokio::test]
async fn buffered_final_blob_reaches_peer_without_waiting_for_another_blob() {
    let (stream, mut peer) = tokio::io::duplex(1024);
    let mut buffered = tokio::io::BufWriter::with_capacity(1024, stream);
    write_with_progress_timeout(&mut buffered, b"final blob", Duration::from_secs(1))
        .await
        .unwrap()
        .unwrap();
    let mut received = [0; 10];
    tokio::time::timeout(Duration::from_millis(100), peer.read_exact(&mut received))
        .await
        .expect("accepted bytes were left buffered until a later blob")
        .unwrap();
    assert_eq!(&received, b"final blob");
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
    stalled_primary_preserves_bytes(false).await;
}

#[tokio::test]
async fn buffered_primary_flush_retains_pressure_and_all_bytes() {
    stalled_primary_preserves_bytes(true).await;
}

async fn stalled_primary_preserves_bytes(buffered: bool) {
    use super::{WireBlob, writer_task};
    use crate::local_source_activity::{LocalSourceActivity, NETWORK_CONTROL_BYTES};
    use std::sync::Arc;
    use tokio::io::{AsyncWriteExt, split};
    let activity = Arc::new(LocalSourceActivity::default());
    activity.note(std::time::Instant::now());
    let source = super::local_primary_write::PrimaryWriteState::new(Arc::clone(&activity));
    let (stream, mut peer) = tokio::io::duplex(1);
    let stream: veil_transport::BoxIoStream = if buffered {
        Box::new(tokio::io::BufWriter::with_capacity(1024, stream))
    } else {
        Box::new(stream)
    };
    let (_read, write) = split(stream);
    let (tx, rx) = tokio::sync::mpsc::channel::<WireBlob>(2);
    let writer = tokio::spawn(writer_task(
        write,
        rx,
        None,
        Some(Arc::clone(&source)),
        None,
        Arc::new(veil_observability::NodeLogger::new_noop()),
        "fixture".into(),
    ));
    tx.send(WireBlob {
        bytes: veil_bufpool::pooled_shared_from_vec(b"primary".to_vec()),
        control: false,
        primary_feedback: Some(source.retain()),
    })
    .await
    .unwrap();
    // Use the pressure-only recovery allowance: healthy primaries now always
    // bound reliable DATA, so DATA admission alone cannot prove pressure.
    // No QUIC stats, incoming packets or producer events are available. A
    // pinned blocked partial write itself must publish endpoint pressure.
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let now = std::time::Instant::now();
            assert!(
                activity
                    .admit_network_control(NETWORK_CONTROL_BYTES, now)
                    .is_ok()
            );
            if activity
                .admit_network_control(NETWORK_CONTROL_BYTES, now)
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
            .admit_network_control(NETWORK_CONTROL_BYTES, now)
            .is_ok()
    );
    assert!(
        activity
            .admit_network_control(NETWORK_CONTROL_BYTES, now)
            .is_ok()
    );
}

#[tokio::test]
async fn stalled_neutral_writer_does_not_claim_primary_pressure() {
    use super::{WireBlob, writer_task};
    use crate::local_source_activity::{LocalSourceActivity, NETWORK_CONTROL_BYTES};
    use std::sync::Arc;
    let activity = Arc::new(LocalSourceActivity::default());
    // Another local primary is active. Neutral wire bytes still cannot publish.
    activity.note(std::time::Instant::now());
    let source = super::local_primary_write::PrimaryWriteState::new(Arc::clone(&activity));
    let (stream, mut peer) = tokio::io::duplex(1);
    let stream: veil_transport::BoxIoStream = Box::new(stream);
    let (_read, write) = tokio::io::split(stream);
    let (tx, rx) = tokio::sync::mpsc::channel::<WireBlob>(2);
    let writer = tokio::spawn(writer_task(
        write,
        rx,
        None,
        Some(Arc::clone(&source)),
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
            .admit_network_control(NETWORK_CONTROL_BYTES, now)
            .is_ok()
    );
    assert!(
        activity
            .admit_network_control(NETWORK_CONTROL_BYTES, now)
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
    let activity =
        std::sync::Arc::new(crate::local_source_activity::LocalSourceActivity::default());
    activity.note(std::time::Instant::now());
    let source = super::local_primary_write::PrimaryWriteState::new(activity);
    let _pending = source.retain();
    let (mut writer, _reader) = tokio::io::duplex(1);
    let started = tokio::time::Instant::now();
    assert!(
        super::write_with_source_feedback(
            &mut writer,
            b"blocked",
            Duration::from_millis(500),
            Some(&source)
        )
        .await
        .is_err()
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "feedback renewed the stalled-write deadline"
    );
}

#[tokio::test]
async fn slowly_progressing_primary_still_holds_other_producers() {
    use crate::local_source_activity::{LocalSourceActivity, NETWORK_CONTROL_BYTES};
    use std::sync::Arc;
    let activity = Arc::new(LocalSourceActivity::default());
    activity.note(std::time::Instant::now());
    let source = super::local_primary_write::PrimaryWriteState::new(Arc::clone(&activity));
    let (mut writer, mut reader) = tokio::io::duplex(1);
    let send = tokio::spawn(async move {
        let _lease = source.retain();
        super::write_with_source_feedback(
            &mut writer,
            b"abcdef",
            Duration::from_secs(1),
            Some(&source),
        )
        .await
        .unwrap()
        .unwrap();
        writer
    });
    let receive = tokio::spawn(async move {
        let mut received = Vec::new();
        for _ in 0..6 {
            tokio::time::sleep(Duration::from_millis(60)).await;
            let mut byte = [0];
            reader.read_exact(&mut byte).await.unwrap();
            received.extend(byte);
        }
        received
    });
    tokio::time::sleep(Duration::from_millis(220)).await;
    let now = std::time::Instant::now();
    assert!(
        activity
            .admit_network_control(NETWORK_CONTROL_BYTES, now)
            .is_ok()
    );
    assert!(
        activity
            .admit_network_control(NETWORK_CONTROL_BYTES, now)
            .is_err(),
        "small write progress concealed a delayed primary"
    );
    assert_eq!(receive.await.unwrap(), b"abcdef");
    let _writer = send.await.unwrap();
}
