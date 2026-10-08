use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::timeout;

async fn raw_record(peer: &mut DuplexStream) -> Vec<u8> {
    timeout(Duration::from_secs(2), async {
        let len = peer.read_u16().await.unwrap() as usize;
        assert!((1..=MAX_RECORD_BYTES).contains(&len));
        let mut bytes = vec![0; len];
        peer.read_exact(&mut bytes).await.unwrap();
        bytes
    })
    .await
    .unwrap()
}

async fn until(mut condition: impl FnMut() -> bool) {
    timeout(Duration::from_secs(2), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn duplex_records_flush_the_last_buffered_record_and_preserve_boundaries() {
    let (a, b) = tokio::io::duplex(4096);
    let a = OrderedRecordPlane::new(Box::new(tokio::io::BufWriter::with_capacity(8192, a)));
    let b = OrderedRecordPlane::new(Box::new(tokio::io::BufWriter::with_capacity(8192, b)));
    let left = a.handle();
    let right = b.handle();
    for bytes in [
        vec![0x42],
        vec![0x33; MAX_RECORD_BYTES],
        b"last record".to_vec(),
    ] {
        left.send(&bytes).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), right.recv())
                .await
                .unwrap()
                .unwrap(),
            bytes
        );
    }
    right.send(b"reply on the same child").unwrap();
    assert_eq!(left.recv().await.unwrap(), b"reply on the same child");
    until(|| left.progress().completed_records == 3 && right.progress().completed_records == 1)
        .await;
    assert_eq!(left.send_buffer_space(), RECORD_BUFFER_BYTES);
    assert_eq!(right.send_buffer_space(), RECORD_BUFFER_BYTES);
}

#[tokio::test]
async fn queued_expiry_preserves_in_flight_bytes_and_skips_only_unsent_records() {
    let (a, mut peer) = tokio::io::duplex(1);
    let plane = OrderedRecordPlane::new(Box::new(a));
    let h = plane.handle();
    h.send_before(&[0x42; 64], Instant::now() + Duration::from_millis(30))
        .unwrap();
    // Prove a partial prefix was actually written before its deadline.
    assert_eq!(peer.read_u8().await.unwrap(), 0);
    for _ in 0..5 {
        h.send_before(b"obsolete", Instant::now() + Duration::from_millis(30))
            .unwrap();
    }
    h.send(b"fresh").unwrap();
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(h.progress().active_record_age.unwrap() >= Duration::from_millis(30));
    assert!(h.progress().reserved_bytes >= 66 + 6 * MIN_RECORD_CHARGE);
    // Expiry must not abandon an already-started record or lose framing.
    assert_eq!(peer.read_u8().await.unwrap(), 64);
    let mut first = [0; 64];
    peer.read_exact(&mut first).await.unwrap();
    assert_eq!(first, [0x42; 64]);
    assert_eq!(raw_record(&mut peer).await, b"fresh");
    until(|| h.progress().completed_records == 2 && h.progress().expired_records == 5).await;
    assert_eq!(h.send_buffer_space(), RECORD_BUFFER_BYTES);
}

#[tokio::test]
async fn deadline_also_applies_while_first_write_is_pending_without_progress() {
    let (mut a, mut peer) = tokio::io::duplex(1);
    // The control byte fills the raw buffer before the plane starts: not a
    // single byte of the expired record can have entered this transport.
    a.write_all(b"x").await.unwrap();
    let plane = OrderedRecordPlane::new(Box::new(a));
    let h = plane.handle();
    h.send_before(b"obsolete", Instant::now() + Duration::from_millis(30))
        .unwrap();
    h.send(b"fresh").unwrap();
    until(|| h.progress().expired_records == 1).await;
    assert_eq!(peer.read_u8().await.unwrap(), b'x');
    assert_eq!(raw_record(&mut peer).await, b"fresh");
    until(|| h.progress().completed_records == 1).await;
}

#[tokio::test]
async fn byte_and_tiny_record_metadata_budgets_include_the_blocked_record() {
    for len in [1, MAX_RECORD_BYTES] {
        let (a, _unread_peer) = tokio::io::duplex(1);
        let plane = OrderedRecordPlane::new(Box::new(a));
        let h = plane.handle();
        let bytes = vec![0; len];
        let charge = (len + 2).max(MIN_RECORD_CHARGE);
        let count = RECORD_BUFFER_BYTES / charge;
        // No await permits the writer to make progress during admission.
        for _ in 0..count {
            h.send(&bytes).unwrap();
        }
        assert_eq!(h.send(&bytes), Err(RecordSendError::Full));
        assert_eq!(h.send_buffer_space(), RECORD_BUFFER_BYTES - count * charge);
        until(|| h.progress().active_record_age.is_some()).await;
        // Dequeue is not completion: the blocked writer still owns its lease.
        assert_eq!(h.send(&bytes), Err(RecordSendError::Full));
        drop(plane);
        until(|| h.0.capacity.available_permits() == RECORD_BUFFER_BYTES).await;
        assert_eq!(h.send(&bytes), Err(RecordSendError::Closed));
        assert_eq!(h.max_size(), None);
    }
}

#[tokio::test]
async fn invalid_or_truncated_record_closes_both_halves_before_dispatch() {
    for wire in [vec![0, 0], vec![0xff, 0xff], vec![0, 10, 1, 2]] {
        let (a, mut peer) = tokio::io::duplex(4096);
        let plane = OrderedRecordPlane::new(Box::new(a));
        let h = plane.handle();
        peer.write_all(&wire).await.unwrap();
        peer.shutdown().await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), h.recv())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert_eq!(h.send(b"reply"), Err(RecordSendError::Closed));
        until(|| plane.tasks.iter().all(|task| task.is_finished())).await;
    }
}

#[tokio::test]
async fn owner_drop_wakes_retained_pending_reads_and_other_planes_survive() {
    let (a, _peer) = tokio::io::duplex(1);
    let plane = OrderedRecordPlane::new(Box::new(a));
    let h = plane.handle();
    let retained = h.clone();
    let mut pending = Box::pin(retained.recv());
    assert!(
        timeout(Duration::from_millis(20), pending.as_mut())
            .await
            .is_err()
    );
    h.send(&[0x42; MAX_RECORD_BYTES]).unwrap();
    until(|| h.progress().active_record_age.is_some()).await;
    drop(plane);
    assert_eq!(
        timeout(Duration::from_secs(1), pending)
            .await
            .unwrap()
            .unwrap_err()
            .kind(),
        io::ErrorKind::ConnectionAborted
    );
    until(|| h.0.capacity.available_permits() == RECORD_BUFFER_BYTES).await;
    let (a, b) = tokio::io::duplex(4096);
    let sibling_a = OrderedRecordPlane::new(Box::new(a));
    let sibling_b = OrderedRecordPlane::new(Box::new(b));
    sibling_a.handle().send(b"other child lives").unwrap();
    assert_eq!(
        sibling_b.handle().recv().await.unwrap(),
        b"other child lives"
    );
}

#[tokio::test]
async fn incomplete_write_timeout_closes_the_whole_plane_without_resuming_framing() {
    let (a, _peer) = tokio::io::duplex(1);
    let plane = OrderedRecordPlane::with_write_timeout(Box::new(a), Duration::from_millis(30));
    let h = plane.handle();
    h.send(b"blocked record").unwrap();
    h.send(b"must never follow a partial record").unwrap();
    timeout(Duration::from_secs(1), h.closed()).await.unwrap();
    assert_eq!(h.send(b"next"), Err(RecordSendError::Closed));
    assert_eq!(h.progress().completed_records, 0);
    until(|| plane.tasks.iter().all(|task| task.is_finished())).await;
    assert_eq!(h.0.capacity.available_permits(), RECORD_BUFFER_BYTES);
}

#[tokio::test]
async fn cancelled_receive_does_not_consume_a_later_complete_record() {
    let (a, mut peer) = tokio::io::duplex(4096);
    let plane = OrderedRecordPlane::new(Box::new(a));
    let h = plane.handle();
    assert!(timeout(Duration::from_millis(20), h.recv()).await.is_err());
    peer.write_all(&[0, 2, b'o', b'k']).await.unwrap();
    assert_eq!(h.recv().await.unwrap(), b"ok");
    assert_eq!(h.send(&[]), Err(RecordSendError::TooLarge));
    assert_eq!(
        h.send(&vec![0; MAX_RECORD_BYTES + 1]),
        Err(RecordSendError::TooLarge)
    );
    assert_eq!(
        h.send_before(b"old", Instant::now()),
        Err(RecordSendError::Expired)
    );
}

#[tokio::test]
async fn incoming_overflow_keeps_the_newest_records_with_the_same_byte_budget() {
    let (a, mut peer) = tokio::io::duplex(256 * 1024);
    let plane = OrderedRecordPlane::with_timeouts(
        Box::new(a),
        Duration::from_secs(30),
        Duration::from_secs(10),
    );
    let h = plane.handle();
    for index in 0..100u8 {
        peer.write_u16(MAX_RECORD_BYTES as u16).await.unwrap();
        peer.write_all(&vec![index; MAX_RECORD_BYTES])
            .await
            .unwrap();
    }
    until(|| h.progress().received_records == 100).await;
    let capacity = RECORD_BUFFER_BYTES / (MAX_RECORD_BYTES + 2);
    assert_eq!(
        h.progress().dropped_incoming_records,
        (100 - capacity) as u64
    );
    assert!(h.progress().incoming_buffered_bytes <= RECORD_BUFFER_BYTES);
    for index in (100 - capacity)..100 {
        assert_eq!(h.recv().await.unwrap(), vec![index as u8; MAX_RECORD_BYTES]);
    }
    assert_eq!(h.progress().incoming_buffered_bytes, 0);
    assert!(timeout(Duration::from_millis(20), h.recv()).await.is_err());
}

#[tokio::test]
async fn incoming_residence_expiry_does_not_return_old_data_after_a_consumer_pause() {
    let (a, mut peer) = tokio::io::duplex(4096);
    let plane = OrderedRecordPlane::with_timeouts(
        Box::new(a),
        Duration::from_secs(30),
        Duration::from_millis(30),
    );
    let h = plane.handle();
    peer.write_all(&[0, 3, b'o', b'l', b'd']).await.unwrap();
    until(|| h.progress().received_records == 1).await;
    tokio::time::sleep(Duration::from_millis(60)).await;
    peer.write_all(&[0, 3, b'n', b'e', b'w']).await.unwrap();
    assert_eq!(h.recv().await.unwrap(), b"new");
    assert_eq!(h.progress().expired_incoming_records, 1);
    assert_eq!(h.progress().incoming_buffered_bytes, 0);
}
