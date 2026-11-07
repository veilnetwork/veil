use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::timeout;

#[test]
fn record_trace_observes_real_io_without_claiming_remote_ack() {
    const CHILD: &str = "VEIL_TEST_ORDERED_TRACE";
    if let Ok(enabled) = std::env::var(CHILD) {
        static EVENTS: Mutex<Vec<String>> = Mutex::new(Vec::new());
        struct Sink;
        impl log::Log for Sink {
            fn enabled(&self, _: &log::Metadata<'_>) -> bool {
                true
            }
            fn log(&self, r: &log::Record<'_>) {
                if r.target().ends_with("ordered_record_trace") {
                    EVENTS.lock().unwrap().push(r.args().to_string());
                }
            }
            fn flush(&self) {}
        }
        static SINK: Sink = Sink;
        log::set_logger(&SINK).unwrap();
        log::set_max_level(log::LevelFilter::Info);
        let enabled = enabled == "1";
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                timeout(Duration::from_secs(3), async {
                    let (left, right) = tokio::io::duplex(8192);
                    let a = OrderedRecordPlane::new(Box::new(left));
                    let ah = a.handle();
                    assert_eq!(ah.local_trace_id() != 0, enabled);
                    assert_eq!(ah.local_trace_id(), ah.clone().local_trace_id());
                    let payload = b"PRIVATE_SYNTHETIC_RECORD";
                    ah.send(payload).unwrap();
                    while ah.progress().completed_records != 1 {
                        tokio::task::yield_now().await;
                    }
                    // Model a record that expired while queued. Exercise the
                    // actual writer, not an invented successful send result.
                    let stale = b"PRIVATE_EXPIRED_RECORD";
                    let mut wire = (stale.len() as u16).to_be_bytes().to_vec();
                    wire.extend_from_slice(stale);
                    let permit =
                        ah.0.capacity
                            .clone()
                            .try_acquire_many_owned(record_queue_charge(stale.len()) as u32)
                            .unwrap();
                    let past = Instant::now() - Duration::from_secs(1);
                    ah.0.outgoing
                        .send(Record {
                            wire,
                            queued_at: past,
                            expires_at: past,
                            _bytes: permit,
                        })
                        .unwrap();
                    while ah.progress().expired_records != 1 {
                        tokio::task::yield_now().await;
                    }
                    let before_reader = EVENTS.lock().unwrap().clone();
                    // The peer has not even started its read task. Local flush
                    // completion cannot be counted as remote delivery or an ACK.
                    if enabled {
                        assert!(before_reader.iter().any(|s| s.contains("stage=flushed ")));
                        assert!(
                            !before_reader
                                .iter()
                                .any(|s| s.contains("stage=read_complete "))
                        );
                    }
                    let b = OrderedRecordPlane::new(Box::new(right));
                    let bh = b.handle();
                    assert_eq!(bh.recv().await.unwrap(), payload);
                    if enabled {
                        assert_ne!(ah.local_trace_id(), bh.local_trace_id());
                    }
                    let rows = EVENTS.lock().unwrap().clone();
                    if enabled {
                        let digest = trace::fingerprint(payload).unwrap();
                        let stale_digest = trace::fingerprint(stale).unwrap();
                        assert!(
                            rows.iter()
                                .any(|s| s.contains("stage=expired_before_write ")
                                    && s.contains(&stale_digest))
                        );
                        assert!(
                            !rows
                                .iter()
                                .any(|s| s.contains("stage=flushed ") && s.contains(&stale_digest))
                        );
                        for stage in [
                            "send_admitted",
                            "write_start",
                            "first_write",
                            "flushed",
                            "read_complete",
                        ] {
                            assert!(
                                rows.iter().any(|s| s.contains(&format!("stage={stage} "))
                                    && s.contains(&format!("record_sha256={digest}"))),
                                "missing {stage}"
                            );
                        }
                        for row in rows {
                            assert!(!row.contains("PRIVATE_"));
                            assert!(!row.contains("ack="));
                            assert!(!row.contains("peer="));
                        }
                        assert!(trace::fingerprint(&[]).is_none());
                        assert!(trace::fingerprint(&vec![0; MAX_RECORD_BYTES + 1]).is_none());
                    } else {
                        assert!(rows.is_empty());
                        assert!(trace::fingerprint(payload).is_none());
                    }
                })
                .await
                .unwrap();
            });
        return;
    }
    for value in ["0", "1", "invalid"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ordered_records::tests::record_trace_observes_real_io_without_claiming_remote_ack",
                "--nocapture",
            ])
            .env(CHILD, value)
            .env("VEIL_DIAG_ORDERED_RECORDS", value)
            .output()
            .unwrap();
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("running 1 test")
                && String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

struct ObservedRead {
    stream: DuplexStream,
    bytes: Arc<std::sync::atomic::AtomicUsize>,
}

impl tokio::io::AsyncRead for ObservedRead {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = std::pin::Pin::new(&mut self.stream).poll_read(cx, buffer);
        self.bytes.fetch_add(
            buffer.filled().len() - before,
            std::sync::atomic::Ordering::Release,
        );
        result
    }
}

impl tokio::io::AsyncWrite for ObservedRead {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[tokio::test(start_paused = true)]
async fn incomplete_incoming_record_expires_from_first_byte_without_retiring_other_children() {
    for prefix in [&[0][..], &[0, 3][..], &[0, 3, b'o'][..]] {
        let (stream, mut peer) = tokio::io::duplex(4096);
        let bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let plane = OrderedRecordPlane::new(Box::new(ObservedRead {
            stream,
            bytes: bytes.clone(),
        }));
        let h = plane.handle();
        // Idle time must not start the incomplete-record budget.
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert!(!h.is_closed());
        peer.write_all(prefix).await.unwrap();
        until(|| bytes.load(std::sync::atomic::Ordering::Acquire) == prefix.len()).await;
        tokio::time::sleep(RECORD_RECEIVE_MAX_AGE).await;
        timeout(Duration::from_millis(1), h.closed())
            .await
            .expect("incomplete record retained a live child beyond its receive budget");
        assert_eq!(h.progress().close_reason, RecordCloseReason::ReadTimeout);
        assert_eq!(h.progress().received_records, 0);
        assert_eq!(
            h.send(b"must not reuse partial framing"),
            Err(RecordSendError::Closed)
        );
        assert!(h.recv().await.is_err());
        until(|| plane.tasks.iter().all(|task| task.is_finished())).await;

        let (other, mut other_peer) = tokio::io::duplex(4096);
        let other = OrderedRecordPlane::new(Box::new(other));
        other_peer.write_all(&[0, 2, b'o', b'k']).await.unwrap();
        assert_eq!(other.handle().recv().await.unwrap(), b"ok");
        assert!(!other.handle().is_closed());
    }
}

#[tokio::test(start_paused = true)]
async fn incoming_trickle_does_not_restart_the_record_budget() {
    let (stream, mut peer) = tokio::io::duplex(4096);
    let bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let plane = OrderedRecordPlane::new(Box::new(ObservedRead {
        stream,
        bytes: bytes.clone(),
    }));
    let h = plane.handle();
    peer.write_all(&[0]).await.unwrap();
    until(|| bytes.load(std::sync::atomic::Ordering::Acquire) == 1).await;
    tokio::time::sleep(RECORD_RECEIVE_MAX_AGE / 2).await;
    peer.write_all(&[3, b'o']).await.unwrap();
    until(|| bytes.load(std::sync::atomic::Ordering::Acquire) == 3).await;
    tokio::time::sleep(RECORD_RECEIVE_MAX_AGE / 2).await;
    timeout(Duration::from_millis(1), h.closed())
        .await
        .expect("header/body progress restarted the original record deadline");
    assert_eq!(h.progress().received_records, 0);
}

#[tokio::test(start_paused = true)]
async fn fragmented_incoming_record_keeps_first_byte_age_and_idle_children_remain_usable() {
    let (stream, mut peer) = tokio::io::duplex(4096);
    let bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let plane = OrderedRecordPlane::new(Box::new(ObservedRead {
        stream,
        bytes: bytes.clone(),
    }));
    let h = plane.handle();
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert!(!h.is_closed());
    let before_first = Instant::now();
    peer.write_all(&[0]).await.unwrap();
    until(|| bytes.load(std::sync::atomic::Ordering::Acquire) == 1).await;
    let after_first = Instant::now();
    tokio::time::sleep(RECORD_RECEIVE_MAX_AGE / 2).await;
    peer.write_all(&[3, b'o', b'l', b'd']).await.unwrap();
    until(|| h.progress().received_records == 1).await;
    {
        let q = h.0.incoming.lock().unwrap();
        let age_origin = q.records.front().unwrap().queued_at;
        assert!(
            age_origin >= before_first && age_origin <= after_first,
            "completed assembly renewed the receive residence budget"
        );
    }
    assert_eq!(h.recv().await.unwrap(), b"old");
    tokio::time::sleep(Duration::from_secs(20)).await;
    peer.write_all(&[0, 2, b'o', b'k']).await.unwrap();
    assert_eq!(h.recv().await.unwrap(), b"ok");
    assert_eq!(h.progress().received_records, 2);
    assert!(!h.is_closed());
}

struct FaultStream {
    read_error: Option<io::ErrorKind>,
    write_error: Option<io::ErrorKind>,
    write_zero: bool,
    read_polled: Arc<std::sync::atomic::AtomicBool>,
}

impl tokio::io::AsyncRead for FaultStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.read_polled
            .store(true, std::sync::atomic::Ordering::Release);
        match self.read_error {
            Some(kind) => std::task::Poll::Ready(Err(io::Error::new(kind, "PRIVATE_IO_CANARY"))),
            None => std::task::Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for FaultStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match self.write_error {
            Some(kind) => std::task::Poll::Ready(Err(io::Error::new(kind, "PRIVATE_IO_CANARY"))),
            None if self.write_zero => std::task::Poll::Ready(Ok(0)),
            None => std::task::Poll::Pending,
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn first_io_failure_is_typed_and_survives_teardown_without_error_text() {
    for (read_error, write_error, write_zero, expected) in [
        (
            Some(io::ErrorKind::ConnectionReset),
            None,
            false,
            RecordCloseReason::ReadError,
        ),
        // An InvalidData error from an encrypted transport is not evidence
        // that the local two-byte record length parser rejected a record.
        (
            Some(io::ErrorKind::InvalidData),
            None,
            false,
            RecordCloseReason::ReadError,
        ),
        (
            None,
            Some(io::ErrorKind::BrokenPipe),
            false,
            RecordCloseReason::WriteError,
        ),
        (None, None, true, RecordCloseReason::WriteZero),
    ] {
        let plane = OrderedRecordPlane::new(Box::new(FaultStream {
            read_error,
            write_error,
            write_zero,
            read_polled: Arc::default(),
        }));
        let h = plane.handle();
        h.send(b"opaque").unwrap();
        timeout(Duration::from_secs(1), h.closed()).await.unwrap();
        until(|| plane.tasks.iter().all(|task| task.is_finished())).await;
        assert_eq!(h.progress().close_reason, expected);
        h.close();
        drop(plane);
        assert_eq!(h.progress().close_reason, expected);
        assert!(!format!("{:?}", h.progress()).contains("PRIVATE_IO_CANARY"));
    }
}

#[tokio::test]
async fn cancelled_reader_retains_a_terminal_cause_and_wakes_other_half() {
    let polled: Arc<std::sync::atomic::AtomicBool> = Arc::default();
    let plane = OrderedRecordPlane::new(Box::new(FaultStream {
        read_error: None,
        write_error: None,
        write_zero: false,
        read_polled: polled.clone(),
    }));
    let h = plane.handle();
    until(|| polled.load(std::sync::atomic::Ordering::Acquire)).await;
    plane.tasks[0].abort();
    timeout(Duration::from_secs(1), h.closed()).await.unwrap();
    until(|| plane.tasks.iter().all(|task| task.is_finished())).await;
    assert_eq!(h.progress().close_reason, RecordCloseReason::TaskEnded);
    drop(plane);
    assert_eq!(h.progress().close_reason, RecordCloseReason::TaskEnded);
}

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
    assert_eq!(left.progress().close_reason, RecordCloseReason::Open);
    assert_eq!(right.progress().close_reason, RecordCloseReason::Open);
}

#[tokio::test]
async fn queued_expiry_skips_unsent_records_and_preserves_the_live_child() {
    let (mut a, mut peer) = tokio::io::duplex(1);
    // Hold every record before its first byte. Unlike a partial expired
    // prefix, these can be skipped safely on this same connection.
    a.write_all(b"x").await.unwrap();
    let plane = OrderedRecordPlane::new(Box::new(a));
    let h = plane.handle();
    for _ in 0..5 {
        h.send_before(b"obsolete", Instant::now() + Duration::from_millis(30))
            .unwrap();
    }
    h.send(b"fresh").unwrap();
    until(|| h.progress().expired_records == 5).await;
    assert!(h.max_size().is_some());
    assert_eq!(h.progress().close_reason, RecordCloseReason::Open);
    assert_eq!(peer.read_u8().await.unwrap(), b'x');
    assert_eq!(raw_record(&mut peer).await, b"fresh");
    until(|| h.progress().completed_records == 1 && h.progress().expired_records == 5).await;
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
        let expected = if wire.len() == 2 {
            RecordCloseReason::InvalidRecord
        } else {
            RecordCloseReason::ReadEof
        };
        assert_eq!(h.progress().close_reason, expected);
        // Teardown of either half and a later owner drop cannot replace the
        // initiating cause with the generic close observed by the other half.
        h.close();
        drop(plane);
        assert_eq!(h.progress().close_reason, expected);
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
    assert_eq!(h.progress().close_reason, RecordCloseReason::OwnerClosed);
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
    assert_eq!(h.progress().close_reason, RecordCloseReason::WriteTimeout);
}

#[tokio::test]
async fn partial_record_expiry_retires_only_its_child_and_a_fresh_child_can_deliver() {
    let (a, mut peer) = tokio::io::duplex(1);
    let plane = OrderedRecordPlane::new(Box::new(a));
    let h = plane.handle();
    h.send_before(&[0x42; 64], Instant::now() + Duration::from_millis(40))
        .unwrap();
    // A real prefix entered the transport, so skipping this record and using
    // its old connection for another prefix would corrupt the framing.
    assert_eq!(peer.read_u8().await.unwrap(), 0);
    h.send(b"must not follow the partial record").unwrap();

    let (left, right) = tokio::io::duplex(4096);
    let survivor = OrderedRecordPlane::new(Box::new(left));
    let survivor_peer = OrderedRecordPlane::new(Box::new(right));
    survivor.handle().send(b"independent child").unwrap();
    assert_eq!(
        timeout(Duration::from_millis(100), survivor_peer.handle().recv())
            .await
            .unwrap()
            .unwrap(),
        b"independent child"
    );
    timeout(Duration::from_millis(200), h.closed())
        .await
        .expect("partial expired record retained its child beyond its useful lifetime");
    until(|| plane.tasks.iter().all(|task| task.is_finished())).await;
    assert_eq!(h.progress().completed_records, 0);
    assert_eq!(h.progress().expired_records, 1);
    assert_eq!(
        h.progress().close_reason,
        RecordCloseReason::PartialRecordExpired
    );
    assert_eq!(h.0.capacity.available_permits(), RECORD_BUFFER_BYTES);
    assert_eq!(h.send(b"old connection"), Err(RecordSendError::Closed));
    let mut tail = Vec::new();
    timeout(Duration::from_millis(100), peer.read_to_end(&mut tail))
        .await
        .unwrap()
        .unwrap();
    assert!(
        tail.len() < 65,
        "expired record completed or another prefix followed it"
    );

    let (left, right) = tokio::io::duplex(4096);
    let replacement = OrderedRecordPlane::new(Box::new(left));
    let replacement_peer = OrderedRecordPlane::new(Box::new(right));
    replacement.handle().send(b"fresh replacement").unwrap();
    assert_eq!(
        replacement_peer.handle().recv().await.unwrap(),
        b"fresh replacement"
    );
    survivor.handle().send(b"survivor still lives").unwrap();
    assert_eq!(
        survivor_peer.handle().recv().await.unwrap(),
        b"survivor still lives"
    );
}

#[tokio::test]
async fn generic_partial_record_has_the_same_bounded_lifetime_without_a_role_or_deadline() {
    let (a, mut peer) = tokio::io::duplex(1);
    let plane = OrderedRecordPlane::new(Box::new(a));
    let h = plane.handle();
    h.send(&[0x33; 64]).unwrap();
    assert_eq!(peer.read_u8().await.unwrap(), 0);
    timeout(Duration::from_millis(350), h.closed())
        .await
        .expect("generic partial record held its child after the residence budget");
    until(|| plane.tasks.iter().all(|task| task.is_finished())).await;
    assert_eq!(h.0.capacity.available_permits(), RECORD_BUFFER_BYTES);
}

#[tokio::test]
async fn buffered_plaintext_acceptance_does_not_extend_the_flush_deadline() {
    let (a, mut peer) = tokio::io::duplex(1);
    let plane = OrderedRecordPlane::new(Box::new(tokio::io::BufWriter::with_capacity(8192, a)));
    let h = plane.handle();
    h.send_before(&[0x44; 64], Instant::now() + Duration::from_millis(40))
        .unwrap();
    assert_eq!(peer.read_u8().await.unwrap(), 0);
    assert!(h.progress().reserved_bytes >= 66);
    timeout(Duration::from_millis(200), h.closed())
        .await
        .unwrap();
    until(|| plane.tasks.iter().all(|task| task.is_finished())).await;
    assert_eq!(h.progress().completed_records, 0);
    assert_eq!(h.progress().expired_records, 1);
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

#[tokio::test]
async fn residence_maxima_survive_brief_stalls_without_changing_record_service() {
    let (stream, mut peer) = tokio::io::duplex(8);
    let plane = OrderedRecordPlane::new(Box::new(stream));
    let handle = plane.handle();
    let first = vec![0x31; 32];
    let second = vec![0x72; 32];
    handle.send(&first).unwrap();
    handle.send(&second).unwrap();
    until(|| handle.progress().active_record_age.is_some()).await;
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(handle.progress().completed_records, 0);
    assert!(handle.progress().max_write_duration >= Duration::from_millis(40));
    assert_eq!(raw_record(&mut peer).await, first);
    assert_eq!(raw_record(&mut peer).await, second);
    until(|| handle.progress().completed_records == 2).await;
    assert!(handle.progress().max_outgoing_wait >= Duration::from_millis(40));
    assert!(handle.progress().max_write_duration >= Duration::from_millis(40));
    assert_eq!(handle.send_buffer_space(), RECORD_BUFFER_BYTES);
    peer.write_u16(4).await.unwrap();
    peer.write_all(b"held").await.unwrap();
    until(|| handle.progress().received_records == 1).await;
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(handle.recv().await.unwrap(), b"held");
    assert!(handle.progress().max_incoming_residence >= Duration::from_millis(40));
    assert_eq!(handle.progress().incoming_buffered_bytes, 0);
    assert_eq!(handle.progress().expired_records, 0);
    assert_eq!(handle.progress().dropped_incoming_records, 0);
    assert!(!handle.is_closed());
}
