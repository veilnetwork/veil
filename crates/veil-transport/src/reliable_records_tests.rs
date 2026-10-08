use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn pair(bytes: usize) -> (ReliableRecordPlane, ReliableRecordPlane) {
    let (a, b) = tokio::io::duplex(bytes);
    (
        ReliableRecordPlane::new(Box::new(a)),
        ReliableRecordPlane::new(Box::new(b)),
    )
}

async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("condition must become true");
}

#[tokio::test(start_paused = true)]
async fn stalled_consumer_backpressures_then_delivers_exact_large_history() {
    let (a, b) = pair(128);
    let tx = a.handle();
    let rx = b.handle();
    let source = tx.clone();
    let sending = tokio::spawn(async move {
        for n in 0..64u8 {
            source.send(&vec![n; 4096]).await.unwrap();
        }
    });
    until(|| rx.progress().received_records >= 15).await;
    assert!(!sending.is_finished());
    tokio::time::advance(Duration::from_secs(3)).await;
    assert!(
        !sending.is_finished(),
        "no record lifetime may discard the backlog"
    );
    assert!(rx.progress().incoming_buffered_bytes <= RECORD_BUFFER_BYTES);
    assert!(tx.progress().outgoing_buffered_bytes <= RECORD_BUFFER_BYTES);
    for n in 0..64u8 {
        assert_eq!(rx.recv().await.unwrap(), vec![n; 4096]);
    }
    sending.await.unwrap();
    assert_eq!(tx.progress().completed_records, 64);
    assert_eq!(rx.progress().received_records, 64);
    until(|| tx.progress().outgoing_buffered_bytes == 0).await;
    assert_eq!(rx.progress().incoming_buffered_bytes, 0);
}

#[tokio::test(start_paused = true)]
async fn cancelling_admitted_send_finishes_partial_record_before_next_prefix() {
    let (stream, mut peer) = tokio::io::duplex(1);
    let plane = ReliableRecordPlane::new(Box::new(stream));
    let tx = plane.handle();
    let first = tokio::spawn({
        let tx = tx.clone();
        async move { tx.send(b"first record").await }
    });
    // Exactly one accepted prefix byte, then cancel the caller, not the writer.
    assert_eq!(peer.read_u8().await.unwrap(), 0);
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    tokio::time::advance(Duration::from_secs(3)).await;
    let second = tokio::spawn({
        let tx = tx.clone();
        async move { tx.send(b"second").await }
    });
    assert_eq!(peer.read_u8().await.unwrap(), 12);
    let mut payload = [0; 12];
    peer.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"first record");
    assert_eq!(peer.read_u16().await.unwrap(), 6);
    let mut payload = [0; 6];
    peer.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"second");
    second.await.unwrap().unwrap();
    assert_eq!(tx.progress().completed_records, 2);
}

#[tokio::test]
async fn eof_preserves_complete_queued_records_before_reporting_terminal_error() {
    let (stream, mut peer) = tokio::io::duplex(64);
    let plane = ReliableRecordPlane::new(Box::new(stream));
    let rx = plane.handle();
    peer.write_all(b"\x00\x03one\x00\x03two").await.unwrap();
    peer.shutdown().await.unwrap();
    rx.closed().await;
    assert_eq!(rx.recv().await.unwrap(), b"one");
    assert_eq!(rx.recv().await.unwrap(), b"two");
    assert_eq!(
        rx.recv().await.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof
    );
    assert_eq!(rx.progress().incoming_buffered_bytes, 0);
}

#[tokio::test]
async fn invalid_or_partial_record_never_becomes_application_data() {
    for wire in [b"\x00\x00".as_slice(), b"\xff\xff", b"\x00\x04bad"] {
        let (stream, mut peer) = tokio::io::duplex(64);
        let plane = ReliableRecordPlane::new(Box::new(stream));
        let rx = plane.handle();
        peer.write_all(wire).await.unwrap();
        peer.shutdown().await.unwrap();
        assert!(rx.recv().await.is_err());
        assert_eq!(rx.progress().received_records, 0);
        until(|| rx.progress().incoming_buffered_bytes == 0).await;
    }
}

#[tokio::test]
async fn retiring_owner_wakes_queued_io_and_releases_all_admission_credits() {
    let (stream, _unread_peer) = tokio::io::duplex(1);
    let plane = ReliableRecordPlane::new(Box::new(stream));
    let retained = plane.handle();
    let mut sends = tokio::task::JoinSet::new();
    for _ in 0..128 {
        let tx = retained.clone();
        sends.spawn(async move { tx.send(&[7; 2048]).await });
    }
    let receiving = tokio::spawn({
        let rx = retained.clone();
        async move { rx.recv().await }
    });
    until(|| retained.progress().outgoing_buffered_bytes >= 30 * 2050).await;
    drop(plane);
    assert_eq!(
        receiving.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    while let Some(result) = sends.join_next().await {
        assert!(result.unwrap().is_err());
    }
    until(|| retained.progress().outgoing_buffered_bytes == 0).await;
    assert_eq!(
        retained.send(b"late").await.unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
}

#[tokio::test]
async fn retiring_owner_discards_queued_receive_records_even_with_retained_handle() {
    let (stream, mut peer) = tokio::io::duplex(64);
    let plane = ReliableRecordPlane::new(Box::new(stream));
    let retained = plane.handle();
    peer.write_all(b"\x00\x06secret").await.unwrap();
    until(|| retained.progress().received_records == 1).await;
    drop(plane);
    assert_eq!(
        retained.recv().await.unwrap_err().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert_eq!(retained.progress().incoming_buffered_bytes, 0);
}

#[tokio::test]
async fn saturation_of_one_reliable_connection_does_not_hold_its_sibling() {
    let (bulk, _unread_peer) = pair(1);
    let bulk_tx = bulk.handle();
    let mut sends = tokio::task::JoinSet::new();
    for _ in 0..128 {
        let tx = bulk_tx.clone();
        sends.spawn(async move { tx.send(&[7; 2048]).await });
    }
    until(|| bulk_tx.progress().outgoing_buffered_bytes >= 30 * 2050).await;
    let (other, peer) = pair(64);
    let other_tx = other.handle();
    let peer_rx = peer.handle();
    tokio::time::timeout(Duration::from_millis(250), async {
        other_tx.send(b"independent").await.unwrap();
        assert_eq!(peer_rx.recv().await.unwrap(), b"independent");
    })
    .await
    .unwrap();
    assert!(!sends.is_empty());
    drop(bulk);
    while let Some(result) = sends.join_next().await {
        assert!(result.unwrap().is_err());
    }
}

#[tokio::test]
async fn input_size_bound_is_checked_before_waiting_for_admission() {
    let (a, _b) = pair(1);
    for payload in [Vec::new(), vec![0; MAX_RECORD_BYTES + 1]] {
        assert_eq!(
            a.handle().send(&payload).await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert_eq!(a.handle().progress().outgoing_buffered_bytes, 0);
}

struct FlushGate {
    inner: tokio::io::DuplexStream,
    released: Arc<std::sync::atomic::AtomicBool>,
    wake: Arc<futures::task::AtomicWaker>,
}

impl tokio::io::AsyncRead for FlushGate {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for FlushGate {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.wake.register(cx.waker());
        if self.released.load(Ordering::Acquire) {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        } else {
            std::task::Poll::Pending
        }
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn buffered_acceptance_does_not_complete_send_or_release_credit_before_flush() {
    let (stream, mut peer) = tokio::io::duplex(64);
    let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let wake = Arc::new(futures::task::AtomicWaker::new());
    let plane = ReliableRecordPlane::new(Box::new(FlushGate {
        inner: stream,
        released: released.clone(),
        wake: wake.clone(),
    }));
    let tx = plane.handle();
    let sending = tokio::spawn({
        let tx = tx.clone();
        async move { tx.send(b"buffered").await }
    });
    let mut wire = [0; 10];
    peer.read_exact(&mut wire).await.unwrap();
    assert_eq!(&wire, b"\x00\x08buffered");
    assert!(!sending.is_finished());
    assert_eq!(tx.progress().completed_records, 0);
    assert_eq!(tx.progress().outgoing_buffered_bytes, MIN_RECORD_CHARGE);
    released.store(true, Ordering::Release);
    wake.wake();
    sending.await.unwrap().unwrap();
    until(|| tx.progress().outgoing_buffered_bytes == 0).await;
    assert_eq!(tx.progress().completed_records, 1);
}
