use super::*;
use crate::parallel_binding::ParallelParent;
use tokio::time::{Duration, timeout};
use veil_proto::{AppMsg, FrameFamily, codec::encode_frame, header::FrameHeader};

fn bound_pair(
    capacity: usize,
) -> (
    ParallelParent,
    ParallelParent,
    BoundReliableChannel,
    BoundReliableChannel,
) {
    let a = ParallelParent::new([1; 32], [2; 32], [3; 32]);
    let b = ParallelParent::new([1; 32], [3; 32], [2; 32]);
    let (hello, pending) = a.begin_reliable([4; 32]).unwrap();
    let (ack, b_keys) = b.accept_reliable(&hello, [4; 32]).unwrap();
    let (a_stream, b_stream) = tokio::io::duplex(capacity);
    let ca = pending
        .finish(&ack)
        .unwrap()
        .into_reliable(Box::new(a_stream))
        .unwrap();
    let cb = b_keys.into_reliable(Box::new(b_stream)).unwrap();
    (a, b, ca, cb)
}

fn frame(byte: u8, bytes: usize) -> FrameEnvelope {
    let body = vec![byte; bytes];
    let mut h = FrameHeader::new(FrameFamily::App as u8, AppMsg::AppData as u16);
    h.stream_id = 19;
    h.body_len = body.len() as u32;
    FrameEnvelope::from((
        veil_proto::priority::INTERACTIVE,
        veil_bufpool::pooled_shared_from_vec(encode_frame(&h, &body)),
    ))
}

fn admit(handle: &ReliableFrameHandle, f: FrameEnvelope) -> FrameReceipt {
    match handle.try_send(f) {
        Ok(r) => r,
        Err(_) => panic!("unexpected admission failure"),
    }
}

async fn until(mut condition: impl FnMut() -> bool) {
    timeout(Duration::from_secs(2), async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_uncommitted_reservation_releases_credits_without_consuming_nonce() {
    let (_a, _b, a, b) = bound_pair(64);
    let a = ReliableFrameChannel::new(a);
    let b = ReliableFrameChannel::new(b);
    let handle = a.handle();
    let reserved = handle.try_reserve(&frame(3, 100).frame.1).unwrap();
    assert!(handle.buffered_bytes() > 0);
    drop(reserved);
    assert_eq!(handle.buffered_bytes(), 0);
    let receipt = admit(&handle, frame(4, 100));
    assert_eq!(
        &b.handle().recv().await.unwrap()[HEADER_SIZE..],
        vec![4; 100]
    );
    receipt.wait().await.unwrap();
}

#[tokio::test]
async fn parent_retirement_rejects_a_preexisting_reservation_synchronously() {
    let (parent, _b, a, _peer) = bound_pair(64);
    let a = ReliableFrameChannel::new(a);
    let handle = a.handle();
    let reserved = handle.try_reserve(&frame(3, 100).frame.1).unwrap();
    parent.retire();
    assert!(matches!(
        reserved.commit(frame(3, 100)),
        Err(FrameAdmissionError::Closed(_))
    ));
    assert_eq!(handle.buffered_bytes(), 0);
}

#[tokio::test]
async fn cancelled_receipt_keeps_admitted_frame_and_following_cipher_nonces() {
    timeout(Duration::from_secs(3), async {
        let (_a, _b, a, b) = bound_pair(1);
        let a = ReliableFrameChannel::new(a);
        let b = ReliableFrameChannel::new(b);
        let tx = a.handle();
        let rx = b.handle();
        let first = admit(&tx, frame(1, 2048));
        drop(first); // Cancel the producer's observation after committed admission.
        let second = admit(&tx, frame(2, 2048));
        let third = admit(&tx, frame(3, 2048));
        for n in 1..=3 {
            let plain = rx.recv().await.unwrap();
            assert_eq!(&plain[HEADER_SIZE..], vec![n; 2048]);
        }
        second.wait().await.unwrap();
        third.wait().await.unwrap();
        until(|| tx.buffered_bytes() == 0).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn concurrent_producers_share_one_tx_cipher_without_duplicates_or_nonce_gaps() {
    timeout(Duration::from_secs(3), async {
        let (_a, _b, a, b) = bound_pair(64);
        let a = ReliableFrameChannel::new(a);
        let b = ReliableFrameChannel::new(b);
        let mut producers = tokio::task::JoinSet::new();
        let barrier = Arc::new(tokio::sync::Barrier::new(32));
        for n in 0..32u8 {
            let handle = a.handle();
            let barrier = barrier.clone();
            producers.spawn(async move {
                barrier.wait().await;
                admit(&handle, frame(n, 512)).wait().await.unwrap();
            });
        }
        let mut seen = Vec::new();
        for _ in 0..32 {
            let plain = b.handle().recv().await.unwrap();
            let byte = plain[HEADER_SIZE];
            assert_eq!(&plain[HEADER_SIZE..], vec![byte; 512]);
            seen.push(byte);
        }
        while let Some(producer) = producers.join_next().await {
            producer.unwrap();
        }
        seen.sort_unstable();
        assert_eq!(seen, (0..32u8).collect::<Vec<_>>());
    })
    .await
    .unwrap();
}

struct FlushGate {
    inner: tokio::io::DuplexStream,
    gate: Arc<std::sync::atomic::AtomicBool>,
    waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
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
        // Register before the gate load so a release cannot lose this wakeup.
        *self.waker.lock().unwrap() = Some(cx.waker().clone());
        if self.gate.load(std::sync::atomic::Ordering::Acquire) {
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
async fn endpoint_credit_and_receipt_remain_pending_until_actual_transport_flush() {
    timeout(Duration::from_secs(3), async {
        let parent = ParallelParent::new([1; 32], [2; 32], [3; 32]);
        let peer = ParallelParent::new([1; 32], [3; 32], [2; 32]);
        let (hello, pending) = parent.begin_reliable([4; 32]).unwrap();
        let (ack, keys) = peer.accept_reliable(&hello, [4; 32]).unwrap();
        let (stream, other) = tokio::io::duplex(1024);
        let gate = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waker = Arc::new(std::sync::Mutex::new(None));
        let channel = pending
            .finish(&ack)
            .unwrap()
            .into_reliable(Box::new(FlushGate {
                inner: stream,
                gate: gate.clone(),
                waker: waker.clone(),
            }))
            .unwrap();
        let a = ReliableFrameChannel::new(channel);
        let b = ReliableFrameChannel::new(keys.into_reliable(Box::new(other)).unwrap());
        let credits = Arc::new(Semaphore::new(1));
        let mut f = frame(6, 128);
        f.reliable_credit = Some(credits.clone().try_acquire_owned().unwrap());
        let receipt = admit(&a.handle(), f);
        let completion = tokio::spawn(receipt.wait());
        // Remote consumption proves poll_write accepted the entire frame.
        assert_eq!(
            &b.handle().recv().await.unwrap()[HEADER_SIZE..],
            vec![6; 128]
        );
        assert!(!completion.is_finished());
        assert_eq!(credits.available_permits(), 0);
        assert!(a.handle().buffered_bytes() >= 128);
        gate.store(true, std::sync::atomic::Ordering::Release);
        if let Some(waker) = waker.lock().unwrap().take() {
            waker.wake();
        }
        completion.await.unwrap().unwrap();
        until(|| credits.available_permits() == 1 && a.handle().buffered_bytes() == 0).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn failed_admission_retains_plaintext_and_credit_without_burning_nonce() {
    let (_a, _b, a, b) = bound_pair(1);
    let a = ReliableFrameChannel::new(a);
    let b = ReliableFrameChannel::new(b);
    let tx = a.handle();
    // Largest admissible frame fills the entire actor byte budget.
    let size = MAX_RECORD_BYTES - AEAD_OVERHEAD - HEADER_SIZE;
    let first = admit(&tx, frame(1, size));
    let credit = Arc::new(Semaphore::new(1));
    let mut second = frame(2, 100);
    second.reliable_credit = Some(credit.clone().try_acquire_owned().unwrap());
    let second = match tx.try_send(second) {
        Err(FrameAdmissionError::Full(f)) => f,
        _ => panic!("expected byte saturation"),
    };
    assert_eq!(credit.available_permits(), 0);
    assert_eq!(&second.frame.1[HEADER_SIZE..], vec![2; 100]);
    assert_eq!(
        &b.handle().recv().await.unwrap()[HEADER_SIZE..],
        vec![1; size]
    );
    first.wait().await.unwrap();
    until(|| tx.buffered_bytes() == 0).await;
    let second = admit(&tx, second);
    assert_eq!(
        &b.handle().recv().await.unwrap()[HEADER_SIZE..],
        vec![2; 100]
    );
    second.wait().await.unwrap();
    until(|| credit.available_permits() == 1).await;
}

#[tokio::test]
async fn cancelled_receive_does_not_consume_cipher_nonce_or_record() {
    let (_a, _b, a, b) = bound_pair(64);
    let a = ReliableFrameChannel::new(a);
    let b = ReliableFrameChannel::new(b);
    assert!(
        timeout(Duration::from_millis(10), b.handle().recv())
            .await
            .is_err()
    );
    let receipt = admit(&a.handle(), frame(7, 100));
    assert_eq!(
        &b.handle().recv().await.unwrap()[HEADER_SIZE..],
        vec![7; 100]
    );
    receipt.wait().await.unwrap();
}

#[tokio::test]
async fn malformed_local_frame_is_rejected_before_cipher_advancement() {
    let (_a, _b, a, b) = bound_pair(64);
    let a = ReliableFrameChannel::new(a);
    let b = ReliableFrameChannel::new(b);
    for bytes in [
        vec![0; HEADER_SIZE - 1],
        frame(9, 3).frame.1[..HEADER_SIZE + 1].to_vec(),
    ] {
        let f = FrameEnvelope::from((0, veil_bufpool::pooled_shared_from_vec(bytes)));
        assert!(matches!(
            a.handle().try_send(f),
            Err(FrameAdmissionError::Invalid(_))
        ));
    }
    let r = admit(&a.handle(), frame(4, 12));
    assert_eq!(
        &b.handle().recv().await.unwrap()[HEADER_SIZE..],
        vec![4; 12]
    );
    r.wait().await.unwrap();
}

#[tokio::test]
async fn retirement_aborts_pending_receipts_releases_source_credit_and_rejects_retained_handles() {
    let (a_parent, _b, a, _peer) = bound_pair(1);
    let a = ReliableFrameChannel::new(a);
    let handle = a.handle();
    let credit = Arc::new(Semaphore::new(1));
    let mut f = frame(6, 10000);
    f.reliable_credit = Some(credit.clone().try_acquire_owned().unwrap());
    let receipt = admit(&handle, f);
    a_parent.retire();
    // Assert before the asynchronous transport/actor watchers can run.
    assert!(matches!(
        handle.try_send(frame(8, 12)),
        Err(FrameAdmissionError::Closed(_))
    ));
    assert!(
        timeout(Duration::from_secs(1), receipt.wait())
            .await
            .unwrap()
            .is_err()
    );
    until(|| credit.available_permits() == 1).await;
    assert!(matches!(
        handle.try_send(frame(8, 12)),
        Err(FrameAdmissionError::Closed(_))
    ));
    drop(a);
    assert!(handle.recv().await.is_err());
}

#[tokio::test]
async fn transport_eof_preserves_complete_authenticated_tail_before_terminal_error() {
    let (a_parent, _b, a, b) = bound_pair(4096);
    let mut cipher = SessionCipher::new(a.keys.tx_key(), true);
    let wire = crate::runner::apply_tx_cipher(&frame(5, 100).frame.1, &mut cipher).unwrap();
    let raw = a.handle();
    let incoming = b.handle();
    let b = ReliableFrameChannel::new(b);
    raw.send(&wire).await.unwrap();
    until(|| incoming.progress().received_records == 1).await;
    drop(a);
    drop(a_parent);
    incoming.closed().await;
    // Let the writer observe the EOF before we consume its completed RX tail.
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        &b.handle().recv().await.unwrap()[HEADER_SIZE..],
        vec![5; 100]
    );
    assert!(b.handle().recv().await.is_err());
}

#[tokio::test]
async fn altered_authenticated_header_fails_the_child_without_exposing_plaintext() {
    let (_a, _b, a, b) = bound_pair(4096);
    let mut cipher = SessionCipher::new(a.keys.tx_key(), true);
    let wire = crate::runner::apply_tx_cipher(&frame(5, 100).frame.1, &mut cipher).unwrap();
    let mut altered = wire.to_vec();
    altered[19] ^= 1; // Authenticated stream ID.
    let b = ReliableFrameChannel::new(b);
    a.handle().send(&altered).await.unwrap();
    assert_eq!(
        b.handle().recv().await.unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert!(matches!(
        b.handle().try_send(frame(8, 1)),
        Err(FrameAdmissionError::Closed(_))
    ));
}
