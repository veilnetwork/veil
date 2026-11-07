//! Exercise terminal and ordinary writer shutdown through the real runner.
use super::super::{OwnedWriter, SessionRunner, WireBlob, writer_task};
use super::reliable_source_pressure_quic_tests::make_runner;
use std::{
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

async fn poll_once<F: std::future::Future>(mut future: Pin<&mut F>) -> Poll<F::Output> {
    std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
}

struct LogDir(PathBuf);
impl Drop for LogDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct SilentBlocked {
    writes: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
}
impl AsyncRead for SilentBlocked {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for SilentBlocked {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}
impl Drop for SilentBlocked {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn terminal_keepalive_does_not_pay_the_dead_writers_drain_grace() {
    let directory = LogDir(std::env::temp_dir().join(format!(
        "veil-dead-writer-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    )));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory.0).unwrap();
    let log_path = directory.0.join("runner.log");
    let logger = Arc::new(
        veil_observability::NodeLogger::from_parts(
            veil_types::LogsConfig::File,
            Some(&log_path),
            veil_types::LogLevel::Debug,
            veil_types::LogFormat::Text,
        )
        .unwrap(),
    );
    let writes = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let mut registry = crate::SessionTxRegistry::new();
    let outbox = registry.register([0xB1; 32]);
    assert!(registry.has_session(&[0xB1; 32]));
    let mut runner = make_runner(
        Box::new(SilentBlocked {
            writes: writes.clone(),
            dropped: dropped.clone(),
        }),
        outbox,
        None,
    );
    runner.logger = logger.clone();
    runner.keepalive_interval = Duration::from_secs(1);
    runner.mobile.base_keepalive_interval = Duration::from_secs(1);
    // No EOF, idle-timeout or outbox-close exit can substitute for the tested
    // decision. The 30-s writer timeout also cannot fire in this short fixture.
    assert!(runner.idle_timeout.is_zero());
    let mut run = Box::pin(runner.run());
    let mut reaped = false;
    for _ in 0..50 {
        assert!(
            poll_once(run.as_mut()).await.is_pending(),
            "runner ended before the keepalive decision"
        );
        tokio::task::yield_now().await;
        if std::fs::read_to_string(&log_path)
            .unwrap()
            .contains("session.keepalive.timeout_close")
        {
            reaped = true;
            break;
        }
        tokio::time::advance(Duration::from_millis(100)).await;
    }
    let decision_at = tokio::time::Instant::now();
    // On the current-thread executor this lets the single owned writer process
    // cancellation. No clock advance pays any part of the five-second grace.
    tokio::task::yield_now().await;
    let returned = poll_once(run.as_mut()).await.is_ready();
    let reconnect_still_gated = registry.has_session(&[0xB1; 32]);
    assert_eq!(tokio::time::Instant::now(), decision_at);
    drop(run);
    drop(runner);
    tokio::task::yield_now().await;
    assert!(
        dropped.load(Ordering::SeqCst),
        "fixture left the transport owned by a detached writer"
    );
    assert!(
        reaped,
        "fixture never reached the terminal keepalive decision"
    );
    assert!(
        writes.load(Ordering::SeqCst) > 0,
        "fixture never blocked the production writer"
    );
    assert!(
        returned,
        "dead session still waits for the graceful writer-drain timer"
    );
    assert!(
        !reconnect_still_gated,
        "closed runner still gates the reconnect presence check"
    );
}

#[tokio::test(start_paused = true)]
async fn ordinary_writer_shutdown_still_drains_the_accepted_blob() {
    let (stream, mut peer) = tokio::io::duplex(1);
    let stream: veil_transport::BoxIoStream = Box::new(stream);
    let (_read, write) = tokio::io::split(stream);
    let (tx, rx) = tokio::sync::mpsc::channel::<WireBlob>(1);
    let mut writer = OwnedWriter(tokio::spawn(writer_task(
        write,
        rx,
        None,
        None,
        None,
        Arc::new(veil_observability::NodeLogger::new_noop()),
        "fixture".into(),
    )));
    tx.send(WireBlob::from(veil_bufpool::pooled_shared_from_vec(
        b"kept".to_vec(),
    )))
    .await
    .unwrap();
    let mut stop = Box::pin(SessionRunner::stop_writer(tx, &mut writer));
    assert!(poll_once(stop.as_mut()).await.is_pending());
    let mut bytes = [0; 4];
    peer.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"kept");
    stop.await;
}

struct FlushBlocked {
    flushing: Arc<AtomicBool>,
    shutdowns: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
}
impl AsyncRead for FlushBlocked {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for FlushBlocked {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.flushing.store(true, Ordering::SeqCst);
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}
impl Drop for FlushBlocked {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn failed_flush_releases_runner_and_registry_without_drain_grace() {
    let peer = [0xB1; 32];
    let mut registry = crate::SessionTxRegistry::new();
    let outbox = registry.register(peer);
    // Retain the producer: outbox EOF cannot substitute for writer failure.
    let producer = registry.get_sender(&peer).unwrap().clone();
    let header = veil_proto::FrameHeader::new(
        veil_proto::family::FrameFamily::App as u8,
        veil_proto::family::AppMsg::AppData as u16,
    );
    producer
        .try_send((
            veil_proto::priority::INTERACTIVE,
            veil_bufpool::pooled_shared_from_vec(
                veil_proto::codec::encode_header(&header).to_vec(),
            ),
        ))
        .unwrap();
    let flushing = Arc::new(AtomicBool::new(false));
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let mut runner = make_runner(
        Box::new(FlushBlocked {
            flushing: flushing.clone(),
            shutdowns: shutdowns.clone(),
            dropped: dropped.clone(),
        }),
        outbox,
        None,
    );
    assert!(runner.keepalive_interval.is_zero() && runner.idle_timeout.is_zero());
    let mut run = Box::pin(runner.run());
    for _ in 0..32 {
        assert!(poll_once(run.as_mut()).await.is_pending());
        tokio::task::yield_now().await;
        if flushing.load(Ordering::SeqCst) {
            break;
        }
    }
    assert!(
        flushing.load(Ordering::SeqCst),
        "writer never reached flush"
    );
    tokio::time::advance(super::super::WRITE_PROGRESS_TIMEOUT).await;
    let decision_at = tokio::time::Instant::now();
    let mut returned = false;
    for _ in 0..32 {
        tokio::task::yield_now().await;
        if poll_once(run.as_mut()).await.is_ready() {
            returned = true;
            break;
        }
    }
    assert_eq!(tokio::time::Instant::now(), decision_at);
    drop(run);
    drop(runner);
    tokio::task::yield_now().await;
    assert!(
        returned,
        "terminal flush still gates reconnect on drain grace"
    );
    assert!(
        !registry.has_session(&peer),
        "dead session remains registered"
    );
    assert_eq!(shutdowns.load(Ordering::SeqCst), 0);
    assert!(dropped.load(Ordering::SeqCst), "failed transport leaked");
    drop(producer);
}

struct GatedWriter {
    open: Arc<AtomicBool>,
    writes: Arc<AtomicUsize>,
    bytes: Arc<std::sync::Mutex<Vec<u8>>>,
    waker: Arc<std::sync::Mutex<Option<std::task::Waker>>>,
    dropped: Arc<AtomicBool>,
}
impl AsyncRead for GatedWriter {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}
impl AsyncWrite for GatedWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        *self.waker.lock().unwrap() = Some(cx.waker().clone());
        if !self.open.load(Ordering::SeqCst) {
            return Poll::Pending;
        }
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
impl Drop for GatedWriter {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

async fn registry_close_while_writer_is_blocked(explicit: bool, owned: bool) {
    let peer = [0xB1; 32];
    let owner = [0x71; 32];
    let mut registry = crate::SessionTxRegistry::new();
    let outbox = if owned {
        registry.register_owned(peer, owner)
    } else {
        registry.register(peer)
    };
    // A borrowed producer must not hide an explicit retirement or substitute
    // sender EOF for the event under test.
    let producer = registry.get_sender(&peer).unwrap().clone();
    let mut header = veil_proto::FrameHeader::new(
        veil_proto::family::FrameFamily::App as u8,
        veil_proto::family::AppMsg::AppData as u16,
    );
    header.set_priority(veil_proto::priority::INTERACTIVE);
    header.body_len = 4;
    let mut expected = veil_proto::codec::encode_header(&header).to_vec();
    expected.extend_from_slice(b"kept");
    producer
        .try_send((
            veil_proto::priority::INTERACTIVE,
            veil_bufpool::pooled_shared_from_vec(expected.clone()),
        ))
        .unwrap();
    let open = Arc::new(AtomicBool::new(false));
    let writes = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let waker = Arc::new(std::sync::Mutex::new(None));
    let dropped = Arc::new(AtomicBool::new(false));
    let mut runner = make_runner(
        Box::new(GatedWriter {
            open: open.clone(),
            writes: writes.clone(),
            bytes: bytes.clone(),
            waker: waker.clone(),
            dropped: dropped.clone(),
        }),
        outbox,
        None,
    );
    // Keep this control's wire bytes exact; no padding/cover, timer, read EOF
    // or keepalive teardown can replace the registry-close path.
    runner.crypto.tx_cipher = None;
    runner.crypto.rx_cipher = None;
    assert!(runner.keepalive_interval.is_zero() && runner.idle_timeout.is_zero());
    let mut run = Box::pin(runner.run());
    for _ in 0..32 {
        assert!(poll_once(run.as_mut()).await.is_pending());
        tokio::task::yield_now().await;
        if writes.load(Ordering::SeqCst) > 0 {
            break;
        }
    }
    assert!(writes.load(Ordering::SeqCst) > 0, "writer never blocked");
    assert!(bytes.lock().unwrap().is_empty());
    let replacement = if explicit {
        if owned {
            assert!(registry.unregister_owned(&peer, &owner));
        } else {
            registry.unregister(&peer);
        }
        None
    } else {
        // Normal replacement releases the previous registry owner. It is not
        // an administrative disconnect; already accepted bytes may drain.
        Some(registry.register_owned(peer, [0x72; 32]))
    };
    let decision_at = tokio::time::Instant::now();
    let mut returned = false;
    for _ in 0..8 {
        if poll_once(run.as_mut()).await.is_ready() {
            returned = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    if !explicit {
        assert!(!returned, "replacement aborted the accepted wire blob");
        open.store(true, Ordering::SeqCst);
        if let Some(waker) = waker.lock().unwrap().take() {
            waker.wake();
        }
        for _ in 0..32 {
            tokio::task::yield_now().await;
            if poll_once(run.as_mut()).await.is_ready() {
                returned = true;
                break;
            }
        }
        assert_eq!(*bytes.lock().unwrap(), expected);
        assert!(registry.has_session(&peer), "old runner harmed replacement");
    }
    assert_eq!(tokio::time::Instant::now(), decision_at);
    drop(run);
    drop(runner);
    tokio::task::yield_now().await;
    assert!(dropped.load(Ordering::SeqCst), "writer transport leaked");
    drop(producer);
    drop(replacement);
    assert!(returned, "registry close still pays writer drain grace");
}

#[tokio::test(start_paused = true)]
async fn explicit_registry_retirement_aborts_blocked_writer() {
    registry_close_while_writer_is_blocked(true, false).await;
}

#[tokio::test(start_paused = true)]
async fn explicit_owned_retirement_aborts_blocked_writer() {
    registry_close_while_writer_is_blocked(true, true).await;
}

#[tokio::test(start_paused = true)]
async fn ordinary_registry_replacement_drains_blocked_writer() {
    registry_close_while_writer_is_blocked(false, true).await;
}
