//! Exercise the real runner's terminal keepalive path with a stuck writer.
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
