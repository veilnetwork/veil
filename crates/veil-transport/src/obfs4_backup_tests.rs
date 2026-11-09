use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::oneshot;

struct Live(Arc<AtomicUsize>);
impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
async fn attempt(rx: oneshot::Receiver<Result<u8>>, live: Arc<AtomicUsize>) -> Result<u8> {
    live.fetch_add(1, Ordering::SeqCst);
    let _live = Live(live);
    rx.await.unwrap()
}
fn failure(s: &str) -> TransportError {
    TransportError::Tls(s.to_owned())
}

#[tokio::test(start_paused = true)]
async fn an_immediate_primary_error_stays_fail_fast_without_a_second_connection() {
    let started = AtomicUsize::new(0);
    let result = connect_with_backup(
        std::future::ready(Err::<u8, _>(failure("primary"))),
        || {
            started.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<Result<u8>>()
        },
        OBFS4_BACKUP_DELAY,
    )
    .await;
    assert_eq!(
        result.unwrap_err().to_string(),
        failure("primary").to_string()
    );
    assert_eq!(started.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn two_failed_attempts_preserve_the_primary_error() {
    let (tx, rx) = oneshot::channel();
    let mut race = Box::pin(connect_with_backup(
        async { rx.await.unwrap() },
        || async { Err::<u8, _>(failure("backup")) },
        OBFS4_BACKUP_DELAY,
    ));
    assert!(futures::poll!(&mut race).is_pending());
    tokio::time::advance(OBFS4_BACKUP_DELAY).await;
    assert!(futures::poll!(&mut race).is_pending());
    tx.send(Err(failure("primary"))).unwrap();
    assert_eq!(
        race.await.unwrap_err().to_string(),
        failure("primary").to_string()
    );
}

#[tokio::test(start_paused = true)]
async fn a_stalled_handshake_starts_only_one_backup_and_cancels_the_loser() {
    let live = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(AtomicUsize::new(0));
    let (_first_tx, first_rx) = oneshot::channel();
    let (second_tx, second_rx) = oneshot::channel();
    let mut race = Box::pin(connect_with_backup(
        attempt(first_rx, live.clone()),
        || {
            started.fetch_add(1, Ordering::SeqCst);
            attempt(second_rx, live.clone())
        },
        OBFS4_BACKUP_DELAY,
    ));
    assert!(futures::poll!(&mut race).is_pending());
    assert_eq!(started.load(Ordering::SeqCst), 0);
    tokio::time::advance(OBFS4_BACKUP_DELAY).await;
    assert!(futures::poll!(&mut race).is_pending());
    assert_eq!(started.load(Ordering::SeqCst), 1, "backup never started");
    assert_eq!(live.load(Ordering::SeqCst), 2);
    tokio::time::advance(Duration::from_secs(100)).await;
    assert!(futures::poll!(&mut race).is_pending());
    assert_eq!(
        started.load(Ordering::SeqCst),
        1,
        "unbounded extra attempts"
    );
    second_tx.send(Ok(2)).unwrap();
    assert_eq!(race.await.unwrap(), 2);
    assert_eq!(live.load(Ordering::SeqCst), 0, "losing attempt survived");
}

#[tokio::test(start_paused = true)]
async fn a_ready_primary_never_opens_a_backup_even_at_the_delay_boundary() {
    let started = AtomicUsize::new(0);
    let (tx, rx) = oneshot::channel();
    let mut race = Box::pin(connect_with_backup(
        async { rx.await.unwrap() },
        || {
            started.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<Result<u8>>()
        },
        OBFS4_BACKUP_DELAY,
    ));
    assert!(futures::poll!(&mut race).is_pending());
    tokio::time::advance(OBFS4_BACKUP_DELAY).await;
    tx.send(Ok(1)).unwrap();
    assert_eq!(race.await.unwrap(), 1);
    assert_eq!(started.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn a_backup_error_does_not_cancel_a_slow_valid_primary() {
    let (tx, rx) = oneshot::channel();
    let mut race = Box::pin(connect_with_backup(
        async { rx.await.unwrap() },
        || async { Err(failure("backup rejected")) },
        OBFS4_BACKUP_DELAY,
    ));
    assert!(futures::poll!(&mut race).is_pending());
    tokio::time::advance(OBFS4_BACKUP_DELAY).await;
    assert!(futures::poll!(&mut race).is_pending());
    tx.send(Ok(1)).unwrap();
    assert_eq!(race.await.unwrap(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_primary_error_does_not_cancel_the_already_started_backup() {
    let (tx, rx) = oneshot::channel();
    let (backup_tx, backup_rx) = oneshot::channel();
    let mut race = Box::pin(connect_with_backup(
        async { rx.await.unwrap() },
        || async { backup_rx.await.unwrap() },
        OBFS4_BACKUP_DELAY,
    ));
    assert!(futures::poll!(&mut race).is_pending());
    tokio::time::advance(OBFS4_BACKUP_DELAY).await;
    assert!(futures::poll!(&mut race).is_pending());
    tx.send(Err(failure("primary rejected"))).unwrap();
    assert!(futures::poll!(&mut race).is_pending());
    backup_tx.send(Ok(2)).unwrap();
    assert_eq!(race.await.unwrap(), 2);
}

#[tokio::test(start_paused = true)]
async fn timeout_drops_both_attempts_without_extending_the_original_budget() {
    let live = Arc::new(AtomicUsize::new(0));
    let (_tx, rx) = oneshot::channel();
    let (_backup_tx, backup_rx) = oneshot::channel();
    let mut wait = Box::pin(tokio::time::timeout(
        OBFS4_HANDSHAKE_TIMEOUT,
        connect_with_backup(
            attempt(rx, live.clone()),
            || attempt(backup_rx, live.clone()),
            OBFS4_BACKUP_DELAY,
        ),
    ));
    assert!(futures::poll!(&mut wait).is_pending());
    tokio::time::advance(OBFS4_BACKUP_DELAY).await;
    assert!(futures::poll!(&mut wait).is_pending());
    assert_eq!(live.load(Ordering::SeqCst), 2);
    tokio::time::advance(OBFS4_HANDSHAKE_TIMEOUT - OBFS4_BACKUP_DELAY).await;
    assert!(wait.await.is_err());
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn caller_cancellation_drops_both_attempts() {
    let live = Arc::new(AtomicUsize::new(0));
    let (_tx, rx) = oneshot::channel();
    let (_backup_tx, backup_rx) = oneshot::channel();
    let mut wait = Box::pin(connect_with_backup(
        attempt(rx, live.clone()),
        || attempt(backup_rx, live.clone()),
        OBFS4_BACKUP_DELAY,
    ));
    assert!(futures::poll!(&mut wait).is_pending());
    tokio::time::advance(OBFS4_BACKUP_DELAY).await;
    assert!(futures::poll!(&mut wait).is_pending());
    assert_eq!(live.load(Ordering::SeqCst), 2);
    drop(wait);
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

async fn real_socket_fixture(valid_backup: bool) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let psk = [0x42; 32];
    let mut context = TransportContext::for_debug().unwrap();
    context.obfs4_psk = Some(Arc::new(psk));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri =
        TransportUri::parse(&format!("obfs4-tcp://{}", listener.local_addr().unwrap())).unwrap();
    let mut server = tokio::spawn(async move {
        // Accepting the first TCP socket deliberately sends no obfs4 response.
        // The server can service a new flow while this one remains black-holed.
        let (first, first_peer) = listener.accept().await.unwrap();
        let (mut second, second_peer) = listener.accept().await.unwrap();
        let (chosen, peer, loser) = if valid_backup {
            (second, second_peer, Some(first))
        } else {
            // A candidate returning bytes is not enough: it must authenticate.
            // A full malformed handshake plus EOF fails promptly, while the
            // untouched primary can still perform the valid handshake.
            second.write_all(&[0; 4096]).await.unwrap();
            second.shutdown().await.unwrap();
            (first, first_peer, None)
        };
        let mut stream = veil_obfs4::obfs4_server_accept(chosen, &NodeIdMacKey(psk))
            .await
            .unwrap();
        let binding = stream.channel_binding().unwrap();
        let mut input = [0; 5];
        stream.read_exact(&mut input).await.unwrap();
        assert_eq!(&input, b"hello");
        stream.write_all(b"world").await.unwrap();
        stream.flush().await.unwrap();
        if let Some(mut loser) = loser {
            let mut bytes = Vec::new();
            loser.read_to_end(&mut bytes).await.unwrap();
            assert!(!bytes.is_empty(), "primary never sent its handshake");
        }
        assert!(
            futures::poll!(Box::pin(listener.accept())).is_pending(),
            "third attempt opened"
        );
        (peer, binding)
    });
    // A fixture watchdog only: no wall-clock latency threshold is asserted.
    let exercised = tokio::time::timeout(Duration::from_secs(15), async {
        let connection = Obfs4TcpTransport
            .connect(&uri, Arc::new(context))
            .await
            .unwrap();
        let selected_local = connection.peer_meta().local_addr.unwrap();
        let binding = connection.stream_channel_binding().unwrap();
        let mut stream = connection.into_stream().unwrap();
        stream.write_all(b"hello").await.unwrap();
        stream.flush().await.unwrap();
        let mut output = [0; 5];
        stream.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"world");
        let (selected_peer, server_binding) = (&mut server).await.unwrap();
        assert_eq!(
            selected_local, selected_peer,
            "metadata belongs to losing socket"
        );
        assert_eq!(binding, server_binding, "exporter belongs to losing socket");
    })
    .await;
    if !server.is_finished() {
        server.abort();
    }
    assert!(exercised.is_ok(), "real obfs4 fixture did not finish");
}

#[tokio::test]
async fn stalled_first_flow_uses_an_authenticated_second_socket_and_closes_the_first() {
    real_socket_fixture(true).await;
}

#[tokio::test]
async fn unauthenticated_backup_cannot_replace_a_valid_primary() {
    real_socket_fixture(false).await;
}
