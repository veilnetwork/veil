use std::future::pending;
use std::io;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::sync::Notify;
use veil_onion_stream::{CellDuplex, Config, End, Frame, OnionStream, send_backpressure};

struct ColdCarrier {
    attempts: Arc<AtomicU64>,
    blocked: Arc<Notify>,
    closed: Arc<Notify>,
    retry_after: Duration,
    first_send_delay: Duration,
}

impl CellDuplex for ColdCarrier {
    async fn send_cell(&mut self, cell: &[u8]) -> io::Result<()> {
        if matches!(Frame::decode(cell), Some(Frame::Syn { .. }))
            && self.attempts.fetch_add(1, Ordering::Relaxed) == 0
        {
            tokio::time::sleep(self.first_send_delay).await;
            self.blocked.notify_one();
            return Err(send_backpressure(self.retry_after));
        }
        Ok(())
    }
    async fn recv_cell(&mut self) -> io::Result<Option<Vec<u8>>> {
        pending().await
    }
    async fn on_stream_closed(&mut self, _: u32, _: End) {
        self.closed.notify_one();
    }
}

fn stream(
    retry_after: Duration,
    first_send_delay: Duration,
) -> (OnionStream, Arc<AtomicU64>, Arc<Notify>, Arc<Notify>) {
    let attempts = Arc::new(AtomicU64::new(0));
    let blocked = Arc::new(Notify::new());
    let closed = Arc::new(Notify::new());
    let carrier = ColdCarrier {
        attempts: attempts.clone(),
        blocked: blocked.clone(),
        closed: closed.clone(),
        retry_after,
        first_send_delay,
    };
    let stream = OnionStream::connect(
        carrier,
        Config {
            handshake_rto_ms: 6000,
            ..Config::default()
        },
        11,
        100,
    );
    (stream, attempts, blocked, closed)
}

#[tokio::test(start_paused = true)]
async fn driver_honors_carrier_backoff_without_waiting_for_network_rto() {
    let (stream, attempts, blocked, closed) =
        stream(Duration::from_millis(100), Duration::from_millis(50));
    blocked.notified().await;
    tokio::time::advance(Duration::from_millis(99)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        attempts.load(Ordering::Relaxed),
        1,
        "cold-route retry spun too fast"
    );
    tokio::time::advance(Duration::from_millis(3)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        attempts.load(Ordering::Relaxed),
        2,
        "retained SYN waited for its RTO"
    );
    stream
        .reset(veil_onion_stream::wire::reset_reason::APP)
        .await;
    tokio::time::timeout(Duration::from_millis(20), closed.notified())
        .await
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn carrier_backoff_does_not_block_driver_cancellation() {
    let (stream, attempts, blocked, closed) = stream(Duration::from_secs(60), Duration::ZERO);
    blocked.notified().await;
    stream
        .reset(veil_onion_stream::wire::reset_reason::APP)
        .await;
    tokio::time::timeout(Duration::from_millis(20), closed.notified())
        .await
        .unwrap();
    assert_eq!(attempts.load(Ordering::Relaxed), 1);
}
