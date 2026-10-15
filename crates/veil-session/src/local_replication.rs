//! Pace this node's own best-effort background records across all neighbors.
//! Independent of calls, remote priorities and forwarded traffic.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::AbortHandle;
use tokio::time::Instant;
use veil_types::NodeIdBytes;

use crate::tx_registry::SessionTxRegistry;

const BYTES_PER_SECOND: usize = 8192;
const MAX_PENDING_BYTES: usize = 512 * 1024;
const MAX_PENDING_FRAMES: usize = 64;
const MAX_WAIT: Duration = Duration::from_secs(60);

struct Record {
    peer: NodeIdBytes,
    bytes: Vec<u8>,
    queued_at: Instant,
    _permit: OwnedSemaphorePermit,
}

#[derive(Debug)]
struct Worker {
    sender: mpsc::Sender<Record>,
    abort: AbortHandle,
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

#[derive(Debug)]
pub(crate) struct LocalReplication {
    runtime: Option<tokio::runtime::Handle>,
    worker: Mutex<Option<Worker>>,
    bytes: Arc<Semaphore>,
}

impl Default for LocalReplication {
    fn default() -> Self {
        Self {
            runtime: tokio::runtime::Handle::try_current().ok(),
            worker: Mutex::default(),
            bytes: Arc::new(Semaphore::new(MAX_PENDING_BYTES)),
        }
    }
}

impl LocalReplication {
    pub(crate) fn enqueue(
        &self,
        registry: Weak<RwLock<SessionTxRegistry>>,
        peer: NodeIdBytes,
        bytes: Vec<u8>,
        dropped: Arc<AtomicU64>,
    ) -> bool {
        let Ok(cost) = u32::try_from(bytes.len().max(1)) else {
            return false;
        };
        let Ok(permit) = Arc::clone(&self.bytes).try_acquire_many_owned(cost) else {
            return false;
        };
        let mut worker = self.worker.lock().unwrap_or_else(|p| p.into_inner());
        if worker.as_ref().is_none_or(|w| w.sender.is_closed()) {
            // Synchronous maintenance/FFI callers can use the node's captured
            // runtime even when their thread is not inside a Tokio task.
            let Some(runtime) = tokio::runtime::Handle::try_current()
                .ok()
                .or_else(|| self.runtime.clone())
            else {
                return false;
            };
            let (sender, receiver) = mpsc::channel(MAX_PENDING_FRAMES);
            let task = runtime.spawn(drain(registry, receiver, dropped));
            *worker = Some(Worker {
                sender,
                abort: task.abort_handle(),
            });
        }
        worker
            .as_ref()
            .unwrap()
            .sender
            .try_send(Record {
                peer,
                bytes,
                queued_at: Instant::now(),
                _permit: permit,
            })
            .is_ok()
    }
}

async fn drain(
    registry: Weak<RwLock<SessionTxRegistry>>,
    mut records: mpsc::Receiver<Record>,
    dropped: Arc<AtomicU64>,
) {
    let mut ready = Instant::now();
    while let Some(record) = records.recv().await {
        if ready > record.queued_at + MAX_WAIT {
            dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        tokio::time::sleep_until(ready).await;
        let now = Instant::now();
        if now.saturating_duration_since(record.queued_at) > MAX_WAIT {
            dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let cost = record.bytes.len().max(1);
        let sent = {
            let Some(registry) = registry.upgrade() else {
                return;
            };
            let guard = registry.read().unwrap_or_else(|p| p.into_inner());
            guard.send_to(&record.peer, veil_proto::priority::BACKGROUND, record.bytes)
        };
        // Actual emission time, not planned deadlines: a stalled executor must
        // not release accumulated catch-up credit as another publication burst.
        if sent {
            ready = Instant::now() + Duration::from_secs_f64(cost as f64 / BYTES_PER_SECOND as f64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame_outbox::FrameOutbox;
    use veil_proto::priority::{BACKGROUND, INTERACTIVE};

    fn setup() -> (Arc<RwLock<SessionTxRegistry>>, FrameOutbox, FrameOutbox) {
        let mut registry = SessionTxRegistry::new();
        let a = registry.register([1; 32]);
        let b = registry.register([2; 32]);
        (Arc::new(RwLock::new(registry)), a, b)
    }

    #[tokio::test(start_paused = true)]
    async fn publications_share_one_rate_across_neighbors_without_touching_transit() {
        let (registry, mut a, mut b) = setup();
        assert!(SessionTxRegistry::send_local_replication(
            &registry,
            [1; 32],
            vec![1; 1024]
        ));
        assert!(SessionTxRegistry::send_local_replication(
            &registry,
            [2; 32],
            vec![2; 1024]
        ));
        let first = a.recv().await.unwrap();
        assert_eq!(first.0, BACKGROUND);
        assert_eq!(&first.1[..], &[1; 1024]);
        assert!(b.try_recv().is_err());
        assert!(
            registry
                .read()
                .unwrap()
                .send_to(&[2; 32], INTERACTIVE, vec![99])
        );
        assert_eq!(&b.recv().await.unwrap().1[..], &[99]);
        tokio::time::advance(Duration::from_millis(124)).await;
        tokio::task::yield_now().await;
        assert!(b.try_recv().is_err());
        tokio::time::advance(Duration::from_millis(2)).await;
        let second = b.recv().await.unwrap();
        assert_eq!(second.0, BACKGROUND);
        assert_eq!(&second.1[..], &[2; 1024]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_executor_cannot_release_catch_up_credit() {
        let (registry, mut a, _) = setup();
        for index in 0..4 {
            assert!(SessionTxRegistry::send_local_replication(
                &registry,
                [1; 32],
                vec![index; 1024]
            ));
        }
        assert_eq!(a.recv().await.unwrap().1[0], 0);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(a.try_recv().unwrap().1[0], 1);
        assert!(
            a.try_recv().is_err(),
            "planned deadlines must not cause a burst"
        );
        tokio::time::advance(Duration::from_millis(126)).await;
        assert_eq!(a.recv().await.unwrap().1[0], 2);
    }

    #[tokio::test(start_paused = true)]
    async fn frame_and_byte_bounds_reject_without_growing_tasks() {
        let (registry, _a, _b) = setup();
        for _ in 0..MAX_PENDING_FRAMES {
            assert!(SessionTxRegistry::send_local_replication(
                &registry,
                [1; 32],
                vec![0; 1024]
            ));
        }
        assert!(!SessionTxRegistry::send_local_replication(
            &registry,
            [1; 32],
            vec![0; 1024]
        ));
        let (bytes_registry, _bytes_a, _bytes_b) = setup();
        assert!(SessionTxRegistry::send_local_replication(
            &bytes_registry,
            [1; 32],
            vec![0; MAX_PENDING_BYTES]
        ));
        assert!(!SessionTxRegistry::send_local_replication(
            &bytes_registry,
            [1; 32],
            vec![0]
        ));
        assert!(!SessionTxRegistry::send_local_replication(
            &bytes_registry,
            [3; 32],
            vec![0]
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn stale_copies_are_not_replayed_after_a_long_pause() {
        let (registry, mut a, _) = setup();
        for _ in 0..3 {
            assert!(SessionTxRegistry::send_local_replication(
                &registry,
                [1; 32],
                vec![0; 1024]
            ));
        }
        a.recv().await.unwrap();
        tokio::time::advance(MAX_WAIT + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(a.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn a_disconnected_destination_cannot_spend_other_neighbors_budget() {
        let (registry, a, mut b) = setup();
        let began = Instant::now();
        assert!(SessionTxRegistry::send_local_replication(
            &registry,
            [1; 32],
            vec![0; 1024]
        ));
        assert!(SessionTxRegistry::send_local_replication(
            &registry,
            [2; 32],
            vec![1; 1024]
        ));
        drop(a);
        assert_eq!(b.recv().await.unwrap().1[0], 1);
        assert!(Instant::now() - began <= Duration::from_millis(2));
    }

    #[tokio::test(start_paused = true)]
    async fn worker_ends_with_its_registry_and_cannot_retain_the_node() {
        let (registry, mut a, _) = setup();
        let weak = Arc::downgrade(&registry);
        let baseline = tokio::runtime::Handle::current()
            .metrics()
            .num_alive_tasks();
        assert!(SessionTxRegistry::send_local_replication(
            &registry,
            [1; 32],
            vec![1; 1024]
        ));
        a.recv().await.unwrap();
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            baseline + 1
        );
        drop(registry);
        assert!(weak.upgrade().is_none());
        tokio::task::yield_now().await;
        assert_eq!(
            tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks(),
            baseline
        );
    }

    #[tokio::test(start_paused = true)]
    async fn plain_threads_can_publish_using_the_nodes_runtime() {
        let (registry, mut a, _) = setup();
        let from_thread = Arc::clone(&registry);
        assert!(
            std::thread::spawn(move || {
                SessionTxRegistry::send_local_replication(&from_thread, [1; 32], vec![7])
            })
            .join()
            .unwrap()
        );
        assert_eq!(&a.recv().await.unwrap().1[..], &[7]);
    }

    #[tokio::test(start_paused = true)]
    async fn admission_overflow_and_expiry_are_visible_in_existing_drop_metrics() {
        let dropped = Arc::new(AtomicU64::new(0));
        let mut inner = SessionTxRegistry::with_capacity_and_drop_counter(64, Arc::clone(&dropped));
        let mut a = inner.register([1; 32]);
        let registry = Arc::new(RwLock::new(inner));
        for _ in 0..MAX_PENDING_FRAMES {
            assert!(SessionTxRegistry::send_local_replication(
                &registry,
                [1; 32],
                vec![0; 1024]
            ));
        }
        assert!(!SessionTxRegistry::send_local_replication(
            &registry,
            [1; 32],
            vec![0]
        ));
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        a.recv().await.unwrap();
        tokio::time::advance(MAX_WAIT + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(dropped.load(Ordering::Relaxed), MAX_PENDING_FRAMES as u64);
    }
}
