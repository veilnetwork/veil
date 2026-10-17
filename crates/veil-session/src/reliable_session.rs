//! One duplex reliable child tied to the existing canonical session owner.
//! A fixed transport dialer creates it; the acceptor never reverse-dials a TCP
//! client. No identity admission or remote scheduling class is introduced.
use super::*;
use crate::parallel_binding::ParallelParentHandle;
use crate::reliable_frames::{ReliableFrameChannel, ReliableFrameHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;

const BIND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

#[derive(Clone)]
pub enum ReliableTransport {
    Quic(veil_transport::QuicParallelHandle),
    Ordered(veil_transport::stream_parallel::StreamParallelHandle),
}

impl ReliableTransport {
    fn dialer(&self) -> bool {
        match self {
            Self::Quic(h) => h.is_original_dialer(),
            Self::Ordered(h) => h.can_connect(),
        }
    }
    async fn connect(
        &self,
    ) -> veil_transport::Result<Box<dyn veil_transport::TransportConnection>> {
        match self {
            Self::Quic(h) => h.connect().await,
            Self::Ordered(h) => h.connect().await,
        }
    }
    async fn closed(&self) {
        match self {
            Self::Quic(h) => h.closed().await,
            Self::Ordered(h) => h.closed().await,
        }
    }
}

pub struct ReliableReady {
    id: [u8; 32],
    channel: ReliableFrameChannel,
}

impl ReliableReady {
    pub(super) fn quic_snapshot(&self) -> Option<(u64, veil_transport::QuicDatagramPathStats)> {
        self.channel.quic_snapshot()
    }
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
    pub fn handle(&self) -> ReliableFrameHandle {
        self.channel.handle()
    }
}

pub enum ReliableEvent {
    Changed,
    /// The pool worker/parent has ended. The canonical runner must stop
    /// polling this pool until a new generation is installed.
    Stopped,
    Frame {
        child: [u8; 32],
        result: std::io::Result<veil_bufpool::PooledShared>,
    },
}

/// Own this alongside the parent's other child pools. Reconstruct it on rekey.
/// The reader acknowledges a failed child only after draining its completed
/// authenticated frames and aborting streams pinned to that child. Until then
/// the worker retains the owner; reconnection cannot silently discard its tail.
pub struct ReliableSession {
    state: watch::Receiver<Option<Arc<ReliableReady>>>,
    failed: mpsc::Sender<[u8; 32]>,
    worker: tokio::task::JoinHandle<()>,
}

impl ReliableSession {
    /// The caller must opt the same canonical registration into reliable mode
    /// before passing its inbox. Its parent credentials come only from the
    /// existing authenticated OVL1 session, not an incoming wire preface.
    pub fn new(
        transport: ReliableTransport,
        parent: ParallelParentHandle,
        diagnostics: Arc<ParallelDiagnostics>,
        incoming: mpsc::Receiver<BoundReliableChild>,
    ) -> Self {
        let (state, view) = watch::channel(None);
        let (failed, failures) = mpsc::channel(1);
        let worker = tokio::spawn(work(
            transport,
            parent,
            diagnostics,
            incoming,
            state,
            failures,
        ));
        Self {
            state: view,
            failed,
            worker,
        }
    }
    pub fn ready(&self) -> Option<Arc<ReliableReady>> {
        self.state.borrow().clone()
    }
    pub fn running(&self) -> bool {
        !self.worker.is_finished()
    }
    pub fn acknowledge_failure(&self, child: [u8; 32]) {
        let _ = self.failed.try_send(child);
    }
    /// Cancellation-safe frame consumption and readiness changes, suitable for
    /// the canonical runner's select. Read errors retain their child identity.
    pub async fn next(&self) -> ReliableEvent {
        let mut view = self.state.clone();
        let ready = view.borrow_and_update().clone();
        if let Some(ready) = ready {
            let handle = ready.handle();
            tokio::select! {
                changed = view.changed() => if changed.is_ok() { ReliableEvent::Changed } else { ReliableEvent::Stopped },
                result = handle.recv() => ReliableEvent::Frame { child: ready.id, result },
            }
        } else {
            if view.changed().await.is_ok() {
                ReliableEvent::Changed
            } else {
                ReliableEvent::Stopped
            }
        }
    }
}

impl Drop for ReliableSession {
    fn drop(&mut self) {
        // Explicitly close retained snapshots even before the aborted worker
        // gets CPU. A snapshot is observational, not additional authorization.
        if let Some(ready) = self.ready() {
            ready.handle().close();
        }
        self.worker.abort();
    }
}

async fn dial(
    transport: ReliableTransport,
    parent: ParallelParentHandle,
    diagnostics: Arc<ParallelDiagnostics>,
) -> Result<RegisteredReliableChannel, &'static str> {
    let operation = async {
        let connection = transport
            .connect()
            .await
            .map_err(|_| "reliable dial failed")?;
        let mut child =
            parallel_lanes::registry::ReliableDialedChild::new(connection, diagnostics)?;
        let (hello, pending) = parent
            .begin_reliable(child.exporter())
            .map_err(|_| "parent retired")?;
        child
            .stream()
            .write_all(&hello)
            .await
            .map_err(|_| "reliable hello write failed")?;
        child
            .stream()
            .flush()
            .await
            .map_err(|_| "reliable hello flush failed")?;
        let mut ack = [0; 32];
        child
            .stream()
            .read_exact(&mut ack)
            .await
            .map_err(|_| "reliable ACK read failed")?;
        let keys = pending.finish(&ack).map_err(|_| "reliable ACK rejected")?;
        child.finish(keys)
    };
    tokio::select! {
        biased;
        _ = parent.retired() => Err("parent retired"),
        result = tokio::time::timeout(BIND_TIMEOUT, operation) => result.unwrap_or(Err("reliable binding timed out")),
    }
}

async fn work(
    transport: ReliableTransport,
    parent: ParallelParentHandle,
    diagnostics: Arc<ParallelDiagnostics>,
    mut incoming: mpsc::Receiver<BoundReliableChild>,
    state: watch::Sender<Option<Arc<ReliableReady>>>,
    mut failures: mpsc::Receiver<[u8; 32]>,
) {
    let _retire_on_exit = RetireOnExit(state.clone());
    let dialer = transport.dialer();
    let mut attempts = tokio::task::JoinSet::new();
    let mut retry = std::time::Instant::now();
    let mut backoff = RETRY_DELAY;
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            _ = parent.retired() => break,
            _ = transport.closed() => break,
            Some(child) = failures.recv() => {
                if state.borrow().as_ref().is_some_and(|ready| ready.id == child) {
                    state.send_replace(None);
                    retry = std::time::Instant::now() + RETRY_DELAY;
                }
            },
            Some(child) = incoming.recv() => {
                // Exactly one duplex owner; the fixed dialer cannot be displaced
                // by an unexpected reverse child, even with a valid peer proof.
                if !dialer && state.borrow().is_none() && attempts.is_empty() {
                    attempts.spawn(child.finish());
                }
            },
            Some(result) = attempts.join_next(), if !attempts.is_empty() => {
                match result {
                    Ok(Ok(channel)) if parent.is_active() => {
                        let id = channel.keys().session_id;
                        state.send_replace(Some(Arc::new(ReliableReady { id, channel: ReliableFrameChannel::from_registered(channel) })));
                        backoff = RETRY_DELAY;
                    },
                    _ => { backoff = (backoff * 2).min(std::time::Duration::from_secs(30)); },
                }
                retry = std::time::Instant::now() + backoff;
            },
            _ = tick.tick() => {
                if dialer && state.borrow().is_none() && attempts.is_empty() && std::time::Instant::now() >= retry {
                    attempts.spawn(dial(transport.clone(), parent.clone(), diagnostics.clone()));
                }
            },
        }
    }
    // RetireOnExit closes retained snapshots BEFORE clearing the published
    // owner. Clearing it here first would leave an externally retained owner
    // able to decrypt queued records after the canonical transport ended.
}

struct RetireOnExit(watch::Sender<Option<Arc<ReliableReady>>>);
impl Drop for RetireOnExit {
    fn drop(&mut self) {
        let ready = self.0.borrow().clone();
        if let Some(ready) = ready {
            ready.handle().close();
        }
        self.0.send_replace(None);
    }
}
