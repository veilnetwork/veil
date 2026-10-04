//! Endpoint-only sibling selection. Remote accepts see only generic proofs;
//! they dispatch through the canonical peer's existing budgets and identity.
use super::*;
use crate::parallel_binding::{HELLO_BYTES, ParallelParent, ParallelParentHandle};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use veil_transport::QuicParallelHandle;

const BIND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

/// Local observations, never wire fields or relay scheduling requests.
#[derive(Default)]
pub struct ParallelDiagnostics {
    sent: [AtomicU64; 2],
    epoch_sent: [AtomicU64; 2],
    rekeys: AtomicU64,
    active: AtomicUsize,
}

impl ParallelDiagnostics {
    /// Successfully admitted frames on the selected independent connection.
    pub fn sent(&self, local_priority: u8) -> u64 {
        channel_index(local_priority).map_or(0, |index| self.sent[index].load(Ordering::Relaxed))
    }
    pub fn rekeys(&self) -> u64 {
        self.rekeys.load(Ordering::Acquire)
    }
    pub fn sent_this_generation(&self, local_priority: u8) -> u64 {
        channel_index(local_priority)
            .map_or(0, |index| self.epoch_sent[index].load(Ordering::Relaxed))
    }
    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
    pub(super) fn note_sent(&self, index: usize) {
        self.sent[index].fetch_add(1, Ordering::Relaxed);
        self.epoch_sent[index].fetch_add(1, Ordering::Relaxed);
    }
}

/// Offered only after peer capability and exclusive transport negotiation.
/// Clones retain the endpoint, but do not own session authorization.
#[derive(Clone)]
pub struct ParallelQuicOffer {
    handle: QuicParallelHandle,
    diagnostics: Arc<ParallelDiagnostics>,
}

impl ParallelQuicOffer {
    pub fn new(handle: QuicParallelHandle) -> Self {
        Self {
            handle,
            diagnostics: Arc::default(),
        }
    }
    pub fn diagnostics(&self) -> Arc<ParallelDiagnostics> {
        Arc::clone(&self.diagnostics)
    }
}

fn channel_index(priority: u8) -> Option<usize> {
    match priority {
        veil_proto::priority::REALTIME => Some(0),
        veil_proto::priority::BULK => Some(1),
        // Forwarded traffic uses INTERACTIVE: it never requests a local
        // producer's connection or causes a relay to favor a user.
        _ => None,
    }
}

struct Channel {
    handle: veil_transport::QuicDatagramHandle,
    stream: BoxIoStream,
    diagnostics: Arc<ParallelDiagnostics>,
}

impl Channel {
    fn new(
        connection: Box<dyn veil_transport::TransportConnection>,
        diagnostics: Arc<ParallelDiagnostics>,
    ) -> Result<Self, String> {
        let handle = connection
            .quic_datagrams()
            .ok_or("parallel transport has no datagrams")?;
        let stream = match connection.into_stream() {
            Ok(stream) => stream,
            Err(error) => {
                handle.close();
                return Err(error.to_string());
            }
        };
        diagnostics.active.fetch_add(1, Ordering::AcqRel);
        Ok(Self {
            handle,
            stream,
            diagnostics,
        })
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.handle.close();
        self.diagnostics.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct ReadySender {
    sender: RealtimeSender,
    _channel: Channel,
}

#[derive(Default)]
struct Slot {
    ready: Option<ReadySender>,
    warm: Option<(
        tokio::sync::oneshot::Receiver<ReadySender>,
        RealtimeReceiverTask,
    )>,
    retry_after: Option<std::time::Instant>,
}

async fn connect_sender(
    offer: ParallelQuicOffer,
    parent: ParallelParentHandle,
    index: usize,
) -> Result<ReadySender, String> {
    let connection = offer
        .handle
        .connect()
        .await
        .map_err(|error| error.to_string())?;
    let mut channel = Channel::new(connection, Arc::clone(&offer.diagnostics))?;
    let exporter = channel
        .handle
        .channel_binding()
        .map_err(|error| error.to_string())?;
    let (hello, pending) = parent.begin(exporter).map_err(|error| error.to_string())?;
    channel
        .stream
        .write_all(&hello)
        .await
        .map_err(|error| error.to_string())?;
    let mut ack = [0; 32];
    channel
        .stream
        .read_exact(&mut ack)
        .await
        .map_err(|error| error.to_string())?;
    let keys = pending.finish(&ack).map_err(|error| error.to_string())?;
    if channel
        .handle
        .max_size()
        .is_none_or(|size| size < crate::datagram_flows::MIN_FLOW_DATAGRAM_SIZE)
    {
        return Err("parallel datagram ceiling unavailable".to_owned());
    }
    let tx = crate::datagram_flows::SessionDatagramTx::new(keys.tx_key(), &keys.session_id, true);
    let mut sender = RealtimeSender::new(channel.handle.clone(), tx);
    sender.sent_counter = Some((Arc::clone(&offer.diagnostics), index));
    Ok(ReadySender {
        sender,
        _channel: channel,
    })
}

async fn receive_child(
    mut channel: Channel,
    parent: ParallelParentHandle,
    context: RealtimeReceiverContext,
) {
    let authenticated = tokio::time::timeout(BIND_TIMEOUT, async {
        let mut hello = [0; HELLO_BYTES];
        channel.stream.read_exact(&mut hello).await.ok()?;
        let exporter = channel.handle.channel_binding().ok()?;
        let (ack, keys) = parent.accept(&hello, exporter).ok()?;
        channel.stream.write_all(&ack).await.ok()?;
        Some(keys)
    })
    .await;
    let Ok(Some(keys)) = authenticated else {
        return;
    };
    let rx = crate::datagram_flows::SessionDatagramRx::new(keys.rx_key(), &keys.session_id, true);
    // These fixed child keys are retired as a whole at canonical rekey. They
    // never receive the parent's ordinary datagram codec rotations.
    let (_hold_tx, rekey_rx) = tokio::sync::watch::channel(None);
    let mut receiver = spawn_realtime_receiver(channel.handle.clone(), rx, rekey_rx, context);
    tokio::select! {
        _ = channel.handle.closed() => {},
        _ = &mut receiver.0 => {},
    }
    // Channel Drop closes QUIC even when this future is cancelled. The
    // receiver guard aborts its task and releases child key/assembly state.
}

fn spawn_acceptor(
    offer: ParallelQuicOffer,
    parent: ParallelParentHandle,
    context: RealtimeReceiverContext,
) -> RealtimeReceiverTask {
    RealtimeReceiverTask(tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = children.join_next(), if !children.is_empty() => {},
                accepted = offer.handle.accept() => {
                    match accepted {
                        Ok(connection) => {
                            if let Ok(channel) = Channel::new(connection, Arc::clone(&offer.diagnostics)) {
                                children.spawn(receive_child(channel, parent.clone(), context.clone()));
                            }
                        }
                        Err(_) => tokio::time::sleep(RETRY_DELAY).await,
                    }
                }
            }
        }
    }))
}

pub(super) struct ParallelSession {
    offer: ParallelQuicOffer,
    context: RealtimeReceiverContext,
    parent: ParallelParent,
    _acceptor: RealtimeReceiverTask,
    slots: [Slot; 2],
}

impl ParallelSession {
    pub(super) fn new(
        offer: ParallelQuicOffer,
        tx: &[u8; 32],
        rx: &[u8; 32],
        sid: [u8; 32],
        context: RealtimeReceiverContext,
    ) -> Self {
        let parent = ParallelParent::new(sid, *tx, *rx);
        let acceptor = spawn_acceptor(offer.clone(), parent.handle(), context.clone());
        Self {
            offer,
            context,
            parent,
            _acceptor: acceptor,
            slots: Default::default(),
        }
    }

    pub(super) fn rekey(&mut self, tx: &[u8; 32], rx: &[u8; 32], sid: [u8; 32]) {
        for counter in &self.offer.diagnostics.epoch_sent {
            counter.store(0, Ordering::Relaxed);
        }
        self.offer
            .diagnostics
            .rekeys
            .fetch_add(1, Ordering::Release);
        *self = Self::new(self.offer.clone(), tx, rx, sid, self.context.clone());
    }

    /// Poll readiness and initiate warming without awaiting on the main
    /// session. Until authentication succeeds, frames use the current lane.
    pub(super) fn prepare(&mut self, priority: u8) -> bool {
        let Some(index) = channel_index(priority) else {
            return false;
        };
        let slot = &mut self.slots[index];
        if slot.ready.as_ref().is_some_and(|ready| ready.sender.broken) {
            slot.ready = None;
            slot.retry_after = Some(std::time::Instant::now() + RETRY_DELAY);
        }
        if let Some((rx, _)) = slot.warm.as_mut() {
            match rx.try_recv() {
                Ok(ready) => {
                    slot.ready = Some(ready);
                    slot.warm = None;
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    slot.warm = None;
                    slot.retry_after = Some(std::time::Instant::now() + RETRY_DELAY);
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
            }
        }
        if slot.ready.is_some() {
            return true;
        }
        if slot.warm.is_none()
            && slot
                .retry_after
                .is_none_or(|deadline| std::time::Instant::now() >= deadline)
        {
            let offer = self.offer.clone();
            let parent = self.parent.handle();
            let (tx, rx) = tokio::sync::oneshot::channel();
            let task = RealtimeReceiverTask(tokio::spawn(async move {
                if let Ok(Ok(ready)) =
                    tokio::time::timeout(BIND_TIMEOUT, connect_sender(offer, parent, index)).await
                {
                    let _ = tx.send(ready);
                }
            }));
            slot.warm = Some((rx, task));
        }
        false
    }

    pub(super) fn sender(&mut self, priority: u8) -> &mut RealtimeSender {
        &mut self.slots[channel_index(priority).expect("prepared local channel")]
            .ready
            .as_mut()
            .expect("prepared sender")
            .sender
    }
}
