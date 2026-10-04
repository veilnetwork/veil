//! Endpoint-only sibling selection. Remote accepts see only generic proofs;
//! they dispatch through the canonical peer's existing budgets and identity.
use super::*;
use crate::parallel_binding::{HELLO_BYTES, ParallelKeys, ParallelParent, ParallelParentHandle};

#[path = "parallel_registry.rs"]
mod registry;
pub use registry::{ParallelPeekOutcome, ParallelRegistry};
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
    replies: AtomicU64,
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
    pub fn replies(&self) -> u64 {
        self.replies.load(Ordering::Relaxed)
    }

    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
    pub(super) fn note_sent(&self, index: usize) {
        self.sent[index].fetch_add(1, Ordering::Relaxed);
        self.epoch_sent[index].fetch_add(1, Ordering::Relaxed);
    }
}

/// Offered only after peer capability negotiation.
/// Clones retain the endpoint, but do not own session authorization.
#[derive(Clone)]
pub struct ParallelQuicOffer {
    handle: QuicParallelHandle,
    diagnostics: Arc<ParallelDiagnostics>,
    registry: Option<Arc<ParallelRegistry>>,
    duplex: bool,
}

impl ParallelQuicOffer {
    pub fn new(handle: QuicParallelHandle) -> Self {
        Self {
            handle,
            diagnostics: Arc::default(),
            registry: None,
            duplex: false,
        }
    }
    /// Use the runtime's single shared-listener dispatcher.
    pub fn with_registry(mut self, registry: Arc<ParallelRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Enable only after the peer explicitly negotiates duplex children.
    pub fn with_duplex(mut self) -> Self {
        self.duplex = true;
        self
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
    diagnostics: Option<Arc<ParallelDiagnostics>>,
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
            diagnostics: Some(diagnostics),
        })
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.handle.close();
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

struct ReadySender {
    sender: Arc<Mutex<RealtimeSender>>,
    _receiver: Option<RealtimeReceiverTask>,
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
    context: RealtimeReceiverContext,
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
    let sender = Arc::new(Mutex::new(sender));
    let receiver = offer
        .duplex
        .then(|| spawn_child_receiver(&channel, &keys, parent, context, Arc::clone(&sender)));
    Ok(ReadySender {
        sender,
        _receiver: receiver,
        _channel: channel,
    })
}

async fn receive_child(
    mut channel: Channel,
    parent: ParallelParentHandle,
    context: RealtimeReceiverContext,
    duplex: bool,
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
    receive_authenticated(channel, keys, parent, context, duplex).await;
}

async fn receive_authenticated(
    channel: Channel,
    keys: ParallelKeys,
    parent: ParallelParentHandle,
    context: RealtimeReceiverContext,
    duplex: bool,
) {
    let rx = crate::datagram_flows::SessionDatagramRx::new(keys.rx_key(), &keys.session_id, true);
    let (_hold_tx, rekey_rx) = tokio::sync::watch::channel(None);
    let sender = duplex.then(|| {
        Arc::new(Mutex::new(RealtimeSender::new(
            channel.handle.clone(),
            crate::datagram_flows::SessionDatagramTx::new(keys.tx_key(), &keys.session_id, true),
        )))
    });
    let carrier = sender.map(|sender| make_carrier(&channel, sender, parent, context.peer_id));
    let mut receiver =
        spawn_realtime_receiver(channel.handle.clone(), rx, rekey_rx, context, carrier);
    tokio::select! {
        _ = channel.handle.closed() => {},
        _ = &mut receiver.0 => {},
    }
}

fn spawn_child_receiver(
    channel: &Channel,
    keys: &ParallelKeys,
    parent: ParallelParentHandle,
    context: RealtimeReceiverContext,
    sender: Arc<Mutex<RealtimeSender>>,
) -> RealtimeReceiverTask {
    let rx = crate::datagram_flows::SessionDatagramRx::new(keys.rx_key(), &keys.session_id, true);
    let (_hold_tx, rekey_rx) = tokio::sync::watch::channel(None);
    let carrier = make_carrier(channel, sender, parent, context.peer_id);
    spawn_realtime_receiver(channel.handle.clone(), rx, rekey_rx, context, Some(carrier))
}

fn make_carrier(
    channel: &Channel,
    sender: Arc<Mutex<RealtimeSender>>,
    parent: ParallelParentHandle,
    peer: NodeIdBytes,
) -> Arc<dyn veil_anonymity::circuit_carrier::DatagramCarrier> {
    Arc::new(ChildCarrier {
        sender,
        parent,
        peer,
        diagnostics: Arc::clone(channel.diagnostics.as_ref().expect("owned child")),
    })
}

struct ChildCarrier {
    sender: Arc<Mutex<RealtimeSender>>,
    parent: ParallelParentHandle,
    peer: NodeIdBytes,
    diagnostics: Arc<ParallelDiagnostics>,
}

impl veil_anonymity::circuit_carrier::DatagramCarrier for ChildCarrier {
    fn try_send(
        &self,
        peer: &NodeIdBytes,
        frame: &[u8],
        admit: &mut dyn FnMut(usize) -> bool,
    ) -> veil_anonymity::circuit_carrier::CarrierSend {
        use veil_anonymity::circuit_carrier::CarrierSend;
        if peer != &self.peer || !self.parent.is_active() {
            return CarrierSend::Unavailable;
        }
        let Some((header, body, RealtimeLaneFrameKind::CircuitDatagram)) =
            decode_realtime_lane_frame(frame)
        else {
            return CarrierSend::Unavailable;
        };
        if header.priority() != veil_proto::priority::INTERACTIVE {
            return CarrierSend::Unavailable;
        }
        let mut sender = lock!(self.sender);
        if sender.broken {
            return CarrierSend::Unavailable;
        }
        let max_size = sender.max_datagram_size;
        let datagrams = match sender.tx.encode_frame(
            local_datagram_flow(
                veil_proto::priority::INTERACTIVE,
                body,
                RealtimeLaneFrameKind::CircuitDatagram,
            ),
            frame,
            max_size,
        ) {
            Ok(datagrams) => datagrams,
            Err(_) => return CarrierSend::Unavailable,
        };
        let planned = datagrams.iter().map(Vec::len).sum::<usize>();
        if !local_datagram_fits(
            veil_proto::priority::INTERACTIVE,
            planned,
            sender.handle.send_buffer_space(),
        ) || !admit(planned)
        {
            return CarrierSend::Dropped { wire_bytes: 0 };
        }
        let mut wire_bytes = 0;
        for datagram in &datagrams {
            if let Err(error) = sender.handle.send(datagram) {
                if matches!(error, veil_transport::QuicDatagramSendError::TooLarge) {
                    if let Some(size) = sender.handle.max_size().filter(|size| *size > 40) {
                        sender.max_datagram_size = size;
                    }
                } else {
                    sender.broken = true;
                }
                // Admission already spent the shared budget, possibly sent a
                // prefix. Never duplicate this frame on the canonical channel.
                return CarrierSend::Dropped { wire_bytes };
            }
            wire_bytes += datagram.len() as u64;
        }
        self.diagnostics.replies.fetch_add(1, Ordering::Relaxed);
        CarrierSend::Sent { wire_bytes }
    }
}

fn spawn_acceptor(
    offer: ParallelQuicOffer,
    parent: ParallelParentHandle,
    context: RealtimeReceiverContext,
    mut incoming: tokio::sync::mpsc::Receiver<registry::BoundChild>,
) -> RealtimeReceiverTask {
    RealtimeReceiverTask(tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = children.join_next(), if !children.is_empty() => {},
                Some(mut child) = incoming.recv() => {
                    let context = context.clone();
                    let duplex = offer.duplex;
                    children.spawn(async move {
                        if !child.parent.is_active() {
                            return;
                        }
                        if !matches!(tokio::time::timeout(BIND_TIMEOUT, child.channel.stream.write_all(&child.ack)).await, Ok(Ok(()))) {
                            return;
                        }
                        if !child.parent.is_active() {
                            return;
                        }
                        receive_authenticated(child.channel, child.keys, child.parent, context, duplex).await;
                    });
                },
                accepted = offer.handle.accept(), if offer.handle.has_exclusive_accept() => {
                    match accepted {
                        Ok(connection) => {
                            if let Ok(channel) = Channel::new(connection, Arc::clone(&offer.diagnostics)) {
                                children.spawn(receive_child(channel, parent.clone(), context.clone(), offer.duplex));
                            }
                        }
                        Err(_) => tokio::time::sleep(RETRY_DELAY).await,
                    }
                },
                // A full registry or missing shared dispatcher leaves the
                // ordinary lane available; there is no accept source to poll.
                else => break,
            }
        }
    }))
}

pub(super) struct ParallelSession {
    offer: ParallelQuicOffer,
    context: RealtimeReceiverContext,
    parent: ParallelParent,
    _acceptor: RealtimeReceiverTask,
    _registration: Option<registry::Registration>,
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
        let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(8);
        let registration = offer
            .registry
            .as_ref()
            .and_then(|registry| registry.register(sid, parent.handle(), &offer, incoming_tx));
        let acceptor = spawn_acceptor(offer.clone(), parent.handle(), context.clone(), incoming_rx);
        Self {
            offer,
            context,
            parent,
            _acceptor: acceptor,
            _registration: registration,
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
        self.parent.retire();
        self._registration = None;
        *self = Self::new(self.offer.clone(), tx, rx, sid, self.context.clone());
    }

    /// Poll readiness and initiate warming without awaiting on the main
    /// session. Until authentication succeeds, frames use the current lane.
    pub(super) fn prepare(&mut self, priority: u8) -> bool {
        let Some(index) = channel_index(priority) else {
            return false;
        };
        let slot = &mut self.slots[index];
        if slot
            .ready
            .as_ref()
            .is_some_and(|ready| lock!(ready.sender).broken)
        {
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
            let context = self.context.clone();
            let (tx, rx) = tokio::sync::oneshot::channel();
            let task = RealtimeReceiverTask(tokio::spawn(async move {
                if let Ok(Ok(ready)) = tokio::time::timeout(
                    BIND_TIMEOUT,
                    connect_sender(offer, parent, index, context),
                )
                .await
                {
                    let _ = tx.send(ready);
                }
            }));
            slot.warm = Some((rx, task));
        }
        false
    }

    pub(super) fn sender(&self, priority: u8) -> std::sync::MutexGuard<'_, RealtimeSender> {
        lock!(
            self.slots[channel_index(priority).expect("prepared local channel")]
                .ready
                .as_ref()
                .expect("prepared sender")
                .sender
        )
    }
}
