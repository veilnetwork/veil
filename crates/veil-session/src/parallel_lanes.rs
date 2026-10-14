//! Bounded local sibling selection. Remote accepts see only generic proofs;
//! they dispatch through the canonical peer's existing budgets and identity.
use super::*;
use crate::parallel_binding::{HELLO_BYTES, ParallelKeys, ParallelParent, ParallelParentHandle};

#[path = "datagram_recovery.rs"]
mod datagram_recovery;
#[path = "parallel_recovery_trace.rs"]
mod recovery_trace;
#[path = "parallel_registry.rs"]
pub(super) mod registry;
pub use registry::{
    BoundOrderedChild, BoundReliableChild, ParallelPeekOutcome, ParallelRegistry,
    RegisteredOrderedChannel, RegisteredReliableChannel, Registration as ParallelRegistration,
};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use veil_transport::QuicParallelHandle;

const BIND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const SOURCE_SLOTS: usize = crate::local_datagram_status::LOCAL_DATAGRAM_PRIORITIES.len();
const TRANSIT_SLOTS: usize = 2;
const TOTAL_SLOTS: usize = SOURCE_SLOTS + TRANSIT_SLOTS;
// Source counters retain logical ownership; transit counters observe physical
// generic connections without attributing their traffic to a source role.
const COUNTER_COUNT: usize = SOURCE_SLOTS + TOTAL_SLOTS;
// The optional signaling child retires before reliable/replacement capacity
// would be consumed; the peer retains the original generic connection bound.
const _: () = assert!(TOTAL_SLOTS < QuicParallelHandle::CONNECTIONS_PER_DIRECTION);

const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

/// Local observations, never wire fields or relay scheduling requests.
#[derive(Default)]
pub struct ParallelDiagnostics {
    reliable_frames: AtomicU64,
    reliable_full_writer_bypasses: AtomicU64,
    sent: [AtomicU64; COUNTER_COUNT],
    epoch_sent: [AtomicU64; COUNTER_COUNT],
    rekeys: AtomicU64,
    active: AtomicUsize,
    replies: AtomicU64,
    recovery_attempts: AtomicU64,
    recovery_switches: AtomicU64,
}

impl ParallelDiagnostics {
    pub fn reliable_frames_sent(&self) -> u64 {
        self.reliable_frames.load(Ordering::Relaxed)
    }
    /// Child admissions while the canonical writer queue had zero capacity.
    /// Local witness only; never advertises a traffic class to the transport.
    pub fn reliable_full_writer_bypasses(&self) -> u64 {
        self.reliable_full_writer_bypasses.load(Ordering::Relaxed)
    }
    pub(crate) fn note_reliable_frame(&self, canonical_full: bool) -> bool {
        let first = self.reliable_frames.fetch_add(1, Ordering::Relaxed) == 0;
        if canonical_full {
            self.reliable_full_writer_bypasses
                .fetch_add(1, Ordering::Relaxed);
        }
        first
    }
    pub(super) fn connection_opened(&self) {
        self.active.fetch_add(1, Ordering::AcqRel);
    }
    pub(super) fn connection_closed(&self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
    pub(super) fn rotate_generation(&self) {
        for counter in &self.epoch_sent {
            counter.store(0, Ordering::Relaxed);
        }
        self.rekeys.fetch_add(1, Ordering::Release);
    }
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
    /// Forwarded cells on neutral shards, separate from source queue hints.
    pub fn transit_sent(&self) -> u64 {
        self.sent[SOURCE_SLOTS..]
            .iter()
            .map(|counter| counter.load(Ordering::Relaxed))
            .sum()
    }
    pub fn transit_sent_this_generation(&self) -> u64 {
        self.epoch_sent[SOURCE_SLOTS..]
            .iter()
            .map(|counter| counter.load(Ordering::Relaxed))
            .sum()
    }

    pub fn transit_shards_used_this_generation(&self) -> usize {
        self.epoch_sent[SOURCE_SLOTS..]
            .iter()
            .filter(|counter| counter.load(Ordering::Relaxed) != 0)
            .count()
    }

    pub fn recovery_attempts(&self) -> u64 {
        self.recovery_attempts.load(Ordering::Acquire)
    }
    pub fn recovery_switches(&self) -> u64 {
        self.recovery_switches.load(Ordering::Acquire)
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
    reliable: bool,
}

impl ParallelQuicOffer {
    pub fn new(handle: QuicParallelHandle) -> Self {
        Self {
            handle,
            diagnostics: Arc::default(),
            registry: None,
            duplex: false,
            reliable: false,
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

    /// Enable only after the independent reliable-child capability is agreed.
    pub fn with_reliable(mut self) -> Self {
        self.reliable = true;
        self
    }

    pub fn diagnostics(&self) -> Arc<ParallelDiagnostics> {
        Arc::clone(&self.diagnostics)
    }
}

fn channel_index(priority: u8) -> Option<usize> {
    // INTERACTIVE is always neutral transit; local IPC signaling has its own
    // private selector and never exposes it to the receiving peer.
    crate::local_datagram_status::LOCAL_DATAGRAM_PRIORITIES
        .iter()
        .position(|&lane| lane == priority)
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
    replacing: bool,
    recovery: datagram_recovery::ChannelRecovery,
    last_selected: Option<std::time::Instant>,
}

async fn connect_sender(
    offer: ParallelQuicOffer,
    parent: ParallelParentHandle,
    index: usize,
    context: RealtimeReceiverContext,
    trace: Option<&recovery_trace::Attempt>,
) -> Result<ReadySender, &'static str> {
    use recovery_trace::{Attempt, Phase};
    let connection = offer
        .handle
        .connect()
        .await
        .map_err(recovery_trace::connect_failure)?;
    Attempt::phase(trace, Phase::Channel);
    let mut channel =
        Channel::new(connection, Arc::clone(&offer.diagnostics)).map_err(|_| "channel_error")?;
    Attempt::phase(trace, Phase::Exporter);
    let exporter = channel
        .handle
        .channel_binding()
        .map_err(|_| "exporter_error")?;
    Attempt::phase(trace, Phase::Begin);
    let (hello, pending) = parent.begin(exporter).map_err(|_| "parent_retired")?;
    Attempt::phase(trace, Phase::HelloWrite);
    channel
        .stream
        .write_all(&hello)
        .await
        .map_err(|_| "hello_write_error")?;
    let mut ack = [0; 32];
    Attempt::phase(trace, Phase::AckRead);
    channel
        .stream
        .read_exact(&mut ack)
        .await
        .map_err(|_| "ack_read_error")?;
    Attempt::phase(trace, Phase::AckVerify);
    let keys = pending.finish(&ack).map_err(|error| match error {
        crate::parallel_binding::BindingError::Retired => "parent_retired",
        crate::parallel_binding::BindingError::InvalidProof => "invalid_ack_proof",
    })?;
    Attempt::phase(trace, Phase::DatagramCeiling);
    if channel
        .handle
        .max_size()
        .is_none_or(|size| size < crate::datagram_flows::MIN_FLOW_DATAGRAM_SIZE)
    {
        return Err("datagram_ceiling");
    }
    let tx = crate::datagram_flows::SessionDatagramTx::new(keys.tx_key(), &keys.session_id, true);
    let mut sender = RealtimeSender::new(channel.handle.clone(), tx);
    sender.sent_counter = Some((Arc::clone(&offer.diagnostics), index));
    let sender = Arc::new(Mutex::new(sender));
    let receiver = offer
        .duplex
        .then(|| spawn_child_receiver(&channel, &keys, parent, context, Arc::clone(&sender)));
    Attempt::phase(trace, Phase::Ready);
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
    reliable: Option<mpsc::Sender<BoundReliableChild>>,
) {
    let authenticated = tokio::time::timeout(BIND_TIMEOUT, async {
        let mut hello = [0; HELLO_BYTES];
        channel.stream.read_exact(&mut hello).await.ok()?;
        let exporter = channel.handle.channel_binding().ok()?;
        if &hello[..8] == crate::parallel_binding::RELIABLE_PREFACE {
            reliable.as_ref()?;
            let (ack, keys) = parent.accept_reliable(&hello, exporter).ok()?;
            return Some((keys, Some(ack)));
        }
        let (ack, keys) = parent.accept(&hello, exporter).ok()?;
        channel.stream.write_all(&ack).await.ok()?;
        Some((keys, None))
    })
    .await;
    let Ok(Some((keys, ack))) = authenticated else {
        return;
    };
    if let Some(ack) = ack {
        let child = BoundReliableChild::exclusive_quic(channel, keys, ack, parent);
        let _ = reliable.expect("negotiated reliable inbox").try_send(child);
        return;
    }
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
    let carrier = sender.map(|sender| {
        make_carrier(
            channel.diagnostics.as_ref().expect("owned child"),
            sender,
            parent,
            context.peer_id,
        )
    });
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
    let carrier = make_carrier(
        channel.diagnostics.as_ref().expect("owned child"),
        sender,
        parent,
        context.peer_id,
    );
    spawn_realtime_receiver(channel.handle.clone(), rx, rekey_rx, context, Some(carrier))
}

pub(super) fn make_carrier(
    diagnostics: &Arc<ParallelDiagnostics>,
    sender: Arc<Mutex<RealtimeSender>>,
    parent: ParallelParentHandle,
    peer: NodeIdBytes,
) -> Arc<dyn veil_anonymity::circuit_carrier::DatagramCarrier> {
    Arc::new(ChildCarrier {
        sender,
        parent,
        peer,
        diagnostics: Arc::clone(diagnostics),
    })
}

struct ChildCarrier {
    sender: Arc<Mutex<RealtimeSender>>,
    parent: ParallelParentHandle,
    peer: NodeIdBytes,
    diagnostics: Arc<ParallelDiagnostics>,
}

impl veil_anonymity::circuit_carrier::DatagramCarrier for ChildCarrier {
    fn local_ingress_flow(&self) -> Option<veil_anonymity::circuit_carrier::LocalIngressFlow> {
        let sender = lock!(self.sender);
        if !self.parent.is_active() || sender.broken || sender.handle.is_closed() {
            return None;
        }
        Some(veil_anonymity::circuit_carrier::LocalIngressFlow {
            parent: self.parent.local_generation(),
            connection: Arc::as_ptr(&self.sender) as usize,
        })
    }

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
        if sender.broken || sender.handle.is_closed() {
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
        let queue_charge = datagrams
            .iter()
            .map(|packet| sender.handle.queue_charge(packet.len()))
            .sum::<usize>();
        if !local_datagram_fits(
            veil_proto::priority::INTERACTIVE,
            queue_charge,
            sender.handle.send_buffer_space(),
        ) || !admit(planned)
        {
            return CarrierSend::Dropped { wire_bytes: 0 };
        }
        let mut wire_bytes = 0;
        for datagram in &datagrams {
            if let Err(error) = sender.handle.send(datagram) {
                if matches!(error, LossySendError::TooLarge) {
                    if let Some(size) = sender.handle.max_size().filter(|size| *size > 40) {
                        sender.max_datagram_size = size;
                    }
                } else if !error.is_temporary() {
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
    reliable: Option<mpsc::Sender<BoundReliableChild>>,
) -> RealtimeReceiverTask {
    RealtimeReceiverTask(tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        let mut accepts = tokio::task::JoinSet::new();
        loop {
            // Two generic handshakes can progress independently. The shared
            // transport's per-direction and aggregate quotas bound live children.
            // No producer role is inspected by this receiver.
            if offer.handle.has_exclusive_accept() {
                while accepts.len() < 2 {
                    let handle = offer.handle.clone();
                    accepts.spawn(async move {
                        let result = handle.accept().await;
                        if result.is_err() {
                            tokio::time::sleep(RETRY_DELAY).await;
                        }
                        result
                    });
                }
            }
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
                Some(accepted) = accepts.join_next(), if !accepts.is_empty() => {
                    if let Ok(Ok(connection)) = accepted
                        && let Ok(channel) = Channel::new(connection, Arc::clone(&offer.diagnostics)) {
                        children.spawn(receive_child(channel, parent.clone(), context.clone(), offer.duplex, reliable.clone()));
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
    readiness: Option<crate::local_datagram_status::LocalDatagramLease>,
    _acceptor: RealtimeReceiverTask,
    _registration: Option<registry::Registration>,
    slots: [Slot; TOTAL_SLOTS],
    transit_salt: [u8; 32],
    assignments: channel_assignments::ChannelAssignments<TOTAL_SLOTS>,
    recovery_schedule: datagram_recovery::RecoverySchedule,
    reliable: Option<super::reliable_session::ReliableSession>,
}

impl Drop for ParallelSession {
    fn drop(&mut self) {
        self.parent.retire();
        self.reliable = None;
        self._registration = None;
    }
}

impl ParallelSession {
    pub(super) fn note_reliable_frame(&self, canonical_full: bool) -> bool {
        self.offer.diagnostics.note_reliable_frame(canonical_full)
    }
    pub(super) fn reliable(&self) -> Option<&super::reliable_session::ReliableSession> {
        self.reliable.as_ref()
    }
    pub(super) fn new(
        offer: ParallelQuicOffer,
        tx: &[u8; 32],
        rx: &[u8; 32],
        sid: [u8; 32],
        context: RealtimeReceiverContext,
        status: Option<Arc<crate::local_datagram_status::LocalDatagramStatus>>,
    ) -> Self {
        let readiness = status
            .filter(|_| offer.duplex)
            .map(|status| status.activate());
        let parent = ParallelParent::new(sid, *tx, *rx);
        let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(8);
        let registration = offer
            .registry
            .as_ref()
            .and_then(|registry| registry.register(sid, parent.handle(), &offer, incoming_tx));
        let (reliable_tx, reliable_rx) = mpsc::channel(1);
        let reliable_enabled = offer.reliable
            && (registration
                .as_ref()
                .is_some_and(|r| r.enable_reliable(reliable_tx.clone()))
                || offer.handle.has_exclusive_accept());
        let reliable = reliable_enabled.then(|| {
            super::reliable_session::ReliableSession::new(
                super::reliable_session::ReliableTransport::Quic(offer.handle.clone()),
                parent.handle(),
                offer.diagnostics.clone(),
                reliable_rx,
            )
        });
        let acceptor = spawn_acceptor(
            offer.clone(),
            parent.handle(),
            context.clone(),
            incoming_rx,
            reliable_enabled.then_some(reliable_tx),
        );
        Self {
            offer,
            context,
            parent,
            readiness,
            _acceptor: acceptor,
            _registration: registration,
            slots: Default::default(),
            assignments: Default::default(),
            transit_salt: blake3::derive_key("veil/transit-shard/v1", &sid),
            recovery_schedule: Default::default(),
            reliable,
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
        let status = self.readiness.as_ref().map(|lease| lease.status());
        *self = Self::new(
            self.offer.clone(),
            tx,
            rx,
            sid,
            self.context.clone(),
            status,
        );
    }

    /// Poll readiness and initiate warming without awaiting on the main
    /// session. Until authentication succeeds, frames use the current lane.
    pub(super) fn prepare(&mut self, priority: u8) -> bool {
        let Some(index) = channel_index(priority) else {
            return false;
        };
        let Some(selected) = self.assignments.source(index) else {
            return false;
        };
        self.prepare_index(selected.physical)
    }

    /// Called only after the ordinary FIFO selects this frame. Every transit
    /// connection receives the same admission and service cost. Its local live
    /// ingress witness preserves separation; legacy frames use neutral buckets.
    #[cfg(test)]
    pub(super) fn prepare_frame(
        &mut self,
        priority: u8,
        body: &[u8],
        kind: RealtimeLaneFrameKind,
    ) -> Option<usize> {
        self.prepare_frame_with_carrier(priority, body, kind, None)
            .map(|selection| selection.physical)
    }

    pub(super) fn offer_diagnostics(&self) -> Arc<ParallelDiagnostics> {
        self.offer.diagnostics.clone()
    }

    pub(super) fn prepare_frame_with_carrier(
        &mut self,
        priority: u8,
        body: &[u8],
        kind: RealtimeLaneFrameKind,
        ingress: Option<&veil_anonymity::circuit_carrier::Carrier>,
    ) -> Option<channel_assignments::Selection> {
        let selected = if let Some(source) = channel_index(priority) {
            self.assignments.source(source)?
        } else {
            if !self.offer.duplex || priority != veil_proto::priority::INTERACTIVE {
                return None;
            }
            let bucket = neutral_transit_index(&self.transit_salt, body, kind)?;
            let ingress = transit_witness(kind, ingress);
            self.assignments.transit(ingress, bucket)?
        };
        let now = std::time::Instant::now();
        self.slots[selected.physical].last_selected = Some(now);
        let prepared = self.prepare_index(selected.physical);
        self.recover_channels(now);
        prepared.then_some(selected)
    }

    #[cfg(test)]
    pub(super) fn ingress_carrier_for_test(
        &self,
        index: usize,
    ) -> Arc<dyn veil_anonymity::circuit_carrier::DatagramCarrier> {
        make_carrier(
            &self.offer.diagnostics,
            self.sender_arc(index),
            self.parent.handle(),
            self.context.peer_id,
        )
    }

    #[cfg(test)]
    pub(super) async fn stage_verified_primary_replacement(&mut self) {
        // A real exporter-bound handshake completes before the runner's next
        // poll, matching a replacement result racing an ACK on the old path.
        let index = self
            .assignments
            .source_physical(channel_index(veil_proto::priority::REALTIME).unwrap())
            .expect("primary source allocation");
        let old_stats = lock!(self.slots[index].ready.as_ref().unwrap().sender)
            .handle
            .quic()
            .unwrap()
            .path_stats();
        self.slots[index]
            .recovery
            .observe(old_stats, std::time::Instant::now());
        let ready = connect_sender(
            self.offer.clone(),
            self.parent.handle(),
            index,
            self.context.clone(),
            None,
        )
        .await
        .expect("replacement proof");
        let (tx, rx) = tokio::sync::oneshot::channel();
        assert!(tx.send(ready).is_ok());
        let task = RealtimeReceiverTask(tokio::spawn(std::future::pending()));
        self.slots[index].warm = Some((rx, task));
        self.slots[index].replacing = true;
    }

    fn poll_index(&mut self, index: usize) {
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
                    // connect_sender verified the live parent's exporter-bound
                    // ACK before returning ReadySender. Drop the old channel
                    // only now; a failed candidate never displaces it.
                    slot.ready = Some(ready);
                    slot.warm = None;
                    if std::mem::take(&mut slot.replacing) {
                        self.offer
                            .diagnostics
                            .recovery_switches
                            .fetch_add(1, Ordering::AcqRel);
                        slot.recovery.reset();
                        self.context.logger.info(
                            "session.parallel.recovery_switched",
                            format!(
                                "peer_id={} local_slot={}",
                                hex_short(&self.context.peer_id),
                                index
                            ),
                        );
                    }
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    slot.warm = None;
                    slot.replacing = false;
                    slot.retry_after = Some(std::time::Instant::now() + RETRY_DELAY);
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
            }
        }
        if let Some(lease) = &self.readiness {
            for (source, priority) in crate::local_datagram_status::LOCAL_DATAGRAM_PRIORITIES
                .iter()
                .enumerate()
            {
                if self.assignments.source_physical(source) == Some(index) {
                    lease.mark(*priority, slot.ready.is_some());
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn prepare_without_recovery(&mut self, index: usize) -> bool {
        self.prepare_index(index)
    }

    /// Signaling may use an extra local child only while the existing generic
    /// budget leaves room for reliable data and a verified replacement. Keep
    /// the old eight-connection limit, including when the peer is older.
    fn retire_signaling_for_capacity(&mut self) {
        let Some(index) = channel_index(crate::LOCAL_SIGNALING_LANE)
            .and_then(|source| self.assignments.source_physical(source))
        else {
            return;
        };
        let slot = &mut self.slots[index];
        slot.ready = None;
        slot.warm = None;
        slot.replacing = false;
        slot.recovery.reset();
        if let Some(lease) = &self.readiness {
            lease.mark(crate::LOCAL_SIGNALING_LANE, false);
        }
    }

    fn prepare_index(&mut self, index: usize) -> bool {
        let signaling = channel_index(crate::LOCAL_SIGNALING_LANE)
            .and_then(|source| self.assignments.source_physical(source));
        let available = self.offer.handle.available_connection_slots();
        if available <= 1 || (signaling != Some(index) && available <= 2) {
            self.retire_signaling_for_capacity();
        }
        // A live signaling child already owns its slot. Starting a new one
        // must leave two slots: ordinary reliable delivery and replacement.
        if signaling == Some(index)
            && self.slots[index].ready.is_none()
            && self.offer.handle.available_connection_slots() <= 2
        {
            return false;
        }
        self.poll_index(index);
        let slot = &self.slots[index];
        if slot.ready.is_some() {
            return true;
        }
        if slot.warm.is_none()
            && slot
                .retry_after
                .is_none_or(|deadline| std::time::Instant::now() >= deadline)
        {
            self.start_warm(index);
        }
        false
    }

    fn start_warm(&mut self, index: usize) {
        let offer = self.offer.clone();
        let parent = self.parent.handle();
        let context = self.context.clone();
        let status = self.readiness.as_ref().map(|lease| lease.status());
        let mut trace = self.slots[index]
            .replacing
            .then(|| recovery_trace::Attempt::new(&context, offer.handle.clone(), index));
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = RealtimeReceiverTask(tokio::spawn(async move {
            match tokio::time::timeout(
                BIND_TIMEOUT,
                connect_sender(offer, parent, index, context, trace.as_ref()),
            )
            .await
            {
                Ok(Ok(ready)) => {
                    if let Some(trace) = trace.as_mut() {
                        trace.finish("verified", "authenticated");
                    }
                    let _ = tx.send(ready);
                }
                Ok(Err(reason)) => {
                    if let Some(trace) = trace.as_mut() {
                        trace.finish("failed", reason);
                    }
                }
                Err(_) => {
                    if let Some(trace) = trace.as_mut() {
                        trace.finish("timeout", "binding_deadline");
                    }
                }
            }
            if let Some(status) = status {
                status.wake();
            }
        }));
        self.slots[index].warm = Some((rx, task));
    }

    fn recover_channels(&mut self, now: std::time::Instant) {
        use datagram_recovery::Action;
        if self.offer.handle.available_connection_slots() <= 1 {
            self.retire_signaling_for_capacity();
        }
        let mut eligible = [false; TOTAL_SLOTS];
        let mut snapshots = [None; TOTAL_SLOTS];
        // Adopt verified candidates before looking at ACK progress, including
        // a candidate for a channel other than the currently selected one.
        for index in 0..TOTAL_SLOTS {
            self.poll_index(index);
            let slot = &mut self.slots[index];
            let Some(ready) = &slot.ready else {
                slot.recovery.reset();
                continue;
            };
            let stats = {
                let sender = lock!(ready.sender);
                if sender.broken {
                    continue;
                }
                sender
                    .handle
                    .quic()
                    .expect("QUIC session child")
                    .path_stats()
            };
            snapshots[index] = Some(stats);
            match slot.recovery.observe(stats, now) {
                Action::Progress if slot.replacing => {
                    // The old channel recovered while proof was pending. Reap the
                    // redundant task/channel instead of churning a healthy sender.
                    slot.warm = None;
                    slot.replacing = false;
                    self.context.logger.info(
                        "session.parallel.recovery_cancelled",
                        format!(
                            "peer_id={} local_slot={} reason=ack_progress",
                            hex_short(&self.context.peer_id),
                            index,
                        ),
                    );
                }
                Action::Probe if slot.warm.is_none() => {
                    eligible[index] = slot.last_selected.is_some_and(|at| {
                        now.saturating_duration_since(at) <= datagram_recovery::ACTIVE_FOR
                    });
                }
                _ => {}
            }
        }
        let replacing = self.slots.iter().any(|slot| slot.replacing);
        let Some(index) = self.recovery_schedule.choose(eligible, replacing, now) else {
            return;
        };
        let slot = &mut self.slots[index];
        slot.recovery.attempted(now);
        slot.replacing = true;
        self.offer
            .diagnostics
            .recovery_attempts
            .fetch_add(1, Ordering::AcqRel);
        let stats = snapshots[index].expect("eligible channel snapshot");
        self.context.logger.info(
            "session.parallel.recovery_started",
            format!(
                "peer_id={} local_slot={index} pto_count={} expired={}",
                hex_short(&self.context.peer_id),
                stats.pto_count,
                stats.expired_outgoing_datagrams,
            ),
        );
        self.start_warm(index);
    }

    #[cfg(test)]
    pub(super) fn sender(&self, index: usize) -> std::sync::MutexGuard<'_, RealtimeSender> {
        lock!(
            self.slots[index]
                .ready
                .as_ref()
                .expect("prepared sender")
                .sender
        )
    }
    pub(super) fn sender_arc(&self, index: usize) -> Arc<Mutex<RealtimeSender>> {
        self.slots[index]
            .ready
            .as_ref()
            .expect("prepared sender")
            .sender
            .clone()
    }
}

/// Circuit witnesses describe an installed circuit incarnation, not a raw
/// return connection. Forward witnesses retain authenticated ingress ownership.
/// Never interpret the legacy reverse ChildCarrier as a circuit flow identity.
pub(super) fn transit_witness<'a>(
    kind: RealtimeLaneFrameKind,
    witness: Option<&'a veil_anonymity::circuit_carrier::Carrier>,
) -> Option<&'a veil_anonymity::circuit_carrier::Carrier> {
    match kind {
        RealtimeLaneFrameKind::RelayForward => witness,
        RealtimeLaneFrameKind::CircuitDatagram => witness.filter(|w| {
            w.upgrade()
                .is_some_and(|carrier| carrier.local_circuit_flow().is_some())
        }),
        RealtimeLaneFrameKind::DirectApp => None,
    }
}

// Legacy fallback only. The caller has validated the CircuitDataPayload. Only
// its existing per-link ID participates; ciphertext, sender hints and claimed
// priority never do.
pub(super) fn transit_index(salt: &[u8; 32], body: &[u8]) -> usize {
    SOURCE_SLOTS + usize::from(blake3::keyed_hash(salt, &body[..4]).as_bytes()[0]) % TRANSIT_SLOTS
}

// Both formats have passed the ordinary loss-tolerant decoder before selection.
// A forwarded delivery uses only its already visible recipient and sender,
// never app IDs, endpoints, payload, TTL or a sender's traffic-class hint.
// This is the same bounded neutral pool and ordinary FIFO as circuit transit.
pub(super) fn neutral_transit_index(
    salt: &[u8; 32],
    body: &[u8],
    kind: RealtimeLaneFrameKind,
) -> Option<usize> {
    match kind {
        RealtimeLaneFrameKind::CircuitDatagram => {
            body.get(..4)?;
            Some(transit_index(salt, body))
        }
        RealtimeLaneFrameKind::RelayForward => {
            // Forward begins with next_hop (32); the envelope then begins
            // with Recipient's fixed 49-byte routing value and sender (32).
            let routing = body.get(32..32 + 49 + 32)?;
            let mut hash = blake3::Hasher::new_keyed(salt);
            hash.update(b"neutral-forward/v1");
            hash.update(routing);
            Some(SOURCE_SLOTS + usize::from(hash.finalize().as_bytes()[0]) % TRANSIT_SLOTS)
        }
        RealtimeLaneFrameKind::DirectApp => None,
    }
}

#[cfg(test)]
mod transit_tests {
    use super::*;

    #[test]
    fn neutral_shards_are_bounded_stable_and_ignore_contents() {
        let salt = blake3::derive_key("veil/transit-shard/v1", &[7; 32]);
        let mut seen = [false; TRANSIT_SLOTS];
        for cid in 0..256u32 {
            let mut body = cid.to_be_bytes().to_vec();
            body.extend_from_slice(&[0; 128]);
            let index = transit_index(&salt, &body);
            assert!((SOURCE_SLOTS..TOTAL_SLOTS).contains(&index));
            seen[index - SOURCE_SLOTS] = true;
            body[4..].fill(255);
            assert_eq!(transit_index(&salt, &body), index);
        }
        assert!(seen.into_iter().all(|present| present));
        assert_eq!(channel_index(veil_proto::priority::INTERACTIVE), None);
    }

    #[test]
    fn forwarded_delivery_shards_ignore_app_roles_payload_and_claimed_priority() {
        let salt = blake3::derive_key("veil/transit-shard/v1", &[7; 32]);
        let mut body = vec![0; 512];
        let mut seen = [false; TRANSIT_SLOTS];
        for sender in 0..256u16 {
            // Existing routing sender only; never add a flow or role field.
            body[32 + 49..32 + 49 + 2].copy_from_slice(&sender.to_be_bytes());
            let selected =
                neutral_transit_index(&salt, &body, RealtimeLaneFrameKind::RelayForward).unwrap();
            assert!((SOURCE_SLOTS..TOTAL_SLOTS).contains(&selected));
            seen[selected - SOURCE_SLOTS] = true;
            body[..32].fill(12); // a different next-hop routing advertisement
            body[32 + 49 + 32..].fill(255); // apps, timestamps, ciphertext, wire hint
            assert_eq!(
                neutral_transit_index(&salt, &body, RealtimeLaneFrameKind::RelayForward),
                Some(selected)
            );
        }
        assert!(seen.into_iter().all(|x| x));
        assert_eq!(
            neutral_transit_index(&salt, &body, RealtimeLaneFrameKind::DirectApp),
            None
        );
    }

    #[test]
    fn transit_observations_do_not_claim_source_channels() {
        let diagnostics = ParallelDiagnostics::default();
        diagnostics.note_sent(SOURCE_SLOTS);
        diagnostics.note_sent(SOURCE_SLOTS + 1);
        assert_eq!(diagnostics.transit_sent(), 2);
        assert_eq!(diagnostics.transit_sent_this_generation(), 2);
        assert_eq!(diagnostics.sent(0), 0);
        assert_eq!(diagnostics.sent(2), 0);
    }
}
